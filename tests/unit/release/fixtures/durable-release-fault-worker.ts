import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  appendFunctionalReleaseTransactionRecord,
  canonicalReleaseTransactionJson,
  commitFunctionalReleaseTransactionTarget,
  completeFunctionalReleaseMutation,
  prepareFunctionalReleaseMutation,
  readFunctionalReleaseTransactionJournal,
  reconcileFunctionalReleaseTransaction,
  releaseTransactionSha256,
  type FunctionalReleaseTransactionRecord,
} from "../../../../scripts/release/DurableReleaseTransaction";
import { writeDurableFileAtomically } from "../../../../scripts/release/DurableAtomicFile";

interface FixtureState {
  application: "old-app" | "new-app";
  applicationSwap: "none" | "deploy-stranded" | "rollback-stranded" | "archived";
  static: "old-static" | "new-static";
  database: "old-db" | "new-db" | "new-db-with-acknowledged-write";
  vault: "old-vault" | "new-vault" | "new-vault-with-acknowledged-write";
  service: "active" | "inactive";
  receipt: "prepared" | "deployed" | "recovered";
  forwardCounts: Record<string, number>;
  recoveryCounts: Record<string, number>;
}

const [command, workspaceValue, journalValue, killPhase = ""] = process.argv.slice(2);
const workspace = resolve(workspaceValue!);
const journalDirectory = resolve(journalValue!);
const statePath = join(workspace, "state.json");
const originalReceiptPath = join(workspace, "original-receipt.json");
const recoveryReceiptPath = join(workspace, "recovery-receipt.json");
const targetRecoveryReceiptPath = join(workspace, "target-recovery-receipt.json");
const readyPath = join(workspace, "fault-ready");

function readState(): FixtureState {
  return JSON.parse(readFileSync(statePath, "utf8")) as FixtureState;
}

function writeState(state: FixtureState): void {
  writeDurableFileAtomically(statePath, `${canonicalReleaseTransactionJson(state)}\n`, { mode: 0o600 });
}

function mutateState(
  direction: "forward" | "recovery",
  mutation: string,
  apply: (state: FixtureState) => boolean,
): "mutated" | "already_exact" {
  const state = readState();
  if (!apply(state)) return "already_exact";
  const counts = direction === "forward" ? state.forwardCounts : state.recoveryCounts;
  counts[mutation] = (counts[mutation] ?? 0) + 1;
  writeState(state);
  return "mutated";
}

async function faultPoint(phase: string): Promise<void> {
  if (killPhase !== phase) return;
  writeDurableFileAtomically(readyPath, `${phase}\n`, { mode: 0o600 });
  await Bun.sleep(60_000);
}

const precommitForwardMutations = [
  "service_stop",
  "application_activation",
  "static_activation",
  "database_mutation",
  "vault_mutation",
  "target_data_verification",
] as const;

const postcommitForwardMutations = [
  "service_start",
  "deployment_receipt_commit",
] as const;

type ForwardMutation =
  | typeof precommitForwardMutations[number]
  | typeof postcommitForwardMutations[number];

function applyForward(mutation: ForwardMutation): void {
  mutateState("forward", mutation, (state) => {
    if (mutation === "service_stop") {
      if (state.service === "inactive") return false;
      state.service = "inactive";
    } else if (mutation === "application_activation") {
      if (state.application === "new-app") return false;
      state.application = "new-app";
    } else if (mutation === "static_activation") {
      if (state.static === "new-static") return false;
      state.static = "new-static";
    } else if (mutation === "database_mutation") {
      if (state.database === "new-db") return false;
      state.database = "new-db";
    } else if (mutation === "vault_mutation") {
      if (state.vault === "new-vault") return false;
      state.vault = "new-vault";
    } else if (mutation === "service_start") {
      if (state.service === "active") return false;
      state.service = "active";
      // Models startup/API work that was acknowledged after the durable point
      // of no return. Forward reconciliation must preserve these bytes.
      state.database = "new-db-with-acknowledged-write";
      state.vault = "new-vault-with-acknowledged-write";
    } else if (mutation === "target_data_verification") {
      return false;
    } else {
      if (state.receipt === "deployed") return false;
      state.receipt = "deployed";
      writeDurableFileAtomically(
        originalReceiptPath,
        `${canonicalReleaseTransactionJson({ releaseId: "fault-release", status: "deployed" })}\n`,
        { mode: 0o600 },
      );
    }
    return true;
  });
}

async function runForward(): Promise<void> {
  const operation = readFunctionalReleaseTransactionJournal(journalDirectory).binding.operation;
  for (const mutation of precommitForwardMutations) {
    prepareFunctionalReleaseMutation(journalDirectory, "forward", mutation);
    applyForward(mutation);
    if (mutation === "application_activation") {
      const state = readState();
      if (state.applicationSwap === "none") {
        state.applicationSwap = operation === "deploy" ? "deploy-stranded" : "rollback-stranded";
        writeState(state);
      }
      await faultPoint("application_activation_exchange");
      const finalized = readState();
      finalized.applicationSwap = "none";
      writeState(finalized);
    }
    await faultPoint(mutation);
    completeFunctionalReleaseMutation(journalDirectory, "forward", mutation);
  }
  commitFunctionalReleaseTransactionTarget(journalDirectory, {
    application: "new-app",
    static: "new-static",
    database: "new-db",
    vault: "new-vault",
    serviceIntent: "active",
  });
  await faultPoint("target_committed");
  for (const mutation of postcommitForwardMutations) {
    prepareFunctionalReleaseMutation(journalDirectory, "forward", mutation);
    applyForward(mutation);
    await faultPoint(mutation);
    completeFunctionalReleaseMutation(journalDirectory, "forward", mutation);
  }
  await faultPoint("terminal_record");
  const receiptBytes = readFileSync(originalReceiptPath);
  appendFunctionalReleaseTransactionRecord(journalDirectory, {
    event: "terminal",
    detail: {
      outcome: operation === "deploy" ? "deployed" : "rolled_back",
      receiptPath: originalReceiptPath,
      receiptSha256: releaseTransactionSha256(receiptBytes),
    },
  });
}

function exactTarget(state: FixtureState): boolean {
  return state.application === "new-app" && state.static === "new-static" &&
    (state.database === "new-db" || state.database === "new-db-with-acknowledged-write") &&
    (state.vault === "new-vault" || state.vault === "new-vault-with-acknowledged-write") &&
    state.service === "active" && state.receipt === "deployed";
}

function exactSource(state: FixtureState): boolean {
  return state.application === "old-app" && state.static === "old-static" &&
    state.database === "old-db" && state.vault === "old-vault" &&
    state.service === "active" && state.receipt === "recovered" &&
    state.applicationSwap !== "deploy-stranded" &&
    state.applicationSwap !== "rollback-stranded";
}

function terminalDetail(record: FunctionalReleaseTransactionRecord): Record<string, unknown> {
  if (!record.detail) throw new Error("terminal detail missing");
  return record.detail as Record<string, unknown>;
}

async function runRecovery(): Promise<void> {
  const initialJournal = readFunctionalReleaseTransactionJournal(journalDirectory);
  const operation = initialJournal.binding.operation;
  if (initialJournal.records.some((record) => record.event === "target_committed")) {
    const targetOutcome = operation === "deploy" ? "deployed" : "rolled_back";
    await reconcileFunctionalReleaseTransaction(journalDirectory, {
      reconciliationIntent: "complete_target",
      assertBindingAndObservedState: () => {
        const state = readState();
        if (
          state.application !== "new-app" || state.static !== "new-static" ||
          state.database === "old-db" || state.vault === "old-vault"
        ) throw new Error("committed target bytes were replaced");
      },
      steps: [
        {
          mutation: "target_state_verification",
          apply: () => {
            const state = readState();
            if (
              state.application !== "new-app" || state.static !== "new-static" ||
              state.database === "old-db" || state.vault === "old-vault"
            ) throw new Error("target state verification failed");
            return "already_exact";
          },
        },
        {
          mutation: "service_start",
          apply: () => mutateState("recovery", "service_start", (state) => {
            let changed = false;
            if (state.service !== "active") {
              state.service = "active";
              changed = true;
            }
            if (state.database === "new-db") {
              state.database = "new-db-with-acknowledged-write";
              changed = true;
            }
            if (state.vault === "new-vault") {
              state.vault = "new-vault-with-acknowledged-write";
              changed = true;
            }
            return changed;
          }),
        },
        {
          mutation: "deployment_receipt_commit",
          apply: () => mutateState("recovery", "deployment_receipt_commit", (state) => {
            if (state.receipt === "deployed") return false;
            state.receipt = "deployed";
            writeDurableFileAtomically(
              originalReceiptPath,
              `${canonicalReleaseTransactionJson({ releaseId: "fault-release", status: targetOutcome })}\n`,
              { mode: 0o600 },
            );
            return true;
          }),
        },
        {
          mutation: "running_state_verification",
          apply: () => {
            if (!exactTarget(readState())) throw new Error("target state did not survive forward recovery");
            return "already_exact";
          },
        },
      ],
      terminalReceipt: () => ({
        path: targetRecoveryReceiptPath,
        value: {
          schemaVersion: "fault-forward-recovery.v1",
          transactionId: initialJournal.binding.transactionId,
          outcome: targetOutcome,
        },
        outcome: targetOutcome,
      }),
      verifyTerminal: (terminal) => {
        const detail = terminalDetail(terminal);
        const path = String(detail.receiptPath);
        if (!existsSync(path) || releaseTransactionSha256(readFileSync(path)) !== detail.receiptSha256) {
          throw new Error("target terminal receipt identity mismatch");
        }
        if (!exactTarget(readState())) throw new Error("committed target identity mismatch");
      },
      onPhase: async (phase, mutation) => {
        if (phase === "after_step_apply" && mutation) await faultPoint(`recovery:${mutation}`);
        if (phase === "after_terminal_receipt_commit") await faultPoint("recovery:terminal_receipt_commit");
        if (phase === "after_terminal_record") await faultPoint("recovery:terminal_record");
      },
    });
    return;
  }
  const recoveryOutcome = operation === "deploy" ? "predeploy_restored" : "preserved_current_restored";
  await reconcileFunctionalReleaseTransaction(journalDirectory, {
    assertBindingAndObservedState: (journal) => {
      if (journal.binding.releaseId !== "fault-release" || journal.binding.operation !== operation) {
        throw new Error("fixture journal binding mismatch");
      }
    },
    steps: [
      {
        mutation: "service_stop_for_recovery",
        apply: () => mutateState("recovery", "service_stop_for_recovery", (state) => {
          if (state.service === "inactive") return false;
          state.service = "inactive";
          return true;
        }),
      },
      {
        mutation: "application_restore",
        apply: async () => {
          let state = readState();
          let mutated = false;
          if (state.application !== "old-app") {
            state.application = "old-app";
            state.recoveryCounts.application_restore =
              (state.recoveryCounts.application_restore ?? 0) + 1;
            writeState(state);
            mutated = true;
          }
          if (
            state.applicationSwap === "deploy-stranded" ||
            state.applicationSwap === "rollback-stranded"
          ) {
            // Model the real rollback recovery boundary: the live application
            // exchange is already durable, but the displaced forward path has
            // not yet been archived. A second SIGKILL here must not allow a
            // terminal record until a later recovery removes the ambiguity.
            await faultPoint("recovery:application_restore_exchange");
            state = readState();
            state.applicationSwap = operation === "deploy" ? "none" : "archived";
            writeState(state);
            mutated = true;
          }
          return mutated ? "mutated" : "already_exact";
        },
      },
      {
        mutation: "static_restore",
        apply: () => mutateState("recovery", "static_restore", (state) => {
          if (state.static === "old-static") return false;
          state.static = "old-static";
          return true;
        }),
      },
      {
        mutation: "database_restore",
        apply: () => mutateState("recovery", "database_restore", (state) => {
          if (state.database === "old-db") return false;
          state.database = "old-db";
          return true;
        }),
      },
      {
        mutation: "vault_restore",
        apply: () => mutateState("recovery", "vault_restore", (state) => {
          if (state.vault === "old-vault") return false;
          state.vault = "old-vault";
          return true;
        }),
      },
      {
        mutation: "deployment_receipt_restore",
        apply: () => mutateState("recovery", "deployment_receipt_restore", (state) => {
          if (state.receipt === "recovered") return false;
          state.receipt = "recovered";
          writeDurableFileAtomically(
            originalReceiptPath,
            `${canonicalReleaseTransactionJson({ releaseId: "fault-release", status: "recovered" })}\n`,
            { mode: 0o600 },
          );
          return true;
        }),
      },
      {
        mutation: "source_state_verification",
        apply: () => {
          const state = readState();
          if (
            state.application !== "old-app" || state.static !== "old-static" ||
            state.database !== "old-db" || state.vault !== "old-vault"
          ) throw new Error("source state was not restored before restart");
          return "already_exact";
        },
      },
      {
        mutation: "service_start",
        apply: () => mutateState("recovery", "service_start", (state) => {
          if (state.service === "active") return false;
          state.service = "active";
          return true;
        }),
      },
      {
        mutation: "running_state_verification",
        apply: () => {
          if (!exactSource(readState())) throw new Error("service intent or exact source identity is wrong");
          return "already_exact";
        },
      },
    ],
    terminalReceipt: () => ({
      path: recoveryReceiptPath,
      value: {
        schemaVersion: "fault-recovery.v1",
        transactionId: readFunctionalReleaseTransactionJournal(journalDirectory).binding.transactionId,
        outcome: recoveryOutcome,
      },
      outcome: recoveryOutcome,
    }),
    verifyTerminal: (terminal) => {
      const detail = terminalDetail(terminal);
      const path = String(detail.receiptPath);
      if (!existsSync(path) || releaseTransactionSha256(readFileSync(path)) !== detail.receiptSha256) {
        throw new Error("terminal receipt identity mismatch");
      }
      if (detail.outcome === "deployed" || detail.outcome === "rolled_back") {
        if (!exactTarget(readState())) throw new Error("completed forward identity mismatch");
      } else if (!exactSource(readState())) throw new Error("recovered source identity mismatch");
    },
    onPhase: async (phase, mutation) => {
      if (phase === "after_step_apply" && mutation) await faultPoint(`recovery:${mutation}`);
      if (phase === "after_terminal_receipt_commit") await faultPoint("recovery:terminal_receipt_commit");
      if (phase === "after_terminal_record") await faultPoint("recovery:terminal_record");
    },
  });
}

if (command === "forward") await runForward();
else if (command === "recover") await runRecovery();
else throw new Error("worker command must be forward or recover");

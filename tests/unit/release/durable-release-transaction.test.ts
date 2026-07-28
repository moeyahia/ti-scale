import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  appendFunctionalReleaseTransactionRecord,
  canonicalReleaseTransactionJson,
  commitFunctionalReleaseTransactionTarget,
  completeFunctionalReleaseMutation,
  createFunctionalReleaseTransactionJournal,
  discoverIncompleteFunctionalReleaseTransactions,
  type FunctionalReleaseJournalPublicationPhase,
  type DurableRecoveryOperations,
  prepareFunctionalReleaseMutation,
  readFunctionalReleaseTransactionJournal,
  reconcileFunctionalReleaseTransaction,
  releaseTransactionSha256,
} from "../../../scripts/release/DurableReleaseTransaction";
import { writeDurableFileAtomically } from "../../../scripts/release/DurableAtomicFile";
import { assertFunctionalReleaseTransactionAdmission } from "../../../scripts/release/functional-release";
import {
  RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
  RELEASE_SOURCE_RUNTIME_PROTOCOL,
} from "../../../scripts/release/ReleaseStartupMutationBarrier";

const roots: string[] = [];
const worker = join(process.cwd(), "tests/unit/release/fixtures/durable-release-fault-worker.ts");

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

interface FixtureState {
  application: string;
  applicationSwap: "none" | "deploy-stranded" | "rollback-stranded" | "archived";
  static: string;
  database: string;
  vault: string;
  service: string;
  receipt: string;
  forwardCounts: Record<string, number>;
  recoveryCounts: Record<string, number>;
}

function fixture(
  operation: "deploy" | "rollback" = "deploy",
): { workspace: string; journal: string; statePath: string; operation: "deploy" | "rollback" } {
  const workspace = mkdtempSync(join(tmpdir(), "ti-scale-durable-release-"));
  roots.push(workspace);
  const journal = join(workspace, "transaction-journal");
  const statePath = join(workspace, "state.json");
  const receiptPath = join(workspace, "original-receipt.json");
  writeDurableFileAtomically(statePath, `${canonicalReleaseTransactionJson({
    application: "old-app",
    applicationSwap: "none",
    static: "old-static",
    database: "old-db",
    vault: "old-vault",
    service: "active",
    receipt: "prepared",
    forwardCounts: {},
    recoveryCounts: {},
  })}\n`);
  writeDurableFileAtomically(
    receiptPath,
    `${canonicalReleaseTransactionJson({ releaseId: "fault-release", status: "prepared" })}\n`,
  );
  createFunctionalReleaseTransactionJournal({
    directory: journal,
    operation,
    releaseId: "fault-release",
    receiptPath,
    recoveryIntent: operation === "deploy" ? "restore_predeploy" : "restore_preserved_current",
    identity: {
      source: { application: "old-app", static: "old-static", database: "old-db", vault: "old-vault" },
      target: { application: "new-app", static: "new-static", database: "new-db", vault: "new-vault" },
    },
    transactionId: "fault-transaction",
    recordedAt: "2026-07-22T00:00:00.000Z",
  });
  return { workspace, journal, statePath, operation };
}

function journalBelow(
  root: string,
  name: string,
  options: {
    readonly operation?: "deploy" | "rollback";
    readonly terminal?: boolean;
  } = {},
): string {
  const bundle = join(root, name);
  mkdirSync(bundle, { recursive: true });
  const receiptPath = join(bundle, "deployment-receipt.json");
  writeDurableFileAtomically(
    receiptPath,
    `${canonicalReleaseTransactionJson({ releaseId: name, status: "prepared" })}\n`,
  );
  const journal = join(bundle, "transaction-journal");
  createFunctionalReleaseTransactionJournal({
    directory: journal,
    operation: options.operation ?? "deploy",
    releaseId: name,
    receiptPath,
    recoveryIntent: options.operation === "rollback"
      ? "restore_preserved_current"
      : "restore_predeploy",
    identity: {
      source: { application: "old-app" },
      target: { application: "new-app" },
    },
    transactionId: `${name}-transaction`,
    recordedAt: "2026-07-22T00:00:00.000Z",
  });
  if (options.terminal) {
    appendFunctionalReleaseTransactionRecord(journal, {
      event: "recovery_started",
      recordedAt: "2026-07-22T00:00:01.000Z",
      detail: {
        recoveryIntent: options.operation === "rollback"
          ? "restore_preserved_current"
          : "restore_predeploy",
      },
    });
    appendFunctionalReleaseTransactionRecord(journal, {
      event: "terminal",
      recordedAt: "2026-07-22T00:00:02.000Z",
      detail: {
        outcome: options.operation === "rollback"
          ? "preserved_current_restored"
          : "predeploy_restored",
        receiptPath,
        receiptSha256: "0".repeat(64),
      },
    });
  }
  return journal;
}

function completeTargetPrerequisites(journal: string): void {
  for (const mutation of [
    "service_stop",
    "application_activation",
    "static_activation",
    "target_data_verification",
  ] as const) {
    prepareFunctionalReleaseMutation(journal, "forward", mutation);
    completeFunctionalReleaseMutation(journal, "forward", mutation);
  }
}

function sourceRuntimeProtocolFixture(
  noBackupMode: false | true | "forward_v2" = false,
): ReturnType<typeof fixture> & {
  readonly sourceState: Readonly<Record<string, unknown>>;
} {
  const value = fixture();
  rmSync(value.journal, { recursive: true, force: true });
  const sourceState = Object.freeze({
    pointers: { application: "old-app", static: "old-static" },
    applicationTreeSha256: "1".repeat(64),
    databaseSchema: 38,
    databaseFingerprintPolicy: "canonical_content_v4",
    databaseFingerprint: "2".repeat(64),
    vaultFingerprintPolicy: "managed_tree_content_metadata_v1",
    vaultFingerprint: "3".repeat(64),
    serviceIntent: "active",
    previousInvocationId: "4".repeat(32),
  });
  createFunctionalReleaseTransactionJournal({
    directory: value.journal,
    operation: "deploy",
    releaseId: "fault-release",
    receiptPath: join(value.workspace, "original-receipt.json"),
    recoveryIntent: "restore_predeploy",
    identity: {
      releaseStartupProtocol: RELEASE_SOURCE_RUNTIME_PROTOCOL,
      ...(noBackupMode
        ? {
            deploymentKind: noBackupMode === "forward_v2"
              ? "no_backup_forward_v2"
              : "no_backup_preview_v1",
            ...(noBackupMode === "forward_v2"
              ? {
                  deploymentMode: "current_service",
                  releaseObserver: {
                    schemaVersion: "ti-scale.release-observer.v1",
                    mode: "standalone",
                    scope: "ti_scale_only",
                    externalServiceDependency: "none",
                  },
                }
              : {}),
            backupPolicy: "none",
          }
        : {}),
      predeploy: sourceState,
      target: { application: "new-app" },
    },
    transactionId: "fault-transaction",
    recordedAt: "2026-07-22T00:00:00.000Z",
  });
  return { ...value, sourceState };
}

function beginAndCommitSourceRuntime(
  value: ReturnType<typeof sourceRuntimeProtocolFixture>,
): void {
  appendFunctionalReleaseTransactionRecord(value.journal, {
    event: "recovery_started",
    detail: { recoveryIntent: "restore_predeploy" },
  });
  for (const mutation of [
    "service_stop_for_recovery",
    "source_state_verification",
    "service_start",
  ] as const) {
    prepareFunctionalReleaseMutation(value.journal, "recovery", mutation);
    completeFunctionalReleaseMutation(value.journal, "recovery", mutation);
  }
  prepareFunctionalReleaseMutation(
    value.journal,
    "recovery",
    RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
    {
      sourceState: value.sourceState,
      sourceStateSha256: releaseTransactionSha256(value.sourceState),
    },
  );
  completeFunctionalReleaseMutation(
    value.journal,
    "recovery",
    RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
    { outcome: "already_exact" },
  );
}

async function waitFor(path: string): Promise<void> {
  const deadline = performance.now() + 3_000;
  while (!existsSync(path) && performance.now() < deadline) await Bun.sleep(5);
  expect(existsSync(path)).toBe(true);
}

async function killWorker(
  command: "forward" | "recover",
  workspace: string,
  journal: string,
  phase: string,
): Promise<void> {
  const ready = join(workspace, "fault-ready");
  rmSync(ready, { force: true });
  const child = Bun.spawn([process.execPath, worker, command, workspace, journal, phase], {
    cwd: process.cwd(),
    stdout: "pipe",
    stderr: "pipe",
  });
  await waitFor(ready);
  child.kill("SIGKILL");
  await child.exited;
  expect(child.exitCode).not.toBe(0);
}

async function runRecovery(workspace: string, journal: string): Promise<void> {
  const child = Bun.spawn([process.execPath, worker, "recover", workspace, journal], {
    cwd: process.cwd(),
    stdout: "pipe",
    stderr: "pipe",
  });
  const exitCode = await child.exited;
  const stderr = await new Response(child.stderr).text();
  expect(exitCode, stderr).toBe(0);
}

function readState(path: string): FixtureState {
  return JSON.parse(readFileSync(path, "utf8")) as FixtureState;
}

function expectRecovered(fixtureValue: ReturnType<typeof fixture>): void {
  const state = readState(fixtureValue.statePath);
  expect(state).toMatchObject({
    application: "old-app",
    static: "old-static",
    database: "old-db",
    vault: "old-vault",
    service: "active",
    receipt: "recovered",
  });
  expect(state.applicationSwap).not.toBe("deploy-stranded");
  expect(state.applicationSwap).not.toBe("rollback-stranded");
  if (fixtureValue.operation === "deploy") expect(state.applicationSwap).toBe("none");
  const journal = readFunctionalReleaseTransactionJournal(fixtureValue.journal);
  expect(journal.terminal?.detail?.outcome).toBe(
    fixtureValue.operation === "deploy" ? "predeploy_restored" : "preserved_current_restored",
  );
  const receiptPath = String(journal.terminal?.detail?.receiptPath);
  expect(lstatSync(receiptPath).isFile()).toBe(true);
  expect(releaseTransactionSha256(readFileSync(receiptPath))).toBe(
    String(journal.terminal?.detail?.receiptSha256),
  );
}

function expectCommittedTarget(fixtureValue: ReturnType<typeof fixture>): void {
  const state = readState(fixtureValue.statePath);
  expect(state).toMatchObject({
    application: "new-app",
    static: "new-static",
    database: "new-db-with-acknowledged-write",
    vault: "new-vault-with-acknowledged-write",
    service: "active",
    receipt: "deployed",
  });
  expect(readFunctionalReleaseTransactionJournal(fixtureValue.journal).terminal?.detail?.outcome).toBe(
    fixtureValue.operation === "deploy" ? "deployed" : "rolled_back",
  );
}

describe("durable functional release transaction journal", () => {
  test("never publishes a discoverable zero-record journal across opening crash phases", () => {
    const workspace = mkdtempSync(join(tmpdir(), "ti-scale-journal-publication-"));
    roots.push(workspace);
    const phases: FunctionalReleaseJournalPublicationPhase[] = [
      "staging_directory_created",
      "opening_record_committed",
      "staging_directory_synced",
      "final_name_renamed",
      "final_parent_synced",
    ];

    for (const [index, crashPhase] of phases.entries()) {
      const bundle = join(workspace, `case-${index}`);
      mkdirSync(bundle);
      const receiptPath = join(bundle, "deployment-receipt.json");
      writeFileSync(receiptPath, "{}\n");
      const journal = join(bundle, "transaction-journal");
      expect(() => createFunctionalReleaseTransactionJournal({
        directory: journal,
        operation: "deploy",
        releaseId: `publication-${index}`,
        receiptPath,
        recoveryIntent: "restore_predeploy",
        identity: { source: "old", target: "new" },
        transactionId: `publication-transaction-${index}`,
        recordedAt: "2026-07-22T00:00:00.000Z",
        onPublicationPhase: (phase) => {
          if (phase === crashPhase) throw new Error(`crash:${phase}`);
        },
      })).toThrow(`crash:${crashPhase}`);

      const finalNameWasPublished = crashPhase === "final_name_renamed" ||
        crashPhase === "final_parent_synced";
      expect(existsSync(journal)).toBe(finalNameWasPublished);
      if (finalNameWasPublished) {
        expect(readFunctionalReleaseTransactionJournal(journal).latest.event).toBe("opened");
        expect(discoverIncompleteFunctionalReleaseTransactions(bundle)).toEqual([
          expect.objectContaining({ directory: journal, latestEvent: "opened" }),
        ]);
      } else {
        expect(discoverIncompleteFunctionalReleaseTransactions(bundle)).toEqual([]);
      }
    }
  });

  test("SIGKILL before target commitment recovers exact source state without retrying forward work", async () => {
    const phases = [
      "service_stop",
      "application_activation",
      "static_activation",
      "database_mutation",
      "vault_mutation",
      "target_data_verification",
    ];
    for (const phase of phases) {
      const value = fixture();
      await killWorker("forward", value.workspace, value.journal, phase);
      await runRecovery(value.workspace, value.journal);
      const once = readState(value.statePath);
      const counts = { ...once.recoveryCounts };
      await runRecovery(value.workspace, value.journal);
      expect(readState(value.statePath).recoveryCounts).toEqual(counts);
      expectRecovered(value);
      for (const count of Object.values(readState(value.statePath).forwardCounts)) expect(count).toBe(1);
    }
  }, 30_000);

  test("an incomplete rollback SIGKILL at every forward phase restores the preserved current identity", async () => {
    const phases = [
      "service_stop",
      "application_activation",
      "static_activation",
      "database_mutation",
      "vault_mutation",
      "target_data_verification",
    ];
    for (const phase of phases) {
      const value = fixture("rollback");
      await killWorker("forward", value.workspace, value.journal, phase);
      await runRecovery(value.workspace, value.journal);
      expectRecovered(value);
      const once = { ...readState(value.statePath).recoveryCounts };
      await runRecovery(value.workspace, value.journal);
      expect(readState(value.statePath).recoveryCounts).toEqual(once);
    }
  }, 30_000);

  test("SIGKILL after target commitment completes forward and preserves acknowledged target writes", async () => {
    const phases = [
      "target_committed",
      "service_start",
      "deployment_receipt_commit",
      "terminal_record",
    ];
    for (const operation of ["deploy", "rollback"] as const) {
      for (const phase of phases) {
        const value = fixture(operation);
        await killWorker("forward", value.workspace, value.journal, phase);
        await runRecovery(value.workspace, value.journal);
        expectCommittedTarget(value);
        const once = { ...readState(value.statePath).recoveryCounts };
        await runRecovery(value.workspace, value.journal);
        expect(readState(value.statePath).recoveryCounts).toEqual(once);
        expectCommittedTarget(value);
      }
    }
  }, 30_000);

  test("SIGKILL throughout postcommit reconciliation never restores or rejects target writes", async () => {
    const phases = [
      "target_state_verification",
      "service_start",
      "deployment_receipt_commit",
      "running_state_verification",
      "terminal_receipt_commit",
      "terminal_record",
    ];
    for (const operation of ["deploy", "rollback"] as const) {
      for (const phase of phases) {
        const value = fixture(operation);
        await killWorker("forward", value.workspace, value.journal, "target_committed");
        await killWorker("recover", value.workspace, value.journal, `recovery:${phase}`);
        await runRecovery(value.workspace, value.journal);
        expectCommittedTarget(value);
        const before = { ...readState(value.statePath).recoveryCounts };
        await runRecovery(value.workspace, value.journal);
        expect(readState(value.statePath).recoveryCounts).toEqual(before);
      }
    }
  }, 45_000);

  test("SIGKILL after every recovery mutation and terminal publication resumes without duplicate mutation", async () => {
    const phases = [
      "service_stop_for_recovery",
      "application_restore",
      "static_restore",
      "database_restore",
      "vault_restore",
      "deployment_receipt_restore",
      "source_state_verification",
      "service_start",
      "running_state_verification",
      "terminal_receipt_commit",
      "terminal_record",
    ];
    for (const phase of phases) {
      const value = fixture();
      await killWorker("forward", value.workspace, value.journal, "static_activation");
      await killWorker("recover", value.workspace, value.journal, `recovery:${phase}`);
      await runRecovery(value.workspace, value.journal);
      expectRecovered(value);
      const counts = readState(value.statePath).recoveryCounts;
      for (const count of Object.values(counts)) expect(count).toBe(1);
      const before = JSON.stringify(counts);
      await runRecovery(value.workspace, value.journal);
      expect(JSON.stringify(readState(value.statePath).recoveryCounts)).toBe(before);
    }
  }, 45_000);

  test("a second SIGKILL after rollback recovery exchange resumes stranded-path cleanup before terminal success", async () => {
    const value = fixture("rollback");
    await killWorker("forward", value.workspace, value.journal, "application_activation_exchange");
    expect(readState(value.statePath).applicationSwap).toBe("rollback-stranded");

    await killWorker(
      "recover",
      value.workspace,
      value.journal,
      "recovery:application_restore_exchange",
    );
    expect(readState(value.statePath)).toMatchObject({
      application: "old-app",
      applicationSwap: "rollback-stranded",
    });
    expect(readFunctionalReleaseTransactionJournal(value.journal).terminal).toBeUndefined();

    await runRecovery(value.workspace, value.journal);
    expectRecovered(value);
    expect(readState(value.statePath).recoveryCounts.application_restore).toBe(1);
  }, 15_000);

  test("a second SIGKILL after deploy recovery exchange removes its stranded target before terminal success", async () => {
    const value = fixture("deploy");
    await killWorker("forward", value.workspace, value.journal, "application_activation_exchange");
    expect(readState(value.statePath).applicationSwap).toBe("deploy-stranded");

    await killWorker(
      "recover",
      value.workspace,
      value.journal,
      "recovery:application_restore_exchange",
    );
    expect(readState(value.statePath)).toMatchObject({
      application: "old-app",
      applicationSwap: "deploy-stranded",
    });
    expect(readFunctionalReleaseTransactionJournal(value.journal).terminal).toBeUndefined();

    await runRecovery(value.workspace, value.journal);
    expectRecovered(value);
    expect(readState(value.statePath).applicationSwap).toBe("none");
    expect(readState(value.statePath).recoveryCounts.application_restore).toBe(1);
  }, 15_000);

  test("recognizes a completed forward terminal idempotently", async () => {
    const value = fixture();
    const child = Bun.spawn([process.execPath, worker, "forward", value.workspace, value.journal], {
      cwd: process.cwd(), stdout: "pipe", stderr: "pipe",
    });
    expect(await child.exited, await new Response(child.stderr).text()).toBe(0);
    const before = readState(value.statePath);
    await runRecovery(value.workspace, value.journal);
    expect(readState(value.statePath)).toEqual(before);
    expect(readFunctionalReleaseTransactionJournal(value.journal).terminal?.detail?.outcome).toBe("deployed");
  });

  test("refuses tampered, spliced, malformed-time, and symlink-ancestor journals", () => {
    const value = fixture();
    const record = readdirSync(value.journal).find((name) => name.endsWith(".json"))!;
    const path = join(value.journal, record);
    writeDurableFileAtomically(path, readFileSync(path, "utf8").replace("fault-release", "other-release"));
    expect(() => readFunctionalReleaseTransactionJournal(value.journal)).toThrow("tampered journal refused");

    const malformed = fixture();
    expect(() => appendFunctionalReleaseTransactionRecord(malformed.journal, {
      event: "evidence",
      recordedAt: "tomorrow",
      detail: { kind: "invalid-time" },
    })).toThrow("timestamp is invalid");

    const ancestry = fixture();
    const link = join(ancestry.workspace, "journal-link");
    symlinkSync(ancestry.journal, link);
    expect(() => readFunctionalReleaseTransactionJournal(link)).toThrow(/real directory|symbolic-link ancestry/u);
  });

  test("discovers only nonterminal journals and release admission requires their exact reconciliation", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-release-admission-"));
    roots.push(root);
    const active = journalBelow(root, "active-release");
    journalBelow(root, "terminal-release", { terminal: true });

    expect(discoverIncompleteFunctionalReleaseTransactions(root)).toEqual([
      expect.objectContaining({
        directory: active,
        operation: "deploy",
        releaseId: "active-release",
        latestEvent: "opened",
      }),
    ]);
    expect(() => assertFunctionalReleaseTransactionAdmission({ command: "deploy" }, root))
      .toThrow("already owns release recovery");
    expect(() => assertFunctionalReleaseTransactionAdmission({ command: "rollback" }, root))
      .toThrow("already owns release recovery");
    expect(() => assertFunctionalReleaseTransactionAdmission({
      command: "reconcile",
      journalPath: join(root, "different", "transaction-journal"),
    }, root)).toThrow("Another nonterminal transaction owns release recovery");
    expect(() => assertFunctionalReleaseTransactionAdmission({
      command: "reconcile",
      journalPath: active,
    }, root)).not.toThrow();
  });

  test("fails closed when transaction ownership is ambiguous", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-release-ambiguous-"));
    roots.push(root);
    const first = journalBelow(root, "first-release");
    journalBelow(root, "second-release", { operation: "rollback" });
    expect(() => assertFunctionalReleaseTransactionAdmission({
      command: "reconcile",
      journalPath: first,
    }, root)).toThrow("Release recovery is ambiguous: 2 nonterminal transaction journals");
  });

  test("transaction discovery rejects symlinks, excessive depth, and excessive entries", () => {
    const symlinkRoot = mkdtempSync(join(tmpdir(), "ti-scale-release-symlink-discovery-"));
    roots.push(symlinkRoot);
    const outside = mkdtempSync(join(tmpdir(), "ti-scale-release-symlink-target-"));
    roots.push(outside);
    symlinkSync(outside, join(symlinkRoot, "redirect"));
    expect(() => discoverIncompleteFunctionalReleaseTransactions(symlinkRoot))
      .toThrow("refuses symbolic links");

    const deepRoot = mkdtempSync(join(tmpdir(), "ti-scale-release-depth-discovery-"));
    roots.push(deepRoot);
    let current = deepRoot;
    for (let index = 0; index < 10; index += 1) {
      current = join(current, `level-${String(index)}`);
      mkdirSync(current);
    }
    expect(() => discoverIncompleteFunctionalReleaseTransactions(deepRoot))
      .toThrow("exceeded its bounded directory depth");

    const entriesRoot = mkdtempSync(join(tmpdir(), "ti-scale-release-entry-discovery-"));
    roots.push(entriesRoot);
    for (let index = 0; index <= 20_000; index += 1) {
      writeFileSync(join(entriesRoot, `entry-${String(index).padStart(5, "0")}`), "");
    }
    expect(() => discoverIncompleteFunctionalReleaseTransactions(entriesRoot))
      .toThrow("exceeded its bounded entry count");
  }, 30_000);

  test("publishes target commitment only at a complete forward boundary and never poisons the journal", () => {
    const value = fixture();
    prepareFunctionalReleaseMutation(value.journal, "forward", "service_stop");
    completeFunctionalReleaseMutation(value.journal, "forward", "service_stop");
    prepareFunctionalReleaseMutation(value.journal, "forward", "application_activation");
    expect(() => commitFunctionalReleaseTransactionTarget(value.journal, { state: "new" }))
      .toThrow("incomplete forward mutations");
    expect(readFunctionalReleaseTransactionJournal(value.journal).latest.event).toBe("mutation_prepared");
    completeFunctionalReleaseMutation(value.journal, "forward", "application_activation");
    prepareFunctionalReleaseMutation(value.journal, "forward", "static_activation");
    completeFunctionalReleaseMutation(value.journal, "forward", "static_activation");
    prepareFunctionalReleaseMutation(value.journal, "forward", "target_data_verification");
    completeFunctionalReleaseMutation(value.journal, "forward", "target_data_verification");
    const committed = commitFunctionalReleaseTransactionTarget(value.journal, {
      application: "new-app",
      database: "new-db",
    });
    expect(committed.latest.event).toBe("target_committed");
    expect(committed.latest.detail?.targetStateSha256).toBe(
      releaseTransactionSha256({ application: "new-app", database: "new-db" }),
    );
    expect(() => commitFunctionalReleaseTransactionTarget(value.journal, { state: "different" }))
      .toThrow("duplicated");
    expect(readFunctionalReleaseTransactionJournal(value.journal).latest.event).toBe("target_committed");
  });

  test("rejects source restoration immediately after target commitment and allows only forward reconciliation", async () => {
    const value = fixture();
    completeTargetPrerequisites(value.journal);
    commitFunctionalReleaseTransactionTarget(value.journal, { state: "new" });
    let sourceOperationReached = false;
    await expect(reconcileFunctionalReleaseTransaction(value.journal, {
      reconciliationIntent: "restore_source",
      assertBindingAndObservedState: () => { sourceOperationReached = true; },
      steps: [
        { mutation: "service_start", apply: () => "already_exact" },
        { mutation: "deployment_receipt_commit", apply: () => "already_exact" },
      ],
      terminalReceipt: () => ({
        path: join(value.workspace, "forbidden-source-receipt.json"),
        value: { outcome: "predeploy_restored" },
        outcome: "predeploy_restored",
      }),
      verifyTerminal: () => {},
    })).rejects.toThrow("may not enter source-restoration recovery");
    expect(sourceOperationReached).toBe(false);

    const forwardReceipt = join(value.workspace, "forward-receipt.json");
    const result = await reconcileFunctionalReleaseTransaction(value.journal, {
      reconciliationIntent: "complete_target",
      assertBindingAndObservedState: () => {},
      steps: [
        { mutation: "service_start", apply: () => "already_exact" },
        { mutation: "deployment_receipt_commit", apply: () => "already_exact" },
      ],
      terminalReceipt: () => ({
        path: forwardReceipt,
        value: { outcome: "deployed", target: "new" },
        outcome: "deployed",
      }),
      verifyTerminal: (terminal) => {
        expect(terminal.detail?.outcome).toBe("deployed");
      },
    });
    expect(result).toBe("recovered");
    expect(readFunctionalReleaseTransactionJournal(value.journal).terminal?.detail?.outcome).toBe("deployed");
  });

  test("keeps recovery ownership nonterminal until final target and receipt verification succeeds", async () => {
    const value = fixture();
    const terminalReceipt = join(value.workspace, "verified-recovery-receipt.json");
    let verificationMayPass = false;
    const operations = (): DurableRecoveryOperations => ({
      assertBindingAndObservedState: () => {},
      steps: [],
      terminalReceipt: () => ({
        path: terminalReceipt,
        value: { outcome: "predeploy_restored", source: "old" },
        outcome: "predeploy_restored" as const,
      }),
      verifyTerminal: (proposedTerminal) => {
        expect(proposedTerminal.event).toBe("terminal");
        expect(readFunctionalReleaseTransactionJournal(value.journal).terminal).toBeUndefined();
        if (!verificationMayPass) throw new Error("simulated final service verification failure");
      },
    });

    await expect(reconcileFunctionalReleaseTransaction(value.journal, operations()))
      .rejects.toThrow("simulated final service verification failure");
    const failed = readFunctionalReleaseTransactionJournal(value.journal);
    expect(failed.terminal).toBeUndefined();
    expect(failed.latest.event).toBe("mutation_completed");
    expect(failed.latest.mutation).toBe("terminal_receipt_commit");
    expect(discoverIncompleteFunctionalReleaseTransactions(value.workspace)).toEqual([
      expect.objectContaining({ directory: value.journal }),
    ]);

    verificationMayPass = true;
    expect(await reconcileFunctionalReleaseTransaction(value.journal, operations())).toBe("recovered");
    expect(readFunctionalReleaseTransactionJournal(value.journal).terminal?.detail?.outcome)
      .toBe("predeploy_restored");
    expect(discoverIncompleteFunctionalReleaseTransactions(value.workspace)).toEqual([]);
  });

  test("requires the complete source-runtime commit, receipt, activation, and running proof before terminal", () => {
    const withoutCommit = sourceRuntimeProtocolFixture();
    appendFunctionalReleaseTransactionRecord(withoutCommit.journal, {
      event: "recovery_started",
      detail: { recoveryIntent: "restore_predeploy" },
    });
    expect(() => appendFunctionalReleaseTransactionRecord(withoutCommit.journal, {
      event: "terminal",
      detail: { outcome: "predeploy_restored" },
    })).toThrow("cannot terminate without its durable source commitment");

    const value = sourceRuntimeProtocolFixture();
    beginAndCommitSourceRuntime(value);
    expect(() => appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "terminal",
      detail: { outcome: "predeploy_restored" },
    })).toThrow("cannot terminate before receipt restoration and real application verification");

    for (const mutation of [
      "deployment_receipt_restore",
      "runtime_activation",
      "running_state_verification",
    ] as const) {
      prepareFunctionalReleaseMutation(value.journal, "recovery", mutation);
      completeFunctionalReleaseMutation(value.journal, "recovery", mutation);
    }
    expect(() => appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "terminal",
      detail: { outcome: "predeploy_restored" },
    })).not.toThrow();
  });

  test("a no-backup source terminal requires exact restored and final receipt commitments", () => {
    const value = sourceRuntimeProtocolFixture(true);
    const receiptPath = join(value.workspace, "original-receipt.json");
    const restoredReceiptSha256 = "5".repeat(64);
    const restoredLegacySha256 = "6".repeat(64);
    const terminalLegacy = {
      activeState: "active",
      mainPid: 3131,
      invocationId: "8".repeat(32),
      healthStatus: 200,
      semanticStatus: "ok",
    };
    const terminalReceipt = {
      status: "failed_predeploy_restored",
      chillspwnAfter: terminalLegacy,
    };
    const terminalReceiptSha256 = createHash("sha256").update(
      `${JSON.stringify(
        JSON.parse(canonicalReleaseTransactionJson(terminalReceipt)),
        null,
        2,
      )}\n`,
    ).digest("hex");
    const terminalLegacySha256 =
      releaseTransactionSha256(terminalLegacy);
    beginAndCommitSourceRuntime(value);
    prepareFunctionalReleaseMutation(
      value.journal,
      "recovery",
      "deployment_receipt_restore",
      {
        receiptPath,
        receiptSha256: restoredReceiptSha256,
        legacyIdentitySha256: restoredLegacySha256,
      },
    );
    completeFunctionalReleaseMutation(
      value.journal,
      "recovery",
      "deployment_receipt_restore",
      {
        receiptPath,
        receiptSha256: restoredReceiptSha256,
        legacyIdentitySha256: restoredLegacySha256,
      },
    );
    for (const mutation of [
      "runtime_activation",
      "running_state_verification",
    ] as const) {
      prepareFunctionalReleaseMutation(value.journal, "recovery", mutation);
      completeFunctionalReleaseMutation(value.journal, "recovery", mutation);
    }
    expect(() => appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "terminal",
      detail: {
        outcome: "predeploy_restored",
        receiptPath,
        receiptSha256: terminalReceiptSha256,
        legacyIdentitySha256: terminalLegacySha256,
        receiptLegacyIdentitySha256: terminalLegacySha256,
        reconciliationLegacyIdentitySha256: terminalLegacySha256,
        restoredReceiptSha256,
        restoredLegacyIdentitySha256: restoredLegacySha256,
      },
    })).toThrow("source recovery terminal lacks its exact committed receipt");

    prepareFunctionalReleaseMutation(
      value.journal,
      "recovery",
      "terminal_receipt_commit",
      {
        receiptPath,
        receipt: terminalReceipt,
        receiptSha256: terminalReceiptSha256,
        legacyIdentitySha256: terminalLegacySha256,
      },
    );
    completeFunctionalReleaseMutation(
      value.journal,
      "recovery",
      "terminal_receipt_commit",
      {
        receiptPath,
        receiptSha256: terminalReceiptSha256,
        legacyIdentitySha256: terminalLegacySha256,
      },
    );
    expect(() => appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "terminal",
      detail: {
        outcome: "predeploy_restored",
        receiptPath,
        receiptSha256: terminalReceiptSha256,
        legacyIdentitySha256: terminalLegacySha256,
        receiptLegacyIdentitySha256: terminalLegacySha256,
        reconciliationLegacyIdentitySha256: terminalLegacySha256,
        restoredReceiptSha256,
        restoredLegacyIdentitySha256: restoredLegacySha256,
      },
    })).not.toThrow();
  });

  test("v2 rejects tampered prepared, completed, and terminal observer commitments", () => {
    const value = sourceRuntimeProtocolFixture("forward_v2");
    const receiptPath = join(value.workspace, "original-receipt.json");
    const observer = {
      schemaVersion: "ti-scale.release-observer.v1",
      mode: "standalone",
      scope: "ti_scale_only",
      externalServiceDependency: "none",
    };
    const observerSha256 = releaseTransactionSha256(observer);
    const receipt = {
      schemaVersion: "ti-scale.no-backup-forward-release-receipt.v2",
      deploymentMode: "current_service",
      releaseObserver: observer,
      status: "deployed",
    };
    const receiptSha256 = createHash("sha256").update(
      `${JSON.stringify(
        JSON.parse(canonicalReleaseTransactionJson(receipt)),
        null,
        2,
      )}\n`,
    ).digest("hex");

    completeTargetPrerequisites(value.journal);
    commitFunctionalReleaseTransactionTarget(value.journal, {
      databaseSchema: 60,
      pointers: { application: "new-app", static: "new-static" },
    });
    for (const mutation of [
      "service_start",
      "running_state_verification",
    ] as const) {
      prepareFunctionalReleaseMutation(
        value.journal,
        "forward",
        mutation,
      );
      completeFunctionalReleaseMutation(
        value.journal,
        "forward",
        mutation,
      );
    }

    expect(() => prepareFunctionalReleaseMutation(
      value.journal,
      "forward",
      "deployment_receipt_commit",
      {
        receiptPath,
        receipt: {
          ...receipt,
          releaseObserver: {
            ...observer,
            externalServiceDependency: "tampered",
          },
        },
        receiptSha256,
        observerProofSha256: observerSha256,
      },
    )).toThrow("immutable prepared intent");
    expect(() => prepareFunctionalReleaseMutation(
      value.journal,
      "forward",
      "deployment_receipt_commit",
      {
        receiptPath,
        receipt,
        receiptSha256,
        observerProofSha256: "a".repeat(64),
      },
    )).toThrow("immutable prepared intent");

    prepareFunctionalReleaseMutation(
      value.journal,
      "forward",
      "deployment_receipt_commit",
      {
        receiptPath,
        receipt,
        receiptSha256,
        observerProofSha256: observerSha256,
      },
    );
    expect(() => completeFunctionalReleaseMutation(
      value.journal,
      "forward",
      "deployment_receipt_commit",
      {
        receiptPath,
        receiptSha256,
        observerProofSha256: "b".repeat(64),
      },
    )).toThrow("completion differs from its prepared intent");
    completeFunctionalReleaseMutation(
      value.journal,
      "forward",
      "deployment_receipt_commit",
      {
        receiptPath,
        receiptSha256,
        observerProofSha256: observerSha256,
      },
    );

    expect(() => appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "terminal",
      detail: {
        outcome: "deployed",
        deploymentMode: "current_service",
        receiptPath,
        receiptSha256,
        observerProofSha256: observerSha256,
        receiptObserverProofSha256: observerSha256,
        reconciliationObserverProofSha256: "c".repeat(64),
      },
    })).toThrow("exact committed receipt and observer proof");
    expect(() => appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "terminal",
      detail: {
        outcome: "deployed",
        deploymentMode: "current_service",
        receiptPath,
        receiptSha256,
        observerProofSha256: observerSha256,
        receiptObserverProofSha256: observerSha256,
        reconciliationObserverProofSha256: observerSha256,
      },
    })).not.toThrow();
  });

  test("v2 journal identity is bound to current-service standalone observation", () => {
    const observer = {
      schemaVersion: "ti-scale.release-observer.v1",
      mode: "standalone",
      scope: "ti_scale_only",
      externalServiceDependency: "none",
    };
    const malformedIdentities = [
      {
        deploymentKind: "no_backup_forward_v2",
        deploymentMode: "preview",
        backupPolicy: "none",
        releaseObserver: observer,
      },
      {
        deploymentKind: "no_backup_forward_v2",
        deploymentMode: "current_service",
        backupPolicy: "none",
        releaseObserver: {
          ...observer,
          externalServiceDependency: "port_3131",
        },
      },
      {
        deploymentKind: "no_backup_forward_v2",
        deploymentMode: "current_service",
        backupPolicy: "retained",
        releaseObserver: observer,
      },
    ] as const;

    for (const [index, identity] of malformedIdentities.entries()) {
      const workspace = mkdtempSync(
        join(tmpdir(), `ti-scale-v2-journal-identity-${index}-`),
      );
      roots.push(workspace);
      const receiptPath = join(workspace, "receipt.json");
      writeFileSync(receiptPath, "{}\n");
      expect(() => createFunctionalReleaseTransactionJournal({
        directory: join(workspace, "journal"),
        operation: "deploy",
        releaseId: `v2-identity-${index}`,
        receiptPath,
        recoveryIntent: "restore_predeploy",
        identity,
        transactionId: `v2-identity-transaction-${index}`,
      })).toThrow(
        "No-backup forward journal lacks its standalone current-service identity",
      );
    }
  });

  test("binds source commitment to immutable source state and forbids postcommit restore replay", () => {
    const wrongSource = sourceRuntimeProtocolFixture();
    appendFunctionalReleaseTransactionRecord(wrongSource.journal, {
      event: "recovery_started",
      detail: { recoveryIntent: "restore_predeploy" },
    });
    for (const mutation of [
      "service_stop_for_recovery",
      "source_state_verification",
      "service_start",
    ] as const) {
      prepareFunctionalReleaseMutation(wrongSource.journal, "recovery", mutation);
      completeFunctionalReleaseMutation(wrongSource.journal, "recovery", mutation);
    }
    const mismatched = { ...wrongSource.sourceState, serviceIntent: "inactive" };
    expect(() => prepareFunctionalReleaseMutation(
      wrongSource.journal,
      "recovery",
      RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
      {
        sourceState: mismatched,
        sourceStateSha256: releaseTransactionSha256(mismatched),
      },
    )).toThrow("does not match the immutable source identity");

    const committed = sourceRuntimeProtocolFixture();
    beginAndCommitSourceRuntime(committed);
    expect(() => prepareFunctionalReleaseMutation(
      committed.journal,
      "recovery",
      "application_restore",
    )).toThrow("not allowed after source-runtime commitment");
    expect(() => prepareFunctionalReleaseMutation(
      committed.journal,
      "recovery",
      "deployment_receipt_restore",
    )).not.toThrow();
  });

  test("post-source-commit reconciliation skips every precommit mutation and resumes receipt/runtime only", async () => {
    const value = sourceRuntimeProtocolFixture();
    beginAndCommitSourceRuntime(value);
    let forbiddenReplayCount = 0;
    const applied: string[] = [];
    const result = await reconcileFunctionalReleaseTransaction(value.journal, {
      assertBindingAndObservedState: () => {},
      steps: [
        {
          mutation: "application_restore",
          apply: () => {
            forbiddenReplayCount += 1;
            return "mutated";
          },
        },
        {
          mutation: "deployment_receipt_restore",
          apply: () => {
            applied.push("deployment_receipt_restore");
            return "already_exact";
          },
        },
        {
          mutation: "runtime_activation",
          apply: () => {
            applied.push("runtime_activation");
            return "mutated";
          },
        },
        {
          mutation: "running_state_verification",
          apply: () => {
            applied.push("running_state_verification");
            return "already_exact";
          },
        },
      ],
      terminalReceipt: () => ({
        path: join(value.workspace, "source-runtime-recovery-receipt.json"),
        value: { outcome: "predeploy_restored", source: "old" },
        outcome: "predeploy_restored",
      }),
      verifyTerminal: () => {},
    });
    expect(result).toBe("recovered");
    expect(forbiddenReplayCount).toBe(0);
    expect(applied).toEqual([
      "deployment_receipt_restore",
      "runtime_activation",
      "running_state_verification",
    ]);
    expect(readFunctionalReleaseTransactionJournal(value.journal).terminal?.detail?.outcome)
      .toBe("predeploy_restored");
  });

  test("a prepared source-runtime boundary resumes commitment first without reopening restore mutations", async () => {
    const value = sourceRuntimeProtocolFixture();
    appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "recovery_started",
      detail: { recoveryIntent: "restore_predeploy" },
    });
    for (const mutation of [
      "service_stop_for_recovery",
      "source_state_verification",
      "service_start",
    ] as const) {
      prepareFunctionalReleaseMutation(value.journal, "recovery", mutation);
      completeFunctionalReleaseMutation(value.journal, "recovery", mutation);
    }
    prepareFunctionalReleaseMutation(
      value.journal,
      "recovery",
      RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
      {
        sourceState: value.sourceState,
        sourceStateSha256: releaseTransactionSha256(value.sourceState),
      },
    );

    const applied: string[] = [];
    let forbiddenReplayCount = 0;
    await reconcileFunctionalReleaseTransaction(value.journal, {
      assertBindingAndObservedState: () => {},
      steps: [
        {
          mutation: "application_restore",
          apply: () => {
            forbiddenReplayCount += 1;
            return "mutated";
          },
        },
        {
          mutation: "deployment_receipt_restore",
          apply: () => {
            applied.push("deployment_receipt_restore");
            return "already_exact";
          },
        },
        {
          mutation: RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
          apply: () => {
            applied.push(RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION);
            return "already_exact";
          },
        },
        {
          mutation: "runtime_activation",
          apply: () => {
            applied.push("runtime_activation");
            return "mutated";
          },
        },
        {
          mutation: "running_state_verification",
          apply: () => {
            applied.push("running_state_verification");
            return "already_exact";
          },
        },
      ],
      terminalReceipt: () => ({
        path: join(value.workspace, "prepared-source-runtime-recovery-receipt.json"),
        value: { outcome: "predeploy_restored", source: "old" },
        outcome: "predeploy_restored",
      }),
      verifyTerminal: () => {},
    });
    expect(forbiddenReplayCount).toBe(0);
    expect(applied).toEqual([
      RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
      "deployment_receipt_restore",
      "runtime_activation",
      "running_state_verification",
    ]);
  });

  test("enforces operation-specific terminal outcomes and a monotonic postcommit mutation set", () => {
    const value = fixture();
    completeTargetPrerequisites(value.journal);
    commitFunctionalReleaseTransactionTarget(value.journal, { state: "new" });
    appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "recovery_started",
      detail: { recoveryIntent: "complete_target" },
    });
    expect(() => prepareFunctionalReleaseMutation(value.journal, "recovery", "database_restore"))
      .toThrow("not allowed after target commitment");
    expect(readFunctionalReleaseTransactionJournal(value.journal).latest.event).toBe("recovery_started");
    expect(() => appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "terminal",
      detail: { outcome: "rolled_back" },
    })).toThrow("expected deployed");
    expect(readFunctionalReleaseTransactionJournal(value.journal).latest.event).toBe("recovery_started");

    const uncommitted = fixture();
    expect(() => appendFunctionalReleaseTransactionRecord(uncommitted.journal, {
      event: "terminal",
      detail: { outcome: "predeploy_restored" },
    })).toThrow("cannot terminate before source recovery begins");
    expect(readFunctionalReleaseTransactionJournal(uncommitted.journal).latest.event).toBe("opened");
  });
});

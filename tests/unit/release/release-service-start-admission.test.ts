import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  appendFunctionalReleaseTransactionRecord,
  commitFunctionalReleaseTransactionTarget,
  completeFunctionalReleaseMutation,
  createFunctionalReleaseTransactionJournal,
  prepareFunctionalReleaseMutation,
  readFunctionalReleaseTransactionJournal,
  releaseTransactionSha256,
} from "../../../scripts/release/DurableReleaseTransaction";
import { acquireSharedReleaseLock } from "../../../scripts/release/ReleaseExecutionBoundary";
import {
  assertReleaseServiceStartAdmitted,
  authorizeNextReleaseServiceStart,
} from "../../../scripts/release/ReleaseServiceStartAdmission";
import {
  RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL,
  RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
  RELEASE_SOURCE_RUNTIME_PROTOCOL,
  releaseSourceRuntimeCommitted,
  releaseTargetRuntimeCommitPrepared,
} from "../../../scripts/release/ReleaseStartupMutationBarrier";

const roots: string[] = [];
const VALID_INVOCATION_ID = "a".repeat(32);
const NOW = new Date("2026-07-22T12:00:00.000Z");
const BOOT_A = "11111111-1111-4111-8111-111111111111";
const BOOT_B = "22222222-2222-4222-8222-222222222222";
const authorizationOwnerWorker = join(
  process.cwd(),
  "tests/unit/release/fixtures/release-start-authorization-owner-worker.ts",
);

interface AdmissionFixture {
  readonly workspace: string;
  readonly transactionRoot: string;
  readonly journal: string;
  readonly authorizationPath: string;
  readonly startupMutationBarrierPath: string;
  readonly lockPath: string;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function emptyFixture(): AdmissionFixture {
  const workspace = mkdtempSync(join(tmpdir(), "ti-scale-service-start-admission-"));
  roots.push(workspace);
  const transactionRoot = join(workspace, "releases");
  mkdirSync(transactionRoot, { recursive: true });
  return {
    workspace,
    transactionRoot,
    journal: join(transactionRoot, "unused", "transaction-journal"),
    authorizationPath: join(workspace, "service-start-authorization.json"),
    startupMutationBarrierPath: join(workspace, "startup-mutation.barrier"),
    lockPath: join(workspace, "release.lock"),
  };
}

function pendingServiceStartFixture(name = "release-a"): AdmissionFixture {
  const value = emptyFixture();
  const releaseDirectory = join(value.transactionRoot, name);
  mkdirSync(releaseDirectory, { recursive: true });
  const receiptPath = join(releaseDirectory, "deployment-receipt.json");
  writeFileSync(receiptPath, `${JSON.stringify({ releaseId: name, status: "prepared" })}\n`, {
    mode: 0o600,
  });
  const journal = join(releaseDirectory, "transaction-journal");
  createFunctionalReleaseTransactionJournal({
    directory: journal,
    operation: "deploy",
    releaseId: name,
    receiptPath,
    recoveryIntent: "restore_predeploy",
    identity: {
      source: { application: "source-app", static: "source-static" },
      target: { application: "target-app", static: "target-static" },
    },
    transactionId: `${name}-transaction`,
    recordedAt: "2026-07-22T11:59:00.000Z",
  });

  for (const mutation of [
    "service_stop",
    "application_activation",
    "static_activation",
    "target_data_verification",
  ] as const) {
    prepareFunctionalReleaseMutation(journal, "forward", mutation);
    completeFunctionalReleaseMutation(journal, "forward", mutation);
  }
  commitFunctionalReleaseTransactionTarget(journal, {
    application: "target-app",
    static: "target-static",
  });
  prepareFunctionalReleaseMutation(journal, "forward", "service_start");

  return { ...value, journal };
}

function pendingSourceRecoveryStartFixture(name = "release-source"): AdmissionFixture & {
  readonly sourceState: Readonly<Record<string, unknown>>;
} {
  const value = emptyFixture();
  const releaseDirectory = join(value.transactionRoot, name);
  mkdirSync(releaseDirectory, { recursive: true });
  const receiptPath = join(releaseDirectory, "deployment-receipt.json");
  writeFileSync(receiptPath, `${JSON.stringify({ releaseId: name, status: "failed" })}\n`, {
    mode: 0o600,
  });
  const sourceState = Object.freeze({
    pointers: { application: "/opt/source", static: "static-source" },
    applicationTreeSha256: "1".repeat(64),
    databaseSchema: 38,
    databaseFingerprint: "2".repeat(64),
    vaultFingerprint: "3".repeat(64),
    serviceIntent: "active",
  });
  const journal = join(releaseDirectory, "transaction-journal");
  createFunctionalReleaseTransactionJournal({
    directory: journal,
    operation: "deploy",
    releaseId: name,
    receiptPath,
    recoveryIntent: "restore_predeploy",
    identity: {
      releaseStartupProtocol: RELEASE_SOURCE_RUNTIME_PROTOCOL,
      predeploy: sourceState,
      target: { application: "/opt/target" },
    },
    transactionId: `${name}-transaction`,
    recordedAt: "2026-07-22T11:59:00.000Z",
  });
  appendFunctionalReleaseTransactionRecord(journal, {
    event: "recovery_started",
    detail: { recoveryIntent: "restore_predeploy" },
  });
  for (const mutation of ["service_stop_for_recovery", "source_state_verification"] as const) {
    prepareFunctionalReleaseMutation(journal, "recovery", mutation);
    completeFunctionalReleaseMutation(journal, "recovery", mutation);
  }
  prepareFunctionalReleaseMutation(journal, "recovery", "service_start");
  return { ...value, journal, sourceState };
}

function pendingTargetRuntimeStartFixture(
  name: string,
  options: {
    readonly protocol?: boolean;
    readonly commitTarget?: boolean;
    readonly direction?: "forward" | "recovery";
  } = {},
): AdmissionFixture {
  const value = emptyFixture();
  const releaseDirectory = join(value.transactionRoot, name);
  mkdirSync(releaseDirectory, { recursive: true });
  const receiptPath = join(releaseDirectory, "deployment-receipt.json");
  writeFileSync(receiptPath, `${JSON.stringify({ releaseId: name, status: "prepared" })}\n`, {
    mode: 0o600,
  });
  const target = Object.freeze({
    pointers: { application: "/opt/target", static: "static-target" },
    databaseSchema: 48,
  });
  const journal = join(releaseDirectory, "transaction-journal");
  createFunctionalReleaseTransactionJournal({
    directory: journal,
    operation: "deploy",
    releaseId: name,
    receiptPath,
    recoveryIntent: "restore_predeploy",
    identity: {
      ...(options.protocol === false
        ? {}
        : { targetRuntimeCommitProtocol: RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL }),
      predeploy: { databaseSchema: 47 },
      target,
    },
    transactionId: `${name}-transaction`,
    recordedAt: "2026-07-22T11:59:00.000Z",
  });
  if (options.commitTarget !== false) {
    for (const mutation of [
      "service_stop",
      "application_activation",
      "static_activation",
      "target_data_verification",
    ] as const) {
      prepareFunctionalReleaseMutation(journal, "forward", mutation);
      completeFunctionalReleaseMutation(journal, "forward", mutation);
    }
    commitFunctionalReleaseTransactionTarget(journal, target);
  }
  const direction = options.direction ?? "recovery";
  if (direction === "recovery") {
    appendFunctionalReleaseTransactionRecord(journal, {
      event: "recovery_started",
      detail: {
        recoveryIntent: options.commitTarget === false
          ? "restore_predeploy"
          : "complete_target",
      },
    });
  }
  prepareFunctionalReleaseMutation(journal, direction, "service_start");
  completeFunctionalReleaseMutation(journal, direction, "service_start");
  prepareFunctionalReleaseMutation(
    journal,
    direction,
    "running_state_verification",
    {
      targetState: target,
      targetStateSha256: releaseTransactionSha256(target),
    },
  );
  return { ...value, journal };
}

function admissionOptions(value: AdmissionFixture, invocationId = VALID_INVOCATION_ID) {
  return {
    transactionRoot: value.transactionRoot,
    releaseLockPath: value.lockPath,
    authorizationPath: value.authorizationPath,
    startupMutationBarrierPath: value.startupMutationBarrierPath,
    invocationId,
    now: NOW,
  } as const;
}

describe("release service start admission", () => {
  test("fails closed when the canonical transaction root is missing", () => {
    const value = emptyFixture();
    rmSync(value.transactionRoot, { recursive: true, force: true });
    expect(() => assertReleaseServiceStartAdmitted(admissionOptions(value)))
      .toThrow("Release transaction root is missing");
  });

  test("admits ordinary startup only when no nonterminal transaction or stale token exists", () => {
    const value = emptyFixture();
    let lockProbeCalled = false;
    expect(assertReleaseServiceStartAdmitted({
      ...admissionOptions(value),
      releaseLockHeld: () => {
        lockProbeCalled = true;
        return false;
      },
    })).toEqual({ mode: "ordinary" });
    expect(lockProbeCalled).toBe(false);

    writeFileSync(value.authorizationPath, "stale\n", { mode: 0o600 });
    expect(() => assertReleaseServiceStartAdmitted(admissionOptions(value)))
      .toThrow("Stale release service start authorization exists without a nonterminal transaction");
  });

  test("denies a nonterminal transaction without an exact authorization", () => {
    const value = pendingServiceStartFixture();
    expect(() => assertReleaseServiceStartAdmitted(admissionOptions(value)))
      .toThrow("startup is blocked pending explicit release reconciliation");
  });

  test("admits and consumes one exact authorization while the shared lock is active", () => {
    const value = pendingServiceStartFixture();
    const lock = acquireSharedReleaseLock(value.lockPath, "start-admission-test");
    try {
      const authorization = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: NOW,
      });
      expect(authorization.transactionId).toBe("release-a-transaction");
      expect(existsSync(value.authorizationPath)).toBe(true);
      expect(statSync(value.authorizationPath).mode & 0o777).toBe(0o600);

      expect(assertReleaseServiceStartAdmitted(admissionOptions(value))).toEqual({
        mode: "journal_authorized",
        transactionId: "release-a-transaction",
      });
      expect(existsSync(value.authorizationPath)).toBe(false);
      expect(existsSync(value.startupMutationBarrierPath)).toBe(false);
      expect(() => assertReleaseServiceStartAdmitted(admissionOptions(value)))
        .toThrow("startup is blocked pending explicit release reconciliation");
      authorization.release();
    } finally {
      lock.release();
    }
  });

  test("fences precommit source recovery, then admits restart only after exact durable source commitment", () => {
    const value = pendingSourceRecoveryStartFixture();
    const lock = acquireSharedReleaseLock(value.lockPath, "source-recovery-start");
    try {
      const authorization = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: NOW,
      });
      expect(assertReleaseServiceStartAdmitted(admissionOptions(value))).toEqual({
        mode: "journal_authorized",
        transactionId: "release-source-transaction",
      });
      expect(existsSync(value.startupMutationBarrierPath)).toBe(true);
      authorization.release();

      completeFunctionalReleaseMutation(value.journal, "recovery", "service_start");
      prepareFunctionalReleaseMutation(
        value.journal,
        "recovery",
        RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
        {
          sourceState: value.sourceState,
          sourceStateSha256: releaseTransactionSha256(value.sourceState),
        },
      );

      // The guarded wrapper may die after service_start was durably completed
      // but before the source commitment is completed. The exact prepared
      // source_runtime_commit boundary must be able to issue another one-shot
      // start without reopening any pointer/data mutation.
      expect(() => assertReleaseServiceStartAdmitted({
        ...admissionOptions(value, "b".repeat(32)),
      })).toThrow("startup is blocked pending explicit release reconciliation");
      const commitmentRestart = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: NOW,
      });
      expect(assertReleaseServiceStartAdmitted({
        ...admissionOptions(value, "b".repeat(32)),
      })).toEqual({
        mode: "journal_authorized",
        transactionId: "release-source-transaction",
      });
      expect(existsSync(value.startupMutationBarrierPath)).toBe(true);
      commitmentRestart.release();

      completeFunctionalReleaseMutation(
        value.journal,
        "recovery",
        RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
        { outcome: "already_exact" },
      );
      expect(releaseSourceRuntimeCommitted(
        readFunctionalReleaseTransactionJournal(value.journal),
      )).toBe(true);
      expect(assertReleaseServiceStartAdmitted({
        ...admissionOptions(value, "c".repeat(32)),
      })).toEqual({
        mode: "source_runtime_committed",
        transactionId: "release-source-transaction",
      });
      expect(existsSync(value.startupMutationBarrierPath)).toBe(false);
    } finally { lock.release(); }
  });

  test("admits an exact prepared target-runtime commitment through one journal token", () => {
    const value = pendingTargetRuntimeStartFixture("target-runtime-prepared");
    expect(releaseTargetRuntimeCommitPrepared(
      readFunctionalReleaseTransactionJournal(value.journal),
    )).toBe(true);
    const lock = acquireSharedReleaseLock(value.lockPath, "target-runtime-prepared");
    try {
      const authorization = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: NOW,
      });
      expect(assertReleaseServiceStartAdmitted(admissionOptions(value))).toEqual({
        mode: "journal_authorized",
        transactionId: "target-runtime-prepared-transaction",
      });
      authorization.release();
    } finally {
      lock.release();
    }
  });

  test("rejects prepared running-state boundaries without target commit or protocol", () => {
    for (const [name, options] of [
      ["target-runtime-uncommitted", { commitTarget: false }],
      ["target-runtime-no-protocol", { protocol: false }],
    ] as const) {
      const value = pendingTargetRuntimeStartFixture(name, options);
      expect(releaseTargetRuntimeCommitPrepared(
        readFunctionalReleaseTransactionJournal(value.journal),
      )).toBe(false);
      const lock = acquireSharedReleaseLock(value.lockPath, `${name}-lock`);
      try {
        expect(() => authorizeNextReleaseServiceStart(value.journal, {
          authorizationPath: value.authorizationPath,
          now: NOW,
        })).toThrow("uncommitted or non-exact target-runtime boundary");
      } finally {
        lock.release();
      }
    }
  });

  test("admits the latest recovery runtime after an earlier forward running proof", () => {
    const value = pendingTargetRuntimeStartFixture(
      "target-runtime-double-proof",
      { direction: "forward" },
    );
    const target = {
      pointers: { application: "/opt/target", static: "static-target" },
      databaseSchema: 48,
    };
    completeFunctionalReleaseMutation(
      value.journal,
      "forward",
      "running_state_verification",
      {
        outcome: "already_exact",
        invocationId: "b".repeat(32),
        targetState: target,
        targetStateSha256: releaseTransactionSha256(target),
      },
    );
    appendFunctionalReleaseTransactionRecord(value.journal, {
      event: "recovery_started",
      detail: { recoveryIntent: "complete_target" },
    });
    prepareFunctionalReleaseMutation(value.journal, "recovery", "service_start");
    completeFunctionalReleaseMutation(value.journal, "recovery", "service_start");
    prepareFunctionalReleaseMutation(
      value.journal,
      "recovery",
      "running_state_verification",
      {
        targetState: target,
        targetStateSha256: releaseTransactionSha256(target),
      },
    );
    completeFunctionalReleaseMutation(
      value.journal,
      "recovery",
      "running_state_verification",
      {
        outcome: "already_exact",
        invocationId: "c".repeat(32),
        targetState: target,
        targetStateSha256: releaseTransactionSha256(target),
      },
    );

    expect(assertReleaseServiceStartAdmitted({
      ...admissionOptions(value, "d".repeat(32)),
    })).toEqual({
      mode: "target_runtime_committed",
      transactionId: "target-runtime-double-proof-transaction",
    });
  });

  test("denies authorization whose process-wide lock owner is no longer alive", () => {
    const value = pendingServiceStartFixture();
    const lock = acquireSharedReleaseLock(value.lockPath, "departed-release-owner");
    const authorization = authorizeNextReleaseServiceStart(value.journal, {
      authorizationPath: value.authorizationPath,
      now: NOW,
    });
    lock.release();

    expect(() => assertReleaseServiceStartAdmitted({
      ...admissionOptions(value),
      releaseLockHeld: () => false,
    })).toThrow("authorization has no live process-wide lock owner");
    expect(existsSync(value.authorizationPath)).toBe(true);
    authorization.release();
  });

  test("replaces a stale unconsumed authorization after crash and new lock acquisition", async () => {
    const value = pendingServiceStartFixture();
    const readyPath = join(value.workspace, "authorization-owner-ready");
    const crashedOwner = Bun.spawn([
      process.execPath,
      authorizationOwnerWorker,
      value.journal,
      value.authorizationPath,
      value.lockPath,
      readyPath,
      NOW.toISOString(),
    ], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
    const deadline = performance.now() + 3_000;
    while (!existsSync(readyPath) && performance.now() < deadline) await Bun.sleep(10);
    expect(existsSync(readyPath)).toBe(true);
    const stale = JSON.parse(readFileSync(value.authorizationPath, "utf8")) as {
      nonce: string;
      issuedAt: string;
    };
    crashedOwner.kill("SIGKILL");
    await crashedOwner.exited;

    const reconciler = acquireSharedReleaseLock(value.lockPath, "replacement-reconciler");
    try {
      expect(() => assertReleaseServiceStartAdmitted({
        ...admissionOptions(value),
        releaseLockHeld: () => true,
      })).toThrow("authorization has no live issuer capability");
      const replacement = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: new Date(NOW.getTime() + 1_000),
      });
      expect(replacement.nonce).not.toBe(stale.nonce);
      expect(replacement.issuedAt).not.toBe(stale.issuedAt);
      expect(assertReleaseServiceStartAdmitted({
        ...admissionOptions(value),
        now: new Date(NOW.getTime() + 1_000),
      })).toEqual({
        mode: "journal_authorized",
        transactionId: "release-a-transaction",
      });
      replacement.release();
    } finally {
      reconciler.release();
    }
  });

  test("rejects a live authorization from another system boot", () => {
    const value = pendingServiceStartFixture();
    const lock = acquireSharedReleaseLock(value.lockPath, "boot-boundary-test");
    try {
      const authorization = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: NOW,
        bootId: BOOT_A,
      });
      expect(() => assertReleaseServiceStartAdmitted({
        ...admissionOptions(value),
        bootId: BOOT_B,
      })).toThrow("belongs to another system boot");
      authorization.release();
    } finally { lock.release(); }
  });

  test("rejects a token bound to a different release-lock owner nonce", () => {
    const value = pendingServiceStartFixture();
    const lock = acquireSharedReleaseLock(value.lockPath, "owner-nonce-test");
    try {
      const authorization = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: NOW,
      });
      const payload = JSON.parse(readFileSync(value.authorizationPath, "utf8")) as Record<string, unknown>;
      payload.releaseLockOwnerNonce = "00000000-0000-4000-8000-000000000000";
      writeFileSync(value.authorizationPath, `${JSON.stringify(payload)}\n`, { mode: 0o600 });
      expect(() => assertReleaseServiceStartAdmitted(admissionOptions(value)))
        .toThrow("belongs to a different release-lock owner");
      authorization.release();
    } finally { lock.release(); }
  });

  test("rejects an authorization that does not match the journal's exact latest boundary", () => {
    const value = pendingServiceStartFixture();
    const lock = acquireSharedReleaseLock(value.lockPath, "boundary-mismatch-test");
    try {
      const authorization = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: NOW,
      });
      const authorizationPayload = JSON.parse(
        readFileSync(value.authorizationPath, "utf8"),
      ) as Record<string, unknown>;
      authorizationPayload.latestRecordSha256 = "0".repeat(64);
      writeFileSync(value.authorizationPath, `${JSON.stringify(authorizationPayload)}\n`, { mode: 0o600 });

      expect(() => assertReleaseServiceStartAdmitted({
        ...admissionOptions(value),
        releaseLockHeld: () => true,
      })).toThrow("does not match the exact journal boundary");
      expect(existsSync(value.authorizationPath)).toBe(true);
      authorization.release();
    } finally {
      lock.release();
    }
  });

  test("rejects a token when the journal advances beyond prepared service_start", () => {
    const value = pendingServiceStartFixture();
    const lock = acquireSharedReleaseLock(value.lockPath, "advanced-boundary-test");
    try {
      const authorization = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: NOW,
      });
      completeFunctionalReleaseMutation(value.journal, "forward", "service_start");

      expect(() => assertReleaseServiceStartAdmitted({
        ...admissionOptions(value),
        releaseLockHeld: () => true,
      })).toThrow(
        "requires an exact prepared service_start, source_runtime_commit, runtime_activation, or running_state_verification boundary",
      );
      authorization.release();
    } finally {
      lock.release();
    }
  });

  test("rejects an invalid systemd invocation identity without consuming the token", () => {
    const value = pendingServiceStartFixture();
    const lock = acquireSharedReleaseLock(value.lockPath, "invocation-identity-test");
    try {
      const authorization = authorizeNextReleaseServiceStart(value.journal, {
        authorizationPath: value.authorizationPath,
        now: NOW,
      });
      expect(() => assertReleaseServiceStartAdmitted({
        ...admissionOptions(value, "not-a-systemd-invocation-id"),
        releaseLockHeld: () => true,
      })).toThrow("Systemd invocation identity is missing or invalid");
      expect(existsSync(value.authorizationPath)).toBe(true);

      expect(assertReleaseServiceStartAdmitted({
        ...admissionOptions(value),
        releaseLockHeld: () => true,
      }).mode).toBe("journal_authorized");
      authorization.release();
    } finally {
      lock.release();
    }
  });

  test("systemd uses the stable root-owned helper outside the swappable application tree", () => {
    const dropInPath = join(
      process.cwd(),
      "deployment/systemd/ti-scale.service.d/10-release-start-admission.conf",
    );
    const dropIn = readFileSync(dropInPath, "utf8");
    expect(dropIn).toContain(
      "ExecStartPre=+/usr/local/bin/bun run /usr/local/libexec/ti-scale-release-start-admission.js",
    );
    expect(dropIn).not.toContain("/opt/ti-scale");
  });
});

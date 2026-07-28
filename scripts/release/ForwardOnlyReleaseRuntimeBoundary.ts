import type { ActiveV2Work } from "./FunctionalReleasePrimitives";
import type { FunctionalReleaseTransactionJournal } from
  "./DurableReleaseTransaction";
import {
  clearReleaseStartupMutationBarrier,
  readReleaseStartupMutationBarrier,
  releaseStartupMutationBarrierExists,
} from "./ReleaseStartupMutationBarrier";

export interface ServiceIdentity {
  readonly activeState: string;
  readonly mainPid: number;
  readonly invocationId: string;
  readonly healthStatus: number;
  readonly semanticStatus: string;
}

export interface ServiceStopSnapshot {
  readonly activeState: string;
  readonly mainPid: number;
  readonly controlGroup: string;
  readonly controlGroupProcessIds: readonly number[];
  readonly portListening: boolean;
}

interface ApplicationPointerSnapshot {
  readonly kind: "directory" | "symlink";
  readonly target: string;
  readonly device: string;
  readonly inode: string;
}

interface ReleasePointerSnapshot {
  readonly application: ApplicationPointerSnapshot;
  readonly staticReleaseId: string;
  readonly staticManifestSha256: string;
}

interface ServiceStopReleaseIdentity {
  readonly pointers: ReleasePointerSnapshot;
  readonly databaseSchema: number;
}

interface SafeErrorRecord {
  readonly name: string;
  readonly message: string;
  readonly stack?: string;
}

interface FailedServiceStopNormalizationEvidence {
  readonly schemaVersion: "ti-scale.failed-service-stop-normalization.v1";
  readonly disposition: "failed_unit_normalized";
  readonly recordedAt: string;
  readonly stopCommandFailed: boolean;
  readonly stopCommandFailure?: SafeErrorRecord;
  readonly sourceIdentity: ServiceStopReleaseIdentity;
  readonly failedSnapshot: ServiceStopSnapshot;
  readonly normalizedSnapshot: ServiceStopSnapshot;
  readonly proofs: {
    readonly mainPidAbsent: true;
    readonly controlGroupEmpty: true;
    readonly port3132NotListening: true;
    readonly canonicalDatabaseHandlesAbsent: true;
    readonly activeRuntimeWorkAbsent: true;
    readonly applicationPointerUnchanged: true;
    readonly staticPointerUnchanged: true;
    readonly databaseSchemaUnchanged: true;
  };
}

interface ServiceStopResult {
  readonly disposition: "stopped" | "failed_unit_normalized";
  readonly snapshot: ServiceStopSnapshot;
  readonly compatibilityEvidence?: FailedServiceStopNormalizationEvidence;
}

interface GuardedFailedServiceStopNormalizationOperations {
  readonly captureIdentity: () => ServiceStopReleaseIdentity;
  readonly stop: () => void;
  readonly inspect: () => ServiceStopSnapshot;
  readonly assertNoCanonicalDatabaseUsers: () => void;
  readonly assertNoActiveWork: () => void;
  readonly resetFailed: () => void;
  readonly now?: () => string;
}

function applicationPointerMatches(
  observed: ApplicationPointerSnapshot,
  expected: ApplicationPointerSnapshot,
): boolean {
  if (observed.kind !== expected.kind) return false;
  return expected.kind === "symlink"
    ? observed.target === expected.target
    : observed.device === expected.device &&
      observed.inode === expected.inode;
}

function assertStopIdentityUnchanged(
  observed: ServiceStopReleaseIdentity,
  expected: ServiceStopReleaseIdentity,
  boundary: "before" | "after",
): void {
  if (
    !applicationPointerMatches(
      observed.pointers.application,
      expected.pointers.application,
    ) ||
    observed.pointers.staticReleaseId !==
      expected.pointers.staticReleaseId ||
    observed.pointers.staticManifestSha256 !==
      expected.pointers.staticManifestSha256 ||
    observed.databaseSchema !== expected.databaseSchema
  ) {
    throw new Error(
      `Ti-Scale release identity changed ${boundary} failed-unit normalization`,
    );
  }
}

function safeErrorRecord(error: unknown): SafeErrorRecord {
  return error instanceof Error
    ? {
        name: error.name || "Error",
        message: error.message,
        ...(error.stack ? { stack: error.stack } : {}),
      }
    : {
        name: "NonErrorFailure",
        message: typeof error === "string"
          ? error
          : JSON.stringify(error),
      };
}

export function serviceCanRestartUnchanged(
  snapshot: ServiceStopSnapshot,
): boolean {
  if (
    !Number.isSafeInteger(snapshot.mainPid) ||
    snapshot.mainPid < 0
  ) return false;
  return snapshot.mainPid === 0 &&
    (
      snapshot.activeState === "inactive" ||
      snapshot.activeState === "failed"
    ) &&
    snapshot.controlGroupProcessIds.length === 0 &&
    !snapshot.portListening;
}

export function stopServiceWithGuardedFailedUnitNormalization(
  operations: GuardedFailedServiceStopNormalizationOperations,
): ServiceStopResult {
  const sourceIdentity = operations.captureIdentity();
  let stopCommandFailure: unknown;
  try {
    operations.stop();
  } catch (error) {
    stopCommandFailure = error;
  }
  const failedSnapshot = operations.inspect();
  if (
    failedSnapshot.activeState === "inactive" &&
    serviceCanRestartUnchanged(failedSnapshot)
  ) {
    if (stopCommandFailure !== undefined) {
      throw new Error(
        "Ti-Scale systemctl stop failed without a failed unit eligible for guarded normalization",
        { cause: stopCommandFailure },
      );
    }
    return { disposition: "stopped", snapshot: failedSnapshot };
  }
  if (
    failedSnapshot.activeState !== "failed" ||
    !serviceCanRestartUnchanged(failedSnapshot)
  ) {
    throw new Error(
      "Ti-Scale stop did not produce an eligible failed-but-empty unit",
      stopCommandFailure === undefined
        ? undefined
        : { cause: stopCommandFailure },
    );
  }
  operations.assertNoActiveWork();
  assertStopIdentityUnchanged(
    operations.captureIdentity(),
    sourceIdentity,
    "before",
  );
  operations.assertNoCanonicalDatabaseUsers();
  operations.resetFailed();
  const normalizedSnapshot = operations.inspect();
  if (
    normalizedSnapshot.activeState !== "inactive" ||
    !serviceCanRestartUnchanged(normalizedSnapshot)
  ) {
    throw new Error(
      "Ti-Scale reset-failed did not produce a fully inactive unit",
    );
  }
  operations.assertNoActiveWork();
  assertStopIdentityUnchanged(
    operations.captureIdentity(),
    sourceIdentity,
    "after",
  );
  operations.assertNoCanonicalDatabaseUsers();
  return {
    disposition: "failed_unit_normalized",
    snapshot: normalizedSnapshot,
    compatibilityEvidence: {
      schemaVersion:
        "ti-scale.failed-service-stop-normalization.v1",
      disposition: "failed_unit_normalized",
      recordedAt:
        (operations.now ?? (() => new Date().toISOString()))(),
      stopCommandFailed: stopCommandFailure !== undefined,
      ...(stopCommandFailure === undefined
        ? {}
        : { stopCommandFailure: safeErrorRecord(stopCommandFailure) }),
      sourceIdentity,
      failedSnapshot,
      normalizedSnapshot,
      proofs: {
        mainPidAbsent: true,
        controlGroupEmpty: true,
        port3132NotListening: true,
        canonicalDatabaseHandlesAbsent: true,
        activeRuntimeWorkAbsent: true,
        applicationPointerUnchanged: true,
        staticPointerUnchanged: true,
        databaseSchemaUnchanged: true,
      },
    },
  };
}

export interface GuardedSourceRuntimeCommitOperations {
  readonly label: string;
  readonly inspect: () => ServiceStopSnapshot;
  readonly start: () => void | Promise<void>;
  readonly waitAndVerify: () => void | Promise<void>;
}

export async function ensureGuardedSourceRuntimeCommit(
  operations: GuardedSourceRuntimeCommitOperations,
): Promise<"already_exact"> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const snapshot = operations.inspect();
    let startError: unknown;
    if (
      snapshot.activeState !== "active" ||
      snapshot.mainPid <= 0
    ) {
      if (!serviceCanRestartUnchanged(snapshot)) {
        throw new Error(
          `${operations.label} cannot prove guarded-wrapper process absence before restart`,
        );
      }
      try {
        await operations.start();
      } catch (error) {
        startError = error;
      }
    }
    try {
      await operations.waitAndVerify();
      return "already_exact";
    } catch (verificationError) {
      lastError = startError === undefined
        ? verificationError
        : new AggregateError(
            [startError, verificationError],
            `${operations.label} start and guarded verification both failed`,
          );
      if (
        attempt > 0 ||
        !serviceCanRestartUnchanged(operations.inspect())
      ) throw lastError;
    }
  }
  throw lastError;
}

export function assertServiceIdentityUnchanged(
  before: ServiceIdentity,
  after: ServiceIdentity,
  label = "Protected service",
): ServiceIdentity {
  if (
    after.activeState !== "active" ||
    after.mainPid <= 0 ||
    !after.invocationId ||
    after.healthStatus !== 200 ||
    after.semanticStatus !== "ok"
  ) {
    throw new Error(`${label} is not healthy enough for a release boundary`);
  }
  if (
    after.mainPid !== before.mainPid ||
    after.invocationId !== before.invocationId
  ) {
    throw new Error(
      `${label} changed during the Ti-Scale release; release success is refused`,
    );
  }
  return { ...after };
}

export function assertNoActiveWorkSnapshot(
  active: ActiveV2Work,
): void {
  if (
    !active.activeRuns.length &&
    !active.activeLeases.length &&
    !active.activeDatabaseWriters.length
  ) return;
  const details = [
    ...active.activeRuns.map((run) => `run:${run.id}:${run.status}`),
    ...active.activeLeases.map((lease) =>
      `control_plane_lease:${lease.runId}:active`
    ),
    ...active.activeDatabaseWriters.map((writer) =>
      `${writer.kind}:${writer.id}:${writer.status}`
    ),
  ].join(", ");
  throw new Error(
    `Ti-Scale has active durable work; release refused${
      details ? ` (${details})` : ""
    }`,
  );
}

export function clearTerminalReleaseStartupMutationBarrier(
  journal: FunctionalReleaseTransactionJournal,
): "absent" | "cleared" {
  if (!releaseStartupMutationBarrierExists()) return "absent";
  readReleaseStartupMutationBarrier();
  return clearReleaseStartupMutationBarrier(journal);
}

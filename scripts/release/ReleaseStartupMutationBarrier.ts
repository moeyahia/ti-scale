import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { writeDurableFileAtomically } from "./DurableAtomicFile";
import {
  functionalReleaseTargetCommitRecord,
  releaseTransactionSha256,
  type FunctionalReleaseTransactionJournal,
} from "./DurableReleaseTransaction";

export const RELEASE_STARTUP_MUTATION_BARRIER_PATH =
  "/run/ti-scale-release-startup-mutation.barrier";
export const RELEASE_STARTUP_MUTATION_BARRIER_SCHEMA =
  "ti-scale.release-startup-mutation-barrier.v1" as const;
export const RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION = "source_runtime_commit" as const;
export const RELEASE_SOURCE_RUNTIME_PROTOCOL = "source_runtime_commit_v1" as const;
export const RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL =
  "target_runtime_commit_v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;

export interface ReleaseStartupMutationBarrierRecord {
  readonly schemaVersion: typeof RELEASE_STARTUP_MUTATION_BARRIER_SCHEMA;
  readonly transactionId: string;
  readonly operation: "deploy" | "rollback";
  readonly releaseId: string;
  readonly journalDirectory: string;
  readonly bindingSha256: string;
  readonly bootId: string;
  readonly createdAt: string;
}

export interface ReleaseStartupMutationBarrierBinding {
  readonly transactionId: string;
  readonly operation: "deploy" | "rollback";
  readonly releaseId: string;
  readonly journalDirectory: string;
  readonly bindingSha256: string;
  readonly bootId: string;
}

export function releaseSourceRuntimeProtocolEnabled(
  journal: FunctionalReleaseTransactionJournal,
): boolean {
  return (journal.binding.identity as Record<string, unknown>).releaseStartupProtocol ===
    RELEASE_SOURCE_RUNTIME_PROTOCOL;
}

export function releaseSourceRuntimeCommitted(
  journal: FunctionalReleaseTransactionJournal,
): boolean {
  if (functionalReleaseTargetCommitRecord(journal)) return false;
  const prepared = journal.records.filter((record) =>
    record.event === "mutation_prepared" && record.direction === "recovery" &&
    record.mutation === RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION
  );
  const completed = journal.records.filter((record) =>
    record.event === "mutation_completed" && record.direction === "recovery" &&
    record.mutation === RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION
  );
  if (!prepared.length && !completed.length) return false;
  if (!releaseSourceRuntimeProtocolEnabled(journal)) {
    throw new Error("Source-runtime commitment is not enabled by the immutable release binding");
  }
  if (prepared.length !== 1 || completed.length > 1) {
    throw new Error("Release source-runtime commitment is ambiguous");
  }
  const sourceState = prepared[0]!.detail?.sourceState;
  const sourceStateSha256 = prepared[0]!.detail?.sourceStateSha256;
  const identity = journal.binding.identity as Record<string, unknown>;
  const expectedSourceState = journal.binding.operation === "deploy"
    ? identity.predeploy
    : identity.preservedCurrent;
  const recoveryStarted = journal.records.find((record) => record.event === "recovery_started");
  const requiredCompleted = (mutation: string): FunctionalReleaseTransactionJournal["records"][number] | undefined =>
    journal.records.find((record) =>
      record.event === "mutation_completed" && record.direction === "recovery" &&
      record.mutation === mutation && record.sequence < prepared[0]!.sequence
    );
  if (
    !sourceState || typeof sourceState !== "object" || Array.isArray(sourceState) ||
    !expectedSourceState || typeof expectedSourceState !== "object" || Array.isArray(expectedSourceState) ||
    typeof sourceStateSha256 !== "string" || !SHA256.test(sourceStateSha256) ||
    releaseTransactionSha256(sourceState) !== sourceStateSha256 ||
    releaseTransactionSha256(sourceState) !== releaseTransactionSha256(expectedSourceState) ||
    !recoveryStarted || recoveryStarted.sequence >= prepared[0]!.sequence ||
    !requiredCompleted("service_stop_for_recovery") ||
    !requiredCompleted("source_state_verification") || !requiredCompleted("service_start")
  ) throw new Error("Release source-runtime commitment is malformed or unverified");
  // A prepared commitment is a valid, restartable guarded-wrapper boundary,
  // but it has not opened the real application runtime yet.
  if (completed.length === 0) return false;
  if (
    completed[0]!.sequence <= prepared[0]!.sequence ||
    completed[0]!.detail?.outcome !== "already_exact"
  ) throw new Error("Release source-runtime commitment is malformed or unverified");
  return true;
}

/**
 * A target has already crossed its immutable app/static/database commitment.
 * Once a journaled recovery activation has also reached a verified running
 * invocation, later host restarts may re-enter that same target without a
 * one-shot token. This is deliberately opt-in per immutable transaction.
 */
export function releaseTargetRuntimeCommitted(
  journal: FunctionalReleaseTransactionJournal,
): boolean {
  if (!functionalReleaseTargetCommitRecord(journal)) return false;
  if (
    (journal.binding.identity as Record<string, unknown>).targetRuntimeCommitProtocol !==
      RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL
  ) return false;
  const identity = journal.binding.identity as Record<string, unknown>;
  const expectedTarget = identity.target;
  if (!expectedTarget || typeof expectedTarget !== "object" || Array.isArray(expectedTarget)) {
    throw new Error("Release target-runtime commitment lacks its immutable target identity");
  }
  const prepared = journal.records.filter((record) =>
    record.event === "mutation_prepared" &&
    record.mutation === "running_state_verification");
  const completed = journal.records.filter((record) =>
    record.event === "mutation_completed" &&
    record.mutation === "running_state_verification");
  if (!prepared.length && !completed.length) return false;
  for (const direction of ["forward", "recovery"] as const) {
    if (
      prepared.filter((record) => record.direction === direction).length > 1 ||
      completed.filter((record) => record.direction === direction).length > 1
    ) {
      throw new Error("Release target-runtime commitment is ambiguous");
    }
  }
  if (!completed.length) return false;
  const completion = completed[completed.length - 1]!;
  const matchingPrepared = prepared.filter((record) =>
    record.direction === completion.direction &&
    record.sequence < completion.sequence
  );
  if (matchingPrepared.length !== 1) {
    throw new Error("Release target-runtime commitment direction is inconsistent");
  }
  const preparation = matchingPrepared[0]!;
  const serviceStartCompleted = journal.records.some((record) =>
    record.event === "mutation_completed" &&
    record.mutation === "service_start" &&
    record.direction === preparation.direction &&
    record.sequence < preparation.sequence);
  const detail = completion.detail;
  if (
    completion.sequence <= preparation.sequence ||
    !serviceStartCompleted ||
    detail?.outcome !== "already_exact" ||
    typeof detail.invocationId !== "string" ||
    !/^[a-f0-9]{32}$/u.test(detail.invocationId) ||
    !detail.targetState ||
    typeof detail.targetState !== "object" ||
    Array.isArray(detail.targetState) ||
    typeof detail.targetStateSha256 !== "string" ||
    !SHA256.test(detail.targetStateSha256) ||
    releaseTransactionSha256(detail.targetState) !== detail.targetStateSha256 ||
    releaseTransactionSha256(detail.targetState) !== releaseTransactionSha256(expectedTarget)
  ) {
    throw new Error("Release target-runtime commitment is malformed or unverified");
  }
  return true;
}

export function releaseTargetRuntimeCommitPrepared(
  journal: FunctionalReleaseTransactionJournal,
): boolean {
  if (!functionalReleaseTargetCommitRecord(journal)) return false;
  if (
    (journal.binding.identity as Record<string, unknown>).targetRuntimeCommitProtocol !==
      RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL
  ) return false;
  const latest = journal.latest;
  if (
    latest.event !== "mutation_prepared" ||
    latest.mutation !== "running_state_verification" ||
    (latest.direction !== "forward" && latest.direction !== "recovery")
  ) return false;
  const identity = journal.binding.identity as Record<string, unknown>;
  const expectedTarget = identity.target;
  const targetState = latest.detail?.targetState;
  const targetStateSha256 = latest.detail?.targetStateSha256;
  const serviceStartCompleted = journal.records.some((record) =>
    record.event === "mutation_completed" &&
    record.mutation === "service_start" &&
    record.direction === latest.direction &&
    record.sequence < latest.sequence);
  const sameDirectionPrepared = journal.records.filter((record) =>
    record.event === "mutation_prepared" &&
    record.mutation === "running_state_verification" &&
    record.direction === latest.direction);
  const sameDirectionCompleted = journal.records.filter((record) =>
    record.event === "mutation_completed" &&
    record.mutation === "running_state_verification" &&
    record.direction === latest.direction);
  if (
    !serviceStartCompleted ||
    sameDirectionPrepared.length !== 1 ||
    sameDirectionCompleted.length !== 0 ||
    !expectedTarget ||
    typeof expectedTarget !== "object" ||
    Array.isArray(expectedTarget) ||
    !targetState ||
    typeof targetState !== "object" ||
    Array.isArray(targetState) ||
    typeof targetStateSha256 !== "string" ||
    !SHA256.test(targetStateSha256) ||
    releaseTransactionSha256(targetState) !== targetStateSha256 ||
    releaseTransactionSha256(targetState) !== releaseTransactionSha256(expectedTarget)
  ) {
    throw new Error("Prepared target-runtime commitment is malformed or unverified");
  }
  return true;
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function validTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function parseRecord(value: unknown): ReleaseStartupMutationBarrierRecord {
  const record = value as Partial<ReleaseStartupMutationBarrierRecord> | null;
  if (
    !record || record.schemaVersion !== RELEASE_STARTUP_MUTATION_BARRIER_SCHEMA ||
    typeof record.transactionId !== "string" || !SAFE_ID.test(record.transactionId) ||
    (record.operation !== "deploy" && record.operation !== "rollback") ||
    typeof record.releaseId !== "string" || !SAFE_ID.test(record.releaseId) ||
    typeof record.journalDirectory !== "string" ||
    resolve(record.journalDirectory) !== record.journalDirectory ||
    typeof record.bindingSha256 !== "string" || !SHA256.test(record.bindingSha256) ||
    typeof record.bootId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(record.bootId) ||
    !validTimestamp(record.createdAt)
  ) throw new Error("Release startup mutation barrier is malformed or obsolete");
  return record as ReleaseStartupMutationBarrierRecord;
}

function sameBinding(
  left: Pick<ReleaseStartupMutationBarrierRecord,
    "transactionId" | "operation" | "releaseId" | "journalDirectory" | "bindingSha256" | "bootId">,
  right: ReleaseStartupMutationBarrierBinding,
): boolean {
  return left.transactionId === right.transactionId &&
    left.operation === right.operation &&
    left.releaseId === right.releaseId &&
    left.journalDirectory === resolve(right.journalDirectory) &&
    left.bindingSha256 === right.bindingSha256 &&
    left.bootId === right.bootId;
}

/**
 * Root-owned marker inspection used by both ExecStartPre and the unprivileged
 * service. The service needs only metadata visibility: it never reads, edits,
 * or removes the marker.
 */
export function assertReleaseStartupMutationBarrierFile(
  pathValue = RELEASE_STARTUP_MUTATION_BARRIER_PATH,
): string {
  const path = resolve(pathValue);
  const metadata = lstatSync(path);
  if (
    !metadata.isFile() || metadata.isSymbolicLink() || metadata.uid !== 0 ||
    metadata.gid !== 0 || (metadata.mode & 0o777) !== 0o600 || realpathSync(path) !== path
  ) throw new Error("Release startup mutation barrier ownership, mode, or path is invalid");
  return path;
}

export function releaseStartupMutationBarrierExists(
  pathValue = RELEASE_STARTUP_MUTATION_BARRIER_PATH,
): boolean {
  const path = resolve(pathValue);
  // The root reconciler legitimately unlinks this marker while the service
  // poll is running. Use one metadata lookup and treat ENOENT as the opened
  // gate; existsSync + lstat/realpath would turn that normal unlink race into
  // a permanent failure.
  try {
    const metadata = lstatSync(path);
    if (
      !metadata.isFile() || metadata.isSymbolicLink() || metadata.uid !== 0 ||
      metadata.gid !== 0 || (metadata.mode & 0o777) !== 0o600
    ) throw new Error("Release startup mutation barrier ownership, mode, or path is invalid");
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

export function readReleaseStartupMutationBarrier(
  pathValue = RELEASE_STARTUP_MUTATION_BARRIER_PATH,
): ReleaseStartupMutationBarrierRecord {
  const path = assertReleaseStartupMutationBarrierFile(pathValue);
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const descriptorMetadata = fstatSync(descriptor);
    const pathMetadata = lstatSync(path);
    if (
      !descriptorMetadata.isFile() || descriptorMetadata.dev !== pathMetadata.dev ||
      descriptorMetadata.ino !== pathMetadata.ino
    ) throw new Error("Release startup mutation barrier changed during inspection");
    return Object.freeze(parseRecord(JSON.parse(readFileSync(descriptor, "utf8"))));
  } finally { closeSync(descriptor); }
}

/** Root-only publication immediately before a journal-authorized service exec. */
export function publishReleaseStartupMutationBarrier(
  binding: ReleaseStartupMutationBarrierBinding,
  options: {
    readonly path?: string;
    readonly now?: Date;
  } = {},
): ReleaseStartupMutationBarrierRecord {
  if (process.getuid?.() !== 0) {
    throw new Error("Release startup mutation barrier publication requires root");
  }
  const path = resolve(options.path ?? RELEASE_STARTUP_MUTATION_BARRIER_PATH);
  const normalized: ReleaseStartupMutationBarrierBinding = {
    ...binding,
    journalDirectory: resolve(binding.journalDirectory),
  };
  if (existsSync(path)) {
    const existing = readReleaseStartupMutationBarrier(path);
    if (!sameBinding(existing, normalized)) {
      throw new Error("A different release transaction owns the startup mutation barrier");
    }
  }
  const record = parseRecord({
    schemaVersion: RELEASE_STARTUP_MUTATION_BARRIER_SCHEMA,
    ...normalized,
    createdAt: (options.now ?? new Date()).toISOString(),
  });
  writeDurableFileAtomically(path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  assertReleaseStartupMutationBarrierFile(path);
  return Object.freeze(record);
}

/** Removes only the exact barrier after a durable source-runtime or terminal commit. */
export function clearReleaseStartupMutationBarrier(
  journal: FunctionalReleaseTransactionJournal,
  pathValue = RELEASE_STARTUP_MUTATION_BARRIER_PATH,
): "absent" | "cleared" {
  if (process.getuid?.() !== 0) {
    throw new Error("Release startup mutation barrier cleanup requires root");
  }
  if (!journal.terminal && !releaseSourceRuntimeCommitted(journal)) {
    throw new Error(
      "A release transaction may open startup mutation only after a durable source-runtime commitment or terminal record",
    );
  }
  const path = resolve(pathValue);
  if (!existsSync(path)) return "absent";
  const record = readReleaseStartupMutationBarrier(path);
  if (!sameBinding(record, {
    transactionId: journal.binding.transactionId,
    operation: journal.binding.operation,
    releaseId: journal.binding.releaseId,
    journalDirectory: journal.directory,
    bindingSha256: journal.bindingSha256,
    bootId: record.bootId,
  })) {
    throw new Error("Release startup mutation barrier belongs to a different transaction");
  }
  rmSync(path);
  syncDirectory(dirname(path));
  return "cleared";
}

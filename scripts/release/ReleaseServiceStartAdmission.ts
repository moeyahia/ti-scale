import { randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
} from "node:fs";
import { basename, dirname, resolve } from "node:path";
import {
  discoverIncompleteFunctionalReleaseTransactions,
  functionalReleaseTargetCommitRecord,
  readFunctionalReleaseTransactionJournal,
  type FunctionalReleaseTransactionJournal,
} from "./DurableReleaseTransaction";
import { writeDurableFileAtomically } from "./DurableAtomicFile";
import {
  currentActiveReleaseLockDescriptor,
  currentActiveReleaseLockOwnerNonce,
} from "./ReleaseLockContext";
import {
  clearReleaseStartupMutationBarrier,
  publishReleaseStartupMutationBarrier,
  readReleaseStartupMutationBarrier,
  releaseSourceRuntimeCommitted,
  releaseSourceRuntimeProtocolEnabled,
  releaseStartupMutationBarrierExists,
  releaseTargetRuntimeCommitPrepared,
  releaseTargetRuntimeCommitted,
} from "./ReleaseStartupMutationBarrier";

export const RELEASE_SERVICE_START_AUTHORIZATION_PATH =
  "/run/ti-scale-release-start-authorization.json";
export const RELEASE_SERVICE_START_AUTHORIZATION_TTL_MS = 60_000;
export const RELEASE_SERVICE_START_AUTHORIZATION_SCHEMA =
  "ti-scale.release-service-start-authorization.v2" as const;
const RELEASE_LOCK_OWNER_SCHEMA = "ti-scale.release-lock-owner.v1" as const;
const BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id";

interface ReleaseServiceStartAuthorization {
  readonly schemaVersion: typeof RELEASE_SERVICE_START_AUTHORIZATION_SCHEMA;
  readonly transactionId: string;
  readonly operation: "deploy" | "rollback";
  readonly releaseId: string;
  readonly journalDirectory: string;
  readonly bindingSha256: string;
  readonly latestRecordSha256: string;
  readonly direction: "forward" | "recovery";
  readonly releaseLockOwnerNonce: string;
  readonly bootId: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface ReleaseServiceStartAuthorizationLease
  extends Readonly<ReleaseServiceStartAuthorization> {
  /** Releases the live token-inode capability and removes every token artifact. */
  release(): void;
}

interface ReleaseLockOwner {
  readonly schemaVersion: typeof RELEASE_LOCK_OWNER_SCHEMA;
  readonly ownerNonce: string;
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function parseBootId(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(normalized)) {
    throw new Error("Kernel boot identity is missing or malformed");
  }
  return normalized;
}

function currentBootId(path = BOOT_ID_PATH): string {
  return parseBootId(readFileSync(path, "utf8"));
}

function pendingServiceStart(journal: FunctionalReleaseTransactionJournal):
  { readonly direction: "forward" | "recovery"; readonly latestRecordSha256: string } {
  const latest = journal.latest;
  if (
    latest.event === "mutation_prepared" &&
    latest.mutation === "running_state_verification"
  ) {
    if (!releaseTargetRuntimeCommitPrepared(journal)) {
      throw new Error(
        "Release service start authorization rejected an uncommitted or non-exact target-runtime boundary",
      );
    }
    return { direction: latest.direction as "forward" | "recovery", latestRecordSha256: latest.recordSha256 };
  }
  const isPreparedServiceBoundary = latest.mutation === "service_start" ||
    latest.mutation === "runtime_activation" ||
    (latest.direction === "recovery" && latest.mutation === "source_runtime_commit");
  if (
    latest.event !== "mutation_prepared" ||
    !isPreparedServiceBoundary ||
    (latest.direction !== "forward" && latest.direction !== "recovery")
  ) {
    throw new Error(
      "Release service start authorization requires an exact prepared service_start, source_runtime_commit, runtime_activation, or running_state_verification boundary",
    );
  }
  return { direction: latest.direction, latestRecordSha256: latest.recordSha256 };
}

function authorizationValue(
  journal: FunctionalReleaseTransactionJournal,
  now: Date,
  releaseLockOwnerNonce: string,
  bootId: string,
): ReleaseServiceStartAuthorization {
  const pending = pendingServiceStart(journal);
  return Object.freeze({
    schemaVersion: RELEASE_SERVICE_START_AUTHORIZATION_SCHEMA,
    transactionId: journal.binding.transactionId,
    operation: journal.binding.operation,
    releaseId: journal.binding.releaseId,
    journalDirectory: journal.directory,
    bindingSha256: journal.bindingSha256,
    latestRecordSha256: pending.latestRecordSha256,
    direction: pending.direction,
    releaseLockOwnerNonce,
    bootId,
    nonce: randomUUID(),
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + RELEASE_SERVICE_START_AUTHORIZATION_TTL_MS).toISOString(),
  });
}

function authorizationArtifacts(authorizationPath: string): readonly string[] {
  const directory = dirname(authorizationPath);
  if (!existsSync(directory)) return [];
  const prefix = `${basename(authorizationPath)}.`;
  return readdirSync(directory)
    .filter((name) => name === basename(authorizationPath) || name.startsWith(prefix))
    .map((name) => resolve(directory, name))
    .sort();
}

function runDescriptorFlock(
  descriptor: number,
  mode: "shared" | "exclusive",
  nonblocking: boolean,
): boolean {
  const result = Bun.spawnSync([
    "/usr/bin/flock",
    mode === "shared" ? "--shared" : "--exclusive",
    ...(nonblocking ? ["--nonblock"] : []),
    "0",
  ], { stdin: descriptor, stdout: "ignore", stderr: "pipe" });
  if (result.exitCode === 0) return true;
  if (result.exitCode === 1) return false;
  throw new Error("Could not establish the release service-start capability lock");
}

/** Returns true only when another open-file description owns a flock. */
function authorizationCapabilityIsLive(path: string): boolean {
  const descriptor = openSync(path, constants.O_RDONLY);
  try {
    // A successful exclusive lock proves there is no live shared issuer. The
    // lock remains on this open-file description only until the finally close.
    return !runDescriptorFlock(descriptor, "exclusive", true);
  } finally { closeSync(descriptor); }
}

function removeAuthorizationArtifacts(authorizationPath: string): void {
  const artifacts = authorizationArtifacts(authorizationPath);
  for (const artifact of artifacts) {
    const metadata = lstatSync(artifact);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`Release service start authorization artifact is not a real file: ${artifact}`);
    }
    if (artifact === authorizationPath && authorizationCapabilityIsLive(artifact)) {
      throw new Error("A live release service start authorization already exists");
    }
    rmSync(artifact);
  }
  if (artifacts.length) syncDirectory(dirname(authorizationPath));
}

export function authorizeNextReleaseServiceStart(
  journalDirectory: string,
  options: {
    readonly authorizationPath?: string;
    readonly now?: Date;
    readonly bootId?: string;
  } = {},
): ReleaseServiceStartAuthorizationLease {
  if (currentActiveReleaseLockDescriptor() === undefined) {
    throw new Error("Release service start authorization requires the process-wide release lock");
  }
  const releaseLockOwnerNonce = currentActiveReleaseLockOwnerNonce();
  if (!releaseLockOwnerNonce) {
    throw new Error("Release service start authorization requires an identified release-lock owner");
  }
  const authorizationPath = resolve(
    options.authorizationPath ?? RELEASE_SERVICE_START_AUTHORIZATION_PATH,
  );
  // A SIGKILL can leave a file, but cannot leave its issuer-held token flock.
  // Under a newly acquired global release lock, only an unlocked artifact may
  // be removed and replaced. A still-live token fails closed.
  removeAuthorizationArtifacts(authorizationPath);

  const journal = readFunctionalReleaseTransactionJournal(journalDirectory);
  if (journal.terminal) throw new Error("A terminal release transaction cannot authorize a guarded service start");
  const value = authorizationValue(
    journal,
    options.now ?? new Date(),
    releaseLockOwnerNonce,
    parseBootId(options.bootId ?? currentBootId()),
  );
  writeDurableFileAtomically(authorizationPath, `${JSON.stringify(value)}\n`, { mode: 0o600 });

  const descriptor = openSync(authorizationPath, constants.O_RDONLY);
  try {
    if (!runDescriptorFlock(descriptor, "shared", true)) {
      throw new Error("Could not acquire the live release service-start capability");
    }
  } catch (error) {
    closeSync(descriptor);
    removeAuthorizationArtifacts(authorizationPath);
    throw error;
  }

  let released = false;
  return Object.freeze({
    ...value,
    release: () => {
      if (released) return;
      released = true;
      closeSync(descriptor);
      removeAuthorizationArtifacts(authorizationPath);
    },
  });
}

export function revokeReleaseServiceStartAuthorization(
  authorizationPathValue = RELEASE_SERVICE_START_AUTHORIZATION_PATH,
): void {
  removeAuthorizationArtifacts(resolve(authorizationPathValue));
}

function readAuthorizationFromDescriptor(
  descriptor: number,
  authorizationPath: string,
): ReleaseServiceStartAuthorization {
  const descriptorMetadata = fstatSync(descriptor);
  const pathMetadata = lstatSync(authorizationPath);
  if (
    !descriptorMetadata.isFile() || !pathMetadata.isFile() || pathMetadata.isSymbolicLink() ||
    descriptorMetadata.dev !== pathMetadata.dev || descriptorMetadata.ino !== pathMetadata.ino ||
    pathMetadata.uid !== 0 || pathMetadata.gid !== 0 || (pathMetadata.mode & 0o777) !== 0o600
  ) throw new Error("Release service start authorization ownership, mode, or inode is invalid");
  const value = JSON.parse(readFileSync(descriptor, "utf8")) as Partial<ReleaseServiceStartAuthorization>;
  if (
    value.schemaVersion !== RELEASE_SERVICE_START_AUTHORIZATION_SCHEMA ||
    typeof value.transactionId !== "string" ||
    (value.operation !== "deploy" && value.operation !== "rollback") ||
    typeof value.releaseId !== "string" || typeof value.journalDirectory !== "string" ||
    typeof value.bindingSha256 !== "string" || typeof value.latestRecordSha256 !== "string" ||
    (value.direction !== "forward" && value.direction !== "recovery") ||
    typeof value.releaseLockOwnerNonce !== "string" || typeof value.bootId !== "string" ||
    typeof value.nonce !== "string" || typeof value.issuedAt !== "string" ||
    typeof value.expiresAt !== "string"
  ) throw new Error("Release service start authorization is malformed or obsolete");
  return value as ReleaseServiceStartAuthorization;
}

function authorizationMatches(
  authorization: ReleaseServiceStartAuthorization,
  journal: FunctionalReleaseTransactionJournal,
): boolean {
  const pending = pendingServiceStart(journal);
  return authorization.transactionId === journal.binding.transactionId &&
    authorization.operation === journal.binding.operation &&
    authorization.releaseId === journal.binding.releaseId &&
    resolve(authorization.journalDirectory) === journal.directory &&
    authorization.bindingSha256 === journal.bindingSha256 &&
    authorization.latestRecordSha256 === pending.latestRecordSha256 &&
    authorization.direction === pending.direction;
}

function kernelReleaseLockIsHeld(lockPath: string): boolean {
  const result = Bun.spawnSync([
    "/usr/bin/flock", "--exclusive", "--nonblock", lockPath, "/usr/bin/true",
  ], { stdin: "ignore", stdout: "ignore", stderr: "pipe" });
  if (result.exitCode === 1) return true;
  if (result.exitCode === 0) return false;
  throw new Error("Could not inspect the process-wide release lock");
}

function readReleaseLockOwner(lockPath: string): ReleaseLockOwner {
  const metadata = lstatSync(lockPath);
  if (
    !metadata.isFile() || metadata.isSymbolicLink() || metadata.uid !== 0 ||
    metadata.gid !== 0 || (metadata.mode & 0o777) !== 0o600
  ) throw new Error("Process-wide release lock ownership or mode is invalid");
  const value = JSON.parse(readFileSync(lockPath, "utf8")) as Partial<ReleaseLockOwner>;
  if (value.schemaVersion !== RELEASE_LOCK_OWNER_SCHEMA || typeof value.ownerNonce !== "string") {
    throw new Error("Process-wide release lock owner identity is malformed");
  }
  return value as ReleaseLockOwner;
}

function assertTransactionRoot(path: string): void {
  if (!existsSync(path)) {
    throw new Error("Release transaction root is missing, untrusted, or writable by non-root users");
  }
  const metadata = lstatSync(path);
  if (
    !metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== 0 ||
    (metadata.mode & 0o022) !== 0
  ) throw new Error("Release transaction root is missing, untrusted, or writable by non-root users");
}

function reconcileTerminalStartupMutationBarrier(
  transactionRoot: string,
  barrierPath: string | undefined,
): void {
  if (!releaseStartupMutationBarrierExists(barrierPath)) return;
  const barrier = readReleaseStartupMutationBarrier(barrierPath);
  const journal = readFunctionalReleaseTransactionJournal(barrier.journalDirectory, {
    allowedRoot: transactionRoot,
  });
  if (
    !journal.terminal || journal.binding.transactionId !== barrier.transactionId ||
    journal.binding.operation !== barrier.operation ||
    journal.binding.releaseId !== barrier.releaseId ||
    journal.bindingSha256 !== barrier.bindingSha256
  ) throw new Error("Stale startup mutation barrier is not bound to an exact terminal release journal");
  clearReleaseStartupMutationBarrier(journal, barrierPath);
}

/** Root-only systemd ExecStartPre admission. */
export function assertReleaseServiceStartAdmitted(options: {
  readonly transactionRoot: string;
  readonly releaseLockPath: string;
  readonly authorizationPath?: string;
  readonly startupMutationBarrierPath?: string;
  readonly invocationId: string;
  readonly now?: Date;
  readonly bootId?: string;
  readonly releaseLockHeld?: (path: string) => boolean;
}): {
  readonly mode:
    | "ordinary"
    | "journal_authorized"
    | "source_runtime_committed"
    | "target_runtime_committed";
  readonly transactionId?: string;
} {
  const transactionRoot = resolve(options.transactionRoot);
  assertTransactionRoot(transactionRoot);
  const incomplete = discoverIncompleteFunctionalReleaseTransactions(transactionRoot);
  const authorizationPath = resolve(
    options.authorizationPath ?? RELEASE_SERVICE_START_AUTHORIZATION_PATH,
  );
  const artifacts = authorizationArtifacts(authorizationPath);
  if (!incomplete.length) {
    if (artifacts.length) {
      throw new Error("Stale release service start authorization exists without a nonterminal transaction");
    }
    reconcileTerminalStartupMutationBarrier(
      transactionRoot,
      options.startupMutationBarrierPath,
    );
    return { mode: "ordinary" };
  }
  if (incomplete.length !== 1) {
    throw new Error("Ti-Scale startup is blocked by ambiguous nonterminal release ownership");
  }
  if (!/^[A-Fa-f0-9]{32}$/u.test(options.invocationId)) {
    throw new Error("Systemd invocation identity is missing or invalid");
  }
  const incompleteJournal = readFunctionalReleaseTransactionJournal(incomplete[0]!.directory, {
    allowedRoot: transactionRoot,
  });
  if (releaseSourceRuntimeCommitted(incompleteJournal)) {
    if (artifacts.length) {
      throw new Error("Committed source-runtime restart is blocked by a stale one-shot authorization");
    }
    if (releaseStartupMutationBarrierExists(options.startupMutationBarrierPath)) {
      clearReleaseStartupMutationBarrier(incompleteJournal, options.startupMutationBarrierPath);
    }
    return {
      mode: "source_runtime_committed",
      transactionId: incompleteJournal.binding.transactionId,
    };
  }
  if (releaseTargetRuntimeCommitted(incompleteJournal)) {
    if (artifacts.length) {
      throw new Error("Committed target-runtime restart is blocked by a stale one-shot authorization");
    }
    if (releaseStartupMutationBarrierExists(options.startupMutationBarrierPath)) {
      throw new Error("Committed target-runtime restart is blocked by a source mutation barrier");
    }
    return {
      mode: "target_runtime_committed",
      transactionId: incompleteJournal.binding.transactionId,
    };
  }
  if (artifacts.length !== 1 || artifacts[0] !== authorizationPath) {
    throw new Error("Ti-Scale startup is blocked pending explicit release reconciliation");
  }
  const descriptor = openSync(authorizationPath, constants.O_RDONLY);
  try {
    // First prove a distinct issuer owns a shared lock. If exclusive succeeds,
    // only stale bytes remain. Then take a shared handoff lock so issuer death
    // cannot create a time-of-check/time-of-use gap before the one-shot claim.
    if (runDescriptorFlock(descriptor, "exclusive", true)) {
      throw new Error("Release service start authorization has no live issuer capability");
    }
    if (!runDescriptorFlock(descriptor, "shared", true)) {
      throw new Error("Release service start authorization capability could not be handed off");
    }
    const authorization = readAuthorizationFromDescriptor(descriptor, authorizationPath);
    const now = options.now ?? new Date();
    const issuedAt = Date.parse(authorization.issuedAt);
    const expiresAt = Date.parse(authorization.expiresAt);
    if (
      !Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) ||
      issuedAt > now.getTime() + 5_000 || expiresAt <= now.getTime() ||
      expiresAt - issuedAt !== RELEASE_SERVICE_START_AUTHORIZATION_TTL_MS
    ) throw new Error("Release service start authorization is expired or has an invalid lifetime");
    if (authorization.bootId !== parseBootId(options.bootId ?? currentBootId())) {
      throw new Error("Release service start authorization belongs to another system boot");
    }
    const journal = incompleteJournal;
    if (!authorizationMatches(authorization, journal)) {
      throw new Error("Release service start authorization does not match the exact journal boundary");
    }
    if (!(options.releaseLockHeld ?? kernelReleaseLockIsHeld)(options.releaseLockPath)) {
      throw new Error("Release service start authorization has no live process-wide lock owner");
    }
    const releaseLockOwner = readReleaseLockOwner(options.releaseLockPath);
    if (releaseLockOwner.ownerNonce !== authorization.releaseLockOwnerNonce) {
      throw new Error("Release service start authorization belongs to a different release-lock owner");
    }

    // A candidate target has already crossed its durable data commitment and
    // must actually boot before success can be recorded. Only pre-commit
    // source restoration is fenced, so the old/swappable application cannot
    // mutate the exact restored state before that state is durably committed.
    const targetCommitted = functionalReleaseTargetCommitRecord(journal) !== undefined;
    const sourceRuntimeCommitted = releaseSourceRuntimeCommitted(journal);
    if (!targetCommitted && !sourceRuntimeCommitted) {
      if (!releaseSourceRuntimeProtocolEnabled(journal)) {
        throw new Error("Precommit source recovery lacks the required stable-wrapper protocol binding");
      }
      publishReleaseStartupMutationBarrier({
        transactionId: journal.binding.transactionId,
        operation: journal.binding.operation,
        releaseId: journal.binding.releaseId,
        journalDirectory: journal.directory,
        bindingSha256: journal.bindingSha256,
        bootId: authorization.bootId,
      }, { path: options.startupMutationBarrierPath });
    } else if (targetCommitted && releaseStartupMutationBarrierExists(options.startupMutationBarrierPath)) {
      throw new Error("Committed target startup is blocked by an unexpected source-recovery barrier");
    }

    const consumed = `${authorizationPath}.${options.invocationId}.consumed`;
    if (existsSync(consumed)) throw new Error("Release service start authorization was already consumed");
    renameSync(authorizationPath, consumed);
    syncDirectory(dirname(authorizationPath));
    rmSync(consumed);
    syncDirectory(dirname(authorizationPath));
    return { mode: "journal_authorized", transactionId: journal.binding.transactionId };
  } finally { closeSync(descriptor); }
}

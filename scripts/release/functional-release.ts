#!/usr/bin/env bun
import {
  chmodSync,
  chownSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statfsSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  fsyncSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { backupDatabase } from "../../server/db/backup";
import { createDatabaseConnection } from "../../server/db/connection";
import { restoreMigrationBackup } from "../../server/migration/LegacyMigrationService";
import {
  CANONICAL_DATABASE_LEASE_SCHEMA_VERSION,
  CanonicalDatabaseLeaseService,
  StoppedServiceRuntimeLeaseReconciliationService,
  type StoppedServiceRuntimeLeaseReconciliationResult,
  withCanonicalMaintenanceLease,
} from "../../server/maintenance";
import { StaticArtifactReleaseStore, type ActiveStaticReleasePointer } from "../../server/static-release";
import {
  canonicalApplicationTreeFingerprint,
  canonicalReleaseDataFingerprint,
  BACKUP_CHECKSUM_MANIFEST,
  exchangeApplicationTarget,
  queryActiveV2Work,
  sha256File,
  stageServerRelease,
  verifyChecksumManifest,
  verifyServerRelease,
  writeAndVerifyChecksumManifest,
  RELEASE_DATA_FINGERPRINT_POLICY,
  type ActiveV2Work,
  type VerifiedServerRelease,
} from "./FunctionalReleasePrimitives";
import {
  assertReleaseMigrationAttestationsMatch,
  assertValidReleaseMigrationAttestation,
  attestReleaseMigrationCeiling,
  type ReleaseMigrationAttestation,
} from "./ReleaseMigrationAttestation";
import { createDirectoryDurably, writeDurableFileAtomically } from "./DurableAtomicFile";
import {
  appendFunctionalReleaseTransactionRecord,
  canonicalReleaseTransactionJson,
  commitFunctionalReleaseTransactionTarget,
  completeFunctionalReleaseMutation,
  createFunctionalReleaseTransactionJournal,
  discoverIncompleteFunctionalReleaseTransactions,
  functionalReleaseTargetCommitRecord,
  prepareFunctionalReleaseMutation,
  readFunctionalReleaseTransactionJournal,
  reconcileFunctionalReleaseTransaction,
  releaseTransactionSha256,
  type FunctionalReleaseTransactionJournal,
  type FunctionalReleaseTransactionRecord,
} from "./DurableReleaseTransaction";
import {
  withCooperativeReleaseSignals,
  withSharedReleaseLock,
  type CooperativeReleaseInterruption,
} from "./ReleaseExecutionBoundary";
import {
  authorizeNextReleaseServiceStart,
} from "./ReleaseServiceStartAdmission";
import {
  clearReleaseStartupMutationBarrier,
  readReleaseStartupMutationBarrier,
  RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
  RELEASE_SOURCE_RUNTIME_PROTOCOL,
  releaseSourceRuntimeCommitted,
  releaseStartupMutationBarrierExists,
} from "./ReleaseStartupMutationBarrier";
import {
  attestInstalledReleaseServiceStartAdmission,
  RELEASE_SERVICE_START_ADMISSION_BUN_PATH,
  RELEASE_SERVICE_START_ADMISSION_HELPER_PATH,
  RELEASE_SERVICE_WRAPPER_PATH,
  releaseServiceStartAdmissionSelfReportMatches,
  releaseServiceWrapperSelfReportMatches,
  serviceStartAdmissionConfigured as exactServiceStartAdmissionConfigured,
  serviceStartAdmissionMountConfigured,
  serviceWrapperConfigured,
  serviceWrapperIdentityConfigured,
} from "./ReleaseServiceStartAdmissionBundle";
import {
  assertVaultDatabaseSyncConsistency,
  canonicalVaultFingerprint,
  restoreVaultArchiveAtomically,
} from "./VaultReleasePrimitives";
import {
  runBoundedReleaseCommand,
  runBoundedReleaseCommandSync,
} from "./BoundedReleaseCommand";
import {
  assertEarlyAuthenticationAdmissionReceipt,
  captureEarlyAuthenticationStartBoundary,
  waitForEarlyAuthenticationAdmission,
  type EarlyAuthenticationAdmissionReceipt,
  type EarlyAuthenticationStartBoundary,
} from "./EarlyAuthenticationAdmission";

const APPLICATION_PATH = "/opt/ti-scale";
const SERVER_RELEASE_ROOT = "/opt/ti-scale-server-releases";
const DATABASE_PATH = "/var/lib/ti-scale/data/ti-scale.sqlite";
const VAULT_ROOT = "/var/lib/ti-scale/vaults";
const STATIC_RELEASE_ROOT = "/var/lib/ti-scale/static-releases";
const BACKUP_ROOT = "/var/backups/ti-scale/releases";
const DEFAULT_REHEARSAL_ROOT = "/tmp";
const SERVICE = "ti-scale.service";
const LEGACY_SERVICE = "chillspwn.service";
const TI_SCALE_HEALTH = "http://127.0.0.1:3132/api/v2/health";
const TI_SCALE_READINESS = "http://127.0.0.1:3132/api/v2/system/readiness";
const TI_SCALE_SESSION = "http://127.0.0.1:3132/api/v2/auth/session";
const CHILLSPWN_HEALTH = "http://127.0.0.1:3131/api/health";
const BUN = "/usr/local/bin/bun";
const DEFAULT_STARTUP_TIMEOUT_MS = 4 * 60_000;
const MINIMUM_STARTUP_TIMEOUT_MS = 3 * 60_000;
const MAXIMUM_STARTUP_TIMEOUT_MS = 15 * 60_000;
const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

type ReleaseMode = "dry-run" | "execute";
type ReleaseCommand = "deploy" | "rollback" | "reconcile";

interface CliArguments {
  readonly command: ReleaseCommand;
  readonly mode: ReleaseMode;
  readonly sourceRoot: string;
  readonly releaseId?: string;
  readonly confirmation?: string;
  readonly receiptPath?: string;
  readonly journalPath?: string;
}

export type DeploymentPhase =
  | "prepared"
  | "stopping"
  | "quiesced_backup"
  | "database_migration"
  | "application_activation"
  | "static_activation"
  | "service_start"
  | "identity_verification"
  | "receipt_commit";

export interface SafeErrorRecord {
  readonly name: string;
  readonly message: string;
  readonly stack?: string;
  readonly cause?: SafeErrorRecord;
}

export function assertExactReleaseDataFingerprintPolicy(
  policy: unknown,
): asserts policy is typeof RELEASE_DATA_FINGERPRINT_POLICY {
  if (policy === RELEASE_DATA_FINGERPRINT_POLICY) return;
  if (
    policy === "release_data_excluding_lease_rows_v1" ||
    policy === "release_data_excluding_lease_and_fence_rows_v2" ||
    policy === "release_data_excluding_runtime_projection_telemetry_lease_and_fence_rows_v3"
  ) {
    throw new Error(
      `Legacy ${policy} receipts are not silently reinterpreted; ` +
      `a new ${RELEASE_DATA_FINGERPRINT_POLICY} deployment receipt is required`,
    );
  }
  throw new Error(`Release receipt requires ${RELEASE_DATA_FINGERPRINT_POLICY}`);
}

export interface ReleaseFailureDetail {
  readonly phase: DeploymentPhase;
  readonly primary: SafeErrorRecord;
  readonly recovery: {
    readonly attempted: boolean;
    readonly outcome: "not_attempted" | "succeeded" | "failed";
    readonly error?: SafeErrorRecord;
  };
  readonly legacyVerification: "verified_unchanged" | "changed_or_unhealthy" | "observation_failed" | "not_evaluated";
  readonly receiptWriteError?: SafeErrorRecord;
}

export interface ServiceIdentity {
  readonly activeState: string;
  readonly mainPid: number;
  readonly invocationId: string;
  readonly healthStatus: number;
  readonly semanticStatus: string;
}

export interface TiScaleStartupObservation extends ServiceIdentity {
  readonly readinessStatus: number;
  readonly readinessSemanticStatus: string;
  readonly databaseHealthy: boolean;
  readonly databaseSchema: number | null;
  readonly guardedHealthSchema?: string | null;
  readonly guardedMutationFenced?: boolean;
  readonly guardedInvocationId?: string | null;
  readonly pointers: ReleasePointerSnapshot;
  readonly controlGroup: string;
  readonly controlGroupProcessIds: readonly number[];
  readonly listenerProcessIds: readonly number[];
  readonly healthError?: string;
  readonly readinessError?: string;
}

export interface StartupObservationContext {
  readonly remainingMs: number;
  readonly signal: AbortSignal;
}

export interface ExpectedTiScaleStartup {
  readonly previousInvocationId: string;
  readonly databaseSchema: number;
  readonly pointers: ReleasePointerSnapshot;
  readonly readinessMode?: "application" | "journal_guarded";
}

export interface WaitForTiScaleStartupOptions {
  readonly timeoutMs: number;
  readonly pollIntervalMs?: number;
  readonly signal?: AbortSignal;
  readonly observe: (context: StartupObservationContext) => TiScaleStartupObservation | Promise<TiScaleStartupObservation>;
  readonly now?: () => number;
  readonly sleep?: (milliseconds: number) => void | Promise<void>;
  readonly onProgress?: (observation: TiScaleStartupObservation | undefined, elapsedMs: number) => void;
}

export interface ReceiptPreviousApplicationBinding {
  applicationKind: "directory" | "symlink";
  applicationTarget: string;
  applicationDevice: string;
  applicationInode: string;
  applicationTreeSha256: string;
  staticPointer: ActiveStaticReleasePointer;
}

interface DeploymentReceipt {
  readonly schemaVersion: "ti-scale.functional-release-receipt.v1";
  readonly releaseId: string;
  readonly createdAt: string;
  status: "prepared" | "maintenance" | "deployed" | "rolled_back_after_failure" | "rolled_back" | "failed";
  readonly sourceRoot: string;
  readonly serverRelease: {
    readonly path: string;
    readonly manifestSha256: string;
    readonly treeSha256: string;
  };
  readonly staticRelease: {
    readonly releaseId: string;
    readonly manifestSha256: string;
  };
  readonly previous: ReceiptPreviousApplicationBinding;
  readonly backup: {
    readonly root: string;
    readonly database: string;
    databaseSha256: string;
    readonly onlinePreflightDatabase: string;
    onlinePreflightDatabaseSha256: string;
    readonly sourceArchive: string;
    readonly vaultArchive: string;
    vaultArchiveSha256: string;
    readonly staticPointer: string;
    readonly metadata: string;
    checksumManifestSha256?: string;
  };
  readonly database: {
    readonly sourceSchema: number;
    readonly targetSchema: number;
    /**
     * Added additively to the v1 receipt. Older rollback receipts remain
     * readable; every new deployment binds its selected source migration set.
     */
    readonly migrationAttestation?: ReleaseMigrationAttestation;
    readonly ownerUid: number;
    readonly ownerGid: number;
    sourceFingerprint?: string;
    deployedFingerprint?: string;
    fingerprintPolicy?:
      | "release_data_excluding_lease_rows_v1"
      | "release_data_excluding_lease_and_fence_rows_v2"
      | typeof RELEASE_DATA_FINGERPRINT_POLICY;
  };
  readonly vault: {
    readonly fingerprintPolicy: "managed_tree_content_metadata_v1";
    sourceFingerprint?: string;
    deployedFingerprint?: string;
  };
  /**
   * Capacity is captured after release staging and before the first backup
   * byte is written. Byte values are strings so receipts remain valid JSON
   * without losing bigint precision.
   */
  readonly capacityPreflight?: ReleaseCapacityPreflightReceipt;
  readonly chillspwnBefore: ServiceIdentity;
  readonly tiScaleBefore?: TiScaleStartupObservation;
  /**
   * Added additively to the v1 receipt. Older successful receipts remain
   * readable for rollback, while every new successful deployment persists
   * the independently captured post-deployment identity.
   */
  chillspwnAfter?: ServiceIdentity;
  tiScaleAfter?: TiScaleStartupObservation;
  /**
   * Additive release evidence for the browser's hard startup contract. Older
   * rollback receipts remain readable, while a newly deployed receipt records
   * the first exact unauthenticated session response from its new invocation.
   */
  earlyAuthenticationAfter?: EarlyAuthenticationAdmissionReceipt;
  /**
   * Present when the primary deployment stop completed through the narrowly
   * bounded failed-unit compatibility path. The same evidence is committed to
   * the append-only release transaction journal before any release mutation.
   */
  serviceStopCompatibility?: FailedServiceStopNormalizationEvidence;
  deployedAt?: string;
  rolledBackAt?: string;
  failure?: string;
  failureDetail?: ReleaseFailureDetail;
}

export class ProtectedLegacyInvariantError extends Error {
  constructor(
    readonly verification: "changed_or_unhealthy" | "observation_failed",
    readonly before: ServiceIdentity,
    readonly after: ServiceIdentity | undefined,
    message: string,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "ProtectedLegacyInvariantError";
  }
}

export class FunctionalReleaseError extends Error {
  constructor(
    readonly receiptPath: string,
    readonly releaseStatus: DeploymentReceipt["status"],
    readonly failureDetail: ReleaseFailureDetail,
    cause: unknown,
  ) {
    super(`Functional release failed (${releaseStatus}). Receipt: ${receiptPath}`, { cause });
    this.name = "FunctionalReleaseError";
  }
}

export function safeErrorRecord(error: unknown, seen = new Set<unknown>()): SafeErrorRecord {
  if (seen.has(error)) return { name: "CircularErrorCause", message: "Circular error cause omitted" };
  seen.add(error);
  if (!(error instanceof Error)) {
    return { name: "NonErrorFailure", message: typeof error === "string" ? error : JSON.stringify(error) };
  }
  const cause = "cause" in error ? (error as Error & { cause?: unknown }).cause : undefined;
  return {
    name: error.name || "Error",
    message: error.message,
    ...(error.stack ? { stack: error.stack } : {}),
    ...(cause === undefined ? {} : { cause: safeErrorRecord(cause, seen) }),
  };
}

export function legacyVerificationFromError(
  error: unknown,
): ReleaseFailureDetail["legacyVerification"] {
  if (error instanceof ProtectedLegacyInvariantError) return error.verification;
  if (error instanceof FailClosedReleaseRecoveryError) {
    const release = legacyVerificationFromError(error.releaseFailure);
    if (release !== "not_evaluated") return release;
    return legacyVerificationFromError(error.recoveryFailure);
  }
  if (error instanceof Error && "cause" in error) {
    return legacyVerificationFromError((error as Error & { cause?: unknown }).cause);
  }
  return "not_evaluated";
}

export interface ReleaseCapacityInputs {
  readonly databaseBytes: bigint;
  readonly sourceArchiveInputBytes: bigint;
  readonly vaultArchiveInputBytes: bigint;
  readonly schemaMigrationRequired: boolean;
}

export interface ReleaseCapacityRequirements {
  readonly persistentBytes: bigint;
  readonly rehearsalBytes: bigint;
  readonly persistentDatabaseCopies: number;
  readonly persistentArchiveAllowanceBytes: bigint;
  readonly persistentReserveBytes: bigint;
  readonly rehearsalReserveBytes: bigint;
}

export interface FilesystemCapacitySnapshot {
  readonly path: string;
  readonly device: string;
  readonly availableBytes: bigint;
}

export interface ReleaseCapacityPreflightReceipt {
  readonly schemaVersion: "ti-scale.release-capacity-preflight.v1";
  readonly checkedAt: string;
  readonly sharedFilesystem: boolean;
  readonly persistent: {
    readonly path: string;
    readonly device: string;
    readonly availableBytes: string;
    readonly requiredBytes: string;
  };
  readonly rehearsal: {
    readonly path: string;
    readonly device: string;
    readonly availableBytes: string;
    readonly requiredBytes: string;
  };
  readonly requirements: {
    readonly persistentDatabaseCopies: number;
    readonly persistentArchiveAllowanceBytes: string;
    readonly persistentReserveBytes: string;
    readonly rehearsalReserveBytes: string;
  };
}

export interface SecuredRehearsalWorkspaceOptions {
  readonly baseDirectory?: string;
  readonly expectedUid?: number;
  readonly expectedGid?: number;
}

export interface FailedReleaseRecoveryState {
  readonly serviceStopped: boolean;
  readonly staticActivated: boolean;
  readonly applicationSwapped: boolean;
  readonly databaseMayBeChanged: boolean;
  readonly vaultMayBeChanged: boolean;
}

export interface FailedReleaseRecoveryOperations {
  readonly stop: () => void | Promise<void>;
  readonly restoreStatic: () => void | Promise<void>;
  readonly restoreApplication: () => void | Promise<void>;
  readonly restoreDatabase: () => void | Promise<void>;
  readonly restoreVault: () => void | Promise<void>;
  readonly verifyVaultConsistency: () => void | Promise<void>;
  readonly start: () => void | Promise<void>;
  readonly verify: () => void | Promise<void>;
}

export interface ServiceStopSnapshot {
  readonly activeState: string;
  readonly mainPid: number;
  readonly controlGroup: string;
  readonly controlGroupProcessIds: readonly number[];
  readonly portListening: boolean;
}

export interface ServiceStopReleaseIdentity {
  readonly pointers: ReleasePointerSnapshot;
  readonly databaseSchema: number;
}

export interface FailedServiceStopNormalizationEvidence {
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

export interface ServiceStopResult {
  readonly disposition: "stopped" | "failed_unit_normalized";
  readonly snapshot: ServiceStopSnapshot;
  readonly compatibilityEvidence?: FailedServiceStopNormalizationEvidence;
  readonly preStopSnapshot?: ServiceStopSnapshot;
  readonly serviceLeaseReconciliation?: StoppedServiceRuntimeLeaseReconciliationResult;
}

export interface StoppedServiceRuntimeLeaseBoundaryOperations {
  readonly databasePath: string;
  readonly actorId: string;
  readonly boundaryId: string;
  readonly preStop: ServiceStopSnapshot;
  readonly stopped: ServiceStopSnapshot;
  readonly assertNoActiveWork: () => void;
  readonly assertNoCanonicalDatabaseUsers: () => void;
  readonly clock?: () => Date;
  readonly createId?: () => string;
  readonly processExists?: (pid: number) => boolean;
}

/**
 * Converts one proven-dead service-owned writer lease into an audited release
 * event. The OS handle and durable-work proofs bracket the short SQLite
 * transaction; any unrelated lease remains a hard conflict inside it.
 */
export function reconcileStoppedServiceRuntimeLeaseAtBoundary(
  operations: StoppedServiceRuntimeLeaseBoundaryOperations,
): StoppedServiceRuntimeLeaseReconciliationResult {
  if (operations.stopped.activeState !== "inactive" || !serviceCanRestartUnchanged(operations.stopped)) {
    throw new Error("Standalone service lease reconciliation requires a fully stopped Ti-Scale service");
  }
  operations.assertNoActiveWork();
  operations.assertNoCanonicalDatabaseUsers();
  const database = createDatabaseConnection({
    filename: resolve(operations.databasePath),
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    return new StoppedServiceRuntimeLeaseReconciliationService(database, {
      ...(operations.clock ? { clock: operations.clock } : {}),
      ...(operations.createId ? { createId: operations.createId } : {}),
      ...(operations.processExists ? { processExists: operations.processExists } : {}),
    }).reconcile({
      actorId: operations.actorId,
      boundaryId: operations.boundaryId,
      preStop: operations.preStop,
      stopped: operations.stopped,
    });
  } finally {
    database.close();
    operations.assertNoCanonicalDatabaseUsers();
  }
}

export interface GuardedFailedServiceStopNormalizationOperations {
  readonly captureIdentity: () => ServiceStopReleaseIdentity;
  readonly stop: () => void;
  readonly inspect: () => ServiceStopSnapshot;
  readonly assertNoCanonicalDatabaseUsers: () => void;
  readonly assertNoActiveWork: () => void;
  readonly resetFailed: () => void;
  readonly now?: () => string;
}

export interface ApplicationPointerSnapshot {
  readonly kind: "directory" | "symlink";
  readonly target: string;
  readonly device: string;
  readonly inode: string;
}

export interface ReleasePointerSnapshot {
  readonly application: ApplicationPointerSnapshot;
  readonly staticReleaseId: string;
  readonly staticManifestSha256: string;
}

export interface ReleasePointerRecoveryOperations {
  readonly inspect: () => ReleasePointerSnapshot;
  /**
   * Runs even when the live application pointer already matches. This closes
   * the crash window where an exchange committed but cleanup of its
   * deterministic displaced path did not.
   */
  readonly reconcileApplication?: () => void | Promise<void>;
  readonly restoreApplication: () => void | Promise<void>;
  readonly restoreStatic: () => void | Promise<void>;
  readonly applicationMatches?: (
    observed: ApplicationPointerSnapshot,
    expected: ApplicationPointerSnapshot,
  ) => boolean;
}

export function applicationPointerMatches(
  observed: ApplicationPointerSnapshot,
  expected: ApplicationPointerSnapshot,
): boolean {
  if (observed.kind !== expected.kind) return false;
  if (expected.kind === "symlink") return observed.target === expected.target;
  // The first directory-to-symlink activation atomically moves the original
  // /opt/ti-scale directory into its release archive. Its path therefore
  // changes by design, but dev+inode remain the durable identity needed to
  // find and exchange that exact directory back during recovery.
  return observed.device === expected.device && observed.inode === expected.inode;
}

export function releasePointersMatch(
  observed: ReleasePointerSnapshot,
  expected: ReleasePointerSnapshot,
): boolean {
  return applicationPointerMatches(observed.application, expected.application) &&
    observed.staticReleaseId === expected.staticReleaseId &&
    observed.staticManifestSha256 === expected.staticManifestSha256;
}

function assertFailedStopReleaseIdentityUnchanged(
  observed: ServiceStopReleaseIdentity,
  expected: ServiceStopReleaseIdentity,
  boundary: "before" | "after",
): void {
  if (!applicationPointerMatches(observed.pointers.application, expected.pointers.application)) {
    throw new Error(
      `Ti-Scale application pointer changed ${boundary} failed-unit normalization; reset-failed refused`,
    );
  }
  if (
    observed.pointers.staticReleaseId !== expected.pointers.staticReleaseId ||
    observed.pointers.staticManifestSha256 !== expected.pointers.staticManifestSha256
  ) {
    throw new Error(
      `Ti-Scale static release pointer changed ${boundary} failed-unit normalization; reset-failed refused`,
    );
  }
  if (observed.databaseSchema !== expected.databaseSchema) {
    throw new Error(
      `Ti-Scale database schema changed ${boundary} failed-unit normalization; reset-failed refused`,
    );
  }
}

/**
 * Compatibility boundary for an older service whose shutdown may return an
 * error after the process has already exited and systemd has retained the unit
 * in `failed`. `reset-failed` is intentionally unreachable until every
 * process, port, database, durable-work, pointer, and schema proof succeeds.
 * The same proofs are repeated after normalization so callers receive a clean
 * maintenance boundary rather than trusting the reset command itself.
 */
export function stopServiceWithGuardedFailedUnitNormalization(
  operations: GuardedFailedServiceStopNormalizationOperations,
): ServiceStopResult {
  const sourceIdentity = operations.captureIdentity();
  let stopCommandFailure: unknown;
  try { operations.stop(); }
  catch (error) { stopCommandFailure = error; }

  const failedSnapshot = operations.inspect();
  if (failedSnapshot.activeState === "inactive" && serviceCanRestartUnchanged(failedSnapshot)) {
    if (stopCommandFailure !== undefined) {
      throw new Error(
        "Ti-Scale systemctl stop failed without a failed unit eligible for guarded normalization",
        { cause: stopCommandFailure },
      );
    }
    return { disposition: "stopped", snapshot: failedSnapshot };
  }
  if (failedSnapshot.activeState !== "failed" || !serviceCanRestartUnchanged(failedSnapshot)) {
    throw new Error(
      `Ti-Scale stop did not produce an eligible failed-but-empty unit ` +
      `(ActiveState=${failedSnapshot.activeState}, MainPID=${String(failedSnapshot.mainPid)}, ` +
      `cgroupProcesses=${String(failedSnapshot.controlGroupProcessIds.length)}, ` +
      `port3132Listening=${String(failedSnapshot.portListening)})`,
      stopCommandFailure === undefined ? undefined : { cause: stopCommandFailure },
    );
  }

  // Read-only canonical checks must all succeed before reset-failed is issued.
  operations.assertNoActiveWork();
  assertFailedStopReleaseIdentityUnchanged(
    operations.captureIdentity(),
    sourceIdentity,
    "before",
  );
  operations.assertNoCanonicalDatabaseUsers();

  operations.resetFailed();
  const normalizedSnapshot = operations.inspect();
  if (normalizedSnapshot.activeState !== "inactive" || !serviceCanRestartUnchanged(normalizedSnapshot)) {
    throw new Error(
      `Ti-Scale reset-failed did not produce a fully inactive unit ` +
      `(ActiveState=${normalizedSnapshot.activeState}, MainPID=${String(normalizedSnapshot.mainPid)}, ` +
      `cgroupProcesses=${String(normalizedSnapshot.controlGroupProcessIds.length)}, ` +
      `port3132Listening=${String(normalizedSnapshot.portListening)})`,
    );
  }

  // Close the reset-to-release-mutation race with a second complete proof.
  operations.assertNoActiveWork();
  assertFailedStopReleaseIdentityUnchanged(
    operations.captureIdentity(),
    sourceIdentity,
    "after",
  );
  operations.assertNoCanonicalDatabaseUsers();

  const evidence: FailedServiceStopNormalizationEvidence = {
    schemaVersion: "ti-scale.failed-service-stop-normalization.v1",
    disposition: "failed_unit_normalized",
    recordedAt: (operations.now ?? (() => new Date().toISOString()))(),
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
  };
  return {
    disposition: "failed_unit_normalized",
    snapshot: normalizedSnapshot,
    compatibilityEvidence: evidence,
  };
}

export interface RollbackActiveReleaseExpectation {
  readonly applicationTarget: string;
  readonly staticReleaseId: string;
  readonly staticManifestSha256: string;
}

export function assertRollbackActiveReleaseMatchesReceipt(
  observed: ReleasePointerSnapshot,
  expected: RollbackActiveReleaseExpectation,
): void {
  if (
    observed.application.kind !== "symlink" ||
    observed.application.target !== expected.applicationTarget ||
    observed.staticReleaseId !== expected.staticReleaseId ||
    observed.staticManifestSha256 !== expected.staticManifestSha256
  ) {
    throw new Error(
      "Active application/static identity does not match the deployed rollback receipt; stale-receipt rollback is refused",
    );
  }
}

export async function reconcileObservedReleasePointerDrift(
  expected: ReleasePointerSnapshot,
  operations: ReleasePointerRecoveryOperations,
): Promise<ReleasePointerSnapshot> {
  let observed = operations.inspect();
  const matchesApplication = operations.applicationMatches ?? applicationPointerMatches;
  if (operations.reconcileApplication) {
    await operations.reconcileApplication();
    observed = operations.inspect();
  }
  if (!matchesApplication(observed.application, expected.application)) {
    await operations.restoreApplication();
    observed = operations.inspect();
  }
  if (
    observed.staticReleaseId !== expected.staticReleaseId ||
    observed.staticManifestSha256 !== expected.staticManifestSha256
  ) {
    await operations.restoreStatic();
    observed = operations.inspect();
  }
  if (
    !matchesApplication(observed.application, expected.application) ||
    observed.staticReleaseId !== expected.staticReleaseId ||
    observed.staticManifestSha256 !== expected.staticManifestSha256
  ) {
    throw new Error(
      "Release pointer recovery did not restore the exact expected application/static identities",
    );
  }
  return observed;
}

export interface UnchangedServiceRestartOperations {
  readonly inspect: () => ServiceStopSnapshot;
  readonly stop: () => void | Promise<void>;
  readonly beforeStart?: () => void | Promise<void>;
  readonly start: () => void | Promise<void>;
  readonly verify: () => void | Promise<void>;
}

export class FailClosedReleaseRecoveryError extends Error {
  readonly releaseFailure: unknown;
  readonly recoveryFailure: unknown;

  constructor(releaseFailure: unknown, recoveryFailure: unknown) {
    const releaseMessage = releaseFailure instanceof Error ? releaseFailure.message : "unknown release failure";
    const recoveryMessage = recoveryFailure instanceof Error ? recoveryFailure.message : "unknown recovery failure";
    super(
      `Release failed and unchanged-service recovery also failed: ${releaseMessage}; recovery: ${recoveryMessage}`,
      { cause: releaseFailure },
    );
    this.name = "FailClosedReleaseRecoveryError";
    this.releaseFailure = releaseFailure;
    this.recoveryFailure = recoveryFailure;
  }
}

/**
 * A release failure remains a failure even when availability recovery works.
 * Recovery failure is coupled to the original cause so neither can be hidden.
 */
export async function executeWithFailClosedReleaseRecovery<T>(
  execute: () => T | Promise<T>,
  recover: () => void | Promise<void>,
): Promise<T> {
  try { return await execute(); }
  catch (releaseFailure) {
    try { await recover(); }
    catch (recoveryFailure) {
      throw new FailClosedReleaseRecoveryError(releaseFailure, recoveryFailure);
    }
    throw releaseFailure;
  }
}

export interface PreparedDeploymentBoundaryOperations<T> {
  readonly stopAndProveClean: () => void | Promise<void>;
  readonly applyAndVerify: () => T | Promise<T>;
  readonly recoverAndVerifyPrevious: () => void | Promise<void>;
}

/**
 * The mutation callback is unreachable until the clean stop proof succeeds.
 * Any later failure—including one after an atomic commit but before its caller
 * returns—runs observed-state recovery and remains a failed deployment.
 */
export async function executePreparedDeploymentBoundary<T>(
  operations: PreparedDeploymentBoundaryOperations<T>,
  interruption?: CooperativeReleaseInterruption,
): Promise<T> {
  const interruptionCheckpoint = async (): Promise<void> => {
    if (!interruption) return;
    await Bun.sleep(0);
    interruption.throwIfAborted();
  };
  return executeWithFailClosedReleaseRecovery(async () => {
    await interruptionCheckpoint();
    await operations.stopAndProveClean();
    await interruptionCheckpoint();
    const result = await operations.applyAndVerify();
    await interruptionCheckpoint();
    return result;
  }, operations.recoverAndVerifyPrevious);
}

/**
 * A timed-out systemd stop may leave the unit in `failed` even though systemd
 * has already killed the process. That state is not a clean maintenance
 * boundary and must never authorize migration or pointer changes, but it is a
 * safe process-absence proof for restarting the unchanged release.
 */
export function serviceCanRestartUnchanged(snapshot: ServiceStopSnapshot): boolean {
  if (!Number.isSafeInteger(snapshot.mainPid) || snapshot.mainPid < 0) return false;
  return snapshot.mainPid === 0 &&
    (snapshot.activeState === "inactive" || snapshot.activeState === "failed") &&
    snapshot.controlGroupProcessIds.length === 0 && !snapshot.portListening;
}

export interface GuardedSourceRuntimeCommitOperations {
  readonly label: string;
  readonly inspect: () => ServiceStopSnapshot;
  readonly start: () => void | Promise<void>;
  readonly waitAndVerify: () => void | Promise<void>;
}

/**
 * Re-establishes the mutation-fenced service wrapper at an already prepared
 * source-runtime commitment boundary. A systemctl client-side failure is not
 * authoritative: a successfully observed guarded endpoint wins. Conversely,
 * the function retries only after process absence is proven and always
 * returns `already_exact`, because restarting the wrapper does not mutate the
 * journal-bound source identity.
 */
export async function ensureGuardedSourceRuntimeCommit(
  operations: GuardedSourceRuntimeCommitOperations,
): Promise<"already_exact"> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const snapshot = operations.inspect();
    let startError: unknown;
    if (snapshot.activeState !== "active" || snapshot.mainPid <= 0) {
      if (!serviceCanRestartUnchanged(snapshot)) {
        throw new Error(
          `${operations.label} cannot prove guarded-wrapper process absence before restart`,
        );
      }
      try { await operations.start(); }
      catch (error) { startError = error; }
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
      if (attempt > 0 || !serviceCanRestartUnchanged(operations.inspect())) throw lastError;
    }
  }
  throw lastError;
}

/**
 * Restore availability after a pre-mutation stop failure without weakening the
 * clean-stop gate used by release mutations. A failed stop is re-inspected: if
 * it nevertheless left MainPID=0, no second stop is issued. The caller still
 * owns and rethrows the original release error after this recovery completes.
 */
export async function restartUnchangedServiceAfterFailedStop(
  operations: UnchangedServiceRestartOperations,
): Promise<void> {
  let snapshot = operations.inspect();
  let stopFailure: unknown;
  if (!serviceCanRestartUnchanged(snapshot)) {
    try { await operations.stop(); }
    catch (error) { stopFailure = error; }
    snapshot = operations.inspect();
  }
  if (!serviceCanRestartUnchanged(snapshot)) {
    const stopDetail = stopFailure instanceof Error ? `; retry failed: ${stopFailure.message}` : "";
    throw new Error(
      `Ti-Scale process absence could not be proven for unchanged-service recovery ` +
      `(ActiveState=${snapshot.activeState}, MainPID=${String(snapshot.mainPid)})${stopDetail}`,
    );
  }
  await operations.beforeStart?.();
  await operations.start();
  await operations.verify();
}

export interface FailedRollbackRecoveryState {
  readonly stopAttempted: boolean;
  readonly mutationStarted: boolean;
}

export interface FailedRollbackRecoveryOperations {
  readonly recoverUnchangedRelease: () => void | Promise<void>;
  readonly stopMutatedRelease: () => void | Promise<void>;
  readonly restoreCurrentRelease: () => void | Promise<void>;
  readonly startCurrentRelease: () => void | Promise<void>;
  readonly verifyCurrentRelease: () => void | Promise<void>;
}

/**
 * Rollback is itself a coupled release operation. Before its first durable
 * mutation, a stop failure can only restart and verify the unchanged release.
 * After mutation begins, the preserved current pointers and database must be
 * restored as one fail-closed unit before that current release is restarted.
 */
export async function recoverFailedRollback(
  state: FailedRollbackRecoveryState,
  operations: FailedRollbackRecoveryOperations,
): Promise<void> {
  if (!state.stopAttempted) {
    throw new Error("Rollback recovery was requested before its stop attempt");
  }
  if (!state.mutationStarted) {
    await operations.recoverUnchangedRelease();
    return;
  }
  await operations.stopMutatedRelease();
  await operations.restoreCurrentRelease();
  await operations.startCurrentRelease();
  await operations.verifyCurrentRelease();
}

export function restoreDeploymentReceiptAfterFailedRollbackCommit(
  receipt: { status: string; rolledBackAt?: string },
): void {
  if (receipt.status !== "rolled_back") return;
  receipt.status = "deployed";
  delete receipt.rolledBackAt;
}

/**
 * Failure recovery is deliberately stage-aware. Before schema mutation, the
 * old database is left in place; after mutation, server/static/database are
 * restored as one unit before the service is allowed to return.
 */
export async function recoverFailedRelease(
  state: FailedReleaseRecoveryState,
  operations: FailedReleaseRecoveryOperations,
): Promise<void> {
  if (!state.serviceStopped) await operations.stop();
  if (state.staticActivated) await operations.restoreStatic();
  if (state.applicationSwapped) await operations.restoreApplication();
  if (state.databaseMayBeChanged) await operations.restoreDatabase();
  if (state.vaultMayBeChanged) await operations.restoreVault();
  if (state.databaseMayBeChanged || state.vaultMayBeChanged) await operations.verifyVaultConsistency();
  await operations.start();
  await operations.verify();
}

/**
 * Makes the maintenance/start ordering explicit and directly testable. The
 * maintenance callback must not return until its exclusive lease has been
 * released; only then may the service acquire its process writer lease.
 */
export async function runMaintenanceThenServiceStart<T>(
  maintenance: () => T | Promise<T>,
  startAndVerify: () => void | Promise<void>,
): Promise<T> {
  const result = await maintenance();
  await startAndVerify();
  return result;
}

function usage(): string {
  return `Ti-Scale retired backup-capable release command

This command is disabled by the operator no-backup policy. It cannot deploy,
create a backup, create a restore target, or roll back a release. Use the
bounded forward-only no-backup controller.
`;
}

export function parseFunctionalReleaseArguments(
  argv: readonly string[],
  cwd = process.cwd(),
): CliArguments {
  const [requestedCommand, ...rest] = argv;
  const rawCommand = requestedCommand === "resume" ? "reconcile" : requestedCommand;
  if (rawCommand !== "deploy" && rawCommand !== "rollback" && rawCommand !== "reconcile") {
    throw new Error("Command must be deploy, rollback, or reconcile");
  }
  const values = new Map<string, string>();
  const flags = new Set<string>();
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    if (token === "--dry-run" || token === "--execute") {
      if (flags.has(token)) throw new Error(`Duplicate flag: ${token}`);
      flags.add(token);
      continue;
    }
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) throw new Error(`${token} requires a value`);
    if (values.has(token)) throw new Error(`Duplicate option: ${token}`);
    values.set(token, next);
    index += 1;
  }
  if (flags.has("--dry-run") === flags.has("--execute")) {
    throw new Error("Specify exactly one of --dry-run or --execute");
  }
  const allowed = rawCommand === "deploy"
    ? new Set(["--release-id", "--source", "--confirm"])
    : rawCommand === "rollback"
      ? new Set(["--receipt", "--confirm"])
      : new Set(["--journal", "--confirm"]);
  for (const key of values.keys()) if (!allowed.has(key)) throw new Error(`Unsupported ${rawCommand} option: ${key}`);
  const mode: ReleaseMode = flags.has("--execute") ? "execute" : "dry-run";
  const releaseId = values.get("--release-id")?.trim();
  const receiptPath = values.get("--receipt")?.trim();
  const journalPath = values.get("--journal")?.trim();
  if (rawCommand === "deploy" && (!releaseId || !RELEASE_ID.test(releaseId))) {
    throw new Error("deploy requires a safe --release-id");
  }
  if (rawCommand === "rollback" && !receiptPath) throw new Error("rollback requires --receipt");
  if (rawCommand === "reconcile" && !journalPath) throw new Error("reconcile requires --journal");
  const confirmation = values.get("--confirm")?.trim();
  if (mode === "execute" && !confirmation) throw new Error("--execute requires --confirm");
  if (mode === "dry-run" && confirmation) throw new Error("--confirm is valid only with --execute");
  return {
    command: rawCommand,
    mode,
    sourceRoot: resolve(values.get("--source") ?? cwd),
    ...(releaseId ? { releaseId } : {}),
    ...(confirmation ? { confirmation } : {}),
    ...(receiptPath ? { receiptPath: resolve(receiptPath) } : {}),
    ...(journalPath ? { journalPath: resolve(journalPath) } : {}),
  };
}

function minimalEnvironment(home = "/root"): NodeJS.ProcessEnv {
  return {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: home,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NO_COLOR: "1",
  };
}

const MEBIBYTE = 1024n * 1024n;
const PERSISTENT_MINIMUM_RESERVE = 512n * MEBIBYTE;
const REHEARSAL_MINIMUM_RESERVE = 256n * MEBIBYTE;

function nonNegativeBytes(value: bigint, label: string): bigint {
  if (value < 0n) throw new Error(`${label} must not be negative`);
  return value;
}

function percentageCeiling(value: bigint, percent: bigint): bigint {
  return (value * percent + 99n) / 100n;
}

function maximumBigInt(left: bigint, right: bigint): bigint {
  return left > right ? left : right;
}

/**
 * Conservatively models the new bytes written by a deployment. The online
 * preflight and quiesced rollback images are intentionally both durable. A
 * schema migration also creates its own independently retained migration
 * backup. Archive inputs are charged at 105% because incompressible data and
 * tar headers can make a gzip archive slightly larger than its source.
 */
export function estimateReleaseCapacityRequirements(
  inputs: ReleaseCapacityInputs,
): ReleaseCapacityRequirements {
  const databaseBytes = nonNegativeBytes(inputs.databaseBytes, "Database byte size");
  const sourceBytes = nonNegativeBytes(inputs.sourceArchiveInputBytes, "Source archive input byte size");
  const vaultBytes = nonNegativeBytes(inputs.vaultArchiveInputBytes, "Vault archive input byte size");
  const persistentDatabaseCopies = inputs.schemaMigrationRequired ? 3 : 2;
  const archiveInputs = sourceBytes + vaultBytes;
  const persistentArchiveAllowanceBytes = archiveInputs + percentageCeiling(archiveInputs, 5n);
  const persistentPayload = databaseBytes * BigInt(persistentDatabaseCopies) + persistentArchiveAllowanceBytes;
  const persistentReserveBytes = maximumBigInt(
    PERSISTENT_MINIMUM_RESERVE,
    percentageCeiling(persistentPayload, 5n),
  );
  const rehearsalReserveBytes = maximumBigInt(
    REHEARSAL_MINIMUM_RESERVE,
    percentageCeiling(databaseBytes, 5n),
  );
  return {
    persistentBytes: persistentPayload + persistentReserveBytes,
    rehearsalBytes: databaseBytes + rehearsalReserveBytes,
    persistentDatabaseCopies,
    persistentArchiveAllowanceBytes,
    persistentReserveBytes,
    rehearsalReserveBytes,
  };
}

/**
 * A release may migrate only toward a newer schema. Equal schemas are a
 * deliberate no-op: invoking the migration CLI in that case needlessly
 * creates another full database backup and can make an otherwise safe
 * same-schema server activation fail after the service has stopped.
 */
export function databaseMigrationRequired(sourceSchema: number, targetSchema: number): boolean {
  if (!Number.isSafeInteger(sourceSchema) || sourceSchema < 0) {
    throw new Error("Source database schema must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(targetSchema) || targetSchema < 0) {
    throw new Error("Target database schema must be a non-negative safe integer");
  }
  if (sourceSchema > targetSchema) {
    throw new Error(
      `Release target schema ${targetSchema} is older than canonical schema ${sourceSchema}; downgrade is refused`,
    );
  }
  return sourceSchema < targetSchema;
}

function formatCapacity(bytes: bigint): string {
  const gibibyte = 1024n * MEBIBYTE;
  const hundredths = (bytes * 100n + gibibyte - 1n) / gibibyte;
  return `${hundredths / 100n}.${String(hundredths % 100n).padStart(2, "0")} GiB`;
}

/**
 * When backup and rehearsal roots share a device their peak requirements are
 * additive. This prevents two individually passing checks from overcommitting
 * one filesystem. On separate devices, each boundary is enforced separately.
 */
export function assertReleaseCapacityPreflight(
  requirements: ReleaseCapacityRequirements,
  persistent: FilesystemCapacitySnapshot,
  rehearsal: FilesystemCapacitySnapshot,
): void {
  if (persistent.availableBytes < 0n || rehearsal.availableBytes < 0n) {
    throw new Error("Filesystem capacity snapshots must not report negative available bytes");
  }
  if (persistent.device === rehearsal.device) {
    const required = requirements.persistentBytes + requirements.rehearsalBytes;
    if (persistent.availableBytes < required) {
      throw new Error(
        `Release capacity preflight failed: shared persistent/rehearsal filesystem ${persistent.path} ` +
        `has ${formatCapacity(persistent.availableBytes)} available but requires ${formatCapacity(required)} at peak`,
      );
    }
    return;
  }
  if (persistent.availableBytes < requirements.persistentBytes) {
    throw new Error(
      `Release capacity preflight failed: persistent backup filesystem ${persistent.path} ` +
      `has ${formatCapacity(persistent.availableBytes)} available but requires ${formatCapacity(requirements.persistentBytes)}`,
    );
  }
  if (rehearsal.availableBytes < requirements.rehearsalBytes) {
    throw new Error(
      `Release capacity preflight failed: rehearsal filesystem ${rehearsal.path} ` +
      `has ${formatCapacity(rehearsal.availableBytes)} available but requires ${formatCapacity(requirements.rehearsalBytes)}`,
    );
  }
}

function existingFilesystemAnchor(pathValue: string): string {
  let candidate = resolve(pathValue);
  while (!existsSync(candidate)) {
    const parent = dirname(candidate);
    if (parent === candidate) throw new Error(`No existing filesystem anchor for ${pathValue}`);
    candidate = parent;
  }
  return realpathSync(candidate);
}

function filesystemCapacitySnapshot(pathValue: string): FilesystemCapacitySnapshot {
  const path = existingFilesystemAnchor(pathValue);
  const filesystem = statfsSync(path, { bigint: true });
  const metadata = statSync(path, { bigint: true });
  return {
    path,
    device: metadata.dev.toString(),
    availableBytes: filesystem.bavail * filesystem.bsize,
  };
}

function apparentSizeBytes(pathValue: string): bigint {
  const path = realpathSync(resolve(pathValue));
  const output = runRequired([
    "/usr/bin/du", "--summarize", "--bytes", "--apparent-size", "--one-file-system", "--", path,
  ]);
  const value = output.split(/\s+/u, 1)[0];
  if (!value || !/^\d+$/u.test(value)) throw new Error(`Could not measure apparent byte size for ${path}`);
  return BigInt(value);
}

function configuredRehearsalRoot(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.TI_SCALE_RELEASE_REHEARSAL_ROOT?.trim();
  return resolve(configured || DEFAULT_REHEARSAL_ROOT);
}

function inspectRehearsalBase(baseDirectory: string): string {
  const configured = resolve(baseDirectory);
  const configuredMetadata = lstatSync(configured);
  if (configuredMetadata.isSymbolicLink() || !configuredMetadata.isDirectory()) {
    throw new Error("Release rehearsal root must be an existing non-symlink directory");
  }
  return realpathSync(configured);
}

interface RehearsalWorkspaceIdentity {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly uid: number;
  readonly gid: number;
}

function assertWorkspaceOwner(path: string, expectedUid: number, expectedGid: number): void {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || (!metadata.isDirectory() && !metadata.isFile())) {
    throw new Error(`Release rehearsal workspace contains a non-regular entry: ${path}`);
  }
  if (metadata.uid !== expectedUid || metadata.gid !== expectedGid) {
    throw new Error(`Release rehearsal workspace ownership changed: ${path}`);
  }
  if (metadata.isDirectory()) {
    for (const name of readdirSync(path)) assertWorkspaceOwner(join(path, name), expectedUid, expectedGid);
  }
}

function removeSecuredRehearsalWorkspace(
  workspace: string,
  identity: RehearsalWorkspaceIdentity,
): void {
  if (!existsSync(workspace)) throw new Error("Release rehearsal workspace disappeared before cleanup");
  const metadata = lstatSync(workspace, { bigint: true });
  if (
    metadata.isSymbolicLink() || !metadata.isDirectory() ||
    metadata.dev !== identity.dev || metadata.ino !== identity.ino ||
    Number(metadata.uid) !== identity.uid || Number(metadata.gid) !== identity.gid
  ) {
    throw new Error("Release rehearsal workspace identity changed before cleanup");
  }
  let validationError: unknown;
  try {
    assertWorkspaceOwner(workspace, identity.uid, identity.gid);
  } catch (error) {
    validationError = error;
  }
  // Once the root's device/inode/owner identity is proven, recursive removal
  // cannot be redirected through a child symlink: rm removes the link itself.
  rmSync(workspace, { recursive: true, force: false });
  if (existsSync(workspace)) throw new Error("Release rehearsal workspace cleanup did not complete");
  if (validationError) throw validationError;
}

/**
 * Creates an unguessable, owner-only workspace and always removes it. Tests
 * may inject a private base directory and expected identity without changing
 * production constants.
 */
export async function withSecuredReleaseRehearsalWorkspace<T>(
  operation: (workspace: string) => T | Promise<T>,
  options: SecuredRehearsalWorkspaceOptions = {},
): Promise<T> {
  const baseDirectory = inspectRehearsalBase(options.baseDirectory ?? configuredRehearsalRoot());
  const expectedUid = options.expectedUid ?? process.getuid?.() ?? statSync(baseDirectory).uid;
  const expectedGid = options.expectedGid ?? process.getgid?.() ?? statSync(baseDirectory).gid;
  const workspace = mkdtempSync(join(baseDirectory, "ti-scale-release-rehearsal-"));
  chmodSync(workspace, 0o700);
  const metadata = lstatSync(workspace, { bigint: true });
  const identity: RehearsalWorkspaceIdentity = {
    dev: metadata.dev,
    ino: metadata.ino,
    uid: Number(metadata.uid),
    gid: Number(metadata.gid),
  };
  if (
    metadata.isSymbolicLink() || !metadata.isDirectory() ||
    identity.uid !== expectedUid || identity.gid !== expectedGid ||
    (Number(metadata.mode) & 0o777) !== 0o700
  ) {
    rmSync(workspace, { recursive: true, force: true });
    throw new Error("Could not establish an owner-only release rehearsal workspace");
  }
  try {
    return await operation(workspace);
  } finally {
    removeSecuredRehearsalWorkspace(workspace, identity);
  }
}

function runRequired(
  command: readonly string[],
  options: {
    readonly cwd?: string;
    readonly env?: NodeJS.ProcessEnv;
    readonly timeoutMs?: number;
    readonly outputLimitBytes?: number;
  } = {},
): string {
  const result = runBoundedReleaseCommandSync(command, {
    cwd: options.cwd ?? "/",
    env: options.env ?? minimalEnvironment(),
    stdin: "ignore",
    timeoutMs: options.timeoutMs ?? 30 * 60_000,
    outputLimitBytes: options.outputLimitBytes ?? 8 * 1_024 * 1_024,
  });
  return result.stdout;
}

export async function runRequiredBounded(
  command: readonly string[],
  timeoutMs: number,
  signal: AbortSignal,
): Promise<string> {
  const result = await runBoundedReleaseCommand(command, {
    timeoutMs,
    signal,
    cwd: "/",
    env: minimalEnvironment(),
    outputLimitBytes: 1_048_576,
    terminationGraceMs: 1_000,
  });
  return result.stdout;
}

function serviceProperties(service: string): Record<string, string> {
  const output = runRequired([
    "/usr/bin/systemctl", "show", service,
    "--property=ActiveState,MainPID,InvocationID,ControlGroup", "--no-pager",
  ]);
  return Object.fromEntries(output.split("\n").filter(Boolean).map((line) => {
    const index = line.indexOf("=");
    return index >= 0 ? [line.slice(0, index), line.slice(index + 1)] : [line, ""];
  }));
}

function parseProperties(output: string): Record<string, string> {
  return Object.fromEntries(output.split("\n").filter(Boolean).map((line) => {
    const index = line.indexOf("=");
    return index >= 0 ? [line.slice(0, index), line.slice(index + 1)] : [line, ""];
  }));
}

async function servicePropertiesBounded(
  service: string,
  timeoutMs: number,
  signal: AbortSignal,
): Promise<Record<string, string>> {
  return parseProperties(await runRequiredBounded([
    "/usr/bin/systemctl", "show", service,
    "--property=ActiveState,MainPID,InvocationID,ControlGroup", "--no-pager",
  ], timeoutMs, signal));
}

function controlGroupProcessIds(controlGroup: string): readonly number[] {
  const controlGroupPath = controlGroup && controlGroup.startsWith("/") && !controlGroup.split("/").includes("..")
    ? resolve("/sys/fs/cgroup", `.${controlGroup}`, "cgroup.procs")
    : "";
  return controlGroupPath && existsSync(controlGroupPath)
    ? readFileSync(controlGroupPath, "utf8")
        .split(/\s+/u)
        .filter(Boolean)
        .map(Number)
        .filter((pid) => Number.isSafeInteger(pid) && pid > 0)
    : [];
}

function parseListenerProcessIds(output: string): readonly number[] {
  return [...new Set([...output.matchAll(/\bpid=(\d+)\b/gu)]
    .map((match) => Number(match[1]))
    .filter((pid) => Number.isSafeInteger(pid) && pid > 0))]
    .sort((left, right) => left - right);
}

async function fetchHealth(
  url: string,
  timeoutMs = 3_000,
  parentSignal?: AbortSignal,
): Promise<{ status: number; semanticStatus: string; body: unknown }> {
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const signal = parentSignal ? AbortSignal.any([parentSignal, timeoutSignal]) : timeoutSignal;
  const response = await fetch(url, { cache: "no-store", signal });
  const text = await response.text();
  let body: unknown;
  try { body = JSON.parse(text) as unknown; }
  catch { throw new Error(`Health endpoint on port ${new URL(url).port} returned non-JSON content`); }
  const semanticStatus = body && typeof body === "object" && !Array.isArray(body) && typeof (body as Record<string, unknown>).status === "string"
    ? String((body as Record<string, unknown>).status)
    : "unknown";
  return { status: response.status, semanticStatus, body };
}

async function captureReleaseEarlyAuthentication(
  start: EarlyAuthenticationStartBoundary,
  previousInvocationId: string,
  signal?: AbortSignal,
): Promise<EarlyAuthenticationAdmissionReceipt> {
  return waitForEarlyAuthenticationAdmission({
    start,
    previousInvocationId,
    ...(signal ? { signal } : {}),
    observeProcess: async (context) => {
      const properties = await servicePropertiesBounded(
        SERVICE,
        Math.min(750, context.remainingMs),
        context.signal,
      );
      return {
        activeState: properties.ActiveState ?? "unknown",
        mainPid: Number(properties.MainPID ?? 0),
        invocationId: properties.InvocationID ?? "",
      };
    },
    requestSession: async (context) => {
      const timeoutSignal = AbortSignal.timeout(Math.min(750, context.remainingMs));
      const response = await fetch(TI_SCALE_SESSION, {
        method: "GET",
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: AbortSignal.any([context.signal, timeoutSignal]),
      });
      const text = await response.text();
      let body: unknown;
      try { body = JSON.parse(text) as unknown; }
      catch {
        throw new Error("Early authentication session endpoint returned non-JSON content");
      }
      return { status: response.status, body };
    },
  });
}

async function captureServiceIdentity(service: string, healthUrl: string): Promise<ServiceIdentity> {
  const properties = serviceProperties(service);
  const health = await fetchHealth(healthUrl);
  return {
    activeState: properties.ActiveState ?? "unknown",
    mainPid: Number(properties.MainPID ?? 0),
    invocationId: properties.InvocationID ?? "",
    healthStatus: health.status,
    semanticStatus: health.semanticStatus,
  };
}

function assertHealthyIdentity(
  identity: ServiceIdentity,
  label: string,
  expectedSemanticStatus = "ok",
): void {
  if (
    identity.activeState !== "active" || identity.mainPid <= 0 || !identity.invocationId ||
    identity.healthStatus !== 200 || identity.semanticStatus !== expectedSemanticStatus
  ) {
    throw new Error(`${label} is not healthy enough for a release boundary`);
  }
}

function resolveTiScaleServiceIdentity(): { readonly uid: number; readonly gid: number } {
  const uid = Number(runRequired(["/usr/bin/id", "-u", "ti-scale"]));
  const gid = Number(runRequired(["/usr/bin/id", "-g", "ti-scale"]));
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid <= 0) {
    throw new Error("Could not resolve the dedicated ti-scale service account identity");
  }
  return { uid, gid };
}

async function assertChillspwnUnchanged(before: ServiceIdentity): Promise<ServiceIdentity> {
  let after: ServiceIdentity;
  try { after = await captureServiceIdentity(LEGACY_SERVICE, CHILLSPWN_HEALTH); }
  catch (error) {
    throw new ProtectedLegacyInvariantError(
      "observation_failed",
      before,
      undefined,
      "ChillsPwn post-boundary identity could not be observed",
      error,
    );
  }
  try { return assertServiceIdentityUnchanged(before, after, "ChillsPwn on port 3131"); }
  catch (error) {
    throw new ProtectedLegacyInvariantError(
      "changed_or_unhealthy",
      before,
      after,
      "ChillsPwn changed or became unhealthy during the Ti-Scale release boundary",
      error,
    );
  }
}

export function assertServiceIdentityUnchanged(
  before: ServiceIdentity,
  after: ServiceIdentity,
  label = "Protected service",
): ServiceIdentity {
  assertHealthyIdentity(after, label);
  if (after.mainPid !== before.mainPid || after.invocationId !== before.invocationId) {
    throw new Error(`${label} changed during the Ti-Scale release; release success is refused`);
  }
  return { ...after };
}

function currentSchema(databasePath: string): number {
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const row = database.prepare("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations").get() as { version: number };
    return Number(row.version);
  } finally { database.close(); }
}

function canonicalLeaseSchemaAvailable(databasePath: string): boolean {
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try { return CanonicalDatabaseLeaseService.schemaAvailable(database); }
  finally { database.close(); }
}

export function requiresCanonicalMaintenanceBootstrap(
  sourceSchema: number,
  releaseTargetSchema: number,
  leaseSchemaAvailable: boolean,
): boolean {
  if (leaseSchemaAvailable) return false;
  if (sourceSchema >= CANONICAL_DATABASE_LEASE_SCHEMA_VERSION) {
    throw new Error("Canonical database reports the lease migration but its lease tables are unavailable");
  }
  if (releaseTargetSchema < CANONICAL_DATABASE_LEASE_SCHEMA_VERSION) {
    throw new Error("Staged release cannot install the canonical maintenance lease schema");
  }
  return true;
}

export function assertNoActiveWorkSnapshot(active: ActiveV2Work): void {
  if (!active.activeRuns.length && !active.activeLeases.length && !active.activeDatabaseWriters.length) return;

  const details = [
    ...active.activeRuns.map((run) => `run:${run.id}:${run.status}`),
    ...active.activeLeases.map((lease) => `control_plane_lease:${lease.runId}:active`),
    ...active.activeDatabaseWriters.map((writer) => `${writer.kind}:${writer.id}:${writer.status}`),
  ].join(", ");
  throw new Error(`Ti-Scale has active durable work; release refused${details ? ` (${details})` : ""}`);
}

function assertNoActiveWork(): void {
  assertNoActiveWorkSnapshot(queryActiveV2Work(DATABASE_PATH));
}

export function assertNoCanonicalDatabaseUsersSnapshot(pids: readonly number[]): void {
  const active = [...new Set(pids)].filter((pid) => Number.isSafeInteger(pid) && pid > 0).sort((a, b) => a - b);
  if (active.length) {
    throw new Error(`Canonical database still has open process handles; release refused (pid:${active.join(", pid:")})`);
  }
}

function assertNoCanonicalDatabaseUsers(): void {
  // Bun's SQLite statements are finalized by garbage collection even after the
  // owning compatibility connection has been closed. Release validation opens
  // several short-lived read-only connections before this boundary; force only
  // those unreachable statements to finalize so lsof measures real live users,
  // not the release process's already-closed preflight statements.
  Bun.gc(true);
  const paths = [DATABASE_PATH, `${DATABASE_PATH}-wal`, `${DATABASE_PATH}-shm`].filter(existsSync);
  if (!paths.length) throw new Error("Canonical database disappeared before the release boundary");
  const result = runBoundedReleaseCommandSync(["/usr/bin/lsof", "-t", "--", ...paths], {
    cwd: "/",
    env: minimalEnvironment(),
    stdin: "ignore",
    timeoutMs: 30_000,
    outputLimitBytes: 256 * 1_024,
    allowNonZeroExit: true,
  });
  const stdout = result.stdout;
  if (result.exitCode !== 0 && !(result.exitCode === 1 && !stdout)) {
    const stderr = result.stderr;
    throw new Error(`Could not prove exclusive canonical database access${stderr ? `: ${stderr.slice(0, 500)}` : ""}`);
  }
  const pids = stdout
    ? stdout.split(/\s+/u).map((value) => Number(value)).filter((value) => Number.isSafeInteger(value))
    : [];
  assertNoCanonicalDatabaseUsersSnapshot(pids);
}

function applicationKindAndTarget(): { kind: "directory" | "symlink"; target: string } {
  const snapshot = captureApplicationPointerSnapshot();
  return { kind: snapshot.kind, target: snapshot.target };
}

function captureApplicationPointerSnapshot(pathValue = APPLICATION_PATH): ApplicationPointerSnapshot {
  const path = resolve(pathValue);
  const metadata = lstatSync(path, { bigint: true });
  const kind = metadata.isSymbolicLink()
    ? "symlink"
    : metadata.isDirectory()
      ? "directory"
      : undefined;
  if (!kind) throw new Error(`${path} is neither a directory nor a symbolic link`);
  return {
    kind,
    target: realpathSync(path),
    device: metadata.dev.toString(),
    inode: metadata.ino.toString(),
  };
}

function captureReleasePointerSnapshot(
  staticStore: StaticArtifactReleaseStore,
): ReleasePointerSnapshot {
  const pointer = staticStore.readActivePointer();
  return {
    application: captureApplicationPointerSnapshot(),
    staticReleaseId: pointer.activeReleaseId,
    staticManifestSha256: pointer.activeManifestSha256,
  };
}

function writeJsonAtomically(path: string, value: unknown, mode = 0o600): void {
  writeDurableFileAtomically(path, `${JSON.stringify(value, null, 2)}\n`, { mode });
}

function tarDirectory(sourceValue: string, destinationValue: string): void {
  const source = realpathSync(resolve(sourceValue));
  const destination = resolve(destinationValue);
  const temporary = `${destination}.${process.pid}.${Date.now()}.tmp`;
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  try {
    runRequired([
      "/usr/bin/tar", "--acls", "--xattrs", "--numeric-owner", "--one-file-system",
      "-C", dirname(source), "-czf", temporary, "--", basename(source),
    ]);
    chmodSync(temporary, 0o600);
    renameSync(temporary, destination);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

function syncApplicationRecoveryTree(root: string): void {
  const directories: string[] = [];
  const visit = (directory: string): void => {
    directories.push(directory);
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      const metadata = lstatSync(path);
      if (metadata.isDirectory()) visit(path);
      else if (metadata.isFile()) {
        const descriptor = openSync(path, constants.O_RDONLY);
        try { fsyncSync(descriptor); }
        finally { closeSync(descriptor); }
      } else if (!metadata.isSymbolicLink()) {
        throw new Error("Application archive recovery contains a special filesystem entry");
      }
    }
  };
  visit(root);
  for (const directory of directories.reverse()) {
    const descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY);
    try { fsyncSync(descriptor); }
    finally { closeSync(descriptor); }
  }
}

function syncContainingDirectory(path: string): void {
  const descriptor = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function assertTiScaleStopped(): void {
  const snapshot = tiScaleStopSnapshot();
  if (snapshot.activeState !== "inactive" || !serviceCanRestartUnchanged(snapshot)) {
    throw new Error(
      `Ti-Scale did not reach a fully stopped state ` +
      `(ActiveState=${snapshot.activeState}, MainPID=${String(snapshot.mainPid)}, ` +
      `cgroupProcesses=${String(snapshot.controlGroupProcessIds.length)}, port3132Listening=${String(snapshot.portListening)})`,
    );
  }
}

function tiScaleStopSnapshot(): ServiceStopSnapshot {
  const properties = serviceProperties(SERVICE);
  const controlGroup = properties.ControlGroup ?? "";
  const cgroupProcessIds = controlGroupProcessIds(controlGroup);
  const listeners = runRequired([
    "/usr/bin/ss", "--no-header", "--tcp", "--listening", "--numeric", "sport = :3132",
  ]);
  return {
    activeState: properties.ActiveState ?? "unknown",
    mainPid: Number(properties.MainPID ?? -1),
    controlGroup,
    controlGroupProcessIds: cgroupProcessIds,
    portListening: listeners.trim().length > 0,
  };
}

function captureServiceStopReleaseIdentity(): ServiceStopReleaseIdentity {
  return {
    pointers: captureReleasePointerSnapshot(
      new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT }),
    ),
    databaseSchema: currentSchema(DATABASE_PATH),
  };
}

function stopTiScale(): ServiceStopResult {
  const preStopSnapshot = tiScaleStopSnapshot();
  const result = stopServiceWithGuardedFailedUnitNormalization({
    captureIdentity: captureServiceStopReleaseIdentity,
    stop: () => { runRequired(["/usr/bin/systemctl", "stop", SERVICE]); },
    inspect: tiScaleStopSnapshot,
    assertNoCanonicalDatabaseUsers,
    assertNoActiveWork,
    resetFailed: () => {
      runRequired(["/usr/bin/systemctl", "reset-failed", SERVICE]);
    },
  });
  const serviceLeaseReconciliation = reconcileStoppedServiceRuntimeLeaseAtBoundary({
    databasePath: DATABASE_PATH,
    actorId: `release-controller:${process.pid}`,
    boundaryId: `functional-release:service-stop:${process.pid}:${Date.now()}`,
    preStop: preStopSnapshot,
    stopped: result.snapshot,
    assertNoActiveWork,
    assertNoCanonicalDatabaseUsers,
  });
  return {
    ...result,
    preStopSnapshot,
    serviceLeaseReconciliation,
  };
}

export function serviceStartAdmissionConfigured(
  execStartPre: string,
  execStartPreEx: string,
): boolean {
  return exactServiceStartAdmissionConfigured(execStartPre, execStartPreEx);
}

async function assertTiScaleServiceStartAdmissionInstalled(): Promise<void> {
  const configured = runRequired([
    "/usr/bin/systemctl", "show", SERVICE, "--property=ExecStartPre", "--value",
  ]);
  const configuredExtended = runRequired([
    "/usr/bin/systemctl", "show", SERVICE, "--property=ExecStartPreEx", "--value",
  ]);
  const configuredStart = runRequired([
    "/usr/bin/systemctl", "show", SERVICE, "--property=ExecStart", "--value",
  ]);
  const configuredStartExtended = runRequired([
    "/usr/bin/systemctl", "show", SERVICE, "--property=ExecStartEx", "--value",
  ]);
  const configuredMounts = runRequired([
    "/usr/bin/systemctl", "show", SERVICE, "--property=RequiresMountsFor", "--value",
  ]);
  const configuredUser = runRequired([
    "/usr/bin/systemctl", "show", SERVICE, "--property=User", "--value",
  ]);
  const configuredGroup = runRequired([
    "/usr/bin/systemctl", "show", SERVICE, "--property=Group", "--value",
  ]);
  const configuredWorkingDirectory = runRequired([
    "/usr/bin/systemctl", "show", SERVICE, "--property=WorkingDirectory", "--value",
  ]);
  const configuredDynamicUser = runRequired([
    "/usr/bin/systemctl", "show", SERVICE, "--property=DynamicUser", "--value",
  ]);
  if (!serviceStartAdmissionConfigured(configured, configuredExtended)) {
    throw new Error(
      "Ti-Scale release execution requires the root-owned systemd release-start admission gate",
    );
  }
  if (!serviceStartAdmissionMountConfigured(configuredMounts)) {
    throw new Error(
      "Ti-Scale release execution requires the canonical release-journal mount dependency",
    );
  }
  if (!serviceWrapperConfigured(configuredStart, configuredStartExtended)) {
    throw new Error(
      "Ti-Scale release execution requires the exact unprivileged root-owned service wrapper",
    );
  }
  if (!serviceWrapperIdentityConfigured(
    configuredUser,
    configuredGroup,
    configuredWorkingDirectory,
    configuredDynamicUser,
  )) {
    throw new Error("Ti-Scale release execution requires the ti-scale service identity and exact application root");
  }
  await attestInstalledReleaseServiceStartAdmission({
    sourceRoot: resolve(import.meta.dir, "../.."),
  });
  const selfReport = runRequired([
    RELEASE_SERVICE_START_ADMISSION_BUN_PATH,
    "run",
    RELEASE_SERVICE_START_ADMISSION_HELPER_PATH,
    "--self-report",
  ]);
  if (!releaseServiceStartAdmissionSelfReportMatches(selfReport)) {
    throw new Error("Ti-Scale release-start admission helper protocol is incompatible");
  }
  const wrapperSelfReport = runRequired([
    RELEASE_SERVICE_START_ADMISSION_BUN_PATH,
    "run",
    RELEASE_SERVICE_WRAPPER_PATH,
    "--self-report",
  ]);
  if (!releaseServiceWrapperSelfReportMatches(wrapperSelfReport)) {
    throw new Error("Ti-Scale stable service-wrapper protocol is incompatible");
  }
}

function startTiScale(journalDirectory: string): void {
  const journal = readFunctionalReleaseTransactionJournal(journalDirectory);
  if (releaseSourceRuntimeCommitted(journal)) {
    runRequired(["/usr/bin/systemctl", "start", SERVICE]);
    return;
  }
  const authorization = authorizeNextReleaseServiceStart(journal.directory);
  try { runRequired(["/usr/bin/systemctl", "start", SERVICE]); }
  finally { authorization.release(); }
}

function sourceRuntimeState(
  journal: FunctionalReleaseTransactionJournal,
): Readonly<Record<string, unknown>> {
  const identity = journalObject(journal.binding.identity, "release identity");
  const source = journal.binding.operation === "deploy"
    ? journalObject(identity.predeploy, "predeploy source identity")
    : journalObject(identity.preservedCurrent, "preserved-current source identity");
  return source;
}

function sourceRuntimeCommitPrepareDetail(
  journal: FunctionalReleaseTransactionJournal,
): Readonly<Record<string, unknown>> {
  const sourceState = sourceRuntimeState(journal);
  return Object.freeze({
    sourceState,
    sourceStateSha256: releaseTransactionSha256(sourceState),
  });
}

export function clearTerminalReleaseStartupMutationBarrier(
  journal: FunctionalReleaseTransactionJournal,
): "absent" | "cleared" {
  if (!releaseStartupMutationBarrierExists()) return "absent";
  readReleaseStartupMutationBarrier();
  return clearReleaseStartupMutationBarrier(journal);
}

export function releaseStartupTimeoutMs(rawValue = process.env.TI_SCALE_RELEASE_STARTUP_TIMEOUT_MS): number {
  const raw = rawValue?.trim();
  if (!raw) return DEFAULT_STARTUP_TIMEOUT_MS;
  const value = Number(raw);
  if (
    !Number.isSafeInteger(value) ||
    value < MINIMUM_STARTUP_TIMEOUT_MS ||
    value > MAXIMUM_STARTUP_TIMEOUT_MS
  ) {
    throw new Error(
      `TI_SCALE_RELEASE_STARTUP_TIMEOUT_MS must be an integer between ` +
      `${String(MINIMUM_STARTUP_TIMEOUT_MS)} and ${String(MAXIMUM_STARTUP_TIMEOUT_MS)}`,
    );
  }
  return value;
}

async function observeTiScaleStartup(
  staticStore: StaticArtifactReleaseStore,
  context?: StartupObservationContext,
): Promise<TiScaleStartupObservation> {
  const controller = context ? undefined : new AbortController();
  const signal = context?.signal ?? controller!.signal;
  const observationDeadline = performance.now() + (context?.remainingMs ?? 5_000);
  const remaining = (): number => Math.max(1, Math.floor(observationDeadline - performance.now()));
  const properties = await servicePropertiesBounded(
    SERVICE,
    Math.min(2_000, remaining()),
    signal,
  );
  const controlGroup = properties.ControlGroup ?? "";
  const cgroupProcessIds = controlGroupProcessIds(controlGroup);
  const listenerOutput = await runRequiredBounded([
    "/usr/bin/ss", "--no-header", "--tcp", "--listening", "--numeric", "--processes", "sport = :3132",
  ], Math.min(2_000, remaining()), signal);
  const listenerProcessIds = parseListenerProcessIds(listenerOutput);
  let healthStatus = 0;
  let semanticStatus = "unavailable";
  let readinessStatus = 0;
  let readinessSemanticStatus = "unavailable";
  let databaseHealthy = false;
  let databaseSchema: number | null = null;
  let guardedHealthSchema: string | null = null;
  let guardedMutationFenced = false;
  let guardedInvocationId: string | null = null;
  let healthError: string | undefined;
  let readinessError: string | undefined;
  try {
    const health = await fetchHealth(TI_SCALE_HEALTH, Math.min(1_500, remaining()), signal);
    healthStatus = health.status;
    semanticStatus = health.semanticStatus;
  } catch (error) {
    healthError = error instanceof Error ? error.message : "liveness request failed";
  }
  try {
    const readiness = await fetchHealth(TI_SCALE_READINESS, Math.min(1_500, remaining()), signal);
    readinessStatus = readiness.status;
    readinessSemanticStatus = readiness.semanticStatus;
    if (readiness.body && typeof readiness.body === "object" && !Array.isArray(readiness.body)) {
      const readinessRecord = readiness.body as Record<string, unknown>;
      const database = readinessRecord.database as Record<string, unknown> | undefined;
      databaseHealthy = database?.healthy === true;
      const observedSchema = Number(database?.currentMigration);
      databaseSchema = Number.isSafeInteger(observedSchema) ? observedSchema : null;
      guardedHealthSchema = typeof readinessRecord.schemaVersion === "string"
        ? readinessRecord.schemaVersion
        : null;
      guardedMutationFenced = readinessRecord.mutationFenced === true;
      guardedInvocationId = typeof readinessRecord.invocationId === "string"
        ? readinessRecord.invocationId
        : null;
    }
  } catch (error) {
    readinessError = error instanceof Error ? error.message : "readiness request failed";
  }
  return {
    activeState: properties.ActiveState ?? "unknown",
    mainPid: Number(properties.MainPID ?? 0),
    invocationId: properties.InvocationID ?? "",
    healthStatus,
    semanticStatus,
    readinessStatus,
    readinessSemanticStatus,
    databaseHealthy,
    databaseSchema,
    guardedHealthSchema,
    guardedMutationFenced,
    guardedInvocationId,
    pointers: captureReleasePointerSnapshot(staticStore),
    controlGroup,
    controlGroupProcessIds: cgroupProcessIds,
    listenerProcessIds,
    ...(healthError ? { healthError } : {}),
    ...(readinessError ? { readinessError } : {}),
  };
}

function assertTiScaleObservationHealthy(
  observation: TiScaleStartupObservation,
  expectedSchema: number,
  label: string,
): void {
  // Ti-Scale's versioned health contract uses `healthy`; the protected legacy
  // ChillsPwn endpoint uses `ok`. Keeping the values exact prevents a generic
  // HTTP-200 fixture from silently weakening either release boundary.
  assertHealthyIdentity(observation, label, "healthy");
  if (
    observation.readinessStatus !== 200 || observation.readinessSemanticStatus !== "healthy" ||
    !observation.databaseHealthy || observation.databaseSchema !== expectedSchema ||
    !startupProcessOwnershipIsValid(observation)
  ) {
    throw new Error(
      `${label} is not healthy on expected schema ${String(expectedSchema)}: ` +
      startupObservationSummary(observation),
    );
  }
}

function assertTiScaleObservationJournalGuarded(
  observation: TiScaleStartupObservation,
  label: string,
): void {
  if (
    observation.activeState !== "active" || observation.mainPid <= 0 || !observation.invocationId ||
    observation.healthStatus !== 200 || observation.semanticStatus !== "journal_guarded" ||
    observation.readinessStatus !== 200 || observation.readinessSemanticStatus !== "journal_guarded" ||
    observation.guardedHealthSchema !== "ti-scale.release-journal-guarded-health.v1" ||
    !observation.guardedMutationFenced ||
    observation.guardedInvocationId !== observation.invocationId ||
    !startupProcessOwnershipIsValid(observation)
  ) throw new Error(`${label} is not holding the exact journal-guarded startup fence: ${startupObservationSummary(observation)}`);
}

function startupProcessOwnershipIsValid(observation: TiScaleStartupObservation): boolean {
  const cgroup = new Set(observation.controlGroupProcessIds);
  const controlGroupSegments = observation.controlGroup.split("/").filter(Boolean);
  const expectedControlGroup = observation.controlGroup.startsWith("/") &&
    !controlGroupSegments.includes("..") &&
    controlGroupSegments.at(-1) === SERVICE;
  return expectedControlGroup &&
    observation.mainPid > 0 && cgroup.has(observation.mainPid) &&
    observation.listenerProcessIds.length > 0 &&
    observation.listenerProcessIds.every((pid) => cgroup.has(pid));
}

function startupObservationSummary(observation: TiScaleStartupObservation | undefined): string {
  if (!observation) return "no complete startup observation";
  return [
    `ActiveState=${observation.activeState}`,
    `MainPID=${String(observation.mainPid)}`,
    `InvocationID=${observation.invocationId || "missing"}`,
    `liveness=${String(observation.healthStatus)}/${observation.semanticStatus}`,
    `readiness=${String(observation.readinessStatus)}/${observation.readinessSemanticStatus}`,
    `databaseHealthy=${String(observation.databaseHealthy)}`,
    `schema=${observation.databaseSchema === null ? "unknown" : String(observation.databaseSchema)}`,
    `guardedSchema=${observation.guardedHealthSchema ?? "none"}`,
    `mutationFenced=${String(observation.guardedMutationFenced)}`,
    `reportedInvocation=${observation.guardedInvocationId ?? "none"}`,
    `controlGroup=${observation.controlGroup || "missing"}`,
    `cgroupPids=${observation.controlGroupProcessIds.join(",") || "none"}`,
    `listenerPids=${observation.listenerProcessIds.join(",") || "none"}`,
    `application=${observation.pointers.application.kind}:${observation.pointers.application.target}`,
    `static=${observation.pointers.staticReleaseId}@${observation.pointers.staticManifestSha256}`,
    ...(observation.healthError ? [`healthError=${observation.healthError}`] : []),
    ...(observation.readinessError ? [`readinessError=${observation.readinessError}`] : []),
  ].join(", ");
}

function startupAbortError(signal: AbortSignal): Error {
  const reason = signal.reason;
  return reason instanceof Error
    ? reason
    : new Error(typeof reason === "string" ? reason : "Ti-Scale startup verification was cancelled");
}

async function awaitStartupObservation<T>(
  observation: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) throw startupAbortError(signal);
  let abortListener: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    abortListener = () => reject(startupAbortError(signal));
    signal.addEventListener("abort", abortListener, { once: true });
  });
  try {
    // Do not trust an injected observer to honor AbortSignal. The outer
    // monotonic release deadline remains authoritative even if an observation
    // implementation or platform API becomes permanently stuck.
    return await Promise.race([observation, aborted]);
  } finally {
    if (abortListener) signal.removeEventListener("abort", abortListener);
  }
}

export async function waitForExpectedTiScaleStartup(
  expected: ExpectedTiScaleStartup,
  options: WaitForTiScaleStartupOptions,
): Promise<TiScaleStartupObservation> {
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0) {
    throw new Error("Ti-Scale startup timeout must be a positive safe integer");
  }
  const pollIntervalMs = options.pollIntervalMs ?? 1_000;
  if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs <= 0 || pollIntervalMs > options.timeoutMs) {
    throw new Error("Ti-Scale startup poll interval must be positive and no longer than its timeout");
  }
  const now = options.now ?? performance.now.bind(performance);
  const sleep = options.sleep ?? Bun.sleep;
  const startedAt = now();
  const deadline = startedAt + options.timeoutMs;
  const controller = new AbortController();
  const readinessMode = expected.readinessMode ?? "application";
  const abortFromParent = (): void => {
    if (!controller.signal.aborted) controller.abort(options.signal?.reason ?? "release interrupted");
  };
  if (options.signal?.aborted) abortFromParent();
  else options.signal?.addEventListener("abort", abortFromParent, { once: true });
  const deadlineTimer = setTimeout(() => controller.abort("startup deadline exceeded"), options.timeoutMs);
  let last: TiScaleStartupObservation | undefined;
  let lastObservationError: unknown;
  try {
  while (now() < deadline && !controller.signal.aborted) {
    try {
      last = await awaitStartupObservation(Promise.resolve(options.observe({
        remainingMs: Math.max(1, Math.floor(deadline - now())),
        signal: controller.signal,
      })), controller.signal);
      lastObservationError = undefined;
      if (!releasePointersMatch(last.pointers, expected.pointers)) {
        throw new Error(
          `Ti-Scale startup observed an unexpected application/static pointer: ${startupObservationSummary(last)}`,
        );
      }
      if (last.activeState === "failed" && last.mainPid <= 0) {
        throw new Error("Ti-Scale systemd invocation entered a terminal failed state during startup");
      }
      if (readinessMode === "application" &&
        last.activeState === "active" && last.mainPid > 0 && last.invocationId &&
        last.invocationId === expected.previousInvocationId
      ) {
        throw new Error("Ti-Scale startup reused the pre-stop systemd invocation; restart proof failed");
      }
      if (
        readinessMode === "application" &&
        last.activeState === "active" && last.mainPid > 0 && last.invocationId &&
        last.invocationId !== expected.previousInvocationId &&
        last.healthStatus === 200 && last.semanticStatus === "healthy" &&
        last.readinessStatus === 200 && last.readinessSemanticStatus === "healthy" &&
        last.databaseHealthy && last.databaseSchema === expected.databaseSchema &&
        startupProcessOwnershipIsValid(last)
      ) return last;
      if (
        readinessMode === "journal_guarded" &&
        last.activeState === "active" && last.mainPid > 0 && last.invocationId &&
        last.invocationId !== expected.previousInvocationId &&
        last.healthStatus === 200 && last.semanticStatus === "journal_guarded" &&
        last.readinessStatus === 200 && last.readinessSemanticStatus === "journal_guarded" &&
        last.guardedHealthSchema === "ti-scale.release-journal-guarded-health.v1" &&
        last.guardedMutationFenced && last.guardedInvocationId === last.invocationId &&
        startupProcessOwnershipIsValid(last)
      ) return last;
      if (
        last.readinessStatus === 200 && last.readinessSemanticStatus === "healthy" &&
        last.databaseSchema !== null && last.databaseSchema !== expected.databaseSchema
      ) {
        throw new Error(
          `Ti-Scale became healthy on schema ${String(last.databaseSchema)}; expected ${String(expected.databaseSchema)}`,
        );
      }
    } catch (error) {
      if (
        error instanceof Error &&
        (error.message.includes("unexpected application/static pointer") ||
          error.message.includes("reused the pre-stop systemd invocation") ||
          error.message.includes("became healthy on schema") ||
          error.message.includes("terminal failed state"))
      ) throw error;
      lastObservationError = error;
    }
    const elapsedMs = now() - startedAt;
    options.onProgress?.(last, elapsedMs);
    const sleepMs = Math.min(pollIntervalMs, Math.max(1, deadline - now()));
    let abortSleep: (() => void) | undefined;
    const abortPromise = new Promise<void>((resolve) => {
      abortSleep = () => resolve();
      if (controller.signal.aborted) resolve();
      else controller.signal.addEventListener("abort", abortSleep, { once: true });
    });
    try { await Promise.race([sleep(sleepMs), abortPromise]); }
    finally { if (abortSleep) controller.signal.removeEventListener("abort", abortSleep); }
  }
  } finally {
    clearTimeout(deadlineTimer);
    options.signal?.removeEventListener("abort", abortFromParent);
  }
  const observationError = lastObservationError instanceof Error
    ? `; observationError=${lastObservationError.message}`
    : "";
  if (options.signal?.aborted) throw startupAbortError(options.signal);
  throw new Error(
    `Ti-Scale did not reach the expected active identity within ${String(options.timeoutMs)}ms: ` +
    `${startupObservationSummary(last)}${observationError}`,
  );
}

async function waitForTiScaleExpectedRelease(
  staticStore: StaticArtifactReleaseStore,
  expected: ExpectedTiScaleStartup,
  signal?: AbortSignal,
): Promise<TiScaleStartupObservation> {
  let lastProgressAt = -15_000;
  const readinessMode = expected.readinessMode ??
    (releaseStartupMutationBarrierExists() ? "journal_guarded" : "application");
  return waitForExpectedTiScaleStartup({ ...expected, readinessMode }, {
    timeoutMs: releaseStartupTimeoutMs(),
    pollIntervalMs: 1_000,
    ...(signal ? { signal } : {}),
    observe: (context) => observeTiScaleStartup(staticStore, context),
    onProgress: (observation, elapsedMs) => {
      if (elapsedMs - lastProgressAt < 15_000) return;
      lastProgressAt = elapsedMs;
      process.stderr.write(`${JSON.stringify({
        status: "waiting_for_ti_scale_startup",
        elapsedMs,
        deadlineMs: releaseStartupTimeoutMs(),
        observation: startupObservationSummary(observation),
      })}\n`);
    },
  });
}

async function createDatabaseBackup(path: string): Promise<string> {
  const database = createDatabaseConnection({
    filename: DATABASE_PATH,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try { await backupDatabase(database, path); }
  finally { database.close(); }
  const verification = createDatabaseConnection({
    filename: path,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const integrity = verification.pragma("quick_check") as Array<{ quick_check: string }>;
    const foreignKeys = verification.pragma("foreign_key_check") as unknown[];
    if (integrity.length !== 1 || integrity[0]?.quick_check !== "ok" || foreignKeys.length) {
      throw new Error("Fresh database backup failed integrity or foreign-key verification");
    }
  } finally { verification.close(); }
  return sha256File(path);
}

async function rehearseDatabaseRestore(
  backupPath: string,
  hash: string,
  label: string,
  expectedSchema: number,
  rehearsalRoot: string,
): Promise<void> {
  await withSecuredReleaseRehearsalWorkspace(async (workspace) => {
    const destination = join(workspace, `${label}.sqlite`);
    await restoreMigrationBackup({
      databasePath: destination,
      backupPath,
      expectedSha256: hash,
      serviceStopped: true,
    });
    const metadata = lstatSync(destination);
    if (
      metadata.isSymbolicLink() || !metadata.isFile() ||
      metadata.uid !== (process.getuid?.() ?? metadata.uid) ||
      metadata.gid !== (process.getgid?.() ?? metadata.gid) ||
      (metadata.mode & 0o777) !== 0o600
    ) {
      throw new Error("Restore rehearsal produced a non-regular or incorrectly owned database image");
    }
    if (currentSchema(destination) !== expectedSchema) {
      throw new Error("Fresh database backup restored with an unexpected schema");
    }
  }, { baseDirectory: rehearsalRoot });
}

function runReleaseCapacityPreflight(options: {
  readonly persistentRoot: string;
  readonly rehearsalRoot: string;
  readonly databasePath: string;
  readonly sourcePath: string;
  readonly vaultPath: string;
  readonly sourceSchema: number;
  readonly targetSchema: number;
  readonly checkedAt?: string;
}): ReleaseCapacityPreflightReceipt {
  const assessment = assessReleaseCapacityPreflight(options);
  if (!assessment.sufficient) throw new Error(assessment.failure);
  return assessment.receipt;
}

function assessReleaseCapacityPreflight(options: {
  readonly persistentRoot: string;
  readonly rehearsalRoot: string;
  readonly databasePath: string;
  readonly sourcePath: string;
  readonly vaultPath: string;
  readonly sourceSchema: number;
  readonly targetSchema: number;
  readonly checkedAt?: string;
}): {
  readonly receipt: ReleaseCapacityPreflightReceipt;
  readonly sufficient: boolean;
  readonly failure?: string;
} {
  const requirements = estimateReleaseCapacityRequirements({
    databaseBytes: statSync(options.databasePath, { bigint: true }).size,
    sourceArchiveInputBytes: apparentSizeBytes(options.sourcePath),
    vaultArchiveInputBytes: apparentSizeBytes(options.vaultPath),
    schemaMigrationRequired: databaseMigrationRequired(options.sourceSchema, options.targetSchema),
  });
  const persistent = filesystemCapacitySnapshot(options.persistentRoot);
  const rehearsal = filesystemCapacitySnapshot(inspectRehearsalBase(options.rehearsalRoot));
  let failure: string | undefined;
  try {
    assertReleaseCapacityPreflight(requirements, persistent, rehearsal);
  } catch (error) {
    failure = error instanceof Error ? error.message : "Release capacity preflight failed";
  }
  const sharedFilesystem = persistent.device === rehearsal.device;
  const receipt: ReleaseCapacityPreflightReceipt = {
    schemaVersion: "ti-scale.release-capacity-preflight.v1",
    checkedAt: options.checkedAt ?? new Date().toISOString(),
    sharedFilesystem,
    persistent: {
      path: persistent.path,
      device: persistent.device,
      availableBytes: persistent.availableBytes.toString(),
      requiredBytes: requirements.persistentBytes.toString(),
    },
    rehearsal: {
      path: rehearsal.path,
      device: rehearsal.device,
      availableBytes: rehearsal.availableBytes.toString(),
      requiredBytes: requirements.rehearsalBytes.toString(),
    },
    requirements: {
      persistentDatabaseCopies: requirements.persistentDatabaseCopies,
      persistentArchiveAllowanceBytes: requirements.persistentArchiveAllowanceBytes.toString(),
      persistentReserveBytes: requirements.persistentReserveBytes.toString(),
      rehearsalReserveBytes: requirements.rehearsalReserveBytes.toString(),
    },
  };
  return {
    receipt,
    sufficient: failure === undefined,
    ...(failure ? { failure } : {}),
  };
}

function migrateDatabaseWithRelease(
  release: VerifiedServerRelease,
  backupDirectory: string,
  expectedOwner: { readonly uid: number; readonly gid: number },
  sourceSchema: number,
  releaseMigrationAttestation: ReleaseMigrationAttestation,
): void {
  const stagedAttestation = attestReleaseMigrationCeiling(release.releaseDirectory);
  assertReleaseMigrationAttestationsMatch(
    releaseMigrationAttestation,
    stagedAttestation,
    "Migration-time staged release attestation",
  );
  const releaseSchema = releaseMigrationAttestation.targetSchema;
  if (!databaseMigrationRequired(sourceSchema, releaseSchema)) {
    if (currentSchema(DATABASE_PATH) !== releaseSchema) {
      throw new Error("Canonical database schema changed before the same-schema release activation");
    }
    const metadata = statSync(DATABASE_PATH);
    if (metadata.uid !== expectedOwner.uid || metadata.gid !== expectedOwner.gid || (metadata.mode & 0o777) !== 0o600) {
      throw new Error("Database ownership or mode changed before same-schema release activation");
    }
    return;
  }
  mkdirSync(backupDirectory, { recursive: true, mode: 0o700 });
  chownSync(backupDirectory, expectedOwner.uid, expectedOwner.gid);
  runRequired([
    "/usr/sbin/runuser", "--user", "ti-scale", "--",
    BUN, "run", "server/db/cli.ts", "migrate",
    "--db", DATABASE_PATH, "--backup-dir", backupDirectory,
  ], { cwd: release.releaseDirectory, env: minimalEnvironment("/var/lib/ti-scale") });
  if (currentSchema(DATABASE_PATH) !== releaseSchema) throw new Error("Database migration did not reach the release schema");
  assertReleaseMigrationAttestationsMatch(
    releaseMigrationAttestation,
    attestReleaseMigrationCeiling(release.releaseDirectory),
    "Post-migration staged release attestation",
  );
  const metadata = statSync(DATABASE_PATH);
  if (metadata.uid !== expectedOwner.uid || metadata.gid !== expectedOwner.gid || (metadata.mode & 0o777) !== 0o600) {
    throw new Error("Database ownership or mode changed during migration");
  }
}

async function restoreCanonicalDatabase(receipt: DeploymentReceipt): Promise<void> {
  await verifyChecksumManifest(receipt.backup.root);
  await restoreMigrationBackup({
    databasePath: DATABASE_PATH,
    backupPath: receipt.backup.database,
    expectedSha256: receipt.backup.databaseSha256,
    serviceStopped: true,
    expectedUid: receipt.database.ownerUid,
    expectedGid: receipt.database.ownerGid,
    expectedMode: 0o600,
  });
  if (currentSchema(DATABASE_PATH) !== receipt.database.sourceSchema) {
    throw new Error("Database rollback did not restore the recorded source schema");
  }
}

async function restoreReceiptVault(receipt: DeploymentReceipt, swapId: string): Promise<void> {
  if (!receipt.vault.sourceFingerprint) throw new Error("Receipt lacks a checksum-bound source Vault fingerprint");
  await restoreVaultArchiveAtomically({
    archivePath: receipt.backup.vaultArchive,
    vaultRoot: VAULT_ROOT,
    expectedFingerprint: receipt.vault.sourceFingerprint,
    swapId,
  });
  if (await canonicalVaultFingerprint(VAULT_ROOT) !== receipt.vault.sourceFingerprint) {
    throw new Error("Vault rollback did not restore the recorded source fingerprint");
  }
}

async function restorePreservedVaultImage(options: {
  readonly archivePath: string;
  readonly fingerprint: string;
  readonly swapId: string;
}): Promise<void> {
  await restoreVaultArchiveAtomically({
    archivePath: options.archivePath,
    vaultRoot: VAULT_ROOT,
    expectedFingerprint: options.fingerprint,
    swapId: options.swapId,
  });
  if (await canonicalVaultFingerprint(VAULT_ROOT) !== options.fingerprint) {
    throw new Error("Preserved Vault recovery restored an unexpected fingerprint");
  }
}

async function captureCoupledDatabaseVaultState(): Promise<{
  readonly databaseFingerprint: string;
  readonly vaultFingerprint: string;
}> {
  const databaseBefore = canonicalReleaseDataFingerprint(DATABASE_PATH);
  await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
  const vaultFingerprint = await canonicalVaultFingerprint(VAULT_ROOT);
  const databaseAfter = canonicalReleaseDataFingerprint(DATABASE_PATH);
  if (databaseAfter !== databaseBefore) {
    throw new Error("Canonical database changed while the coupled database/Vault release state was captured");
  }
  await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
  if (await canonicalVaultFingerprint(VAULT_ROOT) !== vaultFingerprint) {
    throw new Error("Managed Vault changed while the coupled database/Vault release state was captured");
  }
  return Object.freeze({ databaseFingerprint: databaseBefore, vaultFingerprint });
}

async function restorePreservedDatabaseImage(options: {
  readonly backupPath: string;
  readonly sha256: string;
  readonly expectedSchema: number;
  readonly ownerUid: number;
  readonly ownerGid: number;
}): Promise<void> {
  await restoreMigrationBackup({
    databasePath: DATABASE_PATH,
    backupPath: options.backupPath,
    expectedSha256: options.sha256,
    serviceStopped: true,
    expectedUid: options.ownerUid,
    expectedGid: options.ownerGid,
    expectedMode: 0o600,
  });
  if (currentSchema(DATABASE_PATH) !== options.expectedSchema) {
    throw new Error("Preserved database recovery restored an unexpected schema");
  }
}

function swapToRecordedTarget(
  target: string,
  swapName: string,
  displacedDirectoryArchive?: string,
): void {
  const application = lstatSync(APPLICATION_PATH);
  if (!application.isSymbolicLink() && !application.isDirectory()) {
    throw new Error("Application recovery requires a directory or release symlink");
  }
  const temporary = join(dirname(APPLICATION_PATH), `.${basename(APPLICATION_PATH)}.${swapName}.rollback-swap`);
  if (existsSync(temporary)) throw new Error("Rollback swap path already exists");
  symlinkSync(resolve(target), temporary);
  let exchanged = false;
  try {
    runRequired(["/usr/bin/mv", "--exchange", "--no-copy", "--no-target-directory", "--", temporary, APPLICATION_PATH]);
    exchanged = true;
    if (realpathSync(APPLICATION_PATH) !== realpathSync(target)) throw new Error("Rollback did not activate the recorded server target");
    const displaced = lstatSync(temporary);
    if (displaced.isSymbolicLink()) unlinkSync(temporary);
    else if (displaced.isDirectory() && displacedDirectoryArchive) {
      const archive = resolve(displacedDirectoryArchive);
      if (existsSync(archive)) {
        const existing = lstatSync(archive);
        if (!existing.isSymbolicLink() || realpathSync(archive) !== realpathSync(target)) {
          throw new Error("Displaced rollback directory archive path contains unexpected content");
        }
        unlinkSync(archive);
      }
      renameSync(temporary, archive);
      syncContainingDirectory(archive);
    } else throw new Error("Application recovery displaced an unpreserved directory");
    exchanged = false;
    syncContainingDirectory(APPLICATION_PATH);
  } catch (error) {
    try {
      if (exchanged && existsSync(temporary)) {
        runRequired(["/usr/bin/mv", "--exchange", "--no-copy", "--no-target-directory", "--", temporary, APPLICATION_PATH]);
      }
    } catch { /* leave both paths for operator recovery */ }
    try { unlinkSync(temporary); } catch { /* recovery state may be a directory */ }
    throw error;
  }
}

export function reconcileStrandedRollbackApplicationSwap(options: {
  readonly applicationPath: string;
  readonly expected: ApplicationPointerSnapshot;
  readonly candidatePaths: readonly string[];
  readonly swapName: string;
  readonly serverReleaseRoot: string;
}): "absent" | "removed_symlink" | "archived_directory" {
  void options;
  throw new Error(
    "Rollback application archive reconciliation is disabled by operator no-backup policy",
  );
  /* c8 ignore start -- unreachable retired rollback-archive reconciliation */
  const applicationPath = resolve(options.applicationPath);
  if (!applicationPointerMatches(captureApplicationPointerSnapshot(applicationPath), options.expected)) {
    throw new Error("Stranded rollback swap cannot be reconciled before the live application identity is exact");
  }
  const stranded = join(
    dirname(applicationPath),
    `.${basename(applicationPath)}.${options.swapName}.rollback-swap`,
  );
  if (!existsSync(stranded)) return "absent";
  const displaced = lstatSync(stranded);
  if (displaced.isSymbolicLink()) {
    unlinkSync(stranded);
    syncContainingDirectory(stranded);
    return "removed_symlink";
  }
  if (!displaced.isDirectory()) {
    throw new Error("Stranded rollback swap is neither a directory nor a release symlink");
  }
  const archiveCandidate = options.candidatePaths[0];
  if (!archiveCandidate) {
    throw new Error("Stranded rollback directory has no journal-bound archive destination");
  }
  const archive = resolve(archiveCandidate);
  relativeInside(options.serverReleaseRoot, archive);
  if (existsSync(archive)) {
    const existing = lstatSync(archive);
    if (
      !existing.isSymbolicLink() || options.expected.kind !== "symlink" ||
      realpathSync(archive) !== realpathSync(options.expected.target)
    ) throw new Error("Stranded rollback archive destination contains unexpected content");
    unlinkSync(archive);
    syncContainingDirectory(archive);
  }
  renameSync(stranded, archive);
  // A cross-directory rename changes both directories. Persist both names so
  // another power loss cannot resurrect an ambiguous rollback swap.
  syncContainingDirectory(stranded);
  syncContainingDirectory(archive);
  return "archived_directory";
  /* c8 ignore stop */
}

/**
 * Remove the deterministic deploy handoff name only after the live source
 * pointer is exact and the stranded entry is proven to be the journal-bound
 * target release symlink. This covers a host loss after the recovery exchange
 * but before restoreExactApplicationPointer could unlink the displaced target.
 */
export async function reconcileStrandedDeployApplicationSwap(options: {
  readonly applicationPath: string;
  readonly expectedSource: ApplicationPointerSnapshot;
  readonly expectedSourceTreeSha256: string;
  readonly expectedTarget: ApplicationPointerSnapshot;
  readonly swapName: string;
  readonly serverReleaseRoot: string;
}): Promise<"absent" | "removed_target_symlink"> {
  const applicationPath = resolve(options.applicationPath);
  const source = captureApplicationPointerSnapshot(applicationPath);
  if (
    !recoveryApplicationPointerMatches(source, options.expectedSource) ||
    await canonicalApplicationTreeFingerprint(source.target) !== options.expectedSourceTreeSha256
  ) {
    throw new Error("Stranded deploy swap cannot be reconciled before the live source identity is exact");
  }
  if (options.expectedTarget.kind !== "symlink") {
    throw new Error("Stranded deploy swap target must be a release symlink");
  }
  relativeInside(options.serverReleaseRoot, options.expectedTarget.target);
  const stranded = join(
    dirname(applicationPath),
    `.${basename(applicationPath)}.${options.swapName}.swap`,
  );
  if (!existsSync(stranded)) return "absent";
  const metadata = lstatSync(stranded);
  if (!metadata.isSymbolicLink()) {
    throw new Error("Stranded deploy swap is not the expected target release symlink");
  }
  const observed = captureApplicationPointerSnapshot(stranded);
  if (!applicationPointerMatches(observed, options.expectedTarget)) {
    throw new Error("Stranded deploy swap does not match the journal-bound target release");
  }
  unlinkSync(stranded);
  syncContainingDirectory(stranded);
  return "removed_target_symlink";
}

function restoreExactApplicationPointer(
  expected: ApplicationPointerSnapshot,
  candidatePaths: readonly string[],
  swapName: string,
  retainDisplacedDirectory = false,
): void {
  if (applicationPointerMatches(captureApplicationPointerSnapshot(), expected)) {
    if (retainDisplacedDirectory) {
      reconcileStrandedRollbackApplicationSwap({
        applicationPath: APPLICATION_PATH,
        expected,
        candidatePaths,
        swapName,
        serverReleaseRoot: SERVER_RELEASE_ROOT,
      });
    }
    return;
  }
  const exactCandidate = candidatePaths.find((candidate) => {
    if (!existsSync(candidate)) return false;
    try { return applicationPointerMatches(captureApplicationPointerSnapshot(candidate), expected); }
    catch { return false; }
  });
  if (exactCandidate) {
    runRequired([
      "/usr/bin/mv", "--exchange", "--no-copy", "--no-target-directory", "--",
      exactCandidate, APPLICATION_PATH,
    ]);
    syncContainingDirectory(APPLICATION_PATH);
    if (!applicationPointerMatches(captureApplicationPointerSnapshot(), expected)) {
      throw new Error("Application pointer exchange did not restore the exact pre-release identity");
    }
    const displaced = lstatSync(exactCandidate);
    if (!displaced.isSymbolicLink()) {
      if (retainDisplacedDirectory && displaced.isDirectory()) {
        syncContainingDirectory(exactCandidate);
        return;
      }
      throw new Error(`Recovered application but refused to remove unexpected displaced path ${exactCandidate}`);
    }
    unlinkSync(exactCandidate);
    syncContainingDirectory(exactCandidate);
    return;
  }
  if (expected.kind === "symlink") {
    swapToRecordedTarget(
      expected.target,
      swapName,
      retainDisplacedDirectory ? candidatePaths[0] : undefined,
    );
    if (applicationPointerMatches(captureApplicationPointerSnapshot(), expected)) return;
  }
  throw new Error("No exact pre-release application pointer identity is available for recovery");
}

/**
 * Last-resort reconstruction for a normally impossible lost preserved path.
 * The archive was fsync'd and checksum-published before the first live
 * mutation. Recovery verifies the complete extracted tree before a single
 * atomic exchange/name publication. A pre-existing wrong target is treated as
 * tampering and is never overwritten.
 */
async function restoreApplicationFromSourceArchive(options: {
  readonly archivePath: string;
  readonly expected: ApplicationPointerSnapshot;
  readonly expectedTreeSha256: string;
  readonly swapId: string;
  readonly displacedDirectoryArchive?: string;
}): Promise<void> {
  const archive = resolve(options.archivePath);
  const listing = runRequired(["/usr/bin/tar", "-tzf", archive]).split("\n").filter(Boolean);
  if (!listing.length || listing.some((entry) =>
    entry.startsWith("/") || entry.includes("\\") ||
    entry.split("/").filter(Boolean).some((segment) => segment === "." || segment === "..")
  )) throw new Error("Checksum-bound application source archive has an unsafe layout");
  const topLevel = listing[0]!.split("/").filter(Boolean)[0];
  if (!topLevel || listing.some((entry) => {
    const normalized = entry.replace(/\/$/u, "");
    return normalized !== topLevel && !normalized.startsWith(`${topLevel}/`);
  })) throw new Error("Application source archive contains more than one root");
  const workspace = join(dirname(APPLICATION_PATH), `.${basename(APPLICATION_PATH)}.${options.swapId}.archive-restore`);
  rmSync(workspace, { recursive: true, force: true });
  mkdirSync(workspace, { mode: 0o700 });
  try {
    runRequired([
      "/usr/bin/tar", "--acls", "--xattrs", "--numeric-owner", "--same-owner",
      "--same-permissions", "-xzf", archive, "-C", workspace,
    ]);
    const extracted = join(workspace, topLevel);
    if (!existsSync(extracted) || !lstatSync(extracted).isDirectory() || lstatSync(extracted).isSymbolicLink()) {
      throw new Error("Application source archive did not restore a real tree root");
    }
    if (await canonicalApplicationTreeFingerprint(extracted) !== options.expectedTreeSha256) {
      throw new Error("Application source archive does not reproduce the journal-bound tree identity");
    }
    syncApplicationRecoveryTree(extracted);
    if (options.expected.kind === "directory") {
      runRequired([
        "/usr/bin/mv", "--exchange", "--no-copy", "--no-target-directory", "--",
        extracted, APPLICATION_PATH,
      ]);
      syncContainingDirectory(APPLICATION_PATH);
      const displaced = lstatSync(extracted);
      if (!displaced.isSymbolicLink()) {
        throw new Error("Application archive exchange displaced an unexpected non-symlink");
      }
      unlinkSync(extracted);
    } else {
      const target = resolve(options.expected.target);
      relativeInside(SERVER_RELEASE_ROOT, target);
      if (existsSync(target)) {
        if (await canonicalApplicationTreeFingerprint(target) !== options.expectedTreeSha256) {
          throw new Error("Recorded previous application target exists with tampered content");
        }
      } else {
        renameSync(extracted, target);
        syncContainingDirectory(target);
      }
      swapToRecordedTarget(target, options.swapId, options.displacedDirectoryArchive);
    }
    if (await canonicalApplicationTreeFingerprint(captureApplicationPointerSnapshot().target) !==
      options.expectedTreeSha256) {
      throw new Error("Application archive recovery did not activate the expected tree identity");
    }
  } finally {
    rmSync(workspace, { recursive: true, force: true });
    syncContainingDirectory(APPLICATION_PATH);
  }
}

function describePlan(args: CliArguments): Record<string, unknown> {
  const current = applicationKindAndTarget();
  const active = queryActiveV2Work(DATABASE_PATH);
  const staticStore = new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT });
  const pointer = staticStore.readActivePointer();
  const sourceSchema = currentSchema(DATABASE_PATH);
  const releaseId = args.releaseId ?? "from-receipt";
  const selectedSourceRoot = args.command === "deploy" ? realpathSync(args.sourceRoot) : current.target;
  if (args.command === "deploy" && (
    !existsSync(join(selectedSourceRoot, "package.json")) ||
    !existsSync(join(selectedSourceRoot, "server/index.ts"))
  )) throw new Error("--source is not a Ti-Scale source tree");
  const sourceMigrationAttestation = args.command === "deploy"
    ? attestReleaseMigrationCeiling(selectedSourceRoot)
    : undefined;
  const releaseTargetSchema = sourceMigrationAttestation?.targetSchema ?? sourceSchema;
  const capacityPreflight = args.command === "deploy"
    ? assessReleaseCapacityPreflight({
        persistentRoot: BACKUP_ROOT,
        rehearsalRoot: configuredRehearsalRoot(),
        databasePath: DATABASE_PATH,
        // The persistent source archive is the incumbent rollback target. The
        // selected candidate is separately attested below and staged before
        // the execute-time capacity boundary.
        sourcePath: current.target,
        vaultPath: VAULT_ROOT,
        sourceSchema,
        targetSchema: releaseTargetSchema,
      })
    : undefined;
  return {
    command: args.command,
    mode: args.mode,
    releaseId,
    boundaries: {
      applicationPath: APPLICATION_PATH,
      service: SERVICE,
      port: 3132,
      database: DATABASE_PATH,
      vaultRoot: VAULT_ROOT,
      serverReleaseRoot: SERVER_RELEASE_ROOT,
      staticReleaseRoot: STATIC_RELEASE_ROOT,
      backupRoot: BACKUP_ROOT,
      rehearsalRoot: configuredRehearsalRoot(),
      legacyServiceObservedOnly: LEGACY_SERVICE,
      legacyPortObservedOnly: 3131,
    },
    current: {
      applicationKind: current.kind,
      applicationTarget: current.target,
      databaseSchema: sourceSchema,
      targetSchema: releaseTargetSchema,
      activeV2Runs: active.activeRuns,
      activeV2Leases: active.activeLeases,
      activeDatabaseWriters: active.activeDatabaseWriters,
      reconciliationRequired: active.reconciliationRequired,
      staticPointer: pointer,
    },
    ...(sourceMigrationAttestation ? {
      selectedSource: {
        path: selectedSourceRoot,
        migrationAttestation: sourceMigrationAttestation,
      },
    } : {}),
    ...(capacityPreflight ? {
      capacityPreflight: {
        phase: "preliminary_read_only",
        sufficient: capacityPreflight.sufficient,
        ...(capacityPreflight.failure ? { failure: capacityPreflight.failure } : {}),
        ...capacityPreflight.receipt,
      },
    } : {}),
    executeOrder: args.command === "deploy" ? [
      "typecheck and complete canonical test suite",
      "build and verify static artifact",
      "stage and verify immutable server release",
      "verify zero active V2 runs, leases, and durable database writers",
      "prove persistent backup and disposable rehearsal filesystems can hold their conservative peak",
      "create and restore-rehearse a fresh online SQLite backup",
      "stop ti-scale.service only",
      "prove no service PID, durable work, or process-open canonical database handle remains",
      "for pre-v35 only, capture the authoritative rollback image before bootstrapping the lease schema",
      "acquire the exclusive canonical maintenance lease before remaining database/server/static mutation",
      "publish and reverify SHA256SUMS",
      "migrate database to the release schema",
      "atomically exchange /opt/ti-scale with the release symlink and activate static pointer",
      "release maintenance before starting 3132 and acquiring its process writer lease",
      "verify database health and reacquire maintenance for any coupled recovery",
      "prove chillspwn.service PID, invocation, and 3131 health are unchanged",
    ] : [
      "verify receipt and every backup checksum",
      "verify zero active V2 work and no canonical database change since deployment",
      "stop ti-scale.service only",
      "preserve failed-release database/source/Vault/pointer",
      "restore recorded server, static pointer, and matching database together",
      "start 3132 and verify health",
      "prove 3131 is unchanged",
    ],
  };
}

async function deploy(
  args: CliArguments,
  interruption?: CooperativeReleaseInterruption,
): Promise<void> {
  const releaseId = args.releaseId!;
  if (args.mode === "dry-run") {
    const legacy = await captureServiceIdentity(LEGACY_SERVICE, CHILLSPWN_HEALTH);
    assertHealthyIdentity(legacy, "ChillsPwn on port 3131");
    process.stdout.write(`${JSON.stringify({ ...describePlan(args), chillspwn: legacy }, null, 2)}\n`);
    return;
  }
  if (process.getuid?.() !== 0) throw new Error("Functional release execution requires root");
  if (args.confirmation !== releaseId) throw new Error("--confirm must exactly match --release-id");
  const checkInterruption = async (): Promise<void> => {
    // Yield once so Bun can deliver a pending POSIX signal that arrived while
    // a synchronous filesystem/subprocess boundary was executing.
    await Bun.sleep(0);
    interruption?.throwIfAborted();
  };
  await checkInterruption();
  const sourceRoot = realpathSync(args.sourceRoot);
  if (!existsSync(join(sourceRoot, "package.json")) || !existsSync(join(sourceRoot, "server/index.ts"))) {
    throw new Error("--source is not a Ti-Scale source tree");
  }
  const initialSourceMigrationAttestation = attestReleaseMigrationCeiling(sourceRoot);
  const legacyBefore = await captureServiceIdentity(LEGACY_SERVICE, CHILLSPWN_HEALTH);
  assertHealthyIdentity(legacyBefore, "ChillsPwn on port 3131");
  assertNoActiveWork();

  const bundleRoot = join(BACKUP_ROOT, releaseId);
  if (existsSync(bundleRoot)) throw new Error(`Backup receipt directory already exists: ${bundleRoot}`);
  if (existsSync(join(SERVER_RELEASE_ROOT, "releases", releaseId))) throw new Error(`Server release already exists: ${releaseId}`);
  const databaseOwner = statSync(DATABASE_PATH);
  const serviceAccount = resolveTiScaleServiceIdentity();
  if (
    databaseOwner.uid !== serviceAccount.uid || databaseOwner.gid !== serviceAccount.gid ||
    (databaseOwner.mode & 0o777) !== 0o600
  ) {
    throw new Error("Canonical database ownership/mode does not match the dedicated ti-scale service account");
  }
  createDirectoryDurably(BACKUP_ROOT, { recursive: true, mode: 0o750 });
  chownSync(BACKUP_ROOT, 0, databaseOwner.gid);
  chmodSync(BACKUP_ROOT, 0o750);
  // Persist the final root ownership/mode as well as every first-install name
  // before any later journal or live release mutation can depend on it.
  createDirectoryDurably(BACKUP_ROOT, { recursive: true, mode: 0o750 });

  // All heavyweight validation and staging happens while the current service remains available.
  runRequired([BUN, "run", "typecheck"], { cwd: sourceRoot, env: { ...minimalEnvironment(), CI: "1" } });
  runRequired([BUN, "run", "test"], { cwd: sourceRoot, env: { ...minimalEnvironment(), CI: "1" } });
  runRequired([BUN, "run", "build"], { cwd: sourceRoot, env: { ...minimalEnvironment(), NODE_ENV: "production" } });
  const sourceMigrationAttestation = assertReleaseMigrationAttestationsMatch(
    initialSourceMigrationAttestation,
    attestReleaseMigrationCeiling(sourceRoot),
    "Post-validation source migration attestation",
  );
  const releaseTargetSchema = sourceMigrationAttestation.targetSchema;
  const staticStore = new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT });
  const previousStaticPointer = staticStore.readActivePointer();
  const stagedStatic = staticStore.stageRelease({ releaseId, sourceDirectory: join(sourceRoot, "dist") });
  staticStore.verifyRelease(releaseId, stagedStatic.manifestSha256);
  const stagedServer = await stageServerRelease({ sourceRoot, releaseRoot: SERVER_RELEASE_ROOT, releaseId });
  await verifyServerRelease(stagedServer.releaseDirectory, releaseId, stagedServer.manifestSha256);
  assertReleaseMigrationAttestationsMatch(
    sourceMigrationAttestation,
    attestReleaseMigrationCeiling(stagedServer.releaseDirectory),
    "Staged release migration attestation",
  );
  await checkInterruption();
  assertNoActiveWork();
  await assertChillspwnUnchanged(legacyBefore);

  const currentApplication = captureApplicationPointerSnapshot();
  const previousApplicationTreeSha256 = await canonicalApplicationTreeFingerprint(currentApplication.target);
  const sourceSchema = currentSchema(DATABASE_PATH);
  const previousPointers: ReleasePointerSnapshot = {
    application: currentApplication,
    staticReleaseId: previousStaticPointer.activeReleaseId,
    staticManifestSha256: previousStaticPointer.activeManifestSha256,
  };
  const tiScaleBefore = await observeTiScaleStartup(staticStore);
  assertTiScaleObservationHealthy(tiScaleBefore, sourceSchema, "Ti-Scale on port 3132");
  if (!releasePointersMatch(tiScaleBefore.pointers, previousPointers)) {
    throw new Error("Ti-Scale pre-release runtime does not match the captured application/static pointers");
  }
  const rehearsalRoot = inspectRehearsalBase(configuredRehearsalRoot());
  // This is intentionally after staging (so the snapshot sees the actual
  // remaining free space) and before any persistent database backup is made.
  const capacityPreflight = runReleaseCapacityPreflight({
    persistentRoot: BACKUP_ROOT,
    rehearsalRoot,
    databasePath: DATABASE_PATH,
    sourcePath: currentApplication.target,
    vaultPath: VAULT_ROOT,
    sourceSchema,
    targetSchema: releaseTargetSchema,
  });

  createDirectoryDurably(bundleRoot, { mode: 0o750 });
  chownSync(bundleRoot, 0, databaseOwner.gid);
  const databaseDirectory = join(bundleRoot, "database");
  mkdirSync(databaseDirectory, { mode: 0o700 });
  const databaseBackup = join(databaseDirectory, "pre-release.sqlite");
  const onlinePreflightDatabase = join(databaseDirectory, "online-preflight.sqlite");
  const onlinePreflightDatabaseSha256 = await createDatabaseBackup(onlinePreflightDatabase);
  await rehearseDatabaseRestore(
    onlinePreflightDatabase,
    onlinePreflightDatabaseSha256,
    "online-preflight-restore",
    sourceSchema,
    rehearsalRoot,
  );

  const previousDirectoryArchive = join(SERVER_RELEASE_ROOT, "releases", `previous-${releaseId}`);
  const inProgressSwapPath = join(dirname(APPLICATION_PATH), `.${basename(APPLICATION_PATH)}.${releaseId}.swap`);
  const plannedPreviousTarget = currentApplication.kind === "directory"
    ? previousDirectoryArchive
    : currentApplication.target;
  if (currentApplication.kind === "directory" && existsSync(previousDirectoryArchive)) {
    throw new Error(`Previous server archive already exists: ${previousDirectoryArchive}`);
  }
  const deployedPointers: ReleasePointerSnapshot = {
    application: {
      kind: "symlink",
      target: realpathSync(stagedServer.releaseDirectory),
      device: "not-applicable-for-symlink",
      inode: "not-applicable-for-symlink",
    },
    staticReleaseId: releaseId,
    staticManifestSha256: stagedStatic.manifestSha256,
  };
  const targetApplicationTreeSha256 = await canonicalApplicationTreeFingerprint(
    stagedServer.releaseDirectory,
  );
  const receiptPath = join(bundleRoot, "deployment-receipt.json");
  const journalDirectory = join(bundleRoot, "transaction-journal");
  const receipt: DeploymentReceipt = {
    schemaVersion: "ti-scale.functional-release-receipt.v1",
    releaseId,
    createdAt: new Date().toISOString(),
    status: "prepared",
    sourceRoot,
    serverRelease: {
      path: stagedServer.releaseDirectory,
      manifestSha256: stagedServer.manifestSha256,
      treeSha256: stagedServer.manifest.treeSha256,
    },
    staticRelease: { releaseId, manifestSha256: stagedStatic.manifestSha256 },
    previous: {
      applicationKind: currentApplication.kind,
      applicationTarget: plannedPreviousTarget,
      applicationDevice: currentApplication.device,
      applicationInode: currentApplication.inode,
      applicationTreeSha256: previousApplicationTreeSha256,
      staticPointer: previousStaticPointer,
    },
    backup: {
      root: bundleRoot,
      database: databaseBackup,
      databaseSha256: "",
      onlinePreflightDatabase,
      onlinePreflightDatabaseSha256,
      sourceArchive: join(bundleRoot, "server-source.tar.gz"),
      vaultArchive: join(bundleRoot, "vault.tar.gz"),
      vaultArchiveSha256: "",
      staticPointer: join(bundleRoot, "static-pointer.json"),
      metadata: join(bundleRoot, "backup-metadata.json"),
    },
    database: {
      sourceSchema,
      targetSchema: releaseTargetSchema,
      migrationAttestation: sourceMigrationAttestation,
      ownerUid: databaseOwner.uid,
      ownerGid: databaseOwner.gid,
      fingerprintPolicy: RELEASE_DATA_FINGERPRINT_POLICY,
    },
    vault: {
      fingerprintPolicy: "managed_tree_content_metadata_v1",
    },
    capacityPreflight,
    chillspwnBefore: legacyBefore,
    tiScaleBefore,
  };
  writeJsonAtomically(receiptPath, receipt);

  let stopAttempted = false;
  let serviceStopped = false;
  let databaseMayBeChanged = false;
  let vaultMayBeChanged = false;
  let databaseMigrated = !databaseMigrationRequired(sourceSchema, releaseTargetSchema);
  let quiescedBoundaryCaptured = false;
  let checksumPath = "";
  let deploymentPhase: DeploymentPhase = "prepared";

  const captureQuiescedBoundary = async (): Promise<void> => {
    if (quiescedBoundaryCaptured) return;
    deploymentPhase = "quiesced_backup";
    if (currentSchema(DATABASE_PATH) !== sourceSchema) {
      throw new Error("Database schema changed between preflight and the quiesced backup boundary");
    }
    receipt.backup.databaseSha256 = await createDatabaseBackup(databaseBackup);
    await rehearseDatabaseRestore(
      databaseBackup,
      receipt.backup.databaseSha256,
      "quiesced-restore",
      sourceSchema,
      rehearsalRoot,
    );
    receipt.database.sourceFingerprint = canonicalReleaseDataFingerprint(databaseBackup);
    if (canonicalReleaseDataFingerprint(DATABASE_PATH) !== receipt.database.sourceFingerprint) {
      throw new Error("Canonical release data changed while the recovery database image was captured");
    }
    tarDirectory(currentApplication.target, receipt.backup.sourceArchive);
    if (await canonicalApplicationTreeFingerprint(currentApplication.target) !== previousApplicationTreeSha256) {
      throw new Error("Predeploy application tree changed while its recovery identity was captured");
    }
    receipt.vault.sourceFingerprint = await canonicalVaultFingerprint(VAULT_ROOT);
    tarDirectory(VAULT_ROOT, receipt.backup.vaultArchive);
    receipt.backup.vaultArchiveSha256 = await sha256File(receipt.backup.vaultArchive);
    if (await canonicalVaultFingerprint(VAULT_ROOT) !== receipt.vault.sourceFingerprint) {
      throw new Error("Managed Vault changed while the quiesced rollback image was captured");
    }
    copyFileSync(join(STATIC_RELEASE_ROOT, "state", "active.json"), receipt.backup.staticPointer);
    chmodSync(receipt.backup.staticPointer, 0o600);
    const quiescedPointer = staticStore.readActivePointer();
    if (JSON.stringify(quiescedPointer) !== JSON.stringify(previousStaticPointer)) {
      throw new Error("Static release pointer changed before the quiesced backup completed");
    }
    writeJsonAtomically(receipt.backup.metadata, {
      schemaVersion: "ti-scale.functional-release-backup.v1",
      releaseId,
      createdAt: new Date().toISOString(),
      database: {
        path: relative(bundleRoot, databaseBackup),
        sha256: receipt.backup.databaseSha256,
        schema: sourceSchema,
        quiesced: true,
        ownerUid: databaseOwner.uid,
        ownerGid: databaseOwner.gid,
        fingerprintPolicy: RELEASE_DATA_FINGERPRINT_POLICY,
        fingerprint: receipt.database.sourceFingerprint,
      },
      onlinePreflightDatabase: {
        path: relative(bundleRoot, onlinePreflightDatabase),
        sha256: onlinePreflightDatabaseSha256,
        schema: sourceSchema,
        rollbackSource: false,
      },
      source: { path: relative(bundleRoot, receipt.backup.sourceArchive), livePath: currentApplication.target },
      rollbackServerTarget: plannedPreviousTarget,
      rollbackApplicationKind: currentApplication.kind,
      rollbackApplicationDevice: currentApplication.device,
      rollbackApplicationInode: currentApplication.inode,
      rollbackServerTreeSha256: previousApplicationTreeSha256,
      serverRelease: {
        path: stagedServer.releaseDirectory,
        manifestSha256: stagedServer.manifestSha256,
        migrationAttestation: sourceMigrationAttestation,
      },
      vault: {
        path: relative(bundleRoot, receipt.backup.vaultArchive),
        livePath: VAULT_ROOT,
        sha256: receipt.backup.vaultArchiveSha256,
        fingerprintPolicy: receipt.vault.fingerprintPolicy,
        fingerprint: receipt.vault.sourceFingerprint,
      },
      staticPointer: {
        path: relative(bundleRoot, receipt.backup.staticPointer),
        value: previousStaticPointer,
      },
      tokenMaterialIncluded: false,
      capacityPreflight,
    });
    const checksum = await writeAndVerifyChecksumManifest(bundleRoot, [
      relative(bundleRoot, databaseBackup),
      relative(bundleRoot, onlinePreflightDatabase),
      relative(bundleRoot, receipt.backup.sourceArchive),
      relative(bundleRoot, receipt.backup.vaultArchive),
      relative(bundleRoot, receipt.backup.staticPointer),
      relative(bundleRoot, receipt.backup.metadata),
    ]);
    checksumPath = checksum.path;
    receipt.backup.checksumManifestSha256 = await sha256File(checksum.path);
    writeJsonAtomically(receiptPath, receipt);
    quiescedBoundaryCaptured = true;
  };

  // Publish the complete, checksum-bound recovery image while the incumbent
  // service is still available. Only after its identity is stable and the
  // transaction journal is durable may the first service/live-state mutation
  // begin. The same snapshot is rechecked at the stopped boundary below.
  await captureQuiescedBoundary();
  const predeployCoupledState = await captureCoupledDatabaseVaultState();
  if (
    predeployCoupledState.databaseFingerprint !== receipt.database.sourceFingerprint ||
    predeployCoupledState.vaultFingerprint !== receipt.vault.sourceFingerprint
  ) throw new Error("Prepared recovery images do not match the exact predeploy database/Vault identity");
  if (canonicalReleaseDataFingerprint(databaseBackup) !== receipt.database.sourceFingerprint) {
    throw new Error("Prepared recovery database does not reproduce the predeploy data identity");
  }
  if (await canonicalApplicationTreeFingerprint(currentApplication.target) !== previousApplicationTreeSha256) {
    throw new Error("Prepared recovery application target no longer matches its tree identity");
  }
  let transactionJournal = createFunctionalReleaseTransactionJournal({
    directory: journalDirectory,
    operation: "deploy",
    releaseId,
    receiptPath,
    recoveryIntent: "restore_predeploy",
    identity: {
      releaseStartupProtocol: RELEASE_SOURCE_RUNTIME_PROTOCOL,
      boundaries: {
        applicationPath: APPLICATION_PATH,
        databasePath: DATABASE_PATH,
        vaultRoot: VAULT_ROOT,
        staticReleaseRoot: STATIC_RELEASE_ROOT,
        backupRoot: BACKUP_ROOT,
        service: SERVICE,
      },
      predeploy: {
        pointers: previousPointers,
        applicationTreeSha256: previousApplicationTreeSha256,
        databaseSchema: sourceSchema,
        databaseFingerprintPolicy: RELEASE_DATA_FINGERPRINT_POLICY,
        databaseFingerprint: receipt.database.sourceFingerprint,
        vaultFingerprintPolicy: receipt.vault.fingerprintPolicy,
        vaultFingerprint: receipt.vault.sourceFingerprint,
        serviceIntent: "active",
        previousInvocationId: tiScaleBefore.invocationId,
      },
      target: {
        pointers: deployedPointers,
        databaseSchema: releaseTargetSchema,
        applicationTreeSha256: targetApplicationTreeSha256,
        migrationAttestation: sourceMigrationAttestation,
      },
      recovery: {
        backupRoot: bundleRoot,
        checksumManifestPath: checksumPath,
        checksumManifestSha256: receipt.backup.checksumManifestSha256,
        databasePath: databaseBackup,
        databaseSha256: receipt.backup.databaseSha256,
        vaultArchivePath: receipt.backup.vaultArchive,
        vaultArchiveSha256: receipt.backup.vaultArchiveSha256,
        sourceArchivePath: receipt.backup.sourceArchive,
        previousDirectoryArchive,
        inProgressSwapPath,
        databaseOwnerUid: databaseOwner.uid,
        databaseOwnerGid: databaseOwner.gid,
      },
    },
  });
  const prepareForwardMutation = (mutation: string): void => {
    transactionJournal = prepareFunctionalReleaseMutation(journalDirectory, "forward", mutation);
  };
  const completeForwardMutation = (mutation: string, detail?: Readonly<Record<string, unknown>>): void => {
    transactionJournal = completeFunctionalReleaseMutation(
      journalDirectory,
      "forward",
      mutation,
      detail,
    );
  };
  const ensureDeployRecoveryJournalStarted = (
    recoveryIntent: "restore_predeploy" | "complete_target" = "restore_predeploy",
  ): void => {
    const fresh = readFunctionalReleaseTransactionJournal(journalDirectory);
    if (fresh.terminal) throw new Error("Completed deploy transaction cannot enter recovery");
    const committed = functionalReleaseTargetCommitRecord(fresh);
    if (committed && recoveryIntent !== "complete_target") {
      throw new Error("Committed deploy target may only reconcile forward");
    }
    if (!committed && recoveryIntent === "complete_target") {
      throw new Error("Deploy target cannot reconcile forward before its durable commitment");
    }
    if (!fresh.records.some((record) => record.event === "recovery_started")) {
      transactionJournal = appendFunctionalReleaseTransactionRecord(journalDirectory, {
        event: "recovery_started",
        detail: { recoveryIntent },
      });
    } else {
      const recordedIntent = fresh.records.find((record) => record.event === "recovery_started")
        ?.detail?.recoveryIntent;
      if (recordedIntent !== recoveryIntent) {
        throw new Error("Deploy reconciliation intent conflicts with its durable journal");
      }
      transactionJournal = fresh;
    }
  };
  const journalDeployRecoveryMutation = async (
    mutation: string,
    operation: () => void | Promise<void>,
  ): Promise<void> => {
    let fresh = readFunctionalReleaseTransactionJournal(journalDirectory);
    const records = fresh.records.filter((record) =>
      record.direction === "recovery" && record.mutation === mutation
    );
    if (records.some((record) => record.event === "mutation_completed")) return;
    if (!records.some((record) => record.event === "mutation_prepared")) {
      fresh = prepareFunctionalReleaseMutation(journalDirectory, "recovery", mutation);
    }
    await operation();
    transactionJournal = completeFunctionalReleaseMutation(journalDirectory, "recovery", mutation);
  };

  const commitAndActivateRecoveredPredeploy = async (): Promise<void> => {
    let fresh = readFunctionalReleaseTransactionJournal(journalDirectory);
    const exactPredeploy = async (): Promise<void> => {
      if (!await exactRecoveryState({
        staticStore,
        pointers: previousPointers,
        applicationTreeSha256: previousApplicationTreeSha256,
        databaseSchema: sourceSchema,
        databaseFingerprint: receipt.database.sourceFingerprint!,
        vaultFingerprint: receipt.vault.sourceFingerprint!,
      })) throw new Error("Deploy recovery lost its exact predeploy identity before runtime commitment");
    };
    if (!releaseSourceRuntimeCommitted(fresh)) {
      const records = fresh.records.filter((record) =>
        record.direction === "recovery" && record.mutation === RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION
      );
      if (!records.some((record) => record.event === "mutation_prepared")) {
        fresh = prepareFunctionalReleaseMutation(
          journalDirectory,
          "recovery",
          RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
          sourceRuntimeCommitPrepareDetail(fresh),
        );
      }
      await ensureGuardedSourceRuntimeCommit({
        label: "Prepared predeploy source commitment",
        inspect: tiScaleStopSnapshot,
        start: () => startTiScale(journalDirectory),
        waitAndVerify: async () => {
          await exactPredeploy();
          await waitForTiScaleExpectedRelease(staticStore, {
            previousInvocationId: tiScaleBefore.invocationId,
            databaseSchema: sourceSchema,
            pointers: previousPointers,
            readinessMode: "journal_guarded",
          });
          await exactPredeploy();
        },
      });
      transactionJournal = completeFunctionalReleaseMutation(
        journalDirectory,
        "recovery",
        RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
        { outcome: "already_exact" },
      );
      fresh = transactionJournal;
    }
    await journalDeployRecoveryMutation("runtime_activation", async () => {
      fresh = readFunctionalReleaseTransactionJournal(journalDirectory);
      clearTerminalReleaseStartupMutationBarrier(fresh);
      const snapshot = tiScaleStopSnapshot();
      if (snapshot.activeState !== "active" || snapshot.mainPid <= 0) {
        if (!serviceCanRestartUnchanged(snapshot)) {
          throw new Error("Committed predeploy runtime cannot prove process absence before restart");
        }
        startTiScale(journalDirectory);
      }
      await waitForTiScaleExpectedRelease(staticStore, {
        previousInvocationId: tiScaleBefore.invocationId,
        databaseSchema: sourceSchema,
        pointers: captureReleasePointerSnapshot(staticStore),
        readinessMode: "application",
      });
    });
    await journalDeployRecoveryMutation("running_state_verification", async () => {
      const pointers = captureReleasePointerSnapshot(staticStore);
      if (
        !recoveryPointersMatch(pointers, previousPointers) ||
        await canonicalApplicationTreeFingerprint(pointers.application.target) !== previousApplicationTreeSha256 ||
        currentSchema(DATABASE_PATH) !== sourceSchema
      ) throw new Error("Recovered predeploy runtime lost its immutable app/static/schema identity");
      await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
      const observation = await observeTiScaleStartup(staticStore);
      assertTiScaleObservationHealthy(observation, sourceSchema, "Recovered Ti-Scale on port 3132");
      await assertChillspwnUnchanged(legacyBefore);
    });
  };

  const recoverStoppedRelease = async (): Promise<void> => {
    ensureDeployRecoveryJournalStarted();
    if (releaseSourceRuntimeCommitted(readFunctionalReleaseTransactionJournal(journalDirectory))) {
      await commitAndActivateRecoveredPredeploy();
      serviceStopped = false;
      return;
    }
    const observedPointers = captureReleasePointerSnapshot(staticStore);
    const applicationDrifted = !applicationPointerMatches(
      observedPointers.application,
      previousPointers.application,
    );
    const staticDrifted =
      observedPointers.staticReleaseId !== previousPointers.staticReleaseId ||
      observedPointers.staticManifestSha256 !== previousPointers.staticManifestSha256;
    const applicationRecoveryArtifact = existsSync(inProgressSwapPath);
    const mutationStarted = applicationDrifted || applicationRecoveryArtifact || staticDrifted ||
      databaseMayBeChanged || vaultMayBeChanged;
    await journalDeployRecoveryMutation("service_stop_for_recovery", () => {
      const snapshot = tiScaleStopSnapshot();
      if (!serviceCanRestartUnchanged(snapshot)) stopTiScale();
      assertTiScaleStopped();
      assertNoCanonicalDatabaseUsers();
    });
    serviceStopped = true;
    if (!mutationStarted) {
      if (!stopAttempted) {
        throw new Error("Unchanged-service recovery was requested before a Ti-Scale stop attempt");
      }
      await journalDeployRecoveryMutation("service_start", () =>
        restartUnchangedServiceAfterFailedStop({
          inspect: tiScaleStopSnapshot,
          stop: () => { stopTiScale(); },
          beforeStart: async () => {
            assertNoCanonicalDatabaseUsers();
            if (!releasePointersMatch(captureReleasePointerSnapshot(staticStore), previousPointers)) {
              throw new Error("Application/static pointer changed during the failed pre-mutation stop boundary");
            }
            if (
              currentSchema(DATABASE_PATH) !== sourceSchema ||
              canonicalReleaseDataFingerprint(DATABASE_PATH) !== receipt.database.sourceFingerprint ||
              await canonicalVaultFingerprint(VAULT_ROOT) !== receipt.vault.sourceFingerprint
            ) throw new Error("Database/Vault changed during the failed pre-mutation stop boundary");
            await assertChillspwnUnchanged(legacyBefore);
          },
          start: () => startTiScale(journalDirectory),
          verify: async () => {
            await waitForTiScaleExpectedRelease(staticStore, {
              previousInvocationId: tiScaleBefore.invocationId,
              databaseSchema: sourceSchema,
              pointers: previousPointers,
              readinessMode: "journal_guarded",
            });
            await assertChillspwnUnchanged(legacyBefore);
          },
        })
      );
      await journalDeployRecoveryMutation("source_state_verification", async () => {
        if (!await exactRecoveryState({
          staticStore,
          pointers: previousPointers,
          applicationTreeSha256: previousApplicationTreeSha256,
          databaseSchema: sourceSchema,
          databaseFingerprint: receipt.database.sourceFingerprint!,
          vaultFingerprint: receipt.vault.sourceFingerprint!,
        })) throw new Error("Unchanged deploy recovery lost its exact predeploy state");
      });
      await commitAndActivateRecoveredPredeploy();
      serviceStopped = false;
      return;
    }
    // Never trust the local boolean across a systemctl commit/error boundary.
    // `systemctl start` can make the candidate live and still return a failure
    // (for example after a client-side timeout). Re-inspect the real unit,
    // cgroup, and listener before restoring any pointer or database state.
    const stopSnapshot = tiScaleStopSnapshot();
    if (stopSnapshot.activeState !== "inactive" || !serviceCanRestartUnchanged(stopSnapshot)) {
      await journalDeployRecoveryMutation("service_stop_for_recovery", () => { stopTiScale(); });
    }
    serviceStopped = true;
    assertTiScaleStopped();
    assertNoCanonicalDatabaseUsers();

    if (mutationStarted) {
      if (canonicalLeaseSchemaAvailable(DATABASE_PATH)) {
        assertNoActiveWork();
        const recoveryDatabase = createDatabaseConnection({
          filename: DATABASE_PATH,
          fileMustExist: true,
          verifyIntegrity: false,
        });
        const recoveryLeases = new CanonicalDatabaseLeaseService(recoveryDatabase, {
          allowReplacementWithoutLeaseSchema:
            sourceSchema < CANONICAL_DATABASE_LEASE_SCHEMA_VERSION,
        });
        const recoveryHandle = recoveryLeases.acquireMaintenance({
          ownerId: `release:recovery:${releaseId}:${process.pid}`,
          operation: `deploy-recovery:${releaseId}`,
          ttlMs: 60 * 60_000,
        });
        let recoveryDatabaseClosed = false;
        try {
          recoveryLeases.assertActive(recoveryHandle);
          assertNoActiveWork();
          const reconcileDeployApplication = () => journalDeployRecoveryMutation(
            "application_restore",
            async () => {
              try {
                restoreExactApplicationPointer(
                  previousPointers.application,
                  [inProgressSwapPath, previousDirectoryArchive],
                  releaseId,
                );
              } catch (pointerRecoveryError) {
                if (!existsSync(receipt.backup.sourceArchive)) throw pointerRecoveryError;
                await restoreApplicationFromSourceArchive({
                  archivePath: receipt.backup.sourceArchive,
                  expected: previousPointers.application,
                  expectedTreeSha256: previousApplicationTreeSha256,
                  swapId: `${releaseId}-caught-recovery`,
                });
              }
              await reconcileStrandedDeployApplicationSwap({
                applicationPath: APPLICATION_PATH,
                expectedSource: previousPointers.application,
                expectedSourceTreeSha256: previousApplicationTreeSha256,
                expectedTarget: deployedPointers.application,
                swapName: releaseId,
                serverReleaseRoot: SERVER_RELEASE_ROOT,
              });
            },
          );
          await reconcileObservedReleasePointerDrift(previousPointers, {
            inspect: () => captureReleasePointerSnapshot(staticStore),
            applicationMatches: recoveryApplicationPointerMatches,
            reconcileApplication: reconcileDeployApplication,
            restoreApplication: reconcileDeployApplication,
            restoreStatic: () => journalDeployRecoveryMutation("static_restore", () => {
              staticStore.activateRelease(previousStaticPointer.activeReleaseId);
            }),
          });
          recoveryLeases.assertActive(recoveryHandle);
          if (vaultMayBeChanged) {
            await journalDeployRecoveryMutation("vault_restore", () =>
              restoreReceiptVault(receipt, `${releaseId}-deploy-recovery`)
            );
            recoveryLeases.assertActive(recoveryHandle);
          }
          if (databaseMayBeChanged) {
            recoveryDatabase.close();
            recoveryDatabaseClosed = true;
            await journalDeployRecoveryMutation("database_restore", () => restoreCanonicalDatabase(receipt));
            recoveryLeases.releaseAfterDatabaseReplacement(recoveryHandle, "deploy_recovery_completed");
          } else {
            recoveryLeases.release(recoveryHandle, "deploy_recovery_completed");
          }
          if (databaseMayBeChanged || vaultMayBeChanged) {
            await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
          }
        } finally {
          if (!recoveryDatabaseClosed) {
            try { recoveryLeases.release(recoveryHandle, "deploy_recovery_failed"); }
            finally { recoveryDatabase.close(); }
          }
        }
      } else {
        // A migration failure before migration 35 exists cannot be fenced by
        // the database lease it was trying to install. Only the untouched
        // server/static state and a proven process-free database may be
        // restored through this narrow bootstrap recovery path.
        if (applicationDrifted || staticDrifted) {
          throw new Error("Lease schema disappeared after application/static activation; automatic recovery is refused");
        }
        assertNoActiveWork();
        assertNoCanonicalDatabaseUsers();
        if (databaseMayBeChanged) {
          await journalDeployRecoveryMutation("database_restore", () => restoreCanonicalDatabase(receipt));
        }
        if (vaultMayBeChanged) {
          await journalDeployRecoveryMutation("vault_restore", () =>
            restoreReceiptVault(receipt, `${releaseId}-bootstrap-recovery`)
          );
        }
        if (databaseMayBeChanged || vaultMayBeChanged) {
          await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
        }
      }
    }

    await journalDeployRecoveryMutation("source_state_verification", async () => {
      if (!await exactRecoveryState({
        staticStore,
        pointers: previousPointers,
        applicationTreeSha256: previousApplicationTreeSha256,
        databaseSchema: sourceSchema,
        databaseFingerprint: receipt.database.sourceFingerprint!,
        vaultFingerprint: receipt.vault.sourceFingerprint!,
      })) throw new Error("Deploy recovery did not restore the exact predeploy state before restart");
    });
    await journalDeployRecoveryMutation("service_start", async () => {
      startTiScale(journalDirectory);
      const recoveredPointers = captureReleasePointerSnapshot(staticStore);
      await waitForTiScaleExpectedRelease(staticStore, {
        previousInvocationId: tiScaleBefore.invocationId,
        databaseSchema: sourceSchema,
        pointers: recoveredPointers,
        readinessMode: "journal_guarded",
      });
    });
    await commitAndActivateRecoveredPredeploy();
    serviceStopped = false;
  };

  const finalizeCommittedDeployment = async (): Promise<void> => {
    let fresh = readFunctionalReleaseTransactionJournal(journalDirectory);
    const commitment = functionalReleaseTargetCommitRecord(fresh);
    if (!commitment) throw new Error("Deploy target has no durable forward commitment");
    ensureDeployRecoveryJournalStarted("complete_target");
    fresh = readFunctionalReleaseTransactionJournal(journalDirectory);
    const committedState = journalObject(commitment.detail?.targetState, "committed deploy target state");
    const committedTargetPointers = journalPointer(
      committedState.pointers,
      "committed deploy target pointers",
    );
    if (!releasePointersMatch(committedTargetPointers, deployedPointers)) {
      throw new Error("Committed deploy target pointers conflict with the release binding");
    }
    const committedTreeSha256 = journalString(
      committedState.applicationTreeSha256,
      "committed deploy application tree checksum",
    );
    const committedSchema = journalInteger(
      committedState.databaseSchema,
      "committed deploy database schema",
    );
    if (committedSchema !== releaseTargetSchema || committedTreeSha256 !== targetApplicationTreeSha256) {
      throw new Error("Committed deploy target identity conflicts with the release binding");
    }
    assertReleaseMigrationAttestationsMatch(
      sourceMigrationAttestation,
      committedState.migrationAttestation,
      "Committed deploy migration attestation",
    );
    assertExactReleaseDataFingerprintPolicy(committedState.databaseFingerprintPolicy);
    if (committedState.vaultFingerprintPolicy !== "managed_tree_content_metadata_v1") {
      throw new Error("Committed deploy target Vault fingerprint policy is invalid");
    }
    const committedDatabaseFingerprint = journalString(
      committedState.databaseFingerprint,
      "committed deploy database fingerprint",
    );
    const committedVaultFingerprint = journalString(
      committedState.vaultFingerprint,
      "committed deploy Vault fingerprint",
    );
    const committedRuntimeIdentity = committedTargetRuntimeIdentity(
      committedState,
      "Committed deploy target",
    );
    const expectedDatabaseUid = committedRuntimeIdentity.databaseOwnerUid;
    const expectedDatabaseGid = committedRuntimeIdentity.databaseOwnerGid;
    const expectedDatabaseMode = committedRuntimeIdentity.databaseMode;
    const candidateMayHaveAcknowledgedWrites = (): boolean =>
      readFunctionalReleaseTransactionJournal(journalDirectory).records.some((record) =>
        record.event === "mutation_prepared" && record.mutation === "service_start" &&
        (record.direction === "forward" || record.direction === "recovery")
      );

    const verifyCommittedTarget = async (): Promise<void> => {
      const observedPointers = captureReleasePointerSnapshot(staticStore);
      if (!releasePointersMatch(observedPointers, committedTargetPointers)) {
        throw new Error("Committed deploy target pointer drifted; destructive recovery is refused");
      }
      if (await canonicalApplicationTreeFingerprint(observedPointers.application.target) !== committedTreeSha256) {
        throw new Error("Committed deploy application content changed; recovery is refused");
      }
      if (currentSchema(DATABASE_PATH) !== committedSchema) {
        throw new Error("Committed deploy database schema changed; recovery is refused");
      }
      const metadata = lstatSync(DATABASE_PATH);
      if (
        !metadata.isFile() || metadata.isSymbolicLink() ||
        metadata.uid !== expectedDatabaseUid || metadata.gid !== expectedDatabaseGid ||
        (metadata.mode & 0o777) !== expectedDatabaseMode
      ) throw new Error("Committed deploy database file identity or ownership changed; recovery is refused");
      if (!candidateMayHaveAcknowledgedWrites()) {
        if (canonicalReleaseDataFingerprint(DATABASE_PATH) !== committedDatabaseFingerprint) {
          throw new Error("Deploy database changed before its committed target was started");
        }
        if (await canonicalVaultFingerprint(VAULT_ROOT) !== committedVaultFingerprint) {
          throw new Error("Deploy Vault changed before its committed target was started");
        }
      }
      await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
    };

    const verifyCommittedTargetRunning = async (): Promise<void> => {
      await verifyCommittedTarget();
      const observation = await observeTiScaleStartup(staticStore);
      assertTiScaleObservationHealthy(observation, committedSchema, "Committed Ti-Scale on port 3132");
      if (!releasePointersMatch(observation.pointers, committedTargetPointers)) {
        throw new Error("Committed Ti-Scale runtime does not own its target pointers");
      }
    };

    await journalDeployRecoveryMutation("target_state_verification", async () => {
      await verifyCommittedTarget();
    });
    await journalDeployRecoveryMutation("service_start", async () => {
      const snapshot = tiScaleStopSnapshot();
      if (snapshot.activeState === "active" && snapshot.mainPid > 0) {
        await waitForTiScaleExpectedRelease(staticStore, {
          previousInvocationId: tiScaleBefore.invocationId,
          databaseSchema: committedSchema,
          pointers: committedTargetPointers,
        });
        return;
      }
      if (!serviceCanRestartUnchanged(snapshot)) {
        throw new Error("Committed deploy target cannot prove process absence before restart");
      }
      assertNoCanonicalDatabaseUsers();
      startTiScale(journalDirectory);
      serviceStopped = false;
      await waitForTiScaleExpectedRelease(staticStore, {
        previousInvocationId: tiScaleBefore.invocationId,
        databaseSchema: committedSchema,
        pointers: committedTargetPointers,
      });
    });
    await journalDeployRecoveryMutation("running_state_verification", verifyCommittedTargetRunning);
    await journalDeployRecoveryMutation("deployment_receipt_commit", async () => {
      const liveState = await captureCoupledDatabaseVaultState();
      const observation = await observeTiScaleStartup(staticStore);
      receipt.status = "deployed";
      receipt.deployedAt = commitment.recordedAt;
      receipt.tiScaleAfter = observation;
      receipt.chillspwnAfter = await assertChillspwnUnchanged(legacyBefore);
      receipt.database.deployedFingerprint = liveState.databaseFingerprint;
      receipt.vault.deployedFingerprint = liveState.vaultFingerprint;
      delete receipt.failure;
      delete receipt.failureDetail;
      delete receipt.rolledBackAt;
      writeJsonAtomically(receiptPath, receipt);
    });
    const completedReceiptSha256 = await sha256File(receiptPath);
    const completedReceipt = readReceipt(receiptPath);
    if (completedReceipt.status !== "deployed") {
      throw new Error("Committed deploy target did not produce a deployed receipt");
    }
    await verifyReceiptBindings(completedReceipt);
    await verifyCommittedTargetRunning();
    await verifyTerminalReceiptIdentity(receiptPath, completedReceiptSha256);
    const currentJournal = readFunctionalReleaseTransactionJournal(journalDirectory);
    if (!currentJournal.terminal) {
      transactionJournal = appendFunctionalReleaseTransactionRecord(journalDirectory, {
        event: "terminal",
        detail: {
          outcome: "deployed",
          receiptPath,
          receiptSha256: completedReceiptSha256,
          databaseFingerprint: completedReceipt.database.deployedFingerprint!,
          vaultFingerprint: completedReceipt.vault.deployedFingerprint!,
          reconciledForward: true,
        },
      });
      clearTerminalReleaseStartupMutationBarrier(transactionJournal);
    }
    durableDeploymentCommitted = true;
  };

  let failureRecovered = false;
  let durableDeploymentCommitted = false;
  try {
    await executePreparedDeploymentBoundary({
      stopAndProveClean: () => {
        // A systemd timeout can produce failed/MainPID=0. It is recoverable
        // for availability, but cannot enter applyAndVerify below.
        deploymentPhase = "stopping";
        stopAttempted = true;
        prepareForwardMutation("service_stop");
        const stopResult = stopTiScale();
        serviceStopped = true;
        if (stopResult.compatibilityEvidence) {
          receipt.serviceStopCompatibility = stopResult.compatibilityEvidence;
        }
        completeForwardMutation("service_stop", {
          serviceIntent: "inactive",
          stopDisposition: stopResult.disposition,
          ...(stopResult.serviceLeaseReconciliation
            ? { serviceLeaseReconciliation: stopResult.serviceLeaseReconciliation }
            : {}),
          ...(stopResult.compatibilityEvidence
            ? { failedUnitNormalization: stopResult.compatibilityEvidence }
            : {}),
        });
        prepareForwardMutation("deployment_receipt_maintenance");
        receipt.status = "maintenance";
        writeJsonAtomically(receiptPath, receipt);
        completeForwardMutation("deployment_receipt_maintenance", { receiptStatus: receipt.status });
      },
      applyAndVerify: async () => {
    // The service stop and canonical lease are independent proofs. A stray or
    // unregistered SQLite holder is invisible to the lease table, so every
    // deploy path (including same-schema/schema>=35) must prove OS-level
    // handle absence before opening maintenance or creating quiesced backups.
    assertTiScaleStopped();
    assertNoActiveWork();
    assertNoCanonicalDatabaseUsers();
    const stoppedPredeployState = await captureCoupledDatabaseVaultState();
    if (
      stoppedPredeployState.databaseFingerprint !== receipt.database.sourceFingerprint ||
      stoppedPredeployState.vaultFingerprint !== receipt.vault.sourceFingerprint ||
      await canonicalApplicationTreeFingerprint(captureApplicationPointerSnapshot().target) !==
        previousApplicationTreeSha256 ||
      !releasePointersMatch(captureReleasePointerSnapshot(staticStore), previousPointers)
    ) throw new Error("Stopped release boundary no longer matches the checksum-bound predeploy identity");
    assertReleaseMigrationAttestationsMatch(
      sourceMigrationAttestation,
      attestReleaseMigrationCeiling(stagedServer.releaseDirectory),
      "Pre-mutation staged release migration attestation",
    );
    const bootstrapRequired = requiresCanonicalMaintenanceBootstrap(
      sourceSchema,
      releaseTargetSchema,
      canonicalLeaseSchemaAvailable(DATABASE_PATH),
    );
    if (bootstrapRequired) {
      // Migration 35 cannot protect its own installation. Bootstrap it only
      // after the service, durable work, and every open database handle have
      // independently been proven absent, with the authoritative restore image
      // already checksum-bound and restore-rehearsed.
      assertTiScaleStopped();
      assertNoActiveWork();
      assertNoCanonicalDatabaseUsers();
      await assertChillspwnUnchanged(legacyBefore);
      await captureQuiescedBoundary();
      await checkInterruption();
      assertTiScaleStopped();
      assertNoActiveWork();
      assertNoCanonicalDatabaseUsers();
      databaseMayBeChanged = true;
      deploymentPhase = "database_migration";
      prepareForwardMutation("database_migration");
      migrateDatabaseWithRelease(
        stagedServer,
        join(bundleRoot, "migration-backups"),
        databaseOwner,
        sourceSchema,
        sourceMigrationAttestation,
      );
      databaseMigrated = true;
      completeForwardMutation("database_migration", {
        databaseSchema: releaseTargetSchema,
        migrationAttestationSha256: sourceMigrationAttestation.attestationSha256,
      });
      await checkInterruption();
      if (!canonicalLeaseSchemaAvailable(DATABASE_PATH)) {
        throw new Error("Bootstrap migration completed without installing the canonical maintenance lease schema");
      }
      assertNoCanonicalDatabaseUsers();
    }

    await runMaintenanceThenServiceStart(async () => {
      const maintenanceDatabase = createDatabaseConnection({
        filename: DATABASE_PATH,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      try {
        await withCanonicalMaintenanceLease(maintenanceDatabase, {
          ownerId: `release:${releaseId}:${process.pid}`,
          operation: `deploy:${releaseId}`,
          ttlMs: 60 * 60_000,
        }, async (maintenanceHandle, maintenanceLeases) => {
          maintenanceLeases.assertActive(maintenanceHandle);
          assertNoActiveWork();
          await assertChillspwnUnchanged(legacyBefore);
          if (!quiescedBoundaryCaptured) await captureQuiescedBoundary();
          await checkInterruption();
          if (!databaseMigrated) {
            databaseMayBeChanged = true;
            deploymentPhase = "database_migration";
            maintenanceLeases.assertActive(maintenanceHandle);
            prepareForwardMutation("database_migration");
            migrateDatabaseWithRelease(
              stagedServer,
              join(bundleRoot, "migration-backups"),
              databaseOwner,
              sourceSchema,
              sourceMigrationAttestation,
            );
            databaseMigrated = true;
            completeForwardMutation("database_migration", {
              databaseSchema: releaseTargetSchema,
              migrationAttestationSha256: sourceMigrationAttestation.attestationSha256,
            });
            await checkInterruption();
          }
          maintenanceLeases.assertActive(maintenanceHandle);
          await checkInterruption();
          deploymentPhase = "application_activation";
          prepareForwardMutation("application_activation");
          const swap = exchangeApplicationTarget({
            applicationPath: APPLICATION_PATH,
            newTarget: stagedServer.releaseDirectory,
            previousDirectoryArchive,
            swapName: releaseId,
          });
          if (realpathSync(swap.previousTarget) !== realpathSync(plannedPreviousTarget)) {
            throw new Error("Atomic swap did not preserve the planned previous server target");
          }
          receipt.previous.applicationKind = swap.previousKind;
          receipt.previous.applicationTarget = swap.previousTarget;
          if (await canonicalApplicationTreeFingerprint(swap.previousTarget) !== previousApplicationTreeSha256) {
            throw new Error("Atomic swap preserved a previous target with the wrong application tree identity");
          }
          completeForwardMutation("application_activation", { activeTarget: swap.activeTarget });
          await checkInterruption();
          prepareForwardMutation("deployment_receipt_pointer_progress");
          writeJsonAtomically(receiptPath, receipt);
          completeForwardMutation("deployment_receipt_pointer_progress");
          deploymentPhase = "static_activation";
          prepareForwardMutation("static_activation");
          staticStore.activateRelease(releaseId);
          completeForwardMutation("static_activation", {
            staticReleaseId: releaseId,
            staticManifestSha256: stagedStatic.manifestSha256,
          });
          maintenanceLeases.assertActive(maintenanceHandle);
          await checkInterruption();
        });
      } finally {
        maintenanceDatabase.close();
      }
    }, async () => {
      // The server owns a process-lifetime writer lease. Starting it while the
      // exclusive maintenance marker is present would deterministically fail.
      deploymentPhase = "service_start";
      // This is the durable point of no return. Every target component is
      // exact while the service is still stopped. Once this record reaches
      // disk, crash recovery must preserve target database/Vault writes and
      // complete forward; restoring the predeploy image would discard work
      // that a subsequently started server may have acknowledged.
      assertTiScaleStopped();
      assertNoCanonicalDatabaseUsers();
      prepareForwardMutation("target_data_verification");
      const committedPointers = captureReleasePointerSnapshot(staticStore);
      if (!releasePointersMatch(committedPointers, deployedPointers)) {
        throw new Error("Deploy target pointers are not exact at the durable commit boundary");
      }
      if (await canonicalApplicationTreeFingerprint(committedPointers.application.target) !==
        targetApplicationTreeSha256) {
        throw new Error("Deploy target application content is not exact at the durable commit boundary");
      }
      if (currentSchema(DATABASE_PATH) !== releaseTargetSchema) {
        throw new Error("Deploy target database schema is not exact at the durable commit boundary");
      }
      assertReleaseMigrationAttestationsMatch(
        sourceMigrationAttestation,
        attestReleaseMigrationCeiling(committedPointers.application.target),
        "Commit-bound active release migration attestation",
      );
      await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
      const committedCoupledState = await captureCoupledDatabaseVaultState();
      const committedDatabaseMetadata = statSync(DATABASE_PATH);
      completeForwardMutation("target_data_verification", {
        databaseSchema: releaseTargetSchema,
        databaseFingerprint: committedCoupledState.databaseFingerprint,
        vaultFingerprint: committedCoupledState.vaultFingerprint,
        migrationAttestationSha256: sourceMigrationAttestation.attestationSha256,
      });
      transactionJournal = commitFunctionalReleaseTransactionTarget(journalDirectory, {
        pointers: committedPointers,
        applicationTreeSha256: targetApplicationTreeSha256,
        databaseSchema: releaseTargetSchema,
        migrationAttestation: sourceMigrationAttestation,
        databaseFingerprintPolicy: RELEASE_DATA_FINGERPRINT_POLICY,
        databaseFingerprint: committedCoupledState.databaseFingerprint,
        vaultFingerprintPolicy: "managed_tree_content_metadata_v1",
        vaultFingerprint: committedCoupledState.vaultFingerprint,
        databaseOwnerUid: committedDatabaseMetadata.uid,
        databaseOwnerGid: committedDatabaseMetadata.gid,
        databaseMode: committedDatabaseMetadata.mode & 0o777,
        serviceIntent: "active",
      });
      // Even a same-schema candidate writes process leases, health/read-model
      // state, startup events, and may project notes into the Vault. From this
      // point onward recovery must restore the checksum-bound database+Vault
      // pair, not retain candidate writes from either side.
      databaseMayBeChanged = true;
      vaultMayBeChanged = true;
      await checkInterruption();
      prepareForwardMutation("service_start");
      const earlyAuthenticationStart = captureEarlyAuthenticationStartBoundary();
      startTiScale(journalDirectory);
      serviceStopped = false;
      deploymentPhase = "identity_verification";
      receipt.earlyAuthenticationAfter = await captureReleaseEarlyAuthentication(
        earlyAuthenticationStart,
        tiScaleBefore.invocationId,
        interruption?.signal,
      );
      // Persist this measured boundary immediately. If the process is killed
      // while the longer operational readiness check is still running, the
      // recovery receipt retains what was actually observed rather than
      // reconstructing startup latency after the fact.
      writeJsonAtomically(receiptPath, receipt);
      receipt.tiScaleAfter = await waitForTiScaleExpectedRelease(staticStore, {
        previousInvocationId: tiScaleBefore.invocationId,
        databaseSchema: releaseTargetSchema,
        pointers: deployedPointers,
      }, interruption?.signal);
      assertEarlyAuthenticationAdmissionReceipt(receipt.earlyAuthenticationAfter, {
        previousInvocationId: tiScaleBefore.invocationId,
        currentInvocationId: receipt.tiScaleAfter.invocationId,
      });
      completeForwardMutation("service_start", {
        serviceIntent: "active",
        invocationId: receipt.tiScaleAfter.invocationId,
        earlyAuthentication: receipt.earlyAuthenticationAfter,
      });
      await checkInterruption();
    });
    const legacyAfter = await assertChillspwnUnchanged(legacyBefore);
    receipt.chillspwnAfter = legacyAfter;
    const deployedState = await captureCoupledDatabaseVaultState();
    receipt.vault.deployedFingerprint = deployedState.vaultFingerprint;
    receipt.database.fingerprintPolicy = RELEASE_DATA_FINGERPRINT_POLICY;
    receipt.database.deployedFingerprint = deployedState.databaseFingerprint;
    await checkInterruption();
    deploymentPhase = "receipt_commit";
    receipt.status = "deployed";
    receipt.deployedAt = functionalReleaseTargetCommitRecord(
      readFunctionalReleaseTransactionJournal(journalDirectory),
    )!.recordedAt;
    prepareForwardMutation("deployment_receipt_commit");
    writeJsonAtomically(receiptPath, receipt);
    const deployedReceiptSha256 = await sha256File(receiptPath);
    completeForwardMutation("deployment_receipt_commit", {
      receiptStatus: receipt.status,
      receiptSha256: deployedReceiptSha256,
    });
    const verifiedReceipt = readReceipt(receiptPath);
    if (verifiedReceipt.status !== "deployed") {
      throw new Error("Deploy receipt did not retain its committed status before terminal publication");
    }
    await verifyReceiptBindings(verifiedReceipt);
    await verifyTerminalReceiptIdentity(receiptPath, deployedReceiptSha256);
    const terminalObservation = await observeTiScaleStartup(staticStore);
    assertTiScaleObservationHealthy(terminalObservation, releaseTargetSchema, "Deployed Ti-Scale on port 3132");
    if (!releasePointersMatch(terminalObservation.pointers, deployedPointers)) {
      throw new Error("Deployed Ti-Scale runtime does not own the terminal target pointers");
    }
    await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
    await assertChillspwnUnchanged(legacyBefore);
    transactionJournal = appendFunctionalReleaseTransactionRecord(journalDirectory, {
      event: "terminal",
      detail: {
        outcome: "deployed",
        receiptPath,
        receiptSha256: deployedReceiptSha256,
        databaseFingerprint: receipt.database.deployedFingerprint!,
        vaultFingerprint: receipt.vault.deployedFingerprint!,
      },
    });
    clearTerminalReleaseStartupMutationBarrier(transactionJournal);
    if (transactionJournal.terminal?.detail?.outcome !== "deployed") {
      throw new Error("Deploy terminal journal outcome was not durably retained");
    }
    await verifyTerminalReceiptRecord(transactionJournal.terminal);
    durableDeploymentCommitted = true;
    process.stdout.write(`${JSON.stringify({
      status: "deployed",
      releaseId,
      serverRelease: receipt.serverRelease,
      staticRelease: receipt.staticRelease,
      database: receipt.database,
      backupRoot: bundleRoot,
      receipt: receiptPath,
      checksumManifest: checksumPath,
      legacy3131Unchanged: true,
      chillspwnBefore: receipt.chillspwnBefore,
      chillspwnAfter: receipt.chillspwnAfter,
    }, null, 2)}\n`);
      },
      recoverAndVerifyPrevious: async () => {
        const observedJournal = readFunctionalReleaseTransactionJournal(journalDirectory);
        if (observedJournal.terminal?.detail?.outcome === "deployed") {
          await verifyTerminalReceiptRecord(observedJournal.terminal);
          durableDeploymentCommitted = true;
          return;
        }
        if (functionalReleaseTargetCommitRecord(observedJournal)) {
          await finalizeCommittedDeployment();
          return;
        }
        await recoverStoppedRelease();
        failureRecovered = true;
      },
    }, interruption);
  } catch (error) {
    if (durableDeploymentCommitted) return;
    const primaryFailure = error instanceof FailClosedReleaseRecoveryError
      ? error.releaseFailure
      : error;
    const recoveryFailure = error instanceof FailClosedReleaseRecoveryError
      ? error.recoveryFailure
      : undefined;
    const observedLegacyVerification = legacyVerificationFromError(error);
    const failureDetail: ReleaseFailureDetail = {
      phase: deploymentPhase,
      primary: safeErrorRecord(primaryFailure),
      recovery: {
        attempted: true,
        outcome: failureRecovered ? "succeeded" : "failed",
        ...(recoveryFailure === undefined ? {} : { error: safeErrorRecord(recoveryFailure) }),
      },
      legacyVerification: observedLegacyVerification === "not_evaluated" && failureRecovered
        ? "verified_unchanged"
        : observedLegacyVerification,
    };
    const postFailureJournal = readFunctionalReleaseTransactionJournal(journalDirectory);
    if (functionalReleaseTargetCommitRecord(postFailureJournal)) {
      // Point-of-no-return has passed. Never rewrite the deployment receipt
      // as failed or restore source state here: the committed target may have
      // acknowledged mission, evidence, or Brain writes. Explicit reconcile
      // will continue forward from the durable journal.
      const currentStatus = (JSON.parse(readFileSync(receiptPath, "utf8")) as Partial<DeploymentReceipt>).status;
      const safeStatus: DeploymentReceipt["status"] = [
        "prepared",
        "maintenance",
        "deployed",
        "rolled_back_after_failure",
        "rolled_back",
        "failed",
      ].includes(String(currentStatus))
        ? currentStatus as DeploymentReceipt["status"]
        : receipt.status;
      throw new FunctionalReleaseError(receiptPath, safeStatus, failureDetail, error);
    }
    receipt.failure = failureDetail.primary.message;
    receipt.failureDetail = failureDetail;
    if (failureRecovered) {
      receipt.status = "rolled_back_after_failure";
      const recoveredAt = readFunctionalReleaseTransactionJournal(journalDirectory).records
        .find((record) => record.event === "recovery_started")?.recordedAt ?? new Date().toISOString();
      receipt.rolledBackAt = recoveredAt;
    } else {
      receipt.status = "failed";
    }
    try {
      if (failureRecovered) {
        await journalDeployRecoveryMutation("deployment_receipt_restore", () => {
          writeJsonAtomically(receiptPath, receipt);
        });
      } else writeJsonAtomically(receiptPath, receipt);
    }
    catch (receiptWriteError) {
      const coupledDetail: ReleaseFailureDetail = {
        ...failureDetail,
        receiptWriteError: safeErrorRecord(receiptWriteError),
      };
      throw new FunctionalReleaseError(receiptPath, receipt.status, coupledDetail, error);
    }
    if (failureRecovered) {
      const recoveredJournal = readFunctionalReleaseTransactionJournal(journalDirectory);
      const recoveredAt = recoveredJournal.records.find((record) => record.event === "recovery_started")!.recordedAt;
      const recoveryReceiptPath = join(bundleRoot, "transaction-recovery-receipt.json");
      const recoveryReceipt = functionalRecoveryReceiptValue({
        journal: recoveredJournal,
        recoveredAt,
        pointers: previousPointers,
        applicationTreeSha256: previousApplicationTreeSha256,
        databaseSchema: sourceSchema,
        databaseFingerprint: receipt.database.sourceFingerprint!,
        vaultFingerprint: receipt.vault.sourceFingerprint!,
      });
      await journalDeployRecoveryMutation("terminal_receipt_commit", async () => {
        await writeIdempotentFunctionalRecoveryReceipt(recoveryReceiptPath, recoveryReceipt);
      });
      const recoveryReceiptSha256 = await sha256File(recoveryReceiptPath);
      transactionJournal = appendFunctionalReleaseTransactionRecord(journalDirectory, {
        event: "terminal",
        detail: {
          outcome: "predeploy_restored",
          receiptPath: recoveryReceiptPath,
          receiptSha256: recoveryReceiptSha256,
        },
      });
      clearTerminalReleaseStartupMutationBarrier(transactionJournal);
    }
    throw new FunctionalReleaseError(receiptPath, receipt.status, failureDetail, error);
  }
}

function readReceipt(pathValue: string): DeploymentReceipt {
  const path = assertRealRegularFileWithin(BACKUP_ROOT, pathValue, "Rollback receipt");
  const value = JSON.parse(readFileSync(path, "utf8")) as Partial<DeploymentReceipt>;
  if (
    value.schemaVersion !== "ti-scale.functional-release-receipt.v1" ||
    typeof value.releaseId !== "string" || !RELEASE_ID.test(value.releaseId) || typeof value.backup?.root !== "string" ||
    typeof value.backup?.database !== "string" || typeof value.backup?.databaseSha256 !== "string" ||
    typeof value.backup?.onlinePreflightDatabase !== "string" ||
    typeof value.backup?.onlinePreflightDatabaseSha256 !== "string" ||
    typeof value.backup?.vaultArchive !== "string" || typeof value.backup?.vaultArchiveSha256 !== "string" ||
    typeof value.backup?.checksumManifestSha256 !== "string" ||
    typeof value.backup?.metadata !== "string" || typeof value.backup?.staticPointer !== "string" ||
    typeof value.previous?.applicationTarget !== "string" ||
    typeof value.previous?.applicationDevice !== "string" ||
    typeof value.previous?.applicationInode !== "string" ||
    typeof value.previous?.applicationTreeSha256 !== "string" ||
    typeof value.database?.sourceSchema !== "number" ||
    typeof value.database?.targetSchema !== "number" ||
    typeof value.database?.ownerUid !== "number" || typeof value.database?.ownerGid !== "number" ||
    typeof value.database?.sourceFingerprint !== "string" ||
    typeof value.database?.deployedFingerprint !== "string" ||
    value.vault?.fingerprintPolicy !== "managed_tree_content_metadata_v1" ||
    typeof value.vault.sourceFingerprint !== "string" || typeof value.vault.deployedFingerprint !== "string"
  ) throw new Error("Rollback receipt is invalid or not a completed deployment receipt");
  if (value.database.migrationAttestation !== undefined) {
    const migrationAttestation = assertValidReleaseMigrationAttestation(value.database.migrationAttestation);
    if (migrationAttestation.targetSchema !== value.database.targetSchema) {
      throw new Error("Rollback receipt migration attestation conflicts with its target schema");
    }
  }
  if (value.earlyAuthenticationAfter !== undefined) {
    assertEarlyAuthenticationAdmissionReceipt(value.earlyAuthenticationAfter, {
      ...(value.tiScaleBefore?.invocationId
        ? { previousInvocationId: value.tiScaleBefore.invocationId }
        : {}),
      ...(value.tiScaleAfter?.invocationId
        ? { currentInvocationId: value.tiScaleAfter.invocationId }
        : {}),
    });
  }
  if (resolve(value.backup.root) !== dirname(path)) throw new Error("Rollback receipt backup root does not match its location");
  return value as DeploymentReceipt;
}

function relativeInside(rootValue: string, pathValue: string): string {
  const root = resolve(rootValue);
  const path = resolve(pathValue);
  const child = relative(root, path);
  if (!child || isAbsolute(child) || child === ".." || child.startsWith(`..${sep}`)) {
    throw new Error("Receipt path escapes or aliases its protected release boundary");
  }
  return child.split(sep).join("/");
}

function assertRealRegularFileWithin(
  rootValue: string,
  pathValue: string,
  label: string,
): string {
  const root = resolve(rootValue);
  const rootMetadata = lstatSync(root);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink() || realpathSync(root) !== root) {
    throw new Error(`${label} root must be a real canonical directory`);
  }
  const path = resolve(pathValue);
  const child = relative(root, path);
  if (!child || isAbsolute(child) || child === ".." || child.startsWith(`..${sep}`)) {
    throw new Error(`${label} is outside or aliases its protected root`);
  }
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(path) !== path) {
    throw new Error(`${label} must be a real regular file without symbolic-link ancestry`);
  }
  return path;
}

export interface ReceiptPreviousApplicationBindingVerificationOptions {
  readonly serverReleaseRoot: string;
  /**
   * Set only after a successful rollback has exchanged the preserved original
   * directory back to the live application path. Symlink receipts deliberately
   * continue to bind their immutable release target instead.
   */
  readonly restoredDirectoryApplicationPath?: string;
}

export async function verifyReceiptPreviousApplicationBinding(
  previous: ReceiptPreviousApplicationBinding,
  options: ReceiptPreviousApplicationBindingVerificationOptions,
): Promise<void> {
  // The receipt and checksum-bound metadata always retain the original archive
  // path. Validate that boundary even after the directory itself has moved back
  // to the live application name.
  relativeInside(options.serverReleaseRoot, previous.applicationTarget);

  let identityPath = previous.applicationTarget;
  if (previous.applicationKind === "directory" && options.restoredDirectoryApplicationPath) {
    const restored = captureApplicationPointerSnapshot(options.restoredDirectoryApplicationPath);
    const expected: ApplicationPointerSnapshot = {
      kind: "directory",
      target: previous.applicationTarget,
      device: previous.applicationDevice,
      inode: previous.applicationInode,
    };
    if (!applicationPointerMatches(restored, expected)) {
      throw new Error("Restored directory application identity does not match the checksum-bound receipt dev/inode");
    }
    identityPath = restored.target;
  }

  if (await canonicalApplicationTreeFingerprint(identityPath) !== previous.applicationTreeSha256) {
    const location = identityPath === previous.applicationTarget ? "recorded previous server target" : "restored live application";
    throw new Error(`${location} content no longer matches its checksum-bound tree identity`);
  }
}

interface ReceiptBindingVerificationOptions {
  readonly restoredDirectoryApplicationPath?: string;
}

async function verifyReceiptBindings(
  receipt: DeploymentReceipt,
  options: ReceiptBindingVerificationOptions = {},
): Promise<Readonly<Record<string, string>>> {
  if (receipt.earlyAuthenticationAfter !== undefined) {
    assertEarlyAuthenticationAdmissionReceipt(receipt.earlyAuthenticationAfter, {
      ...(receipt.tiScaleBefore?.invocationId
        ? { previousInvocationId: receipt.tiScaleBefore.invocationId }
        : {}),
      ...(receipt.tiScaleAfter?.invocationId
        ? { currentInvocationId: receipt.tiScaleAfter.invocationId }
        : {}),
    });
  }
  const entries = await verifyChecksumManifest(receipt.backup.root);
  const checksumManifestSha256 = await sha256File(join(receipt.backup.root, BACKUP_CHECKSUM_MANIFEST));
  if (checksumManifestSha256 !== receipt.backup.checksumManifestSha256) {
    throw new Error("Rollback checksum manifest does not match its receipt-bound checksum");
  }
  const databaseRelative = relativeInside(receipt.backup.root, receipt.backup.database);
  const onlineRelative = relativeInside(receipt.backup.root, receipt.backup.onlinePreflightDatabase);
  const vaultRelative = relativeInside(receipt.backup.root, receipt.backup.vaultArchive);
  const metadataRelative = relativeInside(receipt.backup.root, receipt.backup.metadata);
  const pointerRelative = relativeInside(receipt.backup.root, receipt.backup.staticPointer);
  if (
    entries[databaseRelative] !== receipt.backup.databaseSha256 ||
    entries[onlineRelative] !== receipt.backup.onlinePreflightDatabaseSha256 ||
    entries[vaultRelative] !== receipt.backup.vaultArchiveSha256 ||
    !entries[metadataRelative] || !entries[pointerRelative]
  ) throw new Error("Rollback receipt does not match the checksum-bound backup payloads");

  const metadata = JSON.parse(readFileSync(receipt.backup.metadata, "utf8")) as Record<string, unknown>;
  const database = metadata.database as Record<string, unknown> | undefined;
  const online = metadata.onlinePreflightDatabase as Record<string, unknown> | undefined;
  const server = metadata.serverRelease as Record<string, unknown> | undefined;
  const vault = metadata.vault as Record<string, unknown> | undefined;
  const pointerMetadata = metadata.staticPointer as Record<string, unknown> | undefined;
  if (
    metadata.schemaVersion !== "ti-scale.functional-release-backup.v1" || metadata.releaseId !== receipt.releaseId ||
    database?.path !== databaseRelative || database.sha256 !== receipt.backup.databaseSha256 ||
    database.schema !== receipt.database.sourceSchema || database.ownerUid !== receipt.database.ownerUid ||
    database.ownerGid !== receipt.database.ownerGid || database.quiesced !== true ||
    database.fingerprintPolicy !== RELEASE_DATA_FINGERPRINT_POLICY ||
    database.fingerprint !== receipt.database.sourceFingerprint ||
    online?.path !== onlineRelative || online.sha256 !== receipt.backup.onlinePreflightDatabaseSha256 ||
    vault?.path !== vaultRelative || vault.sha256 !== receipt.backup.vaultArchiveSha256 ||
    vault.fingerprintPolicy !== receipt.vault.fingerprintPolicy ||
    vault.fingerprint !== receipt.vault.sourceFingerprint ||
    metadata.rollbackServerTarget !== receipt.previous.applicationTarget ||
    metadata.rollbackApplicationKind !== receipt.previous.applicationKind ||
    metadata.rollbackApplicationDevice !== receipt.previous.applicationDevice ||
    metadata.rollbackApplicationInode !== receipt.previous.applicationInode ||
    metadata.rollbackServerTreeSha256 !== receipt.previous.applicationTreeSha256 ||
    server?.path !== receipt.serverRelease.path || server.manifestSha256 !== receipt.serverRelease.manifestSha256 ||
    (receipt.database.migrationAttestation !== undefined &&
      JSON.stringify(server?.migrationAttestation) !== JSON.stringify(receipt.database.migrationAttestation)) ||
    pointerMetadata?.path !== pointerRelative || JSON.stringify(pointerMetadata.value) !== JSON.stringify(receipt.previous.staticPointer)
  ) throw new Error("Rollback receipt conflicts with its immutable, checksum-bound backup metadata");

  relativeInside(SERVER_RELEASE_ROOT, receipt.serverRelease.path);
  if (receipt.database.migrationAttestation !== undefined) {
    const receiptAttestation = assertValidReleaseMigrationAttestation(receipt.database.migrationAttestation);
    if (receiptAttestation.targetSchema !== receipt.database.targetSchema) {
      throw new Error("Rollback receipt migration attestation conflicts with its target schema");
    }
    const release = await verifyServerRelease(
      receipt.serverRelease.path,
      receipt.releaseId,
      receipt.serverRelease.manifestSha256,
    );
    assertReleaseMigrationAttestationsMatch(
      receiptAttestation,
      attestReleaseMigrationCeiling(release.releaseDirectory),
      "Receipt-bound staged release migration attestation",
    );
  }

  const pointer = JSON.parse(readFileSync(receipt.backup.staticPointer, "utf8")) as unknown;
  if (JSON.stringify(pointer) !== JSON.stringify(receipt.previous.staticPointer)) {
    throw new Error("Recorded previous static pointer differs from the checksum-bound pointer snapshot");
  }
  await verifyReceiptPreviousApplicationBinding(receipt.previous, {
    serverReleaseRoot: SERVER_RELEASE_ROOT,
    restoredDirectoryApplicationPath: options.restoredDirectoryApplicationPath,
  });
  return entries;
}

async function rollback(
  args: CliArguments,
  interruption?: CooperativeReleaseInterruption,
): Promise<void> {
  const receipt = readReceipt(args.receiptPath!);
  assertExactReleaseDataFingerprintPolicy(receipt.database.fingerprintPolicy);
  if (args.mode === "dry-run") {
    const checksums = await verifyReceiptBindings(receipt);
    const active = queryActiveV2Work(DATABASE_PATH);
    const currentFingerprint = canonicalReleaseDataFingerprint(DATABASE_PATH);
    const currentVaultFingerprint = await canonicalVaultFingerprint(VAULT_ROOT);
    const legacy = await captureServiceIdentity(LEGACY_SERVICE, CHILLSPWN_HEALTH);
    assertHealthyIdentity(legacy, "ChillsPwn on port 3131");
    process.stdout.write(`${JSON.stringify({
      ...describePlan(args),
      receipt: args.receiptPath,
      receiptReleaseId: receipt.releaseId,
      checksumEntriesVerified: Object.keys(checksums).length,
      activeV2Work: active,
      canonicalStateUnchanged:
        receipt.database.fingerprintPolicy === RELEASE_DATA_FINGERPRINT_POLICY &&
        currentFingerprint === receipt.database.deployedFingerprint,
      vaultProjectionUnchanged:
        receipt.vault.fingerprintPolicy === "managed_tree_content_metadata_v1" &&
        currentVaultFingerprint === receipt.vault.deployedFingerprint,
      previousServerTargetExists: existsSync(receipt.previous.applicationTarget),
      chillspwn: legacy,
    }, null, 2)}\n`);
    return;
  }
  if (process.getuid?.() !== 0) throw new Error("Functional rollback execution requires root");
  if (args.confirmation !== receipt.releaseId) throw new Error("--confirm must exactly match the receipt release ID");
  if (receipt.status !== "deployed") throw new Error(`Only a deployed receipt can be rolled back; receipt status is ${receipt.status}`);
  const checkInterruption = async (): Promise<void> => {
    await Bun.sleep(0);
    interruption?.throwIfAborted();
  };
  await checkInterruption();
  await verifyReceiptBindings(receipt);
  const deployedServer = await verifyServerRelease(
    receipt.serverRelease.path,
    receipt.releaseId,
    receipt.serverRelease.manifestSha256,
  );
  const deployedExpectation: RollbackActiveReleaseExpectation = {
    applicationTarget: deployedServer.releaseDirectory,
    staticReleaseId: receipt.staticRelease.releaseId,
    staticManifestSha256: receipt.staticRelease.manifestSha256,
  };
  assertNoActiveWork();
  assertExactReleaseDataFingerprintPolicy(receipt.database.fingerprintPolicy);
  const currentCoupledState = await captureCoupledDatabaseVaultState();
  if (currentCoupledState.databaseFingerprint !== receipt.database.deployedFingerprint) {
    throw new Error("Canonical Ti-Scale data changed after deployment; automatic database rollback is refused pending reconciliation");
  }
  if (currentCoupledState.vaultFingerprint !== receipt.vault.deployedFingerprint) {
    throw new Error("Managed Vault changed after deployment; automatic rollback is refused pending reconciliation");
  }
  if (!existsSync(receipt.previous.applicationTarget)) throw new Error("Recorded previous server target no longer exists");
  const legacyBefore = await captureServiceIdentity(LEGACY_SERVICE, CHILLSPWN_HEALTH);
  assertHealthyIdentity(legacyBefore, "ChillsPwn on port 3131");
  const rollbackStaticStore = new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT });
  const currentPointers = captureReleasePointerSnapshot(rollbackStaticStore);
  assertRollbackActiveReleaseMatchesReceipt(currentPointers, deployedExpectation);
  const currentApplicationTreeSha256 = await canonicalApplicationTreeFingerprint(currentPointers.application.target);
  if (currentApplicationTreeSha256 !== await canonicalApplicationTreeFingerprint(deployedServer.releaseDirectory)) {
    throw new Error("Deployed application target changed before rollback preservation");
  }
  await checkInterruption();
  const tiScaleBefore = await observeTiScaleStartup(rollbackStaticStore);
  assertTiScaleObservationHealthy(tiScaleBefore, receipt.database.targetSchema, "Ti-Scale on port 3132");
  if (!releasePointersMatch(tiScaleBefore.pointers, currentPointers)) {
    throw new Error("Ti-Scale rollback preflight runtime does not match its application/static pointers");
  }
  const restoredPointers: ReleasePointerSnapshot = {
    application: {
      kind: receipt.previous.applicationKind,
      target: receipt.previous.applicationKind === "directory"
        ? APPLICATION_PATH
        : realpathSync(receipt.previous.applicationTarget),
      device: receipt.previous.applicationDevice,
      inode: receipt.previous.applicationInode,
    },
    staticReleaseId: receipt.previous.staticPointer.activeReleaseId,
    staticManifestSha256: receipt.previous.staticPointer.activeManifestSha256,
  };

  const failedRoot = join(receipt.backup.root, `rollback-preservation-${new Date().toISOString().replace(/[:.]/gu, "-")}`);
  createDirectoryDurably(failedRoot, { mode: 0o700 });
  const failedDatabase = join(failedRoot, "current.sqlite");
  const failedVaultArchive = join(failedRoot, "vault.tar.gz");
  const preservedDeploymentReceipt = join(failedRoot, "deployment-receipt.pre-rollback.json");
  const rollbackJournalDirectory = join(failedRoot, "transaction-journal");
  const rollbackFailureReceipt = join(failedRoot, "rollback-failure.json");
  const databaseOwner = statSync(DATABASE_PATH);
  let stopAttempted = false;
  let serviceStopped = false;
  let rollbackMutationStarted = false;
  let failedDatabaseSha256 = "";
  let failedVaultArchiveSha256 = "";
  let failedVaultFingerprint = "";
  let failedChecksumManifestSha256 = "";
  let rollbackPhase: DeploymentPhase = "prepared";
  const originalDeploymentReceiptSha256 = await sha256File(args.receiptPath!);
  let rollbackTransactionJournal = createFunctionalReleaseTransactionJournal({
    directory: rollbackJournalDirectory,
    operation: "rollback",
    releaseId: receipt.releaseId,
    receiptPath: args.receiptPath!,
    recoveryIntent: "restore_preserved_current",
    identity: {
      releaseStartupProtocol: RELEASE_SOURCE_RUNTIME_PROTOCOL,
      boundaries: {
        applicationPath: APPLICATION_PATH,
        databasePath: DATABASE_PATH,
        vaultRoot: VAULT_ROOT,
        staticReleaseRoot: STATIC_RELEASE_ROOT,
        backupRoot: BACKUP_ROOT,
        service: SERVICE,
      },
      preservedCurrent: {
        pointers: currentPointers,
        applicationTreeSha256: currentApplicationTreeSha256,
        databaseSchema: receipt.database.targetSchema,
        databaseFingerprintPolicy: RELEASE_DATA_FINGERPRINT_POLICY,
        databaseFingerprint: receipt.database.deployedFingerprint,
        vaultFingerprintPolicy: receipt.vault.fingerprintPolicy,
        vaultFingerprint: receipt.vault.deployedFingerprint,
        serviceIntent: "active",
        previousInvocationId: tiScaleBefore.invocationId,
        deploymentReceiptSha256: originalDeploymentReceiptSha256,
      },
      rollbackTarget: {
        pointers: restoredPointers,
        databaseSchema: receipt.database.sourceSchema,
        databaseFingerprint: receipt.database.sourceFingerprint,
        vaultFingerprint: receipt.vault.sourceFingerprint,
        applicationTreeSha256: receipt.previous.applicationTreeSha256,
      },
      recovery: {
        preservationRoot: failedRoot,
        databasePath: failedDatabase,
        vaultArchivePath: failedVaultArchive,
        applicationArchivePath: join(failedRoot, "server-source.tar.gz"),
        rollbackTargetApplicationPath: receipt.previous.applicationTarget,
        deploymentReceiptPath: preservedDeploymentReceipt,
        databaseOwnerUid: databaseOwner.uid,
        databaseOwnerGid: databaseOwner.gid,
      },
    },
  });
  const prepareRollbackMutation = (mutation: string): void => {
    rollbackTransactionJournal = prepareFunctionalReleaseMutation(
      rollbackJournalDirectory,
      "forward",
      mutation,
    );
  };
  const completeRollbackMutation = (mutation: string, detail?: Readonly<Record<string, unknown>>): void => {
    rollbackTransactionJournal = completeFunctionalReleaseMutation(
      rollbackJournalDirectory,
      "forward",
      mutation,
      detail,
    );
  };
  const ensureRollbackRecoveryJournalStarted = (
    recoveryIntent: "restore_preserved_current" | "complete_target" = "restore_preserved_current",
  ): void => {
    const fresh = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
    if (fresh.terminal) throw new Error("Completed rollback transaction cannot enter recovery");
    const committed = functionalReleaseTargetCommitRecord(fresh);
    if (committed && recoveryIntent !== "complete_target") {
      throw new Error("Committed rollback target may only reconcile forward");
    }
    if (!committed && recoveryIntent === "complete_target") {
      throw new Error("Rollback target cannot reconcile forward before its durable commitment");
    }
    if (!fresh.records.some((record) => record.event === "recovery_started")) {
      rollbackTransactionJournal = appendFunctionalReleaseTransactionRecord(rollbackJournalDirectory, {
        event: "recovery_started",
        detail: { recoveryIntent },
      });
    } else {
      const recordedIntent = fresh.records.find((record) => record.event === "recovery_started")
        ?.detail?.recoveryIntent;
      if (recordedIntent !== recoveryIntent) {
        throw new Error("Rollback reconciliation intent conflicts with its durable journal");
      }
      rollbackTransactionJournal = fresh;
    }
  };
  const journalRollbackRecoveryMutation = async (
    mutation: string,
    operation: () => void | Promise<void>,
  ): Promise<void> => {
    const fresh = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
    const records = fresh.records.filter((record) =>
      record.direction === "recovery" && record.mutation === mutation
    );
    if (records.some((record) => record.event === "mutation_completed")) return;
    if (!records.some((record) => record.event === "mutation_prepared")) {
      prepareFunctionalReleaseMutation(rollbackJournalDirectory, "recovery", mutation);
    }
    await operation();
    rollbackTransactionJournal = completeFunctionalReleaseMutation(
      rollbackJournalDirectory,
      "recovery",
      mutation,
    );
  };

  const commitAndActivatePreservedCurrent = async (): Promise<void> => {
    let fresh = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
    const exactPreservedCurrent = async (): Promise<void> => {
      if (!await exactRecoveryState({
        staticStore: rollbackStaticStore,
        pointers: currentPointers,
        applicationTreeSha256: currentApplicationTreeSha256,
        databaseSchema: receipt.database.targetSchema,
        databaseFingerprint: receipt.database.deployedFingerprint!,
        vaultFingerprint: receipt.vault.deployedFingerprint!,
      })) throw new Error("Rollback recovery lost its exact preserved-current identity before runtime commitment");
    };
    if (!releaseSourceRuntimeCommitted(fresh)) {
      const records = fresh.records.filter((record) =>
        record.direction === "recovery" && record.mutation === RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION
      );
      if (!records.some((record) => record.event === "mutation_prepared")) {
        fresh = prepareFunctionalReleaseMutation(
          rollbackJournalDirectory,
          "recovery",
          RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
          sourceRuntimeCommitPrepareDetail(fresh),
        );
      }
      await ensureGuardedSourceRuntimeCommit({
        label: "Prepared preserved-current source commitment",
        inspect: tiScaleStopSnapshot,
        start: () => startTiScale(rollbackJournalDirectory),
        waitAndVerify: async () => {
          await exactPreservedCurrent();
          await waitForTiScaleExpectedRelease(rollbackStaticStore, {
            previousInvocationId: tiScaleBefore.invocationId,
            databaseSchema: receipt.database.targetSchema,
            pointers: currentPointers,
            readinessMode: "journal_guarded",
          });
          await exactPreservedCurrent();
        },
      });
      rollbackTransactionJournal = completeFunctionalReleaseMutation(
        rollbackJournalDirectory,
        "recovery",
        RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
        { outcome: "already_exact" },
      );
      fresh = rollbackTransactionJournal;
    }
    await journalRollbackRecoveryMutation("runtime_activation", async () => {
      fresh = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
      clearTerminalReleaseStartupMutationBarrier(fresh);
      const snapshot = tiScaleStopSnapshot();
      if (snapshot.activeState !== "active" || snapshot.mainPid <= 0) {
        if (!serviceCanRestartUnchanged(snapshot)) {
          throw new Error("Committed preserved-current runtime cannot prove process absence before restart");
        }
        startTiScale(rollbackJournalDirectory);
      }
      await waitForTiScaleExpectedRelease(rollbackStaticStore, {
        previousInvocationId: tiScaleBefore.invocationId,
        databaseSchema: receipt.database.targetSchema,
        pointers: captureReleasePointerSnapshot(rollbackStaticStore),
        readinessMode: "application",
      });
    });
    await journalRollbackRecoveryMutation("running_state_verification", async () => {
      const pointers = captureReleasePointerSnapshot(rollbackStaticStore);
      if (
        !recoveryPointersMatch(pointers, currentPointers) ||
        await canonicalApplicationTreeFingerprint(pointers.application.target) !== currentApplicationTreeSha256 ||
        currentSchema(DATABASE_PATH) !== receipt.database.targetSchema
      ) throw new Error("Recovered preserved-current runtime lost its immutable app/static/schema identity");
      await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
      const observation = await observeTiScaleStartup(rollbackStaticStore);
      assertTiScaleObservationHealthy(
        observation,
        receipt.database.targetSchema,
        "Recovered Ti-Scale on port 3132",
      );
      await assertChillspwnUnchanged(legacyBefore);
    });
  };

  const recoverUnchangedRelease = async (): Promise<void> => {
    await journalRollbackRecoveryMutation("service_stop_for_recovery", () => {
      const snapshot = tiScaleStopSnapshot();
      if (!serviceCanRestartUnchanged(snapshot)) stopTiScale();
      assertTiScaleStopped();
      assertNoCanonicalDatabaseUsers();
    });
    await journalRollbackRecoveryMutation("service_start", () => restartUnchangedServiceAfterFailedStop({
        inspect: tiScaleStopSnapshot,
        stop: () => { stopTiScale(); },
        beforeStart: async () => {
          if (!releasePointersMatch(captureReleasePointerSnapshot(rollbackStaticStore), currentPointers)) {
            throw new Error("Rollback pre-mutation recovery observed pointer drift");
          }
          if (currentSchema(DATABASE_PATH) !== receipt.database.targetSchema) {
            throw new Error("Rollback pre-mutation recovery observed database schema drift");
          }
          if (await canonicalVaultFingerprint(VAULT_ROOT) !== receipt.vault.deployedFingerprint) {
            throw new Error("Rollback pre-mutation recovery observed Vault drift");
          }
          await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
        },
        start: () => startTiScale(rollbackJournalDirectory),
        verify: async () => {
          await waitForTiScaleExpectedRelease(rollbackStaticStore, {
            previousInvocationId: tiScaleBefore.invocationId,
            databaseSchema: receipt.database.targetSchema,
            pointers: currentPointers,
            readinessMode: "journal_guarded",
          });
          await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
          await assertChillspwnUnchanged(legacyBefore);
        },
    }));
    serviceStopped = false;
  };

  const stopMutatedRelease = (): void => {
    const observedStop = tiScaleStopSnapshot();
    if (observedStop.activeState !== "inactive" || !serviceCanRestartUnchanged(observedStop)) stopTiScale();
    serviceStopped = true;
    assertTiScaleStopped();
    assertNoCanonicalDatabaseUsers();
    if (!failedDatabaseSha256) throw new Error("Rollback mutation began without a verified current-database recovery image");
    if (!failedVaultArchiveSha256 || !failedVaultFingerprint) {
      throw new Error("Rollback mutation began without a verified current-Vault recovery image");
    }
  };

  const restoreCurrentRelease = async (): Promise<void> => {
    await verifyChecksumManifest(failedRoot);
    const reconcileCurrentApplication = () => journalRollbackRecoveryMutation("application_restore", async () => {
      const forwardSwapPath = join(
        dirname(APPLICATION_PATH),
        `.${basename(APPLICATION_PATH)}.${receipt.releaseId}.rollback-swap`,
      );
      try {
        restoreExactApplicationPointer(
          currentPointers.application,
          [receipt.previous.applicationTarget, forwardSwapPath],
          `${receipt.releaseId}-rollback-recovery`,
          true,
        );
      } catch (pointerRecoveryError) {
        const archivePath = join(failedRoot, "server-source.tar.gz");
        if (!existsSync(archivePath)) throw pointerRecoveryError;
        await restoreApplicationFromSourceArchive({
          archivePath,
          expected: currentPointers.application,
          expectedTreeSha256: currentApplicationTreeSha256,
          swapId: `${receipt.releaseId}-rollback-caught-recovery`,
          displacedDirectoryArchive: receipt.previous.applicationTarget,
        });
      }
      // The interrupted forward rollback used the unqualified release ID,
      // while this recovery attempt uses its own name. Reconcile both so a
      // durable forward-exchange artifact cannot poison a later rollback.
      reconcileStrandedRollbackApplicationSwap({
        applicationPath: APPLICATION_PATH,
        expected: currentPointers.application,
        candidatePaths: [receipt.previous.applicationTarget],
        swapName: receipt.releaseId,
        serverReleaseRoot: SERVER_RELEASE_ROOT,
      });
    });
    const restoreCurrentPointers = () => reconcileObservedReleasePointerDrift(currentPointers, {
      inspect: () => captureReleasePointerSnapshot(rollbackStaticStore),
      reconcileApplication: reconcileCurrentApplication,
      restoreApplication: reconcileCurrentApplication,
      restoreStatic: () => journalRollbackRecoveryMutation("static_restore", () => {
        rollbackStaticStore.activateRelease(currentPointers.staticReleaseId);
      }),
    });
    if (canonicalLeaseSchemaAvailable(DATABASE_PATH)) {
      const recoveryDatabase = createDatabaseConnection({
        filename: DATABASE_PATH,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      const recoveryLeases = new CanonicalDatabaseLeaseService(recoveryDatabase, {
        allowReplacementWithoutLeaseSchema:
          receipt.database.targetSchema < CANONICAL_DATABASE_LEASE_SCHEMA_VERSION,
      });
      const handle = recoveryLeases.acquireMaintenance({
        ownerId: `release:rollback-recovery:${receipt.releaseId}:${process.pid}`,
        operation: `rollback-recovery:${receipt.releaseId}`,
        ttlMs: 60 * 60_000,
      });
      let databaseClosed = false;
      try {
        recoveryLeases.assertActive(handle);
        await restoreCurrentPointers();
        recoveryLeases.assertActive(handle);
        await journalRollbackRecoveryMutation("vault_restore", () => restorePreservedVaultImage({
            archivePath: failedVaultArchive,
            fingerprint: failedVaultFingerprint,
            swapId: `${receipt.releaseId}-rollback-recovery`,
          }));
        recoveryLeases.assertActive(handle);
        recoveryDatabase.close();
        databaseClosed = true;
        await journalRollbackRecoveryMutation("database_restore", () => restorePreservedDatabaseImage({
            backupPath: failedDatabase,
            sha256: failedDatabaseSha256,
            expectedSchema: receipt.database.targetSchema,
            ownerUid: databaseOwner.uid,
            ownerGid: databaseOwner.gid,
          }));
        recoveryLeases.releaseAfterDatabaseReplacement(handle, "rollback_recovery_completed");
      } finally {
        if (!databaseClosed) {
          try { recoveryLeases.release(handle, "rollback_recovery_failed"); }
          finally { recoveryDatabase.close(); }
        }
      }
    } else {
      await restoreCurrentPointers();
      await journalRollbackRecoveryMutation("vault_restore", () => restorePreservedVaultImage({
          archivePath: failedVaultArchive,
          fingerprint: failedVaultFingerprint,
          swapId: `${receipt.releaseId}-rollback-recovery-bootstrap`,
        }));
      await journalRollbackRecoveryMutation("database_restore", () => restorePreservedDatabaseImage({
          backupPath: failedDatabase,
          sha256: failedDatabaseSha256,
          expectedSchema: receipt.database.targetSchema,
          ownerUid: databaseOwner.uid,
          ownerGid: databaseOwner.gid,
        }));
    }
    await journalRollbackRecoveryMutation("source_state_verification", async () => {
      await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
      if (!await exactRecoveryState({
        staticStore: rollbackStaticStore,
        pointers: currentPointers,
        applicationTreeSha256: currentApplicationTreeSha256,
        databaseSchema: receipt.database.targetSchema,
        databaseFingerprint: receipt.database.deployedFingerprint!,
        vaultFingerprint: receipt.vault.deployedFingerprint!,
      })) throw new Error("Rollback recovery did not restore its exact preserved current state");
      if (receipt.previous.applicationKind === "directory") {
        const archived = lstatSync(receipt.previous.applicationTarget);
        if (
          !archived.isDirectory() || archived.isSymbolicLink() ||
          await canonicalApplicationTreeFingerprint(receipt.previous.applicationTarget) !==
            receipt.previous.applicationTreeSha256
        ) throw new Error("Rollback recovery did not preserve the exact displaced rollback target directory");
      }
    });
  };

  const verifyCurrentRelease = async (): Promise<void> => {
    await waitForTiScaleExpectedRelease(rollbackStaticStore, {
      previousInvocationId: tiScaleBefore.invocationId,
      databaseSchema: receipt.database.targetSchema,
      pointers: currentPointers,
      readinessMode: "journal_guarded",
    });
    await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
    await assertChillspwnUnchanged(legacyBefore);
  };

  const recoverCurrentRelease = async (): Promise<void> => {
    ensureRollbackRecoveryJournalStarted();
    if (releaseSourceRuntimeCommitted(readFunctionalReleaseTransactionJournal(rollbackJournalDirectory))) {
      await commitAndActivatePreservedCurrent();
      serviceStopped = false;
      return;
    }
    await recoverFailedRollback({
      stopAttempted,
      mutationStarted: rollbackMutationStarted,
    }, {
      recoverUnchangedRelease,
      stopMutatedRelease: () => journalRollbackRecoveryMutation("service_stop_for_recovery", stopMutatedRelease),
      restoreCurrentRelease,
      startCurrentRelease: () => journalRollbackRecoveryMutation("service_start", async () => {
        startTiScale(rollbackJournalDirectory);
        serviceStopped = false;
        await waitForTiScaleExpectedRelease(rollbackStaticStore, {
          previousInvocationId: tiScaleBefore.invocationId,
          databaseSchema: receipt.database.targetSchema,
          pointers: captureReleasePointerSnapshot(rollbackStaticStore),
          readinessMode: "journal_guarded",
        });
      }),
      verifyCurrentRelease: () => journalRollbackRecoveryMutation(
        "service_start_guarded_verification",
        verifyCurrentRelease,
      ),
    });
    await journalRollbackRecoveryMutation("source_state_verification", async () => {
      if (!await exactRecoveryState({
        staticStore: rollbackStaticStore,
        pointers: currentPointers,
        applicationTreeSha256: currentApplicationTreeSha256,
        databaseSchema: receipt.database.targetSchema,
        databaseFingerprint: receipt.database.deployedFingerprint!,
        vaultFingerprint: receipt.vault.deployedFingerprint!,
      })) throw new Error("Rollback recovery did not retain its exact preserved-current state");
    });
    await commitAndActivatePreservedCurrent();
    serviceStopped = false;
  };

  const finalizeCommittedRollback = async (): Promise<void> => {
    let fresh = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
    const commitment = functionalReleaseTargetCommitRecord(fresh);
    if (!commitment) throw new Error("Rollback target has no durable forward commitment");
    ensureRollbackRecoveryJournalStarted("complete_target");
    fresh = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
    const committedState = journalObject(commitment.detail?.targetState, "committed rollback target state");
    const committedTargetPointers = journalPointer(
      committedState.pointers,
      "committed rollback target pointers",
    );
    if (!releasePointersMatch(committedTargetPointers, restoredPointers)) {
      throw new Error("Committed rollback target pointers conflict with the release binding");
    }
    const committedTreeSha256 = journalString(
      committedState.applicationTreeSha256,
      "committed rollback application tree checksum",
    );
    const committedSchema = journalInteger(
      committedState.databaseSchema,
      "committed rollback database schema",
    );
    if (
      committedSchema !== receipt.database.sourceSchema ||
      committedTreeSha256 !== receipt.previous.applicationTreeSha256
    ) throw new Error("Committed rollback target identity conflicts with the release binding");
    assertExactReleaseDataFingerprintPolicy(committedState.databaseFingerprintPolicy);
    if (committedState.vaultFingerprintPolicy !== "managed_tree_content_metadata_v1") {
      throw new Error("Committed rollback target Vault fingerprint policy is invalid");
    }
    const committedDatabaseFingerprint = journalString(
      committedState.databaseFingerprint,
      "committed rollback database fingerprint",
    );
    const committedVaultFingerprint = journalString(
      committedState.vaultFingerprint,
      "committed rollback Vault fingerprint",
    );
    if (
      committedDatabaseFingerprint !== receipt.database.sourceFingerprint ||
      committedVaultFingerprint !== receipt.vault.sourceFingerprint
    ) throw new Error("Committed rollback database/Vault baseline conflicts with the immutable receipt target");
    const committedRuntimeIdentity = committedTargetRuntimeIdentity(
      committedState,
      "Committed rollback target",
    );
    const expectedDatabaseUid = committedRuntimeIdentity.databaseOwnerUid;
    const expectedDatabaseGid = committedRuntimeIdentity.databaseOwnerGid;
    const expectedDatabaseMode = committedRuntimeIdentity.databaseMode;
    const targetMayHaveAcknowledgedWrites = (): boolean =>
      readFunctionalReleaseTransactionJournal(rollbackJournalDirectory).records.some((record) =>
        record.event === "mutation_prepared" && record.mutation === "service_start" &&
        (record.direction === "forward" || record.direction === "recovery")
      );

    const verifyCommittedTarget = async (): Promise<void> => {
      const observedPointers = captureReleasePointerSnapshot(rollbackStaticStore);
      if (!releasePointersMatch(observedPointers, committedTargetPointers)) {
        throw new Error("Committed rollback target pointer drifted; destructive recovery is refused");
      }
      if (await canonicalApplicationTreeFingerprint(observedPointers.application.target) !== committedTreeSha256) {
        throw new Error("Committed rollback application content changed; recovery is refused");
      }
      if (currentSchema(DATABASE_PATH) !== committedSchema) {
        throw new Error("Committed rollback database schema changed; recovery is refused");
      }
      const metadata = lstatSync(DATABASE_PATH);
      if (
        !metadata.isFile() || metadata.isSymbolicLink() ||
        metadata.uid !== expectedDatabaseUid || metadata.gid !== expectedDatabaseGid ||
        (metadata.mode & 0o777) !== expectedDatabaseMode
      ) throw new Error("Committed rollback database file identity or ownership changed; recovery is refused");
      if (!targetMayHaveAcknowledgedWrites()) {
        if (canonicalReleaseDataFingerprint(DATABASE_PATH) !== committedDatabaseFingerprint) {
          throw new Error("Rollback database changed before its committed target was started");
        }
        if (await canonicalVaultFingerprint(VAULT_ROOT) !== committedVaultFingerprint) {
          throw new Error("Rollback Vault changed before its committed target was started");
        }
      }
      await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
    };

    const verifyCommittedTargetRunning = async (): Promise<void> => {
      await verifyCommittedTarget();
      const observation = await observeTiScaleStartup(rollbackStaticStore);
      assertTiScaleObservationHealthy(observation, committedSchema, "Committed rolled-back Ti-Scale on port 3132");
      if (!releasePointersMatch(observation.pointers, committedTargetPointers)) {
        throw new Error("Committed rolled-back runtime does not own its target pointers");
      }
    };

    await journalRollbackRecoveryMutation("target_state_verification", async () => {
      await verifyCommittedTarget();
    });
    await journalRollbackRecoveryMutation("service_start", async () => {
      const snapshot = tiScaleStopSnapshot();
      if (snapshot.activeState === "active" && snapshot.mainPid > 0) {
        await waitForTiScaleExpectedRelease(rollbackStaticStore, {
          previousInvocationId: tiScaleBefore.invocationId,
          databaseSchema: committedSchema,
          pointers: committedTargetPointers,
        });
        return;
      }
      if (!serviceCanRestartUnchanged(snapshot)) {
        throw new Error("Committed rollback target cannot prove process absence before restart");
      }
      assertNoCanonicalDatabaseUsers();
      startTiScale(rollbackJournalDirectory);
      serviceStopped = false;
      await waitForTiScaleExpectedRelease(rollbackStaticStore, {
        previousInvocationId: tiScaleBefore.invocationId,
        databaseSchema: committedSchema,
        pointers: committedTargetPointers,
      });
    });
    await journalRollbackRecoveryMutation("running_state_verification", verifyCommittedTargetRunning);
    await journalRollbackRecoveryMutation("deployment_receipt_commit", async () => {
      receipt.status = "rolled_back";
      receipt.rolledBackAt = commitment.recordedAt;
      writeJsonAtomically(args.receiptPath!, receipt);
    });
    const completedReceiptSha256 = await sha256File(args.receiptPath!);
    const completedReceipt = readReceipt(args.receiptPath!);
    if (completedReceipt.status !== "rolled_back") {
      throw new Error("Committed rollback target did not produce a rolled-back receipt");
    }
    await verifyReceiptBindings(completedReceipt, {
      restoredDirectoryApplicationPath: APPLICATION_PATH,
    });
    const liveState = await captureCoupledDatabaseVaultState();
    await verifyCommittedTargetRunning();
    await verifyTerminalReceiptIdentity(args.receiptPath!, completedReceiptSha256);
    const currentJournal = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
    if (!currentJournal.terminal) {
      rollbackTransactionJournal = appendFunctionalReleaseTransactionRecord(
        rollbackJournalDirectory,
        {
          event: "terminal",
          detail: {
            outcome: "rolled_back",
            receiptPath: args.receiptPath!,
            receiptSha256: completedReceiptSha256,
            databaseFingerprint: liveState.databaseFingerprint,
            vaultFingerprint: liveState.vaultFingerprint,
            reconciledForward: true,
          },
        },
      );
      clearTerminalReleaseStartupMutationBarrier(rollbackTransactionJournal);
    }
    durableRollbackCommitted = true;
  };

  let durableRollbackCommitted = false;
  const recoverRollbackOrRecognizeTerminal = async (): Promise<void> => {
    const observedJournal = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
    if (observedJournal.terminal?.detail?.outcome === "rolled_back") {
      await verifyTerminalReceiptRecord(observedJournal.terminal);
      durableRollbackCommitted = true;
      return;
    }
    if (functionalReleaseTargetCommitRecord(observedJournal)) {
      await finalizeCommittedRollback();
      return;
    }
    await recoverCurrentRelease();
  };

  try {
    await executePreparedDeploymentBoundary({
      stopAndProveClean: () => {
        rollbackPhase = "stopping";
        stopAttempted = true;
        prepareRollbackMutation("service_stop");
        const stopResult = stopTiScale();
        serviceStopped = true;
        completeRollbackMutation("service_stop", {
          serviceIntent: "inactive",
          stopDisposition: stopResult.disposition,
          ...(stopResult.serviceLeaseReconciliation
            ? { serviceLeaseReconciliation: stopResult.serviceLeaseReconciliation }
            : {}),
          ...(stopResult.compatibilityEvidence
            ? { failedUnitNormalization: stopResult.compatibilityEvidence }
            : {}),
        });
      },
      applyAndVerify: async () => {
      assertNoCanonicalDatabaseUsers();
      // The online check is repeated after the clean stop because independent
      // static/pointer tooling is not fenced by the process-wide release lock.
      const stoppedDeployedServer = await verifyServerRelease(
        receipt.serverRelease.path,
        receipt.releaseId,
        receipt.serverRelease.manifestSha256,
      );
      if (stoppedDeployedServer.releaseDirectory !== deployedExpectation.applicationTarget) {
        throw new Error("Deployed server identity changed across the rollback stop boundary");
      }
      assertRollbackActiveReleaseMatchesReceipt(
        captureReleasePointerSnapshot(rollbackStaticStore),
        deployedExpectation,
      );
      await runMaintenanceThenServiceStart(async () => {
    const maintenanceDatabase = createDatabaseConnection({
      filename: DATABASE_PATH,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    const maintenanceLeases = new CanonicalDatabaseLeaseService(maintenanceDatabase, {
      allowReplacementWithoutLeaseSchema:
        receipt.database.sourceSchema < CANONICAL_DATABASE_LEASE_SCHEMA_VERSION,
    });
    const maintenanceHandle = maintenanceLeases.acquireMaintenance({
      ownerId: `release:rollback:${receipt.releaseId}:${process.pid}`,
      operation: `rollback:${receipt.releaseId}`,
      ttlMs: 60 * 60_000,
    });
    let maintenanceDatabaseClosed = false;
    try {
      maintenanceLeases.assertActive(maintenanceHandle);
      assertNoActiveWork();
      const stoppedCoupledState = await captureCoupledDatabaseVaultState();
      if (stoppedCoupledState.databaseFingerprint !== receipt.database.deployedFingerprint) {
        throw new Error("Canonical Ti-Scale data changed at the stop boundary; rollback is refused pending reconciliation");
      }
      if (stoppedCoupledState.vaultFingerprint !== receipt.vault.deployedFingerprint) {
        throw new Error("Managed Vault changed at the stop boundary; rollback is refused pending reconciliation");
      }
      rollbackPhase = "quiesced_backup";
      failedDatabaseSha256 = await createDatabaseBackup(failedDatabase);
      tarDirectory(realpathSync(APPLICATION_PATH), join(failedRoot, "server-source.tar.gz"));
      failedVaultFingerprint = await canonicalVaultFingerprint(VAULT_ROOT);
      tarDirectory(VAULT_ROOT, failedVaultArchive);
      failedVaultArchiveSha256 = await sha256File(failedVaultArchive);
      if (await canonicalVaultFingerprint(VAULT_ROOT) !== failedVaultFingerprint) {
        throw new Error("Managed Vault changed while the rollback recovery image was captured");
      }
      copyFileSync(join(STATIC_RELEASE_ROOT, "state", "active.json"), join(failedRoot, "static-pointer.json"));
      copyFileSync(args.receiptPath!, preservedDeploymentReceipt);
      chmodSync(preservedDeploymentReceipt, 0o600);
      const failedChecksum = await writeAndVerifyChecksumManifest(failedRoot, [
        "current.sqlite", "server-source.tar.gz", "vault.tar.gz", "static-pointer.json",
        "deployment-receipt.pre-rollback.json",
      ]);
      failedChecksumManifestSha256 = await sha256File(failedChecksum.path);
      if (failedChecksum.entries["vault.tar.gz"] !== failedVaultArchiveSha256) {
        throw new Error("Rollback preservation checksum does not bind the current Vault archive");
      }
      if (failedChecksum.entries["current.sqlite"] !== failedDatabaseSha256) {
        throw new Error("Rollback preservation checksum does not bind the current database image");
      }
      if (failedChecksum.entries["deployment-receipt.pre-rollback.json"] !== originalDeploymentReceiptSha256) {
        throw new Error("Rollback preservation checksum does not bind the deployed receipt identity");
      }
      rollbackTransactionJournal = appendFunctionalReleaseTransactionRecord(rollbackJournalDirectory, {
        event: "evidence",
        detail: {
          kind: "rollback_preservation",
          checksumManifestPath: failedChecksum.path,
          checksumManifestSha256: failedChecksumManifestSha256,
          databaseSha256: failedDatabaseSha256,
          vaultArchiveSha256: failedVaultArchiveSha256,
          vaultFingerprint: failedVaultFingerprint,
          deploymentReceiptSha256: originalDeploymentReceiptSha256,
          applicationTreeSha256: currentApplicationTreeSha256,
        },
      });
      await checkInterruption();
      rollbackMutationStarted = true;
      rollbackPhase = "application_activation";
      prepareRollbackMutation("application_activation");
      restoreExactApplicationPointer(
        restoredPointers.application,
        [receipt.previous.applicationTarget],
        receipt.releaseId,
      );
      if (await canonicalApplicationTreeFingerprint(captureApplicationPointerSnapshot().target) !==
        receipt.previous.applicationTreeSha256) {
        throw new Error("Rollback application restoration did not reproduce the checksum-bound previous tree");
      }
      completeRollbackMutation("application_activation", {
        activeTarget: receipt.previous.applicationTarget,
      });
      prepareRollbackMutation("static_activation");
      rollbackStaticStore.activateRelease(receipt.previous.staticPointer.activeReleaseId);
      completeRollbackMutation("static_activation", {
        staticReleaseId: receipt.previous.staticPointer.activeReleaseId,
      });
      await checkInterruption();
      maintenanceLeases.assertActive(maintenanceHandle);
      prepareRollbackMutation("vault_restore");
      await restoreReceiptVault(receipt, `${receipt.releaseId}-rollback-target`);
      completeRollbackMutation("vault_restore", { vaultFingerprint: receipt.vault.sourceFingerprint! });
      maintenanceLeases.assertActive(maintenanceHandle);
      maintenanceDatabase.close();
      maintenanceDatabaseClosed = true;
      prepareRollbackMutation("database_restore");
      await restoreCanonicalDatabase(receipt);
      completeRollbackMutation("database_restore", { databaseFingerprint: receipt.database.sourceFingerprint! });
      await checkInterruption();
      maintenanceLeases.releaseAfterDatabaseReplacement(maintenanceHandle, "rollback_completed");
      await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
    } finally {
      if (!maintenanceDatabaseClosed) {
        try { maintenanceLeases.release(maintenanceHandle, "rollback_failed"); }
        finally { maintenanceDatabase.close(); }
      }
    }
    }, async () => {
      // The restored server acquires its own process writer lease (when its
      // schema supports one), so startup happens only after maintenance releases.
      rollbackPhase = "service_start";
      assertTiScaleStopped();
      assertNoCanonicalDatabaseUsers();
      prepareRollbackMutation("target_data_verification");
      const committedPointers = captureReleasePointerSnapshot(rollbackStaticStore);
      if (!releasePointersMatch(committedPointers, restoredPointers)) {
        throw new Error("Rollback target pointers are not exact at the durable commit boundary");
      }
      if (await canonicalApplicationTreeFingerprint(committedPointers.application.target) !==
        receipt.previous.applicationTreeSha256) {
        throw new Error("Rollback target application content is not exact at the durable commit boundary");
      }
      if (currentSchema(DATABASE_PATH) !== receipt.database.sourceSchema) {
        throw new Error("Rollback target database schema is not exact at the durable commit boundary");
      }
      await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
      const committedCoupledState = await captureCoupledDatabaseVaultState();
      if (
        committedCoupledState.databaseFingerprint !== receipt.database.sourceFingerprint ||
        committedCoupledState.vaultFingerprint !== receipt.vault.sourceFingerprint
      ) throw new Error("Rollback target database/Vault identity is not exact at the durable commit boundary");
      const committedDatabaseMetadata = statSync(DATABASE_PATH);
      completeRollbackMutation("target_data_verification", {
        databaseSchema: receipt.database.sourceSchema,
        databaseFingerprint: committedCoupledState.databaseFingerprint,
        vaultFingerprint: committedCoupledState.vaultFingerprint,
      });
      rollbackTransactionJournal = commitFunctionalReleaseTransactionTarget(
        rollbackJournalDirectory,
        {
          pointers: committedPointers,
          applicationTreeSha256: receipt.previous.applicationTreeSha256,
          databaseSchema: receipt.database.sourceSchema,
          databaseFingerprintPolicy: RELEASE_DATA_FINGERPRINT_POLICY,
          databaseFingerprint: committedCoupledState.databaseFingerprint,
          vaultFingerprintPolicy: "managed_tree_content_metadata_v1",
          vaultFingerprint: committedCoupledState.vaultFingerprint,
          databaseOwnerUid: committedDatabaseMetadata.uid,
          databaseOwnerGid: committedDatabaseMetadata.gid,
          databaseMode: committedDatabaseMetadata.mode & 0o777,
          serviceIntent: "active",
        },
      );
      await checkInterruption();
      prepareRollbackMutation("service_start");
      startTiScale(rollbackJournalDirectory);
      serviceStopped = false;
      await waitForTiScaleExpectedRelease(rollbackStaticStore, {
        previousInvocationId: tiScaleBefore.invocationId,
        databaseSchema: receipt.database.sourceSchema,
        pointers: restoredPointers,
      }, interruption?.signal);
      completeRollbackMutation("service_start", { serviceIntent: "active" });
      await checkInterruption();
    });
    await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
    await assertChillspwnUnchanged(legacyBefore);
    rollbackPhase = "receipt_commit";
    await checkInterruption();
    const rolledBackAt = functionalReleaseTargetCommitRecord(
      readFunctionalReleaseTransactionJournal(rollbackJournalDirectory),
    )!.recordedAt;
    prepareRollbackMutation("deployment_receipt_commit");
    receipt.status = "rolled_back";
    receipt.rolledBackAt = rolledBackAt;
    writeJsonAtomically(args.receiptPath!, receipt);
    const rolledBackReceiptSha256 = await sha256File(args.receiptPath!);
    completeRollbackMutation("deployment_receipt_commit", {
      receiptStatus: receipt.status,
      receiptSha256: rolledBackReceiptSha256,
    });
    const verifiedRollbackReceipt = readReceipt(args.receiptPath!);
    if (verifiedRollbackReceipt.status !== "rolled_back") {
      throw new Error("Rollback receipt did not retain its committed status before terminal publication");
    }
    await verifyReceiptBindings(verifiedRollbackReceipt, {
      restoredDirectoryApplicationPath: APPLICATION_PATH,
    });
    await verifyTerminalReceiptIdentity(args.receiptPath!, rolledBackReceiptSha256);
    const terminalObservation = await observeTiScaleStartup(rollbackStaticStore);
    assertTiScaleObservationHealthy(
      terminalObservation,
      receipt.database.sourceSchema,
      "Rolled-back Ti-Scale on port 3132",
    );
    if (!releasePointersMatch(terminalObservation.pointers, restoredPointers)) {
      throw new Error("Rolled-back Ti-Scale runtime does not own the terminal target pointers");
    }
    await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
    await assertChillspwnUnchanged(legacyBefore);
    rollbackTransactionJournal = appendFunctionalReleaseTransactionRecord(rollbackJournalDirectory, {
      event: "terminal",
      detail: {
        outcome: "rolled_back",
        receiptPath: args.receiptPath!,
        receiptSha256: rolledBackReceiptSha256,
        databaseFingerprint: receipt.database.sourceFingerprint!,
        vaultFingerprint: receipt.vault.sourceFingerprint!,
      },
    });
    clearTerminalReleaseStartupMutationBarrier(rollbackTransactionJournal);
    if (rollbackTransactionJournal.terminal?.detail?.outcome !== "rolled_back") {
      throw new Error("Rollback terminal journal outcome was not durably retained");
    }
    await verifyTerminalReceiptRecord(rollbackTransactionJournal.terminal);
    durableRollbackCommitted = true;
    process.stdout.write(`${JSON.stringify({
      status: "rolled_back",
      releaseId: receipt.releaseId,
      restoredServer: receipt.previous.applicationTarget,
      restoredSchema: receipt.database.sourceSchema,
      failedReleasePreservedAt: failedRoot,
      legacy3131Unchanged: true,
    }, null, 2)}\n`);
      },
      recoverAndVerifyPrevious: recoverRollbackOrRecognizeTerminal,
    }, interruption);
  } catch (error) {
    if (durableRollbackCommitted) return;
    const primary = error instanceof FailClosedReleaseRecoveryError ? error.releaseFailure : error;
    let recovery = error instanceof FailClosedReleaseRecoveryError ? error.recoveryFailure : undefined;
    const postFailureJournal = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
    if (functionalReleaseTargetCommitRecord(postFailureJournal)) {
      const committedDetail: ReleaseFailureDetail = {
        phase: rollbackPhase,
        primary: safeErrorRecord(primary),
        recovery: {
          attempted: true,
          outcome: "failed",
          ...(recovery === undefined ? {} : { error: safeErrorRecord(recovery) }),
        },
        legacyVerification: legacyVerificationFromError(error),
      };
      try {
        writeJsonAtomically(rollbackFailureReceipt, {
          schemaVersion: "ti-scale.rollback-failure.v1",
          releaseId: receipt.releaseId,
          createdAt: new Date().toISOString(),
          originalDeploymentReceipt: args.receiptPath,
          currentReleaseRecovered: false,
          targetCommitted: true,
          requiredReconciliation: "complete_target",
          failureDetail: committedDetail,
        });
      } catch {
        // The immutable transaction journal remains the recovery authority.
      }
      // The rollback target is now the only valid recovery direction. Do not
      // restore the preserved deployment receipt or current-release images.
      throw new FunctionalReleaseError(rollbackFailureReceipt, "failed", committedDetail, error);
    }
    if (recovery === undefined) {
      try {
        await journalRollbackRecoveryMutation("deployment_receipt_restore", async () => {
          if (existsSync(preservedDeploymentReceipt)) {
            const preserved = readFileSync(preservedDeploymentReceipt);
            if (!readFileSync(args.receiptPath!).equals(preserved)) {
              writeDurableFileAtomically(args.receiptPath!, preserved, { mode: 0o600 });
            }
          } else if (await sha256File(args.receiptPath!) !== originalDeploymentReceiptSha256) {
            throw new Error("Rollback receipt changed without a committed preservation image");
          }
        });
      } catch (receiptRestoreError) {
        recovery = receiptRestoreError;
      }
    }
    const baseDetail: ReleaseFailureDetail = {
      phase: rollbackPhase,
      primary: safeErrorRecord(primary),
      recovery: {
        attempted: true,
        outcome: recovery === undefined ? "succeeded" : "failed",
        ...(recovery === undefined ? {} : { error: safeErrorRecord(recovery) }),
      },
      legacyVerification: legacyVerificationFromError(error),
    };
    let detail = baseDetail;
    try {
      writeJsonAtomically(rollbackFailureReceipt, {
        schemaVersion: "ti-scale.rollback-failure.v1",
        releaseId: receipt.releaseId,
        createdAt: new Date().toISOString(),
        originalDeploymentReceipt: args.receiptPath,
        currentReleaseRecovered: recovery === undefined,
        failureDetail: detail,
      });
    } catch (receiptError) {
      detail = { ...baseDetail, receiptWriteError: safeErrorRecord(receiptError) };
    }
    if (recovery === undefined) {
      const recoveredJournal = readFunctionalReleaseTransactionJournal(rollbackJournalDirectory);
      const recoveredAt = recoveredJournal.records.find((record) => record.event === "recovery_started")!.recordedAt;
      const recoveryReceiptPath = join(failedRoot, "transaction-recovery-receipt.json");
      const recoveryReceipt = functionalRecoveryReceiptValue({
        journal: recoveredJournal,
        recoveredAt,
        pointers: currentPointers,
        applicationTreeSha256: currentApplicationTreeSha256,
        databaseSchema: receipt.database.targetSchema,
        databaseFingerprint: receipt.database.deployedFingerprint!,
        vaultFingerprint: receipt.vault.deployedFingerprint!,
      });
      await journalRollbackRecoveryMutation("terminal_receipt_commit", async () => {
        await writeIdempotentFunctionalRecoveryReceipt(recoveryReceiptPath, recoveryReceipt);
      });
      rollbackTransactionJournal = appendFunctionalReleaseTransactionRecord(rollbackJournalDirectory, {
        event: "terminal",
        detail: {
          outcome: "preserved_current_restored",
          receiptPath: recoveryReceiptPath,
          receiptSha256: await sha256File(recoveryReceiptPath),
        },
      });
      clearTerminalReleaseStartupMutationBarrier(rollbackTransactionJournal);
    }
    throw new FunctionalReleaseError(rollbackFailureReceipt, "failed", detail, error);
  }
}

function journalObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Release transaction ${label} is missing or invalid`);
  }
  return value as Record<string, unknown>;
}

function journalString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) throw new Error(`Release transaction ${label} is missing or invalid`);
  return value;
}

function journalInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error(`Release transaction ${label} is missing or invalid`);
  }
  return value as number;
}

function journalPointer(value: unknown, label: string): ReleasePointerSnapshot {
  const pointer = journalObject(value, label);
  const application = journalObject(pointer.application, `${label}.application`);
  const kind = application.kind;
  if (kind !== "directory" && kind !== "symlink") {
    throw new Error(`Release transaction ${label}.application.kind is invalid`);
  }
  return {
    application: {
      kind,
      target: resolve(journalString(application.target, `${label}.application.target`)),
      device: journalString(application.device, `${label}.application.device`),
      inode: journalString(application.inode, `${label}.application.inode`),
    },
    staticReleaseId: journalString(pointer.staticReleaseId, `${label}.staticReleaseId`),
    staticManifestSha256: journalString(pointer.staticManifestSha256, `${label}.staticManifestSha256`),
  };
}

function journalHasForwardMutation(
  journal: FunctionalReleaseTransactionJournal,
  ...mutations: readonly string[]
): boolean {
  const names = new Set(mutations);
  return journal.records.some((record) =>
    record.direction === "forward" && record.event === "mutation_prepared" &&
    typeof record.mutation === "string" && names.has(record.mutation)
  );
}

function functionalRecoveryReceiptValue(options: {
  readonly journal: FunctionalReleaseTransactionJournal;
  readonly recoveredAt: string;
  readonly pointers: ReleasePointerSnapshot;
  readonly applicationTreeSha256: string;
  readonly databaseSchema: number;
  readonly databaseFingerprint: string;
  readonly vaultFingerprint: string;
}): Readonly<Record<string, unknown>> {
  return {
    schemaVersion: "ti-scale.functional-release-recovery-receipt.v1",
    transactionId: options.journal.binding.transactionId,
    operation: options.journal.binding.operation,
    releaseId: options.journal.binding.releaseId,
    outcome: options.journal.binding.operation === "deploy"
      ? "predeploy_restored"
      : "preserved_current_restored",
    recoveredAt: options.recoveredAt,
    originalReceiptPath: options.journal.binding.receiptPath,
    journalPath: options.journal.directory,
    journalBindingSha256: options.journal.bindingSha256,
    serviceIntent: "active",
    state: {
      pointers: options.pointers,
      applicationTreeSha256: options.applicationTreeSha256,
      databaseSchema: options.databaseSchema,
      databaseFingerprintPolicy: RELEASE_DATA_FINGERPRINT_POLICY,
      databaseFingerprint: options.databaseFingerprint,
      vaultFingerprintPolicy: "managed_tree_content_metadata_v1",
      vaultFingerprint: options.vaultFingerprint,
    },
  };
}

async function writeIdempotentFunctionalRecoveryReceipt(
  pathValue: string,
  value: Readonly<Record<string, unknown>>,
): Promise<string> {
  const path = resolve(pathValue);
  const bytes = `${canonicalReleaseTransactionJson(value)}\n`;
  if (existsSync(path)) {
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || readFileSync(path, "utf8") !== bytes) {
      throw new Error("Existing functional recovery receipt is ambiguous or tampered");
    }
  } else writeDurableFileAtomically(path, bytes, { mode: 0o600 });
  return sha256File(path);
}

function rollbackPreservationEvidence(
  journal: FunctionalReleaseTransactionJournal,
): Record<string, unknown> | undefined {
  const evidence = journal.records.filter((record) =>
    record.event === "evidence" && record.detail?.kind === "rollback_preservation"
  );
  if (evidence.length > 1) throw new Error("Rollback transaction has ambiguous preservation evidence");
  return evidence[0]?.detail as Record<string, unknown> | undefined;
}

function assertManagedTransactionBoundaries(
  journal: FunctionalReleaseTransactionJournal,
): void {
  const identity = journalObject(journal.binding.identity, "identity");
  const boundaries = journalObject(identity.boundaries, "identity.boundaries");
  const expected: Readonly<Record<string, string>> = {
    applicationPath: APPLICATION_PATH,
    databasePath: DATABASE_PATH,
    vaultRoot: VAULT_ROOT,
    staticReleaseRoot: STATIC_RELEASE_ROOT,
    backupRoot: BACKUP_ROOT,
    service: SERVICE,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (boundaries[key] !== value) {
      throw new Error(`Release transaction boundary ${key} is stale or targets an unmanaged path`);
    }
  }
  const receiptPath = assertRealRegularFileWithin(
    BACKUP_ROOT,
    journal.binding.receiptPath,
    "Release transaction receipt",
  );
  const rawReceipt = journalObject(JSON.parse(readFileSync(receiptPath, "utf8")), "receipt");
  if (
    rawReceipt.schemaVersion !== "ti-scale.functional-release-receipt.v1" ||
    rawReceipt.releaseId !== journal.binding.releaseId
  ) throw new Error("Release transaction is stale for its bound deployment receipt");
  if (journal.binding.operation === "deploy") {
    const receiptDatabase = journalObject(rawReceipt.database, "receipt.database");
    const target = journalObject(identity.target, "identity.target");
    if (receiptDatabase.migrationAttestation !== undefined || target.migrationAttestation !== undefined) {
      const receiptAttestation = assertValidReleaseMigrationAttestation(receiptDatabase.migrationAttestation);
      assertReleaseMigrationAttestationsMatch(
        receiptAttestation,
        target.migrationAttestation,
        "Transaction-bound release migration attestation",
      );
      if (
        receiptAttestation.targetSchema !== journalInteger(receiptDatabase.targetSchema, "receipt target schema") ||
        receiptAttestation.targetSchema !== journalInteger(target.databaseSchema, "transaction target schema")
      ) throw new Error("Transaction-bound migration attestation conflicts with its target schema");
    }
  }
}

function assertRecoveryMayOwnDatabase(journal: FunctionalReleaseTransactionJournal): void {
  assertNoCanonicalDatabaseUsers();
  const active = queryActiveV2Work(DATABASE_PATH);
  if (active.activeRuns.length || active.activeLeases.length || active.reconciliationRequired.length) {
    assertNoActiveWorkSnapshot(active);
  }
  const allowedOperations = new Set([
    `deploy:${journal.binding.releaseId}`,
    `rollback:${journal.binding.releaseId}`,
    `deploy-recovery:${journal.binding.releaseId}`,
    `rollback-recovery:${journal.binding.releaseId}`,
  ]);
  const unexpected = active.activeDatabaseWriters.filter((writer) =>
    writer.kind !== "canonical_database_writer" || !allowedOperations.has(writer.status)
  );
  if (unexpected.length) {
    assertNoActiveWorkSnapshot({ ...active, activeDatabaseWriters: unexpected });
  }
}

function recoveryApplicationPointerMatches(
  observed: ApplicationPointerSnapshot,
  expected: ApplicationPointerSnapshot,
): boolean {
  if (applicationPointerMatches(observed, expected)) return true;
  // If the checksum-bound source archive had to reconstruct a lost original
  // directory, the inode necessarily changes. Directory kind, canonical live
  // path, and the independently verified complete tree checksum become the
  // exact recoverable identity; symlink targets remain path-exact.
  return expected.kind === "directory" && observed.kind === "directory" &&
    observed.target === resolve(APPLICATION_PATH);
}

function recoveryPointersMatch(
  observed: ReleasePointerSnapshot,
  expected: ReleasePointerSnapshot,
): boolean {
  return recoveryApplicationPointerMatches(observed.application, expected.application) &&
    observed.staticReleaseId === expected.staticReleaseId &&
    observed.staticManifestSha256 === expected.staticManifestSha256;
}

async function exactRecoveryState(options: {
  readonly staticStore: StaticArtifactReleaseStore;
  readonly pointers: ReleasePointerSnapshot;
  readonly applicationTreeSha256: string;
  readonly databaseSchema: number;
  readonly databaseFingerprint: string;
  readonly vaultFingerprint: string;
}): Promise<boolean> {
  try {
    if (!recoveryPointersMatch(captureReleasePointerSnapshot(options.staticStore), options.pointers)) return false;
    if (await canonicalApplicationTreeFingerprint(captureApplicationPointerSnapshot().target) !==
      options.applicationTreeSha256) return false;
    if (currentSchema(DATABASE_PATH) !== options.databaseSchema) return false;
    if (canonicalReleaseDataFingerprint(DATABASE_PATH) !== options.databaseFingerprint) return false;
    if (await canonicalVaultFingerprint(VAULT_ROOT) !== options.vaultFingerprint) return false;
    await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
    return true;
  } catch { return false; }
}

export function committedTargetRuntimeIdentity(
  state: Readonly<Record<string, unknown>>,
  label: string,
): { readonly databaseOwnerUid: number; readonly databaseOwnerGid: number; readonly databaseMode: number } {
  if (state.serviceIntent !== "active") {
    throw new Error(`${label} service intent is unsupported`);
  }
  const databaseOwnerUid = journalInteger(state.databaseOwnerUid, `${label} database owner UID`);
  const databaseOwnerGid = journalInteger(state.databaseOwnerGid, `${label} database owner GID`);
  const databaseMode = journalInteger(state.databaseMode, `${label} database mode`);
  if (databaseOwnerUid < 0 || databaseOwnerGid < 0) {
    throw new Error(`${label} database ownership is invalid`);
  }
  if (databaseMode < 0 || databaseMode > 0o777) {
    throw new Error(`${label} database mode is invalid`);
  }
  return Object.freeze({ databaseOwnerUid, databaseOwnerGid, databaseMode });
}

async function verifyTerminalReceiptIdentity(
  receiptPathValue: unknown,
  receiptSha256Value: unknown,
): Promise<void> {
  const receiptPath = assertRealRegularFileWithin(
    BACKUP_ROOT,
    journalString(receiptPathValue, "terminal receipt path"),
    "Terminal release transaction receipt",
  );
  const expectedSha256 = journalString(receiptSha256Value, "terminal receipt checksum");
  if (await sha256File(receiptPath) !== expectedSha256) {
    throw new Error("Terminal release transaction receipt checksum changed (tampered terminal refused)");
  }
}

async function verifyTerminalReceiptRecord(record: FunctionalReleaseTransactionRecord): Promise<void> {
  const detail = journalObject(record.detail, "terminal detail");
  await verifyTerminalReceiptIdentity(detail.receiptPath, detail.receiptSha256);
}

async function reconcileCommittedFunctionalReleaseJournal(
  initialJournal: FunctionalReleaseTransactionJournal,
  dryRun: boolean,
): Promise<void> {
  let journal = initialJournal;
  const commitment = functionalReleaseTargetCommitRecord(journal);
  if (!commitment) throw new Error("Forward reconciliation requires a durable target commitment");
  const identity = journalObject(journal.binding.identity, "identity");
  const source = journalObject(
    journal.binding.operation === "deploy" ? identity.predeploy : identity.preservedCurrent,
    "committed recovery source identity",
  );
  const target = journalObject(
    journal.binding.operation === "deploy" ? identity.target : identity.rollbackTarget,
    "committed forward target identity",
  );
  const committedState = journalObject(commitment.detail?.targetState, "committed target state");
  const targetPointers = journalPointer(target.pointers, "forward target pointers");
  const committedPointers = journalPointer(committedState.pointers, "committed target pointers");
  const pointersBound = releasePointersMatch(committedPointers, targetPointers);
  if (!pointersBound) throw new Error("Committed target pointers conflict with the immutable transaction binding");
  const targetTreeSha256 = journalString(target.applicationTreeSha256, "forward target application checksum");
  const committedTreeSha256 = journalString(
    committedState.applicationTreeSha256,
    "committed target application checksum",
  );
  const targetSchema = journalInteger(target.databaseSchema, "forward target database schema");
  const committedSchema = journalInteger(committedState.databaseSchema, "committed target database schema");
  if (targetTreeSha256 !== committedTreeSha256 || targetSchema !== committedSchema) {
    throw new Error("Committed target application/database identity conflicts with the transaction binding");
  }
  const targetMigrationAttestation = journal.binding.operation === "deploy" && (
    target.migrationAttestation !== undefined || committedState.migrationAttestation !== undefined
  )
    ? assertValidReleaseMigrationAttestation(target.migrationAttestation)
    : undefined;
  if (targetMigrationAttestation) {
    assertReleaseMigrationAttestationsMatch(
      targetMigrationAttestation,
      committedState.migrationAttestation,
      "Committed target migration attestation",
    );
    if (targetMigrationAttestation.targetSchema !== committedSchema) {
      throw new Error("Committed target migration attestation conflicts with its database schema");
    }
  }
  assertExactReleaseDataFingerprintPolicy(committedState.databaseFingerprintPolicy);
  if (committedState.vaultFingerprintPolicy !== "managed_tree_content_metadata_v1") {
    throw new Error("Committed target Vault fingerprint policy is invalid");
  }
  const committedRuntimeIdentity = committedTargetRuntimeIdentity(committedState, "Committed target");
  const committedDatabaseFingerprint = journalString(
    committedState.databaseFingerprint,
    "committed target database fingerprint",
  );
  const committedVaultFingerprint = journalString(
    committedState.vaultFingerprint,
    "committed target Vault fingerprint",
  );
  if (journal.binding.operation === "rollback") {
    if (
      committedDatabaseFingerprint !== journalString(
        target.databaseFingerprint,
        "rollback target database fingerprint",
      ) ||
      committedVaultFingerprint !== journalString(
        target.vaultFingerprint,
        "rollback target Vault fingerprint",
      )
    ) throw new Error("Committed rollback database/Vault baseline conflicts with the transaction target");
  }
  const databaseOwnerUid = committedRuntimeIdentity.databaseOwnerUid;
  const databaseOwnerGid = committedRuntimeIdentity.databaseOwnerGid;
  const databaseMode = committedRuntimeIdentity.databaseMode;
  const previousInvocationId = journalString(source.previousInvocationId, "source service invocation");
  const staticStore = new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT });
  const serviceMayHaveAcknowledgedWrites = (): boolean => journal.records.some((record) =>
    record.event === "mutation_prepared" && record.mutation === "service_start" &&
    (record.direction === "forward" || record.direction === "recovery")
  );

  const verifyTargetState = async (allowRuntimeWrites: boolean): Promise<void> => {
    const observedPointers = captureReleasePointerSnapshot(staticStore);
    const pointersExact = releasePointersMatch(observedPointers, committedPointers);
    if (!pointersExact) {
      throw new Error("Committed target pointer drifted; source restoration and blind repair are refused");
    }
    if (await canonicalApplicationTreeFingerprint(observedPointers.application.target) !== committedTreeSha256) {
      throw new Error("Committed target application content changed; reconciliation is refused");
    }
    if (targetMigrationAttestation) {
      assertReleaseMigrationAttestationsMatch(
        targetMigrationAttestation,
        attestReleaseMigrationCeiling(observedPointers.application.target),
        "Committed active release migration attestation",
      );
    }
    if (currentSchema(DATABASE_PATH) !== committedSchema) {
      throw new Error("Committed target database schema changed; reconciliation is refused");
    }
    const metadata = lstatSync(DATABASE_PATH);
    if (
      !metadata.isFile() || metadata.isSymbolicLink() ||
      metadata.uid !== databaseOwnerUid || metadata.gid !== databaseOwnerGid ||
      (metadata.mode & 0o777) !== databaseMode
    ) throw new Error("Committed target database file identity or ownership changed");
    if (!allowRuntimeWrites) {
      if (canonicalReleaseDataFingerprint(DATABASE_PATH) !== committedDatabaseFingerprint) {
        throw new Error("Committed target database changed before any journaled service start");
      }
      if (await canonicalVaultFingerprint(VAULT_ROOT) !== committedVaultFingerprint) {
        throw new Error("Committed target Vault changed before any journaled service start");
      }
    }
    await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
  };

  const waitForTarget = async (): Promise<TiScaleStartupObservation> => {
    const observation = await waitForTiScaleExpectedRelease(staticStore, {
      previousInvocationId,
      databaseSchema: committedSchema,
      pointers: committedPointers,
    });
    await verifyTargetState(true);
    return observation;
  };

  const verifyTargetRunning = async (): Promise<void> => {
    await verifyTargetState(true);
    const observation = await observeTiScaleStartup(staticStore);
    assertTiScaleObservationHealthy(observation, committedSchema, "Committed Ti-Scale on port 3132");
    const pointersExact = releasePointersMatch(observation.pointers, committedPointers);
    if (!pointersExact) throw new Error("Committed Ti-Scale runtime does not own its target pointers");
  };

  await verifyTargetState(serviceMayHaveAcknowledgedWrites() || journal.terminal !== undefined);
  if (dryRun) {
    process.stdout.write(`${JSON.stringify({
      status: journal.terminal ? "terminal_verified" : "forward_reconciliation_required",
      operation: journal.binding.operation,
      releaseId: journal.binding.releaseId,
      journal: journal.directory,
      recoveryIntent: "complete_target",
      targetCommittedAt: commitment.recordedAt,
      lastEvent: journal.latest.event,
      lastMutation: journal.latest.mutation ?? null,
    }, null, 2)}\n`);
    return;
  }

  const originalReceiptPath = resolve(journal.binding.receiptPath);
  const transactionReceipt = JSON.parse(readFileSync(originalReceiptPath, "utf8")) as DeploymentReceipt;
  if (
    transactionReceipt.schemaVersion !== "ti-scale.functional-release-receipt.v1" ||
    transactionReceipt.releaseId !== journal.binding.releaseId
  ) throw new Error("Committed target receipt conflicts with its transaction identity");
  const targetOutcome = journal.binding.operation === "deploy" ? "deployed" : "rolled_back";
  const forwardReceiptPath = join(dirname(journal.directory), "transaction-forward-reconciliation-receipt.json");

  const result = await reconcileFunctionalReleaseTransaction(journal.directory, {
    reconciliationIntent: "complete_target",
    assertBindingAndObservedState: async (freshJournal) => {
      journal = freshJournal;
      assertManagedTransactionBoundaries(journal);
      if (!functionalReleaseTargetCommitRecord(journal)) {
        throw new Error("Committed target marker disappeared during reconciliation");
      }
      await verifyTargetState(
        serviceMayHaveAcknowledgedWrites(),
      );
    },
    steps: [
      {
        mutation: "target_state_verification",
        apply: async () => {
          await verifyTargetState(serviceMayHaveAcknowledgedWrites());
          return "already_exact" as const;
        },
      },
      {
        mutation: "service_start",
        apply: async () => {
          const snapshot = tiScaleStopSnapshot();
          if (snapshot.activeState === "active" && snapshot.mainPid > 0) {
            await waitForTarget();
            return "already_exact";
          }
          if (!serviceCanRestartUnchanged(snapshot)) {
            throw new Error("Committed target cannot prove process absence before restart");
          }
          assertNoCanonicalDatabaseUsers();
          startTiScale(journal.directory);
          await waitForTarget();
          return "mutated";
        },
      },
      {
        mutation: "running_state_verification",
        apply: async () => {
          await verifyTargetRunning();
          return "already_exact" as const;
        },
      },
      {
        mutation: "deployment_receipt_commit",
        apply: async () => {
          const current = JSON.parse(readFileSync(originalReceiptPath, "utf8")) as DeploymentReceipt;
          if (current.status === targetOutcome) {
            const timestamp = targetOutcome === "deployed" ? current.deployedAt : current.rolledBackAt;
            if (timestamp !== commitment.recordedAt) {
              throw new Error("Committed target receipt has an ambiguous completion timestamp");
            }
            return "already_exact";
          }
          const observation = await waitForTarget();
          const coupledState = await captureCoupledDatabaseVaultState();
          if (journal.binding.operation === "deploy") {
            current.status = "deployed";
            current.deployedAt = commitment.recordedAt;
            current.tiScaleAfter = observation;
            current.chillspwnAfter = await assertChillspwnUnchanged(current.chillspwnBefore);
            current.database.deployedFingerprint = coupledState.databaseFingerprint;
            current.vault.deployedFingerprint = coupledState.vaultFingerprint;
            delete current.failure;
            delete current.failureDetail;
            delete current.rolledBackAt;
          } else {
            current.status = "rolled_back";
            current.rolledBackAt = commitment.recordedAt;
          }
          writeJsonAtomically(originalReceiptPath, current);
          return "mutated";
        },
      },
    ],
    terminalReceipt: async () => ({
      path: forwardReceiptPath,
      value: {
        schemaVersion: "ti-scale.functional-release-forward-reconciliation-receipt.v1",
        transactionId: journal.binding.transactionId,
        operation: journal.binding.operation,
        releaseId: journal.binding.releaseId,
        outcome: targetOutcome,
        targetCommittedAt: commitment.recordedAt,
        targetStateSha256: commitment.detail?.targetStateSha256,
        deploymentReceiptPath: originalReceiptPath,
        deploymentReceiptSha256: await sha256File(originalReceiptPath),
        journalPath: journal.directory,
        journalBindingSha256: journal.bindingSha256,
        serviceIntent: "active",
      },
      outcome: targetOutcome,
    }),
    verifyTerminal: async (terminal) => {
      await verifyTerminalReceiptRecord(terminal);
      const completed = readReceipt(originalReceiptPath);
      if (completed.status !== targetOutcome) {
        throw new Error("Committed target terminal outcome conflicts with its deployment receipt");
      }
      await verifyTargetRunning();
      await verifyReceiptBindings(completed, {
        ...(journal.binding.operation === "rollback"
          ? { restoredDirectoryApplicationPath: APPLICATION_PATH }
          : {}),
      });
    },
  });
  clearTerminalReleaseStartupMutationBarrier(
    readFunctionalReleaseTransactionJournal(journal.directory),
  );

  process.stdout.write(`${JSON.stringify({
    status: result,
    direction: "forward",
    operation: journal.binding.operation,
    releaseId: journal.binding.releaseId,
    journal: journal.directory,
    targetCommittedAt: commitment.recordedAt,
    forwardReconciliationReceipt: forwardReceiptPath,
  }, null, 2)}\n`);
}

/**
 * Explicit crash/host-loss reconciliation. This path is called only under the
 * same process-wide flock as deploy/rollback. Before the durable target
 * commitment it restores the source identity. After that commitment it only
 * completes forward and preserves any writes the target may have acknowledged.
 */
export async function reconcileFunctionalReleaseJournal(
  journalPath: string,
  confirmation: string | undefined,
  dryRun = false,
): Promise<void> {
  void journalPath;
  void confirmation;
  void dryRun;
  throw new Error(
    "Backup-capable functional release reconciliation is disabled by operator no-backup policy",
  );
  /* c8 ignore start -- unreachable retired backup-capable reconciliation */
  let journal = readFunctionalReleaseTransactionJournal(journalPath, { allowedRoot: BACKUP_ROOT });
  assertManagedTransactionBoundaries(journal);
  if (!dryRun && process.getuid?.() !== 0) throw new Error("Functional release reconciliation requires root");
  if (!dryRun && confirmation !== journal.binding.releaseId) {
    throw new Error("--confirm must exactly match the journal release ID");
  }
  if (functionalReleaseTargetCommitRecord(journal)) {
    await reconcileCommittedFunctionalReleaseJournal(journal, dryRun);
    return;
  }
  const identity = journalObject(journal.binding.identity, "identity");
  const source = journalObject(
    journal.binding.operation === "deploy" ? identity.predeploy : identity.preservedCurrent,
    "recovery source identity",
  );
  const sourcePointers = journalPointer(source.pointers, "recovery source pointers");
  const applicationTreeSha256 = journalString(source.applicationTreeSha256, "source application tree checksum");
  const databaseSchema = journalInteger(source.databaseSchema, "source database schema");
  assertExactReleaseDataFingerprintPolicy(source.databaseFingerprintPolicy);
  const databaseFingerprint = journalString(source.databaseFingerprint, "source database fingerprint");
  if (source.vaultFingerprintPolicy !== "managed_tree_content_metadata_v1") {
    throw new Error("Release transaction Vault fingerprint policy is invalid");
  }
  const vaultFingerprint = journalString(source.vaultFingerprint, "source Vault fingerprint");
  if (source.serviceIntent !== "active") throw new Error("Release transaction service intent is unsupported");
  const previousInvocationId = journalString(source.previousInvocationId, "source service invocation");
  const recovery = journalObject(identity.recovery, "recovery artifacts");
  const staticStore = new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT });
  const preservation = journal.binding.operation === "rollback"
    ? rollbackPreservationEvidence(journal)
    : undefined;

  if (journal.binding.operation === "deploy") {
    const backupRoot = resolve(journalString(recovery.backupRoot, "deploy recovery root"));
    const backupRootMetadata = lstatSync(backupRoot);
    if (
      !backupRootMetadata.isDirectory() || backupRootMetadata.isSymbolicLink() ||
      realpathSync(backupRoot) !== backupRoot ||
      journal.directory !== join(backupRoot, "transaction-journal") ||
      resolve(journal.binding.receiptPath) !== join(backupRoot, "deployment-receipt.json")
    ) {
      throw new Error("Deploy transaction journal is stale for its recovery bundle");
    }
    const manifestPath = assertRealRegularFileWithin(
      backupRoot,
      journalString(recovery.checksumManifestPath, "deploy checksum manifest"),
      "Deploy checksum manifest",
    );
    if (manifestPath !== join(backupRoot, BACKUP_CHECKSUM_MANIFEST)) {
      throw new Error("Deploy transaction checksum manifest path is ambiguous");
    }
    const entries = await verifyChecksumManifest(backupRoot);
    if (await sha256File(manifestPath) !== journalString(
      recovery.checksumManifestSha256,
      "deploy checksum manifest checksum",
    )) throw new Error("Deploy transaction checksum manifest was changed or replaced");
    const backupPath = assertRealRegularFileWithin(
      backupRoot,
      journalString(recovery.databasePath, "deploy recovery database"),
      "Deploy recovery database",
    );
    const vaultArchivePath = assertRealRegularFileWithin(
      backupRoot,
      journalString(recovery.vaultArchivePath, "deploy Vault archive"),
      "Deploy Vault archive",
    );
    const sourceArchivePath = assertRealRegularFileWithin(
      backupRoot,
      journalString(recovery.sourceArchivePath, "deploy application source archive"),
      "Deploy application source archive",
    );
    if (
      backupPath !== join(backupRoot, "database", "pre-release.sqlite") ||
      vaultArchivePath !== join(backupRoot, "vault.tar.gz") ||
      sourceArchivePath !== join(backupRoot, "server-source.tar.gz")
    ) throw new Error("Deploy recovery payload path does not match its fixed bundle layout");
    const databaseSha256 = journalString(recovery.databaseSha256, "deploy database checksum");
    const vaultArchiveSha256 = journalString(recovery.vaultArchiveSha256, "deploy Vault archive checksum");
    if (
      entries[relativeInside(backupRoot, backupPath)] !== databaseSha256 ||
      entries[relativeInside(backupRoot, vaultArchivePath)] !== vaultArchiveSha256 ||
      !entries[relativeInside(backupRoot, sourceArchivePath)] ||
      await sha256File(backupPath) !== databaseSha256 ||
      await sha256File(vaultArchivePath) !== vaultArchiveSha256
    ) throw new Error("Deploy recovery payloads are not exactly bound by the verified checksum manifest");
    const expectedPreviousArchive = join(
      SERVER_RELEASE_ROOT,
      "releases",
      `previous-${journal.binding.releaseId}`,
    );
    const expectedSwapPath = join(
      dirname(APPLICATION_PATH),
      `.${basename(APPLICATION_PATH)}.${journal.binding.releaseId}.swap`,
    );
    if (
      resolve(journalString(recovery.previousDirectoryArchive, "deploy previous archive")) !==
        expectedPreviousArchive ||
      resolve(journalString(recovery.inProgressSwapPath, "deploy swap path")) !== expectedSwapPath
    ) throw new Error("Deploy pointer recovery paths conflict with the fixed release layout");
    if (canonicalReleaseDataFingerprint(backupPath) !== databaseFingerprint) {
      throw new Error("Deploy recovery database does not reproduce the journal-bound source identity");
    }
  } else if (preservation) {
    const preservationRoot = resolve(journalString(recovery.preservationRoot, "rollback preservation root"));
    const preservationRootMetadata = lstatSync(preservationRoot);
    if (
      !preservationRootMetadata.isDirectory() || preservationRootMetadata.isSymbolicLink() ||
      realpathSync(preservationRoot) !== preservationRoot ||
      journal.directory !== join(preservationRoot, "transaction-journal") ||
      !relativeInside(BACKUP_ROOT, preservationRoot)
    ) {
      throw new Error("Rollback transaction journal is stale for its preservation root");
    }
    const checksumPath = assertRealRegularFileWithin(
      preservationRoot,
      journalString(preservation!.checksumManifestPath, "rollback checksum manifest"),
      "Rollback checksum manifest",
    );
    if (checksumPath !== join(preservationRoot, BACKUP_CHECKSUM_MANIFEST)) {
      throw new Error("Rollback preservation checksum manifest path is ambiguous");
    }
    const entries = await verifyChecksumManifest(preservationRoot);
    if (await sha256File(checksumPath) !== journalString(
      preservation!.checksumManifestSha256,
      "rollback checksum manifest checksum",
    )) throw new Error("Rollback preservation checksum manifest was changed or replaced");
    const preservedDatabase = assertRealRegularFileWithin(
      preservationRoot,
      journalString(recovery.databasePath, "preserved database"),
      "Rollback preserved database",
    );
    const preservedVaultArchive = assertRealRegularFileWithin(
      preservationRoot,
      journalString(recovery.vaultArchivePath, "rollback Vault archive"),
      "Rollback preserved Vault archive",
    );
    const preservedApplicationArchive = assertRealRegularFileWithin(
      preservationRoot,
      journalString(recovery.applicationArchivePath, "rollback application source archive"),
      "Rollback preserved application archive",
    );
    const preservedReceipt = assertRealRegularFileWithin(
      preservationRoot,
      journalString(recovery.deploymentReceiptPath, "preserved deployment receipt"),
      "Rollback preserved deployment receipt",
    );
    if (
      preservedDatabase !== join(preservationRoot, "current.sqlite") ||
      preservedVaultArchive !== join(preservationRoot, "vault.tar.gz") ||
      preservedApplicationArchive !== join(preservationRoot, "server-source.tar.gz") ||
      preservedReceipt !== join(preservationRoot, "deployment-receipt.pre-rollback.json")
    ) throw new Error("Rollback preservation payload path does not match its fixed bundle layout");
    const preservedDatabaseSha256 = journalString(
      preservation!.databaseSha256,
      "rollback database checksum",
    );
    const preservedVaultSha256 = journalString(
      preservation!.vaultArchiveSha256,
      "rollback Vault archive checksum",
    );
    const preservedReceiptSha256 = journalString(
      preservation!.deploymentReceiptSha256,
      "rollback deployment receipt checksum",
    );
    if (
      entries[relativeInside(preservationRoot, preservedDatabase)] !== preservedDatabaseSha256 ||
      entries[relativeInside(preservationRoot, preservedVaultArchive)] !== preservedVaultSha256 ||
      entries[relativeInside(preservationRoot, preservedReceipt)] !== preservedReceiptSha256 ||
      !entries[relativeInside(preservationRoot, preservedApplicationArchive)] ||
      await sha256File(preservedDatabase) !== preservedDatabaseSha256 ||
      await sha256File(preservedVaultArchive) !== preservedVaultSha256 ||
      await sha256File(preservedReceipt) !== preservedReceiptSha256
    ) throw new Error("Rollback preservation payloads are not exactly bound by the verified checksum manifest");
    relativeInside(
      SERVER_RELEASE_ROOT,
      journalString(recovery.rollbackTargetApplicationPath, "rollback target application path"),
    );
    if (canonicalReleaseDataFingerprint(preservedDatabase) !== databaseFingerprint) {
      throw new Error("Rollback preservation database does not reproduce the journal-bound current identity");
    }
  } else if (journalHasForwardMutation(
    journal,
    "application_activation", "static_activation", "vault_restore", "database_restore", "service_start",
  )) {
    throw new Error("Rollback mutation was prepared without durable preservation evidence");
  }

  const target = journal.binding.operation === "deploy"
    ? journalObject(identity.target, "deploy target identity")
    : journalObject(identity.rollbackTarget, "rollback target identity");
  const targetPointers = journalPointer(target.pointers, "forward target pointers");
  const observedPointers = captureReleasePointerSnapshot(staticStore);
  const observedApplicationIsSource = recoveryApplicationPointerMatches(
    observedPointers.application,
    sourcePointers.application,
  );
  const observedApplicationIsTarget = applicationPointerMatches(
    observedPointers.application,
    targetPointers.application,
  );
  const observedStaticIsSource = observedPointers.staticReleaseId === sourcePointers.staticReleaseId &&
    observedPointers.staticManifestSha256 === sourcePointers.staticManifestSha256;
  const observedStaticIsTarget = observedPointers.staticReleaseId === targetPointers.staticReleaseId &&
    observedPointers.staticManifestSha256 === targetPointers.staticManifestSha256;
  if (!observedApplicationIsSource && !observedApplicationIsTarget) {
    throw new Error("Live application pointer matches neither journal-bound identity; stale journal refused");
  }
  if (!observedStaticIsSource && !observedStaticIsTarget) {
    throw new Error("Live static pointer matches neither journal-bound identity; stale journal refused");
  }
  if (observedApplicationIsSource &&
    await canonicalApplicationTreeFingerprint(observedPointers.application.target) !== applicationTreeSha256) {
    throw new Error("Journal-bound source application pointer has tampered content");
  }
  if (observedApplicationIsTarget &&
    await canonicalApplicationTreeFingerprint(observedPointers.application.target) !==
      journalString(target.applicationTreeSha256, "forward target application tree checksum")) {
    throw new Error("Journal-bound forward application target has tampered content");
  }

  if (dryRun) {
    process.stdout.write(`${JSON.stringify({
      status: journal.terminal ? "terminal_verified" : "recovery_required",
      operation: journal.binding.operation,
      releaseId: journal.binding.releaseId,
      journal: journal.directory,
      recoveryIntent: journal.binding.recoveryIntent,
      lastEvent: journal.latest.event,
      lastMutation: journal.latest.mutation ?? null,
    }, null, 2)}\n`);
    return;
  }

  if (!journal.terminal && !journal.records.some((record) => record.event === "recovery_started")) {
    journal = appendFunctionalReleaseTransactionRecord(journal.directory, {
      event: "recovery_started",
      detail: { recoveryIntent: journal.binding.recoveryIntent },
    });
  }

  const sourceState = {
    staticStore,
    pointers: sourcePointers,
    applicationTreeSha256,
    databaseSchema,
    databaseFingerprint,
    vaultFingerprint,
  };
  const sourceIsExact = (): Promise<boolean> => exactRecoveryState(sourceState);
  const sourceImmutableStateIsExact = async (): Promise<boolean> => {
    const observed = captureReleasePointerSnapshot(staticStore);
    return recoveryPointersMatch(observed, sourcePointers) &&
      await canonicalApplicationTreeFingerprint(observed.application.target) === applicationTreeSha256 &&
      currentSchema(DATABASE_PATH) === databaseSchema;
  };
  const requireStopped = (): void => {
    const snapshot = tiScaleStopSnapshot();
    if (!serviceCanRestartUnchanged(snapshot)) {
      throw new Error("Release recovery mutation requires proven Ti-Scale process absence");
    }
    assertRecoveryMayOwnDatabase(journal);
  };
  const recoveryReceiptPath = join(dirname(journal.directory), "transaction-recovery-receipt.json");
  const recoveredAt = journal.records.find((record) => record.event === "recovery_started")?.recordedAt ??
    new Date().toISOString();

  const verifySourceGuarded = async (): Promise<void> => {
    if (!await sourceIsExact()) {
      throw new Error("Recovered release state is not the exact journal-bound source identity");
    }
    const observation = await observeTiScaleStartup(staticStore);
    assertTiScaleObservationJournalGuarded(observation, "Recovered Ti-Scale on port 3132");
    if (!recoveryPointersMatch(observation.pointers, sourcePointers)) {
      throw new Error("Recovered Ti-Scale runtime does not own the journal-bound source pointers");
    }
  };

  const verifySourceRunning = async (): Promise<void> => {
    const fresh = readFunctionalReleaseTransactionJournal(journal.directory);
    if (!releaseSourceRuntimeCommitted(fresh)) {
      throw new Error("Recovered application may not run before its durable source-runtime commitment");
    }
    if (!await sourceImmutableStateIsExact()) {
      throw new Error("Recovered runtime no longer owns the journal-bound application/static/schema identity");
    }
    await assertVaultDatabaseSyncConsistency(DATABASE_PATH, VAULT_ROOT);
    const observation = await observeTiScaleStartup(staticStore);
    assertTiScaleObservationHealthy(observation, databaseSchema, "Recovered Ti-Scale on port 3132");
    if (!recoveryPointersMatch(observation.pointers, sourcePointers)) {
      throw new Error("Recovered Ti-Scale runtime does not own the journal-bound source pointers");
    }
  };

  const terminalReceiptValue = (): Readonly<Record<string, unknown>> =>
    functionalRecoveryReceiptValue({
      journal,
      recoveredAt,
      pointers: sourcePointers,
      applicationTreeSha256,
      databaseSchema,
      databaseFingerprint,
      vaultFingerprint,
    });

  const verifyTerminal = async (terminal: FunctionalReleaseTransactionRecord): Promise<void> => {
    await verifyTerminalReceiptRecord(terminal);
    const terminalDetail = journalObject(terminal.detail, "terminal detail");
    const outcome = terminalDetail.outcome;
    if (outcome === "deployed" || outcome === "rolled_back") {
      const completedReceipt = readReceipt(journal.binding.receiptPath);
      if (completedReceipt.status !== (outcome === "deployed" ? "deployed" : "rolled_back")) {
        throw new Error("Terminal journal outcome conflicts with its deployment receipt status");
      }
      if (completedReceipt.database.fingerprintPolicy !== RELEASE_DATA_FINGERPRINT_POLICY) {
        throw new Error(`Terminal deployment receipt does not use the exact ${RELEASE_DATA_FINGERPRINT_POLICY} policy`);
      }
      if (outcome === "deployed") await verifyReceiptBindings(completedReceipt);
      const completedPointers = journalPointer(target.pointers, "terminal target pointers");
      const completedSchema = journalInteger(target.databaseSchema, "terminal target database schema");
      const completedTree = journalString(target.applicationTreeSha256, "terminal target application tree checksum");
      const completedDatabaseFingerprint = outcome === "deployed"
        ? journalString(terminalDetail.databaseFingerprint, "terminal database fingerprint")
        : journalString(target.databaseFingerprint, "rollback target database fingerprint");
      const completedVaultFingerprint = outcome === "deployed"
        ? journalString(terminalDetail.vaultFingerprint, "terminal Vault fingerprint")
        : journalString(target.vaultFingerprint, "rollback target Vault fingerprint");
      if (!await exactRecoveryState({
        staticStore,
        pointers: completedPointers,
        applicationTreeSha256: completedTree,
        databaseSchema: completedSchema,
        databaseFingerprint: completedDatabaseFingerprint,
        vaultFingerprint: completedVaultFingerprint,
      })) throw new Error("Completed release journal no longer matches its exact terminal state");
      const observation = await observeTiScaleStartup(staticStore);
      assertTiScaleObservationHealthy(observation, completedSchema, "Terminal Ti-Scale on port 3132");
      if (!releasePointersMatch(observation.pointers, completedPointers)) {
        throw new Error("Terminal Ti-Scale runtime does not own the recorded pointers");
      }
      return;
    }
    await verifySourceRunning();
  };

  const result = await reconcileFunctionalReleaseTransaction(journal.directory, {
    assertBindingAndObservedState: async (freshJournal) => {
      journal = freshJournal;
      assertManagedTransactionBoundaries(journal);
      if (journal.terminal) return;
      // Unknown data/Vault states are permitted only after the corresponding
      // forward mutation was durably prepared. Pointer ambiguity was rejected
      // before entering the recovery engine.
      const sourceCommitted = releaseSourceRuntimeCommitted(journal);
      if (!sourceCommitted &&
        !journalHasForwardMutation(journal, "database_migration", "database_restore", "service_start") &&
        canonicalReleaseDataFingerprint(DATABASE_PATH) !== databaseFingerprint) {
        throw new Error("Database drift is unrelated to any journaled mutation; stale journal refused");
      }
      if (!sourceCommitted && !journalHasForwardMutation(journal, "vault_restore", "service_start") &&
        await canonicalVaultFingerprint(VAULT_ROOT) !== vaultFingerprint) {
        throw new Error("Vault drift is unrelated to any journaled mutation; stale journal refused");
      }
    },
    steps: [
      {
        mutation: "service_stop_for_recovery",
        apply: async () => {
          const snapshot = tiScaleStopSnapshot();
          if (releaseSourceRuntimeCommitted(readFunctionalReleaseTransactionJournal(journal.directory))) {
            return "already_exact";
          }
          if (serviceCanRestartUnchanged(snapshot)) return "already_exact";
          stopTiScale();
          assertTiScaleStopped();
          assertNoCanonicalDatabaseUsers();
          return "mutated";
        },
      },
      {
        mutation: "application_restore",
        apply: async () => {
          const initiallyExact = recoveryApplicationPointerMatches(
            captureApplicationPointerSnapshot(),
            sourcePointers.application,
          );
          if (initiallyExact) {
            if (await canonicalApplicationTreeFingerprint(captureApplicationPointerSnapshot().target) !== applicationTreeSha256) {
              throw new Error("Source application pointer content is tampered");
            }
          } else {
            requireStopped();
            const candidates = journal.binding.operation === "deploy"
              ? [
                  resolve(journalString(recovery.inProgressSwapPath, "deploy swap path")),
                  resolve(journalString(recovery.previousDirectoryArchive, "deploy previous archive")),
                ]
              : [
                  resolve(journalString(
                    recovery.rollbackTargetApplicationPath,
                    "rollback target application path",
                  )),
                  join(
                    dirname(APPLICATION_PATH),
                    `.${basename(APPLICATION_PATH)}.${journal.binding.releaseId}.rollback-swap`,
                  ),
                ];
            try {
              restoreExactApplicationPointer(
                sourcePointers.application,
                candidates,
                `${journal.binding.releaseId}-journal`,
                journal.binding.operation === "rollback",
              );
            } catch (pointerRecoveryError) {
              const archivePath = journal.binding.operation === "deploy"
                ? resolve(journalString(recovery.sourceArchivePath, "deploy application source archive"))
                : preservation
                  ? resolve(journalString(recovery.applicationArchivePath, "rollback application source archive"))
                  : undefined;
              if (!archivePath) throw pointerRecoveryError;
              await restoreApplicationFromSourceArchive({
                archivePath,
                expected: sourcePointers.application,
                expectedTreeSha256: applicationTreeSha256,
                swapId: `${journal.binding.releaseId}-journal`,
                ...(journal.binding.operation === "rollback" ? {
                  displacedDirectoryArchive: resolve(journalString(
                    recovery.rollbackTargetApplicationPath,
                    "rollback target application path",
                  )),
                } : {}),
              });
            }
          }
          let strandedOutcome:
            | "absent"
            | "removed_target_symlink"
            | "removed_symlink"
            | "archived_directory" = "absent";
          if (journal.binding.operation === "deploy") {
            strandedOutcome = await reconcileStrandedDeployApplicationSwap({
              applicationPath: APPLICATION_PATH,
              expectedSource: sourcePointers.application,
              expectedSourceTreeSha256: applicationTreeSha256,
              expectedTarget: targetPointers.application,
              swapName: journal.binding.releaseId,
              serverReleaseRoot: SERVER_RELEASE_ROOT,
            });
          } else {
            strandedOutcome = reconcileStrandedRollbackApplicationSwap({
              applicationPath: APPLICATION_PATH,
              expected: sourcePointers.application,
              candidatePaths: [resolve(journalString(
                recovery.rollbackTargetApplicationPath,
                "rollback target application path",
              ))],
              swapName: journal.binding.releaseId,
              serverReleaseRoot: SERVER_RELEASE_ROOT,
            });
          }
          if (await canonicalApplicationTreeFingerprint(captureApplicationPointerSnapshot().target) !== applicationTreeSha256) {
            throw new Error("Application recovery did not restore the journal-bound tree identity");
          }
          return initiallyExact && strandedOutcome === "absent" ? "already_exact" : "mutated";
        },
      },
      {
        mutation: "static_restore",
        apply: () => {
          const current = captureReleasePointerSnapshot(staticStore);
          if (
            current.staticReleaseId === sourcePointers.staticReleaseId &&
            current.staticManifestSha256 === sourcePointers.staticManifestSha256
          ) return "already_exact";
          requireStopped();
          staticStore.activateRelease(sourcePointers.staticReleaseId);
          return "mutated";
        },
      },
      {
        mutation: "vault_restore",
        apply: async () => {
          if (await canonicalVaultFingerprint(VAULT_ROOT) === vaultFingerprint) return "already_exact";
          requireStopped();
          if (journal.binding.operation === "deploy") {
            await restoreVaultArchiveAtomically({
              archivePath: resolve(journalString(recovery.vaultArchivePath, "deploy Vault archive")),
              vaultRoot: VAULT_ROOT,
              expectedFingerprint: vaultFingerprint,
              swapId: `${journal.binding.releaseId}-journal-deploy`,
            });
          } else {
            if (!preservation) throw new Error("Rollback Vault changed before preservation was committed");
            await restoreVaultArchiveAtomically({
              archivePath: resolve(journalString(recovery.vaultArchivePath, "rollback Vault archive")),
              vaultRoot: VAULT_ROOT,
              expectedFingerprint: vaultFingerprint,
              swapId: `${journal.binding.releaseId}-journal-rollback`,
            });
          }
          return "mutated";
        },
      },
      {
        mutation: "database_restore",
        apply: async () => {
          if (
            currentSchema(DATABASE_PATH) === databaseSchema &&
            canonicalReleaseDataFingerprint(DATABASE_PATH) === databaseFingerprint
          ) return "already_exact";
          requireStopped();
          const backupPath = resolve(journalString(recovery.databasePath, "recovery database"));
          const backupSha256 = journal.binding.operation === "deploy"
            ? journalString(recovery.databaseSha256, "deploy database checksum")
            : journalString(preservation?.databaseSha256, "rollback database checksum");
          await restorePreservedDatabaseImage({
            backupPath,
            sha256: backupSha256,
            expectedSchema: databaseSchema,
            ownerUid: journalInteger(recovery.databaseOwnerUid, "database owner UID"),
            ownerGid: journalInteger(recovery.databaseOwnerGid, "database owner GID"),
          });
          if (canonicalReleaseDataFingerprint(DATABASE_PATH) !== databaseFingerprint) {
            throw new Error("Database recovery did not reproduce the journal-bound source identity");
          }
          return "mutated";
        },
      },
      {
        mutation: "deployment_receipt_restore",
        apply: async () => {
          if (journal.binding.operation === "rollback") {
            if (!preservation) {
              if (await sha256File(journal.binding.receiptPath) !==
                journalString(source.deploymentReceiptSha256, "deployed receipt checksum")) {
                throw new Error("Rollback receipt changed before preservation was committed");
              }
              return "already_exact";
            }
            const preservedPath = resolve(journalString(recovery.deploymentReceiptPath, "preserved receipt"));
            const expected = readFileSync(preservedPath);
            if (existsSync(journal.binding.receiptPath) &&
              readFileSync(journal.binding.receiptPath).equals(expected)) return "already_exact";
            writeDurableFileAtomically(journal.binding.receiptPath, expected, { mode: 0o600 });
            return "mutated";
          }
          const value = journalObject(JSON.parse(readFileSync(journal.binding.receiptPath, "utf8")), "deploy receipt");
          if (value.status === "rolled_back_after_failure") return "already_exact";
          value.status = "rolled_back_after_failure";
          value.rolledBackAt = recoveredAt;
          delete value.deployedAt;
          value.failure = "Recovered from an incomplete deploy by durable transaction reconciliation";
          writeJsonAtomically(journal.binding.receiptPath, value);
          return "mutated";
        },
      },
      {
        mutation: "source_state_verification",
        apply: async () => {
          if (!await sourceIsExact()) {
            throw new Error("Recovery refused to restart before exact app/static/database/Vault verification");
          }
          if (journal.binding.operation === "rollback" && targetPointers.application.kind === "directory") {
            const rollbackTargetPath = resolve(journalString(
              recovery.rollbackTargetApplicationPath,
              "rollback target application path",
            ));
            const rollbackTargetMetadata = lstatSync(rollbackTargetPath);
            if (
              !rollbackTargetMetadata.isDirectory() || rollbackTargetMetadata.isSymbolicLink() ||
              await canonicalApplicationTreeFingerprint(rollbackTargetPath) !==
                journalString(target.applicationTreeSha256, "rollback target application checksum")
            ) throw new Error("Recovery did not preserve the exact displaced rollback target directory");
          }
          return "already_exact" as const;
        },
      },
      {
        mutation: "service_start",
        apply: async () => {
          let lastError: unknown;
          for (let attempt = 0; attempt < 2; attempt += 1) {
            const snapshot = tiScaleStopSnapshot();
            if (snapshot.activeState !== "active" || snapshot.mainPid <= 0) {
              if (!serviceCanRestartUnchanged(snapshot)) {
                throw new Error("Recovery cannot prove process absence before restoring service intent");
              }
              startTiScale(journal.directory);
            }
            const recoveredPointers = captureReleasePointerSnapshot(staticStore);
            try {
              await waitForTiScaleExpectedRelease(staticStore, {
                previousInvocationId,
                databaseSchema,
                pointers: recoveredPointers,
                readinessMode: "journal_guarded",
              });
              await verifySourceGuarded();
              return attempt === 0 ? "mutated" as const : "already_exact" as const;
            } catch (error) {
              lastError = error;
              if (attempt > 0 || !serviceCanRestartUnchanged(tiScaleStopSnapshot())) throw error;
            }
          }
          throw lastError;
        },
      },
      {
        mutation: RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
        prepareDetail: sourceRuntimeCommitPrepareDetail(journal),
        apply: () => ensureGuardedSourceRuntimeCommit({
          label: "Prepared source-runtime commitment",
          inspect: tiScaleStopSnapshot,
          start: () => startTiScale(journal.directory),
          waitAndVerify: async () => {
              await waitForTiScaleExpectedRelease(staticStore, {
                previousInvocationId,
                databaseSchema,
                pointers: sourcePointers,
                readinessMode: "journal_guarded",
              });
              await verifySourceGuarded();
          },
        }),
      },
      {
        mutation: "runtime_activation",
        apply: async (): Promise<"mutated"> => {
          const fresh = readFunctionalReleaseTransactionJournal(journal.directory);
          if (!releaseSourceRuntimeCommitted(fresh)) {
            throw new Error("Runtime activation requires the exact durable source-runtime commitment");
          }
          clearTerminalReleaseStartupMutationBarrier(fresh);
          const snapshot = tiScaleStopSnapshot();
          if (snapshot.activeState !== "active" || snapshot.mainPid <= 0) {
            if (!serviceCanRestartUnchanged(snapshot)) {
              throw new Error("Committed source runtime cannot prove process absence before restart");
            }
            startTiScale(journal.directory);
          }
          await waitForTiScaleExpectedRelease(staticStore, {
            previousInvocationId,
            databaseSchema,
            pointers: captureReleasePointerSnapshot(staticStore),
            readinessMode: "application",
          });
          return "mutated";
        },
      },
      {
        mutation: "running_state_verification",
        apply: async () => {
          await verifySourceRunning();
          return "already_exact" as const;
        },
      },
    ],
    terminalReceipt: () => ({
      path: recoveryReceiptPath,
      value: terminalReceiptValue(),
      outcome: journal.binding.operation === "deploy"
        ? "predeploy_restored"
        : "preserved_current_restored",
    }),
    verifyTerminal,
  });
  clearTerminalReleaseStartupMutationBarrier(
    readFunctionalReleaseTransactionJournal(journal.directory),
  );
  process.stdout.write(`${JSON.stringify({
    status: result,
    releaseId: journal.binding.releaseId,
    operation: journal.binding.operation,
    journal: journal.directory,
    recoveryReceipt: recoveryReceiptPath,
  }, null, 2)}\n`);
  /* c8 ignore stop */
}

export function assertFunctionalReleaseTransactionAdmission(
  input: {
    readonly command: ReleaseCommand;
    readonly journalPath?: string;
  },
  transactionRoot = BACKUP_ROOT,
): void {
  const incomplete = discoverIncompleteFunctionalReleaseTransactions(transactionRoot);
  if (input.command !== "reconcile") {
    if (!incomplete.length) return;
    const owner = incomplete[0]!;
    throw new Error(
      `A nonterminal ${owner.operation} transaction already owns release recovery ` +
      `(${owner.releaseId}, ${owner.latestEvent}${owner.latestMutation ? `:${owner.latestMutation}` : ""}). ` +
      `Reconcile ${owner.directory} before starting another deploy or rollback.`,
    );
  }

  if (!input.journalPath) throw new Error("Reconcile admission requires an exact journal path");
  const requested = resolve(input.journalPath);
  if (incomplete.length > 1) {
    throw new Error(
      `Release recovery is ambiguous: ${String(incomplete.length)} nonterminal transaction journals require manual lineage review`,
    );
  }
  if (incomplete.length === 1 && incomplete[0]!.directory !== requested) {
    throw new Error(
      `Another nonterminal transaction owns release recovery: ${incomplete[0]!.directory}`,
    );
  }
}

export async function runFunctionalReleaseCli(argv = process.argv.slice(2)): Promise<number> {
  if (!argv.length || argv.includes("--help") || argv[0] === "help") {
    process.stdout.write(usage());
    return 0;
  }
  throw new Error(
    "Backup-capable functional release is disabled by the operator no-backup policy",
  );
}

if (import.meta.main) {
  runFunctionalReleaseCli().then((code) => { process.exitCode = code; }).catch((error) => {
    const failureDetail = error instanceof FunctionalReleaseError
      ? error.failureDetail
      : undefined;
    const legacyVerification = failureDetail?.legacyVerification ?? legacyVerificationFromError(error);
    process.stderr.write(`${JSON.stringify({
      status: "failed",
      message: error instanceof Error ? error.message : "Functional release failed",
      affectedService: SERVICE,
      affectedPort: 3132,
      legacyMutationAttempted: false,
      legacyVerification,
      legacyServiceMutated: legacyVerification === "verified_unchanged" ? false : null,
      ...(failureDetail ? { failureDetail } : { error: safeErrorRecord(error) }),
    })}\n`);
    process.exitCode = 1;
  });
}

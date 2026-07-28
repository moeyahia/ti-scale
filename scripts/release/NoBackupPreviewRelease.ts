import { createHash, randomUUID } from "node:crypto";
import {
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  closeSync,
  fsyncSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { createDatabaseConnection } from "../../server/db/connection";
import { getDatabaseHealth } from "../../server/db/health";
import {
  StoppedServiceRuntimeLeaseReconciliationService,
  withCanonicalMaintenanceLease,
} from "../../server/maintenance";
import {
  StaticArtifactReleaseStore,
  type VerifiedStaticRelease,
} from "../../server/static-release";
import {
  canonicalApplicationTreeFingerprint,
  exchangeApplicationTarget,
  queryActiveV2Work,
  verifyServerRelease,
  type VerifiedServerRelease,
} from "./FunctionalReleasePrimitives";
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
  releaseTransactionSha256,
  type FunctionalReleaseTransactionDirection,
  type FunctionalReleaseTransactionJournal,
} from "./DurableReleaseTransaction";
import {
  renameDirectoryDurably,
  writeDurableFileAtomically,
} from "./DurableAtomicFile";
import {
  runBoundedReleaseCommand,
  runBoundedReleaseCommandSync,
} from "./BoundedReleaseCommand";
import {
  SHARED_RELEASE_LOCK_PATH,
  withCooperativeReleaseSignals,
  withSharedReleaseLock,
  type CooperativeReleaseInterruption,
} from "./ReleaseExecutionBoundary";
import {
  assertReleaseMigrationAttestationsMatch,
  attestReleaseMigrationCeiling,
  type ReleaseMigrationAttestation,
} from "./ReleaseMigrationAttestation";
import {
  authorizeNextReleaseServiceStart,
  type ReleaseServiceStartAuthorizationLease,
} from "./ReleaseServiceStartAdmission";
import {
  attestInstalledReleaseServiceStartAdmission,
  RELEASE_SERVICE_START_ADMISSION_BUN_PATH,
  RELEASE_SERVICE_START_ADMISSION_HELPER_PATH,
  RELEASE_SERVICE_WRAPPER_PATH,
  releaseServiceStartAdmissionSelfReportMatches,
  releaseServiceWrapperSelfReportMatches,
  serviceStartAdmissionConfigured,
  serviceStartAdmissionMountConfigured,
  serviceWrapperConfigured,
  serviceWrapperIdentityConfigured,
} from "./ReleaseServiceStartAdmissionBundle";
import {
  assertReleaseServiceStartAdmissionInstallationCommitted,
} from "./ReleaseServiceStartAdmissionInstallation";
import {
  assertNoActiveWorkSnapshot,
  assertServiceIdentityUnchanged,
  clearTerminalReleaseStartupMutationBarrier,
  ensureGuardedSourceRuntimeCommit,
  serviceCanRestartUnchanged,
  stopServiceWithGuardedFailedUnitNormalization,
  type ServiceIdentity,
  type ServiceStopSnapshot,
} from "./ForwardOnlyReleaseRuntimeBoundary";
import {
  RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
  RELEASE_SOURCE_RUNTIME_PROTOCOL,
  RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL,
  releaseSourceRuntimeCommitted,
  releaseTargetRuntimeCommitted,
} from "./ReleaseStartupMutationBarrier";
import { OrphanedNoBackupMaintenanceLeaseReconciler } from
  "./OrphanedNoBackupMaintenanceLeaseReconciler";
import {
  assertNoBackupForwardOnlySchemaProgression,
  classifyNoBackupForwardOnlyRecovery,
  commitNoBackupTerminalAfterCompatibilityProof,
  enforceNoBackupRecoveryInterruptionPolicy,
  executeNoBackupForwardOnlyController,
  executeNoBackupForwardOnlyPhaseSequence,
  type NoBackupForwardOnlyPhaseOperations,
} from "./NoBackupForwardOnlyController";

export const NO_BACKUP_PREVIEW_RECEIPT_SCHEMA =
  "ti-scale.no-backup-preview-release-receipt.v1" as const;
export const NO_BACKUP_FORWARD_RECEIPT_SCHEMA =
  "ti-scale.no-backup-forward-release-receipt.v2" as const;
export const NO_BACKUP_PREVIEW_ACKNOWLEDGEMENT_FLAG =
  "--acknowledge-no-backup-risk" as const;
export const NO_BACKUP_PREVIEW_BACKUP_POLICY = "none" as const;
export const NO_BACKUP_PREVIEW_ROLLBACK_CAPABILITY =
  "none_after_schema_commit" as const;
export const NO_BACKUP_CURRENT_DEPLOYMENT_MODE =
  "current_service" as const;
export const NO_BACKUP_STANDALONE_RELEASE_OBSERVER = Object.freeze({
  schemaVersion: "ti-scale.release-observer.v1" as const,
  mode: "standalone" as const,
  scope: "ti_scale_only" as const,
  externalServiceDependency: "none" as const,
});

export const NO_BACKUP_APPLICATION_PATH = "/opt/ti-scale";
export const NO_BACKUP_SERVER_RELEASE_ROOT =
  "/opt/ti-scale-server-releases";
export const NO_BACKUP_STATIC_RELEASE_ROOT =
  "/var/lib/ti-scale/static-releases";
const APPLICATION_PATH = NO_BACKUP_APPLICATION_PATH;
const SERVER_RELEASE_ROOT = NO_BACKUP_SERVER_RELEASE_ROOT;
const STATIC_RELEASE_ROOT = NO_BACKUP_STATIC_RELEASE_ROOT;
const DATABASE_PATH = "/var/lib/ti-scale/data/ti-scale.sqlite";
const TRANSACTION_ROOT = "/var/lib/ti-scale/release-transactions";
const SERVICE = "ti-scale.service";
const LEGACY_SERVICE = "chillspwn.service";
const TI_SCALE_HEALTH = "http://127.0.0.1:3132/api/v2/health";
const TI_SCALE_READINESS = "http://127.0.0.1:3132/api/v2/system/readiness";
const CHILLSPWN_HEALTH = "http://127.0.0.1:3131/api/health";
const BUN = "/usr/local/bin/bun";
export const NO_BACKUP_SOURCE_SCHEMA = 60 as const;
export const NO_BACKUP_HISTORICAL_SOURCE_SCHEMA = 47 as const;
export const NO_BACKUP_TARGET_SCHEMA = 60 as const;
const SOURCE_SCHEMA = NO_BACKUP_SOURCE_SCHEMA;
const TARGET_SCHEMA = NO_BACKUP_TARGET_SCHEMA;
const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

export interface NoBackupPreviewArguments {
  readonly command: "deploy" | "recover";
  readonly releaseId: string;
  readonly confirmation: string;
  readonly execute: true;
  readonly noBackupRiskAcknowledged: true;
}

export interface NoBackupPayloadEntry {
  readonly path: string;
  readonly bytes: number;
  readonly device: string;
  readonly inode: string;
  readonly modifiedMs: number;
  readonly changedMs: number;
  readonly sha256: string;
}

export function noBackupTargetStartMode(
  journal: FunctionalReleaseTransactionJournal,
): "journal_authorized" | "target_runtime_committed" {
  return releaseTargetRuntimeCommitted(journal)
    ? "target_runtime_committed"
    : "journal_authorized";
}

export async function startNoBackupTargetService(options: {
  readonly journalDirectory: string;
  readonly startService: () => void | Promise<void>;
  readonly authorizeServiceStart?: (
    journalDirectory: string,
  ) => ReleaseServiceStartAuthorizationLease;
}): Promise<"journal_authorized" | "target_runtime_committed"> {
  const mode = noBackupTargetStartMode(
    readFunctionalReleaseTransactionJournal(options.journalDirectory),
  );
  if (mode === "target_runtime_committed") {
    await options.startService();
    return mode;
  }
  const authorization = (
    options.authorizeServiceStart ?? authorizeNextReleaseServiceStart
  )(options.journalDirectory);
  try {
    await options.startService();
  } finally {
    authorization.release();
  }
  return mode;
}

export interface NoBackupPayloadInventory {
  readonly schemaVersion: "ti-scale.backup-payload-inventory.v1";
  readonly roots: readonly string[];
  readonly entries: readonly NoBackupPayloadEntry[];
  readonly inventorySha256: string;
}

export interface NoBackupReleasePointer {
  readonly applicationTarget: string;
  readonly staticReleaseId: string;
  readonly staticManifestSha256: string;
}

interface NoBackupReceiptBase {
  readonly releaseId: string;
  readonly createdAt: string;
  readonly hostBootId: string;
  status:
    | "prepared"
    | "maintenance"
    | "deployed"
    | "failed_predeploy_restored"
    | "failed_forward_recovery_required";
  readonly backupPolicy: typeof NO_BACKUP_PREVIEW_BACKUP_POLICY;
  readonly rollbackCapability: typeof NO_BACKUP_PREVIEW_ROLLBACK_CAPABILITY;
  readonly operatorAcknowledgement: "no_backup_and_no_downgrade";
  readonly serverRelease: {
    readonly path: string;
    readonly manifestSha256: string;
    readonly treeSha256: string;
  };
  readonly staticRelease: {
    readonly path: string;
    readonly manifestSha256: string;
  };
  readonly candidateStaging?: {
    readonly schemaVersion:
      "ti-scale.no-backup-candidate-staging-binding.v1";
    readonly sourceCommit: string;
    readonly sourceTreeSha256: string;
    readonly staticArtifactSha256: string;
  };
  readonly previous: NoBackupReleasePointer;
  readonly target: NoBackupReleasePointer;
  readonly backupPayloadInventoryBefore: NoBackupPayloadInventory;
  backupPayloadInventoryAfter?: NoBackupPayloadInventory;
  backupPayloadInventoryUnchanged?: boolean;
  recoveryHostBootId?: string;
  tiScaleBefore: ServiceIdentity;
  tiScaleAfter?: ServiceIdentity;
  deployedAt?: string;
  failedAt?: string;
  failure?: string;
  forwardRecoveryRequired?: boolean;
}

export interface NoBackupForwardReceipt extends NoBackupReceiptBase {
  readonly schemaVersion: typeof NO_BACKUP_FORWARD_RECEIPT_SCHEMA;
  readonly deploymentMode: typeof NO_BACKUP_CURRENT_DEPLOYMENT_MODE;
  readonly releaseObserver: typeof NO_BACKUP_STANDALONE_RELEASE_OBSERVER;
  readonly cutoverEligible?: never;
  readonly database: {
    readonly sourceSchema: typeof NO_BACKUP_SOURCE_SCHEMA;
    readonly targetSchema: typeof NO_BACKUP_TARGET_SCHEMA;
    readonly migrationAttestation: ReleaseMigrationAttestation;
    schemaCommittedAt?: string;
  };
  readonly chillspwnBefore?: never;
  chillspwnAfter?: never;
  chillspwnRecoveryBaseline?: never;
  chillspwnIdentityChangedBeforeRecovery?: never;
}

/**
 * Exact historical v1 shape retained solely so an interrupted transaction
 * created by the old controller can still be recovered. No new deployment
 * constructs this shape.
 */
export interface NoBackupLegacyPreviewReceipt extends NoBackupReceiptBase {
  readonly schemaVersion: typeof NO_BACKUP_PREVIEW_RECEIPT_SCHEMA;
  readonly cutoverEligible: false;
  readonly deploymentMode?: never;
  readonly releaseObserver?: never;
  readonly database: {
    readonly sourceSchema: typeof NO_BACKUP_HISTORICAL_SOURCE_SCHEMA;
    readonly targetSchema: typeof NO_BACKUP_TARGET_SCHEMA;
    readonly migrationAttestation: ReleaseMigrationAttestation;
    schemaCommittedAt?: string;
  };
  readonly chillspwnBefore: ServiceIdentity;
  chillspwnAfter?: ServiceIdentity;
  chillspwnRecoveryBaseline?: ServiceIdentity;
  chillspwnIdentityChangedBeforeRecovery?: boolean;
}

export type NoBackupPreviewReceipt =
  | NoBackupForwardReceipt
  | NoBackupLegacyPreviewReceipt;

export interface NoBackupStagedCandidateBinding {
  readonly schemaVersion:
    "ti-scale.no-backup-candidate-staging-binding.v1";
  readonly releaseId: string;
  readonly sourceCommit: string;
  readonly sourceTreeSha256: string;
  readonly staticArtifactSha256: string;
  readonly serverRelease: {
    readonly path: string;
    readonly manifestSha256: string;
    readonly treeSha256: string;
  };
  readonly staticRelease: {
    readonly path: string;
    readonly manifestSha256: string;
    readonly artifactSha256: string;
  };
}

export interface NoBackupCandidateLifecycle {
  stage(): Promise<NoBackupStagedCandidateBinding>;
  discardBeforeTransaction(
    candidate: NoBackupStagedCandidateBinding,
  ): void | Promise<void>;
}

export type NoBackupRecoveryDirection =
  | "restore_source"
  | "complete_target";

export const NO_BACKUP_PAYLOAD_ROOTS = Object.freeze([
  "/var/backups/ti-scale",
  "/var/lib/ti-scale/backups",
  "/var/lib/ti-scale/data/backups",
  "/var/lib/ti-scale/data/migration-backups",
  "/var/lib/ti-scale/hotfix-backups",
  "/var/lib/ti-scale/imports/historical-sqlite-snapshots",
  "/var/lib/ti-scale/rehearsals",
  "/var/lib/ti-scale/release-rehearsal",
  "/var/lib/ti-scale/staging",
] as const);

export interface NoBackupPreviewPhaseOperations {
  readonly stop: NoBackupForwardOnlyPhaseOperations["stop"];
  readonly withMaintenance: NoBackupForwardOnlyPhaseOperations["withMaintenance"];
  readonly migrate: NoBackupForwardOnlyPhaseOperations["migrate"];
  readonly commitTarget: NoBackupForwardOnlyPhaseOperations["commitTarget"];
  readonly startAndFinalize: () => void | Promise<void>;
}

export interface NoBackupServiceProperties {
  readonly activeState: string;
  readonly mainPid: number;
  readonly invocationId: string;
  readonly controlGroup: string;
}

interface JsonHealth {
  readonly statusCode: number;
  readonly semanticStatus: string;
  readonly body: Record<string, unknown>;
}

interface PreparedNoBackupPreview {
  readonly receipt: NoBackupPreviewReceipt;
  readonly receiptPath: string;
  readonly journalDirectory: string;
  /**
   * A source-restoration replay may begin after the failed candidate trees
   * were durably scheduled for deletion and partially or fully removed.
   * Target completion never permits either value to be absent.
   */
  readonly server?: VerifiedServerRelease;
  readonly staticRelease?: VerifiedStaticRelease;
}

export type NoBackupReleaseObserverProof =
  | ServiceIdentity
  | typeof NO_BACKUP_STANDALONE_RELEASE_OBSERVER;

export function isStandaloneNoBackupForwardReceipt(
  receipt: NoBackupPreviewReceipt,
): receipt is NoBackupForwardReceipt {
  return (
    receipt.schemaVersion === NO_BACKUP_FORWARD_RECEIPT_SCHEMA &&
    receipt.deploymentMode === NO_BACKUP_CURRENT_DEPLOYMENT_MODE &&
    releaseTransactionSha256(receipt.releaseObserver ?? null) ===
      releaseTransactionSha256(NO_BACKUP_STANDALONE_RELEASE_OBSERVER) &&
    receipt.cutoverEligible === undefined &&
    receipt.chillspwnBefore === undefined &&
    receipt.chillspwnAfter === undefined &&
    receipt.chillspwnRecoveryBaseline === undefined &&
    receipt.chillspwnIdentityChangedBeforeRecovery === undefined
  );
}

function isLegacyNoBackupPreviewReceipt(
  receipt: NoBackupPreviewReceipt,
): receipt is NoBackupLegacyPreviewReceipt {
  return (
    receipt.schemaVersion === NO_BACKUP_PREVIEW_RECEIPT_SCHEMA &&
    receipt.cutoverEligible === false &&
    receipt.deploymentMode === undefined &&
    receipt.releaseObserver === undefined &&
    receipt.chillspwnBefore !== undefined
  );
}

function receiptObserverProof(
  receipt: NoBackupPreviewReceipt,
  phase: "before" | "after",
): NoBackupReleaseObserverProof {
  if (isStandaloneNoBackupForwardReceipt(receipt)) {
    return NO_BACKUP_STANDALONE_RELEASE_OBSERVER;
  }
  if (!isLegacyNoBackupPreviewReceipt(receipt)) {
    throw new Error("No-backup receipt has no valid release observer");
  }
  const proof = phase === "before"
    ? receipt.chillspwnBefore
    : receipt.chillspwnAfter;
  if (!proof) {
    throw new Error(
      `Historical no-backup receipt lacks its ${phase} compatibility proof`,
    );
  }
  return proof;
}

function observerProofField(
  receipt: NoBackupPreviewReceipt,
): "observerProofSha256" | "legacyIdentitySha256" {
  return isStandaloneNoBackupForwardReceipt(receipt)
    ? "observerProofSha256"
    : "legacyIdentitySha256";
}

export function noBackupObserverProofDetail(
  receipt: NoBackupPreviewReceipt,
  proofSha256: string,
): Readonly<Record<string, string>> {
  return { [observerProofField(receipt)]: proofSha256 };
}

export function noBackupObserverProofSha256FromDetail(
  detail: Readonly<Record<string, unknown>> | undefined,
  receipt: NoBackupPreviewReceipt,
): string | undefined {
  const value = detail?.[observerProofField(receipt)];
  return typeof value === "string" ? value : undefined;
}

export async function resolveNoBackupReleaseObserverProof(
  receipt: NoBackupPreviewReceipt,
  captureHistoricalObserver: () => Promise<ServiceIdentity>,
): Promise<NoBackupReleaseObserverProof> {
  if (isStandaloneNoBackupForwardReceipt(receipt)) {
    return NO_BACKUP_STANDALONE_RELEASE_OBSERVER;
  }
  if (!isLegacyNoBackupPreviewReceipt(receipt)) {
    throw new Error("No-backup receipt has no valid release observer");
  }
  return captureHistoricalObserver();
}

function safeJsonError(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

function minimalEnvironment(home = "/root"): NodeJS.ProcessEnv {
  return {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: home,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NO_COLOR: "1",
    CI: "1",
  };
}

function currentHostBootId(): string {
  const value = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().toLowerCase();
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
  ) {
    throw new Error("Kernel boot identity is missing or malformed");
  }
  return value;
}

function command(
  arguments_: readonly string[],
  options: {
    readonly cwd?: string;
    readonly env?: NodeJS.ProcessEnv;
    readonly timeoutMs?: number;
    readonly allowNonZeroExit?: boolean;
  } = {},
): string {
  return runBoundedReleaseCommandSync(arguments_, {
    cwd: options.cwd ?? "/",
    env: options.env ?? minimalEnvironment(),
    stdin: "ignore",
    timeoutMs: options.timeoutMs ?? 5 * 60_000,
    outputLimitBytes: 2 * 1024 * 1024,
    ...(options.allowNonZeroExit ? { allowNonZeroExit: true } : {}),
  }).stdout;
}

function parseSystemdProperties(output: string): NoBackupServiceProperties {
  const values = Object.fromEntries(output.split("\n").filter(Boolean).map((line) => {
    const index = line.indexOf("=");
    return index < 0 ? [line, ""] : [line.slice(0, index), line.slice(index + 1)];
  }));
  return {
    activeState: values.ActiveState ?? "unknown",
    mainPid: Number(values.MainPID ?? 0),
    invocationId: values.InvocationID ?? "",
    controlGroup: values.ControlGroup ?? "",
  };
}

function serviceProperties(service: string): NoBackupServiceProperties {
  return parseSystemdProperties(command([
    "/usr/bin/systemctl",
    "show",
    service,
    "--property=ActiveState,MainPID,InvocationID,ControlGroup",
    "--no-pager",
  ]));
}

async function jsonHealth(url: string, timeoutMs = 3_000): Promise<JsonHealth> {
  const response = await fetch(url, {
    cache: "no-store",
    signal: AbortSignal.timeout(timeoutMs),
  });
  const body = await response.json() as Record<string, unknown>;
  return {
    statusCode: response.status,
    semanticStatus: typeof body.status === "string" ? body.status : "unknown",
    body,
  };
}

async function captureServiceIdentity(
  service: string,
  healthUrl: string,
): Promise<ServiceIdentity> {
  const properties = serviceProperties(service);
  const health = await jsonHealth(healthUrl);
  return {
    activeState: properties.activeState,
    mainPid: properties.mainPid,
    invocationId: properties.invocationId,
    healthStatus: health.statusCode,
    semanticStatus: health.semanticStatus,
  };
}

function assertHealthyService(
  identity: ServiceIdentity,
  semanticStatus: string,
  label: string,
): void {
  if (
    identity.activeState !== "active" ||
    !Number.isSafeInteger(identity.mainPid) ||
    identity.mainPid <= 0 ||
    !/^[a-f0-9]{32}$/u.test(identity.invocationId) ||
    identity.healthStatus !== 200 ||
    identity.semanticStatus !== semanticStatus
  ) {
    throw new Error(`${label} is not healthy at the no-backup release boundary`);
  }
}

function databaseSchema(): number {
  const database = createDatabaseConnection({
    filename: DATABASE_PATH,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    return Number((database.prepare(
      "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations",
    ).get() as { readonly version: number }).version);
  } finally {
    database.close();
  }
}

function assertCanonicalDatabase(
  targetSchema: number,
  options: { readonly verifyIntegrity?: boolean } = {},
): void {
  const verifyIntegrity = options.verifyIntegrity === true;
  const database = createDatabaseConnection({
    filename: DATABASE_PATH,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity,
  });
  try {
    const schema = Number((database.prepare(
      "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations",
    ).get() as { readonly version: number }).version);
    const foreignKeys = Number(database.pragma("foreign_keys", { simple: true })) === 1;
    const integrityHealthy = !verifyIntegrity || getDatabaseHealth(database).healthy;
    if (!integrityHealthy || !foreignKeys || schema !== targetSchema) {
      throw new Error(
        `Canonical database verification failed ` +
        `(integrityHealthy=${String(integrityHealthy)}, foreignKeys=${String(foreignKeys)}, ` +
        `schema=${String(schema)})`,
      );
    }
    const foreignKeyViolations = database.prepare("PRAGMA foreign_key_check").all();
    if (foreignKeyViolations.length) {
      throw new Error("Canonical database contains foreign-key violations");
    }
  } finally {
    database.close();
  }
  const serviceUid = Number(command(["/usr/bin/id", "-u", "ti-scale"]));
  const serviceGid = Number(command(["/usr/bin/id", "-g", "ti-scale"]));
  const metadata = statSync(DATABASE_PATH);
  if (
    metadata.uid !== serviceUid ||
    metadata.gid !== serviceGid ||
    (metadata.mode & 0o777) !== 0o600
  ) {
    throw new Error("Canonical database ownership or mode changed during forward deployment");
  }
}

function cgroupProcessIds(controlGroup: string): readonly number[] {
  if (
    !controlGroup.startsWith("/") ||
    controlGroup.split("/").includes("..") ||
    basename(controlGroup) !== SERVICE
  ) return [];
  const path = resolve("/sys/fs/cgroup", `.${controlGroup}`, "cgroup.procs");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split(/\s+/u)
    .filter(Boolean)
    .map(Number)
    .filter((pid) => Number.isSafeInteger(pid) && pid > 0)
    .sort((left, right) => left - right);
}

function port3132Listening(): boolean {
  return command([
    "/usr/bin/ss",
    "--no-header",
    "--tcp",
    "--listening",
    "--numeric",
    "sport = :3132",
  ]).trim().length > 0;
}

export function noBackupStopSnapshotFromServiceProperties(
  properties: NoBackupServiceProperties,
  inspection: {
    readonly controlGroupProcessIds: (
      controlGroup: string,
    ) => readonly number[];
    readonly portListening: () => boolean;
  },
): ServiceStopSnapshot {
  const controlGroup =
    properties.activeState === "inactive" &&
      properties.mainPid === 0 &&
      properties.controlGroup === ""
      ? "/system.slice/ti-scale.service"
      : properties.controlGroup;
  return {
    activeState: properties.activeState,
    mainPid: properties.mainPid,
    controlGroup,
    controlGroupProcessIds: inspection.controlGroupProcessIds(controlGroup),
    portListening: inspection.portListening(),
  };
}

function stopSnapshot(): ServiceStopSnapshot {
  return noBackupStopSnapshotFromServiceProperties(
    serviceProperties(SERVICE),
    {
      controlGroupProcessIds: cgroupProcessIds,
      portListening: port3132Listening,
    },
  );
}

function assertNoCanonicalDatabaseUsers(): void {
  Bun.gc(true);
  const paths = [DATABASE_PATH, `${DATABASE_PATH}-wal`, `${DATABASE_PATH}-shm`]
    .filter(existsSync);
  const result = runBoundedReleaseCommandSync([
    "/usr/bin/lsof",
    "-t",
    "--",
    ...paths,
  ], {
    cwd: "/",
    env: minimalEnvironment(),
    stdin: "ignore",
    timeoutMs: 30_000,
    outputLimitBytes: 256 * 1024,
    allowNonZeroExit: true,
  });
  if (result.exitCode !== 0 && !(result.exitCode === 1 && !result.stdout)) {
    throw new Error("Could not prove exclusive canonical database access");
  }
  if (result.stdout.trim()) {
    throw new Error(`Canonical database still has open process handles: ${result.stdout.trim()}`);
  }
}

function assertNoActiveWork(): void {
  assertNoActiveWorkSnapshot(queryActiveV2Work(DATABASE_PATH));
}

function applicationTarget(): string {
  const metadata = lstatSync(APPLICATION_PATH);
  if (!metadata.isSymbolicLink()) {
    throw new Error(
      "No-backup forward deployment requires /opt/ti-scale to already be a symbolic link",
    );
  }
  return realpathSync(APPLICATION_PATH);
}

function activePointer(
  staticStore: StaticArtifactReleaseStore,
): NoBackupReleasePointer {
  const pointer = staticStore.readActivePointer();
  return {
    applicationTarget: applicationTarget(),
    staticReleaseId: pointer.activeReleaseId,
    staticManifestSha256: pointer.activeManifestSha256,
  };
}

function assertPointer(
  staticStore: StaticArtifactReleaseStore,
  expected: NoBackupReleasePointer,
  label: string,
): void {
  const observed = activePointer(staticStore);
  if (
    observed.applicationTarget !== expected.applicationTarget ||
    observed.staticReleaseId !== expected.staticReleaseId ||
    observed.staticManifestSha256 !== expected.staticManifestSha256
  ) {
    throw new Error(`${label} application/static pointer identity is not exact`);
  }
}

function atomicApplicationActivation(
  releaseId: string,
  target: string,
): void {
  if (applicationTarget() === realpathSync(target)) return;
  const forbiddenDirectoryArchive = join(
    SERVER_RELEASE_ROOT,
    "releases",
    `.no-backup-directory-archive-forbidden-${releaseId}`,
  );
  if (existsSync(forbiddenDirectoryArchive)) {
    throw new Error("No-backup forward directory-archive sentinel already exists");
  }
  const result = exchangeApplicationTarget({
    applicationPath: APPLICATION_PATH,
    newTarget: target,
    previousDirectoryArchive: forbiddenDirectoryArchive,
    swapName: `no-backup-${releaseId}`,
  });
  if (result.previousKind !== "symlink") {
    throw new Error("No-backup forward deployment unexpectedly displaced a directory");
  }
  if (existsSync(forbiddenDirectoryArchive)) {
    throw new Error("No-backup forward deployment created a forbidden application archive");
  }
}

export interface SupersededReleaseCleanupInput {
  readonly serverReleaseRoot: string;
  readonly staticReleaseRoot: string;
  readonly activeServerReleaseId: string;
  readonly activeApplicationTarget: string;
  readonly previousApplicationTarget: string;
  readonly activeStaticReleaseId: string;
  readonly activeStaticManifestSha256: string;
  readonly previousStaticReleaseId: string;
  readonly previousStaticManifestSha256: string;
  readonly onStaticPreviousIdentityCleared?: () => void;
}

export interface SupersededReleaseCleanupResult {
  readonly staticPreviousIdentityCleared: true;
  readonly staticReleaseDeleted: boolean;
  readonly serverReleaseDeleted: boolean;
}

export interface FailedCandidateReleaseCleanupInput {
  readonly serverReleaseRoot: string;
  readonly staticReleaseRoot: string;
  readonly activeApplicationTarget: string;
  readonly activeStaticReleaseId: string;
  readonly activeStaticManifestSha256: string;
  readonly candidateReleaseId: string;
  readonly candidateApplicationTarget: string;
  readonly candidateServerManifestSha256: string;
  readonly candidateServerTreeSha256: string;
  readonly candidateStaticManifestSha256: string;
}

export interface FailedCandidateReleaseCleanupResult {
  readonly staticReleaseDeleted: boolean;
  readonly serverReleaseDeleted: boolean;
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function pathEntryExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return false;
    }
    throw error;
  }
}

function exactManagedServerRelease(
  serverReleaseRoot: string,
  candidate: string,
): { readonly releasesDirectory: string; readonly releaseId: string } | null {
  const releasesDirectory = join(resolve(serverReleaseRoot), "releases");
  const normalized = resolve(candidate);
  if (dirname(normalized) !== releasesDirectory) return null;
  const releaseId = basename(normalized);
  if (!RELEASE_ID.test(releaseId)) {
    throw new Error("Managed server release has an invalid immutable release ID");
  }
  return { releasesDirectory, releaseId };
}

function assertExactReleaseDirectory(path: string, label: string): void {
  const metadata = lstatSync(path);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    realpathSync(path) !== resolve(path)
  ) {
    throw new Error(`${label} is not an exact immutable release directory`);
  }
}

/**
 * Irreversibly discard the two superseded immutable release trees after the
 * replacement runtime and release-observer proof have both succeeded.
 *
 * Pointer identity is cleared before the old static tree is removed. A crash
 * at any later instruction therefore leaves, at worst, an unreferenced old
 * tree. Replaying this function deletes that tree and is otherwise a no-op.
 */
export function finalizeSupersededReleaseArtifacts(
  input: SupersededReleaseCleanupInput,
): SupersededReleaseCleanupResult {
  const activeServer = exactManagedServerRelease(
    input.serverReleaseRoot,
    input.activeApplicationTarget,
  );
  if (
    !activeServer ||
    activeServer.releaseId !== input.activeServerReleaseId
  ) {
    throw new Error(
      "Forward-only cleanup does not match the active managed server release",
    );
  }
  assertExactReleaseDirectory(
    input.activeApplicationTarget,
    "Active server release",
  );
  const previousServer = exactManagedServerRelease(
    input.serverReleaseRoot,
    input.previousApplicationTarget,
  );
  if (
    previousServer &&
    previousServer.releaseId === activeServer.releaseId
  ) {
    throw new Error(
      "Forward-only cleanup must never delete the active server release",
    );
  }

  const staticResult = new StaticArtifactReleaseStore({
    releaseRoot: input.staticReleaseRoot,
  }).finalizeForwardOnlyActivation({
    activeReleaseId: input.activeStaticReleaseId,
    activeManifestSha256: input.activeStaticManifestSha256,
    supersededReleaseId: input.previousStaticReleaseId,
    supersededManifestSha256: input.previousStaticManifestSha256,
    ...(input.onStaticPreviousIdentityCleared
      ? {
        onPreviousIdentityCleared:
          input.onStaticPreviousIdentityCleared,
      }
      : {}),
  });

  let serverReleaseDeleted = false;
  if (previousServer) {
    try {
      assertExactReleaseDirectory(
        input.previousApplicationTarget,
        "Superseded server release",
      );
      rmSync(input.previousApplicationTarget, {
        recursive: true,
        force: false,
      });
      syncDirectory(previousServer.releasesDirectory);
      serverReleaseDeleted = true;
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          (error as NodeJS.ErrnoException).code === "ENOENT"
        )
      ) {
        throw error;
      }
    }
  }
  assertExactReleaseDirectory(
    input.activeApplicationTarget,
    "Active server release after cleanup",
  );
  return {
    staticPreviousIdentityCleared:
      staticResult.previousIdentityCleared,
    staticReleaseDeleted: staticResult.supersededReleaseDeleted,
    serverReleaseDeleted,
  };
}

/**
 * Irreversibly remove only the exact, unreferenced candidate created for a
 * deployment that failed before its schema commit. The restored source
 * identities are proven first and rechecked after deletion. Missing candidate
 * trees are accepted only to make a journaled replay idempotent.
 */
export async function discardFailedPreSchemaCandidateArtifacts(
  input: FailedCandidateReleaseCleanupInput,
): Promise<FailedCandidateReleaseCleanupResult> {
  const activeServer = exactManagedServerRelease(
    input.serverReleaseRoot,
    input.activeApplicationTarget,
  );
  if (!activeServer) {
    throw new Error(
      "Failed-candidate cleanup does not match an active managed server release",
    );
  }
  assertExactReleaseDirectory(
    input.activeApplicationTarget,
    "Restored active server release",
  );

  const candidateServer = exactManagedServerRelease(
    input.serverReleaseRoot,
    input.candidateApplicationTarget,
  );
  if (
    !candidateServer ||
    candidateServer.releaseId !== input.candidateReleaseId ||
    resolve(input.candidateApplicationTarget) !==
      join(candidateServer.releasesDirectory, input.candidateReleaseId)
  ) {
    throw new Error(
      "Failed-candidate cleanup does not match the exact candidate server release",
    );
  }
  if (
    candidateServer.releaseId === activeServer.releaseId ||
    resolve(input.candidateApplicationTarget) ===
      resolve(input.activeApplicationTarget)
  ) {
    throw new Error(
      "Failed-candidate cleanup must never delete the active server release",
    );
  }

  const staticStore = new StaticArtifactReleaseStore({
    releaseRoot: input.staticReleaseRoot,
  });
  const pointerBefore = staticStore.readActivePointer();
  const activeStatic = staticStore.verifyRelease(
    input.activeStaticReleaseId,
    input.activeStaticManifestSha256,
  );
  if (
    pointerBefore.activeReleaseId !== activeStatic.releaseId ||
    pointerBefore.activeManifestSha256 !== activeStatic.manifestSha256
  ) {
    throw new Error(
      "Failed-candidate cleanup does not match the restored active static release",
    );
  }
  if (
    input.candidateReleaseId === pointerBefore.activeReleaseId ||
    input.candidateReleaseId === pointerBefore.previousReleaseId
  ) {
    throw new Error(
      "Failed-candidate cleanup refuses a static release retained by the active pointer",
    );
  }

  const candidateStaticDirectory = join(
    staticStore.releasesDirectory,
    input.candidateReleaseId,
  );
  let candidateServerPresent = pathEntryExists(
    input.candidateApplicationTarget,
  );
  let candidateStaticPresent = pathEntryExists(
    candidateStaticDirectory,
  );
  if (candidateServerPresent) {
    assertExactReleaseDirectory(
      input.candidateApplicationTarget,
      "Failed candidate server release",
    );
    const verified = await verifyServerRelease(
      input.candidateApplicationTarget,
      input.candidateReleaseId,
      input.candidateServerManifestSha256,
    );
    if (verified.manifest.treeSha256 !== input.candidateServerTreeSha256) {
      throw new Error(
        "Failed candidate server tree does not match its recorded identity",
      );
    }
  }
  if (candidateStaticPresent) {
    const verified = staticStore.verifyRelease(
      input.candidateReleaseId,
      input.candidateStaticManifestSha256,
    );
    if (verified.releaseDirectory !== candidateStaticDirectory) {
      throw new Error(
        "Failed candidate static release does not match its recorded identity",
      );
    }
  }

  let staticReleaseDeleted = false;
  if (candidateStaticPresent) {
    try {
      rmSync(candidateStaticDirectory, { recursive: true, force: false });
      syncDirectory(staticStore.releasesDirectory);
      staticReleaseDeleted = true;
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          (error as NodeJS.ErrnoException).code === "ENOENT"
        )
      ) {
        throw error;
      }
      candidateStaticPresent = false;
    }
  }

  let serverReleaseDeleted = false;
  if (candidateServerPresent) {
    try {
      rmSync(input.candidateApplicationTarget, {
        recursive: true,
        force: false,
      });
      syncDirectory(candidateServer.releasesDirectory);
      serverReleaseDeleted = true;
    } catch (error) {
      if (
        !(
          error instanceof Error &&
          "code" in error &&
          (error as NodeJS.ErrnoException).code === "ENOENT"
        )
      ) {
        throw error;
      }
      candidateServerPresent = false;
    }
  }

  assertExactReleaseDirectory(
    input.activeApplicationTarget,
    "Restored active server release after candidate cleanup",
  );
  const pointerAfter = staticStore.readActivePointer();
  staticStore.verifyRelease(
    input.activeStaticReleaseId,
    input.activeStaticManifestSha256,
  );
  if (
    pointerAfter.generation !== pointerBefore.generation ||
    pointerAfter.activeReleaseId !== pointerBefore.activeReleaseId ||
    pointerAfter.activeManifestSha256 !== pointerBefore.activeManifestSha256 ||
    pointerAfter.previousReleaseId !== pointerBefore.previousReleaseId ||
    pointerAfter.previousManifestSha256 !== pointerBefore.previousManifestSha256
  ) {
    throw new Error(
      "Active static release identity changed during failed-candidate cleanup",
    );
  }
  if (
    pathEntryExists(input.candidateApplicationTarget) ||
    pathEntryExists(candidateStaticDirectory)
  ) {
    throw new Error(
      "Failed-candidate cleanup retained an unreferenced candidate release",
    );
  }
  return { staticReleaseDeleted, serverReleaseDeleted };
}

function inventoryRecord(entries: readonly NoBackupPayloadEntry[]): string {
  return JSON.stringify(entries.map((entry) => ({
    path: entry.path,
    bytes: entry.bytes,
    device: entry.device,
    inode: entry.inode,
    modifiedMs: entry.modifiedMs,
    changedMs: entry.changedMs,
    sha256: entry.sha256,
  })));
}

function sha256RegularFile(path: string): string {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const bytes = readSync(descriptor, buffer, 0, buffer.byteLength, null);
      if (bytes === 0) break;
      digest.update(buffer.subarray(0, bytes));
    }
  } finally {
    closeSync(descriptor);
  }
  return digest.digest("hex");
}

function excludedReleaseMetadataJson(path: string): boolean {
  const normalized = resolve(path);
  const metadataRoot = resolve(TRANSACTION_ROOT);
  if (!containedBy(metadataRoot, normalized)) return false;
  const child = relative(metadataRoot, normalized).split(sep);
  if (
    child.length === 2 &&
    RELEASE_ID.test(child[0] ?? "") &&
    child[1] === "no-backup-preview-receipt.json"
  ) return true;
  return child.length === 3 &&
    RELEASE_ID.test(child[0] ?? "") &&
    child[1] === "transaction-journal" &&
    (
      child[2] === "binding.json" ||
      /^\d{8}-[a-f0-9]{64}\.json$/u.test(child[2] ?? "")
    );
}

function containedBy(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" ||
    (!child.startsWith(`..${sep}`) && child !== ".." && !child.startsWith("/"));
}

export function captureNoBackupPayloadInventory(
  roots: readonly string[] = NO_BACKUP_PAYLOAD_ROOTS,
): NoBackupPayloadInventory {
  const canonicalRoots = roots
    .map((value) => resolve(value))
    .sort((left, right) => left.localeCompare(right, "en"));
  const entries: NoBackupPayloadEntry[] = [];
  const visit = (root: string, path: string): void => {
    const metadata = lstatSync(path, { bigint: true });
    if (metadata.isSymbolicLink()) {
      throw new Error(
        `No-backup payload inventory refuses nested symbolic links: ${path}`,
      );
    }
    if (metadata.isDirectory()) {
      for (const name of readdirSync(path).sort((left, right) => left.localeCompare(right, "en"))) {
        const child = join(path, name);
        if (!containedBy(root, child)) throw new Error("Backup inventory traversal escaped its root");
        visit(root, child);
      }
      return;
    }
    if (!metadata.isFile() || excludedReleaseMetadataJson(path)) return;
    const sha256 = sha256RegularFile(path);
    const afterHash = lstatSync(path, { bigint: true });
    if (
      !afterHash.isFile() ||
      afterHash.isSymbolicLink() ||
      afterHash.dev !== metadata.dev ||
      afterHash.ino !== metadata.ino ||
      afterHash.size !== metadata.size ||
      afterHash.mtimeMs !== metadata.mtimeMs ||
      afterHash.ctimeMs !== metadata.ctimeMs
    ) {
      throw new Error(`Backup payload changed while it was inventoried: ${path}`);
    }
    entries.push({
      path: resolve(path),
      bytes: Number(metadata.size),
      device: metadata.dev.toString(),
      inode: metadata.ino.toString(),
      modifiedMs: Number(metadata.mtimeMs),
      changedMs: Number(metadata.ctimeMs),
      sha256,
    });
  };
  for (const root of canonicalRoots) {
    let rootMetadata: ReturnType<typeof lstatSync>;
    try {
      rootMetadata = lstatSync(root);
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        error.code === "ENOENT"
      ) continue;
      throw error;
    }
    if (
      rootMetadata.isSymbolicLink() ||
      (rootMetadata.isDirectory() && realpathSync(root) !== root)
    ) {
      throw new Error(
        `Configured no-backup payload root must not be a symbolic link: ${root}`,
      );
    }
    visit(root, root);
  }
  entries.sort((left, right) => left.path.localeCompare(right.path, "en"));
  const inventorySha256 = createHash("sha256").update(inventoryRecord(entries)).digest("hex");
  return Object.freeze({
    schemaVersion: "ti-scale.backup-payload-inventory.v1",
    roots: Object.freeze(canonicalRoots),
    entries: Object.freeze(entries),
    inventorySha256,
  });
}

export function assertNoBackupPayloadInventoryUnchanged(
  before: NoBackupPayloadInventory,
  after: NoBackupPayloadInventory,
): void {
  if (
    before.schemaVersion !== after.schemaVersion ||
    JSON.stringify(before.roots) !== JSON.stringify(after.roots) ||
    before.inventorySha256 !== after.inventorySha256 ||
    inventoryRecord(before.entries) !== inventoryRecord(after.entries)
  ) {
    throw new Error("No-backup forward deployment created or changed a backup payload");
  }
}

export function assertNoBackupPayloadInventoryEmpty(
  inventory: NoBackupPayloadInventory,
): void {
  const emptyInventorySha256 = createHash("sha256")
    .update(inventoryRecord([]))
    .digest("hex");
  if (
    inventory.schemaVersion !== "ti-scale.backup-payload-inventory.v1" ||
    inventory.entries.length !== 0 ||
    inventory.inventorySha256 !== emptyInventorySha256
  ) {
    throw new Error(
      "No-backup forward preflight requires every configured backup payload root to be empty",
    );
  }
}

export function noBackupRecoveryDirection(
  sourceSchema: number,
  targetSchema: number,
  observedSchema: number,
  forwardSchemas?: readonly number[],
  sameSchemaTargetCommitted?: boolean,
): NoBackupRecoveryDirection {
  return classifyNoBackupForwardOnlyRecovery(
    sourceSchema,
    targetSchema,
    observedSchema,
    forwardSchemas,
    sameSchemaTargetCommitted,
  );
}

function attestedNoBackupForwardSchemas(
  attestation: ReleaseMigrationAttestation,
  sourceSchema: number,
  targetSchema: number,
): readonly number[] {
  const forwardSchemas = attestation.migrations
    .map((migration) => migration.version)
    .filter((version) =>
      version > sourceSchema && version <= targetSchema
    );
  assertNoBackupForwardOnlySchemaProgression(
    sourceSchema,
    targetSchema,
    forwardSchemas,
  );
  return forwardSchemas;
}

export function parseNoBackupPreviewArguments(
  argv: readonly string[],
): NoBackupPreviewArguments {
  const [commandName, ...rest] = argv;
  if (commandName !== "deploy" && commandName !== "recover") {
    throw new Error("No-backup forward command must be deploy or recover");
  }
  const flags = new Set<string>();
  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (token === "--execute" || token === NO_BACKUP_PREVIEW_ACKNOWLEDGEMENT_FLAG) {
      if (flags.has(token)) throw new Error(`Duplicate flag: ${token}`);
      flags.add(token);
      continue;
    }
    if (token !== "--release-id" && token !== "--confirm") {
      throw new Error(`Unsupported no-backup forward option: ${token}`);
    }
    if (values.has(token)) throw new Error(`Duplicate option: ${token}`);
    const value = rest[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`${token} requires a value`);
    values.set(token, value);
    index += 1;
  }
  if (!flags.has("--execute")) {
    throw new Error("No-backup forward deployment requires --execute");
  }
  if (!flags.has(NO_BACKUP_PREVIEW_ACKNOWLEDGEMENT_FLAG)) {
    throw new Error(
      `No-backup forward deployment requires ${NO_BACKUP_PREVIEW_ACKNOWLEDGEMENT_FLAG}`,
    );
  }
  const releaseId = values.get("--release-id")?.trim() ?? "";
  const confirmation = values.get("--confirm")?.trim() ?? "";
  if (!RELEASE_ID.test(releaseId)) throw new Error("A safe --release-id is required");
  if (confirmation !== releaseId) {
    throw new Error("--confirm must exactly match --release-id");
  }
  return {
    command: commandName,
    releaseId,
    confirmation,
    execute: true,
    noBackupRiskAcknowledged: true,
  };
}

export function mutationState(
  journal: FunctionalReleaseTransactionJournal,
  mutation: string,
): "unseen" | "prepared" | "completed" {
  const records = journal.records.filter((record) =>
    record.direction === "forward" && record.mutation === mutation);
  if (records.some((record) => record.event === "mutation_completed")) return "completed";
  if (records.some((record) => record.event === "mutation_prepared")) return "prepared";
  return "unseen";
}

interface CompletedNoBackupReceiptCommit {
  readonly direction: FunctionalReleaseTransactionDirection;
  readonly receiptSha256: string;
  readonly observerProofSha256: string;
}

function noBackupReceiptPreparedRecords(
  journal: FunctionalReleaseTransactionJournal,
  mutation:
    | "deployment_receipt_commit"
    | "deployment_receipt_restore"
    | "terminal_receipt_commit",
): ReadonlyArray<FunctionalReleaseTransactionJournal["records"][number]> {
  return journal.records.filter((record) =>
    record.event === "mutation_prepared" &&
    record.mutation === mutation &&
    (record.direction === "forward" || record.direction === "recovery")
  );
}

interface PreparedNoBackupReceiptIntent {
  readonly receipt: NoBackupPreviewReceipt;
  readonly receiptSha256: string;
  readonly observerProofSha256: string;
}

function noBackupReceiptBytes(receipt: NoBackupPreviewReceipt): string {
  const canonicalReceipt = JSON.parse(
    canonicalReleaseTransactionJson(receipt),
  ) as NoBackupPreviewReceipt;
  return `${JSON.stringify(canonicalReceipt, null, 2)}\n`;
}

function noBackupReceiptValueSha256(receipt: NoBackupPreviewReceipt): string {
  return createHash("sha256").update(noBackupReceiptBytes(receipt)).digest("hex");
}

function writeNoBackupReceiptIntent(
  path: string,
  receipt: NoBackupPreviewReceipt,
): void {
  writeDurableFileAtomically(path, noBackupReceiptBytes(receipt), {
    mode: 0o600,
  });
}

function preparedNoBackupReceiptIntent(
  journal: FunctionalReleaseTransactionJournal,
  mutation: "deployment_receipt_commit" | "terminal_receipt_commit",
): PreparedNoBackupReceiptIntent | undefined {
  const prepared = noBackupReceiptPreparedRecords(journal, mutation);
  if (prepared.length === 0) return undefined;
  const intents = prepared.map((record) => {
    const receiptPath = record.detail?.receiptPath;
    const receiptSha256 = record.detail?.receiptSha256;
    const receipt = record.detail?.receipt;
    if (
      receiptPath !== journal.binding.receiptPath ||
      typeof receiptSha256 !== "string" ||
      !/^[a-f0-9]{64}$/u.test(receiptSha256) ||
      !receipt ||
      typeof receipt !== "object" ||
      Array.isArray(receipt)
    ) {
      throw new Error(
        "Prepared no-backup receipt commitment lacks its exact intended receipt",
      );
    }
    const typedReceipt = receipt as unknown as NoBackupPreviewReceipt;
    const observerProofSha256 = noBackupObserverProofSha256FromDetail(
      record.detail,
      typedReceipt,
    );
    if (
      noBackupReceiptValueSha256(typedReceipt) !== receiptSha256 ||
      typeof observerProofSha256 !== "string" ||
      !/^[a-f0-9]{64}$/u.test(observerProofSha256) ||
      releaseTransactionSha256(
        receiptObserverProof(typedReceipt, "after"),
      ) !== observerProofSha256
    ) {
      throw new Error(
        "Prepared no-backup receipt commitment has a corrupt intended receipt",
      );
    }
    return {
      receipt: typedReceipt,
      receiptSha256,
      observerProofSha256,
    };
  });
  const first = intents[0]!;
  if (
    intents.some((candidate) =>
      candidate.receiptSha256 !== first.receiptSha256 ||
      candidate.observerProofSha256 !== first.observerProofSha256
    )
  ) {
    throw new Error(
      "Prepared no-backup receipt commitments disagree about the intended receipt",
    );
  }
  return first;
}

function completedNoBackupReceiptMutation(
  journal: FunctionalReleaseTransactionJournal,
  mutation: "deployment_receipt_commit" | "terminal_receipt_commit",
): CompletedNoBackupReceiptCommit | undefined {
  const completed = journal.records.filter((record) =>
    record.event === "mutation_completed" &&
    record.mutation === mutation &&
    (record.direction === "forward" || record.direction === "recovery")
  );
  if (completed.length === 0) return undefined;
  const parsed = completed.map((record) => {
    const receiptSha256 = record.detail?.receiptSha256;
    const receiptPath = record.detail?.receiptPath;
    const preparation = journal.records.filter((candidate) =>
      candidate.event === "mutation_prepared" &&
      candidate.direction === record.direction &&
      candidate.mutation === mutation &&
      candidate.sequence < record.sequence
    );
    const preparedReceipt = preparation[0]?.detail?.receipt;
    if (
      typeof receiptSha256 !== "string" ||
      !/^[a-f0-9]{64}$/u.test(receiptSha256) ||
      receiptPath !== journal.binding.receiptPath ||
      preparation.length !== 1 ||
      preparation[0]?.detail?.receiptPath !== journal.binding.receiptPath ||
      preparation[0]?.detail?.receiptSha256 !== receiptSha256 ||
      !preparedReceipt ||
      typeof preparedReceipt !== "object" ||
      Array.isArray(preparedReceipt) ||
      (record.direction !== "forward" && record.direction !== "recovery")
    ) {
      throw new Error(
        "Completed no-backup deployment receipt lacks its immutable receipt and observer proof",
      );
    }
    const typedReceipt = preparedReceipt as unknown as NoBackupPreviewReceipt;
    const observerProofSha256 = noBackupObserverProofSha256FromDetail(
      record.detail,
      typedReceipt,
    );
    if (
      typeof observerProofSha256 !== "string" ||
      !/^[a-f0-9]{64}$/u.test(observerProofSha256) ||
      noBackupObserverProofSha256FromDetail(
        preparation[0]?.detail,
        typedReceipt,
      ) !== observerProofSha256
    ) {
      throw new Error(
        "Completed no-backup deployment receipt lacks its immutable observer proof",
      );
    }
    return {
      direction: record.direction,
      receiptSha256,
      observerProofSha256,
    } as const;
  });
  const first = parsed[0]!;
  if (
    parsed.some((candidate) =>
      candidate.receiptSha256 !== first.receiptSha256 ||
      candidate.observerProofSha256 !== first.observerProofSha256
    )
  ) {
    throw new Error(
      "No-backup deployment receipt has conflicting durable commitments",
    );
  }
  return first;
}

interface CompletedNoBackupReceiptRestore {
  readonly receiptSha256: string;
  readonly observerProofSha256: string;
}

function preparedNoBackupReceiptRestore(
  journal: FunctionalReleaseTransactionJournal,
): CompletedNoBackupReceiptRestore | undefined {
  const prepared = noBackupReceiptPreparedRecords(
    journal,
    "deployment_receipt_restore",
  ).filter((record) => record.direction === "recovery");
  if (prepared.length === 0) return undefined;
  if (prepared.length !== 1) {
    throw new Error(
      "No-backup source receipt restoration has conflicting prepared intents",
    );
  }
  const record = prepared[0]!;
  const receiptSha256 = record.detail?.receiptSha256;
  const receipt = JSON.parse(
    readFileSync(journal.binding.receiptPath, "utf8"),
  ) as NoBackupPreviewReceipt;
  const observerProofSha256 = noBackupObserverProofSha256FromDetail(
    record.detail,
    receipt,
  );
  if (
    record.detail?.receiptPath !== journal.binding.receiptPath ||
    typeof receiptSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(receiptSha256) ||
    typeof observerProofSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(observerProofSha256)
  ) {
    throw new Error(
      "Prepared no-backup source receipt restoration lacks its exact receipt and observer proof",
    );
  }
  return { receiptSha256, observerProofSha256 };
}

function completedNoBackupReceiptRestore(
  journal: FunctionalReleaseTransactionJournal,
): CompletedNoBackupReceiptRestore | undefined {
  const completed = journal.records.filter((record) =>
    record.event === "mutation_completed" &&
    record.direction === "recovery" &&
    record.mutation === "deployment_receipt_restore"
  );
  if (completed.length === 0) return undefined;
  if (completed.length !== 1) {
    throw new Error(
      "No-backup source receipt restoration has conflicting durable commitments",
    );
  }
  const record = completed[0]!;
  const preparation = journal.records.filter((candidate) =>
    candidate.event === "mutation_prepared" &&
    candidate.direction === "recovery" &&
    candidate.mutation === "deployment_receipt_restore" &&
    candidate.sequence < record.sequence
  );
  const receiptSha256 = record.detail?.receiptSha256;
  const receipt = JSON.parse(
    readFileSync(journal.binding.receiptPath, "utf8"),
  ) as NoBackupPreviewReceipt;
  const observerProofSha256 = noBackupObserverProofSha256FromDetail(
    record.detail,
    receipt,
  );
  if (
    preparation.length !== 1 ||
    preparation[0]?.detail?.receiptPath !== journal.binding.receiptPath ||
    preparation[0]?.detail?.receiptSha256 !== receiptSha256 ||
    noBackupObserverProofSha256FromDetail(
      preparation[0]?.detail,
      receipt,
    ) !== observerProofSha256 ||
    record.detail?.receiptPath !== journal.binding.receiptPath ||
    typeof receiptSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(receiptSha256) ||
    typeof observerProofSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(observerProofSha256)
  ) {
    throw new Error(
      "Completed no-backup source receipt restoration lacks its exact receipt and observer proof",
    );
  }
  return { receiptSha256, observerProofSha256 };
}

function completedNoBackupReceiptCommit(
  journal: FunctionalReleaseTransactionJournal,
): CompletedNoBackupReceiptCommit | undefined {
  return completedNoBackupReceiptMutation(
    journal,
    "deployment_receipt_commit",
  );
}

function completedNoBackupSourceReceiptCommit(
  journal: FunctionalReleaseTransactionJournal,
): CompletedNoBackupReceiptCommit | undefined {
  const commitment = completedNoBackupReceiptMutation(
    journal,
    "terminal_receipt_commit",
  );
  if (commitment?.direction === "forward") {
    throw new Error(
      "Source recovery terminal receipt was committed in the wrong direction",
    );
  }
  return commitment;
}

function receiptFileSha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function assertCompletedNoBackupReceiptCommit(
  prepared: PreparedNoBackupPreview,
  commitment: CompletedNoBackupReceiptCommit,
): NoBackupPreviewReceipt {
  const actualSha256 = receiptFileSha256(prepared.receiptPath);
  if (actualSha256 !== commitment.receiptSha256) {
    throw new Error(
      "Durably committed no-backup receipt changed before terminal reconciliation",
    );
  }
  const receipt = JSON.parse(
    readFileSync(prepared.receiptPath, "utf8"),
  ) as NoBackupPreviewReceipt;
  if (
    releaseTransactionSha256(
      receiptObserverProof(receipt, "after"),
    ) !== commitment.observerProofSha256
  ) {
    throw new Error(
      "Durably committed no-backup receipt no longer contains its exact observer proof",
    );
  }
  return receipt;
}

function receiptIntentForCommit(
  prepared: PreparedNoBackupPreview,
  journal: FunctionalReleaseTransactionJournal,
  mutation: "deployment_receipt_commit" | "terminal_receipt_commit",
  currentObserverProof: NoBackupReleaseObserverProof,
): PreparedNoBackupReceiptIntent {
  const preparedIntent = preparedNoBackupReceiptIntent(
    journal,
    mutation,
  );
  if (preparedIntent) {
    return preparedIntent;
  }
  const receipt = JSON.parse(JSON.stringify(
    isStandaloneNoBackupForwardReceipt(prepared.receipt)
      ? prepared.receipt
      : {
        ...prepared.receipt,
        chillspwnAfter: currentObserverProof,
      },
  )) as NoBackupPreviewReceipt;
  const observerProofSha256 =
    releaseTransactionSha256(currentObserverProof);
  if (
    releaseTransactionSha256(
      receiptObserverProof(receipt, "after"),
    ) !== observerProofSha256
  ) {
    throw new Error(
      "No-backup receipt observer proof differs from its deployment mode",
    );
  }
  return {
    receipt,
    receiptSha256: noBackupReceiptValueSha256(receipt),
    observerProofSha256,
  };
}

function assertNoBackupSourceReceiptRestoreCommit(
  prepared: PreparedNoBackupPreview,
  journal: FunctionalReleaseTransactionJournal,
): CompletedNoBackupReceiptRestore | undefined {
  const commitment = completedNoBackupReceiptRestore(journal);
  if (!commitment) return undefined;
  const terminalReceiptState = recoveryMutationState(
    journal,
    "terminal_receipt_commit",
  );
  if (
    terminalReceiptState === "unseen" &&
    receiptFileSha256(prepared.receiptPath) !== commitment.receiptSha256
  ) {
    throw new Error(
      "Durably restored no-backup source receipt changed before terminal receipt preparation",
    );
  }
  return commitment;
}

function ensureNoBackupSourceReceiptRestoreCommit(
  prepared: PreparedNoBackupPreview,
  observerProof: NoBackupReleaseObserverProof,
): CompletedNoBackupReceiptRestore {
  let journal = readFunctionalReleaseTransactionJournal(
    prepared.journalDirectory,
  );
  const existing = assertNoBackupSourceReceiptRestoreCommit(prepared, journal);
  if (existing) return existing;
  let preparedIntent = preparedNoBackupReceiptRestore(journal);
  let state = recoveryMutationState(
    journal,
    "deployment_receipt_restore",
  );
  if (state === "unseen") {
    preparedIntent = {
      receiptSha256: receiptFileSha256(prepared.receiptPath),
      observerProofSha256: releaseTransactionSha256(observerProof),
    };
    prepareFunctionalReleaseMutation(
      prepared.journalDirectory,
      "recovery",
      "deployment_receipt_restore",
      {
        receiptPath: prepared.receiptPath,
        receiptSha256: preparedIntent.receiptSha256,
        ...noBackupObserverProofDetail(
          prepared.receipt,
          preparedIntent.observerProofSha256,
        ),
        backupPolicy: "none",
      },
    );
    state = "prepared";
  }
  if (state === "prepared") {
    journal = readFunctionalReleaseTransactionJournal(
      prepared.journalDirectory,
    );
    preparedIntent = preparedNoBackupReceiptRestore(journal);
    if (
      !preparedIntent ||
      receiptFileSha256(prepared.receiptPath) !==
        preparedIntent.receiptSha256
    ) {
      throw new Error(
        "Prepared no-backup source receipt restoration cannot replay its exact receipt bytes",
      );
    }
    completeFunctionalReleaseMutation(
      prepared.journalDirectory,
      "recovery",
      "deployment_receipt_restore",
      {
        outcome: "already_exact",
        receiptPath: prepared.receiptPath,
        receiptSha256: preparedIntent.receiptSha256,
        ...noBackupObserverProofDetail(
          prepared.receipt,
          preparedIntent.observerProofSha256,
        ),
        backupPolicy: "none",
      },
    );
  }
  journal = readFunctionalReleaseTransactionJournal(
    prepared.journalDirectory,
  );
  const committed = assertNoBackupSourceReceiptRestoreCommit(
    prepared,
    journal,
  );
  if (!committed) {
    throw new Error(
      "Source recovery requires a durable restored-receipt commitment",
    );
  }
  return committed;
}

/**
 * The service-start boundary is deliberately outside the maintenance-lease
 * callback. A successful callback return proves that the lease release path
 * has run before systemd is allowed to start the target runtime.
 */
export async function executeNoBackupPreviewPhaseSequence(
  operations: NoBackupPreviewPhaseOperations,
): Promise<void> {
  await executeNoBackupForwardOnlyPhaseSequence({
    ...operations,
    startAndFinalize: () => operations.startAndFinalize(),
  });
}

function ensureMutation(
  journalDirectory: string,
  mutation: string,
  apply: () => void,
  detail: () => Readonly<Record<string, unknown>> = () => ({ outcome: "exact" }),
): void {
  let journal = readFunctionalReleaseTransactionJournal(journalDirectory);
  let state = mutationState(journal, mutation);
  if (state === "unseen") {
    journal = prepareFunctionalReleaseMutation(
      journalDirectory,
      "forward",
      mutation,
      { backupPolicy: "none" },
    );
    state = mutationState(journal, mutation);
  }
  if (state !== "prepared") return;
  apply();
  completeFunctionalReleaseMutation(
    journalDirectory,
    "forward",
    mutation,
    detail(),
  );
}

function writeReceipt(path: string, receipt: NoBackupPreviewReceipt): void {
  writeDurableFileAtomically(path, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
}

function assertNoIncompleteTransaction(): void {
  const incomplete = discoverIncompleteFunctionalReleaseTransactions(TRANSACTION_ROOT);
  if (incomplete.length) {
    throw new Error(
      `No-backup forward deployment is blocked by nonterminal release ${incomplete[0]!.releaseId}`,
    );
  }
}

async function assertStartAdmissionInstalled(): Promise<void> {
  assertReleaseServiceStartAdmissionInstallationCommitted({
    transactionRoot: TRANSACTION_ROOT,
  });
  const show = (property: string): string => command([
    "/usr/bin/systemctl",
    "show",
    SERVICE,
    `--property=${property}`,
    "--value",
  ]);
  if (!serviceStartAdmissionConfigured(show("ExecStartPre"), show("ExecStartPreEx"))) {
    throw new Error("No-backup forward deployment requires the exact release-start admission gate");
  }
  if (!serviceWrapperConfigured(show("ExecStart"), show("ExecStartEx"))) {
    throw new Error("No-backup forward deployment requires the exact stable service wrapper");
  }
  if (!serviceStartAdmissionMountConfigured(show("RequiresMountsFor"))) {
    throw new Error("No-backup forward deployment requires the release transaction mount");
  }
  if (!serviceWrapperIdentityConfigured(
    show("User"),
    show("Group"),
    show("WorkingDirectory"),
    show("DynamicUser"),
  )) {
    throw new Error("No-backup forward deployment requires the dedicated Ti-Scale service identity");
  }
  await attestInstalledReleaseServiceStartAdmission({ sourceRoot: resolve(import.meta.dir, "../..") });
  const helper = command([
    RELEASE_SERVICE_START_ADMISSION_BUN_PATH,
    "run",
    RELEASE_SERVICE_START_ADMISSION_HELPER_PATH,
    "--self-report",
  ]);
  if (!releaseServiceStartAdmissionSelfReportMatches(helper)) {
    throw new Error("Installed release-start helper protocol does not match reviewed source");
  }
  const wrapper = command([
    RELEASE_SERVICE_START_ADMISSION_BUN_PATH,
    "run",
    RELEASE_SERVICE_WRAPPER_PATH,
    "--self-report",
  ]);
  if (!releaseServiceWrapperSelfReportMatches(wrapper)) {
    throw new Error("Installed service-wrapper protocol does not match reviewed source");
  }
}

function createMetadataDirectory(path: string): void {
  mkdirSync(path, { mode: 0o700 });
  const metadata = lstatSync(path);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== 0 ||
    metadata.gid !== 0 ||
    (metadata.mode & 0o777) !== 0o700
  ) {
    throw new Error("No-backup forward metadata directory is not root-owned mode 0700");
  }
  const descriptor = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function prepareNoBackupPreview(
  releaseId: string,
  tiScaleBefore: ServiceIdentity,
  inventoryBefore: NoBackupPayloadInventory,
  candidateBinding?: NoBackupStagedCandidateBinding,
): Promise<PreparedNoBackupPreview> {
  return (async () => {
    assertNoBackupPayloadInventoryEmpty(inventoryBefore);
    const sourceAttestation = attestReleaseMigrationCeiling(resolve(import.meta.dir, "../.."));
    const serverDirectory = join(SERVER_RELEASE_ROOT, "releases", releaseId);
    const server = await verifyServerRelease(serverDirectory, releaseId);
    const stagedAttestation = attestReleaseMigrationCeiling(server.releaseDirectory);
    const migrationAttestation = assertReleaseMigrationAttestationsMatch(
      sourceAttestation,
      stagedAttestation,
      "No-backup forward staged migration attestation",
    );
    if (
      migrationAttestation.targetSchema !== TARGET_SCHEMA ||
      databaseSchema() !== SOURCE_SCHEMA
    ) {
      throw new Error(
        `No-backup forward deployment is bound to schema ${SOURCE_SCHEMA}→${TARGET_SCHEMA}`,
      );
    }
    attestedNoBackupForwardSchemas(
      migrationAttestation,
      SOURCE_SCHEMA,
      TARGET_SCHEMA,
    );
    const staticStore = new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT });
    const staticRelease = staticStore.verifyRelease(releaseId);
    if (candidateBinding) {
      if (
        candidateBinding.schemaVersion !==
          "ti-scale.no-backup-candidate-staging-binding.v1" ||
        candidateBinding.releaseId !== releaseId ||
        !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u.test(
          candidateBinding.sourceCommit,
        ) ||
        !/^[a-f0-9]{64}$/u.test(candidateBinding.sourceTreeSha256) ||
        !/^[a-f0-9]{64}$/u.test(
          candidateBinding.staticArtifactSha256,
        ) ||
        resolve(candidateBinding.serverRelease.path) !==
          resolve(server.releaseDirectory) ||
        candidateBinding.serverRelease.manifestSha256 !==
          server.manifestSha256 ||
        candidateBinding.serverRelease.treeSha256 !==
          server.manifest.treeSha256 ||
        candidateBinding.sourceTreeSha256 !==
          server.manifest.treeSha256 ||
        resolve(candidateBinding.staticRelease.path) !==
          resolve(staticRelease.releaseDirectory) ||
        candidateBinding.staticRelease.manifestSha256 !==
          staticRelease.manifestSha256 ||
        candidateBinding.staticRelease.artifactSha256 !==
          staticRelease.manifest.artifactSha256 ||
        candidateBinding.staticArtifactSha256 !==
          staticRelease.manifest.artifactSha256
      ) {
        throw new Error(
          "No-backup forward candidate differs from its clean-source staging binding",
        );
      }
    }
    const previousStaticPointer = staticStore.readActivePointer();
    const previousApplicationTarget = applicationTarget();
    const targetApplicationTarget = realpathSync(server.releaseDirectory);
    const metadataRoot = join(TRANSACTION_ROOT, releaseId);
    if (existsSync(metadataRoot)) {
      throw new Error(`No-backup forward metadata already exists for ${releaseId}`);
    }
    const stagingMetadataRoot = join(
      TRANSACTION_ROOT,
      `.${releaseId}.${process.pid}.${randomUUID()}.opening`,
    );
    createMetadataDirectory(stagingMetadataRoot);
    const receiptPath = join(metadataRoot, "no-backup-preview-receipt.json");
    const journalDirectory = join(metadataRoot, "transaction-journal");
    const stagingReceiptPath = join(
      stagingMetadataRoot,
      "no-backup-preview-receipt.json",
    );
    const stagingJournalDirectory = join(
      stagingMetadataRoot,
      "transaction-journal",
    );
    const receipt: NoBackupPreviewReceipt = {
      schemaVersion: NO_BACKUP_FORWARD_RECEIPT_SCHEMA,
      releaseId,
      createdAt: new Date().toISOString(),
      hostBootId: currentHostBootId(),
      status: "prepared",
      backupPolicy: NO_BACKUP_PREVIEW_BACKUP_POLICY,
      deploymentMode: NO_BACKUP_CURRENT_DEPLOYMENT_MODE,
      releaseObserver: NO_BACKUP_STANDALONE_RELEASE_OBSERVER,
      rollbackCapability: NO_BACKUP_PREVIEW_ROLLBACK_CAPABILITY,
      operatorAcknowledgement: "no_backup_and_no_downgrade",
      serverRelease: {
        path: server.releaseDirectory,
        manifestSha256: server.manifestSha256,
        treeSha256: server.manifest.treeSha256,
      },
      staticRelease: {
        path: staticRelease.releaseDirectory,
        manifestSha256: staticRelease.manifestSha256,
      },
      ...(candidateBinding
        ? {
          candidateStaging: {
            schemaVersion: candidateBinding.schemaVersion,
            sourceCommit: candidateBinding.sourceCommit,
            sourceTreeSha256: candidateBinding.sourceTreeSha256,
            staticArtifactSha256:
              candidateBinding.staticArtifactSha256,
          },
        }
        : {}),
      database: {
        sourceSchema: SOURCE_SCHEMA,
        targetSchema: TARGET_SCHEMA,
        migrationAttestation,
      },
      previous: {
        applicationTarget: previousApplicationTarget,
        staticReleaseId: previousStaticPointer.activeReleaseId,
        staticManifestSha256: previousStaticPointer.activeManifestSha256,
      },
      target: {
        applicationTarget: targetApplicationTarget,
        staticReleaseId: releaseId,
        staticManifestSha256: staticRelease.manifestSha256,
      },
      backupPayloadInventoryBefore: inventoryBefore,
      tiScaleBefore,
    };
    writeReceipt(stagingReceiptPath, receipt);
    createFunctionalReleaseTransactionJournal({
      directory: stagingJournalDirectory,
      operation: "deploy",
      releaseId,
      receiptPath,
      recoveryIntent: "restore_predeploy",
      identity: {
        deploymentKind: "no_backup_forward_v2",
        deploymentMode: NO_BACKUP_CURRENT_DEPLOYMENT_MODE,
        releaseStartupProtocol: RELEASE_SOURCE_RUNTIME_PROTOCOL,
        targetRuntimeCommitProtocol: RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL,
        requireRunningStateVerification: true,
        hostBootId: receipt.hostBootId,
        releaseObserver: receipt.releaseObserver,
        backupPayloadInventoryBefore: {
          roots: receipt.backupPayloadInventoryBefore.roots,
          inventorySha256: receipt.backupPayloadInventoryBefore.inventorySha256,
        },
        backupPolicy: "none",
        rollbackCapability: NO_BACKUP_PREVIEW_ROLLBACK_CAPABILITY,
        ...(receipt.candidateStaging
          ? { candidateStaging: receipt.candidateStaging }
          : {}),
        predeploy: {
          pointers: receipt.previous,
          databaseSchema: SOURCE_SCHEMA,
          serviceIntent: "active",
          previousInvocationId: tiScaleBefore.invocationId,
        },
        target: {
          pointers: receipt.target,
          databaseSchema: TARGET_SCHEMA,
          migrationAttestation,
        },
      },
    });
    renameDirectoryDurably(stagingMetadataRoot, metadataRoot);
    return {
      receipt,
      receiptPath,
      journalDirectory,
      server,
      staticRelease,
    };
  })();
}

async function loadPreparedNoBackupPreview(
  releaseId: string,
): Promise<PreparedNoBackupPreview> {
  const metadataRoot = join(TRANSACTION_ROOT, releaseId);
  const receiptPath = join(metadataRoot, "no-backup-preview-receipt.json");
  const journalDirectory = join(metadataRoot, "transaction-journal");
  if (!existsSync(receiptPath) || !existsSync(journalDirectory)) {
    throw new Error(`No recoverable no-backup release metadata exists for ${releaseId}`);
  }
  const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as NoBackupPreviewReceipt;
  const receiptObserverShapeValid =
    isStandaloneNoBackupForwardReceipt(receipt) ||
    isLegacyNoBackupPreviewReceipt(receipt);
  const expectedSourceSchema =
    receipt.schemaVersion === NO_BACKUP_FORWARD_RECEIPT_SCHEMA
      ? NO_BACKUP_SOURCE_SCHEMA
      : NO_BACKUP_HISTORICAL_SOURCE_SCHEMA;
  if (
    !receiptObserverShapeValid ||
    receipt.releaseId !== releaseId ||
    receipt.backupPolicy !== "none" ||
    receipt.rollbackCapability !== NO_BACKUP_PREVIEW_ROLLBACK_CAPABILITY ||
    receipt.operatorAcknowledgement !== "no_backup_and_no_downgrade" ||
    typeof receipt.hostBootId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      receipt.hostBootId,
    ) ||
    receipt.database?.sourceSchema !== expectedSourceSchema ||
    receipt.database?.targetSchema !== TARGET_SCHEMA ||
    !receipt.serverRelease ||
    !receipt.staticRelease ||
    !receipt.previous ||
    !receipt.target ||
    !receipt.backupPayloadInventoryBefore
  ) {
    throw new Error("No-backup forward recovery receipt is malformed or policy-incompatible");
  }
  if (
    JSON.stringify(receipt.backupPayloadInventoryBefore.roots) !==
      JSON.stringify([...NO_BACKUP_PAYLOAD_ROOTS].sort((left, right) =>
        left.localeCompare(right, "en")))
  ) {
    throw new Error("No-backup forward recovery receipt lacks the complete payload inventory roots");
  }
  assertNoBackupPayloadInventoryEmpty(
    receipt.backupPayloadInventoryBefore,
  );
  if (
    receipt.candidateStaging !== undefined &&
    (
      receipt.candidateStaging.schemaVersion !==
        "ti-scale.no-backup-candidate-staging-binding.v1" ||
      !/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/u.test(
        receipt.candidateStaging.sourceCommit,
      ) ||
      !/^[a-f0-9]{64}$/u.test(
        receipt.candidateStaging.sourceTreeSha256,
      ) ||
      !/^[a-f0-9]{64}$/u.test(
        receipt.candidateStaging.staticArtifactSha256,
      ) ||
      receipt.candidateStaging.sourceTreeSha256 !==
        receipt.serverRelease.treeSha256
    )
  ) {
    throw new Error(
      "No-backup forward recovery candidate staging binding is malformed",
    );
  }
  const journal = readFunctionalReleaseTransactionJournal(journalDirectory);
  const identity = journal.binding.identity as Record<string, unknown>;
  const observerIdentityMatches = isStandaloneNoBackupForwardReceipt(receipt)
    ? (
      identity.deploymentKind === "no_backup_forward_v2" &&
      identity.deploymentMode === NO_BACKUP_CURRENT_DEPLOYMENT_MODE &&
      releaseTransactionSha256(identity.releaseObserver) ===
        releaseTransactionSha256(receipt.releaseObserver)
    )
    : (
      identity.deploymentKind === "no_backup_preview_v1" &&
      releaseTransactionSha256(identity.chillspwnBefore) ===
        releaseTransactionSha256(receipt.chillspwnBefore)
    );
  if (
    journal.binding.operation !== "deploy" ||
    journal.binding.releaseId !== releaseId ||
    journal.binding.receiptPath !== receiptPath ||
    journal.terminal ||
    !observerIdentityMatches ||
    identity.backupPolicy !== "none" ||
    identity.rollbackCapability !== NO_BACKUP_PREVIEW_ROLLBACK_CAPABILITY ||
    identity.releaseStartupProtocol !== RELEASE_SOURCE_RUNTIME_PROTOCOL ||
    identity.targetRuntimeCommitProtocol !== RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL ||
    identity.requireRunningStateVerification !== true ||
    identity.hostBootId !== receipt.hostBootId ||
    releaseTransactionSha256(identity.backupPayloadInventoryBefore) !==
      releaseTransactionSha256({
        roots: receipt.backupPayloadInventoryBefore.roots,
        inventorySha256: receipt.backupPayloadInventoryBefore.inventorySha256,
      }) ||
    (
      (
        identity.candidateStaging !== undefined ||
        receipt.candidateStaging !== undefined
      ) &&
      releaseTransactionSha256(
        identity.candidateStaging ?? null,
      ) !==
        releaseTransactionSha256(receipt.candidateStaging ?? null)
    ) ||
    releaseTransactionSha256(identity.predeploy) !== releaseTransactionSha256({
      pointers: receipt.previous,
      databaseSchema: receipt.database.sourceSchema,
      serviceIntent: "active",
      previousInvocationId: receipt.tiScaleBefore.invocationId,
    }) ||
    releaseTransactionSha256(identity.target) !== releaseTransactionSha256({
      pointers: receipt.target,
      databaseSchema: TARGET_SCHEMA,
      migrationAttestation: receipt.database.migrationAttestation,
    })
  ) {
    throw new Error("No-backup forward recovery journal does not match its immutable receipt");
  }
  const serverDirectory = join(SERVER_RELEASE_ROOT, "releases", releaseId);
  const staticDirectory = join(STATIC_RELEASE_ROOT, "releases", releaseId);
  if (
    resolve(receipt.serverRelease.path) !== serverDirectory ||
    resolve(receipt.target.applicationTarget) !== serverDirectory ||
    resolve(receipt.staticRelease.path) !== staticDirectory
  ) {
    throw new Error(
      "No-backup forward recovery candidate paths differ from their immutable release IDs",
    );
  }
  const cleanupState = recoveryMutationState(
    journal,
    "running_state_verification",
  );
  const cleanupPreparation = journal.records.find((record) =>
    record.event === "mutation_prepared" &&
    record.direction === "recovery" &&
    record.mutation === "running_state_verification"
  );
  const cleanupCompletion = journal.records.find((record) =>
    record.event === "mutation_completed" &&
    record.direction === "recovery" &&
    record.mutation === "running_state_verification"
  );
  const cleanupIdentityMatches =
    cleanupPreparation?.detail?.candidateCleanupProtocol ===
      "failed_pre_schema_candidate_cleanup_v1" &&
    releaseTransactionSha256(
      cleanupPreparation.detail.sourcePointers,
    ) === releaseTransactionSha256(receipt.previous) &&
    releaseTransactionSha256(
      cleanupPreparation.detail.candidatePointers,
    ) === releaseTransactionSha256(receipt.target) &&
    cleanupPreparation.detail.candidateServerManifestSha256 ===
      receipt.serverRelease.manifestSha256 &&
    cleanupPreparation.detail.candidateServerTreeSha256 ===
      receipt.serverRelease.treeSha256 &&
    cleanupPreparation.detail.candidateStaticManifestSha256 ===
      receipt.staticRelease.manifestSha256 &&
    (
      cleanupState !== "completed" ||
      cleanupCompletion?.detail?.candidateCleanupCompleted === true
    );
  const candidateMayBeMissing =
    cleanupState !== "unseen" &&
    cleanupIdentityMatches &&
    databaseSchema() === receipt.database.sourceSchema &&
    releaseSourceRuntimeCommitted(journal) &&
    completedNoBackupReceiptRestore(journal) !== null;

  let server: VerifiedServerRelease | undefined;
  if (pathEntryExists(serverDirectory)) {
    server = await verifyServerRelease(serverDirectory, releaseId);
    if (
      server.releaseDirectory !== receipt.serverRelease.path ||
      server.manifestSha256 !== receipt.serverRelease.manifestSha256 ||
      server.manifest.treeSha256 !== receipt.serverRelease.treeSha256 ||
      realpathSync(server.releaseDirectory) !== receipt.target.applicationTarget
    ) {
      throw new Error("No-backup forward recovery server release differs from its receipt");
    }
    assertReleaseMigrationAttestationsMatch(
      receipt.database.migrationAttestation,
      attestReleaseMigrationCeiling(server.releaseDirectory),
      "No-backup forward recovery migration attestation",
    );
  } else if (!candidateMayBeMissing) {
    throw new Error(
      "No-backup forward recovery candidate server release is missing without a durable cleanup boundary",
    );
  }

  let staticRelease: VerifiedStaticRelease | undefined;
  if (pathEntryExists(staticDirectory)) {
    staticRelease = new StaticArtifactReleaseStore({
      releaseRoot: STATIC_RELEASE_ROOT,
    }).verifyRelease(releaseId);
    if (
      staticRelease.releaseDirectory !== receipt.staticRelease.path ||
      staticRelease.manifestSha256 !== receipt.staticRelease.manifestSha256 ||
      staticRelease.manifestSha256 !== receipt.target.staticManifestSha256
    ) {
      throw new Error("No-backup forward recovery static release differs from its receipt");
    }
  } else if (!candidateMayBeMissing) {
    throw new Error(
      "No-backup forward recovery candidate static release is missing without a durable cleanup boundary",
    );
  }
  if (
    cleanupState === "completed" &&
    (server !== undefined || staticRelease !== undefined)
  ) {
    throw new Error(
      "Completed failed-candidate cleanup unexpectedly retained a candidate release",
    );
  }
  const currentInventory = captureNoBackupPayloadInventory(
    receipt.backupPayloadInventoryBefore.roots,
  );
  assertNoBackupPayloadInventoryEmpty(currentInventory);
  assertNoBackupPayloadInventoryUnchanged(
    receipt.backupPayloadInventoryBefore,
    currentInventory,
  );
  return {
    receipt,
    receiptPath,
    journalDirectory,
    server,
    staticRelease,
  };
}

function requirePreparedServer(
  prepared: PreparedNoBackupPreview,
  operation: string,
): VerifiedServerRelease {
  if (!prepared.server) {
    throw new Error(
      `${operation} requires the exact verified candidate server release`,
    );
  }
  return prepared.server;
}

function stopTiScaleAtJournalBoundary(prepared: PreparedNoBackupPreview): void {
  ensureMutation(prepared.journalDirectory, "service_stop", () => {
    const preStop = stopSnapshot();
    const stopped = stopServiceWithGuardedFailedUnitNormalization({
      captureIdentity: () => ({
        pointers: {
          application: {
            kind: "symlink",
            target: applicationTarget(),
            device: "symlink",
            inode: "symlink",
          },
          staticReleaseId: new StaticArtifactReleaseStore({
            releaseRoot: STATIC_RELEASE_ROOT,
          }).readActivePointer().activeReleaseId,
          staticManifestSha256: new StaticArtifactReleaseStore({
            releaseRoot: STATIC_RELEASE_ROOT,
          }).readActivePointer().activeManifestSha256,
        },
        databaseSchema: databaseSchema(),
      }),
      stop: () => {
        command(["/usr/bin/systemctl", "stop", SERVICE], { timeoutMs: 90_000 });
      },
      inspect: stopSnapshot,
      assertNoCanonicalDatabaseUsers,
      assertNoActiveWork,
      resetFailed: () => {
        command(["/usr/bin/systemctl", "reset-failed", SERVICE]);
      },
    });
    if (!serviceCanRestartUnchanged(stopped.snapshot) || stopped.snapshot.activeState !== "inactive") {
      throw new Error("Ti-Scale did not reach a clean stopped boundary");
    }
    assertNoCanonicalDatabaseUsers();
    const database = createDatabaseConnection({
      filename: DATABASE_PATH,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try {
      new StoppedServiceRuntimeLeaseReconciliationService(database).reconcile({
        actorId: `no-backup-preview:${process.pid}`,
        boundaryId: `no-backup-preview:${prepared.receipt.releaseId}:${Date.now()}`,
        preStop,
        stopped: stopped.snapshot,
      });
    } finally {
      database.close();
    }
    assertNoCanonicalDatabaseUsers();
  }, () => ({ outcome: "inactive_process_and_database_boundary_proven" }));
  prepared.receipt.status = "maintenance";
  writeReceipt(prepared.receiptPath, prepared.receipt);
}

function runNoBackupMigration(prepared: PreparedNoBackupPreview): void {
  const server = requirePreparedServer(
    prepared,
    "No-backup database migration",
  );
  ensureMutation(prepared.journalDirectory, "database_migration", () => {
    if (
      prepared.receipt.database.sourceSchema !==
        prepared.receipt.database.targetSchema
    ) {
      command([
        "/usr/sbin/runuser",
        "--user",
        "ti-scale",
        "--",
        BUN,
        "run",
        "server/db/cli.ts",
        "migrate",
        "--db",
        DATABASE_PATH,
        "--no-backup",
        "--acknowledge-no-backup-risk",
      ], {
        cwd: server.releaseDirectory,
        env: minimalEnvironment("/var/lib/ti-scale"),
        timeoutMs: 15 * 60_000,
      });
    }
    assertCanonicalDatabase(TARGET_SCHEMA, { verifyIntegrity: true });
    assertReleaseMigrationAttestationsMatch(
      prepared.receipt.database.migrationAttestation,
      attestReleaseMigrationCeiling(server.releaseDirectory),
      "No-backup forward post-migration attestation",
    );
    prepared.receipt.database.schemaCommittedAt = new Date().toISOString();
    writeReceipt(prepared.receiptPath, prepared.receipt);
  }, () => ({
    databaseSchema: TARGET_SCHEMA,
    backupPolicy: "none",
    migrationAttestationSha256:
      prepared.receipt.database.migrationAttestation.attestationSha256,
  }));
}

async function waitForTargetRuntime(
  prepared: PreparedNoBackupPreview,
  previousInvocationId: string,
  timeoutMs = 4 * 60_000,
): Promise<ServiceIdentity> {
  const deadline = performance.now() + timeoutMs;
  let last = "no observation";
  while (performance.now() < deadline) {
    try {
      const identity = await captureServiceIdentity(SERVICE, TI_SCALE_HEALTH);
      const readiness = await jsonHealth(TI_SCALE_READINESS);
      const database = readiness.body.database as Record<string, unknown> | undefined;
      last = `${identity.activeState}/${identity.semanticStatus}; readiness=${readiness.semanticStatus}`;
      if (
        identity.activeState === "active" &&
        identity.mainPid > 0 &&
        identity.invocationId &&
        identity.invocationId !== previousInvocationId &&
        identity.healthStatus === 200 &&
        identity.semanticStatus === "healthy" &&
        readiness.statusCode === 200 &&
        readiness.semanticStatus === "healthy" &&
        database?.healthy === true &&
        Number(database.currentMigration) === TARGET_SCHEMA
      ) {
        assertPointer(
          new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT }),
          prepared.receipt.target,
          "Running target",
        );
        assertCanonicalDatabase(TARGET_SCHEMA);
        return identity;
      }
    } catch (error) {
      last = safeJsonError(error);
    }
    await Bun.sleep(500);
  }
  throw new Error(`Ti-Scale target runtime did not become healthy: ${last}`);
}

export interface NoBackupTargetApplicationCommitIdentity {
  readonly releaseId: string;
  readonly applicationTarget: string;
  readonly serverReleasePath: string;
  readonly manifestSha256: string;
  readonly manifestTreeSha256: string;
}

export async function verifyNoBackupTargetApplicationForCommit(
  identity: NoBackupTargetApplicationCommitIdentity,
): Promise<string> {
  const applicationTarget = resolve(identity.applicationTarget);
  const serverReleasePath = resolve(identity.serverReleasePath);
  if (applicationTarget !== serverReleasePath) {
    throw new Error(
      "Target application path differs from its recorded server release",
    );
  }
  const verified = await verifyServerRelease(
    applicationTarget,
    identity.releaseId,
    identity.manifestSha256,
  );
  if (
    verified.releaseDirectory !== serverReleasePath ||
    verified.manifestSha256 !== identity.manifestSha256 ||
    verified.manifest.treeSha256 !== identity.manifestTreeSha256
  ) {
    throw new Error(
      "Target application release differs from its immutable receipt",
    );
  }
  return canonicalApplicationTreeFingerprint(applicationTarget);
}

async function commitTargetWhileStopped(
  prepared: PreparedNoBackupPreview,
): Promise<void> {
  const server = requirePreparedServer(
    prepared,
    "No-backup target commitment",
  );
  if (databaseSchema() !== TARGET_SCHEMA) {
    throw new Error("Forward completion requires the committed target schema");
  }
  const staticStore = new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT });
  ensureMutation(prepared.journalDirectory, "application_activation", () => {
    atomicApplicationActivation(
      prepared.receipt.releaseId,
      server.releaseDirectory,
    );
    if (applicationTarget() !== prepared.receipt.target.applicationTarget) {
      throw new Error("Atomic application activation did not select the target release");
    }
  }, () => ({ applicationTarget: prepared.receipt.target.applicationTarget }));
  ensureMutation(prepared.journalDirectory, "static_activation", () => {
    staticStore.activateRelease(prepared.receipt.releaseId);
    assertPointer(staticStore, prepared.receipt.target, "Activated target");
  }, () => ({
    staticReleaseId: prepared.receipt.target.staticReleaseId,
    staticManifestSha256: prepared.receipt.target.staticManifestSha256,
  }));
  ensureMutation(prepared.journalDirectory, "target_data_verification", () => {
    assertPointer(staticStore, prepared.receipt.target, "Target commitment");
    assertCanonicalDatabase(TARGET_SCHEMA);
  }, () => ({
    databaseSchema: TARGET_SCHEMA,
    pointers: prepared.receipt.target,
    backupPolicy: "none",
  }));
  let journal = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
  if (!functionalReleaseTargetCommitRecord(journal)) {
    const applicationTreeSha256 =
      await verifyNoBackupTargetApplicationForCommit({
        releaseId: prepared.receipt.releaseId,
        applicationTarget: prepared.receipt.target.applicationTarget,
        serverReleasePath: server.releaseDirectory,
        manifestSha256: prepared.receipt.serverRelease.manifestSha256,
        manifestTreeSha256: prepared.receipt.serverRelease.treeSha256,
      });
    journal = commitFunctionalReleaseTransactionTarget(prepared.journalDirectory, {
      pointers: prepared.receipt.target,
      databaseSchema: TARGET_SCHEMA,
      applicationTreeSha256,
      migrationAttestationSha256:
        prepared.receipt.database.migrationAttestation.attestationSha256,
      backupPolicy: "none",
      rollbackCapability: NO_BACKUP_PREVIEW_ROLLBACK_CAPABILITY,
    });
  }
}

async function startAndFinalizeTarget(
  prepared: PreparedNoBackupPreview,
  observerBefore: NoBackupReleaseObserverProof,
  forceRecovery = false,
): Promise<void> {
  let journal = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
  if (!functionalReleaseTargetCommitRecord(journal)) {
    throw new Error("Journal-authorized start requires a committed target");
  }
  assertPointer(
    new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT }),
    prepared.receipt.target,
    "Committed target before start",
  );
  assertCanonicalDatabase(TARGET_SCHEMA);
  const recoveryStarted = (): boolean =>
    readFunctionalReleaseTransactionJournal(prepared.journalDirectory)
      .records.some((record) => record.event === "recovery_started");
  if (forceRecovery && !recoveryStarted()) {
    journal = appendFunctionalReleaseTransactionRecord(prepared.journalDirectory, {
      event: "recovery_started",
      detail: { recoveryIntent: "complete_target" },
    });
  }
  const useRecovery = recoveryStarted();
  const startState = useRecovery
    ? recoveryMutationState(journal, "service_start")
    : mutationState(journal, "service_start");
  if (startState === "unseen") {
    journal = prepareFunctionalReleaseMutation(
      prepared.journalDirectory,
      useRecovery ? "recovery" : "forward",
      "service_start",
      { targetCommitted: true, backupPolicy: "none" },
    );
  }
  const pendingStartState = useRecovery
    ? recoveryMutationState(
        readFunctionalReleaseTransactionJournal(prepared.journalDirectory),
        "service_start",
      )
    : mutationState(
        readFunctionalReleaseTransactionJournal(prepared.journalDirectory),
        "service_start",
      );
  if (pendingStartState === "prepared") {
    const observed = serviceProperties(SERVICE);
    if (observed.activeState !== "active" || observed.mainPid <= 0) {
      if (!serviceCanRestartUnchanged(stopSnapshot())) {
        throw new Error("Ti-Scale process state is unsafe for journal-authorized start");
      }
      await startNoBackupTargetService({
        journalDirectory: prepared.journalDirectory,
        startService: async () => {
          await runBoundedReleaseCommand([
            "/usr/bin/systemctl",
            "start",
            SERVICE,
          ], {
            cwd: "/",
            env: minimalEnvironment(),
            timeoutMs: 90_000,
            outputLimitBytes: 256 * 1024,
          });
        },
      });
    }
    prepared.receipt.tiScaleAfter = await waitForTargetRuntime(
      prepared,
      prepared.receipt.tiScaleBefore.invocationId,
    );
    completeFunctionalReleaseMutation(
      prepared.journalDirectory,
      useRecovery ? "recovery" : "forward",
      "service_start",
      {
        invocationId: prepared.receipt.tiScaleAfter.invocationId,
        healthStatus: prepared.receipt.tiScaleAfter.healthStatus,
      },
    );
  }
  journal = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
  const targetState = (journal.binding.identity as Record<string, unknown>).target;
  if (!targetState || typeof targetState !== "object" || Array.isArray(targetState)) {
    throw new Error("Target running-state verification lacks its immutable target identity");
  }
  let runningState = useRecovery
    ? recoveryMutationState(journal, "running_state_verification")
    : mutationState(journal, "running_state_verification");
  if (runningState === "unseen") {
    journal = prepareFunctionalReleaseMutation(
      prepared.journalDirectory,
      useRecovery ? "recovery" : "forward",
      "running_state_verification",
      {
        targetState: targetState as Readonly<Record<string, unknown>>,
        targetStateSha256: releaseTransactionSha256(targetState),
        backupPolicy: "none",
      },
    );
    runningState = useRecovery
      ? recoveryMutationState(journal, "running_state_verification")
      : mutationState(journal, "running_state_verification");
  }
  const physicalRuntime = serviceProperties(SERVICE);
  if (physicalRuntime.activeState !== "active" || physicalRuntime.mainPid <= 0) {
    if (!serviceCanRestartUnchanged(stopSnapshot())) {
      throw new Error("Target recovery cannot prove process absence before restart");
    }
    if (runningState === "prepared") {
      await startNoBackupTargetService({
        journalDirectory: prepared.journalDirectory,
        startService: () => {
          command(["/usr/bin/systemctl", "start", SERVICE], { timeoutMs: 90_000 });
        },
      });
    } else if (runningState === "completed") {
      // The exact target running-state commitment is durable, so ExecStartPre
      // admits a repeatable restart without a one-shot token after any later
      // controller or host crash.
      command(["/usr/bin/systemctl", "start", SERVICE], { timeoutMs: 90_000 });
    } else {
      throw new Error("Target runtime has no journal-authorized restart boundary");
    }
  }
  prepared.receipt.tiScaleAfter = await waitForTargetRuntime(
    prepared,
    prepared.receipt.tiScaleBefore.invocationId,
  );
  const verifyTargetRunningState = (): "already_exact" => {
    const observed = serviceProperties(SERVICE);
    if (
      observed.activeState !== "active" ||
      observed.mainPid !== prepared.receipt.tiScaleAfter?.mainPid ||
      observed.invocationId !== prepared.receipt.tiScaleAfter?.invocationId ||
      !cgroupProcessIds(observed.controlGroup).includes(observed.mainPid) ||
      !port3132Listening()
    ) {
      throw new Error("Target runtime changed before durable running-state verification");
    }
    assertPointer(
      new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT }),
      prepared.receipt.target,
      "Running-state verification",
    );
    assertCanonicalDatabase(TARGET_SCHEMA);
    return "already_exact";
  };
  if (runningState === "prepared") {
    completeFunctionalReleaseMutation(
      prepared.journalDirectory,
      useRecovery ? "recovery" : "forward",
      "running_state_verification",
      {
        outcome: verifyTargetRunningState(),
        invocationId: prepared.receipt.tiScaleAfter.invocationId,
        targetState: targetState as Readonly<Record<string, unknown>>,
        targetStateSha256: releaseTransactionSha256(targetState),
        backupPolicy: "none",
      },
    );
  } else {
    verifyTargetRunningState();
  }
  const receiptCommitmentBeforeFinalization =
    completedNoBackupReceiptCommit(
      readFunctionalReleaseTransactionJournal(prepared.journalDirectory),
    );
  if (receiptCommitmentBeforeFinalization) {
    assertCompletedNoBackupReceiptCommit(
      prepared,
      receiptCommitmentBeforeFinalization,
    );
  } else {
    const inventoryAfter = captureNoBackupPayloadInventory(
      prepared.receipt.backupPayloadInventoryBefore.roots,
    );
    assertNoBackupPayloadInventoryEmpty(inventoryAfter);
    assertNoBackupPayloadInventoryUnchanged(
      prepared.receipt.backupPayloadInventoryBefore,
      inventoryAfter,
    );
    prepared.receipt.backupPayloadInventoryAfter = inventoryAfter;
    prepared.receipt.backupPayloadInventoryUnchanged = true;
    prepared.receipt.forwardRecoveryRequired = false;
    delete prepared.receipt.failedAt;
    delete prepared.receipt.failure;
    prepared.receipt.status = "deployed";
    prepared.receipt.deployedAt ??= new Date().toISOString();
  }
  await commitNoBackupTerminalAfterCompatibilityProof({
    verifyCompatibility: () =>
      captureAndAssertReleaseObserverUnchanged(
        prepared.receipt,
        observerBefore,
      ),
    commitTerminal: (observerProof) => {
      journal = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
      let receiptCommitment = completedNoBackupReceiptCommit(journal);
      if (receiptCommitment) {
        assertCompletedNoBackupReceiptCommit(prepared, receiptCommitment);
      }
      const receiptIntent = receiptCommitment
        ? undefined
        : receiptIntentForCommit(
            prepared,
            journal,
            "deployment_receipt_commit",
            observerProof,
          );
      const receiptObserverProofSha256 = receiptCommitment
        ?.observerProofSha256 ?? receiptIntent!.observerProofSha256;
      const intendedReceiptSha256 = receiptCommitment
        ?.receiptSha256 ?? receiptIntent!.receiptSha256;
      const receiptState = useRecovery
        ? recoveryMutationState(journal, "deployment_receipt_commit")
        : mutationState(journal, "deployment_receipt_commit");
      if (!receiptCommitment && receiptState === "unseen") {
        prepareFunctionalReleaseMutation(
          prepared.journalDirectory,
          useRecovery ? "recovery" : "forward",
          "deployment_receipt_commit",
          {
            receiptPath: prepared.receiptPath,
            receipt: receiptIntent!.receipt,
            receiptSha256: intendedReceiptSha256,
            ...noBackupObserverProofDetail(
              prepared.receipt,
              receiptObserverProofSha256,
            ),
          },
        );
      }
      if (!receiptCommitment) {
        writeNoBackupReceiptIntent(
          prepared.receiptPath,
          receiptIntent!.receipt,
        );
        if (
          receiptFileSha256(prepared.receiptPath) !==
            intendedReceiptSha256
        ) {
          throw new Error(
            "No-backup target receipt write differs from its prepared intent",
          );
        }
      }
      if (
        !receiptCommitment &&
        (
          useRecovery
            ? recoveryMutationState(
                readFunctionalReleaseTransactionJournal(prepared.journalDirectory),
                "deployment_receipt_commit",
              )
            : mutationState(
                readFunctionalReleaseTransactionJournal(prepared.journalDirectory),
                "deployment_receipt_commit",
              )
        ) === "prepared"
      ) {
        completeFunctionalReleaseMutation(
          prepared.journalDirectory,
          useRecovery ? "recovery" : "forward",
          "deployment_receipt_commit",
          {
            receiptPath: prepared.receiptPath,
            receiptSha256: intendedReceiptSha256,
            ...noBackupObserverProofDetail(
              prepared.receipt,
              receiptObserverProofSha256,
            ),
          },
        );
      }
      journal = readFunctionalReleaseTransactionJournal(
        prepared.journalDirectory,
      );
      receiptCommitment = completedNoBackupReceiptCommit(journal);
      if (!receiptCommitment) {
        throw new Error(
          "No-backup target terminal requires a durable receipt commitment",
        );
      }
      assertCompletedNoBackupReceiptCommit(prepared, receiptCommitment);
      const supersededReleaseCleanup =
        finalizeSupersededReleaseArtifacts({
          serverReleaseRoot: SERVER_RELEASE_ROOT,
          staticReleaseRoot: STATIC_RELEASE_ROOT,
          activeServerReleaseId: prepared.receipt.releaseId,
          activeApplicationTarget:
            prepared.receipt.target.applicationTarget,
          previousApplicationTarget:
            prepared.receipt.previous.applicationTarget,
          activeStaticReleaseId:
            prepared.receipt.target.staticReleaseId,
          activeStaticManifestSha256:
            prepared.receipt.target.staticManifestSha256,
          previousStaticReleaseId:
            prepared.receipt.previous.staticReleaseId,
          previousStaticManifestSha256:
            prepared.receipt.previous.staticManifestSha256,
        });
      if (!journal.terminal) {
        appendFunctionalReleaseTransactionRecord(prepared.journalDirectory, {
          event: "terminal",
          detail: {
            outcome: "deployed",
            receiptPath: prepared.receiptPath,
            backupPolicy: "none",
            deploymentMode:
              isStandaloneNoBackupForwardReceipt(prepared.receipt)
                ? NO_BACKUP_CURRENT_DEPLOYMENT_MODE
                : "historical_preview",
            ...(
              isStandaloneNoBackupForwardReceipt(prepared.receipt)
                ? {
                  observerProofSha256:
                    receiptCommitment.observerProofSha256,
                  receiptObserverProofSha256:
                    receiptCommitment.observerProofSha256,
                  reconciliationObserverProofSha256:
                    releaseTransactionSha256(observerProof),
                }
                : {
                  cutoverEligible: false,
                  legacyIdentitySha256:
                    receiptCommitment.observerProofSha256,
                  receiptLegacyIdentitySha256:
                    receiptCommitment.observerProofSha256,
                  reconciliationLegacyIdentitySha256:
                    releaseTransactionSha256(observerProof),
                }
            ),
            receiptSha256: receiptCommitment.receiptSha256,
            staticPreviousIdentityCleared:
              supersededReleaseCleanup
                .staticPreviousIdentityCleared,
            supersededStaticReleaseDeleted:
              supersededReleaseCleanup.staticReleaseDeleted,
            supersededServerReleaseDeleted:
              supersededReleaseCleanup.serverReleaseDeleted,
          },
        });
      }
    },
  });
}

async function withNoBackupMaintenance<T>(
  prepared: PreparedNoBackupPreview,
  operation: (
    handle: Parameters<
      Parameters<typeof withCanonicalMaintenanceLease>[2]
    >[0],
    leases: Parameters<
      Parameters<typeof withCanonicalMaintenanceLease>[2]
    >[1],
  ) => Promise<T>,
): Promise<T> {
  const maintenanceDatabase = createDatabaseConnection({
    filename: DATABASE_PATH,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    return await withCanonicalMaintenanceLease(maintenanceDatabase, {
      ownerId: `no-backup-preview:${prepared.receipt.releaseId}:${process.pid}`,
      operation: `no-backup-preview:${prepared.receipt.releaseId}`,
      ttlMs: 60 * 60_000,
    }, operation);
  } finally {
    maintenanceDatabase.close();
  }
}

function reconcileOrphanedNoBackupMaintenance(
  prepared: PreparedNoBackupPreview,
): void {
  const markerPath = `${DATABASE_PATH}.maintenance-lock.json`;
  const stopped = stopSnapshot();
  // A missing sidecar is not proof that maintenance was released: SIGKILL
  // between sidecar unlink and SQLite commit leaves an active row only. Probe
  // every stopped recovery boundary, while avoiding a needless database-handle
  // assertion after a target runtime has already started.
  if (
    !existsSync(markerPath) &&
    (
      stopped.activeState !== "inactive" ||
      stopped.mainPid !== 0 ||
      stopped.portListening ||
      stopped.controlGroupProcessIds.length !== 0
    )
  ) return;
  new OrphanedNoBackupMaintenanceLeaseReconciler().reconcile({
    transactionRoot: TRANSACTION_ROOT,
    journalDirectory: prepared.journalDirectory,
    releaseId: prepared.receipt.releaseId,
    databasePath: DATABASE_PATH,
    maintenanceMarkerPath: markerPath,
    releaseLockPath: SHARED_RELEASE_LOCK_PATH,
    stopped,
    assertNoDatabaseHandles: assertNoCanonicalDatabaseUsers,
    actorId: `no-backup-recovery:${process.pid}`,
  });
}

async function ensureTargetCommittedUnderMaintenance(
  prepared: PreparedNoBackupPreview,
): Promise<void> {
  const journal = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
  if (functionalReleaseTargetCommitRecord(journal)) return;
  const stopped = stopSnapshot();
  if (
    stopped.activeState !== "inactive" ||
    !serviceCanRestartUnchanged(stopped)
  ) {
    throw new Error(
      "Forward target completion requires Ti-Scale to remain at the clean stopped boundary",
    );
  }
  assertNoCanonicalDatabaseUsers();
  await withNoBackupMaintenance(prepared, async (handle, leases) => {
    leases.assertActive(handle);
    assertNoActiveWork();
    if (
      mutationState(
        readFunctionalReleaseTransactionJournal(prepared.journalDirectory),
        "database_migration",
      ) !== "completed"
    ) {
      runNoBackupMigration(prepared);
    }
    leases.assertActive(handle);
    await commitTargetWhileStopped(prepared);
    leases.assertActive(handle);
  });
}

async function captureAndAssertReleaseObserverUnchanged(
  receipt: NoBackupPreviewReceipt,
  before: NoBackupReleaseObserverProof,
): Promise<NoBackupReleaseObserverProof> {
  const after = await resolveNoBackupReleaseObserverProof(
    receipt,
    () => captureServiceIdentity(LEGACY_SERVICE, CHILLSPWN_HEALTH),
  );
  if (isStandaloneNoBackupForwardReceipt(receipt)) {
    if (
      releaseTransactionSha256(before) !==
        releaseTransactionSha256(after)
    ) {
      throw new Error(
        "Standalone Ti-Scale release observer changed during deployment",
      );
    }
    return after;
  }
  return assertServiceIdentityUnchanged(
    before as ServiceIdentity,
    after as ServiceIdentity,
    "Historical compatibility service",
  );
}

function recoveryMutationState(
  journal: FunctionalReleaseTransactionJournal,
  mutation: string,
): "unseen" | "prepared" | "completed" {
  const records = journal.records.filter((record) =>
    record.direction === "recovery" && record.mutation === mutation);
  if (records.some((record) => record.event === "mutation_completed")) return "completed";
  if (records.some((record) => record.event === "mutation_prepared")) return "prepared";
  return "unseen";
}

async function ensureRecoveryMutation(
  journalDirectory: string,
  mutation: string,
  apply: () => "mutated" | "already_exact" | Promise<"mutated" | "already_exact">,
  prepareDetail?: Readonly<Record<string, unknown>>,
  completionDetail: (
    outcome: "mutated" | "already_exact",
  ) => Readonly<Record<string, unknown>> = (outcome) => ({ outcome }),
): Promise<void> {
  let journal = readFunctionalReleaseTransactionJournal(journalDirectory);
  let state = recoveryMutationState(journal, mutation);
  if (state === "unseen") {
    journal = prepareFunctionalReleaseMutation(
      journalDirectory,
      "recovery",
      mutation,
      prepareDetail,
    );
    state = recoveryMutationState(journal, mutation);
  }
  if (state !== "prepared") return;
  const outcome = await apply();
  completeFunctionalReleaseMutation(
    journalDirectory,
    "recovery",
    mutation,
    completionDetail(outcome),
  );
}

async function waitForJournalGuardedRuntime(
  prepared: PreparedNoBackupPreview,
  timeoutMs = 90_000,
): Promise<ServiceIdentity> {
  const deadline = performance.now() + timeoutMs;
  let last = "no observation";
  while (performance.now() < deadline) {
    try {
      const properties = serviceProperties(SERVICE);
      const health = await jsonHealth(TI_SCALE_HEALTH);
      const readiness = await jsonHealth(TI_SCALE_READINESS);
      const healthInvocation = String(health.body.invocationId ?? "");
      const readinessInvocation = String(readiness.body.invocationId ?? "");
      last =
        `${properties.activeState}; health=${health.semanticStatus}; ` +
        `readiness=${readiness.semanticStatus}`;
      if (
        properties.activeState === "active" &&
        properties.mainPid > 0 &&
        properties.invocationId &&
        properties.invocationId !== prepared.receipt.tiScaleBefore.invocationId &&
        health.statusCode === 200 &&
        health.semanticStatus === "journal_guarded" &&
        readiness.statusCode === 200 &&
        readiness.semanticStatus === "journal_guarded" &&
        health.body.schemaVersion === "ti-scale.release-journal-guarded-health.v1" &&
        health.body.mutationFenced === true &&
        readiness.body.mutationFenced === true &&
        healthInvocation === properties.invocationId &&
        readinessInvocation === properties.invocationId &&
        cgroupProcessIds(properties.controlGroup).includes(properties.mainPid) &&
        port3132Listening()
      ) {
        assertPointer(
          new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT }),
          prepared.receipt.previous,
          "Journal-guarded source",
        );
        assertCanonicalDatabase(prepared.receipt.database.sourceSchema);
        return {
          activeState: properties.activeState,
          mainPid: properties.mainPid,
          invocationId: properties.invocationId,
          healthStatus: health.statusCode,
          semanticStatus: health.semanticStatus,
        };
      }
    } catch (error) {
      last = safeJsonError(error);
    }
    await Bun.sleep(250);
  }
  throw new Error(`Source runtime did not enter the journal-guarded boundary: ${last}`);
}

async function waitForRecoveredSourceRuntime(
  prepared: PreparedNoBackupPreview,
  invocationId: string,
  timeoutMs = 4 * 60_000,
): Promise<ServiceIdentity> {
  const deadline = performance.now() + timeoutMs;
  let last = "no observation";
  while (performance.now() < deadline) {
    try {
      const identity = await captureServiceIdentity(SERVICE, TI_SCALE_HEALTH);
      const readiness = await jsonHealth(TI_SCALE_READINESS);
      const database = readiness.body.database as Record<string, unknown> | undefined;
      last =
        `${identity.activeState}/${identity.semanticStatus}; ` +
        `readiness=${readiness.semanticStatus}`;
      if (
        identity.activeState === "active" &&
        identity.mainPid > 0 &&
        identity.invocationId === invocationId &&
        identity.healthStatus === 200 &&
        identity.semanticStatus === "healthy" &&
        readiness.statusCode === 200 &&
        readiness.semanticStatus === "healthy" &&
        database?.healthy === true &&
        Number(database.currentMigration) ===
          prepared.receipt.database.sourceSchema
      ) {
        assertPointer(
          new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT }),
          prepared.receipt.previous,
          "Recovered source",
        );
        assertCanonicalDatabase(prepared.receipt.database.sourceSchema);
        return identity;
      }
    } catch (error) {
      last = safeJsonError(error);
    }
    await Bun.sleep(500);
  }
  throw new Error(`Recovered source runtime did not become healthy: ${last}`);
}

function startWithJournalAuthorization(journalDirectory: string): void {
  const authorization = authorizeNextReleaseServiceStart(journalDirectory);
  try {
    command(["/usr/bin/systemctl", "start", SERVICE], { timeoutMs: 90_000 });
  } finally {
    authorization.release();
  }
}

async function recoverSourceBeforeSchemaCommit(
  prepared: PreparedNoBackupPreview,
  originalFailure: unknown,
  observerBefore: NoBackupReleaseObserverProof =
    receiptObserverProof(prepared.receipt, "before"),
): Promise<void> {
  const sourceSchema = prepared.receipt.database.sourceSchema;
  if (databaseSchema() !== sourceSchema) {
    throw new Error("Pre-schema recovery refused because the source schema is no longer exact");
  }
  const staticStore = new StaticArtifactReleaseStore({ releaseRoot: STATIC_RELEASE_ROOT });
  let journal = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
  if (!journal.records.some((record) => record.event === "recovery_started")) {
    journal = appendFunctionalReleaseTransactionRecord(prepared.journalDirectory, {
      event: "recovery_started",
      detail: { recoveryIntent: "restore_predeploy" },
    });
  }
  await ensureRecoveryMutation(
    prepared.journalDirectory,
    "service_stop_for_recovery",
    () => {
      const before = stopSnapshot();
      if (!serviceCanRestartUnchanged(before)) {
        command(["/usr/bin/systemctl", "stop", SERVICE], { timeoutMs: 90_000 });
      }
      const stopped = stopSnapshot();
      if (!serviceCanRestartUnchanged(stopped)) {
        throw new Error("Source recovery could not prove complete Ti-Scale process absence");
      }
      assertNoCanonicalDatabaseUsers();
      return serviceCanRestartUnchanged(before) ? "already_exact" : "mutated";
    },
    { backupPolicy: "none" },
  );
  await ensureRecoveryMutation(
    prepared.journalDirectory,
    "source_state_verification",
    () => {
      const observedApplication = applicationTarget();
      if (
        observedApplication !== prepared.receipt.previous.applicationTarget &&
        observedApplication !== prepared.receipt.target.applicationTarget
      ) {
        throw new Error(
          "Source recovery found an application pointer outside the immutable source/target pair",
        );
      }
      const observedStatic = staticStore.readActivePointer();
      const staticIsSource =
        observedStatic.activeReleaseId ===
          prepared.receipt.previous.staticReleaseId &&
        observedStatic.activeManifestSha256 ===
          prepared.receipt.previous.staticManifestSha256;
      const staticIsTarget =
        observedStatic.activeReleaseId ===
          prepared.receipt.target.staticReleaseId &&
        observedStatic.activeManifestSha256 ===
          prepared.receipt.target.staticManifestSha256;
      if (!staticIsSource && !staticIsTarget) {
        throw new Error(
          "Source recovery found a static pointer outside the immutable source/target pair",
        );
      }
      let mutated = false;
      if (
        observedApplication !== prepared.receipt.previous.applicationTarget
      ) {
        atomicApplicationActivation(
          prepared.receipt.releaseId,
          prepared.receipt.previous.applicationTarget,
        );
        mutated = true;
      }
      if (!staticIsSource) {
        staticStore.activateRelease(
          prepared.receipt.previous.staticReleaseId,
        );
        mutated = true;
      }
      assertPointer(staticStore, prepared.receipt.previous, "Source recovery");
      assertCanonicalDatabase(sourceSchema, { verifyIntegrity: true });
      return mutated ? "mutated" : "already_exact";
    },
    {
      sourceSchema,
      sourcePointers: prepared.receipt.previous,
      targetPointers: prepared.receipt.target,
      backupPolicy: "none",
    },
  );
  let guardedIdentity: ServiceIdentity | undefined;
  await ensureRecoveryMutation(
    prepared.journalDirectory,
    "service_start",
    async () => {
      const observed = serviceProperties(SERVICE);
      if (observed.activeState !== "active" || observed.mainPid <= 0) {
        if (!serviceCanRestartUnchanged(stopSnapshot())) {
          throw new Error("Source recovery cannot prove process absence before guarded start");
        }
        startWithJournalAuthorization(prepared.journalDirectory);
      }
      guardedIdentity = await waitForJournalGuardedRuntime(prepared);
      return "mutated" as const;
    },
    {
      mode: "journal_guarded",
      sourceSchema,
      backupPolicy: "none",
    },
  );
  journal = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
  const sourceState = (journal.binding.identity as Record<string, unknown>).predeploy;
  if (!sourceState || typeof sourceState !== "object" || Array.isArray(sourceState)) {
    throw new Error("No-backup source-runtime commitment lacks its immutable source identity");
  }
  await ensureRecoveryMutation(
    prepared.journalDirectory,
    RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
    () => ensureGuardedSourceRuntimeCommit({
      label: "No-backup source-runtime commitment",
      inspect: stopSnapshot,
      start: () => startWithJournalAuthorization(prepared.journalDirectory),
      waitAndVerify: async () => {
        guardedIdentity = await waitForJournalGuardedRuntime(prepared);
      },
    }),
    {
      sourceState: sourceState as Readonly<Record<string, unknown>>,
      sourceStateSha256: releaseTransactionSha256(sourceState),
    },
  );
  ensureNoBackupSourceReceiptRestoreCommit(prepared, observerBefore);
  await ensureRecoveryMutation(
    prepared.journalDirectory,
    "runtime_activation",
    async () => {
      const fresh = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
      if (!releaseSourceRuntimeCommitted(fresh)) {
        throw new Error("Source runtime activation requires a durable source commitment");
      }
      clearTerminalReleaseStartupMutationBarrier(fresh);
      const observed = serviceProperties(SERVICE);
      if (observed.activeState !== "active" || observed.mainPid <= 0) {
        if (!serviceCanRestartUnchanged(stopSnapshot())) {
          throw new Error("Committed source runtime cannot prove process absence before restart");
        }
        command(["/usr/bin/systemctl", "start", SERVICE], { timeoutMs: 90_000 });
      }
      const invocationId = serviceProperties(SERVICE).invocationId;
      if (!invocationId) {
        throw new Error("Committed source runtime has no systemd invocation identity");
      }
      await waitForRecoveredSourceRuntime(prepared, invocationId);
      return "mutated" as const;
    },
  );
  let candidateCleanup:
    | FailedCandidateReleaseCleanupResult
    | undefined;
  await ensureRecoveryMutation(
    prepared.journalDirectory,
    "running_state_verification",
    async () => {
      const identity = await captureServiceIdentity(SERVICE, TI_SCALE_HEALTH);
      assertHealthyService(identity, "healthy", "Recovered Ti-Scale");
      assertPointer(staticStore, prepared.receipt.previous, "Recovered source");
      assertCanonicalDatabase(sourceSchema);
      const activeApplicationTarget = applicationTarget();
      if (
        activeApplicationTarget !==
          prepared.receipt.previous.applicationTarget
      ) {
        throw new Error(
          "Recovered source application pointer changed before candidate cleanup",
        );
      }
      candidateCleanup =
        await discardFailedPreSchemaCandidateArtifacts({
          serverReleaseRoot: SERVER_RELEASE_ROOT,
          staticReleaseRoot: STATIC_RELEASE_ROOT,
          activeApplicationTarget,
          activeStaticReleaseId:
            prepared.receipt.previous.staticReleaseId,
          activeStaticManifestSha256:
            prepared.receipt.previous.staticManifestSha256,
          candidateReleaseId: prepared.receipt.releaseId,
          candidateApplicationTarget:
            prepared.receipt.target.applicationTarget,
          candidateServerManifestSha256:
            prepared.receipt.serverRelease.manifestSha256,
          candidateServerTreeSha256:
            prepared.receipt.serverRelease.treeSha256,
          candidateStaticManifestSha256:
            prepared.receipt.staticRelease.manifestSha256,
        });
      return candidateCleanup.serverReleaseDeleted ||
          candidateCleanup.staticReleaseDeleted
        ? "mutated"
        : "already_exact";
    },
    {
      backupPolicy: "none",
      candidateCleanupProtocol:
        "failed_pre_schema_candidate_cleanup_v1",
      sourcePointers: prepared.receipt.previous,
      candidatePointers: prepared.receipt.target,
      candidateServerManifestSha256:
        prepared.receipt.serverRelease.manifestSha256,
      candidateServerTreeSha256:
        prepared.receipt.serverRelease.treeSha256,
      candidateStaticManifestSha256:
        prepared.receipt.staticRelease.manifestSha256,
    },
    (outcome) => ({
      outcome,
      backupPolicy: "none",
      candidateCleanupProtocol:
        "failed_pre_schema_candidate_cleanup_v1",
      candidateCleanupCompleted: true,
      candidateServerDeleted:
        candidateCleanup?.serverReleaseDeleted ?? false,
      candidateStaticDeleted:
        candidateCleanup?.staticReleaseDeleted ?? false,
    }),
  );
  const sourceRuntimeState = serviceProperties(SERVICE);
  if (sourceRuntimeState.activeState !== "active" || sourceRuntimeState.mainPid <= 0) {
    if (
      !releaseSourceRuntimeCommitted(
        readFunctionalReleaseTransactionJournal(prepared.journalDirectory),
      ) ||
      !serviceCanRestartUnchanged(stopSnapshot())
    ) {
      throw new Error("Recovered source runtime is absent without a durable restart boundary");
    }
    command(["/usr/bin/systemctl", "start", SERVICE], { timeoutMs: 90_000 });
  }
  const recoveredInvocationId = serviceProperties(SERVICE).invocationId;
  if (!recoveredInvocationId) {
    throw new Error("Recovered source runtime has no systemd invocation identity");
  }
  await waitForRecoveredSourceRuntime(prepared, recoveredInvocationId);
  journal = readFunctionalReleaseTransactionJournal(
    prepared.journalDirectory,
  );
  const restoredReceiptCommitment = completedNoBackupReceiptRestore(journal);
  if (!restoredReceiptCommitment) {
    throw new Error(
      "Source recovery lost its durable restored-receipt or observer proof",
    );
  }
  const sourceReceiptCommitmentBeforeFinalization =
    completedNoBackupSourceReceiptCommit(journal);
  if (sourceReceiptCommitmentBeforeFinalization) {
    assertCompletedNoBackupReceiptCommit(
      prepared,
      sourceReceiptCommitmentBeforeFinalization,
    );
  } else {
    prepared.receipt.status = "failed_predeploy_restored";
    prepared.receipt.failedAt ??= new Date().toISOString();
    prepared.receipt.failure ??= safeJsonError(originalFailure);
    prepared.receipt.forwardRecoveryRequired = false;
    prepared.receipt.backupPayloadInventoryAfter =
      captureNoBackupPayloadInventory(
        prepared.receipt.backupPayloadInventoryBefore.roots,
      );
    assertNoBackupPayloadInventoryEmpty(
      prepared.receipt.backupPayloadInventoryAfter,
    );
    assertNoBackupPayloadInventoryUnchanged(
      prepared.receipt.backupPayloadInventoryBefore,
      prepared.receipt.backupPayloadInventoryAfter,
    );
    prepared.receipt.backupPayloadInventoryUnchanged = true;
  }
  await commitNoBackupTerminalAfterCompatibilityProof({
    verifyCompatibility: () =>
      captureAndAssertReleaseObserverUnchanged(
        prepared.receipt,
        observerBefore,
      ),
    commitTerminal: (observerProof) => {
      journal = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
      let receiptCommitment = completedNoBackupSourceReceiptCommit(journal);
      if (receiptCommitment) {
        assertCompletedNoBackupReceiptCommit(prepared, receiptCommitment);
      }
      const receiptIntent = receiptCommitment
        ? undefined
        : receiptIntentForCommit(
            prepared,
            journal,
            "terminal_receipt_commit",
            observerProof,
          );
      const receiptObserverProofSha256 = receiptCommitment
        ?.observerProofSha256 ?? receiptIntent!.observerProofSha256;
      const intendedReceiptSha256 = receiptCommitment
        ?.receiptSha256 ?? receiptIntent!.receiptSha256;
      let receiptState = recoveryMutationState(
        journal,
        "terminal_receipt_commit",
      );
      if (!receiptCommitment && receiptState === "unseen") {
        prepareFunctionalReleaseMutation(
          prepared.journalDirectory,
          "recovery",
          "terminal_receipt_commit",
          {
            receiptPath: prepared.receiptPath,
            receipt: receiptIntent!.receipt,
            receiptSha256: intendedReceiptSha256,
            ...noBackupObserverProofDetail(
              prepared.receipt,
              receiptObserverProofSha256,
            ),
            backupPolicy: "none",
          },
        );
        receiptState = "prepared";
      }
      if (!receiptCommitment && receiptState === "prepared") {
        writeNoBackupReceiptIntent(
          prepared.receiptPath,
          receiptIntent!.receipt,
        );
        if (
          receiptFileSha256(prepared.receiptPath) !==
            intendedReceiptSha256
        ) {
          throw new Error(
            "No-backup source terminal receipt write differs from its prepared intent",
          );
        }
        completeFunctionalReleaseMutation(
          prepared.journalDirectory,
          "recovery",
          "terminal_receipt_commit",
          {
            receiptPath: prepared.receiptPath,
            receiptSha256: intendedReceiptSha256,
            ...noBackupObserverProofDetail(
              prepared.receipt,
              receiptObserverProofSha256,
            ),
            backupPolicy: "none",
          },
        );
      }
      journal = readFunctionalReleaseTransactionJournal(prepared.journalDirectory);
      receiptCommitment = completedNoBackupSourceReceiptCommit(
        journal,
      );
      if (!receiptCommitment) {
        throw new Error(
          "Source recovery terminal requires a durable receipt commitment",
        );
      }
      assertCompletedNoBackupReceiptCommit(
        prepared,
        receiptCommitment,
      );
      if (!journal.terminal) {
        appendFunctionalReleaseTransactionRecord(prepared.journalDirectory, {
          event: "terminal",
          detail: {
            outcome: "predeploy_restored",
            receiptPath: prepared.receiptPath,
            backupPolicy: "none",
            deploymentMode:
              isStandaloneNoBackupForwardReceipt(prepared.receipt)
                ? NO_BACKUP_CURRENT_DEPLOYMENT_MODE
                : "historical_preview",
            ...(
              isStandaloneNoBackupForwardReceipt(prepared.receipt)
                ? {
                  observerProofSha256:
                    receiptCommitment.observerProofSha256,
                  receiptObserverProofSha256:
                    receiptCommitment.observerProofSha256,
                  reconciliationObserverProofSha256:
                    releaseTransactionSha256(observerProof),
                }
                : {
                  legacyIdentitySha256:
                    receiptCommitment.observerProofSha256,
                  receiptLegacyIdentitySha256:
                    receiptCommitment.observerProofSha256,
                  reconciliationLegacyIdentitySha256:
                    releaseTransactionSha256(observerProof),
                }
            ),
            restoredReceiptSha256:
              restoredReceiptCommitment.receiptSha256,
            ...(
              isStandaloneNoBackupForwardReceipt(prepared.receipt)
                ? {
                  restoredObserverProofSha256:
                    restoredReceiptCommitment.observerProofSha256,
                }
                : {
                  restoredLegacyIdentitySha256:
                    restoredReceiptCommitment.observerProofSha256,
                }
            ),
            receiptSha256: receiptCommitment.receiptSha256,
          },
        });
      }
    },
  });
  clearTerminalReleaseStartupMutationBarrier(
    readFunctionalReleaseTransactionJournal(prepared.journalDirectory),
  );
}

async function executePreparedNoBackupPreview(
  prepared: PreparedNoBackupPreview,
  interruption?: CooperativeReleaseInterruption,
): Promise<void> {
  const observerBefore = receiptObserverProof(
    prepared.receipt,
    "before",
  );
  const checkpoint = async (): Promise<void> => {
    await Bun.sleep(0);
    interruption?.throwIfAborted();
  };
  await executeNoBackupForwardOnlyController({
    command: "deploy",
    sourceSchema: prepared.receipt.database.sourceSchema,
    targetSchema: prepared.receipt.database.targetSchema,
    forwardSchemas: attestedNoBackupForwardSchemas(
      prepared.receipt.database.migrationAttestation,
      prepared.receipt.database.sourceSchema,
      prepared.receipt.database.targetSchema,
    ),
    operations: {
      stop: async () => {
        await checkpoint();
        stopTiScaleAtJournalBoundary(prepared);
        await captureAndAssertReleaseObserverUnchanged(
          prepared.receipt,
          observerBefore,
        );
        await checkpoint();
      },
      withMaintenance: async (operation) =>
        withNoBackupMaintenance(prepared, async (handle, leases) => {
          leases.assertActive(handle);
          assertNoActiveWork();
          const result = await operation();
          leases.assertActive(handle);
          return result;
        }),
      migrate: async () => {
        runNoBackupMigration(prepared);
        await checkpoint();
      },
      commitTarget: async () => {
        await commitTargetWhileStopped(prepared);
        await checkpoint();
      },
      startAndFinalize: async (forceRecovery) => {
        await startAndFinalizeTarget(
          prepared,
          observerBefore,
          forceRecovery,
        );
      },
      observedSchema: databaseSchema,
      durableTargetCommitted: () =>
        Boolean(functionalReleaseTargetCommitRecord(
          readFunctionalReleaseTransactionJournal(
            prepared.journalDirectory,
          ),
        )),
      restoreSourceBeforeSchemaCommit: (error) =>
        recoverSourceBeforeSchemaCommit(prepared, error),
      ensureTargetCommitted: () =>
        ensureTargetCommittedUnderMaintenance(prepared),
      recordForwardRecoveryFailure: (primaryFailure, recoveryFailure) => {
      prepared.receipt.forwardRecoveryRequired = true;
        prepared.receipt.status = "failed_forward_recovery_required";
        prepared.receipt.failedAt = new Date().toISOString();
        prepared.receipt.failure =
          `${safeJsonError(primaryFailure)}; ` +
          `forward recovery: ${safeJsonError(recoveryFailure)}`;
        writeReceipt(prepared.receiptPath, prepared.receipt);
      },
    },
  });
}

function assertTerminalNoBackupReceipt(
  receipt: NoBackupPreviewReceipt,
  allowedStatus: "deployed" | "failed_predeploy_restored",
): NoBackupPreviewReceipt {
  assertNoBackupPayloadInventoryEmpty(
    receipt.backupPayloadInventoryBefore,
  );
  if (!receipt.backupPayloadInventoryAfter) {
    throw new Error(
      "Durable no-backup release receipt lacks its terminal payload inventory",
    );
  }
  assertNoBackupPayloadInventoryEmpty(
    receipt.backupPayloadInventoryAfter,
  );
  assertNoBackupPayloadInventoryUnchanged(
    receipt.backupPayloadInventoryBefore,
    receipt.backupPayloadInventoryAfter,
  );
  if (
    receipt.status !== allowedStatus ||
    receipt.backupPolicy !== "none" ||
    !(
      isStandaloneNoBackupForwardReceipt(receipt) ||
      isLegacyNoBackupPreviewReceipt(receipt)
    ) ||
    receipt.rollbackCapability !== "none_after_schema_commit" ||
    receipt.backupPayloadInventoryUnchanged !== true ||
    (
      allowedStatus === "deployed" &&
      (
        receipt.forwardRecoveryRequired !== false ||
        receipt.failedAt !== undefined ||
        receipt.failure !== undefined
      )
    )
  ) {
    throw new Error("Durable no-backup release receipt failed terminal verification");
  }
  return receipt;
}

async function resumeNoBackupPreview(
  releaseId: string,
  interruption?: CooperativeReleaseInterruption,
): Promise<NoBackupPreviewReceipt> {
  const incomplete = discoverIncompleteFunctionalReleaseTransactions(TRANSACTION_ROOT);
  if (
    incomplete.length !== 1 ||
    incomplete[0]?.releaseId !== releaseId ||
    incomplete[0]?.operation !== "deploy"
  ) {
    throw new Error(
      `Recovery requires the one exact incomplete no-backup release journal for ${releaseId}`,
    );
  }
  const prepared = await loadPreparedNoBackupPreview(releaseId);
  const observedRecoverySchema = databaseSchema();
  const recoveryJournal = readFunctionalReleaseTransactionJournal(
    prepared.journalDirectory,
  );
  const recoveryDirection = noBackupRecoveryDirection(
    prepared.receipt.database.sourceSchema,
    prepared.receipt.database.targetSchema,
    observedRecoverySchema,
    attestedNoBackupForwardSchemas(
      prepared.receipt.database.migrationAttestation,
      prepared.receipt.database.sourceSchema,
      prepared.receipt.database.targetSchema,
    ),
    Boolean(functionalReleaseTargetCommitRecord(recoveryJournal)),
  );
  enforceNoBackupRecoveryInterruptionPolicy(
    recoveryDirection,
    interruption,
  );
  reconcileOrphanedNoBackupMaintenance(prepared);
  const recoveryObserverBaseline =
    await resolveNoBackupReleaseObserverProof(
      prepared.receipt,
      () => captureServiceIdentity(
        LEGACY_SERVICE,
        CHILLSPWN_HEALTH,
      ),
    );
  if (isLegacyNoBackupPreviewReceipt(prepared.receipt)) {
    assertHealthyService(
      recoveryObserverBaseline as ServiceIdentity,
      "ok",
      "Historical compatibility service",
    );
  }
  const targetReceiptCommitment =
    completedNoBackupReceiptCommit(recoveryJournal);
  const sourceReceiptCommitment =
    completedNoBackupSourceReceiptCommit(recoveryJournal);
  const sourceReceiptRestoreCommitment =
    completedNoBackupReceiptRestore(recoveryJournal);
  const sourceReceiptRestoreIntent =
    preparedNoBackupReceiptRestore(recoveryJournal);
  if (targetReceiptCommitment && sourceReceiptCommitment) {
    throw new Error(
      "No-backup recovery journal contains both source and target receipt commitments",
    );
  }
  const existingReceiptCommitment =
    targetReceiptCommitment ?? sourceReceiptCommitment;
  if (existingReceiptCommitment) {
    assertCompletedNoBackupReceiptCommit(
      prepared,
      existingReceiptCommitment,
    );
  } else if (sourceReceiptRestoreCommitment) {
    assertNoBackupSourceReceiptRestoreCommit(
      prepared,
      recoveryJournal,
    );
  } else if (sourceReceiptRestoreIntent) {
    if (
      receiptFileSha256(prepared.receiptPath) !==
        sourceReceiptRestoreIntent.receiptSha256
    ) {
      throw new Error(
        "Prepared no-backup source receipt restoration lost its exact receipt bytes",
      );
    }
  } else {
    if (isLegacyNoBackupPreviewReceipt(prepared.receipt)) {
      const historicalBefore = receiptObserverProof(
        prepared.receipt,
        "before",
      ) as ServiceIdentity;
      const historicalBaseline =
        recoveryObserverBaseline as ServiceIdentity;
      prepared.receipt.chillspwnRecoveryBaseline =
        historicalBaseline;
      prepared.receipt.chillspwnIdentityChangedBeforeRecovery =
        historicalBefore.mainPid !== historicalBaseline.mainPid ||
        historicalBefore.invocationId !==
          historicalBaseline.invocationId ||
        historicalBefore.activeState !==
          historicalBaseline.activeState ||
        historicalBefore.healthStatus !==
          historicalBaseline.healthStatus ||
        historicalBefore.semanticStatus !==
          historicalBaseline.semanticStatus;
    }
    prepared.receipt.recoveryHostBootId = currentHostBootId();
    writeReceipt(prepared.receiptPath, prepared.receipt);
  }
  // The unchanged schema cannot identify which same-schema release owns the
  // pointers. Before the durable target commitment, cancellation may restore
  // the source. After that commitment, recovery must complete the immutable
  // target before yielding.
  const result = await executeNoBackupForwardOnlyController({
    command: "recover",
    sourceSchema: prepared.receipt.database.sourceSchema,
    targetSchema: prepared.receipt.database.targetSchema,
    forwardSchemas: attestedNoBackupForwardSchemas(
      prepared.receipt.database.migrationAttestation,
      prepared.receipt.database.sourceSchema,
      prepared.receipt.database.targetSchema,
    ),
    recoveryInterruption: interruption,
    operations: {
      stop: () => {
        throw new Error("Recovery cannot enter the deploy stop phase");
      },
      withMaintenance: async () => {
        throw new Error("Recovery cannot enter the deploy maintenance phase");
      },
      migrate: () => {
        throw new Error("Recovery cannot enter the deploy migration phase");
      },
      commitTarget: () => {
        throw new Error("Recovery cannot enter the deploy commitment phase");
      },
      startAndFinalize: async () => {
        await startAndFinalizeTarget(
          prepared,
          recoveryObserverBaseline,
          true,
        );
      },
      observedSchema: () => observedRecoverySchema,
      durableTargetCommitted: () =>
        Boolean(functionalReleaseTargetCommitRecord(
          readFunctionalReleaseTransactionJournal(
            prepared.journalDirectory,
          ),
        )),
      restoreSourceBeforeSchemaCommit: (cause) =>
        recoverSourceBeforeSchemaCommit(
          prepared,
          cause,
          recoveryObserverBaseline,
        ),
      ensureTargetCommitted: async () => {
        if (
          !completedNoBackupReceiptCommit(
            readFunctionalReleaseTransactionJournal(
              prepared.journalDirectory,
            ),
          )
        ) {
          prepared.receipt.forwardRecoveryRequired = true;
          writeReceipt(prepared.receiptPath, prepared.receipt);
        }
        await ensureTargetCommittedUnderMaintenance(prepared);
      },
    },
  });
  const durable = JSON.parse(
    readFileSync(prepared.receiptPath, "utf8"),
  ) as NoBackupPreviewReceipt;
  return assertTerminalNoBackupReceipt(
    durable,
    result.status === "deployed" ? "deployed" : "failed_predeploy_restored",
  );
}

async function executeNoBackupPreviewReleaseUnderLock(
  args: NoBackupPreviewArguments,
  interruption: CooperativeReleaseInterruption,
  candidateLifecycle?: NoBackupCandidateLifecycle,
): Promise<NoBackupPreviewReceipt> {
  await assertStartAdmissionInstalled();
  if (args.command === "recover") {
    if (candidateLifecycle) {
      throw new Error(
        "Candidate staging is not valid during no-backup recovery",
      );
    }
    return resumeNoBackupPreview(args.releaseId, interruption);
  }
  assertNoIncompleteTransaction();
  const tiScaleBefore = await captureServiceIdentity(
    SERVICE,
    TI_SCALE_HEALTH,
  );
  assertHealthyService(
    tiScaleBefore,
    "healthy",
    "Ti-Scale on port 3132",
  );
  assertNoActiveWork();
  const inventoryBefore = captureNoBackupPayloadInventory();
  assertNoBackupPayloadInventoryEmpty(inventoryBefore);

  let candidate: NoBackupStagedCandidateBinding | undefined;
  let transactionPublished = false;
  try {
    candidate = await candidateLifecycle?.stage();
    if (candidate) {
      if (candidate.releaseId !== args.releaseId) {
        throw new Error(
          "Staged candidate release ID differs from the confirmed deployment release ID",
        );
      }
      const inventoryAfterStaging = captureNoBackupPayloadInventory();
      assertNoBackupPayloadInventoryEmpty(inventoryAfterStaging);
      assertNoBackupPayloadInventoryUnchanged(
        inventoryBefore,
        inventoryAfterStaging,
      );
    }
    const prepared = await prepareNoBackupPreview(
      args.releaseId,
      tiScaleBefore,
      inventoryBefore,
      candidate,
    );
    transactionPublished = true;
    await executePreparedNoBackupPreview(prepared, interruption);
    const durable = JSON.parse(
      readFileSync(prepared.receiptPath, "utf8"),
    ) as NoBackupPreviewReceipt;
    return assertTerminalNoBackupReceipt(durable, "deployed");
  } catch (error) {
    if (
      candidate &&
      candidateLifecycle &&
      !transactionPublished
    ) {
      try {
        await candidateLifecycle.discardBeforeTransaction(candidate);
      } catch (cleanupError) {
        throw new AggregateError(
          [error, cleanupError],
          "Candidate staging failed before the durable transaction and its exact cleanup also failed",
        );
      }
    }
    throw error;
  }
}

async function runNoBackupPreviewOperation(
  argv: readonly string[],
  candidateLifecycle?: NoBackupCandidateLifecycle,
): Promise<NoBackupPreviewReceipt> {
  const args = parseNoBackupPreviewArguments(argv);
  if (process.getuid?.() !== 0) {
    throw new Error("No-backup forward deployment requires root");
  }
  return withCooperativeReleaseSignals((interruption) =>
    withSharedReleaseLock(async () => {
      return executeNoBackupPreviewReleaseUnderLock(
        args,
        interruption,
        candidateLifecycle,
      );
    }, { operation: `no-backup-preview:${args.releaseId}` }));
}

export async function runNoBackupPreviewRelease(
  argv = process.argv.slice(2),
): Promise<NoBackupPreviewReceipt> {
  return runNoBackupPreviewOperation(argv);
}

/**
 * Package-owned candidate publication path. Staging runs only after the
 * normal live-service, active-work, admission, and zero-backup preflight has
 * passed, while the same kernel release lock remains held. Once the durable
 * transaction is published the existing no-backup controller owns every
 * recovery decision.
 */
export async function runNoBackupPreviewReleaseWithCandidate(
  argv: readonly string[],
  candidateLifecycle: NoBackupCandidateLifecycle,
): Promise<NoBackupPreviewReceipt> {
  return runNoBackupPreviewOperation(argv, candidateLifecycle);
}

export function noBackupPreviewUsage(): string {
  return [
    "Ti-Scale metadata-journaled no-backup forward deployment",
    "",
    "Usage:",
    "  bun run release:no-backup:stage-deploy -- \\",
    "    --source-root /absolute/clean/checkout \\",
    "    --static-build-root /absolute/clean/checkout/dist \\",
    "    --source-commit FULL_GIT_COMMIT \\",
    "    --source-tree-sha256 SERVER_TREE_SHA256 \\",
    "    --static-artifact-sha256 STATIC_TREE_SHA256 \\",
    "    --release-id ID --confirm ID --execute \\",
    "    --acknowledge-no-backup-risk",
    "  bun run release:no-backup:recover -- \\",
    "    --release-id ID --confirm ID --execute \\",
    "    --acknowledge-no-backup-risk",
    "",
    "This path creates no database, source, Vault, static-pointer, archive, snapshot,",
    "or restore-rehearsal copy. It activates the confirmed build as the current",
    "Ti-Scale service. After an attested schema or target commitment, recovery",
    "resumes only forward through the exact verified release.",
    "",
  ].join("\n");
}

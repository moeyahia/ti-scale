#!/usr/bin/env bun
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
} from "node:fs";
import { dirname } from "node:path";
import {
  executeNoBackupForwardOnlyController,
  type NoBackupForwardOnlyControllerResult,
} from "../../../../scripts/release/NoBackupForwardOnlyController";
import {
  assertNoBackupPayloadInventoryUnchanged,
  captureNoBackupPayloadInventory,
  NO_BACKUP_SOURCE_SCHEMA,
  type NoBackupPayloadInventory,
} from "../../../../scripts/release/NoBackupPreviewRelease";
import {
  appendFunctionalReleaseTransactionRecord,
  canonicalReleaseTransactionJson,
  commitFunctionalReleaseTransactionTarget,
  completeFunctionalReleaseMutation,
  createFunctionalReleaseTransactionJournal,
  functionalReleaseTargetCommitRecord,
  prepareFunctionalReleaseMutation,
  readFunctionalReleaseTransactionJournal,
  releaseTransactionSha256,
  type FunctionalReleaseTransactionDirection,
  type FunctionalReleaseTransactionJournal,
} from "../../../../scripts/release/DurableReleaseTransaction";
import { writeDurableFileAtomically } from
  "../../../../scripts/release/DurableAtomicFile";
import { withSharedReleaseLock } from
  "../../../../scripts/release/ReleaseExecutionBoundary";
import {
  assertReleaseServiceStartAdmitted,
  authorizeNextReleaseServiceStart,
} from
  "../../../../scripts/release/ReleaseServiceStartAdmission";
import { OrphanedNoBackupMaintenanceLeaseReconciler } from
  "../../../../scripts/release/OrphanedNoBackupMaintenanceLeaseReconciler";
import {
  clearReleaseStartupMutationBarrier,
  RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
  RELEASE_SOURCE_RUNTIME_PROTOCOL,
  RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL,
} from "../../../../scripts/release/ReleaseStartupMutationBarrier";
import { createDatabaseConnection } from "../../../../server/db/connection";
import { DATABASE_MIGRATIONS } from "../../../../server/db/migrations";
import { migrateDatabase } from "../../../../server/db/migrations/runner";
import { withCanonicalMaintenanceLease } from "../../../../server/maintenance";
import type { Migration } from "../../../../server/db/types";

interface FixtureServiceIdentity {
  readonly pid: number;
  readonly invocationId: string;
  readonly status: "ok";
}

interface FixtureState {
  schema: number;
  application: "source-application" | "target-application";
  staticRelease: "source-static" | "target-static";
  tiScale: {
    active: boolean;
    runtime: "source" | "target";
    invocationId: string;
    generation: number;
  };
}

interface FixtureReceipt {
  readonly schemaVersion:
    | "ti-scale.no-backup-preview-release-receipt.v1"
    | "ti-scale.no-backup-forward-release-receipt.v2";
  readonly releaseId: string;
  status:
    | "prepared"
    | "failed_predeploy_restored"
    | "deployed"
    | "failed_forward_recovery_required";
  readonly backupPolicy: "none";
  readonly cutoverEligible?: false;
  readonly deploymentMode?: "current_service";
  readonly releaseObserver?: typeof STANDALONE_RELEASE_OBSERVER;
  readonly rollbackCapability: "none_after_schema_commit";
  readonly sourceSchema: number;
  readonly targetSchema: number;
  readonly source: Readonly<Record<string, unknown>>;
  readonly target: Readonly<Record<string, unknown>>;
  readonly legacyBefore?: FixtureServiceIdentity;
  legacyAfter?: FixtureServiceIdentity;
  schemaCommitted?: boolean;
  forwardRecoveryRequired?: boolean;
  backupPayloadInventoryBefore: NoBackupPayloadInventory;
  backupPayloadInventoryAfter?: NoBackupPayloadInventory;
  backupPayloadInventoryUnchanged?: boolean;
  failure?: string;
  recoveryHostBootId?: string;
  legacyRecoveryBaseline?: FixtureServiceIdentity;
}

interface FixtureConfiguration {
  readonly releaseId: string;
  readonly sourceSchema: number;
  readonly targetSchema: number;
  readonly statePath: string;
  readonly legacyIdentityPath: string;
  readonly hostBootIdPath: string;
  readonly receiptPath: string;
  readonly journalDirectory: string;
  readonly transactionRoot: string;
  readonly releaseLockPath: string;
  readonly authorizationPath: string;
  readonly startupMutationBarrierPath: string;
  readonly leaseDatabasePath: string;
  readonly maintenanceMarkerPath: string;
  readonly boundaryPath: string;
  readonly resultPath: string;
  readonly inventoryRoots: readonly string[];
}

type CrashBoundary =
  | "none"
  | "pre_schema"
  | "post_schema"
  | `schema_${number}`
  | "target_precommit"
  | "target_committed"
  | "target_receipt_prepared"
  | "target_receipt_written"
  | "target_receipt_committed"
  | "source_restore_prepared"
  | "source_receipt_prepared"
  | "source_receipt_committed";

const [command, configurationPath, crashBoundaryValue] = process.argv.slice(2);
if (
  (command !== "deploy" && command !== "recover") ||
  !configurationPath
) {
  process.stderr.write(
    "usage: no-backup-full-controller-worker.ts deploy|recover CONFIG BOUNDARY\n",
  );
  process.exit(64);
}
const configuration = JSON.parse(
  readFileSync(configurationPath, "utf8"),
) as FixtureConfiguration;
const SOURCE_SCHEMA = configuration.sourceSchema;
const TARGET_SCHEMA = configuration.targetSchema;
const STANDALONE_RELEASE_OBSERVER = Object.freeze({
  schemaVersion: "ti-scale.release-observer.v1" as const,
  mode: "standalone" as const,
  scope: "ti_scale_only" as const,
  externalServiceDependency: "none" as const,
});
const FORWARD_V2 = SOURCE_SCHEMA === NO_BACKUP_SOURCE_SCHEMA &&
  TARGET_SCHEMA >= SOURCE_SCHEMA;
if (
  !Number.isSafeInteger(SOURCE_SCHEMA) ||
  !Number.isSafeInteger(TARGET_SCHEMA) ||
  SOURCE_SCHEMA < 0 ||
  TARGET_SCHEMA < SOURCE_SCHEMA ||
  TARGET_SCHEMA > DATABASE_MIGRATIONS.length
) {
  throw new Error("Fixture schema progression is invalid");
}
const FORWARD_SCHEMAS = Object.freeze(
  Array.from(
    { length: TARGET_SCHEMA - SOURCE_SCHEMA },
    (_, index) => SOURCE_SCHEMA + index + 1,
  ),
);
const schemaCrashBoundary = /^schema_(\d+)$/u.exec(
  crashBoundaryValue ?? "",
);
const validSchemaCrashBoundary = schemaCrashBoundary !== null &&
  FORWARD_SCHEMAS.includes(Number(schemaCrashBoundary[1]));
if (
  ![
    "none",
    "pre_schema",
    "post_schema",
    "target_precommit",
    "target_committed",
    "target_receipt_prepared",
    "target_receipt_written",
    "target_receipt_committed",
    "source_restore_prepared",
    "source_receipt_prepared",
    "source_receipt_committed",
  ].includes(crashBoundaryValue ?? "") &&
  !validSchemaCrashBoundary
) {
  process.stderr.write(
    "usage: no-backup-full-controller-worker.ts deploy|recover CONFIG " +
      "none|pre_schema|post_schema|target_receipt_prepared|" +
      "target_precommit|target_committed|" +
      "target_receipt_written|target_receipt_committed|" +
      "source_receipt_prepared|" +
      "source_restore_prepared|source_receipt_committed|schema_SOURCE..schema_TARGET\n",
  );
  process.exit(64);
}
const crashBoundary = crashBoundaryValue as CrashBoundary;
const controllerCommand = command as "deploy" | "recover";

function withoutBackupRequirement(migration: Migration): Migration {
  const {
    requiresVerifiedBackup: _requiresVerifiedBackup,
    ...noBackupMigration
  } = migration;
  return noBackupMigration;
}

function readState(): FixtureState {
  return JSON.parse(readFileSync(configuration.statePath, "utf8")) as FixtureState;
}

function writeState(value: FixtureState): void {
  writeDurableFileAtomically(
    configuration.statePath,
    `${JSON.stringify(value, null, 2)}\n`,
    { mode: 0o600 },
  );
}

function readLegacyIdentity(): FixtureServiceIdentity {
  return JSON.parse(
    readFileSync(configuration.legacyIdentityPath, "utf8"),
  ) as FixtureServiceIdentity;
}

function readReceipt(): FixtureReceipt {
  return JSON.parse(
    readFileSync(configuration.receiptPath, "utf8"),
  ) as FixtureReceipt;
}

function writeReceipt(receipt: FixtureReceipt): void {
  writeDurableFileAtomically(
    configuration.receiptPath,
    receiptBytes(receipt),
    { mode: 0o600 },
  );
}

function receiptBytes(receipt: FixtureReceipt): string {
  const canonicalReceipt = JSON.parse(
    canonicalReleaseTransactionJson(receipt),
  ) as FixtureReceipt;
  return `${JSON.stringify(canonicalReceipt, null, 2)}\n`;
}

function fileSha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function receiptSha256(receipt: FixtureReceipt): string {
  return createHash("sha256").update(receiptBytes(receipt)).digest("hex");
}

function databaseSchema(): number {
  const database = createDatabaseConnection({
    filename: configuration.leaseDatabasePath,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const version = Number((database.prepare(
      "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations",
    ).get() as { readonly version: number }).version);
    if (
      !Number.isSafeInteger(version) ||
      version < SOURCE_SCHEMA ||
      version > TARGET_SCHEMA
    ) {
      throw new Error(`Fixture database has unexpected schema ${String(version)}`);
    }
    return version;
  } finally {
    database.close();
  }
}

function assertJsonAndDatabaseSchemaMatch(): number {
  const schema = databaseSchema();
  if (readState().schema !== schema) {
    throw new Error("Fixture JSON state diverged from the canonical SQLite schema");
  }
  return schema;
}

function targetState(): Readonly<Record<string, unknown>> {
  return {
    databaseSchema: TARGET_SCHEMA,
    pointers: {
      application: "target-application",
      staticRelease: "target-static",
    },
  };
}

function sourceState(): Readonly<Record<string, unknown>> {
  return {
    databaseSchema: SOURCE_SCHEMA,
    pointers: {
      application: "source-application",
      staticRelease: "source-static",
    },
  };
}

function stateOfMutation(
  journal: FunctionalReleaseTransactionJournal,
  direction: FunctionalReleaseTransactionDirection,
  mutation: string,
): "unseen" | "prepared" | "completed" {
  const records = journal.records.filter((record) =>
    record.direction === direction && record.mutation === mutation
  );
  if (records.some((record) => record.event === "mutation_completed")) {
    return "completed";
  }
  if (records.some((record) => record.event === "mutation_prepared")) {
    return "prepared";
  }
  return "unseen";
}

interface FixtureReceiptCommitment {
  readonly receipt: FixtureReceipt;
  readonly receiptSha256: string;
  readonly observerProofSha256: string;
}

interface FixtureRestoredReceiptCommitment {
  readonly receiptSha256: string;
  readonly observerProofSha256: string;
}

function observerProofField():
  "observerProofSha256" | "legacyIdentitySha256" {
  return FORWARD_V2 ? "observerProofSha256" : "legacyIdentitySha256";
}

function receiptObserverProof(
  receipt: FixtureReceipt,
): FixtureServiceIdentity | typeof STANDALONE_RELEASE_OBSERVER {
  if (FORWARD_V2) {
    if (
      receipt.schemaVersion !==
        "ti-scale.no-backup-forward-release-receipt.v2" ||
      receipt.deploymentMode !== "current_service" ||
      releaseTransactionSha256(receipt.releaseObserver ?? null) !==
        releaseTransactionSha256(STANDALONE_RELEASE_OBSERVER) ||
      receipt.cutoverEligible !== undefined ||
      receipt.legacyBefore !== undefined ||
      receipt.legacyAfter !== undefined
    ) {
      throw new Error("Fixture v2 receipt lacks its standalone observer binding");
    }
    return STANDALONE_RELEASE_OBSERVER;
  }
  if (
    receipt.schemaVersion !==
      "ti-scale.no-backup-preview-release-receipt.v1" ||
    receipt.cutoverEligible !== false ||
    !receipt.legacyAfter
  ) {
    throw new Error("Fixture v1 receipt lacks its historical identity binding");
  }
  return receipt.legacyAfter;
}

function observerProofDetail(
  observerProofSha256: string,
): Readonly<Record<string, string>> {
  return { [observerProofField()]: observerProofSha256 };
}

function observerProofFromDetail(
  detail: Readonly<Record<string, unknown>> | undefined,
): string | undefined {
  const value = detail?.[observerProofField()];
  return typeof value === "string" ? value : undefined;
}

function preparedRestoredReceiptCommitment():
  FixtureRestoredReceiptCommitment | undefined {
  const journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  const preparations = journal.records.filter((record) =>
    record.event === "mutation_prepared" &&
    record.direction === "recovery" &&
    record.mutation === "deployment_receipt_restore"
  );
  if (!preparations.length) return undefined;
  if (preparations.length !== 1) {
    throw new Error("Fixture source receipt restore intents conflict");
  }
  const preparation = preparations[0]!;
  const receiptSha256 = preparation.detail?.receiptSha256;
  const observerProofSha256 = observerProofFromDetail(preparation.detail);
  if (
    preparation.detail?.receiptPath !== configuration.receiptPath ||
    typeof receiptSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(receiptSha256) ||
    typeof observerProofSha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(observerProofSha256)
  ) {
    throw new Error("Fixture source receipt restore intent is malformed");
  }
  return { receiptSha256, observerProofSha256 };
}

function receiptIntent(
  mutation: "deployment_receipt_commit" | "terminal_receipt_commit",
): FixtureReceiptCommitment | undefined {
  const journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  const records = journal.records.filter((record) =>
    record.event === "mutation_prepared" &&
    record.mutation === mutation
  );
  if (!records.length) return undefined;
  const intents = records.map((record) => {
    const receipt = record.detail?.receipt as FixtureReceipt | undefined;
    const intendedSha256 = record.detail?.receiptSha256;
    const observerProofSha256 = observerProofFromDetail(record.detail);
    if (
      record.detail?.receiptPath !== configuration.receiptPath ||
      !receipt ||
      typeof intendedSha256 !== "string" ||
      intendedSha256 !== receiptSha256(receipt) ||
      typeof observerProofSha256 !== "string" ||
      observerProofSha256 !== releaseTransactionSha256(
        receiptObserverProof(receipt),
      )
    ) {
      throw new Error(
        `Fixture prepared receipt intent is malformed: ${
          JSON.stringify({
            direction: record.direction,
            mutation: record.mutation,
            receiptPath: record.detail?.receiptPath,
            expectedReceiptPath: configuration.receiptPath,
            intendedSha256,
            computedSha256: receipt ? receiptSha256(receipt) : null,
            observerProofSha256,
            receiptObserverProofSha256: receipt
              ? releaseTransactionSha256(receiptObserverProof(receipt))
              : null,
          })
        }`,
      );
    }
    return {
      receipt,
      receiptSha256: intendedSha256,
      observerProofSha256,
    };
  });
  const first = intents[0]!;
  if (intents.some((candidate) =>
    candidate.receiptSha256 !== first.receiptSha256 ||
    candidate.observerProofSha256 !== first.observerProofSha256
  )) {
    throw new Error("Fixture prepared receipt intents conflict");
  }
  return first;
}

function completedReceiptCommitment(
  mutation: "deployment_receipt_commit" | "terminal_receipt_commit",
): FixtureReceiptCommitment | undefined {
  const journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  const records = journal.records.filter((record) =>
    record.event === "mutation_completed" &&
    record.mutation === mutation
  );
  if (!records.length) return undefined;
  const intent = receiptIntent(mutation);
  if (!intent) throw new Error("Fixture receipt completion lacks an intent");
  for (const record of records) {
    if (
      record.detail?.receiptPath !== configuration.receiptPath ||
      record.detail?.receiptSha256 !== intent.receiptSha256 ||
      observerProofFromDetail(record.detail) !==
        intent.observerProofSha256
    ) {
      throw new Error("Fixture receipt completion differs from its intent");
    }
  }
  if (
    fileSha256(configuration.receiptPath) !== intent.receiptSha256
  ) {
    throw new Error("Fixture committed receipt bytes changed");
  }
  return intent;
}

function completedRestoredReceiptCommitment():
  FixtureRestoredReceiptCommitment | undefined {
  const journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  const completion = journal.records.find((record) =>
    record.event === "mutation_completed" &&
    record.direction === "recovery" &&
    record.mutation === "deployment_receipt_restore"
  );
  if (!completion) return undefined;
  const preparation = preparedRestoredReceiptCommitment();
  const receiptSha256 = completion.detail?.receiptSha256;
  const observerProofSha256 = observerProofFromDetail(completion.detail);
  if (
    !preparation ||
    preparation.receiptSha256 !== receiptSha256 ||
    preparation.observerProofSha256 !== observerProofSha256 ||
    completion.detail?.receiptPath !== configuration.receiptPath ||
    typeof receiptSha256 !== "string" ||
    typeof observerProofSha256 !== "string"
  ) {
    throw new Error("Fixture restored receipt commitment is malformed");
  }
  return { receiptSha256, observerProofSha256 };
}

async function ensureMutation(
  direction: FunctionalReleaseTransactionDirection,
  mutation: string,
  apply: () => void | Promise<void>,
  prepareDetail: Readonly<Record<string, unknown>> = { backupPolicy: "none" },
  completionDetail: () => Readonly<Record<string, unknown>> = () => ({
    outcome: "already_exact",
  }),
): Promise<void> {
  let journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  let state = stateOfMutation(journal, direction, mutation);
  if (state === "unseen") {
    journal = prepareFunctionalReleaseMutation(
      configuration.journalDirectory,
      direction,
      mutation,
      prepareDetail,
    );
    state = stateOfMutation(journal, direction, mutation);
  }
  if (state !== "prepared") return;
  await apply();
  completeFunctionalReleaseMutation(
    configuration.journalDirectory,
    direction,
    mutation,
    completionDetail(),
  );
}

function recoveryStarted(): boolean {
  return readFunctionalReleaseTransactionJournal(configuration.journalDirectory)
    .records.some((record) => record.event === "recovery_started");
}

function ensureRecoveryStarted(intent: "restore_predeploy" | "complete_target"): void {
  if (recoveryStarted()) return;
  appendFunctionalReleaseTransactionRecord(configuration.journalDirectory, {
    event: "recovery_started",
    detail: { recoveryIntent: intent },
  });
}

async function blockForSigkill(boundary: Exclude<CrashBoundary, "none">): Promise<void> {
  if (crashBoundary !== boundary) return;
  writeDurableFileAtomically(
    configuration.boundaryPath,
    `${JSON.stringify({
      boundary,
      controllerPid: process.pid,
      state: readState(),
    })}\n`,
    { mode: 0o600 },
  );
  await new Promise<never>(() => undefined);
}

function assertLegacyIdentityUnchanged(expected: FixtureServiceIdentity): void {
  const observed = readLegacyIdentity();
  if (releaseTransactionSha256(observed) !== releaseTransactionSha256(expected)) {
    throw new Error("Fake legacy service identity changed");
  }
}

function startFixtureService(runtime: "source" | "target"): FixtureState {
  const authorization = authorizeNextReleaseServiceStart(
    configuration.journalDirectory,
    { authorizationPath: configuration.authorizationPath },
  );
  try {
    const state = readState();
    const generation = state.tiScale.generation + 1;
    const invocationId = generation.toString(16).padStart(
      32,
      runtime === "source" ? "a" : "b",
    );
    const admission = assertReleaseServiceStartAdmitted({
      transactionRoot: configuration.transactionRoot,
      releaseLockPath: configuration.releaseLockPath,
      authorizationPath: configuration.authorizationPath,
      startupMutationBarrierPath: configuration.startupMutationBarrierPath,
      invocationId,
    });
    if (admission.mode !== "journal_authorized") {
      throw new Error("Fixture ExecStartPre did not consume the journal authorization");
    }
    const next: FixtureState = {
      ...state,
      tiScale: {
        active: true,
        runtime,
        invocationId,
        generation,
      },
    };
    writeState(next);
    return next;
  } finally {
    authorization.release();
  }
}

function assertInventoryAndLegacy(
  receipt: FixtureReceipt,
  expectedLegacy: FixtureServiceIdentity,
): FixtureReceipt {
  const inventoryAfter = captureNoBackupPayloadInventory(
    receipt.backupPayloadInventoryBefore.roots,
  );
  assertNoBackupPayloadInventoryUnchanged(
    receipt.backupPayloadInventoryBefore,
    inventoryAfter,
  );
  assertLegacyIdentityUnchanged(expectedLegacy);
  const common = {
    ...receipt,
    backupPayloadInventoryAfter: inventoryAfter,
    backupPayloadInventoryUnchanged: true,
  };
  return FORWARD_V2
    ? common
    : { ...common, legacyAfter: expectedLegacy };
}

function initializeDeployment(): void {
  if (existsSync(configuration.journalDirectory)) return;
  mkdirSync(dirname(configuration.receiptPath), { recursive: true, mode: 0o700 });
  const legacyBefore = readLegacyIdentity();
  const inventoryBefore = captureNoBackupPayloadInventory(
    configuration.inventoryRoots,
  );
  const receipt: FixtureReceipt = {
    schemaVersion: FORWARD_V2
      ? "ti-scale.no-backup-forward-release-receipt.v2"
      : "ti-scale.no-backup-preview-release-receipt.v1",
    releaseId: configuration.releaseId,
    status: "prepared",
    backupPolicy: "none",
    ...(FORWARD_V2
      ? {
        deploymentMode: "current_service" as const,
        releaseObserver: STANDALONE_RELEASE_OBSERVER,
      }
      : {
        cutoverEligible: false as const,
        legacyBefore,
      }),
    rollbackCapability: "none_after_schema_commit",
    sourceSchema: SOURCE_SCHEMA,
    targetSchema: TARGET_SCHEMA,
    source: sourceState(),
    target: targetState(),
    backupPayloadInventoryBefore: inventoryBefore,
  };
  writeReceipt(receipt);
  createFunctionalReleaseTransactionJournal({
    directory: configuration.journalDirectory,
    operation: "deploy",
    releaseId: configuration.releaseId,
    receiptPath: configuration.receiptPath,
    recoveryIntent: "restore_predeploy",
    identity: {
      deploymentKind: FORWARD_V2
        ? "no_backup_forward_v2"
        : "no_backup_preview_v1",
      ...(FORWARD_V2
        ? {
          deploymentMode: "current_service",
          releaseObserver: STANDALONE_RELEASE_OBSERVER,
        }
        : { legacyBefore }),
      releaseStartupProtocol: RELEASE_SOURCE_RUNTIME_PROTOCOL,
      targetRuntimeCommitProtocol: RELEASE_TARGET_RUNTIME_COMMIT_PROTOCOL,
      requireRunningStateVerification: true,
      backupPolicy: "none",
      rollbackCapability: "none_after_schema_commit",
      predeploy: sourceState(),
      target: targetState(),
      backupPayloadInventoryBefore: {
        roots: inventoryBefore.roots,
        inventorySha256: inventoryBefore.inventorySha256,
      },
    },
    transactionId: `${configuration.releaseId}-transaction`,
  });
}

async function stop(): Promise<void> {
  await ensureMutation("forward", "service_stop", () => {
    const state = readState();
    writeState({
      ...state,
      tiScale: {
        ...state.tiScale,
        active: false,
      },
    });
  });
  if (!FORWARD_V2) {
    const legacyBefore = readReceipt().legacyBefore;
    if (!legacyBefore) {
      throw new Error("Fixture v1 receipt lost its historical identity");
    }
    assertLegacyIdentityUnchanged(legacyBefore);
  }
}

async function withMaintenance<T>(operation: () => Promise<T>): Promise<T> {
  const database = createDatabaseConnection({
    filename: configuration.leaseDatabasePath,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    return await withCanonicalMaintenanceLease(database, {
      ownerId: `no-backup-preview:${configuration.releaseId}:${process.pid}`,
      operation: `no-backup-preview:${configuration.releaseId}`,
      ttlMs: 60 * 60_000,
    }, async () => operation(), {
      maintenanceMarkerPath: configuration.maintenanceMarkerPath,
    });
  } finally {
    database.close();
  }
}

async function migrate(): Promise<void> {
  await blockForSigkill("pre_schema");
  await ensureMutation("forward", "database_migration", async () => {
    let state = readState();
    const observedSchema = databaseSchema();
    if (
      state.schema !== observedSchema ||
      observedSchema < SOURCE_SCHEMA ||
      observedSchema > TARGET_SCHEMA
    ) {
      throw new Error(
        "Fixture migration did not begin at a known forward-only schema",
      );
    }
    for (
      let nextSchema = observedSchema + 1;
      nextSchema <= TARGET_SCHEMA;
      nextSchema += 1
    ) {
      const database = createDatabaseConnection({
        filename: configuration.leaseDatabasePath,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      try {
        migrateDatabase(
          database,
          DATABASE_MIGRATIONS
            .slice(0, nextSchema)
            .map(withoutBackupRequirement),
        );
      } finally {
        database.close();
      }
      if (databaseSchema() !== nextSchema) {
        throw new Error(
          `Fixture canonical SQLite migration did not commit schema ${String(nextSchema)}`,
        );
      }
      state = { ...state, schema: nextSchema };
      writeState(state);
      await blockForSigkill(
        `schema_${String(nextSchema)}` as `schema_${number}`,
      );
    }
    writeReceipt({
      ...readReceipt(),
      schemaCommitted: true,
    });
  }, {
    sourceSchema: SOURCE_SCHEMA,
    targetSchema: TARGET_SCHEMA,
    forwardSchemas: FORWARD_SCHEMAS,
    backupPolicy: "none",
  }, () => ({
    databaseSchema: TARGET_SCHEMA,
    backupPolicy: "none",
  }));
  await blockForSigkill("post_schema");
}

async function commitTarget(): Promise<void> {
  if (assertJsonAndDatabaseSchemaMatch() !== TARGET_SCHEMA) {
    throw new Error(
      `Target commitment requires schema ${String(TARGET_SCHEMA)}`,
    );
  }
  await ensureMutation("forward", "application_activation", () => {
    const state = readState();
    writeState({ ...state, application: "target-application" });
  });
  await ensureMutation("forward", "static_activation", () => {
    const state = readState();
    writeState({ ...state, staticRelease: "target-static" });
  });
  await ensureMutation("forward", "target_data_verification", () => {
    const state = readState();
    if (
      state.schema !== TARGET_SCHEMA ||
      state.application !== "target-application" ||
      state.staticRelease !== "target-static"
    ) {
      throw new Error("Target fixture state is not exact");
    }
  });
  await blockForSigkill("target_precommit");
  const journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  if (!functionalReleaseTargetCommitRecord(journal)) {
    commitFunctionalReleaseTransactionTarget(
      configuration.journalDirectory,
      targetState(),
    );
  }
  await blockForSigkill("target_committed");
}

async function startAndFinalize(forceRecovery: boolean): Promise<void> {
  if (!functionalReleaseTargetCommitRecord(
    readFunctionalReleaseTransactionJournal(configuration.journalDirectory),
  )) {
    throw new Error("Target start requires its durable commitment");
  }
  if (existsSync(configuration.maintenanceMarkerPath)) {
    throw new Error("Target start occurred inside the maintenance boundary");
  }
  if (forceRecovery) ensureRecoveryStarted("complete_target");
  const direction: FunctionalReleaseTransactionDirection =
    recoveryStarted() ? "recovery" : "forward";
  let runningState = readState();
  await ensureMutation(direction, "service_start", () => {
    const observed = readState();
    runningState =
      observed.tiScale.active && observed.tiScale.runtime === "target"
        ? observed
        : startFixtureService("target");
  }, { targetCommitted: true, backupPolicy: "none" }, () => ({
    invocationId: runningState.tiScale.invocationId,
    healthStatus: 200,
  }));
  runningState = readState();
  if (!runningState.tiScale.active || runningState.tiScale.runtime !== "target") {
    throw new Error("Target fixture service is not active");
  }
  const immutableTarget = targetState();
  await ensureMutation(
    direction,
    "running_state_verification",
    () => {
      const state = readState();
      if (
        state.schema !== TARGET_SCHEMA ||
        databaseSchema() !== TARGET_SCHEMA ||
        state.application !== "target-application" ||
        state.staticRelease !== "target-static" ||
        !state.tiScale.active ||
        state.tiScale.runtime !== "target"
      ) {
        throw new Error("Target running state is not exact");
      }
    },
    {
      targetState: immutableTarget,
      targetStateSha256: releaseTransactionSha256(immutableTarget),
      backupPolicy: "none",
    },
    () => ({
      outcome: "already_exact",
      invocationId: readState().tiScale.invocationId,
      targetState: immutableTarget,
      targetStateSha256: releaseTransactionSha256(immutableTarget),
      backupPolicy: "none",
    }),
  );
  let commitment = completedReceiptCommitment(
    "deployment_receipt_commit",
  );
  if (!commitment) {
    let intent = receiptIntent("deployment_receipt_commit");
    if (!intent) {
      const legacyProof = readLegacyIdentity();
      const receipt: FixtureReceipt = {
        ...assertInventoryAndLegacy(readReceipt(), legacyProof),
        status: "deployed",
        schemaCommitted: true,
        forwardRecoveryRequired: false,
      };
      intent = {
        receipt,
        receiptSha256: receiptSha256(receipt),
        observerProofSha256: releaseTransactionSha256(
          receiptObserverProof(receipt),
        ),
      };
    }
    if (
      stateOfMutation(
        readFunctionalReleaseTransactionJournal(
          configuration.journalDirectory,
        ),
        direction,
        "deployment_receipt_commit",
      ) === "unseen"
    ) {
      prepareFunctionalReleaseMutation(
        configuration.journalDirectory,
        direction,
        "deployment_receipt_commit",
        {
          receiptPath: configuration.receiptPath,
          receipt: intent.receipt,
          receiptSha256: intent.receiptSha256,
          ...observerProofDetail(intent.observerProofSha256),
          backupPolicy: "none",
        },
      );
    }
    await blockForSigkill("target_receipt_prepared");
    writeReceipt(intent.receipt);
    if (fileSha256(configuration.receiptPath) !== intent.receiptSha256) {
      throw new Error("Fixture target receipt write differs from intent");
    }
    await blockForSigkill("target_receipt_written");
    if (
      stateOfMutation(
        readFunctionalReleaseTransactionJournal(
          configuration.journalDirectory,
        ),
        direction,
        "deployment_receipt_commit",
      ) === "prepared"
    ) {
      completeFunctionalReleaseMutation(
        configuration.journalDirectory,
        direction,
        "deployment_receipt_commit",
        {
          receiptPath: configuration.receiptPath,
          receiptSha256: intent.receiptSha256,
          ...observerProofDetail(intent.observerProofSha256),
          backupPolicy: "none",
        },
      );
    }
    commitment = completedReceiptCommitment(
      "deployment_receipt_commit",
    );
  }
  if (!commitment) {
    throw new Error("Fixture target receipt was not durably committed");
  }
  await blockForSigkill("target_receipt_committed");
  const journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  if (!journal.terminal) {
    appendFunctionalReleaseTransactionRecord(configuration.journalDirectory, {
      event: "terminal",
      detail: {
        outcome: "deployed",
        receiptPath: configuration.receiptPath,
        backupPolicy: "none",
        deploymentMode: FORWARD_V2
          ? "current_service"
          : "historical_preview",
        receiptSha256: commitment.receiptSha256,
        ...(FORWARD_V2
          ? {
            observerProofSha256: commitment.observerProofSha256,
            receiptObserverProofSha256:
              commitment.observerProofSha256,
            reconciliationObserverProofSha256:
              releaseTransactionSha256(STANDALONE_RELEASE_OBSERVER),
          }
          : {
            cutoverEligible: false,
            legacyIdentitySha256: commitment.observerProofSha256,
            receiptLegacyIdentitySha256:
              commitment.observerProofSha256,
            reconciliationLegacyIdentitySha256:
              releaseTransactionSha256(readLegacyIdentity()),
          }),
      },
    });
  }
}

async function restoreSourceBeforeSchemaCommit(cause: unknown): Promise<void> {
  const before = readState();
  if (before.schema !== SOURCE_SCHEMA) {
    throw new Error("Source recovery refused after schema commit");
  }
  const entryJournal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  if (
    !preparedRestoredReceiptCommitment() &&
    !completedRestoredReceiptCommitment() &&
    !entryJournal.terminal
  ) {
    writeReceipt({
      ...readReceipt(),
      recoveryHostBootId: readFileSync(
        configuration.hostBootIdPath,
        "utf8",
      ).trim(),
      legacyRecoveryBaseline: readLegacyIdentity(),
    });
  }
  ensureRecoveryStarted("restore_predeploy");
  await ensureMutation("recovery", "service_stop_for_recovery", () => {
    const state = readState();
    writeState({
      ...state,
      tiScale: { ...state.tiScale, active: false },
    });
  });
  await ensureMutation("recovery", "source_state_verification", () => {
    let state = readState();
    if (
      !["source-application", "target-application"].includes(
        state.application,
      ) ||
      !["source-static", "target-static"].includes(state.staticRelease)
    ) {
      throw new Error("Source fixture pointers are outside the immutable pair");
    }
    if (
      state.application !== "source-application" ||
      state.staticRelease !== "source-static"
    ) {
      state = {
        ...state,
        application: "source-application",
        staticRelease: "source-static",
      };
      writeState(state);
    }
    if (
      state.schema !== SOURCE_SCHEMA ||
      databaseSchema() !== SOURCE_SCHEMA ||
      state.application !== "source-application" ||
      state.staticRelease !== "source-static"
    ) {
      throw new Error("Source fixture state is not exact");
    }
  });
  let runningState = readState();
  await ensureMutation("recovery", "service_start", () => {
    runningState = startFixtureService("source");
  }, {
    mode: "journal_guarded",
    sourceSchema: SOURCE_SCHEMA,
    backupPolicy: "none",
  }, () => ({
    invocationId: runningState.tiScale.invocationId,
    healthStatus: 200,
  }));
  const immutableSource = sourceState();
  await ensureMutation(
    "recovery",
    RELEASE_SOURCE_RUNTIME_COMMIT_MUTATION,
    () => {
      const state = readState();
      if (!state.tiScale.active || state.tiScale.runtime !== "source") {
        throw new Error("Source runtime is not active at commitment");
      }
    },
    {
      sourceState: immutableSource,
      sourceStateSha256: releaseTransactionSha256(immutableSource),
    },
    () => ({ outcome: "already_exact" }),
  );
  let journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  let restoreState = stateOfMutation(
    journal,
    "recovery",
    "deployment_receipt_restore",
  );
  let restoredCommitment = completedRestoredReceiptCommitment();
  let restoredIntent = preparedRestoredReceiptCommitment();
  const restoredReceiptSha256 = restoredCommitment?.receiptSha256 ??
    restoredIntent?.receiptSha256 ??
    fileSha256(configuration.receiptPath);
  const restoredObserverProofSha256 =
    restoredCommitment?.observerProofSha256 ??
    restoredIntent?.observerProofSha256 ??
    releaseTransactionSha256(
      FORWARD_V2
        ? STANDALONE_RELEASE_OBSERVER
        : readLegacyIdentity(),
    );
  if (restoreState === "unseen") {
    prepareFunctionalReleaseMutation(
      configuration.journalDirectory,
      "recovery",
      "deployment_receipt_restore",
      {
        receiptPath: configuration.receiptPath,
        receiptSha256: restoredReceiptSha256,
        ...observerProofDetail(restoredObserverProofSha256),
        backupPolicy: "none",
      },
    );
    restoreState = "prepared";
    restoredIntent = preparedRestoredReceiptCommitment();
  }
  await blockForSigkill("source_restore_prepared");
  if (restoreState === "prepared") {
    if (
      !restoredIntent ||
      restoredIntent.receiptSha256 !== restoredReceiptSha256 ||
      restoredIntent.observerProofSha256 !==
        restoredObserverProofSha256 ||
      fileSha256(configuration.receiptPath) !==
        restoredIntent.receiptSha256
    ) {
      throw new Error("Fixture source receipt restore intent changed");
    }
    completeFunctionalReleaseMutation(
      configuration.journalDirectory,
      "recovery",
      "deployment_receipt_restore",
      {
        outcome: "already_exact",
        receiptPath: configuration.receiptPath,
        receiptSha256: restoredReceiptSha256,
        ...observerProofDetail(restoredObserverProofSha256),
        backupPolicy: "none",
      },
    );
    restoredCommitment = completedRestoredReceiptCommitment();
  }
  if (!restoredCommitment) {
    throw new Error("Fixture source receipt restoration was not committed");
  }
  clearReleaseStartupMutationBarrier(
    readFunctionalReleaseTransactionJournal(configuration.journalDirectory),
    configuration.startupMutationBarrierPath,
  );
  await ensureMutation("recovery", "runtime_activation", () => {
    const state = readState();
    if (!state.tiScale.active || state.tiScale.runtime !== "source") {
      throw new Error("Source fixture runtime activation is not exact");
    }
  });
  await ensureMutation("recovery", "running_state_verification", () => {
    const state = readState();
    if (
      state.schema !== SOURCE_SCHEMA ||
      databaseSchema() !== SOURCE_SCHEMA ||
      state.application !== "source-application" ||
      state.staticRelease !== "source-static" ||
      !state.tiScale.active ||
      state.tiScale.runtime !== "source"
    ) {
      throw new Error("Recovered source running state is not exact");
    }
  });
  let commitment = completedReceiptCommitment(
    "terminal_receipt_commit",
  );
  if (!commitment) {
    let intent = receiptIntent("terminal_receipt_commit");
    if (!intent) {
      const legacyProof = readLegacyIdentity();
      const receipt: FixtureReceipt = {
        ...assertInventoryAndLegacy(readReceipt(), legacyProof),
        status: "failed_predeploy_restored",
        forwardRecoveryRequired: false,
        failure: cause instanceof Error ? cause.message : String(cause),
      };
      intent = {
        receipt,
        receiptSha256: receiptSha256(receipt),
        observerProofSha256: releaseTransactionSha256(
          receiptObserverProof(receipt),
        ),
      };
    }
    if (
      stateOfMutation(
        readFunctionalReleaseTransactionJournal(
          configuration.journalDirectory,
        ),
        "recovery",
        "terminal_receipt_commit",
      ) === "unseen"
    ) {
      prepareFunctionalReleaseMutation(
        configuration.journalDirectory,
        "recovery",
        "terminal_receipt_commit",
        {
          receiptPath: configuration.receiptPath,
          receipt: intent.receipt,
          receiptSha256: intent.receiptSha256,
          ...observerProofDetail(intent.observerProofSha256),
          backupPolicy: "none",
        },
      );
    }
    await blockForSigkill("source_receipt_prepared");
    writeReceipt(intent.receipt);
    if (fileSha256(configuration.receiptPath) !== intent.receiptSha256) {
      throw new Error("Fixture source receipt write differs from intent");
    }
    if (
      stateOfMutation(
        readFunctionalReleaseTransactionJournal(
          configuration.journalDirectory,
        ),
        "recovery",
        "terminal_receipt_commit",
      ) === "prepared"
    ) {
      completeFunctionalReleaseMutation(
        configuration.journalDirectory,
        "recovery",
        "terminal_receipt_commit",
        {
          receiptPath: configuration.receiptPath,
          receiptSha256: intent.receiptSha256,
          ...observerProofDetail(intent.observerProofSha256),
          backupPolicy: "none",
        },
      );
    }
    commitment = completedReceiptCommitment(
      "terminal_receipt_commit",
    );
  }
  if (!commitment) {
    throw new Error("Fixture source terminal receipt was not committed");
  }
  await blockForSigkill("source_receipt_committed");
  journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  if (!journal.terminal) {
    appendFunctionalReleaseTransactionRecord(configuration.journalDirectory, {
      event: "terminal",
      detail: {
        outcome: "predeploy_restored",
        receiptPath: configuration.receiptPath,
        backupPolicy: "none",
        deploymentMode: FORWARD_V2
          ? "current_service"
          : "historical_preview",
        receiptSha256: commitment.receiptSha256,
        ...(FORWARD_V2
          ? {
            observerProofSha256: commitment.observerProofSha256,
            receiptObserverProofSha256:
              commitment.observerProofSha256,
            reconciliationObserverProofSha256:
              releaseTransactionSha256(STANDALONE_RELEASE_OBSERVER),
          }
          : {
            legacyIdentitySha256: commitment.observerProofSha256,
            receiptLegacyIdentitySha256:
              commitment.observerProofSha256,
            reconciliationLegacyIdentitySha256:
              releaseTransactionSha256(readLegacyIdentity()),
          }),
        restoredReceiptSha256,
        ...(FORWARD_V2
          ? {
            restoredObserverProofSha256:
              restoredCommitment.observerProofSha256,
          }
          : {
            restoredLegacyIdentitySha256:
              restoredCommitment.observerProofSha256,
          }),
      },
    });
  }
}

async function ensureTargetCommitted(): Promise<void> {
  await withMaintenance(async () => {
    if (
      stateOfMutation(
        readFunctionalReleaseTransactionJournal(
          configuration.journalDirectory,
        ),
        "forward",
        "database_migration",
      ) !== "completed"
    ) {
      await migrate();
    }
    if (assertJsonAndDatabaseSchemaMatch() !== TARGET_SCHEMA) {
      throw new Error(
        `Forward-only completion requires schema ${String(TARGET_SCHEMA)}`,
      );
    }
    await commitTarget();
  });
}

async function runController(): Promise<NoBackupForwardOnlyControllerResult> {
  if (controllerCommand === "deploy") initializeDeployment();
  if (!existsSync(configuration.journalDirectory)) {
    throw new Error("Recovery has no prepared transaction journal");
  }
  if (controllerCommand === "recover") {
    new OrphanedNoBackupMaintenanceLeaseReconciler().reconcile({
      transactionRoot: configuration.transactionRoot,
      journalDirectory: configuration.journalDirectory,
      releaseId: configuration.releaseId,
      databasePath: configuration.leaseDatabasePath,
      maintenanceMarkerPath: configuration.maintenanceMarkerPath,
      releaseLockPath: configuration.releaseLockPath,
      stopped: {
        activeState: "inactive",
        mainPid: 0,
        controlGroup: "/system.slice/ti-scale.service",
        controlGroupProcessIds: [],
        portListening: false,
      },
      assertNoDatabaseHandles: () => {
        const paths = [
          configuration.leaseDatabasePath,
          `${configuration.leaseDatabasePath}-wal`,
          `${configuration.leaseDatabasePath}-shm`,
        ].filter(existsSync);
        const inspection = Bun.spawnSync([
          "/usr/bin/lsof",
          "-t",
          "--",
          ...paths,
        ], {
          cwd: "/",
          stdin: "ignore",
          stdout: "pipe",
          stderr: "pipe",
        });
        if (
          !(
            (inspection.exitCode === 1 && inspection.stdout.length === 0) ||
            (inspection.exitCode === 0 && inspection.stdout.length === 0)
          )
        ) {
          throw new Error("Fixture canonical database still has process handles");
        }
      },
      actorId: `no-backup-recovery:${process.pid}`,
    });
  }
  return executeNoBackupForwardOnlyController({
    command: controllerCommand,
    sourceSchema: SOURCE_SCHEMA,
    targetSchema: TARGET_SCHEMA,
    forwardSchemas: FORWARD_SCHEMAS,
    operations: {
      stop,
      withMaintenance,
      migrate,
      commitTarget,
      startAndFinalize,
      observedSchema: databaseSchema,
      durableTargetCommitted: () =>
        Boolean(functionalReleaseTargetCommitRecord(
          readFunctionalReleaseTransactionJournal(
            configuration.journalDirectory,
          ),
        )),
      restoreSourceBeforeSchemaCommit,
      ensureTargetCommitted,
      recordForwardRecoveryFailure: (primaryFailure, recoveryFailure) => {
        const receipt = readReceipt();
        writeReceipt({
          ...receipt,
          status: "failed_forward_recovery_required",
          forwardRecoveryRequired: true,
          failure:
            `${primaryFailure instanceof Error ? primaryFailure.message : String(primaryFailure)}; ` +
            `${recoveryFailure instanceof Error ? recoveryFailure.message : String(recoveryFailure)}`,
        });
      },
    },
  });
}

try {
const result = await withSharedReleaseLock(runController, {
    path: configuration.releaseLockPath,
    operation: `no-backup-full-controller-fixture:${controllerCommand}`,
  });
  writeDurableFileAtomically(
    configuration.resultPath,
    `${JSON.stringify(result)}\n`,
    { mode: 0o600 },
  );
} catch (error) {
  process.stderr.write(
    `${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}\n`,
  );
  process.exitCode = 1;
}

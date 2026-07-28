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
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import {
  assertNoBackupPayloadInventoryUnchanged,
  captureNoBackupPayloadInventory,
  type NoBackupPayloadInventory,
} from "../../../scripts/release/NoBackupPreviewRelease";
import {
  functionalReleaseTargetCommitRecord,
  readFunctionalReleaseTransactionJournal,
  releaseTransactionSha256,
} from "../../../scripts/release/DurableReleaseTransaction";
import { createDatabaseConnection } from "../../../server/db/connection";
import { migrateDatabase } from "../../../server/db/migrations/runner";
import { DATABASE_MIGRATIONS } from "../../../server/db/migrations";
import type { Migration } from "../../../server/db/types";

interface FixtureServiceIdentity {
  readonly pid: number;
  readonly invocationId: string;
  readonly status: "ok";
}

interface FixtureState {
  readonly schema: number;
  readonly application: "source-application" | "target-application";
  readonly staticRelease: "source-static" | "target-static";
  readonly tiScale: {
    readonly active: boolean;
    readonly runtime: "source" | "target";
    readonly invocationId: string;
    readonly generation: number;
  };
}

interface FixtureReceipt {
  readonly schemaVersion:
    | "ti-scale.no-backup-preview-release-receipt.v1"
    | "ti-scale.no-backup-forward-release-receipt.v2";
  readonly status: string;
  readonly backupPolicy: "none";
  readonly cutoverEligible?: false;
  readonly deploymentMode?: "current_service";
  readonly releaseObserver?: typeof STANDALONE_RELEASE_OBSERVER;
  readonly rollbackCapability: "none_after_schema_commit";
  readonly sourceSchema: number;
  readonly targetSchema: number;
  readonly legacyBefore?: FixtureServiceIdentity;
  readonly legacyAfter?: FixtureServiceIdentity;
  readonly schemaCommitted?: boolean;
  readonly forwardRecoveryRequired?: boolean;
  readonly backupPayloadInventoryBefore: NoBackupPayloadInventory;
  readonly backupPayloadInventoryAfter?: NoBackupPayloadInventory;
  readonly backupPayloadInventoryUnchanged?: boolean;
  readonly recoveryHostBootId?: string;
  readonly legacyRecoveryBaseline?: FixtureServiceIdentity;
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

interface BoundaryReceipt {
  readonly boundary:
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
  readonly controllerPid: number;
  readonly state: FixtureState;
}

type CrashBoundary = BoundaryReceipt["boundary"] | "none";

const SOURCE_SCHEMA = 47;
const TARGET_SCHEMA = 60;
const STANDALONE_RELEASE_OBSERVER = Object.freeze({
  schemaVersion: "ti-scale.release-observer.v1" as const,
  mode: "standalone" as const,
  scope: "ti_scale_only" as const,
  externalServiceDependency: "none" as const,
});
const FORWARD_SCHEMAS = Object.freeze(
  Array.from(
    { length: TARGET_SCHEMA - SOURCE_SCHEMA },
    (_, index) => SOURCE_SCHEMA + index + 1,
  ),
);

const temporaryRoots: string[] = [];
const children = new Set<Bun.Subprocess>();
const workerPath = join(
  process.cwd(),
  "tests/unit/release/fixtures/no-backup-full-controller-worker.ts",
);

function withoutBackupRequirement(migration: Migration): Migration {
  const {
    requiresVerifiedBackup: _requiresVerifiedBackup,
    ...noBackupMigration
  } = migration;
  return noBackupMigration;
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function sqliteSchema(path: string): number {
  const database = createDatabaseConnection({
    filename: path,
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

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function replaceLegacyAndBootIdentity(
  configuration: FixtureConfiguration,
  seed: string,
): FixtureServiceIdentity {
  const identity: FixtureServiceIdentity = {
    pid: 4_000 + seed.charCodeAt(0),
    invocationId: seed.repeat(32).slice(0, 32),
    status: "ok",
  };
  writeFileSync(
    configuration.legacyIdentityPath,
    `${JSON.stringify(identity, null, 2)}\n`,
    { mode: 0o600 },
  );
  writeFileSync(
    configuration.hostBootIdPath,
    `${seed.repeat(32).slice(0, 32)}\n`,
    { mode: 0o600 },
  );
  return identity;
}

function clearCrashBoundary(
  configuration: FixtureConfiguration,
): void {
  rmSync(configuration.boundaryPath, { force: true });
}

async function waitForFile(path: string, timeoutMs = 8_000): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (!existsSync(path) && performance.now() < deadline) {
    await Bun.sleep(10);
  }
  if (!existsSync(path)) throw new Error(`Timed out waiting for ${path}`);
}

function setupFixture(
  suffix: string,
  schemas: {
    readonly sourceSchema: number;
    readonly targetSchema: number;
  } = {
    sourceSchema: SOURCE_SCHEMA,
    targetSchema: TARGET_SCHEMA,
  },
): {
  readonly root: string;
  readonly configurationPath: string;
  readonly configuration: FixtureConfiguration;
  readonly legacySha256: string;
} {
  const root = mkdtempSync(join(tmpdir(), `ti-scale-no-backup-full-${suffix}-`));
  temporaryRoots.push(root);
  const transactionRoot = join(root, "transactions");
  const metadataRoot = join(transactionRoot, `release-${suffix}`);
  const inventoryRootNames = [
    "var-backups-ti-scale",
    "var-lib-ti-scale-backups",
    "data-backups",
    "migration-backups",
    "hotfix-backups",
    "historical-sqlite-snapshots",
    "rehearsals",
    "release-rehearsal",
    "historical-base-backup",
  ] as const;
  const inventoryRoots = inventoryRootNames.map((name) =>
    join(root, "no-backup-payload-inventory", name)
  );
  mkdirSync(metadataRoot, { recursive: true, mode: 0o700 });
  for (const [index, inventoryRoot] of inventoryRoots.entries()) {
    mkdirSync(inventoryRoot, { recursive: true, mode: 0o700 });
    writeFileSync(
      join(inventoryRoot, "existing-state.bin"),
      `unchanged-state-${String(index)}\n`,
    );
  }

  const statePath = join(root, "state.json");
  const legacyIdentityPath = join(root, "legacy-service.json");
  const hostBootIdPath = join(root, "host-boot-id");
  const initialState: FixtureState = {
    schema: schemas.sourceSchema,
    application: "source-application",
    staticRelease: "source-static",
    tiScale: {
      active: true,
      runtime: "source",
      invocationId: "1".repeat(32),
      generation: 1,
    },
  };
  const legacyIdentity: FixtureServiceIdentity = {
    pid: 3131,
    invocationId: "c".repeat(32),
    status: "ok",
  };
  writeFileSync(statePath, `${JSON.stringify(initialState, null, 2)}\n`, {
    mode: 0o600,
  });
  writeFileSync(
    legacyIdentityPath,
    `${JSON.stringify(legacyIdentity, null, 2)}\n`,
    { mode: 0o600 },
  );
  writeFileSync(hostBootIdPath, `${"b".repeat(32)}\n`, { mode: 0o600 });

  const canonicalDataRoot = join(root, "canonical-data");
  mkdirSync(canonicalDataRoot, { recursive: true, mode: 0o700 });
  const leaseDatabasePath = join(canonicalDataRoot, "ti-scale.sqlite");
  const leaseDatabase = createDatabaseConnection({
    filename: leaseDatabasePath,
  });
  try {
    migrateDatabase(
      leaseDatabase,
      DATABASE_MIGRATIONS
        .slice(0, schemas.sourceSchema)
        .map(withoutBackupRequirement),
    );
  } finally {
    leaseDatabase.close();
  }
  const configuration: FixtureConfiguration = {
    releaseId: `release-${suffix}`,
    sourceSchema: schemas.sourceSchema,
    targetSchema: schemas.targetSchema,
    statePath,
    legacyIdentityPath,
    hostBootIdPath,
    receiptPath: join(metadataRoot, "no-backup-preview-receipt.json"),
    journalDirectory: join(metadataRoot, "transaction-journal"),
    transactionRoot,
    releaseLockPath: join(root, "release.lock"),
    authorizationPath: join(root, "service-start-authorization.json"),
    startupMutationBarrierPath: join(root, "startup-mutation-barrier.json"),
    leaseDatabasePath,
    maintenanceMarkerPath: `${leaseDatabasePath}.maintenance-lock.json`,
    boundaryPath: join(root, "crash-boundary.json"),
    resultPath: join(root, "controller-result.json"),
    inventoryRoots,
  };
  const configurationPath = join(root, "fixture-config.json");
  writeFileSync(
    configurationPath,
    `${JSON.stringify(configuration, null, 2)}\n`,
    { mode: 0o600 },
  );
  return {
    root,
    configurationPath,
    configuration,
    legacySha256: sha256(legacyIdentityPath),
  };
}

function spawnController(
  configurationPath: string,
  command: "deploy" | "recover",
  crashBoundary: CrashBoundary,
): Bun.Subprocess {
  const child = Bun.spawn([
    process.execPath,
    workerPath,
    command,
    configurationPath,
    crashBoundary,
  ], {
    cwd: process.cwd(),
    stdout: "pipe",
    stderr: "pipe",
  });
  children.add(child);
  return child;
}

async function killAtBoundary(
  configuration: FixtureConfiguration,
  deploy: Bun.Subprocess,
): Promise<BoundaryReceipt> {
  await waitForFile(configuration.boundaryPath);
  const boundary = readJson<BoundaryReceipt>(configuration.boundaryPath);
  expect(boundary.controllerPid).toBe(deploy.pid);
  deploy.kill("SIGKILL");
  expect(await deploy.exited).not.toBe(0);
  children.delete(deploy);
  return boundary;
}

async function recoverInFreshProcess(
  configurationPath: string,
  crashedPid: number,
  configuration: FixtureConfiguration,
): Promise<void> {
  const recover = spawnController(configurationPath, "recover", "none");
  expect(recover.pid).not.toBe(crashedPid);
  const [exitCode, stdout, stderr] = await Promise.all([
    recover.exited,
    new Response(recover.stdout).text(),
    new Response(recover.stderr).text(),
  ]);
  children.delete(recover);
  if (exitCode !== 0) {
    throw new Error(
      `Fresh recovery process exited ${exitCode}: ${stderr || stdout}`,
    );
  }
  expect(stdout).toBe("");
  expect(stderr).toBe("");
  await waitForFile(configuration.resultPath);
}

function regularFiles(root: string): readonly string[] {
  const paths: string[] = [];
  const visit = (path: string): void => {
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink()) return;
    if (metadata.isDirectory()) {
      for (const name of readdirSync(path)) visit(join(path, name));
      return;
    }
    if (metadata.isFile()) paths.push(path);
  };
  visit(root);
  return paths.sort((left, right) => left.localeCompare(right, "en"));
}

function assertNoAuthorizationResidue(
  root: string,
  authorizationPath: string,
): void {
  expect(existsSync(authorizationPath)).toBe(false);
  const authorizationName = basename(authorizationPath);
  for (const path of regularFiles(root)) {
    expect(basename(path).startsWith(`${authorizationName}.`)).toBe(false);
    const bytes = readFileSync(path);
    expect(bytes.includes(
      Buffer.from("ti-scale.release-service-start-authorization.v2"),
    )).toBe(false);
  }
}

function assertNoMigrationCopyArtifacts(databasePath: string): void {
  const databaseName = basename(databasePath);
  const allowed = new Set([
    databaseName,
    `${databaseName}-wal`,
    `${databaseName}-shm`,
  ]);
  const unexpected = readdirSync(dirname(databasePath))
    .filter((name) => !allowed.has(name));
  expect(unexpected).toEqual([]);
}

function receiptMutationCommitment(
  configuration: FixtureConfiguration,
  event: "mutation_prepared" | "mutation_completed",
  mutation:
    | "deployment_receipt_commit"
    | "deployment_receipt_restore"
    | "terminal_receipt_commit",
): {
  readonly receiptSha256: string;
  readonly observerProofSha256: string;
} {
  const record = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  ).records.find((candidate) =>
    candidate.event === event &&
    candidate.mutation === mutation
  );
  const receiptSha256 = record?.detail?.receiptSha256;
  const proofField = configuration.sourceSchema === 60 &&
      configuration.targetSchema === 60
    ? "observerProofSha256"
    : "legacyIdentitySha256";
  const observerProofSha256 = record?.detail?.[proofField];
  expect(receiptSha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(observerProofSha256).toMatch(/^[a-f0-9]{64}$/u);
  return {
    receiptSha256: String(receiptSha256),
    observerProofSha256: String(observerProofSha256),
  };
}

function assertTerminalHashes(
  configuration: FixtureConfiguration,
  receiptCommitment: {
    readonly receiptSha256: string;
    readonly observerProofSha256: string;
  },
  currentLegacy: FixtureServiceIdentity,
): void {
  const terminal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  ).terminal;
  expect(terminal?.detail?.receiptSha256)
    .toBe(receiptCommitment.receiptSha256);
  if (
    configuration.sourceSchema === 60 &&
    configuration.targetSchema === 60
  ) {
    const observerSha256 = releaseTransactionSha256(
      STANDALONE_RELEASE_OBSERVER,
    );
    expect(terminal?.detail?.deploymentMode).toBe("current_service");
    expect(terminal?.detail?.observerProofSha256)
      .toBe(receiptCommitment.observerProofSha256);
    expect(terminal?.detail?.receiptObserverProofSha256)
      .toBe(receiptCommitment.observerProofSha256);
    expect(terminal?.detail?.reconciliationObserverProofSha256)
      .toBe(observerSha256);
    expect(terminal?.detail?.legacyIdentitySha256).toBeUndefined();
    return;
  }
  expect(terminal?.detail?.legacyIdentitySha256)
    .toBe(receiptCommitment.observerProofSha256);
  expect(terminal?.detail?.receiptLegacyIdentitySha256)
    .toBe(receiptCommitment.observerProofSha256);
  expect(terminal?.detail?.reconciliationLegacyIdentitySha256)
    .toBe(releaseTransactionSha256(currentLegacy));
}

function assertCommonTerminalProof(
  root: string,
  configuration: FixtureConfiguration,
  legacySha256: string,
  expectedStatus: "failed_predeploy_restored" | "deployed",
  expectedOutcome: "predeploy_restored" | "deployed",
  expectedLegacyAfter?: FixtureServiceIdentity,
): FixtureReceipt {
  const receipt = readJson<FixtureReceipt>(configuration.receiptPath);
  expect(receipt).toMatchObject({
    status: expectedStatus,
    backupPolicy: "none",
    rollbackCapability: "none_after_schema_commit",
    sourceSchema: configuration.sourceSchema,
    targetSchema: configuration.targetSchema,
    forwardRecoveryRequired: false,
    backupPayloadInventoryUnchanged: true,
  });
  const forwardV2 = configuration.sourceSchema === 60 &&
    configuration.targetSchema === 60;
  if (forwardV2) {
    expect(receipt).toMatchObject({
      schemaVersion: "ti-scale.no-backup-forward-release-receipt.v2",
      deploymentMode: "current_service",
      releaseObserver: STANDALONE_RELEASE_OBSERVER,
    });
    expect(receipt.cutoverEligible).toBeUndefined();
    expect(receipt.legacyBefore).toBeUndefined();
    expect(receipt.legacyAfter).toBeUndefined();
  } else {
    expect(receipt).toMatchObject({
      schemaVersion: "ti-scale.no-backup-preview-release-receipt.v1",
      cutoverEligible: false,
    });
    expect(receipt.legacyAfter).toEqual(
      expectedLegacyAfter ?? receipt.legacyBefore,
    );
  }
  expect(sha256(configuration.legacyIdentityPath)).toBe(legacySha256);

  const inventoryAfter = captureNoBackupPayloadInventory(
    receipt.backupPayloadInventoryBefore.roots,
  );
  assertNoBackupPayloadInventoryUnchanged(
    receipt.backupPayloadInventoryBefore,
    inventoryAfter,
  );
  expect(receipt.backupPayloadInventoryAfter).toEqual(inventoryAfter);
  expect(inventoryAfter.entries).toHaveLength(9);

  const journal = readFunctionalReleaseTransactionJournal(
    configuration.journalDirectory,
  );
  expect(journal.terminal?.detail?.outcome).toBe(expectedOutcome);
  expect(journal.terminal?.detail?.backupPolicy).toBe("none");
  if (forwardV2) {
    const observerSha256 = releaseTransactionSha256(
      STANDALONE_RELEASE_OBSERVER,
    );
    const receiptRecords = journal.records.filter((record) =>
      record.mutation === "deployment_receipt_commit" ||
      record.mutation === "deployment_receipt_restore" ||
      record.mutation === "terminal_receipt_commit"
    );
    expect(receiptRecords.length).toBeGreaterThanOrEqual(2);
    for (const record of receiptRecords) {
      expect(record.detail?.observerProofSha256).toBe(observerSha256);
      expect(record.detail?.legacyIdentitySha256).toBeUndefined();
    }
    expect(journal.terminal?.detail).toMatchObject({
      deploymentMode: "current_service",
      observerProofSha256: observerSha256,
      receiptObserverProofSha256: observerSha256,
      reconciliationObserverProofSha256: observerSha256,
    });
    expect(journal.terminal?.detail?.legacyIdentitySha256).toBeUndefined();
  }
  expect(journal.binding.identity).toMatchObject(
    forwardV2
      ? {
        deploymentKind: "no_backup_forward_v2",
        deploymentMode: "current_service",
        releaseObserver: STANDALONE_RELEASE_OBSERVER,
      }
      : {
        deploymentKind: "no_backup_preview_v1",
      },
  );
  expect(existsSync(configuration.maintenanceMarkerPath)).toBe(false);
  expect(existsSync(configuration.startupMutationBarrierPath)).toBe(false);
  expect(sqliteSchema(configuration.leaseDatabasePath)).toBe(
    expectedStatus === "deployed"
      ? configuration.targetSchema
      : configuration.sourceSchema,
  );
  assertNoMigrationCopyArtifacts(configuration.leaseDatabasePath);
  assertNoAuthorizationResidue(root, configuration.authorizationPath);
  return receipt;
}

afterEach(async () => {
  for (const child of children) {
    if (child.exitCode === null) child.kill("SIGKILL");
    await child.exited;
  }
  children.clear();
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("full no-backup controller process recovery", () => {
  test("cleanly deploys the exact schema-47 source through schema 60", async () => {
    const fixture = setupFixture("clean-47-to-60");
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "none",
    );
    const [exitCode, stdout, stderr] = await Promise.all([
      deploy.exited,
      new Response(deploy.stdout).text(),
      new Response(deploy.stderr).text(),
    ]);
    children.delete(deploy);
    if (exitCode !== 0) {
      throw new Error(
        `Clean no-backup deploy exited ${String(exitCode)}: ${stderr || stdout}`,
      );
    }
    expect(exitCode).toBe(0);
    expect(stdout).toBe("");
    expect(stderr).toBe("");
    await waitForFile(fixture.configuration.resultPath);
    expect(readJson<FixtureState>(fixture.configuration.statePath))
      .toMatchObject({
        schema: TARGET_SCHEMA,
        application: "target-application",
        staticRelease: "target-static",
        tiScale: { active: true, runtime: "target" },
      });
    const receipt = assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      fixture.legacySha256,
      "deployed",
      "deployed",
    );
    expect(receipt.schemaCommitted).toBe(true);
  }, 30_000);

  test("cleanly deploys an exact schema-60 source to a new schema-60 target", async () => {
    const fixture = setupFixture("clean-60-to-60", {
      sourceSchema: 60,
      targetSchema: 60,
    });
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "none",
    );
    const [exitCode, stdout, stderr] = await Promise.all([
      deploy.exited,
      new Response(deploy.stdout).text(),
      new Response(deploy.stderr).text(),
    ]);
    children.delete(deploy);
    if (exitCode !== 0) {
      throw new Error(
        `Clean same-schema deploy exited ${String(exitCode)}: ${stderr || stdout}`,
      );
    }
    expect(stdout).toBe("");
    expect(stderr).toBe("");
    expect(readJson<FixtureState>(fixture.configuration.statePath))
      .toMatchObject({
        schema: 60,
        application: "target-application",
        staticRelease: "target-static",
        tiScale: { active: true, runtime: "target" },
      });
    const receipt = assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      fixture.legacySha256,
      "deployed",
      "deployed",
    );
    expect(receipt.schemaCommitted).toBe(true);
  }, 30_000);

  test("same-schema SIGKILL before target commitment restores source pointers", async () => {
    const fixture = setupFixture("same-schema-target-precommit", {
      sourceSchema: 60,
      targetSchema: 60,
    });
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "target_precommit",
    );
    const boundary = await killAtBoundary(fixture.configuration, deploy);
    expect(boundary.boundary).toBe("target_precommit");
    expect(boundary.state).toMatchObject({
      schema: 60,
      application: "target-application",
      staticRelease: "target-static",
      tiScale: { active: false, runtime: "source" },
    });
    expect(functionalReleaseTargetCommitRecord(
      readFunctionalReleaseTransactionJournal(
        fixture.configuration.journalDirectory,
      ),
    )).toBeUndefined();

    await recoverInFreshProcess(
      fixture.configurationPath,
      boundary.controllerPid,
      fixture.configuration,
    );

    expect(readJson<FixtureState>(fixture.configuration.statePath))
      .toMatchObject({
        schema: 60,
        application: "source-application",
        staticRelease: "source-static",
        tiScale: { active: true, runtime: "source" },
      });
    assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      fixture.legacySha256,
      "failed_predeploy_restored",
      "predeploy_restored",
    );
  }, 30_000);

  test("same-schema SIGKILL after target commitment completes target forward", async () => {
    const fixture = setupFixture("same-schema-target-committed", {
      sourceSchema: 60,
      targetSchema: 60,
    });
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "target_committed",
    );
    const boundary = await killAtBoundary(fixture.configuration, deploy);
    expect(boundary.boundary).toBe("target_committed");
    expect(boundary.state).toMatchObject({
      schema: 60,
      application: "target-application",
      staticRelease: "target-static",
      tiScale: { active: false, runtime: "source" },
    });
    expect(functionalReleaseTargetCommitRecord(
      readFunctionalReleaseTransactionJournal(
        fixture.configuration.journalDirectory,
      ),
    )).toBeDefined();

    await recoverInFreshProcess(
      fixture.configurationPath,
      boundary.controllerPid,
      fixture.configuration,
    );

    expect(readJson<FixtureState>(fixture.configuration.statePath))
      .toMatchObject({
        schema: 60,
        application: "target-application",
        staticRelease: "target-static",
        tiScale: { active: true, runtime: "target" },
      });
    assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      fixture.legacySha256,
      "deployed",
      "deployed",
    );
  }, 30_000);

  test("SIGKILL before schema commit restores the exact source in a new process", async () => {
    const fixture = setupFixture("pre-schema");
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "pre_schema",
    );
    const boundary = await killAtBoundary(fixture.configuration, deploy);
    expect(boundary.boundary).toBe("pre_schema");
    expect(boundary.state).toMatchObject({
      schema: SOURCE_SCHEMA,
      application: "source-application",
      staticRelease: "source-static",
      tiScale: { active: false, runtime: "source" },
    });
    expect(existsSync(fixture.configuration.maintenanceMarkerPath)).toBe(true);
    const interruptedJournal = readFunctionalReleaseTransactionJournal(
      fixture.configuration.journalDirectory,
    );
    expect(interruptedJournal.terminal).toBeUndefined();
    expect(functionalReleaseTargetCommitRecord(interruptedJournal)).toBeUndefined();

    await recoverInFreshProcess(
      fixture.configurationPath,
      boundary.controllerPid,
      fixture.configuration,
    );

    expect(readJson<FixtureState>(fixture.configuration.statePath)).toMatchObject({
      schema: SOURCE_SCHEMA,
      application: "source-application",
      staticRelease: "source-static",
      tiScale: { active: true, runtime: "source" },
    });
    const receipt = assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      fixture.legacySha256,
      "failed_predeploy_restored",
      "predeploy_restored",
    );
    expect(receipt.schemaCommitted).not.toBe(true);
    expect(functionalReleaseTargetCommitRecord(
      readFunctionalReleaseTransactionJournal(
        fixture.configuration.journalDirectory,
      ),
    )).toBeUndefined();
  }, 20_000);

  test("SIGKILL after schema commit can only complete the exact target forward", async () => {
    const fixture = setupFixture("post-schema");
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "post_schema",
    );
    const boundary = await killAtBoundary(fixture.configuration, deploy);
    expect(boundary.boundary).toBe("post_schema");
    expect(boundary.state).toMatchObject({
      schema: TARGET_SCHEMA,
      application: "source-application",
      staticRelease: "source-static",
      tiScale: { active: false, runtime: "source" },
    });
    expect(existsSync(fixture.configuration.maintenanceMarkerPath)).toBe(true);
    const interruptedJournal = readFunctionalReleaseTransactionJournal(
      fixture.configuration.journalDirectory,
    );
    expect(interruptedJournal.terminal).toBeUndefined();
    expect(functionalReleaseTargetCommitRecord(interruptedJournal)).toBeUndefined();

    await recoverInFreshProcess(
      fixture.configurationPath,
      boundary.controllerPid,
      fixture.configuration,
    );

    expect(readJson<FixtureState>(fixture.configuration.statePath)).toMatchObject({
      schema: TARGET_SCHEMA,
      application: "target-application",
      staticRelease: "target-static",
      tiScale: { active: true, runtime: "target" },
    });
    const receipt = assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      fixture.legacySha256,
      "deployed",
      "deployed",
    );
    expect(receipt.schemaCommitted).toBe(true);
    expect(functionalReleaseTargetCommitRecord(
      readFunctionalReleaseTransactionJournal(
        fixture.configuration.journalDirectory,
      ),
    )).toBeDefined();
  }, 20_000);

  test("resumes forward after SIGKILL at every committed schema 48 through 60", async () => {
    for (const intermediateSchema of FORWARD_SCHEMAS) {
      const fixture = setupFixture(
        `schema-${String(intermediateSchema)}`,
      );
      const crashBoundary =
        `schema_${String(intermediateSchema)}` as `schema_${number}`;
      const deploy = spawnController(
        fixture.configurationPath,
        "deploy",
        crashBoundary,
      );
      const boundary = await killAtBoundary(
        fixture.configuration,
        deploy,
      );
      expect(boundary.boundary).toBe(crashBoundary);
      expect(boundary.state).toMatchObject({
        schema: intermediateSchema,
        application: "source-application",
        staticRelease: "source-static",
        tiScale: { active: false, runtime: "source" },
      });
      expect(sqliteSchema(fixture.configuration.leaseDatabasePath))
        .toBe(intermediateSchema);
      const interruptedJournal = readFunctionalReleaseTransactionJournal(
        fixture.configuration.journalDirectory,
      );
      expect(interruptedJournal.records.some((record) =>
        record.event === "mutation_prepared" &&
        record.direction === "forward" &&
        record.mutation === "database_migration"
      )).toBe(true);
      expect(interruptedJournal.records.some((record) =>
        record.event === "mutation_completed" &&
        record.direction === "forward" &&
        record.mutation === "database_migration"
      )).toBe(false);
      expect(functionalReleaseTargetCommitRecord(interruptedJournal))
        .toBeUndefined();

      await recoverInFreshProcess(
        fixture.configurationPath,
        boundary.controllerPid,
        fixture.configuration,
      );

      expect(readJson<FixtureState>(fixture.configuration.statePath))
        .toMatchObject({
          schema: TARGET_SCHEMA,
          application: "target-application",
          staticRelease: "target-static",
          tiScale: { active: true, runtime: "target" },
        });
      const receipt = assertCommonTerminalProof(
        fixture.root,
        fixture.configuration,
        fixture.legacySha256,
        "deployed",
        "deployed",
      );
      expect(receipt.schemaCommitted).toBe(true);
      expect(functionalReleaseTargetCommitRecord(
        readFunctionalReleaseTransactionJournal(
          fixture.configuration.journalDirectory,
        ),
      )).toBeDefined();

      rmSync(fixture.root, { recursive: true, force: true });
      const fixtureIndex = temporaryRoots.indexOf(fixture.root);
      if (fixtureIndex >= 0) temporaryRoots.splice(fixtureIndex, 1);
    }
  }, 180_000);

  test("target receipt preparation replays exact bytes after legacy identity changes", async () => {
    const fixture = setupFixture("target-receipt-prepared");
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "target_receipt_prepared",
    );
    const boundary = await killAtBoundary(fixture.configuration, deploy);
    expect(boundary.boundary).toBe("target_receipt_prepared");
    expect(sqliteSchema(fixture.configuration.leaseDatabasePath))
      .toBe(TARGET_SCHEMA);
    const commitment = receiptMutationCommitment(
      fixture.configuration,
      "mutation_prepared",
      "deployment_receipt_commit",
    );
    const newLegacy = replaceLegacyAndBootIdentity(
      fixture.configuration,
      "d",
    );
    const newLegacyFileSha256 = sha256(
      fixture.configuration.legacyIdentityPath,
    );
    clearCrashBoundary(fixture.configuration);

    await recoverInFreshProcess(
      fixture.configurationPath,
      boundary.controllerPid,
      fixture.configuration,
    );

    expect(sha256(fixture.configuration.receiptPath))
      .toBe(commitment.receiptSha256);
    assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      newLegacyFileSha256,
      "deployed",
      "deployed",
    );
    assertTerminalHashes(
      fixture.configuration,
      commitment,
      newLegacy,
    );
  }, 30_000);

  test("committed target receipt remains immutable through a fresh recovery", async () => {
    const fixture = setupFixture("target-receipt-committed");
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "target_receipt_committed",
    );
    const boundary = await killAtBoundary(fixture.configuration, deploy);
    expect(boundary.boundary).toBe("target_receipt_committed");
    const commitment = receiptMutationCommitment(
      fixture.configuration,
      "mutation_completed",
      "deployment_receipt_commit",
    );
    expect(sha256(fixture.configuration.receiptPath))
      .toBe(commitment.receiptSha256);
    const newLegacy = replaceLegacyAndBootIdentity(
      fixture.configuration,
      "f",
    );
    const newLegacyFileSha256 = sha256(
      fixture.configuration.legacyIdentityPath,
    );
    clearCrashBoundary(fixture.configuration);

    await recoverInFreshProcess(
      fixture.configurationPath,
      boundary.controllerPid,
      fixture.configuration,
    );

    expect(sha256(fixture.configuration.receiptPath))
      .toBe(commitment.receiptSha256);
    assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      newLegacyFileSha256,
      "deployed",
      "deployed",
    );
    assertTerminalHashes(
      fixture.configuration,
      commitment,
      newLegacy,
    );
  }, 30_000);

  test("a target receipt written before completion is adopted only from its prepared hash", async () => {
    const fixture = setupFixture("target-receipt-written");
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "target_receipt_written",
    );
    const boundary = await killAtBoundary(fixture.configuration, deploy);
    const prepared = receiptMutationCommitment(
      fixture.configuration,
      "mutation_prepared",
      "deployment_receipt_commit",
    );
    expect(sha256(fixture.configuration.receiptPath))
      .toBe(prepared.receiptSha256);
    clearCrashBoundary(fixture.configuration);

    await recoverInFreshProcess(
      fixture.configurationPath,
      boundary.controllerPid,
      fixture.configuration,
    );

    expect(receiptMutationCommitment(
      fixture.configuration,
      "mutation_completed",
      "deployment_receipt_commit",
    )).toEqual(prepared);
    expect(sha256(fixture.configuration.receiptPath))
      .toBe(prepared.receiptSha256);
  }, 30_000);

  test("source receipt restoration replays its prepared intent across host and legacy changes", async () => {
    const fixture = setupFixture("source-restore-prepared");
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "pre_schema",
    );
    await killAtBoundary(
      fixture.configuration,
      deploy,
    );
    clearCrashBoundary(fixture.configuration);
    const recovery = spawnController(
      fixture.configurationPath,
      "recover",
      "source_restore_prepared",
    );
    const restoreBoundary = await killAtBoundary(
      fixture.configuration,
      recovery,
    );
    expect(restoreBoundary.boundary).toBe("source_restore_prepared");
    const restored = receiptMutationCommitment(
      fixture.configuration,
      "mutation_prepared",
      "deployment_receipt_restore",
    );
    expect(sha256(fixture.configuration.receiptPath))
      .toBe(restored.receiptSha256);
    const originalReceipt = readJson<FixtureReceipt>(
      fixture.configuration.receiptPath,
    );
    const newLegacy = replaceLegacyAndBootIdentity(
      fixture.configuration,
      "a",
    );
    const newLegacyFileSha256 = sha256(
      fixture.configuration.legacyIdentityPath,
    );
    clearCrashBoundary(fixture.configuration);

    await recoverInFreshProcess(
      fixture.configurationPath,
      restoreBoundary.controllerPid,
      fixture.configuration,
    );

    const receipt = assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      newLegacyFileSha256,
      "failed_predeploy_restored",
      "predeploy_restored",
      newLegacy,
    );
    expect(receipt.recoveryHostBootId)
      .toBe(originalReceipt.recoveryHostBootId);
    expect(receipt.legacyRecoveryBaseline)
      .toEqual(originalReceipt.legacyRecoveryBaseline);
    const terminal = readFunctionalReleaseTransactionJournal(
      fixture.configuration.journalDirectory,
    ).terminal;
    expect(terminal?.detail?.restoredReceiptSha256)
      .toBe(restored.receiptSha256);
    expect(terminal?.detail?.restoredLegacyIdentitySha256)
      .toBe(restored.observerProofSha256);
  }, 30_000);

  test("source terminal receipt preparation survives a second SIGKILL without recomputation", async () => {
    const fixture = setupFixture("source-terminal-prepared");
    const deploy = spawnController(
      fixture.configurationPath,
      "deploy",
      "pre_schema",
    );
    await killAtBoundary(fixture.configuration, deploy);
    clearCrashBoundary(fixture.configuration);
    const recovery = spawnController(
      fixture.configurationPath,
      "recover",
      "source_receipt_prepared",
    );
    const boundary = await killAtBoundary(
      fixture.configuration,
      recovery,
    );
    expect(boundary.boundary).toBe("source_receipt_prepared");
    const commitment = receiptMutationCommitment(
      fixture.configuration,
      "mutation_prepared",
      "terminal_receipt_commit",
    );
    const newLegacy = replaceLegacyAndBootIdentity(
      fixture.configuration,
      "9",
    );
    const newLegacyFileSha256 = sha256(
      fixture.configuration.legacyIdentityPath,
    );
    clearCrashBoundary(fixture.configuration);

    await recoverInFreshProcess(
      fixture.configurationPath,
      boundary.controllerPid,
      fixture.configuration,
    );

    expect(sha256(fixture.configuration.receiptPath))
      .toBe(commitment.receiptSha256);
    assertCommonTerminalProof(
      fixture.root,
      fixture.configuration,
      newLegacyFileSha256,
      "failed_predeploy_restored",
      "predeploy_restored",
    );
    assertTerminalHashes(
      fixture.configuration,
      commitment,
      newLegacy,
    );
  }, 30_000);
});

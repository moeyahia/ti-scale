import { createHash } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { discoverLegacyEngagements } from "../LegacyEngagementDiscovery";
import { LegacyMigrationService } from "../LegacyMigrationService";
import { HistoricalSourceDeltaPlanner } from "../HistoricalSourceDeltaPlanner";
import { canonicalJson, hashJson } from "../../orchestration/serialization";
import {
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
} from "../HistoricalSourceRootConfiguration";
import { discoverLegacySources } from "../SourceDiscovery";
import {
  HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION,
  inspectHistoricalSqliteSource,
} from "../HistoricalSqliteSnapshotService";
import {
  indexHistoricalSqliteSnapshotQuarantineFiles,
  loadHistoricalSqliteSnapshotQuarantineMapping,
} from "../HistoricalSqliteSnapshotQuarantineMapping";

const temporaryDirectories: string[] = [];
const children = new Set<ChildProcess>();

afterEach(() => {
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }
  children.clear();
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

async function strandedEmptySqlmapWal(path: string): Promise<void> {
  const child = spawn("node", [
    resolve("server/migration/__tests__/fixtures/StrandedEmptySqlmapWalWriter.cjs"),
    path,
  ], { cwd: resolve("."), stdio: ["ignore", "pipe", "pipe"] });
  children.add(child);
  await new Promise<void>((resolveReady, reject) => {
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      reject(new Error(`SQLMap WAL fixture exited early (${code ?? signal}): ${stderr}`));
    });
    child.stdout.on("data", (chunk) => {
      if (String(chunk).includes("STRANDED_EMPTY_SQLMAP_WAL_READY")) resolveReady();
    });
  });
  child.kill("SIGKILL");
  await new Promise<void>((resolveExit) => child.once("exit", () => resolveExit()));
  children.delete(child);
}

async function createSnapshotReceiptFixture(input: {
  readonly sourceDatabasePath: string;
  readonly sourceContainmentRoot: string;
  readonly destinationPath: string;
  readonly receiptPath: string;
  readonly normalizedStorageRows?: readonly Readonly<{
    id: number;
    value: string;
  }>[];
}): Promise<void> {
  const before = inspectHistoricalSqliteSource(input);
  const normalized = createDatabaseConnection({ filename: input.destinationPath });
  let totalPages: number;
  try {
    // This fixture models the independently normalized result of an empty
    // historical SQLMap database. It deliberately creates that result from
    // schema state instead of invoking the application backup API.
    normalized.exec("CREATE TABLE storage (id INTEGER PRIMARY KEY, value TEXT)");
    const insertStorage = normalized.prepare(
      "INSERT INTO storage (id, value) VALUES (?, ?)",
    );
    for (const row of input.normalizedStorageRows ?? []) {
      insertStorage.run(row.id, row.value);
    }
    normalized.pragma("journal_mode = DELETE");
    normalized.pragma("wal_checkpoint(TRUNCATE)");
    totalPages = Number(normalized.pragma("page_count", { simple: true }));
  } finally {
    normalized.close();
  }
  chmodSync(input.destinationPath, 0o600);
  const after = inspectHistoricalSqliteSource(input);
  expect(after.sourceBundleSha256).toBe(before.sourceBundleSha256);
  expect(after.files).toEqual(before.files);
  const normalizedBytes = lstatSync(input.destinationPath).size;
  const normalizedSha256 = sha256File(input.destinationPath);
  const receiptWithoutSeal = {
    schemaVersion: HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION,
    snapshotId: `test_snapshot_${normalizedSha256.slice(0, 32)}`,
    createdAt: "2026-07-24T00:00:00.000Z",
    method: "attested_byte_clone_then_readonly_sqlite_online_backup" as const,
    sourceBefore: before,
    sourceAfter: after,
    sourceUnchanged: true as const,
    normalizedSnapshot: {
      path: input.destinationPath,
      sha256: normalizedSha256,
      sizeBytes: normalizedBytes,
      mode: "0600" as const,
      sqliteOnlineBackupPages: totalPages,
      quickCheck: ["ok"] as const,
      integrityCheck: ["ok"] as const,
      foreignKeyViolations: 0 as const,
      journalMode: "delete" as const,
      nonEmptySidecars: [] as const,
    },
    receiptPath: input.receiptPath,
  };
  const receipt = {
    ...receiptWithoutSeal,
    receiptPayloadSha256: hashJson(receiptWithoutSeal),
  };
  writeFileSync(input.receiptPath, `${canonicalJson(receipt)}\n`, { mode: 0o600 });
  chmodSync(input.receiptPath, 0o600);
}

async function emptyMappingFixture() {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-sqlite-quarantine-"));
  temporaryDirectories.push(root);
  const sourceRoot = join(root, "sources");
  const engagement = join(sourceRoot, "engagement");
  const sourceDatabasePath = join(engagement, "scans", "sqlmap", "target", "session.sqlite");
  const receiptRoot = join(root, "receipts");
  const destinationPath = join(receiptRoot, "session.normalized.sqlite");
  const receiptPath = join(receiptRoot, "session.receipt.json");
  mkdirSync(dirname(sourceDatabasePath), { recursive: true, mode: 0o700 });
  mkdirSync(receiptRoot, { mode: 0o700 });
  mkdirSync(join(engagement, "notes"), { recursive: true });
  writeFileSync(join(engagement, "notes", "usable.md"), "Observed reusable technique summary.\n");
  await strandedEmptySqlmapWal(sourceDatabasePath);
  await createSnapshotReceiptFixture({
    sourceDatabasePath,
    sourceContainmentRoot: engagement,
    destinationPath,
    receiptPath,
  });
  const receiptSha256 = sha256File(receiptPath);
  const mapping = await loadHistoricalSqliteSnapshotQuarantineMapping({
    receipt: {
      path: receiptPath,
      trustRoot: receiptRoot,
      expectedSha256: receiptSha256,
      allowedOwnerUids: [process.geteuid?.() ?? 0],
      maximumBytes: 64 * 1024,
    },
    allowedSourceRoots: [sourceRoot],
  });
  return {
    root,
    sourceRoot,
    engagement,
    sourceDatabasePath,
    destinationPath,
    receiptPath,
    receiptSha256,
    mapping,
  };
}

describe("HistoricalSqliteSnapshotQuarantineMapping", () => {
  test("maps an exact empty SQLMap DB/WAL/SHM trio to quarantine while keeping other files importable", async () => {
    const fixture = await emptyMappingFixture();
    expect(fixture.mapping.semanticRowCount).toBe(0);
    expect(fixture.mapping.sourceFiles).toHaveLength(3);
    expect(fixture.mapping.disposition).toBe("quarantined_no_semantic_records");
    const indexed = indexHistoricalSqliteSnapshotQuarantineFiles(
      [fixture.mapping],
      [fixture.sourceRoot],
    );

    const engagements = await discoverLegacyEngagements([fixture.sourceRoot], {
      receiptBoundSqliteQuarantines: indexed,
    });
    expect(engagements.manifests).toHaveLength(1);
    expect(engagements.manifests[0]!.quarantined.filter(
      ({ category }) => category === "snapshot_no_semantic_records",
    )).toHaveLength(3);
    expect(engagements.manifests[0]!.files.some(({ relativePath }) =>
      relativePath.endsWith("session.sqlite"))).toBeFalse();
    expect(engagements.manifests[0]!.files.some(({ relativePath }) =>
      relativePath === "notes/usable.md")).toBeTrue();

    const generic = await discoverLegacySources([fixture.sourceRoot], {
      receiptBoundSqliteQuarantines: indexed,
    });
    expect(generic.coverage.activeSqliteFiles).toBe(0);
    expect(generic.coverage.receiptBoundSqliteFiles).toBe(3);
    expect(generic.coverage.receiptBoundSqliteBytes).toBeGreaterThan(0);
  }, 30_000);

  test("dry-run records receipt-bound custody and does not create semantic knowledge from the empty snapshot", async () => {
    const fixture = await emptyMappingFixture();
    const databasePath = join(fixture.root, "canonical.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try { migrateDatabase(database); } finally { database.close(); }
    const result = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [fixture.sourceRoot],
      outputDirectory: join(fixture.root, "migration-output"),
      dryRun: true,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      sqliteSnapshotQuarantineMappings: [fixture.mapping],
      sqliteSnapshotQuarantineAcknowledged: true,
    }).run();
    expect(result.report.sqliteSnapshotQuarantine).toMatchObject({
      mappings: 1,
      sourceFiles: 3,
      semanticRows: 0,
      disposition: "quarantined_no_semantic_records",
    });
    expect(result.report.engagementDiscovery?.hashAddressedQuarantinedPaths).toBe(3);
    expect(result.report.genericSourceDiscovery?.activeSqliteFiles).toBe(0);
    expect(result.report.genericSourceDiscovery?.receiptBoundSqliteFiles).toBe(0);
    expect(result.report.inventoryReceipt.objectCount).toBe(4);
  }, 30_000);

  test("unblocks the full engagement-root delta plan without hiding the quarantined trio", async () => {
    const fixture = await emptyMappingFixture();
    const databasePath = join(fixture.root, "delta.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    try {
      migrateDatabase(database);
      const result = await new HistoricalSourceDeltaPlanner(database).plan({
        configuration: {
          schemaVersion: HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
          configurationVersion: "sqlite-quarantine-test-v1",
          roots: [{
            id: "complete-engagement-root",
            path: fixture.sourceRoot,
            mode: "children",
            required: true,
          }],
        },
        configurationSha256: "a".repeat(64),
        settleSeconds: 60,
        now: new Date(Date.now() + 120_000),
        sqliteSnapshotQuarantineMappings: [fixture.mapping],
      });
      expect(result.status).toBe("ready");
      expect(result.current.activeSqliteFiles).toBe(0);
      expect(result.current.receiptBoundSqliteFiles).toBe(3);
      expect(result.delta.files).toBe(4);
      expect(result.delta.quarantinedFiles).toBe(3);
      expect(result.sqliteSnapshotQuarantine).toMatchObject({
        mappings: 1,
        sourceFiles: 3,
        semanticRows: 0,
      });
    } finally { database.close(); }
  }, 30_000);

  test("fails closed if any mapped source byte changes after approval", async () => {
    const fixture = await emptyMappingFixture();
    const indexedBefore = indexHistoricalSqliteSnapshotQuarantineFiles(
      [fixture.mapping],
      [fixture.sourceRoot],
    );
    expect(indexedBefore.size).toBe(3);
    appendFileSync(`${fixture.sourceDatabasePath}-wal`, "changed");
    expect(() => indexHistoricalSqliteSnapshotQuarantineFiles(
      [fixture.mapping],
      [fixture.sourceRoot],
    )).toThrow("changed after quarantine mapping approval");
  }, 30_000);

  test("rejects a legitimately snapshotted SQLMap storage table when it contains a row", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-sqlite-quarantine-row-"));
    temporaryDirectories.push(root);
    const sourceRoot = join(root, "sources");
    const engagement = join(sourceRoot, "engagement");
    const receiptRoot = join(root, "receipts");
    const sourceDatabasePath = join(engagement, "session.sqlite");
    const destinationPath = join(receiptRoot, "session.normalized.sqlite");
    const receiptPath = join(receiptRoot, "session.receipt.json");
    mkdirSync(engagement, { recursive: true, mode: 0o700 });
    mkdirSync(receiptRoot, { mode: 0o700 });
    const source = createDatabaseConnection({ filename: sourceDatabasePath });
    try {
      source.exec("CREATE TABLE storage (id INTEGER PRIMARY KEY, value TEXT); INSERT INTO storage VALUES (1, 'review-required')");
      source.pragma("wal_checkpoint(TRUNCATE)");
    } finally { source.close(); }
    await createSnapshotReceiptFixture({
      sourceDatabasePath,
      sourceContainmentRoot: engagement,
      destinationPath,
      receiptPath,
      normalizedStorageRows: [{ id: 1, value: "review-required" }],
    });
    await expect(loadHistoricalSqliteSnapshotQuarantineMapping({
      receipt: {
        path: receiptPath,
        trustRoot: receiptRoot,
        expectedSha256: sha256File(receiptPath),
        allowedOwnerUids: [process.geteuid?.() ?? 0],
        maximumBytes: 64 * 1024,
      },
      allowedSourceRoots: [sourceRoot],
    })).rejects.toThrow("contains rows and requires a separate semantic review");
  }, 30_000);
});

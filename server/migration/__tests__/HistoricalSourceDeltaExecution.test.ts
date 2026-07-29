import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { LegacyMigrationService } from "../LegacyMigrationService";
import { HistoricalSourceDeltaPlanner } from "../HistoricalSourceDeltaPlanner";
import { HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION } from "../HistoricalSourceRootConfiguration";

const sandboxes: string[] = [];

afterEach(() => {
  for (const sandbox of sandboxes.splice(0)) rmSync(sandbox, { recursive: true, force: true });
});

function fixture() {
  const sandbox = mkdtempSync(join(tmpdir(), "ti-scale-exact-delta-"));
  sandboxes.push(sandbox);
  const historyRoot = join(sandbox, "history");
  const sourceOne = join(historyRoot, "one", "runtime", "events.jsonl");
  const sourceTwo = join(historyRoot, "two", "runtime", "events.jsonl");
  mkdirSync(join(sourceOne, ".."), { recursive: true, mode: 0o700 });
  mkdirSync(join(sourceTwo, ".."), { recursive: true, mode: 0o700 });
  writeFileSync(sourceOne, `${JSON.stringify({ message: "safe first observation" })}\n`, { mode: 0o600 });
  writeFileSync(sourceTwo, `${JSON.stringify({ message: "safe second observation" })}\n`, { mode: 0o600 });
  const old = new Date(Date.now() - 10 * 60_000);
  utimesSync(sourceOne, old, old);
  utimesSync(sourceTwo, old, old);
  const databasePath = join(sandbox, "canonical.sqlite");
  const database = createDatabaseConnection({ filename: databasePath });
  migrateDatabase(database);
  const configuration = {
    schemaVersion: HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
    configurationVersion: "exact-delta-test-v1",
    roots: [{ id: "history", path: historyRoot, mode: "history-root" as const, required: true as const }],
  };
  return {
    sandbox,
    historyRoot,
    sourceOne,
    sourceTwo,
    database,
    databasePath,
    configuration,
  };
}

async function plannedFixture() {
  const value = fixture();
  const planned = await new HistoricalSourceDeltaPlanner(value.database).planForExecution({
    configuration: value.configuration,
    configurationSha256: "a".repeat(64),
    settleSeconds: 60,
  });
  return { ...value, plan: planned.executionPlan };
}

function service(input: Awaited<ReturnType<typeof plannedFixture>>, outputName: string) {
  return new LegacyMigrationService({
    databasePath: input.databasePath,
    sourceRoots: [],
    historyRoots: [input.historyRoot],
    outputDirectory: join(input.sandbox, outputName),
    dryRun: true,
    settleSeconds: 60,
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
    reviewedDeltaExecutionPlan: input.plan,
  });
}

describe("reviewed historical source delta execution", () => {
  test("discovers only the sealed exact paths and binds them into reconciliation", async () => {
    const input = await plannedFixture();
    try {
      const unreviewed = join(input.historyRoot, "later", "runtime", "events.jsonl");
      mkdirSync(join(unreviewed, ".."), { recursive: true, mode: 0o700 });
      writeFileSync(unreviewed, `${JSON.stringify({ message: "not in reviewed batch" })}\n`, { mode: 0o600 });
      const old = new Date(Date.now() - 10 * 60_000);
      utimesSync(unreviewed, old, old);

      const result = await service(input, "dry-run").run();
      expect(result.report.inventoryReceipt.objectCount).toBe(2);
      expect(result.report.sources.map(({ path }) => path).sort()).toEqual([
        input.sourceOne,
        input.sourceTwo,
      ].sort());
      expect(result.report.sources.some(({ path }) => path === unreviewed)).toBe(false);
      expect(result.report.genericSourceDiscovery?.scannedFiles).toBe(2);
      expect(result.report.reviewedDeltaExecution).toEqual({
        executionPlanHash: input.plan.planHash,
        publicPlanHash: input.plan.publicPlanHash,
        configurationSha256: input.plan.configuration.sha256,
        baselineInventoryReceiptSetHash: input.plan.baseline.inventoryReceiptSetHash,
        admittedFiles: 2,
        admittedBytes: input.plan.delta.bytes,
        exactPathAdmission: true,
      });
    } finally {
      input.database.close();
    }
  });

  test("fails closed when a reviewed source changes", async () => {
    const input = await plannedFixture();
    try {
      writeFileSync(input.sourceOne, `${JSON.stringify({ message: "changed after review" })}\n`);
      await expect(service(input, "source-drift").run()).rejects.toThrow(
        "Reviewed delta admission identity drifted after planning",
      );
    } finally {
      input.database.close();
    }
  });

  test("fails closed when canonical completed-migration baseline changes", async () => {
    const input = await plannedFixture();
    try {
      input.database.prepare(`
        INSERT INTO legacy_migration_runs (
          id, status, source_roots_json, database_path, output_directory,
          source_retention, source_retention_acknowledged_at,
          brain_projection_mode, brain_projection_acknowledged_at,
          started_at, completed_at
        ) VALUES (?, 'completed', '[]', ?, ?, 'verified-reference', ?,
          'attack-knowledge-only', ?, ?, ?)
      `).run(
        "baseline_drift",
        input.databasePath,
        join(input.sandbox, "prior"),
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:00:00.000Z",
        "2026-01-01T00:01:00.000Z",
      );
      input.database.prepare(`
        INSERT INTO legacy_migration_inventory_receipts (
          migration_id, receipt_hash, object_count, byte_count, created_at
        ) VALUES (?, ?, 0, 0, ?)
      `).run("baseline_drift", "b".repeat(64), "2026-01-01T00:01:00.000Z");
      await expect(service(input, "baseline-drift").run()).rejects.toThrow(
        "Reviewed delta execution baseline drifted after planning",
      );
    } finally {
      input.database.close();
    }
  });

  test("refuses a reviewed file that is currently open for write", async () => {
    const input = await plannedFixture();
    const descriptor = openSync(input.sourceOne, "a");
    try {
      await expect(service(input, "active-writer").run()).rejects.toThrow(
        "Reviewed delta admission is currently open for write",
      );
    } finally {
      closeSync(descriptor);
      input.database.close();
    }
  });

  test("builds delta-only engagement manifests without walking unchanged sibling files", async () => {
    const sandbox = mkdtempSync(join(tmpdir(), "ti-scale-exact-engagement-delta-"));
    sandboxes.push(sandbox);
    const parentRoot = join(sandbox, "engagements");
    const reviewed = join(parentRoot, "box-one", "notes", "reviewed.md");
    mkdirSync(join(reviewed, ".."), { recursive: true, mode: 0o700 });
    writeFileSync(reviewed, "Verified service-version observation\n", { mode: 0o600 });
    const old = new Date(Date.now() - 10 * 60_000);
    utimesSync(reviewed, old, old);
    const databasePath = join(sandbox, "canonical.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    migrateDatabase(database);
    try {
      const configuration = {
        schemaVersion: HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
        configurationVersion: "exact-engagement-delta-test-v1",
        roots: [{ id: "engagements", path: parentRoot, mode: "children" as const, required: true as const }],
      };
      const planned = await new HistoricalSourceDeltaPlanner(database).planForExecution({
        configuration,
        configurationSha256: "c".repeat(64),
        settleSeconds: 60,
      });
      const unreviewed = join(parentRoot, "box-one", "notes", "later.md");
      writeFileSync(unreviewed, "This appeared after the reviewed plan\n", { mode: 0o600 });
      utimesSync(unreviewed, old, old);
      const result = await new LegacyMigrationService({
        databasePath,
        sourceRoots: [parentRoot],
        outputDirectory: join(sandbox, "engagement-dry-run"),
        dryRun: true,
        settleSeconds: 60,
        sourceRetention: "verified-reference",
        verifiedReferenceAcknowledged: true,
        brainProjectionMode: "attack-knowledge-only",
        attackKnowledgeOnlyAcknowledged: true,
        reviewedDeltaExecutionPlan: planned.executionPlan,
      }).run();
      expect(result.report.inventoryReceipt.objectCount).toBe(1);
      expect(result.report.engagementDiscovery).toMatchObject({
        manifests: 1,
        classifiedFiles: 1,
      });
      expect(result.report.genericSourceDiscovery?.scannedFiles).toBe(0);
      expect(JSON.stringify(result.report)).not.toContain(unreviewed);
    } finally {
      database.close();
    }
  });

  test("keeps the existing receipt and bounded resume semantics without backup or rollback metadata", async () => {
    const input = await plannedFixture();
    const outputDirectory = join(input.sandbox, "execute-resume");
    input.database.close();
    const options = {
      databasePath: input.databasePath,
      sourceRoots: [] as readonly string[],
      historyRoots: [input.historyRoot],
      outputDirectory,
      settleSeconds: 60,
      sourceRetention: "verified-reference" as const,
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only" as const,
      attackKnowledgeOnlyAcknowledged: true,
      reviewedDeltaExecutionPlan: input.plan,
    };
    await expect(new LegacyMigrationService({
      ...options,
      genericAttackKnowledgeSourceHandler: () => {
        throw new Error("fixture interruption after exact custody");
      },
    }).run()).rejects.toThrow("fixture interruption after exact custody");
    const database = createDatabaseConnection({ filename: input.databasePath });
    try {
      const failed = database.prepare(`
        SELECT id, status FROM legacy_migration_runs ORDER BY started_at DESC LIMIT 1
      `).get() as { id: string; status: string };
      expect(failed.status).toBe("failed");
      const resumed = await new LegacyMigrationService({
        ...options,
        resumeMigrationId: failed.id,
        genericAttackKnowledgeSourceHandler: () => [],
      }).run();
      expect(resumed.migrationId).toBe(failed.id);
      expect(resumed.report.reviewedDeltaExecution?.executionPlanHash).toBe(input.plan.planHash);
      expect(resumed.report.databaseBackup).toBeUndefined();
      expect(resumed.report.rollback).toBeUndefined();
      expect(resumed.report.sourceBackup).toBeUndefined();
      expect(resumed.report.sourceReferences?.sourceBytesCopied).toBe(false);
      expect(existsSync(join(outputDirectory, "database-backups"))).toBe(false);
      expect(existsSync(join(outputDirectory, failed.id, "sources"))).toBe(false);
      const custody = database.prepare(`
        SELECT COUNT(*) AS count
        FROM legacy_migration_source_objects
        WHERE migration_id = ?
      `).get(failed.id) as { count: number };
      expect(custody.count).toBe(2);
      const receipt = database.prepare(`
        SELECT receipt_hash FROM legacy_migration_inventory_receipts WHERE migration_id = ?
      `).get(failed.id) as { receipt_hash: string };
      expect(receipt.receipt_hash).toBe(resumed.report.inventoryReceipt.hash);
    } finally {
      database.close();
    }
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { BoundedHistoricalAttackKnowledgeResumeService } from "../BoundedHistoricalAttackKnowledgeResumeService";
import { GenericHistoricalAttackKnowledgeIngestionService } from "../GenericHistoricalAttackKnowledgeIngestionService";
import { HistoricalAttackKnowledgeExtractionReconciliationService } from "../HistoricalAttackKnowledgeExtractionReconciliationService";
import { LegacyMigrationService } from "../LegacyMigrationService";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";
import type { LegacySource } from "../types";

const HMAC_KEY = "bounded-generic-resume-test-key-longer-than-thirty-two-bytes";
const directories: string[] = [];

afterEach(() => {
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

describe("BoundedHistoricalAttackKnowledgeResumeService", () => {
  test("resumes the exact durable cursor with connection-scoped pages and reconciles without promotion", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-bounded-history-resume-"));
    directories.push(root);
    const historyRoot = join(root, "history");
    mkdirSync(historyRoot, { recursive: true });
    const sourcePath = join(historyRoot, "events.jsonl");
    const content = [
      { summary: "Apache HTTP Server/2.4.49 path traversal worked and was validated" },
      { summary: "nginx 1.24.0 remote code execution failed with timeout" },
      { summary: "PHP 8.2.1 command injection worked and was confirmed" },
      { summary: "OpenSSH_9.2p1 authentication bypass failed with timeout" },
    ].map((value) => JSON.stringify(value)).join("\n");
    writeFileSync(sourcePath, content, { mode: 0o600 });
    const state = statSync(sourcePath);
    const databasePath = join(root, "ti-scale.sqlite");
    const outputDirectory = join(root, "output");
    const database = createDatabaseConnection({ filename: databasePath });
    migrateDatabase(database);
    const metadata = new MigrationMetadataRepository(database);
    const migration = metadata.createRun({
      sourceRoots: [historyRoot],
      databasePath,
      outputDirectory,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
    });
    const source: LegacySource = {
      absolutePath: sourcePath,
      relativePath: "events.jsonl",
      root: historyRoot,
      type: "event_jsonl",
      sha256: sha256(content),
      byteSize: Buffer.byteLength(content),
      modifiedAt: state.mtime.toISOString(),
    };
    const sourceId = metadata.registerSource(migration.id, source, undefined, {
      retentionMode: "verified-reference",
      device: state.dev,
      inode: state.ino,
    });
    metadata.registerSourceObject({
      migrationId: migration.id,
      sourceId,
      objectKey: "source",
      sourcePath,
      objectKind: "source",
      classification: source.type,
      sourceSha256: source.sha256,
      byteSize: source.byteSize,
      modifiedAt: source.modifiedAt,
      sourceDevice: state.dev,
      sourceInode: state.ino,
    });
    metadata.markSource(sourceId, "completed");
    const receipt = "d".repeat(64);
    database.prepare(`
      INSERT INTO legacy_migration_inventory_receipts (
        migration_id, receipt_hash, object_count, byte_count, created_at
      ) VALUES (?, ?, 1, ?, '2026-07-21T17:00:00.000Z')
    `).run(migration.id, receipt, source.byteSize);

    const interrupted = new GenericHistoricalAttackKnowledgeIngestionService(database, {
      receiptHmacKey: HMAC_KEY,
    }).ingest({
      migrationId: migration.id,
      inventoryReceiptHash: receipt,
      sources: [source],
      maxRecordsThisRun: 1,
      maxBundlesThisRun: 1,
    });
    expect(interrupted.status).toBe("partial");
    metadata.recordExtractionBatch({
      migrationId: migration.id,
      extractorKind: "generic",
      report: interrupted,
    });

    let heartbeats = 0;
    const resumed = new BoundedHistoricalAttackKnowledgeResumeService(database, {
      databasePath,
      migrationId: migration.id,
      outputDirectory,
      sourceRoots: [historyRoot],
      receiptHmacKey: HMAC_KEY,
      maxRecordsPerPage: 1,
      maxBundlesPerPage: 1,
      maxSourcesPerPage: 1,
      heartbeat: () => { heartbeats += 1; },
    }).run();
    expect(resumed).toMatchObject({
      migrationId: migration.id,
      status: "completed",
      sourceCount: 1,
      pagesProcessed: 3,
      finalSequence: 4,
    });
    expect(heartbeats).toBeGreaterThanOrEqual(6);

    const reconciliation = new HistoricalAttackKnowledgeExtractionReconciliationService(database)
      .reconcile(migration.id, false);
    expect(reconciliation).toMatchObject({
      status: "completed",
      partialScopeCount: 0,
      batchesProcessed: 4,
      genericSourcesDiscovered: 1,
      genericSourcesCompleted: 1,
      genericRecordsProcessed: 4,
      sourceEvidenceCandidatesCreated: 1,
      sourceEvidenceCandidatesReused: 0,
      evidenceAutomaticallyVerified: 0,
      reusableMemoryAutomaticallyPromoted: 0,
    });
    expect(reconciliation.resumeCursors).toEqual([]);
    expect(reconciliation.sourceEvidenceCandidateIds).toHaveLength(1);
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_candidates WHERE status != 'pending'
    `).get()).toEqual({ count: 0 });
    database.close();
  });

  test("the production CLI finalizes an interrupted migration through bounded resume", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-bounded-history-cli-"));
    directories.push(root);
    const historyRoot = join(root, "history");
    mkdirSync(join(historyRoot, "runtime"), { recursive: true });
    const sourcePath = join(historyRoot, "runtime", "events.jsonl");
    writeFileSync(sourcePath, [
      { summary: "Apache HTTP Server/2.4.49 path traversal worked and was validated" },
      { summary: "nginx 1.24.0 remote code execution failed with timeout" },
      { summary: "PHP 8.2.1 command injection worked and was confirmed" },
    ].map((value) => JSON.stringify(value)).join("\n"), { mode: 0o600 });
    const databasePath = join(root, "ti-scale.sqlite");
    const outputDirectory = join(root, "output");
    const database = createDatabaseConnection({ filename: databasePath });
    migrateDatabase(database);
    database.close();

    await expect(new LegacyMigrationService({
      databasePath,
      sourceRoots: [],
      historyRoots: [historyRoot],
      outputDirectory,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      genericAttackKnowledgeSourceHandler: (input, migrationDatabase, context) => {
        const page = new GenericHistoricalAttackKnowledgeIngestionService(migrationDatabase, {
          receiptHmacKey: HMAC_KEY,
        }).ingest({ ...input, maxRecordsThisRun: 1, maxBundlesThisRun: 1 });
        context.recordBatch(page);
        throw new Error("simulated post-checkpoint interruption");
      },
    }).run()).rejects.toThrow("simulated post-checkpoint interruption");

    const interruptedDatabase = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    const migration = interruptedDatabase.prepare(`
      SELECT id FROM legacy_migration_runs WHERE status = 'failed' ORDER BY started_at DESC LIMIT 1
    `).get() as { readonly id: string };
    interruptedDatabase.close();

    const child = Bun.spawn([
      process.execPath,
      "run",
      "server/migration/cli.ts",
      "migrate",
      "--db", databasePath,
      "--history-root", historyRoot,
      "--output", outputDirectory,
      "--source-retention", "verified-reference",
      "--acknowledge-verified-reference",
      "--brain-projection", "attack-knowledge-only",
      "--acknowledge-attack-knowledge-only",
      "--resume", migration.id,
      "--bounded-resume",
    ], {
      cwd: process.cwd(),
      env: { ...process.env, TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY: HMAC_KEY },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(exitCode).toBe(0);
    expect(stderr).toBe("");
    const output = JSON.parse(stdout) as {
      readonly migrationId: string;
      readonly boundedResume: {
        readonly status: string;
        readonly pagesProcessed: number;
      };
      readonly attackKnowledge: {
        readonly status: string;
        readonly reusableMemoryAutomaticallyPromoted: number;
        readonly evidenceAutomaticallyVerified: number;
      };
    };
    expect(output).toMatchObject({
      migrationId: migration.id,
      boundedResume: { status: "completed" },
      attackKnowledge: {
        status: "completed",
        reusableMemoryAutomaticallyPromoted: 0,
        evidenceAutomaticallyVerified: 0,
      },
    });
    expect(output.boundedResume.pagesProcessed).toBeGreaterThan(0);

    const completed = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect(completed.prepare(`
        SELECT status FROM legacy_migration_runs WHERE id = ?
      `).get(migration.id)).toEqual({ status: "completed" });
      expect(completed.prepare(`
        SELECT COUNT(*) AS count FROM legacy_migration_reconciliation WHERE migration_id = ?
      `).get(migration.id)).toEqual({ count: 1 });
      expect(completed.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    } finally {
      completed.close();
    }
  });
});

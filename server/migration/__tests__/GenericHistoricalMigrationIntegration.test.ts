import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES,
  GenericHistoricalAttackKnowledgeIngestionService,
  type GenericHistoricalAttackKnowledgeIngestionResult,
} from "../GenericHistoricalAttackKnowledgeIngestionService";
import { LegacyMigrationService } from "../LegacyMigrationService";

const HMAC_KEY = "generic-migration-integration-test-key-longer-than-thirty-two-bytes";
const directories: string[] = [];

afterEach(() => {
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function fixture(): { readonly root: string; readonly source: string; readonly databasePath: string; readonly output: string } {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-generic-migration-integration-"));
  directories.push(root);
  const source = join(root, "history");
  mkdirSync(join(source, "runtime"), { recursive: true });
  writeFileSync(join(source, "runtime", "events.jsonl"), [
    JSON.stringify({ timestamp: "2026-06-01T00:00:00Z", summary: "Apache HTTP Server/2.4.49 path traversal CVE-2021-41773 worked" }),
    JSON.stringify({ timestamp: "2026-06-01T00:01:00Z", summary: "nginx 1.24.0 remote code execution failed with timeout; restart service before retry" }),
  ].join("\n"), { mode: 0o600 });
  const databasePath = join(root, "ti-scale.sqlite");
  const database = createDatabaseConnection({ filename: databasePath });
  migrateDatabase(database);
  database.close();
  return { root, source, databasePath, output: join(root, "output") };
}

function handler(
  collected: GenericHistoricalAttackKnowledgeIngestionResult[],
  interruptFirst = false,
) {
  let first = true;
  return (input: {
    readonly migrationId: string;
    readonly inventoryReceiptHash: string;
    readonly sources: readonly import("../types").LegacySource[];
  }, database: ReturnType<typeof createDatabaseConnection>, context: import("../types").AttackKnowledgeExtractionHandlerContext) => {
    const allowed = new Set<string>(GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES);
    const sources = input.sources.filter((source) => allowed.has(source.type));
    if (sources.length === 0) return [];
    const service = new GenericHistoricalAttackKnowledgeIngestionService(database, {
      receiptHmacKey: HMAC_KEY,
    });
    const result = service.ingest({
      ...input,
      sources,
      dryRun: context.dryRun,
      ...(interruptFirst && first ? { interruptAfterNewRecords: 1 } : {}),
      ...(context.dryRun ? { maxSourcesThisRun: sources.length } : {}),
    });
    first = false;
    collected.push(result);
    context.recordBatch(result);
    if (interruptFirst) throw new Error("simulated generic ingestion process interruption");
    return [result];
  };
}

describe("generic historical migration integration", () => {
  test("bounded dry-run defers canonical database integrity scanning to the explicit verify command", async () => {
    const item = fixture();
    // A dry preview needs only the configured path identity. Replacing the
    // canonical fixture with a non-SQLite sentinel proves the preview neither
    // opens it nor performs quick_check/foreign_key_check behind the scenes.
    writeFileSync(item.databasePath, "CANONICAL-DATABASE-MUST-NOT-BE-OPENED-BY-DRY-RUN", { mode: 0o600 });
    const result = await new LegacyMigrationService({
      databasePath: item.databasePath,
      sourceRoots: [item.source],
      outputDirectory: item.output,
      dryRun: true,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
    }).run();

    expect(result.report.integrity).toEqual({
      verificationStatus: "deferred",
      quickCheck: ["canonical database verification deferred to the explicit verify command"],
      foreignKeyViolations: null,
    });
    expect(result.report.warnings.join(" ")).toContain("explicit database verify command separately");
  });

  test("reconciliation exposes incomplete cursors and deduplicates source evidence across completed dry-run pages", async () => {
    const partialFixture = fixture();
    const onePage = await new LegacyMigrationService({
      databasePath: partialFixture.databasePath,
      sourceRoots: [partialFixture.source],
      outputDirectory: partialFixture.output,
      dryRun: true,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      genericAttackKnowledgeSourceHandler: (input, database, context) => {
        const service = new GenericHistoricalAttackKnowledgeIngestionService(database, { receiptHmacKey: HMAC_KEY });
        return [service.ingest({ ...input, dryRun: context.dryRun, maxRecordsThisRun: 1 })];
      },
    }).run();
    expect(onePage.report.attackKnowledgeExtraction).toMatchObject({
      status: "partial",
      partialScopeCount: 1,
      genericSourcesDiscovered: 1,
      genericSourcesCompleted: 0,
    });
    expect(onePage.report.attackKnowledgeExtraction?.resumeCursors).toHaveLength(1);
    expect(onePage.report.attackKnowledgeExtraction?.resumeCursors[0]).toMatchObject({
      manifestFingerprint: expect.stringMatching(/^[a-f0-9]{64}$/u),
      nextResumeAfterSourceKey: expect.stringMatching(/^[a-f0-9]{64}$/u),
      nextResumeAfterRecordKey: expect.stringMatching(/^[a-f0-9]{64}$/u),
    });

    const completeFixture = fixture();
    const completed = await new LegacyMigrationService({
      databasePath: completeFixture.databasePath,
      sourceRoots: [completeFixture.source],
      outputDirectory: completeFixture.output,
      dryRun: true,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      genericAttackKnowledgeSourceHandler: (input, database, context) => {
        const service = new GenericHistoricalAttackKnowledgeIngestionService(database, { receiptHmacKey: HMAC_KEY });
        const batches: GenericHistoricalAttackKnowledgeIngestionResult[] = [];
        let sourceCursor: string | undefined;
        let recordCursor: string | undefined;
        do {
          const page = service.ingest({
            ...input,
            dryRun: context.dryRun,
            maxRecordsThisRun: 1,
            ...(sourceCursor ? { resumeAfterSourceKey: sourceCursor } : {}),
            ...(recordCursor ? { resumeAfterRecordKey: recordCursor } : {}),
          });
          batches.push(page);
          sourceCursor = page.nextResumeAfterSourceKey;
          recordCursor = page.nextResumeAfterRecordKey;
        } while (batches.at(-1)?.status === "partial");
        return batches;
      },
    }).run();
    expect(completed.report.attackKnowledgeExtraction).toMatchObject({
      status: "completed",
      partialScopeCount: 0,
      resumeCursors: [],
      genericSourcesDiscovered: 1,
      genericSourcesCompleted: 1,
      genericRecordsProcessed: 2,
      sourceEvidenceCandidatesCreated: 1,
      sourceEvidenceCandidatesReused: 0,
    });
    expect(completed.report.attackKnowledgeExtraction?.sourceEvidenceCandidateIds).toHaveLength(1);
    expect(completed.report.attackKnowledgeExtraction?.nodeTypeCounts).toMatchObject({
      technology_product: 2,
      exact_version_fingerprint: 2,
    });
    expect(Object.keys(completed.report.attackKnowledgeExtraction?.edgeTypeCounts ?? {})).not.toHaveLength(0);
  });

  test("execute cannot mark a migration completed while an extractor scope is partial", async () => {
    const item = fixture();
    await expect(new LegacyMigrationService({
      databasePath: item.databasePath,
      sourceRoots: [item.source],
      outputDirectory: item.output,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      genericAttackKnowledgeSourceHandler: (input, database, context) => {
        const service = new GenericHistoricalAttackKnowledgeIngestionService(database, { receiptHmacKey: HMAC_KEY });
        const page = service.ingest({ ...input, maxRecordsThisRun: 1 });
        context.recordBatch(page);
        return [page];
      },
    }).run()).rejects.toThrow("extraction is incomplete across 1 scope");

    const database = createDatabaseConnection({ filename: item.databasePath, readonly: true, fileMustExist: true });
    try {
      expect(database.prepare(`
        SELECT status FROM legacy_migration_runs ORDER BY started_at DESC LIMIT 1
      `).get()).toEqual({ status: "failed" });
      const batch = database.prepare(`
        SELECT report_json FROM legacy_migration_extraction_batches ORDER BY sequence DESC LIMIT 1
      `).get() as { readonly report_json: string };
      expect(JSON.parse(batch.report_json)).toMatchObject({
        status: "partial",
        nextResumeAfterSourceKey: expect.stringMatching(/^[a-f0-9]{64}$/u),
        nextResumeAfterRecordKey: expect.stringMatching(/^[a-f0-9]{64}$/u),
      });
    } finally {
      database.close();
    }
  });

  test("dry preview invokes semantic parsing in a disposable database and leaves canonical state unchanged", async () => {
    const item = fixture();
    const collected: GenericHistoricalAttackKnowledgeIngestionResult[] = [];
    const beforeDatabase = createDatabaseConnection({ filename: item.databasePath, readonly: true, fileMustExist: true });
    const beforeCounts = {
      migrations: (beforeDatabase.prepare("SELECT COUNT(*) AS count FROM legacy_migration_runs").get() as { count: number }).count,
      candidates: (beforeDatabase.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get() as { count: number }).count,
      bundles: (beforeDatabase.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_bundles").get() as { count: number }).count,
    };
    beforeDatabase.close();
    const result = await new LegacyMigrationService({
      databasePath: item.databasePath,
      sourceRoots: [item.source],
      outputDirectory: item.output,
      dryRun: true,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      genericAttackKnowledgeSourceHandler: handler(collected),
    }).run();

    expect(collected).toHaveLength(1);
    expect(collected[0]).toMatchObject({ dryRun: true, filesParsed: 1, compilerBundlesStaged: 2 });
    expect(result.report.attackKnowledgeExtraction).toMatchObject({
      semanticPreview: true,
      filesDiscovered: 1,
      filesParsed: 1,
      connectedBundlesStaged: 2,
      evidenceAutomaticallyVerified: 0,
      reusableMemoryAutomaticallyPromoted: 0,
    });
    const afterDatabase = createDatabaseConnection({ filename: item.databasePath, readonly: true, fileMustExist: true });
    expect({
      migrations: (afterDatabase.prepare("SELECT COUNT(*) AS count FROM legacy_migration_runs").get() as { count: number }).count,
      candidates: (afterDatabase.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get() as { count: number }).count,
      bundles: (afterDatabase.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_bundles").get() as { count: number }).count,
    }).toEqual(beforeCounts);
    afterDatabase.close();
  });

  test("execute resumes durable record checkpoints and reconciles generic candidates into the real migration report", async () => {
    const item = fixture();
    const interrupted: GenericHistoricalAttackKnowledgeIngestionResult[] = [];
    await expect(new LegacyMigrationService({
      databasePath: item.databasePath,
      sourceRoots: [item.source],
      outputDirectory: item.output,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      genericAttackKnowledgeSourceHandler: handler(interrupted, true),
    }).run()).rejects.toThrow("simulated generic ingestion process interruption");
    expect(interrupted[0]).toMatchObject({ status: "partial", recordsProcessed: 1 });

    const database = createDatabaseConnection({ filename: item.databasePath, readonly: true, fileMustExist: true });
    const failed = database.prepare(`
      SELECT id FROM legacy_migration_runs WHERE status = 'failed' ORDER BY started_at DESC LIMIT 1
    `).get() as { readonly id: string };
    database.close();

    const resumedBatches: GenericHistoricalAttackKnowledgeIngestionResult[] = [];
    const resumed = await new LegacyMigrationService({
      databasePath: item.databasePath,
      sourceRoots: [item.source],
      outputDirectory: item.output,
      resumeMigrationId: failed.id,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
      genericAttackKnowledgeSourceHandler: handler(resumedBatches),
    }).run();

    expect(resumed.migrationId).toBe(failed.id);
    expect(resumedBatches[0]).toMatchObject({ status: "completed", recordsProcessed: 1, recordsDeduplicated: 1 });
    expect(resumed.report.attackKnowledgeExtraction).toMatchObject({
      semanticPreview: false,
      filesDiscovered: 1,
      filesParsed: 2,
      connectedBundlesStaged: 2,
      candidatesCreated: 11,
      genericSourcesProcessed: 2,
      genericRecordsProcessed: 2,
      evidenceAutomaticallyVerified: 0,
      reusableMemoryAutomaticallyPromoted: 0,
    });
    const canonical = createDatabaseConnection({ filename: item.databasePath, readonly: true, fileMustExist: true });
    try {
      expect(canonical.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_provenance_receipts").get()).toEqual({ count: 2 });
      expect(canonical.prepare("SELECT COUNT(*) AS count FROM historical_attack_knowledge_bundle_sources").get()).toEqual({ count: 2 });
      expect(canonical.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
      expect(canonical.prepare("SELECT COUNT(*) AS count FROM artifacts").get()).toEqual({ count: 0 });
      const reusable = JSON.stringify(canonical.prepare("SELECT title, summary, body FROM memory_candidates ORDER BY title").all());
      expect(reusable).not.toMatch(/(?:10\.\d+\.\d+\.\d+|private-|mission_|run_)/u);
    } finally {
      canonical.close();
    }
  });

  test("the production CLI executes generic ingestion and reports bounded semantic work", async () => {
    const item = fixture();
    const child = Bun.spawn([
      globalThis.process.execPath,
      "run",
      "server/migration/cli.ts",
      "migrate",
      "--db", item.databasePath,
      "--source", item.source,
      "--output", item.output,
      "--source-retention", "verified-reference",
      "--acknowledge-verified-reference",
      "--brain-projection", "attack-knowledge-only",
      "--acknowledge-attack-knowledge-only",
    ], {
      cwd: globalThis.process.cwd(),
      env: {
        ...globalThis.process.env,
        TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY: HMAC_KEY,
      },
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
      readonly attackKnowledge: {
        readonly semanticPreview: boolean;
        readonly genericSourcesProcessed: number;
        readonly genericRecordsProcessed: number;
        readonly genericRecordsQuarantined: number;
        readonly sourceEvidenceCandidateIds: readonly string[];
      };
    };
    expect(output.attackKnowledge).toMatchObject({
      semanticPreview: false,
      genericSourcesProcessed: 1,
      genericRecordsProcessed: 2,
      genericRecordsQuarantined: 0,
    });
    expect(output.attackKnowledge.sourceEvidenceCandidateIds).toHaveLength(1);

    const canonical = createDatabaseConnection({ filename: item.databasePath, readonly: true, fileMustExist: true });
    try {
      expect(canonical.prepare("SELECT status FROM legacy_migration_runs WHERE id = ?").get(output.migrationId))
        .toEqual({ status: "completed" });
      expect(canonical.prepare("SELECT COUNT(*) AS count FROM attack_knowledge_provenance_receipts").get())
        .toEqual({ count: 2 });
      expect(canonical.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    } finally {
      canonical.close();
    }
  });

  test("the production CLI dry run continues beyond the 20,000-record page boundary", async () => {
    const item = fixture();
    const recordCount = 20_001;
    writeFileSync(join(item.source, "runtime", "events.jsonl"), Array.from(
      { length: recordCount },
      (_, index) => JSON.stringify({ message: `Routine historical status record ${index}` }),
    ).join("\n"), { mode: 0o600 });
    const child = Bun.spawn([
      globalThis.process.execPath,
      "run",
      "server/migration/cli.ts",
      "migrate",
      "--db", item.databasePath,
      "--source", item.source,
      "--output", item.output,
      "--dry-run",
      "--source-retention", "verified-reference",
      "--acknowledge-verified-reference",
      "--brain-projection", "attack-knowledge-only",
      "--acknowledge-attack-knowledge-only",
    ], {
      cwd: globalThis.process.cwd(),
      env: {
        ...globalThis.process.env,
        TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY: HMAC_KEY,
      },
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
      readonly attackKnowledge: {
        readonly status: string;
        readonly partialScopeCount: number;
        readonly resumeCursors: readonly unknown[];
        readonly batchesProcessed: number;
        readonly genericSourcesDiscovered: number;
        readonly genericSourcesCompleted: number;
        readonly genericRecordsProcessed: number;
      };
    };
    expect(output.attackKnowledge).toMatchObject({
      status: "completed",
      partialScopeCount: 0,
      resumeCursors: [],
      batchesProcessed: 5,
      genericSourcesDiscovered: 1,
      genericSourcesCompleted: 1,
      genericRecordsProcessed: recordCount,
    });
  }, 30_000);
});

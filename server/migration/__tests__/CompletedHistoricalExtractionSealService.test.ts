import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { withCanonicalWriterLease } from "../../maintenance";
import {
  CompletedHistoricalExtractionSealService,
  POST_EXTRACTION_INVENTORY_DRIFT_ERROR,
} from "../CompletedHistoricalExtractionSealService";
import { GenericHistoricalAttackKnowledgeIngestionService } from
  "../GenericHistoricalAttackKnowledgeIngestionService";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";
import type { AttackKnowledgeExtractionBatchReport, LegacySource } from "../types";

const HMAC_KEY = "completed-extraction-seal-test-key-longer-than-thirty-two-bytes";
const directories: string[] = [];

afterEach(() => {
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function fixture(options: {
  readonly parentError?: string;
  readonly sourceStatus?: "completed" | "failed";
  readonly receiptByteDelta?: number;
  readonly batchMode?: "valid" | "tampered_hash" | "partial";
  readonly receiptOnlyCandidate?: boolean;
  readonly occurrenceOnlyCandidate?: "valid" | "incomplete";
} = {}) {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-completed-extraction-seal-"));
  directories.push(root);
  const historyRoot = join(root, "history");
  const outputDirectory = join(root, "output");
  mkdirSync(historyRoot, { recursive: true });
  mkdirSync(outputDirectory, { recursive: true });
  const sourcePath = join(historyRoot, "events.jsonl");
  const content = JSON.stringify({
    summary: "Apache HTTP Server 2.4.49 path traversal worked and was validated",
  });
  writeFileSync(sourcePath, content, { mode: 0o600 });
  const state = statSync(sourcePath);
  const databasePath = ":memory:";
  const database = createDatabaseConnection({ filename: databasePath });
  migrateDatabase(database);
  const fixed = new Date("2026-07-21T17:00:00.000Z");
  const metadata = new MigrationMetadataRepository(database, () => fixed);
  const migration = metadata.createRun({
    sourceRoots: [historyRoot],
    databasePath,
    outputDirectory,
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
  });
  mkdirSync(join(outputDirectory, migration.id));
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
  metadata.markSource(sourceId, options.sourceStatus ?? "completed");
  const inventoryReceiptHash = "d".repeat(64);
  database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, 1, ?, ?)
  `).run(
    migration.id,
    inventoryReceiptHash,
    source.byteSize + (options.receiptByteDelta ?? 0),
    fixed.toISOString(),
  );
  const extraction = new GenericHistoricalAttackKnowledgeIngestionService(database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => fixed,
  }).ingest({
    migrationId: migration.id,
    inventoryReceiptHash,
    sources: [source],
  });
  expect(extraction.status).toBe("completed");
  let extractionReport: AttackKnowledgeExtractionBatchReport = options.occurrenceOnlyCandidate
    ? {
        ...extraction,
        sourceEvidenceCandidateIds: [],
      }
    : extraction;
  if (options.occurrenceOnlyCandidate === "incomplete") {
    database.prepare(`
      UPDATE attack_knowledge_compiler_runs
      SET status = 'interrupted', completed_at = NULL
      WHERE id IN (
        SELECT compiler.id
        FROM attack_knowledge_compiler_runs compiler
        JOIN historical_attack_knowledge_bundle_sources source_binding
          ON source_binding.bundle_id = compiler.bundle_id
          AND source_binding.receipt_id = compiler.receipt_id
        JOIN historical_attack_knowledge_source_occurrences occurrence
          ON occurrence.candidate_id = source_binding.candidate_id
        WHERE occurrence.migration_id = ?
      )
    `).run(migration.id);
  }
  if (options.receiptOnlyCandidate) {
    const priorPath = join(historyRoot, "prior-events.jsonl");
    const priorContent = JSON.stringify({
      summary: "nginx 1.24.0 request smuggling failed with timeout",
    });
    writeFileSync(priorPath, priorContent, { mode: 0o600 });
    const priorState = statSync(priorPath);
    const prior = metadata.createRun({
      sourceRoots: [historyRoot],
      databasePath,
      outputDirectory,
      sourceRetention: "verified-reference",
      verifiedReferenceAcknowledged: true,
      brainProjectionMode: "attack-knowledge-only",
      attackKnowledgeOnlyAcknowledged: true,
    });
    const priorSource: LegacySource = {
      absolutePath: priorPath,
      relativePath: "prior-events.jsonl",
      root: historyRoot,
      type: "event_jsonl",
      sha256: sha256(priorContent),
      byteSize: Buffer.byteLength(priorContent),
      modifiedAt: priorState.mtime.toISOString(),
    };
    const priorSourceId = metadata.registerSource(prior.id, priorSource, undefined, {
      retentionMode: "verified-reference",
      device: priorState.dev,
      inode: priorState.ino,
    });
    metadata.registerSourceObject({
      migrationId: prior.id,
      sourceId: priorSourceId,
      objectKey: "source",
      sourcePath: priorPath,
      objectKind: "source",
      classification: priorSource.type,
      sourceSha256: priorSource.sha256,
      byteSize: priorSource.byteSize,
      modifiedAt: priorSource.modifiedAt,
      sourceDevice: priorState.dev,
      sourceInode: priorState.ino,
    });
    metadata.markSource(priorSourceId, "completed");
    const priorReceipt = "f".repeat(64);
    database.prepare(`
      INSERT INTO legacy_migration_inventory_receipts (
        migration_id, receipt_hash, object_count, byte_count, created_at
      ) VALUES (?, ?, 1, ?, ?)
    `).run(prior.id, priorReceipt, priorSource.byteSize, fixed.toISOString());
    const priorExtraction = new GenericHistoricalAttackKnowledgeIngestionService(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => fixed,
    }).ingest({ migrationId: prior.id, inventoryReceiptHash: priorReceipt, sources: [priorSource] });
    const candidateId = priorExtraction.sourceEvidenceCandidateIds[0]!;
    extractionReport = {
      ...extraction,
      sourceEvidenceCandidateIds: [...extraction.sourceEvidenceCandidateIds, candidateId].sort(),
      sourceEvidenceCandidatesReused: extraction.sourceEvidenceCandidatesReused + 1,
    };
  }
  if (options.batchMode === "tampered_hash") {
    const reportJson = JSON.stringify(extractionReport);
    const pageKey = sha256(JSON.stringify({
      status: extractionReport.status,
      nextResumeAfterSourceKey: extractionReport.nextResumeAfterSourceKey ?? null,
      nextResumeAfterRecordKey: extractionReport.nextResumeAfterRecordKey ?? null,
    }));
    database.prepare(`
      INSERT INTO legacy_migration_extraction_batches (
        migration_id, extractor_kind, scope_key, page_key, sequence,
        report_json, report_hash, created_at
      ) VALUES (?, 'generic', ?, ?, 1, ?, ?, ?)
    `).run(
      migration.id,
      extractionReport.manifestFingerprint,
      pageKey,
      reportJson,
      "0".repeat(64),
      fixed.toISOString(),
    );
  } else {
    const report: AttackKnowledgeExtractionBatchReport = options.batchMode === "partial"
      ? {
          ...extractionReport,
          status: "partial",
          nextResumeAfterSourceKey: "a".repeat(64),
        }
      : extractionReport;
    metadata.recordExtractionBatch({
      migrationId: migration.id,
      extractorKind: "generic",
      report,
    });
  }
  metadata.failRun(migration.id, options.parentError ?? POST_EXTRACTION_INVENTORY_DRIFT_ERROR);
  return { database, migration, outputDirectory, inventoryReceiptHash };
}

function service(database: ReturnType<typeof createDatabaseConnection>) {
  return new CompletedHistoricalExtractionSealService(database, {
    clock: () => new Date("2026-07-21T18:00:00.000Z"),
    createId: () => "audit_completed_extraction_seal_test",
    activeMigrationProcessIds: () => [],
  });
}

describe("CompletedHistoricalExtractionSealService", () => {
  test("seals only immutable completed extraction receipts without changing knowledge", async () => {
    const { database, migration, inventoryReceiptHash } = fixture();
    try {
      const before = {
        candidates: database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get(),
        nodes: database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get(),
        evidence: database.prepare("SELECT COUNT(*) AS count FROM evidence").get(),
      };
      const preview = service(database).preview({ migrationId: migration.id });
      expect(preview).toMatchObject({
        migrationId: migration.id,
        statusBefore: "failed",
        originalFailure: POST_EXTRACTION_INVENTORY_DRIFT_ERROR,
        inventory: {
          receiptHash: inventoryReceiptHash,
          objectCount: 1,
          sourceCount: 1,
          completedSourceCount: 1,
        },
        extraction: {
          status: "completed",
          partialScopeCount: 0,
          evidenceAutomaticallyVerified: 0,
          reusableMemoryAutomaticallyPromoted: 0,
        },
        semanticKnowledgeChanged: false,
        sourceBytesCopied: false,
        currentSourceInventoryReused: false,
      });
      const result = await withCanonicalWriterLease(database, {
        ownerId: "local-operator",
        operation: "completed-historical-extraction-seal",
      }, (handle, leases) => service(database).seal({
        migrationId: migration.id,
        expectedPreviewHash: preview.previewHash,
        actorId: "local-operator",
        reason: "Seal the completed receipt ledger; import later source drift separately.",
        acknowledged: true,
      }, { handle, leases }));
      expect(result).toMatchObject({
        status: "sealed",
        migrationId: migration.id,
        inventoryReceiptHash,
        previewHash: preview.previewHash,
        completedAt: "2026-07-21T18:00:00.000Z",
      });
      expect(statSync(result.reportPath).mode & 0o777).toBe(0o600);
      expect(JSON.parse(readFileSync(result.reportPath, "utf8"))).toMatchObject({
        disposition: "completed_from_durable_extraction_receipts",
        semanticKnowledgeChanged: false,
        currentSourceInventoryReused: false,
      });
      expect(database.prepare(`
        SELECT status, reconciliation_path, error_summary
        FROM legacy_migration_runs WHERE id = ?
      `).get(migration.id)).toEqual({
        status: "completed",
        reconciliation_path: result.reportPath,
        error_summary: POST_EXTRACTION_INVENTORY_DRIFT_ERROR,
      });
      expect(database.prepare(`
        SELECT report_hash FROM legacy_migration_reconciliation WHERE migration_id = ?
      `).get(migration.id)).toEqual({ report_hash: result.reportHash });
      expect(database.prepare(`
        SELECT action, actor_id FROM audit_records WHERE id = ?
      `).get(result.auditRecordId)).toEqual({
        action: "legacy_migration.completed_extraction_sealed",
        actor_id: "local-operator",
      });
      expect({
        candidates: database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get(),
        nodes: database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get(),
        evidence: database.prepare("SELECT COUNT(*) AS count FROM evidence").get(),
      }).toEqual(before);
    } finally {
      database.close();
    }
  });

  test("fails closed on an unrecognized parent failure, incomplete source, or active importer", () => {
    const wrongFailure = fixture({ parentError: "provider unavailable" });
    try {
      expect(() => service(wrongFailure.database).preview({ migrationId: wrongFailure.migration.id }))
        .toThrow("exact post-extraction inventory-drift guard");
    } finally { wrongFailure.database.close(); }

    const incomplete = fixture({ sourceStatus: "failed" });
    try {
      expect(() => service(incomplete.database).preview({ migrationId: incomplete.migration.id }))
        .toThrow("incomplete or failed source-custody rows");
    } finally { incomplete.database.close(); }

    const active = fixture();
    try {
      const guarded = new CompletedHistoricalExtractionSealService(active.database, {
        activeMigrationProcessIds: () => [4242],
      });
      expect(() => guarded.preview({ migrationId: active.migration.id }))
        .toThrow("migration process is still active");
    } finally { active.database.close(); }
  });

  test("rejects receipt drift, batch tampering, and partial extraction without mutation", () => {
    const receiptDrift = fixture({ receiptByteDelta: 1 });
    try {
      expect(() => service(receiptDrift.database).preview({ migrationId: receiptDrift.migration.id }))
        .toThrow("source custody no longer matches");
    } finally { receiptDrift.database.close(); }

    const tampered = fixture({ batchMode: "tampered_hash" });
    try {
      expect(() => service(tampered.database).preview({ migrationId: tampered.migration.id }))
        .toThrow("report hash mismatch");
    } finally { tampered.database.close(); }

    const partial = fixture({ batchMode: "partial" });
    try {
      expect(() => service(partial.database).preview({ migrationId: partial.migration.id }))
        .toThrow("no completed terminal page");
      expect(partial.database.prepare(`
        SELECT status FROM legacy_migration_runs WHERE id = ?
      `).get(partial.migration.id)).toEqual({ status: "failed" });
    } finally { partial.database.close(); }
  });

  test("allows a receipt-only reused source candidate while preserving occurrence isolation", () => {
    const value = fixture({ receiptOnlyCandidate: true });
    try {
      const preview = service(value.database).preview({ migrationId: value.migration.id });
      expect(preview.integrity).toMatchObject({
        sourceCandidateReceiptCount: 2,
        sourceCandidateOccurrenceCount: 1,
        receiptOnlySourceCandidateCount: 1,
      });
      expect(preview.extraction.status).toBe("completed");
    } finally { value.database.close(); }
  });

  test("accepts an occurrence-only candidate only with its complete immutable source-and-bundle proof chain", () => {
    const value = fixture({ occurrenceOnlyCandidate: "valid" });
    try {
      const preview = service(value.database).preview({ migrationId: value.migration.id });
      expect(preview.integrity).toMatchObject({
        sourceCandidateReceiptCount: 0,
        sourceCandidateOccurrenceCount: 1,
        receiptOnlySourceCandidateCount: 0,
        occurrenceOnlySourceCandidateCount: 1,
        reconciledSourceCandidateCount: 1,
        occurrenceLedgerProofRowCount: 1,
      });
      expect(preview.integrity.occurrenceLedgerProofHash).toMatch(/^[a-f0-9]{64}$/u);
    } finally { value.database.close(); }
  });

  test("rejects an occurrence-only candidate when its compiler proof chain is incomplete", () => {
    const value = fixture({ occurrenceOnlyCandidate: "incomplete" });
    try {
      expect(() => service(value.database).preview({ migrationId: value.migration.id }))
        .toThrow("lacks a complete immutable source-and-bundle proof chain");
      expect(value.database.prepare(`
        SELECT status FROM legacy_migration_runs WHERE id = ?
      `).get(value.migration.id)).toEqual({ status: "failed" });
    } finally { value.database.close(); }
  });

});

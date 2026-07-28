import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { canonicalJson } from "../../orchestration/serialization";
import { GenericHistoricalAttackKnowledgeIngestionService } from "../GenericHistoricalAttackKnowledgeIngestionService";
import {
  HistoricalResidualCandidateSuppressionError,
  HistoricalResidualCandidateSuppressionService,
} from "../HistoricalResidualCandidateSuppressionService";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";
import { runHistoricalResidualSuppressionCli } from "../historical-residual-suppression-cli";
import type { LegacySource } from "../types";

const NOW = "2026-07-21T14:30:00.000Z";
const HMAC_KEY = "historical-residual-suppression-test-key-more-than-32-bytes";
const RECEIPT = "b".repeat(64);
const REASON = "Remove only residual reusable candidates whose source custody is entirely sensitive quarantine.";
const directories: string[] = [];
const databases: SqliteDatabase[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

interface Fixture {
  readonly root: string;
  readonly databasePath: string;
  readonly database: SqliteDatabase;
  readonly source: LegacySource;
  readonly sourceId: string;
  readonly migrationId: string;
  readonly candidateIds: readonly string[];
}

function fixture(status: "completed" | "failed" = "completed"): Fixture {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-residual-suppression-"));
  directories.push(root);
  const databasePath = join(root, "ti-scale.sqlite");
  const database = createDatabaseConnection({ filename: databasePath });
  databases.push(database);
  migrateDatabase(database);

  const sourceRoot = join(root, "historical");
  const path = join(sourceRoot, "runtime", "events.jsonl");
  const content = `${JSON.stringify({
    summary: "Apache HTTP Server 2.4.49 path traversal failed with timeout; reset the service before retry",
  })}\n`;
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, content, { mode: 0o600 });
  const state = statSync(path);
  const source: LegacySource = {
    absolutePath: path,
    relativePath: "runtime/events.jsonl",
    root: sourceRoot,
    type: "event_jsonl",
    sha256: sha256(content),
    byteSize: Buffer.byteLength(content),
    modifiedAt: state.mtime.toISOString(),
  };
  const metadata = new MigrationMetadataRepository(database, () => new Date(NOW));
  const migration = metadata.createRun({
    sourceRoots: [sourceRoot],
    databasePath,
    outputDirectory: join(root, "output"),
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
  });
  const sourceId = metadata.registerSource(migration.id, source, undefined, {
    retentionMode: "verified-reference",
    device: state.dev,
    inode: state.ino,
  });
  metadata.registerSourceObject({
    migrationId: migration.id,
    sourceId,
    objectKey: "source",
    sourcePath: path,
    objectKind: "source",
    classification: source.type,
    sourceSha256: source.sha256,
    byteSize: source.byteSize,
    modifiedAt: source.modifiedAt!,
    sourceDevice: state.dev,
    sourceInode: state.ino,
  });
  database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, 1, ?, ?)
  `).run(migration.id, RECEIPT, source.byteSize, NOW);
  const ingested = new GenericHistoricalAttackKnowledgeIngestionService(database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => new Date(NOW),
  }).ingest({
    migrationId: migration.id,
    inventoryReceiptHash: RECEIPT,
    sources: [source],
  });
  expect(ingested.candidateIds.length).toBeGreaterThan(0);
  database.prepare(`
    UPDATE legacy_migration_source_objects
    SET object_kind = 'quarantined', classification = 'sensitive_content'
    WHERE migration_id = ? AND source_sha256 = ?
  `).run(migration.id, source.sha256);
  database.prepare(`
    UPDATE legacy_migration_runs SET status = ?, completed_at = ? WHERE id = ?
  `).run(status, NOW, migration.id);
  return {
    root,
    databasePath,
    database,
    source,
    sourceId,
    migrationId: migration.id,
    candidateIds: ingested.candidateIds,
  };
}

function input(maxCandidates = 1_000, afterContentFingerprint?: string) {
  return {
    actorId: "operator:historical-privacy-review",
    reason: REASON,
    maxCandidates,
    ...(afterContentFingerprint ? { afterContentFingerprint } : {}),
  } as const;
}

function registerAcceptedCorroboration(value: Fixture): string {
  const metadata = new MigrationMetadataRepository(value.database, () => new Date(NOW));
  const migration = metadata.createRun({
    sourceRoots: [value.source.root],
    databasePath: value.databasePath,
    outputDirectory: join(value.root, "corroboration-output"),
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
  });
  const state = statSync(value.source.absolutePath);
  const sourceId = metadata.registerSource(migration.id, value.source, undefined, {
    retentionMode: "verified-reference",
    device: state.dev,
    inode: state.ino,
  });
  metadata.registerSourceObject({
    migrationId: migration.id,
    sourceId,
    objectKey: "accepted:corroborated",
    sourcePath: value.source.absolutePath,
    objectKind: "accepted",
    classification: "event_jsonl",
    sourceSha256: value.source.sha256,
    byteSize: value.source.byteSize,
    modifiedAt: value.source.modifiedAt!,
    sourceDevice: state.dev,
    sourceInode: state.ino,
  });
  value.database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, 1, ?, ?)
  `).run(migration.id, "c".repeat(64), value.source.byteSize, NOW);
  value.database.prepare(`
    UPDATE legacy_migration_runs SET status = 'completed', completed_at = ? WHERE id = ?
  `).run(NOW, migration.id);
  return migration.id;
}

describe("HistoricalResidualCandidateSuppressionService", () => {
  test("suppresses only the exact previewed sensitive residual page and emits privacy-safe receipts", () => {
    const value = fixture();
    const service = new HistoricalResidualCandidateSuppressionService(value.database, {
      clock: () => new Date(NOW),
    });
    const preview = service.preview(input());
    expect(preview.candidateCount).toBe(value.candidateIds.length);
    expect(preview.candidates.every(({ decision }) => decision === "suppress_do_not_relearn")).toBeTrue();
    expect(preview.candidates.every(({ completedSensitiveMigrationCount }) => completedSensitiveMigrationCount === 1)).toBeTrue();
    const disclosed = canonicalJson(preview);
    expect(disclosed).not.toContain(value.source.absolutePath);
    expect(disclosed).not.toContain(value.source.sha256);
    expect(disclosed).not.toContain("Apache HTTP Server");

    let fenced = false;
    const result = service.execute({
      ...input(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeSuppressSensitiveResiduals: true,
    }, {
      assertActiveInCurrentTransaction: () => {
        expect(value.database.inTransaction).toBeTrue();
        fenced = true;
      },
    });
    expect(fenced).toBeTrue();
    expect(result).toMatchObject({
      status: "completed",
      receipt: {
        selectedCount: preview.candidateCount,
        suppressedCount: preview.candidateCount,
        previewHash: preview.previewHash,
      },
    });
    expect(result.receipt.receiptHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(value.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_candidates
      WHERE id IN (${value.candidateIds.map(() => "?").join(",")})
        AND status = 'suppressed' AND title = '[Suppressed candidate]'
        AND summary = '' AND body = '' AND confidence = 0
        AND source_json = ?
    `).get(...value.candidateIds, canonicalJson({
      method: "suppressed", explanation: "Content removed", sources: [],
    }))).toEqual({ count: value.candidateIds.length });
    expect(value.database.prepare("SELECT COUNT(*) AS count FROM memory_suppressions").get())
      .toEqual({ count: value.candidateIds.length });
    expect(value.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_residual_candidates.suppressed'
    `).get()).toEqual({ count: 1 });
    expect(JSON.stringify(value.database.prepare(`
      SELECT details_json FROM audit_records
      WHERE action = 'historical_residual_candidates.suppressed'
    `).get())).not.toContain(value.source.sha256);

    const replay = service.execute({
      ...input(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeSuppressSensitiveResiduals: true,
    }, { assertActiveInCurrentTransaction: () => undefined });
    expect(replay).toMatchObject({ status: "replayed", receipt: result.receipt });
  });

  test("fails a stale preview when safe completed corroboration arrives", () => {
    const value = fixture();
    const service = new HistoricalResidualCandidateSuppressionService(value.database, {
      clock: () => new Date(NOW),
    });
    const preview = service.preview(input());
    expect(preview.candidateCount).toBeGreaterThan(0);
    registerAcceptedCorroboration(value);
    expect(service.preview(input()).candidateCount).toBe(0);
    expect(() => service.execute({
      ...input(),
      expectedPreviewHash: preview.previewHash,
      acknowledgeSuppressSensitiveResiduals: true,
    }, { assertActiveInCurrentTransaction: () => undefined })).toThrow(
      HistoricalResidualCandidateSuppressionError,
    );
    expect(value.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_candidates WHERE status = 'suppressed'
    `).get()).toEqual({ count: 0 });
  });

  test("does not select failed-only custody and pages deterministically", () => {
    const failed = fixture("failed");
    expect(new HistoricalResidualCandidateSuppressionService(failed.database).preview(input()).candidateCount)
      .toBe(0);

    const completed = fixture();
    const service = new HistoricalResidualCandidateSuppressionService(completed.database);
    const first = service.preview(input(1));
    expect(first.candidateCount).toBe(1);
    if (completed.candidateIds.length > 1) {
      expect(first.hasMore).toBeTrue();
      const second = service.preview(input(1, first.nextSelectionCursor!));
      expect(second.candidateCount).toBe(1);
      expect(second.candidates[0]!.candidateId).not.toBe(first.candidates[0]!.candidateId);
    }
  });

  test("CLI is preview-gated, lease-fenced, and writes a mode-0600 receipt", async () => {
    const value = fixture();
    let output = "";
    expect(await runHistoricalResidualSuppressionCli([
      "preview", "--db", value.databasePath,
      "--actor", "operator:historical-privacy-review", "--reason", REASON,
      "--dry-run", "--max-candidates", "1000",
    ], {}, { write: (chunk) => { output += chunk; } })).toBe(0);
    const preview = JSON.parse(output) as { previewHash: string; candidateCount: number };
    expect(preview.candidateCount).toBeGreaterThan(0);
    const receiptPath = join(value.root, "suppression-receipt.json");
    output = "";
    expect(await runHistoricalResidualSuppressionCli([
      "run", "--db", value.databasePath,
      "--actor", "operator:historical-privacy-review", "--reason", REASON,
      "--expected-preview-hash", preview.previewHash,
      "--receipt", receiptPath,
      "--acknowledge-suppress-sensitive-residuals",
      "--max-candidates", "1000",
    ], {}, { write: (chunk) => { output += chunk; } })).toBe(0);
    expect(statSync(receiptPath).mode & 0o777).toBe(0o600);
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as {
      status: string;
      receipt: { previewHash: string };
    };
    expect(receipt).toMatchObject({
      status: "completed",
      receipt: { previewHash: preview.previewHash },
    });
    expect(output).not.toContain(value.source.sha256);
  });
});

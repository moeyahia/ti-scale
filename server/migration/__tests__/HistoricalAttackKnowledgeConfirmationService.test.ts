import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository, memoryContentHash } from "../../memory";
import {
  CanonicalDatabaseLeaseLostError,
  CanonicalDatabaseLeaseService,
  withCanonicalWriterLease,
} from "../../maintenance";
import { canonicalJson } from "../../orchestration/serialization";
import { HistoricalAttackKnowledgeConfirmationService } from "../HistoricalAttackKnowledgeConfirmationService";
import {
  HistoricalPrivateSourceCustodyProjectionService,
  type HistoricalPrivateSourceBindingInput,
} from "../HistoricalPrivateSourceCustodyProjectionService";
import {
  HistoricalAttackKnowledgeConfirmationOrchestrator,
  historicalConfirmationAllPagesStateKey,
} from "../HistoricalAttackKnowledgeConfirmationOrchestrator";
import { HistoricalAttackKnowledgeExtractionService } from "../HistoricalAttackKnowledgeExtractionService";
import type { LegacyEngagementFile, LegacyEngagementManifest } from "../LegacyEngagementDiscovery";
import { ensureLegacyEngagementSchema } from "../LegacyEngagementImporter";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";
import { runHistoricalAttackConfirmationCli } from "../historical-attack-confirmation-cli";
import { runHistoricalAttackConfirmationAllCli } from "../historical-attack-confirm-all-cli";

const HMAC_KEY = "historical-confirmation-test-key-more-than-32-bytes";
const NOW = "2026-07-21T10:00:00.000Z";
const REASON = "Confirm every sanitized historical attack-memory candidate in this exact page.";
const directories: string[] = [];
const databases: SqliteDatabase[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function fixture(content: string, options: {
  readonly kind?: LegacyEngagementFile["kind"];
  readonly relativePath?: string;
  readonly duplicateRelativePaths?: readonly string[];
} = {}): {
  readonly directory: string;
  readonly database: SqliteDatabase;
  readonly databasePath: string;
  readonly migrationId: string;
  readonly compilerBundlesStaged: number;
} {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-historical-confirm-"));
  directories.push(directory);
  const databasePath = join(directory, "test.sqlite");
  const database = createDatabaseConnection({ filename: databasePath });
  databases.push(database);
  migrateDatabase(database);

  const engagementName = "historical-source";
  const engagementDirectory = join(directory, engagementName);
  const files = [options.relativePath ?? "notes/attack.md", ...(options.duplicateRelativePaths ?? [])]
    .map((relativePath): LegacyEngagementFile => {
      const absolutePath = join(engagementDirectory, relativePath);
      mkdirSync(join(absolutePath, ".."), { recursive: true });
      writeFileSync(absolutePath, content);
      const state = statSync(absolutePath);
      return {
        absolutePath,
        relativePath,
        kind: options.kind ?? "note",
        contentClass: "text",
        mediaType: "text/markdown",
        sha256: sha256(content),
        byteSize: Buffer.byteLength(content),
        modifiedAt: state.mtime.toISOString(),
      };
    });
  const file = files[0]!;
  const engagementKey = sha256(`engagement\0${engagementName}`);
  const manifest: LegacyEngagementManifest = {
    id: `legacy_engagement_${engagementKey.slice(0, 40)}`,
    root: directory,
    rootIdentity: "confirmation-test-root",
    engagementDirectory,
    engagementName,
    engagementKey,
    sha256: sha256(canonicalManifest(files)),
    byteSize: files.reduce((total, item) => total + item.byteSize, 0),
    modifiedAt: files.map(({ modifiedAt }) => modifiedAt).sort().at(-1)!,
    files,
    quarantined: [],
  };
  const metadata = new MigrationMetadataRepository(database, () => new Date(NOW));
  metadata.ensureSchema();
  const run = metadata.createRun({
    sourceRoots: [directory],
    databasePath,
    outputDirectory: join(directory, "output"),
    startedAt: NOW,
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
  });
  const rootState = statSync(engagementDirectory);
  const sourceId = metadata.registerSource(run.id, {
    absolutePath: engagementDirectory,
    relativePath: engagementName,
    root: directory,
    type: "engagement_manifest",
    sha256: manifest.sha256,
    byteSize: manifest.byteSize,
    modifiedAt: manifest.modifiedAt,
  }, undefined, {
    retentionMode: "verified-reference",
    device: rootState.dev,
    inode: rootState.ino,
  });
  for (const sourceFile of files) {
    const state = statSync(sourceFile.absolutePath);
    metadata.registerSourceObject({
      migrationId: run.id,
      sourceId,
      objectKey: `accepted:${sourceFile.relativePath}`,
      sourcePath: sourceFile.absolutePath,
      objectKind: "accepted",
      classification: sourceFile.kind,
      sourceSha256: sourceFile.sha256,
      byteSize: sourceFile.byteSize,
      modifiedAt: sourceFile.modifiedAt,
      sourceDevice: state.dev,
      sourceInode: state.ino,
    });
  }
  database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, ?, ?, ?)
  `).run(run.id, sha256(canonicalManifest(files)), files.length, manifest.byteSize, NOW);
  const extracted = new HistoricalAttackKnowledgeExtractionService(database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => new Date(NOW),
  }).extract(manifest);
  database.prepare(`
    UPDATE legacy_migration_runs SET status = 'completed', completed_at = ? WHERE id = ?
  `).run(NOW, run.id);
  return {
    directory,
    database,
    databasePath,
    migrationId: run.id,
    compilerBundlesStaged: extracted.compilerBundlesStaged,
  };
}

function canonicalManifest(files: readonly LegacyEngagementFile[]): string {
  return JSON.stringify(files.map((file) => ({
    relativePath: file.relativePath,
    sha256: file.sha256,
    byteSize: file.byteSize,
    modifiedAt: file.modifiedAt,
  })));
}

function evidenceLinkedScript(marker = "ready"): string {
  return [
    "#!/usr/bin/env sh",
    "# Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
    "# Encoded path normalization and directory traversal were observed together in this bounded procedure.",
    "# The bounded procedure succeeded against the exact reviewed version.",
    "set -eu",
    `printf '%s\\n' ${marker}`,
  ].join("\n");
}

function request(migrationId: string, maxCandidates = 1_000, afterContentFingerprint?: string) {
  return {
    migrationId,
    actorId: "operator:historical-confirmation",
    reason: REASON,
    maxCandidates,
    ...(afterContentFingerprint ? { afterContentFingerprint } : {}),
  } as const;
}

function rekeyCandidateAfterTestMutation(
  database: SqliteDatabase,
  candidateId: string,
): string {
  const prior = database.prepare(`
    SELECT content_fingerprint FROM attack_knowledge_candidate_registry
    WHERE candidate_id = ?
  `).get(candidateId) as { readonly content_fingerprint: string };
  const candidate = new MemoryRepository(database, { clock: () => new Date(NOW) })
    .requireCandidate(candidateId);
  const next = memoryContentHash(candidate);
  database.exec("PRAGMA defer_foreign_keys = ON; BEGIN IMMEDIATE");
  try {
    database.prepare(`
      UPDATE attack_knowledge_candidate_registry
      SET content_fingerprint = ? WHERE candidate_id = ?
    `).run(next, candidateId);
    database.prepare(`
      UPDATE attack_knowledge_bundle_candidates
      SET content_fingerprint = ? WHERE content_fingerprint = ?
    `).run(next, prior.content_fingerprint);
    database.exec("COMMIT");
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
  return next;
}

function addRepeatedRelationshipOrigins(
  database: SqliteDatabase,
  migrationId: string,
  count: number,
): void {
  const base = database.prepare(`
    SELECT edge.source_role, edge.target_role, edge.edge_type,
      source_candidate.content_fingerprint AS source_fingerprint,
      target_candidate.content_fingerprint AS target_fingerprint,
      source_binding.candidate_id, source_binding.source_hash
    FROM attack_knowledge_bundle_edges edge
    JOIN attack_knowledge_bundle_candidates source_candidate
      ON source_candidate.bundle_id = edge.bundle_id
     AND source_candidate.role = edge.source_role
    JOIN attack_knowledge_bundle_candidates target_candidate
      ON target_candidate.bundle_id = edge.bundle_id
     AND target_candidate.role = edge.target_role
    JOIN historical_attack_knowledge_bundle_sources source_binding
      ON source_binding.bundle_id = edge.bundle_id
    JOIN historical_attack_knowledge_source_occurrences occurrence
      ON occurrence.candidate_id = source_binding.candidate_id
     AND occurrence.source_hash = source_binding.source_hash
    WHERE occurrence.migration_id = ?
    ORDER BY edge.bundle_id, edge.edge_key LIMIT 1
  `).get(migrationId) as {
    readonly source_role: string;
    readonly target_role: string;
    readonly edge_type: string;
    readonly source_fingerprint: string;
    readonly target_fingerprint: string;
    readonly candidate_id: string;
    readonly source_hash: string;
  };
  for (let index = 0; index < count; index += 1) {
    const sanitized = canonicalJson({
      schemaVersion: 1,
      knowledge: "same typed relationship observed in an independent bounded bundle",
      observationOrdinal: index,
    });
    const fingerprint = sha256(sanitized);
    const bundleId = `akb_${fingerprint}`;
    const receiptId = `akreceipt_test_${index}`;
    database.prepare(`
      INSERT INTO attack_knowledge_bundles (
        id, semantic_fingerprint, sanitized_bundle_json, status,
        first_observed_at, last_observed_at, created_at, updated_at
      ) VALUES (?, ?, ?, 'staged', ?, ?, ?, ?)
    `).run(bundleId, fingerprint, sanitized, NOW, NOW, NOW, NOW);
    database.prepare(`
      INSERT INTO attack_knowledge_provenance_receipts (
        id, source_class, source_hash, evidence_count, observed_at, created_at
      ) VALUES (?, 'historical', ?, 1, ?, ?)
    `).run(receiptId, sha256(`relationship-origin-${index}`), NOW, NOW);
    database.prepare(`
      INSERT INTO attack_knowledge_bundle_receipts (bundle_id, receipt_id, linked_at)
      VALUES (?, ?, ?)
    `).run(bundleId, receiptId, NOW);
    database.prepare(`
      INSERT INTO attack_knowledge_bundle_candidates (
        bundle_id, role, content_fingerprint, required, ordinal, linked_at
      ) VALUES (?, ?, ?, 1, 0, ?), (?, ?, ?, 1, 1, ?)
    `).run(
      bundleId, base.source_role, base.source_fingerprint, NOW,
      bundleId, base.target_role, base.target_fingerprint, NOW,
    );
    database.prepare(`
      INSERT INTO attack_knowledge_bundle_edges (
        bundle_id, edge_key, source_role, target_role, edge_type
      ) VALUES (?, 'relationship', ?, ?, ?)
    `).run(bundleId, base.source_role, base.target_role, base.edge_type);
    database.prepare(`
      INSERT INTO historical_attack_knowledge_bundle_sources (
        bundle_id, receipt_id, candidate_id, source_hash, binding_hash, linked_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      bundleId,
      receiptId,
      base.candidate_id,
      base.source_hash,
      sha256(`${bundleId}\0${receiptId}\0${base.candidate_id}`),
      NOW,
    );
  }
}

function prepareCustodyInputs(
  database: SqliteDatabase,
  migrationId: string,
): readonly HistoricalPrivateSourceBindingInput[] {
  const preview = new HistoricalAttackKnowledgeConfirmationService(
    database,
    () => new Date(NOW),
  ).preview(request(migrationId));
  const context = database.prepare(`
    SELECT mission_id, run_id FROM historical_attack_knowledge_import_contexts
    WHERE migration_id = ?
  `).get(migrationId) as { readonly mission_id: string; readonly run_id: string };
  const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const inputs: HistoricalPrivateSourceBindingInput[] = [];
  for (const candidate of preview.review.candidates) {
    if (candidate.decision !== "confirm") continue;
    const node = memory.confirmCandidate(
      candidate.candidateId,
      "operator:historical-confirmation",
    );
    for (const source of candidate.sourceBindings) {
      const memorySourceId = `msrc_hak_${sha256(
        `${node.id}\0${source.sourceCandidateId}\0${migrationId}`,
      ).slice(0, 48)}`;
      database.prepare(`
        INSERT INTO memory_sources (
          id, node_id, source_type, source_id, mission_id, run_id,
          evidence_id, source_hash, excerpt_redacted, acquired_at, created_at
        ) VALUES (?, ?, 'historical_attack_knowledge_source_candidate', ?, ?, ?, ?, ?, NULL, ?, ?)
        ON CONFLICT(node_id, source_type, source_id) DO NOTHING
      `).run(
        memorySourceId,
        node.id,
        source.sourceId,
        context.mission_id,
        context.run_id,
        source.evidenceId,
        source.sourceHash,
        source.modifiedAt,
        NOW,
      );
      inputs.push({
        memorySourceId,
        sourceCandidateId: source.sourceCandidateId,
        migrationId,
        sourceReference: source.sourceReference,
        sourceHash: source.sourceHash,
      });
    }
  }
  return inputs;
}

function convertFixtureSourceToVerifiedFileRoot(
  database: SqliteDatabase,
  migrationId: string,
  registeredRelativePath = "provider-history/sessions/health-check.sh",
): { readonly sourceId: string; readonly sourcePath: string } {
  const row = database.prepare(`
    SELECT source.id AS source_id, object.source_path, object.source_sha256,
      object.byte_size, object.modified_at, object.source_device, object.source_inode
    FROM legacy_migration_sources source
    JOIN legacy_migration_source_objects object ON object.source_id = source.id
    WHERE source.migration_id = ?
    ORDER BY object.id LIMIT 1
  `).get(migrationId) as {
    readonly source_id: string;
    readonly source_path: string;
    readonly source_sha256: string;
    readonly byte_size: number;
    readonly modified_at: string;
    readonly source_device: number;
    readonly source_inode: number;
  };
  const sourceType = "provider_session_jsonl";
  database.prepare(
    "UPDATE legacy_migration_runs SET status = 'running', completed_at = NULL WHERE id = ?",
  ).run(migrationId);
  try {
    database.prepare(`
      UPDATE legacy_migration_sources SET source_path = ?, relative_path = ?,
        source_type = ?, source_identity = ?, source_sha256 = ?, byte_size = ?,
        modified_at = ?, source_device = ?, source_inode = ?
      WHERE id = ?
    `).run(
      row.source_path,
      registeredRelativePath,
      sourceType,
      sha256(`${sourceType}\0${row.source_path}`),
      row.source_sha256,
      row.byte_size,
      row.modified_at,
      row.source_device,
      row.source_inode,
      row.source_id,
    );
    database.prepare(`
      UPDATE legacy_migration_source_objects SET object_kind = 'source'
      WHERE source_id = ?
    `).run(row.source_id);
  } finally {
    database.prepare(
      "UPDATE legacy_migration_runs SET status = 'completed', completed_at = ? WHERE id = ?",
    ).run(NOW, migrationId);
  }
  return { sourceId: row.source_id, sourcePath: row.source_path };
}

function mutateFixtureSourceObject(
  database: SqliteDatabase,
  migrationId: string,
  sql: string,
  ...parameters: readonly unknown[]
): void {
  database.prepare(
    "UPDATE legacy_migration_runs SET status = 'running', completed_at = NULL WHERE id = ?",
  ).run(migrationId);
  try {
    database.prepare(sql).run(...parameters);
  } finally {
    database.prepare(
      "UPDATE legacy_migration_runs SET status = 'completed', completed_at = ? WHERE id = ?",
    ).run(NOW, migrationId);
  }
}

describe("HistoricalAttackKnowledgeConfirmationService", () => {
  test("hash-binds, confirms, connects, pages, and replays without claiming verification", () => {
    const { database, migrationId } = fixture([
      "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
      "Encoded path normalization and directory traversal were observed together in the same bounded technical record.",
    ].join("\n"));
    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    let after: string | undefined;
    let totalConfirmed = 0;
    let totalEdges = 0;
    let first: { previewHash: string; cursor: string } | undefined;
    for (let page = 0; page < 50; page += 1) {
      const preview = service.preview(request(migrationId, 1, after));
      expect(preview.candidateCount).toBe(1);
      expect(preview.review.candidates[0]).toMatchObject({ decision: "confirm" });
      const result = service.execute({
        ...request(migrationId, 1, after),
        expectedPreviewHash: preview.previewHash,
        acknowledgeConfirmAllSafe: true,
      });
      expect(result.status).toBe("completed");
      totalConfirmed += result.confirmedCount;
      totalEdges += result.edgesCreated;
      first ??= { previewHash: preview.previewHash, cursor: preview.nextSelectionCursor! };
      after = preview.nextSelectionCursor ?? undefined;
      if (!preview.hasMore) break;
    }
    expect(totalConfirmed).toBeGreaterThan(1);
    expect(totalEdges).toBeGreaterThan(0);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_nodes
      WHERE lifecycle_status = 'confirmed' AND confirmation_state = 'confirmed'
        AND author_type = 'operator'
    `).get()).toEqual({ count: totalConfirmed });
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM memory_nodes WHERE lifecycle_status = 'verified'",
    ).get()).toEqual({ count: 0 });
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM memory_edges WHERE lifecycle_status = 'confirmed'",
    ).get()).toEqual({ count: totalEdges });
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM reusable_knowledge_outcome_links",
    ).get()).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count
      FROM memory_nodes node
      WHERE node.lifecycle_status = 'confirmed'
        AND NOT EXISTS (
          SELECT 1 FROM memory_sources source
          WHERE source.node_id = node.id
            AND source.source_type = 'historical_attack_knowledge_source_candidate'
            AND source.mission_id IS NOT NULL
            AND source.run_id IS NOT NULL
            AND source.source_hash IS NOT NULL
        )
    `).get()).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM historical_private_source_bindings
    `).get()).toEqual({ count: totalConfirmed });
    expect(database.prepare(`
      SELECT COUNT(DISTINCT artifact_id) AS count
      FROM historical_private_source_bindings
    `).get()).toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM historical_private_source_collections
    `).get()).toEqual({ count: 1 });

    const replay = service.execute({
      ...request(migrationId, 1),
      expectedPreviewHash: first!.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    expect(replay).toMatchObject({ status: "replayed", confirmedCount: 1 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.confirmed'
    `).get()).toEqual({ count: totalConfirmed });
  });

  test("does not stage a source-only script artifact or invent an edge", () => {
    const content = "#!/usr/bin/env sh\nset -eu\nprintf '%s\\n' ready\n";
    const { database, compilerBundlesStaged } = fixture(content, {
      kind: "script",
      relativePath: "scripts/health-check.sh",
    });
    expect(compilerBundlesStaged).toBe(0);
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM memory_candidates",
    ).get()).toEqual({ count: 0 });
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM attack_knowledge_bundles",
    ).get()).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_edges
    `).get()).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM historical_private_source_bindings
    `).get()).toEqual({ count: 0 });
  });

  test("an exact confirmation replay repairs custody rows created before migration 034", () => {
    const content = evidenceLinkedScript();
    const { database, migrationId } = fixture(content, {
      kind: "script",
      relativePath: "scripts/health-check.sh",
    });
    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    const preview = service.preview(request(migrationId));
    const executed = service.execute({
      ...request(migrationId),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    const bindingCount = database.prepare(
      "SELECT COUNT(*) AS count FROM historical_private_source_bindings",
    ).get() as { readonly count: number };
    expect(bindingCount.count).toBeGreaterThan(0);
    const edgeCount = database.prepare(
      "SELECT COUNT(*) AS count FROM memory_edges",
    ).get();
    const auditCount = database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.confirmed'
    `).get();

    // Test-only downgrade simulation: older confirmed memory had source rows,
    // but migration 034 and its immutable private custody binding did not yet exist.
    database.exec("DROP TRIGGER historical_private_source_bindings_no_delete");
    database.exec("DELETE FROM historical_private_source_bindings");
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM historical_private_source_bindings",
    ).get()).toEqual({ count: 0 });

    const replay = service.execute({
      ...request(migrationId),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    expect(replay).toMatchObject({
      status: "replayed",
      auditRecordId: executed.auditRecordId,
    });
    expect(replay.privateSourceBindingsCreated).toBeGreaterThanOrEqual(bindingCount.count);
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM historical_private_source_bindings",
    ).get()).toEqual(bindingCount);
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get()).toEqual(edgeCount);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.confirmed'
    `).get()).toEqual(auditCount);
  });

  test("preserves every exact origin when one e90-shaped candidate and hash occurs in four source records", () => {
    const content = evidenceLinkedScript("exact-origin");
    const { database, migrationId } = fixture(content, {
      kind: "script",
      relativePath: "scripts/health-check.sh",
      duplicateRelativePaths: [
        "ops/recovery/health-check.sh",
        "research/replay/health-check.sh",
        "web/root_push/health-check.sh",
      ],
    });
    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    const preview = service.preview(request(migrationId));
    const script = preview.review.candidates.find(({ nodeType }) => nodeType === "script_artifact")!;
    expect(script).toMatchObject({
      decision: "confirm",
      relationshipState: "typed",
      sourceBindingCount: 4,
    });
    expect(script.typedRelationshipCount).toBeGreaterThan(0);
    expect(new Set(script.sourceBindings.map(({ sourceReference }) => sourceReference)).size).toBe(4);

    const result = service.execute({
      ...request(migrationId),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    expect(result.privateSourceBindingsCreated).toBeGreaterThanOrEqual(4);
    const materialized = database.prepare(
      "SELECT proposed_node_id FROM memory_candidates WHERE id = ?",
    ).get(script.candidateId) as { readonly proposed_node_id: string };
    expect(database.prepare(`
      SELECT COUNT(*) AS binding_count,
        COUNT(DISTINCT binding.source_reference) AS source_reference_count,
        COUNT(DISTINCT binding.artifact_id) AS artifact_count,
        COUNT(DISTINCT binding.memory_source_id) AS memory_source_count
      FROM historical_private_source_bindings binding
      JOIN memory_sources source ON source.id = binding.memory_source_id
      WHERE source.node_id = ?
    `).get(materialized.proposed_node_id)).toEqual({
      binding_count: 4,
      source_reference_count: 4,
      artifact_count: 4,
      memory_source_count: 1,
    });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_edges
      WHERE source_node_id = ? OR target_node_id = ?
    `).get(materialized.proposed_node_id, materialized.proposed_node_id)).toEqual({
      count: script.typedRelationshipCount,
    });

    const replay = service.execute({
      ...request(migrationId),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    expect(replay.status).toBe("replayed");
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM historical_private_source_bindings binding
      JOIN memory_sources source ON source.id = binding.memory_source_id
      WHERE source.node_id = ?
    `).get(materialized.proposed_node_id)).toEqual({ count: 4 });
  });

  test("batched private custody is row- and receipt-equivalent to scalar binding with duplicate origins", async () => {
    const content = [
      "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
      "Encoded path normalization and directory traversal were observed together.",
      "The bounded procedure failed with an execution timeout.",
      "Restart the disposable service and require a health check before retrying.",
    ].join("\n");
    const { directory, database, migrationId } = fixture(content, {
      duplicateRelativePaths: [
        "ops/recovery/attack.md",
        "research/replay/attack.md",
        "web/root_push/attack.md",
      ],
    });
    const baseInputs = prepareCustodyInputs(database, migrationId);
    expect(baseInputs.length).toBeGreaterThan(4);
    expect(new Set(baseInputs.map(({ sourceReference }) => sourceReference)).size)
      .toBeGreaterThan(1);
    const inputs = [...baseInputs, baseInputs[0]!];

    const scalarStatements: string[] = [];
    const batchStatements: string[] = [];
    const trace = (target: SqliteDatabase, statements: string[]): SqliteDatabase => new Proxy(target, {
      get(databaseTarget, property) {
        if (property === "prepare") {
          return (sql: string) => {
            statements.push(sql);
            return databaseTarget.prepare(sql);
          };
        }
        const value = Reflect.get(databaseTarget, property, databaseTarget) as unknown;
        return typeof value === "function" ? value.bind(databaseTarget) : value;
      },
    }) as SqliteDatabase;
    const scalarService = new HistoricalPrivateSourceCustodyProjectionService(
      trace(database, scalarStatements),
      { clock: () => new Date(NOW) },
    );
    const batchService = new HistoricalPrivateSourceCustodyProjectionService(
      trace(database, batchStatements),
      { clock: () => new Date(NOW) },
    );

    const custodySnapshot = (source: SqliteDatabase) => ({
      collections: source.prepare(`
        SELECT source_identity, mission_id, run_id, created_at
        FROM historical_private_source_collections ORDER BY source_identity
      `).all(),
      missions: source.prepare(`
        SELECT id, name, objective, journey, status, authorization_status,
          engagement_id, scope_json, success_criteria_json,
          retention_policy_json, memory_policy_json, created_by,
          version, created_at, updated_at, control_plane
        FROM missions
        WHERE created_by = 'system:historical-private-source-projection'
        ORDER BY id
      `).all(),
      runs: source.prepare(`
        SELECT run.id, run.mission_id, run.journey, run.status, run.progress,
          run.status_reason, run.next_action_summary, run.budget_json,
          run.budget_usage_json, run.retry_count, run.replan_count,
          run.started_at, run.ended_at, run.created_at, run.updated_at,
          run.version, run.control_plane
        FROM runs run JOIN missions mission ON mission.id = run.mission_id
        WHERE mission.created_by = 'system:historical-private-source-projection'
        ORDER BY run.id
      `).all(),
      artifacts: source.prepare(`
        SELECT id, mission_id, run_id, journey, artifact_type, storage_uri,
          content_hash, byte_size, media_type, sensitivity, metadata_json,
          created_at
        FROM artifacts WHERE artifact_type = 'legacy_private_source_custody'
        ORDER BY id
      `).all(),
      bindings: source.prepare(`
        SELECT memory_source_id, source_candidate_id, migration_id,
          source_reference, source_hash, mission_id, run_id, artifact_id,
          binding_method, binding_receipt_hash, created_at
        FROM historical_private_source_bindings
        ORDER BY memory_source_id, source_reference
      `).all(),
    });
    database.exec("BEGIN IMMEDIATE");
    let scalarResults!: readonly ReturnType<
      HistoricalPrivateSourceCustodyProjectionService["bind"]
    >[];
    let scalarSnapshot!: ReturnType<typeof custodySnapshot>;
    try {
      scalarResults = inputs.map((input) => scalarService.bind(input));
      scalarSnapshot = custodySnapshot(database);
    } finally {
      database.exec("ROLLBACK");
    }
    const batchResults = batchService.bindBatch(inputs);
    expect(canonicalJson(batchResults)).toBe(canonicalJson(scalarResults));
    expect(batchResults.at(-1)).toMatchObject({ created: false });
    expect(canonicalJson(custodySnapshot(database))).toBe(canonicalJson(scalarSnapshot));
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM historical_private_source_bindings
    `).get()).toEqual({ count: new Set(baseInputs.map((input) => (
      JSON.stringify([input.memorySourceId, input.sourceReference])
    ))).size });

    expect(batchStatements.length).toBeLessThanOrEqual(12);
    expect(batchStatements.length * 3).toBeLessThan(scalarStatements.length);
    scalarStatements.length = 0;
    batchStatements.length = 0;
    const scalarReplay = inputs.map((input) => scalarService.bind(input));
    const batchReplay = batchService.bindBatch(inputs);
    expect(canonicalJson(batchReplay)).toBe(canonicalJson(scalarReplay));
    expect(batchReplay.every(({ created }) => !created)).toBe(true);
    expect(batchStatements.length).toBe(1);
    expect(scalarStatements.length).toBe(inputs.length);
  });

  test("batched preview is byte-equivalent to the prior per-candidate query semantics", () => {
    const { database, migrationId } = fixture([
      "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
      "Encoded path normalization and directory traversal were observed together in the same bounded technical record.",
    ].join("\n"), {
      duplicateRelativePaths: [
        "ops/recovery/attack.md",
        "research/replay/attack.md",
        "web/root_push/attack.md",
      ],
    });
    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    const input = request(migrationId);
    const preview = service.preview(input);
    const legacyRows = database.prepare(`
      SELECT DISTINCT registry.content_fingerprint, registry.candidate_id
      FROM attack_knowledge_bundle_candidates bundle_candidate
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = bundle_candidate.content_fingerprint
      WHERE registry.content_fingerprint > ?
        AND EXISTS (
          SELECT 1
          FROM historical_attack_knowledge_bundle_sources source_binding
          JOIN historical_attack_knowledge_source_occurrences occurrence
            ON occurrence.candidate_id = source_binding.candidate_id
           AND occurrence.source_hash = source_binding.source_hash
          WHERE source_binding.bundle_id = bundle_candidate.bundle_id
            AND occurrence.migration_id = ?
        )
      ORDER BY registry.content_fingerprint
      LIMIT ?
    `).all("", migrationId, input.maxCandidates + 1) as Array<{
      readonly content_fingerprint: string;
      readonly candidate_id: string;
    }>;
    const legacySelected = legacyRows.slice(0, input.maxCandidates);
    expect(legacyRows.length > input.maxCandidates).toBe(preview.hasMore);
    expect(legacySelected.map(({ content_fingerprint }) => content_fingerprint))
      .toEqual(preview.review.candidates.map(({ contentFingerprint }) => contentFingerprint));
    expect(legacySelected.map(({ candidate_id }) => candidate_id))
      .toEqual(preview.review.candidates.map(({ candidateId }) => candidateId));

    const optimizedByCandidate = new Map(
      preview.review.candidates.map((candidate) => [candidate.candidateId, candidate]),
    );
    const legacyCandidates = legacySelected.map((selected) => {
      const optimized = optimizedByCandidate.get(selected.candidate_id)!;
      const sourceRows = database.prepare(`
        SELECT DISTINCT occurrence.candidate_id, occurrence.source_reference,
          occurrence.source_hash, occurrence.modified_at, occurrence.observed_at,
          evidence_candidate.promoted_evidence_id
        FROM attack_knowledge_bundle_candidates bundle_candidate
        JOIN historical_attack_knowledge_bundle_sources source_binding
          ON source_binding.bundle_id = bundle_candidate.bundle_id
        JOIN historical_attack_knowledge_source_occurrences occurrence
          ON occurrence.candidate_id = source_binding.candidate_id
         AND occurrence.source_hash = source_binding.source_hash
        JOIN evidence_candidates evidence_candidate
          ON evidence_candidate.id = occurrence.candidate_id
        WHERE bundle_candidate.content_fingerprint = ?
          AND occurrence.migration_id = ?
        ORDER BY occurrence.source_hash, occurrence.source_reference
        LIMIT ?
      `).all(
        selected.content_fingerprint,
        migrationId,
        25_001,
      ) as Array<{
        readonly candidate_id: string;
        readonly source_reference: string;
        readonly source_hash: string;
        readonly modified_at: string;
        readonly observed_at: string;
        readonly promoted_evidence_id: string | null;
      }>;
      const relationship = database.prepare(`
        SELECT COUNT(DISTINCT edge.bundle_id || char(0) || edge.edge_key) AS relationship_count
        FROM attack_knowledge_bundle_candidates candidate
        JOIN attack_knowledge_bundle_edges edge
          ON edge.bundle_id = candidate.bundle_id
         AND (edge.source_role = candidate.role OR edge.target_role = candidate.role)
        WHERE candidate.content_fingerprint = ?
          AND EXISTS (
            SELECT 1
            FROM historical_attack_knowledge_bundle_sources source_binding
            JOIN historical_attack_knowledge_source_occurrences occurrence
              ON occurrence.candidate_id = source_binding.candidate_id
             AND occurrence.source_hash = source_binding.source_hash
            WHERE source_binding.bundle_id = candidate.bundle_id
              AND occurrence.migration_id = ?
          )
      `).get(selected.content_fingerprint, migrationId) as {
        readonly relationship_count: number;
      };
      const sourceBindings = sourceRows.map((source) => ({
        sourceCandidateId: source.candidate_id,
        sourceReference: source.source_reference,
        sourceHash: source.source_hash,
        modifiedAt: source.modified_at,
        observedAt: source.observed_at,
        evidenceId: source.promoted_evidence_id,
        sourceId: `${source.candidate_id}:${migrationId}`,
      }));
      return {
        ...optimized,
        sourceBindingCount: sourceBindings.length,
        typedRelationshipCount: relationship.relationship_count,
        relationshipState: relationship.relationship_count > 0 ? "typed" as const : "unlinked" as const,
        sourceBindings,
      };
    });
    const selectedFingerprints = legacySelected.map(({ content_fingerprint }) => content_fingerprint);
    const placeholders = selectedFingerprints.map(() => "?").join(", ");
    const lastFingerprint = selectedFingerprints.at(-1)!;
    const legacyEdgeRows = database.prepare(`
      SELECT bundle.id AS bundle_id, bundle.semantic_fingerprint,
        bundle.sanitized_bundle_json, bundle.last_observed_at,
        edge.edge_key, edge.edge_type,
        source_candidate.content_fingerprint AS source_fingerprint,
        target_candidate.content_fingerprint AS target_fingerprint
      FROM attack_knowledge_bundle_edges edge
      JOIN attack_knowledge_bundles bundle ON bundle.id = edge.bundle_id
      JOIN attack_knowledge_bundle_candidates source_candidate
        ON source_candidate.bundle_id = edge.bundle_id
       AND source_candidate.role = edge.source_role
      JOIN attack_knowledge_bundle_candidates target_candidate
        ON target_candidate.bundle_id = edge.bundle_id
       AND target_candidate.role = edge.target_role
      WHERE (
          source_candidate.content_fingerprint IN (${placeholders})
          OR target_candidate.content_fingerprint IN (${placeholders})
        )
        AND source_candidate.content_fingerprint <= ?
        AND target_candidate.content_fingerprint <= ?
        AND EXISTS (
          SELECT 1
          FROM historical_attack_knowledge_bundle_sources source_binding
          JOIN historical_attack_knowledge_source_occurrences occurrence
            ON occurrence.candidate_id = source_binding.candidate_id
           AND occurrence.source_hash = source_binding.source_hash
          WHERE source_binding.bundle_id = bundle.id
            AND occurrence.migration_id = ?
        )
      ORDER BY source_candidate.content_fingerprint, edge.edge_type,
        target_candidate.content_fingerprint, bundle.semantic_fingerprint
      LIMIT 50001
    `).all(
      ...selectedFingerprints,
      ...selectedFingerprints,
      lastFingerprint,
      lastFingerprint,
      migrationId,
    ) as Array<{
      readonly bundle_id: string;
      readonly semantic_fingerprint: string;
      readonly sanitized_bundle_json: string;
      readonly last_observed_at: string;
      readonly edge_key: string;
      readonly edge_type: typeof preview.review.edges[number]["edgeType"];
      readonly source_fingerprint: string;
      readonly target_fingerprint: string;
    }>;
    const legacyEdgeGroups = new Map<string, {
      sourceFingerprint: string;
      edgeType: typeof preview.review.edges[number]["edgeType"];
      targetFingerprint: string;
      bundleFingerprints: Set<string>;
      bundleObservations: Map<string, string>;
    }>();
    for (const row of legacyEdgeRows) {
      expect(sha256(row.sanitized_bundle_json)).toBe(row.semantic_fingerprint);
      expect(row.bundle_id).toBe(`akb_${row.semantic_fingerprint}`);
      const key = `${row.source_fingerprint}\0${row.edge_type}\0${row.target_fingerprint}`;
      const group = legacyEdgeGroups.get(key) ?? {
        sourceFingerprint: row.source_fingerprint,
        edgeType: row.edge_type,
        targetFingerprint: row.target_fingerprint,
        bundleFingerprints: new Set<string>(),
        bundleObservations: new Map<string, string>(),
      };
      group.bundleFingerprints.add(row.semantic_fingerprint);
      const prior = group.bundleObservations.get(row.semantic_fingerprint);
      if (!prior || prior < row.last_observed_at) {
        group.bundleObservations.set(row.semantic_fingerprint, row.last_observed_at);
      }
      legacyEdgeGroups.set(key, group);
    }
    const legacyEdges = [...legacyEdgeGroups.values()].map((edge) => ({
      sourceFingerprint: edge.sourceFingerprint,
      edgeType: edge.edgeType,
      targetFingerprint: edge.targetFingerprint,
      sourceBundleFingerprints: [...edge.bundleFingerprints].sort(),
      sourceBundleObservations: [...edge.bundleObservations.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([fingerprint, observedAt]) => ({ fingerprint, observedAt })),
    }));
    expect(canonicalJson(legacyEdges)).toBe(canonicalJson(preview.review.edges));
    const legacyReview = {
      ...preview.review,
      candidates: legacyCandidates,
      edges: legacyEdges,
    };
    expect(canonicalJson(legacyReview)).toBe(canonicalJson(preview.review));
    expect(sha256(canonicalJson(legacyReview))).toBe(preview.previewHash);
  });

  test("keeps migration-wide source scans bounded independently of page candidates", () => {
    const { database, migrationId } = fixture([
      "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
      "Encoded path normalization and directory traversal were observed together.",
      "The bounded procedure failed with an execution timeout.",
      "Restart the disposable service and require a health check before retrying.",
    ].join("\n"), {
      duplicateRelativePaths: [
        "ops/recovery/attack.md",
        "research/replay/attack.md",
        "web/root_push/attack.md",
      ],
    });
    const statements: string[] = [];
    const traced = new Proxy(database, {
      get(target, property) {
        if (property === "prepare") {
          return (sql: string) => {
            statements.push(sql);
            return target.prepare(sql);
          };
        }
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as SqliteDatabase;
    const service = new HistoricalAttackKnowledgeConfirmationService(traced, () => new Date(NOW));
    const preview = service.preview(request(migrationId));
    expect(preview.candidateCount).toBeGreaterThan(3);
    const previewMigrationScans = statements.filter((sql) => (
      sql.includes("historical_attack_knowledge_source_occurrences")
    ));
    expect(previewMigrationScans.length).toBeLessThanOrEqual(4);
    expect(statements.filter((sql) => sql.trimStart().startsWith("SELECT")).length)
      .toBeLessThanOrEqual(8);
    expect(statements.filter((sql) => (
      sql.includes("SELECT DISTINCT bundle_candidate.content_fingerprint")
      && sql.includes("evidence_candidate.promoted_evidence_id")
    ))).toHaveLength(1);
    expect(statements.filter((sql) => (
      sql.includes("COUNT(DISTINCT edge.bundle_id")
      && sql.includes("selected_fingerprints(value)")
    ))).toHaveLength(1);
    expect(statements.some((sql) => (
      sql.includes("WHERE bundle_candidate.content_fingerprint = ?")
    ))).toBe(false);

    statements.length = 0;
    const reconciliation = service.reconcile(migrationId);
    expect(reconciliation.totalMigrationCandidateCount).toBe(preview.candidateCount);
    const reconciliationMigrationScans = statements.filter((sql) => (
      sql.includes("historical_attack_knowledge_source_occurrences")
    ));
    expect(reconciliationMigrationScans.length).toBeLessThanOrEqual(4);
    expect(statements.filter((sql) => sql.trimStart().startsWith("SELECT")).length)
      .toBeLessThanOrEqual(8);
  });

  test("reuses an exact private legacy mission/run/artifact projection without inventing a custody edge", () => {
    const content = evidenceLinkedScript();
    const { database, migrationId } = fixture(content, {
      kind: "script",
      relativePath: "scripts/health-check.sh",
    });
    ensureLegacyEngagementSchema(database);
    const source = database.prepare(`
      SELECT source_path, source_identity, source_sha256
      FROM legacy_migration_sources WHERE migration_id = ?
    `).get(migrationId) as {
      readonly source_path: string;
      readonly source_identity: string;
      readonly source_sha256: string;
    };
    const missionId = "mission-existing-private-source";
    const runId = "run-existing-private-source";
    const artifactId = "artifact-existing-private-source";
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, status, authorization_status,
        engagement_id, scope_json, success_criteria_json, retention_policy_json,
        memory_policy_json, created_by, created_at, updated_at, control_plane
      ) VALUES (?, 'Private imported collection', 'Preserve private source custody.',
        'guided', 'archived', 'unverified', 'private-engagement', '{}', '[]',
        '{}', '{}', 'import:legacy-engagement', ?, ?, 'legacy')
    `).run(missionId, NOW, NOW);
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, progress, budget_json,
        budget_usage_json, created_at, updated_at, control_plane
      ) VALUES (?, ?, 'guided', 'completed', 1, '{}', '{}', ?, ?, 'legacy')
    `).run(runId, missionId, NOW, NOW);
    database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, media_type, sensitivity, metadata_json,
        created_at
      ) VALUES (?, ?, ?, 'guided', 'legacy_script', 'legacy-private-source://existing',
        ?, ?, 'text/x-shellscript', 'restricted', ?, ?)
    `).run(
      artifactId,
      missionId,
      runId,
      sha256(content),
      Buffer.byteLength(content),
      JSON.stringify({ relativePath: "scripts/health-check.sh" }),
      NOW,
    );
    database.prepare(`
      INSERT INTO legacy_engagement_manifests (
        id, engagement_key, root_identity, source_path, engagement_name,
        manifest_hash, mission_id, run_id, latest_migration_id, status,
        created_at, updated_at
      ) VALUES ('legacy-manifest-existing-source', ?, 'existing-root', ?,
        'Private imported collection', ?, ?, ?, ?, 'reconciled', ?, ?)
    `).run(
      source.source_identity,
      source.source_path,
      source.source_sha256,
      missionId,
      runId,
      migrationId,
      NOW,
      NOW,
    );

    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    const preview = service.preview(request(migrationId));
    const script = preview.review.candidates.find(({ nodeType }) => nodeType === "script_artifact")!;
    expect(script.typedRelationshipCount).toBeGreaterThan(0);
    service.execute({
      ...request(migrationId),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    const node = database.prepare(
      "SELECT proposed_node_id FROM memory_candidates WHERE id = ?",
    ).get(script.candidateId) as { readonly proposed_node_id: string };
    expect(database.prepare(`
      SELECT binding.binding_method, binding.mission_id,
        binding.run_id, binding.artifact_id
      FROM historical_private_source_bindings binding
      JOIN memory_sources source ON source.id = binding.memory_source_id
      WHERE source.node_id = ?
    `).get(node.proposed_node_id)).toEqual({
      binding_method: "existing_legacy_projection",
      mission_id: missionId,
      run_id: runId,
      artifact_id: artifactId,
    });
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM historical_private_source_collections",
    ).get()).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_edges
      WHERE source_node_id = ? OR target_node_id = ?
    `).get(node.proposed_node_id, node.proposed_node_id)).toEqual({
      count: script.typedRelationshipCount,
    });
  });

  test("uses the immutable configured-root-relative locator for a verified generic file root", () => {
    const { database, migrationId } = fixture(
      evidenceLinkedScript(),
      { kind: "script", relativePath: "health-check.sh" },
    );
    const inputs = prepareCustodyInputs(database, migrationId);
    const locator = "provider-history/sessions/health-check.sh";
    convertFixtureSourceToVerifiedFileRoot(database, migrationId, locator);

    const results = new HistoricalPrivateSourceCustodyProjectionService(
      database,
      { clock: () => new Date(NOW) },
    ).bindBatch(inputs);

    expect(results.length).toBeGreaterThan(0);
    expect(new Set(results.map(({ sourceLocator }) => sourceLocator))).toEqual(new Set([locator]));
    expect(database.prepare(`
      SELECT DISTINCT json_extract(metadata_json, '$.sourceLocator') AS source_locator
      FROM artifacts WHERE artifact_type = 'legacy_private_source_custody'
    `).all()).toEqual([{ source_locator: locator }]);
  });

  test("rejects unsafe immutable locators for a generic file root without partial custody writes", () => {
    const { database, migrationId } = fixture(
      evidenceLinkedScript(),
      { kind: "script", relativePath: "health-check.sh" },
    );
    const inputs = prepareCustodyInputs(database, migrationId);
    const { sourceId } = convertFixtureSourceToVerifiedFileRoot(database, migrationId);
    const service = new HistoricalPrivateSourceCustodyProjectionService(database);
    for (const unsafe of [
      "",
      ".",
      "../health-check.sh",
      "/private/health-check.sh",
      "provider-history/../health-check.sh",
      "provider-history//health-check.sh",
      "C:\\private\\health-check.sh",
      "provider-history/health\0-check.sh",
    ]) {
      database.prepare(
        "UPDATE legacy_migration_sources SET relative_path = ? WHERE id = ?",
      ).run(unsafe, sourceId);
      expect(() => service.bindBatch(inputs)).toThrow(
        "Historical private source does not resolve inside its registered collection",
      );
      expect(database.prepare(
        "SELECT COUNT(*) AS count FROM historical_private_source_bindings",
      ).get()).toEqual({ count: 0 });
      expect(database.prepare(
        "SELECT COUNT(*) AS count FROM historical_private_source_collections",
      ).get()).toEqual({ count: 0 });
    }
  });

  test("rejects a generic file-root locator that does not preserve the source filename", () => {
    const { database, migrationId } = fixture(
      evidenceLinkedScript(),
      { kind: "script", relativePath: "health-check.sh" },
    );
    const inputs = prepareCustodyInputs(database, migrationId);
    convertFixtureSourceToVerifiedFileRoot(
      database,
      migrationId,
      "provider-history/sessions/different-file.sh",
    );
    expect(() => new HistoricalPrivateSourceCustodyProjectionService(database).bindBatch(inputs))
      .toThrow("Historical private source locator conflicts with its registered file identity");
  });

  test("rejects directory containment escapes and symlink inventory objects", () => {
    for (const mutation of ["escape", "symlink"] as const) {
      const { directory, database, migrationId } = fixture([
        "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
        "Encoded path normalization and directory traversal were observed together.",
      ].join("\n"));
      const inputs = prepareCustodyInputs(database, migrationId);
      if (mutation === "escape") {
        mutateFixtureSourceObject(database, migrationId, `
          UPDATE legacy_migration_source_objects SET source_path = ?
          WHERE migration_id = ?
        `, join(directory, "outside-collection.md"), migrationId);
      } else {
        mutateFixtureSourceObject(database, migrationId, `
          UPDATE legacy_migration_source_objects SET object_kind = 'symlink'
          WHERE migration_id = ?
        `, migrationId);
      }
      expect(() => new HistoricalPrivateSourceCustodyProjectionService(database).bindBatch(inputs))
        .toThrow("Historical private source");
      expect(database.prepare(
        "SELECT COUNT(*) AS count FROM historical_private_source_bindings",
      ).get()).toEqual({ count: 0 });
    }
  });

  test("rejects a file-root source whose stable identity receipt was altered", () => {
    const { database, migrationId } = fixture(
      evidenceLinkedScript(),
      { kind: "script", relativePath: "health-check.sh" },
    );
    const inputs = prepareCustodyInputs(database, migrationId);
    const { sourceId } = convertFixtureSourceToVerifiedFileRoot(database, migrationId);
    database.prepare(
      "UPDATE legacy_migration_sources SET source_identity = ? WHERE id = ?",
    ).run(sha256("altered-source-identity"), sourceId);
    expect(() => new HistoricalPrivateSourceCustodyProjectionService(database).bindBatch(inputs))
      .toThrow("Historical private source conflicts with its registered source identity");
  });

  test("confirms a source-reported failed outcome but leaves canonical outcome tags unclassified", () => {
    const { database, migrationId } = fixture([
      "V8 JavaScript engine 12.2.281.1 Harmony Set type confusion produced arbitrary read and arbitrary write before a WASM foothold.",
      "The bounded procedure failed and the process crashed. Restart the service and require a health check before retrying.",
    ].join("\n"));
    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    const preview = service.preview(request(migrationId));
    expect(preview.review.candidates.some(({ nodeType }) => nodeType === "outcome")).toBe(true);
    service.execute({
      ...request(migrationId),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    expect(database.prepare(`
      SELECT lifecycle_status, confirmation_state FROM memory_nodes
      WHERE node_type = 'outcome'
    `).all()).toEqual(expect.arrayContaining([
      { lifecycle_status: "confirmed", confirmation_state: "confirmed" },
    ]));
    expect(database.prepare(
      "SELECT COUNT(*) AS count FROM reusable_knowledge_outcome_links",
    ).get()).toEqual({ count: 0 });
  });

  test("suppresses a candidate whose content no longer matches the reviewed reusable boundary", () => {
    const { database, migrationId } = fixture([
      "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
      "Encoded path normalization and directory traversal were observed together.",
    ].join("\n"));
    const candidate = database.prepare(`
      SELECT candidate.id FROM memory_candidates candidate
      JOIN attack_knowledge_candidate_registry registry ON registry.candidate_id = candidate.id
      ORDER BY registry.content_fingerprint LIMIT 1
    `).get() as { readonly id: string };
    database.prepare("UPDATE memory_candidates SET title = 'Target address 10.1.2.3' WHERE id = ?")
      .run(candidate.id);
    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    const preview = service.preview(request(migrationId));
    const unsafe = preview.review.candidates.find(({ candidateId }) => candidateId === candidate.id)!;
    expect(unsafe).toMatchObject({ decision: "suppress" });
    expect(unsafe.reasonCategories).toEqual(expect.arrayContaining([
      "candidate_fingerprint_mismatch",
      "operational_locator_content",
    ]));
    const result = service.execute({
      ...request(migrationId),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    expect(result.suppressedCount).toBe(1);
    expect(database.prepare(
      "SELECT status, title FROM memory_candidates WHERE id = ?",
    ).get(candidate.id)).toEqual({ status: "suppressed", title: "[Suppressed candidate]" });
  });

  test("keeps credential-bearing historical content suppressed and erases its plaintext", () => {
    const { database, migrationId } = fixture([
      "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
      "Encoded path normalization and directory traversal were observed together.",
    ].join("\n"));
    const candidate = database.prepare(`
      SELECT candidate.id FROM memory_candidates candidate
      JOIN attack_knowledge_candidate_registry registry ON registry.candidate_id = candidate.id
      ORDER BY registry.content_fingerprint LIMIT 1
    `).get() as { readonly id: string };
    const unsafeValue = `credential ${["pass", "word"].join("")}=ExampleHistoricalSecretValue42`;
    database.prepare("UPDATE memory_candidates SET body = ? WHERE id = ?")
      .run(unsafeValue, candidate.id);
    rekeyCandidateAfterTestMutation(database, candidate.id);

    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    const preview = service.preview(request(migrationId));
    const unsafe = preview.review.candidates.find(({ candidateId }) => candidateId === candidate.id)!;
    expect(unsafe).toMatchObject({ decision: "suppress" });
    expect(unsafe.reasonCategories).toEqual(expect.arrayContaining([
      "credential_assignment",
      "secret_bearing_content",
      "reusable_retention_boundary_failed",
    ]));
    const result = service.execute({
      ...request(migrationId),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    expect(result.suppressedCount).toBe(1);
    const stored = database.prepare(`
      SELECT title, summary, body, source_json FROM memory_candidates WHERE id = ?
    `).get(candidate.id) as Record<string, string>;
    expect(stored).toEqual({
      title: "[Suppressed candidate]",
      summary: "",
      body: "",
      source_json: canonicalJson({ method: "suppressed", explanation: "Content removed", sources: [] }),
    });
    expect(canonicalJson(stored)).not.toContain("ExampleHistoricalSecretValue42");
  });

  test("keeps repeated relationship origins normalized instead of overflowing one graph edge", () => {
    const { database, migrationId } = fixture([
      "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
      "Encoded path normalization and directory traversal were observed together.",
    ].join("\n"));
    addRepeatedRelationshipOrigins(database, migrationId, 320);
    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    const preview = service.preview(request(migrationId));
    const repeated = preview.review.edges.find(
      ({ sourceBundleObservations }) => sourceBundleObservations.length > 300,
    );
    expect(repeated).toBeDefined();
    const stablePreviewHash = service.preview(request(migrationId)).previewHash;
    expect(stablePreviewHash).toBe(preview.previewHash);

    const result = service.execute({
      ...request(migrationId),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    expect(result.edgesCreated).toBeGreaterThan(0);
    const edge = database.prepare(`
      SELECT edge.provenance_json
      FROM memory_edges edge
      JOIN attack_knowledge_candidate_registry source_registry
        ON source_registry.content_fingerprint = ?
      JOIN memory_candidates source_candidate
        ON source_candidate.id = source_registry.candidate_id
       AND source_candidate.proposed_node_id = edge.source_node_id
      JOIN attack_knowledge_candidate_registry target_registry
        ON target_registry.content_fingerprint = ?
      JOIN memory_candidates target_candidate
        ON target_candidate.id = target_registry.candidate_id
       AND target_candidate.proposed_node_id = edge.target_node_id
      WHERE edge.edge_type = ?
    `).get(
      repeated!.sourceFingerprint,
      repeated!.targetFingerprint,
      repeated!.edgeType,
    ) as { readonly provenance_json: string };
    const provenance = JSON.parse(edge.provenance_json) as {
      readonly sources: ReadonlyArray<{ readonly sourceType: string }>;
    };
    expect(provenance.sources.length).toBeLessThanOrEqual(9);
    expect(provenance.sources.some(({ sourceType }) => (
      sourceType === "attack_knowledge_bundle_set"
    ))).toBe(true);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE edge_type = ?
    `).get(repeated!.edgeType)).toEqual({ count: expect.any(Number) });
    const exactOriginCount = database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE edge_type = ?
    `).get(repeated!.edgeType) as { readonly count: number };
    expect(exactOriginCount.count).toBeGreaterThan(300);
    const audit = database.prepare(`
      SELECT details_json FROM audit_records
      WHERE action = 'historical_attack_knowledge.confirmed'
      ORDER BY rowid DESC LIMIT 1
    `).get() as { readonly details_json: string };
    expect(JSON.parse(audit.details_json)).toMatchObject({
      previewHash: preview.previewHash,
      selectedCount: preview.candidateCount,
      edgesCreated: result.edgesCreated,
    });
  });

  test("CLI keeps preview read-only and requires the exact execution acknowledgement", async () => {
    const { database, databasePath, migrationId } = fixture([
      "Apache HTTP Server/2.4.49 path traversal and encoded path normalization were observed together.",
    ].join("\n"));
    const before = database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get();
    let output = "";
    expect(await runHistoricalAttackConfirmationCli([
      "preview", "--db", databasePath, "--migration", migrationId,
      "--actor", "operator:historical-confirmation", "--reason", REASON,
      "--dry-run",
    ], {}, { write: (value) => { output += value; } })).toBe(0);
    expect(JSON.parse(output)).toMatchObject({ mode: "dry_run", candidateCount: expect.any(Number) });
    expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual(before);
    await expect(runHistoricalAttackConfirmationCli([
      "run", "--db", databasePath, "--migration", migrationId,
      "--actor", "operator:historical-confirmation", "--reason", REASON,
      "--expected-preview-hash", "a".repeat(64),
    ])).rejects.toThrow(/acknowledge-confirm-all-safe/iu);
  });

  test("refuses running, legacy-projection, or receiptless migrations", () => {
    const { database, migrationId } = fixture(
      "Apache HTTP Server/2.4.49 path traversal and encoded path normalization were observed together.",
    );
    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    database.prepare("UPDATE legacy_migration_runs SET status = 'running', completed_at = NULL WHERE id = ?")
      .run(migrationId);
    expect(() => service.preview(request(migrationId))).toThrow(/completed.*receipt-backed/iu);
  });
});

describe("HistoricalAttackKnowledgeConfirmationOrchestrator", () => {
  const multiCandidateContent = [
    "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
    "Encoded path normalization and directory traversal were observed together.",
    "The bounded procedure failed with an execution timeout.",
    "Restart the disposable service and require a health check before retrying.",
  ].join("\n");

  test("processes a bounded page set, persists a cursor, resumes, and replays terminal state", () => {
    const { database, migrationId } = fixture(multiCandidateContent);
    const first = new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => new Date(NOW),
      () => "hakc_inv_test_first",
    ).run({
      ...request(migrationId, 1),
      pageSize: 1,
      maxPages: 1,
    });
    expect(first).toMatchObject({
      outcome: "bounded",
      pagesProcessedThisInvocation: 1,
      receipt: {
        status: "in_progress",
        pagesCompleted: 1,
        lease: null,
        nextSelectionCursor: expect.stringMatching(/^[a-f0-9]{64}$/u),
      },
    });
    expect(first.receipt.reconciliation.pendingEligibleCount).toBeGreaterThan(0);
    expect(database.prepare(
      "SELECT sensitivity FROM settings WHERE key = ?",
    ).get(historicalConfirmationAllPagesStateKey(migrationId))).toEqual({ sensitivity: "private" });

    const resumed = new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => new Date(NOW),
      () => "hakc_inv_test_resume",
    ).run({
      ...request(migrationId, 1),
      pageSize: 1,
      maxPages: 100,
    });
    expect(resumed.outcome).toBe("completed");
    expect(resumed.receipt).toMatchObject({
      status: "completed",
      lease: null,
      reconciliation: {
        pendingEligibleCount: 0,
        incompatibleEligibleCount: 0,
        provenanceBindingMissingCount: 0,
      },
    });
    expect(resumed.receipt.reconciliation.confirmedEligibleCount)
      .toBe(resumed.receipt.reconciliation.eligibleCandidateCount);
    expect(resumed.receipt.reconciliation.provenanceBindingPresentCount)
      .toBe(resumed.receipt.reconciliation.provenanceBindingExpectedCount);
    expect(resumed.receipt.totals.selectedCount)
      .toBe(resumed.receipt.reconciliation.totalMigrationCandidateCount);

    const auditsBefore = database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.confirmed'
    `).get();
    const replayed = new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => new Date(NOW),
      () => "hakc_inv_test_replay",
    ).run({
      ...request(migrationId, 1),
      pageSize: 1,
      maxPages: 100,
    });
    expect(replayed).toMatchObject({ outcome: "replayed", pagesProcessedThisInvocation: 0 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.confirmed'
    `).get()).toEqual(auditsBefore);
  });

  test("renews the canonical writer fence across a synchronous all-page run longer than its TTL", async () => {
    const { database, migrationId } = fixture(multiCandidateContent);
    let now = new Date(NOW);
    let heartbeatCount = 0;
    const result = await withCanonicalWriterLease(database, {
      ownerId: "operator:long-confirmation",
      operation: `historical-attack-confirmation-all:${migrationId}`,
      ttlMs: 1_000,
    }, (_handle, _leases, heartbeat) => new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => now,
      () => "hakc_inv_test_long_writer",
      () => {
        now = new Date(now.getTime() + 450);
        heartbeat.renew();
        heartbeatCount += 1;
      },
    ).run({
      ...request(migrationId, 1),
      pageSize: 1,
      maxPages: 100,
    }), {
      clock: () => now,
      createId: () => "canonical_lease_long_confirmation",
      maintenanceMarkerPath: null,
    });
    expect(result.outcome).toBe("completed");
    expect(heartbeatCount).toBeGreaterThan(3);
    const lease = database.prepare(`
      SELECT acquired_at, heartbeat_at, expires_at, released_at, release_reason
      FROM canonical_database_leases WHERE id = 'canonical_lease_long_confirmation'
    `).get() as Record<string, string>;
    expect(Date.parse(lease.released_at) - Date.parse(lease.acquired_at)).toBeGreaterThan(1_000);
    expect(Date.parse(lease.heartbeat_at)).toBeGreaterThan(Date.parse(lease.acquired_at));
    expect(lease.release_reason).toBe("completed");
  });

  test("an expired and superseded writer is fenced before it can start another confirmation page", async () => {
    const { database, migrationId } = fixture(multiCandidateContent);
    let now = new Date(NOW);
    let heartbeatCount = 0;
    let maintenance: ReturnType<CanonicalDatabaseLeaseService["acquireMaintenance"]> | undefined;
    let replacementLeases: CanonicalDatabaseLeaseService | undefined;
    await expect(withCanonicalWriterLease(database, {
      ownerId: "operator:stale-confirmation",
      operation: `historical-attack-confirmation-all:${migrationId}`,
      ttlMs: 1_000,
    }, (_handle, _leases, heartbeat) => new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => now,
      () => "hakc_inv_test_stale_writer",
      () => {
        heartbeatCount += 1;
        if (heartbeatCount === 4) {
          now = new Date(now.getTime() + 1_001);
          replacementLeases = new CanonicalDatabaseLeaseService(database, {
            clock: () => now,
            createId: () => "canonical_lease_replacement_maintenance",
            maintenanceMarkerPath: null,
          });
          maintenance = replacementLeases.acquireMaintenance({
            ownerId: "release:replacement",
            operation: "test-stale-writer-fence",
            ttlMs: 1_000,
          });
        } else {
          now = new Date(now.getTime() + 300);
        }
        heartbeat.renew();
      },
    ).run({
      ...request(migrationId, 1),
      pageSize: 1,
      maxPages: 100,
    }), {
      clock: () => now,
      createId: () => "canonical_lease_stale_confirmation",
      maintenanceMarkerPath: null,
    })).rejects.toBeInstanceOf(CanonicalDatabaseLeaseLostError);
    expect(heartbeatCount).toBe(4);
    const checkpoint = new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => now,
    ).getReceipt(migrationId)!;
    expect(checkpoint.pagesCompleted).toBe(1);
    expect(checkpoint.status).toBe("in_progress");
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.confirmed'
    `).get()).toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT release_reason FROM canonical_database_leases
      WHERE id = 'canonical_lease_stale_confirmation'
    `).get()).toEqual({ release_reason: "expired" });
    if (!replacementLeases || !maintenance) throw new Error("Replacement maintenance fixture was not acquired");
    replacementLeases.release(maintenance, "test-completed");
  });

  test("suppresses an oversized historical candidate and continues every remaining page", () => {
    const { database, migrationId } = fixture(multiCandidateContent);
    const candidate = database.prepare(`
      SELECT candidate.id FROM memory_candidates candidate
      JOIN attack_knowledge_candidate_registry registry
        ON registry.candidate_id = candidate.id
      ORDER BY registry.content_fingerprint LIMIT 1
    `).get() as { readonly id: string };
    database.prepare("UPDATE memory_candidates SET body = ? WHERE id = ?")
      .run("x".repeat(64 * 1024 + 1), candidate.id);
    const fingerprint = rekeyCandidateAfterTestMutation(database, candidate.id);

    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    let cursor: string | undefined;
    let reviewed: ReturnType<typeof service.preview>["review"]["candidates"][number] | undefined;
    for (let page = 0; page < 100; page += 1) {
      const preview = service.preview(request(migrationId, 1, cursor));
      reviewed = preview.review.candidates.find(({ candidateId }) => candidateId === candidate.id);
      if (reviewed || !preview.hasMore) break;
      cursor = preview.nextSelectionCursor ?? undefined;
    }
    expect(reviewed).toMatchObject({
      contentFingerprint: fingerprint,
      decision: "suppress",
      reasonCategories: expect.arrayContaining([
        "size_limit",
        "reusable_retention_boundary_failed",
      ]),
    });

    const result = new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => new Date(NOW),
      () => "hakc_inv_test_oversized",
    ).run({
      ...request(migrationId, 1),
      pageSize: 1,
      maxPages: 100,
    });
    expect(result).toMatchObject({
      outcome: "completed",
      receipt: {
        status: "completed",
        totals: { suppressedCount: 1 },
        reconciliation: {
          pendingEligibleCount: 0,
          provenanceBindingMissingCount: 0,
        },
      },
    });
    expect(database.prepare(`
      SELECT status, title, summary, body, source_json
      FROM memory_candidates WHERE id = ?
    `).get(candidate.id)).toEqual({
      status: "suppressed",
      title: "[Suppressed candidate]",
      summary: "",
      body: "",
      source_json: canonicalJson({ method: "suppressed", explanation: "Content removed", sources: [] }),
    });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_suppressions
    `).get()).toEqual({ count: 1 });
    const suppressionAudit = database.prepare(`
      SELECT details_json FROM audit_records
      WHERE action = 'memory_candidate.suppressed' AND resource_id = ?
    `).get(candidate.id) as { readonly details_json: string };
    expect(suppressionAudit.details_json).not.toContain("xxxx");
    expect(JSON.parse(suppressionAudit.details_json)).toMatchObject({
      doNotRelearn: true,
    });
  });

  test("replays a page executed before its aggregate checkpoint was published", () => {
    const { database, migrationId } = fixture(multiCandidateContent);
    const service = new HistoricalAttackKnowledgeConfirmationService(database, () => new Date(NOW));
    const preview = service.preview(request(migrationId, 1));
    const executed = service.execute({
      ...request(migrationId, 1),
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    expect(executed.status).toBe("completed");

    const result = new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => new Date(NOW),
      () => "hakc_inv_test_crash_gap",
    ).run({
      ...request(migrationId, 1),
      pageSize: 1,
      maxPages: 1,
    });
    expect(result.receipt.lastPage).toMatchObject({
      previewHash: preview.previewHash,
      executionStatus: "replayed",
    });
    expect(result.receipt.totals.confirmedCount).toBe(executed.confirmedCount);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.confirmed'
        AND resource_id = ?
    `).get(`hakconfirm_${preview.previewHash}`)).toEqual({ count: 1 });
  });

  test("fails closed on changed bindings and a tampered durable receipt", () => {
    const { database, migrationId } = fixture(multiCandidateContent);
    new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => new Date(NOW),
      () => "hakc_inv_test_binding",
    ).run({
      ...request(migrationId, 1),
      pageSize: 1,
      maxPages: 1,
    });
    expect(() => new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => new Date(NOW),
      () => "hakc_inv_test_binding_changed",
    ).run({
      ...request(migrationId, 2),
      pageSize: 2,
      maxPages: 1,
    })).toThrow(/different actor, reason, page size, or inventory receipt/iu);

    const key = historicalConfirmationAllPagesStateKey(migrationId);
    const row = database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(key) as { readonly value_json: string };
    const tampered = JSON.parse(row.value_json) as Record<string, unknown>;
    tampered.nextSelectionCursor = "f".repeat(64);
    database.prepare("UPDATE settings SET value_json = ? WHERE key = ?")
      .run(JSON.stringify(tampered), key);
    expect(() => new HistoricalAttackKnowledgeConfirmationOrchestrator(
      database,
      () => new Date(NOW),
      () => "hakc_inv_test_tamper",
    ).run({
      ...request(migrationId, 1),
      pageSize: 1,
      maxPages: 1,
    })).toThrow(/receipt hash does not match/iu);
  });

  test("CLI writes only a compact mode-0600 aggregate receipt", async () => {
    const { directory, databasePath, migrationId } = fixture(multiCandidateContent);
    const receiptPath = join(directory, "confirmation-all-pages.json");
    let output = "";
    expect(await runHistoricalAttackConfirmationAllCli([
      "run", "--db", databasePath, "--migration", migrationId,
      "--actor", "operator:historical-confirmation", "--reason", REASON,
      "--page-size", "1000", "--max-pages", "100",
      "--receipt", receiptPath, "--acknowledge-confirm-all-safe",
    ], {}, { cwd: directory, write: (value) => { output += value; } })).toBe(0);
    const printed = JSON.parse(output) as Record<string, unknown>;
    const persisted = JSON.parse(readFileSync(receiptPath, "utf8")) as Record<string, unknown>;
    expect(printed).toEqual(persisted);
    expect(printed).toMatchObject({
      mode: "execute",
      outcome: "completed",
      receipt: {
        status: "completed",
        reconciliation: {
          pendingEligibleCount: 0,
          provenanceBindingMissingCount: 0,
          unlinkedEligibleCount: expect.any(Number),
          unlinkedConfirmedCount: expect.any(Number),
        },
      },
    });
    expect(readFileSync(receiptPath, "utf8"))
      .not.toMatch(/"(?:sourceBindings|review|candidates)"\s*:/u);
    expect(statSync(receiptPath).mode & 0o777).toBe(0o600);

    // The durable database receipt is authoritative. If the process completed
    // its final page but died before writing the compact file, the exact same
    // command reconstructs that file without repeating any mutation.
    rmSync(receiptPath);
    output = "";
    expect(await runHistoricalAttackConfirmationAllCli([
      "run", "--db", databasePath, "--migration", migrationId,
      "--actor", "operator:historical-confirmation", "--reason", REASON,
      "--page-size", "1000", "--max-pages", "100",
      "--receipt", receiptPath, "--acknowledge-confirm-all-safe",
    ], {}, { cwd: directory, write: (value) => { output += value; } })).toBe(0);
    const recovered = JSON.parse(output) as Record<string, unknown>;
    expect(recovered).toMatchObject({
      outcome: "replayed",
      pagesProcessedThisInvocation: 0,
      receipt: { status: "completed" },
    });
    expect(JSON.parse(readFileSync(receiptPath, "utf8"))).toEqual(recovered);
    expect(statSync(receiptPath).mode & 0o777).toBe(0o600);
  });
});

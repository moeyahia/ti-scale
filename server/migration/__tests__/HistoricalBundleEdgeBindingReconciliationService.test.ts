import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDatabaseConnection,
  inImmediateTransaction,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  CanonicalDatabaseLeaseService,
  withCanonicalWriterLease,
} from "../../maintenance";
import { canonicalJson } from "../../orchestration/serialization";
import { HistoricalAttackKnowledgeConfirmationService } from "../HistoricalAttackKnowledgeConfirmationService";
import { HistoricalAttackKnowledgeExtractionService } from "../HistoricalAttackKnowledgeExtractionService";
import { HistoricalBundleEdgeBindingReconciliationService } from "../HistoricalBundleEdgeBindingReconciliationService";
import { runHistoricalAttackPromotionCli } from "../historical-attack-promotion-cli";
import { runHistoricalBundleEdgeBindingCli } from "../historical-bundle-edge-binding-cli";
import type { LegacyEngagementFile, LegacyEngagementManifest } from "../LegacyEngagementDiscovery";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";

const NOW = "2026-07-22T09:00:00.000Z";
const HMAC_KEY = "historical-binding-reconciliation-test-key-more-than-32-bytes";
const ACTOR = "operator:bundle-edge-reconciliation";
const REASON = "Reconcile reviewed historical bundle provenance with existing canonical graph edges";
const PRIVATE_ENGAGEMENT = "private-binding-fixture";
const PRIVATE_TARGET = "10.129.39.191";
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
  readonly directory: string;
  readonly databasePath: string;
  readonly database: SqliteDatabase;
  readonly migrationId: string;
  readonly manifest: LegacyEngagementManifest;
  readonly service: HistoricalBundleEdgeBindingReconciliationService;
}

function createFixture(): Fixture {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-bundle-edge-binding-"));
  directories.push(directory);
  const databasePath = join(directory, "test.sqlite");
  const database = createDatabaseConnection({ filename: databasePath });
  databases.push(database);
  migrateDatabase(database);

  const engagementDirectory = join(directory, PRIVATE_ENGAGEMENT);
  const absolutePath = join(engagementDirectory, "notes", "attack.md");
  const content = [
    `Private target ${PRIVATE_TARGET} is deliberately outside reusable memory.`,
    "Apache HTTP Server/2.4.49 path traversal was identified by an active service scan.",
    "Encoded path normalization and directory traversal were observed together in the same bounded technical record.",
    "The attempt failed with an execution timeout, and a disposable service reset was required before retry.",
  ].join("\n");
  mkdirSync(join(engagementDirectory, "notes"), { recursive: true });
  writeFileSync(absolutePath, content);
  const sourceState = statSync(absolutePath);
  const file: LegacyEngagementFile = {
    absolutePath,
    relativePath: "notes/attack.md",
    kind: "note",
    contentClass: "text",
    mediaType: "text/markdown",
    sha256: sha256(content),
    byteSize: Buffer.byteLength(content),
    modifiedAt: sourceState.mtime.toISOString(),
  };
  const engagementKey = sha256(`engagement\0${PRIVATE_ENGAGEMENT}`);
  const manifest: LegacyEngagementManifest = {
    id: `legacy_engagement_${engagementKey.slice(0, 40)}`,
    root: directory,
    rootIdentity: "binding-test-root",
    engagementDirectory,
    engagementName: PRIVATE_ENGAGEMENT,
    engagementKey,
    sha256: sha256(canonicalJson([{
      relativePath: file.relativePath,
      sha256: file.sha256,
      byteSize: file.byteSize,
      modifiedAt: file.modifiedAt,
    }])),
    byteSize: file.byteSize,
    modifiedAt: file.modifiedAt,
    files: [file],
    quarantined: [],
  };
  const metadata = new MigrationMetadataRepository(database, () => new Date(NOW));
  const migration = metadata.createRun({
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
  const sourceId = metadata.registerSource(migration.id, {
    absolutePath: engagementDirectory,
    relativePath: PRIVATE_ENGAGEMENT,
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
  metadata.registerSourceObject({
    migrationId: migration.id,
    sourceId,
    objectKey: `accepted:${file.relativePath}`,
    sourcePath: file.absolutePath,
    objectKind: "accepted",
    classification: file.kind,
    sourceSha256: file.sha256,
    byteSize: file.byteSize,
    modifiedAt: file.modifiedAt,
    sourceDevice: sourceState.dev,
    sourceInode: sourceState.ino,
  });
  database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, 1, ?, ?)
  `).run(migration.id, manifest.sha256, manifest.byteSize, NOW);
  const extracted = new HistoricalAttackKnowledgeExtractionService(database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => new Date(NOW),
  }).extract(manifest);
  expect(extracted.compilerBundlesStaged).toBeGreaterThan(0);
  database.prepare(`
    UPDATE legacy_migration_runs SET status = 'completed', completed_at = ? WHERE id = ?
  `).run(NOW, migration.id);

  const confirmation = new HistoricalAttackKnowledgeConfirmationService(
    database,
    () => new Date(NOW),
  );
  let afterContentFingerprint: string | undefined;
  for (let page = 0; page < 100; page += 1) {
    const input = {
      migrationId: migration.id,
      actorId: ACTOR,
      reason: "Confirm sanitized candidates before binding their exact typed relationships",
      maxCandidates: 1_000,
      ...(afterContentFingerprint ? { afterContentFingerprint } : {}),
    } as const;
    const preview = confirmation.preview(input);
    if (preview.candidateCount === 0) break;
    confirmation.execute({
      ...input,
      expectedPreviewHash: preview.previewHash,
      acknowledgeConfirmAllSafe: true,
    });
    afterContentFingerprint = preview.nextSelectionCursor ?? undefined;
    if (!preview.hasMore) break;
  }
  expect(database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get())
    .toEqual(expect.objectContaining({ count: expect.any(Number) }));
  expect(Number((database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get() as { count: number }).count))
    .toBeGreaterThan(0);
  return {
    directory,
    databasePath,
    database,
    migrationId: migration.id,
    manifest,
    service: new HistoricalBundleEdgeBindingReconciliationService(
      database,
      () => new Date(NOW),
    ),
  };
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
      ON source_candidate.bundle_id = edge.bundle_id AND source_candidate.role = edge.source_role
    JOIN attack_knowledge_bundle_candidates target_candidate
      ON target_candidate.bundle_id = edge.bundle_id AND target_candidate.role = edge.target_role
    JOIN historical_attack_knowledge_bundle_sources source_binding
      ON source_binding.bundle_id = edge.bundle_id
    JOIN historical_attack_knowledge_source_occurrences occurrence
      ON occurrence.candidate_id = source_binding.candidate_id
     AND occurrence.source_hash = source_binding.source_hash
    WHERE occurrence.migration_id = ?
      AND EXISTS (
        SELECT 1 FROM memory_edges_safe canonical_edge
        JOIN attack_knowledge_candidate_registry source_registry
          ON source_registry.content_fingerprint = source_candidate.content_fingerprint
        JOIN memory_candidates reviewed_source ON reviewed_source.id = source_registry.candidate_id
        JOIN attack_knowledge_candidate_registry target_registry
          ON target_registry.content_fingerprint = target_candidate.content_fingerprint
        JOIN memory_candidates reviewed_target ON reviewed_target.id = target_registry.candidate_id
        WHERE canonical_edge.source_node_id = reviewed_source.proposed_node_id
          AND canonical_edge.edge_type = edge.edge_type
          AND canonical_edge.target_node_id = reviewed_target.proposed_node_id
      )
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
  inImmediateTransaction(database, () => {
    const insertBundle = database.prepare(`
      INSERT INTO attack_knowledge_bundles (
        id, semantic_fingerprint, sanitized_bundle_json, status,
        first_observed_at, last_observed_at, created_at, updated_at
      ) VALUES (?, ?, ?, 'staged', ?, ?, ?, ?)
    `);
    const insertReceipt = database.prepare(`
      INSERT INTO attack_knowledge_provenance_receipts (
        id, source_class, source_hash, evidence_count, observed_at, created_at
      ) VALUES (?, 'historical', ?, 1, ?, ?)
    `);
    const linkReceipt = database.prepare(`
      INSERT INTO attack_knowledge_bundle_receipts (bundle_id, receipt_id, linked_at)
      VALUES (?, ?, ?)
    `);
    const linkCandidate = database.prepare(`
      INSERT INTO attack_knowledge_bundle_candidates (
        bundle_id, role, content_fingerprint, required, ordinal, linked_at
      ) VALUES (?, ?, ?, 1, ?, ?)
    `);
    const insertEdge = database.prepare(`
      INSERT INTO attack_knowledge_bundle_edges (
        bundle_id, edge_key, source_role, target_role, edge_type
      ) VALUES (?, ?, ?, ?, ?)
    `);
    const linkSource = database.prepare(`
      INSERT INTO historical_attack_knowledge_bundle_sources (
        bundle_id, receipt_id, candidate_id, source_hash, binding_hash, linked_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);
    for (let index = 0; index < count; index += 1) {
      const sanitized = canonicalJson({
        schemaVersion: 1,
        relationship: "independent exact typed observation",
        ordinal: index,
      });
      const fingerprint = sha256(sanitized);
      const bundleId = `akb_${fingerprint}`;
      const receiptId = `akreceipt_binding_${sha256(`receipt-${index}`).slice(0, 40)}`;
      const edgeKey = `ake_${sha256(`edge-${index}`).slice(0, 48)}`;
      insertBundle.run(bundleId, fingerprint, sanitized, NOW, NOW, NOW, NOW);
      insertReceipt.run(receiptId, sha256(`relationship-origin-${index}`), NOW, NOW);
      linkReceipt.run(bundleId, receiptId, NOW);
      linkCandidate.run(bundleId, base.source_role, base.source_fingerprint, 0, NOW);
      linkCandidate.run(bundleId, base.target_role, base.target_fingerprint, 1, NOW);
      insertEdge.run(bundleId, edgeKey, base.source_role, base.target_role, base.edge_type);
      linkSource.run(
        bundleId,
        receiptId,
        base.candidate_id,
        base.source_hash,
        sha256(`${bundleId}\0${receiptId}\0${base.candidate_id}`),
        NOW,
      );
    }
  });
}

function addVerifiedCustodyFanout(
  database: SqliteDatabase,
  migrationId: string,
  count: number,
  offset = 0,
): string {
  const base = database.prepare(`
    SELECT source.bundle_id, source.candidate_id, source.source_hash,
      object.source_id, object.byte_size, object.modified_at,
      object.source_device, object.source_inode
    FROM historical_attack_knowledge_bundle_sources source
    JOIN historical_attack_knowledge_source_occurrences occurrence
      ON occurrence.candidate_id = source.candidate_id
     AND occurrence.source_hash = source.source_hash
     AND occurrence.migration_id = ?
    JOIN legacy_migration_source_objects object
      ON object.migration_id = occurrence.migration_id
     AND object.source_reference = occurrence.source_reference
     AND object.source_sha256 = occurrence.source_hash
    JOIN attack_knowledge_bundle_edges edge ON edge.bundle_id = source.bundle_id
    WHERE edge.materialized_edge_id IS NULL
    ORDER BY edge.bundle_id, edge.edge_key LIMIT 1
  `).get(migrationId) as {
    readonly bundle_id: string;
    readonly candidate_id: string;
    readonly source_hash: string;
    readonly source_id: string;
    readonly byte_size: number;
    readonly modified_at: string;
    readonly source_device: number;
    readonly source_inode: number;
  };
  inImmediateTransaction(database, () => {
    database.prepare(`
      WITH RECURSIVE sequence(value) AS (
        SELECT ?
        UNION ALL SELECT value + 1 FROM sequence WHERE value + 1 < ?
      )
      INSERT INTO legacy_migration_source_objects (
        id, migration_id, source_id, object_key, source_reference, source_path,
        object_kind, classification, source_sha256, byte_size, modified_at,
        source_device, source_inode, verification_status, verified_at
      ) SELECT
        'source_object_fanout_' || printf('%08d', value), ?, ?,
        'fanout:' || printf('%08d', value),
        'legacy-private-source://source_object_fanout_' || printf('%08d', value),
        '/private/fanout/' || printf('%08d', value),
        'accepted', 'note', ?, ?, ?, ?, ?, 'verified_reference', ?
      FROM sequence
    `).run(
      offset,
      offset + count,
      migrationId,
      base.source_id,
      base.source_hash,
      base.byte_size,
      base.modified_at,
      base.source_device,
      base.source_inode,
      NOW,
    );
    database.prepare(`
      WITH RECURSIVE sequence(value) AS (
        SELECT ?
        UNION ALL SELECT value + 1 FROM sequence WHERE value + 1 < ?
      )
      INSERT INTO historical_attack_knowledge_source_occurrences (
        candidate_id, migration_id, source_reference, source_hash, modified_at, observed_at
      ) SELECT ?, ?,
        'legacy-private-source://source_object_fanout_' || printf('%08d', value),
        ?, ?, ?
      FROM sequence
    `).run(
      offset,
      offset + count,
      base.candidate_id,
      migrationId,
      base.source_hash,
      base.modified_at,
      NOW,
    );
  });
  return base.bundle_id;
}

function preservationSnapshot(database: SqliteDatabase): string {
  return canonicalJson({
    bundles: database.prepare(`
      SELECT id, status, materialized_at, exact_procedure_attempt_count,
        exact_procedure_reproducibility_count, exact_procedure_evidence_count,
        exact_procedure_reset_count, operator_reported_reset_count_minimum
      FROM attack_knowledge_bundles ORDER BY id
    `).all(),
    compilerRuns: database.prepare(`
      SELECT id, status, checkpoint_ordinal, reconciliation_json, completed_at
      FROM attack_knowledge_compiler_runs ORDER BY id
    `).all(),
    nodes: database.prepare(`
      SELECT id, lifecycle_status, confirmation_state, author_type, author_id, version
      FROM memory_nodes ORDER BY id
    `).all(),
    edges: database.prepare(`
      SELECT id, lifecycle_status, author_type, author_id, version
      FROM memory_edges ORDER BY id
    `).all(),
    evidenceBindings: database.prepare(`
      SELECT * FROM attack_knowledge_bundle_evidence_bindings ORDER BY bundle_id, evidence_id
    `).all(),
    promotionReceipts: database.prepare(`
      SELECT * FROM attack_knowledge_promotion_receipts ORDER BY id
    `).all(),
    outcomeLinks: database.prepare(`
      SELECT * FROM reusable_knowledge_outcome_links ORDER BY id
    `).all(),
  });
}

async function executeReviewed(
  fixture: Fixture,
  preview: ReturnType<HistoricalBundleEdgeBindingReconciliationService["preview"]>,
) {
  return await withCanonicalWriterLease(fixture.database, {
    ownerId: ACTOR,
    operation: "historical-bundle-edge-binding-reconciliation",
  }, (handle, leases) => fixture.service.execute({
    actorId: ACTOR,
    reason: REASON,
    ...(preview.selection.afterBindingCursor
      ? { afterBindingCursor: preview.selection.afterBindingCursor }
      : {}),
    maxBindings: preview.selection.maxBindings,
    expectedPreviewHash: preview.previewHash,
    acknowledgeExistingEdgeBindingOnly: true,
  }, { handle, leases }), {
    clock: () => new Date(NOW),
    maintenanceMarkerPath: null,
  });
}

async function runCli(
  fixture: Fixture,
  argv: readonly string[],
): Promise<Record<string, unknown>> {
  let output = "";
  const code = await runHistoricalBundleEdgeBindingCli(argv, {
    TI_SCALE_DATABASE_PATH: fixture.databasePath,
  }, {
    cwd: fixture.directory,
    write: (value) => { output += value; },
  });
  expect(code).toBe(0);
  return JSON.parse(output) as Record<string, unknown>;
}

describe("HistoricalBundleEdgeBindingReconciliationService", () => {
  test("streams and hash-binds more than 10,000 verified custody rows without weakening change detection", async () => {
    const fixture = createFixture();
    const bundleId = addVerifiedCustodyFanout(fixture.database, fixture.migrationId, 10_050);
    const first = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    const repeated = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    expect(first.bindings[0]).toMatchObject({ bundleId, custodyCount: 10_051 });
    expect(first.bindings[0]!.custodySetHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(repeated.previewHash).toBe(first.previewHash);
    expect(repeated.custodySetHash).toBe(first.custodySetHash);

    addVerifiedCustodyFanout(fixture.database, fixture.migrationId, 1, 10_050);
    const changed = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    expect(changed.bindings[0]).toMatchObject({ bundleId, custodyCount: 10_052 });
    expect(changed.bindings[0]!.custodySetHash).not.toBe(first.bindings[0]!.custodySetHash);
    await expect(executeReviewed(fixture, first)).rejects.toThrow(/preview changed/iu);

    const completed = await executeReviewed(fixture, changed);
    expect(completed).toMatchObject({ status: "completed", bindingsReconciled: 1 });
  }, 60_000);

  test("binds many source-backed occurrences to one existing confirmed edge without promotion or counter changes", async () => {
    const fixture = createFixture();
    addRepeatedRelationshipOrigins(fixture.database, fixture.migrationId, 3);
    const before = preservationSnapshot(fixture.database);
    const edgeCountBefore = fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get();
    const preview = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 5_000 });
    const reconciliation = fixture.service.reconcile();
    expect(preview.bindingCount).toBeGreaterThanOrEqual(4);
    expect(reconciliation).toMatchObject({
      unboundBindingCount: preview.bindingCount,
      eligibleExistingEdgeBindingCount: preview.bindingCount,
      ineligibleBindingCount: 0,
    });
    expect(preview.canonicalEdgeCount).toBeLessThan(preview.bindingCount);
    expect(preview.mutationBoundary).toEqual({
      createsCanonicalEdges: false,
      changesVerificationState: false,
      changesBundleStatus: false,
      changesEvidenceOrOutcomeState: false,
      changesProcedureCounters: false,
      bindsExistingCanonicalEdgesOnly: true,
    });
    expect(JSON.stringify(preview)).not.toContain(PRIVATE_ENGAGEMENT);
    expect(JSON.stringify(preview)).not.toContain(PRIVATE_TARGET);
    expect(JSON.stringify(preview)).not.toContain(fixture.manifest.engagementDirectory);

    const completed = await executeReviewed(fixture, preview);
    expect(completed).toMatchObject({
      status: "completed",
      bindingsReconciled: preview.bindingCount,
      canonicalEdgesReused: preview.canonicalEdgeCount,
      bundlesTouched: preview.bundleCount,
    });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE materialized_edge_id IS NOT NULL
    `).get()).toEqual({ count: preview.bindingCount });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get())
      .toEqual(edgeCountBefore);
    expect(preservationSnapshot(fixture.database)).toBe(before);
    const details = fixture.database.prepare(`
      SELECT details_json FROM audit_records
      WHERE action = 'historical_attack_knowledge.bundle_edges_reconciled'
    `).get() as { readonly details_json: string };
    expect(details.details_json).toContain('"canonicalEdgesCreated":0');
    expect(details.details_json).toContain('"procedureCountersChanged":false');
    expect(details.details_json).not.toContain(PRIVATE_ENGAGEMENT);
    expect(details.details_json).not.toContain(PRIVATE_TARGET);

    const replayed = await executeReviewed(fixture, preview);
    expect(replayed).toEqual({ ...completed, status: "replayed" });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.bundle_edges_reconciled'
    `).get()).toEqual({ count: 1 });
  });

  test("reuses an existing verified edge without creating a verification or promotion receipt", async () => {
    const fixture = createFixture();
    const selected = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    expect(selected.bindingCount).toBe(1);
    fixture.database.prepare(`
      UPDATE memory_edges SET lifecycle_status = 'verified'
      WHERE id = ?
    `).run(selected.bindings[0]!.canonicalEdgeId);
    const preview = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    const receiptsBefore = fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_promotion_receipts
    `).get();
    const evidenceBefore = fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_evidence_bindings
    `).get();
    await executeReviewed(fixture, preview);
    expect(fixture.database.prepare(`
      SELECT lifecycle_status FROM memory_edges WHERE id = ?
    `).get(preview.bindings[0]!.canonicalEdgeId)).toEqual({ lifecycle_status: "verified" });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_promotion_receipts
    `).get()).toEqual(receiptsBefore);
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_evidence_bindings
    `).get()).toEqual(evidenceBefore);
  });

  test("pages deterministically and rejects replay when the exact request changes", async () => {
    const fixture = createFixture();
    addRepeatedRelationshipOrigins(fixture.database, fixture.migrationId, 4);
    const first = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 2 });
    expect(first).toMatchObject({ bindingCount: 2, hasMore: true });
    expect(first.nextSelectionCursor).toBeTruthy();
    const completed = await executeReviewed(fixture, first);
    const second = fixture.service.preview({
      actorId: ACTOR,
      reason: REASON,
      maxBindings: 2,
      afterBindingCursor: first.nextSelectionCursor!,
    });
    expect(second.bindings[0]!.cursor > first.bindings.at(-1)!.cursor).toBe(true);
    await expect(withCanonicalWriterLease(fixture.database, {
      ownerId: ACTOR,
      operation: "historical-bundle-edge-binding-reconciliation",
    }, (handle, leases) => fixture.service.execute({
      actorId: ACTOR,
      reason: `${REASON} with a changed authorization reason`,
      maxBindings: first.selection.maxBindings,
      expectedPreviewHash: first.previewHash,
      acknowledgeExistingEdgeBindingOnly: true,
    }, { handle, leases }), { maintenanceMarkerPath: null }))
      .rejects.toThrow(/exact reviewed request/iu);
    expect(completed.status).toBe("completed");
  });

  test("fails closed when verified-reference custody, reviewed endpoints, or the safe canonical edge is unavailable", () => {
    const missingCustody = createFixture();
    // Test-only downgrade simulation: production receipts are immutable, but
    // an older/incomplete database can lack the required inventory anchor.
    missingCustody.database.exec("DROP TRIGGER legacy_migration_inventory_receipts_no_delete");
    missingCustody.database.prepare(
      "DELETE FROM legacy_migration_inventory_receipts WHERE migration_id = ?",
    ).run(missingCustody.migrationId);
    expect(missingCustody.service.preview({ actorId: ACTOR, reason: REASON }).bindingCount).toBe(0);

    const wrongRetention = createFixture();
    wrongRetention.database.prepare(`
      UPDATE legacy_migration_runs SET source_retention = 'protected-copy' WHERE id = ?
    `).run(wrongRetention.migrationId);
    expect(wrongRetention.service.preview({ actorId: ACTOR, reason: REASON }).bindingCount).toBe(0);

    const staleEndpoint = createFixture();
    const stalePreview = staleEndpoint.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    staleEndpoint.database.prepare("UPDATE memory_nodes SET lifecycle_status = 'stale' WHERE id = ?")
      .run(stalePreview.bindings[0]!.sourceNodeId);
    expect(staleEndpoint.service.preview({ actorId: ACTOR, reason: REASON }).bindings.some(
      ({ sourceNodeId, targetNodeId }) => sourceNodeId === stalePreview.bindings[0]!.sourceNodeId
        || targetNodeId === stalePreview.bindings[0]!.sourceNodeId,
    )).toBe(false);

    const unreviewedEdge = createFixture();
    const edgePreview = unreviewedEdge.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    unreviewedEdge.database.prepare("UPDATE memory_edges SET author_type = 'agent' WHERE id = ?")
      .run(edgePreview.bindings[0]!.canonicalEdgeId);
    expect(unreviewedEdge.service.preview({ actorId: ACTOR, reason: REASON }).bindings.some(
      ({ canonicalEdgeId }) => canonicalEdgeId === edgePreview.bindings[0]!.canonicalEdgeId,
    )).toBe(false);

    const suppressedCandidate = createFixture();
    const suppressedPreview = suppressedCandidate.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    suppressedCandidate.database.prepare(`
      UPDATE memory_candidates SET status = 'suppressed'
      WHERE proposed_node_id = ?
    `).run(suppressedPreview.bindings[0]!.sourceNodeId);
    expect(suppressedCandidate.service.preview({ actorId: ACTOR, reason: REASON }).bindings.some(
      ({ sourceNodeId, targetNodeId }) => sourceNodeId === suppressedPreview.bindings[0]!.sourceNodeId
        || targetNodeId === suppressedPreview.bindings[0]!.sourceNodeId,
    )).toBe(false);

    const quarantined = createFixture();
    const quarantinePreview = quarantined.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    quarantined.database.prepare(`
      INSERT INTO memory_edge_privacy_quarantine (
        edge_id, reason_code, source_node_type, target_node_type, detected_at
      ) VALUES (?, 'reusable_private_boundary', ?, ?, ?)
    `).run(
      quarantinePreview.bindings[0]!.canonicalEdgeId,
      quarantinePreview.bindings[0]!.sourceNodeType,
      quarantinePreview.bindings[0]!.targetNodeType,
      NOW,
    );
    expect(quarantined.service.preview({ actorId: ACTOR, reason: REASON }).bindings.some(
      ({ canonicalEdgeId }) => canonicalEdgeId === quarantinePreview.bindings[0]!.canonicalEdgeId,
    )).toBe(false);
  });

  test("rejects a persisted relationship outside the typed attack-memory vocabulary", () => {
    const fixture = createFixture();
    const selected = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 }).bindings[0]!;
    fixture.database.prepare("UPDATE memory_edges SET edge_type = 'prefers' WHERE id = ?")
      .run(selected.canonicalEdgeId);
    fixture.database.prepare(`
      UPDATE attack_knowledge_bundle_edges SET edge_type = 'prefers'
      WHERE bundle_id = ? AND edge_key = ?
    `).run(selected.bundleId, selected.edgeKey);
    expect(() => fixture.service.preview({ actorId: ACTOR, reason: REASON }))
      .toThrow(/outside the attack-memory taxonomy/iu);
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE materialized_edge_id IS NOT NULL
    `).get()).toEqual({ count: 0 });
  });

  test("rejects a stale preview and rolls back the whole page when one conditional binding fails", async () => {
    const stale = createFixture();
    const stalePreview = stale.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    stale.database.prepare("UPDATE memory_edges SET lifecycle_status = 'stale' WHERE id = ?")
      .run(stalePreview.bindings[0]!.canonicalEdgeId);
    await expect(executeReviewed(stale, stalePreview)).rejects.toThrow(/preview changed/iu);
    expect(stale.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE materialized_edge_id IS NOT NULL
    `).get()).toEqual({ count: 0 });

    const custodyChanged = createFixture();
    const custodyPreview = custodyChanged.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    // Test-only corruption simulation: immutable production custody changing
    // after review must invalidate the hash-bound page rather than bind it.
    custodyChanged.database.exec("DROP TRIGGER legacy_migration_inventory_receipts_no_update");
    custodyChanged.database.prepare(`
      UPDATE legacy_migration_inventory_receipts SET receipt_hash = ? WHERE migration_id = ?
    `).run(sha256("changed-inventory-receipt"), custodyChanged.migrationId);
    await expect(executeReviewed(custodyChanged, custodyPreview)).rejects.toThrow(/preview changed/iu);
    expect(custodyChanged.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE materialized_edge_id IS NOT NULL
    `).get()).toEqual({ count: 0 });

    const rollback = createFixture();
    addRepeatedRelationshipOrigins(rollback.database, rollback.migrationId, 2);
    const preview = rollback.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 5_000 });
    expect(preview.bindingCount).toBeGreaterThan(1);
    rollback.database.exec(`
      CREATE TRIGGER test_fail_bundle_edge_binding
      BEFORE UPDATE OF materialized_edge_id ON attack_knowledge_bundle_edges
      WHEN old.bundle_id = '${preview.bindings[1]!.bundleId}'
       AND old.edge_key = '${preview.bindings[1]!.edgeKey}'
      BEGIN
        SELECT RAISE(ABORT, 'injected binding failure');
      END;
    `);
    await expect(executeReviewed(rollback, preview)).rejects.toThrow(/injected binding failure/iu);
    expect(rollback.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE materialized_edge_id IS NOT NULL
    `).get()).toEqual({ count: 0 });
    expect(rollback.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.bundle_edges_reconciled'
    `).get()).toEqual({ count: 0 });
  });

  test("requires an active writer lease and rejects a released fence without writing", () => {
    const fixture = createFixture();
    const preview = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 1 });
    const leases = new CanonicalDatabaseLeaseService(fixture.database, {
      clock: () => new Date(NOW),
      maintenanceMarkerPath: null,
    });
    const handle = leases.acquireWriter({
      ownerId: ACTOR,
      operation: "historical-bundle-edge-binding-reconciliation",
    });
    leases.release(handle, "test_released");
    expect(() => fixture.service.execute({
      actorId: ACTOR,
      reason: REASON,
      maxBindings: 1,
      expectedPreviewHash: preview.previewHash,
      acknowledgeExistingEdgeBindingOnly: true,
    }, { handle, leases })).toThrow(/lease/iu);
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE materialized_edge_id IS NOT NULL
    `).get()).toEqual({ count: 0 });
  });

  test("CLI preview is read-only and execute emits a mode-0600 receipt without exposing private attribution", async () => {
    const fixture = createFixture();
    const previewPath = join(fixture.directory, "preview.json");
    chmodSync(fixture.databasePath, 0o640);
    const previewPayload = await runCli(fixture, [
      "preview",
      "--actor", ACTOR,
      "--reason", REASON,
      "--dry-run",
      "--max-bindings", "2",
      "--output", previewPath,
    ]);
    expect(previewPayload.mode).toBe("preview");
    expect(statSync(fixture.databasePath).mode & 0o777).toBe(0o640);
    expect(statSync(previewPath).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(previewPath, "utf8"))).toEqual(previewPayload);
    const serialized = JSON.stringify(previewPayload);
    expect(serialized).not.toContain(PRIVATE_ENGAGEMENT);
    expect(serialized).not.toContain(PRIVATE_TARGET);
    expect(serialized).not.toContain(fixture.manifest.engagementDirectory);
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE materialized_edge_id IS NOT NULL
    `).get()).toEqual({ count: 0 });

    chmodSync(fixture.databasePath, 0o600);
    const result = previewPayload.result as { readonly previewHash: string };
    const receiptPath = join(fixture.directory, "receipt.json");
    const executed = await runCli(fixture, [
      "execute",
      "--actor", ACTOR,
      "--reason", REASON,
      "--max-bindings", "2",
      "--expected-preview-hash", result.previewHash,
      "--acknowledge-existing-edge-bindings",
      "--receipt", receiptPath,
    ]);
    expect((executed.result as { readonly status: string }).status).toBe("completed");
    expect(statSync(receiptPath).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(receiptPath, "utf8"))).toEqual(executed);

    const ordinary = join(fixture.directory, "ordinary.json");
    const linked = join(fixture.directory, "linked.json");
    writeFileSync(ordinary, "{}\n");
    symlinkSync(ordinary, linked);
    await expect(runHistoricalBundleEdgeBindingCli([
      "reconcile", "--output", linked,
    ], { TI_SCALE_DATABASE_PATH: fixture.databasePath }, { cwd: fixture.directory }))
      .rejects.toThrow(/regular non-link file/iu);
    await expect(runHistoricalBundleEdgeBindingCli([
      "reconcile", "--output", fixture.databasePath,
    ], { TI_SCALE_DATABASE_PATH: fixture.databasePath }, { cwd: fixture.directory }))
      .rejects.toThrow(/must not replace the database/iu);
    expect(existsSync(receiptPath)).toBe(true);
  });

  test("bounds a production-shaped 7,440-occurrence page without loading it into one execution", () => {
    const fixture = createFixture();
    addRepeatedRelationshipOrigins(fixture.database, fixture.migrationId, 7_440);
    const preview = fixture.service.preview({ actorId: ACTOR, reason: REASON, maxBindings: 500 });
    expect(preview).toMatchObject({ bindingCount: 500, hasMore: true });
    expect(preview.nextSelectionCursor).toBe(preview.bindings.at(-1)!.cursor);
    expect(preview.canonicalEdgeCount).toBeLessThan(preview.bindingCount);
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges
      WHERE materialized_edge_id IS NOT NULL
    `).get()).toEqual({ count: 0 });
  }, 30_000);

  test("historical promotion preview opens without changing file mode through a writable connection", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-promotion-readonly-"));
    directories.push(directory);
    const databasePath = join(directory, "promotion.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    migrateDatabase(database);
    database.close();
    chmodSync(databasePath, 0o640);
    let output = "";
    expect(await runHistoricalAttackPromotionCli([
      "preview",
      "--db", databasePath,
      "--actor", ACTOR,
      "--reason", "Prove that historical promotion preview is physically read-only",
      "--dry-run",
    ], {}, { write: (value) => { output += value; } })).toBe(0);
    expect(JSON.parse(output)).toMatchObject({ mode: "dry_run", stagedCount: 0 });
    expect(statSync(databasePath).mode & 0o777).toBe(0o640);
  });
});

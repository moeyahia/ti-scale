import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
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
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { CanonicalDatabaseLeaseService, withCanonicalWriterLease } from "../../maintenance";
import { MemoryRepository } from "../../memory";
import { canonicalJson } from "../../orchestration/serialization";
import { AttackKnowledgeCompiler } from "../AttackKnowledgeCompiler";
import { HistoricalAttackKnowledgeExtractionService } from "../HistoricalAttackKnowledgeExtractionService";
import { HistoricalReusableKnowledgeLinkRepairService } from "../HistoricalReusableKnowledgeLinkRepairService";
import { runHistoricalReusableLinkRepairCli } from "../historical-reusable-link-repair-cli";
import type { LegacyEngagementFile, LegacyEngagementManifest } from "../LegacyEngagementDiscovery";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";

const NOW = "2026-07-21T12:00:00.000Z";
const HMAC_KEY = "historical-orphan-repair-test-key-more-than-32-bytes";
const PRIVATE_ENGAGEMENT = "private-reapertwo-regression";
const PRIVATE_TARGET = "10.129.39.191";
const ACTOR = "operator:orphan-repair-test";
const REASON = "Review and reconstruct exact typed historical relationships";
const directories: string[] = [];
const databases: SqliteDatabase[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function sourceManifest(directory: string): LegacyEngagementManifest {
  const engagementDirectory = join(directory, PRIVATE_ENGAGEMENT);
  const absolutePath = join(engagementDirectory, "scripts", "ready-after-reset.sh");
  const content = [
    "#!/bin/sh",
    `# Private source target ${PRIVATE_TARGET}; this locator must remain outside reusable memory.`,
    "# After reset, refresh the live layout and do not reuse stale values.",
    "runner --dump-layout --timeout 60",
    "runner --mode rop_ll --map \"$MAP\" --elems \"$ELEMS\" --timeout 60",
    "# The bounded attempt failed after it timed out; reset the disposable environment before another attempt.",
  ].join("\n");
  mkdirSync(join(engagementDirectory, "scripts"), { recursive: true });
  writeFileSync(absolutePath, content);
  const state = statSync(absolutePath);
  const file: LegacyEngagementFile = {
    absolutePath,
    relativePath: "scripts/ready-after-reset.sh",
    kind: "script",
    contentClass: "text",
    mediaType: "text/x-shellscript",
    sha256: sha256(content),
    byteSize: Buffer.byteLength(content),
    modifiedAt: state.mtime.toISOString(),
  };
  const engagementKey = sha256(`engagement\0${PRIVATE_ENGAGEMENT}`);
  return {
    id: `legacy_engagement_${engagementKey.slice(0, 40)}`,
    root: directory,
    rootIdentity: "test-device:test-inode",
    engagementDirectory,
    engagementName: PRIVATE_ENGAGEMENT,
    engagementKey,
    sha256: sha256(canonicalJson([{
      sha256: file.sha256,
      byteSize: file.byteSize,
      modifiedAt: file.modifiedAt,
      kind: file.kind,
    }])),
    byteSize: file.byteSize,
    modifiedAt: file.modifiedAt,
    files: [file],
    quarantined: [],
  };
}

function createFixture(): {
  readonly database: SqliteDatabase;
  readonly directory: string;
  readonly manifest: LegacyEngagementManifest;
  readonly migrationId: string;
  readonly sourceId: string;
  readonly metadata: MigrationMetadataRepository;
} {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-historical-orphan-repair-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "test.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  const manifest = sourceManifest(directory);
  const metadata = new MigrationMetadataRepository(database, () => new Date(NOW));
  const migration = metadata.createRun({
    sourceRoots: [manifest.root],
    databasePath: join(directory, "test.sqlite"),
    outputDirectory: join(directory, "output"),
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
  });
  const rootState = statSync(manifest.engagementDirectory);
  const sourceId = metadata.registerSource(migration.id, {
    absolutePath: manifest.engagementDirectory,
    relativePath: manifest.engagementName,
    root: manifest.root,
    type: "engagement_manifest",
    sha256: manifest.sha256,
    byteSize: manifest.byteSize,
    modifiedAt: manifest.modifiedAt,
  }, undefined, {
    retentionMode: "verified-reference",
    device: rootState.dev,
    inode: rootState.ino,
  });
  for (const file of manifest.files) {
    const state = statSync(file.absolutePath);
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
      sourceDevice: state.dev,
      sourceInode: state.ino,
    });
  }
  database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, ?, ?, ?)
  `).run(
    migration.id,
    sha256(canonicalJson(manifest.files.map(({ relativePath, sha256: hash, byteSize, modifiedAt }) => ({
      relativePath, hash, byteSize, modifiedAt,
    })))),
    manifest.files.length,
    manifest.byteSize,
    NOW,
  );
  return { database, directory, manifest, migrationId: migration.id, sourceId, metadata };
}

function confirmPending(database: SqliteDatabase): void {
  const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const pending = database.prepare(`
    SELECT id FROM memory_candidates WHERE status = 'pending' ORDER BY id
  `).all() as Array<{ readonly id: string }>;
  pending.forEach(({ id }) => memory.confirmCandidate(id, ACTOR));
}

function scriptTitle(manifest: LegacyEngagementManifest): string {
  return `Shell procedure artifact ${manifest.files[0]!.sha256.slice(0, 16)}`;
}

function scriptNode(database: SqliteDatabase, manifest: LegacyEngagementManifest): {
  readonly id: string;
  readonly fingerprint: string;
} {
  const row = database.prepare(`
    SELECT node.id, registry.content_fingerprint AS fingerprint
    FROM memory_candidates candidate
    JOIN attack_knowledge_candidate_registry registry ON registry.candidate_id = candidate.id
    JOIN memory_nodes node ON node.id = candidate.proposed_node_id
    WHERE candidate.title = ?
  `).get(scriptTitle(manifest)) as { readonly id: string; readonly fingerprint: string } | undefined;
  if (!row) throw new Error("Script candidate did not resolve to a confirmed node");
  return row;
}

function stageOldParserShape(database: SqliteDatabase, manifest: LegacyEngagementManifest): void {
  const file = manifest.files[0]!;
  const result = new AttackKnowledgeCompiler(database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => new Date(NOW),
  }).compile({
    source: {
      privateSourceReference: file.absolutePath,
      privateLabels: [manifest.engagementName, PRIVATE_TARGET],
      sourceClass: "historical",
      sourceHash: sha256(`${file.sha256}\0${file.modifiedAt}\0${manifest.engagementKey}`),
      observedAt: file.modifiedAt,
      evidenceCount: 1,
    },
    knowledge: {
      kind: "reusable_bundle",
      facts: [
        {
          role: "failure_mode.0",
          nodeType: "failure_mode",
          title: "Execution timeout",
          summary: "The execution path exceeded its bounded completion window.",
          body: canonicalJson({ failureMode: "Execution timeout" }),
        },
        {
          role: "recovery_pattern.0",
          nodeType: "recovery_pattern",
          title: "Disposable environment reset",
          summary: "Reset the disposable environment before retrying the affected execution path.",
          body: canonicalJson({ recoveryPattern: "Disposable environment reset" }),
        },
        {
          role: "script_artifact.0",
          nodeType: "script_artifact",
          title: scriptTitle(manifest),
          summary: "Exact historical Shell script artifact retained by content hash for review and controlled reuse.",
          body: canonicalJson({
            language: "Shell",
            contentHash: file.sha256,
            sourceRetainedPrivately: true,
          }),
        },
      ],
      edges: [{
        sourceRole: "failure_mode.0",
        edgeType: "recovered_with",
        targetRole: "recovery_pattern.0",
      }],
    },
    confidence: 0.84,
  });
  expect(result).toMatchObject({ status: "staged", edgeProposalsStaged: 1 });
  confirmPending(database);
}

function addPrivateCustody(database: SqliteDatabase, migrationId: string, nodeId: string, sourceHash: string): void {
  const context = database.prepare(`
    SELECT mission_id, run_id FROM historical_attack_knowledge_import_contexts WHERE migration_id = ?
  `).get(migrationId) as { readonly mission_id: string; readonly run_id: string };
  database.prepare(`
    INSERT INTO memory_sources (
      id, node_id, source_type, source_id, mission_id, run_id,
      source_hash, acquired_at, created_at
    ) VALUES (?, ?, 'historical_attack_knowledge_source_candidate', ?, ?, ?, ?, ?, ?)
  `).run(
    `msrc_test_${sha256(`${nodeId}\0${migrationId}`).slice(0, 40)}`,
    nodeId,
    `private-source-${sha256(migrationId).slice(0, 20)}`,
    context.mission_id,
    context.run_id,
    sourceHash,
    NOW,
    NOW,
  );
}

function currentParserRepairFixture(): ReturnType<typeof createFixture> & {
  readonly service: HistoricalReusableKnowledgeLinkRepairService;
  readonly script: { readonly id: string; readonly fingerprint: string };
  readonly missionId: string;
  readonly runId: string;
} {
  const fixture = createFixture();
  stageOldParserShape(fixture.database, fixture.manifest);
  const scriptBefore = scriptNode(fixture.database, fixture.manifest);
  const oldIncidentEdges = Number((fixture.database.prepare(`
    SELECT COUNT(*) AS count
    FROM attack_knowledge_bundle_edges edge
    JOIN attack_knowledge_bundle_candidates source
      ON source.bundle_id = edge.bundle_id AND source.role = edge.source_role
    JOIN attack_knowledge_bundle_candidates target
      ON target.bundle_id = edge.bundle_id AND target.role = edge.target_role
    WHERE source.content_fingerprint = ? OR target.content_fingerprint = ?
  `).get(scriptBefore.fingerprint, scriptBefore.fingerprint) as { readonly count: number }).count);
  expect(oldIncidentEdges).toBe(0);
  expect(fixture.database.prepare(`
    SELECT 1 FROM memory_edges WHERE source_node_id = ? OR target_node_id = ?
  `).get(scriptBefore.id, scriptBefore.id)).toBeNull();

  const extracted = new HistoricalAttackKnowledgeExtractionService(fixture.database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => new Date(NOW),
  }).extract(fixture.manifest);
  expect(extracted).toMatchObject({ filesParsed: 1, filesQuarantined: 0 });
  expect(extracted.edgeTypeCounts.implemented_by).toBe(1);
  expect(extracted.edgeTypeCounts.produces_outcome).toBeGreaterThanOrEqual(1);
  confirmPending(fixture.database);
  const script = scriptNode(fixture.database, fixture.manifest);
  expect(script.id).toBe(scriptBefore.id);
  fixture.metadata.markSource(fixture.sourceId, "completed");
  fixture.metadata.completeRun(fixture.migrationId, {
    sourceRetention: { mode: "verified-reference" },
    brainProjection: { mode: "attack-knowledge-only" },
  }, join(fixture.directory, "reconciliation.json"));
  const context = fixture.database.prepare(`
    SELECT mission_id, run_id FROM historical_attack_knowledge_import_contexts WHERE migration_id = ?
  `).get(fixture.migrationId) as { readonly mission_id: string; readonly run_id: string };
  addPrivateCustody(
    fixture.database,
    fixture.migrationId,
    script.id,
    fixture.manifest.files[0]!.sha256,
  );
  return {
    ...fixture,
    service: new HistoricalReusableKnowledgeLinkRepairService(fixture.database, () => new Date(NOW)),
    script,
    missionId: context.mission_id,
    runId: context.run_id,
  };
}

async function executeReviewed(
  fixture: ReturnType<typeof currentParserRepairFixture>,
  preview: ReturnType<HistoricalReusableKnowledgeLinkRepairService["preview"]>,
) {
  return await withCanonicalWriterLease(fixture.database, {
    ownerId: ACTOR,
    operation: "historical-orphan-link-repair",
  }, (handle, leases) => fixture.service.execute({
    actorId: ACTOR,
    reason: REASON,
    expectedPreviewHash: preview.previewHash,
    acknowledged: true,
  }, { handle, leases }), {
    clock: () => new Date(NOW),
    maintenanceMarkerPath: null,
  });
}

async function runCli(
  fixture: ReturnType<typeof currentParserRepairFixture>,
  argv: readonly string[],
): Promise<Record<string, unknown>> {
  let output = "";
  const code = await runHistoricalReusableLinkRepairCli(argv, {
    TI_SCALE_DATABASE_PATH: fixture.database.name,
  }, {
    cwd: fixture.directory,
    write: (value) => { output += value; },
  });
  expect(code).toBe(0);
  return JSON.parse(output) as Record<string, unknown>;
}

async function cliPreview(
  fixture: ReturnType<typeof currentParserRepairFixture>,
  additional: readonly string[] = [],
): Promise<Record<string, unknown>> {
  return await runCli(fixture, [
    "preview",
    "--actor", ACTOR,
    "--reason", REASON,
    "--dry-run",
    ...additional,
  ]);
}

function expectCliOutputToExcludePrivateAttribution(
  payload: unknown,
  fixture: ReturnType<typeof currentParserRepairFixture>,
): void {
  const serialized = JSON.stringify(payload);
  for (const privateValue of [
    PRIVATE_ENGAGEMENT,
    PRIVATE_TARGET,
    fixture.manifest.files[0]!.absolutePath,
    fixture.missionId,
    fixture.runId,
  ]) expect(serialized).not.toContain(privateValue);
}

describe("HistoricalReusableKnowledgeLinkRepairService", () => {
  test("CLI help states the three commands and the no-implicit-re-extraction boundary", async () => {
    let output = "";
    expect(await runHistoricalReusableLinkRepairCli(["--help"], {}, {
      write: (value) => { output += value; },
    })).toBe(0);
    expect(output).toContain("reconcile");
    expect(output).toContain("preview");
    expect(output).toContain("execute");
    expect(output).toContain("never scans or re-extracts historical files");
    expect(output).toContain("history:migrate-configured");
  });

  test("repairs the old live-layout script orphan only after current deterministic re-extraction", async () => {
    const fixture = currentParserRepairFixture();
    const before = fixture.service.reconcile();
    const preview = fixture.service.preview({ actorId: ACTOR, reason: REASON });
    expect(before.orphanNodeCount).toBeGreaterThan(0);
    expect(preview.repairableOrphanNodeCount).toBeGreaterThan(0);
    expect(preview.relationships).toEqual(expect.arrayContaining([
      expect.objectContaining({
        sourceNodeType: "attack_procedure",
        edgeType: "implemented_by",
        targetNodeId: fixture.script.id,
      }),
      expect.objectContaining({
        sourceNodeId: fixture.script.id,
        edgeType: "produces_outcome",
        targetNodeType: "outcome",
      }),
    ]));
    expect(fixture.database.prepare("SELECT 1 FROM memory_edges LIMIT 1").get()).toBeNull();

    const result = await executeReviewed(fixture, preview);
    expect(result).toMatchObject({ status: "completed" });
    expect(result.relationshipsCreated).toBe(preview.relationshipCount);
    expect(result.orphanNodesConnected).toBe(preview.repairableOrphanNodeCount);
    const scriptEdges = fixture.database.prepare(`
      SELECT edge_type FROM memory_edges_safe
      WHERE source_node_id = ? OR target_node_id = ? ORDER BY edge_type
    `).all(fixture.script.id, fixture.script.id) as Array<{ readonly edge_type: string }>;
    expect(scriptEdges.map(({ edge_type }) => edge_type)).toEqual([
      "implemented_by",
      "produces_outcome",
    ]);
    const after = fixture.service.reconcile();
    expect(after.orphanNodeCount).toBeLessThan(before.orphanNodeCount);
    expect(after.connectedReusableNodeCount + after.orphanNodeCount).toBe(after.reusableNodeCount);

    const reusableGraph = JSON.stringify({
      nodes: fixture.database.prepare(`
        SELECT title, summary, body, provenance_json, scope, engagement_id, mission_id
        FROM memory_nodes ORDER BY id
      `).all(),
      edges: fixture.database.prepare(`
        SELECT title, summary, explanation, provenance_json FROM memory_edges ORDER BY id
      `).all(),
    });
    for (const privateValue of [
      PRIVATE_ENGAGEMENT,
      PRIVATE_TARGET,
      fixture.manifest.files[0]!.absolutePath,
      fixture.missionId,
      fixture.runId,
    ]) expect(reusableGraph).not.toContain(privateValue);
    expect(fixture.database.prepare(`
      SELECT mission_id, run_id FROM memory_sources
      WHERE node_id = ? AND source_type = 'historical_attack_knowledge_source_candidate'
    `).get(fixture.script.id)).toEqual({
      mission_id: fixture.missionId,
      run_id: fixture.runId,
    });
  });

  test("replays an already audited repair without duplicating edges or audit records", async () => {
    const fixture = currentParserRepairFixture();
    const preview = fixture.service.preview({ actorId: ACTOR, reason: REASON });
    const completed = await executeReviewed(fixture, preview);
    const edgeCount = fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get();
    const auditCount = fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.orphan_links_repaired'
    `).get();
    const replayed = await executeReviewed(fixture, preview);
    expect(replayed).toEqual({ ...completed, status: "replayed" });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get()).toEqual(edgeCount);
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.orphan_links_repaired'
    `).get()).toEqual(auditCount);
    await expect(runHistoricalReusableLinkRepairCli([
      "execute",
      "--actor", ACTOR,
      "--reason", "A different reason must not replay the earlier authorization",
      "--expected-preview-hash", preview.previewHash,
      "--acknowledge-reviewed-orphan-links",
      "--receipt", join(fixture.directory, "wrong-reason.json"),
    ], { TI_SCALE_DATABASE_PATH: fixture.database.name }, {
      cwd: fixture.directory,
      write: () => {},
    })).rejects.toThrow(/exact reviewed request/iu);
  });

  test("rejects a stale preview when graph state changes before the writer-leased execute", async () => {
    const fixture = currentParserRepairFixture();
    const preview = fixture.service.preview({ actorId: ACTOR, reason: REASON });
    const selected = preview.relationships[0]!;
    new MemoryRepository(fixture.database, { clock: () => new Date(NOW) }).createEdge({
      sourceNodeId: selected.sourceNodeId,
      targetNodeId: selected.targetNodeId,
      edgeType: selected.edgeType,
      title: "Reviewed relationship",
      summary: "A competing operator review changed the graph after the preview was issued.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 0.8,
      lifecycleStatus: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "Disposable stale-preview test fixture.",
        sources: [{
          sourceType: "test_review",
          sourceId: "stale-preview-fixture",
          acquiredAt: NOW,
        }],
      },
      explanation: "This edge deliberately invalidates the earlier preview.",
      authorType: "operator",
      authorId: ACTOR,
    });
    await expect(executeReviewed(fixture, preview)).rejects.toThrow(/preview changed/iu);
    expect(fixture.database.prepare(`
      SELECT 1 FROM audit_records
      WHERE action = 'historical_attack_knowledge.orphan_links_repaired'
    `).get()).toBeNull();
  });

  test("fails closed on a staged edge whose endpoint types do not permit that relationship", () => {
    const fixture = currentParserRepairFixture();
    fixture.database.prepare(`
      UPDATE attack_knowledge_bundle_edges SET edge_type = 'failed_because'
      WHERE materialized_edge_id IS NULL AND bundle_id IN (
        SELECT bundle_id FROM attack_knowledge_bundle_candidates
        WHERE content_fingerprint = ?
      ) AND (source_role IN (
        SELECT role FROM attack_knowledge_bundle_candidates
        WHERE bundle_id = attack_knowledge_bundle_edges.bundle_id AND content_fingerprint = ?
      ) OR target_role IN (
        SELECT role FROM attack_knowledge_bundle_candidates
        WHERE bundle_id = attack_knowledge_bundle_edges.bundle_id AND content_fingerprint = ?
      ))
    `).run(fixture.script.fingerprint, fixture.script.fingerprint, fixture.script.fingerprint);
    const preview = fixture.service.preview({ actorId: ACTOR, reason: REASON });
    expect(preview.relationships.some(({ sourceNodeId, targetNodeId }) =>
      sourceNodeId === fixture.script.id || targetNodeId === fixture.script.id)).toBe(false);
    expect(preview.unresolvedReasonCounts.invalid_typed_endpoints).toBeGreaterThanOrEqual(1);
    expect(fixture.database.prepare(`
      SELECT 1 FROM memory_edges WHERE source_node_id = ? OR target_node_id = ?
    `).get(fixture.script.id, fixture.script.id)).toBeNull();
  });

  test("does not offer a valid typed edge without the exact source-custody chain", () => {
    const fixture = createFixture();
    stageOldParserShape(fixture.database, fixture.manifest);
    const service = new HistoricalReusableKnowledgeLinkRepairService(
      fixture.database,
      () => new Date(NOW),
    );
    const preview = service.preview({ actorId: ACTOR, reason: REASON });
    expect(preview.relationshipCount).toBe(0);
    expect(preview.repairableOrphanNodeCount).toBe(0);
    expect(preview.unresolvedReasonCounts.missing_hash_bound_source_custody)
      .toBeGreaterThanOrEqual(2);
    expect(fixture.database.prepare("SELECT 1 FROM memory_edges LIMIT 1").get()).toBeNull();
  });

  test("CLI reconcile and bounded preview use configured read-only state and safe mode-0600 output", async () => {
    const fixture = currentParserRepairFixture();
    const edgesBefore = fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get();
    const reconciliation = await runCli(fixture, ["reconcile"]);
    expect(reconciliation.mode).toBe("reconcile");
    expect((reconciliation.result as { orphanNodeCount: number }).orphanNodeCount).toBeGreaterThan(0);

    const outputPath = join(fixture.directory, "preview.json");
    const first = await cliPreview(fixture, [
      "--max-relationships", "2",
      "--output", outputPath,
    ]);
    const firstResult = first.result as {
      relationshipCount: number;
      hasMore: boolean;
      nextProposalKey: string;
      relationships: readonly { proposalKey: string }[];
    };
    expect(firstResult).toMatchObject({ relationshipCount: 2, hasMore: true });
    expectCliOutputToExcludePrivateAttribution(first, fixture);
    expect(JSON.parse(readFileSync(outputPath, "utf8"))).toEqual(first);
    expect(statSync(outputPath).mode & 0o777).toBe(0o600);
    const second = await cliPreview(fixture, [
      "--max-relationships", "2",
      "--after", firstResult.nextProposalKey,
    ]);
    const secondResult = second.result as {
      relationships: readonly { proposalKey: string }[];
    };
    expect(secondResult.relationships[0]!.proposalKey)
      .not.toBe(firstResult.relationships[0]!.proposalKey);
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get())
      .toEqual(edgesBefore);
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.orphan_links_repaired'
    `).get()).toEqual({ count: 0 });
  });

  test("CLI execute writes a safe receipt and exact replay creates no duplicate state", async () => {
    const fixture = currentParserRepairFixture();
    const preview = await cliPreview(fixture);
    const previewHash = (preview.result as { previewHash: string }).previewHash;
    const receiptPath = join(fixture.directory, "execution.json");
    const command = [
      "execute",
      "--actor", ACTOR,
      "--reason", REASON,
      "--expected-preview-hash", previewHash,
      "--acknowledge-reviewed-orphan-links",
      "--receipt", receiptPath,
    ] as const;
    const completed = await runCli(fixture, command);
    expect((completed.result as { status: string }).status).toBe("completed");
    expectCliOutputToExcludePrivateAttribution(completed, fixture);
    expect(JSON.parse(readFileSync(receiptPath, "utf8"))).toEqual(completed);
    expect(statSync(receiptPath).mode & 0o777).toBe(0o600);
    const edgeCount = fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get();
    const auditCount = fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.orphan_links_repaired'
    `).get();

    const replayed = await runCli(fixture, command);
    expect((replayed.result as { status: string }).status).toBe("replayed");
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get())
      .toEqual(edgeCount);
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.orphan_links_repaired'
    `).get()).toEqual(auditCount);
  });

  test("CLI rejects a stale preview hash and missing execution acknowledgement", async () => {
    const fixture = currentParserRepairFixture();
    const receiptPath = join(fixture.directory, "rejected.json");
    await expect(runHistoricalReusableLinkRepairCli([
      "execute",
      "--actor", ACTOR,
      "--reason", REASON,
      "--expected-preview-hash", "0".repeat(64),
      "--acknowledge-reviewed-orphan-links",
      "--receipt", receiptPath,
    ], { TI_SCALE_DATABASE_PATH: fixture.database.name }, { cwd: fixture.directory }))
      .rejects.toThrow(/preview changed/iu);
    expect(existsSync(receiptPath)).toBe(false);
    await expect(runHistoricalReusableLinkRepairCli([
      "execute",
      "--actor", ACTOR,
      "--reason", REASON,
      "--expected-preview-hash", "0".repeat(64),
      "--receipt", receiptPath,
    ], { TI_SCALE_DATABASE_PATH: fixture.database.name }, { cwd: fixture.directory }))
      .rejects.toThrow(/acknowledge-reviewed-orphan-links/iu);
    expect(fixture.database.prepare("SELECT 1 FROM memory_edges LIMIT 1").get()).toBeNull();
  });

  test("CLI execute cannot obtain its writer lease while canonical maintenance is exclusive", async () => {
    const fixture = currentParserRepairFixture();
    const preview = await cliPreview(fixture);
    const previewHash = (preview.result as { previewHash: string }).previewHash;
    const leases = new CanonicalDatabaseLeaseService(fixture.database);
    const handle = leases.acquireMaintenance({
      ownerId: "operator:maintenance",
      operation: "exclusive-test-maintenance",
      ttlMs: 60_000,
    });
    try {
      await expect(runHistoricalReusableLinkRepairCli([
        "execute",
        "--actor", ACTOR,
        "--reason", REASON,
        "--expected-preview-hash", previewHash,
        "--acknowledge-reviewed-orphan-links",
        "--receipt", join(fixture.directory, "blocked.json"),
      ], { TI_SCALE_DATABASE_PATH: fixture.database.name }, {
        cwd: fixture.directory,
        write: () => {},
      }))
        .rejects.toThrow(/lease/iu);
    } finally {
      leases.release(handle, "test_complete");
    }
    expect(fixture.database.prepare("SELECT 1 FROM memory_edges LIMIT 1").get()).toBeNull();
  });

  test("CLI output validation refuses database replacement and symlink targets", async () => {
    const fixture = currentParserRepairFixture();
    await expect(runHistoricalReusableLinkRepairCli([
      "reconcile", "--output", fixture.database.name,
    ], { TI_SCALE_DATABASE_PATH: fixture.database.name }, { cwd: fixture.directory }))
      .rejects.toThrow(/must not replace the database/iu);
    const ordinary = join(fixture.directory, "ordinary.json");
    const linked = join(fixture.directory, "linked.json");
    writeFileSync(ordinary, "{}\n");
    symlinkSync(ordinary, linked);
    await expect(runHistoricalReusableLinkRepairCli([
      "preview",
      "--actor", ACTOR,
      "--reason", REASON,
      "--dry-run",
      "--output", linked,
    ], { TI_SCALE_DATABASE_PATH: fixture.database.name }, { cwd: fixture.directory }))
      .rejects.toThrow(/regular non-link file/iu);
    expect(readFileSync(ordinary, "utf8")).toBe("{}\n");
  });
});

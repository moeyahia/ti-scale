import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import express from "express";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { CanonicalDatabaseLeaseService, withCanonicalWriterLease } from "../../maintenance";
import {
  MemoryRepository,
  MemoryRetrievalService,
} from "../../memory";
import { createSecondBrainRouter } from "../../memory/SecondBrainRouter";
import { canonicalJson } from "../../orchestration/serialization";
import { ObsidianVaultBridge, VaultPathPolicy } from "../../vault";
import { AttackKnowledgeCompiler } from "../AttackKnowledgeCompiler";
import {
  HistoricalUnlinkedScriptArtifactReviewService,
  HistoricalUnlinkedScriptReviewError,
} from "../HistoricalUnlinkedScriptArtifactReviewService";
import { runHistoricalUnlinkedScriptReviewCli } from "../historical-unlinked-script-review-cli";
import { MigrationMetadataRepository } from "../MigrationMetadataRepository";

const NOW = "2026-07-22T09:00:00.000Z";
const ACTOR = "operator:unlinked-script-review";
const REASON = "Remove legacy parser noise while retaining private source custody for later review.";
const HMAC_KEY = "historical-unlinked-script-review-test-key-more-than-32-bytes";
const directories: string[] = [];
const databases: SqliteDatabase[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

interface ScriptFixtureItem {
  readonly candidateId: string;
  readonly nodeId: string;
  readonly contentFingerprint: string;
  readonly sourceHash: string;
  readonly sourceReference: string;
}

interface Fixture {
  readonly directory: string;
  readonly database: SqliteDatabase;
  readonly databasePath: string;
  readonly migrationId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly scripts: readonly ScriptFixtureItem[];
  readonly cveNodeId: string;
  readonly service: HistoricalUnlinkedScriptArtifactReviewService;
}

function insertImportContext(
  database: SqliteDatabase,
  migrationId: string,
): { readonly missionId: string; readonly runId: string } {
  const digest = sha256(migrationId).slice(0, 40);
  const missionId = `mission_hak_import_${digest}`;
  const runId = `run_hak_import_${digest}`;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
      created_by, version, created_at, updated_at, control_plane
    ) VALUES (?, 'Internal historical attack-knowledge import',
      'Private source-custody fixture; not an executable engagement.',
      'guided', 'archived', 'unverified', '{}', '[]', '{}', '{}',
      'system:historical-attack-knowledge-import', 1, ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      next_action_summary, budget_json, budget_usage_json, retry_count,
      replan_count, started_at, ended_at, created_at, updated_at, version,
      control_plane
    ) VALUES (?, ?, 'guided', 'completed', 1,
      'Internal source-custody fixture completed.', 'Review reusable candidates',
      '{}', '{}', 0, 0, ?, ?, ?, ?, 1, 'ti_scale')
  `).run(runId, missionId, NOW, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO historical_attack_knowledge_import_contexts (
      migration_id, mission_id, run_id, created_at
    ) VALUES (?, ?, ?, ?)
  `).run(migrationId, missionId, runId, NOW);
  return { missionId, runId };
}

function stageSourceCandidate(input: {
  readonly database: SqliteDatabase;
  readonly migrationId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly sourceHash: string;
  readonly sourceReference: string;
  readonly byteSize: number;
}): string {
  const candidateId = `candidate_hak_source_${sha256(input.sourceHash).slice(0, 48)}`;
  input.database.prepare(`
    INSERT INTO evidence_candidates (
      id, mission_id, run_id, observation_id, artifact_id, evidence_type,
      label, meaning, promotion_reason, validation_requirements_json,
      state, sensitivity, proposed_by, created_at
    ) VALUES (?, ?, ?, NULL, NULL, 'historical_attack_source_record',
      'Historical attack-knowledge source record',
      'Hash-verified local source supporting a generalized candidate.',
      'Independent semantic review remains required.', '[]',
      'candidate', 'private', 'system:historical-attack-knowledge-extractor', ?)
  `).run(candidateId, input.missionId, input.runId, NOW);
  input.database.prepare(`
    INSERT INTO historical_attack_knowledge_source_candidates (
      candidate_id, source_hash, byte_size, created_at
    ) VALUES (?, ?, ?, ?)
  `).run(candidateId, input.sourceHash, input.byteSize, NOW);
  input.database.prepare(`
    INSERT INTO historical_attack_knowledge_source_occurrences (
      candidate_id, migration_id, source_reference, source_hash,
      modified_at, observed_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(candidateId, input.migrationId, input.sourceReference, input.sourceHash, NOW, NOW);
  return candidateId;
}

function stageFact(input: {
  readonly database: SqliteDatabase;
  readonly compiler: AttackKnowledgeCompiler;
  readonly migrationId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly sourceHash: string;
  readonly sourceReference: string;
  readonly byteSize: number;
  readonly nodeType: "script_artifact" | "cve";
  readonly role: string;
  readonly title: string;
  readonly summary: string;
  readonly body: string;
}): { readonly candidateId: string; readonly nodeId: string; readonly contentFingerprint: string } {
  const compiled = input.compiler.compile({
    source: {
      privateSourceReference: input.sourceReference,
      privateLabels: [input.sourceReference],
      sourceClass: "historical",
      sourceHash: input.sourceHash,
      observedAt: NOW,
      evidenceCount: 1,
    },
    knowledge: {
      // Reproduce the pre-fix parser shape: the bundle contains one valid
      // typed failure/recovery relationship plus a bare artifact role that is
      // not incident to any edge.
      kind: "reusable_bundle",
      facts: [{
          role: input.role,
          nodeType: input.nodeType,
          title: input.title,
          summary: input.summary,
          body: input.body,
        }, {
          role: "failure_mode.0",
          nodeType: "failure_mode",
          title: "Bounded helper attempt failed",
          summary: "The bounded helper attempt did not produce attributable progress.",
          body: canonicalJson({ failureMode: "Bounded helper attempt failed" }),
        }, {
          role: "recovery_pattern.0",
          nodeType: "recovery_pattern",
          title: "Review the exact typed procedure",
          summary: "Review the exact typed procedure before another bounded attempt.",
          body: canonicalJson({ recoveryPattern: "Review the exact typed procedure" }),
        }],
      edges: [{
        sourceRole: "failure_mode.0",
        edgeType: "recovered_with",
        targetRole: "recovery_pattern.0",
      }],
    },
    confidence: 0.82,
  });
  expect(compiled).toMatchObject({ status: "staged", edgeProposalsStaged: 1 });
  const sourceCandidateId = stageSourceCandidate(input);
  input.database.prepare(`
    INSERT INTO historical_attack_knowledge_bundle_sources (
      bundle_id, receipt_id, candidate_id, source_hash, binding_hash, linked_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    compiled.bundleId!,
    compiled.provenanceReceiptId!,
    sourceCandidateId,
    input.sourceHash,
    sha256(canonicalJson({
      bundleId: compiled.bundleId,
      receiptId: compiled.provenanceReceiptId,
      sourceCandidateId,
      sourceHash: input.sourceHash,
    })),
    NOW,
  );
  const memory = new MemoryRepository(input.database, { clock: () => new Date(NOW) });
  for (const candidateId of compiled.candidateIds) {
    if (memory.requireCandidate(candidateId).status === "pending") {
      memory.confirmCandidate(candidateId, ACTOR);
    }
  }
  const selected = input.database.prepare(`
    SELECT candidate.id AS candidate_id, candidate.proposed_node_id AS node_id,
      registry.content_fingerprint
    FROM memory_candidates candidate
    JOIN attack_knowledge_candidate_registry registry ON registry.candidate_id = candidate.id
    WHERE candidate.candidate_type = ? AND candidate.title = ?
  `).get(input.nodeType, input.title) as {
    readonly candidate_id: string;
    readonly node_id: string;
    readonly content_fingerprint: string;
  };
  const candidateId = selected.candidate_id;
  const node = memory.requireNode(selected.node_id);
  input.database.prepare(`
    INSERT INTO memory_sources (
      id, node_id, source_type, source_id, mission_id, run_id,
      source_hash, acquired_at, created_at
    ) VALUES (?, ?, 'historical_attack_knowledge_source_candidate', ?, ?, ?, ?, ?, ?)
  `).run(
    `msrc_fixture_${sha256(`${node.id}\0${sourceCandidateId}`).slice(0, 40)}`,
    node.id,
    `${sourceCandidateId}:${input.migrationId}`,
    input.missionId,
    input.runId,
    input.sourceHash,
    NOW,
    NOW,
  );
  return { candidateId, nodeId: node.id, contentFingerprint: selected.content_fingerprint };
}

function fixture(scriptCount = 1): Fixture {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-unlinked-script-review-"));
  directories.push(directory);
  const databasePath = join(directory, "brain.sqlite");
  const database = createDatabaseConnection({ filename: databasePath });
  databases.push(database);
  migrateDatabase(database);
  const sourceRoot = join(directory, "historical");
  mkdirSync(sourceRoot, { recursive: true });
  const files = Array.from({ length: scriptCount + 1 }, (_, index) => {
    const isCve = index === scriptCount;
    const path = join(sourceRoot, isCve ? "candidate-cve.txt" : `helper-${index}.sh`);
    const content = isCve
      ? "CVE candidate retained for product and exact-version applicability review."
      : `#!/bin/sh\necho reusable-helper-${index}\n`;
    writeFileSync(path, content, { mode: 0o600 });
    const state = statSync(path);
    return {
      path,
      content,
      sourceHash: sha256(content),
      byteSize: Buffer.byteLength(content),
      modifiedAt: state.mtime.toISOString(),
      device: state.dev,
      inode: state.ino,
      isCve,
    };
  });
  const metadata = new MigrationMetadataRepository(database, () => new Date(NOW));
  const migration = metadata.createRun({
    sourceRoots: [sourceRoot],
    databasePath,
    outputDirectory: join(directory, "output"),
    sourceRetention: "verified-reference",
    verifiedReferenceAcknowledged: true,
    brainProjectionMode: "attack-knowledge-only",
    attackKnowledgeOnlyAcknowledged: true,
  });
  const rootState = statSync(sourceRoot);
  const manifestHash = sha256(canonicalJson(files.map(({ sourceHash, byteSize }) => ({ sourceHash, byteSize }))));
  const sourceId = metadata.registerSource(migration.id, {
    absolutePath: sourceRoot,
    relativePath: "historical",
    root: directory,
    type: "engagement_manifest",
    sha256: manifestHash,
    byteSize: files.reduce((sum, item) => sum + item.byteSize, 0),
    modifiedAt: NOW,
  }, undefined, {
    retentionMode: "verified-reference",
    device: rootState.dev,
    inode: rootState.ino,
  });
  const sourceReferences = files.map((file, index) => metadata.registerSourceObject({
    migrationId: migration.id,
    sourceId,
    objectKey: `accepted:${index}`,
    sourcePath: file.path,
    objectKind: "accepted",
    classification: file.isCve ? "note" : "script",
    sourceSha256: file.sourceHash,
    byteSize: file.byteSize,
    modifiedAt: file.modifiedAt,
    sourceDevice: file.device,
    sourceInode: file.inode,
  }));
  const receiptHash = sha256(canonicalJson(sourceReferences.map((sourceReference, index) => ({
    sourceReference,
    sourceHash: files[index]!.sourceHash,
  }))));
  database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, ?, ?, ?)
  `).run(
    migration.id,
    receiptHash,
    files.length,
    files.reduce((sum, item) => sum + item.byteSize, 0),
    NOW,
  );
  const context = insertImportContext(database, migration.id);
  const compiler = new AttackKnowledgeCompiler(database, {
    receiptHmacKey: HMAC_KEY,
    clock: () => new Date(NOW),
  });
  const scripts = files.slice(0, scriptCount).map((file, index): ScriptFixtureItem => ({
    ...stageFact({
      database,
      compiler,
      migrationId: migration.id,
      missionId: context.missionId,
      runId: context.runId,
      sourceHash: file.sourceHash,
      sourceReference: sourceReferences[index]!,
      byteSize: file.byteSize,
      nodeType: "script_artifact",
      role: `script_artifact.${index}`,
      title: `Shell procedure artifact ${file.sourceHash.slice(0, 16)}`,
      summary: "Exact historical Shell helper retained by content hash for controlled review.",
      body: canonicalJson({ language: "Shell", contentHash: file.sourceHash, sourceRetainedPrivately: true }),
    }),
    sourceHash: file.sourceHash,
    sourceReference: sourceReferences[index]!,
  }));
  const cveFile = files.at(-1)!;
  const cve = stageFact({
    database,
    compiler,
    migrationId: migration.id,
    missionId: context.missionId,
    runId: context.runId,
    sourceHash: cveFile.sourceHash,
    sourceReference: sourceReferences.at(-1)!,
    byteSize: cveFile.byteSize,
    nodeType: "cve",
    role: "cve.0",
    title: "CVE-2021-41773",
    summary: "Historical CVE candidate requiring exact product-version applicability review.",
    body: canonicalJson({ cveId: "CVE-2021-41773", applicability: "insufficient_evidence" }),
  });
  metadata.markSource(sourceId, "completed");
  metadata.completeRun(migration.id, {
    sourceRetention: { mode: "verified-reference" },
    brainProjection: { mode: "attack-knowledge-only" },
  }, join(directory, "reconciliation.json"));
  let createdIdSequence = 0;
  const service = new HistoricalUnlinkedScriptArtifactReviewService(database, {
    clock: () => new Date(NOW),
    createId: (prefix) => `${prefix}_unlinked_script_review_test_${createdIdSequence++}`,
  });
  return {
    directory,
    database,
    databasePath,
    migrationId: migration.id,
    missionId: context.missionId,
    runId: context.runId,
    scripts,
    cveNodeId: cve.nodeId,
    service,
  };
}

function request(maxCandidates = 250, afterContentFingerprint?: string) {
  return {
    actorId: ACTOR,
    reason: REASON,
    maxCandidates,
    ...(afterContentFingerprint ? { afterContentFingerprint } : {}),
  } as const;
}

async function execute(
  value: Fixture,
  preview: ReturnType<HistoricalUnlinkedScriptArtifactReviewService["preview"]>,
  afterContentFingerprint?: string,
) {
  return await withCanonicalWriterLease(value.database, {
    ownerId: ACTOR,
    operation: "historical-unlinked-script-artifact-review-test",
  }, (handle, leases) => value.service.execute({
    ...request(preview.selection.maxCandidates, afterContentFingerprint),
    expectedPreviewHash: preview.previewHash,
    acknowledgeMarkConfirmedUnlinkedScriptsStale: true,
  }, {
    assertActiveInCurrentTransaction: () => leases.assertActiveInCurrentTransaction(handle),
  }), {
    clock: () => new Date(NOW),
    maintenanceMarkerPath: null,
  });
}

async function graphNodeIds(database: SqliteDatabase): Promise<readonly string[]> {
  const app = express();
  app.use(express.json());
  app.use(createSecondBrainRouter({
    database,
    resolveActor: () => ACTOR,
    resolveAccess: () => ({ maximumSensitivity: "restricted", allowGlobal: true }),
  }));
  const server = await new Promise<Server>((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  servers.push(server);
  const address = server.address() as AddressInfo;
  const response = await fetch(`http://127.0.0.1:${address.port}/api/v2/brain/graph?view=global&scope=global&limit=1000`);
  expect(response.status).toBe(200);
  const payload = await response.json() as { readonly nodes: readonly { readonly id: string }[] };
  return payload.nodes.map(({ id }) => id);
}

describe("HistoricalUnlinkedScriptArtifactReviewService", () => {
  test("previews only parser-rejected unlinked scripts and reports CVEs without changing them", () => {
    const value = fixture(2);
    const before = value.service.reconcile();
    const preview = value.service.preview(request());
    expect(before).toMatchObject({
      activeUnlinkedConfirmedScriptArtifactCount: 2,
      eligibleStaleReviewCount: 2,
      staleReviewedScriptArtifactCount: 0,
      protectedUnlinkedVerifiedScriptArtifactCount: 0,
      unlinkedCveApplicabilityReview: {
        unlinkedConfirmedCount: 1,
        decision: "retain_for_cve_applicability_review",
        automaticallyChanged: false,
      },
    });
    expect(preview.selectedCount).toBe(2);
    expect(preview.candidates.every(({ decision }) => decision === "mark_stale_parser_rejected_noise")).toBeTrue();
    const serialized = JSON.stringify(preview);
    for (const privateValue of [
      value.directory,
      value.migrationId,
      value.missionId,
      value.runId,
      ...value.scripts.flatMap(({ sourceHash, sourceReference }) => [sourceHash, sourceReference]),
    ]) expect(serialized).not.toContain(privateValue);
    expect(value.database.prepare("SELECT lifecycle_status FROM memory_nodes WHERE id = ?")
      .get(value.cveNodeId)).toEqual({ lifecycle_status: "confirmed" });
  });

  test("stales a reviewed node, removes its active Vault projection, and preserves inspectable custody and history", async () => {
    const value = fixture();
    const script = value.scripts[0]!;
    const memory = new MemoryRepository(value.database, { clock: () => new Date(NOW) });
    const allowedVaults = join(value.directory, "allowed-vaults");
    const bridge = new ObsidianVaultBridge(value.database, memory, new VaultPathPolicy(allowedVaults));
    const connection = bridge.connect({
      id: "vault-unlinked-script-review",
      vaultPath: "Attack-Knowledge",
      displayName: "Attack Knowledge",
      syncScope: {},
      permissionGranted: true,
    });
    const exported = bridge.exportNode(connection.id, script.nodeId);
    const projectionPath = join(connection.vaultPath, exported.relativePath);
    expect(existsSync(projectionPath)).toBeTrue();
    const custodyBefore = Number((value.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_sources
      WHERE node_id = ? AND source_type = 'historical_attack_knowledge_source_candidate'
    `).get(script.nodeId) as { readonly count: number }).count);
    expect(custodyBefore).toBe(1);

    const preview = value.service.preview(request());
    const completed = await execute(value, preview);
    expect(completed).toMatchObject({ status: "completed", receipt: { staleCount: 1 } });
    const node = memory.requireNode(script.nodeId);
    expect(node).toMatchObject({ lifecycleStatus: "stale", confirmationState: "confirmed" });
    expect(memory.requireCandidate(script.candidateId)).toMatchObject({
      status: "confirmed",
      proposedNodeId: script.nodeId,
    });
    expect(value.database.prepare(`
      SELECT status FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
    `).get(connection.id, script.nodeId)).toEqual({ status: "database_ahead" });
    expect(bridge.exportableNodeIds(connection.id)).not.toContain(script.nodeId);
    expect(existsSync(projectionPath)).toBeFalse();
    expect(value.database.prepare(`
      SELECT 1 FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
    `).get(connection.id, script.nodeId)).toBeNull();
    const custodyAfter = Number((value.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_sources
      WHERE node_id = ? AND source_type = 'historical_attack_knowledge_source_candidate'
    `).get(script.nodeId) as { readonly count: number }).count);
    expect(custodyAfter).toBe(custodyBefore);
    expect(memory.listVersions(script.nodeId).map(({ lifecycleStatus }) => lifecycleStatus))
      .toEqual(["confirmed", "stale"]);

    const retrieved = new MemoryRetrievalService(memory).retrieve("Shell procedure artifact", {
      journey: "guided",
      maximumSensitivity: "restricted",
      allowGlobal: true,
      allowedNodeTypes: ["script_artifact"],
      contextBudget: 10_000,
      exactNodeIds: [script.nodeId],
      exactNodeIdsOnly: true,
    });
    expect(retrieved).toEqual([]);
    expect(await graphNodeIds(value.database)).not.toContain(script.nodeId);
    expect(memory.getNode(script.nodeId, true)?.lifecycleStatus).toBe("stale");

    const replay = await execute(value, preview);
    expect(replay).toMatchObject({ status: "replayed" });
    expect(value.service.preview(request()).selectedCount).toBe(0);
    expect(() => memory.confirmCandidate(script.candidateId, ACTOR)).toThrow("Only pending candidates");
    expect(value.service.reconcile()).toMatchObject({
      activeUnlinkedConfirmedScriptArtifactCount: 0,
      eligibleStaleReviewCount: 0,
      staleReviewedScriptArtifactCount: 1,
      unlinkedCveApplicabilityReview: { unlinkedConfirmedCount: 1 },
    });
  });

  test("rejects concurrent preview drift under the writer fence", async () => {
    const value = fixture();
    const script = value.scripts[0]!;
    const preview = value.service.preview(request());
    const memory = new MemoryRepository(value.database, { clock: () => new Date(NOW) });
    memory.correctNode(script.nodeId, {
      summary: "Operator-reviewed summary changed after the original cleanup preview.",
      authorType: "operator",
      authorId: ACTOR,
      changeReason: "Exercise stale cleanup preview protection",
    });
    try {
      await execute(value, preview);
      throw new Error("Expected stale preview rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(HistoricalUnlinkedScriptReviewError);
      expect((error as HistoricalUnlinkedScriptReviewError).code).toBe("stale_preview");
    }
    expect(memory.requireNode(script.nodeId).lifecycleStatus).toBe("confirmed");
  });

  test("paginates deterministically and executes each page exactly once", async () => {
    const value = fixture(3);
    const seen = new Set<string>();
    let cursor: string | undefined;
    let first: ReturnType<HistoricalUnlinkedScriptArtifactReviewService["preview"]> | undefined;
    do {
      const preview = value.service.preview(request(1, cursor));
      first ??= preview;
      expect(preview.selectedCount).toBe(1);
      const fingerprint = preview.candidates[0]!.contentFingerprint;
      expect(seen.has(fingerprint)).toBeFalse();
      seen.add(fingerprint);
      await execute(value, preview, cursor);
      cursor = preview.nextSelectionCursor ?? undefined;
      if (!preview.hasMore) break;
    } while (true);
    expect(seen.size).toBe(3);
    expect(value.service.reconcile()).toMatchObject({
      activeUnlinkedConfirmedScriptArtifactCount: 0,
      eligibleStaleReviewCount: 0,
      staleReviewedScriptArtifactCount: 3,
    });
    expect((await execute(value, first!)).status).toBe("replayed");
    const audits = Number((value.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'historical_attack_knowledge.unlinked_script_artifacts_staled'
    `).get() as { readonly count: number }).count);
    expect(audits).toBe(3);
  });

  test("CLI exposes read-only reconciliation/preview and writes a private execute receipt", async () => {
    const value = fixture();
    let output = "";
    expect(await runHistoricalUnlinkedScriptReviewCli([
      "reconcile", "--db", value.databasePath,
    ], {}, { write: (text) => { output += text; } })).toBe(0);
    expect(JSON.parse(output)).toMatchObject({ eligibleStaleReviewCount: 1 });
    output = "";
    expect(await runHistoricalUnlinkedScriptReviewCli([
      "preview", "--db", value.databasePath, "--actor", ACTOR,
      "--reason", REASON, "--dry-run", "--max-candidates", "1",
    ], {}, { write: (text) => { output += text; } })).toBe(0);
    const preview = JSON.parse(output) as { readonly previewHash: string };
    const receiptPath = join(value.directory, "review-receipt.json");
    // The fixture connection is closed so the CLI can acquire the canonical writer.
    value.database.close();
    databases.splice(databases.indexOf(value.database), 1);
    output = "";
    expect(await runHistoricalUnlinkedScriptReviewCli([
      "execute", "--db", value.databasePath, "--actor", ACTOR,
      "--reason", REASON, "--max-candidates", "1",
      "--expected-preview-hash", preview.previewHash,
      "--receipt", receiptPath,
      "--acknowledge-mark-confirmed-unlinked-scripts-stale",
    ], {}, { cwd: value.directory, write: (text) => { output += text; } })).toBe(0);
    expect(existsSync(receiptPath)).toBeTrue();
    expect(statSync(receiptPath).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(receiptPath, "utf8"))).toMatchObject({
      mode: "execute",
      status: "completed",
      receipt: { staleCount: 1 },
    });
  });
});

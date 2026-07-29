import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createHash } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { existsSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db/index";
import { MemoryRepository } from "../MemoryRepository";
import { OperationalHazardProfileRepository } from "../OperationalHazardProfileRepository";
import { ReusableKnowledgeOutcomeService } from "../ReusableKnowledgeOutcomeService";
import { createSecondBrainRouter, type MemoryAccessPolicy } from "../SecondBrainRouter";
import type { MemoryNodeType, MemoryProvenance, MemoryScope } from "../types";

const servers: Server[] = [];
const directories: string[] = [];
const NOW = "2026-07-21T12:00:00.000Z";

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function provenance(id: string): MemoryProvenance {
  return {
    method: "operator_statement",
    explanation: "Confirmed by the authorized operator",
    sources: [{
      sourceType: "message",
      sourceId: id,
      acquiredAt: "2026-07-15T10:00:00.000Z",
    }],
  };
}

function projectionHash(nodeIds: readonly string[]): string {
  const canonical = `[${nodeIds.map((nodeId) => JSON.stringify(nodeId)).join(",")}]`;
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

function insertMission(
  database: ReturnType<typeof createDatabaseConnection>,
  id: string,
  engagementId: string,
  journey: "autonomous" | "guided" = "guided",
): void {
  const now = "2026-07-15T10:00:00.000Z";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Authorized scope', ?, ?, 'operator', ?, ?)
  `).run(id, id, journey, engagementId, now, now);
}

function node(
  repository: MemoryRepository,
  id: string,
  scope: MemoryScope,
  title: string,
  nodeType: MemoryNodeType = "technique",
) {
  return repository.createNode({
    id,
    nodeType,
    title,
    summary: `Evidence-backed memory for ${title}`,
    body: `Procedure details for ${title}`,
    scope,
    sensitivity: "private",
    confidence: 0.9,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: provenance(`source-${id}`),
    authorType: "operator",
    authorId: "operator-route-test",
  });
}

function opaqueMemoryId(sequence: number): string {
  return `mem_${sequence.toString(16).padStart(32, "0")}`;
}

const HAZARD_NODE_IDS = {
  hazard: opaqueMemoryId(101),
  procedure: opaqueMemoryId(102),
  procedureVersion: opaqueMemoryId(103),
  product: opaqueMemoryId(104),
  version: opaqueMemoryId(105),
  stack: opaqueMemoryId(106),
  prerequisite: opaqueMemoryId(107),
  state: opaqueMemoryId(108),
  health: opaqueMemoryId(109),
  recovery: opaqueMemoryId(110),
  alternative: opaqueMemoryId(111),
} as const;

function seedReusableAttackKnowledge(
  repository: MemoryRepository,
  count = 3,
): readonly string[] {
  const definitions = [
    [opaqueMemoryId(1), "Reusable validation technique", "attack_technique"],
    [opaqueMemoryId(2), "Reusable technology product", "technology_product"],
    [opaqueMemoryId(3), "Reusable validation pattern", "validation_pattern"],
    [opaqueMemoryId(4), "Reusable recovery pattern", "recovery_pattern"],
  ] as const;
  return definitions.slice(0, count).map(([id, title, nodeType]) => (
    node(repository, id, { kind: "global" }, title, nodeType).id
  ));
}

function seedClassifiedReusableOutcome(
  database: ReturnType<typeof createDatabaseConnection>,
  repository: MemoryRepository,
): string {
  const id = opaqueMemoryId(120);
  repository.createNode({
    id,
    nodeType: "attack_procedure",
    title: "Evidence-backed bounded validation",
    summary: "Reusable procedure reviewed against one exact canonical attempt.",
    body: "Run one bounded validation only after its prerequisite state is confirmed.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.97,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Generalized through local operator review.",
      sources: [{ sourceType: "review_receipt", sourceId: "classified-outcome-source", acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "operator-route-test",
  });
  database.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
    VALUES ('run-classified-outcome', 'mission-b', 'autonomous', 'completed', ?, ?)
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO attack_attempts (
      id, mission_id, run_id, objective, technique_name, action_class,
      prerequisites_json, normalized_parameters_json, status, outcome_summary,
      ended_at, created_at, updated_at
    ) VALUES ('attempt-classified-outcome', 'mission-b', 'run-classified-outcome',
      'Validate the bounded procedure', 'Bounded validation', 'exploit-validation',
      '[]', '{}', 'succeeded', 'The represented procedure succeeded.', ?, ?, ?)
  `).run(NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO attack_attempt_knowledge_contexts (
      attack_attempt_id, procedure_node_id, product_node_ids_json,
      version_node_ids_json, stack_node_ids_json, prerequisite_node_ids_json,
      observed_state_node_ids_json, normalized_parameters_json, created_at, updated_at
    ) VALUES ('attempt-classified-outcome', ?, '[]', '[]', '[]', '[]', '[]', '{}', ?, ?)
  `).run(id, NOW, NOW);
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, target, evidence_type,
      content_hash, provenance_json, confidence, sensitivity, verification_state,
      summary, created_by, created_at
    ) VALUES ('evidence-classified-outcome', 'mission-b', 'run-classified-outcome',
      'local-evaluator', ?, 'redacted fixture', 'exploit_validation_result', ?,
      '{}', 0.98, 'internal', 'verified', 'Verified exact-attempt result.',
      'worker-route-test', ?)
  `).run(NOW, "a".repeat(64), NOW);
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES ('custody-classified-outcome', 'evidence-classified-outcome',
      'verified', 'local-evaluator', '{}', ?)
  `).run(NOW);
  database.prepare(`
    INSERT INTO attack_attempt_evidence (
      attack_attempt_id, evidence_id, relationship, created_at
    ) VALUES ('attempt-classified-outcome', 'evidence-classified-outcome', 'outcome', ?)
  `).run(NOW);
  new ReusableKnowledgeOutcomeService(database, () => new Date(NOW)).bind({
    memoryNodeId: id,
    attackAttemptId: "attempt-classified-outcome",
    evidenceIds: ["evidence-classified-outcome"],
    actorId: "operator-route-test",
    actorType: "operator",
    reason: "Reviewed the exact canonical attempt and verified result.",
  });
  return id;
}

function seedOperationalHazardDetail(
  database: ReturnType<typeof createDatabaseConnection>,
  repository: MemoryRepository,
): string {
  const definitions = [
    [HAZARD_NODE_IDS.hazard, "operational_hazard", "Bounded worker request can hang"],
    [HAZARD_NODE_IDS.procedure, "attack_procedure", "Bounded worker validation"],
    [HAZARD_NODE_IDS.procedureVersion, "procedure_version", "Health-gated bounded validation v1"],
    [HAZARD_NODE_IDS.product, "technology_product", "Managed web execution worker"],
    [HAZARD_NODE_IDS.version, "exact_version_fingerprint", "Managed web worker release 1"],
    [HAZARD_NODE_IDS.stack, "framework", "Managed web application runtime"],
    [HAZARD_NODE_IDS.prerequisite, "prerequisite", "Execution worker health confirmed"],
    [HAZARD_NODE_IDS.state, "target_state_transition", "Execution worker stopped responding"],
    [HAZARD_NODE_IDS.health, "health_check", "Minimal execution health probe"],
    [HAZARD_NODE_IDS.recovery, "recovery_pattern", "Recycle disposable execution worker"],
    [HAZARD_NODE_IDS.alternative, "attack_procedure", "Lower-risk diagnostic procedure"],
  ] as const;
  for (const [id, nodeType, title] of definitions) {
    repository.createNode({
      id,
      nodeType,
      title,
      summary: `Generalized reusable knowledge for ${title.toLowerCase()}.`,
      body: "This record contains no mission, target, address, credential, or raw artifact content.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 0.96,
      lifecycleStatus: "verified",
      confirmationState: "confirmed",
      provenance: {
        method: "derived",
        explanation: "Promoted from operator-reviewed local evidence through the reusable-memory boundary.",
        sources: [{
          sourceType: "private_receipt",
          sourceId: `source-${id}`,
          acquiredAt: "2026-07-20T12:00:00.000Z",
        }],
      },
      authorType: "operator",
      authorId: "operator-route-test",
    });
  }
  new OperationalHazardProfileRepository(database, {
    clock: () => new Date("2026-07-20T12:00:00.000Z"),
  }).create({
    hazardNodeId: HAZARD_NODE_IDS.hazard,
    procedureNodeId: HAZARD_NODE_IDS.procedure,
    procedureVersionNodeId: HAZARD_NODE_IDS.procedureVersion,
    productNodeIds: [HAZARD_NODE_IDS.product],
    versionNodeIds: [HAZARD_NODE_IDS.version],
    stackNodeIds: [HAZARD_NODE_IDS.stack],
    prerequisiteNodeIds: [HAZARD_NODE_IDS.prerequisite],
    observedStateNodeIds: [HAZARD_NODE_IDS.health, HAZARD_NODE_IDS.state],
    orderedSteps: [
      "Confirm the minimal health probe returns",
      "Run one bounded validation request",
      "Checkpoint the result before any continuation",
    ],
    normalizedParameters: { automaticRetries: 0, maximumStageCount: 1, healthProbeRequired: true },
    loadMinimum: 1,
    concurrencyMinimum: 1,
    timingWindowMs: 5_000,
    observedSymptom: "The base service responded while the execution worker stopped returning bounded results",
    affectedComponent: "Managed server-side execution worker",
    stateBefore: "The minimal execution health probe returned the expected scalar result",
    stateAfter: "Bounded execution requests timed out and the worker required recovery",
    stateTransitionNodeId: HAZARD_NODE_IDS.state,
    reproducibilityCount: 2,
    attemptCount: 3,
    recoveryPatternNodeId: HAZARD_NODE_IDS.recovery,
    recoveryActionSummary: "Recycle the disposable worker and re-establish a known-good baseline before selecting a safer represented procedure",
    recoveryCost: {
      resetCount: 2,
      operatorReportedResetCountMinimum: 11,
      serviceRecycleCount: 2,
      requiresDisposableTargetReset: true,
    },
    unsafeRetryConditions: ["The health probe does not return the expected bounded result"],
    safeRetryGate: ["A fresh minimal execution health probe returns the expected scalar result"],
    alternativeSequence: [
      "Restore a clean execution worker",
      "Use the lower-risk diagnostic procedure",
      "Checkpoint health before any next represented stage",
    ],
    alternativeProcedureNodeId: HAZARD_NODE_IDS.alternative,
    applicabilityConstraints: {
      requireExactProcedureVersion: true,
      requireAllStackNodes: true,
      requireAllPrerequisites: true,
      requireObservedState: true,
    },
    confidence: 0.95,
    observedAt: "2026-07-20T12:00:00.000Z",
    freshUntil: "2099-07-20T12:00:00.000Z",
  });
  database.prepare(`
    UPDATE memory_sources
    SET source_id = ?, source_hash = ?
    WHERE node_id = ?
  `).run(
    "/root/engagements/private-box/raw-output.json",
    "d".repeat(64),
    HAZARD_NODE_IDS.hazard,
  );
  return HAZARD_NODE_IDS.hazard;
}

async function application() {
  const directory = mkdtempSync(join(tmpdir(), "brain-router-test-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  insertMission(database, "mission-a", "eng-a");
  insertMission(database, "mission-b", "eng-b", "autonomous");
  const repository = new MemoryRepository(database);
  node(repository, "node-global", { kind: "global" }, "Global evidence method");
  node(repository, "node-a", { kind: "engagement", engagementId: "eng-a" }, "Engagement A credential path");
  node(repository, "node-b", { kind: "engagement", engagementId: "eng-b" }, "Engagement B credential path");
  node(repository, "node-mission-a", {
    kind: "mission",
    engagementId: "eng-a",
    missionId: "mission-a",
  }, "Mission A attack path");
  repository.createEdge({
    sourceNodeId: "node-global",
    targetNodeId: "node-a",
    edgeType: "applies_to",
    title: "Global method applies to engagement A",
    summary: "Scoped operational relationship",
    scope: { kind: "engagement", engagementId: "eng-a" },
    sensitivity: "private",
    confidence: 0.8,
    lifecycleStatus: "confirmed",
    provenance: provenance("edge-a"),
    explanation: "The evidence method was reused in this engagement",
    authorType: "operator",
  });
  repository.createCandidate({
    id: "candidate-a",
    nodeType: "preference",
    title: "Use deeper evidence explanations",
    summary: "Candidate Guided teaching preference",
    scope: { kind: "engagement", engagementId: "eng-a" },
    sensitivity: "private",
    confidence: 0.75,
    provenance: provenance("candidate-a-source"),
    proposedBy: "agent",
  });
  repository.createCandidate({
    id: "candidate-b",
    nodeType: "preference",
    title: "Engagement B preference",
    summary: "Must not cross the tenant boundary",
    scope: { kind: "engagement", engagementId: "eng-b" },
    sensitivity: "private",
    confidence: 0.75,
    provenance: provenance("candidate-b-source"),
    proposedBy: "agent",
  });

  const policy = (access: string | undefined): MemoryAccessPolicy => {
    if (access === "all") return { maximumSensitivity: "restricted", allEngagements: true };
    if (access === "b") return { maximumSensitivity: "private", engagementIds: ["eng-b"] };
    return { maximumSensitivity: "private", engagementIds: ["eng-a"], missionIds: ["mission-a"] };
  };
  const app = express();
  app.use(express.json({ limit: "2mb" }));
  app.use(createSecondBrainRouter({
    database,
    vaultAllowedRoot: join(directory, "vaults"),
    resolveActor: (request) => request.get("X-Test-Actor") ?? "operator-route-test",
    resolveAccess: (request) => policy(request.get("X-Test-Access")),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const port = (server.address() as AddressInfo).port;
  return { database, repository, directory, url: `http://127.0.0.1:${port}` };
}

async function json(response: Response): Promise<Record<string, any>> {
  return response.json() as Promise<Record<string, any>>;
}

describe("Second Brain HTTP boundary", () => {
  test("exposes confirmed preferences separately and reveals private source custody only inside mission access", async () => {
    const { database, repository, url } = await application();
    const now = "2026-07-21T11:30:00.000Z";
    database.prepare(`
      INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
      VALUES ('run-origin-a', 'mission-a', 'guided', 'completed', ?, ?)
    `).run(now, now);
    const preference = node(
      repository,
      "preference-confirmed-global",
      { kind: "global" },
      "Readable technical explanations",
      "preference",
    );
    database.prepare(`
      INSERT INTO preference_profiles (
        id, operator_id, scope, preference_key, value_json, confirmation_state,
        confidence, source_node_id, consent_policy, version, confirmed_at,
        created_at, updated_at
      ) VALUES (
        'profile-readable-technical', 'operator-route-test', 'global',
        'guided.explanation_depth', ?, 'confirmed', 1, ?,
        'explicit_operator_confirmation', 1, ?, ?, ?
      )
    `).run(
      JSON.stringify({ value: { depth: "readable_technical" }, appliesTo: ["guided_explanations"] }),
      preference.id,
      now,
      now,
      now,
    );

    const artifact = node(
      repository,
      opaqueMemoryId(130),
      { kind: "global" },
      "Shell procedure artifact fixture",
      "script_artifact",
    );
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, created_by, created_at
      ) VALUES (
        'evidence-private-origin', 'mission-a', 'run-origin-a',
        'local-hash-review', ?, 'Reusable source', 'artifact', ?, ?, 1,
        'private', 'verified', 'Hash-verified private source custody.',
        'operator-route-test', ?
      )
    `).run(
      now,
      "f".repeat(64),
      JSON.stringify({ sourceReference: "legacy-private-source://fixture-origin-a" }),
      now,
    );
    database.prepare(`
      UPDATE memory_sources
      SET source_type = 'attack_knowledge_evidence_binding',
        evidence_id = 'evidence-private-origin', mission_id = NULL, run_id = NULL
      WHERE node_id = ?
    `).run(artifact.id);

    const preferenceResponse = await json(await fetch(`${url}/api/v2/brain/preferences`));
    expect(preferenceResponse).toMatchObject({ schemaVersion: "2.4", totalReturned: 1 });
    expect(preferenceResponse.items[0]).toMatchObject({
      preferenceKey: "guided.explanation_depth",
      value: { depth: "readable_technical" },
      appliesTo: ["guided_explanations"],
      confirmationState: "confirmed",
      lastConfirmedAt: now,
      node: { id: preference.id, nodeType: "preference", confirmationState: "confirmed" },
      provenance: { method: "operator_statement" },
    });
    const otherOperatorPreferences = await json(await fetch(`${url}/api/v2/brain/preferences`, {
      headers: { "X-Test-Actor": "operator-other" },
    }));
    expect(otherOperatorPreferences).toMatchObject({ totalReturned: 0, items: [] });

    const permitted = await json(await fetch(`${url}/api/v2/brain/nodes/${artifact.id}`));
    expect(permitted.sources[0].origins).toEqual([{
      missionId: "mission-a",
      missionName: "mission-a",
      runId: "run-origin-a",
      runStatus: "completed",
      engagementId: "eng-a",
      evidenceId: "evidence-private-origin",
      privateSourceReference: "legacy-private-source://fixture-origin-a",
    }]);

    const hidden = await json(await fetch(`${url}/api/v2/brain/nodes/${artifact.id}`, {
      headers: { "X-Test-Access": "b" },
    }));
    expect(hidden.sources[0].origins).toBeUndefined();
  });

  test("resolves candidate:migration custody without presenting the synthetic import mission as the source engagement", async () => {
    const { database, repository, url } = await application();
    const now = "2026-07-21T11:45:00.000Z";
    const sourceHash = "c5ed693881a4ad5a5834b076bc16a58ac54ed1c0abdbd69fd808f758c804aa47";
    const migrationId = "migration-candidate-source-custody";
    const candidateId = "candidate-historical-shell-source";
    const sourceReference = "legacy-private-source://source-object-shell-procedure";
    const duplicateSourceReference = "legacy-private-source://source-object-shell-procedure-copy";
    const custodyMissionId = "mission-historical-source-custody";
    const custodyRunId = "run-historical-source-custody";
    const originMissionId = "mission-private-source-origin";
    const originRunId = "run-private-source-origin";
    const originArtifactId = "artifact-private-source-origin";
    const duplicateOriginArtifactId = "artifact-private-source-origin-copy";
    const artifact = node(
      repository,
      opaqueMemoryId(131),
      { kind: "global" },
      "Shell procedure artifact c5ed693881a4ad5a",
      "script_artifact",
    );

    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, status, authorization_status,
        created_by, created_at, updated_at
      ) VALUES (?, 'Internal historical attack-knowledge import',
        'Private local source-custody context; not an executable engagement.',
        'guided', 'archived', 'unverified',
        'system:historical-attack-knowledge-import', ?, ?)
    `).run(custodyMissionId, now, now);
    database.prepare(`
      INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
      VALUES (?, ?, 'guided', 'completed', ?, ?)
    `).run(custodyRunId, custodyMissionId, now, now);
    database.prepare(`
      INSERT INTO legacy_migration_runs (
        id, status, source_roots_json, database_path, output_directory,
        started_at, completed_at, source_retention,
        source_retention_acknowledged_at, brain_projection_mode,
        brain_projection_acknowledged_at
      ) VALUES (?, 'completed', '[]', '/private/brain.sqlite', '/private/import',
        ?, ?, 'verified-reference', ?, 'attack-knowledge-only', ?)
    `).run(migrationId, now, now, now, now);
    database.prepare(`
      INSERT INTO legacy_migration_sources (
        id, migration_id, source_path, relative_path, source_type,
        source_identity, source_sha256, byte_size, modified_at,
        source_reference, source_retention, source_device, source_inode,
        verified_at, status, discovered_at, completed_at
      ) VALUES ('legacy-source-reapertwo', ?, '/private/engagements/reapertwo',
        'reapertwo', 'directory', 'reapertwo-source', ?, 4154, ?, ?,
        'verified-reference', 1, 2, ?, 'completed', ?, ?)
    `).run(migrationId, sourceHash, now, sourceReference, now, now, now);
    database.prepare(`
      INSERT INTO legacy_migration_source_objects (
        id, migration_id, source_id, object_key, source_reference, source_path,
        object_kind, classification, source_sha256, byte_size, modified_at,
        source_device, source_inode, verification_status, verified_at
      ) VALUES ('legacy-object-shell-procedure', ?, 'legacy-source-reapertwo',
        'web/root_push/ready_after_reset.sh', ?,
        '/private/engagements/reapertwo/web/root_push/ready_after_reset.sh',
        'accepted', 'script', ?, 4154, ?, 1, 3, 'verified_reference', ?)
    `).run(migrationId, sourceReference, sourceHash, now, now);
    database.prepare(`
      INSERT INTO legacy_migration_source_objects (
        id, migration_id, source_id, object_key, source_reference, source_path,
        object_kind, classification, source_sha256, byte_size, modified_at,
        source_device, source_inode, verification_status, verified_at
      ) VALUES ('legacy-object-shell-procedure-copy', ?, 'legacy-source-reapertwo',
        'research/replay/ready_after_reset.sh', ?,
        '/private/engagements/reapertwo/research/replay/ready_after_reset.sh',
        'accepted', 'script', ?, 4154, ?, 1, 4, 'verified_reference', ?)
    `).run(migrationId, duplicateSourceReference, sourceHash, now, now);
    database.prepare(`
      INSERT INTO historical_attack_knowledge_import_contexts (
        migration_id, mission_id, run_id, created_at
      ) VALUES (?, ?, ?, ?)
    `).run(migrationId, custodyMissionId, custodyRunId, now);
    database.prepare(`
      INSERT INTO evidence_candidates (
        id, mission_id, run_id, evidence_type, label, meaning,
        promotion_reason, state, sensitivity, proposed_by, created_at
      ) VALUES (?, ?, ?, 'artifact', 'Historical shell source',
        'Provides immutable local source custody.', 'Independent review required.',
        'candidate', 'private', 'system:historical-attack-knowledge-extractor', ?)
    `).run(candidateId, custodyMissionId, custodyRunId, now);
    database.prepare(`
      INSERT INTO historical_attack_knowledge_source_candidates (
        candidate_id, source_hash, byte_size, created_at
      ) VALUES (?, ?, 4154, ?)
    `).run(candidateId, sourceHash, now);
    database.prepare(`
      INSERT INTO historical_attack_knowledge_source_occurrences (
        candidate_id, migration_id, source_reference, source_hash,
        modified_at, observed_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(candidateId, migrationId, sourceReference, sourceHash, now, now);
    database.prepare(`
      INSERT INTO historical_attack_knowledge_source_occurrences (
        candidate_id, migration_id, source_reference, source_hash,
        modified_at, observed_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(candidateId, migrationId, duplicateSourceReference, sourceHash, now, now);
    database.prepare(`
      INSERT INTO memory_sources (
        id, node_id, source_type, source_id, mission_id, run_id,
        source_hash, acquired_at, created_at
      ) VALUES ('memory-source-shell-candidate-migration', ?,
        'historical_attack_knowledge_source_candidate', ?, ?, ?, ?, ?, ?)
    `).run(
      artifact.id,
      `${candidateId}:${migrationId}`,
      custodyMissionId,
      custodyRunId,
      sourceHash,
      now,
      now,
    );
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, status, authorization_status,
        engagement_id, created_by, created_at, updated_at, control_plane
      ) VALUES (?, 'Private source collection', 'Retain exact private source custody.',
        'guided', 'archived', 'unverified', 'eng-private-source',
        'import:legacy-engagement', ?, ?, 'legacy')
    `).run(originMissionId, now, now);
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, created_at, updated_at, control_plane
      ) VALUES (?, ?, 'guided', 'completed', ?, ?, 'legacy')
    `).run(originRunId, originMissionId, now, now);
    database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, sensitivity, metadata_json, created_at
      ) VALUES (?, ?, ?, 'guided', 'legacy_private_source_custody', ?, ?, 4154,
        'restricted', ?, ?)
    `).run(
      originArtifactId,
      originMissionId,
      originRunId,
      sourceReference,
      sourceHash,
      JSON.stringify({ sourceLocator: "web/root_push/ready_after_reset.sh" }),
      now,
    );
    database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, sensitivity, metadata_json, created_at
      ) VALUES (?, ?, ?, 'guided', 'legacy_private_source_custody', ?, ?, 4154,
        'restricted', ?, ?)
    `).run(
      duplicateOriginArtifactId,
      originMissionId,
      originRunId,
      duplicateSourceReference,
      sourceHash,
      JSON.stringify({ sourceLocator: "research/replay/ready_after_reset.sh" }),
      now,
    );
    database.prepare(`
      INSERT INTO historical_private_source_bindings (
        memory_source_id, source_candidate_id, migration_id, source_reference,
        source_hash, mission_id, run_id, artifact_id, binding_method,
        binding_receipt_hash, created_at
      ) VALUES ('memory-source-shell-candidate-migration', ?, ?, ?, ?, ?, ?, ?,
        'existing_legacy_projection', ?, ?)
    `).run(
      candidateId,
      migrationId,
      sourceReference,
      sourceHash,
      originMissionId,
      originRunId,
      originArtifactId,
      "b".repeat(64),
      now,
    );
    database.prepare(`
      INSERT INTO historical_private_source_bindings (
        memory_source_id, source_candidate_id, migration_id, source_reference,
        source_hash, mission_id, run_id, artifact_id, binding_method,
        binding_receipt_hash, created_at
      ) VALUES ('memory-source-shell-candidate-migration', ?, ?, ?, ?, ?, ?, ?,
        'existing_legacy_projection', ?, ?)
    `).run(
      candidateId,
      migrationId,
      duplicateSourceReference,
      sourceHash,
      originMissionId,
      originRunId,
      duplicateOriginArtifactId,
      "c".repeat(64),
      now,
    );

    const authorized = await json(await fetch(`${url}/api/v2/brain/nodes/${artifact.id}`, {
      headers: { "X-Test-Access": "all" },
    }));
    const historicalSource = authorized.sources.find((source: Record<string, unknown>) => (
      source.sourceType === "historical_attack_knowledge_source_candidate"
    ));
    expect(historicalSource).toMatchObject({
      sourceId: `${candidateId}:${migrationId}`,
      sourceHash,
      origins: [{
        missionId: originMissionId,
        missionName: "Private source collection",
        runId: originRunId,
        runStatus: "completed",
        engagementLabel: "reapertwo",
        engagementId: "eng-private-source",
        artifactId: originArtifactId,
        privateSourceReference: sourceReference,
        sourceLocator: "web/root_push/ready_after_reset.sh",
      }, {
        missionId: originMissionId,
        missionName: "Private source collection",
        runId: originRunId,
        runStatus: "completed",
        engagementLabel: "reapertwo",
        engagementId: "eng-private-source",
        artifactId: duplicateOriginArtifactId,
        privateSourceReference: duplicateSourceReference,
        sourceLocator: "research/replay/ready_after_reset.sh",
      }],
    });
    expect(historicalSource.origins[0].engagementLabel).not.toBe(
      historicalSource.origins[0].missionName,
    );
    expect(historicalSource).toMatchObject({ originCount: 2, originsNextCursor: null });

    const pagedSources = await json(await fetch(
      `${url}/api/v2/brain/nodes/${artifact.id}/sources?limit=1`,
      { headers: { "X-Test-Access": "all" } },
    ));
    expect(pagedSources).toMatchObject({
      nodeId: artifact.id,
      totalCount: 2,
      nextCursor: expect.any(String),
    });
    const candidateSource = pagedSources.items.find((source: Record<string, unknown>) => (
      source.sourceType === "historical_attack_knowledge_source_candidate"
    ));
    const candidateSourcePage = candidateSource
      ? pagedSources
      : await json(await fetch(
          `${url}/api/v2/brain/nodes/${artifact.id}/sources?limit=1&cursor=${encodeURIComponent(pagedSources.nextCursor)}`,
          { headers: { "X-Test-Access": "all" } },
        ));
    const pagedCandidateSource = candidateSource ?? candidateSourcePage.items[0];
    expect(pagedCandidateSource.sourceRecordId).toBe("memory-source-shell-candidate-migration");
    const firstOriginPage = await json(await fetch(
      `${url}/api/v2/brain/nodes/${artifact.id}/sources/${pagedCandidateSource.sourceRecordId}/origins?limit=1`,
      { headers: { "X-Test-Access": "all" } },
    ));
    expect(firstOriginPage).toMatchObject({ totalCount: 2, items: [{ artifactId: originArtifactId }] });
    expect(firstOriginPage.nextCursor).toEqual(expect.any(String));
    const secondOriginPage = await json(await fetch(
      `${url}/api/v2/brain/nodes/${artifact.id}/sources/${pagedCandidateSource.sourceRecordId}/origins?limit=1&cursor=${encodeURIComponent(firstOriginPage.nextCursor)}`,
      { headers: { "X-Test-Access": "all" } },
    ));
    expect(secondOriginPage).toMatchObject({
      totalCount: 2,
      nextCursor: null,
      items: [{ artifactId: duplicateOriginArtifactId }],
    });

    const missionScoped = await json(await fetch(`${url}/api/v2/brain/nodes/${artifact.id}`));
    const hiddenHistoricalSource = missionScoped.sources.find((source: Record<string, unknown>) => (
      source.sourceType === "historical_attack_knowledge_source_candidate"
    ));
    expect(hiddenHistoricalSource.origins).toBeUndefined();
  });

  test("bounds node provenance and pages every canonical source exactly once", async () => {
    const { database, repository, url } = await application();
    const now = "2026-07-21T13:00:00.000Z";
    const memory = node(
      repository,
      opaqueMemoryId(140),
      { kind: "global" },
      "High-fanout reusable source fixture",
      "attack_lesson",
    );
    const insertSource = database.prepare(`
      INSERT INTO memory_sources (
        id, node_id, source_type, source_id, acquired_at, created_at
      ) VALUES (?, ?, 'fixture', ?, ?, ?)
    `);
    for (let index = 0; index < 30; index += 1) {
      const id = `source-pagination-${index.toString().padStart(2, "0")}`;
      insertSource.run(id, memory.id, `fixture-${index}`, now, now);
    }

    const detail = await json(await fetch(`${url}/api/v2/brain/nodes/${memory.id}`, {
      headers: { "X-Test-Access": "all" },
    }));
    expect(detail.node.sourceCount).toBe(31);
    expect(detail.sources).toHaveLength(25);
    expect(detail.node.provenance.sources).toHaveLength(25);
    expect(detail.sourcesNextCursor).toEqual(expect.any(String));

    const second = await json(await fetch(
      `${url}/api/v2/brain/nodes/${memory.id}/sources?limit=25&cursor=${encodeURIComponent(detail.sourcesNextCursor)}`,
      { headers: { "X-Test-Access": "all" } },
    ));
    expect(second).toMatchObject({ totalCount: 31, nextCursor: null });
    expect(second.items).toHaveLength(6);
    const allIds = [...detail.sources, ...second.items]
      .map((source: Record<string, unknown>) => source.sourceRecordId);
    expect(new Set(allIds).size).toBe(31);

    const crossNodeCursor = await fetch(
      `${url}/api/v2/brain/nodes/node-global/sources?cursor=${encodeURIComponent(detail.sourcesNextCursor)}`,
      { headers: { "X-Test-Access": "all" } },
    );
    expect(crossNodeCursor.status).toBe(400);
  });

  test("projects and filters canonical reusable outcome tags across list, graph, and detail", async () => {
    const { database, repository, url } = await application();
    try {
      const classifiedNodeId = seedClassifiedReusableOutcome(database, repository);
      const listed = await json(await fetch(`${url}/api/v2/brain/nodes?outcome=success&limit=20`));
      expect(listed.items.map((item: { id: string }) => item.id)).toEqual([classifiedNodeId]);
      expect(listed.items[0]).toMatchObject({ outcomeTags: ["success"] });

      const graph = await json(await fetch(`${url}/api/v2/brain/graph?view=global&outcome=success&limit=50`));
      expect(graph.nodes.map((item: { id: string }) => item.id)).toEqual([classifiedNodeId]);
      expect(graph.nodes[0]).toMatchObject({ outcomeTags: ["success"] });

      const detail = await json(await fetch(`${url}/api/v2/brain/nodes/${classifiedNodeId}`));
      expect(detail.node).toMatchObject({ id: classifiedNodeId, outcomeTags: ["success"] });

      const unclassified = await json(await fetch(`${url}/api/v2/brain/nodes?outcome=unclassified&limit=20`));
      expect(unclassified.items.map((item: { id: string }) => item.id)).not.toContain(classifiedNodeId);
      expect(unclassified.items.every((item: { outcomeTags: string[] }) => item.outcomeTags.length === 0)).toBeTrue();

      const invalid = await fetch(`${url}/api/v2/brain/nodes?outcome=worked`);
      expect(invalid.status).toBe(400);
    } finally {
      database.close();
    }
  });

  test("projects historical source reports separately across list, graph, detail, and filters", async () => {
    const { database, repository, url } = await application();
    try {
      const successId = opaqueMemoryId(141);
      const failureId = opaqueMemoryId(142);
      const mixedId = opaqueMemoryId(143);
      const unknownId = opaqueMemoryId(144);
      const notReportedId = opaqueMemoryId(145);
      for (const [id, title] of [
        [successId, "Historically reported successful procedure"],
        [failureId, "Historically reported failed procedure"],
        [mixedId, "Historically mixed procedure"],
        [unknownId, "Historical procedure without a stated outcome"],
        [notReportedId, "Procedure without historical reports"],
      ] as const) node(repository, id, { kind: "global" }, title, "attack_procedure");

      // This route test exercises the read projection only. A TEMP table with
      // the same name shadows the guarded canonical view on this connection;
      // production claim creation remains exclusively covered by the
      // classification service and immutable database guards.
      database.exec(`
        CREATE TEMP TABLE historical_reported_outcome_node_claims (
          memory_node_id TEXT NOT NULL,
          claim_id TEXT NOT NULL,
          source_hash TEXT NOT NULL,
          classification TEXT NOT NULL,
          classification_confidence REAL NOT NULL,
          policy_version TEXT NOT NULL
        )
      `);
      const insert = database.prepare(`
        INSERT INTO historical_reported_outcome_node_claims (
          memory_node_id, claim_id, source_hash, classification,
          classification_confidence, policy_version
        ) VALUES (?, ?, ?, ?, ?, 'historical-reported-outcome/v1')
      `);
      insert.run(successId, "claim-success", "a".repeat(64), "reported_success", 0.9);
      insert.run(failureId, "claim-failure", "b".repeat(64), "reported_failure", 0.8);
      insert.run(mixedId, "claim-mixed-success", "c".repeat(64), "reported_success", 0.7);
      insert.run(mixedId, "claim-mixed-failure", "d".repeat(64), "reported_failure", 0.75);
      insert.run(unknownId, "claim-unknown", "e".repeat(64), "unknown", 0.6);

      const listed = await json(await fetch(`${url}/api/v2/brain/nodes?reportedOutcome=reported_success&limit=20`));
      expect(listed.items.map((item: { id: string }) => item.id)).toEqual([successId]);
      expect(listed.items[0]).toMatchObject({
        outcomeTags: [],
        reportedOutcome: {
          classification: "reported_success",
          classificationConfidence: 0.9,
          claimCount: 1,
          sourceCount: 1,
          policyVersion: "historical-reported-outcome/v1",
        },
      });

      const graph = await json(await fetch(`${url}/api/v2/brain/graph?view=global&scope=global&reportedOutcome=mixed&limit=50`));
      expect(graph.nodes.map((item: { id: string }) => item.id)).toEqual([mixedId]);
      expect(graph.nodes[0]).toMatchObject({
        outcomeTags: [],
        reportedOutcome: { classification: "mixed", claimCount: 2, sourceCount: 2 },
      });

      const detail = await json(await fetch(`${url}/api/v2/brain/nodes/${failureId}`));
      expect(detail.node).toMatchObject({
        id: failureId,
        outcomeTags: [],
        reportedOutcome: { classification: "reported_failure" },
      });

      const notReported = await json(await fetch(`${url}/api/v2/brain/graph?view=global&scope=global&reportedOutcome=not_reported&limit=50`));
      expect(notReported.nodes.map((item: { id: string }) => item.id)).toContain(notReportedId);
      expect(notReported.nodes.map((item: { id: string }) => item.id)).not.toContain(successId);

      const conflated = await json(await fetch(`${url}/api/v2/brain/graph?view=global&scope=global&outcome=success&reportedOutcome=reported_success&limit=50`));
      expect(conflated.nodes).toEqual([]);

      const invalid = await fetch(`${url}/api/v2/brain/graph?reportedOutcome=succeeded`);
      expect(invalid.status).toBe(400);
    } finally {
      database.close();
    }
  });

  test("operational-hazard detail is human-readable, exact about corroboration, and exposes only opaque provenance receipts", async () => {
    const { database, repository, url } = await application();
    try {
      const hazardNodeId = seedOperationalHazardDetail(database, repository);
      // Model a pre-boundary imported history row in this isolated database;
      // production writes remain protected by the append-only triggers.
      database.exec("DROP TRIGGER memory_versions_no_update");
      database.prepare(`
        UPDATE memory_versions
        SET title = 'Legacy private hazard note',
            summary = 'Historical reusable content that should have remained protected',
            body = '/root/engagements/private-box/raw-history.txt',
            change_reason = 'Imported before the reusable-memory privacy boundary'
        WHERE node_id = ?
      `).run(hazardNodeId);
      database.exec(`
        CREATE TRIGGER memory_versions_no_update
        BEFORE UPDATE ON memory_versions BEGIN
          SELECT RAISE(ABORT, 'memory versions are append-only');
        END;
      `);
      const response = await fetch(`${url}/api/v2/brain/nodes/${hazardNodeId}`);
      expect(response.status).toBe(200);
      const detail = await json(response);
      expect(detail.operationalHazard).toMatchObject({
        procedure: { id: HAZARD_NODE_IDS.procedure, title: "Bounded worker validation" },
        procedureVersion: { id: HAZARD_NODE_IDS.procedureVersion, title: "Health-gated bounded validation v1" },
        affectedVersions: [{ title: "Managed web worker release 1" }],
        affectedStack: [{ title: "Managed web application runtime" }],
        corroboration: {
          exactHangCount: 2,
          observedAttemptCount: 3,
          operatorReportedResetMinimum: 11,
        },
        safeHealthGate: ["A fresh minimal execution health probe returns the expected scalar result"],
        provenanceReceipt: {
          profileVersion: 1,
          sourceCount: 1,
          receiptIds: [expect.stringMatching(/^receipt-[a-f0-9]{20}$/u)],
          receiptHash: expect.stringMatching(/^[a-f0-9]{64}$/u),
        },
      });
      expect(detail.sources[0]).toMatchObject({ sourceId: expect.stringMatching(/^receipt-[a-f0-9]{20}$/u) });
      expect(detail.sources[0].sourceHash).toBeUndefined();
      expect(detail.operationalHazard.provenanceReceipt.sourceHashes).toBeUndefined();
      expect(detail.versions[0]).toMatchObject({
        title: "[Protected historical version]",
        summary: "Historical content was withheld because it contains private operational context.",
        changedBy: "reusable-memory privacy boundary",
      });
      const serialized = JSON.stringify(detail);
      expect(serialized).not.toContain("/root/engagements/private-box/raw-output.json");
      expect(serialized).not.toContain("d".repeat(64));
      expect(serialized).not.toContain(`source-${HAZARD_NODE_IDS.hazard}`);
      expect(serialized).not.toContain("raw-history.txt");
    } finally {
      database.close();
    }
  });

  test("memory controls are versioned, idempotent, and cannot disable safety invariants", async () => {
    const { database, url } = await application();
    try {
      const initial = await json(await fetch(`${url}/api/v2/brain/control`));
      expect(initial.policy).toMatchObject({ version: 0, enabled: true, engagementIsolation: true, secretsNeverRetained: true });
      const request = {
        method: "PUT",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "memory-control-update-0001" },
        body: JSON.stringify({
          expectedVersion: 0,
          policy: {
            enabled: true,
            personalPreferencePolicy: "disabled",
            operationalMemoryEnabled: true,
            engagementIsolation: true,
            defaultRetentionDays: 90,
            autonomousUse: false,
            guidedUse: true,
            obsidianSyncScope: "confirmed",
            secretsNeverRetained: true,
          },
        }),
      };
      const saved = await json(await fetch(`${url}/api/v2/brain/control`, request));
      expect(saved.policy).toMatchObject({ version: 1, autonomousUse: false, personalPreferencePolicy: "disabled" });
      expect(await json(await fetch(`${url}/api/v2/brain/control`, request))).toEqual(saved);

      const unsafe = await fetch(`${url}/api/v2/brain/control`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "memory-control-unsafe-0001" },
        body: JSON.stringify({ expectedVersion: 1, policy: { ...saved.policy, engagementIsolation: false } }),
      });
      expect(unsafe.status).toBe(400);

      const candidateConfirm = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "confirm-disabled-preference-0001" },
        body: JSON.stringify({}),
      });
      expect(candidateConfirm.status).toBe(403);
      expect(await candidateConfirm.json()).toMatchObject({ error: { code: "memory_retention_disabled" } });
    } finally {
      database.close();
    }
  });

  test("summary, search, graph, and detail never leak another engagement", async () => {
    const { database, url } = await application();
    try {
      const summary = await json(await fetch(`${url}/api/v2/brain/summary`));
      expect(summary).toMatchObject({
        schemaVersion: "2.4",
        counts: {
          confirmed: 3,
          verified: 0,
          candidateNodes: 0,
          pendingReviews: 1,
          candidates: 1,
          edges: 1,
        },
        health: { database: "healthy", fts: "healthy" },
      });

      const nodes = await json(await fetch(`${url}/api/v2/brain/nodes?query=credential&limit=20`));
      expect(nodes.items.map((item: { id: string }) => item.id)).toEqual(["node-a"]);
      expect(JSON.stringify(nodes)).not.toContain("Engagement B");

      const graph = await json(await fetch(`${url}/api/v2/brain/graph?view=global&limit=50`));
      expect(graph.availableNodeCount).toBe(3);
      expect(graph.nodes.map((item: { id: string }) => item.id)).toContain("node-a");
      expect(graph.nodes.map((item: { id: string }) => item.id)).not.toContain("node-b");
      expect(graph.edges).toHaveLength(1);

      // The graph workspace expands its bounded view in 250-node increments.
      // Keep that public contract covered even when the fixture is smaller.
      const expandedGraph = await fetch(`${url}/api/v2/brain/graph?view=global&limit=500`);
      expect(expandedGraph.status).toBe(200);

      const denied = await fetch(`${url}/api/v2/brain/nodes/node-b`);
      expect(denied.status).toBe(404);
      expect(await denied.json()).toMatchObject({ error: { code: "memory_node_not_found" } });
      const detail = await json(await fetch(`${url}/api/v2/brain/nodes/node-a`));
      expect(detail.node).toMatchObject({ id: "node-a", scope: { engagementId: "eng-a" } });
      expect(detail.sources[0]).toMatchObject({ sourceId: "source-node-a" });
      expect(detail.versions).toHaveLength(1);
    } finally {
      database.close();
    }
  });

  test("default global knowledge includes confirmed and verified memories with truthful bounded counts", async () => {
    const { database, repository, url } = await application();
    try {
      const createLifecycleNode = (
        id: string,
        lifecycleStatus: "candidate" | "verified" | "disputed" | "stale" | "superseded",
      ) => repository.createNode({
        id,
        nodeType: "entity",
        title: `Global ${lifecycleStatus} lifecycle fixture`,
        summary: `Exercises the ${lifecycleStatus} global graph boundary.`,
        body: "Sanitized lifecycle-boundary fixture content.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.9,
        lifecycleStatus,
        confirmationState: lifecycleStatus === "candidate" ? "pending" : "not_required",
        provenance: provenance(`source-${id}`),
        authorType: "system",
        authorId: "graph-lifecycle-test",
      });

      createLifecycleNode("global-verified", "verified");
      createLifecycleNode("global-candidate", "candidate");
      createLifecycleNode("global-disputed", "disputed");
      createLifecycleNode("global-stale", "stale");
      createLifecycleNode("global-forgotten", "superseded");
      database.prepare(`
        UPDATE memory_nodes
        SET lifecycle_status = 'forgotten', title = '[forgotten]', summary = '', body = ''
        WHERE id = 'global-forgotten'
      `).run();

      const bounded = await json(await fetch(`${url}/api/v2/brain/graph?view=global&scope=global&limit=1`));
      expect(bounded).toMatchObject({ availableNodeCount: 2, truncated: true });
      expect(bounded.nodes).toHaveLength(1);

      const complete = await json(await fetch(`${url}/api/v2/brain/graph?view=global&scope=global&limit=50`));
      expect(complete).toMatchObject({ availableNodeCount: 2, truncated: false });
      expect(complete.nodes.map((item: { id: string }) => item.id).sort()).toEqual([
        "global-verified",
        "node-global",
      ]);
      expect(complete.nodes.map((item: { lifecycleStatus: string }) => item.lifecycleStatus).sort()).toEqual([
        "confirmed",
        "verified",
      ]);

      for (const lifecycle of ["candidate", "disputed", "stale"] as const) {
        const explicit = await json(await fetch(`${url}/api/v2/brain/graph?view=global&scope=global&status=${lifecycle}&limit=50`));
        expect(explicit.availableNodeCount).toBe(1);
        expect(explicit.nodes.map((item: { id: string }) => item.id)).toEqual([`global-${lifecycle}`]);
      }

      const forgotten = await fetch(`${url}/api/v2/brain/graph?view=global&scope=global&status=forgotten&limit=50`);
      expect(forgotten.status).toBe(400);
    } finally {
      database.close();
    }
  });

  test("graph metadata filters execute inside the bounded access-controlled query", async () => {
    const { database, repository, url } = await application();
    try {
      repository.createEdge({
        sourceNodeId: "node-global",
        targetNodeId: "node-b",
        edgeType: "similar_to",
        title: "Cross-engagement access-policy fixture",
        summary: "The inaccessible endpoint must never affect the visible local count.",
        scope: { kind: "engagement", engagementId: "eng-b" },
        sensitivity: "private",
        confidence: 0.7,
        lifecycleStatus: "confirmed",
        provenance: provenance("edge-hidden-local"),
        explanation: "Exercises access-controlled local-neighborhood counting.",
        authorType: "operator",
      });
      const local = await json(await fetch(`${url}/api/v2/brain/graph?view=local&nodeId=node-global&depth=1&limit=1`));
      expect(local).toMatchObject({ availableNodeCount: 2, truncated: true });
      expect(local.nodes.map((item: { id: string }) => item.id)).toEqual(["node-global"]);
      const localAll = await json(await fetch(`${url}/api/v2/brain/graph?view=local&nodeId=node-global&depth=1&limit=50`, {
        headers: { "X-Test-Access": "all" },
      }));
      expect(localAll.availableNodeCount).toBe(3);

      const relationship = await json(await fetch(`${url}/api/v2/brain/graph?view=global&edgeType=applies_to&limit=50`));
      expect(relationship.availableNodeCount).toBe(2);
      expect(relationship.nodes.map((item: { id: string }) => item.id).sort()).toEqual(["node-a", "node-global"]);
      expect(relationship.edges.map((item: { edgeType: string }) => item.edgeType)).toEqual(["applies_to"]);

      const scoped = await json(await fetch(`${url}/api/v2/brain/graph?view=global&scope=engagement&engagementId=eng-a&status=confirmed&minConfidence=0.75&limit=50`));
      expect(scoped.availableNodeCount).toBe(1);
      expect(scoped.nodes.map((item: { id: string }) => item.id)).toEqual(["node-a"]);
      expect(JSON.stringify(scoped)).not.toContain("Engagement B");

      const future = await json(await fetch(`${url}/api/v2/brain/graph?view=global&updatedAfter=2099-01-01T00%3A00%3A00.000Z&limit=50`));
      expect(future.availableNodeCount).toBe(0);
      expect(future.nodes).toEqual([]);
      node(repository, "lesson-a", { kind: "engagement", engagementId: "eng-a" }, "Engagement A recovery lesson", "lesson");
      const preset = await json(await fetch(`${url}/api/v2/brain/graph?view=global&preset=lessons_failures&limit=50`));
      expect(preset.availableNodeCount).toBe(1);
      expect(preset.nodes.map((item: { id: string }) => item.id)).toEqual(["lesson-a"]);
      expect(preset.edges).toEqual([]);

      const invalidConfidence = await fetch(`${url}/api/v2/brain/graph?view=global&minConfidence=1.5`);
      expect(invalidConfidence.status).toBe(400);
      const inheritedPreset = await fetch(`${url}/api/v2/brain/graph?view=global&preset=constructor`);
      expect(inheritedPreset.status).toBe(400);
      const invalidRange = await fetch(`${url}/api/v2/brain/graph?view=global&updatedAfter=2026-07-15T00%3A00%3A00Z&updatedBefore=2026-07-01T00%3A00%3A00Z`);
      expect(invalidRange.status).toBe(400);
    } finally {
      database.close();
    }
  });

  test("global graph pages balance reusable semantic clusters before provenance volume", async () => {
    const { database, repository, url } = await application();
    try {
      for (let index = 0; index < 30; index += 1) {
        node(repository, `provenance-volume-${index}`, { kind: "global" }, `Historical provenance ${index}`, "mission");
      }
      const balanced = {
        technology: opaqueMemoryId(201),
        evidence: opaqueMemoryId(202),
        attack: opaqueMemoryId(203),
        tool: opaqueMemoryId(204),
        failure: opaqueMemoryId(205),
        lesson: opaqueMemoryId(206),
      } as const;
      node(repository, balanced.technology, { kind: "global" }, "Apache HTTP Server 2.4", "technology_product");
      node(repository, balanced.evidence, { kind: "global" }, "Version fingerprint", "discovery_pattern");
      node(repository, balanced.attack, { kind: "global" }, "Path traversal", "attack_vector");
      node(repository, balanced.tool, { kind: "global" }, "Reusable validation script", "script_artifact");
      node(repository, balanced.failure, { kind: "global" }, "Application worker hang", "failure_mode");
      node(repository, balanced.lesson, { kind: "global" }, "Require an execution health probe", "attack_lesson");

      const response = await fetch(`${url}/api/v2/brain/graph?view=global&limit=8`, {
        headers: { "X-Test-Access": "all" },
      });
      expect(response.status).toBe(200);
      const payload = await json(response);
      const ids = new Set(payload.nodes.map((item: { id: string }) => item.id));
      expect(ids.has(balanced.technology)).toBe(true);
      expect(ids.has(balanced.evidence)).toBe(true);
      expect(ids.has(balanced.tool)).toBe(true);
      expect(ids.has(balanced.failure)).toBe(true);
      expect(ids.has(balanced.lesson)).toBe(true);
      expect(ids.has(balanced.attack) || ids.has("node-global") || ids.has("node-a")).toBe(true);
      expect(payload.nodes.filter((item: { nodeType: string }) => item.nodeType === "mission")).toHaveLength(1);
      expect(payload.availableNodeCount).toBe(40);
      expect(payload.truncated).toBe(true);
    } finally {
      database.close();
    }
  });

  test("candidate consent mutations require idempotency and cannot cross scope", async () => {
    const { database, repository, url } = await application();
    try {
      const inbox = await json(await fetch(`${url}/api/v2/brain/candidates`));
      expect(inbox.items.map((item: { id: string }) => item.id)).toEqual(["candidate-a"]);

      const missingKey = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(missingKey.status).toBe(400);
      expect(await missingKey.json()).toMatchObject({ error: { code: "idempotency_key_required" } });

      const mutation = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "confirm-candidate-a-0001",
        },
        body: JSON.stringify({ edits: { summary: "Operator-confirmed deep evidence preference" } }),
      };
      const first = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, mutation);
      expect(first.status).toBe(201);
      const confirmed = await json(first);
      expect(confirmed.node).toMatchObject({ nodeType: "preference", lifecycleStatus: "confirmed" });
      const replay = await json(await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, mutation));
      expect(replay).toEqual(confirmed);

      const revokedReplay = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        ...mutation,
        headers: { ...mutation.headers, "X-Test-Access": "b" },
      });
      expect(revokedReplay.status).toBe(404);
      const revokedBody = await json(revokedReplay);
      expect(revokedBody).toMatchObject({ error: { category: "not_found" } });
      expect(JSON.stringify(revokedBody)).not.toContain("Operator-confirmed deep evidence preference");
      expect(repository.getNode(confirmed.node.id)).toMatchObject({ version: 1 });

      const otherActor = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        ...mutation,
        headers: { ...mutation.headers, "X-Test-Actor": "operator-route-test-other" },
      });
      expect(otherActor.status).toBe(409);
      expect(JSON.stringify(await otherActor.json())).not.toContain("Operator-confirmed deep evidence preference");

      const denied = await fetch(`${url}/api/v2/brain/candidates/candidate-b/confirm`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "confirm-candidate-b-0001",
        },
        body: JSON.stringify({}),
      });
      expect(denied.status).toBe(404);

      repository.createCandidate({
        id: "candidate-b-plain-reject",
        nodeType: "preference",
        title: "Incorrect engagement B preference",
        summary: "Reject without creating a durable relearning suppression",
        scope: { kind: "engagement", engagementId: "eng-b" },
        sensitivity: "private",
        confidence: 0.7,
        provenance: provenance("candidate-b-plain-source"),
        proposedBy: "agent",
      });
      const plainRejected = await fetch(`${url}/api/v2/brain/candidates/candidate-b-plain-reject/reject`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "reject-candidate-b-plain-0001",
          "X-Test-Access": "b",
        },
        body: JSON.stringify({
          reason: "Operator rejected this candidate without suppressing a future corrected observation",
          doNotRelearn: false,
        }),
      });
      expect(plainRejected.status).toBe(200);
      expect(await json(plainRejected)).toMatchObject({
        candidateId: "candidate-b-plain-reject",
        status: "rejected",
      });
      expect(repository.requireCandidate("candidate-b-plain-reject")).toMatchObject({
        status: "rejected",
        reviewedBy: "operator-route-test",
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_suppressions").get()).toEqual({ count: 0 });

      const rejectRequest = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "reject-candidate-b-0001",
          "X-Test-Access": "b",
        },
        body: JSON.stringify({ reason: "Operator rejected this engagement-specific preference" }),
      };
      const rejected = await fetch(`${url}/api/v2/brain/candidates/candidate-b/reject`, rejectRequest);
      expect(rejected.status).toBe(200);
      const rejectedBody = await json(rejected);
      expect(rejectedBody.status).toBe("suppressed");
      expect(typeof rejectedBody.suppressionId).toBe("string");
      const suppressionId = rejectedBody.suppressionId as string;
      expect(suppressionId.length).toBeGreaterThan(0);
      const rejectedReplay = await fetch(`${url}/api/v2/brain/candidates/candidate-b/reject`, {
        ...rejectRequest,
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "reject-candidate-b-0001",
        },
      });
      expect(rejectedReplay.status).toBe(404);
      expect(JSON.stringify(await rejectedReplay.json())).not.toContain(suppressionId);
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_suppressions").get()).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });

  test("run-filtered candidates require exact canonical provenance and remain scope isolated", async () => {
    const { database, repository, url } = await application();
    try {
      const now = "2026-07-15T10:00:00.000Z";
      const insertRun = database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES (?, ?, ?, 'completed', ?, ?)
      `);
      insertRun.run("run-a-one", "mission-a", "guided", now, now);
      insertRun.run("run-a-two", "mission-a", "guided", now, now);
      insertRun.run("run-b-one", "mission-b", "autonomous", now, now);
      insertMission(database, "mission-a-other", "eng-a");
      const insertConversation = database.prepare(`
        INSERT INTO conversations (id, mission_id, run_id, conversation_type, created_at, updated_at)
        VALUES (?, ?, ?, 'guided', ?, ?)
      `);
      insertConversation.run("conversation-a-one", "mission-a", "run-a-one", now, now);
      insertConversation.run("conversation-a-two", "mission-a", "run-a-two", now, now);
      insertConversation.run("conversation-b-one", "mission-b", "run-b-one", now, now);
      const insertMessage = database.prepare(`
        INSERT INTO messages (id, conversation_id, role, body, created_at)
        VALUES (?, ?, 'assistant', 'Bounded reusable insight', ?)
      `);
      insertMessage.run("message-a-one", "conversation-a-one", now);
      insertMessage.run("message-a-two", "conversation-a-two", now);
      insertMessage.run("message-b-one", "conversation-b-one", now);
      for (const [id, missionId, messageId] of [
        ["candidate-run-a-one", "mission-a", "message-a-one"],
        ["candidate-run-a-two", "mission-a", "message-a-two"],
        ["candidate-run-b-one", "mission-b", "message-b-one"],
      ] as const) {
        repository.createCandidate({
          id,
          nodeType: "procedure",
          title: `Procedure from ${id}`,
          summary: "Reviewable exact-run procedure",
          scope: id === "candidate-run-a-one"
            ? { kind: "engagement", engagementId: "eng-a" }
            : { kind: "mission", missionId },
          sensitivity: "private",
          confidence: 0.8,
          provenance: {
            method: "operator_statement",
            explanation: "Created from one exact Guided message.",
            sources: [{ sourceType: "message", sourceId: messageId, acquiredAt: now }],
          },
          proposedBy: "operator-route-test",
        });
      }

      for (const [id, scope, messageId] of [
        ["candidate-run-a-global", { kind: "global" }, "message-a-one"],
        ["candidate-run-a-wrong-mission", {
          kind: "mission",
          engagementId: "eng-a",
          missionId: "mission-a-other",
        }, "message-a-one"],
        ["candidate-run-a-wrong-engagement", {
          kind: "engagement",
          engagementId: "eng-b",
        }, "message-a-one"],
        ["candidate-global-other-run", { kind: "global" }, "message-a-two"],
      ] as const) {
        repository.createCandidate({
          id,
          nodeType: "procedure",
          title: `Procedure from ${id}`,
          summary: "Reviewable scope-isolation procedure",
          scope,
          sensitivity: "private",
          confidence: 0.8,
          provenance: {
            method: "operator_statement",
            explanation: "Created from one exact Guided message.",
            sources: [{ sourceType: "message", sourceId: messageId, acquiredAt: now }],
          },
          proposedBy: "operator-route-test",
        });
      }

      const exact = await json(await fetch(`${url}/api/v2/brain/candidates?missionId=mission-a&runId=run-a-one`, {
        headers: { "X-Test-Access": "all" },
      }));
      expect(exact.items.map((item: { id: string }) => item.id).sort()).toEqual([
        "candidate-run-a-global",
        "candidate-run-a-one",
      ]);
      expect(JSON.stringify(exact)).not.toContain("candidate-run-a-two");
      expect(JSON.stringify(exact)).not.toContain("candidate-run-b-one");
      expect(JSON.stringify(exact)).not.toContain("candidate-run-a-wrong-mission");
      expect(JSON.stringify(exact)).not.toContain("candidate-run-a-wrong-engagement");
      expect(JSON.stringify(exact)).not.toContain("candidate-global-other-run");

      const inaccessible = await json(await fetch(`${url}/api/v2/brain/candidates?runId=run-b-one`));
      expect(inaccessible.items).toEqual([]);
      const mismatched = await json(await fetch(`${url}/api/v2/brain/candidates?missionId=mission-a&runId=run-b-one`, {
        headers: { "X-Test-Access": "all" },
      }));
      expect(mismatched.items).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("versioned node mutations reject stale writes and forgetting is idempotent", async () => {
    const { database, url } = await application();
    try {
      const correctedResponse = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "correct-node-a-0001",
        },
        body: JSON.stringify({
          expectedVersion: 1,
          summary: "Corrected engagement A memory",
          reason: "Operator corrected the summary",
        }),
      });
      expect(correctedResponse.status).toBe(200);
      const corrected = await json(correctedResponse);
      expect(corrected.node).toMatchObject({ version: 2, summary: "Corrected engagement A memory" });

      const stale = await fetch(`${url}/api/v2/brain/nodes/node-a/pin`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "pin-node-a-stale-0001",
        },
        body: JSON.stringify({ expectedVersion: 1, pinned: true }),
      });
      expect(stale.status).toBe(409);

      const forgetRequest = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "forget-node-a-0001",
        },
        body: JSON.stringify({ expectedVersion: 2, reason: "Privacy request" }),
      };
      const forgotten = await json(await fetch(`${url}/api/v2/brain/nodes/node-a/forget`, forgetRequest));
      expect(forgotten.result).toMatchObject({ nodeId: "node-a", removed: { versions: 2 } });
      const replay = await json(await fetch(`${url}/api/v2/brain/nodes/node-a/forget`, forgetRequest));
      expect(replay).toEqual(forgotten);
      expect((await fetch(`${url}/api/v2/brain/nodes/node-a`)).status).toBe(200);
      expect((await json(await fetch(`${url}/api/v2/brain/nodes/node-a`))).node.lifecycleStatus).toBe("forgotten");
    } finally {
      database.close();
    }
  });

  test("cached node mutations reauthorize the current canonical resource before replay", async () => {
    const { database, repository, url } = await application();
    try {
      const request = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "correct-node-resource-reauth-0001",
        },
        body: JSON.stringify({
          expectedVersion: 1,
          summary: "Scoped result that must not survive revoked access",
          reason: "Exercise replay authorization",
        }),
      };
      const firstResponse = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, request);
      expect(firstResponse.status).toBe(200);
      const first = await json(firstResponse);
      expect(first.node).toMatchObject({ id: "node-a", version: 2 });
      expect(await json(await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, request))).toEqual(first);

      repository.correctNode("node-a", {
        scope: { kind: "engagement", engagementId: "eng-b" },
        authorType: "operator",
        authorId: "scope-administrator",
        changeReason: "Resource moved outside the original operator scope",
      });
      const denied = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, request);
      expect(denied.status).toBe(404);
      const deniedBody = await json(denied);
      expect(deniedBody).toMatchObject({ error: { category: "not_found" } });
      expect(JSON.stringify(deniedBody)).not.toContain("Scoped result that must not survive revoked access");
      expect(repository.getNode("node-a")).toMatchObject({ version: 3, scope: { engagementId: "eng-b" } });
    } finally {
      database.close();
    }
  });

  test("context-pack detail enforces mission scope and exposes concise use explanations", async () => {
    const { database, repository, url } = await application();
    try {
      const item = repository.requireNode("node-mission-a");
      const pack = repository.persistContextPack({
        id: "ctx-route-a",
        missionId: "mission-a",
        journey: "guided",
        purpose: "Explain the next step",
        scopePolicy: {
          engagementId: "eng-a",
          missionId: "mission-a",
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node: item, score: 1, relevanceReason: "Same mission", signals: ["exact"] }],
      });
      repository.setContextItemDisposition(pack.id, {
        nodeId: item.id,
        used: true,
        relevanceReason: "Same mission and phase",
        influenceSummary: "Expanded the evidence validation guidance",
      });
      repository.persistContextPack({
        id: "ctx-route-b",
        missionId: "mission-b",
        journey: "autonomous",
        purpose: "Hidden engagement planning context",
        scopePolicy: {
          engagementId: "eng-b",
          missionId: "mission-b",
          journey: "autonomous",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node: repository.requireNode("node-b"), score: 1, relevanceReason: "Other engagement", signals: ["exact"] }],
      });
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-b', 'mission-b', 'autonomous', 'planning', ?, ?)
      `).run("2026-07-15T10:00:00.000Z", "2026-07-15T10:00:00.000Z");
      repository.persistContextPack({
        id: "ctx-route-b-linked",
        runId: "run-b",
        journey: "autonomous",
        purpose: "Run-linked hidden engagement planning context",
        scopePolicy: {
          engagementId: "eng-b",
          missionId: "mission-b",
          journey: "autonomous",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node: repository.requireNode("node-b"), score: 1, relevanceReason: "Other engagement run", signals: ["exact"] }],
      });
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-a', 'mission-a', 'guided', 'planning', ?, ?)
      `).run("2026-07-15T10:00:00.000Z", "2026-07-15T10:00:00.000Z");
      repository.persistContextPack({
        id: "ctx-route-a-linked",
        runId: "run-a",
        journey: "guided",
        purpose: "Run-linked visible planning context",
        scopePolicy: {
          engagementId: "eng-a",
          missionId: "mission-a",
          journey: "guided",
          maximumSensitivity: "private",
          contextBudget: 1_000,
        },
        contextBudget: 1_000,
        createdBy: "commander",
        items: [{ node: item, score: 1, relevanceReason: "Same engagement run", signals: ["exact"] }],
      });
      const summaryA = await json(await fetch(`${url}/api/v2/brain/summary`));
      const summaryB = await json(await fetch(`${url}/api/v2/brain/summary`, {
        headers: { "X-Test-Access": "b" },
      }));
      expect(summaryA.counts.contextPacks).toBe(2);
      expect(summaryB.counts.contextPacks).toBe(2);
      const listed = await json(await fetch(`${url}/api/v2/brain/context-packs?missionId=mission-a`));
      expect(listed.schemaVersion).toBe("2.4");
      expect(listed.totalReturned).toBe(2);
      expect(listed.items.map((entry: { id: string }) => entry.id).sort()).toEqual(["ctx-route-a", "ctx-route-a-linked"]);
      expect(listed.items.find((entry: { id: string }) => entry.id === "ctx-route-a")).toMatchObject({
        missionId: "mission-a", journey: "guided", purpose: "Explain the next step",
        retrievedItemCount: 1, usedItemCount: 1, correctedItemCount: 0,
      });
      expect(listed.items.find((entry: { id: string }) => entry.id === "ctx-route-a-linked"))
        .toMatchObject({ missionId: "mission-a", runId: "run-a" });
      const visibleToA = JSON.stringify(await json(await fetch(`${url}/api/v2/brain/context-packs`)));
      expect(visibleToA).not.toContain("ctx-route-b");
      expect(visibleToA).not.toContain("ctx-route-b-linked");
      const detail = await json(await fetch(`${url}/api/v2/brain/context-packs/${pack.id}`));
      expect(detail.items[0]).toMatchObject({
        used: true,
        influenceSummary: "Expanded the evidence validation guidance",
        node: { id: "node-mission-a" },
      });
      const denied = await fetch(`${url}/api/v2/brain/context-packs/${pack.id}`, { headers: { "X-Test-Access": "b" } });
      expect(denied.status).toBe(404);
      const linkedDenied = await fetch(`${url}/api/v2/brain/context-packs/ctx-route-b-linked`);
      expect(linkedDenied.status).toBe(404);
      const engagementB = await json(await fetch(`${url}/api/v2/brain/context-packs`, { headers: { "X-Test-Access": "b" } }));
      expect(engagementB.items.map((item: { id: string }) => item.id).sort()).toEqual(["ctx-route-b", "ctx-route-b-linked"]);
    } finally {
      database.close();
    }
  });

  test("vault connection remains inside the configured root", async () => {
    const { database, repository, directory, url } = await application();
    try {
      seedReusableAttackKnowledge(repository, 3);
      const health = await fetch(`${url}/api/v2/brain/vault/health-check`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "health-vault-safe-0001",
        },
        body: JSON.stringify({
          vaultPath: "Operator-Brain",
          permissionGranted: true,
        }),
      });
      expect(health.status).toBe(200);
      expect(await json(health)).toMatchObject({
        result: {
          status: "healthy",
          vaultPath: "Operator-Brain",
          checks: { write: true, read: true, rename: true, delete: true },
        },
      });
      expect(readdirSync(join(directory, "vaults", "Operator-Brain"))
        .some((entry) => /^\.ti-scale-health-/u.test(entry))).toBe(false);
      const connect = await fetch(`${url}/api/v2/brain/vault/connect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "connect-vault-safe-0001",
        },
        body: JSON.stringify({
          vaultPath: "Operator-Brain",
          displayName: "Operator Brain",
          permissionGranted: true,
        }),
      });
      expect(connect.status).toBe(201);
      const connected = await json(connect);
      expect(connected).toMatchObject({ connection: { vaultPath: "Operator-Brain", status: "connected" } });

      const exportRequest = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "export-vault-safe-0001",
        },
        body: JSON.stringify({ connectionId: connected.connection.id }),
      };
      const exported = await fetch(`${url}/api/v2/brain/vault/export`, exportRequest);
      expect(exported.status).toBe(200);
      const exportedPayload = await json(exported);
      expect(exportedPayload).toMatchObject({ result: { connectionId: connected.connection.id, status: "synced" } });
      expect(await json(await fetch(`${url}/api/v2/brain/vault/export`, exportRequest))).toEqual(exportedPayload);
      const revokedExportReplay = await fetch(`${url}/api/v2/brain/vault/export`, {
        ...exportRequest,
        headers: { ...exportRequest.headers, "X-Test-Access": "b" },
      });
      expect(revokedExportReplay.status).toBe(404);
      expect(JSON.stringify(await revokedExportReplay.json())).not.toContain("Exported 3 accessible canonical notes");
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'memory.exported' AND resource_type = 'memory_node'
      `).get()).toEqual({ count: 3 });
      const snapshot = await json(await fetch(`${url}/api/v2/brain/vault`));
      expect(snapshot.syncStates.length).toBe(3);
      expect(snapshot.connections[0]).toMatchObject({
        status: "connected",
        healthChecks: { write: true, read: true, rename: true, delete: true },
        trackedNoteCount: 3,
        needsReviewCount: 0,
      });
      expect(typeof snapshot.connections[0].lastHealthCheckAt).toBe("string");
      expect(JSON.stringify(snapshot)).not.toContain(join(directory, "vaults"));

      const insertAggregateFixture = database.prepare(`
        INSERT INTO vault_sync_state (
          id, connection_id, relative_path, status, last_scanned_at
        ) VALUES (?, ?, ?, ?, ?)
      `);
      database.transaction(() => {
        for (let index = 0; index < 260; index += 1) {
          insertAggregateFixture.run(
            `aggregate-fixture-${index}`,
            connected.connection.id,
            `.ti-scale/quarantine/aggregate-fixture-${index}.md`,
            index === 0 ? "quarantined" : "synced",
            "2026-07-16T22:00:00.000Z",
          );
        }
      })();
      const aggregateSnapshot = await json(await fetch(`${url}/api/v2/brain/vault`, {
        headers: { "X-Test-Access": "all" },
      }));
      expect(aggregateSnapshot.syncStates).toHaveLength(250);
      expect(aggregateSnapshot.connections[0]).toMatchObject({
        trackedNoteCount: 263,
        needsReviewCount: 1,
      });
      database.prepare("DELETE FROM vault_sync_state WHERE id LIKE 'aggregate-fixture-%'").run();

      const audits = database.prepare(`
        SELECT action, resource_type, details_json FROM audit_records
        WHERE action IN ('vault.health.verified', 'vault.connection.connected')
        ORDER BY rowid
      `).all() as Array<{ action: string; resource_type: string; details_json: string }>;
      expect(audits.map((item) => [item.action, item.resource_type])).toEqual([
        ["vault.health.verified", "vault_path_candidate"],
        ["vault.health.verified", "vault_connection"],
        ["vault.connection.connected", "vault_connection"],
      ]);
      const connectionHealth = JSON.parse(audits[1]!.details_json) as Record<string, unknown>;
      expect(connectionHealth).toMatchObject({
        connectionId: connected.connection.id,
        connectionUpdatedAt: connected.connection.updatedAt,
        checks: { write: true, read: true, rename: true, delete: true },
      });
      expect(connectionHealth.pathFingerprint).toMatch(/^[a-f0-9]{64}$/u);
      expect(JSON.stringify(audits)).not.toContain(join(directory, "vaults"));

      const synchronized = await fetch(`${url}/api/v2/brain/vault/sync`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "sync-vault-safe-0001",
        },
        body: JSON.stringify({ connectionId: connected.connection.id }),
      });
      expect(synchronized.status).toBe(200);
      expect(await synchronized.json()).toMatchObject({ result: { status: "synced" } });

      const traversal = await fetch(`${url}/api/v2/brain/vault/connect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "connect-vault-escape-0001",
        },
        body: JSON.stringify({
          vaultPath: "../../outside",
          displayName: "Outside",
          permissionGranted: true,
        }),
      });
      expect([400, 403]).toContain(traversal.status);
      expect(JSON.stringify(await traversal.json())).not.toContain(directory.replaceAll("\\", "/"));
    } finally {
      database.close();
    }
  });

  test("legacy projection approval cannot bypass the reusable Attack Vault boundary", async () => {
    const { database, url } = await application();
    try {
      database.exec(`
        CREATE TABLE legacy_engagement_brain_nodes (
          migration_id TEXT NOT NULL,
          manifest_id TEXT NOT NULL,
          node_id TEXT NOT NULL,
          created_at TEXT NOT NULL,
          PRIMARY KEY (migration_id, node_id)
        ) STRICT;
        CREATE TABLE legacy_vault_projection_approvals (
          id TEXT PRIMARY KEY,
          migration_id TEXT NOT NULL,
          reconciliation_hash TEXT NOT NULL,
          projection_hash TEXT NOT NULL,
          connection_id TEXT NOT NULL,
          approved_by TEXT NOT NULL,
          status TEXT NOT NULL,
          projected_node_ids_json TEXT NOT NULL,
          result_json TEXT,
          approved_at TEXT NOT NULL,
          completed_at TEXT
        ) STRICT;
      `);
      const migrationId = "migration-vault-export-gate";
      const reconciliationHash = "a".repeat(64);
      const now = "2026-07-17T16:00:00.000Z";
      database.prepare(`
        INSERT INTO legacy_migration_runs (
          id, status, source_roots_json, database_path, output_directory,
          started_at, completed_at
        ) VALUES (?, 'completed', '[]', '/redacted/database', '/redacted/output', ?, ?)
      `).run(migrationId, now, now);
      database.prepare(`
        INSERT INTO legacy_migration_reconciliation (
          migration_id, report_json, report_hash, created_at
        ) VALUES (?, '{}', ?, ?)
      `).run(migrationId, reconciliationHash, now);
      database.prepare(`
        INSERT INTO legacy_engagement_brain_nodes (
          migration_id, manifest_id, node_id, created_at
        ) VALUES (?, 'manifest-vault-export-gate', 'node-a', ?)
      `).run(migrationId, now);

      const connectedResponse = await fetch(`${url}/api/v2/brain/vault/connect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "connect-legacy-export-gate-0001",
        },
        body: JSON.stringify({
          vaultPath: "Legacy-Export-Gate",
          displayName: "Legacy Export Gate",
          permissionGranted: true,
        }),
      });
      expect(connectedResponse.status).toBe(201);
      const connected = await json(connectedResponse);
      const connectionId = String(connected.connection.id);

      const unapprovedTarget = await fetch(`${url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "legacy-target-export-unapproved-0001",
        },
        body: JSON.stringify({ connectionId, nodeId: "node-a" }),
      });
      const unapprovedBulk = await fetch(`${url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "legacy-bulk-export-unapproved-0001",
        },
        body: JSON.stringify({ connectionId }),
      });
      expect(unapprovedTarget.status).toBe(403);
      expect(unapprovedBulk.status).toBe(200);
      expect(await unapprovedTarget.json()).toMatchObject({
        error: {
          code: "memory_scope_denied",
        },
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state
        WHERE connection_id = ? AND node_id = 'node-a'
      `).get(connectionId)).toEqual({ count: 0 });

      const expectedProjectionHash = projectionHash(["node-a"]);
      database.prepare(`
        INSERT INTO legacy_vault_projection_approvals (
          id, migration_id, reconciliation_hash, projection_hash, connection_id,
          approved_by, status, projected_node_ids_json, result_json,
          approved_at, completed_at
        ) VALUES (
          'approval-vault-export-gate', ?, ?, ?, ?, 'operator-route-test',
          'completed', '["node-a"]', '{}', ?, ?
        )
      `).run(migrationId, reconciliationHash, "b".repeat(64), connectionId, now, now);
      const wrongProjectionHash = await fetch(`${url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "legacy-target-export-wrong-hash-0001",
        },
        body: JSON.stringify({ connectionId, nodeId: "node-a" }),
      });
      expect(wrongProjectionHash.status).toBe(403);

      database.prepare(`
        UPDATE legacy_vault_projection_approvals SET projection_hash = ?
        WHERE id = 'approval-vault-export-gate'
      `).run(expectedProjectionHash);
      const approvedRequest = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "legacy-target-export-approved-0001",
        },
        body: JSON.stringify({ connectionId, nodeId: "node-a" }),
      } as const;
      const approved = await fetch(`${url}/api/v2/brain/vault/export`, approvedRequest);
      expect(approved.status).toBe(403);

      database.prepare(`
        UPDATE legacy_migration_reconciliation SET report_hash = ? WHERE migration_id = ?
      `).run("c".repeat(64), migrationId);
      const staleReplay = await fetch(`${url}/api/v2/brain/vault/export`, approvedRequest);
      expect(staleReplay.status).toBe(403);
      expect(await staleReplay.json()).toMatchObject({
        error: { code: "memory_scope_denied" },
      });
    } finally {
      database.close();
    }
  });

  test("vault repair and reindex enforce V2 ownership, optimistic versions, idempotency, and offline safety", async () => {
    const { database, repository, directory, url } = await application();
    try {
      seedReusableAttackKnowledge(repository, 4);
      const commonHeaders = {
        "Content-Type": "application/json",
        "X-Test-Access": "all",
      };
      const connectedResponse = await fetch(`${url}/api/v2/brain/vault/connect`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "connect-vault-recovery-0001" },
        body: JSON.stringify({
          vaultPath: "Recovery-Brain",
          displayName: "Recovery Brain",
          permissionGranted: true,
        }),
      });
      expect(connectedResponse.status).toBe(201);
      const connected = await json(connectedResponse);
      const connectionId = String(connected.connection.id);
      const exported = await fetch(`${url}/api/v2/brain/vault/export`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "export-vault-recovery-0001" },
        body: JSON.stringify({ connectionId }),
      });
      expect(exported.status).toBe(200);

      let snapshot = await json(await fetch(`${url}/api/v2/brain/vault`, { headers: { "X-Test-Access": "all" } }));
      let connection = snapshot.connections.find((item: { id: string }) => item.id === connectionId);
      const repairRequest = {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "repair-vault-recovery-0001" },
        body: JSON.stringify({
          connectionId,
          expectedUpdatedAt: connection.updatedAt,
          controlPlane: "ti_scale",
        }),
      };
      const repairedResponse = await fetch(`${url}/api/v2/brain/vault/repair`, repairRequest);
      expect(repairedResponse.status).toBe(200);
      const repaired = await json(repairedResponse);
      expect(repaired).toMatchObject({
        result: {
          operation: "repair",
          status: "completed",
          connectionId,
          health: { checks: { write: true, read: true, rename: true, delete: true } },
          progress: { remaining: 0 },
        },
      });
      expect(repaired.result.connectionVersion).not.toBe(connection.updatedAt);
      expect(await json(await fetch(`${url}/api/v2/brain/vault/repair`, repairRequest))).toEqual(repaired);

      const stale = await fetch(`${url}/api/v2/brain/vault/reindex`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "reindex-vault-stale-0001" },
        body: JSON.stringify({
          connectionId,
          expectedUpdatedAt: connection.updatedAt,
          controlPlane: "ti_scale",
        }),
      });
      expect(stale.status).toBe(409);
      expect(await stale.json()).toMatchObject({ error: { code: "vault_connection_version_conflict" } });

      snapshot = await json(await fetch(`${url}/api/v2/brain/vault`, { headers: { "X-Test-Access": "all" } }));
      connection = snapshot.connections.find((item: { id: string }) => item.id === connectionId);
      const wrongPlane = await fetch(`${url}/api/v2/brain/vault/reindex`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "reindex-vault-plane-0001" },
        body: JSON.stringify({ connectionId, expectedUpdatedAt: connection.updatedAt, controlPlane: "legacy" }),
      });
      expect(wrongPlane.status).toBe(409);
      expect(await wrongPlane.json()).toMatchObject({ error: { code: "vault_control_plane_conflict" } });

      const limited = await fetch(`${url}/api/v2/brain/vault/reindex`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "reindex-vault-limited-0001" },
        body: JSON.stringify({ connectionId, expectedUpdatedAt: connection.updatedAt, controlPlane: "ti_scale" }),
      });
      expect(limited.status).toBe(403);
      expect(await limited.json()).toMatchObject({ error: { code: "vault_recovery_admin_required" } });

      const reindexed = await fetch(`${url}/api/v2/brain/vault/reindex`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "reindex-vault-recovery-0001" },
        body: JSON.stringify({ connectionId, expectedUpdatedAt: connection.updatedAt, controlPlane: "ti_scale" }),
      });
      expect(reindexed.status).toBe(200);
      expect(await reindexed.json()).toMatchObject({
        result: { operation: "reindex", status: "completed", counts: { indexed: 4 } },
      });

      snapshot = await json(await fetch(`${url}/api/v2/brain/vault`, { headers: { "X-Test-Access": "all" } }));
      connection = snapshot.connections.find((item: { id: string }) => item.id === connectionId);
      const vaultPath = join(directory, "vaults", "Recovery-Brain");
      const offlinePath = `${vaultPath}-offline`;
      renameSync(vaultPath, offlinePath);
      const offline = await fetch(`${url}/api/v2/brain/vault/repair`, {
        method: "POST",
        headers: { ...commonHeaders, "Idempotency-Key": "repair-vault-offline-0001" },
        body: JSON.stringify({ connectionId, expectedUpdatedAt: connection.updatedAt, controlPlane: "ti_scale" }),
      });
      expect(offline.status).toBe(503);
      expect(await offline.json()).toMatchObject({ error: { code: "vault_connection_offline" } });
      const offlineSnapshot = await json(await fetch(`${url}/api/v2/brain/vault`, { headers: { "X-Test-Access": "all" } }));
      expect(offlineSnapshot.connections.find((item: { id: string }) => item.id === connectionId)).toMatchObject({
        status: "error",
        pathAvailable: false,
      });
      expect(existsSync(vaultPath)).toBe(false);
      expect(existsSync(offlinePath)).toBe(true);

      const recoveryAudits = database.prepare(`
        SELECT action, details_json FROM audit_records
        WHERE resource_id = ? AND action IN ('vault.repair.completed', 'vault.reindex.completed')
        ORDER BY rowid
      `).all(connectionId) as Array<{ action: string; details_json: string }>;
      expect(recoveryAudits.map((item) => item.action)).toEqual(["vault.repair.completed", "vault.reindex.completed"]);
      expect(recoveryAudits.every((item) => JSON.parse(item.details_json).controlPlane === "ti_scale")).toBe(true);
    } finally {
      database.close();
    }
  });

  test("production router denies retained portable Vault creation and delivery", async () => {
    const { database, directory, url } = await application();
    try {
      const create = await fetch(`${url}/api/v2/brain/vault/portable-export`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "portable-export-disabled-0001",
        },
        body: JSON.stringify({ connectionId: "any-connected-vault" }),
      });
      expect(create.status).toBe(409);
      expect(await json(create)).toMatchObject({
        error: {
          code: "vault_portable_export_disabled",
          category: "policy_denied",
          retryable: false,
        },
      });
      const download = await fetch(
        `${url}/api/v2/brain/vault/portable-exports/any-connected-vault/ti-scale-brain-disabled.zip`,
      );
      expect(download.status).toBe(409);
      expect(await json(download)).toMatchObject({
        error: {
          code: "vault_portable_export_disabled",
          category: "policy_denied",
          retryable: false,
        },
      });
      expect(existsSync(join(directory, "vaults", "any-connected-vault", ".ti-scale", "exports"))).toBe(false);
    } finally {
      database.close();
    }
  });

  test("candidate confirmation and manual correction reject authentication material with safe metadata", async () => {
    const { database, repository, url } = await application();
    try {
      const sessionMaterial = ["session_token", ": ", "unit-test-session-material-123456789"].join("");
      const confirm = await fetch(`${url}/api/v2/brain/candidates/candidate-a/confirm`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "confirm-candidate-secret-denied-0001",
        },
        body: JSON.stringify({ edits: { body: sessionMaterial } }),
      });
      expect(confirm.status).toBe(422);
      const confirmBody = await json(confirm);
      expect(confirmBody).toMatchObject({
        error: {
          code: "sensitive_material_not_retained",
          category: "policy_denied",
          retryable: false,
        },
      });
      expect(JSON.stringify(confirmBody)).not.toContain(sessionMaterial);
      expect(repository.requireCandidate("candidate-a").status).toBe("pending");
      expect(repository.requireCandidate("candidate-a").proposedNodeId).toBeUndefined();

      const current = repository.requireNode("node-a");
      const correct = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "correct-node-secret-denied-0001",
        },
        body: JSON.stringify({
          expectedVersion: current.version,
          body: sessionMaterial,
          reason: "Operator correction",
        }),
      });
      expect(correct.status).toBe(422);
      const correctionBody = await json(correct);
      expect(correctionBody.error.code).toBe("sensitive_material_not_retained");
      expect(JSON.stringify(correctionBody)).not.toContain(sessionMaterial);
      expect(repository.requireNode("node-a")).toMatchObject({ version: current.version, body: current.body });
      expect(repository.listVersions("node-a")).toHaveLength(1);

      const safe = await fetch(`${url}/api/v2/brain/nodes/node-a/correct`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "correct-node-placeholder-safe-0001",
        },
        body: JSON.stringify({
          expectedVersion: current.version,
          body: "Use Authorization: Bearer <TOKEN> and retain only evidence ID evidence-route-001.",
          reason: "Document safe credential indirection",
        }),
      });
      expect(safe.status).toBe(200);
      expect((await json(safe)).node.body).toContain("Bearer <TOKEN>");
    } finally {
      database.close();
    }
  });
});

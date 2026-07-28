import { createHash } from "node:crypto";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2099-07-21T12:30:00.000Z";
const OPERATOR_ID = "e2e-local-operator";

export interface BrainSourceCustodyFixture {
  readonly nodeId: string;
  readonly nodeTitle: string;
  readonly engagementId: string;
  readonly missionId: string;
  readonly missionName: string;
  readonly runId: string;
  readonly artifactId: string;
  readonly evidenceId: string;
  readonly evidenceSummary: string;
  readonly privateSourceReference: string;
  readonly paginationNodeId: string;
  readonly paginationNodeTitle: string;
  readonly paginationSourceCount: number;
  readonly paginationOriginCount: number;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Brain source-custody E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function createBrainSourceCustodyFixture(instanceId: string): BrainSourceCustodyFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const suffix = sha256(namespace).slice(0, 8);
  const engagementId = `eng-source-custody-${namespace}`;
  const missionId = `mission-source-custody-${namespace}`;
  const runId = `run-source-custody-${namespace}`;
  const missionName = `Private source custody fixture ${suffix}`;
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    inImmediateTransaction(database, () => {
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          engagement_id, scope_json, success_criteria_json,
          retention_policy_json, memory_policy_json, created_by, version,
          created_at, updated_at
        ) VALUES (?, ?, ?, 'guided', 'active', 'verified', ?, ?, ?, '{}',
          '{}', ?, 1, ?, ?)
      `).run(
        missionId,
        missionName,
        "Verify access-controlled historical source custody and its canonical navigation links.",
        engagementId,
        JSON.stringify({ allowedTargets: [`lab:source-custody-${suffix}`] }),
        JSON.stringify(["Private provenance remains attributable without becoming reusable attack content"]),
        OPERATOR_ID,
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason,
          next_action_summary, created_at, updated_at, version
        ) VALUES (?, ?, 'guided', 'waiting_guided_decision', 0.5,
          'Private source custody is ready for operator review.',
          'Inspect the canonical mission, run, and evidence relations', ?, ?, 1)
      `).run(runId, missionId, FIXTURE_TIME, FIXTURE_TIME);
    });
    // Reusable attack knowledge deliberately uses an opaque stable identifier;
    // the private operational locator remains only in its access-controlled
    // source/evidence custody projection below.
    const nodeId = `mem_${sha256(`${namespace}:node`)}`;
    const nodeTitle = `Shell procedure artifact ${suffix}`;
    const evidenceId = `evidence-source-custody-${namespace}`;
    const artifactId = `artifact-source-custody-${namespace}`;
    const evidenceSummary = `Verified source custody receipt ${suffix}`;
    const privateSourceReference = `legacy-private-source://source-custody-${suffix}`;
    const sourceId = `source-custody-${namespace}`;
    const repository = new MemoryRepository(database, { clock: () => new Date(FIXTURE_TIME) });
    repository.createNode({
      id: nodeId,
      nodeType: "script_artifact",
      title: nodeTitle,
      summary: "A reusable shell procedure whose private source remains separately attributable.",
      body: "The canonical memory contains only the reusable procedure description; private source identity remains in access-controlled custody metadata.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "confirmed",
      provenance: {
        method: "evidence",
        explanation: "The reusable procedure is linked to an independently verified private source receipt.",
        sources: [{
          sourceType: "attack_knowledge_evidence_binding",
          sourceId,
          sourceHash: sha256(`${namespace}:source`),
          acquiredAt: FIXTURE_TIME,
        }],
      },
      authorType: "operator",
      authorId: OPERATOR_ID,
      retentionPolicy: { allowGuided: true, allowAutonomous: true },
    });
    database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
      ) VALUES (?, ?, ?, 'guided', 'private_source_custody', ?, ?, 128,
        'application/octet-stream', 'private', '{}', ?)
    `).run(
      artifactId,
      missionId,
      runId,
      privateSourceReference,
      sha256(`${namespace}:artifact`),
      FIXTURE_TIME,
    );
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, artifact_id, created_by, created_at
      ) VALUES (?, ?, ?, 'local-hash-review', ?, 'Reusable source', 'artifact', ?, ?, 1,
        'private', 'verified', ?, ?, ?, ?)
    `).run(
      evidenceId,
      missionId,
      runId,
      FIXTURE_TIME,
      sha256(`${namespace}:evidence`),
      JSON.stringify({ sourceReference: privateSourceReference }),
      evidenceSummary,
      artifactId,
      OPERATOR_ID,
      FIXTURE_TIME,
    );
    database.prepare(`
      UPDATE memory_sources
      SET source_type = 'attack_knowledge_evidence_binding', evidence_id = ?,
        mission_id = NULL, run_id = NULL
      WHERE node_id = ? AND source_id = ?
    `).run(evidenceId, nodeId, sourceId);

    const paginationNodeId = `mem_${sha256(`${namespace}:pagination-node`)}`;
    const paginationNodeTitle = `Bounded provenance fixture ${suffix}`;
    const paginationSourceCount = 31;
    const paginationOriginCount = 52;
    repository.createNode({
      id: paginationNodeId,
      nodeType: "script_artifact",
      title: paginationNodeTitle,
      summary: "A canonical memory with enough source and custody records to prove bounded pagination.",
      body: "The complete source count remains truthful while source records and private custody origins load in explicit bounded pages.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "confirmed",
      provenance: {
        method: "evidence",
        explanation: "Every fixture source remains attributable while the browser receives only bounded pages.",
        sources: [{
          sourceType: "pagination_fixture_seed",
          sourceId: `pagination-seed-${namespace}`,
          sourceHash: sha256(`${namespace}:pagination-seed`),
          acquiredAt: FIXTURE_TIME,
        }],
      },
      authorType: "operator",
      authorId: OPERATOR_ID,
      retentionPolicy: { allowGuided: true, allowAutonomous: true },
    });

    const paginationMigrationId = `migration-source-pagination-${namespace}`;
    const paginationCandidateId = `candidate-source-pagination-${namespace}`;
    const paginationImportMissionId = `mission-source-pagination-import-${namespace}`;
    const paginationImportRunId = `run-source-pagination-import-${namespace}`;
    const paginationSourceRecordId = `memory-source-pagination-primary-${namespace}`;
    const paginationSourceHash = sha256(`${namespace}:pagination-source`);
    inImmediateTransaction(database, () => {
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          created_by, created_at, updated_at
        ) VALUES (?, 'Internal provenance pagination import',
          'Fixture-only private source-custody context.', 'guided', 'archived',
          'unverified', 'system:historical-attack-knowledge-import', ?, ?)
      `).run(paginationImportMissionId, FIXTURE_TIME, FIXTURE_TIME);
      database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES (?, ?, 'guided', 'completed', ?, ?)
      `).run(paginationImportRunId, paginationImportMissionId, FIXTURE_TIME, FIXTURE_TIME);
      database.prepare(`
        INSERT INTO historical_attack_knowledge_import_contexts (
          migration_id, mission_id, run_id, created_at
        ) VALUES (?, ?, ?, ?)
      `).run(
        paginationMigrationId,
        paginationImportMissionId,
        paginationImportRunId,
        FIXTURE_TIME,
      );
      database.prepare(`
        INSERT INTO evidence_candidates (
          id, mission_id, run_id, evidence_type, label, meaning,
          promotion_reason, state, sensitivity, proposed_by, created_at
        ) VALUES (?, ?, ?, 'artifact', 'Pagination source fixture',
          'Provides immutable local source custody for bounded browser traversal.',
          'Fixture-only independent review.', 'candidate', 'private',
          'system:historical-attack-knowledge-extractor', ?)
      `).run(
        paginationCandidateId,
        paginationImportMissionId,
        paginationImportRunId,
        FIXTURE_TIME,
      );
      database.prepare(`
        INSERT INTO historical_attack_knowledge_source_candidates (
          candidate_id, source_hash, byte_size, created_at
        ) VALUES (?, ?, 512, ?)
      `).run(paginationCandidateId, paginationSourceHash, FIXTURE_TIME);
      database.prepare(`
        INSERT INTO memory_sources (
          id, node_id, source_type, source_id, mission_id, run_id,
          source_hash, acquired_at, created_at
        ) VALUES (?, ?, 'historical_attack_knowledge_source_candidate', ?, ?, ?, ?, ?, ?)
      `).run(
        paginationSourceRecordId,
        paginationNodeId,
        `${paginationCandidateId}:${paginationMigrationId}`,
        paginationImportMissionId,
        paginationImportRunId,
        paginationSourceHash,
        "2099-07-21T12:31:00.000Z",
        FIXTURE_TIME,
      );

      const insertOrdinarySource = database.prepare(`
        INSERT INTO memory_sources (
          id, node_id, source_type, source_id, source_hash, acquired_at, created_at
        ) VALUES (?, ?, 'pagination_fixture_source', ?, ?, ?, ?)
      `);
      for (let index = 1; index < paginationSourceCount - 1; index += 1) {
        const sourceKey = String(index).padStart(2, "0");
        insertOrdinarySource.run(
          `memory-source-pagination-${sourceKey}-${namespace}`,
          paginationNodeId,
          `pagination-source-${sourceKey}-${namespace}`,
          sha256(`${namespace}:pagination-source:${sourceKey}`),
          new Date(Date.parse(FIXTURE_TIME) - index * 1_000).toISOString(),
          FIXTURE_TIME,
        );
      }

      const insertOccurrence = database.prepare(`
        INSERT INTO historical_attack_knowledge_source_occurrences (
          candidate_id, migration_id, source_reference, source_hash,
          modified_at, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `);
      const insertArtifact = database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, journey, artifact_type, storage_uri,
          content_hash, byte_size, sensitivity, metadata_json, created_at
        ) VALUES (?, ?, ?, 'guided', 'legacy_private_source_custody', ?, ?, 512,
          'restricted', ?, ?)
      `);
      const insertBinding = database.prepare(`
        INSERT INTO historical_private_source_bindings (
          memory_source_id, source_candidate_id, migration_id, source_reference,
          source_hash, mission_id, run_id, artifact_id, binding_method,
          binding_receipt_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'existing_legacy_projection', ?, ?)
      `);
      for (let index = 1; index <= paginationOriginCount; index += 1) {
        const originKey = String(index).padStart(2, "0");
        const sourceReference = `legacy-private-source://pagination-${suffix}-${originKey}`;
        const originArtifactId = `artifact-source-pagination-${namespace}-${originKey}`;
        insertOccurrence.run(
          paginationCandidateId,
          paginationMigrationId,
          sourceReference,
          paginationSourceHash,
          FIXTURE_TIME,
          FIXTURE_TIME,
        );
        insertArtifact.run(
          originArtifactId,
          missionId,
          runId,
          sourceReference,
          paginationSourceHash,
          JSON.stringify({ sourceLocator: `fixture/provenance/source-${originKey}.txt` }),
          FIXTURE_TIME,
        );
        insertBinding.run(
          paginationSourceRecordId,
          paginationCandidateId,
          paginationMigrationId,
          sourceReference,
          paginationSourceHash,
          missionId,
          runId,
          originArtifactId,
          sha256(`${namespace}:pagination-binding:${originKey}`),
          FIXTURE_TIME,
        );
      }
    });

    return {
      nodeId,
      nodeTitle,
      engagementId,
      missionId,
      missionName,
      runId,
      artifactId,
      evidenceId,
      evidenceSummary,
      privateSourceReference,
      paginationNodeId,
      paginationNodeTitle,
      paginationSourceCount,
      paginationOriginCount,
    };
  } finally {
    database.close();
  }
}

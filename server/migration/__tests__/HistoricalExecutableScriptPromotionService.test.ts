import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { AuditTrailWriter } from "../../intelligence-v24/AuditTrailWriter";
import { digestCanonicalJson } from "../../mcp";
import { MemoryRepository, type MemoryNode } from "../../memory";
import {
  MemoryScriptSourceStore,
  ScriptArtifactService,
} from "../../script-artifacts";
import { ConnectedVaultMemoryProjector } from "../../vault/ConnectedVaultMemoryProjector";
import { ObsidianVaultBridge } from "../../vault/ObsidianVaultBridge";
import { VaultPathPolicy } from "../../vault/VaultPathPolicy";
import { HistoricalPrivateSourceCustodyProjectionService } from "../HistoricalPrivateSourceCustodyProjectionService";
import {
  HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_RECEIPT_SCHEMA,
  HistoricalExecutableScriptPromotionError,
  HistoricalExecutableScriptPromotionService,
  type HistoricalExecutableScriptPromotionInput,
  type HistoricalExecutableScriptValidationPort,
} from "../HistoricalExecutableScriptPromotionService";
import { LocalHistoricalExecutableScriptValidator } from "../LocalHistoricalExecutableScriptValidator";

const NOW = new Date("2026-07-23T18:00:00.000Z");
const OPERATOR = "operator:historical-script-reviewer";
const MIGRATION = "migration-historical-script";
const BUNDLE = "bundle-historical-script";
const RECEIPT = "receipt-historical-script";
const SOURCE_CANDIDATE = "candidate-historical-script-source";
const SOURCE_REFERENCE = "legacy-private-source://historical-script";
const IMPORT_MISSION = "mission-historical-script-import";
const IMPORT_RUN = "run-historical-script-import";
const ATTEMPT_MISSION = "mission-historical-script-success";
const ATTEMPT_RUN = "run-historical-script-success";
const ATTEMPT = "attempt-historical-script-success";
const SUCCESS_EVIDENCE = "evidence-historical-script-success";
const SOURCE_EVIDENCE = "evidence-historical-script-source";
const memoryId = (value: string): string =>
  `mem_${createHash("sha256").update(value, "utf8").digest("hex")}`;
const SCRIPT = memoryId("historical-script");
const PROCEDURE = memoryId("historical-procedure");
const PRODUCT = memoryId("historical-product");
const VERSION = memoryId("historical-version");
const CVE = memoryId("historical-cve");
const SOURCE = [
  "import argparse",
  "parser = argparse.ArgumentParser()",
  "parser.add_argument('--target', required=True)",
  "target = parser.parse_args().target",
  "print({'target': target, 'validated': True})",
  "",
].join("\n");
const SOURCE_HASH = createHash("sha256").update(SOURCE, "utf8").digest("hex");
const databases: SqliteDatabase[] = [];
const directories: string[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function insertMissionRun(
  database: SqliteDatabase,
  missionId: string,
  runId: string,
  options: {
    readonly journey: "guided" | "autonomous";
    readonly missionStatus: "active" | "archived" | "completed";
    readonly runStatus: "running" | "completed";
    readonly createdBy: string;
  },
): void {
  const now = NOW.toISOString();
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      scope_json, success_criteria_json, retention_policy_json,
      memory_policy_json, created_by, version, created_at, updated_at,
      control_plane
    ) VALUES (?, 'Historical script fixture', 'Local fixture only', ?, ?,
      'unverified', '{}', '[]', '{}', '{}', ?, 1, ?, ?, 'ti_scale')
  `).run(
    missionId,
    options.journey,
    options.missionStatus,
    options.createdBy,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      next_action_summary, budget_json, budget_usage_json, retry_count,
      replan_count, started_at, ended_at, created_at, updated_at, version,
      control_plane
    ) VALUES (?, ?, ?, ?, 1, 'Fixture terminal state', 'No action', '{}',
      '{}', 0, 0, ?, ?, ?, ?, 1, 'ti_scale')
  `).run(
    runId,
    missionId,
    options.journey,
    options.runStatus,
    now,
    options.runStatus === "completed" ? now : null,
    now,
    now,
  );
}

function memoryNode(
  repository: MemoryRepository,
  id: string,
  nodeType: MemoryNode["nodeType"],
  title: string,
  body = "{}",
): MemoryNode {
  return repository.createNode({
    id,
    nodeType,
    title,
    summary: `Verified historical ${title}.`,
    body,
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.99,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Operator-confirmed historical bundle fixture.",
      sources: [{
        sourceType: "private_receipt",
        sourceId: `${BUNDLE}:${id}`,
        sourceHash: SOURCE_HASH,
        acquiredAt: NOW.toISOString(),
      }],
    },
    authorType: "operator",
    authorId: OPERATOR,
    retentionPolicy: { allowAutonomous: true, journeys: ["autonomous"] },
  });
}

function insertEdge(
  database: SqliteDatabase,
  ordinal: number,
  source: string,
  edgeType: string,
  target: string,
): void {
  const id = `edge-historical-script-${ordinal}`;
  database.prepare(`
    INSERT INTO memory_edges (
      id, source_node_id, target_node_id, edge_type, title, summary, scope,
      sensitivity, confidence, lifecycle_status, provenance_json, explanation,
      author_type, author_id, version, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'Verified historical binding',
      'Exact source-bundle relationship', 'global', 'internal', 1,
      'verified', '{}', 'Operator-reviewed exact relationship',
      'operator', ?, 1, ?, ?)
  `).run(id, source, target, edgeType, OPERATOR, NOW.toISOString(), NOW.toISOString());
  database.prepare(`
    INSERT INTO attack_knowledge_bundle_edges (
      bundle_id, edge_key, source_role, target_role, edge_type,
      materialized_edge_id, materialized_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    BUNDLE,
    `edge-key-${ordinal}`,
    `source-role-${ordinal}`,
    `target-role-${ordinal}`,
    edgeType,
    id,
    NOW.toISOString(),
  );
}

function fixture(): Readonly<{
  database: SqliteDatabase;
  service: HistoricalExecutableScriptPromotionService;
  input: HistoricalExecutableScriptPromotionInput;
  sourcePath: string;
  projectedNodeIds: string[][];
  vaultPath: string;
}> {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  insertMissionRun(database, IMPORT_MISSION, IMPORT_RUN, {
    journey: "guided",
    missionStatus: "archived",
    runStatus: "completed",
    createdBy: "system:historical-attack-knowledge-import",
  });
  insertMissionRun(database, ATTEMPT_MISSION, ATTEMPT_RUN, {
    journey: "autonomous",
    missionStatus: "completed",
    runStatus: "completed",
    createdBy: OPERATOR,
  });
  database.prepare(`
    INSERT INTO historical_attack_knowledge_import_contexts (
      migration_id, mission_id, run_id, created_at
    ) VALUES (?, ?, ?, ?)
  `).run(MIGRATION, IMPORT_MISSION, IMPORT_RUN, NOW.toISOString());

  const directory = mkdtempSync(join(tmpdir(), "ti-scale-historical-script-"));
  directories.push(directory);
  const sourcePath = join(directory, "reviewed_validation.py");
  writeFileSync(sourcePath, SOURCE, { mode: 0o600 });
  const stat = statSync(sourcePath);
  const sourceType = "generic_file";
  const sourceIdentity = sha256(`${sourceType}\0${sourcePath}`);
  database.prepare(`
    INSERT INTO legacy_migration_runs (
      id, status, source_roots_json, database_path, output_directory,
      source_retention, source_retention_acknowledged_at,
      brain_projection_mode, brain_projection_acknowledged_at,
      started_at, completed_at
    ) VALUES (?, 'completed', '[]', ':memory:', '/tmp',
      'verified-reference', ?, 'attack-knowledge-only', ?, ?, ?)
  `).run(MIGRATION, NOW.toISOString(), NOW.toISOString(), NOW.toISOString(), NOW.toISOString());
  database.prepare(`
    INSERT INTO legacy_migration_sources (
      id, migration_id, source_path, relative_path, source_type,
      source_identity, source_sha256, byte_size, modified_at,
      source_reference, source_retention, source_device, source_inode,
      verified_at, status, discovered_at, completed_at
    ) VALUES ('source-historical-script', ?, ?, 'reviewed_validation.py', ?,
      ?, ?, ?, ?, ?, 'verified-reference', ?, ?, ?, 'completed', ?, ?)
  `).run(
    MIGRATION,
    sourcePath,
    sourceType,
    sourceIdentity,
    SOURCE_HASH,
    stat.size,
    stat.mtime.toISOString(),
    SOURCE_REFERENCE,
    Number(stat.dev),
    Number(stat.ino),
    NOW.toISOString(),
    NOW.toISOString(),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO legacy_migration_source_objects (
      id, migration_id, source_id, object_key, source_reference, source_path,
      object_kind, classification, source_sha256, byte_size, modified_at,
      source_device, source_inode, verification_status, verified_at
    ) VALUES ('source-object-historical-script', ?,
      'source-historical-script', 'source', ?, ?, 'source', 'script',
      ?, ?, ?, ?, ?, 'verified_reference', ?)
  `).run(
    MIGRATION,
    SOURCE_REFERENCE,
    sourcePath,
    SOURCE_HASH,
    stat.size,
    stat.mtime.toISOString(),
    Number(stat.dev),
    Number(stat.ino),
    NOW.toISOString(),
  );

  database.prepare(`
    INSERT INTO evidence_candidates (
      id, mission_id, run_id, evidence_type, label, meaning,
      promotion_reason, validation_requirements_json, state, sensitivity,
      proposed_by, created_at
    ) VALUES (?, ?, ?, 'historical_source', 'Private source custody',
      'Exact source hash', 'Operator review', '[]', 'candidate', 'private',
      'system:historical-attack-knowledge-extractor', ?)
  `).run(SOURCE_CANDIDATE, IMPORT_MISSION, IMPORT_RUN, NOW.toISOString());
  database.prepare(`
    INSERT INTO historical_attack_knowledge_source_candidates (
      candidate_id, source_hash, byte_size, created_at
    ) VALUES (?, ?, ?, ?)
  `).run(SOURCE_CANDIDATE, SOURCE_HASH, stat.size, NOW.toISOString());
  database.prepare(`
    INSERT INTO historical_attack_knowledge_source_occurrences (
      candidate_id, migration_id, source_reference, source_hash,
      modified_at, observed_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    SOURCE_CANDIDATE,
    MIGRATION,
    SOURCE_REFERENCE,
    SOURCE_HASH,
    stat.mtime.toISOString(),
    NOW.toISOString(),
  );

  database.prepare(`
    INSERT INTO attack_knowledge_bundles (
      id, semantic_fingerprint, sanitized_bundle_json, status,
      exact_procedure_attempt_count, exact_procedure_reproducibility_count,
      exact_procedure_evidence_count, first_observed_at, last_observed_at,
      materialized_at, created_at, updated_at
    ) VALUES (?, ?, '{"kind":"reusable_bundle"}', 'materialized',
      1, 1, 1, ?, ?, ?, ?, ?)
  `).run(
    BUNDLE,
    sha256(BUNDLE),
    NOW.toISOString(),
    NOW.toISOString(),
    NOW.toISOString(),
    NOW.toISOString(),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO attack_knowledge_provenance_receipts (
      id, source_class, source_hash, evidence_count, observed_at, created_at
    ) VALUES (?, 'historical', ?, 1, ?, ?)
  `).run(RECEIPT, SOURCE_HASH, NOW.toISOString(), NOW.toISOString());
  database.prepare(`
    INSERT INTO attack_knowledge_bundle_receipts (
      bundle_id, receipt_id, exact_procedure_attempt_count,
      exact_procedure_reproducibility_count, exact_procedure_evidence_count,
      linked_at
    ) VALUES (?, ?, 1, 1, 1, ?)
  `).run(BUNDLE, RECEIPT, NOW.toISOString());
  database.prepare(`
    INSERT INTO historical_attack_knowledge_bundle_sources (
      bundle_id, receipt_id, candidate_id, source_hash, binding_hash, linked_at
    ) VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    BUNDLE,
    RECEIPT,
    SOURCE_CANDIDATE,
    SOURCE_HASH,
    sha256(`${BUNDLE}:${SOURCE_HASH}`),
    NOW.toISOString(),
  );

  const repository = new MemoryRepository(database, { clock: () => NOW });
  const nodes = [
    memoryNode(
      repository,
      SCRIPT,
      "script_artifact",
      "Python validation procedure",
      JSON.stringify({ language: "python", contentHash: SOURCE_HASH }),
    ),
    memoryNode(repository, PROCEDURE, "attack_procedure", "Bounded CVE validation"),
    memoryNode(repository, PRODUCT, "technology_product", "Apache HTTP Server"),
    memoryNode(repository, VERSION, "exact_version_fingerprint", "Apache HTTP Server 2.4.58"),
    memoryNode(repository, CVE, "cve", "CVE-2024-0001"),
  ];
  for (const [ordinal, node] of nodes.entries()) {
    const candidateId = `memory-candidate-historical-${ordinal}`;
    const fingerprint = sha256(`candidate:${ordinal}`);
    database.prepare(`
      INSERT INTO memory_candidates (
        id, proposed_node_id, candidate_type, title, summary, body,
        proposed_scope, sensitivity, confidence, source_json, status,
        proposed_by, reviewed_by, reviewed_at, created_at
      ) VALUES (?, ?, ?, ?, ?, '{}', 'global', 'internal', 1, '{}',
        'confirmed', 'system:test', ?, ?, ?)
    `).run(
      candidateId,
      node.id,
      node.nodeType,
      node.title,
      node.summary,
      OPERATOR,
      NOW.toISOString(),
      NOW.toISOString(),
    );
    database.prepare(`
      INSERT INTO attack_knowledge_candidate_registry (
        content_fingerprint, candidate_id, node_type, created_at
      ) VALUES (?, ?, ?, ?)
    `).run(fingerprint, candidateId, node.nodeType, NOW.toISOString());
    database.prepare(`
      INSERT INTO attack_knowledge_bundle_candidates (
        bundle_id, role, content_fingerprint, required, ordinal, linked_at
      ) VALUES (?, ?, ?, 1, ?, ?)
    `).run(BUNDLE, `role-${ordinal}`, fingerprint, ordinal, NOW.toISOString());
  }
  [
    [PROCEDURE, "implemented_by", SCRIPT],
    [PROCEDURE, "exploits", CVE],
    [PROCEDURE, "tested_against", PRODUCT],
    [PROCEDURE, "tested_against", VERSION],
    [PRODUCT, "has_exact_version", VERSION],
    [CVE, "affects", PRODUCT],
    [CVE, "affects", VERSION],
  ].forEach(([source, edgeType, target], ordinal) => {
    insertEdge(database, ordinal, source!, edgeType!, target!);
  });

  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, evidence_type,
      content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES (?, ?, ?, 'local:historical-review', ?, 'file_artifact', ?,
      '{"method":"operator_hash_review"}', 1, 'private', 'verified',
      'Exact historical script source was reviewed.', ?, ?)
  `).run(
    SOURCE_EVIDENCE,
    IMPORT_MISSION,
    IMPORT_RUN,
    NOW.toISOString(),
    SOURCE_HASH,
    OPERATOR,
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES ('custody-historical-source', ?, 'verified', ?, '{}', ?)
  `).run(SOURCE_EVIDENCE, OPERATOR, NOW.toISOString());
  const sourceAudit = new AuditTrailWriter(database).append({
    missionId: IMPORT_MISSION,
    runId: IMPORT_RUN,
    actor: { id: OPERATOR, type: "operator" },
    action: "historical_attack_source.verified",
    resourceType: "evidence_candidate",
    resourceId: SOURCE_CANDIDATE,
    reason: "Reviewed exact source hash for local-only historical promotion.",
    details: { sourceHash: SOURCE_HASH },
    occurredAt: NOW.toISOString(),
  });
  database.prepare(`
    UPDATE evidence_candidates SET state = 'promoted', reviewed_by = ?,
      review_reason = 'Exact operator hash review',
      promoted_evidence_id = ?, reviewed_at = ?
    WHERE id = ?
  `).run(OPERATOR, SOURCE_EVIDENCE, NOW.toISOString(), SOURCE_CANDIDATE);
  database.prepare(`
    INSERT INTO historical_attack_knowledge_verified_bundle_links (
      bundle_id, receipt_id, candidate_id, evidence_id, source_hash,
      verification_audit_id, verified_by, verified_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    BUNDLE,
    RECEIPT,
    SOURCE_CANDIDATE,
    SOURCE_EVIDENCE,
    SOURCE_HASH,
    sourceAudit,
    OPERATOR,
    NOW.toISOString(),
  );
  const memorySourceId = "msrc_historical_script_source";
  database.prepare(`
    INSERT INTO memory_sources (
      id, node_id, source_type, source_id, source_hash, acquired_at, created_at
    ) VALUES (?, ?, 'historical_attack_knowledge_source_candidate',
      ?, ?, ?, ?)
  `).run(
    memorySourceId,
    SCRIPT,
    `${SOURCE_CANDIDATE}:${MIGRATION}`,
    SOURCE_HASH,
    NOW.toISOString(),
    NOW.toISOString(),
  );
  new HistoricalPrivateSourceCustodyProjectionService(
    database,
    { clock: () => NOW },
  ).bind({
    memorySourceId,
    sourceCandidateId: SOURCE_CANDIDATE,
    migrationId: MIGRATION,
    sourceReference: SOURCE_REFERENCE,
    sourceHash: SOURCE_HASH,
  });

  database.prepare(`
    INSERT INTO attack_attempts (
      id, mission_id, run_id, objective, technique_name, action_class,
      prerequisites_json, normalized_parameters_json, status,
      outcome_summary, started_at, ended_at, created_at, updated_at, version
    ) VALUES (?, ?, ?, 'Validate exact historical CVE procedure',
      'Bounded CVE validation', 'exploit_validation', '[]', '{}',
      'succeeded', 'The exact procedure produced the expected proof.', ?,
      ?, ?, ?, 1)
  `).run(
    ATTEMPT,
    ATTEMPT_MISSION,
    ATTEMPT_RUN,
    NOW.toISOString(),
    NOW.toISOString(),
    NOW.toISOString(),
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, evidence_type,
      content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES (?, ?, ?, 'local:attempt-evaluator', ?, 'exploit_validation',
      ?, '{"method":"local_verified_attempt"}', 1, 'internal', 'verified',
      'The exact procedure succeeded.', ?, ?)
  `).run(
    SUCCESS_EVIDENCE,
    ATTEMPT_MISSION,
    ATTEMPT_RUN,
    NOW.toISOString(),
    sha256("successful-attempt-proof"),
    OPERATOR,
    NOW.toISOString(),
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES ('custody-historical-success', ?, 'verified', ?, '{}', ?)
  `).run(SUCCESS_EVIDENCE, OPERATOR, NOW.toISOString());
  database.prepare(`
    INSERT INTO attack_attempt_evidence (
      attack_attempt_id, evidence_id, relationship, created_at
    ) VALUES (?, ?, 'outcome', ?)
  `).run(ATTEMPT, SUCCESS_EVIDENCE, NOW.toISOString());
  database.prepare(`
    INSERT INTO attack_attempt_knowledge_contexts (
      attack_attempt_id, procedure_node_id, product_node_ids_json,
      version_node_ids_json, stack_node_ids_json,
      prerequisite_node_ids_json, observed_state_node_ids_json,
      normalized_parameters_json, created_at, updated_at
    ) VALUES (?, ?, ?, ?, '[]', '[]', '[]', '{}', ?, ?)
  `).run(
    ATTEMPT,
    PROCEDURE,
    JSON.stringify([PRODUCT]),
    JSON.stringify([VERSION]),
    NOW.toISOString(),
    NOW.toISOString(),
  );
  const outcomeId = "outcome-link-historical-success";
  const outcomeAudit = new AuditTrailWriter(database).append({
    missionId: ATTEMPT_MISSION,
    runId: ATTEMPT_RUN,
    actor: { id: OPERATOR, type: "operator" },
    action: "reusable_knowledge.outcome_classified",
    resourceType: "reusable_knowledge_outcome_link",
    resourceId: outcomeId,
    reason: "Verified exact historical procedure success.",
    details: { procedureNodeId: PROCEDURE },
    occurredAt: NOW.toISOString(),
  });
  const auditHash = (database.prepare(
    "SELECT record_hash FROM audit_records WHERE id = ?",
  ).get(outcomeAudit) as { readonly record_hash: string }).record_hash;
  database.prepare(`
    INSERT INTO reusable_knowledge_outcome_links (
      id, memory_node_id, attack_attempt_id, evidence_id, outcome_tag,
      actor_id, reason, audit_record_id, audit_record_hash, created_at
    ) VALUES (?, ?, ?, ?, 'success', ?,
      'Verified exact historical procedure success.', ?, ?, ?)
  `).run(
    outcomeId,
    PROCEDURE,
    ATTEMPT,
    SUCCESS_EVIDENCE,
    OPERATOR,
    outcomeAudit,
    auditHash,
    NOW.toISOString(),
  );

  const scripts = new ScriptArtifactService(
    database,
    new MemoryScriptSourceStore(),
    () => NOW,
  );
  const validator: HistoricalExecutableScriptValidationPort = {
    validate: async (request) => {
      expect(request).toMatchObject({
        sourceHash: SOURCE_HASH,
        source: SOURCE,
        language: "python",
        publicProvider: false,
        targetContact: false,
        sourceExecution: false,
      });
      const material = {
        schemaVersion: HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_RECEIPT_SCHEMA,
        receiptId: "validation-historical-script",
        bundleId: request.bundleId,
        migrationId: request.migrationId,
        sourceCandidateId: request.sourceCandidateId,
        sourceHash: request.sourceHash,
        language: request.language,
        validatorBindingId: "reviewed-python:nonexecuting-ast-v1",
        tests: [{
          name: "Exact source continuity",
          status: "passed" as const,
          summary: "Hash matched.",
        }, {
          name: "Non-executing syntax validation",
          status: "passed" as const,
          summary: "Syntax parsed without executing source.",
        }],
        publicProvider: false as const,
        targetContact: false as const,
        sourceExecution: false as const,
        isolatedLocalValidation: true as const,
        validatedAt: NOW.toISOString(),
      };
      return {
        ...material,
        receiptHash: digestCanonicalJson(
          material,
          { maxBytes: 1_048_576, maxDepth: 24 },
        ).sha256,
      };
    },
  };
  const vaultRoot = join(directory, "vaults");
  const bridge = new ObsidianVaultBridge(
    database,
    new MemoryRepository(database, { clock: () => NOW }),
    new VaultPathPolicy(vaultRoot),
    { clock: () => NOW },
  );
  const connection = bridge.connect({
    id: "vault-historical-script",
    vaultPath: "Ti-Scale-Brain",
    displayName: "Historical script Vault",
    syncScope: {
      sensitivities: ["internal", "private"],
      lifecycleStatuses: ["verified"],
    },
    permissionGranted: true,
  });
  const realVaultProjector = new ConnectedVaultMemoryProjector(
    database,
    bridge,
    { clock: () => NOW },
  );
  const projectedNodeIds: string[][] = [];
  const service = new HistoricalExecutableScriptPromotionService({
    database,
    scripts,
    validator,
    vaultProjector: {
      project: (nodeIds) => {
        expect(database.inTransaction).toBe(false);
        projectedNodeIds.push([...nodeIds]);
        return realVaultProjector.project(nodeIds);
      },
    },
    clock: () => NOW,
  });
  const input: HistoricalExecutableScriptPromotionInput = {
    actorId: OPERATOR,
    reason: "Promote exact reviewed source for byte-identical local reuse.",
    selection: {
      bundleId: BUNDLE,
      sourceCandidateId: SOURCE_CANDIDATE,
      migrationId: MIGRATION,
      sourceReference: SOURCE_REFERENCE,
      expectedSourceHash: SOURCE_HASH,
      scriptNodeId: SCRIPT,
      procedureNodeId: PROCEDURE,
      productNodeId: PRODUCT,
      versionNodeId: VERSION,
      cveNodeId: CVE,
    },
    documentation: {
      name: "reviewed_validation.py",
      language: "python",
      laymanExplanation: "Checks one already-confirmed issue against the exact target supplied at execution time.",
      technicalPurpose: "Perform a bounded deterministic CVE validation with no persistent target change.",
      inputs: [{
        name: "target",
        description: "One exact operator-authorized target supplied by the runtime.",
        required: true,
        sensitivity: "ordinary",
      }],
      expectedOutputs: [{
        label: "Validation result",
        description: "Structured confirmation from the bounded validation path.",
        successRecognition: "The expected validated marker is present.",
        failureRecognition: "The process fails or the marker is absent.",
      }],
      prerequisites: ["Exact product, version, and CVE applicability are independently verified."],
      dependencies: ["Reviewed Python interpreter binding"],
      touches: {
        files: [],
        network: ["One exact operator-authorized target parameter"],
        services: [],
      },
      sideEffects: ["One bounded validation request may reach the exact target only after runtime authorization."],
      riskClass: "medium",
      reversibility: "No persistent state is written by the reviewed procedure.",
      cleanupNotes: "No cleanup is expected; stop if the target changes state.",
      secretsHandling: "No credentials, tokens, or secrets are accepted or embedded.",
      evidenceExpectations: ["Retain the attributable exact-target validation receipt."],
      sensitivity: "private",
    },
  };
  return {
    database,
    service,
    input,
    sourcePath,
    projectedNodeIds,
    vaultPath: connection.vaultPath,
  };
}

describe("HistoricalExecutableScriptPromotionService", () => {
  test("promotes only an explicitly fenced byte-identical, exact-bound, previously successful source and replays idempotently", async () => {
    const value = fixture();
    expect(value.service.listEligibility()).toMatchObject({
      historicalScriptNodeCount: 1,
      languageCounts: { python: 1 },
      exactBoundVerifiedSuccessCount: 1,
      executableByCurrentRuntimeCount: 1,
      custodiedScripts: [{
        scriptNodeId: SCRIPT,
        language: "python",
        sourceHash: SOURCE_HASH,
        executableByCurrentRuntime: true,
        exactBoundVerifiedSuccessEligible: true,
        reasonCategories: [],
      }],
      entries: [{
        language: "python",
        executableByCurrentRuntime: true,
        selection: {
          scriptNodeId: SCRIPT,
          procedureNodeId: PROCEDURE,
          productNodeId: PRODUCT,
          versionNodeId: VERSION,
          cveNodeId: CVE,
        },
      }],
    });
    const preview = value.service.preview(value.input);
    expect(preview).toMatchObject({
      sourceHash: SOURCE_HASH,
      source: SOURCE,
      destinationMissionId: IMPORT_MISSION,
      destinationRunId: IMPORT_RUN,
      successfulAttemptId: ATTEMPT,
      successEvidenceId: SUCCESS_EVIDENCE,
      executableByCurrentRuntime: true,
      publicProvider: false,
      targetContact: false,
      sourceExecution: false,
    });
    const fence = {
      expectedPreviewHash: preview.previewHash,
      expectedSourceHash: preview.sourceHash,
      reviewedExactSourceAndBindings: true as const,
      acknowledgedNoAutomaticExecution: true as const,
    };
    const promoted = await value.service.promote(value.input, fence);
    expect(promoted.status).toBe("promoted");
    expect(promoted.scriptArtifact).toMatchObject({
      missionId: IMPORT_MISSION,
      runId: IMPORT_RUN,
      contentHash: SOURCE_HASH,
      source: SOURCE,
      validation: {
        state: "approved",
        testArtifactId: promoted.validationArtifactId,
      },
    });
    expect(promoted).toMatchObject({
      vaultProjection: {
        complete: true,
        attempted: 1,
        synchronized: 1,
      },
      publicProvider: false,
      targetContactDuringPromotion: false,
      sourceExecutedDuringPromotion: false,
    });
    expect(typeof promoted.provenanceSourceId).toBe("string");
    expect(typeof promoted.provenanceAuditId).toBe("string");
    const replay = await value.service.promote(value.input, fence);
    expect(replay.status).toBe("replayed");
    expect(replay.scriptArtifact.id).toBe(promoted.scriptArtifact.id);
    expect(replay.provenanceSourceId).toBe(promoted.provenanceSourceId);
    expect(replay.provenanceAuditId).toBe(promoted.provenanceAuditId);
    expect(value.projectedNodeIds).toEqual([[SCRIPT], [SCRIPT]]);
    expect(value.database.prepare(
      "SELECT COUNT(*) AS count FROM script_artifacts",
    ).get()).toEqual({ count: 1 });
    expect(value.database.prepare(`
      SELECT COUNT(*) AS count FROM artifacts
      WHERE artifact_type = 'script_test_result'
    `).get()).toEqual({ count: 1 });
    expect(value.database.prepare(`
      SELECT actor_type, actor_id, action FROM audit_records
      WHERE id = ?
    `).get(promoted.promotionAuditId)).toEqual({
      actor_type: "operator",
      actor_id: OPERATOR,
      action: "historical_executable_script.promoted",
    });
    expect(value.database.prepare(`
      SELECT id, node_id, source_type, source_id, mission_id, run_id,
        evidence_id, source_hash
      FROM memory_sources WHERE id = ?
    `).get(promoted.provenanceSourceId)).toEqual({
      id: promoted.provenanceSourceId,
      node_id: SCRIPT,
      source_type: "script_artifact",
      source_id: promoted.scriptArtifact.id,
      mission_id: IMPORT_MISSION,
      run_id: IMPORT_RUN,
      evidence_id: null,
      source_hash: SOURCE_HASH,
    });
    expect(value.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_sources
      WHERE node_id = ? AND source_type = 'script_artifact'
        AND source_id = ?
    `).get(SCRIPT, promoted.scriptArtifact.id)).toEqual({ count: 1 });
    expect(value.database.prepare(`
      SELECT actor_type, actor_id, action FROM audit_records
      WHERE id = ?
    `).get(promoted.provenanceAuditId)).toEqual({
      actor_type: "operator",
      actor_id: OPERATOR,
      action: "historical_executable_script.provenance_bound",
    });
    const projection = value.database.prepare(`
      SELECT relative_path, status FROM vault_sync_state
      WHERE connection_id = 'vault-historical-script' AND node_id = ?
    `).get(SCRIPT) as { readonly relative_path: string; readonly status: string };
    expect(projection.status).toBe("synced");
    expect(existsSync(join(value.vaultPath, projection.relative_path))).toBe(true);
  });

  test("rejects stale review fences, non-runtime languages, missing canonical success, and source-byte drift without writes", async () => {
    const stale = fixture();
    const stalePreview = stale.service.preview(stale.input);
    await expect(stale.service.promote(stale.input, {
      expectedPreviewHash: "f".repeat(64),
      expectedSourceHash: stalePreview.sourceHash,
      reviewedExactSourceAndBindings: true,
      acknowledgedNoAutomaticExecution: true,
    })).rejects.toMatchObject({ code: "historical_script_operator_fence_invalid" });

    const shell = fixture();
    expect(() => shell.service.preview({
      ...shell.input,
      documentation: {
        ...shell.input.documentation,
        name: "reviewed_validation.sh",
        language: "bash",
      },
    })).toThrow("current production execution gate supports only");

    const noSuccess = fixture();
    noSuccess.database.exec("DROP TRIGGER reusable_knowledge_outcomes_no_delete");
    noSuccess.database.prepare(
      "DELETE FROM reusable_knowledge_outcome_links WHERE memory_node_id = ?",
    ).run(PROCEDURE);
    expect(() => noSuccess.service.preview(noSuccess.input))
      .toThrow("no canonical prior successful attempt");

    const drift = fixture();
    writeFileSync(drift.sourcePath, `${SOURCE}# changed\n`, { mode: 0o600 });
    expect(() => drift.service.preview(drift.input))
      .toThrow("device, inode, size");
    expect(drift.database.prepare(
      "SELECT COUNT(*) AS count FROM script_artifacts",
    ).get()).toEqual({ count: 0 });
  });

  test("blocks promotion without an active Vault and rejects provenance drift on replay", async () => {
    const noVault = fixture();
    noVault.database.prepare(`
      UPDATE vault_connections SET status = 'disconnected'
      WHERE id = 'vault-historical-script'
    `).run();
    const noVaultPreview = noVault.service.preview(noVault.input);
    await expect(noVault.service.promote(noVault.input, {
      expectedPreviewHash: noVaultPreview.previewHash,
      expectedSourceHash: noVaultPreview.sourceHash,
      reviewedExactSourceAndBindings: true,
      acknowledgedNoAutomaticExecution: true,
    })).rejects.toMatchObject({
      code: "historical_script_connected_vault_required",
    });
    expect(noVault.database.prepare(
      "SELECT COUNT(*) AS count FROM script_artifacts",
    ).get()).toEqual({ count: 0 });

    const drift = fixture();
    const preview = drift.service.preview(drift.input);
    const fence = {
      expectedPreviewHash: preview.previewHash,
      expectedSourceHash: preview.sourceHash,
      reviewedExactSourceAndBindings: true as const,
      acknowledgedNoAutomaticExecution: true as const,
    };
    const promoted = await drift.service.promote(drift.input, fence);
    drift.database.prepare(`
      UPDATE memory_sources SET source_hash = ?
      WHERE id = ?
    `).run("f".repeat(64), promoted.provenanceSourceId);
    await expect(drift.service.promote(drift.input, fence)).rejects.toMatchObject({
      code: "historical_script_canonical_provenance_conflict",
    });
    expect(drift.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_sources
      WHERE node_id = ? AND source_type = 'script_artifact'
        AND source_id = ?
    `).get(SCRIPT, promoted.scriptArtifact.id)).toEqual({ count: 1 });
  });
});

describe("LocalHistoricalExecutableScriptValidator", () => {
  test("parses syntax without executing the historical program and rejects malformed source", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-script-noexec-"));
    directories.push(directory);
    const marker = join(directory, "must-not-exist");
    const source = `from pathlib import Path\nPath(${JSON.stringify(marker)}).write_text('executed')\n`;
    const hash = sha256(source);
    const validator = new LocalHistoricalExecutableScriptValidator({
      clock: () => NOW,
    });
    const request = {
      schemaVersion: "ti-scale.historical-executable-script-validation.v1" as const,
      bundleId: BUNDLE,
      migrationId: MIGRATION,
      sourceCandidateId: SOURCE_CANDIDATE,
      sourceReference: SOURCE_REFERENCE,
      sourceHash: hash,
      source,
      language: "python" as const,
      publicProvider: false as const,
      targetContact: false as const,
      sourceExecution: false as const,
    };
    const receipt = await validator.validate(request);
    expect(receipt.tests.every(({ status }) => status === "passed")).toBe(true);
    expect(Bun.file(marker).size).toBe(0);
    await expect(validator.validate({
      ...request,
      source: "def broken(:\n",
      sourceHash: sha256("def broken(:\n"),
    })).rejects.toMatchObject({
      code: "historical_script_local_syntax_validation_failed",
    });
  });
});

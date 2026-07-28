import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { MemoryRepository } from "../../memory";
import {
  AttackKnowledgeCompiler,
  AttackKnowledgePromotionService,
} from "../../migration";
import { canonicalJson } from "../../orchestration/serialization";
import {
  AutonomousRecoveryPolicyProjector,
  structuredFailureMode,
  structuredOperationalHazardBody,
} from "../AutonomousRecoveryPolicyProjector";

const NOW = "2026-07-23T12:00:00.000Z";
const databases: SqliteDatabase[] = [];
const directories: string[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) =>
    rmSync(directory, { recursive: true, force: true }));
});

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function seedBase(database: SqliteDatabase): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (
      'mission-recovery-projection', 'Recovery projection fixture',
      'Verify bounded recovery projection', 'autonomous', 'completed',
      'verified', '{}', 'operator', ?, ?, 'ti_scale'
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version, control_plane
    ) VALUES (
      'run-recovery-projection', 'mission-recovery-projection', 'autonomous',
      'completed', 1, 'Fixture complete', '{}', '{}', ?, ?, 1, 'ti_scale'
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, target, evidence_type,
      content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES (
      'evidence-recovery-projection', 'mission-recovery-projection',
      'run-recovery-projection', 'trusted-local-evaluator', ?, 'redacted',
      'finding_reproduction', ?, '{"method":"local_evaluator"}', 1,
      'internal', 'verified', 'Verified reusable failure evidence',
      'local-evidence-verifier', ?
    )
  `).run(NOW, "e".repeat(64), NOW);
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES (
      'custody-recovery-projection', 'evidence-recovery-projection',
      'verified', 'local-evidence-verifier', '{}', ?
    )
  `).run(NOW);
}

function stageAndPromote(
  database: SqliteDatabase,
  failureMode: string,
): Readonly<{ procedureNodeId: string; failureNodeId: string }> {
  const clock = () => new Date(NOW);
  const compiler = new AttackKnowledgeCompiler(database, {
    receiptHmacKey: "recovery-policy-projector-test-hmac-key-32-bytes",
    clock,
  });
  const memory = new MemoryRepository(database, { clock });
  const compiled = compiler.compile({
    source: {
      privateSourceReference: "protected:test-recovery-source",
      sourceClass: "current",
      sourceHash: "a".repeat(64),
      observedAt: NOW,
      evidenceCount: 1,
      canonicalEvidenceIds: ["evidence-recovery-projection"],
    },
    knowledge: {
      kind: "reusable_bundle",
      facts: [
        {
          role: "procedure",
          nodeType: "attack_procedure",
          title: "Bounded exact diagnostic",
          summary: "A bounded reusable diagnostic procedure.",
          body: canonicalJson({
            procedureVersion: "v1",
            orderedSequence: ["Run one bounded diagnostic"],
            normalizedBoundedParameters: { retries: 0 },
          }),
        },
        {
          role: "outcome",
          nodeType: "outcome",
          title: "Diagnostic timed out",
          summary: "The bounded diagnostic reached its timeout.",
          body: canonicalJson({
            reportedStatus: "failed",
            outcomeClassification: "unclassified",
            classificationBasis: "compiler_report_only",
          }),
        },
        {
          role: "failure",
          nodeType: "failure_mode",
          title: "Structured failure record",
          summary: "A structured failure mode from verified evidence.",
          body: canonicalJson({ failureMode }),
        },
      ],
      edges: [
        {
          sourceRole: "procedure",
          edgeType: "produces_outcome",
          targetRole: "outcome",
        },
        {
          sourceRole: "outcome",
          edgeType: "failed_because",
          targetRole: "failure",
        },
      ],
    },
    confidence: 0.98,
  });
  if (!compiled.bundleId || !compiled.bundleFingerprint) {
    throw new Error(`Attack-knowledge fixture failed: ${compiled.reasonCategories?.join(",")}`);
  }
  const nodes = new Map<string, string>();
  const candidates = database.prepare(`
    SELECT link.role, registry.candidate_id
    FROM attack_knowledge_bundle_candidates link
    JOIN attack_knowledge_candidate_registry registry
      ON registry.content_fingerprint = link.content_fingerprint
    WHERE link.bundle_id = ? ORDER BY link.ordinal
  `).all(compiled.bundleId) as Array<{
    readonly role: string;
    readonly candidate_id: string;
  }>;
  for (const candidate of candidates) {
    nodes.set(
      candidate.role,
      memory.confirmCandidate(candidate.candidate_id, "operator-reviewer").id,
    );
  }
  const promotion = new AttackKnowledgePromotionService(database, { clock });
  const preview = promotion.preview(compiled.bundleFingerprint, ["evidence-recovery-projection"]);
  if (!preview.ready) {
    throw new Error(`Promotion fixture is not ready: ${JSON.stringify(preview.blockers)}`);
  }
  promotion.promote({
    bundleFingerprint: compiled.bundleFingerprint,
    actor: "operator-reviewer",
    expectedReviewHash: preview.reviewHash,
    verificationEvidenceIds: ["evidence-recovery-projection"],
  });
  return {
    procedureNodeId: nodes.get("procedure")!,
    failureNodeId: nodes.get("failure")!,
  };
}

function connectVault(database: SqliteDatabase, nodeId: string): void {
  database.prepare(`
    INSERT INTO vault_connections (
      id, vault_path, display_name, status, sync_scope_json,
      permission_granted_at, last_sync_at, created_at, updated_at
    ) VALUES (
      'vault-recovery-projection', '/tmp/ti-scale-test-vault',
      'Test Vault', 'connected', '{}', ?, ?, ?, ?
    )
  `).run(NOW, NOW, NOW, NOW);
  const version = (database.prepare("SELECT version FROM memory_nodes WHERE id = ?")
    .get(nodeId) as { readonly version: number }).version;
  database.prepare(`
    INSERT INTO vault_sync_state (
      id, connection_id, node_id, relative_path, database_version,
      vault_content_hash, database_content_hash, status,
      last_scanned_at, last_synced_at
    ) VALUES (
      'vault-sync-recovery-projection', 'vault-recovery-projection', ?,
      '60 Failures and Recoveries/failure.md', ?, ?, ?, 'synced', ?, ?
    )
  `).run(nodeId, version, "b".repeat(64), "c".repeat(64), NOW, NOW);
}

function bindExactProcedure(
  database: SqliteDatabase,
  procedureNodeId: string,
): void {
  database.prepare(`
    INSERT INTO attack_attempts (
      id, mission_id, run_id, objective, technique_name, action_class,
      prerequisites_json, normalized_parameters_json, status,
      created_at, updated_at, version
    ) VALUES (
      'attempt-recovery-projection', 'mission-recovery-projection',
      'run-recovery-projection', 'Run the bounded exact diagnostic',
      'Bounded diagnostic', 'exploit_validation', '[]', '{}',
      'failed', ?, ?, 1
    )
  `).run(NOW, NOW);
  const normalizedArguments = { maximumAttempts: 1 };
  const binding = {
    missionId: "mission-recovery-projection",
    runId: "run-recovery-projection",
    stepId: null,
    actionType: "bounded_diagnostic",
    actionClass: "exploit_validation",
    normalizedArguments,
    scopedTarget: "authorized-target-redacted",
  };
  database.prepare(`
    INSERT INTO attack_attempt_action_bindings (
      attack_attempt_id, action_type, action_class,
      normalized_arguments_json, scoped_target, binding_hash, created_at
    ) VALUES (
      'attempt-recovery-projection', 'bounded_diagnostic',
      'exploit_validation', ?, 'authorized-target-redacted', ?, ?
    )
  `).run(canonicalJson(normalizedArguments), sha256(canonicalJson(binding)), NOW);
  database.prepare(`
    INSERT INTO attack_attempt_knowledge_contexts (
      attack_attempt_id, procedure_node_id, product_node_ids_json,
      version_node_ids_json, stack_node_ids_json, prerequisite_node_ids_json,
      observed_state_node_ids_json, normalized_parameters_json,
      created_at, updated_at
    ) VALUES (
      'attempt-recovery-projection', ?, '[]', '[]', '[]', '[]', '[]', '{}', ?, ?
    )
  `).run(procedureNodeId, NOW, NOW);
}

function fixture(failureMode = "Execution timeout") {
  const directory = mkdtempSync(join(tmpdir(), "recovery-policy-projector-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "test.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  seedBase(database);
  return { database, ...stageAndPromote(database, failureMode) };
}

describe("AutonomousRecoveryPolicyProjector", () => {
  test("rejects ambiguous or prose-shaped bodies without inferring from labels", () => {
    expect(structuredFailureMode(canonicalJson({
      failureMode: "Execution timeout",
      inferredFromTitle: true,
    }))).toBeUndefined();
    expect(structuredFailureMode("Execution timeout mentioned in prose")).toBeUndefined();
    expect(structuredOperationalHazardBody(canonicalJson({
      unsafeRetryCondition: "Do not repeat until healthy",
      matchingRequired: ["exact procedure"],
      inferredActionClass: "exploit_validation",
    }))).toBe(false);
  });

  test("requires a connected synchronized Vault and verified promotion provenance", () => {
    const { database, failureNodeId } = fixture();
    const projector = new AutonomousRecoveryPolicyProjector(database, {
      clock: () => new Date(NOW),
    });
    const disconnected = projector.project();
    expect(disconnected.projected).toBe(0);
    expect(disconnected.ignored[failureNodeId]).toBe("not_connected_vault_backed");

    connectVault(database, failureNodeId);
    database.prepare(`
      UPDATE memory_nodes SET lifecycle_status = 'confirmed' WHERE id = ?
    `).run(failureNodeId);
    const unverified = projector.project();
    expect(unverified.projected).toBe(0);
    expect(unverified.ignored[failureNodeId]).toBe("not_verified_and_confirmed");
  });

  test("adds bounded backoff without broad denial when no exact action binding exists", () => {
    const { database, failureNodeId } = fixture();
    connectVault(database, failureNodeId);
    const projectedNodeIds: string[][] = [];
    const projector = new AutonomousRecoveryPolicyProjector(database, {
      clock: () => new Date(NOW),
      idFactory: (prefix) => `${prefix}_first`,
      projectMemoryNodes: (nodeIds) => projectedNodeIds.push([...nodeIds]),
    });
    const first = projector.project();
    expect(first.projected).toBe(1);
    expect(first.changedNodeIds).toEqual([failureNodeId]);
    expect(projectedNodeIds).toEqual([[failureNodeId]]);
    const row = database.prepare(`
      SELECT version, retention_policy_json FROM memory_nodes WHERE id = ?
    `).get(failureNodeId) as {
      readonly version: number;
      readonly retention_policy_json: string;
    };
    const retention = JSON.parse(row.retention_policy_json) as Record<string, {
      readonly schemaVersion: string;
      readonly match: Record<string, unknown>;
      readonly effects: Record<string, unknown>;
    }>;
    expect(retention.autonomousRecovery).toEqual({
      schemaVersion: "1",
      match: { failureCategories: ["timeout"] },
      effects: { minimumBackoffMs: 5_000 },
    });
    expect(retention.autonomousRecovery.effects.denyRetry).toBeUndefined();
    expect(retention.autonomousRecovery.match.actionClasses).toBeUndefined();

    const versionCount = (database.prepare(`
      SELECT COUNT(*) AS count FROM memory_versions WHERE node_id = ?
    `).get(failureNodeId) as { readonly count: number }).count;
    const auditCount = (database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'memory.autonomous_recovery_policy_projected'
    `).get() as { readonly count: number }).count;
    const second = projector.project();
    expect(second.projected).toBe(0);
    expect(second.unchanged).toBe(1);
    expect(second.ignored[failureNodeId]).toBe("policy_already_current");
    expect((database.prepare(`
      SELECT COUNT(*) AS count FROM memory_versions WHERE node_id = ?
    `).get(failureNodeId) as { readonly count: number }).count).toBe(versionCount);
    expect((database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'memory.autonomous_recovery_policy_projected'
    `).get() as { readonly count: number }).count).toBe(auditCount);
  });

  test("denies retry only after one immutable exact procedure/action binding exists", () => {
    const { database, failureNodeId, procedureNodeId } = fixture();
    connectVault(database, failureNodeId);
    bindExactProcedure(database, procedureNodeId);
    const projector = new AutonomousRecoveryPolicyProjector(database, {
      clock: () => new Date(NOW),
      idFactory: (prefix) => `${prefix}_bound`,
    });
    const report = projector.project();
    expect(report.projected).toBe(1);
    const retention = JSON.parse((database.prepare(`
      SELECT retention_policy_json FROM memory_nodes WHERE id = ?
    `).get(failureNodeId) as { readonly retention_policy_json: string }).retention_policy_json) as
      Record<string, {
        readonly schemaVersion: string;
        readonly match: Record<string, unknown>;
        readonly effects: Record<string, unknown>;
      }>;
    expect(retention.autonomousRecovery.match).toEqual({
      failureCategories: ["timeout"],
      actionTypes: ["bounded_diagnostic"],
      actionClasses: ["exploit_validation"],
    });
    expect(retention.autonomousRecovery.effects).toEqual({
      denyRetry: true,
      minimumBackoffMs: 5_000,
    });
    expect(canonicalJson(retention)).not.toContain("authorized-target-redacted");
    expect(canonicalJson(retention)).not.toContain("maximumAttempts");
  });

  test("does not project an evidence-verified but unmapped failure label", () => {
    const { database, failureNodeId } = fixture("Authentication lockout");
    connectVault(database, failureNodeId);
    const report = new AutonomousRecoveryPolicyProjector(database, {
      clock: () => new Date(NOW),
    }).project();
    expect(report.projected).toBe(0);
    expect(report.ignored[failureNodeId]).toBe("failure_mode_not_mapped");
  });
});

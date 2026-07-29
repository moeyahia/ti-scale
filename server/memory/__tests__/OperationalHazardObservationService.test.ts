import { describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { EventRepository } from "../../events/EventRepository";
import { historicalHangKnowledgeInputs } from "../../migration/fixtures/HistoricalHangKnowledgeFixtures";
import type { OperationalHazardKnowledge } from "../../migration/AttackKnowledgeCompiler";
import {
  appendVerifiedOperationalHazardReset,
  operationalHazardTargetContextFingerprint,
  OperationalHazardLocalResetEvaluator,
  OperationalHazardObservationError,
  OperationalHazardObservationService,
  OperationalHazardObservationWorker,
  OperationalHazardRuntimeRecoveryProducer,
  OperationalResetControlReceiptIssuer,
  OperationalResetControlAttestor,
  OperationalResetHealthEvidenceRecorder,
  TrustedLocalResetControllerAdapter,
} from "../OperationalHazardObservationService";
import { ActionRepository } from "../../orchestration";
import { canonicalJson } from "../../orchestration/serialization";
import { createOperationalHazardObservationRouter } from "../OperationalHazardObservationRouter";
import { MemoryRepository } from "../MemoryRepository";
import { OperationalHazardMatcher } from "../OperationalHazardMatcher";
import { AttackKnowledgePromotionService } from "../../migration/AttackKnowledgePromotionService";

const NOW = "2026-07-20T13:00:00.000Z";
const ACTION_START = "2026-07-20T12:59:00.000Z";
const HMAC_KEY = "operational-hazard-observation-test-key-32-bytes";

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function resetControlReceipt(suffix: string, actionId = `action-reset-${suffix}`) {
  const targetContextFingerprint = operationalHazardTargetContextFingerprint({
    missionId: "mission-observation",
    runId: "run-observation",
    targetAssetId: "asset-observation",
    targetServiceId: null,
  });
  return new OperationalResetControlAttestor(HMAC_KEY).attest({
    controllerId: "local-disposable-lab-controller",
    resetOperationId: `reset-operation-${suffix}`,
    targetGenerationId: `target-generation-${suffix}`,
    missionId: "mission-observation",
    runId: "run-observation",
    recoveryActionId: actionId,
    targetContextFingerprint,
  });
}

function resetControlReceiptFingerprint(suffix: string, actionId = `action-reset-${suffix}`): string {
  const receipt = resetControlReceipt(suffix, actionId);
  return hash(canonicalJson({
    schema: receipt.schema,
    issuer: receipt.issuer,
    controllerId: receipt.controllerId,
    resetOperationId: receipt.resetOperationId,
    targetGenerationId: receipt.targetGenerationId,
  }));
}

function fixture(): { readonly database: SqliteDatabase; readonly service: OperationalHazardObservationService } {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      engagement_id, scope_json, memory_policy_json, created_by,
      created_at, updated_at, control_plane
    ) VALUES ('mission-observation', 'Private reset fixture', 'Validate bounded recovery',
      'guided', 'active', 'verified', 'private-environment', '{}', '{}',
      'operator:test', ?, ?, 'ti_scale')
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-observation', 'mission-observation', 'private-target.local',
      'domain', 'allowed', 'private-target.local', ?)
  `).run(NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, budget_json, budget_usage_json,
      created_at, updated_at, control_plane
    ) VALUES ('run-observation', 'mission-observation', 'guided', 'blocked',
      '{}', '{}', ?, ?, 'ti_scale')
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      content_hash, content_hash_version, created_by, created_at
    ) VALUES ('plan-observation', 'run-observation', 1, 'active',
      'Preserve one exact failed procedure', ?, ?, 1, 'planner', ?)
  `).run("a".repeat(64), "a".repeat(64), NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      action_class, risk_class, created_at, updated_at
    ) VALUES ('step-observation', 'plan-observation', 'run-observation', 0,
      'validation', 'Exact failed procedure', 'Retain exact failure context',
      'failed', 'exploit_validation', 'high', ?, ?)
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, properties_json, confidence,
      verification_state, sensitivity, first_seen_at, last_seen_at,
      created_at, updated_at
    ) VALUES ('asset-observation', 'mission-observation', 'run-observation',
      'asset', 'private-target.local', 'private-target.local', 'allowed',
      'blocked', '{}', 1, 'verified', 'private', ?, ?, ?, ?)
  `).run(NOW, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO attack_attempts (
      id, mission_id, run_id, plan_id, step_id, target_asset_id, objective, technique_name,
      action_class, prerequisites_json, normalized_parameters_json, status,
      outcome_summary, failure_category, created_at, updated_at, version
    ) VALUES ('attempt-observation', 'mission-observation', 'run-observation',
      'plan-observation', 'step-observation', 'asset-observation', 'Run one exact bounded procedure',
      'Exact reviewed procedure', 'exploit_validation', '[]',
      '{"automaticRetries":0}', 'failed', 'The application stopped responding',
      'target_hang', ?, ?, 2)
  `).run(NOW, NOW);
  const targetContextFingerprint = operationalHazardTargetContextFingerprint({
    missionId: "mission-observation",
    runId: "run-observation",
    targetAssetId: "asset-observation",
    targetServiceId: null,
  });
  for (const suffix of ["a", "b"] as const) {
    const recoveryActionId = `action-reset-${suffix}`;
    const evidenceId = `evidence-reset-${suffix}`;
    const preResetHealthEvidenceId = `health-reset-${suffix}-pre`;
    const postResetHealthEvidenceId = `health-reset-${suffix}-post`;
    database.prepare(`
      INSERT INTO actions (
        id, mission_id, run_id, step_id, action_type, action_class,
        fingerprint, normalized_arguments_json, scoped_target, status,
        intent_summary, result_summary, retry_count, created_at, updated_at,
        started_at, ended_at
      ) VALUES (?, 'mission-observation', 'run-observation', 'step-observation',
        'target_reset', 'cleanup_restoration', ?, ?, 'private-target.local',
        'running', 'Reset the disposable target once', NULL,
        0, ?, ?, ?, ?)
    `).run(
      recoveryActionId,
      hash(recoveryActionId),
      JSON.stringify({
        input: {
          operationalHazardReset: {
            schemaVersion: "ti_scale.operational_hazard_reset/v1",
            attackAttemptId: "attempt-observation",
            targetAssetId: "asset-observation",
            targetServiceId: null,
            preResetHealthEvidenceId,
            postResetHealthEvidenceId,
            knowledge: knowledge(),
          },
        },
        orchestration: { target: "private-target.local", kind: "tool", idempotent: false, destructive: false },
      }),
      NOW, NOW, NOW, NOW,
    );
    const resetIssuer = new OperationalResetControlReceiptIssuer(database, HMAC_KEY);
    resetIssuer.authorizeBeforeDispatch(new ActionRepository(database).get(recoveryActionId));
    database.prepare(`
      UPDATE actions SET status = 'succeeded', result_summary = 'Baseline restored',
        updated_at = ?, ended_at = ? WHERE id = ?
    `).run(NOW, NOW, recoveryActionId);
    for (const [healthEvidenceId, phase, baselineRestored] of [
      [preResetHealthEvidenceId, "before_reset", false],
      [postResetHealthEvidenceId, "after_reset", true],
    ] as const) {
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
          evidence_type, content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, created_by, created_at
        ) VALUES (?, 'mission-observation', 'run-observation', 'step-observation', ?,
          'local-operational-reset-evaluator', ?, 'private-target.local',
          'health_check_result', ?, ?, 1, 'private', 'verified',
          'Typed local reset health observation',
          'local-operational-reset-evaluator', ?)
      `).run(
        healthEvidenceId,
        recoveryActionId,
        NOW,
        hash(healthEvidenceId),
        JSON.stringify({
          healthAssessment: {
            schema: "ti_scale.operational_health/v1",
            phase,
            baselineRestored,
            ...(phase === "after_reset" ? { resetCompleted: true } : {}),
            ...(phase === "after_reset" ? {
              resetControlReceipt: resetControlReceipt(suffix),
              resetControlReceiptFingerprint: resetControlReceiptFingerprint(suffix),
            } : {}),
            attackAttemptId: "attempt-observation",
            recoveryActionId,
            targetContextFingerprint,
          },
        }),
        NOW,
      );
      database.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'verified', 'local-operational-reset-evaluator', '{}', ?)
      `).run(`chain-${healthEvidenceId}`, healthEvidenceId, NOW);
    }
    const issuedReceipt = resetIssuer
      .issueFromCompletedReset(new ActionRepository(database).get(recoveryActionId));
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
        evidence_type, content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, created_by, created_at
      ) VALUES (?, 'mission-observation', 'run-observation', 'step-observation', ?,
        'local-operational-reset-evaluator', ?, 'private-target.local', 'target_reset_result',
        ?, ?, 1, 'private', 'verified',
        'Local recovery monitor verified a clean target reset',
        'local-operational-reset-evaluator', ?)
    `).run(
      evidenceId,
      recoveryActionId,
      NOW,
      hash(evidenceId),
      JSON.stringify({
        resetAssessment: {
          schema: "ti_scale.operational_reset/v1",
          resetCompleted: true,
          baselineRestored: true,
          attackAttemptId: "attempt-observation",
          recoveryActionId,
          targetContextFingerprint,
          resetControlReceiptId: issuedReceipt.id,
          resetControlReceiptFingerprint: resetControlReceiptFingerprint(suffix),
          preResetHealthEvidenceId,
          preResetHealthEvidenceHash: hash(preResetHealthEvidenceId),
          postResetHealthEvidenceId,
          postResetHealthEvidenceHash: hash(postResetHealthEvidenceId),
        },
      }),
      NOW,
    );
    database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'verified', 'local-runtime', '{}', ?)
    `).run(`chain-${evidenceId}`, evidenceId, NOW);
  }
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES ('evidence-reset-a-secondary', 'mission-observation', 'run-observation',
      'step-observation', 'action-reset-a', 'local-operational-reset-evaluator', ?,
      'private-target.local', 'target_reset_result', ?, ?, 1, 'private', 'verified',
      'A second artifact describes the same physical reset',
      'local-operational-reset-evaluator', ?)
  `).run(
    NOW,
    hash("evidence-reset-a-secondary"),
    JSON.stringify({
      resetAssessment: {
        schema: "ti_scale.operational_reset/v1",
        resetCompleted: true,
        baselineRestored: true,
        attackAttemptId: "attempt-observation",
        recoveryActionId: "action-reset-a",
        targetContextFingerprint,
        resetControlReceiptId: (database.prepare(`
          SELECT id FROM operational_reset_control_receipts WHERE recovery_action_id = 'action-reset-a'
        `).get() as { id: string }).id,
        resetControlReceiptFingerprint: resetControlReceiptFingerprint("a"),
        preResetHealthEvidenceId: "health-reset-a-pre",
        preResetHealthEvidenceHash: hash("health-reset-a-pre"),
        postResetHealthEvidenceId: "health-reset-a-post",
        postResetHealthEvidenceHash: hash("health-reset-a-post"),
      },
    }),
    NOW,
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES ('chain-evidence-reset-a-secondary', 'evidence-reset-a-secondary',
      'verified', 'local-runtime', '{}', ?)
  `).run(NOW);
  return {
    database,
    service: new OperationalHazardObservationService(database, {
      hmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
    }),
  };
}

function knowledge(): OperationalHazardKnowledge {
  const source = structuredClone(
    historicalHangKnowledgeInputs[0]!.knowledge as OperationalHazardKnowledge,
  );
  const safeRetryGate = [
    ...source.hazard.healthGate,
    ...(source.hazard.retryValidConditions ?? []),
  ];
  return {
    ...source,
    hazard: {
      ...source.hazard,
      saferAlternative: {
        ...source.hazard.saferAlternative,
        reviewedBinding: {
          version: `sha256:${hash("reviewed-offline-layout-calibration-v1")}`,
          normalizedParameters: {
            automaticRetries: 0,
            concurrency: 1,
            debugPrintCalls: 0,
            mode: "offline_only",
          },
          sourceLoad: source.hazard.loadMinimum ?? 0,
          sourceConcurrency: source.hazard.concurrencyMinimum ?? 1,
          sourceTimingWindowMs: source.hazard.timingWindowMs ?? 0,
          load: 0,
          concurrency: 1,
          timingWindowMs: 45_000,
        },
        retryConditionEvidence: safeRetryGate.map((statement, index) => ({
          statement,
          evidenceKey: `reviewed_retry_condition_${index + 1}`,
        })),
      },
    },
  };
}

function seedAdditionalResetAction(
  database: SqliteDatabase,
  suffix: string,
  options: {
    readonly receiptSuffix?: string;
    readonly source?: string;
    readonly issue?: boolean;
    readonly createEvidence?: boolean;
    readonly forgedAuthenticator?: string;
  } = {},
): string {
  const actionId = `action-reset-${suffix}`;
  const preId = `health-reset-${suffix}-pre`;
  const postId = `health-reset-${suffix}-post`;
  const receiptSuffix = options.receiptSuffix ?? suffix;
  const source = options.source ?? "local-operational-reset-evaluator";
  const targetContextFingerprint = operationalHazardTargetContextFingerprint({
    missionId: "mission-observation",
    runId: "run-observation",
    targetAssetId: "asset-observation",
    targetServiceId: null,
  });
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, action_type, action_class,
      fingerprint, normalized_arguments_json, scoped_target, status,
      intent_summary, result_summary, retry_count, created_at, updated_at,
      started_at, ended_at
    ) VALUES (?, 'mission-observation', 'run-observation', 'step-observation',
      'target_reset', 'cleanup_restoration', ?, ?, 'private-target.local',
      'running', 'Reset the disposable target once', NULL,
      0, ?, ?, ?, ?)
  `).run(
    actionId,
    hash(actionId),
    JSON.stringify({
      input: {
        operationalHazardReset: {
          schemaVersion: "ti_scale.operational_hazard_reset/v1",
          attackAttemptId: "attempt-observation",
          targetAssetId: "asset-observation",
          targetServiceId: null,
          preResetHealthEvidenceId: preId,
          postResetHealthEvidenceId: postId,
          knowledge: knowledge(),
        },
      },
      orchestration: { target: "private-target.local", kind: "tool", idempotent: false, destructive: false },
    }),
    NOW, NOW, ACTION_START, NOW,
  );
  const resetIssuer = new OperationalResetControlReceiptIssuer(database, HMAC_KEY);
  resetIssuer.authorizeBeforeDispatch(new ActionRepository(database).get(actionId));
  database.prepare(`
    UPDATE actions SET status = 'succeeded', result_summary = 'Baseline restored',
      updated_at = ?, ended_at = ? WHERE id = ?
  `).run(NOW, NOW, actionId);
  if (options.createEvidence !== false) for (const [evidenceId, phase, baselineRestored] of [
    [preId, "before_reset", false],
    [postId, "after_reset", true],
  ] as const) {
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
        evidence_type, content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, created_by, created_at
      ) VALUES (?, 'mission-observation', 'run-observation', 'step-observation', ?,
        ?, ?, 'private-target.local', 'health_check_result', ?, ?, 1,
        'private', 'verified', 'Typed local reset health observation', ?, ?)
    `).run(
      evidenceId,
      actionId,
      source,
      NOW,
      hash(evidenceId),
      JSON.stringify({
        healthAssessment: {
          schema: "ti_scale.operational_health/v1",
          phase,
          baselineRestored,
          ...(phase === "after_reset" ? {
            resetCompleted: true,
            resetControlReceipt: {
              ...resetControlReceipt(receiptSuffix, actionId),
              ...(options.forgedAuthenticator
                ? { authenticator: options.forgedAuthenticator }
                : {}),
            },
            resetControlReceiptFingerprint: resetControlReceiptFingerprint(receiptSuffix, actionId),
          } : {}),
          attackAttemptId: "attempt-observation",
          recoveryActionId: actionId,
          targetContextFingerprint,
        },
      }),
      source,
      NOW,
    );
    database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'verified', ?, '{}', ?)
    `).run(`chain-${evidenceId}`, evidenceId, source, NOW);
  }
  if (options.issue !== false && options.createEvidence !== false) {
    resetIssuer.issueFromCompletedReset(new ActionRepository(database).get(actionId));
  }
  return actionId;
}

function appendReset(
  database: SqliteDatabase,
  suffix: string,
  overrides: Partial<{
    knowledge: OperationalHazardKnowledge;
    verifiedEvidenceIds: readonly string[];
    attackAttemptId: string;
  }> = {},
): string {
  const actionId = `action-reset-${suffix}`;
  const proofId = new OperationalHazardLocalResetEvaluator(database)
    .evaluateCompletedAction(new ActionRepository(database).get(actionId));
  if (!proofId) throw new Error("Expected a deterministic reset proof");
  const receipt = database.prepare(`
    SELECT id, receipt_fingerprint FROM operational_reset_control_receipts
    WHERE recovery_action_id = ?
  `).get(actionId) as { id: string; receipt_fingerprint: string };
  return appendVerifiedOperationalHazardReset({
    database,
    missionId: "mission-observation",
    runId: "run-observation",
    actor: { id: `runtime:${suffix}`, type: "worker" },
    payload: {
      attackAttemptId: overrides.attackAttemptId ?? "attempt-observation",
      recoveryActionId: actionId,
      resetKind: "target_reset",
      targetContextFingerprint: operationalHazardTargetContextFingerprint({
        missionId: "mission-observation",
        runId: "run-observation",
        targetAssetId: "asset-observation",
        targetServiceId: null,
      }),
      resetControlReceiptId: receipt.id,
      resetControlReceiptFingerprint: receipt.receipt_fingerprint,
      verifiedEvidenceIds: overrides.verifiedEvidenceIds ?? [proofId],
      knowledge: overrides.knowledge ?? knowledge(),
      confidence: 0.96,
    },
    occurredAt: NOW,
  });
}

describe("OperationalHazardObservationService", () => {
  test("one locally attested reset promotes into a cross-target exact-stack safety gate", () => {
    const { database, service } = fixture();
    try {
      const recoveryEventId = appendReset(database, "a");
      const staged = service.recordCanonicalReset({
        recoveryEventId,
        actor: { id: "operator:test", type: "operator" },
        idempotencyKey: "reset-occurrence-promote-and-match",
      });
      const bundleId = staged.occurrence.bundleId;
      const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
      const roleToNode = new Map<string, string>();
      const candidates = database.prepare(`
        SELECT bundle_candidate.role, registry.candidate_id
        FROM attack_knowledge_bundle_candidates bundle_candidate
        JOIN attack_knowledge_candidate_registry registry
          ON registry.content_fingerprint = bundle_candidate.content_fingerprint
        WHERE bundle_candidate.bundle_id = ?
        ORDER BY bundle_candidate.ordinal
      `).all(bundleId) as Array<{ readonly role: string; readonly candidate_id: string }>;
      for (const candidate of candidates) {
        const node = memory.confirmCandidate(candidate.candidate_id, "operator:test");
        roleToNode.set(candidate.role, node.id);
      }

      const promotion = new AttackKnowledgePromotionService(database, {
        clock: () => new Date(NOW),
      });
      const preview = promotion.preview(
        staged.compile.bundleFingerprint!,
        staged.occurrence.verifiedEvidenceIds,
      );
      expect(preview.ready).toBe(true);
      promotion.promote({
        bundleFingerprint: staged.compile.bundleFingerprint!,
        actor: "operator:test",
        expectedReviewHash: preview.reviewHash,
        verificationEvidenceIds: staged.occurrence.verifiedEvidenceIds,
      });

      const hazardNodeId = roleToNode.get("hazard")!;
      const profile = database.prepare(`
        SELECT receipt_backed_occurrence_count, reproducibility_count,
          recovery_cost_json, node_id
        FROM operational_hazard_profiles WHERE node_id = ?
      `).get(hazardNodeId) as {
        readonly receipt_backed_occurrence_count: number;
        readonly reproducibility_count: number;
        readonly recovery_cost_json: string;
        readonly node_id: string;
      };
      expect(profile.receipt_backed_occurrence_count).toBe(1);
      expect(profile.reproducibility_count).toBe(1);

      const roles = [...roleToNode.entries()];
      const ids = (prefix: string): string[] => roles
        .filter(([role]) => role === prefix || role.startsWith(`${prefix}.`))
        .filter(([role]) => !role.endsWith(".version"))
        .map(([, nodeId]) => nodeId)
        .sort();
      const versionIds = roles
        .filter(([role]) => role === "product.version" || /^stack\.\d+\.version$/u.test(role))
        .map(([, nodeId]) => nodeId)
        .sort();
      const context = {
        procedureNodeId: roleToNode.get("procedure")!,
        procedureVersionNodeId: roleToNode.get("procedure.version")!,
        productNodeIds: [roleToNode.get("product")!],
        versionNodeIds: versionIds,
        stackNodeIds: ids("stack"),
        prerequisiteNodeIds: ids("prerequisite"),
        observedStateNodeIds: [roleToNode.get("health")!, roleToNode.get("state")!].sort(),
        normalizedParameters: knowledge().procedure.normalizedParameters,
        concurrency: knowledge().hazard.concurrencyMinimum,
        timingWindowMs: knowledge().hazard.timingWindowMs,
      };
      const matcher = new OperationalHazardMatcher(database, {
        clock: () => new Date(NOW),
        minimumReproducibilityCount: 2,
      });
      expect(matcher.assess(context)).toMatchObject({
        decision: "block",
        matchedHazardNodeIds: [hazardNodeId],
        blockedProcedureNodeIds: [roleToNode.get("procedure")!],
      });
      expect(matcher.assess({
        ...context,
        versionNodeIds: [...versionIds.slice(0, -1), "mem_verified_different_stack_version"],
      }).decision).toBe("allow");

      const reusable = JSON.stringify({ profile, context });
      expect(reusable).not.toMatch(/ReaperTwo|private-target|mission-observation|run-observation|10\.129\./u);
    } finally {
      database.close();
    }
  });

  test("runtime worker stages one exact occurrence once and never promotes it", () => {
    const { database } = fixture();
    try {
      const recoveryEventId = appendReset(database, "a");
      expect((database.prepare(`
        SELECT status FROM operational_hazard_observation_jobs WHERE event_id = ?
      `).get(recoveryEventId) as { status: string }).status).toBe("pending");

      const worker = new OperationalHazardObservationWorker(database, {
        hmacKey: HMAC_KEY,
        clock: () => new Date(NOW),
      });
      expect(worker.drain()).toEqual({ completed: 1, quarantined: 0 });
      expect(worker.drain()).toEqual({ completed: 0, quarantined: 0 });

      const occurrence = database.prepare("SELECT * FROM operational_hazard_occurrences")
        .get() as Record<string, unknown>;
      expect(occurrence.attack_attempt_id).toBe("attempt-observation");
      expect(occurrence.recovery_event_id).toBe(recoveryEventId);
      expect(occurrence.recovery_action_id).toBe("action-reset-a");
      expect(occurrence.exact_attempt_count).toBe(1);
      expect(occurrence.exact_reproducibility_count).toBe(1);
      expect(occurrence.exact_reset_count).toBe(1);
      expect(String(occurrence.occurrence_key_hash)).toHaveLength(64);
      expect(String(occurrence.id)).not.toContain("attempt-observation");
      expect(String(occurrence.id)).not.toContain("private-target");
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_candidates WHERE status = 'pending'")
        .get() as { count: number }).count).toBeGreaterThan(10);
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_nodes")
        .get() as { count: number }).count).toBe(0);
      expect((database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_profiles")
        .get() as { count: number }).count).toBe(0);
      const canonicalBindings = database.prepare(`
        SELECT binding.evidence_id, binding.content_hash, binding.acquired_at
        FROM attack_knowledge_bundle_evidence_bindings binding
        WHERE binding.bundle_id = ?
      `).all(occurrence.bundle_id) as Array<{
        evidence_id: string;
        content_hash: string;
        acquired_at: string;
      }>;
      expect(canonicalBindings).toHaveLength(1);
      expect(JSON.parse(String(occurrence.evidence_ids_json))).toContain(
        canonicalBindings[0]!.evidence_id,
      );
      expect(canonicalBindings[0]).toMatchObject({ acquired_at: NOW });
      expect(canonicalBindings[0]!.content_hash).toMatch(/^[a-f0-9]{64}$/u);
      expect(database.prepare(`
        SELECT e.verification_state,
          EXISTS (
            SELECT 1 FROM evidence_chain_events custody
            WHERE custody.evidence_id = e.id AND custody.event_type = 'verified'
          ) AS has_verified_custody
        FROM evidence e WHERE e.id = ?
      `).get(canonicalBindings[0]!.evidence_id)).toEqual({
        verification_state: "verified",
        has_verified_custody: 1,
      });
      expect((database.prepare(`
        SELECT operator_reported_reset_count_minimum AS minimum
        FROM attack_knowledge_bundles WHERE id = ?
      `).get(occurrence.bundle_id) as { minimum: number | null }).minimum).toBeNull();
      expect((database.prepare(`
        SELECT status FROM operational_hazard_observation_jobs WHERE event_id = ?
      `).get(recoveryEventId) as { status: string }).status).toBe("completed");
    } finally {
      database.close();
    }
  });

  test("runtime worker defers transient SQLite contention without crashing the process", () => {
    const busyError = Object.assign(new Error("database is locked"), {
      code: "SQLITE_BUSY",
      errno: 5,
    });
    const busyDatabase = {
      prepare: () => ({
        run: () => { throw busyError; },
      }),
    } as unknown as SqliteDatabase;
    const worker = new OperationalHazardObservationWorker(busyDatabase, {
      hmacKey: HMAC_KEY,
      clock: () => new Date(NOW),
      workerId: "busy-safe-worker",
    });

    expect(worker.drain()).toEqual({
      completed: 0,
      quarantined: 0,
      deferred: { reason: "database_busy" },
    });

    // The periodic worker uses the same fail-soft path. The initial drain in
    // start() must therefore not surface SQLITE_BUSY as an uncaught error.
    expect(() => worker.start(100)).not.toThrow();
    worker.stop();
  });

  test("counts unique exact resets and keeps the operator aggregate as a monotonic MAX", () => {
    const { database, service } = fixture();
    try {
      const first = appendReset(database, "a");
      const second = appendReset(database, "b");
      service.recordCanonicalReset({
        recoveryEventId: first,
        actor: { id: "operator:test", type: "operator" },
        idempotencyKey: "reset-observation-a",
      });
      service.recordCanonicalReset({
        recoveryEventId: second,
        actor: { id: "operator:test", type: "operator" },
        idempotencyKey: "reset-observation-b",
      });
      const reported = service.reportAggregateResetMinimum({
        missionId: "mission-observation",
        runId: "run-observation",
        reportedMinimum: 11,
        actor: { id: "operator:test", type: "operator" },
        idempotencyKey: "aggregate-reset-minimum-11",
      });
      expect(reported.totals).toEqual({
        missionId: "mission-observation",
        runId: "run-observation",
        exactAttributableResetCount: 2,
        operatorReportedResetMinimum: 11,
        minimumUnattributedResetCount: 9,
      });
      const lower = service.reportAggregateResetMinimum({
        missionId: "mission-observation",
        runId: "run-observation",
        reportedMinimum: 7,
        actor: { id: "operator:test", type: "operator" },
        idempotencyKey: "aggregate-reset-minimum-07",
      });
      expect(lower.totals.operatorReportedResetMinimum).toBe(11);
      expect((database.prepare(`
        SELECT MAX(operator_reported_reset_count_minimum) AS attributed
        FROM attack_knowledge_bundles
      `).get() as { attributed: number | null }).attributed).toBeNull();
    } finally {
      database.close();
    }
  });

  test("is idempotent, rejects changed replay, and makes occurrence rows immutable", () => {
    const { database, service } = fixture();
    try {
      const eventId = appendReset(database, "a");
      const first = service.recordCanonicalReset({
        recoveryEventId: eventId,
        actor: { id: "operator:test", type: "operator" },
        idempotencyKey: "same-reset-observation",
      });
      const replay = service.recordCanonicalReset({
        recoveryEventId: eventId,
        actor: { id: "operator:test", type: "operator" },
        idempotencyKey: "same-reset-observation",
      });
      expect(replay.replayed).toBe(true);
      expect(replay.occurrence.id).toBe(first.occurrence.id);
      expect((database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_occurrences")
        .get() as { count: number }).count).toBe(1);
      expect(() => database.prepare(`
        UPDATE operational_hazard_occurrences SET exact_reset_count = 2 WHERE id = ?
      `).run(first.occurrence.id)).toThrow("immutable");

      const otherEvent = appendReset(database, "b");
      expect(() => service.recordCanonicalReset({
        recoveryEventId: otherEvent,
        actor: { id: "operator:test", type: "operator" },
        idempotencyKey: "same-reset-observation",
      })).toThrow(OperationalHazardObservationError);
    } finally {
      database.close();
    }
  });

  test("counts one physical reset once even when a duplicate event cites another artifact", () => {
    const { database } = fixture();
    try {
      const firstEventId = appendReset(database, "a");
      const worker = new OperationalHazardObservationWorker(database, {
        hmacKey: HMAC_KEY,
        clock: () => new Date(NOW),
      });
      expect(worker.drain()).toEqual({ completed: 1, quarantined: 0 });
      expect(appendReset(database, "a")).toBe(firstEventId);
      const receipt = database.prepare(`
        SELECT id, receipt_fingerprint FROM operational_reset_control_receipts
        WHERE recovery_action_id = 'action-reset-a'
      `).get() as { id: string; receipt_fingerprint: string };
      new EventRepository(database).append({
        id: "duplicate-reset-event-different-artifact",
        missionId: "mission-observation",
        runId: "run-observation",
        eventType: "operational_hazard.reset_verified",
        actorType: "worker",
        actorId: "runtime:duplicate",
        summary: "Duplicate report for the same physical reset.",
        payload: {
          attackAttemptId: "attempt-observation",
          recoveryActionId: "action-reset-a",
          resetKind: "target_reset",
          targetContextFingerprint: operationalHazardTargetContextFingerprint({
            missionId: "mission-observation",
            runId: "run-observation",
            targetAssetId: "asset-observation",
            targetServiceId: null,
          }),
          resetControlReceiptId: receipt.id,
          resetControlReceiptFingerprint: receipt.receipt_fingerprint,
          verifiedEvidenceIds: ["evidence-reset-a-secondary"],
          knowledge: knowledge() as unknown as import("../../events/types").JsonValue,
          confidence: 0.96,
        },
        occurredAt: NOW,
        sensitivity: "private",
      });
      expect(worker.drain()).toEqual({ completed: 0, quarantined: 1 });
      expect((database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_occurrences")
        .get() as { count: number }).count).toBe(1);
      expect((database.prepare(`
        SELECT exact_attributable_reset_count AS count
        FROM operational_hazard_reset_totals
        WHERE mission_id = 'mission-observation' AND run_id = 'run-observation'
      `).get() as { count: number }).count).toBe(1);
    } finally {
      database.close();
    }
  });

  test("quarantines target-specific reusable text and refuses unverified evidence", () => {
    const { database } = fixture();
    try {
      const original = knowledge();
      const unsafe = {
        ...original,
        hazard: { ...original.hazard, name: "Private reset fixture worker hang" },
      } as OperationalHazardKnowledge;
      const unsafeEvent = appendReset(database, "a", { knowledge: unsafe });
      const unverifiedEvent = appendReset(database, "b", { verifiedEvidenceIds: ["missing-evidence"] });
      const worker = new OperationalHazardObservationWorker(database, {
        hmacKey: HMAC_KEY,
        clock: () => new Date(NOW),
      });
      expect(worker.drain()).toEqual({ completed: 0, quarantined: 2 });
      const jobs = database.prepare(`
        SELECT event_id, failure_category FROM operational_hazard_observation_jobs ORDER BY event_id
      `).all() as Array<{ event_id: string; failure_category: string }>;
      expect(jobs.find((row) => row.event_id === unsafeEvent)?.failure_category)
        .toBe("hazard_observation_compiler_rejected");
      expect(jobs.find((row) => row.event_id === unverifiedEvent)?.failure_category)
        .toBe("hazard_observation_verified_local_evidence_required");
      expect((database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_occurrences")
        .get() as { count: number }).count).toBe(0);
    } finally {
      database.close();
    }
  });

  test("trigger rejects direct cross-scope or non-reset occurrence insertion", () => {
    const { database } = fixture();
    try {
      const ordinary = new EventRepository(database).append({
        missionId: "mission-observation",
        runId: "run-observation",
        eventType: "run.recovery_started",
        actorType: "system",
        summary: "Recovery began but no reset is verified.",
      });
      expect(() => database.prepare(`
        INSERT INTO operational_hazard_occurrences (
          id, occurrence_key_hash, request_key_hash, request_hash,
          mission_id, run_id, attack_attempt_id, recovery_action_id, recovery_event_id,
          evidence_ids_json, bundle_id, provenance_receipt_id, knowledge_hash,
          recorded_by, audit_record_id, audit_record_hash, observed_at, created_at
        ) VALUES ('hazocc-direct', ?, ?, ?, 'mission-observation', 'run-observation',
          'attempt-observation', 'action-reset-a', ?, '[]', 'missing-bundle', 'missing-receipt', ?,
          'operator:test', 'missing-audit', ?, ?, ?)
      `).run(
        "1".repeat(64), "2".repeat(64), "3".repeat(64), ordinary.id,
        "4".repeat(64), "5".repeat(64), NOW, NOW,
      )).toThrow();
    } finally {
      database.close();
    }
  });

  test("production producer derives one proof from the typed health pair and queues one event", () => {
    const { database } = fixture();
    try {
      const action = new ActionRepository(database).get("action-reset-a");
      const evaluator = new OperationalHazardLocalResetEvaluator(database);
      const proofId = evaluator.evaluateCompletedAction(action);
      expect(proofId).toStartWith("hazresetproof_");
      const receipt = new OperationalHazardRuntimeRecoveryProducer(database)
        .recordCompletedAction(action, { id: "runtime:test", type: "worker" });
      expect(receipt?.verifiedEvidenceIds).toEqual([proofId!]);
      expect(receipt?.resetControlReceiptId).toStartWith("resetctl_");
      expect((database.prepare(`
        SELECT status FROM operational_hazard_observation_jobs WHERE event_id = ?
      `).get(receipt!.recoveryEventId) as { status: string }).status).toBe("pending");
    } finally {
      database.close();
    }
  });

  test("trusted local reset-controller seam creates health evidence before receipt, proof, and event", () => {
    const { database } = fixture();
    try {
      const actionId = seedAdditionalResetAction(database, "adapter-seam", {
        createEvidence: false,
        issue: false,
      });
      const action = new ActionRepository(database).get(actionId);
      const targetContextFingerprint = operationalHazardTargetContextFingerprint({
        missionId: action.missionId,
        runId: action.runId,
        targetAssetId: "asset-observation",
        targetServiceId: null,
      });
      const envelope = new TrustedLocalResetControllerAdapter(HMAC_KEY).attestCompletion({
        missionId: action.missionId,
        runId: action.runId,
        recoveryActionId: action.id,
        attackAttemptId: "attempt-observation",
        targetContextFingerprint,
        preReset: {
          observedAt: "2026-07-20T12:59:30.000Z",
          baselineRestored: false,
          measurementHash: hash("adapter-seam-before"),
        },
        postReset: {
          observedAt: NOW,
          resetCompleted: true,
          baselineRestored: true,
          measurementHash: hash("adapter-seam-after"),
        },
        controllerId: "local-disposable-lab-controller",
        resetOperationId: "reset-operation-adapter-seam",
        targetGenerationId: "target-generation-adapter-seam",
      });
      expect(new OperationalResetHealthEvidenceRecorder(database, HMAC_KEY)
        .record(action, envelope)).toEqual([
        "health-reset-adapter-seam-pre",
        "health-reset-adapter-seam-post",
      ]);
      const issued = new OperationalResetControlReceiptIssuer(database, HMAC_KEY)
        .issueFromCompletedReset(action);
      expect(issued.recoveryActionId).toBe(action.id);
      const proof = new OperationalHazardLocalResetEvaluator(database)
        .evaluateCompletedAction(action);
      expect(proof).toStartWith("hazresetproof_");
      const produced = new OperationalHazardRuntimeRecoveryProducer(database)
        .recordCompletedAction(action, { id: "runtime:adapter-seam", type: "worker" });
      expect(produced?.resetControlReceiptId).toBe(issued.id);
    } finally {
      database.close();
    }
  });

  test("fails closed without typed local health and rejects public-model evidence", () => {
    const { database } = fixture();
    try {
      const noEvidenceActionId = seedAdditionalResetAction(database, "no-evidence", {
        createEvidence: false,
        issue: false,
      });
      expect(() => new OperationalHazardLocalResetEvaluator(database)
        .evaluateCompletedAction(new ActionRepository(database).get(noEvidenceActionId)))
        .toThrow(OperationalHazardObservationError);

      const publicEvidenceActionId = seedAdditionalResetAction(database, "public-evidence", {
        source: "openai-public-model",
        issue: false,
      });
      expect(() => new OperationalResetControlReceiptIssuer(database, HMAC_KEY)
        .issueFromCompletedReset(new ActionRepository(database).get(publicEvidenceActionId)))
        .toThrow(OperationalHazardObservationError);
    } finally {
      database.close();
    }
  });

  test("rejects a forged fresh reset receipt and a second action for one physical reset", () => {
    const { database } = fixture();
    try {
      const forgedActionId = seedAdditionalResetAction(database, "forged", {
        issue: false,
        forgedAuthenticator: "0".repeat(64),
      });
      expect(() => new OperationalResetControlReceiptIssuer(database, HMAC_KEY)
        .issueFromCompletedReset(new ActionRepository(database).get(forgedActionId)))
        .toThrow(OperationalHazardObservationError);

      const duplicateActionId = seedAdditionalResetAction(database, "duplicate-physical", {
        receiptSuffix: "a",
        issue: false,
      });
      expect(() => new OperationalResetControlReceiptIssuer(database, HMAC_KEY)
        .issueFromCompletedReset(new ActionRepository(database).get(duplicateActionId)))
        .toThrow(OperationalHazardObservationError);
      expect((database.prepare(`
        SELECT COUNT(*) AS count FROM operational_reset_control_receipts
      `).get() as { count: number }).count).toBe(2);
    } finally {
      database.close();
    }
  });

  test("rejects tampered, reversed, stale, and future reset health envelopes", () => {
    const { database } = fixture();
    try {
      const actionId = seedAdditionalResetAction(database, "timeline", {
        createEvidence: false,
        issue: false,
      });
      const action = new ActionRepository(database).get(actionId);
      const targetContextFingerprint = operationalHazardTargetContextFingerprint({
        missionId: action.missionId,
        runId: action.runId,
        targetAssetId: "asset-observation",
        targetServiceId: null,
      });
      const adapter = new TrustedLocalResetControllerAdapter(HMAC_KEY);
      const recorder = new OperationalResetHealthEvidenceRecorder(database, HMAC_KEY);
      const completion = (preObservedAt: string, postObservedAt: string) => adapter.attestCompletion({
        missionId: action.missionId,
        runId: action.runId,
        recoveryActionId: action.id,
        attackAttemptId: "attempt-observation",
        targetContextFingerprint,
        preReset: {
          observedAt: preObservedAt,
          baselineRestored: false,
          measurementHash: hash(`pre:${preObservedAt}`),
        },
        postReset: {
          observedAt: postObservedAt,
          resetCompleted: true,
          baselineRestored: true,
          measurementHash: hash(`post:${postObservedAt}`),
        },
        controllerId: "local-disposable-lab-controller",
        resetOperationId: `reset-operation:${preObservedAt}:${postObservedAt}`.replaceAll(":", "-"),
        targetGenerationId: `target-generation:${postObservedAt}`.replaceAll(":", "-"),
      });
      const valid = completion("2026-07-20T12:59:20.000Z", "2026-07-20T12:59:40.000Z");
      const tampered = {
        ...valid,
        preReset: { ...valid.preReset, measurementHash: hash("tampered") },
      };
      expect(() => recorder.record(action, tampered)).toThrow(OperationalHazardObservationError);
      expect(() => recorder.record(action,
        completion("2026-07-20T12:59:50.000Z", "2026-07-20T12:59:30.000Z")))
        .toThrow(OperationalHazardObservationError);
      expect(() => recorder.record(action,
        completion("2026-07-20T12:58:59.000Z", "2026-07-20T12:59:30.000Z")))
        .toThrow(OperationalHazardObservationError);
      expect(() => recorder.record(action,
        completion("2026-07-20T12:59:30.000Z", "2026-07-20T13:00:01.000Z")))
        .toThrow(OperationalHazardObservationError);
      expect((database.prepare(`
        SELECT COUNT(*) AS count FROM evidence WHERE action_id = ?
      `).get(actionId) as { count: number }).count).toBe(0);
    } finally {
      database.close();
    }
  });

  test("reclaims an expired worker lease after the occurrence committed before job completion", () => {
    const { database, service } = fixture();
    try {
      const eventId = appendReset(database, "a");
      const first = service.recordCanonicalReset({
        recoveryEventId: eventId,
        actor: { id: "operator:test", type: "operator" },
        idempotencyKey: "crash-before-job-completion",
      });
      const expiredAt = "2026-07-20T12:59:00.000Z";
      database.prepare(`
        UPDATE operational_hazard_observation_jobs
        SET status = 'processing', lease_owner = 'crashed-worker',
          lease_expires_at = ?, claimed_at = ?, updated_at = ?
        WHERE event_id = ?
      `).run(expiredAt, expiredAt, expiredAt, eventId);
      const worker = new OperationalHazardObservationWorker(database, {
        hmacKey: HMAC_KEY,
        clock: () => new Date(NOW),
        workerId: "replacement-worker",
      });
      expect(worker.drain()).toEqual({ completed: 1, quarantined: 0 });
      expect((database.prepare(`
        SELECT occurrence_id, status, attempt_count
        FROM operational_hazard_observation_jobs WHERE event_id = ?
      `).get(eventId) as Record<string, unknown>)).toMatchObject({
        occurrence_id: first.occurrence.id,
        status: "completed",
        attempt_count: 1,
      });
      expect((database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_occurrences")
        .get() as { count: number }).count).toBe(1);
    } finally {
      database.close();
    }
  });

  test("aggregate reset minimum is operator-only", () => {
    const { database, service } = fixture();
    try {
      expect(() => service.reportAggregateResetMinimum({
        missionId: "mission-observation",
        runId: "run-observation",
        reportedMinimum: 11,
        actor: { id: "runtime:test", type: "worker" },
        idempotencyKey: "worker-cannot-report-minimum",
      })).toThrow(OperationalHazardObservationError);
    } finally {
      database.close();
    }
  });

  test("authenticated V2 router enforces identity, capability, scope, and idempotent reset staging", async () => {
    const { database } = fixture();
    let currentActor: { id: string; type: "operator" | "worker" } | undefined;
    let allowed = true;
    const app = express();
    app.use(express.json());
    app.use(createOperationalHazardObservationRouter({
      database,
      hmacKey: HMAC_KEY,
      resolveActor: () => currentActor,
      authorize: () => allowed,
      clock: () => new Date(NOW),
    }));
    const server: Server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${address.port}`;
    try {
      const totalsPath = `${base}/api/v2/missions/mission-observation/runs/run-observation/operational-hazards/reset-totals`;
      expect((await fetch(totalsPath)).status).toBe(403);

      currentActor = { id: "runtime:test", type: "worker" };
      const aggregatePath = `${base}/api/v2/missions/mission-observation/runs/run-observation/operational-hazards/reset-minimum-observations`;
      expect((await fetch(aggregatePath, {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": "worker-aggregate-denied" },
        body: JSON.stringify({ reportedMinimum: 11 }),
      })).status).toBe(403);

      currentActor = { id: "operator:test", type: "operator" };
      allowed = false;
      expect((await fetch(totalsPath)).status).toBe(403);
      allowed = true;
      const resetPath = `${base}/api/v2/missions/mission-observation/runs/run-observation/actions/action-reset-a/operational-hazard-reset`;
      const created = await fetch(resetPath, {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": "router-reset-observation" },
        body: "{}",
      });
      expect(created.status).toBe(201);
      expect((await created.json() as { replayed: boolean }).replayed).toBe(false);
      const replay = await fetch(resetPath, {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": "router-reset-observation" },
        body: "{}",
      });
      expect(replay.status).toBe(200);
      expect((await replay.json() as { replayed: boolean }).replayed).toBe(true);
      const totals = await fetch(totalsPath);
      expect(totals.status).toBe(200);
      expect(await totals.json()).toMatchObject({ exactAttributableResetCount: 1 });
      const missing = await fetch(resetPath.replace("action-reset-a", "action-missing"), {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": "router-missing-action" },
        body: "{}",
      });
      expect(missing.status).toBe(404);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      database.close();
    }
  });
});

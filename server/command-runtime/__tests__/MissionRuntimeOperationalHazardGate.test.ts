import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  MemoryRepository,
  operationalHazardRetryContractHash,
  type MemoryNodeType,
  type OperationalHazardReviewedRetryContract,
} from "../../memory";
import { ActionRepository, type DurableAction } from "../../orchestration";
import { AttackAttemptService } from "../../run-intelligence";
import {
  CommandRuntimeError,
  createMissionRuntime,
  type MissionPlannerPort,
  type ResultAwareExecutionPort,
} from "../index";

const NOW = "2026-07-20T12:00:00.000Z";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

class CapturingExecution implements ResultAwareExecutionPort {
  readonly dispatched: DurableAction[] = [];
  async dispatch(action: DurableAction): Promise<void> { this.dispatched.push(action); }
  async resume(): Promise<void> {}
  async cancelRun(): Promise<void> {}
}

function seed(database: SqliteDatabase, suffix: string) {
  const missionId = `mission-hazard-${suffix}`;
  const runId = `run-hazard-${suffix}`;
  const agentId = `agent-hazard-${suffix}`;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Guided operational-hazard fixture',
      'Validate one authorized disposable-lab procedure', 'guided', 'active',
      'verified', '{}', 'operator:test', ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES (?, ?, 'lab.internal', 'domain', 'allowed', 'lab.internal', ?)
  `).run(`target-hazard-${suffix}`, missionId, NOW);
  database.prepare(`
    INSERT INTO agents (id, role, display_name, status, version, created_at, updated_at)
    VALUES (?, 'validation-specialist', 'Validation specialist', 'available', 'test-1', ?, ?)
  `).run(agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'guided', 'planning', 0, 'Create a represented high-risk step',
      '{"wallClockMs":60000,"toolCalls":10,"providerTurns":10,"retries":2,"replans":2,"concurrency":1}',
      '{}', ?, ?, 1, 'ti_scale')
  `).run(runId, missionId, NOW, NOW);
  const assetId = `asset-hazard-${suffix}`;
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, confidence, verification_state,
      sensitivity, first_seen_at, last_seen_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'asset', 'Authorized disposable-lab service',
      'opaque-lab-service', 'allowed', 'observed', 1, 'verified', 'internal', ?, ?, ?, ?)
  `).run(assetId, missionId, runId, NOW, NOW, NOW, NOW);
  return { missionId, runId, agentId, assetId };
}

function planner(agentId: string): MissionPlannerPort {
  return {
    async plan() {
      return {
        strategySummary: "Represent one bounded validation attempt",
        rationaleSummary: "The exact attempt remains separately reviewable and health-gated",
        steps: [{
          phase: "Validation",
          title: "Validate the bounded server-side procedure",
          objective: "Confirm one authorized disposable-lab behavior",
          explanation: "The specialist performs one exact represented validation only after local safety checks.",
          rationale: "This avoids chaining or silently changing consequential actions.",
          successCriteria: ["One bounded response is retained"],
          dependencyOrdinals: [],
          assignedAgentId: agentId,
          riskClass: "high",
          reversibility: "Disposable lab worker can be recycled",
          action: {
            actionType: "bounded_server_validation",
            actionClass: "exploit_validation",
            target: "lab.internal",
            arguments: { target: "lab.internal", probe: "bounded" },
            intentSummary: "Run one exact bounded validation request",
            kind: "tool",
            idempotent: false,
            destructive: false,
          },
        }],
      };
    },
  };
}

function pendingDecision(database: SqliteDatabase, runId: string) {
  return database.prepare(`
    SELECT gd.id, gd.step_id, ps.plan_id
    FROM guided_decisions gd
    JOIN plan_steps ps ON ps.id = gd.step_id
    WHERE gd.run_id = ? AND gd.status = 'pending'
  `).get(runId) as { id: string; step_id: string; plan_id: string };
}

function readyAttackAttempt(
  database: SqliteDatabase,
  fixture: ReturnType<typeof seed>,
  decision: ReturnType<typeof pendingDecision>,
) {
  const service = new AttackAttemptService(database, () => new Date(NOW));
  const attempt = service.create({
    missionId: fixture.missionId,
    runId: fixture.runId,
    planId: decision.plan_id,
    stepId: decision.step_id,
    targetAssetId: fixture.assetId,
    objective: "Validate one bounded server-side procedure",
    techniqueName: "Bounded server-side behavior validation",
    actionClass: "exploit_validation",
    assignedAgentId: fixture.agentId,
    normalizedParameters: { probe: "bounded" },
  });
  return service.transition({
    attemptId: attempt.id,
    expectedVersion: attempt.version,
    status: "ready",
    actorId: "operator:test",
    actorType: "operator",
  });
}

function verifiedNode(repository: MemoryRepository, id: string, nodeType: MemoryNodeType): void {
  repository.createNode({
    id,
    nodeType,
    title: `${nodeType.replaceAll("_", " ")} reviewed fixture`,
    summary: "Generalized verified procedure knowledge with private operational sources retained separately.",
    body: "Apply only when the exact bound procedure, version, stack, parameters, and state match.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.98,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "A trusted local evaluation repeatedly reproduced and an operator reviewed this knowledge.",
      sources: [{ sourceType: "evaluation", sourceId: `source-${id}`, acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "operator:test",
    retentionPolicy: { journeys: ["autonomous", "guided"] },
  });
}

function opaqueMemoryId(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

function bindRepeatedHazard(
  database: SqliteDatabase,
  runtime: ReturnType<typeof createMissionRuntime>,
  attackAttemptId: string,
) {
  const repository = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const ids = {
    procedure: opaqueMemoryId("procedure-bounded-validation"),
    procedureVersion: opaqueMemoryId("procedure-version-reviewed"),
    saferProcedureVersion: opaqueMemoryId("procedure-version-bounded-safer"),
    product: opaqueMemoryId("product-reviewed-service"),
    version: opaqueMemoryId("version-reviewed-service"),
    stack: opaqueMemoryId("stack-reviewed-runtime"),
    hazard: opaqueMemoryId("hazard-repeated-worker-hang"),
  } as const;
  verifiedNode(repository, ids.procedure, "attack_procedure");
  verifiedNode(repository, ids.procedureVersion, "procedure_version");
  verifiedNode(repository, ids.saferProcedureVersion, "procedure_version");
  verifiedNode(repository, ids.product, "technology_product");
  verifiedNode(repository, ids.version, "exact_version_fingerprint");
  verifiedNode(repository, ids.stack, "runtime");
  verifiedNode(repository, ids.hazard, "operational_hazard");
  const safeRetryStatement = "Confirm the read-only health check returns the expected bounded result";
  const reviewedRetryContract: OperationalHazardReviewedRetryContract = {
    schema: "ti_scale.operational_hazard_retry_contract/v1",
    alternativeKind: "structured_delta",
    source: {
      procedureNodeId: ids.procedure,
      procedureVersionNodeId: ids.procedureVersion,
      normalizedParameters: { payload_shape: "bounded-print-probe" },
      load: 1,
      concurrency: 1,
      timingWindowMs: 2_000,
    },
    alternative: {
      procedureNodeId: ids.procedure,
      procedureVersionNodeId: ids.saferProcedureVersion,
      normalizedParameters: { payload_shape: "bounded-safer" },
      load: 1,
      concurrency: 1,
      timingWindowMs: 2_000,
    },
    retryValidConditions: [{
      id: "baseline_restored",
      statement: safeRetryStatement,
      evidenceKey: "baselineRestored",
    }],
  };
  database.prepare(`
    INSERT INTO operational_hazard_profiles (
      node_id, procedure_node_id, procedure_version_node_id,
      product_node_ids_json, version_node_ids_json, stack_node_ids_json,
      prerequisite_node_ids_json, observed_state_node_ids_json,
      ordered_steps_json, normalized_parameters_json,
      load_min, concurrency_min, timing_window_ms,
      observed_symptom, affected_component, state_before, state_after,
      reproducibility_count, attempt_count, recovery_action_summary,
      recovery_cost_json, unsafe_retry_conditions_json, safe_retry_gate_json,
      alternative_sequence_json, applicability_constraints_json,
      reviewed_retry_contract_json,
      confidence, observed_at, fresh_until, version, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, '[]', '[]', ?, ?, 1, 1, 5000,
      'The disposable worker stopped returning bounded responses',
      'Server-side worker', 'Healthy response path', 'Wedged response path',
      2, 2, 'Recycle the disposable worker and prove health',
      '{"resetCount":2,"operatorReportedResetCountMinimum":11,"serviceRecycleCount":2,"requiresDisposableTargetReset":true}',
      ?, ?, ?, '{}', ?,
      0.98, ?, '2026-08-20T12:00:00.000Z', 1, ?, ?)
  `).run(
    ids.hazard,
    ids.procedure,
    ids.procedureVersion,
    JSON.stringify([ids.product]),
    JSON.stringify([ids.version]),
    JSON.stringify([ids.stack]),
    JSON.stringify(["Run a read-only health check", "Run one bounded validation request"]),
    JSON.stringify({ payload_shape: "bounded-print-probe" }),
    JSON.stringify(["The health check is still failing"]),
    JSON.stringify([safeRetryStatement]),
    JSON.stringify([
      "Run the read-only health check",
      "Recycle the disposable worker if unhealthy",
      "Represent one new bounded attempt only after health is restored",
    ]),
    JSON.stringify(reviewedRetryContract),
    "2026-07-19T12:00:00.000Z",
    NOW,
    NOW,
  );
  runtime.operationalHazards.bindAttackAttempt({
    attackAttemptId,
    procedureNodeId: ids.procedure,
    procedureVersionNodeId: ids.procedureVersion,
    productNodeIds: [ids.product],
    versionNodeIds: [ids.version],
    stackNodeIds: [ids.stack],
    prerequisiteNodeIds: [],
    observedStateNodeIds: [],
    normalizedParameters: { payload_shape: "bounded-print-probe" },
    load: 1,
    concurrency: 1,
    timingWindowMs: 2_000,
  });
  return { ...ids, reviewedRetryContract };
}

function prepareRecoveryAttempt(
  database: SqliteDatabase,
  runtime: ReturnType<typeof createMissionRuntime>,
  fixture: ReturnType<typeof seed>,
  decision: ReturnType<typeof pendingDecision>,
  suffix: string,
  linked: boolean,
) {
  const sourceStepId = `step-hazard-source-${suffix}`;
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      assigned_agent_id, action_class, risk_class, created_at, updated_at
    ) VALUES (?, ?, ?, 99, 'Recovery', 'Preserved known-bad attempt',
      'Retain the exact failed procedure without repeating it', 'ready', ?,
      'exploit_validation', 'high', ?, ?)
  `).run(sourceStepId, decision.plan_id, fixture.runId, fixture.agentId, NOW, NOW);
  const attempts = new AttackAttemptService(database, () => new Date(NOW));
  const sourceCreated = attempts.create({
    missionId: fixture.missionId,
    runId: fixture.runId,
    planId: decision.plan_id,
    stepId: sourceStepId,
    targetAssetId: fixture.assetId,
    objective: "Preserve the exact failed procedure",
    techniqueName: "Reviewed bounded procedure",
    actionClass: "exploit_validation",
    assignedAgentId: fixture.agentId,
    normalizedParameters: { represented: true },
  });
  const sourceReady = attempts.transition({
    attemptId: sourceCreated.id,
    expectedVersion: sourceCreated.version,
    status: "ready",
    actorId: "operator:test",
    actorType: "operator",
  });
  const ids = bindRepeatedHazard(database, runtime, sourceReady.id);
  const source = attempts.transition({
    attemptId: sourceReady.id,
    expectedVersion: sourceReady.version,
    status: "waiting_conditions",
    reason: "Exact verified operational hazard requires a represented local health check",
    actorId: "operational-hazard-gate",
    actorType: "system",
  });
  const candidateCreated = attempts.create({
    missionId: fixture.missionId,
    runId: fixture.runId,
    planId: decision.plan_id,
    stepId: decision.step_id,
    targetAssetId: fixture.assetId,
    ...(linked ? { recoverySourceAttackAttemptId: source.id } : {}),
    objective: "Run one explicitly distinct bounded recovery attempt",
    techniqueName: "Reviewed bounded procedure",
    actionClass: "exploit_validation",
    assignedAgentId: fixture.agentId,
    normalizedParameters: { represented: true },
    representedActionBinding: {
      actionType: "bounded_server_validation",
      actionClass: "exploit_validation",
      normalizedArguments: { target: "lab.internal", probe: "bounded" },
      scopedTarget: "lab.internal",
    },
    reviewedKnowledgeBinding: {
      procedureNodeId: ids.procedure,
      procedureVersionNodeId: ids.saferProcedureVersion,
      productNodeIds: [ids.product],
      versionNodeIds: [ids.version],
      stackNodeIds: [ids.stack],
      prerequisiteNodeIds: [],
      observedStateNodeIds: [],
      normalizedParameters: { payload_shape: "bounded-safer" },
      load: 1,
      concurrency: 1,
      timingWindowMs: 2_000,
    },
  });
  const candidate = attempts.transition({
    attemptId: candidateCreated.id,
    expectedVersion: candidateCreated.version,
    status: "ready",
    actorId: "operator:test",
    actorType: "operator",
  });
  return { source, candidate, ids };
}

function recordPassingHealthAssessment(
  database: SqliteDatabase,
  runtime: ReturnType<typeof createMissionRuntime>,
  fixture: ReturnType<typeof seed>,
  decision: ReturnType<typeof pendingDecision>,
  recovery: ReturnType<typeof prepareRecoveryAttempt>,
  suffix: string,
) {
  const healthStepId = `step-hazard-health-${suffix}`;
  const healthActionId = `action-hazard-health-${suffix}`;
  const evidenceId = `evidence-hazard-health-${suffix}`;
  const contextPackId = `pack-hazard-health-${suffix}`;
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      assigned_agent_id, action_class, risk_class, created_at, updated_at
    ) VALUES (?, ?, ?, 100, 'Recovery', 'Represented local health check',
      'Prove the private target baseline before one safer attempt', 'completed', ?,
      'passive_intelligence_osint', 'low', ?, ?)
  `).run(healthStepId, decision.plan_id, fixture.runId, fixture.agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, action_type, action_class, fingerprint,
      normalized_arguments_json, scoped_target, status, intent_summary,
      result_summary, retry_count, started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'operational_hazard_health_check',
      'passive_intelligence_osint', ?, ?, 'lab.internal', 'succeeded',
      'Check the exact private target baseline', 'Baseline restored', 0, ?, ?, ?, ?)
  `).run(
    healthActionId, fixture.missionId, fixture.runId, healthStepId, "c".repeat(64),
    JSON.stringify({
      input: {
        hazardNodeId: recovery.ids.hazard,
        hazardProfileVersion: 1,
        blockedAttackAttemptId: recovery.source.id,
        contextPackId,
      },
      orchestration: { kind: "tool", idempotent: true, destructive: false },
    }),
    NOW, NOW, NOW, NOW,
  );
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, 'local_tool_health_verifier', ?, 'lab.internal',
      'health_check_result', ?, ?, 1, 'private', 'verified',
      'Trusted local evaluator confirmed the baseline response',
      'local-evidence-verifier', ?)
  `).run(
    evidenceId, fixture.missionId, fixture.runId, healthStepId, healthActionId,
    NOW, "d".repeat(64), JSON.stringify({
      method: "local_tool_verification",
      boundary: "trusted_local",
      healthAssessment: {
        schema: "ti_scale.operational_health/v2",
        baselineRestored: true,
        retryContractHash: operationalHazardRetryContractHash(recovery.ids.reviewedRetryContract),
        retryConditionResults: { baselineRestored: true },
      },
    }), NOW,
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES (?, ?, 'verified', 'local-evidence-verifier',
      '{"method":"local_evaluator"}', ?)
  `).run(`custody-hazard-health-${suffix}`, evidenceId, NOW);
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, step_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json, created_by, created_at
    ) VALUES (?, ?, ?, ?, 'guided', 'Operational hazard health gate',
      'Exact reviewed hazard health gate', '{}', 3000, '{}',
      'local-operational-hazard-evaluator', ?)
  `).run(contextPackId, fixture.missionId, fixture.runId, healthStepId, NOW);
  const insertItem = database.prepare(`
    INSERT INTO memory_context_items (
      context_pack_id, node_id, rank, retrieval_score, used,
      relevance_reason, influence_summary
    ) VALUES (?, ?, ?, 1, 1, 'Exact reviewed gate input', 'Required the local health gate')
  `);
  [recovery.ids.hazard, recovery.ids.procedure, recovery.ids.procedureVersion]
    .forEach((nodeId, rank) => insertItem.run(contextPackId, nodeId, rank));
  const assessment = runtime.operationalHazardHealthGate.recordAssessmentForCompletedAction(
    new ActionRepository(database).get(healthActionId),
    { id: "local-health-worker", type: "worker" },
  );
  if (!assessment) throw new Error("Expected the represented health action to create an assessment");
  return assessment;
}

function expectRuntimeCode(error: unknown, code: string): CommandRuntimeError {
  expect(error).toBeInstanceOf(CommandRuntimeError);
  expect((error as CommandRuntimeError).code).toBe(code);
  return error as CommandRuntimeError;
}

describe("MissionRuntimeEngine operational-hazard pre-execution gate", () => {
  test("never routes a represented physical reset through the generic execution adapter", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database, "reset-router");
    const execution = new CapturingExecution();
    const resetPlanner: MissionPlannerPort = {
      async plan() {
        return {
          strategySummary: "Represent one explicit disposable-lab reset",
          rationaleSummary: "A physical reset requires the distinct reviewed local controller boundary",
          steps: [{
            phase: "Recovery",
            title: "Reset the disposable target",
            objective: "Restore the isolated target baseline once",
            explanation: "The local reset controller must attest the reset and before/after health state.",
            rationale: "Generic tool execution must never receive physical reset authority.",
            successCriteria: ["A reviewed controller proves the fresh baseline"],
            dependencyOrdinals: [],
            assignedAgentId: fixture.agentId,
            riskClass: "high",
            reversibility: "Disposable target reset",
            action: {
              actionType: "target_reset",
              actionClass: "cleanup_restoration",
              target: "lab.internal",
              arguments: { representedReset: true },
              intentSummary: "Reset the disposable target once",
              kind: "tool",
              idempotent: false,
              destructive: false,
            },
          }],
        };
      },
    };
    const runtime = createMissionRuntime({
      database,
      planner: resetPlanner,
      outcomeEvaluator: { async evaluate() { throw new Error("blocked run must not evaluate"); } },
      execution,
      workerId: "hazard-worker-reset-router",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const decision = pendingDecision(database, fixture.runId);
      let failure: unknown;
      try {
        await runtime.approveGuidedDecision(
          decision.id,
          "operator:test",
          "Run this one represented disposable-target reset",
        );
      } catch (error) {
        failure = error;
      }
      const runtimeError = expectRuntimeCode(failure, "trusted_reset_controller_unavailable");
      expect(runtimeError.options.category).toBe("dependency_missing");
      expect(runtimeError.options.humanMessage).toContain("stopped before dispatch");
      expect(execution.dispatched).toEqual([]);
      expect(database.prepare("SELECT COUNT(*) AS count FROM operational_reset_authorizations")
        .get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM operational_reset_control_receipts")
        .get()).toEqual({ count: 0 });
    } finally {
      await runtime.stop();
    }
  });

  test("fails closed before a high-risk first-class attempt with no exact procedure binding", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database, "missing-binding");
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner: planner(fixture.agentId),
      outcomeEvaluator: { async evaluate() { throw new Error("blocked run must not evaluate"); } },
      execution,
      workerId: "hazard-worker-missing-binding",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const decision = pendingDecision(database, fixture.runId);
      readyAttackAttempt(database, fixture, decision);
      let failure: unknown;
      try {
        await runtime.approveGuidedDecision(decision.id, "operator:test", "Run this exact represented step");
      } catch (error) {
        failure = error;
      }
      const runtimeError = expectRuntimeCode(failure, "attack_procedure_knowledge_required");
      expect(runtimeError.options.details).toMatchObject({ inferredFromTargetOrName: false });
      expect(execution.dispatched).toEqual([]);
      expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(fixture.runId))
        .toEqual({ status: "blocked" });
      expect(database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?").get(fixture.runId))
        .toEqual({ count: 0 });
    } finally {
      await runtime.stop();
    }
  });

  test("safe-stops an exact repeatedly reproduced hazard, persists Context Pack use, and dispatches no tool", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database, "repeated-hang");
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner: planner(fixture.agentId),
      outcomeEvaluator: { async evaluate() { throw new Error("blocked run must not evaluate"); } },
      execution,
      workerId: "hazard-worker-repeated-hang",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const decision = pendingDecision(database, fixture.runId);
      const attempt = readyAttackAttempt(database, fixture, decision);
      const ids = bindRepeatedHazard(database, runtime, attempt.id);
      let failure: unknown;
      try {
        await runtime.approveGuidedDecision(decision.id, "operator:test", "Run this exact represented step");
      } catch (error) {
        failure = error;
      }
      const runtimeError = expectRuntimeCode(failure, "operational_hazard_health_gate_required");
      expect(runtimeError.options.details).toMatchObject({
        attackAttemptId: attempt.id,
        matchedHazardNodeIds: [ids.hazard],
        automaticRetryPermitted: false,
        targetContacted: false,
      });
      expect(execution.dispatched).toEqual([]);
      expect(database.prepare(`
        SELECT status, outcome_summary FROM attack_attempts WHERE id = ?
      `).get(attempt.id)).toEqual({
        status: "waiting_conditions",
        outcome_summary: "Execution prevented until the represented operational health gate is satisfied",
      });
      const binding = database.prepare(`
        SELECT context_pack_id FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = ?
      `).get(attempt.id) as { context_pack_id: string };
      expect(binding.context_pack_id).toBeTruthy();
      expect(database.prepare(`
        SELECT COUNT(*) AS count, MIN(used) AS all_used,
          SUM(CASE WHEN influence_summary IS NOT NULL THEN 1 ELSE 0 END) AS influenced
        FROM memory_context_items WHERE context_pack_id = ?
      `).get(binding.context_pack_id)).toMatchObject({ all_used: 1 });
      const pack = database.prepare(`
        SELECT query_redacted, scope_policy_json FROM memory_context_packs WHERE id = ?
      `).get(binding.context_pack_id) as { query_redacted: string; scope_policy_json: string };
      expect(pack.query_redacted).not.toContain("lab.internal");
      expect(pack.scope_policy_json).not.toContain("lab.internal");
      expect(database.prepare(`
        SELECT summary, context_pack_id,
          json_extract(payload_json, '$.retryMustReevaluate') AS retry_must_reevaluate,
          json_extract(payload_json, '$.targetIdentifiersPersistedInReusableContext') AS target_ids_persisted
        FROM events
        WHERE run_id = ? AND event_type = 'attack_attempt.operational_hazard_assessed'
      `).get(fixture.runId)).toMatchObject({
        context_pack_id: binding.context_pack_id,
        retry_must_reevaluate: 1,
        target_ids_persisted: 0,
      });
      await runtime.scanOnce();
      expect(execution.dispatched).toEqual([]);
    } finally {
      await runtime.stop();
    }
  });

  test("a new attempt ID cannot bypass unresolved same-target recovery lineage", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database, "unlinked-recovery");
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner: planner(fixture.agentId),
      outcomeEvaluator: { async evaluate() { throw new Error("blocked run must not evaluate"); } },
      execution,
      workerId: "hazard-worker-unlinked-recovery",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const decision = pendingDecision(database, fixture.runId);
      const recovery = prepareRecoveryAttempt(
        database, runtime, fixture, decision, "unlinked-recovery", false,
      );
      let failure: unknown;
      try {
        await runtime.approveGuidedDecision(
          decision.id,
          "operator:test",
          "Try the separately represented safer version",
        );
      } catch (error) {
        failure = error;
      }
      const runtimeError = expectRuntimeCode(failure, "hazard_retry_lineage_required");
      expect(runtimeError.options.humanMessage).toContain("same canonical target");
      expect(runtimeError.options.remediation).toContain("immutable recovery source");
      expect(execution.dispatched).toEqual([]);
      expect(database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?")
        .get(fixture.runId)).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_retry_authorizations")
        .get()).toEqual({ count: 0 });
    } finally {
      await runtime.stop();
    }
  });

  test("a locally verified health result plus exact operator authorization dispatches one action and atomically consumes it", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database, "authorized-recovery");
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner: planner(fixture.agentId),
      outcomeEvaluator: { async evaluate() { throw new Error("active action must not evaluate"); } },
      execution,
      workerId: "hazard-worker-authorized-recovery",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const decision = pendingDecision(database, fixture.runId);
      const recovery = prepareRecoveryAttempt(
        database, runtime, fixture, decision, "authorized-recovery", true,
      );
      const assessment = recordPassingHealthAssessment(
        database, runtime, fixture, decision, recovery, "authorized-recovery",
      );
      const authorization = runtime.authorizeOperationalHazardRecovery({
        runId: fixture.runId,
        healthAssessmentId: assessment.id,
        attackAttemptId: recovery.candidate.id,
        operatorId: "operator:test",
        ttlMs: 60_000,
      });
      expect(authorization).toMatchObject({
        sourceAttackAttemptId: recovery.source.id,
        authorizedAttackAttemptId: recovery.candidate.id,
        authorizationBasis: "distinct_procedure_version",
        maxAttempts: 1,
        automaticRetry: false,
      });

      const action = await runtime.approveGuidedDecision(
        decision.id,
        "operator:test",
        "Run this one exact safer represented action",
      );
      expect(action).toMatchObject({
        runId: fixture.runId,
        stepId: decision.step_id,
        actionType: "bounded_server_validation",
        actionClass: "exploit_validation",
        arguments: { target: "lab.internal", probe: "bounded" },
        target: "lab.internal",
        status: "running",
      });
      expect(execution.dispatched).toHaveLength(1);
      expect(execution.dispatched[0]?.id).toBe(action.id);
      expect(database.prepare(`
        SELECT authorization_id, attack_attempt_id, action_id
        FROM operational_hazard_retry_consumptions
      `).get()).toEqual({
        authorization_id: authorization.id,
        attack_attempt_id: recovery.candidate.id,
        action_id: action.id,
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM events
        WHERE run_id = ? AND event_type = 'operational_hazard.safer_attempt_consumed'
      `).get(fixture.runId)).toEqual({ count: 1 });
    } finally {
      await runtime.stop();
    }
  });
});

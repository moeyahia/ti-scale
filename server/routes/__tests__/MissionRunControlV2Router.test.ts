import { afterEach, describe, expect, test } from "bun:test";
import express, { type Request } from "express";
import { createHash } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createMissionRuntime,
  type MissionOutcomeEvaluatorPort,
  type MissionPlannerPort,
  type ResultAwareExecutionPort,
  type ResumeRunBoundary,
} from "../../command-runtime";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  MemoryRepository,
  OperationalHazardProfileRepository,
  operationalHazardRetryContractHash,
  type MemoryNodeType,
  type OperationalHazardContext,
  type OperationalHazardReviewedRetryContract,
} from "../../memory";
import { ActionRepository, type DurableAction } from "../../orchestration";
import { hashJson } from "../../orchestration/serialization";
import { AttackAttemptService } from "../../run-intelligence";
import {
  createMissionRunControlV2Router,
  createMissionRuntimeV2Router,
} from "../missionRuntimeV2Routes";

const NOW = "2026-07-16T12:00:00.000Z";
const servers: Server[] = [];
const databases: SqliteDatabase[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  for (const database of databases.splice(0)) database.close();
});

class NoopExecution implements ResultAwareExecutionPort {
  async dispatch(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async cancelRun(_runId: string, _reason: string): Promise<void> {}
}

const planner: MissionPlannerPort = {
  async plan() {
    throw new Error("Planning is outside this focused run-control test");
  },
};

const evaluator: MissionOutcomeEvaluatorPort = {
  async evaluate() {
    return { success: false, summary: "Cancelled by the operator", criteria: [] };
  },
};

function seedGuidedRun(database: SqliteDatabase, suffix: string): {
  missionId: string;
  runId: string;
  planId: string;
  stepId: string;
  assignmentId: string;
} {
  const missionId = `mission-${suffix}`;
  const runId = `run-${suffix}`;
  const planId = `plan-${suffix}`;
  const stepId = `step-${suffix}`;
  const assignmentId = `assignment-${suffix}`;
  const agentId = `agent-${suffix}`;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Run control test', 'Exercise the exact run control boundary',
      'guided', 'active', 'verified', 'operator:test', ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (?, 'recon-specialist', 'Recon specialist', 'available', 'test-1', ?, ?)
  `).run(agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id,
      current_owner_id, progress, status_reason, next_action_summary,
      budget_json, budget_usage_json, started_at, created_at, updated_at,
      version, control_plane
    ) VALUES (?, ?, 'guided', 'waiting_guided_decision', ?, ?, ?, 0.25,
      'Waiting at one represented Guided decision', 'Wait for the exact decision',
      '{"retries":2,"replans":2,"concurrency":1}', '{}', ?, ?, ?, 1,
      'ti_scale')
  `).run(runId, missionId, planId, stepId, agentId, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Collect one bounded observation', ?,
      'planner:test', ?, ?)
  `).run(planId, runId, "a".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      assigned_agent_id, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'Recon', 'Observe service', 'Reduce uncertainty',
      'waiting_guided_decision', ?, ?, ?)
  `).run(stepId, planId, runId, agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
      last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'queued', NULL, NULL, NULL, NULL, NULL, ?, ?)
  `).run(assignmentId, runId, stepId, agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO guided_decisions (
      id, mission_id, run_id, step_id, requested_action_fingerprint,
      requested_parameters_json, rationale, risk_class, reversibility,
      status, expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, '{}', 'Wait for one exact operator decision',
      'low', 'Read-only', 'pending', '2026-07-17T12:00:00.000Z', ?)
  `).run(`decision-${suffix}`, missionId, runId, stepId, "b".repeat(64), NOW);
  return { missionId, runId, planId, stepId, assignmentId };
}

function opaqueMemoryId(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

function addReviewedKnowledgeNode(
  repository: MemoryRepository,
  id: string,
  nodeType: MemoryNodeType,
): void {
  repository.createNode({
    id,
    nodeType,
    title: `${nodeType.replaceAll("_", " ")} reviewed knowledge`,
    summary: "Generalized reusable procedure knowledge with private operational sources retained separately.",
    body: "Use only when the typed procedure, version, stack, parameters, and current state match.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.98,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "A trusted local evaluator and operator review established this reusable relationship.",
      sources: [{ sourceType: "evaluation", sourceId: `receipt-${id}`, acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "operator:test",
    retentionPolicy: { journeys: ["autonomous", "guided"] },
  });
}

function seedHazardAuthorizationBoundary(
  database: SqliteDatabase,
  fixture: ReturnType<typeof seedGuidedRun>,
  suffix: string,
) {
  const assetId = `asset-hazard-route-${suffix}`;
  const sourceStepId = `step-hazard-source-${suffix}`;
  const healthStepId = `step-hazard-health-${suffix}`;
  const healthActionId = `action-hazard-health-${suffix}`;
  const evidenceId = `evidence-hazard-health-${suffix}`;
  const contextPackId = `pack-hazard-health-${suffix}`;
  const target = `service-${suffix}.local`;

  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES (?, ?, ?, 'domain', 'allowed', ?, ?)
  `).run(`target-hazard-route-${suffix}`, fixture.missionId, target, target, NOW);
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, properties_json, confidence,
      verification_state, sensitivity, first_seen_at, last_seen_at,
      created_at, updated_at
    ) VALUES (?, ?, ?, 'asset', 'Authorized disposable service', ?, 'allowed',
      'observed', '{"environment":"disposable"}', 1, 'verified', 'private', ?, ?, ?, ?)
  `).run(assetId, fixture.missionId, fixture.runId, target, NOW, NOW, NOW, NOW);
  database.prepare(`
    UPDATE plan_steps SET action_class = 'exploit_validation', risk_class = 'high'
    WHERE id = ?
  `).run(fixture.stepId);
  const insertStep = database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      action_class, risk_class, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'Validation', ?, 'Prove the local safety boundary',
      'ready', ?, ?, ?, ?)
  `);
  insertStep.run(
    sourceStepId, fixture.planId, fixture.runId, 1, "Preserved failed attempt",
    "exploit_validation", "high", NOW, NOW,
  );
  insertStep.run(
    healthStepId, fixture.planId, fixture.runId, 2, "Represented local health check",
    "passive_intelligence_osint", "low", NOW, NOW,
  );

  const ids = {
    hazard: opaqueMemoryId(`route-hazard-${suffix}`),
    procedure: opaqueMemoryId(`route-procedure-${suffix}`),
    procedureVersion: opaqueMemoryId(`route-procedure-version-known-bad-${suffix}`),
    saferProcedureVersion: opaqueMemoryId(`route-procedure-version-safer-${suffix}`),
    product: opaqueMemoryId(`route-product-${suffix}`),
    version: opaqueMemoryId(`route-version-${suffix}`),
    stack: opaqueMemoryId(`route-stack-${suffix}`),
  } as const;
  const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
  addReviewedKnowledgeNode(memory, ids.hazard, "operational_hazard");
  addReviewedKnowledgeNode(memory, ids.procedure, "attack_procedure");
  addReviewedKnowledgeNode(memory, ids.procedureVersion, "procedure_version");
  addReviewedKnowledgeNode(memory, ids.saferProcedureVersion, "procedure_version");
  addReviewedKnowledgeNode(memory, ids.product, "technology_product");
  addReviewedKnowledgeNode(memory, ids.version, "exact_version_fingerprint");
  addReviewedKnowledgeNode(memory, ids.stack, "runtime");
  const safeRetryStatement = "A trusted local health result proves the baseline is restored";
  const reviewedRetryContract: OperationalHazardReviewedRetryContract = {
    schema: "ti_scale.operational_hazard_retry_contract/v1",
    alternativeKind: "structured_delta",
    source: {
      procedureNodeId: ids.procedure,
      procedureVersionNodeId: ids.procedureVersion,
      normalizedParameters: { payload_shape: "known-bad" },
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
  new OperationalHazardProfileRepository(database, { clock: () => new Date(NOW) }).create({
    hazardNodeId: ids.hazard,
    procedureNodeId: ids.procedure,
    procedureVersionNodeId: ids.procedureVersion,
    productNodeIds: [ids.product],
    versionNodeIds: [ids.version],
    stackNodeIds: [ids.stack],
    prerequisiteNodeIds: [],
    observedStateNodeIds: [],
    orderedSteps: ["Prove baseline health", "Use one bounded safer attempt"],
    normalizedParameters: { payload_shape: "known-bad" },
    loadMinimum: 1,
    concurrencyMinimum: 1,
    timingWindowMs: 5_000,
    observedSymptom: "The application worker stopped returning responses",
    affectedComponent: "Managed application worker",
    stateBefore: "Healthy bounded-response state",
    stateAfter: "Wedged response state",
    reproducibilityCount: 2,
    attemptCount: 2,
    recoveryActionSummary: "Recycle the disposable worker and prove baseline health",
    recoveryCost: {
      resetCount: 2,
      operatorReportedResetCountMinimum: 11,
      serviceRecycleCount: 2,
      requiresDisposableTargetReset: true,
    },
    unsafeRetryConditions: ["Baseline health check is failing"],
    safeRetryGate: [safeRetryStatement],
    alternativeSequence: ["Restore the baseline", "Use the safer variant once"],
    reviewedRetryContract,
    confidence: 0.98,
    observedAt: NOW,
    freshUntil: "2026-07-17T12:00:00.000Z",
  });

  const exactContext = (procedureVersionNodeId: string, payload: string): OperationalHazardContext => ({
    procedureNodeId: ids.procedure,
    procedureVersionNodeId,
    productNodeIds: [ids.product],
    versionNodeIds: [ids.version],
    stackNodeIds: [ids.stack],
    prerequisiteNodeIds: [],
    observedStateNodeIds: [],
    normalizedParameters: { payload_shape: payload },
    load: 1,
    concurrency: 1,
    timingWindowMs: 2_000,
  });
  const attempts = new AttackAttemptService(database, () => new Date(NOW));
  const sourceCreated = attempts.create({
    missionId: fixture.missionId,
    runId: fixture.runId,
    planId: fixture.planId,
    stepId: sourceStepId,
    targetAssetId: assetId,
    objective: "Preserve the exact failed procedure",
    techniqueName: "Reviewed procedure",
    actionClass: "exploit_validation",
    normalizedParameters: { represented: true },
    reviewedKnowledgeBinding: exactContext(ids.procedureVersion, "known-bad"),
  });
  const sourceReady = attempts.transition({
    attemptId: sourceCreated.id,
    expectedVersion: sourceCreated.version,
    status: "ready",
    actorId: "operator:test",
    actorType: "operator",
  });
  const source = attempts.transition({
    attemptId: sourceReady.id,
    expectedVersion: sourceReady.version,
    status: "waiting_conditions",
    reason: "Exact verified operational hazard requires a represented health check",
    actorId: "operational-hazard-gate",
    actorType: "system",
  });
  const candidateCreated = attempts.create({
    missionId: fixture.missionId,
    runId: fixture.runId,
    planId: fixture.planId,
    stepId: fixture.stepId,
    targetAssetId: assetId,
    recoverySourceAttackAttemptId: source.id,
    objective: "Run one explicitly distinct bounded recovery attempt",
    techniqueName: "Reviewed safer procedure",
    actionClass: "exploit_validation",
    normalizedParameters: { represented: true },
    representedActionBinding: {
      actionType: "bounded_safer_validation",
      actionClass: "exploit_validation",
      normalizedArguments: { probe: "bounded" },
      scopedTarget: target,
    },
    reviewedKnowledgeBinding: exactContext(ids.saferProcedureVersion, "bounded-safer"),
  });
  const candidate = attempts.transition({
    attemptId: candidateCreated.id,
    expectedVersion: candidateCreated.version,
    status: "ready",
    actorId: "operator:test",
    actorType: "operator",
  });

  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, action_type, action_class, fingerprint,
      normalized_arguments_json, scoped_target, status, intent_summary,
      result_summary, retry_count, started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'operational_hazard_health_check',
      'passive_intelligence_osint', ?, ?, ?, 'succeeded',
      'Check the exact private target baseline', 'Baseline restored', 0, ?, ?, ?, ?)
  `).run(
    healthActionId, fixture.missionId, fixture.runId, healthStepId, "d".repeat(64),
    JSON.stringify({
      input: {
        hazardNodeId: ids.hazard,
        hazardProfileVersion: 1,
        blockedAttackAttemptId: source.id,
        contextPackId,
      },
      orchestration: { kind: "tool", idempotent: true, destructive: false },
    }),
    target, NOW, NOW, NOW, NOW,
  );
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, step_id, action_id, source, acquired_at, target,
      evidence_type, content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, 'local_tool_health_verifier', ?, ?,
      'health_check_result', ?, ?, 1, 'private', 'verified',
      'Trusted local evaluator confirmed the baseline response',
      'local-evidence-verifier', ?)
  `).run(
    evidenceId, fixture.missionId, fixture.runId, healthStepId, healthActionId,
    NOW, target, "e".repeat(64), JSON.stringify({
      method: "local_tool_verification",
      boundary: "trusted_local",
      healthAssessment: {
        schema: "ti_scale.operational_health/v2",
        baselineRestored: true,
        retryContractHash: operationalHazardRetryContractHash(reviewedRetryContract),
        retryConditionResults: { baselineRestored: true },
      },
    }), NOW,
  );
  database.prepare(`
    INSERT INTO evidence_chain_events (
      id, evidence_id, event_type, actor, details_json, occurred_at
    ) VALUES (?, ?, 'verified', 'local-evidence-verifier', '{"method":"local_evaluator"}', ?)
  `).run(`custody-hazard-health-${suffix}`, evidenceId, NOW);
  database.prepare(`
    INSERT INTO memory_context_packs (
      id, mission_id, run_id, step_id, journey, purpose, query_redacted,
      scope_policy_json, context_budget, retrieval_metrics_json, created_by, created_at
    ) VALUES (?, ?, ?, ?, 'guided', 'Operational hazard health gate',
      'Exact reviewed hazard health gate', '{}', 3000, '{}',
      'local-operational-hazard-evaluator', ?)
  `).run(contextPackId, fixture.missionId, fixture.runId, healthStepId, NOW);
  const insertContextItem = database.prepare(`
    INSERT INTO memory_context_items (
      context_pack_id, node_id, rank, retrieval_score, used,
      relevance_reason, influence_summary
    ) VALUES (?, ?, ?, 1, 1, 'Exact reviewed gate input', 'Required the local health gate')
  `);
  [ids.hazard, ids.procedure, ids.procedureVersion]
    .forEach((nodeId, rank) => insertContextItem.run(contextPackId, nodeId, rank));

  return { candidate, source, healthActionId, contextPackId };
}

function seedLegacyAutonomousPlanningRateLimit(database: SqliteDatabase, suffix: string): {
  missionId: string;
  runId: string;
} {
  const missionId = `mission-${suffix}`;
  const runId = `run-${suffix}`;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'ReaperTwo', 'Plan the authorized lab assessment',
      'autonomous', 'active', 'verified', 'operator:test', ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      next_action_summary, budget_json, budget_usage_json, retry_count,
      replan_count, started_at, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'autonomous', 'blocked', 0,
      'The planning provider is rate-limited and no result was committed.',
      'Retry the first in-contract plan once the provider is available',
      '{"retries":2,"replans":2}', '{}', 0, 0, ?, ?, ?, 4, 'ti_scale')
  `).run(runId, missionId, NOW, NOW, NOW);
  const event = database.prepare(`
    INSERT INTO events (
      id, mission_id, run_id, sequence, event_type, occurred_at,
      actor_type, summary, payload_json, journey, sensitivity, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'autonomous', 'internal', ?)
  `);
  event.run(`event-${suffix}-created`, missionId, runId, 1, "mission.created", NOW,
    "operator", "Autonomous mission created", "{}", NOW);
  event.run(`event-${suffix}-planning`, missionId, runId, 2,
    "run.autonomous_planning_started", NOW, "system", "Autonomous planning started", "{}", NOW);
  event.run(`event-${suffix}-blocked`, missionId, runId, 3, "run.state_changed", NOW,
    "worker", "planning -> blocked: provider rate limit",
    '{"from":"planning","to":"blocked","stateVersion":4}', NOW);
  event.run(`event-${suffix}-safe-stop`, missionId, runId, 4,
    "run.autonomous_safe_stopped", NOW, "system",
    "The planning provider is rate-limited and no result was committed.",
    '{"code":"mission_runtime_rate_limit","category":"rate_limit"}', NOW);
  const state = {
    schemaVersion: 1 as const,
    run: {
      id: runId,
      missionId,
      journey: "autonomous" as const,
      state: "blocked" as const,
      stateVersion: 4,
      reason: "The planning provider is rate-limited and no result was committed.",
      leaseOwner: null,
      leaseExpiresAt: null,
    },
    control: {
      budget: { limits: { retries: 2, replans: 2 }, usage: {} },
      retryCount: 0,
      replanCount: 0,
      circuits: {},
      progress: {},
    },
    completedActionIds: [],
    inFlightActions: [],
    lastEventSequence: 3,
  };
  database.prepare(`
    INSERT INTO checkpoints (
      id, mission_id, run_id, journey, event_sequence, plan_version,
      state_json, state_hash, in_flight_classification, created_at
    ) VALUES (?, ?, ?, 'autonomous', 3, NULL, ?, ?, NULL, ?)
  `).run(`checkpoint-${suffix}`, missionId, runId, JSON.stringify(state), hashJson(state), NOW);
  return { missionId, runId };
}

type RuntimeCrashHook = NonNullable<Parameters<typeof createMissionRuntime>[0]["crashAfterCommit"]>;

function runtime(database: SqliteDatabase, workerId: string, crashAfterCommit?: RuntimeCrashHook) {
  return createMissionRuntime({
    database,
    planner,
    outcomeEvaluator: evaluator,
    execution: new NoopExecution(),
    workerId,
    leaseTtlMs: 2_000,
    now: () => new Date(NOW),
    ...(crashAfterCommit ? { crashAfterCommit } : {}),
  });
}

async function startApplication(
  database: SqliteDatabase,
  workerId: string,
  crashAfterCommit?: RuntimeCrashHook,
) {
  const engine = runtime(database, workerId, crashAfterCommit);
  const app = express();
  app.use(express.json());
  app.use(createMissionRunControlV2Router({ runtime: engine, resolveActor: () => "operator:test" }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return { engine, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

async function startRuntimeApplication(
  database: SqliteDatabase,
  workerId: string,
  resolveActor: (request: Request) => string,
) {
  const engine = runtime(database, workerId);
  const app = express();
  app.use(express.json());
  app.use(createMissionRuntimeV2Router({ runtime: engine, resolveActor }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return { engine, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

function resumeBoundary(engine: ReturnType<typeof runtime>, runId: string): ResumeRunBoundary {
  const run = engine.repository.getRunProjection(runId);
  const checkpoint = engine.coordinator.getLatestCheckpoint(runId);
  if (!checkpoint || run.status !== "blocked") throw new Error("Fixture has no blocked resume boundary");
  return {
    expectedRunVersion: run.version,
    expectedRunStatus: "blocked",
    expectedCheckpointId: checkpoint.id,
    expectedCheckpointStateHash: checkpoint.stateHash,
    expectedCheckpointEventSequence: checkpoint.eventSequence,
  };
}

async function mutate(
  base: string,
  runId: string,
  command: "pause" | "resume" | "cancel",
  key: string,
  boundary?: ResumeRunBoundary,
) {
  return fetch(`${base}/api/v2/runs/${runId}/${command}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": key },
    body: JSON.stringify({ reason: `${command} from focused route test`, ...(boundary ?? {}) }),
  });
}

function activeControlLeaseCount(database: SqliteDatabase, runId: string): number {
  return (database.prepare(`
    SELECT count(*) AS count FROM control_plane_leases
    WHERE run_id = ? AND released_at IS NULL AND expires_at > ?
  `).get(runId, NOW) as { count: number }).count;
}

describe("mission run-control V2 boundary", () => {
  test("operational-hazard retry authorization is authenticated, exact-run-bound, and control-plane fenced", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "hazard-route");
    const otherRun = seedGuidedRun(database, "hazard-route-other-run");
    const hazard = seedHazardAuthorizationBoundary(database, fixture, "hazard-route");
    const { engine, base } = await startRuntimeApplication(
      database,
      "hazard-route-worker",
      (request) => request.get("x-test-operator") ?? "",
    );
    const action = new ActionRepository(database).get(hazard.healthActionId);
    const assessment = engine.operationalHazardHealthGate.recordAssessmentForCompletedAction(
      action,
      { id: "local-health-worker", type: "worker" },
    );
    if (!assessment) throw new Error("Expected the represented health action to create an assessment");
    const body = {
      healthAssessmentId: assessment.id,
      attackAttemptId: hazard.candidate.id,
      ttlMs: 60_000,
    };
    const authorize = (
      runId: string,
      key: string,
      operator = "operator:test",
      requestBody: Readonly<Record<string, unknown>> = body,
    ) => fetch(`${base}/api/v2/runs/${runId}/operational-hazards/retry-authorizations`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": key,
        ...(operator ? { "x-test-operator": operator } : {}),
      },
      body: JSON.stringify(requestBody),
    });

    const unauthenticated = await authorize(
      fixture.runId,
      "hazard-route-no-identity",
      "",
    );
    expect(unauthenticated.status).toBe(401);
    expect(await unauthenticated.json()).toMatchObject({
      error: { code: "operator_identity_required", category: "authentication_missing" },
    });

    const invalid = await authorize(
      fixture.runId,
      "hazard-route-invalid-ttl",
      "operator:test",
      { ...body, ttlMs: 999 },
    );
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toMatchObject({
      error: { code: "invalid_hazard_authorization_expiry", category: "invalid_input" },
    });

    const crossRun = await authorize(
      otherRun.runId,
      "hazard-route-cross-run",
    );
    expect(crossRun.status).toBe(409);
    expect(await crossRun.json()).toMatchObject({
      error: { code: "hazard_retry_cross_run_denied", category: "scope_conflict" },
    });

    database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?")
      .run(fixture.runId);
    const wrongControlPlane = await authorize(
      fixture.runId,
      "hazard-route-wrong-control-plane",
    );
    expect(wrongControlPlane.status).toBe(409);
    expect(await wrongControlPlane.json()).toMatchObject({
      error: { code: "control_plane_mismatch", category: "policy_denied" },
    });
    database.prepare("UPDATE runs SET control_plane = 'ti_scale' WHERE id = ?")
      .run(fixture.runId);

    expect(database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_retry_authorizations").get())
      .toEqual({ count: 0 });
    const accepted = await authorize(
      fixture.runId,
      "hazard-route-exact-authorization",
    );
    expect(accepted.status).toBe(200);
    const acceptedBody = await accepted.json() as Record<string, unknown>;
    expect(acceptedBody).toMatchObject({
      schemaVersion: "2.4",
      authorization: {
        missionId: fixture.missionId,
        runId: fixture.runId,
        healthAssessmentId: assessment.id,
        sourceAttackAttemptId: hazard.source.id,
        authorizedAttackAttemptId: hazard.candidate.id,
        authorizationBasis: "distinct_procedure_version",
        maxAttempts: 1,
        automaticRetry: false,
      },
    });
    expect(database.prepare(`
      SELECT run_id, authorized_attack_attempt_id, max_attempts, automatic_retry
      FROM operational_hazard_retry_authorizations
    `).get()).toEqual({
      run_id: fixture.runId,
      authorized_attack_attempt_id: hazard.candidate.id,
      max_attempts: 1,
      automatic_retry: 0,
    });
    expect(database.prepare(`
      SELECT actor_id, action FROM audit_records
      WHERE action = 'operational_hazard.safer_attempt_authorized'
    `).get()).toEqual({
      actor_id: "operator:test",
      action: "operational_hazard.safer_attempt_authorized",
    });

    const replay = await authorize(
      fixture.runId,
      "hazard-route-exact-authorization",
    );
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(acceptedBody);
    expect(database.prepare("SELECT COUNT(*) AS count FROM operational_hazard_retry_authorizations").get())
      .toEqual({ count: 1 });
    await engine.stop();
  });

  test("resume accepts the exact legacy zero-in-flight boundary for an Autonomous planning rate limit", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedLegacyAutonomousPlanningRateLimit(database, "planning-rate-limit-resume");
    const { engine, base } = await startApplication(database, "planning-rate-limit-worker");
    const boundary = resumeBoundary(engine, fixture.runId);

    const resumed = await mutate(
      base,
      fixture.runId,
      "resume",
      "planning-rate-limit-resume-command",
      boundary,
    );
    expect(resumed.status).toBe(200);
    expect(await resumed.json()).toMatchObject({
      schemaVersion: "2.4",
      run: { id: fixture.runId, journey: "autonomous", status: "recovering" },
      latestCheckpoint: {
        state: {
          run: { id: fixture.runId, state: "recovering" },
          inFlightActions: [],
        },
      },
    });
    expect(database.prepare(`
      SELECT count(*) AS count FROM audit_records
      WHERE run_id = ? AND action = 'run.resumed'
    `).get(fixture.runId)).toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT count(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.state_changed'
        AND json_extract(payload_json, '$.from') = 'blocked'
        AND json_extract(payload_json, '$.to') = 'recovering'
    `).get(fixture.runId)).toEqual({ count: 1 });
  });

  test("resume rejects missing, stale, and newly in-flight checkpoint boundaries without reserving execution", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "exact-resume-rejections");
    const { engine, base } = await startApplication(database, "exact-resume-worker");

    const paused = await mutate(base, fixture.runId, "pause", "exact-resume-pause");
    expect(paused.status).toBe(200);
    const exact = resumeBoundary(engine, fixture.runId);

    const missing = await mutate(base, fixture.runId, "resume", "exact-resume-missing");
    expect(missing.status).toBe(400);
    expect(await missing.json()).toMatchObject({
      error: {
        code: "invalid_resume_boundary",
        humanMessage: "Resume is available only for the exact blocked run state shown in the Recovery Panel.",
        retryable: false,
        category: "invalid_input",
        traceId: expect.any(String),
      },
    });

    const stale = await mutate(base, fixture.runId, "resume", "exact-resume-stale", {
      ...exact,
      expectedCheckpointStateHash: "c".repeat(64),
    });
    expect(stale.status).toBe(409);
    expect(await stale.json()).toMatchObject({ error: { code: "resume_checkpoint_stale" } });

    database.prepare(`
      INSERT INTO provider_turns (id, run_id, provider, status, started_at)
      VALUES ('provider-exact-resume', ?, 'fixture', 'started', ?)
    `).run(fixture.runId, NOW);
    const inFlight = await mutate(base, fixture.runId, "resume", "exact-resume-in-flight", exact);
    expect(inFlight.status).toBe(409);
    expect(await inFlight.json()).toMatchObject({
      error: {
        code: "resume_has_in_flight_work",
        details: { blockingWorkKind: "provider_turn", blockingWorkId: "provider-exact-resume" },
      },
    });
    expect(engine.repository.getRunProjection(fixture.runId)).toMatchObject({
      status: "blocked",
      version: exact.expectedRunVersion,
    });
    expect(database.prepare(`
      SELECT count(*) AS count FROM settings
      WHERE key LIKE 'ti_scale.runtime.idempotency.run.resume.%'
    `).get()).toEqual({ count: 0 });
  });

  test("pause rejects execution-bearing provider, continuation, and assignment state", () => {
    for (const kind of ["provider", "continuation", "assignment"] as const) {
      const database = createDatabaseConnection({ filename: ":memory:" });
      databases.push(database);
      migrateDatabase(database);
      const fixture = seedGuidedRun(database, `pause-${kind}`);
      const engine = runtime(database, `pause-${kind}-worker`);
      if (kind === "provider") {
        database.prepare(`
          INSERT INTO provider_turns (id, run_id, provider, status, started_at)
          VALUES (?, ?, 'fixture', 'started', ?)
        `).run(`provider-pause-${kind}`, fixture.runId, NOW);
      } else if (kind === "continuation") {
        database.prepare(`
          INSERT INTO runtime_continuations (
            id, run_id, kind, source_id, status, attempt_count, available_at,
            created_at, updated_at
          ) VALUES (?, ?, 'resume_recovery_pending', ?, 'pending', 0, ?, ?, ?)
        `).run(`continuation-pause-${kind}`, fixture.runId, `source-${kind}`, NOW, NOW, NOW);
      } else {
        database.prepare(`
          UPDATE assignments SET status = 'active', lease_owner = 'fixture-worker',
            lease_acquired_at = ?, last_heartbeat_at = ?, lease_expires_at = ?
          WHERE id = ?
        `).run(NOW, NOW, "2026-07-16T12:30:00.000Z", fixture.assignmentId);
      }
      expect(() => engine.pauseRun(fixture.runId, "operator:test", `Pause with ${kind} active`))
        .toThrow("Pause requires a zero-in-flight durable boundary");
      expect(engine.repository.getRunProjection(fixture.runId).status).toBe("waiting_guided_decision");
    }
  });

  test("pause, resume, and cancel replay re-check ownership atomically before returning cached responses", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "route-replay");
    const { engine, base } = await startApplication(database, "route-worker");

    for (const command of ["pause", "resume", "cancel"] as const) {
      if (command === "cancel") {
        database.prepare(`
          INSERT INTO provider_turns (id, run_id, provider, status, started_at)
          VALUES ('provider-route-replay', ?, 'fixture', 'started', ?)
        `).run(fixture.runId, NOW);
        database.prepare(`
          INSERT INTO runtime_continuations (
            id, run_id, kind, source_id, status, attempt_count, available_at,
            lease_owner, lease_expires_at, created_at, updated_at
          ) VALUES ('continuation-route-replay', ?, 'action_result_to_advance',
            'open-fixture-child', 'processing', 1, ?, 'fixture-worker',
            '2026-07-16T12:30:00.000Z', ?, ?)
        `).run(fixture.runId, NOW, NOW, NOW);
      }
      const key = `route-replay-${command}`;
      const boundary = command === "resume" ? resumeBoundary(engine, fixture.runId) : undefined;
      const accepted = await mutate(base, fixture.runId, command, key, boundary);
      expect(accepted.status).toBe(200);
      const acceptedBody = await accepted.json();
      expect(activeControlLeaseCount(database, fixture.runId)).toBe(command === "resume" ? 1 : 0);

      database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?").run(fixture.runId);
      const rejectedReplay = await mutate(base, fixture.runId, command, key, boundary);
      expect(rejectedReplay.status).toBe(409);
      expect(await rejectedReplay.json()).toMatchObject({
        error: {
          code: "control_plane_mismatch",
          humanMessage: "This mission and run are controlled elsewhere, so Ti-Scale made no changes.",
          retryable: false,
          category: "policy_denied",
        },
      });

      database.prepare("UPDATE runs SET control_plane = 'ti_scale' WHERE id = ?").run(fixture.runId);
      const acceptedReplay = await mutate(base, fixture.runId, command, key, boundary);
      expect(acceptedReplay.status).toBe(200);
      expect(await acceptedReplay.json()).toEqual(acceptedBody);
      expect(activeControlLeaseCount(database, fixture.runId)).toBe(command === "resume" ? 1 : 0);
    }

    expect(database.prepare("SELECT status FROM provider_turns WHERE run_id = ?").get(fixture.runId))
      .toEqual({ status: "cancelled" });
    expect(database.prepare("SELECT status, lease_owner FROM runtime_continuations WHERE id = 'continuation-route-replay'").get())
      .toEqual({ status: "cancelled", lease_owner: null });
    expect(database.prepare("SELECT lease_owner, lease_expires_at FROM runs WHERE id = ?").get(fixture.runId))
      .toEqual({ lease_owner: null, lease_expires_at: null });
  });

  test("cancel repairs a stale event allocator instead of returning a generic 500", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "cancel-stale-event-sequence");
    const { base } = await startApplication(database, "cancel-stale-event-sequence-worker");

    // Reproduce the production boundary: an evidence verifier atomically
    // committed semantic event 41 while the cached allocator still held 40.
    database.prepare(`
      INSERT INTO run_event_sequences (run_id, last_sequence) VALUES (?, 40)
    `).run(fixture.runId);
    database.prepare(`
      INSERT INTO events (
        id, mission_id, run_id, sequence, event_type, occurred_at,
        actor_type, actor_id, summary, payload_json, schema_version, journey,
        sensitivity, redaction_json, created_at
      ) VALUES (
        'event-cancel-stale-sequence-41', ?, ?, 41,
        'autonomous_cve_applicability_completed', ?, 'agent',
        'specialist:test', 'Domain evidence committed before runtime handoff',
        '{}', 1, 'guided', 'internal', '{}', ?
      )
    `).run(fixture.missionId, fixture.runId, NOW, NOW);

    const response = await mutate(
      base,
      fixture.runId,
      "cancel",
      "cancel-stale-event-sequence",
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      schemaVersion: "2.4",
      run: {
        id: fixture.runId,
        status: "cancelled",
        currentStepId: null,
        currentOwnerId: null,
      },
    });
    expect(database.prepare(`
      SELECT sequence FROM events
      WHERE run_id = ? AND event_type = 'run.cancellation_requested'
    `).get(fixture.runId)).toEqual({ sequence: 42 });
    expect(database.prepare(`
      SELECT sequence FROM events
      WHERE run_id = ? AND event_type = 'run.cancelled'
    `).get(fixture.runId)).toEqual({ sequence: 43 });
    const sequenceBoundary = database.prepare(`
      SELECT allocator.last_sequence, MAX(events.sequence) AS max_sequence
      FROM run_event_sequences AS allocator
      JOIN events ON events.run_id = allocator.run_id
      WHERE allocator.run_id = ?
      GROUP BY allocator.run_id, allocator.last_sequence
    `).get(fixture.runId) as { last_sequence: number; max_sequence: number };
    expect(sequenceBoundary.last_sequence).toBe(sequenceBoundary.max_sequence);
    expect(sequenceBoundary.last_sequence).toBeGreaterThanOrEqual(43);
  });

  test("ownership transfer after a route claim removes the pending Ti-Scale idempotency reservation", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "route-claim-transfer");
    let transferred = false;
    const { base } = await startApplication(
      database,
      "route-claim-transfer-worker",
      (point, context) => {
        if (point !== "pause_projection_committed" || transferred) return;
        transferred = true;
        database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?")
          .run(context.runId);
      },
    );

    const response = await mutate(
      base,
      fixture.runId,
      "pause",
      "route-claim-transfer-pause",
    );
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({
      error: {
        code: "control_plane_mismatch",
        humanMessage: "This mission and run are controlled elsewhere, so Ti-Scale made no changes.",
        retryable: false,
        category: "policy_denied",
      },
    });
    expect(transferred).toBe(true);
    expect(database.prepare("SELECT status, control_plane FROM runs WHERE id = ?")
      .get(fixture.runId)).toEqual({ status: "blocked", control_plane: "legacy" });
    expect(database.prepare("SELECT status FROM missions WHERE id = ?")
      .get(fixture.missionId)).toEqual({ status: "paused" });
    expect(database.prepare(`
      SELECT count(*) AS count FROM settings
      WHERE key LIKE 'ti_scale.runtime.idempotency.run.pause.%'
    `).get()).toEqual({ count: 0 });
    expect(activeControlLeaseCount(database, fixture.runId)).toBe(0);

    const eventsBefore = database.prepare("SELECT count(*) AS count FROM events WHERE run_id = ?")
      .get(fixture.runId);
    const auditsBefore = database.prepare("SELECT count(*) AS count FROM audit_records WHERE run_id = ?")
      .get(fixture.runId);
    const retry = await mutate(
      base,
      fixture.runId,
      "pause",
      "route-claim-transfer-pause",
    );
    expect(retry.status).toBe(409);
    expect(database.prepare(`
      SELECT count(*) AS count FROM settings
      WHERE key LIKE 'ti_scale.runtime.idempotency.run.pause.%'
    `).get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT count(*) AS count FROM events WHERE run_id = ?")
      .get(fixture.runId)).toEqual(eventsBefore);
    expect(database.prepare("SELECT count(*) AS count FROM audit_records WHERE run_id = ?")
      .get(fixture.runId)).toEqual(auditsBefore);
  });

  test("pause releases authority and the resuming worker retains it for the waiting decision", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "worker-handoff");
    const firstWorker = runtime(database, "pause-worker-a");
    const secondWorker = runtime(database, "resume-worker-b");

    firstWorker.pauseRun(fixture.runId, "operator:test", "Pause for an exact worker handoff");
    expect(database.prepare("SELECT status, lease_owner, lease_expires_at FROM runs WHERE id = ?").get(fixture.runId))
      .toEqual({ status: "blocked", lease_owner: null, lease_expires_at: null });
    expect(database.prepare("SELECT status FROM plan_steps WHERE id = ?").get(fixture.stepId))
      .toEqual({ status: "waiting_guided_decision" });
    expect(database.prepare(`
      SELECT status, lease_owner, lease_acquired_at, last_heartbeat_at, lease_expires_at
      FROM assignments WHERE id = ?
    `).get(fixture.assignmentId)).toEqual({
      status: "blocked",
      lease_owner: null,
      lease_acquired_at: null,
      last_heartbeat_at: null,
      lease_expires_at: null,
    });
    expect(activeControlLeaseCount(database, fixture.runId)).toBe(0);

    secondWorker.resumeRun(
      fixture.runId,
      "operator:test",
      "Resume from the exact waiting decision",
      resumeBoundary(secondWorker, fixture.runId),
    );
    expect(database.prepare("SELECT status, lease_owner, lease_expires_at FROM runs WHERE id = ?").get(fixture.runId))
      .toEqual({ status: "waiting_guided_decision", lease_owner: null, lease_expires_at: null });
    expect(database.prepare("SELECT status, lease_owner FROM assignments WHERE id = ?").get(fixture.assignmentId))
      .toEqual({ status: "queued", lease_owner: null });
    expect(activeControlLeaseCount(database, fixture.runId)).toBe(1);
  });

  test("resume never re-enters a Guided wait on an expired pending decision", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "expired-decision-resume");
    const engine = runtime(database, "expired-decision-worker");

    database.prepare(`
      UPDATE guided_decisions SET expires_at = '2026-07-16T11:59:59.000Z'
      WHERE run_id = ?
    `).run(fixture.runId);
    engine.pauseRun(fixture.runId, "operator:test", "Pause before the expired decision boundary");
    engine.resumeRun(
      fixture.runId,
      "operator:test",
      "Recover without reviving an expired decision",
      resumeBoundary(engine, fixture.runId),
    );

    expect((database.prepare("SELECT status FROM runs WHERE id = ?").get(fixture.runId) as { status: string }).status)
      .not.toBe("waiting_guided_decision");
    expect(database.prepare(`
      SELECT count(*) AS count FROM guided_decisions
      WHERE run_id = ? AND status = 'pending' AND expires_at > ?
    `).get(fixture.runId, NOW)).toEqual({ count: 0 });
  });
});

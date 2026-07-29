import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository, type ContextPack, type MemoryNode, type MemoryNodeType } from "../../memory";
import { DurableRunCoordinator, type DurableAction, type ExecutionPort } from "../../orchestration";
import type { BrainContextResult } from "../../brain-runtime";
import { compileAutonomousRecoveryMemory } from "..";

const NOW = "2026-07-22T12:00:00.000Z";
const MATCHING_NODE_ID = "mem_11111111111111111111111111111111";
const UNRELATED_NODE_ID = "mem_22222222222222222222222222222222";
const FOREIGN_NODE_ID = "mem_33333333333333333333333333333333";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

class NoopExecution implements ExecutionPort {
  async dispatch(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async cancelRun(_runId: string, _reason: string): Promise<void> {}
}

function node(input: {
  id: string;
  nodeType?: MemoryNodeType;
  missionId?: string;
  engagementId?: string;
  lifecycleStatus?: MemoryNode["lifecycleStatus"];
  policy?: unknown;
}): MemoryNode {
  return {
    id: input.id,
    nodeType: input.nodeType ?? "failure_mode",
    title: `Recovery memory ${input.id}`,
    summary: "A typed local recovery constraint from verified operational history.",
    body: "No command, target, or tool instruction is retained here.",
    scope: input.missionId
      ? { kind: "mission", missionId: input.missionId }
      : input.engagementId
        ? { kind: "engagement", engagementId: input.engagementId }
        : { kind: "global" },
    sensitivity: "private",
    confidence: 1,
    lifecycleStatus: input.lifecycleStatus ?? "confirmed",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Deterministic recovery compiler test fixture.",
      sources: [{ sourceType: "test", sourceId: input.id, acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "operator:test",
    version: 1,
    retentionPolicy: {
      allowAutonomous: true,
      journeys: ["autonomous"],
      ...(input.policy === undefined ? {} : { autonomousRecovery: input.policy }),
    },
    pinned: false,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function pack(items: readonly MemoryNode[], overrides: Partial<ContextPack> = {}): BrainContextResult {
  const contextPack: ContextPack = {
    id: "ctx-recovery",
    missionId: "mission-recovery",
    runId: "run-recovery",
    stepId: "step-recovery",
    actionId: "action-recovery",
    journey: "autonomous",
    purpose: "Failure handling: deterministic bounded recovery",
    scopePolicy: {
      missionId: "mission-recovery",
      allowGlobal: true,
      journey: "autonomous",
      maximumSensitivity: "private",
      allowedStatuses: ["confirmed", "verified"],
      contextBudget: 16,
    },
    contextBudget: 16,
    retrievalMetrics: {},
    releaseDataClass: "canonical",
    createdBy: "run-supervisor",
    createdAt: NOW,
    items: items.map((item, rank) => ({
      nodeId: item.id,
      used: false,
      relevanceReason: `fixture rank ${rank}`,
      corrected: false,
    })),
    ...overrides,
  };
  return {
    hook: "failure",
    status: items.length ? "ready" : "no_relevant_memory",
    contextPack,
    items: items.map((item) => ({ node: item, relevanceReason: "Matched typed fixture" })),
    auditRecordId: "audit-recovery",
  };
}

function typedPolicy(effects: Record<string, unknown>) {
  return {
    schemaVersion: "1",
    match: {
      failureCategories: ["timeout"],
      actionTypes: ["provider_analysis"],
      actionClasses: ["provider_analysis"],
    },
    effects,
  };
}

function compile(
  context: BrainContextResult,
  missionId = "mission-recovery",
  engagementId: string | null = null,
) {
  return compileAutonomousRecoveryMemory({
    hook: "failure",
    context,
    missionId,
    engagementId,
    runId: "run-recovery",
    stepId: "step-recovery",
    actionId: "action-recovery",
    failureCategory: "timeout",
    actionType: "provider_analysis",
    actionClass: "provider_analysis",
  });
}

function seedRuntime(database: SqliteDatabase): {
  coordinator: DurableRunCoordinator;
  lease: ReturnType<DurableRunCoordinator["acquireRunLease"]>;
  repository: MemoryRepository;
} {
  const hash = "c".repeat(64);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (
      'mission-recovery', 'Recovery fixture', 'Inspect one authorized lab service',
      'autonomous', 'active', 'verified', '{}', 'operator:test', ?, ?, 'ti_scale'
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-recovery', 'mission-recovery', 'lab.internal', 'domain',
      'allowed', 'lab.internal', ?)
  `).run(NOW);
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (
      'contract-recovery', 'mission-recovery', 1, 'confirmed', ?, '{}',
      ?, '{}', '{}', '[]', '["verified_lessons","confirmed_attack_knowledge"]',
      'operator:test', ?, ?
    )
  `).run(hash, JSON.stringify({
    allowedActionClasses: ["provider_analysis"],
    prohibitedActionClasses: [],
    specialistAgentIds: ["agent-recovery"],
    destructivePolicy: "prohibited",
  }), NOW, NOW);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES ('agent-recovery', 'analysis', 'Recovery analyst', 'available', '1', ?, ?)
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, current_plan_id,
      current_step_id, current_owner_id, progress, status_reason,
      budget_json, budget_usage_json, retry_count, replan_count,
      started_at, created_at, updated_at, version, control_plane,
      contract_version_bound, contract_hash_bound
    ) VALUES (
      'run-recovery', 'mission-recovery', 'autonomous', 'running',
      'contract-recovery', 'plan-recovery', 'step-recovery', 'agent-recovery',
      0, 'Executing one represented action',
      '{"wallClockMs":60000,"providerTurns":10,"retries":2,"replans":0,"concurrency":1}',
      '{"providerTurns":1,"concurrency":1}', 0, 0, ?, ?, ?, 1, 'ti_scale', 1, ?
    )
  `).run(NOW, NOW, NOW, hash);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES ('plan-recovery', 'run-recovery', 1, 'active',
      'One bounded analysis', 'The represented action is reversible', ?,
      'runtime-planner', ?, ?)
  `).run("p".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, started_at, created_at, updated_at
    ) VALUES (
      'step-recovery', 'plan-recovery', 'run-recovery', 0, 'Analysis',
      'Inspect response', 'Reduce uncertainty', 'running', '[]', '[]',
      'provider_analysis', 'low', 'agent-recovery', ?, ?, ?
    )
  `).run(NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, started_at, created_at, updated_at
    ) VALUES (
      'assignment-recovery', 'run-recovery', 'step-recovery', 'agent-recovery',
      'active', ?, ?, ?
    )
  `).run(NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, assignment_id, action_type,
      action_class, fingerprint, normalized_arguments_json, scoped_target,
      status, intent_summary, contract_id, started_at, created_at, updated_at
    ) VALUES (
      'action-recovery', 'mission-recovery', 'run-recovery', 'step-recovery',
      'assignment-recovery', 'provider_analysis', 'provider_analysis', ?,
      ?, 'lab.internal', 'running', 'Analyze one bounded response',
      'contract-recovery', ?, ?, ?
    )
  `).run(
    "f".repeat(64),
    JSON.stringify({
      orchestration: { kind: "provider_turn", idempotent: true, destructive: false },
      input: { observationId: "observation-1" },
    }),
    NOW,
    NOW,
    NOW,
  );
  const coordinator = new DurableRunCoordinator(database, new NoopExecution(), {
    now: () => new Date(NOW),
  });
  return {
    coordinator,
    lease: coordinator.acquireRunLease("run-recovery", "recovery-test-worker", 60_000),
    repository: new MemoryRepository(database, { clock: () => new Date(NOW) }),
  };
}

function persistContext(
  repository: MemoryRepository,
  nodes: readonly MemoryNode[],
): BrainContextResult {
  for (const item of nodes) {
    repository.createNode({
      id: item.id,
      nodeType: item.nodeType,
      title: item.title,
      summary: item.summary,
      body: item.body,
      scope: item.scope,
      sensitivity: item.sensitivity,
      confidence: item.confidence,
      lifecycleStatus: item.lifecycleStatus,
      confirmationState: item.confirmationState,
      provenance: item.provenance,
      authorType: item.authorType,
      authorId: item.authorId,
      retentionPolicy: item.retentionPolicy,
    });
  }
  const canonical = nodes.map((item) => repository.getNode(item.id)!);
  const contextPack = repository.persistContextPack({
    id: "ctx-recovery",
    missionId: "mission-recovery",
    runId: "run-recovery",
    stepId: "step-recovery",
    actionId: "action-recovery",
    journey: "autonomous",
    purpose: "Failure handling: deterministic bounded recovery",
    queryRedacted: "Retrieve verified recovery constraints",
    scopePolicy: {
      missionId: "mission-recovery",
      allowGlobal: true,
      journey: "autonomous",
      maximumSensitivity: "private",
      allowedNodeTypes: canonical.map((item) => item.nodeType),
      allowedStatuses: ["confirmed", "verified"],
      contextBudget: 16,
      limit: 16,
      allowedScopeClasses: ["confirmed_attack_knowledge", "verified_attack_knowledge"],
    },
    contextBudget: 16,
    createdBy: "run-supervisor",
    items: canonical.map((item, rank) => ({
      node: item,
      score: 1 - rank / 100,
      relevanceReason: "Exact typed recovery fixture",
      signals: ["exact"],
    })),
  });
  return {
    hook: "failure",
    status: canonical.length ? "ready" : "no_relevant_memory",
    contextPack,
    items: canonical.map((item) => ({ node: item, relevanceReason: "Exact typed recovery fixture" })),
    auditRecordId: "audit-recovery",
  };
}

async function completeFailure(input: {
  database: SqliteDatabase;
  effects: Record<string, unknown>;
  unrelated?: MemoryNode;
  retryAfterMs?: number;
}) {
  const { coordinator, lease, repository } = seedRuntime(input.database);
  const matching = node({ id: MATCHING_NODE_ID, policy: typedPolicy(input.effects) });
  const context = persistContext(repository, [matching, ...(input.unrelated ? [input.unrelated] : [])]);
  const compiled = compile(context);
  const result = await coordinator.completeAction({
    lease,
    actionId: "action-recovery",
    success: false,
    resultSummary: "The bounded provider operation timed out without new evidence.",
    before: {},
    after: {},
    failureCategory: "timeout",
    ...(input.retryAfterMs === undefined ? {} : { retryAfterMs: input.retryAfterMs }),
    recoveryMemory: compiled,
  });
  return { result, context, compiled };
}

describe("Autonomous recovery memory compiler", () => {
  test("matched confirmed failure memory vetoes an otherwise eligible retry and persists exact influence", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const { result } = await completeFailure({ database, effects: { denyRetry: true } });

    expect(result.directive).toBe("failed");
    expect(result.recoveryMemoryReceipt).toMatchObject({
      effects: ["retry_denied"],
      candidateNodeIds: [MATCHING_NODE_ID],
      appliedNodeIds: [MATCHING_NODE_ID],
      baseline: { retryEligible: true, recoveryKind: "retry" },
      resolved: { retryEligible: false, recoveryKind: "fail" },
    });
    expect(database.prepare(`
      SELECT used, influence_summary, ignored_reason FROM memory_context_items
      WHERE context_pack_id = 'ctx-recovery' AND node_id = ?
    `).get(MATCHING_NODE_ID)).toMatchObject({ used: 1, ignored_reason: null });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM runtime_continuations
      WHERE run_id = 'run-recovery' AND kind = 'autonomous_retry_to_dispatch'
    `).get()).toEqual({ count: 0 });
  });

  test("matched memory increases bounded backoff but cannot shorten or broaden retry authority", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const { result } = await completeFailure({ database, effects: { minimumBackoffMs: 5_000 } });

    expect(result.directive).toBe("retry");
    expect(result.recoveryMemoryReceipt).toMatchObject({
      effects: ["bounded_backoff_raised"],
      appliedNodeIds: [MATCHING_NODE_ID],
      baseline: { retryEligible: true, recoveryKind: "retry" },
      resolved: { retryEligible: true, retryDelayMs: 5_000, recoveryKind: "retry" },
    });
    expect(database.prepare(`
      SELECT available_at FROM runtime_continuations
      WHERE run_id = 'run-recovery' AND kind = 'autonomous_retry_to_dispatch'
    `).get()).toEqual({ available_at: "2026-07-22T12:00:05.000Z" });
  });

  test("unrelated retrieved nodes remain explicitly unused", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const unrelated = node({
      id: UNRELATED_NODE_ID,
      nodeType: "technology_product",
      lifecycleStatus: "verified",
      policy: typedPolicy({ denyRetry: true }),
    });
    const { result } = await completeFailure({
      database,
      effects: { minimumBackoffMs: 5_000 },
      unrelated,
    });
    expect(result.recoveryMemoryReceipt?.appliedNodeIds).toEqual([MATCHING_NODE_ID]);
    expect(result.recoveryMemoryReceipt?.ignoredNodeIds).toEqual([UNRELATED_NODE_ID]);
    expect(database.prepare(`
      SELECT used, influence_summary, ignored_reason FROM memory_context_items
      WHERE context_pack_id = 'ctx-recovery' AND node_id = ?
    `).get(UNRELATED_NODE_ID)).toMatchObject({
      used: 0,
      influence_summary: null,
      ignored_reason: "node_type_not_allowed",
    });
  });

  test("mission-scoped memory from another mission cannot become a candidate", () => {
    const foreign = node({
      id: FOREIGN_NODE_ID,
      missionId: "mission-other",
      policy: typedPolicy({ denyRetry: true }),
    });
    const compiled = compile(pack([foreign]));
    expect(compiled.candidates).toEqual([]);
    expect(compiled.ignored).toEqual({ [FOREIGN_NODE_ID]: "scope_mismatch" });
  });

  test("engagement-scoped memory cannot cross the canonical engagement boundary", () => {
    const foreign = node({
      id: FOREIGN_NODE_ID,
      engagementId: "engagement-other",
      policy: typedPolicy({ denyRetry: true }),
    });
    const context = pack([foreign]);
    const scopedContext: BrainContextResult = {
      ...context,
      contextPack: {
        ...context.contextPack,
        scopePolicy: {
          ...context.contextPack.scopePolicy,
          engagementId: "engagement-current",
        },
      },
    };
    const compiled = compile(scopedContext, "mission-recovery", "engagement-current");
    expect(compiled.candidates).toEqual([]);
    expect(compiled.ignored).toEqual({ [FOREIGN_NODE_ID]: "scope_mismatch" });
  });

  test("the Context Pack's own mission and engagement boundary must match the failed action", () => {
    const matching = node({
      id: MATCHING_NODE_ID,
      engagementId: "engagement-current",
      policy: typedPolicy({ denyRetry: true }),
    });
    const context = pack([matching]);
    const mismatchedContext: BrainContextResult = {
      ...context,
      contextPack: {
        ...context.contextPack,
        scopePolicy: {
          ...context.contextPack.scopePolicy,
          missionId: "mission-other",
          engagementId: "engagement-current",
        },
      },
    };
    const compiled = compile(mismatchedContext, "mission-recovery", "engagement-current");
    expect(compiled.candidates).toEqual([]);
    expect(compiled.ignored).toEqual({ [MATCHING_NODE_ID]: "context_boundary_mismatch" });
  });

  test("unconfirmed knowledge and unverified lessons cannot influence recovery", () => {
    const candidate = node({
      id: MATCHING_NODE_ID,
      lifecycleStatus: "candidate",
      policy: typedPolicy({ denyRetry: true }),
    });
    const unverifiedLesson = node({
      id: UNRELATED_NODE_ID,
      nodeType: "attack_lesson",
      lifecycleStatus: "confirmed",
      policy: typedPolicy({ denyRetry: true }),
    });
    const compiled = compile(pack([candidate, unverifiedLesson]));
    expect(compiled.candidates).toEqual([]);
    expect(compiled.ignored).toEqual({
      [MATCHING_NODE_ID]: "node_not_confirmed_or_verified",
      [UNRELATED_NODE_ID]: "lesson_not_verified",
    });
  });

  test("memory cannot exceed the bounded retry-delay ceiling", () => {
    const matching = node({
      id: MATCHING_NODE_ID,
      policy: typedPolicy({ minimumBackoffMs: 30_001 }),
    });
    const compiled = compile(pack([matching]));
    expect(compiled.candidates).toEqual([]);
    expect(compiled.ignored).toEqual({
      [MATCHING_NODE_ID]: "typed_policy_missing_or_invalid",
    });
  });

  test("a smaller memory backoff never shortens a provider boundary and remains unused", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const { result } = await completeFailure({
      database,
      effects: { minimumBackoffMs: 5_000 },
      retryAfterMs: 10_000,
    });

    expect(result.directive).toBe("retry");
    expect(result.recoveryMemoryReceipt).toMatchObject({
      effects: [],
      appliedNodeIds: [],
      baseline: { retryDelayMs: 10_000 },
      resolved: { retryDelayMs: 10_000 },
    });
    expect(database.prepare(`
      SELECT used, influence_summary, ignored_reason FROM memory_context_items
      WHERE context_pack_id = 'ctx-recovery' AND node_id = ?
    `).get(MATCHING_NODE_ID)).toMatchObject({
      used: 0,
      influence_summary: null,
    });
  });

  test("an empty Context Pack compiles to a no-op without invented memory", () => {
    const compiled = compile(pack([]));
    expect(compiled.candidates).toEqual([]);
    expect(compiled.ignored).toEqual({});
  });
});

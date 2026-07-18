import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import type { DurableAction } from "../../orchestration";
import type { RunSupervisor } from "../../supervisor";
import {
  createMissionRuntime,
  type MissionOutcomeEvaluatorPort,
  type MissionPlannerPort,
  type ResultAwareExecutionPort,
} from "..";

const NOW = "2026-07-16T12:00:00.000Z";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

class CapturingExecution implements ResultAwareExecutionPort {
  readonly dispatched: DurableAction[] = [];
  async dispatch(action: DurableAction, _signal: AbortSignal): Promise<void> {
    this.dispatched.push(action);
  }
  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async cancelRun(_runId: string, _reason: string): Promise<void> {}
}

function seed(database: SqliteDatabase) {
  const missionId = "mission-brain-runtime";
  const runId = "run-brain-runtime";
  const agentId = "agent-brain-runtime";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Guided Brain runtime', 'Inspect the authorized lab service',
      'guided', 'active', 'verified', '{}', 'operator:test', ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-brain-runtime', ?, 'lab.internal', 'domain', 'allowed', 'lab.internal', ?)
  `).run(missionId, NOW);
  database.prepare(`
    INSERT INTO agents (id, role, display_name, status, version, created_at, updated_at)
    VALUES (?, 'recon-specialist', 'Recon specialist', 'available', 'test-1', ?, ?)
  `).run(agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'guided', 'planning', 0, 'Create the first represented Guided step',
      '{"wallClockMs":60000,"toolCalls":10,"providerTurns":10,"retries":2,"replans":2,"concurrency":1}',
      '{}', ?, ?, 1, 'ti_scale')
  `).run(runId, missionId, NOW, NOW);
  return { missionId, runId, agentId };
}

describe("MissionRuntimeEngine mandatory Brain lifecycle order", () => {
  test("retrieves planning, assignment, and tool context before provider planning and dispatch", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database);
    const observedProviderContextIds: string[] = [];
    const observedEvaluatorContextIds: string[] = [];
    const planner: MissionPlannerPort = {
      async plan(input) {
        observedProviderContextIds.push(input.brainContext.contextPackId);
        expect(input.brainContext).toMatchObject({
          trust: "untrusted_memory_summary",
          items: [],
          rejected: [],
        });
        return {
          strategySummary: "Collect one bounded service observation",
          rationaleSummary: "A single reversible step reduces uncertainty without broad execution",
          steps: [{
            phase: "Reconnaissance",
            title: "Inspect approved HTTPS service",
            objective: "Confirm whether the approved service responds",
            explanation: "The specialist performs one represented read-only service check.",
            rationale: "The result determines whether deeper authorized analysis is useful.",
            successCriteria: ["A bounded service response is recorded"],
            dependencyOrdinals: [],
            assignedAgentId: fixture.agentId,
            riskClass: "low",
            reversibility: "Read-only and immediately reversible",
            action: {
              actionType: "service_probe",
              actionClass: "service_enumeration",
              target: "lab.internal",
              arguments: { target: "lab.internal", port: 443 },
              intentSummary: "Inspect the approved HTTPS service once",
              kind: "tool",
              idempotent: true,
              destructive: false,
            },
          }],
        };
      },
    };
    const evaluator: MissionOutcomeEvaluatorPort = {
      async evaluate(input) {
        observedEvaluatorContextIds.push(input.brainContext.contextPackId);
        expect(input.brainContext.items).toEqual([]);
        return {
          success: true,
          summary: "The represented Guided step completed and the bounded objective was satisfied.",
          criteria: [],
        };
      },
    };
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner,
      outcomeEvaluator: evaluator,
      execution,
      workerId: "brain-runtime-worker",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const decision = database.prepare(`
        SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
      `).get(fixture.runId) as { id: string };
      const action = await runtime.approveGuidedDecision(
        decision.id,
        "operator:test",
        "Run this exact represented read-only step",
      );
      expect(execution.dispatched).toHaveLength(1);
      expect(action.contextPackId).toBeTruthy();
      expect(execution.dispatched[0]?.contextPackId).toBe(action.contextPackId);
      const receipt = await runtime.acceptExecutionResult({
        actionId: action.id,
        runId: fixture.runId,
        actionFingerprint: action.fingerprint,
        success: true,
        summary: "The approved HTTPS service returned one bounded response.",
        progress: { uncertainty: 0.25 },
      });
      expect(receipt.runState).toBe("completed");
      const hooks = database.prepare(`
        SELECT json_extract(details_json, '$.hook') AS hook,
          json_extract(details_json, '$.status') AS status,
          json_extract(details_json, '$.contextPackId') AS context_pack_id
        FROM audit_records
        WHERE run_id = ? AND action = 'brain.context_hook.invoked'
        ORDER BY rowid
      `).all(fixture.runId) as Array<{
        hook: string;
        status: string;
        context_pack_id: string;
      }>;
      expect(hooks.map(({ hook }) => hook)).toEqual([
        "planning",
        "assignment_acceptance",
        "tool_selection",
        "phase_transition",
        "evaluation",
        "lesson_proposal",
        "closeout",
      ]);
      expect(hooks.every(({ status }) => status === "no_relevant_memory")).toBe(true);
      expect(observedProviderContextIds).toEqual([hooks[0]!.context_pack_id]);
      expect(observedEvaluatorContextIds).toEqual([hooks[4]!.context_pack_id]);
      expect(action.contextPackId).toBe(hooks[2]!.context_pack_id);
    } finally {
      await runtime.stop();
    }
  });

  test("persists action-scoped failure context before the supervisor chooses recovery", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database);
    const planner: MissionPlannerPort = {
      async plan() {
        return {
          strategySummary: "Collect one bounded service observation",
          rationaleSummary: "A single reversible step reduces uncertainty",
          steps: [{
            phase: "Reconnaissance",
            title: "Inspect approved HTTPS service",
            objective: "Confirm whether the approved service responds",
            explanation: "Perform one represented read-only service check.",
            rationale: "The result determines the next authorized step.",
            successCriteria: ["A bounded response is recorded"],
            dependencyOrdinals: [],
            assignedAgentId: fixture.agentId,
            riskClass: "low",
            reversibility: "Read-only and immediately reversible",
            action: {
              actionType: "service_probe",
              actionClass: "service_enumeration",
              target: "lab.internal",
              arguments: { target: "lab.internal", port: 443 },
              intentSummary: "Inspect the approved HTTPS service once",
              kind: "tool",
              idempotent: true,
              destructive: false,
            },
          }],
        };
      },
    };
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner,
      outcomeEvaluator: { async evaluate() { throw new Error("blocked run must not evaluate"); } },
      execution,
      workerId: "brain-recovery-order-worker",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const decision = database.prepare(`
        SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
      `).get(fixture.runId) as { id: string };
      const action = await runtime.approveGuidedDecision(
        decision.id,
        "operator:test",
        "Run this exact represented read-only step",
      );

      const order: string[] = [];
      const originalRetrieve = runtime.brainContext.retrieve.bind(runtime.brainContext);
      runtime.brainContext.retrieve = (request) => {
        if (request.hook === "failure") order.push("failure_context");
        return originalRetrieve(request);
      };
      const supervisor = (runtime.coordinator as unknown as { supervisor: RunSupervisor }).supervisor;
      const originalDecision = supervisor.decideRecovery.bind(supervisor);
      supervisor.decideRecovery = (input) => {
        order.push("recovery_decision");
        expect(order[0]).toBe("failure_context");
        return originalDecision(input);
      };

      const receipt = await runtime.acceptExecutionResult({
        actionId: action.id,
        runId: fixture.runId,
        actionFingerprint: action.fingerprint,
        success: false,
        summary: "The represented action was denied by the local policy boundary.",
        failureCategory: "policy_denied",
        progress: {},
      });
      expect(receipt.runState).toBe("blocked");
      expect(order).toEqual(["failure_context", "recovery_decision"]);
      expect(database.prepare(`
        SELECT step_id, action_id FROM memory_context_packs
        WHERE run_id = ? AND purpose LIKE 'Failure handling:%'
      `).get(fixture.runId)).toEqual({ step_id: action.stepId, action_id: action.id });
    } finally {
      await runtime.stop();
    }
  });
});

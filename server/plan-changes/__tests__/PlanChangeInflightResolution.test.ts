import { afterEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  PlanChangeError,
  PlanChangeService,
  type PlanChangeAffectedWorkStopReceipt,
} from "../index";

const NOW = "2026-07-24T12:00:00.000Z";
const MISSION_ID = "mission-plan-inflight";
const RUN_ID = "run-plan-inflight";
const PLAN_ID = "plan-plan-inflight";
const STEP_ONE = "step-plan-inflight-one";
const STEP_TWO = "step-plan-inflight-two";
const STEP_UNRELATED = "step-plan-inflight-unrelated";
const ASSIGNMENT_ONE = "assignment-plan-inflight-one";
const ACTION_ONE = "action-plan-inflight-one";
const ATTEMPT_ONE = "attempt-plan-inflight-one";
const AGENT_ID = "agent-plan-inflight";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function representedAction(actionClass: string, dependencies: readonly string[]) {
  return JSON.stringify({
    action: {
      actionType: actionClass,
      actionClass,
      target: "fixture.local",
      arguments: {},
      intentSummary: "Collect one attributable observation",
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
    explanation: "Collect one bounded observation.",
    rationale: "Reduce uncertainty before dependent work.",
    reversibility: "Read-only and repeat-safe.",
    dependencies,
  });
}

function setup(options: { readonly unrelatedRunningAction?: boolean } = {}) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      scope_json, success_criteria_json, retention_policy_json,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'In-flight amendment fixture', 'Review one active plan safely',
      'guided', 'active', 'verified', '{}', '[]', '{}', '{}',
      'operator:test', ?, ?, 'ti_scale')
  `).run(MISSION_ID, NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target,
      metadata_json, created_at
    ) VALUES ('target-plan-inflight', ?, 'fixture.local', 'domain', 'allowed',
      'fixture.local', '{}', ?)
  `).run(MISSION_ID, NOW);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, created_at, updated_at
    ) VALUES (?, 'recon', 'Recon specialist', 'available', '{}', '{}', '{}',
      'test-1', ?, ?)
  `).run(AGENT_ID, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id,
      current_owner_id, progress, status_reason, next_action_summary,
      budget_json, budget_usage_json, started_at, created_at, updated_at,
      version, control_plane, lease_owner, lease_acquired_at,
      last_heartbeat_at, lease_expires_at
    ) VALUES (?, ?, 'guided', 'running', ?, ?, ?, 0.25,
      'Executing represented work', 'Await the exact action result',
      '{}', '{}', ?, ?, ?, 1, 'ti_scale', 'fixture-worker', ?, ?,
      '2026-07-24T12:10:00.000Z')
  `).run(
    RUN_ID,
    MISSION_ID,
    PLAN_ID,
    STEP_ONE,
    AGENT_ID,
    NOW,
    NOW,
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Collect bounded observations',
      'Keep dependent work attributable', ?, 'planner:test', ?, ?)
  `).run(PLAN_ID, RUN_ID, "a".repeat(64), NOW, NOW);
  const insertStep = database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'Recon', ?, ?, ?, '["Observation recorded"]', ?,
      ?, 'low', ?, ?, ?, ?)
  `);
  insertStep.run(
    STEP_ONE,
    PLAN_ID,
    RUN_ID,
    0,
    "Observe current service",
    "Collect current service identity",
    "running",
    "[]",
    "passive_intelligence_osint",
    AGENT_ID,
    NOW,
    NOW,
    NOW,
  );
  insertStep.run(
    STEP_TWO,
    PLAN_ID,
    RUN_ID,
    1,
    "Interpret dependent evidence",
    "Classify the attributable observation",
    "pending",
    JSON.stringify([STEP_ONE]),
    "passive_intelligence_osint",
    AGENT_ID,
    null,
    NOW,
    NOW,
  );
  insertStep.run(
    STEP_UNRELATED,
    PLAN_ID,
    RUN_ID,
    2,
    "Observe unrelated source",
    "Keep independent work isolated",
    options.unrelatedRunningAction ? "running" : "pending",
    "[]",
    "passive_intelligence_osint",
    AGENT_ID,
    options.unrelatedRunningAction ? NOW : null,
    NOW,
    NOW,
  );
  const insertRepresentation = database.prepare(`
    INSERT INTO mission_constraints (
      id, mission_id, constraint_type, value_json, source, created_at
    ) VALUES (?, ?, 'represented_action', ?, ?, ?)
  `);
  insertRepresentation.run(
    "constraint-plan-inflight-one",
    MISSION_ID,
    representedAction("passive_intelligence_osint", []),
    STEP_ONE,
    NOW,
  );
  insertRepresentation.run(
    "constraint-plan-inflight-two",
    MISSION_ID,
    representedAction("passive_intelligence_osint", [STEP_ONE]),
    STEP_TWO,
    NOW,
  );
  insertRepresentation.run(
    "constraint-plan-inflight-unrelated",
    MISSION_ID,
    representedAction("passive_intelligence_osint", []),
    STEP_UNRELATED,
    NOW,
  );
  database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
      last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'active', 'fixture-worker', ?, ?,
      '2026-07-24T12:10:00.000Z', ?, ?, ?)
  `).run(
    ASSIGNMENT_ONE,
    RUN_ID,
    STEP_ONE,
    AGENT_ID,
    NOW,
    NOW,
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, assignment_id, action_type,
      action_class, fingerprint, normalized_arguments_json, scoped_target,
      status, intent_summary, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'fixture:observe', 'passive_intelligence_osint',
      ?, ?, 'fixture.local', 'running', 'Collect one attributable observation',
      ?, ?, ?)
  `).run(
    ACTION_ONE,
    MISSION_ID,
    RUN_ID,
    STEP_ONE,
    ASSIGNMENT_ONE,
    "b".repeat(64),
    JSON.stringify({
      orchestration: {
        idempotent: true,
        destructive: false,
      },
    }),
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO attack_attempts (
      id, mission_id, run_id, plan_id, step_id, objective, technique_name,
      action_class, status, assigned_agent_id, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, 'Observe the current service',
      'Bounded service observation', 'passive_intelligence_osint', 'running',
      ?, ?, ?, ?)
  `).run(
    ATTEMPT_ONE,
    MISSION_ID,
    RUN_ID,
    PLAN_ID,
    STEP_ONE,
    AGENT_ID,
    NOW,
    NOW,
    NOW,
  );
  if (options.unrelatedRunningAction) {
    database.prepare(`
      INSERT INTO assignments (
        id, run_id, step_id, agent_id, status, lease_owner,
        lease_acquired_at, last_heartbeat_at, lease_expires_at,
        started_at, created_at, updated_at
      ) VALUES ('assignment-plan-inflight-unrelated', ?, ?, ?, 'active',
        'fixture-worker', ?, ?, '2026-07-24T12:10:00.000Z', ?, ?, ?)
    `).run(
      RUN_ID,
      STEP_UNRELATED,
      AGENT_ID,
      NOW,
      NOW,
      NOW,
      NOW,
      NOW,
    );
    database.prepare(`
      INSERT INTO actions (
        id, mission_id, run_id, step_id, assignment_id, action_type,
        action_class, fingerprint, normalized_arguments_json, scoped_target,
        status, intent_summary, started_at, created_at, updated_at
      ) VALUES ('action-plan-inflight-unrelated', ?, ?, ?,
        'assignment-plan-inflight-unrelated', 'fixture:observe',
        'passive_intelligence_osint', ?, ?, 'fixture.local', 'running',
        'Collect an unrelated attributable observation', ?, ?, ?)
    `).run(
      MISSION_ID,
      RUN_ID,
      STEP_UNRELATED,
      "c".repeat(64),
      JSON.stringify({
        orchestration: {
          idempotent: true,
          destructive: false,
        },
      }),
      NOW,
      NOW,
      NOW,
    );
  }
  let idSequence = 0;
  const service = new PlanChangeService(
    database,
    () => new Date(NOW),
    (prefix) => `${prefix}_inflight_${++idSequence}`,
  );
  const actor = { id: "operator-plan", type: "operator" } as const;
  const request = service.propose({
    missionId: MISSION_ID,
    runId: RUN_ID,
    basePlanId: PLAN_ID,
    expectedRunVersion: 1,
    expectedPlanVersion: 1,
    requestText: "Clarify the active observation before dependent work advances.",
    operations: [{
      kind: "update_step",
      stepId: STEP_ONE,
      title: "Observe the current service precisely",
    }],
  }, actor);
  return { database, service, actor, request };
}

function resolutionInput(requestId: string) {
  return {
    requestId,
    mode: "checkpoint_cancel_affected_work" as const,
    expectedRequestVersion: 1,
    expectedRunVersion: 1,
    expectedPlanVersion: 1,
    reason: "Stop only the represented affected work before reviewing a fresh diff.",
  };
}

const exactReceipt: PlanChangeAffectedWorkStopReceipt = {
  stoppedActionIds: [ACTION_ONE],
  stoppedAssignmentIds: [ASSIGNMENT_ONE],
  stoppedAttackAttemptIds: [ATTEMPT_ONE],
  stoppedStepIds: [STEP_ONE],
};

describe("PlanChangeService in-flight resolution", () => {
  test("fences dispatch without claiming that a process stopped early", () => {
    const { database, service, actor, request } = setup();
    service.beginInflightResolution(resolutionInput(request.id), actor);
    const event = database.prepare(`
      SELECT summary FROM events
      WHERE run_id = ? AND event_type = 'plan_change.inflight_resolution_started'
      ORDER BY sequence DESC LIMIT 1
    `).get(RUN_ID) as { readonly summary: string };
    expect(event.summary).toContain("Dispatch was fenced");
    expect(event.summary).toContain("confirmation is still pending");
    expect(database.prepare(
      "SELECT status FROM actions WHERE id = ?",
    ).get(ACTION_ONE)).toEqual({ status: "running" });
  });

  test("requires an exact mapped child receipt before closing live records", () => {
    const { database, service, actor, request } = setup();
    const resolution = service.beginInflightResolution(
      resolutionInput(request.id),
      actor,
    );
    let mismatch: unknown;
    try {
      service.confirmAffectedCancellation(
        request.id,
        resolution.version,
        actor,
        { ...exactReceipt, stoppedAssignmentIds: [] },
      );
    } catch (error) {
      mismatch = error;
    }
    expect(mismatch).toBeInstanceOf(PlanChangeError);
    expect((mismatch as PlanChangeError).code).toBe(
      "plan_change_cancellation_receipt_mismatch",
    );
    expect(database.prepare(
      "SELECT status FROM actions WHERE id = ?",
    ).get(ACTION_ONE)).toEqual({ status: "running" });

    service.confirmAffectedCancellation(
      request.id,
      resolution.version,
      actor,
      exactReceipt,
    );
    expect(database.prepare(
      "SELECT status FROM actions WHERE id = ?",
    ).get(ACTION_ONE)).toEqual({ status: "cancelled" });
    expect(database.prepare(
      "SELECT status FROM assignments WHERE id = ?",
    ).get(ASSIGNMENT_ONE)).toEqual({ status: "cancelled" });
    expect(database.prepare(
      "SELECT status FROM attack_attempts WHERE id = ?",
    ).get(ATTEMPT_ONE)).toEqual({ status: "cancelled" });
    expect(database.prepare(
      "SELECT status FROM plan_steps WHERE id = ?",
    ).get(STEP_ONE)).toEqual({ status: "cancelled" });
  });

  test("replays the same durable boundary after the begin/receipt crash window", () => {
    const { database, service, actor, request } = setup();
    const input = resolutionInput(request.id);
    const first = service.beginInflightResolution(input, actor);
    const replay = service.beginInflightResolution(input, actor);
    expect(replay).toEqual(first);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM plan_change_inflight_resolutions
      WHERE plan_change_request_id = ?
    `).get(request.id)).toEqual({ count: 1 });
    expect(database.prepare(
      "SELECT version, status FROM runs WHERE id = ?",
    ).get(RUN_ID)).toEqual({ version: 2, status: "blocked" });
  });

  test("keeps cancellation disabled while unrelated running work exists", () => {
    const { service, request } = setup({ unrelatedRunningAction: true });
    const cancel = request.inflightImpact.resolutionOptions.find((option) =>
      option.mode === "checkpoint_cancel_affected_work");
    expect(cancel).toMatchObject({
      enabled: false,
      disabledReason: expect.stringContaining("unrelated running child"),
    });
    expect(() => service.beginInflightResolution(
      resolutionInput(request.id),
      { id: "operator-plan", type: "operator" },
    )).toThrow(PlanChangeError);
  });
});

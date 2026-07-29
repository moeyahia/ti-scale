import { createHash } from "node:crypto";
import { createDatabaseConnection, inImmediateTransaction, type SqliteDatabase } from "../../../server/db";
import { PlanChangeService, type PlanChangeRequest } from "../../../server/plan-changes";
import { acquireTestRunMutationAuthority } from "../../../server/control-plane/TestRunMutationAuthority";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

export type PlanChangeFixtureState =
  | "queued_apply"
  | "queued_reject"
  | "running"
  | "inflight_resolution"
  | "corrupt_history"
  | "direct_editor"
  | "direct_edit"
  | "version_history";

export interface PlanChangeFixture {
  readonly missionId: string;
  readonly missionName: string;
  readonly target: string;
  readonly runId: string;
  readonly planId: string;
  readonly historicalPlanId?: string;
  readonly historicalPlanV1Id?: string;
  readonly historicalPlanV2Id?: string;
  readonly stepOneId: string;
  readonly stepTwoId: string;
  readonly stepThreeId?: string;
  readonly agentId: string;
  readonly alternateAgentId?: string;
  readonly assignmentId: string;
  readonly workerId: string;
  readonly strategySummary: string;
  readonly runVersion: number;
  readonly planVersion: number;
  readonly corruptRequestId?: string;
  readonly validNormalizedChangeJson?: string;
}

export interface PlanChangeFixtureSnapshot {
  readonly run: {
    readonly status: string;
    readonly currentPlanId: string | null;
    readonly version: number;
    readonly replanCount: number;
    readonly leaseOwner: string | null;
  };
  readonly plans: readonly {
    readonly id: string;
    readonly version: number;
    readonly status: string;
    readonly strategySummary: string;
  }[];
  readonly requests: readonly {
    readonly id: string;
    readonly status: string;
    readonly version: number;
    readonly resultPlanId: string | null;
  }[];
  readonly actionCount: number;
  readonly assignmentStates: readonly string[];
}

function database(): SqliteDatabase {
  if (!E2E_DATABASE_PATH) throw new Error("The isolated Playwright database path was not configured");
  return createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
}

function hash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function representedAction(actionClass: string, target: string, dependencies: readonly string[]): string {
  return JSON.stringify({
    action: {
      actionType: actionClass,
      actionClass,
      target,
      arguments: {},
      intentSummary: "Collect attributable observations inside the represented lab scope",
      kind: "manual",
      idempotent: true,
      destructive: false,
    },
    explanation: "Collect one bounded, attributable observation.",
    rationale: "Reduce uncertainty without changing target state.",
    reversibility: "Read-only",
    dependencies,
  });
}

/**
 * Seeds only canonical V2 relational state. Plan-change behavior itself stays
 * behind the authenticated production service and route boundaries exercised
 * by the browser tests.
 */
export function createPlanChangeFixture(state: PlanChangeFixtureState, instanceId: string): PlanChangeFixture {
  const normalizedInstance = normalizeFixtureNamespace(instanceId);
  const suffix = `${state.replaceAll("_", "-")}-${normalizedInstance}`;
  const missionId = `mission-plan-change-e2e-${suffix}`;
  const missionName = `Plan amendment ${suffix} fixture`;
  const target = `${suffix}.fixture.test`;
  const runId = `run-plan-change-e2e-${suffix}`;
  const planId = `plan-plan-change-e2e-${suffix}-v1`;
  const versionHistory = state === "version_history";
  const stepOneId = `step-plan-change-e2e-${suffix}-one`;
  const stepTwoId = `step-plan-change-e2e-${suffix}-two`;
  const direct = state === "direct_editor" || state === "direct_edit";
  const stepThreeId = direct ? `step-plan-change-e2e-${suffix}-three` : undefined;
  const agentId = `agent-plan-change-e2e-${suffix}`;
  const alternateAgentId = direct ? `agent-plan-change-e2e-${suffix}-alternate` : undefined;
  const assignmentId = `assignment-plan-change-e2e-${suffix}`;
  const intermediatePlanId = versionHistory ? `plan-plan-change-e2e-${suffix}-v2` : undefined;
  const currentPlanId = versionHistory ? `plan-plan-change-e2e-${suffix}-v3` : planId;
  const intermediateStepId = versionHistory ? `step-plan-change-e2e-${suffix}-intermediate` : undefined;
  const currentStepId = versionHistory ? `step-plan-change-e2e-${suffix}-current` : stepOneId;
  const currentAssignmentId = versionHistory ? `assignment-plan-change-e2e-${suffix}-current` : assignmentId;
  const workerId = `worker-plan-change-e2e-${suffix}`;
  const strategySummary = versionHistory ? "Map the approved surface" : `Map the authorized ${suffix} fixture`;
  const now = "2026-07-16T18:00:00.000Z";
  const running = state === "running" || state === "inflight_resolution";
  const exactInflight = state === "inflight_resolution";
  const connection = database();
  let corruptRequest: PlanChangeRequest | undefined;

  try {
    inImmediateTransaction(connection, () => {
      connection.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status, scope_json,
          success_criteria_json, retention_policy_json, memory_policy_json,
          created_by, created_at, updated_at
        ) VALUES (?, ?, ?, 'guided', 'active', 'verified', ?, ?, '{}', '{}', 'e2e-local-operator', ?, ?)
      `).run(
        missionId,
        missionName,
        "Review and amend only represented pre-execution work inside the authorized local lab.",
        JSON.stringify({ environment: "local_test_fixture", controlPlane: "ti_scale" }),
        JSON.stringify(["Every plan amendment remains reviewed and evidence attributable"]),
        now,
        now,
      );
      connection.prepare(`
        INSERT INTO mission_targets (
          id, mission_id, target, target_type, disposition, normalized_target,
          metadata_json, created_at
        ) VALUES (?, ?, ?, 'domain', 'allowed', ?, '{}', ?)
      `).run(`target-plan-change-e2e-${suffix}`, missionId, target, target, now);
      connection.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json, tool_policy_json,
          configuration_json, version, last_heartbeat_at, created_at, updated_at
        ) VALUES (?, 'recon', 'Recon specialist', 'available', '{}', '{}', '{}', 'e2e-1', ?, ?, ?)
      `).run(agentId, now, now, now);
      if (alternateAgentId) {
        connection.prepare(`
          INSERT INTO agents (
            id, role, display_name, status, provider_policy_json, tool_policy_json,
            configuration_json, version, last_heartbeat_at, created_at, updated_at
          ) VALUES (?, 'web', 'Web assessment specialist', 'available', '{}', '{}', '{}', 'e2e-1', ?, ?, ?)
        `).run(alternateAgentId, now, now, now);
      }
      connection.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, current_plan_id, current_step_id,
          current_owner_id, progress, status_reason, next_action_summary,
          budget_json, budget_usage_json, lease_owner, lease_acquired_at,
          last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at,
          version
        ) VALUES (?, ?, 'guided', ?, ?, ?, ?, ?, ?, ?, '{}', '{}', ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        runId,
        missionId,
        running ? "running" : "queued",
        planId,
        stepOneId,
        running ? agentId : null,
        running ? 0.25 : 0,
        running
          ? "The represented recon specialist is actively collecting an observation."
          : "The represented plan is queued at a safe pre-execution boundary.",
        running ? "Finish or checkpoint the represented observation" : "Review the first represented step",
        running ? workerId : null,
        running ? now : null,
        running ? now : null,
        running ? "2026-07-16T18:30:00.000Z" : null,
        running ? now : null,
        now,
        now,
        running ? 2 : 1,
      );
      connection.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, rationale_summary,
          plan_hash, created_by, created_at, activated_at
        ) VALUES (?, ?, 1, 'active', ?, 'Start with attributable, represented discovery', ?, 'e2e-runtime-planner', ?, ?)
      `).run(planId, runId, strategySummary, hash(`${planId}:${strategySummary}`), now, now);

      const insertStep = connection.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          success_criteria_json, dependencies_json, action_class, risk_class,
          assigned_agent_id, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'Recon', ?, ?, ?, ?, ?, ?, 'low', ?, ?, ?, ?)
      `);
      insertStep.run(
        stepOneId,
        planId,
        runId,
        0,
        "Collect passive scope facts",
        "Establish attributable target identity",
        running ? "running" : "ready",
        JSON.stringify(["Target identity is recorded"]),
        "[]",
        "passive_intelligence_osint",
        agentId,
        running ? now : null,
        now,
        now,
      );
      if (stepThreeId) {
        insertStep.run(
          stepThreeId,
          planId,
          runId,
          2,
          "Capture application metadata",
          "Preserve attributable HTTP metadata without changing the target",
          "pending",
          JSON.stringify(["Application metadata is linked to the approved target"]),
          "[]",
          "web_crawling_page_capture",
          alternateAgentId,
          null,
          now,
          now,
        );
      }
      insertStep.run(
        stepTwoId,
        planId,
        runId,
        1,
        "Validate DNS records",
        "Correlate only approved names",
        "pending",
        JSON.stringify(["DNS evidence is recorded"]),
        JSON.stringify([stepOneId]),
        "dns_domain_certificate_discovery",
        agentId,
        null,
        now,
        now,
      );

      const insertRepresentation = connection.prepare(`
        INSERT INTO mission_constraints (
          id, mission_id, constraint_type, value_json, source, created_at
        ) VALUES (?, ?, 'represented_action', ?, ?, ?)
      `);
      insertRepresentation.run(
        `constraint-plan-change-e2e-${suffix}-one`,
        missionId,
        representedAction("passive_intelligence_osint", target, []),
        stepOneId,
        now,
      );
      if (stepThreeId) {
        insertRepresentation.run(
          `constraint-plan-change-e2e-${suffix}-three`,
          missionId,
          representedAction("web_crawling_page_capture", target, []),
          stepThreeId,
          now,
        );
      }
      insertRepresentation.run(
        `constraint-plan-change-e2e-${suffix}-two`,
        missionId,
        representedAction("dns_domain_certificate_discovery", target, [stepOneId]),
        stepTwoId,
        now,
      );
      connection.prepare(`
        INSERT INTO assignments (
          id, run_id, step_id, agent_id, status, lease_owner,
          lease_acquired_at, last_heartbeat_at, lease_expires_at, started_at,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        assignmentId,
        runId,
        stepOneId,
        agentId,
        running ? "active" : "queued",
        running ? workerId : null,
        running ? now : null,
        running ? now : null,
        running ? "2026-07-16T18:30:00.000Z" : null,
        running ? now : null,
        now,
        now,
      );
      if (exactInflight) {
        connection.prepare(`
          INSERT INTO actions (
            id, mission_id, run_id, step_id, assignment_id, action_type,
            action_class, fingerprint, normalized_arguments_json,
            scoped_target, status, intent_summary, started_at, created_at,
            updated_at
          ) VALUES (?, ?, ?, ?, ?, 'fixture:observe',
            'passive_intelligence_osint', ?, ?, ?, 'running',
            'Collect one attributable observation', ?, ?, ?)
        `).run(
          `action-plan-change-e2e-${suffix}`,
          missionId,
          runId,
          stepOneId,
          assignmentId,
          hash(`action:${runId}`),
          JSON.stringify({
            orchestration: {
              idempotent: true,
              destructive: false,
            },
          }),
          target,
          now,
          now,
          now,
        );
        connection.prepare(`
          INSERT INTO attack_attempts (
            id, mission_id, run_id, plan_id, step_id, objective,
            technique_name, action_class, status, assigned_agent_id,
            started_at, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, 'Observe the current represented service',
            'Bounded service observation', 'passive_intelligence_osint',
            'running', ?, ?, ?, ?)
        `).run(
          `attempt-plan-change-e2e-${suffix}`,
          missionId,
          runId,
          planId,
          stepOneId,
          agentId,
          now,
          now,
          now,
        );
      }

      if (versionHistory) {
        if (!intermediatePlanId || !intermediateStepId) throw new Error("Version-history fixture IDs were not initialized");
        const versionTwoStrategy = "Correlate verified service evidence";
        const currentStrategy = "Validate the current application hypothesis";
        connection.prepare("UPDATE plans SET status = 'superseded' WHERE id = ?").run(planId);
        connection.prepare("UPDATE plan_steps SET status = 'cancelled', ended_at = ?, updated_at = ? WHERE plan_id = ?").run(now, now, planId);
        connection.prepare("UPDATE assignments SET status = 'cancelled', ended_at = ?, updated_at = ? WHERE run_id = ?").run(now, now, runId);
        connection.prepare(`
          INSERT INTO plans (
            id, run_id, version, status, strategy_summary, rationale_summary,
            plan_hash, created_by, created_at, activated_at
          ) VALUES (?, ?, 2, 'superseded', ?, 'Version two correlated the first verified service observations', ?, 'e2e-runtime-planner', ?, ?)
        `).run(intermediatePlanId, runId, versionTwoStrategy, hash(`${intermediatePlanId}:${versionTwoStrategy}`), now, now);
        connection.prepare(`
          INSERT INTO plan_steps (
            id, plan_id, run_id, ordinal, phase, title, objective, status,
            success_criteria_json, dependencies_json, action_class, risk_class,
            assigned_agent_id, ended_at, created_at, updated_at
          ) VALUES (?, ?, ?, 0, 'Analysis', 'Correlate service observations',
            'Retain only independently attributable service evidence', 'cancelled',
            '["Verified service evidence is correlated"]', '[]', 'passive_intelligence_osint',
            'low', ?, ?, ?, ?)
        `).run(intermediateStepId, intermediatePlanId, runId, agentId, now, now, now);
        insertRepresentation.run(
          `constraint-plan-change-e2e-${suffix}-intermediate`,
          missionId,
          representedAction("passive_intelligence_osint", target, []),
          intermediateStepId,
          now,
        );
        connection.prepare(`
          INSERT INTO plans (
            id, run_id, version, status, strategy_summary, rationale_summary,
            plan_hash, created_by, created_at, activated_at
          ) VALUES (?, ?, 3, 'active', ?, 'Version three follows a separately reviewed current hypothesis', ?, 'e2e-runtime-planner', ?, ?)
        `).run(currentPlanId, runId, currentStrategy, hash(`${currentPlanId}:${currentStrategy}`), now, now);
        connection.prepare(`
          INSERT INTO plan_steps (
            id, plan_id, run_id, ordinal, phase, title, objective, status,
            success_criteria_json, dependencies_json, action_class, risk_class,
            assigned_agent_id, created_at, updated_at
          ) VALUES (?, ?, ?, 0, 'Analysis', 'Validate the current hypothesis',
            'Classify one current evidence-backed branch', 'ready',
            '["Current branch is classified"]', '[]', 'passive_intelligence_osint',
            'low', ?, ?, ?)
        `).run(currentStepId, currentPlanId, runId, agentId, now, now);
        insertRepresentation.run(
          `constraint-plan-change-e2e-${suffix}-current`,
          missionId,
          representedAction("passive_intelligence_osint", target, []),
          currentStepId,
          now,
        );
        connection.prepare(`
          INSERT INTO assignments (id, run_id, step_id, agent_id, status, created_at, updated_at)
          VALUES (?, ?, ?, ?, 'queued', ?, ?)
        `).run(currentAssignmentId, runId, currentStepId, agentId, now, now);
        connection.prepare(`
          UPDATE runs SET current_plan_id = ?, current_step_id = ?, status_reason = ?, next_action_summary = ?
          WHERE id = ?
        `).run(currentPlanId, currentStepId, "Plan v3 is queued at a safe pre-execution boundary.", "Review the current represented step", runId);
      }

      if (state === "corrupt_history") {
        const service = new PlanChangeService(
          connection,
          () => new Date("2026-07-16T18:01:00.000Z"),
          (prefix) => `${prefix}_plan_change_e2e_corrupt_history_${normalizedInstance}`,
        );
        corruptRequest = service.propose({
          missionId,
          runId,
          basePlanId: planId,
          expectedRunVersion: 1,
          expectedPlanVersion: 1,
          requestText: "Preserve a deterministic proposal while exercising strict client parsing.",
          operations: [{
            kind: "update_plan",
            strategySummary: "Correlate represented scope facts before DNS validation",
          }],
        }, { id: "e2e-local-operator", type: "operator" });
        connection.prepare(`
          UPDATE plan_change_requests SET normalized_change_json = '{}'
          WHERE id = ?
        `).run(corruptRequest.id);
      }
    });
    acquireTestRunMutationAuthority(connection, runId);
  } finally {
    connection.close();
  }

  return {
    missionId,
    missionName,
    target,
    runId,
    planId: currentPlanId,
    ...(versionHistory ? {
      historicalPlanId: planId,
      historicalPlanV1Id: planId,
      historicalPlanV2Id: intermediatePlanId,
    } : {}),
    stepOneId: currentStepId,
    stepTwoId,
    ...(stepThreeId ? { stepThreeId } : {}),
    agentId,
    ...(alternateAgentId ? { alternateAgentId } : {}),
    assignmentId: currentAssignmentId,
    workerId,
    strategySummary: versionHistory ? "Validate the current application hypothesis" : strategySummary,
    runVersion: running ? 2 : 1,
    planVersion: versionHistory ? 3 : 1,
    ...(corruptRequest ? {
      corruptRequestId: corruptRequest.id,
      validNormalizedChangeJson: JSON.stringify(corruptRequest.normalizedChange),
    } : {}),
  };
}

export function repairPlanChangeHistory(fixture: PlanChangeFixture): void {
  if (!fixture.corruptRequestId || !fixture.validNormalizedChangeJson) {
    throw new Error("The fixture has no deliberately malformed proposal projection to repair");
  }
  const connection = database();
  try {
    const result = connection.prepare(`
      UPDATE plan_change_requests SET normalized_change_json = ? WHERE id = ?
    `).run(fixture.validNormalizedChangeJson, fixture.corruptRequestId);
    if (result.changes !== 1) throw new Error("The malformed proposal projection was not repaired");
  } finally {
    connection.close();
  }
}

/**
 * The standalone preview intentionally projects an empty attested runtime and
 * marks database-only fixture agents offline every 15 seconds. Refreshing the
 * canonical fixture row immediately before a real proposal mutation removes
 * that wall-clock race without changing production readiness behavior.
 */
export function refreshPlanChangeFixtureAgents(fixture: PlanChangeFixture): void {
  const connection = database();
  try {
    const ids = [fixture.agentId, fixture.alternateAgentId].filter((id): id is string => Boolean(id));
    const placeholders = ids.map(() => "?").join(", ");
    const result = connection.prepare(`
      UPDATE agents SET status = 'available', last_heartbeat_at = ?, updated_at = ?
      WHERE id IN (${placeholders})
    `).run("2026-07-16T18:00:00.000Z", "2026-07-16T18:00:00.000Z", ...ids);
    if (result.changes !== ids.length) throw new Error("Not every plan-change fixture specialist was restored");
    acquireTestRunMutationAuthority(connection, fixture.runId);
  } finally {
    connection.close();
  }
}

export function settlePlanChangeInflightWork(fixture: PlanChangeFixture): void {
  const connection = database();
  const now = "2026-07-16T18:02:00.000Z";
  try {
    inImmediateTransaction(connection, () => {
      const actions = connection.prepare(`
        UPDATE actions SET status = 'succeeded',
          result_summary = 'The represented repeat-safe observation completed.',
          ended_at = ?, updated_at = ?
        WHERE run_id = ? AND status = 'running'
      `).run(now, now, fixture.runId);
      const attempts = connection.prepare(`
        UPDATE attack_attempts SET status = 'succeeded',
          outcome_summary = 'The bounded observation completed.',
          ended_at = ?, updated_at = ?, version = version + 1
        WHERE run_id = ? AND status = 'running'
      `).run(now, now, fixture.runId);
      const assignments = connection.prepare(`
        UPDATE assignments SET status = 'completed', ended_at = ?,
          lease_owner = NULL, lease_acquired_at = NULL,
          last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
        WHERE run_id = ? AND status = 'active'
      `).run(now, now, fixture.runId);
      const steps = connection.prepare(`
        UPDATE plan_steps SET status = 'completed', ended_at = ?, updated_at = ?
        WHERE run_id = ? AND status = 'running'
      `).run(now, now, fixture.runId);
      if (
        actions.changes !== 1
        || attempts.changes !== 1
        || assignments.changes !== 1
        || steps.changes !== 1
      ) {
        throw new Error("The exact in-flight fixture did not settle every represented child");
      }
    });
  } finally {
    connection.close();
  }
}

export function readPlanChangeFixtureSnapshot(fixture: PlanChangeFixture): PlanChangeFixtureSnapshot {
  const connection = database();
  try {
    const run = connection.prepare(`
      SELECT status, current_plan_id, version, replan_count, lease_owner
      FROM runs WHERE id = ?
    `).get(fixture.runId) as {
      status: string;
      current_plan_id: string | null;
      version: number;
      replan_count: number;
      lease_owner: string | null;
    } | undefined;
    if (!run) throw new Error(`Fixture run is missing: ${fixture.runId}`);
    const plans = connection.prepare(`
      SELECT id, version, status, strategy_summary
      FROM plans WHERE run_id = ? ORDER BY version, id
    `).all(fixture.runId) as Array<{ id: string; version: number; status: string; strategy_summary: string }>;
    const requests = connection.prepare(`
      SELECT id, status, version, result_plan_id
      FROM plan_change_requests WHERE run_id = ? ORDER BY created_at, id
    `).all(fixture.runId) as Array<{ id: string; status: string; version: number; result_plan_id: string | null }>;
    const actionCount = (connection.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?")
      .get(fixture.runId) as { count: number }).count;
    const assignmentStates = (connection.prepare(`
      SELECT status FROM assignments WHERE run_id = ? ORDER BY created_at, id
    `).all(fixture.runId) as Array<{ status: string }>).map((row) => row.status);
    return {
      run: {
        status: run.status,
        currentPlanId: run.current_plan_id,
        version: run.version,
        replanCount: run.replan_count,
        leaseOwner: run.lease_owner,
      },
      plans: plans.map((plan) => ({
        id: plan.id,
        version: plan.version,
        status: plan.status,
        strategySummary: plan.strategy_summary,
      })),
      requests: requests.map((request) => ({
        id: request.id,
        status: request.status,
        version: request.version,
        resultPlanId: request.result_plan_id,
      })),
      actionCount,
      assignmentStates,
    };
  } finally {
    connection.close();
  }
}

import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { RuntimeRepository } from "../RuntimeRepository";

const NOW = "2026-07-16T16:00:00.000Z";

function representedAction(target: string, dependencies: readonly string[]): string {
  return JSON.stringify({
    action: {
      actionType: "service_enumeration",
      actionClass: "port_service_enumeration",
      target,
      arguments: { ports: [443] },
      intentSummary: `Inspect ${target}`,
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
    explanation: "Collect one bounded service observation.",
    rationale: "Reduce uncertainty before deeper analysis.",
    reversibility: "Read-only.",
    dependencies,
  });
}

describe("RuntimeRepository plan dependency projection", () => {
  test("returns stable prerequisite step IDs from the exact represented action", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          success_criteria_json, memory_policy_json, created_by, created_at, updated_at
        ) VALUES (
          'mission-plan-projection', 'Plan projection', 'Map the authorized fixture',
          'guided', 'active', 'verified', '[]', '{}', 'operator:test', ?, ?
        )
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, budget_json, budget_usage_json,
          created_at, updated_at
        ) VALUES (
          'run-plan-projection', 'mission-plan-projection', 'guided',
          'running', '{}', '{}', ?, ?
        )
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, plan_hash,
          created_by, created_at, activated_at
        ) VALUES (
          'plan-projection', 'run-plan-projection', 1, 'active',
          'Collect bounded observations', ?, 'planner:test', ?, ?
        )
      `).run("a".repeat(64), NOW, NOW);

      const insertStep = database.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          success_criteria_json, dependencies_json, action_class, risk_class,
          assigned_agent_id, created_at, updated_at
        ) VALUES (?, 'plan-projection', 'run-plan-projection', ?, 'reconnaissance',
          ?, ?, 'ready', '[]', ?, 'port_service_enumeration', 'low',
          'ReconScout', ?, ?)
      `);
      insertStep.run(
        "step-prerequisite",
        0,
        "Resolve the target",
        "Resolve the authorized target",
        "[]",
        NOW,
        NOW,
      );
      insertStep.run(
        "step-dependent",
        1,
        "Inspect the service",
        "Inspect the resolved service",
        JSON.stringify(["step-prerequisite"]),
        NOW,
        NOW,
      );

      const insertRepresentation = database.prepare(`
        INSERT INTO mission_constraints (
          id, mission_id, constraint_type, value_json, source, created_at
        ) VALUES (?, 'mission-plan-projection', 'represented_action', ?, ?, ?)
      `);
      insertRepresentation.run(
        "constraint-prerequisite",
        representedAction("fixture.local", []),
        "step-prerequisite",
        NOW,
      );
      insertRepresentation.run(
        "constraint-dependent",
        representedAction("fixture.local", ["step-prerequisite"]),
        "step-dependent",
        NOW,
      );

      const plan = new RuntimeRepository(database).listPlans("run-plan-projection")[0];
      expect(plan?.steps.map((step) => ({
        id: step.id,
        dependencyStepIds: step.dependencyStepIds,
      }))).toEqual([
        { id: "step-prerequisite", dependencyStepIds: [] },
        { id: "step-dependent", dependencyStepIds: ["step-prerequisite"] },
      ]);
    } finally {
      database.close();
    }
  });

  test("fail-closes the current recovering step and assignment without touching completed work", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          success_criteria_json, memory_policy_json, created_by, created_at, updated_at
        ) VALUES (
          'mission-planning-fail-close', 'Planning fail close', 'Prove a bounded terminal boundary',
          'guided', 'active', 'verified', '[]', '{}', 'operator:test', ?, ?
        )
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO agents (id, role, display_name, status, version, created_at, updated_at)
        VALUES ('agent-planning-fail-close', 'recon-specialist', 'Recon specialist',
          'available', 'test-1', ?, ?)
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, current_plan_id, current_step_id,
          budget_json, budget_usage_json, created_at, updated_at
        ) VALUES (
          'run-planning-fail-close', 'mission-planning-fail-close', 'guided',
          'blocked', 'plan-planning-fail-close', 'step-planning-current', '{}', '{}', ?, ?
        )
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, plan_hash,
          created_by, created_at, activated_at
        ) VALUES (
          'plan-planning-fail-close', 'run-planning-fail-close', 1, 'active',
          'Try one bounded recovery strategy', ?, 'planner:test', ?, ?
        )
      `).run("b".repeat(64), NOW, NOW);
      const insertStep = database.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          assigned_agent_id, created_at, updated_at
        ) VALUES (?, 'plan-planning-fail-close', 'run-planning-fail-close', ?,
          'recovery', ?, ?, ?, 'agent-planning-fail-close', ?, ?)
      `);
      insertStep.run(
        "step-planning-completed", 0, "Retain prior evidence", "Preserve completed work",
        "completed", NOW, NOW,
      );
      insertStep.run(
        "step-planning-current", 1, "Prepare a bounded alternative", "Reduce uncertainty",
        "recovering", NOW, NOW,
      );
      database.prepare(`
        INSERT INTO assignments (
          id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
          last_heartbeat_at, lease_expires_at, created_at, updated_at
        ) VALUES (
          'assignment-planning-current', 'run-planning-fail-close', 'step-planning-current',
          'agent-planning-fail-close', 'blocked', 'stale-worker', ?, ?, ?, ?, ?
        )
      `).run(NOW, NOW, "2026-07-16T16:05:00.000Z", NOW, NOW);

      const result = new RuntimeRepository(database).failCurrentPlanningBoundary(
        "run-planning-fail-close",
        "2026-07-16T16:01:00.000Z",
      );

      expect(result).toEqual({ stepsFailed: 1, assignmentsFailed: 1 });
      expect(database.prepare(`
        SELECT id, status FROM plan_steps WHERE run_id = ? ORDER BY ordinal
      `).all("run-planning-fail-close")).toEqual([
        { id: "step-planning-completed", status: "completed" },
        { id: "step-planning-current", status: "failed" },
      ]);
      expect(database.prepare(`
        SELECT status, lease_owner, lease_acquired_at, last_heartbeat_at, lease_expires_at
        FROM assignments WHERE id = 'assignment-planning-current'
      `).get()).toEqual({
        status: "failed",
        lease_owner: null,
        lease_acquired_at: null,
        last_heartbeat_at: null,
        lease_expires_at: null,
      });
    } finally {
      database.close();
    }
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import type { DurableAction } from "../../orchestration";
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

class NoopExecution implements ResultAwareExecutionPort {
  async dispatch(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async cancelRun(_runId: string, _reason: string): Promise<void> {}
}

const planner: MissionPlannerPort = {
  async plan() {
    throw new Error("Planning is outside this cancellation test");
  },
};

const evaluator: MissionOutcomeEvaluatorPort = {
  async evaluate() {
    return { success: false, summary: "Cancelled by the operator", criteria: [] };
  },
};

function seedRun(database: SqliteDatabase) {
  const missionId = "mission-cancellation-crash";
  const runId = "run-cancellation-crash";
  const planId = "plan-cancellation-crash";
  const stepId = "step-cancellation-crash";
  const assignmentId = "assignment-cancellation-crash";
  const agentId = "agent-cancellation-crash";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Cancellation crash fixture', 'Prove terminal cleanup is atomic',
      'guided', 'active', 'verified', 'operator:test', ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO agents (id, role, display_name, status, version, created_at, updated_at)
    VALUES (?, 'recon-specialist', 'Recon specialist', 'available', 'test-1', ?, ?)
  `).run(agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id,
      current_owner_id, progress, status_reason, next_action_summary,
      budget_json, budget_usage_json, started_at, created_at, updated_at,
      version, control_plane
    ) VALUES (?, ?, 'guided', 'running', ?, ?, ?, 0.25,
      'Executing represented work', 'Wait for the next result',
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
      'running', ?, ?, ?)
  `).run(stepId, planId, runId, agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
      last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'active', 'fixture-worker', ?, ?,
      '2026-07-16T12:10:00.000Z', ?, ?, ?)
  `).run(assignmentId, runId, stepId, agentId, NOW, NOW, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO provider_turns (id, run_id, provider, status, started_at)
    VALUES ('provider-cancellation-crash', ?, 'fixture', 'started', ?)
  `).run(runId, NOW);
  return { missionId, runId, assignmentId };
}

function runtime(
  database: SqliteDatabase,
  workerId: string,
  crashAfterCommit?: Parameters<typeof createMissionRuntime>[0]["crashAfterCommit"],
) {
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

describe("MissionRuntimeEngine cancellation durability", () => {
  test("closes provider work before the terminal checkpoint and reconciles historical terminal residue", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedRun(database);
    const crashing = runtime(database, "cancellation-worker-a", (point) => {
      if (point === "cancellation_terminal_before_runtime_cleanup") {
        throw new Error("simulated process loss after terminal commit");
      }
    });

    await expect(crashing.cancelRun(
      fixture.runId,
      "operator:test",
      "Stop the disposable run and every child",
    )).rejects.toThrow("Injected process crash after durable commit");

    expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(fixture.runId))
      .toEqual({ status: "cancelled" });
    expect(database.prepare("SELECT status, ended_at FROM provider_turns WHERE run_id = ?").get(fixture.runId))
      .toEqual({ status: "cancelled", ended_at: NOW });
    expect(database.prepare(`
      SELECT status, lease_owner, lease_acquired_at, last_heartbeat_at, lease_expires_at
      FROM assignments WHERE id = ?
    `).get(fixture.assignmentId)).toEqual({
      status: "cancelled",
      lease_owner: null,
      lease_acquired_at: null,
      last_heartbeat_at: null,
      lease_expires_at: null,
    });
    const terminalCheckpoint = database.prepare(`
      SELECT state_json, state_hash FROM checkpoints
      WHERE run_id = ? ORDER BY event_sequence DESC, created_at DESC LIMIT 1
    `).get(fixture.runId) as { state_json: string; state_hash: string };
    expect(JSON.parse(terminalCheckpoint.state_json)).toMatchObject({
      run: { state: "cancelled", leaseOwner: null, leaseExpiresAt: null },
      inFlightActions: [],
    });

    // Model residue from an older build/process and prove a terminal retry
    // repairs it without reviving execution.
    database.prepare(`
      UPDATE provider_turns SET status = 'started', ended_at = NULL,
        error_category = NULL WHERE run_id = ?
    `).run(fixture.runId);
    database.prepare(`
      UPDATE assignments SET lease_owner = 'orphan-worker', lease_acquired_at = ?,
        last_heartbeat_at = ?, lease_expires_at = '2026-07-16T12:10:00.000Z'
      WHERE id = ?
    `).run(NOW, NOW, fixture.assignmentId);
    database.prepare(`
      INSERT INTO runtime_continuations (
        id, run_id, kind, source_id, status, attempt_count, available_at,
        created_at, updated_at
      ) VALUES ('continuation-terminal-residue', ?, 'resume_recovery_pending',
        'terminal-residue', 'pending', 0, ?, ?, ?)
    `).run(fixture.runId, NOW, NOW, NOW);
    database.prepare(`
      INSERT INTO control_plane_leases (
        run_id, control_plane, lease_owner, lease_token_hash, acquired_at,
        heartbeat_at, expires_at, released_at, version
      ) VALUES (?, 'ti_scale', 'orphan-worker', ?, ?, ?,
        '2026-07-16T12:10:00.000Z', NULL, 1)
      ON CONFLICT(run_id) DO UPDATE SET lease_owner = excluded.lease_owner,
        lease_token_hash = excluded.lease_token_hash, acquired_at = excluded.acquired_at,
        heartbeat_at = excluded.heartbeat_at, expires_at = excluded.expires_at,
        released_at = NULL, version = control_plane_leases.version + 1
    `).run(fixture.runId, "c".repeat(64), NOW, NOW);

    const restarted = runtime(database, "cancellation-worker-b");
    await restarted.cancelRun(
      fixture.runId,
      "operator:test",
      "Reconcile the already terminal cancellation",
    );

    expect(database.prepare("SELECT status FROM provider_turns WHERE run_id = ?").get(fixture.runId))
      .toEqual({ status: "cancelled" });
    expect(database.prepare("SELECT status, lease_owner FROM runtime_continuations WHERE id = ?")
      .get("continuation-terminal-residue")).toEqual({ status: "cancelled", lease_owner: null });
    expect(database.prepare(`
      SELECT lease_owner, lease_acquired_at, last_heartbeat_at, lease_expires_at
      FROM assignments WHERE id = ?
    `).get(fixture.assignmentId)).toEqual({
      lease_owner: null,
      lease_acquired_at: null,
      last_heartbeat_at: null,
      lease_expires_at: null,
    });
    expect(database.prepare(`
      SELECT released_at FROM control_plane_leases WHERE run_id = ?
    `).get(fixture.runId)).toEqual({ released_at: NOW });
    expect(database.prepare(`
      SELECT count(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.cancellation_residue_reconciled'
    `).get(fixture.runId)).toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT state_json FROM checkpoints
      WHERE run_id = ? ORDER BY event_sequence DESC, created_at DESC LIMIT 1
    `).get(fixture.runId)).toMatchObject({ state_json: expect.stringContaining('"state":"cancelled"') });
    const brainHooks = database.prepare(`
      SELECT json_extract(details_json, '$.hook') AS hook,
        json_extract(details_json, '$.status') AS status,
        json_extract(details_json, '$.contextPackId') AS context_pack_id
      FROM audit_records
      WHERE run_id = ? AND action = 'brain.context_hook.invoked'
      ORDER BY rowid
    `).all(fixture.runId) as Array<{
      hook: string;
      status: string;
      context_pack_id: string | null;
    }>;
    expect(brainHooks.map(({ hook }) => hook)).toEqual([
      "evaluation",
      "lesson_proposal",
      "closeout",
    ]);
    expect(brainHooks.every(({ status, context_pack_id }) =>
      status === "no_relevant_memory" && typeof context_pack_id === "string")).toBe(true);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_context_packs
      WHERE run_id = ? AND NOT EXISTS (
        SELECT 1 FROM memory_context_items
        WHERE context_pack_id = memory_context_packs.id
      )
    `).get(fixture.runId)).toEqual({ count: 3 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM run_evaluations WHERE run_id = ?")
      .get(fixture.runId)).toEqual({ count: 1 });
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
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
import type { DurableAction } from "../../orchestration";
import { hashJson } from "../../orchestration/serialization";
import { createMissionRunControlV2Router } from "../missionRuntimeV2Routes";

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

function runtime(database: SqliteDatabase, workerId: string) {
  return createMissionRuntime({
    database,
    planner,
    outcomeEvaluator: evaluator,
    execution: new NoopExecution(),
    workerId,
    leaseTtlMs: 2_000,
    now: () => new Date(NOW),
  });
}

async function startApplication(database: SqliteDatabase, workerId: string) {
  const engine = runtime(database, workerId);
  const app = express();
  app.use(express.json());
  app.use(createMissionRunControlV2Router({ runtime: engine, resolveActor: () => "operator:test" }));
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
    expect(await missing.json()).toMatchObject({ error: { code: "invalid_resume_boundary" } });

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
      expect(activeControlLeaseCount(database, fixture.runId)).toBe(0);

      database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?").run(fixture.runId);
      const rejectedReplay = await mutate(base, fixture.runId, command, key, boundary);
      expect(rejectedReplay.status).toBe(409);
      expect(await rejectedReplay.json()).toMatchObject({
        error: { code: "control_plane_control_plane_mismatch" },
      });

      database.prepare("UPDATE runs SET control_plane = 'ti_scale' WHERE id = ?").run(fixture.runId);
      const acceptedReplay = await mutate(base, fixture.runId, command, key, boundary);
      expect(acceptedReplay.status).toBe(200);
      expect(await acceptedReplay.json()).toEqual(acceptedBody);
      expect(activeControlLeaseCount(database, fixture.runId)).toBe(0);
    }

    expect(database.prepare("SELECT status FROM provider_turns WHERE run_id = ?").get(fixture.runId))
      .toEqual({ status: "cancelled" });
    expect(database.prepare("SELECT status, lease_owner FROM runtime_continuations WHERE id = 'continuation-route-replay'").get())
      .toEqual({ status: "cancelled", lease_owner: null });
    expect(database.prepare("SELECT lease_owner, lease_expires_at FROM runs WHERE id = ?").get(fixture.runId))
      .toEqual({ lease_owner: null, lease_expires_at: null });
  });

  test("pause commits a waiting child boundary and releases authority before another worker resumes", () => {
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
    expect(activeControlLeaseCount(database, fixture.runId)).toBe(0);
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

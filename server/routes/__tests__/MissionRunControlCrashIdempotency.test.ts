import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
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
import type { DurableAction } from "../../orchestration";
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
    throw new Error("Planning is outside this crash-idempotency test");
  },
};

const evaluator: MissionOutcomeEvaluatorPort = {
  async evaluate() {
    return { success: false, summary: "Cancelled by the operator", criteria: [] };
  },
};

function seedGuidedRun(database: SqliteDatabase, suffix: string): { missionId: string; runId: string } {
  const missionId = `mission-crash-idempotency-${suffix}`;
  const runId = `run-crash-idempotency-${suffix}`;
  const planId = `plan-crash-idempotency-${suffix}`;
  const stepId = `step-crash-idempotency-${suffix}`;
  const agentId = `agent-crash-idempotency-${suffix}`;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Crash idempotency fixture', 'Recover only the exact committed command',
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
      id, run_id, step_id, agent_id, status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'queued', ?, ?)
  `).run(`assignment-${suffix}`, runId, stepId, agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO guided_decisions (
      id, mission_id, run_id, step_id, requested_action_fingerprint,
      requested_parameters_json, rationale, risk_class, reversibility,
      status, expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, '{}', 'Wait for one exact operator decision',
      'low', 'Read-only', 'pending', '2026-07-17T12:00:00.000Z', ?)
  `).run(`decision-${suffix}`, missionId, runId, stepId, "b".repeat(64), NOW);
  return { missionId, runId };
}

type CrashPoint = NonNullable<Parameters<typeof createMissionRuntime>[0]["crashAfterCommit"]> extends (
  point: infer Point,
  context: Readonly<{ runId: string; sourceId?: string }>,
) => void ? Point : never;

function runtime(database: SqliteDatabase, workerId: string, crashPoint?: CrashPoint) {
  let crashed = false;
  return createMissionRuntime({
    database,
    planner,
    outcomeEvaluator: evaluator,
    execution: new NoopExecution(),
    workerId,
    leaseTtlMs: 2_000,
    now: () => new Date(NOW),
    ...(crashPoint ? {
      crashAfterCommit(point) {
        if (!crashed && point === crashPoint) {
          crashed = true;
          throw new Error(`simulated process loss at ${crashPoint}`);
        }
      },
    } : {}),
  });
}

async function startApplication(engine: ReturnType<typeof runtime>): Promise<string> {
  const app = express();
  app.use(express.json());
  app.use(createMissionRunControlV2Router({ runtime: engine, resolveActor: () => "operator:test" }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
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

function requestBody(command: "pause" | "resume" | "cancel", boundary?: ResumeRunBoundary) {
  return { reason: `${command} across the post-commit crash boundary`, ...(boundary ?? {}) };
}

async function mutate(
  base: string,
  runId: string,
  command: "pause" | "resume" | "cancel",
  key: string,
  boundary?: ResumeRunBoundary,
): Promise<Response> {
  return fetch(`${base}/api/v2/runs/${runId}/${command}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": key },
    body: JSON.stringify(requestBody(command, boundary)),
  });
}

function abandonClaim(database: SqliteDatabase, scope: string, key: string): void {
  const digest = createHash("sha256").update(key, "utf8").digest("hex");
  const settingKey = `idempotency.runtime.${scope}.${digest}`;
  const row = database.prepare("SELECT value_json FROM settings WHERE key = ?")
    .get(settingKey) as { value_json: string } | undefined;
  if (!row) throw new Error(`Missing idempotency claim for ${scope}`);
  const value = JSON.parse(row.value_json) as Record<string, unknown>;
  expect(value.status).toBe("pending");
  database.prepare("UPDATE settings SET value_json = ? WHERE key = ?")
    .run(JSON.stringify({ ...value, leaseExpiresAt: "1970-01-01T00:00:00.000Z" }), settingKey);
}

function auditCount(database: SqliteDatabase, runId: string, action: string): number {
  return (database.prepare(`
    SELECT count(*) AS count FROM audit_records WHERE run_id = ? AND action = ?
  `).get(runId, action) as { count: number }).count;
}

describe("mission run-control crash-safe idempotency", () => {
  test("pause recovers only the same command after its runtime commit outlives the HTTP worker", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "pause");
    const first = runtime(database, "pause-crashing-worker", "pause_projection_committed");
    const firstBase = await startApplication(first);
    const key = "pause-post-commit-crash";

    const lostResponse = await mutate(firstBase, fixture.runId, "pause", key);
    expect(lostResponse.status).toBe(500);
    expect(first.repository.getRunProjection(fixture.runId)).toMatchObject({ status: "blocked" });
    expect(auditCount(database, fixture.runId, "run.paused")).toBe(1);
    abandonClaim(database, "run.pause", key);

    const restarted = runtime(database, "pause-restarted-worker");
    const restartedBase = await startApplication(restarted);
    const recovered = await mutate(restartedBase, fixture.runId, "pause", key);
    expect(recovered.status).toBe(200);
    expect(await recovered.json()).toMatchObject({
      run: { id: fixture.runId, status: "blocked" },
    });
    expect(auditCount(database, fixture.runId, "run.paused")).toBe(1);

    const unrelated = await mutate(restartedBase, fixture.runId, "pause", "pause-different-command");
    expect(unrelated.status).toBe(409);
    expect(auditCount(database, fixture.runId, "run.paused")).toBe(1);
  });

  test("resume recovers only the same command after its exact boundary was durably consumed", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "resume");
    const preparing = runtime(database, "resume-preparing-worker");
    preparing.pauseRun(fixture.runId, "operator:test", "Prepare an exact blocked checkpoint");
    const boundary = resumeBoundary(preparing, fixture.runId);
    const first = runtime(database, "resume-crashing-worker", "resume_projection_committed");
    const firstBase = await startApplication(first);
    const key = "resume-post-commit-crash";

    const lostResponse = await mutate(firstBase, fixture.runId, "resume", key, boundary);
    expect(lostResponse.status).toBe(500);
    expect(first.repository.getRunProjection(fixture.runId)).toMatchObject({ status: "waiting_guided_decision" });
    expect(auditCount(database, fixture.runId, "run.resumed")).toBe(1);
    abandonClaim(database, "run.resume", key);

    const restarted = runtime(database, "resume-restarted-worker");
    const restartedBase = await startApplication(restarted);
    const recovered = await mutate(restartedBase, fixture.runId, "resume", key, boundary);
    expect(recovered.status).toBe(200);
    expect(await recovered.json()).toMatchObject({
      run: { id: fixture.runId, status: "waiting_guided_decision" },
    });
    expect(auditCount(database, fixture.runId, "run.resumed")).toBe(1);

    const unrelated = await mutate(
      restartedBase,
      fixture.runId,
      "resume",
      "resume-different-command",
      boundary,
    );
    expect(unrelated.status).toBe(409);
    expect(await unrelated.json()).toMatchObject({ error: { code: "resume_checkpoint_stale" } });
    expect(auditCount(database, fixture.runId, "run.resumed")).toBe(1);
  });

  test("cancel recovers only the same command after the terminal commit outlives the HTTP worker", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "cancel");
    const first = runtime(
      database,
      "cancel-crashing-worker",
      "cancellation_terminal_before_runtime_cleanup",
    );
    const firstBase = await startApplication(first);
    const key = "cancel-post-commit-crash";

    const lostResponse = await mutate(firstBase, fixture.runId, "cancel", key);
    expect(lostResponse.status).toBe(500);
    expect(first.repository.getRunProjection(fixture.runId)).toMatchObject({ status: "cancelled" });
    expect(database.prepare(`
      SELECT count(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.cancelled'
    `).get(fixture.runId)).toEqual({ count: 1 });
    abandonClaim(database, "run.cancel", key);

    const restarted = runtime(database, "cancel-restarted-worker");
    const restartedBase = await startApplication(restarted);
    const recovered = await mutate(restartedBase, fixture.runId, "cancel", key);
    expect(recovered.status).toBe(200);
    expect(await recovered.json()).toMatchObject({
      run: { id: fixture.runId, status: "cancelled" },
    });
    expect(database.prepare(`
      SELECT count(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.cancelled'
    `).get(fixture.runId)).toEqual({ count: 1 });

    const unrelated = await mutate(restartedBase, fixture.runId, "cancel", "cancel-different-command");
    expect(unrelated.status).toBe(409);
    expect(database.prepare(`
      SELECT count(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.cancelled'
    `).get(fixture.runId)).toEqual({ count: 1 });
  });

  test("cancel resumes its exact durable continuation when the worker dies after child cleanup", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seedGuidedRun(database, "cancel-before-finalize");
    const first = runtime(
      database,
      "cancel-cleanup-crashing-worker",
      "cancellation_cleanup_before_finalize",
    );
    const firstBase = await startApplication(first);
    const key = "cancel-cleanup-post-commit-crash";

    const lostResponse = await mutate(firstBase, fixture.runId, "cancel", key);
    expect(lostResponse.status).toBe(500);
    expect(database.prepare(`
      SELECT count(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.cancellation_requested'
    `).get(fixture.runId)).toEqual({ count: 1 });
    expect(first.repository.getRunProjection(fixture.runId).status).not.toBe("cancelled");

    abandonClaim(database, "run.cancel", key);
    database.prepare(`
      UPDATE runtime_continuations
      SET lease_expires_at = '1970-01-01T00:00:00.000Z'
      WHERE run_id = ? AND kind = 'cancellation_finalize_pending'
    `).run(fixture.runId);
    database.prepare(`
      UPDATE runs SET lease_expires_at = '1970-01-01T00:00:00.000Z'
      WHERE id = ?
    `).run(fixture.runId);

    const restarted = runtime(database, "cancel-cleanup-restarted-worker");
    const restartedBase = await startApplication(restarted);
    const recovered = await mutate(restartedBase, fixture.runId, "cancel", key);
    expect(recovered.status).toBe(200);
    expect(await recovered.json()).toMatchObject({
      run: { id: fixture.runId, status: "cancelled" },
    });
    expect(database.prepare(`
      SELECT count(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.cancellation_requested'
    `).get(fixture.runId)).toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT count(*) AS count FROM events
      WHERE run_id = ? AND event_type = 'run.cancelled'
    `).get(fixture.runId)).toEqual({ count: 1 });

    const unrelated = await mutate(
      restartedBase,
      fixture.runId,
      "cancel",
      "cancel-cleanup-different-command",
    );
    expect(unrelated.status).toBe(409);
  });
});

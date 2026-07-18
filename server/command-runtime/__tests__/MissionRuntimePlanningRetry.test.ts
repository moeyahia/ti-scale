import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import type { DurableAction } from "../../orchestration";
import {
  CommandRuntimeError,
  createMissionRuntime,
  type MissionPlannerPort,
  type ResultAwareExecutionPort,
} from "..";

const START = Date.parse("2026-07-17T08:00:00.000Z");
const databases: SqliteDatabase[] = [];
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

class TestClock {
  private value = START;
  now = (): Date => new Date(this.value);
  at(offsetMs: number): void { this.value = START + offsetMs; }
  iso(offsetMs: number): string { return new Date(START + offsetMs).toISOString(); }
}

class NoopExecution implements ResultAwareExecutionPort {
  async dispatch(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async cancelRun(_runId: string, _reason: string): Promise<void> {}
}

function seed(database: SqliteDatabase, suffix: string, budget = {
  wallClockMs: 60_000,
  providerTurns: 8,
  retries: 2,
  replans: 1,
}, journey: "autonomous" | "guided" = "autonomous"): { missionId: string; runId: string } {
  const now = new Date(START).toISOString();
  const missionId = `mission-planning-retry-${suffix}`;
  const runId = `run-planning-retry-${suffix}`;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Planning retry fixture', 'Inspect the authorized lab target',
      ?, 'active', 'verified',
      '{"exactContextNodeIds":[],"allowedScopes":[]}',
      'operator:test', ?, ?, 'ti_scale')
  `).run(missionId, journey, now, now);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES (?, ?, 'lab.internal', 'domain', 'allowed', 'lab.internal', ?)
  `).run(`target-${suffix}`, missionId, now);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, retry_count, replan_count,
      started_at, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, ?, 'planning', 0,
      'Build the first in-contract plan', ?, '{}', 0, 0, ?, ?, ?, 1, 'ti_scale')
  `).run(runId, missionId, journey, JSON.stringify(budget), now, now, now);
  return { missionId, runId };
}

function rateLimit(retryAfterMs?: number): CommandRuntimeError {
  return new CommandRuntimeError(429, "provider_rate_limited", "Provider returned HTTP 429 rate limit", {
    humanMessage: "The planning provider is temporarily rate-limited.",
    retryable: true,
    category: "rate_limit",
    ...(retryAfterMs === undefined ? {} : { details: { retryAfterMs } }),
  });
}

function policyDenial(): CommandRuntimeError {
  return new CommandRuntimeError(403, "provider_policy_denied", "Provider planning was denied by policy", {
    humanMessage: "The planning request was denied by enforced policy.",
    retryable: false,
    category: "policy_denied",
  });
}

function invalidPlanningInput(): CommandRuntimeError {
  return new CommandRuntimeError(422, "provider_plan_input_invalid", "Provider planning input was invalid", {
    humanMessage: "The represented planning input is invalid.",
    retryable: false,
    category: "invalid_input",
  });
}

function runtime(input: {
  database: SqliteDatabase;
  planner: MissionPlannerPort;
  clock: TestClock;
  workerId: string;
  random?: () => number;
  crashAfterCommit?: Parameters<typeof createMissionRuntime>[0]["crashAfterCommit"];
}) {
  return createMissionRuntime({
    database: input.database,
    planner: input.planner,
    outcomeEvaluator: {
      async evaluate() { throw new Error("A planning failure fixture must not evaluate"); },
    },
    execution: new NoopExecution(),
    workerId: input.workerId,
    leaseTtlMs: 1_000,
    now: input.clock.now,
    ...(input.random ? { retryRandom: input.random } : {}),
    ...(input.crashAfterCommit ? { crashAfterCommit: input.crashAfterCommit } : {}),
  });
}

function memoryDatabase(): SqliteDatabase {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  return database;
}

describe("MissionRuntimeEngine durable planning retries", () => {
  test("persists the first rate-limit retry and honors Retry-After without blocking", async () => {
    const database = memoryDatabase();
    const clock = new TestClock();
    const fixture = seed(database, "first");
    let calls = 0;
    const engine = runtime({
      database,
      clock,
      workerId: "planning-retry-first",
      random: () => 0,
      planner: {
        async plan() {
          calls += 1;
          database.prepare(`
            INSERT INTO provider_turns (
              id, run_id, provider, model, status, error_category,
              latency_ms, started_at, ended_at
            ) VALUES (?, ?, 'xai-grok-oauth', 'grok-4.5', 'failed', ?, 125, ?, ?)
          `).run(
            `provider-turn-first-${calls}`,
            fixture.runId,
            calls === 1 ? "rate_limit" : "policy_denied",
            clock.now().toISOString(),
            clock.now().toISOString(),
          );
          if (calls === 1) throw rateLimit(2_000);
          throw policyDenial();
        },
      },
    });
    try {
      await engine.processRunNow(fixture.runId);
      expect(calls).toBe(1);
      const persisted = database.prepare(`
        SELECT status, retry_count, budget_usage_json, lease_owner
        FROM runs WHERE id = ?
      `).get(fixture.runId) as {
        status: string;
        retry_count: number;
        budget_usage_json: string;
        lease_owner: string | null;
      };
      expect({ ...persisted, budget_usage_json: undefined }).toEqual({
        status: "planning",
        retry_count: 1,
        budget_usage_json: undefined,
        lease_owner: null,
      });
      expect(JSON.parse(persisted.budget_usage_json)).toMatchObject({ providerTurns: 1, retries: 1 });
      const continuation = database.prepare(`
        SELECT id, status, available_at, payload_json FROM runtime_continuations
        WHERE run_id = ? AND kind = 'planning_retry_to_dispatch'
      `).get(fixture.runId) as {
        id: string;
        status: string;
        available_at: string;
        payload_json: string;
      };
      expect(continuation).toMatchObject({ status: "pending", available_at: clock.iso(2_000) });
      expect(JSON.parse(continuation.payload_json)).toEqual({
        errorCode: "provider_rate_limited",
        failureCategory: "rate_limit",
        retryCount: "1",
      });
      const checkpoint = engine.coordinator.getLatestCheckpoint(fixture.runId)!;
      expect(checkpoint.state.control).toMatchObject({
        retryCount: 1,
        planningRetry: {
          continuationId: continuation.id,
          failureCategory: "rate_limit",
          retryCount: 1,
          notBefore: clock.iso(2_000),
        },
      });
      const diagnosis = database.prepare(`
        SELECT category, retryable, state, retry_history_json,
          automatic_recovery_json, preserved_refs_json
        FROM failure_diagnoses WHERE run_id = ?
        ORDER BY created_at DESC, id DESC LIMIT 1
      `).get(fixture.runId) as {
        category: string;
        retryable: number;
        state: string;
        retry_history_json: string;
        automatic_recovery_json: string;
        preserved_refs_json: string;
      };
      expect(diagnosis).toMatchObject({ category: "rate_limit", retryable: 1, state: "active" });
      expect(JSON.parse(diagnosis.retry_history_json)).toEqual([
        expect.objectContaining({
          providerTurnId: "provider-turn-first-1",
          provider: "xai-grok-oauth",
          model: "grok-4.5",
          providerTurnStatus: "failed",
          errorCategory: "rate_limit",
          httpStatus: 429,
          retryAfterMs: 2_000,
        }),
      ]);
      expect(JSON.parse(diagnosis.automatic_recovery_json)).toMatchObject({
        directive: "retry",
        scheduled: true,
        continuationId: continuation.id,
        retryCount: 1,
        retryAfterMs: 2_000,
      });
      expect(JSON.parse(diagnosis.preserved_refs_json)).toEqual([
        expect.objectContaining({ id: checkpoint.id, kind: "checkpoint" }),
      ]);

      clock.at(1_999);
      expect(await engine.replayContinuations(fixture.runId, ["planning_retry_to_dispatch"])).toBe(0);
      expect(calls).toBe(1);
      clock.at(2_000);
      await engine.replayContinuations(fixture.runId, ["planning_retry_to_dispatch"]);
      expect(calls).toBe(2);
      expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(fixture.runId))
        .toEqual({ status: "blocked" });
      await engine.replayContinuations(fixture.runId, ["planning_retry_to_dispatch"]);
      expect(calls).toBe(2);
    } finally {
      await engine.stop();
    }
  });

  test("persists nested HTTP status and Retry-After from a provider response", async () => {
    const database = memoryDatabase();
    const clock = new TestClock();
    const fixture = seed(database, "response-metadata");
    const providerError = Object.assign(new Error("Grok provider returned too many requests"), {
      response: {
        status: 429,
        headers: { get: (name: string) => name.toLowerCase() === "retry-after" ? "3" : null },
      },
    });
    const engine = runtime({
      database,
      clock,
      workerId: "planning-retry-response-metadata",
      random: () => 0,
      planner: { async plan() { throw providerError; } },
    });
    try {
      await engine.processRunNow(fixture.runId);
      const continuation = database.prepare(`
        SELECT available_at FROM runtime_continuations
        WHERE run_id = ? AND kind = 'planning_retry_to_dispatch'
      `).get(fixture.runId) as { available_at: string };
      expect(continuation.available_at).toBe(clock.iso(3_000));
      const row = database.prepare(`
        SELECT category, retry_history_json, automatic_recovery_json
        FROM failure_diagnoses WHERE run_id = ? LIMIT 1
      `).get(fixture.runId) as {
        category: string;
        retry_history_json: string;
        automatic_recovery_json: string;
      };
      expect(row.category).toBe("rate_limit");
      expect(JSON.parse(row.retry_history_json)[0]).toMatchObject({
        providerTurnStatus: "failed",
        errorCategory: "rate_limit",
        httpStatus: 429,
        retryAfterMs: 3_000,
      });
      expect(JSON.parse(row.automatic_recovery_json)).toMatchObject({
        directive: "retry",
        notBefore: clock.iso(3_000),
        retryAfterMs: 3_000,
      });
    } finally {
      await engine.stop();
    }
  });

  test("safe-stops instead of shortening a provider wait beyond the automatic limit", async () => {
    const database = memoryDatabase();
    const clock = new TestClock();
    const fixture = seed(database, "retry-after-bound");
    const requestedWaitMs = 30 * 60_000 + 1;
    let calls = 0;
    const engine = runtime({
      database,
      clock,
      workerId: "planning-retry-after-bound",
      planner: { async plan() { calls += 1; throw rateLimit(requestedWaitMs); } },
    });
    try {
      await expect(engine.processRunNow(fixture.runId)).rejects.toMatchObject({
        code: "mission_runtime_rate_limit_retry_after_exceeds_bound",
        options: {
          humanMessage: expect.stringContaining("did not shorten that window or retry early"),
          details: expect.objectContaining({
            retriesUsed: 0,
            retryReason: "provider_retry_after_exceeds_bound",
            retryAfterMs: requestedWaitMs,
          }),
        },
      });
      expect(calls).toBe(1);
      const run = database.prepare(`
        SELECT status, retry_count, status_reason, budget_usage_json
        FROM runs WHERE id = ?
      `).get(fixture.runId) as {
        status: string;
        retry_count: number;
        status_reason: string;
        budget_usage_json: string;
      };
      expect(run.status).toBe("blocked");
      expect(run.retry_count).toBe(0);
      expect(run.status_reason).toContain("requested a wait longer");
      expect(JSON.parse(run.budget_usage_json)).toMatchObject({ providerTurns: 1, retries: 0 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM runtime_continuations
        WHERE run_id = ? AND kind = 'planning_retry_to_dispatch'
      `).get(fixture.runId)).toEqual({ count: 0 });
      const diagnosis = database.prepare(`
        SELECT retryable, automatic_recovery_json
        FROM failure_diagnoses WHERE run_id = ? ORDER BY created_at DESC, id DESC LIMIT 1
      `).get(fixture.runId) as { retryable: number; automatic_recovery_json: string };
      expect(diagnosis.retryable).toBe(0);
      expect(JSON.parse(diagnosis.automatic_recovery_json)).toMatchObject({
        directive: "safe_stop",
        scheduled: false,
        retriesUsed: 0,
        retryAfterMs: requestedWaitMs,
      });
    } finally {
      await engine.stop();
    }
  });

  test("safe-stops precisely after the default two transient retries", async () => {
    const database = memoryDatabase();
    const clock = new TestClock();
    const fixture = seed(database, "exhaustion");
    let calls = 0;
    const engine = runtime({
      database,
      clock,
      workerId: "planning-retry-exhaustion",
      random: () => 0.5,
      planner: { async plan() { calls += 1; throw rateLimit(); } },
    });
    try {
      await engine.processRunNow(fixture.runId);
      clock.at(500);
      await engine.replayContinuations(fixture.runId, ["planning_retry_to_dispatch"]);
      clock.at(1_500);
      await engine.replayContinuations(fixture.runId, ["planning_retry_to_dispatch"]);

      expect(calls).toBe(3);
      const run = database.prepare(`
        SELECT status, status_reason, retry_count, budget_usage_json
        FROM runs WHERE id = ?
      `).get(fixture.runId) as {
        status: string;
        status_reason: string;
        retry_count: number;
        budget_usage_json: string;
      };
      expect(run.status).toBe("blocked");
      expect(run.status_reason).toContain("after 2 bounded automatic retries");
      expect(run.retry_count).toBe(2);
      expect(JSON.parse(run.budget_usage_json)).toMatchObject({ providerTurns: 3, retries: 2 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM runtime_continuations
        WHERE run_id = ? AND kind = 'planning_retry_to_dispatch' AND status != 'completed'
      `).get(fixture.runId)).toEqual({ count: 0 });
      const safeStop = database.prepare(`
        SELECT json_extract(payload_json, '$.category') AS category, summary
        FROM events WHERE run_id = ? AND event_type = 'run.autonomous_safe_stopped'
        ORDER BY sequence DESC LIMIT 1
      `).get(fixture.runId) as { category: string; summary: string };
      expect(safeStop.category).toBe("rate_limit");
      expect(safeStop.summary).toContain("after 2 bounded automatic retries");
    } finally {
      await engine.stop();
    }
  });

  test("resumes one exact eligible retry after process loss without duplicating a provider turn", async () => {
    const directory = mkdtempSync(join(tmpdir(), "planning-retry-restart-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "ti-scale.sqlite");
    const firstDatabase = createDatabaseConnection({ filename: path });
    migrateDatabase(firstDatabase);
    const firstClock = new TestClock();
    const fixture = seed(firstDatabase, "restart");
    const first = runtime({
      database: firstDatabase,
      clock: firstClock,
      workerId: "planning-retry-before-crash",
      planner: { async plan() { throw rateLimit(2_000); } },
      crashAfterCommit(point) {
        if (point === "planning_retry_started") throw new Error("simulated process loss");
      },
    });
    await first.processRunNow(fixture.runId);
    firstClock.at(2_000);
    await expect(first.replayContinuations(fixture.runId, ["planning_retry_to_dispatch"])).rejects.toThrow(
      "Injected process crash after durable commit: planning_retry_started",
    );
    firstDatabase.close();

    const restartedDatabase = createDatabaseConnection({ filename: path, fileMustExist: true });
    databases.push(restartedDatabase);
    migrateDatabase(restartedDatabase);
    const restartedClock = new TestClock();
    restartedClock.at(3_100);
    let restartedCalls = 0;
    const restarted = runtime({
      database: restartedDatabase,
      clock: restartedClock,
      workerId: "planning-retry-after-crash",
      planner: { async plan() { restartedCalls += 1; throw policyDenial(); } },
    });
    try {
      await restarted.start();
      expect(restartedCalls).toBe(1);
      await restarted.scanOnce();
      await restarted.replayContinuations(fixture.runId, ["planning_retry_to_dispatch"]);
      expect(restartedCalls).toBe(1);
      expect(restartedDatabase.prepare("SELECT status FROM runs WHERE id = ?").get(fixture.runId))
        .toEqual({ status: "blocked" });
    } finally {
      await restarted.stop();
    }
  });

  test("fails closed immediately for a nonretryable planning denial", async () => {
    const database = memoryDatabase();
    const clock = new TestClock();
    const fixture = seed(database, "denial");
    let calls = 0;
    const engine = runtime({
      database,
      clock,
      workerId: "planning-retry-denial",
      planner: { async plan() { calls += 1; throw policyDenial(); } },
    });
    try {
      await expect(engine.processRunNow(fixture.runId)).rejects.toMatchObject({
        code: "provider_policy_denied",
      });
      expect(calls).toBe(1);
      expect(database.prepare("SELECT status, retry_count FROM runs WHERE id = ?").get(fixture.runId))
        .toEqual({ status: "blocked", retry_count: 0 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM runtime_continuations
        WHERE run_id = ? AND kind = 'planning_retry_to_dispatch'
      `).get(fixture.runId)).toEqual({ count: 0 });
    } finally {
      await engine.stop();
    }
  });

  test("preserves invalid_input in the persisted planning failure diagnosis", async () => {
    const database = memoryDatabase();
    const clock = new TestClock();
    const fixture = seed(database, "invalid-input");
    let calls = 0;
    const engine = runtime({
      database,
      clock,
      workerId: "planning-invalid-input",
      planner: { async plan() { calls += 1; throw invalidPlanningInput(); } },
    });
    try {
      await expect(engine.processRunNow(fixture.runId)).rejects.toMatchObject({
        code: "provider_plan_input_invalid",
      });
      expect(calls).toBe(1);
      expect(database.prepare("SELECT status, retry_count FROM runs WHERE id = ?").get(fixture.runId))
        .toEqual({ status: "blocked", retry_count: 0 });
      expect(database.prepare(`
        SELECT category, retryable FROM failure_diagnoses
        WHERE run_id = ? ORDER BY created_at DESC, id DESC LIMIT 1
      `).get(fixture.runId)).toEqual({ category: "invalid_input", retryable: 0 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM runtime_continuations
        WHERE run_id = ? AND kind = 'planning_retry_to_dispatch'
      `).get(fixture.runId)).toEqual({ count: 0 });
    } finally {
      await engine.stop();
    }
  });

  test("keeps jittered planning eligibility inside policy bounds", async () => {
    for (const [suffix, random, expectedDelay] of [
      ["jitter-low", () => 0, 400],
      ["jitter-high", () => 1, 600],
    ] as const) {
      const database = memoryDatabase();
      const clock = new TestClock();
      const fixture = seed(database, suffix);
      const engine = runtime({
        database,
        clock,
        workerId: `planning-retry-${suffix}`,
        random,
        planner: { async plan() { throw rateLimit(); } },
      });
      try {
        await engine.processRunNow(fixture.runId);
        const row = database.prepare(`
          SELECT available_at FROM runtime_continuations
          WHERE run_id = ? AND kind = 'planning_retry_to_dispatch'
        `).get(fixture.runId) as { available_at: string };
        expect(row.available_at).toBe(clock.iso(expectedDelay));
      } finally {
        await engine.stop();
      }
    }
  });

  test("does not schedule work the signed provider-turn budget cannot cover", async () => {
    const database = memoryDatabase();
    const clock = new TestClock();
    const fixture = seed(database, "provider-budget", {
      wallClockMs: 60_000,
      providerTurns: 1,
      retries: 2,
      replans: 1,
    });
    let calls = 0;
    const engine = runtime({
      database,
      clock,
      workerId: "planning-retry-provider-budget",
      planner: { async plan() { calls += 1; throw rateLimit(); } },
    });
    try {
      await expect(engine.processRunNow(fixture.runId)).rejects.toMatchObject({
        code: "mission_runtime_rate_limit_retry_exhausted",
      });
      expect(calls).toBe(1);
      const run = database.prepare(`
        SELECT status, retry_count, status_reason, budget_usage_json
        FROM runs WHERE id = ?
      `).get(fixture.runId) as {
        status: string;
        retry_count: number;
        status_reason: string;
        budget_usage_json: string;
      };
      expect(run.status).toBe("blocked");
      expect(run.retry_count).toBe(0);
      expect(run.status_reason).toContain("signed providerTurns budget");
      expect(JSON.parse(run.budget_usage_json)).toMatchObject({ providerTurns: 1, retries: 0 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM runtime_continuations
        WHERE run_id = ? AND kind = 'planning_retry_to_dispatch'
      `).get(fixture.runId)).toEqual({ count: 0 });
    } finally {
      await engine.stop();
    }
  });

  test("does not turn Guided planning recovery into silent autonomy", async () => {
    const database = memoryDatabase();
    const clock = new TestClock();
    const fixture = seed(database, "guided", {
      wallClockMs: 60_000,
      providerTurns: 8,
      retries: 2,
      replans: 1,
    }, "guided");
    let calls = 0;
    const engine = runtime({
      database,
      clock,
      workerId: "planning-retry-guided",
      planner: { async plan() { calls += 1; throw rateLimit(); } },
    });
    try {
      await expect(engine.processRunNow(fixture.runId)).rejects.toMatchObject({
        code: "provider_rate_limited",
      });
      expect(calls).toBe(1);
      expect(database.prepare("SELECT status, retry_count FROM runs WHERE id = ?").get(fixture.runId))
        .toEqual({ status: "blocked", retry_count: 0 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM runtime_continuations
        WHERE run_id = ? AND kind = 'planning_retry_to_dispatch'
      `).get(fixture.runId)).toEqual({ count: 0 });
    } finally {
      await engine.stop();
    }
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { RuntimeRepository } from "../../command-runtime/RuntimeRepository";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { ActionRepository } from "../../orchestration/ActionRepository";
import { CheckpointRepository } from "../../orchestration/CheckpointRepository";
import { canonicalJson, hashJson } from "../../orchestration/serialization";
import { createMissionRuntimeReadRouter } from "../MissionRuntimeReadRouter";

const NOW = "2026-07-16T12:00:00.000Z";
const servers: Server[] = [];
const databases: SqliteDatabase[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  for (const database of databases.splice(0)) database.close();
});

function seedMission(
  database: SqliteDatabase,
  input: {
    readonly id: string;
    readonly name: string;
    readonly journey: "autonomous" | "guided";
    readonly target: string;
  },
): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      success_criteria_json, memory_policy_json, created_by, created_at, updated_at
    ) VALUES (?, ?, ?, ?, 'active', 'verified', ?, ?, 'operator:test', ?, ?)
  `).run(
    input.id,
    input.name,
    `Assess the authorized ${input.target} target`,
    input.journey,
    JSON.stringify(["Retain one attributable observation"]),
    JSON.stringify({ allowGuided: true, allowAutonomous: false }),
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition,
      normalized_target, metadata_json, created_at
    ) VALUES (?, ?, ?, 'domain', 'allowed', ?, '{}', ?)
  `).run(`target-${input.id}`, input.id, input.target, input.target, NOW);
}

function seedRun(
  database: SqliteDatabase,
  input: {
    readonly id: string;
    readonly missionId: string;
    readonly journey: "autonomous" | "guided";
    readonly status: "running" | "waiting_guided_decision";
    readonly owner: string;
    readonly progress: number;
  },
): void {
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      next_action_summary, current_owner_id, budget_json, budget_usage_json,
      last_heartbeat_at, started_at, created_at, updated_at, version
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', '{}', ?, ?, ?, ?, 2)
  `).run(
    input.id,
    input.missionId,
    input.journey,
    input.status,
    input.progress,
    input.status === "waiting_guided_decision"
      ? "Waiting for one represented operator choice"
      : "Executing inside the signed contract",
    input.status === "waiting_guided_decision"
      ? "Review the represented reconnaissance step"
      : "Collect the next unique observation",
    input.owner,
    NOW,
    NOW,
    NOW,
    NOW,
  );
}

function seedGuidedPlan(database: SqliteDatabase): void {
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (
      'plan-alpha', 'run-alpha', 1, 'active',
      'Collect one bounded service observation',
      'The read-only action is sufficient for the current Guided phase',
      ?, 'planner:test', ?, ?
    )
  `).run("a".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, action_class, risk_class, assigned_agent_id,
      created_at, updated_at
    ) VALUES (
      'step-alpha', 'plan-alpha', 'run-alpha', 0, 'reconnaissance',
      'Inspect HTTPS service', 'Collect one attributable service result',
      'waiting_guided_decision', '["One service result is retained"]',
      'port_service_enumeration', 'low', 'ReconScout', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO mission_constraints (
      id, mission_id, constraint_type, value_json, source, created_at
    ) VALUES (
      'constraint-step-alpha', 'mission-alpha', 'represented_action', ?,
      'step-alpha', ?
    )
  `).run(JSON.stringify({
    action: {
      actionType: "service_enumeration",
      actionClass: "port_service_enumeration",
      target: "alpha.lab",
      arguments: { ports: [443] },
      intentSummary: "Inspect the authorized HTTPS service",
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
    explanation: "This step checks one authorized service without changing it.",
    rationale: "The result determines whether deeper HTTP inspection is useful.",
    reversibility: "Read-only and immediately reversible.",
    dependencies: [],
  }), NOW);
  database.prepare(`
    UPDATE runs SET current_plan_id = 'plan-alpha', current_step_id = 'step-alpha'
    WHERE id = 'run-alpha'
  `).run();
  database.prepare(`
    INSERT INTO guided_decisions (
      id, mission_id, run_id, step_id, requested_action_fingerprint,
      requested_parameters_json, rationale, risk_class, reversibility,
      status, expires_at, created_at
    ) VALUES (
      'decision-alpha', 'mission-alpha', 'run-alpha', 'step-alpha', ?, ?,
      'Collect one bounded service observation', 'low', 'Read-only',
      'pending', '2026-07-17T12:00:00.000Z', ?
    )
  `).run("b".repeat(64), JSON.stringify({ ports: [443], target: "alpha.lab" }), NOW);

  const state = {
    schemaVersion: 1 as const,
    run: {
      id: "run-alpha",
      missionId: "mission-alpha",
      journey: "guided" as const,
      state: "waiting_guided_decision" as const,
      stateVersion: 2,
      reason: "Waiting for one represented operator choice",
      leaseOwner: null,
      leaseExpiresAt: null,
    },
    control: {
      budget: { limits: { toolCalls: 20 }, usage: { toolCalls: 0 } },
      retryCount: 0,
      replanCount: 0,
      circuits: {},
      progress: { planVersion: 1, uncertainty: 0.5 },
    },
    completedActionIds: [],
    inFlightActions: [],
    lastEventSequence: 4,
  };
  database.prepare(`
    INSERT INTO checkpoints (
      id, mission_id, run_id, journey, event_sequence, plan_version,
      state_json, state_hash, created_at
    ) VALUES (
      'checkpoint-alpha', 'mission-alpha', 'run-alpha', 'guided', 4, 1,
      ?, ?, ?
    )
  `).run(canonicalJson(state), hashJson(state), NOW);
}

function seed(database: SqliteDatabase): void {
  seedMission(database, {
    id: "mission-empty",
    name: "New Guided mission",
    journey: "guided",
    target: "empty.lab",
  });
  seedMission(database, {
    id: "mission-alpha",
    name: "Credential portal assessment",
    journey: "guided",
    target: "alpha.lab",
  });
  seedMission(database, {
    id: "mission-private",
    name: "Private autonomous assessment",
    journey: "autonomous",
    target: "private.lab",
  });
  seedRun(database, {
    id: "run-alpha",
    missionId: "mission-alpha",
    journey: "guided",
    status: "waiting_guided_decision",
    owner: "ReconScout",
    progress: 0.4,
  });
  seedRun(database, {
    id: "run-private",
    missionId: "mission-private",
    journey: "autonomous",
    status: "running",
    owner: "VulnIntel",
    progress: 0.2,
  });
  seedGuidedPlan(database);
}

interface ErrorEnvelope {
  readonly error: {
    readonly code: string;
    readonly category: string;
    readonly humanMessage: string;
    readonly retryable: boolean;
    readonly traceId: string;
  };
}

async function json<T>(response: Response): Promise<T> {
  return response.json() as Promise<T>;
}

async function application() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  seed(database);
  const repository = new RuntimeRepository(database);
  const checkpoints = new CheckpointRepository(database, new ActionRepository(database));
  let actor: string | undefined = "operator:test";
  const allowedMissions = new Set(["mission-empty", "mission-alpha"]);
  const allowedRuns = new Set(["run-alpha"]);
  const authorizationCalls: string[] = [];
  const app = express();
  app.use(createMissionRuntimeReadRouter({
    repository,
    checkpoints,
    resolveActor: () => actor,
    authorizeMission: (_request, actorId, missionId) => {
      authorizationCalls.push(`mission:${actorId}:${missionId}`);
      return allowedMissions.has(missionId);
    },
    authorizeRun: (_request, actorId, scope) => {
      authorizationCalls.push(`run:${actorId}:${scope.missionId}:${scope.runId}`);
      return allowedRuns.has(scope.runId);
    },
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    allowedMissions,
    allowedRuns,
    authorizationCalls,
    setActor(value: string | undefined) { actor = value; },
  };
}

describe("MissionRuntimeReadRouter", () => {
  test("returns a canonical empty runtime snapshot for a newly created Guided mission", async () => {
    const fixture = await application();
    const response = await fetch(`${fixture.url}/api/v2/missions/mission-empty/runtime`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-request-id")).toBeTruthy();
    expect(await json<unknown>(response)).toEqual({
      schemaVersion: "2.4",
      mission: {
        id: "mission-empty",
        name: "New Guided mission",
        objective: "Assess the authorized empty.lab target",
        journey: "guided",
        engagementId: null,
        authorizationStatus: "verified",
        allowedTargets: ["empty.lab"],
        prohibitedTargets: [],
        successCriteria: ["Retain one attributable observation"],
        memoryPolicy: { allowAutonomous: false, allowGuided: true },
      },
      runs: [],
    });
    expect(fixture.authorizationCalls).toEqual([
      "mission:operator:test:mission-empty",
    ]);
  });

  test("returns client-compatible run, checkpoint, plan, and Guided decision projections", async () => {
    const fixture = await application();
    const runResponse = await fetch(`${fixture.url}/api/v2/runs/run-alpha`);
    expect(runResponse.status).toBe(200);
    const runBody = await json<{
      readonly schemaVersion: string;
      readonly run: Record<string, unknown>;
      readonly latestCheckpoint: Record<string, unknown>;
    }>(runResponse);
    expect(runBody.schemaVersion).toBe("2.4");
    expect(runBody.run).toEqual({
      id: "run-alpha",
      missionId: "mission-alpha",
      missionName: "Credential portal assessment",
      objective: "Assess the authorized alpha.lab target",
      journey: "guided",
      status: "waiting_guided_decision",
      statusReason: "Waiting for one represented operator choice",
      progress: 0.4,
      nextAction: "Review the represented reconnaissance step",
      currentPlanId: "plan-alpha",
      currentStepId: "step-alpha",
      currentOwnerId: "ReconScout",
      lastHeartbeatAt: NOW,
      leaseExpiresAt: null,
      startedAt: NOW,
      endedAt: null,
      createdAt: NOW,
      updatedAt: NOW,
      version: 2,
    });
    expect(runBody.latestCheckpoint).toMatchObject({
      id: "checkpoint-alpha",
      journey: "guided",
      eventSequence: 4,
      stateHash: expect.stringMatching(/^[a-f0-9]{64}$/u),
      state: { run: { id: "run-alpha", state: "waiting_guided_decision" } },
    });

    const planBody = await json<{
      readonly schemaVersion: string;
      readonly items: readonly Record<string, unknown>[];
    }>(await fetch(`${fixture.url}/api/v2/runs/run-alpha/plans`));
    expect(planBody.schemaVersion).toBe("2.4");
    expect(planBody.items).toHaveLength(1);
    expect(planBody.items[0]).toMatchObject({
      id: "plan-alpha",
      runId: "run-alpha",
      version: 1,
      steps: [{
        id: "step-alpha",
        dependencyStepIds: [],
        action: {
          actionType: "service_enumeration",
          actionClass: "port_service_enumeration",
          target: "alpha.lab",
          kind: "tool",
          idempotent: true,
          destructive: false,
        },
      }],
    });

    const decisions = await json<{
      readonly schemaVersion: string;
      readonly items: readonly Record<string, unknown>[];
    }>(await fetch(`${fixture.url}/api/v2/decisions?runId=run-alpha&status=pending`));
    expect(decisions).toMatchObject({
      schemaVersion: "2.4",
      items: [{
        id: "decision-alpha",
        missionId: "mission-alpha",
        runId: "run-alpha",
        stepId: "step-alpha",
        status: "pending",
        requestedParameters: { ports: [443], target: "alpha.lab" },
      }],
    });
  });

  test("authenticates every read and enforces mission and run authorization without leaking list items", async () => {
    const fixture = await application();
    fixture.setActor(undefined);
    const unauthenticated = await fetch(`${fixture.url}/api/v2/missions/mission-alpha/runtime`);
    expect(unauthenticated.status).toBe(401);
    expect(await json<ErrorEnvelope>(unauthenticated)).toMatchObject({
      error: {
        code: "runtime_read_authentication_required",
        category: "authentication_missing",
        retryable: false,
      },
    });

    fixture.setActor("operator:test");
    const deniedMission = await fetch(`${fixture.url}/api/v2/missions/mission-private/runtime`);
    expect(deniedMission.status).toBe(403);
    expect(await json<ErrorEnvelope>(deniedMission)).toMatchObject({
      error: { code: "runtime_read_policy_denied", category: "policy_denied" },
    });
    expect(fixture.authorizationCalls).not.toContain(
      "run:operator:test:mission-private:run-private",
    );

    fixture.allowedMissions.add("mission-private");
    const deniedRun = await fetch(`${fixture.url}/api/v2/runs/run-private`);
    expect(deniedRun.status).toBe(403);
    expect(await json<ErrorEnvelope>(deniedRun)).toMatchObject({
      error: { code: "runtime_read_policy_denied", category: "policy_denied" },
    });

    const list = await json<{ readonly items: readonly { readonly id: string }[] }>(
      await fetch(`${fixture.url}/api/v2/runs?limit=10`),
    );
    expect(list.items.map((run) => run.id)).toEqual(["run-alpha"]);
    const decisions = await json<{ readonly items: readonly { readonly id: string }[] }>(
      await fetch(`${fixture.url}/api/v2/decisions`),
    );
    expect(decisions.items.map((decision) => decision.id)).toEqual(["decision-alpha"]);
  });

  test("returns canonical not-found errors for absent missions, runs, plans, and decision run filters", async () => {
    const fixture = await application();
    for (const [path, code] of [
      ["/api/v2/missions/mission-missing/runtime", "mission_not_found"],
      ["/api/v2/runs/run-missing", "run_not_found"],
      ["/api/v2/runs/run-missing/plans", "run_not_found"],
      ["/api/v2/decisions?runId=run-missing", "run_not_found"],
    ] as const) {
      const response = await fetch(`${fixture.url}${path}`);
      expect(response.status).toBe(404);
      const payload = await json<ErrorEnvelope>(response);
      expect(payload.error).toMatchObject({
        code,
        category: "not_found",
        retryable: false,
      });
      expect(payload.error.traceId).toBeTruthy();
    }
  });

  test("applies strict run and decision filters and rejects ambiguous or unsupported query input", async () => {
    const fixture = await application();
    const runs = await json<{ readonly items: readonly { readonly id: string }[] }>(
      await fetch(
        `${fixture.url}/api/v2/runs?journey=guided&status=waiting_guided_decision&query=Credential&limit=1`,
      ),
    );
    expect(runs.items.map((run) => run.id)).toEqual(["run-alpha"]);
    const decisions = await json<{ readonly items: readonly { readonly id: string }[] }>(
      await fetch(
        `${fixture.url}/api/v2/decisions?status=pending&runId=run-alpha&query=bounded&limit=1`,
      ),
    );
    expect(decisions.items.map((decision) => decision.id)).toEqual(["decision-alpha"]);

    for (const [path, code] of [
      ["/api/v2/runs?journey=direct", "invalid_journey_filter"],
      ["/api/v2/runs?status=waiting_input", "invalid_run_status"],
      ["/api/v2/runs?limit=1e2", "invalid_pagination"],
      ["/api/v2/runs?query=%20", "invalid_run_search"],
      ["/api/v2/runs?status=running&status=blocked", "invalid_run_status"],
      ["/api/v2/runs?offset=1", "unsupported_runtime_filter"],
      ["/api/v2/decisions?status=authorized", "invalid_decision_status"],
      ["/api/v2/decisions?runId=bad%2Fid", "invalid_resource_id"],
      ["/api/v2/missions/mission-alpha/runtime?expand=all", "unsupported_runtime_filter"],
    ] as const) {
      const response = await fetch(`${fixture.url}${path}`);
      expect(response.status).toBe(400);
      expect(await json<ErrorEnvelope>(response)).toMatchObject({
        error: { code, category: "invalid_input", retryable: false },
      });
    }
  });

  test("exposes no write route and preserves durable state on rejected methods", async () => {
    const fixture = await application();
    const before = fixture.database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM runs) AS runs,
        (SELECT COUNT(*) FROM plans) AS plans,
        (SELECT COUNT(*) FROM guided_decisions) AS decisions,
        (SELECT COUNT(*) FROM checkpoints) AS checkpoints
    `).get();
    for (const path of [
      "/api/v2/missions/mission-alpha/runtime",
      "/api/v2/runs",
      "/api/v2/runs/run-alpha",
      "/api/v2/runs/run-alpha/plans",
      "/api/v2/decisions",
    ]) {
      const response = await fetch(`${fixture.url}${path}`, { method: "POST" });
      expect(response.status).toBe(405);
      expect(response.headers.get("allow")).toBe("GET");
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(await json<ErrorEnvelope>(response)).toMatchObject({
        error: {
          code: "runtime_read_method_not_allowed",
          category: "method_not_allowed",
          retryable: false,
        },
      });
    }
    expect(fixture.database.prepare(`
      SELECT
        (SELECT COUNT(*) FROM runs) AS runs,
        (SELECT COUNT(*) FROM plans) AS plans,
        (SELECT COUNT(*) FROM guided_decisions) AS decisions,
        (SELECT COUNT(*) FROM checkpoints) AS checkpoints
    `).get()).toEqual(before);
  });
});

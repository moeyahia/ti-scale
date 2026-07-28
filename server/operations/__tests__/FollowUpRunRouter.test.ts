import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createMissionRuntime,
  type ExecutionResultSink,
  type MissionOutcomeEvaluatorPort,
  type MissionPlannerPort,
  type ResultAwareExecutionPort,
} from "../../command-runtime";
import { ControlPlaneLeaseService } from "../../control-plane";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { canonicalLessonMemoryNodeId } from "../../learning/AttackChainLessonRepository";
import { MemoryRepository } from "../../memory";
import type { DurableAction } from "../../orchestration";
import { createOperationsRouter } from "../../routes/operationsRoutes";
import type { OperationsAccessPolicy } from "../types";

const NOW = "2026-07-15T14:00:00.000Z";
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

function seed(database: ReturnType<typeof createDatabaseConnection>): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      created_by, created_at, updated_at
    ) VALUES (
      'mission-follow-up', 'Follow-up mission', 'Validate the authorized service',
      'autonomous', 'completed', 'verified', 'eng-follow-up', 'operator', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES (
      'target-follow-up', 'mission-follow-up', 'lab.internal', 'domain',
      'allowed', 'lab.internal', ?
    )
  `).run(NOW);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, tool_policy_json, version, created_at, updated_at
    ) VALUES (
      'ReconScout', 'reconnaissance', 'ReconScout',
      'available', '{"allowedTools":["quick_scan"],"deniedTools":[],"approvalRequiredTools":[]}',
      '1', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO agent_capabilities (
      agent_id, capability, source, enabled, metadata_json
    ) VALUES (
      'ReconScout', 'quick_scan', 'runtime-manifest-tool-binding', 1,
      '{"toolId":"quick_scan","actionClassIds":["reconnaissance"]}'
    )
  `).run();
  database.prepare(`
    INSERT INTO mcp_servers (
      id, name, transport, status, capabilities_json, policy_json,
      last_checked_at, created_at, updated_at
    ) VALUES (
      'sechub-reconnaissance', 'sechub-reconnaissance', 'stdio', 'healthy',
      '["quick_scan"]',
      '{"schemaVersion":"ti-scale.specialist-mcp-execution-policy.v1","enabled":true,"startPermitted":true,"executionAuthorization":"signed_contract_specialist_action","autonomousExecution":true,"exactInventoryRequired":true,"directCommanderToolsAllowed":false,"assignedAgents":["ReconScout"]}',
      ?, ?, ?
    )
  `).run(NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (
      'contract-follow-up', 'mission-follow-up', 1, 'confirmed', ?, '{}',
      '{"allowedActionClasses":["reconnaissance"],"specialistAgentIds":["ReconScout"],"contextNodeIds":[]}',
      '{"retries":2,"replans":1}', '{}', '[]', '["verified_lessons"]',
      'operator', ?, ?
    )
  `).run("a".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, progress, status_reason,
      budget_json, budget_usage_json, started_at, ended_at, created_at, updated_at
    ) VALUES (
      'run-source', 'mission-follow-up', 'autonomous', 'completed',
      'contract-follow-up', 1, 'Completed autonomously',
      '{"retries":2,"replans":1}', '{"retries":0,"replans":0}', ?, ?, ?, ?
    )
  `).run(NOW, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO lessons (
      id, statement, lesson_type, applicability_scope, engagement_id, mission_id,
      confidence, expected_benefit, risk, status, authoring_agent_id,
      created_at, updated_at
    ) VALUES (
      'lesson-follow-up', 'Prefer the evidence-producing bounded service check',
      'strategy', 'mission', 'eng-follow-up', 'mission-follow-up', 0.9,
      'Avoid an unproductive repeated observation', 'low', 'under_review',
      'agent-evaluator', ?, ?
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO lesson_evidence (
      lesson_id, run_id, relationship, rationale, created_at
    ) VALUES (
      'lesson-follow-up', 'run-source', 'supports',
      'The terminal run provides canonical support', ?
    )
  `).run(NOW);
  database.prepare(`
    UPDATE lessons SET status = 'verified', reviewed_by = 'reviewer-independent',
      reviewed_at = ?, updated_at = ? WHERE id = 'lesson-follow-up'
  `).run(NOW, NOW);
  new MemoryRepository(database, { clock: () => new Date(NOW) }).createNode({
    id: canonicalLessonMemoryNodeId("lesson-follow-up"),
    nodeType: "lesson",
    title: "Prefer the evidence-producing bounded service check",
    summary: "Use the verified bounded observation that produced immutable evidence.",
    body: "Apply only inside the existing authorization and target boundary.",
    scope: { kind: "mission", engagementId: "eng-follow-up", missionId: "mission-follow-up" },
    sensitivity: "private",
    confidence: 0.9,
    lifecycleStatus: "verified",
    confirmationState: "not_required",
    provenance: {
      method: "derived",
      explanation: "Projected from an independently reviewed canonical lesson.",
      sources: [{ sourceType: "lesson", sourceId: "lesson-follow-up", acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "reviewer-independent",
    retentionPolicy: { allowAutonomous: true, allowGuided: true },
  });
}

class SchedulerExecution implements ResultAwareExecutionPort {
  readonly dispatched: DurableAction[] = [];
  private sink?: ExecutionResultSink;

  bindResultSink(sink: ExecutionResultSink): () => void {
    this.sink = sink;
    return () => { this.sink = undefined; };
  }

  async dispatch(action: DurableAction): Promise<void> {
    this.dispatched.push(action);
  }

  async resume(action: DurableAction): Promise<void> {
    this.dispatched.push(action);
  }

  async cancelRun(): Promise<void> {}
}

const schedulerPlanner: MissionPlannerPort = {
  async plan(input) {
    return {
      strategySummary: "Apply the bounded verified service observation in a fresh attempt",
      rationaleSummary: "The same signed target and action class remain sufficient",
      steps: [{
        phase: "reconnaissance",
        title: "Observe the authorized service",
        objective: "Collect one fresh specialist result",
        explanation: "The follow-up repeats only the bounded read-only observation.",
        rationale: "This action remains inside the unchanged Autonomous contract.",
        successCriteria: ["A fresh specialist result is retained"],
        assignedAgentId: "ReconScout",
        riskClass: "low",
        reversibility: "Read-only",
        action: {
          actionType: "reconnaissance",
          actionClass: "reconnaissance",
          target: input.mission.allowedTargets[0]!,
          arguments: {
            mcpServer: "sechub-reconnaissance",
            toolName: "quick_scan",
            arguments: { service: "https" },
          },
          intentSummary: "Observe the authorized service",
          kind: "tool",
          idempotent: true,
          destructive: false,
        },
      }],
    };
  },
};

const schedulerEvaluator: MissionOutcomeEvaluatorPort = {
  async evaluate() {
    return {
      success: false,
      summary: "The scheduler acceptance test leaves the action in flight.",
      criteria: [],
    };
  },
};

type LeaseMode = "valid" | "missing" | "stale" | "takeover";

async function application(config: { readonly includeLeaseResolver?: boolean } = {}) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  seed(database);
  const controlPlaneLeases = new ControlPlaneLeaseService(database);
  const leaseOwner = "follow-up-source-runtime";
  const leaseToken = "follow-up-source-runtime-token-000000";
  const initialProof = controlPlaneLeases.acquire({
    runId: "run-source",
    controlPlane: "ti_scale",
    leaseOwner,
    leaseToken,
    ttlMs: 300_000,
    now: new Date(NOW),
  }).lease;
  let leaseMode: LeaseMode = "valid";
  let leaseChecks = 0;
  const app = express();
  app.use(express.json());
  app.use(createOperationsRouter({
    database,
    clock: () => new Date(NOW),
    resolveActor: (request) => ({
      id: request.get("X-Test-Actor") ?? "operator-follow-up",
      type: request.get("X-Test-Actor-Type") === "reviewer" ? "reviewer" : "operator",
    }),
    resolveAccess: (request): OperationsAccessPolicy => request.get("X-Test-Access-Revoked") === "1"
      ? {
          maximumSensitivity: "private",
          engagementIds: [],
          missionIds: [],
          allowGlobalKnowledge: false,
        }
      : {
          maximumSensitivity: "private",
          engagementIds: ["eng-follow-up"],
          missionIds: ["mission-follow-up"],
          allowGlobalKnowledge: true,
        },
    ...(config.includeLeaseResolver === false ? {} : {
      assertRunMutationLease: ({ runId }: { readonly runId: string }) => {
        leaseChecks += 1;
        if (leaseMode === "missing") return undefined;
        if (leaseMode === "stale" && leaseChecks === 2) {
          controlPlaneLeases.heartbeat({
            runId,
            controlPlane: "ti_scale",
            leaseOwner,
            leaseToken,
            ttlMs: 300_000,
            now: new Date("2026-07-15T14:00:01.000Z"),
          });
          return initialProof;
        }
        if (leaseMode === "takeover" && leaseChecks === 2) {
          controlPlaneLeases.release({
            runId,
            controlPlane: "ti_scale",
            leaseOwner,
            leaseToken,
            now: new Date("2026-07-15T14:00:01.000Z"),
          });
          const takeoverOwner = "follow-up-takeover-runtime";
          const takeoverToken = "follow-up-takeover-runtime-token-0000";
          controlPlaneLeases.acquire({
            runId,
            controlPlane: "ti_scale",
            leaseOwner: takeoverOwner,
            leaseToken: takeoverToken,
            ttlMs: 300_000,
            now: new Date("2026-07-15T14:00:02.000Z"),
          });
          return controlPlaneLeases.assertMutationAuthority({
            runId,
            controlPlane: "ti_scale",
            leaseOwner: takeoverOwner,
            leaseToken: takeoverToken,
            now: new Date("2026-07-15T14:00:02.000Z"),
          });
        }
        return controlPlaneLeases.assertMutationAuthority({
          runId,
          controlPlane: "ti_scale",
          leaseOwner,
          leaseToken,
          now: new Date(NOW),
        });
      },
    }),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    setLeaseMode: (mode: LeaseMode) => { leaseMode = mode; leaseChecks = 0; },
    releaseSourceLease: () => controlPlaneLeases.release({
      runId: "run-source",
      controlPlane: "ti_scale",
      leaseOwner,
      leaseToken,
      now: new Date(NOW),
    }),
  };
}

function requestBody(reason = "Validate the verified lesson against a fresh bounded attempt"): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": "follow-up-run-0001" },
    body: JSON.stringify({ reason, selectedLessonIds: ["lesson-follow-up"] }),
  };
}

describe("canonical follow-up run HTTP boundary", () => {
  test("requires a current trusted V2 lease before first use, atomic write, and idempotent replay", async () => {
    const missingResolver = await application({ includeLeaseResolver: false });
    try {
      const missing = await fetch(`${missingResolver.url}/api/v2/operations/runs/run-source/follow-up`, requestBody());
      expect(missing.status).toBe(409);
      expect(await missing.json()).toMatchObject({ error: { code: "control_plane_lease_missing" } });
      expect(missingResolver.database.prepare("SELECT COUNT(*) AS count FROM runs").get()).toEqual({ count: 1 });
    } finally {
      missingResolver.database.close();
    }

    const stale = await application();
    try {
      stale.setLeaseMode("stale");
      const response = await fetch(`${stale.url}/api/v2/operations/runs/run-source/follow-up`, requestBody());
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ error: { code: "control_plane_lease_fence_invalid" } });
      expect(stale.database.prepare("SELECT COUNT(*) AS count FROM runs").get()).toEqual({ count: 1 });
    } finally {
      stale.database.close();
    }

    const takeover = await application();
    try {
      takeover.setLeaseMode("takeover");
      const response = await fetch(`${takeover.url}/api/v2/operations/runs/run-source/follow-up`, requestBody());
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ error: { code: "control_plane_lease_fence_invalid" } });
      expect(takeover.database.prepare("SELECT COUNT(*) AS count FROM runs").get()).toEqual({ count: 1 });
    } finally {
      takeover.database.close();
    }

    const replay = await application();
    try {
      expect((await fetch(`${replay.url}/api/v2/operations/runs/run-source/follow-up`, requestBody())).status).toBe(201);
      replay.releaseSourceLease();
      const deniedReplay = await fetch(`${replay.url}/api/v2/operations/runs/run-source/follow-up`, requestBody());
      expect(deniedReplay.status).toBe(409);
      expect(await deniedReplay.json()).toMatchObject({ error: { code: "control_plane_lease_missing" } });
      expect(replay.database.prepare("SELECT COUNT(*) AS count FROM runs").get()).toEqual({ count: 2 });
    } finally {
      replay.database.close();
    }

    const imported = await application();
    try {
      imported.database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = 'run-source'").run();
      const response = await fetch(`${imported.url}/api/v2/operations/runs/run-source/follow-up`, requestBody());
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ error: { code: "control_plane_mismatch" } });
      expect(imported.database.prepare("SELECT COUNT(*) AS count FROM runs").get()).toEqual({ count: 1 });
    } finally {
      imported.database.close();
    }
  });

  test("a live MissionRuntimeEngine scheduler discovers the HTTP-created follow-up and dispatches its Autonomous action", async () => {
    const { database, url } = await application();
    const execution = new SchedulerExecution();
    const runtime = createMissionRuntime({
      database,
      planner: schedulerPlanner,
      outcomeEvaluator: schedulerEvaluator,
      execution,
      workerId: "follow-up-scheduler-test",
      scanIntervalMs: 50,
      leaseTtlMs: 1_000,
    });
    try {
      await runtime.start();
      const response = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, {
        ...requestBody(),
        headers: { "Content-Type": "application/json", "Idempotency-Key": "follow-up-live-scheduler" },
      });
      expect(response.status).toBe(201);
      const created = await response.json() as { run: { id: string } };

      const deadline = Date.now() + 2_000;
      while (execution.dispatched.length === 0 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      expect(execution.dispatched).toHaveLength(1);
      expect(execution.dispatched[0]).toMatchObject({
        runId: created.run.id,
        kind: "tool",
        actionType: "reconnaissance",
        target: "lab.internal",
      });
      expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(created.run.id))
        .toEqual({ status: "running" });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM lesson_usage WHERE run_id = ?
      `).get(created.run.id)).toEqual({ count: 0 });
      expect(database.prepare(`
        SELECT mci.node_id
        FROM memory_context_packs mcp
        JOIN memory_context_items mci ON mci.context_pack_id = mcp.id
        WHERE mcp.run_id = ? AND mcp.purpose LIKE 'Mission planning:%'
      `).get(created.run.id)).toEqual({
        node_id: canonicalLessonMemoryNodeId("lesson-follow-up"),
      });
      expect(database.prepare(`
        SELECT control_plane, lease_owner, released_at
        FROM control_plane_leases WHERE run_id = ?
      `).get(created.run.id)).toEqual({
        control_plane: "ti_scale",
        lease_owner: "follow-up-scheduler-test",
        released_at: null,
      });
    } finally {
      await runtime.stop();
      database.close();
    }
  });

  test("replays an HTTP-created follow-up exactly once after a plan-commit scheduler crash", async () => {
    const { database, url } = await application();
    const response = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, {
      ...requestBody(),
      headers: { "Content-Type": "application/json", "Idempotency-Key": "follow-up-restart-replay" },
    });
    expect(response.status).toBe(201);
    const created = await response.json() as { run: { id: string } };

    let nowMs = Date.parse(NOW);
    const clock = () => new Date(nowMs);
    const firstExecution = new SchedulerExecution();
    let injected = false;
    const first = createMissionRuntime({
      database,
      planner: schedulerPlanner,
      outcomeEvaluator: schedulerEvaluator,
      execution: firstExecution,
      workerId: "follow-up-before-restart",
      scanIntervalMs: 50,
      leaseTtlMs: 1_000,
      now: clock,
      crashAfterCommit(point) {
        if (!injected && point === "plan_ready_to_dispatch") {
          injected = true;
          throw new Error("simulated scheduler process exit");
        }
      },
    });
    const replacementExecution = new SchedulerExecution();
    const replacement = createMissionRuntime({
      database,
      planner: schedulerPlanner,
      outcomeEvaluator: schedulerEvaluator,
      execution: replacementExecution,
      workerId: "follow-up-after-restart",
      scanIntervalMs: 50,
      leaseTtlMs: 1_000,
      now: clock,
    });
    try {
      expect(await first.scanOnce()).toBe(1);
      const deadline = Date.now() + 1_000;
      let continuation: { status: string } | undefined;
      while (!continuation && Date.now() < deadline) {
        continuation = database.prepare(`
          SELECT status FROM runtime_continuations
          WHERE run_id = ? AND kind = 'plan_ready_to_dispatch'
        `).get(created.run.id) as { status: string } | undefined;
        if (!continuation) await new Promise((resolve) => setTimeout(resolve, 5));
      }
      expect(injected).toBe(true);
      expect(continuation).toEqual({ status: "pending" });
      expect(firstExecution.dispatched).toHaveLength(0);
      expect(database.prepare("SELECT status FROM runs WHERE id = ?").get(created.run.id))
        .toEqual({ status: "running" });
      expect(database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?").get(created.run.id))
        .toEqual({ count: 0 });

      await first.stop();
      expect(database.prepare(`
        SELECT lease_owner, released_at IS NOT NULL AS released
        FROM control_plane_leases WHERE run_id = ?
      `).get(created.run.id)).toEqual({
        lease_owner: "follow-up-before-restart",
        released: 1,
      });
      nowMs += 2_000;
      await replacement.start();
      expect(replacementExecution.dispatched).toHaveLength(1);
      expect(replacementExecution.dispatched[0]).toMatchObject({
        runId: created.run.id,
        actionType: "reconnaissance",
        target: "lab.internal",
      });
      expect(database.prepare(`
        SELECT control_plane, lease_owner, released_at
        FROM control_plane_leases WHERE run_id = ?
      `).get(created.run.id)).toEqual({
        control_plane: "ti_scale",
        lease_owner: "follow-up-after-restart",
        released_at: null,
      });

      await replacement.scanOnce();
      expect(await replacement.replayContinuations(created.run.id)).toBe(0);
      expect(replacementExecution.dispatched).toHaveLength(1);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM actions WHERE run_id = ?
      `).get(created.run.id)).toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM events
        WHERE run_id = ? AND event_type = 'action.authorized'
      `).get(created.run.id)).toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT status FROM runtime_continuations
        WHERE run_id = ? AND kind = 'plan_ready_to_dispatch'
      `).get(created.run.id)).toEqual({ status: "completed" });
      expect(database.prepare(`
        SELECT a.status AS action_status, ass.status AS assignment_status,
          ps.status AS step_status, p.status AS plan_status
        FROM actions a
        JOIN assignments ass ON ass.id = a.assignment_id
        JOIN plan_steps ps ON ps.id = a.step_id
        JOIN plans p ON p.id = ps.plan_id
        WHERE a.run_id = ?
      `).get(created.run.id)).toEqual({
        action_status: "running",
        assignment_status: "active",
        step_status: "running",
        plan_status: "active",
      });
    } finally {
      await first.stop();
      await replacement.stop();
      database.close();
    }
  });

  test("creates one planning run with the unchanged journey and contract plus immutable verified-lesson selection", async () => {
    const { database, url } = await application();
    try {
      const first = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, requestBody());
      expect(first.status).toBe(201);
      const created = await first.json() as any;
      expect(created).toMatchObject({
        schemaVersion: "2.4",
        sourceRunId: "run-source",
        run: {
          missionId: "mission-follow-up",
          missionName: "Follow-up mission",
          journey: "autonomous",
          status: "planning",
        },
        selectedLessons: [{
          id: "lesson-follow-up",
          selectionState: "eligible_for_planning",
        }],
      });
      expect(created.nextUrl).toBe(`/missions/mission-follow-up/runs/${created.run.id}`);
      expect(database.prepare(`
        SELECT contract_id, contract_version_bound, contract_hash_bound,
          journey, status, budget_usage_json, retry_count, replan_count
        FROM runs WHERE id = ?
      `).get(created.run.id)).toEqual({
        contract_id: "contract-follow-up",
        contract_version_bound: 1,
        contract_hash_bound: "a".repeat(64),
        journey: "autonomous",
        status: "planning",
        budget_usage_json: "{}",
        retry_count: 0,
        replan_count: 0,
      });
      expect(database.prepare(`
        SELECT lesson_id, node_id, selected_by FROM run_context_selections WHERE run_id = ?
      `).get(created.run.id)).toMatchObject({
        lesson_id: "lesson-follow-up",
        node_id: canonicalLessonMemoryNodeId("lesson-follow-up"),
        selected_by: "operator-follow-up",
      });
      expect(() => database.prepare(`
        UPDATE run_context_selections SET reason = 'rewrite history' WHERE run_id = ?
      `).run(created.run.id)).toThrow("run context selections are immutable");
      expect(() => database.prepare(`
        DELETE FROM run_context_selections WHERE run_id = ?
      `).run(created.run.id)).toThrow("run context selections are immutable");
      expect(database.prepare(`
        SELECT event_type, journey,
          json_extract(payload_json, '$.sourceRunId') AS source_run_id,
          json_extract(payload_json, '$.contractChanged') AS contract_changed
        FROM events WHERE run_id = ?
      `).get(created.run.id)).toEqual({
        event_type: "run.follow_up_created",
        journey: "autonomous",
        source_run_id: "run-source",
        contract_changed: 0,
      });
      expect(database.prepare(`
        SELECT action, journey, actor_id FROM audit_records WHERE run_id = ?
      `).get(created.run.id)).toEqual({
        action: "run.follow_up_created",
        journey: "autonomous",
        actor_id: "operator-follow-up",
      });

      const replay = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, requestBody());
      expect(replay.status).toBe(201);
      expect((await replay.json() as any).run.id).toBe(created.run.id);
      const revokedReplay = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, {
        ...requestBody(),
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "follow-up-run-0001",
          "X-Test-Access-Revoked": "1",
        },
      });
      expect(revokedReplay.status).toBe(404);
      expect(await revokedReplay.json()).toMatchObject({
        error: { code: "operations_resource_not_found", category: "not_found" },
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM runs WHERE mission_id = 'mission-follow-up'
      `).get()).toEqual({ count: 2 });
    } finally {
      database.close();
    }
  });

  test("fails closed for a changed idempotent request, nonterminal source, non-operator actor, and stale lesson", async () => {
    const { database, url } = await application();
    try {
      expect((await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, requestBody())).status).toBe(201);
      expect((await fetch(
        `${url}/api/v2/operations/runs/run-source/follow-up`,
        requestBody("A materially different request using the same key must fail"),
      )).status).toBe(409);

      database.prepare("UPDATE runs SET status = 'running' WHERE id = 'run-source'").run();
      const nonterminal = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, {
        ...requestBody(),
        headers: { "Content-Type": "application/json", "Idempotency-Key": "follow-up-run-nonterminal" },
      });
      expect(nonterminal.status).toBe(409);
      database.prepare("UPDATE runs SET status = 'completed' WHERE id = 'run-source'").run();

      const reviewer = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, {
        ...requestBody(),
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "follow-up-run-reviewer",
          "X-Test-Actor-Type": "reviewer",
        },
      });
      expect(reviewer.status).toBe(403);

      database.prepare(`
        UPDATE memory_nodes SET retention_policy_json = '{}'
        WHERE id = ?
      `).run(canonicalLessonMemoryNodeId("lesson-follow-up"));
      const missingJourneyPermission = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, {
        ...requestBody(),
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "follow-up-run-missing-journey-permission",
        },
      });
      expect(missingJourneyPermission.status).toBe(409);
      expect(await missingJourneyPermission.json()).toMatchObject({
        error: { code: "follow_up_lesson_ineligible" },
      });
      database.prepare(`
        UPDATE memory_nodes SET retention_policy_json = '{"allowAutonomous":true,"allowGuided":true}'
        WHERE id = ?
      `).run(canonicalLessonMemoryNodeId("lesson-follow-up"));

      database.prepare("UPDATE lessons SET status = 'stale', updated_at = ? WHERE id = 'lesson-follow-up'").run(NOW);
      const stale = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, {
        ...requestBody(),
        headers: { "Content-Type": "application/json", "Idempotency-Key": "follow-up-run-stale" },
      });
      expect(stale.status).toBe(409);
      expect(await stale.json()).toMatchObject({ error: { code: "follow_up_lesson_ineligible" } });
    } finally {
      database.close();
    }
  });

  test("rejects credential-shaped follow-up reasons before immutable persistence without reflecting the value", async () => {
    const { database, url } = await application();
    try {
      // Assemble the deliberately synthetic value at runtime so repository
      // secret scanners do not mistake this negative fixture for a credential.
      const secretValue = ["follow", "up", "sensitive", "fixture"].join("-");
      const beforeRuns = database.prepare("SELECT COUNT(*) AS count FROM runs").get();
      const response = await fetch(`${url}/api/v2/operations/runs/run-source/follow-up`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "follow-up-secret-rejection",
        },
        body: JSON.stringify({
          reason: `password=${secretValue}`,
          selectedLessonIds: ["lesson-follow-up"],
        }),
      });
      expect(response.status).toBe(422);
      const errorBody = await response.json();
      expect(errorBody).toMatchObject({
        error: {
          code: "sensitive_material_not_retained",
          category: "policy_denied",
          details: { field: "Follow-up reason", rejection: "credential_like_material" },
        },
      });
      expect(JSON.stringify(errorBody)).not.toContain(secretValue);
      expect(database.prepare("SELECT COUNT(*) AS count FROM runs").get()).toEqual(beforeRuns);

      const persistedText = database.prepare(`
        SELECT reason AS value FROM run_context_selections
        UNION ALL SELECT summary || ' ' || payload_json FROM events
        UNION ALL SELECT reason || ' ' || details_json FROM audit_records
        UNION ALL SELECT value_json FROM settings
      `).all();
      expect(JSON.stringify(persistedText)).not.toContain(secretValue);
      expect(database.prepare("SELECT COUNT(*) AS count FROM run_context_selections").get())
        .toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });
});

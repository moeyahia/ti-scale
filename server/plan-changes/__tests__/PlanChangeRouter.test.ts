import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { BrainContextService } from "../../brain-runtime";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { RuntimeRepository } from "../../command-runtime";
import { ControlPlaneLeaseService, type ControlPlaneLease } from "../../control-plane";
import { createPlanChangeRouter, type PlanChangeActor, type PlanChangeAuthorizationRequest } from "../index";
import type { PlanChangeRequest } from "../types";

const MISSION_ID = "mission-plan-change";
const RUN_ID = "run-plan-change";
const PLAN_ID = "plan-plan-change-v1";
const STEP_ONE = "step-plan-change-one";
const STEP_TWO = "step-plan-change-two";
const AGENT_ID = "agent-plan-change";
const NOW = "2026-07-16T15:00:00.000Z";
const AUTONOMOUS_CONTRACT_ID = "contract-plan-change";
const CONTROL_LEASE_OWNER = "plan-change-router-runtime";
const CONTROL_LEASE_TOKEN = "plan-change-router-token-000000000000";

const exactRepresentation = (
  actionType: string,
  target = "fixture.local",
  argumentsValue: Record<string, unknown> = {},
  destructive = false,
) => ({
  action: {
    actionType,
    target,
    arguments: argumentsValue,
    intentSummary: "Collect one attributable authorized observation",
    kind: "manual",
    idempotent: true,
    destructive,
  },
  explanation: "Collect one bounded observation inside the supplied target scope.",
  rationale: "Reduce uncertainty before any dependent work begins.",
  reversibility: destructive ? "Use only on the named disposable lab target." : "Read-only and repeat-safe.",
});

interface Harness {
  readonly database: SqliteDatabase;
  readonly server: Server;
  readonly origin: string;
  readonly state: {
    actor: PlanChangeActor | undefined;
    allowed: boolean;
    leaseMode: "valid" | "missing" | "wrong_token" | "wrong_fence";
    readonly authorizations: PlanChangeAuthorizationRequest[];
  };
}

const harnesses: Harness[] = [];

interface HarnessOptions {
  readonly journey?: "autonomous" | "guided";
  readonly includeBrain?: boolean;
  readonly brainUnavailable?: boolean;
  readonly memoryRequired?: boolean;
}

function fixture(database: SqliteDatabase, options: HarnessOptions = {}): void {
  const journey = options.journey ?? "guided";
  const memoryPolicy = journey === "autonomous"
    ? {
        allowedScopes: options.memoryRequired ? ["verified_lessons"] : [],
        exactContextNodeIds: [],
      }
    : {};
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, scope_json,
      success_criteria_json, retention_policy_json, memory_policy_json,
      created_by, created_at, updated_at
    ) VALUES (?, 'Plan amendment fixture', 'Amend only reviewed pre-execution plans', ?, 'active', 'verified', '{}', '[]', '{}', ?, 'operator', ?, ?)
  `).run(MISSION_ID, journey, JSON.stringify(memoryPolicy), NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target,
      metadata_json, created_at
    ) VALUES ('target-plan-change', ?, 'fixture.local', 'domain', 'allowed', 'fixture.local', '{}', ?)
  `).run(MISSION_ID, NOW);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, created_at, updated_at
    ) VALUES (?, 'recon', 'Recon specialist', 'available', '{}', '{}', '{}', '1', ?, ?)
  `).run(AGENT_ID, NOW, NOW);
  if (journey === "autonomous") {
    database.prepare(`
      INSERT INTO mission_contracts (
        id, mission_id, version, state, contract_hash, authorization_json,
        action_policy_json, budgets_json, safe_stop_json, deliverables_json,
        memory_scopes_json, confirmed_by, confirmed_at, created_at
      ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{}', '{}', '[]', '[]', 'operator-plan', ?, ?)
    `).run(AUTONOMOUS_CONTRACT_ID, MISSION_ID, "b".repeat(64), JSON.stringify({
      allowedActionClasses: ["passive_intelligence_osint", "dns_domain_certificate_discovery"],
      prohibitedActionClasses: [],
      destructivePolicy: "prohibited",
      boundedDestructiveTargets: [],
      specialistAgentIds: [AGENT_ID],
    }), NOW, NOW);
  }
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id, contract_id,
      created_at, updated_at, version
    ) VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, ?, 1)
  `).run(RUN_ID, MISSION_ID, journey, PLAN_ID, STEP_ONE, journey === "autonomous" ? AUTONOMOUS_CONTRACT_ID : null, NOW, NOW);
  new ControlPlaneLeaseService(database).acquire({
    runId: RUN_ID,
    controlPlane: "ti_scale",
    leaseOwner: CONTROL_LEASE_OWNER,
    leaseToken: CONTROL_LEASE_TOKEN,
    ttlMs: 300_000,
    now: new Date(NOW),
  });
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Map the authorized fixture', 'Start with attributable discovery', ?, 'planner', ?, ?)
  `).run(PLAN_ID, RUN_ID, "a".repeat(64), NOW, NOW);
  const insertStep = database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'low', ?, ?, ?)
  `);
  insertStep.run(STEP_ONE, PLAN_ID, RUN_ID, 0, "Recon", "Collect passive scope facts", "Establish attributable target identity", "ready", '["Target identity recorded"]', "[]", "passive_intelligence_osint", AGENT_ID, NOW, NOW);
  insertStep.run(STEP_TWO, PLAN_ID, RUN_ID, 1, "Recon", "Validate DNS records", "Correlate approved names", "pending", '["DNS evidence recorded"]', JSON.stringify([STEP_ONE]), "dns_domain_certificate_discovery", AGENT_ID, NOW, NOW);
  const insertRepresentation = database.prepare(`
    INSERT INTO mission_constraints (id, mission_id, constraint_type, value_json, source, created_at)
    VALUES (?, ?, 'represented_action', ?, ?, ?)
  `);
  const representation = (actionClass: string, target: string, dependencies: string[]) => JSON.stringify({
    action: { actionType: actionClass, actionClass, target, arguments: {}, intentSummary: "Collect attributable authorized observations", kind: "manual", idempotent: true, destructive: false },
    explanation: "Collect one bounded observation.", rationale: "Reduce uncertainty without changing target state.", reversibility: "Read-only", dependencies,
  });
  insertRepresentation.run("constraint-step-one", MISSION_ID, representation("passive_intelligence_osint", "fixture.local", []), STEP_ONE, NOW);
  insertRepresentation.run("constraint-step-two", MISSION_ID, representation("dns_domain_certificate_discovery", "fixture.local", [STEP_ONE]), STEP_TWO, NOW);
  database.prepare(`
    INSERT INTO assignments (id, run_id, step_id, agent_id, status, created_at, updated_at)
    VALUES ('assignment-plan-change', ?, ?, ?, 'queued', ?, ?)
  `).run(RUN_ID, STEP_ONE, AGENT_ID, NOW, NOW);
}

async function createHarness(options: HarnessOptions = {}): Promise<Harness> {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  fixture(database, options);
  const state: Harness["state"] = {
    actor: { id: "operator-plan", type: "operator" },
    allowed: true,
    leaseMode: "valid",
    authorizations: [],
  };
  const leases = new ControlPlaneLeaseService(database);
  const brainContext = options.includeBrain
    ? new BrainContextService({
        database,
        secondBrain: new SecondBrainService(new MemoryRepository(database, {
          clock: () => new Date(NOW),
        })),
        ...(options.brainUnavailable
          ? {
              availability: () => ({
                available: false,
                code: "brain_offline",
                explanation: "The local Second Brain dependency is offline.",
              }),
            }
          : {}),
      })
    : undefined;
  const app = express();
  app.use(express.json());
  app.use(createPlanChangeRouter({
    database,
    resolveActor: () => state.actor,
    authorize: (_request, _actor, authorization) => { state.authorizations.push(authorization); return state.allowed; },
    clock: () => new Date(NOW),
    ...(brainContext ? { brainContext } : {}),
    assertRunMutationLease: ({ runId }) => {
      if (state.leaseMode === "missing") return undefined;
      const proof = leases.assertMutationAuthority({
        runId,
        controlPlane: "ti_scale",
        leaseOwner: CONTROL_LEASE_OWNER,
        leaseToken: state.leaseMode === "wrong_token"
          ? "wrong-plan-change-token-000000000"
          : CONTROL_LEASE_TOKEN,
        now: new Date(NOW),
      });
      return state.leaseMode === "wrong_fence"
        ? { ...proof, version: proof.version + 1 } satisfies ControlPlaneLease
        : proof;
    },
  }));
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  const harness = { database, server, origin: `http://127.0.0.1:${address.port}`, state };
  harnesses.push(harness);
  return harness;
}

afterEach(async () => {
  await Promise.all(harnesses.splice(0).map(async (harness) => {
    await new Promise<void>((resolve) => harness.server.close(() => resolve()));
    harness.database.close();
  }));
});

async function request(harness: Harness, path: string, input: { readonly method?: string; readonly key?: string; readonly body?: unknown } = {}) {
  const headers = new Headers({ "X-Request-ID": "plan-change-router-test" });
  if (input.body !== undefined) headers.set("Content-Type", "application/json");
  if (input.key) headers.set("Idempotency-Key", input.key);
  const response = await fetch(`${harness.origin}${path}`, { method: input.method ?? "GET", headers, ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }) });
  return { status: response.status, headers: response.headers, body: await response.json() as Record<string, unknown> };
}

const summaryProposal = (summary: string) => ({
  basePlanId: PLAN_ID,
  expectedRunVersion: 1,
  expectedPlanVersion: 1,
  requestText: "Narrow the strategy after reviewing the current authorized scope.",
  operations: [{ kind: "update_plan", strategySummary: summary }],
});

function seedReplanLesson(database: SqliteDatabase): void {
  new MemoryRepository(database, { clock: () => new Date(NOW) }).createNode({
    id: "memory-plan-change-recovery",
    nodeType: "lesson",
    title: "Plan recovery evidence lesson",
    summary: "Review failed plan conditions and verified evidence before applying a materially different recovery plan.",
    body: "This verified local lesson is retrieval context only and never rewrites an operator amendment.",
    scope: { kind: "mission", missionId: MISSION_ID },
    sensitivity: "internal",
    confidence: 0.9,
    lifecycleStatus: "verified",
    confirmationState: "not_required",
    provenance: {
      method: "derived",
      explanation: "Verified from a prior local run evaluation.",
      sources: [{ sourceType: "run_evaluation", sourceId: "evaluation-plan-change", acquiredAt: NOW }],
    },
    authorType: "agent",
    authorId: "run-evaluator",
    retentionPolicy: { allowAutonomous: true, allowGuided: true },
  });
}

describe("PlanChangeRouter", () => {
  test("persists replan Context Packs for propose, edit, and apply without silently reinterpreting the operator diff", async () => {
    const harness = await createHarness({ includeBrain: true });
    seedReplanLesson(harness.database);
    const created = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST",
      key: "plan-brain-propose",
      body: summaryProposal("Use the bounded evidence-backed recovery path"),
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const proposal = created.body.request as PlanChangeRequest;
    const proposePackId = created.body.contextPackId as string;
    expect(proposePackId).toMatch(/^ctx_/u);
    expect(harness.database.prepare(`
      SELECT journey, purpose, query_redacted, retrieval_metrics_json
      FROM memory_context_packs WHERE id = ?
    `).get(proposePackId)).toEqual(expect.objectContaining({
      journey: "guided",
      purpose: expect.stringContaining("Replanning:"),
      query_redacted: "Retrieve bounded scoped context before propose plan amendment.",
    }));
    expect(harness.database.prepare(`
      SELECT used, influence_summary, ignored_reason
      FROM memory_context_items WHERE context_pack_id = ? AND node_id = ?
    `).get(proposePackId, "memory-plan-change-recovery")).toEqual({
      used: 0,
      influence_summary: null,
      ignored_reason: expect.stringContaining("did not silently reinterpret"),
    });

    const edited = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}`, {
      method: "PUT",
      key: "plan-brain-edit",
      body: {
        expectedRequestVersion: 1,
        expectedRunVersion: 1,
        expectedPlanVersion: 1,
        operations: [{ kind: "update_plan", strategySummary: "Use a narrower evidence-backed recovery path" }],
      },
    });
    expect(edited.status).toBe(200);
    expect(edited.body.contextPackId).not.toBe(proposePackId);

    const applied = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}/apply`, {
      method: "POST",
      key: "plan-brain-apply",
      body: { expectedRequestVersion: 2, expectedRunVersion: 1, expectedPlanVersion: 1 },
    });
    expect(applied.status, JSON.stringify(applied.body)).toBe(200);
    expect(applied.body.contextPackId).not.toBe(edited.body.contextPackId);
    expect(harness.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_context_packs
      WHERE run_id = ? AND purpose LIKE 'Replanning:%'
    `).get(RUN_ID)).toEqual({ count: 3 });
  });

  test("persists degraded Guided context and fails required Autonomous replanning closed with an audit receipt", async () => {
    const guided = await createHarness({ includeBrain: true, brainUnavailable: true });
    const degraded = await request(guided, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST",
      key: "plan-brain-guided-degraded",
      body: summaryProposal("Preserve the represented plan while memory is degraded"),
    });
    expect(degraded.status, JSON.stringify(degraded.body)).toBe(201);
    const degradedPackId = degraded.body.contextPackId as string;
    const degradedPack = guided.database.prepare(`
      SELECT retrieval_metrics_json FROM memory_context_packs WHERE id = ?
    `).get(degradedPackId) as { readonly retrieval_metrics_json: string };
    expect(JSON.parse(degradedPack.retrieval_metrics_json)).toMatchObject({
      hook: "replan",
      status: "degraded",
      dependencyCode: "brain_offline",
    });

    const autonomous = await createHarness({
      journey: "autonomous",
      includeBrain: true,
      brainUnavailable: true,
      memoryRequired: true,
    });
    const blocked = await request(autonomous, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST",
      key: "plan-brain-autonomous-blocked",
      body: summaryProposal("This amendment must not bypass required memory"),
    });
    expect(blocked.status).toBe(503);
    expect((blocked.body.error as { readonly code: string }).code).toBe("brain_context_unavailable");
    expect(autonomous.database.prepare("SELECT COUNT(*) AS count FROM plan_change_requests").get())
      .toEqual({ count: 0 });
    const audit = autonomous.database.prepare(`
      SELECT details_json FROM audit_records
      WHERE run_id = ? AND action = 'brain.context_hook.invoked'
      ORDER BY rowid DESC LIMIT 1
    `).get(RUN_ID) as { readonly details_json: string };
    expect(JSON.parse(audit.details_json)).toMatchObject({
      hook: "replan",
      status: "blocked",
      contextPackId: null,
      availabilityPolicy: "required",
      dependencyCode: "brain_offline",
    });
  });

  test("fences every proposal mutation by V2 ownership and the current server-held lease", async () => {
    const harness = await createHarness();

    harness.database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?").run(MISSION_ID);
    const legacy = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-authority-legacy", body: summaryProposal("Retain the authorized strategy"),
    });
    expect(legacy.status).toBe(409);
    expect((legacy.body.error as { code: string }).code).toBe("control_plane_mismatch");
    harness.database.prepare("UPDATE missions SET control_plane = 'ti_scale' WHERE id = ?").run(MISSION_ID);

    harness.database.prepare("UPDATE runs SET control_plane = 'legacy' WHERE id = ?").run(RUN_ID);
    const legacyRun = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-authority-legacy-run", body: summaryProposal("Retain the authorized strategy"),
    });
    expect(legacyRun.status).toBe(409);
    expect((legacyRun.body.error as { code: string }).code).toBe("control_plane_mismatch");
    harness.database.prepare("UPDATE runs SET control_plane = 'ti_scale' WHERE id = ?").run(RUN_ID);

    harness.database.prepare("DELETE FROM control_plane_leases WHERE run_id = ?").run(RUN_ID);
    const absentLease = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-authority-no-row", body: summaryProposal("Retain the authorized strategy"),
    });
    expect(absentLease.status).toBe(409);
    expect((absentLease.body.error as { code: string }).code).toBe("control_plane_lease_missing");
    new ControlPlaneLeaseService(harness.database).acquire({
      runId: RUN_ID,
      controlPlane: "ti_scale",
      leaseOwner: CONTROL_LEASE_OWNER,
      leaseToken: CONTROL_LEASE_TOKEN,
      ttlMs: 300_000,
      now: new Date(NOW),
    });

    harness.state.leaseMode = "missing";
    const missing = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-authority-missing", body: summaryProposal("Retain the authorized strategy"),
    });
    expect(missing.status).toBe(409);
    expect((missing.body.error as { code: string }).code).toBe("control_plane_lease_missing");

    harness.state.leaseMode = "wrong_token";
    const wrongToken = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-authority-token", body: summaryProposal("Retain the authorized strategy"),
    });
    expect(wrongToken.status).toBe(409);
    expect((wrongToken.body.error as { code: string }).code).toBe("control_plane_lease_authority_invalid");

    harness.state.leaseMode = "wrong_fence";
    const wrongFence = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-authority-fence", body: summaryProposal("Retain the authorized strategy"),
    });
    expect(wrongFence.status).toBe(409);
    expect((wrongFence.body.error as { code: string }).code).toBe("control_plane_lease_fence_invalid");

    harness.state.leaseMode = "valid";
    harness.database.prepare("UPDATE control_plane_leases SET expires_at = ? WHERE run_id = ?")
      .run("2026-07-16T14:59:59.000Z", RUN_ID);
    const expired = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-authority-expired", body: summaryProposal("Retain the authorized strategy"),
    });
    expect(expired.status).toBe(409);
    expect((expired.body.error as { code: string }).code).toBe("control_plane_lease_expired");

    harness.database.prepare("UPDATE control_plane_leases SET expires_at = ? WHERE run_id = ?")
      .run("2026-07-16T15:05:00.000Z", RUN_ID);
    const valid = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-authority-valid", body: summaryProposal("Retain the authorized strategy with proof"),
    });
    expect(valid.status).toBe(201);
    const proposal = valid.body.request as PlanChangeRequest;
    expect(proposal.status).toBe("validated");

    // A durable replay is still unauthorized after the runtime proof is lost.
    harness.state.leaseMode = "missing";
    const replayWithoutAuthority = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-authority-valid", body: summaryProposal("Retain the authorized strategy with proof"),
    });
    expect(replayWithoutAuthority.status).toBe(409);
    expect((replayWithoutAuthority.body.error as { code: string }).code).toBe("control_plane_lease_missing");

    const edit = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}`, {
      method: "PUT",
      key: "plan-authority-edit-missing",
      body: {
        expectedRequestVersion: 1,
        expectedRunVersion: 1,
        expectedPlanVersion: 1,
        operations: [{ kind: "update_plan", strategySummary: "A fenced edit must not apply" }],
      },
    });
    expect(edit.status).toBe(409);
    expect((edit.body.error as { code: string }).code).toBe("control_plane_lease_missing");

    harness.state.leaseMode = "wrong_token";
    const apply = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}/apply`, {
      method: "POST",
      key: "plan-authority-apply-token",
      body: { expectedRequestVersion: 1, expectedRunVersion: 1, expectedPlanVersion: 1 },
    });
    expect(apply.status).toBe(409);
    expect((apply.body.error as { code: string }).code).toBe("control_plane_lease_authority_invalid");

    harness.state.leaseMode = "wrong_fence";
    const reject = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}/reject`, {
      method: "POST",
      key: "plan-authority-reject-fence",
      body: { expectedRequestVersion: 1, reason: "A stale lease must not reject this proposal." },
    });
    expect(reject.status).toBe(409);
    expect((reject.body.error as { code: string }).code).toBe("control_plane_lease_fence_invalid");
  });

  test("fails closed for missing identity, denied scope, missing idempotency, and stale versions", async () => {
    const harness = await createHarness();
    harness.state.actor = undefined;
    expect((await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`)).status).toBe(401);
    harness.state.actor = { id: "operator-plan", type: "operator" };
    harness.state.allowed = false;
    const denied = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`);
    expect(denied.status).toBe(403);
    expect(harness.state.authorizations.at(-1)).toEqual({ missionId: MISSION_ID, runId: RUN_ID, capability: "read_plan_changes" });
    harness.state.allowed = true;
    expect((await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, { method: "POST", body: summaryProposal("Use the evidence-backed path") })).status).toBe(400);
    const stale = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, { method: "POST", key: "plan-stale-0001", body: { ...summaryProposal("Use the evidence-backed path"), expectedRunVersion: 2 } });
    expect(stale.status).toBe(409);
    expect((stale.body.error as { code: string }).code).toBe("plan_change_run_version_conflict");
  });

  test("proposes, replays, edits, lists, and rejects exact structured diffs", async () => {
    const harness = await createHarness();
    const created = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, { method: "POST", key: "plan-create-0001", body: summaryProposal("Map only attributable scope and preserve evidence") });
    expect(created.status).toBe(201);
    expect(created.headers.get("idempotency-replayed")).toBe("false");
    const proposal = created.body.request as PlanChangeRequest;
    expect(proposal).toMatchObject({ status: "validated", basePlanId: PLAN_ID, version: 1 });
    expect(proposal.structuredDiff).toEqual([expect.objectContaining({ kind: "replace", path: "strategySummary" })]);
    expect(proposal.inflightImpact).toMatchObject({ safeToApply: true, queuedAssignmentIdsToCancel: ["assignment-plan-change"] });
    expect(proposal.budgetImpact).toMatchObject({ durationEstimate: "not_observed", costEstimate: "not_observed" });

    const replay = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, { method: "POST", key: "plan-create-0001", body: summaryProposal("Map only attributable scope and preserve evidence") });
    expect(replay.headers.get("idempotency-replayed")).toBe("true");
    expect(replay.body).toEqual(created.body);
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM plan_change_requests").get() as { count: number }).count).toBe(1);

    const edited = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}`, {
      method: "PUT", key: "plan-edit-0001", body: {
        expectedRequestVersion: 1, expectedRunVersion: 1, expectedPlanVersion: 1,
        requestText: "Use a clearer strategy summary without changing action scope.",
        operations: [{ kind: "update_plan", strategySummary: "Correlate passive scope facts before DNS validation" }],
      },
    });
    expect(edited.status).toBe(200);
    expect(edited.body.request).toMatchObject({ status: "validated", version: 2 });
    const listed = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`);
    expect(listed.status).toBe(200);
    expect((listed.body.items as PlanChangeRequest[])[0]?.version).toBe(2);

    const rejected = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}/reject`, {
      method: "POST", key: "plan-reject-0001", body: { expectedRequestVersion: 2, reason: "Keep the original strategy until new evidence exists." },
    });
    expect(rejected.status).toBe(200);
    expect(rejected.body.request).toMatchObject({ status: "rejected", version: 3 });
    expect((harness.database.prepare("SELECT status FROM plans WHERE id = ?").get(PLAN_ID) as { status: string }).status).toBe("active");
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM events").get() as { count: number }).count).toBe(3);
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM audit_records").get() as { count: number }).count).toBe(3);
  });

  test("activates a new immutable plan version without executing or reinterpreting an action", async () => {
    const harness = await createHarness();
    const created = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, { method: "POST", key: "plan-create-apply", body: summaryProposal("Map attributable scope, then validate DNS evidence") });
    const proposal = created.body.request as PlanChangeRequest;
    const applied = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}/apply`, {
      method: "POST", key: "plan-apply-0001", body: { expectedRequestVersion: 1, expectedRunVersion: 1, expectedPlanVersion: 1 },
    });
    expect(applied.status).toBe(200);
    expect(applied.body.request).toMatchObject({ status: "applied", version: 2 });
    expect(applied.body.resultPlanVersion).toBe(2);
    const resultPlanId = applied.body.resultPlanId as string;
    expect(harness.database.prepare("SELECT status FROM plans WHERE id = ?").get(PLAN_ID)).toEqual({ status: "superseded" });
    expect(harness.database.prepare("SELECT status, version FROM plans WHERE id = ?").get(resultPlanId)).toEqual({ status: "active", version: 2 });
    expect(harness.database.prepare("SELECT current_plan_id, version, replan_count, status FROM runs WHERE id = ?").get(RUN_ID)).toEqual({ current_plan_id: resultPlanId, version: 2, replan_count: 1, status: "queued" });
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM plan_step_versions WHERE plan_id = ?").get(resultPlanId) as { count: number }).count).toBe(2);
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM mission_constraints WHERE constraint_type = 'represented_action' AND source IN (SELECT id FROM plan_steps WHERE plan_id = ?)").get(resultPlanId) as { count: number }).count).toBe(2);
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM actions").get() as { count: number }).count).toBe(0);
    expect(harness.database.prepare("SELECT status FROM assignments WHERE id = 'assignment-plan-change'").get()).toEqual({ status: "cancelled" });
    expect((harness.database.prepare("SELECT DISTINCT status FROM plan_steps WHERE plan_id = ?").all(PLAN_ID) as Array<{ status: string }>)).toEqual([{ status: "cancelled" }]);
    const applyEvent = harness.database.prepare("SELECT summary, payload_json FROM events WHERE event_type = 'plan_change.applied'").get() as { summary: string; payload_json: string };
    expect(applyEvent.summary).toContain("without starting or replaying any action");
    expect(JSON.parse(applyEvent.payload_json).details.executionStarted).toBe(false);
    const runtimePlan = new RuntimeRepository(harness.database).listPlans(RUN_ID)[0];
    expect(runtimePlan).toMatchObject({ id: resultPlanId, version: 2, status: "active" });
    expect(runtimePlan?.steps.map((step) => step.action.actionClass)).toEqual([
      "passive_intelligence_osint",
      "dns_domain_certificate_discovery",
    ]);
  });

  test("persists blocked policy and in-flight impact instead of cancelling work or widening scope", async () => {
    const harness = await createHarness();
    harness.database.prepare("UPDATE runs SET status = 'running', lease_owner = 'worker-live', version = 2 WHERE id = ?").run(RUN_ID);
    harness.database.prepare("UPDATE plan_steps SET status = 'running' WHERE id = ?").run(STEP_ONE);
    harness.database.prepare("UPDATE assignments SET status = 'active' WHERE id = 'assignment-plan-change'").run();
    const blocked = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-running-0001", body: {
        basePlanId: PLAN_ID, expectedRunVersion: 2, expectedPlanVersion: 1,
        requestText: "Do not interrupt the live specialist; record this for review only.",
        operations: [{ kind: "update_step", stepId: STEP_TWO, actionClass: "destructive_modification" }],
      },
    });
    expect(blocked.status).toBe(201);
    const proposal = blocked.body.request as PlanChangeRequest;
    expect(proposal.status).toBe("proposed");
    expect(proposal.policyValidation).toMatchObject({ valid: false, prohibitedActionClasses: ["destructive_modification"] });
    expect(proposal.inflightImpact).toMatchObject({ safeToApply: false, requiresCancellation: true, leaseOwner: "worker-live" });
    const apply = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}/apply`, {
      method: "POST", key: "plan-running-apply", body: { expectedRequestVersion: 1, expectedRunVersion: 2, expectedPlanVersion: 1 },
    });
    expect(apply.status).toBe(409);
    expect((apply.body.error as { code: string }).code).toBe("plan_change_policy_denied");
    expect(harness.database.prepare("SELECT lease_owner, status FROM runs WHERE id = ?").get(RUN_ID)).toEqual({ lease_owner: "worker-live", status: "running" });
    expect(harness.database.prepare("SELECT status FROM assignments WHERE id = 'assignment-plan-change'").get()).toEqual({ status: "active" });
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM actions").get() as { count: number }).count).toBe(0);
  });

  test("keeps invalid dependency order as a non-applicable proposal", async () => {
    const harness = await createHarness();
    const created = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-dependency-0001", body: {
        basePlanId: PLAN_ID, expectedRunVersion: 1, expectedPlanVersion: 1,
        requestText: "Record this invalid ordering so the operator can correct it before apply.",
        operations: [{ kind: "set_dependencies", stepId: STEP_ONE, dependencyStepIds: [STEP_TWO] }],
      },
    });
    expect(created.status).toBe(201);
    const proposal = created.body.request as PlanChangeRequest;
    expect(proposal.status).toBe("proposed");
    expect(proposal.dependencyImpact.valid).toBe(false);
    expect(proposal.dependencyImpact.issues.join(" ")).toContain(`must appear after dependency ${STEP_TWO}`);
    const apply = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}/apply`, {
      method: "POST", key: "plan-dependency-apply", body: { expectedRequestVersion: 1, expectedRunVersion: 1, expectedPlanVersion: 1 },
    });
    expect(apply.status).toBe(409);
    expect((apply.body.error as { code: string }).code).toBe("plan_change_dependency_invalid");
    expect(harness.database.prepare("SELECT status FROM plans WHERE id = ?").get(PLAN_ID)).toEqual({ status: "active" });
  });

  test("adds a fully represented step and preserves its exact action in the diff and immutable version", async () => {
    const harness = await createHarness();
    const created = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-add-step-0001", body: {
        basePlanId: PLAN_ID, expectedRunVersion: 1, expectedPlanVersion: 1,
        requestText: "Add bounded version-aware CVE classification after DNS evidence is preserved.",
        operations: [{
          kind: "add_step",
          clientStepId: "draft-cve-applicability",
          afterStepId: STEP_TWO,
          phase: "Analysis",
          title: "Classify applicable CVEs",
          objective: "Compare verified product evidence with authoritative vulnerability sources",
          successCriteria: ["Every candidate has an explicit applicability state and source"],
          dependencyStepIds: [STEP_TWO],
          actionClass: "cve_intelligence_applicability_validation",
          riskClass: "low",
          assignedAgentId: AGENT_ID,
          representation: exactRepresentation("cve_intelligence_applicability_validation", "fixture.local", { versionEvidenceId: "evidence-version-1" }),
        }],
      },
    });
    expect(created.status).toBe(201);
    const proposal = created.body.request as PlanChangeRequest;
    expect(proposal).toMatchObject({ status: "validated", affectedRefs: { addedClientStepIds: ["draft-cve-applicability"] } });
    const added = proposal.structuredDiff.find((entry) => entry.path === "steps[draft-cve-applicability]");
    expect(added).toMatchObject({ kind: "add" });
    expect(added?.after).toMatchObject({
      actionClass: "cve_intelligence_applicability_validation",
      representation: { action: { target: "fixture.local", actionClass: "cve_intelligence_applicability_validation", destructive: false } },
    });

    const applied = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes/${proposal.id}/apply`, {
      method: "POST", key: "plan-add-apply-0001", body: {
        expectedRequestVersion: 1, expectedRunVersion: 1, expectedPlanVersion: 1,
      },
    });
    expect(applied.status).toBe(200);
    const resultPlanId = applied.body.resultPlanId as string;
    const runtimePlan = new RuntimeRepository(harness.database).listPlans(RUN_ID).find((plan) => plan.id === resultPlanId);
    expect(runtimePlan?.steps).toHaveLength(3);
    expect(runtimePlan?.steps[2]).toMatchObject({
      title: "Classify applicable CVEs",
      action: { actionType: "cve_intelligence_applicability_validation", actionClass: "cve_intelligence_applicability_validation", target: "fixture.local" },
    });
    const snapshot = harness.database.prepare(`
      SELECT snapshot_json FROM plan_step_versions
      WHERE plan_id = ? ORDER BY rowid DESC LIMIT 1
    `).get(resultPlanId) as { readonly snapshot_json: string };
    expect(JSON.parse(snapshot.snapshot_json)).toMatchObject({
      logicalId: "draft-cve-applicability",
      representation: { action: { arguments: { versionEvidenceId: "evidence-version-1" } } },
    });
  });

  test("revalidates represented action scope and rejects embedded authentication material", async () => {
    const harness = await createHarness();
    const outOfScope = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-action-scope-1", body: {
        basePlanId: PLAN_ID, expectedRunVersion: 1, expectedPlanVersion: 1,
        operations: [{
          kind: "set_represented_action",
          stepId: STEP_TWO,
          representation: exactRepresentation("dns_domain_certificate_discovery", "outside.fixture"),
        }],
      },
    });
    expect(outOfScope.status).toBe(201);
    const proposal = outOfScope.body.request as PlanChangeRequest;
    expect(proposal.status).toBe("proposed");
    expect(proposal.policyValidation.valid).toBe(false);
    expect(proposal.policyValidation.reasons.join(" ")).toContain("outside the mission's normalized allowed scope");
    expect(proposal.structuredDiff).toEqual([expect.objectContaining({
      kind: "replace", path: `steps[${STEP_TWO}].representation`, label: "Validate DNS records: Exact represented action",
    })]);

    const secret = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-action-secret-1", body: {
        basePlanId: PLAN_ID, expectedRunVersion: 1, expectedPlanVersion: 1,
        operations: [{
          kind: "set_represented_action",
          stepId: STEP_TWO,
          representation: exactRepresentation("dns_domain_certificate_discovery", "fixture.local", { password: "not-stored" }),
        }],
      },
    });
    expect(secret.status).toBe(400);
    expect((secret.body.error as { readonly code: string }).code).toBe("sensitive_plan_change_argument");
    expect((harness.database.prepare("SELECT COUNT(*) AS count FROM plan_change_requests").get() as { readonly count: number }).count).toBe(1);
  });

  test("mirrors Autonomous action-type, specialist, target, and destructive contract gates before apply", async () => {
    const harness = await createHarness({ journey: "autonomous" });
    const created = await request(harness, `/api/v2/runs/${RUN_ID}/plan-changes`, {
      method: "POST", key: "plan-autonomous-gates", body: {
        basePlanId: PLAN_ID, expectedRunVersion: 1, expectedPlanVersion: 1,
        operations: [{
          kind: "set_represented_action",
          stepId: STEP_TWO,
          representation: exactRepresentation("unapproved_action_type", "fixture.local", {}, true),
        }],
      },
    });
    expect(created.status).toBe(201);
    const proposal = created.body.request as PlanChangeRequest;
    expect(proposal.status).toBe("proposed");
    expect(proposal.policyValidation).toMatchObject({ valid: false, journey: "autonomous", contractId: AUTONOMOUS_CONTRACT_ID });
    expect(proposal.policyValidation.reasons.join(" ")).toContain("action type unapproved_action_type is not pre-authorized");
    expect(proposal.policyValidation.reasons.join(" ")).toContain("destructive action outside the signed bounded-lab destructive policy");
  });
});

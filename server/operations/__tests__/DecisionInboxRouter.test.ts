import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { createOperationsRouter } from "../../routes/operationsRoutes";
import type { OperationsAccessPolicy } from "../types";

type Db = ReturnType<typeof createDatabaseConnection>;
const servers: Server[] = [];
const A = "2026-07-15T10:00:00.000Z";
const B = "2026-07-15T10:01:00.000Z";
const C = "2026-07-15T10:02:00.000Z";
const D = "2026-07-15T10:03:00.000Z";

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

function mission(database: Db, id: string, journey: "autonomous" | "guided", engagementId: string): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      engagement_id, created_by, created_at, updated_at
    ) VALUES (?, ?, 'Bounded fixture objective', ?, 'active', 'verified', ?, 'operator', ?, ?)
  `).run(id, `${journey} ${id}`, journey, engagementId, A, D);
}

function contract(database: Db, id: string, missionId: string, version: number, state: "draft" | "confirmed"): void {
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, ?, ?, ?, '{"authorizationConfirmed":true}',
      '{"allowedActionClasses":["reconnaissance"]}', '{}', '{}', '[]', '[]', ?, ?, ?)
  `).run(
    id,
    missionId,
    version,
    state,
    (version === 1 ? "a" : "b").repeat(64),
    state === "confirmed" ? "operator" : null,
    state === "confirmed" ? B : null,
    state === "confirmed" ? B : C,
  );
}

function run(database: Db, id: string, missionId: string, journey: "autonomous" | "guided", status: string, contractId: string | null = null): void {
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, progress, status_reason,
      ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    missionId,
    journey,
    status,
    contractId,
    status === "failed" ? 0.4 : 0.2,
    status === "failed" ? "Safe-stopped outside contract" : "Canonical fixture",
    status === "failed" ? D : null,
    A,
    D,
  );
}

function seed(database: Db): void {
  mission(database, "mission-guided-a", "guided", "eng-a");
  mission(database, "mission-auto-a", "autonomous", "eng-a");
  mission(database, "mission-auto-active-a", "autonomous", "eng-a");
  mission(database, "mission-auto-b", "autonomous", "eng-b");
  contract(database, "contract-a", "mission-auto-a", 1, "confirmed");
  contract(database, "contract-a-draft", "mission-auto-a", 2, "draft");
  contract(database, "contract-active-a", "mission-auto-active-a", 1, "confirmed");
  contract(database, "contract-b", "mission-auto-b", 1, "confirmed");
  run(database, "run-guided-a", "mission-guided-a", "guided", "waiting_guided_decision");
  run(database, "run-auto-a", "mission-auto-a", "autonomous", "failed", "contract-a");
  run(database, "run-auto-active-a", "mission-auto-active-a", "autonomous", "running", "contract-active-a");
  run(database, "run-auto-b", "mission-auto-b", "autonomous", "failed", "contract-b");

  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      created_by, created_at, activated_at
    ) VALUES ('plan-guided-a', 'run-guided-a', 1, 'active', 'Bounded Guided plan', ?, 'commander', ?, ?)
  `).run("p".repeat(64), A, B);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      action_class, risk_class, created_at, updated_at
    ) VALUES ('step-guided-a', 'plan-guided-a', 'run-guided-a', 0, 'Recon',
      'Inspect bounded target', 'Collect unique evidence', 'waiting_guided_decision',
      'reconnaissance', 'low', ?, ?)
  `).run(A, B);
  database.prepare(`
    INSERT INTO guided_decisions (
      id, mission_id, run_id, step_id, requested_action_fingerprint,
      requested_parameters_json, rationale, risk_class, reversibility,
      status, expires_at, created_at
    ) VALUES ('guided-decision-a', 'mission-guided-a', 'run-guided-a',
      'step-guided-a', ?, '{"target":"lab.internal","credential":"must-redact"}',
      'Inspect the exact approved target', 'low', 'Read only', 'pending',
      '2026-07-16T10:00:00.000Z', ?)
  `).run("f".repeat(64), C);

  const approval = database.prepare(`
    INSERT INTO approvals (
      id, mission_id, run_id, approval_type, status, requested_by, reason,
      policy_rule, request_json, expires_at, created_at
    ) VALUES (?, ?, ?, ?, 'pending', 'policy-service', ?, ?, ?,
      '2026-07-16T10:00:00.000Z', ?)
  `);
  approval.run(
    "approval-terminal-a", "mission-auto-a", "run-auto-a", "policy_change",
    "Review a future policy change", "future.policy", '{"api_key":"must-redact","change":"future-only"}', C,
  );
  approval.run(
    "approval-active-a", "mission-auto-active-a", "run-auto-active-a", "configuration_change",
    "Must not unblock the active run", "future.configuration", '{}', D,
  );
  approval.run(
    "approval-hidden-b", "mission-auto-b", "run-auto-b", "policy_change",
    "Hidden engagement approval", "future.policy", '{}', D,
  );

  const event = database.prepare(`
    INSERT INTO events (
      id, mission_id, run_id, sequence, event_type, occurred_at,
      actor_type, actor_id, summary, payload_json, journey, trace_id,
      sensitivity, redaction_json, created_at
    ) VALUES (?, ?, ?, 1, 'run.autonomous_safe_stopped', ?, 'system', 'supervisor',
      ?, ?, 'autonomous', ?, 'private', '{"paths":["nested.secret"]}', ?)
  `);
  event.run(
    "exception-a", "mission-auto-a", "run-auto-a", D,
    "No in-contract path remained", '{"code":"outside_contract","category":"scope_conflict","token":"must-redact","nested":{"secret":"hide","safe":"visible"}}',
    "trace-a", D,
  );
  event.run(
    "exception-b", "mission-auto-b", "run-auto-b", D,
    "Hidden engagement exception", '{}', "trace-b", D,
  );
  database.prepare(`
    INSERT INTO events (
      id, mission_id, run_id, sequence, event_type, occurred_at,
      actor_type, actor_id, summary, payload_json, journey, trace_id,
      sensitivity, redaction_json, created_at
    ) VALUES ('continuation-blocked-a', 'mission-auto-active-a', 'run-auto-active-a', 2,
      'run.continuation_blocked', ?, 'system', 'runtime-supervisor',
      'Unsafe in-flight action was not replayed',
      '{"code":"unsafe_replay_blocked","category":"deterministic_tool_error"}',
      'autonomous', 'trace-continuation-a', 'private', '{}', ?)
  `).run(D, D);
}

async function application(canReview = true) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  seed(database);
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.use(createOperationsRouter({
    database,
    clock: () => new Date("2026-07-15T12:00:00.000Z"),
    resolveActor: () => ({ id: "reviewer-one", type: "reviewer" }),
    resolveAccess: (): OperationsAccessPolicy => ({
      maximumSensitivity: "private",
      engagementIds: ["eng-a"],
      missionIds: ["mission-guided-a", "mission-auto-a", "mission-auto-active-a"],
      allowUnscopedSystemData: false,
      canReviewAdministrativeApprovals: canReview,
    }),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return { database, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

describe("canonical decision inbox", () => {
  test("returns scoped first-class records, redacts payloads, and paginates by stable cursor", async () => {
    const { database, url } = await application();
    try {
      const first = await fetch(`${url}/api/v2/decision-inbox?limit=2`);
      expect(first.status).toBe(200);
      const payload = await first.json() as any;
      expect(payload.items).toHaveLength(2);
      expect(payload.nextCursor).toBeString();
      const second = await fetch(`${url}/api/v2/decision-inbox?limit=2&cursor=${encodeURIComponent(payload.nextCursor)}`);
      const secondPayload = await second.json() as any;
      expect(secondPayload.items).toHaveLength(2);
      expect(secondPayload.items.map((item: any) => `${item.kind}:${item.id}`))
        .not.toEqual(payload.items.map((item: any) => `${item.kind}:${item.id}`));

      const exceptions = await (await fetch(`${url}/api/v2/decision-inbox?kind=autonomous_exception`)).json() as any;
      expect(exceptions.items).toHaveLength(2);
      const safeStop = exceptions.items.find((item: any) => item.id === "exception-a");
      expect(safeStop).toMatchObject({
        id: "exception-a", status: "post_run", mission: { id: "mission-auto-a" },
        run: { id: "run-auto-a", journey: "autonomous" },
        exception: { eventType: "run.autonomous_safe_stopped", phase: "post_run", code: "outside_contract" },
      });
      expect(exceptions.items.find((item: any) => item.id === "continuation-blocked-a")).toMatchObject({
        title: "Autonomous continuation blocked",
        status: "attention",
        run: { id: "run-auto-active-a", journey: "autonomous" },
        exception: { eventType: "run.continuation_blocked", phase: "active", code: "unsafe_replay_blocked" },
      });
      expect(JSON.stringify(exceptions)).not.toContain("must-redact");
      expect(JSON.stringify(exceptions)).not.toContain('"secret":"hide"');
      expect(JSON.stringify(exceptions)).toContain("visible");

      const contracts = await (await fetch(`${url}/api/v2/decision-inbox?kind=autonomous_contract`)).json() as any;
      expect(contracts.items.map((item: any) => item.id).sort()).toEqual(["contract-a", "contract-a-draft", "contract-active-a"]);
      expect(JSON.stringify(contracts)).not.toContain("allowedActionClasses");
      expect(contracts.items.find((item: any) => item.id === "contract-a-draft"))
        .toMatchObject({ status: "draft", contract: { version: 2, state: "draft" } });

      const guided = await (await fetch(`${url}/api/v2/decision-inbox?kind=guided_decision&status=pending`)).json() as any;
      expect(guided.items[0]).toMatchObject({
        id: "guided-decision-a", exactStep: { stepId: "step-guided-a", riskClass: "low" },
      });
      expect(guided.items[0].exactStep.requestedParameters.credential).toBe("[REDACTED]");
      expect(database.prepare("SELECT COUNT(*) AS count FROM events WHERE id = 'exception-b'").get()).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });

  test("reviews terminal administrative records idempotently without changing runtime state", async () => {
    const { database, url } = await application();
    try {
      const request = () => fetch(`${url}/api/v2/administrative-approvals/approval-terminal-a/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "admin-review-terminal-a" },
        body: JSON.stringify({ status: "approved", reason: "Approved for future policy configuration only" }),
      });
      const first = await request();
      expect(first.status).toBe(200);
      const result = await first.json() as any;
      expect(result.approval).toMatchObject({
        id: "approval-terminal-a", status: "approved",
        runtimeStateChanged: false, autonomousActionUnblocked: false,
      });
      expect((await request()).status).toBe(200);
      expect(database.prepare("SELECT status FROM runs WHERE id = 'run-auto-a'").get()).toEqual({ status: "failed" });
      expect(database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = 'run-auto-a'").get()).toEqual({ count: 0 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE resource_id = 'approval-terminal-a' AND action = 'administrative_approval.approved'
      `).get()).toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT details_json FROM audit_records WHERE resource_id = 'approval-terminal-a'
      `).get()).toMatchObject({ details_json: expect.stringContaining('"autonomousActionUnblocked":false') });
    } finally {
      database.close();
    }
  });

  test("never uses an administrative approval to unblock a running Autonomous mission", async () => {
    const { database, url } = await application();
    try {
      const response = await fetch(`${url}/api/v2/administrative-approvals/approval-active-a/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "admin-review-active-a" },
        body: JSON.stringify({ status: "approved", reason: "Attempt to resume active work" }),
      });
      expect(response.status).toBe(409);
      const payload = await response.json() as any;
      expect(payload.error.remediation).toContain("contract amendment");
      expect(database.prepare("SELECT status FROM approvals WHERE id = 'approval-active-a'").get()).toEqual({ status: "pending" });
      expect(database.prepare("SELECT status FROM runs WHERE id = 'run-auto-active-a'").get()).toEqual({ status: "running" });
      expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE resource_id = 'approval-active-a'").get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("requires explicit administrative review authority and validates inbox filters", async () => {
    const { database, url } = await application(false);
    try {
      const denied = await fetch(`${url}/api/v2/administrative-approvals/approval-terminal-a/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": "admin-review-denied-a" },
        body: JSON.stringify({ status: "rejected", reason: "Not authorized to decide" }),
      });
      expect(denied.status).toBe(403);
      expect((await fetch(`${url}/api/v2/decision-inbox?kind=not-real`)).status).toBe(400);
    } finally {
      database.close();
    }
  });
});

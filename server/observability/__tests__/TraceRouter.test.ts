import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import type { OperationsAccessPolicy } from "../../operations/types";
import { createOperationsRouter } from "../../routes/operationsRoutes";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

const A = "2026-07-15T12:00:00.000Z";
const B = "2026-07-15T12:00:01.000Z";
const C = "2026-07-15T12:00:02.000Z";

type Database = ReturnType<typeof createDatabaseConnection>;

function seed(database: Database): void {
  const mission = database.prepare(`
    INSERT INTO missions (id, name, objective, journey, engagement_id, created_by, created_at, updated_at)
    VALUES (?, ?, 'Authorized trace test', 'guided', ?, 'operator', ?, ?)
  `);
  mission.run("mission-visible", "Visible mission", "eng-visible", A, C);
  mission.run("mission-hidden", "Hidden mission", "eng-hidden", A, C);
  const run = database.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, progress, created_at, updated_at)
    VALUES (?, ?, 'guided', 'running', 0.5, ?, ?)
  `);
  run.run("run-visible", "mission-visible", A, C);
  run.run("run-hidden", "mission-hidden", A, C);
  const event = database.prepare(`
    INSERT INTO events (
      id, mission_id, run_id, sequence, event_type, occurred_at, actor_type, actor_id,
      summary, payload_json, journey, trace_id, span_id, sensitivity, redaction_json, created_at
    ) VALUES (?, ?, ?, 1, ?, ?, 'agent', 'recon', ?, ?, 'guided', ?, ?, 'private', ?, ?)
  `);
  event.run("event-visible", "mission-visible", "run-visible", "evidence.added", B, "Unique service evidence retained", JSON.stringify({ credential: "trace-event-secret", opaque: { value: "trace-path-secret" } }), "trace-shared", "span-event", JSON.stringify({ paths: ["opaque.value"] }), B); // gitleaks:allow -- synthetic redaction fixture
  event.run("event-hidden", "mission-hidden", "run-hidden", "hidden.event", B, "Hidden engagement event", "{}", "trace-shared", "span-hidden", "{}", B);
  database.prepare(`
    INSERT INTO structured_logs (
      id, mission_id, run_id, severity, domain, message, attributes_json,
      trace_id, span_id, sensitivity, occurred_at
    ) VALUES ('log-visible', 'mission-visible', 'run-visible', 'error', 'provider',
      'Provider timeout while preserving checkpoint', ?, 'trace-shared', 'span-log', 'private', ?)
  `).run(JSON.stringify({ password: "trace-log-secret", category: "timeout" }), B); // gitleaks:allow -- synthetic redaction fixture
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, action_type, action_class, fingerprint,
      normalized_arguments_json, status, intent_summary, result_summary,
      trace_id, span_id, started_at, ended_at, created_at, updated_at
    ) VALUES (
      'action-visible', 'mission-visible', 'run-visible', 'scan', 'reconnaissance', ?,
      ?, 'succeeded', 'Map approved service', 'One unique service retained',
      'trace-shared', 'span-action', ?, ?, ?, ?
    )
  `).run("a".repeat(64), JSON.stringify({ token: "trace-action-secret" }), A, C, A, C); // gitleaks:allow -- synthetic redaction fixture
  database.prepare(`
    INSERT INTO tool_calls (
      id, action_id, provider, tool_name, normalized_arguments_json, status,
      latency_ms, output_summary, redacted_payload_json, started_at, ended_at, created_at
    ) VALUES (
      'tool-visible', 'action-visible', 'mcp', 'network_scan', ?, 'succeeded',
      900, 'Service map retained', ?, ?, ?, ?
    )
  `).run(JSON.stringify({ api_key: "trace-tool-argument-secret" }), JSON.stringify({ api_key: "trace-tool-output-secret", services: 1 }), A, B, A); // gitleaks:allow -- synthetic redaction fixture
  database.prepare(`
    INSERT INTO events (
      id, mission_id, run_id, sequence, event_type, occurred_at, actor_type,
      summary, payload_json, journey, trace_id, sensitivity, created_at
    ) VALUES (
      'event-hidden-only', 'mission-hidden', 'run-hidden', 2, 'hidden.only', ?, 'system',
      'Hidden trace only', '{}', 'guided', 'trace-hidden-only', 'private', ?
    )
  `).run(C, C);
}

async function application(): Promise<{ database: Database; url: string }> {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  seed(database);
  const app = express();
  app.use(createOperationsRouter({
    database,
    resolveActor: () => ({ id: "reviewer", type: "reviewer" }),
    resolveAccess: (): OperationsAccessPolicy => ({
      maximumSensitivity: "private",
      engagementIds: ["eng-visible"],
      missionIds: ["mission-visible"],
      allowUnscopedSystemData: false,
    }),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return { database, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

describe("scope-enforced trace HTTP projections", () => {
  test("correlates real visible sources, paginates records, and redacts technical detail", async () => {
    const { database, url } = await application();
    try {
      const listResponse = await fetch(`${url}/api/v2/observability/traces?query=provider`);
      expect(listResponse.status).toBe(200);
      const list = await listResponse.json() as any;
      expect(list.items).toHaveLength(1);
      expect(list.items[0]).toMatchObject({
        traceId: "trace-shared",
        status: "failed",
        mission: { id: "mission-visible", name: "Visible mission" },
        missionCount: 1,
        runId: "run-visible",
        counts: { events: 1, logs: 1, actions: 1, toolCalls: 1, errors: 1 },
      });

      const firstResponse = await fetch(`${url}/api/v2/observability/traces/trace-shared?limit=2`);
      expect(firstResponse.status).toBe(200);
      const first = await firstResponse.json() as any;
      expect(first.records.items).toHaveLength(2);
      expect(first.records.nextCursor).toEqual(expect.any(String));
      const second = await (await fetch(`${url}/api/v2/observability/traces/trace-shared?limit=2&cursor=${encodeURIComponent(first.records.nextCursor)}`)).json() as any;
      expect(second.records.items).toHaveLength(2);
      expect(new Set([...first.records.items, ...second.records.items].map((item: any) => item.id)).size).toBe(4);
      expect([...first.records.items, ...second.records.items].map((item: any) => item.kind).sort()).toEqual(["action", "event", "log", "tool_call"]);

      const serialized = JSON.stringify({ list, first, second });
      for (const forbidden of [
        "Hidden engagement event", "event-hidden", "trace-event-secret", "trace-log-secret",
        "trace-action-secret", "trace-tool-argument-secret", "trace-tool-output-secret", "trace-path-secret",
      ]) expect(serialized).not.toContain(forbidden); // gitleaks:allow -- synthetic redaction fixtures
      expect(serialized).toContain("[REDACTED]");
      expect(await fetch(`${url}/api/v2/observability/traces/trace-hidden-only`).then((response) => response.status)).toBe(404);
      expect(await fetch(`${url}/api/v2/observability/traces?status=unknown`).then((response) => response.status)).toBe(400);
    } finally {
      database.close();
    }
  });
});

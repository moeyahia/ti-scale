import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { BrainContextService } from "../../brain-runtime";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { createOperationsRouter } from "../../routes/operationsRoutes";
import type { OperationsAccessPolicy } from "../types";
import { canonicalJson, sha256 } from "../validation";

const NOW = "2026-07-17T05:00:00.000Z";
const servers: Server[] = [];
const databases: SqliteDatabase[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  for (const database of databases.splice(0)) database.close();
});

function seedTerminalRun(
  database: SqliteDatabase,
  journey: "autonomous" | "guided",
  memoryPolicy: Readonly<Record<string, unknown>>,
): { readonly missionId: string; readonly runId: string } {
  const missionId = `mission-reporting-${journey}`;
  const runId = `run-reporting-${journey}`;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      engagement_id, success_criteria_json, memory_policy_json,
      created_by, created_at, updated_at
    ) VALUES (?, ?, 'Produce the bounded terminal report', ?, 'completed',
      'verified', 'eng-reporting', '[]', ?, 'operator:test', ?, ?)
  `).run(
    missionId,
    `${journey} reporting fixture`,
    journey,
    JSON.stringify(memoryPolicy),
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, started_at, ended_at,
      created_at, updated_at
    ) VALUES (?, ?, ?, 'completed', 1, 'Authorized fixture completed',
      '{}', '{}', ?, ?, ?, ?)
  `).run(runId, missionId, journey, NOW, NOW, NOW, NOW);
  return { missionId, runId };
}

async function application(input: {
  readonly journey: "autonomous" | "guided";
  readonly memoryPolicy: Readonly<Record<string, unknown>>;
}) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  const fixture = seedTerminalRun(database, input.journey, input.memoryPolicy);
  const brainContext = new BrainContextService({
    database,
    secondBrain: new SecondBrainService(new MemoryRepository(database)),
    availability: (hook) => hook === "reporting"
      ? {
          available: false,
          code: "brain_offline",
          explanation: "The local Second Brain index is unavailable for this test.",
        }
      : { available: true },
  });
  const access: OperationsAccessPolicy = {
    maximumSensitivity: "private",
    engagementIds: ["eng-reporting"],
    missionIds: [fixture.missionId],
    allowUnscopedSystemData: false,
    allowGlobalKnowledge: false,
  };
  const app = express();
  app.use(createOperationsRouter({
    database,
    brainContext,
    clock: () => new Date(NOW),
    resolveActor: () => ({ id: "operator:test", type: "operator" }),
    resolveAccess: () => access,
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    fixture,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
  };
}

describe("terminal report mandatory Brain context", () => {
  test("Guided persists an audited degraded Context Pack before producing the report", async () => {
    const scope = await application({
      journey: "guided",
      memoryPolicy: { preferenceUse: "confirmed_or_consent_governed" },
    });

    const response = await fetch(`${scope.url}/api/v2/reports/runs/${scope.fixture.runId}/export`);
    expect(response.status).toBe(200);
    const exported = await response.json() as Record<string, any>;
    expect(exported.reportingContext).toMatchObject({
      status: "degraded",
      retrievedItems: 0,
      appliedItems: 0,
      degradation: { code: "brain_offline" },
    });
    expect(exported.reportingContext.contextPackId).toBeTruthy();
    expect(exported.memoryContext).toContainEqual(expect.objectContaining({
      id: exported.reportingContext.contextPackId,
      retrievedItems: 0,
      usedItems: 0,
    }));
    const { integrity, ...metadata } = exported;
    expect(integrity).toEqual({ algorithm: "sha256", digest: sha256(canonicalJson(metadata)) });

    const records = scope.database.prepare(`
      SELECT action, details_json FROM audit_records
      WHERE run_id = ? AND action IN ('brain.context_hook.invoked', 'run.completion_exported')
      ORDER BY rowid
    `).all(scope.fixture.runId) as Array<{ readonly action: string; readonly details_json: string }>;
    expect(records.map(({ action }) => action)).toEqual([
      "brain.context_hook.invoked",
      "run.completion_exported",
    ]);
    expect(JSON.parse(records[0]!.details_json)).toMatchObject({
      hook: "reporting",
      status: "degraded",
      availabilityPolicy: "degraded_allowed",
      contextPackId: exported.reportingContext.contextPackId,
      dependencyCode: "brain_offline",
    });
  });

  test("Autonomous fails closed before report production when signed memory is required", async () => {
    const scope = await application({
      journey: "autonomous",
      memoryPolicy: {
        allowedScopes: ["verified_lessons"],
        exactContextNodeIds: ["lesson-required-for-reporting"],
      },
    });

    const response = await fetch(`${scope.url}/api/v2/reports/runs/${scope.fixture.runId}/export`);
    expect(response.status).toBe(503);
    const error = await response.json() as Record<string, any>;
    expect(error).toMatchObject({
      error: {
        code: "brain_context_unavailable",
        retryable: true,
        category: "dependency_unavailable",
        details: { hook: "reporting" },
      },
    });
    expect(JSON.stringify(error)).not.toContain("lesson-required-for-reporting");
    expect(scope.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_context_packs WHERE run_id = ?
    `).get(scope.fixture.runId)).toEqual({ count: 0 });
    expect(scope.database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE run_id = ? AND action = 'run.completion_exported'
    `).get(scope.fixture.runId)).toEqual({ count: 0 });
    const hook = scope.database.prepare(`
      SELECT details_json FROM audit_records
      WHERE run_id = ? AND action = 'brain.context_hook.invoked'
    `).get(scope.fixture.runId) as { readonly details_json: string };
    expect(JSON.parse(hook.details_json)).toMatchObject({
      hook: "reporting",
      status: "blocked",
      availabilityPolicy: "required",
      contextPackId: null,
      dependencyCode: "brain_offline",
    });
  });
});

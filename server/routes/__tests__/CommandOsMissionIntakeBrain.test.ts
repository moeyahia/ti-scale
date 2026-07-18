import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  getMemoryControlPolicy,
  updateMemoryControlPolicy,
} from "../../memory";
import type { AutonomousMissionRequest, ReadinessCheckProvider } from "../../missions";
import { createCommandOsRouter } from "../commandOsRoutes";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
});

const readiness: ReadinessCheckProvider = {
  id: "test-runtime",
  label: "Test runtime",
  journeys: ["autonomous", "guided"],
  evaluate: () => ({
    id: "test-runtime",
    label: "Test runtime",
    status: "pass",
    journeys: ["autonomous", "guided"],
    impact: "The isolated route fixture enforces its test boundary.",
  }),
};

async function application(database: SqliteDatabase): Promise<string> {
  const app = express();
  app.use(express.json());
  app.use(createCommandOsRouter({
    database,
    readinessProviders: [readiness],
    resolveActor: () => "operator-route",
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function seedAutonomousReadiness(database: SqliteDatabase): void {
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (
      'agent-route-planner', 'planning', 'Route planner', 'available',
      '{"defaultProvider":"provider-route"}',
      '{"allowedTools":[],"deniedTools":[],"approvalRequiredTools":[]}',
      '{}', '2.4', ?, ?, ?
    )
  `).run(now, now, now);
  database.prepare(`
    INSERT INTO health_snapshots (
      id, component_type, component_id, status, metrics_json, message, captured_at
    ) VALUES (
      'health-route-provider', 'provider', 'provider-route', 'healthy', ?,
      'Authenticated enforcing route fixture', ?
    )
  `).run(JSON.stringify({
    authenticated: true,
    callable: true,
    expiresAt,
    enforcesAutonomousBoundary: true,
    reportsExactTokenUsage: true,
    reportsExactCostUsage: true,
  }), now);
}

function autonomousRequest(): AutonomousMissionRequest {
  return {
    journey: "autonomous",
    launch: true,
    title: "Route-level signed Brain mission",
    objective: "Produce a local report for the exact authorized lab target",
    successCriteria: ["The local report is generated"],
    authorization: {
      engagementId: "eng-route",
      allowedTargets: ["lab:route-fixture"],
      prohibitedTargets: [],
      authorizationConfirmed: true,
    },
    contract: {
      allowedActionClasses: ["reporting"],
      prohibitedActionClasses: ["destructive"],
      destructivePolicy: "prohibited",
      evidenceRequirements: ["artifact hash"],
      timeBudgetMinutes: 10,
      retryBudget: 1,
      replanBudget: 1,
      concurrencyLimit: 1,
      evidenceStorageBudgetBytes: 1_048_576,
      artifactStorageBudgetBytes: 1_048_576,
      notificationPolicy: "in_app_only",
      reportingFormat: "ti_scale_json",
      dataHandlingPolicy: "local_private",
      retentionPolicy: "operator_managed",
      providerPolicy: "automatic_enforcing_only",
      toolPolicy: "contract_allowlist",
      specialistAgentIds: ["agent-route-planner"],
      memoryScopes: ["verified_lessons"],
      contextNodeIds: [],
      safeStopConditions: ["budget_reached"],
      deliverables: ["technical_report"],
    },
  };
}

describe("Ti-Scale mission intake Brain route", () => {
  test("returns the durable Guided intake Context Pack binding", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const base = await application(database);
      const response = await fetch(`${base}/api/v2/missions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "route-guided-intake-0001",
        },
        body: JSON.stringify({
          journey: "guided",
          launch: true,
          authorizationConfirmed: true,
          title: "Guided route fixture",
          objective: "Explain one authorized local assessment step",
          target: "lab:guided-route",
          engagementId: "eng-guided-route",
          explanationDepth: "balanced",
          executionPreference: "manual",
          evidenceExpectations: ["normalized observation"],
        }),
      });
      expect(response.status).toBe(201);
      const body = await response.json() as {
        intakeContext: { contextPackId: string; auditRecordId: string; status: string; memoryInfluencedDefaults: boolean };
      };
      expect(body.intakeContext).toMatchObject({
        status: "no_relevant_memory",
        memoryInfluencedDefaults: false,
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs WHERE id = ?")
        .get(body.intakeContext.contextPackId)).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE id = ?")
        .get(body.intakeContext.auditRecordId)).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });

  test("returns a structured fail-closed response before committing an Autonomous run", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      seedAutonomousReadiness(database);
      const control = getMemoryControlPolicy(database);
      updateMemoryControlPolicy({
        database,
        expectedVersion: control.version,
        actor: "operator-route",
        policy: {
          enabled: control.enabled,
          personalPreferencePolicy: control.personalPreferencePolicy,
          operationalMemoryEnabled: control.operationalMemoryEnabled,
          engagementIsolation: true,
          defaultRetentionDays: control.defaultRetentionDays,
          autonomousUse: false,
          guidedUse: control.guidedUse,
          obsidianSyncScope: control.obsidianSyncScope,
          secretsNeverRetained: true,
        },
      });
      const base = await application(database);
      const response = await fetch(`${base}/api/v2/missions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "route-autonomous-intake-0001",
        },
        body: JSON.stringify(autonomousRequest()),
      });
      expect(response.status).toBe(503);
      expect(await response.json()).toMatchObject({
        error: {
          code: "brain_context_unavailable",
          retryable: true,
          category: "dependency_missing",
          details: {
            hook: "intake",
            auditRecordId: expect.any(String),
          },
          humanMessage: expect.stringContaining("stopped safely"),
          remediation: expect.any(String),
        },
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM missions").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM runs").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs").get()).toEqual({ count: 0 });
      const receipt = database.prepare(`
        SELECT details_json FROM audit_records WHERE action = 'mission.intake_context.blocked'
      `).get() as { details_json: string };
      expect(receipt.details_json).not.toContain("lab:route-fixture");
    } finally {
      database.close();
    }
  });
});

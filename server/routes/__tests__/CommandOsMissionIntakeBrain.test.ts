import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE,
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
} from "../../autonomous-runtime";
import { canonicalMissionMemoryNodeId } from "../../brain-runtime";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
  type RuntimeSourceManifests,
} from "../../domain";
import {
  getMemoryControlPolicy,
  updateMemoryControlPolicy,
} from "../../memory";
import {
  ModelConfigurationRepository,
  ModelConfigurationService,
  modelCatalogItems,
} from "../../model-config";
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

const AUTONOMOUS_PRODUCT_AGENT_ID = "ReconScout";
const AUTONOMOUS_RUNTIME_AGENT_ID = "agent-route-dns";
const AUTONOMOUS_PROVIDER_ID = "provider-route";
const AUTONOMOUS_MODEL_ID = "model-route-dns";

function autonomousDnsRuntimeManifests(): RuntimeSourceManifests {
  const observedAt = new Date().toISOString();
  return {
    riskClasses: [{
      id: "risk-route-read-only",
      label: "Read-only route fixture",
      actionClassIds: [AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS],
    }],
    evidenceKinds: [{
      id: "evidence-route-dns",
      label: "DNS route fixture evidence",
      evidenceTypeIds: [AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE],
    }],
    capabilities: [{
      id: `capability:${AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID}`,
      label: "Bounded DNS route fixture",
      actionClassIds: [AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS],
      evidenceTypeIds: [AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE],
    }],
    tools: [{
      id: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
      label: "Reviewed DNS A query",
      available: true,
      locallyPolicyEnforced: true,
      requiresModel: false,
      executionJourneys: ["autonomous"],
      actionClassIds: [AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS],
      evidenceTypeIds: [AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE],
      riskClassIds: ["risk-route-read-only"],
    }],
    mcpServers: [],
    agents: [{
      id: AUTONOMOUS_RUNTIME_AGENT_ID,
      label: "Route DNS specialist",
      available: true,
      capabilityIds: [`capability:${AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID}`],
      actionClassIds: [AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS],
      toolIds: [AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID],
      modelRefs: [{ providerId: AUTONOMOUS_PROVIDER_ID, modelId: AUTONOMOUS_MODEL_ID }],
    }],
    providers: [{
      id: AUTONOMOUS_PROVIDER_ID,
      authenticated: true,
      healthy: true,
      catalogObservedAt: observedAt,
      models: [{
        id: AUTONOMOUS_MODEL_ID,
        displayName: "Route DNS model",
        toolCalling: true,
        structuredOutput: true,
        enforcement: "enforced_executor",
        compatibleActionClassIds: [AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS],
        disclosureClasses: ["public"],
      }],
    }],
  };
}

async function application(
  database: SqliteDatabase,
  readRuntimeManifests?: () => RuntimeSourceManifests,
): Promise<string> {
  const app = express();
  app.use(express.json());
  const modelConfigurations = readRuntimeManifests
    ? new ModelConfigurationService(
        new ModelConfigurationRepository(database),
        { readRuntimeManifests },
      )
    : undefined;
  app.use(createCommandOsRouter({
    database,
    readinessProviders: [readiness],
    resolveActor: () => "operator-route",
    ...(readRuntimeManifests ? { readRuntimeManifests } : {}),
    ...(modelConfigurations ? { modelConfigurations } : {}),
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
      ?, 'reconnaissance', 'Route DNS specialist', 'available',
      '{"defaultProvider":"provider-route"}',
      ?,
      ?, '2.4', ?, ?, ?
    )
  `).run(
    AUTONOMOUS_PRODUCT_AGENT_ID,
    JSON.stringify({
      allowedTools: [AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID],
      deniedTools: [],
      approvalRequiredTools: [],
    }),
    JSON.stringify({
      userFacing: true,
      productAgent: true,
      runtimeBindingAgentIds: [AUTONOMOUS_RUNTIME_AGENT_ID],
    }),
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO agent_capabilities (
      agent_id, capability, source, enabled, metadata_json
    ) VALUES (?, ?, 'live-route-attestation', 1, ?)
  `).run(
    AUTONOMOUS_PRODUCT_AGENT_ID,
    AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
    JSON.stringify({
      attestedAt: now,
      validUntil: expiresAt,
      providerIds: [AUTONOMOUS_PROVIDER_ID],
      executionBinding: "reviewed_local_process",
      toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
      executionJourneys: ["autonomous"],
      actionClassId: AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
      runtimeBindingAgentId: AUTONOMOUS_RUNTIME_AGENT_ID,
    }),
  );
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

function autonomousRequest(
  runtimeManifests: RuntimeSourceManifests,
): AutonomousMissionRequest {
  return {
    journey: "autonomous",
    launch: true,
    title: "Route-level signed DNS mission",
    objective: "Record one DNS A lookup for the exact authorized domain",
    successCriteria: [AUTONOMOUS_DNS_A_SUCCESS_CRITERION],
    authorization: {
      engagementId: "eng-route",
      allowedTargets: ["does-not-exist.invalid"],
      prohibitedTargets: [],
      authorizationConfirmed: true,
    },
    contract: {
      allowedActionClasses: [AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS],
      prohibitedActionClasses: ["destructive"],
      destructivePolicy: "prohibited",
      evidenceRequirements: [AUTONOMOUS_DNS_SAFE_RECON_EVIDENCE_TYPE],
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
      specialistAgentIds: [AUTONOMOUS_PRODUCT_AGENT_ID],
      agentModelAssignments: [{
        agentId: AUTONOMOUS_PRODUCT_AGENT_ID,
        primaryConfigurationId:
          modelCatalogItems(runtimeManifests)[0]!
            .configurationId,
        fallbackConfigurationId: null,
      }],
      memoryScopes: ["verified_lessons"],
      contextNodeIds: [],
      safeStopConditions: ["budget_reached"],
      deliverables: [],
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
        mission: { id: string };
        intakeContext: {
          hook: string;
          contextPackId: string;
          auditRecordId: string;
          status: string;
          retrievedCount: number;
          memoryInfluencedDefaults: boolean;
        };
      };
      expect(body.intakeContext).toMatchObject({
        hook: "intake",
        status: "ready",
        retrievedCount: 1,
        memoryInfluencedDefaults: false,
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs WHERE id = ?")
        .get(body.intakeContext.contextPackId)).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE id = ?")
        .get(body.intakeContext.auditRecordId)).toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT node_id, used FROM memory_context_items
        WHERE context_pack_id = ?
      `).all(body.intakeContext.contextPackId)).toEqual([{
        node_id: canonicalMissionMemoryNodeId(body.mission.id),
        used: 0,
      }]);
    } finally {
      database.close();
    }
  });

  test("blocks Autonomous preflight before create when required Brain use is disabled", async () => {
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
      const runtimeManifests = autonomousDnsRuntimeManifests();
      const readRuntimeManifests = () => runtimeManifests;
      const base = await application(database, readRuntimeManifests);
      const request = autonomousRequest(runtimeManifests);
      const preflightResponse = await fetch(`${base}/api/v2/missions/autonomous/preflight`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      });
      expect(preflightResponse.status).toBe(200);
      const preflight = await preflightResponse.json() as {
        contract: { version: number; hash: string };
        readiness: { status: string; checks: Array<{ id: string; status: string }> };
      };
      expect(preflight.readiness.status).toBe("blocked");
      expect(preflight.readiness.checks).toContainEqual(expect.objectContaining({
        id: "contract_memory_runtime",
        status: "fail",
      }));
      expect(preflight.contract.version).toBe(1);
      expect(preflight.contract.hash).toMatch(/^[a-f0-9]{64}$/u);
      const response = await fetch(`${base}/api/v2/missions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": "route-autonomous-intake-0001",
        },
        body: JSON.stringify({ ...request, contractReview: preflight.contract }),
      });
      const responseBody = await response.json();
      expect({ status: response.status, body: responseBody }).toMatchObject({
        status: 409,
        body: {
          error: {
            code: "autonomous_readiness_blocked",
            retryable: false,
            category: "dependency_missing",
            details: {
              status: "blocked",
              checks: [
                expect.objectContaining({
                  id: "contract_memory_runtime",
                  status: "fail",
                }),
              ],
            },
            humanMessage: expect.stringContaining("cannot start"),
            remediation: expect.any(String),
          },
        },
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM missions").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM runs").get()).toEqual({ count: 0 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_context_packs").get()).toEqual({ count: 0 });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'mission.intake_context.blocked'
      `).get()).toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });
});

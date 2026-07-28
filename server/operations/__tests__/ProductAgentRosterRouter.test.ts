import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { AddressInfo } from "node:net";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import type { RuntimeProjectionInput } from "../../app/RuntimeProjectionService";
import { RuntimeProjectionService } from "../../app/RuntimeProjectionService";
import { createOperationsRouter } from "../../routes/operationsRoutes";

const servers: Array<ReturnType<ReturnType<typeof express>["listen"]>> = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) =>
    new Promise<void>((resolve) => server.close(() => resolve()))));
});

function projection(): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
      specialistsConfigured: 1,
      providers: [],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      eventStream: "healthy",
      secondBrain: "healthy",
      legacyExecutionEnabled: false,
    },
    agents: [{
      id: "internal-reviewed-recon-adapter",
      role: "reviewed-local-process-adapter",
      displayName: "Internal reviewed recon adapter",
      status: "available",
      providerPolicy: {},
      toolPolicy: { allowedTools: ["kali:nmap"] },
      configuration: { adapterId: "internal-reviewed-recon-v1" },
      version: "1",
      lastHeartbeatAt: "2026-07-23T12:00:00.000Z",
      capabilities: [{
        name: "kali:nmap",
        source: "live-route-attestation",
        enabled: true,
        metadata: { actionClassId: "port_service_enumeration" },
      }],
    }],
    mcpServers: [],
  };
}

async function fixture() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  new RuntimeProjectionService({
    database,
    read: projection,
    clock: () => new Date("2026-07-23T12:00:00.000Z"),
  }).projectNow();
  const app = express();
  app.use(createOperationsRouter({
    database,
    resolveActor: () => ({ id: "operator-one", type: "operator" }),
    resolveAccess: (request) => ({
      maximumSensitivity: "restricted",
      allEngagements: true,
      allowGlobalKnowledge: true,
      allowUnscopedSystemData: request.get("X-System-Inventory") === "yes",
    }),
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    database,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
  };
}

describe("product agent fleet API", () => {
  test("returns only the twelve product agents by default and gates internal runtime components", async () => {
    const { database, url } = await fixture();
    try {
      const publicResponse = await fetch(`${url}/api/v2/agents?limit=100`);
      expect(publicResponse.status).toBe(200);
      const publicBody = await publicResponse.json() as {
        items: Array<{ id: string; configuration: Record<string, unknown> }>;
      };
      expect(publicBody.items).toHaveLength(12);
      expect(publicBody.items.map(({ id }) => id).sort()).toEqual([
        "ADAttackMapper",
        "CloudSentinel",
        "CredSmith",
        "FuzzSmith",
        "OSINTSeeker",
        "ReconScout",
        "ReportSmith",
        "ReverseSage",
        "SecretHunter",
        "SessionRunner",
        "VulnIntel",
        "WebBreaker",
      ]);
      expect(publicBody.items.every(({ configuration }) =>
        configuration.userFacing === true
        && configuration.productAgent === true)).toBe(true);
      expect(publicBody.items.find(({ id }) => id === "ReconScout")
        ?.configuration).toMatchObject({
          runtimeBindingCount: 1,
          runtimeBindingsVersioned: true,
          runtimeBindings: [{
            id: "internal-reviewed-recon-adapter",
            version: "1",
          }],
        });
      expect(JSON.stringify(publicBody)).not.toContain("internalComponent");
      expect(JSON.stringify(publicBody)).not.toContain("adapterId");

      const deniedInternal = await fetch(`${url}/api/v2/agents?includeInternal=1&limit=100`);
      expect(deniedInternal.status).toBe(403);
      expect(await deniedInternal.json()).toMatchObject({
        error: { code: "operations_policy_denied" },
      });

      const internalResponse = await fetch(
        `${url}/api/v2/agents?includeInternal=1&limit=100`,
        { headers: { "X-System-Inventory": "yes" } },
      );
      expect(internalResponse.status).toBe(200);
      const internalBody = await internalResponse.json() as {
        items: Array<{ id: string; configuration: Record<string, unknown> }>;
      };
      expect(internalBody.items).toHaveLength(13);
      expect(internalBody.items.find(({ id }) => id === "internal-reviewed-recon-adapter")
        ?.configuration).toMatchObject({
          userFacing: false,
          internalComponent: true,
          projectedProductAgentIds: ["ReconScout"],
        });

      const hiddenDetail = await fetch(
        `${url}/api/v2/agents/internal-reviewed-recon-adapter`,
      );
      expect(hiddenDetail.status).toBe(404);
      const internalDetail = await fetch(
        `${url}/api/v2/agents/internal-reviewed-recon-adapter?includeInternal=1`,
        { headers: { "X-System-Inventory": "yes" } },
      );
      expect(internalDetail.status).toBe(200);

      const invalidFilter = await fetch(`${url}/api/v2/agents?includeInternal=true`);
      expect(invalidFilter.status).toBe(400);
      expect(await invalidFilter.json()).toMatchObject({
        error: { code: "invalid_filter" },
      });
    } finally {
      database.close();
    }
  });
});

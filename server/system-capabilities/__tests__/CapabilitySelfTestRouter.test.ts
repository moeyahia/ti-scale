import { createServer } from "node:http";
import { describe, expect, test } from "bun:test";
import express from "express";
import type { CapabilityLocalHealthReader } from "../CapabilitySelfTestRepository";
import { CapabilitySelfTestService } from "../CapabilitySelfTestService";
import { createCapabilitySelfTestRouter } from "../CapabilitySelfTestRouter";

describe("capability self-test route", () => {
  test("requires an authenticated actor and serves a no-store read-only snapshot", async () => {
    const checkedAt = "2026-07-18T20:00:00.000Z";
    const repository: CapabilityLocalHealthReader = {
      read: () => ({
        checkedAt,
        database: {
          healthy: true,
          integrity: ["ok"],
          integrityStatus: "verified",
          integrityCheckedAt: checkedAt,
          integritySource: "startup",
          journalMode: "wal",
          foreignKeys: true,
          busyTimeoutMs: 5_000,
          currentMigration: 15,
          pendingOutbox: 0,
          checkedAt,
        },
        eventStream: { started: true, subscribers: 0 },
        secondBrain: {
          health: "healthy",
          databaseHealthy: true,
          canonicalStoreAvailable: true,
          lexicalIndexAvailable: true,
          lexicalIndexSynchronized: true,
          vaultProjection: {
            status: "not_configured",
            configuredConnections: 0,
            connectedConnections: 0,
            reachableConnections: 0,
            healthVerifiedConnections: 0,
            reason: "No Vault configured",
          },
          reason: "Canonical Brain is readable",
        },
      }),
    };
    const service = new CapabilitySelfTestService({
      repository,
      clock: () => new Date(checkedAt),
      readRuntimeProjection: () => ({
        readiness: {
          actionBoundaryActive: false,
          delegationEnforced: false,
          noHandsCommanderEnforced: true,
          directCommanderToolsDenied: true,
          specialistAssignmentRequired: true,
          specialistsConfigured: 0,
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
        agents: [],
        mcpServers: [],
        capabilityManifests: {
          riskClasses: [],
          evidenceKinds: [],
          capabilities: [],
          tools: [],
          mcpServers: [],
          agents: [],
          providers: [],
        },
      }),
    });
    const app = express();
    app.use(createCapabilitySelfTestRouter({
      service,
      resolveActor: (request) => request.get("X-Test-Actor"),
    }));
    const server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Test server has no address");
      const url = `http://127.0.0.1:${address.port}/api/v2/system/capability-self-tests`;

      const unauthenticated = await fetch(url);
      expect(unauthenticated.status).toBe(401);
      expect(unauthenticated.headers.get("Cache-Control")).toBe("no-store");
      expect(await unauthenticated.json()).toMatchObject({
        error: { code: "ti_scale_authentication_required" },
      });

      const authenticated = await fetch(url, { headers: { "X-Test-Actor": "operator" } });
      expect(authenticated.status).toBe(200);
      expect(authenticated.headers.get("Cache-Control")).toBe("no-store");
      expect(await authenticated.json()).toMatchObject({
        schemaVersion: "2.4",
        readOnly: true,
        grantsMissionExecution: false,
        accounting: { runtimeRegistryRead: true, manifestValid: true, complete: true },
      });
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});

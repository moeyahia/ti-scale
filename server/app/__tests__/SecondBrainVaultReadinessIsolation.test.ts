import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRuntimeReadinessProviders } from "../RuntimeReadiness";
import { createCommandOsApplication, type CommandOsApplication } from "../CommandOsApplication";

const applications: CommandOsApplication[] = [];
const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(applications.splice(0).map((application) => application.stop()));
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("Second Brain and Obsidian readiness isolation", () => {
  test("an offline optional Vault projection cannot block canonical memory readiness", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-vault-readiness-"));
    directories.push(directory);
    const runtime = {
      actionBoundaryActive: false,
      delegationEnforced: false,
      noHandsCommanderEnforced: false,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
      specialistsConfigured: 0,
      providers: [],
      mcp: {
        enabled: false,
        executionMode: "disabled" as const,
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      eventStream: "healthy" as const,
      secondBrain: "unknown" as const,
      legacyExecutionEnabled: false,
    };
    const application = createCommandOsApplication({
      databasePath: join(directory, "ti-scale.sqlite"),
      readinessProviders: (_database, readRuntimeProjection) =>
        createRuntimeReadinessProviders(() => readRuntimeProjection().readiness),
      runtimeProjection: () => ({ readiness: runtime, agents: [], mcpServers: [] }),
      resolveActor: () => "operator",
      resolveExistingVaultPath: () => {
        throw new Error("optional projection is offline");
      },
      projectionIntervalMs: 60_000,
    });
    applications.push(application);
    const now = "2026-07-19T12:00:00.000Z";
    application.database.prepare(`
      INSERT INTO vault_connections (
        id, vault_path, display_name, status, sync_scope_json,
        permission_granted_at, created_at, updated_at
      ) VALUES (
        'vault-offline-integration', '/configured/offline-vault',
        'Offline optional projection', 'connected', '{}', ?, ?, ?
      )
    `).run(now, now, now);
    application.database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id,
        reason, details_json, record_hash, occurred_at
      ) VALUES (
        'audit-vault-offline-integration', 'operator', 'operator',
        'vault.health.verified', 'vault_connection', 'vault-offline-integration',
        'Prior bounded proof', '{}', ?, ?
      )
    `).run("c".repeat(64), now);

    const http = express();
    http.use(express.json());
    http.use(application.router);
    const server = createServer(http);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server has no TCP address");
    application.start();

    const response = await fetch(`http://127.0.0.1:${address.port}/api/v2/system/readiness`);
    expect(response.status).toBe(200);
    const body = await response.json() as {
      dependencies: {
        secondBrain: {
          status: string;
          canonicalStoreAvailable: boolean;
          lexicalIndexSynchronized: boolean;
          reason: string;
          vaultProjection: {
            status: string;
            configuredConnections: number;
            reachableConnections: number;
            reason: string;
          };
        };
      };
    };
    expect(body.dependencies.secondBrain).toMatchObject({
      status: "degraded",
      canonicalStoreAvailable: true,
      lexicalIndexSynchronized: true,
      vaultProjection: {
        status: "degraded",
        configuredConnections: 1,
        reachableConnections: 0,
      },
    });
    expect(body.dependencies.secondBrain.reason).toContain("Obsidian projection is degraded");
    expect(body.dependencies.secondBrain.vaultProjection.reason).toContain("unavailable or outside");

    const resolveResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/registries/intake/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        journey: "autonomous",
        authorizationAcknowledged: true,
        targets: [{ value: "lab:brain-readiness-integration" }],
      }),
    });
    expect(resolveResponse.status).toBe(200);
    const resolved = await resolveResponse.json() as { request: Record<string, unknown> };
    const preflightResponse = await fetch(`http://127.0.0.1:${address.port}/api/v2/missions/autonomous/preflight`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(resolved.request),
    });
    expect(preflightResponse.status).toBe(200);
    const preflight = await preflightResponse.json() as {
      readiness: { checks: Array<{ id: string; status: string }> };
    };
    expect(preflight.readiness.checks.find(({ id }) => id === "memory_policy"))
      .toMatchObject({ status: "pass" });
  });
});

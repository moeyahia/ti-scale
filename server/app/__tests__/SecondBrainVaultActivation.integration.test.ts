import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSecondBrainRouter } from "../../memory/SecondBrainRouter";
import { VaultPathPolicy } from "../../vault";
import { createCommandOsApplication, type CommandOsApplication } from "../CommandOsApplication";
import { createRuntimeReadinessProviders } from "../RuntimeReadiness";

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

function runtimeSnapshot() {
  return {
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
}

describe("standalone Obsidian Vault activation", () => {
  test("activates only after a real round trip, preserves operator notes, and becomes visible in runtime health", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-vault-activation-"));
    directories.push(directory);
    const vaultRoot = join(directory, "vaults");
    const vaultPath = join(vaultRoot, "Operator-Brain");
    mkdirSync(vaultPath, { recursive: true, mode: 0o700 });
    const existingNotePath = join(vaultPath, "operator-existing-note.md");
    const syntheticAuthenticationMaterial = [
      "api_",
      "key: ",
      "unit-test-only-material-that-must-not-be-imported",
    ].join("");
    const existingNote = `# Operator note\n\n${syntheticAuthenticationMaterial}\n`;
    writeFileSync(existingNotePath, existingNote, { encoding: "utf8", mode: 0o600 });

    const pathPolicy = new VaultPathPolicy(vaultRoot);
    const runtime = runtimeSnapshot();
    const application = createCommandOsApplication({
      databasePath: join(directory, "ti-scale.sqlite"),
      readinessProviders: (_database, readRuntimeProjection) =>
        createRuntimeReadinessProviders(() => readRuntimeProjection().readiness),
      runtimeProjection: () => ({ readiness: runtime, agents: [], mcpServers: [] }),
      resolveActor: () => "operator:vault-activation-test",
      resolveExistingVaultPath: (configuredPath) => pathPolicy.resolveExistingVault(configuredPath),
      projectionIntervalMs: 60_000,
    });
    applications.push(application);

    const http = express();
    http.use(express.json());
    http.use(application.router);
    http.use(createSecondBrainRouter({
      database: application.database,
      resolveActor: () => "operator:vault-activation-test",
      resolveAccess: () => ({ maximumSensitivity: "restricted", allEngagements: true }),
      vaultPathPolicy: pathPolicy,
    }));
    const server = createServer(http);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server has no TCP address");
    const baseUrl = `http://127.0.0.1:${address.port}`;
    application.start();

    const healthResponse = await fetch(`${baseUrl}/api/v2/brain/vault/health-check`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "vault-activation-health-0001",
      },
      body: JSON.stringify({ vaultPath: "Operator-Brain", permissionGranted: true }),
    });
    expect(healthResponse.status).toBe(200);
    expect(await healthResponse.json()).toMatchObject({
      result: {
        status: "healthy",
        vaultPath: "Operator-Brain",
        checks: { write: true, read: true, rename: true, delete: true },
      },
    });
    expect(readFileSync(existingNotePath, "utf8")).toBe(existingNote);
    expect(readdirSync(vaultPath).filter((name) => name.startsWith(".ti-scale-health-"))).toEqual([]);

    const connectResponse = await fetch(`${baseUrl}/api/v2/brain/vault/connect`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "vault-activation-connect-0001",
      },
      body: JSON.stringify({
        vaultPath: "Operator-Brain",
        displayName: "Operator Brain",
        permissionGranted: true,
        syncScope: { lifecycleStatuses: ["confirmed", "verified"] },
      }),
    });
    expect(connectResponse.status).toBe(201);
    const connected = await connectResponse.json() as {
      connection: { id: string; updatedAt: string };
    };

    const snapshotResponse = await fetch(`${baseUrl}/api/v2/brain/vault`);
    expect(snapshotResponse.status).toBe(200);
    expect(await snapshotResponse.json()).toMatchObject({
      enabled: true,
      syncEnabled: true,
      connections: [{
        id: connected.connection.id,
        displayName: "Operator Brain",
        vaultPath: "Operator-Brain",
        status: "connected",
        pathAvailable: true,
        healthChecks: { write: true, read: true, rename: true, delete: true },
      }],
      syncStates: [],
      conflicts: [],
    });

    const readinessResponse = await fetch(`${baseUrl}/api/v2/system/readiness`);
    expect(readinessResponse.status).toBe(200);
    expect(await readinessResponse.json()).toMatchObject({
      dependencies: {
        secondBrain: {
          status: "healthy",
          canonicalStoreAvailable: true,
          vaultProjection: {
            status: "healthy",
            configuredConnections: 1,
            connectedConnections: 1,
            reachableConnections: 1,
            healthVerifiedConnections: 1,
          },
        },
      },
    });
    expect(application.brainContext.inspectComposition()).toMatchObject({
      serviceId: "ti-scale.local-second-brain-context.v1",
      activeVaultCount: 1,
      localOnly: true,
      userOwned: true,
      targetInteraction: false,
      executionAuthority: "none",
    });

    application.database.prepare(`
      INSERT INTO vault_connections (
        id, vault_path, display_name, status, sync_scope_json,
        permission_granted_at, created_at, updated_at
      ) VALUES ('vault-legacy-archive', ?, 'Legacy Brain', 'disconnected', '{}', ?, ?, ?)
    `).run(
      join(vaultRoot, "Legacy-Brain"),
      "2026-07-19T18:00:00.000Z",
      "2026-07-19T18:00:00.000Z",
      "2026-07-20T18:00:00.000Z",
    );
    const coexistenceResponse = await fetch(`${baseUrl}/api/v2/system/readiness`);
    expect(coexistenceResponse.status).toBe(200);
    expect(await coexistenceResponse.json()).toMatchObject({
      dependencies: {
        secondBrain: {
          status: "healthy",
          vaultProjection: {
            status: "healthy",
            configuredConnections: 2,
            connectedConnections: 1,
            reachableConnections: 1,
            healthVerifiedConnections: 1,
          },
        },
      },
    });

    expect(application.database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 0 });
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM memory_candidates").get()).toEqual({ count: 0 });
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM vault_sync_state").get()).toEqual({ count: 0 });
    expect(readFileSync(existingNotePath, "utf8")).toBe(existingNote);

    const audits = application.database.prepare(`
      SELECT action, resource_type AS resourceType, details_json AS detailsJson
      FROM audit_records WHERE action LIKE 'vault.%' ORDER BY rowid
    `).all() as Array<{ action: string; resourceType: string; detailsJson: string }>;
    expect(audits.map(({ action }) => action)).toEqual([
      "vault.health.verified",
      "vault.health.verified",
      "vault.connection.connected",
    ]);
    expect(audits.at(-1)).toMatchObject({
      action: "vault.connection.connected",
      resourceType: "vault_connection",
    });
    const connectionHealth = JSON.parse(audits[1]!.detailsJson) as Record<string, unknown>;
    expect(connectionHealth).toMatchObject({
      connectionId: connected.connection.id,
      connectionUpdatedAt: connected.connection.updatedAt,
      checks: { write: true, read: true, rename: true, delete: true },
    });
    expect(connectionHealth.pathFingerprint).toMatch(/^[a-f0-9]{64}$/u);
    expect(JSON.stringify(audits)).not.toContain(syntheticAuthenticationMaterial);
    expect(JSON.stringify(audits)).not.toContain(vaultPath);
  });
});

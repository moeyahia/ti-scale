import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { RuntimeProjectionService } from "../RuntimeProjectionService";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function database() {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-projection-"));
  temporaryDirectories.push(directory);
  const db = createDatabaseConnection({ filename: join(directory, "ti-scale.sqlite") });
  migrateDatabase(db);
  return db;
}

describe("RuntimeProjectionService", () => {
  test("projects real fleet, MCP, and secret-free health state", () => {
    const db = database();
    const service = new RuntimeProjectionService({
      database: db,
      intervalMs: 60_000,
      clock: () => new Date("2026-07-15T09:00:00.000Z"),
      read: () => ({
        readiness: {
          actionBoundaryActive: true,
          delegationEnforced: true,
          noHandsCommanderEnforced: true,
          directCommanderToolsDenied: true,
          specialistAssignmentRequired: true,
          specialistsConfigured: 1,
          providers: [{
            id: "grok-acp",
            health: "healthy",
            authenticated: true,
            callable: true,
            attestedAt: "2026-07-15T08:59:00.000Z",
            expiresAt: "2026-07-15T09:04:00.000Z",
            supportsGuided: true,
            enforcesAutonomousBoundary: true,
            reportsExactTokenUsage: true,
            reportsExactCostUsage: false,
            reason: "OAuth state and ACP boundary are available",
          }],
          mcp: {
            enabled: true,
            executionMode: "enabled",
            startPermitted: true,
            configuredServers: 1,
            runnableServers: 1,
            missingDependencies: 0,
            missingSecrets: 0,
          },
          eventStream: "healthy",
          secondBrain: "healthy",
          legacyExecutionEnabled: false,
        },
        agents: [{
          id: "ReconScout",
          role: "reconnaissance",
          displayName: "Recon Scout",
          status: "available",
          providerPolicy: { defaultProvider: "grok-acp" },
          toolPolicy: { allowed: ["nmap"] },
          configuration: { noHands: true },
          version: "2.4",
          capabilities: [{
            name: "nmap",
            source: "live-route-attestation",
            enabled: true,
            metadata: { validUntil: "2026-07-15T09:04:00.000Z" },
          }],
        }],
        mcpServers: [{
          id: "recon-mcp",
          name: "Recon MCP",
          transport: "stdio",
          endpointRedacted: "local stdio",
          status: "healthy",
          capabilities: ["nmap"],
          policy: { assignedAgents: ["ReconScout"] },
        }],
      }),
    });

    const result = service.projectNow();
    expect(result).toEqual({
      projectedAt: "2026-07-15T09:00:00.000Z",
      agentCount: 1,
      mcpServerCount: 1,
      healthSnapshotCount: 4,
    });
    expect(db.prepare("SELECT id, status FROM agents").get()).toEqual({
      id: "ReconScout",
      status: "available",
    });
    expect(db.prepare("SELECT last_heartbeat_at FROM agents").get()).toEqual({
      last_heartbeat_at: null,
    });
    expect(db.prepare("SELECT capability FROM agent_capabilities").get()).toEqual({
      capability: "nmap",
    });
    expect(db.prepare("SELECT id, status FROM mcp_servers").get()).toEqual({
      id: "recon-mcp",
      status: "healthy",
    });
    expect(db.prepare("SELECT COUNT(*) AS count FROM health_snapshots").get()).toEqual({ count: 4 });
    expect(db.prepare(
      "SELECT status, metrics_json FROM health_snapshots WHERE component_type = 'policy' AND component_id = 'legacy-execution'",
    ).get()).toEqual({ status: "healthy", metrics_json: '{"enabled":false}' });
    const metrics = String(
      (db.prepare("SELECT metrics_json FROM health_snapshots WHERE component_type = 'provider'").get() as { metrics_json: string }).metrics_json,
    );
    expect(JSON.parse(metrics)).toMatchObject({
      authenticated: true,
      callable: true,
      attestedAt: "2026-07-15T08:59:00.000Z",
      expiresAt: "2026-07-15T09:04:00.000Z",
      enforcesAutonomousBoundary: true,
      reportsExactTokenUsage: true,
      reportsExactCostUsage: false,
    });
    expect(metrics).not.toContain("token");
    expect(metrics).not.toContain("secret");
    db.close();
  });

  test("preserves a genuine worker heartbeat instead of refreshing it from roster projection", () => {
    const db = database();
    let now = new Date("2026-07-15T09:00:00.000Z");
    const service = new RuntimeProjectionService({
      database: db,
      intervalMs: 60_000,
      clock: () => now,
      read: () => ({
        readiness: {
          actionBoundaryActive: true,
          delegationEnforced: true,
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
        agents: [{
          id: "worker-recon",
          role: "reconnaissance",
          displayName: "Worker Recon",
          status: "degraded",
          providerPolicy: {},
          toolPolicy: {},
          configuration: {},
          version: "2.4",
          capabilities: [],
        }],
        mcpServers: [],
      }),
    });

    service.projectNow();
    expect(db.prepare("SELECT last_heartbeat_at FROM agents WHERE id = 'worker-recon'").get())
      .toEqual({ last_heartbeat_at: null });
    db.prepare("UPDATE agents SET last_heartbeat_at = ? WHERE id = 'worker-recon'")
      .run("2026-07-15T09:00:30.000Z");
    now = new Date("2026-07-15T09:05:00.000Z");
    service.projectNow();
    expect(db.prepare("SELECT last_heartbeat_at FROM agents WHERE id = 'worker-recon'").get())
      .toEqual({ last_heartbeat_at: "2026-07-15T09:00:30.000Z" });
    db.close();
  });

  test("rejects duplicate runtime identities atomically", () => {
    const db = database();
    const service = new RuntimeProjectionService({
      database: db,
      read: () => ({
        readiness: {
          actionBoundaryActive: false,
          delegationEnforced: false,
          noHandsCommanderEnforced: true,
          directCommanderToolsDenied: true,
          specialistAssignmentRequired: false,
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
          eventStream: "unknown",
          secondBrain: "healthy",
          legacyExecutionEnabled: false,
        },
        agents: ["first", "second"].map((displayName) => ({
          id: "duplicate",
          role: "test",
          displayName,
          status: "available" as const,
          providerPolicy: {},
          toolPolicy: {},
          configuration: {},
          version: "2.4",
          capabilities: [],
        })),
        mcpServers: [],
      }),
    });

    expect(() => service.projectNow()).toThrow("Duplicate projected agent");
    expect(db.prepare("SELECT COUNT(*) AS count FROM agents").get()).toEqual({ count: 0 });
    db.close();
  });
});

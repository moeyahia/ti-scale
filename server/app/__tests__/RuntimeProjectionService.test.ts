import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalReleaseDataFingerprint,
} from "../../../scripts/release/FunctionalReleasePrimitives";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  RuntimeProjectionService,
  type RuntimeProjectionInput,
} from "../RuntimeProjectionService";

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
  test("timer-driven projection defers under writer contention without blocking the event loop", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-projection-contention-"));
    temporaryDirectories.push(directory);
    const filename = join(directory, "ti-scale.sqlite");
    const db = createDatabaseConnection({
      filename,
      busyTimeoutMs: 2_000,
    });
    migrateDatabase(db);
    const competingWriter = createDatabaseConnection({
      filename,
      busyTimeoutMs: 0,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    const service = new RuntimeProjectionService({
      database: db,
      intervalMs: 1_000,
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
          eventStream: "healthy",
          secondBrain: "healthy",
          legacyExecutionEnabled: false,
        },
        agents: [],
        mcpServers: [],
      }),
    });

    service.start();
    const initialHealthSnapshots = Number(
      (db.prepare("SELECT COUNT(*) AS count FROM health_snapshots").get() as {
        count: number;
      }).count,
    );
    competingWriter.exec("BEGIN IMMEDIATE");
    const startedAt = performance.now();
    await new Promise<void>((resolve) => setTimeout(resolve, 1_150));
    const elapsedMs = performance.now() - startedAt;

    // Before this contract, the 1-second timer inherited the 2-second
    // connection timeout, so this callback could not run until roughly 3s.
    expect(elapsedMs).toBeLessThan(1_750);
    expect(db.pragma("busy_timeout", { simple: true })).toBe(2_000);
    competingWriter.exec("ROLLBACK");

    const recoveryDeadline = Date.now() + 2_500;
    let recoveredHealthSnapshots = initialHealthSnapshots;
    while (Date.now() < recoveryDeadline) {
      recoveredHealthSnapshots = Number(
        (db.prepare("SELECT COUNT(*) AS count FROM health_snapshots").get() as {
          count: number;
        }).count,
      );
      if (recoveredHealthSnapshots > initialHealthSnapshots) break;
      await new Promise<void>((resolve) => setTimeout(resolve, 25));
    }
    expect(recoveredHealthSnapshots).toBeGreaterThan(initialHealthSnapshots);

    service.stop();
    competingWriter.close();
    db.close();
  });

  test("projects real fleet, MCP, and secret-free health state", () => {
    const db = database();
    const databasePath = (db.prepare("PRAGMA database_list").get() as { file: string }).file;
    const rollbackFingerprintBeforeProjection = canonicalReleaseDataFingerprint(databasePath);
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
          lastCheckedAt: "2026-07-15T08:59:30.000Z",
        }],
      }),
    });

    const result = service.projectNow();
    expect(result).toEqual({
      projectedAt: "2026-07-15T09:00:00.000Z",
      agentCount: 13,
      mcpServerCount: 1,
      healthSnapshotCount: 4,
    });
    expect(db.prepare("SELECT COUNT(*) AS count FROM agents").get()).toEqual({
      count: 13,
    });
    expect(db.prepare(`
      SELECT id, status, json_extract(configuration_json, '$.executionAuthority')
        AS execution_authority
      FROM agents WHERE id = 'Commander'
    `).get()).toEqual({
      id: "Commander",
      status: "available",
      execution_authority: "none",
    });
    expect(db.prepare("SELECT id, status FROM agents WHERE id = 'ReconScout'").get()).toEqual({
      id: "ReconScout",
      status: "available",
    });
    expect(db.prepare("SELECT last_heartbeat_at FROM agents WHERE id = 'ReconScout'").get()).toEqual({
      last_heartbeat_at: null,
    });
    expect(db.prepare(`
      SELECT capability FROM agent_capabilities
      WHERE agent_id = 'ReconScout' AND capability = 'nmap'
    `).get()).toEqual({
      capability: "nmap",
    });
    expect(db.prepare("SELECT id, status, last_checked_at FROM mcp_servers").get()).toEqual({
      id: "recon-mcp",
      status: "healthy",
      last_checked_at: "2026-07-15T08:59:30.000Z",
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
    expect(canonicalReleaseDataFingerprint(databasePath)).toBe(rollbackFingerprintBeforeProjection);
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

  test("preserves the real MCP check time instead of inventing a projection heartbeat", () => {
    const db = database();
    let now = new Date("2026-07-15T09:00:00.000Z");
    const lastCheckedAt = "2026-07-15T08:58:00.000Z";
    const service = new RuntimeProjectionService({
      database: db,
      intervalMs: 60_000,
      clock: () => now,
      read: () => ({
        readiness: {
          actionBoundaryActive: false,
          delegationEnforced: false,
          noHandsCommanderEnforced: false,
          directCommanderToolsDenied: true,
          specialistAssignmentRequired: true,
          specialistsConfigured: 0,
          providers: [],
          mcp: {
            enabled: false,
            executionMode: "disabled",
            startPermitted: false,
            configuredServers: 1,
            runnableServers: 0,
            missingDependencies: 1,
            missingSecrets: 0,
          },
          eventStream: "healthy",
          secondBrain: "healthy",
          legacyExecutionEnabled: false,
        },
        agents: [],
        mcpServers: [{
          id: "public-nvd",
          name: "Official public NVD intelligence",
          transport: "streamable-http",
          status: "degraded",
          capabilities: [],
          policy: { executionAuthorization: "none" },
          lastCheckedAt,
        }],
      }),
    });

    service.projectNow();
    now = new Date("2026-07-15T09:10:00.000Z");
    service.projectNow();
    expect(db.prepare("SELECT last_checked_at, updated_at FROM mcp_servers WHERE id = 'public-nvd'").get())
      .toEqual({
        last_checked_at: lastCheckedAt,
        updated_at: "2026-07-15T09:10:00.000Z",
      });
    db.close();
  });

  test("withdraws stale product readiness and leaves old adapters internal after the next generation", () => {
    const db = database();
    let agents: RuntimeProjectionInput["agents"] = [{
      id: "runtime-web-adapter",
      role: "reviewed-web-adapter",
      displayName: "Reviewed Web Adapter",
      status: "available",
      providerPolicy: {},
      toolPolicy: { allowedTools: ["kali:curl"] },
      configuration: { adapterId: "runtime-web-adapter-v1" },
      version: "1",
      capabilities: [{
        name: "kali:curl",
        source: "live-route-attestation",
        enabled: true,
        metadata: { actionClassId: "web_crawling_page_capture" },
      }],
    }];
    const service = new RuntimeProjectionService({
      database: db,
      clock: () => new Date("2026-07-15T09:00:00.000Z"),
      read: () => ({
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
        agents,
        mcpServers: [],
      }),
    });

    service.projectNow();
    expect(db.prepare("SELECT status FROM agents WHERE id = 'WebBreaker'").get())
      .toEqual({ status: "available" });
    expect(db.prepare(`
      SELECT enabled FROM agent_capabilities
      WHERE agent_id = 'WebBreaker' AND capability = 'kali:curl'
    `).get()).toEqual({ enabled: 1 });

    agents = [];
    service.projectNow();
    expect(db.prepare("SELECT status FROM agents WHERE id = 'WebBreaker'").get())
      .toEqual({ status: "offline" });
    expect(db.prepare(`
      SELECT COUNT(*) AS count FROM agent_capabilities
      WHERE agent_id = 'WebBreaker' AND capability = 'kali:curl'
    `).get()).toEqual({ count: 0 });
    expect(JSON.parse(String((db.prepare(`
      SELECT configuration_json FROM agents WHERE id = 'runtime-web-adapter'
    `).get() as { configuration_json: string }).configuration_json))).toMatchObject({
      userFacing: false,
      internalComponent: true,
    });
    expect(db.prepare("SELECT status FROM agents WHERE id = 'runtime-web-adapter'").get())
      .toEqual({ status: "offline" });
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

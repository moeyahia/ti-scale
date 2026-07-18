import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import type {
  ComponentHealth,
  RuntimeReadinessSnapshot,
} from "./RuntimeReadiness";
import type { RuntimeSourceManifests } from "../domain";

export type FleetAgentStatus =
  | "available"
  | "busy"
  | "degraded"
  | "offline"
  | "quarantined";

export type McpServerStatus =
  | "unknown"
  | "healthy"
  | "degraded"
  | "offline"
  | "quarantined";

export interface FleetAgentProjection {
  readonly id: string;
  readonly role: string;
  readonly displayName: string;
  readonly status: FleetAgentStatus;
  readonly providerPolicy: Readonly<Record<string, unknown>>;
  readonly toolPolicy: Readonly<Record<string, unknown>>;
  readonly configuration: Readonly<Record<string, unknown>>;
  readonly version: string;
  /**
   * A heartbeat emitted by the actual specialist worker. Control-plane roster,
   * provider, or MCP projections must leave this absent/null.
   */
  readonly lastHeartbeatAt?: string | null;
  readonly capabilities: readonly {
    readonly name: string;
    readonly source: string;
    readonly enabled: boolean;
    readonly metadata?: Readonly<Record<string, unknown>>;
  }[];
}

export interface McpServerProjection {
  readonly id: string;
  readonly name: string;
  readonly transport: string;
  readonly endpointRedacted?: string;
  readonly status: McpServerStatus;
  readonly capabilities: readonly string[];
  readonly policy: Readonly<Record<string, unknown>>;
}

export interface RuntimeProjectionInput {
  readonly readiness: RuntimeReadinessSnapshot;
  readonly agents: readonly FleetAgentProjection[];
  readonly mcpServers: readonly McpServerProjection[];
  /** Canonical, attested manifests used to derive V2 registries. */
  readonly capabilityManifests?: RuntimeSourceManifests;
}

export interface RuntimeProjectionResult {
  readonly projectedAt: string;
  readonly agentCount: number;
  readonly mcpServerCount: number;
  readonly healthSnapshotCount: number;
}

interface RuntimeProjectionServiceOptions {
  readonly database: SqliteDatabase;
  readonly read: () => RuntimeProjectionInput;
  readonly intervalMs?: number;
  readonly retentionMs?: number;
  readonly clock?: () => Date;
}

const IDENTIFIER = /^[A-Za-z0-9._:@/-]{1,200}$/u;

function identifier(value: string, label: string): string {
  const normalized = value.trim();
  if (!IDENTIFIER.test(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function text(value: string, label: string, maximum = 500): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/u.test(normalized)) {
    throw new Error(`${label} is invalid`);
  }
  return normalized;
}

function json(value: unknown): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new Error("Runtime projection value is not serializable");
  return serialized;
}

function componentMessage(component: string, health: ComponentHealth): string {
  if (health === "healthy") return `${component} is operational`;
  if (health === "degraded") return `${component} is operating with reduced capability`;
  if (health === "unhealthy") return `${component} is unavailable`;
  return `${component} health has not been verified`;
}

/**
 * Materializes live, secret-free runtime facts into the canonical database.
 * The Overview remains a cheap database projection while readiness itself is
 * evaluated from the live callback on every request.
 */
export class RuntimeProjectionService {
  private readonly database: SqliteDatabase;
  private readonly read: () => RuntimeProjectionInput;
  private readonly intervalMs: number;
  private readonly retentionMs: number;
  private readonly clock: () => Date;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(options: RuntimeProjectionServiceOptions) {
    this.database = options.database;
    this.read = options.read;
    this.intervalMs = options.intervalMs ?? 15_000;
    this.retentionMs = options.retentionMs ?? 7 * 24 * 60 * 60 * 1_000;
    this.clock = options.clock ?? (() => new Date());
    if (!Number.isSafeInteger(this.intervalMs) || this.intervalMs < 1_000 || this.intervalMs > 300_000) {
      throw new RangeError("intervalMs must be between 1000 and 300000");
    }
    if (!Number.isSafeInteger(this.retentionMs) || this.retentionMs < 60_000) {
      throw new RangeError("retentionMs must be at least 60000");
    }
  }

  get isStarted(): boolean {
    return this.timer !== null;
  }

  start(): RuntimeProjectionResult {
    if (!this.timer) {
      this.timer = setInterval(() => {
        try {
          this.projectNow();
        } catch {
          // Readiness remains fail-closed. The next interval can recover; the
          // operational logger records startup/runtime failures at the caller.
        }
      }, this.intervalMs);
      this.timer.unref?.();
    }
    return this.projectNow();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  projectNow(): RuntimeProjectionResult {
    const input = this.read();
    const now = this.clock();
    const projectedAt = now.toISOString();
    const agentIds = new Set<string>();
    const mcpIds = new Set<string>();

    inImmediateTransaction(this.database, () => {
      const upsertAgent = this.database.prepare(`
        INSERT INTO agents (
          id, role, display_name, status, provider_policy_json,
          tool_policy_json, configuration_json, version,
          last_heartbeat_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          role = excluded.role,
          display_name = excluded.display_name,
          status = CASE
            WHEN EXISTS (
              SELECT 1 FROM assignments
              WHERE assignments.agent_id = excluded.id
                AND assignments.status = 'active'
            ) THEN 'busy'
            ELSE excluded.status
          END,
          provider_policy_json = excluded.provider_policy_json,
          tool_policy_json = excluded.tool_policy_json,
          configuration_json = excluded.configuration_json,
          version = excluded.version,
          last_heartbeat_at = COALESCE(excluded.last_heartbeat_at, agents.last_heartbeat_at),
          updated_at = excluded.updated_at
      `);
      const removeCapabilities = this.database.prepare(
        "DELETE FROM agent_capabilities WHERE agent_id = ? AND source = ?",
      );
      const insertCapability = this.database.prepare(`
        INSERT INTO agent_capabilities (
          agent_id, capability, source, enabled, metadata_json
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(agent_id, capability, source) DO UPDATE SET
          enabled = excluded.enabled,
          metadata_json = excluded.metadata_json
      `);

      for (const agent of input.agents) {
        const id = identifier(agent.id, "agent ID");
        if (agentIds.has(id)) throw new Error(`Duplicate projected agent: ${id}`);
        agentIds.add(id);
        const heartbeat = agent.lastHeartbeatAt == null
          ? null
          : new Date(agent.lastHeartbeatAt).toISOString();
        if (agent.lastHeartbeatAt != null && !Number.isFinite(Date.parse(agent.lastHeartbeatAt))) {
          throw new Error(`Agent heartbeat is invalid: ${id}`);
        }
        upsertAgent.run(
          id,
          text(agent.role, "agent role"),
          text(agent.displayName, "agent display name"),
          agent.status,
          json(agent.providerPolicy),
          json(agent.toolPolicy),
          json(agent.configuration),
          text(agent.version, "agent version", 100),
          heartbeat,
          projectedAt,
          projectedAt,
        );
        const sources = new Set([
          "live-route-attestation",
          ...agent.capabilities.map((capability) => text(capability.source, "capability source", 100)),
        ]);
        for (const source of sources) removeCapabilities.run(id, source);
        for (const capability of agent.capabilities) {
          insertCapability.run(
            id,
            text(capability.name, "capability", 300),
            text(capability.source, "capability source", 100),
            capability.enabled ? 1 : 0,
            json(capability.metadata ?? {}),
          );
        }
      }
      if (agentIds.size === 0) {
        this.database.prepare("UPDATE agents SET status = 'offline', updated_at = ?").run(projectedAt);
      } else {
        this.database.prepare(
          `UPDATE agents SET status = 'offline', updated_at = ? WHERE id NOT IN (${[...agentIds].map(() => "?").join(",")})`,
        ).run(projectedAt, ...agentIds);
      }

      const upsertMcp = this.database.prepare(`
        INSERT INTO mcp_servers (
          id, name, transport, endpoint_redacted, status,
          capabilities_json, policy_json, last_checked_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          name = excluded.name,
          transport = excluded.transport,
          endpoint_redacted = excluded.endpoint_redacted,
          status = excluded.status,
          capabilities_json = excluded.capabilities_json,
          policy_json = excluded.policy_json,
          last_checked_at = excluded.last_checked_at,
          updated_at = excluded.updated_at
      `);
      for (const server of input.mcpServers) {
        const id = identifier(server.id, "MCP server ID");
        if (mcpIds.has(id)) throw new Error(`Duplicate projected MCP server: ${id}`);
        mcpIds.add(id);
        upsertMcp.run(
          id,
          text(server.name, "MCP server name"),
          text(server.transport, "MCP transport", 100),
          server.endpointRedacted ? text(server.endpointRedacted, "redacted MCP endpoint", 1_000) : null,
          server.status,
          json(server.capabilities),
          json(server.policy),
          projectedAt,
          projectedAt,
          projectedAt,
        );
      }
      if (mcpIds.size === 0) {
        this.database.prepare("UPDATE mcp_servers SET status = 'offline', updated_at = ?").run(projectedAt);
      } else {
        this.database.prepare(
          `UPDATE mcp_servers SET status = 'offline', updated_at = ? WHERE id NOT IN (${[...mcpIds].map(() => "?").join(",")})`,
        ).run(projectedAt, ...mcpIds);
      }

      const insertHealth = this.database.prepare(`
        INSERT INTO health_snapshots (
          id, component_type, component_id, status,
          metrics_json, message, captured_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      for (const provider of input.readiness.providers) {
        const id = identifier(provider.id, "provider ID");
        insertHealth.run(
          randomUUID(),
          "provider",
          id,
          provider.health,
          json({
            authenticated: provider.authenticated,
            callable: provider.callable,
            attestedAt: provider.attestedAt ?? null,
            expiresAt: provider.expiresAt ?? null,
            circuitState: provider.circuitState ?? null,
            supportsGuided: provider.supportsGuided,
            enforcesAutonomousBoundary: provider.enforcesAutonomousBoundary,
            reportsExactTokenUsage: provider.reportsExactTokenUsage,
            reportsExactCostUsage: provider.reportsExactCostUsage,
          }),
          provider.reason ? text(provider.reason, "provider health reason", 1_000) : componentMessage(id, provider.health),
          projectedAt,
        );
      }
      insertHealth.run(
        randomUUID(),
        "event_stream",
        "local-sse",
        input.readiness.eventStream,
        json({}),
        componentMessage("Local event stream", input.readiness.eventStream),
        projectedAt,
      );
      insertHealth.run(
        randomUUID(),
        "memory",
        "second-brain",
        input.readiness.secondBrain,
        json({}),
        componentMessage("Second Brain", input.readiness.secondBrain),
        projectedAt,
      );
      insertHealth.run(
        randomUUID(),
        "policy",
        "legacy-execution",
        input.readiness.legacyExecutionEnabled ? "degraded" : "healthy",
        json({ enabled: input.readiness.legacyExecutionEnabled }),
        input.readiness.legacyExecutionEnabled
          ? "The legacy execution compatibility window is active"
          : "Legacy compatibility is read-only; Ti-Scale owns mutations",
        projectedAt,
      );

      this.database.prepare("DELETE FROM health_snapshots WHERE captured_at < ?").run(
        new Date(now.getTime() - this.retentionMs).toISOString(),
      );
    });

    return {
      projectedAt,
      agentCount: agentIds.size,
      mcpServerCount: mcpIds.size,
      healthSnapshotCount: input.readiness.providers.length + 3,
    };
  }
}

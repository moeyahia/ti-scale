import { getDatabaseHealth } from "../db";
import type { SqliteDatabase } from "../db";
import type { AgentSummary, AttentionItem, OverviewSnapshot } from "./types";
import { MissionRepository } from "./MissionRepository";

interface CountRow {
  readonly count: number;
}

interface LastEventRow {
  readonly occurred_at: string | null;
}

interface AttentionRow {
  readonly id: string;
  readonly type: string;
  readonly severity: string;
  readonly title: string;
  readonly summary: string;
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly created_at: string;
}

interface AgentRow {
  readonly id: string;
  readonly name: string;
  readonly status: string;
  readonly assignment: string | null;
}

interface MemoryCountsRow {
  readonly confirmed: number;
  readonly candidates: number;
  readonly stale: number;
  readonly disputed: number;
}

interface VaultRow {
  readonly status: string;
}

interface HealthStatusRow {
  readonly status: string;
}

interface McpStatusRow {
  readonly status: string;
  readonly policy_json: string;
}

function count(database: SqliteDatabase, sql: string): number {
  return (database.prepare(sql).get() as CountRow).count;
}

function attention(row: AttentionRow): AttentionItem {
  return {
    id: row.id,
    type: row.type,
    severity: row.severity,
    title: row.title,
    summary: row.summary,
    ...(row.mission_id ? { missionId: row.mission_id } : {}),
    ...(row.run_id ? { runId: row.run_id } : {}),
  };
}

function aggregateHealth(statuses: readonly string[], empty: string): string {
  if (statuses.length === 0) return empty;
  if (statuses.some((status) => status === "unhealthy" || status === "offline" || status === "quarantined" || status === "error")) {
    return "unhealthy";
  }
  if (statuses.some((status) => status === "degraded" || status === "unknown" || status === "connecting")) {
    return "degraded";
  }
  return "healthy";
}

function mcpRouteEnabled(policyJson: string): boolean {
  try {
    const policy = JSON.parse(policyJson) as { readonly enabled?: unknown } | null;
    return policy?.enabled !== false && policy?.enabled !== 0;
  } catch {
    // A malformed policy must not make an unreviewed route disappear from health reporting.
    return true;
  }
}

/**
 * Overview-only MCP roll-up. Execution readiness remains governed by the runtime's
 * exact route attestation and policy gates; this function only describes fleet health.
 */
export function aggregateMcpHealth(routes: readonly McpStatusRow[]): string {
  if (routes.length === 0) return "not_configured";

  // Quarantine and explicit errors remain visible even when a route is disabled.
  if (routes.some(({ status }) => status === "quarantined" || status === "error")) {
    return "unhealthy";
  }

  const enabledRoutes = routes.filter(({ policy_json }) => mcpRouteEnabled(policy_json));
  if (enabledRoutes.length === 0) return "not_configured";

  const statuses = enabledRoutes.map(({ status }) => status);
  if (statuses.every((status) => status === "healthy")) return "healthy";
  if (statuses.some((status) => status === "healthy")) return "degraded";
  if (statuses.every((status) => status === "offline" || status === "unhealthy")) {
    return "unhealthy";
  }
  return "degraded";
}

/** Real database-backed operational projection used by the Command Center. */
export class OverviewRepository {
  private readonly missions: MissionRepository;

  constructor(private readonly database: SqliteDatabase) {
    this.missions = new MissionRepository(database);
  }

  readData(): Omit<OverviewSnapshot, "readiness"> {
    const lastEvent = this.database
      .prepare("SELECT MAX(occurred_at) AS occurred_at FROM events")
      .get() as LastEventRow;
    const pendingDecisions = count(
      this.database,
      `SELECT
        (SELECT COUNT(*) FROM guided_decisions WHERE status = 'pending') +
        (SELECT COUNT(*) FROM approvals WHERE status = 'pending') AS count`,
    );

    const attentionRows = this.database
      .prepare(`
        SELECT * FROM (
          SELECT
            gd.id,
            'guided_decision' AS type,
            'warning' AS severity,
            'Guided decision required' AS title,
            gd.rationale AS summary,
            gd.mission_id,
            gd.run_id,
            gd.created_at
          FROM guided_decisions gd
          WHERE gd.status = 'pending'
          UNION ALL
          SELECT
            a.id,
            'administrative_approval' AS type,
            'warning' AS severity,
            'Administrative approval required' AS title,
            a.reason AS summary,
            a.mission_id,
            a.run_id,
            a.created_at
          FROM approvals a
          WHERE a.status = 'pending'
          UNION ALL
          SELECT
            r.id,
            CASE WHEN r.status = 'recovering' THEN 'recovery' ELSE 'blocked_run' END AS type,
            CASE WHEN r.status = 'recovering' THEN 'warning' ELSE 'error' END AS severity,
            CASE
              WHEN r.status = 'recovering' THEN 'Run is recovering'
              WHEN r.journey = 'autonomous' THEN 'Autonomous run safe-stopped or blocked'
              ELSE 'Guided mission is blocked'
            END AS title,
            COALESCE(r.status_reason, 'The run requires a documented recovery path.') AS summary,
            r.mission_id,
            r.id AS run_id,
            r.updated_at AS created_at
          FROM runs r
          WHERE r.status IN ('recovering', 'blocked')
        )
        ORDER BY created_at DESC, id DESC
        LIMIT 12
      `)
      .all() as AttentionRow[];

    const agentRows = this.database
      .prepare(`
        SELECT
          a.id,
          a.display_name AS name,
          a.status,
          (
            SELECT m.name
            FROM assignments x
            JOIN runs r ON r.id = x.run_id
            JOIN missions m ON m.id = r.mission_id
            WHERE x.agent_id = a.id AND x.status IN ('queued', 'active', 'blocked')
            ORDER BY x.updated_at DESC, x.id DESC
            LIMIT 1
          ) AS assignment
        FROM agents a
        ORDER BY
          CASE a.status
            WHEN 'busy' THEN 0 WHEN 'degraded' THEN 1 WHEN 'available' THEN 2
            WHEN 'quarantined' THEN 3 ELSE 4
          END,
          a.display_name ASC
        LIMIT 20
      `)
      .all() as AgentRow[];

    const memory = this.database
      .prepare(`
        SELECT
          SUM(CASE WHEN lifecycle_status IN ('confirmed', 'verified') THEN 1 ELSE 0 END) AS confirmed,
          SUM(CASE WHEN lifecycle_status = 'candidate' THEN 1 ELSE 0 END) AS candidates,
          SUM(CASE WHEN lifecycle_status = 'stale' THEN 1 ELSE 0 END) AS stale,
          SUM(CASE WHEN lifecycle_status = 'disputed' THEN 1 ELSE 0 END) AS disputed
        FROM memory_nodes
      `)
      .get() as MemoryCountsRow;
    const openVaultConflicts = count(
      this.database,
      "SELECT COUNT(*) AS count FROM vault_conflicts WHERE status = 'open'",
    );
    const vault = this.database
      .prepare(`
        SELECT status FROM vault_connections
        ORDER BY updated_at DESC, id DESC LIMIT 1
      `)
      .get() as VaultRow | undefined;

    const eventStreamStatuses = this.database
      .prepare(`
        WITH latest AS (
          SELECT status,
            ROW_NUMBER() OVER (PARTITION BY component_id ORDER BY captured_at DESC, id DESC) AS rank
          FROM health_snapshots WHERE component_type = 'event_stream'
        ) SELECT status FROM latest WHERE rank = 1
      `)
      .all() as HealthStatusRow[];
    const providerStatuses = this.database
      .prepare(`
        WITH latest AS (
          SELECT status,
            ROW_NUMBER() OVER (PARTITION BY component_id ORDER BY captured_at DESC, id DESC) AS rank
          FROM health_snapshots WHERE component_type = 'provider'
        ) SELECT status FROM latest WHERE rank = 1
      `)
      .all() as HealthStatusRow[];
    const mcpStatuses = this.database
      .prepare("SELECT status, policy_json FROM mcp_servers")
      .all() as McpStatusRow[];
    const databaseHealth = getDatabaseHealth(this.database);

    return {
      schemaVersion: "2.4",
      summary: {
        activeMissions: count(
          this.database,
          "SELECT COUNT(*) AS count FROM missions WHERE status IN ('ready', 'active', 'paused')",
        ),
        activeAgents: count(
          this.database,
          "SELECT COUNT(*) AS count FROM agents WHERE status = 'busy'",
        ),
        pendingDecisions,
        recoveringRuns: count(
          this.database,
          "SELECT COUNT(*) AS count FROM runs WHERE status = 'recovering'",
        ),
        lastEventAt: lastEvent.occurred_at,
      },
      missions: this.missions.listRecent(12),
      attention: attentionRows.map(attention),
      agents: agentRows.map(
        (row): AgentSummary => ({
          id: row.id,
          name: row.name,
          status: row.status,
          ...(row.assignment ? { assignment: row.assignment } : {}),
        }),
      ),
      brain: {
        confirmed: memory.confirmed ?? 0,
        candidates: memory.candidates ?? 0,
        stale: memory.stale ?? 0,
        conflicts: (memory.disputed ?? 0) + openVaultConflicts,
        vaultStatus: vault?.status ?? "not_configured",
      },
      system: {
        database: databaseHealth.healthy ? "healthy" : "unhealthy",
        eventStream: aggregateHealth(
          eventStreamStatuses.map((row) => row.status),
          "unknown",
        ),
        providers: aggregateHealth(
          providerStatuses.map((row) => row.status),
          "unknown",
        ),
        mcp: aggregateMcpHealth(mcpStatuses),
      },
    };
  }
}

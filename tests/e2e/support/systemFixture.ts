import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const SYSTEM_FIXTURE_COUNT = 26;
const SYSTEM_TIME_MS = Date.parse("2199-07-16T12:00:00.000Z");

export const SYSTEM_FIXTURE_SECRET = "system-fixture-secret-that-must-not-render";
export const SYSTEM_PROVIDER_FIRST_PAGE = "system-fixture-provider-26";
export const SYSTEM_PROVIDER_SECOND_PAGE = "system-fixture-provider-01";
export const SYSTEM_MCP_FIRST_PAGE = "System Fixture MCP 26";
export const SYSTEM_MCP_SECOND_PAGE = "System Fixture MCP 01";
export const SYSTEM_HEALTH_COMPONENT = "system-fixture-event-stream";
export const SYSTEM_POLICY_SETTING = "policy.system.fixture";

const MCP_STATUSES = ["unknown", "healthy", "degraded", "offline", "quarantined"] as const;

export interface SystemFixture {
  readonly namespace: string;
  readonly providerGroupCount: number;
  readonly mcpServerCount: number;
  readonly healthSnapshotCount: number;
}

export interface SystemFixtureSnapshot {
  readonly providerTurnCount: number;
  readonly mcpServerCount: number;
  readonly healthSnapshotCount: number;
  readonly policySetting: unknown;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("System E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

function fixtureTime(index: number): string {
  return new Date(SYSTEM_TIME_MS + index * 1_000).toISOString();
}

function numbered(prefix: string, index: number): string {
  return `${prefix}${String(index + 1).padStart(2, "0")}`;
}

/**
 * Seeds canonical system records through the same SQLite schema read by the
 * mounted V2 operations routes. Provider and MCP identities are deliberately
 * stable across Playwright projects so a matrix run cannot inflate the 26
 * logical pagination groups; individual provider turns remain namespaced.
 */
export function createSystemFixture(instanceId: string): SystemFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    inImmediateTransaction(database, () => {
      for (let index = 0; index < SYSTEM_FIXTURE_COUNT; index += 1) {
        const provider = numbered("system-fixture-provider-", index);
        const model = numbered("system-fixture-model-", index);
        const timestamp = fixtureTime(index);
        const failed = index === 1;
        database.prepare(`
          INSERT OR IGNORE INTO provider_turns (
            id, provider, model, status, input_tokens, output_tokens,
            estimated_cost, latency_ms, error_category, started_at, ended_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          `provider-turn-system-${namespace}-${String(index + 1).padStart(2, "0")}`,
          provider,
          model,
          failed ? "failed" : "completed",
          100 + index,
          20 + index,
          Number((0.001 * (index + 1)).toFixed(6)),
          80 + index,
          failed ? "provider_unavailable" : null,
          timestamp,
          timestamp,
        );

        const mcpId = numbered("mcp-system-fixture-", index);
        const mcpName = numbered("System Fixture MCP ", index);
        const status = MCP_STATUSES[index % MCP_STATUSES.length];
        database.prepare(`
          INSERT INTO mcp_servers (
            id, name, transport, endpoint_redacted, status, capabilities_json,
            policy_json, last_checked_at, created_at, updated_at
          ) VALUES (?, ?, 'stdio', ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            transport = excluded.transport,
            endpoint_redacted = excluded.endpoint_redacted,
            status = excluded.status,
            capabilities_json = excluded.capabilities_json,
            policy_json = excluded.policy_json,
            last_checked_at = excluded.last_checked_at,
            updated_at = excluded.updated_at
        `).run(
          mcpId,
          mcpName,
          `local://${mcpId}/[redacted]`,
          status,
          JSON.stringify(["fixture.read", `fixture.capability.${index + 1}`]),
          JSON.stringify({
            enforcement: index % 2 === 0 ? "enforced" : "advisory",
            allowedActionClasses: ["passive_intelligence_osint"],
            apiToken: SYSTEM_FIXTURE_SECRET,
          }),
          timestamp,
          fixtureTime(0),
          timestamp,
        );
      }

      database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'internal', 1, 'e2e-system-fixture', ?)
        ON CONFLICT(key) DO UPDATE SET
          value_json = excluded.value_json,
          sensitivity = excluded.sensitivity,
          version = settings.version + 1,
          updated_by = excluded.updated_by,
          updated_at = excluded.updated_at
      `).run(
        SYSTEM_POLICY_SETTING,
        JSON.stringify({ mode: "enforce", authorizationToken: SYSTEM_FIXTURE_SECRET }),
        fixtureTime(-1),
      );

      const health = [
        {
          id: "health-system-fixture-database",
          componentType: "database",
          componentId: "system-fixture-database",
          status: "healthy",
          message: "The isolated V2 database passed its canonical fixture health check.",
          metrics: { integrity: "ok", wal: true, latencyMs: 2 },
        },
        {
          id: "health-system-fixture-events",
          componentType: "event_stream",
          componentId: SYSTEM_HEALTH_COMPONENT,
          status: "degraded",
          message: "The fixture records a bounded degraded state with an explicit remediation path.",
          metrics: { connectedSubscribers: 1, queuedEvents: 2, bearerToken: SYSTEM_FIXTURE_SECRET },
        },
        {
          id: "health-system-fixture-worker",
          componentType: "worker",
          componentId: "system-fixture-worker",
          status: "unknown",
          message: "The fixture worker has no recent executable assignment.",
          metrics: { queueDepth: 0, heartbeatAgeMs: null },
        },
      ] as const;
      health.forEach((item, index) => {
        database.prepare(`
          INSERT INTO health_snapshots (
            id, component_type, component_id, status, metrics_json, message, captured_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            component_type = excluded.component_type,
            component_id = excluded.component_id,
            status = excluded.status,
            metrics_json = excluded.metrics_json,
            message = excluded.message,
            captured_at = excluded.captured_at
        `).run(
          item.id,
          item.componentType,
          item.componentId,
          item.status,
          JSON.stringify(item.metrics),
          item.message,
          fixtureTime(SYSTEM_FIXTURE_COUNT + index + 1),
        );
      });
    });
    return {
      namespace,
      providerGroupCount: SYSTEM_FIXTURE_COUNT,
      mcpServerCount: SYSTEM_FIXTURE_COUNT,
      healthSnapshotCount: 3,
    };
  } finally {
    database.close();
  }
}

export function readSystemFixtureSnapshot(fixture: SystemFixture): SystemFixtureSnapshot {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const providerTurnCount = database.prepare(`
      SELECT COUNT(*) AS count FROM provider_turns WHERE id LIKE ?
    `).get(`provider-turn-system-${fixture.namespace}-%`) as { readonly count: number };
    const mcpServerCount = database.prepare(`
      SELECT COUNT(*) AS count FROM mcp_servers WHERE id LIKE 'mcp-system-fixture-%'
    `).get() as { readonly count: number };
    const healthSnapshotCount = database.prepare(`
      SELECT COUNT(*) AS count FROM health_snapshots WHERE id LIKE 'health-system-fixture-%'
    `).get() as { readonly count: number };
    const policy = database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(SYSTEM_POLICY_SETTING) as { readonly value_json: string } | undefined;
    if (!policy) throw new Error("System fixture policy setting is missing");
    return {
      providerTurnCount: providerTurnCount.count,
      mcpServerCount: mcpServerCount.count,
      healthSnapshotCount: healthSnapshotCount.count,
      policySetting: JSON.parse(policy.value_json) as unknown,
    };
  } finally {
    database.close();
  }
}

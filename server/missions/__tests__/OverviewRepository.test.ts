import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { aggregateMcpHealth, OverviewRepository } from "../OverviewRepository";

type StoredMcpStatus = "unknown" | "healthy" | "degraded" | "offline" | "quarantined";

function insertMcpRoute(
  database: SqliteDatabase,
  index: number,
  status: StoredMcpStatus,
  enabled = true,
): void {
  const timestamp = "2026-07-18T06:00:00.000Z";
  database.prepare(`
    INSERT INTO mcp_servers (
      id, name, transport, endpoint_redacted, status, capabilities_json,
      policy_json, last_checked_at, created_at, updated_at
    ) VALUES (?, ?, 'stdio', 'local reviewed route', ?, '[]', ?, ?, ?, ?)
  `).run(
    `mcp-${index}`,
    `MCP route ${index}`,
    status,
    JSON.stringify({ enabled }),
    timestamp,
    timestamp,
    timestamp,
  );
}

function readMcpHealth(
  routes: readonly { readonly status: StoredMcpStatus; readonly enabled?: boolean }[],
): string {
  const database = createDatabaseConnection({ filename: ":memory:" });
  try {
    migrateDatabase(database);
    routes.forEach((route, index) => insertMcpRoute(
      database,
      index,
      route.status,
      route.enabled ?? true,
    ));
    return new OverviewRepository(database).readData().system.mcp;
  } finally {
    database.close();
  }
}

describe("OverviewRepository MCP health", () => {
  test("reports no routes or an entirely disabled fleet as not configured", () => {
    expect(readMcpHealth([])).toBe("not_configured");
    expect(readMcpHealth([
      { status: "offline", enabled: false },
      { status: "healthy", enabled: false },
    ])).toBe("not_configured");
  });

  test("reports an enabled fleet with every route offline as unhealthy", () => {
    expect(readMcpHealth([
      { status: "offline" },
      { status: "offline" },
    ])).toBe("unhealthy");
  });

  test("reports healthy and offline enabled routes as degraded", () => {
    expect(readMcpHealth([
      { status: "healthy" },
      { status: "offline" },
    ])).toBe("degraded");
  });

  test("reports all enabled routes operational while ignoring disabled offline routes", () => {
    expect(readMcpHealth([
      { status: "healthy" },
      { status: "healthy" },
      { status: "offline", enabled: false },
    ])).toBe("healthy");
  });

  test("keeps quarantined and explicit error routes as hard health failures", () => {
    expect(readMcpHealth([
      { status: "healthy" },
      { status: "quarantined" },
    ])).toBe("unhealthy");
    expect(aggregateMcpHealth([
      { status: "healthy", policy_json: '{"enabled":true}' },
      { status: "error", policy_json: '{"enabled":true}' },
    ])).toBe("unhealthy");
  });
});

import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository } from "../../memory/MemoryRepository";
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

describe("OverviewRepository memory count semantics", () => {
  test("keeps lifecycle-candidate nodes separate from pending Memory Inbox reviews", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database);
      const memory = new MemoryRepository(database);
      const provenance = {
        method: "imported" as const,
        explanation: "Imported canonical node remains a lifecycle candidate until reviewed through its provenance workflow.",
        sources: [{
          sourceType: "legacy_note",
          sourceId: "candidate-node-source",
          acquiredAt: "2026-07-19T12:00:00.000Z",
        }],
      };
      memory.createNode({
        id: "candidate-node",
        nodeType: "source",
        title: "Imported candidate node",
        summary: "A canonical graph node that is not itself a pending Inbox proposal.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.7,
        lifecycleStatus: "candidate",
        confirmationState: "pending",
        provenance,
        authorType: "import",
        authorId: "legacy-importer",
      });
      memory.createCandidate({
        id: "pending-inbox-review",
        nodeType: "preference",
        title: "Pending explanation preference",
        summary: "A proposal that is actually waiting for operator review in the Memory Inbox.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.8,
        provenance: {
          method: "operator_statement",
          explanation: "The operator statement must be reviewed before it can influence future behavior.",
          sources: [{
            sourceType: "message",
            sourceId: "pending-review-source",
            acquiredAt: "2026-07-19T12:01:00.000Z",
          }],
        },
        proposedBy: "guided-commander",
      });

      const brain = new OverviewRepository(database).readData().brain;
      expect(brain).toMatchObject({
        candidateNodes: 1,
        pendingReviews: 1,
        candidates: 1,
      });
    } finally {
      database.close();
    }
  });
});

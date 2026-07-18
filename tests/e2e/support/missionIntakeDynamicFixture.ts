import { createHash } from "node:crypto";
import { createDatabaseConnection } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

export interface MissionIntakeDynamicFixture {
  readonly agentId: string;
  readonly agentName: string;
  readonly memoryNodeId: string;
  readonly memoryTitle: string;
}

/**
 * Creates one real, scope-safe specialist route and one confirmed preference in
 * the isolated Playwright database. Production repositories and preflight
 * queries consume them; the browser does not receive a mocked response.
 */
export function createMissionIntakeDynamicFixture(instanceId: string): MissionIntakeDynamicFixture {
  if (!E2E_DATABASE_PATH) throw new Error("Mission-intake E2E requires the isolated V2 database path");
  const namespace = normalizeFixtureNamespace(instanceId);
  const suffix = createHash("sha256").update(namespace, "utf8").digest("hex").slice(0, 12);
  const agentId = `agent-intake-${suffix}`;
  const agentName = `Recon readiness specialist ${suffix}`;
  const providerId = `provider-intake-${suffix}`;
  const mcpServerId = `mcp:intake-${suffix}`;
  const memoryNodeId = `mem-intake-${suffix}`;
  const memoryTitle = `Evidence-led explanation preference ${suffix}`;
  const now = new Date().toISOString();
  const validUntil = new Date(Date.now() + 10 * 60_000).toISOString();
  const database = createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });

  try {
    database.prepare(`
      INSERT OR IGNORE INTO agents (
        id, role, display_name, status, provider_policy_json, tool_policy_json,
        configuration_json, version, last_heartbeat_at, created_at, updated_at
      ) VALUES (?, 'reconnaissance', ?, 'available', ?, ?, '{}', '2.4', ?, ?, ?)
    `).run(
      agentId,
      agentName,
      JSON.stringify({ defaultProvider: providerId }),
      JSON.stringify({ allowedTools: ["nmap"], deniedTools: [], approvalRequiredTools: [] }),
      now,
      now,
      now,
    );
    database.prepare(`
      INSERT OR IGNORE INTO agent_capabilities (
        agent_id, capability, source, enabled, metadata_json
      ) VALUES (?, 'nmap', 'live-route-attestation', 1, ?)
    `).run(agentId, JSON.stringify({ validUntil, attestedAt: now, providerIds: [providerId] }));
    database.prepare(`
      INSERT OR IGNORE INTO mcp_servers (
        id, name, transport, endpoint_redacted, status, capabilities_json,
        policy_json, last_checked_at, created_at, updated_at
      ) VALUES (?, 'Nmap intake fixture', 'stdio', 'isolated local fixture', 'healthy', '["nmap"]', ?, ?, ?, ?)
    `).run(
      mcpServerId,
      JSON.stringify({
        enabled: true,
        assignedAgents: [agentId],
        startPermitted: true,
        riskClass: "network",
      }),
      now,
      now,
      now,
    );
    database.prepare(`
      INSERT OR IGNORE INTO health_snapshots (
        id, component_type, component_id, status, metrics_json, message, captured_at
      ) VALUES (?, 'provider', ?, 'healthy', ?, 'Isolated enforcing provider fixture is callable', ?)
    `).run(
      `health-intake-${suffix}`,
      providerId,
      JSON.stringify({
        authenticated: true,
        callable: true,
        attestedAt: now,
        expiresAt: validUntil,
        enforcesAutonomousBoundary: true,
        reportsExactTokenUsage: true,
        reportsExactCostUsage: true,
      }),
      now,
    );

    const existingMemory = database.prepare("SELECT id FROM memory_nodes WHERE id = ?").get(memoryNodeId);
    if (!existingMemory) {
      new MemoryRepository(database).createNode({
        id: memoryNodeId,
        nodeType: "preference",
        title: memoryTitle,
        summary: "Use technically literate, evidence-led explanations without internal binding jargon.",
        body: "Keep operator prose readable while retaining useful protocol, product, CVE, and verification detail.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 1,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: {
          method: "operator_statement",
          explanation: "Confirmed in the isolated mission-intake browser fixture.",
          sources: [{ sourceType: "e2e_fixture", sourceId: `source-${memoryNodeId}`, acquiredAt: now }],
        },
        authorType: "operator",
        authorId: "e2e-local-operator",
        retentionPolicy: { allowGuided: true, allowAutonomous: true },
      });
    }
  } finally {
    database.close();
  }

  return { agentId, agentName, memoryNodeId, memoryTitle };
}

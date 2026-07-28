import { createHash } from "node:crypto";
import { createDatabaseConnection } from "../../../server/db";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

export interface MissionIntakeDynamicFixture {
  readonly agentId: string;
  readonly agentName: string;
  readonly memoryNodeId: string;
  readonly memoryTitle: string;
}

export interface MissionIntakeDynamicFixtureOptions {
  readonly preseedExpiredAttestation?: boolean;
}

/**
 * Creates one real, scope-safe specialist route and one confirmed preference in
 * the isolated Playwright database. Production repositories and preflight
 * queries consume them; the browser does not receive a mocked response.
 */
export function createMissionIntakeDynamicFixture(
  instanceId: string,
  options: MissionIntakeDynamicFixtureOptions = {},
): MissionIntakeDynamicFixture {
  if (!E2E_DATABASE_PATH) throw new Error("Mission-intake E2E requires the isolated V2 database path");
  const namespace = normalizeFixtureNamespace(instanceId);
  const suffix = createHash("sha256").update(namespace, "utf8").digest("hex").slice(0, 12);
  const agentId = "ReconScout";
  const agentName = "ReconScout";
  const providerId = `provider-intake-${suffix}`;
  const mcpServerId = `mcp:intake-${suffix}`;
  const memoryNodeId = `mem-intake-${suffix}`;
  const memoryTitle = `Evidence-led explanation preference ${suffix}`;
  const now = new Date().toISOString();
  const validUntil = new Date(Date.now() + 10 * 60_000).toISOString();
  const capabilityMetadata = {
    validUntil,
    attestedAt: now,
    providerIds: [providerId],
    actionClassIds: [
      "active_host_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
    ],
  } as const;
  const productAgentConfiguration = JSON.stringify({
    schemaVersion: "ti-scale.product-agent-roster.v1",
    userFacing: true,
    productAgent: true,
    runtimeBindingAgentIds: [agentId],
    readiness: {
      status: "available",
      boundAdapterCount: 1,
      enabledCapabilityCount: 1,
    },
  });
  const database = createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });

  try {
    database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, provider_policy_json, tool_policy_json,
        configuration_json, version, last_heartbeat_at, created_at, updated_at
      ) VALUES (?, 'reconnaissance', ?, 'available', ?, ?, ?, '2.4', ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        role = excluded.role,
        display_name = excluded.display_name,
        status = excluded.status,
        provider_policy_json = excluded.provider_policy_json,
        tool_policy_json = excluded.tool_policy_json,
        configuration_json = excluded.configuration_json,
        version = excluded.version,
        last_heartbeat_at = excluded.last_heartbeat_at,
        updated_at = excluded.updated_at
    `).run(
      agentId,
      agentName,
      JSON.stringify({ defaultProvider: providerId }),
      JSON.stringify({ allowedTools: ["nmap"], deniedTools: [], approvalRequiredTools: [] }),
      productAgentConfiguration,
      now,
      now,
      now,
    );
    if (options.preseedExpiredAttestation) {
      database.prepare(`
        INSERT INTO agent_capabilities (
          agent_id, capability, source, enabled, metadata_json
        ) VALUES (?, 'nmap', 'live-route-attestation', 1, ?)
        ON CONFLICT(agent_id, capability, source) DO UPDATE SET
          enabled = excluded.enabled,
          metadata_json = excluded.metadata_json
      `).run(agentId, JSON.stringify({
        validUntil: new Date(Date.now() - 60_000).toISOString(),
        attestedAt: new Date(Date.now() - 120_000).toISOString(),
        providerIds: ["provider-expired-regression-canary"],
        actionClassIds: [
          "active_host_discovery",
          "port_service_enumeration",
          "os_technology_fingerprinting",
        ],
      }));
    }
    database.prepare(`
      INSERT INTO agent_capabilities (
        agent_id, capability, source, enabled, metadata_json
      ) VALUES (?, 'nmap', 'live-route-attestation', 1, ?)
      ON CONFLICT(agent_id, capability, source) DO UPDATE SET
        enabled = excluded.enabled,
        metadata_json = excluded.metadata_json
    `).run(agentId, JSON.stringify(capabilityMetadata));
    const persistedCapability = database.prepare(`
      SELECT metadata_json
      FROM agent_capabilities
      WHERE agent_id = ?
        AND capability = 'nmap'
        AND source = 'live-route-attestation'
    `).get(agentId) as { readonly metadata_json: string } | undefined;
    if (
      !persistedCapability
      || persistedCapability.metadata_json !== JSON.stringify(capabilityMetadata)
    ) {
      throw new Error(
        "Mission-intake fixture did not replace the stable specialist's stale capability attestation",
      );
    }
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

const instanceId = process.argv[2];
if (!instanceId) {
  throw new Error("Mission-intake fixture backend requires one isolated test instance ID");
}
const preseedExpiredAttestation =
  process.argv.includes("--preseed-expired-attestation");
process.stdout.write(
  `TI_SCALE_MISSION_INTAKE_FIXTURE=${JSON.stringify(createMissionIntakeDynamicFixture(
    instanceId,
    { preseedExpiredAttestation },
  ))}\n`,
);

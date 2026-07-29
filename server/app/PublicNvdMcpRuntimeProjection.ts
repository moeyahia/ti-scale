import { PUBLIC_NVD_TOOL_NAME } from "../mcp-public-nvd";
import {
  PUBLIC_NVD_MCP_CONNECTION_ID,
  type PublicNvdMcpRuntimeSnapshot,
} from "../mcp";
import {
  emptyRuntimeSourceManifests,
  type RuntimeSourceManifests,
} from "../domain";
import type {
  McpServerProjection,
  McpServerStatus,
  RuntimeProjectionInput,
} from "./RuntimeProjectionService";

const ACTION_CLASS_ID = "cve_intelligence_applicability_validation";
const CAPABILITY_ID = "public-nvd-cve-detail";
const TOOL_ID = `mcp:${PUBLIC_NVD_MCP_CONNECTION_ID}/${PUBLIC_NVD_TOOL_NAME}`;

function serverStatus(status: PublicNvdMcpRuntimeSnapshot["status"]): McpServerStatus {
  if (status === "ready") return "healthy";
  if (status === "degraded") return "degraded";
  if (status === "probing") return "unknown";
  return "offline";
}

const STABLE_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;

function stableId(value: string, kind: string): string {
  if (value !== value.trim() || !STABLE_ID.test(value)) {
    throw new Error(`${kind} has an invalid stable ID: ${JSON.stringify(value)}`);
  }
  return value;
}

function assertUniqueStableIds<T extends { readonly id: string }>(
  kind: string,
  records: readonly T[],
): void {
  const seen = new Set<string>();
  for (const record of records) {
    const id = stableId(record.id, kind);
    if (seen.has(id)) throw new Error(`${kind} stable ID collision: ${id}`);
    seen.add(id);
  }
}

function mergeByStableId<T extends { readonly id: string }>(
  kind: string,
  existing: readonly T[],
  additions: readonly T[],
): readonly T[] {
  assertUniqueStableIds(kind, existing);
  assertUniqueStableIds(kind, additions);
  const existingIds = new Set(existing.map(({ id }) => id));
  for (const addition of additions) {
    if (existingIds.has(addition.id)) {
      throw new Error(`${kind} stable ID collision: ${addition.id}`);
    }
  }
  return [...existing, ...additions];
}

function publicNvdManifests(
  state: PublicNvdMcpRuntimeSnapshot,
  missionReadAdapterAvailable: boolean,
): RuntimeSourceManifests {
  const ready = state.status === "ready" && state.attested
    && state.toolNames.length === 1
    && state.toolNames[0] === PUBLIC_NVD_TOOL_NAME;
  const callableForMissionRead = ready && missionReadAdapterAvailable;
  return {
    riskClasses: ready ? [{
      id: "read-only",
      label: "Read-only public intelligence",
      actionClassIds: [ACTION_CLASS_ID],
    }] : [],
    evidenceKinds: [],
    capabilities: ready ? [{
      id: CAPABILITY_ID,
      label: "Official public NVD CVE detail",
      actionClassIds: [ACTION_CLASS_ID],
    }] : [],
    tools: ready ? [{
      id: TOOL_ID,
      label: "Fetch official public NVD CVE detail",
      // Availability means only the reviewed mission-scoped public-read
      // adapter is callable. It does not grant target or run execution.
      available: callableForMissionRead,
      locallyPolicyEnforced: true,
      requiresModel: false,
      // This mission-scoped public-read adapter is inspectable by Guided and
      // intelligence surfaces; it is not mounted in the Autonomous executor.
      executionJourneys: ["guided"],
      actionClassIds: [ACTION_CLASS_ID],
      // A public NVD record supports analysis but is not verified target
      // applicability evidence by itself.
      evidenceTypeIds: [],
      riskClassIds: ["read-only"],
      mcpServerId: PUBLIC_NVD_MCP_CONNECTION_ID,
      dependencies: [
        { id: "exact-live-attestation", ready: true },
        { id: "mission-scoped-read-adapter", ready: missionReadAdapterAvailable },
      ],
    }] : [],
    mcpServers: [{
      id: PUBLIC_NVD_MCP_CONNECTION_ID,
      label: "Official public NVD intelligence",
      status: ready
        ? "healthy"
        : state.status === "degraded" || state.status === "probing"
          ? "degraded"
          : "offline",
      toolIds: ready ? [TOOL_ID] : [],
    }],
    // No specialist or provider is fabricated by this dependency monitor.
    agents: [],
    providers: [],
  };
}

function mergeManifests(
  existing: RuntimeSourceManifests,
  additions: RuntimeSourceManifests,
): RuntimeSourceManifests {
  for (const provider of existing.providers) {
    assertUniqueStableIds(`runtime provider ${provider.id} model`, provider.models);
  }
  for (const provider of additions.providers) {
    assertUniqueStableIds(`runtime provider ${provider.id} model`, provider.models);
  }
  return {
    riskClasses: mergeByStableId("runtime risk class", existing.riskClasses, additions.riskClasses),
    evidenceKinds: mergeByStableId("runtime evidence kind", existing.evidenceKinds, additions.evidenceKinds),
    capabilities: mergeByStableId("runtime capability", existing.capabilities, additions.capabilities),
    tools: mergeByStableId("runtime tool", existing.tools, additions.tools),
    mcpServers: mergeByStableId("runtime MCP manifest", existing.mcpServers, additions.mcpServers),
    agents: mergeByStableId("runtime agent manifest", existing.agents, additions.agents),
    providers: mergeByStableId("runtime provider manifest", existing.providers, additions.providers),
  };
}

function mcpServer(
  state: PublicNvdMcpRuntimeSnapshot,
  missionReadAdapterAvailable: boolean,
): McpServerProjection {
  const ready = state.status === "ready" && state.attested;
  return {
    id: PUBLIC_NVD_MCP_CONNECTION_ID,
    name: "Official public NVD intelligence",
    transport: "streamable-http",
    endpointRedacted: "loopback://public-nvd-mcp",
    status: serverStatus(state.status),
    // Runtime and manifest inventories use the same fully-qualified stable ID.
    // A bare tool name can collide across MCP servers and is never accepted.
    capabilities: ready ? [TOOL_ID] : [],
    policy: {
      executionAuthorization: "none",
      autonomousExecution: false,
      guidedExecution: false,
      targetInteraction: false,
      readOnly: true,
      exactInventoryRequired: true,
      missionScopedReadAdapter: missionReadAdapterAvailable,
      credentialSource: "systemd-load-credential",
      attested: state.attested,
      attestedAt: state.attestedAt ?? null,
      expiresAt: state.expiresAt ?? null,
      manifestSha256: state.manifestSha256 ?? null,
      reason: state.reason,
    },
    lastCheckedAt: state.lastCheckedAt ?? null,
  };
}

/**
 * Adds truthful NVD dependency/capability state without converting that
 * state into generic MCP execution readiness or Autonomous authorization.
 */
export function projectPublicNvdMcpRuntime(
  baseline: RuntimeProjectionInput,
  state: PublicNvdMcpRuntimeSnapshot,
  options: Readonly<{ missionReadAdapterAvailable?: boolean }> = {},
): RuntimeProjectionInput {
  assertUniqueStableIds("runtime readiness provider", baseline.readiness.providers);
  assertUniqueStableIds("runtime fleet agent", baseline.agents);
  const probing = state.status === "probing" ? 1 : 0;
  const missingSecret = state.credentialMounted ? 0 : 1;
  const missingDependency = state.credentialMounted
    && state.status !== "ready"
    && state.status !== "probing"
    ? 1
    : 0;
  return {
    readiness: {
      ...baseline.readiness,
      // The sidecar's discovery state never grants execution readiness.
      mcp: {
        ...baseline.readiness.mcp,
        configuredServers: baseline.readiness.mcp.configuredServers + 1,
        probingServers: (baseline.readiness.mcp.probingServers ?? 0) + probing,
        missingSecrets: baseline.readiness.mcp.missingSecrets + missingSecret,
        missingDependencies: baseline.readiness.mcp.missingDependencies + missingDependency,
      },
      publicNvd: {
        status: state.status,
        credentialMounted: state.credentialMounted,
        attested: state.attested,
        ...(state.lastCheckedAt ? { lastCheckedAt: state.lastCheckedAt } : {}),
        ...(state.attestedAt ? { attestedAt: state.attestedAt } : {}),
        ...(state.expiresAt ? { expiresAt: state.expiresAt } : {}),
        reason: state.reason,
      },
    },
    agents: [...baseline.agents],
    mcpServers: mergeByStableId(
      "runtime MCP server",
      baseline.mcpServers,
      [mcpServer(state, options.missionReadAdapterAvailable === true)],
    ),
    capabilityManifests: mergeManifests(
      baseline.capabilityManifests ?? emptyRuntimeSourceManifests(),
      publicNvdManifests(state, options.missionReadAdapterAvailable === true),
    ),
  };
}

import { describe, expect, test } from "bun:test";
import { buildRuntimeCapabilityProjection } from "../../domain";
import type { PublicNvdMcpRuntimeSnapshot } from "../../mcp";
import { projectPublicNvdMcpRuntime } from "../PublicNvdMcpRuntimeProjection";
import type { RuntimeProjectionInput } from "../RuntimeProjectionService";

function baseline(): RuntimeProjectionInput {
  return {
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
      configuredServers: 0,
      runnableServers: 0,
      missingDependencies: 0,
      missingSecrets: 0,
    },
    eventStream: "healthy",
    secondBrain: "unknown",
    legacyExecutionEnabled: false,
    },
    agents: [],
    mcpServers: [],
    capabilityManifests: {
      riskClasses: [],
      evidenceKinds: [],
      capabilities: [],
      tools: [],
      mcpServers: [],
      agents: [],
      providers: [],
    },
  };
}

function state(status: PublicNvdMcpRuntimeSnapshot["status"]): PublicNvdMcpRuntimeSnapshot {
  const ready = status === "ready";
  return {
    status,
    credentialMounted: status !== "unavailable" && status !== "stopped",
    attested: ready,
    toolNames: ready ? ["get_cve_details"] : [],
    lastCheckedAt: "2026-07-18T18:00:05.000Z",
    ...(ready ? {
      attestedAt: "2026-07-18T18:00:00.000Z",
      expiresAt: "2026-07-18T18:01:00.000Z",
      manifestSha256: "a".repeat(64),
    } : {}),
    reason: `${status} fixture`,
  };
}

describe("public NVD production projection", () => {
  test("projects exact ready capability without inventing execution, Autonomous readiness, an agent, or a heartbeat", () => {
    const projection = projectPublicNvdMcpRuntime(baseline(), state("ready"));
    expect(projection.readiness).toMatchObject({
      actionBoundaryActive: false,
      specialistsConfigured: 0,
      providers: [],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 1,
        runnableServers: 0,
      },
      publicNvd: { status: "ready", attested: true },
    });
    expect(projection.agents).toEqual([]);
    expect(projection.mcpServers).toEqual([expect.objectContaining({
      status: "healthy",
      capabilities: ["mcp:public-nvd/get_cve_details"],
      lastCheckedAt: "2026-07-18T18:00:05.000Z",
      policy: expect.objectContaining({
        executionAuthorization: "none",
        autonomousExecution: false,
        guidedExecution: false,
      }),
    })]);
    expect(projection.capabilityManifests?.agents).toEqual([]);
    expect(projection.capabilityManifests?.providers).toEqual([]);
    expect(projection.capabilityManifests?.tools).toHaveLength(1);
    const registry = buildRuntimeCapabilityProjection(projection.capabilityManifests!);
    expect(registry.actionClasses.cve_intelligence_applicability_validation).toMatchObject({
      availability: "unsupported",
      agentIds: [],
      availableAgentIds: [],
      toolIds: ["mcp:public-nvd/get_cve_details"],
      availableToolIds: [],
      enforcementReady: false,
    });
  });

  test("marks only the mission-scoped public-read tool callable without claiming Autonomous enforcement", () => {
    const projection = projectPublicNvdMcpRuntime(
      baseline(),
      state("ready"),
      { missionReadAdapterAvailable: true },
    );
    expect(projection.readiness).toMatchObject({
      actionBoundaryActive: false,
      specialistsConfigured: 0,
      mcp: {
        enabled: false,
        executionMode: "disabled",
        runnableServers: 0,
      },
    });
    expect(projection.mcpServers[0]?.policy).toMatchObject({
      executionAuthorization: "none",
      autonomousExecution: false,
      guidedExecution: false,
      targetInteraction: false,
      missionScopedReadAdapter: true,
    });
    const tool = projection.capabilityManifests?.tools[0];
    expect(tool).toMatchObject({
      id: "mcp:public-nvd/get_cve_details",
      available: true,
      requiresModel: false,
      locallyPolicyEnforced: true,
      executionJourneys: ["guided"],
      dependencies: [
        { id: "exact-live-attestation", ready: true },
        { id: "mission-scoped-read-adapter", ready: true },
      ],
    });
    const registry = buildRuntimeCapabilityProjection(projection.capabilityManifests!);
    expect(registry.actionClasses.cve_intelligence_applicability_validation).toMatchObject({
      availability: "unsupported",
      agentIds: [],
      availableToolIds: ["mcp:public-nvd/get_cve_details"],
      locallyEnforcedToolIds: [],
      enforcementReady: false,
      readinessReasons: ["No agent declares this action class."],
    });
  });

  test.each(["unavailable", "degraded", "probing"] as const)(
    "withdraws tools and reports %s truthfully",
    (status) => {
      const projection = projectPublicNvdMcpRuntime(baseline(), state(status));
      expect(projection.readiness.mcp.runnableServers).toBe(0);
      expect(projection.readiness.publicNvd?.status).toBe(status);
      expect(projection.mcpServers[0]?.capabilities).toEqual([]);
      expect(projection.capabilityManifests?.tools).toEqual([]);
      expect(projection.capabilityManifests?.agents).toEqual([]);
    },
  );

  test("preserves every existing readiness, fleet, MCP, and manifest registry entry", () => {
    const existing: RuntimeProjectionInput = {
      ...baseline(),
      readiness: {
        ...baseline().readiness,
        specialistsConfigured: 1,
        providers: [{
          id: "existing-provider",
          health: "healthy",
          authenticated: true,
          callable: true,
          supportsGuided: true,
          enforcesAutonomousBoundary: true,
          reportsExactTokenUsage: true,
          reportsExactCostUsage: true,
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
      },
      agents: [{
        id: "existing-agent",
        role: "reconnaissance",
        displayName: "Existing Agent",
        status: "available",
        providerPolicy: { providerId: "existing-provider" },
        toolPolicy: { toolIds: ["existing-tool"] },
        configuration: { source: "attested-runtime" },
        version: "2.4",
        capabilities: [{ name: "existing-capability", source: "live-route-attestation", enabled: true }],
      }],
      mcpServers: [{
        id: "existing-mcp",
        name: "Existing MCP",
        transport: "stdio",
        status: "healthy",
        capabilities: ["existing-tool"],
        policy: { assignedAgents: ["existing-agent"] },
        lastCheckedAt: "2026-07-18T17:59:00.000Z",
      }],
      capabilityManifests: {
        riskClasses: [{
          id: "existing-risk",
          label: "Existing risk",
          actionClassIds: ["active_host_discovery"],
        }],
        evidenceKinds: [],
        capabilities: [{
          id: "existing-capability",
          label: "Existing capability",
          actionClassIds: ["active_host_discovery"],
        }],
        tools: [{
          id: "existing-tool",
          label: "Existing tool",
          available: true,
          locallyPolicyEnforced: true,
          actionClassIds: ["active_host_discovery"],
          evidenceTypeIds: ["asset_discovery_proof"],
          riskClassIds: ["existing-risk"],
          mcpServerId: "existing-mcp",
        }],
        mcpServers: [{
          id: "existing-mcp",
          label: "Existing MCP",
          status: "healthy",
          toolIds: ["existing-tool"],
        }],
        agents: [{
          id: "existing-agent",
          label: "Existing Agent",
          available: true,
          capabilityIds: ["existing-capability"],
          toolIds: ["existing-tool"],
          modelRefs: [{ providerId: "existing-provider", modelId: "existing-model" }],
        }],
        providers: [{
          id: "existing-provider",
          authenticated: true,
          healthy: true,
          catalogObservedAt: "2026-07-18T17:59:00.000Z",
          models: [{
            id: "existing-model",
            displayName: "Existing Model",
            toolCalling: true,
            structuredOutput: true,
            enforcement: "enforced_executor",
            compatibleActionClassIds: ["active_host_discovery"],
            disclosureClasses: ["public"],
          }],
        }],
      },
    };

    const projection = projectPublicNvdMcpRuntime(existing, state("ready"));
    expect(projection.readiness.providers).toEqual(existing.readiness.providers);
    expect(projection.readiness.specialistsConfigured).toBe(1);
    expect(projection.readiness.mcp).toMatchObject({
      configuredServers: 2,
      runnableServers: 1,
      enabled: true,
      executionMode: "enabled",
    });
    expect(projection.agents).toEqual(existing.agents);
    expect(projection.mcpServers.map(({ id }) => id)).toEqual(["existing-mcp", "public-nvd"]);
    expect(projection.capabilityManifests?.agents).toEqual(existing.capabilityManifests?.agents);
    expect(projection.capabilityManifests?.providers).toEqual(existing.capabilityManifests?.providers);
    expect(projection.capabilityManifests?.tools.map(({ id }) => id)).toEqual([
      "existing-tool",
      "mcp:public-nvd/get_cve_details",
    ]);
    expect(() => buildRuntimeCapabilityProjection(projection.capabilityManifests!)).not.toThrow();
  });

  test("rejects a stable-ID collision instead of overwriting an existing runtime MCP server", () => {
    const existing: RuntimeProjectionInput = {
      ...baseline(),
      mcpServers: [{
        id: "public-nvd",
        name: "Conflicting server",
        transport: "stdio",
        status: "healthy",
        capabilities: ["different-tool"],
        policy: {},
      }],
    };
    expect(() => projectPublicNvdMcpRuntime(existing, state("ready")))
      .toThrow("runtime MCP server stable ID collision: public-nvd");
  });
});

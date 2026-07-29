import { describe, expect, test } from "bun:test";
import type { OpenRouterReadinessRuntimeSnapshot } from "../../providers/openrouter";
import {
  COMMANDER_AGENT_ID,
  PRODUCT_AGENT_REGISTRY,
} from "../../agents";
import {
  OPENROUTER_RUNTIME_PROVIDER_ID,
  projectOpenRouterRuntime,
} from "../OpenRouterRuntimeProjection";
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
  };
}

function snapshot(callable: boolean): OpenRouterReadinessRuntimeSnapshot {
  return {
    status: callable ? "ready" : "degraded",
    configured: true,
    authenticated: true,
    callable,
    supportsGuided: callable,
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: callable,
    reportsExactCostUsage: callable,
    requestedModel: "openai/gpt-5.2",
    ...(callable ? { returnedModel: "openai/gpt-5.2-20260718" } : {}),
    modelConfigurationHash: "a".repeat(64),
    contextLength: 400_000,
    ...(callable ? { completionProbeReceiptId: "provider-request-readiness" } : {}),
    lastCheckedAt: "2026-07-18T19:00:01.000Z",
    attestedAt: "2026-07-18T19:00:00.000Z",
    expiresAt: "2026-07-18T19:05:00.000Z",
    reason: callable ? "Audited fixture." : "Metadata-only fixture.",
  };
}

describe("OpenRouter runtime projection", () => {
  test("keeps a disabled runtime row matched to an empty fail-closed provider manifest", () => {
    const projection = projectOpenRouterRuntime(baseline(), {
      status: "disabled",
      configured: false,
      authenticated: false,
      callable: false,
      supportsGuided: false,
      enforcesAutonomousBoundary: false,
      reportsExactTokenUsage: false,
      reportsExactCostUsage: false,
      lastCheckedAt: "2026-07-18T18:59:00.000Z",
      reason: "No service-owned OpenRouter credential file is configured.",
    });

    expect(projection.readiness.providers).toEqual([expect.objectContaining({
      id: "openrouter",
      health: "unknown",
      configured: false,
      authenticated: false,
      callable: false,
    })]);
    expect(projection.capabilityManifests?.providers).toEqual([{
      id: "openrouter",
      authenticated: false,
      healthy: false,
      catalogObservedAt: "2026-07-18T18:59:00.000Z",
      models: [],
    }]);
    expect(projection.readiness.providers.map(({ id }) => id))
      .toEqual(projection.capabilityManifests!.providers.map(({ id }) => id));
  });

  test("projects metadata truth without overclaiming Guided callability or Autonomous enforcement", () => {
    const projection = projectOpenRouterRuntime(baseline(), snapshot(false));
    expect(projection.readiness.providers).toEqual([expect.objectContaining({
      id: OPENROUTER_RUNTIME_PROVIDER_ID,
      health: "degraded",
      configured: true,
      authenticated: true,
      callable: false,
      supportsGuided: false,
      enforcesAutonomousBoundary: false,
      requestedModel: "openai/gpt-5.2",
      modelConfigurationHash: "a".repeat(64),
    })]);
    expect(projection.agents).toEqual([]);
    expect(projection.capabilityManifests?.agents.map(({ id }) => id)).toEqual([
      COMMANDER_AGENT_ID,
      ...PRODUCT_AGENT_REGISTRY.map(({ id }) => id),
    ]);
    expect(projection.capabilityManifests?.agents.every((agent) =>
      agent.available === false
      && agent.capabilityIds.length === 0
      && agent.toolIds.length === 0
      && agent.modelRefs.some(({ providerId, modelId }) =>
        providerId === "openrouter" && modelId === "openai/gpt-5.2")))
      .toBe(true);
    expect(projection.capabilityManifests?.providers).toEqual([expect.objectContaining({
      id: "openrouter",
      authenticated: true,
      healthy: false,
      models: [expect.objectContaining({
        id: "openai/gpt-5.2",
        toolCalling: false,
        structuredOutput: true,
        enforcement: "advisor_only",
        disclosureClasses: ["public"],
      })],
    })]);
  });

  test("projects exact returned model and durable receipt only after audited callability", () => {
    const projection = projectOpenRouterRuntime(baseline(), snapshot(true));
    expect(projection.readiness.providers[0]).toMatchObject({
      health: "healthy",
      callable: true,
      supportsGuided: true,
      enforcesAutonomousBoundary: false,
      requestedModel: "openai/gpt-5.2",
      returnedModel: "openai/gpt-5.2-20260718",
      completionProbeReceiptId: "provider-request-readiness",
      reportsExactTokenUsage: true,
      reportsExactCostUsage: true,
    });
    expect(projection.capabilityManifests?.providers[0]?.healthy).toBe(true);
  });

  test("declares attested advisor compatibility for every canonical specialist without changing execution authority", () => {
    const existing = baseline();
    const projection = projectOpenRouterRuntime({
      ...existing,
      capabilityManifests: {
        riskClasses: [],
        evidenceKinds: [],
        capabilities: [],
        tools: [],
        mcpServers: [],
        providers: [],
        agents: [{
          id: "ReconScout",
          label: "ReconScout",
          available: true,
          capabilityIds: ["recon"],
          actionClassIds: ["active_host_discovery"],
          toolIds: ["reviewed-nmap"],
          modelRefs: [],
        }],
      },
    }, snapshot(true));

    const agents = projection.capabilityManifests!.agents;
    expect(agents.filter(({ id }) => id === "ReconScout")).toHaveLength(1);
    expect(agents.find(({ id }) => id === "ReconScout")).toMatchObject({
      available: true,
      capabilityIds: ["recon"],
      actionClassIds: ["active_host_discovery"],
      toolIds: ["reviewed-nmap"],
      modelRefs: [{
        providerId: "openrouter",
        modelId: "openai/gpt-5.2",
      }],
    });
    for (const specialist of PRODUCT_AGENT_REGISTRY) {
      expect(agents.find(({ id }) => id === specialist.id)?.modelRefs)
        .toContainEqual({
          providerId: "openrouter",
          modelId: "openai/gpt-5.2",
        });
    }
    expect(projection.capabilityManifests!.providers[0]!.models[0])
      .toMatchObject({
        enforcement: "advisor_only",
        toolCalling: false,
        compatibleActionClassIds: [],
      });
  });

  test("rejects readiness and manifest stable-ID collisions", () => {
    const existing = baseline();
    expect(() => projectOpenRouterRuntime({
      ...existing,
      readiness: {
        ...existing.readiness,
        providers: [{
          id: "openrouter",
          health: "healthy",
          authenticated: true,
          callable: true,
          supportsGuided: true,
          enforcesAutonomousBoundary: false,
          reportsExactTokenUsage: true,
          reportsExactCostUsage: true,
        }],
      },
    }, snapshot(true))).toThrow("runtime readiness provider stable ID collision");
  });

  test("rejects a Commander manifest that carries specialist execution authority", () => {
    const existing = baseline();
    expect(() => projectOpenRouterRuntime({
      ...existing,
      capabilityManifests: {
        riskClasses: [],
        evidenceKinds: [],
        capabilities: [],
        tools: [],
        mcpServers: [],
        providers: [],
        agents: [{
          id: "Commander",
          label: "Commander",
          available: true,
          capabilityIds: ["specialist-execution"],
          actionClassIds: ["active_host_discovery"],
          toolIds: ["nmap"],
          modelRefs: [],
        }],
      },
    }, snapshot(true))).toThrow(
      "Commander manifest collides with executable specialist authority",
    );
  });

  test("rejects a runtime row that cannot be tied to a real registry observation", () => {
    expect(() => projectOpenRouterRuntime(baseline(), {
      status: "disabled",
      configured: false,
      authenticated: false,
      callable: false,
      supportsGuided: false,
      enforcesAutonomousBoundary: false,
      reportsExactTokenUsage: false,
      reportsExactCostUsage: false,
      reason: "Unobserved fixture.",
    })).toThrow("runtime registry observation time is missing or invalid");
  });
});

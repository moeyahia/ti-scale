import type { RuntimeProviderManifest } from "../domain";
import { PRODUCT_AGENT_REGISTRY } from "../agents";
import type { OpenRouterReadinessRuntimeSnapshot } from "../providers/openrouter";
import type { ProviderReadiness } from "./RuntimeReadiness";
import type { RuntimeProjectionInput } from "./RuntimeProjectionService";

export const OPENROUTER_RUNTIME_PROVIDER_ID = "openrouter";

function providerReadiness(state: OpenRouterReadinessRuntimeSnapshot): ProviderReadiness {
  return {
    id: OPENROUTER_RUNTIME_PROVIDER_ID,
    health: state.status === "ready"
      ? "healthy"
      : state.status === "blocked"
        ? "unhealthy"
        : state.status === "disabled" || state.status === "stopped"
          ? "unknown"
          : "degraded",
    configured: state.configured,
    authenticated: state.authenticated,
    callable: state.callable,
    ...(state.attestedAt ? { attestedAt: state.attestedAt } : {}),
    ...(state.expiresAt ? { expiresAt: state.expiresAt } : {}),
    circuitState: state.status === "ready"
      ? "closed"
      : state.status === "probing"
        ? "probing"
        : "open",
    supportsGuided: state.supportsGuided,
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: state.reportsExactTokenUsage,
    reportsExactCostUsage: state.reportsExactCostUsage,
    ...(state.requestedModel ? { requestedModel: state.requestedModel } : {}),
    ...(state.returnedModel ? { returnedModel: state.returnedModel } : {}),
    ...(state.modelConfigurationHash
      ? { modelConfigurationHash: state.modelConfigurationHash }
      : {}),
    ...(state.completionProbeReceiptId
      ? { completionProbeReceiptId: state.completionProbeReceiptId }
      : {}),
    reason: state.reason,
  };
}

function providerManifest(
  state: OpenRouterReadinessRuntimeSnapshot,
): RuntimeProviderManifest {
  const observedAt = state.attestedAt ?? state.lastCheckedAt;
  if (!observedAt || !Number.isFinite(Date.parse(observedAt))) {
    throw new Error("OpenRouter runtime registry observation time is missing or invalid");
  }
  const attestedModel = state.requestedModel && state.attestedAt && state.contextLength
    ? [{
        id: state.requestedModel,
        displayName: state.requestedModel,
        // Ti-Scale's public-provider planning boundary always sends tools: [].
        toolCalling: false,
        structuredOutput: true,
        enforcement: "advisor_only" as const,
        compatibleActionClassIds: [],
        disclosureClasses: ["public"],
        contextLimit: state.contextLength,
      }]
    : [];
  return {
    id: OPENROUTER_RUNTIME_PROVIDER_ID,
    authenticated: state.authenticated,
    // Metadata-only authentication is useful diagnostic truth but is not a
    // healthy provider route until the durable completion receipt exists.
    healthy: state.status === "ready" && state.callable,
    // Before a live catalog/model attestation this is only the local registry
    // observation time and models remains empty. The projection therefore
    // keeps stable IDs reconcilable without inventing model capability.
    catalogObservedAt: observedAt,
    models: attestedModel,
  };
}

function planningAgentManifests(
  baseline: RuntimeProjectionInput,
  state: OpenRouterReadinessRuntimeSnapshot,
) {
  const agents = [...(baseline.capabilityManifests?.agents ?? [])];
  if (!state.requestedModel || !state.attestedAt || !state.contextLength) return agents;
  const modelRef = {
    providerId: OPENROUTER_RUNTIME_PROVIDER_ID,
    modelId: state.requestedModel,
  } as const;
  for (const product of PRODUCT_AGENT_REGISTRY) {
    const actionClassIds = product.capabilities.flatMap(({ actionClassIds }) => actionClassIds);
    const index = agents.findIndex(({ id }) => id === product.id);
    if (index >= 0) {
      const current = agents[index]!;
      const alreadyBound = current.modelRefs.some(
        (reference) =>
          reference.providerId === modelRef.providerId
          && reference.modelId === modelRef.modelId,
      );
      agents[index] = {
        ...current,
        actionClassIds: [...new Set([
          ...(current.actionClassIds ?? []),
          ...actionClassIds,
        ])],
        modelRefs: alreadyBound ? current.modelRefs : [...current.modelRefs, modelRef],
      };
      continue;
    }
    // This is a provider-planning definition only. It deliberately remains
    // unavailable as an execution agent and has no tool or capability grant.
    agents.push({
      id: product.id,
      label: product.displayName,
      available: false,
      capabilityIds: [],
      actionClassIds,
      toolIds: [],
      ...(product.deliverableIds ? { deliverableIds: product.deliverableIds } : {}),
      modelRefs: [modelRef],
    });
  }
  return agents;
}

/**
 * Adds one truthfully attested public-provider route. This projection cannot
 * create an agent, grant tool use, or make OpenRouter an Autonomous executor.
 */
export function projectOpenRouterRuntime(
  baseline: RuntimeProjectionInput,
  state: OpenRouterReadinessRuntimeSnapshot,
): RuntimeProjectionInput {
  if (baseline.readiness.providers.some(({ id }) => id === OPENROUTER_RUNTIME_PROVIDER_ID)) {
    throw new Error(`runtime readiness provider stable ID collision: ${OPENROUTER_RUNTIME_PROVIDER_ID}`);
  }
  if (baseline.capabilityManifests?.providers.some(
    ({ id }) => id === OPENROUTER_RUNTIME_PROVIDER_ID,
  )) {
    throw new Error(`runtime provider manifest stable ID collision: ${OPENROUTER_RUNTIME_PROVIDER_ID}`);
  }
  const manifest = providerManifest(state);
  return {
    ...baseline,
    readiness: {
      ...baseline.readiness,
      providers: [...baseline.readiness.providers, providerReadiness(state)],
    },
    capabilityManifests: {
          riskClasses: baseline.capabilityManifests?.riskClasses ?? [],
          evidenceKinds: baseline.capabilityManifests?.evidenceKinds ?? [],
          capabilities: baseline.capabilityManifests?.capabilities ?? [],
          tools: baseline.capabilityManifests?.tools ?? [],
          mcpServers: baseline.capabilityManifests?.mcpServers ?? [],
          agents: planningAgentManifests(baseline, state),
          providers: [
            ...(baseline.capabilityManifests?.providers ?? []),
            manifest,
          ],
        },
  };
}

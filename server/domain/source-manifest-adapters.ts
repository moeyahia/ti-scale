import {
  ACTION_CLASS_IDS,
  DELIVERABLE_IDS,
  EVIDENCE_TYPE_IDS,
  isActionClassId,
  isDeliverableId,
  isEvidenceTypeId,
  type ActionClassId,
  type DeliverableId,
  type EvidenceTypeId,
} from "./catalog-ids";
import type { ModelEnforcementState, ProviderModelCapability } from "./model-readiness";

export type CapabilityAvailability = "supported" | "unavailable" | "unsupported";

export interface RuntimeRiskClassManifest {
  readonly id: string;
  readonly label: string;
  readonly actionClassIds: readonly string[];
}

export interface RuntimeEvidenceKindManifest {
  readonly id: string;
  readonly label: string;
  readonly evidenceTypeIds: readonly string[];
}

export interface RuntimeCapabilityManifest {
  readonly id: string;
  readonly label: string;
  readonly actionClassIds: readonly string[];
  readonly evidenceTypeIds?: readonly string[];
  readonly deliverableIds?: readonly string[];
}

export interface RuntimeToolManifest {
  readonly id: string;
  readonly label: string;
  readonly available: boolean;
  readonly locallyPolicyEnforced: boolean;
  readonly requiresModel?: boolean;
  readonly actionClassIds: readonly string[];
  readonly evidenceTypeIds: readonly string[];
  readonly deliverableIds?: readonly string[];
  readonly riskClassIds: readonly string[];
  readonly mcpServerId?: string;
  readonly dependencies?: readonly {
    readonly id: string;
    readonly ready: boolean;
  }[];
}

export interface RuntimeMcpServerManifest {
  readonly id: string;
  readonly label: string;
  readonly status: "healthy" | "degraded" | "offline" | "unconfigured";
  readonly toolIds: readonly string[];
}

export interface RuntimeAgentManifest {
  readonly id: string;
  readonly label: string;
  readonly available: boolean;
  readonly capabilityIds: readonly string[];
  readonly actionClassIds?: readonly string[];
  readonly toolIds: readonly string[];
  readonly deliverableIds?: readonly string[];
  readonly modelRefs: readonly {
    readonly providerId: string;
    readonly modelId: string;
  }[];
}

export interface RuntimeProviderModelManifest {
  readonly id: string;
  readonly displayName: string;
  readonly toolCalling: boolean;
  readonly structuredOutput: boolean;
  readonly enforcement: Exclude<ModelEnforcementState, "unavailable">;
  readonly compatibleActionClassIds: readonly string[];
  readonly disclosureClasses: readonly string[];
  readonly contextLimit?: number;
  readonly reasoningEfforts?: readonly string[];
}

export interface RuntimeProviderManifest {
  readonly id: string;
  readonly authenticated: boolean;
  readonly healthy: boolean;
  readonly catalogObservedAt: string;
  readonly models: readonly RuntimeProviderModelManifest[];
}

export interface RuntimeSourceManifests {
  readonly riskClasses: readonly RuntimeRiskClassManifest[];
  readonly evidenceKinds: readonly RuntimeEvidenceKindManifest[];
  readonly capabilities: readonly RuntimeCapabilityManifest[];
  readonly tools: readonly RuntimeToolManifest[];
  readonly mcpServers: readonly RuntimeMcpServerManifest[];
  readonly agents: readonly RuntimeAgentManifest[];
  readonly providers: readonly RuntimeProviderManifest[];
}

/**
 * Fail-closed source used by the isolated preview until the live runtime has
 * supplied an attested capability manifest. Static registry definitions still
 * remain inspectable, but every operational capability resolves unsupported.
 */
export function emptyRuntimeSourceManifests(): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: [],
    mcpServers: [],
    agents: [],
    providers: [],
  };
}

export interface ActionCapabilityMapping {
  readonly actionClassId: ActionClassId;
  readonly availability: CapabilityAvailability;
  readonly riskClassIds: readonly string[];
  readonly agentIds: readonly string[];
  readonly availableAgentIds: readonly string[];
  readonly toolIds: readonly string[];
  readonly availableToolIds: readonly string[];
  readonly mcpServerIds: readonly string[];
  readonly providerModelRefs: readonly string[];
  readonly enforcedProviderModelRefs: readonly string[];
  readonly locallyEnforcedToolIds: readonly string[];
  readonly evidenceTypeIds: readonly EvidenceTypeId[];
  readonly enforcementReady: boolean;
  readonly readinessReasons: readonly string[];
}

export interface EvidenceCapabilityMapping {
  readonly evidenceTypeId: EvidenceTypeId;
  readonly runtimeEvidenceKindIds: readonly string[];
  readonly producerToolIds: readonly string[];
  readonly availability: CapabilityAvailability;
}

export interface DeliverableCapabilityMapping {
  readonly deliverableId: DeliverableId;
  readonly producerAgentIds: readonly string[];
  readonly producerToolIds: readonly string[];
  readonly availability: CapabilityAvailability;
}

export interface RuntimeCapabilityProjection {
  readonly actionClasses: Readonly<Record<ActionClassId, ActionCapabilityMapping>>;
  readonly evidenceTypes: Readonly<Record<EvidenceTypeId, EvidenceCapabilityMapping>>;
  readonly deliverables: Readonly<Record<DeliverableId, DeliverableCapabilityMapping>>;
  readonly models: readonly ProviderModelCapability[];
  readonly sourceCounts: {
    readonly riskClasses: number;
    readonly evidenceKinds: number;
    readonly capabilities: number;
    readonly tools: number;
    readonly mcpServers: number;
    readonly agents: number;
    readonly providers: number;
    readonly models: number;
  };
}

function sorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function assertUniqueIds<T extends { readonly id: string }>(
  kind: string,
  records: readonly T[],
): void {
  const seen = new Set<string>();
  for (const record of records) {
    if (record.id.trim().length === 0) {
      throw new Error(`${kind} manifest contains an empty id.`);
    }
    if (seen.has(record.id)) {
      throw new Error(`${kind} manifest contains duplicate id ${record.id}.`);
    }
    seen.add(record.id);
  }
}

function validateCatalogReferences(manifests: RuntimeSourceManifests): void {
  const unknown: string[] = [];
  const checkActionClasses = (owner: string, values: readonly string[]): void => {
    for (const value of values) {
      if (!isActionClassId(value)) unknown.push(`${owner}.actionClassIds:${value}`);
    }
  };
  const checkEvidenceTypes = (owner: string, values: readonly string[]): void => {
    for (const value of values) {
      if (!isEvidenceTypeId(value)) unknown.push(`${owner}.evidenceTypeIds:${value}`);
    }
  };
  const checkDeliverables = (owner: string, values: readonly string[]): void => {
    for (const value of values) {
      if (!isDeliverableId(value)) unknown.push(`${owner}.deliverableIds:${value}`);
    }
  };

  for (const risk of manifests.riskClasses) {
    checkActionClasses(`risk:${risk.id}`, risk.actionClassIds);
  }
  for (const evidence of manifests.evidenceKinds) {
    checkEvidenceTypes(`evidence-kind:${evidence.id}`, evidence.evidenceTypeIds);
  }
  for (const capability of manifests.capabilities) {
    checkActionClasses(`capability:${capability.id}`, capability.actionClassIds);
    checkEvidenceTypes(`capability:${capability.id}`, capability.evidenceTypeIds ?? []);
    checkDeliverables(`capability:${capability.id}`, capability.deliverableIds ?? []);
  }
  for (const tool of manifests.tools) {
    checkActionClasses(`tool:${tool.id}`, tool.actionClassIds);
    checkEvidenceTypes(`tool:${tool.id}`, tool.evidenceTypeIds);
    checkDeliverables(`tool:${tool.id}`, tool.deliverableIds ?? []);
  }
  for (const agent of manifests.agents) {
    checkActionClasses(`agent:${agent.id}`, agent.actionClassIds ?? []);
    checkDeliverables(`agent:${agent.id}`, agent.deliverableIds ?? []);
  }
  for (const provider of manifests.providers) {
    for (const model of provider.models) {
      checkActionClasses(
        `provider-model:${provider.id}/${model.id}`,
        model.compatibleActionClassIds,
      );
    }
  }

  if (unknown.length > 0) {
    throw new Error(`Runtime manifests reference unknown registry ids: ${unknown.join(", ")}`);
  }
}

function validateCrossReferences(manifests: RuntimeSourceManifests): void {
  const capabilityIds = new Set(manifests.capabilities.map(({ id }) => id));
  const toolIds = new Set(manifests.tools.map(({ id }) => id));
  const mcpIds = new Set(manifests.mcpServers.map(({ id }) => id));
  const modelRefs = new Set(
    manifests.providers.flatMap((provider) =>
      provider.models.map((model) => `${provider.id}/${model.id}`),
    ),
  );
  const errors: string[] = [];

  for (const tool of manifests.tools) {
    if (tool.mcpServerId !== undefined && !mcpIds.has(tool.mcpServerId)) {
      errors.push(`tool:${tool.id}.mcpServerId:${tool.mcpServerId}`);
    }
    for (const riskId of tool.riskClassIds) {
      if (!manifests.riskClasses.some(({ id }) => id === riskId)) {
        errors.push(`tool:${tool.id}.riskClassIds:${riskId}`);
      }
    }
  }
  for (const server of manifests.mcpServers) {
    for (const toolId of server.toolIds) {
      if (!toolIds.has(toolId)) errors.push(`mcp:${server.id}.toolIds:${toolId}`);
    }
  }
  for (const agent of manifests.agents) {
    for (const capabilityId of agent.capabilityIds) {
      if (!capabilityIds.has(capabilityId)) {
        errors.push(`agent:${agent.id}.capabilityIds:${capabilityId}`);
      }
    }
    for (const toolId of agent.toolIds) {
      if (!toolIds.has(toolId)) errors.push(`agent:${agent.id}.toolIds:${toolId}`);
    }
    for (const ref of agent.modelRefs) {
      const modelRef = `${ref.providerId}/${ref.modelId}`;
      if (!modelRefs.has(modelRef)) errors.push(`agent:${agent.id}.modelRefs:${modelRef}`);
    }
  }

  if (errors.length > 0) {
    throw new Error(`Runtime manifests contain broken references: ${errors.join(", ")}`);
  }
}

export function buildRuntimeCapabilityProjection(
  manifests: RuntimeSourceManifests,
): RuntimeCapabilityProjection {
  assertUniqueIds("risk class", manifests.riskClasses);
  assertUniqueIds("evidence kind", manifests.evidenceKinds);
  assertUniqueIds("capability", manifests.capabilities);
  assertUniqueIds("tool", manifests.tools);
  assertUniqueIds("MCP server", manifests.mcpServers);
  assertUniqueIds("agent", manifests.agents);
  assertUniqueIds("provider", manifests.providers);
  for (const provider of manifests.providers) {
    assertUniqueIds(`provider ${provider.id} model`, provider.models);
  }
  validateCatalogReferences(manifests);
  validateCrossReferences(manifests);

  const capabilitiesById = new Map(manifests.capabilities.map((item) => [item.id, item]));
  const mcpById = new Map(manifests.mcpServers.map((item) => [item.id, item]));
  const models: ProviderModelCapability[] = manifests.providers.flatMap((provider) =>
    provider.models.map((model) => ({
      providerId: provider.id,
      modelId: model.id,
      displayName: model.displayName,
      providerAuthenticated: provider.authenticated,
      providerHealthy: provider.healthy,
      catalogObservedAt: provider.catalogObservedAt,
      toolCalling: model.toolCalling,
      structuredOutput: model.structuredOutput,
      declaredEnforcement: model.enforcement,
      compatibleActionClassIds: model.compatibleActionClassIds.filter(isActionClassId),
      disclosureClasses: model.disclosureClasses,
      contextLimit: model.contextLimit,
      reasoningEfforts: model.reasoningEfforts,
    })),
  );
  const modelsByRef = new Map(
    models.map((model) => [`${model.providerId}/${model.modelId}`, model]),
  );

  const actionClasses = Object.fromEntries(
    ACTION_CLASS_IDS.map((actionClassId): [ActionClassId, ActionCapabilityMapping] => {
      const riskClassIds = manifests.riskClasses
        .filter(({ actionClassIds }) => actionClassIds.includes(actionClassId))
        .map(({ id }) => id);
      const agents = manifests.agents.filter((agent) => {
        if (agent.actionClassIds?.includes(actionClassId)) return true;
        return agent.capabilityIds.some((capabilityId) =>
          capabilitiesById.get(capabilityId)?.actionClassIds.includes(actionClassId),
        );
      });
      const tools = manifests.tools.filter(({ actionClassIds }) =>
        actionClassIds.includes(actionClassId),
      );
      const availableTools = tools.filter((tool) => {
        const dependenciesReady = (tool.dependencies ?? []).every(({ ready }) => ready);
        const mcpReady =
          tool.mcpServerId === undefined || mcpById.get(tool.mcpServerId)?.status === "healthy";
        return tool.available && dependenciesReady && mcpReady;
      });
      const availableAgents = agents.filter(({ available }) => available);
      const providerModelRefs = sorted(
        agents.flatMap(({ modelRefs }) =>
          modelRefs.map(({ providerId, modelId }) => `${providerId}/${modelId}`),
        ),
      );
      const enforcedProviderModelRefs = providerModelRefs.filter((ref) => {
        const model = modelsByRef.get(ref);
        return (
          model !== undefined &&
          model.providerAuthenticated &&
          model.providerHealthy &&
          model.toolCalling &&
          model.structuredOutput &&
          model.declaredEnforcement === "enforced_executor" &&
          model.compatibleActionClassIds.includes(actionClassId)
        );
      });
      const locallyEnforcedTools = availableTools.filter(
        ({ locallyPolicyEnforced }) => locallyPolicyEnforced,
      );
      const modelFreeEnforcedTool = locallyEnforcedTools.some(
        ({ requiresModel }) => requiresModel === false,
      );
      const enforcementReady =
        locallyEnforcedTools.length > 0 &&
        (modelFreeEnforcedTool || enforcedProviderModelRefs.length > 0);
      const readinessReasons: string[] = [];

      if (agents.length === 0) readinessReasons.push("No agent declares this action class.");
      if (tools.length === 0) readinessReasons.push("No runtime tool declares this action class.");
      if (agents.length > 0 && availableAgents.length === 0) {
        readinessReasons.push("All mapped agents are unavailable.");
      }
      if (tools.length > 0 && availableTools.length === 0) {
        readinessReasons.push("All mapped tools or dependencies are unavailable.");
      }
      if (!enforcementReady && agents.length > 0 && tools.length > 0) {
        readinessReasons.push("No locally enforced tool and compatible executor path is ready.");
      }

      const hasMappings = agents.length > 0 && tools.length > 0;
      const availability: CapabilityAvailability = !hasMappings
        ? "unsupported"
        : availableAgents.length > 0 && availableTools.length > 0
          ? "supported"
          : "unavailable";

      return [
        actionClassId,
        {
          actionClassId,
          availability,
          riskClassIds: sorted([
            ...riskClassIds,
            ...tools.flatMap(({ riskClassIds }) => riskClassIds),
          ]),
          agentIds: sorted(agents.map(({ id }) => id)),
          availableAgentIds: sorted(availableAgents.map(({ id }) => id)),
          toolIds: sorted(tools.map(({ id }) => id)),
          availableToolIds: sorted(availableTools.map(({ id }) => id)),
          mcpServerIds: sorted(
            tools.flatMap(({ mcpServerId }) => (mcpServerId === undefined ? [] : [mcpServerId])),
          ),
          providerModelRefs,
          enforcedProviderModelRefs,
          locallyEnforcedToolIds: sorted(locallyEnforcedTools.map(({ id }) => id)),
          evidenceTypeIds: sorted(
            tools.flatMap(({ evidenceTypeIds }) => evidenceTypeIds),
          ).filter(isEvidenceTypeId),
          enforcementReady,
          readinessReasons,
        },
      ];
    }),
  ) as Record<ActionClassId, ActionCapabilityMapping>;

  const evidenceTypes = Object.fromEntries(
    EVIDENCE_TYPE_IDS.map((evidenceTypeId): [EvidenceTypeId, EvidenceCapabilityMapping] => {
      const runtimeEvidenceKindIds = manifests.evidenceKinds
        .filter(({ evidenceTypeIds }) => evidenceTypeIds.includes(evidenceTypeId))
        .map(({ id }) => id);
      const producerTools = manifests.tools.filter(({ evidenceTypeIds }) =>
        evidenceTypeIds.includes(evidenceTypeId),
      );
      const availableProducer = producerTools.some((tool) => {
        const dependenciesReady = (tool.dependencies ?? []).every(({ ready }) => ready);
        const mcpReady =
          tool.mcpServerId === undefined || mcpById.get(tool.mcpServerId)?.status === "healthy";
        return tool.available && dependenciesReady && mcpReady;
      });
      const hasSource = runtimeEvidenceKindIds.length > 0 || producerTools.length > 0;
      return [
        evidenceTypeId,
        {
          evidenceTypeId,
          runtimeEvidenceKindIds: sorted(runtimeEvidenceKindIds),
          producerToolIds: sorted(producerTools.map(({ id }) => id)),
          availability: !hasSource
            ? "unsupported"
            : availableProducer || (runtimeEvidenceKindIds.length > 0 && producerTools.length === 0)
              ? "supported"
              : "unavailable",
        },
      ];
    }),
  ) as Record<EvidenceTypeId, EvidenceCapabilityMapping>;

  const deliverables = Object.fromEntries(
    DELIVERABLE_IDS.map((deliverableId): [DeliverableId, DeliverableCapabilityMapping] => {
      const agents = manifests.agents.filter((agent) => {
        if (agent.deliverableIds?.includes(deliverableId)) return true;
        return agent.capabilityIds.some((capabilityId) =>
          capabilitiesById.get(capabilityId)?.deliverableIds?.includes(deliverableId),
        );
      });
      const tools = manifests.tools.filter(({ deliverableIds }) =>
        deliverableIds?.includes(deliverableId),
      );
      const hasProducer = agents.length > 0 || tools.length > 0;
      const availableProducer =
        agents.some(({ available }) => available) || tools.some(({ available }) => available);
      return [
        deliverableId,
        {
          deliverableId,
          producerAgentIds: sorted(agents.map(({ id }) => id)),
          producerToolIds: sorted(tools.map(({ id }) => id)),
          availability: !hasProducer
            ? "unsupported"
            : availableProducer
              ? "supported"
              : "unavailable",
        },
      ];
    }),
  ) as Record<DeliverableId, DeliverableCapabilityMapping>;

  return {
    actionClasses,
    evidenceTypes,
    deliverables,
    models,
    sourceCounts: {
      riskClasses: manifests.riskClasses.length,
      evidenceKinds: manifests.evidenceKinds.length,
      capabilities: manifests.capabilities.length,
      tools: manifests.tools.length,
      mcpServers: manifests.mcpServers.length,
      agents: manifests.agents.length,
      providers: manifests.providers.length,
      models: models.length,
    },
  };
}

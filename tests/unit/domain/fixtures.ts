import {
  ACTION_CLASS_IDS,
  DELIVERABLE_IDS,
  EVIDENCE_TYPE_IDS,
  type RuntimeSourceManifests,
} from "../../../server/domain";

export function completeRuntimeManifests(
  options: {
    readonly enforcement?: "enforced_executor" | "observe_only_executor" | "advisor_only";
    readonly providerHealthy?: boolean;
    readonly toolAvailable?: boolean;
    readonly mcpStatus?: "healthy" | "degraded" | "offline" | "unconfigured";
  } = {},
): RuntimeSourceManifests {
  return {
    riskClasses: [
      {
        id: "runtime-risk",
        label: "Runtime classified",
        actionClassIds: ACTION_CLASS_IDS,
      },
    ],
    evidenceKinds: [
      {
        id: "runtime-evidence",
        label: "Runtime evidence record",
        evidenceTypeIds: EVIDENCE_TYPE_IDS,
      },
    ],
    capabilities: [
      {
        id: "all-domain-capability",
        label: "Test capability",
        actionClassIds: ACTION_CLASS_IDS,
        evidenceTypeIds: EVIDENCE_TYPE_IDS,
        deliverableIds: DELIVERABLE_IDS,
      },
    ],
    tools: [
      {
        id: "policy-gated-tool",
        label: "Policy-gated test tool",
        available: options.toolAvailable ?? true,
        locallyPolicyEnforced: true,
        actionClassIds: ACTION_CLASS_IDS,
        evidenceTypeIds: EVIDENCE_TYPE_IDS,
        deliverableIds: DELIVERABLE_IDS,
        riskClassIds: ["runtime-risk"],
        mcpServerId: "test-mcp",
      },
    ],
    mcpServers: [
      {
        id: "test-mcp",
        label: "Test MCP",
        status: options.mcpStatus ?? "healthy",
        toolIds: ["policy-gated-tool"],
      },
    ],
    agents: [
      {
        id: "test-specialist",
        label: "Test specialist",
        available: true,
        capabilityIds: ["all-domain-capability"],
        toolIds: ["policy-gated-tool"],
        deliverableIds: DELIVERABLE_IDS,
        modelRefs: [{ providerId: "test-provider", modelId: "test-model" }],
      },
    ],
    providers: [
      {
        id: "test-provider",
        authenticated: true,
        healthy: options.providerHealthy ?? true,
        catalogObservedAt: "2026-07-16T00:00:00.000Z",
        models: [
          {
            id: "test-model",
            displayName: "Test Model",
            toolCalling: true,
            structuredOutput: true,
            enforcement: options.enforcement ?? "enforced_executor",
            compatibleActionClassIds: ACTION_CLASS_IDS,
            disclosureClasses: ["public", "internal_sanitized"],
            contextLimit: 128_000,
            reasoningEfforts: ["low", "medium", "high"],
          },
        ],
      },
    ],
  };
}

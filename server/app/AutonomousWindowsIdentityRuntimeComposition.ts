import {
  buildRuntimeCapabilityProjection,
  type RuntimeSourceManifests,
} from "../domain";
import {
  AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
  AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
  AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID,
  DirectWindowsIdentityProcessAdapter,
  WindowsIdentityCapabilityRegistry,
  windowsIdentityReadinessCurrent,
  type WindowsIdentityToolReadinessReceipt,
} from "../windows-identity-tools";
import type {
  FleetAgentProjection,
  RuntimeProjectionInput,
} from "./RuntimeProjectionService";
import type {
  WindowsIdentityActivationSnapshot,
} from "./WindowsIdentityRuntimeComposition";

export const AUTONOMOUS_WINDOWS_IDENTITY_COMPOSITION_SCHEMA_VERSION =
  "ti-scale.autonomous-windows-identity-composition.v1" as const;

export interface AutonomousWindowsIdentityRuntimeBinding {
  readonly registry: WindowsIdentityCapabilityRegistry;
  readonly adapter: DirectWindowsIdentityProcessAdapter;
  readonly activation: WindowsIdentityActivationSnapshot;
  readonly logicalWorkspace: string;
}

export type AutonomousWindowsIdentityCompositionReadiness =
  | Readonly<{
      schemaVersion:
        typeof AUTONOMOUS_WINDOWS_IDENTITY_COMPOSITION_SCHEMA_VERSION;
      status: "ready";
      checkedAt: string;
      receipt: WindowsIdentityToolReadinessReceipt;
      reason: string;
    }>
  | Readonly<{
      schemaVersion:
        typeof AUTONOMOUS_WINDOWS_IDENTITY_COMPOSITION_SCHEMA_VERSION;
      status: "blocked";
      checkedAt: string;
      receipt: null;
      code:
        | "autonomous_windows_identity_activation_missing"
        | "autonomous_windows_identity_receipt_stale"
        | "autonomous_windows_identity_adapter_mismatch";
      reason: string;
      remediation: string;
    }>;

function unique(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function currentReceipt(
  input: AutonomousWindowsIdentityRuntimeBinding,
  now: Date,
): WindowsIdentityToolReadinessReceipt | undefined {
  const definition = input.registry.pack.resolveTool(
    AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
  );
  const matches = input.activation.receipts.filter(({ toolId }) =>
    toolId === AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID);
  if (!definition || matches.length !== 1
    || !windowsIdentityReadinessCurrent(definition, matches[0], now)) {
    return undefined;
  }
  return matches[0];
}

/**
 * Proves the exact executable/adapter readiness wave used by both manifest
 * admission and execution. This receipt grants no mission authority.
 */
export function inspectAutonomousWindowsIdentityComposition(
  input: AutonomousWindowsIdentityRuntimeBinding,
  now: Date = new Date(),
): AutonomousWindowsIdentityCompositionReadiness {
  const checkedAt = now.toISOString();
  if (input.activation.status !== "ready"
    || !input.activation.readyToolIds.includes(
      AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    )) {
    return Object.freeze({
      schemaVersion: AUTONOMOUS_WINDOWS_IDENTITY_COMPOSITION_SCHEMA_VERSION,
      status: "blocked",
      checkedAt,
      receipt: null,
      code: "autonomous_windows_identity_activation_missing",
      reason:
        "The anonymous NetExec SMB summary has no complete current target-free activation wave.",
      remediation:
        "Restore the exact NetExec executable, sandbox, workspace, output, and cancellation receipts before advertising Autonomous identity work.",
    });
  }
  const receipt = currentReceipt(input, now);
  if (!receipt) {
    return Object.freeze({
      schemaVersion: AUTONOMOUS_WINDOWS_IDENTITY_COMPOSITION_SCHEMA_VERSION,
      status: "blocked",
      checkedAt,
      receipt: null,
      code: "autonomous_windows_identity_receipt_stale",
      reason:
        "The anonymous NetExec executable or bounded-adapter receipt is missing, stale, or no longer matches the reviewed registry.",
      remediation:
        "Repeat the target-free Windows/identity activation wave and use only its current exact receipt.",
    });
  }
  const adapterReceipt = input.adapter.readiness(
    AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
  );
  if (input.activation.adapterId !== input.adapter.adapterId
    || !adapterReceipt
    || adapterReceipt.registryBindingSha256
      !== receipt.registryBindingSha256
    || adapterReceipt.preflightBindingSha256
      !== receipt.preflightBindingSha256
    || adapterReceipt.expiresAt !== receipt.expiresAt) {
    return Object.freeze({
      schemaVersion: AUTONOMOUS_WINDOWS_IDENTITY_COMPOSITION_SCHEMA_VERSION,
      status: "blocked",
      checkedAt,
      receipt: null,
      code: "autonomous_windows_identity_adapter_mismatch",
      reason:
        "The mounted NetExec process adapter does not hold the exact activation receipt being projected.",
      remediation:
        "Bind the same adapter instance that completed the current target-free readiness wave, then refresh the Autonomous lifecycle.",
    });
  }
  return Object.freeze({
    schemaVersion: AUTONOMOUS_WINDOWS_IDENTITY_COMPOSITION_SCHEMA_VERSION,
    status: "ready",
    checkedAt,
    receipt,
    reason:
      "The exact anonymous NetExec executable, direct-argv adapter, confined workspace, bounded output, and run cancellation receipts are current.",
  });
}

function composeManifests(
  baseline: RuntimeSourceManifests,
  input: Readonly<{
    providerId: string;
    modelId: string;
    receipt: WindowsIdentityToolReadinessReceipt;
  }>,
): RuntimeSourceManifests {
  buildRuntimeCapabilityProjection(baseline, new Date(input.receipt.observedAt));
  const sourceTool = baseline.tools.find(({ id }) =>
    id === AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID);
  const sourceAgent = baseline.agents.find(({ id }) =>
    id === AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID);
  const sourceProvider = baseline.providers.find(({ id }) =>
    id === input.providerId);
  const sourceModel = sourceProvider?.models.find(({ id }) =>
    id === input.modelId);
  if (!sourceTool?.available || !sourceAgent?.available
    || !sourceProvider?.healthy || !sourceProvider.authenticated
    || !sourceModel
    || !sourceTool.actionClassIds.includes(
      AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
    )
    || !sourceAgent.toolIds.includes(AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID)) {
    throw new Error(
      "The current Windows identity tool, specialist, or local provider manifest is incomplete",
    );
  }
  const manifests: RuntimeSourceManifests = Object.freeze({
    ...baseline,
    tools: Object.freeze(baseline.tools.map((tool) => {
      if (tool.id !== AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID) return tool;
      const {
        missionSelectionReason: _guidedOnlyReason,
        ...autonomousTool
      } = tool;
      return Object.freeze({
            ...autonomousTool,
            available: true,
            locallyPolicyEnforced: true,
            missionSelectable: true,
            executionJourneys: Object.freeze([
              "autonomous",
              "guided",
            ] as const),
          });
    })),
    agents: Object.freeze(baseline.agents.map((agent) =>
      agent.id === AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID
        ? Object.freeze({
            ...agent,
            available: true,
            capabilityIds: unique([
              ...agent.capabilityIds,
              `capability:${AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID}`,
            ]),
            actionClassIds: unique([
              ...(agent.actionClassIds ?? []),
              AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
            ]),
            toolIds: unique([
              ...agent.toolIds,
              AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
            ]),
            modelRefs: Object.freeze([
              ...agent.modelRefs.filter(({ providerId, modelId }) =>
                providerId !== input.providerId || modelId !== input.modelId),
              Object.freeze({
                providerId: input.providerId,
                modelId: input.modelId,
              }),
            ]),
          })
        : agent)),
    providers: Object.freeze(baseline.providers.map((provider) =>
      provider.id === input.providerId
        ? Object.freeze({
            ...provider,
            models: Object.freeze(provider.models.map((model) =>
              model.id === input.modelId
                ? Object.freeze({
                    ...model,
                    compatibleActionClassIds: unique([
                      ...model.compatibleActionClassIds,
                      AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
                    ]),
                  })
                : model)),
          })
        : provider)),
  });
  buildRuntimeCapabilityProjection(manifests, new Date(input.receipt.observedAt));
  return manifests;
}

function composeAgent(
  agent: FleetAgentProjection,
  input: Readonly<{
    providerId: string;
    modelId: string;
    modelConfigurationHash: string;
    executionAdapterId: string;
    receipt: WindowsIdentityToolReadinessReceipt;
  }>,
): FleetAgentProjection {
  const allowedTools = Array.isArray(agent.toolPolicy.allowedTools)
    ? agent.toolPolicy.allowedTools.filter(
        (value): value is string => typeof value === "string",
      )
    : [];
  const deniedTools = Array.isArray(agent.toolPolicy.deniedTools)
    ? agent.toolPolicy.deniedTools.filter(
        (value): value is string => typeof value === "string",
      )
    : [];
  return Object.freeze({
    ...agent,
    status: "available",
    lastHeartbeatAt: input.receipt.observedAt,
    providerPolicy: Object.freeze({
      ...agent.providerPolicy,
      providerContact: false,
      publicProviderExecution: false,
      autonomousPlanner: Object.freeze({
        providerId: input.providerId,
        modelId: input.modelId,
        modelConfigurationHash: input.modelConfigurationHash,
        executionBoundary: "local_deterministic_policy",
      }),
    }),
    toolPolicy: Object.freeze({
      ...agent.toolPolicy,
      allowedTools: unique([
        ...allowedTools,
        AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
      ]),
      deniedTools: unique(deniedTools.filter((toolId) =>
        toolId !== AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID)),
      exactGuidedDecisionRequired: true,
      exactAutonomousContractRequired: true,
    }),
    // The aggregate Autonomous composition accepts one execution-factory
    // identity. The composite port is therefore the exact mounted adapter for
    // both its delegated base actions and this identity action. Keep this
    // record in the same closed specialist schema used by the composition
    // verifier; operation-specific details remain in capability metadata.
    configuration: Object.freeze({
      schemaVersion: "ti-scale.autonomous-specialist-runtime.v1",
      executionMode: "reviewed_local_process",
      adapterId: input.executionAdapterId,
      toolSelection: "exact_persisted_binding_only",
      resultDelivery: "bound_execution_result_sink",
      shellInterpolation: false,
      publicProviderToolExecution: false,
    }),
    capabilities: Object.freeze(agent.capabilities.map((capability) =>
      capability.name === AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID
        ? Object.freeze({
            ...capability,
            enabled: true,
            metadata: Object.freeze({
              ...capability.metadata,
              actionClassId:
                AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
              executionJourneys: Object.freeze([
                "autonomous",
                "guided",
              ]),
              validUntil: input.receipt.expiresAt,
              targetReadOnly: true,
              authenticationMode: "anonymous",
              evidencePromotion: "none",
            }),
          })
        : capability)),
  });
}

function rebindDelegatedAutonomousAgent(
  agent: FleetAgentProjection,
  executionAdapterId: string,
): FleetAgentProjection {
  const configuration = agent.configuration;
  return configuration.schemaVersion
      === "ti-scale.autonomous-specialist-runtime.v1"
    && configuration.executionMode === "reviewed_local_process"
    && typeof configuration.adapterId === "string"
    ? Object.freeze({
        ...agent,
        configuration: Object.freeze({
          ...configuration,
          adapterId: executionAdapterId,
        }),
      })
    : agent;
}

/**
 * Promotes only the exact NXC binding after the full route is mounted. Other
 * Windows/identity tools remain Guided-only.
 */
export function composeAutonomousWindowsIdentityProjection(
  baseline: RuntimeProjectionInput,
  input: Readonly<{
    binding: AutonomousWindowsIdentityRuntimeBinding;
    providerId: string;
    modelId: string;
    modelConfigurationHash: string;
    executionAdapterId: string;
    now?: Date;
  }>,
): RuntimeProjectionInput {
  const now = input.now ?? new Date();
  const readiness = inspectAutonomousWindowsIdentityComposition(
    input.binding,
    now,
  );
  if (readiness.status !== "ready") throw new Error(readiness.reason);
  const agents = baseline.agents.map((agent) => {
    if (agent.id === AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID) {
      return composeAgent(agent, {
        providerId: input.providerId,
        modelId: input.modelId,
        modelConfigurationHash: input.modelConfigurationHash,
        executionAdapterId: input.executionAdapterId,
        receipt: readiness.receipt,
      });
    }
    return rebindDelegatedAutonomousAgent(
      agent,
      input.executionAdapterId,
    );
  });
  if (!agents.some(({ id }) =>
    id === AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID)) {
    throw new Error(
      "The canonical Windows identity runtime agent is missing from the baseline projection",
    );
  }
  return Object.freeze({
    ...baseline,
    agents: Object.freeze(agents),
    capabilityManifests: composeManifests(
      baseline.capabilityManifests ?? {
        riskClasses: [],
        evidenceKinds: [],
        capabilities: [],
        tools: [],
        mcpServers: [],
        agents: [],
        providers: [],
      },
      {
        providerId: input.providerId,
        modelId: input.modelId,
        receipt: readiness.receipt,
      },
    ),
  });
}

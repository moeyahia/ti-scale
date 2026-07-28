import {
  PRODUCT_AGENT_IDS,
  productAgentIdForActionClass,
  type ProductAgentId,
} from "../agents";
import type {
  GuidedCommanderPort,
  GuidedCommanderRuntimeBinding,
  GuidedCommanderRuntimeBindingResolver,
  GuidedCommanderRuntimeScope,
} from "../guided-commander";
import {
  ModelConfigurationService,
  type StoredModelConfiguration,
} from "../model-config";
import { AgentRuntimeBindingService } from "./AgentRuntimeBindingService";
import { AgentRuntimeBindingError } from "./types";

export const GUIDED_AGENT_RUNTIME_RESOLVER_SCHEMA_VERSION =
  "ti-scale.guided-agent-runtime-resolver.v1" as const;

export interface GuidedPlanningPortFactory {
  /**
   * Returns no port when this process has no fresh operational adapter for the
   * exact pinned configuration. It must never silently substitute a model.
   */
  create(configuration: StoredModelConfiguration): GuidedCommanderPort | undefined;
}

export interface GuidedAgentRuntimeResolverOptions {
  readonly bindings: AgentRuntimeBindingService;
  readonly modelConfigurations: ModelConfigurationService;
  readonly planningPorts: GuidedPlanningPortFactory;
}

function productAgent(scope: GuidedCommanderRuntimeScope): ProductAgentId {
  const assigned = scope.assignedAgentId?.trim() ?? "";
  if (assigned && PRODUCT_AGENT_IDS.has(assigned)) {
    return assigned as ProductAgentId;
  }
  const owner = scope.actionClassId
    ? productAgentIdForActionClass(scope.actionClassId)
    : undefined;
  if (!owner) {
    throw new AgentRuntimeBindingError(
      "agent_runtime_binding_product_agent_missing",
      `No canonical product specialist owns Guided step ${scope.stepId}`,
      "not_found",
      "Assign a canonical Ti-Scale specialist or a registered action class before requesting model-backed guidance.",
    );
  }
  return owner;
}

function assertPortMatchesConfiguration(
  port: GuidedCommanderPort,
  configuration: StoredModelConfiguration,
): void {
  if (
    port.kind !== "planning_only"
    || port.supportsToolExecution !== false
    || port.providerId !== configuration.providerId
    || port.model !== configuration.modelId
  ) {
    throw new AgentRuntimeBindingError(
      "agent_runtime_binding_model_configuration_incompatible",
      `The operational planning adapter does not match pinned configuration ${configuration.id}`,
      "policy_denied",
      "Restore an exact planning-only adapter for the pinned provider and model. Do not substitute an unreviewed route.",
    );
  }
}

/**
 * Bridges a represented Guided step to its canonical product specialist and
 * immutable model assignment. A missing historical pin is created exactly
 * once, before any Context Pack or provider turn is prepared.
 */
export class GuidedAgentRuntimeResolver {
  constructor(private readonly options: GuidedAgentRuntimeResolverOptions) {}

  resolve: GuidedCommanderRuntimeBindingResolver = (
    scope: GuidedCommanderRuntimeScope,
  ): GuidedCommanderRuntimeBinding => {
    let binding;
    try {
      binding = this.options.bindings.resolve(scope);
    } catch (error) {
      if (
        !(error instanceof AgentRuntimeBindingError)
        || error.code !== "agent_runtime_binding_model_assignment_missing"
      ) {
        throw error;
      }
      const agentId = productAgent(scope);
      this.options.modelConfigurations.resolveAndPin(
        {
          agentId,
          missionId: scope.missionId,
          runId: scope.runId,
          stepId: scope.stepId,
          resolutionReason:
            "Pinned before the first model-backed Guided response for this exact represented step",
        },
        { requireAutonomousExecutor: false },
      );
      binding = this.options.bindings.resolve(scope);
    }

    const primary = this.options.planningPorts.create(
      binding.primaryConfiguration,
    );
    if (primary) {
      assertPortMatchesConfiguration(primary, binding.primaryConfiguration);
      return Object.freeze({
        port: primary,
        productAgentId: binding.productAgentId,
        modelAssignmentId: binding.modelAssignmentId,
        modelConfigurationId: binding.primaryConfigurationId,
        usedFallback: false,
      });
    }

    if (binding.fallbackConfiguration) {
      const fallback = this.options.planningPorts.create(
        binding.fallbackConfiguration,
      );
      if (fallback) {
        assertPortMatchesConfiguration(fallback, binding.fallbackConfiguration);
        return Object.freeze({
          port: fallback,
          productAgentId: binding.productAgentId,
          modelAssignmentId: binding.modelAssignmentId,
          modelConfigurationId: binding.fallbackConfigurationId!,
          usedFallback: true,
        });
      }
    }

    throw new AgentRuntimeBindingError(
      "agent_runtime_binding_model_configuration_unavailable",
      `No fresh planning adapter is mounted for pinned model assignment ${binding.modelAssignmentId}`,
      "state_conflict",
      "Restore the pinned provider route or configure a current compatible fallback for a future step.",
    );
  };
}

export function createGuidedAgentRuntimeResolver(
  options: GuidedAgentRuntimeResolverOptions,
): GuidedAgentRuntimeResolver {
  return new GuidedAgentRuntimeResolver(options);
}

import type { ActionClassId, Journey } from "./catalog-ids";

export const MODEL_ENFORCEMENT_STATES = [
  "enforced_executor",
  "observe_only_executor",
  "advisor_only",
  "unavailable",
] as const;

export type ModelEnforcementState = (typeof MODEL_ENFORCEMENT_STATES)[number];

export interface ProviderModelCapability {
  readonly providerId: string;
  readonly modelId: string;
  readonly displayName: string;
  readonly providerAuthenticated: boolean;
  readonly providerHealthy: boolean;
  readonly catalogObservedAt: string;
  readonly toolCalling: boolean;
  readonly structuredOutput: boolean;
  readonly declaredEnforcement: Exclude<ModelEnforcementState, "unavailable">;
  readonly compatibleActionClassIds: readonly ActionClassId[];
  readonly disclosureClasses: readonly string[];
  readonly contextLimit?: number;
  readonly reasoningEfforts?: readonly string[];
}

export interface ModelReadinessRequest {
  readonly journey: Journey;
  readonly requiredActionClassIds: readonly ActionClassId[];
  readonly requiredDisclosureClass?: string;
  readonly requiresToolCalling?: boolean;
  readonly requiresStructuredOutput?: boolean;
}

export interface ModelReadiness {
  readonly providerId: string;
  readonly modelId: string;
  readonly state: ModelEnforcementState;
  readonly ready: boolean;
  readonly reasons: readonly string[];
  readonly incompatibleActionClassIds: readonly ActionClassId[];
  readonly catalogObservedAt: string;
}

export interface ModelConfiguration {
  readonly providerId: string;
  readonly modelId: string;
  readonly reasoningEffort?: string;
  readonly contextPolicy: string;
  readonly promptTemplateHash: string;
  readonly source: "inherited" | "recommended" | "manual_override" | "research_verified";
}

export interface AgentModelAssignment {
  readonly agentId: string;
  readonly primary: ModelConfiguration;
  readonly fallback?: ModelConfiguration;
  readonly resolvedAt: string;
  readonly pinned: true;
}

export function evaluateModelReadiness(
  model: ProviderModelCapability,
  request: ModelReadinessRequest,
): ModelReadiness {
  const reasons: string[] = [];
  const compatible = new Set(model.compatibleActionClassIds);
  const incompatibleActionClassIds = request.requiredActionClassIds.filter(
    (actionClassId) => !compatible.has(actionClassId),
  );

  if (!model.providerAuthenticated) {
    reasons.push("Provider authentication is unavailable.");
  }
  if (!model.providerHealthy) {
    reasons.push("Provider health check is failing.");
  }
  if ((request.requiresToolCalling ?? true) && !model.toolCalling) {
    reasons.push("The model does not support the required tool-calling contract.");
  }
  if ((request.requiresStructuredOutput ?? true) && !model.structuredOutput) {
    reasons.push("The model does not support the required structured-output contract.");
  }
  if (request.requiredDisclosureClass !== undefined) {
    if (!model.disclosureClasses.includes(request.requiredDisclosureClass)) {
      reasons.push(
        `The model is not approved for ${request.requiredDisclosureClass} disclosure.`,
      );
    }
  }
  if (incompatibleActionClassIds.length > 0) {
    reasons.push(
      `The model is not declared compatible with: ${incompatibleActionClassIds.join(", ")}.`,
    );
  }

  let state: ModelEnforcementState = model.declaredEnforcement;
  if (!model.providerAuthenticated || !model.providerHealthy) {
    state = "unavailable";
  } else if (!model.toolCalling || !model.structuredOutput) {
    state = "advisor_only";
  } else if (incompatibleActionClassIds.length > 0) {
    state = "advisor_only";
  }

  if (request.journey === "autonomous" && state !== "enforced_executor") {
    reasons.push("Autonomous execution requires an enforced executor.");
  }

  return {
    providerId: model.providerId,
    modelId: model.modelId,
    state,
    ready:
      reasons.length === 0 &&
      (request.journey === "guided" || state === "enforced_executor"),
    reasons,
    incompatibleActionClassIds,
    catalogObservedAt: model.catalogObservedAt,
  };
}

export function assertPinnedAgentAssignment(
  assignment: AgentModelAssignment,
): AgentModelAssignment {
  if (!assignment.pinned) {
    throw new Error("A running mission must pin every agent model assignment.");
  }
  if (assignment.primary.providerId.length === 0 || assignment.primary.modelId.length === 0) {
    throw new Error("A pinned agent assignment requires an exact provider and model.");
  }
  return assignment;
}

import type { ProductAgentId } from "../agents";
import type { StoredModelConfiguration } from "../model-config";

export const AGENT_RUNTIME_BINDING_SCHEMA_VERSION =
  "ti-scale.agent-runtime-binding.v1" as const;

export const AGENT_RUNTIME_BINDING_ERROR_CODES = [
  "agent_runtime_binding_invalid_input",
  "agent_runtime_binding_step_not_found",
  "agent_runtime_binding_scope_mismatch",
  "agent_runtime_binding_product_agent_missing",
  "agent_runtime_binding_product_agent_ambiguous",
  "agent_runtime_binding_model_assignment_missing",
  "agent_runtime_binding_model_assignment_ambiguous",
  "agent_runtime_binding_model_assignment_scope_mismatch",
  "agent_runtime_binding_signed_assignment_mismatch",
  "agent_runtime_binding_model_configuration_missing",
  "agent_runtime_binding_model_configuration_unavailable",
  "agent_runtime_binding_model_configuration_incompatible",
] as const;

export type AgentRuntimeBindingErrorCode =
  (typeof AGENT_RUNTIME_BINDING_ERROR_CODES)[number];

export type AgentRuntimeBindingErrorCategory =
  | "invalid_input"
  | "not_found"
  | "scope_conflict"
  | "state_conflict"
  | "policy_denied";

export class AgentRuntimeBindingError extends Error {
  constructor(
    readonly code: AgentRuntimeBindingErrorCode,
    message: string,
    readonly category: AgentRuntimeBindingErrorCategory,
    readonly remediation: string,
  ) {
    super(message);
    this.name = "AgentRuntimeBindingError";
  }
}

export interface ResolveAgentRuntimeBindingInput {
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string;
}

export type ProductAgentResolutionSource =
  | "assigned_product_agent"
  | "action_class_registry"
  | "explicit_run_agent";

export type ModelAssignmentBindingScope = "step" | "run";

/**
 * Immutable, provider-call-free receipt binding one canonical plan step to its
 * product specialist and launch-pinned model configuration.
 */
export interface AgentRuntimeBinding {
  readonly schemaVersion: typeof AGENT_RUNTIME_BINDING_SCHEMA_VERSION;
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string;
  readonly representedActionClassId: string | null;
  readonly productAgentId: ProductAgentId;
  readonly productAgentResolutionSource: ProductAgentResolutionSource;
  readonly modelAssignmentId: string;
  readonly modelAssignmentScope: ModelAssignmentBindingScope;
  readonly assignmentResolutionReason: string;
  readonly assignmentResolvedAt: string;
  readonly primaryConfigurationId: string;
  readonly fallbackConfigurationId: string | null;
  readonly primaryConfiguration: StoredModelConfiguration;
  readonly fallbackConfiguration: StoredModelConfiguration | null;
}

/** Exact run-pinned assignment resolved before a plan step exists. */
export interface AgentRunRuntimeBinding extends Omit<
  AgentRuntimeBinding,
  "stepId" | "representedActionClassId" | "productAgentResolutionSource" | "modelAssignmentScope"
> {
  readonly stepId: null;
  readonly representedActionClassId: null;
  readonly productAgentResolutionSource: "explicit_run_agent";
  readonly modelAssignmentScope: "run";
}

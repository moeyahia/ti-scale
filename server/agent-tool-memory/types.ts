import type { Journey } from "../memory";

export const AGENT_TOOL_MEMORY_SCHEMA_VERSION = "1" as const;
export const AGENT_TOOL_MEMORY_COMPILER_VERSION = "1" as const;

export type AgentToolMemoryHook = "assignment_acceptance" | "tool_selection";
export type AgentToolMemoryVerdict = "compatible" | "incompatible" | "missing_dependency";
export type AgentToolMemoryDecision =
  | "no_applicable_memory"
  | "attest_compatible"
  | "veto_incompatible"
  | "veto_missing_dependency";

export type AgentToolMemoryIgnoredReason =
  | "context_boundary_mismatch"
  | "node_not_active_vault_backed"
  | "node_type_not_allowed"
  | "node_not_confirmed_or_verified"
  | "lesson_not_verified"
  | "journey_use_not_permitted"
  | "scope_mismatch"
  | "typed_policy_missing_or_invalid"
  | "hook_mismatch"
  | "represented_agent_mismatch"
  | "represented_action_type_mismatch"
  | "represented_action_class_mismatch"
  | "required_represented_agent_match_missing"
  | "required_represented_action_match_missing";

export interface AgentToolMemoryCandidate {
  readonly nodeId: string;
  readonly verdict: AgentToolMemoryVerdict;
  readonly reasonCode: string;
}

/**
 * The only mutable-looking input is a hash of the already represented action.
 * A memory decision cannot contain a target, command, tool replacement,
 * provider, action class replacement, or argument patch.
 */
export interface AgentToolRepresentedSelection {
  readonly representationHash: string;
  readonly assignmentId?: string;
  readonly representedAgentId?: string;
  readonly representedActionType: string;
  readonly representedActionClass: string;
}

export interface CompiledAgentToolMemoryDecision {
  readonly schemaVersion: typeof AGENT_TOOL_MEMORY_SCHEMA_VERSION;
  readonly compilerVersion: typeof AGENT_TOOL_MEMORY_COMPILER_VERSION;
  readonly hook: AgentToolMemoryHook;
  readonly journey: Journey;
  readonly contextPackId: string;
  readonly brainAuditRecordId: string;
  readonly missionId: string;
  readonly engagementId: string | null;
  readonly runId: string;
  readonly stepId: string;
  readonly selection: AgentToolRepresentedSelection;
  readonly decision: AgentToolMemoryDecision;
  readonly candidates: readonly AgentToolMemoryCandidate[];
  readonly appliedNodeIds: readonly string[];
  readonly ignored: Readonly<Record<string, AgentToolMemoryIgnoredReason>>;
}

export interface AgentToolMemoryDecisionReceipt {
  /** This is also the immutable decision audit-record ID. */
  readonly id: string;
  readonly decisionAuditRecordId: string;
  readonly schemaVersion: typeof AGENT_TOOL_MEMORY_SCHEMA_VERSION;
  readonly compilerVersion: typeof AGENT_TOOL_MEMORY_COMPILER_VERSION;
  readonly hook: AgentToolMemoryHook;
  readonly journey: Journey;
  readonly contextPackId: string;
  readonly brainAuditRecordId: string;
  readonly missionId: string;
  readonly engagementId: string | null;
  readonly runId: string;
  readonly stepId: string;
  readonly selection: AgentToolRepresentedSelection;
  readonly decision: AgentToolMemoryDecision;
  readonly candidateNodeIds: readonly string[];
  readonly appliedNodeIds: readonly string[];
  readonly ignoredNodeIds: readonly string[];
  readonly ignoredReasons: Readonly<Record<string, string>>;
  readonly representationUnchanged: true;
  readonly scopeExpanded: false;
  readonly toolChanged: false;
  readonly actionClassChanged: false;
  readonly argumentsChanged: false;
  readonly providerExposureCreated: false;
  readonly receiptHash: string;
  readonly createdAt: string;
}

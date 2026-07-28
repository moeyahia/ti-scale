import type { RuntimeSourceManifests } from "../domain";

export const MODEL_CONFIGURATION_SCHEMA_VERSION = "2.4" as const;

export const MODEL_PREFERENCE_SCOPE_TYPES = [
  "global",
  "agent",
  "mission",
  "run",
  "step",
] as const;

export type ModelPreferenceScopeType =
  (typeof MODEL_PREFERENCE_SCOPE_TYPES)[number];

export const MODEL_ASSIGNMENT_PURPOSES = [
  "execution",
  "planning",
] as const;

export type ModelAssignmentPurpose =
  (typeof MODEL_ASSIGNMENT_PURPOSES)[number];

export type CatalogEnforcementMode =
  | "enforced_executor"
  | "observe_only_executor"
  | "advisor_only"
  | "unavailable";

export type CatalogAuthState =
  | "authenticated"
  | "unconfigured"
  | "invalid"
  | "unknown";

export type CatalogHealthState =
  | "healthy"
  | "degraded"
  | "unavailable"
  | "unknown";

export type ModelExecutionBoundary =
  | "provider_tool_calling"
  | "local_deterministic_policy";

export interface ModelCatalogItem {
  readonly configurationId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly displayName: string;
  readonly executionBoundary: ModelExecutionBoundary;
  readonly reasoningEffort: string | null;
  readonly supportedReasoningEfforts: readonly string[];
  readonly contextLimit: number | null;
  readonly costClass: "low" | "standard" | "high" | "unknown";
  readonly latencyClass: "fast" | "standard" | "slow" | "unknown";
  readonly disclosureClass:
    | "public_only"
    | "sanitized_internal"
    | "local_only"
    | "unavailable";
  readonly enforcementMode: CatalogEnforcementMode;
  readonly authState: CatalogAuthState;
  readonly healthState: CatalogHealthState;
  readonly catalogSource: string;
  readonly catalogRetrievedAt: string | null;
  readonly capabilities: {
    readonly toolCalling: boolean;
    readonly structuredOutput: boolean;
    readonly compatibleActionClassIds: readonly string[];
    /**
     * Evidence-backed local execution coverage keyed by canonical product
     * agent. Empty unless the runtime model explicitly declares the local
     * deterministic boundary and exact no-model tool joins were proven.
     */
    readonly localDeterministicActionClassIdsByAgent:
      Readonly<Record<string, readonly string[]>>;
  };
  readonly compatibleAgentIds: readonly string[];
  readonly selectable: boolean;
  readonly unavailableReasons: readonly string[];
}

export interface StoredModelConfiguration {
  readonly id: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly displayName: string;
  readonly executionBoundary: ModelExecutionBoundary;
  readonly reasoningEffort: string | null;
  readonly contextPolicy: Readonly<Record<string, unknown>>;
  readonly capabilities: Readonly<Record<string, unknown>>;
  readonly contextLimit: number | null;
  readonly costClass: "low" | "standard" | "high" | "unknown";
  readonly latencyClass: "fast" | "standard" | "slow" | "unknown";
  readonly disclosureClass:
    | "public_only"
    | "sanitized_internal"
    | "local_only"
    | "unavailable";
  readonly enforcementMode: CatalogEnforcementMode;
  readonly authState: CatalogAuthState;
  readonly healthState: CatalogHealthState;
  readonly catalogSource: string;
  readonly catalogRetrievedAt: string | null;
  readonly configurationSource:
    | "inherited"
    | "recommended"
    | "manual"
    | "research_verified";
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ModelAssignmentPreference {
  readonly id: string;
  readonly scopeType: ModelPreferenceScopeType;
  readonly scopeId: string;
  readonly agentId: string | null;
  readonly primaryConfigurationId: string;
  readonly fallbackConfigurationId: string | null;
  readonly resolutionReason: string;
  readonly version: number;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly updatedBy: string;
  readonly updatedAt: string;
}

export interface ModelPreferenceFilters {
  readonly scopeType?: ModelPreferenceScopeType;
  readonly scopeId?: string;
  readonly agentId?: string;
}

export interface PutModelPreferenceInput {
  readonly scopeType: ModelPreferenceScopeType;
  readonly scopeId: string;
  readonly agentId: string | null;
  readonly primaryConfigurationId: string;
  readonly fallbackConfigurationId: string | null;
  readonly expectedVersion: number;
  readonly reason: string;
}

export interface ModelResolutionContext {
  readonly missionId: string | null;
  readonly runId: string | null;
  readonly stepId: string | null;
}

export interface ModelResolution {
  readonly agentId: string;
  readonly context: ModelResolutionContext;
  readonly source: {
    readonly scopeType: ModelPreferenceScopeType;
    readonly scopeId: string;
    readonly preferenceId: string;
    readonly preferenceVersion: number;
  };
  readonly primaryConfiguration: StoredModelConfiguration;
  readonly fallbackConfiguration: StoredModelConfiguration | null;
  readonly resolvedAt: string;
}

/**
 * Public read-model contract for an agent-profile preference. These
 * preferences govern specialist execution. Autonomous planning remains a
 * separately reviewed mission-contract route and cannot inherit execution
 * authority from an agent preference.
 */
export interface ModelAssignmentSemantics {
  readonly purpose: "execution";
  readonly preferenceResolutionOrder:
    "global_then_agent_then_mission_then_run_then_step";
  readonly saveEffect: "future_resolutions_only";
  readonly activeRunPinning: "immutable";
  readonly planningRoute: "autonomous_mission_contract";
}

export const MODEL_ASSIGNMENT_SEMANTICS: ModelAssignmentSemantics =
  Object.freeze({
    purpose: "execution",
    preferenceResolutionOrder:
      "global_then_agent_then_mission_then_run_then_step",
    saveEffect: "future_resolutions_only",
    activeRunPinning: "immutable",
    planningRoute: "autonomous_mission_contract",
  });

export interface PinModelAssignmentInput {
  readonly agentId: string;
  readonly missionId?: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly purpose?: ModelAssignmentPurpose;
  readonly resolutionReason?: string;
}

/**
 * Exact provider/model authority signed into an Autonomous mission contract.
 * The configuration IDs are live-catalog identities, not mutable preference
 * references. `null` is deliberate so canonical JSON never changes because a
 * client omitted an optional fallback property.
 */
export interface AgentModelAssignmentSelection {
  readonly agentId: string;
  readonly primaryConfigurationId: string;
  readonly fallbackConfigurationId: string | null;
  /**
   * Resolution provenance is part of the reviewed contract once intake has
   * materialized the complete assignment set. Raw intake overrides omit this
   * field; the server records them as operator_override.
   */
  readonly source?: AgentModelAssignmentSource;
}

/**
 * The signed planning route is deliberately separate from specialist
 * execution assignments. A local route is deterministic product code and
 * therefore has no provider/model pin. A provider route is advisory-only and
 * can never acquire execution authority through this contract.
 */
export type AutonomousPlanningSelection =
  | {
      readonly route: "local_deterministic";
      readonly plannerId: "ti-scale.local-autonomous-contract-planner.v1";
      readonly enforcementMode: "local_policy";
      readonly disclosureClass: "local_only";
      readonly executionAuthority: "none";
    }
  | {
      readonly route: "provider_advisory";
      readonly agentId: string;
      readonly primaryConfigurationId: string;
      readonly fallbackConfigurationId: string | null;
      readonly enforcementMode: "advisor_only";
      readonly disclosureClass: "public_only" | "sanitized_internal";
      readonly executionAuthority: "none";
    };

export const AUTONOMOUS_LOCAL_PLANNING_SELECTION: AutonomousPlanningSelection =
  Object.freeze({
    route: "local_deterministic",
    plannerId: "ti-scale.local-autonomous-contract-planner.v1",
    enforcementMode: "local_policy",
    disclosureClass: "local_only",
    executionAuthority: "none",
  });

export function resolveAutonomousPlanningSelection(
  selection: AutonomousPlanningSelection | undefined,
): AutonomousPlanningSelection {
  return selection ?? AUTONOMOUS_LOCAL_PLANNING_SELECTION;
}

export type AgentModelAssignmentSource =
  | "recommended"
  | "inherited"
  | "operator_override";

export interface ModelAssignmentConfigurationReceipt {
  readonly configurationId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly displayName: string;
  readonly executionBoundary: ModelExecutionBoundary;
  readonly reasoningEffort: string | null;
  readonly enforcementMode: CatalogEnforcementMode;
  readonly authState: CatalogAuthState;
  readonly healthState: CatalogHealthState;
  readonly disclosureClass: ModelCatalogItem["disclosureClass"];
  readonly costClass: ModelCatalogItem["costClass"];
  readonly latencyClass: ModelCatalogItem["latencyClass"];
  readonly contextLimit: number | null;
  readonly catalogSource: string;
  readonly catalogRetrievedAt: string | null;
}

export interface AgentModelAssignmentReceipt {
  readonly agentId: string;
  readonly source: AgentModelAssignmentSource;
  readonly ready: boolean;
  readonly reasons: readonly string[];
  readonly primary: ModelAssignmentConfigurationReceipt;
  readonly fallback: ModelAssignmentConfigurationReceipt | null;
}

export interface AgentModelAssignmentBatch {
  readonly observedAt: string;
  readonly selections: readonly AgentModelAssignmentSelection[];
  readonly receipts: readonly AgentModelAssignmentReceipt[];
}

export interface ExactPinModelAssignmentInput extends PinModelAssignmentInput {
  readonly primaryConfigurationId: string;
  readonly fallbackConfigurationId: string | null;
  readonly inheritanceLevel?: ModelPreferenceScopeType;
}

export interface PinnedModelAssignment {
  readonly id: string;
  readonly agentId: string;
  readonly missionId: string | null;
  readonly runId: string | null;
  readonly stepId: string | null;
  readonly purpose: ModelAssignmentPurpose;
  readonly primaryConfigurationId: string;
  readonly fallbackConfigurationId: string | null;
  readonly inheritanceLevel: ModelPreferenceScopeType;
  readonly pinned: true;
  readonly resolutionReason: string;
  readonly resolvedAt: string;
  readonly createdAt: string;
}

export interface ModelConfigurationServiceDependencies {
  readonly readRuntimeManifests: () => RuntimeSourceManifests;
  readonly clock?: () => Date;
  readonly catalogMaximumAgeMs?: number;
  readonly catalogMaximumFutureSkewMs?: number;
}

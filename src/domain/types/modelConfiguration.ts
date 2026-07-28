export type ModelEnforcementMode =
  | "enforced_executor"
  | "observe_only_executor"
  | "advisor_only"
  | "unavailable";

export type ModelAuthState =
  | "authenticated"
  | "unconfigured"
  | "invalid"
  | "unknown";

export type ModelHealthState =
  | "healthy"
  | "degraded"
  | "unavailable"
  | "unknown";

export type ModelExecutionBoundary =
  | "provider_tool_calling"
  | "local_deterministic_policy";

export type ModelPreferenceScope =
  | "global"
  | "agent"
  | "mission"
  | "run"
  | "step";

export interface ModelCatalogItem {
  readonly configurationId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly displayName: string;
  readonly executionBoundary: ModelExecutionBoundary;
  readonly reasoningEffort: string | null;
  readonly supportedReasoningEfforts: readonly string[];
  readonly contextLimit: number | null;
  readonly costClass: string;
  readonly latencyClass: string;
  readonly disclosureClass: string;
  readonly enforcementMode: ModelEnforcementMode;
  readonly authState: ModelAuthState;
  readonly healthState: ModelHealthState;
  readonly catalogSource: string;
  readonly catalogRetrievedAt: string | null;
  readonly capabilities: {
    readonly toolCalling: boolean;
    readonly structuredOutput: boolean;
    readonly compatibleActionClassIds: readonly string[];
    readonly localDeterministicActionClassIdsByAgent:
      Readonly<Record<string, readonly string[]>>;
  };
  readonly compatibleAgentIds: readonly string[];
  readonly selectable: boolean;
  readonly unavailableReasons: readonly string[];
}

export interface ModelCatalog {
  readonly schemaVersion: "2.4";
  readonly observedAt: string;
  readonly items: readonly ModelCatalogItem[];
}

export interface ModelConfiguration {
  readonly id: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly displayName: string;
  readonly executionBoundary: ModelExecutionBoundary;
  readonly reasoningEffort: string | null;
  readonly contextPolicy: Readonly<Record<string, unknown>>;
  readonly capabilities: Readonly<Record<string, unknown>>;
  readonly contextLimit: number | null;
  readonly costClass: string;
  readonly latencyClass: string;
  readonly disclosureClass: string;
  readonly enforcementMode: ModelEnforcementMode;
  readonly authState: ModelAuthState;
  readonly healthState: ModelHealthState;
  readonly catalogSource: string;
  readonly catalogRetrievedAt: string | null;
  readonly configurationSource: string;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ModelConfigurationPage {
  readonly schemaVersion: "2.4";
  readonly items: readonly ModelConfiguration[];
}

export interface ModelPreference {
  readonly id: string;
  readonly scopeType: ModelPreferenceScope;
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

export interface ModelPreferencePage {
  readonly schemaVersion: "2.4";
  readonly items: readonly ModelPreference[];
}

export interface ModelPreferenceMutation {
  readonly schemaVersion: "2.4";
  readonly preference: ModelPreference;
}

export interface ModelResolution {
  readonly agentId: string;
  readonly context: {
    readonly missionId: string | null;
    readonly runId: string | null;
    readonly stepId: string | null;
  };
  readonly source: {
    readonly scopeType: ModelPreferenceScope;
    readonly scopeId: string;
    readonly preferenceId: string;
    readonly preferenceVersion: number;
  };
  readonly primaryConfiguration: ModelConfiguration;
  readonly fallbackConfiguration: ModelConfiguration | null;
  readonly resolvedAt: string;
}

export interface ModelAssignmentSemantics {
  readonly purpose: "execution";
  readonly preferenceResolutionOrder:
    "global_then_agent_then_mission_then_run_then_step";
  readonly saveEffect: "future_resolutions_only";
  readonly activeRunPinning: "immutable";
  readonly planningRoute: "autonomous_mission_contract";
}

export interface ModelResolutionResult {
  readonly schemaVersion: "2.4";
  readonly assignmentSemantics: ModelAssignmentSemantics;
  readonly resolution: ModelResolution | null;
  readonly availability: {
    readonly status: "configured" | "unconfigured";
    readonly agentId: string;
    readonly humanMessage: string;
    readonly remediation: string | null;
  };
}

export interface UpdateModelPreferenceInput {
  readonly agentId: string | null;
  readonly primaryConfigurationId: string;
  readonly fallbackConfigurationId: string | null;
  readonly expectedVersion: number;
  readonly reason: string;
}

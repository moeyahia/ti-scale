import type {
  ActionClassRegistry,
  ActionClassId,
  ActionPolicyState,
  BudgetPresetId,
  DeliverableRegistry,
  DestructiveActionPolicy,
  EvidenceTypeId,
  EvidenceTypeRegistry,
  MissionBudgetPreset,
  MissionTarget,
  MissionTemplateId,
  MissionTemplateRegistry,
  RuntimeCapabilityProjection,
  SafeStopDefinition,
} from "../domain";
import type { MissionCreateRequest, MissionEnvironmentClassification } from "../missions";
import type {
  GuidedReconnaissanceSelection,
  GuidedTcpPortPresetId,
} from "../missions/GuidedReconnaissance";
import type {
  AutonomousOutcomeProfileId,
} from "../domain/autonomous-outcome-registry";
import type {
  AgentModelAssignmentSelection,
  AutonomousPlanningSelection,
} from "../model-config";

export interface IntakeFieldDefinition {
  readonly id: string;
  readonly label: string;
  readonly purpose: string;
  readonly example: string;
  readonly optional: boolean;
  readonly structuredWhenPossible: boolean;
}

export interface MissionIntakeTargetInput {
  readonly value: string;
  readonly type?: MissionTarget["type"];
  readonly excluded?: boolean;
}

export interface MissionIntakeRequest {
  readonly journey: "autonomous" | "guided";
  readonly authorizationAcknowledged: boolean;
  readonly targets: readonly MissionIntakeTargetInput[];
  readonly templateId?: MissionTemplateId;
  readonly title?: string;
  readonly objective?: string;
  readonly successCriteria?: readonly string[];
  readonly deliverableIds?: readonly string[];
  readonly evidenceTypeIds?: readonly string[];
  readonly optionalSafeStopIds?: readonly string[];
  readonly actionPolicyOverrides?: Readonly<Partial<Record<ActionClassId, ActionPolicyState>>>;
  readonly destructivePolicy?: DestructiveActionPolicy;
  readonly boundedDestructiveTargetIds?: readonly string[];
  readonly budgetPresetId?: BudgetPresetId;
  readonly engagementId?: string;
  readonly environmentClassification?: MissionEnvironmentClassification;
  readonly explanationDepth?: "concise" | "balanced" | "deep";
  readonly executionPreference?: "manual" | "single_step_agent";
  readonly guidedReconnaissance?: GuidedReconnaissanceSelection;
  readonly specialistAgentIds?: readonly string[];
  /**
   * Partial mission-local overrides. Missing selected agents are materialized
   * from current scoped defaults or a deterministic live-catalog recommendation.
   */
  readonly agentModelAssignments?: readonly AgentModelAssignmentSelection[];
  /**
   * Selects how the Autonomous plan itself is constructed. This is separate
   * from specialist execution assignments: provider-backed planning is always
   * advisory-only and carries no tool or execution authority.
   */
  readonly planningSelection?: AutonomousPlanningSelection;
  readonly memoryScopes?: readonly string[];
  readonly contextNodeIds?: readonly string[];
}

export interface IntakeRegistrySnapshot {
  readonly schemaVersion: "2.4";
  readonly source: {
    readonly status: "live" | "unavailable";
    readonly explanation: string;
    readonly counts: RuntimeCapabilityProjection["sourceCounts"];
  };
  readonly fields: readonly IntakeFieldDefinition[];
  readonly actionClasses: ActionClassRegistry;
  readonly evidenceTypes: EvidenceTypeRegistry;
  readonly deliverables: DeliverableRegistry;
  readonly templates: MissionTemplateRegistry;
  readonly safeStops: {
    readonly mandatory: readonly SafeStopDefinition[];
    readonly optional: readonly SafeStopDefinition[];
  };
  readonly budgets: Readonly<Record<"quick" | "standard" | "deep", MissionBudgetPreset>>;
  readonly guidedReconnaissance: {
    readonly registryVersion: 1;
    readonly modes: readonly {
      readonly id: "host_liveness" | "tcp_service_scan";
      readonly label: string;
      readonly description: string;
      readonly toolId: string;
      readonly readiness: "ready" | "unavailable";
      readonly readinessExplanation: string;
      readonly remediation: string;
      readonly manualFallbackAvailable: true;
    }[];
    readonly tcpPortPresets: readonly {
      readonly id: GuidedTcpPortPresetId;
      readonly version: number;
      readonly label: string;
      readonly description: string;
      readonly ports: readonly number[];
    }[];
    readonly customPorts: {
      readonly maximumIndividualPorts: number;
      readonly example: string;
      readonly explanation: string;
    };
  };
}

export interface ResolvedMissionIntake {
  readonly schemaVersion: "2.4";
  readonly request: MissionCreateRequest;
  /**
   * Present only for Autonomous. This describes the promised result without
   * introducing another journey or exposing an internal runtime mode.
   */
  readonly autonomousOutcome?: {
    readonly id: AutonomousOutcomeProfileId;
    readonly label: string;
    readonly concisePromise: string;
    readonly completionMeaning: string;
    readonly requiredTerminalSuccessCriteria: readonly string[];
    readonly requiredActionClassIds: readonly string[];
  };
  readonly normalizedTargets: readonly MissionTarget[];
  readonly template: {
    readonly id: MissionTemplateId;
    readonly version: number;
  };
  readonly policyMatrix: ActionClassRegistry;
  readonly evidenceTypeIds: readonly EvidenceTypeId[];
  readonly deliverableIds: readonly string[];
  readonly mandatorySafeStopIds: readonly string[];
  readonly optionalSafeStopIds: readonly string[];
  readonly budget: MissionBudgetPreset;
  readonly inferredFields: readonly string[];
  readonly limitations: readonly string[];
}

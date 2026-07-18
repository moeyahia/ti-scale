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
import type { MissionCreateRequest } from "../missions";

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
  readonly explanationDepth?: "concise" | "balanced" | "deep";
  readonly executionPreference?: "manual" | "single_step_agent";
  readonly specialistAgentIds?: readonly string[];
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
}

export interface ResolvedMissionIntake {
  readonly schemaVersion: "2.4";
  readonly request: MissionCreateRequest;
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

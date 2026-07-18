import type { AutonomousMissionRequest, GuidedMissionRequest, Journey, MissionCreateRequest } from "./commandOs";

export type MissionTemplateId =
  | "safe_recon"
  | "external_web_assessment"
  | "internal_network_assessment"
  | "active_directory_lab"
  | "cloud_read_only"
  | "full_authorized_lab_compromise"
  | "custom";
export type BudgetPresetId = "quick" | "standard" | "deep" | "custom";
export type ActionPolicyState = "pre_authorized" | "prohibited" | "guided_only" | "inherited_default";
export type ResolvedActionPolicyState = Exclude<ActionPolicyState, "inherited_default">;
export type DestructiveActionPolicy = "prohibited" | "validate_without_executing" | "bounded_lab_only";

export interface MissionIntakeTargetInput {
  value: string;
  type?: "host" | "cidr" | "url" | "domain" | "cloud_account" | "scope_file" | "engagement" | "lab_environment";
  excluded?: boolean;
}

export interface MissionIntakeRequest {
  journey: Journey;
  authorizationAcknowledged: boolean;
  targets: MissionIntakeTargetInput[];
  templateId?: MissionTemplateId;
  title?: string;
  objective?: string;
  successCriteria?: string[];
  deliverableIds?: string[];
  evidenceTypeIds?: string[];
  optionalSafeStopIds?: string[];
  actionPolicyOverrides?: Record<string, ActionPolicyState>;
  destructivePolicy?: DestructiveActionPolicy;
  boundedDestructiveTargetIds?: string[];
  budgetPresetId?: BudgetPresetId;
  engagementId?: string;
  explanationDepth?: GuidedMissionRequest["explanationDepth"];
  executionPreference?: GuidedMissionRequest["executionPreference"];
  specialistAgentIds?: string[];
  memoryScopes?: string[];
  contextNodeIds?: string[];
}

export interface CapabilityMapping {
  availability: "supported" | "unavailable" | "unsupported";
  riskClassIds: string[];
  agentIds: string[];
  availableAgentIds: string[];
  toolIds: string[];
  availableToolIds: string[];
  mcpServerIds: string[];
  providerModelRefs: string[];
  enforcedProviderModelRefs: string[];
  locallyEnforcedToolIds: string[];
  evidenceTypeIds: string[];
  enforcementReady: boolean;
  readinessReasons: string[];
}

export interface IntakeActionClass {
  id: string;
  label: string;
  plainLanguageDescription: string;
  technicalDescription: string;
  riskBand: "low" | "moderate" | "high" | "critical";
  likelySideEffects: string[];
  defaultPolicyState: ResolvedActionPolicyState;
  defaultEvidenceTypeIds: string[];
  destructiveOrDisruptive: boolean;
  policyState: ResolvedActionPolicyState;
  policySource: "platform_default" | "preset" | "operator_override";
  capability: CapabilityMapping;
  launchBlockingReasons: string[];
}

export interface IntakeActionClassRegistry {
  journey: Journey;
  presetId: MissionTemplateId;
  destructivePolicy: DestructiveActionPolicy;
  classes: Record<string, IntakeActionClass>;
  autonomousLaunchReady: boolean;
  launchBlockingReasons: string[];
}

export interface IntakeEvidenceType {
  id: string;
  label: string;
  proves: string;
  storageAndSensitivity: string;
  normallyRequiredForActionClassIds: string[];
  immutableHashRequired: boolean;
  chainOfCustodyRequired: boolean;
  capability: {
    evidenceTypeId: string;
    runtimeEvidenceKindIds: string[];
    producerToolIds: string[];
    availability: "supported" | "unavailable" | "unsupported";
  };
}

export interface IntakeDeliverable {
  id: string;
  label: string;
  purpose: string;
  formats: string[];
  sensitivityNotes: string;
  capability: {
    deliverableId: string;
    producerAgentIds: string[];
    producerToolIds: string[];
    availability: "supported" | "unavailable" | "unsupported";
  };
}

export interface IntakeMissionTemplate {
  id: MissionTemplateId;
  version: number;
  label: string;
  summary: string;
  supportedJourneys: Journey[];
  actionPolicyPresetId: MissionTemplateId;
  scopeHints: string[];
  objectivePattern: string;
  successCriteria: string[];
  recommendedActionClassIds: string[];
  recommendedEvidenceTypeIds: string[];
  recommendedDeliverableIds: string[];
  recommendedOptionalSafeStops: string[];
  recommendedAgentCapabilityIds: string[];
  modelReadinessRequirements: string[];
  budgetPreset: BudgetPresetId;
  unsupportedActionClassIds: string[];
  unavailableEvidenceTypeIds: string[];
  unavailableDeliverableIds: string[];
}

export interface SafeStopDefinition {
  id: string;
  label: string;
  explanation: string;
  remediation: string;
  mandatory: boolean;
  userRemovable: boolean;
}

export interface MissionBudgetPreset {
  id: "quick" | "standard" | "deep";
  label: string;
  description: string;
  timeBudgetMinutes: number;
  tokenBudget: number;
  estimatedCostBudget: number;
  toolCallBudget: number;
  retryBudget: number;
  replanBudget: number;
  concurrencyLimit: number;
  screenshotBudget: number;
  evidenceStorageBudgetBytes: number;
  artifactStorageBudgetBytes: number;
  maximumArtifactBytes: number;
}

export interface IntakeFieldDefinition {
  id: string;
  label: string;
  purpose: string;
  example: string;
  optional: boolean;
  structuredWhenPossible: boolean;
}

export interface IntakeRegistrySnapshot {
  schemaVersion: "2.4";
  source: {
    status: "live" | "unavailable";
    explanation: string;
    counts: Record<string, number>;
  };
  fields: IntakeFieldDefinition[];
  actionClasses: IntakeActionClassRegistry;
  evidenceTypes: { types: Record<string, IntakeEvidenceType> };
  deliverables: { deliverables: Record<string, IntakeDeliverable> };
  templates: { templates: Record<string, IntakeMissionTemplate> };
  safeStops: { mandatory: SafeStopDefinition[]; optional: SafeStopDefinition[] };
  budgets: Record<"quick" | "standard" | "deep", MissionBudgetPreset>;
}

export interface ResolvedMissionIntake {
  schemaVersion: "2.4";
  request: MissionCreateRequest;
  normalizedTargets: Array<MissionIntakeTargetInput & { id: string; type: NonNullable<MissionIntakeTargetInput["type"]> }>;
  template: { id: MissionTemplateId; version: number };
  policyMatrix: IntakeActionClassRegistry;
  evidenceTypeIds: string[];
  deliverableIds: string[];
  mandatorySafeStopIds: string[];
  optionalSafeStopIds: string[];
  budget: MissionBudgetPreset;
  inferredFields: string[];
  limitations: string[];
}

export function isAutonomousResolved(value: ResolvedMissionIntake): value is ResolvedMissionIntake & { request: AutonomousMissionRequest } {
  return value.request.journey === "autonomous";
}

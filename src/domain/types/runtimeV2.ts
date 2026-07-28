import type { Journey, RunStatus } from "./commandOs";

export interface RuntimeRun {
  id: string; missionId: string; missionName: string; objective: string; journey: Journey; status: RunStatus;
  statusReason: string | null; progress: number; nextAction: string | null; currentPlanId: string | null;
  currentStepId: string | null; currentOwnerId: string | null; lastHeartbeatAt: string | null;
  leaseExpiresAt: string | null; startedAt: string | null; endedAt: string | null; createdAt: string;
  updatedAt: string; version: number;
}

export interface RuntimeMission {
  id: string; name: string; objective: string; journey: Journey; engagementId: string | null;
  authorizationStatus: string; allowedTargets: string[]; prohibitedTargets: string[]; successCriteria: string[];
  memoryPolicy: Record<string, unknown>;
}

export interface MissionRuntimeSnapshot { schemaVersion: "2.4"; mission: RuntimeMission; runs: RuntimeRun[] }
export interface RuntimeCheckpoint {
  id: string;
  journey: Journey;
  eventSequence: number;
  stateHash: string;
  createdAt: string;
  state: {
    run: { id: string; state: RunStatus; stateVersion: number; leaseOwner: string | null; leaseExpiresAt: string | null };
    inFlightActions: Array<{ id: string; status: string; idempotent: boolean; destructive: boolean }>;
    lastEventSequence: number;
  };
}
export type AutonomousActivationReceiptIntegrityStatus =
  | "verified"
  | "expired"
  | "integrity_failure";
export interface AutonomousActivationReceiptIntegrity {
  status: AutonomousActivationReceiptIntegrityStatus;
  code: string | null;
  verifiedAt: string;
  humanMessage: string;
  remediation: string | null;
}
export interface AutonomousActivationReceiptSummary {
  id: string;
  runId: string;
  generation: number;
  issuedAt: string;
  expiresAt: string;
  planningRoute: "local_deterministic" | "provider_advisory";
  plannerId: string;
  planningModelAssignmentId: string | null;
  selectedActionClassCount: number;
  activatedActionClassCount: number;
  modelRouteCount: number;
  toolRouteCount: number;
  bindingCount: number;
  runtimeGenerationHash: string;
  brainContextPackId: string;
  receiptHash: string;
  integrity: AutonomousActivationReceiptIntegrity;
}
export type AutonomousActivationPlanningSelection =
  | {
      route: "local_deterministic";
      plannerId: string;
      enforcementMode: "local_policy";
      disclosureClass: "local_only";
      executionAuthority: "none";
    }
  | {
      route: "provider_advisory";
      agentId: string;
      primaryConfigurationId: string;
      fallbackConfigurationId: string | null;
      enforcementMode: "advisor_only";
      disclosureClass: string;
      executionAuthority: "none";
    };
export interface AutonomousActivationPlanningSnapshot {
  route: "local_deterministic" | "provider_advisory";
  selection: AutonomousActivationPlanningSelection;
  selectionHash: string;
  plannerId: string;
  modelAssignmentId: string | null;
  primaryConfigurationId: string | null;
  fallbackConfigurationId: string | null;
  primaryConfigurationHash: string | null;
  fallbackConfigurationHash: string | null;
}
export interface AutonomousActivationReceiptItem {
  actionClassId: string;
  agentId: string;
  executionModelAssignmentId: string;
  executionPrimaryConfigurationId: string;
  executionFallbackConfigurationId: string | null;
  toolId: string;
  toolBindingKind: "local" | "mcp";
  mcpServerId: string | null;
  toolActivationReceiptId: string;
  toolActivationReceiptHash: string;
  toolManifestHash: string;
  evidenceTypeIds: string[];
  evidenceProducerIds: string[];
  routeExpiresAt: string;
  routeHash: string;
  createdAt: string;
}
export interface AutonomousActivationBinding {
  id: string;
  receiptId: string;
  sequence: number;
  bindingType: "launch" | "planning" | "plan_version" | "dispatch" | "resume" | "restart_recovery";
  subjectId: string;
  subjectDigest: string;
  runtimeGenerationHash: string;
  planId: string | null;
  stepId: string | null;
  actionId: string | null;
  contextPackId: string | null;
  providerTurnId: string | null;
  previousBindingHash: string | null;
  boundBy: string;
  boundAt: string;
  bindingHash: string;
}
export interface AutonomousActivationReceipt {
  id: string;
  schemaVersion: "2.4";
  missionId: string;
  runId: string;
  contractId: string;
  generation: number;
  contractVersion: number;
  contractHash: string;
  runtimeGenerationHash: string;
  modelAssignmentSetHash: string;
  evidencePolicyHash: string;
  brainContextPackId: string;
  brainContextPackHash: string;
  planning: AutonomousActivationPlanningSnapshot;
  selectedActionClassIds: string[];
  selectedActionClassCount: number;
  activatedActionClassCount: number;
  routeSetHash: string;
  issuedBy: string;
  issuedAt: string;
  expiresAt: string;
  receiptHash: string;
  items: AutonomousActivationReceiptItem[];
  bindings: AutonomousActivationBinding[];
}
export interface AutonomousActivationReceiptHistory {
  schemaVersion: "2.4";
  items: AutonomousActivationReceiptSummary[];
}
export interface AutonomousActivationReceiptDetail {
  schemaVersion: "2.4";
  summary: AutonomousActivationReceiptSummary;
  receipt: AutonomousActivationReceipt;
}
export interface ResumeRunBoundary {
  expectedRunVersion: number;
  expectedRunStatus: "blocked";
  expectedCheckpointId: string;
  expectedCheckpointStateHash: string;
  expectedCheckpointEventSequence: number;
}
export type RunControlInput =
  | { command: "pause" | "cancel"; reason: string }
  | { command: "resume"; reason: string; boundary: ResumeRunBoundary };
export interface RunSnapshot {
  schemaVersion: "2.4";
  run: RuntimeRun;
  latestCheckpoint: RuntimeCheckpoint | null;
  currentAutonomousActivationReceipt: AutonomousActivationReceiptSummary | null;
}
export interface RunPage { schemaVersion: "2.4"; items: RuntimeRun[]; nextCursor: string | null }

export type PlannedActionKind = "tool" | "provider_turn" | "replan" | "delegation" | "manual";
export interface PlannedAction {
  actionType: string; actionClass: string; target: string; arguments: Record<string, unknown>;
  intentSummary: string; kind: PlannedActionKind; idempotent: boolean; destructive: boolean;
}

export interface PlanStep {
  id: string; ordinal: number; phase: string; title: string; objective: string; status: string;
  assignedAgentId: string; riskClass: string; successCriteria: string[]; dependencyStepIds: string[]; action: PlannedAction;
  explanation: string; rationale: string; reversibility: string;
}

export interface RunPlan {
  id: string; runId: string; version: number; status: string; strategySummary: string;
  rationaleSummary: string | null; createdAt: string; activatedAt: string | null; steps: PlanStep[];
}

export interface PlansSnapshot { schemaVersion: "2.4"; items: RunPlan[] }
export type DecisionStatus = "pending" | "approved" | "manual" | "alternative" | "rejected" | "expired" | "cancelled";
export interface GuidedDecision {
  id: string; missionId: string; runId: string; stepId: string; status: DecisionStatus;
  actionFingerprint: string; requestedParameters: unknown; rationale: string; riskClass: string;
  reversibility: string; expiresAt: string; createdAt: string;
}
export interface DecisionsSnapshot { schemaVersion: "2.4"; items: GuidedDecision[] }
export interface PartialRunCollection {
  runs: RuntimeRun[];
  failures: Array<{ missionId: string; message: string }>;
  nextCursor: string | null;
}
export type GuidedDecisionControl = "approve" | "reject" | "manual-result" | "skip" | "stop";
export interface DecisionMutationResult {
  schemaVersion: "2.4";
  decisionId: string;
  status: string;
  action?: unknown;
  receipt?: unknown;
  run?: RuntimeRun;
}

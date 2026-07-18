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
export interface RunSnapshot { schemaVersion: "2.4"; run: RuntimeRun; latestCheckpoint: RuntimeCheckpoint | null }
export interface RunPage { schemaVersion: "2.4"; items: RuntimeRun[] }

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
export interface PartialRunCollection { runs: RuntimeRun[]; failures: Array<{ missionId: string; message: string }> }
export type GuidedDecisionControl = "approve" | "reject" | "manual-result" | "skip" | "stop";
export interface DecisionMutationResult {
  schemaVersion: "2.4";
  decisionId: string;
  status: string;
  action?: unknown;
  receipt?: unknown;
  run?: RuntimeRun;
}

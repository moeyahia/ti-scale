export type PlanChangeJson = string | number | boolean | null | readonly PlanChangeJson[] | { readonly [key: string]: PlanChangeJson };
export type PlanChangeStatus = "proposed" | "validated" | "rejected" | "applied" | "cancelled";
export type PlanStepActionKind = "tool" | "provider_turn" | "replan" | "delegation" | "manual";
export interface PlanStepRepresentationInput {
  readonly action: {
    readonly actionType: string;
    readonly target: string;
    readonly arguments: Readonly<Record<string, PlanChangeJson>>;
    readonly intentSummary: string;
    readonly kind: PlanStepActionKind;
    readonly idempotent: boolean;
    readonly destructive: boolean;
  };
  readonly explanation: string;
  readonly rationale: string;
  readonly reversibility: string;
}

export type PlanChangeOperation =
  | { readonly kind: "update_plan"; readonly strategySummary?: string; readonly rationaleSummary?: string | null }
  | { readonly kind: "update_step"; readonly stepId: string; readonly phase?: string; readonly title?: string; readonly objective?: string; readonly successCriteria?: readonly string[]; readonly actionClass?: string | null; readonly riskClass?: string | null; readonly assignedAgentId?: string | null }
  | { readonly kind: "add_step"; readonly clientStepId: string; readonly afterStepId?: string | null; readonly phase: string; readonly title: string; readonly objective: string; readonly successCriteria: readonly string[]; readonly dependencyStepIds: readonly string[]; readonly actionClass: string; readonly riskClass: "low" | "medium" | "high" | "critical"; readonly assignedAgentId: string; readonly representation: PlanStepRepresentationInput }
  | { readonly kind: "remove_step"; readonly stepId: string; readonly reason: string }
  | { readonly kind: "reorder_steps"; readonly orderedStepIds: readonly string[] }
  | { readonly kind: "set_dependencies"; readonly stepId: string; readonly dependencyStepIds: readonly string[] }
  | { readonly kind: "set_represented_action"; readonly stepId: string; readonly representation: PlanStepRepresentationInput };

export interface PlanChangeDiffEntry {
  readonly kind: "add" | "remove" | "replace" | "move";
  readonly path: string;
  readonly label: string;
  readonly before: PlanChangeJson;
  readonly after: PlanChangeJson;
}

export interface PlanChangeRequest {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly basePlanId: string;
  readonly basePlanVersion: number;
  readonly requestedBy: string;
  readonly requestText: string | null;
  readonly normalizedChange: { readonly summary: string; readonly operations: readonly PlanChangeOperation[] };
  readonly structuredDiff: readonly PlanChangeDiffEntry[];
  readonly affectedRefs: { readonly stepIds: readonly string[]; readonly addedClientStepIds: readonly string[]; readonly removedStepIds: readonly string[]; readonly agentIds: readonly string[]; readonly actionClasses: readonly string[] };
  readonly dependencyImpact: { readonly valid: boolean; readonly changed: boolean; readonly reordered: boolean; readonly issues: readonly string[] };
  readonly policyValidation: { readonly valid: boolean; readonly journey: "autonomous" | "guided"; readonly contractId: string | null; readonly checkedActionClasses: readonly string[]; readonly prohibitedActionClasses: readonly string[]; readonly reasons: readonly string[] };
  readonly readinessImpact: { readonly valid: boolean; readonly checkedAgentIds: readonly string[]; readonly unavailableAgentIds: readonly string[]; readonly reasons: readonly string[] };
  readonly budgetImpact: { readonly addedSteps: number; readonly removedSteps: number; readonly netStepChange: number; readonly durationEstimate: "not_observed"; readonly costEstimate: "not_observed"; readonly explanation: string };
  readonly inflightImpact: { readonly safeToApply: boolean; readonly runStatus: string; readonly leaseOwner: string | null; readonly activeStepIds: readonly string[]; readonly activeAssignmentIds: readonly string[]; readonly activeActionIds: readonly string[]; readonly pendingDecisionIds: readonly string[]; readonly queuedAssignmentIdsToCancel: readonly string[]; readonly requiresCheckpoint: boolean; readonly requiresCancellation: boolean; readonly reasons: readonly string[] };
  readonly status: PlanChangeStatus;
  readonly resultPlanId: string | null;
  readonly createdAt: string;
  readonly resolvedAt: string | null;
  readonly version: number;
}

export interface PlanChangeListResponse { readonly schemaVersion: "2.4"; readonly items: readonly PlanChangeRequest[] }
export interface PlanChangeDetailResponse { readonly schemaVersion: "2.4"; readonly request: PlanChangeRequest; readonly contextPackId: string | null }
export interface PlanChangeApplyResponse { readonly schemaVersion: "2.4"; readonly request: PlanChangeRequest; readonly resultPlanId: string; readonly resultPlanVersion: number; readonly contextPackId: string | null }

export interface CreatePlanChangeRequest {
  readonly basePlanId: string;
  readonly expectedRunVersion: number;
  readonly expectedPlanVersion: number;
  readonly requestText?: string;
  readonly operations: readonly PlanChangeOperation[];
}

export interface EditPlanChangeRequest {
  readonly expectedRequestVersion: number;
  readonly expectedRunVersion: number;
  readonly expectedPlanVersion: number;
  readonly requestText?: string;
  readonly operations: readonly PlanChangeOperation[];
}

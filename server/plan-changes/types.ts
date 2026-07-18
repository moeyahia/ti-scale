export type PlanChangeJson =
  | string
  | number
  | boolean
  | null
  | readonly PlanChangeJson[]
  | { readonly [key: string]: PlanChangeJson };

export type PlanChangeStatus = "proposed" | "validated" | "rejected" | "applied" | "cancelled";

export interface PlanUpdateOperation {
  readonly kind: "update_plan";
  readonly strategySummary?: string;
  readonly rationaleSummary?: string | null;
}

export interface PlanStepUpdateOperation {
  readonly kind: "update_step";
  readonly stepId: string;
  readonly phase?: string;
  readonly title?: string;
  readonly objective?: string;
  readonly successCriteria?: readonly string[];
  readonly actionClass?: string | null;
  readonly riskClass?: string | null;
  readonly assignedAgentId?: string | null;
}

export type PlanStepActionKind = "tool" | "provider_turn" | "replan" | "delegation" | "manual";

/**
 * Exact action representation reviewed with a plan amendment. Action class is
 * stored on the step and injected by the service so the two values cannot
 * drift. Guided decisions bind to this entire shape after activation.
 */
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

export interface PlanStepAddOperation {
  readonly kind: "add_step";
  readonly clientStepId: string;
  readonly afterStepId?: string | null;
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly successCriteria: readonly string[];
  readonly dependencyStepIds: readonly string[];
  readonly actionClass: string;
  readonly riskClass: "low" | "medium" | "high" | "critical";
  readonly assignedAgentId: string;
  readonly representation: PlanStepRepresentationInput;
}

export interface PlanStepRemoveOperation {
  readonly kind: "remove_step";
  readonly stepId: string;
  readonly reason: string;
}

export interface PlanStepOrderOperation {
  readonly kind: "reorder_steps";
  readonly orderedStepIds: readonly string[];
}

export interface PlanStepDependenciesOperation {
  readonly kind: "set_dependencies";
  readonly stepId: string;
  readonly dependencyStepIds: readonly string[];
}

export interface PlanStepRepresentationOperation {
  readonly kind: "set_represented_action";
  readonly stepId: string;
  readonly representation: PlanStepRepresentationInput;
}

export type PlanChangeOperation =
  | PlanUpdateOperation
  | PlanStepUpdateOperation
  | PlanStepAddOperation
  | PlanStepRemoveOperation
  | PlanStepOrderOperation
  | PlanStepDependenciesOperation
  | PlanStepRepresentationOperation;

export interface NormalizedPlanChange {
  readonly summary: string;
  readonly operations: readonly PlanChangeOperation[];
}

export interface PlanChangeDiffEntry {
  readonly kind: "add" | "remove" | "replace" | "move";
  readonly path: string;
  readonly label: string;
  readonly before: PlanChangeJson;
  readonly after: PlanChangeJson;
}

export interface PlanChangeAffectedRefs {
  readonly stepIds: readonly string[];
  readonly addedClientStepIds: readonly string[];
  readonly removedStepIds: readonly string[];
  readonly agentIds: readonly string[];
  readonly actionClasses: readonly string[];
}

export interface PlanChangeDependencyImpact {
  readonly valid: boolean;
  readonly changed: boolean;
  readonly reordered: boolean;
  readonly issues: readonly string[];
}

export interface PlanChangePolicyValidation {
  readonly valid: boolean;
  readonly journey: "autonomous" | "guided";
  readonly contractId: string | null;
  readonly checkedActionClasses: readonly string[];
  readonly prohibitedActionClasses: readonly string[];
  readonly reasons: readonly string[];
}

export interface PlanChangeReadinessImpact {
  readonly valid: boolean;
  readonly checkedAgentIds: readonly string[];
  readonly unavailableAgentIds: readonly string[];
  readonly reasons: readonly string[];
}

export interface PlanChangeBudgetImpact {
  readonly addedSteps: number;
  readonly removedSteps: number;
  readonly netStepChange: number;
  readonly durationEstimate: "not_observed";
  readonly costEstimate: "not_observed";
  readonly explanation: string;
}

export interface PlanChangeInflightImpact {
  readonly safeToApply: boolean;
  readonly runStatus: string;
  readonly leaseOwner: string | null;
  readonly activeStepIds: readonly string[];
  readonly activeAssignmentIds: readonly string[];
  readonly activeActionIds: readonly string[];
  readonly pendingDecisionIds: readonly string[];
  readonly queuedAssignmentIdsToCancel: readonly string[];
  readonly requiresCheckpoint: boolean;
  readonly requiresCancellation: boolean;
  readonly reasons: readonly string[];
}

export interface PlanChangeRequest {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly basePlanId: string;
  readonly basePlanVersion: number;
  readonly requestedBy: string;
  readonly requestText: string | null;
  readonly normalizedChange: NormalizedPlanChange;
  readonly structuredDiff: readonly PlanChangeDiffEntry[];
  readonly affectedRefs: PlanChangeAffectedRefs;
  readonly dependencyImpact: PlanChangeDependencyImpact;
  readonly policyValidation: PlanChangePolicyValidation;
  readonly readinessImpact: PlanChangeReadinessImpact;
  readonly budgetImpact: PlanChangeBudgetImpact;
  readonly inflightImpact: PlanChangeInflightImpact;
  readonly status: PlanChangeStatus;
  readonly resultPlanId: string | null;
  readonly createdAt: string;
  readonly resolvedAt: string | null;
  readonly version: number;
}

export interface CreatePlanChangeInput {
  readonly missionId: string;
  readonly runId: string;
  readonly basePlanId: string;
  readonly expectedRunVersion: number;
  readonly expectedPlanVersion: number;
  readonly requestText?: string;
  readonly operations: readonly PlanChangeOperation[];
}

export interface EditPlanChangeInput {
  readonly requestId: string;
  readonly expectedRequestVersion: number;
  readonly expectedRunVersion: number;
  readonly expectedPlanVersion: number;
  readonly requestText?: string;
  readonly operations: readonly PlanChangeOperation[];
}

export interface ApplyPlanChangeInput {
  readonly requestId: string;
  readonly expectedRequestVersion: number;
  readonly expectedRunVersion: number;
  readonly expectedPlanVersion: number;
}

export interface RejectPlanChangeInput {
  readonly requestId: string;
  readonly expectedRequestVersion: number;
  readonly reason: string;
}

export interface PlanChangeActor {
  readonly id: string;
  readonly type: "operator" | "reviewer" | "admin";
}

export class PlanChangeError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly category: "invalid_input" | "not_found" | "scope_conflict" | "state_conflict" | "policy_denied" | "dependency_missing" | "sensitive_data",
    readonly status: number = category === "not_found" ? 404 : category === "policy_denied" ? 403 : category === "invalid_input" || category === "sensitive_data" ? 400 : 409,
    readonly remediation?: string,
  ) {
    super(message);
    this.name = "PlanChangeError";
  }
}

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

/**
 * Rebuild a prior immutable plan as a newly reviewed version. The historical
 * record remains superseded and is never reactivated or mutated in place.
 */
export interface PlanVersionRestoreOperation {
  readonly kind: "restore_plan_version";
  readonly targetPlanId: string;
  /** Visible immutable version selected by the operator, used as a stale-history fence. */
  readonly targetPlanVersion: number;
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
  | PlanVersionRestoreOperation
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
  readonly affectedSubgraphStepIds: readonly string[];
  /** Base-plan steps in the proposal's direct or transitive affected subgraph. */
  readonly activeStepIds: readonly string[];
  readonly unaffectedActiveStepIds: readonly string[];
  readonly activeAssignmentIds: readonly string[];
  readonly unaffectedActiveAssignmentIds: readonly string[];
  readonly activeActionIds: readonly string[];
  readonly unaffectedActiveActionIds: readonly string[];
  readonly pendingDecisionIds: readonly string[];
  readonly unaffectedPendingDecisionIds: readonly string[];
  readonly queuedAssignmentIdsToCancel: readonly string[];
  readonly affectedActions: readonly PlanChangeAffectedAction[];
  readonly unaffectedActions: readonly PlanChangeAffectedAction[];
  readonly affectedAttackAttempts: readonly PlanChangeAffectedAttackAttempt[];
  readonly unaffectedAttackAttempts: readonly PlanChangeAffectedAttackAttempt[];
  readonly resolutionOptions: readonly [
    PlanChangeInflightResolutionOption,
    PlanChangeInflightResolutionOption,
  ];
  readonly requiresCheckpoint: boolean;
  readonly requiresCancellation: boolean;
  readonly reasons: readonly string[];
}

export interface PlanChangeAffectedAction {
  readonly id: string;
  readonly stepId: string | null;
  readonly actionType: string;
  readonly actionClass: string;
  readonly intentSummary: string;
  readonly target: string | null;
  readonly status: "queued" | "running";
  readonly idempotent: boolean;
  readonly destructive: boolean;
}

export interface PlanChangeAffectedAttackAttempt {
  readonly id: string;
  readonly stepId: string | null;
  readonly objective: string;
  readonly techniqueName: string;
  readonly actionClass: string;
  readonly status: string;
  readonly targetAssetId: string | null;
  readonly targetServiceId: string | null;
}

export type PlanChangeInflightResolutionMode =
  | "checkpoint_finish_idempotent_work"
  | "checkpoint_cancel_affected_work";

export interface PlanChangeInflightResolutionOption {
  readonly mode: PlanChangeInflightResolutionMode;
  readonly label: string;
  readonly consequence: string;
  readonly enabled: boolean;
  readonly disabledReason: string | null;
}

export type PlanChangeInflightResolutionStatus =
  | "waiting_for_terminal_work"
  | "ready_for_review"
  | "failed";

export interface PlanChangeInflightResolution {
  readonly id: string;
  readonly planChangeRequestId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly basePlanId: string;
  readonly mode: PlanChangeInflightResolutionMode;
  readonly status: PlanChangeInflightResolutionStatus;
  readonly affectedStepIds: readonly string[];
  readonly affectedAssignmentIds: readonly string[];
  readonly affectedActionIds: readonly string[];
  readonly affectedAttackAttemptIds: readonly string[];
  readonly affectedDecisionIds: readonly string[];
  readonly sourceCheckpointId: string;
  readonly sourceCheckpointStateHash: string;
  readonly sourceCheckpointEventSequence: number;
  readonly settleDeadlineAt: string;
  readonly lastHeartbeatAt: string;
  readonly failureReason: string | null;
  readonly freshRequestId: string | null;
  readonly requestedBy: string;
  readonly reason: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly resolvedAt: string | null;
  readonly version: number;
}

/**
 * Trusted runtime receipt for the exact live child records whose underlying
 * processes were stopped at an amendment boundary. Logical records may only
 * be closed after every identity is reconciled against canonical runtime
 * relationships.
 */
export interface PlanChangeAffectedWorkStopReceipt {
  readonly stoppedActionIds: readonly string[];
  readonly stoppedAssignmentIds: readonly string[];
  readonly stoppedAttackAttemptIds: readonly string[];
  readonly stoppedStepIds: readonly string[];
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

export interface ResolvePlanChangeInflightInput {
  readonly requestId: string;
  readonly mode: PlanChangeInflightResolutionMode;
  readonly expectedRequestVersion: number;
  readonly expectedRunVersion: number;
  readonly expectedPlanVersion: number;
  readonly reason: string;
}

export interface FinalizePlanChangeInflightInput {
  readonly requestId: string;
  readonly expectedResolutionVersion: number;
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

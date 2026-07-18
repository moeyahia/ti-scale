import type { JsonValue } from "../events";
import type { PlanningContextAttribution } from "../memory";
import type { BrainContextService, BrainProviderContextEnvelope } from "../brain-runtime";
import type {
  DurableAction,
  DurableActionKind,
  ExecutionPort,
  RunLeaseToken,
} from "../orchestration";
import type {
  FailureCategory,
  FailureSignal,
  Journey,
  ProgressSnapshot,
  RetryPolicyConfig,
  RunState,
} from "../supervisor";

export interface PlanningMission {
  readonly id: string;
  readonly name: string;
  readonly objective: string;
  readonly journey: Journey;
  readonly engagementId: string | null;
  readonly authorizationStatus: "unverified" | "verified" | "expired" | "revoked";
  readonly allowedTargets: readonly string[];
  readonly prohibitedTargets: readonly string[];
  readonly successCriteria: readonly string[];
  readonly memoryPolicy: Readonly<Record<string, unknown>>;
}

export interface PlanningRun {
  readonly id: string;
  readonly missionId: string;
  readonly journey: Journey;
  readonly state: RunState;
  readonly replanCount: number;
  readonly currentPlanVersion: number | null;
  readonly previousStrategySummary: string | null;
  readonly stateReason: string;
}

export type PlannedActionKind = DurableActionKind;

/** One represented action. Guided decisions bind to every field in this shape. */
export interface PlannedAction {
  /** For Autonomous, this value must be an allowed action class in the signed contract. */
  readonly actionType: string;
  readonly actionClass: string;
  readonly target: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly intentSummary: string;
  readonly kind: PlannedActionKind;
  readonly idempotent: boolean;
  readonly destructive: boolean;
}

export interface PlannedStep {
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly explanation: string;
  readonly rationale: string;
  readonly successCriteria: readonly string[];
  /** Zero-based ordinals of prerequisite steps in this same plan. */
  readonly dependencyOrdinals?: readonly number[];
  readonly assignedAgentId: string;
  readonly riskClass: "low" | "medium" | "high" | "critical";
  readonly reversibility: string;
  readonly action: PlannedAction;
}

export interface MissionPlanDraft {
  readonly strategySummary: string;
  readonly rationaleSummary: string;
  readonly steps: readonly PlannedStep[];
  /** Runtime-only exact provider usage; never part of the provider JSON schema. */
  readonly providerUsage?: ProviderUsageReport;
  /** Runtime-only citations committed only with lease-fenced plan activation. */
  readonly planningAttribution?: PlanningContextAttribution;
}

/** Exact usage as reported by the provider. Values are never estimated. */
export interface ProviderUsageReport {
  readonly providerTurnId?: string;
  /** Number of provider turns represented by this aggregate usage report. */
  readonly providerTurns?: number;
  readonly providerTokens?: number;
  readonly estimatedCost?: number;
  readonly exactTokenUsage: boolean;
  readonly exactCostUsage: boolean;
}

export interface MissionPlanPortResult {
  readonly plan: MissionPlanDraft;
  readonly usage?: ProviderUsageReport;
}

export interface MissionPlannerInput {
  readonly mission: PlanningMission;
  readonly run: PlanningRun;
  readonly rejectionReason?: string;
  /** Sanitized, explicitly disclosure-approved summaries only. */
  readonly brainContext: BrainProviderContextEnvelope;
}

/** Provider-neutral planning boundary. It must return real, bounded work—not fixtures. */
export interface MissionPlannerPort {
  plan(
    input: MissionPlannerInput,
    signal: AbortSignal,
  ): Promise<MissionPlanDraft | MissionPlanPortResult>;
}

export interface CompletionCriterion {
  readonly criterion: string;
  readonly satisfied: boolean;
  readonly explanation: string;
  readonly evidenceIds: readonly string[];
}

export interface MissionCompletionEvaluation {
  readonly success: boolean;
  readonly summary: string;
  readonly criteria: readonly CompletionCriterion[];
  /** Runtime-only exact provider usage; never inferred from response text. */
  readonly providerUsage?: ProviderUsageReport;
}

export interface MissionCompletionPortResult {
  readonly evaluation: MissionCompletionEvaluation;
  readonly usage?: ProviderUsageReport;
}

export interface MissionOutcomeEvaluatorInput {
  readonly mission: PlanningMission;
  readonly run: PlanningRun;
  readonly planId: string;
  readonly completedActionIds: readonly string[];
  /** Sanitized, explicitly disclosure-approved summaries only. */
  readonly brainContext: BrainProviderContextEnvelope;
}

/** Success is never inferred from terminal provider text alone. */
export interface MissionOutcomeEvaluatorPort {
  evaluate(
    input: MissionOutcomeEvaluatorInput,
    signal: AbortSignal,
  ): Promise<MissionCompletionEvaluation | MissionCompletionPortResult>;
}

export interface ExecutionResult {
  readonly actionId: string;
  readonly runId: string;
  readonly actionFingerprint: string;
  readonly success: boolean;
  readonly summary: string;
  readonly progress: ProgressSnapshot;
  readonly failure?: FailureSignal;
  readonly failureCategory?: FailureCategory;
  /** Provider Retry-After converted to milliseconds, when explicitly reported. */
  readonly retryAfterMs?: number;
  readonly usage?: {
    readonly wallClockMs?: number;
    readonly providerTokens?: number;
    readonly estimatedCost?: number;
    readonly evidenceBytes?: number;
    readonly artifactBytes?: number;
  };
  readonly circuitKey?: string;
}

export interface ExecutionResultReceipt {
  readonly accepted: boolean;
  readonly duplicate: boolean;
  readonly actionId: string;
  readonly runId: string;
  readonly runState: RunState;
  readonly nextAction: string | null;
  /** Canonical retained evidence made available to evaluation by this result. */
  readonly evidenceIds?: readonly string[];
}

export interface ExecutionResultSink {
  acceptExecutionResult(result: ExecutionResult): Promise<ExecutionResultReceipt>;
}

/**
 * Existing provider runtimes can implement ExecutionPort and invoke the bound
 * sink from their asynchronous terminal callback. `dispatch` still means
 * accepted, not completed.
 */
export interface ResultAwareExecutionPort extends ExecutionPort {
  bindResultSink?(sink: ExecutionResultSink): void | (() => void);
}

export interface RuntimeLifecycleResult {
  readonly recoveredRuns: number;
  readonly scheduledRuns: number;
}

/**
 * Optimistic boundary carried by every operator-initiated resume.
 *
 * The checkpoint fields identify the exact durable state the operator
 * inspected. `expectedRunStatus` is intentionally a literal: resuming is not
 * a generic transition out of any stopped-looking state.
 */
export interface ResumeRunBoundary {
  readonly expectedRunVersion: number;
  readonly expectedRunStatus: "blocked";
  readonly expectedCheckpointId: string;
  readonly expectedCheckpointStateHash: string;
  readonly expectedCheckpointEventSequence: number;
}

export interface MissionRuntimeOptions {
  readonly database: import("../db").SqliteDatabase;
  readonly planner: MissionPlannerPort;
  readonly outcomeEvaluator: MissionOutcomeEvaluatorPort;
  readonly execution: ResultAwareExecutionPort;
  /** Injectable for availability/fault policies; defaults to the local V2 Brain. */
  readonly brainContext?: BrainContextService;
  readonly workerId?: string;
  readonly scanIntervalMs?: number;
  readonly leaseTtlMs?: number;
  readonly decisionTtlMs?: number;
  readonly maxPlanSteps?: number;
  /** Shared bounded retry policy; defaults to two transient retries. */
  readonly retryPolicy?: Partial<RetryPolicyConfig>;
  /** Injectable entropy source for deterministic retry timing tests. */
  readonly retryRandom?: () => number;
  readonly now?: () => Date;
  /** Test-only fault injection immediately after a durable predecessor commit. */
  readonly crashAfterCommit?: (
    point:
      | "plan_ready_to_dispatch"
      | "planning_retry_scheduled"
      | "planning_retry_started"
      | "action_reserved_before_dispatch"
      | "guided_approval_to_dispatch"
      | "action_result_to_advance"
      | "manual_result_to_advance"
      | "guided_failure_to_recover"
      | "step_advance_to_evaluation"
      | "cancellation_cleanup_before_finalize"
      | "cancellation_terminal_before_runtime_cleanup"
      | "pause_projection_committed"
      | "resume_projection_committed",
    context: Readonly<{ runId: string; sourceId?: string }>,
  ) => void;
}

export interface StoredPlanStep {
  readonly id: string;
  readonly ordinal: number;
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly status: string;
  readonly assignedAgentId: string;
  readonly riskClass: string;
  readonly successCriteria: readonly string[];
  /** Stable IDs of prerequisite steps in this exact immutable plan version. */
  readonly dependencyStepIds: readonly string[];
  readonly action: PlannedAction;
  readonly explanation: string;
  readonly rationale: string;
  readonly reversibility: string;
}

export interface StoredPlan {
  readonly id: string;
  readonly runId: string;
  readonly version: number;
  readonly status: string;
  readonly strategySummary: string;
  readonly rationaleSummary: string | null;
  readonly createdAt: string;
  readonly activatedAt: string | null;
  readonly steps: readonly StoredPlanStep[];
}

export interface GuidedDecisionProjection {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string;
  readonly status: string;
  readonly actionFingerprint: string;
  readonly requestedParameters: JsonValue;
  readonly rationale: string;
  readonly riskClass: string;
  readonly reversibility: string;
  readonly expiresAt: string;
  readonly createdAt: string;
}

export interface GuidedDecisionSkipResult {
  readonly decisionId: string;
  readonly status: "cancelled";
  readonly skippedStepId: string;
  readonly nextDecisionId: string | null;
  readonly runId: string;
  readonly runState: RunState;
  readonly nextAction: string | null;
  readonly duplicate: boolean;
}

export interface RuntimeActionContext {
  readonly action: DurableAction;
  lease: RunLeaseToken;
  readonly before: ProgressSnapshot;
  heartbeat?: ReturnType<typeof setInterval>;
  completing: boolean;
}

export class CommandRuntimeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly options: {
      readonly humanMessage?: string;
      readonly retryable?: boolean;
      readonly category?: string;
      readonly details?: JsonValue;
      readonly remediation?: string;
    } = {},
  ) {
    super(message);
    this.name = "CommandRuntimeError";
  }
}

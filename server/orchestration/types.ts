import type { JsonValue } from "../events";
import type {
  ActionIntent,
  BudgetState,
  BudgetValues,
  CircuitBreakerSnapshot,
  FailureCategory,
  FailureSignal,
  Journey,
  ProgressSnapshot,
  RunState,
  SupervisedRun,
} from "../supervisor";

export interface RunLeaseToken {
  readonly runId: string;
  readonly ownerId: string;
  readonly fence: number;
  readonly expiresAt: string;
}

export interface DurableControlState {
  readonly budget: BudgetState;
  readonly retryCount: number;
  readonly replanCount: number;
  readonly circuits: Readonly<Record<string, CircuitBreakerSnapshot>>;
  readonly progress: ProgressSnapshot;
  /** Exact delayed provider-planning retry currently authorized to run. */
  readonly planningRetry?: {
    readonly continuationId: string;
    readonly failureCategory: FailureCategory;
    readonly retryCount: number;
    readonly notBefore: string;
    readonly errorCode: string;
  };
  /** Durable recovery instruction. A retry may not execute before `notBefore`. */
  readonly recovery?: {
    readonly kind: "retry" | "replan";
    readonly failedActionId: string;
    readonly notBefore: string;
    readonly reason: string;
  };
}

export interface DurableRun {
  readonly run: SupervisedRun;
  readonly contractId: string | null;
  readonly lease: RunLeaseToken | null;
  readonly control: DurableControlState;
}

/**
 * `manual` is a durable representation of work the Guided operator performs
 * outside the execution port. It may be completed only by an operator-supplied
 * result and is never dispatchable by an Autonomous run.
 */
export type DurableActionKind = "tool" | "provider_turn" | "replan" | "delegation" | "manual";

export interface DurableActionIntent extends ActionIntent {
  readonly actionClass: string;
  readonly intentSummary: string;
  readonly kind: DurableActionKind;
  readonly idempotent: boolean;
  readonly destructive: boolean;
  readonly assignmentId?: string;
  readonly parentActionId?: string;
  readonly contextPackId?: string;
  readonly traceId?: string;
  readonly spanId?: string;
}

export interface DurableAction {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string;
  readonly actionType: string;
  readonly actionClass: string;
  readonly fingerprint: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly target: string;
  readonly kind: DurableActionKind;
  readonly intentSummary: string;
  readonly status: "queued" | "running" | "succeeded" | "failed" | "cancelled" | "timed_out" | "denied";
  readonly idempotent: boolean;
  readonly destructive: boolean;
  readonly guidedDecisionId: string | null;
  readonly contractId: string | null;
  readonly contextPackId: string | null;
  readonly resultSummary: string | null;
  readonly errorCategory: FailureCategory | null;
  readonly retryCount: number;
  readonly progressSignature: string | null;
  readonly createdAt: string;
  readonly startedAt: string | null;
  readonly endedAt: string | null;
}

export interface ExecutionPort {
  /** Resolves once work has been accepted by the execution boundary, not when it completes. */
  dispatch(action: DurableAction, signal: AbortSignal): Promise<void>;
  /** Resume only a previously persisted action classified as safe and idempotent. */
  resume(action: DurableAction, signal: AbortSignal): Promise<void>;
  /** Must resolve only after child work has cooperatively stopped and cleanup completed. */
  cancelRun(runId: string, reason: string): Promise<void>;
}

export interface StartActionInput {
  readonly lease: RunLeaseToken;
  readonly intent: DurableActionIntent;
  readonly guidedDecisionId?: string;
  readonly budgetDelta?: BudgetValues;
}

export interface StartActionResult {
  readonly action: DurableAction;
  readonly lease: RunLeaseToken;
  readonly eventSequence: number;
  readonly checkpointId: string;
}

export interface CompleteActionInput {
  readonly lease: RunLeaseToken;
  readonly actionId: string;
  readonly success: boolean;
  readonly resultSummary: string;
  readonly before: ProgressSnapshot;
  readonly after: ProgressSnapshot;
  readonly failure?: FailureSignal;
  readonly failureCategory?: FailureCategory;
  readonly retryAfterMs?: number;
  readonly budgetDelta?: BudgetValues;
  readonly circuitKey?: string;
}

export interface CompleteActionResult {
  readonly action: DurableAction;
  readonly run: DurableRun;
  readonly directive: "continue" | "retry" | "replan" | "recover" | "blocked" | "failed";
  readonly reason: string;
  readonly loopKinds: readonly string[];
  readonly eventSequence: number;
  readonly checkpointId: string;
}

export interface DurableTransitionResult {
  readonly run: DurableRun;
  readonly eventSequence: number;
  readonly checkpointId: string;
}

export type StartupRecoveryDisposition =
  | "restarted_planning"
  | "resumed_idempotently"
  | "blocked_for_review"
  | "failed_safely";

export interface StartupRecoveryResult {
  readonly runId: string;
  readonly disposition: StartupRecoveryDisposition;
  readonly actionIds: readonly string[];
  readonly reason: string;
}

export interface PersistedCheckpointState {
  readonly schemaVersion: 1;
  readonly run: {
    readonly id: string;
    readonly missionId: string;
    readonly journey: Journey;
    readonly state: RunState;
    readonly stateVersion: number;
    readonly reason: string;
    readonly leaseOwner: string | null;
    readonly leaseExpiresAt: string | null;
  };
  readonly control: {
    readonly budget: JsonValue;
    readonly retryCount: number;
    readonly replanCount: number;
    readonly circuits: JsonValue;
    readonly progress: JsonValue;
    readonly planningRetry?: JsonValue;
    readonly recovery?: JsonValue;
  };
  readonly completedActionIds: readonly string[];
  readonly inFlightActions: readonly {
    readonly id: string;
    readonly status: string;
    readonly idempotent: boolean;
    readonly destructive: boolean;
  }[];
  readonly lastEventSequence: number;
}

export class DurableOrchestrationError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "DurableOrchestrationError";
  }
}

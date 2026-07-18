import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { RuntimeContinuationRepository } from "../command-runtime/RuntimeContinuationRepository";
import {
  CircuitBreaker,
  RunSupervisor,
  allowedRunTransitions,
  checkBudget,
  classifyFailure,
  classifyInFlightAction,
  isTerminalRunState,
  type BudgetValues,
  type FailureCategory,
  type RunState,
  type SupervisedRun,
} from "../supervisor";
import { ActionRepository } from "./ActionRepository";
import { CheckpointRepository } from "./CheckpointRepository";
import { RunRepository } from "./RunRepository";
import {
  DurableOrchestrationError,
  type CompleteActionInput,
  type CompleteActionResult,
  type DurableAction,
  type DurableControlState,
  type DurableRun,
  type DurableTransitionResult,
  type ExecutionPort,
  type RunLeaseToken,
  type StartActionInput,
  type StartActionResult,
  type StartupRecoveryResult,
} from "./types";

export interface DurableRunCoordinatorOptions {
  readonly database: SqliteDatabase;
  readonly execution: ExecutionPort;
  readonly supervisor?: RunSupervisor;
  readonly now?: () => Date;
  readonly leaseTtlMs?: number;
  readonly afterActionCommit?: (action: DurableAction) => void;
  readonly afterCancellationCleanup?: (runId: string) => void;
}

export type PlanningRetryScheduleResult =
  | {
      readonly scheduled: true;
      readonly run: DurableRun;
      readonly continuationId: string;
      readonly retryCount: number;
      readonly notBefore: string;
      readonly delayMs: number;
      readonly eventSequence: number;
      readonly checkpointId: string;
    }
  | {
      readonly scheduled: false;
      readonly reason:
        | "non_retryable"
        | "retry_budget_exhausted"
        | "provider_retry_after_exceeds_bound"
        | "signed_budget_exhausted";
      readonly exhausted: readonly string[];
    };

function bumpedRun(run: SupervisedRun, now: string, reason: string): SupervisedRun {
  return {
    ...run,
    stateVersion: run.stateVersion + 1,
    stateReason: reason,
    updatedAt: now,
  };
}

function leaseDisposition(state: RunState): "keep" | "clear" {
  return state === "waiting_guided_decision" || state === "blocked" || isTerminalRunState(state)
    ? "clear"
    : "keep";
}

function startBudget(kind: StartActionInput["intent"]["kind"]): BudgetValues {
  switch (kind) {
    case "provider_turn": return { providerTurns: 1, concurrency: 1 };
    case "replan": return { replans: 1 };
    case "delegation": return { concurrency: 1 };
    case "manual": return {};
    default: return { toolCalls: 1, concurrency: 1 };
  }
}

function addBudget(left: BudgetValues, right: BudgetValues): BudgetValues {
  const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
  const output: Record<string, number> = {};
  for (const key of keys) {
    const value = (left as Record<string, number | undefined>)[key] ?? 0;
    const increment = (right as Record<string, number | undefined>)[key] ?? 0;
    output[key] = value + increment;
  }
  return output as BudgetValues;
}

function withoutWallClock(delta: BudgetValues): BudgetValues {
  const { wallClockMs: _ignored, ...rest } = delta;
  return rest;
}

function elapsedUsage(run: DurableRun, now: string): BudgetValues {
  const usage = { ...run.control.budget.usage };
  if (run.run.startedAt) {
    const started = Date.parse(run.run.startedAt);
    const current = Date.parse(now);
    if (Number.isFinite(started) && Number.isFinite(current)) {
      // Wall time is an absolute high-water mark, never an accumulation of
      // action latencies. This includes planning, recovery delays, and idle
      // provider/tool time without double counting overlapping work.
      usage.wallClockMs = Math.max(usage.wallClockMs ?? 0, current - started);
    }
  }
  return usage;
}

interface DeniedActionStart {
  readonly denied: true;
  readonly code: string;
  readonly message: string;
}

export class DurableRunCoordinator {
  private readonly runs: RunRepository;
  private readonly actions: ActionRepository;
  private readonly checkpoints: CheckpointRepository;
  private readonly events: EventRepository;
  private readonly continuations: RuntimeContinuationRepository;
  private readonly supervisor: RunSupervisor;
  private readonly now: () => Date;
  private readonly leaseTtlMs: number;
  private readonly afterActionCommit?: (action: DurableAction) => void;
  private readonly afterCancellationCleanup?: (runId: string) => void;
  private readonly controllers = new Map<string, AbortController>();

  constructor(
    private readonly database: SqliteDatabase,
    private readonly execution: ExecutionPort,
    options: Omit<DurableRunCoordinatorOptions, "database" | "execution"> = {},
  ) {
    this.runs = new RunRepository(database);
    this.actions = new ActionRepository(database);
    this.checkpoints = new CheckpointRepository(database, this.actions);
    this.events = new EventRepository(database);
    this.continuations = new RuntimeContinuationRepository(database);
    this.supervisor = options.supervisor ?? new RunSupervisor();
    this.now = options.now ?? (() => new Date());
    this.leaseTtlMs = options.leaseTtlMs ?? 30_000;
    this.afterActionCommit = options.afterActionCommit;
    this.afterCancellationCleanup = options.afterCancellationCleanup;
    if (!Number.isFinite(this.leaseTtlMs) || this.leaseTtlMs <= 0) {
      throw new Error("leaseTtlMs must be positive");
    }
  }

  private timestamp(): string {
    return this.now().toISOString();
  }

  private load(runId: string): DurableRun {
    const run = this.runs.get(runId);
    return {
      ...run,
      control: this.checkpoints.restoreControl(runId, run.control),
    };
  }

  private signal(runId: string): AbortSignal {
    let controller = this.controllers.get(runId);
    if (!controller || controller.signal.aborted) {
      controller = new AbortController();
      this.controllers.set(runId, controller);
    }
    return controller.signal;
  }

  acquireRunLease(runId: string, ownerId: string, ttlMs = this.leaseTtlMs): RunLeaseToken {
    if (!ownerId.trim()) throw new DurableOrchestrationError("invalid_lease_owner", "Lease owner is required");
    return inImmediateTransaction(this.database, () =>
      this.runs.acquire(runId, ownerId.trim(), this.timestamp(), ttlMs));
  }

  heartbeatRunLease(token: RunLeaseToken, ttlMs = this.leaseTtlMs): RunLeaseToken {
    return inImmediateTransaction(this.database, () =>
      this.runs.heartbeat(token, this.timestamp(), ttlMs));
  }

  getRun(runId: string): DurableRun {
    return this.load(runId);
  }

  getLatestCheckpoint(runId: string) {
    return this.checkpoints.latest(runId);
  }

  /** Account a provider/planning turn and the current signed-run elapsed time. */
  accountUsage(input: {
    readonly lease: RunLeaseToken;
    readonly delta?: BudgetValues;
    readonly phase: string;
    readonly providerTurnId?: string;
  }): {
    readonly run: DurableRun;
    readonly allowed: boolean;
    readonly exhausted: readonly string[];
    readonly eventSequence: number;
    readonly checkpointId: string;
  } {
    const now = this.timestamp();
    return inImmediateTransaction(this.database, () => {
      const current = this.load(input.lease.runId);
      this.runs.assertLease(current, input.lease, now);
      const budget = checkBudget({
        limits: current.control.budget.limits,
        usage: elapsedUsage(current, now),
      }, withoutWallClock(input.delta ?? {}));
      const reason = budget.allowed
        ? `${input.phase} usage accounted from canonical runtime telemetry`
        : `Budget safe stop during ${input.phase}: ${budget.exhausted.join(", ")}`;
      const nextRun = budget.allowed
        ? bumpedRun(current.run, now, reason)
        : this.supervisor.transition(current.run, "blocked", { reason, now }).run;
      const control: DurableControlState = {
        ...current.control,
        budget: { limits: current.control.budget.limits, usage: budget.projected },
        ...(budget.allowed ? {} : { recovery: undefined }),
      };
      const persisted = this.runs.persistMutation({
        current,
        nextRun,
        control,
        now,
        lease: budget.allowed ? "keep" : "clear",
      });
      const event = this.events.append({
        missionId: persisted.run.missionId,
        runId: persisted.run.id,
        journey: persisted.run.journey,
        eventType: budget.allowed ? "run.budget_accounted" : "run.budget_exhausted",
        actorType: "system",
        summary: reason,
        payload: {
          phase: input.phase,
          providerTurnId: input.providerTurnId ?? null,
          exactDelta: withoutWallClock(input.delta ?? {}),
          wallClockMs: budget.projected.wallClockMs ?? 0,
          exhausted: [...budget.exhausted],
        },
      });
      const checkpoint = this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
      return {
        run: persisted,
        allowed: budget.allowed,
        exhausted: budget.exhausted,
        eventSequence: event.sequence,
        checkpointId: checkpoint.id,
      };
    });
  }

  /**
   * Atomically account one failed planning turn and reserve one bounded retry.
   * The retry is represented only by its exact delayed continuation; no timer
   * or ambient runnable-run scan is allowed to recreate it.
   */
  schedulePlanningRetry(input: {
    readonly lease: RunLeaseToken;
    readonly category: FailureCategory;
    readonly errorCode: string;
    readonly retryAfterMs?: number;
    readonly random?: () => number;
  }): PlanningRetryScheduleResult {
    const now = this.timestamp();
    return inImmediateTransaction(this.database, () => {
      const current = this.load(input.lease.runId);
      this.runs.assertLease(current, input.lease, now);
      if (current.run.journey !== "autonomous") {
        return { scheduled: false, reason: "non_retryable", exhausted: [] };
      }
      const decision = this.supervisor.decideRecovery({
        journey: "autonomous",
        category: input.category,
        retriesUsed: current.control.retryCount,
        retrySafe: true,
        inContract: true,
        materiallyNewReplanAvailable: false,
        replanBudgetAvailable: false,
        ...(input.retryAfterMs === undefined ? {} : { retryAfterMs: input.retryAfterMs }),
        ...(input.random ? { random: input.random } : {}),
      }).retry;
      if (!decision.retry) {
        return {
          scheduled: false,
          reason: decision.reason === "retry_budget_exhausted"
            ? "retry_budget_exhausted"
            : decision.reason === "provider_retry_after_exceeds_bound"
              ? "provider_retry_after_exceeds_bound"
              : "non_retryable",
          exhausted: [],
        };
      }

      const delayMs = decision.delayMs ?? 0;
      const notBefore = new Date(Date.parse(now) + delayMs).toISOString();
      const failureBudget = checkBudget({
        limits: current.control.budget.limits,
        usage: elapsedUsage(current, now),
      }, { providerTurns: 1, retries: 1 });
      const nextTurnBudget = failureBudget.allowed
        ? checkBudget({
            limits: current.control.budget.limits,
            usage: failureBudget.projected,
          }, { providerTurns: 1 })
        : failureBudget;
      const wallClockLimit = current.control.budget.limits.wallClockMs;
      const retryExceedsWallClock = wallClockLimit !== undefined && current.run.startedAt !== undefined
        && Date.parse(notBefore) - Date.parse(current.run.startedAt) > wallClockLimit;
      if (!failureBudget.allowed || !nextTurnBudget.allowed || retryExceedsWallClock) {
        const exhausted = new Set([
          ...failureBudget.exhausted,
          ...nextTurnBudget.exhausted,
          ...(retryExceedsWallClock ? ["wallClockMs"] : []),
        ]);
        return {
          scheduled: false,
          reason: "signed_budget_exhausted",
          exhausted: [...exhausted],
        };
      }

      const retryCount = current.control.retryCount + 1;
      const continuation = this.continuations.enqueue({
        runId: current.run.id,
        kind: "planning_retry_to_dispatch",
        sourceId: `planning-retry-${retryCount}`,
        payload: {
          failureCategory: input.category,
          retryCount: String(retryCount),
          errorCode: input.errorCode,
        },
        now,
        availableAt: notBefore,
      });
      const reason = `Autonomous planning retry ${retryCount} scheduled after transient ${input.category}; eligible at ${notBefore}`;
      const nextRun = bumpedRun(current.run, now, reason);
      const control: DurableControlState = {
        ...current.control,
        budget: {
          limits: current.control.budget.limits,
          usage: failureBudget.projected,
        },
        retryCount,
        planningRetry: {
          continuationId: continuation.id,
          failureCategory: input.category,
          retryCount,
          notBefore,
          errorCode: input.errorCode,
        },
      };
      const persisted = this.runs.persistMutation({
        current,
        nextRun,
        control,
        now,
        lease: "clear",
      });
      const event = this.events.append({
        missionId: persisted.run.missionId,
        runId: persisted.run.id,
        journey: persisted.run.journey,
        eventType: "run.planning_retry_scheduled",
        actorType: "system",
        summary: reason,
        payload: {
          continuationId: continuation.id,
          failureCategory: input.category,
          errorCode: input.errorCode,
          retryCount,
          nextEligibility: notBefore,
          delayMs,
          retryAfterMs: input.retryAfterMs ?? null,
        },
      });
      const checkpoint = this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
      return {
        scheduled: true,
        run: persisted,
        continuationId: continuation.id,
        retryCount,
        notBefore,
        delayMs,
        eventSequence: event.sequence,
        checkpointId: checkpoint.id,
      };
    });
  }

  /** Consume only the exact eligible retry before opening its provider turn. */
  beginScheduledPlanningRetry(input: {
    readonly lease: RunLeaseToken;
    readonly continuationId: string;
  }): DurableTransitionResult {
    const now = this.timestamp();
    return inImmediateTransaction(this.database, () => {
      const current = this.load(input.lease.runId);
      this.runs.assertLease(current, input.lease, now);
      const retry = current.control.planningRetry;
      if (!retry || retry.continuationId !== input.continuationId) {
        throw new DurableOrchestrationError(
          "planning_retry_fence_mismatch",
          "The planning retry continuation is no longer the exact durable retry",
        );
      }
      if (Date.parse(retry.notBefore) > Date.parse(now)) {
        throw new DurableOrchestrationError(
          "planning_retry_not_eligible",
          `Planning retry is not eligible before ${retry.notBefore}`,
        );
      }
      const reason = `Autonomous planning retry ${retry.retryCount} started from its exact durable continuation`;
      const persisted = this.runs.persistMutation({
        current,
        nextRun: bumpedRun(current.run, now, reason),
        control: { ...current.control, planningRetry: undefined },
        now,
        lease: "keep",
      });
      const event = this.events.append({
        missionId: persisted.run.missionId,
        runId: persisted.run.id,
        journey: persisted.run.journey,
        eventType: "run.planning_retry_started",
        actorType: "worker",
        actorId: input.lease.ownerId,
        summary: reason,
        payload: {
          continuationId: input.continuationId,
          failureCategory: retry.failureCategory,
          retryCount: retry.retryCount,
          eligibleAt: retry.notBefore,
        },
      });
      const checkpoint = this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
      return { run: persisted, eventSequence: event.sequence, checkpointId: checkpoint.id };
    });
  }

  transitionRun(input: {
    readonly lease: RunLeaseToken;
    readonly to: RunState;
    readonly reason: string;
    readonly guidedDecisionId?: string;
  }): DurableTransitionResult {
    const now = this.timestamp();
    return inImmediateTransaction(this.database, () => {
      const current = this.load(input.lease.runId);
      this.runs.assertLease(current, input.lease, now);
      let contractConfirmed = false;
      if (current.run.journey === "autonomous" && input.to === "running") {
        const contract = this.runs.autonomousContract(current);
        contractConfirmed = Boolean(
          contract &&
          contract.status === "signed" &&
          contract.version === current.run.contractVersion,
        );
      }
      if (current.run.journey === "guided" && input.to === "waiting_guided_decision") {
        const decision = input.guidedDecisionId
          ? this.runs.guidedDecision(input.guidedDecisionId)
          : undefined;
        if (!decision || decision.runId !== current.run.id || decision.status !== "pending") {
          throw new DurableOrchestrationError(
            "guided_decision_not_pending",
            "Guided waiting state requires one real pending decision for this run",
          );
        }
      }
      const result = this.supervisor.transition(current.run, input.to, {
        reason: input.reason,
        now,
        contractConfirmed,
        guidedDecisionId: input.guidedDecisionId,
      });
      const persisted = this.runs.persistMutation({
        current,
        nextRun: result.run,
        control: current.control,
        now,
        lease: leaseDisposition(result.run.state),
      });
      const event = this.events.append({
        missionId: persisted.run.missionId,
        runId: persisted.run.id,
        journey: persisted.run.journey,
        eventType: "run.state_changed",
        actorType: "worker",
        actorId: input.lease.ownerId,
        summary: result.events[0]!.summary,
        payload: {
          from: current.run.state,
          to: persisted.run.state,
          reason: persisted.run.stateReason,
          stateVersion: persisted.run.stateVersion,
        },
      });
      const checkpoint = this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
      return { run: persisted, eventSequence: event.sequence, checkpointId: checkpoint.id };
    });
  }

  async startAction(input: StartActionInput): Promise<StartActionResult> {
    const now = this.timestamp();
    const committed: StartActionResult | DeniedActionStart = inImmediateTransaction(this.database, () => {
      const current = this.load(input.lease.runId);
      this.runs.assertLease(current, input.lease, now);
      if (input.intent.runId !== current.run.id || input.intent.missionId !== current.run.missionId) {
        throw new DurableOrchestrationError("action_run_mismatch", "Action belongs to another run or mission");
      }
      if (input.intent.kind === "manual") {
        throw new DurableOrchestrationError(
          current.run.journey === "autonomous"
            ? "autonomous_manual_action_forbidden"
            : "guided_manual_action_requires_operator_result",
          current.run.journey === "autonomous"
            ? "Autonomous runs cannot depend on an operator-executed manual action"
            : "Manual Guided actions are completed only by an operator-supplied result",
        );
      }

      let workingRun = current.run;
      let transitionSummary: string | undefined;
      let guidedDecision = input.guidedDecisionId
        ? this.runs.guidedDecision(input.guidedDecisionId)
        : undefined;
      if (current.run.journey === "guided" && current.run.state === "waiting_guided_decision") {
        if (!guidedDecision || guidedDecision.status !== "authorized") {
          throw new DurableOrchestrationError("guided_decision_not_authorized", "The exact Guided decision is not approved");
        }
        const waitingRun = { ...current.run, pendingGuidedDecisionId: guidedDecision.id };
        const transition = this.supervisor.transition(waitingRun, "running", {
          reason: `Operator authorized exact Guided decision ${guidedDecision.id}`,
          now,
          guidedDecisionId: guidedDecision.id,
        });
        workingRun = transition.run;
        transitionSummary = transition.events[0]!.summary;
      }

      const authorization = this.supervisor.authorizeAction({
        run: workingRun,
        action: input.intent,
        now,
        autonomousContract:
          current.run.journey === "autonomous" ? this.runs.autonomousContract(current) : undefined,
        guidedDecision,
      });
      if (!authorization.allowed) {
        if (
          current.run.journey === "autonomous" &&
          authorization.reason.startsWith("autonomous_")
        ) {
          return this.persistActionDenial(
            current,
            now,
            input.lease.ownerId,
            authorization.reason,
            authorization.humanMessage,
          );
        }
        throw new DurableOrchestrationError(authorization.reason, authorization.humanMessage);
      }
      if (current.run.journey === "autonomous") {
        const canonical = this.runs.authorizeAutonomousIntent(current, input.intent);
        if (!canonical.allowed) {
          return this.persistActionDenial(
            current,
            now,
            input.lease.ownerId,
            canonical.code,
            canonical.humanMessage,
          );
        }
      } else {
        const canonical = this.runs.authorizeGuidedIntent(current, input.intent);
        if (!canonical.allowed) {
          return this.persistActionDenial(
            current,
            now,
            input.lease.ownerId,
            canonical.code,
            canonical.humanMessage,
          );
        }
      }

      const delta = addBudget(startBudget(input.intent.kind), withoutWallClock(input.budgetDelta ?? {}));
      const budget = checkBudget({
        limits: current.control.budget.limits,
        usage: elapsedUsage(current, now),
      }, delta);
      if (!budget.allowed) {
        throw new DurableOrchestrationError(
          "budget_exhausted",
          `Action would exceed budget: ${budget.exhausted.join(", ")}`,
        );
      }
      const control: DurableControlState = {
        ...current.control,
        budget: { limits: current.control.budget.limits, usage: budget.projected },
        recovery: undefined,
      };
      if (workingRun.stateVersion === current.run.stateVersion) {
        workingRun = bumpedRun(workingRun, now, `Authorized action: ${input.intent.intentSummary}`);
      }
      const action = this.actions.create({
        intent: input.intent,
        fingerprint: authorization.actionFingerprint,
        guidedDecisionId: input.guidedDecisionId,
        contractId: current.contractId ?? undefined,
        now,
      });
      if (input.intent.assignmentId) {
        this.database.prepare(`
          UPDATE assignments SET status = 'active',
            started_at = COALESCE(started_at, ?), updated_at = ?
          WHERE id = ? AND run_id = ? AND step_id = ?
        `).run(now, now, input.intent.assignmentId, input.intent.runId, input.intent.stepId);
      }
      this.database.prepare(`
        UPDATE plan_steps SET status = 'running',
          started_at = COALESCE(started_at, ?), updated_at = ?
        WHERE id = ? AND run_id = ?
      `).run(now, now, input.intent.stepId, input.intent.runId);
      const persisted = this.runs.persistMutation({
        current,
        nextRun: workingRun,
        control,
        now,
        lease: "keep",
      });
      if (transitionSummary) {
        this.events.append({
          missionId: persisted.run.missionId,
          runId: persisted.run.id,
          journey: persisted.run.journey,
          eventType: "run.state_changed",
          actorType: "operator",
          summary: transitionSummary,
          payload: { from: current.run.state, to: "running", guidedDecisionId: input.guidedDecisionId ?? null },
        });
      }
      const event = this.events.append({
        missionId: action.missionId,
        runId: action.runId,
        journey: persisted.run.journey,
        eventType: "action.authorized",
        actorType: "worker",
        actorId: input.lease.ownerId,
        summary: `${action.intentSummary} was authorized and durably assigned for execution`,
        ...(action.contextPackId ? { contextPackId: action.contextPackId } : {}),
        payload: {
          actionId: action.id,
          actionFingerprint: action.fingerprint,
          actionType: action.actionType,
          target: action.target,
          contractId: action.contractId,
          guidedDecisionId: action.guidedDecisionId,
          contextPackId: action.contextPackId,
        },
      });
      const checkpoint = this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
      if (!persisted.lease) throw new DurableOrchestrationError("lease_lost", "Action mutation unexpectedly released its run lease");
      return {
        action,
        lease: persisted.lease,
        eventSequence: event.sequence,
        checkpointId: checkpoint.id,
      };
    });

    if ("denied" in committed) {
      throw new DurableOrchestrationError(committed.code, committed.message);
    }

    this.afterActionCommit?.(committed.action);

    // Close the commit-to-dispatch window with one final side-effect-free read
    // of canonical mission, contract, target, decision, assignment, and tool
    // policy state. The execution adapter repeats this assertion at the MCP
    // call boundary because dispatch acceptance itself is asynchronous.
    const finalAuthorization = this.runs.authorizePersistedAction(
      this.load(committed.action.runId),
      committed.action,
    );
    if (!finalAuthorization.allowed) {
      this.denyPersistedActionBeforeDispatch(
        committed.lease,
        committed.action,
        finalAuthorization.code,
        finalAuthorization.humanMessage,
      );
      throw new DurableOrchestrationError(finalAuthorization.code, finalAuthorization.humanMessage);
    }

    try {
      await this.execution.dispatch(committed.action, this.signal(committed.action.runId));
      return committed;
    } catch (error) {
      await this.completeAction({
        lease: committed.lease,
        actionId: committed.action.id,
        success: false,
        resultSummary: "Execution boundary rejected the persisted action dispatch",
        before: this.load(committed.action.runId).control.progress,
        after: this.load(committed.action.runId).control.progress,
        failure: {
          source: "worker",
          code: "dispatch_failed",
          message: error instanceof Error ? error.message : "Dispatch failed",
        },
      }).catch(() => undefined);
      throw new DurableOrchestrationError("dispatch_failed", "Persisted action could not be dispatched");
    }
  }

  private persistActionDenial(
    current: DurableRun,
    now: string,
    actorId: string,
    code: string,
    humanMessage: string,
  ): DeniedActionStart {
    const reason = current.run.journey === "autonomous"
      ? `Safe-stopped (outside_contract): ${humanMessage}`
      : `Guided execution blocked: ${humanMessage}`;
    const currentStep = this.database.prepare(
      "SELECT current_step_id FROM runs WHERE id = ?",
    ).get(current.run.id) as { current_step_id: string | null } | undefined;
    if (currentStep?.current_step_id) {
      this.database.prepare(`
        UPDATE plan_steps SET status = 'blocked', updated_at = ?
        WHERE id = ? AND run_id = ?
          AND status NOT IN ('completed', 'failed', 'cancelled', 'skipped')
      `).run(now, currentStep.current_step_id, current.run.id);
      this.database.prepare(`
        UPDATE assignments SET status = 'blocked', updated_at = ?
        WHERE run_id = ? AND step_id = ?
          AND status IN ('queued', 'active')
      `).run(now, current.run.id, currentStep.current_step_id);
    }
    const transition = this.supervisor.transition(current.run, "blocked", { reason, now });
    const persisted = this.runs.persistMutation({
      current,
      nextRun: transition.run,
      control: { ...current.control, recovery: undefined },
      now,
      lease: "clear",
    });
    const event = this.events.append({
      missionId: persisted.run.missionId,
      runId: persisted.run.id,
      journey: current.run.journey,
      eventType: current.run.journey === "autonomous"
        ? "run.autonomous_safe_stopped"
        : "run.guided_blocked",
      actorType: "worker",
      actorId,
      summary: reason,
      payload: {
        code,
        category: code.includes("authorization") ? "authorization_denied" : "scope_conflict",
        dispatchAttempted: false,
        stateVersion: persisted.run.stateVersion,
      },
      occurredAt: now,
      sensitivity: "private",
    });
    this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
    return { denied: true, code, message: humanMessage };
  }

  private denyPersistedActionBeforeDispatch(
    lease: RunLeaseToken,
    action: DurableAction,
    code: string,
    humanMessage: string,
  ): void {
    const now = this.timestamp();
    inImmediateTransaction(this.database, () => {
      const current = this.load(lease.runId);
      this.runs.assertLease(current, lease, now);
      const row = this.database.prepare(`
        SELECT status FROM actions WHERE id = ? AND run_id = ?
      `).get(action.id, action.runId) as { status: string } | undefined;
      if (row?.status !== "running") return;
      const reason = current.run.journey === "autonomous"
        ? `Safe-stopped (outside_contract): ${humanMessage}`
        : `Guided execution blocked before dispatch: ${humanMessage}`;
      this.database.prepare(`
        UPDATE actions SET status = 'denied', result_summary = ?,
          error_category = ?, ended_at = ?, updated_at = ?
        WHERE id = ? AND status = 'running'
      `).run(reason, code.includes("authorization") ? "authorization_denied" : "scope_conflict", now, now, action.id);
      this.database.prepare(`
        UPDATE plan_steps SET status = 'blocked', updated_at = ?
        WHERE id = ? AND run_id = ? AND status = 'running'
      `).run(now, action.stepId, action.runId);
      this.database.prepare(`
        UPDATE assignments SET status = 'blocked', updated_at = ?
        WHERE id = (SELECT assignment_id FROM actions WHERE id = ?)
          AND status = 'active'
      `).run(now, action.id);
      const transition = this.supervisor.transition(current.run, "blocked", { reason, now });
      const persisted = this.runs.persistMutation({
        current,
        nextRun: transition.run,
        control: { ...current.control, recovery: undefined },
        now,
        lease: "clear",
      });
      const event = this.events.append({
        missionId: action.missionId,
        runId: action.runId,
        journey: current.run.journey,
        eventType: "action.pre_dispatch_denied",
        actorType: "system",
        summary: reason,
        payload: { actionId: action.id, code, dispatchAttempted: false },
        occurredAt: now,
        sensitivity: "private",
      });
      this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
    });
  }

  async completeAction(input: CompleteActionInput): Promise<CompleteActionResult> {
    const now = this.timestamp();
    return inImmediateTransaction(this.database, () => {
      const current = this.load(input.lease.runId);
      this.runs.assertLease(current, input.lease, now);
      const pendingAction = this.actions.get(input.actionId);
      if (pendingAction.runId !== current.run.id) {
        throw new DurableOrchestrationError("action_run_mismatch", "Action result belongs to another run");
      }
      const category = input.success
        ? undefined
        : input.failureCategory ?? classifyFailure(input.failure ?? { source: "unknown" });
      const evaluation = this.supervisor.evaluateCompletedAction({
        history: this.actions.observations(current.run.id),
        observation: {
          actionId: pendingAction.id,
          actionFingerprint: pendingAction.fingerprint,
          completedAt: now,
          ...(category ? { errorCategory: category } : {}),
          actionKind: pendingAction.kind,
        },
        before: input.before,
        after: input.after,
        budgetState: {
          limits: current.control.budget.limits,
          usage: elapsedUsage(current, now),
        },
        budgetDelta: withoutWallClock(input.budgetDelta ?? {}),
      });

      const usage = {
        ...evaluation.budget.projected,
        concurrency: Math.max(0, (evaluation.budget.projected.concurrency ?? 0) - 1),
      };
      const circuits = { ...current.control.circuits };
      if (input.circuitKey?.trim()) {
        const key = input.circuitKey.trim();
        const breaker = new CircuitBreaker({}, circuits[key]);
        circuits[key] = input.success
          ? breaker.recordSuccess()
          : breaker.recordFailure(
              Date.parse(now),
              category === "transient_network" ||
                category === "provider_unavailable" ||
                category === "mcp_unavailable" ||
                category === "timeout",
            );
      }

      let targetState: RunState = current.run.state === "recovering" && input.success
        ? "running"
        : current.run.state;
      let directive: CompleteActionResult["directive"] = "continue";
      let reason = evaluation.humanReason;
      let retryIncrement = 0;
      let recoveryState: DurableControlState["recovery"];
      if (!evaluation.budget.allowed) {
        targetState = "blocked";
        directive = "blocked";
        reason = `Budget safe stop: ${evaluation.budget.exhausted.join(", ")}`;
      } else if (evaluation.loops.length > 0) {
        targetState = "blocked";
        directive = "blocked";
        reason = `Loop safe stop: ${evaluation.loops[0]!.summary}`;
      } else if (!input.success) {
        const replanBudgetAvailable =
          current.control.replanCount <
          (current.control.budget.limits.replans ?? Number.POSITIVE_INFINITY);
        const inContract = current.run.journey === "autonomous"
          ? this.runs.autonomousActionRemainsInContract(current, pendingAction)
          : true;
        const materiallyNewReplanAvailable = evaluation.progress.dimensions.includes("evidence_added")
          || evaluation.progress.dimensions.includes("finding_strengthened")
          || evaluation.progress.dimensions.includes("entity_discovered")
          || evaluation.progress.dimensions.includes("dependency_resolved")
          || evaluation.progress.dimensions.includes("uncertainty_reduced");
        const recovery = this.supervisor.decideRecovery({
          journey: current.run.journey,
          category: category ?? "unknown",
          retriesUsed: current.control.retryCount,
          retrySafe:
            pendingAction.idempotent &&
            !pendingAction.destructive &&
            current.control.retryCount <
              (current.control.budget.limits.retries ?? Number.POSITIVE_INFINITY),
          inContract,
          materiallyNewReplanAvailable,
          replanBudgetAvailable,
          retryAfterMs: input.retryAfterMs,
          guidedRecommendation:
            "Prepare one materially different represented action, explain it, and wait for a new exact decision.",
        });
        if (current.run.journey === "autonomous" && recovery.recovery.kind === "retry") {
          targetState = "recovering";
          directive = "retry";
          retryIncrement = 1;
          reason = recovery.recovery.reason;
          recoveryState = {
            kind: "retry",
            failedActionId: pendingAction.id,
            notBefore: new Date(Date.parse(now) + recovery.recovery.delayMs).toISOString(),
            reason,
          };
        } else if (current.run.journey === "autonomous" && recovery.recovery.kind === "replan") {
          targetState = "recovering";
          directive = "replan";
          reason = recovery.recovery.reason;
          recoveryState = {
            kind: "replan",
            failedActionId: pendingAction.id,
            notBefore: now,
            reason,
          };
        } else if (current.run.journey === "guided") {
          if (
            category === "authorization_denied" ||
            category === "scope_conflict" ||
            category === "policy_denied"
          ) {
            targetState = "blocked";
            directive = "blocked";
            reason = `Guided execution blocked because the approved action is no longer authorized (${category}). Review scope and create a new exact decision.`;
          } else if (recovery.recovery.kind === "waiting_guided_decision" && replanBudgetAvailable) {
            // A failed Guided action is never silently repeated. Keep the
            // fenced lease long enough for MissionRuntimeEngine to prepare a
            // materially different represented action and publish a new
            // exact decision. The run enters the user-wait state only after
            // that decision has been durably created.
            targetState = "recovering";
            directive = "recover";
            reason = `${pendingAction.intentSummary} failed (${category ?? "unknown"}). ${recovery.recovery.recommendation}`;
          } else {
            targetState = "blocked";
            directive = "blocked";
            reason = `Guided recovery blocked after ${category ?? "unknown"}: the bounded replan budget is exhausted, so no replacement decision was created.`;
          }
        } else if (recovery.recovery.kind === "safe_stop") {
          targetState = "blocked";
          directive = "blocked";
          reason = `Safe-stopped (${recovery.recovery.exceptionCode}): ${recovery.recovery.reason}`;
        } else {
          targetState = "failed";
          directive = "failed";
          reason = recovery.recovery.reason;
        }
      }

      const action = this.actions.complete({
        actionId: input.actionId,
        success: input.success,
        summary: input.resultSummary,
        category,
        progressSignature: evaluation.progress.afterSignature,
        now,
      });
      let retryAssignmentId: string | null = null;
      if (directive === "retry") {
        // A retry is a new action reservation, not a redispatch of the failed
        // action. Revalidate the now-terminal predecessor while its exact
        // assignment and step are still active/running, then requeue only that
        // canonical pair in this same transaction. The next reservation must
        // still pass startAction's queued/ready boundary and its final
        // post-reservation dispatch assertion.
        const retryAuthorization = this.runs.authorizePersistedAction(current, action);
        if (!retryAuthorization.allowed) {
          throw new DurableOrchestrationError(
            retryAuthorization.code,
            retryAuthorization.humanMessage,
          );
        }
        const predecessor = this.database.prepare(`
          SELECT assignment_id FROM actions
          WHERE id = ? AND run_id = ? AND step_id = ?
            AND status IN ('failed', 'timed_out')
        `).get(action.id, action.runId, action.stepId) as { assignment_id: string | null } | undefined;
        if (!predecessor?.assignment_id) {
          throw new DurableOrchestrationError(
            "retry_predecessor_not_canonical",
            "The bounded retry has no exact failed specialist assignment.",
          );
        }
        const assignment = this.database.prepare(`
          UPDATE assignments SET status = 'queued', updated_at = ?
          WHERE id = ? AND run_id = ? AND step_id = ? AND status = 'active'
        `).run(now, predecessor.assignment_id, action.runId, action.stepId);
        const step = this.database.prepare(`
          UPDATE plan_steps SET status = 'ready', updated_at = ?
          WHERE id = ? AND run_id = ? AND status = 'running'
        `).run(now, action.stepId, action.runId);
        if (assignment.changes !== 1 || step.changes !== 1) {
          throw new DurableOrchestrationError(
            "retry_requeue_fence_lost",
            "The exact failed assignment or step changed before retry requeue.",
          );
        }
        retryAssignmentId = predecessor.assignment_id;
      }
      const control: DurableControlState = {
        budget: {
          limits: current.control.budget.limits,
          usage: retryIncrement > 0
            ? { ...usage, retries: (usage.retries ?? 0) + retryIncrement }
            : usage,
        },
        retryCount: current.control.retryCount + retryIncrement,
        replanCount: current.control.replanCount,
        circuits,
        progress: input.after,
        recovery: recoveryState,
      };
      let nextRun: SupervisedRun;
      let transitionSummary: string | undefined;
      if (targetState !== current.run.state) {
        const transition = this.supervisor.transition(current.run, targetState, { reason, now });
        nextRun = transition.run;
        transitionSummary = transition.events[0]!.summary;
      } else {
        nextRun = bumpedRun(current.run, now, reason);
      }
      const persisted = this.runs.persistMutation({
        current,
        nextRun,
        control,
        now,
        lease: directive === "retry" || directive === "replan"
          ? "clear"
          : leaseDisposition(nextRun.state),
      });
      if (transitionSummary) {
        this.events.append({
          missionId: persisted.run.missionId,
          runId: persisted.run.id,
          journey: persisted.run.journey,
          eventType: "run.state_changed",
          actorType: "system",
          summary: transitionSummary,
          payload: { from: current.run.state, to: persisted.run.state, reason },
        });
      }
      const event = this.events.append({
        missionId: action.missionId,
        runId: action.runId,
        journey: persisted.run.journey,
        eventType: "action.completed",
        actorType: "worker",
        actorId: input.lease.ownerId,
        summary: input.resultSummary,
        ...(action.contextPackId ? { contextPackId: action.contextPackId } : {}),
        payload: {
          actionId: action.id,
          actionFingerprint: action.fingerprint,
          actionKind: action.kind,
          meaningfulProgress: evaluation.progress.meaningful,
          progressDimensions: [...evaluation.progress.dimensions],
          progressSignatureAfter: evaluation.progress.afterSignature,
          completedAt: now,
          errorCategory: category ?? null,
          loopKinds: evaluation.loops.map((loop) => loop.kind),
          directive,
          contextPackId: action.contextPackId,
          retryNotBefore: recoveryState?.notBefore ?? null,
          retryAssignmentId,
        },
      });
      const checkpoint = this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
      if (!input.success && directive === "retry" && recoveryState?.kind === "retry") {
        this.continuations.enqueue({
          runId: action.runId,
          kind: "autonomous_retry_to_dispatch",
          sourceId: action.id,
          payload: { actionId: action.id, stepId: action.stepId },
          now,
          availableAt: recoveryState.notBefore,
        });
      } else if (input.success && directive === "continue") {
        this.continuations.enqueue({
          runId: action.runId,
          kind: "action_result_to_advance",
          sourceId: action.id,
          payload: { actionId: action.id, stepId: action.stepId },
          now,
        });
      } else if (!input.success && persisted.run.journey === "guided" && directive === "recover") {
        this.continuations.enqueue({
          runId: action.runId,
          kind: "guided_failure_to_recover",
          sourceId: action.id,
          payload: { actionId: action.id, stepId: action.stepId },
          now,
        });
      } else if (persisted.run.state === "failed") {
        this.continuations.enqueue({
          runId: action.runId,
          kind: "evaluation_pending",
          sourceId: action.id,
          payload: { terminalStatus: "failed" },
          now,
        });
      }
      return {
        action,
        run: persisted,
        directive,
        reason,
        loopKinds: evaluation.loops.map((loop) => loop.kind),
        eventSequence: event.sequence,
        checkpointId: checkpoint.id,
      };
    });
  }

  beginReplan(input: { lease: RunLeaseToken; reason: string }): DurableTransitionResult {
    const now = this.timestamp();
    return inImmediateTransaction(this.database, () => {
      const current = this.load(input.lease.runId);
      this.runs.assertLease(current, input.lease, now);
      if (current.run.state !== "recovering") {
        throw new DurableOrchestrationError("replan_requires_recovery", "A bounded replan starts only from recovery");
      }
      if (current.control.recovery?.kind === "retry") {
        throw new DurableOrchestrationError(
          "retry_delay_not_replan",
          "A persisted delayed retry cannot be bypassed by starting a replan",
        );
      }
      const budget = checkBudget(current.control.budget, { replans: 1 });
      if (!budget.allowed) throw new DurableOrchestrationError("replan_budget_exhausted", "Replan budget is exhausted");
      const transition = this.supervisor.transition(current.run, "planning", {
        reason: input.reason,
        now,
      });
      const control: DurableControlState = {
        ...current.control,
        budget: { limits: current.control.budget.limits, usage: budget.projected },
        replanCount: current.control.replanCount + 1,
        recovery: undefined,
      };
      const persisted = this.runs.persistMutation({ current, nextRun: transition.run, control, now, lease: "keep" });
      const event = this.events.append({
        missionId: persisted.run.missionId,
        runId: persisted.run.id,
        journey: persisted.run.journey,
        eventType: "run.replan_started",
        actorType: "worker",
        actorId: input.lease.ownerId,
        summary: input.reason,
        payload: { replanCount: control.replanCount, stateVersion: persisted.run.stateVersion },
      });
      const checkpoint = this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
      return { run: persisted, eventSequence: event.sequence, checkpointId: checkpoint.id };
    });
  }

  async recoverOnStartup(workerId: string): Promise<StartupRecoveryResult[]> {
    const now = this.timestamp();
    const expired = this.runs.listExpiredNonterminal(now);
    const results: StartupRecoveryResult[] = [];
    for (const candidate of expired) {
      const prepared = inImmediateTransaction(this.database, () => {
        const current = this.load(candidate.run.id);
        if (!current.lease || current.lease.expiresAt > now) return undefined;
        const inFlight = this.actions.inFlight(current.run.id);
        if (current.run.state === "planning" && inFlight.length === 0) {
          // Planning ACP turns have no execution authority. If their fenced
          // owner disappears, close the durable provider records first, make
          // recovery visible, then release the lease so the normal scheduler
          // can reacquire and plan once. Never classify an action-bearing run
          // through this path.
          const interruptedTurns = this.database.prepare(`
            SELECT id, started_at FROM provider_turns
            WHERE run_id = ? AND status = 'started'
            ORDER BY started_at, id
          `).all(current.run.id) as Array<{ id: string; started_at: string }>;
          const closeTurn = this.database.prepare(`
            UPDATE provider_turns SET status = 'cancelled', error_category = 'process_crash',
              latency_ms = ?, ended_at = ?
            WHERE id = ? AND status = 'started'
          `);
          for (const turn of interruptedTurns) {
            const startedAt = Date.parse(turn.started_at);
            const latency = Number.isFinite(startedAt) ? Math.max(0, Date.parse(now) - startedAt) : 0;
            closeTurn.run(latency, now, turn.id);
          }
          const reason = interruptedTurns.length > 0
            ? "Expired planning lease recovered; interrupted provider work was closed before deterministic replanning"
            : "Expired planning lease recovered before deterministic replanning";
          const persisted = this.runs.persistMutation({
            current,
            nextRun: bumpedRun(current.run, now, reason),
            control: current.control,
            now,
            lease: "clear",
          });
          const event = this.events.append({
            missionId: persisted.run.missionId,
            runId: persisted.run.id,
            journey: persisted.run.journey,
            eventType: "run.recovery_started",
            actorType: "system",
            summary: reason,
            payload: {
              expiredLeaseOwner: current.lease.ownerId,
              interruptedProviderTurnIds: interruptedTurns.map((turn) => turn.id),
              classification: "restart_planning",
            },
          });
          this.checkpoints.create({
            run: persisted,
            eventSequence: event.sequence,
            now,
            inFlightClassification: "restart_planning",
          });
          return { kind: "planning" as const, persisted, reason };
        }
        const safe = inFlight.length > 0 && inFlight.every(
          (action) => classifyInFlightAction({
            idempotent: action.idempotent,
            destructive: action.destructive,
            completionKnown: false,
          }) === "resume_idempotently" && this.runs.authorizePersistedAction(current, action).allowed,
        );
        const canRecover = safe && (
          current.run.state === "running" ||
          current.run.state === "recovering" ||
          current.run.state === "blocked" ||
          current.run.state === "waiting_guided_decision"
        );
        const target: RunState = canRecover
          ? "recovering"
          : allowedRunTransitions(current.run.state, current.run.journey).includes("blocked")
            ? "blocked"
            : "failed";
        const reason = canRecover
          ? "Expired worker lease recovered; only safe idempotent in-flight work will resume"
          : "Expired worker lease requires review because in-flight completion cannot be repeated safely";
        const nextRun = target === current.run.state
          ? bumpedRun(current.run, now, reason)
          : this.supervisor.transition(current.run, target, { reason, now }).run;
        const expiresAt = new Date(Date.parse(now) + this.leaseTtlMs).toISOString();
        const persisted = this.runs.persistMutation({
          current,
          nextRun,
          control: current.control,
          now,
          lease: canRecover ? { ownerId: workerId, expiresAt, acquiredAt: now } : "clear",
        });
        const event = this.events.append({
          missionId: persisted.run.missionId,
          runId: persisted.run.id,
          journey: persisted.run.journey,
          eventType: canRecover ? "run.recovery_started" : "run.recovery_blocked",
          actorType: "system",
          summary: reason,
          payload: {
            expiredLeaseOwner: current.lease.ownerId,
            inFlightActionIds: inFlight.map((action) => action.id),
            classification: canRecover ? "resume_idempotently" : "review_required",
          },
        });
        this.checkpoints.create({
          run: persisted,
          eventSequence: event.sequence,
          now,
          inFlightClassification: canRecover ? "resume_idempotently" : "review_required",
        });
        return { kind: "actions" as const, persisted, inFlight, canRecover, reason };
      });
      if (!prepared) continue;
      if (prepared.kind === "planning") {
        results.push({
          runId: prepared.persisted.run.id,
          disposition: "restarted_planning",
          actionIds: [],
          reason: prepared.reason,
        });
        continue;
      }
      if (!prepared.canRecover || !prepared.persisted.lease) {
        results.push({
          runId: prepared.persisted.run.id,
          disposition: prepared.persisted.run.state === "failed" ? "failed_safely" : "blocked_for_review",
          actionIds: prepared.inFlight.map((action) => action.id),
          reason: prepared.reason,
        });
        continue;
      }
      try {
        for (const action of prepared.inFlight) {
          const current = this.load(action.runId);
          const authorization = this.runs.authorizePersistedAction(current, action);
          if (!authorization.allowed) {
            throw new DurableOrchestrationError(authorization.code, authorization.humanMessage);
          }
          await this.execution.resume(action, this.signal(action.runId));
        }
        results.push({
          runId: prepared.persisted.run.id,
          disposition: "resumed_idempotently",
          actionIds: prepared.inFlight.map((action) => action.id),
          reason: prepared.reason,
        });
      } catch {
        await this.blockRecoveryFailure(prepared.persisted.lease);
        results.push({
          runId: prepared.persisted.run.id,
          disposition: "blocked_for_review",
          actionIds: prepared.inFlight.map((action) => action.id),
          reason: "The safe resume dispatch failed and the run was blocked without repeating again.",
        });
      }
    }
    return results;
  }

  private async blockRecoveryFailure(lease: RunLeaseToken): Promise<void> {
    const now = this.timestamp();
    inImmediateTransaction(this.database, () => {
      const current = this.load(lease.runId);
      this.runs.assertLease(current, lease, now);
      const reason = "Recovery dispatch failed; no further automatic repeat is permitted";
      const transition = this.supervisor.transition(current.run, "blocked", { reason, now });
      const persisted = this.runs.persistMutation({
        current,
        nextRun: transition.run,
        control: current.control,
        now,
        lease: "clear",
      });
      const event = this.events.append({
        missionId: persisted.run.missionId,
        runId: persisted.run.id,
        journey: persisted.run.journey,
        eventType: "run.recovery_blocked",
        actorType: "system",
        summary: reason,
      });
      this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
    });
  }

  async cancelRun(input: {
    lease: RunLeaseToken;
    reason: string;
    commandId?: string;
  }): Promise<DurableTransitionResult> {
    const requestedAt = this.timestamp();
    const reservation = inImmediateTransaction(this.database, () => {
      const current = this.load(input.lease.runId);
      this.runs.assertLease(current, input.lease, requestedAt);
      const nextRun = bumpedRun(current.run, requestedAt, `Cancellation requested: ${input.reason}`);
      const persisted = this.runs.persistMutation({
        current,
        nextRun,
        control: current.control,
        now: requestedAt,
        lease: "keep",
      });
      const event = this.events.append({
        missionId: persisted.run.missionId,
        runId: persisted.run.id,
        journey: persisted.run.journey,
        eventType: "run.cancellation_requested",
        actorType: "operator",
        summary: `Cancellation requested: ${input.reason}`,
        payload: {
          requestId: randomUUID(),
          ...(input.commandId ? { commandId: input.commandId } : {}),
        },
      });
      this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now: requestedAt });
      if (!persisted.lease) throw new DurableOrchestrationError("lease_lost", "Cancellation reservation lost its lease");
      const pending = this.continuations.enqueue({
        runId: persisted.run.id,
        kind: "cancellation_finalize_pending",
        sourceId: event.id,
        now: requestedAt,
      });
      const continuation = this.continuations.claimById({
        id: pending.id,
        workerId: input.lease.ownerId,
        now: requestedAt,
        leaseTtlMs: this.leaseTtlMs,
      });
      return { lease: persisted.lease, continuation };
    });

    this.controllers.get(input.lease.runId)?.abort(input.reason);
    try {
      await this.execution.cancelRun(input.lease.runId, input.reason);
    } catch {
      const failedAt = this.timestamp();
      inImmediateTransaction(this.database, () => {
        const current = this.load(reservation.lease.runId);
        this.runs.assertLease(current, reservation.lease, failedAt);
        const target = allowedRunTransitions(current.run.state, current.run.journey).includes("blocked")
          ? "blocked"
          : "failed";
        const reason = "Execution cleanup did not confirm cancellation; run stopped for review";
        const transition = this.supervisor.transition(current.run, target, { reason, now: failedAt });
        const persisted = this.runs.persistMutation({
          current,
          nextRun: transition.run,
          control: current.control,
          now: failedAt,
          lease: "clear",
        });
        const event = this.events.append({
          missionId: persisted.run.missionId,
          runId: persisted.run.id,
          journey: persisted.run.journey,
          eventType: "run.cancellation_failed",
          actorType: "system",
          summary: reason,
        });
        this.continuations.fail({
          id: reservation.continuation.id,
          ownerToken: reservation.continuation.leaseOwner!,
          now: failedAt,
          error: reason,
        });
        this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now: failedAt });
      });
      throw new DurableOrchestrationError("cancellation_cleanup_failed", "Execution port did not confirm child cleanup");
    }

    this.afterCancellationCleanup?.(input.lease.runId);
    const completedAt = this.timestamp();
    return inImmediateTransaction(this.database, () => {
      const current = this.load(reservation.lease.runId);
      this.runs.assertLease(current, reservation.lease, completedAt);
      this.closeAggregateChildren(current.run.id, input.reason, completedAt);
      const transition = this.supervisor.transition(current.run, "cancelled", {
        reason: input.reason,
        now: completedAt,
      });
      const persisted = this.runs.persistMutation({
        current,
        nextRun: transition.run,
        control: {
          ...current.control,
          budget: {
            limits: current.control.budget.limits,
            usage: { ...current.control.budget.usage, concurrency: 0 },
          },
        },
        now: completedAt,
        lease: "clear",
      });
      this.database.prepare("UPDATE missions SET status = 'cancelled', updated_at = ? WHERE id = ?")
        .run(completedAt, persisted.run.missionId);
      this.continuations.complete(
        reservation.continuation.id,
        reservation.continuation.leaseOwner!,
        completedAt,
      );
      this.continuations.cancelOpen(current.run.id, completedAt, "Run reached a terminal cancelled state");
      const event = this.events.append({
        missionId: persisted.run.missionId,
        runId: persisted.run.id,
        journey: persisted.run.journey,
        eventType: "run.cancelled",
        actorType: "operator",
        summary: `Run cancelled and child work stopped: ${input.reason}`,
        payload: {
          activeLeaseReleased: true,
          stateVersion: persisted.run.stateVersion,
          ...(input.commandId ? { commandId: input.commandId } : {}),
        },
      });
      this.continuations.enqueue({
        runId: persisted.run.id,
        kind: "evaluation_pending",
        sourceId: event.id,
        payload: { terminalStatus: "cancelled" },
        now: completedAt,
      });
      const checkpoint = this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now: completedAt });
      return { run: persisted, eventSequence: event.sequence, checkpointId: checkpoint.id };
    });
  }

  private closeAggregateChildren(runId: string, reason: string, now: string): void {
    this.database.prepare(`
      UPDATE tool_calls SET status = 'cancelled', ended_at = COALESCE(ended_at, ?)
      WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
        AND status IN ('queued', 'running')
    `).run(now, runId);
    this.database.prepare(`
      UPDATE actions SET status = 'cancelled', result_summary = COALESCE(result_summary, ?),
        ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE run_id = ? AND status IN ('queued', 'running')
    `).run(`Cancelled: ${reason}`, now, now, runId);
    this.database.prepare(`
      UPDATE guided_decisions SET status = 'cancelled', decision_reason = ?,
        decided_at = COALESCE(decided_at, ?)
      WHERE run_id = ? AND status = 'pending'
    `).run(reason, now, runId);
    this.database.prepare(`
      UPDATE approvals SET status = 'cancelled', decided_at = COALESCE(decided_at, ?)
      WHERE run_id = ? AND status = 'pending'
    `).run(now, runId);
    this.database.prepare(`
      UPDATE plan_steps SET status = 'cancelled', ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE run_id = ? AND status IN (
        'pending', 'ready', 'running', 'waiting_guided_decision', 'blocked', 'recovering'
      )
    `).run(now, now, runId);
    this.database.prepare(`
      UPDATE assignments SET status = 'cancelled', ended_at = COALESCE(ended_at, ?),
        lease_owner = NULL, lease_acquired_at = NULL, last_heartbeat_at = NULL,
        lease_expires_at = NULL, updated_at = ?
      WHERE run_id = ? AND status IN ('queued', 'active', 'blocked')
    `).run(now, now, runId);
    // A provider turn is execution-bearing durable child state. It must close
    // before the terminal transition/checkpoint, not in a caller transaction
    // afterward, otherwise a crash can leave a cancelled run with live work.
    this.database.prepare(`
      UPDATE provider_turns SET status = 'cancelled',
        error_category = COALESCE(error_category, 'operator_rejection'),
        ended_at = COALESCE(ended_at, ?)
      WHERE run_id = ? AND status = 'started'
    `).run(now, runId);
    this.database.prepare(`
      UPDATE plans SET status = 'abandoned'
      WHERE run_id = ? AND status IN ('draft', 'active')
    `).run(runId);
  }
}

export function createDurableRunCoordinator(options: DurableRunCoordinatorOptions): DurableRunCoordinator {
  return new DurableRunCoordinator(options.database, options.execution, options);
}

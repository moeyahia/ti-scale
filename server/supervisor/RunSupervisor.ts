import type { BudgetCheck, BudgetState, BudgetValues } from "./BudgetManager";
import { checkBudget } from "./BudgetManager";
import type { FailureCategory } from "./ErrorTaxonomy";
import type { ActionObservation, LoopDetectorConfig, LoopFinding } from "./LoopDetector";
import { LoopDetector } from "./LoopDetector";
import type { ProgressEvaluation, ProgressSnapshot } from "./ProgressEvaluator";
import { evaluateProgress } from "./ProgressEvaluator";
import type { RecoveryDecision, RecoveryInput } from "./RecoveryPlanner";
import { planRecovery } from "./RecoveryPlanner";
import type { RetryDecision, RetryPolicyConfig } from "./RetryPolicy";
import { decideRetry } from "./RetryPolicy";
import { transitionRun } from "./RunStateMachine";
import { enforceJourneyActionBoundary, type ActionBoundaryResult } from "./JourneyActionBoundary";
import type {
  ActionIntent,
  AutonomousContractBoundary,
  GuidedDecision,
  Journey,
  RunState,
  SupervisedRun,
  TransitionResult,
} from "./types";

export interface SupervisorPersistencePort {
  persistTransition(result: Readonly<TransitionResult>): Promise<void>;
  persistCheckpoint(run: Readonly<SupervisedRun>): Promise<void>;
  appendActionObservation(runId: string, observation: Readonly<ActionObservation>): Promise<void>;
}

export interface SupervisorCancellationPort {
  cancelRunChildren(runId: string, reason: string): Promise<void>;
  releaseRunLeases(runId: string): Promise<void>;
}

export interface CompletedActionEvaluation {
  observation: ActionObservation;
  progress: ProgressEvaluation;
  loops: readonly LoopFinding[];
  budget: BudgetCheck;
  directive: "continue" | "recover" | "block_budget";
  humanReason: string;
}

export interface RunSupervisorConfig {
  loopDetector?: Partial<LoopDetectorConfig>;
  retryPolicy?: Partial<RetryPolicyConfig>;
}

export interface RecoveryRequest
  extends Omit<RecoveryInput, "retryDecision" | "category"> {
  category: FailureCategory;
  retriesUsed: number;
  retryAfterMs?: number;
  random?: () => number;
}

export class RunSupervisor {
  private readonly loopDetector: LoopDetector;
  private readonly retryPolicy?: Partial<RetryPolicyConfig>;

  constructor(config: RunSupervisorConfig = {}) {
    this.loopDetector = new LoopDetector(config.loopDetector);
    this.retryPolicy = config.retryPolicy;
  }

  createRun(input: {
    id: string;
    missionId: string;
    journey: Journey;
    now: string;
    contractVersion?: number;
  }): SupervisedRun {
    return {
      id: input.id,
      missionId: input.missionId,
      journey: input.journey,
      state: "queued",
      launched: false,
      contractVersion: input.contractVersion,
      stateVersion: 0,
      stateReason: "Run queued",
      createdAt: input.now,
      updatedAt: input.now,
    };
  }

  transition(
    run: Readonly<SupervisedRun>,
    to: RunState,
    input: { reason: string; now: string; contractConfirmed?: boolean; guidedDecisionId?: string },
  ): TransitionResult {
    return transitionRun(run, to, input);
  }

  authorizeAction(input: {
    run: Readonly<SupervisedRun>;
    action: Readonly<ActionIntent>;
    now: string;
    autonomousContract?: Readonly<AutonomousContractBoundary>;
    guidedDecision?: Readonly<GuidedDecision>;
  }): ActionBoundaryResult {
    if (input.run.id !== input.action.runId || input.run.missionId !== input.action.missionId) {
      return {
        allowed: false,
        reason: "action_run_mismatch",
        humanMessage: "The action belongs to a different mission or run.",
      };
    }
    if (input.run.state !== "running") {
      return {
        allowed: false,
        reason: "run_not_running",
        humanMessage: `Actions cannot start while the run is ${input.run.state}.`,
      };
    }
    if (
      input.run.journey === "autonomous" &&
      input.run.contractVersion !== input.autonomousContract?.version
    ) {
      return {
        allowed: false,
        reason: "autonomous_contract_not_signed",
        humanMessage: "The signed contract version does not match the launched run.",
      };
    }
    return enforceJourneyActionBoundary({
      journey: input.run.journey,
      action: input.action,
      now: input.now,
      autonomousContract: input.autonomousContract,
      guidedDecision: input.guidedDecision,
    });
  }

  evaluateCompletedAction(input: {
    history: readonly ActionObservation[];
    observation: Readonly<Omit<ActionObservation, "meaningfulProgress" | "progressSignatureAfter">>;
    before: Readonly<ProgressSnapshot>;
    after: Readonly<ProgressSnapshot>;
    budgetState: Readonly<BudgetState>;
    budgetDelta: BudgetValues;
  }): CompletedActionEvaluation {
    const progress = evaluateProgress(input.before, input.after);
    const observation: ActionObservation = {
      ...input.observation,
      meaningfulProgress: progress.meaningful,
      progressSignatureAfter: progress.afterSignature,
    };
    const loops = this.loopDetector.inspect([...input.history, observation]);
    const budget = checkBudget(input.budgetState, input.budgetDelta);
    if (!budget.allowed) {
      return {
        observation,
        progress,
        loops,
        budget,
        directive: "block_budget",
        humanReason: `Budget limit reached: ${budget.exhausted.join(", ")}`,
      };
    }
    if (loops.length > 0) {
      return {
        observation,
        progress,
        loops,
        budget,
        directive: "recover",
        humanReason: loops[0]!.summary,
      };
    }
    return {
      observation,
      progress,
      loops,
      budget,
      directive: "continue",
      humanReason: progress.summary,
    };
  }

  decideRecovery(input: Readonly<RecoveryRequest>): {
    retry: RetryDecision;
    recovery: RecoveryDecision;
  } {
    const retry = decideRetry({
      category: input.category,
      retriesUsed: input.retriesUsed,
      retryAfterMs: input.retryAfterMs,
      config: this.retryPolicy,
      random: input.random,
    });
    return {
      retry,
      recovery: planRecovery({ ...input, retryDecision: retry }),
    };
  }
}

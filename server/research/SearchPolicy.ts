import { deepFreeze } from "./canonical";
import type { InitialResearchDimensionId } from "./ResearchTypes";

export interface ResearchDimensionStatistics {
  readonly id: InitialResearchDimensionId;
  readonly trials: number;
  readonly meanImprovement: number;
  readonly variance: number;
  readonly failureCount: number;
  readonly safetyFailureCount: number;
  readonly lastAttemptedAt?: string;
}

export interface SearchBounds {
  readonly maxTrialsPerDimension: number;
  readonly safetyFailureCircuitBreaker: number;
}

export interface DimensionScore {
  readonly id: InitialResearchDimensionId;
  readonly score: number | null;
  readonly eligible: boolean;
  readonly reason: string;
}

export interface DimensionSelection {
  readonly selectedDimensionId: InitialResearchDimensionId;
  readonly method: "ucb1";
  readonly scores: readonly DimensionScore[];
  readonly reason: string;
}

function validateStatistics(statistics: ResearchDimensionStatistics): void {
  if (!Number.isSafeInteger(statistics.trials) || statistics.trials < 0) {
    throw new Error(`${statistics.id} has invalid trial count.`);
  }
  if (!Number.isFinite(statistics.meanImprovement)) {
    throw new Error(`${statistics.id} has invalid mean improvement.`);
  }
  if (!Number.isFinite(statistics.variance) || statistics.variance < 0) {
    throw new Error(`${statistics.id} has invalid variance.`);
  }
  if (!Number.isSafeInteger(statistics.failureCount) || statistics.failureCount < 0) {
    throw new Error(`${statistics.id} has invalid failure count.`);
  }
  if (!Number.isSafeInteger(statistics.safetyFailureCount) || statistics.safetyFailureCount < 0) {
    throw new Error(`${statistics.id} has invalid safety-failure count.`);
  }
}

export class Ucb1SearchPolicy {
  readonly explorationCoefficient: number;

  constructor(explorationCoefficient = Math.SQRT2) {
    if (!Number.isFinite(explorationCoefficient) || explorationCoefficient <= 0) {
      throw new Error("UCB1 exploration coefficient must be positive and finite.");
    }
    this.explorationCoefficient = explorationCoefficient;
  }

  select(
    statistics: readonly ResearchDimensionStatistics[],
    eligibleDimensionIds: readonly InitialResearchDimensionId[],
    bounds: SearchBounds,
  ): DimensionSelection {
    if (statistics.length === 0 || eligibleDimensionIds.length === 0) {
      throw new Error("UCB1 requires at least one eligible research dimension.");
    }
    const eligibleSet = new Set(eligibleDimensionIds);
    const byId = new Map<InitialResearchDimensionId, ResearchDimensionStatistics>();
    for (const item of statistics) {
      validateStatistics(item);
      if (byId.has(item.id)) throw new Error(`Duplicate research statistics for ${item.id}.`);
      byId.set(item.id, item);
    }
    for (const id of eligibleDimensionIds) {
      if (!byId.has(id)) throw new Error(`Missing research statistics for ${id}.`);
    }
    const totalTrials = eligibleDimensionIds.reduce((sum, id) => sum + byId.get(id)!.trials, 0);
    const scores: DimensionScore[] = statistics
      .filter(({ id }) => eligibleSet.has(id))
      .map((item): DimensionScore => {
        if (item.safetyFailureCount >= bounds.safetyFailureCircuitBreaker) {
          return { id: item.id, score: null, eligible: false, reason: "safety circuit breaker open" };
        }
        if (item.trials >= bounds.maxTrialsPerDimension) {
          return { id: item.id, score: null, eligible: false, reason: "dimension trial budget exhausted" };
        }
        if (item.trials === 0) {
          return { id: item.id, score: null, eligible: true, reason: "untried dimension receives priority" };
        }
        const exploration = this.explorationCoefficient * Math.sqrt(
          Math.log(Math.max(1, totalTrials) + 1) / item.trials,
        );
        const failurePenalty = item.failureCount / item.trials * 0.25;
        const safetyPenalty = item.safetyFailureCount / item.trials;
        return {
          id: item.id,
          score: item.meanImprovement + exploration - failurePenalty - safetyPenalty,
          eligible: true,
          reason: "mean improvement plus bounded UCB1 exploration minus failure penalties",
        };
      })
      .sort((left, right) => left.id.localeCompare(right.id));
    const candidates = scores.filter(({ eligible }) => eligible);
    if (candidates.length === 0) {
      throw new Error("All research dimensions are stopped by trial budgets or safety circuit breakers.");
    }
    const untried = candidates.filter(({ score }) => score === null);
    const selected = untried.length > 0
      ? untried[0]!
      : [...candidates].sort((left, right) => {
          const scoreDelta = (right.score ?? Number.NEGATIVE_INFINITY) - (left.score ?? Number.NEGATIVE_INFINITY);
          return scoreDelta !== 0 ? scoreDelta : left.id.localeCompare(right.id);
        })[0]!;
    return deepFreeze({
      selectedDimensionId: selected.id,
      method: "ucb1",
      scores,
      reason: selected.reason,
    });
  }

  recordOutcome(
    current: ResearchDimensionStatistics,
    improvement: number,
    outcome: "success" | "failure" | "safety_failure",
    attemptedAt: string,
  ): ResearchDimensionStatistics {
    validateStatistics(current);
    if (!Number.isFinite(improvement)) throw new Error("Research improvement must be finite.");
    const trials = current.trials + 1;
    const delta = improvement - current.meanImprovement;
    const meanImprovement = current.meanImprovement + delta / trials;
    const previousM2 = current.trials > 1 ? current.variance * (current.trials - 1) : 0;
    const nextM2 = previousM2 + delta * (improvement - meanImprovement);
    return deepFreeze({
      ...current,
      trials,
      meanImprovement,
      variance: trials > 1 ? nextM2 / (trials - 1) : 0,
      failureCount: current.failureCount + (outcome === "failure" ? 1 : 0),
      safetyFailureCount: current.safetyFailureCount + (outcome === "safety_failure" ? 1 : 0),
      lastAttemptedAt: attemptedAt,
    });
  }
}

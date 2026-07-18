import {
  DEFAULT_STRATEGY_BUNDLE,
  INITIAL_RESEARCH_CAMPAIGNS,
  INITIAL_RESEARCH_DIMENSIONS,
  type InitialResearchCampaignId,
  type InitialResearchDimensionId,
  type ResearchBudgets,
  type ResearchCharter,
  type ResearchDimensionStatistics,
  type TrustedBenchmarkScenario,
  type TrustedScenarioResult,
} from "../../../server/research";

export const HASH_A = "a".repeat(64);
export const HASH_B = "b".repeat(64);
export const HASH_C = "c".repeat(64);

export const DEFAULT_RESEARCH_BUDGETS: ResearchBudgets = {
  maxExperiments: 10,
  maxWallClockMs: 100_000,
  maxPublicLlmTokens: 10_000,
  maxEstimatedCost: 25,
  maxToolCalls: 1_000,
  maxConcurrentExperiments: 2,
  maxFailures: 3,
  maxRetries: 2,
  maxPatchOperations: 3,
  maxTrialsPerDimension: 10,
  safetyFailureCircuitBreaker: 2,
};

export function charter(
  campaignId: InitialResearchCampaignId,
  budgets: ResearchBudgets = DEFAULT_RESEARCH_BUDGETS,
): ResearchCharter {
  const definition = INITIAL_RESEARCH_CAMPAIGNS.find(({ id }) => id === campaignId)!;
  return {
    id: `charter_${campaignId}`,
    campaignId,
    version: 1,
    status: "approved",
    approvedBy: "operator-reviewer",
    approvedAt: "2026-07-16T00:00:00.000Z",
    charterHash: HASH_A,
    immutableBenchmarkSnapshotHash: HASH_B,
    immutableEvaluatorHash: HASH_C,
    mutablePaths: definition.dimensionIds.map(
      (id) => INITIAL_RESEARCH_DIMENSIONS.find((item) => item.id === id)!.path,
    ),
    forbiddenPathPrefixes: ["/safety", "/benchmark", "/evaluator"],
    budgets,
  };
}

export function dimensionStatistics(
  campaignId: InitialResearchCampaignId,
  selectedDimensionId: InitialResearchDimensionId,
): ResearchDimensionStatistics[] {
  const definition = INITIAL_RESEARCH_CAMPAIGNS.find(({ id }) => id === campaignId)!;
  if (!definition.dimensionIds.includes(selectedDimensionId)) {
    throw new Error(`${selectedDimensionId} does not belong to ${campaignId}`);
  }
  return definition.dimensionIds.map((id) => ({
    id,
    trials: id === selectedDimensionId ? 0 : 1,
    meanImprovement: id === selectedDimensionId ? 0 : 0.1,
    variance: 0,
    failureCount: 0,
    safetyFailureCount: 0,
  }));
}

export const BENCHMARK_SCENARIOS: readonly TrustedBenchmarkScenario[] = [
  {
    id: "scenario-development-1",
    familyId: "reliability-core",
    split: "development",
    name: "Visible development loop fixture",
    scenarioHash: HASH_A,
    environmentDigest: "sha256:development-image",
    groundTruthRef: "local://ground-truth/development-1",
  },
  {
    id: "scenario-validation-1",
    familyId: "reliability-core",
    split: "validation",
    name: "Visible validation loop fixture",
    scenarioHash: HASH_B,
    environmentDigest: "sha256:validation-image",
    groundTruthRef: "local://ground-truth/validation-1",
  },
  {
    id: "holdout-secret-case-7",
    familyId: "reliability-core",
    split: "hidden_holdout",
    name: "SECRET HOLDOUT LOOP SHAPE",
    scenarioHash: HASH_C,
    environmentDigest: "sha256:hidden-image",
    groundTruthRef: "local://SECRET-HOLDOUT-GROUND-TRUTH",
  },
];

export function trustedResult(
  scenarioId: string,
  split: TrustedScenarioResult["split"],
  metrics: Readonly<Record<string, number>>,
  gateSignals: TrustedScenarioResult["gateSignals"] = [],
): TrustedScenarioResult {
  return {
    scenarioId,
    split,
    source: "local_evaluator",
    metrics,
    gateSignals,
    eventHash: HASH_A,
    evidenceHash: HASH_B,
  };
}

export { DEFAULT_STRATEGY_BUNDLE };

import type { MutableStrategyPath } from "./StrategyBundleSchema";

export const INITIAL_RESEARCH_CAMPAIGN_IDS = [
  "repeated_no_progress_action_reduction",
  "specialist_routing_quality",
  "memory_retrieval_precision",
] as const;

export type InitialResearchCampaignId = (typeof INITIAL_RESEARCH_CAMPAIGN_IDS)[number];

export const INITIAL_RESEARCH_DIMENSIONS = [
  { id: "loop.max_identical_fingerprints", campaignId: "repeated_no_progress_action_reduction", path: "/loopControl/maxIdenticalFingerprints" },
  { id: "loop.no_progress_action_limit", campaignId: "repeated_no_progress_action_reduction", path: "/loopControl/noProgressActionLimit" },
  { id: "loop.max_automatic_replans", campaignId: "repeated_no_progress_action_reduction", path: "/loopControl/maxAutomaticReplans" },
  { id: "routing.minimum_capability_score", campaignId: "specialist_routing_quality", path: "/specialistRouting/minimumCapabilityScore" },
  { id: "routing.max_concurrent_assignments", campaignId: "specialist_routing_quality", path: "/specialistRouting/maxConcurrentAssignments" },
  { id: "routing.handoff_penalty", campaignId: "specialist_routing_quality", path: "/specialistRouting/handoffPenalty" },
  { id: "memory.max_context_items", campaignId: "memory_retrieval_precision", path: "/memoryRetrieval/maxContextItems" },
  { id: "memory.minimum_confidence", campaignId: "memory_retrieval_precision", path: "/memoryRetrieval/minimumConfidence" },
  { id: "memory.recency_weight", campaignId: "memory_retrieval_precision", path: "/memoryRetrieval/recencyWeight" },
  { id: "memory.graph_weight", campaignId: "memory_retrieval_precision", path: "/memoryRetrieval/graphWeight" },
  { id: "memory.lexical_weight", campaignId: "memory_retrieval_precision", path: "/memoryRetrieval/lexicalWeight" },
] as const satisfies readonly {
  readonly id: string;
  readonly campaignId: InitialResearchCampaignId;
  readonly path: MutableStrategyPath;
}[];

export type InitialResearchDimensionId = (typeof INITIAL_RESEARCH_DIMENSIONS)[number]["id"];

export interface InitialResearchCampaignDefinition {
  readonly id: InitialResearchCampaignId;
  readonly title: string;
  readonly purpose: string;
  readonly primaryMetric: string;
  readonly primaryMetricDirection: "higher_better" | "lower_better";
  readonly dimensionIds: readonly InitialResearchDimensionId[];
}

export const INITIAL_RESEARCH_CAMPAIGNS: readonly InitialResearchCampaignDefinition[] = [
  {
    id: "repeated_no_progress_action_reduction",
    title: "Repeated and no-progress action reduction",
    purpose: "Reduce duplicate/no-progress actions while preserving completion, safety, and evidence coverage.",
    primaryMetric: "duplicate_action_rate",
    primaryMetricDirection: "lower_better",
    dimensionIds: [
      "loop.max_identical_fingerprints",
      "loop.no_progress_action_limit",
      "loop.max_automatic_replans",
    ],
  },
  {
    id: "specialist_routing_quality",
    title: "Specialist routing quality",
    purpose: "Improve capable specialist selection and handoffs without hidden commander execution.",
    primaryMetric: "specialist_routing_quality",
    primaryMetricDirection: "higher_better",
    dimensionIds: [
      "routing.minimum_capability_score",
      "routing.max_concurrent_assignments",
      "routing.handoff_penalty",
    ],
  },
  {
    id: "memory_retrieval_precision",
    title: "Memory retrieval precision",
    purpose: "Improve relevant context selection while preventing stale or cross-engagement retrieval.",
    primaryMetric: "memory_retrieval_precision",
    primaryMetricDirection: "higher_better",
    dimensionIds: [
      "memory.max_context_items",
      "memory.minimum_confidence",
      "memory.recency_weight",
      "memory.graph_weight",
      "memory.lexical_weight",
    ],
  },
] as const;

export interface ResearchBudgets {
  readonly maxExperiments: number;
  readonly maxWallClockMs: number;
  readonly maxPublicLlmTokens: number;
  readonly maxEstimatedCost: number;
  readonly maxToolCalls: number;
  readonly maxConcurrentExperiments: number;
  readonly maxFailures: number;
  readonly maxRetries: number;
  readonly maxPatchOperations: number;
  readonly maxTrialsPerDimension: number;
  readonly safetyFailureCircuitBreaker: number;
}

export interface ResearchBudgetUsage {
  readonly experiments: number;
  readonly wallClockMs: number;
  readonly publicLlmTokens: number;
  readonly estimatedCost: number;
  readonly toolCalls: number;
  readonly concurrentExperiments: number;
  readonly failures: number;
  readonly retries: number;
}

export interface ExperimentEstimatedCost {
  readonly wallClockMs: number;
  readonly publicLlmTokens: number;
  readonly estimatedCost: number;
  readonly toolCalls: number;
}

export interface ResearchCharter {
  readonly id: string;
  readonly campaignId: InitialResearchCampaignId;
  readonly version: number;
  readonly status: "approved";
  readonly approvedBy: string;
  readonly approvedAt: string;
  readonly charterHash: string;
  readonly immutableBenchmarkSnapshotHash: string;
  readonly immutableEvaluatorHash: string;
  readonly mutablePaths: readonly MutableStrategyPath[];
  readonly forbiddenPathPrefixes: readonly string[];
  readonly budgets: ResearchBudgets;
}

export function campaignDefinition(
  id: InitialResearchCampaignId,
): InitialResearchCampaignDefinition {
  const definition = INITIAL_RESEARCH_CAMPAIGNS.find((item) => item.id === id);
  if (definition === undefined) throw new Error(`Unknown initial research campaign ${id}.`);
  return definition;
}

export function dimensionDefinition(id: InitialResearchDimensionId) {
  const definition = INITIAL_RESEARCH_DIMENSIONS.find((item) => item.id === id);
  if (definition === undefined) throw new Error(`Unknown initial research dimension ${id}.`);
  return definition;
}

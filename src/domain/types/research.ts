export type InitialResearchCampaignId =
  | "repeated_no_progress_action_reduction"
  | "specialist_routing_quality"
  | "memory_retrieval_precision";

export interface ResearchBudgets {
  maxExperiments: number;
  maxWallClockMs: number;
  maxPublicLlmTokens: number;
  maxEstimatedCost: number;
  maxToolCalls: number;
  maxConcurrentExperiments: number;
  maxFailures: number;
  maxRetries: number;
  maxPatchOperations: number;
  maxTrialsPerDimension: number;
  safetyFailureCircuitBreaker: number;
}

export interface ResearchCampaignRecord {
  id: string;
  catalogId: InitialResearchCampaignId;
  name: string;
  purpose: string;
  status: "draft" | "approved" | "running" | "paused" | "completed" | "stopped" | "rejected";
  owner: string;
  budgets: ResearchBudgets;
  dimensionCount: number;
  experimentCount: number;
  charterCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface ResearchLabSnapshot {
  schemaVersion: "2.4";
  governingPrinciple: string;
  readiness: {
    status: "ready" | "blocked";
    checks: Array<{
      id: string;
      status: "pass" | "fail";
      label: string;
      impact: string;
      remediation?: string;
    }>;
  };
  publicLlmBoundary: {
    role: "proposal_only";
    rawClientEvidenceAllowed: false;
    directToolExecutionAllowed: false;
    authoritativeScoringAllowed: false;
    automaticPromotionAllowed: false;
  };
  promotionPath: ["development", "validation", "hidden_holdout", "human_review", "shadow", "bounded_canary", "verified"];
  catalog: Array<{
    id: InitialResearchCampaignId;
    title: string;
    purpose: string;
    primaryMetric: string;
    primaryMetricDirection: "higher_better" | "lower_better";
    mutablePaths: string[];
    existingCampaignIds: string[];
  }>;
  campaigns: ResearchCampaignRecord[];
  experiments: Array<{
    id: string;
    campaignId: string;
    hypothesis: string;
    status: string;
    dimensionId: string;
    candidateStrategyId: string;
    updatedAt: string;
  }>;
  integrity: {
    benchmarkFamilies: number;
    benchmarkSnapshots: number;
    approvedCharters: number;
    integrityReceipts: number;
    providerExposureReceipts: number;
    blockedProviderExposures: number;
  };
}

export interface ResearchCampaignMutation {
  schemaVersion: "2.4";
  campaign: ResearchCampaignRecord;
  nextUrl?: string;
}

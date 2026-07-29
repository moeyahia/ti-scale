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

export type ResearchPromotionState =
  | "proposed"
  | "policy_rejected"
  | "queued"
  | "running"
  | "early_aborted"
  | "failed"
  | "benchmarked"
  | "holdout_failed"
  | "shadow_ready"
  | "shadow_running"
  | "canary_ready"
  | "canary_running"
  | "verified"
  | "rejected"
  | "stale"
  | "superseded"
  | "rolled_back";

export type HumanResearchPromotionAction =
  | "approve_human_review"
  | "reject_human_review"
  | "start_shadow"
  | "approve_canary"
  | "start_canary"
  | "verify"
  | "reject"
  | "mark_stale"
  | "supersede"
  | "rollback";

export type LocalResearchPromotionAction =
  | "policy_accept"
  | "policy_reject"
  | "start_benchmark"
  | "development_pass"
  | "development_fail"
  | "validation_pass"
  | "validation_fail"
  | "hidden_holdout_pass"
  | "hidden_holdout_fail"
  | "shadow_pass"
  | "shadow_fail"
  | "canary_pass"
  | "canary_fail";

export type ResearchPromotionAction =
  | LocalResearchPromotionAction
  | HumanResearchPromotionAction;

export type ResearchHardGateCode =
  | "scope_violation"
  | "policy_bypass"
  | "unauthorized_destructive_action"
  | "provider_sensitive_exposure"
  | "prompt_injection_compliance"
  | "fabricated_evidence"
  | "unsupported_finding"
  | "evaluator_mutation"
  | "benchmark_mutation"
  | "budget_overrun"
  | "unbounded_loop"
  | "orphaned_process"
  | "cross_engagement_memory_leak"
  | "commander_direct_execution"
  | "integrity_receipt_mismatch";

export interface ResearchPromotionLifecycleRecord {
  experimentId: string;
  campaignId: string;
  strategyVersionId: string;
  state: ResearchPromotionState;
  stage:
    | "development"
    | "validation"
    | "hidden_holdout"
    | "human_review"
    | "shadow"
    | "bounded_canary"
    | "verified"
    | "terminal";
  milestones: {
    developmentPassed: boolean;
    validationPassed: boolean;
    hiddenHoldoutPassed: boolean;
    humanReviewApproved: boolean;
    shadowPassed: boolean;
    canaryPassed: boolean;
  };
  version: number;
  updatedAt: string;
  latestIntegrityReceiptId?: string;
  availableHumanActions: HumanResearchPromotionAction[];
  rollbackTargets: Array<{
    experimentId: string;
    strategyVersionId: string;
  }>;
  transitions: Array<{
    id: string;
    sequence: number;
    version: number;
    fromState: ResearchPromotionState;
    toState: ResearchPromotionState;
    action: ResearchPromotionAction;
    actorKind: "local_policy" | "local_evaluator" | "human_reviewer";
    actorId: string;
    rationale: string;
    evidenceRefs: string[];
    hardGateFailures: ResearchHardGateCode[];
    /**
     * Exact normalized human decision binding. Legacy transitions created
     * before the binding migration may omit it and are never attributed as a
     * successful response-loss reconciliation.
     */
    decisionFingerprint?: string;
    integrityReceiptId?: string;
    exposureReceiptIds: string[];
    deploymentId?: string;
    createdAt: string;
  }>;
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
    setup: ResearchCampaignSetupPreview;
  }>;
  campaigns: ResearchCampaignRecord[];
  experiments: Array<{
    id: string;
    campaignId: string;
    hypothesis: string;
    status: string;
    dimensionId: string;
    candidateStrategyId: string;
    scenarioId: string;
    latestRun?: {
      id: string;
      status: ResearchExperimentRunStatus;
      startedAt: string | null;
      endedAt: string | null;
    };
    updatedAt: string;
  }>;
  promotions: ResearchPromotionLifecycleRecord[];
  integrity: {
    benchmarkFamilies: number;
    benchmarkSnapshots: number;
    approvedCharters: number;
    integrityReceipts: number;
    providerExposureReceipts: number;
    blockedProviderExposures: number;
  };
}

export interface ResearchCampaignSetupPreview {
  candidatePresetId: string;
  dimensionId: string;
  path: string;
  hypothesis: string;
  patch: Array<{
    op: "replace";
    path: string;
    value: string | number | boolean | null;
  }>;
  developmentScenarioId: string;
  splitCounts: {
    development: 1;
    validation: 1;
    hiddenHoldout: "operator_descriptor_required";
  };
  baselineBundleHash: string | null;
  candidateBundleHash: string | null;
  evaluatorHash: string | null;
  toolManifestHash: string | null;
  executionEnvironmentIdentityHash: string | null;
  executionReadiness: "ready" | "blocked";
  executionBoundary: {
    targetClass: "synthetic_fixture";
    liveClientTargetAllowed: false;
    outboundNetworkAllowed: false;
    publicProviderUsed: false;
    arbitrarySourcePatchAllowed: false;
    automaticPromotionAllowed: false;
    automaticDeploymentAllowed: false;
  };
}

export interface ResearchCampaignSetupMutation {
  schemaVersion: "2.4";
  campaign: ResearchCampaignRecord;
  setup: {
    charterId: string;
    charterHash: string;
    benchmarkFamilyId: string;
    benchmarkSnapshotId: string;
    benchmarkSnapshotHash: string;
    developmentScenarioId: string;
    baselineStrategyId: string;
    baselineStrategyHash: string;
    candidateStrategyId: string;
    candidateStrategyHash: string;
    strategyPatchId: string;
    strategyPatchHash: string;
    experimentId: string;
    experimentStatus: "queued";
    candidatePresetId: string;
    dimensionId: string;
    hypothesis: string;
    automaticPromotion: false;
    automaticDeployment: false;
  };
}

export type ResearchExperimentRunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "early_aborted";

export interface ResearchExperimentRunRecord {
  id: string;
  experimentId: string;
  scenarioId: string;
  seed: string;
  workerId: string;
  status: ResearchExperimentRunStatus;
  startedAt: string | null;
  endedAt: string | null;
  createdAt: string;
}

export interface ResearchExperimentRunMutation {
  schemaVersion: "2.4";
  run: ResearchExperimentRunRecord;
}

export interface ResearchCampaignMutation {
  schemaVersion: "2.4";
  campaign: ResearchCampaignRecord;
  nextUrl?: string;
}

export interface ResearchPromotionMutation {
  schemaVersion: "2.4";
  lifecycle: ResearchPromotionLifecycleRecord;
}

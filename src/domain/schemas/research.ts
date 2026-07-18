import { array, boolean, nonEmpty, number, object, schema, stringList } from "./common";
import type {
  InitialResearchCampaignId,
  ResearchBudgets,
  ResearchCampaignMutation,
  ResearchCampaignRecord,
  ResearchLabSnapshot,
} from "../types/research";

const CAMPAIGN_IDS = new Set<InitialResearchCampaignId>([
  "repeated_no_progress_action_reduction",
  "specialist_routing_quality",
  "memory_retrieval_precision",
]);
const CAMPAIGN_STATES = new Set<ResearchCampaignRecord["status"]>([
  "draft", "approved", "running", "paused", "completed", "stopped", "rejected",
]);

function campaignId(value: unknown): InitialResearchCampaignId {
  const result = nonEmpty(value, "research campaign catalog ID") as InitialResearchCampaignId;
  if (!CAMPAIGN_IDS.has(result)) throw new Error("research campaign catalog ID is not registered");
  return result;
}

function integer(value: unknown, label: string): number {
  const result = number(value, label);
  if (!Number.isSafeInteger(result) || result < 0) throw new Error(`${label} must be a non-negative integer`);
  return result;
}

function budgets(value: unknown): ResearchBudgets {
  const item = object(value, "research budgets");
  return {
    maxExperiments: integer(item.maxExperiments, "maxExperiments"),
    maxWallClockMs: integer(item.maxWallClockMs, "maxWallClockMs"),
    maxPublicLlmTokens: integer(item.maxPublicLlmTokens, "maxPublicLlmTokens"),
    maxEstimatedCost: number(item.maxEstimatedCost, "maxEstimatedCost"),
    maxToolCalls: integer(item.maxToolCalls, "maxToolCalls"),
    maxConcurrentExperiments: integer(item.maxConcurrentExperiments, "maxConcurrentExperiments"),
    maxFailures: integer(item.maxFailures, "maxFailures"),
    maxRetries: integer(item.maxRetries, "maxRetries"),
    maxPatchOperations: integer(item.maxPatchOperations, "maxPatchOperations"),
    maxTrialsPerDimension: integer(item.maxTrialsPerDimension, "maxTrialsPerDimension"),
    safetyFailureCircuitBreaker: integer(item.safetyFailureCircuitBreaker, "safetyFailureCircuitBreaker"),
  };
}

export function parseResearchCampaign(value: unknown): ResearchCampaignRecord {
  const item = object(value, "research campaign");
  const status = nonEmpty(item.status, "research campaign status") as ResearchCampaignRecord["status"];
  if (!CAMPAIGN_STATES.has(status)) throw new Error("research campaign status is invalid");
  return {
    id: nonEmpty(item.id, "research campaign ID"),
    catalogId: campaignId(item.catalogId),
    name: nonEmpty(item.name, "research campaign name"),
    purpose: nonEmpty(item.purpose, "research campaign purpose"),
    status,
    owner: nonEmpty(item.owner, "research campaign owner"),
    budgets: budgets(item.budgets),
    dimensionCount: integer(item.dimensionCount, "dimensionCount"),
    experimentCount: integer(item.experimentCount, "experimentCount"),
    charterCount: integer(item.charterCount, "charterCount"),
    createdAt: nonEmpty(item.createdAt, "research campaign createdAt"),
    updatedAt: nonEmpty(item.updatedAt, "research campaign updatedAt"),
  };
}

export function parseResearchLab(payload: unknown): ResearchLabSnapshot {
  const root = object(payload, "Research Lab");
  schema(root);
  const readiness = object(root.readiness, "research readiness");
  const readinessStatus = readiness.status === "ready" || readiness.status === "blocked"
    ? readiness.status : (() => { throw new Error("research readiness status is invalid"); })();
  const boundary = object(root.publicLlmBoundary, "public LLM boundary");
  if (
    boundary.role !== "proposal_only"
    || boolean(boundary.rawClientEvidenceAllowed, "rawClientEvidenceAllowed") !== false
    || boolean(boundary.directToolExecutionAllowed, "directToolExecutionAllowed") !== false
    || boolean(boundary.authoritativeScoringAllowed, "authoritativeScoringAllowed") !== false
    || boolean(boundary.automaticPromotionAllowed, "automaticPromotionAllowed") !== false
  ) throw new Error("public LLM research boundary is unsafe");
  const promotionPath = stringList(root.promotionPath, "promotion path");
  const expectedPath = ["development", "validation", "hidden_holdout", "human_review", "shadow", "bounded_canary", "verified"];
  if (promotionPath.join("|") !== expectedPath.join("|")) throw new Error("research promotion path is invalid");
  const integrity = object(root.integrity, "research integrity");
  return {
    schemaVersion: "2.4",
    governingPrinciple: nonEmpty(root.governingPrinciple, "governing principle"),
    readiness: {
      status: readinessStatus,
      checks: array(readiness.checks, "research readiness checks").map((value) => {
        const item = object(value, "research readiness check");
        const status = item.status === "pass" || item.status === "fail"
          ? item.status : (() => { throw new Error("research readiness check status is invalid"); })();
        return {
          id: nonEmpty(item.id, "research readiness check ID"), status,
          label: nonEmpty(item.label, "research readiness check label"),
          impact: nonEmpty(item.impact, "research readiness check impact"),
          ...(typeof item.remediation === "string" ? { remediation: item.remediation } : {}),
        };
      }),
    },
    publicLlmBoundary: {
      role: "proposal_only",
      rawClientEvidenceAllowed: false,
      directToolExecutionAllowed: false,
      authoritativeScoringAllowed: false,
      automaticPromotionAllowed: false,
    },
    promotionPath: expectedPath as ResearchLabSnapshot["promotionPath"],
    catalog: array(root.catalog, "research catalog").map((value) => {
      const item = object(value, "research catalog item");
      const direction = item.primaryMetricDirection === "higher_better" || item.primaryMetricDirection === "lower_better"
        ? item.primaryMetricDirection : (() => { throw new Error("primary metric direction is invalid"); })();
      return {
        id: campaignId(item.id), title: nonEmpty(item.title, "catalog title"),
        purpose: nonEmpty(item.purpose, "catalog purpose"),
        primaryMetric: nonEmpty(item.primaryMetric, "primary metric"),
        primaryMetricDirection: direction,
        mutablePaths: stringList(item.mutablePaths, "mutable paths"),
        existingCampaignIds: stringList(item.existingCampaignIds, "existing campaign IDs"),
      };
    }),
    campaigns: array(root.campaigns, "research campaigns").map(parseResearchCampaign),
    experiments: array(root.experiments, "research experiments").map((value) => {
      const item = object(value, "research experiment");
      return {
        id: nonEmpty(item.id, "experiment ID"), campaignId: nonEmpty(item.campaignId, "experiment campaign ID"),
        hypothesis: nonEmpty(item.hypothesis, "experiment hypothesis"), status: nonEmpty(item.status, "experiment status"),
        dimensionId: nonEmpty(item.dimensionId, "experiment dimension"),
        candidateStrategyId: nonEmpty(item.candidateStrategyId, "candidate strategy ID"),
        updatedAt: nonEmpty(item.updatedAt, "experiment updatedAt"),
      };
    }),
    integrity: {
      benchmarkFamilies: integer(integrity.benchmarkFamilies, "benchmarkFamilies"),
      benchmarkSnapshots: integer(integrity.benchmarkSnapshots, "benchmarkSnapshots"),
      approvedCharters: integer(integrity.approvedCharters, "approvedCharters"),
      integrityReceipts: integer(integrity.integrityReceipts, "integrityReceipts"),
      providerExposureReceipts: integer(integrity.providerExposureReceipts, "providerExposureReceipts"),
      blockedProviderExposures: integer(integrity.blockedProviderExposures, "blockedProviderExposures"),
    },
  };
}

export function parseResearchCampaignMutation(payload: unknown): ResearchCampaignMutation {
  const root = object(payload, "research campaign mutation");
  schema(root);
  return {
    schemaVersion: "2.4",
    campaign: parseResearchCampaign(root.campaign),
    ...(typeof root.nextUrl === "string" ? { nextUrl: root.nextUrl } : {}),
  };
}

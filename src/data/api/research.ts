import {
  parseResearchCampaignMutation,
  parseResearchCampaignSetupMutation,
  parseResearchExperimentRunMutation,
  parseResearchLab,
  parseResearchPromotionMutation,
} from "../../domain/schemas/research";
import type {
  HumanResearchPromotionAction,
  InitialResearchCampaignId,
  ResearchCampaignMutation,
  ResearchCampaignSetupMutation,
  ResearchExperimentRunMutation,
  ResearchLabSnapshot,
  ResearchPromotionMutation,
} from "../../domain/types/research";
import { apiRequest } from "./client";

const ROOT = "/api/v2/research";

export interface ResearchPromotionRequestBody {
  readonly expectedVersion: number;
  readonly action: HumanResearchPromotionAction;
  readonly rationale: string;
  readonly evidenceRefs: readonly string[];
  readonly targetStrategyVersionId?: string;
  readonly canaryBounds?: {
    readonly maxMissions: number;
    readonly maxWallClockMs: number;
  };
}

export function serializeResearchPromotionRequest(
  input: ResearchPromotionRequestBody,
): string {
  return JSON.stringify({
    expectedVersion: input.expectedVersion,
    action: input.action,
    rationale: input.rationale,
    evidenceRefs: input.evidenceRefs,
    ...(input.targetStrategyVersionId
      ? { targetStrategyVersionId: input.targetStrategyVersionId }
      : {}),
    ...(input.canaryBounds
      ? { canaryBounds: input.canaryBounds }
      : {}),
  });
}

export const researchApi = {
  snapshot(signal?: AbortSignal): Promise<ResearchLabSnapshot> {
    return apiRequest(ROOT, { method: "GET", signal, parse: parseResearchLab });
  },
  createCampaign(catalogId: InitialResearchCampaignId, idempotencyKey: string, signal?: AbortSignal): Promise<ResearchCampaignMutation> {
    return apiRequest(`${ROOT}/campaigns`, {
      method: "POST",
      signal,
      headers: { "Idempotency-Key": idempotencyKey },
      body: JSON.stringify({ catalogId, ownerAcknowledged: true }),
      parse: parseResearchCampaignMutation,
    });
  },
  approveAndQueueCampaign(input: {
    readonly campaignId: string;
    readonly expectedUpdatedAt: string;
    readonly candidatePresetId: string;
    readonly idempotencyKey: string;
    readonly signal?: AbortSignal;
  }): Promise<ResearchCampaignSetupMutation> {
    return apiRequest(
      `${ROOT}/campaigns/${encodeURIComponent(input.campaignId)}/setup`,
      {
        method: "POST",
        signal: input.signal,
        headers: { "Idempotency-Key": input.idempotencyKey },
        body: JSON.stringify({
          expectedUpdatedAt: input.expectedUpdatedAt,
          candidatePresetId: input.candidatePresetId,
          ownerApproval: true,
        }),
        parse: parseResearchCampaignSetupMutation,
      },
    );
  },
  startExperiment(input: {
    readonly experimentId: string;
    readonly scenarioId: string;
    readonly seed: string;
    readonly idempotencyKey: string;
    readonly signal?: AbortSignal;
  }): Promise<ResearchExperimentRunMutation> {
    return apiRequest(
      `${ROOT}/experiments/${encodeURIComponent(input.experimentId)}/runs`,
      {
        method: "POST",
        signal: input.signal,
        headers: { "Idempotency-Key": input.idempotencyKey },
        body: JSON.stringify({
          scenarioId: input.scenarioId,
          seed: input.seed,
        }),
        parse: parseResearchExperimentRunMutation,
      },
    );
  },
  experimentRun(
    experimentId: string,
    runId: string,
    signal?: AbortSignal,
  ): Promise<ResearchExperimentRunMutation> {
    return apiRequest(
      `${ROOT}/experiments/${encodeURIComponent(experimentId)}/runs/${encodeURIComponent(runId)}`,
      {
        method: "GET",
        signal,
        parse: parseResearchExperimentRunMutation,
      },
    );
  },
  cancelExperiment(input: {
    readonly experimentId: string;
    readonly runId: string;
    readonly reason: string;
    readonly idempotencyKey: string;
    readonly signal?: AbortSignal;
  }): Promise<ResearchExperimentRunMutation> {
    return apiRequest(
      `${ROOT}/experiments/${encodeURIComponent(input.experimentId)}/runs/${encodeURIComponent(input.runId)}/cancel`,
      {
        method: "POST",
        signal: input.signal,
        headers: { "Idempotency-Key": input.idempotencyKey },
        body: JSON.stringify({ reason: input.reason }),
        parse: parseResearchExperimentRunMutation,
      },
    );
  },
  stopCampaign(campaignId: string, expectedUpdatedAt: string, reason: string, idempotencyKey: string, signal?: AbortSignal): Promise<ResearchCampaignMutation> {
    return apiRequest(`${ROOT}/campaigns/${encodeURIComponent(campaignId)}/stop`, {
      method: "POST",
      signal,
      headers: { "Idempotency-Key": idempotencyKey },
      body: JSON.stringify({ expectedUpdatedAt, reason }),
      parse: parseResearchCampaignMutation,
    });
  },
  transitionPromotion(input: {
    readonly experimentId: string;
    readonly expectedVersion: number;
    readonly action: HumanResearchPromotionAction;
    readonly rationale: string;
    readonly evidenceRefs: readonly string[];
    readonly targetStrategyVersionId?: string;
    readonly canaryBounds?: {
      readonly maxMissions: number;
      readonly maxWallClockMs: number;
    };
    readonly idempotencyKey: string;
    readonly signal?: AbortSignal;
  }): Promise<ResearchPromotionMutation> {
    return this.transitionPromotionSerialized(
      input.experimentId,
      serializeResearchPromotionRequest(input),
      input.idempotencyKey,
      input.signal,
    );
  },
  transitionPromotionSerialized(
    experimentId: string,
    serializedBody: string,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<ResearchPromotionMutation> {
    return apiRequest(
      `${ROOT}/experiments/${encodeURIComponent(experimentId)}/promotion`,
      {
        method: "POST",
        signal,
        headers: { "Idempotency-Key": idempotencyKey },
        body: serializedBody,
        parse: parseResearchPromotionMutation,
      },
    );
  },
};

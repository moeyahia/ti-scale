import { parseResearchCampaignMutation, parseResearchLab } from "../../domain/schemas/research";
import type { InitialResearchCampaignId, ResearchCampaignMutation, ResearchLabSnapshot } from "../../domain/types/research";
import { apiRequest } from "./client";

const ROOT = "/api/v2/research";

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
  stopCampaign(campaignId: string, expectedUpdatedAt: string, reason: string, idempotencyKey: string, signal?: AbortSignal): Promise<ResearchCampaignMutation> {
    return apiRequest(`${ROOT}/campaigns/${encodeURIComponent(campaignId)}/stop`, {
      method: "POST",
      signal,
      headers: { "Idempotency-Key": idempotencyKey },
      body: JSON.stringify({ expectedUpdatedAt, reason }),
      parse: parseResearchCampaignMutation,
    });
  },
};

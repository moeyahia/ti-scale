import {
  parseGuidedCommanderReply,
  parseGuidedMemoryCandidate,
  parseGuidedMemorySuppression,
  parseGuidedTranscript,
} from "../../domain/schemas/guidedCommander";
import type {
  GuidedCommanderReplyEnvelope,
  GuidedContextualActionInput,
  GuidedDoNotRememberInput,
  GuidedMemoryCandidateResult,
  GuidedMemorySuppressionResult,
  GuidedRememberInput,
  GuidedTextResultInput,
  GuidedTranscript,
} from "../../domain/types/guidedCommander";
import { apiRequest } from "./client";

export const GUIDED_COMMANDER_ENDPOINTS = {
  transcript: (missionId: string) => `/api/v2/guided/${encodeURIComponent(missionId)}/commander/transcript`,
  explainMore: (missionId: string) => `/api/v2/guided/${encodeURIComponent(missionId)}/commander/explain-more`,
  showNextStep: (missionId: string) => `/api/v2/guided/${encodeURIComponent(missionId)}/commander/show-next-step`,
  interpretResult: (missionId: string) => `/api/v2/guided/${encodeURIComponent(missionId)}/commander/interpret-result`,
  useAnotherApproach: (missionId: string) => `/api/v2/guided/${encodeURIComponent(missionId)}/commander/use-another-approach`,
  remember: (missionId: string) => `/api/v2/guided/${encodeURIComponent(missionId)}/commander/remember`,
  doNotRemember: (missionId: string) => `/api/v2/guided/${encodeURIComponent(missionId)}/commander/do-not-remember`,
} as const;

function mutation<T>(
  path: string,
  body: unknown,
  idempotencyKey: string,
  parse: (payload: unknown) => T,
  signal?: AbortSignal,
): Promise<T> {
  return apiRequest(path, {
    method: "POST",
    signal,
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify(body),
    parse,
  });
}

export const guidedCommanderApi = {
  transcript(
    missionId: string,
    query: { runId: string; stepId?: string; cursor?: string; limit?: number },
    signal?: AbortSignal,
  ): Promise<GuidedTranscript> {
    const params = new URLSearchParams({ runId: query.runId });
    if (query.stepId) params.set("stepId", query.stepId);
    if (query.cursor) params.set("cursor", query.cursor);
    if (query.limit !== undefined) params.set("limit", String(query.limit));
    return apiRequest(`${GUIDED_COMMANDER_ENDPOINTS.transcript(missionId)}?${params}`, {
      method: "GET",
      signal,
      parse: parseGuidedTranscript,
    });
  },

  explainMore(
    missionId: string,
    input: GuidedContextualActionInput,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<GuidedCommanderReplyEnvelope> {
    return mutation(
      GUIDED_COMMANDER_ENDPOINTS.explainMore(missionId),
      input,
      idempotencyKey,
      parseGuidedCommanderReply,
      signal,
    );
  },

  showNextStep(
    missionId: string,
    input: GuidedContextualActionInput,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<GuidedCommanderReplyEnvelope> {
    return mutation(
      GUIDED_COMMANDER_ENDPOINTS.showNextStep(missionId),
      input,
      idempotencyKey,
      parseGuidedCommanderReply,
      signal,
    );
  },

  interpretResult(
    missionId: string,
    input: GuidedTextResultInput,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<GuidedCommanderReplyEnvelope> {
    return mutation(
      GUIDED_COMMANDER_ENDPOINTS.interpretResult(missionId),
      input,
      idempotencyKey,
      parseGuidedCommanderReply,
      signal,
    );
  },

  useAnotherApproach(
    missionId: string,
    input: GuidedContextualActionInput,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<GuidedCommanderReplyEnvelope> {
    return mutation(
      GUIDED_COMMANDER_ENDPOINTS.useAnotherApproach(missionId),
      input,
      idempotencyKey,
      parseGuidedCommanderReply,
      signal,
    );
  },

  remember(
    missionId: string,
    input: GuidedRememberInput,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<GuidedMemoryCandidateResult> {
    return mutation(
      GUIDED_COMMANDER_ENDPOINTS.remember(missionId),
      input,
      idempotencyKey,
      parseGuidedMemoryCandidate,
      signal,
    );
  },

  doNotRemember(
    missionId: string,
    input: GuidedDoNotRememberInput,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<GuidedMemorySuppressionResult> {
    return mutation(
      GUIDED_COMMANDER_ENDPOINTS.doNotRemember(missionId),
      input,
      idempotencyKey,
      parseGuidedMemorySuppression,
      signal,
    );
  },
};

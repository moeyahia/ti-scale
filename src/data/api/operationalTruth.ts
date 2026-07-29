import {
  parseEngagementLogDetail,
  parseEngagementLogPage,
  parseEvidenceCandidateDetail,
  parseEvidenceCandidateMutation,
  parseEvidenceCandidatePage,
  parseFailureDiagnosisDetail,
  parseFailureDiagnosisList,
  parseFailureDiagnosisMutation,
  parseObservationDetail,
  parseObservationPage,
  parseVerifiedEvidenceDetail,
  parseVerifiedEvidenceMutation,
  parseVerifiedEvidencePage,
} from "../../domain/schemas/operationalTruth";
import type {
  EngagementLogDetailV24,
  EngagementLogRecordV24,
  EvidenceCandidateDetailV24,
  EvidenceCandidateMutationV24,
  EvidenceCandidateQueryV24,
  EvidenceCandidateV24,
  FailureDiagnosisDetailV24,
  FailureDiagnosisListV24,
  FailureDiagnosisMutationV24,
  FailureDiagnosisQueryV24,
  ObservationDetailV24,
  ObservationV24,
  OperationalTruthPage,
  OperationalTruthPageQueryV24,
  ResolveFailureDiagnosisRequestV24,
  VerifiedEvidenceDetailV24,
  VerifiedEvidenceMutationV24,
  VerifiedEvidenceV24,
  VerifyEvidenceCandidateRequestV24,
} from "../../domain/types/operationalTruth";
import { apiRequest } from "./client";

const ROOT = "/api/v2/operational-truth";

function missionRoot(missionId: string): string {
  return `${ROOT}/missions/${encodeURIComponent(missionId)}`;
}

function pageQuery(query: OperationalTruthPageQueryV24): URLSearchParams {
  const params = new URLSearchParams();
  if (query.runId) params.set("runId", query.runId);
  if (query.stepId) params.set("stepId", query.stepId);
  if (query.cursor) params.set("cursor", query.cursor);
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  return params;
}

function queryPath(path: string, params: URLSearchParams): string {
  const value = params.toString();
  return value ? `${path}?${value}` : path;
}

function get<T>(path: string, parse: (payload: unknown) => T, signal?: AbortSignal): Promise<T> {
  return apiRequest(path, { method: "GET", signal, parse });
}

function mutate<T>(
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

export const operationalTruthApi = {
  listLogs(
    missionId: string,
    query: OperationalTruthPageQueryV24 = {},
    signal?: AbortSignal,
  ): Promise<OperationalTruthPage<EngagementLogRecordV24>> {
    return get(queryPath(`${missionRoot(missionId)}/logs`, pageQuery(query)), parseEngagementLogPage, signal);
  },

  log(missionId: string, logId: string, signal?: AbortSignal): Promise<EngagementLogDetailV24> {
    return get(
      `${missionRoot(missionId)}/logs/${encodeURIComponent(logId)}`,
      parseEngagementLogDetail,
      signal,
    );
  },

  listObservations(
    missionId: string,
    query: OperationalTruthPageQueryV24 = {},
    signal?: AbortSignal,
  ): Promise<OperationalTruthPage<ObservationV24>> {
    return get(queryPath(`${missionRoot(missionId)}/observations`, pageQuery(query)), parseObservationPage, signal);
  },

  observation(
    missionId: string,
    observationId: string,
    signal?: AbortSignal,
  ): Promise<ObservationDetailV24> {
    return get(
      `${missionRoot(missionId)}/observations/${encodeURIComponent(observationId)}`,
      parseObservationDetail,
      signal,
    );
  },

  listEvidenceCandidates(
    missionId: string,
    query: EvidenceCandidateQueryV24 = {},
    signal?: AbortSignal,
  ): Promise<OperationalTruthPage<EvidenceCandidateV24>> {
    const params = pageQuery(query);
    if (query.state) params.set("state", query.state);
    return get(
      queryPath(`${missionRoot(missionId)}/evidence-candidates`, params),
      parseEvidenceCandidatePage,
      signal,
    );
  },

  evidenceCandidate(
    missionId: string,
    candidateId: string,
    signal?: AbortSignal,
  ): Promise<EvidenceCandidateDetailV24> {
    return get(
      `${missionRoot(missionId)}/evidence-candidates/${encodeURIComponent(candidateId)}`,
      parseEvidenceCandidateDetail,
      signal,
    );
  },

  promoteEvidenceCandidate(
    missionId: string,
    candidateId: string,
    reason: string,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<EvidenceCandidateMutationV24> {
    return mutate(
      `${missionRoot(missionId)}/evidence-candidates/${encodeURIComponent(candidateId)}/promote`,
      { reason },
      idempotencyKey,
      parseEvidenceCandidateMutation,
      signal,
    );
  },

  rejectEvidenceCandidate(
    missionId: string,
    candidateId: string,
    reason: string,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<EvidenceCandidateMutationV24> {
    return mutate(
      `${missionRoot(missionId)}/evidence-candidates/${encodeURIComponent(candidateId)}/reject`,
      { reason },
      idempotencyKey,
      parseEvidenceCandidateMutation,
      signal,
    );
  },

  demoteEvidenceCandidate(
    missionId: string,
    candidateId: string,
    reason: string,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<EvidenceCandidateMutationV24> {
    return mutate(
      `${missionRoot(missionId)}/evidence-candidates/${encodeURIComponent(candidateId)}/demote`,
      { reason },
      idempotencyKey,
      parseEvidenceCandidateMutation,
      signal,
    );
  },

  verifyEvidenceCandidate(
    missionId: string,
    candidateId: string,
    request: VerifyEvidenceCandidateRequestV24,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<VerifiedEvidenceMutationV24> {
    return mutate(
      `${missionRoot(missionId)}/evidence-candidates/${encodeURIComponent(candidateId)}/verify`,
      request,
      idempotencyKey,
      parseVerifiedEvidenceMutation,
      signal,
    );
  },

  listVerifiedEvidence(
    missionId: string,
    query: OperationalTruthPageQueryV24 = {},
    signal?: AbortSignal,
  ): Promise<OperationalTruthPage<VerifiedEvidenceV24>> {
    return get(
      queryPath(`${missionRoot(missionId)}/verified-evidence`, pageQuery(query)),
      parseVerifiedEvidencePage,
      signal,
    );
  },

  verifiedEvidence(
    missionId: string,
    evidenceId: string,
    signal?: AbortSignal,
  ): Promise<VerifiedEvidenceDetailV24> {
    return get(
      `${missionRoot(missionId)}/verified-evidence/${encodeURIComponent(evidenceId)}`,
      parseVerifiedEvidenceDetail,
      signal,
    );
  },

  listFailureDiagnoses(
    missionId: string,
    runId: string,
    query: FailureDiagnosisQueryV24 = {},
    signal?: AbortSignal,
  ): Promise<FailureDiagnosisListV24> {
    const params = new URLSearchParams();
    if (query.states?.length) params.set("states", query.states.join(","));
    if (query.limit !== undefined) params.set("limit", String(query.limit));
    return get(
      queryPath(`${missionRoot(missionId)}/runs/${encodeURIComponent(runId)}/failure-diagnoses`, params),
      parseFailureDiagnosisList,
      signal,
    );
  },

  failureDiagnosis(
    missionId: string,
    runId: string,
    diagnosisId: string,
    signal?: AbortSignal,
  ): Promise<FailureDiagnosisDetailV24> {
    return get(
      `${missionRoot(missionId)}/runs/${encodeURIComponent(runId)}/failure-diagnoses/${encodeURIComponent(diagnosisId)}`,
      parseFailureDiagnosisDetail,
      signal,
    );
  },

  resolveFailureDiagnosis(
    missionId: string,
    runId: string,
    diagnosisId: string,
    request: ResolveFailureDiagnosisRequestV24,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<FailureDiagnosisMutationV24> {
    return mutate(
      `${missionRoot(missionId)}/runs/${encodeURIComponent(runId)}/failure-diagnoses/${encodeURIComponent(diagnosisId)}/resolve`,
      request,
      idempotencyKey,
      parseFailureDiagnosisMutation,
      signal,
    );
  },
};

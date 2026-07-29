import {
  parseCveApplicabilityDetail,
  parseCveApplicabilityList,
  parseCveApplicabilityReviewDetail,
  parseMissionScopedNvdDetail,
} from "../../domain/schemas/cveIntelligence";
import type {
  CveApplicabilityDetail,
  CveApplicabilityFilter,
  CveApplicabilityList,
  CveApplicabilityReviewDetail,
  MissionScopedNvdDetail,
  ReviewCveApplicabilityRequest,
} from "../../domain/types/cveIntelligence";
import { ApiError, apiRequest } from "./client";

interface PendingReviewMutation {
  readonly key: string;
  active: number;
  authoritativeResponseSeen: boolean;
}

const pendingReviewMutations = new Map<string, PendingReviewMutation>();

function canonicalJson(value: unknown): string {
  const normalize = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(normalize);
    if (item && typeof item === "object") {
      return Object.fromEntries(
        Object.entries(item as Record<string, unknown>)
          .filter(([, child]) => child !== undefined)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([name, child]) => [name, normalize(child)]),
      );
    }
    return item;
  };
  return JSON.stringify(normalize(value));
}

async function idempotentReviewMutation(
  exactMutation: unknown,
  execute: (idempotencyKey: string) => Promise<CveApplicabilityReviewDetail>,
): Promise<CveApplicabilityReviewDetail> {
  const fingerprint = canonicalJson(exactMutation);
  const existing = pendingReviewMutations.get(fingerprint);
  const mutation = existing ?? {
    key: `cve-review:${crypto.randomUUID()}`,
    active: 0,
    authoritativeResponseSeen: false,
  };
  mutation.active += 1;
  pendingReviewMutations.set(fingerprint, mutation);
  try {
    const result = await execute(mutation.key);
    mutation.authoritativeResponseSeen = true;
    return result;
  } catch (error) {
    mutation.authoritativeResponseSeen ||= error instanceof ApiError;
    throw error;
  } finally {
    mutation.active = Math.max(0, mutation.active - 1);
    if (
      mutation.active === 0
      && mutation.authoritativeResponseSeen
      && pendingReviewMutations.get(fingerprint) === mutation
    ) {
      pendingReviewMutations.delete(fingerprint);
    }
  }
}

function identifier(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 240 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError(`${label} is invalid`);
  }
  return encodeURIComponent(normalized);
}

function root(missionId: string): string {
  return `/api/v2/missions/${identifier(missionId, "Mission ID")}/intelligence/cves`;
}

function query(filter: CveApplicabilityFilter): string {
  const parameters = new URLSearchParams();
  if (filter.runId) parameters.set("runId", filter.runId.trim());
  if (filter.assetNodeId) parameters.set("assetNodeId", filter.assetNodeId.trim());
  if (filter.serviceNodeId) parameters.set("serviceNodeId", filter.serviceNodeId.trim());
  if (filter.applicability) parameters.set("applicability", filter.applicability);
  if (filter.limit !== undefined) {
    if (!Number.isSafeInteger(filter.limit) || filter.limit < 1 || filter.limit > 100) {
      throw new RangeError("CVE applicability limit must be from 1 through 100");
    }
    parameters.set("limit", String(filter.limit));
  }
  const serialized = parameters.toString();
  return serialized ? `?${serialized}` : "";
}

export const cveIntelligenceApi = {
  list(missionId: string, filter: CveApplicabilityFilter = {}, signal?: AbortSignal): Promise<CveApplicabilityList> {
    return apiRequest(`${root(missionId)}${query(filter)}`, {
      method: "GET",
      signal,
      parse: parseCveApplicabilityList,
    });
  },

  detail(missionId: string, recordId: string, signal?: AbortSignal): Promise<CveApplicabilityDetail> {
    return apiRequest(`${root(missionId)}/${identifier(recordId, "CVE applicability ID")}`, {
      method: "GET",
      signal,
      parse: parseCveApplicabilityDetail,
    });
  },

  review(
    missionId: string,
    recordId: string,
    input: ReviewCveApplicabilityRequest,
    signal?: AbortSignal,
  ): Promise<CveApplicabilityReviewDetail> {
    const exactMutation = {
      missionId: missionId.trim(),
      recordId: recordId.trim(),
      input,
    };
    return idempotentReviewMutation(exactMutation, (idempotencyKey) => apiRequest(
      `${root(missionId)}/${identifier(recordId, "CVE applicability ID")}/review`,
      {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: JSON.stringify(input),
        signal,
        parse: parseCveApplicabilityReviewDetail,
      },
    ));
  },

  officialNvdDetail(
    missionId: string,
    runId: string,
    stepId: string,
    recordId: string,
    signal?: AbortSignal,
  ): Promise<MissionScopedNvdDetail> {
    const expected = {
      missionId: missionId.trim(),
      runId: runId.trim(),
      stepId: stepId.trim(),
      reviewedCveRef: recordId.trim(),
    };
    const path = `/api/v2/missions/${identifier(missionId, "Mission ID")}`
      + `/runs/${identifier(runId, "Run ID")}`
      + `/steps/${identifier(stepId, "Plan step ID")}`
      + `/intelligence/cves/${identifier(recordId, "CVE applicability ID")}/nvd-detail`;
    return apiRequest(path, {
      method: "GET",
      signal,
      parse(payload) {
        const result = parseMissionScopedNvdDetail(payload);
        for (const [key, value] of Object.entries(expected)) {
          if (result.context[key as keyof typeof expected] !== value) {
            throw new Error(`mission-scoped NVD response does not match the requested ${key}`);
          }
        }
        return result;
      },
    });
  },
};

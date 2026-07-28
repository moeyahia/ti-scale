import {
  parsePlanChangeApply,
  parsePlanChangeDetail,
  parsePlanChangeInflightFinalize,
  parsePlanChangeInflightResolution,
  parsePlanChangeList,
} from "../../domain/schemas/planChanges";
import type {
  CreatePlanChangeRequest,
  EditPlanChangeRequest,
  PlanChangeApplyResponse,
  PlanChangeDetailResponse,
  PlanChangeInflightFinalizeResponse,
  PlanChangeInflightResolutionMode,
  PlanChangeInflightResolutionResponse,
  PlanChangeListResponse,
} from "../../domain/types/planChanges";
import { ApiError, apiRequest } from "./client";

function id(value: string, label: string): string {
  const result = value.trim();
  if (!result || result.length > 200 || /[\u0000-\u001f\u007f]/u.test(result)) throw new TypeError(`${label} is invalid`);
  return encodeURIComponent(result);
}

function canonicalJson(value: unknown): string {
  const normalize = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(normalize);
    if (item && typeof item === "object") {
      return Object.fromEntries(Object.entries(item as Record<string, unknown>)
        .filter(([, child]) => child !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([name, child]) => [name, normalize(child)]));
    }
    return item;
  };
  return JSON.stringify(normalize(value));
}

interface PendingMutationKey {
  readonly key: string;
  active: number;
  authoritativeResponseSeen: boolean;
}

const pendingMutationKeys = new Map<string, PendingMutationKey>();

function claimMutationKey(prefix: string, exactMutation: unknown): {
  readonly fingerprint: string;
  readonly claim: PendingMutationKey;
} {
  const fingerprint = `${prefix}:${canonicalJson(exactMutation)}`;
  const existing = pendingMutationKeys.get(fingerprint);
  const claim = existing ?? {
    key: `${prefix}:${crypto.randomUUID()}`,
    active: 0,
    authoritativeResponseSeen: false,
  };
  claim.active += 1;
  pendingMutationKeys.set(fingerprint, claim);
  return { fingerprint, claim };
}

function settleMutationKey(
  fingerprint: string,
  claim: PendingMutationKey,
  authoritativeResponse: boolean,
): void {
  claim.active = Math.max(0, claim.active - 1);
  claim.authoritativeResponseSeen ||= authoritativeResponse;
  if (claim.active === 0 && claim.authoritativeResponseSeen && pendingMutationKeys.get(fingerprint) === claim) {
    pendingMutationKeys.delete(fingerprint);
  }
}

async function idempotentMutation<T>(
  prefix: string,
  exactMutation: unknown,
  execute: (idempotencyKey: string) => Promise<T>,
): Promise<T> {
  const { fingerprint, claim } = claimMutationKey(prefix, exactMutation);
  try {
    const result = await execute(claim.key);
    settleMutationKey(fingerprint, claim, true);
    return result;
  } catch (error) {
    // An HTTP/schema ApiError proves the server replied. A transport or
    // response-decoding failure is ambiguous, so retain this exact key for a
    // safe retry. A later intentional same-body submission receives a fresh
    // key after any authoritative response settles the prior lifecycle.
    settleMutationKey(fingerprint, claim, error instanceof ApiError);
    throw error;
  }
}

function root(runId: string): string { return `/api/v2/runs/${id(runId, "Run ID")}/plan-changes`; }

export const planChangesApi = {
  list(runId: string, signal?: AbortSignal): Promise<PlanChangeListResponse> {
    return apiRequest(root(runId), { method: "GET", signal, parse: parsePlanChangeList });
  },
  get(runId: string, requestId: string, signal?: AbortSignal): Promise<PlanChangeDetailResponse> {
    return apiRequest(`${root(runId)}/${id(requestId, "Plan change ID")}`, { method: "GET", signal, parse: parsePlanChangeDetail });
  },
  async create(runId: string, input: CreatePlanChangeRequest): Promise<PlanChangeDetailResponse> {
    return idempotentMutation("plan-change-create", { runId, input }, (idempotencyKey) => apiRequest(root(runId), { method: "POST", headers: { "Idempotency-Key": idempotencyKey }, body: JSON.stringify(input), parse: parsePlanChangeDetail }));
  },
  async edit(runId: string, requestId: string, input: EditPlanChangeRequest): Promise<PlanChangeDetailResponse> {
    return idempotentMutation("plan-change-edit", { runId, requestId, input }, (idempotencyKey) => apiRequest(`${root(runId)}/${id(requestId, "Plan change ID")}`, { method: "PUT", headers: { "Idempotency-Key": idempotencyKey }, body: JSON.stringify(input), parse: parsePlanChangeDetail }));
  },
  async apply(runId: string, requestId: string, input: { readonly expectedRequestVersion: number; readonly expectedRunVersion: number; readonly expectedPlanVersion: number }): Promise<PlanChangeApplyResponse> {
    return idempotentMutation("plan-change-apply", { runId, requestId, input }, (idempotencyKey) => apiRequest(`${root(runId)}/${id(requestId, "Plan change ID")}/apply`, { method: "POST", headers: { "Idempotency-Key": idempotencyKey }, body: JSON.stringify(input), parse: parsePlanChangeApply }));
  },
  async reject(runId: string, requestId: string, input: { readonly expectedRequestVersion: number; readonly reason: string }): Promise<PlanChangeDetailResponse> {
    return idempotentMutation("plan-change-reject", { runId, requestId, input }, (idempotencyKey) => apiRequest(`${root(runId)}/${id(requestId, "Plan change ID")}/reject`, { method: "POST", headers: { "Idempotency-Key": idempotencyKey }, body: JSON.stringify(input), parse: parsePlanChangeDetail }));
  },
  inflightResolution(
    runId: string,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<PlanChangeInflightResolutionResponse> {
    return apiRequest(
      `${root(runId)}/${id(requestId, "Plan change ID")}/inflight-resolution`,
      { method: "GET", signal, parse: parsePlanChangeInflightResolution },
    );
  },
  async resolveInflight(
    runId: string,
    requestId: string,
    input: {
      readonly mode: PlanChangeInflightResolutionMode;
      readonly expectedRequestVersion: number;
      readonly expectedRunVersion: number;
      readonly expectedPlanVersion: number;
      readonly reason: string;
    },
  ): Promise<PlanChangeInflightResolutionResponse> {
    return idempotentMutation(
      "plan-change-resolve-inflight",
      { runId, requestId, input },
      (idempotencyKey) => apiRequest(
        `${root(runId)}/${id(requestId, "Plan change ID")}/resolve-inflight`,
        {
          method: "POST",
          headers: { "Idempotency-Key": idempotencyKey },
          body: JSON.stringify(input),
          parse: parsePlanChangeInflightResolution,
        },
      ),
    );
  },
  async finalizeInflight(
    runId: string,
    requestId: string,
    input: { readonly expectedResolutionVersion: number },
  ): Promise<PlanChangeInflightFinalizeResponse> {
    return idempotentMutation(
      "plan-change-finalize-inflight",
      { runId, requestId, input },
      (idempotencyKey) => apiRequest(
        `${root(runId)}/${id(requestId, "Plan change ID")}/inflight-resolution/finalize`,
        {
          method: "POST",
          headers: { "Idempotency-Key": idempotencyKey },
          body: JSON.stringify(input),
          parse: parsePlanChangeInflightFinalize,
        },
      ),
    );
  },
};

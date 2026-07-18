import { parsePlanChangeApply, parsePlanChangeDetail, parsePlanChangeList } from "../../domain/schemas/planChanges";
import type {
  CreatePlanChangeRequest,
  EditPlanChangeRequest,
  PlanChangeApplyResponse,
  PlanChangeDetailResponse,
  PlanChangeListResponse,
} from "../../domain/types/planChanges";
import { apiRequest } from "./client";

function id(value: string, label: string): string {
  const result = value.trim();
  if (!result || result.length > 200 || /[\u0000-\u001f\u007f]/u.test(result)) throw new TypeError(`${label} is invalid`);
  return encodeURIComponent(result);
}

function key(prefix: string): string {
  return `${prefix}:${crypto.randomUUID()}`;
}

function root(runId: string): string { return `/api/v2/runs/${id(runId, "Run ID")}/plan-changes`; }

export const planChangesApi = {
  list(runId: string, signal?: AbortSignal): Promise<PlanChangeListResponse> {
    return apiRequest(root(runId), { method: "GET", signal, parse: parsePlanChangeList });
  },
  get(runId: string, requestId: string, signal?: AbortSignal): Promise<PlanChangeDetailResponse> {
    return apiRequest(`${root(runId)}/${id(requestId, "Plan change ID")}`, { method: "GET", signal, parse: parsePlanChangeDetail });
  },
  create(runId: string, input: CreatePlanChangeRequest): Promise<PlanChangeDetailResponse> {
    return apiRequest(root(runId), { method: "POST", headers: { "Idempotency-Key": key("plan-change-create") }, body: JSON.stringify(input), parse: parsePlanChangeDetail });
  },
  edit(runId: string, requestId: string, input: EditPlanChangeRequest): Promise<PlanChangeDetailResponse> {
    return apiRequest(`${root(runId)}/${id(requestId, "Plan change ID")}`, { method: "PUT", headers: { "Idempotency-Key": key("plan-change-edit") }, body: JSON.stringify(input), parse: parsePlanChangeDetail });
  },
  apply(runId: string, requestId: string, input: { readonly expectedRequestVersion: number; readonly expectedRunVersion: number; readonly expectedPlanVersion: number }): Promise<PlanChangeApplyResponse> {
    return apiRequest(`${root(runId)}/${id(requestId, "Plan change ID")}/apply`, { method: "POST", headers: { "Idempotency-Key": key("plan-change-apply") }, body: JSON.stringify(input), parse: parsePlanChangeApply });
  },
  reject(runId: string, requestId: string, input: { readonly expectedRequestVersion: number; readonly reason: string }): Promise<PlanChangeDetailResponse> {
    return apiRequest(`${root(runId)}/${id(requestId, "Plan change ID")}/reject`, { method: "POST", headers: { "Idempotency-Key": key("plan-change-reject") }, body: JSON.stringify(input), parse: parsePlanChangeDetail });
  },
};

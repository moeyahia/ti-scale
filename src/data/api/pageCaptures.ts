import { apiRequest } from "./client";
import { parsePageCaptureDetail, parsePageCaptureList } from "../../domain/schemas/pageCaptures";
import type { PageCaptureDetail, PageCaptureFilter, PageCaptureList } from "../../domain/types/pageCaptures";

function identifier(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 240 || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError(`${label} is invalid`);
  return encodeURIComponent(normalized);
}

function root(missionId: string): string { return `/api/v2/missions/${identifier(missionId, "Mission ID")}/intelligence/page-captures`; }

function query(filter: PageCaptureFilter): string {
  const parameters = new URLSearchParams();
  if (filter.runId) parameters.set("runId", filter.runId.trim());
  if (filter.assetNodeId) parameters.set("assetNodeId", filter.assetNodeId.trim());
  if (filter.serviceNodeId) parameters.set("serviceNodeId", filter.serviceNodeId.trim());
  if (filter.redactionState) parameters.set("redactionState", filter.redactionState);
  if (filter.cursor) parameters.set("cursor", filter.cursor.trim());
  if (filter.limit !== undefined) {
    if (!Number.isSafeInteger(filter.limit) || filter.limit < 1 || filter.limit > 100) throw new RangeError("Page-capture limit must be from 1 through 100");
    parameters.set("limit", String(filter.limit));
  }
  const result = parameters.toString();
  return result ? `?${result}` : "";
}

export const pageCapturesApi = {
  list(missionId: string, filter: PageCaptureFilter = {}, signal?: AbortSignal): Promise<PageCaptureList> {
    return apiRequest(`${root(missionId)}${query(filter)}`, { method: "GET", signal, parse: (payload) => {
      const result = parsePageCaptureList(payload);
      if (result.items.some((item) => item.missionId !== missionId.trim() || (filter.runId && item.runId !== filter.runId.trim()))) throw new Error("Page-capture response escaped the requested mission/run scope");
      return result;
    } });
  },
  detail(missionId: string, captureId: string, signal?: AbortSignal): Promise<PageCaptureDetail> {
    return apiRequest(`${root(missionId)}/${identifier(captureId, "Page capture ID")}`, { method: "GET", signal, parse: (payload) => {
      const result = parsePageCaptureDetail(payload);
      if (result.record.missionId !== missionId.trim() || result.record.id !== captureId.trim()) throw new Error("Page-capture detail escaped the requested canonical identity");
      return result;
    } });
  },
};

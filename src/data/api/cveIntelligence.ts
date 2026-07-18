import {
  parseCveApplicabilityDetail,
  parseCveApplicabilityList,
} from "../../domain/schemas/cveIntelligence";
import type {
  CveApplicabilityDetail,
  CveApplicabilityFilter,
  CveApplicabilityList,
} from "../../domain/types/cveIntelligence";
import { apiRequest } from "./client";

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
};

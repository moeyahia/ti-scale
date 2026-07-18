import { apiRequest } from "./client";
import { parseScriptArtifactDetail, parseScriptArtifactList } from "../../domain/schemas/scriptArtifacts";
import type { ScriptArtifactDetailResponse, ScriptArtifactFilter, ScriptArtifactList } from "../../domain/types/scriptArtifacts";

function identifier(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 240 || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError(`${label} is invalid`);
  return encodeURIComponent(normalized);
}

function root(missionId: string): string { return `/api/v2/missions/${identifier(missionId, "Mission ID")}/script-artifacts`; }

function query(filter: ScriptArtifactFilter): string {
  const parameters = new URLSearchParams();
  for (const [key, value] of Object.entries(filter)) {
    if (value === undefined) continue;
    if (key === "limit") {
      if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 100) throw new RangeError("Script-artifact limit must be from 1 through 100");
      parameters.set(key, String(value));
    } else parameters.set(key, String(value).trim());
  }
  const result = parameters.toString();
  return result ? `?${result}` : "";
}

export const scriptArtifactsApi = {
  list(missionId: string, filter: ScriptArtifactFilter = {}, signal?: AbortSignal): Promise<ScriptArtifactList> {
    return apiRequest(`${root(missionId)}${query(filter)}`, { method: "GET", signal, parse: (payload) => {
      const result = parseScriptArtifactList(payload);
      if (result.items.some((item) => item.missionId !== missionId.trim() || (filter.runId && item.runId !== filter.runId.trim()))) throw new Error("Script-artifact response escaped the requested mission/run scope");
      return result;
    } });
  },
  detail(missionId: string, scriptArtifactId: string, signal?: AbortSignal): Promise<ScriptArtifactDetailResponse> {
    return apiRequest(`${root(missionId)}/${identifier(scriptArtifactId, "Script artifact ID")}`, { method: "GET", signal, parse: (payload) => {
      const result = parseScriptArtifactDetail(payload);
      if (result.record.missionId !== missionId.trim() || result.record.id !== scriptArtifactId.trim()) throw new Error("Script-artifact detail escaped the requested canonical identity");
      return result;
    } });
  },
};

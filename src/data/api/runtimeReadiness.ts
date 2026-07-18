import { parseRuntimeReadiness } from "../../domain/schemas/runtimeReadiness";
import type { RuntimeReadinessSnapshot } from "../../domain/types/runtimeReadiness";
import { apiRequest } from "./client";

export function fetchRuntimeReadiness(signal?: AbortSignal): Promise<RuntimeReadinessSnapshot> {
  return apiRequest("/api/v2/system/readiness", {
    method: "GET",
    signal,
    parse: parseRuntimeReadiness,
  });
}

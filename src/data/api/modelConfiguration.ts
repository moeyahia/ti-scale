import {
  parseModelCatalog,
  parseModelConfigurations,
  parseModelPreferenceMutation,
  parseModelPreferences,
  parseModelResolution,
} from "../../domain/schemas/modelConfiguration";
import type {
  ModelCatalog,
  ModelConfigurationPage,
  ModelPreferenceMutation,
  ModelPreferencePage,
  ModelPreferenceScope,
  ModelResolutionResult,
  UpdateModelPreferenceInput,
} from "../../domain/types/modelConfiguration";
import { apiRequest } from "./client";

const ROOTS = {
  catalog: "/api/v2/model-catalog",
  configurations: "/api/v2/model-configurations",
  preferences: "/api/v2/model-preferences",
  resolution: "/api/v2/model-resolution",
} as const;

// A cached live-catalog response cannot outlive the server's default provider
// attestation window. Refresh failures preserve the original query timestamp,
// so consumers can retire the exact snapshot at this boundary.
export const MODEL_CATALOG_SNAPSHOT_MAXIMUM_AGE_MS = 15 * 60 * 1_000;

function queryPath(path: string, values: Record<string, string | null | undefined>): string {
  const query = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") query.set(key, value);
  });
  const serialized = query.toString();
  return serialized ? `${path}?${serialized}` : path;
}

function idempotencyKey(): string {
  return globalThis.crypto?.randomUUID?.()
    ?? `model-preference-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function fetchModelCatalog(signal: AbortSignal): Promise<ModelCatalog> {
  return apiRequest(ROOTS.catalog, { method: "GET", signal, parse: parseModelCatalog });
}

export function fetchModelConfigurations(
  ids: readonly string[],
  signal: AbortSignal,
): Promise<ModelConfigurationPage> {
  return apiRequest(queryPath(ROOTS.configurations, {
    ids: ids.length ? ids.join(",") : undefined,
  }), { method: "GET", signal, parse: parseModelConfigurations });
}

export function fetchModelPreferences(
  query: {
    readonly scopeType?: ModelPreferenceScope;
    readonly scopeId?: string;
    readonly agentId?: string | null;
  },
  signal: AbortSignal,
): Promise<ModelPreferencePage> {
  return apiRequest(queryPath(ROOTS.preferences, query), {
    method: "GET",
    signal,
    parse: parseModelPreferences,
  });
}

export function fetchModelResolution(
  query: {
    readonly agentId: string;
    readonly missionId?: string;
    readonly runId?: string;
    readonly stepId?: string;
  },
  signal: AbortSignal,
): Promise<ModelResolutionResult> {
  return apiRequest(queryPath(ROOTS.resolution, query), {
    method: "GET",
    signal,
    parse: parseModelResolution,
  });
}

export function updateModelPreference(
  scopeType: ModelPreferenceScope,
  scopeId: string,
  input: UpdateModelPreferenceInput,
  signal?: AbortSignal,
  key = idempotencyKey(),
): Promise<ModelPreferenceMutation> {
  return apiRequest(
    `${ROOTS.preferences}/${encodeURIComponent(scopeType)}/${encodeURIComponent(scopeId)}`,
    {
      method: "PUT",
      signal,
      headers: { "Idempotency-Key": key },
      body: JSON.stringify(input),
      parse: parseModelPreferenceMutation,
    },
  );
}

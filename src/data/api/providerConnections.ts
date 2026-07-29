import {
  parseOpenRouterAttestationRefresh,
  parseOpenRouterConnection,
} from "../../domain/schemas/providerConnections";
import type {
  OpenRouterAttestationRefresh,
  OpenRouterConnection,
  UpdateOpenRouterConnectionInput,
} from "../../domain/types/providerConnections";
import { apiRequest } from "./client";

const OPENROUTER = "/api/v2/provider-connections/openrouter";

function idempotencyKey(prefix: string): string {
  return globalThis.crypto?.randomUUID?.()
    ?? `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function fetchOpenRouterConnection(
  signal: AbortSignal,
): Promise<OpenRouterConnection> {
  return apiRequest(OPENROUTER, {
    method: "GET",
    signal,
    parse: parseOpenRouterConnection,
  });
}

export function updateOpenRouterConnection(
  input: UpdateOpenRouterConnectionInput,
  signal?: AbortSignal,
  key = idempotencyKey("openrouter-connection"),
): Promise<OpenRouterConnection> {
  return apiRequest(OPENROUTER, {
    method: "PUT",
    signal,
    headers: { "Idempotency-Key": key },
    body: JSON.stringify(input),
    parse: parseOpenRouterConnection,
  });
}

export function refreshOpenRouterAttestation(
  expectedVersion: number,
  signal?: AbortSignal,
  key = idempotencyKey("openrouter-attestation"),
): Promise<OpenRouterAttestationRefresh> {
  return apiRequest(`${OPENROUTER}/attestation`, {
    method: "PUT",
    signal,
    headers: { "Idempotency-Key": key },
    body: JSON.stringify({ expectedVersion }),
    parse: parseOpenRouterAttestationRefresh,
  });
}

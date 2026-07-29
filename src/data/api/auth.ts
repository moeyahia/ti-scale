import { apiRequest } from "./client";
import type { LocalSessionState } from "../../domain/types/auth";

const LOCAL_ACTOR_ID = /^[A-Za-z0-9._:@/-]{1,128}$/u;
const SESSION_FIELDS = new Set([
  "schemaVersion",
  "configured",
  "authenticated",
  "actorId",
  "expiresAt",
]);

export function parseLocalSession(value: unknown): LocalSessionState {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Session response must be an object");
  }
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== "2.4"
    || typeof record.authenticated !== "boolean"
    || (
      record.configured !== undefined
      && typeof record.configured !== "boolean"
    )
    || Object.keys(record).some((key) => !SESSION_FIELDS.has(key))
  ) {
    throw new Error("Session response is incompatible with Ti-Scale 2.4");
  }
  const configured = record.configured !== false;
  if (record.authenticated) {
    const expiresAt = typeof record.expiresAt === "string"
      ? Date.parse(record.expiresAt)
      : Number.NaN;
    if (
      !configured
      || typeof record.actorId !== "string"
      || !LOCAL_ACTOR_ID.test(record.actorId)
      || typeof record.expiresAt !== "string"
      || !Number.isFinite(expiresAt)
      || new Date(expiresAt).toISOString() !== record.expiresAt
    ) {
      throw new Error("Authenticated session identity or expiry is invalid");
    }
    return {
      schemaVersion: "2.4",
      configured,
      authenticated: true,
      actorId: record.actorId,
      expiresAt: record.expiresAt,
    };
  }
  if (record.actorId !== undefined || record.expiresAt !== undefined) {
    throw new Error("Unauthenticated session must not include an actor or expiry");
  }
  return {
    schemaVersion: "2.4",
    configured,
    authenticated: false,
  };
}

export function fetchLocalSession(signal?: AbortSignal): Promise<LocalSessionState> {
  return apiRequest("/api/v2/auth/session", {
    method: "GET",
    signal,
    parse: parseLocalSession,
  });
}

export function createLocalSession(operatorToken: string): Promise<LocalSessionState> {
  return apiRequest("/api/v2/auth/session", {
    method: "POST",
    body: JSON.stringify({ operatorToken }),
    parse: parseLocalSession,
  });
}

export function deleteLocalSession(): Promise<LocalSessionState> {
  return apiRequest("/api/v2/auth/session", {
    method: "DELETE",
    parse: parseLocalSession,
  });
}

import { apiRequest } from "./client";
import type { LocalSessionState } from "../../domain/types/auth";

function parseSession(value: unknown): LocalSessionState {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Session response must be an object");
  }
  const record = value as Record<string, unknown>;
  if (record.schemaVersion !== "2.4" || typeof record.authenticated !== "boolean") {
    throw new Error("Session response is incompatible with Ti-Scale 2.4");
  }
  return {
    schemaVersion: "2.4",
    configured: record.configured !== false,
    authenticated: record.authenticated,
    ...(typeof record.actorId === "string" ? { actorId: record.actorId } : {}),
    ...(typeof record.expiresAt === "string" ? { expiresAt: record.expiresAt } : {}),
  };
}

export function fetchLocalSession(): Promise<LocalSessionState> {
  return apiRequest("/api/v2/auth/session", { method: "GET", parse: parseSession });
}

export function createLocalSession(operatorToken: string): Promise<LocalSessionState> {
  return apiRequest("/api/v2/auth/session", {
    method: "POST",
    body: JSON.stringify({ operatorToken }),
    parse: parseSession,
  });
}

export function deleteLocalSession(): Promise<LocalSessionState> {
  return apiRequest("/api/v2/auth/session", { method: "DELETE", parse: parseSession });
}

import { createHash } from "node:crypto";
import type { AutonomousMissionRequest } from "./types";

function normalized(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalized);
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item !== undefined) result[key] = normalized(item);
    }
    return result;
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalized(value));
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function hashCanonical(value: unknown): string {
  return sha256(canonicalJson(value));
}

/** Hash every field that defines Autonomous authority or promised outcome. */
export function autonomousContractHash(request: AutonomousMissionRequest): string {
  return hashCanonical({
    title: request.title,
    objective: request.objective,
    successCriteria: request.successCriteria,
    authorization: request.authorization,
    contract: request.contract,
  });
}

import { createHash } from "node:crypto";
import type { ActionIntent } from "./types";

const DEFAULT_VOLATILE_KEYS = new Set([
  "timestamp",
  "createdat",
  "updatedat",
  "requestid",
  "correlationid",
  "traceid",
  "spanid",
  "nonce",
  "elapsedms",
]);

export interface FingerprintOptions {
  volatileKeys?: ReadonlySet<string>;
}

function normalizedKey(key: string): string {
  return key.replace(/[-_\s]/g, "").toLowerCase();
}

export function normalizeFingerprintValue(
  value: unknown,
  options: FingerprintOptions = {},
): unknown {
  const volatileKeys = new Set(
    [...(options.volatileKeys ?? DEFAULT_VOLATILE_KEYS)].map((key) => normalizedKey(key)),
  );
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : String(value);
  if (typeof value === "string") return value.replace(/\r\n/g, "\n").trim();
  if (Array.isArray(value)) return value.map((item) => normalizeFingerprintValue(item, options));
  if (typeof value === "object") {
    const normalized: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    )) {
      if (child === undefined || volatileKeys.has(normalizedKey(key))) continue;
      normalized[key] = normalizeFingerprintValue(child, options);
    }
    return normalized;
  }
  return String(value);
}

export function stableSerialize(value: unknown, options: FingerprintOptions = {}): string {
  return JSON.stringify(normalizeFingerprintValue(value, options));
}

export interface ActionFingerprint {
  hash: string;
  canonical: string;
}

export function fingerprintAction(
  action: Readonly<ActionIntent>,
  options: FingerprintOptions = {},
): ActionFingerprint {
  const canonical = stableSerialize({
    missionId: action.missionId,
    actionType: action.actionType.trim().toLowerCase(),
    arguments: normalizeFingerprintValue(action.arguments, options),
    target: action.target.trim(),
    runId: action.runId,
    stepId: action.stepId,
    planVersion: action.planVersion,
    precedingState: normalizeFingerprintValue(action.precedingState ?? {}, options),
  }, options);
  return { hash: createHash("sha256").update(canonical).digest("hex"), canonical };
}

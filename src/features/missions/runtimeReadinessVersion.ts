import type { RuntimeReadinessSnapshot } from "../../domain/types/runtimeReadiness";

export interface RuntimeReadinessVersion {
  readonly signature: string;
  readonly checkedAt: string;
}

const VOLATILE_READINESS_KEYS = new Set([
  "attestedat",
  "checkedat",
  "completedat",
  "completionreceiptid",
  "createdat",
  "expiresat",
  "finishedat",
  "lastcheckedat",
  "lastheartbeatat",
  "nonce",
  "observedat",
  "probeid",
  "receiptid",
  "startedat",
  "updatedat",
]);

function normalizedKey(key: string): string {
  return key.replace(/[-_]/gu, "").toLocaleLowerCase("en-US");
}

function isVolatileReadinessKey(key: string): boolean {
  const normalized = normalizedKey(key);
  return VOLATILE_READINESS_KEYS.has(normalized)
    || normalized.endsWith("nonce")
    || normalized.endsWith("completionreceiptid");
}

/**
 * Canonicalize semantic capability state while removing rotating observation
 * metadata. Status, reasons, counts, booleans, ready IDs, and configuration
 * hashes remain part of the signature; timestamps and nonce-like receipt IDs
 * do not force a new mission review by themselves.
 */
function semanticReadinessValue(value: unknown, parentKey = ""): unknown {
  if (Array.isArray(value)) {
    const normalized = value.map((item) => semanticReadinessValue(item));
    return /ids$/iu.test(parentKey) && normalized.every((item) => typeof item === "string")
      ? [...normalized].sort()
      : normalized;
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key, item]) => item !== undefined && !isVolatileReadinessKey(key))
        .sort(([left], [right]) => left.localeCompare(right, "en-US"))
        .map(([key, item]) => [key, semanticReadinessValue(item, key)]),
    );
  }
  return value;
}

/**
 * Produces a deterministic capability-state signature for an Autonomous
 * preflight. `checkedAt` is deliberately excluded: a new observation of the
 * same capability state must not retire a valid review, while any material
 * execution/dependency change must.
 */
export function runtimeReadinessVersion(
  snapshot: RuntimeReadinessSnapshot,
): RuntimeReadinessVersion {
  return {
    signature: JSON.stringify(semanticReadinessValue({
      status: snapshot.status,
      execution: snapshot.execution,
      dependencies: snapshot.dependencies,
    })),
    checkedAt: snapshot.checkedAt,
  };
}

export function runtimeReadinessChanged(
  stamped: RuntimeReadinessVersion | undefined,
  current: RuntimeReadinessSnapshot | undefined,
): boolean {
  if (!stamped || !current) return false;
  return stamped.signature !== runtimeReadinessVersion(current).signature;
}

import { createHash } from "node:crypto";

export type JsonScalar = string | number | boolean | null;
export type JsonValue = JsonScalar | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };

function normalize(value: unknown, seen: Set<object>): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Run-intelligence JSON cannot contain non-finite numbers");
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value !== "object") {
    throw new TypeError(`Run-intelligence JSON cannot contain ${typeof value}`);
  }
  if (seen.has(value)) throw new TypeError("Run-intelligence JSON cannot contain cycles");
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.map((item) => normalize(item, seen));
    const prototype = Object.getPrototypeOf(value) as object | null;
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Run-intelligence JSON objects must be plain records");
    }
    const result: Record<string, JsonValue> = {};
    for (const key of Object.keys(value).sort()) {
      if (key === "__proto__" || key === "prototype" || key === "constructor") {
        throw new TypeError(`Unsafe run-intelligence JSON key: ${key}`);
      }
      const item = (value as Record<string, unknown>)[key];
      if (item === undefined) throw new TypeError(`Run-intelligence JSON key ${key} is undefined`);
      result[key] = normalize(item, seen);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value, new Set<object>()));
}

export function canonicalValue(value: unknown): JsonValue {
  return normalize(value, new Set<object>());
}

function isJsonArray(value: JsonValue): value is readonly JsonValue[] {
  return Array.isArray(value);
}

export function canonicalObject(value: unknown): JsonObject {
  const normalized = canonicalValue(value);
  if (normalized === null || isJsonArray(normalized) || typeof normalized !== "object") {
    throw new TypeError("Expected a JSON object");
  }
  return normalized;
}

export function parseJsonObject(value: string, label: string): JsonObject {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new RunIntelligenceDataError(`${label} is not valid JSON`);
  }
  try {
    return canonicalObject(parsed);
  } catch {
    throw new RunIntelligenceDataError(`${label} must be a safe JSON object`);
  }
}

export function parseJsonArray(value: string, label: string): readonly JsonValue[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new RunIntelligenceDataError(`${label} is not valid JSON`);
  }
  const normalized = canonicalValue(parsed);
  if (!Array.isArray(normalized)) throw new RunIntelligenceDataError(`${label} must be a JSON array`);
  return normalized;
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function hashCanonical(value: unknown): string {
  return sha256(canonicalJson(value));
}

export function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

export class RunIntelligenceDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RunIntelligenceDataError";
  }
}

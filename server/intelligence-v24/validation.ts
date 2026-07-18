import { createHash } from "node:crypto";
import { redactSecrets } from "../contracts/redaction";
import { invalid } from "./errors";
import type { JsonValue } from "./types";

const IDENTIFIER = /^[A-Za-z0-9._:@/-]{1,240}$/u;
const TOKEN_KEY = /(?:^|[_-])(?:authorization|api[_-]?key|cookie|credential|password|passwd|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token)(?:$|[_-])/iu;
const SHA256 = /^[a-f0-9]{64}$/u;

function isSensitiveJsonKey(key: string): boolean {
  // Producers use snake_case, kebab-case, and camelCase. Normalize camel-case
  // boundaries before applying the key policy so apiToken, clientSecret, and
  // refreshToken cannot bypass the canonical ingestion redactor.
  const delimited = key
    .replace(/([a-z0-9])([A-Z])/gu, "$1_$2")
    .replace(/[^A-Za-z0-9]+/gu, "_");
  return TOKEN_KEY.test(delimited);
}

export function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value.trim())) {
    throw invalid("invalid_identifier", `${label} must be a stable identifier`);
  }
  return value.trim();
}

export function optionalIdentifier(value: unknown, label: string): string | undefined {
  return value === undefined ? undefined : identifier(value, label);
}

export function text(value: unknown, label: string, maximum = 4_000): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw invalid("invalid_text", `${label} must contain 1-${maximum} characters`);
  }
  const normalized = value.trim();
  if (redactSecrets(normalized) !== normalized) {
    throw invalid(
      "sensitive_material_rejected",
      `${label} contains credential-like material and was not retained`,
      "Replace sensitive values with opaque references.",
    );
  }
  return normalized;
}

export function redactedText(value: unknown, label: string, maximum = 20_000): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw invalid("invalid_text", `${label} must contain 1-${maximum} characters`);
  }
  return redactSecrets(value.trim());
}

export function isoTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string") throw invalid("invalid_timestamp", `${label} must be an ISO-8601 timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw invalid("invalid_timestamp", `${label} must be an ISO-8601 timestamp`);
  return new Date(milliseconds).toISOString();
}

export function confidence(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw invalid("invalid_confidence", "confidence must be a finite number between zero and one");
  }
  return value;
}

interface JsonBudget {
  nodes: number;
  redacted: boolean;
}

function normalizeJson(value: unknown, budget: JsonBudget, depth: number): JsonValue {
  budget.nodes += 1;
  if (budget.nodes > 10_000 || depth > 16) throw invalid("json_budget_exceeded", "JSON payload exceeds the operational truth bound");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw invalid("invalid_json_number", "JSON numbers must be finite");
    return value;
  }
  if (typeof value === "string") {
    if (value.length > 100_000) throw invalid("json_string_too_large", "JSON string exceeds the operational truth bound");
    const redacted = redactSecrets(value);
    if (redacted !== value) budget.redacted = true;
    return redacted;
  }
  if (Array.isArray(value)) {
    if (value.length > 2_000) throw invalid("json_array_too_large", "JSON array exceeds the operational truth bound");
    return value.map((item) => normalizeJson(item, budget, depth + 1));
  }
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > 2_000) throw invalid("json_object_too_large", "JSON object exceeds the operational truth bound");
    const result: Record<string, JsonValue> = {};
    for (const [key, child] of entries) {
      if (isSensitiveJsonKey(key)) {
        result[key] = "[REDACTED]";
        budget.redacted = true;
      } else if (child !== undefined) {
        result[key] = normalizeJson(child, budget, depth + 1);
      }
    }
    return result;
  }
  throw invalid("invalid_json_value", "Payload must contain JSON-compatible values only");
}

export function sanitizedJson(value: unknown): { readonly value: JsonValue; readonly redacted: boolean } {
  const budget: JsonBudget = { nodes: 0, redacted: false };
  const normalized = normalizeJson(value, budget, 0);
  return { value: normalized, redacted: budget.redacted };
}

export function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as { readonly [key: string]: JsonValue };
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key]!)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function sha256Hash(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw invalid("invalid_content_hash", `${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

export function uniqueStrings(values: readonly string[], label: string, maximum = 100): readonly string[] {
  if (values.length > maximum) throw invalid("too_many_values", `${label} exceeds ${maximum} values`);
  const normalized = values.map((value) => text(value, label, 200));
  if (new Set(normalized).size !== normalized.length) throw invalid("duplicate_values", `${label} contains duplicates`);
  return normalized;
}

export function parseJson(serialized: string): JsonValue {
  return JSON.parse(serialized) as JsonValue;
}

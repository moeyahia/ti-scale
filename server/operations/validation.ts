import { createHash } from "node:crypto";
import { OperationsApiError } from "./errors";

const IDENTIFIER = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const SENSITIVE_KEY = /(?:^|[_-])(?:api[_-]?key|authorization|auth[_-]?token|bearer|client[_-]?secret|cookie|credential|password|passwd|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token)(?:$|[_-])/iu;
const SENSITIVE_SETTING_KEY = /(?:secret|token|password|passwd|credential|private[_-]?key|api[_-]?key|auth(?:entication|orization)?)/iu;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*/giu;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu;
const COMMON_TOKEN = /\b(?:sk|gh[pousr]|xox[baprs]|AIza)[-_][A-Za-z0-9_-]{12,}\b/gu;

function isSensitiveJsonKey(key: string): boolean {
  // Database producers and imported manifests are not consistent about key
  // casing. Normalize camelCase before applying the canonical key policy so
  // apiToken, clientSecret, and refreshToken cannot bypass a projection
  // boundary that already protects api_token/client_secret forms.
  const normalized = key
    .replace(/([a-z0-9])([A-Z])/gu, "$1_$2")
    .replace(/[^A-Za-z0-9]+/gu, "_");
  return SENSITIVE_KEY.test(normalized);
}

export interface CursorValue {
  readonly sort: string;
  readonly id: string;
}

export function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value.trim())) {
    throw new OperationsApiError(400, "invalid_identifier", `${label} is invalid`, {
      humanMessage: `${label} must be a valid identifier.`,
      category: "invalid_input",
    });
  }
  return value.trim();
}

export function optionalIdentifier(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return identifier(value, label);
}

export function boundedLimit(value: unknown, fallback = 50): number {
  if (value === undefined) return fallback;
  const parsed = typeof value === "string" && /^\d+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || Number(parsed) < 1 || Number(parsed) > 100) {
    throw new OperationsApiError(400, "invalid_pagination", "Invalid page size", {
      humanMessage: "Page size must be an integer between 1 and 100.",
      category: "invalid_input",
    });
  }
  return Number(parsed);
}

export function optionalEnum<T extends string>(
  value: unknown,
  allowed: ReadonlySet<T>,
  label: string,
): T | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !allowed.has(value as T)) {
    throw new OperationsApiError(400, "invalid_filter", `${label} is invalid`, {
      humanMessage: `${label} is not one of the supported values.`,
      category: "invalid_input",
      details: { field: label, allowed: [...allowed] },
    });
  }
  return value as T;
}

export function optionalTimestamp(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new OperationsApiError(400, "invalid_time_filter", `${label} is invalid`, {
      humanMessage: `${label} must be an ISO-8601 timestamp.`,
      category: "invalid_input",
    });
  }
  return new Date(value).toISOString();
}

export function optionalSearch(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !value.trim() || value.length > 500) {
    throw new OperationsApiError(400, "invalid_search", "Search text is invalid", {
      humanMessage: "Search text must contain between 1 and 500 characters.",
      category: "invalid_input",
    });
  }
  return value.trim();
}

export function ftsQuery(value: string): string {
  const tokens = value.normalize("NFKC").split(/\s+/u).filter(Boolean).slice(0, 20);
  return tokens.map((token) => `"${token.replaceAll('"', '""')}"*`).join(" AND ");
}

export function decodeCursor(value: unknown): CursorValue | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || value.length > 1_000) throw invalidCursor();
  try {
    const decoded = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown;
    if (!decoded || typeof decoded !== "object") throw new Error("invalid");
    const candidate = decoded as Record<string, unknown>;
    if (
      typeof candidate.sort !== "string" || !candidate.sort || candidate.sort.length > 300 ||
      typeof candidate.id !== "string" || !IDENTIFIER.test(candidate.id)
    ) throw new Error("invalid");
    return { sort: candidate.sort, id: candidate.id };
  } catch {
    throw invalidCursor();
  }
}

function invalidCursor(): OperationsApiError {
  return new OperationsApiError(400, "invalid_cursor", "The page cursor is invalid", {
    humanMessage: "The page cursor is invalid or no longer usable.",
    category: "invalid_input",
    remediation: "Restart pagination without a cursor.",
  });
}

export function encodeCursor(sort: string, id: string): string {
  return Buffer.from(JSON.stringify({ sort, id }), "utf8").toString("base64url");
}

export function requiredIdempotencyKey(value: string | undefined): string {
  const normalized = value?.trim();
  if (!normalized || !IDEMPOTENCY_KEY.test(normalized)) {
    throw new OperationsApiError(400, "idempotency_key_required", "A valid Idempotency-Key header is required", {
      humanMessage: "This mutation requires a stable Idempotency-Key header containing 8-200 safe characters.",
      category: "invalid_input",
    });
  }
  return normalized;
}

export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new OperationsApiError(400, "invalid_request", "Request body must be an object", {
      humanMessage: "The request body must be a JSON object.",
      category: "invalid_input",
    });
  }
  return value as Record<string, unknown>;
}

export function requiredText(value: unknown, label: string, maximum = 4_000): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new OperationsApiError(400, "invalid_request", `${label} is invalid`, {
      humanMessage: `${label} must contain between 1 and ${maximum} characters.`,
      category: "invalid_input",
    });
  }
  return value.trim();
}

/**
 * Validate operator-authored text before it crosses an immutable audit/event
 * boundary. Rejection is intentional: redacting only the audit copy would make
 * the persisted reason differ from the operator's deliberate authorization.
 */
export function requiredSafeReason(value: unknown, label: string, maximum = 2_000): string {
  const reason = requiredText(value, label, maximum);
  if (redactString(reason) !== reason) {
    throw new OperationsApiError(422, "sensitive_material_not_retained", "Sensitive material was rejected", {
      humanMessage: `${label} appears to contain authentication or credential material and was not retained.`,
      category: "policy_denied",
      details: { field: label, rejection: "credential_like_material" },
      remediation: "Remove the sensitive value and reference the protected credential by an opaque identifier instead.",
    });
  }
  return reason;
}

export function requiredPositiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw new OperationsApiError(400, "invalid_request", `${label} is invalid`, {
      humanMessage: `${label} must be a positive integer.`,
      category: "invalid_input",
    });
  }
  return Number(value);
}

export function parseJson(value: string | null | undefined): unknown {
  if (!value) return null;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}

function redactString(value: string): string {
  return value
    .replace(PRIVATE_KEY, "[REDACTED PRIVATE KEY]")
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(JWT, "[REDACTED TOKEN]")
    .replace(COMMON_TOKEN, "[REDACTED TOKEN]")
    .replace(
      /\b(api[_-]?(?:key|token)|authorization|auth[_-]?token|client[_-]?secret|credential|password|passwd|private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token)\s*[:=]\s*["']?[^\s,;"'&]{4,}/giu,
      "$1=[REDACTED]",
    )
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/giu, "$1[REDACTED]@");
}

/** Defense-in-depth for projections even when a producer failed to redact. */
export function sanitizeJson(value: unknown, depth = 0): unknown {
  if (depth > 12) return "[REDACTED: depth limit]";
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.slice(0, 1_000).map((item) => sanitizeJson(item, depth + 1));
  if (value && typeof value === "object") {
    const safe: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>).slice(0, 1_000)) {
      safe[key] = isSensitiveJsonKey(key) ? "[REDACTED]" : sanitizeJson(child, depth + 1);
    }
    return safe;
  }
  return value;
}

function configuredRedactionPaths(metadata: unknown): readonly string[] {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return [];
  const record = metadata as Record<string, unknown>;
  const configured = Array.isArray(record.paths)
    ? record.paths
    : Array.isArray(record.fields)
      ? record.fields
      : [];
  return configured
    .filter((entry): entry is string => typeof entry === "string")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .slice(0, 200);
}

function redactConfiguredPath(value: unknown, segments: readonly string[]): unknown {
  if (segments.length === 0 || !value || typeof value !== "object" || Array.isArray(value)) return value;
  const [head, ...tail] = segments;
  if (!head || !Object.prototype.hasOwnProperty.call(value, head)) return value;
  const record = value as Record<string, unknown>;
  return {
    ...record,
    [head]: tail.length === 0 ? "[REDACTED]" : redactConfiguredPath(record[head], tail),
  };
}

/** Apply producer-declared redaction paths in addition to projection-level secret defense. */
export function sanitizeJsonWithRedaction(value: unknown, metadata: unknown): unknown {
  let result = sanitizeJson(value);
  for (const path of configuredRedactionPaths(metadata)) {
    result = redactConfiguredPath(result, path.split(".").filter(Boolean));
  }
  return result;
}

export function isSensitiveSettingKey(key: string): boolean {
  return SENSITIVE_SETTING_KEY.test(key);
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().filter((key) => record[key] !== undefined).map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

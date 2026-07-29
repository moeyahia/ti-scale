import { createHash } from "node:crypto";
import { redactSecrets } from "../contracts/redaction";

const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/giu;
const LONG_SECRET = /\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/gu;
const ASSIGNMENT_SECRET = /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|password|passwd|passphrase|secret)\b\s*[:=]\s*[^\s,;]+/giu;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/giu;
const COOKIE = /\b(?:set-cookie|cookie)\s*:\s*[^\r\n]+/giu;

export function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** Redaction used before any legacy text enters canonical tables or reports. */
export function redactLegacyText(value: unknown, maximumLength = 32_768): string {
  const source = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return redactSecrets(source)
    .replace(PRIVATE_KEY, "[REDACTED-PRIVATE-KEY]")
    .replace(LONG_SECRET, "[REDACTED-KEY]")
    .replace(ASSIGNMENT_SECRET, (match) => `${match.split(/[:=]/u, 1)[0]}: [REDACTED]`)
    .replace(BEARER, "Bearer [REDACTED]")
    .replace(COOKIE, "Cookie: [REDACTED]")
    .replace(/\b(?:HTB|FLAG|flag|root|user)\{[^}\n]{3,}\}/gu, "[REDACTED-FLAG]")
    .replace(/\b[a-fA-F0-9]{31,}:[a-fA-F0-9]{31,}\b/gu, "[REDACTED-HASH]")
    .replace(/\b[a-fA-F0-9]{32,}\b/gu, "[REDACTED-HASH]")
    .slice(0, maximumLength);
}

/** Reject content when redaction would still leave non-reusable secret material. */
export function containsHardSecret(value: string): boolean {
  return /-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(value)
    || /\b[a-fA-F0-9]{31,}:[a-fA-F0-9]{31,}\b/u.test(value)
    || /\b(?:HTB|FLAG|flag|root|user)\{[^}\n]{3,}\}/u.test(value);
}

export function safeJson(value: unknown): string {
  return JSON.stringify(redactRecursively(value));
}

export function redactRecursively(value: unknown, depth = 0): unknown {
  if (depth > 12) return "[TRUNCATED-DEPTH]";
  if (typeof value === "string") return redactLegacyText(value);
  if (Array.isArray(value)) return value.slice(0, 1_000).map((item) => redactRecursively(item, depth + 1));
  if (!value || typeof value !== "object") return value;
  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (/^(?:authorization|cookie|password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key)$/iu.test(key)) {
      output[key] = "[REDACTED]";
    } else {
      output[key] = redactRecursively(item, depth + 1);
    }
  }
  return output;
}

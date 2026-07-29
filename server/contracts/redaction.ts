/**
 * Conservative, deterministic redaction shared by V2 persistence boundaries.
 *
 * This module intentionally has no dependency on the legacy runtime. It is
 * used before reusable memory, migration data, branch requests, or audit text
 * reaches the dedicated Ti-Scale database.
 */
export function redactSecrets(text: string): string {
  if (!text) return text;
  return text
    .replace(/\b(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/gu, "[REDACTED-KEY]")
    .replace(/\b(Authorization|Bearer|api[_-]?key|token|password|passwd|secret)\b\s*[:=]\s*\S+/giu, "$1: [REDACTED]")
    .replace(/\b((?:password|passwd|passphrase)\s+(?:(?:is|was)\s+|equals?\s+))(?!(?:<PASSWORD>|<SECRET>|<TOKEN>|<CREDENTIAL>))(?:"[^"]+"|'[^']+'|`[^`]+`|\S+)/giu, "$1[REDACTED]")
    .replace(/\b((?:token|secret|api[_ -]?key)\s+(?:(?:is|was)\s+|equals?\s+))(?!(?:<PASSWORD>|<SECRET>|<TOKEN>|<CREDENTIAL>))(?:"[^"]+"|'[^']+'|`[^`]+`|\S+)/giu, "$1[REDACTED]")
    .replace(/\b(credentials?\s*(?:(?:is|was)\s+|[:=]\s*)?)(?!<CREDENTIAL>|<USER_REF>)([A-Za-z][A-Za-z0-9._$-]{1,31}):(?!<PASSWORD>|<SECRET>)[^\s,;]+/giu, "$1[REDACTED-CREDENTIAL]")
    .replace(/\b(login\s+(?:with|as)\s+[^\s,;]+\s+(?:and|using|with\s+(?:password|secret))\s+)(?!<PASSWORD>|<SECRET>|<TOKEN>)[^\s,;]+/giu, "$1[REDACTED]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu, "[REDACTED-PRIVATE-KEY]");
}

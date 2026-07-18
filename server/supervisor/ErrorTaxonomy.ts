export const FAILURE_CATEGORIES = [
  "transient_network",
  "rate_limit",
  "provider_unavailable",
  "mcp_unavailable",
  "timeout",
  "worker_lost",
  "process_crash",
  "invalid_input",
  "deterministic_tool_error",
  "authorization_denied",
  "policy_denied",
  "authentication_missing",
  "dependency_missing",
  "scope_conflict",
  "evidence_insufficient",
  "operator_rejection",
  "unknown",
] as const;
export type FailureCategory = (typeof FAILURE_CATEGORIES)[number];

export const TRANSIENT_FAILURE_CATEGORIES: ReadonlySet<FailureCategory> = new Set([
  "transient_network",
  "rate_limit",
  "provider_unavailable",
  "mcp_unavailable",
  "timeout",
  "worker_lost",
  "process_crash",
]);

export interface FailureSignal {
  code?: string;
  message?: string;
  httpStatus?: number;
  source?: "provider" | "mcp" | "worker" | "tool" | "policy" | "operator" | "unknown";
}

export function isRetryableCategory(category: FailureCategory): boolean {
  return TRANSIENT_FAILURE_CATEGORIES.has(category);
}

export function classifyFailure(signal: Readonly<FailureSignal>): FailureCategory {
  const text = `${signal.code ?? ""} ${signal.message ?? ""}`.toLowerCase();
  if (signal.httpStatus === 429 || /rate.?limit|too many requests/.test(text)) return "rate_limit";
  if (signal.httpStatus === 401 || /missing (api )?(key|credential)|not authenticated|token revoked/.test(text)) {
    return "authentication_missing";
  }
  if (signal.httpStatus === 403 || /authorization denied|not authorized/.test(text)) {
    return "authorization_denied";
  }
  if (/policy (denied|violation)|outside policy/.test(text)) return "policy_denied";
  if (/outside scope|scope conflict|target.*not allowed/.test(text)) return "scope_conflict";
  if (/operator rejected|user rejected/.test(text) || signal.source === "operator") return "operator_rejection";
  if (/invalid (argument|input|parameter)|validation failed/.test(text)) return "invalid_input";
  if (/dependency.*(missing|not found)|command not found|enoent|missing grok|not a trusted executable|must be root-owned|must have mode 0?600|parent.*root-controlled/.test(text)) {
    return "dependency_missing";
  }
  if (/oauth auth|cached_token|run [`'"]?grok login|authentication method/.test(text)) return "authentication_missing";
  if (/evidence.*insufficient|insufficient evidence/.test(text)) return "evidence_insufficient";
  if (/heartbeat.*(lost|expired)|worker lost/.test(text)) return "worker_lost";
  if (/process (crash|exited)|segmentation fault/.test(text)) return "process_crash";
  if (/timed? ?out|timeout|etimedout/.test(text)) return "timeout";
  if (signal.source === "mcp" && /unavailable|disconnect|connection/.test(text)) return "mcp_unavailable";
  if (signal.source === "provider" && (signal.httpStatus === 502 || signal.httpStatus === 503 || signal.httpStatus === 504)) {
    return "provider_unavailable";
  }
  if (signal.source === "provider" && /unavailable|overloaded|exited before completing|planning boundary attestation failed/.test(text)) {
    return "provider_unavailable";
  }
  if (/econnreset|econnrefused|network|socket hang up|dns/.test(text)) return "transient_network";
  if (signal.source === "tool" && /exit(ed)? (code )?[1-9]|deterministic/.test(text)) {
    return "deterministic_tool_error";
  }
  return "unknown";
}

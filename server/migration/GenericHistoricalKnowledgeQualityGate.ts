import type { LegacySource, LegacySourceType } from "./types";

export type GenericHistoricalRecordClass =
  | "structured_operational"
  | "tool_result"
  | "narrative"
  | "prompt_or_stream";

export type GenericHistoricalKnowledgeRejectionReason =
  | "provider_prompt_or_stream"
  | "non_evidentiary_narrative"
  | "insufficient_technical_context";

const UNBOUND_OPERATOR_PROVIDER_HISTORY = /^\/root\/\.(?:claude|codex|grok)(?:\/|$)/u;
const PROVIDER_HISTORY_TYPES: ReadonlySet<LegacySourceType> = new Set([
  "provider_log",
  "provider_session_json",
  "provider_session_jsonl",
  "raw_llm_jsonl",
]);

/**
 * Operator-wide provider archives may contain product development, unrelated
 * conversations, and engagement work in the same tree. Without a reviewed
 * source-to-engagement binding they are retained as private custody only and
 * cannot seed reusable attack knowledge.
 */
export function hasGenericHistoricalReusableSourceBoundary(
  source: Pick<LegacySource, "absolutePath" | "type">,
): boolean {
  return !(UNBOUND_OPERATOR_PROVIDER_HISTORY.test(source.absolutePath) &&
    PROVIDER_HISTORY_TYPES.has(source.type));
}

export interface GenericHistoricalKnowledgeSignals {
  readonly productCount: number;
  readonly cveCount: number;
  readonly attackCount: number;
  readonly toolCount: number;
  readonly hasOperationalObservation: boolean;
  readonly hasCveApplicability: boolean;
  readonly hasFailedOutcome: boolean;
  readonly hasWorkedOutcome: boolean;
  readonly hasRecoveryAction: boolean;
  readonly hasRecoverySequence: boolean;
}

export interface GenericHistoricalKnowledgeQualityDecision {
  readonly accepted: boolean;
  readonly reason?: GenericHistoricalKnowledgeRejectionReason;
  readonly retainOutcome: boolean;
  readonly retainRecovery: boolean;
}

const PROVIDER_NARRATIVE_SOURCE_TYPES: ReadonlySet<LegacySourceType> = new Set([
  "raw_llm_jsonl",
  "provider_session_json",
  "provider_session_jsonl",
  "provider_log",
  "conversation_markdown",
  "dashboard_log",
]);

const STRUCTURED_OPERATIONAL_SOURCE_TYPES: ReadonlySet<LegacySourceType> = new Set([
  "run_json",
  "event_jsonl",
  "memory_json",
  "training_json",
  "kanban_sqlite",
  "conversation_state_sqlite",
]);

const PROMPT_ROLES = new Set(["developer", "system"]);
const TOOL_ROLES = new Set(["function", "tool"]);
const TOOL_RESULT_TYPES = new Set([
  "custom_tool_call_output",
  "function_call_output",
  "mcp_tool_call_end",
  "tool_output",
  "tool_result",
]);
const STREAM_OR_CONTROL_TYPES = new Set([
  "compacted",
  "compaction",
  "content_block_delta",
  "context_compacted",
  "encrypted_content",
  "message_delta",
  "message_start",
  "reasoning",
  "session_meta",
  "stream_event",
  "text_delta",
  "thinking",
  "thread_settings_applied",
  "token_count",
  "turn_context",
]);
const EXPLICIT_OPERATIONAL_KEYS = new Set([
  "artifact",
  "artifacts",
  "command_output",
  "evidence",
  "finding",
  "findings",
  "observation",
  "observations",
  "output",
  "result",
  "results",
  "stderr",
  "stdout",
  "tool_result",
]);

interface EnvelopeSignals {
  readonly roles: ReadonlySet<string>;
  readonly types: ReadonlySet<string>;
  readonly keys: ReadonlySet<string>;
  readonly topLevelType?: string;
}

function normalizedString(value: unknown): string | undefined {
  return typeof value === "string" && value.length <= 128
    ? value.trim().toLowerCase().replaceAll("-", "_")
    : undefined;
}

function envelopeSignals(value: unknown, maxDepth = 8): EnvelopeSignals {
  const roles = new Set<string>();
  const types = new Set<string>();
  const keys = new Set<string>();
  const topLevelType = value && typeof value === "object" && !Array.isArray(value)
    ? normalizedString((value as Record<string, unknown>).type)
    : undefined;
  const visit = (candidate: unknown, depth: number): void => {
    if (depth > maxDepth || !candidate || typeof candidate !== "object") return;
    if (Array.isArray(candidate)) {
      candidate.slice(0, 256).forEach((item) => visit(item, depth + 1));
      return;
    }
    Object.entries(candidate as Record<string, unknown>)
      .slice(0, 256)
      .forEach(([key, item]) => {
        const normalizedKey = key.trim().toLowerCase().replaceAll("-", "_");
        keys.add(normalizedKey);
        const normalizedValue = normalizedString(item);
        if (["author_role", "role", "speaker"].includes(normalizedKey) && normalizedValue) {
          roles.add(normalizedValue);
        }
        if (["event_type", "kind", "type"].includes(normalizedKey) && normalizedValue) {
          types.add(normalizedValue);
        }
        visit(item, depth + 1);
      });
  };
  visit(value, 0);
  return { roles, types, keys, ...(topLevelType ? { topLevelType } : {}) };
}

/**
 * Classify the record envelope before any free text is considered. Public-model
 * prompts, incremental token streams, and model prose are not evidence. Only
 * explicit completed tool results may cross a provider-history boundary.
 */
export function classifyGenericHistoricalRecord(
  value: unknown,
  sourceType: LegacySourceType,
): GenericHistoricalRecordClass {
  const signals = envelopeSignals(value);
  if ([...signals.roles].some((role) => PROMPT_ROLES.has(role))) return "prompt_or_stream";
  if (signals.topLevelType && STREAM_OR_CONTROL_TYPES.has(signals.topLevelType)) return "prompt_or_stream";
  if ([...signals.types].some((type) => TOOL_RESULT_TYPES.has(type)) ||
      [...signals.roles].some((role) => TOOL_ROLES.has(role))) {
    return "tool_result";
  }
  if (PROVIDER_NARRATIVE_SOURCE_TYPES.has(sourceType)) return "narrative";
  if (STRUCTURED_OPERATIONAL_SOURCE_TYPES.has(sourceType)) return "structured_operational";
  if ([...signals.keys].some((key) => EXPLICIT_OPERATIONAL_KEYS.has(key))) return "structured_operational";
  return "narrative";
}

/**
 * Admit only reusable technical relationships. A bare status word, tool name,
 * attack label, reset verb, or model assertion can never create Brain memory.
 */
export function evaluateGenericHistoricalKnowledgeQuality(
  recordClass: GenericHistoricalRecordClass,
  signals: GenericHistoricalKnowledgeSignals,
): GenericHistoricalKnowledgeQualityDecision {
  if (recordClass === "prompt_or_stream") {
    return {
      accepted: false,
      reason: "provider_prompt_or_stream",
      retainOutcome: false,
      retainRecovery: false,
    };
  }
  if (recordClass === "narrative") {
    return {
      accepted: false,
      reason: "non_evidentiary_narrative",
      retainOutcome: false,
      retainRecovery: false,
    };
  }

  const concreteStackObservation = signals.productCount > 0 && (
    signals.hasOperationalObservation || signals.attackCount > 0 || signals.cveCount > 0
  );
  const attributableAttackResult = signals.attackCount > 0 && (
    signals.productCount > 0 || signals.cveCount > 0 || signals.toolCount > 0
  ) && (
    signals.hasOperationalObservation || signals.hasFailedOutcome || signals.hasWorkedOutcome
  );
  const attributableCveResult = signals.cveCount > 0 && (
    signals.productCount > 0 || signals.attackCount > 0 || signals.hasCveApplicability
  ) && (
    signals.hasOperationalObservation || signals.hasCveApplicability ||
    signals.hasFailedOutcome || signals.hasWorkedOutcome
  );
  const accepted = concreteStackObservation || attributableAttackResult || attributableCveResult;
  if (!accepted) {
    return {
      accepted: false,
      reason: "insufficient_technical_context",
      retainOutcome: false,
      retainRecovery: false,
    };
  }

  const retainOutcome = signals.attackCount > 0 &&
    (signals.hasFailedOutcome || signals.hasWorkedOutcome) &&
    (signals.productCount > 0 || signals.cveCount > 0 || signals.toolCount > 0);
  const retainRecovery = retainOutcome && signals.hasFailedOutcome &&
    signals.hasRecoveryAction && signals.hasRecoverySequence;
  return { accepted: true, retainOutcome, retainRecovery };
}

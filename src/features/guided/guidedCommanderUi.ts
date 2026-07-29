import type { GuidedCommanderMessage } from "../../domain/types/guidedCommander";

export const GUIDED_TEXT_RESULT_LIMIT = 128 * 1024;

export type GuidedTextMediaType =
  | "text/plain"
  | "application/json"
  | "text/csv"
  | "application/xml"
  | "text/xml";

const MEDIA_TYPES = new Set<GuidedTextMediaType>([
  "text/plain",
  "application/json",
  "text/csv",
  "application/xml",
  "text/xml",
]);

const EXTENSION_MEDIA_TYPES: Readonly<Record<string, GuidedTextMediaType>> = {
  txt: "text/plain",
  log: "text/plain",
  json: "application/json",
  csv: "text/csv",
  xml: "application/xml",
};

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

export interface GuidedResponsePresentation {
  readonly kind?: string;
  readonly summary?: string;
  readonly confidence?: number;
  readonly observations: readonly string[];
  readonly recommendedNextStep?: string;
  readonly evidenceId?: string;
  readonly executionPerformed?: boolean;
  readonly nextConsequentialActionRequiresDecision?: boolean;
}

export function responsePresentation(message: GuidedCommanderMessage): GuidedResponsePresentation {
  const content = message.structuredContent;
  return {
    kind: optionalText(content.kind),
    summary: optionalText(content.summary),
    confidence: typeof content.confidence === "number" && Number.isFinite(content.confidence)
      ? Math.max(0, Math.min(1, content.confidence))
      : undefined,
    observations: Array.isArray(content.observations)
      ? content.observations.filter((item): item is string => typeof item === "string" && Boolean(item.trim()))
      : [],
    recommendedNextStep: optionalText(content.recommendedNextStep),
    evidenceId: optionalText(content.evidenceId),
    executionPerformed: typeof content.executionPerformed === "boolean" ? content.executionPerformed : undefined,
    nextConsequentialActionRequiresDecision: typeof content.nextConsequentialActionRequiresDecision === "boolean"
      ? content.nextConsequentialActionRequiresDecision
      : undefined,
  };
}

/**
 * Reconstructs source-message → candidate links from the durable paired
 * memory-request exchange. This survives reload without inventing client-only
 * memory state.
 */
export function memoryCandidatesBySource(
  messages: readonly GuidedCommanderMessage[],
): ReadonlyMap<string, { candidateId: string; status: string }> {
  const result = new Map<string, { candidateId: string; status: string }>();
  let sourceMessageId: string | undefined;
  for (const message of messages) {
    const content = message.structuredContent;
    if (message.role === "operator" && content.kind === "guided_memory_request") {
      sourceMessageId = optionalText(content.sourceMessageId);
      continue;
    }
    if (message.role !== "assistant") continue;
    if (content.kind === "guided_memory_candidate" && sourceMessageId) {
      const candidateId = optionalText(content.candidateId);
      if (candidateId) result.set(sourceMessageId, { candidateId, status: optionalText(content.status) ?? "pending" });
      sourceMessageId = undefined;
    } else if (content.kind === "guided_memory_suppression") {
      const candidateId = optionalText(content.candidateId);
      if (!candidateId) continue;
      for (const [messageId, candidate] of result) {
        if (candidate.candidateId === candidateId) result.set(messageId, { ...candidate, status: "suppressed" });
      }
    }
  }
  return result;
}

export function mediaTypeForTextFile(file: Pick<File, "name" | "type">): GuidedTextMediaType | null {
  const reported = file.type.toLowerCase().split(";", 1)[0] as GuidedTextMediaType;
  if (MEDIA_TYPES.has(reported)) return reported;
  const extension = file.name.toLowerCase().split(".").pop() ?? "";
  return EXTENSION_MEDIA_TYPES[extension] ?? null;
}

export function utf8ByteSize(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

export function suggestedMemoryTitle(message: GuidedCommanderMessage): string {
  const summary = optionalText(message.structuredContent.summary);
  const source = summary ?? message.body.trim().split(/\n/u, 1)[0] ?? "Guided mission note";
  return source.slice(0, 120) || "Guided mission note";
}

export function suggestedMemorySummary(message: GuidedCommanderMessage): string {
  const summary = optionalText(message.structuredContent.summary) ?? message.body.trim();
  return summary.slice(0, 800);
}

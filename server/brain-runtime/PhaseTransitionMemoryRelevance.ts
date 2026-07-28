import type { MemoryNodeType } from "../memory";
import type { BrainContextResult } from "./types";

export type PhaseTransitionSemanticSignalKind =
  | "technology"
  | "version"
  | "action"
  | "phase"
  | "observation"
  | "evidence";

export interface PhaseTransitionSemanticSignal {
  readonly kind: PhaseTransitionSemanticSignalKind;
  readonly key: string;
  readonly value: string;
}

export interface PhaseTransitionMemorySelection {
  readonly nodeIds: readonly string[];
  readonly activeVaultCandidateCount: number;
  readonly semanticallyRelevantCount: number;
}

const TECHNOLOGY_NODE_TYPES = new Set<MemoryNodeType>([
  "technology_product",
  "exact_version_fingerprint",
  "version_range_fingerprint",
  "operating_system",
  "kernel",
  "framework",
  "runtime",
  "database",
  "firewall",
  "waf",
  "proxy",
  "security_control",
  "topology_pattern",
  "topology_role",
  "cve",
  "advisory",
  "cwe",
  "misconfiguration",
  "attribute",
  "fingerprint_pattern",
]);

const GENERIC_TOKENS = new Set([
  "action",
  "attack",
  "canonical",
  "confirmed",
  "current",
  "evidence",
  "historical",
  "knowledge",
  "memory",
  "observation",
  "phase",
  "product",
  "result",
  "service",
  "signal",
  "target",
  "technology",
  "verified",
  "version",
]);

const MAXIMUM_USED_PHASE_NODES = 8;

function normalized(value: string): string {
  return value.normalize("NFKC").toLocaleLowerCase("en-US")
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim()
    .replace(/\s+/gu, " ");
}

function boundedNodeText(result: BrainContextResult["items"][number]): string {
  return normalized([
    result.node.nodeType,
    result.node.title,
    result.node.summary,
    result.node.body.slice(0, 64 * 1_024),
  ].join(" "));
}

function distinctiveTokens(value: string): readonly string[] {
  return [...new Set(normalized(value).split(" ").filter((token) =>
    token.length >= 3 && !GENERIC_TOKENS.has(token)))];
}

function phraseMatch(text: string, value: string): boolean {
  const phrase = normalized(value);
  if (
    phrase.length < 3
    || !/[\p{L}]/u.test(phrase)
    || GENERIC_TOKENS.has(phrase)
  ) return false;
  return (` ${text} `).includes(` ${phrase} `);
}

function versionPhraseMatch(text: string, value: string): boolean {
  const phrase = normalized(value);
  if (phrase.length < 2 || !/\p{N}/u.test(phrase)) return false;
  return (` ${text} `).includes(` ${phrase} `);
}

/**
 * Selects only active-Vault-backed memory with a deterministic relationship
 * to the current action, phase, or canonical parsed technology signals.
 *
 * Retrieval still happens and remains persisted for lifecycle coverage. This
 * selector controls only which retrieved items may be marked as influential;
 * it cannot add nodes, alter execution, or broaden the signed memory policy.
 */
export function selectRelevantPhaseTransitionMemory(input: Readonly<{
  context: BrainContextResult;
  semanticSignals: readonly PhaseTransitionSemanticSignal[];
  allowedNodeTypes: ReadonlySet<string>;
  activeVaultBackedNodeIds: ReadonlySet<string>;
}>): PhaseTransitionMemorySelection {
  const technologySignals = input.semanticSignals.filter(({ kind }) =>
    kind === "technology");
  const versionSignals = input.semanticSignals.filter(({ kind }) =>
    kind === "version");
  const actionPhaseTokens = new Set(input.semanticSignals
    .filter(({ kind }) => kind === "action" || kind === "phase")
    .flatMap(({ value }) => distinctiveTokens(value)));
  const observationEvidenceTokens = new Set(input.semanticSignals
    .filter(({ kind }) => kind === "observation" || kind === "evidence")
    .flatMap(({ value }) => distinctiveTokens(value)));
  const retrievalOrder = new Map(
    input.context.items.map((item, index) => [item.node.id, index]),
  );
  const activeCandidates = input.context.items.filter(({ node }) =>
    input.allowedNodeTypes.has(node.nodeType)
    && input.activeVaultBackedNodeIds.has(node.id));
  const ranked = activeCandidates.flatMap((item) => {
    const text = boundedNodeText(item);
    const nodeTokens = new Set(distinctiveTokens(text));
    const exactTechnologyMatches = technologySignals.filter(({ value }) =>
      phraseMatch(text, value)).length;
    const exactVersionMatches = versionSignals.filter(({ value }) =>
      versionPhraseMatch(text, value)).length;
    const actionPhaseMatches = [...actionPhaseTokens].filter((token) =>
      nodeTokens.has(token)).length;
    const observationEvidenceMatches = [...observationEvidenceTokens].filter((token) =>
      nodeTokens.has(token)).length;
    const technologyNode = TECHNOLOGY_NODE_TYPES.has(item.node.nodeType);
    const semanticallyRelevant = technologyNode
      ? exactTechnologyMatches > 0 || exactVersionMatches > 0
      : exactTechnologyMatches > 0
        || actionPhaseMatches >= 2
        || (actionPhaseMatches >= 1 && observationEvidenceMatches >= 1);
    if (!semanticallyRelevant) return [];
    return [{
      nodeId: item.node.id,
      score:
        exactTechnologyMatches * 100
        + exactVersionMatches * 20
        + actionPhaseMatches * 5
        + observationEvidenceMatches * 3,
      retrievalRank: retrievalOrder.get(item.node.id) ?? Number.MAX_SAFE_INTEGER,
    }];
  }).sort((left, right) =>
    right.score - left.score
    || left.retrievalRank - right.retrievalRank
    || left.nodeId.localeCompare(right.nodeId));
  return Object.freeze({
    nodeIds: Object.freeze(ranked.slice(0, MAXIMUM_USED_PHASE_NODES)
      .map(({ nodeId }) => nodeId)),
    activeVaultCandidateCount: activeCandidates.length,
    semanticallyRelevantCount: ranked.length,
  });
}

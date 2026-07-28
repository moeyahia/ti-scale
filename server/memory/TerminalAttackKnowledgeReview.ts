import type { MemoryNode, MemoryNodeType, MemoryRetentionPolicy } from "./types";

export const TERMINAL_ATTACK_KNOWLEDGE_REVIEW_SCHEMA =
  "ti-scale.terminal-attack-knowledge-candidate.v1" as const;

export const TERMINAL_ATTACK_KNOWLEDGE_REVIEW_NODE_TYPES = [
  "outcome",
  "attack_lesson",
] as const satisfies readonly MemoryNodeType[];

const REVIEW_NODE_TYPE_SET: ReadonlySet<MemoryNodeType> =
  new Set(TERMINAL_ATTACK_KNOWLEDGE_REVIEW_NODE_TYPES);

export function terminalAttackKnowledgeReviewRetentionPolicy(): MemoryRetentionPolicy {
  return Object.freeze({
    allowAutonomous: false,
    allowGuided: false,
    terminalAttackKnowledgeReview: Object.freeze({
      schemaVersion: TERMINAL_ATTACK_KNOWLEDGE_REVIEW_SCHEMA,
      status: "pending_operator_review",
    }),
  });
}

/**
 * Candidate Vault projection is deliberately narrower than general candidate
 * memory. It accepts only the two generalized terminal records created by the
 * deterministic run evaluator and never makes them trusted retrieval context.
 */
export function isTerminalAttackKnowledgeReviewCandidate(
  node: Pick<MemoryNode,
    "nodeType" | "scope" | "lifecycleStatus" | "confirmationState" |
    "authorType" | "authorId" | "retentionPolicy">,
): boolean {
  const marker = node.retentionPolicy.terminalAttackKnowledgeReview;
  return REVIEW_NODE_TYPE_SET.has(node.nodeType)
    && node.scope.kind === "global"
    && !node.scope.engagementId
    && !node.scope.missionId
    && node.lifecycleStatus === "candidate"
    && node.confirmationState === "pending"
    && node.authorType === "agent"
    && node.authorId === "run-evaluator"
    && Boolean(
      marker
      && typeof marker === "object"
      && !Array.isArray(marker)
      && (marker as Record<string, unknown>).schemaVersion
        === TERMINAL_ATTACK_KNOWLEDGE_REVIEW_SCHEMA
      && (marker as Record<string, unknown>).status === "pending_operator_review",
    );
}

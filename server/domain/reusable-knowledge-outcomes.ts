/**
 * Evidence-backed terminal outcomes for reusable attack knowledge.
 *
 * This is deliberately a many-to-many classification. A technique can
 * succeed against one exact stack and fail against another, so callers must
 * not collapse these values into one mutable status field. An empty tag set
 * means supporting/unclassified knowledge.
 */
export const REUSABLE_KNOWLEDGE_OUTCOME_TAGS = ["success", "failed"] as const;

export type ReusableKnowledgeOutcomeTag =
  (typeof REUSABLE_KNOWLEDGE_OUTCOME_TAGS)[number];

export type ReusableKnowledgeOutcomeClassification =
  | ReusableKnowledgeOutcomeTag
  | "unclassified";

export interface ReusableKnowledgeOutcomeSummary {
  readonly memoryNodeId: string;
  readonly outcomeTags: readonly ReusableKnowledgeOutcomeTag[];
  readonly classification: "classified" | "unclassified";
  readonly successAttemptCount: number;
  readonly failedAttemptCount: number;
  readonly evidenceCount: number;
}

const OUTCOME_TAG_SET: ReadonlySet<string> = new Set(
  REUSABLE_KNOWLEDGE_OUTCOME_TAGS,
);

export function isReusableKnowledgeOutcomeTag(
  value: unknown,
): value is ReusableKnowledgeOutcomeTag {
  return typeof value === "string" && OUTCOME_TAG_SET.has(value);
}

export function canonicalReusableKnowledgeOutcomeTags(
  values: readonly ReusableKnowledgeOutcomeTag[],
): readonly ReusableKnowledgeOutcomeTag[] {
  const selected = new Set(values);
  return REUSABLE_KNOWLEDGE_OUTCOME_TAGS.filter((tag) => selected.has(tag));
}

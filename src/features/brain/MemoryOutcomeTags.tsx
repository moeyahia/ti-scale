import {
  MEMORY_OUTCOME_TAGS,
  type MemoryOutcomeTag,
} from "../../domain/types/brain";

export const MEMORY_OUTCOME_FILTERS = [
  ...MEMORY_OUTCOME_TAGS,
  "unclassified",
] as const;

export type MemoryOutcomeFilter = (typeof MEMORY_OUTCOME_FILTERS)[number] | "";

/**
 * Outcome tags are independent, evidence-backed facts. Their canonical order
 * is stable for URLs, tables, screen readers, and Vault projections.
 */
export function canonicalMemoryOutcomeTags(
  tags: readonly MemoryOutcomeTag[] | undefined,
): MemoryOutcomeTag[] {
  if (!tags?.length) return [];
  const selected = new Set(tags);
  return MEMORY_OUTCOME_TAGS.filter((tag) => selected.has(tag));
}

export function memoryMatchesOutcomeFilter(
  tags: readonly MemoryOutcomeTag[] | undefined,
  filter: MemoryOutcomeFilter,
): boolean {
  const normalized = canonicalMemoryOutcomeTags(tags);
  if (!filter) return true;
  if (filter === "unclassified") return normalized.length === 0;
  return normalized.includes(filter);
}

export function memoryOutcomeLabel(tag: MemoryOutcomeTag): string {
  return tag === "success" ? "Success" : "Failed";
}

export function MemoryOutcomeTags({
  tags,
  showUnclassified = true,
  counts,
}: {
  readonly tags?: readonly MemoryOutcomeTag[];
  readonly showUnclassified?: boolean;
  readonly counts?: Readonly<Partial<Record<MemoryOutcomeTag | "unclassified", number>>>;
}) {
  const normalized = canonicalMemoryOutcomeTags(tags);
  if (normalized.length === 0) {
    if (!showUnclassified) return null;
    return (
      <span
        className="brain-outcome-tags"
        role="group"
        aria-label={`Verified outcome evidence: Supporting or unclassified${counts?.unclassified === undefined ? "" : `, ${counts.unclassified}`}`}
      >
        <span className="brain-outcome-badge brain-outcome-badge--unclassified" aria-hidden="true">
          Supporting / unclassified{counts?.unclassified === undefined ? "" : ` ${counts.unclassified}`}
        </span>
      </span>
    );
  }
  const accessible = normalized.map((tag) => (
    `${memoryOutcomeLabel(tag)}${counts?.[tag] === undefined ? "" : `, ${counts[tag]}`}`
  )).join(" and ");
  return (
    <span
      className="brain-outcome-tags"
      role="group"
      aria-label={`Verified outcome evidence: ${accessible}`}
    >
      {normalized.map((tag) => (
        <span key={tag} className={`brain-outcome-badge brain-outcome-badge--${tag}`} aria-hidden="true">
          {memoryOutcomeLabel(tag)}{counts?.[tag] === undefined ? "" : ` ${counts[tag]}`}
        </span>
      ))}
    </span>
  );
}

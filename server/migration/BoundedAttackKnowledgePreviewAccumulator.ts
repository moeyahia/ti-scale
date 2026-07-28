import type { AttackKnowledgeExtractionBatchReport } from "./types";

const MAX_DISTRIBUTION_BUCKETS = 256;
const MAX_ISSUE_BUCKETS = 512;
const MAX_SOURCE_EVIDENCE_IDS = 10_000;

type GenericBatchMetrics = Readonly<{
  sourcesProcessed?: number;
  sourcesCompleted?: number;
  recordsProcessed?: number;
  recordsQuarantined?: number;
  sourceEvidenceCandidateIds?: readonly string[];
}>;

type CompactPreviewBatch = AttackKnowledgeExtractionBatchReport & Required<Pick<GenericBatchMetrics,
  "sourcesProcessed" | "sourcesCompleted" | "recordsProcessed" | "recordsQuarantined"
>>;

const SUM_FIELDS = [
  "filesParsed",
  "filesSkipped",
  "filesQuarantined",
  "bytesParsed",
  "semanticFactsParsed",
  "ambiguousFragments",
  "compilerBundlesStaged",
  "candidatesCreated",
  "candidatesReused",
  "sourceEvidenceCandidatesCreated",
  "sourceEvidenceCandidatesReused",
  "sourceBundleLinks",
] as const satisfies readonly (keyof AttackKnowledgeExtractionBatchReport)[];

function incrementBounded(
  target: Map<string, number>,
  key: string,
  value: number,
  maximum: number,
  label: string,
): void {
  if (!target.has(key) && target.size >= maximum) {
    throw new RangeError(`${label} exceeded its bounded preview bucket limit`);
  }
  target.set(key, (target.get(key) ?? 0) + value);
}

function sortedRecord(source: ReadonlyMap<string, number>): Readonly<Record<string, number>> {
  return Object.fromEntries([...source.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

/**
 * Constant-space reducer for multi-page semantic previews.
 *
 * The production dry run can traverse millions of historical records. Keeping
 * every page's per-record issue array made memory proportional to the corpus.
 * This accumulator retains only numeric totals, bounded taxonomy buckets,
 * bounded issue buckets, the latest opaque cursor, and unique opaque source
 * candidate IDs. Raw text, paths, records, and individual issue objects are
 * never retained between pages.
 */
export class BoundedAttackKnowledgePreviewAccumulator {
  readonly #totals = Object.fromEntries(SUM_FIELDS.map((field) => [field, 0])) as Record<(typeof SUM_FIELDS)[number], number>;
  readonly #issues = new Map<string, number>();
  readonly #nodeTypes = new Map<string, number>();
  readonly #edgeTypes = new Map<string, number>();
  readonly #sourceEvidenceCandidateIds = new Set<string>();
  #manifestFingerprint?: string;
  #filesDiscovered?: number;
  #latest?: AttackKnowledgeExtractionBatchReport;
  #representedBatchCount = 0;
  #generic = false;
  #sourcesProcessed = 0;
  #sourcesCompleted = 0;
  #recordsProcessed = 0;
  #recordsQuarantined = 0;

  add(batch: AttackKnowledgeExtractionBatchReport): void {
    if (this.#manifestFingerprint && this.#manifestFingerprint !== batch.manifestFingerprint) {
      throw new Error("A bounded preview accumulator cannot combine different extractor scopes");
    }
    this.#manifestFingerprint = batch.manifestFingerprint;
    this.#filesDiscovered ??= batch.filesDiscovered;
    this.#latest = batch;
    this.#representedBatchCount += batch.representedBatchCount ?? 1;
    for (const field of SUM_FIELDS) this.#totals[field] += Number(batch[field]);
    for (const issue of batch.issues) {
      incrementBounded(
        this.#issues,
        `${issue.disposition}\0${issue.reason}`,
        issue.count ?? 1,
        MAX_ISSUE_BUCKETS,
        "Historical extraction issue taxonomy",
      );
    }
    for (const [type, count] of Object.entries(batch.nodeTypeCounts ?? {})) {
      incrementBounded(this.#nodeTypes, type, Number(count), MAX_DISTRIBUTION_BUCKETS, "Historical node taxonomy");
    }
    for (const [type, count] of Object.entries(batch.edgeTypeCounts ?? {})) {
      incrementBounded(this.#edgeTypes, type, Number(count), MAX_DISTRIBUTION_BUCKETS, "Historical edge taxonomy");
    }
    const generic = batch as AttackKnowledgeExtractionBatchReport & GenericBatchMetrics;
    if (generic.sourcesProcessed !== undefined || generic.recordsProcessed !== undefined) this.#generic = true;
    this.#sourcesProcessed += generic.sourcesProcessed ?? 0;
    this.#sourcesCompleted += generic.sourcesCompleted ?? 0;
    this.#recordsProcessed += generic.recordsProcessed ?? 0;
    this.#recordsQuarantined += generic.recordsQuarantined ?? 0;
    for (const id of generic.sourceEvidenceCandidateIds ?? []) {
      if (!this.#sourceEvidenceCandidateIds.has(id) && this.#sourceEvidenceCandidateIds.size >= MAX_SOURCE_EVIDENCE_IDS) {
        throw new RangeError("Historical source-evidence preview exceeded its bounded opaque-ID limit");
      }
      this.#sourceEvidenceCandidateIds.add(id);
    }
  }

  finish(): AttackKnowledgeExtractionBatchReport | CompactPreviewBatch {
    const latest = this.#latest;
    if (!latest || !this.#manifestFingerprint || this.#filesDiscovered === undefined) {
      throw new Error("Cannot finish an empty historical preview accumulator");
    }
    const compact: AttackKnowledgeExtractionBatchReport & GenericBatchMetrics = {
      status: latest.status,
      dryRun: true,
      manifestFingerprint: this.#manifestFingerprint,
      filesDiscovered: this.#filesDiscovered,
      ...this.#totals,
      representedBatchCount: this.#representedBatchCount,
      nodeTypeCounts: sortedRecord(this.#nodeTypes),
      edgeTypeCounts: sortedRecord(this.#edgeTypes),
      ...(latest.nextResumeAfterSourceKey
        ? { nextResumeAfterSourceKey: latest.nextResumeAfterSourceKey }
        : {}),
      ...(latest.nextResumeAfterRecordKey
        ? { nextResumeAfterRecordKey: latest.nextResumeAfterRecordKey }
        : {}),
      issues: [...this.#issues.entries()].map(([key, count]) => {
        const [disposition, reason] = key.split("\0") as ["skipped" | "quarantined" | "ambiguous", string];
        return { disposition, reason, count };
      }).sort((left, right) => left.disposition.localeCompare(right.disposition) || left.reason.localeCompare(right.reason)),
      sourceEvidenceCandidateIds: [...this.#sourceEvidenceCandidateIds].sort(),
      ...(this.#generic ? {
        sourcesProcessed: this.#sourcesProcessed,
        sourcesCompleted: this.#sourcesCompleted,
        recordsProcessed: this.#recordsProcessed,
        recordsQuarantined: this.#recordsQuarantined,
      } : {}),
    };
    return compact;
  }
}

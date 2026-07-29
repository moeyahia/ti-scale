import { describe, expect, test } from "bun:test";
import { BoundedAttackKnowledgePreviewAccumulator } from "../BoundedAttackKnowledgePreviewAccumulator";
import type { AttackKnowledgeExtractionBatchReport } from "../types";

const FINGERPRINT = "a".repeat(64);

function batch(index: number, status: "completed" | "partial" = "partial"): AttackKnowledgeExtractionBatchReport & {
  readonly sourcesProcessed: number;
  readonly sourcesCompleted: number;
  readonly recordsProcessed: number;
  readonly recordsQuarantined: number;
} {
  return {
    status,
    dryRun: true,
    manifestFingerprint: FINGERPRINT,
    filesDiscovered: 156,
    filesParsed: 1,
    filesSkipped: 0,
    filesQuarantined: 0,
    bytesParsed: 1_024,
    semanticFactsParsed: 2,
    ambiguousFragments: 0,
    compilerBundlesStaged: 1,
    candidatesCreated: 0,
    candidatesReused: 0,
    sourceEvidenceCandidatesCreated: index === 0 ? 1 : 0,
    sourceEvidenceCandidatesReused: index === 0 ? 0 : 1,
    sourceBundleLinks: 0,
    nodeTypeCounts: { attack_vector: 1, technology_product: 1 },
    edgeTypeCounts: { tested_against: 1 },
    ...(status === "partial" ? {
      nextResumeAfterSourceKey: String(index).padStart(64, "0"),
      nextResumeAfterRecordKey: String(index + 1).padStart(64, "0"),
    } : {}),
    issues: [
      { disposition: "skipped", reason: "no_reusable_semantics" },
      { disposition: "quarantined", reason: "secret_bearing_record", count: 2 },
    ],
    sourceEvidenceCandidateIds: ["candidate_source_opaque"],
    sourcesProcessed: 1,
    sourcesCompleted: status === "completed" ? 1 : 0,
    recordsProcessed: 5_000,
    recordsQuarantined: 2,
  };
}

describe("bounded attack-knowledge preview aggregation", () => {
  test("collapses a high-page preview into bounded issue and taxonomy buckets without losing totals", () => {
    const accumulator = new BoundedAttackKnowledgePreviewAccumulator();
    const pageCount = 50_000;
    for (let index = 0; index < pageCount; index += 1) {
      accumulator.add(batch(index, index === pageCount - 1 ? "completed" : "partial"));
    }

    const result = accumulator.finish() as AttackKnowledgeExtractionBatchReport & {
      readonly sourcesProcessed: number;
      readonly sourcesCompleted: number;
      readonly recordsProcessed: number;
      readonly recordsQuarantined: number;
    };
    expect(result).toMatchObject({
      status: "completed",
      representedBatchCount: pageCount,
      filesDiscovered: 156,
      filesParsed: pageCount,
      bytesParsed: pageCount * 1_024,
      semanticFactsParsed: pageCount * 2,
      compilerBundlesStaged: pageCount,
      sourcesProcessed: pageCount,
      sourcesCompleted: 1,
      recordsProcessed: pageCount * 5_000,
      recordsQuarantined: pageCount * 2,
      nodeTypeCounts: { attack_vector: pageCount, technology_product: pageCount },
      edgeTypeCounts: { tested_against: pageCount },
      sourceEvidenceCandidateIds: ["candidate_source_opaque"],
    });
    expect(result.issues).toEqual([
      { disposition: "quarantined", reason: "secret_bearing_record", count: pageCount * 2 },
      { disposition: "skipped", reason: "no_reusable_semantics", count: pageCount },
    ]);
    expect(result.nextResumeAfterSourceKey).toBeUndefined();
    expect(result.nextResumeAfterRecordKey).toBeUndefined();
  });

  test("rejects cross-scope aggregation and empty completion", () => {
    const empty = new BoundedAttackKnowledgePreviewAccumulator();
    expect(() => empty.finish()).toThrow("empty historical preview accumulator");

    const accumulator = new BoundedAttackKnowledgePreviewAccumulator();
    accumulator.add(batch(0));
    expect(() => accumulator.add({ ...batch(1), manifestFingerprint: "b".repeat(64) }))
      .toThrow("cannot combine different extractor scopes");
  });
});

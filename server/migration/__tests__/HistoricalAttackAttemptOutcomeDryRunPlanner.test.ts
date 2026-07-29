import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { canonicalJson } from "../../orchestration/serialization";
import {
  HistoricalAttackAttemptOutcomeDryRunPlanner,
  HistoricalAttackAttemptOutcomePlannerError,
} from "../HistoricalAttackAttemptOutcomeDryRunPlanner";
import { runHistoricalAttemptOutcomeDryRunCli } from "../historical-attempt-outcome-dry-run-cli";

const NOW = "2026-07-22T10:00:00.000Z";

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function database(filename = ":memory:"): SqliteDatabase {
  const result = createDatabaseConnection({ filename });
  migrateDatabase(result);
  return result;
}

function seedMissionRun(
  db: SqliteDatabase,
  suffix: string,
  options: { readonly syntheticImportContext?: boolean } = {},
): { readonly missionId: string; readonly runId: string } {
  const missionId = `mission-${suffix}`;
  const runId = `run-${suffix}`;
  db.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at
    ) VALUES (?, ?, 'Review one exact historical attempt', 'autonomous', ?,
      'verified', ?, ?, ?)
  `).run(
    missionId,
    `Historical attempt ${suffix}`,
    options.syntheticImportContext ? "archived" : "completed",
    options.syntheticImportContext ? "system:historical-attack-knowledge-import" : "operator-test",
    NOW,
    NOW,
  );
  db.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, 'autonomous', 'completed', ?, ?, ?, ?)
  `).run(runId, missionId, NOW, NOW, NOW, NOW);
  if (options.syntheticImportContext) {
    db.prepare(`
      INSERT INTO historical_attack_knowledge_import_contexts (
        migration_id, mission_id, run_id, created_at
      ) VALUES (?, ?, ?, ?)
    `).run(`migration-${suffix}`, missionId, runId, NOW);
  }
  return { missionId, runId };
}

function seedHistoricalBundle(
  db: SqliteDatabase,
  suffix: string,
  options: {
    readonly reportedOutcome?: boolean;
    readonly missionId?: string;
    readonly runId?: string;
    readonly evidenceType?: string;
    readonly custody?: boolean;
    readonly reusableNode?: boolean;
  } = {},
): {
  readonly bundleId: string;
  readonly bundleFingerprint: string;
  readonly evidenceId: string | null;
  readonly memoryNodeId: string | null;
} {
  const knowledge = options.reportedOutcome
    ? {
        knowledge: {
          kind: "reusable_bundle",
          facts: [{ role: "reported-outcome", nodeType: "outcome" }],
          edges: [],
        },
        privateNarrativeThatMustNeverBeReturned: "/private/source/engagement-note.md",
      }
    : {
        knowledge: {
          kind: "reusable_bundle",
          facts: [{ role: "procedure", nodeType: "attack_procedure" }],
          edges: [],
        },
        privateNarrativeThatMustNeverBeReturned: "/private/source/procedure.md",
      };
  const sanitized = canonicalJson(knowledge);
  const bundleFingerprint = sha256(sanitized);
  const bundleId = `akb_${bundleFingerprint}`;
  const sourceHash = sha256(`source-${suffix}`);
  const receiptId = `receipt-${suffix}`;
  db.prepare(`
    INSERT INTO attack_knowledge_bundles (
      id, semantic_fingerprint, sanitized_bundle_json, status,
      first_observed_at, last_observed_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'staged', ?, ?, ?, ?)
  `).run(bundleId, bundleFingerprint, sanitized, NOW, NOW, NOW, NOW);
  db.prepare(`
    INSERT INTO attack_knowledge_provenance_receipts (
      id, source_class, source_hash, evidence_count, observed_at, created_at
    ) VALUES (?, 'historical', ?, 1, ?, ?)
  `).run(receiptId, sourceHash, NOW, NOW);
  db.prepare(`
    INSERT INTO attack_knowledge_bundle_receipts (
      bundle_id, receipt_id, linked_at
    ) VALUES (?, ?, ?)
  `).run(bundleId, receiptId, NOW);

  let evidenceId: string | null = null;
  if (options.missionId && options.runId) {
    evidenceId = `evidence-${suffix}`;
    db.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, created_by, created_at
      ) VALUES (?, ?, ?, 'local-evaluator', ?, 'opaque-target', ?, ?, '{}', 0.99,
        'internal', 'verified', 'Exact local result.', 'worker-test', ?)
    `).run(
      evidenceId,
      options.missionId,
      options.runId,
      NOW,
      options.evidenceType ?? "exploit_validation_result",
      sourceHash,
      NOW,
    );
    if (options.custody !== false) {
      db.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, 'verified', 'local-evaluator', '{}', ?)
      `).run(`custody-${suffix}`, evidenceId, NOW);
    }
    if (options.evidenceType !== "command_output" && options.custody !== false) {
      db.prepare(`
        INSERT INTO attack_knowledge_bundle_evidence_bindings (
          bundle_id, receipt_id, evidence_id, content_hash, acquired_at, bound_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(bundleId, receiptId, evidenceId, sourceHash, NOW, NOW);
    }
  }

  let memoryNodeId: string | null = null;
  if (options.reusableNode !== false) {
    memoryNodeId = `mem_${sha256(`memory-${suffix}`).slice(0, 32)}`;
    const candidateId = `candidate-${suffix}`;
    const contentFingerprint = sha256(`candidate-content-${suffix}`);
    db.prepare(`
      INSERT INTO memory_nodes (
        id, node_type, title, summary, body, scope, sensitivity, confidence,
        lifecycle_status, confirmation_state, provenance_json, author_type,
        author_id, created_at, updated_at
      ) VALUES (?, 'attack_procedure', 'Reviewed procedure',
        'Reviewed reusable procedure.', 'Bounded reviewed procedure.', 'global',
        'internal', 0.98, 'verified', 'confirmed', '{}', 'operator',
        'operator-test', ?, ?)
    `).run(memoryNodeId, NOW, NOW);
    db.prepare(`
      INSERT INTO memory_candidates (
        id, proposed_node_id, candidate_type, title, summary, body,
        proposed_scope, sensitivity, confidence, source_json, status,
        proposed_by, reviewed_by, reviewed_at, created_at
      ) VALUES (?, ?, 'attack_procedure', 'Reviewed procedure',
        'Reviewed reusable procedure.', 'Bounded reviewed procedure.', 'global',
        'internal', 0.98, '{}', 'confirmed', 'attack-knowledge-compiler',
        'operator-test', ?, ?)
    `).run(candidateId, memoryNodeId, NOW, NOW);
    db.prepare(`
      INSERT INTO attack_knowledge_candidate_registry (
        content_fingerprint, candidate_id, node_type, created_at
      ) VALUES (?, ?, 'attack_procedure', ?)
    `).run(contentFingerprint, candidateId, NOW);
    db.prepare(`
      INSERT INTO attack_knowledge_bundle_candidates (
        bundle_id, role, content_fingerprint, required, ordinal, linked_at
      ) VALUES (?, 'procedure', ?, 1, 0, ?)
    `).run(bundleId, contentFingerprint, NOW);
  }
  return { bundleId, bundleFingerprint, evidenceId, memoryNodeId };
}

function seedCanonicalAttempt(
  db: SqliteDatabase,
  input: {
    readonly suffix: string;
    readonly missionId: string;
    readonly runId: string;
    readonly evidenceId: string;
    readonly memoryNodeId: string;
    readonly status?: "succeeded" | "failed" | "running";
    readonly omitTypedFields?: boolean;
    readonly omitTarget?: boolean;
    readonly omitActionBinding?: boolean;
    readonly omitEvidenceBinding?: boolean;
    readonly omitKnowledgeContext?: boolean;
  },
): string {
  const attemptId = `attempt-${input.suffix}`;
  const assetId = `asset-${input.suffix}`;
  if (!input.omitTarget) {
    db.prepare(`
      INSERT INTO topology_nodes (
        id, mission_id, run_id, node_type, primary_label, normalized_identity,
        scope_status, lifecycle_state, properties_json, confidence,
        verification_state, originating_tool, sensitivity, first_seen_at,
        last_seen_at, created_at, updated_at
      ) VALUES (?, ?, ?, 'asset', 'Opaque asset', ?, 'allowed', 'validated', '{}',
        0.99, 'verified', 'local-evaluator', 'internal', ?, ?, ?, ?)
    `).run(assetId, input.missionId, input.runId, assetId, NOW, NOW, NOW, NOW);
  }
  const status = input.status ?? "succeeded";
  const terminal = status === "succeeded" || status === "failed";
  db.prepare(`
    INSERT INTO attack_attempts (
      id, mission_id, run_id, target_asset_id, objective, technique_id,
      technique_name, action_class, prerequisites_json,
      normalized_parameters_json, status, outcome_summary, failure_category,
      ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', '{}', ?, ?, ?, ?, ?, ?)
  `).run(
    attemptId,
    input.missionId,
    input.runId,
    input.omitTarget ? null : assetId,
    input.omitTypedFields ? "" : "Validate one exact represented procedure",
    input.omitTypedFields ? null : "T1203",
    input.omitTypedFields ? "" : "Bounded exploitation validation",
    input.omitTypedFields ? "" : "exploit_validation",
    status,
    terminal ? "The exact represented attempt reached a terminal result." : null,
    status === "failed" ? "deterministic_tool_error" : null,
    terminal ? NOW : null,
    NOW,
    NOW,
  );
  if (!input.omitActionBinding) {
    const normalizedArguments = { mode: "bounded" };
    const binding = {
      missionId: input.missionId,
      runId: input.runId,
      stepId: null,
      actionType: "exploit_validation",
      actionClass: "exploit_validation",
      normalizedArguments,
      scopedTarget: assetId,
    };
    db.prepare(`
      INSERT INTO attack_attempt_action_bindings (
        attack_attempt_id, action_type, action_class,
        normalized_arguments_json, scoped_target, binding_hash, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      attemptId,
      binding.actionType,
      binding.actionClass,
      canonicalJson(normalizedArguments),
      binding.scopedTarget,
      sha256(canonicalJson(binding)),
      NOW,
    );
  }
  if (!input.omitKnowledgeContext) {
    db.prepare(`
      INSERT INTO attack_attempt_knowledge_contexts (
        attack_attempt_id, procedure_node_id, product_node_ids_json,
        version_node_ids_json, stack_node_ids_json, prerequisite_node_ids_json,
        observed_state_node_ids_json, normalized_parameters_json,
        created_at, updated_at
      ) VALUES (?, ?, '[]', '[]', '[]', '[]', '[]', '{}', ?, ?)
    `).run(attemptId, input.memoryNodeId, NOW, NOW);
  }
  if (!input.omitEvidenceBinding) {
    db.prepare(`
      INSERT INTO attack_attempt_evidence (
        attack_attempt_id, evidence_id, relationship, created_at
      ) VALUES (?, ?, 'outcome', ?)
    `).run(attemptId, input.evidenceId, NOW);
  }
  return attemptId;
}

describe("HistoricalAttackAttemptOutcomeDryRunPlanner", () => {
  test("accepts only an exact canonical terminal attempt with typed target/action, reviewed knowledge, and custody-backed evidence", () => {
    const db = database();
    try {
      const binding = seedMissionRun(db, "eligible");
      const bundle = seedHistoricalBundle(db, "eligible", {
        ...binding,
        reusableNode: true,
      });
      seedCanonicalAttempt(db, {
        suffix: "eligible",
        ...binding,
        evidenceId: bundle.evidenceId!,
        memoryNodeId: bundle.memoryNodeId!,
      });
      const before = db.prepare("SELECT total_changes() AS count").get() as CountRow;
      const planner = new HistoricalAttackAttemptOutcomeDryRunPlanner(db);
      const preview = planner.preview({ maxRecords: 10 });
      const after = db.prepare("SELECT total_changes() AS count").get() as CountRow;

      expect(preview).toMatchObject({ reviewedCount: 1, eligibleCount: 1, rejectedCount: 0 });
      expect(preview.review.entries[0]).toMatchObject({
        bundleFingerprint: bundle.bundleFingerprint,
        disposition: "eligible",
        canonicalEvidenceCount: 1,
        reviewedReusableNodeCount: 1,
        candidateAttemptCount: 1,
        eligibleAttemptCount: 1,
        eligibleOutcomeBindingCount: 1,
        successBindingCount: 1,
        failedBindingCount: 0,
        reasonCategories: [],
      });
      expect(preview.review.entries[0]!.eligibleBindingHashes).toHaveLength(1);
      expect(preview.review.entries[0]!.eligibleBindingHashes[0]).toMatch(/^[a-f0-9]{64}$/u);
      expect(after.count).toBe(before.count);
      expect(JSON.stringify(preview)).not.toContain("/private/source/");
      expect(preview.previewHash).toMatch(/^[a-f0-9]{64}$/u);
    } finally {
      db.close();
    }
  });

  test("rejects narrative outcome claims without manufacturing an attempt or classification", () => {
    const db = database();
    try {
      const bundle = seedHistoricalBundle(db, "prose-only", {
        reportedOutcome: true,
        reusableNode: false,
      });
      const planner = new HistoricalAttackAttemptOutcomeDryRunPlanner(db);
      const preview = planner.preview();
      expect(preview).toMatchObject({ reviewedCount: 1, eligibleCount: 0, rejectedCount: 1 });
      expect(preview.review.entries[0]).toMatchObject({
        bundleFingerprint: bundle.bundleFingerprint,
        reportedOutcomeClaim: true,
        disposition: "rejected",
        candidateAttemptCount: 0,
        eligibleOutcomeBindingCount: 0,
      });
      expect(preview.review.entries[0]!.reasonCategories).toEqual(expect.arrayContaining([
        "canonical_attack_attempt_required",
        "exact_mission_run_binding_required",
        "typed_intent_required",
        "typed_technique_required",
        "typed_target_context_required",
        "represented_action_binding_required",
        "terminal_outcome_required",
        "verified_non_command_evidence_required",
        "verified_evidence_custody_required",
        "verified_outcome_evidence_binding_required",
        "reviewed_reusable_membership_required",
        "reported_prose_not_authoritative",
      ]));
      expect(db.prepare("SELECT COUNT(*) AS count FROM attack_attempts").get()).toEqual({ count: 0 });
      expect(db.prepare("SELECT COUNT(*) AS count FROM reusable_knowledge_outcome_links").get()).toEqual({ count: 0 });
    } finally {
      db.close();
    }
  });

  test("reports every missing canonical gate for a weak same-run record", () => {
    const db = database();
    try {
      const binding = seedMissionRun(db, "weak");
      const bundle = seedHistoricalBundle(db, "weak", { ...binding });
      seedCanonicalAttempt(db, {
        suffix: "weak",
        ...binding,
        evidenceId: bundle.evidenceId!,
        memoryNodeId: bundle.memoryNodeId!,
        status: "running",
        omitTypedFields: true,
        omitTarget: true,
        omitActionBinding: true,
        omitEvidenceBinding: true,
        omitKnowledgeContext: true,
      });
      const entry = new HistoricalAttackAttemptOutcomeDryRunPlanner(db).preview().review.entries[0]!;
      expect(entry.disposition).toBe("rejected");
      expect(entry.candidateAttemptCount).toBe(1);
      expect(entry.reasonCategories).toEqual(expect.arrayContaining([
        "typed_intent_required",
        "typed_technique_required",
        "typed_target_context_required",
        "represented_action_binding_required",
        "terminal_outcome_required",
        "verified_outcome_evidence_binding_required",
        "reviewed_reusable_membership_required",
      ]));
    } finally {
      db.close();
    }
  });

  test("rejects a generic historical import container as an exact execution mission/run", () => {
    const db = database();
    try {
      const binding = seedMissionRun(db, "synthetic", { syntheticImportContext: true });
      const bundle = seedHistoricalBundle(db, "synthetic", { ...binding });
      seedCanonicalAttempt(db, {
        suffix: "synthetic",
        ...binding,
        evidenceId: bundle.evidenceId!,
        memoryNodeId: bundle.memoryNodeId!,
      });
      const entry = new HistoricalAttackAttemptOutcomeDryRunPlanner(db).preview().review.entries[0]!;
      expect(entry.disposition).toBe("rejected");
      expect(entry.reasonCategories).toEqual(expect.arrayContaining([
        "synthetic_import_context_not_execution_binding",
        "exact_mission_run_binding_required",
      ]));
      expect(entry.eligibleOutcomeBindingCount).toBe(0);
    } finally {
      db.close();
    }
  });

  test("paginates deterministically and summarizes only hashes and reason counts", () => {
    const db = database();
    try {
      seedHistoricalBundle(db, "page-a", { reportedOutcome: true, reusableNode: false });
      seedHistoricalBundle(db, "page-b", { reusableNode: false });
      const planner = new HistoricalAttackAttemptOutcomeDryRunPlanner(db);
      const first = planner.preview({ maxRecords: 1 });
      expect(first.review.hasMore).toBe(true);
      expect(first.review.nextCursor).toMatch(/^[a-f0-9]{64}$/u);
      const second = planner.preview({
        afterBundleFingerprint: first.review.nextCursor!,
        maxRecords: 1,
      });
      expect(second.review.entries[0]!.bundleFingerprint)
        .not.toBe(first.review.entries[0]!.bundleFingerprint);

      const audit = planner.audit({ maxRecordsPerPage: 1, maxPages: 5, maxDurationMs: 30_000 });
      expect(audit).toMatchObject({
        dryRun: true,
        status: "completed",
        pageCount: 2,
        reviewedCount: 2,
        eligibleCount: 0,
        rejectedCount: 2,
      });
      for (const hash of [
        audit.reviewedBundleSetHash,
        audit.eligibleBundleSetHash,
        audit.rejectedBundleSetHash,
        audit.sourceSetHash,
        audit.evidenceSetHash,
        audit.pageSetHash,
        audit.reportHash,
      ]) expect(hash).toMatch(/^[a-f0-9]{64}$/u);
      expect(audit.reasonCounts.canonical_attack_attempt_required).toBe(2);
      expect(JSON.stringify(audit)).not.toContain("privateNarrativeThatMustNeverBeReturned");
    } finally {
      db.close();
    }
  });

  test("fails closed before migration 033 and rejects unbounded cursors/page sizes", () => {
    const db = database();
    try {
      expect(() => new HistoricalAttackAttemptOutcomeDryRunPlanner(db).preview({
        afterBundleFingerprint: "not-a-hash",
      })).toThrow(HistoricalAttackAttemptOutcomePlannerError);
      expect(() => new HistoricalAttackAttemptOutcomeDryRunPlanner(db).preview({
        maxRecords: 1_001,
      })).toThrow(HistoricalAttackAttemptOutcomePlannerError);
      db.exec("DROP TABLE reusable_knowledge_outcome_links");
      expect(() => new HistoricalAttackAttemptOutcomeDryRunPlanner(db))
        .toThrow("schema-33 integrity boundary");
    } finally {
      db.close();
    }
  });

  test("CLI opens the database read-only and emits a hash-only audit receipt", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-historical-outcome-audit-"));
    const filename = join(directory, "fixture.sqlite");
    const db = database(filename);
    try {
      seedHistoricalBundle(db, "cli-prose", { reportedOutcome: true, reusableNode: false });
    } finally {
      db.close();
    }
    const beforeHash = sha256(readFileSync(filename).toString("base64"));
    const output: string[] = [];
    const errors: string[] = [];
    try {
      expect(await runHistoricalAttemptOutcomeDryRunCli([
        "audit",
        "--dry-run",
        "--db",
        filename,
        "--max-records",
        "1",
        "--max-pages",
        "2",
      ], {}, {
        write: (value) => output.push(value),
        writeError: (value) => errors.push(value),
      })).toBe(0);
      expect(errors).toEqual([]);
      const report = JSON.parse(output.join("")) as Record<string, unknown>;
      expect(report).toMatchObject({
        dryRun: true,
        status: "completed",
        reviewedCount: 1,
        eligibleCount: 0,
        rejectedCount: 1,
      });
      expect(report.reportHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(output.join("")).not.toContain("/private/source/");
      expect(sha256(readFileSync(filename).toString("base64"))).toBe(beforeHash);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

interface CountRow {
  readonly count: number;
}

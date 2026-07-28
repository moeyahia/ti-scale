import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MemoryRepository, OperationalHazardMatcher } from "../../memory";
import { SecondBrainService } from "../../memory/SecondBrainService";
import { BrainContextService } from "../../brain-runtime/BrainContextService";
import { ObsidianVaultBridge } from "../../vault/ObsidianVaultBridge";
import { VaultPathPolicy } from "../../vault/VaultPathPolicy";
import {
  AttackKnowledgeCompiler,
  type AttackKnowledgeCompilerInput,
  type OperationalHazardKnowledge,
} from "../AttackKnowledgeCompiler";
import {
  AttackKnowledgePromotionError,
  AttackKnowledgePromotionService,
} from "../AttackKnowledgePromotionService";

const NOW = "2026-07-20T18:00:00.000Z";
const HMAC_KEY = "attack-knowledge-promotion-test-key-32-bytes-minimum";
const databases: SqliteDatabase[] = [];
const directories: string[] = [];

afterEach(() => {
  databases.splice(0).forEach((database) => database.close());
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function knowledge(): OperationalHazardKnowledge {
  return {
    kind: "operational_hazard",
    product: { name: "Microsoft IIS", exactVersion: "10.0" },
    stack: [
      { nodeType: "framework", name: "ASP.NET", exactVersion: "4.8" },
      { nodeType: "runtime", name: "Embedded JavaScript engine", exactVersion: "1.0" },
      { nodeType: "operating_system", name: "Windows Server", exactVersion: "2022" },
    ],
    procedure: {
      name: "Bounded expression diagnostic sequence",
      version: "v3",
      orderedSteps: [
        "Run one harmless scalar execution probe",
        "Submit one bounded expression diagnostic",
        "Repeat the harmless scalar execution probe",
      ],
      normalizedParameters: {
        automaticRetries: 0,
        maximumDiagnosticStages: 1,
        healthProbeRequired: true,
      },
      prerequisites: [
        "Base application page responds",
        "Expression execution health probe succeeds",
      ],
    },
    hazard: {
      name: "Application execution path hangs after known-bad diagnostic sequence",
      observedSymptom: "The base page remains reachable while expression requests stop completing",
      affectedComponent: "Application expression execution worker",
      unaffectedComponents: ["Base HTTP request handler"],
      survivingHealthSignals: ["The base page continues returning a successful response"],
      stateBefore: "Harmless scalar execution probe succeeds",
      stateAfter: "Expression execution requests time out while the base page remains available",
      unsafeRetryConditions: [
        "The harmless expression health probe does not return",
        "The previous bounded diagnostic has no terminal outcome",
      ],
      healthGate: [
        "Recycle the isolated application execution worker",
        "Prove a fresh harmless scalar execution probe succeeds",
      ],
      retryValidConditions: [
        "The prior diagnostic process is absent",
        "The local execution queue is within its reviewed safe bound",
      ],
      recoveryActionSummary: "Recycle the application pool and pass the harmless execution health probe",
      recoveryCost: {
        exactProcedureResetCount: 2,
        operatorReportedResetCountMinimum: 11,
        serviceRecycleCount: 2,
        operatorMinutes: 18,
      },
      saferAlternative: {
        name: "Single-stage expression validation",
        orderedSteps: [
          "Restore a healthy execution worker",
          "Run one lower-risk diagnostic stage",
          "Re-check execution health before any next stage",
        ],
        reviewedBinding: {
          version: "v4-reviewed",
          normalizedParameters: {
            automaticRetries: 0,
            maximumDiagnosticStages: 1,
            healthProbeRequired: true,
            postStageHealthCheckRequired: true,
          },
          sourceLoad: 1,
          sourceConcurrency: 1,
          sourceTimingWindowMs: 60_000,
          load: 1,
          concurrency: 1,
          timingWindowMs: 30_000,
        },
        retryConditionEvidence: [
          { statement: "Recycle the isolated application execution worker", evidenceKey: "worker_recycled" },
          { statement: "Prove a fresh harmless scalar execution probe succeeds", evidenceKey: "scalar_probe_ok" },
          { statement: "The prior diagnostic process is absent", evidenceKey: "prior_process_absent" },
          {
            statement: "The local execution queue is within its reviewed safe bound",
            evidenceKey: "execution_queue_within_bound",
          },
        ],
      },
      concurrencyMinimum: 1,
      timingWindowMs: 120_000,
      freshUntil: "2027-01-20T18:00:00.000Z",
    },
    corroboration: {
      exactProcedureAttemptCount: 3,
      exactProcedureReproducibilityCount: 2,
      exactProcedureEvidenceCount: 2,
    },
  };
}

function input(
  canonicalEvidenceIds?: readonly string[],
  knowledgeInput: OperationalHazardKnowledge = knowledge(),
): AttackKnowledgeCompilerInput {
  return {
    source: {
      privateSourceReference: "/root/htb/boxes/ReaperTwo/notes/private-current-state.md",
      privateLabels: ["ReaperTwo", "10.129.39.191"],
      sourceClass: "historical",
      sourceHash: "a".repeat(64),
      observedAt: NOW,
      evidenceCount: 8,
      ...(canonicalEvidenceIds?.length ? { canonicalEvidenceIds } : {}),
    },
    knowledge: knowledgeInput,
    confidence: 0.96,
  };
}

function stageApprovedHistoricalEvidencePath(
  database: SqliteDatabase,
  bundleId: string,
  provenanceReceiptId: string,
  sourceHash: string,
  evidenceIds: readonly string[],
): void {
  const jobId = "historical-hazard-job-promotion-fixture";
  database.prepare(`
    INSERT INTO historical_hazard_import_jobs (
      id, request_fingerprint, preview_hash, source_manifest_hash,
      private_label_hashes_json, mission_id, run_id, status, source_count,
      source_bytes, checkpoint_ordinal, protected_manifest_ref,
      protected_manifest_hash, approved_by, approved_at, created_at,
      updated_at, completed_at
    ) VALUES (?, ?, ?, ?, ?, 'mission-attack-knowledge-review',
      'run-attack-knowledge-review', 'candidates_staged', ?, ?, ?,
      'protected:historical-hazard-fixture', ?, 'operator-reviewer', ?, ?, ?, ?)
  `).run(
    jobId,
    "3".repeat(64),
    "4".repeat(64),
    "5".repeat(64),
    JSON.stringify(["6".repeat(64)]),
    evidenceIds.length,
    evidenceIds.length * 128,
    evidenceIds.length,
    "7".repeat(64),
    NOW,
    NOW,
    NOW,
    NOW,
  );
  evidenceIds.forEach((evidenceId, index) => {
    const evidence = database.prepare("SELECT content_hash FROM evidence WHERE id = ?")
      .get(evidenceId) as { readonly content_hash: string };
    const artifactId = `artifact-historical-hazard-${index}`;
    const candidateId = `candidate-historical-hazard-${index}`;
    database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, artifact_type, storage_uri, content_hash,
        byte_size, media_type, sensitivity, metadata_json, created_at, journey
      ) VALUES (?, 'mission-attack-knowledge-review', 'run-attack-knowledge-review',
        'historical_hazard_source', ?, ?, 128, 'application/octet-stream',
        'private', '{}', ?, 'guided')
    `).run(artifactId, `protected:historical-hazard-source-${index}`, evidence.content_hash, NOW);
    database.prepare(`
      INSERT INTO evidence_candidates (
        id, mission_id, run_id, artifact_id, evidence_type, label, meaning,
        promotion_reason, validation_requirements_json, state, sensitivity,
        proposed_by, reviewed_by, review_reason, promoted_evidence_id,
        created_at, reviewed_at
      ) VALUES (?, 'mission-attack-knowledge-review', 'run-attack-knowledge-review',
        ?, 'finding_reproduction', 'Historical hazard source',
        'Independently reviewed source for the reusable hazard',
        'Operator approved the source and its canonical evidence', '[]',
        'promoted', 'private', 'historical-hazard-importer',
        'operator-reviewer', 'Exact source review completed', ?, ?, ?)
    `).run(candidateId, artifactId, evidenceId, NOW, NOW);
    database.prepare(`
      INSERT INTO historical_hazard_import_sources (
        job_id, ordinal, selection_key, source_hash, byte_size, modified_at,
        evidence_type, protected_backup_ref, artifact_id, candidate_id,
        status, staged_at
      ) VALUES (?, ?, ?, ?, 128, ?, 'finding_reproduction', ?, ?, ?,
        'candidate_staged', ?)
    `).run(
      jobId,
      index,
      String(index + 8).repeat(64),
      evidence.content_hash,
      NOW,
      `protected:historical-hazard-backup-${index}`,
      artifactId,
      candidateId,
      NOW,
    );
  });
  database.prepare(`
    INSERT INTO historical_hazard_import_bundle_links (
      job_id, bundle_id, provenance_receipt_id, source_hash,
      binding_preview_hash, evidence_ids_json, actor_id, bound_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'operator-reviewer', ?)
  `).run(
    jobId,
    bundleId,
    provenanceReceiptId,
    sourceHash,
    "d".repeat(64),
    JSON.stringify([...evidenceIds].sort()),
    NOW,
  );
}

function setup(options: {
  readonly bindCanonicalEvidence?: boolean;
  readonly canonicalEvidenceCount?: number;
  readonly bindEvidenceProvenance?: boolean;
  readonly knowledgeInput?: OperationalHazardKnowledge;
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "attack-knowledge-promotion-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  databases.push(database);
  migrateDatabase(database);
  const clock = () => new Date(NOW);
  const missionId = "mission-attack-knowledge-review";
  const runId = "run-attack-knowledge-review";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Private promotion evidence fixture',
      'Retain private canonical evidence for a reusable review', 'guided',
      'completed', 'verified', '{}', 'operator-reviewer', ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version, control_plane
    ) VALUES (?, ?, 'guided', 'completed', 1, 'Evidence review complete',
      '{}', '{}', ?, ?, 1, 'ti_scale')
  `).run(runId, missionId, NOW, NOW);
  // Deliberately include a private target label in one canonical evidence ID.
  // That identifier is allowed in the private evidence binding, but must never
  // become reusable node content, provider context, or a Vault projection.
  const verificationEvidenceIds = [
    "evidence-ReaperTwo-10.129.39.191-reset-proof",
    "evidence-ak-review-2",
  ] as const;
  verificationEvidenceIds.forEach((evidenceId, index) => {
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, created_by, created_at
      ) VALUES (?, ?, ?, 'trusted-local-evaluator', ?, 'private-target-redacted',
        'finding_reproduction', ?, '{"method":"local_evaluator"}', 1,
        'private', 'verified', 'Private canonical reproduction evidence',
        'local-evidence-verifier', ?)
    `).run(evidenceId, missionId, runId, NOW, String(index + 1).repeat(64), NOW);
    database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'verified', 'local-evidence-verifier',
        '{"method":"deterministic_local_verification"}', ?)
    `).run(`custody-${evidenceId}`, evidenceId, NOW);
  });
  const compiler = new AttackKnowledgeCompiler(database, { receiptHmacKey: HMAC_KEY, clock });
  const promotion = new AttackKnowledgePromotionService(database, { clock });
  const memory = new MemoryRepository(database, { clock });
  const canonicalEvidenceIds = options.bindCanonicalEvidence === false
    ? []
    : verificationEvidenceIds.slice(0, options.canonicalEvidenceCount ?? verificationEvidenceIds.length);
  const compiled = compiler.compile(input(
    canonicalEvidenceIds,
    options.knowledgeInput,
  ));
  if (!compiled.bundleFingerprint || !compiled.bundleId) {
    throw new Error(`Compiler fixture did not stage a bundle: ${JSON.stringify(compiled.reasonCategories)}`);
  }
  if (options.bindEvidenceProvenance !== false) {
    stageApprovedHistoricalEvidencePath(
      database,
      compiled.bundleId,
      compiled.provenanceReceiptId!,
      "a".repeat(64),
      canonicalEvidenceIds.length > 0 ? canonicalEvidenceIds : verificationEvidenceIds,
    );
  }
  return { database, compiler, promotion, memory, compiled, verificationEvidenceIds };
}

function candidateRoles(database: SqliteDatabase, bundleId: string): readonly {
  role: string;
  candidateId: string;
}[] {
  return (database.prepare(`
    SELECT bc.role, registry.candidate_id AS candidateId
    FROM attack_knowledge_bundle_candidates bc
    JOIN attack_knowledge_candidate_registry registry
      ON registry.content_fingerprint = bc.content_fingerprint
    WHERE bc.bundle_id = ? ORDER BY bc.ordinal
  `).all(bundleId) as Array<{ role: string; candidateId: string }>);
}

function confirmAll(
  database: SqliteDatabase,
  memory: MemoryRepository,
  bundleId: string,
  editedRole?: string,
): ReadonlyMap<string, string> {
  const result = new Map<string, string>();
  for (const candidate of candidateRoles(database, bundleId)) {
    const node = memory.confirmCandidate(
      candidate.candidateId,
      "operator-reviewer",
      candidate.role === editedRole
        ? { summary: "Operator-edited reusable summary retained under the same reviewed node type." }
        : {},
    );
    result.set(candidate.role, node.id);
  }
  return result;
}

function count(database: SqliteDatabase, table: string, where = "1 = 1"): number {
  return Number((database.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE ${where}`).get() as { count: number }).count);
}

describe("AttackKnowledgePromotionService", () => {
  test("blocks promotion when the safer retry lacks an exact reviewed binding and condition evidence", () => {
    const complete = knowledge();
    const incompleteKnowledge: OperationalHazardKnowledge = {
      ...complete,
      hazard: {
        ...complete.hazard,
        saferAlternative: {
          name: complete.hazard.saferAlternative.name,
          orderedSteps: complete.hazard.saferAlternative.orderedSteps,
        },
      },
    };
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup({
      knowledgeInput: incompleteKnowledge,
    });
    confirmAll(database, memory, compiled.bundleId!);

    const preview = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    expect(preview.ready).toBe(false);
    expect(preview.blockers).toContainEqual(expect.objectContaining({
      code: "promotion_retry_contract_incomplete",
      message: expect.stringContaining("exact reviewed source/alternative execution bindings"),
    }));
    expect(preview.review.operationalHazardProfile).toMatchObject({ action: "blocked" });
    expect(count(database, "operational_hazard_profiles")).toBe(0);
    expect(count(database, "memory_edges")).toBe(0);
  });

  test("keeps a historical candidate-only bundle unpromotable until canonical evidence is bound during compilation", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup({
      bindCanonicalEvidence: false,
    });
    confirmAll(database, memory, compiled.bundleId!);
    expect(count(database, "attack_knowledge_bundle_evidence_bindings")).toBe(0);

    const preview = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    expect(preview.ready).toBe(false);
    expect(preview.blockers).toContainEqual(expect.objectContaining({
      code: "verification_evidence_invalid",
    }));
    expect(() => promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds,
    })).toThrow(AttackKnowledgePromotionError);
    expect(count(database, "memory_edges")).toBe(0);
    expect(count(database, "operational_hazard_profiles")).toBe(0);
  });

  test("rejects missing, unbound, and direct-correction verification paths", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup();
    const nodes = confirmAll(database, memory, compiled.bundleId!);
    const missing = promotion.preview(compiled.bundleFingerprint!);
    expect(missing.ready).toBe(false);
    expect(missing.blockers).toContainEqual(expect.objectContaining({
      code: "verification_evidence_missing",
    }));

    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, created_by, created_at
      ) SELECT 'evidence-unrelated-other-engagement', mission_id, run_id,
        'trusted-local-evaluator', acquired_at, 'different-private-target',
        evidence_type, ?, provenance_json, confidence, sensitivity,
        'verified', 'Unrelated canonical evidence', created_by, created_at
      FROM evidence WHERE id = ?
    `).run("f".repeat(64), verificationEvidenceIds[0]);
    database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES ('custody-unrelated-other-engagement',
        'evidence-unrelated-other-engagement', 'verified',
        'local-evidence-verifier', '{}', ?)
    `).run(NOW);
    const unbound = promotion.preview(compiled.bundleFingerprint!, [
      verificationEvidenceIds[0],
      "evidence-unrelated-other-engagement",
    ]);
    expect(unbound.ready).toBe(false);
    expect(unbound.blockers).toContainEqual(expect.objectContaining({
      code: "verification_evidence_invalid",
    }));
    expect(() => memory.correctNode(nodes.get("hazard")!, {
      lifecycleStatus: "verified",
      authorType: "operator",
      authorId: "operator-reviewer",
      changeReason: "Attempt to bypass the evidence-backed promotion review",
    })).toThrow("only through an evidence-backed attack-knowledge promotion review");
  });

  test("rejects compiler-bound verified evidence that has no exact occurrence or approved import path", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup({
      bindEvidenceProvenance: false,
    });
    confirmAll(database, memory, compiled.bundleId!);
    expect(count(database, "attack_knowledge_bundle_evidence_bindings")).toBe(2);
    expect(count(database, "historical_hazard_import_bundle_links")).toBe(0);
    expect(count(database, "operational_hazard_occurrences")).toBe(0);

    const preview = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    expect(preview.ready).toBe(false);
    expect(preview.blockers).toContainEqual(expect.objectContaining({
      code: "verification_evidence_invalid",
      message: expect.stringContaining("exact current occurrence or approved historical import"),
    }));
    expect(() => promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds,
    })).toThrow(AttackKnowledgePromotionError);
    expect(count(database, "operational_hazard_profiles")).toBe(0);
    expect(count(database, "memory_edges")).toBe(0);
  });

  test("rejects an unreviewed bundle without materializing graph state", () => {
    const { database, promotion, compiled, verificationEvidenceIds } = setup();
    const preview = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);

    expect(preview.ready).toBe(false);
    expect(preview.blockers.some(({ code }) => code === "candidate_unreviewed")).toBe(true);
    expect(() => promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds,
    })).toThrow(AttackKnowledgePromotionError);
    expect(count(database, "memory_edges")).toBe(0);
    expect(count(database, "operational_hazard_profiles")).toBe(0);
    expect(database.prepare("SELECT status FROM attack_knowledge_bundles WHERE id = ?").get(compiled.bundleId!))
      .toEqual({ status: "staged" });
  });

  test("accepts an operator edit of the same type and blocks a candidate/node type mismatch", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup();
    const nodes = confirmAll(database, memory, compiled.bundleId!, "product");
    const edited = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);

    expect(edited.ready).toBe(true);
    expect(edited.review.candidates.find(({ role }) => role === "product")?.candidateStatus)
      .toBe("edited_confirmed");

    database.prepare("UPDATE memory_nodes SET node_type = 'framework' WHERE id = ?")
      .run(nodes.get("product")!);
    const mismatch = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    expect(mismatch.ready).toBe(false);
    expect(mismatch.blockers).toContainEqual(expect.objectContaining({
      code: "candidate_type_mismatch",
      role: "product",
    }));
  });

  test("rejects a stale review hash after a reviewed node is corrected", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup();
    const nodes = confirmAll(database, memory, compiled.bundleId!);
    const stale = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    memory.correctNode(nodes.get("health")!, {
      summary: "Operator-corrected harmless health gate for the generalized execution worker.",
      authorType: "operator",
      authorId: "operator-reviewer",
      changeReason: "Clarify the reusable health-gate meaning before graph promotion",
    });
    const current = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    expect(current.ready).toBe(true);
    expect(current.reviewHash).not.toBe(stale.reviewHash);

    try {
      promotion.promote({
        bundleFingerprint: compiled.bundleFingerprint!,
        actor: "operator-reviewer",
        expectedReviewHash: stale.reviewHash,
        verificationEvidenceIds,
      });
      throw new Error("Expected stale promotion review to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(AttackKnowledgePromotionError);
      expect((error as AttackKnowledgePromotionError).code).toBe("promotion_stale_review");
    }
    expect(count(database, "memory_edges")).toBe(0);
  });

  test("atomically verifies a connected evidence-backed graph, exact-count hazard profile, and tamper-evident receipt", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup();
    const nodes = confirmAll(database, memory, compiled.bundleId!, "procedure");
    const preview = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    expect(preview.ready).toBe(true);
    expect(preview.review.edges.every(({ action }) => action === "create")).toBe(true);

    const result = promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds,
    });
    expect(result.status).toBe("materialized");
    expect(result.edgeIds).toHaveLength(preview.review.edges.length);
    expect(database.prepare(`
      SELECT status FROM attack_knowledge_bundles WHERE id = ?
    `).get(compiled.bundleId!)).toEqual({ status: "materialized" });
    expect(database.prepare(`
      SELECT DISTINCT status FROM attack_knowledge_compiler_runs WHERE bundle_id = ?
    `).all(compiled.bundleId!)).toEqual([{ status: "materialized" }]);
    expect(count(database, "attack_knowledge_bundle_edges", "materialized_edge_id IS NULL")).toBe(0);
    expect(database.prepare(`
      SELECT DISTINCT lifecycle_status, author_type FROM memory_edges
    `).all()).toEqual([{ lifecycle_status: "verified", author_type: "operator" }]);
    expect(database.prepare(`
      SELECT DISTINCT lifecycle_status, confirmation_state FROM memory_nodes
      WHERE id IN (${[...nodes.values()].map(() => "?").join(",")})
    `).all(...nodes.values())).toEqual([{
      lifecycle_status: "verified",
      confirmation_state: "confirmed",
    }]);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM memory_versions
      WHERE lifecycle_status = 'verified'
    `).get()).toEqual({ count: nodes.size });

    const candidateNodeIds = new Set(nodes.values());
    const reached = new Set<string>([nodes.get("procedure")!]);
    const graphEdges = database.prepare(`
      SELECT source_node_id, target_node_id FROM memory_edges
    `).all() as Array<{ source_node_id: string; target_node_id: string }>;
    let changed = true;
    while (changed) {
      changed = false;
      for (const edge of graphEdges) {
        if (reached.has(edge.source_node_id) && !reached.has(edge.target_node_id)) {
          reached.add(edge.target_node_id);
          changed = true;
        }
        if (reached.has(edge.target_node_id) && !reached.has(edge.source_node_id)) {
          reached.add(edge.source_node_id);
          changed = true;
        }
      }
    }
    expect([...candidateNodeIds].every((nodeId) => reached.has(nodeId))).toBe(true);

    expect(database.prepare(`
      SELECT attempt_count, reproducibility_count, recovery_cost_json,
        safe_retry_gate_json
      FROM operational_hazard_profiles WHERE node_id = ?
    `).get(result.hazardProfileNodeId!)).toEqual({
      attempt_count: 3,
      reproducibility_count: 2,
      recovery_cost_json: JSON.stringify({
        operatorMinutes: 18,
        operatorReportedResetCountMinimum: 11,
        resetCount: 2,
        serviceRecycleCount: 2,
      }),
      safe_retry_gate_json: JSON.stringify([
        "Recycle the isolated application execution worker",
        "Prove a fresh harmless scalar execution probe succeeds",
        "The prior diagnostic process is absent",
        "The local execution queue is within its reviewed safe bound",
      ]),
    });
    const receipt = database.prepare(`
      SELECT review_hash, audit_record_id, audit_record_hash
      FROM attack_knowledge_promotion_receipts WHERE id = ?
    `).get(result.receiptId) as { review_hash: string; audit_record_id: string; audit_record_hash: string };
    expect(receipt.review_hash).toBe(preview.reviewHash);
    expect(database.prepare("SELECT record_hash FROM audit_records WHERE id = ?").get(receipt.audit_record_id))
      .toEqual({ record_hash: receipt.audit_record_hash });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'attack_knowledge.verification_approved'
    `).get()).toEqual({ count: 1 });
  });

  test("compiler-to-operator-verification promotion creates a real matcher gate for the exact reusable stack", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup();
    const nodes = confirmAll(database, memory, compiled.bundleId!);
    const preview = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds,
    });

    database.prepare(`
      INSERT INTO plans (
        id, run_id, version, status, strategy_summary, plan_hash,
        content_hash, content_hash_version, created_by, created_at
      ) VALUES ('plan-promotion-vertical', 'run-attack-knowledge-review', 1,
        'active', 'Exercise the promoted local hazard gate', ?, ?, 1,
        'operator-reviewer', ?)
    `).run("8".repeat(64), "8".repeat(64), NOW);
    database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        action_class, risk_class, created_at, updated_at
      ) VALUES ('step-promotion-vertical', 'plan-promotion-vertical',
        'run-attack-knowledge-review', 0, 'validation',
        'Repeat the exact represented procedure',
        'Prove the promoted hazard blocks a blind repeat', 'ready',
        'exploit_validation', 'high', ?, ?)
    `).run(NOW, NOW);
    database.prepare(`
      INSERT INTO attack_attempts (
        id, mission_id, run_id, plan_id, step_id, objective, technique_name,
        action_class, prerequisites_json, normalized_parameters_json,
        status, created_at, updated_at
      ) VALUES ('attempt-promotion-vertical', 'mission-attack-knowledge-review',
        'run-attack-knowledge-review', 'plan-promotion-vertical',
        'step-promotion-vertical', 'Repeat the exact represented procedure',
        'Bounded expression diagnostic sequence', 'exploit_validation', '[]',
        '{}', 'ready', ?, ?)
    `).run(NOW, NOW);

    const matcher = new OperationalHazardMatcher(database, { clock: () => new Date(NOW) });
    matcher.bindAttackAttempt({
      attackAttemptId: "attempt-promotion-vertical",
      procedureNodeId: nodes.get("procedure")!,
      procedureVersionNodeId: nodes.get("procedure.version")!,
      productNodeIds: [nodes.get("product")!],
      versionNodeIds: [
        nodes.get("product.version")!,
        nodes.get("stack.0.version")!,
        nodes.get("stack.1.version")!,
        nodes.get("stack.2.version")!,
      ],
      stackNodeIds: [
        nodes.get("stack.0")!,
        nodes.get("stack.1")!,
        nodes.get("stack.2")!,
      ],
      prerequisiteNodeIds: [nodes.get("prerequisite.0")!, nodes.get("prerequisite.1")!],
      observedStateNodeIds: [nodes.get("health")!, nodes.get("state")!],
      normalizedParameters: knowledge().procedure.normalizedParameters,
      concurrency: 1,
      timingWindowMs: 120_000,
    });
    const assessment = matcher.assessAttackAttempt("attempt-promotion-vertical");
    expect(assessment).toMatchObject({
      decision: "block",
      matchedHazardNodeIds: [nodes.get("hazard")!],
      blockedProcedureNodeIds: [nodes.get("procedure")!],
      warning: expect.stringContaining("blind retry"),
      saferKnownSequence: expect.arrayContaining([
        "Restore a healthy execution worker",
        "Re-check execution health before any next stage",
      ]),
    });
  });

  test("generic verified evidence plus an asserted reset count cannot lower the matcher threshold", () => {
    const base = knowledge();
    const singleObservation: OperationalHazardKnowledge = {
      ...base,
      hazard: {
        ...base.hazard,
        recoveryCost: {
          exactProcedureResetCount: 1,
          operatorReportedResetCountMinimum: 11,
          requiresDisposableTargetReset: true,
        },
      },
      corroboration: {
        exactProcedureAttemptCount: 1,
        exactProcedureReproducibilityCount: 1,
        exactProcedureEvidenceCount: 1,
      },
    };
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup({
      knowledgeInput: singleObservation,
      canonicalEvidenceCount: 1,
    });
    const nodes = confirmAll(database, memory, compiled.bundleId!);
    const genericEvidence = [verificationEvidenceIds[0]!] as const;
    const preview = promotion.preview(compiled.bundleFingerprint!, genericEvidence);
    expect(preview.review.verification.evidence[0]?.evidenceType).toBe("finding_reproduction");
    promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds: genericEvidence,
    });
    expect(database.prepare(`
      SELECT receipt_backed_occurrence_count, reproducibility_count,
        json_extract(recovery_cost_json, '$.resetCount') AS asserted_reset_count
      FROM operational_hazard_profiles WHERE node_id = ?
    `).get(nodes.get("hazard")!)).toEqual({
      receipt_backed_occurrence_count: 0,
      reproducibility_count: 1,
      asserted_reset_count: 1,
    });
    expect(() => database.prepare(`
      UPDATE operational_hazard_profiles
      SET receipt_backed_occurrence_count = 1
      WHERE node_id = ?
    `).run(nodes.get("hazard")!)).toThrow(/must be derived from canonical receipts/u);

    database.prepare(`
      INSERT INTO plans (
        id, run_id, version, status, strategy_summary, plan_hash,
        content_hash, content_hash_version, created_by, created_at
      ) VALUES ('plan-unproven-reset-threshold', 'run-attack-knowledge-review', 1,
        'active', 'Exercise the fail-closed reset threshold', ?, ?, 1,
        'operator-reviewer', ?)
    `).run("7".repeat(64), "7".repeat(64), NOW);
    database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        action_class, risk_class, created_at, updated_at
      ) VALUES ('step-unproven-reset-threshold', 'plan-unproven-reset-threshold',
        'run-attack-knowledge-review', 0, 'validation',
        'Review one asserted reset observation',
        'Do not treat generic evidence as a signed physical reset', 'ready',
        'exploit_validation', 'high', ?, ?)
    `).run(NOW, NOW);
    database.prepare(`
      INSERT INTO attack_attempts (
        id, mission_id, run_id, plan_id, step_id, objective, technique_name,
        action_class, prerequisites_json, normalized_parameters_json,
        status, created_at, updated_at
      ) VALUES ('attempt-unproven-reset-threshold', 'mission-attack-knowledge-review',
        'run-attack-knowledge-review', 'plan-unproven-reset-threshold',
        'step-unproven-reset-threshold', 'Review the exact represented procedure',
        'Bounded expression diagnostic sequence', 'exploit_validation', '[]',
        '{}', 'ready', ?, ?)
    `).run(NOW, NOW);

    const matcher = new OperationalHazardMatcher(database, { clock: () => new Date(NOW) });
    matcher.bindAttackAttempt({
      attackAttemptId: "attempt-unproven-reset-threshold",
      procedureNodeId: nodes.get("procedure")!,
      procedureVersionNodeId: nodes.get("procedure.version")!,
      productNodeIds: [nodes.get("product")!],
      versionNodeIds: [
        nodes.get("product.version")!,
        nodes.get("stack.0.version")!,
        nodes.get("stack.1.version")!,
        nodes.get("stack.2.version")!,
      ],
      stackNodeIds: [nodes.get("stack.0")!, nodes.get("stack.1")!, nodes.get("stack.2")!],
      prerequisiteNodeIds: [nodes.get("prerequisite.0")!, nodes.get("prerequisite.1")!],
      observedStateNodeIds: [nodes.get("health")!, nodes.get("state")!],
      normalizedParameters: singleObservation.procedure.normalizedParameters,
      concurrency: 1,
      timingWindowMs: 120_000,
    });
    expect(matcher.assessAttackAttempt("attempt-unproven-reset-threshold")).toMatchObject({
      decision: "warn",
      blockedProcedureNodeIds: [],
    });
  });

  test("rolls back edges, profile, audit, mappings, and statuses when the final receipt cannot commit", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup();
    confirmAll(database, memory, compiled.bundleId!);
    const preview = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    database.exec(`
      CREATE TRIGGER test_reject_attack_knowledge_receipt
      BEFORE INSERT ON attack_knowledge_promotion_receipts BEGIN
        SELECT RAISE(ABORT, 'fixture rejects final promotion receipt');
      END;
    `);

    expect(() => promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds,
    })).toThrow("fixture rejects final promotion receipt");
    expect(count(database, "memory_edges")).toBe(0);
    expect(count(database, "operational_hazard_profiles")).toBe(0);
    expect(count(database, "audit_records", "action = 'attack_knowledge.promoted'")).toBe(0);
    expect(count(database, "audit_records", "action = 'attack_knowledge.verification_approved'")).toBe(0);
    expect(count(database, "attack_knowledge_promotion_receipts")).toBe(0);
    expect(count(database, "attack_knowledge_bundle_edges", "materialized_edge_id IS NOT NULL")).toBe(0);
    expect(database.prepare("SELECT status FROM attack_knowledge_bundles WHERE id = ?").get(compiled.bundleId!))
      .toEqual({ status: "staged" });
    expect(database.prepare("SELECT DISTINCT status FROM attack_knowledge_compiler_runs WHERE bundle_id = ?").all(compiled.bundleId!))
      .toEqual([{ status: "staged" }]);
    expect(database.prepare(`
      SELECT DISTINCT lifecycle_status FROM memory_nodes
      WHERE id IN (
        SELECT candidate.proposed_node_id
        FROM attack_knowledge_bundle_candidates link
        JOIN attack_knowledge_candidate_registry registry
          ON registry.content_fingerprint = link.content_fingerprint
        JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
        WHERE link.bundle_id = ?
      )
    `).all(compiled.bundleId!)).toEqual([{ lifecycle_status: "confirmed" }]);
  });

  test("replays the exact same operator receipt idempotently without duplicate graph writes", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup();
    confirmAll(database, memory, compiled.bundleId!);
    const preview = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    const first = promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds,
    });
    const countsBefore = {
      edges: count(database, "memory_edges"),
      profiles: count(database, "operational_hazard_profiles"),
      receipts: count(database, "attack_knowledge_promotion_receipts"),
      audits: count(database, "audit_records", "action = 'attack_knowledge.promoted'"),
    };

    const second = promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds,
    });
    expect(second).toEqual({ ...first, status: "replayed" });
    expect({
      edges: count(database, "memory_edges"),
      profiles: count(database, "operational_hazard_profiles"),
      receipts: count(database, "attack_knowledge_promotion_receipts"),
      audits: count(database, "audit_records", "action = 'attack_knowledge.promoted'"),
    }).toEqual(countsBefore);
    expect(promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds)).toMatchObject({
      ready: true,
      replay: true,
      reviewHash: preview.reviewHash,
    });
  });

  test("does not leak source path, target address, or engagement label into promoted graph/profile/audit state", () => {
    const { database, promotion, memory, compiled, verificationEvidenceIds } = setup();
    const nodes = confirmAll(database, memory, compiled.bundleId!);
    const preview = promotion.preview(compiled.bundleFingerprint!, verificationEvidenceIds);
    promotion.promote({
      bundleFingerprint: compiled.bundleFingerprint!,
      actor: "operator-reviewer",
      expectedReviewHash: preview.reviewHash,
      verificationEvidenceIds,
    });

    const reusableState = JSON.stringify({
      nodes: database.prepare("SELECT * FROM memory_nodes").all(),
      versions: database.prepare("SELECT * FROM memory_versions").all(),
      edges: database.prepare("SELECT * FROM memory_edges").all(),
      profiles: database.prepare("SELECT * FROM operational_hazard_profiles").all(),
    });
    expect(reusableState).not.toContain("ReaperTwo");
    expect(reusableState).not.toContain("10.129.39.191");
    expect(reusableState).not.toContain("/root/htb/boxes");

    const privateSources = database.prepare(`
      SELECT source_type, source_id, evidence_id FROM memory_sources
      WHERE source_type = 'attack_knowledge_evidence_binding'
    `).all() as Array<{ source_type: string; source_id: string; evidence_id: string }>;
    expect(privateSources.some(({ evidence_id: evidenceId }) =>
      evidenceId === verificationEvidenceIds[0])).toBe(true);
    expect(JSON.stringify(privateSources.map(({ source_id: sourceId }) => sourceId)))
      .not.toContain("ReaperTwo");
    expect(JSON.stringify(privateSources.map(({ source_id: sourceId }) => sourceId)))
      .not.toContain("10.129.39.191");

    const secondBrain = new SecondBrainService(memory);
    const contextPack = secondBrain.retrieveAndPersistContext({
      query: "application execution worker hang health gate recovery",
      queryRedacted: "application execution worker hang health gate recovery",
      policy: {
        journey: "guided",
        allowGlobal: true,
        maximumSensitivity: "internal",
        allowedStatuses: ["verified"],
        contextBudget: 8_000,
        limit: nodes.size,
        graphDepth: 1,
        exactNodeIds: [...nodes.values()],
      },
      purpose: "Target-identity privacy regression",
      createdBy: "operator-reviewer",
    });
    const providerEnvelope = new BrainContextService({ database, secondBrain }).providerContext({
      hook: "planning",
      status: "ready",
      contextPack,
      items: contextPack.items.map((item) => ({
        node: memory.requireNode(item.nodeId),
        relevanceReason: item.relevanceReason,
      })),
      auditRecordId: "audit-target-identity-privacy",
    });
    expect(JSON.stringify(providerEnvelope)).not.toContain("ReaperTwo");
    expect(JSON.stringify(providerEnvelope)).not.toContain("10.129.39.191");

    const vault = new ObsidianVaultBridge(
      database,
      memory,
      new VaultPathPolicy(join(directories.at(-1)!, "vaults")),
      { clock: () => new Date(NOW) },
    );
    const connection = vault.connect({
      id: "vault-promotion-privacy",
      vaultPath: "Attack-Brain",
      displayName: "Attack Brain",
      permissionGranted: true,
    });
    const exported = vault.exportNode(connection.id, nodes.get("hazard")!);
    const note = readFileSync(join(connection.vaultPath, exported.relativePath), "utf8");
    expect(note).not.toContain("ReaperTwo");
    expect(note).not.toContain("10.129.39.191");
    expect(note).not.toContain(verificationEvidenceIds[0]);
  });
});

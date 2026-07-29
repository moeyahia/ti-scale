import { createHash } from "node:crypto";
import {
  createDatabaseConnection,
  inImmediateTransaction,
  type SqliteDatabase,
} from "../../../server/db";
import {
  AttackKnowledgeCompiler,
  type OperationalHazardKnowledge,
} from "../../../server/migration/AttackKnowledgeCompiler";
import { MemoryRepository } from "../../../server/memory/MemoryRepository";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2099-07-20T20:00:00.000Z";
const HMAC_KEY = "attack-knowledge-browser-fixture-hmac-key-32-bytes";

export interface AttackKnowledgePromotionFixture {
  readonly namespace: string;
  readonly bundleId: string;
  readonly bundleFingerprint: string;
  readonly blockedBundleId: string;
  readonly blockedBundleFingerprint: string;
  readonly evidenceIds: readonly [string, string];
  readonly candidateCount: number;
}

export interface AttackKnowledgePromotionSnapshot {
  readonly bundleStatus: string;
  readonly receiptCount: number;
  readonly promotionAuditCount: number;
  readonly verifiedNodeCount: number;
  readonly verifiedEdgeCount: number;
  readonly reusableText: string;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Attack Knowledge Promotion E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function bindApprovedHistoricalEvidencePath(
  database: SqliteDatabase,
  input: {
    readonly namespace: string;
    readonly missionId: string;
    readonly runId: string;
    readonly bundleId: string;
    readonly provenanceReceiptId: string;
    readonly sourceHash: string;
    readonly evidenceIds: readonly string[];
  },
): void {
  const jobId = `historical-hazard-job-akpromo-${input.namespace}`;
  database.prepare(`
    INSERT INTO historical_hazard_import_jobs (
      id, request_fingerprint, preview_hash, source_manifest_hash,
      private_label_hashes_json, mission_id, run_id, status, source_count,
      source_bytes, checkpoint_ordinal, protected_manifest_ref,
      protected_manifest_hash, approved_by, approved_at, created_at,
      updated_at, completed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'candidates_staged', ?, ?, ?,
      ?, ?, 'e2e-local-operator', ?, ?, ?, ?)
  `).run(
    jobId,
    digest(`request:${input.namespace}`),
    digest(`preview:${input.namespace}`),
    digest(`manifest:${input.namespace}`),
    JSON.stringify([digest(`private-label:${input.namespace}`)]),
    input.missionId,
    input.runId,
    input.evidenceIds.length,
    input.evidenceIds.length * 128,
    input.evidenceIds.length,
    `protected:historical-hazard-akpromo-manifest-${input.namespace}`,
    digest(`protected-manifest:${input.namespace}`),
    FIXTURE_TIME,
    FIXTURE_TIME,
    FIXTURE_TIME,
    FIXTURE_TIME,
  );
  input.evidenceIds.forEach((evidenceId, index) => {
    const evidence = database.prepare("SELECT content_hash FROM evidence WHERE id = ?")
      .get(evidenceId) as { readonly content_hash: string };
    const artifactId = `artifact-historical-hazard-akpromo-${input.namespace}-${index}`;
    const candidateId = `candidate-historical-hazard-akpromo-${input.namespace}-${index}`;
    database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, artifact_type, storage_uri, content_hash,
        byte_size, media_type, sensitivity, metadata_json, created_at, journey
      ) VALUES (?, ?, ?, 'historical_hazard_source', ?, ?, 128,
        'application/octet-stream', 'private', '{}', ?, 'guided')
    `).run(
      artifactId,
      input.missionId,
      input.runId,
      `protected:historical-hazard-akpromo-source-${input.namespace}-${index}`,
      evidence.content_hash,
      FIXTURE_TIME,
    );
    database.prepare(`
      INSERT INTO evidence_candidates (
        id, mission_id, run_id, artifact_id, evidence_type, label, meaning,
        promotion_reason, validation_requirements_json, state, sensitivity,
        proposed_by, reviewed_by, review_reason, promoted_evidence_id,
        created_at, reviewed_at
      ) VALUES (?, ?, ?, ?, 'finding_reproduction', 'Historical hazard source',
        'Independently reviewed source for the reusable hazard',
        'Operator approved the source and its canonical evidence', '[]',
        'promoted', 'private', 'historical-hazard-importer', 'e2e-local-operator',
        'Exact source review completed', ?, ?, ?)
    `).run(
      candidateId,
      input.missionId,
      input.runId,
      artifactId,
      evidenceId,
      FIXTURE_TIME,
      FIXTURE_TIME,
    );
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
      digest(`selection:${input.namespace}:${index}`),
      evidence.content_hash,
      FIXTURE_TIME,
      `protected:historical-hazard-akpromo-backup-${input.namespace}-${index}`,
      artifactId,
      candidateId,
      FIXTURE_TIME,
    );
  });
  database.prepare(`
    INSERT INTO historical_hazard_import_bundle_links (
      job_id, bundle_id, provenance_receipt_id, source_hash,
      binding_preview_hash, evidence_ids_json, actor_id, bound_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'e2e-local-operator', ?)
  `).run(
    jobId,
    input.bundleId,
    input.provenanceReceiptId,
    input.sourceHash,
    digest(`binding-preview:${input.namespace}`),
    JSON.stringify([...input.evidenceIds].sort()),
    FIXTURE_TIME,
  );
}

function hazard(token: string, variant: "ready" | "historical"): OperationalHazardKnowledge {
  const healthGate = [
    "Recycle the isolated execution worker",
    "Prove a fresh harmless scalar probe succeeds",
  ] as const;
  const retryValidConditions = [
    "The prior diagnostic process is absent",
    "The local execution queue is within its reviewed safe bound",
  ] as const;
  return {
    kind: "operational_hazard",
    product: { name: "Microsoft IIS", exactVersion: "10.0" },
    stack: [{ nodeType: "runtime", name: "Embedded expression engine", exactVersion: "1.0" }],
    procedure: {
      name: `${variant === "ready" ? "Bounded" : "Historical"} expression diagnostic ${token}`,
      version: "v3",
      orderedSteps: [
        "Run one harmless scalar execution probe",
        "Submit one bounded expression diagnostic",
        "Repeat the harmless scalar execution probe",
      ],
      normalizedParameters: { automaticRetries: 0, maximumDiagnosticStages: 1, healthProbeRequired: true },
      prerequisites: ["Base application page responds", "Expression execution health probe succeeds"],
    },
    hazard: {
      name: `Execution worker hang after ${variant} diagnostic ${token}`,
      observedSymptom: "The base page remains reachable while expression requests stop completing",
      affectedComponent: "Application expression execution worker",
      stateBefore: "Harmless scalar execution probe succeeds",
      stateAfter: "Expression execution requests time out while the base page remains available",
      unsafeRetryConditions: ["The harmless expression health probe does not return"],
      healthGate,
      retryValidConditions,
      recoveryActionSummary: "Recycle the application pool and pass the harmless execution health probe",
      recoveryCost: {
        exactProcedureResetCount: 2,
        operatorReportedResetCountMinimum: 11,
        serviceRecycleCount: 2,
      },
      saferAlternative: {
        name: "Single-stage expression validation",
        orderedSteps: ["Restore a healthy execution worker", "Run one lower-risk diagnostic stage"],
        reviewedBinding: {
          version: "v4-reviewed",
          normalizedParameters: {
            automaticRetries: 0,
            maximumDiagnosticStages: 1,
            healthProbeRequired: true,
          },
          sourceLoad: 1,
          sourceConcurrency: 1,
          sourceTimingWindowMs: 120_000,
          load: 1,
          concurrency: 1,
          timingWindowMs: 30_000,
        },
        retryConditionEvidence: [...healthGate, ...retryValidConditions].map((statement, index) => ({
          statement,
          evidenceKey: `reviewed_retry_condition_${index + 1}`,
        })),
      },
      concurrencyMinimum: 1,
      timingWindowMs: 120_000,
    },
    corroboration: {
      exactProcedureAttemptCount: 3,
      exactProcedureReproducibilityCount: 2,
      exactProcedureEvidenceCount: 2,
    },
  };
}

export function createAttackKnowledgePromotionFixture(instanceId: string): AttackKnowledgePromotionFixture {
  const namespace = normalizeFixtureNamespace(instanceId);
  const token = `akpromo${digest(namespace).slice(0, 10)}`;
  const missionId = `mission-akpromo-${namespace}`;
  const runId = `run-akpromo-${namespace}`;
  const evidenceIds = [
    `evidence-akpromo-private-10.129.39.191-reset-${namespace}`,
    `evidence-akpromo-private-health-${namespace}`,
  ] as const;
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });
  try {
    inImmediateTransaction(database, () => {
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          memory_policy_json, created_by, created_at, updated_at, control_plane
        ) VALUES (?, 'Private promotion browser fixture',
          'Review generalized attack knowledge through canonical evidence',
          'guided', 'completed', 'verified', '{}', 'e2e-local-operator', ?, ?, 'ti_scale')
      `).run(missionId, FIXTURE_TIME, FIXTURE_TIME);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason,
          budget_json, budget_usage_json, created_at, updated_at, version, control_plane
        ) VALUES (?, ?, 'guided', 'completed', 1, 'Promotion review fixture ready',
          '{}', '{}', ?, ?, 1, 'ti_scale')
      `).run(runId, missionId, FIXTURE_TIME, FIXTURE_TIME);
      for (const [index, evidenceId] of evidenceIds.entries()) {
        database.prepare(`
          INSERT INTO evidence (
            id, mission_id, run_id, source, acquired_at, target, evidence_type,
            content_hash, provenance_json, confidence, sensitivity,
            verification_state, summary, created_by, created_at
          ) VALUES (?, ?, ?, 'trusted-local-evaluator', ?, 'private-target-redacted',
            'finding_reproduction', ?, '{"method":"local_evaluator"}', 1,
            'private', 'verified', 'Private canonical reproduction evidence',
            'local-evidence-verifier', ?)
        `).run(evidenceId, missionId, runId, FIXTURE_TIME, String(index + 3).repeat(64), FIXTURE_TIME);
        database.prepare(`
          INSERT INTO evidence_chain_events (
            id, evidence_id, event_type, actor, details_json, occurred_at
          ) VALUES (?, ?, 'verified', 'local-evidence-verifier', '{}', ?)
        `).run(`custody-akpromo-${namespace}-${index}`, evidenceId, FIXTURE_TIME);
      }
    });

    const compiler = new AttackKnowledgeCompiler(database, {
      receiptHmacKey: HMAC_KEY,
      clock: () => new Date(FIXTURE_TIME),
    });
    const readySourceHash = digest(`ready:${namespace}`);
    const ready = compiler.compile({
      source: {
        privateSourceReference: `/private/engagements/ReaperTwo/${namespace}/10.129.39.191.md`,
        privateLabels: ["ReaperTwo", "10.129.39.191"],
        sourceClass: "historical",
        sourceHash: readySourceHash,
        observedAt: FIXTURE_TIME,
        evidenceCount: 8,
        canonicalEvidenceIds: evidenceIds,
      },
      knowledge: hazard(token, "ready"),
      confidence: 0.96,
    });
    const blocked = compiler.compile({
      source: {
        privateSourceReference: `/private/engagements/ReaperTwo/${namespace}/historical.md`,
        privateLabels: ["ReaperTwo", "10.129.39.191"],
        sourceClass: "historical",
        sourceHash: digest(`blocked:${namespace}`),
        observedAt: FIXTURE_TIME,
        evidenceCount: 8,
      },
      knowledge: hazard(token, "historical"),
      confidence: 0.91,
    });
    if (!ready.bundleId || !ready.bundleFingerprint || !blocked.bundleId || !blocked.bundleFingerprint) {
      throw new Error("Attack Knowledge Promotion browser fixture did not stage both bundles");
    }
    if (!ready.provenanceReceiptId) {
      throw new Error("Attack Knowledge Promotion browser fixture did not stage historical provenance");
    }
    bindApprovedHistoricalEvidencePath(database, {
      namespace,
      missionId,
      runId,
      bundleId: ready.bundleId,
      provenanceReceiptId: ready.provenanceReceiptId,
      sourceHash: readySourceHash,
      evidenceIds,
    });
    const memory = new MemoryRepository(database, { clock: () => new Date(FIXTURE_TIME) });
    const candidates = database.prepare(`
      SELECT registry.candidate_id AS candidateId
      FROM attack_knowledge_bundle_candidates linked
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = linked.content_fingerprint
      WHERE linked.bundle_id = ? ORDER BY linked.ordinal
    `).all(ready.bundleId) as Array<{ candidateId: string }>;
    for (const { candidateId } of candidates) {
      const candidate = memory.requireCandidate(candidateId);
      if (candidate.status === "pending") memory.confirmCandidate(candidateId, "e2e-local-operator", {});
    }
    return {
      namespace,
      bundleId: ready.bundleId,
      bundleFingerprint: ready.bundleFingerprint,
      blockedBundleId: blocked.bundleId,
      blockedBundleFingerprint: blocked.bundleFingerprint,
      evidenceIds,
      candidateCount: candidates.length,
    };
  } finally {
    database.close();
  }
}

export function readAttackKnowledgePromotionSnapshot(
  fixture: AttackKnowledgePromotionFixture,
): AttackKnowledgePromotionSnapshot {
  const database = createDatabaseConnection({
    filename: databasePath(),
    fileMustExist: true,
    readonly: true,
    busyTimeoutMs: 120_000,
  });
  try {
    const scalar = (sql: string, ...parameters: readonly unknown[]): number => Number(
      (database.prepare(sql).get(...parameters) as { count: number }).count,
    );
    return {
      bundleStatus: (database.prepare("SELECT status FROM attack_knowledge_bundles WHERE id = ?")
        .get(fixture.bundleId) as { status: string }).status,
      receiptCount: scalar("SELECT COUNT(*) AS count FROM attack_knowledge_promotion_receipts WHERE bundle_id = ?", fixture.bundleId),
      promotionAuditCount: scalar("SELECT COUNT(*) AS count FROM audit_records WHERE resource_id = ? AND action = 'attack_knowledge.promoted'", fixture.bundleId),
      verifiedNodeCount: scalar(`
        SELECT COUNT(*) AS count
        FROM attack_knowledge_bundle_candidates linked
        JOIN attack_knowledge_candidate_registry registry ON registry.content_fingerprint = linked.content_fingerprint
        JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
        JOIN memory_nodes node ON node.id = candidate.proposed_node_id
        WHERE linked.bundle_id = ? AND node.lifecycle_status = 'verified'
      `, fixture.bundleId),
      verifiedEdgeCount: scalar("SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges WHERE bundle_id = ? AND materialized_edge_id IS NOT NULL", fixture.bundleId),
      reusableText: JSON.stringify({
        nodes: database.prepare(`
          SELECT node.title, node.summary, node.body
          FROM attack_knowledge_bundle_candidates linked
          JOIN attack_knowledge_candidate_registry registry ON registry.content_fingerprint = linked.content_fingerprint
          JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
          JOIN memory_nodes node ON node.id = candidate.proposed_node_id
          WHERE linked.bundle_id = ?
        `).all(fixture.bundleId),
        edges: database.prepare(`
          SELECT edge.title, edge.summary, edge.explanation
          FROM attack_knowledge_bundle_edges linked
          JOIN memory_edges edge ON edge.id = linked.materialized_edge_id
          WHERE linked.bundle_id = ?
        `).all(fixture.bundleId),
      }),
    };
  } finally {
    database.close();
  }
}

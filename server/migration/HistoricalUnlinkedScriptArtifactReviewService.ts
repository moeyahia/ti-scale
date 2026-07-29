import { createHash, randomUUID } from "node:crypto";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import {
  assertReusableMemoryText,
  MemoryRepository,
  REUSABLE_MEMORY_LIMITS,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";

const POLICY_VERSION = "historical-unlinked-script-artifact-review-v1" as const;
const SCHEMA_VERSION = "ti_scale.historical_unlinked_script_artifact_review/v1" as const;
const DEFAULT_PAGE_SIZE = 250;
const MAXIMUM_PAGE_SIZE = 1_000;
const SHA256 = /^[a-f0-9]{64}$/u;
const ACTOR = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const AGGREGATE_ACTION = "historical_attack_knowledge.unlinked_script_artifacts_staled";

const ELIGIBILITY_CTES = String.raw`
WITH base AS (
  SELECT registry.content_fingerprint, candidate.id AS candidate_id,
    node.id AS node_id, node.version AS node_version, node.pinned
  FROM attack_knowledge_candidate_registry registry
  JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
  JOIN memory_nodes node ON node.id = candidate.proposed_node_id
  WHERE registry.node_type = 'script_artifact'
    AND candidate.candidate_type = 'script_artifact'
    AND candidate.proposed_by = 'attack-knowledge-compiler'
    AND candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
    AND node.node_type = 'script_artifact'
    AND node.scope = 'global'
    AND node.engagement_id IS NULL
    AND node.mission_id IS NULL
    AND node.lifecycle_status = 'confirmed'
    AND node.confirmation_state = 'confirmed'
),
appearance AS (
  SELECT base.content_fingerprint,
    COUNT(DISTINCT linked.bundle_id) AS bundle_count,
    COUNT(DISTINCT CASE WHEN edge.edge_key IS NOT NULL
      THEN linked.bundle_id || char(0) || edge.edge_key END) AS incident_edge_count,
    COUNT(DISTINCT CASE WHEN bundle.status = 'materialized'
      THEN bundle.id END) AS materialized_bundle_count,
    COUNT(DISTINCT CASE WHEN source.bundle_id IS NOT NULL
      THEN linked.bundle_id END) AS sourced_bundle_count,
    COUNT(DISTINCT evidence.evidence_id) AS canonical_evidence_count
  FROM base
  JOIN attack_knowledge_bundle_candidates linked
    ON linked.content_fingerprint = base.content_fingerprint
  JOIN attack_knowledge_bundles bundle ON bundle.id = linked.bundle_id
  LEFT JOIN attack_knowledge_bundle_edges edge
    ON edge.bundle_id = linked.bundle_id
   AND (edge.source_role = linked.role OR edge.target_role = linked.role)
  LEFT JOIN historical_attack_knowledge_bundle_sources source
    ON source.bundle_id = linked.bundle_id
  LEFT JOIN attack_knowledge_bundle_evidence_bindings evidence
    ON evidence.bundle_id = linked.bundle_id
  GROUP BY base.content_fingerprint
),
origins AS (
  SELECT DISTINCT base.content_fingerprint, source.source_hash,
    occurrence.migration_id,
    CASE WHEN migration.status = 'completed'
      AND migration.source_retention = 'verified-reference'
      AND migration.brain_projection_mode = 'attack-knowledge-only'
      AND inventory.migration_id IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM legacy_migration_source_objects object
        WHERE object.migration_id = occurrence.migration_id
          AND object.source_reference = occurrence.source_reference
          AND object.source_sha256 = occurrence.source_hash
          AND object.verification_status = 'verified_reference'
          AND object.object_kind IN ('accepted', 'source')
      ) THEN 1 ELSE 0 END AS completed_covered,
    CASE WHEN migration.status = 'running' THEN 1 ELSE 0 END AS active
  FROM base
  JOIN attack_knowledge_bundle_candidates linked
    ON linked.content_fingerprint = base.content_fingerprint
  JOIN historical_attack_knowledge_bundle_sources source
    ON source.bundle_id = linked.bundle_id
  JOIN historical_attack_knowledge_source_occurrences occurrence
    ON occurrence.candidate_id = source.candidate_id
   AND occurrence.source_hash = source.source_hash
  LEFT JOIN legacy_migration_runs migration ON migration.id = occurrence.migration_id
  LEFT JOIN legacy_migration_inventory_receipts inventory
    ON inventory.migration_id = migration.id
),
coverage AS (
  SELECT content_fingerprint,
    COUNT(DISTINCT source_hash) AS source_hash_count,
    COUNT(DISTINCT CASE WHEN completed_covered = 1
      THEN source_hash END) AS covered_source_hash_count,
    MAX(active) AS has_active_origin,
    COUNT(DISTINCT CASE WHEN completed_covered = 1
      THEN migration_id END) AS completed_migration_count
  FROM origins
  GROUP BY content_fingerprint
),
eligible AS (
  SELECT base.content_fingerprint, base.candidate_id, base.node_id,
    base.node_version, appearance.bundle_count, coverage.source_hash_count,
    coverage.completed_migration_count
  FROM base
  JOIN appearance USING (content_fingerprint)
  JOIN coverage USING (content_fingerprint)
  WHERE base.pinned = 0
    AND appearance.incident_edge_count = 0
    AND appearance.materialized_bundle_count = 0
    AND appearance.canonical_evidence_count = 0
    AND appearance.sourced_bundle_count = appearance.bundle_count
    AND coverage.source_hash_count > 0
    AND coverage.covered_source_hash_count = coverage.source_hash_count
    AND coverage.has_active_origin = 0
    AND coverage.completed_migration_count > 0
    AND NOT EXISTS (
      SELECT 1 FROM memory_edges edge
      WHERE (edge.source_node_id = base.node_id OR edge.target_node_id = base.node_id)
        AND edge.lifecycle_status IN ('confirmed', 'verified')
    )
    AND NOT EXISTS (
      SELECT 1 FROM memory_context_items item WHERE item.node_id = base.node_id
    )
    AND NOT EXISTS (
      SELECT 1 FROM reusable_knowledge_outcome_links outcome
      WHERE outcome.memory_node_id = base.node_id
    )
)
`;

interface EligibleRow {
  readonly content_fingerprint: string;
  readonly candidate_id: string;
  readonly node_id: string;
  readonly node_version: number;
  readonly bundle_count: number;
  readonly source_hash_count: number;
  readonly completed_migration_count: number;
}

interface CustodyRow {
  readonly content_fingerprint: string;
  readonly semantic_fingerprint: string;
  readonly receipt_id: string;
  readonly source_hash: string;
  readonly binding_hash: string;
  readonly migration_id: string;
  readonly source_reference: string;
  readonly migration_status: string | null;
  readonly inventory_receipt_hash: string | null;
}

interface ReplayRow {
  readonly id: string;
  readonly details_json: string;
}

interface HashRow {
  readonly record_hash: string;
}

export interface HistoricalUnlinkedScriptReviewInput {
  readonly actorId: string;
  readonly reason: string;
  readonly afterContentFingerprint?: string;
  readonly maxCandidates?: number;
}

export interface HistoricalUnlinkedScriptReviewExecuteInput
  extends HistoricalUnlinkedScriptReviewInput {
  readonly expectedPreviewHash: string;
  readonly acknowledgeMarkConfirmedUnlinkedScriptsStale: true;
}

export interface HistoricalUnlinkedScriptReviewFence {
  readonly assertActiveInCurrentTransaction: () => unknown;
}

export interface HistoricalUnlinkedScriptReviewItem {
  readonly candidateId: string;
  readonly nodeId: string;
  readonly nodeVersion: number;
  readonly contentFingerprint: string;
  readonly bundleCount: number;
  readonly sourceHashCount: number;
  readonly completedMigrationCount: number;
  readonly sourceOccurrenceCount: number;
  readonly failedMigrationCount: number;
  readonly bundleSetHash: string;
  /** Hash-binds private source references and hashes without returning them. */
  readonly custodySetHash: string;
  readonly decision: "mark_stale_parser_rejected_noise";
  readonly reasonCategories: readonly [
    "no_typed_reusable_relationship",
    "unlinked_global_script_artifact",
    "unverified_staged_bundle_only",
    "completed_receipt_backed_source_custody",
  ];
}

export interface HistoricalUnlinkedCveReviewSummary {
  readonly unlinkedConfirmedCount: number;
  readonly nodeSetHash: string;
  readonly decision: "retain_for_cve_applicability_review";
  readonly automaticallyChanged: false;
}

export interface HistoricalUnlinkedScriptReviewPreview {
  readonly schemaVersion: typeof SCHEMA_VERSION;
  readonly policyVersion: typeof POLICY_VERSION;
  readonly mode: "dry_run";
  readonly previewHash: string;
  readonly actorId: string;
  readonly selection: {
    readonly afterContentFingerprint: string | null;
    readonly maxCandidates: number;
  };
  readonly selectedCount: number;
  readonly candidateSetHash: string;
  readonly custodySetHash: string;
  readonly candidates: readonly HistoricalUnlinkedScriptReviewItem[];
  readonly unlinkedCves: HistoricalUnlinkedCveReviewSummary;
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
  readonly safeguards: {
    readonly sourceContentRead: false;
    readonly privateSourceReferencesDisclosed: false;
    readonly graphRelationshipsFabricated: false;
    readonly immutableEvidenceDeleted: false;
    readonly verifiedMemoryChanged: false;
    readonly lessonsPromoted: false;
  };
}

export interface HistoricalUnlinkedScriptReviewReceipt {
  readonly schemaVersion: typeof SCHEMA_VERSION;
  readonly policyVersion: typeof POLICY_VERSION;
  readonly previewHash: string;
  readonly actorId: string;
  readonly auditRecordId: string;
  readonly selectedCount: number;
  readonly staleCount: number;
  readonly candidateSetHash: string;
  readonly custodySetHash: string;
  readonly decision: "mark_stale_parser_rejected_noise";
  readonly unlinkedCveCountReported: number;
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
  readonly occurredAt: string;
  readonly receiptHash: string;
}

export interface HistoricalUnlinkedScriptReviewResult {
  readonly status: "completed" | "replayed";
  readonly receipt: HistoricalUnlinkedScriptReviewReceipt;
}

export interface HistoricalUnlinkedScriptReconciliation {
  readonly schemaVersion: "ti_scale.historical_unlinked_script_artifact_reconciliation/v1";
  readonly policyVersion: typeof POLICY_VERSION;
  readonly activeUnlinkedConfirmedScriptArtifactCount: number;
  readonly eligibleStaleReviewCount: number;
  readonly staleReviewedScriptArtifactCount: number;
  readonly protectedUnlinkedVerifiedScriptArtifactCount: number;
  readonly unlinkedCveApplicabilityReview: HistoricalUnlinkedCveReviewSummary;
  readonly interpretation: {
    readonly unlinkedScriptsAreNotAttackAttempts: true;
    readonly reportedOutcomesRemainUnverified: true;
    readonly cvesRequireTechnologyVersionApplicability: true;
  };
}

export class HistoricalUnlinkedScriptReviewError extends Error {
  constructor(
    readonly code:
      | "invalid_request"
      | "schema_unavailable"
      | "empty_page"
      | "stale_preview"
      | "node_integrity_failed"
      | "audit_integrity_failed",
    message: string,
  ) {
    super(message);
    this.name = "HistoricalUnlinkedScriptReviewError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function placeholders(count: number): string {
  return Array.from({ length: count }, () => "?").join(", ");
}

function normalizeInput(input: HistoricalUnlinkedScriptReviewInput): Required<HistoricalUnlinkedScriptReviewInput> {
  const actorId = input.actorId.trim().normalize("NFKC");
  if (!ACTOR.test(actorId)) {
    throw new HistoricalUnlinkedScriptReviewError("invalid_request", "A bounded operator actor ID is required");
  }
  const reason = input.reason.trim().normalize("NFKC");
  if (!reason || Buffer.byteLength(reason, "utf8") > 1_200) {
    throw new HistoricalUnlinkedScriptReviewError("invalid_request", "A concise review reason is required");
  }
  assertReusableMemoryText([{
    field: "historicalUnlinkedScriptReview.reason",
    value: reason,
    maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceExplanation,
  }]);
  const afterContentFingerprint = input.afterContentFingerprint?.trim().toLowerCase() ?? "";
  if (afterContentFingerprint && !SHA256.test(afterContentFingerprint)) {
    throw new HistoricalUnlinkedScriptReviewError("invalid_request", "The page cursor must be a lowercase SHA-256 fingerprint");
  }
  const maxCandidates = input.maxCandidates ?? DEFAULT_PAGE_SIZE;
  if (!Number.isSafeInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > MAXIMUM_PAGE_SIZE) {
    throw new HistoricalUnlinkedScriptReviewError(
      "invalid_request",
      `maxCandidates must be between 1 and ${MAXIMUM_PAGE_SIZE}`,
    );
  }
  return { actorId, reason, afterContentFingerprint, maxCandidates };
}

function receiptHash(receipt: Omit<HistoricalUnlinkedScriptReviewReceipt, "receiptHash">): string {
  return sha256(canonicalJson(receipt));
}

function parseReplay(row: ReplayRow, expectedPreviewHash: string): HistoricalUnlinkedScriptReviewResult {
  let parsed: unknown;
  try { parsed = JSON.parse(row.details_json) as unknown; }
  catch {
    throw new HistoricalUnlinkedScriptReviewError("audit_integrity_failed", "The prior review audit is not valid JSON");
  }
  const receipt = parsed && typeof parsed === "object" && !Array.isArray(parsed)
    ? (parsed as { receipt?: unknown }).receipt
    : undefined;
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    throw new HistoricalUnlinkedScriptReviewError("audit_integrity_failed", "The prior review audit has no receipt");
  }
  const value = receipt as HistoricalUnlinkedScriptReviewReceipt;
  const { receiptHash: recordedHash, ...unsigned } = value;
  if (
    value.auditRecordId !== row.id
    || value.previewHash !== expectedPreviewHash
    || !SHA256.test(recordedHash)
    || receiptHash(unsigned) !== recordedHash
  ) {
    throw new HistoricalUnlinkedScriptReviewError("audit_integrity_failed", "The prior review receipt failed integrity verification");
  }
  return { status: "replayed", receipt: value };
}

/**
 * Review gate for an exact legacy-parser residual: a confirmed global script
 * artifact that has no typed relationship in any source bundle and no active
 * graph, Context Pack, evidence, outcome, or promotion use.
 *
 * Execution marks the node stale; it does not erase source evidence, rewrite
 * the candidate, infer a relationship, or turn historical prose into a
 * successful/failed AttackAttempt. A future typed observation can therefore
 * be reviewed explicitly without losing the immutable source history.
 */
export class HistoricalUnlinkedScriptArtifactReviewService {
  readonly #memory: MemoryRepository;
  readonly #clock: () => Date;
  readonly #createId: (prefix: string) => string;

  constructor(
    readonly database: SqliteDatabase,
    options: {
      readonly clock?: () => Date;
      readonly createId?: (prefix: string) => string;
    } = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? ((prefix) => `${prefix}_${randomUUID()}`);
    this.#memory = new MemoryRepository(database, {
      clock: this.#clock,
      createId: this.#createId,
    });
  }

  preview(input: HistoricalUnlinkedScriptReviewInput): HistoricalUnlinkedScriptReviewPreview {
    this.#assertSchema();
    const normalized = normalizeInput(input);
    const rows = this.#eligibleRows(
      normalized.afterContentFingerprint,
      normalized.maxCandidates + 1,
    );
    const hasMore = rows.length > normalized.maxCandidates;
    const selected = rows.slice(0, normalized.maxCandidates);
    const custody = this.#custody(selected.map(({ content_fingerprint }) => content_fingerprint));
    const custodyByFingerprint = new Map<string, CustodyRow[]>();
    for (const row of custody) {
      const list = custodyByFingerprint.get(row.content_fingerprint) ?? [];
      list.push(row);
      custodyByFingerprint.set(row.content_fingerprint, list);
    }
    const candidates = selected.map((row): HistoricalUnlinkedScriptReviewItem => {
      const originRows = custodyByFingerprint.get(row.content_fingerprint) ?? [];
      if (originRows.length === 0) {
        throw new HistoricalUnlinkedScriptReviewError(
          "node_integrity_failed",
          "An eligible script artifact lost its source-custody rows",
        );
      }
      const bundleFingerprints = [...new Set(originRows.map(({ semantic_fingerprint }) => semantic_fingerprint))].sort();
      const completedMigrations = new Set(originRows
        .filter(({ migration_status }) => migration_status === "completed")
        .map(({ migration_id }) => migration_id));
      const failedMigrations = new Set(originRows
        .filter(({ migration_status }) => migration_status === "failed")
        .map(({ migration_id }) => migration_id));
      if (
        bundleFingerprints.length !== Number(row.bundle_count)
        || completedMigrations.size < Number(row.completed_migration_count)
      ) {
        throw new HistoricalUnlinkedScriptReviewError(
          "node_integrity_failed",
          "An eligible script artifact changed while source custody was assembled",
        );
      }
      const custodySetHash = sha256(canonicalJson(originRows));
      return Object.freeze({
        candidateId: row.candidate_id,
        nodeId: row.node_id,
        nodeVersion: Number(row.node_version),
        contentFingerprint: row.content_fingerprint,
        bundleCount: Number(row.bundle_count),
        sourceHashCount: Number(row.source_hash_count),
        completedMigrationCount: completedMigrations.size,
        sourceOccurrenceCount: new Set(originRows.map((item) => canonicalJson([
          item.migration_id,
          item.source_reference,
        ]))).size,
        failedMigrationCount: failedMigrations.size,
        bundleSetHash: sha256(canonicalJson(bundleFingerprints)),
        custodySetHash,
        decision: "mark_stale_parser_rejected_noise" as const,
        reasonCategories: [
          "no_typed_reusable_relationship",
          "unlinked_global_script_artifact",
          "unverified_staged_bundle_only",
          "completed_receipt_backed_source_custody",
        ] as const,
      });
    });
    const unlinkedCves = this.#unlinkedCves();
    const candidateSetHash = sha256(canonicalJson(candidates.map((candidate) => ({
      candidateId: candidate.candidateId,
      nodeId: candidate.nodeId,
      nodeVersion: candidate.nodeVersion,
      contentFingerprint: candidate.contentFingerprint,
      bundleSetHash: candidate.bundleSetHash,
      custodySetHash: candidate.custodySetHash,
    }))));
    const custodySetHash = sha256(canonicalJson(candidates.map((candidate) => candidate.custodySetHash)));
    const review = {
      schemaVersion: SCHEMA_VERSION,
      policyVersion: POLICY_VERSION,
      actorId: normalized.actorId,
      reason: normalized.reason,
      selection: {
        afterContentFingerprint: normalized.afterContentFingerprint || null,
        maxCandidates: normalized.maxCandidates,
      },
      candidateSetHash,
      custodySetHash,
      candidates,
      unlinkedCves,
      hasMore,
      nextSelectionCursor: candidates.at(-1)?.contentFingerprint ?? null,
    } as const;
    return Object.freeze({
      schemaVersion: SCHEMA_VERSION,
      policyVersion: POLICY_VERSION,
      mode: "dry_run" as const,
      previewHash: sha256(canonicalJson(review)),
      actorId: normalized.actorId,
      selection: review.selection,
      selectedCount: candidates.length,
      candidateSetHash,
      custodySetHash,
      candidates: Object.freeze(candidates),
      unlinkedCves,
      hasMore,
      nextSelectionCursor: review.nextSelectionCursor,
      safeguards: Object.freeze({
        sourceContentRead: false as const,
        privateSourceReferencesDisclosed: false as const,
        graphRelationshipsFabricated: false as const,
        immutableEvidenceDeleted: false as const,
        verifiedMemoryChanged: false as const,
        lessonsPromoted: false as const,
      }),
    });
  }

  execute(
    input: HistoricalUnlinkedScriptReviewExecuteInput,
    fence: HistoricalUnlinkedScriptReviewFence,
  ): HistoricalUnlinkedScriptReviewResult {
    if (
      input.acknowledgeMarkConfirmedUnlinkedScriptsStale !== true
      || !SHA256.test(input.expectedPreviewHash)
    ) {
      throw new HistoricalUnlinkedScriptReviewError(
        "invalid_request",
        "Execution requires the exact preview hash and explicit stale-review acknowledgement",
      );
    }
    const normalized = normalizeInput(input);
    return inImmediateTransaction(this.database, () => {
      fence.assertActiveInCurrentTransaction();
      const resourceId = `historical_unlinked_script_review_${input.expectedPreviewHash}`;
      const replay = this.database.prepare(`
        SELECT id, details_json FROM audit_records
        WHERE action = ?
          AND resource_type = 'historical_unlinked_script_artifact_review'
          AND resource_id = ? AND actor_type = 'operator' AND actor_id = ?
        ORDER BY rowid LIMIT 1
      `).get(AGGREGATE_ACTION, resourceId, normalized.actorId) as ReplayRow | undefined;
      if (replay) return parseReplay(replay, input.expectedPreviewHash);

      const preview = this.preview(normalized);
      if (preview.selectedCount === 0) {
        throw new HistoricalUnlinkedScriptReviewError("empty_page", "This unlinked-script review page is empty");
      }
      if (preview.previewHash !== input.expectedPreviewHash) {
        throw new HistoricalUnlinkedScriptReviewError(
          "stale_preview",
          "The candidate graph or private source custody changed after preview",
        );
      }

      let staleCount = 0;
      const occurredAt = this.#clock().toISOString();
      for (const reviewed of preview.candidates) {
        const node = this.#memory.requireNode(reviewed.nodeId);
        const candidate = this.#memory.requireCandidate(reviewed.candidateId);
        if (
          node.version !== reviewed.nodeVersion
          || node.nodeType !== "script_artifact"
          || node.lifecycleStatus !== "confirmed"
          || node.confirmationState !== "confirmed"
          || node.scope.kind !== "global"
          || node.pinned
          || candidate.proposedNodeId !== node.id
          || candidate.nodeType !== "script_artifact"
          || !["confirmed", "edited_confirmed", "merged"].includes(candidate.status)
        ) {
          throw new HistoricalUnlinkedScriptReviewError(
            "node_integrity_failed",
            "A reviewed script artifact changed before execution",
          );
        }
        this.#memory.correctNode(node.id, {
          lifecycleStatus: "stale",
          confirmationState: "confirmed",
          additionalProvenanceSources: [{
            sourceType: "historical_unlinked_script_review",
            sourceId: `husr_${reviewed.contentFingerprint.slice(0, 48)}`,
            sourceHash: reviewed.custodySetHash,
            acquiredAt: occurredAt,
          }],
          provenanceExplanation: "Operator review marked this confirmed historical script artifact stale because every source bundle lacked a typed reusable relationship. Immutable private source custody remains available for audit and later reconsideration.",
          authorType: "operator",
          authorId: normalized.actorId,
          changeReason: `Unlinked historical script review ${input.expectedPreviewHash}: ${normalized.reason}`,
        });
        staleCount += 1;
      }

      const auditRecordId = this.#createId("audit");
      const unsignedReceipt = {
        schemaVersion: SCHEMA_VERSION,
        policyVersion: POLICY_VERSION,
        previewHash: preview.previewHash,
        actorId: normalized.actorId,
        auditRecordId,
        selectedCount: preview.selectedCount,
        staleCount,
        candidateSetHash: preview.candidateSetHash,
        custodySetHash: preview.custodySetHash,
        decision: "mark_stale_parser_rejected_noise" as const,
        unlinkedCveCountReported: preview.unlinkedCves.unlinkedConfirmedCount,
        hasMore: preview.hasMore,
        nextSelectionCursor: preview.nextSelectionCursor,
        occurredAt,
      };
      const receipt: HistoricalUnlinkedScriptReviewReceipt = {
        ...unsignedReceipt,
        receiptHash: receiptHash(unsignedReceipt),
      };
      const previous = this.database.prepare(
        "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
      ).get() as HashRow | undefined;
      const details = {
        schemaVersion: SCHEMA_VERSION,
        policyVersion: POLICY_VERSION,
        receipt,
        verificationState: "stale_review_only",
        privateSourceReferencesDisclosed: false,
        immutableEvidenceDeleted: false,
        graphRelationshipsFabricated: false,
        verifiedMemoryChanged: false,
        cvesAutomaticallyChanged: false,
      } as const;
      const recordHash = sha256(canonicalJson({
        id: auditRecordId,
        actor: normalized.actorId,
        action: AGGREGATE_ACTION,
        resourceType: "historical_unlinked_script_artifact_review",
        resourceId,
        reason: normalized.reason,
        details,
        missionId: null,
        runId: null,
        journey: null,
        previousHash: previous?.record_hash ?? null,
        occurredAt,
      }));
      this.database.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, journey, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json, previous_hash,
          record_hash, occurred_at
        ) VALUES (?, NULL, NULL, NULL, 'operator', ?, ?,
          'historical_unlinked_script_artifact_review', ?, ?, ?, ?, ?, ?)
      `).run(
        auditRecordId,
        normalized.actorId,
        AGGREGATE_ACTION,
        resourceId,
        normalized.reason,
        canonicalJson(details),
        previous?.record_hash ?? null,
        recordHash,
        occurredAt,
      );
      fence.assertActiveInCurrentTransaction();
      return { status: "completed", receipt };
    });
  }

  reconcile(): HistoricalUnlinkedScriptReconciliation {
    this.#assertSchema();
    const eligible = Number((this.database.prepare(`${ELIGIBILITY_CTES}
      SELECT COUNT(*) AS count FROM eligible
    `).get() as { readonly count: number }).count);
    const activeConfirmed = Number((this.database.prepare(`
      SELECT COUNT(DISTINCT node.id) AS count
      FROM attack_knowledge_candidate_registry registry
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      JOIN memory_nodes node ON node.id = candidate.proposed_node_id
      WHERE node.node_type = 'script_artifact'
        AND candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.lifecycle_status = 'confirmed' AND node.confirmation_state = 'confirmed'
        AND NOT EXISTS (
          SELECT 1 FROM memory_edges_safe edge
          WHERE edge.source_node_id = node.id OR edge.target_node_id = node.id
        )
    `).get() as { readonly count: number }).count);
    const verified = Number((this.database.prepare(`
      SELECT COUNT(DISTINCT node.id) AS count
      FROM attack_knowledge_candidate_registry registry
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      JOIN memory_nodes node ON node.id = candidate.proposed_node_id
      WHERE node.node_type = 'script_artifact'
        AND candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.lifecycle_status = 'verified' AND node.confirmation_state = 'confirmed'
        AND NOT EXISTS (
          SELECT 1 FROM memory_edges_safe edge
          WHERE edge.source_node_id = node.id OR edge.target_node_id = node.id
        )
    `).get() as { readonly count: number }).count);
    const staleReviewed = Number((this.database.prepare(`
      SELECT COUNT(DISTINCT node.id) AS count
      FROM memory_nodes node
      JOIN memory_sources source ON source.node_id = node.id
      WHERE node.node_type = 'script_artifact'
        AND node.lifecycle_status = 'stale'
        AND source.source_type = 'historical_unlinked_script_review'
    `).get() as { readonly count: number }).count);
    return Object.freeze({
      schemaVersion: "ti_scale.historical_unlinked_script_artifact_reconciliation/v1" as const,
      policyVersion: POLICY_VERSION,
      activeUnlinkedConfirmedScriptArtifactCount: activeConfirmed,
      eligibleStaleReviewCount: eligible,
      staleReviewedScriptArtifactCount: staleReviewed,
      protectedUnlinkedVerifiedScriptArtifactCount: verified,
      unlinkedCveApplicabilityReview: this.#unlinkedCves(),
      interpretation: Object.freeze({
        unlinkedScriptsAreNotAttackAttempts: true as const,
        reportedOutcomesRemainUnverified: true as const,
        cvesRequireTechnologyVersionApplicability: true as const,
      }),
    });
  }

  #eligibleRows(after: string, limit: number): EligibleRow[] {
    return this.database.prepare(`${ELIGIBILITY_CTES}
      SELECT content_fingerprint, candidate_id, node_id, node_version,
        bundle_count, source_hash_count, completed_migration_count
      FROM eligible
      WHERE content_fingerprint > ?
      ORDER BY content_fingerprint
      LIMIT ?
    `).all(after, limit) as EligibleRow[];
  }

  #custody(fingerprints: readonly string[]): CustodyRow[] {
    if (fingerprints.length === 0) return [];
    return this.database.prepare(`
      SELECT DISTINCT linked.content_fingerprint,
        bundle.semantic_fingerprint, source.receipt_id, source.source_hash,
        source.binding_hash, occurrence.migration_id,
        occurrence.source_reference, migration.status AS migration_status,
        inventory.receipt_hash AS inventory_receipt_hash
      FROM attack_knowledge_bundle_candidates linked
      JOIN attack_knowledge_bundles bundle ON bundle.id = linked.bundle_id
      JOIN historical_attack_knowledge_bundle_sources source
        ON source.bundle_id = linked.bundle_id
      JOIN attack_knowledge_provenance_receipts receipt
        ON receipt.id = source.receipt_id AND receipt.source_class = 'historical'
      JOIN historical_attack_knowledge_source_occurrences occurrence
        ON occurrence.candidate_id = source.candidate_id
       AND occurrence.source_hash = source.source_hash
      LEFT JOIN legacy_migration_runs migration ON migration.id = occurrence.migration_id
      LEFT JOIN legacy_migration_inventory_receipts inventory
        ON inventory.migration_id = migration.id
      WHERE linked.content_fingerprint IN (${placeholders(fingerprints.length)})
      ORDER BY linked.content_fingerprint, bundle.semantic_fingerprint,
        source.receipt_id, source.source_hash, occurrence.migration_id,
        occurrence.source_reference
    `).all(...fingerprints) as CustodyRow[];
  }

  #unlinkedCves(): HistoricalUnlinkedCveReviewSummary {
    const rows = this.database.prepare(`
      SELECT DISTINCT registry.content_fingerprint, node.id
      FROM attack_knowledge_candidate_registry registry
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      JOIN memory_nodes node ON node.id = candidate.proposed_node_id
      WHERE node.node_type = 'cve'
        AND candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.lifecycle_status = 'confirmed' AND node.confirmation_state = 'confirmed'
        AND NOT EXISTS (
          SELECT 1 FROM memory_edges_safe edge
          WHERE edge.source_node_id = node.id OR edge.target_node_id = node.id
        )
      ORDER BY registry.content_fingerprint
    `).all() as Array<{ readonly content_fingerprint: string; readonly id: string }>;
    return Object.freeze({
      unlinkedConfirmedCount: rows.length,
      nodeSetHash: sha256(canonicalJson(rows)),
      decision: "retain_for_cve_applicability_review" as const,
      automaticallyChanged: false as const,
    });
  }

  #assertSchema(): void {
    const required = [
      "attack_knowledge_bundle_candidates",
      "attack_knowledge_bundle_edges",
      "attack_knowledge_bundle_evidence_bindings",
      "attack_knowledge_bundles",
      "attack_knowledge_candidate_registry",
      "attack_knowledge_provenance_receipts",
      "historical_attack_knowledge_bundle_sources",
      "historical_attack_knowledge_source_occurrences",
      "legacy_migration_inventory_receipts",
      "legacy_migration_runs",
      "legacy_migration_source_objects",
      "memory_candidates",
      "memory_context_items",
      "memory_edges",
      "memory_nodes",
      "memory_sources",
      "reusable_knowledge_outcome_links",
    ];
    const rows = this.database.prepare(`
      SELECT name FROM sqlite_master WHERE type = 'table'
        AND name IN (${placeholders(required.length)})
    `).all(...required) as Array<{ readonly name: string }>;
    if (rows.length !== required.length) {
      throw new HistoricalUnlinkedScriptReviewError(
        "schema_unavailable",
        "Unlinked script review requires the canonical memory, attack-knowledge, and source-custody schema",
      );
    }
  }
}

import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import {
  attackKnowledgeOperationalLocatorCategories,
  findReusableMemorySecretCategories,
  isAttackCentricReusableNodeType,
  MemoryRepository,
  memoryContentHash,
  validateAttackCentricReusableCandidate,
  type AttackCentricReusableNodeType,
  type MemoryCandidate,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";
import {
  AttackKnowledgePromotionService,
  type AttackKnowledgePromotionResult,
} from "./AttackKnowledgePromotionService";
import { HistoricalAttackKnowledgeExtractionService } from "./HistoricalAttackKnowledgeExtractionService";

const SHA256 = /^[a-f0-9]{64}$/u;
const ACTOR = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const DEFAULT_MAX_RECORDS = 50;
const DEFAULT_MAX_SOURCE_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAX_DURATION_MS = 30_000;
const POLICY_VERSION = "historical-objective-facts-v3";

/** These facts can be checked directly against a hash-verified source. */
const OBJECTIVE_FACT_TYPES: ReadonlySet<AttackCentricReusableNodeType> = new Set([
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
  "attack_vector",
  "prerequisite",
  "attribute",
  "discovery_pattern",
  "fingerprint_pattern",
  "script_artifact",
  "tool_artifact",
  "outcome",
  "failure_mode",
  "procedure_version",
  "operational_hazard",
  "target_state_transition",
  "recovery_pattern",
  "health_check",
  "attack_tactic",
  "attack_technique",
  "attack_procedure",
]);

/** Applicability, advice, and lessons require an item-by-item human decision. */
const MANUAL_REVIEW_TYPES: ReadonlySet<string> = new Set([
  "cve",
  "advisory",
  "cwe",
  "misconfiguration",
  "alternative",
  "evidence_pattern",
  "validation_pattern",
  "detection",
  "remediation",
  "strategy",
  "research",
  "attack_lesson",
  "outcome",
]);

type ReviewDisposition = "eligible" | "rejected";

interface BundleRow {
  readonly id: string;
  readonly semantic_fingerprint: string;
  readonly sanitized_bundle_json: string;
}

interface SourceRow {
  readonly candidate_id: string;
  readonly source_hash: string;
  readonly byte_size: number;
  readonly custody_available: number;
  readonly mission_id: string;
  readonly run_id: string;
}

interface CandidateLinkRow {
  readonly role: string;
  readonly content_fingerprint: string;
  readonly candidate_id: string;
}

interface BatchRunRow {
  readonly authorization_id: string;
  readonly status: string;
  readonly staged_count: number;
  readonly rejected_count: number;
  readonly verified_count: number;
  readonly promoted_count: number;
  readonly source_bytes_processed: number;
}

export interface HistoricalAttackBatchFactReview {
  readonly role: string;
  readonly candidateId: string;
  readonly contentFingerprint: string;
  readonly nodeType: string;
  readonly title: string;
  readonly summary: string;
}

export interface HistoricalAttackBatchReviewEntry {
  readonly bundleId: string;
  readonly semanticFingerprint: string;
  readonly knowledgeKind: string;
  readonly facts: readonly HistoricalAttackBatchFactReview[];
  readonly edgeCount: number;
  readonly sourceCandidateIds: readonly string[];
  readonly sourceHashes: readonly string[];
  readonly sourceBytes: number;
  readonly disposition: ReviewDisposition;
  readonly reasonCategories: readonly string[];
}

export interface HistoricalAttackBatchReviewDocument {
  readonly schemaVersion: 1;
  readonly policyVersion: typeof POLICY_VERSION;
  readonly actorId: string;
  readonly reason: string;
  readonly acknowledgement: "objective_hash_verified_facts_only";
  readonly selection: {
    readonly afterSemanticFingerprint: string | null;
    readonly maxRecords: number;
    readonly maxSourceBytes: number;
    readonly maxDurationMs: number;
  };
  readonly entries: readonly HistoricalAttackBatchReviewEntry[];
  readonly selectedSourceBytes: number;
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
}

export interface HistoricalAttackBatchPreview {
  readonly previewHash: string;
  readonly review: HistoricalAttackBatchReviewDocument;
  readonly stagedCount: number;
  readonly rejectedCount: number;
  readonly eligibleCount: number;
}

export interface HistoricalAttackBatchRunResult {
  readonly status: "completed" | "partial" | "replayed";
  readonly authorizationId: string;
  readonly authorizationHash: string;
  readonly batchId: string;
  readonly stagedCount: number;
  readonly rejectedCount: number;
  readonly verifiedCount: number;
  readonly promotedCount: number;
  readonly sourceBytesProcessed: number;
  readonly nextResumeBundleFingerprint: string | null;
  readonly nextSelectionCursor: string | null;
  readonly reconciliationId: string;
}

export interface HistoricalAttackBatchPreviewInput {
  readonly actorId: string;
  readonly reason: string;
  readonly afterSemanticFingerprint?: string;
  readonly maxRecords?: number;
  readonly maxSourceBytes?: number;
  readonly maxDurationMs?: number;
}

export interface HistoricalAttackBatchExecuteInput extends HistoricalAttackBatchPreviewInput {
  readonly expectedPreviewHash: string;
  readonly acknowledgeObjectiveFactReview: true;
}

export interface HistoricalAttackBatchPromotionOptions {
  readonly receiptHmacKey?: string | Buffer;
  readonly clock?: () => Date;
  readonly monotonicNow?: () => number;
  /** Test/process-supervision hook invoked only after a durable item checkpoint. */
  readonly afterDurableItem?: (completedItemCount: number) => void;
}

export class HistoricalAttackBatchPromotionError extends Error {
  constructor(
    readonly code:
      | "invalid_request"
      | "empty_review"
      | "stale_preview"
      | "authorization_conflict"
      | "receipt_key_unavailable"
      | "source_custody_failed",
    message: string,
  ) {
    super(message);
    this.name = "HistoricalAttackBatchPromotionError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function integer(value: number | undefined, fallback: number, minimum: number, maximum: number, label: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new HistoricalAttackBatchPromotionError("invalid_request", `${label} is outside its bounded range`);
  }
  return resolved;
}

function parseObject(value: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}

function strings(value: string): readonly string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
    throw new Error("Historical batch persisted an invalid string array");
  }
  return parsed as readonly string[];
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort();
}

function storedReview(value: string, expectedHash: string): HistoricalAttackBatchReviewDocument {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; }
  catch { throw new HistoricalAttackBatchPromotionError("authorization_conflict", "Stored batch authorization is malformed"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
      (parsed as { readonly schemaVersion?: unknown }).schemaVersion !== 1 ||
      (parsed as { readonly policyVersion?: unknown }).policyVersion !== POLICY_VERSION ||
      !Array.isArray((parsed as { readonly entries?: unknown }).entries) ||
      sha256(canonicalJson(parsed)) !== expectedHash) {
    throw new HistoricalAttackBatchPromotionError("authorization_conflict", "Stored batch authorization failed its immutable hash check");
  }
  return parsed as HistoricalAttackBatchReviewDocument;
}

function normalizeInput(input: HistoricalAttackBatchPreviewInput): Required<HistoricalAttackBatchPreviewInput> {
  const actorId = input.actorId.trim().normalize("NFKC");
  const reason = input.reason.trim().normalize("NFKC");
  if (!ACTOR.test(actorId) || !reason || Buffer.byteLength(reason, "utf8") > 1_200) {
    throw new HistoricalAttackBatchPromotionError("invalid_request", "A bounded operator actor and review reason are required");
  }
  if (findReusableMemorySecretCategories(reason).length > 0) {
    throw new HistoricalAttackBatchPromotionError("invalid_request", "The operator review reason must not contain authentication material");
  }
  const afterSemanticFingerprint = input.afterSemanticFingerprint?.trim().toLowerCase() ?? "";
  if (afterSemanticFingerprint && !SHA256.test(afterSemanticFingerprint)) {
    throw new HistoricalAttackBatchPromotionError("invalid_request", "The selection cursor must be a lowercase SHA-256 digest");
  }
  return {
    actorId,
    reason,
    afterSemanticFingerprint,
    maxRecords: integer(input.maxRecords, DEFAULT_MAX_RECORDS, 1, 1_000, "Record budget"),
    maxSourceBytes: integer(input.maxSourceBytes, DEFAULT_MAX_SOURCE_BYTES, 1, 1024 * 1024 * 1024, "Source-byte budget"),
    maxDurationMs: integer(input.maxDurationMs, DEFAULT_MAX_DURATION_MS, 1, 3_600_000, "Duration budget"),
  };
}

/**
 * Local-only batch gate for the small class of homogeneous historical facts
 * that may be batch-reviewed under an explicit operator receipt.
 */
export class HistoricalAttackKnowledgeBatchPromotionService {
  readonly #clock: () => Date;
  readonly #monotonicNow: () => number;
  readonly #memory: MemoryRepository;
  readonly #promotion: AttackKnowledgePromotionService;
  readonly #audit: AuditTrailWriter;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly options: HistoricalAttackBatchPromotionOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#monotonicNow = options.monotonicNow ?? (() => performance.now());
    this.#memory = new MemoryRepository(database, { clock: this.#clock });
    this.#promotion = new AttackKnowledgePromotionService(database, { clock: this.#clock });
    this.#audit = new AuditTrailWriter(database);
    if (!this.#tableExists("historical_attack_knowledge_batch_authorizations")) {
      throw new Error("Historical attack batch promotion requires database migration 030");
    }
  }

  preview(input: HistoricalAttackBatchPreviewInput): HistoricalAttackBatchPreview {
    const normalized = normalizeInput(input);
    const rows = this.database.prepare(`
      SELECT bundle.id, bundle.semantic_fingerprint, bundle.sanitized_bundle_json
      FROM attack_knowledge_bundles bundle
      WHERE bundle.status = 'staged'
        AND bundle.semantic_fingerprint > ?
        AND EXISTS (
          SELECT 1 FROM historical_attack_knowledge_bundle_sources source
          WHERE source.bundle_id = bundle.id
        )
        AND NOT EXISTS (
          SELECT 1 FROM historical_attack_knowledge_batch_rejections rejected
          WHERE rejected.bundle_id = bundle.id
        )
      ORDER BY bundle.semantic_fingerprint
      LIMIT ?
    `).all(normalized.afterSemanticFingerprint, normalized.maxRecords + 1) as BundleRow[];

    const entries: HistoricalAttackBatchReviewEntry[] = [];
    let selectedSourceBytes = 0;
    let hasMore = rows.length > normalized.maxRecords;
    for (const row of rows.slice(0, normalized.maxRecords)) {
      const entry = this.#reviewEntry(row);
      if (entries.length > 0 && selectedSourceBytes + entry.sourceBytes > normalized.maxSourceBytes) {
        hasMore = true;
        break;
      }
      if (entries.length === 0 && entry.sourceBytes > normalized.maxSourceBytes) {
        hasMore = true;
        break;
      }
      entries.push(entry);
      selectedSourceBytes += entry.sourceBytes;
    }
    const nextSelectionCursor = hasMore && entries.length > 0
      ? entries.at(-1)!.semanticFingerprint
      : null;
    const review: HistoricalAttackBatchReviewDocument = {
      schemaVersion: 1,
      policyVersion: POLICY_VERSION,
      actorId: normalized.actorId,
      reason: normalized.reason,
      acknowledgement: "objective_hash_verified_facts_only",
      selection: {
        afterSemanticFingerprint: normalized.afterSemanticFingerprint || null,
        maxRecords: normalized.maxRecords,
        maxSourceBytes: normalized.maxSourceBytes,
        maxDurationMs: normalized.maxDurationMs,
      },
      entries,
      selectedSourceBytes,
      hasMore,
      nextSelectionCursor,
    };
    return {
      previewHash: sha256(canonicalJson(review)),
      review,
      stagedCount: entries.length,
      rejectedCount: entries.filter(({ disposition }) => disposition === "rejected").length,
      eligibleCount: entries.filter(({ disposition }) => disposition === "eligible").length,
    };
  }

  execute(input: HistoricalAttackBatchExecuteInput): HistoricalAttackBatchRunResult {
    if (input.acknowledgeObjectiveFactReview !== true) {
      throw new HistoricalAttackBatchPromotionError("invalid_request", "Explicit objective-fact review acknowledgement is required");
    }
    const expectedPreviewHash = input.expectedPreviewHash.trim().toLowerCase();
    if (!SHA256.test(expectedPreviewHash)) {
      throw new HistoricalAttackBatchPromotionError("invalid_request", "Expected preview hash must be a lowercase SHA-256 digest");
    }
    const normalized = normalizeInput(input);
    const persisted = this.database.prepare(`
      SELECT id, review_document_json, actor_id, reason
      FROM historical_attack_knowledge_batch_authorizations
      WHERE authorization_hash = ?
    `).get(expectedPreviewHash) as {
      readonly id: string;
      readonly review_document_json: string;
      readonly actor_id: string;
      readonly reason: string;
    } | undefined;
    const preview = persisted
      ? (() => {
          const review = storedReview(persisted.review_document_json, expectedPreviewHash);
          if (persisted.actor_id !== normalized.actorId || persisted.reason !== normalized.reason ||
              review.actorId !== normalized.actorId || review.reason !== normalized.reason ||
              (review.selection.afterSemanticFingerprint ?? "") !== normalized.afterSemanticFingerprint ||
              review.selection.maxRecords !== normalized.maxRecords ||
              review.selection.maxSourceBytes !== normalized.maxSourceBytes ||
              review.selection.maxDurationMs !== normalized.maxDurationMs) {
            throw new HistoricalAttackBatchPromotionError(
              "authorization_conflict",
              "Resume inputs do not match the immutable operator authorization",
            );
          }
          return {
            previewHash: expectedPreviewHash,
            review,
            stagedCount: review.entries.length,
            rejectedCount: review.entries.filter(({ disposition }) => disposition === "rejected").length,
            eligibleCount: review.entries.filter(({ disposition }) => disposition === "eligible").length,
          } satisfies HistoricalAttackBatchPreview;
        })()
      : this.preview(input);
    if (preview.review.entries.length === 0) {
      throw new HistoricalAttackBatchPromotionError("empty_review", "No bounded historical records are available for this review window");
    }
    if (preview.previewHash !== expectedPreviewHash) {
      throw new HistoricalAttackBatchPromotionError("stale_preview", "The reviewed historical batch changed; inspect and authorize the new preview hash");
    }
    const authorizationId = persisted?.id ?? `hakba_${preview.previewHash.slice(0, 48)}`;
    const batchId = `hakbatch_${preview.previewHash.slice(0, 48)}`;
    this.#authorizeAndStage(authorizationId, batchId, preview);

    const existing = this.#runRow(batchId);
    if (existing.status === "completed") return this.#result(batchId, preview, "replayed");
    if (!this.options.receiptHmacKey) {
      throw new HistoricalAttackBatchPromotionError(
        "receipt_key_unavailable",
        "A server-only historical receipt key is required to re-verify private source custody",
      );
    }
    const sourceReview = new HistoricalAttackKnowledgeExtractionService(this.database, {
      receiptHmacKey: this.options.receiptHmacKey,
      clock: this.#clock,
    });
    const started = this.#monotonicNow();
    let durableItems = 0;
    this.database.prepare(`
      UPDATE historical_attack_knowledge_batch_runs
      SET status = 'running', error_category = NULL, updated_at = ? WHERE id = ?
    `).run(this.#clock().toISOString(), batchId);
    try {
      const pending = this.database.prepare(`
        SELECT bundle_id, semantic_fingerprint, source_candidate_ids_json,
          source_hashes_json, source_bytes, reason_categories_json
        FROM historical_attack_knowledge_batch_items
        WHERE batch_id = ? AND disposition = 'pending'
        ORDER BY semantic_fingerprint
      `).all(batchId) as Array<{
        readonly bundle_id: string;
        readonly semantic_fingerprint: string;
        readonly source_candidate_ids_json: string;
        readonly source_hashes_json: string;
        readonly source_bytes: number;
        readonly reason_categories_json: string;
      }>;
      for (const item of pending) {
        if (this.#monotonicNow() - started >= preview.review.selection.maxDurationMs) break;
        const rejectionReasons = strings(item.reason_categories_json);
        if (rejectionReasons.length > 0) {
          this.#rejectItem(batchId, authorizationId, item.bundle_id, item.semantic_fingerprint, rejectionReasons);
        } else {
          const candidateIds = strings(item.source_candidate_ids_json);
          const sourceHashes = strings(item.source_hashes_json);
          const evidenceIds: string[] = [];
          let sourceCustodyFailed = false;
          for (let index = 0; index < candidateIds.length; index += 1) {
            const candidateId = candidateIds[index]!;
            const sourceHash = sourceHashes[index]!;
            try {
              sourceReview.beginSourceEvidenceReview({
                candidateId,
                actorId: preview.review.actorId,
                reason: `Authorized batch ${authorizationId}: ${preview.review.reason}`,
              });
              const verified = sourceReview.verifySourceEvidence({
                candidateId,
                actorId: preview.review.actorId,
                reason: `Hash and objective claims approved by authorization ${authorizationId}`,
                expectedSourceHash: sourceHash,
              });
              evidenceIds.push(verified.evidenceId);
            } catch {
              sourceCustodyFailed = true;
              break;
            }
          }
          if (sourceCustodyFailed) {
            this.#rejectItem(
              batchId,
              authorizationId,
              item.bundle_id,
              item.semantic_fingerprint,
              ["source_custody_revalidation_failed"],
            );
          } else {
            this.#materializeItem({
              batchId,
              bundleId: item.bundle_id,
              semanticFingerprint: item.semantic_fingerprint,
              actorId: preview.review.actorId,
              reason: preview.review.reason,
              evidenceIds: uniqueSorted(evidenceIds),
            });
          }
        }
        durableItems += 1;
        this.options.afterDurableItem?.(durableItems);
      }
    } catch (error) {
      this.database.prepare(`
        UPDATE historical_attack_knowledge_batch_runs
        SET status = 'failed', error_category = 'execution_interrupted', updated_at = ?
        WHERE id = ?
      `).run(this.#clock().toISOString(), batchId);
      this.#persistReconciliation(batchId, preview, "failed");
      throw error;
    }
    const remaining = Number((this.database.prepare(`
      SELECT COUNT(*) AS count FROM historical_attack_knowledge_batch_items
      WHERE batch_id = ? AND disposition = 'pending'
    `).get(batchId) as { readonly count: number }).count);
    const now = this.#clock().toISOString();
    this.#refreshRunCounts(batchId, remaining === 0 ? "completed" : "partial", now);
    const reconciliationId = this.#persistReconciliation(
      batchId,
      preview,
      remaining === 0 ? "completed" : "partial",
    );
    return { ...this.#result(batchId, preview, remaining === 0 ? "completed" : "partial"), reconciliationId };
  }

  #tableExists(name: string): boolean {
    return Boolean(this.database.prepare(
      "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?",
    ).get(name));
  }

  #reviewEntry(bundle: BundleRow): HistoricalAttackBatchReviewEntry {
    const sources = this.database.prepare(`
      SELECT DISTINCT source.candidate_id, source.source_hash, source.byte_size,
        candidate.mission_id, candidate.run_id,
        CASE WHEN EXISTS (
          SELECT 1
          FROM historical_attack_knowledge_source_occurrences occurrence
          JOIN legacy_migration_source_objects inventory
            ON inventory.migration_id = occurrence.migration_id
            AND inventory.source_reference = occurrence.source_reference
          WHERE occurrence.candidate_id = source.candidate_id
            AND occurrence.source_hash = source.source_hash
            AND inventory.source_sha256 = source.source_hash
            AND inventory.byte_size = source.byte_size
            AND inventory.object_kind = 'accepted'
            AND inventory.verification_status = 'verified_reference'
        ) THEN 1 ELSE 0 END AS custody_available
      FROM historical_attack_knowledge_bundle_sources binding
      JOIN historical_attack_knowledge_source_candidates source
        ON source.candidate_id = binding.candidate_id
      JOIN evidence_candidates candidate ON candidate.id = source.candidate_id
      WHERE binding.bundle_id = ?
      ORDER BY source.source_hash, source.candidate_id
    `).all(bundle.id) as SourceRow[];
    const links = this.database.prepare(`
      SELECT bundle.role, bundle.content_fingerprint, registry.candidate_id
      FROM attack_knowledge_bundle_candidates bundle
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = bundle.content_fingerprint
      WHERE bundle.bundle_id = ? ORDER BY bundle.ordinal, bundle.role
    `).all(bundle.id) as CandidateLinkRow[];
    const root = parseObject(bundle.sanitized_bundle_json);
    const rawKnowledge = root?.knowledge;
    const knowledge = rawKnowledge && typeof rawKnowledge === "object" && !Array.isArray(rawKnowledge)
      ? rawKnowledge as Record<string, unknown>
      : undefined;
    const knowledgeKind = typeof knowledge?.kind === "string" ? knowledge.kind : "invalid";
    const reasons = new Set<string>();
    if (sha256(bundle.sanitized_bundle_json) !== bundle.semantic_fingerprint ||
        bundle.id !== `akb_${bundle.semantic_fingerprint}`) {
      reasons.add("bundle_integrity_mismatch");
    }
    if (knowledgeKind !== "reusable_bundle") reasons.add("manual_or_unlinked_bundle_review_required");
    const edgeCount = Number((this.database.prepare(`
      SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges WHERE bundle_id = ?
    `).get(bundle.id) as { readonly count: number }).count);
    if (edgeCount < 1) reasons.add("unlinked_fact_requires_manual_review");
    if (sources.length < 1 || sources.some(({ custody_available }) => custody_available !== 1)) {
      reasons.add("verified_source_custody_unavailable");
    }

    const facts: HistoricalAttackBatchFactReview[] = [];
    for (const link of links) {
      const candidate = this.#memory.getCandidate(link.candidate_id);
      if (!candidate) {
        reasons.add("candidate_missing");
        continue;
      }
      const candidateReasons = this.#candidateRejectionReasons(
        candidate,
        link.content_fingerprint,
      );
      const withhold = candidateReasons.includes("secret_bearing_content") ||
        candidateReasons.includes("target_or_engagement_identifier") ||
        candidateReasons.includes("reusable_boundary_validation_failed");
      facts.push({
        role: link.role,
        candidateId: candidate.id,
        contentFingerprint: link.content_fingerprint,
        nodeType: candidate.nodeType,
        title: withhold ? "[Rejected unsafe candidate]" : candidate.title,
        summary: withhold ? "Candidate text is withheld by the reusable-memory privacy boundary." : candidate.summary,
      });
      candidateReasons.forEach((reason) => reasons.add(reason));
    }
    if (links.length === 0) reasons.add("candidate_missing");
    const sourceBytes = sources.reduce((sum, item) => sum + Number(item.byte_size), 0);
    return {
      bundleId: bundle.id,
      semanticFingerprint: bundle.semantic_fingerprint,
      knowledgeKind,
      facts,
      edgeCount,
      sourceCandidateIds: sources.map(({ candidate_id }) => candidate_id),
      sourceHashes: sources.map(({ source_hash }) => source_hash),
      sourceBytes,
      disposition: reasons.size === 0 ? "eligible" : "rejected",
      reasonCategories: [...reasons].sort(),
    };
  }

  #candidateRejectionReasons(
    candidate: MemoryCandidate,
    expectedFingerprint: string,
  ): readonly string[] {
    const reasons = new Set<string>();
    if (!isAttackCentricReusableNodeType(candidate.nodeType)) reasons.add("non_reusable_or_personal_memory");
    if (MANUAL_REVIEW_TYPES.has(candidate.nodeType)) reasons.add("human_judgment_required");
    if (candidate.nodeType === "outcome") {
      reasons.add("human_judgment_required");
      reasons.add("canonical_attack_attempt_outcome_required");
    }
    if (isAttackCentricReusableNodeType(candidate.nodeType) && !OBJECTIVE_FACT_TYPES.has(candidate.nodeType)) {
      reasons.add("unsupported_objective_fact_type");
    }
    if (candidate.proposedBy !== "attack-knowledge-compiler") reasons.add("untrusted_candidate_producer");
    if (!["pending", "confirmed", "edited_confirmed", "merged"].includes(candidate.status)) {
      reasons.add("candidate_not_promotable");
    }
    if (candidate.scope.kind !== "global" || candidate.scope.engagementId || candidate.scope.missionId) {
      reasons.add("operational_scope_identifier");
    }
    if (memoryContentHash(candidate) !== expectedFingerprint) reasons.add("candidate_fingerprint_mismatch");
    const text = `${candidate.title}\n${candidate.summary}\n${candidate.body}`;
    if (findReusableMemorySecretCategories(text).length > 0) reasons.add("secret_bearing_content");
    if (attackKnowledgeOperationalLocatorCategories(text).length > 0 ||
      /\b(?:autonomous|guided)\s+(?:mission|run|mode|journey)\b/iu.test(text) ||
      /\b(?:target|box|engagement|mission|run)\s+(?:name|identifier|address|id)\b/iu.test(text)) {
      reasons.add("target_or_engagement_identifier");
    }
    try {
      validateAttackCentricReusableCandidate(candidate);
    } catch {
      reasons.add("reusable_boundary_validation_failed");
    }
    return [...reasons].sort();
  }

  #authorizeAndStage(
    authorizationId: string,
    batchId: string,
    preview: HistoricalAttackBatchPreview,
  ): void {
    inImmediateTransaction(this.database, () => {
      const existing = this.database.prepare(`
        SELECT authorization_hash, review_document_json, actor_id
        FROM historical_attack_knowledge_batch_authorizations WHERE id = ?
      `).get(authorizationId) as {
        readonly authorization_hash: string;
        readonly review_document_json: string;
        readonly actor_id: string;
      } | undefined;
      const document = canonicalJson(preview.review);
      if (existing) {
        if (existing.authorization_hash !== preview.previewHash ||
            existing.review_document_json !== document ||
            existing.actor_id !== preview.review.actorId) {
          throw new HistoricalAttackBatchPromotionError("authorization_conflict", "Historical batch authorization identity conflict");
        }
        return;
      }
      const anchor = this.database.prepare(`
        SELECT candidate.mission_id, candidate.run_id
        FROM historical_attack_knowledge_bundle_sources binding
        JOIN evidence_candidates candidate ON candidate.id = binding.candidate_id
        WHERE binding.bundle_id = ? ORDER BY binding.candidate_id LIMIT 1
      `).get(preview.review.entries[0]!.bundleId) as {
        readonly mission_id: string;
        readonly run_id: string;
      } | undefined;
      if (!anchor) throw new Error("Historical batch authorization lacks a private audit anchor");
      const now = this.#clock().toISOString();
      const auditRecordId = this.#audit.append({
        missionId: anchor.mission_id,
        runId: anchor.run_id,
        actor: { type: "operator", id: preview.review.actorId },
        action: "historical_attack_batch.authorized",
        resourceType: "historical_attack_knowledge_batch_authorization",
        resourceId: authorizationId,
        reason: preview.review.reason,
        details: {
          authorizationHash: preview.previewHash,
          policyVersion: POLICY_VERSION,
          reviewedRecords: preview.review.entries.length,
          reviewedSourceBytes: preview.review.selectedSourceBytes,
          maxDurationMs: preview.review.selection.maxDurationMs,
        },
        occurredAt: now,
      });
      this.database.prepare(`
        INSERT INTO historical_attack_knowledge_batch_authorizations (
          id, authorization_hash, review_document_json, actor_id, reason,
          selection_after_fingerprint, max_records, max_source_bytes,
          max_duration_ms, reviewed_record_count, reviewed_source_bytes,
          acknowledged_objective_fact_review, audit_record_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
      `).run(
        authorizationId,
        preview.previewHash,
        document,
        preview.review.actorId,
        preview.review.reason,
        preview.review.selection.afterSemanticFingerprint,
        preview.review.selection.maxRecords,
        preview.review.selection.maxSourceBytes,
        preview.review.selection.maxDurationMs,
        preview.review.entries.length,
        preview.review.selectedSourceBytes,
        auditRecordId,
        now,
      );
      this.database.prepare(`
        INSERT INTO historical_attack_knowledge_batch_runs (
          id, authorization_id, status, staged_count, started_at, updated_at
        ) VALUES (?, ?, 'authorized', ?, ?, ?)
      `).run(batchId, authorizationId, preview.review.entries.length, now, now);
      const insert = this.database.prepare(`
        INSERT INTO historical_attack_knowledge_batch_items (
          batch_id, bundle_id, semantic_fingerprint, source_candidate_ids_json,
          source_hashes_json, source_bytes, disposition, reason_categories_json
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
      `);
      for (const entry of preview.review.entries) {
        insert.run(
          batchId,
          entry.bundleId,
          entry.semanticFingerprint,
          canonicalJson(entry.sourceCandidateIds),
          canonicalJson(entry.sourceHashes),
          entry.sourceBytes,
          canonicalJson(entry.reasonCategories),
        );
      }
      this.#appendEvent(batchId, "batch.authorized", null, {
        authorizationHash: preview.previewHash,
        reviewedRecords: preview.review.entries.length,
      }, now);
    });
  }

  #rejectItem(
    batchId: string,
    authorizationId: string,
    bundleId: string,
    semanticFingerprint: string,
    reasons: readonly string[],
  ): void {
    inImmediateTransaction(this.database, () => {
      const authorization = this.database.prepare(`
        SELECT actor_id, reason FROM historical_attack_knowledge_batch_authorizations WHERE id = ?
      `).get(authorizationId) as { readonly actor_id: string; readonly reason: string };
      const now = this.#clock().toISOString();
      this.database.prepare(`
        INSERT INTO historical_attack_knowledge_batch_rejections (
          bundle_id, semantic_fingerprint, reason_categories_json,
          authorization_id, actor_id, rejected_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(bundle_id) DO NOTHING
      `).run(bundleId, semanticFingerprint, canonicalJson(uniqueSorted(reasons)), authorizationId, authorization.actor_id, now);
      this.database.prepare(`
        INSERT INTO attack_knowledge_quarantine_records (
          fingerprint, source_class, reason_categories_json, occurrence_count,
          first_seen_at, last_seen_at
        ) VALUES (?, 'historical', ?, 1, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
          occurrence_count = occurrence_count + 1,
          last_seen_at = excluded.last_seen_at
      `).run(semanticFingerprint, canonicalJson(uniqueSorted(reasons)), now, now);
      this.database.prepare(`
        UPDATE historical_attack_knowledge_batch_items
        SET disposition = 'rejected', completed_at = ?
        WHERE batch_id = ? AND bundle_id = ? AND disposition = 'pending'
      `).run(now, batchId, bundleId);
      this.#appendItemAudit(batchId, bundleId, authorization.actor_id, authorization.reason,
        "historical_attack_batch.rejected", { reasonCategories: uniqueSorted(reasons) }, now);
      this.#appendEvent(batchId, "item.rejected", bundleId, { reasonCategories: uniqueSorted(reasons) }, now);
      this.#refreshRunCounts(batchId, "running", now, semanticFingerprint);
    });
  }

  #materializeItem(input: {
    readonly batchId: string;
    readonly bundleId: string;
    readonly semanticFingerprint: string;
    readonly actorId: string;
    readonly reason: string;
    readonly evidenceIds: readonly string[];
  }): AttackKnowledgePromotionResult {
    return inImmediateTransaction(this.database, () => {
      const links = this.database.prepare(`
        SELECT registry.candidate_id
        FROM attack_knowledge_bundle_candidates bundle
        JOIN attack_knowledge_candidate_registry registry
          ON registry.content_fingerprint = bundle.content_fingerprint
        WHERE bundle.bundle_id = ? ORDER BY bundle.ordinal, bundle.role
      `).all(input.bundleId) as Array<{ readonly candidate_id: string }>;
      for (const { candidate_id: candidateId } of links) {
        const candidate = this.#memory.requireCandidate(candidateId);
        if (candidate.status === "pending") this.#memory.confirmCandidate(candidateId, input.actorId);
      }
      const promotionPreview = this.#promotion.preview(input.semanticFingerprint, input.evidenceIds);
      const promoted = this.#promotion.promote({
        bundleFingerprint: input.semanticFingerprint,
        actor: input.actorId,
        expectedReviewHash: promotionPreview.reviewHash,
        verificationEvidenceIds: input.evidenceIds,
      });
      const now = this.#clock().toISOString();
      this.database.prepare(`
        UPDATE historical_attack_knowledge_batch_items
        SET disposition = 'promoted', verification_evidence_ids_json = ?,
          promotion_review_hash = ?, promotion_receipt_id = ?, completed_at = ?
        WHERE batch_id = ? AND bundle_id = ? AND disposition = 'pending'
      `).run(
        canonicalJson(input.evidenceIds),
        promoted.reviewHash,
        promoted.receiptId,
        now,
        input.batchId,
        input.bundleId,
      );
      this.#appendItemAudit(input.batchId, input.bundleId, input.actorId, input.reason,
        "historical_attack_batch.promoted", {
          promotionReceiptId: promoted.receiptId,
          reviewHash: promoted.reviewHash,
          verifiedEvidenceCount: input.evidenceIds.length,
          materializedEdgeCount: promoted.edgeIds.length,
        }, now);
      this.#appendEvent(input.batchId, "item.promoted", input.bundleId, {
        promotionReceiptId: promoted.receiptId,
        reviewHash: promoted.reviewHash,
        verifiedEvidenceCount: input.evidenceIds.length,
        materializedEdgeCount: promoted.edgeIds.length,
      }, now);
      this.#refreshRunCounts(input.batchId, "running", now, input.semanticFingerprint);
      return promoted;
    });
  }

  #appendItemAudit(
    batchId: string,
    bundleId: string,
    actorId: string,
    reason: string,
    action: string,
    details: Record<string, unknown>,
    occurredAt: string,
  ): void {
    const anchor = this.database.prepare(`
      SELECT candidate.mission_id, candidate.run_id
      FROM historical_attack_knowledge_bundle_sources binding
      JOIN evidence_candidates candidate ON candidate.id = binding.candidate_id
      WHERE binding.bundle_id = ? ORDER BY binding.candidate_id LIMIT 1
    `).get(bundleId) as { readonly mission_id: string; readonly run_id: string };
    this.#audit.append({
      missionId: anchor.mission_id,
      runId: anchor.run_id,
      actor: { type: "operator", id: actorId },
      action,
      resourceType: "historical_attack_knowledge_batch_item",
      resourceId: `${batchId}:${bundleId}`,
      reason,
      details: details as never,
      occurredAt,
    });
  }

  #appendEvent(
    batchId: string,
    eventType: string,
    bundleId: string | null,
    details: Record<string, unknown>,
    occurredAt: string,
  ): void {
    const previous = this.database.prepare(`
      SELECT sequence, record_hash FROM historical_attack_knowledge_batch_events
      WHERE batch_id = ? ORDER BY sequence DESC LIMIT 1
    `).get(batchId) as { readonly sequence: number; readonly record_hash: string } | undefined;
    const sequence = (previous?.sequence ?? 0) + 1;
    const body = { batchId, sequence, eventType, bundleId, details, occurredAt };
    const recordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(body)}`);
    this.database.prepare(`
      INSERT INTO historical_attack_knowledge_batch_events (
        id, batch_id, sequence, event_type, bundle_id, details_json,
        previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      `hakbe_${recordHash.slice(0, 48)}`,
      batchId,
      sequence,
      eventType,
      bundleId,
      canonicalJson(details),
      previous?.record_hash ?? null,
      recordHash,
      occurredAt,
    );
  }

  #refreshRunCounts(
    batchId: string,
    status: "running" | "partial" | "completed",
    now: string,
    lastProcessedFingerprint?: string,
  ): void {
    const counts = this.database.prepare(`
      SELECT COUNT(*) AS staged,
        SUM(CASE WHEN disposition = 'rejected' THEN 1 ELSE 0 END) AS rejected,
        SUM(CASE WHEN disposition = 'promoted' AND json_array_length(verification_evidence_ids_json) > 0 THEN 1 ELSE 0 END) AS verified,
        SUM(CASE WHEN disposition = 'promoted' THEN 1 ELSE 0 END) AS promoted,
        SUM(CASE WHEN disposition != 'pending' THEN source_bytes ELSE 0 END) AS bytes
      FROM historical_attack_knowledge_batch_items WHERE batch_id = ?
    `).get(batchId) as Record<string, number | null>;
    this.database.prepare(`
      UPDATE historical_attack_knowledge_batch_runs SET
        status = ?,
        last_processed_fingerprint = COALESCE(?, last_processed_fingerprint),
        staged_count = ?, rejected_count = ?, verified_count = ?, promoted_count = ?,
        source_bytes_processed = ?, updated_at = ?,
        completed_at = CASE WHEN ? = 'completed' THEN ? ELSE NULL END
      WHERE id = ?
    `).run(
      status,
      lastProcessedFingerprint ?? null,
      Number(counts.staged ?? 0),
      Number(counts.rejected ?? 0),
      Number(counts.verified ?? 0),
      Number(counts.promoted ?? 0),
      Number(counts.bytes ?? 0),
      now,
      status,
      now,
      batchId,
    );
  }

  #persistReconciliation(
    batchId: string,
    preview: HistoricalAttackBatchPreview,
    status: "completed" | "partial" | "failed",
  ): string {
    const run = this.#runRow(batchId);
    const pending = this.database.prepare(`
      SELECT semantic_fingerprint FROM historical_attack_knowledge_batch_items
      WHERE batch_id = ? AND disposition = 'pending'
      ORDER BY semantic_fingerprint LIMIT 1
    `).get(batchId) as { readonly semantic_fingerprint: string } | undefined;
    const report = {
      schemaVersion: 1,
      batchId,
      authorizationId: run.authorization_id,
      authorizationHash: preview.previewHash,
      status,
      staged: Number(run.staged_count),
      rejected: Number(run.rejected_count),
      verified: Number(run.verified_count),
      promoted: Number(run.promoted_count),
      sourceBytesProcessed: Number(run.source_bytes_processed),
      nextResumeBundleFingerprint: pending?.semantic_fingerprint ?? null,
      nextSelectionCursor: preview.review.nextSelectionCursor,
    };
    const reportHash = sha256(canonicalJson(report));
    const sequence = Number((this.database.prepare(`
      SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence
      FROM historical_attack_knowledge_batch_reconciliations WHERE batch_id = ?
    `).get(batchId) as { readonly sequence: number }).sequence);
    const id = `hakbr_${reportHash.slice(0, 48)}`;
    this.database.prepare(`
      INSERT INTO historical_attack_knowledge_batch_reconciliations (
        id, batch_id, sequence, report_json, report_hash, created_at
      ) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(batch_id, report_hash) DO NOTHING
    `).run(id, batchId, sequence, canonicalJson(report), reportHash, this.#clock().toISOString());
    return id;
  }

  #runRow(batchId: string): BatchRunRow {
    const row = this.database.prepare(`
      SELECT authorization_id, status, staged_count, rejected_count,
        verified_count, promoted_count, source_bytes_processed
      FROM historical_attack_knowledge_batch_runs WHERE id = ?
    `).get(batchId) as BatchRunRow | undefined;
    if (!row) throw new Error("Historical attack batch run was not found");
    return row;
  }

  #result(
    batchId: string,
    preview: HistoricalAttackBatchPreview,
    status: HistoricalAttackBatchRunResult["status"],
  ): HistoricalAttackBatchRunResult {
    const run = this.#runRow(batchId);
    const pending = this.database.prepare(`
      SELECT semantic_fingerprint FROM historical_attack_knowledge_batch_items
      WHERE batch_id = ? AND disposition = 'pending'
      ORDER BY semantic_fingerprint LIMIT 1
    `).get(batchId) as { readonly semantic_fingerprint: string } | undefined;
    const reconciliation = this.database.prepare(`
      SELECT id FROM historical_attack_knowledge_batch_reconciliations
      WHERE batch_id = ? ORDER BY sequence DESC LIMIT 1
    `).get(batchId) as { readonly id: string } | undefined;
    return {
      status,
      authorizationId: run.authorization_id,
      authorizationHash: preview.previewHash,
      batchId,
      stagedCount: Number(run.staged_count),
      rejectedCount: Number(run.rejected_count),
      verifiedCount: Number(run.verified_count),
      promotedCount: Number(run.promoted_count),
      sourceBytesProcessed: Number(run.source_bytes_processed),
      nextResumeBundleFingerprint: pending?.semantic_fingerprint ?? null,
      nextSelectionCursor: preview.review.nextSelectionCursor,
      reconciliationId: reconciliation?.id ?? "",
    };
  }
}

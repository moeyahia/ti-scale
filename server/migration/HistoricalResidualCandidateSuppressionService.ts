import { createHash, randomUUID } from "node:crypto";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import {
  assertReusableMemoryText,
  MemoryRepository,
  REUSABLE_MEMORY_LIMITS,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";

const SHA256 = /^[a-f0-9]{64}$/u;
const DEFAULT_PAGE_SIZE = 250;
const MAXIMUM_PAGE_SIZE = 1_000;
const POLICY_VERSION = "historical-residual-sensitive-suppression-v1";
const SCHEMA_VERSION = "ti_scale.historical_residual_suppression/v1";
const AGGREGATE_ACTION = "historical_residual_candidates.suppressed";

interface CandidateRow {
  readonly content_fingerprint: string;
  readonly candidate_id: string;
  readonly node_type: string;
}

interface OriginRow {
  readonly content_fingerprint: string;
  readonly candidate_id: string;
  readonly node_type: string;
  readonly source_candidate_id: string;
  readonly source_hash: string;
  readonly occurrence_migration_id: string;
  readonly source_reference: string;
}

interface InventoryRow {
  readonly source_hash: string;
  readonly object_id: string;
  readonly migration_id: string;
  readonly migration_status: "running" | "completed" | "failed" | "rolled_back";
  readonly source_retention: string;
  readonly brain_projection_mode: string;
  readonly receipt_hash: string | null;
  readonly object_kind: string;
  readonly classification: string;
  readonly source_reference: string;
}

interface ReplayRow {
  readonly id: string;
  readonly details_json: string;
}

interface HashRow {
  readonly record_hash: string;
}

export interface HistoricalResidualSuppressionInput {
  readonly actorId: string;
  readonly reason: string;
  readonly afterContentFingerprint?: string;
  readonly maxCandidates?: number;
}

export interface HistoricalResidualSuppressionExecuteInput
  extends HistoricalResidualSuppressionInput {
  readonly expectedPreviewHash: string;
  readonly acknowledgeSuppressSensitiveResiduals: true;
}

export interface HistoricalResidualSuppressionFence {
  /** Must assert the durable canonical writer lease from the open transaction. */
  readonly assertActiveInCurrentTransaction: () => unknown;
}

export interface HistoricalResidualSuppressionReviewItem {
  readonly candidateId: string;
  readonly contentFingerprint: string;
  readonly nodeType: string;
  readonly originSourceHashCount: number;
  readonly originOccurrenceCount: number;
  readonly terminalMigrationCount: number;
  readonly sensitiveQuarantineObjectCount: number;
  readonly completedSensitiveMigrationCount: number;
  readonly failedSensitiveMigrationCount: number;
  /** Hash-binds private origins and inventory rows without disclosing them. */
  readonly custodySetHash: string;
  readonly decision: "suppress_do_not_relearn";
  readonly reasonCategories: readonly [
    "zero_completed_accepted_source",
    "completed_inventory_sensitive_content",
    "all_terminal_inventory_sensitive_content",
  ];
}

export interface HistoricalResidualSuppressionPreview {
  readonly schemaVersion: typeof SCHEMA_VERSION;
  readonly policyVersion: typeof POLICY_VERSION;
  readonly mode: "dry_run";
  readonly previewHash: string;
  readonly actorId: string;
  readonly selection: {
    readonly afterContentFingerprint: string | null;
    readonly maxCandidates: number;
  };
  readonly candidateCount: number;
  readonly candidateSetHash: string;
  readonly originSetHash: string;
  readonly totalOriginSourceHashCount: number;
  readonly totalOriginOccurrenceCount: number;
  readonly totalSensitiveQuarantineObjectCount: number;
  readonly candidates: readonly HistoricalResidualSuppressionReviewItem[];
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
}

export interface HistoricalResidualSuppressionReceipt {
  readonly schemaVersion: typeof SCHEMA_VERSION;
  readonly policyVersion: typeof POLICY_VERSION;
  readonly previewHash: string;
  readonly actorId: string;
  readonly auditRecordId: string;
  readonly selectedCount: number;
  readonly suppressedCount: number;
  readonly candidateSetHash: string;
  readonly originSetHash: string;
  readonly totalOriginSourceHashCount: number;
  readonly totalOriginOccurrenceCount: number;
  readonly totalSensitiveQuarantineObjectCount: number;
  readonly decision: "suppress_do_not_relearn";
  readonly reasonCategories: readonly [
    "zero_completed_accepted_source",
    "completed_inventory_sensitive_content",
    "all_terminal_inventory_sensitive_content",
  ];
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
  readonly occurredAt: string;
  readonly receiptHash: string;
}

export interface HistoricalResidualSuppressionResult {
  readonly status: "completed" | "replayed";
  readonly receipt: HistoricalResidualSuppressionReceipt;
}

export class HistoricalResidualCandidateSuppressionError extends Error {
  constructor(
    readonly code:
      | "invalid_request"
      | "schema_unavailable"
      | "stale_preview"
      | "candidate_integrity_failed"
      | "audit_integrity_failed",
    message: string,
  ) {
    super(message);
    this.name = "HistoricalResidualCandidateSuppressionError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function bounded(value: string, label: string, maximum: number): string {
  const normalized = value.normalize("NFKC").trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new HistoricalResidualCandidateSuppressionError(
      "invalid_request",
      `${label} must contain 1 to ${maximum} printable characters`,
    );
  }
  return normalized;
}

function normalizeInput(input: HistoricalResidualSuppressionInput): Required<HistoricalResidualSuppressionInput> {
  const actorId = bounded(input.actorId, "actor ID", 256);
  const reason = bounded(input.reason, "suppression reason", 800);
  assertReusableMemoryText([{
    field: "historicalResidualSuppression.reason",
    value: reason,
    maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceExplanation,
  }]);
  const afterContentFingerprint = input.afterContentFingerprint?.trim() ?? "";
  if (afterContentFingerprint && !SHA256.test(afterContentFingerprint)) {
    throw new HistoricalResidualCandidateSuppressionError(
      "invalid_request",
      "The page cursor must be a lowercase SHA-256 fingerprint",
    );
  }
  const maxCandidates = input.maxCandidates ?? DEFAULT_PAGE_SIZE;
  if (
    !Number.isSafeInteger(maxCandidates)
    || maxCandidates < 1
    || maxCandidates > MAXIMUM_PAGE_SIZE
  ) {
    throw new HistoricalResidualCandidateSuppressionError(
      "invalid_request",
      `maxCandidates must be between 1 and ${MAXIMUM_PAGE_SIZE}`,
    );
  }
  return { actorId, reason, afterContentFingerprint, maxCandidates };
}

function placeholders(count: number): string {
  return Array.from({ length: count }, () => "?").join(", ");
}

function aggregateResourceId(previewHash: string): string {
  return `historical_residual_suppression_${previewHash}`;
}

function receiptHash(receipt: Omit<HistoricalResidualSuppressionReceipt, "receiptHash">): string {
  return sha256(canonicalJson(receipt));
}

function parseReplay(row: ReplayRow, expectedPreviewHash: string): HistoricalResidualSuppressionResult {
  let parsed: unknown;
  try { parsed = JSON.parse(row.details_json); }
  catch {
    throw new HistoricalResidualCandidateSuppressionError(
      "audit_integrity_failed",
      "The prior suppression audit receipt is not valid JSON",
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HistoricalResidualCandidateSuppressionError(
      "audit_integrity_failed",
      "The prior suppression audit receipt is malformed",
    );
  }
  const receipt = (parsed as { receipt?: unknown }).receipt;
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    throw new HistoricalResidualCandidateSuppressionError(
      "audit_integrity_failed",
      "The prior suppression aggregate audit does not contain a receipt",
    );
  }
  const value = receipt as HistoricalResidualSuppressionReceipt;
  const { receiptHash: recordedHash, ...unsigned } = value;
  if (
    value.auditRecordId !== row.id
    || value.previewHash !== expectedPreviewHash
    || !SHA256.test(recordedHash)
    || receiptHash(unsigned) !== recordedHash
  ) {
    throw new HistoricalResidualCandidateSuppressionError(
      "audit_integrity_failed",
      "The prior suppression receipt failed its integrity check",
    );
  }
  return { status: "replayed", receipt: value };
}

/**
 * Destructive privacy cleanup for one narrow post-import residual class.
 *
 * It never confirms memory. A candidate is eligible only while pending, only
 * when every historical origin hash has a completed receipt-backed
 * `sensitive_content` quarantine, and only when no terminal inventory or
 * current receipt contradicts that classification. Exact accepted bytes in a
 * completed import remove the candidate from the page and make an existing
 * preview stale.
 */
export class HistoricalResidualCandidateSuppressionService {
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
    this.#assertSchema();
  }

  preview(input: HistoricalResidualSuppressionInput): HistoricalResidualSuppressionPreview {
    const normalized = normalizeInput(input);
    const rows = this.#eligibleRows(
      normalized.afterContentFingerprint,
      normalized.maxCandidates + 1,
    );
    const hasMore = rows.length > normalized.maxCandidates;
    const selected = rows.slice(0, normalized.maxCandidates);
    const candidates = this.#reviewItems(selected);
    const nextSelectionCursor = candidates.at(-1)?.contentFingerprint ?? null;
    const candidateSetHash = sha256(canonicalJson(candidates.map((candidate) => ({
      candidateId: candidate.candidateId,
      contentFingerprint: candidate.contentFingerprint,
      nodeType: candidate.nodeType,
      custodySetHash: candidate.custodySetHash,
    }))));
    const originSetHash = sha256(canonicalJson(candidates.map((candidate) => ({
      contentFingerprint: candidate.contentFingerprint,
      custodySetHash: candidate.custodySetHash,
    }))));
    const review = {
      schemaVersion: SCHEMA_VERSION,
      policyVersion: POLICY_VERSION,
      actorId: normalized.actorId,
      reason: normalized.reason,
      acknowledgement: "suppress_sensitive_historical_residuals_only",
      selection: {
        afterContentFingerprint: normalized.afterContentFingerprint || null,
        maxCandidates: normalized.maxCandidates,
      },
      candidateSetHash,
      originSetHash,
      candidates,
      hasMore,
      nextSelectionCursor,
    } as const;
    return {
      schemaVersion: SCHEMA_VERSION,
      policyVersion: POLICY_VERSION,
      mode: "dry_run",
      previewHash: sha256(canonicalJson(review)),
      actorId: normalized.actorId,
      selection: review.selection,
      candidateCount: candidates.length,
      candidateSetHash,
      originSetHash,
      totalOriginSourceHashCount: candidates.reduce(
        (total, candidate) => total + candidate.originSourceHashCount,
        0,
      ),
      totalOriginOccurrenceCount: candidates.reduce(
        (total, candidate) => total + candidate.originOccurrenceCount,
        0,
      ),
      totalSensitiveQuarantineObjectCount: candidates.reduce(
        (total, candidate) => total + candidate.sensitiveQuarantineObjectCount,
        0,
      ),
      candidates,
      hasMore,
      nextSelectionCursor,
    };
  }

  execute(
    input: HistoricalResidualSuppressionExecuteInput,
    fence: HistoricalResidualSuppressionFence,
  ): HistoricalResidualSuppressionResult {
    if (
      input.acknowledgeSuppressSensitiveResiduals !== true
      || !SHA256.test(input.expectedPreviewHash)
    ) {
      throw new HistoricalResidualCandidateSuppressionError(
        "invalid_request",
        "Execution requires the exact preview hash and the sensitive-residual suppression acknowledgement",
      );
    }
    const normalized = normalizeInput(input);
    return inImmediateTransaction(this.database, () => {
      fence.assertActiveInCurrentTransaction();
      const resourceId = aggregateResourceId(input.expectedPreviewHash);
      const replay = this.database.prepare(`
        SELECT id, details_json FROM audit_records
        WHERE action = ? AND resource_type = 'historical_residual_suppression'
          AND resource_id = ? AND actor_type = 'operator' AND actor_id = ?
        ORDER BY rowid LIMIT 1
      `).get(AGGREGATE_ACTION, resourceId, normalized.actorId) as ReplayRow | undefined;
      if (replay) return parseReplay(replay, input.expectedPreviewHash);

      const preview = this.preview(normalized);
      if (preview.candidateCount === 0) {
        throw new HistoricalResidualCandidateSuppressionError(
          "invalid_request",
          "This residual suppression page is empty",
        );
      }
      if (preview.previewHash !== input.expectedPreviewHash) {
        throw new HistoricalResidualCandidateSuppressionError(
          "stale_preview",
          "Residual source custody changed after preview; generate a fresh preview",
        );
      }

      const candidates = this.#memory.getCandidates(
        preview.candidates.map(({ candidateId }) => candidateId),
      );
      let suppressedCount = 0;
      for (const reviewed of preview.candidates) {
        const candidate = candidates.get(reviewed.candidateId);
        if (
          !candidate
          || candidate.status !== "pending"
          || candidate.proposedBy !== "attack-knowledge-compiler"
          || candidate.proposedNodeId !== undefined
        ) {
          throw new HistoricalResidualCandidateSuppressionError(
            "candidate_integrity_failed",
            "A reviewed residual candidate is no longer an unmaterialized pending compiler candidate",
          );
        }
        this.#memory.rejectCandidateAndSuppress(
          reviewed.candidateId,
          normalized.actorId,
          `Historical residual privacy boundary: all receipt-backed terminal origins are quarantined sensitive_content. ${normalized.reason}`,
        );
        suppressedCount += 1;
      }

      const occurredAt = this.#clock().toISOString();
      const auditRecordId = this.#createId("audit");
      const unsignedReceipt = {
        schemaVersion: SCHEMA_VERSION,
        policyVersion: POLICY_VERSION,
        previewHash: preview.previewHash,
        actorId: normalized.actorId,
        auditRecordId,
        selectedCount: preview.candidateCount,
        suppressedCount,
        candidateSetHash: preview.candidateSetHash,
        originSetHash: preview.originSetHash,
        totalOriginSourceHashCount: preview.totalOriginSourceHashCount,
        totalOriginOccurrenceCount: preview.totalOriginOccurrenceCount,
        totalSensitiveQuarantineObjectCount: preview.totalSensitiveQuarantineObjectCount,
        decision: "suppress_do_not_relearn",
        reasonCategories: [
          "zero_completed_accepted_source",
          "completed_inventory_sensitive_content",
          "all_terminal_inventory_sensitive_content",
        ],
        hasMore: preview.hasMore,
        nextSelectionCursor: preview.nextSelectionCursor,
        occurredAt,
      } as const;
      const receipt: HistoricalResidualSuppressionReceipt = {
        ...unsignedReceipt,
        receiptHash: receiptHash(unsignedReceipt),
      };
      const previous = this.database.prepare(
        "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
      ).get() as HashRow | undefined;
      const details = {
        schemaVersion: SCHEMA_VERSION,
        policyVersion: POLICY_VERSION,
        decision: "suppress_do_not_relearn",
        reasonCategories: receipt.reasonCategories,
        verificationState: "privacy_suppression_only",
        receipt,
      } as const;
      const recordHash = sha256(canonicalJson({
        id: auditRecordId,
        actor: normalized.actorId,
        action: AGGREGATE_ACTION,
        resourceType: "historical_residual_suppression",
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
          'historical_residual_suppression', ?, ?, ?, ?, ?, ?)
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
      return { status: "completed", receipt };
    });
  }

  #assertSchema(): void {
    const required = [
      "attack_knowledge_bundle_candidates",
      "attack_knowledge_bundle_receipts",
      "attack_knowledge_candidate_registry",
      "attack_knowledge_provenance_receipts",
      "historical_attack_knowledge_bundle_sources",
      "historical_attack_knowledge_import_contexts",
      "historical_attack_knowledge_source_occurrences",
      "legacy_migration_inventory_receipts",
      "legacy_migration_runs",
      "legacy_migration_source_objects",
      "memory_candidates",
      "memory_suppressions",
    ];
    const rows = this.database.prepare(`
      SELECT name FROM sqlite_master WHERE type='table' AND name IN (${placeholders(required.length)})
    `).all(...required) as Array<{ readonly name: string }>;
    if (rows.length !== required.length) {
      throw new HistoricalResidualCandidateSuppressionError(
        "schema_unavailable",
        "Historical residual suppression requires the canonical attack-knowledge and migration custody schema",
      );
    }
  }

  #eligibleRows(after: string, limit: number): CandidateRow[] {
    return this.database.prepare(`
      WITH candidate_links AS (
        SELECT DISTINCT registry.content_fingerprint, registry.candidate_id,
          candidate.candidate_type AS node_type,
          source_binding.candidate_id AS source_candidate_id,
          source_binding.source_hash
        FROM memory_candidates candidate
        JOIN attack_knowledge_candidate_registry registry
          ON registry.candidate_id = candidate.id
        JOIN attack_knowledge_bundle_candidates bundle_candidate
          ON bundle_candidate.content_fingerprint = registry.content_fingerprint
        JOIN historical_attack_knowledge_bundle_sources source_binding
          ON source_binding.bundle_id = bundle_candidate.bundle_id
        WHERE candidate.status = 'pending'
          AND candidate.proposed_by = 'attack-knowledge-compiler'
          AND candidate.proposed_node_id IS NULL
      ),
      candidate_hashes AS (
        SELECT DISTINCT content_fingerprint, candidate_id, node_type, source_hash
        FROM candidate_links
      ),
      hash_safety AS (
        SELECT candidate_hashes.*,
          EXISTS (
            SELECT 1
            FROM legacy_migration_source_objects object
            JOIN legacy_migration_runs migration ON migration.id = object.migration_id
            JOIN legacy_migration_inventory_receipts receipt
              ON receipt.migration_id = migration.id
            WHERE object.source_sha256 = candidate_hashes.source_hash
              AND migration.status = 'completed'
              AND migration.source_retention = 'verified-reference'
              AND migration.brain_projection_mode = 'attack-knowledge-only'
              AND object.object_kind = 'quarantined'
              AND object.classification = 'sensitive_content'
          ) AS completed_sensitive,
          EXISTS (
            SELECT 1
            FROM legacy_migration_source_objects object
            JOIN legacy_migration_runs migration ON migration.id = object.migration_id
            JOIN legacy_migration_inventory_receipts receipt
              ON receipt.migration_id = migration.id
            WHERE object.source_sha256 = candidate_hashes.source_hash
              AND migration.status = 'completed'
              AND migration.source_retention = 'verified-reference'
              AND migration.brain_projection_mode = 'attack-knowledge-only'
              AND object.object_kind = 'accepted'
          ) AS completed_accepted,
          EXISTS (
            SELECT 1
            FROM legacy_migration_source_objects object
            JOIN legacy_migration_runs migration ON migration.id = object.migration_id
            WHERE object.source_sha256 = candidate_hashes.source_hash
              AND migration.status = 'running'
          ) AS active_inventory,
          EXISTS (
            SELECT 1
            FROM legacy_migration_source_objects object
            JOIN legacy_migration_runs migration ON migration.id = object.migration_id
            WHERE object.source_sha256 = candidate_hashes.source_hash
              AND migration.status IN ('completed', 'failed', 'rolled_back')
              AND NOT (
                object.object_kind = 'quarantined'
                AND object.classification = 'sensitive_content'
              )
          ) AS conflicting_terminal_inventory
        FROM candidate_hashes
      ),
      candidate_hash_safety AS (
        SELECT content_fingerprint, candidate_id, node_type,
          COUNT(*) AS source_hash_count,
          MIN(completed_sensitive) AS every_hash_completed_sensitive,
          MAX(completed_accepted) AS has_completed_accepted,
          MAX(active_inventory) AS has_active_inventory,
          MAX(conflicting_terminal_inventory) AS has_conflicting_terminal_inventory
        FROM hash_safety
        GROUP BY content_fingerprint, candidate_id, node_type
      ),
      link_safety AS (
        SELECT candidate_links.content_fingerprint,
          COUNT(DISTINCT candidate_links.source_candidate_id) AS source_candidate_count,
          COUNT(DISTINCT CASE WHEN EXISTS (
            SELECT 1 FROM historical_attack_knowledge_source_occurrences occurrence
            WHERE occurrence.candidate_id = candidate_links.source_candidate_id
              AND occurrence.source_hash = candidate_links.source_hash
          ) THEN candidate_links.source_candidate_id END) AS source_candidates_with_occurrence
        FROM candidate_links
        GROUP BY candidate_links.content_fingerprint
      ),
      occurrence_safety AS (
        SELECT candidate_links.content_fingerprint,
          MAX(CASE
            WHEN migration.status = 'running' THEN 1
            WHEN migration.id IS NULL AND NOT (
              context.migration_id IS NOT NULL
              AND mission.status = 'archived'
              AND mission.created_by = 'system:historical-attack-knowledge-import'
              AND run.status = 'completed'
            ) THEN 1
            ELSE 0
          END) AS has_nonterminal_occurrence
        FROM candidate_links
        LEFT JOIN historical_attack_knowledge_source_occurrences occurrence
          ON occurrence.candidate_id = candidate_links.source_candidate_id
         AND occurrence.source_hash = candidate_links.source_hash
        LEFT JOIN legacy_migration_runs migration ON migration.id = occurrence.migration_id
        LEFT JOIN historical_attack_knowledge_import_contexts context
          ON context.migration_id = occurrence.migration_id
        LEFT JOIN missions mission ON mission.id = context.mission_id
        LEFT JOIN runs run ON run.id = context.run_id
        GROUP BY candidate_links.content_fingerprint
      ),
      receipt_safety AS (
        SELECT registry.content_fingerprint,
          MAX(provenance.source_class = 'current') AS has_current_receipt,
          MAX(CASE WHEN provenance.source_class = 'historical'
            AND source_binding.candidate_id IS NULL THEN 1 ELSE 0 END) AS has_unbound_historical_receipt
        FROM attack_knowledge_candidate_registry registry
        JOIN attack_knowledge_bundle_candidates bundle_candidate
          ON bundle_candidate.content_fingerprint = registry.content_fingerprint
        JOIN attack_knowledge_bundle_receipts bundle_receipt
          ON bundle_receipt.bundle_id = bundle_candidate.bundle_id
        JOIN attack_knowledge_provenance_receipts provenance
          ON provenance.id = bundle_receipt.receipt_id
        LEFT JOIN historical_attack_knowledge_bundle_sources source_binding
          ON source_binding.bundle_id = bundle_receipt.bundle_id
         AND source_binding.receipt_id = bundle_receipt.receipt_id
        GROUP BY registry.content_fingerprint
      )
      SELECT safety.content_fingerprint, safety.candidate_id, safety.node_type
      FROM candidate_hash_safety safety
      JOIN link_safety ON link_safety.content_fingerprint = safety.content_fingerprint
      JOIN occurrence_safety ON occurrence_safety.content_fingerprint = safety.content_fingerprint
      JOIN receipt_safety ON receipt_safety.content_fingerprint = safety.content_fingerprint
      WHERE safety.content_fingerprint > ?
        AND safety.source_hash_count > 0
        AND safety.every_hash_completed_sensitive = 1
        AND safety.has_completed_accepted = 0
        AND safety.has_active_inventory = 0
        AND safety.has_conflicting_terminal_inventory = 0
        AND link_safety.source_candidate_count = link_safety.source_candidates_with_occurrence
        AND occurrence_safety.has_nonterminal_occurrence = 0
        AND receipt_safety.has_current_receipt = 0
        AND receipt_safety.has_unbound_historical_receipt = 0
      ORDER BY safety.content_fingerprint
      LIMIT ?
    `).all(after, limit) as CandidateRow[];
  }

  #reviewItems(rows: readonly CandidateRow[]): HistoricalResidualSuppressionReviewItem[] {
    if (rows.length === 0) return [];
    const ids = rows.map(({ candidate_id }) => candidate_id);
    const origins: OriginRow[] = [];
    for (let offset = 0; offset < ids.length; offset += 250) {
      const batch = ids.slice(offset, offset + 250);
      origins.push(...this.database.prepare(`
        SELECT DISTINCT registry.content_fingerprint, registry.candidate_id,
          candidate.candidate_type AS node_type,
          source_binding.candidate_id AS source_candidate_id,
          source_binding.source_hash,
          occurrence.migration_id AS occurrence_migration_id,
          occurrence.source_reference
        FROM memory_candidates candidate
        JOIN attack_knowledge_candidate_registry registry
          ON registry.candidate_id = candidate.id
        JOIN attack_knowledge_bundle_candidates bundle_candidate
          ON bundle_candidate.content_fingerprint = registry.content_fingerprint
        JOIN historical_attack_knowledge_bundle_sources source_binding
          ON source_binding.bundle_id = bundle_candidate.bundle_id
        JOIN historical_attack_knowledge_source_occurrences occurrence
          ON occurrence.candidate_id = source_binding.candidate_id
         AND occurrence.source_hash = source_binding.source_hash
        WHERE registry.candidate_id IN (${placeholders(batch.length)})
        ORDER BY registry.content_fingerprint, source_binding.source_hash,
          occurrence.migration_id, occurrence.source_reference
      `).all(...batch) as OriginRow[]);
    }
    const sourceHashes = [...new Set(origins.map(({ source_hash }) => source_hash))];
    const inventory: InventoryRow[] = [];
    for (let offset = 0; offset < sourceHashes.length; offset += 250) {
      const batch = sourceHashes.slice(offset, offset + 250);
      inventory.push(...this.database.prepare(`
        SELECT object.source_sha256 AS source_hash, object.id AS object_id,
          object.migration_id, migration.status AS migration_status,
          migration.source_retention, migration.brain_projection_mode,
          receipt.receipt_hash, object.object_kind, object.classification,
          object.source_reference
        FROM legacy_migration_source_objects object
        JOIN legacy_migration_runs migration ON migration.id = object.migration_id
        LEFT JOIN legacy_migration_inventory_receipts receipt
          ON receipt.migration_id = migration.id
        WHERE object.source_sha256 IN (${placeholders(batch.length)})
        ORDER BY object.source_sha256, object.migration_id, object.id
      `).all(...batch) as InventoryRow[]);
    }

    const originByCandidate = new Map<string, OriginRow[]>();
    for (const origin of origins) {
      const current = originByCandidate.get(origin.candidate_id) ?? [];
      current.push(origin);
      originByCandidate.set(origin.candidate_id, current);
    }
    const inventoryByHash = new Map<string, InventoryRow[]>();
    for (const item of inventory) {
      const current = inventoryByHash.get(item.source_hash) ?? [];
      current.push(item);
      inventoryByHash.set(item.source_hash, current);
    }

    return rows.map((row) => {
      const candidateOrigins = originByCandidate.get(row.candidate_id) ?? [];
      const candidateHashes = [...new Set(candidateOrigins.map(({ source_hash }) => source_hash))].sort();
      if (candidateHashes.length === 0) {
        throw new HistoricalResidualCandidateSuppressionError(
          "candidate_integrity_failed",
          "A selected residual candidate lost its source origins",
        );
      }
      const candidateInventory = candidateHashes
        .flatMap((hash) => inventoryByHash.get(hash) ?? [])
        .sort((left, right) => (
          left.source_hash.localeCompare(right.source_hash)
          || left.migration_id.localeCompare(right.migration_id)
          || left.object_id.localeCompare(right.object_id)
        ));
      const terminal = candidateInventory.filter(({ migration_status }) => migration_status !== "running");
      const sensitive = terminal.filter(({ object_kind, classification }) => (
        object_kind === "quarantined" && classification === "sensitive_content"
      ));
      if (
        candidateInventory.some(({ migration_status }) => migration_status === "running")
        || terminal.length !== sensitive.length
        || candidateHashes.some((hash) => !candidateInventory.some((item) => (
          item.source_hash === hash
          && item.migration_status === "completed"
          && item.source_retention === "verified-reference"
          && item.brain_projection_mode === "attack-knowledge-only"
          && item.receipt_hash !== null
          && item.object_kind === "quarantined"
          && item.classification === "sensitive_content"
        )))
      ) {
        throw new HistoricalResidualCandidateSuppressionError(
          "candidate_integrity_failed",
          "A selected residual candidate no longer has exclusive receipt-backed sensitive quarantine custody",
        );
      }
      const custodySetHash = sha256(canonicalJson({
        candidateId: row.candidate_id,
        contentFingerprint: row.content_fingerprint,
        origins: candidateOrigins.map((origin) => ({
          sourceCandidateId: origin.source_candidate_id,
          sourceHash: origin.source_hash,
          migrationId: origin.occurrence_migration_id,
          sourceReference: origin.source_reference,
        })),
        inventory: candidateInventory.map((item) => ({
          sourceHash: item.source_hash,
          objectId: item.object_id,
          migrationId: item.migration_id,
          migrationStatus: item.migration_status,
          sourceRetention: item.source_retention,
          brainProjectionMode: item.brain_projection_mode,
          receiptHash: item.receipt_hash,
          objectKind: item.object_kind,
          classification: item.classification,
          sourceReference: item.source_reference,
        })),
      }));
      const terminalMigrations = new Set(terminal.map(({ migration_id }) => migration_id));
      const completedMigrations = new Set(sensitive
        .filter(({ migration_status }) => migration_status === "completed")
        .map(({ migration_id }) => migration_id));
      const failedMigrations = new Set(sensitive
        .filter(({ migration_status }) => migration_status === "failed")
        .map(({ migration_id }) => migration_id));
      return {
        candidateId: row.candidate_id,
        contentFingerprint: row.content_fingerprint,
        nodeType: row.node_type,
        originSourceHashCount: candidateHashes.length,
        originOccurrenceCount: candidateOrigins.length,
        terminalMigrationCount: terminalMigrations.size,
        sensitiveQuarantineObjectCount: sensitive.length,
        completedSensitiveMigrationCount: completedMigrations.size,
        failedSensitiveMigrationCount: failedMigrations.size,
        custodySetHash,
        decision: "suppress_do_not_relearn",
        reasonCategories: [
          "zero_completed_accepted_source",
          "completed_inventory_sensitive_content",
          "all_terminal_inventory_sensitive_content",
        ],
      };
    });
  }
}

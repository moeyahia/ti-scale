import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION,
  type HistoricalReportedOutcomeClassification,
} from "../domain";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import {
  attackKnowledgeOperationalLocatorCategories,
  findReusableMemorySecretCategories,
  isAttackCentricReusableNodeType,
  type MemoryNodeType,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";

const SHA256 = /^[a-f0-9]{64}$/u;
const OPAQUE_ID = /^[A-Za-z0-9._:@/-]{1,300}$/u;
const SENSITIVE_KEY_NAME = /^(?:api[_-]?key|auth(?:orization)?|cookie|credential|password|passwd|private[_-]?key|secret|session[_-]?token|ticket|token)$/iu;
const DEFAULT_PAGE_SIZE = 250;
const MAX_PAGE_SIZE = 1_000;

export const HISTORICAL_REPORTED_OUTCOME_BASIS_CATEGORIES = [
  "operational_hazard_reported_success",
  "operational_hazard_reported_failure",
  "structured_outcome_reported_success",
  "structured_outcome_reported_failure",
  "structured_outcome_reported_mixed",
  "legacy_candidate_worked",
  "legacy_candidate_failed",
  "no_reported_outcome_marker",
] as const;

export const HISTORICAL_REPORTED_OUTCOME_REJECTION_REASONS = [
  "bundle_integrity_mismatch",
  "malformed_sanitized_bundle",
  "reusable_boundary_violation",
  "technique_or_stack_context_required",
] as const;

export type HistoricalReportedOutcomeBasisCategory =
  (typeof HISTORICAL_REPORTED_OUTCOME_BASIS_CATEGORIES)[number];
export type HistoricalReportedOutcomeRejectionReason =
  (typeof HISTORICAL_REPORTED_OUTCOME_REJECTION_REASONS)[number];

interface Cursor {
  readonly semanticFingerprint: string;
  readonly receiptId: string;
  readonly candidateId: string;
}

interface SourceBindingRow {
  readonly bundle_id: string;
  readonly semantic_fingerprint: string;
  readonly sanitized_bundle_json: string;
  readonly receipt_id: string;
  readonly candidate_id: string;
  readonly source_hash: string;
  readonly mission_id: string;
  readonly run_id: string | null;
}

interface ExistingClaimRow {
  readonly bundle_id: string;
  readonly receipt_id: string;
  readonly source_candidate_id: string;
  readonly source_hash: string;
  readonly bundle_semantic_fingerprint: string;
  readonly classification: string;
  readonly classification_confidence: number;
  readonly basis_categories_json: string;
  readonly policy_version: string;
  readonly classification_receipt_hash: string;
}

interface ClassifiedBinding {
  readonly row: SourceBindingRow;
  readonly claimId: string;
  readonly classification: HistoricalReportedOutcomeClassification;
  readonly classificationConfidence: number;
  readonly basisCategories: readonly HistoricalReportedOutcomeBasisCategory[];
  readonly classificationReceiptHash: string;
  readonly disposition: "eligible" | "rejected";
  readonly rejectionReasons: readonly HistoricalReportedOutcomeRejectionReason[];
}

export interface HistoricalReportedOutcomeReviewEntry {
  readonly bundleFingerprint: string;
  readonly sourceHash: string;
  /** Hash only; receipt/candidate IDs remain internal. */
  readonly claimKeyHash: string;
  readonly classification: HistoricalReportedOutcomeClassification;
  /** Extraction confidence only. It is never attack-success confidence. */
  readonly classificationConfidence: number;
  readonly basisCategories: readonly HistoricalReportedOutcomeBasisCategory[];
  readonly classificationReceiptHash: string;
  readonly disposition: "eligible" | "rejected";
  readonly rejectionReasons: readonly HistoricalReportedOutcomeRejectionReason[];
}

export interface HistoricalReportedOutcomePreview {
  readonly schemaVersion: "ti_scale.historical_reported_outcome_preview/v1";
  readonly policyVersion: typeof HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION;
  readonly dryRun: true;
  readonly selection: {
    readonly afterCursor: string | null;
    readonly maxRecords: number;
  };
  readonly entries: readonly HistoricalReportedOutcomeReviewEntry[];
  readonly reviewedCount: number;
  readonly eligibleCount: number;
  readonly rejectedCount: number;
  readonly classificationCounts: Readonly<Record<HistoricalReportedOutcomeClassification, number>>;
  readonly bundleSetHash: string;
  readonly sourceSetHash: string;
  readonly claimSetHash: string;
  readonly hasMore: boolean;
  readonly nextCursor: string | null;
  readonly previewHash: string;
}

export interface HistoricalReportedOutcomeApplyInput {
  readonly afterCursor?: string;
  readonly maxRecords?: number;
  readonly expectedPreviewHash: string;
  readonly acknowledgeReportedOnly: true;
  readonly actorId: string;
  readonly reason: string;
}

export interface HistoricalReportedOutcomeApplyResult {
  readonly previewHash: string;
  readonly reviewedCount: number;
  readonly eligibleCount: number;
  readonly rejectedCount: number;
  readonly insertedCount: number;
  readonly reusedCount: number;
  readonly classificationCounts: Readonly<Record<HistoricalReportedOutcomeClassification, number>>;
  readonly nextCursor: string | null;
  readonly hasMore: boolean;
  readonly resultHash: string;
}

export class HistoricalReportedOutcomeClassificationError extends Error {
  constructor(
    readonly code: "migration_required" | "invalid_request" | "review_mismatch" | "immutable_conflict",
    message: string,
  ) {
    super(message);
    this.name = "HistoricalReportedOutcomeClassificationError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function setHash(values: readonly string[]): string {
  return sha256(canonicalJson([...new Set(values)].sort()));
}

function boundedPageSize(value?: number): number {
  const resolved = value ?? DEFAULT_PAGE_SIZE;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > MAX_PAGE_SIZE) {
    throw new HistoricalReportedOutcomeClassificationError(
      "invalid_request",
      `maxRecords must be an integer between 1 and ${MAX_PAGE_SIZE}`,
    );
  }
  return resolved;
}

function encodeCursor(value: Cursor): string {
  return Buffer.from(canonicalJson(value), "utf8").toString("base64url");
}

function decodeCursor(value?: string): Cursor | null {
  if (!value) return null;
  if (value.length > 2_000) {
    throw new HistoricalReportedOutcomeClassificationError("invalid_request", "cursor is invalid");
  }
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as Record<string, unknown>;
    if (
      !SHA256.test(String(parsed.semanticFingerprint ?? ""))
      || !OPAQUE_ID.test(String(parsed.receiptId ?? ""))
      || !OPAQUE_ID.test(String(parsed.candidateId ?? ""))
    ) throw new Error("invalid");
    return {
      semanticFingerprint: String(parsed.semanticFingerprint),
      receiptId: String(parsed.receiptId),
      candidateId: String(parsed.candidateId),
    };
  } catch {
    throw new HistoricalReportedOutcomeClassificationError("invalid_request", "cursor is invalid");
  }
}

function strictObject(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function containsSensitiveKey(value: unknown, depth = 0): boolean {
  if (depth > 12) return true;
  if (typeof value === "string") {
    const candidate = value.trim();
    if (!(candidate.startsWith("{") || candidate.startsWith("["))) return false;
    try { return containsSensitiveKey(JSON.parse(candidate) as unknown, depth + 1); }
    catch { return false; }
  }
  if (Array.isArray(value)) return value.some((item) => containsSensitiveKey(item, depth + 1));
  if (!value || typeof value !== "object") return false;
  return Object.entries(value as Record<string, unknown>).some(([key, item]) => (
    SENSITIVE_KEY_NAME.test(key) || containsSensitiveKey(item, depth + 1)
  ));
}

function reportedMarker(value: unknown): "success" | "failure" | "mixed" | null {
  if (typeof value !== "string") return null;
  switch (value.trim().toLowerCase().replaceAll("-", "_")) {
    case "worked":
    case "success":
    case "succeeded":
    case "successful":
    case "reported_success":
      return "success";
    case "failed":
    case "failure":
    case "reported_failed":
    case "reported_failure":
      return "failure";
    case "mixed":
    case "reported_mixed":
      return "mixed";
    default:
      return null;
  }
}

function techniqueOrStackContext(knowledge: Record<string, unknown>): boolean {
  if (knowledge.kind === "operational_hazard") return true;
  if (knowledge.kind === "reusable_fact") {
    return isAttackCentricReusableNodeType(knowledge.nodeType as MemoryNodeType);
  }
  if (knowledge.kind !== "reusable_bundle" || !Array.isArray(knowledge.facts)) return false;
  return knowledge.facts.some((fact) => {
    const item = strictObject(fact);
    return item !== null
      && item.nodeType !== "outcome"
      && isAttackCentricReusableNodeType(item.nodeType as MemoryNodeType);
  });
}

function classifySanitizedBundle(value: string): {
  readonly classification: HistoricalReportedOutcomeClassification;
  readonly confidence: number;
  readonly basis: readonly HistoricalReportedOutcomeBasisCategory[];
  readonly rejectionReasons: readonly HistoricalReportedOutcomeRejectionReason[];
} {
  if (
    findReusableMemorySecretCategories(value).length > 0
    || attackKnowledgeOperationalLocatorCategories(value).length > 0
  ) {
    return {
      classification: "unknown",
      confidence: 0,
      basis: ["no_reported_outcome_marker"],
      rejectionReasons: ["reusable_boundary_violation"],
    };
  }
  let root: Record<string, unknown> | null = null;
  try { root = strictObject(JSON.parse(value) as unknown); } catch { root = null; }
  if (root && containsSensitiveKey(root)) {
    return {
      classification: "unknown",
      confidence: 0,
      basis: ["no_reported_outcome_marker"],
      rejectionReasons: ["reusable_boundary_violation"],
    };
  }
  const knowledge = strictObject(root?.knowledge);
  if (!knowledge) {
    return {
      classification: "unknown",
      confidence: 0,
      basis: ["no_reported_outcome_marker"],
      rejectionReasons: ["malformed_sanitized_bundle"],
    };
  }
  if (!techniqueOrStackContext(knowledge)) {
    return {
      classification: "unknown",
      confidence: 0,
      basis: ["no_reported_outcome_marker"],
      rejectionReasons: ["technique_or_stack_context_required"],
    };
  }

  const success: number[] = [];
  const failure: number[] = [];
  const basis = new Set<HistoricalReportedOutcomeBasisCategory>();
  if (knowledge.kind === "operational_hazard" && Array.isArray(knowledge.outcomes)) {
    for (const raw of knowledge.outcomes) {
      const outcome = strictObject(raw);
      const marker = reportedMarker(outcome?.status);
      if (marker === "success" || marker === "mixed") {
        success.push(0.8);
        basis.add("operational_hazard_reported_success");
      }
      if (marker === "failure" || marker === "mixed") {
        failure.push(0.8);
        basis.add("operational_hazard_reported_failure");
      }
    }
  }
  if (knowledge.kind === "reusable_bundle" && Array.isArray(knowledge.facts)) {
    for (const raw of knowledge.facts) {
      const fact = strictObject(raw);
      if (fact?.nodeType !== "outcome" || typeof fact.body !== "string") continue;
      let body: Record<string, unknown> | null = null;
      try { body = strictObject(JSON.parse(fact.body) as unknown); } catch { body = null; }
      if (!body) continue;
      const explicit = reportedMarker(body.reportedOutcome ?? body.reportedStatus);
      if (explicit) {
        if (explicit === "success" || explicit === "mixed") {
          success.push(0.75);
          basis.add(explicit === "mixed"
            ? "structured_outcome_reported_mixed"
            : "structured_outcome_reported_success");
        }
        if (explicit === "failure" || explicit === "mixed") {
          failure.push(0.75);
          basis.add(explicit === "mixed"
            ? "structured_outcome_reported_mixed"
            : "structured_outcome_reported_failure");
        }
        continue;
      }
      if (body.verification !== "candidate") continue;
      const legacy = reportedMarker(body.status);
      if (legacy === "success") {
        success.push(0.65);
        basis.add("legacy_candidate_worked");
      }
      if (legacy === "failure") {
        failure.push(0.65);
        basis.add("legacy_candidate_failed");
      }
    }
  }

  if (success.length > 0 && failure.length > 0) {
    return {
      classification: "mixed",
      confidence: Math.min(Math.max(...success), Math.max(...failure)),
      basis: [...basis].sort(),
      rejectionReasons: [],
    };
  }
  if (success.length > 0) {
    return {
      classification: "reported_success",
      confidence: Math.max(...success),
      basis: [...basis].sort(),
      rejectionReasons: [],
    };
  }
  if (failure.length > 0) {
    return {
      classification: "reported_failure",
      confidence: Math.max(...failure),
      basis: [...basis].sort(),
      rejectionReasons: [],
    };
  }
  return {
    classification: "unknown",
    confidence: 0,
    basis: ["no_reported_outcome_marker"],
    rejectionReasons: [],
  };
}

function emptyCounts(): Record<HistoricalReportedOutcomeClassification, number> {
  return { reported_success: 0, reported_failure: 0, mixed: 0, unknown: 0 };
}

export class HistoricalReportedOutcomeClassificationService {
  readonly #audit: AuditTrailWriter;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {
    for (const table of [
      "historical_reported_outcome_claims",
      "historical_attack_knowledge_bundle_sources",
      "historical_attack_knowledge_import_contexts",
      "historical_attack_knowledge_source_occurrences",
      "legacy_migration_inventory_receipts",
      "legacy_migration_runs",
      "legacy_migration_source_objects",
    ]) {
      if (!database.prepare(
        "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?",
      ).get(table)) {
        throw new HistoricalReportedOutcomeClassificationError(
          "migration_required",
          "Historical reported-outcome schema is not installed",
        );
      }
    }
    this.#audit = new AuditTrailWriter(database);
  }

  preview(input: { readonly afterCursor?: string; readonly maxRecords?: number } = {}): HistoricalReportedOutcomePreview {
    return this.#preview(input).preview;
  }

  apply(input: HistoricalReportedOutcomeApplyInput): HistoricalReportedOutcomeApplyResult {
    if (input.acknowledgeReportedOnly !== true) {
      throw new HistoricalReportedOutcomeClassificationError(
        "invalid_request",
        "Reported-only acknowledgement is required",
      );
    }
    if (!SHA256.test(input.expectedPreviewHash)) {
      throw new HistoricalReportedOutcomeClassificationError("invalid_request", "expectedPreviewHash is invalid");
    }
    const actorId = input.actorId.trim();
    const reason = input.reason.trim();
    if (!actorId || actorId.length > 256 || !reason || reason.length > 1_200) {
      throw new HistoricalReportedOutcomeClassificationError("invalid_request", "actorId or reason is invalid");
    }
    if (
      findReusableMemorySecretCategories(`${actorId}\n${reason}`).length > 0
      || attackKnowledgeOperationalLocatorCategories(reason).length > 0
    ) {
      throw new HistoricalReportedOutcomeClassificationError(
        "invalid_request",
        "Classification authorization must not contain secrets or operational target locators",
      );
    }

    const classified = this.#preview({
      ...(input.afterCursor ? { afterCursor: input.afterCursor } : {}),
      ...(input.maxRecords === undefined ? {} : { maxRecords: input.maxRecords }),
    });
    if (classified.preview.previewHash !== input.expectedPreviewHash) {
      throw new HistoricalReportedOutcomeClassificationError(
        "review_mismatch",
        "Historical reported-outcome preview changed; review the new hash before applying",
      );
    }

    let insertedCount = 0;
    let reusedCount = 0;
    inImmediateTransaction(this.database, () => {
      for (const item of classified.bindings) {
        if (item.disposition !== "eligible") continue;
        const existing = this.database.prepare(`
          SELECT bundle_id, receipt_id, source_candidate_id, source_hash,
            bundle_semantic_fingerprint, classification, classification_confidence,
            basis_categories_json, policy_version, classification_receipt_hash
          FROM historical_reported_outcome_claims WHERE id = ?
        `).get(item.claimId) as ExistingClaimRow | undefined;
        const basisJson = canonicalJson(item.basisCategories);
        if (existing) {
          if (
            existing.bundle_id !== item.row.bundle_id
            || existing.receipt_id !== item.row.receipt_id
            || existing.source_candidate_id !== item.row.candidate_id
            || existing.source_hash !== item.row.source_hash
            || existing.bundle_semantic_fingerprint !== item.row.semantic_fingerprint
            || existing.classification !== item.classification
            || Number(existing.classification_confidence) !== item.classificationConfidence
            || existing.basis_categories_json !== basisJson
            || existing.policy_version !== HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION
            || existing.classification_receipt_hash !== item.classificationReceiptHash
          ) {
            throw new HistoricalReportedOutcomeClassificationError(
              "immutable_conflict",
              "Existing historical reported-outcome claim differs from the reviewed classification",
            );
          }
          reusedCount += 1;
          continue;
        }
        const now = this.clock().toISOString();
        const auditId = this.#audit.append({
          missionId: item.row.mission_id,
          ...(item.row.run_id ? { runId: item.row.run_id } : {}),
          actor: { type: "operator", id: actorId },
          action: "historical_reported_outcome.classified",
          resourceType: "historical_reported_outcome_claim",
          resourceId: item.claimId,
          reason,
          details: {
            reportedOnly: true,
            verifiedOutcome: false,
            policyVersion: HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION,
            classification: item.classification,
            classificationConfidence: item.classificationConfidence,
            bundleFingerprint: item.row.semantic_fingerprint,
            sourceHash: item.row.source_hash,
            classificationReceiptHash: item.classificationReceiptHash,
            reviewHash: classified.preview.previewHash,
          },
          occurredAt: now,
        });
        const audit = this.database.prepare(
          "SELECT record_hash FROM audit_records WHERE id = ?",
        ).get(auditId) as { readonly record_hash: string };
        this.database.prepare(`
          INSERT INTO historical_reported_outcome_claims (
            id, bundle_id, receipt_id, source_candidate_id, source_hash,
            bundle_semantic_fingerprint, classification, classification_confidence,
            basis_categories_json, policy_version, classification_receipt_hash,
            review_hash, actor_id, reason, audit_record_id, audit_record_hash, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          item.claimId,
          item.row.bundle_id,
          item.row.receipt_id,
          item.row.candidate_id,
          item.row.source_hash,
          item.row.semantic_fingerprint,
          item.classification,
          item.classificationConfidence,
          basisJson,
          HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION,
          item.classificationReceiptHash,
          classified.preview.previewHash,
          actorId,
          reason,
          auditId,
          audit.record_hash,
          now,
        );
        insertedCount += 1;
      }
    });
    const resultWithoutHash = {
      previewHash: classified.preview.previewHash,
      reviewedCount: classified.preview.reviewedCount,
      eligibleCount: classified.preview.eligibleCount,
      rejectedCount: classified.preview.rejectedCount,
      insertedCount,
      reusedCount,
      classificationCounts: classified.preview.classificationCounts,
      nextCursor: classified.preview.nextCursor,
      hasMore: classified.preview.hasMore,
    };
    return { ...resultWithoutHash, resultHash: sha256(canonicalJson(resultWithoutHash)) };
  }

  #preview(input: { readonly afterCursor?: string; readonly maxRecords?: number }): {
    readonly preview: HistoricalReportedOutcomePreview;
    readonly bindings: readonly ClassifiedBinding[];
  } {
    const after = decodeCursor(input.afterCursor);
    const maxRecords = boundedPageSize(input.maxRecords);
    const rows = this.#page(after, maxRecords + 1);
    const hasMore = rows.length > maxRecords;
    const selected = rows.slice(0, maxRecords);
    const bindings = selected.map((row): ClassifiedBinding => {
      const rejectionReasons: HistoricalReportedOutcomeRejectionReason[] = [];
      if (
        row.bundle_id !== `akb_${row.semantic_fingerprint}`
        || sha256(row.sanitized_bundle_json) !== row.semantic_fingerprint
      ) rejectionReasons.push("bundle_integrity_mismatch");
      const classification = classifySanitizedBundle(row.sanitized_bundle_json);
      rejectionReasons.push(...classification.rejectionReasons);
      const identity = {
        bundleFingerprint: row.semantic_fingerprint,
        receiptId: row.receipt_id,
        sourceCandidateId: row.candidate_id,
        policyVersion: HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION,
      };
      const claimId = `hroc_${sha256(canonicalJson(identity))}`;
      const classificationReceiptHash = sha256(canonicalJson({
        ...identity,
        sourceHash: row.source_hash,
        classification: classification.classification,
        classificationConfidence: classification.confidence,
        basisCategories: classification.basis,
        reportedOnly: true,
        verifiedOutcome: false,
      }));
      return {
        row,
        claimId,
        classification: classification.classification,
        classificationConfidence: classification.confidence,
        basisCategories: classification.basis,
        classificationReceiptHash,
        disposition: rejectionReasons.length === 0 ? "eligible" : "rejected",
        rejectionReasons: [...new Set(rejectionReasons)].sort(),
      };
    });
    const entries = bindings.map((item): HistoricalReportedOutcomeReviewEntry => ({
      bundleFingerprint: item.row.semantic_fingerprint,
      sourceHash: item.row.source_hash,
      claimKeyHash: sha256(item.claimId),
      classification: item.classification,
      classificationConfidence: item.classificationConfidence,
      basisCategories: item.basisCategories,
      classificationReceiptHash: item.classificationReceiptHash,
      disposition: item.disposition,
      rejectionReasons: item.rejectionReasons,
    }));
    const counts = emptyCounts();
    bindings.filter(({ disposition }) => disposition === "eligible")
      .forEach(({ classification }) => { counts[classification] += 1; });
    const last = selected.at(-1);
    const nextCursor = hasMore && last
      ? encodeCursor({
          semanticFingerprint: last.semantic_fingerprint,
          receiptId: last.receipt_id,
          candidateId: last.candidate_id,
        })
      : null;
    const withoutHash = {
      schemaVersion: "ti_scale.historical_reported_outcome_preview/v1" as const,
      policyVersion: HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION,
      dryRun: true as const,
      selection: {
        afterCursor: input.afterCursor ?? null,
        maxRecords,
      },
      entries,
      reviewedCount: entries.length,
      eligibleCount: entries.filter(({ disposition }) => disposition === "eligible").length,
      rejectedCount: entries.filter(({ disposition }) => disposition === "rejected").length,
      classificationCounts: Object.freeze({ ...counts }),
      bundleSetHash: setHash(entries.map(({ bundleFingerprint }) => bundleFingerprint)),
      sourceSetHash: setHash(entries.map(({ sourceHash }) => sourceHash)),
      claimSetHash: setHash(entries.map(({ classificationReceiptHash }) => classificationReceiptHash)),
      hasMore,
      nextCursor,
    };
    return {
      preview: { ...withoutHash, previewHash: sha256(canonicalJson(withoutHash)) },
      bindings,
    };
  }

  #page(after: Cursor | null, limit: number): SourceBindingRow[] {
    return this.database.prepare(`
      SELECT bundle.id AS bundle_id, bundle.semantic_fingerprint,
        bundle.sanitized_bundle_json, source.receipt_id, source.candidate_id,
        source.source_hash, candidate.mission_id, candidate.run_id
      FROM historical_attack_knowledge_bundle_sources source
      JOIN attack_knowledge_bundles bundle ON bundle.id = source.bundle_id
      JOIN attack_knowledge_provenance_receipts receipt ON receipt.id = source.receipt_id
      JOIN evidence_candidates candidate ON candidate.id = source.candidate_id
      WHERE receipt.source_class = 'historical'
        AND candidate.sensitivity = 'private'
        AND candidate.proposed_by = 'system:historical-attack-knowledge-extractor'
        AND (
          bundle.semantic_fingerprint > ?
          OR (bundle.semantic_fingerprint = ? AND source.receipt_id > ?)
          OR (bundle.semantic_fingerprint = ? AND source.receipt_id = ? AND source.candidate_id > ?)
        )
        AND EXISTS (
          SELECT 1
          FROM historical_attack_knowledge_source_occurrences occurrence
          JOIN historical_attack_knowledge_import_contexts context
            ON context.migration_id = occurrence.migration_id
          JOIN legacy_migration_runs migration ON migration.id = occurrence.migration_id
          JOIN legacy_migration_inventory_receipts inventory
            ON inventory.migration_id = migration.id
          WHERE occurrence.candidate_id = source.candidate_id
            AND occurrence.source_hash = source.source_hash
            AND migration.status = 'completed'
            AND migration.source_retention = 'verified-reference'
            AND migration.brain_projection_mode = 'attack-knowledge-only'
            AND EXISTS (
              SELECT 1 FROM legacy_migration_source_objects object
              WHERE object.migration_id = occurrence.migration_id
                AND object.source_reference = occurrence.source_reference
                AND object.source_sha256 = occurrence.source_hash
                AND object.verification_status = 'verified_reference'
                AND object.object_kind IN ('accepted', 'source')
            )
        )
      ORDER BY bundle.semantic_fingerprint, source.receipt_id, source.candidate_id
      LIMIT ?
    `).all(
      after?.semanticFingerprint ?? "",
      after?.semanticFingerprint ?? "",
      after?.receiptId ?? "",
      after?.semanticFingerprint ?? "",
      after?.receiptId ?? "",
      after?.candidateId ?? "",
      limit,
    ) as SourceBindingRow[];
  }
}

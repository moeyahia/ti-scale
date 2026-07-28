import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { ACTION_CLASS_IDS } from "../domain/catalog-ids";
import {
  isAttackCentricReusableNodeType,
  type MemoryNodeType,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";

const SHA256 = /^[a-f0-9]{64}$/u;
const DEFAULT_PAGE_SIZE = 250;
const MAX_PAGE_SIZE = 1_000;
const DEFAULT_MAX_PAGES = 100;
const MAX_PAGES = 1_000;
const DEFAULT_MAX_DURATION_MS = 120_000;
const MAX_DURATION_MS = 3_600_000;
const ACTION_CLASSES = new Set<string>(ACTION_CLASS_IDS);

export const HISTORICAL_ATTACK_ATTEMPT_OUTCOME_POLICY_VERSION =
  "historical-attack-attempt-outcome/v1" as const;

export const HISTORICAL_ATTACK_ATTEMPT_OUTCOME_REASONS = [
  "bundle_integrity_mismatch",
  "historical_source_receipt_required",
  "canonical_attack_attempt_required",
  "exact_mission_run_binding_required",
  "synthetic_import_context_not_execution_binding",
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
] as const;

export type HistoricalAttackAttemptOutcomeReason =
  (typeof HISTORICAL_ATTACK_ATTEMPT_OUTCOME_REASONS)[number];

interface BundleRow {
  readonly id: string;
  readonly semantic_fingerprint: string;
  readonly sanitized_bundle_json: string;
}

interface SourceReceiptRow {
  readonly source_hash: string;
}

interface MissionRunBindingRow {
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly synthetic_import_context: number;
}

interface EvidenceRow extends MissionRunBindingRow {
  readonly id: string;
  readonly evidence_type: string;
  readonly content_hash: string;
  readonly verification_state: string;
  readonly verified_custody: number;
}

interface ReusableNodeRow {
  readonly id: string;
  readonly node_type: string;
  readonly scope: string;
  readonly engagement_id: string | null;
  readonly mission_id: string | null;
  readonly lifecycle_status: string;
  readonly confirmation_state: string;
}

interface AttackAttemptRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string | null;
  readonly target_asset_id: string | null;
  readonly target_service_id: string | null;
  readonly objective: string;
  readonly technique_id: string | null;
  readonly technique_name: string;
  readonly action_class: string;
  readonly status: string;
  readonly outcome_summary: string | null;
  readonly failure_category: string | null;
  readonly ended_at: string | null;
  readonly action_type: string | null;
  readonly binding_action_class: string | null;
  readonly normalized_arguments_json: string | null;
  readonly scoped_target: string | null;
  readonly binding_hash: string | null;
}

interface AttemptEvidenceRow {
  readonly id: string;
  readonly relationship: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly evidence_type: string;
  readonly content_hash: string;
  readonly verification_state: string;
  readonly verified_custody: number;
}

interface KnowledgeContextRow {
  readonly procedure_node_id: string;
  readonly procedure_version_node_id: string | null;
  readonly product_node_ids_json: string;
  readonly version_node_ids_json: string;
  readonly stack_node_ids_json: string;
  readonly prerequisite_node_ids_json: string;
  readonly observed_state_node_ids_json: string;
}

interface CountRow {
  readonly count: number;
}

export interface HistoricalAttackAttemptOutcomeReviewEntry {
  /** SHA-256 identity of the reusable bundle; no source path or content. */
  readonly bundleFingerprint: string;
  /** SHA-256 over the sorted historical receipt hashes. */
  readonly sourceSetHash: string;
  readonly sourceReceiptCount: number;
  /** SHA-256 over the sorted canonical evidence content hashes. */
  readonly evidenceSetHash: string;
  readonly canonicalEvidenceCount: number;
  readonly reviewedReusableNodeCount: number;
  readonly reportedOutcomeClaim: boolean;
  readonly candidateAttemptCount: number;
  readonly eligibleAttemptCount: number;
  readonly eligibleOutcomeBindingCount: number;
  readonly successBindingCount: number;
  readonly failedBindingCount: number;
  /** Opaque SHA-256 receipts for eligible attempt/node/evidence combinations. */
  readonly eligibleBindingHashes: readonly string[];
  readonly disposition: "eligible" | "rejected";
  readonly reasonCategories: readonly HistoricalAttackAttemptOutcomeReason[];
}

export interface HistoricalAttackAttemptOutcomeReviewDocument {
  readonly schemaVersion: 1;
  readonly policyVersion: typeof HISTORICAL_ATTACK_ATTEMPT_OUTCOME_POLICY_VERSION;
  readonly dryRun: true;
  readonly selection: {
    readonly afterBundleFingerprint: string | null;
    readonly maxRecords: number;
  };
  readonly entries: readonly HistoricalAttackAttemptOutcomeReviewEntry[];
  readonly hasMore: boolean;
  readonly nextCursor: string | null;
}

export interface HistoricalAttackAttemptOutcomePreview {
  readonly previewHash: string;
  readonly reviewedCount: number;
  readonly eligibleCount: number;
  readonly rejectedCount: number;
  readonly review: HistoricalAttackAttemptOutcomeReviewDocument;
}

export interface HistoricalAttackAttemptOutcomeAudit {
  readonly schemaVersion: 1;
  readonly policyVersion: typeof HISTORICAL_ATTACK_ATTEMPT_OUTCOME_POLICY_VERSION;
  readonly dryRun: true;
  readonly status: "completed" | "partial";
  readonly pageCount: number;
  readonly reviewedCount: number;
  readonly eligibleCount: number;
  readonly rejectedCount: number;
  readonly successBindingCount: number;
  readonly failedBindingCount: number;
  readonly reasonCounts: Readonly<Record<HistoricalAttackAttemptOutcomeReason, number>>;
  readonly reviewedBundleSetHash: string;
  readonly eligibleBundleSetHash: string;
  readonly rejectedBundleSetHash: string;
  readonly sourceSetHash: string;
  readonly evidenceSetHash: string;
  readonly pageSetHash: string;
  readonly nextCursor: string | null;
  readonly reportHash: string;
}

export interface HistoricalAttackAttemptOutcomeAuditInput {
  readonly afterBundleFingerprint?: string;
  readonly maxRecordsPerPage?: number;
  readonly maxPages?: number;
  readonly maxDurationMs?: number;
}

export class HistoricalAttackAttemptOutcomePlannerError extends Error {
  constructor(
    readonly code: "migration_required" | "invalid_request",
    message: string,
  ) {
    super(message);
    this.name = "HistoricalAttackAttemptOutcomePlannerError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function setHash(values: readonly string[]): string {
  return sha256(canonicalJson([...new Set(values)].sort()));
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new HistoricalAttackAttemptOutcomePlannerError(
      "invalid_request",
      `${label} must be an integer between ${minimum} and ${maximum}`,
    );
  }
  return resolved;
}

function cursor(value: string | undefined): string {
  const normalized = value?.trim().toLowerCase() ?? "";
  if (normalized && !SHA256.test(normalized)) {
    throw new HistoricalAttackAttemptOutcomePlannerError(
      "invalid_request",
      "The historical outcome cursor must be a lowercase SHA-256 digest",
    );
  }
  return normalized;
}

function nonEmpty(value: string | null | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

function validTimestamp(value: string | null): boolean {
  return nonEmpty(value) && Number.isFinite(Date.parse(value!));
}

function parseStringArray(value: string): readonly string[] | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) && parsed.every((item) => typeof item === "string")
      ? parsed
      : null;
  } catch {
    return null;
  }
}

function parseObject(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function hasReportedOutcomeClaim(sanitizedBundleJson: string): boolean {
  const root = parseObject(sanitizedBundleJson);
  const knowledge = root?.knowledge;
  if (!knowledge || typeof knowledge !== "object" || Array.isArray(knowledge)) return false;
  const record = knowledge as Record<string, unknown>;
  if (record.nodeType === "outcome") return true;
  if (Array.isArray(record.outcomes) && record.outcomes.length > 0) return true;
  return Array.isArray(record.facts) && record.facts.some((fact) => {
    return Boolean(
      fact && typeof fact === "object" && !Array.isArray(fact)
      && (fact as { readonly nodeType?: unknown }).nodeType === "outcome",
    );
  });
}

function allContextNodeIds(context: KnowledgeContextRow | undefined): ReadonlySet<string> {
  if (!context) return new Set();
  const arrays = [
    context.product_node_ids_json,
    context.version_node_ids_json,
    context.stack_node_ids_json,
    context.prerequisite_node_ids_json,
    context.observed_state_node_ids_json,
  ].map(parseStringArray);
  if (arrays.some((value) => value === null)) return new Set();
  return new Set([
    context.procedure_node_id,
    ...(context.procedure_version_node_id ? [context.procedure_version_node_id] : []),
    ...arrays.flatMap((value) => value ?? []),
  ]);
}

function actionBindingIsValid(attempt: AttackAttemptRow): boolean {
  if (
    !nonEmpty(attempt.action_type)
    || !nonEmpty(attempt.binding_action_class)
    || attempt.binding_action_class !== attempt.action_class
    || !nonEmpty(attempt.scoped_target)
    || !nonEmpty(attempt.binding_hash)
    || !attempt.normalized_arguments_json
  ) return false;
  const normalizedArguments = parseObject(attempt.normalized_arguments_json);
  if (!normalizedArguments) return false;
  const expected = sha256(canonicalJson({
    missionId: attempt.mission_id,
    runId: attempt.run_id,
    stepId: attempt.step_id,
    actionType: attempt.action_type,
    actionClass: attempt.binding_action_class,
    normalizedArguments,
    scopedTarget: attempt.scoped_target,
  }));
  return expected === attempt.binding_hash;
}

function emptyReasonCounts(): Record<HistoricalAttackAttemptOutcomeReason, number> {
  return Object.fromEntries(
    HISTORICAL_ATTACK_ATTEMPT_OUTCOME_REASONS.map((reason) => [reason, 0]),
  ) as Record<HistoricalAttackAttemptOutcomeReason, number>;
}

/**
 * Read-only, hash-only audit of historical material against migration 033's
 * canonical outcome boundary. It never creates an AttackAttempt and never
 * interprets narrative text as a terminal result.
 */
export class HistoricalAttackAttemptOutcomeDryRunPlanner {
  constructor(private readonly database: SqliteDatabase) {
    for (const table of [
      "reusable_knowledge_outcome_links",
      "attack_attempts",
      "attack_attempt_knowledge_contexts",
      "attack_attempt_evidence",
      "attack_knowledge_bundles",
      "attack_knowledge_bundle_receipts",
      "attack_knowledge_provenance_receipts",
      "attack_knowledge_bundle_evidence_bindings",
      "historical_attack_knowledge_import_contexts",
    ]) {
      if (!this.database.prepare(
        "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?",
      ).get(table)) {
        throw new HistoricalAttackAttemptOutcomePlannerError(
          "migration_required",
          "Historical outcome review requires the schema-33 integrity boundary",
        );
      }
    }
  }

  preview(input: {
    readonly afterBundleFingerprint?: string;
    readonly maxRecords?: number;
  } = {}): HistoricalAttackAttemptOutcomePreview {
    const after = cursor(input.afterBundleFingerprint);
    const maxRecords = boundedInteger(input.maxRecords, DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE, "Page size");
    const rows = this.database.prepare(`
      SELECT bundle.id, bundle.semantic_fingerprint, bundle.sanitized_bundle_json
      FROM attack_knowledge_bundles bundle
      WHERE bundle.semantic_fingerprint > ?
        AND EXISTS (
          SELECT 1
          FROM attack_knowledge_bundle_receipts binding
          JOIN attack_knowledge_provenance_receipts receipt ON receipt.id = binding.receipt_id
          WHERE binding.bundle_id = bundle.id AND receipt.source_class = 'historical'
        )
      ORDER BY bundle.semantic_fingerprint
      LIMIT ?
    `).all(after, maxRecords + 1) as BundleRow[];
    const selected = rows.slice(0, maxRecords);
    const entries = selected.map((bundle) => this.#reviewBundle(bundle));
    const hasMore = rows.length > maxRecords;
    const nextCursor = hasMore && entries.length > 0
      ? entries.at(-1)!.bundleFingerprint
      : null;
    const review: HistoricalAttackAttemptOutcomeReviewDocument = {
      schemaVersion: 1,
      policyVersion: HISTORICAL_ATTACK_ATTEMPT_OUTCOME_POLICY_VERSION,
      dryRun: true,
      selection: {
        afterBundleFingerprint: after || null,
        maxRecords,
      },
      entries,
      hasMore,
      nextCursor,
    };
    return {
      previewHash: sha256(canonicalJson(review)),
      reviewedCount: entries.length,
      eligibleCount: entries.filter(({ disposition }) => disposition === "eligible").length,
      rejectedCount: entries.filter(({ disposition }) => disposition === "rejected").length,
      review,
    };
  }

  audit(input: HistoricalAttackAttemptOutcomeAuditInput = {}): HistoricalAttackAttemptOutcomeAudit {
    const maxRecordsPerPage = boundedInteger(
      input.maxRecordsPerPage,
      DEFAULT_PAGE_SIZE,
      1,
      MAX_PAGE_SIZE,
      "Page size",
    );
    const maxPages = boundedInteger(input.maxPages, DEFAULT_MAX_PAGES, 1, MAX_PAGES, "Page budget");
    const maxDurationMs = boundedInteger(
      input.maxDurationMs,
      DEFAULT_MAX_DURATION_MS,
      1,
      MAX_DURATION_MS,
      "Duration budget",
    );
    let nextCursor = cursor(input.afterBundleFingerprint) || null;
    let hasMore = true;
    let pageCount = 0;
    const started = performance.now();
    const entries: HistoricalAttackAttemptOutcomeReviewEntry[] = [];
    const pageHashes: string[] = [];
    while (hasMore && pageCount < maxPages && performance.now() - started < maxDurationMs) {
      const page = this.preview({
        afterBundleFingerprint: nextCursor ?? undefined,
        maxRecords: maxRecordsPerPage,
      });
      entries.push(...page.review.entries);
      pageHashes.push(page.previewHash);
      pageCount += 1;
      hasMore = page.review.hasMore;
      nextCursor = page.review.nextCursor;
      if (page.review.entries.length === 0) break;
    }
    const reasonCounts = emptyReasonCounts();
    for (const entry of entries) {
      for (const reason of entry.reasonCategories) reasonCounts[reason] += 1;
    }
    const eligible = entries.filter(({ disposition }) => disposition === "eligible");
    const rejected = entries.filter(({ disposition }) => disposition === "rejected");
    const reportWithoutHash = {
      schemaVersion: 1 as const,
      policyVersion: HISTORICAL_ATTACK_ATTEMPT_OUTCOME_POLICY_VERSION,
      dryRun: true as const,
      status: hasMore ? "partial" as const : "completed" as const,
      pageCount,
      reviewedCount: entries.length,
      eligibleCount: eligible.length,
      rejectedCount: rejected.length,
      successBindingCount: entries.reduce((sum, entry) => sum + entry.successBindingCount, 0),
      failedBindingCount: entries.reduce((sum, entry) => sum + entry.failedBindingCount, 0),
      reasonCounts,
      reviewedBundleSetHash: setHash(entries.map(({ bundleFingerprint }) => bundleFingerprint)),
      eligibleBundleSetHash: setHash(eligible.map(({ bundleFingerprint }) => bundleFingerprint)),
      rejectedBundleSetHash: setHash(rejected.map(({ bundleFingerprint }) => bundleFingerprint)),
      sourceSetHash: setHash(entries.map(({ sourceSetHash }) => sourceSetHash)),
      evidenceSetHash: setHash(entries.map(({ evidenceSetHash }) => evidenceSetHash)),
      pageSetHash: setHash(pageHashes),
      nextCursor: hasMore ? nextCursor : null,
    };
    return {
      ...reportWithoutHash,
      reportHash: sha256(canonicalJson(reportWithoutHash)),
    };
  }

  #reviewBundle(bundle: BundleRow): HistoricalAttackAttemptOutcomeReviewEntry {
    const baseReasons = new Set<HistoricalAttackAttemptOutcomeReason>();
    if (
      bundle.id !== `akb_${bundle.semantic_fingerprint}`
      || sha256(bundle.sanitized_bundle_json) !== bundle.semantic_fingerprint
    ) baseReasons.add("bundle_integrity_mismatch");

    const sourceReceipts = this.database.prepare(`
      SELECT DISTINCT receipt.source_hash
      FROM attack_knowledge_bundle_receipts binding
      JOIN attack_knowledge_provenance_receipts receipt ON receipt.id = binding.receipt_id
      WHERE binding.bundle_id = ? AND receipt.source_class = 'historical'
      ORDER BY receipt.source_hash
    `).all(bundle.id) as SourceReceiptRow[];
    if (sourceReceipts.length === 0) baseReasons.add("historical_source_receipt_required");

    const evidence = this.database.prepare(`
      SELECT DISTINCT canonical.id, canonical.mission_id, canonical.run_id,
        canonical.evidence_type, canonical.content_hash, canonical.verification_state,
        CASE WHEN EXISTS (
          SELECT 1 FROM evidence_chain_events custody
          WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified'
        ) THEN 1 ELSE 0 END AS verified_custody,
        CASE WHEN EXISTS (
          SELECT 1 FROM historical_attack_knowledge_import_contexts context
          WHERE context.mission_id = canonical.mission_id AND context.run_id = canonical.run_id
        ) THEN 1 ELSE 0 END AS synthetic_import_context
      FROM evidence canonical
      WHERE canonical.id IN (
        SELECT binding.evidence_id
        FROM attack_knowledge_bundle_evidence_bindings binding
        WHERE binding.bundle_id = ?
        UNION
        SELECT binding.evidence_id
        FROM historical_attack_knowledge_verified_bundle_links binding
        WHERE binding.bundle_id = ?
      )
      ORDER BY canonical.content_hash, canonical.id
    `).all(bundle.id, bundle.id) as EvidenceRow[];
    const verifiedEvidence = evidence.filter(({ verification_state, evidence_type }) => {
      return verification_state === "verified" && evidence_type.trim().toLowerCase() !== "command_output";
    });
    const custodyEvidence = verifiedEvidence.filter(({ verified_custody }) => verified_custody === 1);
    if (verifiedEvidence.length === 0) baseReasons.add("verified_non_command_evidence_required");
    if (custodyEvidence.length === 0) baseReasons.add("verified_evidence_custody_required");

    const bindingRows = this.database.prepare(`
      SELECT DISTINCT candidate.mission_id, candidate.run_id,
        CASE WHEN EXISTS (
          SELECT 1 FROM historical_attack_knowledge_import_contexts context
          WHERE context.mission_id = candidate.mission_id AND context.run_id = candidate.run_id
        ) THEN 1 ELSE 0 END AS synthetic_import_context
      FROM historical_attack_knowledge_bundle_sources source
      JOIN evidence_candidates candidate ON candidate.id = source.candidate_id
      WHERE source.bundle_id = ?
      UNION
      SELECT DISTINCT canonical.mission_id, canonical.run_id,
        CASE WHEN EXISTS (
          SELECT 1 FROM historical_attack_knowledge_import_contexts context
          WHERE context.mission_id = canonical.mission_id AND context.run_id = canonical.run_id
        ) THEN 1 ELSE 0 END AS synthetic_import_context
      FROM evidence canonical
      WHERE canonical.id IN (
        SELECT evidence_id FROM attack_knowledge_bundle_evidence_bindings WHERE bundle_id = ?
        UNION SELECT evidence_id FROM historical_attack_knowledge_verified_bundle_links WHERE bundle_id = ?
      )
      ORDER BY mission_id, run_id
    `).all(bundle.id, bundle.id, bundle.id) as MissionRunBindingRow[];
    const exactBindingRows = bindingRows.filter((binding) => {
      if (!binding.run_id || binding.synthetic_import_context === 1) return false;
      const run = this.database.prepare(
        "SELECT COUNT(*) AS count FROM runs WHERE id = ? AND mission_id = ?",
      ).get(binding.run_id, binding.mission_id) as CountRow;
      return Number(run.count) === 1;
    });
    if (
      exactBindingRows.length === 0
      && bindingRows.some(({ synthetic_import_context }) => synthetic_import_context === 1)
    ) {
      baseReasons.add("synthetic_import_context_not_execution_binding");
    }
    if (exactBindingRows.length === 0) baseReasons.add("exact_mission_run_binding_required");

    const reusableNodes = this.database.prepare(`
      SELECT DISTINCT node.id, node.node_type, node.scope, node.engagement_id,
        node.mission_id, node.lifecycle_status, node.confirmation_state
      FROM attack_knowledge_bundle_candidates binding
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = binding.content_fingerprint
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      JOIN memory_nodes node ON node.id = candidate.proposed_node_id
      WHERE binding.bundle_id = ?
      ORDER BY node.id
    `).all(bundle.id) as ReusableNodeRow[];
    const reviewedReusableNodes = reusableNodes.filter((node) => {
      return isAttackCentricReusableNodeType(node.node_type as MemoryNodeType)
        && node.scope === "global"
        && node.engagement_id === null
        && node.mission_id === null
        && node.lifecycle_status === "verified"
        && node.confirmation_state === "confirmed";
    });
    if (reviewedReusableNodes.length === 0) {
      baseReasons.add("reviewed_reusable_membership_required");
    }

    const attempts = new Map<string, AttackAttemptRow>();
    const selectAttempts = this.database.prepare(`
      SELECT attempt.id, attempt.mission_id, attempt.run_id, attempt.step_id,
        attempt.target_asset_id, attempt.target_service_id, attempt.objective,
        attempt.technique_id, attempt.technique_name, attempt.action_class,
        attempt.status, attempt.outcome_summary, attempt.failure_category,
        attempt.ended_at, binding.action_type,
        binding.action_class AS binding_action_class,
        binding.normalized_arguments_json, binding.scoped_target, binding.binding_hash
      FROM attack_attempts attempt
      LEFT JOIN attack_attempt_action_bindings binding ON binding.attack_attempt_id = attempt.id
      WHERE attempt.mission_id = ? AND attempt.run_id = ?
      ORDER BY attempt.id
    `);
    for (const binding of bindingRows) {
      if (!binding.run_id) continue;
      const rows = selectAttempts.all(binding.mission_id, binding.run_id) as AttackAttemptRow[];
      rows.forEach((attempt) => attempts.set(attempt.id, attempt));
    }
    if (attempts.size === 0) {
      baseReasons.add("canonical_attack_attempt_required");
      baseReasons.add("typed_intent_required");
      baseReasons.add("typed_technique_required");
      baseReasons.add("typed_target_context_required");
      baseReasons.add("represented_action_binding_required");
      baseReasons.add("terminal_outcome_required");
      baseReasons.add("verified_outcome_evidence_binding_required");
      baseReasons.add("reviewed_reusable_membership_required");
    }

    const outcomeCandidateCount = this.database.prepare(`
      SELECT COUNT(*) AS count
      FROM attack_knowledge_bundle_candidates binding
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = binding.content_fingerprint
      WHERE binding.bundle_id = ? AND registry.node_type = 'outcome'
    `).get(bundle.id) as CountRow;
    const hasReportedClaim = hasReportedOutcomeClaim(bundle.sanitized_bundle_json)
      || Number(outcomeCandidateCount.count) > 0;

    const eligibleBindingHashes: string[] = [];
    let eligibleAttemptCount = 0;
    let successBindingCount = 0;
    let failedBindingCount = 0;
    const attemptFailureReasons = new Set<HistoricalAttackAttemptOutcomeReason>();
    for (const attempt of attempts.values()) {
      const reasons = new Set<HistoricalAttackAttemptOutcomeReason>();
      const exactPair = exactBindingRows.some(({ mission_id, run_id }) => {
        return mission_id === attempt.mission_id && run_id === attempt.run_id;
      });
      if (!exactPair) reasons.add("exact_mission_run_binding_required");
      if (!nonEmpty(attempt.objective)) reasons.add("typed_intent_required");
      if (
        !nonEmpty(attempt.technique_name)
        || !nonEmpty(attempt.action_class)
        || !ACTION_CLASSES.has(attempt.action_class)
      ) {
        reasons.add("typed_technique_required");
      }
      if (!actionBindingIsValid(attempt)) reasons.add("represented_action_binding_required");
      if (!this.#targetContextIsValid(attempt)) reasons.add("typed_target_context_required");
      const outcomeTag = attempt.status === "succeeded"
        ? "success" as const
        : attempt.status === "failed"
          ? "failed" as const
          : null;
      if (
        !outcomeTag
        || !validTimestamp(attempt.ended_at)
        || !nonEmpty(attempt.outcome_summary)
        || (outcomeTag === "failed" && !nonEmpty(attempt.failure_category))
      ) reasons.add("terminal_outcome_required");

      const context = this.database.prepare(`
        SELECT procedure_node_id, procedure_version_node_id,
          product_node_ids_json, version_node_ids_json, stack_node_ids_json,
          prerequisite_node_ids_json, observed_state_node_ids_json
        FROM attack_attempt_knowledge_contexts WHERE attack_attempt_id = ?
      `).get(attempt.id) as KnowledgeContextRow | undefined;
      const contextNodeIds = allContextNodeIds(context);
      const matchedNodes = reviewedReusableNodes.filter(({ id }) => contextNodeIds.has(id));
      if (matchedNodes.length === 0) reasons.add("reviewed_reusable_membership_required");

      const attemptEvidence = this.database.prepare(`
        SELECT DISTINCT canonical.id, link.relationship, canonical.mission_id,
          canonical.run_id, canonical.evidence_type, canonical.content_hash,
          canonical.verification_state,
          CASE WHEN EXISTS (
            SELECT 1 FROM evidence_chain_events custody
            WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified'
          ) THEN 1 ELSE 0 END AS verified_custody
        FROM attack_attempt_evidence link
        JOIN evidence canonical ON canonical.id = link.evidence_id
        WHERE link.attack_attempt_id = ?
          AND canonical.id IN (
            SELECT evidence_id FROM attack_knowledge_bundle_evidence_bindings WHERE bundle_id = ?
            UNION SELECT evidence_id FROM historical_attack_knowledge_verified_bundle_links WHERE bundle_id = ?
          )
        ORDER BY canonical.content_hash, canonical.id
      `).all(attempt.id, bundle.id, bundle.id) as AttemptEvidenceRow[];
      const exactEvidence = attemptEvidence.filter((proof) => {
        return ["supports", "outcome"].includes(proof.relationship)
          && proof.mission_id === attempt.mission_id
          && proof.run_id === attempt.run_id
          && proof.verification_state === "verified"
          && proof.evidence_type.trim().toLowerCase() !== "command_output"
          && proof.verified_custody === 1;
      });
      if (exactEvidence.length === 0) reasons.add("verified_outcome_evidence_binding_required");
      if (
        hasReportedClaim
        && exactEvidence.length > 0
        && exactEvidence.every(({ evidence_type }) => {
          return evidence_type.trim().toLowerCase() === "historical_attack_source_record";
        })
      ) reasons.add("reported_prose_not_authoritative");

      if (reasons.size === 0 && outcomeTag) {
        eligibleAttemptCount += 1;
        for (const node of matchedNodes) {
          for (const proof of exactEvidence) {
            eligibleBindingHashes.push(sha256(canonicalJson({
              bundleFingerprint: bundle.semantic_fingerprint,
              attackAttemptId: attempt.id,
              memoryNodeId: node.id,
              evidenceContentHash: proof.content_hash,
              outcomeTag,
            })));
            if (outcomeTag === "success") successBindingCount += 1;
            else failedBindingCount += 1;
          }
        }
      } else {
        reasons.forEach((reason) => attemptFailureReasons.add(reason));
      }
    }
    if (eligibleAttemptCount === 0) {
      attemptFailureReasons.forEach((reason) => baseReasons.add(reason));
      if (hasReportedClaim) baseReasons.add("reported_prose_not_authoritative");
    }
    const reasons = [...baseReasons].sort();
    return {
      bundleFingerprint: bundle.semantic_fingerprint,
      sourceSetHash: setHash(sourceReceipts.map(({ source_hash }) => source_hash)),
      sourceReceiptCount: sourceReceipts.length,
      evidenceSetHash: setHash(evidence.map(({ content_hash }) => content_hash)),
      canonicalEvidenceCount: evidence.length,
      reviewedReusableNodeCount: reviewedReusableNodes.length,
      reportedOutcomeClaim: hasReportedClaim,
      candidateAttemptCount: attempts.size,
      eligibleAttemptCount,
      eligibleOutcomeBindingCount: eligibleBindingHashes.length,
      successBindingCount,
      failedBindingCount,
      eligibleBindingHashes: eligibleBindingHashes.sort(),
      disposition: eligibleAttemptCount > 0 && reasons.length === 0 ? "eligible" : "rejected",
      reasonCategories: reasons,
    };
  }

  #targetContextIsValid(attempt: AttackAttemptRow): boolean {
    const targets = [
      [attempt.target_asset_id, "asset"],
      [attempt.target_service_id, "service"],
    ] as const;
    const represented = targets.filter(
      (entry): entry is readonly [string, "asset" | "service"] => nonEmpty(entry[0]),
    );
    if (represented.length === 0) return false;
    for (const [id, expectedType] of represented) {
      const row = this.database.prepare(`
        SELECT node_type FROM topology_nodes
        WHERE id = ? AND mission_id = ? AND (run_id IS NULL OR run_id = ?)
      `).get(id, attempt.mission_id, attempt.run_id) as { readonly node_type: string } | undefined;
      if (row?.node_type !== expectedType) return false;
    }
    return true;
  }
}

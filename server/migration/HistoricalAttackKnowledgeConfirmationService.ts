import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import {
  attackKnowledgeOperationalLocatorCategories,
  findReusableMemorySecretCategories,
  isAttackCentricReusableNodeType,
  MEMORY_NODE_TYPES,
  MemoryRepository,
  memoryContentHash,
  assertReusableMemoryText,
  assertReusableMemoryUnknown,
  REUSABLE_MEMORY_LIMITS,
  ReusableMemorySafetyError,
  validateAttackCentricEdgeEndpoints,
  validateAttackCentricReusableCandidate,
  type AttackCentricEdgeType,
  type MemoryCandidate,
  type MemoryNode,
  type MemoryNodeType,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";
import {
  HistoricalPrivateSourceCustodyProjectionService,
  type HistoricalPrivateSourceBindingInput,
} from "./HistoricalPrivateSourceCustodyProjectionService";

const SHA256 = /^[a-f0-9]{64}$/u;
const ACTOR = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const DEFAULT_MAX_CANDIDATES = 500;
const MAX_CANDIDATES = 1_000;
const MAX_SOURCE_BINDINGS_PER_PAGE = 25_000;
const MAX_EDGE_PROPOSALS_PER_PAGE = 50_000;
const MAX_EDGE_PROVENANCE_EXACT_SOURCES = 8;
const POLICY_VERSION = "historical-safe-candidate-confirmation-v1" as const;

interface MigrationBoundaryRow {
  readonly status: string;
  readonly source_retention: string;
  readonly brain_projection_mode: string;
  readonly receipt_hash: string | null;
  readonly mission_id: string | null;
  readonly run_id: string | null;
}

interface CandidateRegistryRow {
  readonly content_fingerprint: string;
  readonly candidate_id: string;
}

interface EdgeProposalRow {
  readonly bundle_id: string;
  readonly semantic_fingerprint: string;
  readonly sanitized_bundle_json: string;
  readonly last_observed_at: string;
  readonly edge_key: string;
  readonly edge_type: AttackCentricEdgeType;
  readonly source_fingerprint: string;
  readonly target_fingerprint: string;
}

interface CandidateSourceRow {
  readonly content_fingerprint: string;
  readonly candidate_id: string;
  readonly source_reference: string;
  readonly source_hash: string;
  readonly modified_at: string;
  readonly observed_at: string;
  readonly promoted_evidence_id: string | null;
}

interface CandidateRelationshipCountRow {
  readonly content_fingerprint: string;
  readonly relationship_count: number;
}

interface ExistingEdgeRow {
  readonly id: string;
  readonly lifecycle_status: string;
  readonly author_type: string;
}

interface AuditReplayRow {
  readonly id: string;
  readonly details_json: string;
}

export type HistoricalCandidateConfirmationDecision =
  | "confirm"
  | "suppress"
  | "preserve_operator_rejection";

export interface HistoricalCandidateConfirmationReviewItem {
  readonly candidateId: string;
  readonly contentFingerprint: string;
  readonly nodeType: string;
  readonly title: string;
  readonly decision: HistoricalCandidateConfirmationDecision;
  readonly reasonCategories: readonly string[];
  readonly sourceBindingCount: number;
  readonly typedRelationshipCount: number;
  readonly relationshipState: "typed" | "unlinked";
  readonly sourceBindings: readonly HistoricalCandidateSourceBindingReview[];
}

export interface HistoricalCandidateSourceBindingReview {
  readonly sourceCandidateId: string;
  readonly sourceReference: string;
  readonly sourceHash: string;
  readonly modifiedAt: string;
  readonly observedAt: string;
  readonly evidenceId: string | null;
  readonly sourceId: string;
}

export interface HistoricalCandidateConfirmationEdgeReview {
  readonly sourceFingerprint: string;
  readonly edgeType: AttackCentricEdgeType;
  readonly targetFingerprint: string;
  readonly sourceBundleFingerprints: readonly string[];
  readonly sourceBundleObservations: readonly {
    readonly fingerprint: string;
    readonly observedAt: string;
  }[];
}

export interface HistoricalCandidateConfirmationReview {
  readonly schemaVersion: 1;
  readonly policyVersion: typeof POLICY_VERSION;
  readonly migrationId: string;
  readonly inventoryReceiptHash: string;
  readonly actorId: string;
  readonly reason: string;
  readonly acknowledgement: "confirm_sanitized_historical_attack_knowledge_only";
  readonly selection: {
    readonly afterContentFingerprint: string | null;
    readonly maxCandidates: number;
  };
  readonly candidates: readonly HistoricalCandidateConfirmationReviewItem[];
  readonly edges: readonly HistoricalCandidateConfirmationEdgeReview[];
}

export interface HistoricalCandidateConfirmationPreview {
  readonly previewHash: string;
  readonly review: HistoricalCandidateConfirmationReview;
  readonly candidateCount: number;
  readonly confirmCount: number;
  readonly suppressCount: number;
  readonly preserveOperatorRejectionCount: number;
  readonly edgeCount: number;
  readonly sourceBindingCount: number;
  readonly unlinkedCandidateCount: number;
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
}

export interface HistoricalCandidateConfirmationInput {
  readonly migrationId: string;
  readonly actorId: string;
  readonly reason: string;
  readonly afterContentFingerprint?: string;
  readonly maxCandidates?: number;
}

export interface HistoricalCandidateConfirmationExecuteInput
  extends HistoricalCandidateConfirmationInput {
  readonly expectedPreviewHash: string;
  readonly acknowledgeConfirmAllSafe: true;
}

export interface HistoricalCandidateConfirmationResult {
  readonly status: "completed" | "replayed";
  readonly previewHash: string;
  readonly auditRecordId: string;
  readonly selectedCount: number;
  readonly confirmedCount: number;
  readonly alreadyConfirmedCount: number;
  readonly suppressedCount: number;
  readonly preservedOperatorRejectionCount: number;
  readonly edgesCreated: number;
  readonly edgesAlreadyPresent: number;
  readonly edgesDeferred: number;
  readonly provenanceBindingsCreated: number;
  readonly provenanceBindingsAlreadyPresent: number;
  readonly privateSourceBindingsCreated: number;
  readonly privateSourceBindingsAlreadyPresent: number;
  readonly unlinkedCandidateCount: number;
  readonly unlinkedCandidates: readonly {
    readonly candidateId: string;
    readonly contentFingerprint: string;
    readonly nodeType: string;
    readonly title: string;
  }[];
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
}

export interface HistoricalCandidateConfirmationReconciliation {
  readonly migrationId: string;
  readonly inventoryReceiptHash: string;
  readonly totalMigrationCandidateCount: number;
  readonly eligibleCandidateCount: number;
  readonly pendingEligibleCount: number;
  readonly confirmedEligibleCount: number;
  readonly incompatibleEligibleCount: number;
  readonly rejectedOrSuppressedCount: number;
  readonly provenanceBindingExpectedCount: number;
  readonly provenanceBindingPresentCount: number;
  readonly provenanceBindingMissingCount: number;
  readonly unlinkedEligibleCount: number;
  readonly unlinkedConfirmedCount: number;
}

export class HistoricalAttackKnowledgeConfirmationError extends Error {
  constructor(
    readonly code:
      | "invalid_request"
      | "migration_not_eligible"
      | "stale_preview"
      | "selection_budget_exceeded"
      | "candidate_integrity_failed"
      | "edge_integrity_failed",
    message: string,
  ) {
    super(message);
    this.name = "HistoricalAttackKnowledgeConfirmationError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isMemoryNodeType(value: string): value is MemoryNodeType {
  return (MEMORY_NODE_TYPES as readonly string[]).includes(value);
}

function boundedActor(value: string): string {
  const normalized = value.trim().normalize("NFKC");
  if (!ACTOR.test(normalized)) {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "invalid_request",
      "A bounded operator actor identifier is required",
    );
  }
  return normalized;
}

function boundedReason(value: string): string {
  const normalized = value.trim().normalize("NFKC");
  if (!normalized || Buffer.byteLength(normalized, "utf8") > 1_200) {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "invalid_request",
      "A concise operator confirmation reason is required",
    );
  }
  if (findReusableMemorySecretCategories(normalized).length > 0) {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "invalid_request",
      "The confirmation reason must not contain authentication material",
    );
  }
  return normalized;
}

function boundedPageSize(value: number | undefined): number {
  const resolved = value ?? DEFAULT_MAX_CANDIDATES;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > MAX_CANDIDATES) {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "invalid_request",
      `maxCandidates must be an integer between 1 and ${MAX_CANDIDATES}`,
    );
  }
  return resolved;
}

function optionalFingerprint(value: string | undefined): string {
  const normalized = value?.trim().toLowerCase() ?? "";
  if (normalized && !SHA256.test(normalized)) {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "invalid_request",
      "The confirmation cursor must be a lowercase SHA-256 digest",
    );
  }
  return normalized;
}

function migrationIdentifier(value: string): string {
  const normalized = value.trim();
  if (!/^migration_[A-Za-z0-9-]{1,120}$/u.test(normalized)) {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "invalid_request",
      "A canonical historical migration identifier is required",
    );
  }
  return normalized;
}

/**
 * Canonicalize the exact selection inputs shared by single-page and bounded
 * all-page confirmation. Keeping this normalization in one place prevents an
 * orchestration receipt from binding subtly different actor, reason, cursor,
 * or page-size semantics than the page service executes.
 */
export function normalizeHistoricalCandidateConfirmationInput(
  input: HistoricalCandidateConfirmationInput,
): Required<HistoricalCandidateConfirmationInput> {
  return {
    migrationId: migrationIdentifier(input.migrationId),
    actorId: boundedActor(input.actorId),
    reason: boundedReason(input.reason),
    afterContentFingerprint: optionalFingerprint(input.afterContentFingerprint),
    maxCandidates: boundedPageSize(input.maxCandidates),
  };
}

function confirmationId(previewHash: string): string {
  return `hakconfirm_${previewHash}`;
}

function edgeId(sourceNodeId: string, edgeType: string, targetNodeId: string): string {
  return `medge_ak_${sha256(`${sourceNodeId}\0${edgeType}\0${targetNodeId}`).slice(0, 48)}`;
}

function memorySourceId(nodeId: string, sourceCandidateId: string, migrationId: string): string {
  return `msrc_hak_${sha256(`${nodeId}\0${sourceCandidateId}\0${migrationId}`).slice(0, 48)}`;
}

function occurrenceSourceId(sourceCandidateId: string, migrationId: string): string {
  return `${sourceCandidateId}:${migrationId}`;
}

function candidateSafetyReasons(
  candidate: MemoryCandidate,
  expectedFingerprint: string,
): readonly string[] {
  const reasons = new Set<string>();
  if (candidate.proposedBy !== "attack-knowledge-compiler") {
    reasons.add("untrusted_candidate_producer");
  }
  if (!isAttackCentricReusableNodeType(candidate.nodeType)) {
    reasons.add("non_reusable_memory_type");
  }
  if (candidate.scope.kind !== "global" || candidate.scope.engagementId || candidate.scope.missionId) {
    reasons.add("non_global_reusable_scope");
  }
  if (memoryContentHash(candidate) !== expectedFingerprint) {
    reasons.add("candidate_fingerprint_mismatch");
  }
  const text = `${candidate.title}\n${candidate.summary}\n${candidate.body}`;
  if (findReusableMemorySecretCategories(text).length > 0) {
    reasons.add("secret_bearing_content");
  }
  if (attackKnowledgeOperationalLocatorCategories(text).length > 0) {
    reasons.add("operational_locator_content");
  }
  try {
    // A candidate can predate the current reusable-memory byte boundary or be
    // damaged by a non-repository writer. Classify that before materializing a
    // node so one unsafe historical row is suppressed instead of aborting the
    // hash-bound confirmation page.
    assertReusableMemoryUnknown(
      candidate.provenance,
      "candidate.provenance",
      REUSABLE_MEMORY_LIMITS.provenance,
    );
    assertReusableMemoryText([
      { field: "candidate.title", value: candidate.title, maximumBytes: REUSABLE_MEMORY_LIMITS.title },
      { field: "candidate.summary", value: candidate.summary, maximumBytes: REUSABLE_MEMORY_LIMITS.summary },
      { field: "candidate.body", value: candidate.body, maximumBytes: REUSABLE_MEMORY_LIMITS.body },
      {
        field: "candidate.provenance.explanation",
        value: candidate.provenance.explanation,
        maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceExplanation,
      },
      ...candidate.provenance.sources.flatMap((source, index) => [
        {
          field: `candidate.provenance.sources[${index}].sourceType`,
          value: source.sourceType,
          maximumBytes: 128,
        },
        {
          field: `candidate.provenance.sources[${index}].sourceId`,
          value: source.sourceId,
          maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceIdentifier,
        },
        {
          field: `candidate.provenance.sources[${index}].excerptRedacted`,
          value: source.excerptRedacted,
          maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceExcerpt,
        },
      ]),
    ]);
  } catch (error) {
    if (!(error instanceof ReusableMemorySafetyError)) throw error;
    error.details.reasonCategories.forEach((category) => reasons.add(category));
    reasons.add("reusable_retention_boundary_failed");
  }
  try {
    validateAttackCentricReusableCandidate(candidate);
  } catch {
    reasons.add("reusable_boundary_validation_failed");
  }
  return [...reasons].sort();
}

/**
 * A relationship can recur in thousands of exact historical bundles. Those
 * exact origins remain losslessly queryable in attack_knowledge_bundle_edges,
 * historical_attack_knowledge_bundle_sources, and the endpoint nodes'
 * composite memory_sources custody. Repeating every origin inside one graph
 * edge would turn normalized custody into an unbounded reusable payload.
 *
 * Keep a deterministic sample plus a hash-bound aggregate receipt on the
 * edge. The page preview hash still binds the complete sorted origin set.
 */
function boundedEdgeProvenanceSources(
  observations: HistoricalCandidateConfirmationEdgeReview["sourceBundleObservations"],
): readonly {
  readonly sourceType: string;
  readonly sourceId: string;
  readonly sourceHash: string;
  readonly acquiredAt: string;
}[] {
  const exact = observations.slice(0, MAX_EDGE_PROVENANCE_EXACT_SOURCES).map((observation) => ({
    sourceType: "attack_knowledge_bundle",
    sourceId: `akb_${observation.fingerprint}`,
    sourceHash: observation.fingerprint,
    acquiredAt: observation.observedAt,
  }));
  if (observations.length <= MAX_EDGE_PROVENANCE_EXACT_SOURCES) return exact;
  const setHash = sha256(canonicalJson(observations));
  const acquiredAt = observations.reduce(
    (latest, observation) => observation.observedAt > latest ? observation.observedAt : latest,
    observations[0]!.observedAt,
  );
  return [...exact, {
    sourceType: "attack_knowledge_bundle_set",
    sourceId: `akbs_${setHash}`,
    sourceHash: setHash,
    acquiredAt,
  }];
}

function resolvedConfirmedNodeFromSnapshot(
  candidate: MemoryCandidate,
  node: MemoryNode | undefined,
): MemoryNode | undefined {
  if (!node) return undefined;
  if (
    !isAttackCentricReusableNodeType(node.nodeType)
    || node.scope.kind !== "global"
    || node.lifecycleStatus !== "confirmed" && node.lifecycleStatus !== "verified"
    || node.confirmationState !== "confirmed"
    || node.authorType !== "operator"
  ) return undefined;
  return node;
}

function resolvedConfirmedNode(memory: MemoryRepository, candidate: MemoryCandidate): MemoryNode | undefined {
  return resolvedConfirmedNodeFromSnapshot(
    candidate,
    candidate.proposedNodeId ? memory.getNode(candidate.proposedNodeId) : undefined,
  );
}

function parseReplay(
  row: AuditReplayRow,
  expectedPreviewHash: string,
): HistoricalCandidateConfirmationResult {
  let details: unknown;
  try { details = JSON.parse(row.details_json) as unknown; }
  catch {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "candidate_integrity_failed",
      "The prior confirmation audit receipt is malformed",
    );
  }
  if (!details || typeof details !== "object" || Array.isArray(details)) {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "candidate_integrity_failed",
      "The prior confirmation audit receipt is invalid",
    );
  }
  const value = details as Record<string, unknown>;
  const number = (key: string): number => {
    const item = value[key];
    if (!Number.isSafeInteger(item) || Number(item) < 0) {
      throw new HistoricalAttackKnowledgeConfirmationError(
        "candidate_integrity_failed",
        "The prior confirmation audit counts are invalid",
      );
    }
    return Number(item);
  };
  if (value.previewHash !== expectedPreviewHash || typeof value.hasMore !== "boolean"
      || !(value.nextSelectionCursor === null || typeof value.nextSelectionCursor === "string")) {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "candidate_integrity_failed",
      "The prior confirmation audit does not match this preview",
    );
  }
  const unlinkedCandidateCount = number("unlinkedCandidateCount");
  if (!Array.isArray(value.unlinkedCandidates)
      || value.unlinkedCandidates.length !== unlinkedCandidateCount) {
    throw new HistoricalAttackKnowledgeConfirmationError(
      "candidate_integrity_failed",
      "The prior confirmation audit has an invalid unlinked-candidate inventory",
    );
  }
  const unlinkedCandidates = value.unlinkedCandidates.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new HistoricalAttackKnowledgeConfirmationError(
        "candidate_integrity_failed",
        "The prior confirmation audit has a malformed unlinked candidate",
      );
    }
    const candidate = item as Record<string, unknown>;
    if (
      typeof candidate.candidateId !== "string" || !candidate.candidateId
      || typeof candidate.contentFingerprint !== "string"
      || !SHA256.test(candidate.contentFingerprint)
      || typeof candidate.nodeType !== "string"
      || !isMemoryNodeType(candidate.nodeType)
      || !isAttackCentricReusableNodeType(candidate.nodeType)
      || typeof candidate.title !== "string" || !candidate.title.trim()
    ) {
      throw new HistoricalAttackKnowledgeConfirmationError(
        "candidate_integrity_failed",
        "The prior confirmation audit has an invalid unlinked candidate",
      );
    }
    return {
      candidateId: candidate.candidateId,
      contentFingerprint: candidate.contentFingerprint,
      nodeType: candidate.nodeType,
      title: candidate.title,
    };
  });
  return {
    status: "replayed",
    previewHash: expectedPreviewHash,
    auditRecordId: row.id,
    selectedCount: number("selectedCount"),
    confirmedCount: number("confirmedCount"),
    alreadyConfirmedCount: number("alreadyConfirmedCount"),
    suppressedCount: number("suppressedCount"),
    preservedOperatorRejectionCount: number("preservedOperatorRejectionCount"),
    edgesCreated: number("edgesCreated"),
    edgesAlreadyPresent: number("edgesAlreadyPresent"),
    edgesDeferred: number("edgesDeferred"),
    provenanceBindingsCreated: number("provenanceBindingsCreated"),
    provenanceBindingsAlreadyPresent: number("provenanceBindingsAlreadyPresent"),
    privateSourceBindingsCreated: value.privateSourceBindingsCreated === undefined
      ? 0 : number("privateSourceBindingsCreated"),
    privateSourceBindingsAlreadyPresent: value.privateSourceBindingsAlreadyPresent === undefined
      ? 0 : number("privateSourceBindingsAlreadyPresent"),
    unlinkedCandidateCount,
    unlinkedCandidates,
    hasMore: value.hasMore,
    nextSelectionCursor: value.nextSelectionCursor as string | null,
  };
}

/**
 * Hash-bound operator confirmation for sanitized historical attack knowledge.
 *
 * Confirmation is deliberately weaker than evidence verification. This
 * service never changes a candidate to verified and never assigns success or
 * failed outcome tags. It can, however, turn an explicitly authorized page of
 * safe compiler candidates and their exact source-bundle relationships into
 * visible confirmed memory.
 */
export class HistoricalAttackKnowledgeConfirmationService {
  readonly #memory: MemoryRepository;
  readonly #audit: AuditTrailWriter;
  readonly #privateSourceProjection: HistoricalPrivateSourceCustodyProjectionService;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {
    this.#memory = new MemoryRepository(database, { clock });
    this.#audit = new AuditTrailWriter(database);
    this.#privateSourceProjection = new HistoricalPrivateSourceCustodyProjectionService(
      database,
      { clock },
    );
  }

  preview(input: HistoricalCandidateConfirmationInput): HistoricalCandidateConfirmationPreview {
    const normalized = this.#normalize(input);
    const boundary = this.#migrationBoundary(normalized.migrationId);
    const rows = this.database.prepare(`
      SELECT DISTINCT registry.content_fingerprint, registry.candidate_id
      FROM historical_attack_knowledge_source_occurrences occurrence
      JOIN historical_attack_knowledge_bundle_sources source_binding
        ON source_binding.candidate_id = occurrence.candidate_id
       AND source_binding.source_hash = occurrence.source_hash
      JOIN attack_knowledge_bundle_candidates bundle_candidate
        ON bundle_candidate.bundle_id = source_binding.bundle_id
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = bundle_candidate.content_fingerprint
      WHERE occurrence.migration_id = ?
        AND registry.content_fingerprint > ?
      ORDER BY registry.content_fingerprint
      LIMIT ?
    `).all(
      normalized.migrationId,
      normalized.afterContentFingerprint,
      normalized.maxCandidates + 1,
    ) as CandidateRegistryRow[];
    const hasMore = rows.length > normalized.maxCandidates;
    const selected = rows.slice(0, normalized.maxCandidates);
    const selectedFingerprints = selected.map(({ content_fingerprint }) => content_fingerprint);
    const sourceBindingsByFingerprint = this.#candidateSourceBindingsForPage(
      normalized.migrationId,
      selectedFingerprints,
    );
    const relationshipCounts = this.#candidateRelationshipCountsForPage(
      normalized.migrationId,
      selectedFingerprints,
    );
    const selectedCandidates = this.#memory.getCandidates(
      selected.map(({ candidate_id }) => candidate_id),
    );
    let pageSourceBindingCount = 0;
    const candidates = selected.map((row): HistoricalCandidateConfirmationReviewItem => {
      const candidate = selectedCandidates.get(row.candidate_id);
      if (!candidate) {
        throw new HistoricalAttackKnowledgeConfirmationError(
          "candidate_integrity_failed",
          "A migration-linked attack-knowledge candidate is missing",
        );
      }
      const reasons = candidateSafetyReasons(candidate, row.content_fingerprint);
      const priorRejection = candidate.status === "rejected" || candidate.status === "suppressed";
      const sourceBindings = sourceBindingsByFingerprint.get(row.content_fingerprint) ?? [];
      pageSourceBindingCount += sourceBindings.length;
      const typedRelationshipCount = relationshipCounts.get(row.content_fingerprint) ?? 0;
      return {
        candidateId: candidate.id,
        contentFingerprint: row.content_fingerprint,
        nodeType: candidate.nodeType,
        title: candidate.title,
        decision: priorRejection
          ? "preserve_operator_rejection"
          : reasons.length > 0 ? "suppress" : "confirm",
        reasonCategories: priorRejection ? ["prior_operator_rejection"] : reasons,
        sourceBindingCount: sourceBindings.length,
        typedRelationshipCount,
        relationshipState: typedRelationshipCount > 0 ? "typed" : "unlinked",
        sourceBindings,
      };
    });
    const lastFingerprint = candidates.at(-1)?.contentFingerprint ?? null;
    const edges = lastFingerprint
      ? this.#edgeReview(
        normalized.migrationId,
        new Set(candidates.map(({ contentFingerprint }) => contentFingerprint)),
        lastFingerprint,
      )
      : [];
    const review: HistoricalCandidateConfirmationReview = {
      schemaVersion: 1,
      policyVersion: POLICY_VERSION,
      migrationId: normalized.migrationId,
      inventoryReceiptHash: boundary.receipt_hash!,
      actorId: normalized.actorId,
      reason: normalized.reason,
      acknowledgement: "confirm_sanitized_historical_attack_knowledge_only",
      selection: {
        afterContentFingerprint: normalized.afterContentFingerprint || null,
        maxCandidates: normalized.maxCandidates,
      },
      candidates,
      edges,
    };
    return {
      previewHash: sha256(canonicalJson(review)),
      review,
      candidateCount: candidates.length,
      confirmCount: candidates.filter(({ decision }) => decision === "confirm").length,
      suppressCount: candidates.filter(({ decision }) => decision === "suppress").length,
      preserveOperatorRejectionCount: candidates.filter(
        ({ decision }) => decision === "preserve_operator_rejection",
      ).length,
      edgeCount: edges.length,
      sourceBindingCount: pageSourceBindingCount,
      unlinkedCandidateCount: candidates.filter(
        ({ decision, relationshipState }) => decision === "confirm" && relationshipState === "unlinked",
      ).length,
      hasMore,
      nextSelectionCursor: lastFingerprint,
    };
  }

  execute(input: HistoricalCandidateConfirmationExecuteInput): HistoricalCandidateConfirmationResult {
    if (input.acknowledgeConfirmAllSafe !== true || !SHA256.test(input.expectedPreviewHash)) {
      throw new HistoricalAttackKnowledgeConfirmationError(
        "invalid_request",
        "Execution requires the exact preview hash and explicit safe-confirmation acknowledgement",
      );
    }
    const normalized = this.#normalize(input);
    const resourceId = confirmationId(input.expectedPreviewHash);
    const replay = this.database.prepare(`
      SELECT id, details_json FROM audit_records
      WHERE action = 'historical_attack_knowledge.confirmed'
        AND resource_type = 'historical_attack_knowledge_confirmation'
        AND resource_id = ? AND actor_type = 'operator' AND actor_id = ?
      ORDER BY rowid LIMIT 1
    `).get(resourceId, normalized.actorId) as AuditReplayRow | undefined;
    if (replay) {
      const result = parseReplay(replay, input.expectedPreviewHash);
      if (!this.#privateSourceProjection.isAvailable()) return result;
      try {
        const repaired = this.#privateSourceProjection.backfillMigration(
          normalized.migrationId,
          MAX_SOURCE_BINDINGS_PER_PAGE,
        );
        if (repaired.hasMore) {
          throw new Error(
            "The bounded private source custody repair has more rows; replay this exact confirmation page again",
          );
        }
        return {
          ...result,
          privateSourceBindingsCreated:
            result.privateSourceBindingsCreated + repaired.createdCount,
          privateSourceBindingsAlreadyPresent:
            result.privateSourceBindingsAlreadyPresent + repaired.replayedCount,
        };
      } catch (error) {
        throw new HistoricalAttackKnowledgeConfirmationError(
          "candidate_integrity_failed",
          error instanceof Error
            ? `Private source custody replay repair failed: ${error.message}`
            : "Private source custody replay repair failed",
        );
      }
    }

    const preview = this.preview(normalized);
    if (preview.candidateCount === 0) {
      throw new HistoricalAttackKnowledgeConfirmationError(
        "invalid_request",
        "This migration confirmation page is empty",
      );
    }
    if (preview.previewHash !== input.expectedPreviewHash) {
      throw new HistoricalAttackKnowledgeConfirmationError(
        "stale_preview",
        "Historical candidate selection changed after preview; generate a fresh preview",
      );
    }
    const boundary = this.#migrationBoundary(normalized.migrationId);

    return inImmediateTransaction(this.database, () => {
      let confirmedCount = 0;
      let alreadyConfirmedCount = 0;
      let suppressedCount = 0;
      let preservedOperatorRejectionCount = 0;
      let provenanceBindingsCreated = 0;
      let provenanceBindingsAlreadyPresent = 0;
      let privateSourceBindingsCreated = 0;
      let privateSourceBindingsAlreadyPresent = 0;
      const privateSourceInputs: HistoricalPrivateSourceBindingInput[] = [];
      const privateSourceProjectionAvailable = this.#privateSourceProjection.isAvailable();
      const currentCandidates = this.#memory.getCandidates(
        preview.review.candidates.map(({ candidateId }) => candidateId),
      );
      const currentNodes = this.#memory.getNodes(
        [...currentCandidates.values()].flatMap((candidate) => (
          candidate.proposedNodeId ? [candidate.proposedNodeId] : []
        )),
      );
      for (const reviewed of preview.review.candidates) {
        const candidate = currentCandidates.get(reviewed.candidateId);
        if (!candidate) {
          throw new HistoricalAttackKnowledgeConfirmationError(
            "candidate_integrity_failed",
            "A reviewed historical candidate is missing during execution",
          );
        }
        if (reviewed.decision === "preserve_operator_rejection") {
          if (candidate.status !== "rejected" && candidate.status !== "suppressed") {
            throw new HistoricalAttackKnowledgeConfirmationError(
              "candidate_integrity_failed",
              "A previously rejected candidate changed after preview",
            );
          }
          preservedOperatorRejectionCount += 1;
          continue;
        }
        const reasons = candidateSafetyReasons(candidate, reviewed.contentFingerprint);
        if (canonicalJson(reasons) !== canonicalJson(reviewed.reasonCategories)) {
          throw new HistoricalAttackKnowledgeConfirmationError(
            "candidate_integrity_failed",
            "A candidate safety classification changed after preview",
          );
        }
        if (reviewed.decision === "suppress") {
          if (candidate.status === "pending") {
            this.#memory.rejectCandidateAndSuppress(
              candidate.id,
              normalized.actorId,
              `Historical confirmation safety boundary: ${reasons.join(", ")}`,
            );
            suppressedCount += 1;
            continue;
          }
          if (candidate.status === "suppressed" || candidate.status === "rejected") {
            preservedOperatorRejectionCount += 1;
            continue;
          }
          throw new HistoricalAttackKnowledgeConfirmationError(
            "candidate_integrity_failed",
            "An unsafe candidate was already materialized and cannot be silently rewritten",
          );
        }
        let node: MemoryNode | undefined;
        if (candidate.status === "pending") {
          node = this.#memory.confirmCandidate(candidate.id, normalized.actorId);
          confirmedCount += 1;
        } else if (
          ["confirmed", "edited_confirmed", "merged"].includes(candidate.status)
          && (node = resolvedConfirmedNodeFromSnapshot(
            candidate,
            candidate.proposedNodeId ? currentNodes.get(candidate.proposedNodeId) : undefined,
          ))
        ) {
          alreadyConfirmedCount += 1;
        } else {
          throw new HistoricalAttackKnowledgeConfirmationError(
            "candidate_integrity_failed",
            "A safe candidate has an incompatible review state",
          );
        }

        if (!node) {
          throw new HistoricalAttackKnowledgeConfirmationError(
            "candidate_integrity_failed",
            "A confirmed historical candidate did not resolve to a confirmed reusable node",
          );
        }
        for (const source of reviewed.sourceBindings) {
          const sourceMemoryId = memorySourceId(
            node.id,
            source.sourceCandidateId,
            normalized.migrationId,
          );
          const inserted = this.database.prepare(`
            INSERT INTO memory_sources (
              id, node_id, source_type, source_id, mission_id, run_id,
              evidence_id, source_hash, excerpt_redacted, acquired_at, created_at
            ) VALUES (?, ?, 'historical_attack_knowledge_source_candidate', ?, ?, ?, ?, ?, NULL, ?, ?)
            ON CONFLICT(node_id, source_type, source_id) DO NOTHING
          `).run(
            sourceMemoryId,
            node.id,
            source.sourceId,
            boundary.mission_id,
            boundary.run_id,
            source.evidenceId,
            source.sourceHash,
            source.modifiedAt,
            this.clock().toISOString(),
          ).changes;
          if (inserted === 1) provenanceBindingsCreated += 1;
          else provenanceBindingsAlreadyPresent += 1;
          if (privateSourceProjectionAvailable) {
            privateSourceInputs.push({
              memorySourceId: sourceMemoryId,
              sourceCandidateId: source.sourceCandidateId,
              migrationId: normalized.migrationId,
              sourceReference: source.sourceReference,
              sourceHash: source.sourceHash,
            });
          }
        }
      }
      if (privateSourceInputs.length > 0) {
        try {
          for (const privateBinding of this.#privateSourceProjection.bindBatch(privateSourceInputs)) {
            if (privateBinding.created) privateSourceBindingsCreated += 1;
            else privateSourceBindingsAlreadyPresent += 1;
          }
        } catch (error) {
          throw new HistoricalAttackKnowledgeConfirmationError(
            "candidate_integrity_failed",
            error instanceof Error
              ? `Private source custody could not be projected: ${error.message}`
              : "Private source custody could not be projected",
          );
        }
      }

      let edgesCreated = 0;
      let edgesAlreadyPresent = 0;
      let edgesDeferred = 0;
      for (const edge of preview.review.edges) {
        const source = this.#nodeForFingerprint(edge.sourceFingerprint);
        const target = this.#nodeForFingerprint(edge.targetFingerprint);
        if (!source || !target) {
          edgesDeferred += 1;
          continue;
        }
        try {
          validateAttackCentricEdgeEndpoints(edge.edgeType, source.nodeType, target.nodeType);
        } catch {
          throw new HistoricalAttackKnowledgeConfirmationError(
            "edge_integrity_failed",
            "A staged historical relationship has incompatible reviewed endpoints",
          );
        }
        const existing = this.database.prepare(`
          SELECT id, lifecycle_status, author_type FROM memory_edges
          WHERE source_node_id = ? AND edge_type = ? AND target_node_id = ?
            AND lifecycle_status != 'forgotten'
          ORDER BY version DESC LIMIT 1
        `).get(source.id, edge.edgeType, target.id) as ExistingEdgeRow | undefined;
        if (existing) {
          if (
            !["confirmed", "verified"].includes(existing.lifecycle_status)
            || existing.author_type !== "operator"
          ) {
            throw new HistoricalAttackKnowledgeConfirmationError(
              "edge_integrity_failed",
              "A conflicting unreviewed relationship already exists",
            );
          }
          edgesAlreadyPresent += 1;
          continue;
        }
        this.#memory.createEdge({
          id: edgeId(source.id, edge.edgeType, target.id),
          sourceNodeId: source.id,
          targetNodeId: target.id,
          edgeType: edge.edgeType,
          title: edge.edgeType.replaceAll("_", " "),
          summary: "Operator-confirmed relationship from a hash-bound historical source bundle.",
          scope: { kind: "global" },
          sensitivity: source.sensitivity === "restricted" || target.sensitivity === "restricted"
            ? "restricted" : "internal",
          confidence: Math.min(source.confidence, target.confidence),
          lifecycleStatus: "confirmed",
          provenance: {
            method: "derived",
            explanation: "Confirmed from exact typed relationships within one or more hash-verified historical source bundles.",
            sources: boundedEdgeProvenanceSources(edge.sourceBundleObservations),
          },
          explanation: "The operator confirmed this source-bundle relationship for reusable historical knowledge; it remains unverified until evidence promotion.",
          authorType: "operator",
          authorId: normalized.actorId,
        });
        edgesCreated += 1;
      }

      const unlinkedCandidates = preview.review.candidates
        .filter(({ decision, relationshipState }) => (
          decision === "confirm" && relationshipState === "unlinked"
        ))
        .map(({ candidateId, contentFingerprint, nodeType, title }) => ({
          candidateId, contentFingerprint, nodeType, title,
        }));
      const details = {
        previewHash: preview.previewHash,
        policyVersion: POLICY_VERSION,
        migrationId: normalized.migrationId,
        inventoryReceiptHash: boundary.receipt_hash,
        selectedCount: preview.candidateCount,
        confirmedCount,
        alreadyConfirmedCount,
        suppressedCount,
        preservedOperatorRejectionCount,
        edgesCreated,
        edgesAlreadyPresent,
        edgesDeferred,
        provenanceBindingsCreated,
        provenanceBindingsAlreadyPresent,
        privateSourceBindingsCreated,
        privateSourceBindingsAlreadyPresent,
        unlinkedCandidateCount: unlinkedCandidates.length,
        unlinkedCandidates,
        hasMore: preview.hasMore,
        nextSelectionCursor: preview.nextSelectionCursor,
        verificationState: "confirmation_only",
        outcomeClassification: "unchanged",
      } as const;
      const auditRecordId = this.#audit.append({
        missionId: boundary.mission_id!,
        runId: boundary.run_id!,
        actor: { type: "operator", id: normalized.actorId },
        action: "historical_attack_knowledge.confirmed",
        resourceType: "historical_attack_knowledge_confirmation",
        resourceId,
        reason: normalized.reason,
        details,
        occurredAt: this.clock().toISOString(),
      });
      return {
        status: "completed",
        auditRecordId,
        ...details,
      };
    });
  }

  /**
   * Recompute the migration-wide confirmation state from canonical candidates,
   * source occurrences, memory nodes, and custody bindings. This deliberately
   * uses the same reusable-memory safety boundary as page preview/execute.
   */
  reconcile(migrationId: string): HistoricalCandidateConfirmationReconciliation {
    const normalizedMigrationId = migrationIdentifier(migrationId);
    const boundary = this.#migrationBoundary(normalizedMigrationId);
    const rows = this.database.prepare(`
      SELECT DISTINCT registry.content_fingerprint, registry.candidate_id
      FROM historical_attack_knowledge_source_occurrences occurrence
      JOIN historical_attack_knowledge_bundle_sources source_binding
        ON source_binding.candidate_id = occurrence.candidate_id
       AND source_binding.source_hash = occurrence.source_hash
      JOIN attack_knowledge_bundle_candidates bundle_candidate
        ON bundle_candidate.bundle_id = source_binding.bundle_id
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = bundle_candidate.content_fingerprint
      WHERE occurrence.migration_id = ?
      ORDER BY registry.content_fingerprint
    `).all(normalizedMigrationId) as CandidateRegistryRow[];
    const relationshipRows = this.database.prepare(`
      SELECT candidate.content_fingerprint,
        COUNT(DISTINCT edge.bundle_id || char(0) || edge.edge_key) AS relationship_count
      FROM historical_attack_knowledge_source_occurrences occurrence
      JOIN historical_attack_knowledge_bundle_sources source_binding
        ON source_binding.candidate_id = occurrence.candidate_id
       AND source_binding.source_hash = occurrence.source_hash
      JOIN attack_knowledge_bundle_candidates candidate
        ON candidate.bundle_id = source_binding.bundle_id
      JOIN attack_knowledge_bundle_edges edge
        ON edge.bundle_id = candidate.bundle_id
       AND (edge.source_role = candidate.role OR edge.target_role = candidate.role)
      WHERE occurrence.migration_id = ?
      GROUP BY candidate.content_fingerprint
    `).all(normalizedMigrationId) as Array<{
      readonly content_fingerprint: string;
      readonly relationship_count: number;
    }>;
    const relationshipCounts = new Map(
      relationshipRows.map((row) => [row.content_fingerprint, row.relationship_count]),
    );
    const sourceRows = this.database.prepare(`
      SELECT DISTINCT bundle_candidate.content_fingerprint,
        occurrence.candidate_id AS source_candidate_id
      FROM historical_attack_knowledge_source_occurrences occurrence
      JOIN historical_attack_knowledge_bundle_sources source_binding
        ON source_binding.candidate_id = occurrence.candidate_id
       AND source_binding.source_hash = occurrence.source_hash
      JOIN attack_knowledge_bundle_candidates bundle_candidate
        ON bundle_candidate.bundle_id = source_binding.bundle_id
      WHERE occurrence.migration_id = ?
      ORDER BY bundle_candidate.content_fingerprint, occurrence.candidate_id
    `).all(normalizedMigrationId) as Array<{
      readonly content_fingerprint: string;
      readonly source_candidate_id: string;
    }>;
    const sourceCandidates = new Map<string, string[]>();
    for (const row of sourceRows) {
      const current = sourceCandidates.get(row.content_fingerprint) ?? [];
      current.push(row.source_candidate_id);
      sourceCandidates.set(row.content_fingerprint, current);
    }
    const presentSourceRows = this.database.prepare(`
      SELECT DISTINCT memory_source.node_id,
        occurrence.candidate_id AS source_candidate_id
      FROM historical_attack_knowledge_source_occurrences occurrence
      JOIN memory_sources memory_source
        ON memory_source.source_type = 'historical_attack_knowledge_source_candidate'
       AND memory_source.source_id = occurrence.candidate_id || ':' || occurrence.migration_id
      WHERE occurrence.migration_id = ?
        AND memory_source.mission_id = ? AND memory_source.run_id = ?
    `).all(
      normalizedMigrationId,
      boundary.mission_id,
      boundary.run_id,
    ) as Array<{
      readonly node_id: string;
      readonly source_candidate_id: string;
    }>;
    const presentSourceBindings = new Set(
      presentSourceRows.map((row) => `${row.node_id}\0${row.source_candidate_id}`),
    );
    const candidates = this.#memory.getCandidates(rows.map(({ candidate_id }) => candidate_id));
    const nodes = this.#memory.getNodes(
      [...candidates.values()].flatMap((candidate) => (
        candidate.proposedNodeId ? [candidate.proposedNodeId] : []
      )),
    );

    let eligibleCandidateCount = 0;
    let pendingEligibleCount = 0;
    let confirmedEligibleCount = 0;
    let incompatibleEligibleCount = 0;
    let rejectedOrSuppressedCount = 0;
    let provenanceBindingExpectedCount = 0;
    let provenanceBindingPresentCount = 0;
    let unlinkedEligibleCount = 0;
    let unlinkedConfirmedCount = 0;
    for (const row of rows) {
      const candidate = candidates.get(row.candidate_id);
      if (!candidate) {
        throw new HistoricalAttackKnowledgeConfirmationError(
          "candidate_integrity_failed",
          "A migration-linked attack-knowledge candidate is missing during reconciliation",
        );
      }
      if (candidate.status === "rejected" || candidate.status === "suppressed") {
        rejectedOrSuppressedCount += 1;
        continue;
      }
      if (candidateSafetyReasons(candidate, row.content_fingerprint).length > 0) continue;
      eligibleCandidateCount += 1;
      const unlinked = (relationshipCounts.get(row.content_fingerprint) ?? 0) === 0;
      if (unlinked) unlinkedEligibleCount += 1;
      if (candidate.status === "pending") {
        pendingEligibleCount += 1;
        continue;
      }
      const node = resolvedConfirmedNodeFromSnapshot(
        candidate,
        candidate.proposedNodeId ? nodes.get(candidate.proposedNodeId) : undefined,
      );
      if (!node) {
        incompatibleEligibleCount += 1;
        continue;
      }
      confirmedEligibleCount += 1;
      if (unlinked) unlinkedConfirmedCount += 1;
      for (const sourceCandidateId of sourceCandidates.get(row.content_fingerprint) ?? []) {
        provenanceBindingExpectedCount += 1;
        if (presentSourceBindings.has(`${node.id}\0${sourceCandidateId}`)) {
          provenanceBindingPresentCount += 1;
        }
      }
    }
    return {
      migrationId: normalizedMigrationId,
      inventoryReceiptHash: boundary.receipt_hash!,
      totalMigrationCandidateCount: rows.length,
      eligibleCandidateCount,
      pendingEligibleCount,
      confirmedEligibleCount,
      incompatibleEligibleCount,
      rejectedOrSuppressedCount,
      provenanceBindingExpectedCount,
      provenanceBindingPresentCount,
      provenanceBindingMissingCount:
        provenanceBindingExpectedCount - provenanceBindingPresentCount,
      unlinkedEligibleCount,
      unlinkedConfirmedCount,
    };
  }

  #normalize(input: HistoricalCandidateConfirmationInput): Required<HistoricalCandidateConfirmationInput> {
    return normalizeHistoricalCandidateConfirmationInput(input);
  }

  #migrationBoundary(migrationId: string): MigrationBoundaryRow {
    const row = this.database.prepare(`
      SELECT run.status, run.source_retention, run.brain_projection_mode,
        receipt.receipt_hash, context.mission_id, context.run_id
      FROM legacy_migration_runs run
      LEFT JOIN legacy_migration_inventory_receipts receipt
        ON receipt.migration_id = run.id
      LEFT JOIN historical_attack_knowledge_import_contexts context
        ON context.migration_id = run.id
      WHERE run.id = ?
    `).get(migrationId) as MigrationBoundaryRow | undefined;
    if (
      !row
      || row.status !== "completed"
      || row.source_retention !== "verified-reference"
      || row.brain_projection_mode !== "attack-knowledge-only"
      || !row.receipt_hash || !SHA256.test(row.receipt_hash)
      || !row.mission_id || !row.run_id
    ) {
      throw new HistoricalAttackKnowledgeConfirmationError(
        "migration_not_eligible",
        "Confirmation requires one completed, receipt-backed, attack-knowledge-only migration",
      );
    }
    return row;
  }

  #edgeReview(
    migrationId: string,
    selectedFingerprints: ReadonlySet<string>,
    lastFingerprint: string,
  ): readonly HistoricalCandidateConfirmationEdgeReview[] {
    const selectedFingerprintsJson = JSON.stringify([...selectedFingerprints]);
    const rows = this.database.prepare(`
      WITH selected_fingerprints(value) AS MATERIALIZED (
        SELECT value FROM json_each(?)
      ), migration_sources(candidate_id, source_hash) AS MATERIALIZED (
        SELECT DISTINCT candidate_id, source_hash
        FROM historical_attack_knowledge_source_occurrences
        WHERE migration_id = ?
      ), migration_bundles(bundle_id) AS MATERIALIZED (
        SELECT DISTINCT source_binding.bundle_id
        FROM migration_sources source
        JOIN historical_attack_knowledge_bundle_sources source_binding
          ON source_binding.candidate_id = source.candidate_id
         AND source_binding.source_hash = source.source_hash
      )
      SELECT bundle.id AS bundle_id, bundle.semantic_fingerprint,
        bundle.sanitized_bundle_json, bundle.last_observed_at,
        edge.edge_key, edge.edge_type,
        source_candidate.content_fingerprint AS source_fingerprint,
        target_candidate.content_fingerprint AS target_fingerprint
      FROM migration_bundles migration_bundle
      JOIN attack_knowledge_bundle_edges edge
        ON edge.bundle_id = migration_bundle.bundle_id
      JOIN attack_knowledge_bundles bundle ON bundle.id = edge.bundle_id
      JOIN attack_knowledge_bundle_candidates source_candidate
        ON source_candidate.bundle_id = edge.bundle_id
       AND source_candidate.role = edge.source_role
      JOIN attack_knowledge_bundle_candidates target_candidate
        ON target_candidate.bundle_id = edge.bundle_id
       AND target_candidate.role = edge.target_role
      LEFT JOIN selected_fingerprints selected_source
        ON selected_source.value = source_candidate.content_fingerprint
      LEFT JOIN selected_fingerprints selected_target
        ON selected_target.value = target_candidate.content_fingerprint
      WHERE (selected_source.value IS NOT NULL OR selected_target.value IS NOT NULL)
        AND source_candidate.content_fingerprint <= ?
        AND target_candidate.content_fingerprint <= ?
      ORDER BY source_candidate.content_fingerprint, edge.edge_type,
        target_candidate.content_fingerprint, bundle.semantic_fingerprint
      LIMIT ?
    `).all(
      selectedFingerprintsJson,
      migrationId,
      lastFingerprint,
      lastFingerprint,
      MAX_EDGE_PROPOSALS_PER_PAGE + 1,
    ) as EdgeProposalRow[];
    if (rows.length > MAX_EDGE_PROPOSALS_PER_PAGE) {
      throw new HistoricalAttackKnowledgeConfirmationError(
        "selection_budget_exceeded",
        `The selected page exceeds ${MAX_EDGE_PROPOSALS_PER_PAGE} typed source relationships; reduce maxCandidates`,
      );
    }
    const byRelationship = new Map<string, {
      sourceFingerprint: string;
      edgeType: AttackCentricEdgeType;
      targetFingerprint: string;
      bundleFingerprints: Set<string>;
      bundleObservations: Map<string, string>;
    }>();
    for (const row of rows) {
      if (
        sha256(row.sanitized_bundle_json) !== row.semantic_fingerprint
        || row.bundle_id !== `akb_${row.semantic_fingerprint}`
      ) {
        throw new HistoricalAttackKnowledgeConfirmationError(
          "edge_integrity_failed",
          "A staged historical source bundle failed its semantic fingerprint check",
        );
      }
      const key = `${row.source_fingerprint}\0${row.edge_type}\0${row.target_fingerprint}`;
      const current = byRelationship.get(key) ?? {
        sourceFingerprint: row.source_fingerprint,
        edgeType: row.edge_type,
        targetFingerprint: row.target_fingerprint,
        bundleFingerprints: new Set<string>(),
        bundleObservations: new Map<string, string>(),
      };
      current.bundleFingerprints.add(row.semantic_fingerprint);
      const priorObservedAt = current.bundleObservations.get(row.semantic_fingerprint);
      if (!priorObservedAt || priorObservedAt < row.last_observed_at) {
        current.bundleObservations.set(row.semantic_fingerprint, row.last_observed_at);
      }
      byRelationship.set(key, current);
    }
    return [...byRelationship.values()].map((edge) => ({
      sourceFingerprint: edge.sourceFingerprint,
      edgeType: edge.edgeType,
      targetFingerprint: edge.targetFingerprint,
      sourceBundleFingerprints: [...edge.bundleFingerprints].sort(),
      sourceBundleObservations: [...edge.bundleObservations.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([fingerprint, observedAt]) => ({ fingerprint, observedAt })),
    }));
  }

  #candidateSourceBindingsForPage(
    migrationId: string,
    contentFingerprints: readonly string[],
  ): ReadonlyMap<string, readonly HistoricalCandidateSourceBindingReview[]> {
    if (contentFingerprints.length === 0) return new Map();
    const selectedFingerprintsJson = JSON.stringify(contentFingerprints);
    const rows = this.database.prepare(`
      WITH selected_fingerprints(value) AS MATERIALIZED (
        SELECT value FROM json_each(?)
      )
      SELECT DISTINCT bundle_candidate.content_fingerprint,
        occurrence.candidate_id, occurrence.source_reference,
        occurrence.source_hash, occurrence.modified_at, occurrence.observed_at,
        evidence_candidate.promoted_evidence_id
      FROM historical_attack_knowledge_source_occurrences occurrence
      JOIN historical_attack_knowledge_bundle_sources source_binding
        ON source_binding.candidate_id = occurrence.candidate_id
       AND source_binding.source_hash = occurrence.source_hash
      JOIN attack_knowledge_bundle_candidates bundle_candidate
        ON bundle_candidate.bundle_id = source_binding.bundle_id
      JOIN selected_fingerprints selected
        ON selected.value = bundle_candidate.content_fingerprint
      JOIN evidence_candidates evidence_candidate
        ON evidence_candidate.id = occurrence.candidate_id
      WHERE occurrence.migration_id = ?
      ORDER BY bundle_candidate.content_fingerprint,
        occurrence.source_hash, occurrence.source_reference
      LIMIT ?
    `).all(
      selectedFingerprintsJson,
      migrationId,
      MAX_SOURCE_BINDINGS_PER_PAGE + 1,
    ) as CandidateSourceRow[];
    if (rows.length > MAX_SOURCE_BINDINGS_PER_PAGE) {
      throw new HistoricalAttackKnowledgeConfirmationError(
        "selection_budget_exceeded",
        `The selected page exceeds ${MAX_SOURCE_BINDINGS_PER_PAGE} private source bindings; reduce maxCandidates`,
      );
    }
    const byFingerprint = new Map<string, HistoricalCandidateSourceBindingReview[]>();
    for (const row of rows) {
      const bindings = byFingerprint.get(row.content_fingerprint) ?? [];
      bindings.push({
        sourceCandidateId: row.candidate_id,
        sourceReference: row.source_reference,
        sourceHash: row.source_hash,
        modifiedAt: row.modified_at,
        observedAt: row.observed_at,
        evidenceId: row.promoted_evidence_id,
        sourceId: occurrenceSourceId(row.candidate_id, migrationId),
      });
      byFingerprint.set(row.content_fingerprint, bindings);
    }
    return byFingerprint;
  }

  #candidateRelationshipCountsForPage(
    migrationId: string,
    contentFingerprints: readonly string[],
  ): ReadonlyMap<string, number> {
    if (contentFingerprints.length === 0) return new Map();
    const selectedFingerprintsJson = JSON.stringify(contentFingerprints);
    const rows = this.database.prepare(`
      WITH selected_fingerprints(value) AS MATERIALIZED (
        SELECT value FROM json_each(?)
      ), migration_sources(candidate_id, source_hash) AS MATERIALIZED (
        SELECT DISTINCT candidate_id, source_hash
        FROM historical_attack_knowledge_source_occurrences
        WHERE migration_id = ?
      ), migration_bundles(bundle_id) AS MATERIALIZED (
        SELECT DISTINCT source_binding.bundle_id
        FROM migration_sources source
        JOIN historical_attack_knowledge_bundle_sources source_binding
          ON source_binding.candidate_id = source.candidate_id
         AND source_binding.source_hash = source.source_hash
      )
      SELECT candidate.content_fingerprint,
        COUNT(DISTINCT edge.bundle_id || char(0) || edge.edge_key) AS relationship_count
      FROM migration_bundles migration_bundle
      JOIN attack_knowledge_bundle_candidates candidate
        ON candidate.bundle_id = migration_bundle.bundle_id
      JOIN selected_fingerprints selected
        ON selected.value = candidate.content_fingerprint
      JOIN attack_knowledge_bundle_edges edge
        ON edge.bundle_id = candidate.bundle_id
       AND (edge.source_role = candidate.role OR edge.target_role = candidate.role)
      GROUP BY candidate.content_fingerprint
    `).all(
      selectedFingerprintsJson,
      migrationId,
    ) as CandidateRelationshipCountRow[];
    return new Map(rows.map((row) => [row.content_fingerprint, row.relationship_count]));
  }

  #nodeForFingerprint(contentFingerprint: string): MemoryNode | undefined {
    const row = this.database.prepare(`
      SELECT candidate_id FROM attack_knowledge_candidate_registry
      WHERE content_fingerprint = ?
    `).get(contentFingerprint) as { readonly candidate_id: string } | undefined;
    if (!row) return undefined;
    const candidate = this.#memory.getCandidate(row.candidate_id);
    return candidate ? resolvedConfirmedNode(this.#memory, candidate) : undefined;
  }
}

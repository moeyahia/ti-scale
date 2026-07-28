import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import type {
  CanonicalDatabaseLeaseHandle,
  CanonicalDatabaseLeaseService,
} from "../maintenance";
import {
  ATTACK_CENTRIC_EDGE_TYPES,
  findReusableMemorySecretCategories,
  isAttackCentricReusableNodeType,
  validateAttackCentricEdgeEndpoints,
  type AttackCentricEdgeType,
  type MemoryNodeType,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";

const POLICY_VERSION = "historical-bundle-edge-binding-reconciliation-v1" as const;
const DEFAULT_MAX_BINDINGS = 500;
const MAX_BINDINGS = 5_000;
const SHA256 = /^[a-f0-9]{64}$/u;
const ACTOR = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const BUNDLE_ID = /^akb_[a-f0-9]{64}$/u;
const EDGE_KEY = /^ake_[a-f0-9]{48}$/u;
const ATTACK_EDGE_TYPES = new Set<string>(ATTACK_CENTRIC_EDGE_TYPES);

interface EligibleBindingRow {
  readonly bundle_id: string;
  readonly edge_key: string;
  readonly edge_type: AttackCentricEdgeType;
  readonly bundle_semantic_fingerprint: string;
  readonly source_node_id: string;
  readonly source_node_type: MemoryNodeType;
  readonly target_node_id: string;
  readonly target_node_type: MemoryNodeType;
  readonly canonical_edge_id: string;
  readonly canonical_edge_version: number;
}

interface StrictCustodyRow {
  readonly migration_id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly inventory_receipt_hash: string;
  readonly receipt_id: string;
  readonly source_candidate_id: string;
  readonly source_hash: string;
  readonly source_reference: string;
  readonly source_object_id: string;
  readonly source_object_kind: "accepted" | "source";
}

interface StrictCustodyProof {
  readonly count: number;
  readonly setHash: string;
  readonly auditMissionId: string;
  readonly auditRunId: string;
}

interface BindingCursor {
  readonly bundleId: string;
  readonly edgeKey: string;
}

interface PlannedBinding {
  readonly cursor: string;
  readonly bundleId: string;
  readonly edgeKey: string;
  readonly edgeType: AttackCentricEdgeType;
  readonly sourceNodeId: string;
  readonly sourceNodeType: MemoryNodeType;
  readonly targetNodeId: string;
  readonly targetNodeType: MemoryNodeType;
  readonly canonicalEdgeId: string;
  readonly canonicalEdgeVersion: number;
  readonly custodyCount: number;
  readonly custodySetHash: string;
  readonly auditMissionId: string;
  readonly auditRunId: string;
}

interface BindingPlan {
  readonly bindings: readonly PlannedBinding[];
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
  readonly bindingSetHash: string;
  readonly custodySetHash: string;
}

export interface HistoricalBundleEdgeBindingReconciliationInput {
  readonly actorId: string;
  readonly reason: string;
  readonly afterBindingCursor?: string;
  readonly maxBindings?: number;
}

export interface HistoricalBundleEdgeBindingReviewItem {
  readonly cursor: string;
  readonly bundleId: string;
  readonly edgeKey: string;
  readonly edgeType: AttackCentricEdgeType;
  readonly sourceNodeId: string;
  readonly sourceNodeType: MemoryNodeType;
  readonly targetNodeId: string;
  readonly targetNodeType: MemoryNodeType;
  readonly canonicalEdgeId: string;
  readonly canonicalEdgeVersion: number;
  readonly custodyCount: number;
  readonly custodySetHash: string;
}

export interface HistoricalBundleEdgeBindingReconciliationPreview {
  readonly schemaVersion: "ti_scale.historical_bundle_edge_binding_preview/v1";
  readonly policyVersion: typeof POLICY_VERSION;
  readonly previewHash: string;
  readonly bindingSetHash: string;
  readonly custodySetHash: string;
  readonly selection: {
    readonly afterBindingCursor: string | null;
    readonly maxBindings: number;
  };
  readonly bindingCount: number;
  readonly canonicalEdgeCount: number;
  readonly bundleCount: number;
  readonly bindings: readonly HistoricalBundleEdgeBindingReviewItem[];
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
  readonly mutationBoundary: {
    readonly createsCanonicalEdges: false;
    readonly changesVerificationState: false;
    readonly changesBundleStatus: false;
    readonly changesEvidenceOrOutcomeState: false;
    readonly changesProcedureCounters: false;
    readonly bindsExistingCanonicalEdgesOnly: true;
  };
}

export interface HistoricalBundleEdgeBindingReconciliationExecuteInput
  extends HistoricalBundleEdgeBindingReconciliationInput {
  readonly expectedPreviewHash: string;
  readonly acknowledgeExistingEdgeBindingOnly: true;
}

export interface HistoricalBundleEdgeBindingReconciliationResult {
  readonly status: "completed" | "replayed";
  readonly previewHash: string;
  readonly bindingSetHash: string;
  readonly custodySetHash: string;
  readonly auditRecordId: string;
  readonly bindingsReconciled: number;
  readonly canonicalEdgesReused: number;
  readonly bundlesTouched: number;
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
}

export interface HistoricalBundleEdgeBindingReconciliationSummary {
  readonly schemaVersion: "ti_scale.historical_bundle_edge_binding_reconciliation/v1";
  readonly policyVersion: typeof POLICY_VERSION;
  readonly totalBindingCount: number;
  readonly boundBindingCount: number;
  readonly unboundBindingCount: number;
  readonly eligibleExistingEdgeBindingCount: number;
  readonly ineligibleBindingCount: number;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizedActor(value: string): string {
  const normalized = value.trim().normalize("NFKC");
  if (!ACTOR.test(normalized)) throw new TypeError("A bounded operator actor identifier is required");
  return normalized;
}

function normalizedReason(value: string): string {
  const normalized = value.trim().normalize("NFKC");
  if (!normalized || Buffer.byteLength(normalized, "utf8") > 1_200) {
    throw new TypeError("A concise bundle-edge reconciliation reason is required");
  }
  if (findReusableMemorySecretCategories(normalized).length > 0) {
    throw new TypeError("The bundle-edge reconciliation reason must not contain authentication material");
  }
  return normalized;
}

function normalizedPageSize(value: number | undefined): number {
  const resolved = value ?? DEFAULT_MAX_BINDINGS;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > MAX_BINDINGS) {
    throw new TypeError(`maxBindings must be between 1 and ${MAX_BINDINGS}`);
  }
  return resolved;
}

function bindingCursor(bundleId: string, edgeKey: string): string {
  if (!BUNDLE_ID.test(bundleId) || !EDGE_KEY.test(edgeKey)) {
    throw new Error("A persisted bundle-edge identity is malformed");
  }
  return `${bundleId}/${edgeKey}`;
}

function parseBindingCursor(value: string | undefined): BindingCursor {
  const normalized = value?.trim().toLowerCase() ?? "";
  if (!normalized) return { bundleId: "", edgeKey: "" };
  const [bundleId, edgeKey, extra] = normalized.split("/");
  if (extra !== undefined || !bundleId || !edgeKey || !BUNDLE_ID.test(bundleId) || !EDGE_KEY.test(edgeKey)) {
    throw new TypeError("The binding cursor must be an exact bundle-id/edge-key pair");
  }
  return { bundleId, edgeKey };
}

/**
 * Reconciles only the missing provenance pointer between a staged typed bundle
 * edge and an already-existing, operator-reviewed canonical graph edge.
 *
 * This deliberately cannot create an edge, verify a fact, classify an
 * outcome, revive a stale candidate, or alter bundle procedure counters.
 */
export class HistoricalBundleEdgeBindingReconciliationService {
  readonly #audit: AuditTrailWriter;

  constructor(
    readonly database: SqliteDatabase,
    readonly clock: () => Date = () => new Date(),
  ) {
    this.#audit = new AuditTrailWriter(database);
  }

  preview(
    input: HistoricalBundleEdgeBindingReconciliationInput,
  ): HistoricalBundleEdgeBindingReconciliationPreview {
    const normalized = this.#normalize(input);
    const plan = this.#plan(normalized.afterBindingCursor, normalized.maxBindings);
    const bindings = plan.bindings.map((binding) => Object.freeze({
      cursor: binding.cursor,
      bundleId: binding.bundleId,
      edgeKey: binding.edgeKey,
      edgeType: binding.edgeType,
      sourceNodeId: binding.sourceNodeId,
      sourceNodeType: binding.sourceNodeType,
      targetNodeId: binding.targetNodeId,
      targetNodeType: binding.targetNodeType,
      canonicalEdgeId: binding.canonicalEdgeId,
      canonicalEdgeVersion: binding.canonicalEdgeVersion,
      custodyCount: binding.custodyCount,
      custodySetHash: binding.custodySetHash,
    }));
    const review = {
      schemaVersion: "ti_scale.historical_bundle_edge_binding_review/v1",
      policyVersion: POLICY_VERSION,
      actorId: normalized.actorId,
      reason: normalized.reason,
      selection: {
        afterBindingCursor: normalized.afterBindingCursor || null,
        maxBindings: normalized.maxBindings,
      },
      bindingSetHash: plan.bindingSetHash,
      custodySetHash: plan.custodySetHash,
      bindings,
      hasMore: plan.hasMore,
      nextSelectionCursor: plan.nextSelectionCursor,
      acknowledgement: "bind_existing_operator_reviewed_edges_only",
    } as const;
    return Object.freeze({
      schemaVersion: "ti_scale.historical_bundle_edge_binding_preview/v1" as const,
      policyVersion: POLICY_VERSION,
      previewHash: sha256(canonicalJson(review)),
      bindingSetHash: plan.bindingSetHash,
      custodySetHash: plan.custodySetHash,
      selection: review.selection,
      bindingCount: bindings.length,
      canonicalEdgeCount: new Set(bindings.map(({ canonicalEdgeId }) => canonicalEdgeId)).size,
      bundleCount: new Set(bindings.map(({ bundleId }) => bundleId)).size,
      bindings: Object.freeze(bindings),
      hasMore: plan.hasMore,
      nextSelectionCursor: plan.nextSelectionCursor,
      mutationBoundary: Object.freeze({
        createsCanonicalEdges: false as const,
        changesVerificationState: false as const,
        changesBundleStatus: false as const,
        changesEvidenceOrOutcomeState: false as const,
        changesProcedureCounters: false as const,
        bindsExistingCanonicalEdgesOnly: true as const,
      }),
    });
  }

  execute(
    input: HistoricalBundleEdgeBindingReconciliationExecuteInput,
    authority: {
      readonly handle: CanonicalDatabaseLeaseHandle;
      readonly leases: CanonicalDatabaseLeaseService;
    },
  ): HistoricalBundleEdgeBindingReconciliationResult {
    if (input.acknowledgeExistingEdgeBindingOnly !== true || !SHA256.test(input.expectedPreviewHash)) {
      throw new TypeError("Execution requires the exact preview hash and existing-edge-only acknowledgement");
    }
    const normalized = this.#normalize(input);
    return inImmediateTransaction(this.database, () => {
      authority.leases.assertActiveInCurrentTransaction(authority.handle);
      if (authority.handle.mode !== "writer") throw new Error("A canonical writer lease is required");
      const executionRequestHash = sha256(canonicalJson({
        actorId: normalized.actorId,
        reason: normalized.reason,
        afterBindingCursor: normalized.afterBindingCursor || null,
        maxBindings: normalized.maxBindings,
        expectedPreviewHash: input.expectedPreviewHash,
      }));
      const resourceId = `historical_bundle_edge_binding_${input.expectedPreviewHash}`;
      const replay = this.database.prepare(`
        SELECT id, details_json FROM audit_records
        WHERE action = 'historical_attack_knowledge.bundle_edges_reconciled'
          AND resource_type = 'historical_attack_knowledge_bundle_edge_binding'
          AND resource_id = ? AND actor_type = 'operator' AND actor_id = ?
        ORDER BY rowid LIMIT 1
      `).get(resourceId, normalized.actorId) as {
        readonly id: string;
        readonly details_json: string;
      } | undefined;
      if (replay) return this.#replay(replay, input.expectedPreviewHash, executionRequestHash);

      const preview = this.preview(normalized);
      if (preview.previewHash !== input.expectedPreviewHash) {
        throw new Error("Historical bundle-edge binding preview changed; review the current proof before retrying");
      }
      if (preview.bindingCount === 0) {
        throw new Error("No source-backed existing edge bindings are eligible on this page");
      }
      const executionPlan = this.#plan(normalized.afterBindingCursor, normalized.maxBindings);
      const byCursor = new Map(executionPlan.bindings.map((binding) => [binding.cursor, binding]));
      const now = this.clock().toISOString();
      const canonicalEdges = new Set<string>();
      const bundles = new Set<string>();
      for (const reviewed of preview.bindings) {
        const planned = byCursor.get(reviewed.cursor);
        if (!planned
            || planned.canonicalEdgeId !== reviewed.canonicalEdgeId
            || planned.canonicalEdgeVersion !== reviewed.canonicalEdgeVersion
            || planned.custodySetHash !== reviewed.custodySetHash
            || planned.custodyCount !== reviewed.custodyCount) {
          throw new Error("A reviewed bundle-edge or its verified-reference custody changed before execution");
        }
        const changed = this.database.prepare(`
          UPDATE attack_knowledge_bundle_edges
          SET materialized_edge_id = ?, materialized_at = ?
          WHERE bundle_id = ? AND edge_key = ? AND edge_type = ?
            AND materialized_edge_id IS NULL
        `).run(
          planned.canonicalEdgeId,
          now,
          planned.bundleId,
          planned.edgeKey,
          planned.edgeType,
        ).changes;
        if (changed !== 1) throw new Error("A reviewed bundle-edge changed during reconciliation");
        canonicalEdges.add(planned.canonicalEdgeId);
        bundles.add(planned.bundleId);
      }
      const anchor = executionPlan.bindings[0]!;
      const details = {
        policyVersion: POLICY_VERSION,
        previewHash: preview.previewHash,
        executionRequestHash,
        bindingSetHash: preview.bindingSetHash,
        custodySetHash: preview.custodySetHash,
        bindingsReconciled: preview.bindingCount,
        canonicalEdgesReused: canonicalEdges.size,
        bundlesTouched: bundles.size,
        afterBindingCursor: preview.selection.afterBindingCursor,
        maxBindings: preview.selection.maxBindings,
        firstBindingCursor: preview.bindings[0]!.cursor,
        lastBindingCursor: preview.bindings.at(-1)!.cursor,
        hasMore: preview.hasMore,
        nextSelectionCursor: preview.nextSelectionCursor,
        canonicalEdgesCreated: 0,
        verificationStateChanged: false,
        bundleStatusChanged: false,
        evidenceOrOutcomeStateChanged: false,
        procedureCountersChanged: false,
      } as const;
      const auditRecordId = this.#audit.append({
        missionId: anchor.auditMissionId,
        runId: anchor.auditRunId,
        actor: { type: "operator", id: normalized.actorId },
        action: "historical_attack_knowledge.bundle_edges_reconciled",
        resourceType: "historical_attack_knowledge_bundle_edge_binding",
        resourceId,
        reason: normalized.reason,
        details,
        occurredAt: now,
      });
      authority.leases.assertActiveInCurrentTransaction(authority.handle);
      return Object.freeze({
        status: "completed" as const,
        previewHash: preview.previewHash,
        bindingSetHash: preview.bindingSetHash,
        custodySetHash: preview.custodySetHash,
        auditRecordId,
        bindingsReconciled: preview.bindingCount,
        canonicalEdgesReused: canonicalEdges.size,
        bundlesTouched: bundles.size,
        hasMore: preview.hasMore,
        nextSelectionCursor: preview.nextSelectionCursor,
      });
    });
  }

  reconcile(): HistoricalBundleEdgeBindingReconciliationSummary {
    const counts = this.database.prepare(`
      SELECT COUNT(*) AS total,
        SUM(CASE WHEN materialized_edge_id IS NOT NULL THEN 1 ELSE 0 END) AS bound,
        SUM(CASE WHEN materialized_edge_id IS NULL THEN 1 ELSE 0 END) AS unbound
      FROM attack_knowledge_bundle_edges
    `).get() as { readonly total: number; readonly bound: number | null; readonly unbound: number | null };
    const eligible = Number((this.database.prepare(`
      SELECT COUNT(*) AS count FROM (${this.#eligibleBindingSql()}) eligible
    `).get("", "", "", "", Number.MAX_SAFE_INTEGER) as { readonly count: number }).count);
    const unbound = Number(counts.unbound ?? 0);
    return Object.freeze({
      schemaVersion: "ti_scale.historical_bundle_edge_binding_reconciliation/v1" as const,
      policyVersion: POLICY_VERSION,
      totalBindingCount: Number(counts.total),
      boundBindingCount: Number(counts.bound ?? 0),
      unboundBindingCount: unbound,
      eligibleExistingEdgeBindingCount: eligible,
      ineligibleBindingCount: unbound - eligible,
    });
  }

  #normalize(
    input: HistoricalBundleEdgeBindingReconciliationInput,
  ): Required<HistoricalBundleEdgeBindingReconciliationInput> {
    const cursor = parseBindingCursor(input.afterBindingCursor);
    return {
      actorId: normalizedActor(input.actorId),
      reason: normalizedReason(input.reason),
      afterBindingCursor: cursor.bundleId ? bindingCursor(cursor.bundleId, cursor.edgeKey) : "",
      maxBindings: normalizedPageSize(input.maxBindings),
    };
  }

  #plan(after: string, maximum: number): BindingPlan {
    const cursor = parseBindingCursor(after);
    const rows = this.database.prepare(this.#eligibleBindingSql()).all(
      cursor.bundleId,
      cursor.bundleId,
      cursor.edgeKey,
      cursor.bundleId,
      maximum + 1,
    ) as EligibleBindingRow[];
    const custodyByBundle = new Map<string, StrictCustodyProof>();
    const selected = rows.slice(0, maximum).map((row) => {
      if (!ATTACK_EDGE_TYPES.has(row.edge_type)) {
        throw new Error("An eligible bundle-edge uses a relationship outside the attack-memory taxonomy");
      }
      if (!isAttackCentricReusableNodeType(row.source_node_type)
          || !isAttackCentricReusableNodeType(row.target_node_type)) {
        throw new Error("An eligible bundle-edge resolved outside the reusable attack-memory taxonomy");
      }
      validateAttackCentricEdgeEndpoints(
        row.edge_type,
        row.source_node_type,
        row.target_node_type,
      );
      let custodyProof = custodyByBundle.get(row.bundle_id);
      if (!custodyProof) {
        custodyProof = this.#strictCustodyProof(row.bundle_id);
        custodyByBundle.set(row.bundle_id, custodyProof);
      }
      return Object.freeze({
        cursor: bindingCursor(row.bundle_id, row.edge_key),
        bundleId: row.bundle_id,
        edgeKey: row.edge_key,
        edgeType: row.edge_type,
        sourceNodeId: row.source_node_id,
        sourceNodeType: row.source_node_type,
        targetNodeId: row.target_node_id,
        targetNodeType: row.target_node_type,
        canonicalEdgeId: row.canonical_edge_id,
        canonicalEdgeVersion: Number(row.canonical_edge_version),
        custodyCount: custodyProof.count,
        custodySetHash: custodyProof.setHash,
        auditMissionId: custodyProof.auditMissionId,
        auditRunId: custodyProof.auditRunId,
      });
    });
    const hasMore = rows.length > selected.length;
    const nextSelectionCursor = hasMore ? selected.at(-1)?.cursor ?? null : null;
    const bindingSetHash = sha256(canonicalJson(selected.map((binding) => ({
      cursor: binding.cursor,
      edgeType: binding.edgeType,
      sourceNodeId: binding.sourceNodeId,
      targetNodeId: binding.targetNodeId,
      canonicalEdgeId: binding.canonicalEdgeId,
      canonicalEdgeVersion: binding.canonicalEdgeVersion,
    }))));
    const custodySetHash = sha256(canonicalJson(selected.map((binding) => ({
      cursor: binding.cursor,
      custodyCount: binding.custodyCount,
      custodySetHash: binding.custodySetHash,
    }))));
    return Object.freeze({
      bindings: Object.freeze(selected),
      hasMore,
      nextSelectionCursor,
      bindingSetHash,
      custodySetHash,
    });
  }

  #eligibleBindingSql(): string {
    return `
      SELECT edge.bundle_id, edge.edge_key, edge.edge_type,
        bundle.semantic_fingerprint AS bundle_semantic_fingerprint,
        source_node.id AS source_node_id, source_node.node_type AS source_node_type,
        target_node.id AS target_node_id, target_node.node_type AS target_node_type,
        canonical_edge.id AS canonical_edge_id,
        canonical_edge.version AS canonical_edge_version
      FROM attack_knowledge_bundle_edges edge
      JOIN attack_knowledge_bundles bundle ON bundle.id = edge.bundle_id
      JOIN attack_knowledge_bundle_candidates source_role
        ON source_role.bundle_id = edge.bundle_id AND source_role.role = edge.source_role
      JOIN attack_knowledge_candidate_registry source_registry
        ON source_registry.content_fingerprint = source_role.content_fingerprint
      JOIN memory_candidates source_candidate
        ON source_candidate.id = source_registry.candidate_id
      JOIN memory_nodes source_node ON source_node.id = source_candidate.proposed_node_id
      JOIN attack_knowledge_bundle_candidates target_role
        ON target_role.bundle_id = edge.bundle_id AND target_role.role = edge.target_role
      JOIN attack_knowledge_candidate_registry target_registry
        ON target_registry.content_fingerprint = target_role.content_fingerprint
      JOIN memory_candidates target_candidate
        ON target_candidate.id = target_registry.candidate_id
      JOIN memory_nodes target_node ON target_node.id = target_candidate.proposed_node_id
      JOIN memory_edges_safe canonical_edge
        ON canonical_edge.source_node_id = source_node.id
       AND canonical_edge.edge_type = edge.edge_type
       AND canonical_edge.target_node_id = target_node.id
       AND canonical_edge.id = (
         SELECT latest.id FROM memory_edges_safe latest
         WHERE latest.source_node_id = source_node.id
           AND latest.edge_type = edge.edge_type
           AND latest.target_node_id = target_node.id
         ORDER BY latest.version DESC, latest.id DESC LIMIT 1
       )
      WHERE edge.materialized_edge_id IS NULL
        AND source_candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND target_candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND source_node.scope = 'global' AND source_node.engagement_id IS NULL
        AND source_node.mission_id IS NULL AND source_node.confirmation_state = 'confirmed'
        AND source_node.lifecycle_status IN ('confirmed', 'verified')
        AND source_node.author_type = 'operator'
        AND target_node.scope = 'global' AND target_node.engagement_id IS NULL
        AND target_node.mission_id IS NULL AND target_node.confirmation_state = 'confirmed'
        AND target_node.lifecycle_status IN ('confirmed', 'verified')
        AND target_node.author_type = 'operator'
        AND canonical_edge.scope = 'global' AND canonical_edge.engagement_id IS NULL
        AND canonical_edge.mission_id IS NULL
        AND canonical_edge.lifecycle_status IN ('confirmed', 'verified')
        AND canonical_edge.author_type = 'operator'
        AND EXISTS (
          SELECT 1
          FROM historical_attack_knowledge_bundle_sources custody_source
          JOIN attack_knowledge_provenance_receipts custody_receipt
            ON custody_receipt.id = custody_source.receipt_id
           AND custody_receipt.source_class = 'historical'
          JOIN historical_attack_knowledge_source_occurrences occurrence
            ON occurrence.candidate_id = custody_source.candidate_id
           AND occurrence.source_hash = custody_source.source_hash
          JOIN historical_attack_knowledge_import_contexts context
            ON context.migration_id = occurrence.migration_id
          JOIN legacy_migration_runs migration
            ON migration.id = occurrence.migration_id
           AND migration.status = 'completed'
           AND migration.brain_projection_mode = 'attack-knowledge-only'
           AND migration.source_retention = 'verified-reference'
          JOIN legacy_migration_inventory_receipts inventory_receipt
            ON inventory_receipt.migration_id = occurrence.migration_id
          JOIN legacy_migration_source_objects source_object
            ON source_object.migration_id = occurrence.migration_id
           AND source_object.source_reference = occurrence.source_reference
           AND source_object.source_sha256 = occurrence.source_hash
           AND source_object.verification_status = 'verified_reference'
           AND source_object.object_kind IN ('accepted', 'source')
          WHERE custody_source.bundle_id = edge.bundle_id
        )
        AND (
          edge.bundle_id > ?
          OR (edge.bundle_id = ? AND edge.edge_key > ?)
          OR (? = '' AND edge.bundle_id > '')
        )
      ORDER BY edge.bundle_id, edge.edge_key
      LIMIT ?
    `;
  }

  #strictCustodyProof(bundleId: string): StrictCustodyProof {
    const rows = this.database.prepare(`
      SELECT DISTINCT occurrence.migration_id, context.mission_id, context.run_id,
        inventory_receipt.receipt_hash AS inventory_receipt_hash,
        source.receipt_id, source.candidate_id AS source_candidate_id,
        source.source_hash, occurrence.source_reference,
        source_object.id AS source_object_id,
        source_object.object_kind AS source_object_kind
      FROM historical_attack_knowledge_bundle_sources source
      JOIN attack_knowledge_provenance_receipts receipt
        ON receipt.id = source.receipt_id AND receipt.source_class = 'historical'
      JOIN historical_attack_knowledge_source_occurrences occurrence
        ON occurrence.candidate_id = source.candidate_id
       AND occurrence.source_hash = source.source_hash
      JOIN historical_attack_knowledge_import_contexts context
        ON context.migration_id = occurrence.migration_id
      JOIN legacy_migration_runs migration
        ON migration.id = occurrence.migration_id
       AND migration.status = 'completed'
       AND migration.brain_projection_mode = 'attack-knowledge-only'
       AND migration.source_retention = 'verified-reference'
      JOIN legacy_migration_inventory_receipts inventory_receipt
        ON inventory_receipt.migration_id = occurrence.migration_id
      JOIN legacy_migration_source_objects source_object
        ON source_object.migration_id = occurrence.migration_id
       AND source_object.source_reference = occurrence.source_reference
       AND source_object.source_sha256 = occurrence.source_hash
       AND source_object.verification_status = 'verified_reference'
       AND source_object.object_kind IN ('accepted', 'source')
      WHERE source.bundle_id = ?
      ORDER BY occurrence.migration_id, source.receipt_id, source.candidate_id,
        source.source_hash, occurrence.source_reference, source_object.id
    `).iterate(bundleId) as IterableIterator<StrictCustodyRow>;
    // Hash the exact canonical array representation incrementally. This is
    // byte-for-byte equivalent to hashing canonicalJson(allRows), but does not
    // materialize a high-fanout custody set in the JavaScript heap.
    const digest = createHash("sha256");
    digest.update("[");
    let count = 0;
    let auditMissionId: string | undefined;
    let auditRunId: string | undefined;
    for (const item of rows) {
      if (count > 0) digest.update(",");
      digest.update(canonicalJson({
        migrationId: item.migration_id,
        inventoryReceiptHash: item.inventory_receipt_hash,
        receiptId: item.receipt_id,
        sourceCandidateId: item.source_candidate_id,
        sourceHash: item.source_hash,
        sourceReference: item.source_reference,
        sourceObjectId: item.source_object_id,
        sourceObjectKind: item.source_object_kind,
      }));
      auditMissionId ??= item.mission_id;
      auditRunId ??= item.run_id;
      count += 1;
    }
    digest.update("]");
    if (count === 0 || !auditMissionId || !auditRunId) {
      throw new Error("An eligible bundle-edge lost its strict verified-reference custody");
    }
    return Object.freeze({
      count,
      setHash: digest.digest("hex"),
      auditMissionId,
      auditRunId,
    });
  }

  #replay(
    row: { readonly id: string; readonly details_json: string },
    expectedPreviewHash: string,
    expectedExecutionRequestHash: string,
  ): HistoricalBundleEdgeBindingReconciliationResult {
    const details = JSON.parse(row.details_json) as Record<string, unknown>;
    const integer = (key: string): number => {
      const value = details[key];
      if (!Number.isSafeInteger(value) || Number(value) < 0) {
        throw new Error("Prior bundle-edge reconciliation audit is malformed");
      }
      return Number(value);
    };
    if (details.previewHash !== expectedPreviewHash
        || details.executionRequestHash !== expectedExecutionRequestHash
        || typeof details.bindingSetHash !== "string" || !SHA256.test(details.bindingSetHash)
        || typeof details.custodySetHash !== "string" || !SHA256.test(details.custodySetHash)
        || typeof details.hasMore !== "boolean"
        || !(details.nextSelectionCursor === null || typeof details.nextSelectionCursor === "string")) {
      throw new Error("Prior bundle-edge reconciliation audit does not match this exact reviewed request");
    }
    return Object.freeze({
      status: "replayed" as const,
      previewHash: expectedPreviewHash,
      bindingSetHash: details.bindingSetHash,
      custodySetHash: details.custodySetHash,
      auditRecordId: row.id,
      bindingsReconciled: integer("bindingsReconciled"),
      canonicalEdgesReused: integer("canonicalEdgesReused"),
      bundlesTouched: integer("bundlesTouched"),
      hasMore: details.hasMore,
      nextSelectionCursor: details.nextSelectionCursor as string | null,
    });
  }
}

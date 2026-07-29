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
  isAttackCentricReusableNodeType,
  MemoryRepository,
  validateAttackCentricEdgeEndpoints,
  type AttackCentricEdgeType,
  type MemoryNodeType,
  type MemorySensitivity,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";

const POLICY_VERSION = "historical-reusable-orphan-link-repair-v1" as const;
const DEFAULT_MAX_RELATIONSHIPS = 500;
const MAX_RELATIONSHIPS = 5_000;
const MAX_EXACT_PROVENANCE_BUNDLES = 8;
const SHA256 = /^[a-f0-9]{64}$/u;
const ACTOR = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const ATTACK_EDGE_TYPES = new Set<string>(ATTACK_CENTRIC_EDGE_TYPES);

type UnresolvedReason =
  | "no_typed_relationship"
  | "missing_hash_bound_source_custody"
  | "counterpart_not_operator_reviewed"
  | "invalid_typed_endpoints"
  | "relationship_conflict_or_suppression";

interface ReusableNodeRow {
  readonly content_fingerprint: string;
  readonly id: string;
  readonly node_type: MemoryNodeType;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly lifecycle_status: "confirmed" | "verified";
}

interface StagedEdgeRow {
  readonly bundle_id: string;
  readonly edge_key: string;
  readonly edge_type: string;
  readonly source_fingerprint: string;
  readonly target_fingerprint: string;
  readonly semantic_fingerprint: string;
  readonly last_observed_at: string;
}

interface SourceCustodyRow {
  readonly bundle_id: string;
  readonly mission_id: string;
  readonly run_id: string;
}

interface BundleBinding {
  readonly bundleId: string;
  readonly edgeKey: string;
  readonly semanticFingerprint: string;
  readonly observedAt: string;
  readonly missionId: string;
  readonly runId: string;
}

interface RepairPlanRelationship {
  readonly proposalKey: string;
  readonly sourceNode: ReusableNodeRow;
  readonly targetNode: ReusableNodeRow;
  readonly edgeType: AttackCentricEdgeType;
  readonly bindings: readonly BundleBinding[];
  readonly bundleSetHash: string;
}

interface RepairPlan {
  readonly orphanNodeCount: number;
  readonly orphanNodeIds: ReadonlySet<string>;
  readonly orphanNodeTypeCounts: Readonly<Record<string, number>>;
  readonly repairableOrphanNodeIds: ReadonlySet<string>;
  readonly unresolvedReasonCounts: Readonly<Record<UnresolvedReason, number>>;
  readonly relationships: readonly RepairPlanRelationship[];
}

export interface HistoricalReusableKnowledgeLinkRepairInput {
  readonly actorId: string;
  readonly reason: string;
  readonly afterProposalKey?: string;
  readonly maxRelationships?: number;
}

export interface HistoricalReusableKnowledgeLinkRepairPreviewRelationship {
  readonly proposalKey: string;
  readonly sourceNodeId: string;
  readonly sourceNodeType: MemoryNodeType;
  readonly edgeType: AttackCentricEdgeType;
  readonly targetNodeId: string;
  readonly targetNodeType: MemoryNodeType;
  readonly bundleEdgeCount: number;
  readonly bundleSetHash: string;
}

export interface HistoricalReusableKnowledgeLinkRepairPreview {
  readonly schemaVersion: "ti_scale.historical_reusable_orphan_link_repair_preview/v1";
  readonly policyVersion: typeof POLICY_VERSION;
  readonly previewHash: string;
  readonly selection: {
    readonly afterProposalKey: string | null;
    readonly maxRelationships: number;
  };
  readonly orphanNodeCount: number;
  readonly orphanNodeTypeCounts: Readonly<Record<string, number>>;
  readonly repairableOrphanNodeCount: number;
  readonly unresolvedOrphanNodeCount: number;
  readonly unresolvedReasonCounts: Readonly<Record<UnresolvedReason, number>>;
  readonly relationshipCount: number;
  readonly relationships: readonly HistoricalReusableKnowledgeLinkRepairPreviewRelationship[];
  readonly hasMore: boolean;
  readonly nextProposalKey: string | null;
  readonly privacyBoundary: {
    readonly reusableContentContainsOperationalLocators: false;
    readonly privateAttributionRemainsInMemorySources: true;
    readonly rawSourceContentCopiedToGraph: false;
  };
}

export interface HistoricalReusableKnowledgeLinkRepairExecuteInput
  extends HistoricalReusableKnowledgeLinkRepairInput {
  readonly expectedPreviewHash: string;
  readonly acknowledged: true;
}

export interface HistoricalReusableKnowledgeLinkRepairResult {
  readonly status: "completed" | "replayed";
  readonly previewHash: string;
  readonly auditRecordId: string;
  readonly relationshipsCreated: number;
  readonly bundleEdgeBindingsReconciled: number;
  readonly orphanNodesConnected: number;
  readonly hasMore: boolean;
  readonly nextProposalKey: string | null;
}

export interface HistoricalReusableKnowledgeLinkReconciliation {
  readonly schemaVersion: "ti_scale.historical_reusable_orphan_link_reconciliation/v1";
  readonly policyVersion: typeof POLICY_VERSION;
  readonly reusableNodeCount: number;
  readonly connectedReusableNodeCount: number;
  readonly orphanNodeCount: number;
  readonly orphanNodeTypeCounts: Readonly<Record<string, number>>;
  readonly repairableOrphanNodeCount: number;
  readonly repairableRelationshipCount: number;
  readonly unresolvedOrphanNodeCount: number;
  readonly unresolvedReasonCounts: Readonly<Record<UnresolvedReason, number>>;
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
    throw new TypeError("A concise orphan-link repair reason is required");
  }
  return normalized;
}

function normalizedPageSize(value: number | undefined): number {
  const resolved = value ?? DEFAULT_MAX_RELATIONSHIPS;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > MAX_RELATIONSHIPS) {
    throw new TypeError(`maxRelationships must be between 1 and ${MAX_RELATIONSHIPS}`);
  }
  return resolved;
}

function normalizedCursor(value: string | undefined): string {
  const normalized = value?.trim().toLowerCase() ?? "";
  if (normalized && !SHA256.test(normalized)) {
    throw new TypeError("The orphan-link repair cursor must be a lowercase SHA-256 digest");
  }
  return normalized;
}

function edgeId(sourceNodeId: string, edgeType: string, targetNodeId: string): string {
  return `medge_orphan_${sha256(canonicalJson({ sourceNodeId, edgeType, targetNodeId })).slice(0, 48)}`;
}

function edgeTitle(edgeType: string): string {
  return edgeType.split("_").map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`).join(" ");
}

function maximumSensitivity(left: MemorySensitivity, right: MemorySensitivity): MemorySensitivity {
  const ranking: readonly MemorySensitivity[] = ["public", "internal", "private", "restricted"];
  return ranking[Math.max(ranking.indexOf(left), ranking.indexOf(right))]!;
}

function emptyReasonCounts(): Record<UnresolvedReason, number> {
  return {
    no_typed_relationship: 0,
    missing_hash_bound_source_custody: 0,
    counterpart_not_operator_reviewed: 0,
    invalid_typed_endpoints: 0,
    relationship_conflict_or_suppression: 0,
  };
}

/**
 * Repairs graph materialization gaps only from relationships already emitted
 * by the typed historical extractor and backed by an immutable source-custody
 * chain. It never infers from titles, co-occurrence, target identity, paths,
 * mission IDs, or run IDs. Re-extraction is therefore the only way to add a
 * relationship that an older parser did not type.
 */
export class HistoricalReusableKnowledgeLinkRepairService {
  readonly #memory: MemoryRepository;
  readonly #audit: AuditTrailWriter;

  constructor(
    readonly database: SqliteDatabase,
    readonly clock: () => Date = () => new Date(),
  ) {
    this.#memory = new MemoryRepository(database, { clock });
    this.#audit = new AuditTrailWriter(database);
  }

  preview(input: HistoricalReusableKnowledgeLinkRepairInput): HistoricalReusableKnowledgeLinkRepairPreview {
    const normalized = this.#normalize(input);
    const plan = this.#plan();
    const available = plan.relationships.filter(({ proposalKey }) =>
      proposalKey > normalized.afterProposalKey);
    const selected = available.slice(0, normalized.maxRelationships);
    const relationships = selected.map((relationship) => ({
      proposalKey: relationship.proposalKey,
      sourceNodeId: relationship.sourceNode.id,
      sourceNodeType: relationship.sourceNode.node_type,
      edgeType: relationship.edgeType,
      targetNodeId: relationship.targetNode.id,
      targetNodeType: relationship.targetNode.node_type,
      bundleEdgeCount: relationship.bindings.length,
      bundleSetHash: relationship.bundleSetHash,
    }));
    const hasMore = available.length > selected.length;
    const review = {
      schemaVersion: "ti_scale.historical_reusable_orphan_link_repair_review/v1",
      policyVersion: POLICY_VERSION,
      actorId: normalized.actorId,
      reason: normalized.reason,
      selection: {
        afterProposalKey: normalized.afterProposalKey || null,
        maxRelationships: normalized.maxRelationships,
      },
      orphanNodeCount: plan.orphanNodeCount,
      repairableOrphanNodeCount: plan.repairableOrphanNodeIds.size,
      unresolvedReasonCounts: plan.unresolvedReasonCounts,
      relationships,
      hasMore,
      nextProposalKey: selected.at(-1)?.proposalKey ?? null,
    } as const;
    return Object.freeze({
      schemaVersion: "ti_scale.historical_reusable_orphan_link_repair_preview/v1" as const,
      policyVersion: POLICY_VERSION,
      previewHash: sha256(canonicalJson(review)),
      selection: review.selection,
      orphanNodeCount: plan.orphanNodeCount,
      orphanNodeTypeCounts: plan.orphanNodeTypeCounts,
      repairableOrphanNodeCount: plan.repairableOrphanNodeIds.size,
      unresolvedOrphanNodeCount: plan.orphanNodeCount - plan.repairableOrphanNodeIds.size,
      unresolvedReasonCounts: plan.unresolvedReasonCounts,
      relationshipCount: relationships.length,
      relationships: Object.freeze(relationships),
      hasMore,
      nextProposalKey: review.nextProposalKey,
      privacyBoundary: Object.freeze({
        reusableContentContainsOperationalLocators: false as const,
        privateAttributionRemainsInMemorySources: true as const,
        rawSourceContentCopiedToGraph: false as const,
      }),
    });
  }

  execute(
    input: HistoricalReusableKnowledgeLinkRepairExecuteInput,
    authority: {
      readonly handle: CanonicalDatabaseLeaseHandle;
      readonly leases: CanonicalDatabaseLeaseService;
    },
  ): HistoricalReusableKnowledgeLinkRepairResult {
    if (!input.acknowledged || !SHA256.test(input.expectedPreviewHash)) {
      throw new TypeError("Execution requires the exact preview hash and explicit acknowledgement");
    }
    const normalized = this.#normalize(input);
    return inImmediateTransaction(this.database, () => {
      authority.leases.assertActiveInCurrentTransaction(authority.handle);
      if (authority.handle.mode !== "writer") throw new Error("A canonical writer lease is required");
      const executionRequestHash = sha256(canonicalJson({
        actorId: normalized.actorId,
        reason: normalized.reason,
        afterProposalKey: normalized.afterProposalKey || null,
        maxRelationships: normalized.maxRelationships,
        expectedPreviewHash: input.expectedPreviewHash,
      }));
      const resourceId = `historical_orphan_link_repair_${input.expectedPreviewHash}`;
      const replay = this.database.prepare(`
        SELECT id, details_json FROM audit_records
        WHERE action = 'historical_attack_knowledge.orphan_links_repaired'
          AND resource_type = 'historical_reusable_knowledge_graph'
          AND resource_id = ? AND actor_type = 'operator' AND actor_id = ?
        ORDER BY rowid LIMIT 1
      `).get(resourceId, normalized.actorId) as {
        readonly id: string;
        readonly details_json: string;
      } | undefined;
      if (replay) return this.#replay(replay, input.expectedPreviewHash, executionRequestHash);

      const preview = this.preview(normalized);
      if (preview.previewHash !== input.expectedPreviewHash) {
        throw new Error("Historical orphan-link repair preview changed; review the current proof before retrying");
      }
      if (preview.relationshipCount === 0) {
        throw new Error("No source-backed orphan relationships are eligible on this page");
      }
      const executionPlan = this.#plan();
      const planByKey = new Map(executionPlan.relationships.map((item) => [item.proposalKey, item]));
      const createdEdgeIds: string[] = [];
      const connectedOrphans = new Set<string>();
      let bundleEdgeBindingsReconciled = 0;
      for (const reviewed of preview.relationships) {
        const proposal = planByKey.get(reviewed.proposalKey);
        if (!proposal || proposal.bundleSetHash !== reviewed.bundleSetHash
            || proposal.bindings.length !== reviewed.bundleEdgeCount) {
          throw new Error("A reviewed orphan relationship changed before execution");
        }
        const id = edgeId(proposal.sourceNode.id, proposal.edgeType, proposal.targetNode.id);
        const provenance = proposal.bindings.slice(0, MAX_EXACT_PROVENANCE_BUNDLES).map((binding) => ({
          sourceType: "attack_knowledge_bundle",
          sourceId: binding.bundleId,
          sourceHash: binding.semanticFingerprint,
          acquiredAt: binding.observedAt,
        }));
        if (proposal.bindings.length > MAX_EXACT_PROVENANCE_BUNDLES) {
          provenance.push({
            sourceType: "attack_knowledge_bundle_set",
            sourceId: `akbs_${proposal.bundleSetHash}`,
            sourceHash: proposal.bundleSetHash,
            acquiredAt: proposal.bindings.reduce(
              (latest, binding) => binding.observedAt > latest ? binding.observedAt : latest,
              proposal.bindings[0]!.observedAt,
            ),
          });
        }
        this.#memory.createEdge({
          id,
          sourceNodeId: proposal.sourceNode.id,
          targetNodeId: proposal.targetNode.id,
          edgeType: proposal.edgeType,
          title: edgeTitle(proposal.edgeType),
          summary: "Operator-confirmed relationship reconstructed from an exact typed, hash-bound historical source bundle.",
          scope: { kind: "global" },
          sensitivity: maximumSensitivity(
            proposal.sourceNode.sensitivity,
            proposal.targetNode.sensitivity,
          ),
          confidence: Math.min(proposal.sourceNode.confidence, proposal.targetNode.confidence),
          lifecycleStatus: "confirmed",
          provenance: {
            method: "derived",
            explanation: "Reconciled from a typed historical bundle whose private source identity and hash remain in canonical source custody.",
            sources: provenance,
          },
          explanation: "The operator approved this deterministic graph repair after reviewing the exact relationship set; no target or engagement identity was copied into reusable memory.",
          authorType: "operator",
          authorId: normalized.actorId,
        });
        for (const binding of proposal.bindings) {
          const changed = this.database.prepare(`
            UPDATE attack_knowledge_bundle_edges
            SET materialized_edge_id = ?, materialized_at = ?
            WHERE bundle_id = ? AND edge_key = ? AND materialized_edge_id IS NULL
          `).run(id, this.clock().toISOString(), binding.bundleId, binding.edgeKey).changes;
          if (changed !== 1) throw new Error("A staged orphan relationship changed during reconciliation");
          bundleEdgeBindingsReconciled += 1;
        }
        createdEdgeIds.push(id);
        if (executionPlan.orphanNodeIds.has(proposal.sourceNode.id)) {
          connectedOrphans.add(proposal.sourceNode.id);
        }
        if (executionPlan.orphanNodeIds.has(proposal.targetNode.id)) {
          connectedOrphans.add(proposal.targetNode.id);
        }
      }
      const firstProposal = planByKey.get(preview.relationships[0]!.proposalKey)!;
      const auditRecordId = this.#audit.append({
        missionId: firstProposal.bindings[0]!.missionId,
        runId: firstProposal.bindings[0]!.runId,
        actor: { type: "operator", id: normalized.actorId },
        action: "historical_attack_knowledge.orphan_links_repaired",
        resourceType: "historical_reusable_knowledge_graph",
        resourceId,
        reason: normalized.reason,
        details: {
          policyVersion: POLICY_VERSION,
          previewHash: preview.previewHash,
          executionRequestHash,
          relationshipsCreated: createdEdgeIds.length,
          bundleEdgeBindingsReconciled,
          orphanNodesConnected: connectedOrphans.size,
          createdEdgeIds,
          proposalKeys: preview.relationships.map(({ proposalKey }) => proposalKey),
          bundleSetHashes: preview.relationships.map(({ bundleSetHash }) => bundleSetHash),
          hasMore: preview.hasMore,
          nextProposalKey: preview.nextProposalKey,
          reusableContentContainsOperationalLocators: false,
          privateAttributionRemainsInMemorySources: true,
        },
        occurredAt: this.clock().toISOString(),
      });
      authority.leases.assertActiveInCurrentTransaction(authority.handle);
      return Object.freeze({
        status: "completed" as const,
        previewHash: preview.previewHash,
        auditRecordId,
        relationshipsCreated: createdEdgeIds.length,
        bundleEdgeBindingsReconciled,
        orphanNodesConnected: connectedOrphans.size,
        hasMore: preview.hasMore,
        nextProposalKey: preview.nextProposalKey,
      });
    });
  }

  reconcile(): HistoricalReusableKnowledgeLinkReconciliation {
    const plan = this.#plan();
    const reusableNodeCount = Number((this.database.prepare(`
      SELECT COUNT(DISTINCT node.id) AS count
      FROM attack_knowledge_candidate_registry registry
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      JOIN memory_nodes node ON node.id = candidate.proposed_node_id
      WHERE candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.confirmation_state = 'confirmed'
        AND node.lifecycle_status IN ('confirmed', 'verified')
    `).get() as { readonly count: number }).count);
    return Object.freeze({
      schemaVersion: "ti_scale.historical_reusable_orphan_link_reconciliation/v1" as const,
      policyVersion: POLICY_VERSION,
      reusableNodeCount,
      connectedReusableNodeCount: reusableNodeCount - plan.orphanNodeCount,
      orphanNodeCount: plan.orphanNodeCount,
      orphanNodeTypeCounts: plan.orphanNodeTypeCounts,
      repairableOrphanNodeCount: plan.repairableOrphanNodeIds.size,
      repairableRelationshipCount: plan.relationships.length,
      unresolvedOrphanNodeCount: plan.orphanNodeCount - plan.repairableOrphanNodeIds.size,
      unresolvedReasonCounts: plan.unresolvedReasonCounts,
    });
  }

  #normalize(input: HistoricalReusableKnowledgeLinkRepairInput): Required<HistoricalReusableKnowledgeLinkRepairInput> {
    return {
      actorId: normalizedActor(input.actorId),
      reason: normalizedReason(input.reason),
      afterProposalKey: normalizedCursor(input.afterProposalKey),
      maxRelationships: normalizedPageSize(input.maxRelationships),
    };
  }

  #plan(): RepairPlan {
    const reusableNodes = this.database.prepare(`
      SELECT registry.content_fingerprint, node.id, node.node_type,
        node.sensitivity, node.confidence, node.lifecycle_status
      FROM attack_knowledge_candidate_registry registry
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      JOIN memory_nodes node ON node.id = candidate.proposed_node_id
      WHERE candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.confirmation_state = 'confirmed'
        AND node.lifecycle_status IN ('confirmed', 'verified')
      ORDER BY registry.content_fingerprint
    `).all() as ReusableNodeRow[];
    const nodeByFingerprint = new Map(reusableNodes.map((node) => [node.content_fingerprint, node]));
    const connectedNodeIds = new Set((this.database.prepare(`
      SELECT source_node_id AS id FROM memory_edges_safe
      WHERE lifecycle_status IN ('confirmed', 'verified')
      UNION
      SELECT target_node_id AS id FROM memory_edges_safe
      WHERE lifecycle_status IN ('confirmed', 'verified')
    `).all() as Array<{ readonly id: string }>).map(({ id }) => id));
    const orphanNodes = [...new Map(reusableNodes
      .filter((node) => !connectedNodeIds.has(node.id))
      .map((node) => [node.id, node])).values()];
    const orphanNodeIds = new Set(orphanNodes.map(({ id }) => id));
    const orphanNodeTypeCounts: Record<string, number> = {};
    orphanNodes.forEach(({ node_type }) => {
      orphanNodeTypeCounts[node_type] = (orphanNodeTypeCounts[node_type] ?? 0) + 1;
    });
    const stagedEdges = this.database.prepare(`
      SELECT edge.bundle_id, edge.edge_key, edge.edge_type,
        source.content_fingerprint AS source_fingerprint,
        target.content_fingerprint AS target_fingerprint,
        bundle.semantic_fingerprint, bundle.last_observed_at
      FROM attack_knowledge_bundle_edges edge
      JOIN attack_knowledge_bundle_candidates source
        ON source.bundle_id = edge.bundle_id AND source.role = edge.source_role
      JOIN attack_knowledge_bundle_candidates target
        ON target.bundle_id = edge.bundle_id AND target.role = edge.target_role
      JOIN attack_knowledge_bundles bundle ON bundle.id = edge.bundle_id
      WHERE edge.materialized_edge_id IS NULL
      ORDER BY edge.bundle_id, edge.edge_key
    `).all() as StagedEdgeRow[];
    const custodyRows = this.database.prepare(`
      SELECT DISTINCT source.bundle_id, context.mission_id, context.run_id
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
      JOIN legacy_migration_inventory_receipts inventory_receipt
        ON inventory_receipt.migration_id = occurrence.migration_id
      JOIN legacy_migration_source_objects source_object
        ON source_object.migration_id = occurrence.migration_id
       AND source_object.source_reference = occurrence.source_reference
       AND source_object.source_sha256 = occurrence.source_hash
       AND source_object.verification_status = 'verified_reference'
       AND source_object.object_kind IN ('accepted', 'source')
      ORDER BY source.bundle_id, occurrence.migration_id
    `).all() as SourceCustodyRow[];
    const custodyByBundle = new Map<string, SourceCustodyRow>();
    custodyRows.forEach((row) => {
      if (!custodyByBundle.has(row.bundle_id)) custodyByBundle.set(row.bundle_id, row);
    });
    const reasonsByOrphan = new Map<string, Set<UnresolvedReason>>();
    orphanNodes.forEach(({ id }) => reasonsByOrphan.set(id, new Set()));
    const incidentByOrphan = new Map<string, number>();
    const grouped = new Map<string, {
      sourceNode: ReusableNodeRow;
      targetNode: ReusableNodeRow;
      edgeType: AttackCentricEdgeType;
      bindings: BundleBinding[];
    }>();

    for (const staged of stagedEdges) {
      const sourceNode = nodeByFingerprint.get(staged.source_fingerprint);
      const targetNode = nodeByFingerprint.get(staged.target_fingerprint);
      const incidentOrphans = [sourceNode, targetNode]
        .filter((node): node is ReusableNodeRow => Boolean(node && orphanNodeIds.has(node.id)));
      if (incidentOrphans.length === 0) continue;
      incidentOrphans.forEach(({ id }) => incidentByOrphan.set(id, (incidentByOrphan.get(id) ?? 0) + 1));
      if (!sourceNode || !targetNode) {
        incidentOrphans.forEach(({ id }) => reasonsByOrphan.get(id)!.add("counterpart_not_operator_reviewed"));
        continue;
      }
      if (!ATTACK_EDGE_TYPES.has(staged.edge_type)) {
        incidentOrphans.forEach(({ id }) => reasonsByOrphan.get(id)!.add("invalid_typed_endpoints"));
        continue;
      }
      try {
        if (!isAttackCentricReusableNodeType(sourceNode.node_type)
            || !isAttackCentricReusableNodeType(targetNode.node_type)) throw new TypeError("not reusable");
        validateAttackCentricEdgeEndpoints(staged.edge_type, sourceNode.node_type, targetNode.node_type);
      } catch {
        incidentOrphans.forEach(({ id }) => reasonsByOrphan.get(id)!.add("invalid_typed_endpoints"));
        continue;
      }
      const existing = this.database.prepare(`
        SELECT id FROM memory_edges
        WHERE source_node_id = ? AND edge_type = ? AND target_node_id = ?
        ORDER BY version DESC LIMIT 1
      `).get(sourceNode.id, staged.edge_type, targetNode.id);
      if (existing) {
        incidentOrphans.forEach(({ id }) => reasonsByOrphan.get(id)!.add("relationship_conflict_or_suppression"));
        continue;
      }
      const custody = custodyByBundle.get(staged.bundle_id);
      if (!custody) {
        incidentOrphans.forEach(({ id }) => reasonsByOrphan.get(id)!.add("missing_hash_bound_source_custody"));
        continue;
      }
      const edgeType = staged.edge_type as AttackCentricEdgeType;
      const key = sha256(canonicalJson({
        sourceNodeId: sourceNode.id,
        edgeType,
        targetNodeId: targetNode.id,
      }));
      const item = grouped.get(key) ?? { sourceNode, targetNode, edgeType, bindings: [] };
      item.bindings.push({
        bundleId: staged.bundle_id,
        edgeKey: staged.edge_key,
        semanticFingerprint: staged.semantic_fingerprint,
        observedAt: staged.last_observed_at,
        missionId: custody.mission_id,
        runId: custody.run_id,
      });
      grouped.set(key, item);
    }

    const relationships = [...grouped.entries()].map(([proposalKey, item]) => {
      const bindings = item.bindings.sort((left, right) =>
        left.bundleId.localeCompare(right.bundleId) || left.edgeKey.localeCompare(right.edgeKey));
      return Object.freeze({
        proposalKey,
        sourceNode: item.sourceNode,
        targetNode: item.targetNode,
        edgeType: item.edgeType,
        bindings: Object.freeze(bindings),
        bundleSetHash: sha256(canonicalJson(bindings.map((binding) => ({
          bundleId: binding.bundleId,
          edgeKey: binding.edgeKey,
          semanticFingerprint: binding.semanticFingerprint,
          observedAt: binding.observedAt,
        })))),
      });
    }).sort((left, right) => left.proposalKey.localeCompare(right.proposalKey));
    const repairableOrphanNodeIds = new Set<string>();
    relationships.forEach(({ sourceNode, targetNode }) => {
      if (orphanNodeIds.has(sourceNode.id)) repairableOrphanNodeIds.add(sourceNode.id);
      if (orphanNodeIds.has(targetNode.id)) repairableOrphanNodeIds.add(targetNode.id);
    });
    const unresolvedReasonCounts = emptyReasonCounts();
    for (const orphan of orphanNodes) {
      if (repairableOrphanNodeIds.has(orphan.id)) continue;
      const reasons = reasonsByOrphan.get(orphan.id)!;
      if ((incidentByOrphan.get(orphan.id) ?? 0) === 0) reasons.add("no_typed_relationship");
      const selected = ([
        "relationship_conflict_or_suppression",
        "invalid_typed_endpoints",
        "missing_hash_bound_source_custody",
        "counterpart_not_operator_reviewed",
        "no_typed_relationship",
      ] as const).find((reason) => reasons.has(reason)) ?? "no_typed_relationship";
      unresolvedReasonCounts[selected] += 1;
    }
    return {
      orphanNodeCount: orphanNodes.length,
      orphanNodeIds,
      orphanNodeTypeCounts: Object.freeze(Object.fromEntries(
        Object.entries(orphanNodeTypeCounts).sort(([left], [right]) => left.localeCompare(right)),
      )),
      repairableOrphanNodeIds,
      unresolvedReasonCounts: Object.freeze(unresolvedReasonCounts),
      relationships: Object.freeze(relationships),
    };
  }

  #replay(
    row: { readonly id: string; readonly details_json: string },
    expectedPreviewHash: string,
    expectedExecutionRequestHash: string,
  ): HistoricalReusableKnowledgeLinkRepairResult {
    const details = JSON.parse(row.details_json) as Record<string, unknown>;
    const integer = (key: string): number => {
      const value = details[key];
      if (!Number.isSafeInteger(value) || Number(value) < 0) throw new Error("Prior orphan-link repair audit is malformed");
      return Number(value);
    };
    if (details.previewHash !== expectedPreviewHash
        || details.executionRequestHash !== expectedExecutionRequestHash
        || typeof details.hasMore !== "boolean"
        || !(details.nextProposalKey === null || typeof details.nextProposalKey === "string")) {
      throw new Error("Prior orphan-link repair audit does not match this exact reviewed request");
    }
    return Object.freeze({
      status: "replayed" as const,
      previewHash: expectedPreviewHash,
      auditRecordId: row.id,
      relationshipsCreated: integer("relationshipsCreated"),
      bundleEdgeBindingsReconciled: integer("bundleEdgeBindingsReconciled"),
      orphanNodesConnected: integer("orphanNodesConnected"),
      hasMore: details.hasMore,
      nextProposalKey: details.nextProposalKey as string | null,
    });
  }
}

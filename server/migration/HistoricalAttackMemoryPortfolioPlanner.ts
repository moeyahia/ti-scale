import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import {
  attackKnowledgeOperationalLocatorCategories,
  findReusableMemorySecretCategories,
  isAttackCentricReusableNodeType,
  type MemoryNodeType,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";
import { HistoricalAttackKnowledgeConfirmationService } from
  "./HistoricalAttackKnowledgeConfirmationService";

const POLICY_VERSION = "historical-attack-memory-portfolio-planner-v1" as const;
const SCHEMA_VERSION = "ti_scale.historical_attack_memory_portfolio_plan/v1" as const;
const DEFAULT_MAX_BUNDLES = 100;
const MAX_BUNDLES = 1_000;
const SHA256 = /^[a-f0-9]{64}$/u;

type OutcomeTag = "success" | "failed";
type ReportedOutcomeTag = "reported_success" | "reported_failed";

interface MigrationRow {
  readonly id: string;
  readonly status: "completed" | "failed";
  readonly receipt_hash: string | null;
  readonly mission_id: string | null;
  readonly run_id: string | null;
}

interface BundleRow {
  readonly id: string;
  readonly semantic_fingerprint: string;
  readonly status: "staged" | "materialized";
  readonly sanitized_bundle_json: string;
}

interface CandidateRow {
  readonly bundle_id: string;
  readonly role: string;
  readonly content_fingerprint: string;
  readonly candidate_type: MemoryNodeType;
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly status: string;
  readonly proposed_scope: string;
  readonly proposed_engagement_id: string | null;
  readonly proposed_mission_id: string | null;
  readonly proposed_node_id: string | null;
  readonly node_scope: string | null;
  readonly node_engagement_id: string | null;
  readonly node_mission_id: string | null;
  readonly node_lifecycle_status: string | null;
  readonly node_confirmation_state: string | null;
  readonly reported_status: string | null;
}

interface EdgeRow {
  readonly bundle_id: string;
  readonly edge_type: string;
  readonly materialized_edge_id: string | null;
}

interface ProvenanceRow {
  readonly bundle_id: string;
  readonly completed_migration_count: number;
  readonly source_hash_count: number;
  readonly source_occurrence_count: number;
  readonly verified_reference_occurrence_count: number;
  readonly source_evidence_candidate_count: number;
  readonly promoted_source_evidence_count: number;
}

interface EvidenceRow {
  readonly bundle_id: string;
  readonly evidence_binding_count: number;
}

interface CanonicalOutcomeRow {
  readonly bundle_id: string;
  readonly outcome_tag: OutcomeTag;
}

export type HistoricalAttackMemoryPortfolioDisposition =
  | "privacy_or_scope_blocked"
  | "candidate_confirmation_required"
  | "unlinked_artifact_cleanup_review"
  | "canonical_evidence_promotion_review"
  | "confirmed_unverified"
  | "materialized_verified";

export type HistoricalAttackMemoryOutcomeState =
  | "canonically_verified_success"
  | "canonically_verified_failed"
  | "canonically_verified_mixed"
  | "reported_success_unverified"
  | "reported_failed_unverified"
  | "reported_mixed_unverified"
  | "unclassified";

export interface HistoricalAttackMemoryPortfolioBundlePlan {
  readonly bundleId: string;
  readonly semanticFingerprint: string;
  readonly bundleStatus: "staged" | "materialized";
  readonly knowledgeKind: "reusable_fact" | "reusable_bundle" | "operational_hazard" | "unknown";
  readonly disposition: HistoricalAttackMemoryPortfolioDisposition;
  readonly candidateCount: number;
  readonly candidateStateCounts: Readonly<Record<string, number>>;
  readonly nodeTypeCounts: Readonly<Record<string, number>>;
  readonly edgeTypeCounts: Readonly<Record<string, number>>;
  readonly linkCoverage: {
    readonly typedEdgeCount: number;
    readonly technology: boolean;
    readonly exactVersion: boolean;
    readonly attackVectorOrTechnique: boolean;
    readonly procedure: boolean;
    readonly script: boolean;
    readonly outcome: boolean;
    readonly failureOrRecovery: boolean;
  };
  readonly outcome: {
    readonly state: HistoricalAttackMemoryOutcomeState;
    /** Historical source claims are never returned as canonical outcome tags. */
    readonly reportedTags: readonly ReportedOutcomeTag[];
    readonly canonicalTags: readonly OutcomeTag[];
  };
  readonly evidence: {
    readonly sourceEvidenceCandidateCount: number;
    readonly promotedSourceEvidenceCount: number;
    readonly verifiedCanonicalBindingCount: number;
  };
  readonly provenance: {
    readonly completedMigrationCount: number;
    readonly sourceHashCount: number;
    readonly sourceOccurrenceCount: number;
    readonly verifiedReferenceOccurrenceCount: number;
  };
  readonly safety: {
    readonly reusableScopeSafe: boolean;
    readonly secretFree: boolean;
    readonly operationalLocatorFree: boolean;
    readonly crossEngagementSemanticLinkCount: 0;
    readonly unverifiedEvidenceRemainsUnverified: true;
    readonly lessonsRemainReviewGated: true;
  };
}

export interface HistoricalAttackMemoryPortfolioPlan {
  readonly schemaVersion: typeof SCHEMA_VERSION;
  readonly policyVersion: typeof POLICY_VERSION;
  readonly mode: "read_only_preview";
  readonly selection: {
    readonly afterSemanticFingerprint: string | null;
    readonly maxBundles: number;
  };
  readonly configuredCoverage: {
    readonly completedMigrationCount: number;
    readonly failedMigrationCount: number;
    readonly receiptBackedCompletedMigrationCount: number;
    readonly eligibleImportContextCount: number;
  };
  readonly reconciliation: {
    readonly eligibleBundleCount: number;
    readonly stagedBundleCount: number;
    readonly materializedBundleCount: number;
    readonly pendingEligibleCandidateCount: number;
    readonly incompatibleEligibleCandidateCount: number;
    readonly missingProvenanceBindingCount: number;
    readonly unlinkedConfirmedCandidateCount: number;
    readonly unlinkedConfirmedScriptArtifactCount: number;
    readonly reportedSuccessOutcomeCount: number;
    readonly reportedFailedOutcomeCount: number;
    readonly canonicalSuccessOutcomeLinkCount: number;
    readonly canonicalFailedOutcomeLinkCount: number;
    readonly verifiedCanonicalEvidenceBindingCount: number;
  };
  readonly bundles: readonly HistoricalAttackMemoryPortfolioBundlePlan[];
  readonly selectedDispositionCounts: Readonly<Record<HistoricalAttackMemoryPortfolioDisposition, number>>;
  readonly hasMore: boolean;
  readonly nextSelectionCursor: string | null;
  readonly previewHash: string;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function placeholders(count: number): string {
  return Array.from({ length: count }, () => "?").join(", ");
}

function normalizeInput(input: {
  readonly afterSemanticFingerprint?: string;
  readonly maxBundles?: number;
}): { readonly afterSemanticFingerprint: string; readonly maxBundles: number } {
  const afterSemanticFingerprint = input.afterSemanticFingerprint?.trim().toLowerCase() ?? "";
  if (afterSemanticFingerprint && !SHA256.test(afterSemanticFingerprint)) {
    throw new TypeError("Portfolio cursor must be a lowercase SHA-256 digest");
  }
  const maxBundles = input.maxBundles ?? DEFAULT_MAX_BUNDLES;
  if (!Number.isSafeInteger(maxBundles) || maxBundles < 1 || maxBundles > MAX_BUNDLES) {
    throw new TypeError(`maxBundles must be between 1 and ${MAX_BUNDLES}`);
  }
  return { afterSemanticFingerprint, maxBundles };
}

function increment(target: Record<string, number>, key: string): void {
  target[key] = (target[key] ?? 0) + 1;
}

function sortedRecord(input: Readonly<Record<string, number>>): Readonly<Record<string, number>> {
  return Object.freeze(Object.fromEntries(
    Object.entries(input).sort(([left], [right]) => left.localeCompare(right)),
  ));
}

function knowledgeKind(value: string): HistoricalAttackMemoryPortfolioBundlePlan["knowledgeKind"] {
  try {
    const parsed = JSON.parse(value) as { readonly knowledge?: { readonly kind?: unknown } };
    const kind = parsed.knowledge?.kind;
    return kind === "reusable_fact" || kind === "reusable_bundle" || kind === "operational_hazard"
      ? kind
      : "unknown";
  } catch {
    return "unknown";
  }
}

function outcomeState(
  canonicalTags: readonly OutcomeTag[],
  reportedTags: readonly ReportedOutcomeTag[],
): HistoricalAttackMemoryOutcomeState {
  if (canonicalTags.length === 2) return "canonically_verified_mixed";
  if (canonicalTags[0] === "success") return "canonically_verified_success";
  if (canonicalTags[0] === "failed") return "canonically_verified_failed";
  if (reportedTags.length === 2) return "reported_mixed_unverified";
  if (reportedTags[0] === "reported_success") return "reported_success_unverified";
  if (reportedTags[0] === "reported_failed") return "reported_failed_unverified";
  return "unclassified";
}

function rowMap<T extends { readonly bundle_id: string }>(rows: readonly T[]): ReadonlyMap<string, readonly T[]> {
  const result = new Map<string, T[]>();
  for (const row of rows) {
    const list = result.get(row.bundle_id) ?? [];
    list.push(row);
    result.set(row.bundle_id, list);
  }
  return result;
}

/**
 * A bounded, read-only portfolio planner for the attack-centric historical
 * memory pipeline. It never reads source bytes or Vault notes and never turns
 * a historical claim into verified evidence. The result answers which exact
 * bundle should be reviewed next and why, across every receipt-backed
 * completed configured import.
 */
export class HistoricalAttackMemoryPortfolioPlanner {
  constructor(private readonly database: SqliteDatabase) {}

  preview(input: {
    readonly afterSemanticFingerprint?: string;
    readonly maxBundles?: number;
  } = {}): HistoricalAttackMemoryPortfolioPlan {
    const normalized = normalizeInput(input);
    const migrations = this.database.prepare(`
      SELECT run.id, run.status, receipt.receipt_hash,
        context.mission_id, context.run_id
      FROM legacy_migration_runs run
      LEFT JOIN legacy_migration_inventory_receipts receipt
        ON receipt.migration_id = run.id
      LEFT JOIN historical_attack_knowledge_import_contexts context
        ON context.migration_id = run.id
      WHERE run.brain_projection_mode = 'attack-knowledge-only'
        AND run.source_retention = 'verified-reference'
        AND run.status IN ('completed', 'failed')
      ORDER BY run.id
    `).all() as MigrationRow[];
    const completed = migrations.filter(({ status }) => status === "completed");
    const eligibleMigrations = completed.filter((row) => (
      row.receipt_hash !== null && SHA256.test(row.receipt_hash)
      && row.mission_id !== null && row.run_id !== null
    ));

    const confirmation = new HistoricalAttackKnowledgeConfirmationService(this.database);
    const confirmationReconciliations = eligibleMigrations.map(({ id }) => confirmation.reconcile(id));
    const bundles = this.#bundlePage(
      normalized.afterSemanticFingerprint,
      normalized.maxBundles + 1,
    );
    const hasMore = bundles.length > normalized.maxBundles;
    const selected = bundles.slice(0, normalized.maxBundles);
    const selectedIds = selected.map(({ id }) => id);
    const candidates = selectedIds.length === 0 ? [] : this.#candidates(selectedIds);
    const edges = selectedIds.length === 0 ? [] : this.#edges(selectedIds);
    const provenance = selectedIds.length === 0 ? [] : this.#provenance(selectedIds);
    const evidence = selectedIds.length === 0 ? [] : this.#evidence(selectedIds);
    const canonicalOutcomes = selectedIds.length === 0 ? [] : this.#canonicalOutcomes(selectedIds);
    const candidatesByBundle = rowMap(candidates);
    const edgesByBundle = rowMap(edges);
    const provenanceByBundle = new Map(provenance.map((row) => [row.bundle_id, row]));
    const evidenceByBundle = new Map(evidence.map((row) => [row.bundle_id, row]));
    const canonicalOutcomesByBundle = rowMap(canonicalOutcomes);

    const plannedBundles = selected.map((bundle): HistoricalAttackMemoryPortfolioBundlePlan => {
      const bundleCandidates = candidatesByBundle.get(bundle.id) ?? [];
      const bundleEdges = edgesByBundle.get(bundle.id) ?? [];
      const candidateStateCounts: Record<string, number> = {};
      const nodeTypeCounts: Record<string, number> = {};
      let reusableScopeSafe = true;
      let secretFree = true;
      let operationalLocatorFree = true;
      const reported = new Set<ReportedOutcomeTag>();
      for (const candidate of bundleCandidates) {
        increment(candidateStateCounts, candidate.status);
        increment(nodeTypeCounts, candidate.candidate_type);
        reusableScopeSafe = reusableScopeSafe
          && isAttackCentricReusableNodeType(candidate.candidate_type)
          && candidate.proposed_scope === "global"
          && candidate.proposed_engagement_id === null
          && candidate.proposed_mission_id === null
          && (candidate.proposed_node_id === null || (
            candidate.node_scope === "global"
            && candidate.node_engagement_id === null
            && candidate.node_mission_id === null
          ));
        const reusableText = [candidate.title, candidate.summary, candidate.body];
        secretFree = secretFree && reusableText.every((value) => (
          findReusableMemorySecretCategories(value).length === 0
        ));
        operationalLocatorFree = operationalLocatorFree && reusableText.every((value) => (
          attackKnowledgeOperationalLocatorCategories(value).length === 0
        ));
        if (candidate.candidate_type === "outcome") {
          if (candidate.reported_status === "worked") reported.add("reported_success");
          if (candidate.reported_status === "failed") reported.add("reported_failed");
        }
      }
      const edgeTypeCounts: Record<string, number> = {};
      bundleEdges.forEach(({ edge_type }) => increment(edgeTypeCounts, edge_type));
      const canonicalTags = [...new Set(
        (canonicalOutcomesByBundle.get(bundle.id) ?? []).map(({ outcome_tag }) => outcome_tag),
      )].sort() as OutcomeTag[];
      const reportedTags = [...reported].sort() as ReportedOutcomeTag[];
      const source = provenanceByBundle.get(bundle.id);
      const proof = evidenceByBundle.get(bundle.id);
      const typeSet = new Set(bundleCandidates.map(({ candidate_type }) => candidate_type));
      const pending = bundleCandidates.some(({ status }) => status === "pending");
      const incompatible = bundleCandidates.some((candidate) => (
        ["confirmed", "edited_confirmed", "merged"].includes(candidate.status)
        && (!candidate.proposed_node_id
          || !["confirmed", "verified"].includes(candidate.node_lifecycle_status ?? "")
          || candidate.node_confirmation_state !== "confirmed")
      ));
      const privacyBlocked = !reusableScopeSafe || !secretFree || !operationalLocatorFree;
      const unlinkedArtifactOnly = typeSet.size === 1
        && typeSet.has("script_artifact") && bundleEdges.length === 0;
      let disposition: HistoricalAttackMemoryPortfolioDisposition;
      if (privacyBlocked || incompatible) disposition = "privacy_or_scope_blocked";
      else if (pending) disposition = "candidate_confirmation_required";
      else if (unlinkedArtifactOnly) disposition = "unlinked_artifact_cleanup_review";
      else if (bundle.status === "materialized") disposition = "materialized_verified";
      else if (Number(proof?.evidence_binding_count ?? 0) > 0) {
        disposition = "canonical_evidence_promotion_review";
      } else disposition = "confirmed_unverified";
      return Object.freeze({
        bundleId: bundle.id,
        semanticFingerprint: bundle.semantic_fingerprint,
        bundleStatus: bundle.status,
        knowledgeKind: knowledgeKind(bundle.sanitized_bundle_json),
        disposition,
        candidateCount: bundleCandidates.length,
        candidateStateCounts: sortedRecord(candidateStateCounts),
        nodeTypeCounts: sortedRecord(nodeTypeCounts),
        edgeTypeCounts: sortedRecord(edgeTypeCounts),
        linkCoverage: Object.freeze({
          typedEdgeCount: bundleEdges.length,
          technology: [...typeSet].some((type) => [
            "technology_product", "operating_system", "kernel", "framework", "runtime",
            "database", "firewall", "waf", "proxy", "security_control",
          ].includes(type)),
          exactVersion: typeSet.has("exact_version_fingerprint"),
          attackVectorOrTechnique: typeSet.has("attack_vector") || typeSet.has("attack_technique"),
          procedure: typeSet.has("attack_procedure") || typeSet.has("procedure_version"),
          script: typeSet.has("script_artifact"),
          outcome: typeSet.has("outcome"),
          failureOrRecovery: typeSet.has("failure_mode") || typeSet.has("recovery_pattern")
            || typeSet.has("operational_hazard") || typeSet.has("health_check"),
        }),
        outcome: Object.freeze({
          state: outcomeState(canonicalTags, reportedTags),
          reportedTags: Object.freeze(reportedTags),
          canonicalTags: Object.freeze(canonicalTags),
        }),
        evidence: Object.freeze({
          sourceEvidenceCandidateCount: Number(source?.source_evidence_candidate_count ?? 0),
          promotedSourceEvidenceCount: Number(source?.promoted_source_evidence_count ?? 0),
          verifiedCanonicalBindingCount: Number(proof?.evidence_binding_count ?? 0),
        }),
        provenance: Object.freeze({
          completedMigrationCount: Number(source?.completed_migration_count ?? 0),
          sourceHashCount: Number(source?.source_hash_count ?? 0),
          sourceOccurrenceCount: Number(source?.source_occurrence_count ?? 0),
          verifiedReferenceOccurrenceCount: Number(source?.verified_reference_occurrence_count ?? 0),
        }),
        safety: Object.freeze({
          reusableScopeSafe,
          secretFree,
          operationalLocatorFree,
          crossEngagementSemanticLinkCount: 0 as const,
          unverifiedEvidenceRemainsUnverified: true as const,
          lessonsRemainReviewGated: true as const,
        }),
      });
    });
    const selectedDispositionCounts = Object.fromEntries(([
      "privacy_or_scope_blocked",
      "candidate_confirmation_required",
      "unlinked_artifact_cleanup_review",
      "canonical_evidence_promotion_review",
      "confirmed_unverified",
      "materialized_verified",
    ] as const).map((disposition) => [
      disposition,
      plannedBundles.filter((bundle) => bundle.disposition === disposition).length,
    ])) as Record<HistoricalAttackMemoryPortfolioDisposition, number>;
    const totals = this.#globalTotals();
    const reconciliation = Object.freeze({
      ...totals,
      pendingEligibleCandidateCount: confirmationReconciliations.reduce(
        (sum, item) => sum + item.pendingEligibleCount,
        0,
      ),
      incompatibleEligibleCandidateCount: confirmationReconciliations.reduce(
        (sum, item) => sum + item.incompatibleEligibleCount,
        0,
      ),
      missingProvenanceBindingCount: confirmationReconciliations.reduce(
        (sum, item) => sum + item.provenanceBindingMissingCount,
        0,
      ),
      unlinkedConfirmedCandidateCount: this.#unlinkedConfirmedCandidateCount(),
    });
    const body = {
      schemaVersion: SCHEMA_VERSION,
      policyVersion: POLICY_VERSION,
      mode: "read_only_preview" as const,
      selection: {
        afterSemanticFingerprint: normalized.afterSemanticFingerprint || null,
        maxBundles: normalized.maxBundles,
      },
      configuredCoverage: {
        completedMigrationCount: completed.length,
        failedMigrationCount: migrations.length - completed.length,
        receiptBackedCompletedMigrationCount: completed.filter(({ receipt_hash }) => (
          receipt_hash !== null && SHA256.test(receipt_hash)
        )).length,
        eligibleImportContextCount: eligibleMigrations.length,
      },
      reconciliation,
      bundles: Object.freeze(plannedBundles),
      selectedDispositionCounts: Object.freeze(selectedDispositionCounts),
      hasMore,
      nextSelectionCursor: plannedBundles.at(-1)?.semanticFingerprint ?? null,
    };
    return Object.freeze({ ...body, previewHash: sha256(canonicalJson(body)) });
  }

  #bundlePage(after: string, limit: number): BundleRow[] {
    return this.database.prepare(`
      SELECT bundle.id, bundle.semantic_fingerprint, bundle.status,
        bundle.sanitized_bundle_json
      FROM attack_knowledge_bundles bundle
      WHERE bundle.semantic_fingerprint > ?
        AND EXISTS (
          SELECT 1
          FROM historical_attack_knowledge_bundle_sources source
          JOIN historical_attack_knowledge_source_occurrences occurrence
            ON occurrence.candidate_id = source.candidate_id
           AND occurrence.source_hash = source.source_hash
          JOIN legacy_migration_runs migration
            ON migration.id = occurrence.migration_id
           AND migration.status = 'completed'
           AND migration.source_retention = 'verified-reference'
           AND migration.brain_projection_mode = 'attack-knowledge-only'
          JOIN legacy_migration_inventory_receipts inventory
            ON inventory.migration_id = migration.id
          WHERE source.bundle_id = bundle.id
            AND EXISTS (
              SELECT 1 FROM legacy_migration_source_objects object
              WHERE object.migration_id = occurrence.migration_id
                AND object.source_reference = occurrence.source_reference
                AND object.source_sha256 = occurrence.source_hash
                AND object.verification_status = 'verified_reference'
                AND object.object_kind IN ('accepted', 'source')
            )
        )
      ORDER BY bundle.semantic_fingerprint
      LIMIT ?
    `).all(after, limit) as BundleRow[];
  }

  #candidates(bundleIds: readonly string[]): CandidateRow[] {
    return this.database.prepare(`
      SELECT linked.bundle_id, linked.role, linked.content_fingerprint,
        candidate.candidate_type, candidate.title, candidate.summary,
        candidate.body, candidate.status, candidate.proposed_scope,
        candidate.proposed_engagement_id, candidate.proposed_mission_id,
        candidate.proposed_node_id, node.scope AS node_scope,
        node.engagement_id AS node_engagement_id,
        node.mission_id AS node_mission_id,
        node.lifecycle_status AS node_lifecycle_status,
        node.confirmation_state AS node_confirmation_state,
        CASE WHEN candidate.candidate_type = 'outcome' AND json_valid(candidate.body)
          THEN COALESCE(
            json_extract(candidate.body, '$.reportedStatus'),
            CASE WHEN json_extract(candidate.body, '$.verification') = 'candidate'
              THEN json_extract(candidate.body, '$.status') ELSE NULL END
          ) ELSE NULL END AS reported_status
      FROM attack_knowledge_bundle_candidates linked
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = linked.content_fingerprint
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      LEFT JOIN memory_nodes node ON node.id = candidate.proposed_node_id
      WHERE linked.bundle_id IN (${placeholders(bundleIds.length)})
      ORDER BY linked.bundle_id, linked.ordinal
    `).all(...bundleIds) as CandidateRow[];
  }

  #edges(bundleIds: readonly string[]): EdgeRow[] {
    return this.database.prepare(`
      SELECT bundle_id, edge_type, materialized_edge_id
      FROM attack_knowledge_bundle_edges
      WHERE bundle_id IN (${placeholders(bundleIds.length)})
      ORDER BY bundle_id, edge_key
    `).all(...bundleIds) as EdgeRow[];
  }

  #provenance(bundleIds: readonly string[]): ProvenanceRow[] {
    return this.database.prepare(`
      SELECT source.bundle_id,
        COUNT(DISTINCT CASE WHEN migration.status = 'completed'
          THEN occurrence.migration_id END) AS completed_migration_count,
        COUNT(DISTINCT source.source_hash) AS source_hash_count,
        COUNT(DISTINCT occurrence.migration_id || char(0) || occurrence.source_reference)
          AS source_occurrence_count,
        COUNT(DISTINCT CASE WHEN migration.status = 'completed'
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
          ) THEN occurrence.migration_id || char(0) || occurrence.source_reference END)
          AS verified_reference_occurrence_count,
        COUNT(DISTINCT source.candidate_id) AS source_evidence_candidate_count,
        COUNT(DISTINCT CASE WHEN evidence_candidate.state = 'promoted'
          THEN source.candidate_id END) AS promoted_source_evidence_count
      FROM historical_attack_knowledge_bundle_sources source
      JOIN historical_attack_knowledge_source_occurrences occurrence
        ON occurrence.candidate_id = source.candidate_id
       AND occurrence.source_hash = source.source_hash
      JOIN legacy_migration_runs migration ON migration.id = occurrence.migration_id
      LEFT JOIN legacy_migration_inventory_receipts inventory
        ON inventory.migration_id = migration.id
      JOIN evidence_candidates evidence_candidate
        ON evidence_candidate.id = source.candidate_id
      WHERE source.bundle_id IN (${placeholders(bundleIds.length)})
      GROUP BY source.bundle_id
      ORDER BY source.bundle_id
    `).all(...bundleIds) as ProvenanceRow[];
  }

  #evidence(bundleIds: readonly string[]): EvidenceRow[] {
    return this.database.prepare(`
      SELECT binding.bundle_id, COUNT(DISTINCT binding.evidence_id) AS evidence_binding_count
      FROM attack_knowledge_bundle_evidence_bindings binding
      JOIN evidence canonical ON canonical.id = binding.evidence_id
      WHERE binding.bundle_id IN (${placeholders(bundleIds.length)})
        AND canonical.verification_state = 'verified'
        AND lower(trim(canonical.evidence_type)) <> 'command_output'
        AND EXISTS (
          SELECT 1 FROM evidence_chain_events custody
          WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified'
        )
      GROUP BY binding.bundle_id
      ORDER BY binding.bundle_id
    `).all(...bundleIds) as EvidenceRow[];
  }

  #canonicalOutcomes(bundleIds: readonly string[]): CanonicalOutcomeRow[] {
    return this.database.prepare(`
      SELECT DISTINCT linked.bundle_id, outcome.outcome_tag
      FROM attack_knowledge_bundle_candidates linked
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = linked.content_fingerprint
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      JOIN reusable_knowledge_outcome_links outcome
        ON outcome.memory_node_id = candidate.proposed_node_id
      WHERE linked.bundle_id IN (${placeholders(bundleIds.length)})
      ORDER BY linked.bundle_id, outcome.outcome_tag
    `).all(...bundleIds) as CanonicalOutcomeRow[];
  }

  #globalTotals(): Omit<HistoricalAttackMemoryPortfolioPlan["reconciliation"],
    "pendingEligibleCandidateCount" | "incompatibleEligibleCandidateCount" |
    "missingProvenanceBindingCount" | "unlinkedConfirmedCandidateCount"> {
    const row = this.database.prepare(`
      WITH eligible_bundles AS (
        SELECT DISTINCT source.bundle_id
        FROM historical_attack_knowledge_bundle_sources source
        JOIN historical_attack_knowledge_source_occurrences occurrence
          ON occurrence.candidate_id = source.candidate_id
         AND occurrence.source_hash = source.source_hash
        JOIN legacy_migration_runs migration
          ON migration.id = occurrence.migration_id
         AND migration.status = 'completed'
         AND migration.source_retention = 'verified-reference'
         AND migration.brain_projection_mode = 'attack-knowledge-only'
        JOIN legacy_migration_inventory_receipts inventory
          ON inventory.migration_id = migration.id
        WHERE EXISTS (
          SELECT 1 FROM legacy_migration_source_objects object
          WHERE object.migration_id = occurrence.migration_id
            AND object.source_reference = occurrence.source_reference
            AND object.source_sha256 = occurrence.source_hash
            AND object.verification_status = 'verified_reference'
            AND object.object_kind IN ('accepted', 'source')
        )
      )
      SELECT COUNT(*) AS eligible_bundle_count,
        SUM(bundle.status = 'staged') AS staged_bundle_count,
        SUM(bundle.status = 'materialized') AS materialized_bundle_count
      FROM eligible_bundles eligible
      JOIN attack_knowledge_bundles bundle ON bundle.id = eligible.bundle_id
    `).get() as {
      readonly eligible_bundle_count: number;
      readonly staged_bundle_count: number;
      readonly materialized_bundle_count: number;
    };
    const unlinkedScripts = Number((this.database.prepare(`
      SELECT COUNT(*) AS count
      FROM memory_nodes node
      JOIN memory_candidates candidate ON candidate.proposed_node_id = node.id
      WHERE node.node_type = 'script_artifact'
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.lifecycle_status = 'confirmed' AND node.confirmation_state = 'confirmed'
        AND candidate.proposed_by = 'attack-knowledge-compiler'
        AND candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND NOT EXISTS (
          SELECT 1 FROM memory_edges_safe edge
          WHERE edge.source_node_id = node.id OR edge.target_node_id = node.id
        )
    `).get() as { readonly count: number }).count);
    const reported = this.database.prepare(`
      SELECT
        COUNT(DISTINCT CASE WHEN status = 'worked' THEN node_id END) AS success_count,
        COUNT(DISTINCT CASE WHEN status = 'failed' THEN node_id END) AS failed_count
      FROM (
        SELECT node.id AS node_id,
          CASE WHEN json_valid(node.body) THEN COALESCE(
            json_extract(node.body, '$.reportedStatus'),
            CASE WHEN json_extract(node.body, '$.verification') = 'candidate'
              THEN json_extract(node.body, '$.status') ELSE NULL END
          ) ELSE NULL END AS status
        FROM memory_nodes node
        WHERE node.node_type = 'outcome'
          AND node.lifecycle_status IN ('confirmed', 'verified')
          AND node.confirmation_state = 'confirmed'
      )
    `).get() as { readonly success_count: number; readonly failed_count: number };
    const canonical = this.database.prepare(`
      SELECT
        COUNT(DISTINCT CASE WHEN outcome_tag = 'success' THEN id END) AS success_count,
        COUNT(DISTINCT CASE WHEN outcome_tag = 'failed' THEN id END) AS failed_count
      FROM reusable_knowledge_outcome_links
    `).get() as { readonly success_count: number; readonly failed_count: number };
    const evidence = Number((this.database.prepare(`
      SELECT COUNT(DISTINCT binding.bundle_id || char(0) || binding.evidence_id) AS count
      FROM attack_knowledge_bundle_evidence_bindings binding
      JOIN evidence canonical ON canonical.id = binding.evidence_id
      WHERE canonical.verification_state = 'verified'
        AND lower(trim(canonical.evidence_type)) <> 'command_output'
        AND EXISTS (
          SELECT 1 FROM evidence_chain_events custody
          WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified'
        )
    `).get() as { readonly count: number }).count);
    return {
      eligibleBundleCount: Number(row.eligible_bundle_count ?? 0),
      stagedBundleCount: Number(row.staged_bundle_count ?? 0),
      materializedBundleCount: Number(row.materialized_bundle_count ?? 0),
      unlinkedConfirmedScriptArtifactCount: unlinkedScripts,
      reportedSuccessOutcomeCount: Number(reported.success_count ?? 0),
      reportedFailedOutcomeCount: Number(reported.failed_count ?? 0),
      canonicalSuccessOutcomeLinkCount: Number(canonical.success_count ?? 0),
      canonicalFailedOutcomeLinkCount: Number(canonical.failed_count ?? 0),
      verifiedCanonicalEvidenceBindingCount: evidence,
    };
  }

  #unlinkedConfirmedCandidateCount(): number {
    return Number((this.database.prepare(`
      SELECT COUNT(DISTINCT node.id) AS count
      FROM attack_knowledge_candidate_registry registry
      JOIN memory_candidates candidate ON candidate.id = registry.candidate_id
      JOIN memory_nodes node ON node.id = candidate.proposed_node_id
      WHERE candidate.status IN ('confirmed', 'edited_confirmed', 'merged')
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.lifecycle_status IN ('confirmed', 'verified')
        AND node.confirmation_state = 'confirmed'
        AND NOT EXISTS (
          SELECT 1 FROM memory_edges_safe edge
          WHERE edge.source_node_id = node.id OR edge.target_node_id = node.id
        )
    `).get() as { readonly count: number }).count);
  }
}

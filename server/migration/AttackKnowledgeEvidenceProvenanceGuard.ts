import type { SqliteDatabase } from "../db";

type SourceClass = "current" | "historical";

interface ReceiptRow {
  readonly receipt_id: string;
  readonly source_class: SourceClass;
  readonly source_hash: string;
  readonly exact_procedure_attempt_count: number;
  readonly exact_procedure_reproducibility_count: number;
  readonly exact_procedure_evidence_count: number;
  readonly exact_procedure_reset_count: number;
  readonly operator_reported_reset_count_minimum: number | null;
}

interface BindingRow {
  readonly receipt_id: string;
  readonly evidence_id: string;
}

export interface AttackKnowledgeEvidenceProvenanceAssessment {
  readonly valid: boolean;
  readonly reasonCategories: readonly (
    | "evidence_selection_mismatch"
    | "receipt_has_no_evidence"
    | "current_occurrence_missing"
    | "current_occurrence_count_mismatch"
    | "historical_import_link_missing"
    | "unsupported_source_class"
  )[];
}

function sortedUnique(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort();
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  const a = sortedUnique(left);
  const b = sortedUnique(right);
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

/**
 * Promotion-time trust boundary for canonical attack-knowledge evidence.
 *
 * A verified evidence row is necessary but not sufficient. Every immutable
 * compiler receipt and every evidence binding must also have one exact local
 * origin path:
 *
 * - current observations: a typed operational-hazard occurrence carrying the
 *   same bundle, provenance receipt, evidence IDs, and exact counters; or
 * - historical observations: an immutable, operator-approved importer bundle
 *   link whose database trigger proves the selected IDs came from promoted
 *   import candidates.
 *
 * This prevents a generic compiler caller from attaching unrelated verified
 * evidence to an asserted hazard and turning it into a reusable runtime gate.
 */
export class AttackKnowledgeEvidenceProvenanceGuard {
  constructor(private readonly database: SqliteDatabase) {}

  assess(
    bundleId: string,
    selectedEvidenceIds: readonly string[],
  ): AttackKnowledgeEvidenceProvenanceAssessment {
    const reasons = new Set<AttackKnowledgeEvidenceProvenanceAssessment["reasonCategories"][number]>();
    const receipts = this.database.prepare(`
      SELECT linked.receipt_id, receipt.source_class, receipt.source_hash,
        linked.exact_procedure_attempt_count,
        linked.exact_procedure_reproducibility_count,
        linked.exact_procedure_evidence_count,
        linked.exact_procedure_reset_count,
        linked.operator_reported_reset_count_minimum
      FROM attack_knowledge_bundle_receipts linked
      JOIN attack_knowledge_provenance_receipts receipt ON receipt.id = linked.receipt_id
      WHERE linked.bundle_id = ?
      ORDER BY linked.receipt_id
    `).all(bundleId) as ReceiptRow[];
    const bindings = this.database.prepare(`
      SELECT receipt_id, evidence_id
      FROM attack_knowledge_bundle_evidence_bindings
      WHERE bundle_id = ?
      ORDER BY receipt_id, evidence_id
    `).all(bundleId) as BindingRow[];

    if (!sameSet(selectedEvidenceIds, bindings.map(({ evidence_id }) => evidence_id))) {
      reasons.add("evidence_selection_mismatch");
    }

    for (const receipt of receipts) {
      const receiptEvidence = bindings
        .filter(({ receipt_id }) => receipt_id === receipt.receipt_id)
        .map(({ evidence_id }) => evidence_id);
      if (receiptEvidence.length === 0) {
        reasons.add("receipt_has_no_evidence");
        continue;
      }
      if (receipt.source_class === "current") {
        this.#assessCurrent(bundleId, receipt, receiptEvidence, reasons);
      } else if (receipt.source_class === "historical") {
        this.#assessHistorical(bundleId, receipt, receiptEvidence, reasons);
      } else {
        reasons.add("unsupported_source_class");
      }
    }

    if (receipts.length === 0) reasons.add("receipt_has_no_evidence");
    return Object.freeze({
      valid: reasons.size === 0,
      reasonCategories: Object.freeze([...reasons].sort()),
    });
  }

  #assessCurrent(
    bundleId: string,
    receipt: ReceiptRow,
    receiptEvidence: readonly string[],
    reasons: Set<AttackKnowledgeEvidenceProvenanceAssessment["reasonCategories"][number]>,
  ): void {
    const occurrences = this.database.prepare(`
      SELECT exact_attempt_count, exact_reproducibility_count, exact_reset_count,
        evidence_ids_json
      FROM operational_hazard_occurrences
      WHERE bundle_id = ? AND provenance_receipt_id = ?
      ORDER BY id
    `).all(bundleId, receipt.receipt_id) as Array<{
      readonly exact_attempt_count: number;
      readonly exact_reproducibility_count: number;
      readonly exact_reset_count: number;
      readonly evidence_ids_json: string;
    }>;
    if (occurrences.length === 0) {
      reasons.add("current_occurrence_missing");
      return;
    }
    let occurrenceEvidence: string[] = [];
    let attempts = 0;
    let reproducible = 0;
    let resets = 0;
    try {
      for (const occurrence of occurrences) {
        const ids = JSON.parse(occurrence.evidence_ids_json) as unknown;
        if (!Array.isArray(ids) || ids.some((value) => typeof value !== "string")) {
          reasons.add("current_occurrence_count_mismatch");
          return;
        }
        occurrenceEvidence = occurrenceEvidence.concat(ids);
        attempts += Number(occurrence.exact_attempt_count);
        reproducible += Number(occurrence.exact_reproducibility_count);
        resets += Number(occurrence.exact_reset_count);
      }
    } catch {
      reasons.add("current_occurrence_count_mismatch");
      return;
    }
    if (
      !sameSet(receiptEvidence, occurrenceEvidence)
      || Number(receipt.exact_procedure_attempt_count) !== attempts
      || Number(receipt.exact_procedure_reproducibility_count) !== reproducible
      || Number(receipt.exact_procedure_evidence_count) !== sortedUnique(occurrenceEvidence).length
      || Number(receipt.exact_procedure_reset_count) !== resets
      || receipt.operator_reported_reset_count_minimum !== null
    ) {
      reasons.add("current_occurrence_count_mismatch");
    }
  }

  #assessHistorical(
    bundleId: string,
    receipt: ReceiptRow,
    receiptEvidence: readonly string[],
    reasons: Set<AttackKnowledgeEvidenceProvenanceAssessment["reasonCategories"][number]>,
  ): void {
    const rows = this.database.prepare(`
      SELECT DISTINCT selected.value AS evidence_id
      FROM historical_hazard_import_bundle_links link
      JOIN historical_hazard_import_jobs job ON job.id = link.job_id
      JOIN json_each(link.evidence_ids_json) selected
      WHERE link.bundle_id = ?
        AND link.provenance_receipt_id = ?
        AND link.source_hash = ?
        AND job.status IN ('candidates_staged', 'bundle_staged')
      UNION
      SELECT DISTINCT local_link.evidence_id
      FROM historical_attack_knowledge_verified_bundle_links local_link
      JOIN evidence_candidates candidate ON candidate.id = local_link.candidate_id
      JOIN evidence canonical ON canonical.id = local_link.evidence_id
      JOIN audit_records verification_audit
        ON verification_audit.id = local_link.verification_audit_id
      WHERE local_link.bundle_id = ?
        AND local_link.receipt_id = ?
        AND candidate.state = 'promoted'
        AND candidate.promoted_evidence_id = local_link.evidence_id
        AND canonical.content_hash = local_link.source_hash
        AND canonical.verification_state = 'verified'
        AND verification_audit.action = 'historical_attack_source.verified'
        AND verification_audit.actor_type = 'operator'
      ORDER BY evidence_id
    `).all(
      bundleId,
      receipt.receipt_id,
      receipt.source_hash,
      bundleId,
      receipt.receipt_id,
    ) as Array<{ readonly evidence_id: string }>;
    const imported = new Set(rows.map(({ evidence_id }) => evidence_id));
    if (receiptEvidence.some((evidenceId) => !imported.has(evidenceId))) {
      reasons.add("historical_import_link_missing");
    }
  }
}

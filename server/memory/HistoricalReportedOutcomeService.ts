import type { SqliteDatabase } from "../db";
import {
  HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS,
  HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION,
  type HistoricalReportedOutcomeClassification,
  type HistoricalReportedOutcomeSummary,
} from "../domain";

interface SummaryRow {
  readonly memory_node_id: string;
  readonly classification: HistoricalReportedOutcomeClassification;
  readonly claim_count: number;
  readonly source_count: number;
  readonly maximum_confidence: number;
}

function aggregateClassification(rows: readonly SummaryRow[]): HistoricalReportedOutcomeClassification {
  const represented = new Set(rows.filter(({ claim_count }) => Number(claim_count) > 0)
    .map(({ classification }) => classification));
  if (
    represented.has("mixed")
    || (represented.has("reported_success") && represented.has("reported_failure"))
  ) return "mixed";
  if (represented.has("reported_success")) return "reported_success";
  if (represented.has("reported_failure")) return "reported_failure";
  return "unknown";
}

/** Read-only aggregate for Vault/API projection; it cannot create a claim. */
export class HistoricalReportedOutcomeService {
  constructor(private readonly database: SqliteDatabase) {}

  summary(memoryNodeId: string): HistoricalReportedOutcomeSummary | undefined {
    return this.summaries([memoryNodeId]).get(memoryNodeId);
  }

  /**
   * Bounded node-first projection used by graph and list responses. Keeping
   * this batched avoids one or two aggregate queries per rendered node while
   * preserving the same reported-only semantics as `summary`.
   */
  summaries(memoryNodeIds: readonly string[]): ReadonlyMap<string, HistoricalReportedOutcomeSummary> {
    const selected = [...new Set(memoryNodeIds)];
    if (selected.length === 0) return new Map();
    const grouped = new Map<string, SummaryRow[]>();
    const sourceCounts = new Map<string, number>();
    for (let offset = 0; offset < selected.length; offset += 400) {
      const batch = selected.slice(offset, offset + 400);
      const placeholders = batch.map(() => "?").join(",");
      const rows = this.database.prepare(`
        SELECT memory_node_id, classification,
          COUNT(DISTINCT claim_id) AS claim_count,
          COUNT(DISTINCT source_hash) AS source_count,
          MAX(classification_confidence) AS maximum_confidence
        FROM historical_reported_outcome_node_claims
        WHERE policy_version = ? AND memory_node_id IN (${placeholders})
        GROUP BY memory_node_id, classification
        ORDER BY memory_node_id, classification
      `).all(HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION, ...batch) as SummaryRow[];
      rows.forEach((row) => {
        const values = grouped.get(row.memory_node_id) ?? [];
        values.push(row);
        grouped.set(row.memory_node_id, values);
      });
      const sources = this.database.prepare(`
        SELECT memory_node_id, COUNT(DISTINCT source_hash) AS source_count
        FROM historical_reported_outcome_node_claims
        WHERE policy_version = ? AND memory_node_id IN (${placeholders})
        GROUP BY memory_node_id
      `).all(HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION, ...batch) as Array<{
        readonly memory_node_id: string;
        readonly source_count: number;
      }>;
      sources.forEach((row) => sourceCounts.set(row.memory_node_id, Number(row.source_count)));
    }
    return new Map([...grouped].map(([memoryNodeId, rows]) => [memoryNodeId, {
      classification: aggregateClassification(rows),
      classificationConfidence: rows.reduce(
        (maximum, row) => Math.max(maximum, Number(row.maximum_confidence)),
        0,
      ),
      claimCount: rows.reduce((sum, row) => sum + Number(row.claim_count), 0),
      sourceCount: sourceCounts.get(memoryNodeId) ?? 0,
      policyVersion: HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION,
    }]));
  }

  countByClassification(): Readonly<Record<HistoricalReportedOutcomeClassification, number>> {
    const result = Object.fromEntries(
      HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS.map((classification) => [classification, 0]),
    ) as Record<HistoricalReportedOutcomeClassification, number>;
    const rows = this.database.prepare(`
      SELECT classification, COUNT(*) AS count
      FROM historical_reported_outcome_claims
      WHERE policy_version = ? GROUP BY classification ORDER BY classification
    `).all(HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION) as Array<{
      classification: HistoricalReportedOutcomeClassification;
      count: number;
    }>;
    rows.forEach(({ classification, count }) => { result[classification] = Number(count); });
    return Object.freeze(result);
  }
}

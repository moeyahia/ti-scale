import type { SqliteDatabase } from "../db";
import type { AttackKnowledgeExtractionReconciliation } from "./types";

interface AggregateRow {
  readonly scopes: number;
  readonly batches: number;
  readonly files_discovered: number | null;
  readonly files_parsed: number | null;
  readonly files_skipped: number | null;
  readonly files_quarantined: number | null;
  readonly bytes_parsed: number | null;
  readonly semantic_facts_parsed: number | null;
  readonly ambiguous_fragments: number | null;
  readonly compiler_bundles_staged: number | null;
  readonly candidates_created: number | null;
  readonly candidates_reused: number | null;
  readonly source_candidates_created: number | null;
  readonly source_candidates_reused: number | null;
  readonly source_bundle_links: number | null;
  readonly generic_scopes: number;
  readonly generic_sources_discovered: number | null;
  readonly generic_sources_processed: number | null;
  readonly generic_sources_completed: number | null;
  readonly generic_records_processed: number | null;
  readonly generic_records_quarantined: number | null;
}

interface CountRow {
  readonly key: string;
  readonly count: number;
}

interface LatestScopeRow {
  readonly manifest_fingerprint: string;
  readonly status: "completed" | "partial";
  readonly source_cursor: string | null;
  readonly record_cursor: string | null;
}

function number(value: number | null | undefined): number {
  return Number(value ?? 0);
}

function countRecord(rows: readonly CountRow[]): Readonly<Record<string, number>> {
  return Object.fromEntries(rows.map((row) => [row.key, Number(row.count)]));
}

/**
 * Recompute the durable extraction result without materializing report_json.
 *
 * Historical imports can produce hundreds of megabytes of immutable page
 * receipts. SQLite's JSON1 virtual tables project only the scalar counters and
 * the small, explicitly required unique-ID set, keeping JS heap use bounded by
 * the final reconciliation rather than by every compiler run and candidate ID
 * carried in every page.
 */
export class HistoricalAttackKnowledgeExtractionReconciliationService {
  constructor(private readonly database: SqliteDatabase) {}

  reconcile(
    migrationId: string,
    semanticPreview: boolean,
  ): AttackKnowledgeExtractionReconciliation {
    const aggregate = this.database.prepare(`
      WITH batches AS (
        SELECT extractor_kind, scope_key, sequence, report_json,
          ROW_NUMBER() OVER (
            PARTITION BY extractor_kind, scope_key ORDER BY sequence
          ) AS first_ordinal
        FROM legacy_migration_extraction_batches
        WHERE migration_id = ?
      )
      SELECT
        COUNT(DISTINCT extractor_kind || char(0) || scope_key) AS scopes,
        COUNT(*) AS batches,
        SUM(CASE WHEN first_ordinal = 1
          THEN COALESCE(json_extract(report_json, '$.filesDiscovered'), 0)
          ELSE 0 END) AS files_discovered,
        SUM(COALESCE(json_extract(report_json, '$.filesParsed'), 0)) AS files_parsed,
        SUM(COALESCE(json_extract(report_json, '$.filesSkipped'), 0)) AS files_skipped,
        SUM(COALESCE(json_extract(report_json, '$.filesQuarantined'), 0)) AS files_quarantined,
        SUM(COALESCE(json_extract(report_json, '$.bytesParsed'), 0)) AS bytes_parsed,
        SUM(COALESCE(json_extract(report_json, '$.semanticFactsParsed'), 0)) AS semantic_facts_parsed,
        SUM(COALESCE(json_extract(report_json, '$.ambiguousFragments'), 0)) AS ambiguous_fragments,
        SUM(COALESCE(json_extract(report_json, '$.compilerBundlesStaged'), 0)) AS compiler_bundles_staged,
        SUM(COALESCE(json_extract(report_json, '$.candidatesCreated'), 0)) AS candidates_created,
        SUM(COALESCE(json_extract(report_json, '$.candidatesReused'), 0)) AS candidates_reused,
        SUM(COALESCE(json_extract(report_json, '$.sourceEvidenceCandidatesCreated'), 0)) AS source_candidates_created,
        SUM(COALESCE(json_extract(report_json, '$.sourceEvidenceCandidatesReused'), 0)) AS source_candidates_reused,
        SUM(COALESCE(json_extract(report_json, '$.sourceBundleLinks'), 0)) AS source_bundle_links,
        COUNT(DISTINCT CASE
          WHEN json_type(report_json, '$.sourcesProcessed') IS NOT NULL
          THEN extractor_kind || char(0) || scope_key END) AS generic_scopes,
        SUM(CASE
          WHEN first_ordinal = 1 AND json_type(report_json, '$.sourcesProcessed') IS NOT NULL
          THEN COALESCE(json_extract(report_json, '$.filesDiscovered'), 0)
          ELSE 0 END) AS generic_sources_discovered,
        SUM(COALESCE(json_extract(report_json, '$.sourcesProcessed'), 0)) AS generic_sources_processed,
        SUM(COALESCE(json_extract(report_json, '$.sourcesCompleted'), 0)) AS generic_sources_completed,
        SUM(COALESCE(json_extract(report_json, '$.recordsProcessed'), 0)) AS generic_records_processed,
        SUM(COALESCE(json_extract(report_json, '$.recordsQuarantined'), 0)) AS generic_records_quarantined
      FROM batches
    `).get(migrationId) as AggregateRow;

    const latest = this.database.prepare(`
      WITH latest AS (
        SELECT extractor_kind, scope_key, MAX(sequence) AS sequence
        FROM legacy_migration_extraction_batches
        WHERE migration_id = ?
        GROUP BY extractor_kind, scope_key
      )
      SELECT
        COALESCE(json_extract(batch.report_json, '$.manifestFingerprint'), batch.scope_key)
          AS manifest_fingerprint,
        json_extract(batch.report_json, '$.status') AS status,
        json_extract(batch.report_json, '$.nextResumeAfterSourceKey') AS source_cursor,
        json_extract(batch.report_json, '$.nextResumeAfterRecordKey') AS record_cursor
      FROM latest
      JOIN legacy_migration_extraction_batches batch
        ON batch.migration_id = ?
        AND batch.extractor_kind = latest.extractor_kind
        AND batch.scope_key = latest.scope_key
        AND batch.sequence = latest.sequence
      ORDER BY batch.extractor_kind, batch.scope_key
    `).all(migrationId, migrationId) as LatestScopeRow[];
    const incomplete = latest.filter((row) => row.status === "partial");

    const distribution = (path: "nodeTypeCounts" | "edgeTypeCounts"): Readonly<Record<string, number>> =>
      countRecord(this.database.prepare(`
        SELECT entry.key AS key, SUM(CAST(entry.value AS INTEGER)) AS count
        FROM legacy_migration_extraction_batches batch,
          json_each(batch.report_json, ?) entry
        WHERE batch.migration_id = ?
        GROUP BY entry.key
        ORDER BY entry.key
      `).all(`$.${path}`, migrationId) as CountRow[]);

    const issueCounts = countRecord(this.database.prepare(`
      SELECT
        json_extract(issue.value, '$.disposition') || ':' ||
          json_extract(issue.value, '$.reason') AS key,
        SUM(COALESCE(json_extract(issue.value, '$.count'), 1)) AS count
      FROM legacy_migration_extraction_batches batch,
        json_each(batch.report_json, '$.issues') issue
      WHERE batch.migration_id = ?
      GROUP BY key
      ORDER BY key
    `).all(migrationId) as CountRow[]);

    const sourceEvidenceCandidateIds = (this.database.prepare(`
      SELECT DISTINCT CAST(candidate.value AS TEXT) AS id
      FROM legacy_migration_extraction_batches batch,
        json_each(batch.report_json, '$.sourceEvidenceCandidateIds') candidate
      WHERE batch.migration_id = ?
      ORDER BY id
    `).all(migrationId) as Array<{ readonly id: string }>).map(({ id }) => id);
    const sourceCandidatesCreated = Math.min(
      number(aggregate.source_candidates_created),
      sourceEvidenceCandidateIds.length,
    );

    return {
      mode: "attack-knowledge-only",
      semanticPreview,
      status: incomplete.length > 0 ? "partial" : "completed",
      partialScopeCount: incomplete.length,
      resumeCursors: incomplete.map((row) => ({
        manifestFingerprint: row.manifest_fingerprint,
        ...(row.source_cursor ? { nextResumeAfterSourceKey: row.source_cursor } : {}),
        ...(row.record_cursor ? { nextResumeAfterRecordKey: row.record_cursor } : {}),
      })).sort((left, right) => left.manifestFingerprint.localeCompare(right.manifestFingerprint)),
      manifestsParsed: number(aggregate.scopes),
      batchesProcessed: number(aggregate.batches),
      filesDiscovered: number(aggregate.files_discovered),
      filesParsed: number(aggregate.files_parsed),
      filesSkipped: number(aggregate.files_skipped),
      filesQuarantined: number(aggregate.files_quarantined),
      bytesParsed: number(aggregate.bytes_parsed),
      semanticFactsParsed: number(aggregate.semantic_facts_parsed),
      ambiguousFragments: number(aggregate.ambiguous_fragments),
      connectedBundlesStaged: number(aggregate.compiler_bundles_staged),
      candidatesCreated: number(aggregate.candidates_created),
      candidatesReused: number(aggregate.candidates_reused),
      sourceEvidenceCandidatesCreated: sourceCandidatesCreated,
      sourceEvidenceCandidatesReused: Math.max(0, sourceEvidenceCandidateIds.length - sourceCandidatesCreated),
      sourceBundleLinksCreated: number(aggregate.source_bundle_links),
      nodeTypeCounts: distribution("nodeTypeCounts"),
      edgeTypeCounts: distribution("edgeTypeCounts"),
      genericSourcesDiscovered: number(aggregate.generic_sources_discovered),
      genericSourcesProcessed: number(aggregate.generic_sources_processed),
      genericSourcesCompleted: number(aggregate.generic_sources_completed),
      genericRecordsProcessed: number(aggregate.generic_records_processed),
      genericRecordsQuarantined: number(aggregate.generic_records_quarantined),
      sourceEvidenceCandidateIds,
      issueCounts,
      evidenceAutomaticallyVerified: 0,
      reusableMemoryAutomaticallyPromoted: 0,
    };
  }
}

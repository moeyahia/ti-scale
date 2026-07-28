import { resolve } from "node:path";
import { createDatabaseConnection, type SqliteDatabase } from "../db";
import {
  GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES,
  GenericHistoricalAttackKnowledgeIngestionService,
} from "./GenericHistoricalAttackKnowledgeIngestionService";
import { MigrationMetadataRepository } from "./MigrationMetadataRepository";
import type { LegacySource, LegacySourceType } from "./types";

const SHA256 = /^[a-f0-9]{64}$/u;
const GENERIC_TYPES: ReadonlySet<string> = new Set(GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES);

interface RegisteredSourceRow {
  readonly source_path: string;
  readonly relative_path: string;
  readonly source_type: LegacySourceType;
  readonly source_sha256: string;
  readonly byte_size: number;
  readonly modified_at: string;
}

export interface BoundedHistoricalAttackKnowledgeResumeOptions {
  readonly databasePath: string;
  readonly migrationId: string;
  readonly outputDirectory: string;
  readonly sourceRoots: readonly string[];
  readonly receiptHmacKey: string | Buffer;
  /** Defaults keep every page small enough to release native SQLite state. */
  readonly maxRecordsPerPage?: number;
  readonly maxBundlesPerPage?: number;
  readonly maxSourcesPerPage?: number;
  readonly maxPages?: number;
  /** Assert/renew the externally held canonical writer lease. */
  readonly heartbeat: () => void;
  readonly onPage?: (page: {
    readonly sequence: number;
    readonly status: "completed" | "partial";
    readonly recordsProcessed: number;
    readonly sourcesCompleted: number;
  }) => void;
}

export interface BoundedHistoricalAttackKnowledgeResumeResult {
  readonly migrationId: string;
  readonly inventoryReceiptHash: string;
  readonly sourceCount: number;
  readonly pagesProcessed: number;
  readonly status: "completed";
  readonly finalSequence: number;
}

function boundedPositiveInteger(value: number | undefined, fallback: number, label: string): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1) throw new TypeError(`${label} must be a positive safe integer`);
  return result;
}

function sortedPaths(values: readonly string[]): readonly string[] {
  return values.map((value) => resolve(value)).sort();
}

/**
 * Continue only the generic semantic-extraction phase of an already captured
 * verified-reference migration. Each page owns a fresh SQLite connection, so
 * its prepared statements and large transient JSON structures are finalized
 * before the next page starts. The immutable source and item ledgers remain
 * the idempotency authority.
 */
export class BoundedHistoricalAttackKnowledgeResumeService {
  readonly #maxRecordsPerPage: number;
  readonly #maxBundlesPerPage: number;
  readonly #maxSourcesPerPage: number;
  readonly #maxPages: number;

  constructor(
    private readonly leaseDatabase: SqliteDatabase,
    private readonly options: BoundedHistoricalAttackKnowledgeResumeOptions,
  ) {
    if (typeof options.heartbeat !== "function") {
      throw new TypeError("Bounded resume requires a canonical writer-lease heartbeat");
    }
    this.#maxRecordsPerPage = boundedPositiveInteger(options.maxRecordsPerPage, 2_000, "maxRecordsPerPage");
    this.#maxBundlesPerPage = boundedPositiveInteger(options.maxBundlesPerPage, 250, "maxBundlesPerPage");
    this.#maxSourcesPerPage = boundedPositiveInteger(options.maxSourcesPerPage, 200, "maxSourcesPerPage");
    this.#maxPages = boundedPositiveInteger(options.maxPages, 100_000, "maxPages");
  }

  run(): BoundedHistoricalAttackKnowledgeResumeResult {
    const databasePath = resolve(this.options.databasePath);
    const outputDirectory = resolve(this.options.outputDirectory);
    const metadata = new MigrationMetadataRepository(this.leaseDatabase);
    const migration = metadata.getRun(this.options.migrationId);
    if (!migration) throw new Error("Unknown historical migration resume ID");
    if (migration.status !== "running" && migration.status !== "failed") {
      throw new Error(`Historical extraction cannot resume from status ${migration.status}`);
    }
    if (resolve(migration.databasePath) !== databasePath) {
      throw new Error("Bounded resume database path does not match migration metadata");
    }
    if (resolve(migration.outputDirectory) !== outputDirectory) {
      throw new Error("Bounded resume output directory does not match migration metadata");
    }
    if (JSON.stringify(sortedPaths(migration.sourceRoots)) !== JSON.stringify(sortedPaths(this.options.sourceRoots))) {
      throw new Error("Bounded resume source roots do not match migration metadata");
    }
    if (migration.sourceRetention !== "verified-reference" ||
        migration.brainProjectionMode !== "attack-knowledge-only" ||
        !migration.sourceRetentionAcknowledgedAt || !migration.brainProjectionAcknowledgedAt) {
      throw new Error("Bounded resume requires an acknowledged verified-reference attack-knowledge-only migration");
    }
    const receipt = this.leaseDatabase.prepare(`
      SELECT receipt_hash, object_count, byte_count
      FROM legacy_migration_inventory_receipts WHERE migration_id = ?
    `).get(migration.id) as {
      readonly receipt_hash: string;
      readonly object_count: number;
      readonly byte_count: number;
    } | undefined;
    if (!receipt || !SHA256.test(receipt.receipt_hash)) {
      throw new Error("Bounded resume requires the immutable source inventory receipt");
    }
    const custody = this.leaseDatabase.prepare(`
      SELECT COUNT(*) AS object_count, COALESCE(SUM(byte_size), 0) AS byte_count
      FROM legacy_migration_source_objects WHERE migration_id = ?
    `).get(migration.id) as { readonly object_count: number; readonly byte_count: number };
    if (Number(custody.object_count) !== Number(receipt.object_count) ||
        Number(custody.byte_count) !== Number(receipt.byte_count)) {
      throw new Error("Bounded resume source custody no longer matches the immutable inventory receipt");
    }
    const incompleteSources = this.leaseDatabase.prepare(`
      SELECT COUNT(*) AS count FROM legacy_migration_sources
      WHERE migration_id = ? AND status != 'completed'
    `).get(migration.id) as { readonly count: number };
    if (Number(incompleteSources.count) !== 0) {
      throw new Error("Bounded semantic resume requires every source-custody row to be completed first");
    }
    const genericCount = this.leaseDatabase.prepare(`
      SELECT COUNT(*) AS count FROM legacy_migration_sources
      WHERE migration_id = ? AND source_type IN (${GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES.map(() => "?").join(", ")})
    `).get(migration.id, ...GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES) as { readonly count: number };
    const rows = this.leaseDatabase.prepare(`
      SELECT source.source_path, source.relative_path, source.source_type,
        source.source_sha256, source.byte_size, source.modified_at
      FROM legacy_migration_sources source
      JOIN legacy_migration_source_objects object
        ON object.migration_id = source.migration_id
        AND object.source_id = source.id
        AND object.object_key = 'source'
        AND object.object_kind = 'source'
        AND object.verification_status = 'verified_reference'
        AND object.source_path = source.source_path
        AND object.source_sha256 = source.source_sha256
        AND object.byte_size = source.byte_size
        AND object.modified_at = source.modified_at
      WHERE source.migration_id = ?
      ORDER BY source.source_path
    `).all(migration.id) as RegisteredSourceRow[];
    const genericRows = rows.filter((row) => GENERIC_TYPES.has(row.source_type));
    if (genericRows.length !== Number(genericCount.count)) {
      throw new Error("One or more generic sources lack exact verified-reference custody");
    }
    if (genericRows.length === 0) {
      throw new Error("Bounded semantic resume found no registered generic historical sources");
    }
    const fallbackRoot = migration.sourceRoots[0];
    if (!fallbackRoot) throw new Error("Historical migration has no source root");
    const sources: LegacySource[] = genericRows.map((row) => ({
      absolutePath: row.source_path,
      relativePath: row.relative_path,
      root: fallbackRoot,
      type: row.source_type,
      sha256: row.source_sha256,
      byteSize: Number(row.byte_size),
      modifiedAt: row.modified_at,
    }));

    let checkpoint = metadata.latestExtractionCheckpoint(migration.id, "generic", receipt.receipt_hash);
    if (checkpoint?.status === "completed") {
      return {
        migrationId: migration.id,
        inventoryReceiptHash: receipt.receipt_hash,
        sourceCount: sources.length,
        pagesProcessed: 0,
        status: "completed",
        finalSequence: checkpoint.sequence,
      };
    }
    let sourceCursor = checkpoint?.nextResumeAfterSourceKey;
    let recordCursor = checkpoint?.nextResumeAfterRecordKey;
    let previousCursor = checkpoint ? JSON.stringify([sourceCursor, recordCursor ?? null]) : undefined;

    for (let pageIndex = 0; pageIndex < this.#maxPages; pageIndex += 1) {
      this.options.heartbeat();
      const pageDatabase = createDatabaseConnection({
        filename: databasePath,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      const page = (() => {
        try {
          const extractor = new GenericHistoricalAttackKnowledgeIngestionService(pageDatabase, {
            receiptHmacKey: this.options.receiptHmacKey,
            maxSources: Math.max(10_000, sources.length),
            maxRecordsThisRun: this.#maxRecordsPerPage,
            maxBundlesThisRun: this.#maxBundlesPerPage,
          });
          const result = extractor.ingest({
            migrationId: migration.id,
            inventoryReceiptHash: receipt.receipt_hash,
            sources,
            maxSourcesThisRun: this.#maxSourcesPerPage,
            maxRecordsThisRun: this.#maxRecordsPerPage,
            maxBundlesThisRun: this.#maxBundlesPerPage,
            ...(sourceCursor ? { resumeAfterSourceKey: sourceCursor } : {}),
            ...(recordCursor ? { resumeAfterRecordKey: recordCursor } : {}),
          });
          new MigrationMetadataRepository(pageDatabase).recordExtractionBatch({
            migrationId: migration.id,
            extractorKind: "generic",
            report: result,
          });
          // Return only the cursor/counters needed by the coordinator. Large
          // issues, compiler receipts, and candidate arrays die with this scope.
          return {
            status: result.status,
            recordsProcessed: result.recordsProcessed,
            sourcesCompleted: result.sourcesCompleted,
            nextResumeAfterSourceKey: result.nextResumeAfterSourceKey,
            nextResumeAfterRecordKey: result.nextResumeAfterRecordKey,
          };
        } finally {
          pageDatabase.close();
        }
      })();
      // Bun owns native SQLite statements. Closing above finalizes the page;
      // an explicit collection prevents unreachable parsed receipt structures
      // from spanning many pages in one operator process.
      Bun.gc(true);
      checkpoint = metadata.latestExtractionCheckpoint(migration.id, "generic", receipt.receipt_hash);
      if (!checkpoint) throw new Error("Bounded resume failed to persist its extraction checkpoint");
      this.options.onPage?.({
        sequence: checkpoint.sequence,
        status: page.status,
        recordsProcessed: page.recordsProcessed,
        sourcesCompleted: page.sourcesCompleted,
      });
      this.options.heartbeat();
      if (page.status === "completed") {
        return {
          migrationId: migration.id,
          inventoryReceiptHash: receipt.receipt_hash,
          sourceCount: sources.length,
          pagesProcessed: pageIndex + 1,
          status: "completed",
          finalSequence: checkpoint.sequence,
        };
      }
      if (!page.nextResumeAfterSourceKey) {
        throw new Error("Bounded resume produced a partial page without an opaque source cursor");
      }
      const currentCursor = JSON.stringify([
        page.nextResumeAfterSourceKey,
        page.nextResumeAfterRecordKey ?? null,
      ]);
      if (currentCursor === previousCursor) {
        throw new Error("Bounded resume produced a non-advancing durable cursor");
      }
      previousCursor = currentCursor;
      sourceCursor = page.nextResumeAfterSourceKey;
      recordCursor = page.nextResumeAfterRecordKey;
    }
    throw new Error("Bounded resume exceeded its configured page limit");
  }
}

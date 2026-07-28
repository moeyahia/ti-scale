import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { sha256Text } from "./SecretSafety";
import type {
  AttackKnowledgeExtractionBatchReport,
  LegacyBrainProjectionMode,
  LegacySource,
  LegacySourceRetentionMode,
  QuarantineInput,
} from "./types";

interface ExtractionBatchRow {
  readonly extractor_kind: "manifest" | "generic";
  readonly scope_key: string;
  readonly report_json: string;
}

const METADATA_SCHEMA = String.raw`
CREATE TABLE IF NOT EXISTS legacy_migration_runs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'rolled_back')),
  source_roots_json TEXT NOT NULL CHECK (json_valid(source_roots_json)),
  database_path TEXT NOT NULL,
  output_directory TEXT NOT NULL,
  database_backup_path TEXT,
  database_backup_sha256 TEXT,
  reconciliation_path TEXT,
  rollback_json TEXT CHECK (rollback_json IS NULL OR json_valid(rollback_json)),
  error_summary TEXT,
  source_retention TEXT NOT NULL DEFAULT 'protected-copy' CHECK (source_retention IN ('protected-copy', 'verified-reference')),
  source_retention_acknowledged_at TEXT,
  brain_projection_mode TEXT NOT NULL DEFAULT 'legacy-engagement' CHECK (brain_projection_mode IN ('legacy-engagement', 'attack-knowledge-only')),
  brain_projection_acknowledged_at TEXT,
  settle_seconds INTEGER CHECK (settle_seconds IS NULL OR settle_seconds BETWEEN 60 AND 86400),
  settle_cutoff_at TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  CHECK ((settle_seconds IS NULL) = (settle_cutoff_at IS NULL))
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_sources (
  id TEXT PRIMARY KEY,
  migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  source_path TEXT NOT NULL,
  relative_path TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_identity TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
  modified_at TEXT NOT NULL,
  backup_relative_path TEXT,
  source_reference TEXT,
  source_retention TEXT NOT NULL DEFAULT 'protected-copy' CHECK (source_retention IN ('protected-copy', 'verified-reference')),
  source_device INTEGER,
  source_inode INTEGER,
  verified_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'importing', 'completed', 'failed')),
  error_summary TEXT,
  discovered_at TEXT NOT NULL,
  completed_at TEXT,
  UNIQUE (migration_id, source_path)
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_items (
  id TEXT PRIMARY KEY,
  migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  source_id TEXT NOT NULL REFERENCES legacy_migration_sources(id) ON DELETE RESTRICT,
  source_identity TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_hash TEXT NOT NULL,
  target_table TEXT,
  target_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('imported', 'deduplicated', 'quarantined', 'skipped')),
  importer_version INTEGER NOT NULL DEFAULT 1,
  error_category TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (source_identity, item_key, item_hash, importer_version)
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_source_objects (
  id TEXT PRIMARY KEY,
  migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  source_id TEXT NOT NULL REFERENCES legacy_migration_sources(id) ON DELETE RESTRICT,
  object_key TEXT NOT NULL,
  source_reference TEXT NOT NULL,
  source_path TEXT NOT NULL,
  object_kind TEXT NOT NULL CHECK (object_kind IN ('accepted', 'quarantined', 'symlink', 'source')),
  classification TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
  modified_at TEXT NOT NULL,
  source_device INTEGER NOT NULL,
  source_inode INTEGER NOT NULL,
  verification_status TEXT NOT NULL CHECK (verification_status IN ('verified_reference')),
  verified_at TEXT NOT NULL,
  UNIQUE (migration_id, source_id, object_key)
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_quarantine (
  id TEXT PRIMARY KEY,
  migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  source_sha256 TEXT NOT NULL,
  source_path TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_hash TEXT,
  category TEXT NOT NULL,
  reason TEXT NOT NULL,
  redacted_excerpt TEXT,
  source_content_sha256 TEXT,
  byte_size INTEGER CHECK (byte_size IS NULL OR byte_size >= 0),
  source_created_at TEXT,
  source_modified_at TEXT,
  protected_backup_ref TEXT,
  protected_backup_sha256 TEXT,
  backup_mode TEXT CHECK (backup_mode IS NULL OR backup_mode IN ('byte_copy', 'metadata_only')),
  source_reference TEXT,
  retention_mode TEXT CHECK (retention_mode IS NULL OR retention_mode IN ('protected-copy', 'verified-reference')),
  source_device INTEGER,
  source_inode INTEGER,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS legacy_migration_reconciliation (
  migration_id TEXT PRIMARY KEY REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
  report_json TEXT NOT NULL CHECK (json_valid(report_json)),
  report_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_legacy_sources_hash_status
  ON legacy_migration_sources(source_sha256, status);
CREATE INDEX IF NOT EXISTS idx_legacy_items_source_status
  ON legacy_migration_items(source_sha256, status);
CREATE INDEX IF NOT EXISTS idx_legacy_items_source_key_hash_version
  ON legacy_migration_items(source_sha256, item_key, item_hash, importer_version);
CREATE INDEX IF NOT EXISTS idx_legacy_items_identity_status
  ON legacy_migration_items(source_identity, status);
CREATE INDEX IF NOT EXISTS idx_legacy_source_objects_hash
  ON legacy_migration_source_objects(source_sha256, object_kind);
CREATE INDEX IF NOT EXISTS idx_legacy_quarantine_source
  ON legacy_migration_quarantine(source_sha256, created_at DESC);
`;

interface ItemRow {
  readonly status: "imported" | "deduplicated" | "quarantined" | "skipped";
  readonly target_table: string | null;
  readonly target_id: string | null;
}

interface RunRow {
  readonly id: string;
  readonly status: string;
  readonly source_roots_json: string;
  readonly database_path: string;
  readonly output_directory: string;
  readonly database_backup_path: string | null;
  readonly database_backup_sha256: string | null;
  readonly reconciliation_path: string | null;
  readonly rollback_json: string | null;
  readonly source_retention: LegacySourceRetentionMode;
  readonly source_retention_acknowledged_at: string | null;
  readonly brain_projection_mode: LegacyBrainProjectionMode;
  readonly brain_projection_acknowledged_at: string | null;
  readonly settle_seconds: number | null;
  readonly settle_cutoff_at: string | null;
  readonly started_at: string;
}

export interface PreviousItem {
  readonly status: ItemRow["status"];
  readonly targetTable?: string;
  readonly targetId?: string;
}

export interface MigrationRunRecord {
  readonly id: string;
  readonly status: string;
  readonly sourceRoots: readonly string[];
  readonly databasePath: string;
  readonly outputDirectory: string;
  readonly databaseBackupPath?: string;
  readonly databaseBackupSha256?: string;
  readonly reconciliationPath?: string;
  readonly rollback?: unknown;
  readonly sourceRetention: LegacySourceRetentionMode;
  readonly sourceRetentionAcknowledgedAt?: string;
  readonly brainProjectionMode: LegacyBrainProjectionMode;
  readonly brainProjectionAcknowledgedAt?: string;
  readonly settleSeconds?: number;
  readonly settleCutoffAt?: string;
  readonly startedAt: string;
}

export interface ExtractionCheckpoint {
  readonly status: "completed" | "partial";
  readonly sequence: number;
  readonly manifestFingerprint: string;
  readonly nextResumeAfterSourceKey?: string;
  readonly nextResumeAfterRecordKey?: string;
}

export class MigrationMetadataRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  ensureSchema(): void {
    this.database.exec(METADATA_SCHEMA);
    const existing = new Set((this.database.prepare("PRAGMA table_info('legacy_migration_quarantine')").all() as Array<{ name: string }>).map((row) => row.name));
    const additions: ReadonlyArray<readonly [string, string]> = [
      ["source_content_sha256", "TEXT"],
      ["byte_size", "INTEGER CHECK (byte_size IS NULL OR byte_size >= 0)"],
      ["source_created_at", "TEXT"],
      ["source_modified_at", "TEXT"],
      ["protected_backup_ref", "TEXT"],
      ["protected_backup_sha256", "TEXT"],
      ["backup_mode", "TEXT CHECK (backup_mode IS NULL OR backup_mode IN ('byte_copy', 'metadata_only'))"],
      ["source_reference", "TEXT"],
      ["retention_mode", "TEXT CHECK (retention_mode IS NULL OR retention_mode IN ('protected-copy', 'verified-reference'))"],
      ["source_device", "INTEGER"],
      ["source_inode", "INTEGER"],
    ];
    for (const [name, definition] of additions) {
      if (!existing.has(name)) this.database.exec(`ALTER TABLE legacy_migration_quarantine ADD COLUMN ${name} ${definition}`);
    }
    const runColumns = new Set((this.database.prepare("PRAGMA table_info('legacy_migration_runs')").all() as Array<{ name: string }>).map((row) => row.name));
    if (!runColumns.has("source_retention")) {
      this.database.exec("ALTER TABLE legacy_migration_runs ADD COLUMN source_retention TEXT NOT NULL DEFAULT 'protected-copy' CHECK (source_retention IN ('protected-copy', 'verified-reference'))");
    }
    if (!runColumns.has("source_retention_acknowledged_at")) {
      this.database.exec("ALTER TABLE legacy_migration_runs ADD COLUMN source_retention_acknowledged_at TEXT");
    }
    if (!runColumns.has("brain_projection_mode")) {
      this.database.exec("ALTER TABLE legacy_migration_runs ADD COLUMN brain_projection_mode TEXT NOT NULL DEFAULT 'legacy-engagement' CHECK (brain_projection_mode IN ('legacy-engagement', 'attack-knowledge-only'))");
    }
    if (!runColumns.has("brain_projection_acknowledged_at")) {
      this.database.exec("ALTER TABLE legacy_migration_runs ADD COLUMN brain_projection_acknowledged_at TEXT");
    }
    if (!runColumns.has("settle_seconds")) {
      this.database.exec("ALTER TABLE legacy_migration_runs ADD COLUMN settle_seconds INTEGER CHECK (settle_seconds IS NULL OR settle_seconds BETWEEN 60 AND 86400)");
    }
    if (!runColumns.has("settle_cutoff_at")) {
      this.database.exec("ALTER TABLE legacy_migration_runs ADD COLUMN settle_cutoff_at TEXT");
    }
    const sourceColumns = new Set((this.database.prepare("PRAGMA table_info('legacy_migration_sources')").all() as Array<{ name: string }>).map((row) => row.name));
    const sourceAdditions: ReadonlyArray<readonly [string, string]> = [
      ["source_reference", "TEXT"],
      ["source_retention", "TEXT NOT NULL DEFAULT 'protected-copy' CHECK (source_retention IN ('protected-copy', 'verified-reference'))"],
      ["source_device", "INTEGER"],
      ["source_inode", "INTEGER"],
      ["verified_at", "TEXT"],
    ];
    for (const [name, definition] of sourceAdditions) {
      if (!sourceColumns.has(name)) this.database.exec(`ALTER TABLE legacy_migration_sources ADD COLUMN ${name} ${definition}`);
    }
    this.database.exec(`
      CREATE INDEX IF NOT EXISTS idx_legacy_quarantine_backup_ref
        ON legacy_migration_quarantine(protected_backup_ref)
    `);
  }

  createRun(input: {
    sourceRoots: readonly string[];
    databasePath: string;
    outputDirectory: string;
    startedAt?: string;
    settleSeconds?: number;
    settleCutoffAt?: string;
    sourceRetention?: LegacySourceRetentionMode;
    verifiedReferenceAcknowledged?: boolean;
    brainProjectionMode?: LegacyBrainProjectionMode;
    attackKnowledgeOnlyAcknowledged?: boolean;
  }): MigrationRunRecord {
    const id = `migration_${randomUUID()}`;
    const startedAt = input.startedAt ?? this.clock().toISOString();
    const settleSeconds = input.settleSeconds;
    const settleCutoffAt = input.settleCutoffAt;
    if ((settleSeconds === undefined) !== (settleCutoffAt === undefined)) {
      throw new Error("Settled-source duration and cutoff must be recorded together");
    }
    if (settleSeconds !== undefined) {
      if (!Number.isSafeInteger(settleSeconds) || settleSeconds < 60 || settleSeconds > 86_400) {
        throw new Error("Settled-source duration is outside its audited bounds");
      }
      const expectedCutoff = new Date(Date.parse(startedAt) - settleSeconds * 1_000).toISOString();
      if (settleCutoffAt !== expectedCutoff) {
        throw new Error("Settled-source cutoff does not match the migration start receipt");
      }
    }
    this.database.prepare(`
      INSERT INTO legacy_migration_runs (
        id, status, source_roots_json, database_path, output_directory,
        source_retention, source_retention_acknowledged_at,
        brain_projection_mode, brain_projection_acknowledged_at,
        settle_seconds, settle_cutoff_at, started_at
      ) VALUES (?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      JSON.stringify(input.sourceRoots),
      input.databasePath,
      input.outputDirectory,
      input.sourceRetention ?? "protected-copy",
      input.verifiedReferenceAcknowledged ? startedAt : null,
      input.brainProjectionMode ?? "legacy-engagement",
      input.attackKnowledgeOnlyAcknowledged ? startedAt : null,
      settleSeconds ?? null,
      settleCutoffAt ?? null,
      startedAt,
    );
    return {
      id,
      status: "running",
      sourceRoots: input.sourceRoots,
      databasePath: input.databasePath,
      outputDirectory: input.outputDirectory,
      sourceRetention: input.sourceRetention ?? "protected-copy",
      ...(input.verifiedReferenceAcknowledged ? { sourceRetentionAcknowledgedAt: startedAt } : {}),
      brainProjectionMode: input.brainProjectionMode ?? "legacy-engagement",
      ...(input.attackKnowledgeOnlyAcknowledged ? { brainProjectionAcknowledgedAt: startedAt } : {}),
      ...(settleSeconds !== undefined && settleCutoffAt !== undefined
        ? { settleSeconds, settleCutoffAt }
        : {}),
      startedAt,
    };
  }

  getRun(id: string): MigrationRunRecord | undefined {
    const row = this.database.prepare(`
      SELECT id, status, source_roots_json, database_path, output_directory,
        database_backup_path, database_backup_sha256, reconciliation_path,
        rollback_json, source_retention, source_retention_acknowledged_at,
        brain_projection_mode, brain_projection_acknowledged_at,
        settle_seconds, settle_cutoff_at, started_at
      FROM legacy_migration_runs WHERE id = ?
    `).get(id) as RunRow | undefined;
    if (!row) return undefined;
    return {
      id: row.id,
      status: row.status,
      sourceRoots: JSON.parse(row.source_roots_json) as string[],
      databasePath: row.database_path,
      outputDirectory: row.output_directory,
      ...(row.database_backup_path ? { databaseBackupPath: row.database_backup_path } : {}),
      ...(row.database_backup_sha256 ? { databaseBackupSha256: row.database_backup_sha256 } : {}),
      ...(row.reconciliation_path ? { reconciliationPath: row.reconciliation_path } : {}),
      ...(row.rollback_json ? { rollback: JSON.parse(row.rollback_json) as unknown } : {}),
      sourceRetention: row.source_retention,
      ...(row.source_retention_acknowledged_at ? { sourceRetentionAcknowledgedAt: row.source_retention_acknowledged_at } : {}),
      brainProjectionMode: row.brain_projection_mode,
      ...(row.brain_projection_acknowledged_at ? { brainProjectionAcknowledgedAt: row.brain_projection_acknowledged_at } : {}),
      ...(row.settle_seconds !== null && row.settle_cutoff_at
        ? { settleSeconds: Number(row.settle_seconds), settleCutoffAt: row.settle_cutoff_at }
        : {}),
      startedAt: row.started_at,
    };
  }

  registeredSourcePaths(migrationId: string): string[] {
    const rows = this.database.prepare(`
      SELECT source_path FROM legacy_migration_sources
      WHERE migration_id = ? ORDER BY source_path
    `).all(migrationId) as Array<{ source_path: string }>;
    return rows.map((row) => row.source_path);
  }

  setBackup(id: string, path: string, sha256: string, rollback: unknown): void {
    this.database.prepare(`
      UPDATE legacy_migration_runs
      SET database_backup_path = ?, database_backup_sha256 = ?, rollback_json = ?
      WHERE id = ? AND status = 'running'
    `).run(path, sha256, JSON.stringify(rollback), id);
  }

  registerSource(
    migrationId: string,
    source: LegacySource,
    backupRelativePath?: string,
    reference?: {
      readonly retentionMode: LegacySourceRetentionMode;
      readonly device: number;
      readonly inode: number;
    },
  ): string {
    const sourceIdentity = sha256Text(`${source.type}\0${source.absolutePath}`);
    const id = `source_${sha256Text(`${migrationId}\0${source.absolutePath}`).slice(0, 40)}`;
    this.database.prepare(`
      INSERT INTO legacy_migration_sources (
        id, migration_id, source_path, relative_path, source_type, source_identity, source_sha256,
        byte_size, modified_at, backup_relative_path, status, discovered_at,
        source_reference, source_retention, source_device, source_inode, verified_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
      ON CONFLICT(migration_id, source_path) DO UPDATE SET
        source_identity = excluded.source_identity,
        source_sha256 = excluded.source_sha256,
        byte_size = excluded.byte_size,
        modified_at = excluded.modified_at,
        backup_relative_path = excluded.backup_relative_path,
        source_reference = excluded.source_reference,
        source_retention = excluded.source_retention,
        source_device = excluded.source_device,
        source_inode = excluded.source_inode,
        verified_at = excluded.verified_at
    `).run(
      id,
      migrationId,
      source.absolutePath,
      source.relativePath,
      source.type,
      sourceIdentity,
      source.sha256,
      source.byteSize,
      source.modifiedAt,
      backupRelativePath ?? null,
      this.clock().toISOString(),
      reference ? `legacy-private-source://${id}` : null,
      reference?.retentionMode ?? "protected-copy",
      reference?.device ?? null,
      reference?.inode ?? null,
      reference ? this.clock().toISOString() : null,
    );
    return id;
  }

  markSource(sourceId: string, status: "importing" | "completed" | "failed", error?: string): void {
    this.database.prepare(`
      UPDATE legacy_migration_sources
      SET status = ?, error_summary = ?, completed_at = CASE WHEN ? IN ('completed', 'failed') THEN ? ELSE completed_at END
      WHERE id = ?
    `).run(status, error ?? null, status, this.clock().toISOString(), sourceId);
  }

  registerSourceObject(input: {
    readonly migrationId: string;
    readonly sourceId: string;
    readonly objectKey: string;
    readonly sourcePath: string;
    readonly objectKind: "accepted" | "quarantined" | "symlink" | "source";
    readonly classification: string;
    readonly sourceSha256: string;
    readonly byteSize: number;
    readonly modifiedAt: string;
    readonly sourceDevice: number;
    readonly sourceInode: number;
  }): string {
    const id = `source_object_${sha256Text(`${input.migrationId}\0${input.sourceId}\0${input.objectKey}`).slice(0, 40)}`;
    const sourceReference = `legacy-private-source://${id}`;
    this.database.prepare(`
      INSERT INTO legacy_migration_source_objects (
        id, migration_id, source_id, object_key, source_reference, source_path,
        object_kind, classification, source_sha256, byte_size, modified_at,
        source_device, source_inode, verification_status, verified_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified_reference', ?)
      ON CONFLICT(migration_id, source_id, object_key) DO UPDATE SET
        source_reference = excluded.source_reference,
        source_path = excluded.source_path,
        object_kind = excluded.object_kind,
        classification = excluded.classification,
        source_sha256 = excluded.source_sha256,
        byte_size = excluded.byte_size,
        modified_at = excluded.modified_at,
        source_device = excluded.source_device,
        source_inode = excluded.source_inode,
        verification_status = excluded.verification_status,
        verified_at = excluded.verified_at
    `).run(
      id,
      input.migrationId,
      input.sourceId,
      input.objectKey,
      sourceReference,
      input.sourcePath,
      input.objectKind,
      input.classification,
      input.sourceSha256,
      input.byteSize,
      input.modifiedAt,
      input.sourceDevice,
      input.sourceInode,
      this.clock().toISOString(),
    );
    return sourceReference;
  }

  /**
   * Append one extractor page to the durable reconciliation ledger. The page
   * identity is cursor-derived, so replay after a crash is idempotent even
   * when the extractor reports reused rather than newly-created candidates.
   */
  recordExtractionBatch(input: {
    readonly migrationId: string;
    readonly extractorKind: "manifest" | "generic";
    readonly report: AttackKnowledgeExtractionBatchReport;
  }): void {
    const cursorReport = input.report as AttackKnowledgeExtractionBatchReport & {
      readonly nextResumeAfterSourceKey?: string;
      readonly nextResumeAfterRecordKey?: string;
    };
    const pageIdentity = JSON.stringify({
      status: input.report.status,
      nextResumeAfterSourceKey: cursorReport.nextResumeAfterSourceKey ?? null,
      nextResumeAfterRecordKey: cursorReport.nextResumeAfterRecordKey ?? null,
    });
    const pageKey = sha256Text(pageIdentity);
    const reportJson = JSON.stringify(input.report);
    const reportHash = sha256Text(reportJson);
    this.database.prepare(`
      INSERT OR IGNORE INTO legacy_migration_extraction_batches (
        migration_id, extractor_kind, scope_key, page_key, sequence,
        report_json, report_hash, created_at
      ) VALUES (
        ?, ?, ?, ?,
        COALESCE((
          SELECT MAX(sequence) + 1
          FROM legacy_migration_extraction_batches
          WHERE migration_id = ? AND extractor_kind = ? AND scope_key = ?
        ), 1),
        ?, ?, ?
      )
    `).run(
      input.migrationId,
      input.extractorKind,
      input.report.manifestFingerprint,
      pageKey,
      input.migrationId,
      input.extractorKind,
      input.report.manifestFingerprint,
      reportJson,
      reportHash,
      this.clock().toISOString(),
    );
  }

  extractionBatches(migrationId: string): readonly (readonly AttackKnowledgeExtractionBatchReport[])[] {
    const rows = this.database.prepare(`
      SELECT extractor_kind, scope_key, report_json
      FROM legacy_migration_extraction_batches
      WHERE migration_id = ?
      ORDER BY extractor_kind, scope_key, sequence
    `).all(migrationId) as ExtractionBatchRow[];
    const grouped = new Map<string, AttackKnowledgeExtractionBatchReport[]>();
    for (const row of rows) {
      const key = `${row.extractor_kind}\0${row.scope_key}`;
      const reports = grouped.get(key) ?? [];
      reports.push(JSON.parse(row.report_json) as AttackKnowledgeExtractionBatchReport);
      grouped.set(key, reports);
    }
    return [...grouped.values()];
  }

  /**
   * Read only the lightweight cursor projection from the latest immutable
   * extractor receipt. Heavy compiler reconciliation and candidate arrays stay
   * inside SQLite and are never materialized merely to resume a page.
   */
  latestExtractionCheckpoint(
    migrationId: string,
    extractorKind: "manifest" | "generic",
    scopeKey: string,
  ): ExtractionCheckpoint | undefined {
    const row = this.database.prepare(`
      SELECT sequence,
        json_extract(report_json, '$.status') AS status,
        COALESCE(json_extract(report_json, '$.manifestFingerprint'), scope_key)
          AS manifest_fingerprint,
        json_extract(report_json, '$.nextResumeAfterSourceKey') AS source_cursor,
        json_extract(report_json, '$.nextResumeAfterRecordKey') AS record_cursor
      FROM legacy_migration_extraction_batches
      WHERE migration_id = ? AND extractor_kind = ? AND scope_key = ?
      ORDER BY sequence DESC LIMIT 1
    `).get(migrationId, extractorKind, scopeKey) as {
      readonly sequence: number;
      readonly status: "completed" | "partial";
      readonly manifest_fingerprint: string;
      readonly source_cursor: string | null;
      readonly record_cursor: string | null;
    } | undefined;
    if (!row) return undefined;
    if (row.manifest_fingerprint !== scopeKey) {
      throw new Error("Historical extraction checkpoint no longer matches its immutable scope");
    }
    if (row.status !== "completed" && row.status !== "partial") {
      throw new Error("Historical extraction checkpoint has an invalid status");
    }
    if (row.status === "partial" && !row.source_cursor) {
      throw new Error("Partial historical extraction checkpoint lacks an opaque source cursor");
    }
    return {
      status: row.status,
      sequence: Number(row.sequence),
      manifestFingerprint: row.manifest_fingerprint,
      ...(row.source_cursor ? { nextResumeAfterSourceKey: row.source_cursor } : {}),
      ...(row.record_cursor ? { nextResumeAfterRecordKey: row.record_cursor } : {}),
    };
  }

  previousItem(sourceIdentity: string, sourceSha256: string, itemKey: string, itemHash: string): PreviousItem | undefined {
    const row = this.database.prepare(`
      SELECT status, target_table, target_id
      FROM legacy_migration_items
      WHERE (source_identity = ? OR source_sha256 = ?)
        AND item_key = ? AND item_hash = ? AND importer_version = 1
    `).get(sourceIdentity, sourceSha256, itemKey, itemHash) as ItemRow | undefined;
    if (!row) return undefined;
    return {
      status: row.status,
      ...(row.target_table ? { targetTable: row.target_table } : {}),
      ...(row.target_id ? { targetId: row.target_id } : {}),
    };
  }

  recordItem(input: {
    migrationId: string;
    sourceId: string;
    sourceIdentity: string;
    sourceSha256: string;
    itemKey: string;
    itemHash: string;
    status: ItemRow["status"];
    targetTable?: string;
    targetId?: string;
    errorCategory?: string;
  }): void {
    const id = `migration_item_${sha256Text(`${input.sourceIdentity}\0${input.itemKey}\0${input.itemHash}`).slice(0, 40)}`;
    this.database.prepare(`
      INSERT INTO legacy_migration_items (
        id, migration_id, source_id, source_identity, source_sha256, item_key, item_hash,
        target_table, target_id, status, importer_version, error_category, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT(source_identity, item_key, item_hash, importer_version) DO NOTHING
    `).run(
      id,
      input.migrationId,
      input.sourceId,
      input.sourceIdentity,
      input.sourceSha256,
      input.itemKey,
      input.itemHash,
      input.targetTable ?? null,
      input.targetId ?? null,
      input.status,
      input.errorCategory ?? null,
      this.clock().toISOString(),
    );
  }

  quarantine(migrationId: string, input: QuarantineInput): void {
    const createdAt = this.clock().toISOString();
    const id = `quarantine_${randomUUID()}`;
    this.database.prepare(`
      INSERT INTO legacy_migration_quarantine (
        id, migration_id, source_sha256, source_path, item_key, item_hash,
        category, reason, redacted_excerpt, source_content_sha256, byte_size,
        source_created_at, source_modified_at, protected_backup_ref,
        protected_backup_sha256, backup_mode, source_reference, retention_mode,
        source_device, source_inode, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      migrationId,
      input.sourceSha256,
      input.sourcePath,
      input.itemKey,
      input.itemHash ?? null,
      input.category,
      input.reason,
      input.redactedExcerpt ?? null,
      input.sourceContentSha256 ?? null,
      input.byteSize ?? null,
      input.sourceCreatedAt ?? null,
      input.sourceModifiedAt ?? null,
      input.protectedBackupRef ?? null,
      input.protectedBackupSha256 ?? null,
      input.backupMode ?? null,
      input.sourceReference ?? null,
      input.retentionMode ?? null,
      input.sourceDevice ?? null,
      input.sourceInode ?? null,
      createdAt,
    );
  }

  completeRun(migrationId: string, report: unknown, reportPath: string): void {
    const now = this.clock().toISOString();
    const reportJson = JSON.stringify(report);
    const reportHash = sha256Text(reportJson);
    inImmediateTransaction(this.database, () => {
      this.database.prepare(`
        INSERT OR REPLACE INTO legacy_migration_reconciliation (
          migration_id, report_json, report_hash, created_at
        ) VALUES (?, ?, ?, ?)
      `).run(migrationId, reportJson, reportHash, now);
      const previous = this.database.prepare(`
        SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1
      `).get() as { record_hash: string } | undefined;
      const auditId = `audit_migration_${sha256Text(migrationId).slice(0, 40)}`;
      const reportSummary = report as {
        sourceRetention?: { mode?: unknown };
        brainProjection?: { mode?: unknown };
        settledSourceBoundary?: {
          settleSeconds?: unknown;
          cutoffAt?: unknown;
          deferredObjects?: unknown;
          deferredBytes?: unknown;
        };
      } | null;
      const sourceRetention = reportSummary?.sourceRetention?.mode === "verified-reference"
        ? "verified-reference"
        : "protected-copy";
      const brainProjectionMode = reportSummary?.brainProjection?.mode === "attack-knowledge-only"
        ? "attack-knowledge-only"
        : "legacy-engagement";
      const detailsJson = JSON.stringify({
        migrationId,
        reconciliationHash: reportHash,
        sourceRetention,
        brainProjectionMode,
        ...(reportSummary?.settledSourceBoundary ? {
          settledSourceBoundary: {
            settleSeconds: reportSummary.settledSourceBoundary.settleSeconds,
            cutoffAt: reportSummary.settledSourceBoundary.cutoffAt,
            deferredObjects: reportSummary.settledSourceBoundary.deferredObjects,
            deferredBytes: reportSummary.settledSourceBoundary.deferredBytes,
          },
        } : {}),
      });
      const recordHash = sha256Text([
        previous?.record_hash ?? "",
        auditId,
        "legacy_migration_completed",
        detailsJson,
        now,
      ].join("\0"));
      this.database.prepare(`
        INSERT OR IGNORE INTO audit_records (
          id, actor_type, actor_id, action, resource_type, resource_id,
          reason, details_json, previous_hash, record_hash, occurred_at
        ) VALUES (?, 'system', 'import:legacy', 'legacy_migration_completed',
          'data_migration', ?, ?, ?, ?, ?, ?)
      `).run(
        auditId,
        migrationId,
        sourceRetention === "verified-reference"
          ? "Verified-reference legacy import reconciled"
          : "Backup-first legacy import reconciled",
        detailsJson,
        previous?.record_hash ?? null,
        recordHash,
        now,
      );
      this.database.prepare(`
        UPDATE legacy_migration_runs
        SET status = 'completed', reconciliation_path = ?, completed_at = ?
        WHERE id = ?
      `).run(reportPath, now, migrationId);
    });
  }

  failRun(migrationId: string, error: string): void {
    this.database.prepare(`
      UPDATE legacy_migration_runs
      SET status = 'failed', error_summary = ?, completed_at = ?
      WHERE id = ?
    `).run(error.slice(0, 1_000), this.clock().toISOString(), migrationId);
  }

  markRolledBack(migrationId: string): void {
    this.database.prepare(`
      UPDATE legacy_migration_runs SET status = 'rolled_back', completed_at = ? WHERE id = ?
    `).run(this.clock().toISOString(), migrationId);
  }
}

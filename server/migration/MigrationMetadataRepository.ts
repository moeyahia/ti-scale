import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { sha256Text } from "./SecretSafety";
import type { LegacySource, QuarantineInput } from "./types";

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
  started_at TEXT NOT NULL,
  completed_at TEXT
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
  readonly startedAt: string;
}

export class MigrationMetadataRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  ensureSchema(): void {
    this.database.exec(METADATA_SCHEMA);
  }

  createRun(input: {
    sourceRoots: readonly string[];
    databasePath: string;
    outputDirectory: string;
  }): MigrationRunRecord {
    const id = `migration_${randomUUID()}`;
    const startedAt = this.clock().toISOString();
    this.database.prepare(`
      INSERT INTO legacy_migration_runs (
        id, status, source_roots_json, database_path, output_directory, started_at
      ) VALUES (?, 'running', ?, ?, ?, ?)
    `).run(id, JSON.stringify(input.sourceRoots), input.databasePath, input.outputDirectory, startedAt);
    return {
      id,
      status: "running",
      sourceRoots: input.sourceRoots,
      databasePath: input.databasePath,
      outputDirectory: input.outputDirectory,
      startedAt,
    };
  }

  getRun(id: string): MigrationRunRecord | undefined {
    const row = this.database.prepare(`
      SELECT id, status, source_roots_json, database_path, output_directory,
        database_backup_path, database_backup_sha256, reconciliation_path,
        rollback_json, started_at
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

  registerSource(migrationId: string, source: LegacySource, backupRelativePath: string): string {
    const sourceIdentity = sha256Text(`${source.type}\0${source.absolutePath}`);
    const id = `source_${sha256Text(`${migrationId}\0${source.absolutePath}`).slice(0, 40)}`;
    this.database.prepare(`
      INSERT INTO legacy_migration_sources (
        id, migration_id, source_path, relative_path, source_type, source_identity, source_sha256,
        byte_size, modified_at, backup_relative_path, status, discovered_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
      ON CONFLICT(migration_id, source_path) DO UPDATE SET
        source_identity = excluded.source_identity,
        source_sha256 = excluded.source_sha256,
        byte_size = excluded.byte_size,
        modified_at = excluded.modified_at,
        backup_relative_path = excluded.backup_relative_path
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
      backupRelativePath,
      this.clock().toISOString(),
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
        category, reason, redacted_excerpt, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      const detailsJson = JSON.stringify({ migrationId, reconciliationHash: reportHash });
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
          'data_migration', ?, 'Backup-first legacy import reconciled', ?, ?, ?, ?)
      `).run(auditId, migrationId, detailsJson, previous?.record_hash ?? null, recordHash, now);
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

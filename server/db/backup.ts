import type { SqliteDatabase } from "./types";

export const DATABASE_BACKUP_DISABLED_ERROR =
  "Database backup creation is disabled by operator no-backup policy";

export interface BackupOptions {
  readonly overwrite?: boolean;
}

export interface BackupResult {
  readonly destination: string;
  readonly totalPages: number;
  readonly createdAt: string;
}

/**
 * Retained only as a fail-closed compatibility boundary for historical callers.
 * It must reject before inspecting the database or resolving/touching a path.
 */
export async function backupDatabase(
  _database: SqliteDatabase,
  _destination: string,
  _options: BackupOptions = {},
): Promise<BackupResult> {
  throw new Error(DATABASE_BACKUP_DISABLED_ERROR);
}

export async function createTimestampedBackup(
  _database: SqliteDatabase,
  _directory: string,
  _prefix = "ti-scale",
): Promise<BackupResult> {
  throw new Error(DATABASE_BACKUP_DISABLED_ERROR);
}

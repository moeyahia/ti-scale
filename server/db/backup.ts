import {
  chmodSync,
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { assertDatabaseIntegrity, createDatabaseConnection } from "./connection";
import type { SqliteDatabase } from "./types";

export interface BackupOptions {
  readonly overwrite?: boolean;
}

export interface BackupResult {
  readonly destination: string;
  readonly totalPages: number;
  readonly createdAt: string;
}

/** Create, validate, and atomically publish a SQLite online backup. */
export async function backupDatabase(
  database: SqliteDatabase,
  destination: string,
  options: BackupOptions = {},
): Promise<BackupResult> {
  if (!destination.trim()) throw new Error("A backup destination is required");
  const absoluteDestination = resolve(destination);
  if (database.name !== ":memory:" && resolve(database.name) === absoluteDestination) {
    throw new Error("Backup destination must differ from the live database");
  }
  if (existsSync(absoluteDestination) && !options.overwrite) {
    throw new Error(`Backup destination already exists: ${absoluteDestination}`);
  }

  const parent = dirname(absoluteDestination);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const temporary = join(
    parent,
    `.${basename(absoluteDestination)}.${process.pid}.${Date.now()}.tmp`,
  );

  try {
    const metadata = await database.backup(temporary);
    const verification = createDatabaseConnection({
      filename: temporary,
      readonly: true,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try {
      assertDatabaseIntegrity(verification);
    } finally {
      verification.close();
    }
    chmodSync(temporary, 0o600);
    renameSync(temporary, absoluteDestination);
    return {
      destination: absoluteDestination,
      totalPages: metadata.totalPages,
      createdAt: new Date().toISOString(),
    };
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

export async function createTimestampedBackup(
  database: SqliteDatabase,
  directory: string,
  prefix = "ti-scale",
): Promise<BackupResult> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  return backupDatabase(database, join(directory, `${prefix}-${timestamp}.sqlite`));
}

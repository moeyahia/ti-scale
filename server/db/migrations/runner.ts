import { createHash } from "node:crypto";
import { inImmediateTransaction } from "../transaction";
import type { AppliedMigration, Migration, SqliteDatabase } from "../types";
import { DATABASE_MIGRATIONS } from "./index";

const CREATE_MIGRATION_TABLE = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY CHECK (version > 0),
  name TEXT NOT NULL UNIQUE,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL
) STRICT;
`;

interface MigrationRow {
  readonly version: number;
  readonly name: string;
  readonly checksum: string;
  readonly applied_at: string;
}

export interface MigrationResult {
  readonly applied: readonly AppliedMigration[];
  readonly currentVersion: number;
}

function checksum(sql: string): string {
  return createHash("sha256").update(sql, "utf8").digest("hex");
}

function assertValidMigrationSet(migrations: readonly Migration[]): void {
  let previous = 0;
  const names = new Set<string>();
  for (const migration of migrations) {
    if (!Number.isSafeInteger(migration.version) || migration.version <= previous) {
      throw new Error("Database migrations must have unique, strictly increasing positive versions");
    }
    if (!migration.name.trim() || names.has(migration.name)) {
      throw new Error(`Invalid or duplicate migration name: ${migration.name}`);
    }
    if (!migration.sql.trim()) throw new Error(`Migration ${migration.version} has no SQL`);
    previous = migration.version;
    names.add(migration.name);
  }
}

export function listAppliedMigrations(database: SqliteDatabase): AppliedMigration[] {
  database.exec(CREATE_MIGRATION_TABLE);
  const rows = database
    .prepare("SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version")
    .all() as MigrationRow[];
  return rows.map((row) => ({
    version: row.version,
    name: row.name,
    checksum: row.checksum,
    appliedAt: row.applied_at,
  }));
}

export function migrateDatabase(
  database: SqliteDatabase,
  migrations: readonly Migration[] = DATABASE_MIGRATIONS,
): MigrationResult {
  assertValidMigrationSet(migrations);
  database.exec(CREATE_MIGRATION_TABLE);

  const existing = new Map(
    listAppliedMigrations(database).map((migration) => [migration.version, migration]),
  );
  const knownVersions = new Set(migrations.map((migration) => migration.version));
  for (const applied of existing.values()) {
    if (!knownVersions.has(applied.version)) {
      throw new Error(`Database contains unknown migration version ${applied.version}`);
    }
  }

  const appliedNow: AppliedMigration[] = [];
  const insert = database.prepare(
    "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
  );

  for (const migration of migrations) {
    const migrationChecksum = checksum(migration.sql);
    const alreadyApplied = existing.get(migration.version);
    if (alreadyApplied) {
      if (
        alreadyApplied.name !== migration.name ||
        alreadyApplied.checksum !== migrationChecksum
      ) {
        throw new Error(
          `Migration ${migration.version} differs from the already-applied migration`,
        );
      }
      continue;
    }

    const appliedAt = new Date().toISOString();
    inImmediateTransaction(database, () => {
      database.exec(migration.sql);
      insert.run(migration.version, migration.name, migrationChecksum, appliedAt);
    });
    appliedNow.push({
      version: migration.version,
      name: migration.name,
      checksum: migrationChecksum,
      appliedAt,
    });
  }

  const currentVersion = migrations.at(-1)?.version ?? 0;
  return { applied: appliedNow, currentVersion };
}

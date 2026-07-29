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

function checksum(migration: Migration): string {
  const digest = createHash("sha256").update(migration.sql, "utf8");
  if (migration.compatibilityAddColumns?.length) {
    digest.update("\0compatibility-add-columns\0", "utf8");
    digest.update(JSON.stringify(migration.compatibilityAddColumns), "utf8");
  }
  return digest.digest("hex");
}

const SAFE_SQL_IDENTIFIER = /^[a-z][a-z0-9_]*$/u;

function applyCompatibilityColumns(database: SqliteDatabase, migration: Migration): void {
  for (const table of migration.compatibilityAddColumns ?? []) {
    if (!SAFE_SQL_IDENTIFIER.test(table.table)) {
      throw new Error(`Migration ${migration.version} has an unsafe compatibility table identifier`);
    }
    const exists = database.prepare(
      "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?",
    ).get(table.table) as { present: number } | undefined;
    if (!exists) continue;
    const existing = new Set((database.prepare(`PRAGMA table_info("${table.table}")`).all() as Array<{ name: string }>).map((row) => row.name));
    for (const column of table.columns) {
      if (!SAFE_SQL_IDENTIFIER.test(column.name) || column.definition.includes(";")) {
        throw new Error(`Migration ${migration.version} has an unsafe compatibility column definition`);
      }
      if (existing.has(column.name)) continue;
      database.exec(`ALTER TABLE "${table.table}" ADD COLUMN "${column.name}" ${column.definition}`);
      existing.add(column.name);
    }
  }
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
    for (const table of migration.compatibilityAddColumns ?? []) {
      if (!SAFE_SQL_IDENTIFIER.test(table.table) || table.columns.length === 0) {
        throw new Error(`Migration ${migration.version} has an invalid compatibility-column declaration`);
      }
      const columnNames = new Set<string>();
      for (const column of table.columns) {
        if (!SAFE_SQL_IDENTIFIER.test(column.name) || !column.definition.trim() || column.definition.includes(";") || columnNames.has(column.name)) {
          throw new Error(`Migration ${migration.version} has an invalid compatibility-column declaration`);
        }
        columnNames.add(column.name);
      }
    }
    previous = migration.version;
    names.add(migration.name);
  }
}

function integerPragma(database: SqliteDatabase, name: string): number {
  return Number(database.pragma(name, { simple: true }));
}

function foreignKeyViolations(database: SqliteDatabase): readonly unknown[] {
  return database.prepare("PRAGMA foreign_key_check").all();
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
    const migrationChecksum = checksum(migration);
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
    const apply = (): void => {
      inImmediateTransaction(database, () => {
        applyCompatibilityColumns(database, migration);
        database.exec(migration.sql);
        if (foreignKeyViolations(database).length > 0) {
          throw new Error(`Migration ${migration.version} introduced foreign-key violations`);
        }
        insert.run(migration.version, migration.name, migrationChecksum, appliedAt);
      });
    };
    if (migration.requiresForeignKeysDisabled) {
      if (database.inTransaction) {
        throw new Error(`Migration ${migration.version} is startup-only and cannot run inside a transaction`);
      }
      if (integerPragma(database, "foreign_keys") !== 1) {
        throw new Error(`Migration ${migration.version} requires foreign-key enforcement before it starts`);
      }
      database.pragma("foreign_keys = OFF");
      if (integerPragma(database, "foreign_keys") !== 0) {
        throw new Error(`Migration ${migration.version} could not enter its isolated rebuild boundary`);
      }
      try {
        apply();
      } finally {
        database.pragma("foreign_keys = ON");
      }
      if (integerPragma(database, "foreign_keys") !== 1) {
        throw new Error(`Migration ${migration.version} did not restore foreign-key enforcement`);
      }
      if (foreignKeyViolations(database).length > 0) {
        throw new Error(`Migration ${migration.version} failed its post-commit foreign-key check`);
      }
    } else {
      apply();
    }
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

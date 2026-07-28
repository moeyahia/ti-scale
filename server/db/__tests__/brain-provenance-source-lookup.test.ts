import { describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  migrateDatabase,
} from "../index";

function indexColumns(database: ReturnType<typeof createDatabaseConnection>): string[] {
  return (database.prepare(`
    PRAGMA index_info('idx_legacy_source_objects_reference_verified')
  `).all() as Array<{ name: string }>).map((row) => row.name);
}

function sourceLookupPlan(database: ReturnType<typeof createDatabaseConnection>): string[] {
  return (database.prepare(`
    EXPLAIN QUERY PLAN
    SELECT source_object.source_path, migration_source.relative_path
    FROM legacy_migration_source_objects source_object
    JOIN legacy_migration_sources migration_source
      ON migration_source.id = source_object.source_id
    WHERE source_object.source_reference = ?
    ORDER BY source_object.verified_at DESC, migration_source.relative_path ASC
    LIMIT 1
  `).all("legacy-private-source://query-plan-fixture") as Array<{ detail: string }>)
    .map((row) => row.detail);
}

describe("Brain provenance source lookup migration", () => {
  test("creates the verified-reference lookup index and prevents a source-object scan", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      const result = migrateDatabase(database);
      expect(result.currentVersion).toBe(60);
      expect(indexColumns(database)).toEqual(["source_reference", "verified_at", "source_id"]);

      const plan = sourceLookupPlan(database);
      expect(plan.some((detail) => (
        detail.includes("SEARCH source_object USING INDEX idx_legacy_source_objects_reference_verified")
        && detail.includes("source_reference=?")
      ))).toBeTrue();
      expect(plan.some((detail) => detail.includes("SCAN source_object"))).toBeFalse();
    } finally {
      database.close();
    }
  });

  test("accepts an emergency pre-existing equivalent index during upgrade", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(
        database,
        DATABASE_MIGRATIONS.filter((migration) => migration.version <= 38),
      );
      database.exec(`
        CREATE INDEX idx_legacy_source_objects_reference_verified
          ON legacy_migration_source_objects(source_reference, verified_at DESC, source_id)
      `);

      const result = migrateDatabase(database);
      expect(result.applied.map(({ version }) => version)).toEqual([
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
      ]);
      expect(indexColumns(database)).toEqual(["source_reference", "verified_at", "source_id"]);
      expect(sourceLookupPlan(database).some((detail) => detail.includes(
        "SEARCH source_object USING INDEX idx_legacy_source_objects_reference_verified",
      ))).toBeTrue();
    } finally {
      database.close();
    }
  });
});

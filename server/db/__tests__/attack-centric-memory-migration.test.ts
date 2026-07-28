import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  migrateDatabase,
  type Migration,
} from "../index";
import { MemoryRepository } from "../../memory";
import { ATTACK_CENTRIC_REUSABLE_NODE_TYPES } from "../../memory/types";
import { V21_REUSABLE_MEMORY_NODE_TYPES } from "../migrations/021_reusable_memory_edge_privacy_boundary";

const directories: string[] = [];
const NOW = "2026-07-20T00:00:00.000Z";

function opaqueId(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function temporaryDatabase(name: string): { directory: string; path: string } {
  const directory = mkdtempSync(join(tmpdir(), `${name}-`));
  directories.push(directory);
  return { directory, path: join(directory, "command-os.sqlite") };
}

function migrationsThrough(version: number): readonly Migration[] {
  return DATABASE_MIGRATIONS.filter((migration) => migration.version <= version);
}

function seedLegacyMemory(database: ReturnType<typeof createDatabaseConnection>) {
  const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const source = memory.createNode({
    id: "legacy-technique-source",
    nodeType: "technique",
    title: "Legacy searchable technique",
    summary: "Legacy row retained across a CHECK-constraint rebuild.",
    body: "The full-text marker is titanium-migration-sentinel.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.8,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Legacy migration fixture",
      sources: [{ sourceType: "fixture", sourceId: "legacy-private-source", acquiredAt: NOW }],
    },
    authorType: "operator",
    authorId: "migration-test",
  });
  const target = memory.createNode({
    ...source,
    id: "legacy-technique-target",
    title: "Legacy target technique",
    body: "The companion row verifies edge and source preservation.",
    provenance: {
      ...source.provenance,
      sources: [{ sourceType: "fixture", sourceId: "legacy-target-source", acquiredAt: NOW }],
    },
  });
  memory.createEdge({
    id: "legacy-memory-edge",
    sourceNodeId: source.id,
    targetNodeId: target.id,
    edgeType: "depends_on",
    title: "Legacy dependency",
    summary: "The legacy relationship survives the rebuild.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.8,
    lifecycleStatus: "confirmed",
    provenance: source.provenance,
    explanation: "The source depends on the target.",
    authorType: "operator",
    authorId: "migration-test",
  });
  return { source, target };
}

function migrationVersion(database: ReturnType<typeof createDatabaseConnection>): number {
  return Number((database.prepare(
    "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations",
  ).get() as { version: number }).version);
}

function ftsRowIds(database: ReturnType<typeof createDatabaseConnection>): number[] {
  return (database.prepare(`
    SELECT rowid FROM memory_nodes_fts
    WHERE memory_nodes_fts MATCH ?
    ORDER BY rowid
  `).all('"titanium migration sentinel"') as Array<{ rowid: number }>).map(({ rowid }) => Number(rowid));
}

describe("attack-centric memory migrations", () => {
  test("binds migration v21 to the reusable taxonomy snapshot at introduction", () => {
    expect([...V21_REUSABLE_MEMORY_NODE_TYPES].sort())
      .toEqual([...ATTACK_CENTRIC_REUSABLE_NODE_TYPES].sort());
  });

  test("v17 to current preserves rowids, FTS, foreign keys, and sources without creating a backup", () => {
    const location = temporaryDatabase("attack-memory-upgrade");
    const database = createDatabaseConnection({ filename: location.path });
    try {
      migrateDatabase(database, migrationsThrough(17));
      const { source } = seedLegacyMemory(database);
      const rowidBefore = Number((database.prepare(
        "SELECT rowid FROM memory_nodes WHERE id = ?",
      ).get(source.id) as { rowid: number }).rowid);
      expect(ftsRowIds(database)).toEqual([rowidBefore]);

      const result = migrateDatabase(database);
      expect(result.applied.map(({ version }) => version)).toEqual([
        18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
      ]);
      expect(result.currentVersion).toBe(60);
      expect(existsSync(join(location.directory, "migration-backups"))).toBe(false);

      expect(Number((database.prepare(
        "SELECT rowid FROM memory_nodes WHERE id = ?",
      ).get(source.id) as { rowid: number }).rowid)).toBe(rowidBefore);
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_sources").get())
        .toEqual({ count: 2 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get())
        .toEqual({ count: 1 });
      expect(ftsRowIds(database)).toEqual([rowidBefore]);
      expect(Number(database.pragma("foreign_keys", { simple: true }))).toBe(1);
      expect(database.prepare("PRAGMA foreign_key_check").all()).toEqual([]);

      const schemaObjects = database.prepare(`
        SELECT name, type FROM sqlite_master
        WHERE name IN (
          'memory_nodes_fts_insert', 'memory_nodes_fts_delete', 'memory_nodes_fts_update',
          'idx_memory_edges_source_type_target',
          'operational_hazard_profiles', 'idx_operational_hazard_procedure_freshness',
          'attack_attempt_knowledge_contexts', 'idx_attack_attempt_knowledge_procedure'
        ) ORDER BY name
      `).all() as Array<{ name: string; type: string }>;
      expect(schemaObjects).toEqual([
        { name: "attack_attempt_knowledge_contexts", type: "table" },
        { name: "idx_attack_attempt_knowledge_procedure", type: "index" },
        { name: "idx_memory_edges_source_type_target", type: "index" },
        { name: "idx_operational_hazard_procedure_freshness", type: "index" },
        { name: "memory_nodes_fts_delete", type: "trigger" },
        { name: "memory_nodes_fts_insert", type: "trigger" },
        { name: "memory_nodes_fts_update", type: "trigger" },
        { name: "operational_hazard_profiles", type: "table" },
      ]);

      const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
      const procedure = memory.createNode({
        id: opaqueId("reusable-attack-procedure"),
        nodeType: "attack_procedure",
        title: "Bounded retry procedure",
        summary: "A reviewed generalized procedure without a target locator.",
        body: "Use the health gate before retrying this procedure.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.95,
        lifecycleStatus: "verified",
        confirmationState: "confirmed",
        provenance: {
          method: "derived",
          explanation: "Generalized from private local evidence",
          sources: [{ sourceType: "private_record", sourceId: "private-source", acquiredAt: NOW }],
        },
        authorType: "operator",
        authorId: "migration-test",
      });
      const hazard = memory.createNode({
        ...procedure,
        id: opaqueId("reusable-operational-hazard"),
        nodeType: "operational_hazard",
        title: "Repeated reset leaves service unavailable",
        provenance: {
          ...procedure.provenance,
          sources: [{ sourceType: "private_record", sourceId: "private-hazard", acquiredAt: NOW }],
        },
      });
      database.prepare(`
        INSERT INTO operational_hazard_profiles (
          node_id, procedure_node_id, ordered_steps_json, observed_symptom,
          affected_component, state_before, state_after, reproducibility_count,
          attempt_count, recovery_action_summary, unsafe_retry_conditions_json,
          safe_retry_gate_json, alternative_sequence_json, recovery_cost_json, confidence,
          observed_at, created_at, updated_at
        ) VALUES (?, ?, '[]', 'Requests stop completing', 'Application worker',
          'healthy', 'unavailable', 2, 2, 'Recycle the isolated worker',
          '["health check still fails"]', '["health check passes"]',
          '["use a lower-load validation"]', '{"operatorReportedResetCountMinimum":11}',
          0.95, ?, ?, ?)
      `).run(hazard.id, procedure.id, NOW, NOW, NOW);
      expect(database.prepare(`
        SELECT procedure_node_id, reproducibility_count, attempt_count, recovery_cost_json
        FROM operational_hazard_profiles WHERE node_id = ?
      `).get(hazard.id)).toEqual({
        procedure_node_id: procedure.id,
        reproducibility_count: 2,
        attempt_count: 2,
        recovery_cost_json: '{"operatorReportedResetCountMinimum":11}',
      });
    } finally {
      database.close();
    }
  });

  test("upgrades the exact pre-v29 live migration-metadata shape without losing custody rows", () => {
    const location = temporaryDatabase("historical-custody-live-shape");
    const database = createDatabaseConnection({ filename: location.path });
    try {
      migrateDatabase(database, migrationsThrough(28));
      database.exec(`
        CREATE TABLE legacy_migration_runs (
          id TEXT PRIMARY KEY,
          status TEXT NOT NULL,
          source_roots_json TEXT NOT NULL,
          database_path TEXT NOT NULL,
          output_directory TEXT NOT NULL,
          database_backup_path TEXT,
          database_backup_sha256 TEXT,
          reconciliation_path TEXT,
          rollback_json TEXT,
          error_summary TEXT,
          started_at TEXT NOT NULL,
          completed_at TEXT
        ) STRICT;
        CREATE TABLE legacy_migration_sources (
          id TEXT PRIMARY KEY,
          migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
          source_path TEXT NOT NULL,
          relative_path TEXT NOT NULL,
          source_type TEXT NOT NULL,
          source_identity TEXT NOT NULL,
          source_sha256 TEXT NOT NULL,
          byte_size INTEGER NOT NULL,
          modified_at TEXT NOT NULL,
          backup_relative_path TEXT,
          status TEXT NOT NULL,
          error_summary TEXT,
          discovered_at TEXT NOT NULL,
          completed_at TEXT
        ) STRICT;
        CREATE TABLE legacy_migration_items (
          id TEXT PRIMARY KEY,
          migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
          source_id TEXT NOT NULL REFERENCES legacy_migration_sources(id) ON DELETE RESTRICT,
          source_identity TEXT NOT NULL,
          source_sha256 TEXT NOT NULL,
          item_key TEXT NOT NULL,
          item_hash TEXT NOT NULL,
          target_table TEXT,
          target_id TEXT,
          status TEXT NOT NULL,
          importer_version INTEGER NOT NULL DEFAULT 1,
          error_category TEXT,
          created_at TEXT NOT NULL
        ) STRICT;
        CREATE TABLE legacy_migration_quarantine (
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
        CREATE TABLE legacy_migration_reconciliation (
          migration_id TEXT PRIMARY KEY REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
          report_json TEXT NOT NULL,
          report_hash TEXT NOT NULL,
          created_at TEXT NOT NULL
        ) STRICT;
      `);
      database.prepare(`
        INSERT INTO legacy_migration_runs (
          id, status, source_roots_json, database_path, output_directory,
          started_at, completed_at
        ) VALUES ('legacy-run', 'completed', '["/private/source"]', '/legacy.sqlite',
          '/private/output', ?, ?)
      `).run(NOW, NOW);
      database.prepare(`
        INSERT INTO legacy_migration_sources (
          id, migration_id, source_path, relative_path, source_type,
          source_identity, source_sha256, byte_size, modified_at, status,
          discovered_at, completed_at
        ) VALUES ('legacy-source', 'legacy-run', '/private/source/session.json',
          'session.json', 'session_json', 'opaque-source', ?, 42, ?, 'completed', ?, ?)
      `).run("a".repeat(64), NOW, NOW, NOW);
      database.prepare(`
        INSERT INTO legacy_migration_quarantine (
          id, migration_id, source_sha256, source_path, item_key, category,
          reason, created_at
        ) VALUES ('legacy-quarantine', 'legacy-run', ?, '/private/source/session.json',
          'record-1', 'malformed', 'Legacy parser rejected the record', ?)
      `).run("a".repeat(64), NOW);

      const result = migrateDatabase(database);
      expect(result.applied.map(({ version }) => version)).toEqual([
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
        45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
      ]);
      expect(result.currentVersion).toBe(60);
      expect(database.prepare(`
        SELECT source_retention, source_retention_acknowledged_at,
          brain_projection_mode, brain_projection_acknowledged_at
        FROM legacy_migration_runs WHERE id = 'legacy-run'
      `).get()).toEqual({
        source_retention: "protected-copy",
        source_retention_acknowledged_at: null,
        brain_projection_mode: "legacy-engagement",
        brain_projection_acknowledged_at: null,
      });
      expect(database.prepare(`
        SELECT source_reference, source_retention, source_device, source_inode, verified_at
        FROM legacy_migration_sources WHERE id = 'legacy-source'
      `).get()).toEqual({
        source_reference: null,
        source_retention: "protected-copy",
        source_device: null,
        source_inode: null,
        verified_at: null,
      });
      expect(database.prepare(`
        SELECT category, reason, protected_backup_ref, retention_mode, source_inode
        FROM legacy_migration_quarantine WHERE id = 'legacy-quarantine'
      `).get()).toEqual({
        category: "malformed",
        reason: "Legacy parser rejected the record",
        protected_backup_ref: null,
        retention_mode: null,
        source_inode: null,
      });
      expect(database.pragma("quick_check", { simple: true })).toBe("ok");
      expect(database.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("a failing FK-off rebuild rolls back transactionally without creating a backup", () => {
    const location = temporaryDatabase("attack-memory-rollback");
    const database = createDatabaseConnection({ filename: location.path });
    try {
      const through17 = migrationsThrough(17);
      migrateDatabase(database, through17);
      const { source } = seedLegacyMemory(database);
      const rowidBefore = Number((database.prepare(
        "SELECT rowid FROM memory_nodes WHERE id = ?",
      ).get(source.id) as { rowid: number }).rowid);
      const failing: Migration = {
        version: 18,
        name: "attack_centric_rebuild_failure_fixture",
        requiresForeignKeysDisabled: true,
        requiresVerifiedBackup: true,
        sql: `
          CREATE TABLE migration_failure_marker (id INTEGER PRIMARY KEY) STRICT;
          INSERT INTO migration_failure_marker (id) VALUES (1);
          INSERT INTO table_that_does_not_exist (id) VALUES (1);
        `,
      };

      expect(() => migrateDatabase(database, [...through17, failing])).toThrow();
      expect(migrationVersion(database)).toBe(17);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM sqlite_master
        WHERE type = 'table' AND name = 'migration_failure_marker'
      `).get()).toEqual({ count: 0 });
      expect(Number((database.prepare(
        "SELECT rowid FROM memory_nodes WHERE id = ?",
      ).get(source.id) as { rowid: number }).rowid)).toBe(rowidBefore);
      expect(ftsRowIds(database)).toEqual([rowidBefore]);
      expect(Number(database.pragma("foreign_keys", { simple: true }))).toBe(1);
      expect(database.prepare("PRAGMA foreign_key_check").all()).toEqual([]);

      expect(existsSync(join(location.directory, "migration-backups"))).toBe(false);
    } finally {
      database.close();
    }
  });
});

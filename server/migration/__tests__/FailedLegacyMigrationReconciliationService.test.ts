import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { CanonicalDatabaseLeaseService, withCanonicalWriterLease } from "../../maintenance";
import {
  detectActiveLegacyMigrationProcessIds,
  FailedLegacyMigrationReconciliationService,
} from "../FailedLegacyMigrationReconciliationService";

const FAILED_ID = "migration_failed";
const REPLACEMENT_ID = "migration_replacement";
const STALE_SOURCE_ID = "source_stale";
const REPLACEMENT_SOURCE_ID = "source_replacement";
const SOURCE_PATH = "/history/fireflow";
const SOURCE_IDENTITY = "a".repeat(64);

function fixture() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO legacy_migration_runs (
      id, status, source_roots_json, database_path, output_directory,
      source_retention, source_retention_acknowledged_at,
      brain_projection_mode, brain_projection_acknowledged_at,
      error_summary, started_at, completed_at
    ) VALUES (?, ?, ?, ':memory:', ?, 'verified-reference', ?,
      'attack-knowledge-only', ?, ?, ?, ?)
  `).run(
    FAILED_ID,
    "failed",
    JSON.stringify(["/history"]),
    "/tmp/failed",
    "2026-07-21T10:00:00.000Z",
    "2026-07-21T10:00:00.000Z",
    "Immutable source inventory changed; superseded by a fresh import.",
    "2026-07-21T10:00:00.000Z",
    "2026-07-21T11:00:00.000Z",
  );
  database.prepare(`
    INSERT INTO legacy_migration_runs (
      id, status, source_roots_json, database_path, output_directory,
      source_retention, source_retention_acknowledged_at,
      brain_projection_mode, brain_projection_acknowledged_at,
      started_at, completed_at, reconciliation_path
    ) VALUES (?, 'completed', ?, ':memory:', '/tmp/replacement',
      'verified-reference', ?, 'attack-knowledge-only', ?, ?, ?, '/tmp/reconciliation.json')
  `).run(
    REPLACEMENT_ID,
    JSON.stringify([SOURCE_PATH]),
    "2026-07-21T11:30:00.000Z",
    "2026-07-21T11:30:00.000Z",
    "2026-07-21T11:30:00.000Z",
    "2026-07-21T12:30:00.000Z",
  );
  const insertSource = database.prepare(`
    INSERT INTO legacy_migration_sources (
      id, migration_id, source_path, relative_path, source_type,
      source_identity, source_sha256, byte_size, modified_at,
      status, error_summary, discovered_at, completed_at,
      source_retention, source_reference, source_device, source_inode, verified_at
    ) VALUES (?, ?, ?, 'Fireflow', 'engagement_manifest', ?, ?, 100,
      '2026-07-20T00:00:00.000Z', ?, NULL, ?, ?, 'verified-reference', ?, 8, ?, ?)
  `);
  insertSource.run(
    STALE_SOURCE_ID,
    FAILED_ID,
    SOURCE_PATH,
    SOURCE_IDENTITY,
    "b".repeat(64),
    "importing",
    "2026-07-21T10:30:00.000Z",
    null,
    `legacy-private-source://${STALE_SOURCE_ID}`,
    100,
    "2026-07-21T10:30:00.000Z",
  );
  insertSource.run(
    REPLACEMENT_SOURCE_ID,
    REPLACEMENT_ID,
    SOURCE_PATH,
    SOURCE_IDENTITY,
    "c".repeat(64),
    "completed",
    "2026-07-21T11:40:00.000Z",
    "2026-07-21T12:00:00.000Z",
    `legacy-private-source://${REPLACEMENT_SOURCE_ID}`,
    101,
    "2026-07-21T11:40:00.000Z",
  );
  database.prepare(`
    INSERT INTO legacy_migration_source_objects (
      id, migration_id, source_id, object_key, source_reference, source_path,
      object_kind, classification, source_sha256, byte_size, modified_at,
      source_device, source_inode, verification_status, verified_at
    ) VALUES ('object_replacement', ?, ?, 'source', 'legacy-private-source://object_replacement', ?,
      'source', 'engagement_manifest', ?, 100, '2026-07-20T00:00:00.000Z',
      8, 101, 'verified_reference', '2026-07-21T11:40:00.000Z')
  `).run(REPLACEMENT_ID, REPLACEMENT_SOURCE_ID, SOURCE_PATH, "c".repeat(64));
  database.prepare(`
    INSERT INTO legacy_migration_inventory_receipts (
      migration_id, receipt_hash, object_count, byte_count, created_at
    ) VALUES (?, ?, 1, 100, '2026-07-21T11:35:00.000Z')
  `).run(REPLACEMENT_ID, "d".repeat(64));
  database.prepare(`
    INSERT INTO legacy_migration_reconciliation (
      migration_id, report_json, report_hash, created_at
    ) VALUES (?, '{}', ?, '2026-07-21T12:30:00.000Z')
  `).run(REPLACEMENT_ID, "e".repeat(64));
  return database;
}

describe("FailedLegacyMigrationReconciliationService", () => {
  test("detects importer processes while excluding the reconciliation command ancestry", () => {
    const procRoot = mkdtempSync(join(tmpdir(), "ti-scale-reconciliation-proc-"));
    const processEntry = (pid: number, parentPid: number, command: string) => {
      const directory = join(procRoot, String(pid));
      mkdirSync(directory);
      writeFileSync(join(directory, "stat"), `${pid} (fixture) S ${parentPid} 0 0 0\n`);
      writeFileSync(join(directory, "cmdline"), command);
    };
    try {
      processEntry(100, 50, "bun\0run\0server/migration/cli.ts\0reconcile-failed");
      processEntry(50, 1, "bun\0run\0history:migrate-configured");
      processEntry(1, 0, "/sbin/init\0");
      processEntry(200, 1, "bun\0run\0server/migration/configured-historical-cli.ts");
      processEntry(201, 1, "bun\0run\0server/index.ts");

      expect(detectActiveLegacyMigrationProcessIds(procRoot, 100)).toEqual([200]);
    } finally {
      rmSync(procRoot, { recursive: true, force: true });
    }
  });

  test("correlates an importer to the exact canonical database and fails closed when its database is unknown", () => {
    const procRoot = mkdtempSync(join(tmpdir(), "ti-scale-reconciliation-database-proc-"));
    const processEntry = (
      pid: number,
      command: string,
      environment = "",
    ) => {
      const directory = join(procRoot, String(pid));
      mkdirSync(directory);
      writeFileSync(join(directory, "stat"), `${pid} (fixture) S 1 0 0 0\n`);
      writeFileSync(join(directory, "cmdline"), command);
      writeFileSync(join(directory, "environ"), environment);
    };
    try {
      const targetDatabase = join(procRoot, "target.sqlite");
      const unrelatedDatabase = join(procRoot, "unrelated.sqlite");
      processEntry(1, "/sbin/init\0");
      processEntry(
        200,
        `bun\0run\0server/migration/cli.ts\0migrate\0--db\0${unrelatedDatabase}\0`,
      );
      processEntry(
        201,
        `bun\0run\0server/migration/cli.ts\0migrate\0--db\0${targetDatabase}\0`,
      );
      processEntry(
        202,
        "bun\0run\0server/migration/configured-historical-cli.ts\0",
      );
      processEntry(
        203,
        "bun\0run\0server/migration/configured-historical-cli.ts\0",
        `TI_SCALE_DATABASE_PATH=${unrelatedDatabase}\0`,
      );

      expect(detectActiveLegacyMigrationProcessIds(procRoot, 1, targetDatabase))
        .toEqual([201, 202]);
      expect(detectActiveLegacyMigrationProcessIds(procRoot, 1))
        .toEqual([200, 201, 202, 203]);
    } finally {
      rmSync(procRoot, { recursive: true, force: true });
    }
  });

  test("fails closed during preview and produces no mutation", () => {
    const database = fixture();
    try {
      const blocked = new FailedLegacyMigrationReconciliationService(database, {
        activeMigrationProcessIds: () => [4242],
      });
      expect(() => blocked.preview({
        failedMigrationId: FAILED_ID,
        replacementMigrationId: REPLACEMENT_ID,
      })).toThrow("migration process is still active");
      expect(database.prepare("SELECT status FROM legacy_migration_sources WHERE id = ?")
        .get(STALE_SOURCE_ID)).toEqual({ status: "importing" });

      const leases = new CanonicalDatabaseLeaseService(database);
      const importLease = leases.acquireWriter({
        ownerId: "migration:other",
        operation: "historical-engagement-import",
      });
      const service = new FailedLegacyMigrationReconciliationService(database, {
        activeMigrationProcessIds: () => [],
      });
      expect(() => service.preview({
        failedMigrationId: FAILED_ID,
        replacementMigrationId: REPLACEMENT_ID,
      })).toThrow("active canonical migration lease");
      leases.release(importLease);
    } finally {
      database.close();
    }
  });

  test("requires exact completed replacement identity, root, inventory, and reconciliation receipts", () => {
    const database = fixture();
    try {
      const service = new FailedLegacyMigrationReconciliationService(database, {
        activeMigrationProcessIds: () => [],
      });
      database.prepare("UPDATE legacy_migration_sources SET source_identity = ? WHERE id = ?")
        .run("f".repeat(64), REPLACEMENT_SOURCE_ID);
      expect(() => service.preview({
        failedMigrationId: FAILED_ID,
        replacementMigrationId: REPLACEMENT_ID,
      })).toThrow("exact source identity");
      database.prepare("UPDATE legacy_migration_sources SET source_identity = ? WHERE id = ?")
        .run(SOURCE_IDENTITY, REPLACEMENT_SOURCE_ID);
      database.prepare("UPDATE legacy_migration_runs SET source_roots_json = ? WHERE id = ?")
        .run(JSON.stringify(["/history"]), REPLACEMENT_ID);
      expect(() => service.preview({
        failedMigrationId: FAILED_ID,
        replacementMigrationId: REPLACEMENT_ID,
      })).toThrow("exact source root");
      database.prepare("UPDATE legacy_migration_runs SET source_roots_json = ? WHERE id = ?")
        .run(JSON.stringify([SOURCE_PATH]), REPLACEMENT_ID);
      database.prepare("DELETE FROM legacy_migration_reconciliation WHERE migration_id = ?")
        .run(REPLACEMENT_ID);
      expect(() => service.preview({
        failedMigrationId: FAILED_ID,
        replacementMigrationId: REPLACEMENT_ID,
      })).toThrow("immutable inventory and reconciliation receipt");
      expect(database.prepare("SELECT status FROM legacy_migration_sources WHERE id = ?")
        .get(STALE_SOURCE_ID)).toEqual({ status: "importing" });
    } finally {
      database.close();
    }
  });

  test("uses an active writer fence, terminalizes only lingering children, and appends a privacy-safe audit", async () => {
    const database = fixture();
    try {
      database.prepare(`
        INSERT INTO legacy_migration_sources (
          id, migration_id, source_path, relative_path, source_type,
          source_identity, source_sha256, byte_size, modified_at, status,
          discovered_at, completed_at, source_retention
        ) VALUES ('source_already_completed', ?, '/history/already', 'already',
          'engagement_manifest', ?, ?, 1, '2026-07-20T00:00:00.000Z',
          'completed', '2026-07-21T10:20:00.000Z', '2026-07-21T10:25:00.000Z',
          'verified-reference')
      `).run(FAILED_ID, "1".repeat(64), "2".repeat(64));
      const service = new FailedLegacyMigrationReconciliationService(database, {
        clock: () => new Date("2026-07-21T13:00:00.000Z"),
        createId: () => "audit_reconcile_test",
        activeMigrationProcessIds: () => [],
      });
      const preview = service.preview({
        failedMigrationId: FAILED_ID,
        replacementMigrationId: REPLACEMENT_ID,
      });
      expect(preview.sourceCount).toBe(1);
      expect(preview.sources[0]).toMatchObject({
        id: STALE_SOURCE_ID,
        priorStatus: "importing",
        sourceIdentity: SOURCE_IDENTITY,
        replacementSourceId: REPLACEMENT_SOURCE_ID,
      });
      expect(canonicalText(preview)).not.toContain(SOURCE_PATH);

      const result = await withCanonicalWriterLease(database, {
        ownerId: "operator:test",
        operation: "failed-legacy-migration-reconciliation",
      }, (handle, leases) => service.reconcile({
        failedMigrationId: FAILED_ID,
        replacementMigrationId: REPLACEMENT_ID,
        expectedPreviewHash: preview.previewHash,
        actorId: "operator:test",
        reason: "Close stale child metadata after reviewing the completed replacement receipt",
        acknowledged: true,
      }, { handle, leases }));
      expect(result).toMatchObject({
        status: "reconciled",
        reconciledSourceIds: [STALE_SOURCE_ID],
        terminalAt: "2026-07-21T11:00:00.000Z",
        auditRecordId: "audit_reconcile_test",
      });
      expect(database.prepare(`
        SELECT status, completed_at, error_summary
        FROM legacy_migration_sources WHERE id = ?
      `).get(STALE_SOURCE_ID)).toEqual({
        status: "failed",
        completed_at: "2026-07-21T11:00:00.000Z",
        error_summary: `Reconciled after completed replacement ${REPLACEMENT_ID}. Immutable source inventory changed; superseded by a fresh import.`,
      });
      expect(database.prepare("SELECT status FROM legacy_migration_sources WHERE id = 'source_already_completed'")
        .get()).toEqual({ status: "completed" });
      expect(database.prepare("SELECT COUNT(*) AS count FROM legacy_migration_source_objects")
        .get()).toEqual({ count: 1 });
      const audit = database.prepare(`
        SELECT action, resource_id, details_json, record_hash
        FROM audit_records WHERE id = 'audit_reconcile_test'
      `).get() as { action: string; resource_id: string; details_json: string; record_hash: string };
      expect(audit.action).toBe("legacy_migration.failed_children_reconciled");
      expect(audit.resource_id).toBe(FAILED_ID);
      expect(audit.details_json).not.toContain(SOURCE_PATH);
      expect(JSON.parse(audit.details_json)).toMatchObject({
        disposition: "failed_metadata_quarantine",
        sourceObjectsPreserved: true,
        semanticKnowledgeChanged: false,
      });
      expect(audit.record_hash).toHaveLength(64);
      expect(new CanonicalDatabaseLeaseService(database).listActive()).toEqual([]);
    } finally {
      database.close();
    }
  });
});

function canonicalText(value: unknown): string {
  return JSON.stringify(value);
}

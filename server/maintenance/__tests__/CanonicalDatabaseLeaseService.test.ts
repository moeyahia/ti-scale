import { afterEach, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdtempSync, renameSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  migrateDatabase,
} from "../../db";
import {
  CanonicalDatabaseLeaseConflictError,
  CanonicalDatabaseLeaseLostError,
  CanonicalDatabaseLeaseService,
  withCanonicalWriterLease,
} from "../CanonicalDatabaseLeaseService";

const temporaryDirectories: string[] = [];

function temporaryDatabase(name: string): string {
  const directory = mkdtempSync(join(tmpdir(), `ti-scale-${name}-`));
  temporaryDirectories.push(directory);
  return join(directory, "canonical.sqlite");
}

function migratedMemoryDatabase() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  return database;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("CanonicalDatabaseLeaseService", () => {
  test("allows shared writers while excluding maintenance in both directions", () => {
    const database = migratedMemoryDatabase();
    try {
      const leases = new CanonicalDatabaseLeaseService(database);
      const first = leases.acquireWriter({ ownerId: "writer:first", operation: "vault-export" });
      const second = leases.acquireWriter({ ownerId: "writer:second", operation: "brain-reconcile" });

      expect(leases.listActive().map(({ mode, ownerId }) => ({ mode, ownerId }))).toEqual([
        { mode: "writer", ownerId: "writer:first" },
        { mode: "writer", ownerId: "writer:second" },
      ]);
      expect(() => leases.acquireMaintenance({
        ownerId: "release:one",
        operation: "activate-release",
      })).toThrow(CanonicalDatabaseLeaseConflictError);

      expect(leases.release(first)).toBe(true);
      expect(leases.release(second)).toBe(true);
      const maintenance = leases.acquireMaintenance({
        ownerId: "release:one",
        operation: "activate-release",
      });
      expect(() => leases.acquireWriter({
        ownerId: "writer:late",
        operation: "historical-import",
      })).toThrow(CanonicalDatabaseLeaseConflictError);
      expect(() => leases.acquireMaintenance({
        ownerId: "release:two",
        operation: "rollback-release",
      })).toThrow(CanonicalDatabaseLeaseConflictError);
      expect(maintenance.fencingToken).toBeGreaterThan(second.fencingToken);
    } finally {
      database.close();
    }
  });

  test("renews a matching owner and fence and rejects tampered handles", () => {
    const database = migratedMemoryDatabase();
    let now = new Date("2026-07-21T12:00:00.000Z");
    try {
      const leases = new CanonicalDatabaseLeaseService(database, { clock: () => now });
      const handle = leases.acquireWriter({
        ownerId: "operator:test",
        operation: "preference-import",
        ttlMs: 2_000,
      });
      now = new Date("2026-07-21T12:00:00.500Z");
      const renewed = leases.renew(handle, 4_000);
      expect(renewed.expiresAt).toBe("2026-07-21T12:00:04.500Z");
      expect(renewed.fencingToken).toBe(handle.fencingToken);

      const tampered = { ...renewed, fencingToken: renewed.fencingToken + 1 };
      expect(() => leases.assertActive(tampered)).toThrow(CanonicalDatabaseLeaseLostError);
      expect(() => leases.release(tampered)).toThrow(CanonicalDatabaseLeaseLostError);
      expect(leases.assertActive(renewed).ownerId).toBe("operator:test");
    } finally {
      database.close();
    }
  });

  test("expires stale ownership durably across service restart and fences its handle", () => {
    const database = migratedMemoryDatabase();
    let now = new Date("2026-07-21T12:00:00.000Z");
    try {
      const firstProcess = new CanonicalDatabaseLeaseService(database, { clock: () => now });
      const stale = firstProcess.acquireWriter({
        ownerId: "process:old",
        operation: "historical-confirmation",
        ttlMs: 1_000,
      });
      now = new Date("2026-07-21T12:00:01.001Z");

      const restartedProcess = new CanonicalDatabaseLeaseService(database, { clock: () => now });
      const replacement = restartedProcess.acquireMaintenance({
        ownerId: "release:new",
        operation: "controlled-cutover",
        ttlMs: 1_000,
      });
      expect(replacement.fencingToken).toBeGreaterThan(stale.fencingToken);
      expect(() => firstProcess.assertActive(stale)).toThrow(CanonicalDatabaseLeaseLostError);
      expect(() => firstProcess.renew(stale)).toThrow(CanonicalDatabaseLeaseLostError);
      expect(() => firstProcess.release(stale)).toThrow(CanonicalDatabaseLeaseLostError);
      expect(database.prepare(`
        SELECT released_at, release_reason FROM canonical_database_leases WHERE id = ?
      `).get(stale.id)).toEqual({
        released_at: "2026-07-21T12:00:01.001Z",
        release_reason: "expired",
      });
    } finally {
      database.close();
    }
  });

  test("serializes the final writer snapshot and maintenance acquisition across connections", () => {
    const filename = temporaryDatabase("canonical-toctou");
    const writerDatabase = createDatabaseConnection({ filename });
    migrateDatabase(writerDatabase);
    const releaseDatabase = createDatabaseConnection({ filename, fileMustExist: true });
    try {
      const writerLeases = new CanonicalDatabaseLeaseService(writerDatabase);
      const releaseLeases = new CanonicalDatabaseLeaseService(releaseDatabase);
      const writer = writerLeases.acquireWriter({
        ownerId: "vault:worker",
        operation: "obsidian-sync",
      });
      expect(() => releaseLeases.acquireMaintenance({
        ownerId: "release:controller",
        operation: "deploy",
      })).toThrow(CanonicalDatabaseLeaseConflictError);

      writerLeases.release(writer);
      const maintenance = releaseLeases.acquireMaintenance({
        ownerId: "release:controller",
        operation: "deploy",
      });
      expect(() => writerLeases.acquireWriter({
        ownerId: "migration:late",
        operation: "legacy-import",
      })).toThrow(CanonicalDatabaseLeaseConflictError);
      expect(releaseLeases.assertActive(maintenance).mode).toBe("maintenance");
    } finally {
      releaseDatabase.close();
      writerDatabase.close();
    }
  });

  test("keeps writers excluded when rollback replaces the canonical database file", () => {
    const filename = temporaryDatabase("canonical-replacement");
    const markerPath = `${filename}.maintenance-lock.json`;
    const originalDatabase = createDatabaseConnection({ filename });
    migrateDatabase(originalDatabase);
    const originalLeases = new CanonicalDatabaseLeaseService(originalDatabase);
    const maintenance = originalLeases.acquireMaintenance({
      ownerId: "rollback:controller",
      operation: "restore-canonical-database",
    });
    originalDatabase.close();
    const priorFilename = `${filename}.prior`;
    for (const suffix of ["", "-wal", "-shm"] as const) {
      if (existsSync(`${filename}${suffix}`)) {
        renameSync(`${filename}${suffix}`, `${priorFilename}${suffix}`);
      }
    }

    const replacementDatabase = createDatabaseConnection({ filename });
    migrateDatabase(replacementDatabase);
    try {
      const replacementLeases = new CanonicalDatabaseLeaseService(replacementDatabase);
      expect(() => replacementLeases.acquireWriter({
        ownerId: "writer:during-restore",
        operation: "obsidian-import",
      })).toThrow(CanonicalDatabaseLeaseConflictError);

      const priorDatabase = createDatabaseConnection({
        filename: priorFilename,
        fileMustExist: true,
      });
      try {
        const priorLeases = new CanonicalDatabaseLeaseService(priorDatabase, {
          maintenanceMarkerPath: markerPath,
        });
        expect(priorLeases.release(maintenance, "rollback-completed")).toBe(true);
      } finally {
        priorDatabase.close();
      }
      const writer = replacementLeases.acquireWriter({
        ownerId: "writer:after-restore",
        operation: "obsidian-import",
      });
      expect(writer.mode).toBe("writer");
    } finally {
      replacementDatabase.close();
    }
  });

  test("an explicitly authorized rollback can release after restoring a pre-v35 database", () => {
    const filename = temporaryDatabase("canonical-schema-downgrade");
    const markerPath = `${filename}.maintenance-lock.json`;
    const priorFilename = `${filename}.pre-v35`;
    const priorDatabase = createDatabaseConnection({ filename: priorFilename });
    try {
      migrateDatabase(priorDatabase, DATABASE_MIGRATIONS.slice(0, 34));
      priorDatabase.pragma("wal_checkpoint(TRUNCATE)");
    }
    finally { priorDatabase.close(); }

    const maintenanceDatabase = createDatabaseConnection({ filename });
    migrateDatabase(maintenanceDatabase);
    const leases = new CanonicalDatabaseLeaseService(maintenanceDatabase, {
      allowReplacementWithoutLeaseSchema: true,
    });
    const maintenance = leases.acquireMaintenance({
      ownerId: "rollback:controller",
      operation: "restore-pre-v35-database",
    });
    expect(existsSync(markerPath)).toBe(true);

    // Mirror the release restore boundary: discard the post-release WAL and
    // atomically replace the canonical path after the original connection is
    // closed, while the external maintenance marker remains alive.
    leases.assertActive(maintenance);
    maintenanceDatabase.close();
    rmSync(`${filename}-wal`, { force: true });
    rmSync(`${filename}-shm`, { force: true });
    const replacement = `${filename}.replacement`;
    copyFileSync(priorFilename, replacement);
    renameSync(replacement, filename);
    expect(leases.releaseAfterDatabaseReplacement(maintenance, "schema-downgrade-completed")).toBe(true);
    expect(existsSync(markerPath)).toBe(false);

    const restored = createDatabaseConnection({ filename, readonly: true, fileMustExist: true });
    try {
      expect(CanonicalDatabaseLeaseService.schemaAvailable(restored)).toBe(false);
      expect(restored.prepare("SELECT MAX(version) AS version FROM schema_migrations").get())
        .toEqual({ version: 34 });
      expect(restored.pragma("quick_check")).toEqual([{ quick_check: "ok" }]);
    } finally {
      restored.close();
    }
  });

  test("a pre-v35 replacement remains fenced without explicit downgrade authority", () => {
    const filename = temporaryDatabase("canonical-schema-downgrade-refused");
    const markerPath = `${filename}.maintenance-lock.json`;
    const priorFilename = `${filename}.pre-v35`;
    const priorDatabase = createDatabaseConnection({ filename: priorFilename });
    try {
      migrateDatabase(priorDatabase, DATABASE_MIGRATIONS.slice(0, 34));
      priorDatabase.pragma("wal_checkpoint(TRUNCATE)");
    } finally {
      priorDatabase.close();
    }

    const maintenanceDatabase = createDatabaseConnection({ filename });
    migrateDatabase(maintenanceDatabase);
    const leases = new CanonicalDatabaseLeaseService(maintenanceDatabase);
    const maintenance = leases.acquireMaintenance({
      ownerId: "rollback:controller",
      operation: "restore-pre-v35-database",
    });
    leases.assertActive(maintenance);
    maintenanceDatabase.close();
    rmSync(`${filename}-wal`, { force: true });
    rmSync(`${filename}-shm`, { force: true });
    const replacement = `${filename}.replacement`;
    copyFileSync(priorFilename, replacement);
    renameSync(replacement, filename);

    expect(() => leases.releaseAfterDatabaseReplacement(maintenance)).toThrow(
      "lacks the lease schema",
    );
    expect(existsSync(markerPath)).toBe(true);
  });

  test("fails closed when migration 35 has not been installed", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS.slice(0, 34));
      expect(CanonicalDatabaseLeaseService.schemaAvailable(database)).toBe(false);
      expect(() => new CanonicalDatabaseLeaseService(database)).toThrow(
        "writer and maintenance operations fail closed until migration 35 is installed",
      );
    } finally {
      database.close();
    }
  });

  test("retains immutable released history and monotonically increasing fences", () => {
    const database = migratedMemoryDatabase();
    try {
      const leases = new CanonicalDatabaseLeaseService(database);
      const first = leases.acquireWriter({ ownerId: "writer:a", operation: "first" });
      expect(leases.release(first, "completed-test")).toBe(true);
      expect(leases.release(first, "completed-test")).toBe(false);
      expect(() => database.prepare(`
        UPDATE canonical_database_leases SET heartbeat_at = ? WHERE id = ?
      `).run(new Date().toISOString(), first.id)).toThrow("released canonical database lease is immutable");

      const second = leases.acquireWriter({ ownerId: "writer:b", operation: "second" });
      expect(second.fencingToken).toBe(first.fencingToken + 1);
      expect(() => database.prepare(`
        DELETE FROM canonical_database_leases WHERE id = ?
      `).run(first.id)).toThrow("canonical database lease history is retained");
    } finally {
      database.close();
    }
  });

  test("the writer helper releases authority even when the operation fails", async () => {
    const database = migratedMemoryDatabase();
    try {
      await expect(withCanonicalWriterLease(database, {
        ownerId: "writer:helper",
        operation: "failing-import",
      }, async (handle, leases) => {
        expect(leases.assertActive(handle).mode).toBe("writer");
        throw new Error("fixture failure");
      })).rejects.toThrow("fixture failure");
      expect(new CanonicalDatabaseLeaseService(database).listActive()).toEqual([]);
    } finally {
      database.close();
    }
  });
});

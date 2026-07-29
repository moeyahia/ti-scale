import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { CanonicalDatabaseLeaseService } from "../../maintenance";
import {
  OrphanedHistoricalMigrationLeaseReleaseService,
} from "../OrphanedHistoricalMigrationLeaseReleaseService";

const temporaryDirectories: string[] = [];
const ACQUIRED_AT = new Date("2026-07-21T12:00:00.000Z");
const OBSERVED_AT = new Date("2026-07-21T12:30:00.000Z");

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture(input: {
  filename?: string;
  ownerId?: string;
  operation?: string;
  mode?: "writer" | "maintenance";
  runStatus?: "running" | "failed" | "completed";
  sourceStatus?: "pending" | "importing" | "failed" | "completed";
  errorSummary?: string | null;
} = {}) {
  const database = createDatabaseConnection({ filename: input.filename ?? ":memory:" });
  migrateDatabase(database);
  const leases = new CanonicalDatabaseLeaseService(database, { clock: () => ACQUIRED_AT });
  const lease = (input.mode ?? "writer") === "writer"
    ? leases.acquireWriter({
      ownerId: input.ownerId ?? "operator:historical-migration",
      operation: input.operation ?? "historical-engagement-import",
      ttlMs: 60 * 60_000,
    })
    : leases.acquireMaintenance({
      ownerId: input.ownerId ?? "operator:historical-migration",
      operation: input.operation ?? "historical-engagement-import",
      ttlMs: 60 * 60_000,
    });
  const runStatus = input.runStatus ?? "failed";
  const completedAt = runStatus === "running" ? null : "2026-07-21T12:20:00.000Z";
  const errorSummary = input.errorSummary === undefined
    ? runStatus === "failed" ? "Importer exited after its migration metadata became terminal." : null
    : input.errorSummary;
  database.prepare(`
    INSERT INTO legacy_migration_runs (
      id, status, source_roots_json, database_path, output_directory,
      source_retention, source_retention_acknowledged_at,
      brain_projection_mode, brain_projection_acknowledged_at,
      error_summary, started_at, completed_at
    ) VALUES ('migration_overlap', ?, '["/history"]', ?, '/tmp/import',
      'verified-reference', '2026-07-21T12:00:00.000Z',
      'attack-knowledge-only', '2026-07-21T12:00:00.000Z', ?,
      '2026-07-21T12:00:00.010Z', ?)
  `).run(runStatus, database.name, errorSummary, completedAt);
  const sourceStatus = input.sourceStatus ?? "completed";
  database.prepare(`
    INSERT INTO legacy_migration_sources (
      id, migration_id, source_path, relative_path, source_type,
      source_identity, source_sha256, byte_size, modified_at, status,
      error_summary, discovered_at, completed_at, source_retention
    ) VALUES ('source_overlap', 'migration_overlap', '/history/assessment',
      'assessment', 'engagement_manifest', ?, ?, 10,
      '2026-07-21T11:00:00.000Z', ?, NULL,
      '2026-07-21T12:00:01.000Z', ?, 'verified-reference')
  `).run(
    "a".repeat(64),
    "b".repeat(64),
    sourceStatus,
    sourceStatus === "completed" || sourceStatus === "failed" ? completedAt : null,
  );
  return { database, lease };
}

function service(
  database: ReturnType<typeof createDatabaseConnection>,
  options: {
    activeMigrationProcessIds?: () => readonly number[];
    clock?: () => Date;
  } = {},
) {
  return new OrphanedHistoricalMigrationLeaseReleaseService(database, {
    clock: options.clock ?? (() => OBSERVED_AT),
    createId: () => "audit_orphaned_import_test",
    databasePath: database.name,
    activeMigrationProcessIds: options.activeMigrationProcessIds ?? (() => []),
  });
}

async function runCli(args: readonly string[]): Promise<{
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const child = Bun.spawn([
    globalThis.process.execPath,
    "run",
    "server/migration/cli.ts",
    ...args,
  ], {
    cwd: globalThis.process.cwd(),
    env: globalThis.process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, stdout, stderr };
}

describe("OrphanedHistoricalMigrationLeaseReleaseService", () => {
  test("releases one exact fenced importer lease and appends a privacy-safe audit record", () => {
    const { database, lease } = fixture();
    try {
      const recovery = service(database);
      const preview = recovery.preview({ leaseId: lease.id, fencingToken: lease.fencingToken });
      expect(preview).toMatchObject({
        lease: {
          id: lease.id,
          fencingToken: lease.fencingToken,
          ownerId: "operator:historical-migration",
          operation: "historical-engagement-import",
        },
        matchingImporterProcessIds: [],
        associatedMigrations: [{
          id: "migration_overlap",
          status: "failed",
          pendingSources: 0,
          importingSources: 0,
        }],
      });
      expect(preview.previewHash).toMatch(/^[a-f0-9]{64}$/u);

      const result = recovery.release({
        leaseId: lease.id,
        fencingToken: lease.fencingToken,
        expectedPreviewHash: preview.previewHash,
        actorId: "operator:test",
        reason: "The reviewed importer process is absent and its migration is terminal.",
        acknowledged: true,
      });
      expect(result).toMatchObject({
        status: "released",
        leaseId: lease.id,
        fencingToken: lease.fencingToken,
        releaseReason: "orphaned_historical_import_recovery",
        associatedMigrationIds: ["migration_overlap"],
        auditRecordId: "audit_orphaned_import_test",
      });
      expect(database.prepare(`
        SELECT released_at, release_reason FROM canonical_database_leases WHERE id = ?
      `).get(lease.id)).toEqual({
        released_at: OBSERVED_AT.toISOString(),
        release_reason: "orphaned_historical_import_recovery",
      });
      const audit = database.prepare(`
        SELECT action, resource_type, resource_id, details_json, record_hash
        FROM audit_records WHERE id = 'audit_orphaned_import_test'
      `).get() as {
        action: string;
        resource_type: string;
        resource_id: string;
        details_json: string;
        record_hash: string;
      };
      expect(audit).toMatchObject({
        action: "canonical_database_lease.orphaned_historical_import_released",
        resource_type: "canonical_database_lease",
        resource_id: lease.id,
      });
      expect(JSON.parse(audit.details_json)).toMatchObject({
        sourceStateVerifiedTerminal: true,
        serviceRuntimeLeaseReleasePermitted: false,
      });
      expect(audit.record_hash).toMatch(/^[a-f0-9]{64}$/u);
    } finally {
      database.close();
    }
  });

  test("rejects unknown, mismatched, service/runtime, maintenance, and unsupported writer leases", () => {
    const exact = fixture();
    try {
      const recovery = service(exact.database);
      expect(() => recovery.preview({ leaseId: "canonical_lease_unknown", fencingToken: 1 }))
        .toThrow("Unknown canonical database lease");
      expect(() => recovery.preview({ leaseId: exact.lease.id, fencingToken: exact.lease.fencingToken + 1 }))
        .toThrow("fencing token does not match");
    } finally { exact.database.close(); }

    for (const variant of [
      { ownerId: "ti-scale-service:4242", operation: "standalone-service-runtime", mode: "writer" as const },
      { ownerId: "operator:test", operation: "historical-hazard-stage", mode: "writer" as const },
      { ownerId: "operator:historical-migration", operation: "historical-engagement-import", mode: "maintenance" as const },
    ]) {
      const current = fixture(variant);
      try {
        expect(() => service(current.database).preview({
          leaseId: current.lease.id,
          fencingToken: current.lease.fencingToken,
        })).toThrow("service, runtime, maintenance, and unknown leases are never released");
        expect(current.database.prepare("SELECT released_at FROM canonical_database_leases WHERE id = ?")
          .get(current.lease.id)).toEqual({ released_at: null });
      } finally { current.database.close(); }
    }
  });

  test("fails closed for a matching importer process or nonterminal migration/source state", () => {
    const activeProcess = fixture();
    try {
      expect(() => service(activeProcess.database, {
        activeMigrationProcessIds: () => [4242],
      }).preview({
        leaseId: activeProcess.lease.id,
        fencingToken: activeProcess.lease.fencingToken,
      })).toThrow("matching historical importer process is still active (4242)");
    } finally { activeProcess.database.close(); }

    for (const variant of [
      { runStatus: "running" as const, sourceStatus: "completed" as const, message: "not terminal failed/completed" },
      { runStatus: "failed" as const, sourceStatus: "pending" as const, message: "retains pending/importing sources" },
      { runStatus: "completed" as const, sourceStatus: "importing" as const, message: "retains pending/importing sources" },
      { runStatus: "failed" as const, sourceStatus: "completed" as const, errorSummary: null, message: "no terminal error summary" },
    ]) {
      const current = fixture(variant);
      try {
        expect(() => service(current.database).preview({
          leaseId: current.lease.id,
          fencingToken: current.lease.fencingToken,
        })).toThrow(variant.message);
        expect(current.database.prepare("SELECT released_at FROM canonical_database_leases WHERE id = ?")
          .get(current.lease.id)).toEqual({ released_at: null });
      } finally { current.database.close(); }
    }
  });

  test("requires acknowledgement and rejects a stale preview hash without releasing", () => {
    const { database, lease } = fixture();
    try {
      const recovery = service(database);
      const preview = recovery.preview({ leaseId: lease.id, fencingToken: lease.fencingToken });
      expect(() => recovery.release({
        leaseId: lease.id,
        fencingToken: lease.fencingToken,
        expectedPreviewHash: preview.previewHash,
        actorId: "operator:test",
        reason: "Reviewed recovery.",
        acknowledged: false,
      })).toThrow("requires explicit acknowledgement");

      database.prepare(`
        INSERT INTO legacy_migration_runs (
          id, status, source_roots_json, database_path, output_directory,
          error_summary, started_at, completed_at
        ) VALUES ('migration_new_terminal', 'completed', '["/history"]', ?,
          '/tmp/new', NULL, '2026-07-21T12:05:00.000Z', '2026-07-21T12:25:00.000Z')
      `).run(database.name);
      expect(() => recovery.release({
        leaseId: lease.id,
        fencingToken: lease.fencingToken,
        expectedPreviewHash: preview.previewHash,
        actorId: "operator:test",
        reason: "Reviewed recovery.",
        acknowledged: true,
      })).toThrow("preview changed");
      expect(database.prepare("SELECT released_at FROM canonical_database_leases WHERE id = ?")
        .get(lease.id)).toEqual({ released_at: null });
    } finally { database.close(); }
  });

  test("rejects released, expired, or migration-unassociated leases", () => {
    const released = fixture();
    try {
      const leases = new CanonicalDatabaseLeaseService(released.database, { clock: () => OBSERVED_AT });
      expect(leases.release(released.lease, "failed")).toBe(true);
      expect(() => service(released.database).preview({
        leaseId: released.lease.id,
        fencingToken: released.lease.fencingToken,
      })).toThrow("not active and unexpired");
    } finally { released.database.close(); }

    const expired = fixture();
    try {
      expect(() => service(expired.database, {
        clock: () => new Date("2026-07-21T13:00:00.001Z"),
      }).preview({
        leaseId: expired.lease.id,
        fencingToken: expired.lease.fencingToken,
      })).toThrow("not active and unexpired");
    } finally { expired.database.close(); }

    const unassociated = fixture();
    try {
      unassociated.database.prepare("DELETE FROM legacy_migration_sources").run();
      unassociated.database.prepare("DELETE FROM legacy_migration_runs").run();
      expect(() => service(unassociated.database).preview({
        leaseId: unassociated.lease.id,
        fencingToken: unassociated.lease.fencingToken,
      })).toThrow("No migration run overlaps");
    } finally { unassociated.database.close(); }
  });

  test("CLI exposes the exact preview/release contract and refuses release without acknowledgement", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-orphan-lease-cli-"));
    temporaryDirectories.push(directory);
    const databasePath = join(directory, "canonical.sqlite");
    const database = createDatabaseConnection({ filename: databasePath });
    migrateDatabase(database);
    const lease = new CanonicalDatabaseLeaseService(database).acquireWriter({
      ownerId: "operator:historical-migration",
      operation: "historical-engagement-import",
      ttlMs: 60 * 60_000,
    });
    const now = new Date();
    database.prepare(`
      INSERT INTO legacy_migration_runs (
        id, status, source_roots_json, database_path, output_directory,
        error_summary, started_at, completed_at
      ) VALUES ('migration_cli_terminal', 'failed', '["/history"]', ?, '/tmp/cli', ?, ?, ?)
    `).run(
      databasePath,
      "CLI fixture terminated cleanly.",
      lease.acquiredAt,
      now.toISOString(),
    );
    database.close();

    const previewResult = await runCli([
      "release-orphaned-migration-lease-preview",
      "--db", databasePath,
      "--lease-id", lease.id,
      "--fencing-token", String(lease.fencingToken),
    ]);
    expect(previewResult.exitCode).toBe(0);
    expect(previewResult.stderr).toBe("");
    const preview = JSON.parse(previewResult.stdout) as { status: string; previewHash: string };
    expect(preview.status).toBe("ready_for_release");
    expect(preview.previewHash).toMatch(/^[a-f0-9]{64}$/u);

    const refused = await runCli([
      "release-orphaned-migration-lease",
      "--db", databasePath,
      "--lease-id", lease.id,
      "--fencing-token", String(lease.fencingToken),
      "--expected-preview-hash", preview.previewHash,
      "--actor", "operator:test",
      "--reason", "Reviewed CLI recovery.",
    ]);
    expect(refused.exitCode).toBe(1);
    expect(refused.stderr).toContain("--acknowledge-orphaned-migration-lease-release is required");
    const inspection = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect(inspection.prepare("SELECT released_at FROM canonical_database_leases WHERE id = ?")
        .get(lease.id)).toEqual({ released_at: null });
    } finally { inspection.close(); }
  });
});

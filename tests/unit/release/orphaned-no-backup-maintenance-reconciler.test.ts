import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createFunctionalReleaseTransactionJournal,
  readFunctionalReleaseTransactionJournal,
} from "../../../scripts/release/DurableReleaseTransaction";
import {
  OrphanedNoBackupMaintenanceLeaseReconciler,
} from "../../../scripts/release/OrphanedNoBackupMaintenanceLeaseReconciler";
import { withSharedReleaseLock } from
  "../../../scripts/release/ReleaseExecutionBoundary";
import { createDatabaseConnection } from "../../../server/db/connection";
import { DATABASE_MIGRATIONS } from "../../../server/db/migrations";
import { migrateDatabase } from "../../../server/db/migrations/runner";
import { CanonicalDatabaseLeaseService } from
  "../../../server/maintenance/CanonicalDatabaseLeaseService";
import type { Migration } from "../../../server/db/types";

const roots: string[] = [];
const children = new Set<Bun.Subprocess>();
const NOW = new Date("2026-07-24T10:00:00.000Z");
const workerPath = join(
  process.cwd(),
  "tests/unit/release/fixtures/" +
    "orphan-no-backup-reconcile-worker.ts",
);

function withoutBackupRequirement(migration: Migration): Migration {
  const {
    requiresVerifiedBackup: _requiresVerifiedBackup,
    ...noBackupMigration
  } = migration;
  return noBackupMigration;
}

interface Fixture {
  readonly root: string;
  readonly transactionRoot: string;
  readonly journalDirectory: string;
  readonly receiptPath: string;
  readonly databasePath: string;
  readonly markerPath: string;
  readonly lockPath: string;
  readonly releaseId: string;
  readonly leaseId: string;
  readonly ownerId: string;
}

function fixture(options: {
  readonly markerOnly?: boolean;
  readonly noLease?: boolean;
  readonly deploymentKind?:
    | "no_backup_preview_v1"
    | "no_backup_forward_v2";
} = {}): Fixture {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-orphan-no-backup-"));
  roots.push(root);
  const releaseId = "orphan-state-matrix";
  const transactionRoot = join(root, "release-transactions");
  const metadataRoot = join(transactionRoot, releaseId);
  const journalDirectory = join(metadataRoot, "transaction-journal");
  const receiptPath = join(metadataRoot, "receipt.json");
  mkdirSync(metadataRoot, { recursive: true, mode: 0o700 });
  writeFileSync(receiptPath, "{}\n", { mode: 0o600 });
  const deploymentKind =
    options.deploymentKind ?? "no_backup_preview_v1";
  createFunctionalReleaseTransactionJournal({
    directory: journalDirectory,
    operation: "deploy",
    releaseId,
    receiptPath,
    recoveryIntent: "restore_predeploy",
    identity: {
      deploymentKind,
      ...(deploymentKind === "no_backup_forward_v2"
        ? {
            deploymentMode: "current_service",
            releaseObserver: {
              schemaVersion: "ti-scale.release-observer.v1",
              mode: "standalone",
              scope: "ti_scale_only",
              externalServiceDependency: "none",
            },
          }
        : {}),
      backupPolicy: "none",
      predeploy: { databaseSchema: 47 },
      target: { databaseSchema: 48 },
    },
    transactionId: "orphan-state-matrix-transaction",
  });

  const databasePath = join(root, "canonical.sqlite");
  const markerPath = `${databasePath}.maintenance-lock.json`;
  const database = createDatabaseConnection({ filename: databasePath });
  const leaseId = "lease_orphan_state_matrix";
  const ownerId = `no-backup-preview:${releaseId}:999999`;
  try {
    migrateDatabase(
      database,
      DATABASE_MIGRATIONS.map(withoutBackupRequirement),
    );
    if (options.noLease) {
      // The interrupted controller may have released the lease before it
      // disappeared. Recovery must accept that exact stopped v2 boundary.
    } else if (options.markerOnly) {
      writeFileSync(
        markerPath,
        `${JSON.stringify({
          schemaVersion: "ti-scale.canonical-maintenance-marker.v1",
          id: leaseId,
          ownerId,
          operation: `no-backup-preview:${releaseId}`,
          fencingToken: 1,
          acquiredAt: NOW.toISOString(),
          expiresAt: "2026-07-24T10:01:00.000Z",
        })}\n`,
        { mode: 0o600 },
      );
    } else {
      const leases = new CanonicalDatabaseLeaseService(database, {
        clock: () => NOW,
        createId: () => leaseId,
        maintenanceMarkerPath: markerPath,
      });
      leases.acquireMaintenance({
        ownerId,
        operation: `no-backup-preview:${releaseId}`,
        ttlMs: 60_000,
      });
    }
  } finally {
    database.close();
  }
  return {
    root,
    transactionRoot,
    journalDirectory,
    receiptPath,
    databasePath,
    markerPath,
    lockPath: join(root, "release.lock"),
    releaseId,
    leaseId,
    ownerId,
  };
}

function mutateDatabase(
  value: Fixture,
  mutation: (database: ReturnType<typeof createDatabaseConnection>) => void,
): void {
  const database = createDatabaseConnection({
    filename: value.databasePath,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    mutation(database);
  } finally {
    database.close();
  }
}

async function reconcile(
  value: Fixture,
  options: ConstructorParameters<
    typeof OrphanedNoBackupMaintenanceLeaseReconciler
  >[0] = {},
): Promise<ReturnType<OrphanedNoBackupMaintenanceLeaseReconciler["reconcile"]>> {
  let handleChecks = 0;
  const result = await withSharedReleaseLock(
    () => new OrphanedNoBackupMaintenanceLeaseReconciler({
      clock: () => NOW,
      processExists: () => false,
      createAuditId: () => "audit_orphan_state_matrix",
      ...options,
    }).reconcile({
      transactionRoot: value.transactionRoot,
      journalDirectory: value.journalDirectory,
      releaseId: value.releaseId,
      databasePath: value.databasePath,
      releaseLockPath: value.lockPath,
      maintenanceMarkerPath: value.markerPath,
      stopped: {
        activeState: "inactive",
        mainPid: 0,
        controlGroup: "/system.slice/ti-scale.service",
        controlGroupProcessIds: [],
        portListening: false,
      },
      assertNoDatabaseHandles: () => {
        handleChecks += 1;
      },
    }),
    {
      path: value.lockPath,
      operation: "orphan-state-matrix",
    },
  );
  expect(handleChecks).toBe(1);
  return result;
}

afterEach(async () => {
  for (const child of children) {
    if (child.exitCode === null) child.kill("SIGKILL");
    await child.exited;
  }
  children.clear();
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("orphaned no-backup maintenance lease reconciliation", () => {
  test("accepts a stopped v2 journal with no orphaned lease", async () => {
    const value = fixture({
      deploymentKind: "no_backup_forward_v2",
      noLease: true,
    });
    await expect(reconcile(value)).resolves.toMatchObject({
      status: "not_required",
    });
  });

  test("releases an orphaned lease for a stopped v2 journal", async () => {
    const value = fixture({
      deploymentKind: "no_backup_forward_v2",
    });
    await expect(reconcile(value)).resolves.toMatchObject({
      status: "released",
      leaseId: value.leaseId,
      ownerId: value.ownerId,
    });
    expect(existsSync(value.markerPath)).toBe(false);
  });

  test("continues to accept the historical v1 recovery identity", async () => {
    const value = fixture();
    await expect(reconcile(value)).resolves.toMatchObject({
      status: "released",
      leaseId: value.leaseId,
    });
  });

  test("reconciles row+marker, row-only, marker-only, and renewal-skew states", async () => {
    for (const state of [
      "row_and_marker",
      "row_only",
      "marker_only",
      "renewal_skew",
    ] as const) {
      const value = fixture({ markerOnly: state === "marker_only" });
      if (state === "row_only") {
        rmSync(value.markerPath);
      } else if (state === "renewal_skew") {
        const marker = JSON.parse(
          readFileSync(value.markerPath, "utf8"),
        ) as Record<string, unknown>;
        writeFileSync(
          value.markerPath,
          `${JSON.stringify({
            ...marker,
            expiresAt: "2026-07-24T10:02:00.000Z",
          })}\n`,
          { mode: 0o600 },
        );
      }

      const result = await reconcile(value);
      expect(result).toMatchObject({
        status: "released",
        leaseId: value.leaseId,
        ownerId: value.ownerId,
        releaseReason:
          "orphaned_no_backup_release_controller_absent",
      });
      expect(existsSync(value.markerPath)).toBe(false);
      const journal = readFunctionalReleaseTransactionJournal(
        value.journalDirectory,
      );
      expect(journal.records.some((record) =>
        record.event === "evidence" &&
        record.detail?.kind ===
          "no_backup_maintenance_lease_reconciled.v1"
      )).toBe(true);
    }
  });

  for (const crashBoundary of [
    "after_database_commit",
    "after_marker_cleanup",
    "after_journal_evidence",
  ] as const) {
    test(`resumes idempotently after SIGKILL at ${crashBoundary}`, async () => {
      const value = fixture();
      const configurationPath = join(value.root, "worker.json");
      const boundaryPath = join(value.root, "worker-boundary.json");
      writeFileSync(
        configurationPath,
        `${JSON.stringify({
          transactionRoot: value.transactionRoot,
          journalDirectory: value.journalDirectory,
          releaseId: value.releaseId,
          databasePath: value.databasePath,
          markerPath: value.markerPath,
          lockPath: value.lockPath,
          boundaryPath,
          crashBoundary,
        })}\n`,
        { mode: 0o600 },
      );
      const child = Bun.spawn([
        process.execPath,
        workerPath,
        configurationPath,
      ], {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      });
      children.add(child);
      const deadline = performance.now() + 8_000;
      while (!existsSync(boundaryPath) && performance.now() < deadline) {
        await Bun.sleep(10);
      }
      expect(existsSync(boundaryPath)).toBe(true);
      const boundary = JSON.parse(
        readFileSync(boundaryPath, "utf8"),
      ) as { readonly processId: number; readonly phase: string };
      expect(boundary).toEqual({
        phase: crashBoundary,
        processId: child.pid,
      });
      child.kill("SIGKILL");
      expect(await child.exited).not.toBe(0);
      children.delete(child);
      expect(existsSync(value.markerPath))
        .toBe(crashBoundary === "after_database_commit");

      const result = await reconcile(value);
      expect(result).toMatchObject({
        status: "already_reconciled",
        leaseId: value.leaseId,
      });
      expect(existsSync(value.markerPath)).toBe(false);
      const journal = readFunctionalReleaseTransactionJournal(
        value.journalDirectory,
      );
      expect(journal.records.filter((record) =>
        record.event === "evidence" &&
        record.detail?.kind ===
          "no_backup_maintenance_lease_reconciled.v1"
      )).toHaveLength(1);

      const database = createDatabaseConnection({
        filename: value.databasePath,
        readonly: true,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      try {
        const row = database.prepare(`
          SELECT released_at, release_reason
          FROM canonical_database_leases WHERE id = ?
        `).get(value.leaseId) as Record<string, string>;
        expect(row.release_reason)
          .toBe("orphaned_no_backup_release_controller_absent");
        expect(database.prepare(`
          SELECT COUNT(*) AS count FROM audit_records
          WHERE action =
            'canonical_database_lease.orphaned_no_backup_maintenance_reconciled'
            AND resource_id = ?
        `).get(value.leaseId)).toEqual({ count: 1 });
      } finally {
        database.close();
      }
    });
  }

  test("refuses a live original owner before mutating its lease", async () => {
    const value = fixture();
    await expect(withSharedReleaseLock(
      () => new OrphanedNoBackupMaintenanceLeaseReconciler({
        clock: () => NOW,
        processExists: (pid) => pid === 999999,
      }).reconcile({
        transactionRoot: value.transactionRoot,
        journalDirectory: value.journalDirectory,
        releaseId: value.releaseId,
        databasePath: value.databasePath,
        releaseLockPath: value.lockPath,
        maintenanceMarkerPath: value.markerPath,
        stopped: {
          activeState: "inactive",
          mainPid: 0,
          controlGroup: "/system.slice/ti-scale.service",
          controlGroupProcessIds: [],
          portListening: false,
        },
        assertNoDatabaseHandles: () => {},
      }),
      { path: value.lockPath },
    )).rejects.toThrow("original no-backup maintenance owner process still exists");
    expect(existsSync(value.markerPath)).toBe(true);
  });

  test("refuses malformed and symbolic-link maintenance markers", async () => {
    for (const markerKind of ["malformed", "symbolic_link"] as const) {
      const value = fixture();
      rmSync(value.markerPath);
      if (markerKind === "malformed") {
        writeFileSync(value.markerPath, "{not-json\n", { mode: 0o600 });
      } else {
        const referenced = join(value.root, "referenced-marker.json");
        writeFileSync(referenced, "{}\n", { mode: 0o600 });
        Bun.spawnSync(["/usr/bin/ln", "-s", referenced, value.markerPath]);
      }
      await expect(reconcile(value)).rejects.toThrow(
        markerKind === "malformed"
          ? "maintenance marker is malformed"
          : "maintenance marker is not a safe root-owned file",
      );
    }
  });

  test("fails closed for an active service boundary or unrelated live lease", async () => {
    const value = fixture();
    await expect(withSharedReleaseLock(
      () => new OrphanedNoBackupMaintenanceLeaseReconciler({
        processExists: () => false,
      }).reconcile({
        transactionRoot: value.transactionRoot,
        journalDirectory: value.journalDirectory,
        releaseId: value.releaseId,
        databasePath: value.databasePath,
        releaseLockPath: value.lockPath,
        maintenanceMarkerPath: value.markerPath,
        stopped: {
          activeState: "active",
          mainPid: 3132,
          controlGroup: "/system.slice/ti-scale.service",
          controlGroupProcessIds: [3132],
          portListening: true,
        },
        assertNoDatabaseHandles: () => {},
      }),
      { path: value.lockPath },
    )).rejects.toThrow("requires an inactive");

    mutateDatabase(value, (database) => {
      database.prepare(`
        INSERT INTO canonical_database_leases (
          id, resource_id, mode, owner_id, operation, fencing_token,
          acquired_at, heartbeat_at, expires_at, released_at,
          release_reason
        ) VALUES (?, 'canonical_database', 'writer', ?, ?, ?, ?, ?, ?,
          NULL, NULL)
      `).run(
        "unrelated_writer",
        "ti-scale-service:3132",
        "standalone-service-runtime",
        999,
        NOW.toISOString(),
        NOW.toISOString(),
        "2026-07-24T10:05:00.000Z",
      );
    });
    await expect(reconcile(value)).rejects.toThrow(
      "Unrelated active canonical database leases",
    );
  });
});

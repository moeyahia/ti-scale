#!/usr/bin/env bun
import { readFileSync } from "node:fs";
import {
  OrphanedNoBackupMaintenanceLeaseReconciler,
} from "../../../../scripts/release/OrphanedNoBackupMaintenanceLeaseReconciler";
import { writeDurableFileAtomically } from
  "../../../../scripts/release/DurableAtomicFile";
import { withSharedReleaseLock } from
  "../../../../scripts/release/ReleaseExecutionBoundary";

interface Configuration {
  readonly transactionRoot: string;
  readonly journalDirectory: string;
  readonly releaseId: string;
  readonly databasePath: string;
  readonly markerPath: string;
  readonly lockPath: string;
  readonly boundaryPath: string;
  readonly crashBoundary:
    | "after_database_commit"
    | "after_marker_cleanup"
    | "after_journal_evidence";
}

const configurationPath = process.argv[2];
if (!configurationPath) {
  process.stderr.write("configuration path required\n");
  process.exit(64);
}
const configuration = JSON.parse(
  readFileSync(configurationPath, "utf8"),
) as Configuration;

await withSharedReleaseLock(
  () => new OrphanedNoBackupMaintenanceLeaseReconciler({
    clock: () => new Date("2026-07-24T10:00:00.000Z"),
    processExists: () => false,
    createAuditId: () => "audit_orphan_state_matrix",
    onPhase: (phase) => {
      if (phase !== configuration.crashBoundary) return;
      writeDurableFileAtomically(
        configuration.boundaryPath,
        `${JSON.stringify({
          phase,
          processId: process.pid,
        })}\n`,
        { mode: 0o600 },
      );
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
    },
  }).reconcile({
    transactionRoot: configuration.transactionRoot,
    journalDirectory: configuration.journalDirectory,
    releaseId: configuration.releaseId,
    databasePath: configuration.databasePath,
    releaseLockPath: configuration.lockPath,
    maintenanceMarkerPath: configuration.markerPath,
    stopped: {
      activeState: "inactive",
      mainPid: 0,
      controlGroup: "/system.slice/ti-scale.service",
      controlGroupProcessIds: [],
      portListening: false,
    },
    assertNoDatabaseHandles: () => {},
  }),
  {
    path: configuration.lockPath,
    operation: "orphan-state-sigkill",
  },
);

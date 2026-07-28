#!/usr/bin/env bun
import { randomBytes } from "node:crypto";
import {
  existsSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  appendFunctionalReleaseTransactionRecord,
  prepareFunctionalReleaseMutation,
  readFunctionalReleaseTransactionJournal,
} from "../../../../scripts/release/DurableReleaseTransaction";
import { acquireSharedReleaseLock } from
  "../../../../scripts/release/ReleaseExecutionBoundary";
import {
  assertReleaseServiceStartAdmitted,
  authorizeNextReleaseServiceStart,
} from "../../../../scripts/release/ReleaseServiceStartAdmission";
import { startNoBackupTargetService } from
  "../../../../scripts/release/NoBackupPreviewRelease";

const [
  journalDirectory,
  transactionRoot,
  lockPath,
  authorizationPath,
  barrierPath,
  serviceReadyPath,
  controllerReadyPath,
  phase,
] = process.argv.slice(2);

if (
  !journalDirectory || !transactionRoot || !lockPath || !authorizationPath ||
  !barrierPath || !serviceReadyPath || !controllerReadyPath ||
  (phase !== "forward" && phase !== "recovery")
) process.exit(64);

if (phase === "recovery") {
  let journal = readFunctionalReleaseTransactionJournal(journalDirectory);
  if (!journal.records.some((record) => record.event === "recovery_started")) {
    appendFunctionalReleaseTransactionRecord(journalDirectory, {
      event: "recovery_started",
      detail: { recoveryIntent: "complete_target" },
    });
    journal = readFunctionalReleaseTransactionJournal(journalDirectory);
  }
  if (!journal.records.some((record) =>
    record.event === "mutation_prepared" &&
    record.direction === "recovery" &&
    record.mutation === "service_start"
  )) {
    prepareFunctionalReleaseMutation(
      journalDirectory,
      "recovery",
      "service_start",
      { targetCommitted: true, backupPolicy: "none" },
    );
  }
}

const lock = acquireSharedReleaseLock(lockPath, `no-backup-${phase}-controller`);
let servicePid = 0;
let admissionMode = "";
try {
  const startMode = await startNoBackupTargetService({
    journalDirectory,
    authorizeServiceStart: (directory) => authorizeNextReleaseServiceStart(
      directory,
      { authorizationPath },
    ),
    startService: async () => {
      const admission = assertReleaseServiceStartAdmitted({
        transactionRoot,
        releaseLockPath: lockPath,
        authorizationPath,
        startupMutationBarrierPath: barrierPath,
        invocationId: randomBytes(16).toString("hex"),
      });
      admissionMode = admission.mode;
      const service = Bun.spawn([
        "/usr/bin/setsid",
        process.execPath,
        join(import.meta.dir, "no-backup-fake-service.ts"),
        serviceReadyPath,
      ], {
        cwd: "/",
        stdout: "ignore",
        stderr: "ignore",
      });
      servicePid = service.pid;
      const deadline = performance.now() + 3_000;
      while (!existsSync(serviceReadyPath) && performance.now() < deadline) {
        await Bun.sleep(10);
      }
      if (!existsSync(serviceReadyPath)) {
        throw new Error("Fake systemd service did not become ready");
      }
      const actualPid = Number(
        (JSON.parse(readFileSync(serviceReadyPath, "utf8")) as { pid: number }).pid,
      );
      if (actualPid !== servicePid) {
        throw new Error("Fake systemd service identity changed during start");
      }
    },
  });
  writeFileSync(controllerReadyPath, `${JSON.stringify({
    controllerPid: process.pid,
    servicePid,
    startMode,
    admissionMode,
    authorizationExists: existsSync(authorizationPath),
  })}\n`, { mode: 0o600 });
  setInterval(() => undefined, 1_000);
} catch (error) {
  lock.release();
  throw error;
}

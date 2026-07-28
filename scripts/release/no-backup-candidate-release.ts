#!/usr/bin/env bun
import {
  noBackupCandidateUsage,
  runNoBackupCandidateRelease,
} from "./NoBackupCandidateStaging";

if (import.meta.main) {
  if (
    process.argv.slice(2).length === 0 ||
    process.argv.slice(2).includes("--help") ||
    process.argv.slice(2)[0] === "help"
  ) {
    process.stdout.write(noBackupCandidateUsage());
  } else {
    runNoBackupCandidateRelease().then((result) => {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    }).catch((error) => {
      process.stderr.write(`${JSON.stringify({
        status: "failed",
        message:
          error instanceof Error
            ? error.message
            : "No-backup candidate staging failed",
        backupPolicy: "none",
        cutoverEligible: false,
        priorStateCopyCreatedByStager: false,
      })}\n`);
      process.exitCode = 1;
    });
  }
}

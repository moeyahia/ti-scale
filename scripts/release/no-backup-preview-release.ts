#!/usr/bin/env bun
import {
  noBackupPreviewUsage,
  runNoBackupPreviewRelease,
} from "./NoBackupPreviewRelease";

if (import.meta.main) {
  if (
    process.argv.slice(2).length === 0 ||
    process.argv.slice(2).includes("--help") ||
    process.argv.slice(2)[0] === "help"
  ) {
    process.stdout.write(noBackupPreviewUsage());
  } else {
    runNoBackupPreviewRelease().then((receipt) => {
      process.stdout.write(`${JSON.stringify({
        status: receipt.status,
        releaseId: receipt.releaseId,
        backupPolicy: receipt.backupPolicy,
        cutoverEligible: receipt.cutoverEligible,
        rollbackCapability: receipt.rollbackCapability,
        legacy3131UnchangedDuringOperation: true,
        legacy3131IdentityChangedBeforeRecovery:
          receipt.chillspwnIdentityChangedBeforeRecovery ?? false,
        recoveryHostBootId: receipt.recoveryHostBootId ?? null,
      }, null, 2)}\n`);
    }).catch((error) => {
      process.stderr.write(`${JSON.stringify({
        status: "failed",
        message: error instanceof Error ? error.message : "No-backup preview deployment failed",
        affectedService: "ti-scale.service",
        affectedPort: 3132,
        legacyMutationAttempted: false,
        backupPolicy: "none",
        cutoverEligible: false,
        rollbackCapability: "none_after_schema_commit",
      })}\n`);
      process.exitCode = 1;
    });
  }
}

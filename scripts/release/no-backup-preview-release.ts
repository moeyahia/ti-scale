#!/usr/bin/env bun
import {
  isStandaloneNoBackupForwardReceipt,
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
      const standalone = isStandaloneNoBackupForwardReceipt(receipt);
      process.stdout.write(`${JSON.stringify({
        status: receipt.status,
        releaseId: receipt.releaseId,
        backupPolicy: receipt.backupPolicy,
        rollbackCapability: receipt.rollbackCapability,
        deploymentMode: standalone
          ? receipt.deploymentMode
          : "historical_preview_recovery",
        observerMode: standalone
          ? receipt.releaseObserver?.mode
          : "historical_compatibility",
        externalServiceDependency: standalone
          ? receipt.releaseObserver?.externalServiceDependency
          : "historical_recovery_dependency",
        recoveryHostBootId: receipt.recoveryHostBootId ?? null,
      }, null, 2)}\n`);
    }).catch((error) => {
      process.stderr.write(`${JSON.stringify({
        status: "failed",
        message: error instanceof Error
          ? error.message
          : "No-backup forward deployment failed",
        affectedService: "ti-scale.service",
        affectedPort: 3132,
        deploymentMode: "current_service",
        externalServiceMutationAttempted: false,
        backupPolicy: "none",
        rollbackCapability: "none_after_schema_commit",
      })}\n`);
      process.exitCode = 1;
    });
  }
}

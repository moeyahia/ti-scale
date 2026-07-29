import { describe, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { FunctionalReleaseBackupPruneService } from "../../../scripts/release/functional-release-backup-prune";
import {
  reconcileStrandedRollbackApplicationSwap,
  reconcileFunctionalReleaseJournal,
} from "../../../scripts/release/functional-release";
import { RollbackTargetMaintenanceService } from "../../../scripts/release/rollback-target-maintenance";
import { ServerReleasePruneService } from "../../../scripts/release/server-release-prune";
import {
  restoreVaultArchiveAtomically,
} from "../../../scripts/release/VaultReleasePrimitives";
import {
  NO_BACKUP_PAYLOAD_ROOTS,
} from "../../../scripts/release/NoBackupPreviewRelease";
import { writePortableZip } from "../../../server/vault/PortableZip";

function sentinelRoot(): string {
  return join(
    tmpdir(),
    `ti-scale-no-backup-public-surface-${process.pid}-${randomUUID()}`,
  );
}

describe("operator no-backup public surface", () => {
  test("retired restore, archive, and maintenance entry points reject before touching paths", async () => {
    const sentinel = sentinelRoot();
    expect(existsSync(sentinel)).toBe(false);

    await expect(restoreVaultArchiveAtomically({
      archivePath: join(sentinel, "vault.tar.gz"),
      vaultRoot: join(sentinel, "vault"),
      expectedFingerprint: "0".repeat(64),
      swapId: "disabled",
    })).rejects.toThrow(
      "Vault archive restore is disabled by operator no-backup policy",
    );
    await expect(reconcileFunctionalReleaseJournal(
      join(sentinel, "transaction-journal"),
      "disabled",
      false,
    )).rejects.toThrow(
      "Backup-capable functional release reconciliation is disabled by operator no-backup policy",
    );
    expect(() => reconcileStrandedRollbackApplicationSwap({
      applicationPath: join(sentinel, "application"),
      expected: {
        kind: "symlink",
        target: join(sentinel, "target"),
        device: "unused",
        inode: "unused",
      },
      candidatePaths: [join(sentinel, "archive")],
      swapName: "disabled",
      serverReleaseRoot: join(sentinel, "releases"),
    })).toThrow(
      "Rollback application archive reconciliation is disabled by operator no-backup policy",
    );
    await expect(writePortableZip(
      [{ name: "note.md", data: "never archived" }],
      join(sentinel, "portable.zip"),
    )).rejects.toThrow(
      "Portable Vault ZIP creation is disabled by operator no-backup policy",
    );
    expect(() => new FunctionalReleaseBackupPruneService({
      backupRoot: join(sentinel, "backup-prune"),
    })).toThrow(
      "Legacy functional-release backup maintenance is disabled by operator no-backup policy",
    );
    expect(() => new RollbackTargetMaintenanceService({
      backupRoot: join(sentinel, "rollback-maintenance"),
    })).toThrow(
      "Rollback-target maintenance is disabled by operator no-backup policy",
    );
    expect(() => new ServerReleasePruneService({
      backupRoot: join(sentinel, "server-prune"),
    })).toThrow(
      "Backup-coupled server release pruning is disabled by operator no-backup policy",
    );

    expect(existsSync(sentinel)).toBe(false);
  });

  test("production composition exposes no portable-archive or backup-root override seam", () => {
    const root = resolve(import.meta.dir, "../../..");
    const bridge = readFileSync(
      join(root, "server/vault/ObsidianVaultBridge.ts"),
      "utf8",
    );
    const router = readFileSync(
      join(root, "server/memory/SecondBrainRouter.ts"),
      "utf8",
    );
    const candidate = readFileSync(
      join(root, "scripts/release/NoBackupCandidateStaging.ts"),
      "utf8",
    );

    expect(bridge).not.toContain("allowPortableArchivesInIsolatedTests");
    expect(router).not.toContain(
      "allowPortableVaultArchivesInIsolatedTests",
    );
    expect(candidate).not.toContain("backupPayloadRoots");
    expect(NO_BACKUP_PAYLOAD_ROOTS).toEqual([
      "/var/backups/ti-scale",
      "/var/lib/ti-scale/backups",
      "/var/lib/ti-scale/data/backups",
      "/var/lib/ti-scale/data/migration-backups",
      "/var/lib/ti-scale/hotfix-backups",
      "/var/lib/ti-scale/imports/historical-sqlite-snapshots",
      "/var/lib/ti-scale/rehearsals",
      "/var/lib/ti-scale/release-rehearsal",
      "/var/lib/ti-scale/staging",
    ]);
  });
});

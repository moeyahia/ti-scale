import { expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FunctionalReleaseBackupPruneService } from "../../../scripts/release/functional-release-backup-prune";

test("legacy backup-bundle maintenance rejects before resolving or creating paths", () => {
  const sentinel = join(
    tmpdir(),
    `ti-scale-disabled-backup-prune-${process.pid}`,
  );
  expect(existsSync(sentinel)).toBe(false);

  expect(() => new FunctionalReleaseBackupPruneService({
    backupRoot: join(sentinel, "backups"),
    serverReleaseRoot: join(sentinel, "releases"),
    applicationPath: join(sentinel, "application"),
    currentPointerPath: join(sentinel, "current"),
    staticPointerPath: join(sentinel, "static.json"),
    receiptRoot: join(sentinel, "receipts"),
    quarantineRoot: join(sentinel, "quarantine"),
  })).toThrow(
    "Legacy functional-release backup maintenance is disabled by operator no-backup policy",
  );

  expect(existsSync(sentinel)).toBe(false);
});

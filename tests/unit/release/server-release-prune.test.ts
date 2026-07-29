import { expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ServerReleasePruneService } from "../../../scripts/release/server-release-prune";

test("legacy backup-coupled release pruning rejects before resolving or creating paths", () => {
  const sentinel = join(
    tmpdir(),
    `ti-scale-disabled-server-prune-${process.pid}`,
  );
  expect(existsSync(sentinel)).toBe(false);

  expect(() => new ServerReleasePruneService({
    serverReleaseRoot: join(sentinel, "releases"),
    backupRoot: join(sentinel, "backups"),
    applicationPath: join(sentinel, "application"),
    currentPointerPath: join(sentinel, "current"),
    pruneReceiptRoot: join(sentinel, "receipts"),
  })).toThrow(
    "Backup-coupled server release pruning is disabled by operator no-backup policy",
  );

  expect(existsSync(sentinel)).toBe(false);
});

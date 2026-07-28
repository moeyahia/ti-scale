import { expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RollbackTargetMaintenanceService } from "../rollback-target-maintenance";

test("legacy rollback-target maintenance rejects before resolving or creating paths", () => {
  const sentinel = join(
    tmpdir(),
    `ti-scale-disabled-rollback-maintenance-${process.pid}`,
  );
  expect(existsSync(sentinel)).toBe(false);

  expect(() => new RollbackTargetMaintenanceService({
    serverReleaseRoot: join(sentinel, "releases"),
    staticReleaseRoot: join(sentinel, "static"),
    backupRoot: join(sentinel, "backups"),
    applicationPath: join(sentinel, "application"),
    auditReceiptRoot: join(sentinel, "receipts"),
  })).toThrow(
    "Rollback-target maintenance is disabled by operator no-backup policy",
  );

  expect(existsSync(sentinel)).toBe(false);
});

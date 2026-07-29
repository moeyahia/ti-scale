import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  acquireSharedReleaseLock,
  ReleaseLockContentionError,
} from "../../../scripts/release/ReleaseExecutionBoundary";

const roots: string[] = [];
const lockHolderWorker = join(
  process.cwd(),
  "tests/unit/release/fixtures/bounded-release-lock-holder-worker.ts",
);

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("shared release execution lock", () => {
  test("the parent descriptor retains the inherited flock after the bounded child exits", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-release-lock-"));
    roots.push(root);
    const path = join(root, "release.lock");
    const first = acquireSharedReleaseLock(path, "bounded-owner");
    try {
      expect(JSON.parse(readFileSync(path, "utf8"))).toMatchObject({
        schemaVersion: "ti-scale.release-lock-owner.v1",
        operation: "bounded-owner",
      });
      expect(() => acquireSharedReleaseLock(path, "contender"))
        .toThrow(ReleaseLockContentionError);
    } finally { first.release(); }

    const afterRelease = acquireSharedReleaseLock(path, "after-release");
    afterRelease.release();
  });

  test("a SIGKILLed parent cannot release flock while async or sync bounded mutation children survive", async () => {
    for (const mode of ["async", "sync"] as const) {
      const root = mkdtempSync(join(tmpdir(), `ti-scale-release-orphan-${mode}-`));
      roots.push(root);
      const lockPath = join(root, "release.lock");
      const childReadyPath = join(root, "child-ready");
      const childCompletedPath = join(root, "child-completed");
      const parentReadyPath = join(root, "parent-ready");
      const parent = Bun.spawn([
        process.execPath,
        lockHolderWorker,
        mode,
        lockPath,
        childReadyPath,
        childCompletedPath,
        parentReadyPath,
      ], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
      try {
        const readyDeadline = performance.now() + 3_000;
        while (
          (!existsSync(parentReadyPath) || !existsSync(childReadyPath)) &&
          performance.now() < readyDeadline
        ) await Bun.sleep(10);
        expect(existsSync(parentReadyPath)).toBe(true);
        expect(existsSync(childReadyPath)).toBe(true);
        expect(existsSync(childCompletedPath)).toBe(false);

        parent.kill("SIGKILL");
        await parent.exited;
        expect(() => acquireSharedReleaseLock(lockPath, `premature-contender-${mode}`))
          .toThrow(ReleaseLockContentionError);

        const completionDeadline = performance.now() + 4_000;
        while (!existsSync(childCompletedPath) && performance.now() < completionDeadline) {
          await Bun.sleep(20);
        }
        expect(readFileSync(childCompletedPath, "utf8")).toBe("completed\n");

        let afterChild: ReturnType<typeof acquireSharedReleaseLock> | undefined;
        const releaseDeadline = performance.now() + 2_000;
        while (!afterChild && performance.now() < releaseDeadline) {
          try { afterChild = acquireSharedReleaseLock(lockPath, `after-child-${mode}`); }
          catch (error) {
            if (!(error instanceof ReleaseLockContentionError)) throw error;
            await Bun.sleep(20);
          }
        }
        expect(afterChild).toBeDefined();
        afterChild?.release();
      } finally {
        try { parent.kill("SIGKILL"); } catch { /* already terminal */ }
        try { await parent.exited; } catch { /* already terminal */ }
      }
    }
  });
});

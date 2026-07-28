import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ReleaseCommandExitError,
  ReleaseCommandOutputLimitError,
  ReleaseCommandTimeoutError,
  runBoundedReleaseCommand,
  runBoundedReleaseCommandSync,
} from "../../../scripts/release/BoundedReleaseCommand";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-bounded-release-command-"));
  temporaryDirectories.push(directory);
  return directory;
}

function processIsRunning(pid: number): boolean {
  try {
    const fields = readFileSync(`/proc/${String(pid)}/stat`, "utf8").split(" ");
    return fields[2] !== "Z";
  } catch {
    return false;
  }
}

async function waitForProcessTreeExit(pids: readonly number[]): Promise<void> {
  const deadline = performance.now() + 2_000;
  while (performance.now() < deadline) {
    if (pids.every((pid) => !processIsRunning(pid))) return;
    await Bun.sleep(20);
  }
}

describe("runBoundedReleaseCommand", () => {
  test("runs one absolute executable without shell interpretation", async () => {
    const result = await runBoundedReleaseCommand(
      ["/usr/bin/printf", "%s", "$(touch /tmp/this-must-remain-literal)"],
      { timeoutMs: 1_000 },
    );

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("$(touch /tmp/this-must-remain-literal)");
    expect(result.stderr).toBe("");
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  test("rejects relative executables and invalid bounds before dispatch", async () => {
    await expect(runBoundedReleaseCommand(["printf", "unsafe"], { timeoutMs: 1_000 }))
      .rejects.toThrow("absolute executable");
    await expect(runBoundedReleaseCommand(["/usr/bin/true"], { timeoutMs: 0 }))
      .rejects.toThrow("timeout must be a positive safe integer");
    await expect(runBoundedReleaseCommand(["/usr/bin/true"], { timeoutMs: 1_000, outputLimitBytes: -1 }))
      .rejects.toThrow("output limit must be a positive safe integer");
  });

  test("returns a bounded diagnostic for deterministic command failure", async () => {
    let failure: unknown;
    try {
      await runBoundedReleaseCommand(
        ["/usr/bin/bash", "-c", "printf 'maintenance failed' >&2; exit 23"],
        { timeoutMs: 1_000 },
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ReleaseCommandExitError);
    expect((failure as ReleaseCommandExitError).exitCode).toBe(23);
    expect((failure as ReleaseCommandExitError).diagnostic).toBe("maintenance failed");
  });

  test("hard timeout kills and reaps the complete child process group", async () => {
    const directory = temporaryDirectory();
    const leaderPath = join(directory, "leader.pid");
    const childPath = join(directory, "child.pid");
    let failure: unknown;
    try {
      await runBoundedReleaseCommand(
        [
          "/usr/bin/bash",
          "-c",
          "printf '%s' \"$$\" > \"$1\"; trap '' TERM; sleep 120 & printf '%s' \"$!\" > \"$2\"; wait",
          "bounded-release-test",
          leaderPath,
          childPath,
        ],
        { timeoutMs: 300, terminationGraceMs: 50 },
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ReleaseCommandTimeoutError);
    expect(existsSync(leaderPath)).toBe(true);
    expect(existsSync(childPath)).toBe(true);
    const pids = [Number(readFileSync(leaderPath, "utf8")), Number(readFileSync(childPath, "utf8"))];
    await waitForProcessTreeExit(pids);
    expect(pids.every((pid) => !processIsRunning(pid))).toBe(true);
  });

  test("deadline still owns a background descendant after the group leader exits", async () => {
    const directory = temporaryDirectory();
    const childPath = join(directory, "orphan-candidate.pid");
    let failure: unknown;
    try {
      await runBoundedReleaseCommand(
        [
          "/usr/bin/bash",
          "-c",
          "trap '' TERM; sleep 120 & printf '%s' \"$!\" > \"$1\"",
          "bounded-release-background-test",
          childPath,
        ],
        { timeoutMs: 300, terminationGraceMs: 50 },
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ReleaseCommandTimeoutError);
    expect(existsSync(childPath)).toBe(true);
    const childPid = Number(readFileSync(childPath, "utf8"));
    await waitForProcessTreeExit([childPid]);
    expect(processIsRunning(childPid)).toBe(false);
  });

  test("external abort preserves the exact reason and terminates the process group", async () => {
    const controller = new AbortController();
    const reason = new Error("operator release cancellation");
    setTimeout(() => controller.abort(reason), 50);

    let failure: unknown;
    try {
      await runBoundedReleaseCommand(
        ["/usr/bin/bash", "-c", "trap '' TERM; sleep 120 & wait"],
        { timeoutMs: 5_000, terminationGraceMs: 50, signal: controller.signal },
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBe(reason);
  });

  test("output overflow terminates the command instead of accumulating unbounded memory", async () => {
    let failure: unknown;
    try {
      await runBoundedReleaseCommand(
        ["/usr/bin/bash", "-c", "while :; do printf '0123456789'; done"],
        { timeoutMs: 5_000, terminationGraceMs: 50, outputLimitBytes: 1_024 },
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ReleaseCommandOutputLimitError);
    expect((failure as ReleaseCommandOutputLimitError).outputLimitBytes).toBe(1_024);
  });
});

describe("runBoundedReleaseCommandSync", () => {
  test("forwards literal arguments and returns bounded file-backed output", () => {
    const result = runBoundedReleaseCommandSync(
      ["/usr/bin/printf", "%s", "$(touch /tmp/this-sync-value-must-remain-literal)"],
      { timeoutMs: 1_000 },
    );

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("$(touch /tmp/this-sync-value-must-remain-literal)");
    expect(result.stderr).toBe("");
  });

  test("GNU deadline TERM/KILL escalation removes the complete descendant group", async () => {
    const directory = temporaryDirectory();
    const leaderPath = join(directory, "sync-leader.pid");
    const childPath = join(directory, "sync-child.pid");
    let failure: unknown;
    try {
      runBoundedReleaseCommandSync(
        [
          "/usr/bin/bash",
          "-c",
          "printf '%s' \"$$\" > \"$1\"; trap '' TERM; sleep 120 & printf '%s' \"$!\" > \"$2\"; wait",
          "bounded-sync-release-test",
          leaderPath,
          childPath,
        ],
        { timeoutMs: 300, terminationGraceMs: 50 },
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ReleaseCommandTimeoutError);
    const pids = [Number(readFileSync(leaderPath, "utf8")), Number(readFileSync(childPath, "utf8"))];
    await waitForProcessTreeExit(pids);
    expect(pids.every((pid) => !processIsRunning(pid))).toBe(true);
  });

  test("file-backed stream capture stops noisy commands at the exact output bound", () => {
    let failure: unknown;
    try {
      runBoundedReleaseCommandSync(
        ["/usr/bin/bash", "-c", "while :; do printf '0123456789'; done"],
        { timeoutMs: 5_000, terminationGraceMs: 50, outputLimitBytes: 1_024 },
      );
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ReleaseCommandOutputLimitError);
    expect((failure as ReleaseCommandOutputLimitError).outputLimitBytes).toBe(1_024);
  });

  test("can return an explicitly permitted nonzero status without weakening the default", () => {
    const result = runBoundedReleaseCommandSync(
      ["/usr/bin/bash", "-c", "printf 'not-found' >&2; exit 7"],
      { timeoutMs: 1_000, allowNonZeroExit: true },
    );
    expect(result.exitCode).toBe(7);
    expect(result.stderr).toBe("not-found");
    expect(() => runBoundedReleaseCommandSync(
      ["/usr/bin/bash", "-c", "exit 7"],
      { timeoutMs: 1_000 },
    )).toThrow(ReleaseCommandExitError);
  });
});

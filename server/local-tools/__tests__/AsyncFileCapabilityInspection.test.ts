import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspectLinuxFileCapabilities } from "../AsyncFileCapabilityInspection";

function fixture(source: string): Readonly<{ root: string; helper: string }> {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-async-getcap-"));
  const helper = join(root, "getcap");
  writeFileSync(helper, source, { encoding: "utf8", mode: 0o555 });
  chmodSync(helper, 0o555);
  return { root, helper };
}

async function waitForProcessExit(pid: number): Promise<boolean> {
  const deadline = Date.now() + 500;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return false;
}

describe("inspectLinuxFileCapabilities", () => {
  test("returns an immutable no-capability receipt for empty successful output", async () => {
    const { root, helper } = fixture("#!/bin/sh\nexit 0\n");
    try {
      const result = await inspectLinuxFileCapabilities("/reviewed/tool", { helperPath: helper });
      expect(result).toEqual({
        state: "none",
        outputSha256: createHash("sha256").update("").digest("hex"),
      });
      expect(Object.isFrozen(result)).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("classifies non-empty successful output as capabilities present", async () => {
    const output = "/reviewed/tool cap_net_raw=ep\n";
    const { root, helper } = fixture(`#!/bin/sh\nprintf '${output}'\n`);
    try {
      expect(await inspectLinuxFileCapabilities("/reviewed/tool", { helperPath: helper }))
        .toEqual({
          state: "present",
          outputSha256: createHash("sha256").update(output).digest("hex"),
        });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("fails closed on a helper error and on bounded-output overflow", async () => {
    const failed = fixture("#!/bin/sh\nprintf 'denied' >&2\nexit 1\n");
    const overflow = fixture("#!/bin/sh\nhead -c 8192 /dev/zero\n");
    try {
      expect(await inspectLinuxFileCapabilities("/reviewed/tool", {
        helperPath: failed.helper,
      })).toEqual({ state: "unknown", outputSha256: null });
      expect(await inspectLinuxFileCapabilities("/reviewed/tool", {
        helperPath: overflow.helper,
        maximumOutputBytes: 32,
      })).toEqual({ state: "unknown", outputSha256: null });
    } finally {
      rmSync(failed.root, { recursive: true, force: true });
      rmSync(overflow.root, { recursive: true, force: true });
    }
  });

  test("timeout settles promptly and reaps the detached helper process group", async () => {
    const { root, helper } = fixture("#!/bin/sh\nprintf '%s' \"$$\" > \"$3\"\nsleep 20\n");
    const pidFile = join(root, "pid");
    try {
      const started = performance.now();
      const result = await inspectLinuxFileCapabilities(pidFile, {
        helperPath: helper,
        timeoutMs: 40,
      });
      expect(performance.now() - started).toBeLessThan(500);
      expect(result).toEqual({ state: "unknown", outputSha256: null });
      const pid = Number(readFileSync(pidFile, "utf8"));
      expect(await waitForProcessExit(pid)).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("AbortSignal settles promptly and reaps the detached helper process group", async () => {
    const { root, helper } = fixture("#!/bin/sh\nprintf '%s' \"$$\" > \"$3\"\nsleep 20\n");
    const pidFile = join(root, "pid");
    const controller = new AbortController();
    try {
      const pending = inspectLinuxFileCapabilities(pidFile, {
        helperPath: helper,
        timeoutMs: 2_000,
        signal: controller.signal,
      });
      const pidDeadline = Date.now() + 500;
      while (Date.now() < pidDeadline) {
        try { readFileSync(pidFile, "utf8"); break; }
        catch { await new Promise((resolve) => setTimeout(resolve, 10)); }
      }
      const started = performance.now();
      controller.abort("shutdown");
      expect(await pending).toEqual({ state: "unknown", outputSha256: null });
      expect(performance.now() - started).toBeLessThan(500);
      const pid = Number(readFileSync(pidFile, "utf8"));
      expect(await waitForProcessExit(pid)).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("live readiness and dispatch paths cannot regress to synchronous getcap", () => {
    const sources = {
      coordinator: readFileSync(new URL(
        "../../app/LocalGuidedToolActivationCoordinator.ts",
        import.meta.url,
      ), "utf8"),
      bubblewrap: readFileSync(new URL("../BubblewrapToolProbeEnvironment.ts", import.meta.url), "utf8"),
      localProcess: readFileSync(new URL("../LocalProcessToolExecution.ts", import.meta.url), "utf8"),
      windows: readFileSync(new URL(
        "../../windows-identity-tools/DirectWindowsIdentityProcessAdapter.ts",
        import.meta.url,
      ), "utf8"),
    };
    expect(sources.coordinator).toContain(".inspectAllAsync(configuration.manifest, signal)");
    expect(sources.localProcess).toContain(".inspectAsync(this.options.manifest, invocation.toolId, signal)");
    for (const source of [sources.bubblewrap, sources.localProcess, sources.windows]) {
      expect(source).not.toContain("spawnSync");
      expect(source).not.toMatch(/\bfrom\s+["']bun:ffi["']/u);
      expect(source).toContain("inspectLinuxFileCapabilities");
    }
  });
});

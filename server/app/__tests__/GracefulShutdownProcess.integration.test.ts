import { describe, expect, test } from "bun:test";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const FIXTURE = fileURLToPath(new URL(
  "./fixtures/GracefulShutdownActiveRefreshProcess.ts",
  import.meta.url,
));
const DEADLINE_FIXTURE = fileURLToPath(new URL(
  "./fixtures/GracefulShutdownDeadlineProcess.ts",
  import.meta.url,
));

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not reserve fixture port");
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
  return address.port;
}

function capture(child: ChildProcess): { stdout: () => string; stderr: () => string } {
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString("utf8"); });
  child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString("utf8"); });
  return { stdout: () => stdout, stderr: () => stderr };
}

async function waitForOutput(
  child: ChildProcess,
  read: () => string,
  expected: string,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (read().includes(expected)) return;
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`Shutdown fixture exited before ${expected}`);
    }
    await delay(20);
  }
  throw new Error(`Shutdown fixture did not emit ${expected}`);
}

async function waitForExit(child: ChildProcess, timeoutMs: number): Promise<number | null> {
  if (child.exitCode !== null || child.signalCode !== null) return child.exitCode;
  return await new Promise<number | null>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Shutdown fixture did not exit in time")), timeoutMs);
    child.once("exit", (code) => {
      clearTimeout(timeout);
      resolve(code);
    });
  });
}

describe("standalone graceful shutdown process boundary", () => {
  test("SIGTERM drains the real active Bubblewrap readiness stack and exits before the service-manager bound", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-shutdown-process-"));
    const executable = join(directory, "slow-reviewed-probe");
    const finalizer = join(directory, "finalizer.log");
    const source = "#!/bin/sh\nprintf 'active readiness probe\\n'\nsleep 20\n";
    writeFileSync(executable, source, { encoding: "utf8", mode: 0o555 });
    chmodSync(executable, 0o555);
    const sha256 = createHash("sha256").update(source).digest("hex");
    const port = await reservePort();
    const child = spawn(process.execPath, ["run", FIXTURE], {
      cwd: PROJECT_ROOT,
      env: {
        ...process.env,
        TI_SCALE_SHUTDOWN_FIXTURE_PORT: String(port),
        TI_SCALE_SHUTDOWN_FIXTURE_EXECUTABLE: executable,
        TI_SCALE_SHUTDOWN_FIXTURE_EXECUTABLE_SHA256: sha256,
        TI_SCALE_SHUTDOWN_FIXTURE_FINALIZER_PATH: finalizer,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const output = capture(child);

    try {
      await waitForOutput(child, output.stdout, "ACTIVE_REFRESH", 5_000);
      const health = await fetch(`http://127.0.0.1:${port}`, {
        signal: AbortSignal.timeout(1_000),
      });
      expect(health.status).toBe(200);

      const started = performance.now();
      expect(child.kill("SIGTERM")).toBe(true);
      await delay(25);
      // A second signal must not run the finalizer twice or replace the first
      // signal recorded by the one-shot coordinator.
      expect(child.kill("SIGTERM")).toBe(true);

      let admissionClosed = false;
      const admissionDeadline = Date.now() + 1_000;
      while (Date.now() < admissionDeadline) {
        try {
          await fetch(`http://127.0.0.1:${port}`, {
            signal: AbortSignal.timeout(100),
          });
        } catch {
          admissionClosed = true;
          break;
        }
        await delay(20);
      }
      expect(admissionClosed).toBe(true);

      const exitCode = await waitForExit(child, 5_000);
      const elapsed = performance.now() - started;
      expect(exitCode).toBe(0);
      expect(elapsed).toBeLessThan(4_500);
      expect(output.stdout()).toContain(
        'SHUTDOWN_REPORT {"outcome":"completed","pending":[],"failed":[]}',
      );
      expect(output.stderr()).toBe("");
      expect(readFileSync(finalizer, "utf8")).toBe("finalized\n");
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
        await waitForExit(child, 2_000).catch(() => undefined);
      }
      rmSync(directory, { recursive: true, force: true });
    }
  }, 10_000);

  test("the referenced hard deadline reports and finalizes when no other handle remains", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-shutdown-deadline-"));
    const finalizer = join(directory, "finalizer.log");
    const port = await reservePort();
    const child = spawn(process.execPath, ["run", DEADLINE_FIXTURE], {
      cwd: PROJECT_ROOT,
      env: {
        ...process.env,
        TI_SCALE_SHUTDOWN_FIXTURE_PORT: String(port),
        TI_SCALE_SHUTDOWN_FIXTURE_FINALIZER_PATH: finalizer,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const output = capture(child);

    try {
      await waitForOutput(child, output.stdout, "DEADLINE_READY", 5_000);
      expect(child.kill("SIGTERM")).toBe(true);
      expect(await waitForExit(child, 2_000)).toBe(1);
      expect(output.stdout()).toContain(
        'DEADLINE_REPORT {"outcome":"timed_out","pending":["promise-without-os-handle","http-server"],"failed":[]}',
      );
      expect(output.stderr()).toBe("");
      expect(readFileSync(finalizer, "utf8")).toBe("finalized\n");
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
        await waitForExit(child, 2_000).catch(() => undefined);
      }
      rmSync(directory, { recursive: true, force: true });
    }
  }, 8_000);
});

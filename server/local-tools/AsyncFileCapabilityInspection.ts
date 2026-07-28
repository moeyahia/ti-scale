import { createHash } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { lstat } from "node:fs/promises";

export interface AsyncFileCapabilityInspection {
  readonly state: "none" | "present" | "unknown";
  readonly outputSha256: string | null;
}

export interface AsyncFileCapabilityInspectionOptions {
  readonly helperPath?: string;
  readonly timeoutMs?: number;
  readonly maximumOutputBytes?: number;
  readonly signal?: AbortSignal;
}

const FIXED_ENVIRONMENT = Object.freeze({
  HOME: "/nonexistent",
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
  PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
});

function unknown(): AsyncFileCapabilityInspection {
  return Object.freeze({ state: "unknown", outputSha256: null });
}

/**
 * Inspects Linux file capabilities without blocking the JavaScript event loop.
 * Readiness waves call this helper repeatedly; using spawnSync here can prevent
 * SIGTERM and even the shutdown deadline timer from being observed.
 */
export async function inspectLinuxFileCapabilities(
  path: string,
  options: AsyncFileCapabilityInspectionOptions = {},
): Promise<AsyncFileCapabilityInspection> {
  const helperPath = options.helperPath ?? "/usr/sbin/getcap";
  const timeoutMs = options.timeoutMs ?? 1_000;
  const maximumOutputBytes = options.maximumOutputBytes ?? 4_096;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 5_000
    || !Number.isSafeInteger(maximumOutputBytes)
    || maximumOutputBytes < 1
    || maximumOutputBytes > 64 * 1_024) {
    return unknown();
  }
  try {
    const metadata = await lstat(helperPath, { bigint: true });
    const mode = Number(metadata.mode & 0o7777n);
    if (metadata.isSymbolicLink()
      || !metadata.isFile()
      || Number(metadata.uid) !== 0
      || (mode & 0o022) !== 0
      || (mode & 0o7000) !== 0
      || (mode & 0o111) === 0) {
      return unknown();
    }
  } catch {
    return unknown();
  }
  if (options.signal?.aborted) return unknown();

  return await new Promise<AsyncFileCapabilityInspection>((resolve) => {
    let output = Buffer.alloc(0);
    let stderrBytes = 0;
    let exceeded = false;
    let timedOut = false;
    let settled = false;
    let child: ChildProcess;
    try {
      child = spawn(helperPath, ["-n", "--", path], {
        detached: process.platform !== "win32",
        env: FIXED_ENVIRONMENT,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch {
      resolve(unknown());
      return;
    }

    const finish = (result: AsyncFileCapabilityInspection): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abort);
      resolve(Object.freeze(result));
    };
    const terminate = (): void => {
      if (child.pid && process.platform !== "win32") {
        try {
          process.kill(-child.pid, "SIGKILL");
          return;
        } catch {
          // The group can race process setup; the tracked child remains the
          // mandatory fallback and must still be reaped through close.
        }
      }
      try { child.kill("SIGKILL"); }
      catch { /* Process already reached a terminal state. */ }
    };
    const abort = (): void => {
      terminate();
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      terminate();
    }, timeoutMs);
    options.signal?.addEventListener("abort", abort, { once: true });

    child.stdout?.on("data", (chunk: Buffer) => {
      if (exceeded) return;
      if (output.byteLength + chunk.byteLength > maximumOutputBytes) {
        exceeded = true;
        terminate();
        return;
      }
      output = Buffer.concat([output, chunk]);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.byteLength;
      if (stderrBytes > maximumOutputBytes) terminate();
    });
    child.once("error", () => finish(unknown()));
    child.once("close", (code, signal) => {
      if (timedOut || exceeded || stderrBytes > 0 || code !== 0 || signal !== null) {
        finish(unknown());
        return;
      }
      finish({
        state: output.toString("utf8").trim() ? "present" : "none",
        outputSha256: createHash("sha256").update(output).digest("hex"),
      });
    });
    if (options.signal?.aborted) abort();
  });
}

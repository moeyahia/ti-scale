import {
  closeSync,
  constants,
  ftruncateSync,
  fsyncSync,
  mkdirSync,
  openSync,
  writeSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname } from "node:path";
import {
  ReleaseCommandExitError,
  runBoundedReleaseCommandSync,
} from "./BoundedReleaseCommand";
import { registerActiveReleaseLockDescriptor } from "./ReleaseLockContext";

export const SHARED_RELEASE_LOCK_PATH = "/run/ti-scale-release.lock";
const RELEASE_LOCK_TIMEOUT_MS = 5_000;
const RELEASE_LOCK_OUTPUT_LIMIT_BYTES = 64 * 1_024;

export class ReleaseLockContentionError extends Error {
  constructor(readonly lockPath: string) {
    super(`Another Ti-Scale release operation holds ${lockPath}; concurrent mutation is refused`);
    this.name = "ReleaseLockContentionError";
  }
}

export interface SharedReleaseLockHandle {
  readonly path: string;
  readonly descriptor: number;
  release(): void;
}

/**
 * Uses Linux flock on an inherited open-file description. The short-lived
 * flock child acquires the lock on descriptor 0; the parent descriptor refers
 * to that same open-file description and therefore retains the lock until it
 * closes or the process crashes. Stale metadata never grants ownership.
 */
export function acquireSharedReleaseLock(
  path = SHARED_RELEASE_LOCK_PATH,
  operation = "functional-release",
): SharedReleaseLockHandle {
  mkdirSync(dirname(path), { recursive: true, mode: 0o755 });
  const descriptor = openSync(path, constants.O_CREAT | constants.O_RDWR, 0o600);
  try {
    runBoundedReleaseCommandSync(
      ["/usr/bin/flock", "--exclusive", "--nonblock", "0"],
      {
        timeoutMs: RELEASE_LOCK_TIMEOUT_MS,
        outputLimitBytes: RELEASE_LOCK_OUTPUT_LIMIT_BYTES,
        stdin: descriptor,
      },
    );
  } catch (error) {
    closeSync(descriptor);
    if (error instanceof ReleaseCommandExitError && error.exitCode === 1) {
      throw new ReleaseLockContentionError(path);
    }
    throw error;
  }
  let clearActiveDescriptor: (() => void) | undefined;
  try {
    const ownerNonce = randomUUID();
    const metadata = `${JSON.stringify({
      schemaVersion: "ti-scale.release-lock-owner.v1",
      pid: process.pid,
      operation,
      ownerNonce,
      acquiredAt: new Date().toISOString(),
    })}\n`;
    ftruncateSync(descriptor, 0);
    writeSync(descriptor, metadata, 0, "utf8");
    fsyncSync(descriptor);
    clearActiveDescriptor = registerActiveReleaseLockDescriptor(descriptor, ownerNonce);
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
  let released = false;
  return {
    path,
    descriptor,
    release: () => {
      if (released) return;
      released = true;
      try { clearActiveDescriptor?.(); }
      finally { closeSync(descriptor); }
    },
  };
}

export async function withSharedReleaseLock<T>(
  operation: () => T | Promise<T>,
  options: { readonly path?: string; readonly operation?: string } = {},
): Promise<T> {
  const lock = acquireSharedReleaseLock(
    options.path ?? SHARED_RELEASE_LOCK_PATH,
    options.operation ?? "functional-release",
  );
  try { return await operation(); }
  finally { lock.release(); }
}

export class ReleaseInterruptedError extends Error {
  constructor(readonly signalName: "SIGINT" | "SIGTERM") {
    super(`Release interrupted by ${signalName}; fail-closed recovery is required`);
    this.name = "ReleaseInterruptedError";
  }
}

export interface CooperativeReleaseInterruption {
  readonly signal: AbortSignal;
  throwIfAborted(): void;
}

export interface ReleaseSignalSource {
  on(event: "SIGINT" | "SIGTERM", listener: () => void): unknown;
  off(event: "SIGINT" | "SIGTERM", listener: () => void): unknown;
}

/**
 * Converts cooperative termination signals into an abort state instead of
 * allowing the process to exit past the deployment catch/recovery boundary.
 * Callers must check throwIfAborted at each durable mutation boundary.
 */
export async function withCooperativeReleaseSignals<T>(
  operation: (interruption: CooperativeReleaseInterruption) => T | Promise<T>,
  signalSource: ReleaseSignalSource = process,
): Promise<T> {
  const controller = new AbortController();
  const interrupt = (signalName: "SIGINT" | "SIGTERM"): void => {
    if (!controller.signal.aborted) controller.abort(new ReleaseInterruptedError(signalName));
  };
  const onInterrupt = (): void => interrupt("SIGINT");
  const onTerminate = (): void => interrupt("SIGTERM");
  signalSource.on("SIGINT", onInterrupt);
  signalSource.on("SIGTERM", onTerminate);
  const context: CooperativeReleaseInterruption = {
    signal: controller.signal,
    throwIfAborted: () => {
      if (!controller.signal.aborted) return;
      const reason = controller.signal.reason;
      throw reason instanceof Error ? reason : new Error("Release interrupted");
    },
  };
  try {
    context.throwIfAborted();
    const result = await operation(context);
    // The operation's explicit in-boundary checkpoints are authoritative. A
    // signal delivered after its durable success boundary must not
    // retroactively turn a completed release into an unrecoverable generic
    // failure outside the deployment catch/recovery path.
    return result;
  } finally {
    signalSource.off("SIGINT", onInterrupt);
    signalSource.off("SIGTERM", onTerminate);
  }
}

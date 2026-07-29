import {
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join } from "node:path";
import { currentActiveReleaseLockDescriptor } from "./ReleaseLockContext";

const DEFAULT_OUTPUT_LIMIT_BYTES = 1_048_576;
const DEFAULT_TERMINATION_GRACE_MS = 1_000;
const SYNCHRONOUS_BACKSTOP_MS = 2_000;
const SYNCHRONOUS_OUTPUT_WRAPPER = String.raw`
set -uo pipefail
stdout_file=$1
stderr_file=$2
stdout_pipe=$3
stderr_pipe=$4
capture_bytes=$5
release_lock_guard=$6
shift 6

/usr/bin/mkfifo --mode=600 -- "$stdout_pipe" "$stderr_pipe"
/usr/bin/head -c "$capture_bytes" < "$stdout_pipe" > "$stdout_file" &
stdout_reader=$!
/usr/bin/head -c "$capture_bytes" < "$stderr_pipe" > "$stderr_file" &
stderr_reader=$!

cleanup_readers() {
  kill "$stdout_reader" "$stderr_reader" 2>/dev/null || true
  wait "$stdout_reader" "$stderr_reader" 2>/dev/null || true
}
trap cleanup_readers EXIT HUP INT TERM

if [ "$release_lock_guard" = "1" ]; then
  exec 9<&0
  "$@" </dev/null > "$stdout_pipe" 2> "$stderr_pipe"
else
  "$@" > "$stdout_pipe" 2> "$stderr_pipe"
fi
command_status=$?
wait "$stdout_reader"
wait "$stderr_reader"
trap - EXIT HUP INT TERM
exit "$command_status"
`;
const ASYNCHRONOUS_RELEASE_LOCK_GUARD = String.raw`
set -uo pipefail
exec 9<&0
"$@" </dev/null
command_status=$?
exit "$command_status"
`;

export interface BoundedReleaseCommandOptions {
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly outputLimitBytes?: number;
  readonly terminationGraceMs?: number;
  readonly stdin?: "ignore" | number;
  readonly allowNonZeroExit?: boolean;
}

export type BoundedReleaseCommandSyncOptions = Omit<BoundedReleaseCommandOptions, "signal">;

export interface BoundedReleaseCommandResult {
  readonly command: readonly string[];
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly durationMs: number;
}

export class ReleaseCommandTimeoutError extends Error {
  constructor(
    readonly executable: string,
    readonly timeoutMs: number,
  ) {
    super(`${basename(executable)} exceeded its ${String(timeoutMs)}ms release deadline`);
    this.name = "ReleaseCommandTimeoutError";
  }
}

export class ReleaseCommandOutputLimitError extends Error {
  constructor(
    readonly executable: string,
    readonly outputLimitBytes: number,
  ) {
    super(`${basename(executable)} exceeded its ${String(outputLimitBytes)}-byte release output limit`);
    this.name = "ReleaseCommandOutputLimitError";
  }
}

export class ReleaseCommandExitError extends Error {
  constructor(
    readonly executable: string,
    readonly exitCode: number,
    readonly diagnostic: string,
  ) {
    super(
      `${basename(executable)} failed with exit code ${String(exitCode)}` +
      `${diagnostic ? `: ${diagnostic}` : " without diagnostic output"}`,
    );
    this.name = "ReleaseCommandExitError";
  }
}

function positiveSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} must be a positive safe integer`);
  return value;
}

function releaseCommandEnvironment(): NodeJS.ProcessEnv {
  return {
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: "/root",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    NO_COLOR: "1",
  };
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new Error("Release command cancelled");
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function signalProcessGroup(pid: number, signal: NodeJS.Signals): boolean {
  try {
    process.kill(-pid, signal);
    return true;
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error
      ? String((error as { readonly code?: unknown }).code)
      : "";
    if (code !== "ESRCH") throw error;
    return false;
  }
}

function processGroupExists(pid: number): boolean {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error
      ? String((error as { readonly code?: unknown }).code)
      : "";
    if (code === "ESRCH") return false;
    if (code === "EPERM") return true;
    throw error;
  }
}

function sleepSynchronously(milliseconds: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function terminateProcessGroupSynchronously(pid: number, graceMs: number): Error | undefined {
  try {
    signalProcessGroup(pid, "SIGTERM");
    const gracefulDeadline = performance.now() + graceMs;
    while (processGroupExists(pid) && performance.now() < gracefulDeadline) sleepSynchronously(10);
    if (processGroupExists(pid)) signalProcessGroup(pid, "SIGKILL");
    const killDeadline = performance.now() + Math.max(1_000, graceMs * 2);
    while (processGroupExists(pid) && performance.now() < killDeadline) sleepSynchronously(10);
    return processGroupExists(pid)
      ? new Error(`Release process group ${String(pid)} remained alive after SIGKILL`)
      : undefined;
  } catch (error) {
    return error instanceof Error ? error : new Error("Release process-group cleanup failed");
  }
}

function readBoundedFile(path: string, maximumBytes: number): Uint8Array {
  const size = statSync(path).size;
  if (size > maximumBytes) throw new Error("Release output capture exceeded its internal hard bound");
  return readFileSync(path);
}

async function collectBoundedStream(
  stream: ReadableStream<Uint8Array>,
  limit: number,
  onLimit: () => void,
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > limit) {
        onLimit();
        throw new Error("release-command-output-limit");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

/**
 * Runs one absolute executable without a shell in a dedicated Linux session.
 * Cancellation and deadlines terminate the complete process group, then reap
 * the group leader before returning. Output is bounded independently of the
 * wall-clock deadline so a noisy maintenance command cannot exhaust memory.
 */
export async function runBoundedReleaseCommand(
  command: readonly string[],
  options: BoundedReleaseCommandOptions,
): Promise<BoundedReleaseCommandResult> {
  const executable = command[0];
  if (!executable || !isAbsolute(executable)) {
    throw new Error("Release commands require an absolute executable path");
  }
  const timeoutMs = positiveSafeInteger(options.timeoutMs, "Release command timeout");
  const outputLimitBytes = positiveSafeInteger(
    options.outputLimitBytes ?? DEFAULT_OUTPUT_LIMIT_BYTES,
    "Release command output limit",
  );
  const terminationGraceMs = positiveSafeInteger(
    options.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS,
    "Release command termination grace",
  );
  const externalSignal = options.signal;
  if (externalSignal?.aborted) throw abortReason(externalSignal);

  const startedAt = performance.now();
  const activeReleaseLockDescriptor = currentActiveReleaseLockDescriptor();
  const guardOwnsReleaseLock = activeReleaseLockDescriptor !== undefined &&
    typeof options.stdin !== "number";
  const processHandle = Bun.spawn(guardOwnsReleaseLock
    ? [
        "/usr/bin/setsid", "--wait", "/usr/bin/bash", "-c",
        ASYNCHRONOUS_RELEASE_LOCK_GUARD,
        "ti-scale-release-lock-guardian",
        ...command,
      ]
    : ["/usr/bin/setsid", "--", ...command], {
    cwd: options.cwd ?? "/",
    env: options.env ?? releaseCommandEnvironment(),
    stdin: guardOwnsReleaseLock ? activeReleaseLockDescriptor : options.stdin ?? "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const pid = processHandle.pid;
  let terminalFailure: Error | undefined;
  let termination: Promise<void> | undefined;
  let terminationFailure: Error | undefined;

  const terminateGroup = (): Promise<void> => {
    if (termination) return termination;
    termination = (async () => {
      try {
        if (!signalProcessGroup(pid, "SIGTERM")) {
          try { processHandle.kill("SIGTERM"); } catch { /* process is already terminal */ }
        }
        await Promise.race([processHandle.exited.then(() => undefined), delay(terminationGraceMs)]);
        signalProcessGroup(pid, "SIGKILL");
        try { processHandle.kill("SIGKILL"); } catch { /* group leader is already terminal */ }
        await Promise.race([
          processHandle.exited.then(() => undefined),
          delay(Math.max(1_000, terminationGraceMs * 2)).then(() => {
            throw new Error(`${basename(executable)} process group could not be reaped after SIGKILL`);
          }),
        ]);
      } catch (error) {
        terminationFailure = error instanceof Error ? error : new Error("Release command cleanup failed");
        try { processHandle.kill("SIGKILL"); } catch { /* retain cleanup failure */ }
      }
    })();
    return termination;
  };

  const outputLimitFailure = (): void => {
    if (!terminalFailure) {
      terminalFailure = new ReleaseCommandOutputLimitError(executable, outputLimitBytes);
      void terminateGroup().catch(() => undefined);
    }
  };
  const stdoutPromise = collectBoundedStream(processHandle.stdout, outputLimitBytes, outputLimitFailure);
  const stderrPromise = collectBoundedStream(processHandle.stderr, outputLimitBytes, outputLimitFailure);
  // Attach rejection observers immediately. A very noisy child can exceed the
  // limit before the process-exit race settles; the final allSettled below
  // still owns classification, while these handlers prevent an unhandled
  // rejection window.
  void stdoutPromise.catch(() => undefined);
  void stderrPromise.catch(() => undefined);

  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      const error = new ReleaseCommandTimeoutError(executable, timeoutMs);
      if (!terminalFailure) terminalFailure = error;
      void terminateGroup().catch(() => undefined);
      reject(error);
    }, timeoutMs);
  });
  let rejectOnAbort: (() => void) | undefined;
  const abortPromise = externalSignal
    ? new Promise<never>((_resolve, reject) => {
        rejectOnAbort = () => {
          const error = abortReason(externalSignal);
          if (!terminalFailure) terminalFailure = error;
          void terminateGroup().catch(() => undefined);
          reject(error);
        };
        externalSignal.addEventListener("abort", rejectOnAbort, { once: true });
      })
    : undefined;

  try {
    const [exitCode, stdoutBytes, stderrBytes] = await Promise.race([
      Promise.all([processHandle.exited, stdoutPromise, stderrPromise]),
      timeoutPromise,
      ...(abortPromise ? [abortPromise] : []),
    ]);
    if (terminalFailure) {
      throw terminalFailure;
    }
    const stdout = new TextDecoder().decode(stdoutBytes).trim();
    const stderr = new TextDecoder().decode(stderrBytes).trim();
    if (exitCode !== 0 && !options.allowNonZeroExit) {
      const diagnostic = (stderr || stdout).slice(-6_000);
      throw new ReleaseCommandExitError(executable, exitCode, diagnostic);
    }
    return {
      command: [...command],
      exitCode,
      stdout,
      stderr,
      durationMs: performance.now() - startedAt,
    };
  } catch (error) {
    if (terminalFailure || processHandle.exitCode === null) await terminateGroup();
    const outputDrain = Promise.allSettled([stdoutPromise, stderrPromise]);
    const drained = await Promise.race([
      outputDrain.then(() => true),
      delay(Math.max(1_000, terminationGraceMs * 2)).then(() => false),
    ]);
    if (!drained && !terminationFailure) {
      terminationFailure = new Error(`${basename(executable)} output pipes remained open after process-group termination`);
    }
    const primary = terminalFailure ?? (error instanceof Error ? error : new Error("Release command failed"));
    if (terminationFailure) {
      throw new AggregateError(
        [primary, terminationFailure],
        `${basename(executable)} failed and its process group could not be fully reaped`,
      );
    }
    throw primary;
  } finally {
    if (timeout) clearTimeout(timeout);
    if (externalSignal && rejectOnAbort) externalSignal.removeEventListener("abort", rejectOnAbort);
  }
}

/**
 * Bounded synchronous bridge for the two release primitives whose public API
 * must remain synchronous (atomic path exchange and inherited-FD flock).
 *
 * The target is never interpreted by a shell: the constant wrapper forwards
 * it through "$@". GNU timeout owns the dedicated session and performs the
 * TERM/KILL escalation. Two FIFO readers persist at most limit+1 bytes per
 * stream, which proves overflow without buffering unbounded output or applying
 * RLIMIT_FSIZE to release payload files. Bun's timeout is a final watchdog;
 * after it returns, this process kills any surviving process-group members.
 */
export function runBoundedReleaseCommandSync(
  command: readonly string[],
  options: BoundedReleaseCommandSyncOptions,
): BoundedReleaseCommandResult {
  const executable = command[0];
  if (!executable || !isAbsolute(executable)) {
    throw new Error("Release commands require an absolute executable path");
  }
  const timeoutMs = positiveSafeInteger(options.timeoutMs, "Release command timeout");
  const outputLimitBytes = positiveSafeInteger(
    options.outputLimitBytes ?? DEFAULT_OUTPUT_LIMIT_BYTES,
    "Release command output limit",
  );
  const terminationGraceMs = positiveSafeInteger(
    options.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS,
    "Release command termination grace",
  );
  if (outputLimitBytes >= Number.MAX_SAFE_INTEGER) throw new Error("Release command output limit is too large");

  const captureBytes = outputLimitBytes + 1;
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-release-command-"));
  const stdoutPath = join(directory, "stdout");
  const stderrPath = join(directory, "stderr");
  const stdoutPipe = join(directory, "stdout.pipe");
  const stderrPipe = join(directory, "stderr.pipe");
  const wrapperStdoutPath = join(directory, "wrapper.stdout");
  const wrapperStderrPath = join(directory, "wrapper.stderr");
  const stdoutDescriptor = openSync(wrapperStdoutPath, "wx", 0o600);
  const stderrDescriptor = openSync(wrapperStderrPath, "wx", 0o600);
  const startedAt = performance.now();
  let processId: number | undefined;
  try {
    const activeReleaseLockDescriptor = currentActiveReleaseLockDescriptor();
    const guardOwnsReleaseLock = activeReleaseLockDescriptor !== undefined &&
      typeof options.stdin !== "number";
    const timeoutSeconds = `${String(timeoutMs / 1_000)}s`;
    const graceSeconds = `${String(terminationGraceMs / 1_000)}s`;
    const result = Bun.spawnSync([
      "/usr/bin/setsid",
      "--wait",
      "/usr/bin/timeout",
      "--verbose",
      "--signal=TERM",
      `--kill-after=${graceSeconds}`,
      timeoutSeconds,
      "/usr/bin/bash",
      "-c",
      SYNCHRONOUS_OUTPUT_WRAPPER,
      "ti-scale-bounded-release-command",
      stdoutPath,
      stderrPath,
      stdoutPipe,
      stderrPipe,
      String(captureBytes),
      guardOwnsReleaseLock ? "1" : "0",
      ...command,
    ], {
      cwd: options.cwd ?? "/",
      env: options.env ?? releaseCommandEnvironment(),
      stdin: guardOwnsReleaseLock ? activeReleaseLockDescriptor : options.stdin ?? "ignore",
      stdout: stdoutDescriptor,
      stderr: stderrDescriptor,
      timeout: timeoutMs + terminationGraceMs + SYNCHRONOUS_BACKSTOP_MS,
      killSignal: "SIGKILL",
    });
    processId = result.pid;
    closeSync(stdoutDescriptor);
    closeSync(stderrDescriptor);

    const cleanupFailure = processGroupExists(result.pid)
      ? terminateProcessGroupSynchronously(result.pid, terminationGraceMs)
      : undefined;
    const wrapperDiagnostic = existsSync(wrapperStderrPath)
      ? new TextDecoder().decode(readBoundedFile(wrapperStderrPath, 64 * 1_024)).trim()
      : "";
    const stdoutBytes = existsSync(stdoutPath) ? readBoundedFile(stdoutPath, captureBytes) : new Uint8Array();
    const stderrBytes = existsSync(stderrPath) ? readBoundedFile(stderrPath, captureBytes) : new Uint8Array();
    const overflowed = stdoutBytes.byteLength > outputLimitBytes || stderrBytes.byteLength > outputLimitBytes;
    const timedOut = Boolean(result.exitedDueToTimeout) || /timeout: sending signal (?:TERM|KILL) to command/u.test(wrapperDiagnostic);
    const stdout = new TextDecoder().decode(stdoutBytes.slice(0, outputLimitBytes)).trim();
    const stderr = new TextDecoder().decode(stderrBytes.slice(0, outputLimitBytes)).trim();

    if (cleanupFailure) {
      const primary = timedOut
        ? new ReleaseCommandTimeoutError(executable, timeoutMs)
        : overflowed
          ? new ReleaseCommandOutputLimitError(executable, outputLimitBytes)
          : new Error(`${basename(executable)} left a surviving release process group`);
      throw new AggregateError(
        [primary, cleanupFailure],
        `${basename(executable)} failed and its process group could not be fully reaped`,
      );
    }
    if (overflowed) throw new ReleaseCommandOutputLimitError(executable, outputLimitBytes);
    if (timedOut) throw new ReleaseCommandTimeoutError(executable, timeoutMs);
    if (result.exitCode !== 0 && !options.allowNonZeroExit) {
      throw new ReleaseCommandExitError(executable, result.exitCode, (stderr || stdout || wrapperDiagnostic).slice(-6_000));
    }
    return {
      command: [...command],
      exitCode: result.exitCode,
      stdout,
      stderr,
      durationMs: performance.now() - startedAt,
    };
  } finally {
    try { closeSync(stdoutDescriptor); } catch { /* descriptor was already closed */ }
    try { closeSync(stderrDescriptor); } catch { /* descriptor was already closed */ }
    if (processId !== undefined && processGroupExists(processId)) {
      terminateProcessGroupSynchronously(processId, terminationGraceMs);
    }
    rmSync(directory, { recursive: true, force: true });
  }
}

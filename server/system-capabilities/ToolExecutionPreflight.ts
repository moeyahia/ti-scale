import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { access, lstat, open, readFile, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";
import type {
  CreateFailureDiagnosisInput,
  FailureCategory,
  FailureOperatorAction,
  OperationalActor,
} from "../intelligence-v24/types";

const TOOL_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SAFE_PROBE_ARGUMENTS = new Set([
  "--version",
  "-V",
  "-VV",
  "version",
  "-version",
  "--help",
  "-h",
]);
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const MAXIMUM_EXECUTABLE_BYTES = 256 * 1024 * 1024;

export type ToolExecutionPreflightCode =
  | "ready"
  | "executable_missing"
  | "executable_not_regular_file"
  | "executable_not_executable"
  | "executable_unsafe_permissions"
  | "executable_identity_changed"
  | "working_directory_unavailable"
  | "startup_probe_timeout"
  | "startup_probe_output_limit"
  | "startup_probe_empty"
  | "startup_probe_isolation_unavailable"
  | "no_new_privileges_capability_conflict"
  | "startup_probe_failed";

export interface ToolExecutionPreflightSpec {
  readonly toolId: string;
  readonly displayName: string;
  /** Exact reviewed executable. PATH lookup and shell expansion are forbidden. */
  readonly executablePath: string;
  /** Only conventional version/help switches are accepted by this argument-bounded boundary. */
  readonly probeArguments: readonly string[];
  readonly workingDirectory?: string;
  readonly expectedExitCodes?: readonly number[];
  readonly timeoutMs?: number;
  readonly maximumOutputBytes?: number;
  readonly ttlMs?: number;
}

export interface ToolProbeExecutionResult {
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly outputLimitExceeded: boolean;
  /** Identity of the sealed immutable snapshot actually executed, never only the source path. */
  readonly executableIdentity: ToolExecutableIdentity | null;
  readonly spawnErrorCode?: string;
}

export interface ToolExecutableIdentity {
  readonly sha256: string;
  readonly device: string;
  readonly inode: string;
  readonly sizeBytes: number;
  readonly mode: number;
  readonly uid: number;
  readonly gid: number;
}

export interface ToolProbeIsolation {
  /** True only when the probe worker technically prevents AF_INET/AF_INET6 egress. */
  readonly networkEnforced: boolean;
  /** True only when the probe worker technically prevents writes outside a disposable sandbox. */
  readonly filesystemWritesEnforced: boolean;
  /**
   * True only when the worker executes an immutable sealed snapshot of the
   * bytes whose digest is returned as executableIdentity. An opened ordinary
   * filesystem descriptor is not sufficient because its inode can be changed.
   */
  readonly immutableSnapshotEnforced: boolean;
}

export interface ToolExecutionPreflightEnvironment {
  readonly isolation: ToolProbeIsolation;
  inspectExecutable(path: string): Promise<
    | Readonly<{ state: "ready"; identity: ToolExecutableIdentity }>
    | Readonly<{ state: "missing" | "not_regular" | "not_executable" | "unsafe_permissions" }>
  >;
  inspectWorkingDirectory(path: string): Promise<boolean>;
  readNoNewPrivileges(): Promise<boolean | null>;
  execute(input: Readonly<{
    executablePath: string;
    arguments: readonly string[];
    workingDirectory?: string;
    timeoutMs: number;
    maximumOutputBytes: number;
    expectedExecutableIdentity: ToolExecutableIdentity;
  }>): Promise<ToolProbeExecutionResult>;
}

export interface ToolExecutionFailureExplanation {
  readonly category: FailureCategory;
  readonly humanReason: string;
  readonly retryable: boolean;
  readonly remediation: string;
  readonly operatorActions: readonly FailureOperatorAction[];
}

export interface ToolExecutionPreflightResult {
  readonly schemaVersion: "ti-scale.tool-execution-preflight.v2";
  readonly toolId: string;
  readonly status: "ready" | "unavailable";
  readonly code: ToolExecutionPreflightCode;
  readonly checkedAt: string;
  readonly expiresAt: string;
  readonly bindingSha256: string;
  readonly probeBoundary: Readonly<{
    readonly shell: false;
    readonly targetArgumentsSupplied: false;
    readonly providerArgumentsSupplied: false;
    readonly mcpArgumentsSupplied: false;
    readonly networkIsolationEnforced: boolean;
    readonly filesystemWriteIsolationEnforced: boolean;
    readonly immutableSnapshotExecutionEnforced: boolean;
    /** Contact is not inferred from the absence of target-shaped arguments. */
    readonly externalContact: "not_measured";
  }>;
  readonly executableIdentity: ToolExecutableIdentity | null;
  readonly noNewPrivileges: boolean | null;
  readonly explanation: string;
  readonly remediation: string | null;
  readonly execution: Readonly<{
    exitCode: number | null;
    signal: NodeJS.Signals | null;
    spawnErrorCode: string | null;
    outputBytes: number;
    outputSha256: string | null;
  }>;
  readonly failure?: ToolExecutionFailureExplanation;
}

export interface ToolPreflightFailureContext {
  readonly missionId: string;
  readonly runId: string;
  readonly stepId?: string;
  readonly actionId?: string;
  readonly subjectType?: "run" | "step" | "action";
  readonly subjectId?: string;
  readonly lastSuccessEventId?: string;
  readonly rawErrorLogId?: string;
  readonly progressBeforeFailure?: unknown;
  readonly actor: OperationalActor;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function validateSpec(spec: ToolExecutionPreflightSpec): Required<
  Pick<ToolExecutionPreflightSpec, "timeoutMs" | "maximumOutputBytes" | "ttlMs">
> & ToolExecutionPreflightSpec & { readonly expectedExitCodes: readonly number[] } {
  if (!TOOL_ID.test(spec.toolId) || spec.toolId !== spec.toolId.trim()) {
    throw new Error("Tool preflight requires a stable public tool ID");
  }
  if (
    !spec.displayName.trim()
    || spec.displayName.length > 200
    || CONTROL_CHARACTERS.test(spec.displayName)
  ) throw new Error("Tool preflight displayName is invalid");
  if (!isAbsolute(spec.executablePath) || CONTROL_CHARACTERS.test(spec.executablePath)) {
    throw new Error("Tool preflight executablePath must be an absolute non-control path");
  }
  if (
    spec.workingDirectory !== undefined
    && (!isAbsolute(spec.workingDirectory) || CONTROL_CHARACTERS.test(spec.workingDirectory))
  ) throw new Error("Tool preflight workingDirectory must be absolute when supplied");
  if (
    spec.probeArguments.length < 1
    || spec.probeArguments.length > 2
    || spec.probeArguments.some((argument) => !SAFE_PROBE_ARGUMENTS.has(argument))
  ) {
    throw new Error("Tool preflight accepts only one or two conventional version/help arguments");
  }
  const expectedExitCodes = spec.expectedExitCodes ?? [0];
  if (
    expectedExitCodes.length < 1
    || expectedExitCodes.length > 8
    || new Set(expectedExitCodes).size !== expectedExitCodes.length
    || expectedExitCodes.some((code) => !Number.isInteger(code) || code < 0 || code > 255)
  ) throw new Error("Tool preflight expectedExitCodes are invalid");
  const timeoutMs = spec.timeoutMs ?? 3_000;
  const maximumOutputBytes = spec.maximumOutputBytes ?? 32 * 1_024;
  const ttlMs = spec.ttlMs ?? 60_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new Error("Tool preflight timeoutMs must be between 100 and 10000");
  }
  if (
    !Number.isInteger(maximumOutputBytes)
    || maximumOutputBytes < 128
    || maximumOutputBytes > 64 * 1_024
  ) throw new Error("Tool preflight maximumOutputBytes must be between 128 and 65536");
  if (!Number.isInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 5 * 60_000) {
    throw new Error("Tool preflight ttlMs must be between 1000 and 300000");
  }
  return { ...spec, expectedExitCodes, timeoutMs, maximumOutputBytes, ttlMs };
}

/** Canonical digest of every reviewed input that can change probe behavior. */
export function toolExecutionPreflightBindingSha256(
  input: ToolExecutionPreflightSpec,
): string {
  const spec = validateSpec(input);
  return sha256(JSON.stringify({
    toolId: spec.toolId,
    displayName: spec.displayName,
    executablePath: spec.executablePath,
    probeArguments: [...spec.probeArguments],
    workingDirectory: spec.workingDirectory ?? null,
    expectedExitCodes: [...spec.expectedExitCodes],
    timeoutMs: spec.timeoutMs,
    maximumOutputBytes: spec.maximumOutputBytes,
    ttlMs: spec.ttlMs,
  }));
}

function dependencyActions(): readonly FailureOperatorAction[] {
  return [
    {
      kind: "configure_dependency",
      label: "Repair the reviewed tool binding",
      consequence: "Rechecks the exact local executable and its isolation boundary without supplying mission target arguments.",
      requiresConfirmation: true,
    },
    {
      kind: "use_compatible_fallback",
      label: "Use a reviewed compatible tool",
      consequence: "Replaces this step's tool only after the alternative passes the same policy and readiness checks.",
      requiresConfirmation: true,
    },
    {
      kind: "amend_plan",
      label: "Amend the affected step",
      consequence: "Keeps the run stopped while the plan records a different in-scope method.",
      requiresConfirmation: true,
    },
  ];
}

function timeoutActions(): readonly FailureOperatorAction[] {
  return [
    {
      kind: "retry_bounded",
      label: "Repeat one bounded startup check",
      consequence: "Runs the same argument-bounded startup check once after the local dependency and isolation boundary are inspected.",
      requiresConfirmation: true,
    },
    ...dependencyActions().slice(1),
  ];
}

function explanation(
  code: Exclude<ToolExecutionPreflightCode, "ready">,
  displayName: string,
): ToolExecutionFailureExplanation {
  if (code === "startup_probe_timeout") {
    return {
      category: "timeout",
      humanReason: `${displayName} did not finish its local startup check within the bounded deadline. No mission target, provider, or MCP arguments were supplied; external contact was not independently measured.`,
      retryable: true,
      remediation: "Inspect the local process, dependency health, and probe isolation, then use at most one bounded retry or a reviewed fallback.",
      operatorActions: timeoutActions(),
    };
  }
  if (code === "startup_probe_failed" || code === "startup_probe_empty" || code === "startup_probe_output_limit") {
    return {
      category: "deterministic_tool_error",
      humanReason: code === "startup_probe_empty"
        ? `${displayName} started but returned no version or help output, so its binding was not accepted as usable.`
        : code === "startup_probe_output_limit"
          ? `${displayName} exceeded the bounded startup-output limit and was stopped before mission use.`
          : `${displayName} rejected its local version/help startup check. The same unchanged binding will not be retried automatically.`,
      retryable: false,
      remediation: "Inspect the reviewed executable, arguments, and dependencies; repair the binding or select a compatible attested alternative.",
      operatorActions: dependencyActions(),
    };
  }
  if (code === "no_new_privileges_capability_conflict") {
    return {
      category: "dependency_missing",
      humanReason: `${displayName} exists, but Linux refused to start it inside this worker's no-new-privileges boundary. The executable or a delegated binary requires a privilege transition that this worker cannot receive.`,
      retryable: false,
      remediation: "Run the specialist in a reviewed worker profile with the required capabilities, or bind a reviewed capability-free alternative. Do not copy or strip capabilities from the system binary at runtime.",
      operatorActions: dependencyActions(),
    };
  }
  if (code === "startup_probe_isolation_unavailable") {
    return {
      category: "dependency_missing",
      humanReason: `${displayName} was not started because the probe worker did not enforce network egress isolation, disposable filesystem writes, and immutable hashed-snapshot execution. No diagnostic output can make the tool available without all three boundaries.`,
      retryable: false,
      remediation: "Run the exact reviewed probe only in a worker that technically blocks network egress, confines writes, and executes a sealed immutable snapshot of the hashed bytes, then create a new expiring receipt.",
      operatorActions: dependencyActions(),
    };
  }
  if (code === "executable_identity_changed") {
    return {
      category: "dependency_missing",
      humanReason: `${displayName}'s executable identity changed between inspection and completion, so the startup result was discarded.`,
      retryable: false,
      remediation: "Restore a stable reviewed executable, verify its owner and permissions, and repeat the probe in the isolated worker.",
      operatorActions: dependencyActions(),
    };
  }
  const reason: Readonly<Record<
    "executable_missing" | "executable_not_regular_file" | "executable_not_executable" | "executable_unsafe_permissions" | "working_directory_unavailable",
    string
  >> = {
    executable_missing: `${displayName}'s reviewed executable is not present in this worker image.`,
    executable_not_regular_file: `${displayName}'s reviewed executable path does not identify a regular, non-symlink file.`,
    executable_not_executable: `${displayName}'s reviewed executable cannot be started by this worker.`,
    executable_unsafe_permissions: `${displayName}'s reviewed executable has an unsafe owner, writable mode, excessive size, or unreadable identity.`,
    working_directory_unavailable: `${displayName}'s reviewed working directory is missing or inaccessible to this worker.`,
  };
  return {
    category: "dependency_missing",
    humanReason: `${reason[code]} No mission target, provider, or MCP arguments were supplied; external contact was not independently measured.`,
    retryable: false,
    remediation: code === "working_directory_unavailable"
      ? "Resolve the engagement through the configured workspace map, preserving exact casing and scope, then repeat the isolated check."
      : "Install or repair the exact reviewed executable in the specialist worker, then repeat the isolated check.",
    operatorActions: dependencyActions(),
  };
}

function emptyExecution(): ToolExecutionPreflightResult["execution"] {
  return {
    exitCode: null,
    signal: null,
    spawnErrorCode: null,
    outputBytes: 0,
    outputSha256: null,
  };
}

function executableByCurrentIdentity(mode: number, uid: number, gid: number): boolean {
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const currentGid = process.getegid?.() ?? process.getgid?.() ?? 0;
  const groups = new Set([currentGid, ...(process.getgroups?.() ?? [])]);
  if (currentUid === 0) return (mode & 0o111) !== 0;
  if (currentUid === uid) return (mode & 0o100) !== 0;
  if (groups.has(gid)) return (mode & 0o010) !== 0;
  return (mode & 0o001) !== 0;
}

function sameExecutableIdentity(
  left: ToolExecutableIdentity,
  right: ToolExecutableIdentity,
): boolean {
  return left.sha256 === right.sha256
    && left.device === right.device
    && left.inode === right.inode
    && left.sizeBytes === right.sizeBytes
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

async function inspectExactExecutable(path: string): Promise<
  | Readonly<{ state: "ready"; identity: ToolExecutableIdentity }>
  | Readonly<{ state: "missing" | "not_regular" | "not_executable" | "unsafe_permissions" }>
> {
  let pathMetadata: Awaited<ReturnType<typeof lstat>>;
  try {
    pathMetadata = await lstat(path, { bigint: true });
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT"
      ? { state: "missing" }
      : { state: "not_executable" };
  }
  if (pathMetadata.isSymbolicLink() || !pathMetadata.isFile()) return { state: "not_regular" };

  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(path, flags);
    const metadata = await handle.stat({ bigint: true });
    if (!metadata.isFile()
      || metadata.dev !== pathMetadata.dev
      || metadata.ino !== pathMetadata.ino) return { state: "not_regular" };
    const sizeBytes = Number(metadata.size);
    const mode = Number(metadata.mode & 0o7777n);
    const uid = Number(metadata.uid);
    const gid = Number(metadata.gid);
    const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
    if (!Number.isSafeInteger(sizeBytes)
      || sizeBytes < 1
      || sizeBytes > MAXIMUM_EXECUTABLE_BYTES
      || (uid !== 0 && uid !== currentUid)
      || (mode & 0o022) !== 0) return { state: "unsafe_permissions" };
    if (!executableByCurrentIdentity(mode, uid, gid)) return { state: "not_executable" };

    const digest = createHash("sha256");
    const stream = handle.createReadStream({ autoClose: false, start: 0 });
    for await (const chunk of stream) digest.update(chunk as Buffer);
    return {
      state: "ready",
      identity: Object.freeze({
        sha256: digest.digest("hex"),
        device: metadata.dev.toString(),
        inode: metadata.ino.toString(),
        sizeBytes,
        mode,
        uid,
        gid,
      }),
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") return { state: "not_regular" };
    return { state: "not_executable" };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function defaultEnvironment(): ToolExecutionPreflightEnvironment {
  return {
    isolation: Object.freeze({
      networkEnforced: false,
      filesystemWritesEnforced: false,
      immutableSnapshotEnforced: false,
    }),
    inspectExecutable: inspectExactExecutable,
    async inspectWorkingDirectory(path) {
      try {
        const metadata = await stat(path);
        if (!metadata.isDirectory()) return false;
        await access(path, fsConstants.R_OK | fsConstants.X_OK);
        return true;
      } catch {
        return false;
      }
    },
    async readNoNewPrivileges() {
      if (process.platform !== "linux") return null;
      try {
        const status = await readFile("/proc/self/status", "utf8");
        const match = /^NoNewPrivs:\s+([01])$/mu.exec(status);
        return match ? match[1] === "1" : null;
      } catch {
        return null;
      }
    },
    async execute() {
      // Deliberately unreachable through ToolExecutionPreflightService: this
      // process owns no immutable-snapshot executor. Production must inject a
      // separately reviewed worker before a local tool can even be started.
      return {
        exitCode: null,
        signal: null,
        stdout: "",
        stderr: "",
        timedOut: false,
        outputLimitExceeded: false,
        executableIdentity: null,
        spawnErrorCode: "ENOTSUP",
      };
    },
  };
}

function safeExecution(result: ToolProbeExecutionResult): ToolExecutionPreflightResult["execution"] {
  const combined = result.stdout && result.stderr
    ? `${result.stdout}\n${result.stderr}`
    : result.stdout || result.stderr;
  const bytes = Buffer.byteLength(combined, "utf8");
  return {
    exitCode: result.exitCode,
    signal: result.signal,
    spawnErrorCode: result.spawnErrorCode ?? null,
    outputBytes: bytes,
    outputSha256: bytes > 0 ? sha256(combined) : null,
  };
}

function conflictWithNoNewPrivileges(
  result: ToolProbeExecutionResult,
  noNewPrivileges: boolean | null,
): boolean {
  if (noNewPrivileges !== true) return false;
  const text = `${result.spawnErrorCode ?? ""} ${result.stdout} ${result.stderr}`;
  return /(?:\bEPERM\b|operation not permitted)/iu.test(text);
}

/**
 * Runs only an exact version/help invocation. It never resolves PATH, opens a
 * shell, supplies mission/provider/MCP arguments, or grants execution authority.
 * External contact is not claimed absent unless the injected worker enforces
 * network isolation. The production default owns no immutable-snapshot
 * executor, so it refuses before execute() and cannot promote a tool.
 */
export class ToolExecutionPreflightService {
  private readonly environment: ToolExecutionPreflightEnvironment;
  private readonly clock: () => Date;
  private readonly results = new Map<string, ToolExecutionPreflightResult>();

  constructor(options: {
    readonly environment?: ToolExecutionPreflightEnvironment;
    readonly clock?: () => Date;
  } = {}) {
    this.environment = options.environment ?? defaultEnvironment();
    this.clock = options.clock ?? (() => new Date());
  }

  read(toolId: string): ToolExecutionPreflightResult | undefined {
    return this.results.get(toolId);
  }

  async check(input: ToolExecutionPreflightSpec): Promise<ToolExecutionPreflightResult> {
    const spec = validateSpec(input);
    const checkedAt = this.clock();
    const expiresAt = new Date(checkedAt.getTime() + spec.ttlMs).toISOString();
    const bindingSha256 = toolExecutionPreflightBindingSha256(spec);
    const noNewPrivileges = await this.environment.readNoNewPrivileges();
    const probeBoundary = Object.freeze({
      shell: false as const,
      targetArgumentsSupplied: false as const,
      providerArgumentsSupplied: false as const,
      mcpArgumentsSupplied: false as const,
      networkIsolationEnforced: this.environment.isolation.networkEnforced,
      filesystemWriteIsolationEnforced: this.environment.isolation.filesystemWritesEnforced,
      immutableSnapshotExecutionEnforced:
        this.environment.isolation.immutableSnapshotEnforced,
      externalContact: "not_measured" as const,
    });
    let executableIdentity: ToolExecutableIdentity | null = null;
    const buildFailure = (
      code: Exclude<ToolExecutionPreflightCode, "ready">,
      execution: ToolExecutionPreflightResult["execution"] = emptyExecution(),
    ): ToolExecutionPreflightResult => {
      const failure = explanation(code, spec.displayName);
      return {
        schemaVersion: "ti-scale.tool-execution-preflight.v2",
        toolId: spec.toolId,
        status: "unavailable",
        code,
        checkedAt: checkedAt.toISOString(),
        expiresAt,
        bindingSha256,
        probeBoundary,
        executableIdentity,
        noNewPrivileges,
        explanation: failure.humanReason,
        remediation: failure.remediation,
        execution,
        failure,
      };
    };

    const executable = await this.environment.inspectExecutable(spec.executablePath);
    if (executable.state === "ready") executableIdentity = executable.identity;
    let result: ToolExecutionPreflightResult;
    if (executable.state !== "ready") {
      const code = executable.state === "missing"
        ? "executable_missing"
        : executable.state === "not_regular"
          ? "executable_not_regular_file"
          : executable.state === "unsafe_permissions"
            ? "executable_unsafe_permissions"
            : "executable_not_executable";
      result = buildFailure(code);
    } else if (
      spec.workingDirectory
      && !await this.environment.inspectWorkingDirectory(spec.workingDirectory)
    ) {
      result = buildFailure("working_directory_unavailable");
    } else if (!probeBoundary.networkIsolationEnforced
      || !probeBoundary.filesystemWriteIsolationEnforced
      || !probeBoundary.immutableSnapshotExecutionEnforced) {
      // Refuse before execute(). A version/help probe is still executable code;
      // argument bounding alone cannot make a mutable filesystem inode safe.
      result = buildFailure("startup_probe_isolation_unavailable");
    } else {
      const execution = await this.environment.execute({
        executablePath: spec.executablePath,
        arguments: spec.probeArguments,
        ...(spec.workingDirectory ? { workingDirectory: spec.workingDirectory } : {}),
        timeoutMs: spec.timeoutMs,
        maximumOutputBytes: spec.maximumOutputBytes,
        expectedExecutableIdentity: executable.identity,
      });
      const safe = safeExecution(execution);
      const executableAfter = await this.environment.inspectExecutable(spec.executablePath);
      const identityStable = executableAfter.state === "ready"
        && executableIdentity !== null
        && execution.executableIdentity !== null
        && sameExecutableIdentity(executableIdentity, execution.executableIdentity)
        && sameExecutableIdentity(executableIdentity, executableAfter.identity);
      if (!identityStable) {
        result = buildFailure("executable_identity_changed", safe);
      } else if (conflictWithNoNewPrivileges(execution, noNewPrivileges)) {
        result = buildFailure("no_new_privileges_capability_conflict", safe);
      } else if (execution.timedOut) {
        result = buildFailure("startup_probe_timeout", safe);
      } else if (execution.outputLimitExceeded || safe.outputBytes > spec.maximumOutputBytes) {
        result = buildFailure("startup_probe_output_limit", safe);
      } else if (!spec.expectedExitCodes.includes(execution.exitCode ?? -1)) {
        const code = execution.spawnErrorCode === "ENOENT"
          ? "executable_missing"
          : execution.spawnErrorCode === "EACCES"
            ? "executable_not_executable"
            : "startup_probe_failed";
        result = buildFailure(code, safe);
      } else if (`${execution.stdout}${execution.stderr}`.trim().length === 0) {
        result = buildFailure("startup_probe_empty", safe);
      } else {
        result = {
          schemaVersion: "ti-scale.tool-execution-preflight.v2",
          toolId: spec.toolId,
          status: "ready",
          code: "ready",
          checkedAt: checkedAt.toISOString(),
          expiresAt,
          bindingSha256,
          probeBoundary,
          executableIdentity,
          noNewPrivileges,
          explanation: `${spec.displayName} passed an exact version/help startup check inside enforced network, disposable-write, and immutable hashed-snapshot execution isolation. No mission target, provider, or MCP arguments were supplied. This does not authorize mission execution.`,
          remediation: null,
          execution: safe,
        };
      }
    }
    this.results.set(spec.toolId, result);
    return result;
  }
}

/** Converts a failed preflight into the canonical persisted FailureDiagnosis input. */
export function toolPreflightFailureDiagnosisInput(
  preflight: ToolExecutionPreflightResult,
  context: ToolPreflightFailureContext,
): CreateFailureDiagnosisInput {
  if (preflight.status !== "unavailable" || !preflight.failure) {
    throw new Error("Only an unavailable tool preflight can create a failure diagnosis");
  }
  const subjectType = context.subjectType
    ?? (context.actionId ? "action" : context.stepId ? "step" : "run");
  const expectedSubjectId = subjectType === "action"
    ? context.actionId
    : subjectType === "step"
      ? context.stepId
      : context.runId;
  const subjectId = context.subjectId ?? expectedSubjectId;
  if (!subjectId || subjectId !== expectedSubjectId) {
    throw new Error("Tool preflight failure subject does not match its canonical context");
  }
  return {
    missionId: context.missionId,
    runId: context.runId,
    ...(context.stepId ? { stepId: context.stepId } : {}),
    ...(context.actionId ? { actionId: context.actionId } : {}),
    subjectType,
    subjectId,
    humanReason: preflight.failure.humanReason,
    category: preflight.failure.category,
    code: preflight.code,
    originatingComponent: "tool-runtime-preflight",
    ...(context.lastSuccessEventId ? { lastSuccessEventId: context.lastSuccessEventId } : {}),
    failedComponentRef: preflight.toolId,
    targetSummary: "No mission target, provider, or MCP arguments were supplied. The startup check failed before action dispatch; external contact was not independently measured unless the receipt records enforced network isolation.",
    policyOrDependency: preflight.noNewPrivileges
      ? "The worker has Linux no-new-privileges enabled; privilege transitions and file-capability elevation are denied."
      : "The exact executable, working directory, and bounded startup behavior must pass before dispatch.",
    ...(context.rawErrorLogId ? { rawErrorLogId: context.rawErrorLogId } : {}),
    retryHistory: [],
    progressBeforeFailure: context.progressBeforeFailure ?? {
      targetContact: preflight.probeBoundary.networkIsolationEnforced
        ? false
        : "not_established",
      executionStarted: false,
    },
    preservedReferences: [],
    retryable: preflight.failure.retryable,
    automaticRecovery: {
      attempted: false,
      reason: "Preflight failures do not trigger target-side recovery or runtime workarounds.",
      bindingSha256: preflight.bindingSha256,
    },
    remediation: preflight.failure.remediation,
    operatorActions: preflight.failure.operatorActions,
    objectiveImpact: "The affected step did not start. Prior mission state and evidence remain unchanged.",
    actor: context.actor,
  };
}

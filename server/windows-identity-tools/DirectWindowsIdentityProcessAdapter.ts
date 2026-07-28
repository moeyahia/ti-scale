import { createHash } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  writeSync,
} from "node:fs";
import { lstat, mkdir, open, realpath } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { inspectLinuxFileCapabilities } from "../local-tools/AsyncFileCapabilityInspection";
import { REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION } from "../orchestration";
import { EngagementWorkspaceResolver } from "../system-capabilities";
import { redactWindowsIdentityOutput } from "./WindowsIdentityResultNormalizer";
import { windowsIdentityFailure } from "./failureTaxonomy";
import {
  WINDOWS_IDENTITY_EXECUTION_RECEIPT_SCHEMA_VERSION,
  WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
  WINDOWS_IDENTITY_RESULT_SCHEMA_VERSION,
  WindowsIdentityBoundaryError,
  type CompiledWindowsIdentityInvocation,
  type WindowsIdentityCredentialBindingReceipt,
  type WindowsIdentityCredentialMaterialResolver,
  type WindowsIdentityCredentialView,
  type WindowsIdentityExecutionAdapter,
  type WindowsIdentityRawResult,
  type WindowsIdentityToolDefinition,
  type WindowsIdentityToolId,
  type WindowsIdentityToolReadinessReceipt,
} from "./types";
import { WindowsIdentityToolPack } from "./WindowsIdentityToolPack";

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024;
const MAX_CREDENTIAL_FILE_BYTES = 64 * 1024;
const F_ADD_SEALS = 1033;
const F_GET_SEALS = 1034;
const REQUIRED_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008;
const MFD_ALLOW_SEALING = 0x0002;
const SANDBOX_CREDENTIAL_PATHS: Readonly<Record<WindowsIdentityCredentialView, string>> =
  Object.freeze({
    samba_auth_file: "/run/ti-scale/credential/samba-auth",
    username_file: "/run/ti-scale/credential/username",
    password_file: "/run/ti-scale/credential/password",
    ldap_bind_identity: "/run/ti-scale/credential/ldap-bind-identity",
  });
const FIXED_ENVIRONMENT = Object.freeze({
  HOME: "/workspace/.tool-state",
  XDG_CACHE_HOME: "/workspace/.tool-state/cache",
  XDG_CONFIG_HOME: "/workspace/.tool-state/config",
  XDG_DATA_HOME: "/workspace/.tool-state/data",
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
} as const);

interface OpenedFile {
  readonly handle: Awaited<ReturnType<typeof open>>;
  readonly sha256: string;
  readonly bytes: Buffer;
}

interface ActiveProcess {
  readonly runId: string;
  readonly child: ChildProcess;
  terminate(reason: "cancelled" | "timed_out" | "output_limit"): void;
}

interface BunFfiLibrary {
  readonly symbols: Readonly<{
    memfd_create(label: Buffer, flags: number): number;
    fcntl(descriptor: number, operation: number, argument: number): number;
  }>;
  close(): void;
}

interface BunFfiRuntime {
  readonly FFIType: Readonly<{
    cstring: unknown;
    u32: unknown;
    i32: unknown;
  }>;
  dlopen(
    path: string,
    symbols: Readonly<Record<string, Readonly<{
      args: readonly unknown[];
      returns: unknown;
    }>>>,
  ): BunFfiLibrary;
}

export interface DirectWindowsIdentityProcessAdapterOptions {
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly credentialResolver?: WindowsIdentityCredentialMaterialResolver;
  readonly sandboxExecutable: Readonly<{
    readonly path: string;
    readonly expectedSha256: string;
  }>;
  readonly adapterId?: string;
  /** A lower process budget used by deterministic tests and emergency policy. */
  readonly runtimeTimeoutCapMs?: number;
  /** A lower retained-output budget used by deterministic tests and emergency policy. */
  readonly runtimeOutputCapBytes?: number;
  readonly now?: () => Date;
}

function boundary(code: Parameters<typeof windowsIdentityFailure>[0]): never {
  const failure = windowsIdentityFailure(code);
  throw new WindowsIdentityBoundaryError(
    failure.code,
    failure.category,
    failure.humanMessage,
    failure.retryable,
  );
}

async function fileCapabilitiesAbsent(path: string, signal?: AbortSignal): Promise<boolean> {
  return (await inspectLinuxFileCapabilities(path, signal ? { signal } : {})).state === "none";
}

async function openedReviewedFile(
  path: string,
  expectedSha256: string | null,
  maximumBytes: number,
  executable: boolean,
): Promise<OpenedFile> {
  if (!isAbsolute(path) || (expectedSha256 !== null && !SHA256.test(expectedSha256))) {
    boundary(expectedSha256 === null
      ? "windows_identity_credential_binding_changed"
      : "windows_identity_tool_identity_changed");
  }
  const before = await lstat(path, { bigint: true }).catch(() => undefined);
  if (!before || before.isSymbolicLink() || !before.isFile()) {
    boundary(expectedSha256 === null
      ? "windows_identity_credential_binding_changed"
      : "windows_identity_tool_unavailable");
  }
  const mode = Number(before.mode & 0o7777n);
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const safeOwner = Number(before.uid) === 0 || Number(before.uid) === currentUid;
  if (!safeOwner || (mode & 0o022) !== 0 || (mode & 0o7000) !== 0
    || (executable && (mode & 0o111) === 0)
    || Number(before.size) < 1 || Number(before.size) > maximumBytes) {
    boundary(expectedSha256 === null
      ? "windows_identity_credential_binding_changed"
      : "windows_identity_tool_identity_changed");
  }
  const handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const metadata = await handle.stat({ bigint: true });
    if (metadata.dev !== before.dev || metadata.ino !== before.ino
      || metadata.size !== before.size || metadata.mode !== before.mode
      || metadata.uid !== before.uid || metadata.gid !== before.gid) {
      boundary(expectedSha256 === null
        ? "windows_identity_credential_binding_changed"
        : "windows_identity_tool_identity_changed");
    }
    const size = Number(metadata.size);
    const buffer = Buffer.allocUnsafe(size);
    let position = 0;
    while (position < size) {
      const chunk = await handle.read(buffer, position, size - position, position);
      if (chunk.bytesRead < 1) break;
      position += chunk.bytesRead;
    }
    if (position !== size) boundary("windows_identity_tool_identity_changed");
    const sha256 = createHash("sha256").update(buffer).digest("hex");
    if (expectedSha256 !== null && sha256 !== expectedSha256) {
      boundary("windows_identity_tool_identity_changed");
    }
    return { handle, sha256, bytes: buffer };
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
}

const BUN_FFI_MODULE_SPECIFIER = ["bun", "ffi"].join(":");

async function loadBunFfiRuntime(): Promise<BunFfiRuntime> {
  try {
    return await import(BUN_FFI_MODULE_SPECIFIER) as unknown as BunFfiRuntime;
  } catch {
    boundary("windows_identity_adapter_not_bounded");
  }
}

async function sealedMemfd(bytes: Buffer, label: string): Promise<number> {
  const { dlopen, FFIType } = await loadBunFfiRuntime();
  const libc = dlopen("libc.so.6", {
    memfd_create: { args: [FFIType.cstring, FFIType.u32], returns: FFIType.i32 },
    fcntl: { args: [FFIType.i32, FFIType.i32, FFIType.i32], returns: FFIType.i32 },
  });
  let descriptor = -1;
  try {
    descriptor = libc.symbols.memfd_create(Buffer.from(`${label}\0`), MFD_ALLOW_SEALING);
    if (descriptor < 0) throw new Error("memfd_create_failed");
    let written = 0;
    while (written < bytes.length) {
      const count = writeSync(descriptor, bytes, written, bytes.length - written, written);
      if (count < 1) throw new Error("memfd_write_failed");
      written += count;
    }
    fchmodSync(descriptor, 0o500);
    if (libc.symbols.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS) !== 0
      || libc.symbols.fcntl(descriptor, F_GET_SEALS, 0) !== REQUIRED_SEALS) {
      throw new Error("memfd_seal_failed");
    }
    return descriptor;
  } catch {
    if (descriptor >= 0) closeSync(descriptor);
    boundary("windows_identity_adapter_not_bounded");
  } finally {
    libc.close();
  }
}

function requiredCredentialViews(
  invocation: CompiledWindowsIdentityInvocation,
): readonly WindowsIdentityCredentialView[] {
  if (!invocation.credentialReference) return [];
  if (invocation.operation === "smb_identity_summary") {
    return ["username_file", "password_file"];
  }
  if (invocation.operation === "smb_share_list" || invocation.operation === "rpc_domain_info") {
    return ["samba_auth_file"];
  }
  return ["ldap_bind_identity"];
}

function sameCredentialReceipt(
  expected: WindowsIdentityCredentialBindingReceipt,
  observed: WindowsIdentityCredentialBindingReceipt,
): boolean {
  return expected.schemaVersion === observed.schemaVersion
    && expected.referenceId === observed.referenceId
    && expected.runId === observed.runId
    && expected.actionFingerprint === observed.actionFingerprint
    && expected.mountedReadOnly === observed.mountedReadOnly
    && expected.privateToProcess === observed.privateToProcess
    && expected.expiresAt === observed.expiresAt
    && expected.grantsAuthorization === observed.grantsAuthorization
    && [...expected.availableViews].sort().join("\u0000")
      === [...observed.availableViews].sort().join("\u0000");
}

function killGroup(child: ChildProcess, signal: NodeJS.Signals): void {
  try {
    if (child.pid) process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    try { child.kill(signal); } catch { /* already terminal */ }
  }
}

export class DirectWindowsIdentityProcessAdapter implements WindowsIdentityExecutionAdapter {
  readonly adapterId: string;
  private readonly pack = new WindowsIdentityToolPack();
  private readonly readinessReceipts = new Map<WindowsIdentityToolId, WindowsIdentityToolReadinessReceipt>();
  private readonly active = new Map<string, ActiveProcess>();
  private readonly activeRuns = new Set<string>();
  private readonly clock: () => Date;

  constructor(private readonly options: DirectWindowsIdentityProcessAdapterOptions) {
    this.adapterId = options.adapterId?.trim() || "ti-scale:windows-identity-process";
    if (!PUBLIC_ID.test(this.adapterId)
      || !isAbsolute(options.sandboxExecutable.path)
      || !SHA256.test(options.sandboxExecutable.expectedSha256)) {
      throw new Error("Windows identity adapter binding is invalid");
    }
    if (options.runtimeTimeoutCapMs !== undefined
      && (!Number.isSafeInteger(options.runtimeTimeoutCapMs)
        || options.runtimeTimeoutCapMs < 1
        || options.runtimeTimeoutCapMs > 30_000)) {
      throw new RangeError("Windows identity runtime timeout cap must be 1-30000 ms");
    }
    if (options.runtimeOutputCapBytes !== undefined
      && (!Number.isSafeInteger(options.runtimeOutputCapBytes)
        || options.runtimeOutputCapBytes < 1
        || options.runtimeOutputCapBytes > 16 * 1024 * 1024)) {
      throw new RangeError("Windows identity runtime output cap must be 1-16777216 bytes");
    }
    this.clock = options.now ?? (() => new Date());
  }

  readiness(toolId: WindowsIdentityToolId): WindowsIdentityToolReadinessReceipt | null {
    const receipt = this.readinessReceipts.get(toolId);
    if (!receipt || Date.parse(receipt.expiresAt) <= this.clock().getTime()) return null;
    return receipt;
  }

  acceptReadinessReceipts(receipts: readonly WindowsIdentityToolReadinessReceipt[]): void {
    const next = new Map<WindowsIdentityToolId, WindowsIdentityToolReadinessReceipt>();
    for (const receipt of receipts) {
      const definition = this.pack.resolveTool(receipt.toolId);
      if (!definition || receipt.status !== "ready" || receipt.code !== "ready"
        || receipt.executablePath !== definition.executable.path
        || receipt.expectedExecutableSha256 !== definition.executable.sha256
        || receipt.observedExecutableSha256 !== definition.executable.sha256
        || !receipt.workspaceConfinementReady || !receipt.credentialIsolationReady
        || !receipt.outputBoundReady || !receipt.cancellationReady
        || receipt.grantsMissionExecution !== false
        || Date.parse(receipt.expiresAt) <= this.clock().getTime()) {
        continue;
      }
      next.set(receipt.toolId, Object.freeze(structuredClone(receipt)));
    }
    this.readinessReceipts.clear();
    for (const [toolId, receipt] of next) this.readinessReceipts.set(toolId, receipt);
  }

  async boundaryReadiness(toolId: WindowsIdentityToolId, signal?: AbortSignal): Promise<Readonly<{
    workspaceConfinementReady: boolean;
    credentialIsolationReady: boolean;
    outputBoundReady: boolean;
    cancellationReady: boolean;
  }>> {
    const assertCurrent = (): void => {
      if (signal?.aborted) boundary("windows_identity_cancelled");
    };
    assertCurrent();
    const definition = this.pack.resolveTool(toolId);
    if (!definition) boundary("windows_identity_tool_unavailable");
    const needsCredentials = !definition.authenticationModes.includes("anonymous");
    try {
      const credentialResolverReady = !needsCredentials
        || Boolean(this.options.credentialResolver)
          && (this.options.credentialResolver?.readiness
            ? await this.options.credentialResolver.readiness()
            : true);
      assertCurrent();
      const sandbox = await openedReviewedFile(
        this.options.sandboxExecutable.path,
        this.options.sandboxExecutable.expectedSha256,
        MAX_EXECUTABLE_BYTES,
        true,
      );
      assertCurrent();
      const executable = await openedReviewedFile(
        definition.executable.path,
        definition.executable.sha256,
        MAX_EXECUTABLE_BYTES,
        true,
      );
      await sandbox.handle.close();
      await executable.handle.close();
      assertCurrent();
      const capabilityChecks = await Promise.all([
        fileCapabilitiesAbsent(this.options.sandboxExecutable.path, signal),
        fileCapabilitiesAbsent(definition.executable.path, signal),
      ]);
      assertCurrent();
      const bounded = capabilityChecks.every(Boolean);
      return Object.freeze({
        workspaceConfinementReady: bounded,
        credentialIsolationReady: bounded && credentialResolverReady,
        outputBoundReady: bounded,
        cancellationReady: bounded,
      });
    } catch {
      return Object.freeze({
        workspaceConfinementReady: false,
        credentialIsolationReady: false,
        outputBoundReady: false,
        cancellationReady: false,
      });
    }
  }

  async execute(
    invocation: CompiledWindowsIdentityInvocation,
    signal: AbortSignal,
  ): Promise<WindowsIdentityRawResult> {
    const definition = this.pack.resolveTool(invocation.toolId);
    const readiness = this.readiness(invocation.toolId);
    if (!definition || !readiness) boundary("windows_identity_tool_unavailable");
    if (signal.aborted) boundary("windows_identity_cancelled");
    if (invocation.schemaVersion !== "ti-scale.windows-identity-invocation.v1"
      || (invocation.journey === "guided"
        ? invocation.action.arguments.schemaVersion
          !== WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION
        : invocation.action.arguments.schemaVersion
          !== REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION)
      || invocation.action.actionType !== invocation.toolId
      || invocation.action.runId.length < 1
      || !SHA256.test(invocation.actionFingerprint)
      || invocation.executablePath !== definition.executable.path
      || invocation.executableSha256 !== definition.executable.sha256
      || invocation.shell !== false || invocation.directArgv !== true
      || invocation.targetReadOnly !== true || invocation.evidencePromotion !== "none"
      || !this.pack.executionShapeMatches(invocation)) {
      boundary("windows_identity_tool_identity_changed");
    }
    if (this.activeRuns.has(invocation.action.runId)) {
      boundary("windows_identity_concurrency_exhausted");
    }
    this.activeRuns.add(invocation.action.runId);
    try {
    const workspace = await this.options.workspaceResolver.resolve(invocation.logicalWorkspace);
    if (workspace.status !== "resolved" || !workspace.resolvedPath) {
      boundary("windows_identity_workspace_not_confined");
    }
    const workspacePath = await realpath(workspace.resolvedPath);
    if (workspacePath !== workspace.resolvedPath) boundary("windows_identity_workspace_not_confined");
    await Promise.all([
      mkdir(`${workspacePath}/.tool-state/cache`, { recursive: true, mode: 0o700 }),
      mkdir(`${workspacePath}/.tool-state/config`, { recursive: true, mode: 0o700 }),
      mkdir(`${workspacePath}/.tool-state/data`, { recursive: true, mode: 0o700 }),
    ]);

    const sandboxSource = await openedReviewedFile(
      this.options.sandboxExecutable.path,
      this.options.sandboxExecutable.expectedSha256,
      MAX_EXECUTABLE_BYTES,
      true,
    );
    const toolSource = await openedReviewedFile(
      definition.executable.path,
      definition.executable.sha256,
      MAX_EXECUTABLE_BYTES,
      true,
    );
    const capabilityChecks = await Promise.all([
      fileCapabilitiesAbsent(this.options.sandboxExecutable.path, signal),
      fileCapabilitiesAbsent(definition.executable.path, signal),
    ]);
    if (!capabilityChecks.every(Boolean)) {
      await sandboxSource.handle.close();
      await toolSource.handle.close();
      boundary("windows_identity_tool_identity_changed");
    }

    const requiredViews = requiredCredentialViews(invocation);
    const credentialFiles: { view: WindowsIdentityCredentialView; file: OpenedFile }[] = [];
    if (invocation.credentialReference) {
      if (!invocation.credentialBindingReceipt || !this.options.credentialResolver) {
        await sandboxSource.handle.close();
        await toolSource.handle.close();
        boundary("windows_identity_credential_binding_missing");
      }
      const material = await this.options.credentialResolver.resolve({
        reference: invocation.credentialReference,
        runId: invocation.action.runId,
        actionFingerprint: invocation.actionFingerprint,
        requiredViews,
      });
      if (!sameCredentialReceipt(invocation.credentialBindingReceipt, material.receipt)
        || requiredViews.some((view) => typeof material.files[view] !== "string")) {
        await sandboxSource.handle.close();
        await toolSource.handle.close();
        boundary("windows_identity_credential_binding_changed");
      }
      for (const view of requiredViews) {
        credentialFiles.push({
          view,
          file: await openedReviewedFile(
            material.files[view]!,
            null,
            MAX_CREDENTIAL_FILE_BYTES,
            false,
          ),
        });
      }
    }

    await sandboxSource.handle.close();
    await toolSource.handle.close();
    const sandboxFd = await sealedMemfd(sandboxSource.bytes, "ti-scale-identity-sandbox");
    const toolFd = await sealedMemfd(toolSource.bytes, "ti-scale-identity-tool");
    const inheritedCredentialFds: number[] = [];
    for (const { file } of credentialFiles) {
      await file.handle.close();
      inheritedCredentialFds.push(await sealedMemfd(file.bytes, "ti-scale-identity-credential"));
      file.bytes.fill(0);
    }
    const resolverMount = existsSync("/run/systemd/resolve/stub-resolv.conf")
      ? [
          "--dir", "/run/systemd", "--dir", "/run/systemd/resolve",
          "--ro-bind", "/run/systemd/resolve/stub-resolv.conf",
          "/run/systemd/resolve/stub-resolv.conf",
        ]
      : [];
    const args = [
      // spawn() creates a detached, terminal-free host session. Do not create
      // another session inside bwrap: its PID-namespace child must remain in
      // the exact host process group owned by cancellation and force-kill.
      "--die-with-parent", "--unshare-user-try",
      "--unshare-pid", "--unshare-uts", "--unshare-ipc",
      "--ro-bind", "/usr", "/usr",
      "--ro-bind", "/lib", "/lib",
      "--ro-bind", "/lib64", "/lib64",
      "--ro-bind", "/etc", "/etc",
      ...resolverMount,
      "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
      "--bind", workspacePath, "/workspace",
      "--dir", "/run/ti-scale", "--dir", "/run/ti-scale/credential",
      ...inheritedCredentialFds.flatMap((_descriptor, index) => [
        "--keep-fd", String(5 + index),
      ]),
      ...credentialFiles.flatMap(({ view }, index) => [
        "--ro-bind", `/proc/self/fd/${5 + index}`, SANDBOX_CREDENTIAL_PATHS[view],
      ]),
      "--clearenv",
      ...Object.entries(FIXED_ENVIRONMENT).flatMap(([key, value]) => ["--setenv", key, value]),
      "--chdir", "/workspace",
      "--", "/proc/self/fd/4", ...invocation.arguments,
    ];
    const startedAt = this.clock();
    const stdio = ["ignore", "pipe", "pipe", sandboxFd, toolFd, ...inheritedCredentialFds] as const;
    let child: ChildProcess;
    try {
      child = spawn("/proc/self/fd/3", args, {
        cwd: "/",
        env: {},
        shell: false,
        detached: true,
        windowsHide: true,
        stdio: [...stdio],
      });
    } catch {
      closeSync(sandboxFd);
      closeSync(toolFd);
      for (const descriptor of inheritedCredentialFds) closeSync(descriptor);
      boundary("windows_identity_tool_deterministic_error");
    }
    closeSync(sandboxFd);
    closeSync(toolFd);
    for (const descriptor of inheritedCredentialFds) closeSync(descriptor);

    const termination: { value: "none" | "cancelled" | "timed_out" | "output_limit" } = {
      value: "none",
    };
    let forceKill: ReturnType<typeof setTimeout> | undefined;
    const terminate = (reason: "cancelled" | "timed_out" | "output_limit") => {
      if (termination.value !== "none") return;
      termination.value = reason;
      killGroup(child, "SIGTERM");
      forceKill = setTimeout(() => killGroup(child, "SIGKILL"), definition.execution.terminationGraceMs);
      forceKill.unref?.();
    };
    this.active.set(invocation.actionFingerprint, {
      runId: invocation.action.runId,
      child,
      terminate,
    });
    const abort = () => terminate("cancelled");
    signal.addEventListener("abort", abort, { once: true });
    const timeoutMs = Math.min(
      invocation.timeoutMs,
      this.options.runtimeTimeoutCapMs ?? invocation.timeoutMs,
    );
    const maximumOutputBytes = Math.min(
      invocation.maximumOutputBytes,
      this.options.runtimeOutputCapBytes ?? invocation.maximumOutputBytes,
    );
    const timeout = setTimeout(() => terminate("timed_out"), timeoutMs);
    timeout.unref?.();
    const stdoutParts: Buffer[] = [];
    const stderrParts: Buffer[] = [];
    let observedOutputBytes = 0;
    let retainedOutputBytes = 0;
    const capture = (parts: Buffer[], chunk: Buffer | string) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      observedOutputBytes += bytes.length;
      const remaining = Math.max(0, maximumOutputBytes - retainedOutputBytes);
      if (remaining > 0) {
        const retained = bytes.subarray(0, remaining);
        parts.push(Buffer.from(retained));
        retainedOutputBytes += retained.length;
      }
      if (observedOutputBytes > maximumOutputBytes) terminate("output_limit");
    };
    child.stdout?.on("data", (chunk) => capture(stdoutParts, chunk as Buffer));
    child.stderr?.on("data", (chunk) => capture(stderrParts, chunk as Buffer));

    const completion = await new Promise<Readonly<{
      exitCode: number | null;
      signal: NodeJS.Signals | null;
    }>>((resolve) => {
      let settled = false;
      child.once("error", () => {
        if (settled) return;
        settled = true;
        resolve({ exitCode: null, signal: null });
      });
      child.once("close", (exitCode, closeSignal) => {
        if (settled) return;
        settled = true;
        resolve({ exitCode, signal: closeSignal });
      });
    });
    clearTimeout(timeout);
    if (forceKill) clearTimeout(forceKill);
    signal.removeEventListener("abort", abort);
    this.active.delete(invocation.actionFingerprint);
    const endedAt = this.clock();
    const stdout = redactWindowsIdentityOutput(Buffer.concat(stdoutParts).toString("utf8"));
    const stderr = redactWindowsIdentityOutput(Buffer.concat(stderrParts).toString("utf8"));
    const outputSha256 = createHash("sha256")
      .update(stdout, "utf8").update("\u0000", "utf8").update(stderr, "utf8").digest("hex");
    const outputTruncated = termination.value === "output_limit";
    const cancelled = termination.value === "cancelled";
    const timedOut = termination.value === "timed_out";
    const receipt = Object.freeze({
      schemaVersion: WINDOWS_IDENTITY_EXECUTION_RECEIPT_SCHEMA_VERSION,
      adapterId: this.adapterId,
      toolId: invocation.toolId,
      actionFingerprint: invocation.actionFingerprint,
      runId: invocation.action.runId,
      executableSha256: toolSource.sha256,
      sandboxExecutableSha256: sandboxSource.sha256,
      logicalWorkspace: invocation.logicalWorkspace,
      credentialReferenceId: invocation.credentialReference?.id ?? null,
      directArgv: true as const,
      shell: false as const,
      targetReadOnly: true as const,
      workspaceConfined: true as const,
      credentialsMountedReadOnly: true as const,
      outputRedacted: true as const,
      outputSha256,
      startedAt: startedAt.toISOString(),
      endedAt: endedAt.toISOString(),
      wallClockMs: Math.max(0, endedAt.getTime() - startedAt.getTime()),
      exitCode: completion.exitCode,
      signal: completion.signal,
      timedOut,
      cancelled,
      outputTruncated,
      grantsAuthorization: false as const,
    });
    return Object.freeze({
      schemaVersion: WINDOWS_IDENTITY_RESULT_SCHEMA_VERSION,
      toolId: invocation.toolId,
      actionFingerprint: invocation.actionFingerprint,
      exitCode: completion.exitCode,
      signal: completion.signal,
      stdout,
      stderr,
      observedOutputBytes,
      retainedOutputBytes,
      outputSha256,
      outputTruncated,
      timedOut,
      cancelled,
      startedAt: startedAt.toISOString(),
      endedAt: endedAt.toISOString(),
      receipt,
    });
    } finally {
      this.activeRuns.delete(invocation.action.runId);
    }
  }

  async cancelRun(runId: string, _reason: string): Promise<void> {
    const active = [...this.active.values()].filter((process) => process.runId === runId);
    const completions = active.map(({ child }) => new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) {
        resolve();
        return;
      }
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        resolve();
      };
      child.once("close", done);
      child.once("error", done);
    }));
    for (const process of active) process.terminate("cancelled");
    await Promise.all(completions);
  }
}

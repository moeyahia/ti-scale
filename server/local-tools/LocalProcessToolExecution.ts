import { createHash } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import {
  closeSync,
  constants as fsConstants,
  fchmodSync,
  write as writeCallback,
  type BigIntStats,
} from "node:fs";
import {
  lstat,
  open,
  realpath,
  type FileHandle,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { isAbsolute, resolve, sep } from "node:path";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import {
  EVIDENCE_TYPE_DEFINITIONS,
  classifyOperationalInput,
} from "../domain";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import {
  ActionRepository,
  ExecutionBoundaryError,
  RunRepository,
  reviewedLocalToolActionEnvelope,
  type DurableAction,
} from "../orchestration";
import { ControlPlaneLeaseError, ControlPlaneLeaseService } from "../control-plane";
import type {
  ExecutionResult,
  ExecutionResultReceipt,
  ExecutionResultSink,
  ResultAwareExecutionPort,
} from "../command-runtime/types";
import { FAILURE_CATEGORIES, type FailureCategory } from "../supervisor";
import {
  EngagementWorkspaceResolver,
} from "../system-capabilities";
import { OperationalTruthService } from "../intelligence-v24";
import {
  LocalToolCapabilityManifest,
  type CompiledLocalToolInvocation,
} from "./LocalToolCapabilityManifest";
import { LocalToolInstallationPreflight } from "./LocalToolInstallationPreflight";
import { inspectLinuxFileCapabilities } from "./AsyncFileCapabilityInspection";
import {
  REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID,
  REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION,
  normalizeReviewedLocalToolObservation,
} from "./ReviewedLocalToolObservationNormalizer";
import { ReviewedNmapTopologyMaterializer } from "./ReviewedNmapTopologyMaterializer";

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024;
const MAX_TERMINAL_RECEIPTS = 100_000;
const F_ADD_SEALS = 1033;
const F_GET_SEALS = 1034;
const REQUIRED_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008;
const MFD_ALLOW_SEALING = 0x0002;
const SNAPSHOT_COPY_CHUNK_BYTES = 1024 * 1024;
const FIXED_ENVIRONMENT = Object.freeze({
  HOME: "/nonexistent",
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
} as const);

export const LOCAL_PROCESS_ADAPTER_READINESS_SCHEMA_VERSION =
  "ti-scale.local-process-adapter-readiness.v1" as const;
export const LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION =
  "ti-scale.local-process-tool-invocation.v1" as const;
export const LOCAL_TOOL_RESULT_DELIVERY_SCHEMA_VERSION =
  "ti-scale.local-tool-result-delivery.v1" as const;

interface PersistedLocalToolExecutionResult {
  readonly schemaVersion: typeof LOCAL_TOOL_RESULT_DELIVERY_SCHEMA_VERSION;
  readonly actionId: string;
  readonly runId: string;
  readonly actionFingerprint: string;
  readonly success: boolean;
  readonly summary: string;
  readonly failureCode: string | null;
  readonly failureCategory: FailureCategory | null;
  readonly circuitKey: string | null;
  readonly wallClockMs: number;
}

interface LocalToolTerminalPayload extends Record<string, unknown> {
  readonly engagementLogId: string | null;
  readonly observationIds: readonly string[];
  readonly evidenceCandidateIds: readonly string[];
  readonly evidenceIds: readonly string[];
  readonly artifactIds: readonly string[];
  readonly outputSha256: string;
  readonly outputTruncated: boolean;
  readonly deliveryResult: PersistedLocalToolExecutionResult;
  readonly resultAccepted: boolean;
  readonly duplicateResult: boolean;
  readonly deliveryAttemptCount: number;
  readonly deliveryLastAttemptAt: string | null;
  readonly deliveryLastError: string | null;
}

interface PendingLocalToolResultRow {
  readonly invocation_id: string;
  readonly tool_status: string;
  readonly redacted_payload_json: string | null;
  readonly action_id: string;
  readonly run_id: string;
  readonly action_fingerprint: string;
}

interface BunFfiLibrary {
  readonly symbols: Readonly<{
    memfd_create(label: Buffer, flags: number): number;
    fcntl(descriptor: number, operation: number, argument: number): number;
  }>;
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

export interface LocalProcessAdapterReadinessReceipt {
  readonly schemaVersion: typeof LOCAL_PROCESS_ADAPTER_READINESS_SCHEMA_VERSION;
  readonly adapterId: string;
  readonly manifestSha256: string;
  readonly sandboxExecutableSha256: string;
  readonly tools: readonly Readonly<{
    toolId: string;
    bindingSha256: string;
    expectedExecutableSha256: string;
    installationReceiptSha256: string;
  }>[];
  readonly sandboxExecutableIdentity: ExecutableIdentity;
  readonly boundary: Readonly<{
    platform: "linux";
    directArgv: true;
    shell: false;
    fixedEnvironmentSha256: string;
    workspaceResolver: true;
    filesystemSandbox: "bubblewrap_minimal_read_only_host_workspace_write";
    totalOutputBound: true;
    cooperativeCancellation: true;
    processGroupCleanup: true;
    resultSinkBound: true;
    targetContact: false;
  }>;
  readonly observedAt: string;
  readonly expiresAt: string;
  /** This receipt is one activation input; it never grants mission authority. */
  readonly grantsMissionExecution: false;
  readonly receiptSha256: string;
}

export interface LocalProcessToolInvocation {
  readonly schemaVersion: typeof LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION;
  readonly invocationId: string;
  readonly action: DurableAction;
  readonly toolId: string;
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly inputSha256: string;
  readonly resolvedWorkspacePath: string;
}

export type LocalProcessTermination =
  | "exited"
  | "spawn_error"
  | "timed_out"
  | "output_limit";

export interface LocalProcessToolResult {
  readonly invocationId: string;
  readonly action: DurableAction;
  readonly toolId: string;
  readonly startedAt: string;
  readonly endedAt: string;
  readonly wallClockMs: number;
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly termination: LocalProcessTermination;
  readonly spawnErrorCode: string | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly observedOutputBytes: number;
  readonly retainedOutputBytes: number;
  readonly outputSha256: string;
  readonly outputTruncated: boolean;
  readonly executable: Readonly<{
    sourcePath: string;
    sourceSha256: string;
    snapshotSha256: string;
    sandboxPath: "/run/ti-scale/tool";
  }>;
  readonly sandbox: Readonly<{
    executablePath: string;
    executableSha256: string;
    shell: false;
    environmentSha256: string;
  }>;
}

export type ReviewedLocalToolSemanticOutcome =
  | "positive_observation"
  | "negative_observation"
  | "execution_failure";

export interface ReviewedLocalToolResultClassification {
  readonly success: boolean;
  readonly outcome: ReviewedLocalToolSemanticOutcome;
  readonly category?: FailureCategory;
  readonly code?: string;
  readonly summary: string;
}

export interface LocalProcessToolResultSink {
  acceptLocalProcessToolResult(result: LocalProcessToolResult): Promise<void>;
}

/** Minimal transport boundary consumed by the reviewed result-aware port. */
export interface ReviewedLocalProcessInvocationAdapter {
  bindResultSink(sink: LocalProcessToolResultSink): void | (() => void);
  dispatch(invocation: LocalProcessToolInvocation, signal: AbortSignal): Promise<void>;
  cancelRun(runId: string, reason: string): Promise<void>;
}

export interface LocalToolExecutionOutputRecord {
  readonly logRecordId: string;
  readonly observationIds: readonly string[];
  readonly evidenceCandidateIds: readonly string[];
  /** Empty for the generic recorder; a specialized verifier may return immutable evidence IDs. */
  readonly evidenceIds: readonly string[];
  readonly artifactIds: readonly string[];
  /**
   * Optional deterministic domain result. The execution port accepts it only
   * when its durable action/run/fingerprint correlation is exact.
   */
  readonly executionResult?: ExecutionResult;
}

export interface LocalToolExecutionOutputRecorder {
  record(result: LocalProcessToolResult): LocalToolExecutionOutputRecord;
}

export interface LocalProcessToolAdapterOptions {
  readonly manifest: LocalToolCapabilityManifest;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  /** Compatibility-only location; execution uses a sealed memfd, never a mutable on-disk snapshot. */
  readonly sandboxStateRoot?: string;
  readonly sandboxExecutable: Readonly<{
    readonly path: string;
    readonly expectedSha256: string;
  }>;
  readonly adapterId?: string;
  readonly now?: () => Date;
}

function localProcessBoundaryFailureCategory(code: string): FailureCategory {
  if (/(?:cancelled|canceled)/u.test(code)) return "operator_rejection";
  if (/(?:target|scope)/u.test(code)) return "scope_conflict";
  if (/(?:authorization|not_authorized)/u.test(code)) return "authorization_denied";
  if (/(?:binding|canonical|duplicate|policy|decision|invocation_invalid|compiler_boundary)/u.test(code)) {
    return "policy_denied";
  }
  if (/(?:timeout|timed_out)/u.test(code)) return "timeout";
  // Missing/changed executables, sandbox/workspace/result-sink readiness, and
  // file-capability inspection failures are local runtime dependencies. They
  // remain non-retryable until a fresh readiness wave proves the dependency.
  return "dependency_missing";
}

export class LocalProcessToolExecutionError extends ExecutionBoundaryError {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(code, localProcessBoundaryFailureCategory(code), message);
    this.name = "LocalProcessToolExecutionError";
  }
}

export interface ExecutableIdentity {
  readonly sha256: string;
  readonly device: string;
  readonly inode: string;
  readonly sizeBytes: number;
  readonly mode: number;
  readonly uid: number;
  readonly gid: number;
}

interface ReviewedExecutableSnapshot {
  readonly descriptor: number;
  readonly identity: ExecutableIdentity;
}

export interface LocalProcessAdapterResourceSnapshot {
  readonly activeSnapshotDescriptors: number;
  readonly activeSnapshotBytes: number;
  readonly sealedSnapshotsCreated: number;
  readonly sealedSnapshotBytesCopied: number;
}

interface ActiveProcess {
  readonly invocation: LocalProcessToolInvocation;
  readonly child: ChildProcess;
  readonly done: Promise<void>;
  cancelled: boolean;
  cancellationReason: string | null;
  terminate(reason: "cancelled" | "timed_out" | "output_limit", detail: string): void;
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

function sameExecutableMetadata(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function readinessAbortError(): Error {
  const error = new Error("Local process adapter readiness was cancelled");
  error.name = "AbortError";
  return error;
}

function invocationAbortError(): LocalProcessToolExecutionError {
  return new LocalProcessToolExecutionError(
    "invocation_cancelled",
    "The run was cancelled while Ti-Scale was preparing the immutable executable snapshot.",
  );
}

function assertSnapshotCurrent(
  signal: AbortSignal | undefined,
  abortError: () => Error,
): void {
  if (signal?.aborted) throw abortError();
}

const BUN_FFI_MODULE_SPECIFIER = ["bun", "ffi"].join(":");
const requireFromHere = createRequire(import.meta.url);

function openLocalProcessMemfdLibrary(): BunFfiLibrary {
  const { dlopen, FFIType } = requireFromHere(BUN_FFI_MODULE_SPECIFIER) as BunFfiRuntime;
  return dlopen("libc.so.6", {
    memfd_create: { args: [FFIType.cstring, FFIType.u32], returns: FFIType.i32 },
    fcntl: { args: [FFIType.i32, FFIType.i32, FFIType.i32], returns: FFIType.i32 },
  });
}

// Bun JIT-compiles the FFI wrapper. Reopening it for every dispatched action
// retained native arenas in the long-lived server, so the process owns one
// lazily opened function table instead of one table per snapshot.
let sharedLocalProcessMemfdLibrary:
  | ReturnType<typeof openLocalProcessMemfdLibrary>
  | undefined;

function localProcessMemfdLibrary(): ReturnType<typeof openLocalProcessMemfdLibrary> {
  sharedLocalProcessMemfdLibrary ??= openLocalProcessMemfdLibrary();
  return sharedLocalProcessMemfdLibrary;
}

function writeDescriptor(
  descriptor: number,
  buffer: Buffer,
  offset: number,
  length: number,
  position: number,
): Promise<number> {
  return new Promise((resolveWrite, rejectWrite) => {
    // libuv owns the potentially throttled shmem write. The server event loop
    // remains able to serve health checks and observe cancellation meanwhile.
    writeCallback(descriptor, buffer, offset, length, position, (error, written) => {
      if (error) rejectWrite(error);
      else resolveWrite(written);
    });
  });
}

class LocalProcessSnapshotResources {
  private readonly active = new Map<number, number>();
  private created = 0;
  private copied = 0;

  create(sizeBytes: number): number {
    const descriptor = localProcessMemfdLibrary().symbols.memfd_create(
      Buffer.from("ti-scale-local-tool\0"),
      MFD_ALLOW_SEALING,
    );
    if (descriptor < 0) {
      throw new LocalProcessToolExecutionError(
        "sealed_snapshot_failed",
        "Ti-Scale could not create the immutable in-memory executable snapshot.",
      );
    }
    this.active.set(descriptor, sizeBytes);
    return descriptor;
  }

  copiedBytes(bytes: number): void {
    this.copied += bytes;
  }

  markSealed(): void {
    this.created += 1;
  }

  close(descriptor: number): void {
    if (!this.active.has(descriptor)) return;
    try { closeSync(descriptor); } catch { /* already closed by a failed native boundary */ }
    this.active.delete(descriptor);
  }

  snapshot(): LocalProcessAdapterResourceSnapshot {
    return Object.freeze({
      activeSnapshotDescriptors: this.active.size,
      activeSnapshotBytes: [...this.active.values()].reduce((total, bytes) => total + bytes, 0),
      sealedSnapshotsCreated: this.created,
      sealedSnapshotBytesCopied: this.copied,
    });
  }
}

function sealSnapshot(descriptor: number, mode: 0o400 | 0o500): void {
  try {
    fchmodSync(descriptor, mode);
    const library = localProcessMemfdLibrary();
    if (library.symbols.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS) !== 0
      || library.symbols.fcntl(descriptor, F_GET_SEALS, 0) !== REQUIRED_SEALS) {
      throw new Error("memfd_seal_failed");
    }
  } catch (error) {
    throw new LocalProcessToolExecutionError(
      "sealed_snapshot_failed",
      error instanceof Error ? error.message : "The immutable snapshot could not be sealed.",
    );
  }
}

async function writeSnapshotChunk(
  resources: LocalProcessSnapshotResources,
  descriptor: number,
  chunk: Buffer,
  position: number,
  signal: AbortSignal | undefined,
  abortError: () => Error,
): Promise<void> {
  let written = 0;
  while (written < chunk.length) {
    assertSnapshotCurrent(signal, abortError);
    let count: number;
    try {
      count = await writeDescriptor(
        descriptor,
        chunk,
        written,
        chunk.length - written,
        position + written,
      );
    } catch (error) {
      throw new LocalProcessToolExecutionError(
        "sealed_snapshot_failed",
        error instanceof Error ? error.message : "The immutable snapshot write failed.",
      );
    }
    assertSnapshotCurrent(signal, abortError);
    if (count < 1) {
      throw new LocalProcessToolExecutionError(
        "sealed_snapshot_failed",
        "The immutable snapshot write ended before all reviewed bytes were copied.",
      );
    }
    resources.copiedBytes(count);
    written += count;
  }
}

async function reviewExecutable(input: Readonly<{
  path: string;
  expectedSha256: string;
  signal?: AbortSignal;
  abortError: () => Error;
  snapshotMode?: 0o500;
  resources?: LocalProcessSnapshotResources;
}>): Promise<Readonly<{
  identity: ExecutableIdentity;
  snapshot: ReviewedExecutableSnapshot | null;
}>> {
  const { path, expectedSha256 } = input;
  if (!isAbsolute(path) || !SHA256.test(expectedSha256)) {
    throw new LocalProcessToolExecutionError("executable_binding_invalid", "Executable path or SHA-256 binding is invalid.");
  }
  assertSnapshotCurrent(input.signal, input.abortError);
  const before = await lstat(path, { bigint: true }).catch(() => undefined);
  if (!before || before.isSymbolicLink() || !before.isFile()) {
    throw new LocalProcessToolExecutionError("executable_not_regular", "The reviewed executable is missing, linked, or not a regular file.");
  }
  assertSnapshotCurrent(input.signal, input.abortError);
  let handle: FileHandle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  } catch {
    throw new LocalProcessToolExecutionError(
      "executable_not_regular",
      "The reviewed executable could not be opened without following links.",
    );
  }
  let snapshotDescriptor = -1;
  let keepSnapshot = false;
  try {
    const metadata = await handle.stat({ bigint: true });
    if (!metadata.isFile() || !sameExecutableMetadata(before, metadata)) {
      throw new LocalProcessToolExecutionError("executable_identity_changed", "Executable identity changed while it was opened.");
    }
    const sizeBytes = Number(metadata.size);
    const mode = Number(metadata.mode & 0o7777n);
    const uid = Number(metadata.uid);
    const gid = Number(metadata.gid);
    const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
    if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 1 || sizeBytes > MAX_EXECUTABLE_BYTES
      || (uid !== 0 && uid !== currentUid) || (mode & 0o022) !== 0 || (mode & 0o7000) !== 0
      || !executableByCurrentIdentity(mode, uid, gid)) {
      throw new LocalProcessToolExecutionError("executable_permissions_unsafe", "Executable ownership, mode, size, or execution permission is unsafe.");
    }
    if (input.snapshotMode !== undefined) {
      if (!input.resources) throw new Error("Snapshot resources are required for executable snapshot creation");
      snapshotDescriptor = input.resources.create(sizeBytes);
    }
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(SNAPSHOT_COPY_CHUNK_BYTES, sizeBytes));
    let position = 0;
    while (position < sizeBytes) {
      assertSnapshotCurrent(input.signal, input.abortError);
      const read = await handle.read(buffer, 0, Math.min(buffer.length, sizeBytes - position), position);
      assertSnapshotCurrent(input.signal, input.abortError);
      if (read.bytesRead < 1) break;
      const chunk = buffer.subarray(0, read.bytesRead);
      digest.update(chunk);
      if (snapshotDescriptor >= 0) {
        await writeSnapshotChunk(
          input.resources!,
          snapshotDescriptor,
          chunk,
          position,
          input.signal,
          input.abortError,
        );
      }
      position += read.bytesRead;
    }
    if (position !== sizeBytes) {
      throw new LocalProcessToolExecutionError("executable_read_incomplete", "Executable bytes changed or could not be read completely.");
    }
    const sha256 = digest.digest("hex");
    if (sha256 !== expectedSha256) {
      throw new LocalProcessToolExecutionError("executable_hash_drift", "Executable SHA-256 no longer matches the reviewed manifest.");
    }
    assertSnapshotCurrent(input.signal, input.abortError);
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true }).catch(() => undefined);
    if (!pathAfter
      || !sameExecutableMetadata(metadata, after)
      || !sameExecutableMetadata(after, pathAfter)) {
      throw new LocalProcessToolExecutionError("executable_identity_changed", "Executable identity changed during its hash verification.");
    }
    const identity = Object.freeze({
      sha256,
      device: after.dev.toString(),
      inode: after.ino.toString(),
      sizeBytes,
      mode,
      uid,
      gid,
    } satisfies ExecutableIdentity);
    let snapshot: ReviewedExecutableSnapshot | null = null;
    if (snapshotDescriptor >= 0) {
      sealSnapshot(snapshotDescriptor, input.snapshotMode!);
      input.resources!.markSealed();
      snapshot = Object.freeze({ descriptor: snapshotDescriptor, identity });
      keepSnapshot = true;
    }
    return Object.freeze({ identity, snapshot });
  } finally {
    await handle.close().catch(() => undefined);
    if (snapshotDescriptor >= 0 && !keepSnapshot) input.resources?.close(snapshotDescriptor);
  }
}

async function inspectReviewedExecutable(
  path: string,
  expectedSha256: string,
  signal?: AbortSignal,
): Promise<ExecutableIdentity> {
  return (await reviewExecutable({
    path,
    expectedSha256,
    ...(signal ? { signal } : {}),
    abortError: readinessAbortError,
  })).identity;
}

async function createReviewedExecutableSnapshot(
  path: string,
  expectedSha256: string,
  resources: LocalProcessSnapshotResources,
  signal: AbortSignal,
): Promise<ReviewedExecutableSnapshot> {
  const result = await reviewExecutable({
    path,
    expectedSha256,
    signal,
    abortError: invocationAbortError,
    snapshotMode: 0o500,
    resources,
  });
  if (!result.snapshot) throw new Error("Executable snapshot result was not created");
  return result.snapshot;
}

async function createSealedInputSnapshot(
  bytes: Buffer,
  resources: LocalProcessSnapshotResources,
  signal: AbortSignal,
): Promise<number> {
  assertSnapshotCurrent(signal, invocationAbortError);
  const descriptor = resources.create(bytes.length);
  let keep = false;
  try {
    let position = 0;
    while (position < bytes.length) {
      const chunk = bytes.subarray(position, position + SNAPSHOT_COPY_CHUNK_BYTES);
      await writeSnapshotChunk(
        resources,
        descriptor,
        chunk,
        position,
        signal,
        invocationAbortError,
      );
      position += chunk.length;
    }
    sealSnapshot(descriptor, 0o400);
    resources.markSealed();
    keep = true;
    return descriptor;
  } finally {
    if (!keep) resources.close(descriptor);
  }
}

async function fileCapabilitiesAbsent(path: string, signal?: AbortSignal): Promise<boolean> {
  const result = await inspectLinuxFileCapabilities(path, signal ? { signal } : {});
  return result.state === "none";
}

function redactOutput(value: string): string {
  return value
    .replace(/\u001B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/gu, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/gu, "�")
    .replace(/-----BEGIN(?: RSA)? PRIVATE KEY-----[\s\S]*?-----END(?: RSA)? PRIVATE KEY-----/giu, "[REDACTED PRIVATE KEY]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/giu, "Bearer [REDACTED]")
    .replace(/\b(?:authorization|cookie|password|passwd|api[-_]?key|secret|session[-_]?token)\s*[:=]\s*[^\s,;]+/giu, (match) => `${match.split(/[:=]/u, 1)[0]}=[REDACTED]`)
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu, "[REDACTED JWT]")
    .replace(/\b(?:sk|rk|pk)-[A-Za-z0-9_-]{8,}\b/gu, "[REDACTED TOKEN]");
}

function killProcessGroup(child: ChildProcess, signal: NodeJS.Signals): void {
  if (child.pid && process.platform !== "win32") {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {
      // Cancellation can race the detached child's process-group setup. An
      // ESRCH for the group does not prove that the child itself is gone, so
      // always fall back to signalling the tracked process directly. The
      // bounded force-kill timer repeats this same group-first fallback.
    }
  }
  try { child.kill(signal); } catch { /* the tracked child is already terminal */ }
}

function minimalEtcBindings(): readonly string[] {
  const result: string[] = [];
  for (const path of [
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/gai.conf",
    "/etc/services",
    "/etc/protocols",
  ]) result.push("--ro-bind-try", path, path);
  return result;
}

function reviewedDynamicLoaderCompatibilityBindings(): readonly string[] {
  return [
    // Kali's libblas.so.3 linker name crosses from the read-only /usr tree to
    // /etc/alternatives. Expose only the selected capability-free library
    // target, not the alternatives directory or the host /etc tree.
    "--dir", "/etc/alternatives",
    "--ro-bind-try",
    "/usr/lib/x86_64-linux-gnu/blas/libblas.so.3",
    "/etc/alternatives/libblas.so.3-x86_64-linux-gnu",
  ];
}

function sandboxArguments(input: {
  readonly snapshotFd: number;
  readonly stagedInputFd: number | null;
  readonly workspacePath: string;
  readonly compiled: CompiledLocalToolInvocation;
}): readonly string[] {
  return [
    "--die-with-parent",
    // The launcher is spawned detached with no inherited terminal. Keeping
    // the sandbox command in that launcher-owned process group is essential:
    // a second setsid() here would let bwrap's PID-namespace child escape the
    // exact group that cancellation and force-kill are required to reap.
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup",
    "--cap-drop", "ALL",
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--dir", "/etc",
    ...reviewedDynamicLoaderCompatibilityBindings(),
    ...minimalEtcBindings(),
    "--dir", "/etc/ssl",
    "--ro-bind-try", "/etc/ssl/certs", "/etc/ssl/certs",
    // None of the reviewed direct-argv tools requires process metadata. An
    // empty /proc both withholds host process state and avoids requesting a
    // procfs mount that the hardened production systemd unit correctly denies.
    "--dir", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--dir", "/run",
    "--dir", "/run/ti-scale",
    "--perms", "0500",
    "--ro-bind-data", String(input.snapshotFd), "/run/ti-scale/tool",
    ...(input.stagedInputFd === null ? [] : [
      "--dir", "/run/ti-scale-input",
      "--perms", "0400",
      "--ro-bind-data", String(input.stagedInputFd), input.compiled.stagedInput.kind === "fixed_lines"
        ? input.compiled.stagedInput.mountPath
        : "/run/ti-scale-input/unused",
    ]),
    "--dir", "/workspace",
    "--bind", input.workspacePath, "/workspace",
    "--chdir", "/workspace",
    "--clearenv",
    "--setenv", "HOME", input.compiled.environment.HOME,
    "--setenv", "LANG", input.compiled.environment.LANG,
    "--setenv", "LC_ALL", input.compiled.environment.LC_ALL,
    "--",
    "/run/ti-scale/tool",
    ...input.compiled.arguments,
  ];
}

function targetMatchesAction(
  manifest: LocalToolCapabilityManifest,
  toolId: string,
  parameters: Readonly<Record<string, unknown>>,
  actionTarget: string,
): boolean {
  const tool = manifest.resolve(toolId);
  if (!tool) return false;
  const targetDefinitions = tool.parameters.filter(({ semantic }) => semantic.startsWith("authorized_"));
  if (targetDefinitions.length !== 1) return false;
  const target = parameters[targetDefinitions[0]!.name];
  if (typeof target !== "string") return false;
  if (tool.routing.targetKind === "url") return target === actionTarget;
  if (tool.routing.targetKind === "domain") {
    const normalized = (value: string) => (value.endsWith(".") ? value.slice(0, -1) : value).toLowerCase();
    return normalized(target) === normalized(actionTarget);
  }
  if (tool.routing.intent !== "tcp_connect") return target === actionTarget;
  const portDefinition = tool.parameters.find(({ semantic }) => semantic === "tcp_port");
  const port = portDefinition ? parameters[portDefinition.name] : undefined;
  if (!Number.isSafeInteger(port)) return false;
  try {
    const parsed = new URL(actionTarget);
    return parsed.protocol === "tcp:"
      && parsed.username === "" && parsed.password === ""
      && parsed.pathname === "" && parsed.search === "" && parsed.hash === ""
      && parsed.hostname.toLowerCase() === target.toLowerCase()
      && Number(parsed.port) === port;
  } catch {
    return false;
  }
}

/**
 * Direct subprocess transport for reviewed local tools. It owns no mission
 * authority: callers must pass a canonical, already-authorized action. It
 * nevertheless recompiles the manifest, re-resolves the workspace, and
 * rechecks executable and sandbox hashes at the last possible boundary.
 */
export class DirectProcessLocalToolInvocationAdapter {
  readonly adapterId: string;
  private readonly now: () => Date;
  private readonly snapshotResources = new LocalProcessSnapshotResources();
  private readonly active = new Map<string, ActiveProcess>();
  private readonly terminal = new Set<string>();
  private resultSink?: LocalProcessToolResultSink;

  constructor(private readonly options: LocalProcessToolAdapterOptions) {
    this.adapterId = options.adapterId?.trim() || "ti-scale:reviewed-local-process";
    if (!PUBLIC_ID.test(this.adapterId)) throw new Error("Local process adapter ID is invalid");
    if (process.platform !== "linux") throw new Error("Reviewed local process execution requires Linux namespaces");
    if (options.sandboxStateRoot !== undefined
      && (!isAbsolute(options.sandboxStateRoot) || resolve(options.sandboxStateRoot) === resolve(sep))) {
      throw new Error("Sandbox state root must be a non-root absolute path");
    }
    if (!isAbsolute(options.sandboxExecutable.path) || !SHA256.test(options.sandboxExecutable.expectedSha256)) {
      throw new Error("Sandbox executable requires an absolute path and reviewed SHA-256");
    }
    this.now = options.now ?? (() => new Date());
  }

  bindResultSink(sink: LocalProcessToolResultSink): () => void {
    if (this.resultSink) throw new Error("Local process adapter result sink is already bound");
    this.resultSink = sink;
    return () => {
      if (this.resultSink === sink && this.active.size === 0) this.resultSink = undefined;
    };
  }

  /** Content-free accounting used to prove that dispatch descriptors drain. */
  resourceSnapshot(): LocalProcessAdapterResourceSnapshot {
    return this.snapshotResources.snapshot();
  }

  async readinessReceipt(
    now = this.now(),
    ttlMs = 60_000,
    signal?: AbortSignal,
  ): Promise<LocalProcessAdapterReadinessReceipt> {
    const assertCurrent = (): void => {
      if (!signal?.aborted) return;
      const error = new Error("Local process adapter readiness was cancelled");
      error.name = "AbortError";
      throw error;
    };
    assertCurrent();
    if (!this.resultSink) throw new Error("Local process result sink must be bound before readiness can be attested");
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 5 * 60_000) {
      throw new RangeError("Adapter readiness TTL must be between 1000 and 300000 ms");
    }
    const sandboxExecutableIdentity = await inspectReviewedExecutable(
      this.options.sandboxExecutable.path,
      this.options.sandboxExecutable.expectedSha256,
      signal,
    );
    assertCurrent();
    if (sandboxExecutableIdentity.uid !== 0
      || !await fileCapabilitiesAbsent(this.options.sandboxExecutable.path, signal)) {
      throw new LocalProcessToolExecutionError(
        "sandbox_file_capability_unknown_or_present",
        "The reviewed sandbox helper has Linux file capabilities or its capability state could not be verified.",
      );
    }
    assertCurrent();
    const preflight = new LocalToolInstallationPreflight({ now: () => now });
    const enabledTools = this.options.manifest.list().filter(({ activation }) => activation === "enabled");
    const installationReceipts = await Promise.all(enabledTools.map(async (tool) => {
      assertCurrent();
      const receipt = await preflight.inspectAsync(this.options.manifest, tool.toolId, signal);
      assertCurrent();
      if (receipt.status !== "ready") {
        throw new LocalProcessToolExecutionError(
          `tool_installation_${receipt.code}`,
          `${tool.toolId} did not pass the target-free installation and file-capability check.`,
        );
      }
      return { tool, receipt };
    }));
    assertCurrent();
    const unsigned = {
      schemaVersion: LOCAL_PROCESS_ADAPTER_READINESS_SCHEMA_VERSION,
      adapterId: this.adapterId,
      manifestSha256: this.options.manifest.descriptor.manifestSha256,
      sandboxExecutableSha256: this.options.sandboxExecutable.expectedSha256,
      tools: installationReceipts.map(({ tool, receipt }) => ({
        toolId: tool.toolId,
        bindingSha256: tool.bindingSha256,
        expectedExecutableSha256: tool.executable.expectedSha256,
        installationReceiptSha256: digestCanonicalJson(receipt, { maxBytes: 64 * 1_024, maxDepth: 16 }).sha256,
      })),
      sandboxExecutableIdentity,
      boundary: {
        platform: "linux" as const,
        directArgv: true as const,
        shell: false as const,
        fixedEnvironmentSha256: digestCanonicalJson(FIXED_ENVIRONMENT, { maxBytes: 1_024, maxDepth: 4 }).sha256,
        workspaceResolver: true as const,
        filesystemSandbox: "bubblewrap_minimal_read_only_host_workspace_write" as const,
        totalOutputBound: true as const,
        cooperativeCancellation: true as const,
        processGroupCleanup: true as const,
        resultSinkBound: true as const,
        targetContact: false as const,
      },
      observedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
      grantsMissionExecution: false as const,
    };
    return Object.freeze({
      ...unsigned,
      receiptSha256: digestCanonicalJson(unsigned, { maxBytes: 512 * 1_024, maxDepth: 16 }).sha256,
    });
  }

  private rememberTerminal(invocationId: string): void {
    if (this.terminal.size >= MAX_TERMINAL_RECEIPTS) {
      throw new LocalProcessToolExecutionError("terminal_receipt_capacity", "Local process terminal receipt capacity is exhausted; restart safely before accepting more work.");
    }
    this.terminal.add(invocationId);
  }

  async dispatch(invocation: LocalProcessToolInvocation, signal: AbortSignal): Promise<void> {
    const sink = this.resultSink;
    if (!sink) throw new LocalProcessToolExecutionError("result_sink_unbound", "Local process result sink is not bound.");
    if (invocation.schemaVersion !== LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION
      || !PUBLIC_ID.test(invocation.invocationId) || !PUBLIC_ID.test(invocation.toolId)
      || !SHA256.test(invocation.inputSha256)) {
      throw new LocalProcessToolExecutionError("invocation_invalid", "Local process invocation identity is invalid.");
    }
    if (this.active.has(invocation.invocationId) || this.terminal.has(invocation.invocationId)) {
      throw new LocalProcessToolExecutionError("duplicate_invocation", "This exact local process invocation was already accepted.");
    }
    if (this.terminal.size >= MAX_TERMINAL_RECEIPTS) {
      throw new LocalProcessToolExecutionError("terminal_receipt_capacity", "Local process terminal receipt capacity is exhausted; restart safely before accepting more work.");
    }
    if (signal.aborted) throw new LocalProcessToolExecutionError("invocation_cancelled", "The run was cancelled before local execution started.");
    const inputDigest = digestCanonicalJson(invocation.parameters, { maxBytes: 256 * 1_024, maxDepth: 32 }).sha256;
    if (inputDigest !== invocation.inputSha256) {
      throw new LocalProcessToolExecutionError("input_binding_changed", "Local tool parameters changed after durable authorization.");
    }
    const compiled = this.options.manifest.compileInvocation(invocation.toolId, invocation.parameters);
    if (compiled.shell !== false || compiled.authorizationGranted !== false
      || compiled.scopeEnforcementRequired !== true
      || digestCanonicalJson(compiled.environment, { maxBytes: 1_024, maxDepth: 4 }).sha256
        !== digestCanonicalJson(FIXED_ENVIRONMENT, { maxBytes: 1_024, maxDepth: 4 }).sha256) {
      throw new LocalProcessToolExecutionError("compiler_boundary_invalid", "Compiled local tool boundary is not the reviewed direct-argv contract.");
    }
    if (!targetMatchesAction(this.options.manifest, invocation.toolId, invocation.parameters, invocation.action.target)) {
      throw new LocalProcessToolExecutionError("target_binding_changed", "Compiled local tool target differs from the canonical authorized action target.");
    }
    const workspace = await this.options.workspaceResolver.resolve(compiled.logicalWorkspace);
    if (workspace.status !== "resolved" || !workspace.resolvedPath
      || workspace.resolvedPath !== invocation.resolvedWorkspacePath) {
      throw new LocalProcessToolExecutionError("workspace_binding_changed", "Resolved workspace differs from the durable dispatch receipt.");
    }
    const canonicalWorkspace = await realpath(invocation.resolvedWorkspacePath);
    const finalWorkspaceResolution = await this.options.workspaceResolver.resolve(compiled.logicalWorkspace);
    if (canonicalWorkspace !== invocation.resolvedWorkspacePath
      || finalWorkspaceResolution.status !== "resolved"
      || finalWorkspaceResolution.resolvedPath !== canonicalWorkspace) {
      throw new LocalProcessToolExecutionError("workspace_identity_changed", "Resolved workspace identity changed before process start.");
    }

    let installation: Awaited<ReturnType<LocalToolInstallationPreflight["inspectAsync"]>>;
    try {
      installation = await new LocalToolInstallationPreflight()
        .inspectAsync(this.options.manifest, invocation.toolId, signal);
    } catch (error) {
      if (signal.aborted || (error as Error).name === "AbortError") {
        throw invocationAbortError();
      }
      throw error;
    }
    if (installation.status !== "ready") {
      throw new LocalProcessToolExecutionError(
        `tool_installation_${installation.code}`,
        `${invocation.toolId} did not pass the target-free installation and file-capability check at dispatch.`,
      );
    }
    let sandboxSnapshot: ReviewedExecutableSnapshot | undefined;
    let toolSnapshot: ReviewedExecutableSnapshot | undefined;
    let stagedInputFd = -1;
    let sandboxIdentity!: ExecutableIdentity;
    let sourceIdentity!: ExecutableIdentity;
    let started!: Date;
    let child!: ChildProcess;
    try {
      sandboxSnapshot = await createReviewedExecutableSnapshot(
        this.options.sandboxExecutable.path,
        this.options.sandboxExecutable.expectedSha256,
        this.snapshotResources,
        signal,
      );
      toolSnapshot = await createReviewedExecutableSnapshot(
        compiled.executablePath,
        compiled.expectedExecutableSha256,
        this.snapshotResources,
        signal,
      );
      let sandboxCapabilitiesAbsent: boolean;
      let sourceCapabilitiesAbsent: boolean;
      try {
        [sandboxCapabilitiesAbsent, sourceCapabilitiesAbsent] = await Promise.all([
          fileCapabilitiesAbsent(this.options.sandboxExecutable.path, signal),
          fileCapabilitiesAbsent(compiled.executablePath, signal),
        ]);
      } catch (error) {
        if (signal.aborted || (error as Error).name === "AbortError") {
          throw invocationAbortError();
        }
        throw error;
      }
      if (!sandboxCapabilitiesAbsent
        || !sourceCapabilitiesAbsent
        || sandboxSnapshot.identity.uid !== 0) {
        throw new LocalProcessToolExecutionError(
          "file_capability_unknown_or_present",
          "A reviewed executable has Linux file capabilities or its capability state could not be verified.",
        );
      }
      assertSnapshotCurrent(signal, invocationAbortError);
      sandboxIdentity = sandboxSnapshot.identity;
      sourceIdentity = toolSnapshot.identity;
      if (compiled.stagedInput.kind === "fixed_lines") {
        const bytes = Buffer.from(`${compiled.stagedInput.lines.join("\n")}\n`, "utf8");
        if (createHash("sha256").update(bytes).digest("hex") !== compiled.stagedInput.contentSha256) {
          throw new LocalProcessToolExecutionError(
            "staged_input_binding_changed",
            "The fixed reviewed input no longer matches its manifest hash.",
          );
        }
        stagedInputFd = await createSealedInputSnapshot(
          bytes,
          this.snapshotResources,
          signal,
        );
      }
      started = this.now();
      const argv = sandboxArguments({
        snapshotFd: 4,
        stagedInputFd: stagedInputFd >= 0 ? 5 : null,
        workspacePath: canonicalWorkspace,
        compiled,
      });
      try {
        child = spawn("/proc/self/fd/3", argv, {
          cwd: "/",
          env: { ...compiled.environment },
          shell: false,
          detached: true,
          windowsHide: true,
          stdio: stagedInputFd >= 0
            ? ["ignore", "pipe", "pipe", sandboxSnapshot.descriptor, toolSnapshot.descriptor, stagedInputFd]
            : ["ignore", "pipe", "pipe", sandboxSnapshot.descriptor, toolSnapshot.descriptor],
        });
      } catch (error) {
        throw new LocalProcessToolExecutionError(
          (error as NodeJS.ErrnoException).code ?? "spawn_failed",
          "The reviewed sandbox process could not be started.",
        );
      }
    } finally {
      if (sandboxSnapshot) this.snapshotResources.close(sandboxSnapshot.descriptor);
      if (toolSnapshot) this.snapshotResources.close(toolSnapshot.descriptor);
      if (stagedInputFd >= 0) this.snapshotResources.close(stagedInputFd);
    }

    let resolveDone!: () => void;
    const done = new Promise<void>((resolveDonePromise) => { resolveDone = resolveDonePromise; });
    let finalized = false;
    let termination: LocalProcessTermination = "exited";
    let spawnErrorCode: string | null = null;
    let observedOutputBytes = 0;
    let retainedOutputBytes = 0;
    const stdoutParts: Buffer[] = [];
    const stderrParts: Buffer[] = [];
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let forceKill: ReturnType<typeof setTimeout> | undefined;

    const terminate = (reason: "cancelled" | "timed_out" | "output_limit", detail: string) => {
      if (finalized) return;
      if (reason === "cancelled") {
        active.cancelled = true;
        active.cancellationReason = detail;
      } else {
        termination = reason;
      }
      killProcessGroup(child, "SIGTERM");
      if (!forceKill) {
        forceKill = setTimeout(() => killProcessGroup(child, "SIGKILL"), compiled.terminationGraceMs);
        forceKill.unref?.();
      }
    };
    const active: ActiveProcess = {
      invocation,
      child,
      done,
      cancelled: false,
      cancellationReason: null,
      terminate,
    };
    this.active.set(invocation.invocationId, active);

    const capture = (parts: Buffer[], chunk: Buffer | string) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      observedOutputBytes += bytes.length;
      const remaining = Math.max(0, compiled.maximumOutputBytes - retainedOutputBytes);
      if (remaining > 0) {
        const retained = bytes.subarray(0, remaining);
        parts.push(Buffer.from(retained));
        retainedOutputBytes += retained.length;
      }
      if (observedOutputBytes > compiled.maximumOutputBytes) {
        terminate("output_limit", "Combined stdout and stderr exceeded the reviewed bound.");
      }
    };
    child.stdout?.on("data", (chunk) => capture(stdoutParts, chunk as Buffer));
    child.stderr?.on("data", (chunk) => capture(stderrParts, chunk as Buffer));
    child.once("error", (error) => {
      spawnErrorCode = (error as NodeJS.ErrnoException).code ?? error.name;
      termination = "spawn_error";
    });

    const abort = () => terminate("cancelled", String(signal.reason ?? "Run cancellation requested"));
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    timeout = setTimeout(() => terminate("timed_out", "Reviewed local tool deadline expired."), compiled.timeoutMs);
    timeout.unref?.();

    child.once("close", (exitCode, closeSignal) => {
      void (async () => {
        if (finalized) return;
        finalized = true;
        if (timeout) clearTimeout(timeout);
        if (forceKill) clearTimeout(forceKill);
        signal.removeEventListener("abort", abort);
        this.active.delete(invocation.invocationId);
        if (active.cancelled) {
          this.rememberTerminal(invocation.invocationId);
          resolveDone();
          return;
        }
        const ended = this.now();
        const stdout = redactOutput(Buffer.concat(stdoutParts).toString("utf8"));
        const stderr = redactOutput(Buffer.concat(stderrParts).toString("utf8"));
        const outputSha256 = createHash("sha256")
          .update(stdout, "utf8").update("\u0000", "utf8").update(stderr, "utf8").digest("hex");
        this.rememberTerminal(invocation.invocationId);
        const result: LocalProcessToolResult = Object.freeze({
          invocationId: invocation.invocationId,
          action: invocation.action,
          toolId: invocation.toolId,
          startedAt: started.toISOString(),
          endedAt: ended.toISOString(),
          wallClockMs: Math.max(0, ended.getTime() - started.getTime()),
          exitCode,
          signal: closeSignal,
          termination,
          spawnErrorCode,
          stdout,
          stderr,
          observedOutputBytes,
          retainedOutputBytes,
          outputSha256,
          outputTruncated: observedOutputBytes > retainedOutputBytes,
          executable: {
            sourcePath: compiled.executablePath,
            sourceSha256: sourceIdentity.sha256,
            snapshotSha256: sourceIdentity.sha256,
            sandboxPath: "/run/ti-scale/tool" as const,
          },
          sandbox: {
            executablePath: this.options.sandboxExecutable.path,
            executableSha256: sandboxIdentity.sha256,
            shell: false as const,
            environmentSha256: digestCanonicalJson(compiled.environment, { maxBytes: 1_024, maxDepth: 4 }).sha256,
          },
        });
        try {
          await sink.acceptLocalProcessToolResult(result);
        } finally {
          resolveDone();
        }
      })().catch(() => resolveDone());
    });
  }

  async resume(_invocation: LocalProcessToolInvocation, _signal: AbortSignal): Promise<void> {
    throw new LocalProcessToolExecutionError(
      "resume_requires_new_attempt",
      "A recovered local tool call requires a new bounded action and attempt identity; the previous invocation is never replayed.",
    );
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    const matching = [...this.active.values()].filter(({ invocation }) => invocation.action.runId === runId);
    for (const active of matching) active.terminate("cancelled", reason);
    await Promise.all(matching.map(({ done }) => done));
  }
}

function dnsResultMeansNoRecord(result: LocalProcessToolResult): boolean {
  const output = `${result.stdout}\n${result.stderr}`;
  return /\b(?:NXDOMAIN|NXRRSET)\b/iu.test(output)
    || /\bhas no [A-Z0-9-]+ record\b/iu.test(output);
}

function tcpResultMeansBoundedNegative(result: LocalProcessToolResult): boolean {
  const retained = `${result.stdout}\n${result.stderr}`;
  return /\bconnection refused\b/iu.test(retained)
    || /\b(?:connection\s+)?timed?\s*out\b/iu.test(retained)
    || /\bnetwork is unreachable\b/iu.test(retained)
    || /\bno route to host\b/iu.test(retained);
}

/**
 * Interprets only the stable exit contract of the reviewed local tools.
 * A negative reconnaissance answer is still a completed observation. Process
 * integrity failures and unrecognised non-zero exits always remain failures.
 */
export function classifyReviewedLocalToolResult(
  result: LocalProcessToolResult,
): ReviewedLocalToolResultClassification {
  if (result.termination === "timed_out") {
    return {
      success: false,
      outcome: "execution_failure",
      category: "timeout",
      code: "local_tool_timeout",
      summary: `${result.toolId} exceeded its reviewed time limit.`,
    };
  }
  if (result.termination === "output_limit") {
    return {
      success: false,
      outcome: "execution_failure",
      category: "policy_denied",
      code: "local_tool_output_limit",
      summary: `${result.toolId} exceeded its reviewed output limit and was stopped.`,
    };
  }
  if (result.termination === "spawn_error") {
    return {
      success: false,
      outcome: "execution_failure",
      category: "dependency_missing",
      code: result.spawnErrorCode ?? "local_tool_spawn_error",
      summary: `${result.toolId} could not start inside the reviewed sandbox.`,
    };
  }
  if (result.signal) {
    return {
      success: false,
      outcome: "execution_failure",
      category: "process_crash",
      code: `local_tool_signal_${result.signal}`,
      summary: `${result.toolId} ended unexpectedly under signal ${result.signal}.`,
    };
  }

  const expectedNegative =
    (result.toolId === "kali:ncat-tcp-connect"
      && result.exitCode === 1
      && tcpResultMeansBoundedNegative(result))
    || (result.toolId === "kali:ping-host-liveness" && result.exitCode === 1)
    || (result.toolId === "kali:curl-http-metadata" && result.exitCode === 22)
    || (result.toolId === "kali:host-dns-query"
      && (result.exitCode === 0 || result.exitCode === 1)
      && dnsResultMeansNoRecord(result));

  if (expectedNegative) {
    const summary = result.toolId === "kali:ncat-tcp-connect"
      ? "The bounded TCP check completed and did not establish a connection. This valid negative observation was retained in the Engagement Log."
      : result.toolId === "kali:ping-host-liveness"
        ? "The bounded host-liveness check completed without a reply. This valid negative observation was retained in the Engagement Log."
        : result.toolId === "kali:host-dns-query"
          ? "The DNS query completed without the requested record. This valid negative observation was retained in the Engagement Log."
          : "The HTTP service returned an error response to the bounded metadata check. This valid negative observation was retained in the Engagement Log.";
    return { success: true, outcome: "negative_observation", summary };
  }

  if (result.exitCode !== 0) {
    return {
      success: false,
      outcome: "execution_failure",
      category: "deterministic_tool_error",
      code: `local_tool_exit_${result.exitCode ?? "unknown"}`,
      summary: `${result.toolId} returned exit code ${result.exitCode ?? "unknown"}.`,
    };
  }
  return {
    success: true,
    outcome: "positive_observation",
    summary: `${result.toolId} completed; its output remains an Engagement Log until separately parsed or promoted.`,
  };
}

interface LocalToolObservationScope {
  readonly planId?: string;
  readonly sourceAgentId?: string;
  readonly missionTargetId?: string;
}

interface MissionConstraintRow {
  readonly constraint_type: string;
  readonly value_json: string;
}

function requestedEvidenceTypes(rows: readonly MissionConstraintRow[]): ReadonlySet<string> {
  const selected = new Set<string>();
  for (const row of rows) {
    let value: unknown;
    try {
      value = JSON.parse(row.value_json);
    } catch {
      continue;
    }
    const values = row.constraint_type === "guided_collaboration"
      && value !== null && typeof value === "object" && !Array.isArray(value)
      ? (value as { readonly evidenceExpectations?: unknown }).evidenceExpectations
      : value;
    if (!Array.isArray(values)) continue;
    for (const item of values) {
      if (typeof item === "string" && item.trim() === item && item.length > 0) selected.add(item);
    }
  }
  return selected;
}

/**
 * Persists one raw Engagement Log and, for a successful target observation,
 * one attributable structured Observation. A matching mission evidence policy
 * may propose Evidence Candidates; this boundary never creates Verified Evidence.
 */
export class OperationalTruthLocalToolOutputRecorder implements LocalToolExecutionOutputRecorder {
  private readonly truth: OperationalTruthService;
  private readonly nmapTopology: ReviewedNmapTopologyMaterializer;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly manifest: LocalToolCapabilityManifest,
  ) {
    this.truth = new OperationalTruthService(database);
    this.nmapTopology = new ReviewedNmapTopologyMaterializer(database);
  }

  private scope(result: LocalProcessToolResult): LocalToolObservationScope {
    const step = this.database.prepare(`
      SELECT ps.plan_id, ps.assigned_agent_id
      FROM plan_steps ps
      LEFT JOIN agents a ON a.id = ps.assigned_agent_id
      WHERE ps.id = ? AND ps.run_id = ?
    `).get(result.action.stepId, result.action.runId) as {
      readonly plan_id: string | null;
      readonly assigned_agent_id: string | null;
    } | undefined;
    const agentExists = step?.assigned_agent_id
      ? Boolean(this.database.prepare("SELECT 1 FROM agents WHERE id = ?").get(step.assigned_agent_id))
      : false;
    const target = this.database.prepare(`
      SELECT id FROM mission_targets
      WHERE mission_id = ? AND disposition = 'allowed'
        AND (target = ? OR normalized_target = ?)
      ORDER BY id LIMIT 1
    `).get(
      result.action.missionId,
      result.action.target,
      result.action.target,
    ) as { readonly id: string } | undefined;
    return {
      ...(step?.plan_id ? { planId: step.plan_id } : {}),
      ...(agentExists && step?.assigned_agent_id ? { sourceAgentId: step.assigned_agent_id } : {}),
      ...(target?.id ? { missionTargetId: target.id } : {}),
    };
  }

  private missionEvidenceTypes(missionId: string): ReadonlySet<string> {
    const rows = this.database.prepare(`
      SELECT constraint_type, value_json FROM mission_constraints
      WHERE mission_id = ? AND constraint_type IN ('guided_collaboration', 'evidence_requirements')
      ORDER BY created_at, id
    `).all(missionId) as MissionConstraintRow[];
    return requestedEvidenceTypes(rows);
  }

  /**
   * A reviewed invocation has one deterministic tool-call identity. Returning
   * the already committed projection makes result delivery safe to retry
   * without duplicating logs, observations, or evidence candidates.
   */
  private existingOutput(result: LocalProcessToolResult): LocalToolExecutionOutputRecord | undefined {
    const rows = this.database.prepare(`
      SELECT l.id AS log_record_id, l.technical_payload_json, tc.tool_name,
        o.id AS observation_id, c.id AS evidence_candidate_id
      FROM engagement_log_records l
      JOIN tool_calls tc ON tc.id = l.tool_call_id
      LEFT JOIN observation_log_sources source ON source.log_record_id = l.id
      LEFT JOIN observations o ON o.id = source.observation_id
      LEFT JOIN evidence_candidates c ON c.observation_id = o.id
      WHERE l.tool_call_id = ? AND l.mission_id = ? AND l.run_id = ?
        AND l.step_id = ? AND l.action_id = ?
        AND l.domain = 'local_tool_execution'
        AND l.record_type = 'bounded_process_output'
      ORDER BY l.id, o.id, c.id
    `).all(
      result.invocationId,
      result.action.missionId,
      result.action.runId,
      result.action.stepId,
      result.action.id,
    ) as Array<{
      readonly log_record_id: string;
      readonly technical_payload_json: string;
      readonly tool_name: string;
      readonly observation_id: string | null;
      readonly evidence_candidate_id: string | null;
    }>;
    if (rows.length === 0) return undefined;
    const logRecordIds = new Set(rows.map(({ log_record_id }) => log_record_id));
    if (logRecordIds.size !== 1) {
      throw new LocalProcessToolExecutionError(
        "duplicate_operational_output",
        "The reviewed invocation already has more than one canonical Engagement Log.",
      );
    }
    let payload: unknown;
    try {
      payload = JSON.parse(rows[0]!.technical_payload_json) as unknown;
    } catch {
      throw new LocalProcessToolExecutionError(
        "operational_output_integrity_failed",
        "The reviewed invocation's retained Engagement Log is malformed.",
      );
    }
    if (
      rows[0]!.tool_name !== result.toolId
      ||
      !payload || typeof payload !== "object" || Array.isArray(payload)
      || (payload as { readonly outputSha256?: unknown }).outputSha256 !== result.outputSha256
    ) {
      throw new LocalProcessToolExecutionError(
        "operational_output_binding_changed",
        "The reviewed invocation result differs from its already retained Engagement Log.",
      );
    }
    return {
      logRecordId: rows[0]!.log_record_id,
      observationIds: [...new Set(rows.flatMap(({ observation_id }) => observation_id ? [observation_id] : []))],
      evidenceCandidateIds: [...new Set(rows.flatMap(({ evidence_candidate_id }) =>
        evidence_candidate_id ? [evidence_candidate_id] : []))],
      evidenceIds: [],
      artifactIds: [],
    };
  }

  record(result: LocalProcessToolResult): LocalToolExecutionOutputRecord {
    const classification = classifyReviewedLocalToolResult(result);
    const observationScope = this.scope(result);
    return this.truth.repository.transaction(() => {
      const existing = this.existingOutput(result);
      if (existing) return existing;
      const log = this.truth.appendEngagementLog({
        missionId: result.action.missionId,
        runId: result.action.runId,
        ...(observationScope.planId ? { planId: observationScope.planId } : {}),
        stepId: result.action.stepId,
        actionId: result.action.id,
        ...(observationScope.sourceAgentId ? { agentId: observationScope.sourceAgentId } : {}),
        toolCallId: result.invocationId,
        severity: classification.success ? "notice" : "error",
        domain: "local_tool_execution",
        recordType: "bounded_process_output",
        humanSummary: classification.summary,
        technicalPayload: {
          semanticOutcome: classification.outcome,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.exitCode,
          signal: result.signal,
          termination: result.termination,
          spawnErrorCode: result.spawnErrorCode,
          observedOutputBytes: result.observedOutputBytes,
          retainedOutputBytes: result.retainedOutputBytes,
          outputSha256: result.outputSha256,
          outputTruncated: result.outputTruncated,
          executableSha256: result.executable.sourceSha256,
          snapshotSha256: result.executable.snapshotSha256,
          sandboxExecutableSha256: result.sandbox.executableSha256,
          shell: false,
        },
        sensitivity: "private",
        occurredAt: result.endedAt,
      });
      const normalized = normalizeReviewedLocalToolObservation(result, classification);
      if (!normalized) {
        return {
          logRecordId: log.id,
          observationIds: [],
          evidenceCandidateIds: [],
          evidenceIds: [],
          artifactIds: [],
        };
      }
      const observation = this.truth.createObservation({
        missionId: result.action.missionId,
        runId: result.action.runId,
        stepId: result.action.stepId,
        observationType: normalized.observationType,
        statement: normalized.statement,
        normalizedValue: {
          ...normalized.normalizedValue,
          missionTargetId: observationScope.missionTargetId ?? null,
          provenance: {
            logRecordId: log.id,
            actionId: result.action.id,
            toolCallId: result.invocationId,
          },
        },
        confidence: normalized.confidence,
        verificationState: "unverified",
        ...(observationScope.sourceAgentId ? { sourceAgentId: observationScope.sourceAgentId } : {}),
        sourceTool: result.toolId,
        firstSeenAt: result.startedAt,
        lastSeenAt: result.endedAt,
        sensitivity: "private",
        sources: [{
          logRecordId: log.id,
          parserId: REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_ID,
          parserVersion: REVIEWED_LOCAL_TOOL_OBSERVATION_PARSER_VERSION,
        }],
      });
      this.nmapTopology.materialize(observation);

      const requested = this.missionEvidenceTypes(result.action.missionId);
      const tool = this.manifest.resolve(result.toolId);
      const candidates = (tool?.evidenceTypeIds ?? []).flatMap((evidenceType) => {
        if (!requested.has(evidenceType) || !normalized.completeForCandidate) return [];
        const inputKind = evidenceType === "http_exchange" ? "http_exchange" : "parsed_observation";
        const policy = classifyOperationalInput(inputKind, {
          parsed: true,
          attributable: true,
          provenanceSourceIds: [log.id],
          immutableHash: log.contentHash,
          ...(inputKind === "http_exchange" ? { completeRequestResponsePair: true } : {}),
          policyAllowsCandidate: true,
        });
        if (!policy.stages.includes("evidence_candidate")) return [];
        const label = EVIDENCE_TYPE_DEFINITIONS.find(({ id }) => id === evidenceType)?.label
          ?? evidenceType.replaceAll("_", " ");
        return [this.truth.proposeEvidenceCandidate({
          missionId: result.action.missionId,
          runId: result.action.runId,
          stepId: result.action.stepId,
          observationId: observation.id,
          evidenceType,
          label: `${label} — ${result.action.target}`.slice(0, 500),
          meaning: `${normalized.statement} This candidate supports only the bounded, time-specific observation and remains unverified.`,
          promotionReason: `The mission explicitly requests ${evidenceType}, and the reviewed ${result.toolId} result produced a parsed, attributable observation. Independent human validation is still required.`,
          sensitivity: "private",
          proposedBy: observationScope.sourceAgentId ?? this.manifest.specialist.id,
        })];
      });
      return {
        logRecordId: log.id,
        observationIds: [observation.id],
        evidenceCandidateIds: candidates.map(({ id }) => id),
        evidenceIds: [],
        artifactIds: [],
      };
    });
  }
}

function executionResultForLocalTool(
  result: LocalProcessToolResult,
  classification: ReviewedLocalToolResultClassification,
): ExecutionResult {
  return {
    actionId: result.action.id,
    runId: result.action.runId,
    actionFingerprint: result.action.fingerprint,
    success: classification.success,
    summary: classification.summary,
    progress: {},
    ...(!classification.success ? {
      failure: {
        source: "tool" as const,
        ...(classification.code ? { code: classification.code } : {}),
        message: classification.summary,
      },
      ...(classification.category ? { failureCategory: classification.category } : {}),
      circuitKey: `local-tool:${result.toolId}`,
    } : {}),
    usage: { wallClockMs: result.wallClockMs },
  };
}

function persistableExecutionResult(result: ExecutionResult): PersistedLocalToolExecutionResult {
  return {
    schemaVersion: LOCAL_TOOL_RESULT_DELIVERY_SCHEMA_VERSION,
    actionId: result.actionId,
    runId: result.runId,
    actionFingerprint: result.actionFingerprint,
    success: result.success,
    summary: result.summary,
    failureCode: result.failure?.code ?? null,
    failureCategory: result.failureCategory ?? null,
    circuitKey: result.circuitKey ?? null,
    wallClockMs: result.usage?.wallClockMs ?? 0,
  };
}

function terminalPayload(
  result: LocalProcessToolResult,
  executionResult: ExecutionResult,
  output?: LocalToolExecutionOutputRecord,
): LocalToolTerminalPayload {
  return {
    engagementLogId: output?.logRecordId ?? null,
    observationIds: output?.observationIds ?? [],
    evidenceCandidateIds: output?.evidenceCandidateIds ?? [],
    evidenceIds: output?.evidenceIds ?? [],
    artifactIds: output?.artifactIds ?? [],
    outputSha256: result.outputSha256,
    outputTruncated: result.outputTruncated,
    deliveryResult: persistableExecutionResult(executionResult),
    resultAccepted: false,
    duplicateResult: false,
    deliveryAttemptCount: 0,
    deliveryLastAttemptAt: null,
    deliveryLastError: null,
  };
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function retainedIdentifiers(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length > 10_000) return null;
  return value.every((item) => typeof item === "string" && item.length > 0 && item.length <= 512)
    ? value as readonly string[]
    : null;
}

function parseTerminalPayload(value: string | null): LocalToolTerminalPayload | null {
  if (!value) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    return null;
  }
  const payload = objectValue(parsed);
  const delivery = objectValue(payload?.deliveryResult);
  if (
    !payload || !delivery
    || (payload.engagementLogId !== null && typeof payload.engagementLogId !== "string")
    || retainedIdentifiers(payload.observationIds) === null
    || retainedIdentifiers(payload.evidenceCandidateIds) === null
    || retainedIdentifiers(payload.evidenceIds) === null
    || retainedIdentifiers(payload.artifactIds) === null
    || typeof payload.outputSha256 !== "string"
    || typeof payload.outputTruncated !== "boolean"
    || delivery.schemaVersion !== LOCAL_TOOL_RESULT_DELIVERY_SCHEMA_VERSION
    || typeof delivery.actionId !== "string"
    || typeof delivery.runId !== "string"
    || typeof delivery.actionFingerprint !== "string"
    || typeof delivery.success !== "boolean"
    || typeof delivery.summary !== "string"
    || (delivery.failureCode !== null && typeof delivery.failureCode !== "string")
    || (delivery.failureCategory !== null
      && (typeof delivery.failureCategory !== "string"
        || !(FAILURE_CATEGORIES as readonly string[]).includes(delivery.failureCategory)))
    || (delivery.circuitKey !== null && typeof delivery.circuitKey !== "string")
    || typeof delivery.wallClockMs !== "number"
    || !Number.isSafeInteger(delivery.wallClockMs)
    || delivery.wallClockMs < 0
    || typeof payload.resultAccepted !== "boolean"
    || typeof payload.duplicateResult !== "boolean"
  ) return null;
  return payload as unknown as LocalToolTerminalPayload;
}

function replayableExecutionResult(
  persisted: PersistedLocalToolExecutionResult,
  row: PendingLocalToolResultRow,
  payload: LocalToolTerminalPayload,
): ExecutionResult | null {
  if (
    persisted.actionId !== row.action_id
    || persisted.runId !== row.run_id
    || persisted.actionFingerprint !== row.action_fingerprint
    || (persisted.success && row.tool_status !== "succeeded")
    || (!persisted.success && row.tool_status !== "failed" && row.tool_status !== "timed_out")
  ) return null;
  return {
    actionId: persisted.actionId,
    runId: persisted.runId,
    actionFingerprint: persisted.actionFingerprint,
    success: persisted.success,
    summary: persisted.summary,
    progress: {
      ...(payload.evidenceIds.length > 0 ? { evidenceIds: payload.evidenceIds } : {}),
      ...(payload.artifactIds.length > 0 ? { artifactIds: payload.artifactIds } : {}),
    },
    ...(!persisted.success ? {
      failure: {
        source: "tool" as const,
        ...(persisted.failureCode ? { code: persisted.failureCode } : {}),
        message: persisted.summary,
      },
      ...(persisted.failureCategory ? { failureCategory: persisted.failureCategory } : {}),
      ...(persisted.circuitKey ? { circuitKey: persisted.circuitKey } : {}),
    } : {}),
    usage: { wallClockMs: persisted.wallClockMs },
  };
}

export interface ReviewedLocalToolExecutionPortOptions {
  readonly database: SqliteDatabase;
  /**
   * One execution port belongs to exactly one journey scheduler. Keeping this
   * boundary in the durable result query prevents a Guided process from
   * replaying an Autonomous result (or the reverse) after restart.
   */
  readonly executionJourney: "autonomous" | "guided";
  readonly manifest: LocalToolCapabilityManifest;
  readonly adapter: ReviewedLocalProcessInvocationAdapter;
  readonly workspaceResolver: EngagementWorkspaceResolver;
  readonly outputRecorder: LocalToolExecutionOutputRecorder;
  readonly assertControlPlaneAuthority: (runId: string) => ReturnType<ControlPlaneLeaseService["assertMutationAuthority"]>;
  readonly now?: () => Date;
  /** Deterministic crash-window injection used by persistence tests. */
  readonly crashAfterTerminalCommit?: (context: Readonly<{
    invocationId: string;
    actionId: string;
    runId: string;
  }>) => void;
}

/** Truthful ResultAwareExecutionPort for direct local tools; MCP inventory stays zero. */
export class ReviewedLocalToolExecutionPort implements ResultAwareExecutionPort {
  private readonly actions: ActionRepository;
  private readonly runs: RunRepository;
  private readonly now: () => Date;
  private resultSink?: ExecutionResultSink;
  private readonly terminalInProgress = new Set<string>();
  private readonly unbindAdapter: () => void;

  constructor(private readonly options: ReviewedLocalToolExecutionPortOptions) {
    this.actions = new ActionRepository(options.database);
    this.runs = new RunRepository(options.database);
    this.now = options.now ?? (() => new Date());
    const unbind = options.adapter.bindResultSink({
      acceptLocalProcessToolResult: (result) => this.acceptResult(result),
    });
    this.unbindAdapter = typeof unbind === "function" ? unbind : () => undefined;
  }

  bindResultSink(sink: ExecutionResultSink): () => void {
    if (this.resultSink) throw new Error("Reviewed local tool result sink is already bound");
    this.resultSink = sink;
    return () => {
      if (this.resultSink === sink) this.resultSink = undefined;
    };
  }

  /** Current process-state proof used by activation; reading it performs no work. */
  get runtimeResultSinkBound(): boolean {
    return this.resultSink !== undefined;
  }

  private assertControlPlaneAuthority(runId: string): void {
    try {
      this.options.assertControlPlaneAuthority(runId);
    } catch (error) {
      if (error instanceof ControlPlaneLeaseError) {
        throw new LocalProcessToolExecutionError(
          `control_plane_${error.code}`,
          "Ti-Scale no longer held the run's control-plane authority at the reviewed local-tool boundary.",
        );
      }
      throw error;
    }
  }

  private canonical(input: DurableAction): Readonly<{
    action: DurableAction;
    toolId: string;
    parameters: Readonly<Record<string, unknown>>;
  }> {
    const action = this.actions.get(input.id);
    if (digestCanonicalJson(action, { maxBytes: 1_024 * 1_024, maxDepth: 64 }).sha256
      !== digestCanonicalJson(input, { maxBytes: 1_024 * 1_024, maxDepth: 64 }).sha256
      || action.status !== "running") {
      throw new LocalProcessToolExecutionError("action_not_canonical", "Only the exact running canonical action may enter local execution.");
    }
    this.assertControlPlaneAuthority(action.runId);
    const envelope = reviewedLocalToolActionEnvelope(action.arguments);
    if (!envelope) throw new LocalProcessToolExecutionError("action_binding_invalid", "Action is not an exact reviewed local process envelope.");
    const authorized = this.runs.authorizePersistedLocalTool(this.runs.get(action.runId), action, envelope.toolId);
    if (!authorized.allowed) throw new LocalProcessToolExecutionError(authorized.code, authorized.humanMessage);
    const tool = this.options.manifest.resolve(envelope.toolId);
    if (!tool) throw new LocalProcessToolExecutionError("tool_unavailable", "The reviewed local tool is not in the active manifest.");
    if (action.actionType !== envelope.toolId
      || !tool.actionClassIds.some((actionClassId) => actionClassId === action.actionClass)) {
      throw new LocalProcessToolExecutionError(
        "action_capability_binding_changed",
        "The action type or action class differs from the reviewed local tool capability binding.",
      );
    }
    const workspaceParameter = tool.execution.logicalWorkspaceParameter;
    const logicalWorkspace = envelope.parameters[workspaceParameter];
    if (typeof logicalWorkspace !== "string") throw new LocalProcessToolExecutionError("workspace_parameter_invalid", "Local tool action has no exact logical workspace.");
    return { action, toolId: envelope.toolId, parameters: envelope.parameters };
  }

  private async prepared(input: DurableAction): Promise<LocalProcessToolInvocation> {
    const canonical = this.canonical(input);
    const tool = this.options.manifest.resolve(canonical.toolId)!;
    const logical = canonical.parameters[tool.execution.logicalWorkspaceParameter] as string;
    const workspace = await this.options.workspaceResolver.resolve(logical);
    if (workspace.status !== "resolved" || !workspace.resolvedPath) {
      throw new LocalProcessToolExecutionError(`workspace_${workspace.code}`, workspace.explanation);
    }
    this.assertControlPlaneAuthority(canonical.action.runId);
    const authorized = this.runs.authorizePersistedLocalTool(
      this.runs.get(canonical.action.runId),
      canonical.action,
      canonical.toolId,
    );
    if (!authorized.allowed) throw new LocalProcessToolExecutionError(authorized.code, authorized.humanMessage);
    const invocationId = `local_tool_${createHash("sha256").update(canonical.action.id).digest("hex").slice(0, 40)}`;
    const existing = this.options.database.prepare("SELECT status FROM tool_calls WHERE id = ?")
      .get(invocationId) as { status: string } | undefined;
    if (existing) throw new LocalProcessToolExecutionError("duplicate_invocation", "This exact local action already has a durable tool-call receipt.");
    const now = this.now().toISOString();
    const inputSha256 = digestCanonicalJson(canonical.parameters, { maxBytes: 256 * 1_024, maxDepth: 32 }).sha256;
    this.options.database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, mcp_server_id,
        normalized_arguments_json, status, started_at, created_at
      ) VALUES (?, ?, 'reviewed-local-process', ?, NULL, ?, 'running', ?, ?)
    `).run(invocationId, canonical.action.id, canonical.toolId, JSON.stringify({
      schemaVersion: LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
      // The target is already canonical mission state on the owning action.
      // Retain it here as well so the technical invocation receipt proves the
      // exact target binding without exposing the remaining tool parameters.
      target: canonical.action.target,
      inputSha256,
      manifestSha256: this.options.manifest.descriptor.manifestSha256,
      toolBindingSha256: tool.bindingSha256,
      resolvedWorkspacePathSha256: createHash("sha256").update(workspace.resolvedPath).digest("hex"),
    }), now, now);
    return {
      schemaVersion: LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
      invocationId,
      action: canonical.action,
      toolId: canonical.toolId,
      parameters: canonical.parameters,
      inputSha256,
      resolvedWorkspacePath: workspace.resolvedPath,
    };
  }

  async dispatch(action: DurableAction, signal: AbortSignal): Promise<void> {
    if (!this.resultSink) throw new LocalProcessToolExecutionError("result_sink_unbound", "Mission runtime result sink is not bound.");
    const invocation = await this.prepared(action);
    try {
      await this.options.adapter.dispatch(invocation, signal);
    } catch (error) {
      this.options.database.prepare(`
        UPDATE tool_calls SET status = 'denied', error_category = ?, output_summary = ?, ended_at = ?
        WHERE id = ? AND status = 'running'
      `).run(
        error instanceof LocalProcessToolExecutionError ? error.code : "dispatch_failed",
        error instanceof Error ? error.message : "Reviewed local process dispatch failed.",
        this.now().toISOString(),
        invocation.invocationId,
      );
      throw error;
    }
  }

  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {
    throw new LocalProcessToolExecutionError(
      "resume_requires_new_attempt",
      "A recovered local tool call requires a new bounded action and attempt identity; the previous invocation is never replayed.",
    );
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    await this.options.adapter.cancelRun(runId, reason);
    this.options.database.prepare(`
      UPDATE tool_calls SET status = 'cancelled', error_category = NULL,
        output_summary = ?, ended_at = ?
      WHERE status = 'running' AND provider = 'reviewed-local-process' AND action_id IN (
        SELECT id FROM actions WHERE run_id = ?
      )
    `).run(
      "Run cancellation terminated the reviewed local process before a result was accepted.",
      this.now().toISOString(),
      runId,
    );
  }

  private pendingResult(invocationId: string): PendingLocalToolResultRow | undefined {
    return this.options.database.prepare(`
      SELECT tc.id AS invocation_id, tc.status AS tool_status, tc.redacted_payload_json,
        a.id AS action_id, a.run_id, a.fingerprint AS action_fingerprint
      FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id
      JOIN runs r ON r.id = a.run_id
      JOIN missions m ON m.id = r.mission_id AND m.id = a.mission_id
      WHERE tc.id = ? AND tc.provider = 'reviewed-local-process'
        AND tc.status IN ('succeeded', 'failed', 'timed_out')
        AND r.journey = ?
        AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale'
        AND json_extract(tc.redacted_payload_json, '$.deliveryResult.schemaVersion') = ?
    `).get(
      invocationId,
      this.options.executionJourney,
      LOCAL_TOOL_RESULT_DELIVERY_SCHEMA_VERSION,
    ) as PendingLocalToolResultRow | undefined;
  }

  private recordDeliveryAttempt(
    invocationId: string,
    outcome: Readonly<{
      accepted: boolean;
      duplicate: boolean;
      error: string | null;
    }>,
  ): void {
    inImmediateTransaction(this.options.database, () => {
      const row = this.options.database.prepare(`
        SELECT redacted_payload_json FROM tool_calls
        WHERE id = ? AND provider = 'reviewed-local-process'
          AND status IN ('succeeded', 'failed', 'timed_out')
      `).get(invocationId) as { readonly redacted_payload_json: string | null } | undefined;
      if (!row) return;
      let current: Record<string, unknown> = {};
      try {
        current = objectValue(row.redacted_payload_json
          ? JSON.parse(row.redacted_payload_json) as unknown
          : null) ?? {};
      } catch {
        current = {};
      }
      // A concurrent redelivery may have received the acknowledgement while a
      // second attempt was in flight. Never let that later attempt regress it.
      if (current.resultAccepted === true) return;
      const previousAttempts = typeof current.deliveryAttemptCount === "number"
        && Number.isSafeInteger(current.deliveryAttemptCount)
        && current.deliveryAttemptCount >= 0
        ? current.deliveryAttemptCount
        : 0;
      this.options.database.prepare(`
        UPDATE tool_calls SET redacted_payload_json = ?
        WHERE id = ? AND provider = 'reviewed-local-process'
          AND status IN ('succeeded', 'failed', 'timed_out')
      `).run(JSON.stringify({
        ...current,
        resultAccepted: outcome.accepted,
        duplicateResult: outcome.accepted ? outcome.duplicate : false,
        deliveryAttemptCount: previousAttempts + 1,
        deliveryLastAttemptAt: this.now().toISOString(),
        deliveryLastError: outcome.error,
      }), invocationId);
    });
  }

  private async deliverPendingResult(row: PendingLocalToolResultRow): Promise<boolean> {
    const payload = parseTerminalPayload(row.redacted_payload_json);
    if (payload?.resultAccepted === true) return true;
    if (!payload) {
      this.recordDeliveryAttempt(row.invocation_id, {
        accepted: false,
        duplicate: false,
        error: "terminal_result_delivery_payload_invalid",
      });
      return false;
    }
    const executionResult = replayableExecutionResult(payload.deliveryResult, row, payload);
    if (!executionResult) {
      this.recordDeliveryAttempt(row.invocation_id, {
        accepted: false,
        duplicate: false,
        error: "terminal_result_delivery_correlation_mismatch",
      });
      return false;
    }
    const sink = this.resultSink;
    if (!sink) {
      this.recordDeliveryAttempt(row.invocation_id, {
        accepted: false,
        duplicate: false,
        error: "runtime_result_sink_unbound",
      });
      return false;
    }
    try {
      const receipt: ExecutionResultReceipt = await sink.acceptExecutionResult(executionResult);
      if (!receipt.accepted) {
        this.recordDeliveryAttempt(row.invocation_id, {
          accepted: false,
          duplicate: false,
          error: "runtime_result_receipt_rejected",
        });
        return false;
      }
      if (receipt.actionId !== row.action_id || receipt.runId !== row.run_id) {
        this.recordDeliveryAttempt(row.invocation_id, {
          accepted: false,
          duplicate: false,
          error: "runtime_result_receipt_mismatch",
        });
        return false;
      }
      this.recordDeliveryAttempt(row.invocation_id, {
        accepted: true,
        duplicate: receipt.duplicate,
        error: null,
      });
      return true;
    } catch {
      // Delivery health is transport metadata, not execution truth. In
      // particular, a runtime may have committed the action and then lost the
      // acknowledgement. Keep the terminal tool status intact for replay.
      this.recordDeliveryAttempt(row.invocation_id, {
        accepted: false,
        duplicate: false,
        error: "runtime_result_delivery_failed",
      });
      return false;
    }
  }

  async replayPendingResults(limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) {
      throw new RangeError("Pending local result replay limit must be an integer from 1 to 1000");
    }
    if (!this.resultSink) return 0;
    const rows = this.options.database.prepare(`
      SELECT tc.id AS invocation_id, tc.status AS tool_status, tc.redacted_payload_json,
        a.id AS action_id, a.run_id, a.fingerprint AS action_fingerprint
      FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id
      JOIN runs r ON r.id = a.run_id
      JOIN missions m ON m.id = r.mission_id AND m.id = a.mission_id
      WHERE tc.provider = 'reviewed-local-process'
        AND tc.status IN ('succeeded', 'failed', 'timed_out')
        AND r.journey = ?
        AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale'
        AND json_extract(tc.redacted_payload_json, '$.deliveryResult.schemaVersion') = ?
        AND COALESCE(json_extract(tc.redacted_payload_json, '$.resultAccepted'), 0) = 0
      ORDER BY tc.ended_at, tc.id
      LIMIT ?
    `).all(
      this.options.executionJourney,
      LOCAL_TOOL_RESULT_DELIVERY_SCHEMA_VERSION,
      limit,
    ) as PendingLocalToolResultRow[];
    let acknowledged = 0;
    for (const row of rows) {
      if (this.terminalInProgress.has(row.invocation_id)) continue;
      this.terminalInProgress.add(row.invocation_id);
      try {
        if (await this.deliverPendingResult(row)) acknowledged += 1;
      } finally {
        this.terminalInProgress.delete(row.invocation_id);
      }
    }
    return acknowledged;
  }

  private async acceptResult(result: LocalProcessToolResult): Promise<void> {
    if (this.terminalInProgress.has(result.invocationId)) return;
    this.terminalInProgress.add(result.invocationId);
    try {
      let classification = classifyReviewedLocalToolResult(result);
      let executionResult = executionResultForLocalTool(result, classification);
      let persistedChanges = 0;
      try {
        persistedChanges = inImmediateTransaction(this.options.database, () => {
          const current = this.options.database.prepare(
            "SELECT status FROM tool_calls WHERE id = ?",
          ).get(result.invocationId) as { readonly status: string } | undefined;
          if (current?.status !== "running") return 0;
          const output = this.options.outputRecorder.record(result);
          if (output.executionResult) {
            if (
              output.executionResult.actionId !== result.action.id
              || output.executionResult.runId !== result.action.runId
              || output.executionResult.actionFingerprint !== result.action.fingerprint
            ) {
              throw new LocalProcessToolExecutionError(
                "verified_result_correlation_mismatch",
                "The specialized verifier returned a result for a different durable action.",
              );
            }
            executionResult = output.executionResult;
          }
          const status = executionResult.success ? "succeeded"
            : executionResult.failureCategory === "timeout" ? "timed_out" : "failed";
          return this.options.database.prepare(`
            UPDATE tool_calls SET status = ?, error_category = ?, latency_ms = ?,
              output_summary = ?, redacted_payload_json = ?, ended_at = ?
            WHERE id = ? AND status = 'running'
          `).run(
            status,
            executionResult.failureCategory ?? null,
            result.wallClockMs,
            executionResult.summary,
            JSON.stringify(terminalPayload(result, executionResult, output)),
            this.now().toISOString(),
            result.invocationId,
          ).changes;
        });
      } catch (error) {
        const failureDetail = redactOutput(
          error instanceof Error ? error.message : "The persistence boundary returned an unknown error.",
        ).trim().replace(/\s+/gu, " ").slice(0, 320);
        classification = {
          success: false,
          outcome: "execution_failure",
          category: "dependency_missing",
          code: "engagement_log_retention_failed",
          summary: `${result.toolId} finished, but its bounded output could not be retained in the canonical Engagement Log. ${failureDetail}`,
        };
        executionResult = executionResultForLocalTool(result, classification);
        persistedChanges = this.options.database.prepare(`
          UPDATE tool_calls SET status = 'failed', error_category = ?, latency_ms = ?,
            output_summary = ?, redacted_payload_json = ?, ended_at = ?
          WHERE id = ? AND status = 'running'
        `).run(
          classification.category,
          result.wallClockMs,
          classification.summary,
          JSON.stringify(terminalPayload(result, executionResult)),
          this.now().toISOString(),
          result.invocationId,
        ).changes;
      }
      if (persistedChanges !== 1) return;
      this.options.crashAfterTerminalCommit?.({
        invocationId: result.invocationId,
        actionId: result.action.id,
        runId: result.action.runId,
      });
      const pending = this.pendingResult(result.invocationId);
      if (pending) await this.deliverPendingResult(pending);
    } finally {
      this.terminalInProgress.delete(result.invocationId);
    }
  }

  close(): void {
    this.unbindAdapter();
  }
}

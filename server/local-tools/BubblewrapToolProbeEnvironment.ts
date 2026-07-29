import { createHash } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import {
  closeSync,
  constants as fsConstants,
  fchmodSync,
  readFileSync,
  write as writeCallback,
  type BigIntStats,
} from "node:fs";
import { lstat, open, stat, type FileHandle } from "node:fs/promises";
import { createRequire } from "node:module";
import { isAbsolute, resolve, sep } from "node:path";
import type {
  ToolExecutableIdentity,
  ToolExecutionPreflightEnvironment,
  ToolProbeExecutionResult,
} from "../system-capabilities";
import { inspectLinuxFileCapabilities } from "./AsyncFileCapabilityInspection";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config/TrustedJsonFileLoader";

export const BUBBLEWRAP_PROBE_SANDBOX_SCHEMA_VERSION =
  "ti-scale.bubblewrap-probe-sandbox.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const VERSION = /^[A-Za-z0-9._-]{1,80}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const MAXIMUM_EXECUTABLE_BYTES = 256 * 1024 * 1024;
const F_ADD_SEALS = 1033;
const F_GET_SEALS = 1034;
const REQUIRED_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008;
const MFD_ALLOW_SEALING = 0x0002;
const COPY_CHUNK_BYTES = 1024 * 1024;
const MAXIMUM_CACHED_SNAPSHOT_BYTES = MAXIMUM_EXECUTABLE_BYTES;
const MAXIMUM_CACHED_SNAPSHOTS = 64;

interface OpenedExecutable {
  readonly path: string;
  readonly handle: FileHandle;
  readonly metadata: BigIntStats;
  readonly sizeBytes: number;
  readonly mode: number;
  readonly uid: number;
  readonly gid: number;
}

interface CachedExecutableSnapshot {
  readonly path: string;
  readonly descriptor: number;
  readonly metadata: BigIntStats;
  readonly identity: ToolExecutableIdentity;
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

export interface BubblewrapProbeResourceSnapshot {
  readonly cachedExecutableSnapshots: number;
  readonly cachedExecutableBytes: number;
  readonly immutableSnapshotBuilds: number;
  readonly immutableSnapshotCacheHits: number;
  readonly closed: boolean;
}

export interface BubblewrapProbeSandboxDescriptor {
  readonly schemaVersion: typeof BUBBLEWRAP_PROBE_SANDBOX_SCHEMA_VERSION;
  readonly descriptorVersion: string;
  readonly executablePath: string;
  readonly expectedSha256: string;
  readonly fileCapabilities: "none";
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null);
}

export function parseBubblewrapProbeSandboxDescriptor(
  input: unknown,
): BubblewrapProbeSandboxDescriptor {
  if (!plainRecord(input)) throw new Error("Bubblewrap probe descriptor must be a plain object");
  const expected = ["descriptorVersion", "executablePath", "expectedSha256", "fileCapabilities", "schemaVersion"].sort();
  const actual = Object.keys(input).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`Bubblewrap probe descriptor must contain exactly: ${expected.join(", ")}`);
  }
  if (input.schemaVersion !== BUBBLEWRAP_PROBE_SANDBOX_SCHEMA_VERSION) {
    throw new Error(`Unsupported bubblewrap probe descriptor schema: ${String(input.schemaVersion)}`);
  }
  if (typeof input.descriptorVersion !== "string" || !VERSION.test(input.descriptorVersion)) {
    throw new Error("Bubblewrap probe descriptorVersion is invalid");
  }
  if (typeof input.executablePath !== "string"
    || !isAbsolute(input.executablePath)
    || input.executablePath === resolve(sep)
    || input.executablePath.length > 4_096
    || CONTROL_CHARACTERS.test(input.executablePath)) {
    throw new Error("Bubblewrap probe executablePath must be an absolute safe file path");
  }
  if (typeof input.expectedSha256 !== "string" || !SHA256.test(input.expectedSha256)) {
    throw new Error("Bubblewrap probe expectedSha256 must be a lowercase SHA-256");
  }
  if (input.fileCapabilities !== "none") {
    throw new Error("Bubblewrap probe helper must not carry Linux file capabilities");
  }
  return Object.freeze({
    schemaVersion: BUBBLEWRAP_PROBE_SANDBOX_SCHEMA_VERSION,
    descriptorVersion: input.descriptorVersion,
    executablePath: input.executablePath,
    expectedSha256: input.expectedSha256,
    fileCapabilities: "none",
  });
}

export function loadTrustedBubblewrapProbeSandboxDescriptor(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<BubblewrapProbeSandboxDescriptor> {
  return loadTrustedJson(
    { ...reference, maximumBytes: reference.maximumBytes ?? 16 * 1024 },
    parseBubblewrapProbeSandboxDescriptor,
  );
}

function sameMetadata(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function currentCanExecute(mode: number, uid: number, gid: number): boolean {
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  const currentGid = process.getegid?.() ?? process.getgid?.() ?? 0;
  const groups = new Set([currentGid, ...(process.getgroups?.() ?? [])]);
  if (currentUid === 0) return (mode & 0o111) !== 0;
  if (uid === currentUid) return (mode & 0o100) !== 0;
  if (groups.has(gid)) return (mode & 0o010) !== 0;
  return (mode & 0o001) !== 0;
}

type ExecutableInspection =
  | Readonly<{ state: "ready"; opened: OpenedExecutable }>
  | Readonly<{ state: "missing" | "not_regular" | "not_executable" | "unsafe_permissions" }>;

async function openExecutable(path: string): Promise<ExecutableInspection> {
  let pathMetadata: BigIntStats;
  try {
    pathMetadata = await lstat(path, { bigint: true });
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT"
      ? { state: "missing" }
      : { state: "not_executable" };
  }
  if (pathMetadata.isSymbolicLink() || !pathMetadata.isFile()) return { state: "not_regular" };
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat({ bigint: true });
    if (!sameMetadata(pathMetadata, opened)) {
      await handle.close();
      return { state: "not_regular" };
    }
    const sizeBytes = Number(opened.size);
    const mode = Number(opened.mode & 0o7777n);
    const uid = Number(opened.uid);
    const gid = Number(opened.gid);
    const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
    if (!Number.isSafeInteger(sizeBytes)
      || sizeBytes < 1
      || sizeBytes > MAXIMUM_EXECUTABLE_BYTES
      || (uid !== 0 && uid !== currentUid)
      || (mode & 0o022) !== 0
      || (mode & 0o7000) !== 0) {
      await handle.close();
      return { state: "unsafe_permissions" };
    }
    if (!currentCanExecute(mode, uid, gid)) {
      await handle.close();
      return { state: "not_executable" };
    }
    return {
      state: "ready",
      opened: { path, handle, metadata: opened, sizeBytes, mode, uid, gid },
    };
  } catch (error) {
    await handle?.close().catch(() => undefined);
    return (error as NodeJS.ErrnoException).code === "ELOOP"
      ? { state: "not_regular" }
      : { state: "not_executable" };
  }
}

function sameIdentity(left: ToolExecutableIdentity, right: ToolExecutableIdentity): boolean {
  return left.sha256 === right.sha256
    && left.device === right.device
    && left.inode === right.inode
    && left.sizeBytes === right.sizeBytes
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid;
}

async function helperHasNoCapabilities(path: string): Promise<boolean> {
  return (await inspectLinuxFileCapabilities(path)).state === "none";
}

const BUN_FFI_MODULE_SPECIFIER = ["bun", "ffi"].join(":");
const requireFromHere = createRequire(import.meta.url);

function openMemfdLibrary(): BunFfiLibrary {
  const { dlopen, FFIType } = requireFromHere(BUN_FFI_MODULE_SPECIFIER) as BunFfiRuntime;
  return dlopen("libc.so.6", {
    memfd_create: { args: [FFIType.cstring, FFIType.u32], returns: FFIType.i32 },
    fcntl: { args: [FFIType.i32, FFIType.i32, FFIType.i32], returns: FFIType.i32 },
  });
}

// Bun's FFI wrapper is process-scoped. Reopening and JIT-compiling it for
// every 30-second readiness wave retained native arenas in the production
// process. One lazily opened function table is enough for every bounded
// memfd, while a non-Linux process can still import this module safely.
let sharedMemfdLibrary: ReturnType<typeof openMemfdLibrary> | undefined;

function memfdLibrary(): ReturnType<typeof openMemfdLibrary> {
  sharedMemfdLibrary ??= openMemfdLibrary();
  return sharedMemfdLibrary;
}

function createMemfd(): number {
  const descriptor = memfdLibrary().symbols.memfd_create(
    Buffer.from("ti-scale-tool-probe\0"),
    MFD_ALLOW_SEALING,
  );
  if (descriptor < 0) throw new Error("memfd_create_failed");
  return descriptor;
}

function sealMemfd(descriptor: number): void {
  fchmodSync(descriptor, 0o500);
  const library = memfdLibrary();
  if (library.symbols.fcntl(descriptor, F_ADD_SEALS, REQUIRED_SEALS) !== 0
    || library.symbols.fcntl(descriptor, F_GET_SEALS, 0) !== REQUIRED_SEALS) {
    throw new Error("memfd_seal_failed");
  }
}

function writeDescriptor(
  descriptor: number,
  buffer: Buffer,
  offset: number,
  length: number,
  position: number,
): Promise<number> {
  return new Promise((resolveWrite, rejectWrite) => {
    // The callback-backed write stays in libuv's worker pool so cgroup-backed
    // shmem throttling cannot freeze the HTTP/event-loop thread.
    writeCallback(descriptor, buffer, offset, length, position, (error, written) => {
      if (error) rejectWrite(error);
      else resolveWrite(written);
    });
  });
}

async function createSealedSnapshot(opened: OpenedExecutable): Promise<CachedExecutableSnapshot> {
  const descriptor = createMemfd();
  try {
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(COPY_CHUNK_BYTES, opened.sizeBytes));
    let position = 0;
    while (position < opened.sizeBytes) {
      const length = Math.min(buffer.length, opened.sizeBytes - position);
      const { bytesRead } = await opened.handle.read(buffer, 0, length, position);
      if (bytesRead < 1) throw new Error("executable_snapshot_short_read");
      digest.update(buffer.subarray(0, bytesRead));
      let written = 0;
      while (written < bytesRead) {
        const count = await writeDescriptor(
          descriptor,
          buffer,
          written,
          bytesRead - written,
          position + written,
        );
        if (count < 1) throw new Error("memfd_write_failed");
        written += count;
      }
      position += bytesRead;
    }
    const after = await opened.handle.stat({ bigint: true });
    const pathAfter = await lstat(opened.path, { bigint: true });
    if (position !== opened.sizeBytes
      || !sameMetadata(opened.metadata, after)
      || !sameMetadata(after, pathAfter)) {
      throw new Error("executable_identity_changed");
    }
    sealMemfd(descriptor);
    return {
      path: opened.path,
      descriptor,
      metadata: after,
      identity: Object.freeze({
        sha256: digest.digest("hex"),
        device: after.dev.toString(),
        inode: after.ino.toString(),
        sizeBytes: opened.sizeBytes,
        mode: opened.mode,
        uid: opened.uid,
        gid: opened.gid,
      }),
    };
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

async function inspectExecutableIdentity(path: string): Promise<
  | Readonly<{ state: "ready"; identity: ToolExecutableIdentity }>
  | Readonly<{ state: "missing" | "not_regular" | "not_executable" | "unsafe_permissions" }>
> {
  const inspected = await openExecutable(path);
  if (inspected.state !== "ready") return inspected;
  const { opened } = inspected;
  try {
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(COPY_CHUNK_BYTES, opened.sizeBytes));
    let position = 0;
    while (position < opened.sizeBytes) {
      const length = Math.min(buffer.length, opened.sizeBytes - position);
      const { bytesRead } = await opened.handle.read(buffer, 0, length, position);
      if (bytesRead < 1) return { state: "not_executable" };
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await opened.handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (position !== opened.sizeBytes
      || !sameMetadata(opened.metadata, after)
      || !sameMetadata(after, pathAfter)) return { state: "not_executable" };
    return {
      state: "ready",
      identity: Object.freeze({
        sha256: digest.digest("hex"),
        device: after.dev.toString(),
        inode: after.ino.toString(),
        sizeBytes: opened.sizeBytes,
        mode: opened.mode,
        uid: opened.uid,
        gid: opened.gid,
      }),
    };
  } catch {
    return { state: "not_executable" };
  } finally {
    await opened.handle.close().catch(() => undefined);
  }
}

function sandboxArguments(snapshotFd: number, toolArguments: readonly string[]): string[] {
  return [
    "--unshare-all",
    "--die-with-parent",
    // boundedSpawn creates the terminal-free session and process group. The
    // PID-namespace child must stay in it so timeout/output cancellation reaps
    // the complete probe rather than only bwrap's outer launcher.
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--symlink", "usr/sbin", "/sbin",
    "--dir", "/etc",
    "--dir", "/etc/alternatives",
    // Kali's libblas linker name in /usr resolves through /etc/alternatives.
    // Bind only its capability-free selected target for isolated Nmap probes.
    "--ro-bind-try",
    "/usr/lib/x86_64-linux-gnu/blas/libblas.so.3",
    "/etc/alternatives/libblas.so.3-x86_64-linux-gnu",
    // The reviewed probe tools do not require process metadata. Keeping /proc
    // empty avoids exposing host process state and remains compatible with the
    // production unit's ProtectKernel* and ProtectHostname restrictions,
    // which deliberately forbid a nested procfs mount.
    "--dir", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
    "--dir", "/nonexistent",
    "--dir", "/probe",
    "--perms", "0500",
    "--ro-bind-data", String(snapshotFd), "/probe/tool",
    "--clearenv",
    "--setenv", "HOME", "/nonexistent",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "LC_ALL", "C.UTF-8",
    "--chdir", "/tmp",
    "--",
    "/probe/tool",
    ...toolArguments,
  ];
}

function killProbeGroup(child: ChildProcess, signal: NodeJS.Signals): void {
  if (child.pid && process.platform !== "win32") {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch {
      // The group can race detached-process setup; the tracked child still
      // needs the same signal even when the group is not visible yet.
    }
  }
  try { child.kill(signal); } catch { /* the tracked child is already terminal */ }
}

function boundedSpawn(input: Readonly<{
  helperPath: string;
  arguments: readonly string[];
  snapshotFd: number;
  timeoutMs: number;
  maximumOutputBytes: number;
  executableIdentity: ToolExecutableIdentity;
}>): Promise<ToolProbeExecutionResult> {
  return new Promise((resolveResult) => {
    const child = spawn(input.helperPath, input.arguments, {
      detached: true,
      env: { HOME: "/nonexistent", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
      shell: false,
      stdio: ["ignore", "pipe", "pipe", input.snapshotFd],
      windowsHide: true,
    });
    const chunks: Buffer[] = [];
    let total = 0;
    let timedOut = false;
    let outputLimitExceeded = false;
    let spawnErrorCode: string | undefined;
    const accept = (chunk: Buffer): void => {
      total += chunk.length;
      if (total <= input.maximumOutputBytes) chunks.push(chunk);
      else {
        outputLimitExceeded = true;
        killProbeGroup(child, "SIGKILL");
      }
    };
    child.stdout!.on("data", accept);
    child.stderr!.on("data", accept);
    child.on("error", (error: NodeJS.ErrnoException) => {
      spawnErrorCode = error.code ?? "SPAWN_ERROR";
    });
    const timer = setTimeout(() => {
      timedOut = true;
      killProbeGroup(child, "SIGKILL");
    }, input.timeoutMs);
    timer.unref?.();
    child.on("close", (exitCode, signal) => {
      clearTimeout(timer);
      const output = Buffer.concat(chunks).toString("utf8");
      resolveResult({
        exitCode,
        signal,
        stdout: output,
        stderr: "",
        timedOut,
        outputLimitExceeded,
        executableIdentity: input.executableIdentity,
        ...(spawnErrorCode ? { spawnErrorCode } : {}),
      });
    });
  });
}

/**
 * Target-free probe environment. It executes a sealed memfd snapshot through
 * a hash-pinned bubblewrap helper in a new network namespace and read-only
 * filesystem view. Projection reads never call this environment directly.
 */
export class BubblewrapToolProbeEnvironment implements ToolExecutionPreflightEnvironment {
  readonly isolation = Object.freeze({
    networkEnforced: true,
    filesystemWritesEnforced: true,
    immutableSnapshotEnforced: true,
  });
  private readonly snapshots = new Map<string, CachedExecutableSnapshot>();
  private readonly activeInspections = new Map<string, Promise<
    | Readonly<{ state: "ready"; identity: ToolExecutableIdentity }>
    | Readonly<{ state: "missing" | "not_regular" | "not_executable" | "unsafe_permissions" }>
  >>();
  private cachedBytes = 0;
  private snapshotBuilds = 0;
  private snapshotCacheHits = 0;
  private closed = false;

  constructor(readonly descriptor: BubblewrapProbeSandboxDescriptor) {
    parseBubblewrapProbeSandboxDescriptor(descriptor);
    if (process.platform !== "linux") throw new Error("Bubblewrap tool probes require Linux");
  }

  private evict(path: string): void {
    const existing = this.snapshots.get(path);
    if (!existing) return;
    this.snapshots.delete(path);
    this.cachedBytes -= existing.identity.sizeBytes;
    try { closeSync(existing.descriptor); } catch { /* already closed during teardown */ }
  }

  private retain(snapshot: CachedExecutableSnapshot): void {
    this.evict(snapshot.path);
    while (this.snapshots.size >= MAXIMUM_CACHED_SNAPSHOTS
      || this.cachedBytes + snapshot.identity.sizeBytes > MAXIMUM_CACHED_SNAPSHOT_BYTES) {
      const oldest = this.snapshots.keys().next().value as string | undefined;
      if (!oldest) break;
      this.evict(oldest);
    }
    this.snapshots.set(snapshot.path, snapshot);
    this.cachedBytes += snapshot.identity.sizeBytes;
  }

  private touch(snapshot: CachedExecutableSnapshot): void {
    this.snapshots.delete(snapshot.path);
    this.snapshots.set(snapshot.path, snapshot);
  }

  private async inspectAndCache(path: string): Promise<
    | Readonly<{ state: "ready"; identity: ToolExecutableIdentity }>
    | Readonly<{ state: "missing" | "not_regular" | "not_executable" | "unsafe_permissions" }>
  > {
    if (this.closed) return { state: "not_executable" };
    const inspected = await openExecutable(path);
    if (inspected.state !== "ready") {
      this.evict(path);
      return inspected;
    }
    const { opened } = inspected;
    try {
      const cached = this.snapshots.get(path);
      if (cached && sameMetadata(cached.metadata, opened.metadata)) {
        this.snapshotCacheHits += 1;
        this.touch(cached);
        return { state: "ready", identity: cached.identity };
      }
      if (cached) this.evict(path);
      const snapshot = await createSealedSnapshot(opened);
      if (this.closed) {
        closeSync(snapshot.descriptor);
        return { state: "not_executable" };
      }
      this.snapshotBuilds += 1;
      this.retain(snapshot);
      return { state: "ready", identity: snapshot.identity };
    } catch {
      this.evict(path);
      return { state: "not_executable" };
    } finally {
      await opened.handle.close().catch(() => undefined);
    }
  }

  async inspectExecutable(path: string) {
    const active = this.activeInspections.get(path);
    if (active) return active;
    const inspection = this.inspectAndCache(path).finally(() => {
      if (this.activeInspections.get(path) === inspection) {
        this.activeInspections.delete(path);
      }
    });
    this.activeInspections.set(path, inspection);
    return inspection;
  }

  async inspectWorkingDirectory(path: string): Promise<boolean> {
    try {
      const metadata = await stat(path);
      return metadata.isDirectory();
    } catch {
      return false;
    }
  }

  async readNoNewPrivileges(): Promise<boolean | null> {
    try {
      const match = /^NoNewPrivs:\s+([01])$/mu.exec(readFileSync("/proc/self/status", "utf8"));
      return match ? match[1] === "1" : null;
    } catch {
      return null;
    }
  }

  async execute(input: Readonly<{
    executablePath: string;
    arguments: readonly string[];
    workingDirectory?: string;
    timeoutMs: number;
    maximumOutputBytes: number;
    expectedExecutableIdentity: ToolExecutableIdentity;
  }>): Promise<ToolProbeExecutionResult> {
    const helper = await inspectExecutableIdentity(this.descriptor.executablePath);
    const source = await this.inspectExecutable(input.executablePath);
    const snapshot = this.snapshots.get(input.executablePath);
    if (helper.state !== "ready"
      || helper.identity.sha256 !== this.descriptor.expectedSha256
      || !await helperHasNoCapabilities(this.descriptor.executablePath)
      || source.state !== "ready"
      || !sameIdentity(source.identity, input.expectedExecutableIdentity)
      || snapshot === undefined
      || !sameIdentity(snapshot.identity, input.expectedExecutableIdentity)) {
      return {
        exitCode: null,
        signal: null,
        stdout: "",
        stderr: "",
        timedOut: false,
        outputLimitExceeded: false,
        executableIdentity: null,
        spawnErrorCode: "EINTEGRITY",
      };
    }
    let executionSnapshot: FileHandle | undefined;
    try {
      // bwrap consumes the inherited file-description offset. Reopen the
      // sealed memfd for each probe so every wave starts at byte zero without
      // rebuilding or mutating the cached immutable snapshot.
      executionSnapshot = await open(
        `/proc/self/fd/${snapshot.descriptor}`,
        fsConstants.O_RDONLY,
      );
      const result = await boundedSpawn({
        helperPath: this.descriptor.executablePath,
        arguments: sandboxArguments(3, input.arguments),
        snapshotFd: executionSnapshot.fd,
        timeoutMs: input.timeoutMs,
        maximumOutputBytes: input.maximumOutputBytes,
        executableIdentity: input.expectedExecutableIdentity,
      });
      const sourceAfter = await this.inspectExecutable(input.executablePath);
      if (sourceAfter.state !== "ready"
        || !sameIdentity(sourceAfter.identity, input.expectedExecutableIdentity)) {
        return { ...result, executableIdentity: null, spawnErrorCode: "EIDENTITY" };
      }
      return result;
    } catch {
      return {
        exitCode: null,
        signal: null,
        stdout: "",
        stderr: "",
        timedOut: false,
        outputLimitExceeded: false,
        executableIdentity: null,
        spawnErrorCode: "ESANDBOX",
      };
    } finally {
      await executionSnapshot?.close().catch(() => undefined);
    }
  }

  /** Content-free resource accounting used by soak tests and health diagnostics. */
  resourceSnapshot(): BubblewrapProbeResourceSnapshot {
    return Object.freeze({
      cachedExecutableSnapshots: this.snapshots.size,
      cachedExecutableBytes: this.cachedBytes,
      immutableSnapshotBuilds: this.snapshotBuilds,
      immutableSnapshotCacheHits: this.snapshotCacheHits,
      closed: this.closed,
    });
  }

  /** Call only after the owning runner has drained its bounded active probe. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const path of [...this.snapshots.keys()]) this.evict(path);
  }
}

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  type BigIntStats,
} from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import type {
  LocalToolCapabilityManifest,
  ReviewedLocalToolCapability,
} from "./LocalToolCapabilityManifest";
import { inspectLinuxFileCapabilities } from "./AsyncFileCapabilityInspection";

export const LOCAL_TOOL_INSTALLATION_RECEIPT_SCHEMA_VERSION =
  "ti-scale.local-tool-installation-receipt.v1" as const;

const MAXIMUM_EXECUTABLE_BYTES = 256 * 1_024 * 1_024;
const GETCAP_OUTPUT_LIMIT = 4 * 1_024;

export type LocalToolInstallationCode =
  | "ready"
  | "activation_disabled"
  | "executable_missing"
  | "executable_not_regular"
  | "executable_not_executable"
  | "executable_unsafe_permissions"
  | "executable_too_large"
  | "executable_identity_changed"
  | "executable_hash_mismatch"
  | "dependency_unavailable"
  | "dependency_hash_mismatch"
  | "file_capability_inspection_unavailable"
  | "no_new_privileges_file_capability_conflict";

export interface LocalToolInstallationReceipt {
  readonly schemaVersion: typeof LOCAL_TOOL_INSTALLATION_RECEIPT_SCHEMA_VERSION;
  readonly manifestSha256: string;
  readonly toolId: string;
  readonly bindingSha256: string;
  readonly status: "ready" | "unavailable";
  readonly code: LocalToolInstallationCode;
  readonly checkedAt: string;
  readonly expectedExecutableSha256: string;
  readonly observedExecutableSha256: string | null;
  readonly executableIdentity: Readonly<{
    readonly device: string;
    readonly inode: string;
    readonly sizeBytes: number;
    readonly mode: number;
    readonly uid: number;
    readonly gid: number;
  }> | null;
  readonly fileCapabilitiesPresent: boolean | null;
  readonly fileCapabilitiesOutputSha256: string | null;
  readonly noNewPrivilegesCompatible: boolean;
  readonly probeBoundary: Readonly<{
    readonly toolExecuted: false;
    readonly shell: false;
    readonly targetArgumentsSupplied: false;
    readonly providerArgumentsSupplied: false;
    readonly mcpArgumentsSupplied: false;
    readonly externalContact: "not_attempted";
  }>;
  readonly grantsMissionExecution: false;
  readonly explanation: string;
  readonly remediation: string | null;
}

export interface FileCapabilityInspection {
  readonly state: "none" | "present" | "unknown";
  readonly outputSha256: string | null;
}

export interface LocalToolInstallationPreflightOptions {
  readonly now?: () => Date;
  readonly allowedOwnerUids?: readonly number[];
  readonly inspectFileCapabilities?: (path: string) => FileCapabilityInspection;
  readonly getcapPath?: string;
}

interface InspectedExecutable {
  readonly sha256: string;
  readonly identity: NonNullable<LocalToolInstallationReceipt["executableIdentity"]>;
}

interface AsyncInspectionCacheEntry {
  readonly metadata: BigIntStats;
  readonly inspected: InspectedExecutable;
}

export interface LocalToolInstallationInspectionCacheSnapshot {
  readonly entries: number;
  readonly hashBuilds: number;
  readonly cacheHits: number;
}

const ASYNC_INSPECTION_CACHE_LIMIT = 256;
const asyncInspectionCache = new Map<string, AsyncInspectionCacheEntry>();
let asyncInspectionHashBuilds = 0;
let asyncInspectionCacheHits = 0;

export function localToolInstallationInspectionCacheSnapshot(): LocalToolInstallationInspectionCacheSnapshot {
  return Object.freeze({
    entries: asyncInspectionCache.size,
    hashBuilds: asyncInspectionHashBuilds,
    cacheHits: asyncInspectionCacheHits,
  });
}

function sameIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mode === right.mode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

class InspectionError extends Error {
  constructor(readonly code: LocalToolInstallationCode) {
    super(code);
  }
}

function inspectedExecutable(
  path: string,
  allowedOwnerUids: ReadonlySet<number>,
  executable = true,
): InspectedExecutable {
  let metadata: BigIntStats;
  try {
    metadata = lstatSync(path, { bigint: true });
  } catch {
    throw new InspectionError("executable_missing");
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new InspectionError("executable_not_regular");
  }
  const size = Number(metadata.size);
  const mode = Number(metadata.mode & 0o7777n);
  const uid = Number(metadata.uid);
  if (!Number.isSafeInteger(size) || size < 1 || size > MAXIMUM_EXECUTABLE_BYTES) {
    throw new InspectionError("executable_too_large");
  }
  if (executable && (mode & 0o111) === 0) throw new InspectionError("executable_not_executable");
  if (!allowedOwnerUids.has(uid) || (mode & 0o022) !== 0 || (mode & 0o7000) !== 0) {
    throw new InspectionError("executable_unsafe_permissions");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor, { bigint: true });
    if (!sameIdentity(metadata, opened)) throw new InspectionError("executable_identity_changed");
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (!sameIdentity(opened, after) || bytes.length !== Number(after.size)) {
      throw new InspectionError("executable_identity_changed");
    }
    return {
      sha256: createHash("sha256").update(bytes).digest("hex"),
      identity: {
        device: after.dev.toString(),
        inode: after.ino.toString(),
        sizeBytes: Number(after.size),
        mode: Number(after.mode & 0o7777n),
        uid: Number(after.uid),
        gid: Number(after.gid),
      },
    };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function inspectionCacheKey(
  path: string,
  allowedOwnerUids: ReadonlySet<number>,
  executable: boolean,
): string {
  return `${path}\u0000${executable ? "x" : "r"}\u0000${[...allowedOwnerUids].sort((a, b) => a - b).join(",")}`;
}

function retainAsyncInspection(key: string, entry: AsyncInspectionCacheEntry): void {
  asyncInspectionCache.delete(key);
  while (asyncInspectionCache.size >= ASYNC_INSPECTION_CACHE_LIMIT) {
    const oldest = asyncInspectionCache.keys().next().value as string | undefined;
    if (!oldest) break;
    asyncInspectionCache.delete(oldest);
  }
  asyncInspectionCache.set(key, entry);
}

async function inspectedExecutableAsync(
  path: string,
  allowedOwnerUids: ReadonlySet<number>,
  executable = true,
  signal?: AbortSignal,
): Promise<InspectedExecutable> {
  if (signal?.aborted) {
    const error = new Error("Local tool installation readiness was cancelled");
    error.name = "AbortError";
    throw error;
  }
  let metadata: BigIntStats;
  try {
    metadata = await lstat(path, { bigint: true });
  } catch {
    throw new InspectionError("executable_missing");
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new InspectionError("executable_not_regular");
  }
  const size = Number(metadata.size);
  const mode = Number(metadata.mode & 0o7777n);
  const uid = Number(metadata.uid);
  if (!Number.isSafeInteger(size) || size < 1 || size > MAXIMUM_EXECUTABLE_BYTES) {
    throw new InspectionError("executable_too_large");
  }
  if (executable && (mode & 0o111) === 0) throw new InspectionError("executable_not_executable");
  if (!allowedOwnerUids.has(uid) || (mode & 0o022) !== 0 || (mode & 0o7000) !== 0) {
    throw new InspectionError("executable_unsafe_permissions");
  }
  const key = inspectionCacheKey(path, allowedOwnerUids, executable);
  const cached = asyncInspectionCache.get(key);
  if (cached && sameIdentity(cached.metadata, metadata)) {
    asyncInspectionCacheHits += 1;
    asyncInspectionCache.delete(key);
    asyncInspectionCache.set(key, cached);
    return cached.inspected;
  }
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(metadata, opened)) throw new InspectionError("executable_identity_changed");
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(Math.min(1024 * 1024, size));
    let position = 0;
    while (position < size) {
      if (signal?.aborted) {
        const error = new Error("Local tool installation readiness was cancelled");
        error.name = "AbortError";
        throw error;
      }
      const length = Math.min(buffer.length, size - position);
      const { bytesRead } = await handle.read(buffer, 0, length, position);
      if (signal?.aborted) {
        const error = new Error("Local tool installation readiness was cancelled");
        error.name = "AbortError";
        throw error;
      }
      if (bytesRead < 1) throw new InspectionError("executable_identity_changed");
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(path, { bigint: true });
    if (position !== size || !sameIdentity(opened, after) || !sameIdentity(after, pathAfter)) {
      throw new InspectionError("executable_identity_changed");
    }
    const inspected = Object.freeze({
      sha256: digest.digest("hex"),
      identity: Object.freeze({
        device: after.dev.toString(),
        inode: after.ino.toString(),
        sizeBytes: Number(after.size),
        mode: Number(after.mode & 0o7777n),
        uid: Number(after.uid),
        gid: Number(after.gid),
      }),
    });
    asyncInspectionHashBuilds += 1;
    retainAsyncInspection(key, { metadata: after, inspected });
    return inspected;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function defaultCapabilityInspector(getcapPath: string): (path: string) => FileCapabilityInspection {
  return (path) => {
    let getcap: BigIntStats;
    try {
      getcap = lstatSync(getcapPath, { bigint: true });
    } catch {
      return { state: "unknown", outputSha256: null };
    }
    const mode = Number(getcap.mode & 0o7777n);
    if (getcap.isSymbolicLink()
      || !getcap.isFile()
      || Number(getcap.uid) !== 0
      || (mode & 0o022) !== 0
      || (mode & 0o7000) !== 0
      || (mode & 0o111) === 0) {
      return { state: "unknown", outputSha256: null };
    }
    const result = spawnSync(getcapPath, ["-n", "--", path], {
      encoding: "utf8",
      env: { HOME: "/nonexistent", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
      maxBuffer: GETCAP_OUTPUT_LIMIT,
      shell: false,
      timeout: 1_000,
      windowsHide: true,
    });
    if (result.error || result.status !== 0 || result.signal !== null || result.stderr !== "") {
      return { state: "unknown", outputSha256: null };
    }
    const output = result.stdout;
    if (Buffer.byteLength(output, "utf8") > GETCAP_OUTPUT_LIMIT) {
      return { state: "unknown", outputSha256: null };
    }
    const outputSha256 = createHash("sha256").update(output, "utf8").digest("hex");
    return { state: output.trim() ? "present" : "none", outputSha256 };
  };
}

function explanation(code: LocalToolInstallationCode, tool: ReviewedLocalToolCapability): Readonly<{
  explanation: string;
  remediation: string | null;
}> {
  switch (code) {
    case "ready":
      return {
        explanation: "The exact root-owned executable matches the reviewed SHA-256, has no Linux file capabilities, and is structurally compatible with NoNewPrivileges. This inspection did not execute the tool or contact a target.",
        remediation: null,
      };
    case "activation_disabled":
      return {
        explanation: tool.activationReason ?? "The operator disabled this local tool binding.",
        remediation: "Review the documented incompatibility and create a new manifest version before enabling this tool.",
      };
    case "no_new_privileges_file_capability_conflict":
      return {
        explanation: "The executable carries Linux file capabilities, so executing it under Ti-Scale's NoNewPrivileges service boundary can fail or create an unreviewed privilege transition.",
        remediation: "Keep the binding disabled. If the capability is required, provision a separately reviewed unprivileged executable copy and pin its new SHA-256 without weakening NoNewPrivileges.",
      };
    case "file_capability_inspection_unavailable":
      return {
        explanation: "Ti-Scale could not establish whether the executable carries Linux file capabilities, so NoNewPrivileges compatibility remains unknown.",
        remediation: "Restore the trusted local file-capability inspection dependency and repeat this target-free installation check.",
      };
    case "executable_hash_mismatch":
      return {
        explanation: "The installed executable bytes do not match the reviewed manifest hash.",
        remediation: "Review the package change, update the manifest through release control, and repeat all readiness checks.",
      };
    case "dependency_unavailable":
      return {
        explanation: "A reviewed runtime file required by this tool is missing, linked, unsafe, or changed identity, so execution was not enabled.",
        remediation: "Restore the exact root-owned dependency set declared by the reviewed manifest and repeat the target-free readiness wave.",
      };
    case "dependency_hash_mismatch":
      return {
        explanation: "A reviewed runtime dependency no longer matches its pinned SHA-256, so the tool was not enabled.",
        remediation: "Review the dependency update and publish a new reviewed manifest before enabling this binding.",
      };
    default:
      return {
        explanation: "The exact reviewed executable did not pass the local immutable-file installation boundary.",
        remediation: "Restore the expected root-owned, non-writable executable and repeat this target-free installation check.",
      };
  }
}

function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) freeze(child);
  }
  return value;
}

function installationReceipt(
  manifest: LocalToolCapabilityManifest,
  tool: ReviewedLocalToolCapability,
  checkedAt: string,
  inspected: InspectedExecutable | null,
  capabilities: FileCapabilityInspection,
  code: LocalToolInstallationCode,
): LocalToolInstallationReceipt {
  const copy = explanation(code, tool);
  return freeze({
    schemaVersion: LOCAL_TOOL_INSTALLATION_RECEIPT_SCHEMA_VERSION,
    manifestSha256: manifest.descriptor.manifestSha256,
    toolId: tool.toolId,
    bindingSha256: tool.bindingSha256,
    status: code === "ready" ? "ready" : "unavailable",
    code,
    checkedAt,
    expectedExecutableSha256: tool.executable.expectedSha256,
    observedExecutableSha256: inspected?.sha256 ?? null,
    executableIdentity: inspected?.identity ?? null,
    fileCapabilitiesPresent: capabilities.state === "unknown"
      ? null
      : capabilities.state === "present",
    fileCapabilitiesOutputSha256: capabilities.outputSha256,
    noNewPrivilegesCompatible: capabilities.state === "none",
    probeBoundary: {
      toolExecuted: false,
      shell: false,
      targetArgumentsSupplied: false,
      providerArgumentsSupplied: false,
      mcpArgumentsSupplied: false,
      externalContact: "not_attempted",
    },
    grantsMissionExecution: false,
    explanation: copy.explanation,
    remediation: copy.remediation,
  } satisfies LocalToolInstallationReceipt);
}

export class LocalToolInstallationPreflight {
  private readonly now: () => Date;
  private readonly allowedOwnerUids: ReadonlySet<number>;
  private readonly inspectCapabilities: (path: string) => FileCapabilityInspection;

  constructor(private readonly options: LocalToolInstallationPreflightOptions = {}) {
    this.now = options.now ?? (() => new Date());
    const owners = options.allowedOwnerUids ?? [0];
    if (owners.length < 1
      || owners.length > 8
      || new Set(owners).size !== owners.length
      || owners.some((uid) => !Number.isSafeInteger(uid) || uid < 0)) {
      throw new Error("Local tool installation preflight allowedOwnerUids is invalid");
    }
    this.allowedOwnerUids = new Set(owners);
    this.inspectCapabilities = options.inspectFileCapabilities
      ?? defaultCapabilityInspector(options.getcapPath ?? "/usr/sbin/getcap");
  }

  inspect(
    manifest: LocalToolCapabilityManifest,
    toolId: string,
  ): LocalToolInstallationReceipt {
    return this.inspectWithCapabilities(manifest, toolId, this.inspectCapabilities);
  }

  private inspectWithCapabilities(
    manifest: LocalToolCapabilityManifest,
    toolId: string,
    inspectCapabilities: (path: string) => FileCapabilityInspection,
  ): LocalToolInstallationReceipt {
    const tool = manifest.resolve(toolId);
    if (!tool) throw new Error(`Unknown reviewed local tool ${toolId}`);
    const checkedAt = this.now().toISOString();
    let inspected: InspectedExecutable | null = null;
    let capabilities: FileCapabilityInspection = { state: "unknown", outputSha256: null };
    let code: LocalToolInstallationCode;
    try {
      inspected = inspectedExecutable(tool.executable.path, this.allowedOwnerUids);
      if (inspected.sha256 !== tool.executable.expectedSha256) {
        code = "executable_hash_mismatch";
      } else {
        let dependencyCode: LocalToolInstallationCode | null = null;
        for (const dependency of tool.dependencyFiles ?? []) {
          try {
            const inspectedDependency = inspectedExecutable(
              dependency.path,
              this.allowedOwnerUids,
              dependency.executable,
            );
            if (inspectedDependency.sha256 !== dependency.expectedSha256) {
              dependencyCode = "dependency_hash_mismatch";
              break;
            }
          } catch {
            dependencyCode = "dependency_unavailable";
            break;
          }
        }
        if (dependencyCode) {
          code = dependencyCode;
        } else {
          capabilities = inspectCapabilities(tool.executable.path);
          code = capabilities.state === "unknown"
            ? "file_capability_inspection_unavailable"
            : capabilities.state === "present"
              ? "no_new_privileges_file_capability_conflict"
              : tool.activation === "disabled"
                ? "activation_disabled"
                : "ready";
        }
      }
    } catch (error) {
      code = error instanceof InspectionError ? error.code : "executable_identity_changed";
    }
    return installationReceipt(manifest, tool, checkedAt, inspected, capabilities, code);
  }

  inspectAll(manifest: LocalToolCapabilityManifest): readonly LocalToolInstallationReceipt[] {
    return Object.freeze(manifest.list().map(({ toolId }) => this.inspect(manifest, toolId)));
  }

  /**
   * Event-loop-safe readiness inspection. The executable identity checks stay
   * local and deterministic while the trusted getcap subprocess is awaited
   * asynchronously, allowing SIGTERM and shutdown deadlines to be observed.
   */
  async inspectAsync(
    manifest: LocalToolCapabilityManifest,
    toolId: string,
    signal?: AbortSignal,
  ): Promise<LocalToolInstallationReceipt> {
    if (signal?.aborted) {
      const error = new Error("Local tool installation readiness was cancelled");
      error.name = "AbortError";
      throw error;
    }
    const tool = manifest.resolve(toolId);
    if (!tool) throw new Error(`Unknown reviewed local tool ${toolId}`);
    const capabilities = this.options.inspectFileCapabilities
      ? this.inspectCapabilities(tool.executable.path)
      : await inspectLinuxFileCapabilities(tool.executable.path, {
          helperPath: this.options.getcapPath ?? "/usr/sbin/getcap",
          ...(signal ? { signal } : {}),
        });
    if (signal?.aborted) {
      const error = new Error("Local tool installation readiness was cancelled");
      error.name = "AbortError";
      throw error;
    }
    const checkedAt = this.now().toISOString();
    let inspected: InspectedExecutable | null = null;
    let code: LocalToolInstallationCode;
    try {
      inspected = await inspectedExecutableAsync(
        tool.executable.path,
        this.allowedOwnerUids,
        true,
        signal,
      );
      if (signal?.aborted) {
        const error = new Error("Local tool installation readiness was cancelled");
        error.name = "AbortError";
        throw error;
      }
      if (inspected.sha256 !== tool.executable.expectedSha256) {
        code = "executable_hash_mismatch";
      } else {
        let dependencyCode: LocalToolInstallationCode | null = null;
        for (const dependency of tool.dependencyFiles ?? []) {
          if (signal?.aborted) {
            const error = new Error("Local tool installation readiness was cancelled");
            error.name = "AbortError";
            throw error;
          }
          try {
            const inspectedDependency = await inspectedExecutableAsync(
              dependency.path,
              this.allowedOwnerUids,
              dependency.executable,
              signal,
            );
            if (inspectedDependency.sha256 !== dependency.expectedSha256) {
              dependencyCode = "dependency_hash_mismatch";
              break;
            }
          } catch (error) {
            if ((error as Error).name === "AbortError") throw error;
            dependencyCode = "dependency_unavailable";
            break;
          }
        }
        code = dependencyCode
          ?? (capabilities.state === "unknown"
            ? "file_capability_inspection_unavailable"
            : capabilities.state === "present"
              ? "no_new_privileges_file_capability_conflict"
              : tool.activation === "disabled"
                ? "activation_disabled"
                : "ready");
      }
    } catch (error) {
      if ((error as Error).name === "AbortError") throw error;
      code = error instanceof InspectionError ? error.code : "executable_identity_changed";
    }
    return installationReceipt(manifest, tool, checkedAt, inspected, capabilities, code);
  }

  async inspectAllAsync(
    manifest: LocalToolCapabilityManifest,
    signal?: AbortSignal,
  ): Promise<readonly LocalToolInstallationReceipt[]> {
    const receipts = await Promise.all(manifest.list().map(({ toolId }) =>
      this.inspectAsync(manifest, toolId, signal)));
    return Object.freeze(receipts);
  }
}

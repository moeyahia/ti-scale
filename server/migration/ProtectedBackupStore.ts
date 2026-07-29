import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  futimesSync,
  lstatSync,
  linkSync,
  mkdirSync,
  openSync,
  readSync,
  readlinkSync,
  realpathSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import type { Stats } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { sha256Text } from "./SecretSafety";

const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
export const PROTECTED_BACKUP_STORE_DISABLED_ERROR =
  "Protected historical source copies are disabled by operator no-backup policy";

export interface DiscoveredRegularSource {
  readonly absolutePath: string;
  readonly containmentRoot: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
}

export interface DiscoveredSymlinkSource {
  readonly absolutePath: string;
  readonly containmentRoot: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
}

export interface VerifiedSourceIdentity {
  readonly device: number;
  readonly inode: number;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly sha256: string;
}

interface ProtectedTarget {
  readonly parentDescriptor: number;
  readonly parentDescriptorPath: string;
  readonly finalName: string;
  readonly finalDescriptorPath: string;
}

interface InspectedFile {
  readonly sha256: string;
  readonly byteSize: number;
  readonly content?: Buffer;
}

export interface ProtectedBackupStoreTestHooks {
  /** Test-only scheduling point used to deterministically exercise replacement races. */
  readonly afterExistingDestinationRead?: () => void;
}

function inside(root: string, candidate: string): boolean {
  const value = relative(resolve(root), resolve(candidate));
  return value === "" || (value !== ".." && !value.startsWith(`..${sep}`));
}

function closeQuietly(descriptor: number | undefined): void {
  if (descriptor === undefined) return;
  try { closeSync(descriptor); } catch { /* best-effort cleanup */ }
}

function descriptorPath(descriptor: number): string {
  for (const base of ["/proc/self/fd", "/dev/fd"]) {
    try {
      const value = `${base}/${descriptor}`;
      realpathSync(value);
      return value;
    } catch { /* try the next descriptor filesystem */ }
  }
  throw new Error("Descriptor-relative protected backup operations are unavailable");
}

function assertStableRegularState(
  descriptorState: Stats,
  pathState: Stats,
  expected: Pick<DiscoveredRegularSource, "byteSize" | "modifiedAt">,
): void {
  if (
    !descriptorState.isFile() || !pathState.isFile()
    || descriptorState.dev !== pathState.dev || descriptorState.ino !== pathState.ino
    || descriptorState.size !== expected.byteSize
    || descriptorState.mtime.toISOString() !== expected.modifiedAt
  ) throw new Error("Historical source no longer matches discovery provenance");
}

function openContainedSource(source: DiscoveredRegularSource): { descriptor: number; before: Stats } {
  if (!SHA256.test(source.sha256) || !Number.isSafeInteger(source.byteSize) || source.byteSize < 0) {
    throw new Error("Historical source provenance is malformed");
  }
  const rootState = lstatSync(source.containmentRoot);
  if (!rootState.isDirectory() || rootState.isSymbolicLink()) {
    throw new Error("Historical source containment root is no longer a stable directory");
  }
  const rootReal = realpathSync(source.containmentRoot);
  if (!inside(rootReal, source.absolutePath)) throw new Error("Historical source escaped its engagement directory");
  let descriptor: number | undefined;
  try {
    descriptor = openSync(source.absolutePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    const pathState = lstatSync(source.absolutePath);
    assertStableRegularState(before, pathState, source);
    const sourceReal = realpathSync(descriptorPath(descriptor));
    if (!inside(rootReal, sourceReal)) throw new Error("Historical source resolved outside its engagement directory");
    return { descriptor, before };
  } catch (error) {
    closeQuietly(descriptor);
    throw error;
  }
}

function writeAll(descriptor: number, buffer: Buffer): void {
  let offset = 0;
  while (offset < buffer.length) {
    const written = writeSync(descriptor, buffer, offset, buffer.length - offset);
    if (written <= 0) throw new Error("Protected backup stopped before all bytes were written");
    offset += written;
  }
}

function inspectOpenFile(descriptor: number, captureContent: boolean): InspectedFile {
  const hash = createHash("sha256");
  const chunks: Buffer[] | undefined = captureContent ? [] : undefined;
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let position = 0;
  while (true) {
    const length = readSync(descriptor, buffer, 0, buffer.length, position);
    if (!length) break;
    const chunk = buffer.subarray(0, length);
    hash.update(chunk);
    chunks?.push(Buffer.from(chunk));
    position += length;
  }
  return {
    sha256: hash.digest("hex"),
    byteSize: position,
    ...(chunks ? { content: Buffer.concat(chunks) } : {}),
  };
}

/** Re-read the current inode and prove it is still the exact discovered source. */
export function verifyDiscoveredRegularSource(source: DiscoveredRegularSource): VerifiedSourceIdentity {
  const opened = openContainedSource(source);
  try {
    const inspected = inspectOpenFile(opened.descriptor, false);
    const after = fstatSync(opened.descriptor);
    const pathState = lstatSync(source.absolutePath);
    assertStableRegularState(after, pathState, source);
    if (
      opened.before.dev !== after.dev || opened.before.ino !== after.ino
      || opened.before.size !== after.size || opened.before.mtimeMs !== after.mtimeMs
      || inspected.sha256 !== source.sha256 || inspected.byteSize !== source.byteSize
    ) throw new Error("Historical source changed after discovery");
    return {
      device: after.dev,
      inode: after.ino,
      byteSize: inspected.byteSize,
      modifiedAt: after.mtime.toISOString(),
      sha256: inspected.sha256,
    };
  } finally {
    closeQuietly(opened.descriptor);
  }
}

/** Verify a symlink object without ever resolving or reading its target bytes. */
export function verifyDiscoveredSymlinkSource(source: DiscoveredSymlinkSource): VerifiedSourceIdentity {
  if (!SHA256.test(source.sha256) || !Number.isSafeInteger(source.byteSize) || source.byteSize < 0) {
    throw new Error("Historical symlink provenance is malformed");
  }
  const rootState = lstatSync(source.containmentRoot);
  if (!rootState.isDirectory() || rootState.isSymbolicLink()) {
    throw new Error("Historical source containment root is no longer a stable directory");
  }
  if (!inside(realpathSync(source.containmentRoot), source.absolutePath)) {
    throw new Error("Historical symlink escaped its engagement directory");
  }
  try {
    const before = lstatSync(source.absolutePath);
    const fingerprint = sha256Text(`symlink\0${readlinkSync(source.absolutePath)}`);
    const after = lstatSync(source.absolutePath);
    if (
      !before.isSymbolicLink() || !after.isSymbolicLink()
      || before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
      || after.size !== source.byteSize || after.mtime.toISOString() !== source.modifiedAt
      || fingerprint !== source.sha256
    ) throw new Error("changed");
    return {
      device: after.dev,
      inode: after.ino,
      byteSize: after.size,
      modifiedAt: after.mtime.toISOString(),
      sha256: fingerprint,
    };
  } catch {
    throw new Error("Historical symbolic link changed after discovery");
  }
}

function safeRelativeSegments(relativePath: string): string[] {
  if (!relativePath || isAbsolute(relativePath) || relativePath.includes("\\") || relativePath.includes("\0")) {
    throw new Error("Protected backup relative path is invalid");
  }
  const segments = relativePath.split("/");
  if (!segments.length || segments.some((segment) => !SAFE_SEGMENT.test(segment) || segment === "." || segment === "..")) {
    throw new Error("Protected backup relative path contains an unsafe segment");
  }
  return segments;
}

/**
 * Hash-verified, descriptor-relative protected storage. All final-file reads,
 * writes, permission changes, and publication operate beneath a pinned parent
 * directory descriptor and use O_NOFOLLOW for the final component.
 */
export class ProtectedBackupStore {
  readonly #root: string;

  constructor(
    root: string,
    private readonly testHooks: ProtectedBackupStoreTestHooks = {},
  ) {
    // Retain the exact constructor only as a source-compatibility trap. Reject
    // before resolving the configured root or creating a parent directory.
    void root;
    void this.testHooks;
    throw new Error(PROTECTED_BACKUP_STORE_DISABLED_ERROR);
    /* c8 ignore start -- unreachable retired protected-copy implementation */
    const requested = resolve(root);
    mkdirSync(requested, { recursive: true, mode: 0o700 });
    const state = lstatSync(requested);
    if (!state.isDirectory() || state.isSymbolicLink()) throw new Error("Protected backup root must be a real directory");
    this.#root = realpathSync(requested);
    const descriptor = openSync(this.#root, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0));
    try { fchmodSync(descriptor, 0o700); } finally { closeSync(descriptor); }
    /* c8 ignore stop */
  }

  #assertTargetBinding(
    target: ProtectedTarget,
    descriptor: number,
    expected: Stats,
    stage: string,
  ): Stats {
    const descriptorState = fstatSync(descriptor);
    let pathState: Stats;
    try {
      pathState = lstatSync(target.finalDescriptorPath);
    } catch {
      throw new Error(`Protected backup destination was unlinked or replaced ${stage}`);
    }
    if (
      !descriptorState.isFile() || descriptorState.nlink !== 1
      || !pathState.isFile() || pathState.isSymbolicLink() || pathState.nlink !== 1
      || descriptorState.dev !== pathState.dev || descriptorState.ino !== pathState.ino
      || descriptorState.dev !== expected.dev || descriptorState.ino !== expected.ino
    ) throw new Error(`Protected backup destination was unlinked or replaced ${stage}`);
    return descriptorState;
  }

  #openTarget(relativePath: string): ProtectedTarget {
    const segments = safeRelativeSegments(relativePath);
    const finalName = segments.pop()!;
    let current = this.#root;
    for (const segment of segments) {
      current = resolve(current, segment);
      if (!inside(this.#root, current)) throw new Error("Protected backup directory escaped its root");
      try { mkdirSync(current, { mode: 0o700 }); } catch (error) {
        const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
        if (code !== "EEXIST") throw error;
      }
      const state = lstatSync(current);
      if (!state.isDirectory() || state.isSymbolicLink()) throw new Error("Protected backup parent is not a real directory");
      const real = realpathSync(current);
      if (!inside(this.#root, real)) throw new Error("Protected backup parent resolved outside its root");
      current = real;
    }
    const parentDescriptor = openSync(current, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0));
    try {
      const parentDescriptorPath = descriptorPath(parentDescriptor);
      const pinnedReal = realpathSync(parentDescriptorPath);
      if (!inside(this.#root, pinnedReal)) throw new Error("Pinned protected backup parent escaped its root");
      fchmodSync(parentDescriptor, 0o700);
      return {
        parentDescriptor,
        parentDescriptorPath,
        finalName,
        finalDescriptorPath: `${parentDescriptorPath}/${finalName}`,
      };
    } catch (error) {
      closeQuietly(parentDescriptor);
      throw error;
    }
  }

  #inspectExisting(target: ProtectedTarget, captureContent: boolean): InspectedFile | undefined {
    let pathState: Stats;
    try { pathState = lstatSync(target.finalDescriptorPath); }
    catch (error) {
      const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
      if (code === "ENOENT") return undefined;
      throw error;
    }
    if (!pathState.isFile() || pathState.isSymbolicLink() || pathState.nlink !== 1) {
      throw new Error("Protected backup destination is not a regular file");
    }
    const descriptor = openSync(target.finalDescriptorPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const descriptorState = fstatSync(descriptor);
      if (
        !descriptorState.isFile() || descriptorState.nlink !== 1
        || descriptorState.dev !== pathState.dev || descriptorState.ino !== pathState.ino
      ) throw new Error("Protected backup destination changed during verification");
      const inspected = inspectOpenFile(descriptor, captureContent);
      this.testHooks.afterExistingDestinationRead?.();
      const after = this.#assertTargetBinding(target, descriptor, descriptorState, "after it was read");
      if (
        descriptorState.size !== after.size || descriptorState.mtimeMs !== after.mtimeMs
        || inspected.byteSize !== after.size
      ) throw new Error("Protected backup destination changed while it was read");
      fchmodSync(descriptor, 0o600);
      const afterPermissions = this.#assertTargetBinding(
        target,
        descriptor,
        descriptorState,
        "while its permissions were secured",
      );
      if (
        descriptorState.size !== afterPermissions.size
        || descriptorState.mtimeMs !== afterPermissions.mtimeMs
        || (afterPermissions.mode & 0o777) !== 0o600
      ) throw new Error("Protected backup destination changed while its permissions were secured");
      return inspected;
    } finally {
      closeQuietly(descriptor);
    }
  }

  #publishTemporary(target: ProtectedTarget, temporaryName: string): void {
    const temporaryPath = `${target.parentDescriptorPath}/${temporaryName}`;
    try {
      linkSync(temporaryPath, target.finalDescriptorPath);
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
      if (code !== "EEXIST") throw error;
    } finally {
      try { unlinkSync(temporaryPath); } catch { /* cleanup error is surfaced by final verification */ }
    }
  }

  ensureText(relativePath: string, content: string): { sha256: string; byteSize: number } {
    const bytes = Buffer.from(content, "utf8");
    const expectedHash = createHash("sha256").update(bytes).digest("hex");
    const target = this.#openTarget(relativePath);
    try {
      const existing = this.#inspectExisting(target, true);
      if (existing) {
        if (existing.sha256 !== expectedHash || !existing.content?.equals(bytes)) {
          throw new Error("Existing protected backup content failed verification");
        }
        return { sha256: existing.sha256, byteSize: existing.byteSize };
      }
      const temporaryName = `.${target.finalName}.${randomUUID()}.tmp`;
      const temporaryPath = `${target.parentDescriptorPath}/${temporaryName}`;
      let descriptor: number | undefined;
      try {
        descriptor = openSync(
          temporaryPath,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
          0o600,
        );
        writeAll(descriptor, bytes);
        fchmodSync(descriptor, 0o600);
        fsyncSync(descriptor);
        closeSync(descriptor);
        descriptor = undefined;
        this.#publishTemporary(target, temporaryName);
      } catch (error) {
        closeQuietly(descriptor);
        try { unlinkSync(temporaryPath); } catch { /* best-effort cleanup */ }
        throw error;
      }
      const published = this.#inspectExisting(target, true);
      if (!published || published.sha256 !== expectedHash || !published.content?.equals(bytes)) {
        throw new Error("Published protected backup content failed verification");
      }
      return { sha256: published.sha256, byteSize: published.byteSize };
    } finally {
      closeQuietly(target.parentDescriptor);
    }
  }

  captureRegularFile(relativePath: string, source: DiscoveredRegularSource): { sha256: string; byteSize: number } {
    // This revalidation is intentional even when a protected destination exists.
    verifyDiscoveredRegularSource(source);
    const target = this.#openTarget(relativePath);
    try {
      const existing = this.#inspectExisting(target, false);
      if (existing) {
        if (existing.sha256 !== source.sha256 || existing.byteSize !== source.byteSize) {
          throw new Error("Existing protected source backup failed verification");
        }
        return existing;
      }
      const temporaryName = `.${target.finalName}.${randomUUID()}.tmp`;
      const temporaryPath = `${target.parentDescriptorPath}/${temporaryName}`;
      const opened = openContainedSource(source);
      let destinationDescriptor: number | undefined;
      try {
        destinationDescriptor = openSync(
          temporaryPath,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
          0o600,
        );
        const hash = createHash("sha256");
        const buffer = Buffer.allocUnsafe(64 * 1024);
        let position = 0;
        while (true) {
          const length = readSync(opened.descriptor, buffer, 0, buffer.length, position);
          if (!length) break;
          const chunk = buffer.subarray(0, length);
          hash.update(chunk);
          writeAll(destinationDescriptor, chunk);
          position += length;
        }
        const after = fstatSync(opened.descriptor);
        const pathState = lstatSync(source.absolutePath);
        assertStableRegularState(after, pathState, source);
        const sourceHash = hash.digest("hex");
        if (
          opened.before.dev !== after.dev || opened.before.ino !== after.ino
          || opened.before.size !== after.size || opened.before.mtimeMs !== after.mtimeMs
          || sourceHash !== source.sha256 || position !== source.byteSize
        ) throw new Error("Historical source changed while its protected backup was created");
        fchmodSync(destinationDescriptor, 0o600);
        const modified = new Date(source.modifiedAt);
        futimesSync(destinationDescriptor, modified, modified);
        fsyncSync(destinationDescriptor);
        closeSync(destinationDescriptor);
        destinationDescriptor = undefined;
        closeSync(opened.descriptor);
        this.#publishTemporary(target, temporaryName);
      } catch (error) {
        closeQuietly(destinationDescriptor);
        closeQuietly(opened.descriptor);
        try { unlinkSync(temporaryPath); } catch { /* best-effort cleanup */ }
        throw error;
      }
      const published = this.#inspectExisting(target, false);
      if (!published || published.sha256 !== source.sha256 || published.byteSize !== source.byteSize) {
        throw new Error("Published protected source backup failed verification");
      }
      return published;
    } finally {
      closeQuietly(target.parentDescriptor);
    }
  }
}

export function assertSafeOpaqueId(value: string, label: string, prefix: string): void {
  if (!new RegExp(`^${prefix}[a-f0-9]{40}$`, "u").test(value)) {
    throw new Error(`${label} is not a valid opaque identifier`);
  }
}

export function assertSha256(value: string, label: string): void {
  if (!SHA256.test(value)) throw new Error(`${label} is not a SHA-256 digest`);
}

import { randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";

const CLOSE_ON_EXEC = (constants as unknown as Readonly<Record<string, number>>).O_CLOEXEC ?? 0;

export type DurableAtomicWritePhase =
  | "temporary_written"
  | "temporary_synced"
  | "renamed"
  | "directory_synced";

export interface DurableAtomicWriteOptions {
  readonly mode?: number;
  readonly onPhase?: (phase: DurableAtomicWritePhase) => void;
}

export type DurableDirectoryCreatePhase =
  | "directory_created"
  | "directory_synced"
  | "parent_synced";

export type DurableDirectoryRenamePhase =
  | "source_synced"
  | "renamed"
  | "parent_synced";

function syncOpenedPath(path: string, flags: number): void {
  const descriptor = openSync(path, flags);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function syncDirectory(path: string): void {
  try {
    syncOpenedPath(path, constants.O_RDONLY | constants.O_DIRECTORY | CLOSE_ON_EXEC);
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error
      ? String((error as { code?: unknown }).code)
      : "";
    // Some non-POSIX filesystems do not implement directory fsync. The live
    // ext4 release filesystem does; unsupported disposable test filesystems
    // may safely fall back after the file itself was synced and renamed.
    if (!["EINVAL", "ENOTSUP", "EOPNOTSUPP", "EBADF"].includes(code)) throw error;
  }
}

/**
 * Creates a directory and durably publishes its name in the parent directory.
 * A release must not rely on a newly-created receipt/journal directory until
 * the parent entry has survived fsync: otherwise a power loss can retain a
 * live mutation while losing the only recovery metadata that describes it.
 */
export function createDirectoryDurably(
  path: string,
  options: {
    readonly mode?: number;
    readonly recursive?: boolean;
    readonly onPhase?: (phase: DurableDirectoryCreatePhase, directory: string) => void;
  } = {},
): void {
  const target = resolve(path);
  if (existsSync(target)) {
    // Preserve mkdir's non-recursive EEXIST contract for callers that require
    // exclusive creation. Recursive callers may durably adopt an existing
    // real directory, matching mkdir({ recursive: true }) semantics.
    if (!options.recursive) mkdirSync(target, { mode: options.mode ?? 0o700 });
    const metadata = lstatSync(target);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error(`Durable directory path is not a real directory: ${target}`);
    }
    syncDirectory(target);
    options.onPhase?.("directory_synced", target);
    syncDirectory(dirname(target));
    options.onPhase?.("parent_synced", target);
    return;
  }

  const missing: string[] = [];
  let cursor = target;
  while (!existsSync(cursor)) {
    missing.push(cursor);
    const parent = dirname(cursor);
    if (parent === cursor) throw new Error(`Cannot establish a durable parent for ${target}`);
    cursor = parent;
  }
  const existingParent = lstatSync(cursor);
  if (!existingParent.isDirectory() || existingParent.isSymbolicLink()) {
    throw new Error(`Durable directory ancestor is not a real directory: ${cursor}`);
  }

  // Publish from the first missing ancestor down. Every new name is fsynced in
  // its parent before a child can depend on it, so first-install recovery roots
  // cannot disappear while later live mutations survive a host power loss.
  for (const directory of missing.reverse()) {
    mkdirSync(directory, { mode: directory === target ? options.mode ?? 0o700 : 0o700 });
    options.onPhase?.("directory_created", directory);
    syncDirectory(directory);
    options.onPhase?.("directory_synced", directory);
    syncDirectory(dirname(directory));
    options.onPhase?.("parent_synced", directory);
  }
}

/**
 * Publishes a fully materialized directory under its final name. The source
 * and destination must be siblings so the rename is one filesystem operation.
 */
export function renameDirectoryDurably(
  sourcePath: string,
  destinationPath: string,
  options: {
    readonly onPhase?: (phase: DurableDirectoryRenamePhase) => void;
  } = {},
): void {
  const source = resolve(sourcePath);
  const destination = resolve(destinationPath);
  if (dirname(source) !== dirname(destination)) {
    throw new Error("Durable directory publication requires sibling paths");
  }
  if (existsSync(destination)) {
    throw new Error(`Durable directory destination already exists: ${destination}`);
  }
  const metadata = lstatSync(source);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Durable directory source is not a real directory: ${source}`);
  }
  syncDirectory(source);
  options.onPhase?.("source_synced");
  renameSync(source, destination);
  options.onPhase?.("renamed");
  syncDirectory(dirname(destination));
  options.onPhase?.("parent_synced");
}

/**
 * Durable atomic replacement: sync temporary bytes, rename, then sync the
 * containing directory so the new name survives a crash after success.
 */
export function writeDurableFileAtomically(
  path: string,
  contents: string | Uint8Array,
  options: DurableAtomicWriteOptions = {},
): void {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const mode = options.mode ?? 0o600;
  const noFollow =
    (constants as unknown as Readonly<Record<string, number>>).O_NOFOLLOW ?? 0;
  let descriptor: number | undefined;
  let renamed = false;
  try {
    descriptor = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
        CLOSE_ON_EXEC | noFollow,
      mode,
    );
    writeFileSync(descriptor, contents);
    // open(2) applies the process umask. Restore the reviewed exact mode on
    // the already-open inode so a restrictive installer umask cannot make a
    // service-readable journal silently root-only.
    fchmodSync(descriptor, mode);
    options.onPhase?.("temporary_written");
    fsyncSync(descriptor);
    options.onPhase?.("temporary_synced");
    const completedDescriptor = descriptor;
    descriptor = undefined;
    closeSync(completedDescriptor);
    renameSync(temporary, path);
    renamed = true;
    options.onPhase?.("renamed");
    syncDirectory(directory);
    options.onPhase?.("directory_synced");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (!renamed && existsSync(temporary)) rmSync(temporary, { force: true });
  }
}

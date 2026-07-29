import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { createReadStream } from "node:fs";
import { createDatabaseConnection } from "../../server/db/connection";
import { runBoundedReleaseCommand } from "./BoundedReleaseCommand";

const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_SWAP_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const CLOSE_ON_EXEC = (constants as unknown as Readonly<Record<string, number>>).O_CLOEXEC ?? 0;

export const VAULT_ARCHIVE_RESTORE_DISABLED_ERROR =
  "Vault archive restore is disabled by operator no-backup policy";

async function command(args: readonly string[]): Promise<string> {
  const result = await runBoundedReleaseCommand(args, {
    timeoutMs: 10 * 60_000,
    outputLimitBytes: 16 * 1024 * 1024,
    terminationGraceMs: 1_000,
  });
  return result.stdout;
}

async function stableRegularFileHash(path: string): Promise<string> {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink()) throw new Error(`Vault entry is not a regular file: ${path}`);
  const hash = createHash("sha256");
  await new Promise<void>((resolvePromise, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.once("error", reject);
    stream.once("end", resolvePromise);
  });
  const after = lstatSync(path);
  if (
    !after.isFile() || after.isSymbolicLink() || before.dev !== after.dev ||
    before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs
  ) throw new Error(`Vault entry changed while it was fingerprinted: ${path}`);
  return hash.digest("hex");
}

function safeRelativePath(value: string): string {
  const normalized = value.split("\\").join("/").replace(/^\.\//u, "").replace(/\/$/u, "");
  if (!normalized || isAbsolute(normalized) || normalized.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error(`Vault archive contains an unsafe path: ${value}`);
  }
  return normalized;
}

function containedBy(rootValue: string, pathValue: string): boolean {
  const root = resolve(rootValue);
  const path = resolve(pathValue);
  const child = relative(root, path);
  return child === "" || (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`));
}

/**
 * Stable release fingerprint for the managed Vault projection. It includes
 * every relative path, entry kind, POSIX owner/mode, size, and file bytes.
 * Symlinks and special files fail closed because managed Vaults must not use
 * them and because following either would cross the release boundary.
 */
async function vaultFingerprintOnce(vaultRootValue: string): Promise<string> {
  const vaultRoot = realpathSync(resolve(vaultRootValue));
  const rootMetadata = lstatSync(vaultRoot);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error("Managed Vault root must be a real directory");
  }
  const records: string[] = [];
  const visit = async (directory: string, relativeDirectory: string): Promise<void> => {
    const metadata = lstatSync(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error(`Vault directory is invalid: ${directory}`);
    records.push([
      "directory", relativeDirectory || ".", String(metadata.mode & 0o7777),
      String(metadata.uid), String(metadata.gid),
    ].join("\0"));
    const names = readdirSync(directory).sort((left, right) => left.localeCompare(right, "en"));
    for (const name of names) {
      const path = join(directory, name);
      const child = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      const childMetadata = lstatSync(path);
      if (childMetadata.isSymbolicLink()) throw new Error(`Managed Vault contains a forbidden symbolic link: ${child}`);
      if (childMetadata.isDirectory()) {
        await visit(path, child);
      } else if (childMetadata.isFile()) {
        records.push([
          "file", child, String(childMetadata.mode & 0o7777), String(childMetadata.uid),
          String(childMetadata.gid), String(childMetadata.size), await stableRegularFileHash(path),
        ].join("\0"));
      } else throw new Error(`Managed Vault contains a special filesystem entry: ${child}`);
    }
  };
  await visit(vaultRoot, "");
  return createHash("sha256").update(records.join("\n")).digest("hex");
}

export async function canonicalVaultFingerprint(vaultRootValue: string): Promise<string> {
  const first = await vaultFingerprintOnce(vaultRootValue);
  const second = await vaultFingerprintOnce(vaultRootValue);
  if (first !== second) throw new Error("Managed Vault changed while its tree fingerprint was captured");
  return first;
}

function syncVaultTree(root: string): void {
  const directories: string[] = [];
  const visit = (directory: string): void => {
    directories.push(directory);
    for (const name of readdirSync(directory).sort((left, right) => left.localeCompare(right, "en"))) {
      const path = join(directory, name);
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink()) throw new Error(`Managed Vault restore contains a forbidden symbolic link: ${path}`);
      if (metadata.isDirectory()) visit(path);
      else if (metadata.isFile()) {
        const descriptor = openSync(path, constants.O_RDONLY | CLOSE_ON_EXEC | NO_FOLLOW);
        try { fsyncSync(descriptor); }
        finally { closeSync(descriptor); }
      } else throw new Error(`Managed Vault restore contains a special filesystem entry: ${path}`);
    }
  };
  visit(root);
  for (const directory of directories.reverse()) {
    const descriptor = openSync(
      directory,
      constants.O_RDONLY | constants.O_DIRECTORY | CLOSE_ON_EXEC | NO_FOLLOW,
    );
    try { fsyncSync(descriptor); }
    finally { closeSync(descriptor); }
  }
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | CLOSE_ON_EXEC | NO_FOLLOW);
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

export type VaultRestorePhase =
  | "archive_validated"
  | "extracted"
  | "extracted_verified"
  | "extracted_synced"
  | "exchanged"
  | "parent_synced"
  | "displaced_removed";

export interface RestoreVaultArchiveOptions {
  readonly archivePath: string;
  readonly vaultRoot: string;
  readonly expectedFingerprint: string;
  readonly swapId: string;
  readonly onPhase?: (phase: VaultRestorePhase) => void;
}

/**
 * Extracts and verifies off to the side, syncs every restored byte, then uses
 * one same-filesystem exchange as the commit point. Any ordinary exception
 * after exchange triggers an exchange-back and exact original-fingerprint
 * proof before the primary error is rethrown.
 */
export async function restoreVaultArchiveAtomically(options: RestoreVaultArchiveOptions): Promise<void> {
  void options;
  throw new Error(VAULT_ARCHIVE_RESTORE_DISABLED_ERROR);
  /* c8 ignore start -- unreachable retired archive-restore implementation */
  if (!SHA256.test(options.expectedFingerprint)) throw new Error("Expected Vault fingerprint is invalid");
  if (!SAFE_SWAP_ID.test(options.swapId)) throw new Error("Vault restore swap ID is invalid");
  const archive = resolve(options.archivePath);
  const vaultRoot = realpathSync(resolve(options.vaultRoot));
  const parent = dirname(vaultRoot);
  const topLevel = basename(vaultRoot);
  const workspace = join(parent, `.${topLevel}.${options.swapId}.${process.pid}.${randomUUID()}.restore`);
  const extractedRoot = join(workspace, topLevel);
  const originalFingerprint = await canonicalVaultFingerprint(vaultRoot);
  let exchanged = false;
  try {
    const archiveEntries = (await command(["/usr/bin/tar", "-tzf", archive]))
      .split("\n").filter(Boolean).map(safeRelativePath);
    if (!archiveEntries.length || archiveEntries.some((entry) => entry !== topLevel && !entry.startsWith(`${topLevel}/`))) {
      throw new Error("Vault archive is empty or does not contain exactly the managed Vault root");
    }
    options.onPhase?.("archive_validated");
    mkdirSync(workspace, { mode: 0o700 });
    await command([
      "/usr/bin/tar", "--acls", "--xattrs", "--numeric-owner", "--same-owner",
      "--same-permissions", "-xzf", archive, "-C", workspace,
    ]);
    options.onPhase?.("extracted");
    if (!existsSync(extractedRoot) || !lstatSync(extractedRoot).isDirectory() || lstatSync(extractedRoot).isSymbolicLink()) {
      throw new Error("Vault archive did not restore a real managed root directory");
    }
    if (await canonicalVaultFingerprint(extractedRoot) !== options.expectedFingerprint) {
      throw new Error("Restored Vault tree does not match its checksum-bound fingerprint");
    }
    options.onPhase?.("extracted_verified");
    syncVaultTree(extractedRoot);
    options.onPhase?.("extracted_synced");
    await command(["/usr/bin/mv", "--exchange", "--no-copy", "--no-target-directory", "--", extractedRoot, vaultRoot]);
    exchanged = true;
    options.onPhase?.("exchanged");
    syncDirectory(parent);
    options.onPhase?.("parent_synced");
    if (await canonicalVaultFingerprint(vaultRoot) !== options.expectedFingerprint) {
      throw new Error("Atomic Vault exchange did not activate the expected tree");
    }
    // The expected live tree and its directory entry are now durable. Cleanup
    // of the displaced tree is deliberately best-effort and cannot turn that
    // committed restore into a false failure that attempts to exchange a
    // partially removed old tree back into service.
    exchanged = false;
    try {
      rmSync(extractedRoot, { recursive: true, force: true });
      options.onPhase?.("displaced_removed");
      rmSync(workspace, { recursive: true, force: true });
      syncDirectory(parent);
    } catch { /* committed Vault remains correct; stale cleanup is non-authoritative */ }
  } catch (error) {
    let recoveryError: unknown;
    if (exchanged) {
      try {
        await command(["/usr/bin/mv", "--exchange", "--no-copy", "--no-target-directory", "--", extractedRoot, vaultRoot]);
        syncDirectory(parent);
        if (await canonicalVaultFingerprint(vaultRoot) !== originalFingerprint) {
          throw new Error("Vault exchange-back did not restore the exact original tree");
        }
      } catch (caught) { recoveryError = caught; }
    }
    try { rmSync(workspace, { recursive: true, force: true }); } catch { /* retain primary/recovery truth */ }
    if (recoveryError !== undefined) {
      throw new AggregateError([error, recoveryError], "Vault restore failed and its exchange-back recovery also failed");
    }
    throw error;
  }
  /* c8 ignore stop */
}

export interface VaultDatabaseSyncVerification {
  readonly connections: number;
  readonly syncedFiles: number;
}

/** Verifies that every database row claiming `synced` matches exact Vault bytes. */
export async function assertVaultDatabaseSyncConsistency(
  databasePath: string,
  vaultRootValue: string,
): Promise<VaultDatabaseSyncVerification> {
  const vaultRoot = realpathSync(resolve(vaultRootValue));
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const requiredTables = database.prepare(`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name IN ('vault_connections', 'vault_sync_state')
      ORDER BY name
    `).all() as Array<{ name: string }>;
    if (requiredTables.length !== 2) throw new Error("Restored database lacks the Vault connection/sync schema");
    const connections = database.prepare(`
      SELECT id, vault_path AS vaultPath, status FROM vault_connections ORDER BY id
    `).all() as Array<{ id: string; vaultPath: string; status: string }>;
    for (const connection of connections) {
      const path = resolve(connection.vaultPath);
      if (!containedBy(vaultRoot, path)) throw new Error(`Vault connection escapes the managed root: ${connection.id}`);
      if (connection.status === "connected") {
        if (!existsSync(path) || !lstatSync(path).isDirectory() || lstatSync(path).isSymbolicLink()) {
          throw new Error(`Connected Vault directory is missing or invalid: ${connection.id}`);
        }
      }
    }
    const synced = database.prepare(`
      SELECT state.id, state.relative_path AS relativePath,
        state.vault_content_hash AS vaultHash,
        state.database_content_hash AS databaseHash,
        connection.vault_path AS vaultPath
      FROM vault_sync_state AS state
      JOIN vault_connections AS connection ON connection.id = state.connection_id
      WHERE state.status = 'synced'
      ORDER BY state.id
    `).all() as Array<{
      id: string;
      relativePath: string;
      vaultHash: string | null;
      databaseHash: string | null;
      vaultPath: string;
    }>;
    for (const state of synced) {
      const relativePath = safeRelativePath(state.relativePath);
      const path = resolve(state.vaultPath, ...relativePath.split("/"));
      if (!containedBy(state.vaultPath, path) || !containedBy(vaultRoot, path)) {
        throw new Error(`Vault sync path escapes its managed connection: ${state.id}`);
      }
      if (!existsSync(path) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) {
        throw new Error(`Synced Vault file is missing or invalid: ${state.id}`);
      }
      const actual = await stableRegularFileHash(path);
      if (!state.vaultHash || !state.databaseHash || actual !== state.vaultHash || actual !== state.databaseHash) {
        throw new Error(`Synced Vault bytes disagree with canonical database state: ${state.id}`);
      }
    }
    return Object.freeze({ connections: connections.length, syncedFiles: synced.length });
  } finally { database.close(); }
}

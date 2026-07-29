import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import type { BigIntStats } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import {
  checkDatabaseIntegrity,
  createDatabaseConnection,
} from "../db/connection";
import { canonicalJson, hashJson } from "../orchestration/serialization";

export const HISTORICAL_SQLITE_SOURCE_ATTESTATION_SCHEMA_VERSION =
  "ti_scale.historical_sqlite_source_attestation/v1" as const;
export const HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION =
  "ti_scale.historical_sqlite_snapshot_receipt/v1" as const;
export const HISTORICAL_SQLITE_SNAPSHOT_DISABLED_ERROR =
  "Historical SQLite snapshot creation is disabled by operator no-backup policy; use forward-only verified-reference migration" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const MAXIMUM_RECEIPT_BYTES = 64 * 1024;
const SOURCE_ROLES = ["database", "wal", "shm"] as const;
const ACCESS_MODE_MASK = 0o3;
// Linux O_NOATIME. Node's runtime supports it but @types/node does not expose
// the constant on every target. Failing to obtain permission is intentional:
// restoring atime after a read would itself mutate the historical source.
const O_NOATIME = process.platform === "linux" ? 0o1000000 : 0;

type SourceRole = (typeof SOURCE_ROLES)[number];

export interface HistoricalSqlitePresentFileIdentity {
  readonly role: SourceRole;
  readonly path: string;
  readonly present: true;
  readonly device: string;
  readonly inode: string;
  readonly sizeBytes: number;
  readonly modifiedAt: string;
  readonly accessTimeNanoseconds: string;
  readonly modifiedTimeNanoseconds: string;
  readonly changeTimeNanoseconds: string;
  readonly sha256: string;
}

export interface HistoricalSqliteAbsentFileIdentity {
  readonly role: Exclude<SourceRole, "database">;
  readonly path: string;
  readonly present: false;
}

export type HistoricalSqliteFileIdentity =
  | HistoricalSqlitePresentFileIdentity
  | HistoricalSqliteAbsentFileIdentity;

export interface HistoricalSqliteOpenHandleCheck {
  readonly checkedAt: string;
  readonly platform: "linux-procfs";
  readonly inspectedProcesses: number;
  readonly inspectedDescriptors: number;
  readonly matchingHandles: readonly never[];
}

export interface HistoricalSqliteSourceAttestation {
  readonly schemaVersion: typeof HISTORICAL_SQLITE_SOURCE_ATTESTATION_SCHEMA_VERSION;
  readonly checkedAt: string;
  readonly containmentRoot: string;
  readonly requestedDatabasePath: string;
  readonly canonicalDatabasePath: string;
  readonly files: Readonly<Record<SourceRole, HistoricalSqliteFileIdentity>>;
  readonly committedWalPresent: boolean;
  readonly sourceBundleSha256: string;
  readonly openHandleCheck: HistoricalSqliteOpenHandleCheck;
}

export interface HistoricalSqliteSnapshotReceipt {
  readonly schemaVersion: typeof HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION;
  readonly snapshotId: string;
  readonly createdAt: string;
  readonly method: "attested_byte_clone_then_readonly_sqlite_online_backup";
  readonly sourceBefore: HistoricalSqliteSourceAttestation;
  readonly sourceAfter: HistoricalSqliteSourceAttestation;
  readonly sourceUnchanged: true;
  readonly normalizedSnapshot: {
    readonly path: string;
    readonly sha256: string;
    readonly sizeBytes: number;
    readonly mode: "0600";
    readonly sqliteOnlineBackupPages: number;
    readonly quickCheck: readonly ["ok"];
    readonly integrityCheck: readonly ["ok"];
    readonly foreignKeyViolations: 0;
    readonly journalMode: "delete";
    readonly nonEmptySidecars: readonly never[];
  };
  readonly receiptPath: string;
  readonly receiptPayloadSha256: string;
}

export interface HistoricalSqliteSnapshotResult {
  readonly reused: boolean;
  readonly receipt: HistoricalSqliteSnapshotReceipt;
}

export interface HistoricalSqliteSnapshotOptions {
  readonly sourceDatabasePath: string;
  readonly sourceContainmentRoot: string;
  readonly destinationPath: string;
  readonly receiptPath?: string;
  /** Hash emitted by inspectHistoricalSqliteSource; required by the CLI. */
  readonly expectedSourceBundleSha256: string;
  readonly clock?: () => Date;
  readonly openHandleInspector?: HistoricalSqliteOpenHandleInspector;
  readonly testHooks?: {
    readonly afterInitialSourceCopy?: () => void;
    readonly beforePublication?: () => void;
    readonly afterPublication?: () => void;
  };
}

export type HistoricalSqliteOpenHandleInspector = (
  targets: readonly HistoricalSqlitePreliminaryIdentity[],
  clock: () => Date,
) => HistoricalSqliteOpenHandleCheck;

interface HistoricalSqlitePreliminaryIdentity {
  readonly role: SourceRole;
  readonly path: string;
  readonly accessPath: string;
  readonly present: boolean;
  readonly device?: string;
  readonly inode?: string;
  readonly sizeBytes?: number;
  readonly accessTimeNanoseconds?: string;
  readonly modifiedTimeNanoseconds?: string;
  readonly changeTimeNanoseconds?: string;
}

interface OpenedSourceFile {
  readonly preliminary: HistoricalSqlitePreliminaryIdentity & { readonly present: true };
  readonly descriptor: number;
  closed: boolean;
}

interface ResolvedSnapshotPaths {
  readonly sourceContainmentRoot: string;
  readonly sourceDatabasePath: string;
  readonly sourceDatabaseAccessPath: string;
  readonly destinationPath: string;
  readonly destinationAccessPath: string;
  readonly receiptPath: string;
  readonly receiptAccessPath: string;
  readonly sourceParent: AnchoredDirectory;
  readonly destinationParent: AnchoredDirectory;
  readonly receiptParent: AnchoredDirectory;
}

interface AnchoredDirectory {
  readonly configuredPath: string;
  readonly descriptor: number;
  readonly descriptorPath: string;
  readonly device: bigint;
  readonly inode: bigint;
}

interface NormalizedSnapshotValidation {
  readonly sha256: string;
  readonly sizeBytes: number;
  readonly quickCheck: readonly ["ok"];
  readonly integrityCheck: readonly ["ok"];
  readonly foreignKeyViolations: 0;
  readonly journalMode: "delete";
  readonly nonEmptySidecars: readonly never[];
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === "object" && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

function isMissing(error: unknown): boolean {
  return errorCode(error) === "ENOENT" || errorCode(error) === "ESRCH";
}

function pathObjectExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (isMissing(error)) return false;
    throw error;
  }
}

function closeQuietly(descriptor: number | undefined): void {
  if (descriptor === undefined) return;
  try { closeSync(descriptor); } catch { /* best-effort cleanup */ }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function directoryDescriptorPath(descriptor: number): string {
  for (const base of ["/proc/self/fd", "/dev/fd"] as const) {
    const candidate = `${base}/${descriptor}`;
    try {
      realpathSync(candidate);
      return candidate;
    } catch { /* try the next descriptor filesystem */ }
  }
  throw new Error("Descriptor-relative historical SQLite paths are unavailable");
}

function openAnchoredDirectory(path: string, label: string): AnchoredDirectory {
  const configuredPath = requireCanonicalDirectory(path, label);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      configuredPath,
      constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0),
    );
    const descriptorState = fstatSync(descriptor, { bigint: true });
    const pathState = lstatSync(configuredPath, { bigint: true });
    if (
      !descriptorState.isDirectory() || !pathState.isDirectory() || pathState.isSymbolicLink()
      || descriptorState.dev !== pathState.dev || descriptorState.ino !== pathState.ino
      || realpathSync(configuredPath) !== configuredPath
    ) throw new Error(`${label} changed while its directory descriptor was opened`);
    const result = {
      configuredPath,
      descriptor,
      descriptorPath: directoryDescriptorPath(descriptor),
      device: descriptorState.dev,
      inode: descriptorState.ino,
    };
    descriptor = undefined;
    return result;
  } finally { closeQuietly(descriptor); }
}

function anchoredLeaf(anchor: AnchoredDirectory, leaf: string): string {
  if (!leaf || basename(leaf) !== leaf || leaf === "." || leaf === "..") {
    throw new Error("Historical SQLite anchored leaf name is invalid");
  }
  return join(anchor.descriptorPath, leaf);
}

function assertAnchorStable(anchor: AnchoredDirectory, label: string): void {
  const descriptorState = fstatSync(anchor.descriptor, { bigint: true });
  let pathState: BigIntStats;
  try { pathState = lstatSync(anchor.configuredPath, { bigint: true }); }
  catch { throw new Error(`${label} pathname no longer resolves to its reviewed directory`); }
  if (
    !descriptorState.isDirectory() || !pathState.isDirectory() || pathState.isSymbolicLink()
    || descriptorState.dev !== anchor.device || descriptorState.ino !== anchor.inode
    || pathState.dev !== anchor.device || pathState.ino !== anchor.inode
    || realpathSync(anchor.configuredPath) !== anchor.configuredPath
  ) throw new Error(`${label} no longer matches its reviewed directory descriptor`);
}

function closeResolvedSnapshotPaths(paths: ResolvedSnapshotPaths): void {
  const descriptors = new Set([
    paths.sourceParent.descriptor,
    paths.destinationParent.descriptor,
    paths.receiptParent.descriptor,
  ]);
  let failure: unknown;
  for (const descriptor of descriptors) {
    try { closeSync(descriptor); } catch (error) { failure ??= error; }
  }
  if (failure) throw failure;
}

function sameFileObject(firstPath: string, secondPath: string): boolean {
  const first = bigintState(firstPath);
  const second = bigintState(secondPath);
  return first.dev === second.dev && first.ino === second.ino;
}

function assertResolvedPathAnchors(paths: ResolvedSnapshotPaths): void {
  assertAnchorStable(paths.sourceParent, "Historical SQLite source parent");
  assertAnchorStable(paths.destinationParent, "Historical SQLite destination parent");
  assertAnchorStable(paths.receiptParent, "Historical SQLite receipt parent");
  if (!sameFileObject(paths.sourceDatabasePath, paths.sourceDatabaseAccessPath)) {
    throw new Error("Historical SQLite source leaf no longer matches its reviewed parent descriptor");
  }
  for (const [visible, anchored, label] of [
    [paths.destinationPath, paths.destinationAccessPath, "destination"],
    [paths.receiptPath, paths.receiptAccessPath, "receipt"],
  ] as const) {
    const visibleExists = pathObjectExists(visible);
    const anchoredExists = pathObjectExists(anchored);
    if (visibleExists !== anchoredExists || (visibleExists && !sameFileObject(visible, anchored))) {
      throw new Error(`Historical SQLite ${label} leaf no longer matches its reviewed parent descriptor`);
    }
  }
}

function inside(root: string, candidate: string): boolean {
  const value = relative(root, candidate);
  return value === "" || (value !== ".." && !value.startsWith(`..${sep}`));
}

function requireCanonicalDirectory(path: string, label: string, create = false): string {
  const absolute = resolve(path);
  if (create) mkdirSync(absolute, { recursive: true, mode: 0o700 });
  const state = lstatSync(absolute);
  if (!state.isDirectory() || state.isSymbolicLink()) {
    throw new Error(`${label} must be a regular directory, not a symbolic link`);
  }
  const canonical = realpathSync(absolute);
  if (canonical !== absolute) {
    throw new Error(`${label} must use its exact canonical path without symbolic-link ancestors`);
  }
  return canonical;
}

function requireCanonicalFilePath(path: string, label: string): string {
  const absolute = resolve(path);
  const parent = requireCanonicalDirectory(dirname(absolute), `${label} parent`);
  const exact = join(parent, basename(absolute));
  if (exact !== absolute) throw new Error(`${label} must use its exact canonical path`);
  return exact;
}

function resolveSnapshotPaths(options: Pick<
  HistoricalSqliteSnapshotOptions,
  "sourceDatabasePath" | "sourceContainmentRoot" | "destinationPath" | "receiptPath"
>): ResolvedSnapshotPaths {
  const sourceContainmentRoot = requireCanonicalDirectory(
    options.sourceContainmentRoot,
    "Historical SQLite containment root",
  );
  const sourceDatabasePath = requireCanonicalFilePath(
    options.sourceDatabasePath,
    "Historical SQLite source",
  );
  if (!inside(sourceContainmentRoot, sourceDatabasePath)) {
    throw new Error("Historical SQLite source is outside its configured containment root");
  }
  const destinationPath = requireCanonicalFilePath(
    options.destinationPath,
    "Historical SQLite snapshot destination",
  );
  const receiptPath = requireCanonicalFilePath(
    options.receiptPath ?? `${destinationPath}.receipt.json`,
    "Historical SQLite snapshot receipt",
  );
  if (new Set([sourceDatabasePath, destinationPath, receiptPath]).size !== 3) {
    throw new Error("Historical SQLite source, destination, and receipt paths must be distinct");
  }
  const sourceFamily = new Set([
    sourceDatabasePath,
    `${sourceDatabasePath}-wal`,
    `${sourceDatabasePath}-shm`,
    `${sourceDatabasePath}-journal`,
  ]);
  const destinationFamily = new Set([
    destinationPath,
    `${destinationPath}-wal`,
    `${destinationPath}-shm`,
    `${destinationPath}-journal`,
  ]);
  for (const sourcePath of sourceFamily) {
    if (destinationFamily.has(sourcePath)) {
      throw new Error("Historical SQLite source and destination path families overlap");
    }
  }
  if (sourceFamily.has(receiptPath) || destinationFamily.has(receiptPath)) {
    throw new Error("Historical SQLite receipt must not overlap a database path family");
  }
  let sourceParent: AnchoredDirectory | undefined;
  let destinationParent: AnchoredDirectory | undefined;
  let receiptParent: AnchoredDirectory | undefined;
  try {
    sourceParent = openAnchoredDirectory(
      dirname(sourceDatabasePath),
      "Historical SQLite source parent",
    );
    destinationParent = openAnchoredDirectory(
      dirname(destinationPath),
      "Historical SQLite destination parent",
    );
    receiptParent = openAnchoredDirectory(
      dirname(receiptPath),
      "Historical SQLite receipt parent",
    );
    const paths: ResolvedSnapshotPaths = {
      sourceContainmentRoot,
      sourceDatabasePath,
      sourceDatabaseAccessPath: anchoredLeaf(sourceParent, basename(sourceDatabasePath)),
      destinationPath,
      destinationAccessPath: anchoredLeaf(destinationParent, basename(destinationPath)),
      receiptPath,
      receiptAccessPath: anchoredLeaf(receiptParent, basename(receiptPath)),
      sourceParent,
      destinationParent,
      receiptParent,
    };
    assertResolvedPathAnchors(paths);
    sourceParent = undefined;
    destinationParent = undefined;
    receiptParent = undefined;
    return paths;
  } finally {
    closeQuietly(sourceParent?.descriptor);
    closeQuietly(destinationParent?.descriptor);
    closeQuietly(receiptParent?.descriptor);
  }
}

function bigintState(path: string): BigIntStats {
  const state = lstatSync(path, { bigint: true });
  if (!state.isFile() || state.isSymbolicLink()) {
    throw new Error(`Historical SQLite source is not a regular non-symlink file: ${path}`);
  }
  return state;
}

function preliminaryIdentity(
  role: SourceRole,
  path: string,
  accessPath: string,
): HistoricalSqlitePreliminaryIdentity {
  try {
    const state = bigintState(accessPath);
    const sizeBytes = Number(state.size);
    if (!Number.isSafeInteger(sizeBytes)) {
      throw new Error(`Historical SQLite source is too large to attest safely: ${path}`);
    }
    return {
      role,
      path,
      accessPath,
      present: true,
      device: state.dev.toString(),
      inode: state.ino.toString(),
      sizeBytes,
      accessTimeNanoseconds: state.atimeNs.toString(),
      modifiedTimeNanoseconds: state.mtimeNs.toString(),
      changeTimeNanoseconds: state.ctimeNs.toString(),
    };
  } catch (error) {
    if (role !== "database" && isMissing(error)) {
      return { role, path, accessPath, present: false };
    }
    throw error;
  }
}

function preliminarySourceSet(paths: ResolvedSnapshotPaths): readonly HistoricalSqlitePreliminaryIdentity[] {
  const identities = [
    preliminaryIdentity("database", paths.sourceDatabasePath, paths.sourceDatabaseAccessPath),
    preliminaryIdentity(
      "wal",
      `${paths.sourceDatabasePath}-wal`,
      `${paths.sourceDatabaseAccessPath}-wal`,
    ),
    preliminaryIdentity(
      "shm",
      `${paths.sourceDatabasePath}-shm`,
      `${paths.sourceDatabaseAccessPath}-shm`,
    ),
  ] as const;
  const journalPath = `${paths.sourceDatabasePath}-journal`;
  const journalAccessPath = `${paths.sourceDatabaseAccessPath}-journal`;
  if (pathObjectExists(journalAccessPath)) {
    const journal = bigintState(journalAccessPath);
    if (journal.size > 0n) {
      throw new Error("Historical SQLite source has a non-empty rollback journal and is not snapshot-safe");
    }
    throw new Error("Historical SQLite source has a rollback journal; remove it only through its owning application");
  }
  const wal = identities[1];
  const shm = identities[2];
  if (wal.present && (wal.sizeBytes ?? 0) > 0 && !shm.present) {
    throw new Error("Historical SQLite source has a non-empty WAL without its SHM sidecar");
  }
  return identities;
}

function samePreliminaryIdentity(
  expected: HistoricalSqlitePreliminaryIdentity,
  state: BigIntStats,
): boolean {
  return expected.present
    && expected.device === state.dev.toString()
    && expected.inode === state.ino.toString()
    && expected.sizeBytes === Number(state.size)
    && expected.accessTimeNanoseconds === state.atimeNs.toString()
    && expected.modifiedTimeNanoseconds === state.mtimeNs.toString()
    && expected.changeTimeNanoseconds === state.ctimeNs.toString();
}

function inspectLinuxOpenHandles(
  targets: readonly HistoricalSqlitePreliminaryIdentity[],
  clock: () => Date,
): HistoricalSqliteOpenHandleCheck {
  if (process.platform !== "linux" || !existsSync("/proc/self/fd")) {
    throw new Error("Historical SQLite open-handle attestation requires Linux procfs");
  }
  const targetKeys = new Set(
    targets
      .filter((target) => target.present)
      .map((target) => `${target.device}:${target.inode}`),
  );
  const matches: Array<{ pid: number; descriptor: number; access: string }> = [];
  let inspectedProcesses = 0;
  let inspectedDescriptors = 0;
  for (const processEntry of readdirSync("/proc", { withFileTypes: true })) {
    if (!processEntry.isDirectory() || !/^\d+$/u.test(processEntry.name)) continue;
    const pid = Number(processEntry.name);
    const descriptorDirectory = `/proc/${processEntry.name}/fd`;
    let descriptorEntries;
    try {
      descriptorEntries = readdirSync(descriptorDirectory, { withFileTypes: true });
      inspectedProcesses += 1;
    } catch (error) {
      if (isMissing(error)) continue;
      throw new Error(`Cannot prove historical SQLite handle isolation for process ${pid}: ${errorCode(error) ?? "unreadable procfs"}`);
    }
    for (const descriptorEntry of descriptorEntries) {
      if (!/^\d+$/u.test(descriptorEntry.name)) continue;
      const descriptor = Number(descriptorEntry.name);
      const descriptorPath = `${descriptorDirectory}/${descriptorEntry.name}`;
      let state: BigIntStats;
      try {
        state = statSync(descriptorPath, { bigint: true });
        inspectedDescriptors += 1;
      } catch (error) {
        if (isMissing(error)) continue;
        throw new Error(`Cannot inspect historical SQLite descriptor ${pid}/${descriptor}: ${errorCode(error) ?? "unreadable procfs"}`);
      }
      if (!targetKeys.has(`${state.dev.toString()}:${state.ino.toString()}`)) continue;
      let fdInfo: string;
      try {
        fdInfo = readFileSync(`/proc/${processEntry.name}/fdinfo/${descriptorEntry.name}`, "utf8");
      } catch (error) {
        if (isMissing(error)) continue;
        throw new Error(`Cannot inspect historical SQLite descriptor flags ${pid}/${descriptor}: ${errorCode(error) ?? "unreadable procfs"}`);
      }
      const flagsText = /^flags:\s*([0-7]+)/mu.exec(fdInfo)?.[1];
      if (!flagsText) throw new Error(`Historical SQLite descriptor flags are unavailable for ${pid}/${descriptor}`);
      const accessMode = Number.parseInt(flagsText, 8) & ACCESS_MODE_MASK;
      matches.push({
        pid,
        descriptor,
        access: accessMode === constants.O_WRONLY ? "write-only" : accessMode === constants.O_RDWR ? "read-write" : "read-only",
      });
    }
  }
  if (matches.length > 0) {
    const summary = matches.map((match) => `${match.pid}/${match.descriptor}:${match.access}`).join(", ");
    throw new Error(`Historical SQLite source still has open handles: ${summary}`);
  }
  return {
    checkedAt: clock().toISOString(),
    platform: "linux-procfs",
    inspectedProcesses,
    inspectedDescriptors,
    matchingHandles: [],
  };
}

function openSourceFiles(
  preliminary: readonly HistoricalSqlitePreliminaryIdentity[],
): ReadonlyMap<SourceRole, OpenedSourceFile> {
  const opened = new Map<SourceRole, OpenedSourceFile>();
  try {
    for (const identity of preliminary) {
      if (!identity.present) continue;
      let descriptor: number | undefined;
      try {
        descriptor = openSync(
          identity.accessPath,
          constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | O_NOATIME,
        );
        const state = fstatSync(descriptor, { bigint: true });
        const pathState = bigintState(identity.accessPath);
        if (!samePreliminaryIdentity(identity, state) || !samePreliminaryIdentity(identity, pathState)) {
          throw new Error(`Historical SQLite ${identity.role} identity changed before it could be opened`);
        }
        opened.set(identity.role, {
          preliminary: identity as HistoricalSqlitePreliminaryIdentity & { readonly present: true },
          descriptor,
          closed: false,
        });
        descriptor = undefined;
      } finally {
        closeQuietly(descriptor);
      }
    }
    return opened;
  } catch (error) {
    for (const file of opened.values()) closeQuietly(file.descriptor);
    throw error;
  }
}

function closeOpenedFiles(opened: ReadonlyMap<SourceRole, OpenedSourceFile>): void {
  let failure: unknown;
  for (const file of opened.values()) {
    if (file.closed) continue;
    try {
      closeSync(file.descriptor);
      file.closed = true;
    } catch (error) { failure ??= error; }
  }
  if (failure) throw failure;
}

function readAndHashDescriptor(
  descriptor: number,
  copyDescriptor?: number,
): { readonly sha256: string; readonly sizeBytes: number } {
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(256 * 1024);
  let position = 0;
  while (true) {
    const length = readSync(descriptor, buffer, 0, buffer.length, position);
    if (length === 0) break;
    const chunk = buffer.subarray(0, length);
    hash.update(chunk);
    if (copyDescriptor !== undefined) {
      let written = 0;
      while (written < length) {
        const count = writeSync(copyDescriptor, chunk, written, length - written);
        if (count <= 0) throw new Error("Historical SQLite staging copy stopped before all bytes were written");
        written += count;
      }
    }
    position += length;
  }
  return { sha256: hash.digest("hex"), sizeBytes: position };
}

function secureCreate(path: string): number {
  return openSync(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY
      | (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
}

function copyAndAttestSource(
  opened: ReadonlyMap<SourceRole, OpenedSourceFile>,
  preliminary: readonly HistoricalSqlitePreliminaryIdentity[],
  stagingDatabasePath: string,
): Readonly<Record<SourceRole, HistoricalSqliteFileIdentity>> {
  const output = {} as Record<SourceRole, HistoricalSqliteFileIdentity>;
  for (const identity of preliminary) {
    if (!identity.present) {
      output[identity.role] = {
        role: identity.role as Exclude<SourceRole, "database">,
        path: identity.path,
        present: false,
      };
      continue;
    }
    const openedFile = opened.get(identity.role);
    if (!openedFile) throw new Error(`Historical SQLite ${identity.role} descriptor is unavailable`);
    const stagedPath = identity.role === "database"
      ? stagingDatabasePath
      : `${stagingDatabasePath}-${identity.role}`;
    const stagedDescriptor = secureCreate(stagedPath);
    let inspected;
    try {
      inspected = readAndHashDescriptor(openedFile.descriptor, stagedDescriptor);
      fchmodSync(stagedDescriptor, 0o600);
      fsyncSync(stagedDescriptor);
    } finally {
      closeSync(stagedDescriptor);
    }
    const before = fstatSync(openedFile.descriptor, { bigint: true });
    const pathState = bigintState(identity.accessPath);
    if (
      !samePreliminaryIdentity(identity, before)
      || !samePreliminaryIdentity(identity, pathState)
      || inspected.sizeBytes !== identity.sizeBytes
    ) throw new Error(`Historical SQLite ${identity.role} changed during its initial attestation`);
    output[identity.role] = identityFromState(
      identity as HistoricalSqlitePreliminaryIdentity & { readonly present: true },
      before,
      inspected.sha256,
    );
  }
  fsyncDirectory(dirname(stagingDatabasePath));
  return output;
}

function identityFromState(
  preliminary: HistoricalSqlitePreliminaryIdentity & { readonly present: true },
  state: BigIntStats,
  sha256: string,
): HistoricalSqlitePresentFileIdentity {
  if (!SHA256.test(sha256)) throw new Error("Historical SQLite source hash is malformed");
  return {
    role: preliminary.role,
    path: preliminary.path,
    present: true,
    device: state.dev.toString(),
    inode: state.ino.toString(),
    sizeBytes: Number(state.size),
    modifiedAt: new Date(Number(state.mtimeMs)).toISOString(),
    accessTimeNanoseconds: state.atimeNs.toString(),
    modifiedTimeNanoseconds: state.mtimeNs.toString(),
    changeTimeNanoseconds: state.ctimeNs.toString(),
    sha256,
  };
}

function sourceBundleSha256(
  containmentRoot: string,
  canonicalDatabasePath: string,
  files: Readonly<Record<SourceRole, HistoricalSqliteFileIdentity>>,
): string {
  return hashJson({
    containmentRoot,
    canonicalDatabasePath,
    files,
  });
}

function buildSourceAttestation(input: {
  readonly clock: () => Date;
  readonly paths: ResolvedSnapshotPaths;
  readonly files: Readonly<Record<SourceRole, HistoricalSqliteFileIdentity>>;
  readonly openHandleCheck: HistoricalSqliteOpenHandleCheck;
}): HistoricalSqliteSourceAttestation {
  const wal = input.files.wal;
  return {
    schemaVersion: HISTORICAL_SQLITE_SOURCE_ATTESTATION_SCHEMA_VERSION,
    checkedAt: input.clock().toISOString(),
    containmentRoot: input.paths.sourceContainmentRoot,
    requestedDatabasePath: input.paths.sourceDatabasePath,
    canonicalDatabasePath: input.paths.sourceDatabasePath,
    files: input.files,
    committedWalPresent: wal.present && wal.sizeBytes > 0,
    sourceBundleSha256: sourceBundleSha256(
      input.paths.sourceContainmentRoot,
      input.paths.sourceDatabasePath,
      input.files,
    ),
    openHandleCheck: input.openHandleCheck,
  };
}

function reattestOpenedSource(
  opened: ReadonlyMap<SourceRole, OpenedSourceFile>,
  preliminary: readonly HistoricalSqlitePreliminaryIdentity[],
): Readonly<Record<SourceRole, HistoricalSqliteFileIdentity>> {
  const output = {} as Record<SourceRole, HistoricalSqliteFileIdentity>;
  for (const identity of preliminary) {
    if (!identity.present) {
      if (pathObjectExists(identity.accessPath)) {
        throw new Error(`Historical SQLite ${identity.role} appeared during snapshot creation`);
      }
      output[identity.role] = {
        role: identity.role as Exclude<SourceRole, "database">,
        path: identity.path,
        present: false,
      };
      continue;
    }
    const openedFile = opened.get(identity.role);
    if (!openedFile) throw new Error(`Historical SQLite ${identity.role} descriptor is unavailable`);
    const inspected = readAndHashDescriptor(openedFile.descriptor);
    const after = fstatSync(openedFile.descriptor, { bigint: true });
    const pathState = bigintState(identity.accessPath);
    if (
      !samePreliminaryIdentity(identity, after)
      || !samePreliminaryIdentity(identity, pathState)
      || inspected.sizeBytes !== identity.sizeBytes
    ) throw new Error(`Historical SQLite ${identity.role} changed during snapshot creation`);
    output[identity.role] = identityFromState(
      identity as HistoricalSqlitePreliminaryIdentity & { readonly present: true },
      after,
      inspected.sha256,
    );
  }
  return output;
}

function equalSourceFiles(
  before: Readonly<Record<SourceRole, HistoricalSqliteFileIdentity>>,
  after: Readonly<Record<SourceRole, HistoricalSqliteFileIdentity>>,
): boolean {
  return canonicalJson(before) === canonicalJson(after);
}

function requireExpectedBundle(actual: string, expected: string | undefined): void {
  if (expected === undefined) {
    throw new Error("A reviewed historical SQLite source bundle SHA-256 is required");
  }
  if (!SHA256.test(expected)) throw new Error("Expected historical SQLite source bundle must be a lowercase SHA-256");
  if (actual !== expected) throw new Error("Historical SQLite source bundle does not match the reviewed attestation");
}

function removeZeroLengthSidecars(databasePath: string): readonly never[] {
  for (const suffix of ["-wal", "-journal", "-shm"] as const) {
    const path = `${databasePath}${suffix}`;
    if (!pathObjectExists(path)) continue;
    const state = bigintState(path);
    if (state.size > 0n) {
      throw new Error(`Normalized SQLite snapshot retained a non-empty ${suffix.slice(1)} sidecar`);
    }
    unlinkSync(path);
  }
  return [];
}

function assertFullDatabaseIntegrity(database: ReturnType<typeof createDatabaseConnection>): readonly ["ok"] {
  const rows = database.pragma("integrity_check") as Array<Record<string, unknown>>;
  const messages = rows.map((row) => String(Object.values(row)[0] ?? ""));
  if (messages.length !== 1 || messages[0]?.toLowerCase() !== "ok") {
    throw new Error(`Normalized SQLite snapshot failed integrity_check: ${messages.join("; ")}`);
  }
  return ["ok"];
}

function hashRegularFileNoFollow(path: string): { readonly sha256: string; readonly sizeBytes: number } {
  const descriptor = openSync(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const pathState = bigintState(path);
    if (!before.isFile() || before.dev !== pathState.dev || before.ino !== pathState.ino) {
      throw new Error(`File identity changed while hashing: ${path}`);
    }
    const inspected = readAndHashDescriptor(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (
      before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeNs !== after.mtimeNs
      || inspected.sizeBytes !== Number(after.size)
    ) throw new Error(`File changed while hashing: ${path}`);
    return inspected;
  } finally { closeSync(descriptor); }
}

function readBoundedRegularFileNoFollow(
  path: string,
  maximumBytes: number,
): { readonly content: Buffer; readonly sha256: string; readonly sizeBytes: number } {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor, { bigint: true });
    const pathState = bigintState(path);
    if (
      !before.isFile() || before.dev !== pathState.dev || before.ino !== pathState.ino
      || before.size > BigInt(maximumBytes)
    ) throw new Error(`Bounded regular-file read rejected: ${path}`);
    const content = Buffer.alloc(Number(before.size));
    let position = 0;
    while (position < content.length) {
      const count = readSync(descriptor, content, position, content.length - position, position);
      if (count <= 0) throw new Error(`Bounded regular-file read ended early: ${path}`);
      position += count;
    }
    const after = fstatSync(descriptor, { bigint: true });
    const afterPath = bigintState(path);
    if (
      before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeNs !== after.mtimeNs
      || after.dev !== afterPath.dev || after.ino !== afterPath.ino
    ) throw new Error(`File changed during bounded read: ${path}`);
    return {
      content,
      sha256: createHash("sha256").update(content).digest("hex"),
      sizeBytes: content.length,
    };
  } finally { closeSync(descriptor); }
}

async function normalizeAndValidateStagedDatabase(
  stagedDatabasePath: string,
  normalizedPath: string,
): Promise<NormalizedSnapshotValidation & { readonly sqliteOnlineBackupPages: number }> {
  void stagedDatabasePath;
  void normalizedPath;
  throw new Error(HISTORICAL_SQLITE_SNAPSHOT_DISABLED_ERROR);
}

function writeAll(descriptor: number, content: Buffer): void {
  let position = 0;
  while (position < content.length) {
    const count = writeSync(descriptor, content, position, content.length - position);
    if (count <= 0) throw new Error("Historical SQLite receipt write stopped before completion");
    position += count;
  }
}

type ExistingOutputState = "none" | "destination_only" | "receipt_only" | "complete";

interface PublishedOutputLink {
  readonly path: string;
  readonly device: bigint;
  readonly inode: bigint;
}

interface SnapshotPublication {
  readonly newlyPublished: readonly PublishedOutputLink[];
}

function publishedLink(path: string): PublishedOutputLink {
  const state = bigintState(path);
  return { path, device: state.dev, inode: state.ino };
}

function rollbackPublication(publication: SnapshotPublication): void {
  const directories = new Set<string>();
  for (const link of [...publication.newlyPublished].reverse()) {
    try {
      const state = lstatSync(link.path, { bigint: true });
      if (state.dev !== link.device || state.ino !== link.inode) continue;
      unlinkSync(link.path);
      directories.add(dirname(link.path));
    } catch (error) {
      if (!isMissing(error)) throw error;
    }
  }
  for (const directory of directories) fsyncDirectory(directory);
}

function publishSnapshotAndReceipt(
  normalizedPath: string,
  destinationPath: string,
  receiptPath: string,
  receipt: HistoricalSqliteSnapshotReceipt,
  existingState: ExistingOutputState,
): SnapshotPublication {
  const normalizedDescriptor = openSync(normalizedPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    fchmodSync(normalizedDescriptor, 0o600);
    fsyncSync(normalizedDescriptor);
  } finally { closeSync(normalizedDescriptor); }

  const publishReceipt = existingState !== "receipt_only";
  const publishDestination = existingState !== "destination_only";
  const receiptTemporary = publishReceipt
    ? join(
      dirname(receiptPath),
      `.${basename(receiptPath)}.${process.pid}.${randomUUID()}.tmp`,
    )
    : undefined;
  const newlyPublished: PublishedOutputLink[] = [];
  try {
    if (receiptTemporary) {
      const receiptDescriptor = secureCreate(receiptTemporary);
      try {
        writeAll(receiptDescriptor, Buffer.from(`${canonicalJson(receipt)}\n`, "utf8"));
        fchmodSync(receiptDescriptor, 0o600);
        fsyncSync(receiptDescriptor);
      } finally { closeSync(receiptDescriptor); }
    }
    try {
      if (publishDestination) {
        linkSync(normalizedPath, destinationPath);
        newlyPublished.push(publishedLink(destinationPath));
        fsyncDirectory(dirname(destinationPath));
      }
      if (publishReceipt && receiptTemporary) {
        linkSync(receiptTemporary, receiptPath);
        newlyPublished.push(publishedLink(receiptPath));
        fsyncDirectory(dirname(receiptPath));
      }
      removeZeroLengthSidecars(destinationPath);
      return { newlyPublished };
    } catch (error) {
      try { rollbackPublication({ newlyPublished }); } catch { /* preserve primary failure */ }
      throw error;
    }
  } finally {
    if (receiptTemporary) {
      try {
        unlinkSync(receiptTemporary);
        fsyncDirectory(dirname(receiptTemporary));
      } catch { /* linked receipt is already durable */ }
    }
  }
}

function receiptWithoutSeal(
  receipt: HistoricalSqliteSnapshotReceipt,
): Omit<HistoricalSqliteSnapshotReceipt, "receiptPayloadSha256"> {
  const { receiptPayloadSha256: _seal, ...payload } = receipt;
  return payload;
}

function parseReceipt(content: string): HistoricalSqliteSnapshotReceipt {
  const candidate = JSON.parse(content) as Partial<HistoricalSqliteSnapshotReceipt>;
  if (candidate.schemaVersion !== HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION) {
    throw new Error("Historical SQLite snapshot receipt schema is unsupported");
  }
  if (!candidate.receiptPayloadSha256 || !SHA256.test(candidate.receiptPayloadSha256)) {
    throw new Error("Historical SQLite snapshot receipt seal is malformed");
  }
  const expectedSeal = hashJson(receiptWithoutSeal(candidate as HistoricalSqliteSnapshotReceipt));
  if (candidate.receiptPayloadSha256 !== expectedSeal) {
    throw new Error("Historical SQLite snapshot receipt seal does not verify");
  }
  return candidate as HistoricalSqliteSnapshotReceipt;
}

async function validateExistingSnapshot(
  paths: ResolvedSnapshotPaths,
  current: HistoricalSqliteSourceAttestation,
): Promise<HistoricalSqliteSnapshotReceipt> {
  const receipt = readExistingReceipt(paths, current);
  const destinationState = bigintState(paths.destinationAccessPath);
  if ((Number(destinationState.mode) & 0o7777) !== 0o600) {
    throw new Error("Historical SQLite normalized snapshot mode is not 0600");
  }
  const validation = await validatePublishedSnapshot(paths.destinationAccessPath);
  if (
    validation.sha256 !== receipt.normalizedSnapshot.sha256
    || validation.sizeBytes !== receipt.normalizedSnapshot.sizeBytes
  ) throw new Error("Historical SQLite normalized snapshot no longer matches its receipt");
  return receipt;
}

function readExistingReceipt(
  paths: ResolvedSnapshotPaths,
  current: HistoricalSqliteSourceAttestation,
): HistoricalSqliteSnapshotReceipt {
  const receiptState = bigintState(paths.receiptAccessPath);
  if ((Number(receiptState.mode) & 0o7777) !== 0o600) {
    throw new Error("Historical SQLite snapshot receipt mode is not 0600");
  }
  if (receiptState.size > BigInt(MAXIMUM_RECEIPT_BYTES)) {
    throw new Error("Historical SQLite snapshot receipt exceeds its size bound");
  }
  const receiptFile = readBoundedRegularFileNoFollow(
    paths.receiptAccessPath,
    MAXIMUM_RECEIPT_BYTES,
  );
  const receipt = parseReceipt(receiptFile.content.toString("utf8"));
  if (
    receipt.receiptPath !== paths.receiptPath
    || receipt.normalizedSnapshot.path !== paths.destinationPath
  ) throw new Error("Historical SQLite snapshot receipt is bound to different output paths");
  if (
    receipt.sourceBefore.sourceBundleSha256 !== current.sourceBundleSha256
    || receipt.sourceAfter.sourceBundleSha256 !== current.sourceBundleSha256
  ) throw new Error("Historical SQLite source changed after the existing snapshot was created");
  return receipt;
}

async function validatePublishedSnapshot(path: string): Promise<NormalizedSnapshotValidation> {
  const nonEmptySidecars = removeZeroLengthSidecars(path);
  const database = createDatabaseConnection({
    filename: path,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const integrity = checkDatabaseIntegrity(database);
    if (!integrity.ok || integrity.messages.length !== 1 || integrity.messages[0]?.toLowerCase() !== "ok") {
      throw new Error("Historical SQLite normalized snapshot no longer passes quick_check");
    }
    assertFullDatabaseIntegrity(database);
    const violations = database.pragma("foreign_key_check") as unknown[];
    if (violations.length > 0) throw new Error("Historical SQLite normalized snapshot has foreign-key violations");
    const journalMode = String(database.pragma("journal_mode", { simple: true })).toLowerCase();
    if (journalMode !== "delete") throw new Error("Historical SQLite normalized snapshot is no longer normalized");
  } finally { database.close(); }
  removeZeroLengthSidecars(path);
  return {
    ...hashRegularFileNoFollow(path),
    quickCheck: ["ok"],
    integrityCheck: ["ok"],
    foreignKeyViolations: 0,
    journalMode: "delete",
    nonEmptySidecars,
  };
}

function existingOutputState(paths: ResolvedSnapshotPaths): ExistingOutputState {
  const destinationExists = pathObjectExists(paths.destinationAccessPath);
  const receiptExists = pathObjectExists(paths.receiptAccessPath);
  if (destinationExists && receiptExists) return "complete";
  if (destinationExists) return "destination_only";
  if (receiptExists) return "receipt_only";
  return "none";
}

function inspectSourceWithPreliminary(
  paths: ResolvedSnapshotPaths,
  clock: () => Date,
  inspector: HistoricalSqliteOpenHandleInspector,
): HistoricalSqliteSourceAttestation {
  const preliminary = preliminarySourceSet(paths);
  const openHandleCheck = inspector(preliminary, clock);
  const opened = openSourceFiles(preliminary);
  try {
    const files = reattestOpenedSource(opened, preliminary);
    return buildSourceAttestation({ clock, paths, files, openHandleCheck });
  } finally { closeOpenedFiles(opened); }
}

/**
 * Inspect a historical SQLite DB/WAL/SHM bundle without opening SQLite itself.
 * Every byte is read through O_NOFOLLOW read-only descriptors and no checkpoint
 * or source-side SQLite mutation is possible.
 */
export function inspectHistoricalSqliteSource(options: Pick<
  HistoricalSqliteSnapshotOptions,
  "sourceDatabasePath" | "sourceContainmentRoot" | "destinationPath" | "receiptPath" | "clock" | "openHandleInspector"
>): HistoricalSqliteSourceAttestation {
  const clock = options.clock ?? (() => new Date());
  const inspector = options.openHandleInspector ?? inspectLinuxOpenHandles;
  const paths = resolveSnapshotPaths(options);
  try {
    const attestation = inspectSourceWithPreliminary(paths, clock, inspector);
    assertResolvedPathAnchors(paths);
    return attestation;
  } finally { closeResolvedSnapshotPaths(paths); }
}

/** Retired mutation boundary retained only to fail closed for exact imports. */
export async function createHistoricalSqliteSnapshot(
  options: HistoricalSqliteSnapshotOptions,
): Promise<HistoricalSqliteSnapshotResult> {
  if (HISTORICAL_SQLITE_SNAPSHOT_DISABLED_ERROR.length > 0) {
    throw new Error(HISTORICAL_SQLITE_SNAPSHOT_DISABLED_ERROR);
  }

  /* c8 ignore start -- unreachable retired implementation pending source removal */
  if (options.expectedSourceBundleSha256 === undefined) {
    throw new Error("A reviewed historical SQLite source bundle SHA-256 is required");
  }
  if (!SHA256.test(options.expectedSourceBundleSha256)) {
    throw new Error("Expected historical SQLite source bundle must be a lowercase SHA-256");
  }
  const clock = options.clock ?? (() => new Date());
  const inspector = options.openHandleInspector ?? inspectLinuxOpenHandles;
  const paths = resolveSnapshotPaths(options);
  try {
  const existing = existingOutputState(paths);
  if (existing === "complete") {
    const current = inspectSourceWithPreliminary(paths, clock, inspector);
    requireExpectedBundle(current.sourceBundleSha256, options.expectedSourceBundleSha256);
    const receipt = await validateExistingSnapshot(paths, current);
    assertResolvedPathAnchors(paths);
    return { reused: true, receipt };
  }

  const preliminary = preliminarySourceSet(paths);
  const initialHandleCheck = inspector(preliminary, clock);
  const opened = openSourceFiles(preliminary);
  let stagingDirectory: string | undefined;
  try {
    stagingDirectory = mkdtempSync(
      join(paths.destinationParent.descriptorPath, ".ti-scale-historical-sqlite-snapshot-"),
    );
    const stagingDatabasePath = join(stagingDirectory, "source.sqlite");
    const normalizedPath = join(stagingDirectory, "normalized.sqlite");
    const beforeFiles = copyAndAttestSource(opened, preliminary, stagingDatabasePath);
    const sourceBefore = buildSourceAttestation({
      clock,
      paths,
      files: beforeFiles,
      openHandleCheck: initialHandleCheck,
    });
    requireExpectedBundle(sourceBefore.sourceBundleSha256, options.expectedSourceBundleSha256);
    options.testHooks?.afterInitialSourceCopy?.();

    const normalized = await normalizeAndValidateStagedDatabase(stagingDatabasePath, normalizedPath);
    options.testHooks?.beforePublication?.();
    const afterFiles = reattestOpenedSource(opened, preliminary);
    if (!equalSourceFiles(beforeFiles, afterFiles)) {
      throw new Error("Historical SQLite source DB/WAL/SHM changed while its snapshot was created");
    }
    closeOpenedFiles(opened);
    const finalHandleCheck = inspector(preliminary, clock);
    const sourceAfter = buildSourceAttestation({
      clock,
      paths,
      files: afterFiles,
      openHandleCheck: finalHandleCheck,
    });
    if (sourceBefore.sourceBundleSha256 !== sourceAfter.sourceBundleSha256) {
      throw new Error("Historical SQLite source bundle identity changed before publication");
    }
    assertResolvedPathAnchors(paths);

    if (existingOutputState(paths) !== existing) {
      throw new Error("Historical SQLite snapshot output state changed during preparation");
    }
    if (existing === "destination_only") {
      const recovered = await validatePublishedSnapshot(paths.destinationAccessPath);
      if (recovered.sha256 !== normalized.sha256 || recovered.sizeBytes !== normalized.sizeBytes) {
        throw new Error("Partial historical SQLite destination does not match the reviewed source snapshot");
      }
    }

    let receipt: HistoricalSqliteSnapshotReceipt;
    if (existing === "receipt_only") {
      receipt = readExistingReceipt(paths, sourceAfter);
      if (
        receipt.normalizedSnapshot.sha256 !== normalized.sha256
        || receipt.normalizedSnapshot.sizeBytes !== normalized.sizeBytes
      ) throw new Error("Partial historical SQLite receipt does not match the reviewed source snapshot");
    } else {
      const createdAt = clock().toISOString();
      const receiptPayload = {
        schemaVersion: HISTORICAL_SQLITE_SNAPSHOT_RECEIPT_SCHEMA_VERSION,
        snapshotId: `historical_sqlite_snapshot_${hashJson({
          sourceBundleSha256: sourceBefore.sourceBundleSha256,
          normalizedSha256: normalized.sha256,
        }).slice(0, 32)}`,
        createdAt,
        method: "attested_byte_clone_then_readonly_sqlite_online_backup" as const,
        sourceBefore,
        sourceAfter,
        sourceUnchanged: true as const,
        normalizedSnapshot: {
          path: paths.destinationPath,
          sha256: normalized.sha256,
          sizeBytes: normalized.sizeBytes,
          mode: "0600" as const,
          sqliteOnlineBackupPages: normalized.sqliteOnlineBackupPages,
          quickCheck: normalized.quickCheck,
          integrityCheck: normalized.integrityCheck,
          foreignKeyViolations: normalized.foreignKeyViolations,
          journalMode: normalized.journalMode,
          nonEmptySidecars: normalized.nonEmptySidecars,
        },
        receiptPath: paths.receiptPath,
      };
      receipt = {
        ...receiptPayload,
        receiptPayloadSha256: hashJson(receiptPayload),
      };
    }

    const publication = publishSnapshotAndReceipt(
      normalizedPath,
      paths.destinationAccessPath,
      paths.receiptAccessPath,
      receipt,
      existing,
    );
    try {
      assertResolvedPathAnchors(paths);
      options.testHooks?.afterPublication?.();
      const postPublication = inspectSourceWithPreliminary(paths, clock, inspector);
      if (postPublication.sourceBundleSha256 !== sourceBefore.sourceBundleSha256) {
        throw new Error("Historical SQLite source changed during snapshot publication");
      }
      const verifiedReceipt = await validateExistingSnapshot(paths, postPublication);
      if (verifiedReceipt.receiptPayloadSha256 !== receipt.receiptPayloadSha256) {
        throw new Error("Historical SQLite receipt changed during publication verification");
      }
      assertResolvedPathAnchors(paths);
      return { reused: false, receipt: verifiedReceipt };
    } catch (error) {
      rollbackPublication(publication);
      throw error;
    }
  } finally {
    for (const file of opened.values()) {
      if (file.closed) continue;
      try {
        closeSync(file.descriptor);
        file.closed = true;
      } catch { /* best-effort cleanup */ }
    }
    if (stagingDirectory) rmSync(stagingDirectory, { recursive: true, force: true });
  }
  } finally { closeResolvedSnapshotPaths(paths); }
  /* c8 ignore stop */
}

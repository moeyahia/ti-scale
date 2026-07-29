#!/usr/bin/env bun
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fchownSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { canonicalJson } from "../../server/intelligence-v24/validation";
import type { JsonValue } from "../../server/intelligence-v24/types";
import {
  STATIC_RELEASE_POINTER,
  StaticArtifactReleaseStore,
} from "../../server/static-release/StaticArtifactReleaseStore";
import {
  SERVER_RELEASE_MANIFEST,
  sha256File,
  verifyServerRelease,
  type ServerReleaseManifestEntry,
  type VerifiedServerRelease,
} from "./FunctionalReleasePrimitives";
import { withSharedReleaseLock } from "./ReleaseExecutionBoundary";

export const ROLLBACK_REPAIR_PLAN_ID = "rollback-target-two-file-repair-20260721-v1";
export const FAILED_RELEASE_CLEANUP_PLAN_ID = "failed-functional-release-cleanup-20260721-v1";

export const ROLLBACK_REPAIR_ACTIVE_RELEASE_ID = "brain-full-import-20260721T160000Z";
export const ROLLBACK_REPAIR_TARGET_RELEASE_ID = "brain-outcomes-visual-20260721T091557Z";
export const ROLLBACK_REPAIR_SOURCE_RELEASE_ID = "brain-dark-titanium-20260721T073740Z";
export const ROLLBACK_REPAIR_PATHS = Object.freeze([
  "server/events/EventStreamService.ts",
  "server/memory/OperationalHazardObservationService.ts",
] as const);
export const FAILED_RELEASE_CLEANUP_IDS = Object.freeze([
  "brain-full-import-20260721T152000Z",
  "brain-full-import-20260721T155000Z",
] as const);

const FAILED_RECEIPT_SHA256: Readonly<Record<string, string>> = Object.freeze({
  "brain-full-import-20260721T152000Z": "53deab8830a040e676a90644d02d8344cd7ced8792679ef001beaab7040a9922",
  "brain-full-import-20260721T155000Z": "4bc001131a7fcee66f8c22e82cdc6fb51372e0915b78d27502b70aed1ab135f1",
});

const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$/u;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_SERVER_MANIFEST_BYTES = 16 * 1024 * 1024;

interface DeploymentReceipt {
  readonly schemaVersion: string;
  readonly releaseId: string;
  readonly status: string;
  readonly failure?: string;
  readonly serverRelease?: {
    readonly path?: string;
    readonly manifestSha256?: string;
    readonly treeSha256?: string;
  };
  readonly staticRelease?: {
    readonly releaseId?: string;
    readonly manifestSha256?: string;
  };
  readonly previous?: {
    readonly applicationTarget?: string;
    readonly staticPointer?: unknown;
  };
  readonly backup?: {
    readonly root?: string;
    readonly database?: string;
    readonly databaseSha256?: string;
    readonly onlinePreflightDatabase?: string;
    readonly onlinePreflightDatabaseSha256?: string;
    readonly sourceArchive?: string;
    readonly vaultArchive?: string;
    readonly staticPointer?: string;
    readonly metadata?: string;
    readonly checksumManifestSha256?: string;
  };
}

interface BackupMetadata {
  readonly schemaVersion?: string;
  readonly releaseId?: string;
  readonly rollbackServerTarget?: string;
  readonly serverRelease?: {
    readonly path?: string;
    readonly manifestSha256?: string;
  };
}

interface ParsedServerManifest {
  readonly schemaVersion: "ti-scale.server-release-manifest.v1";
  readonly releaseId: string;
  readonly entryCount: number;
  readonly totalBytes: number;
  readonly treeSha256: string;
  readonly entries: readonly ServerReleaseManifestEntry[];
}

interface CurrentTreeEntry extends ServerReleaseManifestEntry {
  readonly mode: number;
  readonly uid: number;
  readonly gid: number;
  readonly inode: number;
}

export interface RollbackRepairPreview {
  readonly schemaVersion: "ti-scale.rollback-target-repair-preview.v1";
  readonly planId: string;
  readonly activeReleaseId: string;
  readonly rollbackReleaseId: string;
  readonly sourceReleaseId: string;
  readonly activeApplicationTarget: string;
  readonly activeServerManifestSha256: string;
  readonly rollbackServerManifestSha256: string;
  readonly sourceServerManifestSha256: string;
  readonly staticPointerPath: string;
  readonly staticPointerSha256: string;
  readonly repairEntries: readonly {
    readonly path: string;
    readonly expectedSha256: string;
    readonly expectedBytes: number;
    readonly sourceSha256: string;
    readonly currentSha256: string;
    readonly currentBytes: number;
    readonly currentMode: number;
    readonly currentUid: number;
    readonly currentGid: number;
    readonly currentInode: number;
  }[];
  readonly previewHash: string;
}

export interface FailedReleaseCleanupPreview {
  readonly schemaVersion: "ti-scale.failed-release-cleanup-preview.v1";
  readonly planId: string;
  readonly activeReleaseId: string;
  readonly rollbackReleaseId: string;
  readonly activeApplicationTarget: string;
  readonly activeServerManifestSha256: string;
  readonly rollbackServerManifestSha256: string;
  readonly staticPointerPath: string;
  readonly staticPointerSha256: string;
  readonly targets: readonly {
    readonly releaseId: string;
    readonly serverReleasePath: string;
    readonly staticReleasePath: string;
    readonly backupPath: string;
    readonly deploymentReceiptPath: string;
    readonly deploymentReceiptSha256: string;
    readonly serverManifestSha256: string;
    readonly staticManifestSha256: string;
    readonly onlinePreflightDatabasePath: string;
    readonly onlinePreflightDatabaseSha256: string;
    readonly allocatedBytes: number;
    readonly preservedFailureReceipt: JsonValue;
  }[];
  readonly targetCount: number;
  readonly totalAllocatedBytes: number;
  readonly previewHash: string;
}

export interface RollbackMaintenanceOptions {
  readonly serverReleaseRoot?: string;
  readonly staticReleaseRoot?: string;
  readonly backupRoot?: string;
  readonly applicationPath?: string;
  readonly auditReceiptRoot?: string;
  readonly activeReleaseId?: string;
  readonly rollbackReleaseId?: string;
  readonly sourceReleaseId?: string;
  readonly repairPaths?: readonly string[];
  readonly failedReleaseIds?: readonly string[];
  readonly expectedFailedReceiptSha256?: Readonly<Record<string, string>>;
  readonly repairPlanId?: string;
  readonly cleanupPlanId?: string;
  readonly clock?: () => Date;
  readonly uid?: () => number;
  readonly verifyServer?: (
    releaseDirectory: string,
    releaseId: string,
    manifestSha256?: string,
  ) => Promise<VerifiedServerRelease>;
  readonly openReferenceScanner?: (
    roots: readonly string[],
  ) => readonly { readonly pid: number; readonly kind: string; readonly path: string }[];
}

interface MaintenanceEvent {
  readonly sequence: number;
  readonly action: string;
  readonly occurredAt: string;
  readonly previousHash: string | null;
  readonly recordHash: string;
  readonly detail?: JsonValue;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeId(value: string, label: string): string {
  const normalized = value.trim();
  if (!SAFE_ID.test(normalized) || normalized === "." || normalized === "..") {
    throw new Error(`${label} is not a safe identifier`);
  }
  return normalized;
}

function boundedText(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 1_000 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new Error(`${label} must contain 1 to 1000 printable characters`);
  }
  return normalized;
}

function safeRelativePath(value: string): string {
  if (
    !value || value.length > 4_096 || value.includes("\0") || value.includes("\\") ||
    value.startsWith("/") || value.endsWith("/") ||
    value.split("/").some((segment) => !segment || segment === "." || segment === "..")
  ) throw new Error(`Unsafe release-relative path: ${value}`);
  return value;
}

function containedBy(rootValue: string, candidateValue: string): boolean {
  const root = resolve(rootValue);
  const candidate = resolve(candidateValue);
  const child = relative(root, candidate);
  return child === "" || (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`));
}

function exactChild(rootValue: string, idValue: string, label: string): string {
  const root = resolve(rootValue);
  const id = safeId(idValue, label);
  const path = resolve(root, id);
  if (!containedBy(root, path) || path === root || dirname(path) !== root) {
    throw new Error(`${label} is not an exact child of its protected root`);
  }
  return path;
}

function realDirectory(pathValue: string, label: string): string {
  const path = resolve(pathValue);
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(path) !== path) {
    throw new Error(`${label} must be a real, non-link directory`);
  }
  return path;
}

function regularFile(pathValue: string, label: string, maximumBytes = Number.MAX_SAFE_INTEGER): string {
  const path = resolve(pathValue);
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maximumBytes) {
    throw new Error(`${label} must be a regular, non-link file`);
  }
  return path;
}

function boundedJson(pathValue: string, label: string): { readonly bytes: Buffer; readonly value: JsonValue } {
  const path = regularFile(pathValue, label, MAX_JSON_BYTES);
  const bytes = readFileSync(path);
  const value = JSON.parse(bytes.toString("utf8")) as JsonValue;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must contain a JSON object`);
  }
  return { bytes, value };
}

function digestManifestEntries(entries: readonly ServerReleaseManifestEntry[]): string {
  return sha256(entries.map((entry) => [
    entry.kind,
    entry.path,
    String(entry.bytes),
    entry.executable ? "x" : "-",
    entry.sha256,
    entry.linkTarget ?? "",
  ].join("\0")).join("\n"));
}

function parseServerManifest(pathValue: string, releaseId: string, expectedSha256: string): ParsedServerManifest {
  const path = regularFile(
    pathValue,
    `Server manifest ${releaseId}`,
    MAX_SERVER_MANIFEST_BYTES,
  );
  const bytes = readFileSync(path);
  if (sha256(bytes) !== expectedSha256) throw new Error(`Server manifest checksum mismatch for ${releaseId}`);
  const raw = JSON.parse(bytes.toString("utf8")) as Record<string, unknown>;
  if (
    raw.schemaVersion !== "ti-scale.server-release-manifest.v1" || raw.releaseId !== releaseId ||
    !Number.isSafeInteger(raw.entryCount) || !Number.isSafeInteger(raw.totalBytes) ||
    !SHA256.test(String(raw.treeSha256 ?? "")) || !Array.isArray(raw.entries)
  ) throw new Error(`Server manifest is invalid for ${releaseId}`);
  const entries = raw.entries.map((value) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`Server manifest entry is invalid for ${releaseId}`);
    }
    const entry = value as Record<string, unknown>;
    const path = safeRelativePath(String(entry.path ?? ""));
    const kind = entry.kind;
    const bytes = entry.bytes;
    const executable = entry.executable;
    const entrySha256 = entry.sha256;
    if (
      (kind !== "file" && kind !== "symlink") || !Number.isSafeInteger(bytes) || (bytes as number) < 0 ||
      typeof executable !== "boolean" || !SHA256.test(String(entrySha256 ?? ""))
    ) throw new Error(`Server manifest entry is invalid for ${releaseId}: ${path}`);
    const linkTarget = typeof entry.linkTarget === "string" ? entry.linkTarget : undefined;
    if ((kind === "symlink") !== (linkTarget !== undefined)) {
      throw new Error(`Server manifest link entry is invalid for ${releaseId}: ${path}`);
    }
    return Object.freeze({
      path,
      kind,
      bytes: bytes as number,
      executable,
      sha256: String(entrySha256),
      ...(linkTarget !== undefined ? { linkTarget } : {}),
    }) as ServerReleaseManifestEntry;
  });
  const sorted = [...entries].sort((left, right) => left.path.localeCompare(right.path, "en"));
  if (
    new Set(entries.map((entry) => entry.path)).size !== entries.length ||
    JSON.stringify(sorted) !== JSON.stringify(entries) ||
    raw.entryCount !== entries.length ||
    raw.totalBytes !== entries.reduce((sum, entry) => sum + entry.bytes, 0) ||
    raw.treeSha256 !== digestManifestEntries(entries)
  ) throw new Error(`Server manifest aggregate is invalid for ${releaseId}`);
  return Object.freeze({
    schemaVersion: "ti-scale.server-release-manifest.v1",
    releaseId,
    entryCount: entries.length,
    totalBytes: raw.totalBytes as number,
    treeSha256: String(raw.treeSha256),
    entries: Object.freeze(entries),
  });
}

async function scanReleaseTree(rootValue: string): Promise<ReadonlyMap<string, CurrentTreeEntry>> {
  const root = realDirectory(rootValue, "Server release tree");
  const result = new Map<string, CurrentTreeEntry>();
  const visit = async (directory: string): Promise<void> => {
    for (const name of readdirSync(directory).sort((a, b) => a.localeCompare(b, "en"))) {
      const path = join(directory, name);
      const relativePath = safeRelativePath(relative(root, path).split(sep).join("/"));
      if (relativePath === SERVER_RELEASE_MANIFEST) continue;
      const metadata = lstatSync(path);
      if (metadata.isDirectory()) {
        await visit(path);
        continue;
      }
      if (metadata.isSymbolicLink()) {
        const linkTarget = readlinkSync(path);
        if (isAbsolute(linkTarget) || !containedBy(root, resolve(dirname(path), linkTarget))) {
          throw new Error(`Server release symbolic link escapes its root: ${relativePath}`);
        }
        result.set(relativePath, Object.freeze({
          path: relativePath,
          kind: "symlink",
          bytes: Buffer.byteLength(linkTarget),
          executable: false,
          sha256: sha256(linkTarget),
          linkTarget,
          mode: metadata.mode & 0o7777,
          uid: metadata.uid,
          gid: metadata.gid,
          inode: metadata.ino,
        }));
        continue;
      }
      if (!metadata.isFile()) throw new Error(`Server release contains a special entry: ${relativePath}`);
      result.set(relativePath, Object.freeze({
        path: relativePath,
        kind: "file",
        bytes: metadata.size,
        executable: (metadata.mode & 0o111) !== 0,
        sha256: await sha256File(path),
        mode: metadata.mode & 0o7777,
        uid: metadata.uid,
        gid: metadata.gid,
        inode: metadata.ino,
      }));
    }
  };
  await visit(root);
  return result;
}

function sameManifestEntry(expected: ServerReleaseManifestEntry, actual: CurrentTreeEntry): boolean {
  return expected.path === actual.path && expected.kind === actual.kind && expected.bytes === actual.bytes &&
    expected.executable === actual.executable && expected.sha256 === actual.sha256 &&
    (expected.linkTarget ?? null) === (actual.linkTarget ?? null);
}

function parseChecksums(value: string): ReadonlyMap<string, string> {
  const entries = new Map<string, string>();
  for (const line of value.trim().split("\n")) {
    const match = /^([a-f0-9]{64})  ([A-Za-z0-9._/-]+)$/u.exec(line);
    if (!match || entries.has(match[2]!)) throw new Error("Backup checksum manifest is malformed");
    entries.set(match[2]!, match[1]!);
  }
  if (entries.size === 0) throw new Error("Backup checksum manifest is empty");
  return entries;
}

function writeJsonAtomically(pathValue: string, value: unknown): void {
  const path = resolve(pathValue);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  renameSync(temporary, path);
  const descriptor = openSync(dirname(path), constants.O_RDONLY | NO_FOLLOW);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function writeJsonExclusively(pathValue: string, value: unknown): void {
  const path = resolve(pathValue);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const bytes = `${JSON.stringify(value, null, 2)}\n`;
  const descriptor = openSync(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
    0o600,
  );
  try {
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    linkSync(temporary, path);
  } finally {
    unlinkSync(temporary);
  }
  const directory = openSync(dirname(path), constants.O_RDONLY | NO_FOLLOW);
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

function sealReceipt(pathValue: string): void {
  const path = regularFile(pathValue, "Maintenance audit receipt", MAX_JSON_BYTES * 8);
  chmodSync(path, 0o440);
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
  const directory = openSync(dirname(path), constants.O_RDONLY | NO_FOLLOW);
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

function eventHash(previousHash: string | null, value: unknown): string {
  return sha256(`${previousHash ?? ""}\n${canonicalJson(value as JsonValue)}`);
}

function appendEvent(
  events: MaintenanceEvent[],
  clock: () => Date,
  action: string,
  detail?: JsonValue,
): void {
  const previousHash = events.at(-1)?.recordHash ?? null;
  const unsigned = {
    sequence: events.length + 1,
    action,
    occurredAt: clock().toISOString(),
    ...(detail === undefined ? {} : { detail }),
  };
  events.push(Object.freeze({ ...unsigned, previousHash, recordHash: eventHash(previousHash, unsigned) }));
}

function requireApplicationPointer(applicationPathValue: string, expectedTarget: string): string {
  const applicationPath = resolve(applicationPathValue);
  const metadata = lstatSync(applicationPath);
  if (!metadata.isSymbolicLink()) throw new Error("Active application pointer must be a symbolic link");
  const target = realpathSync(applicationPath);
  if (target !== expectedTarget) throw new Error("Active application pointer changed or is outside this maintenance plan");
  return target;
}

function receiptAt(backupRoot: string, releaseId: string): {
  readonly path: string;
  readonly bytes: Buffer;
  readonly sha256: string;
  readonly receipt: DeploymentReceipt;
  readonly value: JsonValue;
} {
  const backupDirectory = realDirectory(exactChild(backupRoot, releaseId, `Backup ${releaseId}`), `Backup ${releaseId}`);
  const path = join(backupDirectory, "deployment-receipt.json");
  const parsed = boundedJson(path, `Deployment receipt ${releaseId}`);
  const receipt = parsed.value as unknown as DeploymentReceipt;
  if (receipt.schemaVersion !== "ti-scale.functional-release-receipt.v1" || receipt.releaseId !== releaseId) {
    throw new Error(`Deployment receipt identity mismatch for ${releaseId}`);
  }
  return { path, bytes: parsed.bytes, sha256: sha256(parsed.bytes), receipt, value: parsed.value };
}

function validateReceiptReleasePaths(input: {
  readonly receipt: DeploymentReceipt;
  readonly releaseId: string;
  readonly serverPath: string;
  readonly staticPath: string;
  readonly backupPath: string;
}): void {
  const { receipt, releaseId, serverPath, staticPath, backupPath } = input;
  if (
    resolve(receipt.serverRelease?.path ?? "") !== serverPath ||
    receipt.staticRelease?.releaseId !== releaseId ||
    resolve(receipt.backup?.root ?? "") !== backupPath ||
    !SHA256.test(receipt.serverRelease?.manifestSha256 ?? "") ||
    !SHA256.test(receipt.serverRelease?.treeSha256 ?? "") ||
    !SHA256.test(receipt.staticRelease?.manifestSha256 ?? "")
  ) throw new Error(`Deployment receipt paths or manifest bindings are invalid for ${releaseId}`);
  if (!staticPath.endsWith(`${sep}releases${sep}${releaseId}`)) {
    throw new Error(`Static release path is outside the expected release layout for ${releaseId}`);
  }
}

function allocatedBytes(pathValue: string, seen: Set<string>): number {
  const path = resolve(pathValue);
  const metadata = lstatSync(path);
  const inode = `${metadata.dev}:${metadata.ino}`;
  if (seen.has(inode)) throw new Error(`Cleanup candidate shares an inode: ${path}`);
  seen.add(inode);
  if (!metadata.isDirectory() && metadata.nlink !== 1) {
    throw new Error(`Cleanup candidate has shared filesystem links: ${path}`);
  }
  let total = metadata.blocks * 512;
  if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
    for (const name of readdirSync(path)) total += allocatedBytes(join(path, name), seen);
  }
  return total;
}

function processReferencesWithin(
  rootsValue: readonly string[],
): readonly { readonly pid: number; readonly kind: string; readonly path: string }[] {
  const roots = rootsValue.map((value) => resolve(value));
  const matches: { pid: number; kind: string; path: string }[] = [];
  const procEntries = (() => {
    try { return readdirSync("/proc"); } catch { return []; }
  })();
  const record = (pid: number, kind: string, rawPath: string): void => {
    const withoutDeleted = rawPath.endsWith(" (deleted)") ? rawPath.slice(0, -10) : rawPath;
    if (!isAbsolute(withoutDeleted)) return;
    const path = resolve(withoutDeleted);
    if (roots.some((root) => containedBy(root, path))) matches.push({ pid, kind, path });
  };
  for (const name of procEntries) {
    if (!/^\d+$/u.test(name)) continue;
    const pid = Number(name);
    for (const kind of ["cwd", "root", "exe"] as const) {
      try { record(pid, kind, readlinkSync(`/proc/${name}/${kind}`)); } catch { /* Process exited or is inaccessible. */ }
    }
    try {
      for (const fd of readdirSync(`/proc/${name}/fd`)) {
        try { record(pid, `fd:${fd}`, readlinkSync(`/proc/${name}/fd/${fd}`)); } catch { /* Raced process exit. */ }
      }
    } catch { /* Process exited or is inaccessible. */ }
    try {
      for (const line of readFileSync(`/proc/${name}/maps`, "utf8").split("\n")) {
        const match = /^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/u.exec(line);
        if (match?.[1]?.startsWith("/")) record(pid, "map", match[1]);
      }
    } catch { /* Process exited or is inaccessible. */ }
  }
  matches.sort((left, right) => left.pid - right.pid || left.kind.localeCompare(right.kind, "en") || left.path.localeCompare(right.path, "en"));
  return Object.freeze(matches);
}

function exactBackupPayload(backupPath: string): void {
  const expectedRoot = ["database", "deployment-receipt.json"];
  const actualRoot = readdirSync(backupPath).sort((a, b) => a.localeCompare(b, "en"));
  if (JSON.stringify(actualRoot) !== JSON.stringify(expectedRoot)) {
    throw new Error(`Failed-release backup contains unexpected payloads: ${backupPath}`);
  }
  const databaseDirectory = realDirectory(join(backupPath, "database"), "Failed-release database backup directory");
  const contents = readdirSync(databaseDirectory);
  if (contents.length !== 1 || contents[0] !== "online-preflight.sqlite") {
    throw new Error(`Failed-release database backup contains unexpected payloads: ${databaseDirectory}`);
  }
}

function readFileNoFollow(pathValue: string): Buffer {
  const descriptor = openSync(resolve(pathValue), constants.O_RDONLY | NO_FOLLOW);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile()) throw new Error(`Repair source is not a regular file: ${pathValue}`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) {
      throw new Error(`Repair source changed while being read: ${pathValue}`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function writeReplacement(input: {
  readonly targetPath: string;
  readonly bytes: Buffer;
  readonly expectedSha256: string;
  readonly mode: number;
  readonly uid: number;
  readonly gid: number;
}): string {
  const parent = realDirectory(dirname(input.targetPath), "Repair target parent");
  const temporary = join(parent, `.ti-scale-repair-${process.pid}-${randomUUID()}.tmp`);
  const descriptor = openSync(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
    0o600,
  );
  try {
    writeFileSync(descriptor, input.bytes);
    fchownSync(descriptor, input.uid, input.gid);
    fchmodSync(descriptor, input.mode);
    fsyncSync(descriptor);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size !== input.bytes.byteLength) {
      throw new Error(`Staged repair size mismatch: ${input.targetPath}`);
    }
  } catch (error) {
    closeSync(descriptor);
    rmSync(temporary, { force: true });
    throw error;
  }
  closeSync(descriptor);
  if (sha256(readFileNoFollow(temporary)) !== input.expectedSha256) {
    rmSync(temporary, { force: true });
    throw new Error(`Staged repair checksum mismatch: ${input.targetPath}`);
  }
  return temporary;
}

export class RollbackTargetMaintenanceService {
  readonly #serverReleaseRoot: string;
  readonly #staticReleaseRoot: string;
  readonly #backupRoot: string;
  readonly #applicationPath: string;
  readonly #auditReceiptRoot: string;
  readonly #activeReleaseId: string;
  readonly #rollbackReleaseId: string;
  readonly #sourceReleaseId: string;
  readonly #repairPaths: readonly string[];
  readonly #failedReleaseIds: readonly string[];
  readonly #expectedFailedReceiptSha256: Readonly<Record<string, string>>;
  readonly #repairPlanId: string;
  readonly #cleanupPlanId: string;
  readonly #clock: () => Date;
  readonly #uid: () => number;
  readonly #verifyServer: NonNullable<RollbackMaintenanceOptions["verifyServer"]>;
  readonly #openReferenceScanner: NonNullable<RollbackMaintenanceOptions["openReferenceScanner"]>;

  constructor(options: RollbackMaintenanceOptions = {}) {
    void options;
    throw new Error(
      "Rollback-target maintenance is disabled by operator no-backup policy",
    );
    /* c8 ignore start -- unreachable retired rollback-maintenance implementation */
    this.#serverReleaseRoot = resolve(options.serverReleaseRoot ?? "/opt/ti-scale-server-releases/releases");
    this.#staticReleaseRoot = resolve(options.staticReleaseRoot ?? "/var/lib/ti-scale/static-releases");
    this.#backupRoot = resolve(options.backupRoot ?? "/var/backups/ti-scale/releases");
    this.#applicationPath = resolve(options.applicationPath ?? "/opt/ti-scale");
    this.#auditReceiptRoot = resolve(options.auditReceiptRoot ?? "/var/backups/ti-scale/release-maintenance");
    this.#activeReleaseId = safeId(options.activeReleaseId ?? ROLLBACK_REPAIR_ACTIVE_RELEASE_ID, "Active release ID");
    this.#rollbackReleaseId = safeId(options.rollbackReleaseId ?? ROLLBACK_REPAIR_TARGET_RELEASE_ID, "Rollback release ID");
    this.#sourceReleaseId = safeId(options.sourceReleaseId ?? ROLLBACK_REPAIR_SOURCE_RELEASE_ID, "Repair source release ID");
    this.#repairPaths = Object.freeze([...(options.repairPaths ?? ROLLBACK_REPAIR_PATHS)].map(safeRelativePath).sort());
    this.#failedReleaseIds = Object.freeze([...(options.failedReleaseIds ?? FAILED_RELEASE_CLEANUP_IDS)].map((id) => safeId(id, "Failed release ID")));
    this.#expectedFailedReceiptSha256 = options.expectedFailedReceiptSha256 ?? FAILED_RECEIPT_SHA256;
    this.#repairPlanId = safeId(options.repairPlanId ?? ROLLBACK_REPAIR_PLAN_ID, "Repair plan ID");
    this.#cleanupPlanId = safeId(options.cleanupPlanId ?? FAILED_RELEASE_CLEANUP_PLAN_ID, "Cleanup plan ID");
    this.#clock = options.clock ?? (() => new Date());
    this.#uid = options.uid ?? (() => process.getuid?.() ?? -1);
    this.#verifyServer = options.verifyServer ?? verifyServerRelease;
    this.#openReferenceScanner = options.openReferenceScanner ?? processReferencesWithin;
    if (new Set([this.#activeReleaseId, this.#rollbackReleaseId, this.#sourceReleaseId]).size !== 3) {
      throw new Error("Active, rollback, and repair-source releases must be distinct");
    }
    if (this.#repairPaths.length !== 2 || new Set(this.#repairPaths).size !== 2) {
      throw new Error("Rollback repair plan must name exactly two unique paths");
    }
    if (this.#failedReleaseIds.length !== 2 || new Set(this.#failedReleaseIds).size !== 2) {
      throw new Error("Failed-release cleanup plan must name exactly two unique releases");
    }
    /* c8 ignore stop */
  }

  async repairPreview(): Promise<RollbackRepairPreview> {
    const serverRoot = realDirectory(this.#serverReleaseRoot, "Server release root");
    const staticRoot = realDirectory(this.#staticReleaseRoot, "Static release root");
    const backupRoot = realDirectory(this.#backupRoot, "Release backup root");
    const activePath = realDirectory(exactChild(serverRoot, this.#activeReleaseId, "Active release"), "Active release");
    const rollbackPath = realDirectory(exactChild(serverRoot, this.#rollbackReleaseId, "Rollback release"), "Rollback release");
    const sourcePath = realDirectory(exactChild(serverRoot, this.#sourceReleaseId, "Repair source release"), "Repair source release");
    const activeApplicationTarget = requireApplicationPointer(this.#applicationPath, activePath);

    const activeReceiptBundle = receiptAt(backupRoot, this.#activeReleaseId);
    const activeReceipt = activeReceiptBundle.receipt;
    const activeBackupPath = dirname(activeReceiptBundle.path);
    const activeStaticPath = join(staticRoot, "releases", this.#activeReleaseId);
    validateReceiptReleasePaths({
      receipt: activeReceipt,
      releaseId: this.#activeReleaseId,
      serverPath: activePath,
      staticPath: activeStaticPath,
      backupPath: activeBackupPath,
    });
    if (activeReceipt.status !== "deployed") throw new Error("Active release receipt is not deployed");
    const activeVerified = await this.#verifyServer(
      activePath,
      this.#activeReleaseId,
      activeReceipt.serverRelease!.manifestSha256!,
    );
    if (activeVerified.manifest.treeSha256 !== activeReceipt.serverRelease!.treeSha256) {
      throw new Error("Active release tree differs from its deployment receipt");
    }

    const checksumPath = regularFile(join(activeBackupPath, "SHA256SUMS"), "Active backup checksum manifest");
    const checksumBytes = readFileSync(checksumPath);
    if (sha256(checksumBytes) !== activeReceipt.backup?.checksumManifestSha256) {
      throw new Error("Active backup checksum manifest differs from its deployment receipt");
    }
    const checksums = parseChecksums(checksumBytes.toString("utf8"));
    const metadataPath = regularFile(activeReceipt.backup?.metadata ?? "", "Active backup metadata", MAX_JSON_BYTES);
    if (dirname(metadataPath) !== activeBackupPath || checksums.get("backup-metadata.json") !== await sha256File(metadataPath)) {
      throw new Error("Active backup metadata is not checksum-bound to the deployment receipt");
    }
    const metadata = boundedJson(metadataPath, "Active backup metadata").value as unknown as BackupMetadata;
    if (
      metadata.schemaVersion !== "ti-scale.functional-release-backup.v1" ||
      metadata.releaseId !== this.#activeReleaseId ||
      resolve(metadata.rollbackServerTarget ?? "") !== rollbackPath ||
      resolve(metadata.serverRelease?.path ?? "") !== activePath ||
      metadata.serverRelease?.manifestSha256 !== activeVerified.manifestSha256
    ) throw new Error("Active backup metadata does not bind the immediate rollback target");

    const rollbackReceiptBundle = receiptAt(backupRoot, this.#rollbackReleaseId);
    const rollbackReceipt = rollbackReceiptBundle.receipt;
    validateReceiptReleasePaths({
      receipt: rollbackReceipt,
      releaseId: this.#rollbackReleaseId,
      serverPath: rollbackPath,
      staticPath: join(staticRoot, "releases", this.#rollbackReleaseId),
      backupPath: dirname(rollbackReceiptBundle.path),
    });
    if (rollbackReceipt.status !== "deployed") throw new Error("Rollback release receipt is not deployed");

    const sourceReceiptBundle = receiptAt(backupRoot, this.#sourceReleaseId);
    const sourceReceipt = sourceReceiptBundle.receipt;
    validateReceiptReleasePaths({
      receipt: sourceReceipt,
      releaseId: this.#sourceReleaseId,
      serverPath: sourcePath,
      staticPath: join(staticRoot, "releases", this.#sourceReleaseId),
      backupPath: dirname(sourceReceiptBundle.path),
    });
    if (sourceReceipt.status !== "deployed") throw new Error("Repair source release receipt is not deployed");
    const sourceVerified = await this.#verifyServer(
      sourcePath,
      this.#sourceReleaseId,
      sourceReceipt.serverRelease!.manifestSha256!,
    );
    if (sourceVerified.manifest.treeSha256 !== sourceReceipt.serverRelease!.treeSha256) {
      throw new Error("Repair source release tree differs from its deployment receipt");
    }

    const staticStore = new StaticArtifactReleaseStore({ releaseRoot: staticRoot });
    const pointer = staticStore.readActivePointer();
    if (pointer.activeReleaseId !== this.#activeReleaseId || pointer.previousReleaseId !== this.#rollbackReleaseId) {
      throw new Error("Static pointer does not identify the active release and immediate rollback target in this plan");
    }
    staticStore.verifyRelease(this.#activeReleaseId, pointer.activeManifestSha256);
    staticStore.verifyRelease(this.#rollbackReleaseId, pointer.previousManifestSha256 ?? undefined);
    const staticPointerPath = regularFile(join(staticRoot, "state", STATIC_RELEASE_POINTER), "Static release pointer", MAX_JSON_BYTES);
    const staticPointerSha256 = await sha256File(staticPointerPath);

    const rollbackManifest = parseServerManifest(
      join(rollbackPath, SERVER_RELEASE_MANIFEST),
      this.#rollbackReleaseId,
      rollbackReceipt.serverRelease!.manifestSha256!,
    );
    if (rollbackManifest.treeSha256 !== rollbackReceipt.serverRelease!.treeSha256) {
      throw new Error("Rollback manifest tree digest differs from its deployment receipt");
    }
    const expectedByPath = new Map(rollbackManifest.entries.map((entry) => [entry.path, entry]));
    const actualByPath = await scanReleaseTree(rollbackPath);
    if (actualByPath.size !== expectedByPath.size) {
      throw new Error("Rollback release contains missing or unmanifested entries beyond the repair plan");
    }
    const repairSet = new Set(this.#repairPaths);
    const repairEntries: Omit<RollbackRepairPreview, "previewHash">["repairEntries"][number][] = [];
    for (const [path, expected] of expectedByPath) {
      const actual = actualByPath.get(path);
      if (!actual) throw new Error(`Rollback release is missing a manifest entry: ${path}`);
      if (!repairSet.has(path)) {
        if (!sameManifestEntry(expected, actual)) {
          throw new Error(`Rollback release has out-of-plan drift: ${path}`);
        }
        continue;
      }
      if (expected.kind !== "file" || actual.kind !== "file" || actual.executable !== expected.executable) {
        throw new Error(`Rollback repair target has an unsafe kind or mode: ${path}`);
      }
      const canonicalMode = expected.executable ? 0o555 : 0o444;
      if (actual.mode !== canonicalMode) {
        throw new Error(`Rollback repair target mode differs from its immutable release policy: ${path}`);
      }
      if (sameManifestEntry(expected, actual)) {
        throw new Error(`Rollback repair target is no longer drifted: ${path}`);
      }
      const sourceFile = regularFile(join(sourcePath, ...path.split("/")), `Repair source ${path}`);
      const sourceMetadata = lstatSync(sourceFile);
      if (
        (sourceMetadata.mode & 0o7777) !== canonicalMode ||
        sourceMetadata.uid !== actual.uid || sourceMetadata.gid !== actual.gid
      ) throw new Error(`Repair source ownership or mode does not match the rollback target: ${path}`);
      const sourceBytes = readFileNoFollow(sourceFile);
      const sourceSha256 = sha256(sourceBytes);
      if (sourceSha256 !== expected.sha256 || sourceBytes.byteLength !== expected.bytes) {
        throw new Error(`Repair source bytes do not match the rollback manifest: ${path}`);
      }
      repairEntries.push(Object.freeze({
        path,
        expectedSha256: expected.sha256,
        expectedBytes: expected.bytes,
        sourceSha256,
        currentSha256: actual.sha256,
        currentBytes: actual.bytes,
        currentMode: actual.mode,
        currentUid: actual.uid,
        currentGid: actual.gid,
        currentInode: actual.inode,
      }));
    }
    if (repairEntries.length !== 2 || repairEntries.map((entry) => entry.path).sort().join("\0") !== this.#repairPaths.join("\0")) {
      throw new Error("Rollback release drift is not exactly the two-file repair plan");
    }
    const rollbackReferences = this.#openReferenceScanner([rollbackPath]);
    if (rollbackReferences.length > 0) {
      const first = rollbackReferences[0]!;
      throw new Error(
        `Rollback target has an open process reference (${first.pid} ${first.kind} ${first.path})`,
      );
    }
    const unsigned = {
      schemaVersion: "ti-scale.rollback-target-repair-preview.v1" as const,
      planId: this.#repairPlanId,
      activeReleaseId: this.#activeReleaseId,
      rollbackReleaseId: this.#rollbackReleaseId,
      sourceReleaseId: this.#sourceReleaseId,
      activeApplicationTarget,
      activeServerManifestSha256: activeVerified.manifestSha256,
      rollbackServerManifestSha256: rollbackReceipt.serverRelease!.manifestSha256!,
      sourceServerManifestSha256: sourceVerified.manifestSha256,
      staticPointerPath,
      staticPointerSha256,
      repairEntries: Object.freeze(repairEntries.sort((a, b) => a.path.localeCompare(b.path, "en"))),
    };
    return Object.freeze({ ...unsigned, previewHash: sha256(canonicalJson(unsigned as unknown as JsonValue)) });
  }

  async repairExecute(input: {
    readonly expectedPreviewHash: string;
    readonly confirmation: string;
    readonly actorId: string;
    readonly reason: string;
  }): Promise<{ readonly status: "completed"; readonly receiptPath: string; readonly previewHash: string }> {
    if (this.#uid() !== 0) throw new Error("Rollback repair requires root");
    if (input.confirmation !== this.#repairPlanId) throw new Error(`Confirmation must exactly match ${this.#repairPlanId}`);
    if (!SHA256.test(input.expectedPreviewHash)) throw new Error("Expected preview hash must be a lowercase SHA-256");
    const actor = safeId(input.actorId, "Actor ID");
    const reason = boundedText(input.reason, "Repair reason");
    const preview = await this.repairPreview();
    if (preview.previewHash !== input.expectedPreviewHash) {
      throw new Error("Rollback repair preview changed; review a fresh preview before execution");
    }
    const receiptPath = join(this.#auditReceiptRoot, `${this.#repairPlanId}.json`);
    if (existsSync(receiptPath)) throw new Error("Rollback repair receipt already exists; repeat execution is refused");
    const rollbackPath = join(this.#serverReleaseRoot, this.#rollbackReleaseId);
    const sourcePath = join(this.#serverReleaseRoot, this.#sourceReleaseId);
    const activePath = join(this.#serverReleaseRoot, this.#activeReleaseId);
    const events: MaintenanceEvent[] = [];
    appendEvent(events, this.#clock, "repair_started", { actor, reason, previewHash: preview.previewHash });
    const receipt = {
      schemaVersion: "ti-scale.rollback-target-repair-receipt.v1",
      planId: this.#repairPlanId,
      status: "executing" as "executing" | "completed" | "failed",
      actor,
      reason,
      preview,
      events,
      repairedEntries: [] as JsonValue[],
    };
    writeJsonExclusively(receiptPath, receipt);

    const staged = new Map<string, string>();
    const originals = new Map<string, Buffer>();
    const replaced: string[] = [];
    try {
      const rollbackReferences = this.#openReferenceScanner([rollbackPath]);
      if (rollbackReferences.length > 0) {
        const first = rollbackReferences[0]!;
        throw new Error(
          `Rollback target gained an open process reference (${first.pid} ${first.kind} ${first.path})`,
        );
      }
      for (const entry of preview.repairEntries) {
        const targetPath = join(rollbackPath, ...entry.path.split("/"));
        const targetMetadata = lstatSync(targetPath);
        if (
          !targetMetadata.isFile() || targetMetadata.isSymbolicLink() || targetMetadata.ino !== entry.currentInode ||
          targetMetadata.uid !== entry.currentUid || targetMetadata.gid !== entry.currentGid ||
          (targetMetadata.mode & 0o7777) !== entry.currentMode || await sha256File(targetPath) !== entry.currentSha256
        ) throw new Error(`Rollback repair target changed after preview: ${entry.path}`);
        const original = readFileNoFollow(targetPath);
        if (original.byteLength !== entry.currentBytes || sha256(original) !== entry.currentSha256) {
          throw new Error(`Rollback repair target changed while being read: ${entry.path}`);
        }
        originals.set(entry.path, original);
        const sourceBytes = readFileNoFollow(join(sourcePath, ...entry.path.split("/")));
        if (sourceBytes.byteLength !== entry.expectedBytes || sha256(sourceBytes) !== entry.expectedSha256) {
          throw new Error(`Repair source changed after preview: ${entry.path}`);
        }
        staged.set(entry.path, writeReplacement({
          targetPath,
          bytes: sourceBytes,
          expectedSha256: entry.expectedSha256,
          mode: entry.currentMode,
          uid: entry.currentUid,
          gid: entry.currentGid,
        }));
      }
      for (const entry of preview.repairEntries) {
        const targetPath = join(rollbackPath, ...entry.path.split("/"));
        renameSync(staged.get(entry.path)!, targetPath);
        staged.delete(entry.path);
        const descriptor = openSync(dirname(targetPath), constants.O_RDONLY | NO_FOLLOW);
        try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
        const after = statSync(targetPath);
        if (
          await sha256File(targetPath) !== entry.expectedSha256 || after.size !== entry.expectedBytes ||
          (after.mode & 0o7777) !== entry.currentMode || after.uid !== entry.currentUid || after.gid !== entry.currentGid
        ) throw new Error(`Atomic rollback repair verification failed: ${entry.path}`);
        replaced.push(entry.path);
        receipt.repairedEntries.push({
          path: entry.path,
          beforeSha256: entry.currentSha256,
          afterSha256: entry.expectedSha256,
          sourceSha256: entry.sourceSha256,
          modeBefore: entry.currentMode,
          modeAfter: after.mode & 0o7777,
          uidBefore: entry.currentUid,
          uidAfter: after.uid,
          gidBefore: entry.currentGid,
          gidAfter: after.gid,
        });
        appendEvent(events, this.#clock, "file_repaired", { path: entry.path, sha256: entry.expectedSha256 });
        writeJsonAtomically(receiptPath, receipt);
      }
      const verifiedRollback = await this.#verifyServer(
        rollbackPath,
        this.#rollbackReleaseId,
        preview.rollbackServerManifestSha256,
      );
      if (verifiedRollback.manifestSha256 !== preview.rollbackServerManifestSha256) {
        throw new Error("Rollback release failed final manifest verification");
      }
      requireApplicationPointer(this.#applicationPath, activePath);
      await this.#verifyServer(activePath, this.#activeReleaseId, preview.activeServerManifestSha256);
      if (await sha256File(preview.staticPointerPath) !== preview.staticPointerSha256) {
        throw new Error("Static release pointer changed during rollback repair");
      }
      receipt.status = "completed";
      appendEvent(events, this.#clock, "repair_completed", {
        verifiedRollbackManifestSha256: verifiedRollback.manifestSha256,
      });
      writeJsonAtomically(receiptPath, receipt);
      sealReceipt(receiptPath);
      return Object.freeze({ status: "completed", receiptPath, previewHash: preview.previewHash });
    } catch (error) {
      for (const path of [...replaced].reverse()) {
        const entry = preview.repairEntries.find((candidate) => candidate.path === path)!;
        try {
          const targetPath = join(rollbackPath, ...path.split("/"));
          const restoration = writeReplacement({
            targetPath,
            bytes: originals.get(path)!,
            expectedSha256: entry.currentSha256,
            mode: entry.currentMode,
            uid: entry.currentUid,
            gid: entry.currentGid,
          });
          renameSync(restoration, targetPath);
        } catch { /* The failed receipt keeps the partial state explicit for manual reconciliation. */ }
      }
      receipt.status = "failed";
      appendEvent(events, this.#clock, "repair_failed", {
        error: error instanceof Error ? error.message.slice(0, 1_000) : "unknown error",
      });
      writeJsonAtomically(receiptPath, receipt);
      sealReceipt(receiptPath);
      throw error;
    } finally {
      for (const temporary of staged.values()) rmSync(temporary, { force: true });
    }
  }

  async cleanupPreview(): Promise<FailedReleaseCleanupPreview> {
    const serverRoot = realDirectory(this.#serverReleaseRoot, "Server release root");
    const staticRoot = realDirectory(this.#staticReleaseRoot, "Static release root");
    const backupRoot = realDirectory(this.#backupRoot, "Release backup root");
    const activePath = realDirectory(exactChild(serverRoot, this.#activeReleaseId, "Active release"), "Active release");
    const rollbackPath = realDirectory(exactChild(serverRoot, this.#rollbackReleaseId, "Rollback release"), "Rollback release");
    const activeApplicationTarget = requireApplicationPointer(this.#applicationPath, activePath);

    const activeReceipt = receiptAt(backupRoot, this.#activeReleaseId).receipt;
    const rollbackReceipt = receiptAt(backupRoot, this.#rollbackReleaseId).receipt;
    if (activeReceipt.status !== "deployed" || rollbackReceipt.status !== "deployed") {
      throw new Error("Active and rollback receipts must both remain deployed");
    }
    validateReceiptReleasePaths({
      receipt: activeReceipt,
      releaseId: this.#activeReleaseId,
      serverPath: activePath,
      staticPath: join(staticRoot, "releases", this.#activeReleaseId),
      backupPath: join(backupRoot, this.#activeReleaseId),
    });
    validateReceiptReleasePaths({
      receipt: rollbackReceipt,
      releaseId: this.#rollbackReleaseId,
      serverPath: rollbackPath,
      staticPath: join(staticRoot, "releases", this.#rollbackReleaseId),
      backupPath: join(backupRoot, this.#rollbackReleaseId),
    });
    const activeVerified = await this.#verifyServer(
      activePath,
      this.#activeReleaseId,
      activeReceipt.serverRelease?.manifestSha256,
    );
    const rollbackVerified = await this.#verifyServer(
      rollbackPath,
      this.#rollbackReleaseId,
      rollbackReceipt.serverRelease?.manifestSha256,
    );
    if (
      activeVerified.manifest.treeSha256 !== activeReceipt.serverRelease?.treeSha256 ||
      rollbackVerified.manifest.treeSha256 !== rollbackReceipt.serverRelease?.treeSha256
    ) throw new Error("Active or rollback server release differs from its deployment receipt");

    const staticStore = new StaticArtifactReleaseStore({ releaseRoot: staticRoot });
    const pointer = staticStore.readActivePointer();
    if (pointer.activeReleaseId !== this.#activeReleaseId || pointer.previousReleaseId !== this.#rollbackReleaseId) {
      throw new Error("Static pointer changed or no longer retains the immediate rollback release");
    }
    staticStore.verifyRelease(this.#activeReleaseId, pointer.activeManifestSha256);
    staticStore.verifyRelease(this.#rollbackReleaseId, pointer.previousManifestSha256 ?? undefined);
    const staticPointerPath = regularFile(join(staticRoot, "state", STATIC_RELEASE_POINTER), "Static release pointer", MAX_JSON_BYTES);
    const staticPointerSha256 = await sha256File(staticPointerPath);

    const protectedIds = new Set([this.#activeReleaseId, this.#rollbackReleaseId, this.#sourceReleaseId]);
    if (this.#failedReleaseIds.some((id) => protectedIds.has(id))) {
      throw new Error("Failed-release cleanup overlaps an active, rollback, or repair-source release");
    }
    const seen = new Set<string>();
    const targets: Omit<FailedReleaseCleanupPreview, "previewHash">["targets"][number][] = [];
    for (const releaseId of this.#failedReleaseIds) {
      const serverReleasePath = realDirectory(exactChild(serverRoot, releaseId, `Failed server release ${releaseId}`), `Failed server release ${releaseId}`);
      const staticReleasePath = realDirectory(
        exactChild(join(staticRoot, "releases"), releaseId, `Failed static release ${releaseId}`),
        `Failed static release ${releaseId}`,
      );
      const backupPath = realDirectory(exactChild(backupRoot, releaseId, `Failed backup ${releaseId}`), `Failed backup ${releaseId}`);
      const bundle = receiptAt(backupRoot, releaseId);
      const expectedReceiptSha = this.#expectedFailedReceiptSha256[releaseId];
      if (!expectedReceiptSha || !SHA256.test(expectedReceiptSha) || bundle.sha256 !== expectedReceiptSha) {
        throw new Error(`Failed deployment receipt checksum is not the approved value for ${releaseId}`);
      }
      if (bundle.receipt.status !== "failed" || !bundle.receipt.failure?.trim()) {
        throw new Error(`Cleanup candidate is not an explicitly failed release: ${releaseId}`);
      }
      validateReceiptReleasePaths({
        receipt: bundle.receipt,
        releaseId,
        serverPath: serverReleasePath,
        staticPath: staticReleasePath,
        backupPath,
      });
      exactBackupPayload(backupPath);
      const onlinePreflightDatabasePath = regularFile(
        join(backupPath, "database", "online-preflight.sqlite"),
        `Online preflight database ${releaseId}`,
      );
      if (resolve(bundle.receipt.backup?.onlinePreflightDatabase ?? "") !== onlinePreflightDatabasePath) {
        throw new Error(`Failed receipt does not bind the retained online preflight database for ${releaseId}`);
      }
      const onlinePreflightDatabaseSha256 = await sha256File(onlinePreflightDatabasePath);
      if (
        !SHA256.test(bundle.receipt.backup?.onlinePreflightDatabaseSha256 ?? "") ||
        onlinePreflightDatabaseSha256 !== bundle.receipt.backup?.onlinePreflightDatabaseSha256 ||
        bundle.receipt.backup?.databaseSha256 !== ""
      ) throw new Error(`Failed receipt database bindings are invalid for ${releaseId}`);
      for (const absent of [
        bundle.receipt.backup?.database,
        bundle.receipt.backup?.sourceArchive,
        bundle.receipt.backup?.vaultArchive,
        bundle.receipt.backup?.staticPointer,
        bundle.receipt.backup?.metadata,
        join(backupPath, "SHA256SUMS"),
      ]) {
        if (absent && existsSync(resolve(absent))) {
          throw new Error(`Failed release unexpectedly contains a completed backup payload: ${releaseId}`);
        }
      }
      const serverVerified = await this.#verifyServer(
        serverReleasePath,
        releaseId,
        bundle.receipt.serverRelease!.manifestSha256!,
      );
      if (serverVerified.manifest.treeSha256 !== bundle.receipt.serverRelease!.treeSha256) {
        throw new Error(`Failed server release differs from its receipt: ${releaseId}`);
      }
      const staticVerified = staticStore.verifyRelease(
        releaseId,
        bundle.receipt.staticRelease!.manifestSha256!,
      );
      const openReferences = this.#openReferenceScanner([serverReleasePath, staticReleasePath, backupPath]);
      if (openReferences.length > 0) {
        const first = openReferences[0]!;
        throw new Error(
          `Failed release still has an open process reference (${first.pid} ${first.kind} ${first.path}): ${releaseId}`,
        );
      }
      const targetAllocatedBytes = allocatedBytes(serverReleasePath, seen) +
        allocatedBytes(staticReleasePath, seen) + allocatedBytes(backupPath, seen);
      targets.push(Object.freeze({
        releaseId,
        serverReleasePath,
        staticReleasePath,
        backupPath,
        deploymentReceiptPath: bundle.path,
        deploymentReceiptSha256: bundle.sha256,
        serverManifestSha256: serverVerified.manifestSha256,
        staticManifestSha256: staticVerified.manifestSha256,
        onlinePreflightDatabasePath,
        onlinePreflightDatabaseSha256,
        allocatedBytes: targetAllocatedBytes,
        preservedFailureReceipt: bundle.value,
      }));
    }
    const unsigned = {
      schemaVersion: "ti-scale.failed-release-cleanup-preview.v1" as const,
      planId: this.#cleanupPlanId,
      activeReleaseId: this.#activeReleaseId,
      rollbackReleaseId: this.#rollbackReleaseId,
      activeApplicationTarget,
      activeServerManifestSha256: activeVerified.manifestSha256,
      rollbackServerManifestSha256: rollbackVerified.manifestSha256,
      staticPointerPath,
      staticPointerSha256,
      targets: Object.freeze(targets),
      targetCount: targets.length,
      totalAllocatedBytes: targets.reduce((sum, target) => sum + target.allocatedBytes, 0),
    };
    return Object.freeze({ ...unsigned, previewHash: sha256(canonicalJson(unsigned as unknown as JsonValue)) });
  }

  async cleanupExecute(input: {
    readonly expectedPreviewHash: string;
    readonly confirmation: string;
    readonly actorId: string;
    readonly reason: string;
  }): Promise<{
    readonly status: "completed";
    readonly receiptPath: string;
    readonly previewHash: string;
    readonly deletedReleaseIds: readonly string[];
    readonly reclaimedAllocatedBytes: number;
  }> {
    if (this.#uid() !== 0) throw new Error("Failed-release cleanup requires root");
    if (input.confirmation !== this.#cleanupPlanId) throw new Error(`Confirmation must exactly match ${this.#cleanupPlanId}`);
    if (!SHA256.test(input.expectedPreviewHash)) throw new Error("Expected preview hash must be a lowercase SHA-256");
    const actor = safeId(input.actorId, "Actor ID");
    const reason = boundedText(input.reason, "Cleanup reason");
    const preview = await this.cleanupPreview();
    if (preview.previewHash !== input.expectedPreviewHash) {
      throw new Error("Failed-release cleanup preview changed; review a fresh preview before execution");
    }
    const receiptPath = join(this.#auditReceiptRoot, `${this.#cleanupPlanId}.json`);
    if (existsSync(receiptPath)) throw new Error("Failed-release cleanup receipt already exists; repeat execution is refused");
    const quarantine = {
      server: join(dirname(this.#serverReleaseRoot), "failed-cleanup-quarantine", this.#cleanupPlanId),
      static: join(this.#staticReleaseRoot, "failed-cleanup-quarantine", this.#cleanupPlanId),
      backup: join(dirname(this.#backupRoot), "failed-cleanup-quarantine", this.#cleanupPlanId),
    };
    for (const path of Object.values(quarantine)) {
      if (existsSync(path)) throw new Error(`Cleanup quarantine already exists: ${path}`);
      mkdirSync(path, { recursive: true, mode: 0o700 });
    }
    const events: MaintenanceEvent[] = [];
    appendEvent(events, this.#clock, "cleanup_started", { actor, reason, previewHash: preview.previewHash });
    const receipt = {
      schemaVersion: "ti-scale.failed-release-cleanup-receipt.v1",
      planId: this.#cleanupPlanId,
      status: "executing" as "executing" | "completed" | "failed",
      actor,
      reason,
      preview,
      preservedFailureReceipts: preview.targets.map((target) => ({
        releaseId: target.releaseId,
        sourcePath: target.deploymentReceiptPath,
        sha256: target.deploymentReceiptSha256,
        receipt: target.preservedFailureReceipt,
      })),
      deleted: [] as JsonValue[],
      events,
    };
    writeJsonExclusively(receiptPath, receipt);
    try {
      for (const target of preview.targets) {
        if (
          await sha256File(target.deploymentReceiptPath) !== target.deploymentReceiptSha256 ||
          await sha256File(target.onlinePreflightDatabasePath) !== target.onlinePreflightDatabaseSha256
        ) throw new Error(`Failed release changed after preview: ${target.releaseId}`);
        await this.#verifyServer(target.serverReleasePath, target.releaseId, target.serverManifestSha256);
        new StaticArtifactReleaseStore({ releaseRoot: this.#staticReleaseRoot })
          .verifyRelease(target.releaseId, target.staticManifestSha256);
        const paths = [
          { kind: "server", source: target.serverReleasePath, quarantineRoot: quarantine.server },
          { kind: "static", source: target.staticReleasePath, quarantineRoot: quarantine.static },
          { kind: "backup", source: target.backupPath, quarantineRoot: quarantine.backup },
        ] as const;
        for (const item of paths) {
          requireApplicationPointer(this.#applicationPath, join(this.#serverReleaseRoot, this.#activeReleaseId));
          if (await sha256File(preview.staticPointerPath) !== preview.staticPointerSha256) {
            throw new Error("Static release pointer changed during cleanup");
          }
          const openReferences = this.#openReferenceScanner([item.source]);
          if (openReferences.length > 0) {
            const first = openReferences[0]!;
            throw new Error(
              `Cleanup source gained an open process reference (${first.pid} ${first.kind} ${first.path})`,
            );
          }
          realDirectory(item.source, `Cleanup source ${target.releaseId} ${item.kind}`);
          const destination = join(item.quarantineRoot, target.releaseId);
          renameSync(item.source, destination);
          rmSync(destination, { recursive: true, force: false });
          receipt.deleted.push({ releaseId: target.releaseId, kind: item.kind, path: item.source });
          appendEvent(events, this.#clock, "bundle_component_deleted", {
            releaseId: target.releaseId,
            kind: item.kind,
            path: item.source,
          });
          writeJsonAtomically(receiptPath, receipt);
        }
      }
      for (const path of Object.values(quarantine)) rmSync(path, { recursive: true, force: false });
      requireApplicationPointer(this.#applicationPath, join(this.#serverReleaseRoot, this.#activeReleaseId));
      if (await sha256File(preview.staticPointerPath) !== preview.staticPointerSha256) {
        throw new Error("Static release pointer changed during cleanup");
      }
      await this.#verifyServer(
        join(this.#serverReleaseRoot, this.#activeReleaseId),
        this.#activeReleaseId,
        preview.activeServerManifestSha256,
      );
      await this.#verifyServer(
        join(this.#serverReleaseRoot, this.#rollbackReleaseId),
        this.#rollbackReleaseId,
        preview.rollbackServerManifestSha256,
      );
      const staticStore = new StaticArtifactReleaseStore({ releaseRoot: this.#staticReleaseRoot });
      const pointer = staticStore.readActivePointer();
      staticStore.verifyRelease(this.#activeReleaseId, pointer.activeManifestSha256);
      staticStore.verifyRelease(this.#rollbackReleaseId, pointer.previousManifestSha256 ?? undefined);
      receipt.status = "completed";
      appendEvent(events, this.#clock, "cleanup_completed", {
        deletedReleaseIds: preview.targets.map((target) => target.releaseId),
        reclaimedAllocatedBytes: preview.totalAllocatedBytes,
      });
      writeJsonAtomically(receiptPath, receipt);
      sealReceipt(receiptPath);
      return Object.freeze({
        status: "completed",
        receiptPath,
        previewHash: preview.previewHash,
        deletedReleaseIds: Object.freeze(preview.targets.map((target) => target.releaseId)),
        reclaimedAllocatedBytes: preview.totalAllocatedBytes,
      });
    } catch (error) {
      receipt.status = "failed";
      appendEvent(events, this.#clock, "cleanup_failed", {
        error: error instanceof Error ? error.message.slice(0, 1_000) : "unknown error",
      });
      writeJsonAtomically(receiptPath, receipt);
      sealReceipt(receiptPath);
      throw error;
    }
  }
}

interface CliArguments {
  readonly command: "repair-preview" | "repair-execute" | "cleanup-preview" | "cleanup-execute";
  readonly values: ReadonlyMap<string, string>;
}

export function parseRollbackMaintenanceArguments(argv: readonly string[]): CliArguments {
  const [command, ...rest] = argv;
  if (
    command !== "repair-preview" && command !== "repair-execute" &&
    command !== "cleanup-preview" && command !== "cleanup-execute"
  ) throw new Error("Command must be repair-preview, repair-execute, cleanup-preview, or cleanup-execute");
  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) throw new Error(`${token} requires a value`);
    if (values.has(token)) throw new Error(`Duplicate option: ${token}`);
    values.set(token, next);
    index += 1;
  }
  const execute = command.endsWith("-execute");
  const allowed = execute
    ? new Set(["--expected-preview-hash", "--confirm", "--actor", "--reason"])
    : new Set<string>();
  for (const key of values.keys()) if (!allowed.has(key)) throw new Error(`Unsupported ${command} option: ${key}`);
  if (execute) for (const key of allowed) if (!values.get(key)?.trim()) throw new Error(`${key} is required`);
  return { command, values };
}

async function main(argv = process.argv.slice(2)): Promise<number> {
  const args = parseRollbackMaintenanceArguments(argv);
  const service = new RollbackTargetMaintenanceService();
  const executeInput = args.command.endsWith("-execute") ? {
    expectedPreviewHash: args.values.get("--expected-preview-hash")!,
    confirmation: args.values.get("--confirm")!,
    actorId: args.values.get("--actor")!,
    reason: args.values.get("--reason")!,
  } : null;
  const result = args.command === "repair-preview" ? await service.repairPreview()
    : args.command === "repair-execute" ? await withSharedReleaseLock(
        () => service.repairExecute(executeInput!),
        { operation: "rollback-target-repair" },
      )
    : args.command === "cleanup-preview" ? await service.cleanupPreview()
    : await withSharedReleaseLock(
        () => service.cleanupExecute(executeInput!),
        { operation: "rollback-target-cleanup" },
      );
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return 0;
}

if (import.meta.main) {
  process.stderr.write(
    "Rollback-target maintenance is disabled by the operator no-backup policy\n",
  );
  process.exitCode = 1;
}

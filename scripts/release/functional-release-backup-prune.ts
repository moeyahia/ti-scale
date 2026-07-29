#!/usr/bin/env bun
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  closeSync,
  fsyncSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { canonicalJson } from "../../server/intelligence-v24/validation";
import type { JsonValue } from "../../server/intelligence-v24/types";
import { sha256File, verifyChecksumManifest } from "./FunctionalReleasePrimitives";
import { withSharedReleaseLock } from "./ReleaseExecutionBoundary";

export const FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID =
  "obsolete-functional-release-backups-20260721-v1";

/**
 * Human-owned recovery anchors. These identities are deliberately exact; a
 * similarly prefixed release is not silently treated as the same release.
 */
export const FUNCTIONAL_RELEASE_BACKUP_PRUNE_PROTECTED = Object.freeze([
  "brain-full-import-20260721T160000Z",
  "brain-outcomes-visual-20260721T091557Z",
  "brain-dark-titanium-20260721T073740Z",
  "brain-atlas-anatomy-20260720T231117Z",
  "previous-functional-20260719T171300Z",
  "functional-safe-recon-20260720T0735Z",
] as const);

export const FUNCTIONAL_RELEASE_BACKUP_PRUNE_ACKNOWLEDGEMENT =
  "--acknowledge-permanent-backup-deletion";

const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const ACTOR_ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const CHECKSUM_PATHS = Object.freeze([
  "backup-metadata.json",
  "database/online-preflight.sqlite",
  "database/pre-release.sqlite",
  "server-source.tar.gz",
  "static-pointer.json",
  "vault.tar.gz",
] as const);
const ROOT_PAYLOADS = Object.freeze([
  "SHA256SUMS",
  "backup-metadata.json",
  "database",
  "deployment-receipt.json",
  "migration-backups",
  "server-source.tar.gz",
  "static-pointer.json",
  "vault.tar.gz",
] as const);
const DATABASE_PAYLOADS = Object.freeze([
  "online-preflight.sqlite",
  "pre-release.sqlite",
] as const);
const MIGRATION_BACKUP = /^before-schema-migration-[0-9TZ:.-]+\.sqlite$/u;

interface StaticPointer {
  readonly schemaVersion: "ti-scale.static-artifact-pointer.v1";
  readonly scope: "v2_static_artifact_pointer_only";
  readonly generation: number;
  readonly activeReleaseId: string;
  readonly activeManifestSha256: string;
  readonly previousReleaseId: string;
  readonly previousManifestSha256: string;
  readonly activatedAt: string;
}

interface DeploymentReceipt {
  readonly schemaVersion: "ti-scale.functional-release-receipt.v1";
  readonly releaseId: string;
  readonly status: string;
  readonly serverRelease: {
    readonly path: string;
    readonly manifestSha256: string;
    readonly treeSha256: string;
  };
  readonly staticRelease: {
    readonly releaseId: string;
    readonly manifestSha256: string;
  };
  readonly previous: {
    readonly applicationKind: "directory" | "symlink";
    readonly applicationTarget: string;
    readonly staticPointer: StaticPointer;
  };
  readonly backup: {
    readonly root: string;
    readonly database: string;
    readonly databaseSha256: string;
    readonly onlinePreflightDatabase: string;
    readonly onlinePreflightDatabaseSha256: string;
    readonly sourceArchive: string;
    readonly vaultArchive: string;
    readonly staticPointer: string;
    readonly metadata: string;
    readonly checksumManifestSha256: string;
  };
  readonly database: {
    readonly sourceSchema: number;
    readonly ownerUid: number;
    readonly ownerGid: number;
    readonly deployedFingerprint: string;
  };
}

interface BackupMetadata {
  readonly schemaVersion: "ti-scale.functional-release-backup.v1";
  readonly releaseId: string;
  readonly database: {
    readonly path: string;
    readonly sha256: string;
    readonly schema: number;
    readonly quiesced: boolean;
    readonly ownerUid: number;
    readonly ownerGid: number;
  };
  readonly onlinePreflightDatabase: {
    readonly path: string;
    readonly sha256: string;
  };
  readonly source: { readonly path: string; readonly livePath: string };
  readonly rollbackServerTarget: string;
  readonly serverRelease: { readonly path: string; readonly manifestSha256: string };
  readonly vault: { readonly path: string; readonly livePath: string };
  readonly staticPointer: { readonly path: string; readonly value: StaticPointer };
  readonly tokenMaterialIncluded: boolean;
}

interface AllocationEntry {
  readonly blocks: number;
  readonly links: number;
  occurrences: number;
}

export interface FunctionalReleaseBackupPruneTarget {
  readonly releaseId: string;
  readonly backupPath: string;
  readonly deploymentReceiptSha256: string;
  readonly backupMetadataSha256: string;
  readonly checksumManifestSha256: string;
  readonly payloadTreeSha256: string;
  readonly checksumEntriesVerified: number;
  readonly migrationBackupSha256: string;
  readonly apparentBytes: number;
  readonly allocatedBytes: number;
}

export interface FunctionalReleaseBackupPrunePreview {
  readonly schemaVersion: "ti-scale.functional-release-backup-prune-preview.v1";
  readonly planId: typeof FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID;
  readonly backupRoot: string;
  readonly serverReleaseRoot: string;
  readonly activeApplicationReleaseId: string;
  readonly currentPointerReleaseId: string | null;
  readonly activeStaticReleaseId: string;
  readonly previousStaticReleaseId: string;
  readonly protectedReleaseIds: readonly string[];
  readonly excludedBundles: readonly {
    readonly releaseId: string;
    readonly reason: "protected" | "server_release_present";
  }[];
  readonly targets: readonly FunctionalReleaseBackupPruneTarget[];
  readonly targetCount: number;
  readonly totalApparentBytes: number;
  readonly totalAllocatedBytes: number;
  readonly minimumReclaimableBytes: number;
  readonly previewHash: string;
}

export interface FunctionalReleaseBackupPruneResult {
  readonly status: "completed";
  readonly planId: typeof FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID;
  readonly previewHash: string;
  readonly deletedReleaseIds: readonly string[];
  readonly minimumReclaimableBytes: number;
  readonly receiptPath: string;
  readonly receiptHash: string;
}

export interface FunctionalReleaseBackupPruneOptions {
  readonly backupRoot?: string;
  readonly serverReleaseRoot?: string;
  readonly applicationPath?: string;
  readonly currentPointerPath?: string;
  readonly staticPointerPath?: string;
  readonly receiptRoot?: string;
  readonly quarantineRoot?: string;
  readonly clock?: () => Date;
  readonly uid?: () => number;
  readonly openReferenceScanner?: (paths: readonly string[]) => readonly string[];
}

interface ReceiptEvent {
  readonly sequence: number;
  readonly action: "prune_started" | "backup_deleted" | "prune_completed" | "prune_failed";
  readonly occurredAt: string;
  readonly previousHash: string | null;
  readonly recordHash: string;
  readonly actorId?: string;
  readonly reason?: string;
  readonly previewHash?: string;
  readonly releaseId?: string;
  readonly error?: string;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeReleaseId(value: string, label: string): string {
  const normalized = value.trim();
  if (!RELEASE_ID.test(normalized) || normalized === "." || normalized === "..") {
    throw new Error(`${label} is not a safe release identifier`);
  }
  return normalized;
}

function safeActor(value: string): string {
  const normalized = value.trim();
  if (!ACTOR_ID.test(normalized)) throw new Error("Actor ID is not a safe identifier");
  return normalized;
}

function boundedReason(value: string): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > 1_000 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new Error("Reason must contain 1 to 1000 printable characters");
  }
  return normalized;
}

function exactChild(rootValue: string, childValue: string, label: string): string {
  const root = resolve(rootValue);
  const child = resolve(childValue);
  const suffix = relative(root, child);
  if (!suffix || isAbsolute(suffix) || suffix === ".." || suffix.startsWith(`..${sep}`)) {
    throw new Error(`${label} is not an exact child of its protected root`);
  }
  return child;
}

function releaseIdFromPath(rootValue: string, pathValue: string, label: string): string {
  const root = resolve(rootValue);
  const path = exactChild(root, pathValue, label);
  const suffix = relative(root, path);
  if (suffix.includes(sep)) throw new Error(`${label} is not a direct release child`);
  return safeReleaseId(suffix, label);
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
    throw new Error(`${label} must be a regular, non-link file within its size bound`);
  }
  return path;
}

function boundedJson(pathValue: string, label: string): unknown {
  return JSON.parse(readFileSync(regularFile(pathValue, label, MAX_JSON_BYTES), "utf8")) as unknown;
}

function exactNames(directory: string, expected: readonly string[], label: string): void {
  const actual = readdirSync(directory).sort((left, right) => left.localeCompare(right, "en"));
  const wanted = [...expected].sort((left, right) => left.localeCompare(right, "en"));
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} contains an unexpected or missing payload`);
  }
}

function parseStaticPointer(value: unknown, label: string): StaticPointer {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid`);
  const pointer = value as Partial<StaticPointer>;
  if (
    pointer.schemaVersion !== "ti-scale.static-artifact-pointer.v1" ||
    pointer.scope !== "v2_static_artifact_pointer_only" ||
    !Number.isSafeInteger(pointer.generation) || (pointer.generation ?? -1) < 0 ||
    typeof pointer.activeReleaseId !== "string" || typeof pointer.previousReleaseId !== "string" ||
    typeof pointer.activeManifestSha256 !== "string" || !SHA256.test(pointer.activeManifestSha256) ||
    typeof pointer.previousManifestSha256 !== "string" || !SHA256.test(pointer.previousManifestSha256) ||
    typeof pointer.activatedAt !== "string" || !Number.isFinite(Date.parse(pointer.activatedAt))
  ) throw new Error(`${label} is invalid`);
  return {
    schemaVersion: pointer.schemaVersion,
    scope: pointer.scope,
    generation: pointer.generation!,
    activeReleaseId: safeReleaseId(pointer.activeReleaseId, `${label} active release`),
    activeManifestSha256: pointer.activeManifestSha256,
    previousReleaseId: safeReleaseId(pointer.previousReleaseId, `${label} previous release`),
    previousManifestSha256: pointer.previousManifestSha256,
    activatedAt: pointer.activatedAt,
  };
}

function asReceipt(value: unknown, releaseId: string): DeploymentReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Deployment receipt is invalid for ${releaseId}`);
  const receipt = value as Partial<DeploymentReceipt>;
  if (
    receipt.schemaVersion !== "ti-scale.functional-release-receipt.v1" ||
    receipt.releaseId !== releaseId || receipt.status !== "deployed" ||
    !receipt.serverRelease || !receipt.staticRelease || !receipt.previous || !receipt.backup || !receipt.database ||
    (receipt.previous.applicationKind !== "directory" && receipt.previous.applicationKind !== "symlink") ||
    !SHA256.test(receipt.serverRelease.manifestSha256 ?? "") ||
    !SHA256.test(receipt.serverRelease.treeSha256 ?? "") ||
    receipt.staticRelease.releaseId !== releaseId || !SHA256.test(receipt.staticRelease.manifestSha256 ?? "") ||
    !SHA256.test(receipt.backup.databaseSha256 ?? "") ||
    !SHA256.test(receipt.backup.onlinePreflightDatabaseSha256 ?? "") ||
    !SHA256.test(receipt.backup.checksumManifestSha256 ?? "") ||
    !Number.isSafeInteger(receipt.database.sourceSchema) ||
    !Number.isSafeInteger(receipt.database.ownerUid) || !Number.isSafeInteger(receipt.database.ownerGid) ||
    !SHA256.test(receipt.database.deployedFingerprint ?? "")
  ) throw new Error(`Deployment receipt does not prove a completed release backup for ${releaseId}`);
  parseStaticPointer(receipt.previous.staticPointer, `Receipt static pointer ${releaseId}`);
  return receipt as DeploymentReceipt;
}

function asMetadata(value: unknown, releaseId: string): BackupMetadata {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Backup metadata is invalid for ${releaseId}`);
  const metadata = value as Partial<BackupMetadata>;
  if (
    metadata.schemaVersion !== "ti-scale.functional-release-backup.v1" ||
    metadata.releaseId !== releaseId || !metadata.database || !metadata.onlinePreflightDatabase ||
    !metadata.source || !metadata.serverRelease || !metadata.vault || !metadata.staticPointer ||
    metadata.tokenMaterialIncluded !== false
  ) throw new Error(`Backup metadata is invalid for ${releaseId}`);
  parseStaticPointer(metadata.staticPointer.value, `Metadata static pointer ${releaseId}`);
  return metadata as BackupMetadata;
}

function assertExactFile(path: string, expected: string, label: string): void {
  if (resolve(path) !== resolve(expected)) throw new Error(`${label} does not have its exact expected path`);
}

function walkAllocation(path: string, allocation: Map<string, AllocationEntry>): { apparent: number; allocated: number } {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || (!metadata.isDirectory() && !metadata.isFile())) {
    throw new Error(`Backup contains a link or special filesystem entry: ${path}`);
  }
  const key = `${metadata.dev}:${metadata.ino}`;
  const current = allocation.get(key);
  if (current) current.occurrences += 1;
  else allocation.set(key, { blocks: metadata.blocks * 512, links: metadata.nlink, occurrences: 1 });
  let apparent = metadata.isFile() ? metadata.size : 0;
  let allocated = metadata.blocks * 512;
  if (metadata.isDirectory()) {
    for (const name of readdirSync(path).sort((left, right) => left.localeCompare(right, "en"))) {
      const child = walkAllocation(join(path, name), allocation);
      apparent += child.apparent;
      allocated += child.allocated;
    }
  }
  return { apparent, allocated };
}

async function payloadTreeHash(
  root: string,
  checksumEntries: Readonly<Record<string, string>>,
): Promise<{ readonly treeHash: string; readonly migrationBackupSha256: string }> {
  const migrationDirectory = realDirectory(join(root, "migration-backups"), "Migration backup directory");
  const migrations = readdirSync(migrationDirectory).sort((left, right) => left.localeCompare(right, "en"));
  if (migrations.length !== 1 || !MIGRATION_BACKUP.test(migrations[0]!)) {
    throw new Error("Migration backup directory must contain exactly one canonical SQLite backup");
  }
  const migrationPath = regularFile(join(migrationDirectory, migrations[0]!), "Migration backup");
  const migrationBackupSha256 = await sha256File(migrationPath);
  const receiptSha = await sha256File(join(root, "deployment-receipt.json"));
  const checksumSha = await sha256File(join(root, "SHA256SUMS"));
  const entries = [
    ...Object.entries(checksumEntries).map(([path, hash]) => `${path}\0${hash}`),
    `SHA256SUMS\0${checksumSha}`,
    `deployment-receipt.json\0${receiptSha}`,
    `migration-backups/${migrations[0]}\0${migrationBackupSha256}`,
  ].sort((left, right) => left.localeCompare(right, "en"));
  return { treeHash: sha256(entries.join("\n")), migrationBackupSha256 };
}

function defaultOpenReferenceScanner(paths: readonly string[]): readonly string[] {
  const roots = paths.map((path) => `${resolve(path)}${sep}`);
  const exact = new Set(paths.map((path) => resolve(path)));
  const matches = new Set<string>();
  let processes: string[] = [];
  try { processes = readdirSync("/proc").filter((name) => /^\d+$/u.test(name)); }
  catch { throw new Error("Unable to inspect /proc for open backup references"); }
  for (const pid of processes) {
    for (const name of ["cwd", "root", "exe"]) {
      const probe = `/proc/${pid}/${name}`;
      try {
        const target = resolve(readlinkSync(probe));
        if (exact.has(target) || roots.some((root) => target.startsWith(root))) matches.add(`${pid}:${name}:${target}`);
      } catch { /* process may exit or deny inspection */ }
    }
    const fdRoot = `/proc/${pid}/fd`;
    try {
      for (const fd of readdirSync(fdRoot)) {
        try {
          const raw = readlinkSync(join(fdRoot, fd)).replace(/ \(deleted\)$/u, "");
          if (!isAbsolute(raw)) continue;
          const target = resolve(raw);
          if (exact.has(target) || roots.some((root) => target.startsWith(root))) matches.add(`${pid}:fd:${fd}:${target}`);
        } catch { /* descriptor changed while scanning */ }
      }
    } catch { /* process may exit or deny inspection */ }
  }
  return [...matches].sort((left, right) => left.localeCompare(right, "en"));
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try { fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
}

function writeJsonAtomically(pathValue: string, value: unknown): void {
  const path = resolve(pathValue);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  chmodSync(path, 0o600);
  fsyncDirectory(dirname(path));
}

function eventRecord(previousHash: string | null, value: Omit<ReceiptEvent, "previousHash" | "recordHash">): ReceiptEvent {
  const recordHash = sha256(`${previousHash ?? ""}\n${canonicalJson(value as JsonValue)}`);
  return { ...value, previousHash, recordHash };
}

function receiptHash(value: Record<string, unknown>): string {
  const { receiptHash: _ignored, ...unsigned } = value;
  return sha256(canonicalJson(unsigned as JsonValue));
}

export class FunctionalReleaseBackupPruneService {
  readonly #backupRoot: string;
  readonly #serverReleaseRoot: string;
  readonly #applicationPath: string;
  readonly #currentPointerPath: string;
  readonly #staticPointerPath: string;
  readonly #receiptRoot: string;
  readonly #quarantineRoot: string;
  readonly #clock: () => Date;
  readonly #uid: () => number;
  readonly #openReferenceScanner: NonNullable<FunctionalReleaseBackupPruneOptions["openReferenceScanner"]>;

  constructor(options: FunctionalReleaseBackupPruneOptions = {}) {
    void options;
    throw new Error(
      "Legacy functional-release backup maintenance is disabled by operator no-backup policy",
    );
    /* c8 ignore start -- unreachable retired backup-maintenance implementation */
    this.#backupRoot = resolve(options.backupRoot ?? "/var/backups/ti-scale/releases");
    this.#serverReleaseRoot = resolve(options.serverReleaseRoot ?? "/opt/ti-scale-server-releases/releases");
    this.#applicationPath = resolve(options.applicationPath ?? "/opt/ti-scale");
    this.#currentPointerPath = resolve(options.currentPointerPath ?? "/opt/ti-scale-server-releases/current");
    this.#staticPointerPath = resolve(options.staticPointerPath ?? "/var/lib/ti-scale/static-releases/state/active.json");
    this.#receiptRoot = resolve(options.receiptRoot ?? "/var/backups/ti-scale/release-backup-prunes");
    this.#quarantineRoot = resolve(options.quarantineRoot ?? "/var/backups/ti-scale/release-backup-prune-quarantine");
    this.#clock = options.clock ?? (() => new Date());
    this.#uid = options.uid ?? (() => process.getuid?.() ?? -1);
    this.#openReferenceScanner = options.openReferenceScanner ?? defaultOpenReferenceScanner;
    /* c8 ignore stop */
  }

  async preview(): Promise<FunctionalReleaseBackupPrunePreview> {
    const backupRoot = realDirectory(this.#backupRoot, "Functional release backup root");
    const serverReleaseRoot = realDirectory(this.#serverReleaseRoot, "Server release root");
    const application = lstatSync(this.#applicationPath);
    if (!application.isSymbolicLink()) throw new Error("Active application path must be a symbolic link");
    const activeApplicationTarget = realpathSync(this.#applicationPath);
    const activeApplicationReleaseId = releaseIdFromPath(
      serverReleaseRoot,
      activeApplicationTarget,
      "Active application target",
    );
    realDirectory(activeApplicationTarget, "Active application release");

    let currentPointerReleaseId: string | null = null;
    if (existsSync(this.#currentPointerPath)) {
      if (!lstatSync(this.#currentPointerPath).isSymbolicLink()) {
        throw new Error("Current release pointer must be a symbolic link when present");
      }
      const target = realpathSync(this.#currentPointerPath);
      currentPointerReleaseId = releaseIdFromPath(serverReleaseRoot, target, "Current release pointer");
      realDirectory(target, "Current pointer release");
    }

    const staticPointer = parseStaticPointer(
      boundedJson(this.#staticPointerPath, "Active static release pointer"),
      "Active static release pointer",
    );
    for (const releaseId of [staticPointer.activeReleaseId, staticPointer.previousReleaseId]) {
      realDirectory(join(serverReleaseRoot, releaseId), `Static pointer release ${releaseId}`);
    }
    if (staticPointer.activeReleaseId !== activeApplicationReleaseId) {
      throw new Error("Active static and server release identities differ");
    }

    const activeReceiptPath = join(backupRoot, activeApplicationReleaseId, "deployment-receipt.json");
    const activeReceipt = asReceipt(
      boundedJson(activeReceiptPath, "Active deployment receipt"),
      activeApplicationReleaseId,
    );
    const activePreviousReleaseId = releaseIdFromPath(
      serverReleaseRoot,
      activeReceipt.previous.applicationTarget,
      "Active receipt previous application target",
    );
    if (activePreviousReleaseId !== staticPointer.previousReleaseId) {
      throw new Error("Active receipt and static pointer disagree on the previous release");
    }

    const protectedReleaseIds = [...new Set([
      ...FUNCTIONAL_RELEASE_BACKUP_PRUNE_PROTECTED.map((value) => safeReleaseId(value, "Protected release")),
      activeApplicationReleaseId,
      activePreviousReleaseId,
      staticPointer.activeReleaseId,
      staticPointer.previousReleaseId,
      ...(currentPointerReleaseId ? [currentPointerReleaseId] : []),
    ])].sort((left, right) => left.localeCompare(right, "en"));
    for (const releaseId of FUNCTIONAL_RELEASE_BACKUP_PRUNE_PROTECTED) {
      realDirectory(join(serverReleaseRoot, releaseId), `Protected server release ${releaseId}`);
    }

    const allocation = new Map<string, AllocationEntry>();
    const targets: FunctionalReleaseBackupPruneTarget[] = [];
    const excludedBundles: FunctionalReleaseBackupPrunePreview["excludedBundles"][number][] = [];
    const bundleIds = readdirSync(backupRoot).sort((left, right) => left.localeCompare(right, "en"));
    for (const rawReleaseId of bundleIds) {
      const releaseId = safeReleaseId(rawReleaseId, "Backup bundle");
      const backupPath = realDirectory(
        exactChild(backupRoot, join(backupRoot, releaseId), `Backup bundle ${releaseId}`),
        `Backup bundle ${releaseId}`,
      );
      if (protectedReleaseIds.includes(releaseId)) {
        excludedBundles.push({ releaseId, reason: "protected" });
        continue;
      }
      const serverPath = join(serverReleaseRoot, releaseId);
      if (existsSync(serverPath)) {
        realDirectory(serverPath, `Existing server release ${releaseId}`);
        excludedBundles.push({ releaseId, reason: "server_release_present" });
        continue;
      }

      exactNames(backupPath, ROOT_PAYLOADS, `Backup bundle ${releaseId}`);
      const databaseDirectory = realDirectory(join(backupPath, "database"), `Database payload ${releaseId}`);
      exactNames(databaseDirectory, DATABASE_PAYLOADS, `Database payload ${releaseId}`);
      const receiptPath = regularFile(join(backupPath, "deployment-receipt.json"), `Deployment receipt ${releaseId}`, MAX_JSON_BYTES);
      const receipt = asReceipt(boundedJson(receiptPath, `Deployment receipt ${releaseId}`), releaseId);
      const expectedServerPath = join(serverReleaseRoot, releaseId);
      assertExactFile(receipt.serverRelease.path, expectedServerPath, `Receipt server release ${releaseId}`);
      assertExactFile(receipt.backup.root, backupPath, `Receipt backup root ${releaseId}`);
      assertExactFile(receipt.backup.database, join(backupPath, "database/pre-release.sqlite"), `Receipt database ${releaseId}`);
      assertExactFile(receipt.backup.onlinePreflightDatabase, join(backupPath, "database/online-preflight.sqlite"), `Receipt online database ${releaseId}`);
      assertExactFile(receipt.backup.sourceArchive, join(backupPath, "server-source.tar.gz"), `Receipt source archive ${releaseId}`);
      assertExactFile(receipt.backup.vaultArchive, join(backupPath, "vault.tar.gz"), `Receipt Vault archive ${releaseId}`);
      assertExactFile(receipt.backup.staticPointer, join(backupPath, "static-pointer.json"), `Receipt static pointer ${releaseId}`);
      assertExactFile(receipt.backup.metadata, join(backupPath, "backup-metadata.json"), `Receipt metadata ${releaseId}`);

      const checksumPath = regularFile(join(backupPath, "SHA256SUMS"), `Checksum manifest ${releaseId}`, MAX_JSON_BYTES);
      const checksumManifestSha256 = await sha256File(checksumPath);
      if (checksumManifestSha256 !== receipt.backup.checksumManifestSha256) {
        throw new Error(`Checksum manifest identity differs from the receipt for ${releaseId}`);
      }
      const checksums = await verifyChecksumManifest(backupPath);
      const checksumNames = Object.keys(checksums).sort((left, right) => left.localeCompare(right, "en"));
      const expectedChecksumNames = [...CHECKSUM_PATHS].sort((left, right) => left.localeCompare(right, "en"));
      if (JSON.stringify(checksumNames) !== JSON.stringify(expectedChecksumNames)) {
        throw new Error(`Checksum manifest payload set is not canonical for ${releaseId}`);
      }
      if (
        checksums["database/pre-release.sqlite"] !== receipt.backup.databaseSha256 ||
        checksums["database/online-preflight.sqlite"] !== receipt.backup.onlinePreflightDatabaseSha256
      ) throw new Error(`Database checksum identity differs from the receipt for ${releaseId}`);

      const metadataPath = regularFile(join(backupPath, "backup-metadata.json"), `Backup metadata ${releaseId}`, MAX_JSON_BYTES);
      const metadata = asMetadata(boundedJson(metadataPath, `Backup metadata ${releaseId}`), releaseId);
      const backupMetadataSha256 = await sha256File(metadataPath);
      if (checksums["backup-metadata.json"] !== backupMetadataSha256) {
        throw new Error(`Backup metadata is not checksum-bound for ${releaseId}`);
      }
      if (
        metadata.database.path !== "database/pre-release.sqlite" ||
        metadata.database.sha256 !== receipt.backup.databaseSha256 ||
        metadata.database.schema !== receipt.database.sourceSchema || metadata.database.quiesced !== true ||
        metadata.database.ownerUid !== receipt.database.ownerUid || metadata.database.ownerGid !== receipt.database.ownerGid ||
        metadata.onlinePreflightDatabase.path !== "database/online-preflight.sqlite" ||
        metadata.onlinePreflightDatabase.sha256 !== receipt.backup.onlinePreflightDatabaseSha256 ||
        metadata.source.path !== "server-source.tar.gz" ||
        metadata.source.livePath !== (
          receipt.previous.applicationKind === "directory"
            ? this.#applicationPath
            : receipt.previous.applicationTarget
        ) ||
        metadata.rollbackServerTarget !== receipt.previous.applicationTarget ||
        metadata.serverRelease.path !== expectedServerPath ||
        metadata.serverRelease.manifestSha256 !== receipt.serverRelease.manifestSha256 ||
        metadata.vault.path !== "vault.tar.gz" || metadata.staticPointer.path !== "static-pointer.json" ||
        JSON.stringify(metadata.staticPointer.value) !== JSON.stringify(receipt.previous.staticPointer)
      ) throw new Error(`Checksum-bound metadata conflicts with the deployment receipt for ${releaseId}`);
      const pointer = parseStaticPointer(
        boundedJson(join(backupPath, "static-pointer.json"), `Static pointer backup ${releaseId}`),
        `Static pointer backup ${releaseId}`,
      );
      if (JSON.stringify(pointer) !== JSON.stringify(receipt.previous.staticPointer)) {
        throw new Error(`Static pointer backup conflicts with the deployment receipt for ${releaseId}`);
      }

      const tree = await payloadTreeHash(backupPath, checksums);
      const space = walkAllocation(backupPath, allocation);
      targets.push(Object.freeze({
        releaseId,
        backupPath,
        deploymentReceiptSha256: await sha256File(receiptPath),
        backupMetadataSha256,
        checksumManifestSha256,
        payloadTreeSha256: tree.treeHash,
        checksumEntriesVerified: checksumNames.length,
        migrationBackupSha256: tree.migrationBackupSha256,
        apparentBytes: space.apparent,
        allocatedBytes: space.allocated,
      }));
    }

    if (!targets.length) throw new Error("No eligible obsolete functional-release backup bundles were found");
    const references = this.#openReferenceScanner(targets.map((target) => target.backupPath));
    if (references.length) {
      throw new Error(`An eligible backup bundle is open by a process: ${references.slice(0, 5).join(", ")}`);
    }
    const minimumReclaimableBytes = [...allocation.values()]
      .filter((entry) => entry.occurrences >= entry.links)
      .reduce((sum, entry) => sum + entry.blocks, 0);
    const unsigned = {
      schemaVersion: "ti-scale.functional-release-backup-prune-preview.v1" as const,
      planId: FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID,
      backupRoot,
      serverReleaseRoot,
      activeApplicationReleaseId,
      currentPointerReleaseId,
      activeStaticReleaseId: staticPointer.activeReleaseId,
      previousStaticReleaseId: staticPointer.previousReleaseId,
      protectedReleaseIds: Object.freeze(protectedReleaseIds),
      excludedBundles: Object.freeze(excludedBundles),
      targets: Object.freeze(targets),
      targetCount: targets.length,
      totalApparentBytes: targets.reduce((sum, target) => sum + target.apparentBytes, 0),
      totalAllocatedBytes: targets.reduce((sum, target) => sum + target.allocatedBytes, 0),
      minimumReclaimableBytes,
    } as const;
    return Object.freeze({
      ...unsigned,
      previewHash: sha256(canonicalJson(unsigned as unknown as JsonValue)),
    });
  }

  async execute(input: {
    readonly expectedPreviewHash: string;
    readonly confirmation: string;
    readonly actorId: string;
    readonly reason: string;
    readonly acknowledgePermanentDeletion: boolean;
  }): Promise<FunctionalReleaseBackupPruneResult> {
    if (this.#uid() !== 0) throw new Error("Functional-release backup pruning requires root");
    if (input.confirmation !== FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID) {
      throw new Error(`Confirmation must exactly match ${FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID}`);
    }
    if (!input.acknowledgePermanentDeletion) {
      throw new Error(`${FUNCTIONAL_RELEASE_BACKUP_PRUNE_ACKNOWLEDGEMENT} is required`);
    }
    if (!SHA256.test(input.expectedPreviewHash)) throw new Error("Expected preview hash must be a lowercase SHA-256");
    const actorId = safeActor(input.actorId);
    const reason = boundedReason(input.reason);
    const preview = await this.preview();
    if (preview.previewHash !== input.expectedPreviewHash) {
      throw new Error("Backup prune preview changed; review a fresh preview before execution");
    }
    const receiptPath = join(this.#receiptRoot, `${FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID}.json`);
    if (existsSync(receiptPath)) throw new Error("Backup prune receipt already exists; repeat execution is refused");
    const quarantine = join(this.#quarantineRoot, FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID);
    if (existsSync(quarantine)) throw new Error("Backup prune quarantine already exists; manual reconciliation is required");
    mkdirSync(quarantine, { recursive: true, mode: 0o700 });
    if (statSync(quarantine).dev !== statSync(this.#backupRoot).dev) {
      throw new Error("Backup quarantine must be on the same filesystem as the backup root");
    }

    const started = eventRecord(null, {
      sequence: 1,
      action: "prune_started",
      occurredAt: this.#clock().toISOString(),
      actorId,
      reason,
      previewHash: preview.previewHash,
    });
    const receipt: Record<string, unknown> & {
      status: "executing" | "completed" | "failed";
      events: ReceiptEvent[];
      deletedReleaseIds: string[];
      receiptHash: string;
    } = {
      schemaVersion: "ti-scale.functional-release-backup-prune-receipt.v1",
      planId: FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID,
      status: "executing",
      actorId,
      reason,
      preview,
      events: [started],
      deletedReleaseIds: [],
      receiptHash: "",
    };
    receipt.receiptHash = receiptHash(receipt);
    writeJsonAtomically(receiptPath, receipt);

    try {
      for (const target of preview.targets) {
        const quarantinePath = join(quarantine, target.releaseId);
        renameSync(target.backupPath, quarantinePath);
        fsyncDirectory(this.#backupRoot);
        rmSync(quarantinePath, { recursive: true, force: false });
        receipt.deletedReleaseIds.push(target.releaseId);
        const event = eventRecord(receipt.events.at(-1)!.recordHash, {
          sequence: receipt.events.length + 1,
          action: "backup_deleted",
          occurredAt: this.#clock().toISOString(),
          releaseId: target.releaseId,
        });
        receipt.events.push(event);
        receipt.receiptHash = receiptHash(receipt);
        writeJsonAtomically(receiptPath, receipt);
      }
      rmSync(quarantine, { recursive: true, force: false });
      receipt.status = "completed";
      receipt.events.push(eventRecord(receipt.events.at(-1)!.recordHash, {
        sequence: receipt.events.length + 1,
        action: "prune_completed",
        occurredAt: this.#clock().toISOString(),
      }));
      receipt.receiptHash = receiptHash(receipt);
      writeJsonAtomically(receiptPath, receipt);
      return Object.freeze({
        status: "completed" as const,
        planId: FUNCTIONAL_RELEASE_BACKUP_PRUNE_PLAN_ID,
        previewHash: preview.previewHash,
        deletedReleaseIds: Object.freeze([...receipt.deletedReleaseIds]),
        minimumReclaimableBytes: preview.minimumReclaimableBytes,
        receiptPath,
        receiptHash: receipt.receiptHash,
      });
    } catch (error) {
      receipt.status = "failed";
      receipt.events.push(eventRecord(receipt.events.at(-1)!.recordHash, {
        sequence: receipt.events.length + 1,
        action: "prune_failed",
        occurredAt: this.#clock().toISOString(),
        error: error instanceof Error ? error.message.slice(0, 1_000) : "unknown error",
      }));
      receipt.receiptHash = receiptHash(receipt);
      writeJsonAtomically(receiptPath, receipt);
      throw error;
    }
  }
}

interface CliArguments {
  readonly command: "preview" | "execute";
  readonly values: ReadonlyMap<string, string>;
  readonly acknowledgement: boolean;
}

export function parseFunctionalReleaseBackupPruneArguments(argv: readonly string[]): CliArguments {
  const [command, ...rest] = argv;
  if (command !== "preview" && command !== "execute") throw new Error("Command must be preview or execute");
  const values = new Map<string, string>();
  let acknowledgement = false;
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (token === FUNCTIONAL_RELEASE_BACKUP_PRUNE_ACKNOWLEDGEMENT) {
      if (acknowledgement) throw new Error(`Duplicate flag: ${token}`);
      acknowledgement = true;
      continue;
    }
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) throw new Error(`${token} requires a value`);
    if (values.has(token)) throw new Error(`Duplicate option: ${token}`);
    values.set(token, next);
    index += 1;
  }
  const allowed = command === "preview"
    ? new Set<string>()
    : new Set(["--expected-preview-hash", "--confirm", "--actor", "--reason"]);
  for (const key of values.keys()) if (!allowed.has(key)) throw new Error(`Unsupported ${command} option: ${key}`);
  if (command === "preview" && acknowledgement) throw new Error("Deletion acknowledgement is valid only for execute");
  if (command === "execute") {
    for (const key of allowed) if (!values.get(key)?.trim()) throw new Error(`${key} is required`);
    if (!acknowledgement) throw new Error(`${FUNCTIONAL_RELEASE_BACKUP_PRUNE_ACKNOWLEDGEMENT} is required`);
  }
  return { command, values, acknowledgement };
}

async function main(argv = process.argv.slice(2)): Promise<number> {
  const args = parseFunctionalReleaseBackupPruneArguments(argv);
  const service = new FunctionalReleaseBackupPruneService();
  const result = args.command === "preview"
    ? await service.preview()
    : await withSharedReleaseLock(
        () => service.execute({
          expectedPreviewHash: args.values.get("--expected-preview-hash")!,
          confirmation: args.values.get("--confirm")!,
          actorId: args.values.get("--actor")!,
          reason: args.values.get("--reason")!,
          acknowledgePermanentDeletion: args.acknowledgement,
        }),
        { operation: "functional-release-backup-prune" },
      );
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return 0;
}

if (import.meta.main) {
  process.stderr.write(
    "Legacy backup-bundle maintenance is disabled by the operator no-backup policy\n",
  );
  process.exitCode = 1;
}

import { createHash } from "node:crypto";
import {
  chmodSync,
  createReadStream,
  existsSync,
  fstatSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
  closeSync,
  fsyncSync,
  constants,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { createDatabaseConnection } from "../../server/db/connection";
import {
  writeDurableFileAtomically,
  type DurableAtomicWritePhase,
} from "./DurableAtomicFile";
import {
  runBoundedReleaseCommand,
  runBoundedReleaseCommandSync,
} from "./BoundedReleaseCommand";

export const SERVER_RELEASE_MANIFEST = "server-release-manifest.json";
export const BACKUP_CHECKSUM_MANIFEST = "SHA256SUMS";
export const RELEASE_DATA_FINGERPRINT_POLICY =
  "release_data_excluding_runtime_projection_telemetry_lease_fence_and_classified_startup_readiness_rows_v4" as const;

/**
 * Whole-table row content excluded by the v4 rollback-data drift proof.
 *
 * The first two tables are process-lifetime coordination state. The remaining
 * four are wholly materialized by RuntimeProjectionService from the currently
 * attested runtime generation and therefore change during every healthy
 * process start. Only their rows are excluded: databaseFingerprint still
 * hashes every table, index, trigger, and view definition, so schema and guard
 * drift remain release-significant. Every table not named here is included by
 * default.
 */
export const RELEASE_DATA_FINGERPRINT_ROW_EXCLUDED_TABLES = Object.freeze([
  "canonical_database_lease_fence",
  "canonical_database_leases",
  "agents",
  "agent_capabilities",
  "health_snapshots",
  "mcp_servers",
] as const);

/**
 * Narrow row-level exclusions for content-free startup readiness audit.
 *
 * The classification is protected by migration-owned constraints and
 * immutable lineage triggers. Ordinary provider turns, Context Packs, and
 * exposure receipts retain `canonical` and remain release-significant.
 */
export const RELEASE_DATA_FINGERPRINT_ROW_CLASS_EXCLUSIONS = Object.freeze({
  provider_turns: "startup_readiness",
  memory_context_packs: "startup_readiness",
  provider_exposure_receipts: "startup_readiness",
} as const);

export const EXCLUDED_SERVER_SOURCE_ENTRIES = Object.freeze([
  ".artifacts",
  ".git",
  ".vite",
  "coverage",
  "playwright-report",
  "test-results",
] as const);

const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const CLOSE_ON_EXEC = (constants as unknown as Readonly<Record<string, number>>).O_CLOEXEC ?? 0;
const RELEASE_COPY_TIMEOUT_MS = 10 * 60 * 1_000;
const RELEASE_EXCHANGE_TIMEOUT_MS = 30_000;
const RELEASE_COMMAND_OUTPUT_LIMIT_BYTES = 256 * 1_024;
const FINGERPRINT_GC_ROW_INTERVAL = 32_768;

export interface ServerReleaseManifestEntry {
  readonly path: string;
  readonly kind: "file" | "symlink";
  readonly bytes: number;
  readonly executable: boolean;
  readonly sha256: string;
  readonly linkTarget?: string;
}

export interface ServerReleaseManifest {
  readonly schemaVersion: "ti-scale.server-release-manifest.v1";
  readonly releaseId: string;
  readonly createdAt: string;
  readonly entryCount: number;
  readonly totalBytes: number;
  readonly treeSha256: string;
  readonly excludedSourceEntries: readonly string[];
  readonly entries: readonly ServerReleaseManifestEntry[];
}

export interface VerifiedServerRelease {
  readonly releaseId: string;
  readonly releaseDirectory: string;
  readonly manifestPath: string;
  readonly manifestSha256: string;
  readonly manifest: ServerReleaseManifest;
}

export interface ServerReleaseSourceFingerprint {
  readonly treeSha256: string;
  readonly entryCount: number;
  readonly totalBytes: number;
}

export type ServerReleaseStagingPhase =
  | "release_layout_synced"
  | "regular_files_synced"
  | "nested_directories_synced"
  | "staging_directory_synced"
  | "renamed"
  | "promoted_directory_synced"
  | "release_root_synced";

export interface StageServerReleaseInput {
  readonly sourceRoot: string;
  readonly releaseRoot: string;
  readonly releaseId: string;
  readonly createdAt?: string;
  readonly onPhase?: (phase: ServerReleaseStagingPhase) => void;
}

export interface ApplicationTargetSwap {
  readonly activeTarget: string;
  readonly previousTarget: string;
  readonly previousKind: "directory" | "symlink";
}

export type ApplicationTargetSwapPhase =
  | "prepared_swap_directory_synced"
  | "exchanged"
  | "exchange_directory_synced"
  | "displaced_finalized"
  | "displaced_parent_synced";

export interface ActiveV2Work {
  readonly activeRuns: readonly { readonly id: string; readonly status: string }[];
  readonly activeLeases: readonly { readonly runId: string; readonly expiresAt: string }[];
  /**
   * Inconsistent terminal records that still require an audited data repair,
   * but cannot own live write authority because their parent operation is
   * durably terminal. They remain visible without impersonating active work.
   */
  readonly reconciliationRequired: readonly {
    readonly kind: "legacy_migration_source";
    readonly id: string;
    readonly status: "reconciliation_required";
    readonly sourceStatus: "importing";
    readonly parentMigrationId: string;
    readonly parentStatus: "failed";
  }[];
  /**
   * Durable execution records whose owners may live outside ti-scale.service.
   * These must be empty before the service stop can be treated as a quiesced
   * database boundary.
   */
  readonly activeDatabaseWriters: readonly {
    readonly kind:
      | "attack_knowledge_batch_run"
      | "attack_knowledge_compiler_run"
      | "canonical_database_writer"
      | "experiment"
      | "experiment_run"
      | "event_outbox"
      | "historical_confirmation"
      | "historical_hazard_import_job"
      | "legacy_migration_run"
      | "legacy_migration_source"
      | "legacy_vault_projection"
      | "operational_hazard_observation_job"
      | "runtime_continuation";
    readonly id: string;
    readonly status: string;
    readonly leaseExpiresAt: string | null;
  }[];
}

function containedBy(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" || (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`));
}

function realDirectoryRoot(rootValue: string, label: string): string {
  const root = resolve(rootValue);
  const metadata = lstatSync(root);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(root) !== root) {
    throw new Error(`${label} must be a real directory without symbolic-link traversal`);
  }
  return root;
}

function realRegularFileWithin(root: string, relativePath: string, label: string): string {
  const absolute = resolve(root, ...safeRelativePath(relativePath).split("/"));
  if (!containedBy(root, absolute)) throw new Error(`${label}: ${relativePath}`);
  const metadata = lstatSync(absolute);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(absolute) !== absolute) {
    throw new Error(`${label}: ${relativePath}`);
  }
  return absolute;
}

function safeReleaseId(value: string): string {
  if (!RELEASE_ID.test(value) || value === "." || value === "..") {
    throw new Error("Release ID must contain only letters, numbers, dot, underscore, and dash");
  }
  return value;
}

function safeRelativePath(value: string): string {
  if (
    !value || value.includes("\0") || value.includes("\\") || value.startsWith("/") ||
    value.split("/").some((segment) => !segment || segment === "." || segment === "..")
  ) {
    throw new Error(`Unsafe release-relative path: ${value}`);
  }
  return value;
}

function normalizedRelative(root: string, path: string): string {
  return relative(root, path).split(sep).join("/");
}

export async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  await new Promise<void>((resolveStream, rejectStream) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.once("error", rejectStream);
    stream.once("end", resolveStream);
  });
  return hash.digest("hex");
}

function digest(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function entriesDigest(entries: readonly ServerReleaseManifestEntry[]): string {
  return digest(entries.map((entry) => [
    entry.kind,
    entry.path,
    String(entry.bytes),
    entry.executable ? "x" : "-",
    entry.sha256,
    entry.linkTarget ?? "",
  ].join("\0")).join("\n"));
}

/**
 * Stable identity for the complete application tree at a recorded target.
 * Unlike a path or inode alone this detects in-place modification of a
 * retained rollback target. The server manifest itself is included when
 * present, binding both its claims and every tree byte/relative symlink.
 */
export async function canonicalApplicationTreeFingerprint(rootValue: string): Promise<string> {
  const entries = await scanTree(resolve(rootValue), { source: false, excludeManifest: false });
  return entriesDigest(entries);
}

export async function assertApplicationTreeFingerprint(
  rootValue: string,
  expectedSha256: string,
): Promise<void> {
  if (!SHA256.test(expectedSha256)) throw new Error("Recorded application tree checksum is invalid");
  if (await canonicalApplicationTreeFingerprint(rootValue) !== expectedSha256) {
    throw new Error("Application tree content does not match its checksum-bound identity");
  }
}

function rootSourceEntryExcluded(name: string): boolean {
  if ((EXCLUDED_SERVER_SOURCE_ENTRIES as readonly string[]).includes(name)) return true;
  if (name === ".env" || (name.startsWith(".env.") && name !== ".env.example")) return true;
  if (name === "core" || name.startsWith("core.")) return true;
  return /\.(?:log|sqlite|sqlite-shm|sqlite-wal)$/u.test(name);
}

async function scanTree(
  rootValue: string,
  options: { readonly source: boolean; readonly excludeManifest: boolean },
): Promise<readonly ServerReleaseManifestEntry[]> {
  const root = resolve(rootValue);
  const rootMetadata = lstatSync(root);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error("Server release tree root must be a real directory");
  }
  const canonicalRoot = realpathSync(root);
  if (canonicalRoot !== root) throw new Error("Server release tree root must not traverse a symbolic link");
  const entries: ServerReleaseManifestEntry[] = [];

  const visit = async (directory: string, depth: number): Promise<void> => {
    for (const name of readdirSync(directory).sort((left, right) => left.localeCompare(right, "en"))) {
      if (depth === 0 && options.source && rootSourceEntryExcluded(name)) continue;
      const path = join(directory, name);
      const relativePath = safeRelativePath(normalizedRelative(root, path));
      if (depth === 0 && options.excludeManifest && relativePath === SERVER_RELEASE_MANIFEST) continue;
      const metadata = lstatSync(path);
      if (metadata.isDirectory()) {
        await visit(path, depth + 1);
        continue;
      }
      if (metadata.isSymbolicLink()) {
        const linkTarget = readlinkSync(path);
        if (isAbsolute(linkTarget)) {
          throw new Error(`Server release contains an absolute symbolic link: ${relativePath}`);
        }
        const resolvedTarget = resolve(dirname(path), linkTarget);
        if (!containedBy(root, resolvedTarget)) {
          throw new Error(`Server release symbolic link escapes its root: ${relativePath}`);
        }
        entries.push({
          path: relativePath,
          kind: "symlink",
          bytes: Buffer.byteLength(linkTarget),
          executable: false,
          sha256: digest(linkTarget),
          linkTarget,
        });
        continue;
      }
      if (!metadata.isFile()) {
        throw new Error(`Server release contains a special filesystem entry: ${relativePath}`);
      }
      entries.push({
        path: relativePath,
        kind: "file",
        bytes: metadata.size,
        executable: (metadata.mode & 0o111) !== 0,
        sha256: await sha256File(path),
      });
    }
  };

  await visit(root, 0);
  entries.sort((left, right) => left.path.localeCompare(right.path, "en"));
  return entries;
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | CLOSE_ON_EXEC | NO_FOLLOW,
  );
  try {
    if (!fstatSync(descriptor).isDirectory()) throw new Error(`Cannot fsync non-directory release path: ${path}`);
    fsyncSync(descriptor);
  }
  finally { closeSync(descriptor); }
}

/**
 * Creates a possibly absent directory chain and durably publishes every new
 * name into its parent. Syncing only the leaf is insufficient on first deploy:
 * a power loss may retain `releases/<id>` while losing the newly-created
 * release root itself from its existing ancestor.
 */
function ensureDirectoryChainDurably(pathValue: string, mode: number): string {
  const path = resolve(pathValue);
  const created: string[] = [];
  let existingAncestor = path;
  while (!existsSync(existingAncestor)) {
    created.push(existingAncestor);
    const parent = dirname(existingAncestor);
    if (parent === existingAncestor) throw new Error("Could not find an existing release-directory ancestor");
    existingAncestor = parent;
  }
  const ancestorMetadata = lstatSync(existingAncestor);
  if (
    !ancestorMetadata.isDirectory() || ancestorMetadata.isSymbolicLink() ||
    realpathSync(existingAncestor) !== existingAncestor
  ) throw new Error("Server release root must not traverse symbolic-link ancestry");

  mkdirSync(path, { recursive: true, mode });
  if (realDirectoryRoot(path, "Server release directory") !== path) {
    throw new Error("Server release directory is not canonical");
  }
  // `created` is deepest-first. Sync each child before its parent so every
  // directory entry is stable before the entry naming its parent is committed.
  for (const directory of created) fsyncDirectory(directory);
  if (created.length) fsyncDirectory(existingAncestor);
  return path;
}

function fsyncRegularFile(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | CLOSE_ON_EXEC | NO_FOLLOW);
  try {
    if (!fstatSync(descriptor).isFile()) throw new Error(`Cannot fsync non-file release path: ${path}`);
    fsyncSync(descriptor);
  }
  finally { closeSync(descriptor); }
}

function fsyncServerReleaseTree(
  rootValue: string,
  onPhase?: (phase: ServerReleaseStagingPhase) => void,
): void {
  const root = resolve(rootValue);
  const rootMetadata = lstatSync(root);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink() || realpathSync(root) !== root) {
    throw new Error("Staged server release root must be a real directory without symbolic-link traversal");
  }
  const files: string[] = [];
  const directories: string[] = [];
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory).sort((left, right) => left.localeCompare(right, "en"))) {
      const path = join(directory, name);
      const relativePath = safeRelativePath(normalizedRelative(root, path));
      const metadata = lstatSync(path);
      if (metadata.isDirectory()) {
        visit(path);
        directories.push(path);
      } else if (metadata.isFile()) {
        files.push(path);
      } else if (metadata.isSymbolicLink()) {
        const linkTarget = readlinkSync(path);
        if (isAbsolute(linkTarget) || !containedBy(root, resolve(dirname(path), linkTarget))) {
          throw new Error(`Staged server release symbolic link escapes its root: ${relativePath}`);
        }
      } else {
        throw new Error(`Staged server release contains a special filesystem entry: ${relativePath}`);
      }
    }
  };
  visit(root);

  // File data and metadata must reach stable storage before any directory entry
  // that makes those bytes reachable is declared durable.
  for (const path of files) fsyncRegularFile(path);
  onPhase?.("regular_files_synced");
  // Post-order traversal makes each child directory durable before its parent.
  for (const path of directories) fsyncDirectory(path);
  onPhase?.("nested_directories_synced");
  fsyncDirectory(root);
  onPhase?.("staging_directory_synced");
}

function makeTreeReadOnly(root: string): void {
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      const metadata = lstatSync(path);
      if (metadata.isDirectory()) {
        visit(path);
        chmodSync(path, 0o555);
      } else if (metadata.isFile()) {
        chmodSync(path, (metadata.mode & 0o111) !== 0 ? 0o555 : 0o444);
      } else if (!metadata.isSymbolicLink()) {
        throw new Error(`Cannot make special release entry immutable: ${path}`);
      }
    }
  };
  visit(root);
  chmodSync(root, 0o555);
}

function parseManifest(value: unknown, expectedReleaseId: string): ServerReleaseManifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Server release manifest must be an object");
  const raw = value as Record<string, unknown>;
  if (
    raw.schemaVersion !== "ti-scale.server-release-manifest.v1" || raw.releaseId !== expectedReleaseId ||
    typeof raw.createdAt !== "string" || !Number.isFinite(Date.parse(raw.createdAt)) ||
    !Number.isSafeInteger(raw.entryCount) || (raw.entryCount as number) < 1 ||
    !Number.isSafeInteger(raw.totalBytes) || (raw.totalBytes as number) < 0 ||
    typeof raw.treeSha256 !== "string" || !SHA256.test(raw.treeSha256) || !Array.isArray(raw.entries) ||
    !Array.isArray(raw.excludedSourceEntries)
  ) throw new Error("Server release manifest metadata is invalid");

  const entries = raw.entries.map((value): ServerReleaseManifestEntry => {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid server release manifest entry");
    const entry = value as Record<string, unknown>;
    if (
      (entry.kind !== "file" && entry.kind !== "symlink") || typeof entry.path !== "string" ||
      !Number.isSafeInteger(entry.bytes) || (entry.bytes as number) < 0 || typeof entry.executable !== "boolean" ||
      typeof entry.sha256 !== "string" || !SHA256.test(entry.sha256) ||
      (entry.linkTarget !== undefined && typeof entry.linkTarget !== "string")
    ) throw new Error("Invalid server release manifest entry metadata");
    return {
      path: safeRelativePath(entry.path),
      kind: entry.kind,
      bytes: entry.bytes as number,
      executable: entry.executable,
      sha256: entry.sha256,
      ...(typeof entry.linkTarget === "string" ? { linkTarget: entry.linkTarget } : {}),
    };
  });
  const sorted = [...entries].sort((left, right) => left.path.localeCompare(right.path, "en"));
  if (new Set(entries.map((entry) => entry.path)).size !== entries.length || JSON.stringify(entries) !== JSON.stringify(sorted)) {
    throw new Error("Server release manifest entries must be unique and sorted");
  }
  if (
    raw.entryCount !== entries.length ||
    raw.totalBytes !== entries.reduce((total, entry) => total + entry.bytes, 0) ||
    raw.treeSha256 !== entriesDigest(entries)
  ) throw new Error("Server release manifest aggregate digest is invalid");
  return {
    schemaVersion: "ti-scale.server-release-manifest.v1",
    releaseId: expectedReleaseId,
    createdAt: raw.createdAt,
    entryCount: entries.length,
    totalBytes: raw.totalBytes as number,
    treeSha256: raw.treeSha256,
    excludedSourceEntries: (raw.excludedSourceEntries as unknown[]).map(String),
    entries,
  };
}

export async function verifyServerRelease(
  releaseDirectoryValue: string,
  expectedReleaseId: string,
  expectedManifestSha256?: string,
): Promise<VerifiedServerRelease> {
  const releaseId = safeReleaseId(expectedReleaseId);
  const releaseDirectory = resolve(releaseDirectoryValue);
  const manifestPath = join(releaseDirectory, SERVER_RELEASE_MANIFEST);
  const manifestBytes = readFileSync(manifestPath);
  const manifestSha256 = digest(manifestBytes);
  if (expectedManifestSha256 && manifestSha256 !== expectedManifestSha256) {
    throw new Error("Server release manifest checksum does not match the recorded value");
  }
  const manifest = parseManifest(JSON.parse(manifestBytes.toString("utf8")) as unknown, releaseId);
  const actual = await scanTree(releaseDirectory, { source: false, excludeManifest: true });
  if (JSON.stringify(actual) !== JSON.stringify(manifest.entries)) {
    throw new Error("Server release tree does not match its immutable manifest");
  }
  return { releaseId, releaseDirectory, manifestPath, manifestSha256, manifest };
}

/**
 * Read-only identity for the exact tree that `stageServerRelease` would copy.
 *
 * This intentionally uses the same source exclusions and canonical entry
 * encoding as the immutable release manifest. Callers can therefore pin a
 * clean source tree before staging without creating a second source copy.
 */
export async function fingerprintServerReleaseSource(
  sourceRootValue: string,
): Promise<ServerReleaseSourceFingerprint> {
  const entries = await scanTree(resolve(sourceRootValue), {
    source: true,
    excludeManifest: true,
  });
  return {
    treeSha256: entriesDigest(entries),
    entryCount: entries.length,
    totalBytes: entries.reduce((total, entry) => total + entry.bytes, 0),
  };
}

export async function stageServerRelease(input: StageServerReleaseInput): Promise<VerifiedServerRelease> {
  const sourceRoot = resolve(input.sourceRoot);
  const releaseRoot = resolve(input.releaseRoot);
  const releaseId = safeReleaseId(input.releaseId);
  const releasesDirectory = join(releaseRoot, "releases");
  const destination = join(releasesDirectory, releaseId);
  if (existsSync(destination)) throw new Error(`Server release already exists: ${releaseId}`);
  ensureDirectoryChainDurably(releasesDirectory, 0o755);
  input.onPhase?.("release_layout_synced");
  const staging = join(releasesDirectory, `.stage-${releaseId}-${process.pid}-${Date.now()}`);
  mkdirSync(staging, { mode: 0o700 });
  try {
    const before = await scanTree(sourceRoot, { source: true, excludeManifest: true });
    if (!before.some((entry) => entry.path === "package.json") || !before.some((entry) => entry.path === "server/index.ts")) {
      throw new Error("Server source is missing package.json or server/index.ts");
    }
    const excludes = EXCLUDED_SERVER_SOURCE_ENTRIES.flatMap((name) => ["--exclude", `/${name}/`]);
    await runBoundedReleaseCommand([
      "/usr/local/bin/rsync", "-a", "--delete", "--numeric-ids",
      ...excludes,
      "--exclude", "/.env", "--include", "/.env.example", "--exclude", "/.env.*",
      "--exclude", `/${SERVER_RELEASE_MANIFEST}`, "--exclude", "/core", "--exclude", "/core.*",
      "--exclude", "/*.log", "--exclude", "/*.sqlite", "--exclude", "/*.sqlite-shm", "--exclude", "/*.sqlite-wal",
      `${sourceRoot}/`, `${staging}/`,
    ], {
      timeoutMs: RELEASE_COPY_TIMEOUT_MS,
      outputLimitBytes: RELEASE_COMMAND_OUTPUT_LIMIT_BYTES,
    });
    const afterSource = await scanTree(sourceRoot, { source: true, excludeManifest: true });
    const copied = await scanTree(staging, { source: false, excludeManifest: true });
    if (JSON.stringify(before) !== JSON.stringify(afterSource)) throw new Error("Server source changed while the release was staged");
    if (JSON.stringify(before) !== JSON.stringify(copied)) throw new Error("Staged server release differs from its source manifest");
    const manifest: ServerReleaseManifest = {
      schemaVersion: "ti-scale.server-release-manifest.v1",
      releaseId,
      createdAt: input.createdAt ?? new Date().toISOString(),
      entryCount: copied.length,
      totalBytes: copied.reduce((total, entry) => total + entry.bytes, 0),
      treeSha256: entriesDigest(copied),
      excludedSourceEntries: EXCLUDED_SERVER_SOURCE_ENTRIES,
      entries: copied,
    };
    writeFileSync(join(staging, SERVER_RELEASE_MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o444, flag: "wx" });
    makeTreeReadOnly(staging);
    fsyncServerReleaseTree(staging, input.onPhase);
    renameSync(staging, destination);
    input.onPhase?.("renamed");
    fsyncDirectory(destination);
    input.onPhase?.("promoted_directory_synced");
    fsyncDirectory(releasesDirectory);
    input.onPhase?.("release_root_synced");
    return await verifyServerRelease(destination, releaseId);
  } catch (error) {
    try { chmodSync(staging, 0o700); } catch { /* staging may already be promoted */ }
    rmSync(staging, { recursive: true, force: true });
    throw error;
  }
}

function resolvedSymlinkTarget(path: string): string {
  const target = readlinkSync(path);
  return resolve(dirname(path), target);
}

/**
 * Atomically exchanges /opt/ti-scale with a prepared symlink. GNU mv uses
 * renameat2(RENAME_EXCHANGE), so the active path is never a partial copy.
 */
export function exchangeApplicationTarget(input: {
  readonly applicationPath: string;
  readonly newTarget: string;
  readonly previousDirectoryArchive: string;
  readonly swapName: string;
  /** Test/audit hook; each phase is reported only after the named boundary. */
  readonly onPhase?: (phase: ApplicationTargetSwapPhase) => void;
}): ApplicationTargetSwap {
  const applicationPath = resolve(input.applicationPath);
  const newTarget = resolve(input.newTarget);
  const previousDirectoryArchive = resolve(input.previousDirectoryArchive);
  if (!lstatSync(newTarget).isDirectory()) throw new Error("New server release target is not a directory");
  const current = lstatSync(applicationPath);
  if (!current.isDirectory() && !current.isSymbolicLink()) throw new Error("Application path must be a directory or symbolic link");
  const applicationParent = dirname(applicationPath);
  const archiveParent = dirname(previousDirectoryArchive);
  const swapPath = join(applicationParent, `.${basename(applicationPath)}.${safeReleaseId(input.swapName)}.swap`);
  if (existsSync(swapPath)) throw new Error(`Application swap path already exists: ${swapPath}`);
  symlinkSync(newTarget, swapPath);
  fsyncDirectory(applicationParent);
  input.onPhase?.("prepared_swap_directory_synced");
  let exchanged = false;
  let previousSymlinkTarget: string | undefined;
  let displacedArchived = false;
  try {
    runBoundedReleaseCommandSync(
      ["/usr/bin/mv", "--exchange", "--no-copy", "--no-target-directory", "--", swapPath, applicationPath],
      {
        timeoutMs: RELEASE_EXCHANGE_TIMEOUT_MS,
        outputLimitBytes: RELEASE_COMMAND_OUTPUT_LIMIT_BYTES,
      },
    );
    exchanged = true;
    input.onPhase?.("exchanged");
    // renameat2 durability is established before any displaced entry is
    // removed or moved. A caller can therefore never journal a successful
    // activation whose directory exchange existed only in page cache.
    fsyncDirectory(applicationParent);
    input.onPhase?.("exchange_directory_synced");
    if (!lstatSync(applicationPath).isSymbolicLink() || realpathSync(applicationPath) !== realpathSync(newTarget)) {
      throw new Error("Atomic application swap did not activate the expected release target");
    }
    const previous = lstatSync(swapPath);
    if (previous.isSymbolicLink()) {
      const previousTarget = resolvedSymlinkTarget(swapPath);
      previousSymlinkTarget = previousTarget;
      unlinkSync(swapPath);
      input.onPhase?.("displaced_finalized");
      fsyncDirectory(applicationParent);
      input.onPhase?.("displaced_parent_synced");
      return { activeTarget: newTarget, previousTarget, previousKind: "symlink" };
    }
    if (!previous.isDirectory()) throw new Error("Atomic application swap produced an unsupported previous target");
    if (existsSync(previousDirectoryArchive)) throw new Error("Previous server archive path already exists");
    mkdirSync(archiveParent, { recursive: true, mode: 0o755 });
    fsyncDirectory(archiveParent);
    renameSync(swapPath, previousDirectoryArchive);
    displacedArchived = true;
    input.onPhase?.("displaced_finalized");
    fsyncDirectory(applicationParent);
    if (archiveParent !== applicationParent) fsyncDirectory(archiveParent);
    input.onPhase?.("displaced_parent_synced");
    makeTreeReadOnly(previousDirectoryArchive);
    return { activeTarget: newTarget, previousTarget: previousDirectoryArchive, previousKind: "directory" };
  } catch (error) {
    if (exchanged) {
      try {
        if (!existsSync(swapPath) && previousSymlinkTarget) {
          symlinkSync(previousSymlinkTarget, swapPath);
          fsyncDirectory(applicationParent);
        } else if (!existsSync(swapPath) && displacedArchived && existsSync(previousDirectoryArchive)) {
          renameSync(previousDirectoryArchive, swapPath);
          fsyncDirectory(archiveParent);
          if (archiveParent !== applicationParent) fsyncDirectory(applicationParent);
        }
        if (!existsSync(swapPath)) throw new Error("Displaced application target is unavailable for atomic rollback");
        runBoundedReleaseCommandSync(
          ["/usr/bin/mv", "--exchange", "--no-copy", "--no-target-directory", "--", swapPath, applicationPath],
          {
            timeoutMs: RELEASE_EXCHANGE_TIMEOUT_MS,
            outputLimitBytes: RELEASE_COMMAND_OUTPUT_LIMIT_BYTES,
          },
        );
        fsyncDirectory(applicationParent);
        exchanged = false;
      }
      catch { /* caller must use the recorded recovery path */ }
    }
    try {
      unlinkSync(swapPath);
      fsyncDirectory(applicationParent);
    } catch { /* swap path may be a directory after a failed exchange */ }
    throw error;
  }
}

export function queryActiveV2Work(databasePathValue: string): ActiveV2Work {
  const database = createDatabaseConnection({
    filename: resolve(databasePathValue),
    readonly: true,
    fileMustExist: true,
    // This is a metadata/work gate. Snapshot integrity is attested separately;
    // admission must not hide a multi-gigabyte quick_check.
    verifyIntegrity: false,
  });
  try {
    const activeRuns = database.prepare(`
      SELECT r.id, r.status
      FROM runs AS r
      JOIN missions AS m ON m.id = r.mission_id
      WHERE r.control_plane = 'ti_scale' AND m.control_plane = 'ti_scale'
        AND r.status IN (
          'queued', 'planning', 'awaiting_contract_confirmation', 'running',
          'waiting_guided_decision', 'recovering'
        )
      ORDER BY r.id
    `).all() as Array<{ id: string; status: string }>;
    const activeLeases = database.prepare(`
      SELECT lease.run_id AS runId, lease.expires_at AS expiresAt
      FROM control_plane_leases AS lease
      JOIN runs AS r ON r.id = lease.run_id
      JOIN missions AS m ON m.id = r.mission_id
      WHERE lease.control_plane = 'ti_scale' AND r.control_plane = 'ti_scale' AND m.control_plane = 'ti_scale'
        AND lease.released_at IS NULL AND datetime(lease.expires_at) > datetime('now')
      ORDER BY lease.run_id
    `).all() as Array<{ runId: string; expiresAt: string }>;
    const tableExists = (name: string): boolean => Boolean(database.prepare(`
      SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1
    `).get(name));
    type ActiveDatabaseWriter = ActiveV2Work["activeDatabaseWriters"][number];
    const activeDatabaseWriters: ActiveDatabaseWriter[] = [];
    const reconciliationRequired: ActiveV2Work["reconciliationRequired"][number][] = [];
    const collect = (
      table: string,
      kind: ActiveDatabaseWriter["kind"],
      sql: string,
    ): void => {
      if (!tableExists(table)) return;
      const rows = database.prepare(sql).all() as Array<{
        id: string;
        status: string;
        leaseExpiresAt: string | null;
      }>;
      activeDatabaseWriters.push(...rows.map((row) => ({ kind, ...row })));
    };

    collect("legacy_migration_runs", "legacy_migration_run", `
      SELECT id, status, NULL AS leaseExpiresAt
      FROM legacy_migration_runs WHERE status = 'running' ORDER BY id
    `);
    collect("canonical_database_leases", "canonical_database_writer", `
      SELECT id, operation AS status, expires_at AS leaseExpiresAt
      FROM canonical_database_leases
      WHERE mode = 'writer' AND released_at IS NULL
        AND operation <> 'standalone-service-runtime'
        AND datetime(expires_at) > datetime('now')
      ORDER BY id
    `);
    collect("legacy_migration_sources", "legacy_migration_source", `
      SELECT source.id, source.status, NULL AS leaseExpiresAt
      FROM legacy_migration_sources AS source
      JOIN legacy_migration_runs AS migration ON migration.id = source.migration_id
      WHERE source.status = 'importing'
        AND NOT (
          migration.status = 'failed'
          AND migration.completed_at IS NOT NULL
          AND length(trim(COALESCE(migration.error_summary, ''))) > 0
        )
      ORDER BY source.id
    `);
    if (tableExists("legacy_migration_sources") && tableExists("legacy_migration_runs")) {
      const terminalChildren = database.prepare(`
        SELECT source.id, source.status AS sourceStatus,
          migration.id AS parentMigrationId, migration.status AS parentStatus
        FROM legacy_migration_sources AS source
        JOIN legacy_migration_runs AS migration ON migration.id = source.migration_id
        WHERE source.status = 'importing'
          AND migration.status = 'failed'
          AND migration.completed_at IS NOT NULL
          AND length(trim(COALESCE(migration.error_summary, ''))) > 0
        ORDER BY source.id
      `).all() as Array<{
        id: string;
        sourceStatus: "importing";
        parentMigrationId: string;
        parentStatus: "failed";
      }>;
      reconciliationRequired.push(...terminalChildren.map((row) => ({
        kind: "legacy_migration_source" as const,
        id: row.id,
        status: "reconciliation_required" as const,
        sourceStatus: row.sourceStatus,
        parentMigrationId: row.parentMigrationId,
        parentStatus: row.parentStatus,
      })));
    }
    collect("historical_hazard_import_jobs", "historical_hazard_import_job", `
      SELECT id, status, NULL AS leaseExpiresAt
      FROM historical_hazard_import_jobs WHERE status = 'staging' ORDER BY id
    `);
    collect("attack_knowledge_compiler_runs", "attack_knowledge_compiler_run", `
      SELECT id, status, NULL AS leaseExpiresAt
      FROM attack_knowledge_compiler_runs WHERE status = 'compiling' ORDER BY id
    `);
    collect("historical_attack_knowledge_batch_runs", "attack_knowledge_batch_run", `
      SELECT id, status, NULL AS leaseExpiresAt
      FROM historical_attack_knowledge_batch_runs WHERE status = 'running' ORDER BY id
    `);
    collect("legacy_vault_projection_approvals", "legacy_vault_projection", `
      SELECT id, status, NULL AS leaseExpiresAt
      FROM legacy_vault_projection_approvals WHERE status = 'approved' ORDER BY id
    `);
    collect("experiment_runs", "experiment_run", `
      SELECT id, status, NULL AS leaseExpiresAt
      FROM experiment_runs WHERE status IN ('queued', 'running') ORDER BY id
    `);
    collect("experiments", "experiment", `
      SELECT id, status, NULL AS leaseExpiresAt
      FROM experiments WHERE status IN ('running', 'shadow_running', 'canary_running') ORDER BY id
    `);
    collect("runtime_continuations", "runtime_continuation", `
      SELECT id, status, lease_expires_at AS leaseExpiresAt
      FROM runtime_continuations
      WHERE status IN ('pending', 'processing')
      ORDER BY id
    `);
    collect("event_outbox", "event_outbox", `
      SELECT id, status, NULL AS leaseExpiresAt
      FROM event_outbox
      WHERE status IN ('pending', 'failed', 'delivering')
      ORDER BY id
    `);
    collect("operational_hazard_observation_jobs", "operational_hazard_observation_job", `
      SELECT event_id AS id, status, lease_expires_at AS leaseExpiresAt
      FROM operational_hazard_observation_jobs
      -- Startup synchronously reclaims expired processing work and may claim
      -- pending work before the reconciler verifies its journal-bound source
      -- fingerprint.  Treat every nonterminal job as release-significant: a
      -- pending job that is not due at admission can become due during service
      -- start, so filtering by available_at would leave a time-of-check gap.
      WHERE status IN ('pending', 'processing')
      ORDER BY event_id
    `);
    if (tableExists("settings")) {
      const confirmations = database.prepare(`
        SELECT key AS id,
          json_extract(value_json, '$.status') AS status,
          json_extract(value_json, '$.lease.expiresAt') AS leaseExpiresAt
        FROM settings
        WHERE key LIKE 'historical_attack_knowledge.confirm_all.%'
          AND json_valid(value_json)
          AND json_extract(value_json, '$.status') = 'in_progress'
          AND json_extract(value_json, '$.lease.owner') IS NOT NULL
          AND datetime(json_extract(value_json, '$.lease.expiresAt')) > datetime('now')
        ORDER BY key
      `).all() as Array<{ id: string; status: string; leaseExpiresAt: string | null }>;
      activeDatabaseWriters.push(...confirmations.map((row) => ({
        kind: "historical_confirmation" as const,
        ...row,
      })));
    }
    activeDatabaseWriters.sort((left, right) => (
      left.kind.localeCompare(right.kind, "en") || left.id.localeCompare(right.id, "en")
    ));
    return { activeRuns, activeLeases, activeDatabaseWriters, reconciliationRequired };
  } finally { database.close(); }
}

function canonicalSqlValue(value: unknown): unknown {
  if (typeof value === "bigint") return { bigint: value.toString() };
  if (value instanceof Uint8Array) return { blobSha256: digest(value), bytes: value.byteLength };
  return value;
}

/**
 * Preserve the v4 fingerprint's order-independent row-set semantics without
 * retaining an entire production table (and a second array of its digests) in
 * the JavaScript heap. The scratch SQLite index is private, file-backed, and
 * removed after every fingerprint. Its `(digest, ordinal)` ordering is exactly
 * equivalent to the previous `rowDigests.sort()` for hexadecimal SHA-256
 * values, while duplicate rows remain significant.
 */
function streamSortedTableRowDigests(
  database: ReturnType<typeof createDatabaseConnection>,
  scratch: ReturnType<typeof createDatabaseConnection>,
  query: string,
  parameters: readonly unknown[],
  consume: (rowDigest: string) => void,
): void {
  const finalize = (statement: unknown): void => {
    (statement as { readonly finalize?: () => void }).finalize?.();
  };
  scratch.exec("DELETE FROM row_digests");
  const insert = scratch.prepare(
    "INSERT INTO row_digests (digest, ordinal) VALUES (?, ?)",
  );
  const statement = database.prepare(query);
  let ordinal = 0;
  scratch.exec("BEGIN IMMEDIATE");
  try {
    try {
      for (const row of statement.iterate(...parameters) as IterableIterator<Record<string, unknown>>) {
        const rowDigest = digest(JSON.stringify(
          Object.fromEntries(Object.keys(row).sort().map((key) => [key, canonicalSqlValue(row[key])])),
        ));
        insert.run(rowDigest, ordinal);
        ordinal += 1;
        // Bun/JSC otherwise lets millions of short-lived SQLite row wrappers and
        // Hash objects grow the native heap into multi-gigabyte territory before
        // applying collection pressure. Release fingerprinting is offline control
        // work, so a deterministic bounded collection cadence is preferable.
        if (ordinal % FINGERPRINT_GC_ROW_INTERVAL === 0) Bun.gc(true);
      }
    } finally {
      finalize(statement);
    }
    scratch.exec("COMMIT");
  } catch (error) {
    if (scratch.inTransaction) scratch.exec("ROLLBACK");
    throw error;
  } finally {
    finalize(insert);
  }
  let sortedRows = 0;
  const sortedStatement = scratch.prepare(
    "SELECT digest FROM row_digests ORDER BY digest, ordinal",
  );
  try {
    for (const row of sortedStatement.iterate() as IterableIterator<{ readonly digest: string }>) {
      consume(row.digest);
      sortedRows += 1;
      if (sortedRows % FINGERPRINT_GC_ROW_INTERVAL === 0) Bun.gc(true);
    }
  } finally {
    finalize(sortedStatement);
  }
  if (sortedRows >= FINGERPRINT_GC_ROW_INTERVAL) Bun.gc(true);
}

function databaseFingerprint(
  databasePathValue: string,
  rowExcludedTables: ReadonlySet<string>,
  rowClassExclusions: Readonly<Record<string, string>> = {},
): string {
  const database = createDatabaseConnection({
    filename: resolve(databasePathValue),
    readonly: true,
    fileMustExist: true,
    // The release workflow independently integrity-checks each immutable
    // snapshot. A content fingerprint must not hide another full quick_check.
    verifyIntegrity: false,
  });
  let scratchRoot: string | undefined;
  let scratch: ReturnType<typeof createDatabaseConnection> | undefined;
  try {
    scratchRoot = mkdtempSync(join(tmpdir(), "ti-scale-release-fingerprint-"));
    chmodSync(scratchRoot, 0o700);
    scratch = createDatabaseConnection({
      filename: join(scratchRoot, "row-digests.sqlite"),
      busyTimeoutMs: 0,
      verifyIntegrity: false,
    });
    // This store is disposable. Bound both the page cache and SQLite's own
    // sorting memory; source data remains read-only and transactionally stable.
    scratch.pragma("journal_mode = DELETE");
    scratch.pragma("synchronous = OFF");
    scratch.pragma("temp_store = FILE");
    scratch.pragma("cache_size = -8192");
    scratch.pragma("mmap_size = 0");
    scratch.exec(`
      CREATE TABLE row_digests (
        digest TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        PRIMARY KEY (digest, ordinal)
      ) WITHOUT ROWID
    `);
    database.exec("BEGIN DEFERRED");
    const schemaObjects = database.prepare(`
      SELECT type, name, tbl_name AS tableName, COALESCE(sql, '') AS sql
      FROM sqlite_master
      WHERE type IN ('table', 'index', 'trigger', 'view')
        AND name NOT LIKE 'sqlite_%'
      ORDER BY type, name
    `).all() as Array<{ type: string; name: string; tableName: string; sql: string }>;
    const aggregate = createHash("sha256");
    for (const schemaObject of schemaObjects) {
      aggregate
        .update("schema\0")
        .update(schemaObject.type).update("\0")
        .update(schemaObject.name).update("\0")
        .update(schemaObject.tableName).update("\0")
        .update(schemaObject.sql).update("\n");
    }
    const tables = schemaObjects.filter((schemaObject) => schemaObject.type === "table");
    for (const table of tables) {
      const quoted = `"${table.name.replaceAll('"', '""')}"`;
      const excludedClass = Object.prototype.hasOwnProperty.call(rowClassExclusions, table.name)
        ? rowClassExclusions[table.name]
        : undefined;
      // A v4 deployment must fingerprint its schema-37 source before migration
      // 038 creates release_data_class. In that pre-migration state every row
      // is canonical, so hash all rows rather than referring to a column that
      // does not exist. The exact table schema is already included above.
      const supportsClassExclusion = excludedClass !== undefined && (
        database.prepare(`PRAGMA table_info(${quoted})`).all() as Array<{ name: string }>
      ).some((column) => column.name === "release_data_class");
      aggregate.update("rows\0").update(table.name).update("\0");
      if (!rowExcludedTables.has(table.name)) {
        streamSortedTableRowDigests(
          database,
          scratch,
          !supportsClassExclusion
            ? `SELECT * FROM ${quoted}`
            : `SELECT * FROM ${quoted} WHERE "release_data_class" IS NOT ?`,
          !supportsClassExclusion ? [] : [excludedClass],
          (rowDigest) => { aggregate.update(rowDigest).update("\n"); },
        );
      }
    }
    const result = aggregate.digest("hex");
    database.exec("COMMIT");
    return result;
  } catch (error) {
    if (database.inTransaction) database.exec("ROLLBACK");
    throw error;
  } finally {
    try { scratch?.close(); }
    finally {
      try { database.close(); }
      finally {
        if (scratchRoot) rmSync(scratchRoot, { recursive: true, force: true });
      }
    }
  }
}

/** Hashes every canonical row without writing or disclosing row values. */
export function canonicalDatabaseFingerprint(databasePathValue: string): string {
  return databaseFingerprint(databasePathValue, new Set());
}

/**
 * Rollback drift proof for durable operator and mission data. Process leases,
 * runtime projections, and health telemetry are deliberately excluded because
 * a normal service start re-materializes them. Their table schemas remain
 * hashed; active leases are independently prohibited by the maintenance gate.
 */
export function canonicalReleaseDataFingerprint(databasePathValue: string): string {
  return databaseFingerprint(
    databasePathValue,
    new Set(RELEASE_DATA_FINGERPRINT_ROW_EXCLUDED_TABLES),
    RELEASE_DATA_FINGERPRINT_ROW_CLASS_EXCLUSIONS,
  );
}

export type ChecksumManifestPublicationPhase =
  | `payload_synced:${string}`
  | "payload_directory_synced"
  | `manifest_${DurableAtomicWritePhase}`;

export interface ChecksumManifestPublicationOptions {
  /** Test/audit hook exposing the durability order without changing it. */
  readonly onPhase?: (phase: ChecksumManifestPublicationPhase) => void;
}

export async function writeAndVerifyChecksumManifest(
  bundleRootValue: string,
  relativePaths: readonly string[],
  options: ChecksumManifestPublicationOptions = {},
): Promise<{ readonly path: string; readonly entries: Readonly<Record<string, string>> }> {
  const bundleRoot = realDirectoryRoot(bundleRootValue, "Backup bundle root");
  const normalized = [...new Set(relativePaths.map(safeRelativePath))].sort((left, right) => left.localeCompare(right, "en"));
  if (!normalized.length || normalized.includes(BACKUP_CHECKSUM_MANIFEST)) {
    throw new Error("Backup checksum manifest requires at least one non-manifest file");
  }
  const entries: Record<string, string> = {};
  for (const relativePath of normalized) {
    const absolute = realRegularFileWithin(bundleRoot, relativePath, "Backup manifest path is not a real regular file");
    entries[relativePath] = await sha256File(absolute);
  }
  // The manifest is the commit marker for this rollback bundle. Persist every
  // referenced payload before publishing that marker, otherwise a power loss
  // could leave a durable checksum pointing at data that never reached disk.
  const payloadDirectories = new Set<string>([bundleRoot]);
  for (const relativePath of normalized) {
    const absolute = realRegularFileWithin(bundleRoot, relativePath, "Backup manifest path changed before durability sync");
    const descriptor = openSync(absolute, constants.O_RDONLY | NO_FOLLOW);
    try {
      if (!fstatSync(descriptor).isFile()) throw new Error(`Backup manifest path changed before durability sync: ${relativePath}`);
      fsyncSync(descriptor);
    }
    finally { closeSync(descriptor); }
    let directory = dirname(absolute);
    while (containedBy(bundleRoot, directory)) {
      payloadDirectories.add(directory);
      if (directory === bundleRoot) break;
      directory = dirname(directory);
    }
    options.onPhase?.(`payload_synced:${relativePath}`);
  }
  // Persist child directory entries before their parents, including every
  // nested payload directory. Syncing only bundleRoot can preserve the
  // SHA256SUMS marker while losing database/foo.sqlite after power failure.
  for (const directory of [...payloadDirectories].sort((left, right) => {
    const depth = (value: string): number => relative(bundleRoot, value).split(sep).filter(Boolean).length;
    return depth(right) - depth(left) || left.localeCompare(right, "en");
  })) fsyncDirectory(directory);
  options.onPhase?.("payload_directory_synced");
  const manifestPath = join(bundleRoot, BACKUP_CHECKSUM_MANIFEST);
  if (existsSync(manifestPath)) {
    realRegularFileWithin(bundleRoot, BACKUP_CHECKSUM_MANIFEST, "Backup checksum manifest is not a real regular file");
  }
  writeDurableFileAtomically(
    manifestPath,
    `${Object.entries(entries).map(([path, hash]) => `${hash}  ${path}`).join("\n")}\n`,
    {
      mode: 0o600,
      onPhase: (phase) => { options.onPhase?.(`manifest_${phase}`); },
    },
  );
  for (const [relativePath, expected] of Object.entries(entries)) {
    const absolute = realRegularFileWithin(bundleRoot, relativePath, "Backup manifest path changed after publication");
    if (await sha256File(absolute) !== expected) throw new Error(`Backup changed while checksums were published: ${relativePath}`);
  }
  return { path: manifestPath, entries };
}

export async function verifyChecksumManifest(bundleRootValue: string): Promise<Readonly<Record<string, string>>> {
  const bundleRoot = realDirectoryRoot(bundleRootValue, "Backup bundle root");
  const manifestPath = realRegularFileWithin(
    bundleRoot,
    BACKUP_CHECKSUM_MANIFEST,
    "Backup checksum manifest is not a real regular file",
  );
  const lines = readFileSync(manifestPath, "utf8").split("\n").filter(Boolean);
  if (!lines.length) throw new Error("Backup checksum manifest is empty");
  const entries: Record<string, string> = {};
  for (const line of lines) {
    const match = /^([a-f0-9]{64})  (.+)$/u.exec(line);
    if (!match) throw new Error("Backup checksum manifest has an invalid line");
    const relativePath = safeRelativePath(match[2]!);
    if (entries[relativePath]) throw new Error("Backup checksum manifest contains a duplicate path");
    const absolute = realRegularFileWithin(bundleRoot, relativePath, "Backup checksum target is missing or traverses a symbolic link");
    if (await sha256File(absolute) !== match[1]) throw new Error(`Backup checksum verification failed: ${relativePath}`);
    entries[relativePath] = match[1];
  }
  return entries;
}

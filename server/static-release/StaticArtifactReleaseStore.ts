import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  ftruncateSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";

export const STATIC_ARTIFACT_MANIFEST = "release-manifest.json";
export const STATIC_RELEASE_POINTER = "active.json";

const MANIFEST_SCHEMA = "ti-scale.static-artifact-manifest.v1" as const;
const POINTER_SCHEMA = "ti-scale.static-artifact-pointer.v1" as const;
const POINTER_SCOPE = "v2_static_artifact_pointer_only" as const;
const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const V2_NAMESPACE = /(?:^|[-_.])ti[-_]?scale(?:$|[-_.])/u;
const LEGACY_SEGMENTS = new Set([".conversation", "legacy", "webapp"]);
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;

export type StaticReleaseErrorCode =
  | "invalid_v2_release_path"
  | "unsafe_artifact_source"
  | "invalid_release_id"
  | "release_already_exists"
  | "release_not_found"
  | "release_locked"
  | "artifact_manifest_invalid"
  | "artifact_integrity_failed"
  | "active_pointer_missing"
  | "active_pointer_invalid"
  | "rollback_target_missing";

export class StaticReleaseError extends Error {
  readonly name = "StaticReleaseError";

  constructor(readonly code: StaticReleaseErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
  }
}

export interface StaticArtifactManifestEntry {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}

export interface StaticArtifactManifest {
  readonly schemaVersion: typeof MANIFEST_SCHEMA;
  readonly scope: typeof POINTER_SCOPE;
  readonly releaseId: string;
  readonly createdAt: string;
  readonly entryCount: number;
  readonly totalBytes: number;
  readonly artifactSha256: string;
  readonly entries: readonly StaticArtifactManifestEntry[];
}

export interface VerifiedStaticRelease {
  readonly releaseId: string;
  readonly releaseDirectory: string;
  readonly manifestPath: string;
  readonly manifestSha256: string;
  readonly manifest: StaticArtifactManifest;
}

export interface StaticArtifactSourceFingerprint {
  readonly artifactSha256: string;
  readonly entryCount: number;
  readonly totalBytes: number;
}

export interface ActiveStaticReleasePointer {
  readonly schemaVersion: typeof POINTER_SCHEMA;
  readonly scope: typeof POINTER_SCOPE;
  readonly generation: number;
  readonly activeReleaseId: string;
  readonly activeManifestSha256: string;
  readonly previousReleaseId: string | null;
  readonly previousManifestSha256: string | null;
  readonly activatedAt: string;
}

export interface PinnedStaticRelease extends VerifiedStaticRelease {
  readonly pointerGeneration: number;
}

export interface StaticArtifactReleaseStoreOptions {
  readonly releaseRoot: string;
  readonly clock?: () => Date;
  /** Test/audit hook invoked only after the kernel advisory lock is held. */
  readonly onLockAcquired?: (path: string) => void;
}

export interface FinalizeForwardOnlyStaticActivationInput {
  readonly activeReleaseId: string;
  readonly activeManifestSha256: string;
  readonly supersededReleaseId: string;
  readonly supersededManifestSha256: string;
  /**
   * Test/audit hook invoked after the durable pointer no longer retains a
   * previous-release identity and before the superseded tree is removed.
   */
  readonly onPreviousIdentityCleared?: () => void;
}

export interface FinalizeForwardOnlyStaticActivationResult {
  readonly activeReleaseId: string;
  readonly pointerGeneration: number;
  readonly previousIdentityCleared: true;
  readonly supersededReleaseDeleted: boolean;
}

function isNodeError(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === code;
}

function digest(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalEntriesDigest(entries: readonly StaticArtifactManifestEntry[]): string {
  return digest(entries.map((entry) => `${entry.path}\u0000${entry.bytes}\u0000${entry.sha256}`).join("\n"));
}

function normalizedSegments(path: string): readonly string[] {
  return path.toLocaleLowerCase("en-US").split(/[\\/]+/u).filter(Boolean);
}

function assertNoExistingSymlinkComponents(path: string, label: string): void {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  for (const segment of absolute.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, segment);
    try {
      const metadata = lstatSync(current);
      if (metadata.isSymbolicLink()) {
        throw new StaticReleaseError("invalid_v2_release_path", `${label} must not traverse symbolic links`);
      }
    } catch (error) {
      if (isNodeError(error, "ENOENT")) return;
      throw error;
    }
  }
}

function v2OwnedAbsolutePath(path: string, label: string): string {
  if (!path.trim() || !isAbsolute(path) || path.includes("\u0000")) {
    throw new StaticReleaseError("invalid_v2_release_path", `${label} must be an absolute V2-owned path`);
  }
  const absolute = resolve(path);
  const segments = normalizedSegments(absolute);
  if (segments.some((segment) => LEGACY_SEGMENTS.has(segment))) {
    throw new StaticReleaseError("invalid_v2_release_path", `${label} must not reference a legacy application path`);
  }
  if (!segments.some((segment) => V2_NAMESPACE.test(segment))) {
    throw new StaticReleaseError("invalid_v2_release_path", `${label} must include a ti-scale namespace segment`);
  }
  assertNoExistingSymlinkComponents(absolute, label);
  return absolute;
}

function containedBy(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" || (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`));
}

function assertDisjointPaths(left: string, right: string): void {
  if (containedBy(left, right) || containedBy(right, left)) {
    throw new StaticReleaseError(
      "invalid_v2_release_path",
      "The artifact source and immutable release root must be disjoint",
    );
  }
}

function releaseId(value: string): string {
  if (!RELEASE_ID.test(value) || value === "." || value === "..") {
    throw new StaticReleaseError("invalid_release_id", "Static release ID is invalid");
  }
  return value;
}

function artifactRelativePath(value: string): string {
  if (
    !value || value.length > 4_096 || value.includes("\\") || value.includes("\u0000") ||
    value.startsWith("/") || value.endsWith("/") ||
    value.split("/").some((segment) => !segment || segment === "." || segment === "..")
  ) {
    throw new StaticReleaseError("artifact_manifest_invalid", "Artifact manifest contains an unsafe path");
  }
  return value;
}

function resolveArtifactPath(root: string, relativePath: string): string {
  const safePath = artifactRelativePath(relativePath);
  const result = resolve(root, ...safePath.split("/"));
  if (!containedBy(root, result) || result === root) {
    throw new StaticReleaseError("artifact_manifest_invalid", "Artifact path escapes its immutable release directory");
  }
  return result;
}

function ensureDirectory(path: string, label: string): void {
  assertNoExistingSymlinkComponents(path, label);
  const absolute = resolve(path);
  const created: string[] = [];
  let existingAncestor = absolute;
  while (!existsSync(existingAncestor)) {
    created.push(existingAncestor);
    const parent = dirname(existingAncestor);
    if (parent === existingAncestor) {
      throw new StaticReleaseError("invalid_v2_release_path", `${label} has no existing directory ancestor`);
    }
    existingAncestor = parent;
  }
  const ancestorMetadata = lstatSync(existingAncestor);
  if (
    !ancestorMetadata.isDirectory() || ancestorMetadata.isSymbolicLink() ||
    realpathSync(existingAncestor) !== existingAncestor
  ) {
    throw new StaticReleaseError("invalid_v2_release_path", `${label} must not traverse symbolic links`);
  }
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const metadata = lstatSync(path);
  if (
    !metadata.isDirectory() || metadata.isSymbolicLink() ||
    realpathSync(absolute) !== absolute
  ) {
    throw new StaticReleaseError("invalid_v2_release_path", `${label} must be a regular directory`);
  }
  assertNoExistingSymlinkComponents(path, label);
  // `created` is deepest-first. Commit every new directory's own entries before
  // committing the entry that names it in the next existing ancestor.
  for (const directory of created) fsyncDirectory(directory);
  if (created.length) fsyncDirectory(existingAncestor);
}

function requireDirectory(path: string, label: string): void {
  assertNoExistingSymlinkComponents(path, label);
  let metadata;
  try {
    metadata = lstatSync(path);
  } catch (error) {
    if (isNodeError(error, "ENOENT")) {
      throw new StaticReleaseError("release_not_found", `${label} does not exist`);
    }
    throw error;
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new StaticReleaseError("invalid_v2_release_path", `${label} must be a regular directory`);
  }
}

function readRegularFile(path: string, label: string, maximumBytes = Number.MAX_SAFE_INTEGER): Buffer {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new StaticReleaseError("unsafe_artifact_source", `${label} must be a regular file and not a symbolic link`);
  }
  if (before.size > maximumBytes) {
    throw new StaticReleaseError("artifact_manifest_invalid", `${label} exceeds its bounded size`);
  }
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new StaticReleaseError("unsafe_artifact_source", `${label} changed while it was being inspected`);
    }
    const value = readFileSync(descriptor);
    if (value.byteLength !== opened.size) {
      throw new StaticReleaseError("unsafe_artifact_source", `${label} changed while it was being read`);
    }
    return value;
  } finally {
    closeSync(descriptor);
  }
}

function writeExclusiveFile(path: string, value: string | Uint8Array, mode: number): void {
  const descriptor = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
    mode,
  );
  try {
    writeFileSync(descriptor, value);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    if (!fstatSync(descriptor).isDirectory()) {
      throw new StaticReleaseError("invalid_v2_release_path", "Durability boundary is not a directory");
    }
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

interface StaticArtifactAdvisoryLock {
  release(): void;
}

/**
 * `flock` owns the lock on the open-file description inherited from this
 * process. The short-lived helper exits after acquisition, while this process'
 * descriptor keeps ownership until close or process death. The pathname is
 * intentionally persistent: stale owner metadata never grants or denies
 * ownership, and SIGKILL releases the kernel lock without cleanup code.
 */
function acquireStaticArtifactAdvisoryLock(
  path: string,
  acquiredAt: string,
): StaticArtifactAdvisoryLock {
  const descriptor = openSync(
    path,
    constants.O_RDWR | constants.O_CREAT | NO_FOLLOW,
    0o600,
  );
  let acquired = false;
  try {
    const descriptorMetadata = fstatSync(descriptor);
    const pathMetadata = lstatSync(path);
    if (
      !descriptorMetadata.isFile() || descriptorMetadata.nlink !== 1 ||
      pathMetadata.isSymbolicLink() || !pathMetadata.isFile() ||
      descriptorMetadata.dev !== pathMetadata.dev || descriptorMetadata.ino !== pathMetadata.ino
    ) {
      throw new StaticReleaseError("invalid_v2_release_path", "Static artifact lock must be one real regular file");
    }
    fchmodSync(descriptor, 0o600);
    const lock = Bun.spawnSync(
      ["/usr/bin/flock", "--exclusive", "--nonblock", "0"],
      {
        cwd: "/",
        env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
        stdin: descriptor,
        stdout: "pipe",
        stderr: "pipe",
        timeout: 5_000,
        killSignal: "SIGKILL",
      },
    );
    if (lock.exitCode === 1) {
      throw new StaticReleaseError("release_locked", "Another V2 static artifact handoff holds the release lock");
    }
    if (lock.exitCode !== 0) {
      const detail = new TextDecoder().decode(lock.stderr).trim().slice(0, 500);
      throw new Error(`Static artifact advisory lock acquisition failed${detail ? `: ${detail}` : ""}`);
    }
    acquired = true;
    const owner = `${JSON.stringify({
      schemaVersion: "ti-scale.static-artifact-lock-owner.v1",
      pid: process.pid,
      acquiredAt,
    })}\n`;
    ftruncateSync(descriptor, 0);
    writeSync(descriptor, owner, 0, "utf8");
    fsyncSync(descriptor);
    fsyncDirectory(dirname(path));
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }

  let released = false;
  return {
    release: () => {
      if (released) return;
      released = true;
      if (acquired) closeSync(descriptor);
    },
  };
}

function fsyncStaticReleaseTree(root: string): void {
  const directories: string[] = [];
  const visit = (directory: string): void => {
    directories.push(directory);
    for (const name of readdirSync(directory).sort((left, right) => left.localeCompare(right, "en"))) {
      const path = join(directory, name);
      const metadata = lstatSync(path);
      if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
        visit(path);
        continue;
      }
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        throw new StaticReleaseError("unsafe_artifact_source", "Immutable release contains an unsafe filesystem entry");
      }
      const descriptor = openSync(path, constants.O_RDONLY | NO_FOLLOW);
      try {
        if (!fstatSync(descriptor).isFile()) {
          throw new StaticReleaseError("unsafe_artifact_source", "Immutable release file changed before durability sync");
        }
        fsyncSync(descriptor);
      } finally {
        closeSync(descriptor);
      }
    }
  };
  visit(root);
  for (const directory of directories.reverse()) fsyncDirectory(directory);
}

function scanRegularArtifactTree(root: string, excludeRootManifest: boolean): readonly StaticArtifactManifestEntry[] {
  requireDirectory(root, "Static artifact directory");
  const canonicalRoot = realpathSync(root);
  if (canonicalRoot !== resolve(root)) {
    throw new StaticReleaseError("unsafe_artifact_source", "Static artifact directory must not traverse symbolic links");
  }
  const entries: StaticArtifactManifestEntry[] = [];
  const visit = (directory: string, prefix: string): void => {
    const canonicalDirectory = realpathSync(directory);
    if (!containedBy(canonicalRoot, canonicalDirectory)) {
      throw new StaticReleaseError("unsafe_artifact_source", "Static artifact directory traversal escaped its root");
    }
    for (const name of readdirSync(directory).sort((left, right) => left.localeCompare(right, "en"))) {
      const relativePath = artifactRelativePath(prefix ? `${prefix}/${name}` : name);
      if (excludeRootManifest && relativePath === STATIC_ARTIFACT_MANIFEST) continue;
      const path = resolveArtifactPath(root, relativePath);
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink()) {
        throw new StaticReleaseError("unsafe_artifact_source", `Static artifact path is a symbolic link: ${relativePath}`);
      }
      if (metadata.isDirectory()) {
        visit(path, relativePath);
        const after = lstatSync(path);
        if (!after.isDirectory() || after.isSymbolicLink()) {
          throw new StaticReleaseError("unsafe_artifact_source", `Static artifact directory changed during traversal: ${relativePath}`);
        }
        continue;
      }
      if (!metadata.isFile()) {
        throw new StaticReleaseError("unsafe_artifact_source", `Static artifact path is not a regular file: ${relativePath}`);
      }
      const content = readRegularFile(path, `Static artifact ${relativePath}`);
      entries.push({ path: relativePath, bytes: content.byteLength, sha256: digest(content) });
    }
  };
  visit(root, "");
  entries.sort((left, right) => left.path.localeCompare(right.path, "en"));
  return entries;
}

/**
 * Read-only identity for the exact browser artifact tree that `stageRelease`
 * would publish. It performs the same path, symlink, and regular-file checks
 * as staging and does not create a candidate or other retained payload.
 */
export function fingerprintStaticArtifactSource(
  sourceDirectory: string,
): StaticArtifactSourceFingerprint {
  const source = v2OwnedAbsolutePath(
    sourceDirectory,
    "Ti-Scale static artifact source",
  );
  const entries = scanRegularArtifactTree(source, false);
  if (
    entries.length === 0 ||
    !entries.some((entry) => entry.path === "index.html")
  ) {
    throw new StaticReleaseError(
      "unsafe_artifact_source",
      "Built V2 artifact source must contain index.html",
    );
  }
  if (entries.some((entry) => entry.path === STATIC_ARTIFACT_MANIFEST)) {
    throw new StaticReleaseError(
      "unsafe_artifact_source",
      `${STATIC_ARTIFACT_MANIFEST} is reserved for the immutable handoff`,
    );
  }
  return {
    artifactSha256: canonicalEntriesDigest(entries),
    entryCount: entries.length,
    totalBytes: entries.reduce((total, entry) => total + entry.bytes, 0),
  };
}

function assertSameEntries(
  actual: readonly StaticArtifactManifestEntry[],
  expected: readonly StaticArtifactManifestEntry[],
  message: string,
): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new StaticReleaseError("artifact_integrity_failed", message);
  }
}

function parseManifest(value: unknown, expectedReleaseId: string): StaticArtifactManifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new StaticReleaseError("artifact_manifest_invalid", "Static artifact manifest must be an object");
  }
  const manifest = value as Record<string, unknown>;
  if (
    manifest.schemaVersion !== MANIFEST_SCHEMA || manifest.scope !== POINTER_SCOPE ||
    manifest.releaseId !== expectedReleaseId || typeof manifest.createdAt !== "string" ||
    !Number.isFinite(Date.parse(manifest.createdAt)) ||
    !Number.isSafeInteger(manifest.entryCount) || (manifest.entryCount as number) < 1 ||
    !Number.isSafeInteger(manifest.totalBytes) || (manifest.totalBytes as number) < 0 ||
    typeof manifest.artifactSha256 !== "string" || !SHA256.test(manifest.artifactSha256) ||
    !Array.isArray(manifest.entries)
  ) {
    throw new StaticReleaseError("artifact_manifest_invalid", "Static artifact manifest metadata is invalid");
  }
  const entries = manifest.entries.map((raw): StaticArtifactManifestEntry => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new StaticReleaseError("artifact_manifest_invalid", "Static artifact manifest entry is invalid");
    }
    const entry = raw as Record<string, unknown>;
    if (
      typeof entry.path !== "string" || !Number.isSafeInteger(entry.bytes) || (entry.bytes as number) < 0 ||
      typeof entry.sha256 !== "string" || !SHA256.test(entry.sha256)
    ) {
      throw new StaticReleaseError("artifact_manifest_invalid", "Static artifact manifest entry metadata is invalid");
    }
    return { path: artifactRelativePath(entry.path), bytes: entry.bytes as number, sha256: entry.sha256 };
  });
  const sorted = [...entries].sort((left, right) => left.path.localeCompare(right.path, "en"));
  if (new Set(entries.map((entry) => entry.path)).size !== entries.length || JSON.stringify(entries) !== JSON.stringify(sorted)) {
    throw new StaticReleaseError("artifact_manifest_invalid", "Static artifact manifest entries must be unique and sorted");
  }
  if (
    manifest.entryCount !== entries.length ||
    manifest.totalBytes !== entries.reduce((total, entry) => total + entry.bytes, 0) ||
    manifest.artifactSha256 !== canonicalEntriesDigest(entries)
  ) {
    throw new StaticReleaseError("artifact_manifest_invalid", "Static artifact manifest aggregate digest is invalid");
  }
  if (!entries.some((entry) => entry.path === "index.html")) {
    throw new StaticReleaseError("artifact_manifest_invalid", "Static artifact manifest must contain index.html");
  }
  return {
    schemaVersion: MANIFEST_SCHEMA,
    scope: POINTER_SCOPE,
    releaseId: expectedReleaseId,
    createdAt: manifest.createdAt,
    entryCount: entries.length,
    totalBytes: manifest.totalBytes as number,
    artifactSha256: manifest.artifactSha256,
    entries,
  };
}

function parsePointer(value: unknown): ActiveStaticReleasePointer {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new StaticReleaseError("active_pointer_invalid", "V2 static release pointer must be an object");
  }
  const pointer = value as Record<string, unknown>;
  const previousPairValid =
    (pointer.previousReleaseId === null && pointer.previousManifestSha256 === null) ||
    (typeof pointer.previousReleaseId === "string" && RELEASE_ID.test(pointer.previousReleaseId) &&
      typeof pointer.previousManifestSha256 === "string" && SHA256.test(pointer.previousManifestSha256));
  if (
    pointer.schemaVersion !== POINTER_SCHEMA || pointer.scope !== POINTER_SCOPE ||
    !Number.isSafeInteger(pointer.generation) || (pointer.generation as number) < 1 ||
    typeof pointer.activeReleaseId !== "string" || !RELEASE_ID.test(pointer.activeReleaseId) ||
    typeof pointer.activeManifestSha256 !== "string" || !SHA256.test(pointer.activeManifestSha256) ||
    !previousPairValid || typeof pointer.activatedAt !== "string" || !Number.isFinite(Date.parse(pointer.activatedAt))
  ) {
    throw new StaticReleaseError("active_pointer_invalid", "V2 static release pointer metadata is invalid");
  }
  return pointer as unknown as ActiveStaticReleasePointer;
}

function readonlyTree(root: string): void {
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink() || (!metadata.isDirectory() && !metadata.isFile())) {
        throw new StaticReleaseError("unsafe_artifact_source", "Immutable release contains an unsafe filesystem entry");
      }
      if (metadata.isDirectory()) visit(path);
      chmodSync(path, metadata.isDirectory() ? 0o555 : 0o444);
    }
  };
  visit(root);
  chmodSync(root, 0o555);
}

/**
 * V2-only static artifact handoff. This class changes only its configured
 * ti-scale release root. It does not restart a process, change a reverse
 * proxy, migrate data, or provide full application cutover rollback.
 */
export class StaticArtifactReleaseStore {
  readonly releaseRoot: string;
  readonly releasesDirectory: string;
  readonly stateDirectory: string;
  readonly pointerPath: string;
  readonly #clock: () => Date;
  readonly #onLockAcquired: ((path: string) => void) | undefined;

  constructor(options: StaticArtifactReleaseStoreOptions) {
    this.releaseRoot = v2OwnedAbsolutePath(options.releaseRoot, "TI_SCALE_STATIC_RELEASE_ROOT");
    this.releasesDirectory = join(this.releaseRoot, "releases");
    this.stateDirectory = join(this.releaseRoot, "state");
    this.pointerPath = join(this.stateDirectory, STATIC_RELEASE_POINTER);
    this.#clock = options.clock ?? (() => new Date());
    this.#onLockAcquired = options.onLockAcquired;
  }

  stageRelease(input: { readonly releaseId: string; readonly sourceDirectory: string }): VerifiedStaticRelease {
    const id = releaseId(input.releaseId);
    const source = v2OwnedAbsolutePath(input.sourceDirectory, "Ti-Scale static artifact source");
    requireDirectory(source, "Ti-Scale static artifact source");
    assertDisjointPaths(source, this.releaseRoot);
    return this.#withLock(() => {
      const destination = join(this.releasesDirectory, id);
      if (existsSync(destination)) {
        throw new StaticReleaseError("release_already_exists", `Static release already exists: ${id}`);
      }
      const staging = join(this.releasesDirectory, `.stage-${id}-${randomUUID()}`);
      mkdirSync(staging, { mode: 0o700 });
      let promoted = false;
      try {
        const sourceEntries = scanRegularArtifactTree(source, false);
        if (sourceEntries.length === 0 || !sourceEntries.some((entry) => entry.path === "index.html")) {
          throw new StaticReleaseError("unsafe_artifact_source", "Built V2 artifact source must contain index.html");
        }
        if (sourceEntries.some((entry) => entry.path === STATIC_ARTIFACT_MANIFEST)) {
          throw new StaticReleaseError("unsafe_artifact_source", `${STATIC_ARTIFACT_MANIFEST} is reserved for the immutable handoff`);
        }
        for (const entry of sourceEntries) {
          const sourcePath = resolveArtifactPath(source, entry.path);
          const targetPath = resolveArtifactPath(staging, entry.path);
          mkdirSync(dirname(targetPath), { recursive: true, mode: 0o755 });
          const content = readRegularFile(sourcePath, `Static artifact ${entry.path}`);
          if (content.byteLength !== entry.bytes || digest(content) !== entry.sha256) {
            throw new StaticReleaseError("unsafe_artifact_source", `Static artifact changed during staging: ${entry.path}`);
          }
          writeExclusiveFile(targetPath, content, 0o444);
        }
        assertSameEntries(
          scanRegularArtifactTree(source, false),
          sourceEntries,
          "Static artifact source changed during staging",
        );
        assertSameEntries(
          scanRegularArtifactTree(staging, false),
          sourceEntries,
          "Staged static artifact copy is incomplete",
        );
        const manifest: StaticArtifactManifest = {
          schemaVersion: MANIFEST_SCHEMA,
          scope: POINTER_SCOPE,
          releaseId: id,
          createdAt: this.#clock().toISOString(),
          entryCount: sourceEntries.length,
          totalBytes: sourceEntries.reduce((total, entry) => total + entry.bytes, 0),
          artifactSha256: canonicalEntriesDigest(sourceEntries),
          entries: sourceEntries,
        };
        const manifestBytes = `${JSON.stringify(manifest, null, 2)}\n`;
        const manifestSha256 = digest(manifestBytes);
        writeExclusiveFile(join(staging, STATIC_ARTIFACT_MANIFEST), manifestBytes, 0o444);
        this.#verifyDirectory(staging, id, manifestSha256, false);
        readonlyTree(staging);
        fsyncStaticReleaseTree(staging);
        renameSync(staging, destination);
        promoted = true;
        fsyncDirectory(this.releasesDirectory);
        try {
          return this.#verifyDirectory(destination, id, manifestSha256, true);
        } catch (error) {
          rmSync(destination, { recursive: true, force: true });
          fsyncDirectory(this.releasesDirectory);
          throw error;
        }
      } finally {
        if (!promoted) rmSync(staging, { recursive: true, force: true });
      }
    });
  }

  verifyRelease(idValue: string, expectedManifestSha256?: string): VerifiedStaticRelease {
    this.#requireLayout();
    const id = releaseId(idValue);
    if (expectedManifestSha256 !== undefined && !SHA256.test(expectedManifestSha256)) {
      throw new StaticReleaseError("artifact_manifest_invalid", "Expected manifest SHA-256 is invalid");
    }
    return this.#verifyDirectory(
      join(this.releasesDirectory, id),
      id,
      expectedManifestSha256,
      true,
    );
  }

  activateRelease(idValue: string): PinnedStaticRelease {
    const id = releaseId(idValue);
    return this.#withLock(() => {
      const selected = this.#verifyDirectory(join(this.releasesDirectory, id), id, undefined, true);
      const current = this.#readPointer(false);
      if (current) {
        const active = this.#verifyDirectory(
          join(this.releasesDirectory, current.activeReleaseId),
          current.activeReleaseId,
          current.activeManifestSha256,
          true,
        );
        if (active.releaseId === selected.releaseId && active.manifestSha256 === selected.manifestSha256) {
          return { ...selected, pointerGeneration: current.generation };
        }
      }
      const pointer: ActiveStaticReleasePointer = {
        schemaVersion: POINTER_SCHEMA,
        scope: POINTER_SCOPE,
        generation: (current?.generation ?? 0) + 1,
        activeReleaseId: selected.releaseId,
        activeManifestSha256: selected.manifestSha256,
        previousReleaseId: current?.activeReleaseId ?? null,
        previousManifestSha256: current?.activeManifestSha256 ?? null,
        activatedAt: this.#clock().toISOString(),
      };
      this.#writePointer(pointer);
      return { ...selected, pointerGeneration: pointer.generation };
    });
  }

  /**
   * Complete a forward-only activation after the replacement runtime has
   * passed its compatibility proof. The active release is reverified under the
   * store lock, the previous pointer identity is durably cleared first, and
   * only the exact superseded immutable tree may then be deleted.
   *
   * The operation is deliberately idempotent. A crash after the pointer write
   * but before deletion leaves an unreferenced tree which a restarted release
   * controller can delete by replaying this exact call.
   */
  finalizeForwardOnlyActivation(
    input: FinalizeForwardOnlyStaticActivationInput,
  ): FinalizeForwardOnlyStaticActivationResult {
    const activeReleaseId = releaseId(input.activeReleaseId);
    const supersededReleaseId = releaseId(input.supersededReleaseId);
    if (!SHA256.test(input.activeManifestSha256) || !SHA256.test(input.supersededManifestSha256)) {
      throw new StaticReleaseError(
        "artifact_manifest_invalid",
        "Forward-only static finalization requires exact manifest SHA-256 values",
      );
    }
    if (activeReleaseId === supersededReleaseId) {
      throw new StaticReleaseError(
        "active_pointer_invalid",
        "Forward-only static finalization must never delete the active release",
      );
    }
    return this.#withLock(() => {
      const current = this.#readPointer(true)!;
      const active = this.#verifyDirectory(
        join(this.releasesDirectory, activeReleaseId),
        activeReleaseId,
        input.activeManifestSha256,
        true,
      );
      if (
        current.activeReleaseId !== active.releaseId ||
        current.activeManifestSha256 !== active.manifestSha256
      ) {
        throw new StaticReleaseError(
          "active_pointer_invalid",
          "Forward-only static finalization does not match the active release",
        );
      }
      if (
        current.previousReleaseId !== null &&
        (
          current.previousReleaseId !== supersededReleaseId ||
          current.previousManifestSha256 !== input.supersededManifestSha256
        )
      ) {
        throw new StaticReleaseError(
          "active_pointer_invalid",
          "Forward-only static finalization does not match the recorded superseded release",
        );
      }

      let pointer = current;
      if (
        current.previousReleaseId !== null ||
        current.previousManifestSha256 !== null
      ) {
        pointer = {
          ...current,
          generation: current.generation + 1,
          previousReleaseId: null,
          previousManifestSha256: null,
        };
        this.#writePointer(pointer);
        input.onPreviousIdentityCleared?.();
      }

      const supersededDirectory = join(
        this.releasesDirectory,
        supersededReleaseId,
      );
      let supersededReleaseDeleted = false;
      try {
        const metadata = lstatSync(supersededDirectory);
        if (
          !metadata.isDirectory() ||
          metadata.isSymbolicLink() ||
          realpathSync(supersededDirectory) !== supersededDirectory
        ) {
          throw new StaticReleaseError(
            "unsafe_artifact_source",
            "Superseded static release is not an exact immutable directory",
          );
        }
        rmSync(supersededDirectory, { recursive: true, force: false });
        fsyncDirectory(this.releasesDirectory);
        supersededReleaseDeleted = true;
      } catch (error) {
        if (!isNodeError(error, "ENOENT")) throw error;
      }

      const stillActive = this.#verifyDirectory(
        join(this.releasesDirectory, activeReleaseId),
        activeReleaseId,
        input.activeManifestSha256,
        true,
      );
      const finalPointer = this.#readPointer(true)!;
      if (
        finalPointer.activeReleaseId !== stillActive.releaseId ||
        finalPointer.activeManifestSha256 !== stillActive.manifestSha256 ||
        finalPointer.previousReleaseId !== null ||
        finalPointer.previousManifestSha256 !== null
      ) {
        throw new StaticReleaseError(
          "active_pointer_invalid",
          "Forward-only static finalization did not preserve the exact active release",
        );
      }
      return {
        activeReleaseId,
        pointerGeneration: finalPointer.generation,
        previousIdentityCleared: true,
        supersededReleaseDeleted,
      };
    });
  }

  pinActiveRelease(): PinnedStaticRelease {
    this.#requireLayout();
    const pointer = this.#readPointer(true)!;
    const verified = this.#verifyDirectory(
      join(this.releasesDirectory, pointer.activeReleaseId),
      pointer.activeReleaseId,
      pointer.activeManifestSha256,
      true,
    );
    return { ...verified, pointerGeneration: pointer.generation };
  }

  readActivePointer(): ActiveStaticReleasePointer {
    this.#requireLayout();
    return this.#readPointer(true)!;
  }

  #ensureLayout(): void {
    ensureDirectory(this.releaseRoot, "Ti-Scale static release root");
    ensureDirectory(this.releasesDirectory, "Ti-Scale immutable releases directory");
    ensureDirectory(this.stateDirectory, "Ti-Scale static release state directory");
  }

  #requireLayout(): void {
    requireDirectory(this.releaseRoot, "Ti-Scale static release root");
    requireDirectory(this.releasesDirectory, "Ti-Scale immutable releases directory");
    requireDirectory(this.stateDirectory, "Ti-Scale static release state directory");
  }

  #withLock<T>(operation: () => T): T {
    this.#ensureLayout();
    const path = join(this.releaseRoot, ".static-artifact-handoff.lock");
    const lock = acquireStaticArtifactAdvisoryLock(path, this.#clock().toISOString());
    try {
      this.#onLockAcquired?.(path);
      return operation();
    } finally {
      lock.release();
    }
  }

  #verifyDirectory(
    directory: string,
    expectedReleaseId: string,
    expectedManifestSha256: string | undefined,
    requireVersionedName: boolean,
  ): VerifiedStaticRelease {
    requireDirectory(directory, `Static release ${expectedReleaseId}`);
    if (requireVersionedName && basename(directory) !== expectedReleaseId) {
      throw new StaticReleaseError("release_not_found", "Static release directory does not match its immutable release ID");
    }
    const manifestPath = join(directory, STATIC_ARTIFACT_MANIFEST);
    let manifestBytes: Buffer;
    try {
      manifestBytes = readRegularFile(manifestPath, "Static artifact manifest", 16 * 1024 * 1024);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        throw new StaticReleaseError("artifact_integrity_failed", "Static release manifest is missing", { cause: error });
      }
      throw error;
    }
    const manifestSha256 = digest(manifestBytes);
    if (expectedManifestSha256 && manifestSha256 !== expectedManifestSha256) {
      throw new StaticReleaseError("artifact_integrity_failed", "Static release manifest does not match its pinned SHA-256");
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(manifestBytes.toString("utf8"));
    } catch (error) {
      throw new StaticReleaseError("artifact_manifest_invalid", "Static release manifest is not valid JSON", { cause: error });
    }
    const manifest = parseManifest(decoded, expectedReleaseId);
    const actualEntries = scanRegularArtifactTree(directory, true);
    assertSameEntries(actualEntries, manifest.entries, "Static release is tampered, partial, or contains unmanifested files");
    return {
      releaseId: expectedReleaseId,
      releaseDirectory: resolve(directory),
      manifestPath,
      manifestSha256,
      manifest,
    };
  }

  #readPointer(required: boolean): ActiveStaticReleasePointer | undefined {
    let content: Buffer;
    try {
      content = readRegularFile(this.pointerPath, "V2 static release pointer", 64 * 1024);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        if (!required) return undefined;
        throw new StaticReleaseError("active_pointer_missing", "No active V2 static release pointer exists", { cause: error });
      }
      throw error;
    }
    try {
      return parsePointer(JSON.parse(content.toString("utf8")));
    } catch (error) {
      if (error instanceof StaticReleaseError) throw error;
      throw new StaticReleaseError("active_pointer_invalid", "V2 static release pointer is not valid JSON", { cause: error });
    }
  }

  #writePointer(pointer: ActiveStaticReleasePointer): void {
    parsePointer(pointer);
    const temporary = join(this.stateDirectory, `.active-${randomUUID()}.tmp`);
    try {
      writeExclusiveFile(temporary, `${JSON.stringify(pointer, null, 2)}\n`, 0o644);
      renameSync(temporary, this.pointerPath);
      fsyncDirectory(this.stateDirectory);
    } finally {
      rmSync(temporary, { force: true });
    }
  }
}

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {
  dirname,
  isAbsolute,
  parse,
  relative,
  resolve,
  sep,
} from "node:path";

export const PERFORMANCE_SOURCE_PROVENANCE_SCHEMA =
  "ti-scale.performance-source.v1";
export const PERFORMANCE_BUILD_PROVENANCE_SCHEMA =
  "ti-scale.performance-build.v1";

export interface FileDigest {
  readonly path: string;
  readonly kind: "file" | "symlink";
  readonly bytes: number;
  readonly sha256: string;
}

export interface FileTreeManifest {
  readonly algorithm: "sha256-canonical-file-manifest-v1";
  readonly fileCount: number;
  readonly totalBytes: number;
  readonly treeSha256: string;
  readonly files: readonly FileDigest[];
}

export interface FileTreeManifestSummary {
  readonly algorithm: FileTreeManifest["algorithm"];
  readonly fileCount: number;
  readonly totalBytes: number;
  readonly treeSha256: string;
}

export interface PerformanceSourceBaseline {
  readonly schemaVersion: typeof PERFORMANCE_SOURCE_PROVENANCE_SCHEMA;
  readonly runId: string;
  readonly measuredAt: string;
  readonly source: FileTreeManifestSummary;
  readonly launcher: {
    readonly runtime: "bun";
    readonly version: string;
  };
}

export interface PerformanceBuildBaseline {
  readonly schemaVersion: typeof PERFORMANCE_BUILD_PROVENANCE_SCHEMA;
  readonly runId: string;
  readonly measuredAt: string;
  readonly build: FileTreeManifestSummary;
  readonly releaseCandidateEligible: false;
}

export interface StaticByteDigest {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}

export type ObservedResourceClassification =
  | {
    readonly kind: "static-build";
    readonly requestUrl: string;
    readonly path: string;
  }
  | {
    readonly kind: "dynamic-api";
    readonly requestUrl: string;
    readonly reason: string;
  }
  | {
    readonly kind: "external-origin";
    readonly requestUrl: string;
    readonly reason: string;
  }
  | {
    readonly kind: "non-http";
    readonly requestUrl: string;
    readonly reason: string;
  }
  | {
    readonly kind: "unclassified-same-origin";
    readonly requestUrl: string;
    readonly path: string;
    readonly reason: string;
  }
  | {
    readonly kind: "invalid";
    readonly requestUrl: string;
    readonly reason: string;
  };

const SAFE_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SOURCE_SCAN_EXCLUDED_ROOTS: ReadonlySet<string> = new Set([
  ".artifacts",
  ".git",
  ".vite",
  "artifacts",
  "coverage",
  "data",
  "dist",
  "node_modules",
  "playwright-report",
  "test-results",
] as const);

function canonicalRelativePath(root: string, path: string): string {
  const absolute = resolve(root, path);
  const inside = relative(root, absolute);
  if (
    inside === ""
    || inside === ".."
    || inside.startsWith(`..${sep}`)
    || isAbsolute(inside)
  ) {
    throw new Error(`Performance manifest path escaped its root: ${path}`);
  }
  return inside.split(sep).join("/");
}

function digestPaths(
  rootValue: string,
  paths: readonly string[],
  allowSymlinks: boolean,
): FileTreeManifest {
  const root = resolve(rootValue);
  const unique = [...new Set(paths.map((path) =>
    canonicalRelativePath(root, path)))].sort();
  const files = unique.map((path): FileDigest => {
    const absolute = resolve(root, path);
    const metadata = lstatSync(absolute);
    let kind: FileDigest["kind"];
    let bytes: Buffer;
    if (metadata.isFile()) {
      kind = "file";
      bytes = readFileSync(absolute);
    } else if (allowSymlinks && metadata.isSymbolicLink()) {
      kind = "symlink";
      bytes = Buffer.from(readlinkSync(absolute), "utf8");
    } else {
      throw new Error(
        `Performance manifest accepts only regular files${allowSymlinks ? " or symbolic links" : ""}: ${path}`,
      );
    }
    return Object.freeze({
      path,
      kind,
      bytes: bytes.byteLength,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  });
  const treeSha256 = createHash("sha256")
    .update(JSON.stringify(files))
    .digest("hex");
  return Object.freeze({
    algorithm: "sha256-canonical-file-manifest-v1",
    fileCount: files.length,
    totalBytes: files.reduce((total, file) => total + file.bytes, 0),
    treeSha256,
    files: Object.freeze(files),
  });
}

function sourceSymlinkPaths(
  root: string,
  directory: string,
  result: string[],
): void {
  const atRoot = directory === root;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (atRoot && SOURCE_SCAN_EXCLUDED_ROOTS.has(entry.name)) continue;
    const absolute = resolve(directory, entry.name);
    const path = canonicalRelativePath(root, absolute);
    if (entry.isSymbolicLink()) {
      result.push(path);
    } else if (entry.isDirectory()) {
      sourceSymlinkPaths(root, absolute, result);
    }
  }
}

export function sourceTreeManifest(rootValue: string): FileTreeManifest {
  const root = resolve(rootValue);
  const rootMetadata = lstatSync(root);
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error("The performance source root must be a real directory");
  }
  const output = execFileSync(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
    {
      cwd: root,
      encoding: "buffer",
      maxBuffer: 64 * 1_024 * 1_024,
    },
  );
  const paths = output
    .toString("utf8")
    .split("\0")
    .filter((path) => path.length > 0);
  // Git deliberately omits ignored files, but an ignored symlink under the
  // application tree can still be imported by Vite or copied from `public/`.
  // Add every such link outside dependency/runtime/output roots so the strict
  // regular-file manifest rejects it before the managed build dereferences
  // unbound bytes.
  sourceSymlinkPaths(root, root, paths);
  if (paths.length === 0) {
    throw new Error("The performance source manifest cannot be empty");
  }
  // Vite dereferences imported and public-file symlinks by default. Hashing
  // only the link text would therefore allow unbound source bytes to enter the
  // measured build. Reject every source symlink rather than following a path
  // whose target can live outside the reviewed tree.
  return digestPaths(root, paths, false);
}

function rawUrlPath(value: string): string {
  return value.split("#", 1)[0]!.split("?", 1)[0]!;
}

function unsafeEncodedPathReason(value: string): string | undefined {
  let decoded = rawUrlPath(value);
  for (let depth = 0; depth < 4; depth += 1) {
    if (/%(?:2f|5c|00)/iu.test(decoded)) {
      return "encoded path separators and null bytes are not accepted";
    }
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return "the URL contains malformed percent encoding";
    }
    if (next.includes("\\") || next.includes("\0")) {
      return "backslashes and null bytes are not accepted in static paths";
    }
    if (next.split("/").some((segment) => segment === "." || segment === "..")) {
      return "dot-segment traversal is not accepted in static paths";
    }
    if (next === decoded) return undefined;
    decoded = next;
  }
  return /%[0-9a-f]{2}/iu.test(decoded)
    ? "the static path exceeds the accepted percent-decoding depth"
    : undefined;
}

function decodedBuildPath(pathname: string): string | undefined {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return undefined;
  }
  if (
    decoded.includes("\\")
    || decoded.includes("\0")
    || decoded.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    return undefined;
  }
  const path = decoded.replace(/^\/+/u, "");
  return path.length > 0 ? path : undefined;
}

/**
 * Classify one browser-observed URL against the exact invocation-owned build.
 * Static ownership is established only by an exact regular-file manifest
 * entry; path prefixes and file extensions are deliberately not trusted.
 */
export function classifyObservedResourceUrl(
  rawUrl: string,
  baseUrl: string,
  build: Pick<FileTreeManifest, "files">,
): ObservedResourceClassification {
  let base: URL;
  let parsed: URL;
  try {
    base = new URL(baseUrl);
    parsed = new URL(rawUrl, base);
  } catch {
    return Object.freeze({
      kind: "invalid",
      requestUrl: `malformed-url:sha256:${
        createHash("sha256").update(rawUrl, "utf8").digest("hex")
      }`,
      reason: "the observed resource URL is malformed and was replaced by a content-free digest",
    });
  }
  parsed.hash = "";
  let requestUrl = parsed.toString();
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return Object.freeze({
      kind: "non-http",
      requestUrl,
      reason: `the ${parsed.protocol || "unknown"} scheme is not a network build resource`,
    });
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    parsed.username = "";
    parsed.password = "";
    requestUrl = parsed.toString();
    return Object.freeze({
      kind: "invalid",
      requestUrl,
      reason: "embedded URL credentials are forbidden and were redacted",
    });
  }
  if (parsed.origin !== base.origin) {
    return Object.freeze({
      kind: "external-origin",
      requestUrl,
      reason: `the resource origin ${parsed.origin} differs from ${base.origin}`,
    });
  }

  const unsafeReason = unsafeEncodedPathReason(rawUrl);
  if (unsafeReason) {
    return Object.freeze({
      kind: "invalid",
      requestUrl,
      reason: unsafeReason,
    });
  }
  const path = decodedBuildPath(parsed.pathname);
  if (!path) {
    return Object.freeze({
      kind: "unclassified-same-origin",
      requestUrl,
      path: "",
      reason: "the same-origin URL does not identify a safe build file",
    });
  }
  if (parsed.pathname === "/api/v2" || parsed.pathname.startsWith("/api/v2/")) {
    return Object.freeze({
      kind: "dynamic-api",
      requestUrl,
      reason: "the URL belongs to the versioned dynamic API boundary",
    });
  }
  const file = build.files.find((candidate) =>
    candidate.path === path && candidate.kind === "file");
  if (file) {
    return Object.freeze({
      kind: "static-build",
      requestUrl,
      path,
    });
  }
  return Object.freeze({
    kind: "unclassified-same-origin",
    requestUrl,
    path,
    reason: "the same-origin path is absent from the invocation-owned build manifest",
  });
}

export function observedResourceIntegrityFailure(
  classification: ObservedResourceClassification,
): string | undefined {
  if (classification.kind === "external-origin") {
    return `Unpinned external HTTP(S) resource is forbidden by the exact-build gate: ${classification.requestUrl}`;
  }
  if (
    classification.kind === "invalid"
    || classification.kind === "unclassified-same-origin"
  ) {
    return `${classification.kind} ${classification.requestUrl}: ${classification.reason}`;
  }
  return undefined;
}

export function staticResponseIntegrityFailures(
  build: Pick<FileTreeManifest, "files">,
  observed: readonly StaticByteDigest[],
): readonly string[] {
  const built = new Map(build.files.map((file) => [file.path, file] as const));
  const failures: string[] = [];
  for (const digest of observed) {
    const file = built.get(digest.path);
    if (!file) {
      failures.push(`Observed path is absent from the complete build manifest: ${digest.path}`);
      continue;
    }
    if (file.kind !== "file") {
      failures.push(`Observed build path is not a regular file: ${digest.path}`);
      continue;
    }
    if (file.bytes !== digest.bytes || file.sha256 !== digest.sha256) {
      failures.push(`Observed bytes differ from the invocation-owned build: ${digest.path}`);
    }
  }
  return Object.freeze(failures);
}

function directoryFiles(
  root: string,
  directory: string,
  result: string[],
): void {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = resolve(directory, entry.name);
    const path = canonicalRelativePath(root, absolute);
    if (entry.isDirectory()) {
      directoryFiles(root, absolute, result);
    } else if (entry.isFile()) {
      result.push(path);
    } else {
      throw new Error(
        `The invocation-owned build manifest rejects non-regular entry ${path}`,
      );
    }
  }
}

export function directoryTreeManifest(rootValue: string): FileTreeManifest {
  const root = resolve(rootValue);
  const metadata = lstatSync(root);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("The invocation-owned build root must be a real directory");
  }
  const paths: string[] = [];
  directoryFiles(root, root, paths);
  if (paths.length === 0) {
    throw new Error("The invocation-owned build manifest cannot be empty");
  }
  return digestPaths(root, paths, false);
}

export function summarizeFileTree(
  manifest: FileTreeManifest,
): FileTreeManifestSummary {
  return Object.freeze({
    algorithm: manifest.algorithm,
    fileCount: manifest.fileCount,
    totalBytes: manifest.totalBytes,
    treeSha256: manifest.treeSha256,
  });
}

export function sameFileTreeSummary(
  left: FileTreeManifestSummary,
  right: FileTreeManifestSummary,
): boolean {
  return left.algorithm === right.algorithm
    && left.fileCount === right.fileCount
    && left.totalBytes === right.totalBytes
    && left.treeSha256 === right.treeSha256;
}

function assertSafeRunId(runId: string, label: string): void {
  if (!SAFE_RUN_ID.test(runId)) throw new Error(`${label} run ID is invalid`);
}

export function performanceSourceBaselinePath(
  dataRootValue: string,
  runId: string,
): string {
  assertSafeRunId(runId, "Performance source-baseline");
  const dataRoot = resolve(dataRootValue);
  return resolve(dataRoot, `performance-source-${runId}.json`);
}

export function performanceEvidenceRunDirectory(
  applicationRootValue: string,
  runId: string,
): string {
  assertSafeRunId(runId, "Performance evidence");
  return resolve(
    applicationRootValue,
    "test-results",
    "performance",
    runId,
  );
}

export function performanceBuildBaselinePath(
  evidenceRootValue: string,
): string {
  return resolve(evidenceRootValue, "build-baseline.json");
}

function validSummary(value: unknown): value is FileTreeManifestSummary {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<FileTreeManifestSummary>;
  return candidate.algorithm === "sha256-canonical-file-manifest-v1"
    && Number.isSafeInteger(candidate.fileCount)
    && (candidate.fileCount ?? 0) > 0
    && Number.isSafeInteger(candidate.totalBytes)
    && (candidate.totalBytes ?? -1) >= 0
    && typeof candidate.treeSha256 === "string"
    && SHA256.test(candidate.treeSha256);
}

export function readPerformanceSourceBaseline(
  path: string,
  expectedRunId: string,
): PerformanceSourceBaseline {
  const value = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (typeof value !== "object" || value === null) {
    throw new Error("Performance source baseline must be an object");
  }
  const candidate = value as Partial<PerformanceSourceBaseline>;
  if (
    candidate.schemaVersion !== PERFORMANCE_SOURCE_PROVENANCE_SCHEMA
    || candidate.runId !== expectedRunId
    || typeof candidate.measuredAt !== "string"
    || !Number.isFinite(Date.parse(candidate.measuredAt))
    || !validSummary(candidate.source)
    || candidate.launcher?.runtime !== "bun"
    || typeof candidate.launcher.version !== "string"
    || candidate.launcher.version.length === 0
  ) {
    throw new Error("Performance source baseline is malformed or mismatched");
  }
  return Object.freeze({
    ...candidate,
    source: Object.freeze({ ...candidate.source }),
    launcher: Object.freeze({ ...candidate.launcher }),
  } as PerformanceSourceBaseline);
}

export function readPerformanceBuildBaseline(
  path: string,
  expectedRunId: string,
): PerformanceBuildBaseline {
  const value = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (typeof value !== "object" || value === null) {
    throw new Error("Performance build baseline must be an object");
  }
  const candidate = value as Partial<PerformanceBuildBaseline>;
  if (
    candidate.schemaVersion !== PERFORMANCE_BUILD_PROVENANCE_SCHEMA
    || candidate.runId !== expectedRunId
    || typeof candidate.measuredAt !== "string"
    || !Number.isFinite(Date.parse(candidate.measuredAt))
    || !validSummary(candidate.build)
    || candidate.releaseCandidateEligible !== false
  ) {
    throw new Error("Performance build baseline is malformed or mismatched");
  }
  return Object.freeze({
    ...candidate,
    build: Object.freeze({ ...candidate.build }),
  } as PerformanceBuildBaseline);
}

function assertRealDirectoryChain(directoryValue: string): string {
  const directory = resolve(directoryValue);
  const parsed = parse(directory);
  const segments = directory
    .slice(parsed.root.length)
    .split(sep)
    .filter(Boolean);
  let current = parsed.root;
  for (const segment of segments) {
    current = resolve(current, segment);
    if (!existsSync(current)) {
      mkdirSync(current, { recursive: false, mode: 0o700 });
    }
    const metadata = lstatSync(current);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error(`Performance evidence path traverses a non-directory or symlink: ${current}`);
    }
  }
  return directory;
}

/**
 * Reserve a permanent run-specific evidence directory before reporters start.
 * Reusing a run ID fails before any prior artifact can be truncated.
 */
export function reserveImmutableEvidenceDirectory(
  directoryValue: string,
): void {
  const directory = resolve(directoryValue);
  const parent = assertRealDirectoryChain(dirname(directory));
  mkdirSync(directory, { recursive: false, mode: 0o700 });
  const metadata = lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("Performance evidence reservation must be a real directory");
  }
  const parentDescriptor = openSync(parent, constants.O_RDONLY);
  try {
    fsyncSync(parentDescriptor);
  } finally {
    closeSync(parentDescriptor);
  }
}

/**
 * Publish one evidence file only after its complete contents are durable. A
 * same-directory temporary inode is linked into place with no-overwrite
 * semantics and removed immediately; it is never retained as a backup.
 */
export function publishAtomicTextExclusive(
  outputPathValue: string,
  contents: string,
): void {
  const outputPath = resolve(outputPathValue);
  const directory = assertRealDirectoryChain(dirname(outputPath));
  const temporaryPath = `${outputPath}.${process.pid}.${randomUUID()}.tmp`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      temporaryPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    writeFileSync(descriptor, contents, { encoding: "utf8" });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    linkSync(temporaryPath, outputPath);
    const directoryDescriptor = openSync(directory, constants.O_RDONLY);
    try {
      fsyncSync(directoryDescriptor);
    } finally {
      closeSync(directoryDescriptor);
    }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    rmSync(temporaryPath, { force: true });
  }
}

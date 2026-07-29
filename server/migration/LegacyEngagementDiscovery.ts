import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
} from "node:fs";
import type { Stats } from "node:fs";
import { basename, extname, relative, resolve, sep } from "node:path";
import { containsHardSecret, redactLegacyText, sha256Text } from "./SecretSafety";
import {
  verifyReceiptBoundSqliteQuarantineFile,
  type ReceiptBoundSqliteQuarantineFile,
} from "./HistoricalSqliteSnapshotQuarantineMapping";

export const LEGACY_ENGAGEMENT_FILE_KINDS = [
  "recon",
  "report",
  "loot",
  "note",
  "script",
  "capture",
  "evidence",
  "log",
] as const;

export type LegacyEngagementFileKind = (typeof LEGACY_ENGAGEMENT_FILE_KINDS)[number];

export interface CanonicalLegacyRoot {
  readonly requestedPath: string;
  readonly canonicalPath: string;
  readonly physicalIdentity: string;
}

export interface LegacyRootAlias {
  readonly requestedPath: string;
  readonly canonicalPath: string;
  readonly duplicateOf: string;
  readonly physicalIdentity: string;
}

export interface CanonicalLegacyRoots {
  readonly roots: readonly CanonicalLegacyRoot[];
  readonly aliases: readonly LegacyRootAlias[];
  readonly missing: readonly string[];
}

export interface LegacyEngagementFile {
  readonly absolutePath: string;
  readonly relativePath: string;
  readonly kind: LegacyEngagementFileKind;
  readonly contentClass: "text" | "structured" | "image" | "document" | "binary";
  readonly mediaType?: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
}

export type LegacyEngagementExclusionCategory =
  | "unsafe_name"
  | "sensitive_content"
  | "oversized"
  | "symlink"
  | "unsupported"
  | "deferred_recent"
  | "changed"
  | "snapshot_no_semantic_records";

export const SETTLED_SOURCE_DEFERRED_REASON =
  "source modified after the settled-source cutoff; deferred to a later migration" as const;
export const EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON =
  "source was explicitly verified active and deferred to a later migration" as const;

export interface LegacyEngagementDeferredSource {
  readonly absolutePath: string;
  readonly reason:
    | typeof SETTLED_SOURCE_DEFERRED_REASON
    | typeof EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly sourceDevice: number;
  readonly sourceInode: number;
}

/**
 * Content-free provenance for a source object that policy excludes from
 * canonical artifacts, evidence, and reusable memory. `quarantineId` is an
 * opaque fingerprint of the path relative to its engagement; the relative
 * path itself is intentionally not written into protected manifests.
 */
export interface LegacyEngagementExclusion {
  readonly absolutePath: string;
  readonly engagementDirectory?: string;
  readonly quarantineId: string;
  readonly category: LegacyEngagementExclusionCategory;
  readonly reason: string;
  readonly sourceKind: "regular_file" | "symlink" | "directory" | "unavailable";
  readonly sourceSha256?: string;
  readonly byteSize?: number;
  readonly createdAt?: string;
  readonly modifiedAt?: string;
  /** Sealed review receipt that authorizes only content-free quarantine custody. */
  readonly dispositionReceiptSha256?: string;
  readonly normalizedSnapshotSha256?: string;
  readonly quarantineMappingId?: string;
}

export interface LegacyEngagementManifest {
  readonly id: string;
  readonly root: string;
  readonly rootIdentity: string;
  readonly engagementDirectory: string;
  readonly engagementName: string;
  readonly engagementKey: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly files: readonly LegacyEngagementFile[];
  readonly quarantined: readonly LegacyEngagementExclusion[];
}

export interface LegacyEngagementDiscovery {
  readonly roots: CanonicalLegacyRoots;
  readonly manifests: readonly LegacyEngagementManifest[];
  readonly excluded: readonly LegacyEngagementExclusion[];
  readonly deferred: readonly LegacyEngagementDeferredSource[];
}

export interface LegacyEngagementDiscoveryOptions {
  /**
   * `children` treats each safe top-level directory as an engagement. `self`
   * treats every configured root as one engagement and is intended for an
   * operator-selected engagement directory such as `.../boxes/ReaperTwo`.
   */
  readonly rootMode?: "children" | "self";
  /** Exact cutoff calculated once by the migration coordinator. */
  readonly settledSourceCutoffAt?: string;
  /** Canonical paths and inode identities admitted by the coordinator's active-source gate. */
  readonly explicitActiveSourceDeferrals?: ReadonlyMap<string, {
    readonly sourceDevice: number;
    readonly sourceInode: number;
  }>;
  /** Exact source files covered by a reviewed empty SQLite snapshot. */
  readonly receiptBoundSqliteQuarantines?: ReadonlyMap<string, ReceiptBoundSqliteQuarantineFile>;
  /**
   * Hash-pinned delta execution only: inspect these exact paths rather than
   * walking every file below the engagement roots.
   */
  readonly exactSourcePaths?: readonly string[];
}

const DENIED_DIRECTORY = new Set([
  ".git", "node_modules", "dist", "build", "cache", "tmp", "backup", "backups",
  ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
]);
const RESERVED_ROOT_DIRECTORY = new Set([
  "artifacts", "artifact", "logs", "llm-logs", "session-logs", "sessions", "runtime",
  "memory", "training", "backups", "backup", "tmp", "cache",
]);
const SENSITIVE_NAME = /(?:^|[._-])(?:auth|credential|credentials|secret|secrets|token|tokens|key|keys|cookie|cookies|password|passwd|shadow|sam|ntds|ticket|tickets|hash|hashes|lootdump|shell[-_]?snapshot|\.env)(?:$|[._-])/iu;
const PRIVATE_KEY_NAME = /^(?:id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx|keystore|jks)|request_dump_.*)$/iu;
const SENSITIVE_DIRECTORY = new Set(["credential", "credentials", "creds", "secret", "secrets", "tokens", "keys"]);
const SAFE_ENGAGEMENT_NAME = /^[\p{L}\p{N}][\p{L}\p{N} ._@+-]{0,199}$/u;
const TEXT_EXTENSIONS = new Set([".txt", ".md", ".json", ".jsonl", ".xml", ".csv", ".yaml", ".yml", ".html", ".htm", ".nmap", ".gnmap", ".log", ".py", ".sh", ".ps1", ".js", ".ts", ".rb", ".go", ".c", ".cpp", ".conf", ".ini"]);
const MAX_TEXT_INSPECTION_BYTES = 2 * 1024 * 1024;

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function physicalIdentity(path: string): string {
  const state = statSync(path);
  return `${state.dev}:${state.ino}`;
}

/** Resolve configured roots once and collapse bind-mount or lexical aliases by device/inode. */
export function canonicalizeLegacySourceRoots(sourceRoots: readonly string[]): CanonicalLegacyRoots {
  const roots: CanonicalLegacyRoot[] = [];
  const aliases: LegacyRootAlias[] = [];
  const missing: string[] = [];
  const seen = new Map<string, CanonicalLegacyRoot>();
  for (const requested of sourceRoots) {
    const requestedPath = resolve(requested);
    let canonicalPath: string;
    try { canonicalPath = realpathSync(requestedPath); }
    catch {
      missing.push(requestedPath);
      continue;
    }
    const lexical = lstatSync(canonicalPath);
    if (!lexical.isDirectory()) {
      missing.push(requestedPath);
      continue;
    }
    const identity = physicalIdentity(canonicalPath);
    const prior = seen.get(identity);
    if (prior) {
      aliases.push({ requestedPath, canonicalPath, duplicateOf: prior.canonicalPath, physicalIdentity: identity });
      continue;
    }
    const root = { requestedPath, canonicalPath, physicalIdentity: identity };
    roots.push(root);
    seen.set(identity, root);
  }
  return { roots, aliases, missing };
}

function normalizedSegments(path: string): string[] {
  return path.split(/[\\/]+/u).filter(Boolean).map((part) => part.toLowerCase());
}

function hasSensitivePath(relativePath: string): boolean {
  const segments = normalizedSegments(relativePath);
  return segments.slice(0, -1).some((segment) => SENSITIVE_DIRECTORY.has(segment));
}

function classify(relativePath: string): LegacyEngagementFileKind | undefined {
  const segments = normalizedSegments(relativePath);
  const filename = segments.at(-1) ?? "";
  const extension = extname(filename);
  const directory = new Set(segments.slice(0, -1));
  if (directory.has("logs") || directory.has("log") || directory.has("session-logs") || directory.has("llm-logs") || extension === ".log" || /(?:stdout|stderr)(?:\.|$)/u.test(filename)) return "log";
  if (directory.has("evidence") || directory.has("proof") || directory.has("proofs")) return "evidence";
  if (directory.has("screenshots") || directory.has("screenshot") || directory.has("captures") || directory.has("capture") || [".png", ".jpg", ".jpeg", ".webp", ".avif"].includes(extension)) return "capture";
  if (directory.has("reports") || directory.has("report") || /^report(?:[._-]|$)/u.test(filename) || [".pdf", ".docx"].includes(extension)) return "report";
  if (directory.has("scans") || directory.has("scan") || directory.has("recon") || directory.has("nmap") || [".nmap", ".gnmap"].includes(extension)) return "recon";
  if (directory.has("loot")) return "loot";
  if (directory.has("scripts") || directory.has("script") || directory.has("exploit") || directory.has("exploits") || [".py", ".sh", ".ps1", ".rb", ".go", ".c", ".cpp"].includes(extension)) return "script";
  if (directory.has("notes") || directory.has("note") || directory.has("writeups") || directory.has("writeup") || [".md", ".txt"].includes(extension)) return "note";
  return undefined;
}

function contentMetadata(path: string): Pick<LegacyEngagementFile, "contentClass" | "mediaType"> {
  const extension = extname(path).toLowerCase();
  const mediaTypes: Record<string, string> = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".avif": "image/avif",
    ".pdf": "application/pdf", ".html": "text/html", ".htm": "text/html", ".json": "application/json", ".jsonl": "application/x-ndjson",
    ".xml": "application/xml", ".csv": "text/csv", ".md": "text/markdown", ".txt": "text/plain", ".log": "text/plain",
  };
  if ([".png", ".jpg", ".jpeg", ".webp", ".avif"].includes(extension)) return { contentClass: "image", mediaType: mediaTypes[extension] };
  if ([".pdf", ".docx"].includes(extension)) return { contentClass: "document", mediaType: mediaTypes[extension] ?? "application/octet-stream" };
  if ([".json", ".jsonl", ".xml", ".csv", ".yaml", ".yml", ".nmap", ".gnmap"].includes(extension)) return { contentClass: "structured", mediaType: mediaTypes[extension] ?? "text/plain" };
  if (TEXT_EXTENSIONS.has(extension)) return { contentClass: "text", mediaType: mediaTypes[extension] ?? "text/plain" };
  return { contentClass: "binary", mediaType: "application/octet-stream" };
}

function isInside(root: string, candidate: string): boolean {
  const value = relative(root, candidate);
  return value !== ".." && !value.startsWith(`..${sep}`);
}

function quarantineId(engagementDirectory: string, candidate: string): string {
  const normalized = relative(engagementDirectory, candidate).split(sep).join("/").normalize("NFKC");
  return `quarantine_${sha256Text(normalized).slice(0, 40)}`;
}

function unavailableExclusion(input: {
  engagementDirectory: string;
  candidate: string;
  category?: LegacyEngagementExclusionCategory;
  reason: string;
  sourceKind?: LegacyEngagementExclusion["sourceKind"];
}): LegacyEngagementExclusion {
  let state: Stats | undefined;
  try { state = lstatSync(input.candidate); } catch { /* provenance remains intentionally partial */ }
  return {
    absolutePath: input.candidate,
    engagementDirectory: input.engagementDirectory,
    quarantineId: quarantineId(input.engagementDirectory, input.candidate),
    category: input.category ?? "changed",
    reason: input.reason,
    sourceKind: input.sourceKind ?? "unavailable",
    ...(state ? {
      byteSize: state.size,
      createdAt: state.birthtime.toISOString(),
      modifiedAt: state.mtime.toISOString(),
    } : {}),
  };
}

function symlinkExclusion(engagementDirectory: string, candidate: string): LegacyEngagementExclusion {
  try {
    const before = lstatSync(candidate);
    const targetFingerprint = sha256Text(`symlink\0${readlinkSync(candidate)}`);
    const after = lstatSync(candidate);
    if (
      !before.isSymbolicLink() || !after.isSymbolicLink()
      || before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
    ) {
      return unavailableExclusion({
        engagementDirectory,
        candidate,
        reason: "symbolic link changed during non-dereferencing discovery",
        sourceKind: "symlink",
      });
    }
    return {
      absolutePath: candidate,
      engagementDirectory,
      quarantineId: quarantineId(engagementDirectory, candidate),
      category: "symlink",
      reason: "symbolic links are not dereferenced or imported",
      sourceKind: "symlink",
      sourceSha256: targetFingerprint,
      byteSize: after.size,
      createdAt: after.birthtime.toISOString(),
      modifiedAt: after.mtime.toISOString(),
    };
  } catch {
    return unavailableExclusion({
      engagementDirectory,
      candidate,
      reason: "symbolic link could not be captured safely without dereferencing it",
      sourceKind: "symlink",
    });
  }
}

interface InspectedRegularFile {
  readonly state: Stats;
  readonly sha256: string;
  readonly prefix: string;
  readonly boundedText?: string;
}

/** Open with O_NOFOLLOW and inspect/hash one stable inode without pathname reopens. */
function inspectRegularFile(candidate: string, captureBoundedText: boolean): InspectedRegularFile {
  const descriptor = openSync(candidate, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile()) throw new Error("not a regular file");
    const hash = createHash("sha256");
    const chunks: Buffer[] | undefined = captureBoundedText && before.size <= MAX_TEXT_INSPECTION_BYTES ? [] : undefined;
    const prefix = Buffer.allocUnsafe(Math.min(65_536, Math.max(0, before.size)));
    let prefixLength = 0;
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (true) {
      const length = readSync(descriptor, buffer, 0, buffer.length, position);
      if (!length) break;
      const chunk = buffer.subarray(0, length);
      hash.update(chunk);
      chunks?.push(Buffer.from(chunk));
      if (prefixLength < prefix.length) {
        const copied = Math.min(prefix.length - prefixLength, length);
        chunk.copy(prefix, prefixLength, 0, copied);
        prefixLength += copied;
      }
      position += length;
    }
    const after = fstatSync(descriptor);
    const pathname = lstatSync(candidate);
    if (
      !pathname.isFile()
      || before.dev !== after.dev || before.ino !== after.ino
      || before.dev !== pathname.dev || before.ino !== pathname.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
    ) throw new Error("source changed during inspection");
    return {
      state: after,
      sha256: hash.digest("hex"),
      prefix: prefix.subarray(0, prefixLength).toString("utf8"),
      ...(chunks ? { boundedText: Buffer.concat(chunks).toString("utf8") } : {}),
    };
  } finally {
    closeSync(descriptor);
  }
}

function exclusionFromInspection(input: {
  engagementDirectory: string;
  candidate: string;
  inspected: InspectedRegularFile;
  category: LegacyEngagementExclusionCategory;
  reason: string;
}): LegacyEngagementExclusion {
  return {
    absolutePath: input.candidate,
    engagementDirectory: input.engagementDirectory,
    quarantineId: quarantineId(input.engagementDirectory, input.candidate),
    category: input.category,
    reason: input.reason,
    sourceKind: "regular_file",
    sourceSha256: input.inspected.sha256,
    byteSize: input.inspected.state.size,
    createdAt: input.inspected.state.birthtime.toISOString(),
    modifiedAt: input.inspected.state.mtime.toISOString(),
  };
}

async function discoverManifest(
  root: CanonicalLegacyRoot,
  engagementDirectory: string,
  engagementName: string,
  excluded: LegacyEngagementDiscovery["excluded"][number][],
  deferred: LegacyEngagementDeferredSource[],
  settledSourceCutoffMs?: number,
  explicitActiveSourceDeferrals: ReadonlyMap<string, {
    readonly sourceDevice: number;
    readonly sourceInode: number;
  }> = new Map(),
  receiptBoundSqliteQuarantines: ReadonlyMap<string, ReceiptBoundSqliteQuarantineFile> = new Map(),
  exactSourcePaths?: readonly string[],
): Promise<LegacyEngagementManifest> {
  const files: LegacyEngagementFile[] = [];
  const quarantined: LegacyEngagementExclusion[] = [];
  const exclude = (item: LegacyEngagementExclusion): void => {
    quarantined.push(item);
    excluded.push(item);
  };
  const candidates: string[] = [];
  if (exactSourcePaths !== undefined) {
    for (const requested of exactSourcePaths) {
      const candidate = resolve(requested);
      if (!isInside(engagementDirectory, candidate) || candidate === engagementDirectory) continue;
      let state;
      try { state = lstatSync(candidate); }
      catch { throw new Error("Exact engagement source admission disappeared before discovery"); }
      if (state.isSymbolicLink()) {
        exclude(symlinkExclusion(engagementDirectory, candidate));
        continue;
      }
      if (!state.isFile()) throw new Error("Exact engagement source admission must be a regular file");
      const segments = relative(engagementDirectory, candidate).split(sep);
      if (segments.slice(0, -1).some((segment) => DENIED_DIRECTORY.has(segment.toLowerCase()))) {
        throw new Error("Exact engagement source admission crosses a denied directory");
      }
      candidates.push(candidate);
    }
  } else {
    const pending = [engagementDirectory];
    while (pending.length) {
      const directory = pending.pop()!;
      for (const child of readdirSync(directory, { withFileTypes: true })) {
        const candidate = resolve(directory, child.name);
        if (!isInside(engagementDirectory, candidate)) continue;
        if (child.isSymbolicLink()) {
          exclude(symlinkExclusion(engagementDirectory, candidate));
          continue;
        }
        if (child.isDirectory()) {
          if (!DENIED_DIRECTORY.has(child.name.toLowerCase())) pending.push(candidate);
          continue;
        }
        if (child.isFile()) candidates.push(candidate);
      }
    }
  }
  for (const candidate of candidates.sort()) {
      const relativePath = relative(engagementDirectory, candidate).split(sep).join("/");
      const sqliteQuarantine = receiptBoundSqliteQuarantines.get(candidate);
      if (sqliteQuarantine) {
        verifyReceiptBoundSqliteQuarantineFile(sqliteQuarantine);
        const state = lstatSync(candidate);
        exclude({
          absolutePath: candidate,
          engagementDirectory,
          quarantineId: quarantineId(engagementDirectory, candidate),
          category: "snapshot_no_semantic_records",
          reason: "A sealed normalized SQLite snapshot proved this exact source bundle has the reviewed SQLMap storage schema and zero semantic rows; retain source custody without creating reusable knowledge.",
          sourceKind: "regular_file",
          sourceSha256: sqliteQuarantine.sha256,
          byteSize: sqliteQuarantine.byteSize,
          createdAt: state.birthtime.toISOString(),
          modifiedAt: sqliteQuarantine.modifiedAt,
          dispositionReceiptSha256: sqliteQuarantine.snapshotReceiptSha256,
          normalizedSnapshotSha256: sqliteQuarantine.normalizedSnapshotSha256,
          quarantineMappingId: sqliteQuarantine.mappingId,
        });
        continue;
      }
      const kind = classify(relativePath);
      const sensitivePath = hasSensitivePath(relativePath)
        || SENSITIVE_NAME.test(basename(candidate))
        || PRIVATE_KEY_NAME.test(basename(candidate));
      if (!kind && !sensitivePath) continue;
      const explicitDeferral = explicitActiveSourceDeferrals.get(candidate);
      if (explicitDeferral) {
        try {
          const state = lstatSync(candidate);
          if (
            state.isFile() && !state.isSymbolicLink()
            && state.dev === explicitDeferral.sourceDevice
            && state.ino === explicitDeferral.sourceInode
          ) {
            deferred.push({
              absolutePath: candidate,
              reason: EXPLICIT_ACTIVE_SOURCE_DEFERRED_REASON,
              byteSize: state.size,
              modifiedAt: state.mtime.toISOString(),
              sourceDevice: state.dev,
              sourceInode: state.ino,
            });
            continue;
          }
        } catch {
          // The unchanged inspection path below records a fail-closed changed
          // exclusion if the file disappeared after coordinator validation.
        }
        throw new Error("Explicitly deferred source changed after active-source validation");
      }
      if (settledSourceCutoffMs !== undefined) {
        try {
          const state = lstatSync(candidate);
          if (state.isFile() && state.mtimeMs > settledSourceCutoffMs) {
            deferred.push({
              absolutePath: candidate,
              reason: SETTLED_SOURCE_DEFERRED_REASON,
              byteSize: state.size,
              modifiedAt: state.mtime.toISOString(),
              sourceDevice: state.dev,
              sourceInode: state.ino,
            });
            continue;
          }
        } catch {
          // The unchanged inspection path below records a fail-closed changed
          // exclusion if the file disappeared during the boundary check.
        }
      }
      let inspected: InspectedRegularFile;
      try { inspected = inspectRegularFile(candidate, TEXT_EXTENSIONS.has(extname(candidate).toLowerCase())); }
      catch {
        exclude(unavailableExclusion({
          engagementDirectory,
          candidate,
          reason: "source could not be captured as one stable regular file during discovery",
        }));
        continue;
      }
      if (sensitivePath) {
        exclude(exclusionFromInspection({
          engagementDirectory,
          candidate,
          inspected,
          category: "unsafe_name",
          reason: "sensitive filename is quarantined from canonical import",
        }));
        continue;
      }
      if (!kind) continue;
      if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(inspected.prefix)) {
        exclude(exclusionFromInspection({
          engagementDirectory,
          candidate,
          inspected,
          category: "sensitive_content",
          reason: "private-key material is quarantined from canonical import",
        }));
        continue;
      }
      if (TEXT_EXTENSIONS.has(extname(candidate).toLowerCase()) && inspected.state.size > MAX_TEXT_INSPECTION_BYTES) {
        exclude(exclusionFromInspection({
          engagementDirectory,
          candidate,
          inspected,
          category: "oversized",
          reason: "text file exceeds the bounded secret-inspection limit and is quarantined",
        }));
        continue;
      }
      if (inspected.boundedText !== undefined) {
        const unsafe = containsHardSecret(inspected.boundedText)
          || redactLegacyText(inspected.boundedText, inspected.boundedText.length + 1) !== inspected.boundedText;
        if (unsafe) {
          exclude(exclusionFromInspection({
            engagementDirectory,
            candidate,
            inspected,
            category: "sensitive_content",
            reason: "credential or sensitive material was detected during bounded inspection",
          }));
          continue;
        }
      }
      files.push({
        absolutePath: candidate,
        relativePath,
        kind,
        ...contentMetadata(candidate),
        sha256: inspected.sha256,
        byteSize: inspected.state.size,
        modifiedAt: inspected.state.mtime.toISOString(),
      });
  }
  files.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  quarantined.sort((left, right) => left.quarantineId.localeCompare(right.quarantineId));
  const engagementKey = sha256Text(`${root.physicalIdentity}\0${engagementName.normalize("NFKC")}`);
  const manifestBody = canonicalJson({
    schemaVersion: 2,
    engagementKey,
    files: files.map((file) => ({
      relativePath: file.relativePath,
      kind: file.kind,
      contentClass: file.contentClass,
      mediaType: file.mediaType ?? null,
      sha256: file.sha256,
      byteSize: file.byteSize,
      modifiedAt: file.modifiedAt,
    })),
    quarantined: quarantined.map((item) => ({
      quarantineId: item.quarantineId,
      category: item.category,
      sourceKind: item.sourceKind,
      sourceSha256: item.sourceSha256 ?? null,
      byteSize: item.byteSize ?? null,
      createdAt: item.createdAt ?? null,
      modifiedAt: item.modifiedAt ?? null,
      dispositionReceiptSha256: item.dispositionReceiptSha256 ?? null,
      normalizedSnapshotSha256: item.normalizedSnapshotSha256 ?? null,
      quarantineMappingId: item.quarantineMappingId ?? null,
    })),
  });
  const modifiedAt = [...files.map((file) => file.modifiedAt), ...quarantined.flatMap((item) => item.modifiedAt ? [item.modifiedAt] : [])]
    .reduce((latest, value) => value > latest ? value : latest, statSync(engagementDirectory).mtime.toISOString());
  return {
    id: `legacy_engagement_${engagementKey.slice(0, 40)}`,
    root: root.canonicalPath,
    rootIdentity: root.physicalIdentity,
    engagementDirectory,
    engagementName,
    engagementKey,
    sha256: sha256Text(manifestBody),
    byteSize: Buffer.byteLength(manifestBody, "utf8"),
    modifiedAt,
    files,
    quarantined,
  };
}

/** Discover stable, secret-safe engagement manifests from parent roots or explicit engagement roots. */
export async function discoverLegacyEngagements(
  sourceRoots: readonly string[],
  options: LegacyEngagementDiscoveryOptions = {},
): Promise<LegacyEngagementDiscovery> {
  const roots = canonicalizeLegacySourceRoots(sourceRoots);
  const excluded: LegacyEngagementDiscovery["excluded"][number][] = [];
  const deferred: LegacyEngagementDeferredSource[] = [];
  const manifests: LegacyEngagementManifest[] = [];
  const rootMode = options.rootMode ?? "children";
  const exactSourcePaths = options.exactSourcePaths === undefined
    ? undefined
    : options.exactSourcePaths.map((path) => resolve(path));
  if (exactSourcePaths && new Set(exactSourcePaths).size !== exactSourcePaths.length) {
    throw new Error("Exact engagement source admission contains duplicate paths");
  }
  const exactPathsAccountedFor = new Set<string>();
  const settledSourceCutoffMs = options.settledSourceCutoffAt === undefined
    ? undefined
    : Date.parse(options.settledSourceCutoffAt);
  if (settledSourceCutoffMs !== undefined && !Number.isFinite(settledSourceCutoffMs)) {
    throw new TypeError("Settled-source cutoff must be a valid timestamp");
  }
  for (const root of roots.roots) {
    const rootExactPaths = exactSourcePaths?.filter((path) => {
      if (!isInside(root.canonicalPath, path) || path === root.canonicalPath) return false;
      exactPathsAccountedFor.add(path);
      return true;
    });
    if (rootMode === "self") {
      if (rootExactPaths !== undefined && rootExactPaths.length === 0) continue;
      const engagementName = basename(root.canonicalPath);
      if (!SAFE_ENGAGEMENT_NAME.test(engagementName)) {
        excluded.push({
          absolutePath: root.canonicalPath,
          quarantineId: `quarantine_${sha256Text(root.canonicalPath).slice(0, 40)}`,
          category: "unsafe_name",
          reason: "engagement directory name is not safe",
          sourceKind: "directory",
        });
        continue;
      }
      manifests.push(await discoverManifest(
        root,
        root.canonicalPath,
        engagementName,
        excluded,
        deferred,
        settledSourceCutoffMs,
        options.explicitActiveSourceDeferrals,
        options.receiptBoundSqliteQuarantines,
        rootExactPaths,
      ));
      continue;
    }
    const entries = rootExactPaths === undefined
      ? readdirSync(root.canonicalPath, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))
      : [...new Set(rootExactPaths.flatMap((path) => {
        const first = relative(root.canonicalPath, path).split(sep)[0];
        if (!first) return [];
        const engagementDirectory = resolve(root.canonicalPath, first);
        try {
          const state = lstatSync(engagementDirectory);
          return state.isDirectory() && !state.isSymbolicLink() ? [first] : [];
        } catch { return []; }
      }))].sort().map((name) => ({
        name,
        isSymbolicLink: () => false,
        isDirectory: () => true,
      }));
    for (const entry of entries) {
      const engagementDirectory = resolve(root.canonicalPath, entry.name);
      if (entry.isSymbolicLink()) {
        excluded.push(symlinkExclusion(root.canonicalPath, engagementDirectory));
        continue;
      }
      if (!entry.isDirectory() || entry.name.startsWith(".") || RESERVED_ROOT_DIRECTORY.has(entry.name.toLowerCase())) continue;
      if (!SAFE_ENGAGEMENT_NAME.test(entry.name)) {
        excluded.push({
          absolutePath: engagementDirectory,
          quarantineId: `quarantine_${sha256Text(entry.name.normalize("NFKC")).slice(0, 40)}`,
          category: "unsafe_name",
          reason: "engagement directory name is not safe",
          sourceKind: "directory",
        });
        continue;
      }
      manifests.push(await discoverManifest(
        root,
        engagementDirectory,
        entry.name,
        excluded,
        deferred,
        settledSourceCutoffMs,
        options.explicitActiveSourceDeferrals,
        options.receiptBoundSqliteQuarantines,
        rootExactPaths?.filter((path) => isInside(engagementDirectory, path)),
      ));
    }
  }
  if (exactSourcePaths !== undefined && exactPathsAccountedFor.size !== exactSourcePaths.length) {
    throw new Error("Exact engagement source admission is not contained by the configured roots");
  }
  manifests.sort((left, right) => left.engagementKey.localeCompare(right.engagementKey));
  deferred.sort((left, right) => left.absolutePath.localeCompare(right.absolutePath));
  return { roots, manifests, excluded, deferred };
}

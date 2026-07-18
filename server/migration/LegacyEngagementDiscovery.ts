import { createHash } from "node:crypto";
import {
  createReadStream,
  lstatSync,
  openSync,
  closeSync,
  readSync,
  readdirSync,
  realpathSync,
  statSync,
  readFileSync,
} from "node:fs";
import { basename, extname, relative, resolve, sep } from "node:path";
import { containsHardSecret, redactLegacyText, sha256Text } from "./SecretSafety";

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
}

export interface LegacyEngagementDiscovery {
  readonly roots: CanonicalLegacyRoots;
  readonly manifests: readonly LegacyEngagementManifest[];
  readonly excluded: readonly {
    readonly absolutePath: string;
    readonly category: "unsafe_name" | "sensitive_content" | "symlink" | "unsupported" | "changed";
    readonly reason: string;
  }[];
}

export interface LegacyEngagementDiscoveryOptions {
  /**
   * `children` treats each safe top-level directory as an engagement. `self`
   * treats every configured root as one engagement and is intended for an
   * operator-selected engagement directory such as `.../boxes/ReaperTwo`.
   */
  readonly rootMode?: "children" | "self";
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

async function hashFile(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
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

function beginsWithPrivateKey(path: string): boolean {
  const descriptor = openSync(path, "r");
  try {
    const buffer = Buffer.allocUnsafe(65_536);
    const length = readSync(descriptor, buffer, 0, buffer.length, 0);
    return /-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(buffer.subarray(0, length).toString("utf8"));
  } finally { closeSync(descriptor); }
}

function unsafeTextContent(path: string, size: number): string | undefined {
  const extension = extname(path).toLowerCase();
  if (!TEXT_EXTENSIONS.has(extension)) return undefined;
  if (size > MAX_TEXT_INSPECTION_BYTES) return "text file exceeds the bounded secret-inspection limit";
  const text = readFileSync(path, "utf8");
  if (containsHardSecret(text)) return "secret-bearing text is quarantined from reusable import";
  const redacted = redactLegacyText(text, text.length + 1);
  if (redacted !== text) return "credential or sensitive material was detected during bounded inspection";
  return undefined;
}

function isInside(root: string, candidate: string): boolean {
  const value = relative(root, candidate);
  return value !== ".." && !value.startsWith(`..${sep}`);
}

async function discoverManifest(
  root: CanonicalLegacyRoot,
  engagementDirectory: string,
  engagementName: string,
  excluded: LegacyEngagementDiscovery["excluded"][number][],
): Promise<LegacyEngagementManifest> {
  const files: LegacyEngagementFile[] = [];
  const pending = [engagementDirectory];
  while (pending.length) {
    const directory = pending.pop()!;
    for (const child of readdirSync(directory, { withFileTypes: true })) {
      const candidate = resolve(directory, child.name);
      if (!isInside(engagementDirectory, candidate)) continue;
      if (child.isSymbolicLink()) {
        excluded.push({ absolutePath: candidate, category: "symlink", reason: "symbolic links are not imported" });
        continue;
      }
      if (child.isDirectory()) {
        if (!DENIED_DIRECTORY.has(child.name.toLowerCase())) pending.push(candidate);
        continue;
      }
      if (!child.isFile()) continue;
      const relativePath = relative(engagementDirectory, candidate).split(sep).join("/");
      const kind = classify(relativePath);
      if (!kind) continue;
      if (SENSITIVE_NAME.test(basename(candidate)) || PRIVATE_KEY_NAME.test(basename(candidate))) {
        excluded.push({ absolutePath: candidate, category: "unsafe_name", reason: "sensitive filename is quarantined" });
        continue;
      }
      let before;
      try { before = statSync(candidate); }
      catch {
        excluded.push({ absolutePath: candidate, category: "changed", reason: "source changed during discovery" });
        continue;
      }
      if (beginsWithPrivateKey(candidate)) {
        excluded.push({ absolutePath: candidate, category: "sensitive_content", reason: "private-key material is quarantined" });
        continue;
      }
      const contentProblem = unsafeTextContent(candidate, before.size);
      if (contentProblem) {
        excluded.push({ absolutePath: candidate, category: "sensitive_content", reason: contentProblem });
        continue;
      }
      const sha256 = await hashFile(candidate);
      const after = statSync(candidate);
      if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
        excluded.push({ absolutePath: candidate, category: "changed", reason: "source changed while it was hashed" });
        continue;
      }
      files.push({
        absolutePath: candidate,
        relativePath,
        kind,
        ...contentMetadata(candidate),
        sha256,
        byteSize: after.size,
        modifiedAt: after.mtime.toISOString(),
      });
    }
  }
  files.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  const engagementKey = sha256Text(`${root.physicalIdentity}\0${engagementName.normalize("NFKC")}`);
  const manifestBody = canonicalJson({
    schemaVersion: 1,
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
  });
  const modifiedAt = files.reduce(
    (latest, file) => file.modifiedAt > latest ? file.modifiedAt : latest,
    statSync(engagementDirectory).mtime.toISOString(),
  );
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
  };
}

/** Discover stable, secret-safe engagement manifests from parent roots or explicit engagement roots. */
export async function discoverLegacyEngagements(
  sourceRoots: readonly string[],
  options: LegacyEngagementDiscoveryOptions = {},
): Promise<LegacyEngagementDiscovery> {
  const roots = canonicalizeLegacySourceRoots(sourceRoots);
  const excluded: LegacyEngagementDiscovery["excluded"][number][] = [];
  const manifests: LegacyEngagementManifest[] = [];
  const rootMode = options.rootMode ?? "children";
  for (const root of roots.roots) {
    if (rootMode === "self") {
      const engagementName = basename(root.canonicalPath);
      if (!SAFE_ENGAGEMENT_NAME.test(engagementName)) {
        excluded.push({ absolutePath: root.canonicalPath, category: "unsafe_name", reason: "engagement directory name is not safe" });
        continue;
      }
      manifests.push(await discoverManifest(root, root.canonicalPath, engagementName, excluded));
      continue;
    }
    const entries = readdirSync(root.canonicalPath, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const engagementDirectory = resolve(root.canonicalPath, entry.name);
      if (entry.isSymbolicLink()) {
        excluded.push({ absolutePath: engagementDirectory, category: "symlink", reason: "symbolic engagement roots are never imported" });
        continue;
      }
      if (!entry.isDirectory() || entry.name.startsWith(".") || RESERVED_ROOT_DIRECTORY.has(entry.name.toLowerCase())) continue;
      if (!SAFE_ENGAGEMENT_NAME.test(entry.name)) {
        excluded.push({ absolutePath: engagementDirectory, category: "unsafe_name", reason: "engagement directory name is not safe" });
        continue;
      }
      manifests.push(await discoverManifest(root, engagementDirectory, entry.name, excluded));
    }
  }
  manifests.sort((left, right) => left.engagementKey.localeCompare(right.engagementKey));
  return { roots, manifests, excluded };
}

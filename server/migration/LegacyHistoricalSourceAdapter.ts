import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync,
  statSync,
} from "node:fs";
import { basename, extname, relative, resolve, sep } from "node:path";
import { createDatabaseConnection, type SqliteDatabase } from "../db";
import {
  containsHardSecret,
  redactRecursively,
  sha256Text,
} from "./SecretSafety";

export const LEGACY_HISTORICAL_SOURCE_KINDS = [
  "grok_nested_session",
  "claude_project_jsonl",
  "session_archive",
  "session_system_text",
  "root_client_log",
  "mission_board_sqlite",
  "codex_sqlite",
  "obsidian_note",
  "prior_v2_export",
  "prior_v2_sqlite",
] as const;

export type LegacyHistoricalSourceKind = (typeof LEGACY_HISTORICAL_SOURCE_KINDS)[number];

export interface LegacyHistoricalSource {
  readonly id: string;
  readonly kind: LegacyHistoricalSourceKind;
  /** Private discovery metadata. Never copy this field into reusable memory. */
  readonly canonicalPath: string;
  readonly root: string;
  readonly physicalIdentity: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
}

export interface LegacyHistoricalExclusion {
  readonly id: string;
  readonly pathFingerprint: string;
  readonly category:
    | "missing"
    | "alias"
    | "duplicate_inode"
    | "duplicate_content"
    | "canonical_database"
    | "unsafe_sqlite"
    | "oversized"
    | "unsupported"
    | "changed"
    | "limit_exceeded";
  readonly reason: string;
  readonly duplicateOf?: string;
  readonly sourceSha256?: string;
}

export interface LegacyHistoricalDiscovery {
  readonly schemaVersion: "ti_scale.legacy_historical_manifest/v1";
  /** Hash-bound to source identities, content hashes, sizes and exclusions. */
  readonly manifestHash: string;
  readonly verificationState: "verified";
  readonly sources: readonly LegacyHistoricalSource[];
  readonly excluded: readonly LegacyHistoricalExclusion[];
  readonly rootAliases: readonly {
    readonly requestedPath: string;
    readonly canonicalPath: string;
    readonly duplicateOf: string;
    readonly physicalIdentity: string;
  }[];
}

export interface LegacyHistoricalDiscoveryOptions {
  readonly roots: readonly string[];
  /** Required fail-closed exclusion set for the active Ti-Scale database. */
  readonly canonicalDatabasePaths: readonly string[];
  readonly maximumFiles?: number;
  readonly maximumDepth?: number;
  readonly maximumTextBytes?: number;
  readonly maximumSqliteBytes?: number;
}

export interface LegacyPrivateHistoryCandidate {
  readonly id: string;
  readonly sourceId: string;
  readonly sourceKind: LegacyHistoricalSourceKind;
  readonly itemKey: string;
  readonly contentHash: string;
  readonly dataClass: "private_operational_history" | "private_memory_candidate";
  readonly sensitivity: "private";
  readonly disclosure: "local_only";
  readonly lifecycle: "candidate";
  readonly reusableMemoryEligible: false;
  readonly projectionPolicy: {
    readonly mode: "attack_knowledge_only";
    readonly forbiddenReusableFields: readonly [
      "target",
      "ip_address",
      "source_path",
      "mission",
      "run",
      "journey",
      "credential",
      "secret",
    ];
  };
  readonly title: string;
  readonly summary: string;
  readonly occurredAt?: string;
  readonly privatePayload: unknown;
}

export interface LegacyHistoricalQuarantine {
  readonly id: string;
  readonly sourceId: string;
  readonly itemKeyHash: string;
  readonly category: "malformed" | "secret_bearing" | "record_limit" | "changed" | "unsupported_schema";
  readonly reason: string;
}

export interface LegacyHistoricalParseResult {
  readonly sourceId: string;
  readonly candidates: readonly LegacyPrivateHistoryCandidate[];
  readonly quarantined: readonly LegacyHistoricalQuarantine[];
}

export interface LegacyHistoricalParseOptions {
  readonly maximumRecords?: number;
  readonly maximumLineBytes?: number;
}

const DEFAULT_MAX_FILES = 10_000;
const DEFAULT_MAX_DEPTH = 12;
const DEFAULT_MAX_TEXT_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_SQLITE_BYTES = 256 * 1024 * 1024;
const DEFAULT_MAX_RECORDS = 5_000;
const DEFAULT_MAX_LINE_BYTES = 512 * 1024;
const DENIED_DIRECTORY = new Set([
  ".git", ".obsidian", "node_modules", "dist", "build", "cache", "tmp",
  "backup", "backups", "attachments", "__pycache__",
]);
const SQLITE_EXTENSION = new Set([".db", ".sqlite", ".sqlite3"]);
const SQLITE_HEADER = "SQLite format 3\0";
const SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;
const SENSITIVE_COLUMN = /(?:authorization|cookie|credential|password|passwd|private[_-]?key|secret|token)/iu;

const SQLITE_TABLES: Readonly<Record<Extract<LegacyHistoricalSourceKind,
  "mission_board_sqlite" | "codex_sqlite" | "prior_v2_sqlite">, readonly string[]>> = {
  mission_board_sqlite: ["boards", "columns", "tasks", "cards", "missions", "runs"],
  codex_sqlite: ["threads", "conversations", "sessions", "messages", "items", "rollouts"],
  prior_v2_sqlite: [
    "missions", "runs", "plans", "plan_steps", "events", "messages", "evidence",
    "findings", "artifacts", "memory_nodes", "memory_edges", "lessons",
  ],
};

function physicalIdentity(path: string): string {
  const state = statSync(path);
  return `${state.dev}:${state.ino}`;
}

function normalizedPath(path: string): string {
  return path.split(sep).join("/").normalize("NFKC");
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function pathFingerprint(path: string): string {
  return sha256Text(normalizedPath(path));
}

function exclusion(
  path: string,
  category: LegacyHistoricalExclusion["category"],
  reason: string,
  optional: Pick<LegacyHistoricalExclusion, "duplicateOf" | "sourceSha256"> = {},
): LegacyHistoricalExclusion {
  const fingerprint = pathFingerprint(path);
  return {
    id: `legacy_exclusion_${sha256Text(`${fingerprint}\0${category}\0${reason}`).slice(0, 40)}`,
    pathFingerprint: fingerprint,
    category,
    reason,
    ...optional,
  };
}

function isInside(root: string, candidate: string): boolean {
  const value = relative(root, candidate);
  return value === "" || (value !== ".." && !value.startsWith(`..${sep}`));
}

interface StableInspection {
  readonly identity: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly prefix: string;
}

/** Hash one stable inode without following a pathname replacement. */
function inspectStableFile(path: string, maximumBytes: number): StableInspection {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile()) throw new Error("source is not a regular file");
    if (before.size > maximumBytes) throw new RangeError("source exceeds its bounded size limit");
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    const prefix = Buffer.allocUnsafe(Math.min(before.size, 64 * 1024));
    let position = 0;
    let prefixLength = 0;
    while (true) {
      const length = readSync(descriptor, buffer, 0, buffer.length, position);
      if (length === 0) break;
      const chunk = buffer.subarray(0, length);
      hash.update(chunk);
      if (prefixLength < prefix.length) {
        const copied = Math.min(prefix.length - prefixLength, length);
        chunk.copy(prefix, prefixLength, 0, copied);
        prefixLength += copied;
      }
      position += length;
    }
    const after = fstatSync(descriptor);
    const pathname = lstatSync(path);
    if (
      !pathname.isFile()
      || before.dev !== after.dev || before.ino !== after.ino
      || before.dev !== pathname.dev || before.ino !== pathname.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
    ) throw new Error("source changed during inspection");
    return {
      identity: `${after.dev}:${after.ino}`,
      sha256: hash.digest("hex"),
      byteSize: after.size,
      modifiedAt: after.mtime.toISOString(),
      prefix: prefix.subarray(0, prefixLength).toString("utf8"),
    };
  } finally {
    closeSync(descriptor);
  }
}

function tableNames(database: SqliteDatabase): readonly string[] {
  return (database.prepare(`
    SELECT name FROM sqlite_master
    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
    ORDER BY name LIMIT 256
  `).all() as Array<{ readonly name: string }>).map(({ name }) => name);
}

function inspectSqlite(path: string, maximumBytes: number): {
  readonly kind?: "mission_board_sqlite" | "codex_sqlite" | "prior_v2_sqlite";
  readonly unsafeReason?: string;
} {
  if (statSync(path).size > maximumBytes) return { unsafeReason: "SQLite source exceeds its bounded size limit" };
  for (const suffix of ["-wal", "-journal"]) {
    const sidecar = `${path}${suffix}`;
    if (existsSync(sidecar) && statSync(sidecar).size > 0) {
      return { unsafeReason: "SQLite source has an active WAL/journal and must be quiesced before read-only import" };
    }
  }
  const descriptor = openSync(path, "r");
  try {
    const header = Buffer.alloc(SQLITE_HEADER.length);
    if (readSync(descriptor, header, 0, header.length, 0) !== header.length || header.toString("utf8") !== SQLITE_HEADER) {
      return { unsafeReason: "SQLite header is invalid" };
    }
  } finally { closeSync(descriptor); }
  let database: SqliteDatabase | undefined;
  try {
    database = createDatabaseConnection({
      filename: path,
      readonly: true,
      fileMustExist: true,
      verifyIntegrity: false,
      busyTimeoutMs: 0,
    });
    database.pragma("query_only = ON");
    const pageSize = Number(database.pragma("page_size", { simple: true }));
    const pageCount = Number(database.pragma("page_count", { simple: true }));
    if (!Number.isSafeInteger(pageSize) || !Number.isSafeInteger(pageCount) || pageSize * pageCount > maximumBytes) {
      return { unsafeReason: "SQLite page geometry exceeds its bounded read limit" };
    }
    const names = new Set(tableNames(database));
    const filename = basename(path).toLowerCase();
    const absolute = normalizedPath(path).toLowerCase();
    if (filename === "mission-board.db" || filename === "mission_board.db") return { kind: "mission_board_sqlite" };
    if (absolute.includes("/.codex/") && [...SQLITE_TABLES.codex_sqlite].some((name) => names.has(name))) {
      return { kind: "codex_sqlite" };
    }
    if (names.has("schema_migrations") && names.has("missions") && names.has("runs")) {
      return { kind: "prior_v2_sqlite" };
    }
    return {};
  } catch {
    return { unsafeReason: "SQLite source could not be opened through the bounded read-only adapter" };
  } finally { database?.close(); }
}

function isVaultRoot(root: string): boolean {
  return existsSync(resolve(root, ".obsidian"))
    || /(?:vault|second[ _-]?brain|chillspwn[ _-]?brain)/iu.test(basename(root));
}

function classifyText(path: string, rootIsVault: boolean, prefix: string): LegacyHistoricalSourceKind | undefined {
  const absolute = normalizedPath(path).toLowerCase();
  const filename = basename(path).toLowerCase();
  const extension = extname(filename);
  if (extension === ".jsonl" && absolute.includes("claude") && absolute.includes("/projects/")) {
    return "claude_project_jsonl";
  }
  if ([".json", ".jsonl"].includes(extension) && absolute.includes("grok") && /\/sessions?\//u.test(absolute)) {
    return "grok_nested_session";
  }
  if (filename.endsWith(".system.txt")) return "session_system_text";
  if ([".json", ".jsonl", ".txt"].includes(extension) && /\/sessions?\/archives?\//u.test(absolute)) {
    return "session_archive";
  }
  if ([".log", ".txt", ".jsonl"].includes(extension)
    && (/(?:^|\/)(?:\.claude|\.codex|\.grok)\/(?:debug|logs?)\//u.test(absolute)
      || /(?:^|\/)(?:client[ _-]?logs?)\//u.test(absolute)
      || /^client[._-].*\.log$/u.test(filename))) {
    return "root_client_log";
  }
  if (rootIsVault && [".md", ".markdown", ".yaml", ".yml"].includes(extension)
    && (prefix.startsWith("---") || /\[\[[^\]\r\n]+\]\]/u.test(prefix))) {
    return "obsidian_note";
  }
  if (extension === ".json" && /(?:command[ _-]?os[ _-]?v2|ti[ _-]?scale|v2).*(?:export|snapshot)/u.test(filename)) {
    return "prior_v2_export";
  }
  return undefined;
}

/**
 * Discover previously missed history sources without mutating or validating
 * the active Ti-Scale database. Roots/files are collapsed by inode and then
 * kind+content hash so stale copied trees cannot be imported twice.
 */
export async function discoverLegacyHistoricalSources(
  options: LegacyHistoricalDiscoveryOptions,
): Promise<LegacyHistoricalDiscovery> {
  if (options.canonicalDatabasePaths.length === 0) {
    throw new Error("At least one canonical Ti-Scale database path is required for fail-closed exclusion");
  }
  const maximumFiles = options.maximumFiles ?? DEFAULT_MAX_FILES;
  const maximumDepth = options.maximumDepth ?? DEFAULT_MAX_DEPTH;
  const maximumTextBytes = options.maximumTextBytes ?? DEFAULT_MAX_TEXT_BYTES;
  const maximumSqliteBytes = options.maximumSqliteBytes ?? DEFAULT_MAX_SQLITE_BYTES;
  const canonicalDatabasePaths = new Set(options.canonicalDatabasePaths.map((path) => resolve(path)));
  const canonicalDatabaseIdentities = new Set<string>();
  for (const path of canonicalDatabasePaths) {
    try { canonicalDatabaseIdentities.add(physicalIdentity(realpathSync(path))); } catch { /* missing active path stays lexically denied */ }
  }

  const excluded: LegacyHistoricalExclusion[] = [];
  const rootAliases: LegacyHistoricalDiscovery["rootAliases"][number][] = [];
  const roots: Array<{ readonly requested: string; readonly canonical: string; readonly identity: string; readonly vault: boolean }> = [];
  const rootByIdentity = new Map<string, string>();
  for (const requested of options.roots) {
    const requestedPath = resolve(requested);
    let canonical: string;
    try { canonical = realpathSync(requestedPath); }
    catch {
      excluded.push(exclusion(requestedPath, "missing", "configured historical source root does not exist"));
      continue;
    }
    if (!lstatSync(canonical).isDirectory()) {
      excluded.push(exclusion(canonical, "unsupported", "historical source root is not a directory"));
      continue;
    }
    const identity = physicalIdentity(canonical);
    const prior = rootByIdentity.get(identity);
    if (prior) {
      rootAliases.push({ requestedPath, canonicalPath: canonical, duplicateOf: prior, physicalIdentity: identity });
      excluded.push(exclusion(canonical, "alias", "root resolves to an already selected physical directory", { duplicateOf: prior }));
      continue;
    }
    rootByIdentity.set(identity, canonical);
    roots.push({ requested: requestedPath, canonical, identity, vault: isVaultRoot(canonical) });
  }

  const sources: LegacyHistoricalSource[] = [];
  const sourceByInode = new Map<string, string>();
  const sourceByContent = new Map<string, string>();
  let visitedFiles = 0;
  for (const root of roots) {
    const pending: Array<{ readonly path: string; readonly depth: number }> = [{ path: root.canonical, depth: 0 }];
    while (pending.length) {
      const directory = pending.pop()!;
      let entries;
      try { entries = readdirSync(directory.path, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)); }
      catch {
        excluded.push(exclusion(directory.path, "changed", "directory could not be read during bounded discovery"));
        continue;
      }
      for (const entry of entries) {
        const candidate = resolve(directory.path, entry.name);
        if (!isInside(root.canonical, candidate)) continue;
        if (entry.isSymbolicLink()) {
          excluded.push(exclusion(candidate, "alias", "symbolic links are never followed by the historical adapter"));
          continue;
        }
        if (entry.isDirectory()) {
          if (directory.depth < maximumDepth && !DENIED_DIRECTORY.has(entry.name.toLowerCase())) {
            pending.push({ path: candidate, depth: directory.depth + 1 });
          }
          continue;
        }
        if (!entry.isFile()) continue;
        visitedFiles += 1;
        if (visitedFiles > maximumFiles) {
          excluded.push(exclusion(root.canonical, "limit_exceeded", "bounded historical source file limit reached"));
          pending.length = 0;
          break;
        }
        const resolvedCandidate = resolve(candidate);
        let identity: string;
        try { identity = physicalIdentity(candidate); }
        catch {
          excluded.push(exclusion(candidate, "changed", "source disappeared during discovery"));
          continue;
        }
        if (canonicalDatabasePaths.has(resolvedCandidate) || canonicalDatabaseIdentities.has(identity)) {
          excluded.push(exclusion(candidate, "canonical_database", "active Ti-Scale database is never a legacy source"));
          continue;
        }
        const priorInode = sourceByInode.get(identity);
        if (priorInode) {
          excluded.push(exclusion(candidate, "duplicate_inode", "file is an inode alias of an already selected source", { duplicateOf: priorInode }));
          continue;
        }
        const extension = extname(candidate).toLowerCase();
        const sqlite = SQLITE_EXTENSION.has(extension);
        let inspected: StableInspection;
        try { inspected = inspectStableFile(candidate, sqlite ? maximumSqliteBytes : maximumTextBytes); }
        catch (error) {
          excluded.push(exclusion(candidate, error instanceof RangeError ? "oversized" : "changed",
            error instanceof Error ? error.message : "source inspection failed"));
          continue;
        }
        let kind: LegacyHistoricalSourceKind | undefined;
        if (sqlite) {
          const assessment = inspectSqlite(candidate, maximumSqliteBytes);
          if (assessment.unsafeReason) {
            excluded.push(exclusion(candidate, "unsafe_sqlite", assessment.unsafeReason, { sourceSha256: inspected.sha256 }));
            continue;
          }
          kind = assessment.kind;
        } else {
          kind = classifyText(candidate, root.vault, inspected.prefix);
        }
        if (!kind) continue;
        const duplicateKey = `${kind}\0${inspected.sha256}`;
        const priorContent = sourceByContent.get(duplicateKey);
        if (priorContent) {
          excluded.push(exclusion(candidate, "duplicate_content", "stale duplicate source content was already selected", {
            duplicateOf: priorContent,
            sourceSha256: inspected.sha256,
          }));
          continue;
        }
        const id = `legacy_history_source_${sha256Text(`${kind}\0${inspected.sha256}`).slice(0, 40)}`;
        sourceByInode.set(identity, id);
        sourceByContent.set(duplicateKey, id);
        sources.push({
          id,
          kind,
          canonicalPath: candidate,
          root: root.canonical,
          physicalIdentity: inspected.identity,
          sha256: inspected.sha256,
          byteSize: inspected.byteSize,
          modifiedAt: inspected.modifiedAt,
        });
      }
    }
  }
  sources.sort((left, right) => left.id.localeCompare(right.id));
  excluded.sort((left, right) => left.id.localeCompare(right.id));
  rootAliases.sort((left, right) => left.requestedPath.localeCompare(right.requestedPath));
  const manifestHash = sha256Text(canonicalJson({
    schemaVersion: "ti_scale.legacy_historical_manifest/v1",
    sources: sources.map((source) => ({
      id: source.id,
      kind: source.kind,
      physicalIdentity: source.physicalIdentity,
      sha256: source.sha256,
      byteSize: source.byteSize,
      modifiedAt: source.modifiedAt,
    })),
    exclusions: excluded.map(({ id, category, duplicateOf, sourceSha256 }) => ({
      id,
      category,
      duplicateOf: duplicateOf ?? null,
      sourceSha256: sourceSha256 ?? null,
    })),
    rootAliases: rootAliases.map(({ physicalIdentity, duplicateOf }) => ({ physicalIdentity, duplicateOf })),
  }));
  return {
    schemaVersion: "ti_scale.legacy_historical_manifest/v1",
    manifestHash,
    verificationState: "verified",
    sources,
    excluded,
    rootAliases,
  };
}

function occurredAt(value: unknown): string | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  for (const key of ["timestamp", "created_at", "createdAt", "updated_at", "updatedAt", "date"]) {
    const candidate = record[key];
    if (typeof candidate !== "string" && typeof candidate !== "number") continue;
    const parsed = new Date(typeof candidate === "number" && candidate < 100_000_000_000 ? candidate * 1_000 : candidate);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return undefined;
}

function quarantine(
  source: LegacyHistoricalSource,
  itemKey: string,
  category: LegacyHistoricalQuarantine["category"],
  reason: string,
): LegacyHistoricalQuarantine {
  const itemKeyHash = sha256Text(itemKey);
  return {
    id: `legacy_history_quarantine_${sha256Text(`${source.id}\0${itemKeyHash}\0${category}`).slice(0, 40)}`,
    sourceId: source.id,
    itemKeyHash,
    category,
    reason,
  };
}

function candidate(
  source: LegacyHistoricalSource,
  itemKey: string,
  value: unknown,
  dataClass: LegacyPrivateHistoryCandidate["dataClass"] = "private_operational_history",
): LegacyPrivateHistoryCandidate | LegacyHistoricalQuarantine {
  let raw: string;
  try { raw = typeof value === "string" ? value : JSON.stringify(value); }
  catch { return quarantine(source, itemKey, "malformed", "record could not be serialized deterministically"); }
  if (containsHardSecret(raw)) {
    return quarantine(source, itemKey, "secret_bearing", "secret-bearing record is quarantined and cannot become reusable memory");
  }
  const privatePayload = redactRecursively(value);
  const normalized = JSON.stringify(privatePayload);
  if (containsHardSecret(normalized)) {
    return quarantine(source, itemKey, "secret_bearing", "record remained secret-bearing after local redaction");
  }
  const contentHash = sha256Text(normalized);
  const label = source.kind.replaceAll("_", " ");
  return {
    id: `legacy_history_candidate_${sha256Text(`${source.id}\0${itemKey}\0${contentHash}`).slice(0, 40)}`,
    sourceId: source.id,
    sourceKind: source.kind,
    itemKey: sha256Text(itemKey),
    contentHash,
    dataClass,
    sensitivity: "private",
    disclosure: "local_only",
    lifecycle: "candidate",
    reusableMemoryEligible: false,
    projectionPolicy: {
      mode: "attack_knowledge_only",
      forbiddenReusableFields: [
        "target", "ip_address", "source_path", "mission", "run", "journey", "credential", "secret",
      ],
    },
    title: `Imported ${label} record`,
    summary: "Private historical context awaiting deterministic review and attack-knowledge extraction.",
    ...(occurredAt(value) ? { occurredAt: occurredAt(value) } : {}),
    privatePayload,
  };
}

function pushCandidate(
  output: { candidates: LegacyPrivateHistoryCandidate[]; quarantined: LegacyHistoricalQuarantine[] },
  source: LegacyHistoricalSource,
  itemKey: string,
  value: unknown,
  dataClass?: LegacyPrivateHistoryCandidate["dataClass"],
): void {
  const result = candidate(source, itemKey, value, dataClass);
  if ("category" in result) output.quarantined.push(result);
  else output.candidates.push(result);
}

function stableText(source: LegacyHistoricalSource): string {
  const descriptor = openSync(source.canonicalPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.size !== source.byteSize || `${before.dev}:${before.ino}` !== source.physicalIdentity) {
      throw new Error("source identity changed after discovery");
    }
    const content = Buffer.alloc(before.size);
    const hash = createHash("sha256");
    let position = 0;
    while (position < content.length) {
      const length = readSync(descriptor, content, position, Math.min(64 * 1024, content.length - position), position);
      if (length === 0) break;
      hash.update(content.subarray(position, position + length));
      position += length;
    }
    const after = fstatSync(descriptor);
    const pathname = lstatSync(source.canonicalPath);
    if (
      position !== content.length || hash.digest("hex") !== source.sha256
      || !pathname.isFile()
      || before.dev !== after.dev || before.ino !== after.ino
      || before.dev !== pathname.dev || before.ino !== pathname.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
    ) throw new Error("source changed during bounded read");
    return content.toString("utf8");
  } finally { closeSync(descriptor); }
}

function parseJsonRecords(
  source: LegacyHistoricalSource,
  text: string,
  maximumRecords: number,
  output: { candidates: LegacyPrivateHistoryCandidate[]; quarantined: LegacyHistoricalQuarantine[] },
): void {
  let value: unknown;
  try { value = JSON.parse(text) as unknown; }
  catch {
    output.quarantined.push(quarantine(source, "document", "malformed", "JSON document is malformed"));
    return;
  }
  const records: unknown[] = [];
  const collect = (item: unknown, depth: number): void => {
    if (records.length > maximumRecords || depth > 8) return;
    if (Array.isArray(item)) {
      item.forEach((child) => collect(child, depth + 1));
      return;
    }
    if (!item || typeof item !== "object") return;
    const record = item as Record<string, unknown>;
    const nestedKeys = ["sessions", "conversations", "messages", "events", "entries", "items", "data"];
    const nested = nestedKeys.filter((key) => Array.isArray(record[key]));
    if (nested.length === 0 || ["role", "type", "content", "message", "timestamp", "id"].some((key) => key in record)) {
      records.push(record);
      return;
    }
    nested.forEach((key) => collect(record[key], depth + 1));
  };
  collect(value, 0);
  if (records.length === 0 && value && typeof value === "object") records.push(value);
  records.slice(0, maximumRecords).forEach((record, index) => pushCandidate(output, source, `json:${index}`, record));
  if (records.length > maximumRecords) {
    output.quarantined.push(quarantine(source, "json:overflow", "record_limit", "JSON record limit reached; remaining records were not parsed"));
  }
}

function parseJsonLines(
  source: LegacyHistoricalSource,
  text: string,
  maximumRecords: number,
  maximumLineBytes: number,
  output: { candidates: LegacyPrivateHistoryCandidate[]; quarantined: LegacyHistoricalQuarantine[] },
): void {
  const lines = text.split(/\r?\n/u).filter((line) => line.trim().length > 0);
  lines.slice(0, maximumRecords).forEach((line, index) => {
    if (Buffer.byteLength(line, "utf8") > maximumLineBytes) {
      output.quarantined.push(quarantine(source, `line:${index}`, "record_limit", "line exceeds the bounded parser size"));
      return;
    }
    try { pushCandidate(output, source, `line:${index}`, JSON.parse(line) as unknown); }
    catch { output.quarantined.push(quarantine(source, `line:${index}`, "malformed", "JSONL record is malformed")); }
  });
  if (lines.length > maximumRecords) {
    output.quarantined.push(quarantine(source, "line:overflow", "record_limit", "line record limit reached; remaining lines were not parsed"));
  }
}

function parseTextLines(
  source: LegacyHistoricalSource,
  text: string,
  maximumRecords: number,
  maximumLineBytes: number,
  output: { candidates: LegacyPrivateHistoryCandidate[]; quarantined: LegacyHistoricalQuarantine[] },
): void {
  const lines = text.split(/\r?\n/u).filter((line) => line.trim().length > 0);
  lines.slice(0, maximumRecords).forEach((line, index) => {
    if (Buffer.byteLength(line, "utf8") > maximumLineBytes) {
      output.quarantined.push(quarantine(source, `line:${index}`, "record_limit", "text line exceeds the bounded parser size"));
    } else pushCandidate(output, source, `line:${index}`, { line });
  });
  if (lines.length > maximumRecords) {
    output.quarantined.push(quarantine(source, "line:overflow", "record_limit", "text record limit reached; remaining lines were not parsed"));
  }
}

function parseObsidian(
  source: LegacyHistoricalSource,
  text: string,
  output: { candidates: LegacyPrivateHistoryCandidate[]; quarantined: LegacyHistoricalQuarantine[] },
): void {
  let frontmatter: Record<string, string> = {};
  let body = text;
  if (text.startsWith("---")) {
    const ending = text.indexOf("\n---", 3);
    if (ending < 0) {
      output.quarantined.push(quarantine(source, "note", "malformed", "Obsidian YAML frontmatter is not closed"));
      return;
    }
    const lines = text.slice(3, ending).split(/\r?\n/u).filter(Boolean);
    if (lines.length > 256) {
      output.quarantined.push(quarantine(source, "note", "record_limit", "Obsidian frontmatter exceeds the bounded property limit"));
      return;
    }
    frontmatter = Object.fromEntries(lines.flatMap((line) => {
      const separator = line.indexOf(":");
      return separator > 0 ? [[line.slice(0, separator).trim(), line.slice(separator + 1).trim()]] : [];
    }));
    body = text.slice(ending + 4).trimStart();
  }
  const wikilinks = [...body.matchAll(/\[\[([^\]\r\n]{1,240})\]\]/gu)].slice(0, 512).map((match) => match[1]!);
  pushCandidate(output, source, "note", { frontmatter, wikilinks, body }, "private_memory_candidate");
}

function safeSqliteColumns(database: SqliteDatabase, table: string): readonly string[] {
  if (!SAFE_IDENTIFIER.test(table)) return [];
  const rows = database.prepare(`PRAGMA table_info("${table}")`).all() as Array<{
    readonly name: string;
    readonly type: string;
  }>;
  return rows
    .filter(({ name, type }) => SAFE_IDENTIFIER.test(name) && !SENSITIVE_COLUMN.test(name) && !/BLOB/iu.test(type))
    .map(({ name }) => name)
    .slice(0, 32);
}

function normalizedSqliteValue(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (Buffer.isBuffer(value)) return `[BINARY:${value.byteLength}]`;
  return value;
}

function parseSqlite(
  source: LegacyHistoricalSource,
  maximumRecords: number,
  output: { candidates: LegacyPrivateHistoryCandidate[]; quarantined: LegacyHistoricalQuarantine[] },
): void {
  const before = inspectStableFile(source.canonicalPath, source.byteSize);
  if (before.sha256 !== source.sha256 || before.identity !== source.physicalIdentity) {
    throw new Error("SQLite source changed after discovery");
  }
  if (!(source.kind in SQLITE_TABLES)) {
    output.quarantined.push(quarantine(source, "sqlite", "unsupported_schema", "SQLite adapter kind is unsupported"));
    return;
  }
  const assessment = inspectSqlite(source.canonicalPath, Math.max(source.byteSize, 1));
  if (assessment.unsafeReason || assessment.kind !== source.kind) {
    output.quarantined.push(quarantine(source, "sqlite", "changed", "SQLite source no longer matches its bounded read-only discovery assessment"));
    return;
  }
  const database = createDatabaseConnection({
    filename: source.canonicalPath,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
    busyTimeoutMs: 0,
  });
  try {
    database.pragma("query_only = ON");
    const available = new Set(tableNames(database));
    let seen = 0;
    for (const table of SQLITE_TABLES[source.kind]) {
      if (!available.has(table) || seen >= maximumRecords) continue;
      const columns = safeSqliteColumns(database, table);
      if (columns.length === 0) continue;
      const remaining = maximumRecords - seen;
      const selected = columns.map((name) => `"${name}"`).join(", ");
      const rows = database.prepare(`SELECT ${selected} FROM "${table}" LIMIT ${remaining + 1}`).all() as Record<string, unknown>[];
      rows.slice(0, remaining).forEach((row, index) => {
        const normalized = Object.fromEntries(Object.entries(row).map(([key, value]) => [key, normalizedSqliteValue(value)]));
        pushCandidate(output, source, `${table}:${index}`, { table, record: normalized });
      });
      seen += Math.min(rows.length, remaining);
      if (rows.length > remaining) {
        output.quarantined.push(quarantine(source, `${table}:overflow`, "record_limit", "SQLite row limit reached; remaining rows were not parsed"));
        break;
      }
    }
    if (seen === 0) {
      output.quarantined.push(quarantine(source, "sqlite", "unsupported_schema", "No bounded allowlisted history rows were found"));
    }
  } finally { database.close(); }
  const after = inspectStableFile(source.canonicalPath, source.byteSize);
  if (after.sha256 !== source.sha256 || after.identity !== source.physicalIdentity) {
    throw new Error("SQLite source changed during bounded read-only parsing");
  }
}

/** Parse one immutable discovery record into local-only, non-reusable candidates. */
export function parseLegacyHistoricalSource(
  source: LegacyHistoricalSource,
  options: LegacyHistoricalParseOptions = {},
): LegacyHistoricalParseResult {
  const maximumRecords = options.maximumRecords ?? DEFAULT_MAX_RECORDS;
  const maximumLineBytes = options.maximumLineBytes ?? DEFAULT_MAX_LINE_BYTES;
  const output = { candidates: [] as LegacyPrivateHistoryCandidate[], quarantined: [] as LegacyHistoricalQuarantine[] };
  try {
    if (source.kind.endsWith("_sqlite")) {
      const sqliteOutput = {
        candidates: [] as LegacyPrivateHistoryCandidate[],
        quarantined: [] as LegacyHistoricalQuarantine[],
      };
      parseSqlite(source, maximumRecords, sqliteOutput);
      output.candidates.push(...sqliteOutput.candidates);
      output.quarantined.push(...sqliteOutput.quarantined);
    } else {
      const text = stableText(source);
      switch (source.kind) {
        case "claude_project_jsonl":
          parseJsonLines(source, text, maximumRecords, maximumLineBytes, output);
          break;
        case "grok_nested_session":
        case "session_archive":
        case "prior_v2_export":
          extname(source.canonicalPath).toLowerCase() === ".jsonl"
            ? parseJsonLines(source, text, maximumRecords, maximumLineBytes, output)
            : parseJsonRecords(source, text, maximumRecords, output);
          break;
        case "obsidian_note":
          parseObsidian(source, text, output);
          break;
        case "session_system_text":
        case "root_client_log":
          parseTextLines(source, text, maximumRecords, maximumLineBytes, output);
          break;
        default:
          output.quarantined.push(quarantine(source, "source", "unsupported_schema", "source adapter is unsupported"));
      }
    }
  } catch {
    output.quarantined.push(quarantine(source, "source", "changed", "source changed or became unavailable after discovery"));
  }
  output.candidates.sort((left, right) => left.id.localeCompare(right.id));
  output.quarantined.sort((left, right) => left.id.localeCompare(right.id));
  return { sourceId: source.id, ...output };
}

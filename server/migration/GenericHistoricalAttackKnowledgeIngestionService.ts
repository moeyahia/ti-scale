import { createHash, createHmac } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  statSync,
} from "node:fs";
import { extname } from "node:path";
import { createDatabaseConnection, type SqliteDatabase } from "../db";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import {
  findReusableMemorySecretCategories,
  type AttackCentricEdgeType,
  type AttackCentricReusableNodeType,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";
import {
  AttackKnowledgeCompiler,
  type AttackKnowledgeReconciliation,
  type ReusableAttackBundleKnowledge,
  type ReusableAttackFactKnowledge,
} from "./AttackKnowledgeCompiler";
import { MigrationMetadataRepository } from "./MigrationMetadataRepository";
import {
  classifyGenericHistoricalRecord,
  evaluateGenericHistoricalKnowledgeQuality,
  hasGenericHistoricalReusableSourceBoundary,
  type GenericHistoricalKnowledgeRejectionReason,
  type GenericHistoricalRecordClass,
} from "./GenericHistoricalKnowledgeQualityGate";
import { containsHardSecret, sha256Text } from "./SecretSafety";
import type {
  AttackKnowledgeExtractionBatchReport,
  LegacySource,
  LegacySourceType,
} from "./types";

const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;
const MALFORMED_TEXT = /\0|\uFFFD/u;
const SENSITIVE_KEY = /(?:auth(?:orization)?|cookie|credential|hash|key|password|passwd|private|secret|session[_-]?token|ticket|token)/iu;
const OPERATIONAL_KEY = /(?:address|box|client|customer|domain|engagement|host|ip|journey|mission|run|scope|target|url)/iu;
export const GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES = [
  "run_json",
  "session_json",
  "event_jsonl",
  "raw_llm_jsonl",
  "dashboard_log",
  "memory_json",
  "training_json",
  "kanban_sqlite",
  "conversation_state_sqlite",
  "provider_session_json",
  "provider_session_jsonl",
  "provider_log",
  "conversation_markdown",
] as const satisfies readonly LegacySourceType[];
const SUPPORTED_SOURCE_TYPES: ReadonlySet<LegacySourceType> = new Set(GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES);
const LINE_SOURCE_TYPES: ReadonlySet<LegacySourceType> = new Set([
  "event_jsonl",
  "raw_llm_jsonl",
  "dashboard_log",
  "provider_session_jsonl",
  "provider_log",
]);
const MARKDOWN_SOURCE_TYPES: ReadonlySet<LegacySourceType> = new Set([
  "conversation_markdown",
]);
const SQLITE_SOURCE_TYPES: ReadonlySet<LegacySourceType> = new Set([
  "kanban_sqlite",
  "conversation_state_sqlite",
]);
const SQLITE_TABLES: Readonly<Record<"kanban_sqlite" | "conversation_state_sqlite", readonly string[]>> = {
  kanban_sqlite: ["boards", "columns", "tasks", "cards", "missions", "runs"],
  conversation_state_sqlite: ["conversations", "sessions", "messages", "events", "memory", "lessons", "state"],
};

const DEFAULTS = Object.freeze({
  maxSources: 10_000,
  maxSourcesThisRun: 200,
  maxSourceBytes: 8 * 1024 * 1024,
  maxTotalBytesThisRun: 128 * 1024 * 1024,
  maxRecordsPerSourceThisRun: 5_000,
  maxRecordsThisRun: 20_000,
  maxRecordBytes: 512 * 1024,
  maxFactsPerRecord: 32,
  maxBundlesThisRun: 5_000,
  maxJsonDepth: 12,
});

interface GenericHistoricalLimits {
  readonly maxSources: number;
  readonly maxSourcesThisRun: number;
  readonly maxSourceBytes: number;
  readonly maxTotalBytesThisRun: number;
  readonly maxRecordsPerSourceThisRun: number;
  readonly maxRecordsThisRun: number;
  readonly maxRecordBytes: number;
  readonly maxFactsPerRecord: number;
  readonly maxBundlesThisRun: number;
  readonly maxJsonDepth: number;
}

interface GenericSourceBinding {
  readonly sourceId: string;
  readonly sourceReference: string;
  readonly sourceHash: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly sourceDevice: number;
  readonly sourceInode: number;
}

interface ParsedRecord {
  readonly key: string;
  readonly contentHash: string;
  readonly observedAt: string;
  readonly text?: string;
  readonly recordClass?: GenericHistoricalRecordClass;
  readonly disposition?: "malformed" | "secret_bearing" | "oversized";
}

type Fact = Readonly<{
  role: string;
  nodeType: AttackCentricReusableNodeType;
  title: string;
  summary: string;
  body?: string;
}>;

type Edge = Readonly<{
  sourceRole: string;
  edgeType: AttackCentricEdgeType;
  targetRole: string;
}>;

interface KnowledgeExtraction {
  readonly knowledge?: ReusableAttackBundleKnowledge | ReusableAttackFactKnowledge;
  readonly factCount: number;
  readonly confidence: number;
  readonly rejectionReason?: GenericHistoricalKnowledgeRejectionReason;
}

function incrementCount(counts: Record<string, number>, key: string): void {
  counts[key] = (counts[key] ?? 0) + 1;
}

function addKnowledgeDistribution(
  knowledge: ReusableAttackBundleKnowledge | ReusableAttackFactKnowledge,
  nodeTypeCounts: Record<string, number>,
  edgeTypeCounts: Record<string, number>,
): void {
  if (knowledge.kind === "reusable_fact") {
    incrementCount(nodeTypeCounts, knowledge.nodeType);
    return;
  }
  knowledge.facts.forEach(({ nodeType }) => incrementCount(nodeTypeCounts, nodeType));
  knowledge.edges.forEach(({ edgeType }) => incrementCount(edgeTypeCounts, edgeType));
}

export type GenericHistoricalIngestionIssueReason =
  | "unsupported_source"
  | "source_budget_exceeded"
  | "total_budget_exceeded"
  | "record_budget_exceeded"
  | "bundle_budget_exceeded"
  | "source_changed"
  | "malformed_record"
  | "secret_bearing_record"
  | "record_size_exceeded"
  | "unbound_provider_history"
  | GenericHistoricalKnowledgeRejectionReason
  | "no_reusable_semantics"
  | "compiler_privacy_boundary"
  | "sqlite_not_quiescent"
  | "sqlite_schema_unsupported";

export interface GenericHistoricalIngestionIssue {
  /** Opaque only: never a path, target, mission, or engagement label. */
  readonly sourceKey: string;
  readonly disposition: "skipped" | "quarantined" | "ambiguous";
  readonly reason: GenericHistoricalIngestionIssueReason;
  readonly count?: number;
}

export interface GenericHistoricalAttackKnowledgeIngestionResult
  extends AttackKnowledgeExtractionBatchReport {
  readonly inventoryReceiptHash: string;
  readonly sourcesProcessed: number;
  readonly sourcesCompleted: number;
  readonly recordsDiscovered: number;
  readonly recordsProcessed: number;
  readonly recordsDeduplicated: number;
  readonly recordsQuarantined: number;
  readonly recordsSkipped: number;
  readonly nodeTypeCounts: Readonly<Record<string, number>>;
  readonly edgeTypeCounts: Readonly<Record<string, number>>;
  readonly nextResumeAfterSourceKey?: string;
  readonly nextResumeAfterRecordKey?: string;
  readonly issues: readonly GenericHistoricalIngestionIssue[];
  readonly candidateIds: readonly string[];
  readonly sourceEvidenceCandidateIds: readonly string[];
  /** Exact global compiler state after this bounded batch's single reconciliation pass. */
  readonly compilerReconciliation: AttackKnowledgeReconciliation;
  readonly compilerReconciliationPasses: 1;
  readonly compilerRunsReconciled: number;
}

export interface GenericHistoricalAttackKnowledgeIngestionOptions {
  readonly receiptHmacKey: string | Buffer;
  readonly maxSources?: number;
  readonly maxSourceBytes?: number;
  readonly maxTotalBytesThisRun?: number;
  readonly maxRecordsPerSourceThisRun?: number;
  readonly maxRecordsThisRun?: number;
  readonly maxRecordBytes?: number;
  readonly maxFactsPerRecord?: number;
  readonly maxBundlesThisRun?: number;
  readonly maxJsonDepth?: number;
  readonly clock?: () => Date;
}

export interface GenericHistoricalAttackKnowledgeIngestionRequest {
  readonly migrationId: string;
  /** Must equal the immutable receipt already stored for migrationId. */
  readonly inventoryReceiptHash: string;
  /** Sources must already have verified-reference custody objects. */
  readonly sources: readonly LegacySource[];
  readonly dryRun?: boolean;
  readonly maxSourcesThisRun?: number;
  readonly maxRecordsThisRun?: number;
  readonly maxBundlesThisRun?: number;
  /** Resume strictly after this opaque source, or within it when a record cursor is also supplied. */
  readonly resumeAfterSourceKey?: string;
  /** Opaque last-accounted record key; valid only with resumeAfterSourceKey. */
  readonly resumeAfterRecordKey?: string;
  /** Test/job boundary. The durable item ledger makes a retry idempotent. */
  readonly interruptAfterNewRecords?: number;
}

class SourceChangedError extends Error {}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${name} must be a positive safe integer`);
  return value;
}

function parseTimestamp(value: unknown, fallback: string): string {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    for (const key of ["timestamp", "occurred_at", "occurredAt", "created_at", "createdAt", "updated_at", "updatedAt", "date"]) {
      const candidate = record[key];
      if (typeof candidate !== "string" && typeof candidate !== "number") continue;
      const date = new Date(typeof candidate === "number" && candidate < 100_000_000_000 ? candidate * 1_000 : candidate);
      if (!Number.isNaN(date.getTime())) return date.toISOString();
    }
  }
  return fallback;
}

function recordText(value: unknown, maxDepth: number): string {
  const output: string[] = [];
  const visit = (candidate: unknown, depth: number, key?: string): void => {
    if (depth > maxDepth || output.length >= 256) return;
    if (key && SENSITIVE_KEY.test(key)) return;
    if (Array.isArray(candidate)) {
      candidate.slice(0, 128).forEach((item) => visit(item, depth + 1));
      return;
    }
    if (candidate && typeof candidate === "object") {
      Object.entries(candidate as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .slice(0, 256)
        .forEach(([childKey, item]) => visit(item, depth + 1, childKey));
      return;
    }
    if (OPERATIONAL_KEY.test(key ?? "")) return;
    if (typeof candidate === "string") output.push(candidate.normalize("NFKC"));
  };
  visit(value, 0);
  return output.join("\n").slice(0, 128 * 1024);
}

function sensitiveRecord(raw: string): boolean {
  return containsHardSecret(raw)
    || findReusableMemorySecretCategories(raw).length > 0
    || /\b(?:[a-z0-9]+[_-])?(?:api[_-]?token|access[_-]?token|auth(?:orization)?|cookie|credential|password|passwd|private[_-]?key|secret|session[_-]?token|ticket)\b\s*[:=]\s*"?[^\s",}]{4,}/iu.test(raw);
}

function sourceKey(receiptHash: string, source: LegacySource): string {
  return sha256(`${receiptHash}\0${source.type}\0${source.sha256}\0${source.byteSize}\0${source.modifiedAt}`);
}

function itemKey(recordKey: string): string {
  return `generic-attack-v1:${sha256Text(recordKey)}`;
}

function stableState(path: string, binding: GenericSourceBinding): ReturnType<typeof fstatSync> {
  const pathname = lstatSync(path);
  if (!pathname.isFile() || pathname.isSymbolicLink() || pathname.dev !== binding.sourceDevice ||
      pathname.ino !== binding.sourceInode || pathname.size !== binding.byteSize ||
      pathname.mtime.toISOString() !== binding.modifiedAt) {
    throw new SourceChangedError("Verified historical source identity changed");
  }
  return pathname;
}

function readPinnedBytes(path: string, binding: GenericSourceBinding, maxBytes: number): Buffer {
  if (binding.byteSize > maxBytes) throw new RangeError("source exceeds bounded parser size");
  stableState(path, binding);
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor);
    if (before.dev !== binding.sourceDevice || before.ino !== binding.sourceInode || before.size !== binding.byteSize) {
      throw new SourceChangedError("Verified historical source descriptor changed");
    }
    const bytes = Buffer.alloc(before.size);
    const digest = createHash("sha256");
    let offset = 0;
    while (offset < bytes.length) {
      const length = readSync(descriptor, bytes, offset, Math.min(64 * 1024, bytes.length - offset), offset);
      if (length === 0) break;
      digest.update(bytes.subarray(offset, offset + length));
      offset += length;
    }
    const after = fstatSync(descriptor);
    if (offset !== bytes.length || digest.digest("hex") !== binding.sourceHash ||
        after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size ||
        after.mtimeMs !== before.mtimeMs) {
      throw new SourceChangedError("Verified historical source changed during pinned read");
    }
    stableState(path, binding);
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function jsonRecords(value: unknown, maxDepth: number): readonly Readonly<{ key: string; value: unknown }>[] {
  const records: Array<{ key: string; value: unknown }> = [];
  const visit = (candidate: unknown, path: string, depth: number): void => {
    if (depth > maxDepth) return;
    if (Array.isArray(candidate)) {
      candidate.forEach((item, index) => visit(item, `${path}/${index}`, depth + 1));
      return;
    }
    if (!candidate || typeof candidate !== "object") return;
    const object = candidate as Record<string, unknown>;
    const nested = ["sessions", "conversations", "messages", "events", "entries", "items", "lessons", "memories", "data"]
      .filter((key) => Array.isArray(object[key]));
    if (nested.length === 0 || ["role", "type", "content", "message", "summary", "title", "timestamp", "id"].some((key) => key in object)) {
      records.push({ key: path, value: object });
      return;
    }
    nested.forEach((key) => visit(object[key], `${path}/${key}`, depth + 1));
  };
  visit(value, "json", 0);
  if (records.length === 0 && value && typeof value === "object") records.push({ key: "json", value });
  return records;
}

function parseStructuredRecords(
  source: LegacySource,
  binding: GenericSourceBinding,
  limits: { readonly maxSourceBytes: number; readonly maxRecordBytes: number; readonly maxJsonDepth: number },
): readonly ParsedRecord[] {
  const bytes = readPinnedBytes(source.absolutePath, binding, limits.maxSourceBytes);
  const raw = bytes.toString("utf8").normalize("NFKC");
  if (MALFORMED_TEXT.test(raw)) {
    return [{ key: "document", contentHash: source.sha256, observedAt: source.modifiedAt, disposition: "malformed" }];
  }
  let value: unknown;
  try { value = JSON.parse(raw) as unknown; }
  catch {
    return [{ key: "document", contentHash: source.sha256, observedAt: source.modifiedAt, disposition: "malformed" }];
  }
  return jsonRecords(value, limits.maxJsonDepth).map((entry) => {
    let serialized: string;
    try { serialized = JSON.stringify(entry.value); }
    catch {
      return { key: entry.key, contentHash: sha256(entry.key), observedAt: source.modifiedAt, disposition: "malformed" as const };
    }
    const contentHash = sha256(serialized);
    if (Buffer.byteLength(serialized) > limits.maxRecordBytes) {
      return { key: entry.key, contentHash, observedAt: parseTimestamp(entry.value, source.modifiedAt), disposition: "oversized" as const };
    }
    if (sensitiveRecord(serialized)) {
      return { key: entry.key, contentHash, observedAt: parseTimestamp(entry.value, source.modifiedAt), disposition: "secret_bearing" as const };
    }
    const text = recordText(entry.value, limits.maxJsonDepth);
    return {
      key: entry.key,
      contentHash,
      observedAt: parseTimestamp(entry.value, source.modifiedAt),
      text,
      recordClass: classifyGenericHistoricalRecord(entry.value, source.type),
    };
  });
}

function parseLineRecords(
  source: LegacySource,
  binding: GenericSourceBinding,
  limits: { readonly maxSourceBytes: number; readonly maxRecordBytes: number; readonly maxJsonDepth: number },
): readonly ParsedRecord[] {
  const bytes = readPinnedBytes(source.absolutePath, binding, limits.maxSourceBytes);
  const records: ParsedRecord[] = [];
  let lineStart = 0;
  let lineNumber = 0;
  const addLine = (line: Buffer): void => {
    const key = `line:${lineNumber}`;
    lineNumber += 1;
    if (line.length === 0 || !line.toString("utf8").trim()) return;
    const contentHash = sha256(line);
    if (line.length > limits.maxRecordBytes) {
      records.push({ key, contentHash, observedAt: source.modifiedAt, disposition: "oversized" });
      return;
    }
    const raw = line.toString("utf8").normalize("NFKC");
    if (MALFORMED_TEXT.test(raw)) {
      records.push({ key, contentHash, observedAt: source.modifiedAt, disposition: "malformed" });
      return;
    }
    let value: unknown = { message: raw };
    if (
      extname(source.absolutePath).toLowerCase() === ".jsonl"
      || (source.type !== "dashboard_log" && source.type !== "provider_log")
    ) {
      try { value = JSON.parse(raw) as unknown; }
      catch {
        records.push({ key, contentHash, observedAt: source.modifiedAt, disposition: "malformed" });
        return;
      }
    }
    if (sensitiveRecord(raw)) {
      records.push({ key, contentHash, observedAt: parseTimestamp(value, source.modifiedAt), disposition: "secret_bearing" });
      return;
    }
    records.push({
      key,
      contentHash,
      observedAt: parseTimestamp(value, source.modifiedAt),
      text: recordText(value, limits.maxJsonDepth),
      recordClass: classifyGenericHistoricalRecord(value, source.type),
    });
  };
  for (let index = 0; index <= bytes.length; index += 1) {
    if (index !== bytes.length && bytes[index] !== 0x0a) continue;
    const end = index > lineStart && bytes[index - 1] === 0x0d ? index - 1 : index;
    addLine(bytes.subarray(lineStart, end));
    lineStart = index + 1;
  }
  return records;
}

/**
 * Parse a bounded Markdown conversation through the same pinned-read,
 * secret classifier, and reusable-text sanitizer used by JSON/session data.
 * Chunks end only at line boundaries and raw Markdown is never persisted.
 */
function parseMarkdownConversationRecords(
  source: LegacySource,
  binding: GenericSourceBinding,
  limits: { readonly maxSourceBytes: number; readonly maxRecordBytes: number; readonly maxJsonDepth: number },
): readonly ParsedRecord[] {
  const bytes = readPinnedBytes(source.absolutePath, binding, limits.maxSourceBytes);
  const raw = bytes.toString("utf8").normalize("NFKC");
  if (MALFORMED_TEXT.test(raw)) {
    return [{
      key: "document",
      contentHash: source.sha256,
      observedAt: source.modifiedAt,
      disposition: "malformed",
    }];
  }
  const records: ParsedRecord[] = [];
  const chunks: string[] = [];
  let current = "";
  const flush = (): void => {
    if (current.trim()) chunks.push(current);
    current = "";
  };
  for (const line of raw.split(/(?<=\n)/u)) {
    const lineBytes = Buffer.byteLength(line, "utf8");
    if (lineBytes > limits.maxRecordBytes) {
      flush();
      records.push({
        key: `oversized-line:${records.length}`,
        contentHash: sha256(line),
        observedAt: source.modifiedAt,
        disposition: "oversized",
      });
      continue;
    }
    if (Buffer.byteLength(current, "utf8") + lineBytes > limits.maxRecordBytes) flush();
    current += line;
  }
  flush();
  chunks.forEach((chunk, index) => {
    const key = `markdown:${index}`;
    const contentHash = sha256(chunk);
    if (sensitiveRecord(chunk)) {
      records.push({
        key,
        contentHash,
        observedAt: source.modifiedAt,
        disposition: "secret_bearing",
      });
      return;
    }
    records.push({
      key,
      contentHash,
      observedAt: source.modifiedAt,
      text: recordText({ message: chunk }, limits.maxJsonDepth),
      recordClass: classifyGenericHistoricalRecord({ message: chunk }, source.type),
    });
  });
  return records;
}

function tableNames(database: SqliteDatabase): readonly string[] {
  return (database.prepare(`
    SELECT name FROM sqlite_master
    WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
    ORDER BY name LIMIT 256
  `).all() as Array<{ readonly name: string }>).map(({ name }) => name);
}

function safeColumns(database: SqliteDatabase, table: string): readonly string[] {
  if (!SAFE_IDENTIFIER.test(table)) return [];
  return (database.prepare(`PRAGMA table_info("${table}")`).all() as Array<{ readonly name: string; readonly type: string }>)
    .filter(({ name, type }) => SAFE_IDENTIFIER.test(name) && !SENSITIVE_KEY.test(name) && !/BLOB/iu.test(type))
    .map(({ name }) => name)
    .slice(0, 32);
}

function parseSqliteRecords(
  source: LegacySource,
  binding: GenericSourceBinding,
  limits: { readonly maxSourceBytes: number; readonly maxRecordBytes: number; readonly maxJsonDepth: number; readonly queryLimit: number },
): readonly ParsedRecord[] {
  if (binding.byteSize > limits.maxSourceBytes) throw new RangeError("source exceeds bounded parser size");
  readPinnedBytes(source.absolutePath, binding, limits.maxSourceBytes);
  for (const suffix of ["-wal", "-journal"]) {
    const sidecar = `${source.absolutePath}${suffix}`;
    if (existsSync(sidecar) && statSync(sidecar).size > 0) throw new Error("sqlite_not_quiescent");
  }
  if (!SQLITE_SOURCE_TYPES.has(source.type)) return [];
  const kind = source.type as "kanban_sqlite" | "conversation_state_sqlite";
  const database = createDatabaseConnection({
    filename: source.absolutePath,
    readonly: true,
    fileMustExist: true,
    busyTimeoutMs: 0,
    verifyIntegrity: false,
  });
  const records: ParsedRecord[] = [];
  try {
    database.pragma("query_only = ON");
    const available = new Set(tableNames(database));
    for (const table of SQLITE_TABLES[kind]) {
      if (!available.has(table) || records.length >= limits.queryLimit) continue;
      const columns = safeColumns(database, table);
      if (columns.length === 0) continue;
      const quoted = columns.map((column) => `"${column}"`).join(", ");
      const remaining = limits.queryLimit - records.length;
      const rows = database.prepare(`SELECT ${quoted} FROM "${table}" ORDER BY rowid LIMIT ?`).all(remaining) as Record<string, unknown>[];
      rows.forEach((row, index) => {
        const normalized = Object.fromEntries(Object.entries(row).map(([key, value]) => [key,
          typeof value === "bigint" ? value.toString() : Buffer.isBuffer(value) ? `[BINARY:${value.byteLength}]` : value]));
        const serialized = JSON.stringify(normalized);
        const contentHash = sha256(serialized);
        if (Buffer.byteLength(serialized) > limits.maxRecordBytes) {
          records.push({ key: `${table}:${index}`, contentHash, observedAt: source.modifiedAt, disposition: "oversized" });
        } else if (sensitiveRecord(serialized)) {
          records.push({ key: `${table}:${index}`, contentHash, observedAt: parseTimestamp(normalized, source.modifiedAt), disposition: "secret_bearing" });
        } else {
          records.push({
            key: `${table}:${index}`,
            contentHash,
            observedAt: parseTimestamp(normalized, source.modifiedAt),
            text: recordText(normalized, limits.maxJsonDepth),
            recordClass: "structured_operational",
          });
        }
      });
    }
  } finally {
    database.close();
  }
  readPinnedBytes(source.absolutePath, binding, limits.maxSourceBytes);
  return records;
}

const PRODUCTS: readonly Readonly<{ expression: RegExp; name: string; type: AttackCentricReusableNodeType }>[] = [
  { expression: /\bApache(?: HTTP Server| httpd)?[ /](\d+(?:\.\d+){1,3}(?:[-+._a-z0-9]*)?)/giu, name: "Apache HTTP Server", type: "technology_product" },
  { expression: /\bnginx(?:\/|\s+)(\d+(?:\.\d+){1,3}(?:[-+._a-z0-9]*)?)/giu, name: "nginx", type: "technology_product" },
  { expression: /\bMicrosoft[- ]IIS(?:\/|\s+| httpd\s+)(\d+(?:\.\d+){1,3})/giu, name: "Microsoft IIS", type: "technology_product" },
  { expression: /\bOpenSSH[_ /](\d+(?:\.\d+){1,3}(?:p\d+)?)/giu, name: "OpenSSH", type: "technology_product" },
  { expression: /\bPHP(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "PHP", type: "runtime" },
  { expression: /\bASP\.NET(?: Core)?(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "ASP.NET", type: "framework" },
  { expression: /\bLinux(?: kernel)?(?:\/|\s+)(\d+\.\d+\.\d+(?:[-+._a-z0-9]*)?)/giu, name: "Linux kernel", type: "kernel" },
  { expression: /\bWindows Server(?:\/|\s+)(20\d{2})/giu, name: "Windows Server", type: "operating_system" },
  { expression: /\bMySQL(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "MySQL", type: "database" },
  { expression: /\bPostgreSQL(?:\/|\s+)(\d+(?:\.\d+){0,3})/giu, name: "PostgreSQL", type: "database" },
];

const ATTACKS: readonly Readonly<{ expression: RegExp; name: string; type: "attack_vector" | "attack_technique" }>[] = [
  { expression: /\bpath traversal\b|\bdirectory traversal\b/iu, name: "Path traversal", type: "attack_vector" },
  { expression: /\bremote code execution\b|\bRCE\b/u, name: "Remote code execution", type: "attack_technique" },
  { expression: /\bcommand injection\b/iu, name: "Command injection", type: "attack_vector" },
  { expression: /\bSQL injection\b|\bSQLi\b/iu, name: "SQL injection", type: "attack_vector" },
  { expression: /\bserver[- ]side request forgery\b|\bSSRF\b/u, name: "Server-side request forgery", type: "attack_vector" },
  { expression: /\bauthentication bypass\b/iu, name: "Authentication bypass", type: "attack_technique" },
  { expression: /\bprivilege escalation\b|\bprivesc\b/iu, name: "Privilege escalation", type: "attack_technique" },
  { expression: /\bNTLM relay\b/iu, name: "NTLM relay", type: "attack_technique" },
];

const TOOLS = ["nmap", "masscan", "naabu", "nuclei", "sqlmap", "ffuf", "gobuster", "feroxbuster", "netexec", "impacket", "metasploit"] as const;

function uniquePush<T>(items: T[], seen: Set<string>, key: string, value: T): void {
  if (!seen.has(key)) {
    seen.add(key);
    items.push(value);
  }
}

function knowledgeFromText(
  text: string,
  maxFacts: number,
  recordClass: GenericHistoricalRecordClass,
): KnowledgeExtraction {
  const facts: Fact[] = [];
  const edges: Edge[] = [];
  const seen = new Set<string>();
  const productRoles: string[] = [];
  const cveRoles: string[] = [];
  const attackRoles: string[] = [];
  for (const product of PRODUCTS) {
    product.expression.lastIndex = 0;
    for (const match of text.matchAll(product.expression)) {
      const version = match[1];
      if (!version) continue;
      const productRole = `product_${sha256(`${product.type}\0${product.name}`).slice(0, 12)}`;
      const versionRole = `version_${sha256(`${product.name}\0${version}`).slice(0, 12)}`;
      uniquePush(facts, seen, productRole, {
        role: productRole,
        nodeType: product.type,
        title: product.name,
        summary: `${product.name} is a reusable technology-stack component observed in historical operational data.`,
      });
      uniquePush(facts, seen, versionRole, {
        role: versionRole,
        nodeType: "exact_version_fingerprint",
        title: `${product.name} ${version}`,
        summary: `Exact ${product.name} version fingerprint ${version}; corroborate before reuse.`,
        body: canonicalJson({ product: product.name, exactVersion: version, verification: "historical_candidate" }),
      });
      productRoles.push(productRole);
      edges.push({ sourceRole: productRole, edgeType: "has_exact_version", targetRole: versionRole });
    }
  }
  for (const match of text.matchAll(/\bCVE-\d{4}-\d{4,7}\b/giu)) {
    const id = match[0]!.toUpperCase();
    const role = `cve_${sha256(id).slice(0, 12)}`;
    uniquePush(facts, seen, role, {
      role,
      nodeType: "cve",
      title: id,
      summary: `${id} was referenced historically and remains a candidate until applicability is independently validated.`,
      body: canonicalJson({ cveId: id, applicability: "unverified_historical_candidate" }),
    });
    cveRoles.push(role);
  }
  for (const attack of ATTACKS) {
    attack.expression.lastIndex = 0;
    if (!attack.expression.test(text)) continue;
    const role = `attack_${sha256(`${attack.type}\0${attack.name}`).slice(0, 12)}`;
    uniquePush(facts, seen, role, {
      role,
      nodeType: attack.type,
      title: attack.name,
      summary: `${attack.name} was observed as a historical attack concept and requires current-stack validation before reuse.`,
    });
    attackRoles.push(role);
  }
  const toolRoles: string[] = [];
  for (const tool of TOOLS) {
    if (!new RegExp(`\\b${tool}\\b`, "iu").test(text)) continue;
    const role = `tool_${sha256(tool).slice(0, 12)}`;
    uniquePush(facts, seen, role, {
      role,
      nodeType: "tool_artifact",
      title: tool === "nmap" ? "Nmap" : tool,
      summary: `${tool} was historically associated with this bounded technical observation.`,
      body: canonicalJson({ tool, version: "historical-unpinned" }),
    });
    toolRoles.push(role);
  }
  const failed = /\b(?:failed|failure|hang(?:s|ing|ed)?|timeout|timed out|crash(?:ed|ing)?|wedged|unreachable)\b/iu.test(text);
  const worked = /\b(?:worked|succeeded|successful|validated|confirmed)\b/iu.test(text);
  const hasOperationalObservation = /\b(?:banner|detected|discovered|evidence|exit(?:ed)?|fingerprint(?:ed)?|health check|identified|observed|open port|output|reported|responded|scan result|service version|timed out|timeout|validated|verified)\b/iu.test(text);
  const hasCveApplicability = /\b(?:affected|applicable|exploitable|not applicable|patched|unaffected|vulnerable)\b/iu.test(text);
  const hasRecoveryAction = /\b(?:reboot|rebooted|rebooting|recycle|recycled|recycling|reset|resetting|restart|restarted|restarting)\b/iu.test(text);
  const hasRecoverySequence = /\b(?:after|before retry|followed by|health check|recover(?:ed|y)|resolved|restore(?:d)?|then|verify health)\b/iu.test(text);
  const quality = evaluateGenericHistoricalKnowledgeQuality(recordClass, {
    productCount: productRoles.length,
    cveCount: cveRoles.length,
    attackCount: attackRoles.length,
    toolCount: toolRoles.length,
    hasOperationalObservation,
    hasCveApplicability,
    hasFailedOutcome: failed,
    hasWorkedOutcome: worked,
    hasRecoveryAction,
    hasRecoverySequence,
  });
  if (!quality.accepted) {
    return {
      factCount: 0,
      confidence: 0,
      ...(quality.reason ? { rejectionReason: quality.reason } : {}),
    };
  }
  let outcomeRole: string | undefined;
  let failureRole: string | undefined;
  if (quality.retainOutcome) {
    const status = failed && worked ? "mixed" : failed ? "failed" : "worked";
    const reportedOutcome = status === "mixed"
      ? "mixed"
      : status === "failed"
        ? "reported_failure"
        : "reported_success";
    outcomeRole = `outcome_${status}`;
    uniquePush(facts, seen, outcomeRole, {
      role: outcomeRole,
      nodeType: "outcome",
      title: `Historical technique outcome: ${status}`,
      summary: `A historical procedure was reported as ${status}; independent evidence review remains required.`,
      body: canonicalJson({
        reportedOutcome,
        reportedStatus: status,
        verification: "source_reported_unverified",
      }),
    });
    if (failed) {
      const name = /\bhang|wedged/iu.test(text) ? "Application or system hang"
        : /\btimeout|timed out/iu.test(text) ? "Execution timeout"
          : /\bcrash/iu.test(text) ? "Process or system crash" : "Historical procedure failure";
      failureRole = `failure_${sha256(name).slice(0, 12)}`;
      uniquePush(facts, seen, failureRole, {
        role: failureRole,
        nodeType: "failure_mode",
        title: name,
        summary: "The historical procedure did not produce a trustworthy successful terminal result.",
      });
      edges.push({ sourceRole: outcomeRole, edgeType: "failed_because", targetRole: failureRole });
    }
  }
  let recoveryRole: string | undefined;
  if (quality.retainRecovery) {
    recoveryRole = "recovery_bounded_reset";
    uniquePush(facts, seen, recoveryRole, {
      role: recoveryRole,
      nodeType: "recovery_pattern",
      title: "Bounded recovery and health verification",
      summary: "Restore only the affected disposable environment or service, then verify the execution path before retrying.",
    });
    if (failureRole) edges.push({ sourceRole: failureRole, edgeType: "recovered_with", targetRole: recoveryRole });
  }
  for (const cve of cveRoles) for (const product of productRoles) edges.push({ sourceRole: cve, edgeType: "affects", targetRole: product });
  for (const attack of attackRoles) {
    for (const cve of cveRoles) edges.push({ sourceRole: attack, edgeType: "exploits", targetRole: cve });
    for (const product of productRoles) edges.push({ sourceRole: attack, edgeType: "tested_against", targetRole: product });
    for (const tool of toolRoles) edges.push({ sourceRole: attack, edgeType: "implemented_by", targetRole: tool });
    if (outcomeRole) edges.push({ sourceRole: attack, edgeType: "produces_outcome", targetRole: outcomeRole });
  }
  if (facts.length === 0) return { factCount: 0, confidence: 0 };
  const bounded = facts.slice(0, maxFacts);
  const roles = new Set(bounded.map(({ role }) => role));
  const boundedEdges = edges.filter(({ sourceRole, targetRole }) => roles.has(sourceRole) && roles.has(targetRole));
  if (bounded.length === 1) {
    const only = bounded[0]!;
    return {
      factCount: 1,
      confidence: 0.72,
      knowledge: { kind: "reusable_fact", nodeType: only.nodeType, title: only.title, summary: only.summary, body: only.body },
    };
  }
  return {
    factCount: bounded.length,
    confidence: 0.76,
    knowledge: {
      kind: "reusable_bundle",
      facts: bounded,
      edges: boundedEdges,
    },
  };
}

/**
 * Canonical ingestion for generic legacy runtime/session/log/memory/lesson and
 * allowlisted SQLite state. It is local-only and never persists raw records,
 * excerpts, targets, addresses, engagement labels, or provider prompts.
 */
export class GenericHistoricalAttackKnowledgeIngestionService {
  readonly #database: SqliteDatabase;
  readonly #metadata: MigrationMetadataRepository;
  readonly #compiler: AttackKnowledgeCompiler;
  readonly #audit: AuditTrailWriter;
  readonly #key: Buffer;
  readonly #clock: () => Date;
  readonly #limits: Readonly<GenericHistoricalLimits>;

  constructor(database: SqliteDatabase, options: GenericHistoricalAttackKnowledgeIngestionOptions) {
    this.#database = database;
    this.#key = Buffer.isBuffer(options.receiptHmacKey) ? Buffer.from(options.receiptHmacKey) : Buffer.from(options.receiptHmacKey, "utf8");
    if (this.#key.byteLength < 32) throw new TypeError("Generic historical ingestion receipt key must contain at least 32 bytes");
    this.#clock = options.clock ?? (() => new Date());
    this.#limits = Object.freeze({
      maxSources: positiveInteger(options.maxSources ?? DEFAULTS.maxSources, "maxSources"),
      maxSourcesThisRun: DEFAULTS.maxSourcesThisRun,
      maxSourceBytes: positiveInteger(options.maxSourceBytes ?? DEFAULTS.maxSourceBytes, "maxSourceBytes"),
      maxTotalBytesThisRun: positiveInteger(options.maxTotalBytesThisRun ?? DEFAULTS.maxTotalBytesThisRun, "maxTotalBytesThisRun"),
      maxRecordsPerSourceThisRun: positiveInteger(options.maxRecordsPerSourceThisRun ?? DEFAULTS.maxRecordsPerSourceThisRun, "maxRecordsPerSourceThisRun"),
      maxRecordsThisRun: positiveInteger(options.maxRecordsThisRun ?? DEFAULTS.maxRecordsThisRun, "maxRecordsThisRun"),
      maxRecordBytes: positiveInteger(options.maxRecordBytes ?? DEFAULTS.maxRecordBytes, "maxRecordBytes"),
      maxFactsPerRecord: positiveInteger(options.maxFactsPerRecord ?? DEFAULTS.maxFactsPerRecord, "maxFactsPerRecord"),
      maxBundlesThisRun: positiveInteger(options.maxBundlesThisRun ?? DEFAULTS.maxBundlesThisRun, "maxBundlesThisRun"),
      maxJsonDepth: positiveInteger(options.maxJsonDepth ?? DEFAULTS.maxJsonDepth, "maxJsonDepth"),
    });
    if (this.#limits.maxTotalBytesThisRun < this.#limits.maxSourceBytes) {
      throw new TypeError("maxTotalBytesThisRun must be at least maxSourceBytes so one eligible source can progress");
    }
    this.#metadata = new MigrationMetadataRepository(database, this.#clock);
    this.#compiler = new AttackKnowledgeCompiler(database, { receiptHmacKey: this.#key, clock: this.#clock });
    this.#audit = new AuditTrailWriter(database);
  }

  #hmac(value: string): string {
    return createHmac("sha256", this.#key).update(value, "utf8").digest("hex");
  }

  #validateJob(request: GenericHistoricalAttackKnowledgeIngestionRequest): void {
    if (!SHA256.test(request.inventoryReceiptHash)) throw new TypeError("inventoryReceiptHash must be a lowercase SHA-256 digest");
    const row = this.#database.prepare(`
      SELECT receipt.receipt_hash, run.status, run.source_retention, run.brain_projection_mode
      FROM legacy_migration_inventory_receipts receipt
      JOIN legacy_migration_runs run ON run.id = receipt.migration_id
      WHERE receipt.migration_id = ?
    `).get(request.migrationId) as {
      readonly receipt_hash: string;
      readonly status: string;
      readonly source_retention: string;
      readonly brain_projection_mode: string;
    } | undefined;
    if (!row || row.receipt_hash !== request.inventoryReceiptHash) {
      throw new Error("Generic historical resume is not bound to the immutable migration inventory receipt");
    }
    if (!new Set(["running", "failed", "completed"]).has(row.status) || row.source_retention !== "verified-reference" ||
        row.brain_projection_mode !== "attack-knowledge-only") {
      throw new Error("Generic historical ingestion requires a verified-reference, attack-knowledge-only migration");
    }
  }

  #binding(migrationId: string, source: LegacySource): GenericSourceBinding {
    const row = this.#database.prepare(`
      SELECT object.source_id, object.source_reference, object.source_sha256,
        object.byte_size, object.modified_at, object.source_device, object.source_inode
      FROM legacy_migration_source_objects object
      JOIN legacy_migration_sources source ON source.id = object.source_id
      WHERE object.migration_id = ? AND object.source_path = ?
        AND object.source_sha256 = ? AND object.byte_size = ? AND object.modified_at = ?
        AND object.object_kind = 'source' AND object.verification_status = 'verified_reference'
        AND source.source_retention = 'verified-reference'
      ORDER BY object.verified_at DESC, object.id DESC LIMIT 1
    `).get(migrationId, source.absolutePath, source.sha256, source.byteSize, source.modifiedAt) as {
      readonly source_id: string;
      readonly source_reference: string;
      readonly source_sha256: string;
      readonly byte_size: number;
      readonly modified_at: string;
      readonly source_device: number;
      readonly source_inode: number;
    } | undefined;
    if (!row) throw new Error("Generic historical source lacks immutable verified-reference custody");
    return {
      sourceId: row.source_id,
      sourceReference: row.source_reference,
      sourceHash: row.source_sha256,
      byteSize: Number(row.byte_size),
      modifiedAt: row.modified_at,
      sourceDevice: Number(row.source_device),
      sourceInode: Number(row.source_inode),
    };
  }

  #contextIds(migrationId: string): { readonly missionId: string; readonly runId: string } {
    const digest = this.#hmac(`context\0${migrationId}`).slice(0, 40);
    return { missionId: `mission_hak_import_${digest}`, runId: `run_hak_import_${digest}` };
  }

  #ensureContext(migrationId: string): { readonly missionId: string; readonly runId: string } {
    const ids = this.#contextIds(migrationId);
    const now = this.#clock().toISOString();
    this.#database.prepare(`
      INSERT OR IGNORE INTO missions (
        id, name, objective, journey, status, authorization_status,
        scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
        created_by, version, created_at, updated_at, control_plane
      ) VALUES (?, 'Internal historical attack-knowledge import',
        'Private local source-custody context; not an executable engagement.',
        'guided', 'archived', 'unverified', '{}', '[]', ?, ?,
        'system:historical-attack-knowledge-import', 1, ?, ?, 'ti_scale')
    `).run(
      ids.missionId,
      canonicalJson({ internalOnly: true, preserveSourceCustody: true }),
      canonicalJson({ reusableRetrieval: false, allowAutonomous: false, projectToBrain: false }),
      now,
      now,
    );
    this.#database.prepare(`
      INSERT OR IGNORE INTO runs (
        id, mission_id, journey, status, progress, status_reason,
        next_action_summary, budget_json, budget_usage_json, retry_count,
        replan_count, started_at, ended_at, created_at, updated_at, version,
        control_plane
      ) VALUES (?, ?, 'guided', 'completed', 1,
        'Internal source-custody context completed; candidates await independent review.',
        'Review hash-bound evidence candidates', '{}', '{}', 0, 0,
        ?, ?, ?, ?, 1, 'ti_scale')
    `).run(ids.runId, ids.missionId, now, now, now, now);
    this.#database.prepare(`
      INSERT INTO historical_attack_knowledge_import_contexts (migration_id, mission_id, run_id, created_at)
      VALUES (?, ?, ?, ?) ON CONFLICT(migration_id) DO NOTHING
    `).run(migrationId, ids.missionId, ids.runId, now);
    return ids;
  }

  #sourceCandidateId(binding: GenericSourceBinding): string {
    return `candidate_hak_source_${this.#hmac(`content\0${binding.sourceHash}\0${binding.byteSize}`).slice(0, 48)}`;
  }

  #sourceCandidateExists(id: string): boolean {
    return Boolean(this.#database.prepare(`
      SELECT 1 AS present FROM historical_attack_knowledge_source_candidates WHERE candidate_id = ?
    `).get(id));
  }

  #sourceCandidate(binding: GenericSourceBinding, migrationId: string): { readonly id: string; readonly created: boolean } {
    const id = this.#sourceCandidateId(binding);
    const existing = this.#database.prepare(`
      SELECT source_hash, byte_size FROM historical_attack_knowledge_source_candidates WHERE candidate_id = ?
    `).get(id) as { readonly source_hash: string; readonly byte_size: number } | undefined;
    const context = this.#ensureContext(migrationId);
    const now = this.#clock().toISOString();
    if (!existing) {
      this.#database.prepare(`
        INSERT INTO evidence_candidates (
          id, mission_id, run_id, observation_id, artifact_id, evidence_type,
          label, meaning, promotion_reason, validation_requirements_json,
          state, sensitivity, proposed_by, created_at
        ) VALUES (?, ?, ?, NULL, NULL, 'historical_attack_source_record',
          'Historical attack-knowledge source record',
          'Hash-verified local source supporting one or more generalized attack-knowledge candidates.',
          'Independent review must re-hash the private local source and validate reusable claims before promotion.',
          ?, 'candidate', 'private', 'system:historical-attack-knowledge-extractor', ?)
      `).run(id, context.missionId, context.runId, canonicalJson([
        "Revalidate source device, inode, byte size, modification time, and SHA-256",
        "Review each generalized claim against the private source",
        "Confirm no target identity, address, journey metadata, or secret enters reusable memory",
      ]), now);
      this.#database.prepare(`
        INSERT INTO historical_attack_knowledge_source_candidates (candidate_id, source_hash, byte_size, created_at)
        VALUES (?, ?, ?, ?)
      `).run(id, binding.sourceHash, binding.byteSize, now);
      this.#audit.append({
        missionId: context.missionId,
        runId: context.runId,
        actor: { type: "system", id: "historical-attack-knowledge-extractor" },
        action: "evidence_candidate.proposed",
        resourceType: "evidence_candidate",
        resourceId: id,
        reason: "A locally parsed generic historical source requires independent review.",
        details: { sourceReference: binding.sourceReference, sourceHash: binding.sourceHash },
        occurredAt: now,
      });
    } else if (existing.source_hash !== binding.sourceHash || Number(existing.byte_size) !== binding.byteSize) {
      throw new Error("Historical generic source candidate immutable identity mismatch");
    }
    this.#database.prepare(`
      INSERT INTO historical_attack_knowledge_source_occurrences (
        candidate_id, migration_id, source_reference, source_hash, modified_at, observed_at
      ) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(candidate_id, migration_id, source_reference) DO NOTHING
    `).run(id, migrationId, binding.sourceReference, binding.sourceHash, binding.modifiedAt, now);
    return { id, created: !existing };
  }

  #linkBundle(bundleId: string, receiptId: string, candidateId: string, binding: GenericSourceBinding): number {
    const now = this.#clock().toISOString();
    const bindingHash = this.#hmac(canonicalJson({ bundleId, receiptId, candidateId, sourceHash: binding.sourceHash }));
    return this.#database.prepare(`
      INSERT INTO historical_attack_knowledge_bundle_sources (
        bundle_id, receipt_id, candidate_id, source_hash, binding_hash, linked_at
      ) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(bundle_id, receipt_id, candidate_id) DO NOTHING
    `).run(bundleId, receiptId, candidateId, binding.sourceHash, bindingHash, now).changes;
  }

  ingest(request: GenericHistoricalAttackKnowledgeIngestionRequest): GenericHistoricalAttackKnowledgeIngestionResult {
    this.#validateJob(request);
    if (request.sources.length > this.#limits.maxSources) throw new RangeError("Generic source inventory exceeds the configured source budget");
    const dryRun = request.dryRun === true;
    const maxSourcesThisRun = Math.min(
      positiveInteger(request.maxSourcesThisRun ?? this.#limits.maxSourcesThisRun, "maxSourcesThisRun"),
      this.#limits.maxSources,
    );
    const maxRecordsThisRun = Math.min(
      positiveInteger(request.maxRecordsThisRun ?? this.#limits.maxRecordsThisRun, "maxRecordsThisRun"),
      this.#limits.maxRecordsThisRun,
    );
    const maxBundlesThisRun = Math.min(
      positiveInteger(request.maxBundlesThisRun ?? this.#limits.maxBundlesThisRun, "maxBundlesThisRun"),
      this.#limits.maxBundlesThisRun,
    );
    const compilerBatch = this.#compiler.beginDeferredReconciliationBatch({
      maxCompilations: maxBundlesThisRun,
    });
    if (request.interruptAfterNewRecords !== undefined) positiveInteger(request.interruptAfterNewRecords, "interruptAfterNewRecords");

    const eligible = request.sources
      .map((source) => ({ source, key: sourceKey(request.inventoryReceiptHash, source) }))
      .sort((left, right) => left.key.localeCompare(right.key));
    if (request.resumeAfterRecordKey && !request.resumeAfterSourceKey) {
      throw new TypeError("resumeAfterRecordKey requires resumeAfterSourceKey");
    }
    if (request.resumeAfterSourceKey && !SHA256.test(request.resumeAfterSourceKey)) {
      throw new TypeError("resumeAfterSourceKey must be an opaque lowercase SHA-256 digest");
    }
    if (request.resumeAfterRecordKey && !SHA256.test(request.resumeAfterRecordKey)) {
      throw new TypeError("resumeAfterRecordKey must be an opaque lowercase SHA-256 digest");
    }
    let startIndex = 0;
    if (request.resumeAfterSourceKey) {
      const index = eligible.findIndex(({ key }) => key === request.resumeAfterSourceKey);
      if (index < 0) throw new TypeError("resumeAfterSourceKey is not part of this immutable inventory receipt");
      startIndex = request.resumeAfterRecordKey ? index : index + 1;
    }
    const issues: GenericHistoricalIngestionIssue[] = [];
    const candidateIds = new Set<string>();
    const sourceEvidenceCandidateIds = new Set<string>();
    let sourcesAccounted = 0;
    let sourcesProcessed = 0;
    let sourcesCompleted = 0;
    let filesParsed = 0;
    let filesSkipped = 0;
    let filesQuarantined = 0;
    let bytesParsed = 0;
    let bytesThisRun = 0;
    let recordsDiscovered = 0;
    let recordsProcessed = 0;
    let recordsDeduplicated = 0;
    let recordsQuarantined = 0;
    let recordsSkipped = 0;
    let semanticFactsParsed = 0;
    let compilerBundlesStaged = 0;
    let candidatesCreated = 0;
    let candidatesReused = 0;
    let sourceEvidenceCandidatesCreated = 0;
    let sourceEvidenceCandidatesReused = 0;
    let sourceBundleLinks = 0;
    const nodeTypeCounts: Record<string, number> = {};
    const edgeTypeCounts: Record<string, number> = {};
    let partial = false;
    let lastSourceKey: string | undefined;
    let lastRecordKey: string | undefined;
    let resumeWithinSource = false;

    for (let sourceIndex = startIndex; sourceIndex < eligible.length; sourceIndex += 1) {
      if (sourcesProcessed >= maxSourcesThisRun || recordsProcessed >= maxRecordsThisRun || compilerBundlesStaged >= maxBundlesThisRun) {
        partial = true;
        break;
      }
      const entry = eligible[sourceIndex]!;
      const { source, key } = entry;
      sourcesAccounted += 1;
      lastRecordKey = undefined;
      resumeWithinSource = false;
      if (!SUPPORTED_SOURCE_TYPES.has(source.type)) {
        sourcesProcessed += 1;
        sourcesCompleted += 1;
        lastSourceKey = key;
        filesSkipped += 1;
        issues.push({ sourceKey: key, disposition: "skipped", reason: "unsupported_source" });
        continue;
      }
      let binding: GenericSourceBinding;
      try { binding = this.#binding(request.migrationId, source); }
      catch {
        filesQuarantined += 1;
        sourcesProcessed += 1;
        sourcesCompleted += 1;
        lastSourceKey = key;
        issues.push({ sourceKey: key, disposition: "quarantined", reason: "source_changed" });
        continue;
      }
      const sourceIdentity = sha256Text(`${source.type}\0${source.absolutePath}`);
      const sourceCompleteKey = "generic-attack-v1:source-complete";
      if (this.#metadata.previousItem(
        sourceIdentity,
        source.sha256,
        sourceCompleteKey,
        source.sha256,
      )) {
        lastSourceKey = key;
        continue;
      }
      if (!hasGenericHistoricalReusableSourceBoundary(source)) {
        sourcesProcessed += 1;
        sourcesCompleted += 1;
        lastSourceKey = key;
        filesSkipped += 1;
        issues.push({ sourceKey: key, disposition: "skipped", reason: "unbound_provider_history" });
        if (!dryRun) this.#metadata.recordItem({
          migrationId: request.migrationId,
          sourceId: binding.sourceId,
          sourceIdentity,
          sourceSha256: source.sha256,
          itemKey: sourceCompleteKey,
          itemHash: source.sha256,
          status: "skipped",
          errorCategory: "unbound_provider_history",
        });
        continue;
      }
      if (source.byteSize > this.#limits.maxSourceBytes) {
        sourcesProcessed += 1;
        sourcesCompleted += 1;
        lastSourceKey = key;
        filesQuarantined += 1;
        issues.push({ sourceKey: key, disposition: "quarantined", reason: "source_budget_exceeded" });
        if (!dryRun) this.#metadata.recordItem({
          migrationId: request.migrationId,
          sourceId: binding.sourceId,
          sourceIdentity,
          sourceSha256: source.sha256,
          itemKey: sourceCompleteKey,
          itemHash: source.sha256,
          status: "quarantined",
          errorCategory: "source_budget_exceeded",
        });
        continue;
      }
      if (bytesThisRun + source.byteSize > this.#limits.maxTotalBytesThisRun) {
        partial = true;
        issues.push({ sourceKey: key, disposition: "ambiguous", reason: "total_budget_exceeded" });
        break;
      }
      let parsed: readonly ParsedRecord[];
      try {
        parsed = SQLITE_SOURCE_TYPES.has(source.type)
          ? parseSqliteRecords(source, binding, {
            maxSourceBytes: this.#limits.maxSourceBytes,
            maxRecordBytes: this.#limits.maxRecordBytes,
            maxJsonDepth: this.#limits.maxJsonDepth,
            queryLimit: this.#limits.maxRecordsPerSourceThisRun + 1,
          })
          : LINE_SOURCE_TYPES.has(source.type)
            ? parseLineRecords(source, binding, this.#limits)
            : MARKDOWN_SOURCE_TYPES.has(source.type)
              ? parseMarkdownConversationRecords(source, binding, this.#limits)
              : parseStructuredRecords(source, binding, this.#limits);
      } catch (error) {
        filesQuarantined += 1;
        sourcesProcessed += 1;
        sourcesCompleted += 1;
        lastSourceKey = key;
        const reason = error instanceof RangeError ? "source_budget_exceeded"
          : error instanceof SourceChangedError ? "source_changed"
            : error instanceof Error && error.message === "sqlite_not_quiescent" ? "sqlite_not_quiescent"
              : "sqlite_schema_unsupported";
        issues.push({ sourceKey: key, disposition: "quarantined", reason });
        continue;
      }
      recordsDiscovered += parsed.length;
      bytesThisRun += source.byteSize;
      let sourceNewRecords = 0;
      let sourceHadSemantic = false;
      let sourceIncomplete = false;
      let sourceCandidate: { readonly id: string; readonly created: boolean } | undefined;
      let recordStartIndex = 0;
      if (request.resumeAfterRecordKey && request.resumeAfterSourceKey === key) {
        const index = parsed.findIndex((record) => sha256Text(`${key}\0${record.key}`) === request.resumeAfterRecordKey);
        if (index < 0) throw new TypeError("resumeAfterRecordKey is not part of its opaque source cursor");
        recordStartIndex = index + 1;
      }
      for (let recordIndex = recordStartIndex; recordIndex < parsed.length; recordIndex += 1) {
        const record = parsed[recordIndex]!;
        const opaqueRecordKey = sha256Text(`${key}\0${record.key}`);
        const ledgerKey = itemKey(record.key);
        // The production preview runs in a newly migrated disposable database
        // and deliberately persists no item ledger. Querying that necessarily
        // empty ledger once per record created hundreds of thousands of native
        // prepared statements and amplified Bun/JSC RSS despite bounded pages.
        // Executing/resumed imports retain the exact durable deduplication gate.
        const previous = dryRun
          ? undefined
          : this.#metadata.previousItem(sourceIdentity, source.sha256, ledgerKey, record.contentHash);
        if (previous) {
          recordsDeduplicated += 1;
          continue;
        }
        if (sourceNewRecords >= this.#limits.maxRecordsPerSourceThisRun || recordsProcessed >= maxRecordsThisRun) {
          partial = true;
          sourceIncomplete = true;
          issues.push({ sourceKey: key, disposition: "ambiguous", reason: "record_budget_exceeded" });
          break;
        }
        if (request.interruptAfterNewRecords !== undefined && recordsProcessed >= request.interruptAfterNewRecords) {
          partial = true;
          sourceIncomplete = true;
          break;
        }
        sourceNewRecords += 1;
        recordsProcessed += 1;
        if (record.disposition) {
          recordsQuarantined += 1;
          const reason = record.disposition === "secret_bearing" ? "secret_bearing_record"
            : record.disposition === "oversized" ? "record_size_exceeded" : "malformed_record";
          issues.push({ sourceKey: key, disposition: "quarantined", reason });
          if (!dryRun) {
            this.#metadata.recordItem({
              migrationId: request.migrationId,
              sourceId: binding.sourceId,
              sourceIdentity,
              sourceSha256: source.sha256,
              itemKey: ledgerKey,
              itemHash: record.contentHash,
              status: "quarantined",
              errorCategory: reason,
            });
            this.#metadata.quarantine(request.migrationId, {
              sourceSha256: source.sha256,
              sourcePath: source.absolutePath,
              itemKey: ledgerKey,
              itemHash: record.contentHash,
              category: reason,
              reason: "Generic historical record was quarantined locally; no raw content or excerpt was retained.",
              byteSize: source.byteSize,
              sourceModifiedAt: source.modifiedAt,
              sourceReference: binding.sourceReference,
              retentionMode: "verified-reference",
              sourceDevice: binding.sourceDevice,
              sourceInode: binding.sourceInode,
            });
          }
          lastRecordKey = opaqueRecordKey;
          continue;
        }
        const extraction = knowledgeFromText(
          record.text ?? "",
          this.#limits.maxFactsPerRecord,
          record.recordClass ?? "narrative",
        );
        if (!extraction.knowledge) {
          recordsSkipped += 1;
          const reason = extraction.rejectionReason ?? "no_reusable_semantics";
          issues.push({ sourceKey: key, disposition: "skipped", reason });
          if (!dryRun) this.#metadata.recordItem({
            migrationId: request.migrationId,
            sourceId: binding.sourceId,
            sourceIdentity,
            sourceSha256: source.sha256,
            itemKey: ledgerKey,
            itemHash: record.contentHash,
            status: "skipped",
            errorCategory: reason,
          });
          lastRecordKey = opaqueRecordKey;
          continue;
        }
        if (compilerBundlesStaged >= maxBundlesThisRun) {
          recordsProcessed -= 1;
          sourceNewRecords -= 1;
          partial = true;
          sourceIncomplete = true;
          issues.push({ sourceKey: key, disposition: "ambiguous", reason: "bundle_budget_exceeded" });
          break;
        }
        const result = compilerBatch.compile({
          source: {
            privateSourceReference: source.absolutePath,
            sourceClass: "historical",
            sourceHash: sha256(`${source.sha256}\0${record.contentHash}\0${record.observedAt}`),
            observedAt: record.observedAt,
            evidenceCount: 1,
          },
          knowledge: extraction.knowledge,
          confidence: extraction.confidence,
        }, { dryRun });
        if (result.status === "quarantined") {
          recordsQuarantined += 1;
          issues.push({ sourceKey: key, disposition: "quarantined", reason: "compiler_privacy_boundary" });
          if (!dryRun) this.#metadata.recordItem({
            migrationId: request.migrationId,
            sourceId: binding.sourceId,
            sourceIdentity,
            sourceSha256: source.sha256,
            itemKey: ledgerKey,
            itemHash: record.contentHash,
            status: "quarantined",
            errorCategory: "compiler_privacy_boundary",
          });
          lastRecordKey = opaqueRecordKey;
          continue;
        }
        addKnowledgeDistribution(extraction.knowledge, nodeTypeCounts, edgeTypeCounts);
        sourceHadSemantic = true;
        semanticFactsParsed += extraction.factCount;
        compilerBundlesStaged += 1;
        candidatesCreated += result.candidatesCreated;
        candidatesReused += result.candidatesReused;
        result.candidateIds.forEach((id) => candidateIds.add(id));
        if (result.bundleId && result.provenanceReceiptId) {
          if (!sourceCandidate) {
            sourceCandidate = dryRun
              ? (() => {
                const id = this.#sourceCandidateId(binding);
                return { id, created: !this.#sourceCandidateExists(id) };
              })()
              : this.#sourceCandidate(binding, request.migrationId);
            sourceEvidenceCandidateIds.add(sourceCandidate.id);
            sourceCandidate.created ? sourceEvidenceCandidatesCreated += 1 : sourceEvidenceCandidatesReused += 1;
          }
          if (!dryRun) {
            sourceBundleLinks += this.#linkBundle(result.bundleId, result.provenanceReceiptId, sourceCandidate.id, binding);
            this.#metadata.recordItem({
              migrationId: request.migrationId,
              sourceId: binding.sourceId,
              sourceIdentity,
              sourceSha256: source.sha256,
              itemKey: ledgerKey,
              itemHash: record.contentHash,
              status: result.candidatesCreated > 0 ? "imported" : "deduplicated",
              targetTable: "attack_knowledge_bundles",
              targetId: result.bundleId,
            });
          }
        }
        lastRecordKey = opaqueRecordKey;
      }
      sourcesProcessed += 1;
      if (sourceHadSemantic) {
        filesParsed += 1;
        bytesParsed += source.byteSize;
      } else if (parsed.some((record) => record.disposition)) filesQuarantined += 1;
      else filesSkipped += 1;
      if (!dryRun && !sourceIncomplete) {
        this.#metadata.recordItem({
          migrationId: request.migrationId,
          sourceId: binding.sourceId,
          sourceIdentity,
          sourceSha256: source.sha256,
          itemKey: sourceCompleteKey,
          itemHash: source.sha256,
          status: "skipped",
          errorCategory: "generic_source_complete",
        });
      }
      if (!sourceIncomplete) {
        sourcesCompleted += 1;
        lastSourceKey = key;
      } else {
        resumeWithinSource = true;
        lastSourceKey = key;
      }
      if (partial) break;
    }
    if (startIndex + sourcesAccounted < eligible.length) partial = true;
    const compilerBatchResult = compilerBatch.finish();
    return {
      status: partial ? "partial" : "completed",
      dryRun,
      manifestFingerprint: request.inventoryReceiptHash,
      inventoryReceiptHash: request.inventoryReceiptHash,
      filesDiscovered: eligible.length,
      filesParsed,
      filesSkipped,
      filesQuarantined,
      bytesParsed,
      semanticFactsParsed,
      ambiguousFragments: issues.filter(({ disposition }) => disposition === "ambiguous").reduce((sum, issue) => sum + (issue.count ?? 1), 0),
      compilerBundlesStaged,
      candidatesCreated,
      candidatesReused,
      sourceEvidenceCandidatesCreated,
      sourceEvidenceCandidatesReused,
      sourceBundleLinks,
      compilerReconciliation: compilerBatchResult.reconciliation,
      compilerReconciliationPasses: compilerBatchResult.reconciliationPasses,
      compilerRunsReconciled: compilerBatchResult.compilerRunsReconciled,
      nodeTypeCounts: Object.fromEntries(Object.entries(nodeTypeCounts).sort(([left], [right]) => left.localeCompare(right))),
      edgeTypeCounts: Object.fromEntries(Object.entries(edgeTypeCounts).sort(([left], [right]) => left.localeCompare(right))),
      sourcesProcessed,
      sourcesCompleted,
      recordsDiscovered,
      recordsProcessed,
      recordsDeduplicated,
      recordsQuarantined,
      recordsSkipped,
      ...(partial && lastSourceKey ? { nextResumeAfterSourceKey: lastSourceKey } : {}),
      ...(partial && resumeWithinSource && lastRecordKey ? { nextResumeAfterRecordKey: lastRecordKey } : {}),
      issues,
      candidateIds: [...candidateIds].sort(),
      sourceEvidenceCandidateIds: [...sourceEvidenceCandidateIds].sort(),
    };
  }
}

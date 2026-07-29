import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { basename, dirname, extname, join } from "node:path";
import type { SqliteDatabase } from "../db/types";
import { inImmediateTransaction } from "../db/transaction";
import {
  getMemoryControlPolicy,
  memoryCandidateAllowed,
  type MemoryControlPolicy,
} from "../memory/MemoryControlPolicy";
import {
  isTerminalAttackKnowledgeReviewCandidate,
  TERMINAL_ATTACK_KNOWLEDGE_REVIEW_NODE_TYPES,
  TERMINAL_ATTACK_KNOWLEDGE_REVIEW_SCHEMA,
} from "../memory/TerminalAttackKnowledgeReview";
import { assertIdentifier } from "../memory/validation";
import {
  assertReusableMemoryText,
  ATTACK_CENTRIC_REUSABLE_NODE_TYPES,
  isAttackCentricReusableNodeType,
  MEMORY_LIFECYCLE_STATES,
  MEMORY_NODE_TYPES,
  MEMORY_SCOPE_KINDS,
  MEMORY_SENSITIVITIES,
  MemoryRepository,
  HistoricalReportedOutcomeService,
  ReusableKnowledgeOutcomeService,
  REUSABLE_MEMORY_LIMITS,
  ReusableMemorySafetyError,
  type CreateMemoryEdgeInput,
  type ForgetResult,
  type MemoryEdge,
  type MemoryNode,
  type MemoryProvenance,
  type ProvenanceSource,
} from "../memory/index";
import {
  OBSIDIAN_V2_4_VAULT_FOLDERS,
  parseObsidianNote,
  projectPrivateProvenanceIds,
  renderObsidianNote,
  vaultRelativePath,
} from "./ObsidianMarkdown";
import {
  safeVaultSegment,
  VaultDestinationChangedError,
  VaultPathPolicy,
} from "./VaultPathPolicy";
import { obsidianDeepLink } from "./ObsidianDeepLink";
import { writePortableZip, type PortableZipEntry } from "./PortableZip";
import { ObsidianPluginManager } from "./ObsidianPluginManager";
import { activeVaultPathFingerprint } from "./ActiveVaultComposition";
import {
  OPERATOR_PROFILE_VAULT_FOLDER,
  isOperatorProfileVaultNodeAllowed,
  operatorProfileVaultOperatorId,
  operatorProfileVaultEligibleNodeIds,
  vaultScopeIncludesOperatorProfile,
} from "./OperatorProfileVaultProjection";
import type {
  VaultConnection,
  VaultBulkExportCounts,
  VaultBulkExportIssue,
  VaultBulkExportOptions,
  VaultBulkExportProgress,
  VaultBulkExportResult,
  VaultImportResult,
  VaultNote,
  VaultPortableExport,
  VaultPortableExportOptions,
  VaultSyncVerification,
  VaultSyncVerificationItem,
  VaultSyncResult,
} from "./types";

interface ConnectionRow {
  id: string;
  vault_path: string;
  display_name: string;
  status: VaultConnection["status"];
  sync_scope_json: string;
  permission_granted_at: string;
  last_sync_at: string | null;
  created_at: string;
  updated_at: string;
}

interface SyncStateRow {
  id: string;
  connection_id: string;
  node_id: string | null;
  relative_path: string;
  database_version: number | null;
  vault_content_hash: string | null;
  database_content_hash: string | null;
  status: string;
  last_scanned_at: string | null;
  last_synced_at: string | null;
  error_message: string | null;
}

export interface BridgeOptions {
  readonly clock?: () => Date;
  readonly createId?: (prefix: string) => string;
  /** Test seam immediately before a managed file is opened with O_NOFOLLOW. */
  readonly beforeManagedRead?: (absolutePath: string) => void;
  /** Legacy-named test seam after a durable quarantine intent and before the guarded move. */
  readonly beforeQuarantineCopy?: (absolutePath: string) => void;
  /** Legacy-named test seam after the move is durable but before its marker/state commit. */
  readonly afterQuarantineCopy?: (intentId: string) => void;
  /** Pinned-release test/deployment seam used only for optional portable handoff. */
  readonly brainAtlasPluginManager?: ObsidianPluginManager;
}

type Mutable<T> = { -readonly [Key in keyof T]: T[Key] };

interface CanonicalVaultAttachment {
  readonly artifactId: string;
  readonly missionId: string;
  readonly contentHash: string;
  readonly byteSize: number;
  readonly mediaType?: string;
  readonly extension: string;
  readonly storageUri: string;
  readonly relativePath: string;
}

interface ArtifactRow {
  readonly id: string;
  readonly mission_id: string;
  readonly journey: "autonomous" | "guided";
  readonly artifact_type: string;
  readonly storage_uri: string;
  readonly content_hash: string;
  readonly byte_size: number;
  readonly media_type: string | null;
  readonly sensitivity: MemoryNode["sensitivity"];
  readonly metadata_json: string;
}

const MAX_ATTACHMENT_BYTES = 32 * 1024 * 1024;
const MAX_ATTACHMENTS_PER_NOTE = 32;
const MAX_RECOVERY_NOTE_BYTES = 2 * 1024 * 1024;
// Keep a hard per-operation ceiling while allowing a fully imported, verified
// engagement corpus to be projected in one resumable pass. The eligible
// imported corpus is already above the previous 50,000-note ceiling.
const MAX_BULK_EXPORT_NOTES = 100_000;
const MAX_SYNC_SCOPE_NODE_IDS = 10_000;
const MAX_BULK_EXPORT_CONCURRENCY = 32;
const MAX_BULK_EXPORT_ISSUES = 100;
const MAX_ARTIFACT_BACKLINKS = 8;
const SHA256_HEX = /^[a-f0-9]{64}$/u;
const REUSABLE_VAULT_NODE_TYPES = [
  ...ATTACK_CENTRIC_REUSABLE_NODE_TYPES,
] as const satisfies readonly MemoryNode["nodeType"][];
const REUSABLE_VAULT_NODE_TYPE_SET: ReadonlySet<string> = new Set(REUSABLE_VAULT_NODE_TYPES);
const RUNTIME_CAPABILITY_VAULT_NODE_TYPE_SET: ReadonlySet<string> =
  new Set(["agent", "tool", "mcp_capability"]);
const RUNTIME_CAPABILITY_MEMORY_SCHEMA =
  "ti-scale.runtime-capability-memory-projection.v1";
const CURRENT_RUNTIME_CAPABILITY_PROJECTION_SQL = `(
  node_type IN ('agent', 'tool', 'mcp_capability')
  AND author_type = 'system'
  AND author_id = 'system:runtime-capability-memory-projector'
  AND scope = 'global'
  AND lifecycle_status = 'verified'
  AND json_extract(
    retention_policy_json,
    '$.runtimeCapabilityProjection.schemaVersion'
  ) = 'ti-scale.runtime-capability-memory-projection.v1'
  AND json_extract(
    retention_policy_json,
    '$.runtimeCapabilityProjection.status'
  ) = 'current'
  AND json_extract(
    retention_policy_json,
    '$.agentToolDecision.schemaVersion'
  ) = '1'
)`;

function isCurrentRuntimeCapabilityProjectionNode(node: MemoryNode): boolean {
  if (!RUNTIME_CAPABILITY_VAULT_NODE_TYPE_SET.has(node.nodeType)) return false;
  const projection = node.retentionPolicy.runtimeCapabilityProjection;
  const typedDecision = node.retentionPolicy.agentToolDecision;
  const currentProjection = projection !== null
    && typeof projection === "object"
    && !Array.isArray(projection)
    && (projection as Record<string, unknown>).schemaVersion
      === RUNTIME_CAPABILITY_MEMORY_SCHEMA
    && (projection as Record<string, unknown>).status === "current";
  const typed = typedDecision !== null
    && typeof typedDecision === "object"
    && !Array.isArray(typedDecision)
    && (typedDecision as Record<string, unknown>).schemaVersion === "1";
  return node.authorType === "system"
    && node.authorId === "system:runtime-capability-memory-projector"
    && node.scope.kind === "global"
    && node.lifecycleStatus === "verified"
    && currentProjection
    && typed;
}
const ATTACHMENT_EXTENSIONS = new Map<string, string>([
  [".avif", "image/avif"],
  [".csv", "text/csv"],
  [".gif", "image/gif"],
  [".jpeg", "image/jpeg"],
  [".jpg", "image/jpeg"],
  [".json", "application/json"],
  [".log", "text/plain"],
  [".pdf", "application/pdf"],
  [".png", "image/png"],
  [".txt", "text/plain"],
  [".webp", "image/webp"],
]);

function hashText(value: string): string {
  return createHash("sha256").update(value.replaceAll("\r\n", "\n"), "utf8").digest("hex");
}

function hashBytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalAuditValue(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalAuditValue).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .filter((key) => record[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonicalAuditValue(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function sameFileIdentity(
  left: { readonly dev: number; readonly ino: number },
  right: { readonly dev: number; readonly ino: number },
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function attachmentExtension(relativePath: string): { extension: string; mediaType: string } {
  if (relativePath.includes("\\") || relativePath.includes("\0")) {
    throw new Error("Vault attachment path is invalid");
  }
  const segments = relativePath.split("/");
  if (segments.length !== 2 || segments[0] !== "Attachments" || !segments[1] || [".", ".."].includes(segments[1])) {
    throw new Error("Vault attachments must be direct files in the managed Attachments directory");
  }
  const extension = extname(segments[1]).toLowerCase();
  const mediaType = ATTACHMENT_EXTENSIONS.get(extension);
  if (!mediaType) throw new Error("Vault attachment type is not permitted");
  return { extension, mediaType };
}

function attachmentStorageUri(connectionId: string, contentHash: string): string {
  return `vault-attachment://${encodeURIComponent(connectionId)}/${contentHash}`;
}

function parseAttachmentStorageUri(value: string): { connectionId: string; contentHash: string } {
  const match = /^vault-attachment:\/\/([^/]+)\/([a-f0-9]{64})$/u.exec(value);
  if (!match) throw new Error("Canonical vault attachment storage reference is invalid");
  let connectionId: string;
  try {
    connectionId = decodeURIComponent(match[1]!);
  } catch {
    throw new Error("Canonical vault attachment connection reference is invalid");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(connectionId)) {
    throw new Error("Canonical vault attachment connection reference is invalid");
  }
  return { connectionId, contentHash: match[2]! };
}

function parseJsonObject(source: string): Record<string, unknown> {
  const value = JSON.parse(source) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Stored vault sync scope is malformed");
  }
  return value as Record<string, unknown>;
}

function connectionFromRow(row: ConnectionRow): VaultConnection {
  return {
    id: row.id,
    vaultPath: row.vault_path,
    displayName: row.display_name,
    status: row.status,
    syncScope: parseJsonObject(row.sync_scope_json),
    permissionGrantedAt: row.permission_granted_at,
    ...(row.last_sync_at ? { lastSyncAt: row.last_sync_at } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function boundedExportError(error: unknown): string {
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  if (error instanceof ReusableMemorySafetyError || message.includes("reusable-memory safety")) {
    return "Canonical memory content was rejected by the reusable-memory safety policy";
  }
  if (message.includes("outside the vault connection")) {
    return "Canonical memory is outside this vault connection's explicit sync scope";
  }
  if (message.includes("private operational provenance")) {
    return "Private operational records are not exportable to the reusable Attack Knowledge Vault";
  }
  if (message.includes("synchronization is not permitted") || message.includes("memory control policy")) {
    return "Obsidian synchronization is disabled by the current memory control policy";
  }
  if (message.includes("symbolic link") || message.includes("symlink")) {
    return "Managed vault path safety validation rejected a symbolic link";
  }
  if (message.includes("traversal") || message.includes("escapes") || message.includes("outside its configured root")) {
    return "Managed vault path safety validation rejected an out-of-scope path";
  }
  if (message.includes("attachment")) {
    return "Canonical attachment projection failed integrity or scope validation";
  }
  if (message.includes("memory node not found")) {
    return "Canonical memory node was not found";
  }
  return "Canonical note export failed validation; inspect restricted server diagnostics";
}

class VaultCanonicalChangedError extends Error {
  constructor() {
    super("Canonical memory changed while an atomic projection was being prepared");
    this.name = "VaultCanonicalChangedError";
  }
}

class VaultSyncPolicyRevokedError extends Error {
  constructor() {
    super("Obsidian synchronization was disabled while bulk export was running");
    this.name = "VaultSyncPolicyRevokedError";
  }
}

export class VaultManagedNoteInspectionError extends Error {
  readonly contentHash: string;

  constructor(message: string, contentHash: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "VaultManagedNoteInspectionError";
    this.contentHash = contentHash;
  }
}

interface ManagedNoteSnapshot {
  readonly bytes: Buffer;
  readonly source: string;
  /** Hash of exact bytes, used only as the quarantine compare-and-move guard. */
  readonly exactHash: string;
}

interface VaultQuarantineIntent {
  readonly id: string;
  readonly connectionId: string;
  readonly sourcePathHash: string;
  readonly sourceContentHash: string;
  readonly quarantineRelative: string;
  readonly markerRelative: string;
  readonly syncStateId: string;
  readonly reason: string;
  readonly status: "planned" | "recovery_required" | "committed";
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface VaultQuarantineRecovery {
  readonly recovered: number;
  readonly unresolved: number;
}

export class VaultBulkExportAbortError extends Error {
  readonly result: VaultBulkExportResult;

  constructor(result: VaultBulkExportResult) {
    super(`Obsidian vault export aborted after ${result.processed} of ${result.total} notes`);
    this.name = "AbortError";
    this.result = result;
  }
}

export class VaultBulkExportPolicyError extends Error {
  readonly result: VaultBulkExportResult;

  constructor(result: VaultBulkExportResult) {
    super(`Obsidian vault export stopped by policy after ${result.processed} of ${result.total} notes`);
    this.name = "VaultBulkExportPolicyError";
    this.result = result;
  }
}

/**
 * Obsidian-compatible projection and import bridge. SQLite remains canonical;
 * files are versioned human-editable projections with explicit conflicts.
 */
export class ObsidianVaultBridge {
  readonly #database: SqliteDatabase;
  readonly #memory: MemoryRepository;
  readonly #paths: VaultPathPolicy;
  readonly #clock: () => Date;
  readonly #createId: (prefix: string) => string;
  readonly #beforeManagedRead?: (absolutePath: string) => void;
  readonly #beforeQuarantineCopy?: (absolutePath: string) => void;
  readonly #afterQuarantineCopy?: (intentId: string) => void;
  readonly #brainAtlasPlugins: ObsidianPluginManager;

  constructor(
    database: SqliteDatabase,
    memory: MemoryRepository,
    pathPolicy: VaultPathPolicy,
    options: BridgeOptions = {},
  ) {
    this.#database = database;
    this.#memory = memory;
    this.#paths = pathPolicy;
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? ((prefix) => `${prefix}_${randomUUID()}`);
    this.#beforeManagedRead = options.beforeManagedRead;
    this.#beforeQuarantineCopy = options.beforeQuarantineCopy;
    this.#afterQuarantineCopy = options.afterQuarantineCopy;
    this.#brainAtlasPlugins = options.brainAtlasPluginManager
      ?? new ObsidianPluginManager({ database, pathPolicy });
  }

  #now(): string {
    return this.#clock().toISOString();
  }

  /**
   * Read policy at the point of use so disabling vault synchronization takes
   * effect for API, CLI, and watcher work without a process restart.
   */
  memoryControlPolicy(): MemoryControlPolicy {
    return getMemoryControlPolicy(this.#database);
  }

  vaultSyncEnabled(): boolean {
    const policy = this.memoryControlPolicy();
    return policy.enabled && policy.obsidianSyncScope !== "disabled";
  }

  projectionLifecycleStatuses(): readonly MemoryNode["lifecycleStatus"][] {
    const policy = this.memoryControlPolicy();
    if (!policy.enabled || policy.obsidianSyncScope === "disabled") return [];
    return policy.obsidianSyncScope === "confirmed"
      ? ["confirmed"]
      : ["confirmed", "verified"];
  }

  #candidateReviewNodeTypes(connection: VaultConnection | undefined): readonly string[] {
    if (!connection) return [];
    return this.#connectionScopeValues(
      connection,
      "candidateReviewNodeTypes",
      TERMINAL_ATTACK_KNOWLEDGE_REVIEW_NODE_TYPES,
    ) ?? [];
  }

  #candidateReviewProjectionAllowed(
    connection: VaultConnection | undefined,
    node: MemoryNode,
  ): boolean {
    return Boolean(
      connection
      && this.#candidateReviewNodeTypes(connection).includes(node.nodeType)
      && isTerminalAttackKnowledgeReviewCandidate(node),
    );
  }

  #projectionLifecycleAllowed(
    connection: VaultConnection | undefined,
    node: MemoryNode,
  ): boolean {
    return this.projectionLifecycleStatuses().includes(node.lifecycleStatus)
      || this.#candidateReviewProjectionAllowed(connection, node);
  }

  #edgeProjectionAllowed(
    connection: VaultConnection | undefined,
    edge: MemoryEdge,
    source: MemoryNode,
    target: MemoryNode,
  ): boolean {
    if (this.projectionLifecycleStatuses().includes(edge.lifecycleStatus)) return true;
    return Boolean(
      connection
      && edge.lifecycleStatus === "candidate"
      && edge.scope.kind === "global"
      && edge.authorType === "agent"
      && edge.authorId === "run-evaluator"
      && (
        this.#candidateReviewProjectionAllowed(connection, source)
        || this.#candidateReviewProjectionAllowed(connection, target)
      )
      && this.#projectionLifecycleAllowed(connection, source)
      && this.#projectionLifecycleAllowed(connection, target),
    );
  }

  assertVaultSyncAllowed(): MemoryControlPolicy {
    const policy = this.memoryControlPolicy();
    if (!policy.enabled || policy.obsidianSyncScope === "disabled") {
      throw new Error("Obsidian synchronization is not permitted by the memory control policy");
    }
    return policy;
  }

  #nodeProjectionAllowed(connection: VaultConnection | undefined, node: MemoryNode): boolean {
    if (
      REUSABLE_VAULT_NODE_TYPE_SET.has(node.nodeType)
      && !RUNTIME_CAPABILITY_VAULT_NODE_TYPE_SET.has(node.nodeType)
    ) return true;
    if (RUNTIME_CAPABILITY_VAULT_NODE_TYPE_SET.has(node.nodeType)) {
      return isCurrentRuntimeCapabilityProjectionNode(node);
    }
    const operatorId = connection
      ? operatorProfileVaultOperatorId(connection.syncScope)
      : undefined;
    return Boolean(
      connection
      && vaultScopeIncludesOperatorProfile(connection.syncScope)
      && operatorId
      && isOperatorProfileVaultNodeAllowed(this.#database, node, operatorId),
    );
  }

  #assertProjectionAllowed(node: MemoryNode, connection?: VaultConnection): void {
    this.assertVaultSyncAllowed();
    if (!this.#nodeProjectionAllowed(connection, node)) {
      throw new Error(
        `Memory node type ${node.nodeType} is private operational provenance and cannot be projected as reusable Vault knowledge`,
      );
    }
    if (!this.#projectionLifecycleAllowed(connection, node)) {
      throw new Error(
        `Memory lifecycle ${node.lifecycleStatus} is not permitted by the current Obsidian projection scope`,
      );
    }
  }

  verifyVaultPath(vaultPath: string): {
    readonly vaultRoot: string;
    readonly checkedAt: string;
    readonly checks: { readonly write: true; readonly read: true; readonly rename: true; readonly delete: true };
  } {
    this.assertVaultSyncAllowed();
    const result = this.#paths.verifyRoundTrip(vaultPath);
    return { ...result, checkedAt: this.#now() };
  }

  /** Recovery-only health proof. Unlike candidate verification, this refuses
   * to recreate a configured Vault that disappeared or went offline. */
  verifyExistingVaultPath(vaultPath: string): {
    readonly vaultRoot: string;
    readonly checkedAt: string;
    readonly checks: { readonly write: true; readonly read: true; readonly rename: true; readonly delete: true };
  } {
    this.assertVaultSyncAllowed();
    const result = this.#paths.verifyExistingRoundTrip(vaultPath);
    return { ...result, checkedAt: this.#now() };
  }

  /** Create only the reviewed Operator Profile category on an existing Vault. */
  ensureOperatorProfileFolder(connectionId: string): { readonly folder: typeof OPERATOR_PROFILE_VAULT_FOLDER; readonly created: boolean } {
    const connection = this.requireConnection(connectionId);
    this.verifyExistingVaultPath(connection.vaultPath);
    const path = this.#paths.resolveRelative(connection.vaultPath, OPERATOR_PROFILE_VAULT_FOLDER, true);
    const created = !existsSync(path);
    mkdirSync(path, { recursive: true, mode: 0o700 });
    return { folder: OPERATOR_PROFILE_VAULT_FOLDER, created };
  }

  connect(input: {
    readonly id?: string;
    readonly vaultPath: string;
    readonly displayName: string;
    readonly syncScope?: Record<string, unknown>;
    readonly permissionGranted: boolean;
  }): VaultConnection {
    this.assertVaultSyncAllowed();
    if (!input.permissionGranted) throw new Error("Explicit filesystem permission is required");
    if (!input.displayName.trim()) throw new TypeError("Vault display name is required");
    // A connection is never reported healthy from mkdir alone. Re-run the
    // complete write/read/rename/delete proof at the point of connection so a
    // stale UI preflight cannot bypass the filesystem boundary.
    const vaultPath = this.verifyVaultPath(input.vaultPath).vaultRoot;
    this.#createVaultFolders(vaultPath);
    const id = input.id ?? this.#createId("vault");
    const now = this.#now();
    this.#database.prepare(`
      INSERT INTO vault_connections (
        id, vault_path, display_name, status, sync_scope_json,
        permission_granted_at, created_at, updated_at
      ) VALUES (?, ?, ?, 'connected', ?, ?, ?, ?)
    `).run(id, vaultPath, input.displayName.trim(), JSON.stringify(input.syncScope ?? {}), now, now, now);
    return this.requireConnection(id);
  }

  #createVaultFolders(vaultRoot: string): void {
    for (const folder of [
      ...OBSIDIAN_V2_4_VAULT_FOLDERS,
      ".ti-scale/attachments",
      ".ti-scale/quarantine",
      ".ti-scale/forget-staging",
    ]) {
      this.#paths.resolveRelative(vaultRoot, folder, true);
      mkdirSync(this.#paths.resolveRelative(vaultRoot, folder), { recursive: true, mode: 0o700 });
    }
  }

  requireConnection(id: string): VaultConnection {
    const row = this.#database.prepare("SELECT * FROM vault_connections WHERE id = ?").get(id) as ConnectionRow | undefined;
    if (!row) throw new Error(`Vault connection not found: ${id}`);
    const connection = connectionFromRow(row);
    if (connection.status === "disconnected") {
      throw new Error(`Vault connection is disconnected: ${id}`);
    }
    this.#paths.resolveExistingVault(connection.vaultPath);
    return connection;
  }

  requireExistingConnection(id: string): VaultConnection {
    const row = this.#database.prepare("SELECT * FROM vault_connections WHERE id = ?").get(id) as ConnectionRow | undefined;
    if (!row) throw new Error(`Vault connection not found: ${id}`);
    const connection = connectionFromRow(row);
    this.#paths.resolveExistingVault(connection.vaultPath);
    return connection;
  }

  inspectManagedNote(connectionId: string, relativePath: string): {
    readonly note: VaultNote;
    readonly contentHash: string;
    readonly sourceHash: string;
  } {
    this.assertVaultSyncAllowed();
    const connection = this.requireConnection(connectionId);
    const path = this.#paths.resolveRelative(connection.vaultPath, relativePath);
    const snapshot = this.#readManagedNoteSnapshot(path);
    try {
      this.#assertVaultSourceSafe(snapshot.source);
      const note = parseObsidianNote(snapshot.source);
      this.#assertVaultNoteSafe(note);
      this.#assertConnectionProjectionAllowed(connection, note);
      if (this.#memory.getNode(note.id)) this.#assertCanonicalPrivateProvenance(note.id, note);
      return { note, contentHash: hashText(snapshot.source), sourceHash: snapshot.exactHash };
    } catch (error) {
      throw new VaultManagedNoteInspectionError(
        error instanceof Error ? error.message : "Managed Vault note failed validation",
        snapshot.exactHash,
        { cause: error },
      );
    }
  }

  /**
   * Move an invalid operator note into quarantine without retaining a second
   * restorable byte copy. A durable content-free intent written before the
   * rename lets the next run reconcile a crash after fsync.
   */
  quarantineManagedNote(
    connectionId: string,
    relativePath: string,
    reason: string,
    expectedContentHash: string,
  ): string {
    this.assertVaultSyncAllowed();
    const connection = this.requireConnection(connectionId);
    const path = this.#paths.resolveRelative(connection.vaultPath, relativePath);
    const snapshot = this.#readManagedNoteSnapshot(path);
    if (snapshot.exactHash !== expectedContentHash) throw new VaultDestinationChangedError();

    const sourcePathHash = hashText(relativePath);
    const prior = this.#matchingQuarantineIntent(connection.id, sourcePathHash, expectedContentHash);
    if (prior?.status === "committed") {
      const quarantinePath = this.#paths.resolveRelative(connection.vaultPath, prior.quarantineRelative);
      if (existsSync(path) && existsSync(quarantinePath)) {
        const current = this.#readManagedNoteSnapshot(path, false);
        const quarantined = this.#readManagedNoteSnapshot(quarantinePath, false);
        if (current.exactHash !== expectedContentHash || quarantined.exactHash !== expectedContentHash) {
          throw new VaultDestinationChangedError();
        }
        unlinkSync(path);
        this.#fsyncDirectory(dirname(path));
      }
      return prior.quarantineRelative;
    }
    const intent = prior ?? this.#createQuarantineIntent(
      connection,
      relativePath,
      sourcePathHash,
      expectedContentHash,
      reason,
    );

    try {
      this.#beforeQuarantineCopy?.(path);
      const publishSnapshot = this.#readManagedNoteSnapshot(path, false);
      if (publishSnapshot.exactHash !== expectedContentHash) throw new VaultDestinationChangedError();
      const quarantinePath = this.#paths.resolveRelative(connection.vaultPath, intent.quarantineRelative, true);
      if (!existsSync(quarantinePath)) {
        renameSync(path, quarantinePath);
        this.#fsyncDirectory(dirname(path));
        this.#fsyncDirectory(dirname(quarantinePath));
      } else if (existsSync(path)) {
        const existing = this.#readManagedNoteSnapshot(quarantinePath, false);
        if (existing.exactHash !== expectedContentHash) {
          throw new Error("Existing quarantine destination failed content verification");
        }
        unlinkSync(path);
        this.#fsyncDirectory(dirname(path));
      }
      const quarantined = this.#readManagedNoteSnapshot(quarantinePath, false);
      if (quarantined.exactHash !== expectedContentHash) {
        throw new Error("Quarantine move failed content verification");
      }
      this.#afterQuarantineCopy?.(intent.id);
      this.#commitQuarantineIntent(connection, intent);
      return intent.quarantineRelative;
    } catch (error) {
      this.#markQuarantineIntent(intent, "recovery_required");
      throw error;
    }
  }

  /** Finish verified quarantine moves left between fsync and SQLite commit. */
  recoverQuarantineIntents(connectionId: string): VaultQuarantineRecovery {
    const connection = this.requireConnection(connectionId);
    let recovered = 0;
    let unresolved = 0;
    for (const intent of this.#quarantineIntents(connectionId).filter((item) => item.status !== "committed")) {
      try {
        const quarantinePath = this.#paths.resolveRelative(connection.vaultPath, intent.quarantineRelative);
        if (!existsSync(quarantinePath)) {
          this.#markQuarantineIntent(intent, "recovery_required");
          unresolved += 1;
          continue;
        }
        const quarantined = this.#readManagedNoteSnapshot(quarantinePath, false);
        if (quarantined.exactHash !== intent.sourceContentHash) {
          this.#markQuarantineIntent(intent, "recovery_required");
          unresolved += 1;
          continue;
        }
        this.#commitQuarantineIntent(connection, intent);
        recovered += 1;
      } catch {
        this.#markQuarantineIntent(intent, "recovery_required");
        unresolved += 1;
      }
    }
    return { recovered, unresolved };
  }

  #readManagedNoteSnapshot(path: string, invokeHook = true): ManagedNoteSnapshot {
    if (!existsSync(path)) throw new Error("Vault note does not exist");
    const before = lstatSync(path);
    if (before.isSymbolicLink() || !before.isFile()) {
      throw new Error("Symbolic links are not permitted in managed vault paths");
    }
    if (before.size > MAX_RECOVERY_NOTE_BYTES) throw new Error("Managed vault note exceeds the recovery size limit");
    if (invokeHook) this.#beforeManagedRead?.(path);
    const noFollow = (fsConstants as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0;
    const descriptor = openSync(path, fsConstants.O_RDONLY | noFollow);
    try {
      const opened = fstatSync(descriptor);
      if (!opened.isFile() || !sameFileIdentity(before, opened)) {
        throw new VaultDestinationChangedError();
      }
      const bytes = readFileSync(descriptor);
      const afterDescriptor = fstatSync(descriptor);
      const afterPath = lstatSync(path);
      if (
        bytes.byteLength > MAX_RECOVERY_NOTE_BYTES
        || !sameFileIdentity(opened, afterDescriptor)
        || !sameFileIdentity(afterDescriptor, afterPath)
        || opened.size !== afterDescriptor.size
        || opened.mtimeMs !== afterDescriptor.mtimeMs
        || afterDescriptor.size !== bytes.byteLength
      ) {
        throw new VaultDestinationChangedError();
      }
      return { bytes, source: bytes.toString("utf8"), exactHash: hashBytes(bytes) };
    } finally {
      closeSync(descriptor);
    }
  }

  #quarantineIntentKey(id: string): string {
    return `brain.vault.quarantine_intent.${id}`;
  }

  #quarantineIntents(connectionId: string): VaultQuarantineIntent[] {
    const rows = this.#database.prepare(`
      SELECT value_json FROM settings
      WHERE key LIKE 'brain.vault.quarantine_intent.%'
      ORDER BY updated_at, key
    `).all() as Array<{ value_json: string }>;
    return rows.flatMap((row) => {
      const value = JSON.parse(row.value_json) as Partial<VaultQuarantineIntent>;
      if (
        typeof value.id !== "string"
        || typeof value.connectionId !== "string"
        || typeof value.sourcePathHash !== "string"
        || typeof value.sourceContentHash !== "string"
        || typeof value.quarantineRelative !== "string"
        || typeof value.markerRelative !== "string"
        || typeof value.syncStateId !== "string"
        || typeof value.reason !== "string"
        || !["planned", "recovery_required", "committed"].includes(String(value.status))
        || typeof value.createdAt !== "string"
        || typeof value.updatedAt !== "string"
      ) {
        throw new Error("Stored Vault quarantine recovery intent is malformed");
      }
      return value.connectionId === connectionId ? [value as VaultQuarantineIntent] : [];
    });
  }

  #matchingQuarantineIntent(
    connectionId: string,
    sourcePathHash: string,
    sourceContentHash: string,
  ): VaultQuarantineIntent | undefined {
    return this.#quarantineIntents(connectionId)
      .filter((intent) => (
        intent.sourcePathHash === sourcePathHash
        && intent.sourceContentHash === sourceContentHash
      ))
      .at(-1);
  }

  #createQuarantineIntent(
    connection: VaultConnection,
    relativePath: string,
    sourcePathHash: string,
    sourceContentHash: string,
    reason: string,
  ): VaultQuarantineIntent {
    const id = this.#createId("vquarantine");
    const now = this.#now();
    const quarantineRelative = `.ti-scale/quarantine/note-${id}.md`;
    const markerRelative = `.ti-scale/quarantine/note-${id}.receipt.json`;
    const existing = this.#database.prepare(`
      SELECT id FROM vault_sync_state WHERE connection_id = ? AND relative_path = ?
    `).get(connection.id, relativePath) as { id: string } | undefined;
    const syncStateId = existing?.id ?? this.#createId("vsync");
    const intent: VaultQuarantineIntent = {
      id,
      connectionId: connection.id,
      sourcePathHash,
      sourceContentHash,
      quarantineRelative,
      markerRelative,
      syncStateId,
      reason: reason.slice(0, 1_000),
      status: "planned",
      createdAt: now,
      updatedAt: now,
    };
    inImmediateTransaction(this.#database, () => {
      if (!existing) {
        // A new malformed filename can itself contain confidential text. Keep
        // only the generated content-free quarantine path in new metadata.
        this.#database.prepare(`
          INSERT INTO vault_sync_state (
            id, connection_id, relative_path, vault_content_hash,
            status, last_scanned_at, error_message
          ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
        `).run(
          syncStateId,
          connection.id,
          quarantineRelative,
          sourceContentHash,
          now,
          "Quarantine move is pending durable verification",
        );
      }
      this.#database.prepare(`
        INSERT INTO settings (
          key, value_json, sensitivity, version, updated_by, updated_at
        ) VALUES (?, ?, 'private', 1, 'vault-recovery', ?)
      `).run(this.#quarantineIntentKey(id), JSON.stringify(intent), now);
    });
    return intent;
  }

  #markQuarantineIntent(
    intent: VaultQuarantineIntent,
    status: VaultQuarantineIntent["status"],
  ): void {
    const updated: VaultQuarantineIntent = { ...intent, status, updatedAt: this.#now() };
    this.#database.prepare(`
      UPDATE settings SET value_json = ?, version = version + 1,
        updated_by = 'vault-recovery', updated_at = ? WHERE key = ?
    `).run(JSON.stringify(updated), updated.updatedAt, this.#quarantineIntentKey(intent.id));
  }

  #commitQuarantineIntent(connection: VaultConnection, intent: VaultQuarantineIntent): void {
    const markerPath = this.#paths.resolveRelative(connection.vaultPath, intent.markerRelative);
    const marker = JSON.stringify({
      schemaVersion: "2.4",
      intentId: intent.id,
      connectionId: intent.connectionId,
      sourcePathHash: intent.sourcePathHash,
      sourceContentHash: intent.sourceContentHash,
      quarantineRelative: intent.quarantineRelative,
    });
    if (existsSync(markerPath)) {
      const existing = readFileSync(markerPath, "utf8");
      if (existing !== marker) throw new Error("Quarantine recovery marker does not match its durable intent");
    } else {
      this.#paths.atomicWrite(connection.vaultPath, intent.markerRelative, marker, { exists: false });
    }
    const markerDescriptor = openSync(markerPath, fsConstants.O_RDONLY);
    try {
      fsyncSync(markerDescriptor);
    } finally {
      closeSync(markerDescriptor);
    }
    chmodSync(markerPath, 0o600);
    this.#fsyncDirectory(dirname(markerPath));

    const now = this.#now();
    const committed: VaultQuarantineIntent = { ...intent, status: "committed", updatedAt: now };
    inImmediateTransaction(this.#database, () => {
      const updatedState = this.#database.prepare(`
        UPDATE vault_sync_state SET node_id = NULL, status = 'quarantined',
          vault_content_hash = ?, error_message = ?, last_scanned_at = ?
        WHERE id = ? AND connection_id = ?
      `).run(
        intent.sourceContentHash,
        intent.reason,
        now,
        intent.syncStateId,
        connection.id,
      );
      if (updatedState.changes !== 1) throw new Error("Quarantine recovery state no longer exists");
      const updatedIntent = this.#database.prepare(`
        UPDATE settings SET value_json = ?, version = version + 1,
          updated_by = 'vault-recovery', updated_at = ? WHERE key = ?
      `).run(JSON.stringify(committed), now, this.#quarantineIntentKey(intent.id));
      if (updatedIntent.changes !== 1) throw new Error("Quarantine recovery intent no longer exists");
    });
  }

  #fsyncDirectory(path: string): void {
    const descriptor = openSync(path, fsConstants.O_RDONLY);
    try {
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
  }

  markConnectionHealth(connectionId: string, status: "connected" | "degraded" | "error"): void {
    const current = this.#database.prepare(`
      SELECT status FROM vault_connections WHERE id = ?
    `).get(connectionId) as { readonly status: VaultConnection["status"] } | undefined;
    if (!current) throw new Error(`Vault connection not found: ${connectionId}`);
    if (current.status === "disconnected") {
      throw new Error(`Vault connection is disconnected: ${connectionId}`);
    }
    const changed = this.#database.prepare(`
      UPDATE vault_connections SET status = ? WHERE id = ? AND status != 'disconnected'
    `).run(status, connectionId);
    if (changed.changes !== 1) {
      throw new Error("Vault connection health state changed concurrently");
    }
  }

  /**
   * Re-run and persist the exact existing-path filesystem lifecycle proof used
   * by Autonomous attack-memory composition. This does not change the
   * connection configuration version: `updated_at` is reserved for path,
   * permission, scope, and lifecycle mutations, while ordinary health and
   * synchronization activity use their dedicated fields.
   */
  refreshConnectionHealthProof(
    connectionId: string,
    actor = "system:vault-health-monitor",
  ): {
    readonly connectionId: string;
    readonly connectionUpdatedAt: string;
    readonly checkedAt: string;
    readonly pathFingerprint: string;
    readonly checks: {
      readonly write: true;
      readonly read: true;
      readonly rename: true;
      readonly delete: true;
    };
    readonly auditRecordId: string;
  } {
    this.assertVaultSyncAllowed();
    if (!actor.trim() || Buffer.byteLength(actor, "utf8") > 256) {
      throw new TypeError("Vault health actor is invalid");
    }
    const before = this.requireConnection(connectionId);
    if (before.status !== "connected") {
      throw new Error("Only a currently connected Vault can refresh its active health proof");
    }
    const health = this.verifyExistingVaultPath(before.vaultPath);
    if (Date.parse(health.checkedAt) < Date.parse(before.updatedAt)) {
      throw new Error("Vault health proof predates the current connection version");
    }
    const pathFingerprint = activeVaultPathFingerprint(health.vaultRoot);
    const auditRecordId = `audit-vault-health-${randomUUID()}`;

    inImmediateTransaction(this.#database, () => {
      const current = this.#database.prepare(`
        SELECT id, vault_path, status, updated_at
        FROM vault_connections WHERE id = ?
      `).get(connectionId) as {
        readonly id: string;
        readonly vault_path: string;
        readonly status: VaultConnection["status"];
        readonly updated_at: string;
      } | undefined;
      if (
        !current
        || current.status === "disconnected"
        || current.vault_path !== before.vaultPath
        || current.updated_at !== before.updatedAt
      ) {
        throw new Error("Vault connection changed while its health proof was being verified");
      }
      const previous = this.#database.prepare(
        "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
      ).get() as { readonly record_hash: string } | undefined;
      const details = {
        connectionId,
        connectionUpdatedAt: before.updatedAt,
        pathFingerprint,
        checks: health.checks,
      };
      const hashMaterial = {
        id: auditRecordId,
        actor: actor.trim(),
        action: "vault.health.verified",
        resourceType: "vault_connection",
        resourceId: connectionId,
        reason: "Automated existing Vault write/read/rename/delete health proof",
        details,
        previousHash: previous?.record_hash ?? null,
        occurredAt: health.checkedAt,
      };
      this.#database.prepare(`
        INSERT INTO audit_records (
          id, actor_type, actor_id, action, resource_type, resource_id, reason,
          details_json, previous_hash, record_hash, occurred_at
        ) VALUES (?, 'system', ?, 'vault.health.verified', 'vault_connection',
          ?, ?, ?, ?, ?, ?)
      `).run(
        auditRecordId,
        actor.trim(),
        connectionId,
        hashMaterial.reason,
        JSON.stringify(details),
        previous?.record_hash ?? null,
        createHash("sha256")
          .update(canonicalAuditValue(hashMaterial), "utf8")
          .digest("hex"),
        health.checkedAt,
      );
    });

    return Object.freeze({
      connectionId,
      connectionUpdatedAt: before.updatedAt,
      checkedAt: health.checkedAt,
      pathFingerprint,
      checks: health.checks,
      auditRecordId,
    });
  }

  deepLink(connectionId: string, relativePath?: string): string {
    const connection = this.requireConnection(connectionId);
    if (relativePath) this.#paths.resolveRelative(connection.vaultPath, relativePath);
    return obsidianDeepLink(connection, relativePath);
  }

  renderNode(
    nodeId: string,
    connection?: VaultConnection,
    allowedTargetIds?: ReadonlySet<string>,
  ): {
    node: MemoryNode;
    text: string;
    relativePath: string;
    attachments: readonly CanonicalVaultAttachment[];
  } {
    const node = this.#memory.requireNode(nodeId);
    const sources = this.#database.prepare(`
      SELECT id AS privateProvenanceId, source_id AS sourceId
      FROM memory_sources WHERE node_id = ? ORDER BY acquired_at, id
    `).all(nodeId) as Array<{ privateProvenanceId: string; sourceId: string }>;
    const now = this.#now();
    const projectedEdgeLifecycleSql = this.#candidateReviewNodeTypes(connection).length > 0
      ? "'confirmed', 'verified', 'candidate'"
      : "'confirmed', 'verified'";
    const rows = this.#database.prepare(`
      SELECT edge.target_node_id, target_state.relative_path AS target_relative_path
      FROM memory_edges_safe edge
      JOIN memory_nodes target ON target.id = edge.target_node_id
      LEFT JOIN vault_sync_state target_state
        ON target_state.connection_id = ? AND target_state.node_id = edge.target_node_id
      WHERE edge.source_node_id = ?
        AND edge.lifecycle_status IN (${projectedEdgeLifecycleSql})
        AND (edge.expires_at IS NULL OR edge.expires_at > ?)
        AND target.lifecycle_status IN (${projectedEdgeLifecycleSql})
        AND (target.expires_at IS NULL OR target.expires_at > ?)
      ORDER BY edge.created_at
    `).all(connection?.id ?? "", nodeId, now, now) as Array<{
      target_node_id: string;
      target_relative_path: string | null;
    }>;
    const incomingRows = node.nodeType === "artifact"
      ? this.#database.prepare(`
        SELECT edge.source_node_id, source_state.relative_path AS source_relative_path
        FROM memory_edges_safe edge
        JOIN memory_nodes source ON source.id = edge.source_node_id
        LEFT JOIN vault_sync_state source_state
          ON source_state.connection_id = ? AND source_state.node_id = edge.source_node_id
        WHERE edge.target_node_id = ?
          AND edge.edge_type = 'produced'
          AND edge.lifecycle_status IN ('confirmed', 'verified')
          AND (edge.expires_at IS NULL OR edge.expires_at > ?)
          AND source.lifecycle_status IN ('confirmed', 'verified')
          AND (source.expires_at IS NULL OR source.expires_at > ?)
        ORDER BY edge.created_at
        LIMIT ${MAX_ARTIFACT_BACKLINKS}
      `).all(connection?.id ?? "", nodeId, now, now) as Array<{
        source_node_id: string;
        source_relative_path: string | null;
      }>
      : [];
    const permittedTargets = new Map(rows.map((row) => [row.target_node_id, row.target_relative_path]));
    const permittedSources = new Map(incomingRows.map((row) => [row.source_node_id, row.source_relative_path]));
    const permittedLifecycleStatuses = new Set(this.projectionLifecycleStatuses());
    const relatedEdges = rows.length + incomingRows.length === 0 ? [] : this.#memory.listEdges(nodeId);
    const outgoing = rows.length === 0
      ? []
      : relatedEdges
        .filter((edge) => (
          edge.sourceNodeId === nodeId
          && permittedTargets.has(edge.targetNodeId)
        ))
        .flatMap((edge) => {
          const target = this.#memory.getNode(edge.targetNodeId);
          if (!target || (allowedTargetIds && !allowedTargetIds.has(target.id))) return [];
          // A canonical edge must never project a wikilink to a note that the
          // live memory-control lifecycle policy excludes. Without this check,
          // a confirmed-only connection can emit a link to a verified note
          // that is intentionally absent from the same vault.
          if (!this.#projectionLifecycleAllowed(connection, target)) return [];
          if (!this.#edgeProjectionAllowed(connection, edge, node, target)) return [];
          if (!this.#nodeProjectionAllowed(connection, target)) return [];
          if (connection && !this.#connectionProjectionMatches(connection, target)) return [];
          // Artifact leaves carry a safe native backlink to their producing
          // node. Omitting the mirrored high-fanout line here keeps run hubs
          // below the reusable-note size boundary without losing graph links.
          if (edge.edgeType === "produced" && target.nodeType === "artifact") return [];
          const relativePath = permittedTargets.get(target.id);
          return [{
            edge,
            target,
            ...(relativePath ? { relativePath } : {}),
          }];
        });
    const backlinks = incomingRows.length === 0
      ? []
      : relatedEdges
        .filter((edge) => (
          edge.targetNodeId === nodeId
          && edge.edgeType === "produced"
          && permittedSources.has(edge.sourceNodeId)
          && permittedLifecycleStatuses.has(edge.lifecycleStatus)
        ))
        .flatMap((edge) => {
          const source = this.#memory.getNode(edge.sourceNodeId);
          if (!source || (allowedTargetIds && !allowedTargetIds.has(source.id))) return [];
          if (!permittedLifecycleStatuses.has(source.lifecycleStatus)) return [];
          if (!this.#nodeProjectionAllowed(connection, source)) return [];
          if (connection && !this.#connectionProjectionMatches(connection, source)) return [];
          const relativePath = permittedSources.get(source.id);
          return [{
            edge,
            source,
            ...(relativePath ? { relativePath } : {}),
          }];
        });
    // `rows` intentionally causes SQLite to use the directed adjacency index;
    // the repository mapping above supplies validated domain records.
    void rows;
    const attachments = this.#attachmentsForNode(node);
    const outcomeTags = new ReusableKnowledgeOutcomeService(this.#database)
      .summary(node.id).outcomeTags;
    const reportedOutcome = new HistoricalReportedOutcomeService(this.#database)
      .summary(node.id);
    const text = renderObsidianNote(
      node,
      sources.map((source) => ({
        sourceId: source.sourceId,
        privateProvenanceId: source.privateProvenanceId,
      })),
      outgoing,
      attachments,
      backlinks,
      outcomeTags,
      reportedOutcome,
    );
    assertReusableMemoryText([{
      field: "vaultProjection.note",
      value: text,
      maximumBytes: REUSABLE_MEMORY_LIMITS.vaultNote,
    }]);
    return {
      node,
      text,
      relativePath: vaultRelativePath(node),
      attachments,
    };
  }

  exportNode(
    connectionId: string,
    nodeId: string,
    allowedTargetIds?: ReadonlySet<string>,
  ): VaultSyncResult {
    return this.#exportNodeSync(connectionId, nodeId, 0, allowedTargetIds);
  }

  #exportNodeSync(
    connectionId: string,
    nodeId: string,
    raceRetry: number,
    allowedTargetIds?: ReadonlySet<string>,
    reprojectionTrail: ReadonlySet<string> = new Set(),
  ): VaultSyncResult {
    const connection = this.requireConnection(connectionId);
    const rendered = this.renderNode(nodeId, connection, allowedTargetIds);
    this.#assertProjectionAllowed(rendered.node, connection);
    this.#assertConnectionProjectionAllowed(connection, rendered.node);
    const state = this.#stateForNode(connectionId, nodeId);
    const pathReconciliation = state
      ? this.#reconcileHiddenProjectionPath(connection, state, rendered.node, rendered.relativePath)
      : { relativePath: rendered.relativePath, renamed: false };
    const relativePath = pathReconciliation.relativePath;
    const filePath = this.#paths.resolveRelative(connection.vaultPath, relativePath, true);
    const databaseHash = hashText(rendered.text);
    const vaultBytes = existsSync(filePath) ? readFileSync(filePath) : undefined;
    const vaultText = vaultBytes?.toString("utf8");
    if (vaultText !== undefined) {
      const quarantined = this.#quarantineUnsafeVaultSource(connection, rendered.node, relativePath, vaultText);
      if (quarantined) return quarantined;
    }
    const vaultHash = vaultText === undefined ? undefined : hashText(vaultText);

    if (!state && vaultText !== undefined && vaultHash !== databaseHash) {
      return this.#createConflict(connection, undefined, rendered.node, relativePath, rendered.text, vaultText);
    }
    if (state) {
      const databaseChanged = state.database_content_hash !== databaseHash;
      const vaultChanged = vaultHash !== undefined && state.vault_content_hash !== vaultHash;
      if (databaseChanged && vaultChanged && vaultHash !== databaseHash && vaultText !== undefined) {
        return this.#createConflict(connection, state, rendered.node, relativePath, rendered.text, vaultText);
      }
      if (!databaseChanged && vaultChanged && vaultText !== undefined) {
        this.#updateState(state.id, "vault_ahead", rendered.node.version, databaseHash, vaultHash, undefined, false);
        return {
          connectionId,
          nodeId,
          relativePath,
          status: "vault_ahead",
          message: "The Obsidian note changed and is ready to import",
        };
      }
    }

    this.#projectAttachments(connection, rendered.attachments);
    try {
      this.#paths.atomicWrite(
        connection.vaultPath,
        relativePath,
        rendered.text,
        vaultBytes
          ? {
              exists: true,
              sha256: createHash("sha256").update(vaultBytes).digest("hex"),
              beforeRename: () => this.#assertBulkRenameStillAllowed(connection, rendered.node),
            }
          : {
              exists: false,
              beforeRename: () => this.#assertBulkRenameStillAllowed(connection, rendered.node),
            },
      );
    } catch (error) {
      if (
        (error instanceof VaultDestinationChangedError || error instanceof VaultCanonicalChangedError)
        && raceRetry < 1
      ) {
        return this.#exportNodeSync(
          connectionId,
          nodeId,
          raceRetry + 1,
          allowedTargetIds,
          reprojectionTrail,
        );
      }
      throw error;
    }
    this.#upsertSyncedState(connectionId, rendered.node, relativePath, databaseHash);
    this.#touchConnection(connectionId);
    if (pathReconciliation.renamed) {
      const nextTrail = new Set(reprojectionTrail);
      nextTrail.add(rendered.node.id);
      this.#reprojectInboundLinkSources(
        connection,
        rendered.node.id,
        allowedTargetIds,
        nextTrail,
      );
    }
    return {
      connectionId,
      nodeId,
      relativePath,
      status: "synced",
      message: "Memory note exported atomically",
    };
  }

  /**
   * Earlier slug generation allowed `.net-*` note names. Obsidian and common
   * file browsers hide dot-prefixed files. Reconcile only that legacy case;
   * ordinary title changes continue to preserve their established path.
   *
   * A hard-link publish keeps at least one complete copy throughout the
   * filesystem/SQLite handoff. A changed operator note or occupied canonical
   * path fails closed instead of being overwritten.
   */
  #reconcileHiddenProjectionPath(
    connection: VaultConnection,
    state: SyncStateRow,
    node: MemoryNode,
    canonicalRelativePath: string,
  ): { readonly relativePath: string; readonly renamed: boolean } {
    if (state.relative_path === canonicalRelativePath) {
      return { relativePath: canonicalRelativePath, renamed: false };
    }
    const legacyName = basename(state.relative_path);
    if (!legacyName.startsWith(".") || basename(canonicalRelativePath).startsWith(".")) {
      return { relativePath: state.relative_path, renamed: false };
    }
    if (state.node_id !== node.id || !state.vault_content_hash) {
      throw new Error("Hidden Vault projection cannot be renamed without an exact tracked content hash");
    }
    const source = this.#paths.resolveRelative(connection.vaultPath, state.relative_path);
    const destination = this.#paths.resolveRelative(
      connection.vaultPath,
      canonicalRelativePath,
      true,
    );
    const expectedHash = state.vault_content_hash;
    let publishedDestination = false;

    if (existsSync(source)) {
      const metadata = lstatSync(source);
      if (metadata.isSymbolicLink() || !metadata.isFile()) {
        throw new Error("Hidden Vault projection is not a regular file");
      }
      if (hashText(readFileSync(source, "utf8")) !== expectedHash) {
        // Preserve the operator edit at its current path. The normal sync path
        // will classify it as Vault-ahead before any later rename is attempted.
        return { relativePath: state.relative_path, renamed: false };
      }
      if (existsSync(destination)) {
        const destinationMetadata = lstatSync(destination);
        if (
          destinationMetadata.isSymbolicLink()
          || !destinationMetadata.isFile()
          || hashText(readFileSync(destination, "utf8")) !== expectedHash
        ) {
          throw new VaultDestinationChangedError();
        }
      } else {
        linkSync(source, destination);
        publishedDestination = true;
      }
    } else if (existsSync(destination)) {
      const destinationMetadata = lstatSync(destination);
      if (
        destinationMetadata.isSymbolicLink()
        || !destinationMetadata.isFile()
        || hashText(readFileSync(destination, "utf8")) !== expectedHash
      ) {
        throw new VaultDestinationChangedError();
      }
    } else {
      // The tracked projection is already missing. Point recovery at the new,
      // visible canonical path; the ordinary atomic export below recreates it.
    }

    try {
      const result = this.#database.prepare(`
        UPDATE vault_sync_state SET relative_path = ?
        WHERE id = ? AND connection_id = ? AND node_id = ? AND relative_path = ?
      `).run(
        canonicalRelativePath,
        state.id,
        connection.id,
        node.id,
        state.relative_path,
      );
      if (result.changes !== 1) throw new VaultCanonicalChangedError();
    } catch (error) {
      if (publishedDestination && existsSync(destination)) unlinkSync(destination);
      throw error;
    }

    if (existsSync(source)) {
      const sourceMetadata = lstatSync(source);
      if (
        !sourceMetadata.isSymbolicLink()
        && sourceMetadata.isFile()
        && hashText(readFileSync(source, "utf8")) === expectedHash
      ) unlinkSync(source);
    }
    return { relativePath: canonicalRelativePath, renamed: true };
  }

  /**
   * A note path is part of every inbound native Obsidian wikilink. When a
   * tracked target moves, refresh already-projected source notes immediately
   * so the native graph never keeps pointing at the retired path. Operator
   * edits still win: the ordinary export path leaves those notes Vault-ahead
   * or in conflict instead of overwriting them.
   */
  #reprojectInboundLinkSources(
    connection: VaultConnection,
    targetNodeId: string,
    allowedTargetIds: ReadonlySet<string> | undefined,
    reprojectionTrail: ReadonlySet<string>,
  ): void {
    const now = this.#now();
    const projectedLifecycleSql = this.#candidateReviewNodeTypes(connection).length > 0
      ? "'confirmed', 'verified', 'candidate'"
      : "'confirmed', 'verified'";
    const rows = this.#database.prepare(`
      SELECT DISTINCT edge.source_node_id AS sourceNodeId
      FROM memory_edges_safe edge
      JOIN memory_nodes source ON source.id = edge.source_node_id
      JOIN vault_sync_state source_state
        ON source_state.connection_id = ? AND source_state.node_id = edge.source_node_id
      WHERE edge.target_node_id = ?
        AND edge.lifecycle_status IN (${projectedLifecycleSql})
        AND (edge.expires_at IS NULL OR edge.expires_at > ?)
        AND source.lifecycle_status IN (${projectedLifecycleSql})
        AND (source.expires_at IS NULL OR source.expires_at > ?)
      ORDER BY edge.source_node_id
    `).all(connection.id, targetNodeId, now, now) as Array<{ sourceNodeId: string }>;

    for (const { sourceNodeId } of rows) {
      if (
        reprojectionTrail.has(sourceNodeId)
        || (allowedTargetIds !== undefined && !allowedTargetIds.has(sourceNodeId))
      ) continue;
      const source = this.#memory.getNode(sourceNodeId);
      if (
        !source
        || !this.#projectionLifecycleAllowed(connection, source)
        || !this.#nodeProjectionAllowed(connection, source)
        || !this.#connectionProjectionMatches(connection, source)
      ) continue;

      try {
        this.#exportNodeSync(
          connection.id,
          sourceNodeId,
          0,
          allowedTargetIds,
          reprojectionTrail,
        );
      } catch (error) {
        // The target rename is already durable. Surface a repairable source
        // projection state without claiming that the target migration failed
        // or risking an overwrite of operator-authored Vault content.
        const state = this.#stateForNode(connection.id, sourceNodeId);
        if (state) {
          this.#database.prepare(`
            UPDATE vault_sync_state
            SET status = 'database_ahead', error_message = ?, last_scanned_at = ?
            WHERE id = ?
          `).run(
            `Inbound wikilink requires re-projection after a linked note moved: ${boundedExportError(error)}`,
            this.#now(),
            state.id,
          );
        }
      }
    }
  }

  /**
   * Select canonical notes permitted by both the live memory policy and this
   * connection's explicit scope. The result is stable and bounded for a single
   * resumable export invocation.
   */
  exportableNodeIds(connectionId: string): readonly string[] {
    const connection = this.requireConnection(connectionId);
    this.assertVaultSyncAllowed();
    this.#purgeRevokedConnectionProjections(connection);
    return this.#selectExportableNodeIds(connection);
  }

  /**
   * Read-only export selection for operator previews. Unlike
   * `exportableNodeIds`, this never removes revoked projections or portable
   * archives and never updates synchronization state.
   */
  previewExportableNodeIds(connectionId: string): readonly string[] {
    const connection = this.requireConnection(connectionId);
    this.assertVaultSyncAllowed();
    return this.#selectExportableNodeIds(connection);
  }

  /**
   * Remove only managed projections whose canonical node is no longer
   * permitted by the live Vault policy. Canonical memory is retained.
   */
  purgeRevokedNodeProjections(
    connectionId: string,
    nodeIds: readonly string[],
  ): readonly string[] {
    const connection = this.requireConnection(connectionId);
    this.assertVaultSyncAllowed();
    return this.#purgeRevokedConnectionProjections(
      connection,
      new Set(nodeIds),
    );
  }

  #selectExportableNodeIds(connection: VaultConnection): readonly string[] {
    const lifecycleStatuses = this.#connectionScopeValues(
      connection,
      "lifecycleStatuses",
      MEMORY_LIFECYCLE_STATES,
    ) ?? this.projectionLifecycleStatuses();
    const permittedLifecycle = lifecycleStatuses.filter((item) =>
      this.projectionLifecycleStatuses().includes(item as MemoryNode["lifecycleStatus"])
    );
    const candidateReviewNodeTypes = this.#candidateReviewNodeTypes(connection);
    if (permittedLifecycle.length === 0 && candidateReviewNodeTypes.length === 0) return [];

    const operatorId = operatorProfileVaultOperatorId(connection.syncScope);
    const operatorProfileNodeIds = operatorId
      && vaultScopeIncludesOperatorProfile(connection.syncScope)
      ? operatorProfileVaultEligibleNodeIds(this.#database, operatorId)
      : [];
    const projectionBoundaryParts = [
      `node_type IN (${REUSABLE_VAULT_NODE_TYPES.map(() => "?").join(",")})`,
      CURRENT_RUNTIME_CAPABILITY_PROJECTION_SQL,
      ...(operatorProfileNodeIds.length > 0
        ? [`id IN (${operatorProfileNodeIds.map(() => "?").join(",")})`]
        : []),
    ];
    const projectionBoundary = `(${projectionBoundaryParts.join(" OR ")})`;
    const lifecycleClause = candidateReviewNodeTypes.length > 0
      ? `(
          ${permittedLifecycle.length > 0
            ? `lifecycle_status IN (${permittedLifecycle.map(() => "?").join(",")}) OR`
            : ""}
          (
            lifecycle_status = 'candidate'
            AND confirmation_state = 'pending'
            AND node_type IN (${candidateReviewNodeTypes.map(() => "?").join(",")})
            AND author_type = 'agent'
            AND author_id = 'run-evaluator'
            AND json_extract(
              retention_policy_json,
              '$.terminalAttackKnowledgeReview.schemaVersion'
            ) = ?
            AND json_extract(
              retention_policy_json,
              '$.terminalAttackKnowledgeReview.status'
            ) = 'pending_operator_review'
          )
        )`
      : `lifecycle_status IN (${permittedLifecycle.map(() => "?").join(",")})`;
    const clauses = [lifecycleClause, projectionBoundary];
    const parameters: string[] = [
      ...permittedLifecycle,
      ...candidateReviewNodeTypes,
      ...(candidateReviewNodeTypes.length > 0
        ? [TERMINAL_ATTACK_KNOWLEDGE_REVIEW_SCHEMA]
        : []),
      ...REUSABLE_VAULT_NODE_TYPES,
      ...operatorProfileNodeIds,
    ];
    const addScopeClause = (key: string, column: string, allowed?: readonly string[]): void => {
      const values = this.#connectionScopeValues(connection, key, allowed);
      if (!values) return;
      if (values.length === 0) {
        clauses.push("0 = 1");
        return;
      }
      clauses.push(`${column} IN (${values.map(() => "?").join(",")})`);
      parameters.push(...values);
    };
    const scopedNodeTypes = this.#connectionScopeValues(connection, "nodeTypes", MEMORY_NODE_TYPES);
    if (scopedNodeTypes) {
      clauses.push(`(
        ${scopedNodeTypes.length > 0
          ? `node_type IN (${scopedNodeTypes.map(() => "?").join(",")}) OR`
          : ""}
        ${CURRENT_RUNTIME_CAPABILITY_PROJECTION_SQL}
      )`);
      parameters.push(...scopedNodeTypes);
    }
    addScopeClause("nodeIds", "id");
    addScopeClause("scopeKinds", "scope", MEMORY_SCOPE_KINDS);
    addScopeClause("sensitivities", "sensitivity", MEMORY_SENSITIVITIES);
    addScopeClause("engagementIds", "engagement_id");
    addScopeClause("missionIds", "mission_id");

    const rows = this.#database.prepare(`
      SELECT id FROM memory_nodes
      WHERE ${clauses.join(" AND ")}
      ORDER BY updated_at DESC, id
      LIMIT ${MAX_BULK_EXPORT_NOTES + 1}
    `).all(...parameters) as Array<{ id: string }>;
    if (rows.length > MAX_BULK_EXPORT_NOTES) {
      throw new Error(`A single Obsidian export is limited to ${MAX_BULK_EXPORT_NOTES} canonical notes`);
    }
    return rows.flatMap((row) => {
      const node = this.#memory.getNode(row.id);
      return node
        && this.#projectionLifecycleAllowed(connection, node)
        && this.#nodeProjectionAllowed(connection, node)
        && this.#connectionProjectionMatches(connection, node)
        ? [row.id]
        : [];
    });
  }

  #purgeRevokedConnectionProjections(
    connection: VaultConnection,
    requestedNodeIds?: ReadonlySet<string>,
  ): readonly string[] {
    const rows = this.#database.prepare(`
      SELECT id, node_id, relative_path, status,
        database_content_hash, vault_content_hash
      FROM vault_sync_state
      WHERE connection_id = ? AND node_id IS NOT NULL
    `).all(connection.id) as Array<{
      id: string;
      node_id: string;
      relative_path: string;
      status: string;
      database_content_hash: string | null;
      vault_content_hash: string | null;
    }>;
    const revoked = rows.filter((row) => {
      if (requestedNodeIds && !requestedNodeIds.has(row.node_id)) return false;
      const node = this.#memory.getNode(row.node_id, true);
      return !node
        || !this.#projectionLifecycleAllowed(connection, node)
        || !this.#nodeProjectionAllowed(connection, node)
        || !this.#connectionProjectionMatches(connection, node);
    });
    if (revoked.length === 0) return [];

    const currentState = this.#database.prepare(`
      SELECT id, node_id, relative_path, status,
        database_content_hash, vault_content_hash
      FROM vault_sync_state
      WHERE id = ? AND connection_id = ?
    `);
    const hasOpenConflict = this.#database.prepare(`
      SELECT 1 FROM vault_conflicts
      WHERE sync_state_id = ? AND status = 'open'
      LIMIT 1
    `);
    const deleteConflicts = this.#database.prepare(`
      DELETE FROM vault_conflicts WHERE sync_state_id IN (
        SELECT id FROM vault_sync_state WHERE connection_id = ? AND relative_path = ?
      )
    `);
    const deleteState = this.#database.prepare(`
      DELETE FROM vault_sync_state
      WHERE id = ? AND connection_id = ? AND node_id = ? AND relative_path = ?
        AND status = 'synced'
        AND database_content_hash = ?
        AND vault_content_hash = ?
    `);
    for (const row of revoked) {
      const path = this.#paths.resolveRelative(connection.vaultPath, row.relative_path);
      const fresh = currentState.get(row.id, connection.id) as typeof row | undefined;
      if (
        !fresh
        || fresh.node_id !== row.node_id
        || fresh.relative_path !== row.relative_path
        || fresh.status !== "synced"
        || fresh.status !== row.status
        || !fresh.vault_content_hash
        || !SHA256_HEX.test(fresh.vault_content_hash)
        || fresh.vault_content_hash !== row.vault_content_hash
        || fresh.database_content_hash !== row.database_content_hash
        || fresh.database_content_hash !== fresh.vault_content_hash
      ) {
        throw new VaultDestinationChangedError();
      }
      if (hasOpenConflict.get(row.id)) {
        throw new Error("Revoked vault projection has an unresolved operator conflict");
      }
      if (!existsSync(path)) throw new VaultDestinationChangedError();
      const metadata = lstatSync(path);
      if (metadata.isSymbolicLink() || !metadata.isFile() || (metadata.mode & 0o777) !== 0o600) {
        throw new Error("Revoked vault projection is not a safe managed file");
      }
      const snapshot = this.#readManagedNoteSnapshot(path);
      if (hashText(snapshot.source) !== fresh.vault_content_hash) {
        throw new VaultDestinationChangedError();
      }

      const guardRelativePath = `.ti-scale/revocation-guards/${randomUUID()}.md`;
      const guardPath = this.#paths.resolveRelative(
        connection.vaultPath,
        guardRelativePath,
        true,
      );
      renameSync(path, guardPath);
      this.#fsyncDirectory(dirname(path));
      this.#fsyncDirectory(dirname(guardPath));
      let stateCommitted = false;
      try {
        const guarded = this.#readManagedNoteSnapshot(guardPath, false);
        const admitted = currentState.get(row.id, connection.id) as typeof row | undefined;
        if (
          !admitted
          || admitted.node_id !== fresh.node_id
          || admitted.relative_path !== fresh.relative_path
          || admitted.status !== "synced"
          || admitted.database_content_hash !== fresh.database_content_hash
          || admitted.vault_content_hash !== fresh.vault_content_hash
          || hashText(guarded.source) !== fresh.vault_content_hash
        ) {
          throw new VaultDestinationChangedError();
        }
        inImmediateTransaction(this.#database, () => {
          deleteConflicts.run(connection.id, row.relative_path);
          const deleted = deleteState.run(
            row.id,
            connection.id,
            row.node_id,
            row.relative_path,
            fresh.database_content_hash,
            fresh.vault_content_hash,
          );
          if (deleted.changes !== 1) throw new VaultDestinationChangedError();
        });
        stateCommitted = true;
        // Keep the verified note privately captured until the synchronization
        // state deletion commits. A post-commit unlink failure therefore
        // cannot leave a public managed note with no canonical state.
        unlinkSync(guardPath);
        this.#fsyncDirectory(dirname(guardPath));
      } finally {
        if (!stateCommitted && existsSync(guardPath) && !existsSync(path)) {
          renameSync(guardPath, path);
          this.#fsyncDirectory(dirname(path));
          this.#fsyncDirectory(dirname(guardPath));
        }
      }
    }

    // Scope changes invalidate every portable snapshot for this connection.
    const exportDirectory = this.#paths.resolveRelative(connection.vaultPath, ".ti-scale/exports", true);
    if (existsSync(exportDirectory)) {
      for (const archiveName of readdirSync(exportDirectory)) {
        if (!/^ti-scale-brain-[A-Za-z0-9._-]+\.zip$/u.test(archiveName) || basename(archiveName) !== archiveName) continue;
        const archivePath = this.#paths.resolveRelative(
          connection.vaultPath,
          `.ti-scale/exports/${archiveName}`,
        );
        const metadata = lstatSync(archivePath);
        if (!metadata.isFile() && !metadata.isSymbolicLink()) {
          throw new Error("Revoked portable vault archive is not a removable file");
        }
        rmSync(archivePath, { force: true });
      }
    }
    return revoked.map(({ node_id }) => node_id).sort();
  }

  /**
   * Bounded, async, individually atomic bulk projection. SQLite sync rows are
   * committed after each successful note, so rerunning after abort or process
   * loss skips current versions and resumes without rewriting completed files.
   */
  async exportNodes(
    connectionId: string,
    nodeIds: readonly string[],
    options: VaultBulkExportOptions = {},
  ): Promise<VaultBulkExportResult> {
    const connection = this.requireConnection(connectionId);
    this.assertVaultSyncAllowed();
    const uniqueNodeIds = [...new Set(nodeIds)];
    if (uniqueNodeIds.length > MAX_BULK_EXPORT_NOTES) {
      throw new RangeError(`A single Obsidian export is limited to ${MAX_BULK_EXPORT_NOTES} canonical notes`);
    }
    const concurrency = options.concurrency ?? 8;
    if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > MAX_BULK_EXPORT_CONCURRENCY) {
      throw new RangeError(`Vault export concurrency must be between 1 and ${MAX_BULK_EXPORT_CONCURRENCY}`);
    }
    const progressInterval = options.progressInterval ?? 100;
    if (!Number.isSafeInteger(progressInterval) || progressInterval < 1 || progressInterval > 10_000) {
      throw new RangeError("Vault export progress interval must be between 1 and 10000");
    }

    const startedAt = this.#now();
    const startedClock = performance.now();
    const counts: Mutable<VaultBulkExportCounts> = {
      synced: 0,
      skipped: 0,
      databaseAhead: 0,
      vaultAhead: 0,
      conflicts: 0,
      quarantined: 0,
      failed: 0,
    };
    const issues: VaultBulkExportIssue[] = [];
    let issueSampleTruncated = false;
    let processed = 0;
    let nextIndex = 0;
    let progressQueue = Promise.resolve();
    let progressFailure: unknown;
    let policyRevoked = false;

    const progress = (): VaultBulkExportProgress => ({
      connectionId,
      total: uniqueNodeIds.length,
      processed,
      remaining: uniqueNodeIds.length - processed,
      counts: { ...counts },
      elapsedMs: performance.now() - startedClock,
    });
    const addIssue = (issue: VaultBulkExportIssue): void => {
      if (issues.length < MAX_BULK_EXPORT_ISSUES) issues.push(issue);
      else issueSampleTruncated = true;
    };
    const emitProgress = (): Promise<void> => {
      if (!options.onProgress) return Promise.resolve();
      const snapshot = progress();
      progressQueue = progressQueue.then(async () => {
        if (progressFailure) return;
        try {
          await options.onProgress?.(snapshot);
        } catch (error) {
          progressFailure = error;
        }
      });
      return progressQueue;
    };
    const worker = async (): Promise<void> => {
      while (!options.signal?.aborted && !progressFailure && !policyRevoked) {
        if (!this.vaultSyncEnabled()) {
          policyRevoked = true;
          return;
        }
        const index = nextIndex;
        nextIndex += 1;
        if (index >= uniqueNodeIds.length) return;
        const nodeId = uniqueNodeIds[index]!;
        try {
          const exported = await this.#exportNodeAsync(connection, nodeId);
          if (exported.skipped) counts.skipped += 1;
          else if (exported.result.status === "synced") counts.synced += 1;
          else if (exported.result.status === "database_ahead") {
            counts.databaseAhead += 1;
            addIssue(this.#bulkIssue(exported.result));
          } else if (exported.result.status === "vault_ahead") {
            counts.vaultAhead += 1;
            addIssue(this.#bulkIssue(exported.result));
          } else if (exported.result.status === "conflict") {
            counts.conflicts += 1;
            addIssue(this.#bulkIssue(exported.result));
          } else {
            counts.quarantined += 1;
            addIssue(this.#bulkIssue(exported.result));
          }
        } catch (error) {
          if (error instanceof VaultSyncPolicyRevokedError) {
            policyRevoked = true;
            return;
          }
          counts.failed += 1;
          addIssue({ nodeId, category: "failed", message: boundedExportError(error) });
        }
        processed += 1;
        if (processed % progressInterval === 0) {
          await emitProgress();
          await new Promise<void>((resolve) => setImmediate(resolve));
        }
      }
    };

    await Promise.all(Array.from(
      { length: Math.min(concurrency, Math.max(1, uniqueNodeIds.length)) },
      () => worker(),
    ));
    await progressQueue;
    if (policyRevoked) this.markConnectionHealth(connectionId, "degraded");
    else if (
      processed > 0
      && counts.failed === processed
      && counts.synced === 0
      && counts.skipped === 0
    ) this.markConnectionHealth(connectionId, "error");
    else if (
      counts.failed > 0
      || counts.databaseAhead > 0
      || counts.vaultAhead > 0
      || counts.conflicts > 0
      || counts.quarantined > 0
    ) this.markConnectionHealth(connectionId, "degraded");
    else if (processed > 0) this.#touchConnection(connectionId);
    const result: VaultBulkExportResult = {
      ...progress(),
      startedAt,
      completedAt: this.#now(),
      issues,
      issueSampleTruncated,
    };
    if (progressFailure) throw progressFailure;
    if (policyRevoked) throw new VaultBulkExportPolicyError(result);
    if (options.signal?.aborted) throw new VaultBulkExportAbortError(result);
    if (processed !== uniqueNodeIds.length) {
      throw new Error(`Obsidian vault export stopped after ${processed} of ${uniqueNodeIds.length} notes`);
    }
    await emitProgress();
    await progressQueue;
    return { ...result, ...progress(), completedAt: this.#now() };
  }

  #connectionScopeValues(
    connection: VaultConnection,
    key: string,
    allowed?: readonly string[],
  ): readonly string[] | undefined {
    const value = connection.syncScope[key];
    if (value === undefined) return undefined;
    if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item.trim())) {
      throw new Error(`Vault connection sync scope ${key} must be a string array`);
    }
    const values = [...new Set(value as string[])];
    if (key === "nodeIds") {
      if (values.length > MAX_SYNC_SCOPE_NODE_IDS) {
        throw new Error(`Vault connection sync scope nodeIds is limited to ${MAX_SYNC_SCOPE_NODE_IDS} exact node IDs`);
      }
      values.forEach((nodeId) => assertIdentifier(nodeId, "vault connection exact memory node ID"));
    }
    if (allowed && values.some((item) => !allowed.includes(item))) {
      throw new Error(`Vault connection sync scope ${key} contains an unsupported value`);
    }
    return values;
  }

  #connectionProjectionMismatch(
    connection: VaultConnection,
    node: Pick<MemoryNode, "id" | "lifecycleStatus" | "nodeType" | "scope" | "sensitivity">,
  ): string | undefined {
    const canonical = this.#memory.getNode(node.id, true);
    const exactRuntimeCapabilityNodeTypeBypass = Boolean(
      canonical
      && canonical.nodeType === node.nodeType
      && isCurrentRuntimeCapabilityProjectionNode(canonical),
    );
    const exactTerminalCandidateLifecycleBypass = Boolean(
      canonical
      && canonical.nodeType === node.nodeType
      && this.#candidateReviewProjectionAllowed(connection, canonical),
    );
    const checks: Array<[string, string | undefined, readonly string[] | undefined]> = [
      ["nodeIds", node.id, undefined],
      ["lifecycleStatuses", node.lifecycleStatus, MEMORY_LIFECYCLE_STATES],
      ["nodeTypes", node.nodeType, MEMORY_NODE_TYPES],
      ["scopeKinds", node.scope.kind, MEMORY_SCOPE_KINDS],
      ["sensitivities", node.sensitivity, MEMORY_SENSITIVITIES],
      ["engagementIds", node.scope.engagementId, undefined],
      ["missionIds", node.scope.missionId, undefined],
    ];
    for (const [key, actual, allowed] of checks) {
      const values = this.#connectionScopeValues(connection, key, allowed);
      // Live reusable-knowledge Vaults intentionally omit general agent/tool
      // node classes. Only the exact canonical, system-authored, current
      // runtime attestation may bypass that one dimension; lifecycle,
      // scope-kind, sensitivity, engagement, and mission filters still apply.
      if (key === "nodeTypes" && exactRuntimeCapabilityNodeTypeBypass) continue;
      // Candidate review is an explicit independent scope. It bypasses only
      // the generic confirmed/verified lifecycle list; every other connection
      // dimension and the exact evaluator marker still applies.
      if (key === "lifecycleStatuses" && exactTerminalCandidateLifecycleBypass) continue;
      if (values && (!actual || !values.includes(actual))) {
        return key;
      }
    }
    return undefined;
  }

  #connectionProjectionMatches(
    connection: VaultConnection,
    node: Pick<MemoryNode, "id" | "lifecycleStatus" | "nodeType" | "scope" | "sensitivity">,
  ): boolean {
    return this.#connectionProjectionMismatch(connection, node) === undefined;
  }

  #assertConnectionProjectionAllowed(
    connection: VaultConnection,
    node: Pick<MemoryNode, "id" | "lifecycleStatus" | "nodeType" | "scope" | "sensitivity">,
  ): void {
    const mismatch = this.#connectionProjectionMismatch(connection, node);
    if (mismatch) {
      throw new Error(`Memory node is outside the vault connection ${mismatch} scope`);
    }
  }

  /** Revalidate live memory policy and a connection's explicit projection scope. */
  assertConnectionNodeAllowed(connectionId: string, nodeId: string): MemoryNode {
    const connection = this.requireConnection(connectionId);
    const node = this.#memory.requireNode(nodeId);
    this.#assertProjectionAllowed(node, connection);
    this.#assertConnectionProjectionAllowed(connection, node);
    return node;
  }

  #bulkIssue(result: VaultSyncResult): VaultBulkExportIssue {
    const category = result.status === "database_ahead"
      ? "database_ahead"
      : result.status === "vault_ahead"
        ? "vault_ahead"
        : result.status === "conflict"
          ? "conflict"
          : "quarantined";
    return {
      nodeId: result.nodeId,
      category,
      message: result.message,
      relativePath: result.relativePath,
      ...(result.conflictId ? { conflictId: result.conflictId } : {}),
    };
  }

  async #exportNodeAsync(
    connection: VaultConnection,
    nodeId: string,
    raceRetry = 0,
  ): Promise<{ readonly result: VaultSyncResult; readonly skipped: boolean }> {
    if (!this.vaultSyncEnabled()) throw new VaultSyncPolicyRevokedError();
    const rendered = this.renderNode(nodeId, connection);
    this.#assertProjectionAllowed(rendered.node, connection);
    this.#assertConnectionProjectionAllowed(connection, rendered.node);
    const state = this.#stateForNode(connection.id, nodeId);
    const relativePath = state?.relative_path ?? rendered.relativePath;
    const filePath = this.#paths.resolveRelative(connection.vaultPath, relativePath, true);
    const databaseHash = hashText(rendered.text);
    const vaultBytes = existsSync(filePath) ? readFileSync(filePath) : undefined;
    const vaultText = vaultBytes?.toString("utf8");
    if (vaultText !== undefined) {
      const quarantined = this.#quarantineUnsafeVaultSource(
        connection,
        rendered.node,
        relativePath,
        vaultText,
      );
      if (quarantined) return { result: quarantined, skipped: false };
    }
    const vaultHash = vaultText === undefined ? undefined : hashText(vaultText);

    if (!state && vaultText !== undefined && vaultHash !== databaseHash) {
      return {
        result: this.#createConflict(
          connection,
          undefined,
          rendered.node,
          relativePath,
          rendered.text,
          vaultText,
        ),
        skipped: false,
      };
    }
    if (state) {
      const databaseChanged = state.database_content_hash !== databaseHash;
      const vaultChanged = vaultHash !== undefined && state.vault_content_hash !== vaultHash;
      if (databaseChanged && vaultChanged && vaultHash !== databaseHash && vaultText !== undefined) {
        return {
          result: this.#createConflict(
            connection,
            state,
            rendered.node,
            relativePath,
            rendered.text,
            vaultText,
          ),
          skipped: false,
        };
      }
      if (!databaseChanged && vaultChanged && vaultText !== undefined) {
        this.#updateState(
          state.id,
          "vault_ahead",
          rendered.node.version,
          databaseHash,
          vaultHash,
          undefined,
          false,
        );
        return {
          result: {
            connectionId: connection.id,
            nodeId,
            relativePath,
            status: "vault_ahead",
            message: "The Obsidian note changed and is ready to import",
          },
          skipped: false,
        };
      }
      if (
        state.status === "synced"
        && state.database_version === rendered.node.version
        && state.database_content_hash === databaseHash
        && state.vault_content_hash === databaseHash
        && vaultHash === databaseHash
      ) {
        return {
          result: {
            connectionId: connection.id,
            nodeId,
            relativePath,
            status: "synced",
            message: "Current canonical memory version is already synchronized",
          },
          skipped: true,
        };
      }
    }

    this.#projectAttachments(connection, rendered.attachments);
    try {
      const expectation = vaultBytes
        ? {
            exists: true as const,
            sha256: createHash("sha256").update(vaultBytes).digest("hex"),
              beforeRename: () => this.#assertBulkRenameStillAllowed(connection, rendered.node),
          }
        : {
            exists: false as const,
            beforeRename: () => this.#assertBulkRenameStillAllowed(connection, rendered.node),
          };
      await this.#paths.atomicWriteAsync(
        connection.vaultPath,
        relativePath,
        rendered.text,
        expectation,
      );
    } catch (error) {
      if (error instanceof VaultDestinationChangedError && raceRetry < 1) {
        return this.#exportNodeAsync(connection, nodeId, raceRetry + 1);
      }
      if (error instanceof VaultCanonicalChangedError) {
        return this.#databaseAheadAfterRace(connection, nodeId, raceRetry);
      }
      throw error;
    }
    this.#upsertSyncedState(connection.id, rendered.node, relativePath, databaseHash);
    return {
      result: {
        connectionId: connection.id,
        nodeId,
        relativePath,
        status: "synced",
        message: "Memory note exported atomically",
      },
      skipped: false,
    };
  }

  #assertBulkRenameStillAllowed(connection: VaultConnection, renderedNode: MemoryNode): void {
    if (!this.vaultSyncEnabled()) throw new VaultSyncPolicyRevokedError();
    const current = this.#memory.requireNode(renderedNode.id);
    if (current.version !== renderedNode.version) throw new VaultCanonicalChangedError();
    this.#assertProjectionAllowed(current, connection);
    this.#assertConnectionProjectionAllowed(connection, current);
  }

  async #databaseAheadAfterRace(
    connection: VaultConnection,
    nodeId: string,
    raceRetry: number,
  ): Promise<{ readonly result: VaultSyncResult; readonly skipped: boolean }> {
    const current = this.renderNode(nodeId, connection);
    this.#assertProjectionAllowed(current.node, connection);
    this.#assertConnectionProjectionAllowed(connection, current.node);
    const state = this.#stateForNode(connection.id, nodeId);
    if (!state) {
      if (raceRetry >= 1) throw new VaultCanonicalChangedError();
      return this.#exportNodeAsync(connection, nodeId, raceRetry + 1);
    }
    const path = this.#paths.resolveRelative(connection.vaultPath, state.relative_path);
    const vaultText = existsSync(path) ? readFileSync(path, "utf8") : undefined;
    if (vaultText !== undefined) {
      const quarantined = this.#quarantineUnsafeVaultSource(
        connection,
        current.node,
        state.relative_path,
        vaultText,
      );
      if (quarantined) return { result: quarantined, skipped: false };
    }
    const databaseHash = hashText(current.text);
    const vaultHash = vaultText === undefined ? undefined : hashText(vaultText);
    this.#updateState(
      state.id,
      "database_ahead",
      current.node.version,
      databaseHash,
      vaultHash,
      undefined,
      false,
    );
    return {
      result: {
        connectionId: connection.id,
        nodeId,
        relativePath: state.relative_path,
        status: "database_ahead",
        message: "Canonical memory changed during projection and is ready for a safe resume",
      },
      skipped: false,
    };
  }

  syncNode(
    connectionId: string,
    nodeId: string,
    actor: string,
    allowedTargetIds?: ReadonlySet<string>,
  ): VaultSyncResult {
    const connection = this.requireConnection(connectionId);
    const rendered = this.renderNode(nodeId, connection, allowedTargetIds);
    this.#assertProjectionAllowed(rendered.node, connection);
    this.#assertConnectionProjectionAllowed(connection, rendered.node);
    const state = this.#stateForNode(connectionId, nodeId);
    if (!state) return this.exportNode(connectionId, nodeId, allowedTargetIds);
    const path = this.#paths.resolveRelative(connection.vaultPath, state.relative_path);
    if (!existsSync(path)) return this.exportNode(connectionId, nodeId, allowedTargetIds);
    const vaultBytes = readFileSync(path);
    const vaultText = vaultBytes.toString("utf8");
    const quarantined = this.#quarantineUnsafeVaultSource(
      connection,
      rendered.node,
      state.relative_path,
      vaultText,
    );
    if (quarantined) return quarantined;
    const databaseHash = hashText(rendered.text);
    const vaultHash = hashText(vaultText);
    const databaseChanged = state.database_content_hash !== databaseHash;
    const vaultChanged = state.vault_content_hash !== vaultHash;
    if (state.status === "conflict") {
      const openConflict = this.#database.prepare(`
        SELECT id, database_hash, vault_hash
        FROM vault_conflicts
        WHERE sync_state_id = ? AND status = 'open'
      `).get(state.id) as {
        id: string;
        database_hash: string;
        vault_hash: string;
      } | undefined;
      if (openConflict) {
        if (
          openConflict.database_hash !== databaseHash
          || openConflict.vault_hash !== vaultHash
        ) {
          return this.#refreshOpenConflict(
            openConflict.id,
            connection,
            nodeId,
            state.relative_path,
            "Conflict inputs changed while awaiting operator resolution",
            allowedTargetIds,
          );
        }
        return {
          connectionId,
          nodeId,
          relativePath: state.relative_path,
          status: "conflict",
          conflictId: openConflict.id,
          message: "Database and vault changes conflict; operator resolution is required",
        };
      }
    }
    if (databaseChanged && vaultChanged && databaseHash !== vaultHash) {
      return this.#createConflict(connection, state, rendered.node, state.relative_path, rendered.text, vaultText);
    }
    if (vaultChanged && !databaseChanged) {
      const imported = this.importNote(connectionId, state.relative_path, actor, true, allowedTargetIds);
      if (imported.status === "quarantined") {
        return {
          connectionId,
          nodeId,
          relativePath: state.relative_path,
          status: "quarantined",
          message: "Malformed vault note was quarantined",
        };
      }
      const normalized = this.renderNode(nodeId, connection, allowedTargetIds);
      const normalizedHash = hashText(normalized.text);
      this.#projectAttachments(connection, normalized.attachments);
      try {
        this.#paths.atomicWrite(connection.vaultPath, state.relative_path, normalized.text, {
          exists: true,
          sha256: createHash("sha256").update(vaultBytes).digest("hex"),
          beforeRename: () => this.#assertBulkRenameStillAllowed(connection, normalized.node),
        });
      } catch (error) {
        if (error instanceof VaultDestinationChangedError) {
          return this.#refreshImportedVaultRace(
            connection,
            nodeId,
            state.relative_path,
            vaultHash,
            "The vault note changed again while its imported edit was being normalized",
            allowedTargetIds,
          );
        }
        if (error instanceof VaultCanonicalChangedError) {
          return this.#refreshImportedVaultRace(
            connection,
            nodeId,
            state.relative_path,
            vaultHash,
            "Canonical memory changed while an imported vault edit was being normalized",
            allowedTargetIds,
          );
        }
        throw error;
      }
      this.#upsertSyncedState(connectionId, normalized.node, state.relative_path, normalizedHash);
      this.#touchConnection(connectionId);
      return {
        connectionId,
        nodeId,
        relativePath: state.relative_path,
        status: "synced",
        message: imported.status === "updated"
          ? "Vault edit was versioned in the database and the projection was normalized"
          : "Vault note is synchronized",
      };
    }
    return this.exportNode(connectionId, nodeId);
  }

  /**
   * Reconcile the watcher-critical window after a vault edit has already been
   * versioned in SQLite but before its normalized Markdown projection could be
   * published. A second vault edit becomes an explicit conflict; an unchanged
   * imported source with a newer canonical version is truthfully database-ahead.
   */
  #refreshImportedVaultRace(
    connection: VaultConnection,
    nodeId: string,
    relativePath: string,
    importedVaultHash: string,
    reason: string,
    allowedTargetIds?: ReadonlySet<string>,
  ): VaultSyncResult {
    const rendered = this.renderNode(nodeId, connection, allowedTargetIds);
    this.#assertProjectionAllowed(rendered.node, connection);
    this.#assertConnectionProjectionAllowed(connection, rendered.node);
    const state = this.#stateForNode(connection.id, nodeId);
    if (!state) throw new Error("Vault synchronization state disappeared during imported-edit recovery");
    const databaseHash = hashText(rendered.text);
    const path = this.#paths.resolveRelative(connection.vaultPath, relativePath);
    if (!existsSync(path)) {
      this.#updateState(
        state.id,
        "database_ahead",
        rendered.node.version,
        databaseHash,
        undefined,
        reason,
        false,
      );
      return {
        connectionId: connection.id,
        nodeId,
        relativePath,
        status: "database_ahead",
        message: "The vault note disappeared after its edit was versioned; canonical memory is ready for a safe resume",
      };
    }
    const vaultText = readFileSync(path, "utf8");
    const quarantined = this.#quarantineUnsafeVaultSource(
      connection,
      rendered.node,
      relativePath,
      vaultText,
    );
    if (quarantined) return quarantined;
    const currentVaultHash = hashText(vaultText);
    if (currentVaultHash === databaseHash) {
      this.#upsertSyncedState(connection.id, rendered.node, relativePath, databaseHash);
      this.#touchConnection(connection.id);
      return {
        connectionId: connection.id,
        nodeId,
        relativePath,
        status: "synced",
        message: "The concurrent projection already matches canonical memory",
      };
    }
    if (currentVaultHash === importedVaultHash) {
      this.#updateState(
        state.id,
        "database_ahead",
        rendered.node.version,
        databaseHash,
        currentVaultHash,
        reason,
        false,
      );
      return {
        connectionId: connection.id,
        nodeId,
        relativePath,
        status: "database_ahead",
        message: "The imported vault edit is preserved and canonical memory is ready for a safe resume",
      };
    }
    return this.#createConflict(
      connection,
      state,
      rendered.node,
      relativePath,
      rendered.text,
      vaultText,
    );
  }

  importNote(
    connectionId: string,
    relativePath: string,
    actor: string,
    allowExistingUpdate = false,
    allowedTargetIds?: ReadonlySet<string>,
  ): VaultImportResult {
    const memoryPolicy = this.assertVaultSyncAllowed();
    const connection = this.requireConnection(connectionId);
    const path = this.#paths.resolveRelative(connection.vaultPath, relativePath);
    if (!existsSync(path) || !statSync(path).isFile()) throw new Error("Vault note does not exist");
    const source = readFileSync(path, "utf8");
    const sourceHash = hashText(source);
    const priorState = this.#stateForPath(connectionId, relativePath);
    if (
      !allowExistingUpdate
      && priorState?.node_id === null
      && priorState.vault_content_hash === sourceHash
      && priorState.status === "pending"
    ) {
      return { relativePath, status: "unchanged" };
    }
    try {
      assertReusableMemoryText([{
        field: "vaultNote.relativePath",
        value: relativePath,
        maximumBytes: 1_000,
      }]);
      this.#assertVaultSourceSafe(source);
    } catch (error) {
      if (!(error instanceof ReusableMemorySafetyError)) throw error;
      const quarantinePath = this.#quarantine(
        connection,
        relativePath,
        "Vault note rejected by reusable-memory safety policy",
        true,
      );
      return { relativePath, status: "quarantined", quarantinePath };
    }
    let note: VaultNote;
    try {
      note = parseObsidianNote(source);
      this.#assertVaultNoteSafe(note);
    } catch (error) {
      const quarantinePath = this.#quarantine(
        connection,
        relativePath,
        error instanceof ReusableMemorySafetyError
          ? "Vault note rejected by reusable-memory safety policy"
          : error instanceof Error ? error.message : String(error),
        error instanceof ReusableMemorySafetyError,
      );
      return { relativePath, status: "quarantined", quarantinePath };
    }
    this.#assertConnectionProjectionAllowed(connection, note);
    this.#assertImportedEdgesAllowed(connection, note, allowedTargetIds);
    const existing = this.#memory.getNode(note.id);
    if (existing) this.#assertCanonicalPrivateProvenance(existing.id, note);
    const candidateImport = !existing || relativePath.startsWith("00 Inbox/");
    if (!existing && note.privateProvenanceSummary?.truncated) {
      throw new Error("A new Vault candidate cannot claim private provenance omitted from canonical SQLite custody");
    }
    if (candidateImport && !REUSABLE_VAULT_NODE_TYPE_SET.has(note.nodeType)) {
      throw new Error(
        `Vault note type ${note.nodeType} is private operational provenance and cannot enter reusable memory`,
      );
    }
    if (candidateImport && !memoryCandidateAllowed(memoryPolicy, note.nodeType)) {
      throw new Error("This Obsidian note type is not permitted by the current memory candidate policy");
    }
    let attachmentSources: readonly ProvenanceSource[];
    try {
      attachmentSources = this.#importAttachments(connection, note);
    } catch {
      const quarantinePath = this.#quarantine(
        connection,
        relativePath,
        "Vault attachment rejected by integrity policy",
        true,
      );
      return { relativePath, status: "quarantined", quarantinePath };
    }
    const provenance: MemoryProvenance = {
      method: "imported",
      explanation: "Imported from an explicitly connected Obsidian vault",
      sources: [
        {
          sourceType: "obsidian_note",
          sourceId: `${connectionId}:${relativePath}`,
          sourceHash,
          acquiredAt: this.#now(),
        },
        ...attachmentSources,
      ],
    };
    if (candidateImport) {
      const candidate = this.#memory.createCandidate({
        nodeType: note.nodeType,
        title: note.title,
        summary: note.summary,
        body: note.body,
        scope: note.scope,
        sensitivity: note.sensitivity,
        confidence: note.confidence,
        provenance,
        proposedBy: actor,
      });
      this.#upsertPendingImportState(connectionId, relativePath, sourceHash);
      return { relativePath, status: "candidate", candidateId: candidate.id };
    }
    if (!allowExistingUpdate) {
      throw new Error("Updating an existing memory requires a version-aware sync operation");
    }
    this.#assertProjectionAllowed(existing, connection);
    this.#assertConnectionProjectionAllowed(connection, existing);
    if (note.nodeType !== existing.nodeType || JSON.stringify(note.scope) !== JSON.stringify(existing.scope)) {
      throw new Error("Node type and memory scope cannot be changed through automatic vault sync");
    }
    if (note.version !== existing.version) {
      throw new Error("Vault note version does not match the canonical memory version");
    }
    const existingSourceKeys = new Set(
      existing.provenance.sources.map((item) => `${item.sourceType}\0${item.sourceId}`),
    );
    const newAttachmentSources = attachmentSources.filter(
      (item) => !existingSourceKeys.has(`${item.sourceType}\0${item.sourceId}`),
    );
    if (
      note.title === existing.title && note.summary === existing.summary && note.body === existing.body &&
      note.sensitivity === existing.sensitivity && note.confidence === existing.confidence &&
      newAttachmentSources.length === 0
    ) {
      return { relativePath, status: "unchanged", nodeId: existing.id };
    }
    const updated = this.#memory.correctNode(existing.id, {
      title: note.title,
      summary: note.summary,
      body: note.body,
      sensitivity: note.sensitivity,
      confidence: note.confidence,
      expiresAt: note.expiresAt ?? null,
      additionalProvenanceSources: newAttachmentSources,
      // The authenticated operator authored this edit through their connected
      // Vault. Preserve that authorship instead of disguising it as an import.
      authorType: "operator",
      authorId: actor,
      changeReason: "Operator edited synchronized Obsidian note",
    });
    this.#importEdges(updated, note, provenance, actor, connection, allowedTargetIds);
    return { relativePath, status: "updated", nodeId: updated.id };
  }

  /**
   * Process one debounced path. Unchanged bridge-authored writes are ignored,
   * deletions are restored from SQLite, and new notes enter candidate review.
   */
  syncChangedPath(
    connectionId: string,
    relativePath: string,
    actor: string,
  ): VaultSyncResult | VaultImportResult | null {
    this.assertVaultSyncAllowed();
    const connection = this.requireConnection(connectionId);
    if (!relativePath.toLowerCase().endsWith(".md")) return null;
    const path = this.#paths.resolveRelative(connection.vaultPath, relativePath);
    const state = this.#stateForPath(connectionId, relativePath);
    if (state?.node_id) {
      if (existsSync(path)) {
        const currentHash = hashText(readFileSync(path, "utf8"));
        if (state.vault_content_hash === currentHash) return null;
      }
      return this.syncNode(connectionId, state.node_id, actor);
    }
    if (!existsSync(path)) return null;
    const currentHash = hashText(readFileSync(path, "utf8"));
    if (state?.vault_content_hash === currentHash && ["pending", "quarantined"].includes(state.status)) return null;
    return this.importNote(connectionId, relativePath, actor);
  }

  async createPortableExport(
    connectionId: string,
    nodeIds: readonly string[],
    actor: string,
    options: VaultPortableExportOptions = {},
  ): Promise<VaultPortableExport> {
    throw new Error(
      "Portable Vault ZIP creation is disabled by operator no-backup policy",
    );
    /* c8 ignore start -- unreachable retired portable-archive implementation */
    this.assertVaultSyncAllowed();
    const connection = this.requireConnection(connectionId);
    const createdAt = this.#now();
    const uniqueIds = [...new Set(nodeIds)];
    const entries: PortableZipEntry[] = [];
    const portableAttachments = new Map<string, PortableZipEntry>();
    const nodeSnapshots: Array<{ nodeId: string; version: number; projectionHash: string }> = [];
    const portableNodeIds = new Set(uniqueIds);
    for (const nodeId of uniqueIds) {
      const rendered = this.renderNode(nodeId, connection, portableNodeIds);
      this.#assertProjectionAllowed(rendered.node, connection);
      this.#assertConnectionProjectionAllowed(connection, rendered.node);
      nodeSnapshots.push({
        nodeId,
        version: rendered.node.version,
        projectionHash: hashText(rendered.text),
      });
      entries.push({ name: rendered.relativePath, data: rendered.text });
      for (const attachment of rendered.attachments) {
        if (portableAttachments.has(attachment.contentHash)) continue;
        portableAttachments.set(attachment.contentHash, {
          name: attachment.relativePath,
          filePath: this.#canonicalAttachmentPath(attachment),
        });
      }
    }
    entries.push(...portableAttachments.values());
    let brainAtlasProfile: VaultPortableExport["brainAtlasProfile"];
    if (options.includeBrainAtlasProfile === true) {
      const health = this.#brainAtlasPlugins.health(connectionId);
      if (!health.healthy || !health.configuration.sha256) {
        throw new Error("The pinned Brain Atlas profile must pass read-only health before portable export");
      }
      const pinnedRelease = this.#brainAtlasPlugins.pinnedRelease();
      const base = `.obsidian/plugins/${pinnedRelease.pluginId}`;
      const profileFiles = [
        "main.js", "manifest.json", "styles.css", "data.json", "release.json", "LICENSE",
      ] as const;
      const assetSha256: Record<string, string> = {};
      for (const name of profileFiles) {
        const filePath = this.#paths.resolveRelative(connection.vaultPath, `${base}/${name}`);
        const bytes = readFileSync(filePath);
        assetSha256[name] = hashBytes(bytes);
        entries.push({
          name: `${base}/${name}`,
          filePath,
          approvedObsidianProfile: "ti-scale-brain-atlas-v1",
        });
      }
      const community = `${JSON.stringify([pinnedRelease.pluginId], null, 2)}\n`;
      entries.push({
        name: ".obsidian/community-plugins.json",
        data: community,
        approvedObsidianProfile: "ti-scale-brain-atlas-v1",
      });
      assetSha256["community-plugins.json"] = hashBytes(Buffer.from(community, "utf8"));
      brainAtlasProfile = {
        pluginId: pinnedRelease.pluginId,
        version: pinnedRelease.version,
        configurationSha256: health.configuration.sha256!,
        assetSha256,
        mode: "portable-copy",
      };
    }
    const manifest = {
      schemaVersion: "2.4",
      product: "Ti-Scale",
      sourceOfTruth: "canonical-sqlite",
      vault: connection.displayName,
      generatedAt: createdAt,
      generatedBy: actor,
      noteCount: uniqueIds.length,
      attachmentCount: portableAttachments.size,
      includesObsidianSettings: options.includeBrainAtlasProfile === true,
      obsidianSettingsScope: options.includeBrainAtlasProfile === true
        ? "pinned-brain-atlas-only"
        : "none",
      ...(brainAtlasProfile ? { brainAtlasProfile } : {}),
    };
    entries.push({ name: "ti-scale-vault-manifest.json", data: `${JSON.stringify(manifest, null, 2)}\n` });
    const stamp = createdAt.replace(/[:.]/gu, "-");
    const archiveName = `ti-scale-brain-${stamp}-${randomUUID()}.zip`;
    const archivePath = this.#paths.resolveRelative(
      connection.vaultPath,
      `.ti-scale/exports/${archiveName}`,
      true,
    );
    const result = await writePortableZip(entries, archivePath, new Date(createdAt));
    return {
      connectionId,
      archiveName,
      archivePath,
      sha256: result.sha256,
      byteSize: result.byteSize,
      fileCount: result.fileCount,
      createdAt,
      nodeSnapshots,
      ...(brainAtlasProfile ? { brainAtlasProfile } : {}),
    };
    /* c8 ignore stop */
  }

  portableExportPath(connectionId: string, archiveName: string): string {
    void connectionId;
    void archiveName;
    throw new Error(
      "Portable Vault ZIP delivery is disabled by operator no-backup policy",
    );
    /* c8 ignore start -- unreachable retired portable-archive delivery */
    const connection = this.requireConnection(connectionId);
    if (!/^ti-scale-brain-[A-Za-z0-9._-]+\.zip$/u.test(archiveName) || basename(archiveName) !== archiveName) {
      throw new TypeError("Portable vault archive name is invalid");
    }
    const path = this.#paths.resolveRelative(connection.vaultPath, `.ti-scale/exports/${archiveName}`);
    if (!existsSync(path) || !statSync(path).isFile()) throw new Error("Portable vault archive was not found");
    return path;
    /* c8 ignore stop */
  }

  /** Compare canonical content, tracked hashes, and projection files read-only. */
  verifyConnection(connectionId: string): VaultSyncVerification {
    const connection = this.requireConnection(connectionId);
    const rows = this.#database.prepare(`
      SELECT * FROM vault_sync_state WHERE connection_id = ? ORDER BY relative_path
    `).all(connectionId) as SyncStateRow[];
    const items: VaultSyncVerificationItem[] = rows.map((state) => {
      const path = this.#paths.resolveRelative(connection.vaultPath, state.relative_path);
      if (state.status === "quarantined") {
        return { relativePath: state.relative_path, ...(state.node_id ? { nodeId: state.node_id } : {}), status: "quarantined" };
      }
      if (!state.node_id) {
        return {
          relativePath: state.relative_path,
          status: existsSync(path) ? "pending" : "missing",
        };
      }
      const node = this.#memory.getNode(state.node_id, true);
      if (!node || node.lifecycleStatus === "forgotten") {
        return { relativePath: state.relative_path, nodeId: state.node_id, status: existsSync(path) ? "vault_ahead" : "missing" };
      }
      const rendered = this.renderNode(node.id, connection);
      const databaseHash = hashText(rendered.text);
      if (!existsSync(path)) return { relativePath: state.relative_path, nodeId: node.id, status: "missing" };
      const vaultHash = hashText(readFileSync(path, "utf8"));
      const databaseChanged = state.database_content_hash !== databaseHash;
      const vaultChanged = state.vault_content_hash !== vaultHash;
      const status: VaultSyncVerificationItem["status"] = databaseChanged && vaultChanged && databaseHash !== vaultHash
        ? "conflict"
        : databaseChanged
          ? "database_ahead"
          : vaultChanged
            ? "vault_ahead"
            : "synced";
      return { relativePath: state.relative_path, nodeId: node.id, status };
    });
    const statuses: VaultSyncVerificationItem["status"][] = [
      "synced", "database_ahead", "vault_ahead", "conflict", "missing", "pending", "quarantined",
    ];
    const counts = Object.fromEntries(statuses.map((status) => [status, items.filter((item) => item.status === status).length])) as Record<VaultSyncVerificationItem["status"], number>;
    return {
      connectionId,
      healthy: counts.database_ahead === 0
        && counts.vault_ahead === 0
        && counts.conflict === 0
        && counts.missing === 0
        && counts.pending === 0
        && counts.quarantined === 0,
      checkedAt: this.#now(),
      counts,
      items,
    };
  }

  #attachmentFromArtifactRow(row: ArtifactRow): CanonicalVaultAttachment {
    if (row.artifact_type !== "obsidian_attachment") {
      throw new Error("Memory attachment source is not an Obsidian attachment artifact");
    }
    const contentHash = row.content_hash.toLowerCase();
    if (!/^[a-f0-9]{64}$/u.test(contentHash) || row.byte_size < 0 || row.byte_size > MAX_ATTACHMENT_BYTES) {
      throw new Error("Canonical vault attachment metadata is invalid");
    }
    const storage = parseAttachmentStorageUri(row.storage_uri);
    if (storage.contentHash !== contentHash) {
      throw new Error("Canonical vault attachment storage hash does not match its artifact record");
    }
    const metadata = parseJsonObject(row.metadata_json);
    if (typeof metadata.extension !== "string") {
      throw new Error("Canonical vault attachment extension metadata is missing");
    }
    const checked = attachmentExtension(`Attachments/attachment${metadata.extension}`);
    if (row.media_type && row.media_type !== checked.mediaType) {
      throw new Error("Canonical vault attachment media type does not match its extension");
    }
    return {
      artifactId: row.id,
      missionId: row.mission_id,
      contentHash,
      byteSize: row.byte_size,
      ...(row.media_type ? { mediaType: row.media_type } : {}),
      extension: checked.extension,
      storageUri: row.storage_uri,
      relativePath: `Attachments/${contentHash}${checked.extension}`,
    };
  }

  #attachmentsForNode(node: MemoryNode): readonly CanonicalVaultAttachment[] {
    const rows = this.#database.prepare(`
      SELECT a.id, a.mission_id, a.journey, a.artifact_type, a.storage_uri, a.content_hash,
        a.byte_size, a.media_type, a.sensitivity, a.metadata_json
      FROM memory_sources ms
      JOIN artifacts a ON a.id = ms.source_id
      WHERE ms.node_id = ? AND ms.source_type = 'artifact'
        AND a.artifact_type = 'obsidian_attachment'
      ORDER BY ms.acquired_at, a.id
    `).all(node.id) as ArtifactRow[];
    if (rows.length === 0) return [];
    if (node.scope.kind !== "mission" || !node.scope.missionId) {
      throw new Error("Obsidian attachments require mission-scoped memory");
    }
    if (rows.length > MAX_ATTACHMENTS_PER_NOTE) {
      throw new Error("Memory note exceeds the attachment count limit");
    }
    return rows.map((row) => {
      if (row.mission_id !== node.scope.missionId) {
        throw new Error("Memory attachment crosses its canonical mission boundary");
      }
      return this.#attachmentFromArtifactRow(row);
    });
  }

  #canonicalAttachmentPath(attachment: CanonicalVaultAttachment): string {
    const storage = parseAttachmentStorageUri(attachment.storageUri);
    if (storage.contentHash !== attachment.contentHash) {
      throw new Error("Canonical vault attachment storage reference is inconsistent");
    }
    const sourceConnection = this.requireConnection(storage.connectionId);
    const path = this.#paths.resolveRelative(
      sourceConnection.vaultPath,
      `.ti-scale/attachments/${attachment.contentHash}`,
    );
    if (!existsSync(path)) throw new Error("Canonical vault attachment bytes are missing");
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size !== attachment.byteSize) {
      throw new Error("Canonical vault attachment is not a matching regular file");
    }
    const actualHash = createHash("sha256").update(readFileSync(path)).digest("hex");
    if (actualHash !== attachment.contentHash) {
      throw new Error("Canonical vault attachment failed its SHA-256 integrity check");
    }
    return path;
  }

  #projectAttachments(
    connection: VaultConnection,
    attachments: readonly CanonicalVaultAttachment[],
  ): void {
    for (const attachment of attachments) {
      const sourcePath = this.#canonicalAttachmentPath(attachment);
      const destination = this.#paths.resolveRelative(
        connection.vaultPath,
        attachment.relativePath,
        true,
      );
      if (existsSync(destination)) {
        const metadata = lstatSync(destination);
        if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size !== attachment.byteSize) {
          throw new Error("Projected vault attachment conflicts with a non-matching file");
        }
        const existingHash = createHash("sha256").update(readFileSync(destination)).digest("hex");
        if (existingHash !== attachment.contentHash) {
          throw new Error("Projected vault attachment failed its SHA-256 integrity check");
        }
        continue;
      }
      this.#paths.atomicWriteBytes(connection.vaultPath, attachment.relativePath, readFileSync(sourcePath));
    }
  }

  #importAttachments(
    connection: VaultConnection,
    note: VaultNote,
  ): readonly ProvenanceSource[] {
    if (note.attachments.length === 0) return [];
    if (note.attachments.length > MAX_ATTACHMENTS_PER_NOTE) {
      throw new Error("Vault note exceeds the attachment count limit");
    }
    if (note.scope.kind !== "mission" || !note.scope.missionId) {
      throw new Error("Vault attachments require mission-scoped memory");
    }
    const missionId = note.scope.missionId;
    const mission = this.#database.prepare("SELECT id, journey FROM missions WHERE id = ?").get(missionId) as
      | { id: string; journey: "autonomous" | "guided" }
      | undefined;
    if (!mission) throw new Error("Vault attachment mission does not exist");

    const now = this.#now();
    const sources = new Map<string, ProvenanceSource>();
    for (const reference of note.attachments) {
      const { extension, mediaType } = attachmentExtension(reference.relativePath);
      const sourcePath = this.#paths.resolveRelative(connection.vaultPath, reference.relativePath);
      if (!existsSync(sourcePath)) throw new Error("Referenced vault attachment does not exist");
      const sourceMetadata = lstatSync(sourcePath);
      if (sourceMetadata.isSymbolicLink() || !sourceMetadata.isFile()) {
        throw new Error("Vault attachment must be a regular non-symbolic-link file");
      }
      if (sourceMetadata.size > MAX_ATTACHMENT_BYTES) {
        throw new Error("Vault attachment exceeds the byte-size limit");
      }
      const bytes = readFileSync(sourcePath);
      const contentHash = createHash("sha256").update(bytes).digest("hex");
      if (reference.contentHash && reference.contentHash !== contentHash) {
        throw new Error("Vault attachment marker failed its SHA-256 integrity check");
      }

      const artifact = inImmediateTransaction(this.#database, () => {
        let row: ArtifactRow | undefined;
        if (reference.artifactId) {
          row = this.#database.prepare(`
            SELECT id, mission_id, journey, artifact_type, storage_uri, content_hash,
              byte_size, media_type, sensitivity, metadata_json
            FROM artifacts WHERE id = ?
          `).get(reference.artifactId) as ArtifactRow | undefined;
          if (!row) throw new Error("Vault attachment marker references an unknown artifact");
        } else {
          row = this.#database.prepare(`
            SELECT id, mission_id, journey, artifact_type, storage_uri, content_hash,
              byte_size, media_type, sensitivity, metadata_json
            FROM artifacts
            WHERE mission_id = ? AND artifact_type = 'obsidian_attachment' AND content_hash = ?
            ORDER BY created_at, id LIMIT 1
          `).get(missionId, contentHash) as ArtifactRow | undefined;
        }
        if (row) {
          const canonical = this.#attachmentFromArtifactRow(row);
          if (
            canonical.missionId !== missionId ||
            row.journey !== mission.journey ||
            canonical.contentHash !== contentHash ||
            canonical.byteSize !== bytes.length
          ) {
            throw new Error("Vault attachment marker does not match its canonical artifact");
          }
          this.#canonicalAttachmentPath(canonical);
          return canonical;
        }

        const artifactId = this.#createId("artifact");
        const canonicalRelativePath = `.ti-scale/attachments/${contentHash}`;
        const canonicalPath = this.#paths.resolveRelative(
          connection.vaultPath,
          canonicalRelativePath,
          true,
        );
        if (existsSync(canonicalPath)) {
          const canonicalMetadata = lstatSync(canonicalPath);
          if (canonicalMetadata.isSymbolicLink() || !canonicalMetadata.isFile()) {
            throw new Error("Canonical attachment destination is not a regular file");
          }
          const canonicalHash = createHash("sha256").update(readFileSync(canonicalPath)).digest("hex");
          if (canonicalHash !== contentHash || canonicalMetadata.size !== bytes.length) {
            throw new Error("Canonical attachment destination failed its integrity check");
          }
        } else {
          this.#paths.atomicWriteBytes(connection.vaultPath, canonicalRelativePath, bytes);
        }
        const storageUri = attachmentStorageUri(connection.id, contentHash);
        this.#database.prepare(`
          INSERT INTO artifacts (
            id, mission_id, journey, artifact_type, storage_uri, content_hash,
            byte_size, media_type, sensitivity, metadata_json, created_at
          ) VALUES (?, ?, ?, 'obsidian_attachment', ?, ?, ?, ?, ?, ?, ?)
        `).run(
          artifactId,
          missionId,
          mission.journey,
          storageUri,
          contentHash,
          bytes.length,
          mediaType,
          note.sensitivity,
          JSON.stringify({ extension, source: "obsidian_vault" }),
          now,
        );
        return {
          artifactId,
          missionId,
          contentHash,
          byteSize: bytes.length,
          mediaType,
          extension,
          storageUri,
          relativePath: `Attachments/${contentHash}${extension}`,
        } satisfies CanonicalVaultAttachment;
      });

      sources.set(artifact.artifactId, {
        sourceType: "artifact",
        sourceId: artifact.artifactId,
        sourceHash: artifact.contentHash,
        acquiredAt: now,
      });
    }
    return [...sources.values()];
  }

  #assertImportedEdgesAllowed(
    connection: VaultConnection,
    note: VaultNote,
    allowedTargetIds?: ReadonlySet<string>,
  ): void {
    for (const noteEdge of note.edges) {
      const target = this.#memory.getNode(noteEdge.targetNodeId);
      if (!target) continue;
      if (
        !this.#connectionProjectionMatches(connection, target)
        || (allowedTargetIds && !allowedTargetIds.has(target.id))
      ) {
        throw new Error("Vault note relationship target is outside the permitted memory scope");
      }
      if (
        isAttackCentricReusableNodeType(note.nodeType)
        !== isAttackCentricReusableNodeType(target.nodeType)
      ) {
        throw new Error(
          "Vault note relationships cannot cross the reusable/private memory boundary",
        );
      }
    }
  }

  #importEdges(
    source: MemoryNode,
    note: VaultNote,
    provenance: MemoryProvenance,
    actor: string,
    connection: VaultConnection,
    allowedTargetIds?: ReadonlySet<string>,
  ): void {
    const existing = this.#memory.listEdges(source.id);
    for (const noteEdge of note.edges) {
      const target = this.#memory.getNode(noteEdge.targetNodeId);
      if (!target) continue;
      if (
        !this.#connectionProjectionMatches(connection, target)
        || (allowedTargetIds && !allowedTargetIds.has(target.id))
      ) continue;
      if (existing.some((edge) =>
        edge.sourceNodeId === source.id && edge.targetNodeId === target.id && edge.edgeType === noteEdge.edgeType
      )) continue;
      const scope = source.scope.kind === "global" ? target.scope : source.scope;
      const input: CreateMemoryEdgeInput = {
        sourceNodeId: source.id,
        targetNodeId: target.id,
        edgeType: noteEdge.edgeType,
        title: `${source.title} ${noteEdge.edgeType} ${target.title}`,
        summary: "Relationship imported from an operator-edited Obsidian note",
        scope,
        sensitivity: source.sensitivity,
        confidence: Math.min(source.confidence, target.confidence),
        lifecycleStatus: "confirmed",
        provenance,
        explanation: "Operator preserved this relationship as a native Obsidian wikilink",
        authorType: "operator",
        authorId: actor,
      };
      this.#memory.createEdge(input);
    }
  }

  #quarantine(
    connection: VaultConnection,
    relativePath: string,
    errorMessage: string,
    redactOriginalPath = false,
  ): string {
    const source = this.#paths.resolveRelative(connection.vaultPath, relativePath);
    // Use a content-free filename. The original filename may itself contain a
    // credential value and must not be copied into diagnostics or projections.
    const quarantineRelative = `.ti-scale/quarantine/${Date.now()}-note-${hashText(relativePath).slice(0, 16)}-${randomUUID()}.md`;
    const destination = this.#paths.resolveRelative(connection.vaultPath, quarantineRelative, true);
    renameSync(source, destination);
    const now = this.#now();
    const state = this.#database.prepare(`
      SELECT id FROM vault_sync_state WHERE connection_id = ? AND relative_path = ?
    `).get(connection.id, relativePath) as { id: string } | undefined;
    if (state) {
      this.#database.prepare(`
        UPDATE vault_sync_state SET status = 'quarantined', error_message = ?, last_scanned_at = ? WHERE id = ?
      `).run(errorMessage.slice(0, 1_000), now, state.id);
    } else {
      this.#database.prepare(`
        INSERT INTO vault_sync_state (
          id, connection_id, relative_path, status, last_scanned_at, error_message
        ) VALUES (?, ?, ?, 'quarantined', ?, ?)
      `).run(
        this.#createId("vsync"),
        connection.id,
        redactOriginalPath ? quarantineRelative : relativePath,
        now,
        errorMessage.slice(0, 1_000),
      );
    }
    return quarantineRelative;
  }

  #assertVaultNoteSafe(note: VaultNote): void {
    if (note.attachments.length > MAX_ATTACHMENTS_PER_NOTE) {
      throw new Error("Vault note exceeds the attachment count limit");
    }
    for (const attachment of note.attachments) attachmentExtension(attachment.relativePath);
    if (isAttackCentricReusableNodeType(note.nodeType) && note.sourceIds.length > 0) {
      throw new Error("Reusable attack knowledge must use opaque private_provenance_ids, not raw source_ids");
    }
    if (
      !isAttackCentricReusableNodeType(note.nodeType)
      && (note.privateProvenanceIds.length > 0 || note.privateProvenanceSummary !== undefined)
    ) {
      throw new Error("Private provenance summaries are permitted only for reusable attack knowledge");
    }
    if (note.privateProvenanceIds.some((id) => !/^msrc_[A-Za-z0-9._:-]+$/u.test(id))) {
      throw new Error("Vault private provenance reference is malformed");
    }
    assertReusableMemoryText([
      { field: "vaultNote.title", value: note.title, maximumBytes: REUSABLE_MEMORY_LIMITS.title },
      { field: "vaultNote.summary", value: note.summary, maximumBytes: REUSABLE_MEMORY_LIMITS.summary },
      { field: "vaultNote.body", value: note.body, maximumBytes: REUSABLE_MEMORY_LIMITS.body },
      ...note.sourceIds.map((sourceId, index) => ({
        field: `vaultNote.sourceIds[${index}]`,
        value: sourceId,
        maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceIdentifier,
      })),
      ...note.privateProvenanceIds.map((sourceId, index) => ({
        field: `vaultNote.privateProvenanceIds[${index}]`,
        value: sourceId,
        maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceIdentifier,
      })),
      ...note.aliases.map((alias, index) => ({
        field: `vaultNote.aliases[${index}]`,
        value: alias,
        maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceIdentifier,
      })),
      ...note.tags.map((tag, index) => ({
        field: `vaultNote.tags[${index}]`,
        value: tag,
        maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceIdentifier,
      })),
      ...note.attachments.flatMap((attachment, index) => [
        {
          field: `vaultNote.attachments[${index}].relativePath`,
          value: attachment.relativePath,
          maximumBytes: 1_000,
        },
        {
          field: `vaultNote.attachments[${index}].artifactId`,
          value: attachment.artifactId,
          maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceIdentifier,
        },
        {
          field: `vaultNote.attachments[${index}].contentHash`,
          value: attachment.contentHash,
          maximumBytes: 64,
        },
      ]),
    ]);
  }

  /**
   * Bind a managed note's bounded projection back to the complete canonical
   * SQLite row set. Legacy notes without summary metadata remain importable
   * once and are normalized on write; current summaries fail closed if their
   * count, digest, truncation state, or visible opaque sample was changed.
   */
  #assertCanonicalPrivateProvenance(nodeId: string, note: VaultNote): void {
    if (!isAttackCentricReusableNodeType(note.nodeType) || !note.privateProvenanceSummary) return;
    const rows = this.#database.prepare(`
      SELECT id FROM memory_sources WHERE node_id = ? ORDER BY id
    `).all(nodeId) as Array<{ id: string }>;
    const canonical = projectPrivateProvenanceIds(rows.map((row) => row.id));
    const summary = note.privateProvenanceSummary;
    if (
      summary.schema !== canonical.summary.schema
      || summary.total !== canonical.summary.total
      || summary.projected !== canonical.summary.projected
      || summary.sha256 !== canonical.summary.sha256
      || summary.truncated !== canonical.summary.truncated
      || note.privateProvenanceIds.length !== canonical.ids.length
      || note.privateProvenanceIds.some((id, index) => id !== canonical.ids[index])
    ) {
      throw new Error("Vault private provenance summary does not match canonical SQLite custody");
    }
  }

  #assertVaultSourceSafe(source: string): void {
    assertReusableMemoryText([{
      field: "vaultNote.source",
      value: source,
      maximumBytes: REUSABLE_MEMORY_LIMITS.vaultNote,
    }]);
    try {
      this.#assertVaultNoteSafe(parseObsidianNote(source));
    } catch (error) {
      // Syntax errors are handled by the existing malformed-note quarantine.
      // Safety errors propagate so valid oversized fields cannot enter a conflict.
      if (error instanceof ReusableMemorySafetyError) throw error;
    }
  }

  #quarantineUnsafeVaultSource(
    connection: VaultConnection,
    node: MemoryNode,
    relativePath: string,
    source: string,
  ): VaultSyncResult | undefined {
    try {
      this.#assertVaultSourceSafe(source);
      return undefined;
    } catch (error) {
      if (!(error instanceof ReusableMemorySafetyError)) throw error;
      this.#quarantine(connection, relativePath, "Vault note rejected by reusable-memory safety policy", true);
      return {
        connectionId: connection.id,
        nodeId: node.id,
        relativePath,
        status: "quarantined",
        message: "Vault note was quarantined because reusable memory cannot retain authentication material or oversized payloads",
      };
    }
  }

  #createConflict(
    connection: VaultConnection,
    state: SyncStateRow | undefined,
    node: MemoryNode,
    relativePath: string,
    databaseText: string,
    vaultText: string,
  ): VaultSyncResult {
    this.#assertVaultSourceSafe(databaseText);
    this.#assertVaultSourceSafe(vaultText);
    const now = this.#now();
    const syncStateId = state?.id ?? this.#createId("vsync");
    const databaseHash = hashText(databaseText);
    const vaultHash = hashText(vaultText);
    return inImmediateTransaction(this.#database, () => {
      if (state) {
        this.#updateState(state.id, "conflict", node.version, databaseHash, vaultHash, "Concurrent database and vault edits", false);
      } else {
        this.#database.prepare(`
          INSERT INTO vault_sync_state (
            id, connection_id, node_id, relative_path, database_version,
            vault_content_hash, database_content_hash, status, last_scanned_at, error_message
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 'conflict', ?, ?)
        `).run(
          syncStateId, connection.id, node.id, relativePath, node.version,
          vaultHash, databaseHash, now, "Existing unmanaged note conflicts with canonical memory",
        );
      }
      const existing = this.#database.prepare(`
        SELECT id FROM vault_conflicts WHERE sync_state_id = ? AND status = 'open'
      `).get(syncStateId) as { id: string } | undefined;
      const conflictId = existing?.id ?? this.#createId("vconf");
      if (!existing) {
        this.#database.prepare(`
          INSERT INTO vault_conflicts (
            id, connection_id, sync_state_id, node_id, base_hash, database_hash,
            vault_hash, database_version_json, vault_version_text, status, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
        `).run(
          conflictId, connection.id, syncStateId, node.id,
          state?.database_content_hash ?? null, databaseHash, vaultHash,
          JSON.stringify({ node, markdown: databaseText }), vaultText, now,
        );
      }
      return {
        connectionId: connection.id,
        nodeId: node.id,
        relativePath,
        status: "conflict",
        conflictId,
        message: "Database and vault changes conflict; operator resolution is required",
      };
    });
  }

  resolveConflict(
    conflictId: string,
    resolution: "database" | "vault" | "merged",
    actor: string,
    mergedText?: string,
    allowedTargetIds?: ReadonlySet<string>,
  ): VaultSyncResult {
    this.assertVaultSyncAllowed();
    const row = this.#database.prepare(`
      SELECT vc.*, vs.relative_path FROM vault_conflicts vc
      JOIN vault_sync_state vs ON vs.id = vc.sync_state_id
      WHERE vc.id = ? AND vc.status = 'open'
    `).get(conflictId) as Record<string, unknown> | undefined;
    if (!row) throw new Error("Open vault conflict not found");
    const connectionId = String(row.connection_id);
    const nodeId = String(row.node_id);
    const connection = this.requireConnection(connectionId);
    this.#assertProjectionAllowed(this.#memory.requireNode(nodeId), connection);
    this.#assertConnectionProjectionAllowed(connection, this.#memory.requireNode(nodeId));
    const relativePath = String(row.relative_path);
    const projectionPath = this.#paths.resolveRelative(connection.vaultPath, relativePath);
    if (!existsSync(projectionPath) || !lstatSync(projectionPath).isFile()) {
      throw new Error("Vault conflict projection is missing; reload synchronization state before resolving");
    }
    const capturedVaultBytes = readFileSync(projectionPath);
    const capturedVaultText = capturedVaultBytes.toString("utf8");
    this.#assertVaultSourceSafe(capturedVaultText);
    const capturedDatabase = this.renderNode(nodeId, connection, allowedTargetIds);
    if (
      hashText(capturedVaultText) !== String(row.vault_hash)
      || hashText(capturedDatabase.text) !== String(row.database_hash)
    ) {
      this.#refreshOpenConflict(
        conflictId,
        connection,
        nodeId,
        relativePath,
        "Conflict inputs changed after the operator opened the review",
        allowedTargetIds,
      );
      throw new Error("Vault conflict changed after review began; reload it before resolving");
    }
    let result: VaultSyncResult;
    if (resolution === "database") {
      const rendered = this.renderNode(nodeId, connection, allowedTargetIds);
      this.#projectAttachments(connection, rendered.attachments);
      try {
        this.#paths.atomicWrite(connection.vaultPath, relativePath, rendered.text, {
          exists: true,
          sha256: createHash("sha256").update(capturedVaultBytes).digest("hex"),
          beforeRename: () => this.#assertBulkRenameStillAllowed(connection, rendered.node),
        });
      } catch (error) {
        if (error instanceof VaultDestinationChangedError || error instanceof VaultCanonicalChangedError) {
          return this.#refreshOpenConflict(
            conflictId,
            connection,
            nodeId,
            relativePath,
            "Vault or canonical memory changed during conflict publication",
            allowedTargetIds,
          );
        }
        throw error;
      }
      const hash = hashText(rendered.text);
      this.#upsertSyncedState(connectionId, rendered.node, relativePath, hash);
      result = {
        connectionId,
        nodeId,
        relativePath,
        status: "synced",
        message: "Conflict resolved using the canonical database version",
      };
    } else {
      const selectedText = resolution === "merged" ? mergedText : String(row.vault_version_text);
      if (!selectedText) throw new Error("Merged conflict resolution requires note content");
      this.#assertVaultSourceSafe(selectedText);
      // Validate before replacing the current note. Import is version-aware and
      // creates a new immutable memory version attributed to the resolver.
      const note = parseObsidianNote(selectedText);
      this.#assertVaultNoteSafe(note);
      this.#assertImportedEdgesAllowed(connection, note, allowedTargetIds);
      const current = this.#memory.requireNode(nodeId);
      if (note.id !== current.id || note.nodeType !== current.nodeType || JSON.stringify(note.scope) !== JSON.stringify(current.scope)) {
        throw new Error("Conflict resolution cannot change stable identity, node type, or memory scope");
      }
      this.#assertCanonicalPrivateProvenance(current.id, note);
      const attachmentSources = this.#importAttachments(connection, note);
      const existingSourceKeys = new Set(
        current.provenance.sources.map((item) => `${item.sourceType}\0${item.sourceId}`),
      );
      const updated = this.#memory.correctNode(current.id, {
        title: note.title,
        summary: note.summary,
        body: note.body,
        sensitivity: note.sensitivity,
        confidence: note.confidence,
        expiresAt: note.expiresAt ?? null,
        additionalProvenanceSources: attachmentSources.filter(
          (item) => !existingSourceKeys.has(`${item.sourceType}\0${item.sourceId}`),
        ),
        authorType: "operator",
        authorId: actor,
        changeReason: `Operator resolved Obsidian conflict using the ${resolution} content`,
      });
      this.#importEdges(updated, note, {
        method: "imported",
        explanation: "Imported through explicit Obsidian conflict resolution",
        sources: [{
          sourceType: "obsidian_conflict",
          sourceId: conflictId,
          sourceHash: hashText(selectedText),
          acquiredAt: this.#now(),
        }],
      }, actor, connection, allowedTargetIds);
      const normalized = this.renderNode(nodeId, connection, allowedTargetIds);
      const hash = hashText(normalized.text);
      this.#projectAttachments(connection, normalized.attachments);
      try {
        this.#paths.atomicWrite(connection.vaultPath, relativePath, normalized.text, {
          exists: true,
          sha256: createHash("sha256").update(capturedVaultBytes).digest("hex"),
          beforeRename: () => this.#assertBulkRenameStillAllowed(connection, normalized.node),
        });
      } catch (error) {
        if (error instanceof VaultDestinationChangedError || error instanceof VaultCanonicalChangedError) {
          return this.#refreshOpenConflict(
            conflictId,
            connection,
            nodeId,
            relativePath,
            "Vault or canonical memory changed after conflict content was versioned",
            allowedTargetIds,
          );
        }
        throw error;
      }
      this.#upsertSyncedState(connectionId, normalized.node, relativePath, hash);
      result = {
        connectionId,
        nodeId,
        relativePath,
        status: "synced",
        message: `Conflict resolved using ${resolution} content and recorded as a memory version`,
      };
    }
    this.#database.prepare(`
      UPDATE vault_conflicts SET status = ?, resolution_reason = ?, resolved_by = ?, resolved_at = ?
      WHERE id = ?
    `).run(
      resolution === "database" ? "resolved_database" : resolution === "vault" ? "resolved_vault" : "resolved_merged",
      `Operator selected ${resolution} version`, actor, this.#now(), conflictId,
    );
    this.#touchConnection(connectionId);
    return result;
  }

  #refreshOpenConflict(
    conflictId: string,
    connection: VaultConnection,
    nodeId: string,
    relativePath: string,
    reason: string,
    allowedTargetIds?: ReadonlySet<string>,
  ): VaultSyncResult {
    const rendered = this.renderNode(nodeId, connection, allowedTargetIds);
    const databaseHash = hashText(rendered.text);
    const state = this.#stateForNode(connection.id, nodeId);
    if (!state) throw new Error("Vault conflict sync state is missing");
    const path = this.#paths.resolveRelative(connection.vaultPath, relativePath);
    if (!existsSync(path)) {
      this.#updateState(
        state.id,
        "database_ahead",
        rendered.node.version,
        databaseHash,
        undefined,
        reason,
        false,
      );
      return {
        connectionId: connection.id,
        nodeId,
        relativePath,
        status: "database_ahead",
        conflictId,
        message: "Conflict publication stopped because the vault note disappeared; canonical memory remains ahead",
      };
    }
    const vaultText = readFileSync(path, "utf8");
    const quarantined = this.#quarantineUnsafeVaultSource(
      connection,
      rendered.node,
      relativePath,
      vaultText,
    );
    if (quarantined) return { ...quarantined, conflictId };
    const vaultHash = hashText(vaultText);
    inImmediateTransaction(this.#database, () => {
      this.#updateState(
        state.id,
        "conflict",
        rendered.node.version,
        databaseHash,
        vaultHash,
        reason,
        false,
      );
      this.#database.prepare(`
        UPDATE vault_conflicts SET
          database_hash = ?, vault_hash = ?, database_version_json = ?,
          vault_version_text = ?, resolution_reason = NULL,
          resolved_by = NULL, resolved_at = NULL
        WHERE id = ? AND status = 'open'
      `).run(
        databaseHash,
        vaultHash,
        JSON.stringify({ node: rendered.node, markdown: rendered.text }),
        vaultText,
        conflictId,
      );
    });
    return {
      connectionId: connection.id,
      nodeId,
      relativePath,
      status: "conflict",
      conflictId,
      message: "Conflict changed during resolution; the latest database and vault versions require review",
    };
  }

  /** Stages synchronized files, erases canonical memory, then removes stages. */
  forgetMemory(nodeId: string, actor: string, reason?: string): ForgetResult {
    const projections = this.#memory.vaultProjectionsForNode(nodeId);
    const staged: Array<{ original: string; staged: string }> = [];
    try {
      // A portable archive can contain a forgotten node indirectly through a
      // relationship label. Conservatively revoke every bridge-managed ZIP on
      // any forget operation, including archives created by the CLI rather than
      // the HTTP authorization layer.
      const connections = this.#database.prepare("SELECT id FROM vault_connections").all() as Array<{ id: string }>;
      for (const connectionRow of connections) {
        const connection = this.requireConnection(connectionRow.id);
        const exportDirectory = this.#paths.resolveRelative(connection.vaultPath, ".ti-scale/exports", true);
        if (!existsSync(exportDirectory)) continue;
        for (const archiveName of readdirSync(exportDirectory)) {
          if (!/^ti-scale-brain-[A-Za-z0-9._-]+\.zip$/u.test(archiveName) || basename(archiveName) !== archiveName) {
            continue;
          }
          const original = this.#paths.resolveRelative(
            connection.vaultPath,
            `.ti-scale/exports/${archiveName}`,
          );
          const metadata = lstatSync(original);
          if (metadata.isSymbolicLink() || !metadata.isFile()) {
            throw new Error("Portable vault archive is not a regular file");
          }
          const stagedRelative = `.ti-scale/forget-staging/${safeVaultSegment(nodeId, "node")}-${randomUUID()}.zip`;
          const stagedPath = this.#paths.resolveRelative(connection.vaultPath, stagedRelative, true);
          renameSync(original, stagedPath);
          staged.push({ original, staged: stagedPath });
        }
      }
      for (const projection of projections) {
        const connection = this.requireConnection(projection.connectionId);
        const original = this.#paths.resolveRelative(connection.vaultPath, projection.relativePath);
        if (!existsSync(original)) continue;
        const stagedRelative = `.ti-scale/forget-staging/${safeVaultSegment(nodeId, "node")}-${randomUUID()}.md`;
        const stagedPath = this.#paths.resolveRelative(connection.vaultPath, stagedRelative, true);
        renameSync(original, stagedPath);
        staged.push({ original, staged: stagedPath });
      }
      const result = this.#memory.forgetNode(nodeId, actor, reason);
      for (const item of staged) rmSync(item.staged, { force: true });
      return result;
    } catch (error) {
      for (const item of [...staged].reverse()) {
        if (existsSync(item.staged)) {
          mkdirSync(dirname(item.original), { recursive: true, mode: 0o700 });
          renameSync(item.staged, item.original);
        }
      }
      throw error;
    }
  }

  #stateForNode(connectionId: string, nodeId: string): SyncStateRow | undefined {
    return this.#database.prepare(`
      SELECT * FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
    `).get(connectionId, nodeId) as SyncStateRow | undefined;
  }

  #stateForPath(connectionId: string, relativePath: string): SyncStateRow | undefined {
    return this.#database.prepare(`
      SELECT * FROM vault_sync_state WHERE connection_id = ? AND relative_path = ?
    `).get(connectionId, relativePath) as SyncStateRow | undefined;
  }

  #upsertPendingImportState(connectionId: string, relativePath: string, vaultHash: string): void {
    const existing = this.#stateForPath(connectionId, relativePath);
    const now = this.#now();
    if (existing) {
      this.#database.prepare(`
        UPDATE vault_sync_state SET node_id = NULL, status = 'pending', vault_content_hash = ?,
          database_content_hash = NULL, database_version = NULL, error_message = NULL,
          last_scanned_at = ? WHERE id = ?
      `).run(vaultHash, now, existing.id);
      return;
    }
    this.#database.prepare(`
      INSERT INTO vault_sync_state (
        id, connection_id, relative_path, vault_content_hash, status, last_scanned_at
      ) VALUES (?, ?, ?, ?, 'pending', ?)
    `).run(this.#createId("vsync"), connectionId, relativePath, vaultHash, now);
  }

  #upsertSyncedState(connectionId: string, node: MemoryNode, relativePath: string, hash: string): void {
    const now = this.#now();
    const existing = this.#stateForNode(connectionId, node.id);
    if (existing) {
      this.#updateState(existing.id, "synced", node.version, hash, hash, undefined, true);
      return;
    }
    this.#database.prepare(`
      INSERT INTO vault_sync_state (
        id, connection_id, node_id, relative_path, database_version,
        vault_content_hash, database_content_hash, status, last_scanned_at, last_synced_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'synced', ?, ?)
    `).run(this.#createId("vsync"), connectionId, node.id, relativePath, node.version, hash, hash, now, now);
  }

  #updateState(
    id: string,
    status: string,
    databaseVersion: number,
    databaseHash: string,
    vaultHash: string | undefined,
    error: string | undefined,
    synced: boolean,
  ): void {
    const now = this.#now();
    this.#database.prepare(`
      UPDATE vault_sync_state SET status = ?, database_version = ?, database_content_hash = ?,
        vault_content_hash = ?, error_message = ?, last_scanned_at = ?,
        last_synced_at = CASE WHEN ? = 1 THEN ? ELSE last_synced_at END WHERE id = ?
    `).run(status, databaseVersion, databaseHash, vaultHash ?? null, error ?? null, now, synced ? 1 : 0, now, id);
  }

  #touchConnection(connectionId: string): void {
    const now = this.#now();
    this.#database.prepare(`
      UPDATE vault_connections SET last_sync_at = ? WHERE id = ?
    `).run(now, connectionId);
  }
}

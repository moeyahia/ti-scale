import { createHash, randomUUID } from "node:crypto";
import { createReadStream, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, relative } from "node:path";
import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { SqliteDatabase } from "../db/types";
import { getDatabaseHealth } from "../db/health";
import { inImmediateTransaction } from "../db/transaction";
import {
  isReusableKnowledgeOutcomeTag,
  type ReusableKnowledgeOutcomeTag,
} from "../domain/reusable-knowledge-outcomes";
import {
  HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION,
  isHistoricalReportedOutcomeClassification,
  type HistoricalReportedOutcomeClassification,
  type HistoricalReportedOutcomeSummary,
} from "../domain/historical-reported-outcomes";
import { MemoryRepository } from "./MemoryRepository";
import { OperationalHazardProfileRepository } from "./OperationalHazardProfileRepository";
import { ReusableMemorySafetyError } from "./ReusableMemorySafety";
import { assertReusableMemoryUnknown, REUSABLE_MEMORY_LIMITS } from "./ReusableMemorySafety";
import { attackKnowledgeOperationalLocatorCategories } from "./AttackKnowledgeTaxonomy";
import { SecondBrainService } from "./SecondBrainService";
import { HistoricalReportedOutcomeService } from "./HistoricalReportedOutcomeService";
import type {
  MemoryCandidate,
  CorrectMemoryNodeInput,
  MemoryEdge,
  MemoryEdgeType,
  MemoryLifecycle,
  MemoryNode,
  MemoryNodeType,
  MemoryScope,
  MemorySensitivity,
} from "./types";
import {
  assertIdentifier,
  deserializeScope,
  validateConfidence,
  validateEdgeType,
  validateLifecycle,
  validateNodeType,
  validateScope,
  validateSensitivity,
} from "./validation";
import { ObsidianVaultBridge } from "../vault/ObsidianVaultBridge";
import {
  VaultConnectionAlreadyDisconnectedError,
  VaultConnectionLifecycleService,
  VaultConnectionVersionConflictError,
  VaultLastHealthyConnectionError,
} from "../vault/VaultConnectionLifecycleService";
import { VaultPathPolicy } from "../vault/VaultPathPolicy";
import {
  DuplicateVaultProjectionError,
  VaultRecoveryRepository,
  VaultSearchIndexIntegrityError,
} from "../vault/VaultRecoveryRepository";
import { VaultRecoveryService } from "../vault/VaultRecoveryService";
import { parseObsidianNote } from "../vault/ObsidianMarkdown";
import {
  ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
  ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
  attackKnowledgeVaultPolicyHash,
  attackKnowledgeVaultPresetPreview,
  attackKnowledgeVaultSyncScope,
} from "../vault/AttackKnowledgeVaultPreset";
import {
  AttackKnowledgeVaultPolicyService,
  AttackKnowledgeVaultScopeAmendmentConflictError,
} from "../vault/AttackKnowledgeVaultPolicyService";
import { ObsidianPluginManager } from "../vault/ObsidianPluginManager";
import { activeVaultPathFingerprint } from "../vault/ActiveVaultComposition";
import type { VaultConnection } from "../vault/types";
import {
  getMemoryControlPolicy,
  memoryCandidateAllowed,
  updateMemoryControlPolicy,
} from "./MemoryControlPolicy";

const SCHEMA_VERSION = "2.4" as const;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const STATUS_FILTERS = new Set<MemoryLifecycle>([
  "candidate", "confirmed", "verified", "disputed", "stale", "superseded", "forgotten",
]);
const SENSITIVITY_ORDER: readonly MemorySensitivity[] = [
  "public", "internal", "private", "restricted",
];
const GRAPH_PRESETS = {
  attack_path: {
    nodeTypes: ["mission", "run", "plan", "phase", "step", "tool", "mcp_capability", "tactic", "technique", "procedure", "target", "asset", "decision", "evidence", "finding", "failure", "recovery"] as readonly MemoryNodeType[],
    edgeTypes: ["applies_to", "belongs_to", "used_in", "targets", "produced", "supports", "depends_on", "failed_in", "recovered_by", "influenced"] as readonly MemoryEdgeType[],
  },
  lessons_failures: {
    nodeTypes: ["mission", "run", "failure", "recovery", "evaluation", "lesson", "evidence", "finding", "source"] as readonly MemoryNodeType[],
    edgeTypes: ["used_in", "supports", "contradicts", "derived_from", "learned_from", "failed_in", "recovered_by", "similar_to", "supersedes", "verified_by", "influenced"] as readonly MemoryEdgeType[],
  },
} as const;

type GraphPreset = keyof typeof GRAPH_PRESETS;

interface GraphFilters {
  readonly nodeType?: MemoryNodeType;
  readonly edgeTypes?: readonly MemoryEdgeType[];
  /** An explicit relationship filter limits both nodes and edges. Presets
   * limit the projected edge set without hiding otherwise relevant nodes. */
  readonly requireEdgeMatch?: boolean;
  readonly scope?: MemoryScope["kind"];
  readonly engagementId?: string;
  readonly lifecycle?: MemoryLifecycle;
  readonly sensitivity?: MemorySensitivity;
  readonly minConfidence?: number;
  readonly updatedAfter?: string;
  readonly updatedBefore?: string;
  readonly preset?: GraphPreset;
  readonly outcome?: ReusableKnowledgeOutcomeTag | "unclassified";
  readonly reportedOutcome?: HistoricalReportedOutcomeClassification | "not_reported";
}

export interface MemoryAccessPolicy {
  readonly maximumSensitivity: MemorySensitivity;
  readonly allowGlobal?: boolean;
  readonly allEngagements?: boolean;
  readonly engagementIds?: readonly string[];
  readonly missionIds?: readonly string[];
}

export interface SecondBrainRouterDependencies {
  readonly database: SqliteDatabase;
  readonly resolveActor: (request: Request) => string;
  readonly resolveAccess: (request: Request, actorId: string) => MemoryAccessPolicy;
  /** Server-owned sandbox. Client paths can never expand this root. */
  readonly vaultAllowedRoot?: string;
  readonly vaultPathPolicy?: VaultPathPolicy;
  readonly vaultBridge?: ObsidianVaultBridge;
  readonly obsidianPluginManager?: ObsidianPluginManager;
  readonly onVaultConnectionChanged?: () => void;
}

interface NodeSummary {
  readonly id: string;
  readonly nodeType: MemoryNodeType;
  readonly title: string;
  readonly summary: string;
  readonly scope: MemoryScope;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly lifecycleStatus: MemoryLifecycle;
  readonly confirmationState: MemoryNode["confirmationState"];
  readonly version: number;
  readonly pinned: boolean;
  readonly expiresAt?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly edgeCount: number;
  readonly sourceCount: number;
  readonly outcomeTags: readonly ReusableKnowledgeOutcomeTag[];
  readonly reportedOutcome?: HistoricalReportedOutcomeSummary;
}

interface NodeSummaryRow {
  readonly id: string;
  readonly node_type: MemoryNodeType;
  readonly title: string;
  readonly summary: string;
  readonly scope: string;
  readonly engagement_id: string | null;
  readonly mission_id: string | null;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly lifecycle_status: MemoryLifecycle;
  readonly confirmation_state: MemoryNode["confirmationState"];
  readonly version: number;
  readonly pinned: number;
  readonly expires_at: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly edge_count: number;
  readonly source_count: number;
  readonly outcome_tags_json: string;
}

interface MemorySourceProjectionRow extends Record<string, unknown> {
  readonly id: string;
  readonly sourceType: string;
  readonly sourceId: string;
  readonly sourceHash: string | null;
  readonly excerptRedacted: string | null;
  readonly acquiredAt: string;
  readonly createdAt: string;
  readonly originMissionId: string | null;
  readonly originMissionName: string | null;
  readonly originRunId: string | null;
  readonly originRunStatus: string | null;
  readonly originEngagementId: string | null;
  readonly originEngagementLabel: string | null;
  readonly artifactId: string | null;
  readonly evidenceId: string | null;
  readonly privateSourceReference: string | null;
  readonly artifactSourceLocator: string | null;
  readonly artifactRelativePath: string | null;
  readonly originCount: number;
}

interface MemorySourcePageRow {
  readonly id: string;
  readonly source_type: string;
  readonly source_id: string;
  readonly source_hash: string | null;
  readonly excerpt_redacted: string | null;
  readonly acquired_at: string;
  readonly created_at: string;
}

interface LegacySourceOriginRow {
  readonly source_reference: string;
  readonly source_path: string;
  readonly source_root_path: string;
  readonly engagement_label: string;
}

interface OperatorPreferenceProfileRow {
  readonly node_id: string;
  readonly operator_id: string;
  readonly preference_key: string;
  readonly value_json: string;
  readonly confirmation_state: "confirmed";
  readonly consent_policy: string;
  readonly version: number;
  readonly confirmed_at: string;
}

interface Cursor {
  readonly updatedAt: string;
  readonly id: string;
}

interface MemorySourceCursor {
  readonly nodeId: string;
  readonly acquiredAt: string;
  readonly sourceRecordId: string;
}

interface MemoryOriginCursor {
  readonly nodeId: string;
  readonly sourceRecordId: string;
  readonly offset: number;
}

class BrainApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly category: string,
    readonly remediation?: string,
  ) {
    super(message);
    this.name = "BrainApiError";
  }
}

function sendError(response: Response, error: unknown, id: string): void {
  const normalized = normalizeError(error);
  sendV2Error(response, id, {
    status: normalized.status,
    code: normalized.code,
    message: normalized.message,
    humanMessage: normalized.message,
    retryable: false,
    category: normalized.category,
    ...(normalized.remediation ? { remediation: normalized.remediation } : {}),
  });
}

function matches(message: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(message));
}

function normalizeError(error: unknown): BrainApiError {
  if (error instanceof BrainApiError) return error;
  if (error instanceof VaultSearchIndexIntegrityError) {
    return new BrainApiError(
      503,
      "vault_search_index_integrity_failed",
      "Canonical memory search failed its bounded incremental refresh; recovery stopped without rebuilding the global index",
      "data_integrity",
      "Run the dedicated database integrity workflow, inspect its receipt, and retry Vault reindex only after search health is restored.",
    );
  }
  if (error instanceof DuplicateVaultProjectionError) {
    return new BrainApiError(
      409,
      "vault_duplicate_projection",
      "Multiple managed paths still claim the same canonical memory node",
      "conflict",
      "Review the duplicate projection diagnostics, select one path deliberately, and retry recovery.",
    );
  }
  if (error instanceof VaultLastHealthyConnectionError) {
    return new BrainApiError(
      409,
      "vault_last_healthy_connection",
      "This is the last healthy Obsidian projection",
      "conflict",
      "Connect and round-trip verify a replacement first, or explicitly acknowledge that Obsidian projection will enter a controlled degraded state. Canonical Second Brain memory remains available in SQLite.",
    );
  }
  if (error instanceof VaultConnectionAlreadyDisconnectedError) {
    return new BrainApiError(
      409,
      "vault_connection_already_disconnected",
      "This Obsidian Vault projection is already disconnected",
      "conflict",
      "Refresh Vault status. The directory and notes remain intact and no further synchronization is scheduled.",
    );
  }
  if (error instanceof VaultConnectionVersionConflictError) {
    return new BrainApiError(
      409,
      "vault_connection_version_conflict",
      "The Obsidian vault connection changed before it could be disconnected",
      "conflict",
      "Refresh Vault status, review the current connection, then submit a new version-pinned request.",
    );
  }
  if (error instanceof AttackKnowledgeVaultScopeAmendmentConflictError) {
    return new BrainApiError(
      409,
      "attack_knowledge_vault_scope_amendment_conflict",
      "The Attack Knowledge Vault policy changed before the scope amendment completed",
      "conflict",
      "Refresh the Vault policy review, verify the same connection and path, then submit the newly hash-pinned amendment.",
    );
  }
  if (error instanceof ReusableMemorySafetyError) {
    return new BrainApiError(
      error.status,
      error.code,
      error.humanMessage,
      error.category,
      error.remediation,
    );
  }
  const message = error instanceof Error ? error.message : "Second Brain request failed";
  if (matches(message, [
    /^Memory (?:node|candidate) not found:/u,
    /^Context pack (?:item )?not found(?::|$)/u,
    /^Vault connection not found:/u,
    /^(?:Vault note|Vault attachment mission|Referenced vault attachment) does not exist$/u,
    /^Portable vault archive was not found$/u,
    /^Open vault conflict not found$/u,
  ])) {
    return new BrainApiError(404, "brain_resource_not_found", "The requested Second Brain resource was not found", "not_found");
  }
  if (matches(message, [
    /^Only pending candidates can be (?:confirmed|rejected)$/u,
    /^memory control policy version does not match;/u,
    /^Context pack memory changed after retrieval$/u,
    /^Updating an existing memory requires a version-aware sync operation$/u,
    /^Vault note version does not match the canonical memory version$/u,
    /^Projected vault attachment conflicts with a non-matching file$/u,
  ])) {
    return new BrainApiError(409, "brain_state_conflict", "The Second Brain resource changed or is no longer actionable", "conflict", "Refresh the record and retry against its current version.");
  }
  if (matches(message, [
    /^Cross-engagement memory edges are not permitted$/u,
    /^Obsidian synchronization is not permitted by the memory control policy$/u,
    /^Explicit filesystem permission is required$/u,
    /^Vault path escapes its configured root$/u,
    /^Vault is outside its configured root$/u,
    /^Vault note path traversal is not permitted$/u,
    /^Symbolic links are not permitted in managed vault paths$/u,
    /^Memory node type .* is private operational provenance and cannot be projected as reusable Vault knowledge$/u,
  ])) {
    return new BrainApiError(403, "memory_scope_denied", "The requested memory or vault operation is outside the authorized scope", "policy_denied");
  }
  if (/^Vault filesystem round-trip health check failed$/u.test(message)) {
    return new BrainApiError(
      503,
      "vault_round_trip_failed",
      "The selected vault path could not complete its write, read, rename, and delete health check",
      "dependency_unavailable",
      "Verify filesystem permissions and path health, then run the round-trip check again.",
    );
  }
  if (/^Configured vault is not an existing directory$/u.test(message)) {
    return new BrainApiError(
      503,
      "vault_connection_offline",
      "The configured Obsidian vault is offline or missing; recovery did not recreate it",
      "dependency_unavailable",
      "Restore the same vault path and filesystem permission, then test the connection before retrying recovery.",
    );
  }
  if (/^Vault connection version does not match;/u.test(message)) {
    return new BrainApiError(
      409,
      "vault_connection_version_conflict",
      "The Obsidian vault connection changed before recovery could be applied",
      "conflict",
      "Refresh Vault status and retry against the current connection version.",
    );
  }
  if (/^Vault connection is disconnected:/u.test(message)) {
    return new BrainApiError(
      409,
      "vault_connection_disconnected",
      "This Obsidian Vault projection is disconnected and cannot synchronize",
      "conflict",
      "Use a connected, health-verified Vault. The retired Vault files remain untouched.",
    );
  }
  if (error instanceof TypeError || error instanceof RangeError || matches(message, [
    /^(?:Stored|Canonical|Vault|Memory|Mission|Context pack|Edge|Node type|YAML|Obsidian note|Unsupported YAML|Duplicate YAML|Portable ZIP).*(?:invalid|malformed|required|must|does not match|missing|cannot change|exceeds|requires)/u,
  ])) {
    return new BrainApiError(400, "invalid_brain_request", "The Second Brain request is invalid", "invalid_input");
  }
  return new BrainApiError(
    500,
    "second_brain_internal_error",
    "Second Brain could not complete the request",
    "internal",
    "Use the trace ID to inspect structured logs before retrying.",
  );
}

function object(value: unknown, label = "request body"): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requiredText(value: unknown, label: string, maximum = 4_000): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new TypeError(`${label} must contain 1-${maximum} characters`);
  }
  return value.trim();
}

function optionalText(value: unknown, label: string, maximum = 4_000): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return requiredText(value, label, maximum);
}

function integer(value: unknown, fallback: number, minimum: number, maximum: number, label: string): number {
  if (value === undefined) return fallback;
  const parsed = typeof value === "string" && /^\d+$/u.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || Number(parsed) < minimum || Number(parsed) > maximum) {
    throw new RangeError(`${label} must be between ${minimum} and ${maximum}`);
  }
  return Number(parsed);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().filter((key) => record[key] !== undefined).map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function appendVaultAudit(database: SqliteDatabase, input: {
  readonly actor: string;
  readonly action:
    | "vault.health.verified"
    | "vault.connection.connected"
    | "vault.connection.disconnected"
    | "vault.attack_knowledge_preset.activated"
    | "vault.repair.completed"
    | "vault.reindex.completed";
  readonly resourceType: "vault_path_candidate" | "vault_connection";
  readonly resourceId: string;
  readonly reason: string;
  readonly details: Record<string, unknown>;
  readonly occurredAt: string;
}): string {
  const previous = database.prepare(
    "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
  ).get() as { record_hash: string } | undefined;
  const id = `audit-vault-${randomUUID()}`;
  const hashMaterial = {
    id,
    actor: input.actor,
    action: input.action,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    reason: input.reason,
    details: input.details,
    previousHash: previous?.record_hash ?? null,
    occurredAt: input.occurredAt,
  };
  const recordHash = sha256(canonical(hashMaterial));
  database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id, reason,
      details_json, previous_hash, record_hash, occurred_at
    ) VALUES (?, 'operator', ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    input.actor,
    input.action,
    input.resourceType,
    input.resourceId,
    input.reason,
    canonical(input.details),
    previous?.record_hash ?? null,
    recordHash,
    input.occurredAt,
  );
  return id;
}

function activeVaultHealthProofDetails(
  connection: VaultConnection,
  resolvedVaultPath: string,
  checks: {
    readonly write: true;
    readonly read: true;
    readonly rename: true;
    readonly delete: true;
  },
  extra: Readonly<Record<string, unknown>> = {},
): Record<string, unknown> {
  return {
    ...extra,
    connectionId: connection.id,
    connectionUpdatedAt: connection.updatedAt,
    pathFingerprint: activeVaultPathFingerprint(resolvedVaultPath),
    checks,
  };
}

function replayAccessFingerprint(actor: string, access: MemoryAccessPolicy): string {
  const allEngagements = access.allEngagements === true;
  return sha256(canonical({
    actor,
    maximumSensitivity: access.maximumSensitivity,
    allowGlobal: access.allowGlobal !== false,
    allEngagements,
    engagementIds: allEngagements ? [] : [...new Set(access.engagementIds ?? [])].sort(),
    missionIds: allEngagements ? [] : [...new Set(access.missionIds ?? [])].sort(),
  }));
}

function denyHiddenBrainResource(): never {
  // Authorization misses are intentionally indistinguishable from absent
  // Second Brain resources, including cached mutations and portable exports.
  throw new BrainApiError(
    404,
    "brain_resource_not_found",
    "The requested Second Brain resource was not found",
    "not_found",
  );
}

interface PortableExportAuthorization {
  readonly schemaVersion: typeof SCHEMA_VERSION;
  readonly actor: string;
  readonly accessFingerprint: string;
  readonly connectionId: string;
  readonly archiveName: string;
  readonly nodeIds: readonly string[];
  readonly nodeSnapshots: readonly {
    readonly nodeId: string;
    readonly version: number;
    readonly projectionHash: string;
  }[];
  readonly sha256: string;
  readonly byteSize: number;
  readonly createdAt: string;
}

function portableExportAuthorizationKey(connectionId: string, archiveName: string): string {
  return `brain.portable_export.authorization.${sha256(`${connectionId}:${archiveName}`)}`;
}

function validatedPortableArchiveName(value: unknown): string {
  const archiveName = requiredText(value, "portable archive name", 300);
  if (!/^ti-scale-brain-[A-Za-z0-9._-]+\.zip$/u.test(archiveName) || basename(archiveName) !== archiveName) {
    throw new TypeError("Portable vault archive name is invalid");
  }
  return archiveName;
}

function storePortableExportAuthorization(
  database: SqliteDatabase,
  authorization: PortableExportAuthorization,
): void {
  database.prepare(`
    INSERT INTO settings (key, value_json, sensitivity, updated_by, updated_at)
    VALUES (?, ?, 'private', ?, ?)
  `).run(
    portableExportAuthorizationKey(authorization.connectionId, authorization.archiveName),
    canonical(authorization),
    authorization.actor,
    authorization.createdAt,
  );
}

function requireAuthorizedPortableExport(
  database: SqliteDatabase,
  vault: ObsidianVaultBridge,
  connectionIdValue: unknown,
  archiveNameValue: unknown,
  actor: string,
  access: MemoryAccessPolicy,
): {
  archivePath: string;
  archiveName: string;
  expectedSha256: string;
  expectedByteSize: number;
} {
  const connectionId = requiredText(connectionIdValue, "vault connection ID", 256);
  assertIdentifier(connectionId, "vault connection ID");
  const archiveName = validatedPortableArchiveName(archiveNameValue);
  const row = database.prepare("SELECT value_json FROM settings WHERE key = ?").get(
    portableExportAuthorizationKey(connectionId, archiveName),
  ) as { value_json: string } | undefined;
  if (!row) denyHiddenBrainResource();

  let authorization: PortableExportAuthorization;
  try {
    authorization = JSON.parse(row.value_json) as PortableExportAuthorization;
  } catch {
    return denyHiddenBrainResource();
  }
  if (
    authorization.schemaVersion !== SCHEMA_VERSION ||
    authorization.actor !== actor ||
    authorization.connectionId !== connectionId ||
    authorization.archiveName !== archiveName ||
    authorization.accessFingerprint !== replayAccessFingerprint(actor, access) ||
    !Array.isArray(authorization.nodeIds) ||
    !Array.isArray(authorization.nodeSnapshots) ||
    typeof authorization.sha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(authorization.sha256) ||
    !Number.isSafeInteger(authorization.byteSize) ||
    authorization.byteSize < 0
  ) {
    denyHiddenBrainResource();
  }
  const nodeIds = [...new Set(authorization.nodeIds)];
  if (nodeIds.length !== authorization.nodeIds.length) denyHiddenBrainResource();
  if (authorization.nodeSnapshots.length !== nodeIds.length) denyHiddenBrainResource();
  for (const nodeId of nodeIds) {
    if (typeof nodeId !== "string") denyHiddenBrainResource();
    try {
      assertIdentifier(nodeId, "portable export memory node ID");
    } catch {
      denyHiddenBrainResource();
    }
  }
  let connectionAllowed: Set<string>;
  try {
    vault.assertVaultSyncAllowed();
    connectionAllowed = new Set(vault.exportableNodeIds(connectionId));
  } catch {
    return denyHiddenBrainResource();
  }
  if (nodeIds.some((nodeId) => !connectionAllowed.has(nodeId))) denyHiddenBrainResource();
  const connection = vault.requireConnection(connectionId);
  const portableNodeIds = new Set(nodeIds);
  const snapshotById = new Map<string, { version: number; projectionHash: string }>();
  for (const snapshot of authorization.nodeSnapshots) {
    if (
      !snapshot || typeof snapshot !== "object"
      || typeof snapshot.nodeId !== "string"
      || !Number.isSafeInteger(snapshot.version) || snapshot.version < 1
      || typeof snapshot.projectionHash !== "string"
      || !/^[a-f0-9]{64}$/u.test(snapshot.projectionHash)
      || snapshotById.has(snapshot.nodeId)
    ) denyHiddenBrainResource();
    snapshotById.set(snapshot.nodeId, {
      version: snapshot.version,
      projectionHash: snapshot.projectionHash,
    });
  }
  for (const nodeId of nodeIds) {
    const expected = snapshotById.get(nodeId);
    if (!expected) denyHiddenBrainResource();
    let rendered;
    try {
      rendered = vault.renderNode(nodeId, connection, portableNodeIds);
    } catch {
      return denyHiddenBrainResource();
    }
    if (rendered.node.version !== expected.version) denyHiddenBrainResource();
    const currentProjectionHash = sha256(rendered.text.replaceAll("\r\n", "\n"));
    if (currentProjectionHash !== expected.projectionHash) denyHiddenBrainResource();
  }
  const nodeAccess = accessSql("mn", access);
  for (let offset = 0; offset < nodeIds.length; offset += 500) {
    const batch = nodeIds.slice(offset, offset + 500);
    const row = database.prepare(`
      SELECT COUNT(*) AS count FROM memory_nodes mn
      WHERE mn.id IN (${batch.map(() => "?").join(",")})
        AND mn.lifecycle_status != 'forgotten'
        AND ${nodeAccess.sql}
    `).get(...batch, ...nodeAccess.params) as { count: number };
    if (Number(row.count) !== batch.length) denyHiddenBrainResource();
  }
  return {
    archivePath: vault.portableExportPath(connectionId, archiveName),
    archiveName: authorization.archiveName,
    expectedSha256: authorization.sha256,
    expectedByteSize: authorization.byteSize,
  };
}

async function verifyPortableExportIntegrity(authorized: {
  archivePath: string;
  expectedSha256: string;
  expectedByteSize: number;
}): Promise<void> {
  try {
    const metadata = statSync(authorized.archivePath);
    if (!metadata.isFile() || metadata.size !== authorized.expectedByteSize) denyHiddenBrainResource();
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(authorized.archivePath)) hash.update(chunk);
    if (hash.digest("hex") !== authorized.expectedSha256) denyHiddenBrainResource();
  } catch (error) {
    if (error instanceof BrainApiError) throw error;
    denyHiddenBrainResource();
  }
}

function validatedIdempotencyKey(request: Request): string {
  const value = request.get("Idempotency-Key")?.trim();
  if (!value || !IDEMPOTENCY_KEY.test(value)) {
    throw new BrainApiError(
      400,
      "idempotency_key_required",
      "A valid Idempotency-Key header is required for this memory mutation",
      "invalid_input",
      "Send a stable 8-200 character key and reuse it only for an identical request.",
    );
  }
  return value;
}

function actorAndAccess(
  request: Request,
  dependencies: SecondBrainRouterDependencies,
): { actor: string; access: MemoryAccessPolicy } {
  const actor = dependencies.resolveActor(request).trim();
  if (!actor) {
    throw new BrainApiError(401, "operator_identity_required", "An authenticated operator identity is required", "authentication_missing");
  }
  const access = dependencies.resolveAccess(request, actor);
  validateSensitivity(access.maximumSensitivity);
  for (const id of [...(access.engagementIds ?? []), ...(access.missionIds ?? [])]) {
    assertIdentifier(id, "memory access identifier");
  }
  return { actor, access };
}

function accessSql(alias: string, access: MemoryAccessPolicy): { sql: string; params: unknown[] } {
  const maximum = SENSITIVITY_ORDER.indexOf(access.maximumSensitivity);
  const sensitivities = SENSITIVITY_ORDER.slice(0, maximum + 1);
  const params: unknown[] = [...sensitivities];
  const scope: string[] = [];
  if (access.allowGlobal !== false) scope.push(`${alias}.scope = 'global'`);
  if (access.allEngagements) {
    scope.push(`${alias}.scope IN ('engagement', 'mission')`);
  } else {
    const engagements = [...new Set(access.engagementIds ?? [])];
    const missions = [...new Set(access.missionIds ?? [])];
    if (engagements.length > 0) {
      scope.push(`(${alias}.scope IN ('engagement', 'mission') AND ${alias}.engagement_id IN (${engagements.map(() => "?").join(",")}))`);
      params.push(...engagements);
    }
    if (missions.length > 0) {
      scope.push(`(${alias}.scope = 'mission' AND ${alias}.mission_id IN (${missions.map(() => "?").join(",")}))`);
      params.push(...missions);
    }
  }
  return {
    sql: `${alias}.sensitivity IN (${sensitivities.map(() => "?").join(",")}) AND (${scope.length > 0 ? scope.join(" OR ") : "0"})`,
    params,
  };
}

function accessibleConnectionNodeIds(
  database: SqliteDatabase,
  vault: ObsidianVaultBridge,
  connectionId: string,
  access: MemoryAccessPolicy,
): readonly string[] {
  const connectionIds = vault.exportableNodeIds(connectionId);
  if (connectionIds.length === 0) return [];
  const accessClause = accessSql("mn", access);
  const rows: Array<{ id: string; updated_at: string }> = [];
  for (let offset = 0; offset < connectionIds.length; offset += 400) {
    const batch = connectionIds.slice(offset, offset + 400);
    rows.push(...database.prepare(`
      SELECT mn.id, mn.updated_at FROM memory_nodes mn
      WHERE mn.id IN (${batch.map(() => "?").join(",")}) AND ${accessClause.sql}
    `).all(...batch, ...accessClause.params) as Array<{ id: string; updated_at: string }>);
  }
  rows.sort((left, right) => (
    right.updated_at.localeCompare(left.updated_at) || left.id.localeCompare(right.id)
  ));
  return rows.map((row) => row.id);
}

interface LegacyVaultProjectionApprovalRow {
  readonly migration_id: string;
  readonly reconciliation_hash: string;
  readonly projection_hash: string;
  readonly projected_node_ids_json: string;
  readonly migration_status: string | null;
  readonly current_reconciliation_hash: string | null;
}

/**
 * Historical engagement import and Vault publication are deliberately two
 * separate operations. A generic export must never become a second,
 * unreviewed publication path for imported nodes: each imported node needs a
 * completed approval whose reconciliation and exact projected-node selection
 * still match their immutable hashes.
 */
function assertLegacyVaultProjectionApproved(
  database: SqliteDatabase,
  connectionId: string,
  nodeIds: readonly string[],
): void {
  if (nodeIds.length === 0) return;
  const mappingTable = database.prepare(`
    SELECT 1 AS present FROM sqlite_master
    WHERE type = 'table' AND name = 'legacy_engagement_brain_nodes'
  `).get() as { present: number } | undefined;
  if (!mappingTable) return;

  const importedMappings: Array<{ migration_id: string; node_id: string }> = [];
  for (let offset = 0; offset < nodeIds.length; offset += 400) {
    const batch = nodeIds.slice(offset, offset + 400);
    importedMappings.push(...database.prepare(`
      SELECT migration_id, node_id FROM legacy_engagement_brain_nodes
      WHERE node_id IN (${batch.map(() => "?").join(",")})
      ORDER BY migration_id, node_id
    `).all(...batch) as Array<{ migration_id: string; node_id: string }>);
  }
  if (importedMappings.length === 0) return;

  const approvalColumns = database.prepare(
    "PRAGMA table_info(legacy_vault_projection_approvals)",
  ).all() as Array<{ name: string }>;
  if (!approvalColumns.some((column) => column.name === "projection_hash")) {
    throw new BrainApiError(
      409,
      "legacy_vault_projection_approval_required",
      "Imported engagement memories require an exact approved Vault projection before export",
      "policy_denied",
      "Run the legacy Vault projection preview, review its reconciliation and projection hashes, then approve that exact projection.",
    );
  }

  const migrationIds = [...new Set(importedMappings.map((item) => item.migration_id))];
  const approvals: LegacyVaultProjectionApprovalRow[] = [];
  for (let offset = 0; offset < migrationIds.length; offset += 300) {
    const batch = migrationIds.slice(offset, offset + 300);
    approvals.push(...database.prepare(`
      SELECT a.migration_id, a.reconciliation_hash, a.projection_hash,
        a.projected_node_ids_json, r.status AS migration_status,
        q.report_hash AS current_reconciliation_hash
      FROM legacy_vault_projection_approvals a
      LEFT JOIN legacy_migration_runs r ON r.id = a.migration_id
      LEFT JOIN legacy_migration_reconciliation q ON q.migration_id = a.migration_id
      WHERE a.connection_id = ? AND a.status = 'completed'
        AND a.completed_at IS NOT NULL
        AND a.migration_id IN (${batch.map(() => "?").join(",")})
    `).all(connectionId, ...batch) as LegacyVaultProjectionApprovalRow[]);
  }

  const approvedByMigration = new Map<string, Set<string>>();
  for (const approval of approvals) {
    if (
      approval.migration_status !== "completed"
      || approval.current_reconciliation_hash !== approval.reconciliation_hash
      || !/^[a-f0-9]{64}$/u.test(approval.reconciliation_hash)
      || !/^[a-f0-9]{64}$/u.test(approval.projection_hash)
    ) continue;
    let projectedNodeIds: unknown;
    try {
      projectedNodeIds = JSON.parse(approval.projected_node_ids_json);
    } catch {
      continue;
    }
    if (
      !Array.isArray(projectedNodeIds)
      || projectedNodeIds.some((nodeId) => typeof nodeId !== "string")
      || new Set(projectedNodeIds).size !== projectedNodeIds.length
      || sha256(canonical(projectedNodeIds)) !== approval.projection_hash
    ) continue;
    approvedByMigration.set(approval.migration_id, new Set(projectedNodeIds as string[]));
  }

  const unapproved = importedMappings.some((mapping) => (
    !approvedByMigration.get(mapping.migration_id)?.has(mapping.node_id)
  ));
  if (unapproved) {
    throw new BrainApiError(
      409,
      "legacy_vault_projection_approval_required",
      "Imported engagement memories require an exact approved Vault projection before export",
      "policy_denied",
      "Run the legacy Vault projection preview, review its reconciliation and projection hashes, then approve that exact projection.",
    );
  }
}

function vaultAuthorizationFingerprint(
  vault: ObsidianVaultBridge,
  connectionId: string,
  nodeIds: readonly string[],
): string {
  const connection = vault.requireConnection(connectionId);
  const policy = vault.memoryControlPolicy();
  return sha256(canonical({
    connectionId,
    syncScope: connection.syncScope,
    memoryControlVersion: policy.version,
    memoryEnabled: policy.enabled,
    obsidianSyncScope: policy.obsidianSyncScope,
    nodeIds: [...nodeIds],
  }));
}

function assertVaultAuthorizationReplay(
  database: SqliteDatabase,
  vault: ObsidianVaultBridge,
  connectionId: string,
  access: MemoryAccessPolicy,
  expectedFingerprint: string,
): void {
  const nodeIds = accessibleConnectionNodeIds(database, vault, connectionId, access);
  if (vaultAuthorizationFingerprint(vault, connectionId, nodeIds) !== expectedFingerprint) {
    // An idempotent replay must not return a success summary authorized under
    // an older Memory Control policy, connection scope, or caller scope.
    denyHiddenBrainResource();
  }
}

function canAccess(node: MemoryNode, access: MemoryAccessPolicy): boolean {
  if (SENSITIVITY_ORDER.indexOf(node.sensitivity) > SENSITIVITY_ORDER.indexOf(access.maximumSensitivity)) return false;
  if (node.scope.kind === "global") return access.allowGlobal !== false;
  if (access.allEngagements) return true;
  if (node.scope.kind === "engagement") return (access.engagementIds ?? []).includes(node.scope.engagementId!);
  return (access.missionIds ?? []).includes(node.scope.missionId!) || Boolean(
    node.scope.engagementId && (access.engagementIds ?? []).includes(node.scope.engagementId),
  );
}

function nodeSummary(row: NodeSummaryRow): NodeSummary {
  const parsedOutcomeTags = JSON.parse(row.outcome_tags_json) as unknown;
  if (
    !Array.isArray(parsedOutcomeTags)
    || parsedOutcomeTags.some((tag) => !isReusableKnowledgeOutcomeTag(tag))
  ) {
    throw new Error("Stored reusable knowledge outcome tags are malformed");
  }
  const selectedOutcomeTags = new Set(parsedOutcomeTags as ReusableKnowledgeOutcomeTag[]);
  return {
    id: row.id,
    nodeType: row.node_type,
    title: row.title,
    summary: row.summary,
    scope: deserializeScope(row.scope, row.engagement_id, row.mission_id),
    sensitivity: row.sensitivity,
    confidence: row.confidence,
    lifecycleStatus: row.lifecycle_status,
    confirmationState: row.confirmation_state,
    version: row.version,
    pinned: row.pinned === 1,
    ...(row.expires_at ? { expiresAt: row.expires_at } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    edgeCount: Number(row.edge_count),
    sourceCount: Number(row.source_count),
    outcomeTags: (["success", "failed"] as const).filter((tag) => selectedOutcomeTags.has(tag)),
  };
}

function nodeSummaries(database: SqliteDatabase, rows: readonly NodeSummaryRow[]): NodeSummary[] {
  const reported = new HistoricalReportedOutcomeService(database)
    .summaries(rows.map((row) => row.id));
  return rows.map((row) => {
    const summary = nodeSummary(row);
    const reportedOutcome = reported.get(row.id);
    return reportedOutcome ? { ...summary, reportedOutcome } : summary;
  });
}

const SUMMARY_COLUMNS = `
  mn.id, mn.node_type, mn.title, mn.summary, mn.scope, mn.engagement_id, mn.mission_id,
  mn.sensitivity, mn.confidence, mn.lifecycle_status, mn.confirmation_state,
  mn.version, mn.pinned, mn.expires_at, mn.created_at, mn.updated_at,
  (SELECT COUNT(*) FROM memory_edges_safe me WHERE me.source_node_id = mn.id OR me.target_node_id = mn.id) AS edge_count,
  (SELECT COUNT(*) FROM memory_sources ms WHERE ms.node_id = mn.id) AS source_count,
  COALESCE((
    SELECT json_group_array(classified.outcome_tag)
    FROM (
      SELECT DISTINCT outcome_link.outcome_tag
      FROM reusable_knowledge_outcome_links outcome_link
      WHERE outcome_link.memory_node_id = mn.id
      ORDER BY outcome_link.outcome_tag DESC
    ) classified
  ), '[]') AS outcome_tags_json
`;

function reusableKnowledgeOutcomeFilter(
  value: unknown,
): ReusableKnowledgeOutcomeTag | "unclassified" | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const normalized = requiredText(value, "outcome filter", 32);
  if (normalized === "unclassified" || isReusableKnowledgeOutcomeTag(normalized)) {
    return normalized;
  }
  throw new TypeError("outcome filter is invalid");
}

function appendReusableKnowledgeOutcomeFilter(
  clauses: string[],
  params: unknown[],
  alias: string,
  outcome: ReusableKnowledgeOutcomeTag | "unclassified" | undefined,
): void {
  if (!outcome) return;
  if (outcome === "unclassified") {
    clauses.push(`NOT EXISTS (
      SELECT 1 FROM reusable_knowledge_outcome_links outcome_filter
      WHERE outcome_filter.memory_node_id = ${alias}.id
    )`);
    return;
  }
  clauses.push(`EXISTS (
    SELECT 1 FROM reusable_knowledge_outcome_links outcome_filter
    WHERE outcome_filter.memory_node_id = ${alias}.id
      AND outcome_filter.outcome_tag = ?
  )`);
  params.push(outcome);
}

function historicalReportedOutcomeFilter(
  value: unknown,
): HistoricalReportedOutcomeClassification | "not_reported" | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const normalized = requiredText(value, "reported outcome filter", 32);
  if (normalized === "not_reported" || isHistoricalReportedOutcomeClassification(normalized)) {
    return normalized;
  }
  throw new TypeError("reported outcome filter is invalid");
}

function appendHistoricalReportedOutcomeFilter(
  clauses: string[],
  params: unknown[],
  alias: string,
  outcome: HistoricalReportedOutcomeClassification | "not_reported" | undefined,
): void {
  if (!outcome) return;
  if (outcome === "not_reported") {
    clauses.push(`NOT EXISTS (
      SELECT 1 FROM historical_reported_outcome_node_claims reported_filter
      WHERE reported_filter.memory_node_id = ${alias}.id
        AND reported_filter.policy_version = ?
    )`);
    params.push(HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION);
    return;
  }
  clauses.push(`EXISTS (
    SELECT 1 FROM historical_reported_outcome_node_claims reported_filter
    WHERE reported_filter.memory_node_id = ${alias}.id
      AND reported_filter.policy_version = ?
    GROUP BY reported_filter.memory_node_id
    HAVING CASE
      WHEN MAX(reported_filter.classification = 'mixed') = 1
        OR (MAX(reported_filter.classification = 'reported_success') = 1
          AND MAX(reported_filter.classification = 'reported_failure') = 1)
        THEN 'mixed'
      WHEN MAX(reported_filter.classification = 'reported_success') = 1
        THEN 'reported_success'
      WHEN MAX(reported_filter.classification = 'reported_failure') = 1
        THEN 'reported_failure'
      ELSE 'unknown'
    END = ?
  )`);
  params.push(HISTORICAL_REPORTED_OUTCOME_POLICY_VERSION, outcome);
}

function encodeCursor(row: Pick<NodeSummaryRow, "updated_at" | "id">): string {
  return Buffer.from(JSON.stringify({ updatedAt: row.updated_at, id: row.id }), "utf8").toString("base64url");
}

function decodeCursor(value: unknown): Cursor | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > 1_000) throw new RangeError("cursor is invalid");
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as Record<string, unknown>;
    if (typeof parsed.updatedAt !== "string" || Number.isNaN(Date.parse(parsed.updatedAt)) || typeof parsed.id !== "string") {
      throw new Error("invalid");
    }
    assertIdentifier(parsed.id, "cursor node ID");
    return { updatedAt: parsed.updatedAt, id: parsed.id };
  } catch {
    throw new RangeError("cursor is invalid");
  }
}

const MEMORY_SOURCE_DETAIL_LIMIT = 25;
const MEMORY_SOURCE_PAGE_MAXIMUM = 100;
const MEMORY_SOURCE_ORIGIN_LIMIT = 50;
const MEMORY_SOURCE_ORIGIN_MAXIMUM = 100;

function encodeMemorySourceCursor(
  nodeId: string,
  row: Pick<MemorySourcePageRow, "id" | "acquired_at">,
): string {
  return Buffer.from(JSON.stringify({
    nodeId,
    acquiredAt: row.acquired_at,
    sourceRecordId: row.id,
  }), "utf8").toString("base64url");
}

function decodeMemorySourceCursor(value: unknown, nodeId: string): MemorySourceCursor | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > 1_000) throw new RangeError("source cursor is invalid");
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as Record<string, unknown>;
    if (parsed.nodeId !== nodeId
      || typeof parsed.acquiredAt !== "string"
      || Number.isNaN(Date.parse(parsed.acquiredAt))
      || typeof parsed.sourceRecordId !== "string") {
      throw new Error("invalid");
    }
    assertIdentifier(parsed.sourceRecordId, "source cursor record ID");
    return {
      nodeId,
      acquiredAt: parsed.acquiredAt,
      sourceRecordId: parsed.sourceRecordId,
    };
  } catch {
    throw new RangeError("source cursor is invalid");
  }
}

function encodeMemoryOriginCursor(nodeId: string, sourceRecordId: string, offset: number): string {
  return Buffer.from(JSON.stringify({ nodeId, sourceRecordId, offset }), "utf8").toString("base64url");
}

function decodeMemoryOriginCursor(
  value: unknown,
  nodeId: string,
  sourceRecordId: string,
): MemoryOriginCursor | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > 1_000) throw new RangeError("origin cursor is invalid");
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as Record<string, unknown>;
    if (parsed.nodeId !== nodeId
      || parsed.sourceRecordId !== sourceRecordId
      || !Number.isSafeInteger(parsed.offset)
      || Number(parsed.offset) < 1
      || Number(parsed.offset) > 10_000_000) {
      throw new Error("invalid");
    }
    return { nodeId, sourceRecordId, offset: Number(parsed.offset) };
  } catch {
    throw new RangeError("origin cursor is invalid");
  }
}

function ftsQuery(source: string): string | undefined {
  const tokens = source.normalize("NFKC").match(/[\p{L}\p{N}_-]+/gu)?.slice(0, 24) ?? [];
  return tokens.length > 0 ? tokens.map((token) => `"${token.replaceAll('"', '""')}"`).join(" OR ") : undefined;
}

function executeIdempotent<T>(
  database: SqliteDatabase,
  actor: string,
  access: MemoryAccessPolicy,
  key: string,
  requestBody: unknown,
  operation: () => T,
  authorizeReplay: (response: T) => void,
): T {
  const settingKey = `idempotency.brain.${sha256(`${actor}:${key}`)}`;
  const requestHash = sha256(canonical(requestBody));
  const accessFingerprint = replayAccessFingerprint(actor, access);
  return inImmediateTransaction(database, () => {
    const stored = database.prepare("SELECT value_json FROM settings WHERE key = ?").get(settingKey) as { value_json: string } | undefined;
    if (stored) {
      const value = JSON.parse(stored.value_json) as {
        requestHash: string;
        accessFingerprint?: string;
        state?: string;
        response: T;
      };
      if (value.requestHash !== requestHash) {
        throw new BrainApiError(
          409,
          "idempotency_key_reused",
          "Idempotency key was already used for a different memory mutation",
          "conflict",
          "Generate a new key for the changed request.",
        );
      }
      if (value.state === "revoked") denyHiddenBrainResource();
      authorizeReplay(value.response);
      if (value.accessFingerprint !== accessFingerprint) denyHiddenBrainResource();
      return value.response;
    }
    const response = operation();
    const now = new Date().toISOString();
    database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, updated_by, updated_at)
      VALUES (?, ?, 'private', ?, ?)
    `).run(settingKey, canonical({ requestHash, accessFingerprint, response }), actor, now);
    return response;
  });
}

async function executeIdempotentAsync<T>(
  database: SqliteDatabase,
  actor: string,
  access: MemoryAccessPolicy,
  key: string,
  requestBody: unknown,
  operation: () => Promise<T>,
  authorizeReplay: (response: T) => void | Promise<void>,
): Promise<T> {
  const settingKey = `idempotency.brain.${sha256(`${actor}:${key}`)}`;
  const requestHash = sha256(canonical(requestBody));
  const accessFingerprint = replayAccessFingerprint(actor, access);
  const pendingValue = canonical({ requestHash, accessFingerprint, state: "pending" });
  const stored = inImmediateTransaction(database, (): { response: T } | undefined => {
    const row = database.prepare("SELECT value_json FROM settings WHERE key = ?").get(settingKey) as { value_json: string } | undefined;
    if (row) {
      const value = JSON.parse(row.value_json) as {
        requestHash: string;
        accessFingerprint?: string;
        state?: string;
        response?: T;
      };
      if (value.requestHash !== requestHash) {
        throw new BrainApiError(409, "idempotency_key_reused", "Idempotency key was already used for a different memory mutation", "conflict", "Generate a new key for the changed request.");
      }
      if (value.state === "revoked") denyHiddenBrainResource();
      if (value.state === "complete" && value.response !== undefined) {
        if (value.accessFingerprint !== accessFingerprint) denyHiddenBrainResource();
        return { response: value.response };
      }
      if (value.accessFingerprint !== accessFingerprint) denyHiddenBrainResource();
      throw new BrainApiError(409, "brain_mutation_in_progress", "An identical memory mutation is already in progress", "conflict", "Wait for the original request to complete before retrying.");
    }
    const now = new Date().toISOString();
    database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, updated_by, updated_at)
      VALUES (?, ?, 'private', ?, ?)
    `).run(settingKey, pendingValue, actor, now);
    return undefined;
  });
  if (stored !== undefined) {
    await authorizeReplay(stored.response);
    return stored.response;
  }
  try {
    const response = await operation();
    database.prepare(`
      UPDATE settings SET value_json = ?, updated_by = ?, updated_at = ? WHERE key = ?
    `).run(canonical({ requestHash, accessFingerprint, state: "complete", response }), actor, new Date().toISOString(), settingKey);
    return response;
  } catch (error) {
    database.prepare("DELETE FROM settings WHERE key = ? AND value_json = ?").run(
      settingKey,
      pendingValue,
    );
    throw error;
  }
}

function requireAccessibleNode(
  repository: MemoryRepository,
  id: string,
  access: MemoryAccessPolicy,
  includeForgotten = false,
): MemoryNode {
  assertIdentifier(id, "memory node ID");
  const node = repository.getNode(id, includeForgotten);
  // A policy miss is intentionally indistinguishable from an absent record.
  if (!node || !canAccess(node, access)) throw new BrainApiError(404, "memory_node_not_found", "Memory node was not found", "not_found");
  return node;
}

function listNodes(
  database: SqliteDatabase,
  access: MemoryAccessPolicy,
  query: Record<string, unknown>,
): { schemaVersion: typeof SCHEMA_VERSION; items: NodeSummary[]; nextCursor: string | null; totalReturned: number } {
  const limit = integer(query.limit, 50, 1, 100, "node page limit");
  const cursor = decodeCursor(query.cursor);
  const accessClause = accessSql("mn", access);
  const clauses = [accessClause.sql];
  const params: unknown[] = [...accessClause.params];
  const search = typeof query.query === "string" && query.query.trim() ? ftsQuery(query.query) : undefined;
  let from = "memory_nodes mn";
  if (search) {
    from = "memory_nodes_fts JOIN memory_nodes mn ON mn.rowid = memory_nodes_fts.rowid";
    clauses.push("memory_nodes_fts MATCH ?");
    params.push(search);
  }
  if (query.nodeType !== undefined) {
    clauses.push("mn.node_type = ?");
    params.push(validateNodeType(query.nodeType));
  }
  if (query.status !== undefined) {
    const status = validateLifecycle(query.status);
    clauses.push("mn.lifecycle_status = ?");
    params.push(status);
  } else {
    clauses.push("mn.lifecycle_status != 'forgotten'");
  }
  if (query.scope !== undefined) {
    const scope = String(query.scope);
    if (!["global", "engagement", "mission"].includes(scope)) throw new TypeError("scope filter is invalid");
    clauses.push("mn.scope = ?");
    params.push(scope);
  }
  if (query.engagementId !== undefined) {
    const id = requiredText(query.engagementId, "engagement filter", 256);
    clauses.push("mn.engagement_id = ?");
    params.push(id);
  }
  if (query.missionId !== undefined) {
    const id = requiredText(query.missionId, "mission filter", 256);
    clauses.push("mn.mission_id = ?");
    params.push(id);
  }
  if (query.sensitivity !== undefined) {
    const sensitivity = validateSensitivity(query.sensitivity);
    if (SENSITIVITY_ORDER.indexOf(sensitivity) > SENSITIVITY_ORDER.indexOf(access.maximumSensitivity)) {
      throw new BrainApiError(403, "memory_sensitivity_denied", "Requested sensitivity exceeds operator access", "policy_denied");
    }
    clauses.push("mn.sensitivity = ?");
    params.push(sensitivity);
  }
  appendReusableKnowledgeOutcomeFilter(
    clauses,
    params,
    "mn",
    reusableKnowledgeOutcomeFilter(query.outcome),
  );
  appendHistoricalReportedOutcomeFilter(
    clauses,
    params,
    "mn",
    historicalReportedOutcomeFilter(query.reportedOutcome),
  );
  clauses.push("(mn.expires_at IS NULL OR mn.expires_at > ? OR mn.lifecycle_status = 'stale')");
  params.push(new Date().toISOString());
  if (cursor) {
    clauses.push("(mn.updated_at < ? OR (mn.updated_at = ? AND mn.id < ?))");
    params.push(cursor.updatedAt, cursor.updatedAt, cursor.id);
  }
  const rows = database.prepare(`
    SELECT ${SUMMARY_COLUMNS}
    FROM ${from}
    WHERE ${clauses.join(" AND ")}
    ORDER BY mn.updated_at DESC, mn.id DESC
    LIMIT ?
  `).all(...params, limit + 1) as NodeSummaryRow[];
  const page = rows.slice(0, limit);
  return {
    schemaVersion: SCHEMA_VERSION,
    items: nodeSummaries(database, page),
    nextCursor: rows.length > limit && page.length > 0 ? encodeCursor(page.at(-1)!) : null,
    totalReturned: page.length,
  };
}

function summaryForNode(database: SqliteDatabase, id: string): NodeSummary | undefined {
  const row = database.prepare(`SELECT ${SUMMARY_COLUMNS} FROM memory_nodes mn WHERE mn.id = ?`).get(id) as NodeSummaryRow | undefined;
  return row ? nodeSummaries(database, [row])[0] : undefined;
}

function edgePayload(edge: MemoryEdge) {
  return {
    id: edge.id,
    sourceNodeId: edge.sourceNodeId,
    targetNodeId: edge.targetNodeId,
    edgeType: edge.edgeType,
    title: edge.title,
    summary: edge.summary,
    confidence: edge.confidence,
    lifecycleStatus: edge.lifecycleStatus,
    explanation: edge.explanation,
  };
}

function graphTimestamp(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const timestamp = requiredText(value, label, 40);
  if (!Number.isFinite(Date.parse(timestamp))) throw new TypeError(`${label} must be an ISO timestamp`);
  return new Date(timestamp).toISOString();
}

function graphFilters(query: Record<string, unknown>, access: MemoryAccessPolicy): GraphFilters {
  const preset = query.preset === undefined ? undefined : requiredText(query.preset, "graph preset", 32) as GraphPreset;
  if (preset && !Object.prototype.hasOwnProperty.call(GRAPH_PRESETS, preset)) throw new TypeError("graph preset is invalid");
  const nodeType = query.nodeType === undefined ? undefined : validateNodeType(query.nodeType);
  const selectedEdgeType = query.edgeType === undefined ? undefined : validateEdgeType(query.edgeType);
  const scope = query.scope === undefined ? undefined : String(query.scope) as MemoryScope["kind"];
  if (scope && !["global", "engagement", "mission"].includes(scope)) throw new TypeError("graph scope filter is invalid");
  const engagementId = optionalText(query.engagementId, "graph engagement filter", 256);
  if (engagementId) assertIdentifier(engagementId, "graph engagement filter");
  const lifecycle = query.status === undefined ? undefined : validateLifecycle(query.status);
  if (lifecycle === "forgotten") throw new TypeError("forgotten memories cannot be graphed");
  const sensitivity = query.sensitivity === undefined ? undefined : validateSensitivity(query.sensitivity);
  if (sensitivity && SENSITIVITY_ORDER.indexOf(sensitivity) > SENSITIVITY_ORDER.indexOf(access.maximumSensitivity)) {
    throw new BrainApiError(403, "memory_sensitivity_denied", "Requested sensitivity exceeds operator access", "policy_denied");
  }
  let minConfidence: number | undefined;
  if (query.minConfidence !== undefined) {
    const parsed = typeof query.minConfidence === "string" ? Number(query.minConfidence) : query.minConfidence;
    minConfidence = validateConfidence(parsed);
  }
  const updatedAfter = graphTimestamp(query.updatedAfter, "graph start date");
  const updatedBefore = graphTimestamp(query.updatedBefore, "graph end date");
  const outcome = reusableKnowledgeOutcomeFilter(query.outcome);
  const reportedOutcome = historicalReportedOutcomeFilter(query.reportedOutcome);
  if (updatedAfter && updatedBefore && updatedAfter > updatedBefore) throw new TypeError("graph start date must not be after end date");
  return {
    ...(nodeType ? { nodeType } : {}),
    ...(selectedEdgeType ? { edgeTypes: [selectedEdgeType] } : preset ? { edgeTypes: GRAPH_PRESETS[preset].edgeTypes } : {}),
    ...(selectedEdgeType ? { requireEdgeMatch: true } : {}),
    ...(scope ? { scope } : {}),
    ...(engagementId ? { engagementId } : {}),
    ...(lifecycle ? { lifecycle } : {}),
    ...(sensitivity ? { sensitivity } : {}),
    ...(minConfidence !== undefined ? { minConfidence } : {}),
    ...(updatedAfter ? { updatedAfter } : {}),
    ...(updatedBefore ? { updatedBefore } : {}),
    ...(preset ? { preset } : {}),
    ...(outcome ? { outcome } : {}),
    ...(reportedOutcome ? { reportedOutcome } : {}),
  };
}

function appendGraphNodeFilters(
  clauses: string[],
  params: unknown[],
  filters: GraphFilters,
  alias: string,
): void {
  if (filters.preset) {
    const nodeTypes = GRAPH_PRESETS[filters.preset].nodeTypes;
    clauses.push(`${alias}.node_type IN (${nodeTypes.map(() => "?").join(",")})`);
    params.push(...nodeTypes);
  }
  if (filters.nodeType) {
    clauses.push(`${alias}.node_type = ?`);
    params.push(filters.nodeType);
  }
  if (filters.scope) {
    clauses.push(`${alias}.scope = ?`);
    params.push(filters.scope);
  }
  if (filters.engagementId) {
    clauses.push(`${alias}.engagement_id = ?`);
    params.push(filters.engagementId);
  }
  if (filters.lifecycle) {
    clauses.push(`${alias}.lifecycle_status = ?`);
    params.push(filters.lifecycle);
  }
  if (filters.sensitivity) {
    clauses.push(`${alias}.sensitivity = ?`);
    params.push(filters.sensitivity);
  }
  if (filters.minConfidence !== undefined) {
    clauses.push(`${alias}.confidence >= ?`);
    params.push(filters.minConfidence);
  }
  if (filters.updatedAfter) {
    clauses.push(`${alias}.updated_at >= ?`);
    params.push(filters.updatedAfter);
  }
  if (filters.updatedBefore) {
    clauses.push(`${alias}.updated_at <= ?`);
    params.push(filters.updatedBefore);
  }
  appendReusableKnowledgeOutcomeFilter(clauses, params, alias, filters.outcome);
  appendHistoricalReportedOutcomeFilter(clauses, params, alias, filters.reportedOutcome);
  if (filters.requireEdgeMatch && filters.edgeTypes?.length) {
    clauses.push(`EXISTS (
      SELECT 1 FROM memory_edges_safe graph_filter_edge
      WHERE (graph_filter_edge.source_node_id = ${alias}.id OR graph_filter_edge.target_node_id = ${alias}.id)
        AND graph_filter_edge.edge_type IN (${filters.edgeTypes.map(() => "?").join(",")})
        AND graph_filter_edge.lifecycle_status != 'forgotten'
        AND (graph_filter_edge.expires_at IS NULL OR graph_filter_edge.expires_at > ?)
    )`);
    params.push(...filters.edgeTypes, new Date().toISOString());
  }
}

/**
 * The primary reusable-knowledge canvas is the global-scope query emitted by
 * the V2 client. Its unfiltered lifecycle boundary is intentionally narrower
 * than a provenance/history view: operator-confirmed and evidence-verified
 * memories are visible, while candidates, disputed/stale records, and
 * forgotten records require an explicit lifecycle/history view.
 *
 * A provenance query has no scope filter and retains the broader active-state
 * boundary so an operator can still inspect disputed and stale history. An
 * explicit lifecycle filter always wins in appendGraphNodeFilters.
 */
function defaultGraphLifecycleClause(filters: GraphFilters, alias: string): string {
  return filters.scope === "global" && !filters.engagementId
    ? `${alias}.lifecycle_status IN ('confirmed', 'verified')`
    : `${alias}.lifecycle_status IN ('confirmed', 'verified', 'disputed', 'stale')`;
}

function accessibleGraphNodeIds(
  database: SqliteDatabase,
  candidateIds: readonly string[],
  access: MemoryAccessPolicy,
  filters: GraphFilters,
  now: string,
): readonly string[] {
  if (candidateIds.length === 0) return [];
  const accessible = new Set<string>();
  for (let offset = 0; offset < candidateIds.length; offset += 400) {
    const batch = candidateIds.slice(offset, offset + 400);
    const accessClause = accessSql("mn", access);
    const clauses = [
      `mn.id IN (${batch.map(() => "?").join(",")})`,
      accessClause.sql,
      ...(filters.lifecycle ? [] : [defaultGraphLifecycleClause(filters, "mn")]),
      "(mn.expires_at IS NULL OR mn.expires_at > ? OR mn.lifecycle_status = 'stale')",
    ];
    const params: unknown[] = [...batch, ...accessClause.params, now];
    appendGraphNodeFilters(clauses, params, filters, "mn");
    const rows = database.prepare(`
      SELECT mn.id FROM memory_nodes mn
      WHERE ${clauses.join(" AND ")}
    `).all(...params) as Array<{ id: string }>;
    rows.forEach((row) => accessible.add(row.id));
  }
  // Preserve discovery order so increasing the render limit adds nodes to the
  // existing local segment instead of reshuffling it.
  return candidateIds.filter((id) => accessible.has(id));
}

function localGraphNodeIds(
  database: SqliteDatabase,
  rootNodeId: string,
  access: MemoryAccessPolicy,
  filters: GraphFilters,
  depth: number,
  now: string,
): readonly string[] {
  const discovered = [rootNodeId];
  const seen = new Set(discovered);
  let frontier = [rootNodeId];
  for (let level = 1; level <= depth && frontier.length > 0; level += 1) {
    const candidates: string[] = [];
    const candidateSet = new Set<string>();
    for (let offset = 0; offset < frontier.length; offset += 300) {
      const batch = frontier.slice(offset, offset + 300);
      const placeholders = batch.map(() => "?").join(",");
      const edgeTypeClause = filters.edgeTypes?.length
        ? `AND edge_type IN (${filters.edgeTypes.map(() => "?").join(",")})`
        : "";
      const rows = database.prepare(`
        SELECT source_node_id, target_node_id FROM memory_edges_safe
        WHERE lifecycle_status IN ('confirmed', 'verified')
          AND (expires_at IS NULL OR expires_at > ?)
          ${edgeTypeClause}
          AND (source_node_id IN (${placeholders}) OR target_node_id IN (${placeholders}))
        ORDER BY confidence DESC, updated_at DESC, id ASC
      `).all(now, ...(filters.edgeTypes ?? []), ...batch, ...batch) as Array<{
        source_node_id: string;
        target_node_id: string;
      }>;
      for (const row of rows) {
        for (const id of [row.source_node_id, row.target_node_id]) {
          if (!seen.has(id) && !candidateSet.has(id)) {
            candidateSet.add(id);
            candidates.push(id);
          }
        }
      }
    }
    frontier = [...accessibleGraphNodeIds(database, candidates, access, filters, now)];
    for (const id of frontier) {
      seen.add(id);
      discovered.push(id);
    }
  }
  return discovered;
}

/**
 * Global graph pages are a semantic overview, not a degree leaderboard. A
 * round-robin rank across these stable groups keeps both attack-knowledge
 * hemispheres populated while still preferring pinned, highly connected, and
 * recent memories inside each group. Mission/runtime provenance remains
 * available, but cannot crowd every reusable technology or procedure out of a
 * bounded first page.
 */
const GRAPH_SEMANTIC_CLUSTER_SQL = `CASE
  WHEN mn.node_type IN ('operator', 'preference') THEN 'operator'
  WHEN mn.node_type IN ('mission', 'run', 'plan', 'phase', 'step', 'target', 'asset', 'entity', 'decision') THEN 'provenance'
  WHEN mn.node_type = 'agent' THEN 'agent'
  WHEN mn.node_type IN (
    'tactic', 'technique', 'procedure', 'cve', 'advisory', 'cwe', 'misconfiguration',
    'attack_vector', 'attack_tactic', 'attack_technique', 'attack_procedure',
    'procedure_version', 'prerequisite', 'attribute'
  ) THEN 'attack'
  WHEN mn.node_type IN ('tool', 'mcp_capability', 'script_artifact', 'tool_artifact') THEN 'tool'
  WHEN mn.node_type IN (
    'evidence', 'finding', 'artifact', 'report', 'source', 'discovery_pattern',
    'fingerprint_pattern', 'evidence_pattern', 'validation_pattern', 'health_check'
  ) THEN 'evidence'
  WHEN mn.node_type IN (
    'failure', 'failure_mode', 'recovery', 'outcome', 'alternative', 'detection',
    'remediation', 'operational_hazard', 'target_state_transition', 'recovery_pattern'
  ) THEN 'failure'
  WHEN mn.node_type IN ('lesson', 'evaluation', 'strategy', 'research', 'attack_lesson') THEN 'lesson'
  ELSE 'technology'
END`;

const GRAPH_SEMANTIC_CLUSTER_ORDER_SQL = `CASE semantic_cluster
  WHEN 'technology' THEN 1
  WHEN 'evidence' THEN 2
  WHEN 'attack' THEN 3
  WHEN 'tool' THEN 4
  WHEN 'lesson' THEN 5
  WHEN 'failure' THEN 6
  WHEN 'provenance' THEN 7
  WHEN 'agent' THEN 8
  WHEN 'operator' THEN 9
  ELSE 10
END`;

function graph(
  database: SqliteDatabase,
  repository: MemoryRepository,
  access: MemoryAccessPolicy,
  query: Record<string, unknown>,
) {
  const view = typeof query.view === "string" ? query.view : "global";
  if (!["global", "local", "mission", "operator"].includes(view)) throw new TypeError("graph view is invalid");
  // The client expands a bounded graph in 250-node increments. Keep the hard
  // ceiling modest enough for predictable canvas work, while allowing those
  // progressive requests to succeed instead of failing after the first page.
  const limit = integer(query.limit, 150, 1, 1_000, "graph node limit");
  const depth = integer(query.depth, 1, 0, 2, "graph depth");
  const filters = graphFilters(query, access);
  const selected = new Set<string>();
  const now = new Date().toISOString();
  let rootNodeId: string | undefined;
  let availableNodeCount = 0;
  let truncated = false;

  if (view === "local") {
    rootNodeId = requiredText(query.nodeId, "local graph node ID", 256);
    requireAccessibleNode(repository, rootNodeId, access);
    const availableIds = localGraphNodeIds(database, rootNodeId, access, filters, depth, now);
    availableNodeCount = availableIds.length;
    availableIds.slice(0, limit).forEach((id) => selected.add(id));
    truncated = availableNodeCount > selected.size;
  } else {
    const accessClause = accessSql("mn", access);
    const clauses = [
      accessClause.sql,
      ...(filters.lifecycle ? [] : [defaultGraphLifecycleClause(filters, "mn")]),
      "(mn.expires_at IS NULL OR mn.expires_at > ? OR mn.lifecycle_status = 'stale')",
    ];
    const params: unknown[] = [...accessClause.params];
    params.push(now);
    appendGraphNodeFilters(clauses, params, filters, "mn");
    if (view === "mission") {
      const missionId = requiredText(query.missionId, "mission graph ID", 256);
      clauses.push("(mn.mission_id = ? OR (mn.node_type = 'mission' AND mn.id = ?))");
      params.push(missionId, missionId);
    } else if (view === "operator") {
      clauses.push("mn.node_type IN ('operator', 'preference')");
    }
    const rows = database.prepare(`
      WITH live_edges AS MATERIALIZED (
        SELECT source_node_id, target_node_id FROM memory_edges_safe
        WHERE lifecycle_status != 'forgotten'
          AND (expires_at IS NULL OR expires_at > ?)
      ), edge_degree AS MATERIALIZED (
        SELECT node_id, COUNT(*) AS degree FROM (
          SELECT source_node_id AS node_id FROM live_edges
          UNION ALL
          SELECT target_node_id AS node_id FROM live_edges
        ) GROUP BY node_id
      ), ranked_nodes AS MATERIALIZED (
        SELECT mn.id, COALESCE(edge_degree.degree, 0) AS degree,
          COUNT(*) OVER () AS available_node_count,
          ${GRAPH_SEMANTIC_CLUSTER_SQL} AS semantic_cluster,
          ROW_NUMBER() OVER (
            PARTITION BY ${GRAPH_SEMANTIC_CLUSTER_SQL}
            ORDER BY mn.pinned DESC, COALESCE(edge_degree.degree, 0) DESC,
              mn.updated_at DESC, mn.id ASC
          ) AS semantic_rank
        FROM memory_nodes mn
        LEFT JOIN edge_degree ON edge_degree.node_id = mn.id
        WHERE ${clauses.join(" AND ")}
      )
      SELECT id, degree, available_node_count
      FROM ranked_nodes
      ORDER BY semantic_rank ASC, ${GRAPH_SEMANTIC_CLUSTER_ORDER_SQL}, degree DESC, id ASC
      LIMIT ?
    `).all(now, ...params, limit) as Array<{ id: string; degree: number; available_node_count: number }>;
    availableNodeCount = Number(rows[0]?.available_node_count ?? 0);
    truncated = availableNodeCount > rows.length;
    rows.forEach((row) => selected.add(row.id));
  }

  const selectedIds = [...selected];
  const selectedRows = selectedIds.length === 0 ? [] : database.prepare(`
    SELECT ${SUMMARY_COLUMNS} FROM memory_nodes mn
    WHERE mn.id IN (${selectedIds.map(() => "?").join(",")})
  `).all(...selectedIds) as NodeSummaryRow[];
  const summaryById = new Map(nodeSummaries(database, selectedRows).map((item) => [item.id, item]));
  const summaries = selectedIds.flatMap((id) => {
    const item = summaryById.get(id);
    return item ? [item] : [];
  });
  let edges: ReturnType<typeof edgePayload>[] = [];
  if (selected.size > 0) {
    const ids = [...selected];
    const placeholders = ids.map(() => "?").join(",");
    const edgeTypeClause = filters.edgeTypes?.length ? `AND edge_type IN (${filters.edgeTypes.map(() => "?").join(",")})` : "";
    const edgeRows = database.prepare(`
      SELECT id, source_node_id, target_node_id, edge_type, title, summary,
        confidence, lifecycle_status, explanation
      FROM memory_edges_safe
      WHERE source_node_id IN (${placeholders}) AND target_node_id IN (${placeholders})
        AND lifecycle_status != 'forgotten' AND (expires_at IS NULL OR expires_at > ?)
        ${edgeTypeClause}
      ORDER BY confidence DESC, updated_at DESC LIMIT 1000
    `).all(...ids, ...ids, now, ...(filters.edgeTypes ?? [])) as Array<{
      id: string;
      source_node_id: string;
      target_node_id: string;
      edge_type: MemoryEdge["edgeType"];
      title: string;
      summary: string;
      confidence: number;
      lifecycle_status: MemoryEdge["lifecycleStatus"];
      explanation: string;
    }>;
    // The selected node set has already passed the access policy. Project the
    // edge rows directly instead of calling listEdges once per edge (an N+1
    // traversal that became quadratic around highly connected graph roots).
    edges = edgeRows.map((edge) => ({
      id: edge.id,
      sourceNodeId: edge.source_node_id,
      targetNodeId: edge.target_node_id,
      edgeType: edge.edge_type,
      title: edge.title,
      summary: edge.summary,
      confidence: edge.confidence,
      lifecycleStatus: edge.lifecycle_status,
      explanation: edge.explanation,
    }));
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    view,
    ...(rootNodeId ? { rootNodeId } : {}),
    nodes: summaries,
    edges,
    availableNodeCount,
    truncated,
  };
}

function canAccessMission(database: SqliteDatabase, missionId: string | null, access: MemoryAccessPolicy): boolean {
  if (!missionId) return access.allowGlobal !== false;
  if (access.allEngagements || (access.missionIds ?? []).includes(missionId)) return true;
  const mission = database.prepare("SELECT engagement_id FROM missions WHERE id = ?").get(missionId) as { engagement_id: string | null } | undefined;
  return Boolean(mission?.engagement_id && (access.engagementIds ?? []).includes(mission.engagement_id));
}

function parseStoredPreferenceValue(value: string): {
  value: Record<string, unknown>;
  appliesTo: string[];
} {
  const stored = object(JSON.parse(value), "stored operator preference");
  const nested = stored.value === undefined
    ? stored
    : object(stored.value, "stored operator preference value");
  const appliesTo = Array.isArray(stored.appliesTo)
    ? stored.appliesTo.map((item) => requiredText(item, "operator preference applicability", 120))
    : [];
  return { value: nested, appliesTo: [...new Set(appliesTo)] };
}

function listOperatorPreferences(
  database: SqliteDatabase,
  repository: MemoryRepository,
  actorId: string,
  access: MemoryAccessPolicy,
) {
  const accessClause = accessSql("mn", access);
  const rows = database.prepare(`
    SELECT pp.source_node_id AS node_id, pp.operator_id, pp.preference_key,
      pp.value_json, pp.confirmation_state, pp.consent_policy, pp.version,
      pp.confirmed_at
    FROM preference_profiles pp
    JOIN memory_nodes mn ON mn.id = pp.source_node_id
    WHERE pp.operator_id = ?
      AND pp.confirmation_state = 'confirmed'
      AND pp.confirmed_at IS NOT NULL
      AND mn.node_type = 'preference'
      AND mn.confirmation_state = 'confirmed'
      AND mn.lifecycle_status IN ('confirmed', 'verified')
      AND (mn.expires_at IS NULL OR mn.expires_at > ?)
      AND ${accessClause.sql}
      AND NOT EXISTS (
        SELECT 1 FROM preference_profiles newer
        WHERE newer.operator_id = pp.operator_id
          AND newer.scope = pp.scope
          AND newer.engagement_id IS pp.engagement_id
          AND newer.mission_type IS pp.mission_type
          AND newer.preference_key = pp.preference_key
          AND newer.version > pp.version
      )
    ORDER BY pp.confirmed_at DESC, pp.preference_key ASC, pp.source_node_id ASC
    LIMIT 100
  `).all(actorId, new Date().toISOString(), ...accessClause.params) as OperatorPreferenceProfileRow[];
  const items = rows.map((row) => {
    const node = repository.requireNode(row.node_id);
    const summary = summaryForNode(database, row.node_id);
    if (!summary || !canAccess(node, access)) {
      throw new BrainApiError(
        500,
        "operator_preference_projection_inconsistent",
        "A confirmed operator preference is missing its canonical memory record",
        "data_integrity",
        "Run the Second Brain integrity check before using operator preferences.",
      );
    }
    const stored = parseStoredPreferenceValue(row.value_json);
    return {
      node: summary,
      preferenceKey: row.preference_key,
      value: stored.value,
      appliesTo: stored.appliesTo,
      operatorId: row.operator_id,
      confirmationState: row.confirmation_state,
      consentPolicy: row.consent_policy,
      profileVersion: row.version,
      lastConfirmedAt: row.confirmed_at,
      provenance: node.provenance,
    };
  });
  return {
    schemaVersion: SCHEMA_VERSION,
    items,
    totalReturned: items.length,
  };
}

const CONTEXT_PACK_MISSION_COLUMNS = [
  "mcp.mission_id",
  "linked_run.mission_id",
  "step_run.mission_id",
  "linked_action.mission_id",
  "linked_conversation.mission_id",
] as const;
const CONTEXT_PACK_EFFECTIVE_MISSION_SQL = `COALESCE(${CONTEXT_PACK_MISSION_COLUMNS.join(", ")})`;
const CONTEXT_PACK_CONSISTENT_SCOPE_SQL = CONTEXT_PACK_MISSION_COLUMNS
  .map((column) => `(${column} IS NULL OR ${column} = ${CONTEXT_PACK_EFFECTIVE_MISSION_SQL})`)
  .join(" AND ");
const CONTEXT_PACK_LINK_JOINS_SQL = `
  LEFT JOIN runs linked_run ON linked_run.id = mcp.run_id
  LEFT JOIN plan_steps linked_step ON linked_step.id = mcp.step_id
  LEFT JOIN plans linked_plan ON linked_plan.id = linked_step.plan_id
  LEFT JOIN runs step_run ON step_run.id = linked_plan.run_id
  LEFT JOIN actions linked_action ON linked_action.id = mcp.action_id
  LEFT JOIN messages linked_message ON linked_message.id = mcp.message_id
  LEFT JOIN conversations linked_conversation ON linked_conversation.id = linked_message.conversation_id
`;

function contextPackEffectiveMissionId(database: SqliteDatabase, contextPackId: string): string | null | undefined {
  const row = database.prepare(`
    SELECT ${CONTEXT_PACK_EFFECTIVE_MISSION_SQL} AS effective_mission_id,
      CASE WHEN ${CONTEXT_PACK_CONSISTENT_SCOPE_SQL} THEN 1 ELSE 0 END AS scope_consistent
    FROM memory_context_packs mcp
    ${CONTEXT_PACK_LINK_JOINS_SQL}
    WHERE mcp.id = ?
  `).get(contextPackId) as {
    effective_mission_id: string | null;
    scope_consistent: number;
  } | undefined;
  if (!row || row.scope_consistent !== 1) return undefined;
  return row.effective_mission_id;
}

function brainSummary(database: SqliteDatabase, access: MemoryAccessPolicy) {
  const clause = accessSql("mn", access);
  const rows = database.prepare(`
    SELECT mn.lifecycle_status AS status, COUNT(*) AS count
    FROM memory_nodes mn WHERE ${clause.sql}
    GROUP BY mn.lifecycle_status
  `).all(...clause.params) as Array<{ status: MemoryLifecycle; count: number }>;
  const counts = new Map(rows.map((row) => [row.status, Number(row.count)]));
  const candidateView = `(
    SELECT id, proposed_scope AS scope, engagement_id, mission_id, sensitivity, status
    FROM memory_candidates
  )`;
  const candidateClause = accessSql("mc", access);
  const candidates = (database.prepare(`
    SELECT COUNT(*) AS count FROM ${candidateView} mc
    WHERE ${candidateClause.sql} AND mc.status = 'pending'
  `).get(...candidateClause.params) as { count: number }).count;
  const edgeClauseA = accessSql("source", access);
  const edgeClauseB = accessSql("target", access);
  const edges = (database.prepare(`
    SELECT COUNT(*) AS count FROM memory_edges_safe me
    JOIN memory_nodes source ON source.id = me.source_node_id
    JOIN memory_nodes target ON target.id = me.target_node_id
    WHERE ${edgeClauseA.sql} AND ${edgeClauseB.sql} AND me.lifecycle_status != 'forgotten'
  `).get(...edgeClauseA.params, ...edgeClauseB.params) as { count: number }).count;
  const packRows = database.prepare(`
    SELECT ${CONTEXT_PACK_EFFECTIVE_MISSION_SQL} AS mission_id
    FROM memory_context_packs mcp
    ${CONTEXT_PACK_LINK_JOINS_SQL}
    WHERE ${CONTEXT_PACK_CONSISTENT_SCOPE_SQL}
  `).all() as Array<{ mission_id: string | null }>;
  const vaultRows = database.prepare("SELECT status, last_sync_at FROM vault_connections ORDER BY updated_at DESC").all() as Array<{ status: string; last_sync_at: string | null }>;
  const conflictRows = database.prepare("SELECT node_id FROM vault_conflicts WHERE status = 'open'").all() as Array<{ node_id: string | null }>;
  const conflicts = conflictRows.filter((row) => {
    if (!row.node_id) return false;
    const node = database.prepare(`SELECT ${SUMMARY_COLUMNS} FROM memory_nodes mn WHERE mn.id = ?`).get(row.node_id) as NodeSummaryRow | undefined;
    if (!node) return false;
    const scope = deserializeScope(node.scope, node.engagement_id, node.mission_id);
    return canAccess({ scope, sensitivity: node.sensitivity } as MemoryNode, access);
  }).length;
  const fts = database.prepare("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'memory_nodes_fts'").get() as { ok: number } | undefined;
  const databaseHealth = getDatabaseHealth(database);
  const recent = listNodes(database, access, { limit: "8" });
  const activeVaultRows = vaultRows.filter((row) => row.status !== "disconnected");
  const vaultStatus = activeVaultRows.length === 0
    ? "disconnected"
    : activeVaultRows.some((row) => row.status === "error")
      ? "error"
      : activeVaultRows.some((row) => row.status === "degraded")
        ? "degraded"
        : "connected";
  return {
    schemaVersion: SCHEMA_VERSION,
    counts: {
      confirmed: counts.get("confirmed") ?? 0,
      verified: counts.get("verified") ?? 0,
      candidateNodes: counts.get("candidate") ?? 0,
      pendingReviews: candidates,
      // Compatibility alias. This has always represented pending Inbox rows
      // on the Brain endpoint, not lifecycle-candidate graph nodes.
      candidates,
      stale: counts.get("stale") ?? 0,
      disputed: counts.get("disputed") ?? 0,
      forgotten: counts.get("forgotten") ?? 0,
      edges: Number(edges),
      contextPacks: packRows.filter((row) => canAccessMission(database, row.mission_id, access)).length,
    },
    health: {
      database: databaseHealth.healthy ? "healthy" : "unhealthy",
      fts: fts?.ok === 1 ? "healthy" : "unavailable",
    },
    vault: {
      status: vaultStatus,
      connections: vaultRows.length,
      conflicts: Number(conflicts),
      lastSyncAt: vaultRows.find((row) => row.last_sync_at)?.last_sync_at ?? null,
    },
    recentNodes: recent.items,
  };
}

const HAZARD_PRIVATE_PARAMETER_KEY = /(?:^|[._-])(?:target|host|domain|url|uri|path|address|ip|box|engagement|mission|credential|secret|token|password)(?:$|[._-])/iu;
const HAZARD_RAW_FILE_PATH = /(?:^|[\s"'(])(?:\/(?:root|home|var|tmp|etc|opt|mnt|srv|private)(?:\/[A-Za-z0-9._-]+)+|[A-Za-z]:\\[^\s"']+)/u;

function opaqueHazardSource(source: Record<string, unknown>): Record<string, unknown> {
  const canonicalSourceId = String(source.id ?? "source");
  return {
    sourceType: source.sourceType,
    sourceId: `receipt-${sha256(canonicalSourceId).slice(0, 20)}`,
    acquiredAt: source.acquiredAt,
    createdAt: source.createdAt,
  };
}

function operationalHazardReference(
  repository: MemoryRepository,
  access: MemoryAccessPolicy,
  nodeId: string | undefined,
) {
  if (!nodeId) return undefined;
  const linked = repository.getNode(nodeId);
  if (!linked || !canAccess(linked, access)) return undefined;
  return {
    id: linked.id,
    nodeType: linked.nodeType,
    title: linked.title,
    summary: linked.summary,
    confidence: linked.confidence,
    lifecycleStatus: linked.lifecycleStatus,
    ...(linked.expiresAt ? { expiresAt: linked.expiresAt } : {}),
  };
}

function operationalHazardDisplayIsUnsafe(value: unknown): boolean {
  try {
    assertReusableMemoryUnknown(value, "operational hazard display", REUSABLE_MEMORY_LIMITS.vaultNote);
  } catch {
    return true;
  }
  const containsPrivateLocator = (candidate: unknown, fieldName?: string): boolean => {
    if (typeof candidate === "string") {
      // nodeType is a validated schema enum; values such as
      // target_state_transition are not target record identifiers.
      if (fieldName === "nodeType") return false;
      return attackKnowledgeOperationalLocatorCategories(candidate).length > 0
        || HAZARD_RAW_FILE_PATH.test(candidate);
    }
    if (Array.isArray(candidate)) return candidate.some((item) => containsPrivateLocator(item));
    if (!candidate || typeof candidate !== "object") return false;
    return Object.entries(candidate).some(([key, item]) => containsPrivateLocator(item, key));
  };
  return containsPrivateLocator(value);
}

function operationalHazardVersionPayload(version: Record<string, unknown>): Record<string, unknown> {
  const common = {
    version: Number(version.version),
    lifecycleStatus: version.lifecycle_status,
    changedAt: version.created_at,
  };
  const potentiallyPrivate = {
    title: version.title,
    summary: version.summary,
    body: version.body,
    changedBy: version.author_id ?? version.author_type,
    changeReason: version.change_reason,
  };
  if (operationalHazardDisplayIsUnsafe(potentiallyPrivate)) {
    return {
      ...common,
      title: "[Protected historical version]",
      summary: "Historical content was withheld because it contains private operational context.",
      body: "",
      changedBy: "reusable-memory privacy boundary",
      changeReason: "Private operational content withheld; inspect its protected source through authorized evidence controls.",
    };
  }
  return {
    ...common,
    ...potentiallyPrivate,
    contentHash: version.content_hash,
  };
}

function operationalHazardDetail(
  database: SqliteDatabase,
  repository: MemoryRepository,
  node: MemoryNode,
  access: MemoryAccessPolicy,
  sources: readonly Record<string, unknown>[],
) {
  const profile = new OperationalHazardProfileRepository(database).get(node.id);
  if (!profile) return undefined;
  const reference = (nodeId: string | undefined) => operationalHazardReference(repository, access, nodeId);
  const references = (nodeIds: readonly string[]) => nodeIds
    .map((nodeId) => reference(nodeId))
    .filter((item): item is NonNullable<typeof item> => Boolean(item));
  const normalizedParameterKeys = Object.keys(profile.normalizedParameters);
  if (normalizedParameterKeys.some((key) => HAZARD_PRIVATE_PARAMETER_KEY.test(key))) {
    throw new BrainApiError(
      422,
      "operational_hazard_display_denied",
      "Operational hazard detail contains a private locator field and cannot be displayed",
      "policy_denied",
      "Generalize the reusable profile and keep target-specific values in protected evidence.",
    );
  }
  const receiptIds = sources
    .map((source) => `receipt-${sha256(String(source.id ?? "source")).slice(0, 20)}`)
    .sort();
  const freshnessStatus = profile.freshUntil
    ? Date.parse(profile.freshUntil) > Date.now() ? "current" : "expired"
    : "unbounded";
  const detail = {
    procedure: reference(profile.procedureNodeId) ?? null,
    procedureVersion: reference(profile.procedureVersionNodeId) ?? null,
    affectedProducts: references(profile.productNodeIds),
    affectedVersions: references(profile.versionNodeIds),
    affectedStack: references(profile.stackNodeIds),
    prerequisites: references(profile.prerequisiteNodeIds),
    observedStates: references(profile.observedStateNodeIds ?? []),
    orderedSequence: profile.orderedSteps,
    normalizedExecution: {
      parameters: profile.normalizedParameters,
      loadMinimum: profile.loadMinimum ?? null,
      concurrencyMinimum: profile.concurrencyMinimum ?? null,
      timingWindowMs: profile.timingWindowMs ?? null,
    },
    applicabilityConstraints: profile.applicabilityConstraints ?? {},
    symptom: {
      observed: profile.observedSymptom,
      affectedComponent: profile.affectedComponent,
    },
    stateTransition: {
      before: profile.stateBefore,
      after: profile.stateAfter,
    },
    corroboration: {
      exactHangCount: profile.reproducibilityCount,
      observedAttemptCount: profile.attemptCount,
      operatorReportedResetMinimum: profile.recoveryCost?.operatorReportedResetCountMinimum ?? null,
    },
    safeHealthGate: profile.safeRetryGate,
    unsafeRetryConditions: profile.unsafeRetryConditions,
    recovery: {
      summary: profile.recoveryActionSummary,
      pattern: reference(profile.recoveryPatternNodeId) ?? null,
      cost: profile.recoveryCost ?? {},
    },
    alternatives: {
      sequence: profile.alternativeSequence ?? [],
      procedure: reference(profile.alternativeProcedureNodeId) ?? null,
    },
    confidence: profile.confidence,
    freshness: {
      observedAt: profile.observedAt,
      freshUntil: profile.freshUntil ?? null,
      status: freshnessStatus,
    },
    provenanceReceipt: {
      profileVersion: profile.version,
      sourceCount: receiptIds.length,
      receiptIds,
      receiptHash: sha256(canonical({
        nodeVersion: node.version,
        profileVersion: profile.version,
        receiptIds,
        observedAt: profile.observedAt,
        updatedAt: profile.updatedAt,
      })),
      recordedAt: profile.updatedAt,
    },
  } as const;
  if (operationalHazardDisplayIsUnsafe(detail)) {
    throw new BrainApiError(
      422,
      "operational_hazard_display_denied",
      "Operational hazard detail contains private operational context and cannot be displayed",
      "policy_denied",
      "Generalize the reusable profile and keep target-specific values in protected evidence.",
    );
  }
  return detail;
}

function memoryOriginAccessSql(access: MemoryAccessPolicy): { sql: string; params: unknown[] } {
  if (access.allEngagements) return { sql: "1", params: [] };
  const clauses: string[] = [];
  const params: unknown[] = [];
  const missionIds = [...new Set(access.missionIds ?? [])];
  const engagementIds = [...new Set(access.engagementIds ?? [])];
  if (missionIds.length > 0) {
    clauses.push(`originMissionId IN (${missionIds.map(() => "?").join(",")})`);
    params.push(...missionIds);
  }
  if (engagementIds.length > 0) {
    clauses.push(`originEngagementId IN (${engagementIds.map(() => "?").join(",")})`);
    params.push(...engagementIds);
  }
  return { sql: clauses.length > 0 ? `(${clauses.join(" OR ")})` : "0", params };
}

function legacySourceOrigins(
  database: SqliteDatabase,
  sourceReferences: readonly string[],
): ReadonlyMap<string, LegacySourceOriginRow> {
  const unique = [...new Set(sourceReferences.filter(Boolean))];
  const resolved = new Map<string, LegacySourceOriginRow>();
  for (let offset = 0; offset < unique.length; offset += 400) {
    const page = unique.slice(offset, offset + 400);
    const rows = database.prepare(`
      SELECT source_object.source_reference, source_object.source_path,
        migration_source.source_path AS source_root_path,
        migration_source.relative_path AS engagement_label
      FROM legacy_migration_source_objects source_object
      JOIN legacy_migration_sources migration_source
        ON migration_source.id = source_object.source_id
      WHERE source_object.source_reference IN (${page.map(() => "?").join(",")})
      ORDER BY source_object.source_reference ASC, source_object.verified_at DESC,
        migration_source.relative_path ASC
    `).all(...page) as LegacySourceOriginRow[];
    for (const row of rows) {
      if (!resolved.has(row.source_reference)) resolved.set(row.source_reference, row);
    }
  }
  return resolved;
}

function memorySourceOriginRows(
  database: SqliteDatabase,
  sourceRecordIds: readonly string[],
  access: MemoryAccessPolicy,
  offset: number,
  limit: number,
): MemorySourceProjectionRow[] {
  if (sourceRecordIds.length === 0) return [];
  const accessClause = memoryOriginAccessSql(access);
  return database.prepare(`
    WITH effective_sources AS (
      SELECT ms.id, ms.source_type AS sourceType, ms.source_id AS sourceId,
        ms.source_hash AS sourceHash, ms.excerpt_redacted AS excerptRedacted,
        ms.acquired_at AS acquiredAt, ms.created_at AS createdAt,
        COALESCE(private_binding.mission_id, ms.mission_id, evidence.mission_id) AS originMissionId,
        mission.name AS originMissionName,
        COALESCE(private_binding.run_id, ms.run_id, evidence.run_id) AS originRunId,
        run.status AS originRunStatus,
        mission.engagement_id AS originEngagementId,
        COALESCE(private_binding.artifact_id, evidence.artifact_id) AS artifactId,
        ms.evidence_id AS evidenceId,
        COALESCE(
          private_binding.source_reference,
          CASE
            WHEN evidence.provenance_json IS NOT NULL
              AND json_type(evidence.provenance_json, '$.sourceReference') = 'text'
            THEN json_extract(evidence.provenance_json, '$.sourceReference')
            ELSE NULL
          END,
          (
            SELECT occurrence.source_reference
            FROM historical_attack_knowledge_source_occurrences occurrence
            WHERE ms.source_type = 'historical_attack_knowledge_source_candidate'
              AND ms.source_id = occurrence.candidate_id || ':' || occurrence.migration_id
              AND (ms.source_hash IS NULL OR ms.source_hash = occurrence.source_hash)
            ORDER BY occurrence.observed_at DESC, occurrence.source_reference ASC
            LIMIT 1
          )
        ) AS privateSourceReference,
        CASE WHEN bound_artifact.metadata_json IS NOT NULL
          AND json_type(bound_artifact.metadata_json, '$.sourceLocator') = 'text'
          THEN json_extract(bound_artifact.metadata_json, '$.sourceLocator') ELSE NULL END
          AS artifactSourceLocator,
        CASE WHEN bound_artifact.metadata_json IS NOT NULL
          AND json_type(bound_artifact.metadata_json, '$.relativePath') = 'text'
          THEN json_extract(bound_artifact.metadata_json, '$.relativePath') ELSE NULL END
          AS artifactRelativePath
      FROM memory_sources ms
      LEFT JOIN evidence ON evidence.id = ms.evidence_id
      LEFT JOIN historical_private_source_bindings private_binding
        ON private_binding.memory_source_id = ms.id
      LEFT JOIN missions mission ON mission.id = COALESCE(
        private_binding.mission_id, ms.mission_id, evidence.mission_id
      )
      LEFT JOIN runs run ON run.id = COALESCE(
        private_binding.run_id, ms.run_id, evidence.run_id
      )
      LEFT JOIN artifacts bound_artifact ON bound_artifact.id = COALESCE(
        private_binding.artifact_id, evidence.artifact_id
      )
      WHERE ms.id IN (${sourceRecordIds.map(() => "?").join(",")})
    ), authorized_origins AS (
      SELECT * FROM effective_sources
      WHERE (originMissionId IS NOT NULL OR originRunId IS NOT NULL
        OR artifactId IS NOT NULL OR evidenceId IS NOT NULL
        OR privateSourceReference IS NOT NULL)
        AND ${accessClause.sql}
    ), ranked_origins AS (
      SELECT authorized_origins.*,
        COUNT(*) OVER (PARTITION BY id) AS originCount,
        ROW_NUMBER() OVER (
          PARTITION BY id ORDER BY privateSourceReference ASC, artifactId ASC,
            evidenceId ASC, originMissionId ASC, originRunId ASC
        ) AS originRank
      FROM authorized_origins
    )
    SELECT * FROM ranked_origins
    WHERE originRank > ? AND originRank <= ?
    ORDER BY acquiredAt DESC, id ASC, originRank ASC
  `).all(
    ...sourceRecordIds,
    ...accessClause.params,
    offset,
    offset + limit,
  ) as MemorySourceProjectionRow[];
}

function projectMemoryOrigins(
  database: SqliteDatabase,
  rows: readonly MemorySourceProjectionRow[],
): Array<Record<string, unknown>> {
  const legacy = legacySourceOrigins(
    database,
    rows.flatMap((row) => row.privateSourceReference ? [row.privateSourceReference] : []),
  );
  return rows.map((row) => {
    const resolved = row.privateSourceReference
      ? legacy.get(row.privateSourceReference)
      : undefined;
    const relativeSourcePath = resolved
      && row.privateSourceReference
      && resolved.source_path.startsWith(`${resolved.source_root_path}/`)
      ? resolved.source_path.slice(resolved.source_root_path.length + 1)
      : undefined;
    return {
      ...(row.originMissionId ? { missionId: row.originMissionId } : {}),
      ...(row.originMissionName ? { missionName: row.originMissionName } : {}),
      ...(row.originRunId ? { runId: row.originRunId } : {}),
      ...(row.originRunStatus ? { runStatus: row.originRunStatus } : {}),
      ...(row.originEngagementId ? { engagementId: row.originEngagementId } : {}),
      ...(resolved?.engagement_label ? { engagementLabel: resolved.engagement_label } : {}),
      ...(row.artifactId ? { artifactId: row.artifactId } : {}),
      ...(row.evidenceId ? { evidenceId: row.evidenceId } : {}),
      ...(row.privateSourceReference ? { privateSourceReference: row.privateSourceReference } : {}),
      ...(row.artifactSourceLocator || row.artifactRelativePath || relativeSourcePath || (resolved && row.privateSourceReference)
        ? { sourceLocator: row.artifactSourceLocator ?? row.artifactRelativePath ?? relativeSourcePath ?? row.privateSourceReference }
        : {}),
    };
  });
}

function memorySourcePage(
  database: SqliteDatabase,
  nodeId: string,
  access: MemoryAccessPolicy,
  input: { readonly limit: number; readonly cursor?: MemorySourceCursor },
) {
  const total = Number((database.prepare(`
    SELECT COUNT(*) AS total FROM memory_sources WHERE node_id = ?
  `).get(nodeId) as { total: number }).total);
  const clauses = ["node_id = ?"];
  const params: unknown[] = [nodeId];
  if (input.cursor) {
    clauses.push("(acquired_at < ? OR (acquired_at = ? AND id > ?))");
    params.push(input.cursor.acquiredAt, input.cursor.acquiredAt, input.cursor.sourceRecordId);
  }
  const selected = database.prepare(`
    SELECT id, source_type, source_id, source_hash, excerpt_redacted,
      acquired_at, created_at
    FROM memory_sources
    WHERE ${clauses.join(" AND ")}
    ORDER BY acquired_at DESC, id ASC
    LIMIT ?
  `).all(...params, input.limit + 1) as MemorySourcePageRow[];
  const page = selected.slice(0, input.limit);
  const originRows = memorySourceOriginRows(
    database,
    page.map((row) => row.id),
    access,
    0,
    MEMORY_SOURCE_ORIGIN_LIMIT,
  );
  const originsBySource = new Map<string, Array<Record<string, unknown>>>();
  const originCounts = new Map<string, number>();
  const projectedOrigins = projectMemoryOrigins(database, originRows);
  originRows.forEach((row, index) => {
    const origins = originsBySource.get(row.id) ?? [];
    origins.push(projectedOrigins[index]!);
    originsBySource.set(row.id, origins);
    originCounts.set(row.id, Number(row.originCount));
  });
  const items = page.map((row) => {
    const origins = originsBySource.get(row.id) ?? [];
    const originCount = originCounts.get(row.id) ?? 0;
    return {
      sourceRecordId: row.id,
      sourceType: row.source_type,
      sourceId: row.source_id,
      ...(row.source_hash ? { sourceHash: row.source_hash } : {}),
      ...(row.excerpt_redacted ? { excerptRedacted: row.excerpt_redacted } : {}),
      acquiredAt: row.acquired_at,
      createdAt: row.created_at,
      originCount,
      ...(origins.length > 0 ? { origins } : {}),
      ...(originCount > origins.length
        ? { originsNextCursor: encodeMemoryOriginCursor(nodeId, row.id, origins.length) }
        : { originsNextCursor: null }),
    };
  });
  return {
    schemaVersion: SCHEMA_VERSION,
    nodeId,
    items,
    totalCount: total,
    nextCursor: selected.length > input.limit && page.length > 0
      ? encodeMemorySourceCursor(nodeId, page.at(-1)!)
      : null,
  };
}

function memoryOriginPage(
  database: SqliteDatabase,
  nodeId: string,
  sourceRecordId: string,
  access: MemoryAccessPolicy,
  input: { readonly limit: number; readonly cursor?: MemoryOriginCursor },
) {
  const source = database.prepare(`
    SELECT id FROM memory_sources WHERE id = ? AND node_id = ?
  `).get(sourceRecordId, nodeId) as { id: string } | undefined;
  if (!source) {
    throw new BrainApiError(404, "memory_source_not_found", "Memory provenance source was not found", "not_found");
  }
  const offset = input.cursor?.offset ?? 0;
  const rows = memorySourceOriginRows(database, [sourceRecordId], access, offset, input.limit);
  const items = projectMemoryOrigins(database, rows);
  const countRow = rows[0]
    ?? memorySourceOriginRows(database, [sourceRecordId], access, 0, 1)[0];
  const totalCount = countRow ? Number(countRow.originCount) : 0;
  return {
    schemaVersion: SCHEMA_VERSION,
    nodeId,
    sourceRecordId,
    items,
    totalCount,
    nextCursor: totalCount > offset + items.length
      ? encodeMemoryOriginCursor(nodeId, sourceRecordId, offset + items.length)
      : null,
  };
}

function nodeDetail(
  database: SqliteDatabase,
  repository: MemoryRepository,
  id: string,
  access: MemoryAccessPolicy,
) {
  const canonicalNode = requireAccessibleNode(repository, id, access, true);
  const summary = summaryForNode(database, id);
  const outcomeTags = summary?.outcomeTags ?? [];
  const sourcePage = memorySourcePage(database, id, access, {
    limit: MEMORY_SOURCE_DETAIL_LIMIT,
  });
  const sources = sourcePage.items;
  const allEdges = canonicalNode.lifecycleStatus === "forgotten" ? [] : repository.listEdges(id);
  const accessibleEdges = allEdges.filter((edge) => {
    const otherId = edge.sourceNodeId === id ? edge.targetNodeId : edge.sourceNodeId;
    const other = repository.getNode(otherId);
    return Boolean(other && canAccess(other, access));
  });
  const usageRows = database.prepare(`
    SELECT mci.context_pack_id AS contextPackId, mci.rank, mci.retrieval_score AS retrievalScore,
      mci.used, mci.relevance_reason AS relevanceReason, mci.influence_summary AS influenceSummary,
      mci.ignored_reason AS ignoredReason, mci.corrected,
      mcp.mission_id AS missionId, mcp.run_id AS runId, mcp.journey, mcp.purpose, mcp.created_at AS createdAt
    FROM memory_context_items mci JOIN memory_context_packs mcp ON mcp.id = mci.context_pack_id
    WHERE mci.node_id = ? ORDER BY mcp.created_at DESC LIMIT 100
  `).all(id) as Array<Record<string, unknown>>;
  const versions = canonicalNode.lifecycleStatus === "forgotten" ? [] : database.prepare(`
    SELECT version, title, summary, body, lifecycle_status, author_type, author_id,
      change_reason, content_hash, created_at
    FROM memory_versions WHERE node_id = ? ORDER BY version DESC
  `).all(id) as Array<Record<string, unknown>>;
  const operationalHazard = canonicalNode.nodeType === "operational_hazard"
    && canonicalNode.lifecycleStatus !== "forgotten"
    ? operationalHazardDetail(
        database,
        repository,
        canonicalNode,
        access,
        database.prepare(`
          SELECT id FROM memory_sources WHERE node_id = ? ORDER BY id ASC
        `).all(id) as Array<Record<string, unknown>>,
      )
    : undefined;
  const safeSources = canonicalNode.nodeType === "operational_hazard"
    ? sources.map(opaqueHazardSource)
    : sources;
  const versionPayloads = canonicalNode.nodeType === "operational_hazard"
    ? versions.map(operationalHazardVersionPayload)
    : versions.map((version) => ({
        version: Number(version.version),
        title: version.title,
        summary: version.summary,
        body: version.body,
        lifecycleStatus: version.lifecycle_status,
        changedBy: version.author_id ?? version.author_type,
        changeReason: version.change_reason,
        contentHash: version.content_hash,
        changedAt: version.created_at,
      }));
  const node = {
    ...canonicalNode,
    ...(summary ?? {}),
    sourceCount: sourcePage.totalCount,
    outcomeTags,
    provenance: {
      ...canonicalNode.provenance,
      sources: canonicalNode.nodeType === "operational_hazard"
        ? safeSources.map((source) => ({
            sourceType: String(source.sourceType),
            sourceId: String(source.sourceId),
            acquiredAt: String(source.acquiredAt),
          }))
        : safeSources,
    },
  };
  return {
    schemaVersion: SCHEMA_VERSION,
    node,
    sources: safeSources,
    sourcesNextCursor: sourcePage.nextCursor,
    ...(operationalHazard ? { operationalHazard } : {}),
    versions: versionPayloads,
    backlinks: accessibleEdges.filter((edge) => edge.targetNodeId === id).map(edgePayload),
    outgoing: accessibleEdges.filter((edge) => edge.sourceNodeId === id).map(edgePayload),
    usage: usageRows
      .filter((row) => canAccessMission(database, row.missionId ? String(row.missionId) : null, access))
      .map((row) => ({
        contextPackId: row.contextPackId,
        ...(row.missionId ? { missionId: row.missionId } : {}),
        ...(row.runId ? { runId: row.runId } : {}),
        journey: row.journey,
        purpose: row.purpose,
        used: Number(row.used) === 1,
        relevanceReason: row.relevanceReason,
        ...(row.influenceSummary ? { influenceSummary: row.influenceSummary } : {}),
        ...(row.ignoredReason ? { ignoredReason: row.ignoredReason } : {}),
        corrected: Number(row.corrected) === 1,
        retrievalScore: Number(row.retrievalScore),
        rank: Number(row.rank),
        createdAt: row.createdAt,
      })),
  };
}

function candidateAccessible(candidate: MemoryCandidate, access: MemoryAccessPolicy): boolean {
  const asNode = {
    scope: candidate.scope,
    sensitivity: candidate.sensitivity,
  } as Pick<MemoryNode, "scope" | "sensitivity">;
  return canAccess(asNode as MemoryNode, access);
}

function requireAccessibleCandidate(
  repository: MemoryRepository,
  id: string,
  access: MemoryAccessPolicy,
): MemoryCandidate {
  assertIdentifier(id, "memory candidate ID");
  const candidate = repository.getCandidate(id);
  // A policy miss is intentionally indistinguishable from an absent record.
  if (!candidate || !candidateAccessible(candidate, access)) {
    throw new BrainApiError(404, "memory_candidate_not_found", "Memory candidate was not found", "not_found");
  }
  return candidate;
}

function listCandidates(
  database: SqliteDatabase,
  repository: MemoryRepository,
  access: MemoryAccessPolicy,
  query: Record<string, unknown>,
) {
  const limit = integer(query.limit, 50, 1, 100, "candidate page limit");
  const status = query.status === undefined ? "pending" : requiredText(query.status, "candidate status", 30);
  if (!["pending", "confirmed", "edited_confirmed", "merged", "rejected", "suppressed"].includes(status)) {
    throw new TypeError("candidate status filter is invalid");
  }
  const missionId = optionalText(query.missionId, "mission ID", 256);
  const runId = optionalText(query.runId, "run ID", 256);
  if (missionId) assertIdentifier(missionId, "mission ID");
  if (runId) assertIdentifier(runId, "run ID");
  if (missionId && !canAccessMission(database, missionId, access)) {
    return { schemaVersion: SCHEMA_VERSION, items: [], nextCursor: null };
  }
  let requestedRunScope: { missionId: string; engagementId: string | null } | undefined;
  if (runId) {
    const run = database.prepare(`
      SELECT r.mission_id AS missionId, m.engagement_id AS engagementId
      FROM runs r
      JOIN missions m ON m.id = r.mission_id
      WHERE r.id = ?
    `).get(runId) as { missionId: string; engagementId: string | null } | undefined;
    if (!run || !canAccessMission(database, run.missionId, access) || (missionId && run.missionId !== missionId)) {
      return { schemaVersion: SCHEMA_VERSION, items: [], nextCursor: null };
    }
    requestedRunScope = run;
  }
  const cursor = decodeCursor(query.cursor);
  const candidateView = `(
    SELECT id, proposed_scope AS scope, engagement_id, mission_id, sensitivity,
      source_json, status, created_at FROM memory_candidates
  )`;
  const accessClause = accessSql("mc", access);
  const clauses = [accessClause.sql, "mc.status = ?"];
  const params: unknown[] = [...accessClause.params, status];
  if (missionId && !runId) {
    clauses.push("mc.mission_id = ?");
    params.push(missionId);
  }
  if (runId) {
    clauses.push("(mc.mission_id IS NULL OR mc.mission_id = ?)");
    clauses.push("(mc.engagement_id IS NULL OR mc.engagement_id = ?)");
    params.push(requestedRunScope!.missionId, requestedRunScope!.engagementId);
    const sourceType = "json_extract(source.value, '$.sourceType')";
    const sourceId = "json_extract(source.value, '$.sourceId')";
    clauses.push(`EXISTS (
      SELECT 1 FROM json_each(mc.source_json, '$.sources') AS source
      WHERE (${sourceType} IN ('run', 'runtime_run') AND ${sourceId} = ?)
        OR (${sourceType} = 'run_evaluation' AND EXISTS (
          SELECT 1 FROM run_evaluations linked WHERE linked.id = ${sourceId} AND linked.run_id = ?
        ))
        OR (${sourceType} = 'message' AND EXISTS (
          SELECT 1 FROM messages linked
          JOIN conversations conversation ON conversation.id = linked.conversation_id
          WHERE linked.id = ${sourceId} AND conversation.run_id = ?
        ))
        OR (${sourceType} = 'action' AND EXISTS (
          SELECT 1 FROM actions linked WHERE linked.id = ${sourceId} AND linked.run_id = ?
        ))
        OR (${sourceType} = 'evidence' AND EXISTS (
          SELECT 1 FROM evidence linked WHERE linked.id = ${sourceId} AND linked.run_id = ?
        ))
        OR (${sourceType} = 'finding' AND EXISTS (
          SELECT 1 FROM findings linked WHERE linked.id = ${sourceId} AND linked.run_id = ?
        ))
        OR (${sourceType} = 'artifact' AND EXISTS (
          SELECT 1 FROM artifacts linked WHERE linked.id = ${sourceId} AND linked.run_id = ?
        ))
        OR (${sourceType} IN ('context_pack', 'memory_context_pack') AND EXISTS (
          SELECT 1 FROM memory_context_packs linked WHERE linked.id = ${sourceId} AND linked.run_id = ?
        ))
    )`);
    params.push(runId, runId, runId, runId, runId, runId, runId, runId);
  }
  if (cursor) {
    clauses.push("(mc.created_at < ? OR (mc.created_at = ? AND mc.id < ?))");
    params.push(cursor.updatedAt, cursor.updatedAt, cursor.id);
  }
  const rows = database.prepare(`
    SELECT mc.id, mc.created_at AS updated_at FROM ${candidateView} mc
    WHERE ${clauses.join(" AND ")} ORDER BY mc.created_at DESC, mc.id DESC LIMIT ?
  `).all(...params, limit + 1) as Array<{ id: string; updated_at: string }>;
  const accessible = rows.flatMap((row) => {
    const candidate = repository.getCandidate(row.id);
    return candidate && candidateAccessible(candidate, access) ? [{ candidate, row }] : [];
  });
  const page = accessible.slice(0, limit);
  return {
    schemaVersion: SCHEMA_VERSION,
    items: page.map((item) => item.candidate),
    nextCursor: rows.length > limit && page.length > 0 ? encodeCursor(page.at(-1)!.row) : null,
  };
}

function parseScopeBody(value: unknown): MemoryScope {
  const body = object(value, "memory scope");
  return validateScope({
    kind: requiredText(body.kind, "memory scope kind", 30) as MemoryScope["kind"],
    ...(body.engagementId ? { engagementId: requiredText(body.engagementId, "engagement ID", 256) } : {}),
    ...(body.missionId ? { missionId: requiredText(body.missionId, "mission ID", 256) } : {}),
  });
}

function correctionInput(body: Record<string, unknown>, actor: string): CorrectMemoryNodeInput {
  const lifecycleStatus = body.lifecycleStatus === undefined
    ? undefined
    : validateLifecycle(body.lifecycleStatus);
  if (lifecycleStatus === "forgotten") throw new TypeError("Use the dedicated forget operation for erasure");
  const expiresAt = body.expiresAt === null
    ? null
    : optionalText(body.expiresAt, "memory expiry", 100);
  if (expiresAt && Number.isNaN(Date.parse(expiresAt))) throw new TypeError("memory expiry must be an ISO timestamp");
  return {
    ...(body.title === undefined ? {} : { title: requiredText(body.title, "memory title", 500) }),
    ...(body.summary === undefined ? {} : { summary: requiredText(body.summary, "memory summary", 4_000) }),
    ...(body.body === undefined ? {} : { body: typeof body.body === "string" ? body.body : requiredText(body.body, "memory body", 1_000_000) }),
    ...(body.scope === undefined ? {} : { scope: parseScopeBody(body.scope) }),
    ...(body.sensitivity === undefined ? {} : { sensitivity: validateSensitivity(body.sensitivity) }),
    ...(body.confidence === undefined ? {} : { confidence: validateConfidence(body.confidence) }),
    ...(lifecycleStatus ? { lifecycleStatus: lifecycleStatus as Exclude<MemoryLifecycle, "forgotten"> } : {}),
    ...(body.confirmationState === undefined ? {} : {
      confirmationState: (() => {
        const value = requiredText(body.confirmationState, "confirmation state", 30);
        if (!["not_required", "pending", "confirmed", "rejected"].includes(value)) {
          throw new TypeError("confirmation state is invalid");
        }
        return value as MemoryNode["confirmationState"];
      })(),
    }),
    ...(body.retentionPolicy === undefined ? {} : { retentionPolicy: object(body.retentionPolicy, "retention policy") }),
    ...(body.expiresAt === undefined ? {} : { expiresAt }),
    ...(body.pinned === undefined ? {} : {
      pinned: typeof body.pinned === "boolean" ? body.pinned : (() => { throw new TypeError("pinned must be boolean"); })(),
    }),
    authorType: "operator",
    authorId: actor,
    changeReason: requiredText(body.reason, "memory change reason", 2_000),
  };
}

function expectedVersion(body: Record<string, unknown>, node: MemoryNode): void {
  const expected = body.expectedVersion;
  if (!Number.isSafeInteger(expected) || Number(expected) < 1) throw new TypeError("expectedVersion must be a positive integer");
  if (Number(expected) !== node.version) {
    throw new BrainApiError(409, "memory_version_conflict", "Memory changed after it was loaded", "conflict", "Refresh the node before applying this change.");
  }
}

function contextPackDetail(
  database: SqliteDatabase,
  repository: MemoryRepository,
  id: string,
  access: MemoryAccessPolicy,
) {
  const pack = repository.requireContextPack(id);
  const effectiveMissionId = contextPackEffectiveMissionId(database, pack.id);
  if (effectiveMissionId === undefined || !canAccessMission(database, effectiveMissionId, access)) {
    throw new BrainApiError(404, "context_pack_not_found", "Context pack was not found", "not_found");
  }
  const items = pack.items.map((item) => {
    const node = repository.getNode(item.nodeId);
    if (!node || !canAccess(node, access)) {
      throw new BrainApiError(404, "context_pack_not_found", "Context pack was not found", "not_found");
    }
    return { ...item, node: summaryForNode(database, node.id)! };
  });
  return { schemaVersion: SCHEMA_VERSION, ...pack, items };
}

function listContextPacks(
  database: SqliteDatabase,
  access: MemoryAccessPolicy,
  query: Record<string, unknown>,
) {
  const limit = integer(query.limit, 100, 1, 200, "context pack page limit");
  const missionId = optionalText(query.missionId, "mission ID", 256);
  const runId = optionalText(query.runId, "run ID", 256);
  const stepId = optionalText(query.stepId, "step ID", 256);
  const actionId = optionalText(query.actionId, "action ID", 256);
  const messageId = optionalText(query.messageId, "message ID", 256);
  const journey = optionalText(query.journey, "journey", 20);
  for (const [label, value] of [["mission ID", missionId], ["run ID", runId], ["step ID", stepId], ["action ID", actionId], ["message ID", messageId]] as const) {
    if (value) assertIdentifier(value, label);
  }
  if (journey && journey !== "autonomous" && journey !== "guided") {
    throw new TypeError("journey must be autonomous or guided");
  }

  const effectiveMission = CONTEXT_PACK_EFFECTIVE_MISSION_SQL;
  const consistentScope = CONTEXT_PACK_CONSISTENT_SCOPE_SQL;
  const visibility: string[] = [];
  const visibilityParams: unknown[] = [];
  if (access.allowGlobal !== false) visibility.push(`${effectiveMission} IS NULL`);
  if (access.allEngagements) visibility.push(`${effectiveMission} IS NOT NULL`);
  else {
    const missions = [...new Set(access.missionIds ?? [])];
    const engagements = [...new Set(access.engagementIds ?? [])];
    if (missions.length) {
      visibility.push(`${effectiveMission} IN (${missions.map(() => "?").join(",")})`);
      visibilityParams.push(...missions);
    }
    if (engagements.length) {
      visibility.push(`m.engagement_id IN (${engagements.map(() => "?").join(",")})`);
      visibilityParams.push(...engagements);
    }
  }
  const clauses = [consistentScope, `(${visibility.length ? visibility.join(" OR ") : "0"})`];
  const params = [...visibilityParams];
  if (missionId) {
    clauses.push(`${effectiveMission} = ?`);
    params.push(missionId);
  }
  for (const [column, value] of [
    ["mcp.run_id", runId], ["mcp.step_id", stepId],
    ["mcp.action_id", actionId], ["mcp.message_id", messageId], ["mcp.journey", journey],
  ] as const) {
    if (value) { clauses.push(`${column} = ?`); params.push(value); }
  }
  const rows = database.prepare(`
    SELECT mcp.id, ${effectiveMission} AS missionId, mcp.run_id AS runId,
      mcp.step_id AS stepId, mcp.action_id AS actionId, mcp.message_id AS messageId,
      mcp.journey, mcp.purpose, mcp.context_budget AS contextBudget,
      mcp.created_by AS createdBy, mcp.created_at AS createdAt,
      COUNT(mci.node_id) AS retrievedItemCount,
      SUM(CASE WHEN mci.used = 1 THEN 1 ELSE 0 END) AS usedItemCount,
      SUM(CASE WHEN mci.corrected = 1 THEN 1 ELSE 0 END) AS correctedItemCount
    FROM memory_context_packs mcp
    ${CONTEXT_PACK_LINK_JOINS_SQL}
    LEFT JOIN missions m ON m.id = ${effectiveMission}
    LEFT JOIN memory_context_items mci ON mci.context_pack_id = mcp.id
    WHERE ${clauses.join(" AND ")}
    GROUP BY mcp.id
    ORDER BY mcp.created_at DESC, mcp.id DESC LIMIT ?
  `).all(...params, limit) as Array<Record<string, unknown>>;
  return {
    schemaVersion: SCHEMA_VERSION,
    items: rows.map((row) => ({
      id: row.id,
      ...(row.missionId ? { missionId: row.missionId } : {}),
      ...(row.runId ? { runId: row.runId } : {}),
      ...(row.stepId ? { stepId: row.stepId } : {}),
      ...(row.actionId ? { actionId: row.actionId } : {}),
      ...(row.messageId ? { messageId: row.messageId } : {}),
      journey: row.journey,
      purpose: row.purpose,
      contextBudget: Number(row.contextBudget),
      createdBy: row.createdBy,
      createdAt: row.createdAt,
      retrievedItemCount: Number(row.retrievedItemCount ?? 0),
      usedItemCount: Number(row.usedItemCount ?? 0),
      correctedItemCount: Number(row.correctedItemCount ?? 0),
    })),
    totalReturned: rows.length,
  };
}

function boundedMarkdownFiles(
  policy: VaultPathPolicy,
  vaultRoot: string,
  maximum = 251,
): string[] {
  const files: string[] = [];
  const visit = (relativeDirectory: string): void => {
    if (files.length >= maximum) return;
    const absolute = policy.resolveRelative(vaultRoot, relativeDirectory || ".");
    for (const entry of readdirSync(absolute, { withFileTypes: true })) {
      if (files.length >= maximum) return;
      if (entry.isSymbolicLink()) throw new BrainApiError(403, "vault_symlink_denied", "Symbolic links are not permitted in managed vault paths", "policy_denied");
      const relativePath = relativeDirectory ? `${relativeDirectory}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (entry.name === ".ti-scale" || entry.name === ".obsidian" || entry.name === "Attachments") continue;
        visit(relativePath);
      } else if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) {
        files.push(relativePath);
      }
    }
  };
  visit("");
  return files;
}

/**
 * Mount with `app.use(createSecondBrainRouter(dependencies))` after JSON body
 * parsing. The caller owns authentication and supplies explicit memory scope.
 */
export function createSecondBrainRouter(dependencies: SecondBrainRouterDependencies): Router {
  const router = Router();
  const repository = new MemoryRepository(dependencies.database);
  const brain = new SecondBrainService(repository);
  const pathPolicy = dependencies.vaultPathPolicy ?? (dependencies.vaultAllowedRoot
    ? new VaultPathPolicy(dependencies.vaultAllowedRoot)
    : undefined);
  const vault = dependencies.vaultBridge ?? (pathPolicy
    ? new ObsidianVaultBridge(
      dependencies.database,
      repository,
      pathPolicy,
      {},
    )
    : undefined);
  if (vault && !pathPolicy) throw new Error("A vault bridge requires its matching path policy");
  const vaultRecovery = vault && pathPolicy
    ? new VaultRecoveryService(
      new VaultRecoveryRepository(dependencies.database),
      repository,
      vault,
      pathPolicy,
    )
    : undefined;
  const vaultLifecycle = vault
    ? new VaultConnectionLifecycleService(dependencies.database, vault)
    : undefined;
  const attackVaultPolicy = vault
    ? new AttackKnowledgeVaultPolicyService(dependencies.database, vault)
    : undefined;
  const obsidianPlugins = dependencies.obsidianPluginManager ?? (pathPolicy
    ? new ObsidianPluginManager({ database: dependencies.database, pathPolicy })
    : undefined);

  const queryObject = (request: Request): Record<string, unknown> => request.query as Record<string, unknown>;
  const handle = (
    request: Request,
    response: Response,
    operation: (actor: string, access: MemoryAccessPolicy) => unknown,
    status = 200,
  ): void => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const { actor, access } = actorAndAccess(request, dependencies);
      response.status(status).json(operation(actor, access));
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  };
  const mutate = <T>(
    request: Request,
    response: Response,
    operation: (actor: string, access: MemoryAccessPolicy) => T,
    authorizeReplay: (cachedResponse: T, actor: string, access: MemoryAccessPolicy) => void,
    status = 200,
  ): void => {
    handle(request, response, (actor, access) => {
      const key = validatedIdempotencyKey(request);
      return executeIdempotent(
        dependencies.database,
        actor,
        access,
        key,
        { path: request.path, params: request.params, body: request.body },
        () => operation(actor, access),
        (cachedResponse) => authorizeReplay(cachedResponse, actor, access),
      );
    }, status);
  };

  router.use((_request, response, next) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  });

  router.get("/api/v2/brain/summary", (request, response) => {
    handle(request, response, (_actor, access) => brainSummary(dependencies.database, access));
  });

  router.get("/api/v2/brain/control", (request, response) => {
    handle(request, response, () => ({
      schemaVersion: SCHEMA_VERSION,
      policy: getMemoryControlPolicy(dependencies.database),
    }));
  });

  router.put("/api/v2/brain/control", (request, response) => {
    mutate(request, response, (actor) => {
      const body = object(request.body);
      const expected = integer(body.expectedVersion, -1, 0, Number.MAX_SAFE_INTEGER, "expectedVersion");
      const policy = updateMemoryControlPolicy({
        database: dependencies.database,
        expectedVersion: expected,
        actor,
        policy: object(body.policy, "memory control policy"),
      });
      return { schemaVersion: SCHEMA_VERSION, policy };
    }, () => undefined);
  });

  router.get("/api/v2/brain/health", (request, response) => {
    handle(request, response, () => {
      const databaseHealth = getDatabaseHealth(dependencies.database);
      const fts = dependencies.database.prepare(
        "SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = 'memory_nodes_fts'",
      ).get() as { ok: number } | undefined;
      const vaultConnections = (dependencies.database.prepare(
        "SELECT COUNT(*) AS count FROM vault_connections WHERE status = 'connected'",
      ).get() as { count: number }).count;
      return {
        schemaVersion: SCHEMA_VERSION,
        status: databaseHealth.healthy && fts?.ok === 1 ? "healthy" : "degraded",
        database: {
          status: databaseHealth.healthy ? "healthy" : "unhealthy",
          integrity: databaseHealth.integrity,
          journalMode: databaseHealth.journalMode,
          foreignKeys: databaseHealth.foreignKeys,
        },
        search: { status: fts?.ok === 1 ? "healthy" : "unavailable" },
        vault: { enabled: Boolean(vault), connected: Number(vaultConnections) },
      };
    });
  });

  router.get("/api/v2/brain/nodes", (request, response) => {
    handle(request, response, (_actor, access) => listNodes(dependencies.database, access, queryObject(request)));
  });

  router.get("/api/v2/brain/graph", (request, response) => {
    handle(request, response, (_actor, access) => graph(
      dependencies.database,
      repository,
      access,
      queryObject(request),
    ));
  });

  router.get("/api/v2/brain/preferences", (request, response) => {
    handle(request, response, (actor, access) => listOperatorPreferences(
      dependencies.database,
      repository,
      actor,
      access,
    ));
  });

  router.get("/api/v2/brain/nodes/:nodeId/sources", (request, response) => {
    handle(request, response, (_actor, access) => {
      const nodeId = request.params.nodeId!;
      requireAccessibleNode(repository, nodeId, access, true);
      const query = queryObject(request);
      const limit = integer(
        query.limit,
        MEMORY_SOURCE_DETAIL_LIMIT,
        1,
        MEMORY_SOURCE_PAGE_MAXIMUM,
        "memory provenance source page limit",
      );
      return memorySourcePage(dependencies.database, nodeId, access, {
        limit,
        ...(query.cursor === undefined
          ? {}
          : { cursor: decodeMemorySourceCursor(query.cursor, nodeId)! }),
      });
    });
  });

  router.get("/api/v2/brain/nodes/:nodeId/sources/:sourceRecordId/origins", (request, response) => {
    handle(request, response, (_actor, access) => {
      const nodeId = request.params.nodeId!;
      const sourceRecordId = request.params.sourceRecordId!;
      requireAccessibleNode(repository, nodeId, access, true);
      assertIdentifier(sourceRecordId, "memory provenance source record ID");
      const query = queryObject(request);
      const limit = integer(
        query.limit,
        MEMORY_SOURCE_ORIGIN_LIMIT,
        1,
        MEMORY_SOURCE_ORIGIN_MAXIMUM,
        "memory provenance origin page limit",
      );
      return memoryOriginPage(dependencies.database, nodeId, sourceRecordId, access, {
        limit,
        ...(query.cursor === undefined
          ? {}
          : { cursor: decodeMemoryOriginCursor(query.cursor, nodeId, sourceRecordId)! }),
      });
    });
  });

  router.get("/api/v2/brain/nodes/:nodeId", (request, response) => {
    handle(request, response, (_actor, access) => nodeDetail(
      dependencies.database,
      repository,
      request.params.nodeId!,
      access,
    ));
  });

  router.get("/api/v2/brain/candidates", (request, response) => {
    handle(request, response, (_actor, access) => listCandidates(
      dependencies.database,
      repository,
      access,
      queryObject(request),
    ));
  });

  router.post("/api/v2/brain/candidates/:candidateId/confirm", (request, response) => {
    mutate(request, response, (actor, access) => {
      const candidate = requireAccessibleCandidate(repository, request.params.candidateId!, access);
      const control = getMemoryControlPolicy(dependencies.database);
      if (!memoryCandidateAllowed(control, candidate.nodeType)) {
        throw new BrainApiError(403, "memory_retention_disabled", "This memory category is disabled by operator controls", "policy_denied", "Review the Second Brain Memory Control Center before confirming this candidate.");
      }
      const body = object(request.body);
      const edits = body.edits === undefined ? {} : object(body.edits, "candidate edits");
      const node = brain.confirmCandidate(candidate.id, actor, {
        ...(edits.title === undefined ? {} : { title: requiredText(edits.title, "candidate title", 500) }),
        ...(edits.summary === undefined ? {} : { summary: requiredText(edits.summary, "candidate summary", 4_000) }),
        ...(edits.body === undefined ? {} : { body: typeof edits.body === "string" ? edits.body : requiredText(edits.body, "candidate body", 1_000_000) }),
        ...(edits.scope === undefined ? {} : { scope: parseScopeBody(edits.scope) }),
        ...(edits.sensitivity === undefined ? {} : { sensitivity: validateSensitivity(edits.sensitivity) }),
        ...(edits.confidence === undefined ? {} : { confidence: validateConfidence(edits.confidence) }),
      });
      if (!canAccess(node, access)) throw new BrainApiError(403, "memory_scope_denied", "Confirmed memory falls outside operator scope", "policy_denied");
      return { schemaVersion: SCHEMA_VERSION, node };
    }, (cachedResponse, _actor, access) => {
      requireAccessibleCandidate(repository, request.params.candidateId!, access);
      requireAccessibleNode(repository, cachedResponse.node.id, access);
    }, 201);
  });

  router.post("/api/v2/brain/candidates/:candidateId/reject", (request, response) => {
    mutate(request, response, (actor, access) => {
      const candidate = requireAccessibleCandidate(repository, request.params.candidateId!, access);
      const body = object(request.body);
      const reason = requiredText(body.reason, "candidate rejection reason", 1_000);
      const doNotRelearn = body.doNotRelearn === undefined
        ? true
        : typeof body.doNotRelearn === "boolean"
          ? body.doNotRelearn
          : (() => { throw new TypeError("doNotRelearn must be boolean"); })();
      if (doNotRelearn) {
        const suppressionId = brain.rejectAndDoNotRelearn(candidate.id, actor, reason);
        return { schemaVersion: SCHEMA_VERSION, candidateId: candidate.id, suppressionId, status: "suppressed" };
      }
      brain.rejectCandidate(candidate.id, actor, reason);
      return { schemaVersion: SCHEMA_VERSION, candidateId: candidate.id, status: "rejected" };
    }, (_cachedResponse, _actor, access) => {
      requireAccessibleCandidate(repository, request.params.candidateId!, access);
    });
  });

  router.post("/api/v2/brain/nodes/:nodeId/correct", (request, response) => {
    mutate(request, response, (actor, access) => {
      const current = requireAccessibleNode(repository, request.params.nodeId!, access);
      const body = object(request.body);
      expectedVersion(body, current);
      const node = repository.correctNode(current.id, correctionInput(body, actor));
      if (!canAccess(node, access)) throw new BrainApiError(403, "memory_scope_denied", "Corrected memory falls outside operator scope", "policy_denied");
      return { schemaVersion: SCHEMA_VERSION, node };
    }, (_cachedResponse, _actor, access) => {
      requireAccessibleNode(repository, request.params.nodeId!, access);
    });
  });

  router.post("/api/v2/brain/nodes/:nodeId/dispute", (request, response) => {
    mutate(request, response, (actor, access) => {
      const current = requireAccessibleNode(repository, request.params.nodeId!, access);
      const body = object(request.body);
      expectedVersion(body, current);
      const node = repository.correctNode(current.id, {
        lifecycleStatus: "disputed",
        authorType: "operator",
        authorId: actor,
        changeReason: requiredText(body.reason, "dispute reason", 2_000),
      });
      return { schemaVersion: SCHEMA_VERSION, node };
    }, (_cachedResponse, _actor, access) => {
      requireAccessibleNode(repository, request.params.nodeId!, access);
    });
  });

  router.post("/api/v2/brain/nodes/:nodeId/pin", (request, response) => {
    mutate(request, response, (actor, access) => {
      const current = requireAccessibleNode(repository, request.params.nodeId!, access);
      const body = object(request.body);
      expectedVersion(body, current);
      if (typeof body.pinned !== "boolean") throw new TypeError("pinned must be boolean");
      const node = repository.correctNode(current.id, {
        pinned: body.pinned,
        authorType: "operator",
        authorId: actor,
        changeReason: body.pinned ? "Operator pinned memory" : "Operator unpinned memory",
      });
      return { schemaVersion: SCHEMA_VERSION, node };
    }, (_cachedResponse, _actor, access) => {
      requireAccessibleNode(repository, request.params.nodeId!, access);
    });
  });

  router.post("/api/v2/brain/nodes/:nodeId/expire", (request, response) => {
    mutate(request, response, (actor, access) => {
      const current = requireAccessibleNode(repository, request.params.nodeId!, access);
      const body = object(request.body);
      expectedVersion(body, current);
      const expiresAt = requiredText(body.expiresAt, "memory expiry", 100);
      if (Number.isNaN(Date.parse(expiresAt))) throw new TypeError("memory expiry must be an ISO timestamp");
      const node = repository.correctNode(current.id, {
        expiresAt,
        lifecycleStatus: Date.parse(expiresAt) <= Date.now() ? "stale" : current.lifecycleStatus as Exclude<MemoryLifecycle, "forgotten">,
        authorType: "operator",
        authorId: actor,
        changeReason: requiredText(body.reason ?? "Operator set memory expiry", "expiry reason", 2_000),
      });
      return { schemaVersion: SCHEMA_VERSION, node };
    }, (_cachedResponse, _actor, access) => {
      requireAccessibleNode(repository, request.params.nodeId!, access);
    });
  });

  router.post("/api/v2/brain/nodes/:nodeId/forget", (request, response) => {
    mutate(request, response, (actor, access) => {
      const current = requireAccessibleNode(repository, request.params.nodeId!, access);
      const body = object(request.body);
      expectedVersion(body, current);
      const result = vault
        ? vault.forgetMemory(current.id, actor, optionalText(body.reason, "forget reason", 1_000))
        : brain.forget(current.id, actor, optionalText(body.reason, "forget reason", 1_000));
      return { schemaVersion: SCHEMA_VERSION, result };
    }, (_cachedResponse, _actor, access) => {
      requireAccessibleNode(repository, request.params.nodeId!, access, true);
    });
  });

  router.get("/api/v2/brain/context-packs", (request, response) => {
    handle(request, response, (_actor, access) => listContextPacks(
      dependencies.database,
      access,
      request.query as Record<string, unknown>,
    ));
  });

  router.get("/api/v2/brain/context-packs/:contextPackId", (request, response) => {
    handle(request, response, (_actor, access) => contextPackDetail(
      dependencies.database,
      repository,
      request.params.contextPackId!,
      access,
    ));
  });

  router.get("/api/v2/brain/vault/attack-knowledge-preset", (request, response) => {
    handle(request, response, (actor, access) => {
      if (access.allowGlobal === false) {
        throw new BrainApiError(
          403,
          "attack_knowledge_vault_scope_denied",
          "Attack Knowledge Vault setup requires access to reusable global knowledge",
          "policy_denied",
        );
      }
      const raw = request.query.includeConfirmed;
      if (raw !== undefined && raw !== "true" && raw !== "false") {
        throw new TypeError("includeConfirmed must be true or false");
      }
      const includeConfirmed = raw === "true";
      const rawOperatorProfile = request.query.includeOperatorProfile;
      if (rawOperatorProfile !== undefined && rawOperatorProfile !== "true" && rawOperatorProfile !== "false") {
        throw new TypeError("includeOperatorProfile must be true or false");
      }
      const includeOperatorProfile = rawOperatorProfile === "true";
      if (includeOperatorProfile && !includeConfirmed) {
        throw new TypeError("includeOperatorProfile requires includeConfirmed=true");
      }
      return {
        schemaVersion: SCHEMA_VERSION,
        enabled: Boolean(vault && pathPolicy),
        preset: attackKnowledgeVaultPresetPreview(dependencies.database, {
          includeConfirmed,
          includeOperatorProfile,
          operatorProfileId: actor,
        }),
      };
    });
  });

  router.get("/api/v2/brain/vault/brain-atlas", (request, response) => {
    handle(request, response, (_actor, access) => {
      if (access.allowGlobal === false) {
        throw new BrainApiError(
          403,
          "brain_atlas_scope_denied",
          "Brain Atlas health requires access to reusable global knowledge",
          "policy_denied",
        );
      }
      const connectionId = optionalText(request.query.connectionId, "vault connection ID", 256);
      if (connectionId) assertIdentifier(connectionId, "vault connection ID");
      return {
        schemaVersion: SCHEMA_VERSION,
        enabled: Boolean(obsidianPlugins),
        health: obsidianPlugins?.health(connectionId),
      };
    });
  });

  router.post("/api/v2/brain/vault/attack-knowledge-preset/amend", (request, response) => {
    mutate(request, response, (actor, access) => {
      if (!vault || !pathPolicy || !attackVaultPolicy) {
        throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      }
      if (access.allowGlobal === false) {
        throw new BrainApiError(
          403,
          "attack_knowledge_vault_scope_denied",
          "Attack Knowledge Vault scope amendment requires access to reusable global knowledge",
          "policy_denied",
        );
      }
      const body = object(request.body);
      if (body.permissionGranted !== true) {
        throw new TypeError("Explicit Vault filesystem permission is required for the scope amendment");
      }
      if (body.includeConfirmed !== true) {
        throw new TypeError("The supported scope amendment must include confirmed attack knowledge");
      }
      const expectedCurrentPolicyHash = requiredText(
        body.expectedCurrentPolicyHash,
        "expected current Attack Knowledge Vault policy hash",
        64,
      );
      const expectedTargetPolicyHash = requiredText(
        body.expectedTargetPolicyHash,
        "expected target Attack Knowledge Vault policy hash",
        64,
      );
      if (!/^[a-f0-9]{64}$/u.test(expectedCurrentPolicyHash) || !/^[a-f0-9]{64}$/u.test(expectedTargetPolicyHash)) {
        throw new TypeError("Attack Knowledge Vault policy hashes must be lowercase SHA-256 digests");
      }
      const includeOperatorProfile = body.includeOperatorProfile === true;
      if (includeOperatorProfile && body.operatorProfileAcknowledged !== true) {
        throw new TypeError("Explicit Operator Profile Vault scope acknowledgement is required");
      }
      if (!includeOperatorProfile && body.amendmentAcknowledged !== true) {
        throw new TypeError("Explicit confirmed-knowledge scope amendment acknowledgement is required");
      }
      const connectionId = requiredText(body.connectionId, "Vault connection ID", 256);
      const expectedUpdatedAt = requiredText(body.expectedUpdatedAt, "expected Vault connection version", 64);
      const reason = requiredText(body.reason, "scope amendment reason", 1_000);
      const result = includeOperatorProfile
        ? attackVaultPolicy.includeOperatorProfile({
            connectionId,
            expectedUpdatedAt,
            expectedCurrentPolicyHash,
            expectedTargetPolicyHash,
            actor,
            reason,
            operatorProfileAcknowledged: true,
          })
        : attackVaultPolicy.includeConfirmed({
            connectionId,
            expectedUpdatedAt,
            expectedCurrentPolicyHash,
            expectedTargetPolicyHash,
            actor,
            reason,
            amendmentAcknowledged: true,
          });
      appendVaultAudit(dependencies.database, {
        actor,
        action: "vault.health.verified",
        resourceType: "vault_connection",
        resourceId: result.connection.id,
        reason: "Attack Knowledge Vault passed its existing-path filesystem round-trip for the amended scope",
        details: activeVaultHealthProofDetails(
          result.connection,
          result.connection.vaultPath,
          result.filesystemHealth.checks,
          {
            scopeAmendment: true,
            policyHash: result.targetPolicyHash,
            filesystemCheckedAt: result.filesystemHealth.checkedAt,
          },
        ),
        occurredAt: result.amendedAt,
      });
      dependencies.onVaultConnectionChanged?.();
      return {
        schemaVersion: SCHEMA_VERSION,
        connection: {
          ...result.connection,
          vaultPath: relative(pathPolicy.allowedRoot, result.connection.vaultPath) || ".",
        },
        result: {
          ...result,
          connection: undefined,
        },
        preset: attackKnowledgeVaultPresetPreview(dependencies.database, {
          includeConfirmed: true,
          includeOperatorProfile,
          operatorProfileId: actor,
        }),
      };
    }, (cachedResponse, _actor, access) => {
      if (access.allowGlobal === false) denyHiddenBrainResource();
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const current = vault.requireConnection(cachedResponse.connection.id);
      const operatorProfileAmendment = "operatorProfileNodeCount" in cachedResponse.result;
      const preview = attackKnowledgeVaultPresetPreview(dependencies.database, {
        includeConfirmed: true,
        includeOperatorProfile: operatorProfileAmendment,
        operatorProfileId: _actor,
      });
      if (preview.alreadyActiveConnectionId !== current.id) {
        throw new AttackKnowledgeVaultScopeAmendmentConflictError();
      }
    });
  });

  router.post("/api/v2/brain/vault/attack-knowledge-preset/activate", (request, response) => {
    mutate(request, response, (actor, access) => {
      if (!vault || !pathPolicy) {
        throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      }
      if (access.allowGlobal === false) {
        throw new BrainApiError(
          403,
          "attack_knowledge_vault_scope_denied",
          "Attack Knowledge Vault activation requires access to reusable global knowledge",
          "policy_denied",
        );
      }
      const body = object(request.body);
      if (body.permissionGranted !== true) {
        throw new TypeError("Explicit vault filesystem permission is required");
      }
      if (body.activationAcknowledged !== true) {
        throw new TypeError("Explicit Attack Knowledge Vault activation acknowledgement is required");
      }
      if (body.includeConfirmed !== undefined && typeof body.includeConfirmed !== "boolean") {
        throw new TypeError("includeConfirmed must be a boolean");
      }
      const includeConfirmed = body.includeConfirmed === true;
      const expectedPolicyHash = requiredText(body.expectedPolicyHash, "expected Attack Knowledge Vault policy hash", 64);
      const currentPolicyHash = attackKnowledgeVaultPolicyHash({ includeConfirmed });
      if (expectedPolicyHash !== currentPolicyHash) {
        throw new BrainApiError(
          409,
          "attack_knowledge_vault_policy_changed",
          "The Attack Knowledge Vault projection policy changed before activation",
          "conflict",
          "Refresh the setup preview, review the current categories and privacy boundary, then activate that exact policy.",
        );
      }
      const preview = attackKnowledgeVaultPresetPreview(dependencies.database, {
        includeConfirmed,
        operatorProfileId: actor,
      });
      if (preview.alreadyActiveConnectionId) {
        const existing = vault.requireConnection(preview.alreadyActiveConnectionId);
        return {
          schemaVersion: SCHEMA_VERSION,
          connection: {
            ...existing,
            vaultPath: relative(pathPolicy.allowedRoot, existing.vaultPath) || ".",
          },
          preset: preview,
          alreadyActive: true,
        };
      }
      if (preview.activePreset) {
        throw new BrainApiError(
          409,
          "attack_knowledge_vault_scope_amendment_required",
          "The Attack Knowledge Vault is already connected with a different reviewed lifecycle scope",
          "conflict",
          preview.confirmedScopeUpgrade
            ? "Review and apply the in-place confirmed-knowledge scope amendment. The existing connection ID, path, notes, and sync history will be retained."
            : "Use the existing broader Attack Knowledge Vault connection; a second preset connection will not be created.",
        );
      }
      const connection = vault.connect({
        vaultPath: ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
        displayName: ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
        syncScope: attackKnowledgeVaultSyncScope({ includeConfirmed }),
        permissionGranted: true,
      });
      const health = vault.verifyExistingVaultPath(connection.vaultPath);
      const activatedAt = health.checkedAt;
      appendVaultAudit(dependencies.database, {
        actor,
        action: "vault.health.verified",
        resourceType: "vault_connection",
        resourceId: connection.id,
        reason: "Attack Knowledge Vault passed its required filesystem round-trip",
        details: activeVaultHealthProofDetails(
          connection,
          health.vaultRoot,
          health.checks,
          { presetId: preview.id, policyHash: currentPolicyHash },
        ),
        occurredAt: activatedAt,
      });
      appendVaultAudit(dependencies.database, {
        actor,
        action: "vault.attack_knowledge_preset.activated",
        resourceType: "vault_connection",
        resourceId: connection.id,
        reason: "Operator activated the exact reviewed Attack Knowledge Vault projection policy",
        details: {
          presetId: preview.id,
          policyHash: currentPolicyHash,
          syncScope: connection.syncScope,
          includeConfirmed,
          policyEligibleNodeCountAtActivation: preview.projection.policyEligibleNodeCount,
        },
        occurredAt: activatedAt,
      });
      dependencies.onVaultConnectionChanged?.();
      return {
        schemaVersion: SCHEMA_VERSION,
        connection: {
          ...connection,
          vaultPath: relative(pathPolicy.allowedRoot, connection.vaultPath) || ".",
        },
        preset: attackKnowledgeVaultPresetPreview(dependencies.database, {
          includeConfirmed,
          operatorProfileId: actor,
        }),
        alreadyActive: false,
      };
    }, (cachedResponse, _actor, access) => {
      if (access.allowGlobal === false) denyHiddenBrainResource();
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      vault.requireConnection(cachedResponse.connection.id);
    }, 201);
  });

  router.get("/api/v2/brain/vault", (request, response) => {
    handle(request, response, (_actor, access) => {
      if (!vault || !pathPolicy) {
        return {
          schemaVersion: SCHEMA_VERSION,
          enabled: false,
          connections: [],
          syncStates: [],
          conflicts: [],
        };
      }
      const connections = dependencies.database.prepare(`
        SELECT id, vault_path, display_name, status, sync_scope_json,
          permission_granted_at, last_sync_at, created_at, updated_at,
          (
            SELECT ar.occurred_at FROM audit_records ar
            WHERE ar.resource_type = 'vault_connection'
              AND ar.resource_id = vault_connections.id
              AND ar.action = 'vault.health.verified'
            ORDER BY ar.occurred_at DESC LIMIT 1
          ) AS last_health_check_at
        FROM vault_connections ORDER BY updated_at DESC
      `).all() as Array<Record<string, unknown>>;
      const connectionById = new Map(connections
        .filter((item) => item.status !== "disconnected")
        .map((item) => [String(item.id), item]));
      const syncAccess = accessSql("mn", access);
      const stateCountRows = dependencies.database.prepare(`
        SELECT vs.connection_id, vs.status, COUNT(*) AS count
        FROM vault_sync_state vs
        LEFT JOIN memory_nodes mn ON mn.id = vs.node_id
        WHERE (vs.node_id IS NOT NULL AND ${syncAccess.sql})
          OR (vs.node_id IS NULL AND ? = 1)
        GROUP BY vs.connection_id, vs.status
      `).all(...syncAccess.params, access.allEngagements ? 1 : 0) as Array<{
        connection_id: string;
        status: string;
        count: number;
      }>;
      const stateCountsByConnection = new Map<string, { trackedNoteCount: number; needsReviewCount: number }>();
      for (const row of stateCountRows) {
        const counts = stateCountsByConnection.get(row.connection_id)
          ?? { trackedNoteCount: 0, needsReviewCount: 0 };
        counts.trackedNoteCount += Number(row.count);
        if (["conflict", "quarantined", "error"].includes(row.status)) {
          counts.needsReviewCount += Number(row.count);
        }
        stateCountsByConnection.set(row.connection_id, counts);
      }
      const states = dependencies.database.prepare(`
        SELECT id, connection_id, node_id, relative_path, database_version, status,
          last_scanned_at, last_synced_at, error_message
        FROM vault_sync_state ORDER BY COALESCE(last_scanned_at, '') DESC LIMIT 250
      `).all() as Array<Record<string, unknown>>;
      const conflicts = dependencies.database.prepare(`
        SELECT vc.id, vc.connection_id, vc.sync_state_id, vc.node_id, vc.base_hash,
          vc.database_hash, vc.vault_hash, vc.status, vc.resolution_reason,
          vc.resolved_by, vc.resolved_at, vc.created_at, vs.database_version,
          vs.relative_path
        FROM vault_conflicts vc JOIN vault_sync_state vs ON vs.id = vc.sync_state_id
        ORDER BY vc.created_at DESC LIMIT 100
      `).all() as Array<Record<string, unknown>>;
      return {
        schemaVersion: SCHEMA_VERSION,
        enabled: true,
        syncEnabled: vault.vaultSyncEnabled(),
        projectionLifecycleStatuses: vault.projectionLifecycleStatuses(),
        allowedRootLabel: basename(pathPolicy.allowedRoot),
        connections: connections.map((item) => {
          const aggregateCounts = stateCountsByConnection.get(String(item.id));
          let obsidianUrl: string | undefined;
          let pathAvailable = true;
          try {
            vault.requireExistingConnection(String(item.id));
          } catch {
            pathAvailable = false;
          }
          if (item.status !== "disconnected" && pathAvailable) {
            try {
              obsidianUrl = vault.deepLink(String(item.id));
            } catch {
              pathAvailable = false;
            }
          }
          return {
            id: item.id,
            displayName: item.display_name,
            status: item.status === "disconnected"
              ? "disconnected"
              : !pathAvailable
              ? "error"
              : item.status === "connected" && !item.last_health_check_at ? "degraded" : item.status,
            pathAvailable,
            vaultPath: relative(pathPolicy.allowedRoot, String(item.vault_path)) || ".",
            syncScope: JSON.parse(String(item.sync_scope_json)),
            permissionGrantedAt: item.permission_granted_at,
            lastSyncAt: item.last_sync_at,
            lastHealthCheckAt: item.last_health_check_at,
            healthChecks: item.last_health_check_at
              ? { write: true, read: true, rename: true, delete: true }
              : undefined,
            createdAt: item.created_at,
            updatedAt: item.updated_at,
            ...(aggregateCounts ?? {}),
            ...(obsidianUrl ? { obsidianUrl } : {}),
          };
        }),
        syncStates: states.flatMap<Record<string, unknown>>((item) => {
          if (!item.node_id) return access.allEngagements ? [{
            id: item.id,
            connectionId: item.connection_id,
            nodeId: null,
            relativePath: item.relative_path,
            databaseVersion: item.database_version,
            status: item.status,
            lastScannedAt: item.last_scanned_at,
            lastSyncedAt: item.last_synced_at,
            errorMessage: item.error_message,
            obsidianUrl: (() => {
              try { return vault.deepLink(String(item.connection_id), String(item.relative_path)); }
              catch { return undefined; }
            })(),
          }] : [];
          const node = repository.getNode(String(item.node_id), true);
          if (!node || !canAccess(node, access)) return [];
          try {
            vault.assertConnectionNodeAllowed(String(item.connection_id), node.id);
          } catch {
            return [];
          }
          return [{
          id: item.id,
          connectionId: item.connection_id,
          nodeId: item.node_id,
          relativePath: item.relative_path,
          databaseVersion: item.database_version,
          status: item.status,
          lastScannedAt: item.last_scanned_at,
          lastSyncedAt: item.last_synced_at,
          errorMessage: item.error_message,
          obsidianUrl: connectionById.has(String(item.connection_id))
            ? (() => {
              try { return vault.deepLink(String(item.connection_id), String(item.relative_path)); }
              catch { return undefined; }
            })()
            : undefined,
          }];
        }),
        conflicts: conflicts.flatMap((item) => {
          if (!item.node_id) return [];
          const node = repository.getNode(String(item.node_id), true);
          if (!node || !canAccess(node, access)) return [];
          try {
            vault.assertConnectionNodeAllowed(String(item.connection_id), node.id);
          } catch {
            return [];
          }
          return [{
          id: item.id,
          connectionId: item.connection_id,
          syncStateId: item.sync_state_id,
          nodeId: item.node_id,
          relativePath: item.relative_path,
          baseHash: item.base_hash,
          databaseHash: item.database_hash,
          vaultHash: item.vault_hash,
            status: item.status === "open" ? "open" : item.status === "dismissed" ? "dismissed" : "resolved",
            databaseVersion: item.database_version,
            resolutionReason: item.resolution_reason,
            resolvedBy: item.resolved_by,
            resolvedAt: item.resolved_at,
            detectedAt: item.created_at,
          }];
        }),
      };
    });
  });

  router.post("/api/v2/brain/vault/health-check", (request, response) => {
    mutate(request, response, (actor) => {
      if (!vault || !pathPolicy) {
        throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      }
      const body = object(request.body);
      const connectionId = optionalText(body.connectionId, "vault connection ID", 256);
      if (connectionId && body.vaultPath !== undefined) {
        throw new TypeError("Vault health check must target either a connection or a candidate path");
      }
      if (!connectionId && body.permissionGranted !== true) {
        throw new TypeError("Explicit vault filesystem permission is required");
      }
      const connection = connectionId ? vault.requireConnection(connectionId) : undefined;
      const requestedPath = connection?.vaultPath ?? requiredText(body.vaultPath, "vault path", 1_000);
      let verifiedConnection = connection;
      let health = connection
        ? vault.verifyExistingVaultPath(requestedPath)
        : vault.verifyVaultPath(requestedPath);
      if (connection && connection.status !== "connected") {
        vault.markConnectionHealth(connection.id, "connected");
        verifiedConnection = vault.requireConnection(connection.id);
        health = vault.verifyExistingVaultPath(verifiedConnection.vaultPath);
      }
      const vaultPath = relative(pathPolicy.allowedRoot, health.vaultRoot) || ".";
      const pathFingerprint = activeVaultPathFingerprint(health.vaultRoot);
      appendVaultAudit(dependencies.database, {
        actor,
        action: "vault.health.verified",
        resourceType: verifiedConnection ? "vault_connection" : "vault_path_candidate",
        resourceId: verifiedConnection?.id ?? pathFingerprint,
        reason: verifiedConnection
          ? "Operator verified a connected Obsidian vault"
          : "Operator verified a candidate Obsidian vault path",
        details: verifiedConnection
          ? activeVaultHealthProofDetails(
              verifiedConnection,
              health.vaultRoot,
              health.checks,
              { allowedRootLabel: basename(pathPolicy.allowedRoot) },
            )
          : {
              pathFingerprint,
              allowedRootLabel: basename(pathPolicy.allowedRoot),
              checks: health.checks,
            },
        occurredAt: health.checkedAt,
      });
      return {
        schemaVersion: SCHEMA_VERSION,
        result: {
          status: "healthy",
          ...(verifiedConnection ? { connectionId: verifiedConnection.id } : {}),
          vaultPath,
          checkedAt: health.checkedAt,
          checks: health.checks,
          message: "Vault path completed the write, read, rename, and delete round-trip.",
        },
      };
    }, (cachedResponse) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      vault.assertVaultSyncAllowed();
      if (cachedResponse.result.connectionId) vault.requireConnection(cachedResponse.result.connectionId);
    });
  });

  router.post("/api/v2/brain/vault/connect", (request, response) => {
    mutate(request, response, (actor) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const body = object(request.body);
      if (body.permissionGranted !== true) throw new TypeError("Explicit vault filesystem permission is required");
      const requestedDisplayName = requiredText(body.displayName, "vault display name", 200);
      const requestedPath = requiredText(body.vaultPath, "vault path", 1_000);
      const requestedPathLeaf = requestedPath
        .replaceAll("\\", "/")
        .split("/")
        .filter(Boolean)
        .at(-1);
      if (
        requestedDisplayName === ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME
        || requestedPathLeaf === ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH
      ) {
        throw new BrainApiError(
          409,
          "attack_knowledge_vault_preset_required",
          "The reserved Attack Knowledge Vault name and path can only be activated from its reviewed preset",
          "conflict",
          "Open the Attack Knowledge Vault setup preview, review its categories and privacy boundary, then activate that exact policy.",
        );
      }
      const connection = vault.connect({
        vaultPath: requestedPath,
        displayName: requestedDisplayName,
        syncScope: body.syncScope === undefined ? {} : object(body.syncScope, "vault sync scope"),
        permissionGranted: true,
      });
      const health = vault.verifyExistingVaultPath(connection.vaultPath);
      const verifiedAt = health.checkedAt;
      appendVaultAudit(dependencies.database, {
        actor,
        action: "vault.health.verified",
        resourceType: "vault_connection",
        resourceId: connection.id,
        reason: "Vault connection passed its required filesystem round-trip",
        details: activeVaultHealthProofDetails(
          connection,
          health.vaultRoot,
          health.checks,
        ),
        occurredAt: verifiedAt,
      });
      appendVaultAudit(dependencies.database, {
        actor,
        action: "vault.connection.connected",
        resourceType: "vault_connection",
        resourceId: connection.id,
        reason: "Operator connected an explicitly permitted Obsidian vault",
        details: {
          healthVerified: true,
          syncScope: connection.syncScope,
        },
        occurredAt: verifiedAt,
      });
      dependencies.onVaultConnectionChanged?.();
      return {
        schemaVersion: SCHEMA_VERSION,
        connection: {
          ...connection,
          vaultPath: pathPolicy ? relative(pathPolicy.allowedRoot, connection.vaultPath) || "." : ".",
        },
      };
    }, (cachedResponse) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      vault.requireConnection(cachedResponse.connection.id);
    }, 201);
  });

  router.post("/api/v2/brain/vault/:connectionId/disconnect", (request, response) => {
    mutate(request, response, (actor, access) => {
      if (!vault || !vaultLifecycle || !pathPolicy) {
        throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      }
      if (access.allEngagements !== true || access.allowGlobal === false) {
        throw new BrainApiError(
          403,
          "vault_disconnect_admin_required",
          "Disconnecting an Obsidian projection requires workspace-wide Second Brain access",
          "policy_denied",
          "Use an authenticated operator authorized to manage every scope represented by this Vault.",
        );
      }
      const body = object(request.body);
      if (body.controlPlane !== "ti_scale") {
        throw new BrainApiError(
          409,
          "vault_control_plane_conflict",
          "Vault lifecycle changes are restricted to the Ti-Scale control plane",
          "conflict",
          "Refresh this V2 Vault connection and retry without a legacy or shared-control request.",
        );
      }
      if (body.disconnectAcknowledged !== true) {
        throw new TypeError("Explicit Vault disconnect acknowledgement is required");
      }
      if (body.allowProjectionDegraded !== undefined && typeof body.allowProjectionDegraded !== "boolean") {
        throw new TypeError("allowProjectionDegraded must be a boolean");
      }
      const reason = requiredText(body.reason, "Vault disconnect reason", 500);
      if (reason.length < 12) throw new TypeError("Vault disconnect reason must contain at least 12 characters");
      const connectionId = requiredText(request.params.connectionId, "vault connection ID", 256);
      assertIdentifier(connectionId, "vault connection ID");
      const expectedUpdatedAt = requiredText(body.expectedUpdatedAt, "expected vault connection version", 100);
      if (Number.isNaN(Date.parse(expectedUpdatedAt))) {
        throw new TypeError("Expected vault connection version must be an ISO timestamp");
      }

      const disconnected = vaultLifecycle.disconnect({
        connectionId,
        expectedUpdatedAt,
        allowProjectionDegraded: body.allowProjectionDegraded === true,
      });
      const auditRecordId = appendVaultAudit(dependencies.database, {
        actor,
        action: "vault.connection.disconnected",
        resourceType: "vault_connection",
        resourceId: connectionId,
        reason,
        details: {
          previousStatus: disconnected.previousStatus,
          connectionVersion: disconnected.connectionVersion,
          expectedConnectionVersion: expectedUpdatedAt,
          projectionState: disconnected.projectionState,
          replacementConnectionId: disconnected.replacementConnectionId ?? null,
          activeRunCount: disconnected.activeRunCount,
          activeRunImpact: disconnected.activeRunImpact,
          syncStopped: disconnected.syncStopped,
          filesDeleted: disconnected.filesDeleted,
          notesRewritten: disconnected.notesRewritten,
          controlPlane: "ti_scale",
        },
        occurredAt: disconnected.disconnectedAt,
      });
      dependencies.onVaultConnectionChanged?.();
      return {
        schemaVersion: SCHEMA_VERSION,
        connection: {
          ...disconnected.connection,
          vaultPath: relative(pathPolicy.allowedRoot, disconnected.connection.vaultPath) || ".",
        },
        result: {
          status: "disconnected",
          connectionId,
          disconnectedAt: disconnected.disconnectedAt,
          connectionVersion: disconnected.connectionVersion,
          projectionState: disconnected.projectionState,
          ...(disconnected.replacementConnectionId
            ? { replacementConnectionId: disconnected.replacementConnectionId }
            : {}),
          activeRunCount: disconnected.activeRunCount,
          activeRunImpact: disconnected.activeRunImpact,
          syncStopped: true,
          filesDeleted: 0,
          notesRewritten: 0,
          auditRecordId,
          message: disconnected.projectionState === "healthy"
            ? "Vault projection disconnected. A health-verified replacement remains active; no Vault files or notes were changed."
            : "Vault projection disconnected into a controlled degraded state. Canonical Second Brain memory remains available; no Vault files or notes were changed.",
        },
      };
    }, (cachedResponse, _actor, access) => {
      if (access.allEngagements !== true || access.allowGlobal === false) denyHiddenBrainResource();
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const current = vault.requireExistingConnection(cachedResponse.result.connectionId);
      if (
        current.status !== "disconnected"
        || current.updatedAt !== cachedResponse.result.connectionVersion
      ) {
        throw new VaultConnectionVersionConflictError();
      }
    });
  });

  router.post("/api/v2/brain/vault/export", (request, response) => {
    mutate(request, response, (actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const body = object(request.body);
      vault.assertVaultSyncAllowed();
      const connectionId = requiredText(body.connectionId, "vault connection ID", 256);
      const connectionNodeIds = accessibleConnectionNodeIds(
        dependencies.database,
        vault,
        connectionId,
        access,
      );
      const allowedTargetIds = new Set(connectionNodeIds);
      const nodeId = optionalText(body.nodeId, "memory node ID", 256);
      if (nodeId) {
        requireAccessibleNode(repository, nodeId, access);
        vault.assertConnectionNodeAllowed(connectionId, nodeId);
        assertLegacyVaultProjectionApproved(dependencies.database, connectionId, [nodeId]);
        const exported = vault.exportNode(connectionId, nodeId, allowedTargetIds);
        repository.recordNodeExportAudit({ nodeId, actor, connectionId, status: exported.status });
        const result = {
          ...exported,
          authorizationFingerprint: vaultAuthorizationFingerprint(vault, connectionId, connectionNodeIds),
        };
        return { schemaVersion: SCHEMA_VERSION, result };
      }
      const nodeIds = connectionNodeIds;
      const bounded = nodeIds.slice(0, 250);
      assertLegacyVaultProjectionApproved(dependencies.database, connectionId, bounded);
      const results = bounded.map((id) => {
        const result = vault.exportNode(connectionId, id, allowedTargetIds);
        repository.recordNodeExportAudit({
          nodeId: id,
          actor,
          connectionId,
          status: result.status,
        });
        return result;
      });
      const conflictCount = results.filter((item) => item.status === "conflict").length;
      const result = {
        connectionId,
        authorizationFingerprint: vaultAuthorizationFingerprint(vault, connectionId, connectionNodeIds),
        status: conflictCount > 0 ? "conflict" : nodeIds.length > 250 ? "partial" : "synced",
        message: nodeIds.length > 250
          ? `Exported the first 250 accessible notes; continue with targeted export for the remaining records.`
          : `Exported ${results.length} accessible canonical notes${conflictCount > 0 ? `; ${conflictCount} require conflict resolution` : ""}.`,
      };
      return { schemaVersion: SCHEMA_VERSION, result };
    }, (cachedResponse, _actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      vault.assertVaultSyncAllowed();
      vault.requireConnection(cachedResponse.result.connectionId);
      assertVaultAuthorizationReplay(
        dependencies.database,
        vault,
        cachedResponse.result.connectionId,
        access,
        cachedResponse.result.authorizationFingerprint,
      );
      const nodeId = optionalText(object(request.body).nodeId, "memory node ID", 256);
      if (nodeId) {
        requireAccessibleNode(repository, nodeId, access);
        vault.assertConnectionNodeAllowed(cachedResponse.result.connectionId, nodeId);
        assertLegacyVaultProjectionApproved(
          dependencies.database,
          cachedResponse.result.connectionId,
          [nodeId],
        );
      } else {
        const currentNodeIds = accessibleConnectionNodeIds(
          dependencies.database,
          vault,
          cachedResponse.result.connectionId,
          access,
        );
        assertLegacyVaultProjectionApproved(
          dependencies.database,
          cachedResponse.result.connectionId,
          currentNodeIds.slice(0, 250),
        );
      }
    });
  });

  router.post("/api/v2/brain/vault/import", (request, response) => {
    mutate(request, response, (actor, access) => {
      if (!vault || !pathPolicy) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const body = object(request.body);
      vault.assertVaultSyncAllowed();
      const connectionId = requiredText(body.connectionId, "vault connection ID", 256);
      const connection = vault.requireConnection(connectionId);
      const connectionNodeIds = accessibleConnectionNodeIds(
        dependencies.database,
        vault,
        connectionId,
        access,
      );
      const allowedTargetIds = new Set(connectionNodeIds);
      const requestedPath = optionalText(body.relativePath, "vault note path", 1_000);
      const paths = requestedPath ? [requestedPath] : boundedMarkdownFiles(pathPolicy, connection.vaultPath);
      const importOne = (relativePath: string) => {
        const path = pathPolicy.resolveRelative(connection.vaultPath, relativePath);
        let note;
        try {
          note = parseObsidianNote(readFileSync(path, "utf8"));
        } catch {
          // The bridge owns malformed-note quarantine; privacy validation cannot
          // inspect malformed content and deliberately delegates only that case.
          return vault.importNote(connectionId, relativePath, actor, false, allowedTargetIds);
        }
        const policyProbe = { scope: note.scope, sensitivity: note.sensitivity } as MemoryNode;
        if (!canAccess(policyProbe, access)) {
          throw new BrainApiError(403, "memory_scope_denied", "Imported note scope exceeds operator access", "policy_denied");
        }
        const existing = repository.getNode(note.id);
        if (existing && !canAccess(existing, access)) denyHiddenBrainResource();
        if (existing) vault.assertConnectionNodeAllowed(connectionId, existing.id);
        if (existing && !relativePath.startsWith("00 Inbox/")) {
          const state = dependencies.database.prepare(`
            SELECT id FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
          `).get(connectionId, existing.id);
          return state
            ? vault.syncNode(connectionId, existing.id, actor, allowedTargetIds)
            : vault.exportNode(connectionId, existing.id, allowedTargetIds);
        }
        return vault.importNote(connectionId, relativePath, actor, false, allowedTargetIds);
      };
      if (requestedPath) {
        const imported = importOne(requestedPath);
        const result = {
          connectionId,
          authorizationFingerprint: vaultAuthorizationFingerprint(
            vault,
            connectionId,
            accessibleConnectionNodeIds(dependencies.database, vault, connectionId, access),
          ),
          nodeId: imported.nodeId,
          relativePath: imported.relativePath,
          status: imported.status,
          message: imported.status === "candidate"
            ? "Vault note was imported as a reviewable memory candidate."
            : imported.status === "quarantined"
              ? "Malformed vault note was quarantined for review."
              : "Vault note was imported and versioned.",
        };
        return { schemaVersion: SCHEMA_VERSION, result };
      }
      const bounded = paths.slice(0, 250);
      const results = bounded.map(importOne);
      const quarantined = results.filter((item) => item.status === "quarantined").length;
      const result = {
        connectionId,
        authorizationFingerprint: vaultAuthorizationFingerprint(
          vault,
          connectionId,
          accessibleConnectionNodeIds(dependencies.database, vault, connectionId, access),
        ),
        status: quarantined > 0 ? "quarantined" : paths.length > 250 ? "partial" : "synced",
        message: paths.length > 250
          ? "Imported the first 250 vault notes; use targeted import for the remaining files."
          : `Processed ${results.length} vault notes${quarantined > 0 ? `; ${quarantined} malformed notes were quarantined` : ""}.`,
      };
      return { schemaVersion: SCHEMA_VERSION, result };
    }, (cachedResponse, _actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      vault.assertVaultSyncAllowed();
      vault.requireConnection(cachedResponse.result.connectionId);
      assertVaultAuthorizationReplay(
        dependencies.database,
        vault,
        cachedResponse.result.connectionId,
        access,
        cachedResponse.result.authorizationFingerprint,
      );
      if ("nodeId" in cachedResponse.result && typeof cachedResponse.result.nodeId === "string") {
        requireAccessibleNode(repository, cachedResponse.result.nodeId, access);
        vault.assertConnectionNodeAllowed(cachedResponse.result.connectionId, cachedResponse.result.nodeId);
      }
    });
  });

  router.post("/api/v2/brain/vault/sync", (request, response) => {
    mutate(request, response, (actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const body = object(request.body);
      vault.assertVaultSyncAllowed();
      const connectionId = requiredText(body.connectionId, "vault connection ID", 256);
      const connectionNodeIds = accessibleConnectionNodeIds(
        dependencies.database,
        vault,
        connectionId,
        access,
      );
      const allowedTargetIds = new Set(connectionNodeIds);
      const nodeId = optionalText(body.nodeId, "memory node ID", 256);
      if (nodeId) {
        requireAccessibleNode(repository, nodeId, access);
        vault.assertConnectionNodeAllowed(connectionId, nodeId);
        const synchronized = vault.syncNode(connectionId, nodeId, actor, allowedTargetIds);
        return {
          schemaVersion: SCHEMA_VERSION,
          result: {
            ...synchronized,
            authorizationFingerprint: vaultAuthorizationFingerprint(
              vault,
              connectionId,
              accessibleConnectionNodeIds(dependencies.database, vault, connectionId, access),
            ),
          },
        };
      }
      const clause = accessSql("mn", access);
      const lifecycleStatuses = vault.projectionLifecycleStatuses();
      const lifecyclePlaceholders = lifecycleStatuses.map(() => "?").join(",");
      const rows = dependencies.database.prepare(`
        SELECT vs.node_id FROM vault_sync_state vs
        JOIN memory_nodes mn ON mn.id = vs.node_id
        WHERE vs.connection_id = ? AND vs.node_id IS NOT NULL AND vs.status != 'deleted'
          AND ${clause.sql}
          AND mn.lifecycle_status IN (${lifecyclePlaceholders})
        ORDER BY COALESCE(vs.last_scanned_at, '') ASC LIMIT 251
      `).all(connectionId, ...clause.params, ...lifecycleStatuses) as Array<{ node_id: string }>;
      const accessible = rows.map((item) => item.node_id).filter((id) => allowedTargetIds.has(id));
      const results = accessible.slice(0, 250).map((id) => (
        vault.syncNode(connectionId, id, actor, allowedTargetIds)
      ));
      const conflicts = results.filter((item) => item.status === "conflict").length;
      const result = {
        connectionId,
        authorizationFingerprint: vaultAuthorizationFingerprint(
          vault,
          connectionId,
          accessibleConnectionNodeIds(dependencies.database, vault, connectionId, access),
        ),
        status: conflicts > 0 ? "conflict" : accessible.length > 250 ? "partial" : "synced",
        message: accessible.length > 250
          ? "Synchronized the first 250 tracked notes; continue with targeted synchronization."
          : `Synchronized ${results.length} tracked notes${conflicts > 0 ? `; ${conflicts} require conflict resolution` : ""}.`,
      };
      return { schemaVersion: SCHEMA_VERSION, result };
    }, (cachedResponse, _actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      vault.assertVaultSyncAllowed();
      vault.requireConnection(cachedResponse.result.connectionId);
      assertVaultAuthorizationReplay(
        dependencies.database,
        vault,
        cachedResponse.result.connectionId,
        access,
        cachedResponse.result.authorizationFingerprint,
      );
      if ("nodeId" in cachedResponse.result && typeof cachedResponse.result.nodeId === "string") {
        requireAccessibleNode(repository, cachedResponse.result.nodeId, access);
        vault.assertConnectionNodeAllowed(cachedResponse.result.connectionId, cachedResponse.result.nodeId);
      }
    });
  });

  const recoverVault = (
    operation: "repair" | "reindex",
    request: Request,
    response: Response,
  ): void => {
    mutate(request, response, (actor, access) => {
      if (!vault || !vaultRecovery) {
        throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      }
      if (access.allEngagements !== true) {
        throw new BrainApiError(
          403,
          "vault_recovery_admin_required",
          "Vault recovery requires workspace-wide Second Brain access",
          "policy_denied",
          "Use an operator role authorized to reconcile every engagement represented by this Vault.",
        );
      }
      const body = object(request.body);
      if (body.controlPlane !== "ti_scale") {
        throw new BrainApiError(
          409,
          "vault_control_plane_conflict",
          "Vault recovery is restricted to the Ti-Scale control plane",
          "conflict",
          "Refresh this V2 Vault connection and retry without a legacy or shared-control request.",
        );
      }
      const connectionId = requiredText(body.connectionId, "vault connection ID", 256);
      const expectedUpdatedAt = requiredText(body.expectedUpdatedAt, "expected vault connection version", 100);
      if (Number.isNaN(Date.parse(expectedUpdatedAt))) {
        throw new TypeError("Expected vault connection version must be an ISO timestamp");
      }
      // Prove the configured directory still exists before any generic Vault
      // helper can resolve/create candidate paths.
      vault.requireConnection(connectionId);
      const nodeIds = accessibleConnectionNodeIds(
        dependencies.database,
        vault,
        connectionId,
        access,
      );
      const recovered = vaultRecovery.run({
        operation,
        connectionId,
        expectedUpdatedAt,
        allowedNodeIds: new Set(nodeIds),
      });
      const recoveredConnection = vault.requireConnection(connectionId);
      const authorizationFingerprint = vaultAuthorizationFingerprint(
        vault,
        connectionId,
        accessibleConnectionNodeIds(dependencies.database, vault, connectionId, access),
      );
      appendVaultAudit(dependencies.database, {
        actor,
        action: "vault.health.verified",
        resourceType: "vault_connection",
        resourceId: connectionId,
        reason: `Vault ${operation} passed its required existing-path filesystem round trip`,
        details: activeVaultHealthProofDetails(
          recoveredConnection,
          recoveredConnection.vaultPath,
          recovered.health.checks,
          {
            recoveryOperation: operation,
            filesystemCheckedAt: recovered.health.checkedAt,
          },
        ),
        occurredAt: recovered.connectionVersion,
      });
      appendVaultAudit(dependencies.database, {
        actor,
        action: operation === "repair" ? "vault.repair.completed" : "vault.reindex.completed",
        resourceType: "vault_connection",
        resourceId: connectionId,
        reason: recovered.message,
        details: {
          status: recovered.status,
          counts: recovered.counts,
          progress: recovered.progress,
          expectedConnectionVersion: recovered.expectedConnectionVersion,
          connectionVersion: recovered.connectionVersion,
          issueSampleTruncated: recovered.issueSampleTruncated,
          controlPlane: "ti_scale",
        },
        occurredAt: recovered.completedAt,
      });
      dependencies.onVaultConnectionChanged?.();
      return {
        schemaVersion: SCHEMA_VERSION,
        result: { ...recovered, authorizationFingerprint },
      };
    }, (cachedResponse, _actor, access) => {
      if (!vault) {
        throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      }
      if (access.allEngagements !== true) denyHiddenBrainResource();
      vault.assertVaultSyncAllowed();
      vault.requireConnection(cachedResponse.result.connectionId);
      assertVaultAuthorizationReplay(
        dependencies.database,
        vault,
        cachedResponse.result.connectionId,
        access,
        cachedResponse.result.authorizationFingerprint,
      );
    });
  };

  router.post("/api/v2/brain/vault/repair", (request, response) => {
    recoverVault("repair", request, response);
  });

  router.post("/api/v2/brain/vault/reindex", (request, response) => {
    recoverVault("reindex", request, response);
  });

  router.get("/api/v2/brain/vault/deep-link", (request, response) => {
    handle(request, response, (_actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const connectionId = requiredText(request.query.connectionId, "vault connection ID", 256);
      const nodeId = optionalText(request.query.nodeId, "memory node ID", 256);
      const requestedPath = optionalText(request.query.relativePath, "vault note path", 1_000);
      if (nodeId && requestedPath) throw new TypeError("Choose nodeId or relativePath, not both");
      let relativePath = requestedPath;
      if (nodeId) {
        requireAccessibleNode(repository, nodeId, access);
        vault.assertConnectionNodeAllowed(connectionId, nodeId);
        const state = dependencies.database.prepare(`
          SELECT relative_path FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
        `).get(connectionId, nodeId) as { relative_path: string } | undefined;
        relativePath = state?.relative_path ?? vault.renderNode(nodeId).relativePath;
      }
      return { schemaVersion: SCHEMA_VERSION, url: vault.deepLink(connectionId, relativePath) };
    });
  });

  router.post("/api/v2/brain/vault/portable-export", async (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    try {
      const retiredPortableVault = vault as ObsidianVaultBridge;
      throw new BrainApiError(
        409,
        "vault_portable_export_disabled",
        "Portable Vault ZIP creation is disabled by the operator no-backup policy",
        "policy_denied",
        "Use the connected Obsidian Vault or synchronize canonical notes directly. Ti-Scale will not retain a portable archive.",
      );
      const idempotencyKey = validatedIdempotencyKey(request);
      if (!retiredPortableVault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const { actor, access } = actorAndAccess(request, dependencies);
      const body = object(request.body);
      const connectionId = requiredText(body.connectionId, "vault connection ID", 256);
      if (body.includeBrainAtlasProfile !== undefined && typeof body.includeBrainAtlasProfile !== "boolean") {
        throw new TypeError("includeBrainAtlasProfile must be a boolean");
      }
      retiredPortableVault.requireConnection(connectionId);
      const payload = await executeIdempotentAsync(
        dependencies.database,
        actor,
        access,
        idempotencyKey,
        { path: request.path, params: request.params, body },
        async () => {
          retiredPortableVault.assertVaultSyncAllowed();
          const nodeIds = accessibleConnectionNodeIds(
            dependencies.database,
            retiredPortableVault,
            connectionId,
            access,
          );
          const result = await retiredPortableVault.createPortableExport(connectionId, nodeIds, actor, {
            includeBrainAtlasProfile: body.includeBrainAtlasProfile === true,
          });
          storePortableExportAuthorization(dependencies.database, {
            schemaVersion: SCHEMA_VERSION,
            actor,
            accessFingerprint: replayAccessFingerprint(actor, access),
            connectionId,
            archiveName: result.archiveName,
            nodeIds,
            nodeSnapshots: result.nodeSnapshots,
            sha256: result.sha256,
            byteSize: result.byteSize,
            createdAt: result.createdAt,
          });
          return {
            schemaVersion: SCHEMA_VERSION,
            result: {
              connectionId,
              status: "ready",
              message: `Portable Obsidian archive contains ${nodeIds.length} canonical notes, a provenance manifest${result.brainAtlasProfile ? ", and the verified pinned Brain Atlas profile" : ""}.`,
              archiveName: result.archiveName,
              downloadUrl: `/api/v2/brain/vault/portable-exports/${encodeURIComponent(connectionId)}/${encodeURIComponent(result.archiveName)}`,
              byteSize: result.byteSize,
              fileCount: result.fileCount,
              sha256: result.sha256,
              createdAt: result.createdAt,
              ...(result.brainAtlasProfile ? { brainAtlasProfile: result.brainAtlasProfile } : {}),
            },
          };
        },
        async (cachedResponse) => {
          const authorized = requireAuthorizedPortableExport(
            dependencies.database,
            retiredPortableVault,
            cachedResponse.result.connectionId,
            cachedResponse.result.archiveName,
            actor,
            access,
          );
          await verifyPortableExportIntegrity(authorized);
        },
      );
      response.json(payload);
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.get("/api/v2/brain/vault/portable-exports/:connectionId/:archiveName", async (request, response) => {
    const requestTraceId = attachV2RequestId(request, response);
    response.setHeader("Cache-Control", "no-store");
    try {
      const retiredPortableVault = vault as ObsidianVaultBridge;
      throw new BrainApiError(
        409,
        "vault_portable_export_disabled",
        "Portable Vault ZIP delivery is disabled by the operator no-backup policy",
        "policy_denied",
        "Use the connected Obsidian Vault or synchronize canonical notes directly. Ti-Scale will not serve retained portable archives.",
      );
      if (!retiredPortableVault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const { actor, access } = actorAndAccess(request, dependencies);
      const authorized = requireAuthorizedPortableExport(
        dependencies.database,
        retiredPortableVault,
        request.params.connectionId!,
        request.params.archiveName!,
        actor,
        access,
      );
      await verifyPortableExportIntegrity(authorized);
      response.download(authorized.archiveName, authorized.archiveName, {
        root: dirname(authorized.archivePath),
        dotfiles: "deny",
        headers: {
          "Cache-Control": "no-store",
          "Content-Disposition": `attachment; filename="${authorized.archiveName}"`,
          "Content-Type": "application/zip",
          "Content-Security-Policy": "sandbox",
          "Cross-Origin-Resource-Policy": "same-origin",
          "Referrer-Policy": "no-referrer",
          "X-Content-Type-Options": "nosniff",
        },
      }, (error) => {
        if (error && !response.headersSent) {
          sendError(response, new BrainApiError(
            404,
            "brain_resource_not_found",
            "The requested Second Brain resource was not found",
            "not_found",
          ), requestTraceId);
        }
      });
    } catch (error) {
      sendError(response, error, requestTraceId);
    }
  });

  router.get("/api/v2/brain/vault/conflicts", (request, response) => {
    handle(request, response, (_actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const rows = dependencies.database.prepare(`
        SELECT vc.id, vc.connection_id, vc.node_id, vc.base_hash, vc.database_hash,
          vc.vault_hash, vc.status, vc.created_at, vs.relative_path
        FROM vault_conflicts vc JOIN vault_sync_state vs ON vs.id = vc.sync_state_id
        ORDER BY vc.created_at DESC LIMIT 250
      `).all() as Array<Record<string, unknown>>;
      return {
        schemaVersion: SCHEMA_VERSION,
        items: rows.flatMap((row) => {
          if (!row.node_id) return [];
          const node = repository.getNode(String(row.node_id));
          if (!node || !canAccess(node, access)) return [];
          try {
            vault.assertConnectionNodeAllowed(String(row.connection_id), node.id);
          } catch {
            return [];
          }
          return [{
            id: row.id,
            connectionId: row.connection_id,
            nodeId: row.node_id,
            relativePath: row.relative_path,
            baseHash: row.base_hash,
            databaseHash: row.database_hash,
            vaultHash: row.vault_hash,
            status: row.status,
            createdAt: row.created_at,
          }];
        }),
      };
    });
  });

  router.get("/api/v2/brain/vault/conflicts/:conflictId", (request, response) => {
    handle(request, response, (_actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const row = dependencies.database.prepare(`
        SELECT vc.*, vs.relative_path FROM vault_conflicts vc
        JOIN vault_sync_state vs ON vs.id = vc.sync_state_id WHERE vc.id = ?
      `).get(request.params.conflictId!) as Record<string, unknown> | undefined;
      if (!row) throw new BrainApiError(404, "vault_conflict_not_found", "Vault conflict was not found", "not_found");
      if (!row.node_id) throw new BrainApiError(404, "vault_conflict_not_found", "Vault conflict was not found", "not_found");
      requireAccessibleNode(repository, String(row.node_id), access);
      try {
        vault.assertConnectionNodeAllowed(String(row.connection_id), String(row.node_id));
      } catch {
        denyHiddenBrainResource();
      }
      return {
        schemaVersion: SCHEMA_VERSION,
        conflict: {
          id: row.id,
          connectionId: row.connection_id,
          nodeId: row.node_id,
          relativePath: row.relative_path,
          baseHash: row.base_hash,
          databaseHash: row.database_hash,
          vaultHash: row.vault_hash,
          databaseVersion: JSON.parse(String(row.database_version_json)),
          vaultVersionText: row.vault_version_text,
          status: row.status,
          createdAt: row.created_at,
        },
      };
    });
  });

  router.post("/api/v2/brain/vault/conflicts/:conflictId/resolve", (request, response) => {
    mutate(request, response, (actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const conflict = dependencies.database.prepare(
        "SELECT node_id FROM vault_conflicts WHERE id = ? AND status = 'open'",
      ).get(request.params.conflictId!) as { node_id: string | null } | undefined;
      if (!conflict?.node_id) throw new BrainApiError(404, "vault_conflict_not_found", "Open vault conflict was not found", "not_found");
      requireAccessibleNode(repository, conflict.node_id, access);
      const conflictConnection = dependencies.database.prepare(
        "SELECT connection_id FROM vault_conflicts WHERE id = ?",
      ).get(request.params.conflictId!) as { connection_id: string } | undefined;
      if (!conflictConnection) denyHiddenBrainResource();
      try {
        vault.assertConnectionNodeAllowed(conflictConnection.connection_id, conflict.node_id);
      } catch {
        denyHiddenBrainResource();
      }
      const body = object(request.body);
      const resolution = requiredText(body.resolution, "conflict resolution", 30);
      if (resolution !== "database" && resolution !== "vault" && resolution !== "merged") {
        throw new TypeError("conflict resolution must be database, vault, or merged");
      }
      const result = vault.resolveConflict(
        request.params.conflictId!,
        resolution,
        actor,
        optionalText(body.mergedText, "merged vault note", 1_000_000),
        new Set(accessibleConnectionNodeIds(
          dependencies.database,
          vault,
          conflictConnection.connection_id,
          access,
        )),
      );
      return { schemaVersion: SCHEMA_VERSION, result };
    }, (_cachedResponse, _actor, access) => {
      if (!vault) throw new BrainApiError(503, "vault_bridge_disabled", "Obsidian vault integration is not configured", "dependency_missing");
      const conflict = dependencies.database.prepare(
        "SELECT node_id FROM vault_conflicts WHERE id = ?",
      ).get(request.params.conflictId!) as { node_id: string | null } | undefined;
      if (!conflict?.node_id) {
        throw new BrainApiError(404, "vault_conflict_not_found", "Vault conflict was not found", "not_found");
      }
      requireAccessibleNode(repository, conflict.node_id, access);
      const conflictConnection = dependencies.database.prepare(
        "SELECT connection_id FROM vault_conflicts WHERE id = ?",
      ).get(request.params.conflictId!) as { connection_id: string } | undefined;
      if (!conflictConnection) denyHiddenBrainResource();
      try {
        vault.assertConnectionNodeAllowed(conflictConnection.connection_id, conflict.node_id);
      } catch {
        denyHiddenBrainResource();
      }
    });
  });

  return router;
}

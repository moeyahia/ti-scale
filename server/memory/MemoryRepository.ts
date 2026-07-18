import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db/types";
import { inImmediateTransaction } from "../db/transaction";
import type {
  ContextPack,
  ContextPackItemDisposition,
  CorrectMemoryNodeInput,
  CreateMemoryCandidateInput,
  CreateMemoryEdgeInput,
  CreateMemoryNodeInput,
  ForgetResult,
  Journey,
  MemoryCandidate,
  MemoryEdge,
  MemoryNode,
  MemoryProvenance,
  MemoryRetentionPolicy,
  MemoryScope,
  RetrievalPolicy,
  RetrievedMemory,
} from "./types";
import {
  assertIdentifier,
  assertNonEmpty,
  assertOptionalTimestamp,
  deserializeScope,
  serializeScope,
  validateConfidence,
  validateCreateEdge,
  validateCreateNode,
  validateLifecycle,
  validateJourney,
  validateNodeType,
  validateProvenance,
  validateScope,
  validateSensitivity,
} from "./validation";
import {
  assertReusableMemoryText,
  assertReusableMemoryUnknown,
  REUSABLE_MEMORY_LIMITS,
} from "./ReusableMemorySafety";
import {
  assertCanonicalMemoryScope,
  memoryNodeMatchesPolicy,
  requireCanonicalMissionScope,
} from "./MemoryScopePolicy";

interface NodeRow {
  id: string;
  node_type: MemoryNode["nodeType"];
  title: string;
  summary: string;
  body: string;
  scope: string;
  engagement_id: string | null;
  mission_id: string | null;
  sensitivity: MemoryNode["sensitivity"];
  confidence: number;
  lifecycle_status: MemoryNode["lifecycleStatus"];
  confirmation_state: MemoryNode["confirmationState"];
  provenance_json: string;
  author_type: MemoryNode["authorType"];
  author_id: string | null;
  version: number;
  retention_policy_json: string;
  expires_at: string | null;
  pinned: number;
  created_at: string;
  updated_at: string;
}

interface EdgeRow {
  id: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: MemoryEdge["edgeType"];
  title: string;
  summary: string;
  scope: string;
  engagement_id: string | null;
  mission_id: string | null;
  sensitivity: MemoryEdge["sensitivity"];
  confidence: number;
  lifecycle_status: MemoryEdge["lifecycleStatus"];
  provenance_json: string;
  explanation: string;
  author_type: MemoryEdge["authorType"];
  author_id: string | null;
  version: number;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
}

interface CandidateRow {
  id: string;
  proposed_node_id: string | null;
  candidate_type: string;
  title: string;
  summary: string;
  body: string;
  proposed_scope: string;
  engagement_id: string | null;
  mission_id: string | null;
  sensitivity: MemoryCandidate["sensitivity"];
  confidence: number;
  source_json: string;
  status: MemoryCandidate["status"];
  proposed_by: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  created_at: string;
}

interface RepositoryOptions {
  readonly clock?: () => Date;
  readonly createId?: (prefix: string) => string;
}

const NODE_COLUMNS = `
  id, node_type, title, summary, body, scope, engagement_id, mission_id,
  sensitivity, confidence, lifecycle_status, confirmation_state,
  provenance_json, author_type, author_id, version, retention_policy_json,
  expires_at, pinned, created_at, updated_at
`;

function parseJson<T>(source: string, label: string): T {
  try {
    return JSON.parse(source) as T;
  } catch {
    throw new Error(`Stored ${label} is malformed`);
  }
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function jsonContainsExactString(value: unknown, expected: string): boolean {
  if (value === expected) return true;
  if (Array.isArray(value)) return value.some((item) => jsonContainsExactString(item, expected));
  if (value && typeof value === "object") {
    return Object.values(value as Record<string, unknown>)
      .some((item) => jsonContainsExactString(item, expected));
  }
  return false;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function memoryContentHash(input: {
  readonly nodeType: string;
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly scope: MemoryScope;
}): string {
  return sha256(canonicalJson({
    nodeType: input.nodeType,
    title: input.title.trim().normalize("NFKC"),
    summary: input.summary.trim().normalize("NFKC"),
    body: input.body.trim().normalize("NFKC"),
    scope: input.scope,
  }));
}

function nodeFromRow(row: NodeRow): MemoryNode {
  return {
    id: row.id,
    nodeType: row.node_type,
    title: row.title,
    summary: row.summary,
    body: row.body,
    scope: deserializeScope(row.scope, row.engagement_id, row.mission_id),
    sensitivity: row.sensitivity,
    confidence: row.confidence,
    lifecycleStatus: row.lifecycle_status,
    confirmationState: row.confirmation_state,
    provenance: parseJson<MemoryProvenance>(row.provenance_json, "memory provenance"),
    authorType: row.author_type,
    ...(row.author_id ? { authorId: row.author_id } : {}),
    version: row.version,
    retentionPolicy: parseJson<MemoryRetentionPolicy>(row.retention_policy_json, "memory retention policy"),
    ...(row.expires_at ? { expiresAt: row.expires_at } : {}),
    pinned: row.pinned === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function candidateFromRow(row: CandidateRow): MemoryCandidate {
  return {
    id: row.id,
    ...(row.proposed_node_id ? { proposedNodeId: row.proposed_node_id } : {}),
    nodeType: validateNodeType(row.candidate_type),
    title: row.title,
    summary: row.summary,
    body: row.body,
    scope: deserializeScope(row.proposed_scope, row.engagement_id, row.mission_id),
    sensitivity: row.sensitivity,
    confidence: row.confidence,
    provenance: parseJson<MemoryProvenance>(row.source_json, "candidate provenance"),
    status: row.status,
    proposedBy: row.proposed_by,
    ...(row.reviewed_by ? { reviewedBy: row.reviewed_by } : {}),
    ...(row.reviewed_at ? { reviewedAt: row.reviewed_at } : {}),
    createdAt: row.created_at,
  };
}

function edgeFromRow(row: EdgeRow, scope: MemoryScope): MemoryEdge {
  return {
    id: row.id,
    sourceNodeId: row.source_node_id,
    targetNodeId: row.target_node_id,
    edgeType: row.edge_type,
    title: row.title,
    summary: row.summary,
    scope,
    sensitivity: row.sensitivity,
    confidence: row.confidence,
    lifecycleStatus: row.lifecycle_status,
    provenance: parseJson<MemoryProvenance>(row.provenance_json, "edge provenance"),
    explanation: row.explanation,
    authorType: row.author_type,
    ...(row.author_id ? { authorId: row.author_id } : {}),
    version: row.version,
    ...(row.expires_at ? { expiresAt: row.expires_at } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function versionProperties(node: MemoryNode): string {
  return canonicalJson({
    nodeType: node.nodeType,
    scope: node.scope,
    sensitivity: node.sensitivity,
    confidence: node.confidence,
    confirmationState: node.confirmationState,
    provenance: node.provenance,
    retentionPolicy: node.retentionPolicy,
    expiresAt: node.expiresAt ?? null,
    pinned: node.pinned,
  });
}

function provenanceContentFields(
  provenance: MemoryProvenance,
  prefix: string,
): Parameters<typeof assertReusableMemoryText>[0] {
  return [
    {
      field: `${prefix}.provenance.explanation`,
      value: provenance.explanation,
      maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceExplanation,
    },
    ...provenance.sources.flatMap((source, index) => [
      {
        field: `${prefix}.provenance.sources[${index}].sourceType`,
        value: source.sourceType,
        maximumBytes: 128,
      },
      {
        field: `${prefix}.provenance.sources[${index}].sourceId`,
        value: source.sourceId,
        maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceIdentifier,
      },
      {
        field: `${prefix}.provenance.sources[${index}].excerptRedacted`,
        value: source.excerptRedacted,
        maximumBytes: REUSABLE_MEMORY_LIMITS.provenanceExcerpt,
      },
    ]),
  ];
}

function assertNodeContentSafe(
  input: Pick<CreateMemoryNodeInput, "title" | "summary" | "body" | "provenance" | "retentionPolicy">,
  prefix = "memory",
): void {
  assertReusableMemoryUnknown(
    input.provenance,
    `${prefix}.provenance`,
    REUSABLE_MEMORY_LIMITS.provenance,
  );
  assertReusableMemoryText([
    { field: `${prefix}.title`, value: input.title, maximumBytes: REUSABLE_MEMORY_LIMITS.title },
    { field: `${prefix}.summary`, value: input.summary, maximumBytes: REUSABLE_MEMORY_LIMITS.summary },
    { field: `${prefix}.body`, value: input.body, maximumBytes: REUSABLE_MEMORY_LIMITS.body },
    ...provenanceContentFields(input.provenance, prefix),
  ]);
  assertReusableMemoryUnknown(
    input.retentionPolicy ?? {},
    `${prefix}.retentionPolicy`,
    REUSABLE_MEMORY_LIMITS.retentionPolicy,
  );
}

function assertCandidateContentSafe(input: CreateMemoryCandidateInput): void {
  assertReusableMemoryUnknown(
    input.provenance,
    "candidate.provenance",
    REUSABLE_MEMORY_LIMITS.provenance,
  );
  assertReusableMemoryText([
    { field: "candidate.title", value: input.title, maximumBytes: REUSABLE_MEMORY_LIMITS.title },
    { field: "candidate.summary", value: input.summary, maximumBytes: REUSABLE_MEMORY_LIMITS.summary },
    { field: "candidate.body", value: input.body, maximumBytes: REUSABLE_MEMORY_LIMITS.body },
    ...provenanceContentFields(input.provenance, "candidate"),
  ]);
}

function assertEdgeContentSafe(input: CreateMemoryEdgeInput): void {
  assertReusableMemoryUnknown(
    input.provenance,
    "edge.provenance",
    REUSABLE_MEMORY_LIMITS.provenance,
  );
  assertReusableMemoryText([
    { field: "edge.title", value: input.title, maximumBytes: REUSABLE_MEMORY_LIMITS.title },
    { field: "edge.summary", value: input.summary, maximumBytes: REUSABLE_MEMORY_LIMITS.summary },
    { field: "edge.explanation", value: input.explanation, maximumBytes: REUSABLE_MEMORY_LIMITS.summary },
    ...provenanceContentFields(input.provenance, "edge"),
  ]);
}

/** Synchronous repository for the local-first canonical memory graph. */
export class MemoryRepository {
  readonly #database: SqliteDatabase;
  readonly #clock: () => Date;
  readonly #createId: (prefix: string) => string;

  constructor(database: SqliteDatabase, options: RepositoryOptions = {}) {
    this.#database = database;
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? ((prefix) => `${prefix}_${randomUUID()}`);
  }

  now(): string {
    return this.#clock().toISOString();
  }

  createId(prefix: string): string {
    return this.#createId(prefix);
  }

  getNode(id: string, includeForgotten = false): MemoryNode | undefined {
    assertIdentifier(id, "memory node ID");
    const row = this.#database
      .prepare(`SELECT ${NODE_COLUMNS} FROM memory_nodes WHERE id = ?`)
      .get(id) as NodeRow | undefined;
    if (!row || (!includeForgotten && row.lifecycle_status === "forgotten")) return undefined;
    return nodeFromRow(row);
  }

  requireNode(id: string, includeForgotten = false): MemoryNode {
    const node = this.getNode(id, includeForgotten);
    if (!node) throw new Error(`Memory node not found: ${id}`);
    return node;
  }

  createNode(input: CreateMemoryNodeInput): MemoryNode {
    assertNodeContentSafe(input);
    validateCreateNode(input);
    assertCanonicalMemoryScope(this.#database, input.scope);
    const id = input.id ?? this.createId("mem");
    assertIdentifier(id, "memory node ID");
    const now = this.now();
    const body = input.body ?? "";
    const retentionPolicy = input.retentionPolicy ?? {};

    return inImmediateTransaction(this.#database, () => {
      this.#database.prepare(`
        INSERT INTO memory_nodes (
          id, node_type, title, summary, body, scope, engagement_id, mission_id,
          sensitivity, confidence, lifecycle_status, confirmation_state,
          provenance_json, author_type, author_id, version, retention_policy_json,
          expires_at, pinned, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
      `).run(
        id, input.nodeType, input.title.trim(), input.summary.trim(), body,
        serializeScope(input.scope), input.scope.engagementId ?? null, input.scope.missionId ?? null,
        input.sensitivity, input.confidence, input.lifecycleStatus, input.confirmationState,
        canonicalJson(input.provenance), input.authorType, input.authorId ?? null,
        canonicalJson(retentionPolicy), input.expiresAt ?? null, input.pinned ? 1 : 0, now, now,
      );
      const node = this.requireNode(id, true);
      this.#insertVersion(node, input.authorType, input.authorId, "Memory created");
      const insertSource = this.#database.prepare(`
        INSERT INTO memory_sources (
          id, node_id, source_type, source_id, source_hash, excerpt_redacted,
          acquired_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const source of input.provenance.sources) {
        insertSource.run(
          this.createId("msrc"), id, source.sourceType, source.sourceId,
          source.sourceHash ?? null, source.excerptRedacted ?? null,
          source.acquiredAt, now,
        );
      }
      return node;
    });
  }

  #insertVersion(
    node: MemoryNode,
    authorType: MemoryNode["authorType"],
    authorId: string | undefined,
    reason: string,
  ): void {
    this.#database.prepare(`
      INSERT INTO memory_versions (
        id, node_id, version, title, summary, body, properties_json,
        lifecycle_status, author_type, author_id, change_reason, content_hash, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      this.createId("mver"), node.id, node.version, node.title, node.summary, node.body,
      versionProperties(node), node.lifecycleStatus, authorType, authorId ?? null,
      reason, memoryContentHash(node), node.updatedAt,
    );
  }

  correctNode(id: string, input: CorrectMemoryNodeInput): MemoryNode {
    assertNonEmpty(input.changeReason, "memory correction reason", 2_000);
    if (input.scope) validateScope(input.scope);
    if (input.sensitivity) validateSensitivity(input.sensitivity);
    if (input.confidence !== undefined) validateConfidence(input.confidence);
    if (input.lifecycleStatus) validateLifecycle(input.lifecycleStatus);
    assertOptionalTimestamp(input.expiresAt, "memory expiry");
    if (input.body !== undefined && input.body.length > 1_000_000) {
      throw new TypeError("memory body is too large");
    }

    return inImmediateTransaction(this.#database, () => {
      const current = this.requireNode(id);
      const existingSourceKeys = new Set(
        current.provenance.sources.map((source) => `${source.sourceType}\0${source.sourceId}`),
      );
      const additionalSources = (input.additionalProvenanceSources ?? []).filter((source) => {
        const key = `${source.sourceType}\0${source.sourceId}`;
        if (existingSourceKeys.has(key)) return false;
        existingSourceKeys.add(key);
        return true;
      });
      const provenance = additionalSources.length > 0
        ? { ...current.provenance, sources: [...current.provenance.sources, ...additionalSources] }
        : current.provenance;
      validateProvenance(provenance);
      const scope = input.scope ?? current.scope;
      assertCanonicalMemoryScope(this.#database, scope);
      const title = input.title?.trim() ?? current.title;
      const summary = input.summary?.trim() ?? current.summary;
      assertNonEmpty(title, "memory title", 500);
      assertNonEmpty(summary, "memory summary", 4_000);
      const nextLifecycle = input.lifecycleStatus ?? current.lifecycleStatus;
      const nextConfirmation = input.confirmationState ?? current.confirmationState;
      if (nextLifecycle === "confirmed" && nextConfirmation !== "confirmed") {
        throw new TypeError("confirmed memory requires confirmed consent state");
      }
      assertNodeContentSafe({
        title,
        summary,
        body: input.body ?? current.body,
        provenance,
        retentionPolicy: input.retentionPolicy ?? current.retentionPolicy,
      }, "memoryCorrection");
      assertReusableMemoryText([{
        field: "memoryCorrection.changeReason",
        value: input.changeReason,
        maximumBytes: 2_000,
      }]);
      const now = this.now();
      this.#database.prepare(`
        UPDATE memory_nodes SET
          title = ?, summary = ?, body = ?, scope = ?, engagement_id = ?, mission_id = ?,
          sensitivity = ?, confidence = ?, lifecycle_status = ?, confirmation_state = ?,
          provenance_json = ?, retention_policy_json = ?, expires_at = ?, pinned = ?, author_type = ?, author_id = ?,
          version = version + 1, updated_at = ?
        WHERE id = ? AND version = ? AND lifecycle_status != 'forgotten'
      `).run(
        title, summary, input.body ?? current.body, serializeScope(scope),
        scope.engagementId ?? null, scope.missionId ?? null,
        input.sensitivity ?? current.sensitivity, input.confidence ?? current.confidence,
        nextLifecycle, nextConfirmation,
        canonicalJson(provenance),
        canonicalJson(input.retentionPolicy ?? current.retentionPolicy),
        input.expiresAt === undefined ? (current.expiresAt ?? null) : input.expiresAt,
        (input.pinned ?? current.pinned) ? 1 : 0,
        input.authorType, input.authorId ?? null, now, id, current.version,
      );
      const updated = this.requireNode(id);
      const insertSource = this.#database.prepare(`
        INSERT INTO memory_sources (
          id, node_id, source_type, source_id, source_hash, excerpt_redacted,
          acquired_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const source of additionalSources) {
        insertSource.run(
          this.createId("msrc"), id, source.sourceType, source.sourceId,
          source.sourceHash ?? null, source.excerptRedacted ?? null,
          source.acquiredAt, now,
        );
      }
      this.#insertVersion(updated, input.authorType, input.authorId, input.changeReason);
      return updated;
    });
  }

  listVersions(nodeId: string): readonly {
    version: number;
    title: string;
    summary: string;
    body: string;
    lifecycleStatus: string;
    changeReason: string;
    contentHash: string;
    createdAt: string;
  }[] {
    assertIdentifier(nodeId, "memory node ID");
    const rows = this.#database.prepare(`
      SELECT version, title, summary, body, lifecycle_status, change_reason, content_hash, created_at
      FROM memory_versions WHERE node_id = ? ORDER BY version
    `).all(nodeId) as Array<Record<string, unknown>>;
    return rows.map((row) => ({
      version: Number(row.version),
      title: String(row.title),
      summary: String(row.summary),
      body: String(row.body),
      lifecycleStatus: String(row.lifecycle_status),
      changeReason: String(row.change_reason),
      contentHash: String(row.content_hash),
      createdAt: String(row.created_at),
    }));
  }

  createEdge(input: CreateMemoryEdgeInput): MemoryEdge {
    assertEdgeContentSafe(input);
    validateCreateEdge(input);
    assertCanonicalMemoryScope(this.#database, input.scope);
    const source = this.requireNode(input.sourceNodeId);
    const target = this.requireNode(input.targetNodeId);
    const canonicalScope = (node: MemoryNode): {
      readonly engagementId: string | null;
      readonly missionId: string | null;
    } => {
      if (node.scope.kind === "global") return { engagementId: null, missionId: null };
      if (node.scope.kind === "engagement") {
        return { engagementId: node.scope.engagementId ?? null, missionId: null };
      }
      const mission = requireCanonicalMissionScope(this.#database, node.scope.missionId ?? "");
      return { engagementId: mission.engagementId, missionId: node.scope.missionId ?? null };
    };
    const sourceCanonical = canonicalScope(source);
    const targetCanonical = canonicalScope(target);
    if (source.scope.kind !== "global" && target.scope.kind !== "global" &&
        sourceCanonical.engagementId !== targetCanonical.engagementId) {
      throw new Error("Cross-engagement memory edges are not permitted");
    }
    if (input.scope.kind === "engagement") {
      const allowed = input.scope.engagementId;
      if ((source.scope.kind !== "global" && sourceCanonical.engagementId !== allowed) ||
          (target.scope.kind !== "global" && targetCanonical.engagementId !== allowed)) {
        throw new Error("Edge scope does not match its nodes");
      }
    }
    let persistedEngagementId = input.scope.engagementId ?? null;
    let persistedMissionId = input.scope.missionId ?? null;
    if (input.scope.kind === "mission") {
      const edgeMissionId = input.scope.missionId ?? "";
      const edgeMission = requireCanonicalMissionScope(this.#database, edgeMissionId);
      persistedEngagementId = edgeMission.engagementId;
      persistedMissionId = edgeMissionId;
      for (const node of [sourceCanonical, targetCanonical]) {
        if (node.missionId && node.missionId !== edgeMissionId) {
          throw new Error("Mission edge scope does not match its nodes");
        }
        if (node.engagementId && node.engagementId !== edgeMission.engagementId) {
          throw new Error("Mission edge engagement does not match its nodes");
        }
      }
    }
    const id = input.id ?? this.createId("medge");
    const now = this.now();
    this.#database.prepare(`
      INSERT INTO memory_edges (
        id, source_node_id, target_node_id, edge_type, title, summary, scope, engagement_id, mission_id,
        sensitivity, confidence, lifecycle_status, provenance_json, explanation,
        author_type, author_id, version, expires_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    `).run(
      id, input.sourceNodeId, input.targetNodeId, input.edgeType, input.title.trim(),
      input.summary.trim(), serializeScope(input.scope), persistedEngagementId, persistedMissionId,
      input.sensitivity, input.confidence,
      input.lifecycleStatus, canonicalJson(input.provenance), input.explanation.trim(),
      input.authorType, input.authorId ?? null, input.expiresAt ?? null, now, now,
    );
    return edgeFromRow(
      this.#database.prepare("SELECT * FROM memory_edges WHERE id = ?").get(id) as EdgeRow,
      input.scope,
    );
  }

  listEdges(nodeId: string): readonly MemoryEdge[] {
    this.requireNode(nodeId);
    const rows = this.#database.prepare(`
      SELECT * FROM memory_edges
      WHERE (source_node_id = ? OR target_node_id = ?)
        AND lifecycle_status != 'forgotten'
        AND (expires_at IS NULL OR expires_at > ?)
      ORDER BY created_at
    `).all(nodeId, nodeId, this.now()) as EdgeRow[];
    return rows.map((row) => {
      return edgeFromRow(row, deserializeScope(row.scope, row.engagement_id, row.mission_id));
    });
  }

  createCandidate(input: CreateMemoryCandidateInput): MemoryCandidate {
    assertCandidateContentSafe(input);
    validateNodeType(input.nodeType);
    assertNonEmpty(input.title, "candidate title", 500);
    assertNonEmpty(input.summary, "candidate summary", 4_000);
    validateScope(input.scope);
    assertCanonicalMemoryScope(this.#database, input.scope);
    validateSensitivity(input.sensitivity);
    validateConfidence(input.confidence);
    validateProvenance(input.provenance);
    assertNonEmpty(input.proposedBy, "candidate author", 256);
    const contentHash = memoryContentHash({
      nodeType: input.nodeType,
      title: input.title,
      summary: input.summary,
      body: input.body ?? "",
      scope: input.scope,
    });
    const suppressed = this.#database.prepare(`
      SELECT id FROM memory_suppressions
      WHERE suppression_hash = ? AND (expires_at IS NULL OR expires_at > ?)
    `).get(contentHash, this.now());
    if (suppressed) throw new Error("This memory candidate is suppressed by operator policy");

    const id = input.id ?? this.createId("mcand");
    const now = this.now();
    this.#database.prepare(`
      INSERT INTO memory_candidates (
        id, candidate_type, title, summary, body, proposed_scope, engagement_id,
        mission_id, sensitivity, confidence, source_json, status, proposed_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
    `).run(
      id, input.nodeType, input.title.trim(), input.summary.trim(), input.body ?? "",
      serializeScope(input.scope), input.scope.engagementId ?? null, input.scope.missionId ?? null,
      input.sensitivity, input.confidence, canonicalJson(input.provenance), input.proposedBy, now,
    );
    return this.requireCandidate(id);
  }

  getCandidate(id: string): MemoryCandidate | undefined {
    assertIdentifier(id, "memory candidate ID");
    const row = this.#database.prepare("SELECT * FROM memory_candidates WHERE id = ?").get(id) as CandidateRow | undefined;
    return row ? candidateFromRow(row) : undefined;
  }

  requireCandidate(id: string): MemoryCandidate {
    const candidate = this.getCandidate(id);
    if (!candidate) throw new Error(`Memory candidate not found: ${id}`);
    return candidate;
  }

  confirmCandidate(
    id: string,
    reviewer: string,
    edits: Partial<Pick<CreateMemoryCandidateInput, "title" | "summary" | "body" | "scope" | "sensitivity" | "confidence">> = {},
  ): MemoryNode {
    assertNonEmpty(reviewer, "candidate reviewer", 256);
    return inImmediateTransaction(this.#database, () => {
      const candidate = this.requireCandidate(id);
      if (candidate.status !== "pending") throw new Error("Only pending candidates can be confirmed");
      const node = this.createNode({
        nodeType: candidate.nodeType,
        title: edits.title ?? candidate.title,
        summary: edits.summary ?? candidate.summary,
        body: edits.body ?? candidate.body,
        scope: edits.scope ?? candidate.scope,
        sensitivity: edits.sensitivity ?? candidate.sensitivity,
        confidence: edits.confidence ?? candidate.confidence,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: candidate.provenance,
        authorType: "operator",
        authorId: reviewer,
      });
      const edited = Object.keys(edits).length > 0;
      this.#database.prepare(`
        UPDATE memory_candidates
        SET proposed_node_id = ?, status = ?, reviewed_by = ?, reviewed_at = ?
        WHERE id = ? AND status = 'pending'
      `).run(node.id, edited ? "edited_confirmed" : "confirmed", reviewer, this.now(), id);
      return node;
    });
  }

  rejectCandidateAndSuppress(id: string, reviewer: string, reason: string): string {
    assertNonEmpty(reviewer, "candidate reviewer", 256);
    assertNonEmpty(reason, "suppression reason", 1_000);
    assertReusableMemoryText([{
      field: "candidateSuppression.reason",
      value: reason,
      maximumBytes: 1_000,
    }]);
    return inImmediateTransaction(this.#database, () => {
      const candidate = this.requireCandidate(id);
      if (candidate.status !== "pending") throw new Error("Only pending candidates can be rejected");
      const hash = memoryContentHash(candidate);
      const suppressionId = this.createId("msup");
      const now = this.now();
      this.#database.prepare(`
        INSERT INTO memory_suppressions (
          id, suppression_hash, scope, engagement_id, category, reason, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        suppressionId, hash, serializeScope(candidate.scope), candidate.scope.engagementId ?? null,
        candidate.nodeType, reason, reviewer, now,
      );
      this.#database.prepare(`
        UPDATE memory_candidates SET status = 'suppressed', reviewed_by = ?, reviewed_at = ?,
          title = '[Suppressed candidate]', summary = '', body = '', confidence = 0,
          source_json = ?
        WHERE id = ?
      `).run(
        reviewer,
        now,
        canonicalJson({ method: "suppressed", explanation: "Content removed", sources: [] }),
        id,
      );
      this.#appendCandidateReviewAudit(candidate, reviewer, reason, true, now);
      return suppressionId;
    });
  }

  rejectCandidate(id: string, reviewer: string, reason: string): MemoryCandidate {
    assertNonEmpty(reviewer, "candidate reviewer", 256);
    assertNonEmpty(reason, "candidate rejection reason", 1_000);
    assertReusableMemoryText([{
      field: "candidateRejection.reason",
      value: reason,
      maximumBytes: 1_000,
    }]);
    return inImmediateTransaction(this.#database, () => {
      const candidate = this.requireCandidate(id);
      if (candidate.status !== "pending") throw new Error("Only pending candidates can be rejected");
      const now = this.now();
      this.#database.prepare(`
        UPDATE memory_candidates
        SET status = 'rejected', reviewed_by = ?, reviewed_at = ?
        WHERE id = ? AND status = 'pending'
      `).run(reviewer, now, id);
      this.#appendCandidateReviewAudit(candidate, reviewer, reason, false, now);
      return this.requireCandidate(id);
    });
  }

  #appendCandidateReviewAudit(
    candidate: MemoryCandidate,
    actor: string,
    reason: string,
    suppressed: boolean,
    occurredAt: string,
  ): string {
    const mission = candidate.scope.kind === "mission" && candidate.scope.missionId
      ? this.#database.prepare("SELECT journey FROM missions WHERE id = ?").get(candidate.scope.missionId) as {
          journey: Journey;
        } | undefined
      : undefined;
    const previous = this.#database.prepare(
      "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
    ).get() as { record_hash: string } | undefined;
    const id = this.createId("audit");
    const details = {
      nodeType: candidate.nodeType,
      scope: candidate.scope.kind,
      sensitivity: candidate.sensitivity,
      doNotRelearn: suppressed,
    };
    const recordHash = sha256(canonicalJson({
      id,
      actor,
      action: suppressed ? "memory_candidate.suppressed" : "memory_candidate.rejected",
      resourceType: "memory_candidate",
      resourceId: candidate.id,
      reason,
      details,
      missionId: candidate.scope.kind === "mission" ? candidate.scope.missionId ?? null : null,
      runId: null,
      journey: mission?.journey ?? null,
      previousHash: previous?.record_hash ?? null,
      occurredAt,
    }));
    this.#database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json, previous_hash,
        record_hash, occurred_at
      ) VALUES (?, ?, NULL, ?, 'operator', ?, ?, 'memory_candidate', ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      candidate.scope.kind === "mission" ? candidate.scope.missionId ?? null : null,
      mission?.journey ?? null,
      actor,
      suppressed ? "memory_candidate.suppressed" : "memory_candidate.rejected",
      candidate.id,
      reason,
      canonicalJson(details),
      previous?.record_hash ?? null,
      recordHash,
      occurredAt,
    );
    return id;
  }

  /**
   * Locate both canonical projections and the original Inbox note that produced
   * a subsequently confirmed candidate. The latter still has a NULL node_id in
   * vault_sync_state, so provenance is the durable privacy link.
   */
  vaultProjectionsForNode(id: string): readonly {
    readonly connectionId: string;
    readonly relativePath: string;
  }[] {
    assertIdentifier(id, "memory node ID");
    const results = new Map<string, { connectionId: string; relativePath: string }>();
    const add = (connectionId: string, relativePath: string): void => {
      if (!connectionId || !relativePath) return;
      results.set(`${connectionId}\0${relativePath}`, { connectionId, relativePath });
    };
    const direct = this.#database.prepare(`
      SELECT connection_id, relative_path FROM vault_sync_state WHERE node_id = ?
    `).all(id) as Array<{ connection_id: string; relative_path: string }>;
    for (const row of direct) add(row.connection_id, row.relative_path);

    const connections = this.#database.prepare("SELECT id FROM vault_connections").all() as Array<{ id: string }>;
    const candidates = this.#database.prepare(`
      SELECT source_json FROM memory_candidates WHERE proposed_node_id = ?
    `).all(id) as Array<{ source_json: string }>;
    for (const candidate of candidates) {
      let provenance: MemoryProvenance;
      try {
        provenance = JSON.parse(candidate.source_json) as MemoryProvenance;
      } catch {
        continue;
      }
      for (const source of provenance.sources ?? []) {
        if (source.sourceType !== "obsidian_note") continue;
        for (const connection of connections) {
          const prefix = `${connection.id}:`;
          if (!source.sourceId.startsWith(prefix)) continue;
          const relativePath = source.sourceId.slice(prefix.length);
          const tracked = this.#database.prepare(`
            SELECT 1 AS present FROM vault_sync_state
            WHERE connection_id = ? AND relative_path = ?
          `).get(connection.id, relativePath) as { present: number } | undefined;
          if (tracked) add(connection.id, relativePath);
        }
      }
    }
    return [...results.values()];
  }

  /**
   * GDPR-style erasure keeps only a generic tombstone, a non-reversible content
   * hash suppression, and a content-free audit record. Historical plaintext
   * versions are deliberately erased despite their normal append-only trigger.
   */
  forgetNode(id: string, actor: string, reason = "Operator requested forgetting"): ForgetResult {
    assertNonEmpty(actor, "forgetting actor", 256);
    assertNonEmpty(reason, "forgetting reason", 1_000);
    return inImmediateTransaction(this.#database, () => {
      const node = this.requireNode(id);
      const suppressionHash = memoryContentHash(node);
      const now = this.now();
      const projections = this.vaultProjectionsForNode(id);
      const linkedCandidates = this.#database.prepare(`
        SELECT id, source_json FROM memory_candidates WHERE proposed_node_id = ?
      `).all(id) as Array<{ id: string; source_json: string }>;

      this.#database.prepare("DELETE FROM vault_conflicts WHERE node_id = ?").run(id);
      this.#database.prepare(`
        UPDATE vault_sync_state SET node_id = NULL, status = 'deleted', database_version = NULL,
          database_content_hash = NULL, vault_content_hash = NULL, error_message = NULL,
          last_scanned_at = ? WHERE node_id = ?
      `).run(now, id);
      const deleteProjectionConflicts = this.#database.prepare(`
        DELETE FROM vault_conflicts WHERE sync_state_id IN (
          SELECT id FROM vault_sync_state WHERE connection_id = ? AND relative_path = ?
        )
      `);
      const deleteProjectionState = this.#database.prepare(`
        DELETE FROM vault_sync_state WHERE connection_id = ? AND relative_path = ?
      `);
      for (const projection of projections) {
        deleteProjectionConflicts.run(projection.connectionId, projection.relativePath);
        deleteProjectionState.run(projection.connectionId, projection.relativePath);
      }
      const contextItems = this.#database.prepare("DELETE FROM memory_context_items WHERE node_id = ?").run(id).changes;
      const edges = this.#database.prepare("DELETE FROM memory_edges WHERE source_node_id = ? OR target_node_id = ?").run(id, id).changes;
      const embeddings = this.#database.prepare("DELETE FROM memory_embeddings WHERE node_id = ?").run(id).changes;
      const sources = this.#database.prepare("DELETE FROM memory_sources WHERE node_id = ?").run(id).changes;

      // Privacy erasure is the one intentional exception to immutable version
      // history. DDL is transactional in SQLite and the protections are restored
      // before this IMMEDIATE transaction becomes visible.
      this.#database.exec(`
        DROP TRIGGER IF EXISTS memory_versions_no_update;
        DROP TRIGGER IF EXISTS memory_versions_no_delete;
      `);
      const versions = this.#database.prepare("DELETE FROM memory_versions WHERE node_id = ?").run(id).changes;
      this.#database.exec(`
        CREATE TRIGGER memory_versions_no_update
        BEFORE UPDATE ON memory_versions BEGIN
          SELECT RAISE(ABORT, 'memory versions are append-only');
        END;
        CREATE TRIGGER memory_versions_no_delete
        BEFORE DELETE ON memory_versions BEGIN
          SELECT RAISE(ABORT, 'memory versions are append-only');
        END;
      `);

      this.#database.prepare(`
        UPDATE preference_profiles
        SET value_json = '{}', confirmation_state = 'forgotten', source_node_id = NULL,
          version = version + 1, updated_at = ?
        WHERE source_node_id = ?
      `).run(now, id);
      this.#database.prepare(`
        UPDATE memory_candidates SET proposed_node_id = NULL,
          title = '[Forgotten candidate]', summary = '', body = '', confidence = 0,
          source_json = ?, status = 'suppressed', reviewed_by = ?, reviewed_at = ?
        WHERE proposed_node_id = ?
      `).run(
        canonicalJson({ method: "forgotten", explanation: "Content removed", sources: [] }),
        actor,
        now,
        id,
      );

      // Idempotency responses can contain a complete node snapshot. Portable
      // export authorizations contain node IDs while their cached response
      // points at the corresponding archive. Erasure revokes both without
      // retaining caller text or relying on a substring match.
      const settingRows = this.#database.prepare(`
        SELECT key, value_json FROM settings
        WHERE key LIKE 'idempotency.brain.%'
           OR key LIKE 'brain.portable_export.authorization.%'
      `).all() as Array<{ key: string; value_json: string }>;
      const settingValues = new Map<string, unknown>();
      const revokedArchives: Array<{ connectionId: string; archiveName: string }> = [];
      const erasedIdentifiers = [
        id,
        ...linkedCandidates.map((candidate) => candidate.id),
        ...projections.map((projection) => projection.relativePath),
      ];
      for (const row of settingRows) {
        let value: unknown;
        try {
          value = JSON.parse(row.value_json) as unknown;
        } catch {
          // A malformed private cache cannot be trusted to be content-free.
          settingValues.set(row.key, undefined);
          continue;
        }
        if (!erasedIdentifiers.some((identifier) => jsonContainsExactString(value, identifier))) continue;
        settingValues.set(row.key, value);
        if (row.key.startsWith("brain.portable_export.authorization.") && value && typeof value === "object") {
          const record = value as Record<string, unknown>;
          if (typeof record.connectionId === "string" && typeof record.archiveName === "string") {
            revokedArchives.push({ connectionId: record.connectionId, archiveName: record.archiveName });
          }
        }
      }
      for (const row of settingRows) {
        if (!row.key.startsWith("idempotency.brain.")) continue;
        let value: unknown;
        try {
          value = JSON.parse(row.value_json) as unknown;
        } catch {
          settingValues.set(row.key, undefined);
          continue;
        }
        if (revokedArchives.some(({ connectionId, archiveName }) => (
          jsonContainsExactString(value, connectionId) && jsonContainsExactString(value, archiveName)
        ))) settingValues.set(row.key, value);
      }
      const deleteSetting = this.#database.prepare("DELETE FROM settings WHERE key = ?");
      const revokeIdempotency = this.#database.prepare(`
        UPDATE settings SET value_json = ?, updated_by = ?, updated_at = ? WHERE key = ?
      `);
      for (const [key, value] of settingValues) {
        if (!key.startsWith("idempotency.brain.")) {
          deleteSetting.run(key);
          continue;
        }
        const record = value && typeof value === "object" && !Array.isArray(value)
          ? value as Record<string, unknown>
          : {};
        const revoked = {
          requestHash: typeof record.requestHash === "string"
            ? record.requestHash
            : sha256(`revoked:${key}`),
          ...(typeof record.accessFingerprint === "string"
            ? { accessFingerprint: record.accessFingerprint }
            : {}),
          state: "revoked",
        };
        revokeIdempotency.run(canonicalJson(revoked), actor, now, key);
      }
      this.#database.prepare(`
        UPDATE memory_nodes SET
          title = '[Forgotten memory]', summary = '', body = '', lifecycle_status = 'forgotten',
          confirmation_state = 'rejected', provenance_json = ?, retention_policy_json = '{}',
          expires_at = ?, pinned = 0, author_type = 'operator', author_id = ?,
          version = version + 1, updated_at = ?
        WHERE id = ?
      `).run(
        canonicalJson({ method: "forgotten", explanation: "Content removed", sources: [] }),
        now, actor, now, id,
      );
      const suppressionId = this.createId("msup");
      this.#database.prepare(`
        INSERT INTO memory_suppressions (
          id, suppression_hash, scope, engagement_id, category, reason, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(suppression_hash) DO NOTHING
      `).run(
        suppressionId, suppressionHash, serializeScope(node.scope), node.scope.engagementId ?? null,
        node.nodeType, "Do not relearn forgotten content", actor, now,
      );
      const storedSuppression = this.#database.prepare(
        "SELECT id FROM memory_suppressions WHERE suppression_hash = ?",
      ).get(suppressionHash) as { id: string };

      const removed = { versions, sources, embeddings, edges, contextItems };
      const auditScope = this.#resolveMemoryAuditScope(node);
      const auditRecordId = this.#appendContentFreeAudit({
        actor,
        action: "memory.forgotten",
        resourceId: id,
        // Never persist caller-supplied free text in an erasure audit: it may
        // repeat the very content the operator asked us to forget.
        reason: "Operator requested memory erasure",
        details: { nodeType: node.nodeType, scope: node.scope.kind, removed },
        ...auditScope,
        occurredAt: now,
      });
      return {
        nodeId: id,
        suppressionId: storedSuppression.id,
        vaultProjections: projections.map((item) => ({
          connectionId: item.connectionId,
          // The original path can contain user-supplied forgotten text and is
          // deliberately excluded from the response/idempotency cache.
          relativePath: "[erased]",
        })),
        removed,
        auditRecordId,
      };
    });
  }

  /** Records a content-free, tamper-evident export event for one memory node. */
  recordNodeExportAudit(input: {
    nodeId: string;
    actor: string;
    connectionId: string;
    status: string;
  }): string {
    assertIdentifier(input.nodeId, "memory node ID");
    assertIdentifier(input.connectionId, "vault connection ID");
    assertNonEmpty(input.actor, "memory export actor", 256);
    assertNonEmpty(input.status, "memory export status", 128);
    return inImmediateTransaction(this.#database, () => {
      const node = this.requireNode(input.nodeId);
      const now = this.now();
      return this.#appendContentFreeAudit({
        actor: input.actor,
        action: "memory.exported",
        resourceId: node.id,
        reason: "Operator exported a human-readable memory projection",
        details: {
          nodeType: node.nodeType,
          scope: node.scope.kind,
          destination: "obsidian_vault",
          connectionId: input.connectionId,
          status: input.status.slice(0, 128),
        },
        ...this.#resolveMemoryAuditScope(node),
        occurredAt: now,
      });
    });
  }

  #appendContentFreeAudit(input: {
    actor: string;
    action: string;
    resourceId: string;
    reason: string;
    details: Record<string, unknown>;
    missionId: string | null;
    runId: string | null;
    journey: Journey | null;
    occurredAt: string;
  }): string {
    const previous = this.#database.prepare(
      "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
    ).get() as { record_hash: string } | undefined;
    const id = this.createId("audit");
    const details = canonicalJson(input.details);
    const recordHash = sha256(canonicalJson({
      id,
      actor: input.actor,
      action: input.action,
      resourceType: "memory_node",
      resourceId: input.resourceId,
      reason: input.reason,
      details: input.details,
      missionId: input.missionId,
      runId: input.runId,
      journey: input.journey,
      previousHash: previous?.record_hash ?? null,
      occurredAt: input.occurredAt,
    }));
    this.#database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action, resource_type, resource_id, reason,
        details_json, previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, 'operator', ?, ?, 'memory_node', ?, ?, ?, ?, ?, ?)
    `).run(
      id, input.missionId, input.runId, input.journey,
      input.actor, input.action, input.resourceId, input.reason, details,
      previous?.record_hash ?? null, recordHash, input.occurredAt,
    );
    return id;
  }

  #resolveMemoryAuditScope(node: MemoryNode): {
    missionId: string | null;
    runId: string | null;
    journey: Journey | null;
  } {
    if (node.scope.kind !== "mission" || !node.scope.missionId) {
      return { missionId: null, runId: null, journey: null };
    }
    const mission = this.#database.prepare(
      "SELECT journey FROM missions WHERE id = ?",
    ).get(node.scope.missionId) as { journey: Journey } | undefined;
    if (!mission) throw new Error("Mission-scoped memory audit requires its canonical mission");

    const runSource = node.provenance.sources.find((source) => source.sourceType === "run");
    if (runSource) {
      const run = this.#database.prepare(
        "SELECT mission_id AS missionId, journey FROM runs WHERE id = ?",
      ).get(runSource.sourceId) as { missionId: string; journey: Journey } | undefined;
      if (run && run.missionId === node.scope.missionId) {
        if (run.journey !== mission.journey) {
          throw new Error("Memory audit run journey does not match its canonical mission");
        }
        return { missionId: node.scope.missionId, runId: runSource.sourceId, journey: run.journey };
      }
    }
    return { missionId: node.scope.missionId, runId: null, journey: mission.journey };
  }

  #assertContextPackLinkage(input: {
    readonly missionId?: string;
    readonly runId?: string;
    readonly stepId?: string;
    readonly actionId?: string;
    readonly messageId?: string;
    readonly journey: ContextPack["journey"];
    readonly scopePolicy: RetrievalPolicy;
  }): void {
    const missionIds = new Set<string>();
    const engagementIds = new Set<string | null>();
    const runIds = new Set<string>();
    const stepIds = new Set<string>();
    const journeys = new Set<Journey>([input.journey, input.scopePolicy.journey]);

    const addMission = (missionId: string, source: string): void => {
      const mission = this.#database.prepare(
        "SELECT journey, engagement_id FROM missions WHERE id = ?",
      ).get(missionId) as { journey: Journey; engagement_id: string | null } | undefined;
      if (!mission) throw new Error(`Context pack ${source} mission link is missing`);
      missionIds.add(missionId);
      engagementIds.add(mission.engagement_id);
      journeys.add(mission.journey);
    };
    const addRun = (runId: string, source: string): void => {
      const run = this.#database.prepare(
        "SELECT mission_id, journey FROM runs WHERE id = ?",
      ).get(runId) as { mission_id: string; journey: Journey } | undefined;
      if (!run) throw new Error(`Context pack ${source} run link is missing`);
      runIds.add(runId);
      journeys.add(run.journey);
      addMission(run.mission_id, `${source} run`);
    };
    const addStep = (stepId: string, source: string): void => {
      const step = this.#database.prepare(`
        SELECT ps.run_id, p.run_id AS plan_run_id
        FROM plan_steps ps
        JOIN plans p ON p.id = ps.plan_id
        WHERE ps.id = ?
      `).get(stepId) as { run_id: string; plan_run_id: string } | undefined;
      if (!step) throw new Error(`Context pack ${source} step link is missing`);
      if (step.run_id !== step.plan_run_id) {
        throw new Error("Context pack step run does not match its canonical plan");
      }
      stepIds.add(stepId);
      // plan_steps.run_id is the canonical direct step linkage. The plan's
      // run_id is checked above as an independent consistency constraint.
      addRun(step.run_id, `${source} step`);
    };

    if (input.missionId) addMission(input.missionId, "explicit");
    if (input.scopePolicy.missionId) addMission(input.scopePolicy.missionId, "scope-policy");
    if (input.scopePolicy.engagementId) engagementIds.add(input.scopePolicy.engagementId);
    if (input.runId) addRun(input.runId, "explicit");
    if (input.stepId) addStep(input.stepId, "explicit");
    if (input.actionId) {
      const action = this.#database.prepare(`
        SELECT mission_id, run_id, step_id FROM actions WHERE id = ?
      `).get(input.actionId) as {
        mission_id: string;
        run_id: string;
        step_id: string | null;
      } | undefined;
      if (!action) throw new Error("Context pack action link is missing");
      addMission(action.mission_id, "action");
      addRun(action.run_id, "action");
      if (action.step_id) addStep(action.step_id, "action");
    }
    if (input.messageId) {
      const message = this.#database.prepare(`
        SELECT c.mission_id, c.run_id, c.step_id
        FROM messages msg
        JOIN conversations c ON c.id = msg.conversation_id
        WHERE msg.id = ?
      `).get(input.messageId) as {
        mission_id: string | null;
        run_id: string | null;
        step_id: string | null;
      } | undefined;
      if (!message) throw new Error("Context pack message link is missing");
      if (message.mission_id) addMission(message.mission_id, "message");
      if (message.run_id) addRun(message.run_id, "message");
      if (message.step_id) addStep(message.step_id, "message");
    }

    if (missionIds.size > 1) throw new Error("Context pack mission links cross canonical scopes");
    if (engagementIds.size > 1) throw new Error("Context pack engagement does not match its canonical mission");
    if (runIds.size > 1) throw new Error("Context pack run links cross canonical scopes");
    if (stepIds.size > 1) throw new Error("Context pack step links cross canonical scopes");
    if (journeys.size > 1) throw new Error("Context pack journey does not match its canonical scope");
  }

  persistContextPack(input: {
    readonly id?: string;
    readonly missionId?: string;
    readonly runId?: string;
    readonly stepId?: string;
    readonly actionId?: string;
    readonly messageId?: string;
    readonly journey: ContextPack["journey"];
    readonly purpose: string;
    readonly queryRedacted?: string;
    readonly scopePolicy: RetrievalPolicy;
    readonly contextBudget: number;
    readonly retrievalMetrics?: Record<string, unknown>;
    readonly createdBy: string;
    readonly items: readonly RetrievedMemory[];
  }): ContextPack {
    assertNonEmpty(input.purpose, "context pack purpose", 2_000);
    assertNonEmpty(input.createdBy, "context pack creator", 256);
    assertReusableMemoryText([
      { field: "contextPack.purpose", value: input.purpose, maximumBytes: 2_000 },
      {
        field: "contextPack.queryRedacted",
        value: input.queryRedacted,
        maximumBytes: REUSABLE_MEMORY_LIMITS.contextMetadata,
      },
      ...input.items.map((item, index) => ({
        field: `contextPack.items[${index}].relevanceReason`,
        value: item.relevanceReason,
        maximumBytes: 2_000,
      })),
    ]);
    assertReusableMemoryUnknown(
      input.retrievalMetrics ?? {},
      "contextPack.retrievalMetrics",
      REUSABLE_MEMORY_LIMITS.contextMetadata,
    );
    if (!Number.isSafeInteger(input.contextBudget) || input.contextBudget < 0) {
      throw new TypeError("context budget must be a non-negative integer");
    }
    validateJourney(input.journey);
    validateJourney(input.scopePolicy.journey);
    validateSensitivity(input.scopePolicy.maximumSensitivity);
    if (input.scopePolicy.allowedStatuses?.some((status) => status !== "confirmed" && status !== "verified")) {
      throw new TypeError("context packs may retain only confirmed or verified memory");
    }
    input.scopePolicy.allowedNodeTypes?.forEach(validateNodeType);
    input.scopePolicy.exactNodeIds?.forEach((nodeId) => assertIdentifier(nodeId, "context pack exact memory ID"));
    if (input.scopePolicy.allowedScopeClasses) {
      const allowed = new Set(["confirmed_preferences", "verified_lessons", "engagement_memory"]);
      if (input.scopePolicy.allowedScopeClasses.some((scopeClass) => !allowed.has(scopeClass))) {
        throw new TypeError("context pack contains an unsupported Autonomous memory scope class");
      }
    }
    if (input.contextBudget !== input.scopePolicy.contextBudget) {
      throw new TypeError("context pack budget must match its retrieval policy");
    }
    for (const [value, label] of [
      [input.missionId, "context pack mission ID"],
      [input.scopePolicy.missionId, "context pack scope-policy mission ID"],
      [input.runId, "context pack run ID"],
      [input.stepId, "context pack step ID"],
      [input.actionId, "context pack action ID"],
      [input.messageId, "context pack message ID"],
    ] as const) {
      if (value !== undefined) assertIdentifier(value, label);
    }
    const id = input.id ?? this.createId("ctx");
    const now = this.now();
    return inImmediateTransaction(this.#database, () => {
      this.#assertContextPackLinkage(input);
      const canonicalItems = input.items.map((item) => {
        const node = this.requireNode(item.node.id);
        if (node.version !== item.node.version) {
          throw new Error("Context pack memory changed after retrieval");
        }
        if (!memoryNodeMatchesPolicy(this.#database, node, input.scopePolicy, now)) {
          throw new Error("Context pack item is outside its canonical retrieval scope");
        }
        return { ...item, node };
      });
      this.#database.prepare(`
        INSERT INTO memory_context_packs (
          id, mission_id, run_id, step_id, action_id, message_id, journey, purpose,
          query_redacted, scope_policy_json, context_budget, retrieval_metrics_json,
          created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, input.missionId ?? null, input.runId ?? null, input.stepId ?? null,
        input.actionId ?? null, input.messageId ?? null, input.journey, input.purpose,
        input.queryRedacted ?? null, canonicalJson(input.scopePolicy), input.contextBudget,
        canonicalJson(input.retrievalMetrics ?? {}), input.createdBy, now,
      );
      const insert = this.#database.prepare(`
        INSERT INTO memory_context_items (
          context_pack_id, node_id, rank, retrieval_score, used, relevance_reason,
          influence_summary, ignored_reason, corrected
        ) VALUES (?, ?, ?, ?, 0, ?, NULL, 'Not yet evaluated', 0)
      `);
      canonicalItems.forEach((item, rank) => {
        insert.run(id, item.node.id, rank, item.score, item.relevanceReason);
      });
      return this.requireContextPack(id);
    });
  }

  setContextItemDisposition(packId: string, disposition: ContextPackItemDisposition): void {
    assertIdentifier(packId, "context pack ID");
    assertIdentifier(disposition.nodeId, "memory node ID");
    assertNonEmpty(disposition.relevanceReason, "context relevance reason", 2_000);
    if (disposition.used && !disposition.influenceSummary?.trim()) {
      throw new TypeError("used context requires a concise influence summary");
    }
    if (!disposition.used && !disposition.ignoredReason?.trim()) {
      throw new TypeError("ignored context requires a reason");
    }
    assertReusableMemoryText([
      { field: "contextDisposition.relevanceReason", value: disposition.relevanceReason, maximumBytes: 2_000 },
      { field: "contextDisposition.influenceSummary", value: disposition.influenceSummary, maximumBytes: 2_000 },
      { field: "contextDisposition.ignoredReason", value: disposition.ignoredReason, maximumBytes: 2_000 },
    ]);
    const result = this.#database.prepare(`
      UPDATE memory_context_items SET used = ?, relevance_reason = ?, influence_summary = ?,
        ignored_reason = ?, corrected = ? WHERE context_pack_id = ? AND node_id = ?
    `).run(
      disposition.used ? 1 : 0, disposition.relevanceReason,
      disposition.used ? disposition.influenceSummary : null,
      disposition.used ? null : disposition.ignoredReason,
      disposition.corrected ? 1 : 0, packId, disposition.nodeId,
    );
    if (result.changes !== 1) throw new Error("Context pack item not found");
  }

  requireContextPack(id: string): ContextPack {
    assertIdentifier(id, "context pack ID");
    const row = this.#database.prepare(
      "SELECT * FROM memory_context_packs WHERE id = ?",
    ).get(id) as Record<string, unknown> | undefined;
    if (!row) throw new Error(`Context pack not found: ${id}`);
    const items = this.#database.prepare(`
      SELECT node_id, used, relevance_reason, influence_summary, ignored_reason, corrected
      FROM memory_context_items WHERE context_pack_id = ? ORDER BY rank
    `).all(id) as Array<Record<string, unknown>>;
    return {
      id,
      ...(row.mission_id ? { missionId: String(row.mission_id) } : {}),
      ...(row.run_id ? { runId: String(row.run_id) } : {}),
      ...(row.step_id ? { stepId: String(row.step_id) } : {}),
      ...(row.action_id ? { actionId: String(row.action_id) } : {}),
      ...(row.message_id ? { messageId: String(row.message_id) } : {}),
      journey: String(row.journey) as ContextPack["journey"],
      purpose: String(row.purpose),
      ...(row.query_redacted ? { queryRedacted: String(row.query_redacted) } : {}),
      scopePolicy: parseJson<RetrievalPolicy>(String(row.scope_policy_json), "context scope policy"),
      contextBudget: Number(row.context_budget),
      retrievalMetrics: parseJson<Record<string, unknown>>(String(row.retrieval_metrics_json), "retrieval metrics"),
      createdBy: String(row.created_by),
      createdAt: String(row.created_at),
      items: items.map((item) => ({
        nodeId: String(item.node_id),
        used: Number(item.used) === 1,
        relevanceReason: String(item.relevance_reason),
        ...(item.influence_summary ? { influenceSummary: String(item.influence_summary) } : {}),
        ...(item.ignored_reason ? { ignoredReason: String(item.ignored_reason) } : {}),
        corrected: Number(item.corrected) === 1,
      })),
    };
  }

  database(): SqliteDatabase {
    return this.#database;
  }
}

import {
  MEMORY_EDGE_TYPES,
  MEMORY_LIFECYCLE_STATES,
  MEMORY_NODE_TYPES,
  MEMORY_SENSITIVITIES,
  type BrainSummary,
  type ContextPackItem,
  type MemoryCandidate,
  type MemoryCandidatePage,
  type MemoryContextPack,
  type MemoryContextPackPage,
  type MemoryControlPolicy,
  type MemoryEdgeSummary,
  type MemoryGraph,
  type MemoryGraphView,
  type MemoryNode,
  type MemoryNodeDetail,
  type MemoryNodePage,
  type MemoryNodeSummary,
  type MemoryProvenance,
  type MemoryScope,
  type MemoryUsage,
  type MemoryVersion,
  type ProvenanceSource,
  type VaultConflict,
  type VaultConnection,
  type VaultHealthCheckResult,
  type VaultHealthChecks,
  type VaultOperationResult,
  type VaultRecoveryResult,
  type VaultSnapshot,
  type VaultSyncState,
} from "../types/brain";

type UnknownRecord = Record<string, unknown>;

function record(value: unknown, label: string): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as UnknownRecord;
}

function unwrap(payload: unknown): unknown {
  const value = record(payload, "response");
  return value.data && typeof value.data === "object" ? value.data : value;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function number(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${label} must be a finite number`);
  return value;
}

function count(value: unknown, label: string): number {
  const result = number(value, label);
  if (!Number.isSafeInteger(result) || result < 0) throw new Error(`${label} must be a non-negative integer`);
  return result;
}

function list(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function enumValue<T extends string>(value: unknown, values: readonly T[], label: string): T {
  if (typeof value === "string" && values.includes(value as T)) return value as T;
  throw new Error(`${label} is invalid`);
}

function schemaVersion(value: unknown): "2.4" {
  if (value !== "2.4") throw new Error("unsupported Second Brain schema version");
  return value;
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be boolean`);
  return value;
}

export function parseMemoryControlPolicy(payload: unknown): MemoryControlPolicy {
  const root = record(unwrap(payload), "memory control response");
  const value = record(root.policy ?? root, "memory control policy");
  const retention = value.defaultRetentionDays;
  if (retention !== null && (typeof retention !== "number" || !Number.isSafeInteger(retention) || retention < 1 || retention > 3_650)) {
    throw new Error("default memory retention is invalid");
  }
  if (value.engagementIsolation !== true || value.secretsNeverRetained !== true) {
    throw new Error("mandatory memory safety invariants are missing");
  }
  return {
    enabled: boolean(value.enabled, "memory enabled"),
    personalPreferencePolicy: enumValue(value.personalPreferencePolicy, ["candidate_only", "disabled"] as const, "preference policy"),
    operationalMemoryEnabled: boolean(value.operationalMemoryEnabled, "operational memory enabled"),
    engagementIsolation: true,
    defaultRetentionDays: retention === null ? null : retention,
    autonomousUse: boolean(value.autonomousUse, "Autonomous memory use"),
    guidedUse: boolean(value.guidedUse, "Guided memory use"),
    obsidianSyncScope: enumValue(value.obsidianSyncScope, ["disabled", "confirmed", "confirmed_and_verified"] as const, "Obsidian sync scope"),
    secretsNeverRetained: true,
    version: count(value.version, "memory control version"),
    updatedBy: text(value.updatedBy, "memory control updater"),
    updatedAt: text(value.updatedAt, "memory control update time"),
  };
}

function parseScope(value: unknown): MemoryScope {
  const item = record(value, "memory scope");
  const kind = enumValue(item.kind, ["global", "engagement", "mission"] as const, "memory scope kind");
  const engagementId = optionalText(item.engagementId);
  const missionId = optionalText(item.missionId);
  if (kind === "engagement" && !engagementId) throw new Error("engagement memory scope requires engagementId");
  if (kind === "mission" && !missionId) throw new Error("mission memory scope requires missionId");
  return { kind, ...(engagementId ? { engagementId } : {}), ...(missionId ? { missionId } : {}) };
}

export function parseProvenanceSource(value: unknown): ProvenanceSource {
  const item = record(value, "provenance source");
  return {
    sourceType: text(item.sourceType, "source type"),
    sourceId: text(item.sourceId, "source id"),
    acquiredAt: text(item.acquiredAt, "source acquiredAt"),
    ...(optionalText(item.sourceHash) ? { sourceHash: optionalText(item.sourceHash) } : {}),
    ...(optionalText(item.excerptRedacted) ? { excerptRedacted: optionalText(item.excerptRedacted) } : {}),
  };
}

function parseProvenance(value: unknown): MemoryProvenance {
  const item = record(value, "memory provenance");
  return {
    method: enumValue(item.method, ["operator_statement", "observation", "evidence", "derived", "imported"] as const, "provenance method"),
    explanation: text(item.explanation, "provenance explanation"),
    sources: list(item.sources, "provenance sources").map(parseProvenanceSource),
  };
}

export function parseMemoryNodeSummary(value: unknown, allowMissingCounts = false): MemoryNodeSummary {
  const item = record(value, "memory node");
  const confidence = number(item.confidence, "memory confidence");
  if (confidence < 0 || confidence > 1) throw new Error("memory confidence must be between zero and one");
  return {
    id: text(item.id, "memory node id"),
    nodeType: enumValue(item.nodeType, MEMORY_NODE_TYPES, "memory node type"),
    title: text(item.title, "memory title"),
    summary: typeof item.summary === "string" ? item.summary : "",
    scope: parseScope(item.scope),
    sensitivity: enumValue(item.sensitivity, MEMORY_SENSITIVITIES, "memory sensitivity"),
    confidence,
    lifecycleStatus: enumValue(item.lifecycleStatus, MEMORY_LIFECYCLE_STATES, "memory lifecycle"),
    confirmationState: enumValue(item.confirmationState, ["not_required", "pending", "confirmed", "rejected"] as const, "confirmation state"),
    version: count(item.version, "memory version"),
    pinned: item.pinned === true,
    ...(optionalText(item.expiresAt) ? { expiresAt: optionalText(item.expiresAt) } : {}),
    createdAt: text(item.createdAt, "memory createdAt"),
    updatedAt: text(item.updatedAt, "memory updatedAt"),
    edgeCount: item.edgeCount === undefined && allowMissingCounts ? 0 : count(item.edgeCount, "memory edge count"),
    sourceCount: item.sourceCount === undefined && allowMissingCounts ? 0 : count(item.sourceCount, "memory source count"),
  };
}

export function parseMemoryNode(value: unknown): MemoryNode {
  const item = record(value, "memory node detail");
  const summary = parseMemoryNodeSummary(item, true);
  const retentionPolicy = record(item.retentionPolicy ?? {}, "memory retention policy");
  return {
    ...summary,
    body: typeof item.body === "string" ? item.body : "",
    authorType: enumValue(item.authorType, ["operator", "agent", "system", "import"] as const, "memory author type"),
    ...(optionalText(item.authorId) ? { authorId: optionalText(item.authorId) } : {}),
    provenance: parseProvenance(item.provenance),
    retentionPolicy,
  };
}

export function parseMemoryEdge(value: unknown): MemoryEdgeSummary {
  const item = record(value, "memory edge");
  return {
    id: text(item.id, "memory edge id"),
    sourceNodeId: text(item.sourceNodeId, "memory edge source"),
    targetNodeId: text(item.targetNodeId, "memory edge target"),
    edgeType: enumValue(item.edgeType, MEMORY_EDGE_TYPES, "memory edge type"),
    title: text(item.title, "memory edge title"),
    summary: typeof item.summary === "string" ? item.summary : "",
    confidence: number(item.confidence, "memory edge confidence"),
    lifecycleStatus: enumValue(item.lifecycleStatus, MEMORY_LIFECYCLE_STATES, "memory edge lifecycle"),
    explanation: text(item.explanation, "memory edge explanation"),
  };
}

export function parseBrainSummary(payload: unknown): BrainSummary {
  const value = record(unwrap(payload), "brain summary");
  const counts = record(value.counts, "brain counts");
  const health = record(value.health, "brain health");
  const vault = record(value.vault, "brain vault summary");
  return {
    schemaVersion: schemaVersion(value.schemaVersion),
    counts: {
      confirmed: count(counts.confirmed, "confirmed count"), verified: count(counts.verified, "verified count"),
      candidates: count(counts.candidates, "candidate count"),
      stale: count(counts.stale, "stale count"), disputed: count(counts.disputed, "disputed count"),
      forgotten: count(counts.forgotten, "forgotten count"), edges: count(counts.edges, "edge count"),
      contextPacks: count(counts.contextPacks, "context pack count"),
    },
    health: { database: text(health.database, "brain database health"), fts: text(health.fts, "brain FTS health") },
    vault: {
      status: text(vault.status, "vault status"), connections: count(vault.connections, "vault connection count"),
      conflicts: count(vault.conflicts, "vault conflict count"),
      lastSyncAt: vault.lastSyncAt === null || vault.lastSyncAt === undefined ? null : text(vault.lastSyncAt, "vault last sync"),
    },
    recentNodes: list(value.recentNodes, "recent memory nodes").map((item) => parseMemoryNodeSummary(item)),
  };
}

export function parseMemoryNodePage(payload: unknown): MemoryNodePage {
  const value = record(unwrap(payload), "memory node page");
  return {
    schemaVersion: schemaVersion(value.schemaVersion),
    items: list(value.items, "memory nodes").map((item) => parseMemoryNodeSummary(item)),
    nextCursor: value.nextCursor === null || value.nextCursor === undefined ? null : text(value.nextCursor, "next cursor"),
    totalReturned: count(value.totalReturned, "returned node count"),
  };
}

export function parseMemoryGraph(payload: unknown): MemoryGraph {
  const value = record(unwrap(payload), "memory graph");
  const nodes = list(value.nodes, "graph nodes").map((item) => parseMemoryNodeSummary(item));
  const availableNodeCount = count(value.availableNodeCount, "available graph node count");
  const truncated = value.truncated === true;
  if (availableNodeCount < nodes.length) throw new RangeError("available graph node count cannot be smaller than the loaded node count");
  if (truncated !== (availableNodeCount > nodes.length)) throw new RangeError("graph truncation must match the available and loaded node counts");
  return {
    schemaVersion: schemaVersion(value.schemaVersion),
    view: enumValue(value.view, ["global", "local", "mission", "operator"] as const, "graph view") as MemoryGraphView,
    ...(optionalText(value.rootNodeId) ? { rootNodeId: optionalText(value.rootNodeId) } : {}),
    nodes,
    edges: list(value.edges, "graph edges").map(parseMemoryEdge),
    availableNodeCount,
    truncated,
  };
}

function parseVersion(value: unknown): MemoryVersion {
  const item = record(value, "memory version");
  return {
    version: count(item.version, "version number"), title: text(item.title, "version title"),
    summary: typeof item.summary === "string" ? item.summary : "",
    changedAt: text(item.changedAt, "version changedAt"), changedBy: text(item.changedBy, "version changedBy"),
    ...(optionalText(item.changeReason) ? { changeReason: optionalText(item.changeReason) } : {}),
  };
}

function parseUsage(value: unknown): MemoryUsage {
  const item = record(value, "memory usage");
  return {
    contextPackId: text(item.contextPackId, "context pack id"),
    ...(optionalText(item.missionId) ? { missionId: optionalText(item.missionId) } : {}),
    ...(optionalText(item.runId) ? { runId: optionalText(item.runId) } : {}),
    purpose: text(item.purpose, "memory use purpose"), used: item.used === true,
    relevanceReason: text(item.relevanceReason, "memory relevance reason"),
    ...(optionalText(item.influenceSummary) ? { influenceSummary: optionalText(item.influenceSummary) } : {}),
    ...(optionalText(item.ignoredReason) ? { ignoredReason: optionalText(item.ignoredReason) } : {}),
    createdAt: text(item.createdAt, "memory usage createdAt"),
  };
}

export function parseMemoryNodeDetail(payload: unknown): MemoryNodeDetail {
  const value = record(unwrap(payload), "memory node response");
  return {
    node: parseMemoryNode(value.node), sources: list(value.sources, "memory sources").map(parseProvenanceSource),
    versions: list(value.versions, "memory versions").map(parseVersion),
    backlinks: list(value.backlinks, "memory backlinks").map(parseMemoryEdge),
    outgoing: list(value.outgoing, "memory outgoing edges").map(parseMemoryEdge),
    usage: list(value.usage, "memory usage").map(parseUsage),
  };
}

function parseCandidate(value: unknown): MemoryCandidate {
  const item = record(value, "memory candidate");
  return {
    id: text(item.id, "candidate id"), ...(optionalText(item.proposedNodeId) ? { proposedNodeId: optionalText(item.proposedNodeId) } : {}),
    nodeType: enumValue(item.nodeType, MEMORY_NODE_TYPES, "candidate node type"), title: text(item.title, "candidate title"),
    summary: typeof item.summary === "string" ? item.summary : "", body: typeof item.body === "string" ? item.body : "",
    scope: parseScope(item.scope), sensitivity: enumValue(item.sensitivity, MEMORY_SENSITIVITIES, "candidate sensitivity"),
    confidence: number(item.confidence, "candidate confidence"), provenance: parseProvenance(item.provenance),
    status: enumValue(item.status, ["pending", "confirmed", "edited_confirmed", "merged", "rejected", "suppressed"] as const, "candidate status"),
    proposedBy: text(item.proposedBy, "candidate proposer"),
    ...(optionalText(item.reviewedBy) ? { reviewedBy: optionalText(item.reviewedBy) } : {}),
    ...(optionalText(item.reviewedAt) ? { reviewedAt: optionalText(item.reviewedAt) } : {}),
    createdAt: text(item.createdAt, "candidate createdAt"),
  };
}

export function parseMemoryCandidatePage(payload: unknown): MemoryCandidatePage {
  const value = record(unwrap(payload), "candidate page");
  return {
    items: list(value.items, "memory candidates").map(parseCandidate),
    nextCursor: value.nextCursor === null || value.nextCursor === undefined ? null : text(value.nextCursor, "candidate next cursor"),
  };
}

function parseContextItem(value: unknown): ContextPackItem {
  const item = record(value, "context pack item");
  return {
    node: parseMemoryNodeSummary(item.node), used: item.used === true,
    relevanceReason: text(item.relevanceReason, "context relevance reason"),
    ...(optionalText(item.influenceSummary) ? { influenceSummary: optionalText(item.influenceSummary) } : {}),
    ...(optionalText(item.ignoredReason) ? { ignoredReason: optionalText(item.ignoredReason) } : {}),
    ...(typeof item.corrected === "boolean" ? { corrected: item.corrected } : {}),
  };
}

export function parseMemoryContextPack(payload: unknown): MemoryContextPack {
  const value = record(unwrap(payload), "context pack");
  return {
    id: text(value.id, "context pack id"),
    ...(optionalText(value.missionId) ? { missionId: optionalText(value.missionId) } : {}),
    ...(optionalText(value.runId) ? { runId: optionalText(value.runId) } : {}),
    ...(optionalText(value.stepId) ? { stepId: optionalText(value.stepId) } : {}),
    ...(optionalText(value.actionId) ? { actionId: optionalText(value.actionId) } : {}),
    ...(optionalText(value.messageId) ? { messageId: optionalText(value.messageId) } : {}),
    journey: enumValue(value.journey, ["autonomous", "guided"] as const, "context journey"),
    purpose: text(value.purpose, "context purpose"),
    ...(optionalText(value.queryRedacted) ? { queryRedacted: optionalText(value.queryRedacted) } : {}),
    contextBudget: count(value.contextBudget, "context budget"),
    retrievalMetrics: record(value.retrievalMetrics ?? {}, "retrieval metrics"),
    createdBy: text(value.createdBy, "context creator"), createdAt: text(value.createdAt, "context createdAt"),
    items: list(value.items, "context items").map(parseContextItem),
  };
}

export function parseMemoryContextPackPage(payload: unknown): MemoryContextPackPage {
  const value = record(unwrap(payload), "context pack page");
  return {
    items: list(value.items, "context pack summaries").map((entry) => {
      const item = record(entry, "context pack summary");
      return {
        id: text(item.id, "context pack summary id"),
        ...(optionalText(item.missionId) ? { missionId: optionalText(item.missionId) } : {}),
        ...(optionalText(item.runId) ? { runId: optionalText(item.runId) } : {}),
        ...(optionalText(item.stepId) ? { stepId: optionalText(item.stepId) } : {}),
        ...(optionalText(item.actionId) ? { actionId: optionalText(item.actionId) } : {}),
        ...(optionalText(item.messageId) ? { messageId: optionalText(item.messageId) } : {}),
        journey: enumValue(item.journey, ["autonomous", "guided"] as const, "context pack summary journey"),
        purpose: text(item.purpose, "context pack summary purpose"),
        contextBudget: count(item.contextBudget, "context pack summary budget"),
        createdBy: text(item.createdBy, "context pack summary creator"),
        createdAt: text(item.createdAt, "context pack summary createdAt"),
        retrievedItemCount: count(item.retrievedItemCount, "context pack retrieved count"),
        usedItemCount: count(item.usedItemCount, "context pack used count"),
        correctedItemCount: count(item.correctedItemCount, "context pack corrected count"),
      };
    }),
    totalReturned: count(value.totalReturned, "returned context pack count"),
  };
}

export function parseVaultConnection(value: unknown): VaultConnection {
  const item = record(value, "vault connection");
  return {
    id: text(item.id, "vault connection id"), vaultPath: text(item.vaultPath, "vault path"),
    displayName: text(item.displayName, "vault display name"),
    status: enumValue(item.status, ["disconnected", "connecting", "connected", "degraded", "error"] as const, "vault connection status"),
    ...(typeof item.pathAvailable === "boolean" ? { pathAvailable: item.pathAvailable } : {}),
    syncScope: record(item.syncScope ?? {}, "vault sync scope"), permissionGrantedAt: text(item.permissionGrantedAt, "vault permission time"),
    ...(optionalText(item.lastSyncAt) ? { lastSyncAt: optionalText(item.lastSyncAt) } : {}),
    ...(optionalText(item.lastHealthCheckAt) ? { lastHealthCheckAt: optionalText(item.lastHealthCheckAt) } : {}),
    ...(item.healthChecks === undefined ? {} : { healthChecks: parseVaultHealthChecks(item.healthChecks) }),
    ...(typeof item.trackedNoteCount === "number" ? { trackedNoteCount: count(item.trackedNoteCount, "tracked note count") } : {}),
    ...(typeof item.needsReviewCount === "number" ? { needsReviewCount: count(item.needsReviewCount, "notes needing review count") } : {}),
    createdAt: text(item.createdAt, "vault createdAt"), updatedAt: text(item.updatedAt, "vault updatedAt"),
    ...(optionalText(item.obsidianUrl) ? { obsidianUrl: optionalText(item.obsidianUrl) } : {}),
  };
}

function parseVaultHealthChecks(value: unknown): VaultHealthChecks {
  const checks = record(value, "vault health checks");
  if (checks.write !== true || checks.read !== true || checks.rename !== true || checks.delete !== true) {
    throw new Error("vault health checks must prove write, read, rename, and delete");
  }
  return { write: true, read: true, rename: true, delete: true };
}

export function parseVaultHealthCheck(payload: unknown): VaultHealthCheckResult {
  const root = record(unwrap(payload), "vault health response");
  const value = record(root.result ?? root, "vault health result");
  return {
    status: enumValue(value.status, ["healthy"] as const, "vault health status"),
    ...(optionalText(value.connectionId) ? { connectionId: optionalText(value.connectionId) } : {}),
    vaultPath: text(value.vaultPath, "vault health path"),
    checkedAt: text(value.checkedAt, "vault health time"),
    checks: parseVaultHealthChecks(value.checks),
    message: text(value.message, "vault health message"),
  };
}

export function parseVaultConnectionMutation(payload: unknown): VaultConnection {
  const root = record(unwrap(payload), "vault connection response");
  return parseVaultConnection(root.connection ?? root);
}

function parseVaultSyncState(value: unknown): VaultSyncState {
  const item = record(value, "vault sync state");
  return {
    id: text(item.id, "sync state id"), connectionId: text(item.connectionId, "sync connection id"),
    ...(optionalText(item.nodeId) ? { nodeId: optionalText(item.nodeId) } : {}), relativePath: text(item.relativePath, "sync relative path"),
    status: enumValue(item.status, ["pending", "synced", "database_ahead", "vault_ahead", "conflict", "quarantined", "deleted", "error"] as const, "sync state status"),
    ...(optionalText(item.lastScannedAt) ? { lastScannedAt: optionalText(item.lastScannedAt) } : {}),
    ...(optionalText(item.lastSyncedAt) ? { lastSyncedAt: optionalText(item.lastSyncedAt) } : {}),
    ...(optionalText(item.errorMessage) ? { errorMessage: optionalText(item.errorMessage) } : {}),
    ...(optionalText(item.obsidianUrl) ? { obsidianUrl: optionalText(item.obsidianUrl) } : {}),
  };
}

function parseVaultConflict(value: unknown): VaultConflict {
  const item = record(value, "vault conflict");
  return {
    id: text(item.id, "vault conflict id"), connectionId: text(item.connectionId, "vault conflict connection"),
    ...(optionalText(item.nodeId) ? { nodeId: optionalText(item.nodeId) } : {}), relativePath: text(item.relativePath, "vault conflict path"),
    status: enumValue(item.status, ["open", "resolved", "dismissed"] as const, "vault conflict status"),
    ...(typeof item.databaseVersion === "number" ? { databaseVersion: count(item.databaseVersion, "conflict database version") } : {}),
    detectedAt: text(item.detectedAt, "conflict detectedAt"),
    ...(optionalText(item.resolvedAt) ? { resolvedAt: optionalText(item.resolvedAt) } : {}),
    ...(optionalText(item.databaseTextRedacted) ? { databaseTextRedacted: optionalText(item.databaseTextRedacted) } : {}),
    ...(optionalText(item.vaultTextRedacted) ? { vaultTextRedacted: optionalText(item.vaultTextRedacted) } : {}),
  };
}

export function parseVaultSnapshot(payload: unknown): VaultSnapshot {
  const value = record(unwrap(payload), "vault snapshot");
  return {
    enabled: value.enabled === true,
    ...(typeof value.syncEnabled === "boolean" ? { syncEnabled: value.syncEnabled } : {}),
    ...(Array.isArray(value.projectionLifecycleStatuses)
      ? { projectionLifecycleStatuses: value.projectionLifecycleStatuses.map((item) => text(item, "vault projection lifecycle")) }
      : {}),
    ...(optionalText(value.allowedRootLabel) ? { allowedRootLabel: optionalText(value.allowedRootLabel) } : {}),
    connections: list(value.connections, "vault connections").map(parseVaultConnection),
    syncStates: list(value.syncStates, "vault sync states").map(parseVaultSyncState),
    conflicts: list(value.conflicts, "vault conflicts").map(parseVaultConflict),
  };
}

export function parseVaultOperation(payload: unknown): VaultOperationResult {
  const root = record(unwrap(payload), "vault operation response");
  const value = record(root.result ?? root, "vault operation result");
  return {
    ...(optionalText(value.connectionId) ? { connectionId: optionalText(value.connectionId) } : {}),
    ...(optionalText(value.nodeId) ? { nodeId: optionalText(value.nodeId) } : {}),
    ...(optionalText(value.relativePath) ? { relativePath: optionalText(value.relativePath) } : {}),
    status: text(value.status, "vault operation status"),
    ...(optionalText(value.conflictId) ? { conflictId: optionalText(value.conflictId) } : {}),
    message: text(value.message, "vault operation message"),
    ...(optionalText(value.archiveName) ? { archiveName: optionalText(value.archiveName) } : {}),
    ...(optionalText(value.downloadUrl) ? { downloadUrl: optionalText(value.downloadUrl) } : {}),
    ...(typeof value.byteSize === "number" ? { byteSize: count(value.byteSize, "vault archive byte size") } : {}),
    ...(typeof value.fileCount === "number" ? { fileCount: count(value.fileCount, "vault archive file count") } : {}),
    ...(optionalText(value.sha256) ? { sha256: optionalText(value.sha256) } : {}),
    ...(optionalText(value.createdAt) ? { createdAt: optionalText(value.createdAt) } : {}),
  };
}

export function parseVaultRecovery(payload: unknown): VaultRecoveryResult {
  const root = record(unwrap(payload), "vault recovery response");
  const value = record(root.result ?? root, "vault recovery result");
  const health = record(value.health, "vault recovery health");
  const progress = record(value.progress, "vault recovery progress");
  const countsValue = record(value.counts, "vault recovery counts");
  if (typeof value.issueSampleTruncated !== "boolean") {
    throw new Error("vault recovery issueSampleTruncated must be boolean");
  }
  return {
    operation: enumValue(value.operation, ["repair", "reindex"] as const, "vault recovery operation"),
    connectionId: text(value.connectionId, "vault recovery connection"),
    status: enumValue(value.status, ["completed", "partial"] as const, "vault recovery status"),
    startedAt: text(value.startedAt, "vault recovery startedAt"),
    completedAt: text(value.completedAt, "vault recovery completedAt"),
    elapsedMs: count(value.elapsedMs, "vault recovery elapsed milliseconds"),
    expectedConnectionVersion: text(value.expectedConnectionVersion, "vault expected connection version"),
    connectionVersion: text(value.connectionVersion, "vault connection version"),
    health: {
      checkedAt: text(health.checkedAt, "vault recovery health time"),
      checks: parseVaultHealthChecks(health.checks),
    },
    progress: {
      discovered: count(progress.discovered, "vault recovery discovered count"),
      processed: count(progress.processed, "vault recovery processed count"),
      remaining: count(progress.remaining, "vault recovery remaining count"),
    },
    counts: {
      synced: count(countsValue.synced, "vault recovery synced count"),
      databaseAhead: count(countsValue.databaseAhead, "vault recovery database-ahead count"),
      vaultAhead: count(countsValue.vaultAhead, "vault recovery vault-ahead count"),
      conflictsPreserved: count(countsValue.conflictsPreserved, "vault recovery preserved-conflict count"),
      quarantined: count(countsValue.quarantined, "vault recovery quarantined count"),
      missing: count(countsValue.missing, "vault recovery missing count"),
      pending: count(countsValue.pending, "vault recovery pending count"),
      indexed: count(countsValue.indexed, "vault recovery indexed count"),
      skipped: count(countsValue.skipped, "vault recovery skipped count"),
      errors: count(countsValue.errors, "vault recovery error count"),
    },
    issues: list(value.issues, "vault recovery issues").map((candidate) => {
      const issue = record(candidate, "vault recovery issue");
      return {
        category: enumValue(issue.category, ["conflict_preserved", "malformed_note", "missing_projection", "pending_candidate", "scope_denied", "unsafe_path", "scan_limit", "duplicate_projection", "permission_denied", "concurrent_change", "quarantine_recovery", "processing_error"] as const, "vault recovery issue category"),
        message: text(issue.message, "vault recovery issue message"),
        ...(optionalText(issue.relativePath) ? { relativePath: optionalText(issue.relativePath) } : {}),
        ...(optionalText(issue.nodeId) ? { nodeId: optionalText(issue.nodeId) } : {}),
      };
    }),
    issueSampleTruncated: value.issueSampleTruncated,
    message: text(value.message, "vault recovery message"),
  };
}

export function parseNodeMutation(payload: unknown): MemoryNode {
  const root = record(unwrap(payload), "memory mutation response");
  return parseMemoryNode(root.node ?? root);
}

export function parseCandidateMutation(payload: unknown): MemoryCandidate {
  const root = record(unwrap(payload), "candidate mutation response");
  return parseCandidate(root.candidate ?? root);
}

export function parseForgetMutation(payload: unknown): { suppressionId: string } {
  const root = record(unwrap(payload), "forget response");
  const result = root.result && typeof root.result === "object" ? record(root.result, "forget result") : root;
  return { suppressionId: text(result.suppressionId, "memory suppression id") };
}

export function parseCandidateRejection(payload: unknown): { status: string; suppressionId?: string } {
  const root = record(unwrap(payload), "candidate rejection response");
  const candidate = root.candidate && typeof root.candidate === "object" ? record(root.candidate, "rejected candidate") : undefined;
  const status = candidate ? text(candidate.status, "candidate rejection status") : optionalText(root.status) ?? "rejected";
  const suppressionId = optionalText(root.suppressionId) ?? (root.result && typeof root.result === "object" ? optionalText(record(root.result, "candidate rejection result").suppressionId) : undefined);
  return { status, ...(suppressionId ? { suppressionId } : {}) };
}

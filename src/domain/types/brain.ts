export const MEMORY_NODE_TYPES = [
  "operator", "preference", "mission", "run", "plan", "phase", "step", "agent",
  "tool", "mcp_capability", "tactic", "technique", "procedure", "target", "asset",
  "entity", "decision", "evidence", "finding", "artifact", "failure", "recovery",
  "evaluation", "lesson", "report", "source",
] as const;

export const MEMORY_EDGE_TYPES = [
  "prefers", "applies_to", "belongs_to", "executed_by", "delegated_to", "used_in",
  "targets", "produced", "supports", "contradicts", "depends_on", "derived_from",
  "learned_from", "failed_in", "recovered_by", "similar_to", "supersedes",
  "verified_by", "mentioned_in", "influenced",
] as const;

export const MEMORY_LIFECYCLE_STATES = [
  "candidate", "confirmed", "verified", "disputed", "stale", "superseded", "forgotten",
] as const;

export const MEMORY_SENSITIVITIES = ["public", "internal", "private", "restricted"] as const;

export type MemoryNodeType = (typeof MEMORY_NODE_TYPES)[number];
export type MemoryEdgeType = (typeof MEMORY_EDGE_TYPES)[number];
export type MemoryLifecycle = (typeof MEMORY_LIFECYCLE_STATES)[number];
export type MemorySensitivity = (typeof MEMORY_SENSITIVITIES)[number];
export type MemoryGraphView = "global" | "local" | "mission" | "operator";

export interface MemoryControlPolicy {
  enabled: boolean;
  personalPreferencePolicy: "candidate_only" | "disabled";
  operationalMemoryEnabled: boolean;
  engagementIsolation: true;
  defaultRetentionDays: number | null;
  autonomousUse: boolean;
  guidedUse: boolean;
  obsidianSyncScope: "disabled" | "confirmed" | "confirmed_and_verified";
  secretsNeverRetained: true;
  version: number;
  updatedBy: string;
  updatedAt: string;
}

export interface MemoryScope {
  kind: "global" | "engagement" | "mission";
  engagementId?: string;
  missionId?: string;
}

export interface ProvenanceSource {
  sourceType: string;
  sourceId: string;
  acquiredAt: string;
  sourceHash?: string;
  excerptRedacted?: string;
}

export interface MemoryProvenance {
  method: "operator_statement" | "observation" | "evidence" | "derived" | "imported";
  explanation: string;
  sources: ProvenanceSource[];
}

export interface MemoryNodeSummary {
  id: string;
  nodeType: MemoryNodeType;
  title: string;
  summary: string;
  scope: MemoryScope;
  sensitivity: MemorySensitivity;
  confidence: number;
  lifecycleStatus: MemoryLifecycle;
  confirmationState: "not_required" | "pending" | "confirmed" | "rejected";
  version: number;
  pinned: boolean;
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
  edgeCount: number;
  sourceCount: number;
}

export interface MemoryNode extends MemoryNodeSummary {
  body: string;
  authorType: "operator" | "agent" | "system" | "import";
  authorId?: string;
  provenance: MemoryProvenance;
  retentionPolicy: Record<string, unknown>;
}

export interface MemoryEdgeSummary {
  id: string;
  sourceNodeId: string;
  targetNodeId: string;
  edgeType: MemoryEdgeType;
  title: string;
  summary: string;
  confidence: number;
  lifecycleStatus: MemoryLifecycle;
  explanation: string;
}

export interface BrainSummary {
  schemaVersion: "2.4";
  counts: {
    confirmed: number;
    verified: number;
    candidates: number;
    stale: number;
    disputed: number;
    forgotten: number;
    edges: number;
    contextPacks: number;
  };
  health: { database: string; fts: string };
  vault: { status: string; connections: number; conflicts: number; lastSyncAt: string | null };
  recentNodes: MemoryNodeSummary[];
}

export interface MemoryNodePage {
  schemaVersion: "2.4";
  items: MemoryNodeSummary[];
  nextCursor: string | null;
  totalReturned: number;
}

export interface MemoryGraph {
  schemaVersion: "2.4";
  view: MemoryGraphView;
  rootNodeId?: string;
  nodes: MemoryNodeSummary[];
  edges: MemoryEdgeSummary[];
  /** Full access-controlled result count before the bounded render limit. */
  availableNodeCount: number;
  truncated: boolean;
}

export interface MemoryVersion {
  version: number;
  title: string;
  summary: string;
  changedAt: string;
  changedBy: string;
  changeReason?: string;
}

export interface MemoryUsage {
  contextPackId: string;
  missionId?: string;
  runId?: string;
  purpose: string;
  used: boolean;
  relevanceReason: string;
  influenceSummary?: string;
  ignoredReason?: string;
  createdAt: string;
}

export interface MemoryNodeDetail {
  node: MemoryNode;
  sources: ProvenanceSource[];
  versions: MemoryVersion[];
  backlinks: MemoryEdgeSummary[];
  outgoing: MemoryEdgeSummary[];
  usage: MemoryUsage[];
}

export interface MemoryCandidate {
  id: string;
  proposedNodeId?: string;
  nodeType: MemoryNodeType;
  title: string;
  summary: string;
  body: string;
  scope: MemoryScope;
  sensitivity: MemorySensitivity;
  confidence: number;
  provenance: MemoryProvenance;
  status: "pending" | "confirmed" | "edited_confirmed" | "merged" | "rejected" | "suppressed";
  proposedBy: string;
  reviewedBy?: string;
  reviewedAt?: string;
  createdAt: string;
}

export interface MemoryCandidatePage {
  items: MemoryCandidate[];
  nextCursor: string | null;
}

export interface ContextPackItem {
  node: MemoryNodeSummary;
  used: boolean;
  relevanceReason: string;
  influenceSummary?: string;
  ignoredReason?: string;
  corrected?: boolean;
}

export interface MemoryContextPack {
  id: string;
  missionId?: string;
  runId?: string;
  stepId?: string;
  actionId?: string;
  messageId?: string;
  journey: "autonomous" | "guided";
  purpose: string;
  queryRedacted?: string;
  contextBudget: number;
  retrievalMetrics: Record<string, unknown>;
  createdBy: string;
  createdAt: string;
  items: ContextPackItem[];
}

export interface MemoryContextPackSummary {
  id: string;
  missionId?: string;
  runId?: string;
  stepId?: string;
  actionId?: string;
  messageId?: string;
  journey: "autonomous" | "guided";
  purpose: string;
  contextBudget: number;
  createdBy: string;
  createdAt: string;
  retrievedItemCount: number;
  usedItemCount: number;
  correctedItemCount: number;
}

export interface MemoryContextPackPage {
  items: MemoryContextPackSummary[];
  totalReturned: number;
}

export interface MemoryContextPackQuery {
  missionId?: string;
  runId?: string;
  stepId?: string;
  actionId?: string;
  messageId?: string;
  journey?: "autonomous" | "guided";
  limit?: number;
}

export interface VaultConnection {
  id: string;
  vaultPath: string;
  displayName: string;
  status: "disconnected" | "connecting" | "connected" | "degraded" | "error";
  pathAvailable?: boolean;
  syncScope: Record<string, unknown>;
  permissionGrantedAt: string;
  lastSyncAt?: string;
  lastHealthCheckAt?: string;
  healthChecks?: VaultHealthChecks;
  trackedNoteCount?: number;
  needsReviewCount?: number;
  createdAt: string;
  updatedAt: string;
  obsidianUrl?: string;
}

export interface VaultHealthChecks {
  write: true;
  read: true;
  rename: true;
  delete: true;
}

export interface VaultHealthCheckResult {
  status: "healthy";
  connectionId?: string;
  vaultPath: string;
  checkedAt: string;
  checks: VaultHealthChecks;
  message: string;
}

export interface VaultSyncState {
  id: string;
  connectionId: string;
  nodeId?: string;
  relativePath: string;
  status: "pending" | "synced" | "database_ahead" | "vault_ahead" | "conflict" | "quarantined" | "deleted" | "error";
  lastScannedAt?: string;
  lastSyncedAt?: string;
  errorMessage?: string;
  obsidianUrl?: string;
}

export interface VaultConflict {
  id: string;
  connectionId: string;
  nodeId?: string;
  relativePath: string;
  status: "open" | "resolved" | "dismissed";
  databaseVersion?: number;
  detectedAt: string;
  resolvedAt?: string;
  databaseTextRedacted?: string;
  vaultTextRedacted?: string;
}

export interface VaultSnapshot {
  enabled: boolean;
  syncEnabled?: boolean;
  projectionLifecycleStatuses?: string[];
  allowedRootLabel?: string;
  connections: VaultConnection[];
  syncStates: VaultSyncState[];
  conflicts: VaultConflict[];
}

export interface VaultOperationResult {
  connectionId?: string;
  nodeId?: string;
  relativePath?: string;
  status: string;
  conflictId?: string;
  message: string;
  archiveName?: string;
  downloadUrl?: string;
  byteSize?: number;
  fileCount?: number;
  sha256?: string;
  createdAt?: string;
}

export interface VaultRecoveryResult {
  operation: "repair" | "reindex";
  connectionId: string;
  status: "completed" | "partial";
  startedAt: string;
  completedAt: string;
  elapsedMs: number;
  expectedConnectionVersion: string;
  connectionVersion: string;
  health: {
    checkedAt: string;
    checks: VaultHealthChecks;
  };
  progress: {
    discovered: number;
    processed: number;
    remaining: number;
  };
  counts: {
    synced: number;
    databaseAhead: number;
    vaultAhead: number;
    conflictsPreserved: number;
    quarantined: number;
    missing: number;
    pending: number;
    indexed: number;
    skipped: number;
    errors: number;
  };
  issues: Array<{
    category: "conflict_preserved" | "malformed_note" | "missing_projection" | "pending_candidate" | "scope_denied" | "unsafe_path" | "scan_limit" | "duplicate_projection" | "permission_denied" | "concurrent_change" | "quarantine_recovery" | "processing_error";
    message: string;
    relativePath?: string;
    nodeId?: string;
  }>;
  issueSampleTruncated: boolean;
  message: string;
}

export interface MemoryNodeQuery {
  query?: string;
  cursor?: string;
  limit?: number;
  nodeType?: MemoryNodeType;
  status?: MemoryLifecycle;
  scope?: MemoryScope["kind"];
  engagementId?: string;
  missionId?: string;
  sensitivity?: MemorySensitivity;
}

export interface MemoryGraphQuery {
  view: MemoryGraphView;
  nodeId?: string;
  missionId?: string;
  depth?: 0 | 1 | 2;
  limit?: number;
  nodeType?: MemoryNodeType;
  edgeType?: MemoryEdgeType;
  scope?: MemoryScope["kind"];
  engagementId?: string;
  status?: MemoryLifecycle;
  sensitivity?: MemorySensitivity;
  minConfidence?: number;
  updatedAfter?: string;
  updatedBefore?: string;
  preset?: "attack_path" | "lessons_failures";
}

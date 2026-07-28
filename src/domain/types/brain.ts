export const MEMORY_NODE_TYPES = [
  "operator", "preference", "mission", "run", "plan", "phase", "step", "agent",
  "tool", "mcp_capability", "tactic", "technique", "procedure", "target", "asset",
  "entity", "decision", "evidence", "finding", "artifact", "failure", "recovery",
  "evaluation", "lesson", "report", "source", "technology_product",
  "exact_version_fingerprint", "version_range_fingerprint", "operating_system",
  "kernel", "framework", "runtime", "database", "firewall", "waf", "proxy",
  "security_control", "topology_pattern", "topology_role", "cve", "advisory",
  "cwe", "misconfiguration", "attack_vector", "prerequisite", "attribute",
  "discovery_pattern", "fingerprint_pattern", "script_artifact", "tool_artifact",
  "outcome", "failure_mode", "alternative", "evidence_pattern",
  "validation_pattern", "detection", "remediation", "strategy", "research",
  "procedure_version", "operational_hazard", "target_state_transition",
  "recovery_pattern", "health_check",
  "attack_tactic", "attack_technique", "attack_procedure", "attack_lesson",
] as const;

export const MEMORY_EDGE_TYPES = [
  "prefers", "applies_to", "belongs_to", "executed_by", "delegated_to", "used_in",
  "targets", "produced", "supports", "contradicts", "depends_on", "derived_from",
  "learned_from", "failed_in", "recovered_by", "similar_to", "supersedes",
  "verified_by", "mentioned_in", "influenced", "has_exact_version",
  "has_version_range", "version_in_range", "runs_on", "built_with",
  "uses_runtime", "uses_database", "protected_by", "has_topology_role",
  "matches_fingerprint", "discovered_by", "fingerprinted_by", "affects",
  "classified_as", "exploits", "requires", "has_attribute", "implemented_by",
  "tested_against", "produces_outcome", "failed_because", "recovered_with",
  "alternative_to", "validated_by", "detected_by", "remediated_by",
  "applicable_to", "not_applicable_to", "mitigates", "bypasses", "improves",
  "caused", "leaves_in_state", "requires_recovery", "avoid_after", "safe_when",
  "mitigated_by",
] as const;

export const MEMORY_LIFECYCLE_STATES = [
  "candidate", "confirmed", "verified", "disputed", "stale", "superseded", "forgotten",
] as const;

export const MEMORY_SENSITIVITIES = ["public", "internal", "private", "restricted"] as const;
export const MEMORY_OUTCOME_TAGS = ["success", "failed"] as const;
export const HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS = [
  "reported_success", "reported_failure", "mixed", "unknown",
] as const;

export type MemoryNodeType = (typeof MEMORY_NODE_TYPES)[number];
export type MemoryEdgeType = (typeof MEMORY_EDGE_TYPES)[number];
export type MemoryLifecycle = (typeof MEMORY_LIFECYCLE_STATES)[number];
export type MemorySensitivity = (typeof MEMORY_SENSITIVITIES)[number];
export type MemoryOutcomeTag = (typeof MEMORY_OUTCOME_TAGS)[number];
export type HistoricalReportedOutcomeClassification =
  (typeof HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS)[number];
export type MemoryGraphView = "global" | "local" | "mission" | "operator";

export interface HistoricalReportedOutcomeSummary {
  classification: HistoricalReportedOutcomeClassification;
  /** Confidence in interpreting the historical claim, never proof of success. */
  classificationConfidence: number;
  claimCount: number;
  sourceCount: number;
  policyVersion: string;
}

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

export interface ProvenanceOrigin {
  missionId?: string;
  missionName?: string;
  runId?: string;
  runStatus?: string;
  engagementId?: string;
  engagementLabel?: string;
  artifactId?: string;
  evidenceId?: string;
  privateSourceReference?: string;
  sourceLocator?: string;
}

export interface ProvenanceSource {
  /** Stable canonical row identity used only for bounded provenance paging. */
  sourceRecordId?: string;
  sourceType: string;
  sourceId: string;
  acquiredAt: string;
  sourceHash?: string;
  excerptRedacted?: string;
  /**
   * Every exact access-controlled custody origin. Reusable memory remains
   * target-free; these private origins are returned only when the current
   * operator may inspect each source mission. They are not graph relationships
   * and are never projected into the reusable Attack Knowledge Vault.
   */
  origins?: ProvenanceOrigin[];
  /** Exact access-controlled origin count, including unloaded origin pages. */
  originCount?: number;
  originsNextCursor?: string | null;
}

export interface MemorySourcePage {
  schemaVersion: "2.4";
  nodeId: string;
  items: ProvenanceSource[];
  totalCount: number;
  nextCursor: string | null;
}

export interface MemoryOriginPage {
  schemaVersion: "2.4";
  nodeId: string;
  sourceRecordId: string;
  items: ProvenanceOrigin[];
  totalCount: number;
  nextCursor: string | null;
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
  /**
   * Evidence-linked terminal outcomes that this reusable node participated in.
   * Both values may be present because the same technique can succeed in one
   * exact context and fail in another. Missing or empty means unclassified;
   * clients must never infer an outcome from titles, node type, or lifecycle.
   */
  outcomeTags?: MemoryOutcomeTag[];
  /** Historical source reports, kept separate from verified outcomeTags. */
  reportedOutcome?: HistoricalReportedOutcomeSummary;
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
    candidateNodes: number;
    pendingReviews: number;
    /** @deprecated Compatibility alias for pendingReviews. */
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

export interface OperationalHazardReference {
  id: string;
  nodeType: MemoryNodeType;
  title: string;
  summary: string;
  confidence: number;
  lifecycleStatus: MemoryLifecycle;
  expiresAt?: string;
}

export interface OperationalHazardDetail {
  procedure: OperationalHazardReference | null;
  procedureVersion: OperationalHazardReference | null;
  affectedProducts: OperationalHazardReference[];
  affectedVersions: OperationalHazardReference[];
  affectedStack: OperationalHazardReference[];
  prerequisites: OperationalHazardReference[];
  observedStates: OperationalHazardReference[];
  orderedSequence: string[];
  normalizedExecution: {
    parameters: Record<string, string | number | boolean>;
    loadMinimum: number | null;
    concurrencyMinimum: number | null;
    timingWindowMs: number | null;
  };
  applicabilityConstraints: {
    requireExactProcedureVersion?: boolean;
    requireVerifiedVersionRelationship?: boolean;
    requireAllStackNodes?: boolean;
    requireAllPrerequisites?: boolean;
    requireObservedState?: boolean;
  };
  symptom: { observed: string; affectedComponent: string };
  stateTransition: { before: string; after: string };
  corroboration: {
    exactHangCount: number;
    observedAttemptCount: number;
    operatorReportedResetMinimum: number | null;
  };
  safeHealthGate: string[];
  unsafeRetryConditions: string[];
  recovery: {
    summary: string;
    pattern: OperationalHazardReference | null;
    cost: {
      resetCount?: number;
      operatorReportedResetCountMinimum?: number;
      serviceRecycleCount?: number;
      downtimeMs?: number;
      operatorMinutes?: number;
      requiresDisposableTargetReset?: boolean;
    };
  };
  alternatives: { sequence: string[]; procedure: OperationalHazardReference | null };
  confidence: number;
  freshness: {
    observedAt: string;
    freshUntil: string | null;
    status: "current" | "expired" | "unbounded";
  };
  provenanceReceipt: {
    profileVersion: number;
    sourceCount: number;
    receiptIds: string[];
    receiptHash: string;
    recordedAt: string;
  };
}

/**
 * Run-scoped reset accounting intentionally kept separate from a reusable
 * procedure profile. An operator statement can preserve the overall recovery
 * burden, but it is never evidence that a particular procedure caused every
 * reported reset.
 */
export interface OperationalHazardResetTotals {
  missionId: string;
  runId: string;
  exactAttributableResetCount: number;
  operatorReportedResetMinimum: number | null;
  minimumUnattributedResetCount: number;
}

export interface OperationalHazardAggregateObservation {
  id: string;
  missionId: string;
  runId: string;
  reportedMinimum: number;
  statementEventId: string;
  reportedAt: string;
}

export interface OperationalHazardAggregateObservationResult {
  observation: OperationalHazardAggregateObservation;
  totals: OperationalHazardResetTotals;
  replayed: boolean;
}

export interface MemoryNodeDetail {
  node: MemoryNode;
  sources: ProvenanceSource[];
  sourcesNextCursor: string | null;
  versions: MemoryVersion[];
  backlinks: MemoryEdgeSummary[];
  outgoing: MemoryEdgeSummary[];
  usage: MemoryUsage[];
  operationalHazard?: OperationalHazardDetail;
}

export interface OperatorPreferenceSummary {
  node: MemoryNodeSummary;
  preferenceKey: string;
  value: Record<string, unknown>;
  appliesTo: string[];
  operatorId: string;
  confirmationState: "confirmed";
  consentPolicy: string;
  profileVersion: number;
  lastConfirmedAt: string;
  provenance: MemoryProvenance;
}

export interface OperatorPreferencePage {
  schemaVersion: "2.4";
  items: OperatorPreferenceSummary[];
  totalReturned: number;
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

export interface VaultDisconnectResult {
  status: "disconnected";
  connectionId: string;
  disconnectedAt: string;
  connectionVersion: string;
  projectionState: "healthy" | "degraded";
  replacementConnectionId?: string;
  activeRunCount: number;
  activeRunImpact: "canonical_brain_unaffected";
  syncStopped: true;
  filesDeleted: 0;
  notesRewritten: 0;
  auditRecordId: string;
  message: string;
}

export interface VaultDisconnectMutation {
  connection: VaultConnection;
  result: VaultDisconnectResult;
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

export interface AttackKnowledgeVaultPresetPreview {
  enabled: boolean;
  id: "ti_scale_attack_knowledge_v1";
  displayName: "Ti-Scale Attack Knowledge Vault";
  vaultPath: "Attack-Knowledge-Vault";
  policyHash: string;
  activationRequired: true;
  alreadyActiveConnectionId?: string;
  activePreset?: {
    connectionId: string;
    updatedAt: string;
    includeConfirmed: boolean;
    includeOperatorProfile: boolean;
    operatorProfileId?: string;
    policyHash: string;
  };
  confirmedScopeUpgrade?: {
    connectionId: string;
    expectedUpdatedAt: string;
    currentPolicyHash: string;
    targetPolicyHash: string;
    eligibleNodeCountBefore: number;
    eligibleNodeCountAfter: number;
    eligibleNodeDelta: number;
  };
  operatorProfileScopeUpgrade?: {
    connectionId: string;
    expectedUpdatedAt: string;
    currentPolicyHash: string;
    targetPolicyHash: string;
    eligibleNodeCountBefore: number;
    eligibleNodeCountAfter: number;
    eligibleNodeDelta: number;
    operatorProfileNodeCount: number;
  };
  operatorProfileAvailability: {
    requested: boolean;
    available: boolean;
    status: "available" | "no_eligible_confirmed_profile";
    eligibleNodeCount: number;
  };
  projection: {
    nodeTypes: string[];
    scopeKinds: ["global"];
    lifecycleStatuses: Array<"verified" | "confirmed">;
    sensitivities: MemorySensitivity[];
    folders: string[];
    policyEligibleNodeCount: number;
    excludedOperationalNodeCount: number;
    confirmedKnowledgeIsOptIn: boolean;
    operatorProfileIncluded: boolean;
    operatorProfileNodeCount: number;
  };
  privacyBoundary: {
    excludesNodeTypes: string[];
    excludesOperationalLocators: string[];
    restrictedSensitivityWithheld: true;
  };
}

export interface AttackKnowledgeVaultScopeAmendment {
  connection: VaultConnection;
  result: {
    previousPolicyHash: string;
    targetPolicyHash: string;
    eligibleNodeCountBefore: number;
    eligibleNodeCountAfter: number;
    eligibleNodeDelta: number;
    amendedAt: string;
    auditRecordId: string;
    filesystemHealth: { checkedAt: string; checks: VaultHealthChecks };
    connectionIdChanged: false;
    vaultPathChanged: false;
    filesDeleted: 0;
    notesWritten: 0;
    operatorProfileFolder?: "10 Operator";
    operatorProfileFolderCreated?: boolean;
    operatorProfileNodeCount?: number;
  };
  preset: AttackKnowledgeVaultPresetPreview;
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
  outcome?: MemoryOutcomeTag | "unclassified";
  reportedOutcome?: HistoricalReportedOutcomeClassification | "not_reported";
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
  outcome?: MemoryOutcomeTag | "unclassified";
  reportedOutcome?: HistoricalReportedOutcomeClassification | "not_reported";
}

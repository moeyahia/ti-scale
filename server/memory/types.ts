export const MEMORY_NODE_TYPES = [
  "operator",
  "preference",
  "mission",
  "run",
  "plan",
  "phase",
  "step",
  "agent",
  "tool",
  "mcp_capability",
  "tactic",
  "technique",
  "procedure",
  "target",
  "asset",
  "entity",
  "decision",
  "evidence",
  "finding",
  "artifact",
  "failure",
  "recovery",
  "evaluation",
  "lesson",
  "report",
  "source",
] as const;

export const MEMORY_EDGE_TYPES = [
  "prefers",
  "applies_to",
  "belongs_to",
  "executed_by",
  "delegated_to",
  "used_in",
  "targets",
  "produced",
  "supports",
  "contradicts",
  "depends_on",
  "derived_from",
  "learned_from",
  "failed_in",
  "recovered_by",
  "similar_to",
  "supersedes",
  "verified_by",
  "mentioned_in",
  "influenced",
] as const;

export const MEMORY_LIFECYCLE_STATES = [
  "candidate",
  "confirmed",
  "verified",
  "disputed",
  "stale",
  "superseded",
  "forgotten",
] as const;

export const MEMORY_SENSITIVITIES = [
  "public",
  "internal",
  "private",
  "restricted",
] as const;

export const MEMORY_AUTHOR_TYPES = ["operator", "agent", "system", "import"] as const;
export const MEMORY_SCOPE_KINDS = ["global", "engagement", "mission"] as const;
export const JOURNEYS = ["autonomous", "guided"] as const;

export type MemoryNodeType = (typeof MEMORY_NODE_TYPES)[number];
export type MemoryEdgeType = (typeof MEMORY_EDGE_TYPES)[number];
export type MemoryLifecycle = (typeof MEMORY_LIFECYCLE_STATES)[number];
export type MemorySensitivity = (typeof MEMORY_SENSITIVITIES)[number];
export type MemoryAuthorType = (typeof MEMORY_AUTHOR_TYPES)[number];
export type MemoryScopeKind = (typeof MEMORY_SCOPE_KINDS)[number];
export type Journey = (typeof JOURNEYS)[number];

export interface MemoryScope {
  readonly kind: MemoryScopeKind;
  readonly engagementId?: string;
  readonly missionId?: string;
}

export interface ProvenanceSource {
  readonly sourceType: string;
  readonly sourceId: string;
  readonly acquiredAt: string;
  readonly sourceHash?: string;
  readonly excerptRedacted?: string;
}

export interface MemoryProvenance {
  readonly method: "operator_statement" | "observation" | "evidence" | "derived" | "imported";
  readonly explanation: string;
  readonly sources: readonly ProvenanceSource[];
}

export interface MemoryRetentionPolicy {
  readonly journeys?: readonly Journey[];
  readonly expiresAfterDays?: number;
  readonly allowAutonomous?: boolean;
  readonly allowGuided?: boolean;
  readonly [key: string]: unknown;
}

export interface MemoryNode {
  readonly id: string;
  readonly nodeType: MemoryNodeType;
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly scope: MemoryScope;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly lifecycleStatus: MemoryLifecycle;
  readonly confirmationState: "not_required" | "pending" | "confirmed" | "rejected";
  readonly provenance: MemoryProvenance;
  readonly authorType: MemoryAuthorType;
  readonly authorId?: string;
  readonly version: number;
  readonly retentionPolicy: MemoryRetentionPolicy;
  readonly expiresAt?: string;
  readonly pinned: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateMemoryNodeInput {
  readonly id?: string;
  readonly nodeType: MemoryNodeType;
  readonly title: string;
  readonly summary: string;
  readonly body?: string;
  readonly scope: MemoryScope;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly lifecycleStatus: MemoryLifecycle;
  readonly confirmationState: MemoryNode["confirmationState"];
  readonly provenance: MemoryProvenance;
  readonly authorType: MemoryAuthorType;
  readonly authorId?: string;
  readonly retentionPolicy?: MemoryRetentionPolicy;
  readonly expiresAt?: string;
  readonly pinned?: boolean;
}

export interface CorrectMemoryNodeInput {
  readonly title?: string;
  readonly summary?: string;
  readonly body?: string;
  readonly scope?: MemoryScope;
  readonly sensitivity?: MemorySensitivity;
  readonly confidence?: number;
  readonly lifecycleStatus?: Exclude<MemoryLifecycle, "forgotten">;
  readonly confirmationState?: MemoryNode["confirmationState"];
  readonly retentionPolicy?: MemoryRetentionPolicy;
  readonly expiresAt?: string | null;
  readonly pinned?: boolean;
  /** New immutable provenance links discovered during an explicit correction/import. */
  readonly additionalProvenanceSources?: readonly ProvenanceSource[];
  readonly authorType: MemoryAuthorType;
  readonly authorId?: string;
  readonly changeReason: string;
}

export interface MemoryEdge {
  readonly id: string;
  readonly sourceNodeId: string;
  readonly targetNodeId: string;
  readonly edgeType: MemoryEdgeType;
  readonly title: string;
  readonly summary: string;
  readonly scope: MemoryScope;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly lifecycleStatus: MemoryLifecycle;
  readonly provenance: MemoryProvenance;
  readonly explanation: string;
  readonly authorType: MemoryAuthorType;
  readonly authorId?: string;
  readonly version: number;
  readonly expiresAt?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateMemoryEdgeInput {
  readonly id?: string;
  readonly sourceNodeId: string;
  readonly targetNodeId: string;
  readonly edgeType: MemoryEdgeType;
  readonly title: string;
  readonly summary: string;
  readonly scope: MemoryScope;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly lifecycleStatus: Exclude<MemoryLifecycle, "forgotten">;
  readonly provenance: MemoryProvenance;
  readonly explanation: string;
  readonly authorType: MemoryAuthorType;
  readonly authorId?: string;
  readonly expiresAt?: string;
}

export interface CreateMemoryCandidateInput {
  readonly id?: string;
  readonly nodeType: MemoryNodeType;
  readonly title: string;
  readonly summary: string;
  readonly body?: string;
  readonly scope: MemoryScope;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly provenance: MemoryProvenance;
  readonly proposedBy: string;
}

export interface MemoryCandidate {
  readonly id: string;
  readonly proposedNodeId?: string;
  readonly nodeType: MemoryNodeType;
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly scope: MemoryScope;
  readonly sensitivity: MemorySensitivity;
  readonly confidence: number;
  readonly provenance: MemoryProvenance;
  readonly status: "pending" | "confirmed" | "edited_confirmed" | "merged" | "rejected" | "suppressed";
  readonly proposedBy: string;
  readonly reviewedBy?: string;
  readonly reviewedAt?: string;
  readonly createdAt: string;
}

export interface RetrievalPolicy {
  readonly engagementId?: string;
  readonly missionId?: string;
  /** Defaults to true for interactive search; Autonomous callers set this explicitly. */
  readonly allowGlobal?: boolean;
  readonly journey: Journey;
  readonly maximumSensitivity: MemorySensitivity;
  readonly allowedNodeTypes?: readonly MemoryNodeType[];
  readonly allowedStatuses?: readonly ("confirmed" | "verified")[];
  readonly contextBudget: number;
  readonly limit?: number;
  readonly graphDepth?: 0 | 1 | 2;
  readonly exactNodeIds?: readonly string[];
  /** When true, lexical/recent/graph expansion is disabled and only exact IDs may enter. */
  readonly exactNodeIdsOnly?: boolean;
  /**
   * Signed Autonomous memory authorities. When present, these classes are
   * enforced in addition to canonical mission/engagement scope. Omitting the
   * field preserves the existing Guided and operator-search behavior.
   */
  readonly allowedScopeClasses?: readonly AutonomousMemoryScopeClass[];
}

export const AUTONOMOUS_MEMORY_SCOPE_CLASSES = [
  "confirmed_preferences",
  "verified_lessons",
  "engagement_memory",
] as const;

export type AutonomousMemoryScopeClass = (typeof AUTONOMOUS_MEMORY_SCOPE_CLASSES)[number];

export interface RetrievedMemory {
  readonly node: MemoryNode;
  readonly score: number;
  readonly relevanceReason: string;
  readonly signals: readonly ("exact" | "lexical" | "graph" | "recent")[];
}

export interface ContextPackItemDisposition {
  readonly nodeId: string;
  readonly used: boolean;
  readonly relevanceReason: string;
  readonly influenceSummary?: string;
  readonly ignoredReason?: string;
  readonly corrected?: boolean;
}

export interface ContextPack {
  readonly id: string;
  readonly missionId?: string;
  readonly runId?: string;
  readonly stepId?: string;
  readonly actionId?: string;
  readonly messageId?: string;
  readonly journey: Journey;
  readonly purpose: string;
  readonly queryRedacted?: string;
  readonly scopePolicy: RetrievalPolicy;
  readonly contextBudget: number;
  readonly retrievalMetrics: Record<string, unknown>;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly items: readonly ContextPackItemDisposition[];
}

/**
 * Provider-returned memory citations waiting for the runtime's lease-fenced
 * plan activation transaction. Retrieval may create a candidate context pack,
 * but no item is marked used and no lesson reuse is attributed until this
 * disposition is committed with the plan that actually won the run lease.
 */
export interface PlanningContextAttribution {
  readonly contextPackIds: readonly string[];
  readonly citations: readonly {
    readonly nodeId: string;
    readonly influence: string;
  }[];
}

export interface ForgetResult {
  readonly nodeId: string;
  readonly suppressionId: string;
  readonly vaultProjections: readonly { readonly connectionId: string; readonly relativePath: string }[];
  readonly removed: Readonly<Record<"versions" | "sources" | "embeddings" | "edges" | "contextItems", number>>;
  readonly auditRecordId: string;
}

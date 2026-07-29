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
  "technology_product",
  "exact_version_fingerprint",
  "version_range_fingerprint",
  "operating_system",
  "kernel",
  "framework",
  "runtime",
  "database",
  "firewall",
  "waf",
  "proxy",
  "security_control",
  "topology_pattern",
  "topology_role",
  "cve",
  "advisory",
  "cwe",
  "misconfiguration",
  "attack_vector",
  "prerequisite",
  "attribute",
  "discovery_pattern",
  "fingerprint_pattern",
  "script_artifact",
  "tool_artifact",
  "outcome",
  "failure_mode",
  "alternative",
  "evidence_pattern",
  "validation_pattern",
  "detection",
  "remediation",
  "strategy",
  "research",
  "procedure_version",
  "operational_hazard",
  "target_state_transition",
  "recovery_pattern",
  "health_check",
  "attack_tactic",
  "attack_technique",
  "attack_procedure",
  "attack_lesson",
] as const;

/**
 * Generalized, operator-reviewed knowledge that may be reused across
 * engagements. Mission, run, target, asset, evidence, finding, and artifact
 * records deliberately remain outside this registry: they are private
 * operational provenance, not semantic retrieval signals.
 */
export const ATTACK_CENTRIC_REUSABLE_NODE_TYPES = [
  "technology_product",
  "exact_version_fingerprint",
  "version_range_fingerprint",
  "operating_system",
  "kernel",
  "framework",
  "runtime",
  "database",
  "firewall",
  "waf",
  "proxy",
  "security_control",
  "topology_pattern",
  "topology_role",
  "cve",
  "advisory",
  "cwe",
  "misconfiguration",
  "attack_vector",
  "prerequisite",
  "attribute",
  "discovery_pattern",
  "fingerprint_pattern",
  "script_artifact",
  "tool_artifact",
  "outcome",
  "failure_mode",
  "alternative",
  "evidence_pattern",
  "validation_pattern",
  "detection",
  "remediation",
  "strategy",
  "research",
  "procedure_version",
  "operational_hazard",
  "target_state_transition",
  "recovery_pattern",
  "health_check",
  "attack_tactic",
  "attack_technique",
  "attack_procedure",
  "attack_lesson",
] as const satisfies readonly (typeof MEMORY_NODE_TYPES)[number][];

export type AttackCentricReusableNodeType =
  (typeof ATTACK_CENTRIC_REUSABLE_NODE_TYPES)[number];

const ATTACK_CENTRIC_REUSABLE_NODE_TYPE_SET: ReadonlySet<string> =
  new Set(ATTACK_CENTRIC_REUSABLE_NODE_TYPES);

export function isAttackCentricReusableNodeType(
  value: MemoryNodeType,
): value is AttackCentricReusableNodeType {
  return ATTACK_CENTRIC_REUSABLE_NODE_TYPE_SET.has(value);
}

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
  "has_exact_version",
  "has_version_range",
  "version_in_range",
  "runs_on",
  "built_with",
  "uses_runtime",
  "uses_database",
  "protected_by",
  "has_topology_role",
  "matches_fingerprint",
  "discovered_by",
  "fingerprinted_by",
  "affects",
  "classified_as",
  "exploits",
  "requires",
  "has_attribute",
  "implemented_by",
  "tested_against",
  "produces_outcome",
  "failed_because",
  "recovered_with",
  "alternative_to",
  "validated_by",
  "detected_by",
  "remediated_by",
  "applicable_to",
  "not_applicable_to",
  "mitigates",
  "bypasses",
  "improves",
  "caused",
  "leaves_in_state",
  "requires_recovery",
  "avoid_after",
  "safe_when",
  "mitigated_by",
] as const;

export const ATTACK_CENTRIC_EDGE_TYPES = [
  "has_exact_version",
  "has_version_range",
  "version_in_range",
  "runs_on",
  "built_with",
  "uses_runtime",
  "uses_database",
  "protected_by",
  "has_topology_role",
  "matches_fingerprint",
  "discovered_by",
  "fingerprinted_by",
  "affects",
  "classified_as",
  "exploits",
  "requires",
  "has_attribute",
  "implemented_by",
  "tested_against",
  "produces_outcome",
  "failed_because",
  "recovered_with",
  "alternative_to",
  "validated_by",
  "detected_by",
  "remediated_by",
  "applicable_to",
  "not_applicable_to",
  "mitigates",
  "bypasses",
  "improves",
  "caused",
  "leaves_in_state",
  "requires_recovery",
  "avoid_after",
  "safe_when",
  "mitigated_by",
] as const satisfies readonly (typeof MEMORY_EDGE_TYPES)[number][];

export interface OperationalHazardContext {
  readonly procedureNodeId: string;
  readonly procedureVersionNodeId?: string;
  readonly productNodeIds: readonly string[];
  readonly versionNodeIds: readonly string[];
  readonly stackNodeIds: readonly string[];
  readonly prerequisiteNodeIds: readonly string[];
  readonly observedStateNodeIds?: readonly string[];
  readonly normalizedParameters: Readonly<Record<string, string | number | boolean>>;
  readonly load?: number;
  readonly concurrency?: number;
  readonly timingWindowMs?: number;
}

export interface OperationalHazardAssessment {
  readonly decision: "allow" | "warn" | "block";
  readonly matchedHazardNodeIds: readonly string[];
  readonly blockedProcedureNodeIds: readonly string[];
  readonly warning?: string;
  readonly checklist: readonly string[];
  readonly saferKnownSequence: readonly string[];
  readonly unsafeRetryConditions: readonly string[];
  readonly healthGate: readonly string[];
  readonly safeRetryGate: readonly string[];
}

export type AttackCentricEdgeType = (typeof ATTACK_CENTRIC_EDGE_TYPES)[number];

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
  /** Updated human-readable provenance explanation; immutable sources remain additive. */
  readonly provenanceExplanation?: string;
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
  /** Structured, target-free facts used to prevent a known harmful retry. */
  readonly hazardContext?: OperationalHazardContext;
}

export const AUTONOMOUS_MEMORY_SCOPE_CLASSES = [
  "confirmed_preferences",
  "verified_lessons",
  "confirmed_attack_knowledge",
  "verified_attack_knowledge",
  "engagement_memory",
] as const;

/**
 * Current system-authored, Vault-synchronized agent/tool compatibility
 * attestations. This is deliberately absent from the operator-signed/default
 * scope-class registry: only the trusted runtime may add it alongside exact
 * stable capability node IDs.
 */
export const RUNTIME_CAPABILITY_MEMORY_SCOPE_CLASS =
  "current_runtime_capabilities" as const;

export const SUPPORTED_MEMORY_SCOPE_CLASSES = [
  ...AUTONOMOUS_MEMORY_SCOPE_CLASSES,
  RUNTIME_CAPABILITY_MEMORY_SCOPE_CLASS,
] as const;

export type AutonomousMemoryScopeClass =
  (typeof SUPPORTED_MEMORY_SCOPE_CLASSES)[number];

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

export const RELEASE_DATA_CLASSES = ["canonical", "startup_readiness"] as const;
export type ReleaseDataClass = (typeof RELEASE_DATA_CLASSES)[number];

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
  /**
   * Release-integrity classification. Only a tightly constrained, content-free
   * startup readiness lineage may use `startup_readiness`; every operational
   * Context Pack remains canonical release data.
   */
  readonly releaseDataClass: ReleaseDataClass;
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

export type RunIntelligenceJson =
  | string
  | number
  | boolean
  | null
  | readonly RunIntelligenceJson[]
  | { readonly [key: string]: RunIntelligenceJson };

export type RunMetricCategory =
  | "objective"
  | "orchestration"
  | "attempts"
  | "discovery"
  | "evidence"
  | "reliability"
  | "resources"
  | "learning";

export type RunMetricUnit = "count" | "ratio" | "milliseconds" | "cost";
export type RunMetricMeasurement = "exact" | "derived" | "partial" | "not_observed";

export type RunMetricKey =
  | "elapsed_ms"
  | "plan_versions"
  | "steps_total"
  | "steps_completed"
  | "steps_failed"
  | "steps_blocked"
  | "steps_skipped"
  | "plan_completion_ratio"
  | "unique_agents"
  | "assignments_total"
  | "assignments_completed"
  | "assignments_failed"
  | "assignments_blocked"
  | "current_concurrent_agents"
  | "peak_concurrent_agents"
  | "agent_handoffs"
  | "average_assignment_duration_ms"
  | "maximum_assignment_duration_ms"
  | "attack_attempts_total"
  | "attack_attempts_started"
  | "attack_attempts_succeeded"
  | "attack_attempts_failed"
  | "attack_attempts_safely_aborted"
  | "attack_attempts_blocked"
  | "attack_attempts_waiting_conditions"
  | "topology_nodes"
  | "assets_discovered"
  | "services_discovered"
  | "topology_edges"
  | "osi_observations"
  | "engagement_log_records"
  | "observations"
  | "evidence_candidates"
  | "verified_evidence"
  | "findings"
  | "verified_findings"
  | "artifacts"
  | "finding_evidence_coverage_ratio"
  | "actions_total"
  | "actions_failed"
  | "action_retries"
  | "run_retries"
  | "replans"
  | "tool_calls_total"
  | "tool_calls_succeeded"
  | "tool_calls_failed"
  | "tool_calls_denied"
  | "tool_calls_timed_out"
  | "provider_turns"
  | "provider_tokens"
  | "estimated_provider_cost"
  | "average_provider_latency_ms"
  | "time_to_first_evidence_ms"
  | "events"
  | "context_packs"
  | "used_context_items"
  | "verified_lessons_used";

export type MetricDrillDownResource =
  | "runs"
  | "plans"
  | "plan_steps"
  | "assignments"
  | "agents"
  | "attack_attempts"
  | "topology_nodes"
  | "topology_edges"
  | "asset_layer_observations"
  | "engagement_log_records"
  | "observations"
  | "evidence_candidates"
  | "evidence"
  | "findings"
  | "artifacts"
  | "actions"
  | "tool_calls"
  | "provider_turns"
  | "events"
  | "memory_context_packs"
  | "memory_context_items"
  | "lesson_usage";

export interface MetricDrillDownFilter {
  readonly field:
    | "run_id"
    | "mission_id"
    | "status"
    | "review_status"
    | "verification_state"
    | "node_type"
    | "lifecycle_state"
    | "event_type"
    | "started_at"
    | "lesson_status"
    | "used";
  readonly operator: "eq" | "in" | "not_eq" | "is_not_null";
  readonly value: string | readonly string[] | number | null;
}

export interface MetricDrillDownReference {
  readonly id: string;
  readonly role: "primary" | "numerator" | "denominator";
  readonly resource: MetricDrillDownResource;
  readonly missionId: string;
  readonly runId: string;
  readonly aggregation:
    | "records"
    | "records_with_relation"
    | "distinct"
    | "sum"
    | "average"
    | "maximum"
    | "max_concurrency"
    | "duration";
  readonly field: string | null;
  readonly filters: readonly MetricDrillDownFilter[];
}

export interface RunMetric {
  readonly key: RunMetricKey;
  readonly label: string;
  readonly category: RunMetricCategory;
  readonly unit: RunMetricUnit;
  readonly value: number | null;
  readonly measurement: RunMetricMeasurement;
  readonly drillDown: readonly MetricDrillDownReference[];
}

export interface RunMetricsSourceCounts {
  readonly plans: number;
  readonly planSteps: number;
  readonly assignments: number;
  readonly actions: number;
  readonly toolCalls: number;
  readonly attackAttempts: number;
  readonly topologyNodes: number;
  readonly topologyEdges: number;
  readonly osiObservations: number;
  readonly logRecords: number;
  readonly observations: number;
  readonly evidenceCandidates: number;
  readonly evidence: number;
  readonly findings: number;
  readonly artifacts: number;
  readonly providerTurns: number;
  readonly events: number;
  readonly contextPacks: number;
  readonly lessonUsage: number;
}

export interface RunMetricsSnapshot {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly throughEventSequence: number;
  readonly metricSchemaVersion: "run-metrics-v2.4.0";
  readonly metrics: readonly RunMetric[];
  readonly sourceCounts: RunMetricsSourceCounts;
  readonly recomputationHash: string;
  readonly computedAt: string;
}

export interface RunMetricsSnapshotList {
  readonly schemaVersion: "2.4";
  readonly items: readonly RunMetricsSnapshot[];
  readonly latestSnapshotId: string | null;
}

export interface RunMetricsSnapshotDetail {
  readonly schemaVersion: "2.4";
  readonly snapshot: RunMetricsSnapshot;
}

export type AttackAttemptStatus =
  | "planned"
  | "ready"
  | "running"
  | "succeeded"
  | "failed"
  | "safely_aborted"
  | "blocked"
  | "waiting_conditions"
  | "cancelled";

export interface AttackAttemptEvidenceLink {
  readonly evidenceId: string;
  readonly relationship: "supports" | "contradicts" | "context" | "outcome";
  readonly verificationState: "unverified" | "verified" | "disputed" | "rejected";
  readonly confidence: number;
  readonly contentHash: string;
  readonly createdAt: string;
}

export interface AttackAttempt {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly planId: string | null;
  readonly stepId: string | null;
  readonly targetAssetId: string | null;
  readonly targetServiceId: string | null;
  readonly objective: string;
  readonly techniqueId: string | null;
  readonly techniqueName: string;
  readonly actionClass: string;
  readonly prerequisites: readonly RunIntelligenceJson[];
  readonly normalizedParameters: Readonly<Record<string, RunIntelligenceJson>>;
  readonly status: AttackAttemptStatus;
  readonly outcomeSummary: string | null;
  readonly failureCategory: string | null;
  readonly failureDiagnosisId: string | null;
  readonly assignedAgentId: string | null;
  readonly modelAssignmentId: string | null;
  readonly startedAt: string | null;
  readonly endedAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly version: number;
  readonly evidence: readonly AttackAttemptEvidenceLink[];
}

export interface AttackAttemptList {
  readonly schemaVersion: "2.4";
  readonly items: readonly AttackAttempt[];
}

export interface AttackAttemptDetail {
  readonly schemaVersion: "2.4";
  readonly attempt: AttackAttempt;
}

export type TopologyVerificationState = "unverified" | "corroborated" | "verified" | "conflicting" | "stale";
export type TopologySensitivity = "public" | "internal" | "private" | "restricted";

export interface IntelligenceProvenance {
  readonly method: string;
  readonly sourceRef: string;
  readonly sourceAgentId?: string;
  readonly sourceTool?: string;
  readonly observationIds?: readonly string[];
}

export interface TopologyEvidenceLink {
  readonly evidenceId: string;
  readonly relationship: "supports" | "contradicts" | "source";
  readonly verificationState: "unverified" | "verified" | "disputed" | "rejected";
  readonly confidence: number;
  readonly contentHash: string;
  readonly summary: string;
  readonly provenance: Readonly<Record<string, RunIntelligenceJson>>;
  readonly createdAt: string;
}

export interface TopologyNode {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string | null;
  readonly nodeType: string;
  readonly primaryLabel: string;
  readonly normalizedIdentity: string;
  readonly scopeStatus: "allowed" | "prohibited" | "unknown" | "out_of_scope";
  readonly lifecycleState: "planned" | "active" | "validated" | "blocked" | "unreachable" | "observed" | "stale";
  readonly properties: Readonly<Record<string, RunIntelligenceJson>>;
  readonly provenance: IntelligenceProvenance;
  readonly confidence: number;
  readonly verificationState: TopologyVerificationState;
  readonly sensitivity: TopologySensitivity;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
  readonly evidence: readonly TopologyEvidenceLink[];
}

export interface TopologyEdge {
  readonly id: string;
  readonly missionId: string;
  readonly sourceNodeId: string;
  readonly targetNodeId: string;
  readonly edgeType: string;
  readonly properties: Readonly<Record<string, RunIntelligenceJson>>;
  readonly provenance: IntelligenceProvenance;
  readonly confidence: number;
  readonly verificationState: TopologyVerificationState;
  readonly sensitivity: TopologySensitivity;
  readonly firstSeenAt: string;
  readonly lastSeenAt: string;
  readonly evidence: readonly TopologyEvidenceLink[];
}

export interface ReconDigitalTwin {
  readonly missionId: string;
  readonly runId: string | null;
  readonly nodes: readonly TopologyNode[];
  readonly edges: readonly TopologyEdge[];
}

export interface ReconDigitalTwinDetail {
  readonly schemaVersion: "2.4";
  readonly digitalTwin: ReconDigitalTwin;
}

export interface TopologyNodeDetail {
  readonly schemaVersion: "2.4";
  readonly node: TopologyNode;
}

export interface OsiLayerObservation {
  readonly id: string;
  readonly assetNodeId: string;
  readonly layer: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  readonly category: string;
  readonly value: string;
  readonly versionValue: string | null;
  readonly derivation: "observed" | "actively_verified" | "inferred" | "user_supplied";
  readonly confidence: number;
  readonly evidenceId: string;
  readonly evidenceVerificationState: "unverified" | "verified" | "disputed" | "rejected";
  readonly evidenceProvenance: Readonly<Record<string, RunIntelligenceJson>>;
  readonly observedAt: string;
  readonly conflictGroupId: string | null;
}

export interface OsiLayerProjection {
  readonly layer: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  readonly name: string;
  readonly state: "not_observed" | "observed" | "conflicting";
  readonly observations: readonly OsiLayerObservation[];
}

export interface AssetOsiStack {
  readonly assetNodeId: string;
  readonly layers: readonly OsiLayerProjection[];
}

export interface AssetOsiStackDetail {
  readonly schemaVersion: "2.4";
  readonly stack: AssetOsiStack;
}

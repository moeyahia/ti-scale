import type {
  AssetOsiStack,
  AssetOsiStackDetail,
  AttackAttempt,
  AttackAttemptDetail,
  AttackAttemptList,
  IntelligenceProvenance,
  MetricDrillDownFilter,
  MetricDrillDownReference,
  OsiLayerObservation,
  OsiLayerProjection,
  ReconDigitalTwin,
  ReconDigitalTwinDetail,
  RunIntelligenceJson,
  RunMetric,
  RunMetricKey,
  RunMetricsSnapshot,
  RunMetricsSnapshotDetail,
  RunMetricsSnapshotList,
  RunMetricsSourceCounts,
  TopologyEdge,
  TopologyEvidenceLink,
  TopologyNode,
  TopologyNodeDetail,
} from "../types/runIntelligence";

const METRIC_KEYS = [
  "elapsed_ms", "plan_versions", "steps_total", "steps_completed", "steps_failed", "steps_blocked",
  "steps_skipped", "plan_completion_ratio", "unique_agents", "assignments_total", "assignments_completed",
  "assignments_failed", "assignments_blocked", "current_concurrent_agents", "peak_concurrent_agents",
  "agent_handoffs", "average_assignment_duration_ms", "maximum_assignment_duration_ms",
  "attack_attempts_total", "attack_attempts_started", "attack_attempts_succeeded", "attack_attempts_failed",
  "attack_attempts_safely_aborted", "attack_attempts_blocked", "attack_attempts_waiting_conditions",
  "topology_nodes", "assets_discovered", "services_discovered", "topology_edges", "osi_observations",
  "engagement_log_records", "observations", "evidence_candidates", "verified_evidence", "findings",
  "verified_findings", "artifacts", "finding_evidence_coverage_ratio", "actions_total", "actions_failed",
  "action_retries", "run_retries", "replans", "tool_calls_total", "tool_calls_succeeded", "tool_calls_failed",
  "tool_calls_denied", "tool_calls_timed_out", "provider_turns", "provider_tokens", "estimated_provider_cost",
  "average_provider_latency_ms", "time_to_first_evidence_ms", "events", "context_packs", "used_context_items",
  "verified_lessons_used",
] as const satisfies readonly RunMetricKey[];

const METRIC_KEY_SET = new Set<string>(METRIC_KEYS);
const METRIC_CATEGORIES = new Set(["objective", "orchestration", "attempts", "discovery", "evidence", "reliability", "resources", "learning"]);
const METRIC_UNITS = new Set(["count", "ratio", "milliseconds", "cost"]);
const METRIC_MEASUREMENTS = new Set(["exact", "derived", "partial", "not_observed"]);
const DRILL_DOWN_RESOURCES = new Set([
  "runs", "plans", "plan_steps", "assignments", "agents", "attack_attempts", "topology_nodes",
  "topology_edges", "asset_layer_observations", "engagement_log_records", "observations", "evidence_candidates",
  "evidence", "findings", "artifacts", "actions", "tool_calls", "provider_turns", "events",
  "memory_context_packs", "memory_context_items", "lesson_usage",
]);
const FILTER_FIELDS = new Set([
  "run_id", "mission_id", "status", "review_status", "verification_state", "node_type", "lifecycle_state",
  "event_type", "started_at", "lesson_status", "used",
]);
const SOURCE_COUNT_KEYS = [
  "plans", "planSteps", "assignments", "actions", "toolCalls", "attackAttempts", "topologyNodes",
  "topologyEdges", "osiObservations", "logRecords", "observations", "evidenceCandidates", "evidence",
  "findings", "artifacts", "providerTurns", "events", "contextPacks", "lessonUsage",
] as const satisfies readonly (keyof RunMetricsSourceCounts)[];
const ATTEMPT_STATUSES = new Set(["planned", "ready", "running", "succeeded", "failed", "safely_aborted", "blocked", "waiting_conditions", "cancelled"]);
const TOPOLOGY_VERIFICATION_STATES = new Set(["unverified", "corroborated", "verified", "conflicting", "stale"]);
const EVIDENCE_VERIFICATION_STATES = new Set(["unverified", "verified", "disputed", "rejected"]);
const TOPOLOGY_SENSITIVITIES = new Set(["public", "internal", "private", "restricted"]);
const OSI_NAMES = ["Physical", "Data Link", "Network", "Transport", "Session", "Presentation", "Application"] as const;

type UnknownRecord = Record<string, unknown>;

function record(value: unknown, label: string): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as UnknownRecord;
}

function exact(value: unknown, label: string, required: readonly string[], optional: readonly string[] = []): UnknownRecord {
  const item = record(value, label);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(item)) {
    if (!allowed.has(key)) throw new Error(`${label} contains unsupported field ${key}`);
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(item, key)) throw new Error(`${label} is missing ${key}`);
  }
  return item;
}

function list(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function nullableText(value: unknown, label: string): string | null {
  return value === null ? null : text(value, label);
}

function timestamp(value: unknown, label: string): string {
  const result = text(value, label);
  if (!Number.isFinite(Date.parse(result))) throw new Error(`${label} must be an ISO timestamp`);
  return result;
}

function nullableTimestamp(value: unknown, label: string): string | null {
  return value === null ? null : timestamp(value, label);
}

function finiteNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${label} must be a finite number`);
  return value;
}

function nonNegativeNumber(value: unknown, label: string): number {
  const result = finiteNumber(value, label);
  if (result < 0) throw new Error(`${label} cannot be negative`);
  return result;
}

function nonNegativeInteger(value: unknown, label: string): number {
  const result = nonNegativeNumber(value, label);
  if (!Number.isSafeInteger(result)) throw new Error(`${label} must be an integer`);
  return result;
}

function positiveInteger(value: unknown, label: string): number {
  const result = nonNegativeInteger(value, label);
  if (result < 1) throw new Error(`${label} must be positive`);
  return result;
}

function confidence(value: unknown, label: string): number {
  const result = finiteNumber(value, label);
  if (result < 0 || result > 1) throw new Error(`${label} must be between zero and one`);
  return result;
}

function enumValue<T extends string>(value: unknown, allowed: ReadonlySet<string>, label: string): T {
  const result = text(value, label);
  if (!allowed.has(result)) throw new Error(`${label} is invalid`);
  return result as T;
}

function jsonValue(value: unknown, label: string, seen = new Set<object>()): RunIntelligenceJson {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return finiteNumber(value, label);
  if (typeof value !== "object") throw new Error(`${label} is not JSON-safe`);
  if (seen.has(value)) throw new Error(`${label} cannot contain cycles`);
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.map((child, index) => jsonValue(child, `${label}[${index}]`, seen));
    const result: Record<string, RunIntelligenceJson> = {};
    for (const [key, child] of Object.entries(value as UnknownRecord)) {
      if (["__proto__", "prototype", "constructor"].includes(key) || child === undefined) {
        throw new Error(`${label} contains an unsafe field`);
      }
      result[key] = jsonValue(child, `${label}.${key}`, seen);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

function jsonObject(value: unknown, label: string): Readonly<Record<string, RunIntelligenceJson>> {
  const result = jsonValue(value, label);
  if (result === null || Array.isArray(result) || typeof result !== "object") throw new Error(`${label} must be a JSON object`);
  return result as Readonly<Record<string, RunIntelligenceJson>>;
}

function schemaVersion(value: unknown): "2.4" {
  if (value !== "2.4") throw new Error("unsupported Ti-Scale schema version");
  return "2.4";
}

function filterValue(value: unknown, label: string): string | readonly string[] | number | null {
  if (value === null || typeof value === "string") return value;
  if (typeof value === "number") return finiteNumber(value, label);
  return list(value, label).map((item, index) => text(item, `${label}[${index}]`));
}

function parseDrillDownFilter(value: unknown): MetricDrillDownFilter {
  const item = exact(value, "metric drill-down filter", ["field", "operator", "value"]);
  return {
    field: enumValue(item.field, FILTER_FIELDS, "metric drill-down field"),
    operator: enumValue(item.operator, new Set(["eq", "in", "not_eq", "is_not_null"]), "metric drill-down operator"),
    value: filterValue(item.value, "metric drill-down value"),
  };
}

function parseDrillDownReference(value: unknown): MetricDrillDownReference {
  const item = exact(value, "metric drill-down", ["id", "role", "resource", "missionId", "runId", "aggregation", "field", "filters"]);
  const filters = list(item.filters, "metric drill-down filters").map(parseDrillDownFilter);
  return {
    id: text(item.id, "metric drill-down ID"),
    role: enumValue(item.role, new Set(["primary", "numerator", "denominator"]), "metric drill-down role"),
    resource: enumValue(item.resource, DRILL_DOWN_RESOURCES, "metric drill-down resource"),
    missionId: text(item.missionId, "metric drill-down mission ID"),
    runId: text(item.runId, "metric drill-down run ID"),
    aggregation: enumValue(item.aggregation, new Set(["records", "records_with_relation", "distinct", "sum", "average", "maximum", "max_concurrency", "duration"]), "metric drill-down aggregation"),
    field: item.field === null ? null : text(item.field, "metric drill-down field target"),
    filters,
  };
}

function parseRunMetric(value: unknown): RunMetric {
  const item = exact(value, "run metric", ["key", "label", "category", "unit", "value", "measurement", "drillDown"]);
  const key = enumValue<RunMetricKey>(item.key, METRIC_KEY_SET, "run metric key");
  const measurement = enumValue<RunMetric["measurement"]>(item.measurement, METRIC_MEASUREMENTS, "run metric measurement");
  const metricValue = item.value === null ? null : nonNegativeNumber(item.value, "run metric value");
  if (measurement === "not_observed" && metricValue !== null) throw new Error(`run metric ${key} cannot invent a not-observed value`);
  const drillDown = list(item.drillDown, "run metric drill-downs").map(parseDrillDownReference);
  if (drillDown.length === 0) throw new Error(`run metric ${key} requires a drill-down`);
  return {
    key,
    label: text(item.label, "run metric label"),
    category: enumValue(item.category, METRIC_CATEGORIES, "run metric category"),
    unit: enumValue(item.unit, METRIC_UNITS, "run metric unit"),
    value: metricValue,
    measurement,
    drillDown,
  };
}

function parseSourceCounts(value: unknown): RunMetricsSourceCounts {
  const item = exact(value, "run metrics source counts", SOURCE_COUNT_KEYS);
  return Object.fromEntries(SOURCE_COUNT_KEYS.map((key) => [key, nonNegativeInteger(item[key], `source count ${key}`)])) as unknown as RunMetricsSourceCounts;
}

export function parseRunMetricsSnapshot(value: unknown): RunMetricsSnapshot {
  const item = exact(value, "run metrics snapshot", ["id", "missionId", "runId", "throughEventSequence", "metricSchemaVersion", "metrics", "sourceCounts", "recomputationHash", "computedAt"]);
  if (item.metricSchemaVersion !== "run-metrics-v2.4.0") throw new Error("unsupported run metrics schema version");
  const missionId = text(item.missionId, "metrics mission ID");
  const runId = text(item.runId, "metrics run ID");
  const metrics = list(item.metrics, "run metrics").map(parseRunMetric);
  const keys = new Set(metrics.map(({ key }) => key));
  if (metrics.length !== METRIC_KEYS.length || keys.size !== METRIC_KEYS.length || METRIC_KEYS.some((key) => !keys.has(key))) {
    throw new Error("run metrics snapshot is incomplete or contains duplicate metrics");
  }
  for (const metric of metrics) {
    for (const drillDown of metric.drillDown) {
      if (drillDown.missionId !== missionId || drillDown.runId !== runId) throw new Error(`run metric ${metric.key} drill-down escapes its snapshot scope`);
      if (!drillDown.filters.some((candidate) => candidate.field === "run_id" && candidate.operator === "eq" && candidate.value === runId)) {
        throw new Error(`run metric ${metric.key} drill-down is missing its canonical run filter`);
      }
    }
  }
  return {
    id: text(item.id, "metrics snapshot ID"), missionId, runId,
    throughEventSequence: nonNegativeInteger(item.throughEventSequence, "metrics event sequence"),
    metricSchemaVersion: "run-metrics-v2.4.0", metrics,
    sourceCounts: parseSourceCounts(item.sourceCounts),
    recomputationHash: text(item.recomputationHash, "metrics recomputation hash"),
    computedAt: timestamp(item.computedAt, "metrics computed time"),
  };
}

export function parseRunMetricsSnapshotList(payload: unknown): RunMetricsSnapshotList {
  const root = exact(payload, "run metrics snapshot list", ["schemaVersion", "items", "latestSnapshotId"]);
  const items = list(root.items, "run metrics snapshots").map(parseRunMetricsSnapshot);
  const latestSnapshotId = nullableText(root.latestSnapshotId, "latest metrics snapshot ID");
  if (latestSnapshotId !== (items[0]?.id ?? null)) throw new Error("latest metrics snapshot ID does not identify the first canonical snapshot");
  return { schemaVersion: schemaVersion(root.schemaVersion), items, latestSnapshotId };
}

export function parseRunMetricsSnapshotDetail(payload: unknown): RunMetricsSnapshotDetail {
  const root = exact(payload, "run metrics snapshot detail", ["schemaVersion", "snapshot"]);
  return { schemaVersion: schemaVersion(root.schemaVersion), snapshot: parseRunMetricsSnapshot(root.snapshot) };
}

function parseAttemptEvidence(value: unknown): AttackAttempt["evidence"][number] {
  const item = exact(value, "attack attempt evidence", ["evidenceId", "relationship", "verificationState", "confidence", "contentHash", "createdAt"]);
  return {
    evidenceId: text(item.evidenceId, "attack attempt evidence ID"),
    relationship: enumValue(item.relationship, new Set(["supports", "contradicts", "context", "outcome"]), "attack attempt evidence relationship"),
    verificationState: enumValue(item.verificationState, EVIDENCE_VERIFICATION_STATES, "attack attempt evidence verification state"),
    confidence: confidence(item.confidence, "attack attempt evidence confidence"),
    contentHash: text(item.contentHash, "attack attempt evidence hash"),
    createdAt: timestamp(item.createdAt, "attack attempt evidence created time"),
  };
}

function parseAttemptActionBinding(value: unknown): NonNullable<AttackAttempt["representedActionBinding"]> {
  const item = exact(value, "attack attempt represented action binding", [
    "actionType", "actionClass", "normalizedArguments", "scopedTarget", "bindingHash", "createdAt",
  ]);
  return {
    actionType: text(item.actionType, "attack attempt represented action type"),
    actionClass: text(item.actionClass, "attack attempt represented action class"),
    normalizedArguments: jsonObject(item.normalizedArguments, "attack attempt represented action arguments"),
    scopedTarget: text(item.scopedTarget, "attack attempt represented scoped target"),
    bindingHash: text(item.bindingHash, "attack attempt represented action binding hash"),
    createdAt: timestamp(item.createdAt, "attack attempt represented action binding created time"),
  };
}

export function parseAttackAttempt(value: unknown): AttackAttempt {
  const item = exact(value, "attack attempt", [
    "id", "missionId", "runId", "planId", "stepId", "targetAssetId", "targetServiceId", "recoverySourceAttackAttemptId", "representedActionBinding", "objective",
    "techniqueId", "techniqueName", "actionClass", "prerequisites", "normalizedParameters", "status",
    "outcomeSummary", "failureCategory", "failureDiagnosisId", "assignedAgentId", "modelAssignmentId",
    "startedAt", "endedAt", "createdAt", "updatedAt", "version", "evidence",
  ]);
  const status = enumValue<AttackAttempt["status"]>(item.status, ATTEMPT_STATUSES, "attack attempt status");
  const evidence = list(item.evidence, "attack attempt evidence").map(parseAttemptEvidence);
  if (status === "succeeded" && !evidence.some((link) => link.verificationState === "verified" && (link.relationship === "supports" || link.relationship === "outcome"))) {
    throw new Error("successful attack attempt lacks verified outcome evidence");
  }
  return {
    id: text(item.id, "attack attempt ID"), missionId: text(item.missionId, "attack attempt mission ID"),
    runId: text(item.runId, "attack attempt run ID"), planId: nullableText(item.planId, "attack attempt plan ID"),
    stepId: nullableText(item.stepId, "attack attempt step ID"), targetAssetId: nullableText(item.targetAssetId, "attack attempt target asset ID"),
    targetServiceId: nullableText(item.targetServiceId, "attack attempt target service ID"),
    recoverySourceAttackAttemptId: nullableText(item.recoverySourceAttackAttemptId, "attack attempt recovery source ID"),
    representedActionBinding: item.representedActionBinding === null
      ? null
      : parseAttemptActionBinding(item.representedActionBinding),
    objective: text(item.objective, "attack attempt objective"), techniqueId: nullableText(item.techniqueId, "attack attempt technique ID"),
    techniqueName: text(item.techniqueName, "attack attempt technique name"), actionClass: text(item.actionClass, "attack attempt action class"),
    prerequisites: list(item.prerequisites, "attack attempt prerequisites").map((candidate, index) => jsonValue(candidate, `attack attempt prerequisite ${index}`)),
    normalizedParameters: jsonObject(item.normalizedParameters, "attack attempt parameters"), status,
    outcomeSummary: nullableText(item.outcomeSummary, "attack attempt outcome summary"),
    failureCategory: nullableText(item.failureCategory, "attack attempt failure category"),
    failureDiagnosisId: nullableText(item.failureDiagnosisId, "attack attempt failure diagnosis ID"),
    assignedAgentId: nullableText(item.assignedAgentId, "attack attempt assigned agent ID"),
    modelAssignmentId: nullableText(item.modelAssignmentId, "attack attempt model assignment ID"),
    startedAt: nullableTimestamp(item.startedAt, "attack attempt started time"),
    endedAt: nullableTimestamp(item.endedAt, "attack attempt ended time"),
    createdAt: timestamp(item.createdAt, "attack attempt created time"),
    updatedAt: timestamp(item.updatedAt, "attack attempt updated time"), version: positiveInteger(item.version, "attack attempt version"), evidence,
  };
}

export function parseAttackAttemptList(payload: unknown): AttackAttemptList {
  const root = exact(payload, "attack attempt list", ["schemaVersion", "items"]);
  return { schemaVersion: schemaVersion(root.schemaVersion), items: list(root.items, "attack attempts").map(parseAttackAttempt) };
}

export function parseAttackAttemptDetail(payload: unknown): AttackAttemptDetail {
  const root = exact(payload, "attack attempt detail", ["schemaVersion", "attempt"]);
  return { schemaVersion: schemaVersion(root.schemaVersion), attempt: parseAttackAttempt(root.attempt) };
}

function parseProvenance(value: unknown): IntelligenceProvenance {
  const item = exact(value, "intelligence provenance", ["method", "sourceRef"], ["sourceAgentId", "sourceTool", "observationIds"]);
  const sourceAgentId = item.sourceAgentId === undefined ? undefined : text(item.sourceAgentId, "provenance source agent ID");
  const sourceTool = item.sourceTool === undefined ? undefined : text(item.sourceTool, "provenance source tool");
  if (!sourceAgentId && !sourceTool) throw new Error("intelligence provenance requires an originating agent or tool");
  return {
    method: text(item.method, "provenance method"), sourceRef: text(item.sourceRef, "provenance source reference"),
    ...(sourceAgentId ? { sourceAgentId } : {}), ...(sourceTool ? { sourceTool } : {}),
    ...(item.observationIds === undefined ? {} : { observationIds: list(item.observationIds, "provenance observation IDs").map((candidate, index) => text(candidate, `provenance observation ID ${index}`)) }),
  };
}

function parseTopologyEvidence(value: unknown): TopologyEvidenceLink {
  const item = exact(value, "topology evidence", ["evidenceId", "relationship", "verificationState", "confidence", "contentHash", "summary", "provenance", "createdAt"]);
  const provenance = jsonObject(item.provenance, "topology evidence provenance");
  if (Object.keys(provenance).length === 0) throw new Error("topology evidence provenance cannot be empty");
  return {
    evidenceId: text(item.evidenceId, "topology evidence ID"),
    relationship: enumValue(item.relationship, new Set(["supports", "contradicts", "source"]), "topology evidence relationship"),
    verificationState: enumValue(item.verificationState, EVIDENCE_VERIFICATION_STATES, "topology evidence verification state"),
    confidence: confidence(item.confidence, "topology evidence confidence"),
    contentHash: text(item.contentHash, "topology evidence hash"), summary: text(item.summary, "topology evidence summary"),
    provenance, createdAt: timestamp(item.createdAt, "topology evidence created time"),
  };
}

function assertTopologyEvidence(subject: string, verificationState: TopologyNode["verificationState"], evidence: readonly TopologyEvidenceLink[]): void {
  if (evidence.length === 0) throw new Error(`${subject} requires canonical evidence`);
  const keys = new Set(evidence.map((link) => `${link.evidenceId}\0${link.relationship}`));
  if (keys.size !== evidence.length) throw new Error(`${subject} contains duplicate evidence relationships`);
  if (verificationState === "verified" && !evidence.some(({ verificationState: state }) => state === "verified")) {
    throw new Error(`verified ${subject} requires verified evidence`);
  }
  if (verificationState === "corroborated" && evidence.length < 2) throw new Error(`corroborated ${subject} requires multiple evidence links`);
  if (verificationState === "conflicting" && (!evidence.some(({ relationship }) => relationship !== "contradicts") || !evidence.some(({ relationship }) => relationship === "contradicts"))) {
    throw new Error(`conflicting ${subject} must preserve both supporting and contradicting evidence`);
  }
}

export function parseTopologyNode(value: unknown): TopologyNode {
  const item = exact(value, "topology node", ["id", "missionId", "runId", "nodeType", "primaryLabel", "normalizedIdentity", "scopeStatus", "lifecycleState", "properties", "provenance", "confidence", "verificationState", "sensitivity", "firstSeenAt", "lastSeenAt", "evidence"]);
  const verificationState = enumValue<TopologyNode["verificationState"]>(item.verificationState, TOPOLOGY_VERIFICATION_STATES, "topology node verification state");
  const evidence = list(item.evidence, "topology node evidence").map(parseTopologyEvidence);
  assertTopologyEvidence("topology node", verificationState, evidence);
  const firstSeenAt = timestamp(item.firstSeenAt, "topology node first seen time");
  const lastSeenAt = timestamp(item.lastSeenAt, "topology node last seen time");
  if (Date.parse(lastSeenAt) < Date.parse(firstSeenAt)) throw new Error("topology node observation window is invalid");
  return {
    id: text(item.id, "topology node ID"), missionId: text(item.missionId, "topology node mission ID"),
    runId: nullableText(item.runId, "topology node run ID"), nodeType: text(item.nodeType, "topology node type"),
    primaryLabel: text(item.primaryLabel, "topology node label"), normalizedIdentity: text(item.normalizedIdentity, "topology normalized identity"),
    scopeStatus: enumValue(item.scopeStatus, new Set(["allowed", "prohibited", "unknown", "out_of_scope"]), "topology scope status"),
    lifecycleState: enumValue(item.lifecycleState, new Set(["planned", "active", "validated", "blocked", "unreachable", "observed", "stale"]), "topology lifecycle state"),
    properties: jsonObject(item.properties, "topology node properties"), provenance: parseProvenance(item.provenance),
    confidence: confidence(item.confidence, "topology node confidence"), verificationState,
    sensitivity: enumValue(item.sensitivity, TOPOLOGY_SENSITIVITIES, "topology node sensitivity"),
    firstSeenAt, lastSeenAt, evidence,
  };
}

function parseTopologyEdge(value: unknown): TopologyEdge {
  const item = exact(value, "topology edge", ["id", "missionId", "sourceNodeId", "targetNodeId", "edgeType", "properties", "provenance", "confidence", "verificationState", "sensitivity", "firstSeenAt", "lastSeenAt", "evidence"]);
  const verificationState = enumValue<TopologyEdge["verificationState"]>(item.verificationState, TOPOLOGY_VERIFICATION_STATES, "topology edge verification state");
  const evidence = list(item.evidence, "topology edge evidence").map(parseTopologyEvidence);
  assertTopologyEvidence("topology edge", verificationState, evidence);
  const firstSeenAt = timestamp(item.firstSeenAt, "topology edge first seen time");
  const lastSeenAt = timestamp(item.lastSeenAt, "topology edge last seen time");
  if (Date.parse(lastSeenAt) < Date.parse(firstSeenAt)) throw new Error("topology edge observation window is invalid");
  const sourceNodeId = text(item.sourceNodeId, "topology edge source node ID");
  const targetNodeId = text(item.targetNodeId, "topology edge target node ID");
  if (sourceNodeId === targetNodeId) throw new Error("topology edge cannot point to itself");
  return {
    id: text(item.id, "topology edge ID"), missionId: text(item.missionId, "topology edge mission ID"), sourceNodeId, targetNodeId,
    edgeType: text(item.edgeType, "topology edge type"), properties: jsonObject(item.properties, "topology edge properties"),
    provenance: parseProvenance(item.provenance), confidence: confidence(item.confidence, "topology edge confidence"), verificationState,
    sensitivity: enumValue(item.sensitivity, TOPOLOGY_SENSITIVITIES, "topology edge sensitivity"), firstSeenAt, lastSeenAt, evidence,
  };
}

function parseReconDigitalTwin(value: unknown): ReconDigitalTwin {
  const item = exact(value, "recon digital twin", ["missionId", "runId", "nodes", "edges"]);
  const missionId = text(item.missionId, "digital twin mission ID");
  const runId = nullableText(item.runId, "digital twin run ID");
  const nodes = list(item.nodes, "digital twin nodes").map(parseTopologyNode);
  const edges = list(item.edges, "digital twin edges").map(parseTopologyEdge);
  const nodeIds = new Set(nodes.map(({ id }) => id));
  const edgeIds = new Set(edges.map(({ id }) => id));
  if (nodeIds.size !== nodes.length || edgeIds.size !== edges.length) throw new Error("digital twin contains duplicate identifiers");
  for (const node of nodes) {
    if (node.missionId !== missionId || (runId !== null && node.runId !== null && node.runId !== runId)) throw new Error("digital twin node escapes its requested scope");
  }
  for (const edge of edges) {
    if (edge.missionId !== missionId || !nodeIds.has(edge.sourceNodeId) || !nodeIds.has(edge.targetNodeId)) throw new Error("digital twin edge has an invalid scoped endpoint");
  }
  return { missionId, runId, nodes, edges };
}

export function parseReconDigitalTwinDetail(payload: unknown): ReconDigitalTwinDetail {
  const root = exact(payload, "recon digital twin response", ["schemaVersion", "digitalTwin"]);
  return { schemaVersion: schemaVersion(root.schemaVersion), digitalTwin: parseReconDigitalTwin(root.digitalTwin) };
}

export function parseTopologyNodeDetail(payload: unknown): TopologyNodeDetail {
  const root = exact(payload, "topology node detail", ["schemaVersion", "node"]);
  return { schemaVersion: schemaVersion(root.schemaVersion), node: parseTopologyNode(root.node) };
}

function parseOsiObservation(value: unknown): OsiLayerObservation {
  const item = exact(value, "OSI observation", ["id", "assetNodeId", "layer", "category", "value", "versionValue", "derivation", "confidence", "evidenceId", "evidenceVerificationState", "evidenceProvenance", "observedAt", "conflictGroupId"]);
  const layer = nonNegativeInteger(item.layer, "OSI observation layer");
  if (layer < 1 || layer > 7) throw new Error("OSI observation layer must be 1 through 7");
  const evidenceProvenance = jsonObject(item.evidenceProvenance, "OSI evidence provenance");
  if (Object.keys(evidenceProvenance).length === 0) throw new Error("OSI evidence provenance cannot be empty");
  const derivation = enumValue<OsiLayerObservation["derivation"]>(item.derivation, new Set(["observed", "actively_verified", "inferred", "user_supplied"]), "OSI derivation");
  const evidenceVerificationState = enumValue<OsiLayerObservation["evidenceVerificationState"]>(item.evidenceVerificationState, EVIDENCE_VERIFICATION_STATES, "OSI evidence verification state");
  if (derivation === "actively_verified" && evidenceVerificationState !== "verified") throw new Error("actively verified OSI observations require verified evidence");
  return {
    id: text(item.id, "OSI observation ID"), assetNodeId: text(item.assetNodeId, "OSI asset node ID"),
    layer: layer as OsiLayerObservation["layer"], category: text(item.category, "OSI observation category"),
    value: text(item.value, "OSI observation value"), versionValue: nullableText(item.versionValue, "OSI observation version"),
    derivation, confidence: confidence(item.confidence, "OSI observation confidence"), evidenceId: text(item.evidenceId, "OSI evidence ID"),
    evidenceVerificationState, evidenceProvenance, observedAt: timestamp(item.observedAt, "OSI observation time"),
    conflictGroupId: nullableText(item.conflictGroupId, "OSI conflict group ID"),
  };
}

function parseOsiLayer(value: unknown): OsiLayerProjection {
  const item = exact(value, "OSI layer", ["layer", "name", "state", "observations"]);
  const layer = nonNegativeInteger(item.layer, "OSI layer number");
  if (layer < 1 || layer > 7) throw new Error("OSI layer must be 1 through 7");
  const state = enumValue<OsiLayerProjection["state"]>(item.state, new Set(["not_observed", "observed", "conflicting"]), "OSI layer state");
  const observations = list(item.observations, "OSI layer observations").map(parseOsiObservation);
  if (text(item.name, "OSI layer name") !== OSI_NAMES[layer - 1]) throw new Error(`OSI layer ${layer} has an invalid name`);
  if (observations.some((observation) => observation.layer !== layer)) throw new Error(`OSI layer ${layer} contains a mismatched observation`);
  if (state === "not_observed" && observations.length !== 0) throw new Error(`not-observed OSI layer ${layer} cannot contain observations`);
  if (state === "observed" && observations.length === 0) throw new Error(`observed OSI layer ${layer} requires an observation`);
  if (state === "conflicting" && (observations.length < 2 || !observations.some(({ conflictGroupId }) => conflictGroupId !== null))) {
    throw new Error(`conflicting OSI layer ${layer} requires grouped conflicting observations`);
  }
  return { layer: layer as OsiLayerProjection["layer"], name: OSI_NAMES[layer - 1], state, observations };
}

function parseAssetOsiStack(value: unknown): AssetOsiStack {
  const item = exact(value, "asset OSI stack", ["assetNodeId", "layers"]);
  const assetNodeId = text(item.assetNodeId, "OSI stack asset node ID");
  const layers = list(item.layers, "OSI layers").map(parseOsiLayer);
  if (layers.length !== 7 || layers.some(({ layer }, index) => layer !== index + 1)) throw new Error("OSI stack must contain all seven ordered layers");
  if (layers.some(({ observations }) => observations.some((observation) => observation.assetNodeId !== assetNodeId))) throw new Error("OSI observation belongs to a different asset");
  return { assetNodeId, layers };
}

export function parseAssetOsiStackDetail(payload: unknown): AssetOsiStackDetail {
  const root = exact(payload, "asset OSI stack response", ["schemaVersion", "stack"]);
  return { schemaVersion: schemaVersion(root.schemaVersion), stack: parseAssetOsiStack(root.stack) };
}

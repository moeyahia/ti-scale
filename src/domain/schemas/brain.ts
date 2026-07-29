import {
  HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS,
  MEMORY_EDGE_TYPES,
  MEMORY_LIFECYCLE_STATES,
  MEMORY_NODE_TYPES,
  MEMORY_OUTCOME_TAGS,
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
  type MemoryOriginPage,
  type MemorySourcePage,
  type MemoryNodeSummary,
  type MemoryOutcomeTag,
  type HistoricalReportedOutcomeSummary,
  type MemoryProvenance,
  type MemoryScope,
  type MemoryUsage,
  type MemoryVersion,
  type OperationalHazardDetail,
  type OperationalHazardAggregateObservationResult,
  type OperationalHazardReference,
  type OperatorPreferencePage,
  type OperationalHazardResetTotals,
  type ProvenanceOrigin,
  type ProvenanceSource,
  type VaultConflict,
  type VaultConnection,
  type VaultDisconnectMutation,
  type AttackKnowledgeVaultPresetPreview,
  type AttackKnowledgeVaultScopeAmendment,
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

function optionalOutcomeTags(value: unknown): MemoryOutcomeTag[] | undefined {
  if (value === undefined || value === null) return undefined;
  const selected = new Set(
    list(value, "memory outcome tags").map((item) => (
      enumValue(item, MEMORY_OUTCOME_TAGS, "memory outcome tag")
    )),
  );
  const normalized = MEMORY_OUTCOME_TAGS.filter((tag) => selected.has(tag));
  return normalized.length > 0 ? normalized : undefined;
}

function optionalHistoricalReportedOutcome(value: unknown): HistoricalReportedOutcomeSummary | undefined {
  if (value === undefined || value === null) return undefined;
  const item = record(value, "historical reported outcome");
  const classificationConfidence = number(
    item.classificationConfidence,
    "historical reported outcome classification confidence",
  );
  if (classificationConfidence < 0 || classificationConfidence > 1) {
    throw new RangeError("historical reported outcome classification confidence must be between zero and one");
  }
  return {
    classification: enumValue(
      item.classification,
      HISTORICAL_REPORTED_OUTCOME_CLASSIFICATIONS,
      "historical reported outcome classification",
    ),
    classificationConfidence,
    claimCount: count(item.claimCount, "historical reported outcome claim count"),
    sourceCount: count(item.sourceCount, "historical reported outcome source count"),
    policyVersion: text(item.policyVersion, "historical reported outcome policy version"),
  };
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

function parseProvenanceOrigin(value: unknown, index: number): ProvenanceOrigin {
  const originValue = record(value, `provenance source origins[${index}]`);
  return {
    ...(optionalText(originValue.missionId) ? { missionId: optionalText(originValue.missionId) } : {}),
    ...(optionalText(originValue.missionName) ? { missionName: optionalText(originValue.missionName) } : {}),
    ...(optionalText(originValue.runId) ? { runId: optionalText(originValue.runId) } : {}),
    ...(optionalText(originValue.runStatus) ? { runStatus: optionalText(originValue.runStatus) } : {}),
    ...(optionalText(originValue.engagementId) ? { engagementId: optionalText(originValue.engagementId) } : {}),
    ...(optionalText(originValue.engagementLabel) ? { engagementLabel: optionalText(originValue.engagementLabel) } : {}),
    ...(optionalText(originValue.artifactId) ? { artifactId: optionalText(originValue.artifactId) } : {}),
    ...(optionalText(originValue.evidenceId) ? { evidenceId: optionalText(originValue.evidenceId) } : {}),
    ...(optionalText(originValue.privateSourceReference) ? { privateSourceReference: optionalText(originValue.privateSourceReference) } : {}),
    ...(optionalText(originValue.sourceLocator) ? { sourceLocator: optionalText(originValue.sourceLocator) } : {}),
  };
}

export function parseProvenanceSource(value: unknown): ProvenanceSource {
  const item = record(value, "provenance source");
  const origins = item.origins === undefined
    ? undefined
    : list(item.origins, "provenance source origins").map(parseProvenanceOrigin);
  if (origins && origins.length > 1_000) {
    throw new Error("provenance source origins exceeds the bounded response limit");
  }
  const originCount = item.originCount === undefined
    ? origins?.length
    : count(item.originCount, "provenance source origin count");
  if (originCount !== undefined && originCount < (origins?.length ?? 0)) {
    throw new Error("provenance source origin count cannot be smaller than loaded origins");
  }
  const originsNextCursor = item.originsNextCursor === undefined || item.originsNextCursor === null
    ? null
    : text(item.originsNextCursor, "provenance origin cursor");
  if (originsNextCursor && originCount === (origins?.length ?? 0)) {
    throw new Error("provenance origin cursor requires unloaded origins");
  }
  return {
    ...(optionalText(item.sourceRecordId) ? { sourceRecordId: optionalText(item.sourceRecordId) } : {}),
    sourceType: text(item.sourceType, "source type"),
    sourceId: text(item.sourceId, "source id"),
    acquiredAt: text(item.acquiredAt, "source acquiredAt"),
    ...(optionalText(item.sourceHash) ? { sourceHash: optionalText(item.sourceHash) } : {}),
    ...(optionalText(item.excerptRedacted) ? { excerptRedacted: optionalText(item.excerptRedacted) } : {}),
    ...(origins && origins.length > 0 ? { origins } : {}),
    ...(originCount === undefined ? {} : { originCount }),
    originsNextCursor,
  };
}

export function parseMemorySourcePage(payload: unknown): MemorySourcePage {
  const value = record(unwrap(payload), "memory provenance source page");
  const items = list(value.items, "memory provenance sources").map(parseProvenanceSource);
  const totalCount = count(value.totalCount, "memory provenance source total");
  if (totalCount < items.length) throw new Error("memory provenance source total cannot be smaller than the loaded page");
  const nextCursor = value.nextCursor === null ? null : text(value.nextCursor, "memory provenance source cursor");
  if (nextCursor && totalCount === items.length) throw new Error("memory provenance source cursor requires unloaded sources");
  return {
    schemaVersion: schemaVersion(value.schemaVersion),
    nodeId: text(value.nodeId, "memory provenance node ID"),
    items,
    totalCount,
    nextCursor,
  };
}

export function parseMemoryOriginPage(payload: unknown): MemoryOriginPage {
  const value = record(unwrap(payload), "memory provenance origin page");
  const items = list(value.items, "memory provenance origins").map(parseProvenanceOrigin);
  const totalCount = count(value.totalCount, "memory provenance origin total");
  if (totalCount < items.length) throw new Error("memory provenance origin total cannot be smaller than the loaded page");
  const nextCursor = value.nextCursor === null ? null : text(value.nextCursor, "memory provenance origin cursor");
  if (nextCursor && totalCount === items.length) throw new Error("memory provenance origin cursor requires unloaded origins");
  return {
    schemaVersion: schemaVersion(value.schemaVersion),
    nodeId: text(value.nodeId, "memory provenance node ID"),
    sourceRecordId: text(value.sourceRecordId, "memory provenance source record ID"),
    items,
    totalCount,
    nextCursor,
  };
}

export function parseOperatorPreferencePage(payload: unknown): OperatorPreferencePage {
  const value = record(unwrap(payload), "operator preference response");
  return {
    schemaVersion: schemaVersion(value.schemaVersion),
    items: list(value.items, "operator preferences").map((entry) => {
      const item = record(entry, "operator preference");
      const rawValue = record(item.value, "operator preference value");
      const appliesTo = list(item.appliesTo, "operator preference applicability")
        .map((scope) => text(scope, "operator preference applicability item"));
      return {
        node: parseMemoryNodeSummary(item.node),
        preferenceKey: text(item.preferenceKey, "operator preference key"),
        value: rawValue,
        appliesTo,
        operatorId: text(item.operatorId, "operator preference owner"),
        confirmationState: enumValue(item.confirmationState, ["confirmed"] as const, "operator preference confirmation"),
        consentPolicy: text(item.consentPolicy, "operator preference consent policy"),
        profileVersion: count(item.profileVersion, "operator preference profile version"),
        lastConfirmedAt: text(item.lastConfirmedAt, "operator preference confirmation time"),
        provenance: parseProvenance(item.provenance),
      };
    }),
    totalReturned: count(value.totalReturned, "operator preference returned count"),
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
  const outcomeTags = optionalOutcomeTags(item.outcomeTags);
  const reportedOutcome = optionalHistoricalReportedOutcome(item.reportedOutcome);
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
    ...(outcomeTags ? { outcomeTags } : {}),
    ...(reportedOutcome ? { reportedOutcome } : {}),
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
      candidateNodes: count(counts.candidateNodes, "candidate node count"),
      pendingReviews: count(counts.pendingReviews, "pending memory review count"),
      candidates: count(counts.candidates, "pending memory review compatibility count"),
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

function parseOperationalHazardReference(value: unknown): OperationalHazardReference {
  const item = record(value, "operational hazard reference");
  const confidence = number(item.confidence, "operational hazard reference confidence");
  if (confidence < 0 || confidence > 1) throw new RangeError("operational hazard reference confidence must be between zero and one");
  return {
    id: text(item.id, "operational hazard reference id"),
    nodeType: enumValue(item.nodeType, MEMORY_NODE_TYPES, "operational hazard reference type"),
    title: text(item.title, "operational hazard reference title"),
    summary: typeof item.summary === "string" ? item.summary : "",
    confidence,
    lifecycleStatus: enumValue(item.lifecycleStatus, MEMORY_LIFECYCLE_STATES, "operational hazard reference lifecycle"),
    ...(optionalText(item.expiresAt) ? { expiresAt: optionalText(item.expiresAt) } : {}),
  };
}

function nullableOperationalHazardReference(value: unknown): OperationalHazardReference | null {
  return value === null || value === undefined ? null : parseOperationalHazardReference(value);
}

function stringList(value: unknown, label: string): string[] {
  return list(value, label).map((item, index) => text(item, `${label}[${index}]`));
}

function nullableFiniteNumber(value: unknown, label: string): number | null {
  return value === null || value === undefined ? null : number(value, label);
}

function primitiveRecord(value: unknown, label: string): Record<string, string | number | boolean> {
  const item = record(value, label);
  const result: Record<string, string | number | boolean> = {};
  for (const [key, entry] of Object.entries(item)) {
    if (typeof entry !== "string" && typeof entry !== "boolean" && (typeof entry !== "number" || !Number.isFinite(entry))) {
      throw new Error(`${label}.${key} must be a finite primitive`);
    }
    result[key] = entry;
  }
  return result;
}

function parseOperationalHazardDetail(value: unknown): OperationalHazardDetail {
  const item = record(value, "operational hazard detail");
  const normalized = record(item.normalizedExecution, "operational hazard execution envelope");
  const constraints = record(item.applicabilityConstraints, "operational hazard applicability constraints");
  const allowedConstraints = [
    "requireExactProcedureVersion",
    "requireVerifiedVersionRelationship",
    "requireAllStackNodes",
    "requireAllPrerequisites",
    "requireObservedState",
  ] as const;
  if (Object.keys(constraints).some((key) => !allowedConstraints.includes(key as typeof allowedConstraints[number]))) {
    throw new Error("operational hazard applicability constraint is unsupported");
  }
  const parsedConstraints: OperationalHazardDetail["applicabilityConstraints"] = {};
  for (const key of allowedConstraints) {
    if (constraints[key] !== undefined) parsedConstraints[key] = boolean(constraints[key], `operational hazard ${key}`);
  }
  const symptom = record(item.symptom, "operational hazard symptom");
  const transition = record(item.stateTransition, "operational hazard state transition");
  const corroboration = record(item.corroboration, "operational hazard corroboration");
  const recovery = record(item.recovery, "operational hazard recovery");
  const recoveryCost = record(recovery.cost, "operational hazard recovery cost");
  const recoveryNumbers = [
    "resetCount",
    "operatorReportedResetCountMinimum",
    "serviceRecycleCount",
    "downtimeMs",
    "operatorMinutes",
  ] as const;
  const parsedRecoveryCost: OperationalHazardDetail["recovery"]["cost"] = {};
  for (const key of recoveryNumbers) {
    if (recoveryCost[key] !== undefined) parsedRecoveryCost[key] = count(recoveryCost[key], `operational hazard recovery ${key}`);
  }
  if (recoveryCost.requiresDisposableTargetReset !== undefined) {
    parsedRecoveryCost.requiresDisposableTargetReset = boolean(
      recoveryCost.requiresDisposableTargetReset,
      "operational hazard disposable reset requirement",
    );
  }
  const alternatives = record(item.alternatives, "operational hazard alternatives");
  const freshness = record(item.freshness, "operational hazard freshness");
  const receipt = record(item.provenanceReceipt, "operational hazard provenance receipt");
  const confidence = number(item.confidence, "operational hazard confidence");
  if (confidence < 0 || confidence > 1) throw new RangeError("operational hazard confidence must be between zero and one");
  return {
    procedure: nullableOperationalHazardReference(item.procedure),
    procedureVersion: nullableOperationalHazardReference(item.procedureVersion),
    affectedProducts: list(item.affectedProducts, "operational hazard products").map(parseOperationalHazardReference),
    affectedVersions: list(item.affectedVersions, "operational hazard versions").map(parseOperationalHazardReference),
    affectedStack: list(item.affectedStack, "operational hazard stack").map(parseOperationalHazardReference),
    prerequisites: list(item.prerequisites, "operational hazard prerequisites").map(parseOperationalHazardReference),
    observedStates: list(item.observedStates, "operational hazard observed states").map(parseOperationalHazardReference),
    orderedSequence: stringList(item.orderedSequence, "operational hazard ordered sequence"),
    normalizedExecution: {
      parameters: primitiveRecord(normalized.parameters, "operational hazard normalized parameters"),
      loadMinimum: nullableFiniteNumber(normalized.loadMinimum, "operational hazard load minimum"),
      concurrencyMinimum: nullableFiniteNumber(normalized.concurrencyMinimum, "operational hazard concurrency minimum"),
      timingWindowMs: nullableFiniteNumber(normalized.timingWindowMs, "operational hazard timing window"),
    },
    applicabilityConstraints: parsedConstraints,
    symptom: {
      observed: text(symptom.observed, "operational hazard observed symptom"),
      affectedComponent: text(symptom.affectedComponent, "operational hazard affected component"),
    },
    stateTransition: {
      before: text(transition.before, "operational hazard state before"),
      after: text(transition.after, "operational hazard state after"),
    },
    corroboration: {
      exactHangCount: count(corroboration.exactHangCount, "operational hazard exact hang count"),
      observedAttemptCount: count(corroboration.observedAttemptCount, "operational hazard observed attempt count"),
      operatorReportedResetMinimum: corroboration.operatorReportedResetMinimum === null
        ? null
        : count(corroboration.operatorReportedResetMinimum, "operational hazard operator reset minimum"),
    },
    safeHealthGate: stringList(item.safeHealthGate, "operational hazard health gate"),
    unsafeRetryConditions: stringList(item.unsafeRetryConditions, "operational hazard unsafe retry conditions"),
    recovery: {
      summary: text(recovery.summary, "operational hazard recovery summary"),
      pattern: nullableOperationalHazardReference(recovery.pattern),
      cost: parsedRecoveryCost,
    },
    alternatives: {
      sequence: stringList(alternatives.sequence, "operational hazard alternative sequence"),
      procedure: nullableOperationalHazardReference(alternatives.procedure),
    },
    confidence,
    freshness: {
      observedAt: text(freshness.observedAt, "operational hazard observed time"),
      freshUntil: freshness.freshUntil === null ? null : text(freshness.freshUntil, "operational hazard freshness deadline"),
      status: enumValue(freshness.status, ["current", "expired", "unbounded"] as const, "operational hazard freshness status"),
    },
    provenanceReceipt: {
      profileVersion: count(receipt.profileVersion, "operational hazard profile version"),
      sourceCount: count(receipt.sourceCount, "operational hazard receipt source count"),
      receiptIds: stringList(receipt.receiptIds, "operational hazard receipt IDs"),
      receiptHash: text(receipt.receiptHash, "operational hazard receipt hash"),
      recordedAt: text(receipt.recordedAt, "operational hazard receipt time"),
    },
  };
}

export function parseMemoryNodeDetail(payload: unknown): MemoryNodeDetail {
  const value = record(unwrap(payload), "memory node response");
  const sources = list(value.sources, "memory sources").map(parseProvenanceSource);
  const rawNode = record(value.node, "memory node detail");
  const parsedNode = parseMemoryNode(rawNode);
  return {
    node: rawNode.sourceCount === undefined
      ? { ...parsedNode, sourceCount: sources.length }
      : parsedNode,
    sources,
    sourcesNextCursor: value.sourcesNextCursor === undefined || value.sourcesNextCursor === null
      ? null
      : text(value.sourcesNextCursor, "memory provenance source cursor"),
    versions: list(value.versions, "memory versions").map(parseVersion),
    backlinks: list(value.backlinks, "memory backlinks").map(parseMemoryEdge),
    outgoing: list(value.outgoing, "memory outgoing edges").map(parseMemoryEdge),
    usage: list(value.usage, "memory usage").map(parseUsage),
    ...(value.operationalHazard === undefined || value.operationalHazard === null
      ? {}
      : { operationalHazard: parseOperationalHazardDetail(value.operationalHazard) }),
  };
}

export function parseOperationalHazardResetTotals(payload: unknown): OperationalHazardResetTotals {
  const value = record(unwrap(payload), "operational hazard reset totals");
  const exactAttributableResetCount = count(
    value.exactAttributableResetCount,
    "exact attributable reset count",
  );
  const operatorReportedResetMinimum = value.operatorReportedResetMinimum === null
    ? null
    : count(value.operatorReportedResetMinimum, "operator-reported reset minimum");
  const minimumUnattributedResetCount = count(
    value.minimumUnattributedResetCount,
    "minimum unattributed reset count",
  );
  const expectedUnattributedMinimum = operatorReportedResetMinimum === null
    ? 0
    : Math.max(operatorReportedResetMinimum - exactAttributableResetCount, 0);
  if (minimumUnattributedResetCount !== expectedUnattributedMinimum) {
    throw new Error("unattributed reset minimum does not match the canonical reset totals");
  }
  return {
    missionId: text(value.missionId, "reset totals mission ID"),
    runId: text(value.runId, "reset totals run ID"),
    exactAttributableResetCount,
    operatorReportedResetMinimum,
    minimumUnattributedResetCount,
  };
}

export function parseOperationalHazardAggregateObservationResult(
  payload: unknown,
): OperationalHazardAggregateObservationResult {
  const value = record(unwrap(payload), "operational hazard aggregate observation result");
  const observation = record(value.observation, "operational hazard aggregate observation");
  const totals = parseOperationalHazardResetTotals(value.totals);
  const missionId = text(observation.missionId, "aggregate observation mission ID");
  const runId = text(observation.runId, "aggregate observation run ID");
  const reportedMinimum = count(observation.reportedMinimum, "aggregate observation minimum");
  if (reportedMinimum < 1) throw new Error("aggregate observation minimum must be positive");
  if (missionId !== totals.missionId || runId !== totals.runId) {
    throw new Error("aggregate observation scope does not match its reset totals");
  }
  if (totals.operatorReportedResetMinimum === null
    || totals.operatorReportedResetMinimum < reportedMinimum) {
    throw new Error("aggregate observation is not represented by its canonical run total");
  }
  return {
    observation: {
      id: text(observation.id, "aggregate observation ID"),
      missionId,
      runId,
      reportedMinimum,
      statementEventId: text(observation.statementEventId, "aggregate observation event ID"),
      reportedAt: text(observation.reportedAt, "aggregate observation time"),
    },
    totals,
    replayed: boolean(value.replayed, "aggregate observation replay state"),
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

export function parseVaultDisconnectMutation(payload: unknown): VaultDisconnectMutation {
  const root = record(unwrap(payload), "vault disconnect response");
  const result = record(root.result, "vault disconnect result");
  const syncStopped = boolean(result.syncStopped, "Vault synchronization stopped");
  const filesDeleted = count(result.filesDeleted, "Vault files deleted");
  const notesRewritten = count(result.notesRewritten, "Vault notes rewritten");
  if (!syncStopped || filesDeleted !== 0 || notesRewritten !== 0) {
    throw new Error("Vault disconnect receipt must prove synchronization stopped without filesystem mutation");
  }
  return {
    connection: parseVaultConnection(root.connection),
    result: {
      status: enumValue(result.status, ["disconnected"] as const, "Vault disconnect status"),
      connectionId: text(result.connectionId, "Vault disconnect connection id"),
      disconnectedAt: text(result.disconnectedAt, "Vault disconnect time"),
      connectionVersion: text(result.connectionVersion, "Vault disconnect connection version"),
      projectionState: enumValue(result.projectionState, ["healthy", "degraded"] as const, "Vault projection state"),
      ...(optionalText(result.replacementConnectionId)
        ? { replacementConnectionId: optionalText(result.replacementConnectionId) }
        : {}),
      activeRunCount: count(result.activeRunCount, "active run count"),
      activeRunImpact: enumValue(result.activeRunImpact, ["canonical_brain_unaffected"] as const, "active run impact"),
      syncStopped: true,
      filesDeleted: 0,
      notesRewritten: 0,
      auditRecordId: text(result.auditRecordId, "Vault disconnect audit record id"),
      message: text(result.message, "Vault disconnect message"),
    },
  };
}

export function parseAttackKnowledgeVaultPresetPreview(payload: unknown): AttackKnowledgeVaultPresetPreview {
  const root = record(unwrap(payload), "Attack Knowledge Vault preset response");
  const value = record(root.preset, "Attack Knowledge Vault preset");
  const projection = record(value.projection, "Attack Knowledge Vault projection");
  const privacy = record(value.privacyBoundary, "Attack Knowledge Vault privacy boundary");
  const scopeKinds = list(projection.scopeKinds, "Attack Knowledge Vault scope kinds")
    .map((item) => enumValue(item, ["global"] as const, "Attack Knowledge Vault scope kind"));
  const nodeTypes = list(projection.nodeTypes, "Attack Knowledge Vault node types")
    .map((item) => text(item, "Attack Knowledge Vault node type"));
  const operatorProfileRequested = projection.operatorProfileIncluded === true;
  const operationalNodeTypes = new Set([
    "mission", "run", "plan", "phase", "step", "target", "asset", "entity",
    "decision", "evidence", "finding", "artifact", "report", "source",
  ]);
  if (nodeTypes.some((nodeType) => (
    operationalNodeTypes.has(nodeType) && !(operatorProfileRequested && nodeType === "entity")
  ))) {
    throw new Error("Attack Knowledge Vault projection cannot include operational node types");
  }
  const sensitivities = list(projection.sensitivities, "Attack Knowledge Vault sensitivities")
    .map((item) => enumValue(item, ["public", "internal", "private", "restricted"] as const, "Attack Knowledge Vault sensitivity"));
  if (sensitivities.includes("restricted")) {
    throw new Error("Attack Knowledge Vault projection cannot include restricted memory");
  }
  if (scopeKinds.length !== 1 || scopeKinds[0] !== "global") {
    throw new Error("Attack Knowledge Vault projection must be global only");
  }
  if (value.activationRequired !== true || privacy.restrictedSensitivityWithheld !== true) {
    throw new Error("Attack Knowledge Vault preset must require activation and withhold restricted memory");
  }
  const lifecycleStatuses = list(projection.lifecycleStatuses, "Attack Knowledge Vault lifecycle statuses")
    .map((item) => enumValue(item, ["verified", "confirmed"] as const, "Attack Knowledge Vault lifecycle status"));
  if (
    lifecycleStatuses.length < 1
    || lifecycleStatuses[0] !== "verified"
    || new Set(lifecycleStatuses).size !== lifecycleStatuses.length
    || (projection.confirmedKnowledgeIsOptIn === true) !== lifecycleStatuses.includes("confirmed")
  ) {
    throw new Error("Attack Knowledge Vault lifecycle policy must be verified-first and match the confirmed-knowledge opt-in");
  }
  const policyHash = text(value.policyHash, "Attack Knowledge Vault policy hash");
  if (!/^[a-f0-9]{64}$/u.test(policyHash)) {
    throw new Error("Attack Knowledge Vault policy hash must be a lowercase SHA-256 digest");
  }
  const excludedNodeTypes = list(privacy.excludesNodeTypes, "Attack Knowledge Vault excluded node types")
    .map((item) => text(item, "Attack Knowledge Vault excluded node type"));
  if ([...operationalNodeTypes].some((nodeType) => !excludedNodeTypes.includes(nodeType))) {
    throw new Error("Attack Knowledge Vault privacy boundary must explicitly exclude every operational node type");
  }
  const activePresetValue = value.activePreset === undefined
    ? undefined
    : record(value.activePreset, "active Attack Knowledge Vault preset");
  const scopeUpgradeValue = value.confirmedScopeUpgrade === undefined
    ? undefined
    : record(value.confirmedScopeUpgrade, "confirmed Attack Knowledge Vault scope upgrade");
  const operatorProfileUpgradeValue = value.operatorProfileScopeUpgrade === undefined
    ? undefined
    : record(value.operatorProfileScopeUpgrade, "Operator Profile Vault scope upgrade");
  const operatorProfileIncluded = boolean(projection.operatorProfileIncluded, "Operator Profile Vault projection state");
  const operatorProfileNodeCount = count(projection.operatorProfileNodeCount, "Operator Profile Vault projection node count");
  const operatorProfileAvailabilityValue = value.operatorProfileAvailability === undefined
    ? undefined
    : record(value.operatorProfileAvailability, "Operator Profile Vault availability");
  // The first 2.4 preset contract already returned an exact requested
  // Operator Profile projection and count, but did not return a separate
  // availability object. Accept only that self-proving legacy shape and derive
  // the narrow requested-preview availability from it. A non-requested legacy
  // preview remains fail-closed (unavailable) rather than guessing from an
  // active connection or silently broadening the requested projection.
  const operatorProfileAvailability = operatorProfileAvailabilityValue ? {
    requested: boolean(
      operatorProfileAvailabilityValue.requested,
      "Operator Profile Vault requested state",
    ),
    available: boolean(
      operatorProfileAvailabilityValue.available,
      "Operator Profile Vault availability state",
    ),
    status: enumValue(
      operatorProfileAvailabilityValue.status,
      ["available", "no_eligible_confirmed_profile"] as const,
      "Operator Profile Vault availability status",
    ),
    eligibleNodeCount: count(
      operatorProfileAvailabilityValue.eligibleNodeCount,
      "Operator Profile Vault eligible node count",
    ),
  } : {
    requested: operatorProfileIncluded,
    available: operatorProfileIncluded && operatorProfileNodeCount > 0,
    status: operatorProfileIncluded && operatorProfileNodeCount > 0
      ? "available" as const
      : "no_eligible_confirmed_profile" as const,
    eligibleNodeCount: operatorProfileIncluded ? operatorProfileNodeCount : 0,
  };
  if (
    operatorProfileAvailability.available !== (operatorProfileAvailability.eligibleNodeCount > 0)
    || (operatorProfileAvailability.status === "available") !== operatorProfileAvailability.available
  ) {
    throw new Error("Operator Profile Vault availability is inconsistent");
  }
  const activePreset = activePresetValue ? {
    connectionId: text(activePresetValue.connectionId, "active Attack Knowledge Vault connection id"),
    updatedAt: text(activePresetValue.updatedAt, "active Attack Knowledge Vault connection version"),
    includeConfirmed: boolean(activePresetValue.includeConfirmed, "active Attack Knowledge Vault confirmed scope"),
    includeOperatorProfile: boolean(activePresetValue.includeOperatorProfile, "active Attack Knowledge Vault Operator Profile scope"),
    ...(optionalText(activePresetValue.operatorProfileId)
      ? { operatorProfileId: optionalText(activePresetValue.operatorProfileId) }
      : {}),
    policyHash: text(activePresetValue.policyHash, "active Attack Knowledge Vault policy hash"),
  } : undefined;
  if (activePreset?.includeOperatorProfile && (!activePreset.includeConfirmed || !activePreset.operatorProfileId)) {
    throw new Error("Active Operator Profile Vault scope requires confirmed knowledge and one operator identity");
  }
  if (activePreset && !/^[a-f0-9]{64}$/u.test(activePreset.policyHash)) {
    throw new Error("Active Attack Knowledge Vault policy hash must be a lowercase SHA-256 digest");
  }
  const confirmedScopeUpgrade = scopeUpgradeValue ? {
    connectionId: text(scopeUpgradeValue.connectionId, "Attack Knowledge Vault upgrade connection id"),
    expectedUpdatedAt: text(scopeUpgradeValue.expectedUpdatedAt, "Attack Knowledge Vault upgrade connection version"),
    currentPolicyHash: text(scopeUpgradeValue.currentPolicyHash, "Attack Knowledge Vault current policy hash"),
    targetPolicyHash: text(scopeUpgradeValue.targetPolicyHash, "Attack Knowledge Vault target policy hash"),
    eligibleNodeCountBefore: count(scopeUpgradeValue.eligibleNodeCountBefore, "Attack Knowledge Vault eligible count before upgrade"),
    eligibleNodeCountAfter: count(scopeUpgradeValue.eligibleNodeCountAfter, "Attack Knowledge Vault eligible count after upgrade"),
    eligibleNodeDelta: count(scopeUpgradeValue.eligibleNodeDelta, "Attack Knowledge Vault eligible count delta"),
  } : undefined;
  if (confirmedScopeUpgrade && (
    !/^[a-f0-9]{64}$/u.test(confirmedScopeUpgrade.currentPolicyHash)
    || !/^[a-f0-9]{64}$/u.test(confirmedScopeUpgrade.targetPolicyHash)
    || confirmedScopeUpgrade.eligibleNodeCountAfter - confirmedScopeUpgrade.eligibleNodeCountBefore
      !== confirmedScopeUpgrade.eligibleNodeDelta
  )) {
    throw new Error("Attack Knowledge Vault confirmed-scope upgrade receipt is inconsistent");
  }
  const operatorProfileScopeUpgrade = operatorProfileUpgradeValue ? {
    connectionId: text(operatorProfileUpgradeValue.connectionId, "Operator Profile Vault upgrade connection id"),
    expectedUpdatedAt: text(operatorProfileUpgradeValue.expectedUpdatedAt, "Operator Profile Vault upgrade connection version"),
    currentPolicyHash: text(operatorProfileUpgradeValue.currentPolicyHash, "Operator Profile Vault current policy hash"),
    targetPolicyHash: text(operatorProfileUpgradeValue.targetPolicyHash, "Operator Profile Vault target policy hash"),
    eligibleNodeCountBefore: count(operatorProfileUpgradeValue.eligibleNodeCountBefore, "Operator Profile Vault eligible count before upgrade"),
    eligibleNodeCountAfter: count(operatorProfileUpgradeValue.eligibleNodeCountAfter, "Operator Profile Vault eligible count after upgrade"),
    eligibleNodeDelta: count(operatorProfileUpgradeValue.eligibleNodeDelta, "Operator Profile Vault eligible count delta"),
    operatorProfileNodeCount: count(operatorProfileUpgradeValue.operatorProfileNodeCount, "Operator Profile Vault node count"),
  } : undefined;
  if (operatorProfileScopeUpgrade && (
    !/^[a-f0-9]{64}$/u.test(operatorProfileScopeUpgrade.currentPolicyHash)
    || !/^[a-f0-9]{64}$/u.test(operatorProfileScopeUpgrade.targetPolicyHash)
    || operatorProfileScopeUpgrade.eligibleNodeCountAfter - operatorProfileScopeUpgrade.eligibleNodeCountBefore
      !== operatorProfileScopeUpgrade.eligibleNodeDelta
    || operatorProfileScopeUpgrade.operatorProfileNodeCount !== operatorProfileScopeUpgrade.eligibleNodeDelta
  )) {
    throw new Error("Operator Profile Vault scope-upgrade receipt is inconsistent");
  }
  if (
    operatorProfileIncluded !== (
      operatorProfileAvailability.requested && operatorProfileAvailability.available
    )
    || operatorProfileIncluded !== nodeTypes.includes("operator")
    || operatorProfileIncluded !== nodeTypes.includes("preference")
    || (operatorProfileIncluded && (!lifecycleStatuses.includes("confirmed") || operatorProfileNodeCount < 1))
    || (!operatorProfileIncluded && operatorProfileNodeCount !== 0)
    || (operatorProfileIncluded
      && operatorProfileNodeCount !== operatorProfileAvailability.eligibleNodeCount)
  ) {
    throw new Error("Operator Profile Vault projection boundary is inconsistent");
  }
  return {
    enabled: root.enabled === true,
    id: enumValue(value.id, ["ti_scale_attack_knowledge_v1"] as const, "Attack Knowledge Vault preset id"),
    displayName: enumValue(value.displayName, ["Ti-Scale Attack Knowledge Vault"] as const, "Attack Knowledge Vault display name"),
    vaultPath: enumValue(value.vaultPath, ["Attack-Knowledge-Vault"] as const, "Attack Knowledge Vault path"),
    policyHash,
    activationRequired: true,
    ...(optionalText(value.alreadyActiveConnectionId)
      ? { alreadyActiveConnectionId: optionalText(value.alreadyActiveConnectionId) }
      : {}),
    ...(activePreset ? { activePreset } : {}),
    ...(confirmedScopeUpgrade ? { confirmedScopeUpgrade } : {}),
    ...(operatorProfileScopeUpgrade ? { operatorProfileScopeUpgrade } : {}),
    operatorProfileAvailability,
    projection: {
      nodeTypes,
      scopeKinds: ["global"],
      lifecycleStatuses,
      sensitivities,
      folders: list(projection.folders, "Attack Knowledge Vault folders")
        .map((item) => text(item, "Attack Knowledge Vault folder")),
      policyEligibleNodeCount: count(projection.policyEligibleNodeCount, "Attack Knowledge Vault eligible node count"),
      excludedOperationalNodeCount: count(projection.excludedOperationalNodeCount, "Attack Knowledge Vault excluded node count"),
      confirmedKnowledgeIsOptIn: projection.confirmedKnowledgeIsOptIn === true,
      operatorProfileIncluded,
      operatorProfileNodeCount,
    },
    privacyBoundary: {
      excludesNodeTypes: excludedNodeTypes,
      excludesOperationalLocators: list(privacy.excludesOperationalLocators, "Attack Knowledge Vault excluded locators")
        .map((item) => text(item, "Attack Knowledge Vault excluded locator")),
      restrictedSensitivityWithheld: true,
    },
  };
}

export function parseAttackKnowledgeVaultScopeAmendment(
  payload: unknown,
): AttackKnowledgeVaultScopeAmendment {
  const root = record(unwrap(payload), "Attack Knowledge Vault scope amendment response");
  const result = record(root.result, "Attack Knowledge Vault scope amendment receipt");
  const health = record(result.filesystemHealth, "Attack Knowledge Vault scope amendment health");
  const connectionIdChanged = boolean(result.connectionIdChanged, "Attack Knowledge Vault connection-id change state");
  const vaultPathChanged = boolean(result.vaultPathChanged, "Attack Knowledge Vault path change state");
  const filesDeleted = count(result.filesDeleted, "Attack Knowledge Vault files deleted");
  const notesWritten = count(result.notesWritten, "Attack Knowledge Vault notes written during amendment");
  if (connectionIdChanged || vaultPathChanged || filesDeleted !== 0 || notesWritten !== 0) {
    throw new Error("Attack Knowledge Vault scope amendment must retain its connection, path, and files");
  }
  const eligibleNodeCountBefore = count(result.eligibleNodeCountBefore, "eligible nodes before scope amendment");
  const eligibleNodeCountAfter = count(result.eligibleNodeCountAfter, "eligible nodes after scope amendment");
  const eligibleNodeDelta = count(result.eligibleNodeDelta, "eligible node scope amendment delta");
  if (eligibleNodeCountAfter - eligibleNodeCountBefore !== eligibleNodeDelta) {
    throw new Error("Attack Knowledge Vault scope amendment counts are inconsistent");
  }
  const previousPolicyHash = text(result.previousPolicyHash, "previous Attack Knowledge Vault policy hash");
  const targetPolicyHash = text(result.targetPolicyHash, "target Attack Knowledge Vault policy hash");
  if (!/^[a-f0-9]{64}$/u.test(previousPolicyHash) || !/^[a-f0-9]{64}$/u.test(targetPolicyHash)) {
    throw new Error("Attack Knowledge Vault scope amendment policy hashes must be lowercase SHA-256 digests");
  }
  return {
    connection: parseVaultConnection(root.connection),
    result: {
      previousPolicyHash,
      targetPolicyHash,
      eligibleNodeCountBefore,
      eligibleNodeCountAfter,
      eligibleNodeDelta,
      amendedAt: text(result.amendedAt, "Attack Knowledge Vault amendment time"),
      auditRecordId: text(result.auditRecordId, "Attack Knowledge Vault amendment audit record"),
      filesystemHealth: {
        checkedAt: text(health.checkedAt, "Attack Knowledge Vault amendment health time"),
        checks: parseVaultHealthChecks(health.checks),
      },
      connectionIdChanged: false,
      vaultPathChanged: false,
      filesDeleted: 0,
      notesWritten: 0,
      ...(optionalText(result.operatorProfileFolder)
        ? { operatorProfileFolder: enumValue(result.operatorProfileFolder, ["10 Operator"] as const, "Operator Profile Vault folder") }
        : {}),
      ...(result.operatorProfileFolderCreated === undefined
        ? {}
        : { operatorProfileFolderCreated: boolean(result.operatorProfileFolderCreated, "Operator Profile Vault folder creation state") }),
      ...(result.operatorProfileNodeCount === undefined
        ? {}
        : { operatorProfileNodeCount: count(result.operatorProfileNodeCount, "Operator Profile Vault amendment node count") }),
    },
    preset: parseAttackKnowledgeVaultPresetPreview({
      schemaVersion: "2.4",
      enabled: true,
      preset: root.preset,
    }),
  };
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

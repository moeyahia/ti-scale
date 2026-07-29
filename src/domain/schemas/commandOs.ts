import type {
  AgentSummary,
  AttentionItem,
  AutonomousContextCandidate,
  AutonomousBranchContext,
  AutonomousBranchPreflight,
  AutonomousBranchResult,
  AutonomousMissionRequest,
  AutonomousMissionPreflight,
  AutonomousPlanningSelection,
  CreatedMission,
  Journey,
  MissionRecord,
  MissionPage,
  MissionBulkArchiveResult,
  MissionBulkExportResult,
  MissionPortfolioFilterState,
  MissionSummary,
  OperationalEvent,
  OverviewSnapshot,
  ReadinessCheck,
  RunStatus,
  SavedMissionViewCollection,
  VersionedAutonomousMissionPreflight,
} from "../types/commandOs";
import { AUTONOMOUS_LOCAL_PLANNING_SELECTION } from "../types/commandOs";
import { MEMORY_NODE_TYPES, type MemoryNodeType } from "../types/brain";

type UnknownRecord = Record<string, unknown>;

function record(value: unknown, label: string): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as UnknownRecord;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function nullableText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function finiteNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${label} must be a number`);
  return value;
}

function nonNegativeInteger(value: unknown, label: string): number {
  const result = finiteNumber(value, label);
  if (!Number.isSafeInteger(result) || result < 0) throw new Error(`${label} must be a non-negative integer`);
  return result;
}

function sha256Text(value: unknown, label: string): string {
  const result = text(value, label);
  if (!/^[a-f0-9]{64}$/u.test(result)) throw new Error(`${label} must be a SHA-256 digest`);
  return result;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function journey(value: unknown, label: string): Journey {
  if (value === "autonomous" || value === "guided") return value;
  throw new Error(`${label} must be autonomous or guided`);
}

function unwrap(payload: unknown): unknown {
  const value = record(payload, "response");
  return value.data && typeof value.data === "object" ? value.data : value;
}

function parseCheck(value: unknown): ReadinessCheck {
  const item = record(value, "readiness check");
  if (item.status !== "pass" && item.status !== "warn" && item.status !== "fail") {
    throw new Error("readiness check status is invalid");
  }
  return {
    id: text(item.id, "readiness check id"),
    label: text(item.label, "readiness check label"),
    status: item.status,
    impact: text(item.impact, "readiness check impact"),
    journeys: list(item.journeys).map((value) => journey(value, "readiness check journey")),
    remediation: optionalText(item.remediation),
  };
}

function parseReadiness(value: unknown): OverviewSnapshot["readiness"] {
  const readiness = record(value, "readiness");
  if (readiness.status !== "ready" && readiness.status !== "degraded" && readiness.status !== "blocked") {
    throw new Error("readiness status is invalid");
  }
  return {
    status: readiness.status,
    score: Math.max(0, Math.min(100, finiteNumber(readiness.score, "readiness score"))),
    checks: list(readiness.checks).map(parseCheck),
  };
}

function parseMission(value: unknown): MissionSummary {
  const item = record(value, "mission summary");
  const scope = item.scope && typeof item.scope === "object" && !Array.isArray(item.scope)
    ? item.scope as UnknownRecord : {};
  const owner = item.currentOwner && typeof item.currentOwner === "object" && !Array.isArray(item.currentOwner)
    ? item.currentOwner as UnknownRecord : undefined;
  const lastEvent = item.lastMeaningfulEvent && typeof item.lastMeaningfulEvent === "object" && !Array.isArray(item.lastMeaningfulEvent)
    ? item.lastMeaningfulEvent as UnknownRecord : undefined;
  const budget = item.budget && typeof item.budget === "object" && !Array.isArray(item.budget)
    ? item.budget as UnknownRecord : {};
  const numericRecord = (value: unknown): Record<string, number> => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    return Object.fromEntries(Object.entries(value as UnknownRecord).flatMap(([key, candidate]) => (
      typeof candidate === "number" && Number.isFinite(candidate) && candidate >= 0
        ? [[key, candidate]]
        : []
    )));
  };
  const progress = typeof item.progress === "number" && Number.isFinite(item.progress)
    ? Math.max(0, Math.min(100, item.progress)) : null;
  const highestFindingSeverity = ["informational", "low", "medium", "high", "critical"].includes(String(item.highestFindingSeverity))
    ? item.highestFindingSeverity as MissionSummary["highestFindingSeverity"] : null;
  const recoveryState = item.recoveryState === "recovering" || item.recoveryState === "blocked"
    ? item.recoveryState : null;
  const updatedAt = text(item.updatedAt, "mission updatedAt");
  return {
    id: text(item.id, "mission id"),
    title: text(item.title, "mission title"),
    journey: journey(item.journey, "mission journey"),
    status: text(item.status, "mission status"),
    missionStatus: optionalText(item.missionStatus) ?? text(item.status, "mission status"),
    authorizationStatus: optionalText(item.authorizationStatus) ?? "unknown",
    engagementId: nullableText(item.engagementId),
    scope: {
      allowedTargets: list(scope.allowedTargets).flatMap((target) => typeof target === "string" ? [target] : []),
      allowedTargetCount: typeof scope.allowedTargetCount === "number" && Number.isSafeInteger(scope.allowedTargetCount)
        ? Math.max(0, scope.allowedTargetCount) : 0,
      prohibitedTargetCount: typeof scope.prohibitedTargetCount === "number" && Number.isSafeInteger(scope.prohibitedTargetCount)
        ? Math.max(0, scope.prohibitedTargetCount) : 0,
    },
    createdAt: optionalText(item.createdAt) ?? updatedAt,
    updatedAt,
    runId: nullableText(item.runId),
    activeRunId: nullableText(item.activeRunId),
    runStartedAt: nullableText(item.runStartedAt),
    runEndedAt: nullableText(item.runEndedAt),
    currentPhase: nullableText(item.currentPhase),
    progress,
    currentOwner: owner && typeof owner.id === "string"
      ? { id: owner.id, name: nullableText(owner.name) }
      : null,
    team: list(item.team).flatMap((candidate) => {
      if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return [];
      const member = candidate as UnknownRecord;
      return typeof member.id === "string" ? [{ id: member.id, name: nullableText(member.name) }] : [];
    }),
    provider: nullableText(item.provider),
    risk: nullableText(item.risk),
    evidenceCount: typeof item.evidenceCount === "number" && Number.isSafeInteger(item.evidenceCount)
      ? Math.max(0, item.evidenceCount) : 0,
    highestFindingSeverity,
    decisionState: nullableText(item.decisionState),
    recoveryState,
    lastMeaningfulEvent: lastEvent && typeof lastEvent.type === "string"
      && typeof lastEvent.summary === "string" && typeof lastEvent.occurredAt === "string"
      ? { type: lastEvent.type, summary: lastEvent.summary, occurredAt: lastEvent.occurredAt }
      : null,
    budget: {
      limits: numericRecord(budget.limits),
      usage: numericRecord(budget.usage),
    },
    nextAction: nullableText(item.nextAction),
  };
}

function parseAttention(value: unknown): AttentionItem {
  const item = record(value, "attention item");
  return {
    id: text(item.id, "attention id"),
    type: text(item.type, "attention type"),
    severity: text(item.severity, "attention severity"),
    title: text(item.title, "attention title"),
    summary: text(item.summary, "attention summary"),
    missionId: optionalText(item.missionId),
    runId: optionalText(item.runId),
  };
}

function parseAgent(value: unknown): AgentSummary {
  const item = record(value, "agent summary");
  return {
    id: text(item.id, "agent id"),
    name: text(item.name, "agent name"),
    status: text(item.status, "agent status"),
    assignment: optionalText(item.assignment),
  };
}

export function parseOverview(payload: unknown): OverviewSnapshot {
  const value = record(unwrap(payload), "overview");
  const summary = record(value.summary, "overview summary");
  const brain = record(value.brain, "overview brain");
  const system = record(value.system, "overview system");
  if (value.schemaVersion !== "2.4") throw new Error("unsupported overview schema version");
  return {
    schemaVersion: "2.4",
    readiness: parseReadiness(value.readiness),
    summary: {
      activeMissions: finiteNumber(summary.activeMissions, "active mission count"),
      activeAgents: finiteNumber(summary.activeAgents, "active agent count"),
      pendingDecisions: finiteNumber(summary.pendingDecisions, "pending decision count"),
      recoveringRuns: finiteNumber(summary.recoveringRuns, "recovering run count"),
      lastEventAt: summary.lastEventAt === null ? null : text(summary.lastEventAt, "last event time"),
    },
    missions: list(value.missions).map(parseMission),
    attention: list(value.attention).map(parseAttention),
    agents: list(value.agents).map(parseAgent),
    brain: {
      confirmed: finiteNumber(brain.confirmed, "confirmed memory count"),
      candidateNodes: finiteNumber(brain.candidateNodes, "candidate node count"),
      pendingReviews: finiteNumber(brain.pendingReviews, "pending memory review count"),
      candidates: finiteNumber(brain.candidates, "pending memory review compatibility count"),
      stale: finiteNumber(brain.stale, "stale memory count"),
      conflicts: finiteNumber(brain.conflicts, "memory conflict count"),
      vaultStatus: text(brain.vaultStatus, "vault status"),
    },
    system: {
      database: text(system.database, "database status"),
      eventStream: text(system.eventStream, "event stream status"),
      providers: text(system.providers, "provider status"),
      mcp: text(system.mcp, "MCP status"),
    },
  };
}

function parseContextCandidate(value: unknown): AutonomousContextCandidate {
  const item = record(value, "Autonomous context candidate");
  const scope = record(item.scope, "Autonomous context scope");
  const nodeType = item.nodeType as MemoryNodeType;
  if (!MEMORY_NODE_TYPES.includes(nodeType)) throw new Error("context node type is invalid");
  if (item.lifecycleStatus !== "confirmed" && item.lifecycleStatus !== "verified") throw new Error("context lifecycle is invalid");
  if (scope.kind !== "global" && scope.kind !== "engagement") throw new Error("context scope is invalid");
  if (item.sensitivity !== "public" && item.sensitivity !== "internal" && item.sensitivity !== "private") {
    throw new Error("context sensitivity is invalid");
  }
  return {
    id: text(item.id, "context node id"),
    nodeType,
    title: text(item.title, "context title"),
    summary: text(item.summary, "context summary"),
    lifecycleStatus: item.lifecycleStatus,
    scope: {
      kind: scope.kind,
      ...(optionalText(scope.engagementId) ? { engagementId: optionalText(scope.engagementId) } : {}),
    },
    sensitivity: item.sensitivity,
    confidence: finiteNumber(item.confidence, "context confidence"),
    provenanceExplanation: text(item.provenanceExplanation, "context provenance"),
    updatedAt: text(item.updatedAt, "context updatedAt"),
  };
}

function parseProviderCandidate(value: unknown): AutonomousMissionPreflight["execution"]["providers"][number] {
  const item = record(value, "Autonomous provider candidate");
  if (item.status !== "healthy" && item.status !== "degraded" && item.status !== "unhealthy" && item.status !== "unknown") {
    throw new Error("Autonomous provider status is invalid");
  }
  return {
    id: text(item.id, "provider candidate id"),
    status: item.status,
    authenticated: booleanValue(item.authenticated, "provider authentication state"),
    enforcesAutonomousBoundary: booleanValue(item.enforcesAutonomousBoundary, "provider enforcement state"),
    reportsExactTokenUsage: booleanValue(item.reportsExactTokenUsage, "provider token accounting state"),
    reportsExactCostUsage: booleanValue(item.reportsExactCostUsage, "provider cost accounting state"),
    compatible: booleanValue(item.compatible, "provider compatibility"),
    reason: text(item.reason, "provider health explanation"),
    checkedAt: text(item.checkedAt, "provider checkedAt"),
  };
}

function parseToolCandidate(value: unknown): AutonomousMissionPreflight["execution"]["tools"][number] {
  const item = record(value, "Autonomous tool candidate");
  if (item.status !== "unknown" && item.status !== "healthy" && item.status !== "degraded" && item.status !== "offline" && item.status !== "quarantined") {
    throw new Error("Autonomous tool server status is invalid");
  }
  return {
    id: text(item.id, "tool server id"),
    name: text(item.name, "tool server name"),
    status: item.status,
    capabilities: list(item.capabilities).map((entry) => text(entry, "tool capability")),
    assignedAgentIds: list(item.assignedAgentIds).map((entry) => text(entry, "tool assigned agent ID")),
    enabled: booleanValue(item.enabled, "tool server enabled state"),
    startPermitted: booleanValue(item.startPermitted, "tool server start policy"),
    riskClass: text(item.riskClass, "tool server risk class"),
    checkedAt: optionalText(item.checkedAt),
  };
}

function parseSpecialistCandidate(value: unknown): AutonomousMissionPreflight["execution"]["team"]["candidates"][number] {
  const item = record(value, "Autonomous specialist candidate");
  const providerPolicy = record(item.providerPolicy, "specialist provider policy");
  const toolPolicy = record(item.toolPolicy, "specialist tool policy");
  if (item.status !== "available" && item.status !== "busy" && item.status !== "degraded" && item.status !== "offline" && item.status !== "quarantined") {
    throw new Error("Autonomous specialist status is invalid");
  }
  return {
    id: text(item.id, "specialist id"),
    displayName: text(item.displayName, "specialist display name"),
    role: text(item.role, "specialist role"),
    status: item.status,
    capabilities: list(item.capabilities).map((entry) => text(entry, "specialist capability")),
    runnableTools: list(item.runnableTools).map((entry) => text(entry, "specialist runnable tool")),
    mcpServerIds: list(item.mcpServerIds).map((entry) => text(entry, "specialist MCP server ID")),
    providerPolicy: { defaultProvider: optionalText(providerPolicy.defaultProvider) },
    toolPolicy: {
      allowedTools: list(toolPolicy.allowedTools).map((entry) => text(entry, "specialist allowed tool")),
      deniedTools: list(toolPolicy.deniedTools).map((entry) => text(entry, "specialist denied tool")),
      approvalRequiredTools: list(toolPolicy.approvalRequiredTools).map((entry) => text(entry, "specialist approval tool")),
    },
    compatible: booleanValue(item.compatible, "specialist compatibility"),
    incompatibilityReasons: list(item.incompatibilityReasons).map((entry) => text(entry, "specialist incompatibility reason")),
    lastHeartbeatAt: optionalText(item.lastHeartbeatAt),
  };
}

function parseModelConfigurationReceipt(
  value: unknown,
  label: string,
): AutonomousMissionPreflight["execution"]["team"]["modelAssignments"][number]["primary"] {
  const item = record(value, label);
  const enforcementMode = item.enforcementMode;
  if (
    enforcementMode !== "enforced_executor"
    && enforcementMode !== "observe_only_executor"
    && enforcementMode !== "advisor_only"
    && enforcementMode !== "unavailable"
  ) throw new Error(`${label} enforcement mode is invalid`);
  const authState = item.authState;
  if (
    authState !== "authenticated"
    && authState !== "unconfigured"
    && authState !== "invalid"
    && authState !== "unknown"
  ) throw new Error(`${label} authentication state is invalid`);
  const healthState = item.healthState;
  if (
    healthState !== "healthy"
    && healthState !== "degraded"
    && healthState !== "unavailable"
    && healthState !== "unknown"
  ) throw new Error(`${label} health state is invalid`);
  const executionBoundary = item.executionBoundary;
  if (
    executionBoundary !== "provider_tool_calling"
    && executionBoundary !== "local_deterministic_policy"
  ) throw new Error(`${label} execution boundary is invalid`);
  return {
    configurationId: text(item.configurationId, `${label} configuration ID`),
    providerId: text(item.providerId, `${label} provider ID`),
    modelId: text(item.modelId, `${label} model ID`),
    displayName: text(item.displayName, `${label} display name`),
    executionBoundary,
    reasoningEffort: parseNullableText(item.reasoningEffort, `${label} reasoning effort`),
    enforcementMode,
    authState,
    healthState,
    disclosureClass: text(item.disclosureClass, `${label} disclosure class`),
    costClass: text(item.costClass, `${label} cost class`),
    latencyClass: text(item.latencyClass, `${label} latency class`),
    contextLimit: item.contextLimit === null
      ? null
      : finiteNumber(item.contextLimit, `${label} context limit`),
    catalogSource: text(item.catalogSource, `${label} catalog source`),
    catalogRetrievedAt: parseNullableText(item.catalogRetrievedAt, `${label} catalog retrieval time`),
  };
}

function parseModelAssignmentReceipt(
  value: unknown,
): AutonomousMissionPreflight["execution"]["team"]["modelAssignments"][number] {
  const item = record(value, "Autonomous agent model assignment");
  const source = item.source;
  if (source !== "recommended" && source !== "inherited" && source !== "operator_override") {
    throw new Error("Autonomous agent model assignment source is invalid");
  }
  return {
    agentId: text(item.agentId, "Autonomous model assignment agent ID"),
    source,
    ready: booleanValue(item.ready, "Autonomous model assignment readiness"),
    reasons: list(item.reasons).map((reason) => text(reason, "Autonomous model assignment reason")),
    primary: parseModelConfigurationReceipt(item.primary, "Autonomous primary model receipt"),
    fallback: item.fallback === null
      ? null
      : parseModelConfigurationReceipt(item.fallback, "Autonomous fallback model receipt"),
  };
}

function parseAgentModelAssignment(
  value: unknown,
  label: string,
): AutonomousMissionRequest["contract"]["agentModelAssignments"][number] {
  const item = record(value, label);
  return {
    agentId: text(item.agentId, `${label} agent ID`),
    primaryConfigurationId: text(
      item.primaryConfigurationId,
      `${label} primary configuration ID`,
    ),
    fallbackConfigurationId: parseNullableText(
      item.fallbackConfigurationId,
      `${label} fallback configuration ID`,
    ),
  };
}

export function parseAutonomousPlanningSelection(
  value: unknown,
  label = "Autonomous planning selection",
): AutonomousPlanningSelection {
  if (value === undefined) return AUTONOMOUS_LOCAL_PLANNING_SELECTION;
  const item = record(value, label);
  if (item.route === "local_deterministic") {
    if (
      item.plannerId !== "ti-scale.local-autonomous-contract-planner.v1"
      || item.enforcementMode !== "local_policy"
      || item.disclosureClass !== "local_only"
      || item.executionAuthority !== "none"
    ) {
      throw new Error(`${label} local deterministic boundary is invalid`);
    }
    return {
      route: "local_deterministic",
      plannerId: "ti-scale.local-autonomous-contract-planner.v1",
      enforcementMode: "local_policy",
      disclosureClass: "local_only",
      executionAuthority: "none",
    };
  }
  if (item.route !== "provider_advisory") {
    throw new Error(`${label} route is invalid`);
  }
  if (
    item.enforcementMode !== "advisor_only"
    || (
      item.disclosureClass !== "public_only"
      && item.disclosureClass !== "sanitized_internal"
    )
    || item.executionAuthority !== "none"
  ) {
    throw new Error(`${label} provider advisory boundary is invalid`);
  }
  const fallbackConfigurationId = item.fallbackConfigurationId === null
    ? null
    : text(
        item.fallbackConfigurationId,
        `${label} fallback configuration ID`,
      );
  const primaryConfigurationId = text(
    item.primaryConfigurationId,
    `${label} primary configuration ID`,
  );
  if (fallbackConfigurationId === primaryConfigurationId) {
    throw new Error(`${label} fallback must differ from its primary configuration`);
  }
  return {
    route: "provider_advisory",
    agentId: text(item.agentId, `${label} planning agent ID`),
    primaryConfigurationId,
    fallbackConfigurationId,
    enforcementMode: "advisor_only",
    disclosureClass: item.disclosureClass,
    executionAuthority: "none",
  };
}

function parseAutonomousPreflight(
  payload: unknown,
  requireInitialVersion: boolean,
): VersionedAutonomousMissionPreflight {
  const value = record(unwrap(payload), "Autonomous preflight");
  const contract = record(value.contract, "Autonomous contract review");
  const outcome = record(value.outcome, "Autonomous outcome");
  const context = record(value.context, "Autonomous context preview");
  const execution = record(value.execution, "Autonomous execution preview");
  const team = record(execution.team, "Autonomous specialist team preview");
  const summary = record(value.policySummary, "Autonomous policy summary");
  if (value.schemaVersion !== "2.4") throw new Error("unsupported Autonomous preflight schema version");
  const version = finiteNumber(contract.version, "Autonomous contract version");
  if (!Number.isSafeInteger(version) || version < 1 || (requireInitialVersion && version !== 1)) {
    throw new Error("Autonomous contract version is invalid");
  }
  const hash = text(contract.hash, "Autonomous contract hash");
  if (!/^[a-f0-9]{64}$/u.test(hash)) throw new Error("Autonomous contract hash is invalid");
  return {
    schemaVersion: "2.4",
    outcome: {
      id: outcome.id === "assessment" || outcome.id === "complete_engagement"
        ? outcome.id
        : (() => { throw new Error("Autonomous outcome ID is invalid"); })(),
      label: text(outcome.label, "Autonomous outcome label"),
      concisePromise: text(
        outcome.concisePromise,
        "Autonomous outcome promise",
      ),
      completionMeaning: text(
        outcome.completionMeaning,
        "Autonomous outcome completion meaning",
      ),
      requiredTerminalSuccessCriteria: list(
        outcome.requiredTerminalSuccessCriteria,
      ).map((item) => text(item, "Autonomous terminal success criterion")),
      requiredActionClassIds: list(outcome.requiredActionClassIds)
        .map((item) => text(item, "Autonomous terminal action class")),
    },
    contract: { version, hash },
    readiness: parseReadiness(value.readiness),
    context: {
      candidates: list(context.candidates).map(parseContextCandidate),
      selectedNodeIds: list(context.selectedNodeIds).map((item) => text(item, "selected context node ID")),
      invalidSelectedNodeIds: list(context.invalidSelectedNodeIds).map((item) => text(item, "invalid context node ID")),
    },
    execution: {
      providers: list(execution.providers).map(parseProviderCandidate),
      tools: list(execution.tools).map(parseToolCandidate),
      team: {
        candidates: list(team.candidates).map(parseSpecialistCandidate),
        selectedAgentIds: list(team.selectedAgentIds).map((item) => text(item, "selected specialist ID")),
        invalidSelectedAgentIds: list(team.invalidSelectedAgentIds).map((item) => text(item, "invalid specialist ID")),
        recommendedAgentIds: list(team.recommendedAgentIds).map((item) => text(item, "recommended specialist ID")),
        effectiveAgentIds: list(team.effectiveAgentIds).map((item) => text(item, "effective specialist ID")),
        modelAssignments: list(team.modelAssignments).map(parseModelAssignmentReceipt),
      },
    },
    policySummary: {
      provider: text(summary.provider, "provider policy summary"),
      tools: text(summary.tools, "tool policy summary"),
      notifications: text(summary.notifications, "notification policy summary"),
      reporting: text(summary.reporting, "reporting policy summary"),
      retention: text(summary.retention, "retention policy summary"),
      storage: text(summary.storage, "storage policy summary"),
    },
  };
}

export function parseAutonomousMissionPreflight(payload: unknown): AutonomousMissionPreflight {
  return parseAutonomousPreflight(payload, true) as AutonomousMissionPreflight;
}

function parseNullableText(value: unknown, label: string): string | null {
  return value === null ? null : text(value, label);
}

function stringList(value: unknown, label: string): string[] {
  return list(value).map((item) => text(item, label));
}

function parseAutonomousRequest(value: unknown): AutonomousMissionRequest {
  const root = record(value, "Autonomous branch request");
  const authorization = record(root.authorization, "Autonomous branch authorization");
  const contract = record(root.contract, "Autonomous branch contract");
  if (root.journey !== "autonomous" || root.launch !== true) throw new Error("branch request is not Autonomous");
  if (authorization.authorizationConfirmed !== true) throw new Error("branch authorization is not confirmed");
  const requiredLiteral = <T extends string>(candidate: unknown, expected: T, label: string): T => {
    if (candidate !== expected) throw new Error(`${label} is invalid`);
    return expected;
  };
  const destructivePolicy = contract.destructivePolicy;
  if (
    destructivePolicy !== "prohibited" &&
    destructivePolicy !== "validate_without_executing" &&
    destructivePolicy !== "bounded_lab_only"
  ) {
    throw new Error("branch destructive policy is invalid");
  }
  const optionalNumber = (candidate: unknown, label: string): number | undefined => (
    candidate === undefined || candidate === null ? undefined : finiteNumber(candidate, label)
  );
  const environmentClassification = authorization.environmentClassification;
  if (
    environmentClassification !== undefined
    && !["client_or_public", "internal", "htb", "ctf", "local_disposable_lab"].includes(
      String(environmentClassification),
    )
  ) {
    throw new Error("branch environment classification is invalid");
  }
  return {
    journey: "autonomous",
    launch: true,
    title: text(root.title, "branch mission title"),
    objective: text(root.objective, "branch mission objective"),
    successCriteria: stringList(root.successCriteria, "branch success criterion"),
    authorization: {
      ...(optionalText(authorization.engagementId) ? { engagementId: optionalText(authorization.engagementId) } : {}),
      ...(environmentClassification === undefined ? {} : {
        environmentClassification: environmentClassification as AutonomousMissionRequest["authorization"]["environmentClassification"],
      }),
      allowedTargets: stringList(authorization.allowedTargets, "branch allowed target"),
      prohibitedTargets: stringList(authorization.prohibitedTargets, "branch prohibited target"),
      authorizationConfirmed: true,
      ...(optionalText(authorization.timeWindow) ? { timeWindow: optionalText(authorization.timeWindow) } : {}),
      ...(optionalText(authorization.dataHandling) ? { dataHandling: optionalText(authorization.dataHandling) } : {}),
    },
    contract: {
      allowedActionClasses: stringList(contract.allowedActionClasses, "branch allowed action class"),
      prohibitedActionClasses: stringList(contract.prohibitedActionClasses, "branch prohibited action class"),
      destructivePolicy,
      boundedDestructiveTargets: contract.boundedDestructiveTargets === undefined
        ? []
        : stringList(contract.boundedDestructiveTargets, "branch bounded destructive target"),
      evidenceRequirements: stringList(contract.evidenceRequirements, "branch evidence requirement"),
      timeBudgetMinutes: finiteNumber(contract.timeBudgetMinutes, "branch time budget"),
      ...(optionalNumber(contract.tokenBudget, "branch token budget") === undefined ? {} : { tokenBudget: optionalNumber(contract.tokenBudget, "branch token budget") }),
      ...(optionalNumber(contract.costBudget, "branch cost budget") === undefined ? {} : { costBudget: optionalNumber(contract.costBudget, "branch cost budget") }),
      retryBudget: finiteNumber(contract.retryBudget, "branch retry budget"),
      replanBudget: finiteNumber(contract.replanBudget, "branch replan budget"),
      concurrencyLimit: finiteNumber(contract.concurrencyLimit, "branch concurrency limit"),
      evidenceStorageBudgetBytes: finiteNumber(contract.evidenceStorageBudgetBytes, "branch evidence storage budget"),
      artifactStorageBudgetBytes: finiteNumber(contract.artifactStorageBudgetBytes, "branch artifact storage budget"),
      notificationPolicy: requiredLiteral(contract.notificationPolicy, "in_app_only", "branch notification policy"),
      reportingFormat: requiredLiteral(contract.reportingFormat, "ti_scale_json", "branch reporting format"),
      dataHandlingPolicy: requiredLiteral(contract.dataHandlingPolicy, "local_private", "branch data handling policy"),
      retentionPolicy: requiredLiteral(contract.retentionPolicy, "operator_managed", "branch retention policy"),
      providerPolicy: requiredLiteral(contract.providerPolicy, "automatic_enforcing_only", "branch provider policy"),
      planningSelection: parseAutonomousPlanningSelection(
        contract.planningSelection,
        "branch planning selection",
      ),
      toolPolicy: requiredLiteral(contract.toolPolicy, "contract_allowlist", "branch tool policy"),
      specialistAgentIds: stringList(contract.specialistAgentIds, "branch specialist ID"),
      agentModelAssignments: list(contract.agentModelAssignments).map((item, index) =>
        parseAgentModelAssignment(item, `branch agent model assignment ${index + 1}`)),
      memoryScopes: stringList(contract.memoryScopes, "branch memory scope"),
      contextNodeIds: stringList(contract.contextNodeIds, "branch context node ID"),
      safeStopConditions: stringList(contract.safeStopConditions, "branch safe-stop condition"),
      deliverables: stringList(contract.deliverables, "branch deliverable"),
    },
  };
}

function parseBranchMode(value: unknown): AutonomousBranchPreflight["mode"] {
  if (value === "unchanged_contract" || value === "contract_amendment") return value;
  throw new Error("Autonomous branch mode is invalid");
}

function parseVersionedPreflight(value: unknown): VersionedAutonomousMissionPreflight {
  return parseAutonomousPreflight(value, false);
}

export function parseAutonomousBranchContext(payload: unknown): AutonomousBranchContext {
  const root = record(unwrap(payload), "Autonomous branch context");
  const mission = record(root.mission, "branch mission");
  const sourceRun = record(root.sourceRun, "branch source run");
  const contract = record(root.contract, "branch contract");
  if (root.schemaVersion !== "2.4") throw new Error("unsupported branch context schema version");
  const hash = text(contract.hash, "branch contract hash");
  if (!/^[a-f0-9]{64}$/u.test(hash)) throw new Error("branch contract hash is invalid");
  return {
    schemaVersion: "2.4",
    mission: {
      id: text(mission.id, "branch mission ID"),
      name: text(mission.name, "branch mission name"),
      version: finiteNumber(mission.version, "branch mission version"),
    },
    sourceRun: {
      id: text(sourceRun.id, "branch source run ID"),
      status: text(sourceRun.status, "branch source run status"),
      statusReason: parseNullableText(sourceRun.statusReason, "branch source reason"),
      version: finiteNumber(sourceRun.version, "branch source version"),
      safeToBranch: booleanValue(sourceRun.safeToBranch, "branch source safety"),
      safeToBranchReason: text(sourceRun.safeToBranchReason, "branch source safety reason"),
    },
    contract: {
      id: text(contract.id, "branch contract ID"),
      version: finiteNumber(contract.version, "branch contract version"),
      state: text(contract.state, "branch contract state"),
      hash,
    },
    request: parseAutonomousRequest(root.request),
    history: list(root.history).map((value) => {
      const item = record(value, "branch contract history");
      const itemHash = text(item.hash, "history contract hash");
      if (!/^[a-f0-9]{64}$/u.test(itemHash)) throw new Error("history contract hash is invalid");
      return {
        id: text(item.id, "history contract ID"),
        version: finiteNumber(item.version, "history contract version"),
        state: text(item.state, "history contract state"),
        hash: itemHash,
        sourceContractId: parseNullableText(item.sourceContractId, "history source contract ID"),
        confirmedBy: parseNullableText(item.confirmedBy, "history confirmer"),
        confirmedAt: parseNullableText(item.confirmedAt, "history confirmation time"),
        createdAt: text(item.createdAt, "history creation time"),
      };
    }),
  };
}

export function parseAutonomousBranchPreflight(payload: unknown): AutonomousBranchPreflight {
  const root = record(unwrap(payload), "Autonomous branch preflight");
  const contract = record(root.contract, "branch preflight contract");
  if (root.schemaVersion !== "2.4") throw new Error("unsupported branch preflight schema version");
  if (contract.state !== "confirmed" && contract.state !== "draft" && contract.state !== "unpersisted") {
    throw new Error("branch preflight contract state is invalid");
  }
  const hash = text(contract.hash, "branch preflight contract hash");
  if (!/^[a-f0-9]{64}$/u.test(hash)) throw new Error("branch preflight contract hash is invalid");
  return {
    schemaVersion: "2.4",
    mode: parseBranchMode(root.mode),
    sourceRunId: text(root.sourceRunId, "branch preflight source run ID"),
    sourceRunVersion: finiteNumber(root.sourceRunVersion, "branch preflight source version"),
    safeToBranch: booleanValue(root.safeToBranch, "branch preflight source safety"),
    safeToBranchReason: text(root.safeToBranchReason, "branch preflight safety reason"),
    contract: {
      id: contract.id === null ? null : text(contract.id, "branch preflight contract ID"),
      version: finiteNumber(contract.version, "branch preflight contract version"),
      state: contract.state,
      hash,
      sourceContractId: text(contract.sourceContractId, "branch source contract ID"),
    },
    request: parseAutonomousRequest(root.request),
    preflight: parseVersionedPreflight(root.preflight),
  };
}

export function parseAutonomousBranchResult(payload: unknown): AutonomousBranchResult {
  const root = record(unwrap(payload), "Autonomous branch result");
  const run = record(root.run, "Autonomous branch run");
  const contract = record(root.contract, "Autonomous branch confirmed contract");
  if (root.schemaVersion !== "2.4" || run.journey !== "autonomous" || run.status !== "planning" || contract.state !== "confirmed") {
    throw new Error("Autonomous branch result is invalid");
  }
  const hash = text(contract.hash, "confirmed branch contract hash");
  if (!/^[a-f0-9]{64}$/u.test(hash)) throw new Error("confirmed branch contract hash is invalid");
  const nextUrl = text(root.nextUrl, "Autonomous branch next URL");
  if (!nextUrl.startsWith("/missions/") || nextUrl.startsWith("//") || nextUrl.includes("\\")) {
    throw new Error("Autonomous branch next URL is invalid");
  }
  return {
    schemaVersion: "2.4",
    sourceRunId: text(root.sourceRunId, "Autonomous branch source run ID"),
    branchMode: parseBranchMode(root.branchMode),
    run: {
      id: text(run.id, "Autonomous branch run ID"),
      missionId: text(run.missionId, "Autonomous branch mission ID"),
      journey: "autonomous",
      status: "planning",
      contractId: text(run.contractId, "Autonomous branch contract ID"),
      createdAt: text(run.createdAt, "Autonomous branch creation time"),
    },
    contract: {
      id: text(contract.id, "confirmed branch contract ID"),
      version: finiteNumber(contract.version, "confirmed branch contract version"),
      state: "confirmed",
      hash,
    },
    nextUrl,
  };
}

export function parseMissionPage(payload: unknown): MissionPage {
  const value = record(unwrap(payload), "mission page");
  if (value.schemaVersion !== "2.4") throw new Error("unsupported mission page schema version");
  return {
    schemaVersion: "2.4",
    items: list(value.items).map(parseMission),
    nextCursor: value.nextCursor === null ? null : text(value.nextCursor, "mission page cursor"),
  };
}

function parsePortfolioState(value: unknown): MissionPortfolioFilterState {
  const item = record(value, "mission portfolio state");
  return {
    query: optionalText(item.query) ?? "",
    journey: item.journey === "autonomous" || item.journey === "guided" ? item.journey : "",
    status: optionalText(item.status) ?? "",
    engagement: optionalText(item.engagement) ?? "",
    target: optionalText(item.target) ?? "",
    agent: optionalText(item.agent) ?? "",
    provider: optionalText(item.provider) ?? "",
    updatedFrom: optionalText(item.updatedFrom) ?? "",
    updatedTo: optionalText(item.updatedTo) ?? "",
    risk: optionalText(item.risk) ?? "",
    evidence: item.evidence === "present" || item.evidence === "none" ? item.evidence : "",
    findingSeverity: optionalText(item.findingSeverity) ?? "",
    decisionState: optionalText(item.decisionState) ?? "",
    recoveryState: item.recoveryState === "recovering" || item.recoveryState === "blocked" || item.recoveryState === "none"
      ? item.recoveryState : "",
    view: item.view === "board" ? "board" : "table",
  };
}

export function parseSavedMissionViewCollection(payload: unknown): SavedMissionViewCollection {
  const value = record(unwrap(payload), "saved mission views");
  if (value.schemaVersion !== "2.4") throw new Error("unsupported saved mission view schema version");
  const version = finiteNumber(value.version, "saved mission view version");
  if (!Number.isSafeInteger(version) || version < 0) throw new Error("saved mission view version is invalid");
  return {
    schemaVersion: "2.4",
    version,
    items: list(value.items).map((candidate) => {
      const item = record(candidate, "saved mission view");
      return {
        id: text(item.id, "saved mission view id"),
        name: text(item.name, "saved mission view name"),
        state: parsePortfolioState(item.state),
        createdAt: text(item.createdAt, "saved mission view createdAt"),
        updatedAt: text(item.updatedAt, "saved mission view updatedAt"),
      };
    }),
  };
}

function parseBulkOutcome(value: unknown): MissionBulkArchiveResult["outcomes"][number] {
  const item = record(value, "mission bulk outcome");
  if (item.status !== "archived" && item.status !== "exported" && item.status !== "ineligible" && item.status !== "not_found") {
    throw new Error("mission bulk outcome status is invalid");
  }
  return {
    missionId: text(item.missionId, "mission bulk outcome ID"),
    status: item.status,
    reason: text(item.reason, "mission bulk outcome reason"),
  };
}

export function parseMissionBulkArchive(payload: unknown): MissionBulkArchiveResult {
  const value = record(unwrap(payload), "mission archive result");
  if (value.schemaVersion !== "2.4") throw new Error("unsupported mission archive schema version");
  return {
    schemaVersion: "2.4",
    selectionHash: sha256Text(value.selectionHash, "mission archive selection hash"),
    outcomes: list(value.outcomes).map(parseBulkOutcome),
    archivedCount: nonNegativeInteger(value.archivedCount, "archived mission count"),
  };
}

export function parseMissionBulkExport(payload: unknown): MissionBulkExportResult {
  const value = record(unwrap(payload), "mission export result");
  const policy = record(value.policy, "mission export policy");
  if (value.schemaVersion !== "2.4") throw new Error("unsupported mission export schema version");
  if (policy.evidenceBlobsIncluded !== false || policy.confidentialPayloadsIncluded !== false) {
    throw new Error("mission export policy must exclude evidence and confidential payloads");
  }
  return {
    schemaVersion: "2.4",
    generatedAt: text(value.generatedAt, "mission export generatedAt"),
    selectionHash: sha256Text(value.selectionHash, "mission export selection hash"),
    exportSha256: sha256Text(value.exportSha256, "mission export hash"),
    records: list(value.records).map((candidate) => {
      const item = record(candidate, "mission export record");
      const engagement = record(item.engagement, "mission export engagement");
      const scope = record(item.scope, "mission export scope");
      const findingCounts = item.findingCounts && typeof item.findingCounts === "object" && !Array.isArray(item.findingCounts)
        ? item.findingCounts as UnknownRecord : {};
      const latest = item.latestRun === null ? null : record(item.latestRun, "mission export latest run");
      return {
        missionId: text(item.missionId, "mission export mission ID"),
        titlePreview: text(item.titlePreview, "mission export title preview"),
        titleSha256: sha256Text(item.titleSha256, "mission export title hash"),
        titleTruncated: booleanValue(item.titleTruncated, "mission export title truncation"),
        journey: journey(item.journey, "mission export journey"),
        missionStatus: text(item.missionStatus, "mission export status"),
        authorizationStatus: text(item.authorizationStatus, "mission export authorization status"),
        createdAt: text(item.createdAt, "mission export createdAt"),
        updatedAt: text(item.updatedAt, "mission export updatedAt"),
        engagement: {
          present: booleanValue(engagement.present, "mission export engagement presence"),
          sha256: engagement.sha256 === null ? null : sha256Text(engagement.sha256, "mission export engagement hash"),
        },
        scope: {
          allowedTargetCount: nonNegativeInteger(scope.allowedTargetCount, "mission export allowed target count"),
          prohibitedTargetCount: nonNegativeInteger(scope.prohibitedTargetCount, "mission export prohibited target count"),
          targetSetSha256: sha256Text(scope.targetSetSha256, "mission export target-set hash"),
        },
        latestRun: latest ? {
          id: text(latest.id, "mission export run ID"),
          status: text(latest.status, "mission export run status"),
          progress: finiteNumber(latest.progress, "mission export run progress"),
          phase: nullableText(latest.phase),
          ownerId: nullableText(latest.ownerId),
          startedAt: nullableText(latest.startedAt),
          endedAt: nullableText(latest.endedAt),
        } : null,
        evidenceCount: nonNegativeInteger(item.evidenceCount, "mission export evidence count"),
        findingCounts: Object.fromEntries(Object.entries(findingCounts).map(([severity, count]) => [
          severity,
          nonNegativeInteger(count, `mission export ${severity} finding count`),
        ])),
      };
    }),
    outcomes: list(value.outcomes).map(parseBulkOutcome),
    policy: {
      maxBatch: nonNegativeInteger(policy.maxBatch, "mission export maximum batch"),
      evidenceBlobsIncluded: false,
      confidentialPayloadsIncluded: false,
      titlePreviewLimit: nonNegativeInteger(policy.titlePreviewLimit, "mission export title preview limit"),
    },
  };
}

function parseMissionRecord(value: unknown): MissionRecord {
  const item = record(value, "mission");
  return {
    id: text(item.id, "mission id"),
    title: text(item.title, "mission title"),
    journey: journey(item.journey, "mission journey"),
    status: text(item.status, "mission status"),
    version: finiteNumber(item.version, "mission version"),
    createdAt: text(item.createdAt, "mission createdAt"),
    updatedAt: text(item.updatedAt, "mission updatedAt"),
  };
}

const RUN_STATES = new Set<RunStatus>([
  "queued", "planning", "awaiting_contract_confirmation", "running",
  "waiting_guided_decision", "blocked", "recovering", "completed",
  "failed", "cancelled",
]);

export function parseCreatedMission(payload: unknown): CreatedMission {
  const value = record(unwrap(payload), "created mission");
  const run = record(value.run, "created run");
  const runStatus = text(run.status, "run status") as RunStatus;
  if (!RUN_STATES.has(runStatus)) throw new Error("created run status is invalid");
  return {
    mission: parseMissionRecord(value.mission),
    run: {
      id: text(run.id, "run id"),
      status: runStatus,
      journey: journey(run.journey, "run journey"),
    },
    nextUrl: text(value.nextUrl, "mission nextUrl"),
  };
}

export function parseOperationalEvent(payload: unknown): OperationalEvent {
  const value = record(payload, "operational event");
  const allowedKeys = new Set([
    "id", "sequence", "type", "timestamp", "missionId", "runId", "journey", "summary",
    "actor", "payload", "schemaVersion", "traceId", "spanId", "sensitivity", "redaction",
    "contextPackId",
  ]);
  const unexpected = Object.keys(value).filter((key) => !allowedKeys.has(key));
  if (unexpected.length > 0) throw new Error(`operational event contains unsupported fields: ${unexpected.join(", ")}`);
  for (const key of ["payload", "redaction"]) {
    if (!(key in value)) throw new Error(`operational event ${key} is required`);
  }
  const sequence = nonNegativeInteger(value.sequence, "event sequence");
  if (sequence < 1) throw new Error("event sequence must be a positive integer");
  const schemaVersion = nonNegativeInteger(value.schemaVersion, "event schema version");
  if (schemaVersion < 1) throw new Error("event schema version must be a positive integer");
  const actor = record(value.actor, "event actor");
  const unexpectedActorKeys = Object.keys(actor).filter((key) => key !== "type" && key !== "id");
  if (unexpectedActorKeys.length > 0) throw new Error(`event actor contains unsupported fields: ${unexpectedActorKeys.join(", ")}`);
  if (![
    "operator", "agent", "worker", "provider", "tool", "system",
  ].includes(String(actor.type))) throw new Error("event actor type is invalid");
  if (actor.id !== null && (typeof actor.id !== "string" || !actor.id.trim())) {
    throw new Error("event actor id must be a non-empty string or null");
  }
  if (![
    "public", "internal", "private", "restricted",
  ].includes(String(value.sensitivity))) throw new Error("event sensitivity is invalid");
  const nullableCorrelation = (item: unknown, label: string): string | null => {
    if (item === null) return null;
    return text(item, label);
  };
  const timestamp = text(value.timestamp, "event timestamp");
  if (Number.isNaN(Date.parse(timestamp))) throw new Error("event timestamp must be an ISO-compatible date-time");
  return {
    id: text(value.id, "event id"),
    sequence,
    type: text(value.type, "event type"),
    timestamp,
    missionId: text(value.missionId, "event mission id"),
    runId: text(value.runId, "event run id"),
    journey: journey(value.journey, "event journey"),
    summary: text(value.summary, "event summary"),
    actor: {
      type: actor.type as OperationalEvent["actor"]["type"],
      id: actor.id as string | null,
    },
    payload: value.payload,
    schemaVersion,
    traceId: nullableCorrelation(value.traceId, "event trace id"),
    spanId: nullableCorrelation(value.spanId, "event span id"),
    sensitivity: value.sensitivity as OperationalEvent["sensitivity"],
    redaction: value.redaction,
    contextPackId: nullableCorrelation(value.contextPackId, "event context pack id"),
  };
}

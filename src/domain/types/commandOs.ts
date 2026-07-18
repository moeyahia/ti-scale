export type Journey = "autonomous" | "guided";

export type RunStatus =
  | "queued"
  | "planning"
  | "awaiting_contract_confirmation"
  | "running"
  | "waiting_guided_decision"
  | "blocked"
  | "recovering"
  | "completed"
  | "failed"
  | "cancelled";

export interface ReadinessCheck {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail";
  impact: string;
  journeys: Journey[];
  remediation?: string;
}

export interface ReadinessSummary {
  status: "ready" | "degraded" | "blocked";
  score: number;
  checks: ReadinessCheck[];
}

export interface MissionSummary {
  id: string;
  title: string;
  journey: Journey;
  status: string;
  missionStatus: string;
  authorizationStatus: string;
  engagementId: string | null;
  scope: {
    allowedTargets: string[];
    allowedTargetCount: number;
    prohibitedTargetCount: number;
  };
  createdAt: string;
  updatedAt: string;
  runId: string | null;
  activeRunId: string | null;
  runStartedAt: string | null;
  runEndedAt: string | null;
  currentPhase: string | null;
  progress: number | null;
  currentOwner: { id: string; name: string | null } | null;
  team: Array<{ id: string; name: string | null }>;
  provider: string | null;
  risk: string | null;
  evidenceCount: number;
  highestFindingSeverity: "informational" | "low" | "medium" | "high" | "critical" | null;
  decisionState: string | null;
  recoveryState: "recovering" | "blocked" | null;
  lastMeaningfulEvent: { type: string; summary: string; occurredAt: string } | null;
  budget: { limits: Record<string, number>; usage: Record<string, number> };
  nextAction: string | null;
}

export interface MissionPortfolioFilterState {
  query: string;
  journey: Journey | "";
  status: string;
  engagement: string;
  target: string;
  agent: string;
  provider: string;
  updatedFrom: string;
  updatedTo: string;
  risk: string;
  evidence: "present" | "none" | "";
  findingSeverity: string;
  decisionState: string;
  recoveryState: "recovering" | "blocked" | "none" | "";
  view: "table" | "board";
}

export interface SavedMissionView {
  id: string;
  name: string;
  state: MissionPortfolioFilterState;
  createdAt: string;
  updatedAt: string;
}

export interface SavedMissionViewCollection {
  schemaVersion: "2.4";
  version: number;
  items: SavedMissionView[];
}

export interface MissionBulkItemOutcome {
  missionId: string;
  status: "archived" | "exported" | "ineligible" | "not_found";
  reason: string;
}

export interface MissionBulkArchiveResult {
  schemaVersion: "2.4";
  selectionHash: string;
  outcomes: MissionBulkItemOutcome[];
  archivedCount: number;
}

export interface MissionExportRecord {
  missionId: string;
  titlePreview: string;
  titleSha256: string;
  titleTruncated: boolean;
  journey: Journey;
  missionStatus: string;
  authorizationStatus: string;
  createdAt: string;
  updatedAt: string;
  engagement: { present: boolean; sha256: string | null };
  scope: { allowedTargetCount: number; prohibitedTargetCount: number; targetSetSha256: string };
  latestRun: {
    id: string;
    status: string;
    progress: number;
    phase: string | null;
    ownerId: string | null;
    startedAt: string | null;
    endedAt: string | null;
  } | null;
  evidenceCount: number;
  findingCounts: Record<string, number>;
}

export interface MissionBulkExportResult {
  schemaVersion: "2.4";
  generatedAt: string;
  selectionHash: string;
  exportSha256: string;
  records: MissionExportRecord[];
  outcomes: MissionBulkItemOutcome[];
  policy: {
    maxBatch: number;
    evidenceBlobsIncluded: false;
    confidentialPayloadsIncluded: false;
    titlePreviewLimit: number;
  };
}

export interface AttentionItem {
  id: string;
  type: string;
  severity: string;
  title: string;
  summary: string;
  missionId?: string;
  runId?: string;
}

export interface AgentSummary {
  id: string;
  name: string;
  status: string;
  assignment?: string;
}

export interface OverviewSnapshot {
  schemaVersion: "2.4";
  readiness: ReadinessSummary;
  summary: {
    activeMissions: number;
    activeAgents: number;
    pendingDecisions: number;
    recoveringRuns: number;
    lastEventAt: string | null;
  };
  missions: MissionSummary[];
  attention: AttentionItem[];
  agents: AgentSummary[];
  brain: {
    confirmed: number;
    candidates: number;
    stale: number;
    conflicts: number;
    vaultStatus: string;
  };
  system: {
    database: string;
    eventStream: string;
    providers: string;
    mcp: string;
  };
}

export interface MissionRecord {
  id: string;
  title: string;
  journey: Journey;
  status: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface MissionPage {
  schemaVersion: "2.4";
  items: MissionSummary[];
  nextCursor: string | null;
}

export interface CreatedMission {
  mission: MissionRecord;
  run: {
    id: string;
    status: RunStatus;
    journey: Journey;
  };
  nextUrl: string;
}

export interface AutonomousMissionRequest {
  journey: "autonomous";
  launch: true;
  title: string;
  objective: string;
  successCriteria: string[];
  authorization: {
    engagementId?: string;
    allowedTargets: string[];
    prohibitedTargets: string[];
    authorizationConfirmed: boolean;
    timeWindow?: string;
    dataHandling?: string;
  };
  contract: {
    allowedActionClasses: string[];
    prohibitedActionClasses: string[];
    destructivePolicy: "prohibited" | "validate_without_executing" | "bounded_lab_only";
    boundedDestructiveTargets?: string[];
    evidenceRequirements: string[];
    timeBudgetMinutes: number;
    tokenBudget?: number;
    costBudget?: number;
    retryBudget: number;
    replanBudget: number;
    concurrencyLimit: number;
    evidenceStorageBudgetBytes: number;
    artifactStorageBudgetBytes: number;
    notificationPolicy: "in_app_only";
    reportingFormat: "ti_scale_json";
    dataHandlingPolicy: "local_private";
    retentionPolicy: "operator_managed";
    providerPolicy: "automatic_enforcing_only";
    toolPolicy: "contract_allowlist";
    specialistAgentIds: string[];
    memoryScopes: string[];
    contextNodeIds: string[];
    safeStopConditions: string[];
    deliverables: string[];
  };
  contractReview?: { version: 1; hash: string };
}

export interface AutonomousContextCandidate {
  id: string;
  nodeType: "preference" | "lesson";
  title: string;
  summary: string;
  lifecycleStatus: "confirmed" | "verified";
  scope: { kind: "global" | "engagement"; engagementId?: string };
  sensitivity: "public" | "internal" | "private";
  confidence: number;
  provenanceExplanation: string;
  updatedAt: string;
}

export interface AutonomousProviderPathCandidate {
  id: string;
  status: "healthy" | "degraded" | "unhealthy" | "unknown";
  authenticated: boolean;
  enforcesAutonomousBoundary: boolean;
  reportsExactTokenUsage: boolean;
  reportsExactCostUsage: boolean;
  compatible: boolean;
  reason: string;
  checkedAt: string;
}

export interface AutonomousToolServerCandidate {
  id: string;
  name: string;
  status: "unknown" | "healthy" | "degraded" | "offline" | "quarantined";
  capabilities: string[];
  assignedAgentIds: string[];
  enabled: boolean;
  startPermitted: boolean;
  riskClass: string;
  checkedAt?: string;
}

export interface AutonomousSpecialistCandidate {
  id: string;
  displayName: string;
  role: string;
  status: "available" | "busy" | "degraded" | "offline" | "quarantined";
  capabilities: string[];
  runnableTools: string[];
  mcpServerIds: string[];
  providerPolicy: { defaultProvider?: string };
  toolPolicy: {
    allowedTools: string[];
    deniedTools: string[];
    approvalRequiredTools: string[];
  };
  compatible: boolean;
  incompatibilityReasons: string[];
  lastHeartbeatAt?: string;
}

export interface AutonomousMissionPreflight {
  schemaVersion: "2.4";
  contract: { version: 1; hash: string };
  readiness: ReadinessSummary;
  context: {
    candidates: AutonomousContextCandidate[];
    selectedNodeIds: string[];
    invalidSelectedNodeIds: string[];
  };
  execution: {
    providers: AutonomousProviderPathCandidate[];
    tools: AutonomousToolServerCandidate[];
    team: {
      candidates: AutonomousSpecialistCandidate[];
      selectedAgentIds: string[];
      invalidSelectedAgentIds: string[];
      recommendedAgentIds: string[];
      effectiveAgentIds: string[];
    };
  };
  policySummary: {
    provider: string;
    tools: string;
    notifications: string;
    reporting: string;
    retention: string;
    storage: string;
  };
}

export type VersionedAutonomousMissionPreflight = Omit<AutonomousMissionPreflight, "contract"> & {
  contract: { version: number; hash: string };
};

export type AutonomousBranchMode = "unchanged_contract" | "contract_amendment";

export interface AutonomousBranchContext {
  schemaVersion: "2.4";
  mission: { id: string; name: string; version: number };
  sourceRun: {
    id: string; status: string; statusReason: string | null; version: number;
    safeToBranch: boolean; safeToBranchReason: string;
  };
  contract: { id: string; version: number; state: string; hash: string };
  request: AutonomousMissionRequest;
  history: Array<{
    id: string; version: number; state: string; hash: string; sourceContractId: string | null;
    confirmedBy: string | null; confirmedAt: string | null; createdAt: string;
  }>;
}

export interface AutonomousBranchPreflight {
  schemaVersion: "2.4";
  mode: AutonomousBranchMode;
  sourceRunId: string;
  sourceRunVersion: number;
  safeToBranch: boolean;
  safeToBranchReason: string;
  contract: {
    id: string | null; version: number; state: "confirmed" | "draft" | "unpersisted";
    hash: string; sourceContractId: string;
  };
  request: AutonomousMissionRequest;
  preflight: VersionedAutonomousMissionPreflight;
}

export interface AutonomousBranchResult {
  schemaVersion: "2.4";
  sourceRunId: string;
  branchMode: AutonomousBranchMode;
  run: {
    id: string; missionId: string; journey: "autonomous"; status: "planning";
    contractId: string; createdAt: string;
  };
  contract: { id: string; version: number; state: "confirmed"; hash: string };
  nextUrl: string;
}

export interface GuidedMissionRequest {
  journey: "guided";
  launch: true;
  authorizationConfirmed: true;
  title: string;
  objective: string;
  target?: string;
  engagementId?: string;
  explanationDepth: "concise" | "balanced" | "deep";
  executionPreference: "manual" | "single_step_agent";
  evidenceExpectations: string[];
}

export type MissionCreateRequest = AutonomousMissionRequest | GuidedMissionRequest;

export interface ApiErrorEnvelope {
  code: string;
  message: string;
  humanMessage: string;
  retryable: boolean;
  category: string;
  details?: unknown;
  traceId: string;
  remediation?: string;
  timestamp: string;
}

export interface OperationalEvent {
  readonly id: string;
  readonly sequence: number;
  readonly type: string;
  readonly timestamp: string;
  readonly missionId: string;
  readonly runId: string;
  readonly journey: Journey;
  readonly summary: string;
  readonly actor: {
    readonly type: "operator" | "agent" | "worker" | "provider" | "tool" | "system";
    readonly id: string | null;
  };
  readonly payload: unknown;
  readonly schemaVersion: number;
  readonly traceId: string | null;
  readonly spanId: string | null;
  readonly sensitivity: "public" | "internal" | "private" | "restricted";
  readonly redaction: unknown;
  readonly contextPackId: string | null;
}

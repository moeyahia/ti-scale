import type { JsonValue, Journey } from "../events";
import type { AttackCentricReusableNodeType } from "../memory";
import type {
  AutonomousOutcomeProfileId,
} from "../domain/autonomous-outcome-registry";
import type { GuidedReconnaissanceSelection } from "./GuidedReconnaissance";
import type {
  AgentModelAssignmentReceipt,
  AgentModelAssignmentSelection,
  AutonomousPlanningSelection,
} from "../model-config";
import type {
  GuidedLocalExploitIntelligenceSelection,
} from "../local-exploit-intelligence/types";

export type { Journey };

export type MissionEnvironmentClassification =
  | "client_or_public"
  | "internal"
  | "htb"
  | "ctf"
  | "local_disposable_lab";

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

export interface AutonomousMissionRequest {
  readonly journey: "autonomous";
  readonly launch: true;
  readonly title: string;
  readonly objective: string;
  readonly successCriteria: readonly string[];
  readonly authorization: {
    readonly engagementId?: string;
    readonly environmentClassification?: MissionEnvironmentClassification;
    readonly allowedTargets: readonly string[];
    readonly prohibitedTargets: readonly string[];
    readonly authorizationConfirmed: true;
    readonly timeWindow?: string;
    readonly dataHandling?: string;
  };
  readonly contract: {
    /**
     * The completion promise inside the Autonomous journey. Older imported
     * contracts may omit this and are classified deterministically during
     * preflight; every newly resolved contract persists it explicitly.
     */
    readonly outcomeProfile?: AutonomousOutcomeProfileId;
    readonly allowedActionClasses: readonly string[];
    readonly prohibitedActionClasses: readonly string[];
    readonly destructivePolicy: "prohibited" | "validate_without_executing" | "bounded_lab_only";
    /** Exact authorized target values where destructive execution is bounded. */
    readonly boundedDestructiveTargets?: readonly string[];
    readonly evidenceRequirements: readonly string[];
    readonly timeBudgetMinutes: number;
    /** Finite supervisor ceiling for all MCP/tool dispatches in this run. */
    readonly toolCallBudget?: number;
    readonly tokenBudget?: number;
    readonly costBudget?: number;
    readonly retryBudget: number;
    readonly replanBudget: number;
    readonly concurrencyLimit: number;
    /** Canonical evidence byte ceiling enforced by the run supervisor. */
    readonly evidenceStorageBudgetBytes: number;
    /** Canonical artifact byte ceiling enforced by the run supervisor. */
    readonly artifactStorageBudgetBytes: number;
    /** Only in-product semantic events are currently an enforceable notification channel. */
    readonly notificationPolicy: "in_app_only";
    /** The terminal, scope-checked Ti-Scale completion bundle. */
    readonly reportingFormat: "ti_scale_json";
    /** Canonical evidence/artifacts stay in the local private data plane. */
    readonly dataHandlingPolicy: "local_private";
    /** Retention remains explicit and operator-controlled until an expiry worker is available. */
    readonly retentionPolicy: "operator_managed";
    /** Provider selection is automatic and restricted to enforcing provider paths. */
    readonly providerPolicy: "automatic_enforcing_only";
    /**
     * Signed authority for constructing the plan. It is never an execution
     * assignment: local deterministic planning has no model pin, while a
     * provider-backed route is advisory-only and explicitly carries no
     * execution authority. Older stored contracts normalize to the local
     * deterministic selection during validation and hashing.
     */
    readonly planningSelection?: AutonomousPlanningSelection;
    /** Every tool action must match the signed action-class and target allowlist. */
    readonly toolPolicy: "contract_allowlist";
    /** Exact specialists permitted for this run; the planner cannot assign outside this pool. */
    readonly specialistAgentIds: readonly string[];
    /**
     * Exact live-catalog provider/model choices reviewed with this contract.
     * These immutable IDs, rather than mutable defaults, are pinned to a run.
     */
    readonly agentModelAssignments: readonly AgentModelAssignmentSelection[];
    readonly memoryScopes: readonly string[];
    /** Exact, operator-selected memory nodes; no broader memory may be retrieved. */
    readonly contextNodeIds: readonly string[];
    readonly safeStopConditions: readonly string[];
    readonly deliverables: readonly string[];
  };
  /** Required by launch; omitted only on the preflight request that issues it. */
  readonly contractReview?: {
    readonly version: 1;
    readonly hash: string;
  };
}

export interface AutonomousContextCandidate {
  readonly id: string;
  readonly nodeType: "preference" | "lesson" | AttackCentricReusableNodeType;
  readonly title: string;
  readonly summary: string;
  readonly lifecycleStatus: "confirmed" | "verified";
  readonly scope: {
    readonly kind: "global" | "engagement";
    readonly engagementId?: string;
  };
  readonly sensitivity: "public" | "internal" | "private";
  readonly confidence: number;
  readonly provenanceExplanation: string;
  readonly updatedAt: string;
}

export interface AutonomousProviderPathCandidate {
  readonly id: string;
  readonly status: "healthy" | "degraded" | "unhealthy" | "unknown";
  readonly authenticated: boolean;
  readonly enforcesAutonomousBoundary: boolean;
  readonly reportsExactTokenUsage: boolean;
  readonly reportsExactCostUsage: boolean;
  readonly compatible: boolean;
  readonly reason: string;
  readonly checkedAt: string;
}

export interface AutonomousToolServerCandidate {
  readonly id: string;
  readonly name: string;
  readonly status: "unknown" | "healthy" | "degraded" | "offline" | "quarantined";
  readonly capabilities: readonly string[];
  readonly assignedAgentIds: readonly string[];
  readonly enabled: boolean;
  readonly startPermitted: boolean;
  readonly riskClass: string;
  readonly checkedAt?: string;
}

export interface AutonomousSpecialistCandidate {
  readonly id: string;
  readonly displayName: string;
  readonly role: string;
  readonly status: "available" | "busy" | "degraded" | "offline" | "quarantined";
  readonly capabilities: readonly string[];
  readonly runnableTools: readonly string[];
  readonly mcpServerIds: readonly string[];
  readonly providerPolicy: {
    readonly defaultProvider?: string;
  };
  readonly toolPolicy: {
    readonly allowedTools: readonly string[];
    readonly deniedTools: readonly string[];
    readonly approvalRequiredTools: readonly string[];
  };
  readonly compatible: boolean;
  readonly incompatibilityReasons: readonly string[];
  readonly lastHeartbeatAt?: string;
}

export interface AutonomousExecutionPreview {
  readonly providers: readonly AutonomousProviderPathCandidate[];
  readonly tools: readonly AutonomousToolServerCandidate[];
  readonly team: {
    readonly candidates: readonly AutonomousSpecialistCandidate[];
    readonly selectedAgentIds: readonly string[];
    readonly invalidSelectedAgentIds: readonly string[];
    readonly recommendedAgentIds: readonly string[];
    readonly effectiveAgentIds: readonly string[];
    readonly modelAssignments: readonly AgentModelAssignmentReceipt[];
  };
}

export interface AutonomousMissionPreflight {
  readonly schemaVersion: "2.4";
  readonly outcome: {
    readonly id: AutonomousOutcomeProfileId;
    readonly label: string;
    readonly concisePromise: string;
    readonly completionMeaning: string;
    readonly requiredTerminalSuccessCriteria: readonly string[];
    readonly requiredActionClassIds: readonly string[];
  };
  readonly contract: {
    readonly version: 1;
    readonly hash: string;
  };
  readonly readiness: ReadinessSummary;
  readonly context: {
    readonly candidates: readonly AutonomousContextCandidate[];
    readonly selectedNodeIds: readonly string[];
    readonly invalidSelectedNodeIds: readonly string[];
  };
  readonly execution: AutonomousExecutionPreview;
  readonly policySummary: {
    readonly provider: string;
    readonly tools: string;
    readonly notifications: string;
    readonly reporting: string;
    readonly retention: string;
    readonly storage: string;
  };
}

export interface GuidedMissionRequest {
  readonly journey: "guided";
  readonly launch: true;
  readonly authorizationConfirmed: true;
  readonly title: string;
  readonly objective: string;
  readonly target?: string;
  readonly engagementId?: string;
  readonly explanationDepth: "concise" | "balanced" | "deep";
  readonly executionPreference: "manual" | "single_step_agent";
  readonly evidenceExpectations: readonly string[];
  /** Optional first represented reconnaissance step. Missing preserves target-derived behavior. */
  readonly guidedReconnaissance?: GuidedReconnaissanceSelection;
  /** One optional reviewed Windows/identity read; never contains credential material. */
  readonly guidedWindowsIdentity?: Readonly<{
    readonly operation:
      | "smb_share_list"
      | "smb_identity_summary"
      | "ldap_root_dse"
      | "rpc_domain_info";
    readonly authenticationMode: "anonymous" | "credential_reference";
    readonly credentialReference: Readonly<{
      readonly kind: "systemd_credential_bundle";
      readonly id: string;
    }> | null;
  }>;
  /**
   * One exact, operator-represented read of the pinned local ExploitDB
   * catalog. It has no provider contact, target contact, or evidence
   * promotion authority.
   */
  readonly guidedLocalExploitIntelligence?: GuidedLocalExploitIntelligenceSelection;
}

export type MissionCreateRequest =
  | AutonomousMissionRequest
  | GuidedMissionRequest;

export interface MissionRecord {
  readonly id: string;
  readonly title: string;
  readonly journey: Journey;
  readonly status: string;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreatedMission {
  readonly mission: MissionRecord;
  readonly run: {
    readonly id: string;
    readonly status: RunStatus;
    readonly journey: Journey;
  };
  /**
   * The persisted, scope-checked Second Brain intake result. A ready pack is
   * not proof that memory changed mission defaults; that attribution remains
   * false until a later consumer records an explicit item disposition.
   */
  readonly intakeContext?: MissionIntakeContextBinding;
  readonly nextUrl: string;
}

export interface MissionIntakeContextBinding {
  readonly hook: "intake";
  readonly contextPackId: string;
  readonly auditRecordId: string;
  readonly status: "ready" | "no_relevant_memory" | "degraded";
  readonly retrievedCount: number;
  readonly memoryInfluencedDefaults: boolean;
  /**
   * Presentation-only defaults selected from explicit, typed, confirmed
   * operator preference profiles. These values cannot alter the signed
   * objective, authorization, targets, action policy, evidence policy,
   * budgets, tools, providers, safe stops, or deliverables.
   */
  readonly safeOptionalDefaults?: {
    readonly autonomyPresentation?: "high_autonomy";
    readonly explanationTemplate?: "technical_readable";
    readonly reportTemplate?: "evidence_first";
    readonly safetyBoundary: "presentation_only_contract_unchanged";
  };
  readonly influenceExplanation?: string;
  readonly degradation?: {
    readonly code: string;
    readonly explanation: string;
  };
}

export type ReadinessCheckStatus = "pass" | "warn" | "fail";

export interface ReadinessCheck {
  readonly id: string;
  readonly label: string;
  readonly status: ReadinessCheckStatus;
  readonly impact: string;
  readonly journeys: readonly Journey[];
  readonly remediation?: string;
}

export interface ReadinessSummary {
  readonly status: "ready" | "degraded" | "blocked";
  readonly score: number;
  readonly checks: readonly ReadinessCheck[];
}

export interface ReadinessContext {
  readonly journey?: Journey;
  readonly request?: MissionCreateRequest;
}

export interface ReadinessCheckProvider {
  readonly id: string;
  readonly label: string;
  readonly journeys: readonly Journey[];
  evaluate(
    context: ReadinessContext,
  ): ReadinessCheck | readonly ReadinessCheck[] | Promise<ReadinessCheck | readonly ReadinessCheck[]>;
}

export interface MissionSummary {
  readonly id: string;
  readonly title: string;
  readonly journey: Journey;
  readonly status: string;
  readonly missionStatus: string;
  readonly authorizationStatus: string;
  readonly engagementId: string | null;
  readonly scope: {
    readonly allowedTargets: readonly string[];
    readonly allowedTargetCount: number;
    readonly prohibitedTargetCount: number;
  };
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly runId: string | null;
  readonly activeRunId: string | null;
  readonly runStartedAt: string | null;
  readonly runEndedAt: string | null;
  readonly currentPhase: string | null;
  readonly progress: number | null;
  readonly currentOwner: {
    readonly id: string;
    readonly name: string | null;
  } | null;
  readonly team: readonly {
    readonly id: string;
    readonly name: string | null;
  }[];
  readonly provider: string | null;
  readonly risk: string | null;
  readonly evidenceCount: number;
  readonly highestFindingSeverity: "informational" | "low" | "medium" | "high" | "critical" | null;
  readonly decisionState: string | null;
  readonly recoveryState: "recovering" | "blocked" | null;
  readonly lastMeaningfulEvent: {
    readonly type: string;
    readonly summary: string;
    readonly occurredAt: string;
  } | null;
  readonly budget: {
    readonly limits: Readonly<Record<string, number>>;
    readonly usage: Readonly<Record<string, number>>;
  };
  readonly nextAction: string | null;
}

export type MissionEvidenceFilter = "present" | "none";
export type MissionRecoveryFilter = "recovering" | "blocked" | "none";

export interface MissionPortfolioFilterState {
  readonly query: string;
  readonly journey: Journey | "";
  readonly status: string;
  readonly engagement: string;
  readonly target: string;
  readonly agent: string;
  readonly provider: string;
  readonly updatedFrom: string;
  readonly updatedTo: string;
  readonly risk: string;
  readonly evidence: MissionEvidenceFilter | "";
  readonly findingSeverity: string;
  readonly decisionState: string;
  readonly recoveryState: MissionRecoveryFilter | "";
  readonly view: "table" | "board";
}

export interface SavedMissionView {
  readonly id: string;
  readonly name: string;
  readonly state: MissionPortfolioFilterState;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface SavedMissionViewCollection {
  readonly schemaVersion: "2.4";
  readonly version: number;
  readonly items: readonly SavedMissionView[];
}

export interface MissionBulkItemOutcome {
  readonly missionId: string;
  readonly status: "archived" | "exported" | "ineligible" | "not_found";
  readonly reason: string;
}

export interface MissionBulkArchiveResult {
  readonly schemaVersion: "2.4";
  readonly selectionHash: string;
  readonly outcomes: readonly MissionBulkItemOutcome[];
  readonly archivedCount: number;
}

export interface MissionExportRecord {
  readonly missionId: string;
  readonly titlePreview: string;
  readonly titleSha256: string;
  readonly titleTruncated: boolean;
  readonly journey: Journey;
  readonly missionStatus: string;
  readonly authorizationStatus: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly engagement: { readonly present: boolean; readonly sha256: string | null };
  readonly scope: {
    readonly allowedTargetCount: number;
    readonly prohibitedTargetCount: number;
    readonly targetSetSha256: string;
  };
  readonly latestRun: {
    readonly id: string;
    readonly status: string;
    readonly progress: number;
    readonly phase: string | null;
    readonly ownerId: string | null;
    readonly startedAt: string | null;
    readonly endedAt: string | null;
  } | null;
  readonly evidenceCount: number;
  readonly findingCounts: Readonly<Record<string, number>>;
}

export interface MissionBulkExportResult {
  readonly schemaVersion: "2.4";
  readonly generatedAt: string;
  readonly selectionHash: string;
  readonly exportSha256: string;
  readonly records: readonly MissionExportRecord[];
  readonly outcomes: readonly MissionBulkItemOutcome[];
  readonly policy: {
    readonly maxBatch: number;
    readonly evidenceBlobsIncluded: false;
    readonly confidentialPayloadsIncluded: false;
    readonly titlePreviewLimit: number;
  };
}

export interface AttentionItem {
  readonly id: string;
  readonly type: string;
  readonly severity: string;
  readonly title: string;
  readonly summary: string;
  readonly missionId?: string;
  readonly runId?: string;
}

export interface AgentSummary {
  readonly id: string;
  readonly name: string;
  readonly status: string;
  readonly assignment?: string;
}

export interface OverviewSnapshot {
  readonly schemaVersion: "2.4";
  readonly readiness: ReadinessSummary;
  readonly summary: {
    readonly activeMissions: number;
    readonly activeAgents: number;
    readonly pendingDecisions: number;
    readonly recoveringRuns: number;
    readonly lastEventAt: string | null;
  };
  readonly missions: readonly MissionSummary[];
  readonly attention: readonly AttentionItem[];
  readonly agents: readonly AgentSummary[];
  readonly brain: {
    readonly confirmed: number;
    /** Canonical graph nodes whose lifecycle is still candidate. */
    readonly candidateNodes: number;
    /** Pending proposals that can actually be reviewed in the Memory Inbox. */
    readonly pendingReviews: number;
    /** @deprecated Compatibility alias for pendingReviews. */
    readonly candidates: number;
    readonly stale: number;
    readonly conflicts: number;
    readonly vaultStatus: string;
  };
  readonly system: {
    readonly database: string;
    readonly eventStream: string;
    readonly providers: string;
    readonly mcp: string;
  };
}

export interface MissionListPage {
  readonly schemaVersion: "2.4";
  readonly items: readonly MissionSummary[];
  readonly nextCursor: string | null;
}

export interface ApiErrorEnvelope {
  readonly code: string;
  readonly message: string;
  readonly humanMessage: string;
  readonly retryable: boolean;
  readonly category: string;
  readonly details?: JsonValue;
  readonly traceId: string;
  readonly remediation?: string;
  readonly timestamp: string;
}

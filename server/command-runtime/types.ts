import type { JsonValue } from "../events";
import type { GuidedReconnaissanceSelection } from "../missions/GuidedReconnaissance";
import type { GuidedMissionRequest } from "../missions";
import type { PlanningContextAttribution } from "../memory";
import type {
  BrainContextService,
  BrainLocalContextEnvelope,
  BrainProviderContextEnvelope,
} from "../brain-runtime";
import type {
  DurableAction,
  DurableActionKind,
  ExecutionPort,
  RunLeaseToken,
} from "../orchestration";
import type {
  FailureCategory,
  FailureSignal,
  Journey,
  ProgressSnapshot,
  RetryPolicyConfig,
  RunState,
} from "../supervisor";
import type { CanonicalReportArtifactCommitment } from "../reports";
import type { ResearchSourceItem } from "../research/LlmExposurePolicy";

export interface PlanningMission {
  readonly id: string;
  /** Canonical operator identity used to scope lifecycle preference resolution. */
  readonly createdBy: string;
  readonly name: string;
  readonly objective: string;
  readonly journey: Journey;
  readonly engagementId: string | null;
  readonly authorizationStatus: "unverified" | "verified" | "expired" | "revoked";
  readonly allowedTargets: readonly string[];
  readonly prohibitedTargets: readonly string[];
  readonly successCriteria: readonly string[];
  readonly memoryPolicy: Readonly<Record<string, unknown>>;
  /** Guided intake preference. Missing legacy records fail closed to manual-only. */
  readonly executionPreference?: "manual" | "single_step_agent";
  /** Optional persisted first Guided reconnaissance step. Missing preserves legacy target routing. */
  readonly guidedReconnaissance?: GuidedReconnaissanceSelection;
  /** Optional persisted reviewed Windows/identity first-step intent. */
  readonly guidedWindowsIdentity?: GuidedMissionRequest["guidedWindowsIdentity"];
  /** Optional persisted pinned local ExploitDB first-step intent. */
  readonly guidedLocalExploitIntelligence?:
    GuidedMissionRequest["guidedLocalExploitIntelligence"];
}

export interface PlanningRun {
  readonly id: string;
  readonly missionId: string;
  readonly journey: Journey;
  readonly state: RunState;
  readonly replanCount: number;
  readonly currentPlanVersion: number | null;
  readonly previousStrategySummary: string | null;
  readonly stateReason: string;
}

export type PlannedActionKind = DurableActionKind;

/** One represented action. Guided decisions bind to every field in this shape. */
export interface PlannedAction {
  /** For Autonomous, this value must be an allowed action class in the signed contract. */
  readonly actionType: string;
  readonly actionClass: string;
  readonly target: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly intentSummary: string;
  readonly kind: PlannedActionKind;
  readonly idempotent: boolean;
  readonly destructive: boolean;
}

/**
 * Immutable execution-model receipt added only by the trusted runtime after
 * provider output has passed schema validation. Provider planners cannot
 * supply or alter this structure.
 */
export interface RuntimeModelBindingReceipt {
  readonly schemaVersion: "ti-scale.runtime-model-binding.v1";
  readonly agentId: string;
  readonly modelAssignmentId: string;
  readonly modelConfigurationId: string;
  /** Canonical hash of the exact immutable assignment configuration snapshot. */
  readonly modelConfigurationHash: string;
  /** Separate provider request/readiness configuration hash for the selected route. */
  readonly providerConfigurationHash: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly reasoningEffort: string | null;
}

export interface PlannedStep {
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly explanation: string;
  readonly rationale: string;
  readonly successCriteria: readonly string[];
  /** Zero-based ordinals of prerequisite steps in this same plan. */
  readonly dependencyOrdinals?: readonly number[];
  readonly assignedAgentId: string;
  readonly riskClass: "low" | "medium" | "high" | "critical";
  readonly reversibility: string;
  readonly action: PlannedAction;
  /** Runtime-only exact launch-pinned model authority. */
  readonly runtimeModelBinding?: RuntimeModelBindingReceipt;
}

export interface MissionPlanDraft {
  readonly strategySummary: string;
  readonly rationaleSummary: string;
  readonly steps: readonly PlannedStep[];
  /** Runtime-only exact provider usage; never part of the provider JSON schema. */
  readonly providerUsage?: ProviderUsageReport;
  /** Runtime-only citations committed only with lease-fenced plan activation. */
  readonly planningAttribution?: PlanningContextAttribution;
}

/** Exact usage as reported by the provider. Values are never estimated. */
export interface ProviderUsageReport {
  readonly providerTurnId?: string;
  /** Number of provider turns represented by this aggregate usage report. */
  readonly providerTurns?: number;
  /** Provider selected before dispatch. It must match the canonical provider turn. */
  readonly providerId?: string;
  /** Model requested in the exact audited outbound body. */
  readonly requestedModel?: string;
  /** Model identifier returned by the provider; kept separate from the requested model. */
  readonly returnedModel?: string;
  /** Exact prompt/input tokens reported for the canonical provider turn. */
  readonly inputTokens?: number;
  /** Exact completion/output tokens reported for the canonical provider turn. */
  readonly outputTokens?: number;
  /** Canonical total reported by the provider. */
  readonly totalTokens?: number;
  /** @deprecated Compatibility alias for totalTokens. */
  readonly providerTokens?: number;
  /** Exact amount billed by the provider in USD. */
  readonly billedCostUsd?: number;
  /** @deprecated Compatibility alias for billedCostUsd. */
  readonly estimatedCost?: number;
  readonly exactTokenUsage: boolean;
  readonly exactCostUsage: boolean;
  /** Adapter-measured provider latency, when available. */
  readonly latencyMs?: number;
}

export interface MissionPlanPortResult {
  readonly plan: MissionPlanDraft;
  readonly usage?: ProviderUsageReport;
}

export interface MissionPlannerInput {
  readonly mission: PlanningMission;
  readonly run: PlanningRun;
  readonly rejectionReason?: string;
  /**
   * Provider planners receive public-disclosure-approved context. Trusted
   * local deterministic planners receive scope-safe local context that may
   * include private confirmed preferences but remains sanitized/untrusted.
   */
  readonly brainContext: BrainProviderContextEnvelope | BrainLocalContextEnvelope;
}

/**
 * Explicit opt-in to the public-provider disclosure boundary.
 *
 * A declared public provider is never called until the runtime has persisted
 * a canonical provider turn and a matching, sanitized exposure receipt.
 * Production local planners instead expose the separately validated exact
 * local deterministic boundary; a bare undeclared planner is compatibility or
 * test-only and cannot satisfy the production composition gate.
 */
export interface MissionPlannerProviderBoundary {
  readonly kind: "public_provider";
  /** Canonical product agent whose run-pinned model authorizes this turn. */
  readonly agentId?: string;
  readonly providerId: string;
  readonly modelId: string;
  /** Hash of the immutable model/request configuration pinned before this run. */
  readonly modelConfigurationHash: string;
}

/** Provider-neutral planning boundary. It must return real, bounded work—not fixtures. */
export interface MissionPlannerPort {
  readonly providerBoundary?: MissionPlannerProviderBoundary;
  plan(
    input: MissionPlannerInput,
    signal: AbortSignal,
  ): Promise<MissionPlanDraft | MissionPlanPortResult>;
}

export interface CompletionCriterion {
  readonly criterion: string;
  /**
   * Explicit Autonomous result. `satisfied` remains the compatibility view
   * and is true only for `achieved`; not-applicable is never presented as a
   * proven outcome.
   */
  readonly outcome?: "achieved" | "not_achieved" | "not_applicable";
  readonly satisfied: boolean;
  readonly explanation: string;
  readonly evidenceIds: readonly string[];
}

export interface MissionCompletionEvaluation {
  readonly success: boolean;
  readonly summary: string;
  readonly criteria: readonly CompletionCriterion[];
  /** Runtime-only exact provider usage; never inferred from response text. */
  readonly providerUsage?: ProviderUsageReport;
}

export interface MissionCompletionPortResult {
  readonly evaluation: MissionCompletionEvaluation;
  readonly usage?: ProviderUsageReport;
}

export interface MissionOutcomeEvaluatorInput {
  readonly mission: PlanningMission;
  readonly run: PlanningRun;
  readonly planId: string;
  readonly completedActionIds: readonly string[];
  /** Sanitized, explicitly disclosure-approved summaries only. */
  readonly brainContext: BrainProviderContextEnvelope;
}

/** Success is never inferred from terminal provider text alone. */
export interface MissionOutcomeEvaluatorPort {
  evaluate(
    input: MissionOutcomeEvaluatorInput,
    signal: AbortSignal,
  ): Promise<MissionCompletionEvaluation | MissionCompletionPortResult>;
}

export interface ExecutionResult {
  readonly actionId: string;
  readonly runId: string;
  readonly actionFingerprint: string;
  readonly success: boolean;
  readonly summary: string;
  readonly progress: ProgressSnapshot;
  readonly failure?: FailureSignal;
  readonly failureCategory?: FailureCategory;
  /** Provider Retry-After converted to milliseconds, when explicitly reported. */
  readonly retryAfterMs?: number;
  readonly usage?: {
    readonly wallClockMs?: number;
    readonly providerTokens?: number;
    readonly estimatedCost?: number;
    readonly evidenceBytes?: number;
    readonly artifactBytes?: number;
  };
  readonly circuitKey?: string;
  /** Authenticated envelope emitted only by a trusted local reset-controller adapter. */
  readonly operationalResetResult?: Readonly<Record<string, unknown>>;
}

export interface ExecutionResultReceipt {
  readonly accepted: boolean;
  readonly duplicate: boolean;
  readonly actionId: string;
  readonly runId: string;
  readonly runState: RunState;
  readonly nextAction: string | null;
  /** Canonical retained evidence made available to evaluation by this result. */
  readonly evidenceIds?: readonly string[];
}

export interface ExecutionResultSink {
  acceptExecutionResult(result: ExecutionResult): Promise<ExecutionResultReceipt>;
}

/**
 * Existing provider runtimes can implement ExecutionPort and invoke the bound
 * sink from their asynchronous terminal callback. `dispatch` still means
 * accepted, not completed.
 */
export interface ResultAwareExecutionPort extends ExecutionPort {
  bindResultSink?(sink: ExecutionResultSink): void | (() => void);
  /**
   * Redeliver terminal execution results that were durably committed by an
   * execution boundary but not yet acknowledged by this runtime. Implementors
   * must make replay correlation-safe and leave terminal provider/tool truth
   * unchanged when delivery fails.
   */
  replayPendingResults?(limit?: number): Promise<number>;
}

/**
 * Narrow execution boundary for a reviewed local target/environment reset
 * controller. Generic provider, MCP, and process adapters must never claim
 * this contract. The controller still cannot create a valid completion unless
 * it owns the separate server-side attestation capability.
 */
export interface TrustedOperationalResetExecutionPort extends ResultAwareExecutionPort {
  readonly operationalResetControllerContract: Readonly<{
    schemaVersion: "ti_scale.trusted-operational-reset-execution.v1";
    controllerId: string;
    localControlPlane: true;
    genericToolDispatch: false;
    authenticatedCompletion: "server_hmac";
  }>;
}

export interface RuntimeLifecycleResult {
  readonly recoveredRuns: number;
  readonly scheduledRuns: number;
}

/**
 * Optimistic boundary carried by every operator-initiated resume.
 *
 * The checkpoint fields identify the exact durable state the operator
 * inspected. `expectedRunStatus` is intentionally a literal: resuming is not
 * a generic transition out of any stopped-looking state.
 */
export interface ResumeRunBoundary {
  readonly expectedRunVersion: number;
  readonly expectedRunStatus: "blocked";
  readonly expectedCheckpointId: string;
  readonly expectedCheckpointStateHash: string;
  readonly expectedCheckpointEventSequence: number;
}

/**
 * Structural closeout boundary supplied by the Autonomous composition root.
 * It owns the outer transaction so database terminal state and filesystem
 * report materialization either commit together or are compensated together.
 */
export interface MissionTerminalDeliverablePort {
  completeAtomically<T>(
    runId: string,
    commitTerminal: (reportCommitment: CanonicalReportArtifactCommitment | null) => T,
  ): { readonly terminal: T; readonly deliverables: unknown };
}

export type AutonomousActivationLifecycleBindingType =
  | "planning"
  | "plan_version"
  | "dispatch"
  | "resume"
  | "restart_recovery";

export interface AutonomousActivationBoundaryReceipt {
  readonly receiptId: string;
  readonly receiptHash: string;
  readonly runtimeGenerationHash: string;
  /** Hash of the exact evidence requirements signed into this receipt. */
  readonly evidencePolicyHash: string;
  readonly expiresAt: string;
  /**
   * Minimal verified route projection used to build provider-advisory
   * candidates. Execution/tool identities remain local; only the evidence
   * requirements are eligible for the opaque candidate catalog.
   */
  readonly items: readonly Readonly<{
    actionClassId: string;
    evidenceTypeIds: readonly string[];
  }>[];
  readonly planning:
    | {
        readonly route: "local_deterministic";
        readonly plannerId: string;
      }
    | {
        readonly route: "provider_advisory";
        readonly plannerId: string;
        readonly modelAssignmentId: string;
        readonly primaryConfigurationId: string;
        readonly fallbackConfigurationId: string | null;
        readonly primaryConfigurationHash: string;
        readonly fallbackConfigurationHash: string | null;
      };
}

/**
 * Narrow disclosure adapter used only after a local Autonomous plan has been
 * compiled and bound. It returns policy-filtered source items; the advisory
 * runtime remains the sole owner of provider envelopes and exposure receipts.
 */
export interface AutonomousProviderPlanningContextPort {
  prepare(input: Readonly<{
    missionId: string;
    runId: string;
    contextPackId: string;
    retrievedByActorId: string;
    actorId: string;
    disclosureClass: "public_only" | "sanitized_internal";
    opaqueTerms?: readonly string[];
    maximumItems?: number;
    maximumBytes?: number;
  }>): Readonly<{
    items: readonly ResearchSourceItem[];
    telemetry: Readonly<{
      inputFingerprint: string;
      outputHash: string;
    }>;
  }>;
}

/**
 * Production-only local-first planning route. `localPlanner` remains the
 * executable plan compiler; the optional provider can reorder only the finite
 * locally materialized catalog selected by a signed per-run receipt.
 */
export interface AutonomousPlanningRuntimePorts {
  readonly providerAdvisory?: import("../autonomous-planning").ProviderAdvisoryRuntimePort;
  readonly providerContext?: AutonomousProviderPlanningContextPort;
}

/**
 * Narrow, synchronous fail-closed boundary owned by the trusted Autonomous
 * composition root. Compatibility and Guided runtimes may omit it; a
 * production Autonomous runtime always supplies it.
 */
export interface AutonomousActivationRuntimePort {
  ensureIssued(input: Readonly<{
    missionId: string;
    runId: string;
    brainContextPackId: string;
    issuedBy: string;
  }>): AutonomousActivationBoundaryReceipt;
  verifyCurrent(input: Readonly<{
    runId: string;
  }>): AutonomousActivationBoundaryReceipt;
  verifyAndBind(input: Readonly<{
    runId: string;
    bindingType: AutonomousActivationLifecycleBindingType;
    subjectId: string;
    subjectDigest: string;
    planId?: string | null;
    stepId?: string | null;
    actionId?: string | null;
    contextPackId?: string | null;
    providerTurnId?: string | null;
    boundBy: string;
  }>): AutonomousActivationBoundaryReceipt;
}

export interface MissionRuntimeOptions {
  readonly database: import("../db").SqliteDatabase;
  /** Server-only key used to preauthorize and authenticate physical reset receipts. */
  readonly operationalHazardHmacKey?: string | Buffer;
  readonly planner: MissionPlannerPort;
  readonly outcomeEvaluator: MissionOutcomeEvaluatorPort;
  readonly execution: ResultAwareExecutionPort;
  /**
   * Required by production Autonomous composition. It binds the signed
   * contract to one exact, expiring runtime generation before any planner,
   * provider, or execution adapter is contacted.
   */
  readonly autonomousActivation?: AutonomousActivationRuntimePort;
  /**
   * Optional provider-advisory route. Autonomous runs select it per signed
   * activation receipt; absence never changes the static planner interface.
   */
  readonly autonomousPlanning?: AutonomousPlanningRuntimePorts;
  /**
   * Required by production Autonomous composition. Compatibility runtimes
   * without this service cannot claim exact per-agent model enforcement.
   */
  readonly agentRuntimeBindings?: import("../agent-runtime").AgentRuntimeBindingService;
  /** Optional reviewed local reset path. Without it every reset action fails before dispatch. */
  readonly trustedOperationalResetExecution?: TrustedOperationalResetExecutionPort;
  /** Injectable for availability/fault policies; defaults to the local V2 Brain. */
  readonly brainContext?: BrainContextService;
  /** Optional failure-isolated post-commit projection into configured Vaults. */
  readonly projectMemoryNodes?: (nodeIds: readonly string[]) => void;
  /** Autonomous-only atomic findings/report closeout; Guided remains unchanged. */
  readonly autonomousTerminalDeliverables?: MissionTerminalDeliverablePort;
  readonly workerId?: string;
  readonly scanIntervalMs?: number;
  readonly leaseTtlMs?: number;
  readonly decisionTtlMs?: number;
  readonly maxPlanSteps?: number;
  /** Journeys this concrete runtime process may claim or mutate. Defaults to both. */
  readonly supportedJourneys?: readonly Journey[];
  /** Shared bounded retry policy; defaults to two transient retries. */
  readonly retryPolicy?: Partial<RetryPolicyConfig>;
  /** Injectable entropy source for deterministic retry timing tests. */
  readonly retryRandom?: () => number;
  readonly now?: () => Date;
  /** Test-only fault injection immediately after a durable predecessor commit. */
  readonly crashAfterCommit?: (
    point:
      | "plan_ready_to_dispatch"
      | "planning_retry_scheduled"
      | "planning_retry_started"
      | "action_reserved_before_dispatch"
      | "guided_approval_to_dispatch"
      | "action_result_to_advance"
      | "manual_result_to_advance"
      | "guided_failure_to_recover"
      | "step_advance_to_evaluation"
      | "cancellation_cleanup_before_finalize"
      | "cancellation_terminal_before_runtime_cleanup"
      | "pause_projection_committed"
      | "resume_projection_committed",
    context: Readonly<{ runId: string; sourceId?: string }>,
  ) => void;
}

export interface StoredPlanStep {
  readonly id: string;
  readonly ordinal: number;
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly status: string;
  readonly assignedAgentId: string;
  readonly riskClass: string;
  readonly successCriteria: readonly string[];
  /** Stable IDs of prerequisite steps in this exact immutable plan version. */
  readonly dependencyStepIds: readonly string[];
  readonly action: PlannedAction;
  readonly explanation: string;
  readonly rationale: string;
  readonly reversibility: string;
}

export interface StoredPlan {
  readonly id: string;
  readonly runId: string;
  readonly version: number;
  readonly status: string;
  readonly strategySummary: string;
  readonly rationaleSummary: string | null;
  readonly createdAt: string;
  readonly activatedAt: string | null;
  readonly steps: readonly StoredPlanStep[];
}

export interface GuidedDecisionProjection {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly stepId: string;
  readonly status: string;
  readonly actionFingerprint: string;
  readonly requestedParameters: JsonValue;
  readonly rationale: string;
  readonly riskClass: string;
  readonly reversibility: string;
  readonly expiresAt: string;
  readonly createdAt: string;
}

export interface GuidedDecisionSkipResult {
  readonly decisionId: string;
  readonly status: "cancelled";
  readonly skippedStepId: string;
  readonly nextDecisionId: string | null;
  readonly runId: string;
  readonly runState: RunState;
  readonly nextAction: string | null;
  readonly duplicate: boolean;
}

export interface RuntimeActionContext {
  readonly action: DurableAction;
  lease: RunLeaseToken;
  readonly before: ProgressSnapshot;
  heartbeat?: ReturnType<typeof setInterval>;
  completing: boolean;
}

export class CommandRuntimeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly options: {
      readonly humanMessage?: string;
      readonly retryable?: boolean;
      readonly category?: string;
      readonly details?: JsonValue;
      readonly remediation?: string;
    } = {},
  ) {
    super(message);
    this.name = "CommandRuntimeError";
  }
}

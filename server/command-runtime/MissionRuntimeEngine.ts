import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import {
  ACTION_CLASS_DEFINITIONS,
  isActionClassId,
  isEvidenceTypeId,
  type ActionClassId,
  type EvidenceTypeId,
} from "../domain";
import type { JsonValue } from "../events";
import {
  ControlPlaneLeaseError,
  ControlPlaneLeaseService,
  RunMutationAuthorityGuard,
  type ControlPlaneLease,
} from "../control-plane";
import {
  ActionRepository,
  CheckpointRepository,
  DurableOrchestrationError,
  DurableRunCoordinator,
  ExecutionBoundaryError,
  type DurableActionFailureContext,
  type DurableAction,
  type GuidedCancellationBoundary,
  type RunLeaseToken,
} from "../orchestration";
import { redactSecrets } from "../contracts/redaction";
import { RunRepository } from "../orchestration";
import { canonicalJson } from "../orchestration/serialization";
import { RunLearningService, canonicalLessonMemoryNodeId } from "../learning";
import type { CanonicalReportArtifactCommitment } from "../reports";
import { FailureDiagnosisRepository } from "../intelligence-v24/FailureDiagnosisRepository";
import { FailureDiagnosisService } from "../intelligence-v24/FailureDiagnosisService";
import {
  AgentToolMemoryDecisionRepository,
  compileAgentToolMemoryDecision,
  runtimeCapabilityMemoryNodeId,
  type AgentToolMemoryDecisionReceipt,
  type AgentToolMemoryHook,
} from "../agent-tool-memory";
import {
  compileAutonomousRecoveryMemory,
  type CompiledAutonomousRecoveryMemory,
} from "../recovery-memory";
import type {
  FailureCategory as OperationalFailureCategory,
  FailureOperatorAction,
} from "../intelligence-v24/types";
import {
  MemoryRepository,
  OperationalHazardHealthGateError,
  OperationalHazardHealthGateService,
  OperationalHazardLocalResetEvaluator,
  OperationalResetHealthEvidenceRecorder,
  OperationalResetControlReceiptIssuer,
  OperationalHazardMatcher,
  OperationalHazardRuntimeRecoveryProducer,
  SecondBrainService,
  isAttackCentricReusableNodeType,
  type AttackAttemptKnowledgeContext,
  type OperationalHazardAssessment,
} from "../memory";
import {
  BrainContextService,
  BrainContextHookError,
  CanonicalMissionMemoryGraph,
  retrieveMissionBrainContext,
  selectRelevantPhaseTransitionMemory,
  type BrainContextResult,
  type BrainLifecycleHook,
  type BrainProviderContextEnvelope,
  type LifecyclePreferenceNodeIds,
  type PhaseTransitionSemanticSignal,
} from "../brain-runtime";
import {
  classifyFailure,
  FAILURE_CATEGORIES,
  fingerprintAction,
  isRetryableCategory,
  isTerminalRunState,
  RunSupervisor,
  transitionRun as transitionSupervisedRun,
  type FailureCategory,
  type ProgressSnapshot,
  type RunState,
} from "../supervisor";
import { RuntimeRepository } from "./RuntimeRepository";
import { hashCanonical } from "../missions/canonical";
import { commitPlanningContextAttribution } from "./PlanningContextAttribution";
import {
  RuntimeContinuationRepository,
  type RuntimeContinuation,
  type RuntimeContinuationKind,
} from "./RuntimeContinuationRepository";
import type {
  ExecutionResult,
  ExecutionResultReceipt,
  ExecutionResultSink,
  GuidedDecisionProjection,
  GuidedDecisionSkipResult,
  MissionCompletionEvaluation,
  MissionCompletionPortResult,
  MissionPlanDraft,
  MissionPlanPortResult,
  MissionPlannerInput,
  MissionRuntimeOptions,
  AutonomousActivationRuntimePort,
  ProviderUsageReport,
  ResultAwareExecutionPort,
  ResumeRunBoundary,
  RuntimeActionContext,
  RuntimeLifecycleResult,
  TrustedOperationalResetExecutionPort,
} from "./types";
import { CommandRuntimeError } from "./types";
import { validateExecutionResultSummary, validateMissionPlanDraft, validateReason } from "./validation";
import type { PlanChangeAffectedWorkStopReceipt } from "../plan-changes/types";
import {
  AgentRuntimeBindingError,
  type AgentRuntimeBindingService,
} from "../agent-runtime";
import {
  ModelConfigurationRepository,
  modelConfigurationBindingHash,
  type AutonomousPlanningSelection,
} from "../model-config";
import {
  agentAssignmentBindsRuntimeAgent,
  type ProductAgentId,
} from "../agents";
import { resolveOpenRouterModelConfiguration } from "../providers/openrouter";
import type { RuntimeModelBindingReceipt } from "./types";
import {
  buildProviderAdvisoryCandidateCatalog,
  ProviderAdvisoryPlanningError,
  SignedAutonomousPlanningRoutePort,
  type BuildProviderAdvisoryCatalogInput,
  type ProviderAdvisoryResolvedPlanningBinding,
  type ProviderAdvisoryRuntimeSafeStop,
} from "../autonomous-planning";

interface HeartbeatLease {
  token(): Promise<RunLeaseToken>;
  stop(): Promise<RunLeaseToken>;
}

type GuidedStopContext = GuidedCancellationBoundary;

interface PlanningProviderTurn {
  readonly id: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly startedAt: number;
  readonly runtimeModelBinding?: RuntimeModelBindingReceipt;
}

interface AutonomousPlanningPolicyProjection {
  readonly contractHash: string;
  readonly selection: AutonomousPlanningSelection;
  readonly allowedActionClassIds: readonly ActionClassId[];
  readonly prohibitedActionClassIds: readonly ActionClassId[];
  readonly specialistAgentIds: readonly string[];
}

const ACTION_CLASS_DEFINITION_BY_ID = new Map(
  ACTION_CLASS_DEFINITIONS.map((definition) => [definition.id, definition]),
);

class RuntimeCrashAfterCommit extends Error {
  constructor(readonly point: string) {
    super(`Injected process crash after durable commit: ${point}`);
    this.name = "RuntimeCrashAfterCommit";
  }
}

function isOperationalResetAction(action: Pick<DurableAction, "actionType">): boolean {
  return action.actionType === "target_reset" || action.actionType === "environment_reset";
}

/**
 * Keeps physical reset dispatch out of every generic execution adapter. A
 * configured reviewed controller receives reset actions exclusively; absent
 * that controller, dispatch and restart/resume both fail closed.
 */
class RuntimeExecutionRouter implements ResultAwareExecutionPort {
  constructor(
    private readonly generic: ResultAwareExecutionPort,
    private readonly reset?: TrustedOperationalResetExecutionPort,
    private readonly database?: SqliteDatabase,
    private readonly agentRuntimeBindings?: AgentRuntimeBindingService,
    private readonly autonomousActivation?: AutonomousActivationRuntimePort,
    private readonly activationActorId = "command-runtime.execution-boundary",
  ) {
    if (reset) {
      const contract = reset.operationalResetControllerContract;
      if (
        contract.schemaVersion !== "ti_scale.trusted-operational-reset-execution.v1"
        || !/^[A-Za-z0-9._:@/-]{1,300}$/u.test(contract.controllerId)
        || contract.localControlPlane !== true
        || contract.genericToolDispatch !== false
        || contract.authenticatedCompletion !== "server_hmac"
      ) {
        throw new TypeError("Trusted operational-reset execution contract is invalid");
      }
    }
  }

  private assertRuntimeModelBinding(action: DurableAction): void {
    if (!this.agentRuntimeBindings || !this.database) return;
    const run = this.database.prepare(`
      SELECT journey FROM runs WHERE id = ?
    `).get(action.runId) as { journey: string } | undefined;
    if (run?.journey !== "autonomous") return;
    const expected = action.runtimeModelBinding;
    if (!expected) {
      throw new ExecutionBoundaryError(
        "autonomous_runtime_model_binding_missing",
        "policy_denied",
        "The Autonomous action has no immutable launch-pinned model binding.",
      );
    }
    let resolved;
    try {
      resolved = this.agentRuntimeBindings.resolve({
        missionId: action.missionId,
        runId: action.runId,
        stepId: action.stepId,
      });
    } catch (error) {
      throw new ExecutionBoundaryError(
        error instanceof AgentRuntimeBindingError
          ? error.code
          : "autonomous_runtime_model_binding_unavailable",
        "policy_denied",
        error instanceof Error
          ? error.message
          : "The exact Autonomous model binding could not be resolved.",
      );
    }
    const primary = resolved.primaryConfiguration;
    if (
      expected.schemaVersion !== "ti-scale.runtime-model-binding.v1"
      || expected.agentId !== resolved.productAgentId
      || expected.modelAssignmentId !== resolved.modelAssignmentId
      || expected.modelConfigurationId !== resolved.primaryConfigurationId
      || expected.providerId !== primary.providerId
      || expected.modelId !== primary.modelId
      || expected.reasoningEffort !== primary.reasoningEffort
      || expected.modelConfigurationHash
        !== modelConfigurationBindingHash(primary)
      || !/^[a-f0-9]{64}$/u.test(expected.providerConfigurationHash)
    ) {
      throw new ExecutionBoundaryError(
        "autonomous_runtime_model_binding_mismatch",
        "policy_denied",
        "The persisted action model receipt no longer matches its exact pinned assignment.",
      );
    }
  }

  private bindAutonomousActivation(
    action: DurableAction,
    bindingType: "dispatch" | "resume",
  ): void {
    if (!this.autonomousActivation || !this.database) return;
    const run = this.database.prepare(`
      SELECT journey FROM runs WHERE id = ?
    `).get(action.runId) as { journey: string } | undefined;
    if (run?.journey !== "autonomous") return;
    const step = this.database.prepare(`
      SELECT plan_id FROM plan_steps WHERE id = ? AND run_id = ?
    `).get(action.stepId, action.runId) as { plan_id: string } | undefined;
    if (!step) {
      throw new ExecutionBoundaryError(
        "autonomous_activation_step_lineage_missing",
        "policy_denied",
        "The Autonomous action is not joined to one current plan step.",
      );
    }
    try {
      this.autonomousActivation.verifyAndBind({
        runId: action.runId,
        bindingType,
        subjectId: action.id,
        subjectDigest: action.fingerprint,
        planId: step.plan_id,
        stepId: action.stepId,
        actionId: action.id,
        ...(action.contextPackId ? { contextPackId: action.contextPackId } : {}),
        boundBy: this.activationActorId,
      });
    } catch (error) {
      if (error instanceof CommandRuntimeError) {
        const category = FAILURE_CATEGORIES.includes(
          error.options.category as FailureCategory,
        )
          ? error.options.category as FailureCategory
          : "policy_denied";
        throw new ExecutionBoundaryError(
          error.code,
          category,
          error.options.humanMessage ?? error.message,
        );
      }
      throw new ExecutionBoundaryError(
        "autonomous_activation_boundary_unavailable",
        "dependency_missing",
        error instanceof Error
          ? error.message
          : "The Autonomous activation boundary could not be verified.",
      );
    }
  }

  bindResultSink(sink: ExecutionResultSink): () => void {
    const unbindGeneric = this.generic.bindResultSink?.(sink);
    let unbindReset: void | (() => void);
    try {
      unbindReset = this.reset?.bindResultSink?.(sink);
    } catch (error) {
      unbindGeneric?.();
      throw error;
    }
    return () => {
      unbindReset?.();
      unbindGeneric?.();
    };
  }

  dispatch(action: DurableAction, signal: AbortSignal): Promise<void> {
    this.assertRuntimeModelBinding(action);
    this.bindAutonomousActivation(action, "dispatch");
    if (isOperationalResetAction(action)) {
      if (!this.reset) {
        throw new ExecutionBoundaryError(
          "trusted_reset_controller_unavailable",
          "dependency_missing",
          "No reviewed local reset controller is configured for this action.",
        );
      }
      return this.reset.dispatch(action, signal);
    }
    return this.generic.dispatch(action, signal);
  }

  resume(action: DurableAction, signal: AbortSignal): Promise<void> {
    this.assertRuntimeModelBinding(action);
    this.bindAutonomousActivation(action, "resume");
    if (isOperationalResetAction(action)) {
      if (!this.reset) {
        throw new ExecutionBoundaryError(
          "trusted_reset_controller_unavailable",
          "dependency_missing",
          "No reviewed local reset controller is configured to resume this action.",
        );
      }
      return this.reset.resume(action, signal);
    }
    return this.generic.resume(action, signal);
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    const results = await Promise.allSettled([
      this.generic.cancelRun(runId, reason),
      ...(this.reset && this.reset !== this.generic
        ? [this.reset.cancelRun(runId, reason)]
        : []),
    ]);
    const rejected = results.find((result): result is PromiseRejectedResult => result.status === "rejected");
    if (rejected) throw rejected.reason;
  }

  async replayPendingResults(limit = 100): Promise<number> {
    const [generic, reset] = await Promise.all([
      this.generic.replayPendingResults?.(limit) ?? 0,
      this.reset?.replayPendingResults?.(limit) ?? 0,
    ]);
    return generic + reset;
  }
}

function planResult(value: MissionPlanDraft | MissionPlanPortResult): MissionPlanPortResult {
  return "plan" in value ? value : { plan: value, usage: value.providerUsage };
}

function canonicalZeroProviderUsage(
  usage: ProviderUsageReport | undefined,
): boolean {
  if (!usage) return true;
  return usage.providerTurnId === undefined
    && usage.providerId === undefined
    && usage.requestedModel === undefined
    && usage.returnedModel === undefined
    && usage.providerTurns === 0
    && usage.inputTokens === 0
    && usage.outputTokens === 0
    && usage.totalTokens === 0
    && (usage.providerTokens === undefined || usage.providerTokens === 0)
    && usage.billedCostUsd === 0
    && (usage.estimatedCost === undefined || usage.estimatedCost === 0)
    && usage.exactTokenUsage === true
    && usage.exactCostUsage === true
    && (usage.latencyMs === undefined || usage.latencyMs === 0);
}

function completionResult(
  value: MissionCompletionEvaluation | MissionCompletionPortResult,
): MissionCompletionPortResult {
  return "evaluation" in value ? value : { evaluation: value, usage: value.providerUsage };
}

function errorRecord(error: unknown): Readonly<Record<string, unknown>> {
  return error && typeof error === "object" ? error as Readonly<Record<string, unknown>> : {};
}

function nestedResponseRecord(error: unknown): Readonly<Record<string, unknown>> {
  const response = errorRecord(error).response;
  return response && typeof response === "object" && !Array.isArray(response)
    ? response as Readonly<Record<string, unknown>>
    : {};
}

function planningHttpStatus(error: unknown): number | undefined {
  const item = errorRecord(error);
  const response = nestedResponseRecord(error);
  const value = item.status ?? item.statusCode ?? response.status ?? response.statusCode;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 100 && value <= 599) return value;
  if (error instanceof CommandRuntimeError && Number.isSafeInteger(error.status)) return error.status;
  return undefined;
}

function failureSignal(error: unknown): Parameters<typeof classifyFailure>[0] {
  const item = errorRecord(error);
  const status = planningHttpStatus(error);
  const message = error instanceof Error ? error.message : "";
  return {
    ...(typeof item.code === "string" ? { code: item.code } : error instanceof Error ? { code: error.name } : {}),
    ...(message ? { message } : {}),
    ...(status === undefined ? {} : { httpStatus: status }),
    source: /grok|provider|acp|oauth|rate.?limit|too many requests/i.test(message)
      || status === 429 || status === 502 || status === 503 || status === 504
      ? "provider"
      : "unknown",
  };
}

function planningFailureCategory(error: unknown, runtimeError: CommandRuntimeError): FailureCategory {
  const declared = runtimeError.options.category;
  if (declared && FAILURE_CATEGORIES.includes(declared as FailureCategory)) {
    return declared as FailureCategory;
  }
  return classifyFailure(failureSignal(error));
}

function planningProviderTurnErrorCategory(
  error: unknown,
  runtimeError: CommandRuntimeError,
): string {
  const details = runtimeError.options.details;
  if (details && typeof details === "object" && !Array.isArray(details)) {
    const advisoryCategory = details.providerAdvisoryCategory;
    if (
      typeof advisoryCategory === "string"
      && [
        "rate_limit",
        "timeout",
        "authentication_missing",
        "authentication_failed",
        "provider_unavailable",
        "provider_refused",
        "audit_unavailable",
        "cancelled",
      ].includes(advisoryCategory)
    ) {
      return advisoryCategory;
    }
  }
  return planningFailureCategory(error, runtimeError);
}

function numericRetryAfter(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function planningRetryAfterMs(error: unknown, now: Date): number | undefined {
  const item = errorRecord(error);
  const direct = numericRetryAfter(item.retryAfterMs);
  if (direct !== undefined) return direct;
  if (error instanceof CommandRuntimeError) {
    const details = error.options.details;
    if (details && typeof details === "object" && !Array.isArray(details)) {
      const fromDetails = numericRetryAfter(details.retryAfterMs);
      if (fromDetails !== undefined) return fromDetails;
    }
  }
  const headers = item.headers ?? nestedResponseRecord(error).headers;
  const raw = headers && typeof headers === "object" && "get" in headers
    && typeof (headers as { get?: unknown }).get === "function"
    ? (headers as { get(name: string): unknown }).get("retry-after")
    : undefined;
  if (typeof raw !== "string" || !raw.trim()) return undefined;
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.round(seconds * 1_000);
  const boundary = Date.parse(raw);
  return Number.isFinite(boundary) ? Math.max(0, boundary - now.getTime()) : undefined;
}

function asRuntimeError(error: unknown): CommandRuntimeError {
  if (error instanceof CommandRuntimeError) return error;
  if (error instanceof ProviderAdvisoryPlanningError) {
    const category: FailureCategory =
      error.category === "invalid_provider_response"
        ? "invalid_input"
        : error.category === "provider_unavailable"
          ? "provider_unavailable"
          : error.category === "cancelled"
            ? "provider_unavailable"
            : "policy_denied";
    return new CommandRuntimeError(
      error.category === "provider_unavailable" ? 503 : 409,
      error.code,
      error.message,
      {
        humanMessage: error.category === "disclosure_denied"
          ? "Safe-stopped before provider contact because the advisory disclosure boundary rejected the planned context."
          : error.message,
        retryable: error.category === "cancelled"
          ? false
          : error.retryable,
        category,
        remediation: error.category === "provider_unavailable"
          ? "Restore the exact signed advisor and begin a fresh bounded planning attempt."
          : "Correct the signed policy, local candidate catalog, or disclosure input; do not fall back to unsanctioned planning.",
      },
    );
  }
  if (error instanceof BrainContextHookError) {
    return new CommandRuntimeError(
      error.code === "brain_context_unavailable" ? 503 : 500,
      error.code,
      error.message,
      {
        humanMessage: error.code === "brain_context_unavailable"
          ? `Second Brain context required for ${error.hook.replaceAll("_", " ")} is unavailable, so the run stopped safely.`
          : `Second Brain context integrity failed during ${error.hook.replaceAll("_", " ")}, so execution did not continue.`,
        retryable: error.code === "brain_context_unavailable",
        category: "dependency_missing",
        details: {
          hook: error.hook,
          auditRecordId: error.auditRecordId ?? null,
        },
        remediation: "Restore the local Second Brain dependency or amend a future mission contract to permit declared degraded behavior; do not bypass the signed memory policy.",
      },
    );
  }
  if (error instanceof ControlPlaneLeaseError) {
    return new CommandRuntimeError(error.code === "run_not_found" ? 404 : 409, `control_plane_${error.code}`, error.message, {
      humanMessage: error.code === "control_plane_mismatch"
        ? "This run belongs to another control plane and Ti-Scale refused to mutate it."
        : "Ti-Scale could not prove exclusive mutation authority for this run.",
      retryable: error.retryable,
      category: error.code === "run_not_found" ? "not_found" : "conflict",
      remediation: error.retryable
        ? "Wait for the current fenced controller to release or expire, then resume from the durable checkpoint."
        : "Open the run through its owning control plane; do not attempt concurrent control.",
    });
  }
  if (error instanceof OperationalHazardHealthGateError) {
    const messages: Readonly<Record<string, { human: string; remediation: string }>> = {
      hazard_retry_authorization_expired: {
        human: "The one-use safer-attempt authorization expired before this action could be reserved.",
        remediation: "Run and verify a new represented health check, then issue a new one-use authorization for a newly represented safer attempt.",
      },
      hazard_health_assessment_expired: {
        human: "The health result is no longer fresh enough to authorize target contact.",
        remediation: "Repeat the represented health check and retain new locally verified evidence.",
      },
      hazard_retry_authorization_replayed: {
        human: "The one-use safer-attempt authorization has already been consumed and cannot dispatch another action.",
        remediation: "Review the first action result. If another attempt is justified, represent a new safer attempt and repeat the health gate.",
      },
      hazard_retry_cross_target_denied: {
        human: "The safer-attempt authorization does not belong to this exact target, environment, or run.",
        remediation: "Create a new health assessment and authorization inside this run's unchanged private target context.",
      },
      hazard_retry_authorization_required: {
        human: "This is a new attempt on the same target and action boundary as an unresolved verified failure. A new attempt ID does not make it safe.",
        remediation: "Complete the represented local health check, retain verified evidence, and authorize exactly one distinct safer procedure version or parameter set.",
      },
      hazard_retry_lineage_required: {
        human: "This reviewed procedure is a new version or explicit alternative of an unresolved failure on the same canonical target, but the new attempt does not identify that recovery source.",
        remediation: "Create the attempt again with the preserved blocked attempt as its immutable recovery source, then complete the health gate and one-use authorization.",
      },
      hazard_retry_source_not_active: {
        human: "The recovery authorization no longer matches the preserved failure state it was issued for.",
        remediation: "Reconcile the source attempt and create a fresh health assessment before authorizing a new safer attempt.",
      },
    };
    const explanation = messages[error.code] ?? {
      human: "The represented safer attempt did not satisfy its evidence-linked operational-hazard authorization.",
      remediation: "Inspect the persisted health assessment and represent one distinct, reviewed safer procedure before trying again.",
    };
    return new CommandRuntimeError(409, error.code, error.message, {
      humanMessage: explanation.human,
      retryable: false,
      category: error.category,
      remediation: explanation.remediation,
    });
  }
  if (error instanceof DurableOrchestrationError) {
    return new CommandRuntimeError(409, error.code, error.message, {
      humanMessage: error.message,
      category: error.code.includes("contract") || error.code.includes("decision")
        ? "policy_denied"
        : "runtime",
    });
  }
  const item = errorRecord(error);
  const category = typeof item.category === "string" && FAILURE_CATEGORIES.includes(item.category as FailureCategory)
    ? item.category as FailureCategory
    : classifyFailure(failureSignal(error));
  const declaredRetryable = typeof item.retryable === "boolean" ? item.retryable : undefined;
  const explanations: Record<FailureCategory, { humanMessage: string; remediation: string }> = {
    transient_network: {
      humanMessage: "The planning provider lost its network connection before it could produce a durable result.",
      remediation: "Restore network connectivity, then resume from the last checkpoint.",
    },
    rate_limit: {
      humanMessage: "The planning provider is rate-limited and no result was committed.",
      remediation: "Wait for the provider retry window, then resume the run.",
    },
    provider_unavailable: {
      humanMessage: "The planning provider or its enforced ACP boundary is unavailable.",
      remediation: "Check provider health and the Grok ACP boundary attestation before retrying.",
    },
    mcp_unavailable: {
      humanMessage: "A required MCP capability is unavailable.",
      remediation: "Restore the reviewed MCP server and rerun readiness before resuming.",
    },
    timeout: {
      humanMessage: "The planning operation exceeded its bounded timeout without committing a result.",
      remediation: "Check provider latency and resume only when the dependency is healthy.",
    },
    worker_lost: {
      humanMessage: "The assigned worker heartbeat expired before the operation completed.",
      remediation: "Inspect the last checkpoint and reassign or resume the bounded step.",
    },
    process_crash: {
      humanMessage: "The isolated planning process exited before completing.",
      remediation: "Check the provider process health and resume from the last checkpoint.",
    },
    invalid_input: {
      humanMessage: "The planning provider returned data that did not satisfy the mission contract.",
      remediation: "Inspect the validation event and amend the plan input before retrying.",
    },
    deterministic_tool_error: {
      humanMessage: "The represented tool action failed deterministically.",
      remediation: "Change the action or its validated parameters before retrying.",
    },
    authorization_denied: {
      humanMessage: "Execution stopped because authorization could not be verified.",
      remediation: "Review and confirm the exact authorized scope before creating a new run.",
    },
    policy_denied: {
      humanMessage: "Execution stopped because the requested operation is outside enforced policy.",
      remediation: "Choose an in-policy alternative or create a reviewed contract amendment.",
    },
    authentication_missing: {
      humanMessage: "The planning provider has no valid refreshable OAuth authentication state.",
      remediation: "Authenticate Grok for the service account and verify the protected OAuth file ownership and mode.",
    },
    dependency_missing: {
      humanMessage: "A required planning dependency is missing or does not satisfy the trusted-file boundary.",
      remediation: "Restore the root-controlled Grok binary and required boundary assets, then rerun readiness.",
    },
    scope_conflict: {
      humanMessage: "The requested operation conflicts with the authorized mission scope.",
      remediation: "Use an in-scope alternative; do not expand scope implicitly.",
    },
    evidence_insufficient: {
      humanMessage: "The run does not have enough verified evidence to support the requested conclusion.",
      remediation: "Collect one bounded evidence item or finish with an explicit inconclusive outcome.",
    },
    operator_rejection: {
      humanMessage: "The represented Guided action was rejected by the operator.",
      remediation: "Explain a materially different in-scope alternative and wait for a new decision.",
    },
    unknown: {
      humanMessage: "The runtime stopped safely because an unclassified planning failure occurred.",
      remediation: "Use the correlated provider turn and runtime event to diagnose the dependency before retrying.",
    },
  };
  const explanation = explanations[category];
  return new CommandRuntimeError(500, `mission_runtime_${category}`, "Mission runtime operation failed", {
    humanMessage: explanation.humanMessage,
    category,
    ...(declaredRetryable === undefined ? {} : { retryable: declaredRetryable }),
    remediation: explanation.remediation,
  });
}

function operationalFailureCategory(category: FailureCategory | undefined): OperationalFailureCategory {
  if (category === "authentication_missing") return "authentication_missing";
  if (category === "dependency_missing") return "dependency_missing";
  if (category === "mcp_unavailable") return "mcp_unavailable";
  if (category === "provider_unavailable" || category === "transient_network") return "provider_unavailable";
  if (category === "rate_limit") return "rate_limit";
  if (category === "timeout") return "timeout";
  if (category === "worker_lost") return "worker_lost";
  if (category === "scope_conflict" || category === "authorization_denied") return "scope_denied";
  if (category === "policy_denied") return "policy_denied";
  if (category === "evidence_insufficient") return "evidence_insufficient";
  if (category === "invalid_input") return "invalid_input";
  if (category === "deterministic_tool_error") return "deterministic_tool_error";
  if (category === "process_crash") return "restart_recovery_required";
  return "unknown";
}

function planningFailureOperatorActions(
  category: OperationalFailureCategory,
  retryable: boolean,
): readonly FailureOperatorAction[] {
  const actions: FailureOperatorAction[] = [];
  if (["provider_unavailable", "rate_limit", "timeout"].includes(category)) {
    actions.push({
      kind: "test_connection",
      label: "Test the planning provider",
      consequence: "Runs a non-mutating provider health check before any new planning attempt.",
      requiresConfirmation: false,
    });
  }
  if (retryable) {
    actions.push({
      kind: "retry_bounded",
      label: "Use the bounded planning retry",
      consequence: "Consumes only the persisted retry continuation after its backoff and within the signed budget.",
      requiresConfirmation: false,
    });
  }
  actions.push({
    kind: "start_new_run",
    label: "Start a new run",
    consequence: "Preserves this provider failure and starts a separately versioned execution attempt.",
    requiresConfirmation: true,
  });
  actions.push({
    kind: "terminate_gracefully",
    label: "Keep the safe stop",
    consequence: "Leaves the run stopped with its checkpoint and diagnosis preserved.",
    requiresConfirmation: true,
  });
  return actions;
}

function operationalActionFailureCategory(category: FailureCategory): OperationalFailureCategory {
  if (category === "transient_network") return "target_unreachable";
  return operationalFailureCategory(category);
}

function actionFailureOperatorActions(
  category: OperationalFailureCategory,
  retryable: boolean,
): readonly FailureOperatorAction[] {
  const actions: FailureOperatorAction[] = [];
  if (["mcp_unavailable", "provider_unavailable", "rate_limit", "target_unreachable", "timeout"].includes(category)) {
    actions.push({
      kind: "test_connection",
      label: "Test the unavailable connection",
      consequence: "Runs a non-mutating health check before another represented action is considered.",
      requiresConfirmation: false,
    });
  }
  if (["authentication_missing", "dependency_missing", "mcp_unavailable"].includes(category)) {
    actions.push({
      kind: "configure_dependency",
      label: "Restore the missing dependency",
      consequence: "Keeps the failed action immutable and verifies the exact missing executable, workspace, credential, or MCP dependency.",
      requiresConfirmation: true,
    });
  }
  if (retryable) {
    actions.push({
      kind: "retry_bounded",
      label: "Use the bounded retry",
      consequence: "Consumes only the persisted retry allowance after its backoff; it does not broaden scope or permissions.",
      requiresConfirmation: false,
    });
  }
  if (!["scope_denied", "policy_denied"].includes(category)) {
    actions.push({
      kind: "use_compatible_fallback",
      label: "Use a verified compatible fallback",
      consequence: "Requires a separately reviewed tool, provider, or specialist that satisfies the same signed action boundary.",
      requiresConfirmation: true,
    });
  }
  actions.push({
    kind: "amend_plan",
    label: "Amend the affected plan step",
    consequence: "Preserves this failure and requires a validated plan diff before any materially different action runs.",
    requiresConfirmation: true,
  });
  actions.push({
    kind: "start_new_run",
    label: "Start a new run",
    consequence: "Preserves the failed run and begins a separately versioned execution attempt.",
    requiresConfirmation: true,
  });
  actions.push({
    kind: "terminate_gracefully",
    label: "Keep the safe stop",
    consequence: "Leaves the run stopped with its event, checkpoint, and diagnosis preserved.",
    requiresConfirmation: true,
  });
  return actions;
}

function stableFailureCode(value: string): string {
  const normalized = value.trim().replace(/[^A-Za-z0-9._:@/-]+/gu, "_").slice(0, 120);
  return /^[A-Za-z0-9]/u.test(normalized) ? normalized : "action_execution_failed";
}

const FINDING_VALIDATION_CONTEXT_TYPES = new Set([
  "evidence",
  "finding",
  "lesson",
  "attack_lesson",
  "outcome",
  "evidence_pattern",
  "validation_pattern",
]);
const PHASE_TRANSITION_GUARD_CONTEXT_TYPES = new Set([
  "lesson",
  "attack_lesson",
  "failure",
  "failure_mode",
  "recovery",
  "recovery_pattern",
  "operational_hazard",
  "health_check",
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
  "misconfiguration",
  "attack_vector",
  "technique",
  "procedure",
  "attack_technique",
  "attack_procedure",
  "procedure_version",
  "prerequisite",
  "attribute",
  "discovery_pattern",
  "fingerprint_pattern",
  "script_artifact",
  "outcome",
  "alternative",
]);
const PHASE_SEMANTIC_KEYS = new Set([
  "product",
  "product_name",
  "version",
  "product_version",
  "service",
  "service_name",
  "protocol",
  "technology",
  "framework",
  "runtime",
  "database",
  "os",
  "kernel",
  "port",
  "cpe",
]);
const REPORTING_PROJECTION_CONTEXT_TYPES = new Set([
  "evaluation",
  "lesson",
]);
const CLOSEOUT_PROJECTION_CONTEXT_TYPES = new Set([
  "mission",
  "run",
  "evaluation",
  "lesson",
]);

interface TerminalProjectionContextManifest {
  readonly evaluationId: string;
  readonly reportingContextPackId: string;
  readonly closeoutContextPackId: string;
  readonly reportingExpectedNodeIds: readonly string[];
  readonly closeoutExpectedNodeIds: readonly string[];
}

export interface AutonomousPostReconPlanExpansion {
  readonly plan: MissionPlanDraft;
  readonly basePlanId: string;
  readonly materialization: Readonly<{
    readonly materializedScriptArtifactId: string;
    readonly materializedScriptContentHash: string;
    readonly contextPackId: string;
    readonly memoryNodeIds: readonly string[];
    readonly candidate: Readonly<{
      readonly targetNodeId: string;
      readonly memory: Readonly<{
        readonly procedureNodeId: string;
        readonly productNodeId: string;
        readonly versionNodeId: string;
      }>;
    }>;
  }>;
  readonly exactTarget: string;
  readonly cveApplicabilityId: string;
  readonly versionEvidenceId: string;
  readonly postExploit?: Readonly<{
    readonly extensionId: string;
    readonly postExploitSpecId: string;
    readonly sessionArtifactId: string;
  }>;
}

export interface AutonomousPostReconPlanExpansionPort {
  prepare(input: Readonly<{
    missionId: string;
    runId: string;
    basePlanId: string;
    completingStepId: string;
    actionId: string;
    signal: AbortSignal;
  }>): Promise<AutonomousPostReconPlanExpansion | null>;
  bindPersistedPlanStep(input: Readonly<{
    expansion: AutonomousPostReconPlanExpansion;
    planId: string;
    stepId: string;
  }>): string;
  ensureCandidateProcedureActivation(input: Readonly<{
    runId: string;
    stepId: string;
    signal: AbortSignal;
  }>): Promise<void>;
}

export class MissionRuntimeEngine implements ExecutionResultSink {
  readonly repository: RuntimeRepository;
  readonly continuations: RuntimeContinuationRepository;
  readonly coordinator: DurableRunCoordinator;
  readonly learning: RunLearningService;
  readonly brainContext: BrainContextService;
  readonly agentToolMemoryDecisions: AgentToolMemoryDecisionRepository;
  readonly operationalHazards: OperationalHazardMatcher;
  readonly operationalHazardHealthGate: OperationalHazardHealthGateService;
  readonly operationalHazardResetEvaluator: OperationalHazardLocalResetEvaluator;
  readonly operationalHazardResetProducer: OperationalHazardRuntimeRecoveryProducer;
  readonly operationalHazardResetReceiptIssuer?: OperationalResetControlReceiptIssuer;
  readonly operationalHazardResetHealthRecorder?: OperationalResetHealthEvidenceRecorder;
  private readonly memoryGraph: CanonicalMissionMemoryGraph;
  private readonly database: SqliteDatabase;
  private readonly workerId: string;
  private readonly scanIntervalMs: number;
  private readonly leaseTtlMs: number;
  private readonly decisionTtlMs: number;
  private readonly maxPlanSteps: number;
  private readonly supportedJourneys: ReadonlySet<"autonomous" | "guided">;
  private readonly now: () => Date;
  private readonly controlPlaneLeases: ControlPlaneLeaseService;
  private readonly runMutationAuthority: RunMutationAuthorityGuard;
  private readonly controlPlaneTokens = new Map<string, string>();
  private readonly processing = new Map<string, Promise<void>>();
  private readonly continuationProcessing = new Map<string, Promise<void>>();
  private readonly actionContexts = new Map<string, RuntimeActionContext>();
  private readonly controllers = new Map<string, AbortController>();
  private readonly execution: ResultAwareExecutionPort;
  private scanTimer?: ReturnType<typeof setInterval>;
  private idleAuthorityTimer?: ReturnType<typeof setInterval>;
  private stopping = false;
  private unbindResultSink?: () => void;
  private autonomousPostReconPlanExpansion?: AutonomousPostReconPlanExpansionPort;

  constructor(private readonly options: MissionRuntimeOptions) {
    this.database = options.database;
    this.now = options.now ?? (() => new Date());
    this.repository = new RuntimeRepository(options.database);
    this.controlPlaneLeases = new ControlPlaneLeaseService(options.database);
    this.runMutationAuthority = new RunMutationAuthorityGuard(options.database, this.now);
    this.continuations = new RuntimeContinuationRepository(
      options.database,
      (runId) => this.assertV2ControlPlaneOwnership(runId),
    );
    this.memoryGraph = new CanonicalMissionMemoryGraph(options.database, { clock: this.now });
    this.learning = new RunLearningService(options.database, {
      clock: this.now,
      events: this.repository.events,
      memoryGraph: this.memoryGraph,
      ...(options.projectMemoryNodes ? { projectMemoryNodes: options.projectMemoryNodes } : {}),
    });
    this.brainContext = options.brainContext ?? new BrainContextService({
      database: options.database,
      secondBrain: new SecondBrainService(new MemoryRepository(options.database, { clock: this.now })),
    });
    this.agentToolMemoryDecisions = new AgentToolMemoryDecisionRepository(options.database, this.now);
    this.operationalHazards = new OperationalHazardMatcher(options.database, { clock: this.now });
    this.operationalHazardHealthGate = new OperationalHazardHealthGateService(options.database, { clock: this.now });
    this.operationalHazardResetEvaluator = new OperationalHazardLocalResetEvaluator(options.database);
    this.operationalHazardResetProducer = new OperationalHazardRuntimeRecoveryProducer(options.database);
    this.operationalHazardResetReceiptIssuer = options.operationalHazardHmacKey
      ? new OperationalResetControlReceiptIssuer(options.database, options.operationalHazardHmacKey)
      : undefined;
    this.operationalHazardResetHealthRecorder = options.operationalHazardHmacKey
      ? new OperationalResetHealthEvidenceRecorder(options.database, options.operationalHazardHmacKey)
      : undefined;
    this.workerId = options.workerId?.trim() || `command-runtime-${randomUUID()}`;
    this.scanIntervalMs = options.scanIntervalMs ?? 500;
    this.leaseTtlMs = options.leaseTtlMs ?? 30_000;
    this.decisionTtlMs = options.decisionTtlMs ?? 24 * 60 * 60 * 1_000;
    this.maxPlanSteps = options.maxPlanSteps ?? 32;
    const supportedJourneys = options.supportedJourneys ?? ["autonomous", "guided"];
    if (
      supportedJourneys.length === 0 ||
      supportedJourneys.some((journey) => journey !== "autonomous" && journey !== "guided")
    ) {
      throw new RangeError("supportedJourneys must contain guided and/or autonomous");
    }
    this.supportedJourneys = new Set(supportedJourneys);
    if (this.scanIntervalMs < 50 || this.leaseTtlMs < 1_000 || this.decisionTtlMs < 1_000) {
      throw new RangeError("Runtime scan, lease, or decision timing is below its safe minimum");
    }
    const routedExecution = new RuntimeExecutionRouter(
      options.execution,
      options.trustedOperationalResetExecution,
      options.database,
      options.agentRuntimeBindings,
      options.autonomousActivation,
      this.workerId,
    );
    this.execution = routedExecution;
    this.coordinator = new DurableRunCoordinator(options.database, routedExecution, {
      now: this.now,
      leaseTtlMs: this.leaseTtlMs,
      supervisor: new RunSupervisor({ retryPolicy: options.retryPolicy }),
      beforeActionCommit: (action) => {
        if (isOperationalResetAction(action)) {
          if (!options.trustedOperationalResetExecution) {
            throw new CommandRuntimeError(
              503,
              "trusted_reset_controller_unavailable",
              "A reviewed local reset controller is not configured",
              {
                humanMessage: "Ti-Scale stopped before dispatch because physical resets must use a reviewed local controller that can prove the before-and-after target health state.",
                category: "dependency_missing",
                remediation: "Configure and validate a reviewed local reset-controller adapter, then create a new represented reset action.",
              },
            );
          }
          if (!this.operationalHazardResetReceiptIssuer || !this.operationalHazardResetHealthRecorder) {
            throw new CommandRuntimeError(
              503,
              "operational_hazard_reset_receipt_key_unavailable",
              "The server-only reset-control receipt key is unavailable",
              {
                humanMessage: "Ti-Scale stopped before dispatch because it could not issue a one-use authenticated reset authorization.",
                category: "dependency_missing",
                remediation: "Restore the server-only operational-hazard HMAC credential, then create a new reset action.",
              },
            );
          }
          this.operationalHazardResetReceiptIssuer.authorizeBeforeDispatch(action);
        }
        const attempt = this.database.prepare(`
          SELECT id FROM attack_attempts
          WHERE run_id = ? AND step_id = ? AND action_class = ? AND status = 'ready'
          ORDER BY created_at, id LIMIT 1
        `).get(action.runId, action.stepId, action.actionClass) as { id: string } | undefined;
        if (!attempt) return;
        this.operationalHazardHealthGate.consumeRequiredForAction({
          attackAttemptId: attempt.id,
          action,
          actorId: this.workerId,
        });
      },
      afterActionCompleteBeforeCommit: (action, result) => {
        if (!result.success) return;
        this.operationalHazardHealthGate.recordAssessmentForCompletedAction(action, {
          id: this.workerId,
          type: "worker",
        });
        if (isOperationalResetAction(action)) {
          if (!this.operationalHazardResetReceiptIssuer || !this.operationalHazardResetHealthRecorder) {
            throw new CommandRuntimeError(
              503,
              "operational_hazard_reset_receipt_key_unavailable",
              "The server-only reset-control receipt key is unavailable",
              { category: "dependency_missing" },
            );
          }
          this.operationalHazardResetHealthRecorder.record(action, result.operationalResetResult);
          this.operationalHazardResetReceiptIssuer.issueFromCompletedReset(action);
        }
        this.operationalHazardResetEvaluator.evaluateCompletedAction(action);
        this.operationalHazardResetProducer.recordCompletedAction(action, {
          id: this.workerId,
          type: "worker",
        });
      },
      afterActionCommit: (action) => {
        this.crashAfterCommit("action_reserved_before_dispatch", action.runId, action.id);
      },
      beforeActionDispatch: (started) => {
        const context: RuntimeActionContext = {
          action: started.action,
          lease: started.lease,
          before: this.coordinator.getRun(started.action.runId).control.progress,
          completing: false,
        };
        this.actionContexts.set(started.action.id, context);
        try {
          this.actionHeartbeat(context);
        } catch (error) {
          this.clearActionContext(started.action.id);
          throw error;
        }
        return {
          currentLease: () => context.lease,
          stop: () => {
            context.completing = true;
            this.clearActionContext(started.action.id);
            return context.lease;
          },
        };
      },
      afterCancellationCleanup: (runId) => {
        this.crashAfterCommit("cancellation_cleanup_before_finalize", runId);
      },
      recordActionFailure: (failure) => this.persistActionFailureDiagnosis(failure),
      assertMutationAuthority: (runId) => this.assertV2ControlPlaneOwnership(runId),
    });
    const unbind = routedExecution.bindResultSink?.(this);
    if (typeof unbind === "function") this.unbindResultSink = unbind;
  }

  configureAutonomousPostReconPlanExpansion(
    expansion: AutonomousPostReconPlanExpansionPort,
  ): void {
    if (this.autonomousPostReconPlanExpansion) {
      throw new Error("Autonomous post-recon plan expansion is already configured");
    }
    this.autonomousPostReconPlanExpansion = expansion;
  }

  authorizeOperationalHazardRecovery(input: {
    readonly runId: string;
    readonly healthAssessmentId: string;
    readonly attackAttemptId: string;
    readonly operatorId: string;
    readonly ttlMs?: number;
  }) {
    const attempt = this.database.prepare(`
      SELECT run_id FROM attack_attempts WHERE id = ?
    `).get(input.attackAttemptId) as { readonly run_id: string } | undefined;
    if (!attempt) {
      throw new CommandRuntimeError(404, "attack_attempt_not_found", "Recovery attack attempt was not found");
    }
    if (attempt.run_id !== input.runId) {
      throw new CommandRuntimeError(409, "hazard_retry_cross_run_denied", "Recovery attempt belongs to another run", {
        category: "scope_conflict",
      });
    }
    this.assertV2ControlPlaneOwnership(attempt.run_id);
    try {
      return this.operationalHazardHealthGate.authorizeSaferAttempt({
        healthAssessmentId: input.healthAssessmentId,
        attackAttemptId: input.attackAttemptId,
        actor: { id: input.operatorId, type: "operator" },
        ...(input.ttlMs === undefined ? {} : { ttlMs: input.ttlMs }),
      });
    } catch (error) {
      throw asRuntimeError(error);
    }
  }

  private timestamp(): string {
    return this.now().toISOString();
  }

  private persistActionFailureDiagnosis(input: DurableActionFailureContext): void {
    const originatingComponent = "command-runtime.reviewed-action-execution";
    const existing = this.database.prepare(`
      SELECT id FROM failure_diagnoses
      WHERE action_id = ? AND originating_component = ?
      LIMIT 1
    `).get(input.action.id, originatingComponent) as { id: string } | undefined;
    if (existing) return;

    const category = operationalActionFailureCategory(input.category);
    const retryable = input.retryable && [
      "mcp_unavailable",
      "provider_unavailable",
      "rate_limit",
      "target_unreachable",
      "timeout",
      "worker_lost",
    ].includes(category);
    const lastSuccess = this.database.prepare(`
      SELECT id FROM events
      WHERE run_id = ? AND event_type = 'action.authorized'
        AND json_extract(payload_json, '$.actionId') = ?
      ORDER BY sequence DESC LIMIT 1
    `).get(input.action.runId, input.action.id) as { id: string } | undefined;
    const humanReason = redactSecrets(input.failureMessage || input.reason).slice(0, 4_000);
    const remediation = category === "dependency_missing"
      ? "Restore and attest the exact missing executable, workspace, file, or runtime dependency, then use a declared recovery action."
      : category === "authentication_missing"
        ? "Configure the missing credential through the server-owned secret boundary, verify it without exposing the value, then start a declared recovery action."
        : category === "mcp_unavailable"
          ? "Test the named MCP service and its authenticated capability receipt; use only a compatible reviewed fallback while it is unavailable."
          : category === "scope_denied" || category === "policy_denied"
            ? "Keep the action stopped. Amend the signed scope or action policy explicitly, or choose an in-policy alternative in a new plan version."
            : retryable
              ? "Allow only the persisted bounded retry after its backoff, or choose a verified compatible fallback."
              : "Inspect the failed action and checkpoint, then amend the plan or select a verified compatible fallback before another attempt.";
    try {
      new FailureDiagnosisService(this.database, { clock: this.now }).create({
        missionId: input.action.missionId,
        runId: input.action.runId,
        stepId: input.action.stepId,
        ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
        actionId: input.action.id,
        subjectType: "action",
        subjectId: input.action.id,
        humanReason,
        category,
        code: stableFailureCode(input.failureCode),
        originatingComponent,
        ...(lastSuccess ? { lastSuccessEventId: lastSuccess.id } : {}),
        failedComponentRef: input.action.actionType,
        targetSummary: `The represented action targeted ${redactSecrets(input.action.target)} inside the signed mission boundary.`,
        policyOrDependency: `Action class ${input.action.actionClass}; recovery directive ${input.directive}; execution remained under the reviewed local/provider/MCP boundary.`,
        retryHistory: [{
          attempt: input.action.retryCount + 1,
          actionId: input.action.id,
          category: input.category,
          directive: input.directive,
        }],
        progressBeforeFailure: input.progressBeforeFailure,
        preservedReferences: [{
          kind: "event",
          id: input.eventId,
          meaning: "Immutable action completion event containing the classified failure and recovery directive",
        }, {
          kind: "checkpoint",
          id: input.checkpointId,
          meaning: "Durable run checkpoint created in the same fenced action-failure transaction",
        }],
        retryable,
        automaticRecovery: {
          directive: input.directive,
          reason: input.reason,
          retryPersisted: input.directive === "retry",
          failedStepClosed: input.directive !== "retry",
          failedAssignmentClosed: input.directive !== "retry",
        },
        remediation,
        operatorActions: actionFailureOperatorActions(category, retryable),
        objectiveImpact: input.run.run.state === "failed"
          ? "This run ended safely before the failed action could advance the objective; all earlier evidence and artifacts remain preserved."
          : "This action did not advance the objective. The run is waiting on its bounded, explicitly represented recovery path.",
        terminal: isTerminalRunState(input.run.run.state),
        actor: { id: this.workerId, type: "worker" },
      });
    } catch (error) {
      this.database.prepare(`
        INSERT INTO structured_logs (
          id, mission_id, run_id, severity, domain, message,
          attributes_json, sensitivity, occurred_at
        ) VALUES (?, ?, ?, 'error', 'command-runtime.failure-diagnosis', ?, ?, 'internal', ?)
      `).run(
        `log_${randomUUID()}`,
        input.action.missionId,
        input.action.runId,
        "Action failure was committed but its structured diagnosis could not be persisted",
        JSON.stringify({
          code: "action_failure_diagnosis_persistence_failed",
          actionId: input.action.id,
          category: input.category,
          directive: input.directive,
          errorType: error instanceof Error ? error.name : "unknown",
          rawErrorPersisted: false,
        }),
        this.timestamp(),
      );
    }
  }

  /**
   * A successful bounded retry is the canonical recovery outcome for every
   * retryable failure in its immutable parent-action chain. Resolve only the
   * runtime-created active diagnoses whose declared recovery was that exact
   * bounded retry. The action lineage, status, run, and step are read from the
   * database so a caller cannot close an unrelated operator diagnosis.
   *
   * This runs inside the same transaction that advances the successful step.
   * A replay therefore either observes the diagnoses already resolved or
   * performs the resolution and audit exactly once.
   */
  private resolveSuccessfulRetryFailureLineage(input: Readonly<{
    missionId: string;
    runId: string;
    stepId: string;
    successfulActionId: string;
    resolvedAt: string;
  }>): readonly string[] {
    const rows = this.database.prepare(`
      WITH RECURSIVE retry_lineage (
        action_id, parent_action_id, depth, visited
      ) AS (
        SELECT id, parent_action_id, 0, '|' || id || '|'
        FROM actions
        WHERE id = ? AND mission_id = ? AND run_id = ? AND step_id = ?
          AND status = 'succeeded'
        UNION ALL
        SELECT parent.id, parent.parent_action_id, lineage.depth + 1,
          lineage.visited || parent.id || '|'
        FROM retry_lineage lineage
        JOIN actions parent ON parent.id = lineage.parent_action_id
        WHERE parent.mission_id = ? AND parent.run_id = ?
          AND parent.step_id = ?
          AND parent.status IN ('failed', 'timed_out')
          AND lineage.depth < 64
          AND instr(lineage.visited, '|' || parent.id || '|') = 0
      )
      SELECT diagnosis.id, diagnosis.action_id, diagnosis.category,
        diagnosis.code, retry_lineage.depth
      FROM retry_lineage
      JOIN failure_diagnoses diagnosis
        ON diagnosis.action_id = retry_lineage.action_id
      WHERE retry_lineage.depth > 0
        AND diagnosis.mission_id = ?
        AND diagnosis.run_id = ?
        AND diagnosis.step_id = ?
        AND diagnosis.subject_type = 'action'
        AND diagnosis.subject_id = diagnosis.action_id
        AND diagnosis.originating_component =
          'command-runtime.reviewed-action-execution'
        AND diagnosis.state = 'active'
        AND diagnosis.retryable = 1
        AND json_extract(
          diagnosis.automatic_recovery_json,
          '$.directive'
        ) = 'retry'
        AND EXISTS (
          SELECT 1 FROM json_each(diagnosis.operator_actions_json) action
          WHERE json_extract(action.value, '$.kind') = 'retry_bounded'
        )
      ORDER BY retry_lineage.depth DESC, diagnosis.created_at, diagnosis.id
    `).all(
      input.successfulActionId,
      input.missionId,
      input.runId,
      input.stepId,
      input.missionId,
      input.runId,
      input.stepId,
      input.missionId,
      input.runId,
      input.stepId,
    ) as Array<{
      readonly id: string;
      readonly action_id: string;
      readonly category: OperationalFailureCategory;
      readonly code: string;
      readonly depth: number;
    }>;
    if (rows.length === 0) return [];

    const repository = new FailureDiagnosisRepository(
      this.database,
      { clock: this.now },
    );
    const resolvedIds: string[] = [];
    for (const row of rows) {
      const current = repository.get(row.id);
      if (current.state !== "active") continue;
      const resolved = repository.resolve(row.id, input.resolvedAt);
      repository.audit.append({
        missionId: input.missionId,
        runId: input.runId,
        actor: { id: this.workerId, type: "worker" },
        action: "failure_diagnosis.resolved",
        resourceType: "failure_diagnosis",
        resourceId: row.id,
        reason:
          `Automatic bounded retry ${input.successfulActionId} succeeded and durably advanced the same represented step.`,
        details: {
          from: current.state,
          to: resolved.state,
          category: row.category,
          code: row.code,
          resolutionMode: "automatic_bounded_retry",
          actionKind: "retry_bounded",
          predecessorActionId: row.action_id,
          successfulActionId: input.successfulActionId,
          retryDepth: row.depth,
          sameRunAndStepVerified: true,
          successfulActionStatusVerified: true,
        },
        occurredAt: input.resolvedAt,
      });
      resolvedIds.push(row.id);
    }
    return resolvedIds;
  }

  /**
   * A follow-up run may deliberately narrow its reusable memory to immutable
   * run_context_selections. Resolve that run-scoped selection from the exact
   * pinned Autonomous contract instead of falling back to mutable/stale
   * mission projection data. Any contract drift or missing permission remains
   * a fail-closed policy error.
   */
  private effectiveRunMemoryPolicy(input: {
    readonly mission: import("./types").PlanningMission;
    readonly run: import("./types").PlanningRun;
  }): Readonly<Record<string, unknown>> {
    if (input.run.journey !== "autonomous") return input.mission.memoryPolicy;
    const selections = this.database.prepare(`
      SELECT node_id, selection_type FROM run_context_selections
      WHERE run_id = ? ORDER BY selected_at, id
    `).all(input.run.id) as Array<{
      node_id: string;
      selection_type: "verified_lesson";
    }>;
    if (selections.length === 0) return input.mission.memoryPolicy;
    if (selections.some((selection) => selection.selection_type !== "verified_lesson")) {
      throw new TypeError("Autonomous run context contains an unsupported immutable selection type");
    }
    const contract = this.database.prepare(`
      SELECT r.contract_version_bound, r.contract_hash_bound,
        mc.version, mc.contract_hash, mc.state, mc.memory_scopes_json
      FROM runs r
      JOIN mission_contracts mc ON mc.id = r.contract_id AND mc.mission_id = r.mission_id
      WHERE r.id = ?
    `).get(input.run.id) as {
      contract_version_bound: number | null;
      contract_hash_bound: string | null;
      version: number;
      contract_hash: string;
      state: string;
      memory_scopes_json: string;
    } | undefined;
    if (
      !contract || contract.state !== "confirmed" ||
      contract.contract_version_bound !== contract.version ||
      contract.contract_hash_bound !== contract.contract_hash
    ) {
      throw new TypeError("Autonomous run context is not bound to its unchanged confirmed contract");
    }
    let allowedScopes: readonly string[] = [];
    try {
      const parsed = JSON.parse(contract.memory_scopes_json) as unknown;
      allowedScopes = Array.isArray(parsed)
        ? [...new Set(parsed.filter((value): value is string => typeof value === "string" && value.trim().length > 0))]
        : [];
    } catch {
      throw new TypeError("Autonomous contract memory scopes are malformed");
    }
    if (!allowedScopes.includes("verified_lessons")) {
      throw new TypeError("Autonomous contract does not permit the selected verified-lesson context");
    }
    return {
      ...input.mission.memoryPolicy,
      allowedScopes,
      exactContextNodeIds: selections.map((selection) => selection.node_id),
    };
  }

  private retrieveBrainContext(input: {
    readonly hook: BrainLifecycleHook;
    readonly mission: import("./types").PlanningMission;
    readonly run: import("./types").PlanningRun;
    readonly actorId: string;
    readonly query: string;
    readonly queryRedacted: string;
    readonly stepId?: string;
    readonly actionId?: string;
    readonly terminalSafe?: boolean;
    readonly trustedRuntimeCapabilityNodeIds?: readonly string[];
    readonly lifecyclePreferenceNodeIds?: LifecyclePreferenceNodeIds;
  }): BrainContextResult {
    const canonical = this.memoryGraph.ensureRun(input.run.id);
    return retrieveMissionBrainContext({
      brainContext: this.brainContext,
      hook: input.hook,
      journey: input.run.journey,
      missionId: input.mission.id,
      runId: input.run.id,
      ...(input.stepId ? { stepId: input.stepId } : {}),
      ...(input.actionId ? { actionId: input.actionId } : {}),
      actorId: input.actorId,
      actorType: "agent",
      query: input.query,
      queryRedacted: input.queryRedacted,
      memoryPolicy: this.effectiveRunMemoryPolicy({ mission: input.mission, run: input.run }),
      canonicalContextNodeIds: canonical.nodeIds,
      ...(input.trustedRuntimeCapabilityNodeIds
        ? { trustedRuntimeCapabilityNodeIds: input.trustedRuntimeCapabilityNodeIds }
        : {}),
      ...(input.lifecyclePreferenceNodeIds
        ? { lifecyclePreferenceNodeIds: input.lifecyclePreferenceNodeIds }
        : {}),
      ...(input.terminalSafe ? { terminalSafe: true } : {}),
    });
  }

  private providerBrainContext(result: BrainContextResult): BrainProviderContextEnvelope {
    return this.brainContext.providerContext(result);
  }

  private currentRuntimeCapabilityNodeIds(
    kind: "agent" | "tool",
    sourceId: string,
  ): readonly string[] {
    const id = runtimeCapabilityMemoryNodeId(kind, sourceId);
    const row = this.database.prepare(`
      SELECT author_type, author_id, lifecycle_status, retention_policy_json
      FROM memory_nodes WHERE id = ?
    `).get(id) as {
      author_type: string;
      author_id: string | null;
      lifecycle_status: string;
      retention_policy_json: string;
    } | undefined;
    if (
      !row
      || row.author_type !== "system"
      || row.author_id !== "system:runtime-capability-memory-projector"
      || row.lifecycle_status !== "verified"
    ) return [];
    let retention: Record<string, unknown>;
    try {
      retention = JSON.parse(row.retention_policy_json) as Record<string, unknown>;
    } catch {
      return [];
    }
    const projection = retention.runtimeCapabilityProjection;
    if (
      !projection
      || typeof projection !== "object"
      || Array.isArray(projection)
      || (projection as Record<string, unknown>).schemaVersion
        !== "ti-scale.runtime-capability-memory-projection.v1"
      || (projection as Record<string, unknown>).status !== "current"
      || (projection as Record<string, unknown>).kind !== kind
      || (projection as Record<string, unknown>).sourceId !== sourceId
    ) return [];
    return [id];
  }

  private recordTypedBrainContextUse(input: {
    readonly context: BrainContextResult;
    readonly allowedTypes: ReadonlySet<string>;
    readonly influenceSummary: string;
    readonly ignoredReason: string;
    readonly enabled?: boolean;
    readonly allowedNodeIds?: ReadonlySet<string>;
  }): readonly string[] {
    const usedNodeIds = input.enabled === false
      ? []
      : [...new Set(input.context.items
        .filter((item) => input.allowedTypes.has(item.node.nodeType)
          && (!input.allowedNodeIds || input.allowedNodeIds.has(item.node.id)))
        .map((item) => item.node.id))];
    if (usedNodeIds.length > 0) {
      this.brainContext.recordContextUse(
        input.context,
        usedNodeIds,
        input.influenceSummary,
        input.ignoredReason,
      );
    } else {
      this.brainContext.recordUnusedContext(input.context, input.ignoredReason);
    }
    return usedNodeIds;
  }

  private applyAgentToolMemoryDecision(input: {
    readonly hook: AgentToolMemoryHook;
    readonly context: BrainContextResult;
    readonly mission: import("./types").PlanningMission;
    readonly run: import("./types").PlanningRun;
    readonly intent: Parameters<DurableRunCoordinator["startAction"]>[0]["intent"];
    readonly actorId: string;
    readonly representedAgentId?: string;
  }): AgentToolMemoryDecisionReceipt {
    const representationHash = hashCanonical({
      actionFingerprint: fingerprintAction(input.intent).hash,
      assignmentId: input.hook === "assignment_acceptance"
        ? input.intent.assignmentId ?? null
        : null,
      representedAgentId: input.representedAgentId ?? null,
      representedActionClass: input.intent.actionClass,
    });
    const compiled = compileAgentToolMemoryDecision({
      hook: input.hook,
      context: input.context,
      journey: input.run.journey,
      missionId: input.mission.id,
      engagementId: input.mission.engagementId,
      runId: input.run.id,
      stepId: input.intent.stepId,
      selection: {
        representationHash,
        ...(input.hook === "assignment_acceptance" && input.intent.assignmentId
          ? { assignmentId: input.intent.assignmentId }
          : {}),
        ...(input.representedAgentId ? { representedAgentId: input.representedAgentId } : {}),
        representedActionType: input.intent.actionType,
        representedActionClass: input.intent.actionClass,
      },
      activeVaultBackedNodeIds: this.agentToolMemoryDecisions.activeVaultBackedNodeIds(
        input.context.contextPack.id,
      ),
    });
    const receipt = inImmediateTransaction(this.database, () => {
      const persisted = this.agentToolMemoryDecisions.persist({
        compiled,
        actorId: input.actorId,
      });
      this.repository.events.append({
        missionId: input.mission.id,
        runId: input.run.id,
        journey: input.run.journey,
        eventType: "brain.agent_tool_memory_decided",
        actorType: "agent",
        actorId: input.actorId,
        summary: persisted.decision === "attest_compatible"
          ? "Synchronized Second Brain memory confirmed the represented agent or tool selection without changing it."
          : persisted.decision === "no_applicable_memory"
            ? "The agent checked synchronized typed memory; no applicable compatibility rule was found, so the represented selection remained unchanged."
            : persisted.decision === "veto_missing_dependency"
              ? "The agent stopped before dispatch because synchronized typed memory identifies a missing dependency for this exact represented selection."
              : "The agent stopped before dispatch because synchronized typed memory marks this exact represented selection incompatible.",
        payload: {
          receiptId: persisted.id,
          decisionAuditRecordId: persisted.decisionAuditRecordId,
          brainAuditRecordId: persisted.brainAuditRecordId,
          contextPackId: persisted.contextPackId,
          hook: persisted.hook,
          decision: persisted.decision,
          representationHash: persisted.selection.representationHash,
          appliedNodeIds: [...persisted.appliedNodeIds],
          ignoredNodeIds: [...persisted.ignoredNodeIds],
          representationUnchanged: true,
          scopeExpanded: false,
          toolChanged: false,
          actionClassChanged: false,
          argumentsChanged: false,
          providerExposureCreated: false,
          targetContacted: false,
        },
        contextPackId: persisted.contextPackId,
        sensitivity: "internal",
      });
      return persisted;
    });
    if (receipt.decision === "veto_missing_dependency") {
      throw new CommandRuntimeError(
        409,
        "agent_memory_dependency_missing",
        "Synchronized typed memory identifies a missing dependency for the represented selection",
        {
          humanMessage: "Ti-Scale stopped before target contact because confirmed Second Brain memory says this exact represented agent or tool is missing a required dependency.",
          retryable: false,
          category: "dependency_missing",
          details: {
            hook: receipt.hook,
            receiptId: receipt.id,
            contextPackId: receipt.contextPackId,
            brainAuditRecordId: receipt.brainAuditRecordId,
            decisionAuditRecordId: receipt.decisionAuditRecordId,
            appliedNodeIds: [...receipt.appliedNodeIds],
            representationUnchanged: true,
            targetContacted: false,
          },
          remediation: "Restore and attest the named dependency, or amend the plan to an already registered compatible agent/tool selection. Memory cannot add a fallback or change scope by itself.",
        },
      );
    }
    if (receipt.decision === "veto_incompatible") {
      throw new CommandRuntimeError(
        409,
        "agent_memory_incompatible",
        "Synchronized typed memory marks the represented selection incompatible",
        {
          humanMessage: "Ti-Scale stopped before target contact because confirmed Second Brain memory marks this exact represented agent or tool incompatible with the action.",
          retryable: false,
          category: "policy_denied",
          details: {
            hook: receipt.hook,
            receiptId: receipt.id,
            contextPackId: receipt.contextPackId,
            brainAuditRecordId: receipt.brainAuditRecordId,
            decisionAuditRecordId: receipt.decisionAuditRecordId,
            appliedNodeIds: [...receipt.appliedNodeIds],
            representationUnchanged: true,
            targetContacted: false,
          },
          remediation: "Amend the plan to a separately represented compatible agent/tool selection. Memory cannot substitute a tool, change parameters, or broaden authorization.",
        },
      );
    }
    return receipt;
  }

  private phaseTransitionSemanticQuery(input: {
    readonly runId: string;
    readonly stepId: string;
    readonly actionId: string;
    readonly actionType: string;
    readonly actionClass: string;
    readonly phase: string;
    readonly stepTitle: string;
  }): {
    readonly query: string;
    readonly queryRedacted: string;
    readonly signalCount: number;
    readonly observationCount: number;
    readonly evidenceTypeCount: number;
    readonly semanticSignals: readonly PhaseTransitionSemanticSignal[];
  } {
    const terms = new Set<string>();
    const signals = new Map<string, PhaseTransitionSemanticSignal>();
    const safeTerm = (value: unknown): string | undefined => {
      if (typeof value !== "string" && typeof value !== "number") return undefined;
      const normalized = redactSecrets(String(value))
        .replace(/[^A-Za-z0-9._:+/-]+/gu, " ")
        .replace(/\s+/gu, " ")
        .trim()
        .slice(0, 96);
      return normalized && !normalized.includes("REDACTED") ? normalized : undefined;
    };
    const addSignal = (
      kind: PhaseTransitionSemanticSignal["kind"],
      key: string,
      value: unknown,
    ): void => {
      const semanticValue = safeTerm(value);
      if (!semanticValue) return;
      const encoded = `${key}:${semanticValue}`;
      terms.add(encoded);
      if (!signals.has(encoded)) {
        signals.set(encoded, Object.freeze({ kind, key, value: semanticValue }));
      }
    };
    addSignal("action", "action_type", input.actionType);
    addSignal("action", "action_class", input.actionClass);
    addSignal("phase", "phase", input.phase);
    addSignal("phase", "step_title", input.stepTitle);
    const observations = this.database.prepare(`
      SELECT DISTINCT o.observation_type, o.normalized_value_json, o.last_seen_at, o.id
      FROM observations o
      JOIN observation_log_sources source ON source.observation_id = o.id
      JOIN engagement_log_records log ON log.id = source.log_record_id
      WHERE o.run_id = ? AND o.step_id = ? AND log.action_id = ?
        AND o.verification_state IN ('unverified', 'corroborated')
      ORDER BY o.last_seen_at DESC, o.id
      LIMIT 24
    `).all(input.runId, input.stepId, input.actionId) as Array<{
      observation_type: string;
      normalized_value_json: string;
      last_seen_at: string;
      id: string;
    }>;
    for (const observation of observations) {
      addSignal("observation", "observation", observation.observation_type);
      let normalized: unknown;
      try {
        normalized = JSON.parse(observation.normalized_value_json) as unknown;
      } catch {
        continue;
      }
      if (!normalized || typeof normalized !== "object" || Array.isArray(normalized)) continue;
      for (const [key, value] of Object.entries(normalized)) {
        if (!PHASE_SEMANTIC_KEYS.has(key.toLowerCase())) continue;
        const values = Array.isArray(value) ? value.slice(0, 4) : [value];
        for (const item of values) {
          const semanticKey = key.toLowerCase();
          addSignal(
            semanticKey.includes("version") ? "version" : "technology",
            semanticKey,
            item,
          );
        }
      }
    }
    const evidenceTypes = (this.database.prepare(`
      SELECT DISTINCT e.evidence_type
      FROM evidence e
      WHERE e.action_id = ? AND e.run_id = ? AND e.step_id = ?
        AND ${verifiedEvidenceSql("e")}
      ORDER BY e.evidence_type
      LIMIT 24
    `).all(input.actionId, input.runId, input.stepId) as Array<{
      evidence_type: string;
    }>).flatMap(({ evidence_type: evidenceType }) => {
      const semanticType = safeTerm(evidenceType);
      addSignal("evidence", "evidence", semanticType);
      return semanticType ? [semanticType] : [];
    });
    const selected = [...terms].slice(0, 48);
    const selectedSet = new Set(selected);
    return {
      query: selected.length > 0
        ? `Phase transition from canonical parsed signals: ${selected.join(", ")}. Retrieve matching confirmed attack knowledge, failure avoidance, and corroboration requirements for the next bounded decision.`
        : "Phase transition has no canonical parsed product, version, service, observation, or verified-evidence signal; return only exact scope-safe context if one applies.",
      queryRedacted: `Refresh scoped phase context from ${observations.length} canonical parsed observation(s) and ${evidenceTypes.length} verified evidence type(s); raw action output was excluded.`,
      signalCount: selected.length,
      observationCount: observations.length,
      evidenceTypeCount: evidenceTypes.length,
      semanticSignals: Object.freeze([...signals.entries()]
        .filter(([encoded]) => selectedSet.has(encoded))
        .map(([, signal]) => signal)),
    };
  }

  /**
   * Validate the evaluator's evidence references locally, then retrieve one
   * bounded step-scoped comparison pack. Memory may add a comparison
   * checkpoint, but it can never promote evidence or make a criterion true.
   */
  private prepareFindingValidationContexts(input: {
    readonly mission: import("./types").PlanningMission;
    readonly run: import("./types").PlanningRun;
    readonly planId: string;
    readonly evaluation: MissionCompletionEvaluation;
  }): Array<Record<string, JsonValue>> {
    const evidenceByStep = new Map<string, string[]>();
    const evidenceIds = [...new Set(input.evaluation.criteria.flatMap((criterion) =>
      criterion.evidenceIds.map((evidenceId) => evidenceId.trim()).filter(Boolean)))];
    for (const evidenceId of evidenceIds) {
      const evidence = this.database.prepare(`
        SELECT e.id, e.step_id
        FROM evidence e
        WHERE e.id = ? AND e.mission_id = ? AND e.run_id = ?
          AND ${verifiedEvidenceSql("e")}
      `).get(evidenceId, input.mission.id, input.run.id) as {
        id: string;
        step_id: string | null;
      } | undefined;
      if (!evidence) {
        throw new CommandRuntimeError(
          422,
          "completion_evidence_reference_invalid",
          "Outcome evaluator cited missing, unverified, raw-log, or cross-run evidence",
          {
            humanMessage: "Ti-Scale stopped before completion because a success claim referenced evidence that is not verified for this exact run.",
            category: "insufficient_evidence",
            remediation: "Verify an attributable evidence item for the exact run and step, then resume evaluation from the checkpoint.",
          },
        );
      }
      if (evidence.step_id) {
        const linked = evidenceByStep.get(evidence.step_id) ?? [];
        linked.push(evidence.id);
        evidenceByStep.set(evidence.step_id, linked);
      }
    }

    const steps = this.database.prepare(`
      SELECT ps.id FROM plan_steps ps
      JOIN plans p ON p.id = ps.plan_id
      WHERE ps.plan_id = ? AND p.run_id = ?
      ORDER BY ps.ordinal, ps.id
    `).all(input.planId, input.run.id) as Array<{ id: string }>;
    return steps.map(({ id: stepId }) => {
      const context = this.retrieveBrainContext({
        hook: "finding_validation",
        mission: input.mission,
        run: input.run,
        stepId,
        actorId: "outcome-evaluator",
        query: "Cross-check this step's verified evidence and finding-related memory before accepting any terminal success claim.",
        queryRedacted: "Cross-check step-scoped verified evidence and finding-related memory before terminal validation.",
      });
      const verifiedEvidenceIds = evidenceByStep.get(stepId) ?? [];
      const usedNodeIds = this.recordTypedBrainContextUse({
        context,
        allowedTypes: FINDING_VALIDATION_CONTEXT_TYPES,
        enabled: verifiedEvidenceIds.length > 0,
        influenceSummary: "Used as a scoped comparison checkpoint alongside canonical verified evidence; memory did not promote evidence, verify a finding, or make a success criterion true.",
        ignoredReason: verifiedEvidenceIds.length > 0
          ? "The retrieved item was not an evidence, finding, lesson, outcome, or validation-pattern comparison relevant to this checkpoint."
          : "This step had no canonical verified evidence reference to compare, so retrieved memory did not influence terminal validation.",
      });
      const payload = {
        contextPackId: context.contextPack.id,
        stepId,
        usedNodeIds: [...usedNodeIds],
        verifiedEvidenceIds: [...verifiedEvidenceIds],
      } satisfies Record<string, JsonValue>;
      this.repository.events.append({
        missionId: input.mission.id,
        runId: input.run.id,
        journey: input.run.journey,
        eventType: "brain.finding_validation_context_applied",
        actorType: "agent",
        actorId: "outcome-evaluator",
        summary: usedNodeIds.length > 0
          ? "Finding validation cross-checked verified step evidence against scoped retained knowledge."
          : "Finding validation retained a scoped Context Pack, but no memory changed the evidence decision.",
        payload,
      });
      return payload;
    });
  }

  private terminalProjectionManifest(
    runId: string,
    evaluationId: string,
  ): TerminalProjectionContextManifest | undefined {
    const row = this.database.prepare(`
      SELECT payload_json FROM events
      WHERE run_id = ? AND event_type = 'brain.terminal_projection_context_selected'
        AND json_extract(payload_json, '$.evaluationId') = ?
      ORDER BY sequence DESC LIMIT 1
    `).get(runId, evaluationId) as { payload_json: string } | undefined;
    if (!row) return undefined;
    const parsed = JSON.parse(row.payload_json) as Partial<TerminalProjectionContextManifest>;
    const stringArray = (value: unknown): value is readonly string[] =>
      Array.isArray(value) && value.every((item) => typeof item === "string" && item.length > 0);
    if (
      parsed.evaluationId !== evaluationId
      || typeof parsed.reportingContextPackId !== "string"
      || typeof parsed.closeoutContextPackId !== "string"
      || !stringArray(parsed.reportingExpectedNodeIds)
      || !stringArray(parsed.closeoutExpectedNodeIds)
    ) {
      throw new Error("Terminal projection context manifest is malformed");
    }
    return parsed as TerminalProjectionContextManifest;
  }

  private projectTerminalMemoryWithBrain(input: {
    readonly runId: string;
    readonly evaluationId: string;
  }): readonly string[] {
    const manifest = this.terminalProjectionManifest(input.runId, input.evaluationId);
    const projectedNodeIds = this.learning.projectTerminalMemory(input.runId);
    if (!manifest) return projectedNodeIds;
    const projected = new Set(projectedNodeIds);
    const missing = [
      ...manifest.reportingExpectedNodeIds,
      ...manifest.closeoutExpectedNodeIds,
    ].filter((nodeId) => !projected.has(nodeId));
    if (missing.length > 0) {
      throw new Error(`Terminal memory projection omitted ${missing.length} selected Context Pack node(s)`);
    }
    return projectedNodeIds;
  }

  private resolveRunModelBinding(input: {
    readonly missionId: string;
    readonly runId: string;
    readonly agentId: string;
    readonly modelConfigurationHash: string;
    readonly expectedProviderId: string;
    readonly expectedModelId: string;
  }): RuntimeModelBindingReceipt {
    const bindings = this.options.agentRuntimeBindings;
    if (!bindings) {
      throw new CommandRuntimeError(
        503,
        "autonomous_runtime_model_binding_unavailable",
        "The production Autonomous model-binding service is unavailable",
        {
          humanMessage: "Safe-stopped before planning because the exact signed specialist model could not be bound to runtime execution.",
          retryable: false,
          category: "dependency_missing",
          remediation: "Restore AgentRuntimeBindingService and start a new run from the unchanged reviewed contract.",
        },
      );
    }
    let resolved;
    try {
      resolved = bindings.resolveRun({
        missionId: input.missionId,
        runId: input.runId,
        agentId: input.agentId as ProductAgentId,
      });
    } catch (error) {
      if (!(error instanceof AgentRuntimeBindingError)) throw error;
      throw new CommandRuntimeError(409, error.code, error.message, {
        humanMessage: "Safe-stopped because the selected specialist no longer matches its exact launch-pinned model assignment.",
        retryable: false,
        category: "policy_denied",
        remediation: error.remediation,
      });
    }
    const configuration = resolved.primaryConfiguration;
    if (
      configuration.providerId !== input.expectedProviderId
      || configuration.modelId !== input.expectedModelId
      || !/^[a-f0-9]{64}$/u.test(input.modelConfigurationHash)
    ) {
      throw new CommandRuntimeError(
        409,
        "autonomous_runtime_model_assignment_mismatch",
        `Pinned model ${configuration.providerId}/${configuration.modelId} for ${input.agentId} does not match the reviewed runtime route ${input.expectedProviderId}/${input.expectedModelId}`,
        {
          humanMessage: "Safe-stopped because the operator-selected specialist model does not match the reviewed executable runtime route.",
          retryable: false,
          category: "policy_denied",
          remediation: "Use a trusted runtime binding for the exact selected provider/model, or review a new contract with an available compatible model.",
        },
      );
    }
    return Object.freeze({
      schemaVersion: "ti-scale.runtime-model-binding.v1",
      agentId: resolved.productAgentId,
      modelAssignmentId: resolved.modelAssignmentId,
      modelConfigurationId: resolved.primaryConfigurationId,
      modelConfigurationHash: modelConfigurationBindingHash(configuration),
      providerConfigurationHash: input.modelConfigurationHash,
      providerId: configuration.providerId,
      modelId: configuration.modelId,
      reasoningEffort: configuration.reasoningEffort,
    });
  }

  private resolvePlanningModelBinding(input: Readonly<{
    missionId: string;
    runId: string;
    agentId: string;
    modelAssignmentId: string;
    primaryConfigurationId: string;
    primaryConfigurationHash: string;
    expectedProviderId?: string;
    expectedModelId?: string;
    providerConfigurationHash?: string;
  }>): RuntimeModelBindingReceipt {
    const assignment = this.database.prepare(`
      SELECT id, agent_id, primary_configuration_id
      FROM agent_model_assignments
      WHERE id = ? AND mission_id = ? AND run_id = ? AND step_id IS NULL
        AND assignment_purpose = 'planning' AND pinned = 1
    `).get(
      input.modelAssignmentId,
      input.missionId,
      input.runId,
    ) as {
      id: string;
      agent_id: string;
      primary_configuration_id: string;
    } | undefined;
    const configuration = assignment
      ? new ModelConfigurationRepository(this.database).getConfiguration(
          assignment.primary_configuration_id,
        )
      : undefined;
    if (
      !assignment ||
      !configuration ||
      assignment.agent_id !== input.agentId ||
      assignment.primary_configuration_id !== input.primaryConfigurationId ||
      (
        input.expectedProviderId !== undefined
        && configuration.providerId !== input.expectedProviderId
      ) ||
      (
        input.expectedModelId !== undefined
        && configuration.modelId !== input.expectedModelId
      ) ||
      configuration.enforcementMode !== "advisor_only" ||
      configuration.authState !== "authenticated" ||
      configuration.healthState !== "healthy" ||
      modelConfigurationBindingHash(configuration) !==
        input.primaryConfigurationHash ||
      (
        input.providerConfigurationHash !== undefined
        && input.providerConfigurationHash !== input.primaryConfigurationHash
      )
    ) {
      throw new CommandRuntimeError(
        409,
        "autonomous_activation_planner_pin_mismatch",
        "The provider-advisory planner no longer matches its exact purpose=planning model pin",
        {
          humanMessage: "Safe-stopped before provider contact because the planner assignment or immutable advisor-only model configuration drifted from the aggregate activation receipt.",
          retryable: false,
          category: "policy_denied",
          remediation: "Restore the exact healthy advisor-only planning pin or start a new run with a newly reviewed contract.",
        },
      );
    }
    return Object.freeze({
      schemaVersion: "ti-scale.runtime-model-binding.v1",
      agentId: input.agentId,
      modelAssignmentId: assignment.id,
      modelConfigurationId: configuration.id,
      modelConfigurationHash: input.primaryConfigurationHash,
      providerConfigurationHash:
        input.providerConfigurationHash ?? input.primaryConfigurationHash,
      providerId: configuration.providerId,
      modelId: configuration.modelId,
      reasoningEffort: configuration.reasoningEffort,
    });
  }

  private bindAutonomousPlanModels(
    missionId: string,
    runId: string,
    plan: MissionPlanDraft,
  ): MissionPlanDraft {
    if (!this.options.agentRuntimeBindings) return plan;
    const planner = this.options.planner as MissionRuntimeOptions["planner"] & {
      readonly localPlanningBoundary?: Readonly<{
        readonly bindings?: readonly Readonly<Record<string, unknown>>[];
      }>;
      readonly autonomousExecutionBindings?:
        readonly Readonly<Record<string, unknown>>[];
    };
    const localBindings = planner.autonomousExecutionBindings
      ?? planner.localPlanningBoundary?.bindings;
    const steps = plan.steps.map((step) => {
      let providerId: string;
      let modelId: string;
      let modelConfigurationHash: string;
      if (localBindings) {
        const candidates = localBindings.filter((candidate) => {
          const candidateAgentId = typeof candidate.agentId === "string"
            ? candidate.agentId.trim()
            : "";
          const exactAgent = candidateAgentId === step.assignedAgentId;
          const reviewedRuntimeBinding = agentAssignmentBindsRuntimeAgent(
            this.database,
            step.assignedAgentId,
            candidateAgentId,
          );
          if (
            (!exactAgent && !reviewedRuntimeBinding)
            || candidate.actionClassId !== step.action.actionClass
          ) return false;
          if (candidate.executionBinding === "reviewed_local_process") {
            return step.action.arguments.executionBinding === "reviewed_local_process"
              && candidate.toolId === step.action.arguments.toolId;
          }
          return candidate.mcpServerId === step.action.arguments.mcpServer
            && candidate.toolName === step.action.arguments.toolName;
        });
        if (candidates.length !== 1) {
          throw new CommandRuntimeError(
            409,
            "autonomous_runtime_model_route_ambiguous",
            `Plan step ${step.title} does not map to exactly one reviewed planner model route`,
            {
              humanMessage: "Safe-stopped because this planned action could not be tied to one exact trusted specialist/model route.",
              retryable: false,
              category: "policy_denied",
              remediation: "Correct the trusted local planning policy so this exact agent/action/tool tuple has one route.",
            },
          );
        }
        const candidate = candidates[0]!;
        providerId = String(candidate.providerId ?? "");
        modelId = String(candidate.modelId ?? "");
        modelConfigurationHash = String(candidate.modelConfigurationHash ?? "");
      } else {
        throw new CommandRuntimeError(
          503,
          "autonomous_runtime_model_route_missing",
          "No trusted specialist execution model route is mounted",
          {
            humanMessage: "Safe-stopped because the planned action has no trusted specialist provider/model route.",
            retryable: false,
            category: "dependency_missing",
          },
        );
      }
      return {
        ...step,
        runtimeModelBinding: this.resolveRunModelBinding({
          missionId,
          runId,
          agentId: step.assignedAgentId,
          modelConfigurationHash,
          expectedProviderId: providerId,
          expectedModelId: modelId,
        }),
      };
    });
    return { ...plan, steps };
  }

  private readAutonomousPlanningPolicy(
    missionId: string,
    runId: string,
  ): AutonomousPlanningPolicyProjection {
    const row = this.database.prepare(`
      SELECT
        run.mission_id,
        run.journey,
        run.contract_hash_bound,
        contract.contract_hash,
        contract.state AS contract_state,
        contract.action_policy_json
      FROM runs AS run
      JOIN mission_contracts AS contract ON contract.id = run.contract_id
      WHERE run.id = ?
    `).get(runId) as {
      readonly mission_id: string;
      readonly journey: string;
      readonly contract_hash_bound: string | null;
      readonly contract_hash: string;
      readonly contract_state: string;
      readonly action_policy_json: string;
    } | undefined;
    let parsed: unknown;
    try {
      parsed = row ? JSON.parse(row.action_policy_json) as unknown : null;
    } catch {
      parsed = null;
    }
    const policy = parsed !== null
      && typeof parsed === "object"
      && !Array.isArray(parsed)
      ? parsed as Readonly<Record<string, unknown>>
      : undefined;
    const stringList = (
      value: unknown,
      label: string,
    ): readonly string[] => {
      if (
        !Array.isArray(value)
        || value.some((item) => typeof item !== "string" || !item.trim())
      ) {
        throw new CommandRuntimeError(
          409,
          "autonomous_planning_policy_invalid",
          `${label} is not a canonical identifier list`,
          {
            humanMessage: "Safe-stopped before planning because the confirmed Autonomous action policy is malformed.",
            retryable: false,
            category: "policy_denied",
            remediation: "Create a new reviewed contract with a valid action policy and specialist assignment set.",
          },
        );
      }
      const normalized = (value as readonly string[]).map((item) =>
        item.trim());
      if (new Set(normalized).size !== normalized.length) {
        throw new CommandRuntimeError(
          409,
          "autonomous_planning_policy_invalid",
          `${label} contains duplicate identifiers`,
          {
            humanMessage: "Safe-stopped before planning because the confirmed Autonomous action policy is not canonical.",
            retryable: false,
            category: "policy_denied",
          },
        );
      }
      return Object.freeze(normalized);
    };
    if (
      !row
      || row.mission_id !== missionId
      || row.journey !== "autonomous"
      || row.contract_state !== "confirmed"
      || row.contract_hash_bound !== row.contract_hash
      || !/^[a-f0-9]{64}$/u.test(row.contract_hash)
      || !policy
      || !policy.planningSelection
    ) {
      throw new CommandRuntimeError(
        409,
        "autonomous_planning_contract_unavailable",
        "No exact confirmed Autonomous planning contract is bound to this run",
        {
          humanMessage: "Safe-stopped before planning because this run is not bound to one unchanged confirmed Autonomous contract.",
          retryable: false,
          category: "policy_denied",
          remediation: "Create a new run from the reviewed contract; do not infer a planning route.",
        },
      );
    }
    const allowed = stringList(
      policy.allowedActionClasses,
      "Allowed action classes",
    );
    const prohibited = stringList(
      policy.prohibitedActionClasses,
      "Prohibited action classes",
    );
    const specialists = stringList(
      policy.specialistAgentIds,
      "Specialist agent IDs",
    );
    if (
      allowed.some((id) => !isActionClassId(id))
      || prohibited.some((id) => !isActionClassId(id))
      || allowed.some((id) => prohibited.includes(id))
    ) {
      throw new CommandRuntimeError(
        409,
        "autonomous_planning_action_policy_invalid",
        "The signed action policy contains unknown or conflicting action classes",
        {
          humanMessage: "Safe-stopped before planning because the signed action-class matrix is not internally consistent.",
          retryable: false,
          category: "policy_denied",
          remediation: "Review the action-class matrix and create a new confirmed run contract.",
        },
      );
    }
    return Object.freeze({
      contractHash: row.contract_hash,
      selection: policy.planningSelection as AutonomousPlanningSelection,
      allowedActionClassIds: Object.freeze(allowed as readonly ActionClassId[]),
      prohibitedActionClassIds: Object.freeze(
        prohibited as readonly ActionClassId[],
      ),
      specialistAgentIds: specialists,
    });
  }

  private providerAdvisoryCandidateInput(input: Readonly<{
    mission: MissionPlannerInput["mission"];
    run: MissionPlannerInput["run"];
    activation: ReturnType<AutonomousActivationRuntimePort["verifyCurrent"]>;
    policy: AutonomousPlanningPolicyProjection;
    localPolicyHash: string;
    localPlan: MissionPlanDraft;
    planningRequestId: string;
    contextPackId: string;
  }>): BuildProviderAdvisoryCatalogInput {
    const receiptItems = new Map<string, readonly EvidenceTypeId[]>();
    for (const item of input.activation.items) {
      if (
        !isActionClassId(item.actionClassId)
        || !Array.isArray(item.evidenceTypeIds)
        || item.evidenceTypeIds.length === 0
        || item.evidenceTypeIds.some((id) => !isEvidenceTypeId(id))
        || receiptItems.has(item.actionClassId)
      ) {
        throw new CommandRuntimeError(
          409,
          "autonomous_activation_evidence_projection_invalid",
          "The verified activation receipt has an invalid evidence route projection",
          {
            humanMessage: "Safe-stopped before provider contact because the activated action/evidence routes are incomplete or ambiguous.",
            retryable: false,
            category: "policy_denied",
            remediation: "Repair the exact tool/evidence activation and issue a fresh run activation receipt.",
          },
        );
      }
      receiptItems.set(
        item.actionClassId,
        Object.freeze([...item.evidenceTypeIds] as EvidenceTypeId[]),
      );
    }
    const candidates = input.localPlan.steps.map((step) => {
      if (!isActionClassId(step.action.actionClass)) {
        throw new CommandRuntimeError(
          409,
          "autonomous_local_candidate_action_class_invalid",
          "A locally compiled candidate uses an unregistered action class",
          {
            humanMessage: "Safe-stopped before provider contact because a local candidate is not represented by the signed Action Class Registry.",
            retryable: false,
            category: "policy_denied",
          },
        );
      }
      const evidenceTypeIds = receiptItems.get(step.action.actionClass);
      const definition = ACTION_CLASS_DEFINITION_BY_ID.get(
        step.action.actionClass,
      );
      if (!evidenceTypeIds || !definition) {
        throw new CommandRuntimeError(
          409,
          "autonomous_activation_evidence_route_missing",
          `No verified evidence route exists for ${step.action.actionClass}`,
          {
            humanMessage: "Safe-stopped before provider contact because a local plan candidate is not covered by the current verified activation receipt.",
            retryable: false,
            category: "policy_denied",
            remediation: "Activate the exact action class, tool, specialist, and evidence route before starting a fresh planning attempt.",
          },
        );
      }
      return Object.freeze({
        publicSummary: Object.freeze({
          // Registry semantics are deliberately independent of target, tool,
          // specialist, model, and local planner rationale.
          phase: definition.label,
          purpose: definition.plainLanguageDescription,
        }),
        step,
        requiredEvidenceTypeIds: evidenceTypeIds,
      });
    });
    const catalogInput: BuildProviderAdvisoryCatalogInput = Object.freeze({
      planningRequestId: input.planningRequestId,
      contractHash: input.policy.contractHash,
      policyHash: input.localPolicyHash,
      contextPackId: input.contextPackId,
      allowedTargets: Object.freeze([...input.mission.allowedTargets]),
      allowedActionClassIds: input.policy.allowedActionClassIds,
      prohibitedActionClassIds: input.policy.prohibitedActionClassIds,
      allowedAgentIds: input.policy.specialistAgentIds,
      maximumSteps: Math.min(this.maxPlanSteps, 24),
      candidates: Object.freeze(candidates),
    });
    // Validate the complete local-only catalog before a provider turn or
    // disclosure audit is opened.
    buildProviderAdvisoryCandidateCatalog(catalogInput);
    return catalogInput;
  }

  private providerAdvisoryOpaqueTerms(
    catalog: BuildProviderAdvisoryCatalogInput,
  ): readonly string[] {
    const terms = new Set<string>(catalog.allowedTargets);
    const add = (value: unknown): void => {
      if (typeof value === "string") {
        const normalized = value.trim();
        if (
          normalized.length >= 3
          && Buffer.byteLength(normalized, "utf8") <= 512
        ) {
          terms.add(normalized);
        }
      }
    };
    const LOCAL_IDENTIFIER_KEYS = [
      "toolId",
      "toolName",
      "mcpServer",
      "mcpServerId",
      "agentId",
      "providerId",
      "modelId",
      "modelConfigurationId",
      "modelAssignmentId",
      "target",
      "exactTarget",
      "url",
      "host",
      "hostname",
      "domain",
    ] as const;
    for (const candidate of catalog.candidates) {
      add(candidate.step.assignedAgentId);
      add(candidate.step.action.actionType);
      const argumentsRecord = candidate.step.action.arguments;
      for (const key of LOCAL_IDENTIFIER_KEYS) add(argumentsRecord[key]);
      const parameters = argumentsRecord.parameters;
      if (parameters && typeof parameters === "object" && !Array.isArray(parameters)) {
        for (const key of LOCAL_IDENTIFIER_KEYS) {
          add((parameters as Readonly<Record<string, unknown>>)[key]);
        }
      }
      if (candidate.step.runtimeModelBinding) {
        for (const value of Object.values(candidate.step.runtimeModelBinding)) {
          add(value);
        }
      }
    }
    const result = [...terms].sort((left, right) =>
      right.length - left.length || left.localeCompare(right));
    if (result.length > 128) {
      throw new CommandRuntimeError(
        409,
        "provider_advisory_opaque_binding_bound_exceeded",
        "The local candidate catalog has too many disclosure-redaction bindings",
        {
          humanMessage: "Safe-stopped before provider contact because the finite local plan exceeds the audited disclosure-redaction bound.",
          retryable: false,
          category: "policy_denied",
          remediation: "Reduce the bounded candidate set or split it into a new plan version; do not truncate disclosure protections.",
        },
      );
    }
    return Object.freeze(result);
  }

  private providerAdvisorySafeStopError(
    safeStop: ProviderAdvisoryRuntimeSafeStop,
  ): CommandRuntimeError {
    const category: FailureCategory =
      safeStop.category === "rate_limit"
        ? "rate_limit"
        : safeStop.category === "timeout"
          ? "timeout"
          : safeStop.category === "authentication_missing"
            ? "authentication_missing"
            : safeStop.category === "authentication_failed"
              ? "authentication_missing"
              : safeStop.category === "provider_unavailable"
                ? "provider_unavailable"
                : safeStop.category === "provider_refused"
                  ? "invalid_input"
                  : safeStop.category === "audit_unavailable"
                    ? "dependency_missing"
                    : "provider_unavailable";
    return new CommandRuntimeError(
      safeStop.category === "provider_refused" ? 502 : 503,
      safeStop.code,
      safeStop.humanReason,
      {
        humanMessage: safeStop.humanReason,
        retryable: safeStop.retryable,
        category,
        remediation: safeStop.remediation,
        details: {
          providerAdvisoryCategory: safeStop.category,
          providerTurnId: safeStop.providerTurnId,
          planningRequestId: safeStop.planningRequestId,
          localCandidatesPreserved: true,
          localFallbackApplied: false,
          ...(safeStop.retryAfterMs === undefined
            ? {}
            : { retryAfterMs: safeStop.retryAfterMs }),
          ...(safeStop.httpStatus === undefined
            ? {}
            : { httpStatus: safeStop.httpStatus }),
        },
      },
    );
  }

  private startPlanningProviderTurn(input: {
    readonly runId: string;
    readonly providerId: string;
    readonly modelId: string;
    readonly modelConfigurationHash: string;
    readonly runtimeModelBinding?: RuntimeModelBindingReceipt;
  }): PlanningProviderTurn {
    const providerId = input.providerId.trim();
    const modelId = input.modelId.trim();
    const modelConfigurationHash = input.modelConfigurationHash.trim();
    if (!providerId || !modelId || !/^[a-f0-9]{64}$/u.test(modelConfigurationHash)) {
      throw new CommandRuntimeError(
        500,
        "planning_provider_identity_invalid",
        "Public planning provider binding is incomplete",
        {
          humanMessage: "Planning stopped before provider disclosure because the provider, model, or immutable model-configuration binding is invalid.",
          retryable: false,
          category: "dependency_missing",
          remediation: "Resolve and pin one concrete provider/model configuration before starting a new public-provider turn.",
        },
      );
    }
    const id = `provider-turn-${randomUUID()}`;
    this.database.prepare(`
      INSERT INTO provider_turns (
        id, run_id, provider, model, model_configuration_hash,
        agent_id, model_assignment_id, model_configuration_id,
        model_assignment_configuration_hash,
        status, started_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'started', ?)
    `).run(
      id,
      input.runId,
      providerId,
      modelId,
      modelConfigurationHash,
      input.runtimeModelBinding?.agentId ?? null,
      input.runtimeModelBinding?.modelAssignmentId ?? null,
      input.runtimeModelBinding?.modelConfigurationId ?? null,
      input.runtimeModelBinding?.modelConfigurationHash ?? null,
      this.timestamp(),
    );
    return {
      id,
      providerId,
      modelId,
      modelConfigurationHash,
      startedAt: performance.now(),
      ...(input.runtimeModelBinding
        ? { runtimeModelBinding: input.runtimeModelBinding }
        : {}),
    };
  }

  private finishPlanningProviderTurn(input: {
    readonly turn: PlanningProviderTurn;
    readonly status: "completed" | "failed" | "cancelled";
    readonly usage?: ProviderUsageReport;
    readonly errorCategory?: string;
  }): void {
    const totalTokens = input.usage?.totalTokens ?? input.usage?.providerTokens ?? null;
    const billedCostUsd = input.usage?.billedCostUsd ?? input.usage?.estimatedCost ?? null;
    this.database.prepare(`
      UPDATE provider_turns SET
        status = ?, input_tokens = ?, output_tokens = ?, total_tokens = ?,
        billed_cost_usd = ?, estimated_cost = ?, returned_model = ?,
        exact_token_usage = ?, exact_cost_usage = ?,
        latency_ms = ?, error_category = ?, ended_at = ?
      WHERE id = ? AND status = 'started'
    `).run(
      input.status,
      input.usage?.inputTokens ?? null,
      input.usage?.outputTokens ?? null,
      totalTokens,
      billedCostUsd,
      billedCostUsd,
      input.usage?.returnedModel ?? null,
      input.usage ? Number(input.usage.exactTokenUsage) : null,
      input.usage ? Number(input.usage.exactCostUsage) : null,
      input.usage?.latencyMs ?? Math.max(0, Math.round(performance.now() - input.turn.startedAt)),
      input.errorCategory ?? null,
      this.timestamp(),
      input.turn.id,
    );
  }

  private bindPlanningProviderUsage(
    usage: ProviderUsageReport | undefined,
    turn: PlanningProviderTurn,
  ): ProviderUsageReport {
    const mismatch = (message: string): never => {
      throw new CommandRuntimeError(
        502,
        "planning_provider_usage_mismatch",
        message,
        {
          humanMessage: "Planning stopped because the provider telemetry could not be bound to the audited request.",
          retryable: false,
          category: "invalid_input",
          remediation: "Repair the planning adapter so it reports identity and exact usage only for the current canonical provider turn.",
        },
      );
    };
    if (usage?.providerTurnId && usage.providerTurnId !== turn.id) {
      mismatch("Planning usage references another provider turn");
    }
    if (usage?.providerId !== undefined && usage.providerId.trim() !== turn.providerId) {
      mismatch("Planning usage references another provider");
    }
    if (usage?.requestedModel !== undefined && usage.requestedModel.trim() !== turn.modelId) {
      mismatch("Planning usage references another requested model");
    }
    if (usage?.providerTurns !== undefined && usage.providerTurns !== 1) {
      mismatch("Planning usage for one canonical provider turn must report exactly one turn");
    }
    const totalTokens = usage?.totalTokens ?? usage?.providerTokens;
    if (
      usage?.totalTokens !== undefined && usage.providerTokens !== undefined &&
      usage.totalTokens !== usage.providerTokens
    ) {
      mismatch("Planning usage reports conflicting total-token values");
    }
    const billedCostUsd = usage?.billedCostUsd ?? usage?.estimatedCost;
    if (
      usage?.billedCostUsd !== undefined && usage.estimatedCost !== undefined &&
      usage.billedCostUsd !== usage.estimatedCost
    ) {
      mismatch("Planning usage reports conflicting billed-cost values");
    }
    const nonNegativeInteger = (value: number | undefined): boolean =>
      value === undefined || (Number.isSafeInteger(value) && value >= 0);
    if (
      !nonNegativeInteger(usage?.inputTokens) || !nonNegativeInteger(usage?.outputTokens) ||
      !nonNegativeInteger(totalTokens) || !nonNegativeInteger(usage?.latencyMs) ||
      (billedCostUsd !== undefined && (!Number.isFinite(billedCostUsd) || billedCostUsd < 0))
    ) {
      mismatch("Planning usage contains invalid telemetry values");
    }
    if (usage?.returnedModel !== undefined && (
      !usage.returnedModel.trim() || Buffer.byteLength(usage.returnedModel.trim(), "utf8") > 256
    )) {
      mismatch("Planning usage contains an invalid returned model");
    }
    if (usage?.exactTokenUsage === true && (
      usage.inputTokens === undefined || usage.outputTokens === undefined || totalTokens === undefined ||
      totalTokens < usage.inputTokens + usage.outputTokens
    )) {
      mismatch("Planning usage marks incomplete token telemetry as exact");
    }
    if (usage?.exactCostUsage === true && billedCostUsd === undefined) {
      mismatch("Planning usage marks missing billed cost as exact");
    }
    return {
      ...(usage ?? { exactTokenUsage: false, exactCostUsage: false }),
      providerTurnId: turn.id,
      providerTurns: usage?.providerTurns ?? 1,
      providerId: turn.providerId,
      requestedModel: turn.modelId,
      ...(usage?.returnedModel === undefined ? {} : { returnedModel: usage.returnedModel.trim() }),
      ...(totalTokens === undefined ? {} : { totalTokens, providerTokens: totalTokens }),
      ...(billedCostUsd === undefined ? {} : { billedCostUsd, estimatedCost: billedCostUsd }),
    };
  }

  /**
   * Terminal learning is idempotent at the evaluation row. Lifecycle context
   * selection and its projection manifest are committed with the first
   * evaluation; the optional Vault/memory projection itself remains a durable
   * post-commit continuation.
   */
  private recordTerminalEvaluationWithBrain(input: {
    readonly runId: string;
    readonly terminalStatus: "completed" | "failed" | "cancelled";
    readonly createdBy: string;
    readonly outcome?: MissionCompletionEvaluation;
    readonly evaluationContextAlreadyRetrieved?: boolean;
    readonly terminalReportCommitment?: CanonicalReportArtifactCommitment;
  }): void {
    const prior = this.database.prepare(`
      SELECT id FROM run_evaluations WHERE run_id = ? LIMIT 1
    `).get(input.runId) as { id: string } | undefined;
    if (prior) {
      this.continuations.enqueue({
        runId: input.runId,
        kind: "memory_projection_pending",
        sourceId: prior.id,
        now: this.timestamp(),
      });
      return;
    }
    const run = this.repository.getPlanningRun(input.runId);
    const mission = this.repository.getMission(run.missionId);
    if (!input.evaluationContextAlreadyRetrieved) {
      const evaluationContext = this.retrieveBrainContext({
        hook: "evaluation",
        mission,
        run,
        actorId: input.createdBy,
        query: `Evaluate the terminal ${run.journey} mission outcome, evidence quality, failures, recoveries, and journey adherence.`,
        queryRedacted: "Evaluate terminal mission outcome, evidence quality, failures, recoveries, and journey adherence.",
        terminalSafe: true,
      });
      this.brainContext.recordUnusedContext(
        evaluationContext,
        "The deterministic terminal evaluation writer used canonical local run metrics; retrieved memory was retained for audit context and did not alter the terminal outcome.",
      );
    }
    const lessonContext = this.retrieveBrainContext({
      hook: "lesson_proposal",
      mission,
      run,
      actorId: input.createdBy,
      query: "Retrieve related verified lessons, counterexamples, failures, and evaluations before proposing reviewable learning.",
      queryRedacted: "Retrieve related verified lessons, counterexamples, failures, and evaluations before proposing reviewable learning.",
      terminalSafe: true,
    });
    const terminalLessonMemoryApplication = run.journey === "autonomous"
      && input.terminalStatus !== "cancelled"
      ? this.learning.compileTerminalLessonMemoryApplication({
          runId: run.id,
          terminalStatus: input.terminalStatus,
          context: lessonContext,
        })
      : undefined;
    if (terminalLessonMemoryApplication) {
      this.brainContext.recordContextDispositions(
        lessonContext,
        terminalLessonMemoryApplication.contextDispositions,
      );
    } else {
      this.brainContext.recordUnusedContext(
        lessonContext,
        run.journey === "autonomous"
          ? "Cancelled runs do not propose reusable learning; retrieved memory did not alter the terminal record."
          : "Guided terminal learning remains review-context only; retrieved memory did not rewrite or self-approve the candidate.",
      );
    }
    const evaluation = this.learning.recordTerminalEvaluation({
      runId: input.runId,
      terminalStatus: input.terminalStatus,
      createdBy: input.createdBy,
      ...(input.outcome ? { outcome: input.outcome } : {}),
      ...(terminalLessonMemoryApplication
        ? { terminalLessonMemoryApplication }
        : {}),
      ...(input.terminalReportCommitment
        ? { terminalReportCommitment: input.terminalReportCommitment }
        : {}),
    });
    const terminalProjectionNodeIds = new Set(
      this.memoryGraph.ensureEvaluation(evaluation.id).nodeIds,
    );
    for (const row of this.database.prepare(`
      SELECT DISTINCT lesson_id FROM lesson_evidence WHERE run_id = ?
    `).all(run.id) as Array<{ lesson_id: string }>) {
      terminalProjectionNodeIds.add(canonicalLessonMemoryNodeId(row.lesson_id));
    }
    const reportingContext = this.retrieveBrainContext({
      hook: "reporting",
      mission,
      run,
      actorId: input.createdBy,
      query: "Retrieve confirmed report context and evidence-linked outcomes needed to verify the terminal projection.",
      queryRedacted: "Retrieve confirmed report context and evidence-linked outcomes needed to verify the terminal projection.",
      lifecyclePreferenceNodeIds: this.brainContext.resolveLifecyclePreferenceNodeIds({
        missionId: mission.id,
        operatorId: mission.createdBy,
        journey: run.journey,
        hook: "reporting",
        preferenceKeys: [
          "communication.technical_readability",
          "communication.evidence_first",
        ],
      }),
      terminalSafe: true,
    });
    const reportingExpectedNodeIds = this.recordTypedBrainContextUse({
      context: reportingContext,
      allowedTypes: REPORTING_PROJECTION_CONTEXT_TYPES,
      allowedNodeIds: terminalProjectionNodeIds,
      influenceSummary: "Selected as a durable integrity expectation for the post-commit terminal report projection; canonical evaluation records and evidence links remained authoritative.",
      ignoredReason: "This retrieved item is not an evaluation or lesson node emitted by the terminal reporting projection, so it was retained as unused context.",
    });
    const closeoutContext = this.retrieveBrainContext({
      hook: "closeout",
      mission,
      run,
      actorId: input.createdBy,
      query: "Retrieve the bounded mission cluster needed to verify the terminal outcome and evidence-linked learning projection.",
      queryRedacted: "Retrieve the bounded mission cluster needed to verify the terminal outcome and evidence-linked learning projection.",
      terminalSafe: true,
    });
    const closeoutExpectedNodeIds = this.recordTypedBrainContextUse({
      context: closeoutContext,
      allowedTypes: CLOSEOUT_PROJECTION_CONTEXT_TYPES,
      allowedNodeIds: terminalProjectionNodeIds,
      influenceSummary: "Selected as a durable integrity expectation for the post-commit mission-cluster projection; it did not alter terminal status or immutable evidence.",
      ignoredReason: "This retrieved item is not a mission, run, evaluation, or lesson anchor emitted by the terminal closeout projection, so it was retained as unused context.",
    });
    this.repository.events.append({
      missionId: mission.id,
      runId: run.id,
      journey: run.journey,
      eventType: "brain.terminal_projection_context_selected",
      actorType: "agent",
      actorId: input.createdBy,
      summary: "Terminal reporting and closeout Context Packs were bound to a post-commit projection integrity manifest.",
      payload: {
        evaluationId: evaluation.id,
        reportingContextPackId: reportingContext.contextPack.id,
        closeoutContextPackId: closeoutContext.contextPack.id,
        reportingExpectedNodeIds: [...reportingExpectedNodeIds],
        closeoutExpectedNodeIds: [...closeoutExpectedNodeIds],
      },
    });
    // Enqueue in the same enclosing transaction as the canonical evaluation.
    // The handler itself runs only after commit and is owner-fenced/replayable.
    this.continuations.enqueue({
      runId: input.runId,
      kind: "memory_projection_pending",
      sourceId: evaluation.id,
      now: this.timestamp(),
    });
  }

  private commitTerminalAtomically<T>(
    runId: string,
    terminalStatus: "completed" | "failed" | "cancelled",
    commit: (reportCommitment?: CanonicalReportArtifactCommitment) => T,
  ): T {
    const run = this.database.prepare("SELECT journey FROM runs WHERE id = ?")
      .get(runId) as { journey: "autonomous" | "guided" } | undefined;
    if (!run) throw new Error(`Terminal run ${runId} no longer exists`);
    if (
      run.journey === "autonomous"
      && terminalStatus !== "cancelled"
      && this.options.autonomousTerminalDeliverables
    ) {
      return this.options.autonomousTerminalDeliverables.completeAtomically(
        runId,
        (reportCommitment) => commit(reportCommitment ?? undefined),
      ).terminal;
    }
    return inImmediateTransaction(this.database, () => commit());
  }

  /**
   * A run-control receipt is written in the same transaction as the durable
   * transition. It is deliberately keyed by a one-way command digest rather
   * than the caller's raw Idempotency-Key. This closes the narrow window where
   * the process can die after runtime commit but before the HTTP receipt is
   * promoted from pending to completed.
   */
  private recoverCurrentRunControlCommand(
    runId: string,
    action: "run.paused" | "run.resumed",
    commandId: string | undefined,
  ): boolean {
    if (!commandId) return false;
    const marker = this.database.prepare(`
      SELECT
        json_extract(details_json, '$.committedRunVersion') AS committed_run_version,
        json_extract(details_json, '$.checkpointId') AS checkpoint_id,
        json_extract(details_json, '$.checkpointEventSequence') AS checkpoint_event_sequence
      FROM audit_records
      WHERE run_id = ? AND action = ?
        AND json_extract(details_json, '$.commandId') = ?
      ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get(runId, action, commandId) as {
      committed_run_version: number | null;
      checkpoint_id: string | null;
      checkpoint_event_sequence: number | null;
    } | undefined;
    if (!marker) return false;

    const current = this.repository.getRunProjection(runId);
    const checkpoint = this.coordinator.getLatestCheckpoint(runId);
    if (
      !Number.isSafeInteger(marker.committed_run_version) ||
      current.version !== marker.committed_run_version ||
      !checkpoint ||
      checkpoint.id !== marker.checkpoint_id ||
      checkpoint.eventSequence !== marker.checkpoint_event_sequence
    ) {
      throw new CommandRuntimeError(
        409,
        "run_control_command_replay_stale",
        "The committed run-control result is no longer the current durable boundary",
        {
          humanMessage: "This command committed, but the run changed before its lost response was recovered.",
          category: "conflict",
          remediation: "Refresh the run and use a new command only for the current represented state.",
        },
      );
    }
    return true;
  }

  private activeCancellationCommand(runId: string): {
    readonly eventId: string;
    readonly commandId: string | null;
  } | null {
    const marker = this.database.prepare(`
      SELECT request.id AS event_id,
        json_extract(request.payload_json, '$.commandId') AS command_id
      FROM events request
      WHERE request.run_id = ?
        AND request.event_type = 'run.cancellation_requested'
        AND NOT EXISTS (
          SELECT 1 FROM events terminal
          WHERE terminal.run_id = request.run_id
            AND terminal.sequence > request.sequence
            AND terminal.event_type IN ('run.cancelled', 'run.cancellation_failed')
        )
      ORDER BY request.sequence DESC LIMIT 1
    `).get(runId) as { event_id: string; command_id: string | null } | undefined;
    return marker ? { eventId: marker.event_id, commandId: marker.command_id } : null;
  }

  private hasCancellationCommand(runId: string, commandId: string | undefined): boolean {
    if (!commandId) return false;
    return Boolean(this.database.prepare(`
      SELECT 1 FROM events
      WHERE run_id = ? AND event_type = 'run.cancellation_requested'
        AND json_extract(payload_json, '$.commandId') = ?
      LIMIT 1
    `).get(runId, commandId));
  }

  /**
   * Repair durable execution residue beneath a terminal cancellation. New
   * cancellations close provider work before their terminal checkpoint; this
   * is defense in depth for an older/interrupted process that crossed the
   * terminal commit before its caller-level cleanup completed.
   */
  private reconcileCancelledRunResidue(
    runId: string,
    reason = "Reconciled terminal cancellation residue after restart",
  ): number {
    return inImmediateTransaction(this.database, () => {
      const row = this.database.prepare(`
        SELECT r.mission_id, r.journey, r.status
        FROM runs r JOIN missions m ON m.id = r.mission_id
        WHERE r.id = ? AND r.control_plane = 'ti_scale'
          AND m.control_plane = 'ti_scale'
      `).get(runId) as {
        mission_id: string;
        journey: "autonomous" | "guided";
        status: string;
      } | undefined;
      if (!row || row.status !== "cancelled") return 0;

      const now = this.timestamp();
      let changed = this.repository.cancelOpenWork(runId, "system:recovery", reason, now);
      changed += this.database.prepare(`
        UPDATE runtime_continuations
        SET status = 'cancelled', lease_owner = NULL, lease_expires_at = NULL,
          last_error = ?, updated_at = ?
        WHERE run_id = ? AND kind != 'evaluation_pending'
          AND status IN ('pending', 'processing')
      `).run(reason.slice(0, 512), now, runId).changes;
      changed += this.database.prepare(`
        UPDATE assignments
        SET lease_owner = NULL, lease_acquired_at = NULL,
          last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
        WHERE run_id = ? AND (
          lease_owner IS NOT NULL OR lease_acquired_at IS NOT NULL OR
          last_heartbeat_at IS NOT NULL OR lease_expires_at IS NOT NULL
        )
      `).run(now, runId).changes;
      changed += this.database.prepare(`
        UPDATE runs SET lease_owner = NULL, lease_acquired_at = NULL,
          last_heartbeat_at = NULL, lease_expires_at = NULL,
          current_step_id = NULL, current_owner_id = NULL, updated_at = ?
        WHERE id = ? AND (
          lease_owner IS NOT NULL OR lease_acquired_at IS NOT NULL OR
          last_heartbeat_at IS NOT NULL OR lease_expires_at IS NOT NULL OR
          current_step_id IS NOT NULL OR current_owner_id IS NOT NULL
        )
      `).run(now, runId).changes;
      // A restarted worker cannot possess the prior process's raw control
      // token. Release only that orphaned terminal authority; a live caller
      // with an in-memory token releases it through the normal fenced service.
      if (!this.controlPlaneTokens.has(runId)) {
        changed += this.database.prepare(`
          UPDATE control_plane_leases SET released_at = ?, version = version + 1
          WHERE run_id = ? AND released_at IS NULL
        `).run(now, runId).changes;
      }
      if (changed === 0) return 0;

      const event = this.repository.events.append({
        missionId: row.mission_id,
        runId,
        journey: row.journey,
        eventType: "run.cancellation_residue_reconciled",
        actorType: "system",
        actorId: this.workerId,
        summary: "Closed durable child residue beneath the terminal cancelled run",
        payload: { changedRecords: changed },
      });
      const durable = this.coordinator.getRun(runId);
      new CheckpointRepository(this.database, new ActionRepository(this.database)).create({
        run: durable,
        eventSequence: event.sequence,
        now,
        inFlightClassification: "safe_no_in_flight_action",
      });
      return changed;
    });
  }

  private reconcileAllCancelledRunResidue(): number {
    const journeys = [...this.supportedJourneys];
    if (journeys.length === 0) return 0;
    const placeholders = journeys.map(() => "?").join(", ");
    const runIds = (this.database.prepare(`
      SELECT r.id FROM runs r JOIN missions m ON m.id = r.mission_id
      WHERE r.status = 'cancelled' AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale'
        AND r.journey IN (${placeholders})
      ORDER BY r.updated_at, r.id
    `).all(...journeys) as Array<{ id: string }>).map((row) => row.id);
    return runIds.reduce(
      (total, runId) => total + this.reconcileCancelledRunResidue(runId),
      0,
    );
  }

  /**
   * Repair an interrupted failure commit produced by an older runtime. A
   * terminal failed run can never retain a running step, active specialist,
   * pending decision, provider turn, or authority lease after restart.
   */
  private reconcileFailedRunResidue(runId: string): number {
    return inImmediateTransaction(this.database, () => {
      const row = this.database.prepare(`
        SELECT r.mission_id, r.journey, r.status
        FROM runs r JOIN missions m ON m.id = r.mission_id
        WHERE r.id = ? AND r.control_plane = 'ti_scale'
          AND m.control_plane = 'ti_scale'
      `).get(runId) as {
        mission_id: string;
        journey: "autonomous" | "guided";
        status: string;
      } | undefined;
      if (!row || row.status !== "failed" || !this.supportedJourneys.has(row.journey)) return 0;

      const now = this.timestamp();
      const reason = "Closed durable child residue beneath a terminal failed run after restart";
      let changed = 0;
      changed += this.database.prepare(`
        UPDATE tool_calls SET status = 'failed',
          error_category = COALESCE(error_category, 'process_crash'),
          output_summary = COALESCE(output_summary, ?), ended_at = COALESCE(ended_at, ?)
        WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
          AND status IN ('queued', 'running')
      `).run(reason, now, runId).changes;
      changed += this.database.prepare(`
        UPDATE actions SET status = 'failed', result_summary = COALESCE(result_summary, ?),
          error_category = COALESCE(error_category, 'process_crash'),
          ended_at = COALESCE(ended_at, ?), updated_at = ?
        WHERE run_id = ? AND status IN ('queued', 'running')
      `).run(reason, now, now, runId).changes;
      changed += this.database.prepare(`
        UPDATE plan_steps SET status = 'failed', ended_at = COALESCE(ended_at, ?),
          updated_at = ?
        WHERE run_id = ? AND id = (SELECT current_step_id FROM runs WHERE id = ?)
          AND status IN ('pending', 'ready', 'running', 'waiting_guided_decision', 'blocked', 'recovering')
      `).run(now, now, runId, runId).changes;
      changed += this.database.prepare(`
        UPDATE plan_steps SET status = 'cancelled', ended_at = COALESCE(ended_at, ?),
          updated_at = ?
        WHERE run_id = ? AND id != COALESCE((SELECT current_step_id FROM runs WHERE id = ?), '')
          AND status IN ('pending', 'ready', 'running', 'waiting_guided_decision', 'blocked', 'recovering')
      `).run(now, now, runId, runId).changes;
      changed += this.database.prepare(`
        UPDATE assignments SET status = CASE
            WHEN step_id = (SELECT current_step_id FROM runs WHERE id = ?) THEN 'failed'
            ELSE 'cancelled'
          END,
          ended_at = COALESCE(ended_at, ?), lease_owner = NULL,
          lease_acquired_at = NULL, last_heartbeat_at = NULL,
          lease_expires_at = NULL, updated_at = ?
        WHERE run_id = ? AND status IN ('queued', 'active', 'blocked')
      `).run(runId, now, now, runId).changes;
      changed += this.database.prepare(`
        UPDATE guided_decisions SET status = 'cancelled', decision_actor = 'system:recovery',
          decision_reason = ?, decided_at = COALESCE(decided_at, ?)
        WHERE run_id = ? AND status = 'pending'
      `).run(reason, now, runId).changes;
      changed += this.database.prepare(`
        UPDATE approvals SET status = 'cancelled', decided_by = 'system:recovery',
          decided_at = COALESCE(decided_at, ?)
        WHERE run_id = ? AND status = 'pending'
      `).run(now, runId).changes;
      changed += this.database.prepare(`
        UPDATE provider_turns SET status = 'failed',
          error_category = COALESCE(error_category, 'process_crash'),
          ended_at = COALESCE(ended_at, ?)
        WHERE run_id = ? AND status = 'started'
      `).run(now, runId).changes;
      changed += this.database.prepare(`
        UPDATE runtime_continuations SET status = 'cancelled', lease_owner = NULL,
          lease_expires_at = NULL, last_error = ?, updated_at = ?
        WHERE run_id = ? AND kind != 'evaluation_pending'
          AND status IN ('pending', 'processing')
      `).run(reason, now, runId).changes;
      changed += this.database.prepare(`
        UPDATE plans SET status = 'abandoned'
        WHERE run_id = ? AND status IN ('draft', 'active')
      `).run(runId).changes;
      changed += this.database.prepare(`
        UPDATE runs SET lease_owner = NULL, lease_acquired_at = NULL,
          last_heartbeat_at = NULL, lease_expires_at = NULL,
          current_step_id = NULL, current_owner_id = NULL, updated_at = ?
        WHERE id = ? AND (
          lease_owner IS NOT NULL OR lease_acquired_at IS NOT NULL OR
          last_heartbeat_at IS NOT NULL OR lease_expires_at IS NOT NULL OR
          current_step_id IS NOT NULL OR current_owner_id IS NOT NULL
        )
      `).run(now, runId).changes;
      if (!this.controlPlaneTokens.has(runId)) {
        changed += this.database.prepare(`
          UPDATE control_plane_leases SET released_at = ?, version = version + 1
          WHERE run_id = ? AND released_at IS NULL
        `).run(now, runId).changes;
      }
      if (changed === 0) return 0;

      const event = this.repository.events.append({
        missionId: row.mission_id,
        runId,
        journey: row.journey,
        eventType: "run.failure_residue_reconciled",
        actorType: "system",
        actorId: this.workerId,
        summary: reason,
        payload: { changedRecords: changed, terminalStatus: "failed" },
      });
      const durable = this.coordinator.getRun(runId);
      const checkpoint = new CheckpointRepository(
        this.database,
        new ActionRepository(this.database),
      ).create({
        run: durable,
        eventSequence: event.sequence,
        now,
        inFlightClassification: "safe_no_in_flight_action",
      });
      const latestAction = this.database.prepare(`
        SELECT id, assignment_id, error_category, result_summary
        FROM actions WHERE run_id = ? AND status IN ('failed', 'timed_out', 'denied')
        ORDER BY ended_at DESC, created_at DESC, id DESC LIMIT 1
      `).get(runId) as {
        id: string;
        assignment_id: string | null;
        error_category: FailureCategory | null;
        result_summary: string | null;
      } | undefined;
      if (latestAction) {
        const action = new ActionRepository(this.database).get(latestAction.id);
        this.persistActionFailureDiagnosis({
          action,
          assignmentId: latestAction.assignment_id,
          category: latestAction.error_category ?? "process_crash",
          failureCode: "terminal_failure_residue_reconciled",
          failureMessage: latestAction.result_summary ?? reason,
          directive: "failed",
          reason,
          run: durable,
          eventId: event.id,
          checkpointId: checkpoint.id,
          progressBeforeFailure: durable.control.progress,
          retryable: false,
        });
      }
      return changed;
    });
  }

  /**
   * Repair terminal projections written by an older runtime that completed
   * the evaluation but retained the last active step/owner or child work.
   * A completed run is immutable execution history, never a runnable queue.
   */
  private reconcileCompletedRunResidue(runId: string): number {
    return inImmediateTransaction(this.database, () => {
      const row = this.database.prepare(`
        SELECT r.mission_id, r.journey, r.status
        FROM runs r JOIN missions m ON m.id = r.mission_id
        WHERE r.id = ? AND r.control_plane = 'ti_scale'
          AND m.control_plane = 'ti_scale'
      `).get(runId) as {
        mission_id: string;
        journey: "autonomous" | "guided";
        status: string;
      } | undefined;
      if (!row || row.status !== "completed" || !this.supportedJourneys.has(row.journey)) return 0;

      const now = this.timestamp();
      const reason = "Closed stale active-work projection beneath a terminal completed run";
      let changed = this.repository.cancelOpenWork(runId, "system:recovery", reason, now);
      changed += this.database.prepare(`
        UPDATE assignments
        SET lease_owner = NULL, lease_acquired_at = NULL,
          last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
        WHERE run_id = ? AND (
          lease_owner IS NOT NULL OR lease_acquired_at IS NOT NULL OR
          last_heartbeat_at IS NOT NULL OR lease_expires_at IS NOT NULL
        )
      `).run(now, runId).changes;
      changed += this.database.prepare(`
        UPDATE runs SET current_step_id = NULL, current_owner_id = NULL,
          lease_owner = NULL, lease_acquired_at = NULL,
          last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
        WHERE id = ? AND (
          current_step_id IS NOT NULL OR current_owner_id IS NOT NULL OR
          lease_owner IS NOT NULL OR lease_acquired_at IS NOT NULL OR
          last_heartbeat_at IS NOT NULL OR lease_expires_at IS NOT NULL
        )
      `).run(now, runId).changes;
      if (changed === 0) return 0;

      const event = this.repository.events.append({
        missionId: row.mission_id,
        runId,
        journey: row.journey,
        eventType: "run.completion_residue_reconciled",
        actorType: "system",
        actorId: this.workerId,
        summary: reason,
        payload: { changedRecords: changed, terminalStatus: "completed" },
      });
      const durable = this.coordinator.getRun(runId);
      new CheckpointRepository(this.database, new ActionRepository(this.database)).create({
        run: durable,
        eventSequence: event.sequence,
        now,
        inFlightClassification: "safe_no_in_flight_action",
      });
      return changed;
    });
  }

  private reconcileAllTerminalRunResidue(): number {
    const cancelled = this.reconcileAllCancelledRunResidue();
    const journeys = [...this.supportedJourneys];
    if (journeys.length === 0) return cancelled;
    const placeholders = journeys.map(() => "?").join(", ");
    const failedRunIds = (this.database.prepare(`
      SELECT r.id FROM runs r JOIN missions m ON m.id = r.mission_id
      WHERE r.status = 'failed' AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale' AND r.journey IN (${placeholders})
      ORDER BY r.updated_at, r.id
    `).all(...journeys) as Array<{ id: string }>).map(({ id }) => id);
    const afterFailed = failedRunIds.reduce(
      (total, failedRunId) => total + this.reconcileFailedRunResidue(failedRunId),
      cancelled,
    );
    const completedRunIds = (this.database.prepare(`
      SELECT r.id FROM runs r JOIN missions m ON m.id = r.mission_id
      WHERE r.status = 'completed' AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale' AND r.journey IN (${placeholders})
      ORDER BY r.updated_at, r.id
    `).all(...journeys) as Array<{ id: string }>).map(({ id }) => id);
    return completedRunIds.reduce(
      (total, completedRunId) => total + this.reconcileCompletedRunResidue(completedRunId),
      afterFailed,
    );
  }

  private crashAfterCommit(
    point: Parameters<NonNullable<MissionRuntimeOptions["crashAfterCommit"]>>[0],
    runId: string,
    sourceId?: string,
  ): void {
    if (!this.options.crashAfterCommit) return;
    try {
      this.options.crashAfterCommit(point, {
        runId,
        ...(sourceId ? { sourceId } : {}),
      });
    } catch {
      throw new RuntimeCrashAfterCommit(point);
    }
  }

  private controller(runId: string): AbortController {
    let controller = this.controllers.get(runId);
    if (!controller || controller.signal.aborted) {
      controller = new AbortController();
      this.controllers.set(runId, controller);
    }
    return controller;
  }

  private heartbeat(initial: RunLeaseToken): HeartbeatLease {
    let lease = initial;
    let stopped = false;
    let chain = Promise.resolve();
    const renew = () => {
      if (stopped) return;
      chain = chain.then(() => {
        if (!stopped) {
          this.heartbeatControlPlane(lease.runId);
          lease = this.coordinator.heartbeatRunLease(lease, this.leaseTtlMs);
        }
      });
    };
    const timer = setInterval(renew, Math.max(250, Math.floor(this.leaseTtlMs / 3)));
    return {
      token: async () => { await chain; return lease; },
      stop: async () => {
        stopped = true;
        clearInterval(timer);
        await chain;
        return lease;
      },
    };
  }

  private accountProviderUsage(
    lease: RunLeaseToken,
    usage: ProviderUsageReport | undefined,
    phase: string,
  ): RunLeaseToken {
    const durable = this.coordinator.getRun(lease.runId);
    const tokenLimit = durable.control.budget.limits.providerTokens ?? 0;
    const costLimit = durable.control.budget.limits.estimatedCost ?? 0;
    if (tokenLimit > 0 && usage?.exactTokenUsage !== true) {
      throw new CommandRuntimeError(409, "exact_token_usage_unavailable", "Provider did not report exact token usage", {
        humanMessage: `Safe-stopped during ${phase}: the signed token budget cannot be enforced because this provider turn did not report exact usage.`,
        category: "dependency_missing",
        remediation: "Use an enforcing provider path with exact token telemetry or remove the finite token budget through a reviewed contract amendment.",
      });
    }
    if (costLimit > 0 && usage?.exactCostUsage !== true) {
      throw new CommandRuntimeError(409, "exact_cost_usage_unavailable", "Provider did not report exact cost usage", {
        humanMessage: `Safe-stopped during ${phase}: the signed cost budget cannot be enforced because this provider turn did not report exact cost telemetry.`,
        category: "dependency_missing",
        remediation: "Use an enforcing provider path with exact cost telemetry or remove the finite cost budget through a reviewed contract amendment.",
      });
    }
    const totalTokens = usage?.totalTokens ?? usage?.providerTokens;
    const billedCostUsd = usage?.billedCostUsd ?? usage?.estimatedCost;
    const accounted = this.coordinator.accountUsage({
      lease,
      phase,
      ...(usage ? {
        delta: {
          providerTurns: usage?.providerTurns ?? 1,
          ...(usage.exactTokenUsage && totalTokens !== undefined
            ? { providerTokens: totalTokens }
            : {}),
          ...(usage.exactCostUsage && billedCostUsd !== undefined
            ? { estimatedCost: billedCostUsd }
            : {}),
        },
      } : {}),
      ...(usage?.providerTurnId ? { providerTurnId: usage.providerTurnId } : {}),
    });
    if (!accounted.allowed || !accounted.run.lease) {
      throw new CommandRuntimeError(409, "run_budget_exhausted", "Signed run budget was exhausted", {
        humanMessage: `Safe-stopped during ${phase}: ${accounted.exhausted.join(", ")} budget exhausted.`,
        category: "policy_denied",
      });
    }
    return accounted.run.lease;
  }

  async start(): Promise<RuntimeLifecycleResult> {
    if (this.scanTimer) return { recoveredRuns: 0, scheduledRuns: 0 };
    this.stopping = false;
    this.reconcileAllTerminalRunResidue();
    this.continuations.reconcileFromCanonicalState(
      this.timestamp(),
      "ti_scale",
      [...this.supportedJourneys],
    );
    // Cancellation wins over ordinary action recovery. A process that died
    // after child cleanup but before aggregate finalization must never resume
    // the very work the operator asked it to stop.
    await this.replayContinuations(undefined, ["cancellation_finalize_pending"]);
    // A reviewed execution boundary can durably finish after the runtime has
    // committed nothing (or after it committed but lost the acknowledgement).
    // Cancellation is finalized first; then correlation-safe result replay
    // closes or deduplicates those actions before ordinary recovery can
    // incorrectly classify them as abandoned work.
    await this.options.execution.replayPendingResults?.(100);
    await this.replayContinuations();
    const recovered = await this.recover();
    // Recovery must classify every expired lease before the scheduler can
    // reclaim planning work. In particular, this closes an interrupted ACP
    // provider turn and checkpoints run.recovery_started before a fresh
    // planning lease is acquired.
    this.continuations.reconcileFromCanonicalState(
      this.timestamp(),
      "ti_scale",
      [...this.supportedJourneys],
    );
    this.maintainWaitingGuidedAuthorities();
    const scheduledRuns = await this.scanOnce();
    this.scanTimer = setInterval(() => {
      void this.scanOnce().catch(() => undefined);
    }, this.scanIntervalMs);
    this.scanTimer.unref?.();
    const idleAuthorityIntervalMs = Math.max(
      250,
      Math.min(this.scanIntervalMs, Math.floor(this.leaseTtlMs / 3)),
    );
    this.idleAuthorityTimer = setInterval(() => {
      try {
        this.maintainWaitingGuidedAuthorities();
      } catch {
        // Authority remains fail-closed. The next bounded interval retries;
        // HTTP mutations cannot mint or recover the raw server token.
      }
    }, idleAuthorityIntervalMs);
    this.idleAuthorityTimer.unref?.();
    return { recoveredRuns: recovered, scheduledRuns };
  }

  beginStop(): void {
    this.stopping = true;
    if (this.scanTimer) clearInterval(this.scanTimer);
    if (this.idleAuthorityTimer) clearInterval(this.idleAuthorityTimer);
    this.scanTimer = undefined;
    this.idleAuthorityTimer = undefined;
    for (const controller of this.controllers.values()) controller.abort("Ti-Scale runtime stopped");
  }

  async stop(): Promise<void> {
    this.beginStop();
    await Promise.allSettled([...this.processing.values()]);
    await Promise.allSettled([...this.continuationProcessing.values()]);
    // Active actions are owned by the execution port, not by the planning
    // promises above. Confirm child cleanup before unbinding the result sink;
    // leave their durable action/lease records nonterminal so startup recovery
    // can classify them instead of pretending shutdown completed the work.
    const activeRunIds = [...new Set(
      [...this.actionContexts.values()].map((context) => context.action.runId),
    )];
    await Promise.allSettled(activeRunIds.map((runId) =>
      this.options.execution.cancelRun(runId, "Ti-Scale runtime is shutting down")));
    for (const context of this.actionContexts.values()) {
      if (context.heartbeat) clearInterval(context.heartbeat);
    }
    this.actionContexts.clear();
    for (const [runId, leaseToken] of this.controlPlaneTokens) {
      try {
        this.controlPlaneLeases.release({
          runId,
          controlPlane: "ti_scale",
          leaseOwner: this.workerId,
          leaseToken,
          now: this.now(),
        });
      } catch {
        // An expired or already-fenced authority is intentionally not revived
        // during shutdown. The durable run lease/recovery path remains the
        // source of truth for unfinished work.
      }
    }
    this.controlPlaneTokens.clear();
    this.unbindResultSink?.();
    this.unbindResultSink = undefined;
  }

  /** Recover expired in-flight work through the coordinator's idempotency classifier. */
  async recover(): Promise<number> {
    this.bindAutonomousRestartRecoveryBoundaries();
    const results = await this.coordinator.recoverOnStartup(
      this.workerId,
      [...this.supportedJourneys],
      "ti_scale",
    );
    const actions = new ActionRepository(this.database);
    for (const result of results) {
      if (result.disposition !== "resumed_idempotently") continue;
      const durable = this.coordinator.getRun(result.runId);
      if (!durable.lease) continue;
      for (const actionId of result.actionIds) {
        const action = actions.get(actionId);
        const context: RuntimeActionContext = {
          action,
          lease: durable.lease,
          before: durable.control.progress,
          completing: false,
        };
        this.actionContexts.set(actionId, context);
        this.actionHeartbeat(context);
      }
    }
    return results.length;
  }

  private bindAutonomousRestartRecoveryBoundaries(): void {
    if (!this.options.autonomousActivation || !this.supportedJourneys.has("autonomous")) {
      return;
    }
    const now = this.timestamp();
    const candidates = this.database.prepare(`
      SELECT r.id AS run_id, r.current_plan_id, r.current_step_id,
        checkpoint.id AS checkpoint_id, checkpoint.state_hash,
        checkpoint.context_pack_id
      FROM runs r
      JOIN missions m ON m.id = r.mission_id
      JOIN autonomous_activation_receipts receipt
        ON receipt.id = (
          SELECT current_receipt.id
          FROM autonomous_activation_receipts current_receipt
          WHERE current_receipt.run_id = r.id
          ORDER BY current_receipt.generation DESC,
            current_receipt.issued_at DESC, current_receipt.id DESC
          LIMIT 1
        )
      JOIN checkpoints checkpoint
        ON checkpoint.id = (
          SELECT latest.id FROM checkpoints latest
          WHERE latest.run_id = r.id
          ORDER BY latest.event_sequence DESC, latest.created_at DESC,
            latest.id DESC
          LIMIT 1
        )
      WHERE r.journey = 'autonomous'
        AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale'
        AND r.status NOT IN ('completed', 'failed', 'cancelled')
        AND r.lease_expires_at IS NOT NULL
        AND r.lease_expires_at <= ?
      ORDER BY r.id
    `).all(now) as Array<{
      run_id: string;
      current_plan_id: string | null;
      current_step_id: string | null;
      checkpoint_id: string;
      state_hash: string;
      context_pack_id: string | null;
    }>;
    for (const candidate of candidates) {
      try {
        this.options.autonomousActivation.verifyAndBind({
          runId: candidate.run_id,
          bindingType: "restart_recovery",
          subjectId: candidate.checkpoint_id,
          subjectDigest: candidate.state_hash,
          ...(candidate.current_plan_id
            ? { planId: candidate.current_plan_id }
            : {}),
          ...(candidate.current_step_id
            ? { stepId: candidate.current_step_id }
            : {}),
          ...(candidate.context_pack_id
            ? { contextPackId: candidate.context_pack_id }
            : {}),
          boundBy: this.workerId,
        });
      } catch {
        // No runtime authority is minted. Planning recovery re-enters the
        // aggregate boundary and action recovery re-enters the routed
        // execution boundary, so both paths persist a fail-closed state
        // without provider, MCP, or local-tool contact.
      }
    }
  }

  async scanOnce(): Promise<number> {
    if (this.stopping) return 0;
    // Also drain a bounded batch during normal operation. A transient sink or
    // lease conflict therefore does not require another process restart.
    await this.options.execution.replayPendingResults?.(50);
    this.blockUnusableWaitingGuidedDecisions();
    this.continuations.reconcileFromCanonicalState(
      this.timestamp(),
      "ti_scale",
      [...this.supportedJourneys],
    );
    const continuationRuns = this.continuations.readyRunIds(this.timestamp(), 50, "ti_scale")
      .filter((runId) => this.supportsRun(runId));
    let scheduled = 0;
    for (const runId of continuationRuns) {
      if (this.continuationProcessing.has(runId)) continue;
      const work = this.processContinuationRun(runId)
        .then(() => undefined)
        .catch(() => undefined)
        .finally(() => this.continuationProcessing.delete(runId));
      this.continuationProcessing.set(runId, work);
      scheduled += 1;
    }
    const candidates = this.repository.listRunnableRuns(
      this.timestamp(),
      20,
      [...this.supportedJourneys],
    );
    for (const runId of candidates) {
      if (this.processing.has(runId) || this.continuationProcessing.has(runId)) continue;
      const work = this.processRun(runId)
        .catch(() => undefined)
        .finally(() => this.processing.delete(runId));
      this.processing.set(runId, work);
      scheduled += 1;
    }
    return scheduled;
  }

  /**
   * An expired or ambiguous Guided checkpoint cannot remain in a normal wait
   * after its control-plane heartbeat stops. Persist a precise block,
   * checkpoint, diagnosis, and audit record without dispatching any action.
   */
  blockUnusableWaitingGuidedDecisions(): number {
    if (this.stopping || !this.supportedJourneys.has("guided")) return 0;
    const now = this.timestamp();
    const boundaries = this.repository.listUnusableWaitingGuidedDecisionBoundaries(now);
    let blocked = 0;
    for (const candidate of boundaries) {
      let authorityHeld = false;
      try {
        this.ensureControlPlaneAuthority(candidate.runId);
        authorityHeld = true;
        const lease = this.controlLease(candidate.runId);
        const committed = inImmediateTransaction(this.database, () => {
          const boundary = this.repository
            .listUnusableWaitingGuidedDecisionBoundaries(now, 1, candidate.runId)
            .at(0);
          if (!boundary) return false;
          const run = this.coordinator.getRun(boundary.runId);
          if (
            run.run.journey !== "guided" ||
            run.run.state !== "waiting_guided_decision"
          ) return false;
          const issues = new Set(boundary.integrityIssues);
          const expired = issues.size === 1 && issues.has("current_decision_expired");
          const diagnosis = issues.has("active_plan_missing_or_stale")
            ? {
                code: "guided_active_plan_integrity_conflict",
                reason: "The Guided checkpoint's active plan is missing, inactive, or no longer belongs to this run; execution stopped before any action ran.",
                remediation: "Review the preserved checkpoint, then restore or create a valid versioned plan and a new represented decision before resuming.",
              }
            : issues.has("current_step_missing_or_stale")
              ? {
                  code: "guided_current_step_integrity_conflict",
                  reason: "The Guided checkpoint's current step is missing, outside the active plan, or no longer waiting for a decision; execution stopped before any action ran.",
                  remediation: "Review the preserved checkpoint, then amend the plan so it has one current waiting step and create a new represented decision.",
                }
              : issues.has("pending_decision_count_invalid") || issues.has("current_decision_missing_or_ambiguous")
                ? {
                    code: "guided_decision_integrity_conflict",
                    reason: `The Guided run has ${boundary.pendingCount} pending decisions across its plan and ${boundary.currentPendingCount} for its current step; execution stopped before any action ran.`,
                    remediation: "Review the preserved checkpoint, reconcile the conflicting decision records, then create exactly one new represented decision for the current step.",
                  }
                : {
                    code: "guided_decision_expired",
                    reason: "The exact Guided decision expired before the operator acted; no target, provider, or tool action ran.",
                    remediation: "Review the preserved checkpoint, then amend the plan to create a new represented decision or start a new run. An expired decision cannot be revived.",
                  };
          const reason = diagnosis.reason;
          const lastSuccess = this.database.prepare(`
            SELECT id FROM events WHERE run_id = ?
            ORDER BY sequence DESC LIMIT 1
          `).get(boundary.runId) as { id: string } | undefined;
          this.database.prepare(`
            UPDATE guided_decisions SET
              status = 'expired',
              decision_actor = ?,
              decision_reason = ?,
              decided_at = ?
            WHERE run_id = ? AND status = 'pending' AND expires_at <= ?
          `).run(this.workerId, reason, now, boundary.runId, now);
          if (boundary.stepId) {
            this.database.prepare(`
              UPDATE plan_steps SET status = 'blocked', updated_at = ?
              WHERE id = ? AND run_id = ? AND status = 'waiting_guided_decision'
            `).run(now, boundary.stepId, boundary.runId);
            this.database.prepare(`
              UPDATE assignments SET status = 'blocked',
                lease_owner = NULL, lease_acquired_at = NULL,
                last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
              WHERE run_id = ? AND step_id = ?
                AND status IN ('queued', 'active')
            `).run(now, boundary.runId, boundary.stepId);
          }
          const transition = this.coordinator.transitionRun({
            lease,
            to: "blocked",
            reason,
          });
          this.repository.events.append({
            missionId: boundary.missionId,
            runId: boundary.runId,
            journey: "guided",
            eventType: expired
              ? "guided.decision_expired"
              : "guided.decision_integrity_blocked",
            actorType: "worker",
            actorId: this.workerId,
            summary: reason,
            payload: {
              stepId: boundary.stepId,
              currentPlanId: boundary.currentPlanId,
              pendingDecisionIds: [...boundary.pendingDecisionIds],
              currentPendingDecisionIds: [...boundary.currentPendingDecisionIds],
              expiredDecisionIds: [...boundary.expiredDecisionIds],
              pendingCount: boundary.pendingCount,
              currentPendingCount: boundary.currentPendingCount,
              unexpiredCount: boundary.unexpiredCount,
              integrityIssues: [...boundary.integrityIssues],
              actionDispatched: false,
              targetContacted: false,
              checkpointId: transition.checkpointId,
            },
          });
          this.repository.appendAudit({
            missionId: boundary.missionId,
            runId: boundary.runId,
            actorId: this.workerId,
            action: expired
              ? "guided.decision_expired"
              : "guided.decision_integrity_blocked",
            resourceType: "run",
            resourceId: boundary.runId,
            reason,
            details: {
              stepId: boundary.stepId,
              currentPlanId: boundary.currentPlanId,
              pendingDecisionIds: [...boundary.pendingDecisionIds],
              currentPendingDecisionIds: [...boundary.currentPendingDecisionIds],
              expiredDecisionIds: [...boundary.expiredDecisionIds],
              integrityIssues: [...boundary.integrityIssues],
              checkpointId: transition.checkpointId,
            },
            now,
          });
          const hasUsableStepReference = Boolean(
            boundary.stepId && !issues.has("current_step_missing_or_stale"),
          );
          new FailureDiagnosisService(this.database, { clock: this.now }).create({
            missionId: boundary.missionId,
            runId: boundary.runId,
            ...(hasUsableStepReference ? { stepId: boundary.stepId! } : {}),
            subjectType: hasUsableStepReference ? "step" : "run",
            subjectId: hasUsableStepReference ? boundary.stepId! : boundary.runId,
            humanReason: reason,
            category: "guided_decision_missing",
            code: diagnosis.code,
            originatingComponent: "command-runtime.guided-decision-supervisor",
            ...(lastSuccess ? { lastSuccessEventId: lastSuccess.id } : {}),
            failedComponentRef: canonicalJson({
              currentPlanId: boundary.currentPlanId,
              currentStepId: boundary.stepId,
              pendingDecisionIds: boundary.pendingDecisionIds,
              currentPendingDecisionIds: boundary.currentPendingDecisionIds,
            }),
            targetSummary: "No target interaction was dispatched while Ti-Scale waited for the operator.",
            policyOrDependency: "Guided execution requires one active plan, one current waiting step inside that plan, and exactly one visible, unexpired pending decision across the run.",
            retryHistory: [],
            progressBeforeFailure: transition.run.control.progress,
            preservedReferences: [{
              kind: "checkpoint",
              id: transition.checkpointId,
              meaning: "Durable zero-execution checkpoint created when the Guided decision became unusable",
            }],
            retryable: false,
            automaticRecovery: {
              directive: "blocked",
              automaticActionDispatched: false,
              expiredDecisionIds: [...boundary.expiredDecisionIds],
              integrityIssues: [...boundary.integrityIssues],
              currentPlanId: boundary.currentPlanId,
              currentStepId: boundary.stepId,
            },
            remediation: diagnosis.remediation,
            operatorActions: [
              {
                kind: "amend_plan",
                label: "Create a new represented step",
                consequence: "Preserves this expired checkpoint and requires a newly versioned plan decision before any action can proceed.",
                requiresConfirmation: true,
              },
              {
                kind: "start_new_run",
                label: "Start a new run",
                consequence: "Keeps the expired run immutable and begins a separately versioned Guided attempt.",
                requiresConfirmation: true,
              },
              {
                kind: "terminate_gracefully",
                label: "Keep the safe stop",
                consequence: "Leaves the run blocked with its evidence, audit trail, and checkpoint preserved.",
                requiresConfirmation: true,
              },
            ],
            objectiveImpact: "The mission objective remains incomplete. No action was dispatched and all prior evidence remains preserved.",
            terminal: false,
            actor: { id: this.workerId, type: "worker" },
          });
          return true;
        });
        if (committed) blocked += 1;
      } catch (error) {
        if (
          (error instanceof ControlPlaneLeaseError && error.code === "lease_conflict" && error.retryable) ||
          (error instanceof DurableOrchestrationError && error.code === "lease_conflict")
        ) {
          continue;
        }
        throw error;
      } finally {
        if (authorityHeld) {
          try {
            this.releaseControlPlaneAuthority(candidate.runId);
          } catch {
            // The durable blocked checkpoint remains authoritative even if a
            // concurrently expired control-plane proof cannot be released.
          }
        }
      }
    }
    return blocked;
  }

  /**
   * Keep the server-only control-plane proof alive while a Guided run waits
   * for its exact operator decision. A restarted worker may reacquire only
   * after the prior fenced lease is released or expires. No run lease is held
   * during the idle wait; the next mutation reacquires that shorter lease.
   */
  maintainWaitingGuidedAuthorities(): {
    readonly held: number;
    readonly contended: number;
    readonly released: number;
  } {
    if (this.stopping) return { held: 0, contended: 0, released: 0 };
    // Maintenance is also an integrity sweep. Corrupt or expired waits are
    // checkpointed and diagnosed before they can retain a control-plane proof.
    this.blockUnusableWaitingGuidedDecisions();
    const waiting = new Set(this.repository.listWaitingGuidedDecisionRuns(this.timestamp()));
    let held = 0;
    let contended = 0;
    for (const runId of waiting) {
      try {
        this.ensureControlPlaneAuthority(runId);
        held += 1;
      } catch (error) {
        if (error instanceof ControlPlaneLeaseError && error.code === "lease_conflict" && error.retryable) {
          contended += 1;
          continue;
        }
        throw error;
      }
    }

    const activelyOwned = new Set<string>([
      ...this.processing.keys(),
      ...this.continuationProcessing.keys(),
      ...[...this.actionContexts.values()].map((context) => context.action.runId),
    ]);
    // A direct HTTP continuation replay is intentionally not registered in
    // continuationProcessing because continuation handlers can replay nested
    // work for the same run. Its fenced, unexpired durable run lease is the
    // canonical proof that mutation or dispatch remains in flight. Retaining
    // control-plane authority for that bounded lease closes the action
    // commit-to-dispatch race without introducing a self-await deadlock.
    const now = this.timestamp();
    const durablyLeased = this.database.prepare(`
      SELECT r.id
      FROM runs r
      JOIN missions m ON m.id = r.mission_id
      WHERE r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale'
        AND r.lease_owner = ?
        AND r.lease_expires_at IS NOT NULL
        AND r.lease_expires_at > ?
    `).all(this.workerId, now) as Array<{ id: string }>;
    for (const leased of durablyLeased) activelyOwned.add(leased.id);
    let released = 0;
    for (const runId of [...this.controlPlaneTokens.keys()]) {
      if (waiting.has(runId) || activelyOwned.has(runId)) continue;
      this.releaseControlPlaneAuthority(runId);
      released += 1;
    }
    return { held, contended, released };
  }

  async processRunNow(runId: string, planningRetryContinuationId?: string): Promise<void> {
    const ownership = this.runMutationAuthority.authorize({
      runId,
      actorId: this.workerId,
      mode: "ownership",
    });
    ownership.assertCurrent();
    if (!this.supportedJourneys.has(this.repository.getPlanningRun(runId).journey)) return;
    const existing = this.processing.get(runId);
    if (existing) return existing;
    const work = this.processRun(runId, planningRetryContinuationId)
      .finally(() => this.processing.delete(runId));
    this.processing.set(runId, work);
    return work;
  }

  async replayContinuations(
    runId?: string,
    kinds?: readonly RuntimeContinuationKind[],
  ): Promise<number> {
    if (runId) this.assertV2ControlPlaneOwnership(runId);
    const runIds = (runId
      ? [runId]
      : this.continuations.readyRunIds(this.timestamp(), 200, "ti_scale"))
      .filter((candidate) => this.supportsRun(candidate));
    let processed = 0;
    for (const candidate of runIds) {
      if (this.continuationProcessing.has(candidate)) {
        await this.continuationProcessing.get(candidate);
        continue;
      }
      processed += await this.processContinuationRun(candidate, kinds);
    }
    return processed;
  }

  /**
   * Wake one run after a committed continuation without enabling the ambient
   * runnable-run scanner. The continuation table and its owner fence remain
   * the source of truth, and stop() drains the tracked work.
   */
  notifyContinuationAvailable(
    runId: string,
    kinds?: readonly RuntimeContinuationKind[],
  ): boolean {
    if (this.stopping) return false;
    this.assertV2ControlPlaneOwnership(runId);
    if (this.continuationProcessing.has(runId)) return false;
    const work = this.processContinuationRun(runId, kinds)
      .then(() => undefined)
      .catch(() => undefined)
      .finally(() => this.continuationProcessing.delete(runId));
    this.continuationProcessing.set(runId, work);
    return true;
  }

  private async processContinuationRun(
    runId: string,
    kinds?: readonly RuntimeContinuationKind[],
  ): Promise<number> {
    this.assertV2ControlPlaneOwnership(runId);
    this.ensureControlPlaneAuthority(runId);
    let processed = 0;
    for (let index = 0; index < 64 && !this.stopping; index += 1) {
      const continuation = this.continuations.claimNext({
        runId,
        workerId: this.workerId,
        now: this.timestamp(),
        leaseTtlMs: this.leaseTtlMs,
        ...(kinds?.length ? { kinds } : {}),
      });
      if (!continuation?.leaseOwner) break;
      const heartbeat = setInterval(() => {
        try {
          this.continuations.heartbeat(
            continuation.id,
            continuation.leaseOwner!,
            this.timestamp(),
            this.leaseTtlMs,
          );
        } catch {
          clearInterval(heartbeat);
        }
      }, Math.max(250, Math.floor(this.leaseTtlMs / 3)));
      try {
        await this.handleContinuation(continuation);
        processed += 1;
        // Cancellation finalization releases the control-plane lease inside
        // its terminal transaction. Do not claim another continuation under
        // the now-retired in-memory authority; a subsequent replay acquires a
        // fresh bounded lease for terminal evaluation/projection work.
        if (
          continuation.kind === "cancellation_finalize_pending" &&
          !this.controlPlaneTokens.has(runId)
          && isTerminalRunState(this.coordinator.getRun(runId).run.state)
        ) break;
      } catch (error) {
        if (error instanceof RuntimeCrashAfterCommit) throw error;
        if (
          error instanceof CommandRuntimeError
          && error.code === "guided_stop_context_corrupt"
        ) {
          this.blockCorruptGuidedStopContinuation(continuation, error);
          break;
        }
        if (
          error instanceof CommandRuntimeError
          && (continuation.kind === "plan_ready_to_dispatch"
            || continuation.kind === "guided_approval_to_dispatch")
          && error.options.retryable !== true
        ) {
          // A deterministic pre-dispatch policy/dependency failure cannot
          // become five opaque continuation retries. Persist the exact safe
          // stop before any generic execution adapter is called so the
          // operator sees the real cause and a concrete remediation.
          const terminal = this.coordinator.getRun(continuation.runId);
          if (!isTerminalRunState(terminal.run.state) && terminal.run.state !== "blocked") {
            const lease = this.continuationLease(continuation.runId);
            await this.safeStopPlanning(continuation.runId, lease, error);
          }
          const current = this.continuations.get(continuation.id);
          if (current.status === "processing" && current.leaseOwner === continuation.leaseOwner) {
            this.continuations.complete(
              continuation.id,
              continuation.leaseOwner,
              this.timestamp(),
            );
          }
          break;
        }
        const message = error instanceof Error ? error.message : "Continuation handler failed";
        const current = this.continuations.get(continuation.id);
        if (current.status === "processing" && current.leaseOwner === continuation.leaseOwner) {
          const run = this.coordinator.getRun(runId);
          if (
            (isTerminalRunState(run.run.state) || run.run.state === "blocked")
            && continuation.kind !== "memory_projection_pending"
          ) {
            this.continuations.complete(continuation.id, continuation.leaseOwner, this.timestamp());
          } else if (continuation.attemptCount >= 5) {
            this.failContinuation(continuation, message);
          } else {
            const delayMs = Math.min(30_000, 250 * (2 ** Math.max(0, continuation.attemptCount - 1)));
            this.continuations.retry({
              id: continuation.id,
              ownerToken: continuation.leaseOwner,
              now: this.timestamp(),
              availableAt: new Date(Date.parse(this.timestamp()) + delayMs).toISOString(),
              error: message,
            });
          }
        }
        break;
      } finally {
        clearInterval(heartbeat);
      }
    }
    return processed;
  }

  private continuationText(
    continuation: RuntimeContinuation,
    key: "actionId" | "stepId" | "decisionId" | "terminalStatus",
  ): string | null {
    const value = continuation.payload[key];
    return typeof value === "string" && value.trim() ? value : null;
  }

  private continuationLease(runId: string): RunLeaseToken {
    this.ensureControlPlaneAuthority(runId);
    const durable = this.coordinator.getRun(runId);
    if (durable.lease?.ownerId === this.workerId) return durable.lease;
    if (durable.lease && Date.parse(durable.lease.expiresAt) > Date.parse(this.timestamp())) {
      throw new CommandRuntimeError(409, "continuation_run_lease_busy", "Another worker owns this run continuation", {
        retryable: true,
        category: "conflict",
      });
    }
    return this.acquireWorkerRunLease(runId);
  }

  private completeContinuation(continuation: RuntimeContinuation): void {
    if (!continuation.leaseOwner) throw new Error("Claimed continuation has no owner fence");
    this.continuations.complete(continuation.id, continuation.leaseOwner, this.timestamp());
  }

  private async handleContinuation(continuation: RuntimeContinuation): Promise<void> {
    this.assertV2ControlPlaneOwnership(continuation.runId);
    const run = this.coordinator.getRun(continuation.runId);
    if (
      isTerminalRunState(run.run.state)
      && continuation.kind !== "evaluation_pending"
      && continuation.kind !== "memory_projection_pending"
    ) {
      this.completeContinuation(continuation);
      return;
    }
    switch (continuation.kind) {
      case "planning_retry_to_dispatch": {
        await this.processRunNow(continuation.runId, continuation.id);
        this.completeContinuation(continuation);
        return;
      }
      case "autonomous_retry_to_dispatch": {
        await this.dispatchAutonomousRetryContinuation(continuation);
        return;
      }
      case "plan_ready_to_dispatch":
      case "guided_approval_to_dispatch": {
        const stepId = this.continuationText(continuation, "stepId");
        if (!stepId) throw new Error("Dispatch continuation is missing its canonical step ID");
        const decisionId = continuation.kind === "guided_approval_to_dispatch"
          ? this.continuationText(continuation, "decisionId") ?? continuation.sourceId
          : undefined;
        const candidateActivation = continuation.kind === "plan_ready_to_dispatch"
          ? this.autonomousPostReconPlanExpansion
          : undefined;
        if (candidateActivation) {
          // This may perform bounded filesystem I/O and a child-process
          // attestation. It deliberately runs outside SQLite transactions.
          // The same continuation is reclaimable after process death, and the
          // activation key/path are deterministic for idempotent replay.
          try {
            await candidateActivation.ensureCandidateProcedureActivation({
              runId: continuation.runId,
              stepId,
              signal: this.controller(continuation.runId).signal,
            });
          } catch (error) {
            const candidate = error && typeof error === "object"
              && "retryable" in error
              && typeof error.retryable === "boolean"
              ? error as Error & {
                  readonly code?: string;
                  readonly retryable: boolean;
                }
              : undefined;
            if (!candidate) throw error;
            throw new CommandRuntimeError(
              candidate.retryable ? 503 : 409,
              candidate.code
                ?? "candidate_procedure_activation_failed",
              candidate.message,
              {
                retryable: candidate.retryable,
                category: candidate.retryable
                  ? "dependency_unavailable"
                  : "policy_denied",
                humanMessage: candidate.retryable
                  ? "Ti-Scale could not finish the bounded candidate procedure attestation yet. No target action was reserved."
                  : "Ti-Scale rejected the candidate because its procedure custody no longer matches the represented run step. No target action was reserved.",
                remediation: candidate.retryable
                  ? "Ti-Scale will retry the same idempotent activation within the continuation budget."
                  : "Review the current ScriptArtifact, observer, target, and action binding; create a new represented step after correcting the mismatch.",
              },
            );
          }
        }
        const existing = this.database.prepare(`
          SELECT id, status FROM actions
          WHERE run_id = ? AND step_id = ?
            ${decisionId ? "AND guided_decision_id = ?" : ""}
          ORDER BY created_at, id LIMIT 1
        `).get(...(decisionId
          ? [continuation.runId, stepId, decisionId]
          : [continuation.runId, stepId])) as { id: string; status: string } | undefined;
        if (existing) {
          inImmediateTransaction(this.database, () => {
            if (existing.status === "succeeded") {
              this.continuations.enqueue({
                runId: continuation.runId,
                kind: "action_result_to_advance",
                sourceId: existing.id,
                payload: { actionId: existing.id, stepId },
                now: this.timestamp(),
              });
            }
            this.completeContinuation(continuation);
          });
          return;
        }
        const lease = this.continuationLease(continuation.runId);
        if (candidateActivation) {
          // Only the Autonomous candidate gate above can wait on filesystem
          // publication and a child-process attestation. Re-fence that path
          // immediately before reservation without changing the established
          // Guided exact-decision lifecycle.
          const dispatchScope = this.database.prepare(`
            SELECT r.current_plan_id, r.current_step_id, r.status,
              step.plan_id, step.status AS step_status
            FROM runs AS r
            JOIN plan_steps AS step
              ON step.id = ? AND step.run_id = r.id
            WHERE r.id = ?
          `).get(stepId, continuation.runId) as Readonly<{
            current_plan_id: string | null;
            current_step_id: string | null;
            status: string;
            plan_id: string;
            step_status: string;
          }> | undefined;
          if (
            !dispatchScope
            || dispatchScope.status !== "running"
            || dispatchScope.current_plan_id !== dispatchScope.plan_id
            || dispatchScope.current_step_id !== stepId
            || dispatchScope.step_status !== "ready"
          ) {
            throw new CommandRuntimeError(
              409,
              "candidate_activation_dispatch_scope_changed",
              "Run, plan, or step authority changed during candidate procedure activation",
              {
                retryable: true,
                category: "conflict",
                humanMessage:
                  "Ti-Scale finished the activation check, but the active plan changed before action reservation. No target action was started.",
                remediation:
                  "Reload the current run state; the durable continuation will reconcile against the active plan.",
              },
            );
          }
        }
        await this.startRepresentedAction(
          this.repository.getStepIntent(stepId),
          lease,
          decisionId,
        );
        this.completeContinuation(continuation);
        return;
      }
      case "action_result_to_advance": {
        await this.advanceContinuation(continuation);
        return;
      }
      case "guided_failure_to_recover": {
        const actionId = this.continuationText(continuation, "actionId") ?? continuation.sourceId;
        inImmediateTransaction(this.database, () => {
          this.repository.recordGuidedActionFailure(actionId, this.timestamp());
          this.continuations.enqueue({
            runId: continuation.runId,
            kind: "resume_recovery_pending",
            sourceId: actionId,
            payload: { actionId },
            now: this.timestamp(),
          });
          this.completeContinuation(continuation);
        });
        return;
      }
      case "resume_recovery_pending": {
        const latest = this.coordinator.getRun(continuation.runId);
        if (latest.run.state !== "recovering" && latest.run.state !== "planning") {
          this.completeContinuation(continuation);
          return;
        }
        await this.processRunNow(continuation.runId);
        this.completeContinuation(continuation);
        return;
      }
      case "evaluation_pending": {
        const terminalStatus = this.continuationText(continuation, "terminalStatus");
        const latest = this.coordinator.getRun(continuation.runId);
        if (terminalStatus === "cancelled" || latest.run.state === "cancelled") {
          const cancellation = this.database.prepare(`
            SELECT actor_id, summary FROM events WHERE id = ? AND run_id = ?
          `).get(continuation.sourceId, continuation.runId) as {
            actor_id: string | null;
            summary: string;
          } | undefined;
          const actorId = cancellation?.actor_id ?? "operator";
          const reason = cancellation?.summary.replace(/^Run cancelled and child work stopped:\s*/u, "").trim()
            || "Operator requested cancellation";
          inImmediateTransaction(this.database, () => {
            this.repository.cancelOpenWork(continuation.runId, actorId, reason, this.timestamp());
            this.database.prepare("UPDATE missions SET status = 'cancelled', updated_at = ? WHERE id = ?")
              .run(this.timestamp(), latest.run.missionId);
            const audit = this.database.prepare(`
              SELECT id FROM audit_records
              WHERE run_id = ? AND action = 'run.cancelled'
              ORDER BY occurred_at DESC, id DESC LIMIT 1
            `).get(continuation.runId) as { id: string } | undefined;
            if (!audit) {
              this.repository.appendAudit({
                missionId: latest.run.missionId,
                runId: continuation.runId,
                actorId,
                action: "run.cancelled",
                resourceType: "run",
                resourceId: continuation.runId,
                reason,
                now: this.timestamp(),
              });
            }
            this.recordTerminalEvaluationWithBrain({
              runId: continuation.runId,
              terminalStatus: "cancelled",
              createdBy: "run-supervisor",
            });
            this.completeContinuation(continuation);
          });
          return;
        }
        if (terminalStatus === "failed" || latest.run.state === "failed") {
          this.commitTerminalAtomically(continuation.runId, "failed", (reportCommitment) => {
            this.recordTerminalEvaluationWithBrain({
              runId: continuation.runId,
              terminalStatus: "failed",
              createdBy: "run-supervisor",
              ...(reportCommitment ? { terminalReportCommitment: reportCommitment } : {}),
            });
            this.completeContinuation(continuation);
          });
          return;
        }
        if (latest.run.state === "completed") {
          this.completeContinuation(continuation);
          return;
        }
        const lease = this.continuationLease(continuation.runId);
        await this.evaluateAndFinish(lease);
        this.completeContinuation(continuation);
        return;
      }
      case "memory_projection_pending": {
        const evaluation = this.database.prepare(`
          SELECT id FROM run_evaluations WHERE id = ? AND run_id = ?
        `).get(continuation.sourceId, continuation.runId) as { id: string } | undefined;
        if (!evaluation) {
          throw new Error("Terminal memory projection continuation does not match its canonical evaluation");
        }
        this.projectTerminalMemoryWithBrain({
          runId: continuation.runId,
          evaluationId: evaluation.id,
        });
        this.completeContinuation(continuation);
        return;
      }
      case "cancellation_finalize_pending": {
        await this.finalizeCancellationContinuation(continuation);
        return;
      }
    }
  }

  private async dispatchAutonomousRetryContinuation(
    continuation: RuntimeContinuation,
  ): Promise<void> {
    const actionId = this.continuationText(continuation, "actionId") ?? continuation.sourceId;
    const stepId = this.continuationText(continuation, "stepId");
    if (!stepId) throw new Error("Autonomous retry continuation is missing its canonical step ID");
    const predecessor = this.database.prepare(`
      SELECT id, status, step_id FROM actions
      WHERE id = ? AND run_id = ?
    `).get(actionId, continuation.runId) as {
      id: string;
      status: string;
      step_id: string;
    } | undefined;
    if (
      !predecessor || predecessor.step_id !== stepId ||
      !["failed", "timed_out"].includes(predecessor.status)
    ) {
      throw new Error("Autonomous retry predecessor is not the exact canonical failed action");
    }

    // A retry successor is explicitly linked to its failed predecessor. This
    // makes replay deterministic even when the process dies after reservation
    // but before external dispatch or continuation acknowledgement.
    const successor = this.database.prepare(`
      SELECT id, status FROM actions
      WHERE run_id = ? AND step_id = ? AND parent_action_id = ?
      ORDER BY created_at, id LIMIT 1
    `).get(continuation.runId, stepId, actionId) as {
      id: string;
      status: string;
    } | undefined;
    if (successor) {
      if (successor.status === "succeeded") {
        inImmediateTransaction(this.database, () => {
          this.continuations.enqueue({
            runId: continuation.runId,
            kind: "action_result_to_advance",
            sourceId: successor.id,
            payload: { actionId: successor.id, stepId },
            now: this.timestamp(),
          });
          this.completeContinuation(continuation);
        });
        return;
      }
      if (successor.status === "running" && !this.actionContexts.has(successor.id)) {
        await this.recover();
        const current = this.database.prepare("SELECT status FROM actions WHERE id = ?")
          .get(successor.id) as { status: string } | undefined;
        if (current?.status === "running" && !this.actionContexts.has(successor.id)) {
          throw new Error("Reserved retry action still has a live owner lease; recovery is not yet claimable");
        }
      }
      this.completeContinuation(continuation);
      return;
    }

    let durable = this.coordinator.getRun(continuation.runId);
    if (["blocked", "completed", "failed", "cancelled"].includes(durable.run.state)) {
      this.completeContinuation(continuation);
      return;
    }
    let lease = this.continuationLease(continuation.runId);
    if (durable.run.state === "recovering") {
      const accounted = this.coordinator.accountUsage({ lease, phase: "delayed retry readiness" });
      if (!accounted.allowed || !accounted.run.lease) {
        throw new CommandRuntimeError(409, "run_budget_exhausted", "Signed run budget was exhausted during recovery", {
          humanMessage: `Safe-stopped before retry: ${accounted.exhausted.join(", ")} budget exhausted.`,
          category: "policy_denied",
        });
      }
      const running = this.coordinator.transitionRun({
        lease: accounted.run.lease,
        to: "running",
        reason: `Bounded retry delay elapsed for ${actionId}; re-authorizing the unchanged in-contract action`,
      });
      if (!running.run.lease) {
        throw new CommandRuntimeError(500, "retry_lease_lost", "Retry lost its run lease");
      }
      lease = running.run.lease;
      durable = running.run;
    }
    if (durable.run.state !== "running") {
      throw new Error(`Autonomous retry cannot dispatch from ${durable.run.state}`);
    }
    const intent = this.repository.getStepIntent(stepId);
    await this.startRepresentedAction({ ...intent, parentActionId: actionId }, lease);
    this.completeContinuation(continuation);
  }

  private async advanceContinuation(continuation: RuntimeContinuation): Promise<void> {
    const actionId = this.continuationText(continuation, "actionId") ?? continuation.sourceId;
    const action = this.database.prepare(`
      SELECT a.step_id, a.status, a.result_summary,
        a.action_type, a.action_class,
        json_extract(a.normalized_arguments_json, '$.orchestration.kind') AS action_kind,
        r.mission_id, r.journey, ps.status AS step_status, ps.plan_id,
        ps.phase, ps.title AS step_title
      FROM actions a
      JOIN runs r ON r.id = a.run_id
      JOIN plan_steps ps ON ps.id = a.step_id
      WHERE a.id = ? AND a.run_id = ?
    `).get(actionId, continuation.runId) as {
      step_id: string;
      status: string;
      result_summary: string | null;
      action_type: string;
      action_class: string;
      action_kind: string | null;
      mission_id: string;
      journey: "autonomous" | "guided";
      step_status: string;
      plan_id: string;
      phase: string;
      step_title: string;
    } | undefined;
    if (!action) throw new Error("Continuation action no longer exists");
    if (["completed", "skipped", "cancelled"].includes(action.step_status)) {
      this.completeContinuation(continuation);
      this.continuations.reconcileFromCanonicalState(
        this.timestamp(),
        "ti_scale",
        [...this.supportedJourneys],
      );
      return;
    }
    if (action.status !== "succeeded") {
      throw new Error(`Action ${actionId} is not a successful advance predecessor`);
    }
    const expansionPort = this.autonomousPostReconPlanExpansion;
    const postReconExpansion = action.journey === "autonomous"
      && expansionPort
      ? await expansionPort.prepare({
          missionId: action.mission_id,
          runId: continuation.runId,
          basePlanId: action.plan_id,
          completingStepId: action.step_id,
          actionId,
          signal: this.controller(continuation.runId).signal,
        })
      : null;
    // Evidence-driven expansion is a second planning boundary, not an
    // exemption from the immutable launch-time model contract. Initial and
    // recovery plans pass through this same validator/binder before they are
    // persisted. Bind the dynamically produced exploit/session continuation
    // here as well so every later action carries the exact run-level
    // specialist/model receipt required by the execution boundary.
    const boundPostReconExpansionPlan = postReconExpansion
      ? this.bindAutonomousPlanModels(
          action.mission_id,
          continuation.runId,
          validateMissionPlanDraft(
            postReconExpansion.plan,
            this.maxPlanSteps,
            "autonomous",
          ),
        )
      : null;
    const phaseContextExists = Boolean(this.database.prepare(`
      SELECT 1 FROM memory_context_packs
      WHERE run_id = ? AND step_id = ? AND action_id = ?
        AND purpose LIKE 'Phase transition:%'
      LIMIT 1
    `).get(continuation.runId, action.step_id, actionId));
    if (!phaseContextExists) {
      inImmediateTransaction(this.database, () => {
        const phaseRun = this.repository.getPlanningRun(continuation.runId);
        const phaseMission = this.repository.getMission(phaseRun.missionId);
        const phaseSignals = this.phaseTransitionSemanticQuery({
          runId: continuation.runId,
          stepId: action.step_id,
          actionId,
          actionType: action.action_type,
          actionClass: action.action_class,
          phase: action.phase,
          stepTitle: action.step_title,
        });
        const phaseContext = this.retrieveBrainContext({
          hook: "phase_transition",
          mission: phaseMission,
          run: phaseRun,
          stepId: action.step_id,
          actionId,
          actorId: "phase-supervisor",
          query: phaseSignals.query,
          queryRedacted: phaseSignals.queryRedacted,
        });
        const phaseMemory = selectRelevantPhaseTransitionMemory({
          context: phaseContext,
          allowedNodeTypes: PHASE_TRANSITION_GUARD_CONTEXT_TYPES,
          activeVaultBackedNodeIds:
            this.agentToolMemoryDecisions.activeVaultBackedNodeIds(
              phaseContext.contextPack.id,
            ),
          semanticSignals: phaseSignals.semanticSignals,
        });
        const usedNodeIds = phaseSignals.signalCount > 0
          ? phaseMemory.nodeIds
          : [];
        if (usedNodeIds.length > 0) {
          this.brainContext.recordContextUse(
            phaseContext,
            usedNodeIds,
            "Applied only active-Vault-backed memory with a deterministic match to the current action, phase, or parsed technology signals; it did not alter the completed result, scope, tools, or authority.",
            "The retrieved item was not both active-Vault-backed and deterministically relevant to the current action, phase, or parsed technology.",
          );
        } else {
          this.brainContext.recordUnusedContext(
            phaseContext,
            phaseSignals.signalCount > 0
              ? "No retrieved item was both active-Vault-backed and deterministically relevant to the current action, phase, or parsed technology."
              : "No canonical parsed product, version, service, observation, or verified-evidence signal existed, so retrieved memory did not influence the transition.",
          );
        }
        this.repository.events.append({
          missionId: phaseMission.id,
          runId: phaseRun.id,
          journey: phaseRun.journey,
          eventType: "brain.phase_transition_guard_selected",
          actorType: "agent",
          actorId: "phase-supervisor",
          summary: usedNodeIds.length > 0
            ? "The next bounded decision received a fixed corroboration and failure-avoidance guard from scoped retained knowledge."
            : "Phase context was refreshed from canonical parsed signals, but no retained memory changed the next-decision guard.",
          payload: {
            contextPackId: phaseContext.contextPack.id,
            stepId: action.step_id,
            actionId,
            usedNodeIds: [...usedNodeIds],
            signalCount: phaseSignals.signalCount,
            observationCount: phaseSignals.observationCount,
            evidenceTypeCount: phaseSignals.evidenceTypeCount,
            activeVaultCandidateCount: phaseMemory.activeVaultCandidateCount,
            semanticallyRelevantCount: phaseMemory.semanticallyRelevantCount,
            completedResultChanged: false,
          },
        });
      });
    }
    const lease = this.continuationLease(continuation.runId);
    const now = this.timestamp();
    let evaluationQueued = false;
    let expandedPlanId: string | null = null;
    let resolvedFailureDiagnosisIds: readonly string[] = [];
    inImmediateTransaction(this.database, () => {
      const runs = new RunRepository(this.database);
      const current = runs.get(continuation.runId);
      runs.assertLease(current, lease, now);
      resolvedFailureDiagnosisIds =
        this.resolveSuccessfulRetryFailureLineage({
          missionId: action.mission_id,
          runId: continuation.runId,
          stepId: action.step_id,
          successfulActionId: actionId,
          resolvedAt: now,
        });
      if (resolvedFailureDiagnosisIds.length > 0) {
        this.repository.events.append({
          missionId: action.mission_id,
          runId: continuation.runId,
          journey: action.journey,
          eventType: "failure_diagnosis.automatic_retry_resolved",
          actorType: "worker",
          actorId: this.workerId,
          summary:
            `Successful bounded retry resolved ${resolvedFailureDiagnosisIds.length} predecessor failure ${resolvedFailureDiagnosisIds.length === 1 ? "diagnosis" : "diagnoses"}.`,
          payload: {
            successfulActionId: actionId,
            stepId: action.step_id,
            resolvedFailureDiagnosisIds: [...resolvedFailureDiagnosisIds],
            resolutionMode: "automatic_bounded_retry",
          },
        });
      }
      if (action.journey === "guided" && action.action_kind !== "manual") {
        const evidenceIds = (this.database.prepare(`
          SELECT id FROM evidence WHERE action_id = ? ORDER BY created_at, id
        `).all(actionId) as Array<{ id: string }>).map((row) => row.id);
        this.repository.recordGuidedExecutionInterpretation(
          actionId,
          action.result_summary ?? "The authorized specialist completed this exact step.",
          evidenceIds,
          now,
        );
      }
      const advanced = this.repository.advanceSuccessfulStep({
        runId: continuation.runId,
        stepId: action.step_id,
        actionId,
        journey: action.journey,
        now,
        decisionTtlMs: this.decisionTtlMs,
      });
      if (advanced.completed && postReconExpansion) {
        if (postReconExpansion.basePlanId !== action.plan_id) {
          throw new CommandRuntimeError(
            409,
            "autonomous_post_recon_plan_changed",
            "The active plan changed before evidence-derived expansion could commit",
            {
              humanMessage:
                "Ti-Scale preserved the reusable candidate but did not add it because the active plan changed.",
              category: "conflict",
              remediation:
                "Resume the current plan. The expansion gate will re-evaluate canonical evidence without repeating target work.",
            },
          );
        }
        const expansionPlan = this.repository.persistPlanRecords({
          mission: this.repository.getMission(action.mission_id),
          run: this.repository.getPlanningRun(continuation.runId),
          lease,
          plan: boundPostReconExpansionPlan!,
          now,
          decisionTtlMs: this.decisionTtlMs,
        });
        expandedPlanId = expansionPlan.planId;
        const attackAttemptId =
          expansionPort!.bindPersistedPlanStep({
            expansion: postReconExpansion,
            planId: expansionPlan.planId,
            stepId: expansionPlan.firstStepId,
          });
        const appendedStepCount = boundPostReconExpansionPlan!.steps.length;
        const appendedStepIds = (this.database.prepare(`
          SELECT id FROM plan_steps
          WHERE plan_id = ? ORDER BY ordinal
        `).all(expansionPlan.planId) as Array<{ readonly id: string }>)
          .map((row) => row.id);
        const changeRequestId = `plan_change_${randomUUID()}`;
        this.database.prepare(`
          INSERT INTO plan_change_requests (
            id, mission_id, run_id, base_plan_id, requested_by, request_text,
            normalized_change_json, structured_diff_json, affected_refs_json,
            dependency_impact_json, policy_validation_json,
            readiness_impact_json, budget_impact_json, inflight_impact_json,
            status, result_plan_id, created_at, resolved_at
          ) VALUES (?, ?, ?, ?, 'system:post-recon-expansion', NULL,
            ?, ?, ?, ?, ?, ?, ?, ?, 'applied', ?, ?, ?)
        `).run(
          changeRequestId,
          action.mission_id,
          continuation.runId,
          action.plan_id,
          canonicalJson({
            kind: "append_evidence_matched_exploit_validation",
            source: "current_run_verified_cve_and_version",
            postExploitExtensionId:
              postReconExpansion.postExploit?.extensionId ?? null,
          }),
          canonicalJson({
            appendedStepId: expansionPlan.firstStepId,
            appendedStepIds,
            scriptArtifactId:
              postReconExpansion.materialization.materializedScriptArtifactId,
          }),
          canonicalJson({
            cveApplicabilityId: postReconExpansion.cveApplicabilityId,
            versionEvidenceId: postReconExpansion.versionEvidenceId,
            contextPackId: postReconExpansion.materialization.contextPackId,
            memoryNodeIds: postReconExpansion.materialization.memoryNodeIds,
          }),
          canonicalJson({
            predecessorPlanCompleted: true,
            newStepDependencies: boundPostReconExpansionPlan!.steps.map(
              (step, ordinal) => ({
                ordinal,
                dependencyOrdinals: [...(step.dependencyOrdinals ?? [])],
              }),
            ),
          }),
          canonicalJson({
            signedContractUnchanged: true,
            targetUnchanged: true,
            actionClassUnchanged: true,
            signedExactMemoryWhitelistUnchanged: true,
            dynamicExactContextPackCreated: true,
          }),
          canonicalJson({
            scriptArtifactApproved: true,
            activeVaultRoundTripRequired: true,
            firstClassAttackAttemptId: attackAttemptId,
          }),
          canonicalJson({
            additionalSteps: appendedStepCount,
            existingSignedBudgetsRemainAuthoritative: true,
          }),
          canonicalJson({
            inFlightActionsCancelled: 0,
            checkpointRequired: false,
          }),
          expansionPlan.planId,
          now,
          now,
        );
        this.continuations.enqueue({
          runId: continuation.runId,
          kind: "plan_ready_to_dispatch",
          sourceId: expansionPlan.firstStepId,
          payload: { stepId: expansionPlan.firstStepId },
          now,
        });
        this.repository.events.append({
          missionId: action.mission_id,
          runId: continuation.runId,
          journey: "autonomous",
          eventType: "plan.evidence_driven_expansion_applied",
          actorType: "system",
          actorId: "system:post-recon-expansion",
          summary:
            postReconExpansion.postExploit
              ? "Verified current-run evidence added an exact Vault-backed exploit, independently identified bounded session, and minimized access-proof sequence."
              : "Verified current-run version/CVE evidence added one exact Vault-backed validation step before terminal evaluation.",
          payload: {
            changeRequestId,
            basePlanId: action.plan_id,
            resultPlanId: expansionPlan.planId,
            stepId: expansionPlan.firstStepId,
            stepIds: appendedStepIds,
            appendedStepCount,
            attackAttemptId,
            target: postReconExpansion.exactTarget,
            cveApplicabilityId: postReconExpansion.cveApplicabilityId,
            versionEvidenceId: postReconExpansion.versionEvidenceId,
            scriptArtifactId:
              postReconExpansion.materialization.materializedScriptArtifactId,
            contextPackId: postReconExpansion.materialization.contextPackId,
            memoryNodeIds: [
              ...postReconExpansion.materialization.memoryNodeIds,
            ],
            postExploit: postReconExpansion.postExploit ?? null,
            contractAmended: false,
            memoryPolicyAmended: false,
          },
        });
      } else if (advanced.completed) {
        evaluationQueued = true;
        this.continuations.enqueue({
          runId: continuation.runId,
          kind: "evaluation_pending",
          sourceId: action.plan_id,
          now,
        });
      } else if (action.journey === "guided") {
        if (!advanced.guidedDecisionId) {
          throw new CommandRuntimeError(500, "guided_decision_missing", "Next Guided decision was not created");
        }
        this.coordinator.transitionRun({
          lease,
          to: "waiting_guided_decision",
          reason: "The previous result was interpreted and the next explained step is ready",
          guidedDecisionId: advanced.guidedDecisionId,
        });
      } else {
        if (!advanced.nextStepId) {
          throw new CommandRuntimeError(500, "next_action_missing", "Next Autonomous action is missing");
        }
        this.continuations.enqueue({
          runId: continuation.runId,
          kind: "plan_ready_to_dispatch",
          sourceId: advanced.nextStepId,
          payload: { stepId: advanced.nextStepId },
          now,
        });
      }
      this.completeContinuation(continuation);
      this.repository.events.append({
        missionId: current.run.missionId,
        runId: continuation.runId,
        journey: current.run.journey,
        eventType: "run.continuation_replayed",
        actorType: "system",
        actorId: this.workerId,
        summary: advanced.completed
          ? expandedPlanId
            ? postReconExpansion?.postExploit
              ? "Durable reconnaissance result expanded into a candidate-bound exploit, session, and minimized proof sequence"
              : "Durable reconnaissance result expanded into one evidence-matched Autonomous validation step"
            : "Durable action result advanced to mission success evaluation"
          : current.run.journey === "guided"
            ? "Durable action result advanced to the next exact Guided decision"
            : "Durable action result advanced to the next in-contract Autonomous step",
        payload: {
          continuationId: continuation.id,
          kind: continuation.kind,
          actionId,
          nextStepId: advanced.nextStepId,
          nextGuidedDecisionId: advanced.guidedDecisionId,
          expandedPlanId,
          resolvedFailureDiagnosisIds: [...resolvedFailureDiagnosisIds],
        },
      });
    });
    if (evaluationQueued) {
      this.crashAfterCommit("step_advance_to_evaluation", continuation.runId, action.plan_id);
    } else if (expandedPlanId) {
      this.crashAfterCommit("plan_ready_to_dispatch", continuation.runId, expandedPlanId);
    }
  }

  private failContinuation(continuation: RuntimeContinuation, message: string): void {
    if (!continuation.leaseOwner) return;
    const now = this.timestamp();
    const durable = this.coordinator.getRun(continuation.runId);
    const lease = durable.lease?.ownerId === this.workerId
      ? durable.lease
      : (!durable.lease || Date.parse(durable.lease.expiresAt) <= Date.parse(now))
        ? this.acquireWorkerRunLease(continuation.runId)
        : null;
    inImmediateTransaction(this.database, () => {
      this.continuations.fail({
        id: continuation.id,
        ownerToken: continuation.leaseOwner!,
        now,
        error: message,
      });
      if (!lease || isTerminalRunState(durable.run.state) || durable.run.state === "blocked") return;
      const transition = this.coordinator.transitionRun({
        lease,
        to: "blocked",
        reason: `Durable continuation retry budget exhausted for ${continuation.kind}`,
      });
      this.repository.events.append({
        missionId: transition.run.run.missionId,
        runId: continuation.runId,
        journey: transition.run.run.journey,
        eventType: "run.continuation_blocked",
        actorType: "system",
        summary: `Run blocked after five bounded attempts to resume ${continuation.kind}`,
        payload: {
          continuationId: continuation.id,
          kind: continuation.kind,
          attempts: continuation.attemptCount,
        },
      });
    });
  }

  private blockCorruptGuidedStopContinuation(
    continuation: RuntimeContinuation,
    error: CommandRuntimeError,
  ): void {
    if (!continuation.leaseOwner) return;
    const now = this.timestamp();
    const lease = this.continuationLease(continuation.runId);
    inImmediateTransaction(this.database, () => {
      this.continuations.fail({
        id: continuation.id,
        ownerToken: continuation.leaseOwner!,
        now,
        error: error.message,
      });
      const transition = this.coordinator.transitionRun({
        lease,
        to: "blocked",
        reason: error.options.humanMessage ?? error.message,
      });
      this.repository.events.append({
        missionId: transition.run.run.missionId,
        runId: continuation.runId,
        journey: transition.run.run.journey,
        eventType: "guided.stop_recovery_integrity_blocked",
        actorType: "system",
        actorId: this.workerId,
        summary: error.options.humanMessage ?? error.message,
        payload: {
          continuationId: continuation.id,
          cancellationRequestEventId: continuation.sourceId,
          errorCode: error.code,
          automaticRetryPermitted: false,
          targetContacted: false,
        },
      });
      new FailureDiagnosisService(this.database, { clock: this.now }).create({
        missionId: transition.run.run.missionId,
        runId: continuation.runId,
        subjectType: "run",
        subjectId: continuation.runId,
        humanReason: error.options.humanMessage ?? error.message,
        category: "migration_integrity_error",
        code: error.code,
        originatingComponent: "command-runtime.guided-stop-recovery",
        failedComponentRef: continuation.sourceId,
        targetSummary: "No new target, provider, MCP, or tool action was dispatched during cancellation recovery.",
        policyOrDependency: "A Guided stop may complete only when its persisted decision, step, fingerprint, and normalized-parameter hash match the canonical decision record.",
        retryHistory: [{
          attempt: continuation.attemptCount,
          continuationId: continuation.id,
          automaticRetryPermitted: false,
        }],
        progressBeforeFailure: transition.run.control.progress,
        preservedReferences: [{
          kind: "checkpoint",
          id: transition.checkpointId,
          meaning: "Authority-fenced checkpoint created when Guided stop recovery failed integrity validation",
        }, {
          kind: "event",
          id: continuation.sourceId,
          meaning: "Immutable cancellation request whose Guided stop boundary requires review",
        }],
        retryable: false,
        automaticRecovery: {
          directive: "blocked",
          automaticActionDispatched: false,
          cancellationContinuationCancelled: true,
        },
        remediation: error.options.remediation
          ?? "Inspect the cancellation request and canonical Guided decision before taking a reviewed recovery action.",
        operatorActions: [{
          kind: "terminate_gracefully",
          label: "Review and terminate safely",
          consequence: "Keeps the corrupt stop boundary quarantined while an operator reviews the immutable cancellation and decision records.",
          requiresConfirmation: true,
        }, {
          kind: "start_new_run",
          label: "Start a new run",
          consequence: "Preserves this blocked run and starts a separately versioned attempt after the integrity issue is reviewed.",
          requiresConfirmation: true,
        }],
        objectiveImpact: "The mission remains incomplete and blocked; no unverified Guided stop record was fabricated.",
        terminal: false,
        actor: { id: this.workerId, type: "worker" },
      });
    });
  }

  private async finalizeCancellationContinuation(continuation: RuntimeContinuation): Promise<void> {
    const event = this.database.prepare(`
      SELECT actor_id, summary, payload_json,
        json_extract(payload_json, '$.commandId') AS command_id
      FROM events
      WHERE id = ? AND run_id = ? AND event_type = 'run.cancellation_requested'
    `).get(continuation.sourceId, continuation.runId) as {
      actor_id: string | null;
      summary: string;
      payload_json: string;
      command_id: string | null;
    } | undefined;
    const actorId = event?.actor_id ?? "operator";
    const reason = event?.summary.replace(/^Cancellation requested:\s*/u, "").trim()
      || "Operator requested cancellation";
    const before = this.coordinator.getRun(continuation.runId);
    const guidedStop = event
      ? this.guidedStopFromCancellationPayload(
          event.payload_json,
          before.run.missionId,
          continuation.runId,
        )
      : undefined;
    if (before.run.state === "cancelled") {
      const now = this.timestamp();
      inImmediateTransaction(this.database, () => {
        this.repository.cancelOpenWork(continuation.runId, actorId, reason, now);
        if (guidedStop) {
          this.appendGuidedStopRecords(
            guidedStop,
            actorId,
            reason,
            now,
            event?.command_id ?? undefined,
          );
        }
        this.completeContinuation(continuation);
        this.releaseControlPlaneAuthorityInTransaction(continuation.runId, now);
      });
      this.clearActionContextsForRun(continuation.runId);
      this.controlPlaneTokens.delete(continuation.runId);
      return;
    }
    const lease = this.continuationLease(continuation.runId);
    this.controllers.get(continuation.runId)?.abort(reason);
    await this.options.execution.cancelRun(continuation.runId, reason);
    const now = this.timestamp();
    inImmediateTransaction(this.database, () => {
      // Close child aggregates before the terminal transition creates its
      // checkpoint so the checkpoint cannot retain ghost in-flight work.
      this.repository.cancelOpenWork(continuation.runId, actorId, reason, now);
      const transition = this.coordinator.transitionRun({
        lease,
        to: "cancelled",
        reason,
      });
      this.database.prepare("UPDATE missions SET status = 'cancelled', updated_at = ? WHERE id = ?")
        .run(now, transition.run.run.missionId);
      if (guidedStop) {
        this.appendGuidedStopRecords(
          guidedStop,
          actorId,
          reason,
          now,
          event?.command_id ?? undefined,
        );
      }
      this.repository.appendAudit({
        missionId: transition.run.run.missionId,
        runId: continuation.runId,
        actorId,
        action: "run.cancelled",
        resourceType: "run",
        resourceId: continuation.runId,
        reason,
        details: {
          ...(event?.command_id ? { commandId: event.command_id } : {}),
          committedRunVersion: transition.run.run.stateVersion,
          checkpointId: transition.checkpointId,
          checkpointEventSequence: transition.eventSequence,
        },
        now,
      });
      this.completeContinuation(continuation);
      this.continuations.cancelOpen(continuation.runId, now, "Run reached a terminal cancelled state");
      // Enqueue the optional post-commit projection after cancellation has
      // closed ordinary work, otherwise cancelOpen would cancel this freshly
      // created terminal projection continuation as if it were child work.
      this.recordTerminalEvaluationWithBrain({
        runId: continuation.runId,
        terminalStatus: "cancelled",
        createdBy: "run-supervisor",
      });
      this.repository.events.append({
        missionId: transition.run.run.missionId,
        runId: continuation.runId,
        journey: transition.run.run.journey,
        eventType: "run.cancelled",
        actorType: "operator",
        actorId,
        summary: `Run cancelled and all durable child work closed: ${reason}`,
        payload: {
          continuationId: continuation.id,
          aggregateClosed: true,
          stateVersion: transition.run.run.stateVersion,
          ...(event?.command_id ? { commandId: event.command_id } : {}),
        },
      });
      this.releaseControlPlaneAuthorityInTransaction(continuation.runId, now);
    });
    this.clearActionContextsForRun(continuation.runId);
    this.controlPlaneTokens.delete(continuation.runId);
  }

  private async processRun(runId: string, planningRetryContinuationId?: string): Promise<void> {
    this.assertV2ControlPlaneOwnership(runId);
    let planningRun = this.repository.getPlanningRun(runId);
    if (!this.supportedJourneys.has(planningRun.journey)) return;
    if (planningRun.state !== "planning" && planningRun.state !== "recovering") return;
    this.ensureControlPlaneAuthority(runId);
    const mission = this.repository.getMission(planningRun.missionId);
    const guidedRecovery = planningRun.journey === "guided"
      ? this.repository.latestGuidedRecovery(runId)
      : null;
    const durableAtStart = this.coordinator.getRun(runId);
    const scheduledPlanningRetry = durableAtStart.control.planningRetry;
    if (scheduledPlanningRetry) {
      if (
        planningRetryContinuationId !== scheduledPlanningRetry.continuationId ||
        Date.parse(scheduledPlanningRetry.notBefore) > Date.parse(this.timestamp())
      ) return;
    }
    const recovery = durableAtStart.control.recovery;
    if (
      planningRun.journey === "autonomous" && planningRun.state === "recovering" &&
      recovery?.kind === "retry" && Date.parse(recovery.notBefore) > Date.parse(this.timestamp())
    ) return;
    let lease = durableAtStart.lease?.ownerId === this.workerId
      ? durableAtStart.lease
      : this.acquireWorkerRunLease(runId);
    if (scheduledPlanningRetry && planningRetryContinuationId) {
      const begun = this.coordinator.beginScheduledPlanningRetry({
        lease,
        continuationId: planningRetryContinuationId,
      });
      if (!begun.run.lease) {
        throw new CommandRuntimeError(500, "planning_retry_lease_lost", "Planning retry lost its run lease");
      }
      lease = begun.run.lease;
      planningRun = this.repository.getPlanningRun(runId);
      this.crashAfterCommit("planning_retry_started", runId, planningRetryContinuationId);
    }
    if (planningRun.journey === "autonomous" && planningRun.state === "recovering" && recovery?.kind === "retry") {
      // The failed action committed a delayed, owner-fenced continuation in
      // the same transaction that requeued its exact assignment and step.
      // Never reconstruct retry work from an in-memory timer.
      await this.replayContinuations(runId, ["autonomous_retry_to_dispatch"]);
      return;
    }
    if (planningRun.journey === "autonomous" && planningRun.state === "recovering" && recovery?.kind === "replan") {
      try {
        this.options.autonomousActivation?.verifyCurrent({ runId });
        const replanContext = this.retrieveBrainContext({
          hook: "replan",
          mission,
          run: planningRun,
          actorId: "recovery-planner",
          query: `${recovery.reason} materially different strategy`,
          queryRedacted: "Autonomous bounded replan",
        });
        this.brainContext.recordUnusedContext(
          replanContext,
          "The deterministic bounded-replan gate used memory only for scoped readiness and audit context; it did not silently alter the signed contract or recovery reason.",
        );
        const accounted = this.coordinator.accountUsage({ lease, phase: "bounded replan readiness" });
        if (!accounted.allowed || !accounted.run.lease) {
          throw new CommandRuntimeError(409, "run_budget_exhausted", "Signed run budget was exhausted before replanning", {
            humanMessage: `Safe-stopped before replan: ${accounted.exhausted.join(", ")} budget exhausted.`,
            category: "policy_denied",
          });
        }
        const failed = new ActionRepository(this.database).get(recovery.failedActionId);
        const bounded = this.coordinator.beginReplan({
          lease: accounted.run.lease,
          reason: `${recovery.reason} Failed action: ${failed.intentSummary}`,
        });
        if (!bounded.run.lease) throw new CommandRuntimeError(500, "replan_lease_lost", "Autonomous replan lost its run lease");
        lease = bounded.run.lease;
        planningRun = this.repository.getPlanningRun(runId);
      } catch (error) {
        const runtimeError = asRuntimeError(error);
        const latest = this.coordinator.getRun(runId);
        const stopLease = latest.lease?.ownerId === this.workerId ? latest.lease : lease;
        await this.safeStopPlanning(runId, stopLease, runtimeError);
        throw runtimeError;
      }
    }
    if (planningRun.journey === "guided" && planningRun.state === "recovering" && guidedRecovery) {
      try {
        const replanContext = this.retrieveBrainContext({
          hook: "replan",
          mission,
          run: planningRun,
          actorId: "guided-recovery-planner",
          query: `${guidedRecovery.errorCategory} materially different recovery strategy`,
          queryRedacted: "Guided bounded replan",
        });
        this.brainContext.recordUnusedContext(
          replanContext,
          "The deterministic Guided recovery gate used memory only for scoped readiness and audit context; it did not silently replace the represented operator decision or failure facts.",
        );
        const bounded = this.coordinator.beginReplan({
          lease,
          reason: `Bounded Guided recovery planning after ${guidedRecovery.errorCategory}; the failed action will not be repeated`,
        });
        if (!bounded.run.lease) {
          throw new CommandRuntimeError(500, "guided_recovery_lease_lost", "Guided recovery lost its run lease");
        }
        lease = bounded.run.lease;
      } catch (error) {
        const runtimeError = asRuntimeError(error);
        await this.safeStopPlanning(runId, lease, runtimeError);
        throw runtimeError;
      }
    }
    const heartbeat = this.heartbeat(lease);
    let heartbeatStopped = false;
    let planningProviderFailed = false;
    let planningProviderUsageAccounted = false;
    const signal = this.controller(runId).signal;
    try {
      if (mission.authorizationStatus !== "verified") {
        throw new CommandRuntimeError(409, "authorization_not_verified", "Mission authorization is not verified", {
          humanMessage: "Execution stopped because the mission authorization is not currently valid.",
          category: "authorization_denied",
        });
      }
      const planningContext = this.retrieveBrainContext({
        hook: "planning",
        mission,
        run: planningRun,
        actorId: "mission-planner",
        query: `${mission.objective} ${planningRun.stateReason}`,
        queryRedacted: `${planningRun.journey} mission planning`,
      });
      const activationPlanningDigest = hashCanonical({
        schemaVersion: "ti-scale.autonomous-planning-boundary.v1",
        missionId: mission.id,
        runId,
        contextPackId: planningContext.contextPack.id,
        runState: planningRun.state,
        replanCount: planningRun.replanCount,
        currentPlanVersion: planningRun.currentPlanVersion,
        stateReason: planningRun.stateReason,
      });
      const activationBoundary =
        planningRun.journey === "autonomous" && this.options.autonomousActivation
          ? this.options.autonomousActivation.ensureIssued({
          missionId: mission.id,
          runId,
          brainContextPackId: planningContext.contextPack.id,
          issuedBy: this.workerId,
        })
          : undefined;
      if (activationBoundary?.planning.route === "local_deterministic") {
        this.options.autonomousActivation?.verifyAndBind({
          runId,
          bindingType: "planning",
          subjectId: `planning:${planningContext.contextPack.id}`,
          subjectDigest: activationPlanningDigest,
          contextPackId: planningContext.contextPack.id,
          boundBy: this.workerId,
        });
      }
      let planned: MissionPlanPortResult;
      let planningProviderTurn: PlanningProviderTurn | undefined;
      let planningProviderTurnFinished = false;
      let planningProviderCallStarted = false;
      let trustedPlanningAttribution:
        MissionPlanDraft["planningAttribution"];
      try {
        const rejectionReason = guidedRecovery
          ? `The represented action "${guidedRecovery.attemptedActionSummary}" failed with ${guidedRecovery.errorCategory}: ${guidedRecovery.failureSummary}. Propose one materially different in-scope action; do not repeat the failed parameters.`
          : recovery?.kind === "replan"
            ? recovery.reason
            : planningRun.state === "recovering"
              ? planningRun.stateReason
              : undefined;
        const useSignedAutonomousRoute =
          planningRun.journey === "autonomous"
          && activationBoundary !== undefined
          && this.options.autonomousPlanning !== undefined;
        if (useSignedAutonomousRoute) {
          const policy = this.readAutonomousPlanningPolicy(
            mission.id,
            runId,
          );
          if (policy.selection.route !== activationBoundary.planning.route) {
            throw new CommandRuntimeError(
              409,
              "autonomous_activation_planning_route_mismatch",
              "The confirmed contract and verified activation receipt select different planning routes",
              {
                humanMessage: "Safe-stopped before planning because the signed per-run planning route is inconsistent.",
                retryable: false,
                category: "policy_denied",
                remediation: "Issue a fresh activation receipt from the unchanged confirmed contract or start a new run.",
              },
            );
          }
          const localBoundary = errorRecord(
            errorRecord(this.options.planner).localPlanningBoundary,
          );
          if (
            localBoundary.kind !== "local_deterministic"
            || localBoundary.providerContact !== false
            || typeof localBoundary.policyHash !== "string"
            || !/^[a-f0-9]{64}$/u.test(localBoundary.policyHash)
          ) {
            throw new CommandRuntimeError(
              503,
              "autonomous_local_planner_boundary_missing",
              "The production Autonomous runtime has no exact local planning compiler",
              {
                humanMessage: "Safe-stopped before planning because every Autonomous route must begin with the reviewed local plan compiler.",
                retryable: false,
                category: "dependency_missing",
                remediation: "Restore the reviewed local deterministic planner and its immutable policy hash.",
              },
            );
          }
          const localPlanned = planResult(await this.options.planner.plan({
            mission,
            run: planningRun,
            brainContext: this.brainContext.localContext(planningContext),
            ...(rejectionReason ? { rejectionReason } : {}),
          }, signal));
          if (
            !canonicalZeroProviderUsage(localPlanned.usage)
            || !canonicalZeroProviderUsage(
              localPlanned.plan.providerUsage,
            )
          ) {
            throw new CommandRuntimeError(
              409,
              "autonomous_local_planner_provider_usage_forbidden",
              "The local plan compiler reported a provider turn",
              {
                humanMessage: "Safe-stopped because the trusted local planner attempted to report public-provider activity.",
                retryable: false,
                category: "policy_denied",
                remediation: "Restore the provider-free local compiler; local planning must create zero provider turns, exposures, or network calls.",
              },
            );
          }
          const localDraft = validateMissionPlanDraft(
            localPlanned.plan,
            this.maxPlanSteps,
            "autonomous",
          );
          const boundLocalDraft = this.bindAutonomousPlanModels(
            mission.id,
            runId,
            localDraft,
          );
          trustedPlanningAttribution =
            localPlanned.plan.planningAttribution;
          if (activationBoundary.planning.route === "local_deterministic") {
            if (policy.selection.route !== "local_deterministic") {
              throw new CommandRuntimeError(
                409,
                "autonomous_local_planning_selection_mismatch",
                "The local route is not the exact confirmed planning selection",
                {
                  humanMessage: "Safe-stopped because the local compiler is not authorized by this run's signed planning selection.",
                  retryable: false,
                  category: "policy_denied",
                },
              );
            }
            planned = {
              plan: {
                ...boundLocalDraft,
                ...(trustedPlanningAttribution
                  ? { planningAttribution: trustedPlanningAttribution }
                  : {}),
              },
              ...(localPlanned.usage
                ? { usage: localPlanned.usage }
                : {}),
            };
          } else {
            if (policy.selection.route !== "provider_advisory") {
              throw new CommandRuntimeError(
                409,
                "autonomous_provider_planning_selection_mismatch",
                "The provider route is not the exact confirmed planning selection",
                {
                  humanMessage: "Safe-stopped before provider contact because this run did not sign the advisory route.",
                  retryable: false,
                  category: "policy_denied",
                },
              );
            }
            const providerAdvisory =
              this.options.autonomousPlanning.providerAdvisory;
            const providerContext =
              this.options.autonomousPlanning.providerContext;
            if (!providerAdvisory || !providerContext) {
              throw new CommandRuntimeError(
                503,
                "autonomous_activation_provider_advisor_missing",
                "The signed provider-advisory route is not fully mounted",
                {
                  humanMessage: "Safe-stopped after local plan compilation because the signed advisor or its provider-safe Brain context adapter is unavailable.",
                  retryable: false,
                  category: "dependency_missing",
                  remediation: "Restore both reviewed advisory ports or start a new run whose contract selects local deterministic planning.",
                },
              );
            }
            const runtimeModelBinding = this.resolvePlanningModelBinding({
              missionId: mission.id,
              runId,
              agentId: policy.selection.agentId,
              modelAssignmentId:
                activationBoundary.planning.modelAssignmentId,
              primaryConfigurationId:
                activationBoundary.planning.primaryConfigurationId,
              primaryConfigurationHash:
                activationBoundary.planning.primaryConfigurationHash,
            });
            if (
              activationBoundary.planning.plannerId !==
                policy.selection.agentId
              || runtimeModelBinding.modelAssignmentId !==
                activationBoundary.planning.modelAssignmentId
              || runtimeModelBinding.modelConfigurationId !==
                policy.selection.primaryConfigurationId
              || runtimeModelBinding.providerId !== "openrouter"
            ) {
              throw new CommandRuntimeError(
                409,
                "autonomous_activation_planner_pin_mismatch",
                "The signed advisor does not match its exact purpose=planning assignment",
                {
                  humanMessage: "Safe-stopped before provider contact because the advisor identity or immutable model pin drifted from the activation receipt.",
                  retryable: false,
                  category: "policy_denied",
                  remediation: "Restore the exact healthy OpenRouter advisor-only planning pin or start a new run.",
                },
              );
            }
            const planningRequestId =
              `planning-request-${randomUUID()}`;
            const candidateCatalog = this.providerAdvisoryCandidateInput({
              mission,
              run: planningRun,
              activation: activationBoundary,
              policy,
              localPolicyHash: localBoundary.policyHash,
              localPlan: boundLocalDraft,
              planningRequestId,
              contextPackId: planningContext.contextPack.id,
            });
            const opaqueTerms =
              this.providerAdvisoryOpaqueTerms(candidateCatalog);
            const providerConfigurationHash =
              resolveOpenRouterModelConfiguration({
                model: runtimeModelBinding.modelId,
              }).configurationHash;
            const resolvedBinding:
              ProviderAdvisoryResolvedPlanningBinding = Object.freeze({
                agentId: policy.selection.agentId,
                primaryConfigurationId:
                  policy.selection.primaryConfigurationId,
                providerId: "openrouter",
                modelId: runtimeModelBinding.modelId,
                modelConfigurationHash:
                  providerConfigurationHash,
                disclosureClass: policy.selection.disclosureClass,
                enforcementMode: "advisor_only",
                executionAuthority: "none",
              });
            planningProviderTurn = this.startPlanningProviderTurn({
              runId,
              providerId: resolvedBinding.providerId,
              modelId: resolvedBinding.modelId,
              modelConfigurationHash:
                providerConfigurationHash,
              runtimeModelBinding,
            });
            this.options.autonomousActivation?.verifyAndBind({
              runId,
              bindingType: "planning",
              subjectId:
                `planning:${planningContext.contextPack.id}:${planningProviderTurn.id}`,
              subjectDigest: hashCanonical({
                activationPlanningDigest,
                providerTurnId: planningProviderTurn.id,
                planningRequestId,
              }),
              contextPackId: planningContext.contextPack.id,
              providerTurnId: planningProviderTurn.id,
              boundBy: this.workerId,
            });
            const brainContextPreparation = Object.freeze({
              missionId: mission.id,
              runId,
              contextPackId: planningContext.contextPack.id,
              retrievedByActorId: "mission-planner",
              actorId: policy.selection.agentId,
              disclosureClass: policy.selection.disclosureClass,
              opaqueTerms,
              maximumItems: 6,
              maximumBytes: 4_000,
            });
            const disclosedContext = providerContext.prepare(
              brainContextPreparation,
            );
            const route = new SignedAutonomousPlanningRoutePort({
              database: this.database,
              local: {
                route: "local_deterministic",
                async plan() {
                  return localPlanned;
                },
              },
              provider: providerAdvisory,
            });
            planningProviderCallStarted = true;
            planningProviderFailed = true;
            const outcome = await route.plan({
              route: "provider_advisory",
              missionId: mission.id,
              runId,
              signedSelection: policy.selection,
              providerInput: {
                providerTurnId: planningProviderTurn.id,
                resolvedBinding,
                candidateCatalog,
                createdAt: this.timestamp(),
                contextItems: disclosedContext.items,
                brainContextSnapshot: Object.freeze({
                  preparation: brainContextPreparation,
                  inputFingerprint:
                    disclosedContext.telemetry.inputFingerprint,
                  outputHash: disclosedContext.telemetry.outputHash,
                }),
              },
            }, signal);
            if (outcome.status === "safe_stopped") {
              if (outcome.safeStop.providerUsage) {
                const failedUsage = this.bindPlanningProviderUsage(
                  outcome.safeStop.providerUsage,
                  planningProviderTurn,
                );
                this.finishPlanningProviderTurn({
                  turn: planningProviderTurn,
                  status: outcome.safeStop.category === "cancelled"
                    ? "cancelled"
                    : "failed",
                  usage: failedUsage,
                  errorCategory: outcome.safeStop.category,
                });
                planningProviderTurnFinished = true;
                lease = await heartbeat.stop();
                heartbeatStopped = true;
                // The provider has already billed this response even though
                // its structured advisory payload was rejected locally.
                planningProviderUsageAccounted = true;
                lease = this.accountProviderUsage(
                  lease,
                  failedUsage,
                  "failed mission planning turn",
                );
              }
              if (outcome.safeStop.category === "cancelled") {
                throw new DOMException(
                  outcome.safeStop.humanReason,
                  "AbortError",
                );
              }
              throw this.providerAdvisorySafeStopError(outcome.safeStop);
            }
            if (outcome.route !== "provider_advisory") {
              throw new CommandRuntimeError(
                500,
                "autonomous_planning_route_result_mismatch",
                "The signed provider route returned a local planning result",
                {
                  humanMessage: "Safe-stopped because the per-run planning router returned the wrong route result.",
                  retryable: false,
                  category: "policy_denied",
                },
              );
            }
            planned = {
              plan: outcome.plan,
              usage: outcome.plan.providerUsage,
            };
          }
        } else {
        const providerBoundary = this.options.planner.providerBoundary;
        let providerContext: MissionPlannerInput["brainContext"];
        if (providerBoundary) {
          if (
            activationBoundary &&
            activationBoundary.planning.route !== "provider_advisory"
          ) {
            throw new CommandRuntimeError(
              409,
              "autonomous_activation_planning_route_mismatch",
              "The signed aggregate activation receipt requires local deterministic planning",
              {
                humanMessage: "Safe-stopped before provider contact because this run is activated for local deterministic planning, not a public planning turn.",
                retryable: false,
                category: "policy_denied",
                remediation: "Start a new run with the desired reviewed planning route signed into its contract.",
              },
            );
          }
          const runtimeModelBinding = planningRun.journey === "autonomous"
            && this.options.agentRuntimeBindings
            ? (() => {
                if (!providerBoundary.agentId) {
                  throw new CommandRuntimeError(
                    409,
                    "autonomous_planner_agent_binding_missing",
                    "The public Autonomous planner does not identify its exact product-agent model assignment",
                    {
                      humanMessage: "Safe-stopped before provider contact because the planner model is not tied to one signed agent assignment.",
                      retryable: false,
                      category: "policy_denied",
                      remediation: "Configure the reviewed public planner with one canonical agentId and launch a new run.",
                    },
                  );
                }
                if (
                  activationBoundary?.planning.route ===
                    "provider_advisory"
                ) {
                  return this.resolvePlanningModelBinding({
                    missionId: mission.id,
                    runId,
                    agentId: providerBoundary.agentId,
                    modelAssignmentId:
                      activationBoundary.planning.modelAssignmentId,
                    primaryConfigurationId:
                      activationBoundary.planning.primaryConfigurationId,
                    primaryConfigurationHash:
                      activationBoundary.planning.primaryConfigurationHash,
                    expectedProviderId: providerBoundary.providerId,
                    expectedModelId: providerBoundary.modelId,
                    providerConfigurationHash:
                      providerBoundary.modelConfigurationHash,
                  });
                }
                return this.resolveRunModelBinding({
                  missionId: mission.id,
                  runId,
                  agentId: providerBoundary.agentId,
                  modelConfigurationHash: providerBoundary.modelConfigurationHash,
                  expectedProviderId: providerBoundary.providerId,
                  expectedModelId: providerBoundary.modelId,
                });
              })()
            : undefined;
          if (
            activationBoundary?.planning.route === "provider_advisory" &&
            (
              !runtimeModelBinding ||
              providerBoundary.agentId !==
                activationBoundary.planning.plannerId ||
              runtimeModelBinding.modelAssignmentId !==
                activationBoundary.planning.modelAssignmentId ||
              runtimeModelBinding.modelConfigurationId !==
                activationBoundary.planning.primaryConfigurationId ||
              runtimeModelBinding.modelConfigurationHash !==
                activationBoundary.planning.primaryConfigurationHash ||
              providerBoundary.modelConfigurationHash !==
                activationBoundary.planning.primaryConfigurationHash
            )
          ) {
            throw new CommandRuntimeError(
              409,
              "autonomous_activation_planner_pin_mismatch",
              "The public planner boundary does not match the aggregate activation receipt",
              {
                humanMessage: "Safe-stopped before provider contact because the planner agent, assignment, or exact model configuration differs from the signed activation receipt.",
                retryable: false,
                category: "policy_denied",
                remediation: "Restore the exact purpose=planning model pin or start a new run with a newly reviewed contract.",
              },
            );
          }
          planningProviderTurn = this.startPlanningProviderTurn({
            runId,
            providerId: providerBoundary.providerId,
            modelId: providerBoundary.modelId,
            modelConfigurationHash: providerBoundary.modelConfigurationHash,
            ...(runtimeModelBinding ? { runtimeModelBinding } : {}),
          });
          if (
            activationBoundary?.planning.route === "provider_advisory" &&
            this.options.autonomousActivation
          ) {
            this.options.autonomousActivation.verifyAndBind({
              runId,
              bindingType: "planning",
              subjectId: `planning:${planningContext.contextPack.id}`,
              subjectDigest: activationPlanningDigest,
              contextPackId: planningContext.contextPack.id,
              providerTurnId: planningProviderTurn.id,
              boundBy: this.workerId,
            });
          }
          providerContext = this.brainContext.prepareProviderContext(planningContext, {
            providerTurnId: planningProviderTurn.id,
            providerId: planningProviderTurn.providerId,
            modelId: planningProviderTurn.modelId,
            modelConfigurationHash: planningProviderTurn.modelConfigurationHash,
          });
        } else {
          if (activationBoundary?.planning.route === "provider_advisory") {
            throw new CommandRuntimeError(
              409,
              "autonomous_activation_provider_planner_missing",
              "The aggregate activation receipt requires one exact provider-advisory planning turn",
              {
                humanMessage: "Safe-stopped before planning because the signed provider-advisory route is not mounted.",
                retryable: false,
                category: "dependency_missing",
                remediation: "Restore the exact signed planning adapter or start a new run using local deterministic planning.",
              },
            );
          }
          providerContext = this.brainContext.localContext(planningContext);
        }
        planningProviderCallStarted = true;
        planningProviderFailed = planningProviderTurn !== undefined;
        planned = planResult(await this.options.planner.plan({
            mission,
            run: planningRun,
            brainContext: providerContext,
            ...(rejectionReason ? { rejectionReason } : {}),
          }, signal));
        }
        if (planningProviderTurn && !planningProviderTurnFinished) {
          const usage = this.bindPlanningProviderUsage(
            planned.usage,
            planningProviderTurn,
          );
          planned = { ...planned, usage };
          this.finishPlanningProviderTurn({
            turn: planningProviderTurn,
            status: "completed",
            usage,
          });
          planningProviderTurnFinished = true;
          lease = await heartbeat.stop();
          heartbeatStopped = true;
          // A completed public-provider response is billable even if a later
          // local model-pin or plan-integrity check rejects activation.
          planningProviderUsageAccounted = true;
          lease = this.accountProviderUsage(
            lease,
            usage,
            "mission planning",
          );
        }
      } catch (error) {
        if (planningProviderTurn && !planningProviderTurnFinished) {
          const aborted = signal.aborted || (error instanceof DOMException && error.name === "AbortError");
          const runtimeError = asRuntimeError(error);
          this.finishPlanningProviderTurn({
            turn: planningProviderTurn,
            status: aborted ? "cancelled" : "failed",
            errorCategory: aborted
              ? "cancelled"
              : planningProviderTurnErrorCategory(error, runtimeError),
          });
          planningProviderTurnFinished = true;
        }
        // A deterministic local planner shares the same bounded planning
        // lifecycle but is not a provider turn. Never charge provider usage,
        // apply provider retry policy, or persist a provider failure diagnosis
        // when no exact provider boundary was opened.
        planningProviderFailed = planningProviderCallStarted
          && planningProviderTurn !== undefined;
        throw error;
      }
      const validatedDraft = validateMissionPlanDraft(
        planned.plan,
        this.maxPlanSteps,
        planningRun.journey,
      );
      const draft = planningRun.journey === "autonomous"
        ? this.bindAutonomousPlanModels(mission.id, runId, validatedDraft)
        : validatedDraft;
      if (!heartbeatStopped) {
        lease = await heartbeat.stop();
        heartbeatStopped = true;
      }
      if (!planningProviderUsageAccounted) {
        lease = this.accountProviderUsage(
          lease,
          planned.usage,
          "mission planning",
        );
      }
      const activationAt = this.timestamp();
      const committed = inImmediateTransaction(this.database, () => {
        const plan = this.repository.persistPlanRecords({
          mission,
          run: planningRun,
          lease,
          plan: draft,
          now: activationAt,
          decisionTtlMs: this.decisionTtlMs,
          ...(guidedRecovery ? { guidedRecovery } : {}),
        });
        if (planningRun.journey === "autonomous" && this.options.autonomousActivation) {
          this.options.autonomousActivation.verifyAndBind({
            runId,
            bindingType: "plan_version",
            subjectId: plan.planId,
            subjectDigest: plan.planHash,
            planId: plan.planId,
            contextPackId: planningContext.contextPack.id,
            boundBy: this.workerId,
          });
        }
        commitPlanningContextAttribution(
          this.database,
          trustedPlanningAttribution ?? planned.plan.planningAttribution,
          {
            missionId: mission.id,
            runId,
            journey: planningRun.journey,
            usedAt: activationAt,
          },
        );
        if (planningRun.journey === "guided") {
          this.database.prepare(`
            UPDATE plan_steps SET status = 'waiting_guided_decision', updated_at = ? WHERE id = ?
          `).run(activationAt, plan.firstStepId);
        }
        let transition = this.coordinator.transitionRun({
          lease,
          to: "running",
          reason: planningRun.journey === "autonomous"
            ? "Confirmed Autonomous plan activated; executing without routine operator input"
            : "Guided plan activated so the first represented decision can be published",
        });
        if (planningRun.journey === "guided") {
          if (!plan.guidedDecisionId || !transition.run.lease) {
            throw new CommandRuntimeError(500, "guided_decision_missing", "Guided planning did not produce a durable decision");
          }
          transition = this.coordinator.transitionRun({
            lease: transition.run.lease,
            to: "waiting_guided_decision",
            reason: "The first Guided step is explained and awaits one exact operator decision",
            guidedDecisionId: plan.guidedDecisionId,
          });
        }
        if (planningRun.journey === "autonomous") {
          this.continuations.enqueue({
            runId,
            kind: "plan_ready_to_dispatch",
            sourceId: plan.planId,
            payload: { stepId: plan.firstStepId },
            now: activationAt,
          });
        }
        return { plan, transition };
      });
      if (planningRun.journey === "autonomous") {
        this.crashAfterCommit("plan_ready_to_dispatch", runId, committed.plan.planId);
      }
      if (planningRun.journey === "autonomous") {
        if (!committed.transition.run.lease) {
          throw new CommandRuntimeError(500, "runtime_lease_lost", "Autonomous launch lost its lease");
        }
        if (!this.continuationProcessing.has(runId)) {
          await this.replayContinuations(runId, ["plan_ready_to_dispatch"]);
        }
      }
    } catch (error) {
      if (!heartbeatStopped) lease = await heartbeat.stop().catch(() => lease);
      if (error instanceof RuntimeCrashAfterCommit) throw error;
      let runtimeError = asRuntimeError(error);
      if (planningProviderFailed) {
        const category = planningFailureCategory(error, runtimeError);
        const canRetry = planningRun.journey === "autonomous"
          && isRetryableCategory(category)
          && runtimeError.options.retryable !== false;
        if (canRetry) {
          const retryAfterMs = planningRetryAfterMs(error, this.now());
          const scheduled = this.coordinator.schedulePlanningRetry({
            lease,
            category,
            errorCode: runtimeError.code,
            ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
            ...(this.options.retryRandom ? { random: this.options.retryRandom } : {}),
          });
          if (scheduled.scheduled) {
            this.persistPlanningFailureDiagnosis({
              runId,
              originalError: error,
              runtimeError,
              boundary: "provider",
              category,
              retryAfterMs,
              checkpointId: scheduled.checkpointId,
              retryScheduled: {
                continuationId: scheduled.continuationId,
                notBefore: scheduled.notBefore,
                retryCount: scheduled.retryCount,
              },
              terminal: false,
            });
            this.crashAfterCommit("planning_retry_scheduled", runId, scheduled.continuationId);
            return;
          }
          const retriesUsed = this.coordinator.getRun(runId).control.retryCount;
          const providerWaitExceedsBound = scheduled.reason === "provider_retry_after_exceeds_bound";
          const exhausted = scheduled.reason === "signed_budget_exhausted"
            ? ` The signed ${scheduled.exhausted.join(", ")} budget leaves no room for another provider turn.`
            : providerWaitExceedsBound
              ? " The provider requested a wait longer than V2's configured automatic-retry safety limit; V2 did not shorten that window or retry early."
              : " The default bounded retry allowance of two automatic retries is exhausted.";
          runtimeError = new CommandRuntimeError(
            429,
            providerWaitExceedsBound
              ? `mission_runtime_${category}_retry_after_exceeds_bound`
              : `mission_runtime_${category}_retry_exhausted`,
            "Autonomous planning retry path exhausted",
            {
              humanMessage: providerWaitExceedsBound
                ? `Safe-stopped: Autonomous planning cannot retry safely.${exhausted} ${retriesUsed} bounded automatic ${retriesUsed === 1 ? "retry was" : "retries were"} used before this response.`
                : `Safe-stopped: Autonomous planning remained unavailable after ${retriesUsed} bounded automatic retries.${exhausted}`,
              retryable: false,
              category,
              details: {
                retriesUsed,
                retryReason: scheduled.reason,
                localCandidatesPreserved: true,
                localFallbackApplied: false,
                ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
                exhausted: [...scheduled.exhausted],
              },
              remediation: providerWaitExceedsBound
                ? "Wait for the provider window to recover, test provider readiness, then start a new run from the preserved mission."
                : "Wait for the provider window to recover, then start a new run from the preserved mission.",
            },
          );
        }
        if (!planningProviderUsageAccounted) {
          const accounted = this.coordinator.accountUsage({
            lease,
            delta: { providerTurns: 1 },
            phase: "failed mission planning turn",
          });
          planningProviderUsageAccounted = true;
          if (accounted.allowed && accounted.run.lease) {
            lease = accounted.run.lease;
          }
        }
      }
      const checkpointId = await this.safeStopPlanning(runId, lease, runtimeError);
      this.persistPlanningFailureDiagnosis({
        runId,
        originalError: error,
        runtimeError,
        boundary: planningProviderFailed ? "provider" : "local_deterministic",
        category: planningFailureCategory(error, runtimeError),
        retryAfterMs: planningRetryAfterMs(error, this.now()),
        ...(checkpointId ? { checkpointId } : {}),
        terminal: true,
      });
      throw runtimeError;
    }
  }

  private persistPlanningFailureDiagnosis(input: {
    readonly runId: string;
    readonly originalError: unknown;
    readonly runtimeError: CommandRuntimeError;
    readonly boundary: "provider" | "local_deterministic";
    readonly category: FailureCategory;
    readonly retryAfterMs?: number;
    readonly checkpointId?: string;
    readonly retryScheduled?: {
      readonly continuationId: string;
      readonly notBefore: string;
      readonly retryCount: number;
    };
    readonly terminal: boolean;
  }): void {
    const run = this.coordinator.getRun(input.runId);
    const providerTurns = this.database.prepare(`
      SELECT id, provider, model, status, error_category, latency_ms, started_at, ended_at
      FROM provider_turns
      WHERE run_id = ? AND status IN ('failed', 'cancelled')
      ORDER BY started_at, id
    `).all(input.runId) as Array<{
      id: string;
      provider: string;
      model: string;
      status: string;
      error_category: string | null;
      latency_ms: number | null;
      started_at: string;
      ended_at: string | null;
    }>;
    const originatingComponent = input.boundary === "provider"
      ? "command-runtime.planning-provider"
      : "command-runtime.local-planning";
    const latestTurn = providerTurns.at(-1);
    if (latestTurn) {
      const existing = this.database.prepare(`
        SELECT fd.id
        FROM failure_diagnoses fd, json_each(fd.retry_history_json) attempt
        WHERE fd.run_id = ? AND fd.subject_type = 'run'
          AND fd.originating_component = ?
          AND json_extract(attempt.value, '$.providerTurnId') = ?
        LIMIT 1
      `).get(input.runId, originatingComponent, latestTurn.id) as { id: string } | undefined;
      if (existing) return;
    } else {
      const existing = this.database.prepare(`
        SELECT id FROM failure_diagnoses
        WHERE run_id = ? AND subject_type = 'run'
          AND originating_component = ? AND code = ?
        LIMIT 1
      `).get(input.runId, originatingComponent, input.runtimeError.code) as { id: string } | undefined;
      if (existing) return;
    }
    const httpStatus = planningHttpStatus(input.originalError);
    const category = operationalFailureCategory(input.category);
    const retryable = isRetryableCategory(input.category)
      && input.runtimeError.options.retryable !== false
      && !input.terminal;
    const lastSuccess = this.database.prepare(`
      SELECT id FROM events
      WHERE run_id = ? AND event_type IN (
        'mission.created', 'run.autonomous_planning_started',
        'run.guided_planning_started', 'run.planning_retry_started'
      )
      ORDER BY sequence DESC LIMIT 1
    `).get(input.runId) as { id: string } | undefined;
    const retryHistory = providerTurns.length > 0
      ? providerTurns.map((turn, index) => ({
          attempt: index + 1,
          providerTurnId: turn.id,
          provider: turn.provider,
          model: turn.model,
          providerTurnStatus: turn.status,
          errorCategory: turn.error_category,
          latencyMs: turn.latency_ms,
          startedAt: turn.started_at,
          endedAt: turn.ended_at,
          ...(turn.id === latestTurn?.id && httpStatus !== undefined ? { httpStatus } : {}),
          ...(turn.id === latestTurn?.id && input.retryAfterMs !== undefined
            ? { retryAfterMs: input.retryAfterMs }
            : {}),
        }))
      : input.boundary === "local_deterministic"
        ? [{
            attempt: 1,
            planningBoundary: "local_deterministic",
            errorCategory: input.category,
          }]
        : [{
          attempt: run.control.retryCount + 1,
          providerTurnId: null,
          provider: null,
          model: null,
          providerTurnStatus: "failed",
          errorCategory: input.category,
          ...(httpStatus === undefined ? {} : { httpStatus }),
          ...(input.retryAfterMs === undefined ? {} : { retryAfterMs: input.retryAfterMs }),
        }];
    const automaticRecovery = input.retryScheduled
      ? {
          directive: "retry",
          scheduled: true,
          continuationId: input.retryScheduled.continuationId,
          notBefore: input.retryScheduled.notBefore,
          retryCount: input.retryScheduled.retryCount,
          retryAfterMs: input.retryAfterMs ?? null,
        }
      : {
          directive: "safe_stop",
          scheduled: false,
          retriesUsed: run.control.retryCount,
          retryAfterMs: input.retryAfterMs ?? null,
        };
    try {
      new FailureDiagnosisService(this.database, { clock: this.now }).create({
        missionId: run.run.missionId,
        runId: input.runId,
        subjectType: "run",
        subjectId: input.runId,
        humanReason: input.runtimeError.options.humanMessage ?? input.runtimeError.message,
        category,
        code: input.runtimeError.code,
        originatingComponent,
        ...(lastSuccess ? { lastSuccessEventId: lastSuccess.id } : {}),
        failedComponentRef: latestTurn
          ? `${latestTurn.provider}/${latestTurn.model}`
          : input.boundary === "local_deterministic"
            ? "local deterministic contract planner"
            : "configured planning provider",
        targetSummary: "Mission planning failed before any target, MCP tool, or represented action was contacted.",
        policyOrDependency: input.boundary === "local_deterministic"
          ? `The local planner rejected a contract, scope, Context Pack, readiness, or exact specialist binding condition inside the signed ${run.run.journey} boundary.`
          : `The provider failure remained inside the signed ${run.run.journey} mission boundary.`,
        retryHistory,
        progressBeforeFailure: run.control.progress,
        preservedReferences: input.checkpointId ? [{
          kind: "checkpoint",
          id: input.checkpointId,
          meaning: input.retryScheduled
            ? "Durable checkpoint that owns the exact delayed planning retry"
            : "Verified zero-in-flight safe-stop checkpoint",
        }] : [],
        retryable,
        automaticRecovery,
        remediation: input.retryScheduled
          ? `Wait until ${input.retryScheduled.notBefore}; the runtime will consume only the exact persisted retry continuation.`
          : input.runtimeError.options.remediation
            ?? (input.boundary === "local_deterministic"
              ? "Restore the exact contract, Context Pack, manifest, specialist, model, MCP, or tool-policy dependency identified by this diagnosis, then start a reviewed recovery path."
              : "Verify provider health, then resume only through the server-declared bounded recovery control."),
        operatorActions: planningFailureOperatorActions(category, retryable),
        objectiveImpact: input.boundary === "local_deterministic"
          ? "No plan, provider turn, target interaction, or target-side evidence was committed by this failed local planning pass; the mission objective remains unchanged."
          : "No plan or target-side evidence was committed by this failed provider turn; the mission objective remains unchanged.",
        terminal: input.terminal,
        actor: { id: this.workerId, type: "worker" },
      });
    } catch (error) {
      this.database.prepare(`
        INSERT INTO structured_logs (
          id, mission_id, run_id, severity, domain, message,
          attributes_json, sensitivity, occurred_at
        ) VALUES (?, ?, ?, 'error', 'command-runtime.failure-diagnosis', ?, ?, 'internal', ?)
      `).run(
        `log_${randomUUID()}`,
        run.run.missionId,
        input.runId,
        "Planning failure was committed but its structured diagnosis could not be persisted",
        JSON.stringify({
          code: "planning_failure_diagnosis_persistence_failed",
          category: input.category,
          planningBoundary: input.boundary,
          providerTurnId: latestTurn?.id ?? null,
          errorType: error instanceof Error ? error.name : "unknown",
          rawErrorPersisted: false,
        }),
        this.timestamp(),
      );
    }
  }

  private async safeStopPlanning(
    runId: string,
    lease: RunLeaseToken,
    error: CommandRuntimeError,
  ): Promise<string | undefined> {
    try {
      return inImmediateTransaction(this.database, () => {
        const now = this.timestamp();
        const current = this.coordinator.getRun(runId);
        if (isTerminalRunState(current.run.state)) return undefined;
        if (current.run.state === "blocked") {
          this.repository.failCurrentPlanningBoundary(runId, now);
          return new CheckpointRepository(this.database, new ActionRepository(this.database)).latest(runId)?.id;
        }
        const transition = this.coordinator.transitionRun({
          lease,
          to: "blocked",
          reason: error.options.humanMessage ?? error.message,
        });
        const closedBoundary = this.repository.failCurrentPlanningBoundary(runId, now);
        const event = this.repository.events.append({
          missionId: transition.run.run.missionId,
          runId,
          journey: transition.run.run.journey,
          eventType: transition.run.run.journey === "autonomous"
            ? "run.autonomous_safe_stopped"
            : "run.guided_blocked",
          actorType: "system",
          summary: error.options.humanMessage ?? error.message,
          payload: {
            code: error.code,
            category: error.options.category ?? "runtime",
            retryable: error.options.retryable ?? false,
            remediation: error.options.remediation ?? null,
            details: error.options.details ?? null,
            stepsFailed: closedBoundary.stepsFailed,
            assignmentsFailed: closedBoundary.assignmentsFailed,
            ...(error.code === "invalid_plan" && error.options.details
              && typeof error.options.details === "object" && !Array.isArray(error.options.details)
              && typeof error.options.details.validationField === "string"
              && typeof error.options.details.validationRule === "string"
              ? {
                  validationField: error.options.details.validationField,
                  validationRule: error.options.details.validationRule,
                }
              : {}),
          },
        });
        const actions = new ActionRepository(this.database);
        const checkpoint = new CheckpointRepository(this.database, actions).create({
          run: transition.run,
          eventSequence: event.sequence,
          now,
          inFlightClassification: actions.inFlight(runId).length === 0
            ? "safe_no_in_flight_action"
            : "review_required",
        });
        return checkpoint.id;
      });
    } catch {
      // A newer fenced owner won the race; never overwrite it with stale planning output.
      return undefined;
    }
  }

  private actionHeartbeat(context: RuntimeActionContext): void {
    if (context.heartbeat) clearInterval(context.heartbeat);
    const renew = () => {
      if (context.completing) return;
      const state = this.database.prepare(`
        SELECT a.status AS action_status, r.status AS run_status
        FROM actions a JOIN runs r ON r.id = a.run_id
        WHERE a.id = ? AND a.run_id = ?
      `).get(context.action.id, context.action.runId) as {
        action_status: string;
        run_status: string;
      } | undefined;
      if (
        !state || state.action_status !== "running" ||
        ["completed", "failed", "cancelled"].includes(state.run_status)
      ) {
        this.clearActionContext(context.action.id);
        return;
      }
      this.heartbeatControlPlane(context.action.runId);
      context.lease = this.coordinator.heartbeatActionLease(
        context.action.id,
        context.lease,
        this.leaseTtlMs,
      );
    };

    // Establish the run, control-plane, and exact assignment heartbeat before
    // dispatch. Some reviewed adapters await the underlying child process, so
    // starting this only after dispatch returns lets every owner fence expire.
    renew();
    context.heartbeat = setInterval(() => {
      try {
        renew();
      } catch {
        this.clearActionContext(context.action.id);
      }
    }, Math.max(250, Math.floor(this.leaseTtlMs / 3)));
  }

  private clearActionContext(actionId: string): void {
    const context = this.actionContexts.get(actionId);
    if (context?.heartbeat) clearInterval(context.heartbeat);
    this.actionContexts.delete(actionId);
  }

  private clearActionContextsForRun(runId: string): void {
    for (const [actionId, context] of this.actionContexts) {
      if (context.action.runId === runId) this.clearActionContext(actionId);
    }
  }

  private assertAttackKnowledgeUseAllowed(input: {
    readonly mission: import("./types").PlanningMission;
    readonly run: import("./types").PlanningRun;
  }): void {
    if (input.run.journey === "guided") return;
    const policy = this.effectiveRunMemoryPolicy(input);
    const scopes = Array.isArray(policy.allowedScopes)
      ? policy.allowedScopes.filter((value): value is string => typeof value === "string")
      : [];
    if (!scopes.includes("verified_attack_knowledge")) {
      throw new CommandRuntimeError(
        409,
        "attack_knowledge_scope_not_permitted",
        "The signed Autonomous contract does not permit reusable attack knowledge",
        {
          humanMessage: "Safe-stopped before this represented attack attempt because its exact procedure-safety knowledge is outside the signed memory policy.",
          retryable: false,
          category: "policy_denied",
          remediation: "Start a new run or explicitly amend the contract to permit verified attack knowledge. Do not broaden the running contract implicitly.",
        },
      );
    }
  }

  private verifiedAttackKnowledgeNodeIds(values: readonly string[]): readonly string[] {
    const now = Date.parse(this.timestamp());
    const selected: string[] = [];
    for (const id of [...new Set(values)]) {
      const row = this.database.prepare(`
        SELECT node_type, scope, lifecycle_status, expires_at
        FROM memory_nodes WHERE id = ?
      `).get(id) as {
        node_type: import("../memory").MemoryNodeType;
        scope: string;
        lifecycle_status: string;
        expires_at: string | null;
      } | undefined;
      if (
        row
        && isAttackCentricReusableNodeType(row.node_type)
        && row.scope === "global"
        && row.lifecycle_status === "verified"
        && (!row.expires_at || Date.parse(row.expires_at) > now)
      ) selected.push(id);
    }
    return selected;
  }

  private persistOperationalHazardAssessment(input: {
    readonly mission: import("./types").PlanningMission;
    readonly run: import("./types").PlanningRun;
    readonly stepId: string;
    readonly actorId: string;
    readonly attackAttemptId: string;
    readonly binding: AttackAttemptKnowledgeContext;
    readonly assessment: OperationalHazardAssessment;
  }): string {
    const exactNodeIds = this.verifiedAttackKnowledgeNodeIds([
      input.binding.procedureNodeId,
      ...(input.binding.procedureVersionNodeId ? [input.binding.procedureVersionNodeId] : []),
      ...input.binding.productNodeIds,
      ...input.binding.versionNodeIds,
      ...input.binding.stackNodeIds,
      ...input.binding.prerequisiteNodeIds,
      ...(input.binding.observedStateNodeIds ?? []),
      ...input.assessment.matchedHazardNodeIds,
    ]);
    if (exactNodeIds.length > 20) {
      throw new CommandRuntimeError(
        409,
        "attack_hazard_context_too_large",
        "The exact operational-hazard Context Pack exceeds its reviewed bound",
        {
          humanMessage: "Execution stopped because the exact procedure-safety context is too large to inspect as one bounded Context Pack.",
          retryable: false,
          category: "evidence_insufficient",
          details: {
            attackAttemptId: input.attackAttemptId,
            selectedNodeCount: exactNodeIds.length,
            maximumNodeCount: 20,
          },
          remediation: "Review and narrow the procedure binding to the minimum exact product, version, stack, prerequisite, and state facts before creating a new represented attempt.",
        },
      );
    }

    let context: BrainContextResult;
    try {
      context = this.brainContext.retrieve({
        hook: "attack_attempt",
        journey: input.run.journey,
        missionId: input.mission.id,
        runId: input.run.id,
        stepId: input.stepId,
        actorId: input.actorId,
        actorType: "agent",
        availabilityPolicy: input.run.journey === "autonomous" ? "required" : "degraded_allowed",
        query: "Exact represented procedure, version, stack, prerequisite, operational hazard, health gate, and safer known sequence",
        queryRedacted: "Exact represented attack-procedure operational-hazard preflight",
        maximumSensitivity: "private",
        contextBudget: 5_000,
        limit: 20,
        allowGlobal: true,
        exactNodeIds,
        exactNodeIdsOnly: true,
        allowedScopeClasses: ["verified_attack_knowledge"],
        requireApplicableExactNodeIds: exactNodeIds.length > 0,
      });
    } catch (error) {
      if (error instanceof BrainContextHookError) {
        throw new CommandRuntimeError(
          409,
          "attack_hazard_context_unavailable",
          "The exact operational-hazard Context Pack is unavailable",
          {
            humanMessage: "Execution stopped because Ti-Scale could not persist and audit the exact procedure-safety context before this attack attempt.",
            retryable: false,
            category: "evidence_insufficient",
            details: {
              attackAttemptId: input.attackAttemptId,
              brainAuditRecordId: error.auditRecordId ?? null,
            },
            remediation: "Restore the Second Brain, verify the bound reusable nodes, then create or resume only a represented attempt that produces a complete Context Pack.",
          },
        );
      }
      throw error;
    }

    const usedNodeIds = context.contextPack.items.map((item) => item.nodeId);
    if (usedNodeIds.length > 0) {
      this.brainContext.recordContextUse(
        context,
        usedNodeIds,
        input.assessment.decision === "block"
          ? "The local pre-execution gate matched an exact, verified operational hazard and prevented automatic execution until its health gate is represented."
          : input.assessment.decision === "warn"
            ? "The local pre-execution gate found related but non-conclusive operational-hazard knowledge and surfaced it without claiming applicability."
            : "The local pre-execution gate checked the exact reusable procedure context and found no applicable verified operational hazard.",
        "The exact-only hazard Context Pack contained no unrelated items.",
      );
    } else {
      this.brainContext.recordUnusedContext(
        context,
        "No verified reusable attack-knowledge node was eligible for this exact binding; no memory was claimed as influential.",
      );
    }
    this.operationalHazards.attachContextPack(input.attackAttemptId, context.contextPack.id);

    inImmediateTransaction(this.database, () => {
      if (input.assessment.decision === "block") {
        this.database.prepare(`
          UPDATE attack_attempts
          SET status = 'waiting_conditions',
            outcome_summary = 'Execution prevented until the represented operational health gate is satisfied',
            updated_at = ?, version = version + 1
          WHERE id = ? AND status = 'ready'
        `).run(this.timestamp(), input.attackAttemptId);
      }
      this.repository.events.append({
        missionId: input.mission.id,
        runId: input.run.id,
        journey: input.run.journey,
        eventType: "attack_attempt.operational_hazard_assessed",
        actorType: "system",
        actorId: "operational-hazard-gate",
        summary: input.assessment.decision === "block"
          ? "Stopped this exact procedure before it could repeat a known failure; a health check must pass before any retry."
          : input.assessment.decision === "warn"
            ? "Found related failure memory, but it does not prove this environment is affected; the uncertainty is visible and no applicability was invented."
            : "Checked verified failure memory for this exact procedure; no applicable operational hazard was found.",
        payload: {
          attackAttemptId: input.attackAttemptId,
          procedureNodeId: input.binding.procedureNodeId,
          procedureVersionNodeId: input.binding.procedureVersionNodeId ?? null,
          decision: input.assessment.decision,
          matchedHazardNodeIds: [...input.assessment.matchedHazardNodeIds],
          unsafeRetryConditions: [...input.assessment.unsafeRetryConditions],
          healthGate: [...input.assessment.healthGate],
          saferKnownSequence: [...input.assessment.saferKnownSequence],
          automaticExecutionPermitted: input.assessment.decision !== "block",
          retryMustReevaluate: true,
          targetIdentifiersPersistedInReusableContext: false,
        },
        contextPackId: context.contextPack.id,
        sensitivity: "internal",
      });
    });
    return context.contextPack.id;
  }

  private async startRepresentedAction(
    intent: Parameters<DurableRunCoordinator["startAction"]>[0]["intent"],
    lease: RunLeaseToken,
    guidedDecisionId?: string,
  ): Promise<DurableAction> {
    try {
      const run = this.repository.getPlanningRun(intent.runId);
      const mission = this.repository.getMission(run.missionId);
      let actionContextPackId: string | undefined;
      let assignmentAgentId: string | undefined;
      if (intent.assignmentId) {
        const assignment = this.database.prepare("SELECT agent_id FROM assignments WHERE id = ? AND run_id = ?")
          .get(intent.assignmentId, intent.runId) as { agent_id: string } | undefined;
        if (!assignment) throw new CommandRuntimeError(409, "assignment_scope_invalid", "Represented assignment is not canonical");
        assignmentAgentId = assignment.agent_id;
        const context = this.retrieveBrainContext({
          hook: "assignment_acceptance",
          mission,
          run,
          stepId: intent.stepId,
          actorId: assignment.agent_id,
          query: `${assignment.agent_id} ${intent.actionType} ${intent.actionClass} ${intent.intentSummary} specialist capability dependencies`,
          queryRedacted: `${assignment.agent_id} ${intent.actionType} ${intent.actionClass} assignment acceptance`,
          trustedRuntimeCapabilityNodeIds: this.currentRuntimeCapabilityNodeIds(
            "agent",
            assignment.agent_id,
          ),
        });
        this.applyAgentToolMemoryDecision({
          hook: "assignment_acceptance",
          context,
          mission,
          run,
          intent,
          actorId: assignment.agent_id,
          representedAgentId: assignment.agent_id,
        });
        actionContextPackId = context.contextPack.id;
      }
      if (intent.kind === "tool") {
        const context = this.retrieveBrainContext({
          hook: "tool_selection",
          mission,
          run,
          stepId: intent.stepId,
          actorId: "specialist-tool-router",
          query: `${intent.actionType} ${intent.actionClass} prerequisites compatibility`,
          queryRedacted: `${intent.actionClass} tool selection`,
          trustedRuntimeCapabilityNodeIds: this.currentRuntimeCapabilityNodeIds(
            "tool",
            intent.actionType,
          ),
        });
        this.applyAgentToolMemoryDecision({
          hook: "tool_selection",
          context,
          mission,
          run,
          intent,
          actorId: "specialist-tool-router",
          ...(assignmentAgentId ? { representedAgentId: assignmentAgentId } : {}),
        });
        actionContextPackId = context.contextPack.id;
      }
      const readyAttackAttempts = this.database.prepare(`
        SELECT aa.id, aa.technique_name, aa.objective, aa.assigned_agent_id,
          aa.target_asset_id, aa.target_service_id, ps.risk_class
        FROM attack_attempts aa
        JOIN plan_steps ps ON ps.id = aa.step_id AND ps.run_id = aa.run_id
        WHERE aa.run_id = ? AND aa.step_id = ? AND aa.action_class = ? AND aa.status = 'ready'
        ORDER BY aa.created_at, aa.id
        LIMIT 2
      `).all(intent.runId, intent.stepId, intent.actionClass) as Array<{
        id: string;
        technique_name: string;
        objective: string;
        assigned_agent_id: string | null;
        target_asset_id: string | null;
        target_service_id: string | null;
        risk_class: string | null;
      }>;
      if (readyAttackAttempts.length > 1) {
        throw new CommandRuntimeError(
          409,
          "attack_attempt_dispatch_ambiguous",
          "More than one ready attack attempt matches this represented step",
          {
            humanMessage: "Execution paused because this step has more than one ready attack attempt and Ti-Scale cannot safely infer which exact attempt the operator or contract represented.",
            retryable: false,
            category: "plan_dependency_unresolved",
            remediation: "Keep one exact attempt ready for the step and move the other candidates back to a non-ready state, then resume from the checkpoint.",
          },
        );
      }
      const attackAttempt = readyAttackAttempts[0];
      if (attackAttempt) {
        if (
          attackAttempt.assigned_agent_id && assignmentAgentId &&
          attackAttempt.assigned_agent_id !== assignmentAgentId
        ) {
          throw new CommandRuntimeError(
            409,
            "attack_attempt_assignment_mismatch",
            "The ready attack attempt is assigned to another specialist",
            {
              humanMessage: "Execution paused because the represented step and its ready attack attempt name different specialists.",
              retryable: false,
              category: "plan_dependency_unresolved",
              remediation: "Reconcile the attack-attempt and plan-step assignment before dispatching the represented action.",
            },
          );
        }
        const actorId = attackAttempt.assigned_agent_id
          ?? assignmentAgentId
          ?? "specialist-attack-router";
        const binding = this.operationalHazards.getAttackAttemptContext(attackAttempt.id);
        const highRisk = ["high", "critical"].includes(attackAttempt.risk_class?.toLowerCase() ?? "");
        if (!binding && highRisk) {
          throw new CommandRuntimeError(
            409,
            "attack_procedure_knowledge_required",
            "A high-risk first-class attack attempt requires an exact reusable procedure binding",
            {
              humanMessage: "Execution stopped before this high-risk attempt because Ti-Scale has no exact procedure, version, stack, prerequisite, and state binding to evaluate safely.",
              retryable: false,
              category: "evidence_insufficient",
              details: {
                attackAttemptId: attackAttempt.id,
                stepId: intent.stepId,
                riskClass: attackAttempt.risk_class ?? "high",
                inferredFromTargetOrName: false,
              },
              remediation: "Bind the represented attempt to a reviewed attack_procedure and its exact generalized environment context, then create a new represented decision or run. Ti-Scale will not guess from the box name, IP, target label, or technique prose.",
            },
          );
        }
        if (binding) {
          this.assertAttackKnowledgeUseAllowed({ mission, run });
          const assessment = this.operationalHazards.assess(binding);
          actionContextPackId = this.persistOperationalHazardAssessment({
            mission,
            run,
            stepId: intent.stepId,
            actorId,
            attackAttemptId: attackAttempt.id,
            binding,
            assessment,
          });
          if (assessment.decision === "block") {
            throw new CommandRuntimeError(
              409,
              "operational_hazard_health_gate_required",
              "A verified operational hazard prevents automatic execution",
              {
                humanMessage: run.journey === "autonomous"
                  ? "Safe-stopped before repeating a verified failure pattern. The recorded health gate must pass before a new attempt can run."
                  : "This approved Guided step was not run because it exactly matches a verified failure pattern. Represent the health check as the next deliberate step before trying again.",
                retryable: false,
                category: "evidence_insufficient",
                details: {
                  attackAttemptId: attackAttempt.id,
                  procedureNodeId: binding.procedureNodeId,
                  matchedHazardNodeIds: [...assessment.matchedHazardNodeIds],
                  unsafeRetryConditions: [...assessment.unsafeRetryConditions],
                  healthGate: [...assessment.healthGate],
                  saferKnownSequence: [...assessment.saferKnownSequence],
                  contextPackId: actionContextPackId,
                  automaticRetryPermitted: false,
                  targetContacted: false,
                },
                remediation: assessment.healthGate.length > 0
                  ? `Represent and verify this health gate before a new attempt: ${assessment.healthGate.join("; ")}`
                  : "Amend the plan with a represented, evidence-producing health check before creating a new attempt.",
              },
            );
          }
        } else {
          const context = this.retrieveBrainContext({
            hook: "attack_attempt",
            mission,
            run,
            stepId: intent.stepId,
            actorId,
            query: `${attackAttempt.technique_name} ${attackAttempt.objective} prerequisites evidence failure recovery`,
            queryRedacted: `${intent.actionClass} represented low-risk attack-attempt start`,
          });
          this.brainContext.recordUnusedContext(
            context,
            "This low-risk represented attempt had no exact reusable procedure binding; generic scoped context was checked without inferring a procedure from its target, name, or prose.",
          );
          actionContextPackId = context.contextPack.id;
        }
        // A distinct attempt on the same target/action boundary cannot evade
        // an unresolved exact hazard merely by receiving a new attempt ID.
        // The actual single-use consumption is repeated inside the fenced
        // action-reservation transaction immediately after action creation.
        this.operationalHazardHealthGate.assertReservationAuthorized(attackAttempt.id);
      }
      const started = await this.coordinator.startAction({
        lease,
        intent: actionContextPackId ? { ...intent, contextPackId: actionContextPackId } : intent,
        ...(guidedDecisionId ? { guidedDecisionId } : {}),
      });
      return started.action;
    } catch (error) {
      if (error instanceof RuntimeCrashAfterCommit) throw error;
      const runtimeError = asRuntimeError(error);
      if (
        runtimeError.code === "autonomous_action_not_allowed" ||
        runtimeError.code === "autonomous_target_not_allowed" ||
        runtimeError.code === "autonomous_contract_not_signed" ||
        runtimeError.code === "autonomous_manual_action_forbidden" ||
        runtimeError.code === "attack_procedure_knowledge_required" ||
        runtimeError.code === "attack_knowledge_scope_not_permitted" ||
        runtimeError.code === "attack_hazard_context_too_large" ||
        runtimeError.code === "attack_hazard_context_unavailable" ||
        runtimeError.code === "operational_hazard_health_gate_required" ||
        runtimeError.code === "agent_memory_dependency_missing" ||
        runtimeError.code === "agent_memory_incompatible"
        || runtimeError.code.startsWith("hazard_")
      ) {
        const contractBoundary = runtimeError.code.startsWith("autonomous_");
        await this.safeStopPlanning(intent.runId, lease, contractBoundary
          ? new CommandRuntimeError(409, runtimeError.code, runtimeError.message, {
              humanMessage: "Safe-stopped: the next action is outside the signed Autonomous contract.",
              category: "scope_conflict",
            })
          : runtimeError);
      }
      throw runtimeError;
    }
  }

  async acceptExecutionResult(result: ExecutionResult): Promise<ExecutionResultReceipt> {
    const summary = validateExecutionResultSummary(result.summary);
    this.assertV2ControlPlaneOwnership(result.runId);
    const row = this.database.prepare(`
      SELECT id, run_id, step_id, action_type, action_class, fingerprint, status
      FROM actions WHERE id = ?
    `).get(result.actionId) as {
      id: string; run_id: string; step_id: string; action_type: string;
      action_class: string; fingerprint: string; status: string;
    } | undefined;
    if (!row) throw new CommandRuntimeError(404, "action_not_found", `Action not found: ${result.actionId}`);
    if (row.run_id !== result.runId || row.fingerprint !== result.actionFingerprint) {
      throw new CommandRuntimeError(409, "execution_result_mismatch", "Execution result correlation did not match", {
        humanMessage: "A stale or mismatched provider result was rejected.",
        category: "conflict",
      });
    }
    if (row.status !== "running") {
      // A late adapter acknowledgement after cancellation is a valid
      // duplicate, but it must also retire any in-memory heartbeat left by
      // the pre-terminal action. Otherwise that timer can reacquire a
      // control-plane lease after the terminal transaction released it.
      this.clearActionContext(result.actionId);
      const run = this.repository.getRunProjection(result.runId);
      return {
        accepted: true,
        duplicate: true,
        actionId: result.actionId,
        runId: result.runId,
        runState: run.status,
        nextAction: run.nextAction,
      };
    }
    this.ensureControlPlaneAuthority(result.runId);
    const mutationAuthority = this.runMutationAuthority.authorize({
      runId: result.runId,
      actorId: this.workerId,
      mode: "lease",
      assertLease: ({ runId }) => this.assertControlPlaneMutationAuthority(runId),
    });

    let context = this.actionContexts.get(result.actionId);
    if (context?.completing) {
      throw new CommandRuntimeError(409, "execution_result_in_progress", "This action result is already being committed", {
        retryable: true,
        category: "conflict",
      });
    }
    if (!context) {
      const durable = this.coordinator.getRun(result.runId);
      let lease = durable.lease;
      if (!lease || Date.parse(lease.expiresAt) <= Date.parse(this.timestamp())) {
        lease = this.acquireWorkerRunLease(result.runId);
      } else if (lease.ownerId !== this.workerId) {
        throw new CommandRuntimeError(409, "execution_result_worker_conflict", "Another worker owns this result", {
          humanMessage: "The result reached a non-owning worker and was not applied.",
          retryable: true,
          category: "conflict",
        });
      }
      const actions = new ActionRepository(this.database);
      context = {
        action: actions.get(result.actionId),
        lease,
        before: durable.control.progress,
        completing: false,
      };
      this.actionContexts.set(result.actionId, context);
    }
    context.completing = true;
    if (context.heartbeat) clearInterval(context.heartbeat);
    const after: ProgressSnapshot = {
      ...context.before,
      ...result.progress,
      stepStates: {
        ...(context.before.stepStates ?? {}),
        ...(result.progress.stepStates ?? {}),
        [row.step_id]: result.success ? "completed" : "failed",
      },
      verifiedWorkerResultIds: result.success
        ? [...new Set([...(context.before.verifiedWorkerResultIds ?? []), ...(result.progress.verifiedWorkerResultIds ?? []), result.actionId])]
        : result.progress.verifiedWorkerResultIds ?? context.before.verifiedWorkerResultIds,
    };
    let completionCommitted = false;
    try {
      let recoveryContextFailure: unknown;
      let recoveryMemory: CompiledAutonomousRecoveryMemory | undefined;
      const classifiedFailureCategory = !result.success
        ? result.failureCategory ?? classifyFailure(result.failure ?? { source: "unknown" })
        : undefined;
      if (!result.success) {
        const recoveryRun = this.repository.getPlanningRun(result.runId);
        const recoveryMission = this.repository.getMission(recoveryRun.missionId);
        try {
          const recoveryContext = this.retrieveBrainContext({
            hook: "failure",
            mission: recoveryMission,
            run: recoveryRun,
            stepId: row.step_id,
            actionId: result.actionId,
            actorId: "run-supervisor",
            query: `Retrieve prior failed attempts and verified recovery lessons before classifying the bounded ${result.failureCategory ?? "unknown"} action failure.`,
            queryRedacted: "Retrieve prior failed attempts and verified recovery lessons before classifying the bounded action failure.",
          });
          if (recoveryRun.journey === "autonomous") {
            recoveryMemory = compileAutonomousRecoveryMemory({
              hook: "failure",
              context: recoveryContext,
              missionId: recoveryMission.id,
              engagementId: recoveryMission.engagementId,
              runId: recoveryRun.id,
              stepId: row.step_id,
              actionId: result.actionId,
              failureCategory: classifiedFailureCategory!,
              actionType: row.action_type,
              actionClass: row.action_class,
            });
          } else {
            this.brainContext.recordUnusedContext(
              recoveryContext,
              "Guided recovery retained the exact failure Context Pack for explanation, but typed memory constraints cannot alter recovery without the next represented operator decision.",
            );
          }
        } catch (error) {
          // A failed required Brain hook must not leave an externally completed
          // action ghost-running. Close it through the normal supervisor path
          // as a policy denial, which deterministically blocks/safe-stops.
          recoveryContextFailure = error;
        }
      }
      const failureCategory = recoveryContextFailure
        ? "policy_denied" satisfies FailureCategory
        : classifiedFailureCategory;
      mutationAuthority.assertCurrent();
      const completed = await this.coordinator.completeAction({
        // DurableRunCoordinator repeats mission+run ownership from inside its
        // IMMEDIATE transaction; this guard fences the surrounding Brain and
        // result-correlation work to the same controller epoch.
        lease: context.lease,
        actionId: result.actionId,
        success: result.success,
        resultSummary: summary,
        before: context.before,
        after,
        ...(result.failure ? { failure: result.failure } : {}),
        ...(failureCategory ? { failureCategory } : {}),
        ...(result.retryAfterMs === undefined ? {} : { retryAfterMs: result.retryAfterMs }),
        ...(result.usage ? { budgetDelta: result.usage } : {}),
        ...(result.circuitKey ? { circuitKey: result.circuitKey } : {}),
        ...(result.operationalResetResult
          ? { operationalResetResult: result.operationalResetResult }
          : {}),
        ...(recoveryMemory && !recoveryContextFailure ? { recoveryMemory } : {}),
      });
      completionCommitted = true;
      this.actionContexts.delete(result.actionId);
      if (result.success && completed.directive === "continue") {
        this.crashAfterCommit("action_result_to_advance", result.runId, result.actionId);
      } else if (!result.success && completed.directive === "recover") {
        this.crashAfterCommit("guided_failure_to_recover", result.runId, result.actionId);
      }
      if (
        (result.success && completed.directive === "continue") ||
        completed.directive === "recover" ||
        completed.run.run.state === "failed"
      ) {
        // A direct execution adapter can synchronously return a retry result
        // while this same run's autonomous_retry_to_dispatch continuation is
        // still being handled. The result transaction has already enqueued
        // action_result_to_advance durably, so awaiting the registered
        // continuation worker here would make that worker wait on itself.
        // Let the active processContinuationRun loop finish its parent handler
        // and claim the durable child on its next iteration.
        if (!this.continuationProcessing.has(result.runId)) {
          await this.replayContinuations(result.runId);
        }
      }
      const projection = this.repository.getRunProjection(result.runId);
      return {
        accepted: true,
        duplicate: false,
        actionId: result.actionId,
        runId: result.runId,
        runState: projection.status,
        nextAction: projection.nextAction,
      };
    } catch (error) {
      let heartbeatRecoveryError: unknown;
      if (!completionCommitted) {
        context.completing = false;
        try {
          this.actionHeartbeat(context);
        } catch (recoveryError) {
          heartbeatRecoveryError = recoveryError;
          this.clearActionContext(result.actionId);
        }
      } else {
        this.actionContexts.delete(result.actionId);
      }
      if (error instanceof RuntimeCrashAfterCommit) throw error;
      try {
        const raw = errorRecord(error);
        const message = redactSecrets(
          error instanceof Error ? error.message : "An unclassified result-commit failure occurred.",
        ).replace(/[\u0000-\u001F\u007F]/gu, " ").trim().replace(/\s+/gu, " ").slice(0, 700);
        this.database.prepare(`
          INSERT INTO structured_logs (
            id, mission_id, run_id, step_id, action_id, severity, domain, message,
            attributes_json, sensitivity, occurred_at
          )
          SELECT ?, mission_id, run_id, step_id, id, 'error',
            'command-runtime.execution-result-commit', ?, ?, 'internal', ?
          FROM actions WHERE id = ? AND run_id = ?
        `).run(
          `log_${randomUUID()}`,
          "A durable execution result could not be committed to the mission state machine",
          JSON.stringify({
            code: "execution_result_commit_failed",
            actionId: result.actionId,
            resultSuccess: result.success,
            errorType: error instanceof Error ? error.name : "unknown",
            errorCode: typeof raw.code === "string" ? raw.code.slice(0, 160) : null,
            errorMessage: message || null,
            heartbeatRecoveryErrorType:
              heartbeatRecoveryError instanceof Error ? heartbeatRecoveryError.name : null,
            heartbeatRecoveryErrorCode:
              typeof errorRecord(heartbeatRecoveryError).code === "string"
                ? String(errorRecord(heartbeatRecoveryError).code).slice(0, 160)
                : null,
            heartbeatRecoveryErrorMessage: heartbeatRecoveryError instanceof Error
              ? redactSecrets(heartbeatRecoveryError.message)
                  .replace(/[\u0000-\u001F\u007F]/gu, " ")
                  .trim()
                  .replace(/\s+/gu, " ")
                  .slice(0, 700)
              : null,
            rawPayloadPersisted: false,
          }),
          this.timestamp(),
          result.actionId,
          result.runId,
        );
      } catch {
        // The original result-commit failure remains authoritative. A
        // secondary observability write must never replace or hide it.
      }
      throw asRuntimeError(error);
    }
  }

  private async evaluateAndFinish(initialLease: RunLeaseToken): Promise<void> {
    const heartbeat = this.heartbeat(initialLease);
    let heartbeatStopped = false;
    let lease = initialLease;
    try {
      const run = this.repository.getPlanningRun(initialLease.runId);
      const mission = this.repository.getMission(run.missionId);
      const projection = this.repository.getRunProjection(run.id);
      if (!projection.currentPlanId) throw new CommandRuntimeError(500, "active_plan_missing", "Run has no plan to evaluate");
      const actionIds = (this.database.prepare(`
        SELECT id FROM actions WHERE run_id = ? AND status = 'succeeded' ORDER BY ended_at, id
      `).all(run.id) as Array<{ id: string }>).map((row) => row.id);
      const evaluationContext = this.retrieveBrainContext({
        hook: "evaluation",
        mission,
        run,
        actorId: "outcome-evaluator",
        query: "Evaluate mission success criteria against verified evidence, failures, recoveries, and the active plan.",
        queryRedacted: "Evaluate mission success criteria against verified evidence, failures, recoveries, and the active plan.",
      });
      const evaluated = completionResult(await this.options.outcomeEvaluator.evaluate({
        mission,
        run,
        planId: projection.currentPlanId,
        completedActionIds: actionIds,
        brainContext: this.providerBrainContext(evaluationContext),
      }, this.controller(run.id).signal));
      const evaluation = evaluated.evaluation;
      if (
        !evaluation || typeof evaluation.success !== "boolean" || !evaluation.summary?.trim() ||
        !Array.isArray(evaluation.criteria)
      ) {
        throw new CommandRuntimeError(422, "invalid_completion_evaluation", "Outcome evaluator returned an invalid result");
      }
      const findingValidationContexts = this.prepareFindingValidationContexts({
        mission,
        run,
        planId: projection.currentPlanId,
        evaluation,
      });
      lease = await heartbeat.stop();
      heartbeatStopped = true;
      lease = this.accountProviderUsage(lease, evaluated.usage, "success evaluation");
      const target: "completed" | "failed" = evaluation.success ? "completed" : "failed";
      this.commitTerminalAtomically(run.id, target, (reportCommitment) => {
        const transition = this.coordinator.transitionRun({
          lease,
          to: target,
          reason: evaluation.summary.trim(),
        });
        this.database.prepare(`
          UPDATE missions SET status = ?, updated_at = ? WHERE id = ?
        `).run(evaluation.success ? "completed" : "failed", this.timestamp(), mission.id);
        this.repository.events.append({
          missionId: mission.id,
          runId: run.id,
          journey: run.journey,
          eventType: evaluation.success ? "run.success_validated" : "run.success_criteria_failed",
          actorType: "agent",
          actorId: "outcome-evaluator",
          summary: evaluation.summary.trim(),
          payload: {
            success: evaluation.success,
            criteria: evaluation.criteria.map((criterion) => ({
              criterion: criterion.criterion,
              satisfied: criterion.satisfied,
              ...(criterion.outcome ? { outcome: criterion.outcome } : {}),
              explanation: criterion.explanation,
              evidenceIds: [...criterion.evidenceIds],
            })),
            findingValidationContexts,
            checkpointId: transition.checkpointId,
          },
        });
        this.recordTerminalEvaluationWithBrain({
          runId: run.id,
          terminalStatus: target,
          createdBy: "outcome-evaluator",
          outcome: evaluation,
          evaluationContextAlreadyRetrieved: true,
          ...(reportCommitment ? { terminalReportCommitment: reportCommitment } : {}),
        });
      });
      try {
        this.releaseControlPlaneAuthority(run.id);
      } catch {
        // Terminal state is already durable; an expired lease must not turn a
        // truthful completion into a second failure.
      }
    } catch (error) {
      if (!heartbeatStopped) lease = await heartbeat.stop().catch(() => lease);
      const runtimeError = asRuntimeError(error);
      await this.safeStopPlanning(initialLease.runId, lease, runtimeError);
      try {
        this.releaseControlPlaneAuthority(initialLease.runId);
      } catch {
        // The safe-stop checkpoint is authoritative even if the lease expired
        // while the failure was being persisted.
      }
      throw runtimeError;
    }
  }

  private controlLease(runId: string): RunLeaseToken {
    this.ensureControlPlaneAuthority(runId);
    const context = [...this.actionContexts.values()].find((candidate) => candidate.action.runId === runId);
    if (context) return context.lease;
    const run = this.coordinator.getRun(runId);
    if (
      run.lease && run.lease.ownerId === this.workerId &&
      Date.parse(run.lease.expiresAt) > this.now().getTime()
    ) return run.lease;
    return this.acquireWorkerRunLease(runId);
  }

  /**
   * Idempotent HTTP responses remain scoped to the run's current canonical
   * control plane. This read-only preflight intentionally does not acquire a
   * worker lease: a cached response is not a mutation and must not leave an
   * idle lease behind after pause or cancellation.
   */
  assertV2ControlPlaneOwnership(runId: string): void {
    const authority = this.runMutationAuthority.authorize({
      runId,
      actorId: this.workerId,
      mode: "ownership",
    });
    authority.assertCurrent();
    const run = this.database.prepare("SELECT journey FROM runs WHERE id = ?")
      .get(runId) as { journey: "autonomous" | "guided" } | undefined;
    if (!run) throw new ControlPlaneLeaseError("run_not_found", `Run ${runId} does not exist`);
    if (!this.supportedJourneys.has(run.journey)) {
      throw new ControlPlaneLeaseError(
        "journey_unsupported",
        `Run ${runId} uses the unsupported ${run.journey} journey`,
      );
    }
  }

  private supportsRun(runId: string): boolean {
    const run = this.database.prepare(`
      SELECT r.journey
      FROM runs r JOIN missions m ON m.id = r.mission_id
      WHERE r.id = ? AND r.control_plane = 'ti_scale'
        AND m.control_plane = 'ti_scale'
    `).get(runId) as { journey: "autonomous" | "guided" } | undefined;
    return Boolean(
      run && this.supportedJourneys.has(run.journey),
    );
  }

  /**
   * Server-only bridge for adjacent V2 services that must mutate the run under
   * the runtime's existing authority. It never acquires a lease on demand and
   * never exposes the raw token; callers receive only a revalidatable proof.
   */
  assertControlPlaneMutationAuthority(runId: string): ControlPlaneLease {
    this.assertV2ControlPlaneOwnership(runId);
    const leaseToken = this.controlPlaneTokens.get(runId);
    if (!leaseToken) {
      throw new ControlPlaneLeaseError(
        "lease_missing",
        `Run ${runId} is not held by this runtime controller`,
      );
    }
    return this.controlPlaneLeases.assertMutationAuthority({
      runId,
      controlPlane: "ti_scale",
      leaseOwner: this.workerId,
      leaseToken,
      now: this.now(),
    });
  }

  /**
   * Fence every runtime mutation behind the V2 control-plane lease as well as
   * the shorter-lived durable run lease. Only the digest is stored in SQLite;
   * the worker keeps the raw token in memory and renews it with active work.
   */
  private ensureControlPlaneAuthority(runId: string): void {
    this.assertV2ControlPlaneOwnership(runId);
    const existingToken = this.controlPlaneTokens.get(runId);
    const acquired = this.controlPlaneLeases.acquire({
      runId,
      controlPlane: "ti_scale",
      leaseOwner: this.workerId,
      ...(existingToken ? { leaseToken: existingToken } : {}),
      ttlMs: this.leaseTtlMs,
      now: this.now(),
    });
    if (acquired.leaseToken) this.controlPlaneTokens.set(runId, acquired.leaseToken);
  }

  private releaseControlPlaneAuthority(runId: string): void {
    const leaseToken = this.controlPlaneTokens.get(runId);
    if (!leaseToken) return;
    try {
      this.controlPlaneLeases.release({
        runId,
        controlPlane: "ti_scale",
        leaseOwner: this.workerId,
        leaseToken,
        now: this.now(),
      });
    } finally {
      // A later worker action must reacquire from canonical state. Retaining a
      // released token is unnecessary and makes ownership handoff opaque.
      this.controlPlaneTokens.delete(runId);
    }
  }

  /**
   * Release the server-only control-plane token from an existing SQLite
   * transaction. The in-memory token is deliberately retained until the
   * enclosing operation returns successfully: if a later statement rolls the
   * transaction back, the caller's finally block can still release the
   * restored durable lease with the same secret proof.
   */
  private releaseControlPlaneAuthorityInTransaction(runId: string, now: string): void {
    if (!this.database.inTransaction) {
      throw new Error("Atomic control-plane release requires an active SQLite transaction");
    }
    const leaseToken = this.controlPlaneTokens.get(runId);
    if (!leaseToken) {
      throw new ControlPlaneLeaseError(
        "lease_missing",
        `Run ${runId} has no in-memory authority to release atomically`,
      );
    }
    this.controlPlaneLeases.release({
      runId,
      controlPlane: "ti_scale",
      leaseOwner: this.workerId,
      leaseToken,
      now: new Date(now),
    });
  }

  private heartbeatControlPlane(runId: string): void {
    const leaseToken = this.controlPlaneTokens.get(runId);
    if (!leaseToken) {
      this.ensureControlPlaneAuthority(runId);
      return;
    }
    this.controlPlaneLeases.heartbeat({
      runId,
      controlPlane: "ti_scale",
      leaseOwner: this.workerId,
      leaseToken,
      ttlMs: this.leaseTtlMs,
      now: this.now(),
    });
  }

  private acquireWorkerRunLease(runId: string): RunLeaseToken {
    this.ensureControlPlaneAuthority(runId);
    return this.coordinator.acquireRunLease(runId, this.workerId, this.leaseTtlMs);
  }

  /**
   * Resolve the exact current Guided decision against the runtime clock once.
   *
   * This preflight timestamp is server-generated and never accepted back from
   * a caller. The fenced write transaction generates its own authoritative
   * instant and shares it with the repository mutation. If the preflight is
   * already expired or ambiguous, the supervisor persists the structured
   * blocked/checkpoint diagnosis before returning the fail-closed error.
   */
  requireCurrentGuidedDecisionBoundary(decisionId: string): GuidedDecisionProjection {
    const evaluatedAt = this.timestamp();
    try {
      return this.repository.requireCurrentPendingDecision(decisionId, evaluatedAt);
    } catch (error) {
      if (
        error instanceof CommandRuntimeError
        && [
          "guided_decision_expired",
          "guided_pending_decision_conflict",
          "guided_step_stale",
        ].includes(error.code)
      ) {
        this.blockUnusableWaitingGuidedDecisions();
      }
      throw error;
    }
  }

  async approveGuidedDecision(decisionId: string, actorId: string, reason?: string): Promise<DurableAction> {
    const existingDecision = this.repository.getDecision(decisionId);
    const ownership = this.runMutationAuthority.authorize({
      runId: existingDecision.runId,
      actorId,
      mode: "ownership",
    });
    ownership.assertCurrent();
    // Prove both V2 control-plane ownership and the shorter durable run lease
    // before examining any replay or writing a decision/continuation. A
    // legacy-owned row is therefore read-only even if its decision shape is
    // otherwise valid.
    const lease = this.controlLease(existingDecision.runId);
    const mutationAuthority = this.runMutationAuthority.authorize({
      runId: existingDecision.runId,
      actorId,
      mode: "lease",
      assertLease: ({ runId }) => this.assertControlPlaneMutationAuthority(runId),
    });
    if (existingDecision.status !== "pending") {
      const existing = this.database.prepare(`
        SELECT id FROM actions WHERE guided_decision_id = ? ORDER BY created_at LIMIT 1
      `).get(decisionId) as { id: string } | undefined;
      if (existingDecision.status === "approved" && existing) return new ActionRepository(this.database).get(existing.id);
      throw new CommandRuntimeError(409, "guided_decision_not_pending", "Only a pending Guided decision can be approved");
    }
    const now = this.timestamp();
    const decision = this.repository.requireCurrentPendingDecision(decisionId, now);
    const representedIntent = this.repository.getStepIntent(decision.stepId);
    if (representedIntent.kind === "manual") {
      throw new CommandRuntimeError(
        409,
        "guided_manual_action_requires_operator_result",
        "A manual Guided action cannot be dispatched through the execution boundary",
        {
          humanMessage: "This represented step is manual. Run it yourself, then use ‘I ran it’ to record the exact result.",
          category: "policy_denied",
          remediation: "Complete the documented manual procedure and submit its result against this unchanged decision fingerprint.",
        },
      );
    }
    inImmediateTransaction(this.database, () => {
      mutationAuthority.assertCurrent();
      const runs = new RunRepository(this.database);
      runs.assertLease(runs.get(decision.runId), lease, now);
      // Repeat the complete boundary under the write reservation so a plan,
      // step, or current-decision change cannot race the status mutation.
      this.repository.requireCurrentPendingDecision(decisionId, now);
      const updated = this.database.prepare(`
        UPDATE guided_decisions SET status = 'approved', decision_actor = ?, decision_reason = ?, decided_at = ?
        WHERE id = ? AND status = 'pending'
      `).run(actorId, reason?.trim() || "Approved exact represented step", now, decisionId);
      if (updated.changes !== 1) throw new CommandRuntimeError(409, "guided_decision_conflict", "Decision changed concurrently");
      this.repository.events.append({
        missionId: decision.missionId,
        runId: decision.runId,
        journey: "guided",
        eventType: "guided.decision_approved",
        actorType: "operator",
        actorId,
        summary: "Operator approved the exact represented Guided action",
        payload: { decisionId, actionFingerprint: decision.actionFingerprint },
      });
      this.repository.appendAudit({
        missionId: decision.missionId, runId: decision.runId, actorId,
        action: "guided.decision_approved", resourceType: "guided_decision",
        resourceId: decisionId, reason: reason?.trim() || "Approved exact represented step",
        details: { actionFingerprint: decision.actionFingerprint }, now,
      });
      this.continuations.enqueue({
        runId: decision.runId,
        kind: "guided_approval_to_dispatch",
        sourceId: decisionId,
        payload: { decisionId, stepId: decision.stepId },
        now,
      });
    });
    this.crashAfterCommit("guided_approval_to_dispatch", decision.runId, decisionId);
    await this.replayContinuations(decision.runId, ["guided_approval_to_dispatch"]);
    const created = this.database.prepare(`
      SELECT id FROM actions WHERE guided_decision_id = ? ORDER BY created_at, id LIMIT 1
    `).get(decisionId) as { id: string } | undefined;
    if (!created) {
      const blocked = this.database.prepare(`
        SELECT r.status, r.status_reason, e.payload_json
        FROM runs r
        LEFT JOIN events e ON e.id = (
          SELECT latest.id FROM events latest
          WHERE latest.run_id = r.id AND latest.event_type = 'run.guided_blocked'
          ORDER BY latest.sequence DESC LIMIT 1
        )
        WHERE r.id = ?
      `).get(decision.runId) as {
        status: string;
        status_reason: string;
        payload_json: string | null;
      } | undefined;
      if (blocked?.status === "blocked" && blocked.payload_json) {
        let payload: Readonly<Record<string, unknown>> = {};
        try {
          const parsed = JSON.parse(blocked.payload_json) as unknown;
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            payload = parsed as Readonly<Record<string, unknown>>;
          }
        } catch {
          payload = {};
        }
        const code = typeof payload.code === "string" ? payload.code : "guided_dispatch_blocked";
        const category = typeof payload.category === "string" ? payload.category : "runtime";
        const remediation = typeof payload.remediation === "string"
          ? payload.remediation
          : "Review the blocked checkpoint and create a new represented recovery decision before another action runs.";
        throw new CommandRuntimeError(409, code, blocked.status_reason, {
          humanMessage: blocked.status_reason,
          retryable: false,
          category,
          ...(payload.details !== undefined ? { details: payload.details as JsonValue } : {}),
          remediation,
        });
      }
      throw new CommandRuntimeError(503, "guided_dispatch_pending", "Approved Guided action is durably queued", {
        humanMessage: "The exact Guided decision is approved and will resume automatically from its durable continuation.",
        retryable: true,
        category: "runtime",
      });
    }
    return new ActionRepository(this.database).get(created.id);
  }

  async skipGuidedDecision(
    decisionId: string,
    actorId: string,
    reason: string,
  ): Promise<GuidedDecisionSkipResult> {
    const normalizedReason = validateReason(reason);
    const initialDecision = this.repository.getDecision(decisionId);
    const ownership = this.runMutationAuthority.authorize({
      runId: initialDecision.runId,
      actorId,
      mode: "ownership",
    });
    ownership.assertCurrent();
    const skipped = this.database.prepare(`
      SELECT ps.status AS step_status,
        EXISTS(
          SELECT 1 FROM events
          WHERE run_id = ? AND event_type = 'guided.decision_skipped'
            AND json_extract(payload_json, '$.decisionId') = ?
        ) AS has_skip_event
      FROM plan_steps ps WHERE ps.id = ?
    `).get(initialDecision.runId, initialDecision.id, initialDecision.stepId) as {
      step_status: string;
      has_skip_event: number;
    } | undefined;
    if (
      initialDecision.status === "cancelled" &&
      skipped?.step_status === "skipped" &&
      skipped.has_skip_event === 1
    ) {
      this.assertV2ControlPlaneOwnership(initialDecision.runId);
      const projection = this.repository.getRunProjection(initialDecision.runId);
      const pending = this.database.prepare(`
        SELECT id FROM guided_decisions
        WHERE run_id = ? AND status = 'pending' AND step_id = ?
        ORDER BY created_at DESC LIMIT 1
      `).get(initialDecision.runId, projection.currentStepId) as { id: string } | undefined;
      return {
        decisionId,
        status: "cancelled",
        skippedStepId: initialDecision.stepId,
        nextDecisionId: pending?.id ?? null,
        runId: initialDecision.runId,
        runState: projection.status,
        nextAction: projection.nextAction,
        duplicate: true,
      };
    }
    const decision = this.requireCurrentGuidedDecisionBoundary(decisionId);
    const lease = this.controlLease(decision.runId);
    const mutationAuthority = this.runMutationAuthority.authorize({
      runId: decision.runId,
      actorId,
      mode: "lease",
      assertLease: ({ runId }) => this.assertControlPlaneMutationAuthority(runId),
    });
    const committed = inImmediateTransaction(this.database, () => {
      // The only authoritative expiry instant is generated inside the fenced
      // transaction. Public callers cannot backdate it, and the repository's
      // full boundary plus skip mutation share this exact value.
      const now = this.timestamp();
      mutationAuthority.assertCurrent();
      const runs = new RunRepository(this.database);
      const current = runs.get(decision.runId);
      runs.assertLease(current, lease, now);
      this.repository.requireCurrentPendingDecision(decisionId, now);
      if (current.run.journey !== "guided" || current.run.state !== "waiting_guided_decision") {
        throw new CommandRuntimeError(409, "guided_run_not_waiting", "Guided run is not waiting for this decision");
      }
      const advanced = this.repository.skipGuidedStep({
        decisionId,
        actorId,
        reason: normalizedReason,
        now,
        decisionTtlMs: this.decisionTtlMs,
      });
      const progress: ProgressSnapshot = {
        ...current.control.progress,
        stepStates: {
          ...(current.control.progress.stepStates ?? {}),
          [decision.stepId]: "skipped",
        },
        resolvedDecisionIds: [
          ...new Set([...(current.control.progress.resolvedDecisionIds ?? []), decision.id]),
        ],
      };
      const reasonText = advanced.completed
        ? "The exact Guided step was skipped; all represented steps are resolved and outcome evaluation is starting"
        : "The exact Guided step was skipped; the next dependency-eligible step is explained and waiting";
      const nextRun = advanced.completed
        ? transitionSupervisedRun(
            { ...current.run, pendingGuidedDecisionId: decision.id },
            "running",
            {
              reason: reasonText,
              now,
              guidedDecisionId: decision.id,
            },
          ).run
        : {
            ...current.run,
            pendingGuidedDecisionId: advanced.guidedDecisionId ?? undefined,
            stateVersion: current.run.stateVersion + 1,
            stateReason: reasonText,
            updatedAt: now,
          };
      const persisted = runs.persistMutation({
        current,
        nextRun,
        control: { ...current.control, progress },
        now,
        lease: "keep",
      });
      let eventSequence = advanced.eventSequence;
      if (advanced.completed) {
        eventSequence = this.repository.events.append({
          missionId: decision.missionId,
          runId: decision.runId,
          journey: "guided",
          eventType: "run.state_changed",
          actorType: "operator",
          actorId,
          summary: "waiting_guided_decision -> running: skipped plan is ready for outcome evaluation",
          payload: {
            from: "waiting_guided_decision",
            to: "running",
            decisionId,
            reason: reasonText,
          },
        }).sequence;
      }
      new CheckpointRepository(this.database, new ActionRepository(this.database)).create({
        run: persisted,
        eventSequence,
        now,
      });
      if (advanced.completed) {
        const plan = this.database.prepare("SELECT plan_id FROM plan_steps WHERE id = ?")
          .get(decision.stepId) as { plan_id: string };
        this.continuations.enqueue({
          runId: decision.runId,
          kind: "evaluation_pending",
          sourceId: plan.plan_id,
          now,
        });
      }
      if (!persisted.lease) {
        throw new CommandRuntimeError(500, "runtime_lease_lost", "Guided skip lost its run lease");
      }
      return { advanced, lease: persisted.lease };
    });
    if (committed.advanced.completed) {
      await this.replayContinuations(decision.runId, ["evaluation_pending"]);
    }
    const updated = this.repository.getRunProjection(decision.runId);
    return {
      decisionId,
      status: "cancelled",
      skippedStepId: committed.advanced.skippedStepId,
      nextDecisionId: committed.advanced.guidedDecisionId,
      runId: decision.runId,
      runState: updated.status,
      nextAction: updated.nextAction,
      duplicate: false,
    };
  }

  async rejectGuidedDecision(decisionId: string, actorId: string, reason: string): Promise<void> {
    const normalizedReason = validateReason(reason);
    const existingDecision = this.repository.getDecision(decisionId);
    const ownership = this.runMutationAuthority.authorize({
      runId: existingDecision.runId,
      actorId,
      mode: "ownership",
    });
    ownership.assertCurrent();
    if (existingDecision.status === "rejected") return;
    if (existingDecision.status !== "pending") throw new CommandRuntimeError(409, "guided_decision_not_pending", "Only a pending decision can be rejected");
    const now = this.timestamp();
    const decision = this.repository.requireCurrentPendingDecision(decisionId, now);
    const lease = this.controlLease(decision.runId);
    const mutationAuthority = this.runMutationAuthority.authorize({
      runId: decision.runId,
      actorId,
      mode: "lease",
      assertLease: ({ runId }) => this.assertControlPlaneMutationAuthority(runId),
    });
    inImmediateTransaction(this.database, () => {
      mutationAuthority.assertCurrent();
      this.repository.requireCurrentPendingDecision(decisionId, now);
      const runs = new RunRepository(this.database);
      runs.assertLease(runs.get(decision.runId), lease, now);
      const updated = this.database.prepare(`
        UPDATE guided_decisions SET status = 'rejected', decision_actor = ?, decision_reason = ?, decided_at = ?
        WHERE id = ? AND status = 'pending'
      `).run(actorId, normalizedReason, now, decisionId);
      if (updated.changes !== 1) {
        throw new CommandRuntimeError(409, "guided_decision_conflict", "Decision changed concurrently");
      }
      this.database.prepare(`
        UPDATE plan_steps SET status = 'recovering', updated_at = ? WHERE id = ?
      `).run(now, decision.stepId);
      this.coordinator.transitionRun({
        lease,
        to: "recovering",
        reason: `Operator rejected the Guided step: ${normalizedReason}`,
      });
      this.repository.appendAudit({
        missionId: decision.missionId, runId: decision.runId, actorId,
        action: "guided.decision_rejected", resourceType: "guided_decision",
        resourceId: decisionId, reason: normalizedReason, now,
      });
      this.continuations.enqueue({
        runId: decision.runId,
        kind: "resume_recovery_pending",
        sourceId: decisionId,
        payload: { decisionId },
        now,
      });
    });
    await this.replayContinuations(decision.runId, ["resume_recovery_pending"]);
  }

  async submitManualGuidedResult(
    decisionId: string,
    actorId: string,
    interpretedEvidenceId: string,
  ): Promise<ExecutionResultReceipt> {
    if (!interpretedEvidenceId.trim()) {
      throw new CommandRuntimeError(400, "interpreted_evidence_required", "Commander-interpreted evidence is required", {
        humanMessage: "Submit and review the manual output before accepting this exact step.",
        category: "invalid_input",
        remediation: "Use the Guided result form, review the local interpretation, then accept that evidence.",
      });
    }
    const decision = this.repository.getDecision(decisionId);
    const ownership = this.runMutationAuthority.authorize({
      runId: decision.runId,
      actorId,
      mode: "ownership",
    });
    ownership.assertCurrent();
    if (decision.status === "manual") {
      const existing = this.database.prepare(`
        SELECT id, result_summary FROM actions
        WHERE guided_decision_id = ? AND status = 'succeeded'
        ORDER BY created_at, id LIMIT 1
      `).get(decisionId) as { id: string; result_summary: string | null } | undefined;
      if (!existing?.result_summary) {
        throw new CommandRuntimeError(500, "manual_result_invariant_broken", "Completed manual decision has no retained action result", {
          humanMessage: "The prior manual result is incomplete and requires integrity review.",
          category: "internal",
        });
      }
      const linked = this.database.prepare(`
        SELECT id, json_extract(provenance_json, '$.originalEvidenceId') AS original_evidence_id
        FROM evidence WHERE action_id = ? AND ${verifiedEvidenceSql("evidence")}
        ORDER BY created_at, id LIMIT 1
      `).get(existing.id) as { id: string; original_evidence_id: string | null } | undefined;
      if (!linked) {
        throw new CommandRuntimeError(500, "manual_result_evidence_invariant_broken", "Completed manual decision has no verified evidence", {
          humanMessage: "The prior manual completion is missing its required verified evidence and needs integrity review.",
          category: "internal",
        });
      }
      if (linked.original_evidence_id !== interpretedEvidenceId) {
        throw new CommandRuntimeError(409, "guided_evidence_scope_conflict", "Reviewed evidence does not belong to the completed exact Guided decision", {
          humanMessage: "This completion already used another reviewed observation for the exact step.",
          category: "scope_conflict",
          remediation: "Refresh the Guided workspace and use the retained completion evidence rather than attaching a different result.",
        });
      }
      const projection = this.repository.getRunProjection(decision.runId);
      return {
        accepted: true,
        duplicate: true,
        actionId: existing.id,
        runId: decision.runId,
        runState: projection.status,
        nextAction: projection.nextAction,
        evidenceIds: [linked.id],
      };
    }
    const now = this.timestamp();
    const currentDecision = this.repository.requireCurrentPendingDecision(decisionId, now);
    const interpreted = this.repository.requireInterpretedGuidedEvidence(
      currentDecision,
      interpretedEvidenceId,
    );
    validateExecutionResultSummary(interpreted.summary);
    const lease = this.controlLease(currentDecision.runId);
    const mutationAuthority = this.runMutationAuthority.authorize({
      runId: currentDecision.runId,
      actorId,
      mode: "lease",
      assertLease: ({ runId }) => this.assertControlPlaneMutationAuthority(runId),
    });
    const { accepted } = inImmediateTransaction(this.database, () => {
      mutationAuthority.assertCurrent();
      const decision = this.repository.requireCurrentPendingDecision(decisionId, now);
      const reviewed = this.repository.requireInterpretedGuidedEvidence(
        decision,
        interpretedEvidenceId,
      );
      const resultSummary = validateExecutionResultSummary(reviewed.summary);
      const runs = new RunRepository(this.database);
      const current = runs.get(decision.runId);
      runs.assertLease(current, lease, now);
      if (
        current.run.journey !== "guided" ||
        current.run.state !== "waiting_guided_decision"
      ) {
        throw new CommandRuntimeError(409, "guided_run_not_waiting", "Guided run is not waiting for this exact result");
      }
      const updated = this.database.prepare(`
        UPDATE guided_decisions SET status = 'manual', decision_actor = ?, decision_reason = ?, decided_at = ?
        WHERE id = ? AND status = 'pending'
      `).run(actorId, "Operator supplied the result for the represented action", now, decisionId);
      if (updated.changes !== 1) throw new CommandRuntimeError(409, "guided_decision_conflict", "Decision changed concurrently");
      const created = this.repository.createManualAction({ decision, summary: resultSummary, now });
      const evidence = this.repository.promoteInterpretedGuidedEvidence({
        decision,
        actionId: created,
        evidenceId: interpretedEvidenceId,
        actorId,
        now,
      });
      this.repository.events.append({
        missionId: decision.missionId, runId: decision.runId, journey: "guided",
        eventType: "guided.manual_result_recorded", actorType: "operator", actorId,
        summary: "Operator accepted the interpreted evidence for the exact Guided action",
        payload: {
          decisionId,
          actionId: created,
          actionFingerprint: decision.actionFingerprint,
          evidenceId: evidence.id,
          interpretedBeforeAdvance: true,
          contentHash: evidence.contentHash,
          byteSize: evidence.byteSize,
        },
        sensitivity: "private",
        redaction: { operatorSuppliedContent: "retained_in_private_evidence_only" },
      });
      this.repository.appendAudit({
        missionId: decision.missionId, runId: decision.runId, actorId,
        action: "guided.manual_result_recorded", resourceType: "guided_decision",
        resourceId: decisionId, reason: "Operator supplied exact-step result",
        details: { actionId: created, evidenceId: evidence.id, contentHash: evidence.contentHash },
        now,
      });
      const nextRun = {
        ...current.run,
        state: "running" as const,
        launched: true,
        pendingGuidedDecisionId: undefined,
        stateVersion: current.run.stateVersion + 1,
        stateReason: `Operator supplied the result for Guided decision ${decisionId}`,
        updatedAt: now,
      };
      const progress: ProgressSnapshot = {
        ...current.control.progress,
        stepStates: {
          ...(current.control.progress.stepStates ?? {}),
          [decision.stepId]: "completed",
        },
        evidenceIds: [...new Set([...(current.control.progress.evidenceIds ?? []), evidence.id])],
        resolvedDecisionIds: [...new Set([...(current.control.progress.resolvedDecisionIds ?? []), decisionId])],
        verifiedWorkerResultIds: [...new Set([...(current.control.progress.verifiedWorkerResultIds ?? []), created])],
      };
      const persisted = runs.persistMutation({
        current,
        nextRun,
        control: { ...current.control, progress },
        now,
        lease: "keep",
      });
      const event = this.repository.events.append({
        missionId: decision.missionId,
        runId: decision.runId,
        journey: "guided",
        eventType: "run.state_changed",
        actorType: "operator",
        actorId,
        summary: "waiting_guided_decision -> running: exact manual result supplied",
        payload: { from: "waiting_guided_decision", to: "running", decisionId },
      });
      new CheckpointRepository(this.database, new ActionRepository(this.database)).create({
        run: persisted,
        eventSequence: event.sequence,
        now,
      });
      this.continuations.enqueue({
        runId: decision.runId,
        kind: "action_result_to_advance",
        sourceId: created,
        payload: { actionId: created, stepId: decision.stepId },
        now,
      });
      if (!persisted.lease) throw new CommandRuntimeError(500, "runtime_lease_lost", "Manual result lost its run lease");
      return {
        accepted: { actionId: created, evidence },
      };
    });
    // Manual work resolves the exact decision without dispatching a duplicate
    // provider action. Decision, immutable evidence, progress, state, event,
    // and checkpoint are committed atomically before execution advances.
    this.crashAfterCommit("manual_result_to_advance", decision.runId, accepted.actionId);
    await this.replayContinuations(decision.runId, ["action_result_to_advance", "evaluation_pending"]);
    const projection = this.repository.getRunProjection(decision.runId);
    return {
      accepted: true,
      duplicate: false,
      actionId: accepted.actionId,
      runId: decision.runId,
      runState: projection.status,
      nextAction: projection.nextAction,
      evidenceIds: [accepted.evidence.id],
    };
  }

  private assertNoExecutionWork(
    runId: string,
    operation: "pause" | "resume",
  ): void {
    const active = this.database.prepare(`
      SELECT kind, id FROM (
        SELECT 'action' AS kind, id FROM actions
          WHERE run_id = ? AND status IN ('queued', 'running')
        UNION ALL
        SELECT 'tool_call' AS kind, tc.id FROM tool_calls tc
          JOIN actions a ON a.id = tc.action_id
          WHERE a.run_id = ? AND tc.status IN ('queued', 'running')
        UNION ALL
        SELECT 'assignment' AS kind, id FROM assignments
          WHERE run_id = ? AND (status = 'active' OR lease_owner IS NOT NULL)
        UNION ALL
        SELECT 'provider_turn' AS kind, id FROM provider_turns
          WHERE run_id = ? AND status = 'started'
        UNION ALL
        SELECT 'runtime_continuation' AS kind, id FROM runtime_continuations
          WHERE run_id = ? AND status IN ('pending', 'processing')
      ) LIMIT 1
    `).get(runId, runId, runId, runId, runId) as {
      kind: string;
      id: string;
    } | undefined;
    if (!active) return;
    throw new CommandRuntimeError(
      409,
      operation === "pause" ? "pause_requires_safe_checkpoint" : "resume_has_in_flight_work",
      `${operation === "pause" ? "Pause" : "Resume"} requires a zero-in-flight durable boundary`,
      {
        humanMessage: operation === "pause"
          ? "Pause is available only after actions, provider turns, assignments, and durable continuations have stopped."
          : "The inspected checkpoint no longer has a zero-in-flight runtime boundary.",
        category: "conflict",
        details: { blockingWorkKind: active.kind, blockingWorkId: active.id },
        remediation: operation === "pause"
          ? "Wait for the named work item to stop, or cancel the run if active child work must be terminated."
          : "Keep the run stopped, reconcile the named work item, then refresh the Recovery Panel.",
      },
    );
  }

  private assertExactResumeBoundary(
    runId: string,
    boundary: ResumeRunBoundary,
    currentVersion: number,
    lease?: RunLeaseToken,
  ) {
    let checkpoint: ReturnType<DurableRunCoordinator["getLatestCheckpoint"]>;
    try {
      checkpoint = this.coordinator.getLatestCheckpoint(runId);
    } catch {
      throw new CommandRuntimeError(409, "resume_checkpoint_integrity_failed", "Resume checkpoint integrity verification failed", {
        humanMessage: "The latest durable checkpoint failed integrity verification and cannot be resumed.",
        category: "data_integrity",
        remediation: "Keep the run stopped and reconcile its immutable checkpoint and event history.",
      });
    }
    if (!checkpoint) {
      throw new CommandRuntimeError(409, "resume_checkpoint_missing", "Resume requires a durable checkpoint", {
        humanMessage: "No verified durable checkpoint is available for this run.",
        category: "conflict",
        remediation: "Keep the run stopped and restore or reconcile its checkpoint before retrying.",
      });
    }
    const current = this.coordinator.getRun(runId);
    const latestSequence = this.database.prepare(`
      SELECT max(
        coalesce((SELECT last_sequence FROM run_event_sequences WHERE run_id = ?), 0),
        coalesce((SELECT max(sequence) FROM events WHERE run_id = ?), 0)
      ) AS sequence
    `).get(runId, runId) as { sequence: number };
    const checkpointMetadata = this.database.prepare(`
      SELECT in_flight_classification FROM checkpoints WHERE id = ? AND run_id = ?
    `).get(checkpoint.id, runId) as { in_flight_classification: string | null } | undefined;
    const trailingEvents = this.database.prepare(`
      SELECT event_type FROM events WHERE run_id = ? AND sequence > ? ORDER BY sequence
    `).all(runId, boundary.expectedCheckpointEventSequence) as Array<{ event_type: string }>;
    const diagnosticTailOnly = trailingEvents.length > 0 && trailingEvents.every((event) =>
      event.event_type === "run.autonomous_safe_stopped" || event.event_type === "run.guided_blocked");
    const legacyZeroInFlightCheckpoint = checkpointMetadata?.in_flight_classification === null
      && checkpoint.state.inFlightActions.length === 0;
    const checkpointClassificationSafe = checkpointMetadata?.in_flight_classification === "safe_no_in_flight_action"
      || checkpointMetadata?.in_flight_classification === "resume_idempotently"
      || legacyZeroInFlightCheckpoint;
    const sequenceBoundaryCurrent = latestSequence.sequence === boundary.expectedCheckpointEventSequence
      || (legacyZeroInFlightCheckpoint && diagnosticTailOnly);
    const stale =
      boundary.expectedRunStatus !== "blocked" ||
      current.run.state !== boundary.expectedRunStatus ||
      current.run.stateVersion !== currentVersion ||
      checkpoint.id !== boundary.expectedCheckpointId ||
      checkpoint.stateHash !== boundary.expectedCheckpointStateHash ||
      checkpoint.eventSequence !== boundary.expectedCheckpointEventSequence ||
      checkpoint.state.run.id !== runId ||
      checkpoint.state.run.missionId !== current.run.missionId ||
      checkpoint.state.run.journey !== current.run.journey ||
      checkpoint.state.run.state !== boundary.expectedRunStatus ||
      checkpoint.state.run.stateVersion !== boundary.expectedRunVersion ||
      checkpoint.state.run.leaseOwner !== null ||
      checkpoint.state.run.leaseExpiresAt !== null ||
      checkpoint.state.lastEventSequence !== boundary.expectedCheckpointEventSequence ||
      !sequenceBoundaryCurrent ||
      !checkpointClassificationSafe ||
      (lease
        ? current.lease?.ownerId !== lease.ownerId ||
          current.lease.fence !== lease.fence ||
          current.lease.expiresAt !== lease.expiresAt ||
          lease.fence !== boundary.expectedRunVersion + 1
        : current.lease !== null);
    if (stale) {
      throw new CommandRuntimeError(409, "resume_checkpoint_stale", "Resume boundary no longer matches canonical state", {
        humanMessage: "The run or durable checkpoint changed after this resume control was loaded.",
        category: "conflict",
        details: {
          expectedRunVersion: boundary.expectedRunVersion,
          currentRunVersion: current.run.stateVersion,
          expectedCheckpointId: boundary.expectedCheckpointId,
          currentCheckpointId: checkpoint.id,
        },
        remediation: "Refresh the Recovery Panel and resume only the newly verified zero-in-flight checkpoint.",
      });
    }
    if (checkpoint.state.inFlightActions.length > 0) {
      throw new CommandRuntimeError(409, "resume_checkpoint_has_in_flight_actions", "Resume checkpoint contains in-flight actions", {
        humanMessage: "The latest durable checkpoint records work that may still have side effects.",
        category: "conflict",
        remediation: "Keep the run stopped and reconcile every recorded action before resuming.",
      });
    }
    this.assertNoExecutionWork(runId, "resume");

    const recovery = checkpoint.state.control.recovery;
    const recoveryKind = recovery && typeof recovery === "object" && !Array.isArray(recovery)
      ? (recovery as Record<string, unknown>).kind
      : undefined;
    const operatorPaused = /^Paused by operator:/iu.test(current.run.stateReason);
    const diagnosedGuidedRecovery = current.run.journey === "guided" && Boolean(this.database.prepare(`
      SELECT 1 WHERE
        EXISTS (SELECT 1 FROM guided_decisions
          WHERE run_id = ? AND status = 'pending' AND expires_at > ?)
        OR EXISTS (SELECT 1 FROM actions
          WHERE run_id = ? AND status IN ('failed', 'timed_out', 'denied'))
        OR EXISTS (SELECT 1 FROM events
          WHERE run_id = ? AND event_type IN (
            'run.recovery_started', 'run.recovery_blocked', 'run.replan_started',
            'run.continuation_blocked'
          ))
    `).get(runId, this.timestamp(), runId, runId));
    const autonomousSafeStop = current.run.journey === "autonomous" && Boolean(this.database.prepare(`
      SELECT 1 FROM events
      WHERE run_id = ? AND event_type IN ('run.safe_stopped', 'run.autonomous_safe_stopped')
      LIMIT 1
    `).get(runId));
    const planningRateLimit = current.run.journey === "autonomous" && current.run.state === "blocked"
      && Boolean(this.database.prepare(`
        SELECT 1 FROM events
        WHERE run_id = ? AND event_type = 'run.autonomous_safe_stopped'
          AND json_extract(payload_json, '$.category') = 'rate_limit'
          AND json_extract(payload_json, '$.code') LIKE 'mission_runtime_%'
        LIMIT 1
      `).get(runId))
      && Boolean(this.database.prepare(`
        SELECT 1 FROM runs
        WHERE id = ? AND current_plan_id IS NULL AND current_step_id IS NULL
          AND retry_count < coalesce(
            json_extract(budget_json, '$.retries'),
            json_extract(budget_json, '$.retryBudget'),
            0
          )
      `).get(runId));
    if (
      (autonomousSafeStop && !planningRateLimit) ||
      (!planningRateLimit && !operatorPaused && recoveryKind !== "retry" && recoveryKind !== "replan" && !diagnosedGuidedRecovery)
    ) {
      throw new CommandRuntimeError(409, "resume_not_permitted_for_blocked_state", "Blocked run is not a resumable operator pause or diagnosed recovery", {
        humanMessage: autonomousSafeStop && !planningRateLimit
          ? "This Autonomous run safe-stopped and cannot be resumed in place."
          : "This blocked state has no verified resumable diagnosis.",
        category: "policy_denied",
        remediation: autonomousSafeStop && !planningRateLimit
          ? "Resolve the exception through a reviewed contract amendment or start a new run."
          : "Open the Recovery Panel and use only a server-declared action for the diagnosed blocker.",
      });
    }
    return current;
  }

  /**
   * Read-only first-application guard used while the HTTP idempotency claim is
   * reserved. The mutating resume path repeats this boundary after acquiring
   * fenced control-plane authority and again after acquiring the run lease.
   */
  assertResumeRunBoundary(
    runId: string,
    boundary: ResumeRunBoundary,
    commandId?: string,
  ): void {
    this.assertV2ControlPlaneOwnership(runId);
    if (this.recoverCurrentRunControlCommand(runId, "run.resumed", commandId)) return;
    this.assertExactResumeBoundary(runId, boundary, boundary.expectedRunVersion);
  }

  pauseRun(runId: string, actorId: string, reason: string, commandId?: string): void {
    const normalized = validateReason(reason);
    const ownership = this.runMutationAuthority.authorize({
      runId,
      actorId,
      mode: "ownership",
    });
    ownership.assertCurrent();
    if (this.recoverCurrentRunControlCommand(runId, "run.paused", commandId)) return;
    if (this.options.autonomousActivation) {
      const run = this.database.prepare(
        "SELECT journey FROM runs WHERE id = ?",
      ).get(runId) as { journey: string } | undefined;
      if (run?.journey === "autonomous") {
        this.options.autonomousActivation.verifyCurrent({ runId });
      }
    }
    this.assertNoExecutionWork(runId, "pause");
    const lease = this.controlLease(runId);
    const mutationAuthority = this.runMutationAuthority.authorize({
      runId,
      actorId,
      mode: "lease",
      assertLease: ({ runId: ownedRunId }) =>
        this.assertControlPlaneMutationAuthority(ownedRunId),
    });
    try {
      const current = this.coordinator.getRun(runId);
      if (current.run.state === "blocked") {
        throw new CommandRuntimeError(409, "run_blocked_not_paused", "Blocked run requires recovery rather than pause");
      }
      const now = this.timestamp();
      inImmediateTransaction(this.database, () => {
        mutationAuthority.assertCurrent();
        const runs = new RunRepository(this.database);
        runs.assertLease(runs.get(runId), lease, now);
        this.assertNoExecutionWork(runId, "pause");
        const currentStepBoundary = this.database.prepare(
          "SELECT current_step_id FROM runs WHERE id = ?",
        ).get(runId) as { current_step_id: string | null };
        const currentStepId = currentStepBoundary.current_step_id;
        const pendingDecision = currentStepId
          ? this.database.prepare(`
              SELECT id FROM guided_decisions
              WHERE run_id = ? AND step_id = ? AND status = 'pending' AND expires_at > ?
              ORDER BY created_at DESC, id DESC LIMIT 1
            `).get(runId, currentStepId, now) as { id: string } | undefined
          : undefined;
        const pausedStepStatus = current.run.journey === "guided" && pendingDecision
          ? "waiting_guided_decision"
          : "blocked";
        const result = this.coordinator.transitionRun({
          lease,
          to: "blocked",
          reason: `Paused by operator: ${normalized}`,
        });
        if (currentStepId) {
          this.database.prepare(`
            UPDATE plan_steps SET status = ?, updated_at = ?
            WHERE id = ? AND run_id = ?
              AND status IN ('ready', 'running', 'waiting_guided_decision', 'recovering')
          `).run(pausedStepStatus, now, currentStepId, runId);
        }
        this.database.prepare(`
          UPDATE assignments SET status = 'blocked',
            lease_owner = NULL, lease_acquired_at = NULL,
            last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
          WHERE run_id = ? AND status = 'active'
        `).run(now, runId);
        if (currentStepId) {
          this.database.prepare(`
            UPDATE assignments SET status = 'blocked',
              lease_owner = NULL, lease_acquired_at = NULL,
              last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
            WHERE run_id = ? AND step_id = ? AND status = 'queued'
          `).run(now, runId, currentStepId);
        }
        this.database.prepare("UPDATE missions SET status = 'paused', updated_at = ? WHERE id = ?")
          .run(now, result.run.run.missionId);
        this.repository.appendAudit({
          missionId: result.run.run.missionId, runId, actorId, action: "run.paused",
          resourceType: "run", resourceId: runId, reason: normalized,
          details: {
            ...(commandId ? { commandId } : {}),
            committedRunVersion: result.run.run.stateVersion,
            checkpointId: result.checkpointId,
            checkpointEventSequence: result.eventSequence,
          },
          now,
        });
      });
      this.crashAfterCommit("pause_projection_committed", runId);
    } finally {
      // The blocked checkpoint and audit are durable before authority is
      // released, allowing a different V2 worker to resume immediately.
      this.releaseControlPlaneAuthority(runId);
    }
  }

  resumeRun(
    runId: string,
    actorId: string,
    reason: string,
    boundary: ResumeRunBoundary,
    commandId?: string,
  ): void {
    const normalized = validateReason(reason);
    let target: RunState = "recovering";
    let continuationKind: RuntimeContinuationKind = "resume_recovery_pending";
    let keepAuthorityForRecovery = false;
    const now = this.timestamp();
    const ownership = this.runMutationAuthority.authorize({
      runId,
      actorId,
      mode: "ownership",
    });
    ownership.assertCurrent();
    if (this.recoverCurrentRunControlCommand(runId, "run.resumed", commandId)) return;
    this.ensureControlPlaneAuthority(runId);
    const mutationAuthority = this.runMutationAuthority.authorize({
      runId,
      actorId,
      mode: "lease",
      assertLease: ({ runId: ownedRunId }) =>
        this.assertControlPlaneMutationAuthority(ownedRunId),
    });
    try {
      inImmediateTransaction(this.database, () => {
        mutationAuthority.assertCurrent();
        const current = this.assertExactResumeBoundary(
          runId,
          boundary,
          boundary.expectedRunVersion,
        );
        if (current.run.journey === "autonomous" && this.options.autonomousActivation) {
          const activationLineage = this.database.prepare(`
            SELECT current_plan_id, current_step_id FROM runs WHERE id = ?
          `).get(runId) as {
            current_plan_id: string | null;
            current_step_id: string | null;
          };
          this.options.autonomousActivation.verifyAndBind({
            runId,
            bindingType: "resume",
            subjectId: `operator-resume:${boundary.expectedCheckpointId}`,
            subjectDigest: hashCanonical({
              schemaVersion: "ti-scale.autonomous-operator-resume-boundary.v1",
              runId,
              actorId,
              reason: normalized,
              expectedRunVersion: boundary.expectedRunVersion,
              expectedRunStatus: boundary.expectedRunStatus,
              expectedCheckpointId: boundary.expectedCheckpointId,
              expectedCheckpointStateHash: boundary.expectedCheckpointStateHash,
              expectedCheckpointEventSequence:
                boundary.expectedCheckpointEventSequence,
            }),
            ...(activationLineage.current_plan_id
              ? { planId: activationLineage.current_plan_id }
              : {}),
            ...(activationLineage.current_step_id
              ? { stepId: activationLineage.current_step_id }
              : {}),
            boundBy: actorId,
          });
        }
        const successor = this.database.prepare(`
          SELECT rb.run_id, r.status
          FROM run_branches rb
          JOIN runs r ON r.id = rb.run_id
          WHERE rb.source_run_id = ?
          ORDER BY rb.created_at DESC, rb.id DESC LIMIT 1
        `).get(runId) as { run_id: string; status: string } | undefined;
        if (successor) {
          throw new CommandRuntimeError(409, "run_superseded_by_branch", "A branched source run cannot resume", {
            humanMessage: "This paused run was superseded by an explicit new execution attempt and cannot run alongside it.",
            category: "conflict",
            details: { successorRunId: successor.run_id, successorStatus: successor.status },
          });
        }
        const recoveryRetry = current.run.journey === "autonomous" && current.control.recovery?.kind === "retry"
          ? this.database.prepare(`
              SELECT a.id AS action_id, a.step_id
              FROM actions a JOIN runs r ON r.id = a.run_id
              WHERE a.id = ? AND a.run_id = ? AND a.status IN ('failed', 'timed_out')
                AND r.current_step_id = a.step_id
            `).get(current.control.recovery.failedActionId, runId) as {
              action_id: string;
              step_id: string;
            } | undefined
          : undefined;
        if (current.control.recovery?.kind === "retry" && current.run.journey === "autonomous" && !recoveryRetry) {
          throw new CommandRuntimeError(409, "recovery_retry_predecessor_stale", "The exact recovery predecessor is no longer current", {
            humanMessage: "Refresh recovery state; the failed predecessor no longer matches the current step.",
            category: "conflict",
          });
        }
        const lease = this.coordinator.acquireRunLease(runId, this.workerId, this.leaseTtlMs);
        this.assertExactResumeBoundary(
          runId,
          boundary,
          boundary.expectedRunVersion + 1,
          lease,
        );
        const currentStepBoundary = this.database.prepare(
          "SELECT current_step_id FROM runs WHERE id = ?",
        ).get(runId) as { current_step_id: string | null };
        const currentStepId = currentStepBoundary.current_step_id;
        const pending = currentStepId
          ? this.database.prepare(`
              SELECT id FROM guided_decisions
              WHERE run_id = ? AND step_id = ? AND status = 'pending' AND expires_at > ?
              ORDER BY created_at DESC, id DESC LIMIT 1
            `).get(runId, currentStepId, now) as { id: string } | undefined
          : undefined;
        target = current.run.journey === "guided" && pending ? "waiting_guided_decision" : "recovering";
        const transitioned = this.coordinator.transitionRun({
          lease,
          to: target,
          reason: `Resumed by operator: ${normalized}`,
          ...(pending ? { guidedDecisionId: pending.id } : {}),
        });
        if (target === "waiting_guided_decision" && currentStepId) {
          this.database.prepare(`
            UPDATE plan_steps SET status = 'waiting_guided_decision', updated_at = ?
            WHERE id = ? AND run_id = ?
              AND status IN ('ready', 'running', 'waiting_guided_decision', 'blocked', 'recovering')
          `).run(now, currentStepId, runId);
          this.database.prepare(`
            UPDATE assignments SET status = 'queued',
              lease_owner = NULL, lease_acquired_at = NULL,
              last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
            WHERE run_id = ? AND step_id = ? AND status = 'blocked'
          `).run(now, runId, currentStepId);
        }
        this.database.prepare("UPDATE missions SET status = 'active', updated_at = ? WHERE id = ?")
          .run(now, current.run.missionId);
        this.repository.appendAudit({
          missionId: current.run.missionId, runId, actorId, action: "run.resumed",
          resourceType: "run", resourceId: runId, reason: normalized,
          details: {
            ...(commandId ? { commandId } : {}),
            committedRunVersion: transitioned.run.run.stateVersion,
            checkpointId: transitioned.checkpointId,
            checkpointEventSequence: transitioned.eventSequence,
          },
          now,
        });
        if (target === "recovering") {
          if (recoveryRetry) {
            continuationKind = "autonomous_retry_to_dispatch";
            this.continuations.enqueue({
              runId,
              kind: continuationKind,
              sourceId: recoveryRetry.action_id,
              payload: { actionId: recoveryRetry.action_id, stepId: recoveryRetry.step_id },
              now,
            });
          } else {
            this.continuations.enqueue({
              runId,
              kind: continuationKind,
              sourceId: String(transitioned.run.run.stateVersion),
              now,
            });
          }
        }
      });
      this.crashAfterCommit("resume_projection_committed", runId);
      keepAuthorityForRecovery = target === "recovering" || target === "waiting_guided_decision";
      if (target === "recovering") void this.replayContinuations(runId, [continuationKind]);
    } finally {
      if (!keepAuthorityForRecovery) this.releaseControlPlaneAuthority(runId);
    }
  }

  private appendGuidedStopRecords(
    stop: GuidedStopContext,
    actorId: string,
    reason: string,
    now: string,
    commandId?: string,
  ): void {
    const canonical = this.database.prepare(`
      SELECT mission_id, run_id, step_id, requested_action_fingerprint,
        requested_parameters_json
      FROM guided_decisions WHERE id = ?
    `).get(stop.decisionId) as {
      mission_id: string;
      run_id: string;
      step_id: string;
      requested_action_fingerprint: string;
      requested_parameters_json: string;
    } | undefined;
    if (
      !canonical || canonical.mission_id !== stop.missionId ||
      canonical.run_id !== stop.runId || canonical.step_id !== stop.stepId ||
      canonical.requested_action_fingerprint !== stop.actionFingerprint ||
      hashCanonical(JSON.parse(canonical.requested_parameters_json)) !== stop.parameterHash
    ) {
      throw new CommandRuntimeError(409, "guided_stop_boundary_changed", "The exact Guided stop boundary changed", {
        humanMessage: "The represented Guided step changed before its stop record could be committed.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and stop only from its current exact decision card.",
      });
    }
    const existing = this.database.prepare(`
      SELECT id FROM events
      WHERE run_id = ? AND event_type = 'guided.mission_stopped'
        AND json_extract(payload_json, '$.decisionId') = ?
      LIMIT 1
    `).get(stop.runId, stop.decisionId) as { id: string } | undefined;
    if (existing) return;
    this.repository.events.append({
      missionId: stop.missionId,
      runId: stop.runId,
      journey: "guided",
      eventType: "guided.mission_stopped",
      actorType: "operator",
      actorId,
      summary: "Operator stopped the mission from the exact represented Guided step",
      payload: {
        decisionId: stop.decisionId,
        stepId: stop.stepId,
        actionFingerprint: stop.actionFingerprint,
        parameterHash: stop.parameterHash,
        reason,
        ...(commandId ? { commandId } : {}),
      },
      sensitivity: "private",
    });
    this.repository.appendAudit({
      missionId: stop.missionId,
      runId: stop.runId,
      actorId,
      action: "guided.mission_stopped",
      resourceType: "guided_decision",
      resourceId: stop.decisionId,
      reason,
      details: {
        stepId: stop.stepId,
        actionFingerprint: stop.actionFingerprint,
        parameterHash: stop.parameterHash,
        ...(commandId ? { commandId } : {}),
      },
      now,
    });
  }

  private guidedStopFromCancellationPayload(
    payloadJson: string,
    missionId: string,
    runId: string,
  ): GuidedStopContext | undefined {
    const corrupt = (): never => {
      throw new CommandRuntimeError(
        409,
        "guided_stop_context_corrupt",
        "Persisted Guided stop context failed integrity validation",
        {
          humanMessage: "Cancellation recovery stopped because the exact Guided decision boundary could not be verified.",
          retryable: false,
          category: "data_integrity",
          remediation: "Inspect the immutable cancellation request and decision provenance before terminating the run through a reviewed recovery action.",
        },
      );
    };
    let payload: unknown;
    try {
      payload = JSON.parse(payloadJson);
    } catch {
      return corrupt();
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return corrupt();
    const payloadRecord = payload as Record<string, unknown>;
    if (!Object.prototype.hasOwnProperty.call(payloadRecord, "guidedStop")) return undefined;
    const value = payloadRecord.guidedStop;
    if (!value || typeof value !== "object" || Array.isArray(value)) return corrupt();
    const stop = value as Record<string, unknown>;
    const text = (key: string): string | undefined => {
      const item = stop[key];
      return typeof item === "string" && item.length > 0 && item.length <= 256
        ? item
        : undefined;
    };
    const decisionId = text("decisionId");
    const storedMissionId = text("missionId");
    const storedRunId = text("runId");
    const stepId = text("stepId");
    const actionFingerprint = text("actionFingerprint");
    const parameterHash = text("parameterHash");
    if (
      !decisionId || storedMissionId !== missionId || storedRunId !== runId || !stepId
      || !actionFingerprint || !parameterHash
      || !/^[a-f0-9]{64}$/u.test(actionFingerprint)
      || !/^[a-f0-9]{64}$/u.test(parameterHash)
    ) return corrupt();
    const canonical = this.database.prepare(`
      SELECT mission_id, run_id, step_id, requested_action_fingerprint,
        requested_parameters_json
      FROM guided_decisions WHERE id = ?
    `).get(decisionId) as {
      mission_id: string;
      run_id: string;
      step_id: string;
      requested_action_fingerprint: string;
      requested_parameters_json: string;
    } | undefined;
    let canonicalParameterHash: string;
    try {
      canonicalParameterHash = canonical
        ? hashCanonical(JSON.parse(canonical.requested_parameters_json))
        : "";
    } catch {
      return corrupt();
    }
    if (
      !canonical || canonical.mission_id !== missionId || canonical.run_id !== runId
      || canonical.step_id !== stepId
      || canonical.requested_action_fingerprint !== actionFingerprint
      || canonicalParameterHash !== parameterHash
    ) return corrupt();
    return {
      decisionId,
      missionId: storedMissionId,
      runId: storedRunId,
      stepId,
      actionFingerprint,
      parameterHash,
    };
  }

  private recordGuidedStopForCancelledRun(
    stop: GuidedStopContext,
    actorId: string,
    reason: string,
    commandId?: string,
  ): void {
    this.ensureControlPlaneAuthority(stop.runId);
    const authority = this.runMutationAuthority.authorize({
      runId: stop.runId,
      actorId,
      mode: "lease",
      assertLease: ({ runId }) => this.assertControlPlaneMutationAuthority(runId),
    });
    inImmediateTransaction(this.database, () => {
      authority.assertCurrent();
      const run = this.database.prepare(`
        SELECT status FROM runs WHERE id = ? AND mission_id = ?
      `).get(stop.runId, stop.missionId) as { status: string } | undefined;
      if (run?.status !== "cancelled") {
        throw new CommandRuntimeError(409, "guided_stop_not_cancelled", "Guided stop record requires a cancelled run");
      }
      this.appendGuidedStopRecords(stop, actorId, reason, this.timestamp(), commandId);
    });
  }

  async stopGuidedMission(
    decisionId: string,
    actorId: string,
    reason: string,
    commandId?: string,
  ): Promise<void> {
    const decision = this.repository.getDecision(decisionId);
    const ownership = this.runMutationAuthority.authorize({
      runId: decision.runId,
      actorId,
      mode: "ownership",
    });
    ownership.assertCurrent();
    const current = this.repository.requireCurrentPendingDecision(decisionId, this.timestamp());
    await this.cancelRun(current.runId, actorId, reason, commandId, {
      decisionId: current.id,
      missionId: current.missionId,
      runId: current.runId,
      stepId: current.stepId,
      actionFingerprint: current.actionFingerprint,
      parameterHash: hashCanonical(current.requestedParameters),
    });
  }

  /**
   * Stop only the exact running children captured by a plan-amendment
   * boundary. The currently supported execution adapters expose a run-scoped
   * process-group stop, so this method proves set equality first and refuses
   * to use that primitive when any unrelated running child exists. It never
   * transitions the run itself to `cancelled`.
   */
  async cancelPlanChangeAffectedWork(
    runId: string,
    actionIds: readonly string[],
    reason: string,
  ): Promise<PlanChangeAffectedWorkStopReceipt> {
    const normalized = validateReason(reason);
    this.assertControlPlaneMutationAuthority(runId);
    const requested = [...new Set(actionIds.map((value) => value.trim())
      .filter(Boolean))].sort();
    const running = (this.database.prepare(`
      SELECT id, step_id, assignment_id FROM actions
      WHERE run_id = ? AND status = 'running'
      ORDER BY id
    `).all(runId) as Array<{
      readonly id: string;
      readonly step_id: string | null;
      readonly assignment_id: string | null;
    }>);
    const runningActionIds = running.map((row) => row.id);
    if (
      requested.length !== runningActionIds.length
      || requested.some((actionId, index) => actionId !== runningActionIds[index])
    ) {
      throw new CommandRuntimeError(
        409,
        "plan_change_exact_child_set_mismatch",
        "Exact affected-child cancellation cannot use a run-scoped process stop while unrelated work is active",
        {
          humanMessage: "Ti-Scale kept unrelated work running and refused to substitute full-run cancellation.",
          category: "conflict",
          remediation: "Wait for unrelated work to settle, then retry the represented affected-work cancellation.",
        },
      );
    }
    const mappedAssignmentIds = [...new Set(running
      .map((row) => row.assignment_id)
      .filter((value): value is string => value !== null))].sort();
    const mappedStepIds = [...new Set(running
      .map((row) => row.step_id)
      .filter((value): value is string => value !== null))].sort();
    const stoppedAssignmentIds = mappedAssignmentIds.length === 0
      ? []
      : (this.database.prepare(`
          SELECT id FROM assignments
          WHERE run_id = ? AND status IN ('active', 'blocked')
            AND id IN (${mappedAssignmentIds.map(() => "?").join(", ")})
          ORDER BY id
        `).all(runId, ...mappedAssignmentIds) as Array<{ readonly id: string }>)
        .map((row) => row.id);
    const stoppedStepIds = mappedStepIds.length === 0
      ? []
      : (this.database.prepare(`
          SELECT id FROM plan_steps
          WHERE run_id = ?
            AND status IN (
              'pending', 'ready', 'running', 'waiting_guided_decision',
              'blocked', 'recovering'
            )
            AND id IN (${mappedStepIds.map(() => "?").join(", ")})
          ORDER BY id
        `).all(runId, ...mappedStepIds) as Array<{ readonly id: string }>)
        .map((row) => row.id);
    const stoppedAttackAttemptIds = stoppedStepIds.length === 0
      ? []
      : (this.database.prepare(`
          SELECT id FROM attack_attempts
          WHERE run_id = ? AND status = 'running'
            AND step_id IN (${stoppedStepIds.map(() => "?").join(", ")})
          ORDER BY id
        `).all(runId, ...stoppedStepIds) as Array<{ readonly id: string }>)
        .map((row) => row.id);
    const receipt: PlanChangeAffectedWorkStopReceipt = {
      stoppedActionIds: requested,
      stoppedAssignmentIds,
      stoppedAttackAttemptIds,
      stoppedStepIds,
    };
    if (requested.length === 0) return receipt;
    await this.execution.cancelRun(runId, normalized);
    this.controllers.get(runId)?.abort(normalized);
    for (const actionId of requested) this.clearActionContext(actionId);
    return receipt;
  }

  async cancelRun(
    runId: string,
    actorId: string,
    reason: string,
    commandId?: string,
    guidedStop?: GuidedStopContext,
  ): Promise<void> {
    const normalized = validateReason(reason);
    const ownership = this.runMutationAuthority.authorize({
      runId,
      actorId,
      mode: "ownership",
    });
    ownership.assertCurrent();
    const current = this.coordinator.getRun(runId);
    if (isTerminalRunState(current.run.state)) {
      if (commandId && !this.hasCancellationCommand(runId, commandId)) {
        throw new CommandRuntimeError(409, "cancellation_command_not_current", "Run is already terminal under another command", {
          humanMessage: "This run already reached a terminal state; a different cancellation command cannot claim that result.",
          category: "conflict",
          remediation: "Refresh the run and inspect the terminal cancellation record.",
        });
      }
      if (current.run.state !== "cancelled") {
        throw new CommandRuntimeError(409, "run_terminal_not_cancelled", "Terminal run cannot accept cancellation", {
          humanMessage: `This run is already ${current.run.state}; cancellation cannot rewrite its outcome.`,
          category: "conflict",
        });
      }
      try {
        this.reconcileCancelledRunResidue(
          runId,
          "Reconciled the exact repeated cancellation command against terminal state",
        );
        if (guidedStop) {
          this.recordGuidedStopForCancelledRun(
            guidedStop,
            actorId,
            normalized,
            commandId,
          );
        }
        this.recordTerminalEvaluationWithBrain({
          runId,
          terminalStatus: "cancelled",
          createdBy: "run-supervisor",
        });
        await this.replayContinuations(runId, ["evaluation_pending", "memory_projection_pending"]);
      } finally {
        this.releaseControlPlaneAuthority(runId);
      }
      return;
    }

    const activeCancellation = this.activeCancellationCommand(runId);
    if (activeCancellation) {
      if (!commandId || activeCancellation.commandId !== commandId) {
        throw new CommandRuntimeError(409, "cancellation_already_requested", "Another durable cancellation command is already active", {
          humanMessage: "Cancellation is already being finalized under a different fenced command.",
          retryable: true,
          category: "conflict",
          remediation: "Refresh the run after the current cancellation continuation reaches a durable outcome.",
        });
      }
      try {
        await this.replayContinuations(runId, ["cancellation_finalize_pending"]);
        const recovered = this.coordinator.getRun(runId);
        if (recovered.run.state === "cancelled") {
          if (guidedStop) {
            this.recordGuidedStopForCancelledRun(
              guidedStop,
              actorId,
              normalized,
              commandId,
            );
          }
          return;
        }
        if (recovered.run.state === "blocked" || recovered.run.state === "failed") {
          throw new CommandRuntimeError(409, "cancellation_recovery_failed", "Cancellation cleanup did not reach a safe terminal state", {
            humanMessage: "The original cancellation command was recovered, but child cleanup requires review.",
            category: "runtime",
            remediation: "Open the Recovery Panel and inspect the cancellation failure diagnosis.",
          });
        }
        throw new CommandRuntimeError(409, "cancellation_in_progress", "Cancellation finalization is still in progress", {
          humanMessage: "The exact cancellation command is still closing durable child work.",
          retryable: true,
          category: "conflict",
        });
      } finally {
        this.releaseControlPlaneAuthority(runId);
      }
    }
    const lease = this.controlLease(runId);
    const mutationAuthority = this.runMutationAuthority.authorize({
      runId,
      actorId,
      mode: "lease",
      assertLease: ({ runId: ownedRunId }) =>
        this.assertControlPlaneMutationAuthority(ownedRunId),
    });
    try {
      await this.coordinator.cancelRun({
        lease,
        reason: normalized,
        commandId,
        actorId,
        ...(guidedStop ? { guidedStop } : {}),
        onTerminalCommit: (boundary) => {
          // Child aggregates, terminal run pointers, the terminal checkpoint,
          // cancellation audit, and control-plane release share one SQLite
          // transaction. There is no post-commit window in which a cancelled
          // run can still look owned or executable.
          mutationAuthority.assertCurrent();
          if (guidedStop) {
            this.appendGuidedStopRecords(
              guidedStop,
              actorId,
              normalized,
              boundary.now,
              commandId,
            );
          }
          this.repository.appendAudit({
            missionId: boundary.run.run.missionId,
            runId,
            actorId,
            action: "run.cancelled",
            resourceType: "run",
            resourceId: runId,
            reason: normalized,
            details: {
              ...(commandId ? { commandId } : {}),
              committedRunVersion: boundary.run.run.stateVersion,
              checkpointId: boundary.checkpointId,
              checkpointEventSequence: boundary.eventSequence,
            },
            now: boundary.now,
          });
          this.releaseControlPlaneAuthorityInTransaction(runId, boundary.now);
        },
      });
      // The durable lease is already released. Retire timers and the local
      // copy of its secret synchronously before any callback or fault
      // injection can yield and accidentally reacquire terminal authority.
      this.clearActionContextsForRun(runId);
      this.controlPlaneTokens.delete(runId);
      // At this boundary the coordinator has already closed every durable
      // execution child, cleared active-work pointers, checkpointed the
      // terminal state, and released control-plane authority atomically.
      this.crashAfterCommit("cancellation_terminal_before_runtime_cleanup", runId);
      await this.replayContinuations(runId, ["evaluation_pending", "memory_projection_pending"]);
    } finally {
      this.releaseControlPlaneAuthority(runId);
    }
  }
}

export function createMissionRuntime(options: MissionRuntimeOptions): MissionRuntimeEngine {
  return new MissionRuntimeEngine(options);
}

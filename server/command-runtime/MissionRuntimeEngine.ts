import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import {
  ControlPlaneLeaseError,
  ControlPlaneLeaseService,
  type ControlPlaneLease,
} from "../control-plane";
import {
  ActionRepository,
  CheckpointRepository,
  DurableOrchestrationError,
  DurableRunCoordinator,
  type DurableAction,
  type RunLeaseToken,
} from "../orchestration";
import { RunRepository } from "../orchestration";
import { canonicalJson } from "../orchestration/serialization";
import { RunLearningService } from "../learning";
import { FailureDiagnosisService } from "../intelligence-v24/FailureDiagnosisService";
import type {
  FailureCategory as OperationalFailureCategory,
  FailureOperatorAction,
} from "../intelligence-v24/types";
import { MemoryRepository, SecondBrainService } from "../memory";
import {
  BrainContextService,
  BrainContextHookError,
  retrieveMissionBrainContext,
  type BrainContextResult,
  type BrainLifecycleHook,
  type BrainProviderContextEnvelope,
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
  GuidedDecisionSkipResult,
  MissionCompletionEvaluation,
  MissionCompletionPortResult,
  MissionPlanDraft,
  MissionPlanPortResult,
  MissionRuntimeOptions,
  ProviderUsageReport,
  ResumeRunBoundary,
  RuntimeActionContext,
  RuntimeLifecycleResult,
} from "./types";
import { CommandRuntimeError } from "./types";
import { validateExecutionResultSummary, validateMissionPlanDraft, validateReason } from "./validation";

interface HeartbeatLease {
  token(): Promise<RunLeaseToken>;
  stop(): Promise<RunLeaseToken>;
}

class RuntimeCrashAfterCommit extends Error {
  constructor(readonly point: string) {
    super(`Injected process crash after durable commit: ${point}`);
    this.name = "RuntimeCrashAfterCommit";
  }
}

function planResult(value: MissionPlanDraft | MissionPlanPortResult): MissionPlanPortResult {
  return "plan" in value ? value : { plan: value, usage: value.providerUsage };
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
  if (error instanceof DurableOrchestrationError) {
    return new CommandRuntimeError(409, error.code, error.message, {
      humanMessage: error.message,
      category: error.code.includes("contract") || error.code.includes("decision")
        ? "policy_denied"
        : "runtime",
    });
  }
  const category = classifyFailure(failureSignal(error));
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

export class MissionRuntimeEngine implements ExecutionResultSink {
  readonly repository: RuntimeRepository;
  readonly continuations: RuntimeContinuationRepository;
  readonly coordinator: DurableRunCoordinator;
  readonly learning: RunLearningService;
  readonly brainContext: BrainContextService;
  private readonly database: SqliteDatabase;
  private readonly workerId: string;
  private readonly scanIntervalMs: number;
  private readonly leaseTtlMs: number;
  private readonly decisionTtlMs: number;
  private readonly maxPlanSteps: number;
  private readonly now: () => Date;
  private readonly controlPlaneLeases: ControlPlaneLeaseService;
  private readonly controlPlaneTokens = new Map<string, string>();
  private readonly processing = new Map<string, Promise<void>>();
  private readonly continuationProcessing = new Map<string, Promise<void>>();
  private readonly actionContexts = new Map<string, RuntimeActionContext>();
  private readonly controllers = new Map<string, AbortController>();
  private scanTimer?: ReturnType<typeof setInterval>;
  private stopping = false;
  private unbindResultSink?: () => void;

  constructor(private readonly options: MissionRuntimeOptions) {
    this.database = options.database;
    this.now = options.now ?? (() => new Date());
    this.repository = new RuntimeRepository(options.database);
    this.controlPlaneLeases = new ControlPlaneLeaseService(options.database);
    this.continuations = new RuntimeContinuationRepository(options.database);
    this.learning = new RunLearningService(options.database, {
      clock: this.now,
      events: this.repository.events,
    });
    this.brainContext = options.brainContext ?? new BrainContextService({
      database: options.database,
      secondBrain: new SecondBrainService(new MemoryRepository(options.database, { clock: this.now })),
    });
    this.workerId = options.workerId?.trim() || `command-runtime-${randomUUID()}`;
    this.scanIntervalMs = options.scanIntervalMs ?? 500;
    this.leaseTtlMs = options.leaseTtlMs ?? 30_000;
    this.decisionTtlMs = options.decisionTtlMs ?? 24 * 60 * 60 * 1_000;
    this.maxPlanSteps = options.maxPlanSteps ?? 32;
    if (this.scanIntervalMs < 50 || this.leaseTtlMs < 500 || this.decisionTtlMs < 1_000) {
      throw new RangeError("Runtime scan, lease, or decision timing is below its safe minimum");
    }
    this.coordinator = new DurableRunCoordinator(options.database, options.execution, {
      now: this.now,
      leaseTtlMs: this.leaseTtlMs,
      supervisor: new RunSupervisor({ retryPolicy: options.retryPolicy }),
      afterActionCommit: (action) => {
        this.crashAfterCommit("action_reserved_before_dispatch", action.runId, action.id);
      },
      afterCancellationCleanup: (runId) => {
        this.crashAfterCommit("cancellation_cleanup_before_finalize", runId);
      },
    });
    const unbind = options.execution.bindResultSink?.(this);
    if (typeof unbind === "function") this.unbindResultSink = unbind;
  }

  private timestamp(): string {
    return this.now().toISOString();
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
  }): BrainContextResult {
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
      ...(input.terminalSafe ? { terminalSafe: true } : {}),
    });
  }

  private providerBrainContext(result: BrainContextResult): BrainProviderContextEnvelope {
    return this.brainContext.providerContext(result);
  }

  private terminalLearningAlreadyRecorded(runId: string): boolean {
    return Boolean(this.database.prepare("SELECT 1 FROM run_evaluations WHERE run_id = ? LIMIT 1").get(runId));
  }

  /**
   * Terminal learning is idempotent at the evaluation row. The lifecycle
   * hooks are kept in the same caller transaction as the first evaluation so
   * a retry cannot manufacture duplicate lesson/closeout Context Packs after
   * the evaluation already exists.
   */
  private recordTerminalEvaluationWithBrain(input: {
    readonly runId: string;
    readonly terminalStatus: "completed" | "failed" | "cancelled";
    readonly createdBy: string;
    readonly outcome?: MissionCompletionEvaluation;
    readonly evaluationContextAlreadyRetrieved?: boolean;
  }): void {
    if (this.terminalLearningAlreadyRecorded(input.runId)) return;
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
    this.brainContext.recordUnusedContext(
      lessonContext,
      "The deterministic candidate-lesson generator used canonical local evaluation records; retrieved memory was retained as review context and did not rewrite or self-approve the candidate.",
    );
    const closeoutContext = this.retrieveBrainContext({
      hook: "closeout",
      mission,
      run,
      actorId: input.createdBy,
      query: "Retrieve the bounded mission cluster needed to preserve the terminal outcome and its evidence-linked learning.",
      queryRedacted: "Retrieve the bounded mission cluster needed to preserve the terminal outcome and its evidence-linked learning.",
      terminalSafe: true,
    });
    this.brainContext.recordUnusedContext(
      closeoutContext,
      "The deterministic closeout writer used canonical mission records; retrieved memory was retained for audit context and did not alter the terminal outcome or immutable evidence links.",
    );
    this.learning.recordTerminalEvaluation(input);
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
        SELECT mission_id, journey, status FROM runs WHERE id = ?
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
          last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
        WHERE id = ? AND (
          lease_owner IS NOT NULL OR lease_acquired_at IS NOT NULL OR
          last_heartbeat_at IS NOT NULL OR lease_expires_at IS NOT NULL
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
    const runIds = (this.database.prepare(`
      SELECT id FROM runs WHERE status = 'cancelled' ORDER BY updated_at, id
    `).all() as Array<{ id: string }>).map((row) => row.id);
    return runIds.reduce(
      (total, runId) => total + this.reconcileCancelledRunResidue(runId),
      0,
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
    const accounted = this.coordinator.accountUsage({
      lease,
      phase,
      ...(usage ? {
        delta: {
          providerTurns: usage?.providerTurns ?? 1,
          ...(usage.exactTokenUsage && usage.providerTokens !== undefined
            ? { providerTokens: usage.providerTokens }
            : {}),
          ...(usage.exactCostUsage && usage.estimatedCost !== undefined
            ? { estimatedCost: usage.estimatedCost }
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
    this.reconcileAllCancelledRunResidue();
    this.continuations.reconcileFromCanonicalState(this.timestamp());
    // Cancellation wins over ordinary action recovery. A process that died
    // after child cleanup but before aggregate finalization must never resume
    // the very work the operator asked it to stop.
    await this.replayContinuations(undefined, ["cancellation_finalize_pending"]);
    await this.replayContinuations();
    const recovered = await this.recover();
    // Recovery must classify every expired lease before the scheduler can
    // reclaim planning work. In particular, this closes an interrupted ACP
    // provider turn and checkpoints run.recovery_started before a fresh
    // planning lease is acquired.
    this.continuations.reconcileFromCanonicalState(this.timestamp());
    const scheduledRuns = await this.scanOnce();
    this.scanTimer = setInterval(() => {
      void this.scanOnce().catch(() => undefined);
    }, this.scanIntervalMs);
    return { recoveredRuns: recovered, scheduledRuns };
  }

  async stop(): Promise<void> {
    this.stopping = true;
    if (this.scanTimer) clearInterval(this.scanTimer);
    this.scanTimer = undefined;
    for (const controller of this.controllers.values()) controller.abort("Ti-Scale runtime stopped");
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
    const results = await this.coordinator.recoverOnStartup(this.workerId);
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

  async scanOnce(): Promise<number> {
    if (this.stopping) return 0;
    this.continuations.reconcileFromCanonicalState(this.timestamp());
    const continuationRuns = this.continuations.readyRunIds(this.timestamp());
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
    const candidates = this.repository.listRunnableRuns(this.timestamp());
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

  async processRunNow(runId: string, planningRetryContinuationId?: string): Promise<void> {
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
    const runIds = runId ? [runId] : this.continuations.readyRunIds(this.timestamp(), 200);
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
    if (this.stopping || this.continuationProcessing.has(runId)) return false;
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
      } catch (error) {
        if (error instanceof RuntimeCrashAfterCommit) throw error;
        const message = error instanceof Error ? error.message : "Continuation handler failed";
        const current = this.continuations.get(continuation.id);
        if (current.status === "processing" && current.leaseOwner === continuation.leaseOwner) {
          const run = this.coordinator.getRun(runId);
          if (isTerminalRunState(run.run.state) || run.run.state === "blocked") {
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
    const run = this.coordinator.getRun(continuation.runId);
    if (isTerminalRunState(run.run.state) && continuation.kind !== "evaluation_pending") {
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
          inImmediateTransaction(this.database, () => {
            this.recordTerminalEvaluationWithBrain({
              runId: continuation.runId,
              terminalStatus: "failed",
              createdBy: "run-supervisor",
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
        json_extract(a.normalized_arguments_json, '$.orchestration.kind') AS action_kind,
        r.journey, ps.status AS step_status, ps.plan_id
      FROM actions a
      JOIN runs r ON r.id = a.run_id
      JOIN plan_steps ps ON ps.id = a.step_id
      WHERE a.id = ? AND a.run_id = ?
    `).get(actionId, continuation.runId) as {
      step_id: string;
      status: string;
      result_summary: string | null;
      action_kind: string | null;
      journey: "autonomous" | "guided";
      step_status: string;
      plan_id: string;
    } | undefined;
    if (!action) throw new Error("Continuation action no longer exists");
    if (["completed", "skipped", "cancelled"].includes(action.step_status)) {
      this.completeContinuation(continuation);
      this.continuations.reconcileFromCanonicalState(this.timestamp());
      return;
    }
    if (action.status !== "succeeded") {
      throw new Error(`Action ${actionId} is not a successful advance predecessor`);
    }
    const phaseContextExists = Boolean(this.database.prepare(`
      SELECT 1 FROM memory_context_packs
      WHERE run_id = ? AND step_id = ? AND action_id = ?
        AND purpose LIKE 'Phase transition:%'
      LIMIT 1
    `).get(continuation.runId, action.step_id, actionId));
    if (!phaseContextExists) {
      const phaseRun = this.repository.getPlanningRun(continuation.runId);
      const phaseMission = this.repository.getMission(phaseRun.missionId);
      const phaseContext = this.retrieveBrainContext({
        hook: "phase_transition",
        mission: phaseMission,
        run: phaseRun,
        stepId: action.step_id,
        actionId,
        actorId: "phase-supervisor",
        query: `${action.result_summary ?? "The represented action completed"} material result phase refresh`,
        queryRedacted: "Refresh scoped context after a material represented-action result.",
      });
      this.brainContext.recordUnusedContext(
        phaseContext,
        "The durable phase transition was derived from canonical action state; retrieved memory was retained for the next bounded decision and did not rewrite the completed result.",
      );
    }
    const lease = this.continuationLease(continuation.runId);
    const now = this.timestamp();
    let evaluationQueued = false;
    inImmediateTransaction(this.database, () => {
      const runs = new RunRepository(this.database);
      const current = runs.get(continuation.runId);
      runs.assertLease(current, lease, now);
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
      if (advanced.completed) {
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
          ? "Durable action result advanced to mission success evaluation"
          : current.run.journey === "guided"
            ? "Durable action result advanced to the next exact Guided decision"
            : "Durable action result advanced to the next in-contract Autonomous step",
        payload: {
          continuationId: continuation.id,
          kind: continuation.kind,
          actionId,
          nextStepId: advanced.nextStepId,
          nextGuidedDecisionId: advanced.guidedDecisionId,
        },
      });
    });
    if (evaluationQueued) {
      this.crashAfterCommit("step_advance_to_evaluation", continuation.runId, action.plan_id);
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

  private async finalizeCancellationContinuation(continuation: RuntimeContinuation): Promise<void> {
    const event = this.database.prepare(`
      SELECT actor_id, summary,
        json_extract(payload_json, '$.commandId') AS command_id
      FROM events
      WHERE id = ? AND run_id = ? AND event_type = 'run.cancellation_requested'
    `).get(continuation.sourceId, continuation.runId) as {
      actor_id: string | null;
      summary: string;
      command_id: string | null;
    } | undefined;
    const actorId = event?.actor_id ?? "operator";
    const reason = event?.summary.replace(/^Cancellation requested:\s*/u, "").trim()
      || "Operator requested cancellation";
    const before = this.coordinator.getRun(continuation.runId);
    if (before.run.state === "cancelled") {
      inImmediateTransaction(this.database, () => {
        this.repository.cancelOpenWork(continuation.runId, actorId, reason, this.timestamp());
        this.completeContinuation(continuation);
      });
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
      this.recordTerminalEvaluationWithBrain({
        runId: continuation.runId,
        terminalStatus: "cancelled",
        createdBy: "run-supervisor",
      });
      this.completeContinuation(continuation);
      this.continuations.cancelOpen(continuation.runId, now, "Run reached a terminal cancelled state");
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
    });
    for (const [actionId, context] of this.actionContexts) {
      if (context.action.runId !== continuation.runId) continue;
      if (context.heartbeat) clearInterval(context.heartbeat);
      this.actionContexts.delete(actionId);
    }
  }

  private async processRun(runId: string, planningRetryContinuationId?: string): Promise<void> {
    let planningRun = this.repository.getPlanningRun(runId);
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
      let planned: MissionPlanPortResult;
      try {
        planned = planResult(await this.options.planner.plan({
            mission,
            run: planningRun,
            brainContext: this.providerBrainContext(planningContext),
            ...(guidedRecovery ? {
              rejectionReason: `The represented action "${guidedRecovery.attemptedActionSummary}" failed with ${guidedRecovery.errorCategory}: ${guidedRecovery.failureSummary}. Propose one materially different in-scope action; do not repeat the failed parameters.`,
            } : recovery?.kind === "replan" ? {
              // beginReplan intentionally moves the run from recovering to
              // planning before this provider turn. Preserve the durable,
              // operator-supplied strategy across that transition so a replay
              // cannot silently fall back to an equivalent plan.
              rejectionReason: recovery.reason,
            } : planningRun.state === "recovering" ? { rejectionReason: planningRun.stateReason } : {}),
          }, signal));
      } catch (error) {
        planningProviderFailed = true;
        throw error;
      }
      const draft = validateMissionPlanDraft(
        planned.plan,
        this.maxPlanSteps,
        planningRun.journey,
      );
      lease = await heartbeat.stop();
      heartbeatStopped = true;
      lease = this.accountProviderUsage(lease, planned.usage, "mission planning");
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
        commitPlanningContextAttribution(
          this.database,
          planned.plan.planningAttribution,
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
                ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
                exhausted: [...scheduled.exhausted],
              },
              remediation: providerWaitExceedsBound
                ? "Wait for the provider window to recover, test provider readiness, then start a new run from the preserved mission."
                : "Wait for the provider window to recover, then start a new run from the preserved mission.",
            },
          );
        }
        const accounted = this.coordinator.accountUsage({
          lease,
          delta: { providerTurns: 1 },
          phase: "failed mission planning turn",
        });
        if (accounted.allowed && accounted.run.lease) lease = accounted.run.lease;
      }
      const checkpointId = await this.safeStopPlanning(runId, lease, runtimeError);
      if (planningProviderFailed) {
        this.persistPlanningFailureDiagnosis({
          runId,
          originalError: error,
          runtimeError,
          category: planningFailureCategory(error, runtimeError),
          retryAfterMs: planningRetryAfterMs(error, this.now()),
          ...(checkpointId ? { checkpointId } : {}),
          terminal: true,
        });
      }
      throw runtimeError;
    }
  }

  private persistPlanningFailureDiagnosis(input: {
    readonly runId: string;
    readonly originalError: unknown;
    readonly runtimeError: CommandRuntimeError;
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
    const latestTurn = providerTurns.at(-1);
    if (latestTurn) {
      const existing = this.database.prepare(`
        SELECT fd.id
        FROM failure_diagnoses fd, json_each(fd.retry_history_json) attempt
        WHERE fd.run_id = ? AND fd.subject_type = 'run'
          AND fd.originating_component = 'command-runtime.planning-provider'
          AND json_extract(attempt.value, '$.providerTurnId') = ?
        LIMIT 1
      `).get(input.runId, latestTurn.id) as { id: string } | undefined;
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
        originatingComponent: "command-runtime.planning-provider",
        ...(lastSuccess ? { lastSuccessEventId: lastSuccess.id } : {}),
        failedComponentRef: latestTurn
          ? `${latestTurn.provider}/${latestTurn.model}`
          : "configured planning provider",
        targetSummary: "Mission planning failed before any target, MCP tool, or represented action was contacted.",
        policyOrDependency: `The provider failure remained inside the signed ${run.run.journey} mission boundary.`,
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
            ?? "Verify provider health, then resume only through the server-declared bounded recovery control.",
        operatorActions: planningFailureOperatorActions(category, retryable),
        objectiveImpact: "No plan or target-side evidence was committed by this failed provider turn; the mission objective remains unchanged.",
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
    context.heartbeat = setInterval(() => {
      if (context.completing) return;
      try {
        this.heartbeatControlPlane(context.action.runId);
        context.lease = this.coordinator.heartbeatRunLease(context.lease, this.leaseTtlMs);
      } catch {
        if (context.heartbeat) clearInterval(context.heartbeat);
      }
    }, Math.max(250, Math.floor(this.leaseTtlMs / 3)));
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
      if (intent.assignmentId) {
        const assignment = this.database.prepare("SELECT agent_id FROM assignments WHERE id = ? AND run_id = ?")
          .get(intent.assignmentId, intent.runId) as { agent_id: string } | undefined;
        if (!assignment) throw new CommandRuntimeError(409, "assignment_scope_invalid", "Represented assignment is not canonical");
        const context = this.retrieveBrainContext({
          hook: "assignment_acceptance",
          mission,
          run,
          stepId: intent.stepId,
          actorId: assignment.agent_id,
          query: `${intent.intentSummary} specialist capability dependencies`,
          queryRedacted: `${intent.actionClass} assignment acceptance`,
        });
        this.brainContext.recordUnusedContext(
          context,
          "The assignment boundary confirmed scoped Brain readiness and preserved the represented specialist assignment; retrieved memory was not yet consumed to alter that assignment.",
        );
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
        });
        this.brainContext.recordUnusedContext(
          context,
          "The deterministic tool-policy boundary preserved the represented tool action; retrieved memory was not consumed to change its type, target, or parameters.",
        );
        actionContextPackId = context.contextPack.id;
      }
      const before = this.coordinator.getRun(intent.runId).control.progress;
      const started = await this.coordinator.startAction({
        lease,
        intent: actionContextPackId ? { ...intent, contextPackId: actionContextPackId } : intent,
        ...(guidedDecisionId ? { guidedDecisionId } : {}),
      });
      const row = this.database.prepare("SELECT status FROM actions WHERE id = ?")
        .get(started.action.id) as { status: string } | undefined;
      if (row?.status === "running") {
        const context: RuntimeActionContext = {
          action: started.action,
          lease: started.lease,
          before,
          completing: false,
        };
        this.actionContexts.set(started.action.id, context);
        this.actionHeartbeat(context);
      }
      return started.action;
    } catch (error) {
      if (error instanceof RuntimeCrashAfterCommit) throw error;
      const runtimeError = asRuntimeError(error);
      if (
        runtimeError.code === "autonomous_action_not_allowed" ||
        runtimeError.code === "autonomous_target_not_allowed" ||
        runtimeError.code === "autonomous_contract_not_signed" ||
        runtimeError.code === "autonomous_manual_action_forbidden"
      ) {
        await this.safeStopPlanning(intent.runId, lease, new CommandRuntimeError(409, runtimeError.code, runtimeError.message, {
          humanMessage: "Safe-stopped: the next action is outside the signed Autonomous contract.",
          category: "scope_conflict",
        }));
      }
      throw runtimeError;
    }
  }

  async acceptExecutionResult(result: ExecutionResult): Promise<ExecutionResultReceipt> {
    const summary = validateExecutionResultSummary(result.summary);
    const row = this.database.prepare(`
      SELECT id, run_id, step_id, fingerprint, status FROM actions WHERE id = ?
    `).get(result.actionId) as {
      id: string; run_id: string; step_id: string; fingerprint: string; status: string;
    } | undefined;
    if (!row) throw new CommandRuntimeError(404, "action_not_found", `Action not found: ${result.actionId}`);
    if (row.run_id !== result.runId || row.fingerprint !== result.actionFingerprint) {
      throw new CommandRuntimeError(409, "execution_result_mismatch", "Execution result correlation did not match", {
        humanMessage: "A stale or mismatched provider result was rejected.",
        category: "conflict",
      });
    }
    if (row.status !== "running") {
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
          this.brainContext.recordUnusedContext(
            recoveryContext,
            "The deterministic recovery policy did not consume memory to alter this retry, replan, or safe-stop decision.",
          );
        } catch (error) {
          // A failed required Brain hook must not leave an externally completed
          // action ghost-running. Close it through the normal supervisor path
          // as a policy denial, which deterministically blocks/safe-stops.
          recoveryContextFailure = error;
        }
      }
      const failureCategory = recoveryContextFailure
        ? "policy_denied" satisfies FailureCategory
        : result.failureCategory;
      const completed = await this.coordinator.completeAction({
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
        await this.replayContinuations(result.runId);
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
      if (!completionCommitted) {
        context.completing = false;
        this.actionHeartbeat(context);
      } else {
        this.actionContexts.delete(result.actionId);
      }
      if (error instanceof RuntimeCrashAfterCommit) throw error;
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
      lease = await heartbeat.stop();
      heartbeatStopped = true;
      lease = this.accountProviderUsage(lease, evaluated.usage, "success evaluation");
      inImmediateTransaction(this.database, () => {
        const target: "completed" | "failed" = evaluation.success ? "completed" : "failed";
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
              explanation: criterion.explanation,
              evidenceIds: [...criterion.evidenceIds],
            })),
            checkpointId: transition.checkpointId,
          },
        });
        this.recordTerminalEvaluationWithBrain({
          runId: run.id,
          terminalStatus: target,
          createdBy: "outcome-evaluator",
          outcome: evaluation,
          evaluationContextAlreadyRetrieved: true,
        });
      });
    } catch (error) {
      if (!heartbeatStopped) lease = await heartbeat.stop().catch(() => lease);
      const runtimeError = asRuntimeError(error);
      await this.safeStopPlanning(initialLease.runId, lease, runtimeError);
      throw runtimeError;
    }
  }

  private controlLease(runId: string): RunLeaseToken {
    this.ensureControlPlaneAuthority(runId);
    const context = [...this.actionContexts.values()].find((candidate) => candidate.action.runId === runId);
    if (context) return context.lease;
    const run = this.coordinator.getRun(runId);
    if (run.lease && run.lease.ownerId === this.workerId) return run.lease;
    return this.acquireWorkerRunLease(runId);
  }

  /**
   * Idempotent HTTP responses remain scoped to the run's current canonical
   * control plane. This read-only preflight intentionally does not acquire a
   * worker lease: a cached response is not a mutation and must not leave an
   * idle lease behind after pause or cancellation.
   */
  assertV2ControlPlaneOwnership(runId: string): void {
    const run = this.database.prepare(
      "SELECT control_plane FROM runs WHERE id = ?",
    ).get(runId) as { control_plane: "legacy" | "ti_scale" } | undefined;
    if (!run) throw new ControlPlaneLeaseError("run_not_found", `Run ${runId} does not exist`);
    if (run.control_plane !== "ti_scale") {
      throw new ControlPlaneLeaseError(
        "control_plane_mismatch",
        `Run ${runId} belongs to ${run.control_plane}, not ti_scale`,
      );
    }
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

  async approveGuidedDecision(decisionId: string, actorId: string, reason?: string): Promise<DurableAction> {
    const existingDecision = this.repository.getDecision(decisionId);
    if (existingDecision.status !== "pending") {
      const existing = this.database.prepare(`
        SELECT id FROM actions WHERE guided_decision_id = ? ORDER BY created_at LIMIT 1
      `).get(decisionId) as { id: string } | undefined;
      if (existingDecision.status === "approved" && existing) return new ActionRepository(this.database).get(existing.id);
      throw new CommandRuntimeError(409, "guided_decision_not_pending", "Only a pending Guided decision can be approved");
    }
    const now = this.timestamp();
    const decision = this.repository.requireCurrentPendingDecision(decisionId);
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
    if (Date.parse(decision.expiresAt) <= Date.parse(now)) {
      this.database.prepare("UPDATE guided_decisions SET status = 'expired' WHERE id = ? AND status = 'pending'").run(decisionId);
      throw new CommandRuntimeError(409, "guided_decision_expired", "The Guided decision expired");
    }
    inImmediateTransaction(this.database, () => {
      // Repeat the complete boundary under the write reservation so a plan,
      // step, or current-decision change cannot race the status mutation.
      this.repository.requireCurrentPendingDecision(decisionId);
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
    const decision = this.repository.getDecision(decisionId);
    const skipped = this.database.prepare(`
      SELECT ps.status AS step_status,
        EXISTS(
          SELECT 1 FROM events
          WHERE run_id = ? AND event_type = 'guided.decision_skipped'
            AND json_extract(payload_json, '$.decisionId') = ?
        ) AS has_skip_event
      FROM plan_steps ps WHERE ps.id = ?
    `).get(decision.runId, decision.id, decision.stepId) as {
      step_status: string;
      has_skip_event: number;
    } | undefined;
    if (
      decision.status === "cancelled" &&
      skipped?.step_status === "skipped" &&
      skipped.has_skip_event === 1
    ) {
      const projection = this.repository.getRunProjection(decision.runId);
      const pending = this.database.prepare(`
        SELECT id FROM guided_decisions
        WHERE run_id = ? AND status = 'pending' AND step_id = ?
        ORDER BY created_at DESC LIMIT 1
      `).get(decision.runId, projection.currentStepId) as { id: string } | undefined;
      return {
        decisionId,
        status: "cancelled",
        skippedStepId: decision.stepId,
        nextDecisionId: pending?.id ?? null,
        runId: decision.runId,
        runState: projection.status,
        nextAction: projection.nextAction,
        duplicate: true,
      };
    }
    if (decision.status !== "pending") {
      throw new CommandRuntimeError(409, "guided_decision_not_pending", "Only the current pending Guided decision can be skipped");
    }
    const projection = this.repository.getRunProjection(decision.runId);
    if (
      projection.journey !== "guided" ||
      projection.status !== "waiting_guided_decision" ||
      projection.currentStepId !== decision.stepId
    ) {
      throw new CommandRuntimeError(409, "guided_decision_not_current", "Decision is not the current represented Guided step", {
        humanMessage: "This decision is stale and no longer owns the Guided checkpoint.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and use the current decision card.",
      });
    }
    const representedIntent = this.repository.getStepIntent(decision.stepId);
    if (
      fingerprintAction(representedIntent).hash !== decision.actionFingerprint ||
      canonicalJson(representedIntent) !== canonicalJson(decision.requestedParameters)
    ) {
      throw new CommandRuntimeError(409, "guided_action_changed", "The represented Guided action changed", {
        humanMessage: "The decision no longer represents the exact current step and cannot be skipped from this card.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and decide on the newly represented step.",
      });
    }

    const lease = this.controlLease(decision.runId);
    const now = this.timestamp();
    const committed = inImmediateTransaction(this.database, () => {
      const runs = new RunRepository(this.database);
      const current = runs.get(decision.runId);
      runs.assertLease(current, lease, now);
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
    if (existingDecision.status === "rejected") return;
    if (existingDecision.status !== "pending") throw new CommandRuntimeError(409, "guided_decision_not_pending", "Only a pending decision can be rejected");
    const decision = this.repository.requireCurrentPendingDecision(decisionId);
    const lease = this.controlLease(decision.runId);
    inImmediateTransaction(this.database, () => {
      this.repository.requireCurrentPendingDecision(decisionId);
      const updated = this.database.prepare(`
        UPDATE guided_decisions SET status = 'rejected', decision_actor = ?, decision_reason = ?, decided_at = ?
        WHERE id = ? AND status = 'pending'
      `).run(actorId, normalizedReason, this.timestamp(), decisionId);
      if (updated.changes !== 1) {
        throw new CommandRuntimeError(409, "guided_decision_conflict", "Decision changed concurrently");
      }
      this.database.prepare(`
        UPDATE plan_steps SET status = 'recovering', updated_at = ? WHERE id = ?
      `).run(this.timestamp(), decision.stepId);
      this.coordinator.transitionRun({
        lease,
        to: "recovering",
        reason: `Operator rejected the Guided step: ${normalizedReason}`,
      });
      this.repository.appendAudit({
        missionId: decision.missionId, runId: decision.runId, actorId,
        action: "guided.decision_rejected", resourceType: "guided_decision",
        resourceId: decisionId, reason: normalizedReason, now: this.timestamp(),
      });
      this.continuations.enqueue({
        runId: decision.runId,
        kind: "resume_recovery_pending",
        sourceId: decisionId,
        payload: { decisionId },
        now: this.timestamp(),
      });
    });
    await this.replayContinuations(decision.runId, ["resume_recovery_pending"]);
  }

  async submitManualGuidedResult(
    decisionId: string,
    actorId: string,
    summary: string,
    interpretedEvidenceId?: string,
  ): Promise<ExecutionResultReceipt> {
    const normalized = validateExecutionResultSummary(summary);
    const decision = this.repository.getDecision(decisionId);
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
        SELECT id FROM evidence WHERE action_id = ? AND ${verifiedEvidenceSql("evidence")}
        ORDER BY created_at, id LIMIT 1
      `).get(existing.id) as { id: string } | undefined;
      const evidence = linked
        ? { id: linked.id }
        : this.repository.transaction(() => interpretedEvidenceId
          ? this.repository.promoteInterpretedGuidedEvidence({
              decision,
              actionId: existing.id,
              evidenceId: interpretedEvidenceId,
              actorId,
              now: this.timestamp(),
            })
          : this.repository.createManualEvidence({
              decision,
              actionId: existing.id,
              actorId,
              content: existing.result_summary!,
              now: this.timestamp(),
            }));
      const projection = this.repository.getRunProjection(decision.runId);
      return {
        accepted: true,
        duplicate: true,
        actionId: existing.id,
        runId: decision.runId,
        runState: projection.status,
        nextAction: projection.nextAction,
        evidenceIds: [evidence.id],
      };
    }
    if (decision.status !== "pending") throw new CommandRuntimeError(409, "guided_decision_not_pending", "Manual result requires the pending represented step");
    const lease = this.controlLease(decision.runId);
    const now = this.timestamp();
    const { accepted, runningLease } = inImmediateTransaction(this.database, () => {
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
      const created = this.repository.createManualAction({ decision, summary: normalized, now });
      const evidence = interpretedEvidenceId
        ? this.repository.promoteInterpretedGuidedEvidence({
            decision,
            actionId: created,
            evidenceId: interpretedEvidenceId,
            actorId,
            now,
          })
        : this.repository.createManualEvidence({
            decision,
            actionId: created,
            actorId,
            content: normalized,
            now,
          });
      this.repository.events.append({
        missionId: decision.missionId, runId: decision.runId, journey: "guided",
        eventType: "guided.manual_result_recorded", actorType: "operator", actorId,
        summary: interpretedEvidenceId
          ? "Operator accepted the interpreted evidence for the exact Guided action"
          : "Operator recorded the result for the exact Guided action",
        payload: {
          decisionId,
          actionId: created,
          actionFingerprint: decision.actionFingerprint,
          evidenceId: evidence.id,
          interpretedBeforeAdvance: Boolean(interpretedEvidenceId),
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
        runningLease: persisted.lease,
      };
    });
    // Manual work resolves the exact decision without dispatching a duplicate
    // provider action. Decision, immutable evidence, progress, state, event,
    // and checkpoint are committed atomically before execution advances.
    void runningLease;
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
    this.assertV2ControlPlaneOwnership(runId);
    if (this.recoverCurrentRunControlCommand(runId, "run.paused", commandId)) return;
    this.assertNoExecutionWork(runId, "pause");
    const lease = this.controlLease(runId);
    try {
      const current = this.coordinator.getRun(runId);
      if (current.run.state === "blocked") {
        throw new CommandRuntimeError(409, "run_blocked_not_paused", "Blocked run requires recovery rather than pause");
      }
      const now = this.timestamp();
      inImmediateTransaction(this.database, () => {
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
    this.assertV2ControlPlaneOwnership(runId);
    if (this.recoverCurrentRunControlCommand(runId, "run.resumed", commandId)) return;
    this.ensureControlPlaneAuthority(runId);
    try {
      inImmediateTransaction(this.database, () => {
        const current = this.assertExactResumeBoundary(
          runId,
          boundary,
          boundary.expectedRunVersion,
        );
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
      keepAuthorityForRecovery = target === "recovering";
      if (target === "recovering") void this.replayContinuations(runId, [continuationKind]);
    } finally {
      if (!keepAuthorityForRecovery) this.releaseControlPlaneAuthority(runId);
    }
  }

  async cancelRun(
    runId: string,
    actorId: string,
    reason: string,
    commandId?: string,
  ): Promise<void> {
    const normalized = validateReason(reason);
    this.assertV2ControlPlaneOwnership(runId);
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
        this.recordTerminalEvaluationWithBrain({
          runId,
          terminalStatus: "cancelled",
          createdBy: "run-supervisor",
        });
        await this.replayContinuations(runId, ["evaluation_pending"]);
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
        if (recovered.run.state === "cancelled") return;
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
    try {
      const result = await this.coordinator.cancelRun({ lease, reason: normalized, commandId });
      // At this boundary the coordinator has already closed every durable
      // execution child, including provider turns, in the same transaction as
      // the terminal checkpoint. Fault injection here proves no caller-level
      // cleanup window can leave ghost work beneath a cancelled run.
      this.crashAfterCommit("cancellation_terminal_before_runtime_cleanup", runId);
      inImmediateTransaction(this.database, () => {
        const now = this.timestamp();
        this.repository.cancelOpenWork(runId, actorId, normalized, now);
        this.database.prepare("UPDATE missions SET status = 'cancelled', updated_at = ? WHERE id = ?")
          .run(now, result.run.run.missionId);
        this.repository.appendAudit({
          missionId: result.run.run.missionId, runId, actorId, action: "run.cancelled",
          resourceType: "run", resourceId: runId, reason: normalized,
          details: {
            ...(commandId ? { commandId } : {}),
            committedRunVersion: result.run.run.stateVersion,
            checkpointId: result.checkpointId,
            checkpointEventSequence: result.eventSequence,
          },
          now,
        });
        this.recordTerminalEvaluationWithBrain({
          runId,
          terminalStatus: "cancelled",
          createdBy: "run-supervisor",
        });
      });
      await this.replayContinuations(runId, ["evaluation_pending"]);
    } finally {
      this.releaseControlPlaneAuthority(runId);
    }
  }
}

export function createMissionRuntime(options: MissionRuntimeOptions): MissionRuntimeEngine {
  return new MissionRuntimeEngine(options);
}

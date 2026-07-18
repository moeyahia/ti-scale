import type { SqliteDatabase } from "../db";
import { hashJson } from "../orchestration/serialization";
import { OperationsApiError, notFound } from "./errors";
import { lessonScopeSql, missionScopeSql, sensitivitySql } from "./scope";
import type {
  OperationsAccessPolicy,
  RecoveryActionAvailability,
  RunRecoveryProjection,
} from "./types";
import { OPERATIONS_SCHEMA_VERSION } from "./types";
import { isRecoveryAgentHeartbeatFresh, recoveryAgentHeartbeatMaxAge } from "./recoveryFreshness";
import { parseJson, sanitizeJson } from "./validation";
import {
  recoveryProviderAttestedAt,
  isRecoveryProviderHealthFresh,
  parseRecoveryProviderRouteBinding,
  recoveryProviderCircuitState,
  recoveryProviderHealthMaxAge,
  recoveryProviderRouteSettingKey,
} from "./recoveryProviderRoute";

type Row = Record<string, unknown>;

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function text(value: unknown): string {
  const safe = sanitizeJson(value);
  return typeof safe === "string" ? safe : String(safe ?? "");
}

function budgetLimit(budget: Record<string, unknown>, canonical: string, legacy: string): number | null {
  return finite(budget[canonical] ?? budget[legacy]);
}

function remaining(used: number, limit: number | null): number | null {
  return limit === null ? null : Math.max(0, limit - used);
}

function isTerminal(status: string): boolean {
  return status === "completed" || status === "failed" || status === "cancelled";
}

function recoveryActions(input: {
  status: string;
  ownedByV2: boolean;
  hasCheckpoint: boolean;
  safeCheckpointForResume: boolean;
  resumableDiagnosis: boolean;
  replanRemaining: number | null;
  hasFailedCurrentAction: boolean;
  canManageRecovery: boolean;
  reassignmentCandidates: number;
  providerCandidates: number;
}): RecoveryActionAvailability[] {
  const stopped = input.status === "blocked" || input.status === "waiting_guided_decision";
  const resumeAvailable = input.ownedByV2 && input.canManageRecovery && input.status === "blocked"
    && input.safeCheckpointForResume && input.resumableDiagnosis;
  const replanAvailable = input.ownedByV2 && input.canManageRecovery && input.status === "blocked" && input.hasCheckpoint
    && input.hasFailedCurrentAction && input.replanRemaining !== null && input.replanRemaining > 0;
  const reassignAvailable = input.ownedByV2 && input.canManageRecovery && stopped && input.reassignmentCandidates > 0;
  const providerAvailable = input.ownedByV2 && input.canManageRecovery && stopped && input.providerCandidates > 0;
  const ownershipReason = "This run belongs to the legacy control plane; use its owning interface and do not attempt concurrent control.";
  return [
    {
      kind: "resume",
      label: "Resume from checkpoint",
      available: resumeAvailable,
      reason: resumeAvailable
        ? "The verified zero-in-flight checkpoint can resume this operator pause or diagnosed recovery."
        : !input.ownedByV2 ? ownershipReason
          : !input.canManageRecovery ? "Recovery-management permission is required."
          : input.status !== "blocked"
          ? "Resume is supported only while the canonical run state is blocked."
          : !input.hasCheckpoint ? "No validated durable checkpoint is available for resume."
            : !input.safeCheckpointForResume
              ? "The latest checkpoint is stale, has in-flight work, or lacks a safe in-flight classification."
              : "The blocked state is not an operator pause or a diagnosed resumable recovery.",
      command: resumeAvailable ? "resume" : null,
    },
    {
      kind: "replan",
      label: "Request bounded replan",
      available: replanAvailable,
      reason: replanAvailable
        ? "One materially different in-scope strategy can be queued through the supervisor from this exact checkpoint."
        : !input.ownedByV2 ? ownershipReason
          : !input.canManageRecovery ? "Recovery-management permission is required."
          : input.replanRemaining === null ? "A finite canonical replan budget is required."
            : input.replanRemaining === 0 ? "The canonical replan budget is exhausted."
              : !input.hasCheckpoint ? "A validated durable checkpoint is required."
                : !input.hasFailedCurrentAction ? "No failed predecessor is linked to the exact current step."
                  : "A bounded replan may be requested only from a blocked run.",
      command: replanAvailable ? "replan" : null,
    },
    {
      kind: "reassign",
      label: "Reassign specialist",
      available: reassignAvailable,
      reason: reassignAvailable
        ? `${input.reassignmentCandidates} healthy declared-capable specialist option${input.reassignmentCandidates === 1 ? " is" : "s are"} available at this exact boundary.`
        : !input.ownedByV2 ? ownershipReason
          : !input.canManageRecovery ? "Recovery-management permission is required."
          : !stopped ? "Reassignment is allowed only while work is durably stopped."
            : "No healthy declared-capable in-policy replacement specialist is available.",
      command: reassignAvailable ? "reassign" : null,
    },
    {
      kind: "change_provider",
      label: "Change provider",
      available: providerAvailable,
      reason: providerAvailable
        ? `${input.providerCandidates} healthy callable provider route${input.providerCandidates === 1 ? " is" : "s are"} compatible with this exact boundary.`
        : !input.ownedByV2 ? ownershipReason
          : !input.canManageRecovery ? "Recovery-management permission is required."
          : !stopped ? "Provider routing is allowed only while work is durably stopped."
            : "No healthy callable provider satisfies the journey and budget enforcement boundary.",
      command: providerAvailable ? "change_provider" : null,
    },
    {
      kind: "terminate",
      label: "Terminate gracefully",
      available: input.ownedByV2 && !isTerminal(input.status),
      reason: isTerminal(input.status)
        ? "The run is already terminal."
        : !input.ownedByV2 ? ownershipReason
          : "The public cancellation command propagates to child work, releases leases, and writes a terminal checkpoint.",
      command: input.ownedByV2 && !isTerminal(input.status) ? "cancel" : null,
    },
  ];
}

/** Scope-enforcing, read-only recovery projection over canonical Ti-Scale state. */
export class RecoveryRepository {
  private readonly providerRouteIds: ReadonlySet<string>;
  private readonly clock: () => Date;
  private readonly providerHealthMaxAgeMs: number;
  private readonly agentHeartbeatMaxAgeMs: number;

  constructor(
    private readonly database: SqliteDatabase,
    options: {
      readonly providerRouteIds?: readonly string[];
      readonly clock?: () => Date;
      readonly providerHealthMaxAgeMs?: number;
      readonly agentHeartbeatMaxAgeMs?: number;
    } = {},
  ) {
    this.providerRouteIds = new Set(options.providerRouteIds ?? ["grok-acp"]);
    this.clock = options.clock ?? (() => new Date());
    this.providerHealthMaxAgeMs = recoveryProviderHealthMaxAge(options.providerHealthMaxAgeMs);
    this.agentHeartbeatMaxAgeMs = recoveryAgentHeartbeatMaxAge(options.agentHeartbeatMaxAgeMs);
  }

  getRunRecovery(runId: string, access: OperationsAccessPolicy): RunRecoveryProjection {
    const scope = missionScopeSql("m", access);
    const run = this.database.prepare(`
      SELECT r.*, m.name AS mission_name, m.engagement_id
      FROM runs r JOIN missions m ON m.id = r.mission_id
      WHERE r.id = ? AND ${scope.sql}
    `).get(runId, ...scope.params) as Row | undefined;
    if (!run) throw notFound("Run recovery record");
    if (run.journey !== "autonomous" && run.journey !== "guided") {
      throw new OperationsApiError(500, "invalid_recovery_journey", "Recovery journey is invalid", {
        category: "data_integrity",
      });
    }

    const failedRows = this.database.prepare(`
      SELECT id, status, intent_summary, result_summary, error_category,
        retry_count, ended_at
      FROM actions
      WHERE run_id = ? AND status IN ('failed', 'timed_out', 'denied')
      ORDER BY coalesce(ended_at, updated_at) DESC, id DESC LIMIT 12
    `).all(runId) as Row[];
    const failedActions = failedRows.map((item) => ({
      id: String(item.id),
      status: String(item.status),
      intentSummary: text(item.intent_summary),
      resultSummary: item.result_summary === null ? null : text(item.result_summary),
      errorCategory: item.error_category === null ? null : String(item.error_category),
      retryCount: Number(item.retry_count ?? 0),
      endedAt: item.ended_at === null ? null : String(item.ended_at),
    }));

    const eventRows = this.database.prepare(`
      SELECT id, event_type, summary, payload_json, occurred_at, sequence
      FROM events
      WHERE run_id = ? AND (
        event_type IN (
          'run.recovery_started', 'run.recovery_blocked', 'run.replan_started',
          'run.safe_stopped', 'run.autonomous_safe_stopped',
          'run.continuation_blocked', 'run.cancellation_failed',
          'action.pre_dispatch_denied', 'policy.denied'
        )
        OR (event_type = 'run.state_changed'
          AND json_extract(payload_json, '$.to') IN ('recovering', 'blocked', 'failed', 'waiting_guided_decision'))
        OR (event_type = 'action.completed'
          AND json_extract(payload_json, '$.directive') IN ('retry', 'recover', 'blocked', 'failed'))
      )
      ORDER BY sequence DESC LIMIT 12
    `).all(runId) as Row[];
    const eventEvidence = eventRows.map((item) => ({
      id: String(item.id),
      eventType: String(item.event_type),
      summary: text(item.summary),
      occurredAt: String(item.occurred_at),
      sequence: Number(item.sequence),
    }));

    const checkpointRow = this.database.prepare(`
      SELECT id, event_sequence, plan_version, state_json, state_hash,
        in_flight_classification, created_at
      FROM checkpoints WHERE run_id = ?
      ORDER BY event_sequence DESC, created_at DESC LIMIT 1
    `).get(runId) as Row | undefined;
    let checkpoint: RunRecoveryProjection["checkpoint"] = null;
    let checkpointStateIsCurrent = false;
    let checkpointHasRecoveryDirective = false;
    if (checkpointRow) {
      const state = record(parseJson(String(checkpointRow.state_json)));
      if (hashJson(state) !== checkpointRow.state_hash) {
        throw new OperationsApiError(500, "checkpoint_integrity_failed", "Recovery checkpoint integrity check failed", {
          humanMessage: "The latest recovery checkpoint failed its integrity check and cannot be used.",
          category: "data_integrity",
          remediation: "Keep the run stopped and inspect the immutable event history before attempting recovery.",
        });
      }
      const completed = Array.isArray(state.completedActionIds) ? state.completedActionIds : [];
      const inFlight = Array.isArray(state.inFlightActions) ? state.inFlightActions : [];
      const stateRun = record(state.run);
      const stateControl = record(state.control);
      const currentPlan = run.current_plan_id === null ? undefined : this.database.prepare(`
        SELECT version FROM plans WHERE id = ? AND run_id = ?
      `).get(run.current_plan_id, runId) as { version: number } | undefined;
      const latestSequence = this.database.prepare(`
        SELECT max(
          coalesce((SELECT last_sequence FROM run_event_sequences WHERE run_id = ?), 0),
          coalesce((SELECT max(sequence) FROM events WHERE run_id = ?), 0)
        ) AS latest_sequence
      `).get(runId, runId) as { latest_sequence: number };
      const trailingEvents = this.database.prepare(`
        SELECT event_type FROM events
        WHERE run_id = ? AND sequence > ?
        ORDER BY sequence
      `).all(runId, checkpointRow.event_sequence) as Array<{ event_type: string }>;
      const diagnosticTailOnly = trailingEvents.length > 0 && trailingEvents.every((event) =>
        event.event_type === "run.autonomous_safe_stopped" || event.event_type === "run.guided_blocked");
      checkpointStateIsCurrent =
        stateRun.id === runId &&
        stateRun.missionId === run.mission_id &&
        stateRun.journey === run.journey &&
        stateRun.state === run.status &&
        stateRun.stateVersion === run.version &&
        state.lastEventSequence === checkpointRow.event_sequence &&
        (latestSequence.latest_sequence === checkpointRow.event_sequence || (
          checkpointRow.in_flight_classification === null && inFlight.length === 0 && diagnosticTailOnly
        )) &&
        (run.current_plan_id === null
          ? checkpointRow.plan_version === null
          : currentPlan?.version === checkpointRow.plan_version);
      checkpointHasRecoveryDirective = ["retry", "replan"].includes(String(record(stateControl.recovery).kind ?? ""));
      checkpoint = {
        id: String(checkpointRow.id),
        eventSequence: Number(checkpointRow.event_sequence),
        planVersion: checkpointRow.plan_version === null ? null : Number(checkpointRow.plan_version),
        createdAt: String(checkpointRow.created_at),
        stateHash: String(checkpointRow.state_hash),
        inFlightClassification: checkpointRow.in_flight_classification === null
          ? null
          : String(checkpointRow.in_flight_classification),
        completedActionCount: completed.length,
        inFlightActions: inFlight.slice(0, 50).flatMap((value) => {
          const item = record(value);
          if (typeof item.id !== "string" || typeof item.status !== "string") return [];
          return [{
            id: item.id,
            status: item.status,
            idempotent: item.idempotent === true,
            destructive: item.destructive === true,
          }];
        }),
      };
    }

    const budget = record(parseJson(String(run.budget_json ?? "{}")));
    const retryCount = Number(run.retry_count ?? 0);
    const replanCount = Number(run.replan_count ?? 0);
    const retryLimit = budgetLimit(budget, "retries", "retryBudget");
    const replanLimit = budgetLimit(budget, "replans", "replanBudget");
    const retriesRemaining = remaining(retryCount, retryLimit);
    const replansRemaining = remaining(replanCount, replanLimit);
    const pendingDecision = this.database.prepare(`
      SELECT id, step_id, requested_action_fingerprint, rationale, risk_class, expires_at
      FROM guided_decisions
      WHERE run_id = ? AND status = 'pending' AND expires_at > ?
      ORDER BY created_at DESC, id DESC LIMIT 1
    `).get(runId, this.clock().toISOString()) as Row | undefined;
    const latestDiagnosis = this.database.prepare(`
      SELECT category, retryable, originating_component, automatic_recovery_json
      FROM failure_diagnoses
      WHERE run_id = ? AND state IN ('active', 'terminal')
      ORDER BY created_at DESC, id DESC LIMIT 1
    `).get(runId) as {
      category: string;
      retryable: number;
      originating_component: string;
      automatic_recovery_json: string;
    } | undefined;
    const eventCategory = eventRows.flatMap((event) => {
      const category = record(parseJson(String(event.payload_json ?? "{}"))).category;
      return typeof category === "string" && category.trim() ? [category] : [];
    })[0];
    const category = latestDiagnosis?.category
      ?? failedActions.find((item) => item.errorCategory)?.errorCategory
      ?? eventCategory
      ?? null;
    const status = String(run.status);
    const statusReason = run.status_reason === null ? null : text(run.status_reason);
    const operatorPaused = status === "blocked" && /paused by operator/iu.test(statusReason ?? "");
    const autonomousSafeStopRecorded = run.journey === "autonomous" && Boolean(this.database.prepare(`
      SELECT 1 FROM events
      WHERE run_id = ? AND event_type IN ('run.safe_stopped', 'run.autonomous_safe_stopped')
      LIMIT 1
    `).get(runId));
    const reason = statusReason
      ?? eventEvidence[0]?.summary
      ?? failedActions[0]?.resultSummary
      ?? "No diagnostic reason has been persisted.";
    const recoveryEvent = eventEvidence.some((item) => item.eventType.startsWith("run.recovery") || item.eventType === "run.replan_started");
    const recoveryRequired = ["blocked", "recovering", "failed"].includes(status)
      || (run.journey === "guided" && status === "waiting_guided_decision" && (failedActions.length > 0 || recoveryEvent));
    const resumableAutonomousPlanningRateLimit = run.journey === "autonomous"
      && status === "blocked"
      && run.current_plan_id === null
      && run.current_step_id === null
      && category === "rate_limit"
      && retriesRemaining !== null
      && retriesRemaining > 0
      && (latestDiagnosis?.originating_component === "command-runtime.planning-provider"
        || eventRows.some((event) => {
          if (event.event_type !== "run.autonomous_safe_stopped") return false;
          const payload = record(parseJson(String(event.payload_json ?? "{}")));
          return payload.category === "rate_limit"
            && typeof payload.code === "string"
            && payload.code.startsWith("mission_runtime_");
        }));

    const noExecutionImpact = status === "blocked" || isTerminal(status);
    const impact = {
      time: noExecutionImpact
        ? "No execution time is consumed while the run remains stopped."
        : `Automatic recovery may consume ${retriesRemaining ?? "an unreported number of"} remaining retries and ${replansRemaining ?? "an unreported number of"} remaining replans.`,
      cost: noExecutionImpact
        ? "No additional provider or tool cost is expected until execution resumes."
        : "Any retry or replan remains subject to the canonical token, cost, and tool-call budgets.",
      scope: run.journey === "autonomous"
        ? "The signed Autonomous contract remains unchanged; recovery cannot expand scope."
        : "The Guided exact-step boundary remains unchanged; a materially different action requires a new decision.",
    };

    let proposedRecovery: RunRecoveryProjection["proposedRecovery"];
    if (!recoveryRequired) {
      proposedRecovery = { kind: "none", summary: "No recovery is currently required.", basis: reason, impact };
    } else if (run.journey === "guided" && pendingDecision) {
      proposedRecovery = {
        kind: "guided_decision",
        summary: "Review the new bounded Guided action and make one deliberate decision.",
        basis: reason,
        impact,
      };
    } else if (status === "recovering") {
      proposedRecovery = {
        kind: "automatic_recovery",
        summary: run.journey === "autonomous"
          ? text(run.next_action_summary ?? "The supervisor is selecting an in-contract recovery path.")
          : "The supervisor is preparing a materially different Guided action; it must publish a decision before execution.",
        basis: reason,
        impact,
      };
    } else if (operatorPaused) {
      proposedRecovery = {
        kind: "operator_resume",
        summary: "Resume from the last durable checkpoint when the recorded pause condition is resolved.",
        basis: reason,
        impact,
      };
    } else if (resumableAutonomousPlanningRateLimit) {
      proposedRecovery = {
        kind: "operator_resume",
        summary: "The planning provider was temporarily rate-limited. A bounded planning retry remains available from the zero-in-flight checkpoint.",
        basis: reason,
        impact,
      };
    } else if (
      run.journey === "autonomous" && status === "blocked" && checkpointHasRecoveryDirective &&
      !autonomousSafeStopRecorded
    ) {
      proposedRecovery = {
        kind: "operator_resume",
        summary: "Resume the bounded in-contract recovery from its exact durable checkpoint.",
        basis: reason,
        impact,
      };
    } else if (run.journey === "autonomous" && (status === "blocked" || /contract|scope|policy/iu.test(statusReason ?? ""))) {
      proposedRecovery = {
        kind: "safe_stop",
        summary: "Keep the run safe-stopped unless an in-contract path becomes available through a new run or versioned contract amendment.",
        basis: reason,
        impact,
      };
    } else if (status === "failed") {
      proposedRecovery = {
        kind: "failed_safely",
        summary: "The run is terminal. Review the exception evidence before creating a new run.",
        basis: reason,
        impact,
      };
    } else {
      proposedRecovery = {
        kind: "operator_resume",
        summary: "Resolve the recorded blocker, then resume from the durable checkpoint.",
        basis: reason,
        impact,
      };
    }

    const visibility = sensitivitySql("mn.sensitivity", access);
    const memoryRows = this.database.prepare(`
      SELECT mn.id, mn.title, mn.lifecycle_status, mn.confidence
      FROM memory_nodes mn
      WHERE mn.node_type = 'failure'
        AND mn.lifecycle_status != 'forgotten'
        AND ${visibility.sql}
        AND (mn.mission_id = ? OR EXISTS (
          SELECT 1 FROM memory_sources ms WHERE ms.node_id = mn.id AND ms.run_id = ?
        ))
      ORDER BY mn.updated_at DESC, mn.id DESC LIMIT 8
    `).all(...visibility.params, run.mission_id, runId) as Row[];
    const lessonScope = lessonScopeSql("l", access);
    const lessonRows = this.database.prepare(`
      SELECT l.id, l.statement, l.status, l.confidence, l.failure_category
      FROM lessons l
      WHERE ${lessonScope.sql}
        AND (l.lesson_type = 'failed_attempt' OR l.failure_category IS NOT NULL)
        AND (
          l.mission_id = ?
          OR EXISTS (SELECT 1 FROM lesson_evidence le WHERE le.lesson_id = l.id AND le.run_id = ?)
          ${category ? "OR (l.failure_category = ? AND (l.engagement_id IS NULL OR l.engagement_id = ?))" : ""}
        )
      ORDER BY CASE l.status WHEN 'verified' THEN 0 ELSE 1 END, l.updated_at DESC, l.id DESC
      LIMIT 8
    `).all(
      ...lessonScope.params,
      run.mission_id,
      runId,
      ...(category ? [category, run.engagement_id] : []),
    ) as Row[];
    const failedAttemptMemories: RunRecoveryProjection["failedAttemptMemories"] = [
      ...memoryRows.map((item) => ({
        kind: "memory" as const,
        id: String(item.id),
        title: text(item.title),
        status: String(item.lifecycle_status),
        confidence: finite(item.confidence),
        failureCategory: null,
      })),
      ...lessonRows.map((item) => ({
        kind: "lesson" as const,
        id: String(item.id),
        title: text(item.statement),
        status: String(item.status),
        confidence: finite(item.confidence),
        failureCategory: item.failure_category === null ? null : String(item.failure_category),
      })),
    ];

    const boundaryRow = run.current_plan_id === null || run.current_step_id === null ? undefined : this.database.prepare(`
      SELECT p.id AS plan_id, p.version AS plan_version, ps.id AS step_id,
        ps.assigned_agent_id AS agent_id, ass.id AS assignment_id,
        ass.status AS assignment_status,
        json_extract(mc.value_json, '$.action.kind') AS action_kind
      FROM plans p
      JOIN plan_steps ps ON ps.plan_id = p.id AND ps.run_id = p.run_id
      JOIN assignments ass ON ass.run_id = p.run_id AND ass.step_id = ps.id
        AND ass.agent_id = ps.assigned_agent_id
      LEFT JOIN mission_constraints mc ON mc.source = ps.id AND mc.constraint_type = 'represented_action'
      WHERE p.run_id = ? AND p.id = ? AND p.status = 'active' AND ps.id = ?
      ORDER BY ass.created_at DESC, ass.id DESC LIMIT 1
    `).get(runId, run.current_plan_id, run.current_step_id) as Row | undefined;
    const boundary: RunRecoveryProjection["boundary"] = boundaryRow ? {
      planId: String(boundaryRow.plan_id),
      planVersion: Number(boundaryRow.plan_version),
      stepId: String(boundaryRow.step_id),
      assignmentId: String(boundaryRow.assignment_id),
      agentId: String(boundaryRow.agent_id),
      actionKind: boundaryRow.action_kind === null ? null : String(boundaryRow.action_kind),
    } : null;
    const stopped = status === "blocked" || status === "waiting_guided_decision";
    const inFlight = (this.database.prepare(`
      SELECT count(*) AS count FROM actions WHERE run_id = ? AND status IN ('queued', 'running')
    `).get(runId) as { count: number }).count > 0;

    const contractRow = run.contract_id === null ? undefined : this.database.prepare(`
      SELECT id, version, state, contract_hash, action_policy_json
      FROM mission_contracts WHERE id = ?
    `).get(run.contract_id) as Row | undefined;
    const contractPolicy = contractRow ? record(parseJson(String(contractRow.action_policy_json))) : {};
    const contractIsExact = run.journey === "guided" || Boolean(
      contractRow && contractRow.state === "confirmed" &&
      Number(contractRow.version) === Number(run.contract_version_bound) &&
      String(contractRow.contract_hash) === String(run.contract_hash_bound),
    );
    const signedSpecialists = new Set(
      (Array.isArray(contractPolicy.specialistAgentIds) ? contractPolicy.specialistAgentIds : [])
        .filter((value): value is string => typeof value === "string"),
    );
    const guidedBoundaryIsExact = run.journey === "autonomous" || Boolean(
      pendingDecision && boundary && String(pendingDecision.step_id) === boundary.stepId,
    );
    const hasRetryableCurrentAction = Boolean(boundary && this.database.prepare(`
      SELECT 1 FROM actions WHERE run_id = ? AND step_id = ?
        AND status IN ('failed', 'timed_out') LIMIT 1
    `).get(runId, boundary.stepId));

    const candidateRows = boundary && stopped && !inFlight && contractIsExact && guidedBoundaryIsExact &&
      (run.journey === "guided" || hasRetryableCurrentAction)
      ? this.database.prepare(`
          SELECT candidate.id AS agent_id, candidate.display_name, candidate.status,
            candidate.role, candidate.last_heartbeat_at, target_cap.capability
          FROM agents candidate
          JOIN agent_capabilities target_cap ON target_cap.agent_id = candidate.id
            AND target_cap.enabled = 1
            AND target_cap.source = 'live-route-attestation'
            AND json_extract(target_cap.metadata_json, '$.validUntil') >= ?
          JOIN agent_capabilities current_cap ON current_cap.agent_id = ?
            AND current_cap.capability = target_cap.capability AND current_cap.enabled = 1
          WHERE candidate.id != ? AND candidate.status = 'available'
          ORDER BY candidate.display_name, candidate.id, target_cap.capability
        `).all(this.clock().toISOString(), boundary.agentId, boundary.agentId) as Row[]
      : [];
    const candidateMap = new Map<string, {
      agentId: string; displayName: string; status: "available"; capabilities: string[];
    }>();
    for (const candidate of candidateRows) {
      const agentId = String(candidate.agent_id);
      if (/commander/iu.test(String(candidate.role)) || /ti-scale/iu.test(agentId)) continue;
      if (!isRecoveryAgentHeartbeatFresh(
        candidate.last_heartbeat_at === null ? null : String(candidate.last_heartbeat_at),
        this.clock().toISOString(),
        this.agentHeartbeatMaxAgeMs,
      )) continue;
      if (run.journey === "autonomous" && !signedSpecialists.has(agentId)) continue;
      const current = candidateMap.get(agentId) ?? {
        agentId,
        displayName: text(candidate.display_name),
        status: "available" as const,
        capabilities: [],
      };
      const capability = String(candidate.capability);
      if (!current.capabilities.includes(capability)) current.capabilities.push(capability);
      candidateMap.set(agentId, current);
    }
    const reassignmentCandidates = [...candidateMap.values()];

    const routeSetting = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(recoveryProviderRouteSettingKey(runId)) as { value_json: string } | undefined;
    const selectedRoute = routeSetting
      ? parseRecoveryProviderRouteBinding(record(parseJson(routeSetting.value_json)))
      : null;
    const currentRouteId = selectedRoute && boundary &&
      selectedRoute.stepId === boundary.stepId && selectedRoute.assignmentId === boundary.assignmentId
      ? selectedRoute.providerId
      : "grok-acp";
    const tokenBudget = budgetLimit(budget, "providerTokens", "tokenBudget") ?? 0;
    const costBudget = budgetLimit(budget, "estimatedCost", "costBudget") ?? 0;
    const providerCandidates: Array<RunRecoveryProjection["providerCandidates"][number]> = [];
    if (
      boundary && stopped && !inFlight && contractIsExact && guidedBoundaryIsExact &&
      (run.journey === "guided" || hasRetryableCurrentAction) &&
      (boundary.actionKind === "provider_turn" || boundary.actionKind === "delegation")
    ) {
      for (const providerId of this.providerRouteIds) {
        if (providerId === currentRouteId) continue;
        const health = this.database.prepare(`
          SELECT status, metrics_json, captured_at FROM health_snapshots
          WHERE component_type = 'provider' AND component_id = ?
          ORDER BY captured_at DESC, id DESC LIMIT 1
        `).get(providerId) as Row | undefined;
        const metrics = health ? record(parseJson(String(health.metrics_json))) : {};
        if (
          health?.status !== "healthy" ||
          !isRecoveryProviderHealthFresh(
            recoveryProviderAttestedAt(metrics),
            this.clock().toISOString(),
            this.providerHealthMaxAgeMs,
          ) ||
          recoveryProviderCircuitState(this.database, runId, providerId) !== "closed" ||
          metrics.authenticated !== true ||
          metrics.callable !== true ||
          (tokenBudget > 0 && metrics.reportsExactTokenUsage !== true) ||
          (costBudget > 0 && metrics.reportsExactCostUsage !== true) ||
          (run.journey === "autonomous" && (
            contractPolicy.providerPolicy !== "automatic_enforcing_only" ||
            metrics.enforcesAutonomousBoundary !== true
          )) ||
          (run.journey === "guided" && metrics.supportsGuided !== true)
        ) continue;
        providerCandidates.push({
          providerId,
          status: "healthy",
          supportsGuided: metrics.supportsGuided === true,
          enforcesAutonomousBoundary: metrics.enforcesAutonomousBoundary === true,
          reportsExactTokenUsage: metrics.reportsExactTokenUsage === true,
          reportsExactCostUsage: metrics.reportsExactCostUsage === true,
        });
      }
    }
    const hasFailedCurrentAction = Boolean(boundary && this.database.prepare(`
      SELECT 1 FROM actions WHERE run_id = ? AND step_id = ?
        AND status IN ('failed', 'timed_out', 'denied') LIMIT 1
    `).get(runId, boundary.stepId));
    const acceptableInFlightClassification = checkpoint?.inFlightClassification === "safe_no_in_flight_action"
      || checkpoint?.inFlightClassification === "resume_idempotently"
      || (checkpoint?.inFlightClassification === null
        && checkpoint.inFlightActions.length === 0 && !inFlight);
    const safeCheckpointForResume = Boolean(
      checkpoint && checkpointStateIsCurrent && checkpoint.inFlightActions.length === 0 && !inFlight
      && acceptableInFlightClassification,
    );
    const resumableDiagnosis = (!autonomousSafeStopRecorded || resumableAutonomousPlanningRateLimit)
      && proposedRecovery.kind !== "safe_stop"
      && proposedRecovery.kind !== "failed_safely"
      && (resumableAutonomousPlanningRateLimit || operatorPaused || checkpointHasRecoveryDirective || (
        run.journey === "guided" && recoveryRequired &&
        (failedActions.length > 0 || recoveryEvent || pendingDecision !== undefined)
      ));

    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      recoveryRequired,
      run: {
        id: String(run.id),
        missionId: String(run.mission_id),
        missionName: text(run.mission_name),
        journey: run.journey,
        status,
        version: Number(run.version),
        statusReason,
        currentStepId: run.current_step_id === null ? null : String(run.current_step_id),
        currentOwnerId: run.current_owner_id === null ? null : String(run.current_owner_id),
        nextAction: run.next_action_summary === null ? null : text(run.next_action_summary),
        leaseExpiresAt: run.lease_expires_at === null ? null : String(run.lease_expires_at),
      },
      detection: {
        summary: reason,
        category,
        evidence: eventEvidence,
        failedActions,
      },
      boundary,
      reassignmentCandidates,
      providerCandidates,
      checkpoint,
      attempts: {
        retryCount,
        retryLimit,
        retriesRemaining,
        replanCount,
        replanLimit,
        replansRemaining,
      },
      proposedRecovery,
      guidedDecision: pendingDecision ? {
        id: String(pendingDecision.id),
        stepId: String(pendingDecision.step_id),
        actionFingerprint: String(pendingDecision.requested_action_fingerprint),
        rationale: text(pendingDecision.rationale),
        riskClass: String(pendingDecision.risk_class),
        expiresAt: String(pendingDecision.expires_at),
      } : null,
      failedAttemptMemories,
      actions: recoveryActions({
        status,
        ownedByV2: run.control_plane === "ti_scale",
        hasCheckpoint: checkpoint !== null,
        safeCheckpointForResume,
        resumableDiagnosis,
        replanRemaining: replansRemaining,
        hasFailedCurrentAction,
        canManageRecovery: access.canManageRecovery === true,
        reassignmentCandidates: reassignmentCandidates.length,
        providerCandidates: providerCandidates.length,
      }),
    };
  }
}

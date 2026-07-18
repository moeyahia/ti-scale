import { createHash, randomUUID } from "node:crypto";
import { RuntimeContinuationRepository } from "../command-runtime/RuntimeContinuationRepository";
import { RuntimeRepository } from "../command-runtime/RuntimeRepository";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import { EventRepository, type JsonValue } from "../events";
import { ActionRepository, CheckpointRepository, RunRepository } from "../orchestration";
import { canonicalJson, hashJson, parseObject } from "../orchestration/serialization";
import { RunSupervisor } from "../supervisor";
import { conflict, forbidden, notFound, OperationsApiError } from "./errors";
import { missionScopeSql } from "./scope";
import type {
  OperationsAccessPolicy,
  OperationsActor,
  RecoveryMutationProjection,
} from "./types";
import { OPERATIONS_SCHEMA_VERSION } from "./types";
import { isRecoveryAgentHeartbeatFresh, recoveryAgentHeartbeatMaxAge } from "./recoveryFreshness";
import {
  recoveryProviderAttestedAt,
  isRecoveryProviderHealthFresh,
  RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION,
  parseRecoveryProviderRouteBinding,
  parseRecoveryProviderRouteTombstone,
  recoveryProviderCircuitState,
  recoveryProviderHealthMaxAge,
  recoveryProviderRouteSettingKey,
  type RecoveryProviderRouteBinding,
} from "./recoveryProviderRoute";

type Row = Record<string, unknown>;

interface RecoveryContextRow {
  readonly run_id: string;
  readonly mission_id: string;
  readonly control_plane: "legacy" | "ti_scale";
  readonly journey: "autonomous" | "guided";
  readonly run_status: string;
  readonly run_version: number;
  readonly contract_id: string | null;
  readonly contract_version_bound: number | null;
  readonly contract_hash_bound: string | null;
  readonly budget_json: string;
  readonly replan_count: number;
  readonly plan_id: string;
  readonly plan_version: number;
  readonly plan_status: string;
  readonly strategy_summary: string;
  readonly step_id: string;
  readonly step_status: string;
  readonly step_action_class: string | null;
  readonly step_agent_id: string | null;
  readonly action_kind: string | null;
  readonly assignment_id: string;
  readonly assignment_status: string;
  readonly assignment_agent_id: string;
}

interface ExactRecoveryExpectation {
  readonly expectedRunVersion: number;
  readonly expectedPlanId: string;
  readonly expectedPlanVersion: number;
  readonly expectedStepId: string;
  readonly expectedAssignmentId: string;
  readonly expectedCheckpointId: string;
  readonly expectedCheckpointStateHash: string;
  readonly expectedCheckpointEventSequence: number;
}

interface VerifiedRecoveryCheckpoint {
  readonly id: string;
  readonly stateHash: string;
  readonly eventSequence: number;
  readonly inFlightClassification: string | null;
}

interface GuidedRecoveryDecisionBoundary {
  readonly id: string;
  readonly fingerprint: string;
  readonly expiresAt: string;
}

interface IdempotencyRecord {
  readonly requestHash: string;
  readonly response: RecoveryMutationProjection;
}

function settingDigest(prefix: string, value: string): string {
  return `${prefix}.${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function idempotencySettingKey(key: string): string {
  return settingDigest("ti_scale.recovery.idempotency", key);
}

function finiteLimit(source: Record<string, unknown>, canonical: string, legacy: string): number | null {
  const value = source[canonical] ?? source[legacy];
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function normalizedStrategy(value: string): string {
  return value.normalize("NFKC").trim().replace(/\s+/gu, " ").toLocaleLowerCase("en-US");
}

function strategyFingerprint(value: string): string {
  return createHash("sha256").update(normalizedStrategy(value), "utf8").digest("hex");
}

function asJson(value: unknown): Record<string, unknown> {
  if (typeof value !== "string") return {};
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function assertManager(actor: OperationsActor, access: OperationsAccessPolicy): void {
  if ((actor.type !== "operator" && actor.type !== "admin") || access.canManageRecovery !== true) {
    throw forbidden(
      "Only an authorized operator or administrator may mutate run recovery state.",
      "Use an operations identity with explicit recovery-management permission.",
    );
  }
}

function assertV2ControlPlane(row: RecoveryContextRow): void {
  if (row.control_plane === "ti_scale") return;
  throw new OperationsApiError(409, "control_plane_mismatch", "Run belongs to another control plane", {
    humanMessage: "This run belongs to the legacy control plane and Ti-Scale refused to mutate it.",
    category: "conflict",
    remediation: "Open the run through its owning control plane; do not attempt concurrent control.",
  });
}

function assertExpected(row: RecoveryContextRow, expected: ExactRecoveryExpectation): void {
  if (
    row.run_version !== expected.expectedRunVersion ||
    row.plan_id !== expected.expectedPlanId || row.plan_version !== expected.expectedPlanVersion ||
    row.step_id !== expected.expectedStepId || row.assignment_id !== expected.expectedAssignmentId ||
    row.plan_status !== "active" || row.step_agent_id !== row.assignment_agent_id
  ) {
    throw conflict(
      "The run, plan, step, or assignment changed before the recovery mutation could be applied.",
      "Refresh the Recovery Panel and retry only against the current exact work boundary.",
    );
  }
}

function assertNoInFlight(database: SqliteDatabase, runId: string): void {
  const active = database.prepare(`
    SELECT id FROM actions WHERE run_id = ? AND status IN ('queued', 'running') LIMIT 1
  `).get(runId) as { id: string } | undefined;
  if (active) {
    throw conflict(
      "Recovery ownership cannot change while an action is in flight.",
      "Wait for the action to reach a durable terminal state or cancel the run.",
    );
  }
}

export class RecoveryMutationRepository {
  private readonly events: EventRepository;
  private readonly runs: RunRepository;
  private readonly actions: ActionRepository;
  private readonly checkpoints: CheckpointRepository;
  private readonly continuations: RuntimeContinuationRepository;
  private readonly runtime: RuntimeRepository;
  private readonly supervisor = new RunSupervisor();
  private readonly clock: () => Date;
  private readonly providerRouteIds: ReadonlySet<string>;
  private readonly providerHealthMaxAgeMs: number;
  private readonly agentHeartbeatMaxAgeMs: number;

  constructor(
    private readonly database: SqliteDatabase,
    options: {
      readonly clock?: () => Date;
      readonly providerRouteIds?: readonly string[];
      readonly providerHealthMaxAgeMs?: number;
      readonly agentHeartbeatMaxAgeMs?: number;
    } = {},
  ) {
    this.events = new EventRepository(database);
    this.runs = new RunRepository(database);
    this.actions = new ActionRepository(database);
    this.checkpoints = new CheckpointRepository(database, this.actions);
    this.continuations = new RuntimeContinuationRepository(database);
    this.runtime = new RuntimeRepository(database);
    this.clock = options.clock ?? (() => new Date());
    this.providerRouteIds = new Set(options.providerRouteIds ?? ["grok-acp"]);
    this.providerHealthMaxAgeMs = recoveryProviderHealthMaxAge(options.providerHealthMaxAgeMs);
    this.agentHeartbeatMaxAgeMs = recoveryAgentHeartbeatMaxAge(options.agentHeartbeatMaxAgeMs);
  }

  requestReplan(
    runId: string,
    input: ExactRecoveryExpectation & { readonly strategyReason: string },
    idempotencyKey: string,
    actor: OperationsActor,
    access: OperationsAccessPolicy,
  ): RecoveryMutationProjection {
    assertManager(actor, access);
    const requestHash = hashJson({ kind: "replan", runId, ...input, actorId: actor.id });
    return inImmediateTransaction(this.database, () => {
      const row = this.context(runId, access);
      assertV2ControlPlane(row);
      const replay = this.idempotentReplay(idempotencyKey, requestHash, row);
      if (replay) return replay;
      assertExpected(row, input);
      const sourceCheckpoint = this.assertExactCheckpoint(row, input);
      if (row.run_status !== "blocked") {
        throw conflict("A deliberate recovery replan may start only from a blocked durable checkpoint.");
      }
      if (!new Set(["blocked", "failed", "waiting_guided_decision", "recovering", "ready"]).has(row.step_status)) {
        throw conflict("The current step is not at a recoverable durable boundary.");
      }
      assertNoInFlight(this.database, runId);
      const budget = asJson(row.budget_json);
      const limit = finiteLimit(budget, "replans", "replanBudget");
      if (limit === null) {
        throw new OperationsApiError(409, "replan_budget_unverified", "A finite canonical replan budget is required", {
          humanMessage: "The run has no verifiable replan budget, so operator-triggered replanning remains disabled.",
          category: "policy_denied",
        });
      }
      if (row.replan_count >= limit) {
        throw new OperationsApiError(409, "replan_budget_exhausted", "The canonical replan budget is exhausted", {
          humanMessage: "No bounded replans remain for this run.",
          category: "policy_denied",
        });
      }
      const proposed = normalizedStrategy(input.strategyReason);
      if (proposed.length < 12 || proposed === normalizedStrategy(row.strategy_summary)) {
        throw new OperationsApiError(409, "equivalent_replan", "The requested strategy is not materially different", {
          humanMessage: "Describe a materially different in-scope strategy or new fact before consuming a replan.",
          category: "deterministic_tool_error",
        });
      }
      const fingerprint = strategyFingerprint(input.strategyReason);
      const repeated = this.database.prepare(`
        SELECT id FROM events WHERE run_id = ? AND event_type = 'run.operator_replan_requested'
          AND json_extract(payload_json, '$.strategyFingerprint') = ? LIMIT 1
      `).get(runId, fingerprint) as { id: string } | undefined;
      if (repeated) {
        throw new OperationsApiError(409, "equivalent_replan", "This recovery strategy was already requested", {
          humanMessage: "The same recovery strategy was already attempted. Add materially new facts or choose another strategy.",
          category: "deterministic_tool_error",
        });
      }
      const failed = this.database.prepare(`
        SELECT id FROM actions WHERE run_id = ? AND step_id = ?
          AND status IN ('failed', 'timed_out', 'denied')
        ORDER BY coalesce(ended_at, updated_at) DESC, id DESC LIMIT 1
      `).get(runId, row.step_id) as { id: string } | undefined;
      if (!failed) {
        throw conflict(
          "A bounded recovery replan requires one canonical failed predecessor on the current step.",
          "Use reassignment for an unstarted step, or preserve the failed action before replanning.",
        );
      }
      this.assertJourneyPolicy(row, "replan");

      const now = this.clock().toISOString();
      const lease = this.runs.acquire(runId, `recovery:${actor.id}:${randomUUID()}`, now, 30_000);
      const acquired = this.withRestoredControl(runId);
      this.runs.assertLease(acquired, lease, now);
      const transition = this.supervisor.transition(acquired.run, "recovering", {
        reason: `Operator requested a materially different bounded replan: ${input.strategyReason}`,
        now,
      });
      const persisted = this.runs.persistMutation({
        current: acquired,
        nextRun: transition.run,
        control: {
          ...acquired.control,
          recovery: {
            kind: "replan",
            failedActionId: failed.id,
            notBefore: now,
            reason: input.strategyReason,
          },
        },
        now,
        lease: "clear",
      });
      this.database.prepare(`
        UPDATE plan_steps SET status = 'recovering', updated_at = ?
        WHERE id = ? AND run_id = ? AND status IN ('blocked', 'failed', 'waiting_guided_decision', 'ready', 'recovering')
      `).run(now, row.step_id, runId);
      this.database.prepare(`
        UPDATE assignments SET status = 'blocked', lease_owner = NULL,
          lease_acquired_at = NULL, last_heartbeat_at = NULL, lease_expires_at = NULL, updated_at = ?
        WHERE id = ? AND run_id = ? AND status IN ('queued', 'active', 'blocked', 'failed')
      `).run(now, row.assignment_id, runId);
      if (row.journey === "guided") {
        this.database.prepare(`
          UPDATE guided_decisions SET status = 'cancelled', decision_actor = ?,
            decision_reason = ?, decided_at = ?
          WHERE run_id = ? AND status = 'pending'
        `).run(actor.id, "Superseded by an explicit bounded recovery replan", now, runId);
      }
      this.database.prepare("UPDATE missions SET status = 'active', updated_at = ? WHERE id = ?")
        .run(now, row.mission_id);
      for (const transitionEvent of transition.events) {
        this.events.append({
          missionId: row.mission_id,
          runId,
          journey: row.journey,
          eventType: transitionEvent.type,
          actorType: "operator",
          actorId: actor.id,
          summary: transitionEvent.summary,
          payload: JSON.parse(canonicalJson(transitionEvent.payload)) as JsonValue,
        });
      }
      const event = this.events.append({
        missionId: row.mission_id,
        runId,
        journey: row.journey,
        eventType: "run.operator_replan_requested",
        actorType: "operator",
        actorId: actor.id,
        summary: "Operator requested one materially different bounded recovery replan",
        payload: {
          from: row.run_status,
          to: "recovering",
          planId: row.plan_id,
          planVersion: row.plan_version,
          stepId: row.step_id,
          assignmentId: row.assignment_id,
          sourceCheckpointId: sourceCheckpoint.id,
          sourceCheckpointStateHash: sourceCheckpoint.stateHash,
          sourceCheckpointEventSequence: sourceCheckpoint.eventSequence,
          failedActionId: failed.id,
          strategyFingerprint: fingerprint,
          remainingBeforeRequest: Math.max(0, limit - row.replan_count),
        },
      });
      const checkpoint = this.checkpoints.create({ run: persisted, eventSequence: event.sequence, now });
      const continuation = this.continuations.enqueue({
        runId,
        kind: "resume_recovery_pending",
        sourceId: event.id,
        payload: { actionId: failed.id },
        now,
      });
      this.appendAudit({
        row, actor, action: "run.replan_requested", reason: input.strategyReason,
        details: {
          eventId: event.id,
          checkpointId: checkpoint.id,
          continuationId: continuation.id,
          strategyFingerprint: fingerprint,
          sourceCheckpoint,
        },
        now,
      });
      const response = this.response("replan", persisted.run.stateVersion, row, {
        eventId: event.id,
        checkpointId: checkpoint.id,
        continuationId: continuation.id,
      });
      this.saveIdempotency(idempotencyKey, requestHash, response, actor.id, now);
      return response;
    });
  }

  reassignSpecialist(
    runId: string,
    input: ExactRecoveryExpectation & {
      readonly targetAgentId: string;
      readonly capability: string;
      readonly guidedDecisionId?: string;
      readonly expectedDecisionFingerprint?: string;
      readonly reason: string;
    },
    idempotencyKey: string,
    actor: OperationsActor,
    access: OperationsAccessPolicy,
  ): RecoveryMutationProjection {
    assertManager(actor, access);
    const requestHash = hashJson({ kind: "reassign", runId, ...input, actorId: actor.id });
    return inImmediateTransaction(this.database, () => {
      const row = this.context(runId, access);
      assertV2ControlPlane(row);
      const replay = this.idempotentReplay(idempotencyKey, requestHash, row);
      if (replay) return replay;
      assertExpected(row, input);
      const sourceCheckpoint = this.assertExactCheckpoint(row, input);
      if (!new Set(["blocked", "waiting_guided_decision"]).has(row.run_status)) {
        throw conflict("Specialist reassignment requires a blocked or waiting Guided checkpoint.");
      }
      if (!new Set(["queued", "blocked", "active"]).has(row.assignment_status)) {
        throw conflict("The current assignment is already terminal and cannot be reassigned in place.");
      }
      assertNoInFlight(this.database, runId);
      const retryPredecessor = row.journey === "autonomous"
        ? this.autonomousRetryPredecessor(runId, row.step_id)
        : null;
      if (row.journey === "autonomous" && !retryPredecessor) {
        throw new OperationsApiError(409, "recovery_retry_predecessor_missing", "Autonomous reassignment has no retryable predecessor", {
          humanMessage: "Autonomous reassignment can resume the exact step only after a canonical failed or timed-out predecessor is retained.",
          category: "policy_denied",
        });
      }
      if (row.assignment_agent_id === input.targetAgentId) {
        throw conflict("The requested specialist already owns this exact assignment.");
      }
      const candidate = this.database.prepare(`
        SELECT a.id, a.role, a.status, a.last_heartbeat_at
        FROM agents a
        JOIN agent_capabilities target_cap ON target_cap.agent_id = a.id
          AND target_cap.capability = ? AND target_cap.enabled = 1
          AND target_cap.source = 'live-route-attestation'
          AND json_extract(target_cap.metadata_json, '$.validUntil') >= ?
        JOIN agent_capabilities current_cap ON current_cap.agent_id = ?
          AND current_cap.capability = target_cap.capability AND current_cap.enabled = 1
        WHERE a.id = ?
      `).get(input.capability, this.clock().toISOString(), row.assignment_agent_id, input.targetAgentId) as {
        id: string; role: string; status: string; last_heartbeat_at: string | null;
      } | undefined;
      if (
        !candidate || candidate.status !== "available" ||
        !isRecoveryAgentHeartbeatFresh(
          candidate.last_heartbeat_at,
          this.clock().toISOString(),
          this.agentHeartbeatMaxAgeMs,
        ) ||
        /commander/iu.test(candidate.role) || /ti-scale/iu.test(candidate.id)
      ) {
        throw new OperationsApiError(409, "reassignment_specialist_incompatible", "The replacement specialist is not healthy and declared capable", {
          humanMessage: "Choose an available non-commander specialist that shares the selected declared capability.",
          category: "policy_denied",
        });
      }
      const guidedDecision = this.assertJourneyPolicy(row, "reassign", input);
      const now = this.clock().toISOString();
      const previousProviderRoute = this.providerRouteBinding(runId);
      const invalidatedProviderId = previousProviderRoute?.stepId === row.step_id &&
        previousProviderRoute.assignmentId === row.assignment_id
        ? previousProviderRoute.providerId
        : null;
      const invalidatedProviderRouteVersion = invalidatedProviderId ? previousProviderRoute!.version : null;
      const replacementAssignmentId = `assignment_${randomUUID()}`;
      const closed = this.database.prepare(`
        UPDATE assignments SET status = 'cancelled', lease_owner = NULL,
          lease_acquired_at = NULL, last_heartbeat_at = NULL, lease_expires_at = NULL,
          ended_at = COALESCE(ended_at, ?), updated_at = ?
        WHERE id = ? AND run_id = ? AND step_id = ? AND agent_id = ?
          AND status IN ('queued', 'active', 'blocked')
      `).run(now, now, row.assignment_id, runId, row.step_id, row.assignment_agent_id);
      const replacement = this.database.prepare(`
        INSERT INTO assignments (
          id, run_id, step_id, agent_id, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'queued', ?, ?)
      `).run(replacementAssignmentId, runId, row.step_id, input.targetAgentId, now, now);
      const step = this.database.prepare(`
        UPDATE plan_steps SET assigned_agent_id = ?, status = ?, updated_at = ?
        WHERE id = ? AND plan_id = ? AND run_id = ? AND assigned_agent_id = ?
      `).run(
        input.targetAgentId,
        row.journey === "guided" ? "waiting_guided_decision" : "ready",
        now,
        row.step_id,
        row.plan_id,
        runId,
        row.assignment_agent_id,
      );
      const run = this.database.prepare(`
        UPDATE runs SET current_owner_id = ?, next_action_summary = ?,
          version = version + 1, updated_at = ?
        WHERE id = ? AND version = ? AND current_plan_id = ? AND current_step_id = ?
      `).run(
        input.targetAgentId,
        invalidatedProviderId
          ? `Select a provider again for the replacement assignment before resuming with ${input.targetAgentId}`
          : row.journey === "guided"
          ? `Review the exact Guided step now assigned to ${input.targetAgentId}`
          : `Resume the current in-contract step with ${input.targetAgentId}`,
        now,
        runId,
        row.run_version,
        row.plan_id,
        row.step_id,
      );
      if (closed.changes !== 1 || replacement.changes !== 1 || step.changes !== 1 || run.changes !== 1) {
        throw conflict("The current recovery ownership changed during reassignment.");
      }
      if (row.journey === "guided" && !guidedDecision) {
        throw conflict(
          "The represented Guided decision changed during reassignment.",
          "Refresh the Recovery Panel and retry only against the current exact decision.",
        );
      }
      if (invalidatedProviderId && previousProviderRoute) {
        this.database.prepare(`
          UPDATE settings SET value_json = ?, version = version + 1,
            updated_by = ?, updated_at = ?
          WHERE key = ?
        `).run(canonicalJson({
          schemaVersion: RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION,
          invalidated: true,
          runId,
          previousProviderId: previousProviderRoute.providerId,
          previousVersion: previousProviderRoute.version,
          planId: previousProviderRoute.planId,
          stepId: previousProviderRoute.stepId,
          assignmentId: previousProviderRoute.assignmentId,
          reason: "assignment_changed",
          invalidatedBy: actor.id,
          invalidatedAt: now,
        }), actor.id, now, recoveryProviderRouteSettingKey(runId));
      }
      const event = this.events.append({
        missionId: row.mission_id,
        runId,
        journey: row.journey,
        eventType: "run.specialist_reassigned",
        actorType: "operator",
        actorId: actor.id,
        summary: `Current recovery step reassigned to the declared-capable specialist ${input.targetAgentId}`,
        payload: {
          planId: row.plan_id,
          planVersion: row.plan_version,
          stepId: row.step_id,
          previousAssignmentId: row.assignment_id,
          replacementAssignmentId,
          previousAgentId: row.assignment_agent_id,
          targetAgentId: input.targetAgentId,
          capability: input.capability,
          sourceCheckpointId: sourceCheckpoint.id,
          sourceCheckpointStateHash: sourceCheckpoint.stateHash,
          sourceCheckpointEventSequence: sourceCheckpoint.eventSequence,
          invalidatedProviderId,
          invalidatedProviderRouteVersion,
          executionStarted: false,
          previousGuidedDecisionId: guidedDecision?.id ?? null,
        },
      });
      let replacementGuidedDecisionId: string | null = null;
      if (guidedDecision) {
        const cancelled = this.database.prepare(`
          UPDATE guided_decisions
          SET status = 'cancelled', decision_actor = ?, decision_reason = ?, decided_at = ?
          WHERE id = ? AND status = 'pending'
        `).run(
          actor.id,
          "Superseded because specialist reassignment changed the represented assignment",
          now,
          guidedDecision.id,
        );
        if (cancelled.changes !== 1) {
          throw conflict("The represented Guided decision changed during reassignment.");
        }
        const remainingTtlMs = Date.parse(guidedDecision.expiresAt) - Date.parse(now);
        if (remainingTtlMs <= 0) {
          throw new OperationsApiError(409, "guided_recovery_decision_expired", "The Guided recovery decision expired", {
            humanMessage: "The exact Guided decision expired and cannot be renewed by a recovery mutation.",
            category: "policy_denied",
            remediation: "Refresh the Guided workspace and create a new represented decision from current plan state.",
          });
        }
        replacementGuidedDecisionId = this.runtime.createDecisionForStep(
          row.step_id,
          now,
          remainingTtlMs,
        ).decisionId;
        this.events.append({
          missionId: row.mission_id,
          runId,
          journey: "guided",
          eventType: "guided.decision_superseded",
          actorType: "operator",
          actorId: actor.id,
          summary: "Guided decision refreshed for the replacement specialist assignment",
          payload: {
            previousDecisionId: guidedDecision.id,
            replacementDecisionId: replacementGuidedDecisionId,
            stepId: row.step_id,
            replacementAssignmentId,
          },
          sensitivity: "private",
        });
      }
      const persisted = this.withRestoredControl(runId);
      const checkpointRun = retryPredecessor ? {
        ...persisted,
        control: {
          ...persisted.control,
          recovery: {
            kind: "retry" as const,
            failedActionId: retryPredecessor.id,
            notBefore: now,
            reason: input.reason,
          },
        },
      } : persisted;
      const latestSequence = this.database.prepare(`
        SELECT last_sequence FROM run_event_sequences WHERE run_id = ?
      `).get(runId) as { last_sequence: number };
      const checkpoint = this.checkpoints.create({
        run: checkpointRun,
        eventSequence: latestSequence.last_sequence,
        now,
      });
      this.appendAudit({
        row, actor, action: "run.specialist_reassigned", reason: input.reason,
        details: {
          eventId: event.id,
          checkpointId: checkpoint.id,
          previousAssignmentId: row.assignment_id,
          replacementAssignmentId,
          previousAgentId: row.assignment_agent_id,
          targetAgentId: input.targetAgentId,
          capability: input.capability,
          retryPredecessorId: retryPredecessor?.id ?? null,
          invalidatedProviderId,
          invalidatedProviderRouteVersion,
          previousGuidedDecisionId: guidedDecision?.id ?? null,
          replacementGuidedDecisionId,
          sourceCheckpoint,
        },
        now,
      });
      const response = this.response("reassign", persisted.run.stateVersion, row, {
        eventId: event.id,
        checkpointId: checkpoint.id,
        agentId: input.targetAgentId,
        assignmentId: replacementAssignmentId,
      });
      this.saveIdempotency(idempotencyKey, requestHash, response, actor.id, now);
      return response;
    });
  }

  changeProvider(
    runId: string,
    input: ExactRecoveryExpectation & {
      readonly providerId: string;
      readonly guidedDecisionId?: string;
      readonly expectedDecisionFingerprint?: string;
      readonly reason: string;
    },
    idempotencyKey: string,
    actor: OperationsActor,
    access: OperationsAccessPolicy,
  ): RecoveryMutationProjection {
    assertManager(actor, access);
    const requestHash = hashJson({ kind: "change_provider", runId, ...input, actorId: actor.id });
    return inImmediateTransaction(this.database, () => {
      const row = this.context(runId, access);
      assertV2ControlPlane(row);
      const replay = this.idempotentReplay(idempotencyKey, requestHash, row);
      if (replay) return replay;
      assertExpected(row, input);
      const sourceCheckpoint = this.assertExactCheckpoint(row, input);
      if (!new Set(["blocked", "waiting_guided_decision"]).has(row.run_status)) {
        throw conflict("Provider recovery routing requires a blocked or waiting Guided checkpoint.");
      }
      if (row.action_kind !== "provider_turn" && row.action_kind !== "delegation") {
        throw new OperationsApiError(409, "provider_route_not_applicable", "The current step is not provider-backed", {
          humanMessage: "Provider routing can change only for the current represented provider-turn or delegation step.",
          category: "policy_denied",
        });
      }
      assertNoInFlight(this.database, runId);
      const retryPredecessor = row.journey === "autonomous"
        ? this.autonomousRetryPredecessor(runId, row.step_id)
        : null;
      if (row.journey === "autonomous" && !retryPredecessor) {
        throw new OperationsApiError(409, "recovery_retry_predecessor_missing", "Autonomous provider recovery has no retryable predecessor", {
          humanMessage: "Autonomous provider recovery can resume the exact step only after a canonical failed or timed-out predecessor is retained.",
          category: "policy_denied",
        });
      }
      if (!this.providerRouteIds.has(input.providerId)) {
        throw new OperationsApiError(409, "provider_route_not_callable", "The requested provider has no callable runtime route", {
          humanMessage: "The requested provider is not connected to the Ti-Scale execution adapter.",
          category: "dependency_missing",
        });
      }
      const health = this.providerHealth(input.providerId);
      if (
        !health || health.status !== "healthy"
        || health.metrics.authenticated !== true
        || health.metrics.callable !== true
      ) {
        throw new OperationsApiError(409, "provider_route_unhealthy", "The requested provider is not healthy", {
          humanMessage: "Choose a healthy, authenticated provider route.",
          category: "provider_unavailable",
          retryable: true,
        });
      }
      if (!isRecoveryProviderHealthFresh(
        recoveryProviderAttestedAt(health.metrics),
        this.clock().toISOString(),
        this.providerHealthMaxAgeMs,
      )) {
        throw new OperationsApiError(409, "provider_route_health_stale", "The requested provider health attestation is stale", {
          humanMessage: "Refresh provider health before selecting this route.",
          category: "provider_unavailable",
          retryable: true,
        });
      }
      if (recoveryProviderCircuitState(this.database, runId, input.providerId) !== "closed") {
        throw new OperationsApiError(409, "provider_route_circuit_open", "The requested provider circuit breaker is not closed", {
          humanMessage: "The provider circuit is open or probing and cannot receive this recovery route.",
          category: "provider_unavailable",
          retryable: true,
        });
      }
      const budget = asJson(row.budget_json);
      if (
        ((finiteLimit(budget, "providerTokens", "tokenBudget") ?? 0) > 0 && health.metrics.reportsExactTokenUsage !== true) ||
        ((finiteLimit(budget, "estimatedCost", "costBudget") ?? 0) > 0 && health.metrics.reportsExactCostUsage !== true)
      ) {
        throw new OperationsApiError(409, "provider_route_budget_telemetry_missing", "The provider cannot enforce the run budget", {
          humanMessage: "The provider does not report exact usage required by this run's finite budget.",
          category: "dependency_missing",
        });
      }
      this.assertJourneyPolicy(row, "change_provider", input, health.metrics);
      const existing = this.providerRouteBinding(runId);
      if (existing?.providerId === input.providerId && existing.planId === row.plan_id && existing.stepId === row.step_id) {
        throw conflict("The requested provider already owns this exact recovery route.");
      }
      const now = this.clock().toISOString();
      const routeVersion = Math.max(
        existing?.version ?? 0,
        this.providerRouteTombstone(runId)?.previousVersion ?? 0,
      ) + 1;
      const binding: RecoveryProviderRouteBinding = row.journey === "autonomous"
        ? {
            schemaVersion: RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION,
            version: routeVersion,
            runId,
            journey: "autonomous",
            providerId: input.providerId,
            planId: row.plan_id,
            planVersion: row.plan_version,
            stepId: row.step_id,
            assignmentId: row.assignment_id,
            contract: {
              id: row.contract_id!,
              version: row.contract_version_bound!,
              hash: row.contract_hash_bound!,
            },
            selectedBy: actor.id,
            selectedAt: now,
          }
        : {
            schemaVersion: RECOVERY_PROVIDER_ROUTE_SCHEMA_VERSION,
            version: routeVersion,
            runId,
            journey: "guided",
            providerId: input.providerId,
            planId: row.plan_id,
            planVersion: row.plan_version,
            stepId: row.step_id,
            assignmentId: row.assignment_id,
            guidedDecision: {
              id: input.guidedDecisionId!,
              fingerprint: input.expectedDecisionFingerprint!,
            },
            selectedBy: actor.id,
            selectedAt: now,
          };
      this.database.prepare(`
        INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
        VALUES (?, ?, 'restricted', 1, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
          version = settings.version + 1, updated_by = excluded.updated_by,
          updated_at = excluded.updated_at
      `).run(recoveryProviderRouteSettingKey(runId), canonicalJson(binding), actor.id, now);
      const updated = this.database.prepare(`
        UPDATE runs SET next_action_summary = ?, version = version + 1, updated_at = ?
        WHERE id = ? AND version = ? AND current_plan_id = ? AND current_step_id = ?
      `).run(`Use ${input.providerId} for the exact current provider-backed step`, now, runId, row.run_version, row.plan_id, row.step_id);
      if (updated.changes !== 1) throw conflict("The current run changed during provider selection.");
      const event = this.events.append({
        missionId: row.mission_id,
        runId,
        journey: row.journey,
        eventType: "run.provider_route_changed",
        actorType: "operator",
        actorId: actor.id,
        summary: `Provider route changed to ${input.providerId} for the exact current step`,
        payload: {
          providerId: input.providerId,
          routeVersion,
          planId: row.plan_id,
          planVersion: row.plan_version,
          stepId: row.step_id,
          assignmentId: row.assignment_id,
          sourceCheckpointId: sourceCheckpoint.id,
          sourceCheckpointStateHash: sourceCheckpoint.stateHash,
          sourceCheckpointEventSequence: sourceCheckpoint.eventSequence,
          contractId: row.contract_id,
          guidedDecisionId: input.guidedDecisionId ?? null,
          retryPredecessorId: retryPredecessor?.id ?? null,
        },
      });
      const persisted = this.withRestoredControl(runId);
      const checkpointRun = retryPredecessor ? {
        ...persisted,
        control: {
          ...persisted.control,
          recovery: {
            kind: "retry" as const,
            failedActionId: retryPredecessor.id,
            notBefore: now,
            reason: input.reason,
          },
        },
      } : persisted;
      const checkpoint = this.checkpoints.create({ run: checkpointRun, eventSequence: event.sequence, now });
      this.appendAudit({
        row, actor, action: "run.provider_route_changed", reason: input.reason,
        details: {
          eventId: event.id,
          checkpointId: checkpoint.id,
          providerId: input.providerId,
          routeVersion,
          planId: row.plan_id,
          stepId: row.step_id,
          retryPredecessorId: retryPredecessor?.id ?? null,
          sourceCheckpoint,
        },
        now,
      });
      const response = this.response("change_provider", persisted.run.stateVersion, row, {
        eventId: event.id,
        checkpointId: checkpoint.id,
        providerId: input.providerId,
        providerRouteVersion: routeVersion,
      });
      this.saveIdempotency(idempotencyKey, requestHash, response, actor.id, now);
      return response;
    });
  }

  private context(runId: string, access: OperationsAccessPolicy): RecoveryContextRow {
    const scope = missionScopeSql("m", access);
    const row = this.database.prepare(`
      SELECT r.id AS run_id, r.mission_id, r.control_plane, r.journey, r.status AS run_status,
        r.version AS run_version, r.contract_id, r.contract_version_bound,
        r.contract_hash_bound, r.budget_json, r.replan_count,
        p.id AS plan_id, p.version AS plan_version, p.status AS plan_status,
        p.strategy_summary, ps.id AS step_id, ps.status AS step_status,
        ps.action_class AS step_action_class, ps.assigned_agent_id AS step_agent_id,
        json_extract(mc.value_json, '$.action.kind') AS action_kind,
        ass.id AS assignment_id, ass.status AS assignment_status,
        ass.agent_id AS assignment_agent_id
      FROM runs r
      JOIN missions m ON m.id = r.mission_id
      JOIN plans p ON p.id = r.current_plan_id
      JOIN plan_steps ps ON ps.id = r.current_step_id AND ps.plan_id = p.id AND ps.run_id = r.id
      JOIN assignments ass ON ass.run_id = r.id AND ass.step_id = ps.id
        AND ass.agent_id = ps.assigned_agent_id
      LEFT JOIN mission_constraints mc ON mc.source = ps.id AND mc.constraint_type = 'represented_action'
      WHERE r.id = ? AND ${scope.sql}
      ORDER BY ass.created_at DESC, ass.id DESC LIMIT 1
    `).get(runId, ...scope.params) as RecoveryContextRow | undefined;
    if (!row) throw notFound("Run recovery mutation boundary");
    return row;
  }

  private withRestoredControl(runId: string) {
    const run = this.runs.get(runId);
    return { ...run, control: this.checkpoints.restoreControl(runId, run.control) };
  }

  /**
   * Fence a first recovery ownership mutation to the exact latest durable
   * checkpoint. Current-result idempotent replay is validated separately;
   * stale replay cannot become valid merely because its key still exists.
   */
  private assertExactCheckpoint(
    row: RecoveryContextRow,
    expected: ExactRecoveryExpectation,
  ): VerifiedRecoveryCheckpoint {
    const checkpoint = this.database.prepare(`
      SELECT id, event_sequence, plan_version, state_json, state_hash,
        in_flight_classification
      FROM checkpoints
      WHERE run_id = ?
      ORDER BY event_sequence DESC, created_at DESC, id DESC
      LIMIT 1
    `).get(row.run_id) as {
      id: string;
      event_sequence: number;
      plan_version: number | null;
      state_json: string;
      state_hash: string;
      in_flight_classification: string | null;
    } | undefined;
    if (!checkpoint) {
      throw new OperationsApiError(409, "recovery_checkpoint_missing", "No durable recovery checkpoint exists", {
        humanMessage: "This run has no durable checkpoint that can own a recovery mutation.",
        category: "conflict",
        remediation: "Keep the run stopped, create or restore a verified checkpoint, then refresh the Recovery Panel.",
      });
    }
    if (
      checkpoint.id !== expected.expectedCheckpointId ||
      checkpoint.state_hash !== expected.expectedCheckpointStateHash ||
      checkpoint.event_sequence !== expected.expectedCheckpointEventSequence
    ) {
      throw new OperationsApiError(409, "recovery_checkpoint_boundary_changed", "The recovery checkpoint changed", {
        humanMessage: "The durable checkpoint changed before this recovery mutation could be applied.",
        category: "conflict",
        details: {
          latestCheckpointId: checkpoint.id,
          latestCheckpointEventSequence: checkpoint.event_sequence,
        },
        remediation: "Refresh the Recovery Panel and retry only against the latest checkpoint identity, hash, and event sequence.",
      });
    }

    const state = asJson(checkpoint.state_json);
    const stateRun = asJson(canonicalJson(state.run ?? {}));
    const inFlightActions = Array.isArray(state.inFlightActions) ? state.inFlightActions : null;
    const sequence = this.database.prepare(`
      SELECT max(
        coalesce((SELECT last_sequence FROM run_event_sequences WHERE run_id = ?), 0),
        coalesce((SELECT max(sequence) FROM events WHERE run_id = ?), 0)
      ) AS latest_sequence
    `).get(row.run_id, row.run_id) as { latest_sequence: number };
    const stateIsExact =
      hashJson(state) === checkpoint.state_hash &&
      checkpoint.plan_version === row.plan_version &&
      stateRun.id === row.run_id &&
      stateRun.missionId === row.mission_id &&
      stateRun.journey === row.journey &&
      stateRun.state === row.run_status &&
      stateRun.stateVersion === row.run_version &&
      state.lastEventSequence === checkpoint.event_sequence &&
      sequence.latest_sequence === checkpoint.event_sequence &&
      inFlightActions !== null;
    if (!stateIsExact) {
      throw new OperationsApiError(409, "recovery_checkpoint_integrity_failed", "The recovery checkpoint no longer matches canonical run state", {
        humanMessage: "The latest checkpoint failed its run, plan, hash, or event-sequence integrity fence.",
        category: "data_integrity",
        remediation: "Keep the run stopped and reconcile its checkpoint with the immutable event history before recovery.",
      });
    }
    if (inFlightActions.length > 0) {
      throw new OperationsApiError(409, "recovery_checkpoint_has_in_flight_actions", "The recovery checkpoint contains in-flight work", {
        humanMessage: "Recovery ownership cannot change from a checkpoint that still records in-flight actions.",
        category: "conflict",
        remediation: "Reconcile or safely cancel the recorded actions, persist a new zero-in-flight checkpoint, and refresh.",
      });
    }
    return {
      id: checkpoint.id,
      stateHash: checkpoint.state_hash,
      eventSequence: checkpoint.event_sequence,
      inFlightClassification: checkpoint.in_flight_classification,
    };
  }

  private assertJourneyPolicy(
    row: RecoveryContextRow,
    operation: "replan" | "reassign" | "change_provider",
    input?: { readonly targetAgentId?: string; readonly guidedDecisionId?: string; readonly expectedDecisionFingerprint?: string },
    providerMetrics?: Record<string, unknown>,
  ): GuidedRecoveryDecisionBoundary | undefined {
    if (row.journey === "autonomous") {
      const contract = this.database.prepare(`
        SELECT id, version, state, contract_hash, action_policy_json
        FROM mission_contracts WHERE id = ?
      `).get(row.contract_id) as {
        id: string; version: number; state: string; contract_hash: string; action_policy_json: string;
      } | undefined;
      const policy = contract ? parseObject(contract.action_policy_json) : {};
      if (
        !contract || contract.state !== "confirmed" ||
        contract.version !== row.contract_version_bound || contract.contract_hash !== row.contract_hash_bound ||
        (operation === "change_provider" && (
          policy.providerPolicy !== "automatic_enforcing_only" ||
          providerMetrics?.enforcesAutonomousBoundary !== true
        ))
      ) {
        throw new OperationsApiError(409, "autonomous_recovery_outside_contract", "The recovery mutation is outside the signed contract", {
          humanMessage: "The signed Autonomous contract or enforcing provider policy no longer permits this recovery change.",
          category: "policy_denied",
        });
      }
      if (operation === "reassign") {
        const specialists = new Set(
          (Array.isArray(policy.specialistAgentIds) ? policy.specialistAgentIds : [])
            .filter((item): item is string => typeof item === "string"),
        );
        if (!input?.targetAgentId || !specialists.has(input.targetAgentId)) {
          throw new OperationsApiError(409, "autonomous_specialist_not_signed", "The replacement specialist is outside the signed contract", {
            humanMessage: "Choose a healthy capable specialist from the exact signed specialist pool.",
            category: "policy_denied",
          });
        }
      }
      return undefined;
    }
    if (operation === "replan") return undefined;
    const decision = this.database.prepare(`
      SELECT id, requested_action_fingerprint, status, step_id, expires_at,
        (SELECT current.id FROM guided_decisions current
          WHERE current.run_id = guided_decisions.run_id AND current.status = 'pending'
          ORDER BY current.created_at DESC, current.id DESC LIMIT 1) AS current_pending_id
      FROM guided_decisions WHERE id = ? AND run_id = ?
    `).get(input?.guidedDecisionId, row.run_id) as {
      id: string;
      requested_action_fingerprint: string;
      status: string;
      step_id: string;
      expires_at: string;
      current_pending_id: string | null;
    } | undefined;
    if (
      !decision || decision.status !== "pending" || decision.step_id !== row.step_id ||
      decision.current_pending_id !== decision.id ||
      decision.requested_action_fingerprint !== input?.expectedDecisionFingerprint
    ) {
      throw new OperationsApiError(409, "guided_recovery_not_represented", "The recovery change is not bound to the exact Guided decision", {
        humanMessage: "Refresh the Guided checkpoint and deliberately choose the change against its current fingerprint.",
        category: "policy_denied",
      });
    }
    if (!Number.isFinite(Date.parse(decision.expires_at)) || Date.parse(decision.expires_at) <= this.clock().getTime()) {
      throw new OperationsApiError(409, "guided_recovery_decision_expired", "The Guided recovery decision expired", {
        humanMessage: "The exact Guided decision expired and cannot be renewed by a recovery mutation.",
        category: "policy_denied",
        remediation: "Refresh the Guided workspace and create a new represented decision from current plan state.",
      });
    }
    return {
      id: decision.id,
      fingerprint: decision.requested_action_fingerprint,
      expiresAt: decision.expires_at,
    };
  }

  private providerHealth(providerId: string): {
    status: string;
    metrics: Record<string, unknown>;
    capturedAt: string;
  } | null {
    const row = this.database.prepare(`
      SELECT status, metrics_json, captured_at FROM health_snapshots
      WHERE component_type = 'provider' AND component_id = ?
      ORDER BY captured_at DESC, id DESC LIMIT 1
    `).get(providerId) as { status: string; metrics_json: string; captured_at: string } | undefined;
    return row ? { status: row.status, metrics: asJson(row.metrics_json), capturedAt: row.captured_at } : null;
  }

  private autonomousRetryPredecessor(runId: string, stepId: string): { id: string } | null {
    return this.database.prepare(`
      SELECT id FROM actions
      WHERE run_id = ? AND step_id = ? AND status IN ('failed', 'timed_out')
      ORDER BY coalesce(ended_at, updated_at) DESC, id DESC LIMIT 1
    `).get(runId, stepId) as { id: string } | undefined ?? null;
  }

  private providerRouteBinding(runId: string): RecoveryProviderRouteBinding | null {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(recoveryProviderRouteSettingKey(runId)) as { value_json: string } | undefined;
    return row ? parseRecoveryProviderRouteBinding(asJson(row.value_json)) : null;
  }

  private providerRouteTombstone(runId: string) {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(recoveryProviderRouteSettingKey(runId)) as { value_json: string } | undefined;
    return row ? parseRecoveryProviderRouteTombstone(asJson(row.value_json)) : null;
  }

  private idempotentReplay(
    key: string,
    requestHash: string,
    current: RecoveryContextRow,
  ): RecoveryMutationProjection | null {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(idempotencySettingKey(key)) as { value_json: string } | undefined;
    if (!row) return null;
    const stored = asJson(row.value_json) as unknown as IdempotencyRecord;
    if (stored.requestHash !== requestHash || !stored.response) {
      throw conflict("The Idempotency-Key was already used for a materially different recovery mutation.", "Use a new Idempotency-Key.");
    }
    const response = stored.response;
    const checkpoint = this.database.prepare(`
      SELECT id, event_sequence, plan_version, state_json, state_hash
      FROM checkpoints WHERE run_id = ?
      ORDER BY event_sequence DESC, created_at DESC, id DESC LIMIT 1
    `).get(current.run_id) as {
      id: string;
      event_sequence: number;
      plan_version: number | null;
      state_json: string;
      state_hash: string;
    } | undefined;
    const checkpointState = checkpoint ? asJson(checkpoint.state_json) : {};
    const checkpointRun = asJson(canonicalJson(checkpointState.run ?? {}));
    const latestSequence = this.database.prepare(`
      SELECT max(
        coalesce((SELECT last_sequence FROM run_event_sequences WHERE run_id = ?), 0),
        coalesce((SELECT max(sequence) FROM events WHERE run_id = ?), 0)
      ) AS latest_sequence
    `).get(current.run_id, current.run_id) as { latest_sequence: number };
    const replayIsCurrent = checkpoint !== undefined &&
      response.run.id === current.run_id &&
      response.run.journey === current.journey &&
      response.run.status === current.run_status &&
      response.run.version === current.run_version &&
      response.run.planId === current.plan_id &&
      response.run.planVersion === current.plan_version &&
      response.run.stepId === current.step_id &&
      response.run.assignmentId === current.assignment_id &&
      checkpoint?.id === response.mutation.checkpointId &&
      checkpoint.plan_version === response.run.planVersion &&
      hashJson(checkpointState) === checkpoint.state_hash &&
      checkpointRun.id === response.run.id &&
      checkpointRun.missionId === current.mission_id &&
      checkpointRun.journey === response.run.journey &&
      checkpointRun.state === response.run.status &&
      checkpointRun.stateVersion === response.run.version &&
      checkpointState.lastEventSequence === checkpoint.event_sequence &&
      latestSequence.latest_sequence === checkpoint.event_sequence;
    if (!replayIsCurrent) {
      throw new OperationsApiError(409, "recovery_idempotent_replay_stale", "The recovery mutation result is no longer current", {
        humanMessage: "This Idempotency-Key belongs to a recovery result that canonical run or checkpoint state has superseded.",
        category: "conflict",
        remediation: "Refresh recovery state and submit a new exact request with a new Idempotency-Key only if another mutation is still valid.",
      });
    }
    return response;
  }

  private saveIdempotency(
    key: string,
    requestHash: string,
    response: RecoveryMutationProjection,
    actorId: string,
    now: string,
  ): void {
    this.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'restricted', 1, ?, ?)
    `).run(idempotencySettingKey(key), canonicalJson({ requestHash, response }), actorId, now);
  }

  private appendAudit(input: {
    readonly row: RecoveryContextRow;
    readonly actor: OperationsActor;
    readonly action: string;
    readonly reason: string;
    readonly details: Record<string, unknown>;
    readonly now: string;
  }): void {
    const previous = this.database.prepare(`
      SELECT record_hash FROM audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get() as { record_hash: string } | undefined;
    const id = `audit_${randomUUID()}`;
    const record = {
      id,
      missionId: input.row.mission_id,
      runId: input.row.run_id,
      journey: input.row.journey,
      actorType: input.actor.type,
      actorId: input.actor.id,
      action: input.action,
      resourceType: "run",
      resourceId: input.row.run_id,
      reason: input.reason,
      details: input.details,
      previousHash: previous?.record_hash ?? null,
      occurredAt: input.now,
    };
    const recordHash = hashJson(record);
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json,
        previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'run', ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      input.row.mission_id,
      input.row.run_id,
      input.row.journey,
      input.actor.type,
      input.actor.id,
      input.action,
      input.row.run_id,
      input.reason,
      canonicalJson(input.details),
      previous?.record_hash ?? null,
      recordHash,
      input.now,
    );
  }

  private response(
    kind: RecoveryMutationProjection["mutation"]["kind"],
    runVersion: number,
    row: RecoveryContextRow,
    details: {
      readonly eventId: string;
      readonly checkpointId: string;
      readonly continuationId?: string;
      readonly agentId?: string;
      readonly providerId?: string;
      readonly providerRouteVersion?: number;
      readonly assignmentId?: string;
    },
  ): RecoveryMutationProjection {
    const current = this.database.prepare("SELECT status FROM runs WHERE id = ?")
      .get(row.run_id) as { status: string };
    return {
      schemaVersion: OPERATIONS_SCHEMA_VERSION,
      mutation: {
        kind,
        eventId: details.eventId,
        checkpointId: details.checkpointId,
        continuationId: details.continuationId ?? null,
        agentId: details.agentId ?? null,
        assignmentId: details.assignmentId ?? null,
        providerId: details.providerId ?? null,
        providerRouteVersion: details.providerRouteVersion ?? null,
      },
      run: {
        id: row.run_id,
        journey: row.journey,
        status: current.status,
        version: runVersion,
        planId: row.plan_id,
        planVersion: row.plan_version,
        stepId: row.step_id,
        assignmentId: details.assignmentId ?? row.assignment_id,
      },
    };
  }
}

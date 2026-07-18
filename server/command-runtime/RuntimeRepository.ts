import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import type { JsonValue } from "../events";
import { EventRepository } from "../events";
import { evaluateDestructiveAuthorization } from "../domain";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import { redactSensitiveText } from "../guided-commander/validation";
import type { DurableActionIntent, RunLeaseToken } from "../orchestration";
import {
  fingerprintAction,
  progressSignature,
  stableSerialize,
  type FailureCategory,
  type Journey,
  type ProgressSnapshot,
  type RunState,
} from "../supervisor";
import { ActionRepository } from "../orchestration";
import { canonicalJson, hashJson, parseObject } from "../orchestration/serialization";
import type {
  GuidedDecisionProjection,
  MissionPlanDraft,
  PlanningMission,
  PlanningRun,
  PlannedAction,
  StoredPlan,
  StoredPlanStep,
} from "./types";
import { CommandRuntimeError } from "./types";

interface MissionRow {
  readonly id: string;
  readonly name: string;
  readonly objective: string;
  readonly journey: Journey;
  readonly engagement_id: string | null;
  readonly authorization_status: PlanningMission["authorizationStatus"];
  readonly success_criteria_json: string;
  readonly memory_policy_json: string;
}

interface RunRow {
  readonly id: string;
  readonly mission_id: string;
  readonly journey: Journey;
  readonly status: RunState;
  readonly replan_count: number;
  readonly current_plan_id: string | null;
  readonly status_reason: string | null;
  readonly version: number;
  readonly lease_owner: string | null;
  readonly lease_expires_at: string | null;
}

interface PlanRow {
  readonly id: string;
  readonly run_id: string;
  readonly version: number;
  readonly status: string;
  readonly strategy_summary: string;
  readonly rationale_summary: string | null;
  readonly created_at: string;
  readonly activated_at: string | null;
  readonly plan_hash: string;
}

interface StepRow {
  readonly id: string;
  readonly ordinal: number;
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly status: string;
  readonly assigned_agent_id: string | null;
  readonly risk_class: string | null;
  readonly success_criteria_json: string;
  readonly representation_json: string | null;
}

interface DecisionRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string;
  readonly status: string;
  readonly requested_action_fingerprint: string;
  readonly requested_parameters_json: string;
  readonly rationale: string;
  readonly risk_class: string;
  readonly reversibility: string;
  readonly expires_at: string;
  readonly created_at: string;
}

interface CompletedIdempotency {
  readonly requestHash: string;
  readonly response: JsonValue;
  readonly status?: "completed";
}

interface PendingIdempotency {
  readonly requestHash: string;
  readonly status: "pending";
  readonly ownerToken: string;
  readonly leaseExpiresAt: string;
}

type StoredIdempotency = CompletedIdempotency | PendingIdempotency;

export type RuntimeIdempotencyClaim =
  | { readonly kind: "claimed"; readonly ownerToken: string }
  | { readonly kind: "in_progress"; readonly leaseExpiresAt: string }
  | { readonly kind: "completed"; readonly response: JsonValue };

export interface PersistedPlanResult {
  readonly planId: string;
  readonly version: number;
  readonly firstStepId: string;
  readonly firstAssignmentId: string;
  readonly firstIntent: DurableActionIntent & {
    readonly actionClass: string;
    readonly intentSummary: string;
    readonly kind: PlannedAction["kind"];
    readonly idempotent: boolean;
    readonly destructive: boolean;
    readonly assignmentId: string;
  };
  readonly guidedDecisionId: string | null;
  readonly planHash: string;
}

export interface RuntimeRunProjection {
  readonly id: string;
  readonly missionId: string;
  readonly missionName: string;
  readonly objective: string;
  readonly journey: Journey;
  readonly status: RunState;
  readonly statusReason: string | null;
  readonly progress: number;
  readonly nextAction: string | null;
  readonly currentPlanId: string | null;
  readonly currentStepId: string | null;
  readonly currentOwnerId: string | null;
  readonly lastHeartbeatAt: string | null;
  readonly leaseExpiresAt: string | null;
  readonly startedAt: string | null;
  readonly endedAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly version: number;
}

export interface StepAdvanceResult {
  readonly completed: boolean;
  readonly nextStepId: string | null;
  readonly nextIntent: PersistedPlanResult["firstIntent"] | null;
  readonly guidedDecisionId: string | null;
  readonly eventSequence: number;
}

export interface GuidedSkipAdvanceResult {
  readonly completed: boolean;
  readonly skippedStepId: string;
  readonly nextStepId: string | null;
  readonly guidedDecisionId: string | null;
  readonly eventSequence: number;
  readonly actionFingerprint: string;
  readonly parameterHash: string;
}

export interface ManualEvidenceReceipt {
  readonly id: string;
  readonly contentHash: string;
  readonly byteSize: number;
  readonly verificationState: "verified";
  readonly deduplicated: boolean;
}

export interface GuidedRecoveryContext {
  readonly failedActionId: string;
  readonly failedStepId: string;
  readonly guidedDecisionId: string | null;
  readonly actionFingerprint: string;
  readonly semanticActionSignature: string;
  readonly attemptedActionSummary: string;
  readonly actionType: string;
  readonly actionClass: string;
  readonly target: string;
  readonly errorCategory: FailureCategory;
  readonly failureSummary: string;
}

function jsonArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function jsonValue(value: unknown): JsonValue {
  return JSON.parse(canonicalJson(value)) as JsonValue;
}

function id(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

function semanticActionSignature(action: Pick<PlannedAction,
  "actionType" | "target" | "arguments"
>): string {
  return createHash("sha256").update(stableSerialize({
    actionType: action.actionType.trim().toLowerCase(),
    target: action.target.trim(),
    arguments: action.arguments,
  }), "utf8").digest("hex");
}

function parseRepresentation(value: string | null): {
  action: PlannedAction;
  explanation: string;
  rationale: string;
  reversibility: string;
  dependencies: readonly string[];
} {
  if (!value) throw new CommandRuntimeError(500, "plan_representation_missing", "Plan step representation is missing");
  const parsed = parseObject(value);
  const action = parsed.action as PlannedAction | undefined;
  if (!action || typeof action !== "object") {
    throw new CommandRuntimeError(500, "plan_representation_corrupt", "Plan step action is corrupt");
  }
  return {
    action,
    explanation: typeof parsed.explanation === "string" ? parsed.explanation : "",
    rationale: typeof parsed.rationale === "string" ? parsed.rationale : "",
    reversibility: typeof parsed.reversibility === "string" ? parsed.reversibility : "",
    dependencies: Array.isArray(parsed.dependencies)
      ? parsed.dependencies.filter((candidate): candidate is string => typeof candidate === "string")
      : [],
  };
}

function mapPlan(row: PlanRow, steps: StepRow[]): StoredPlan {
  return {
    id: row.id,
    runId: row.run_id,
    version: row.version,
    status: row.status,
    strategySummary: row.strategy_summary,
    rationaleSummary: row.rationale_summary,
    createdAt: row.created_at,
    activatedAt: row.activated_at,
    steps: steps.map((step): StoredPlanStep => {
      const represented = parseRepresentation(step.representation_json);
      return {
        id: step.id,
        ordinal: step.ordinal,
        phase: step.phase,
        title: step.title,
        objective: step.objective,
        status: step.status,
        assignedAgentId: step.assigned_agent_id ?? "",
        riskClass: step.risk_class ?? "",
        successCriteria: jsonArray(step.success_criteria_json),
        dependencyStepIds: represented.dependencies,
        action: represented.action,
        explanation: represented.explanation,
        rationale: represented.rationale,
        reversibility: represented.reversibility,
      };
    }),
  };
}

function mapDecision(row: DecisionRow): GuidedDecisionProjection {
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    stepId: row.step_id,
    status: row.status,
    actionFingerprint: row.requested_action_fingerprint,
    requestedParameters: JSON.parse(row.requested_parameters_json) as JsonValue,
    rationale: row.rationale,
    riskClass: row.risk_class,
    reversibility: row.reversibility,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}

function mapRunProjection(row: Record<string, unknown>): RuntimeRunProjection {
  return {
    id: String(row.id),
    missionId: String(row.mission_id),
    missionName: String(row.mission_name),
    objective: String(row.objective),
    journey: row.journey as Journey,
    status: row.status as RunState,
    statusReason: typeof row.status_reason === "string" ? row.status_reason : null,
    progress: typeof row.progress === "number" ? row.progress : 0,
    nextAction: typeof row.next_action_summary === "string" ? row.next_action_summary : null,
    currentPlanId: typeof row.current_plan_id === "string" ? row.current_plan_id : null,
    currentStepId: typeof row.current_step_id === "string" ? row.current_step_id : null,
    currentOwnerId: typeof row.current_owner_id === "string" ? row.current_owner_id : null,
    lastHeartbeatAt: typeof row.last_heartbeat_at === "string" ? row.last_heartbeat_at : null,
    leaseExpiresAt: typeof row.lease_expires_at === "string" ? row.lease_expires_at : null,
    startedAt: typeof row.started_at === "string" ? row.started_at : null,
    endedAt: typeof row.ended_at === "string" ? row.ended_at : null,
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    version: Number(row.version),
  };
}

function idempotencyKey(scope: string, key: string): string {
  const digest = createHash("sha256").update(key, "utf8").digest("hex");
  return `idempotency.runtime.${scope}.${digest}`;
}

export class RuntimeRepository {
  readonly events: EventRepository;

  constructor(readonly database: SqliteDatabase) {
    this.events = new EventRepository(database);
  }

  /** Minimal ownership projection used by shared control-plane guards. */
  getControlPlaneOwnership(runId: string): {
    readonly runId: string;
    readonly missionId: string;
    readonly controlPlane: "legacy" | "ti_scale";
  } | undefined {
    const row = this.database.prepare(
      "SELECT id, mission_id, control_plane FROM runs WHERE id = ?",
    ).get(runId) as {
      readonly id: string;
      readonly mission_id: string;
      readonly control_plane: "legacy" | "ti_scale";
    } | undefined;
    return row
      ? { runId: row.id, missionId: row.mission_id, controlPlane: row.control_plane }
      : undefined;
  }

  /**
   * Close every nonterminal child record after the coordinator has propagated
   * cooperative cancellation to provider/MCP processes. This prevents queued
   * assignments or pending decisions from looking runnable beneath a terminal
   * run after restart.
   */
  cancelOpenWork(runId: string, actorId: string, reason: string, now: string): number {
    let changed = 0;
    changed += this.database.prepare(`
      UPDATE tool_calls SET status = 'cancelled', ended_at = COALESCE(ended_at, ?)
      WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
        AND status IN ('queued', 'running')
    `).run(now, runId).changes;
    changed += this.database.prepare(`
      UPDATE actions SET status = 'cancelled', result_summary = COALESCE(result_summary, ?),
        ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE run_id = ? AND status IN ('queued', 'running')
    `).run(`Cancelled: ${reason}`, now, now, runId).changes;
    changed += this.database.prepare(`
      UPDATE guided_decisions SET status = 'cancelled', decision_actor = ?,
        decision_reason = ?, decided_at = COALESCE(decided_at, ?)
      WHERE run_id = ? AND status = 'pending'
    `).run(actorId, reason, now, runId).changes;
    changed += this.database.prepare(`
      UPDATE approvals SET status = 'cancelled', decided_by = ?,
        decided_at = COALESCE(decided_at, ?)
      WHERE run_id = ? AND status = 'pending'
    `).run(actorId, now, runId).changes;
    changed += this.database.prepare(`
      UPDATE plan_steps SET status = 'cancelled', ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE run_id = ? AND status IN (
        'pending', 'ready', 'running', 'waiting_guided_decision', 'blocked', 'recovering'
      )
    `).run(now, now, runId).changes;
    changed += this.database.prepare(`
      UPDATE assignments SET status = 'cancelled', ended_at = COALESCE(ended_at, ?),
        lease_owner = NULL, lease_acquired_at = NULL, last_heartbeat_at = NULL,
        lease_expires_at = NULL, updated_at = ?
      WHERE run_id = ? AND status IN ('queued', 'active', 'blocked')
    `).run(now, now, runId).changes;
    // Provider turns are durable execution children too. Closing them in the
    // same cancellation boundary prevents a terminal run from retaining a
    // ghost `started` turn after a process crash.
    changed += this.database.prepare(`
      UPDATE provider_turns SET status = 'cancelled',
        error_category = COALESCE(error_category, 'operator_rejection'),
        ended_at = COALESCE(ended_at, ?)
      WHERE run_id = ? AND status = 'started'
    `).run(now, runId).changes;
    changed += this.database.prepare(`
      UPDATE plans SET status = 'abandoned'
      WHERE run_id = ? AND status IN ('draft', 'active')
    `).run(runId).changes;
    return changed;
  }

  /**
   * Close the exact current planning boundary when planning or bounded
   * replanning fails closed. A blocked run must not retain a `recovering`
   * step or a runnable/blocked assignment that suggests work is still active.
   */
  failCurrentPlanningBoundary(runId: string, now: string): {
    readonly stepsFailed: number;
    readonly assignmentsFailed: number;
  } {
    const stepsFailed = this.database.prepare(`
      UPDATE plan_steps SET status = 'failed', ended_at = COALESCE(ended_at, ?),
        updated_at = ?
      WHERE run_id = ?
        AND id = (SELECT current_step_id FROM runs WHERE id = ?)
        AND status IN ('ready', 'running', 'waiting_guided_decision', 'blocked', 'recovering')
    `).run(now, now, runId, runId).changes;
    const assignmentsFailed = this.database.prepare(`
      UPDATE assignments SET status = 'failed', ended_at = COALESCE(ended_at, ?),
        lease_owner = NULL, lease_acquired_at = NULL, last_heartbeat_at = NULL,
        lease_expires_at = NULL, updated_at = ?
      WHERE run_id = ?
        AND step_id = (SELECT current_step_id FROM runs WHERE id = ?)
        AND status IN ('queued', 'active', 'blocked')
    `).run(now, now, runId, runId).changes;
    return { stepsFailed, assignmentsFailed };
  }

  listRunnableRuns(now: string, limit = 20): string[] {
    return (this.database.prepare(`
      SELECT id FROM runs
      WHERE status IN ('planning', 'recovering')
        AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
        AND NOT EXISTS (
          SELECT 1 FROM runtime_continuations continuation
          WHERE continuation.run_id = runs.id
            AND continuation.kind = 'planning_retry_to_dispatch'
            AND continuation.status IN ('pending', 'processing')
        )
      ORDER BY updated_at ASC, id ASC LIMIT ?
    `).all(now, limit) as Array<{ id: string }>).map((row) => row.id);
  }

  getMission(missionId: string): PlanningMission {
    const row = this.database.prepare(`
      SELECT id, name, objective, journey, engagement_id, authorization_status,
        success_criteria_json, memory_policy_json
      FROM missions WHERE id = ?
    `).get(missionId) as MissionRow | undefined;
    if (!row) throw new CommandRuntimeError(404, "mission_not_found", `Mission not found: ${missionId}`);
    const targets = this.database.prepare(`
      SELECT target, disposition FROM mission_targets WHERE mission_id = ? ORDER BY id
    `).all(missionId) as Array<{ target: string; disposition: "allowed" | "prohibited" }>;
    return {
      id: row.id,
      name: row.name,
      objective: row.objective,
      journey: row.journey,
      engagementId: row.engagement_id,
      authorizationStatus: row.authorization_status,
      allowedTargets: targets.filter((target) => target.disposition === "allowed").map((target) => target.target),
      prohibitedTargets: targets.filter((target) => target.disposition === "prohibited").map((target) => target.target),
      successCriteria: jsonArray(row.success_criteria_json),
      memoryPolicy: parseObject(row.memory_policy_json),
    };
  }

  getPlanningRun(runId: string): PlanningRun {
    const row = this.database.prepare(`
      SELECT id, mission_id, journey, status, replan_count, current_plan_id,
        status_reason, version, lease_owner, lease_expires_at
      FROM runs WHERE id = ?
    `).get(runId) as RunRow | undefined;
    if (!row) throw new CommandRuntimeError(404, "run_not_found", `Run not found: ${runId}`);
    const current = row.current_plan_id
      ? this.database.prepare("SELECT version, strategy_summary FROM plans WHERE id = ?")
          .get(row.current_plan_id) as { version: number; strategy_summary: string } | undefined
      : undefined;
    return {
      id: row.id,
      missionId: row.mission_id,
      journey: row.journey,
      state: row.status,
      replanCount: row.replan_count,
      currentPlanVersion: current?.version ?? null,
      previousStrategySummary: current?.strategy_summary ?? null,
      stateReason: row.status_reason ?? `Run is ${row.status}`,
    };
  }

  latestGuidedRecovery(runId: string): GuidedRecoveryContext | null {
    const latest = this.database.prepare(`
      SELECT a.id, a.status FROM actions a
      JOIN runs r ON r.id = a.run_id AND r.current_step_id = a.step_id
      WHERE a.run_id = ? AND a.ended_at IS NOT NULL
      ORDER BY a.ended_at DESC, a.rowid DESC LIMIT 1
    `).get(runId) as { id: string; status: string } | undefined;
    if (!latest || !["failed", "timed_out", "denied"].includes(latest.status)) return null;
    const action = new ActionRepository(this.database).get(latest.id);
    return {
      failedActionId: action.id,
      failedStepId: action.stepId,
      guidedDecisionId: action.guidedDecisionId,
      actionFingerprint: action.fingerprint,
      semanticActionSignature: semanticActionSignature(action),
      attemptedActionSummary: action.intentSummary,
      actionType: action.actionType,
      actionClass: action.actionClass,
      target: action.target,
      errorCategory: action.errorCategory ?? "unknown",
      failureSummary: redactSensitiveText(
        action.resultSummary ?? "The represented action did not complete.",
      ).text,
    };
  }

  /**
   * Persist the failed Guided checkpoint in the structured plan, assignment,
   * conversation, and event stream. This is idempotent by failed action ID and
   * deliberately does not create or authorize a replacement action.
   */
  recordGuidedActionFailure(actionId: string, now: string): GuidedRecoveryContext {
    const action = new ActionRepository(this.database).get(actionId);
    const run = this.getPlanningRun(action.runId);
    if (run.journey !== "guided" || !["failed", "timed_out", "denied"].includes(action.status)) {
      throw new CommandRuntimeError(409, "guided_failure_context_invalid", "Action is not a failed Guided action");
    }
    const context: GuidedRecoveryContext = {
      failedActionId: action.id,
      failedStepId: action.stepId,
      guidedDecisionId: action.guidedDecisionId,
      actionFingerprint: action.fingerprint,
      semanticActionSignature: semanticActionSignature(action),
      attemptedActionSummary: action.intentSummary,
      actionType: action.actionType,
      actionClass: action.actionClass,
      target: action.target,
      errorCategory: action.errorCategory ?? "unknown",
      failureSummary: redactSensitiveText(
        action.resultSummary ?? "The represented action did not complete.",
      ).text,
    };
    this.database.prepare(`
      UPDATE plan_steps SET status = 'failed', ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE id = ? AND run_id = ? AND status IN ('ready', 'running', 'recovering', 'waiting_guided_decision')
    `).run(now, now, action.stepId, action.runId);
    this.database.prepare(`
      UPDATE assignments SET status = 'failed', ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE step_id = ? AND run_id = ? AND status IN ('queued', 'active', 'blocked')
    `).run(now, now, action.stepId, action.runId);
    this.database.prepare(`
      UPDATE runs SET next_action_summary = ?, updated_at = ? WHERE id = ?
    `).run(
      `Diagnose ${context.errorCategory} and prepare one materially different Guided recovery decision`,
      now,
      action.runId,
    );

    const existing = this.database.prepare(`
      SELECT msg.id FROM messages msg
      JOIN conversations c ON c.id = msg.conversation_id
      WHERE c.run_id = ? AND c.conversation_type = 'guided'
        AND json_extract(msg.structured_content_json, '$.kind') = 'guided_failure'
        AND json_extract(msg.structured_content_json, '$.actionId') = ?
      LIMIT 1
    `).get(action.runId, action.id) as { id: string } | undefined;
    if (existing) return context;

    const conversation = this.database.prepare(`
      SELECT id FROM conversations
      WHERE run_id = ? AND step_id = ? AND conversation_type = 'guided'
      ORDER BY created_at, id LIMIT 1
    `).get(action.runId, action.stepId) as { id: string } | undefined;
    const conversationId = conversation?.id ?? id("conversation");
    if (!conversation) {
      this.database.prepare(`
        INSERT INTO conversations (
          id, mission_id, run_id, step_id, conversation_type, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'guided', ?, ?)
      `).run(conversationId, action.missionId, action.runId, action.stepId, now, now);
    }
    this.database.prepare(`
      INSERT INTO messages (
        id, conversation_id, role, body, structured_content_json, created_at
      ) VALUES (?, ?, 'assistant', ?, ?, ?)
    `).run(
      id("message"),
      conversationId,
      `The represented Guided step did not complete.\n\nAttempted action: ${context.attemptedActionSummary}\nFailure category: ${context.errorCategory}\nObserved outcome: ${context.failureSummary}\n\nNothing was rerun. Ti-Scale is preparing one bounded, materially different recovery step. Any consequential recovery action will remain paused for a new exact decision.`,
      canonicalJson({
        kind: "guided_failure",
        stepId: action.stepId,
        actionId: action.id,
        guidedDecisionId: action.guidedDecisionId,
        actionFingerprint: action.fingerprint,
        attemptedAction: {
          type: action.actionType,
          class: action.actionClass,
          target: action.target,
          summary: action.intentSummary,
        },
        errorCategory: context.errorCategory,
        nextConsequentialActionRequiresDecision: true,
      }),
      now,
    );
    this.events.append({
      missionId: action.missionId,
      runId: action.runId,
      journey: "guided",
      eventType: "guided.commander.recovery_started",
      actorType: "system",
      summary: `Guided failure explained; preparing one materially different recovery decision after ${context.errorCategory}`,
      payload: {
        actionId: action.id,
        stepId: action.stepId,
        actionFingerprint: action.fingerprint,
        errorCategory: context.errorCategory,
        automaticRepeatPermitted: false,
      },
    });
    return context;
  }

  /** Persist the specialist result as the Guided interpretation before advance. */
  recordGuidedExecutionInterpretation(
    actionId: string,
    summary: string,
    claimedEvidenceIds: readonly string[],
    now: string,
  ): string {
    const action = new ActionRepository(this.database).get(actionId);
    if (action.status !== "succeeded") {
      throw new CommandRuntimeError(409, "guided_interpretation_action_incomplete", "Only a successful action can be interpreted");
    }
    const existing = this.database.prepare(`
      SELECT msg.id FROM messages msg
      JOIN conversations c ON c.id = msg.conversation_id
      WHERE c.run_id = ? AND c.conversation_type = 'guided'
        AND json_extract(msg.structured_content_json, '$.kind') = 'guided_execution_interpretation'
        AND json_extract(msg.structured_content_json, '$.actionId') = ?
      LIMIT 1
    `).get(action.runId, action.id) as { id: string } | undefined;
    if (existing) return existing.id;
    const verifiedEvidenceIds = claimedEvidenceIds.filter((evidenceId) => Boolean(
      this.database.prepare(`
        SELECT 1 AS present FROM evidence
        WHERE id = ? AND mission_id = ? AND run_id = ? AND step_id = ?
          AND action_id = ? AND ${verifiedEvidenceSql("evidence")}
      `).get(evidenceId, action.missionId, action.runId, action.stepId, action.id),
    ));
    const interpreted = redactSensitiveText(summary).text;
    const assigned = this.database.prepare(`
      SELECT agent_id FROM assignments WHERE run_id = ? AND step_id = ?
      ORDER BY created_at, id LIMIT 1
    `).get(action.runId, action.stepId) as { agent_id: string } | undefined;
    const interpreterId = assigned?.agent_id ?? "guided-specialist";
    const conversation = this.database.prepare(`
      SELECT id FROM conversations
      WHERE run_id = ? AND step_id = ? AND conversation_type = 'guided'
      ORDER BY created_at, id LIMIT 1
    `).get(action.runId, action.stepId) as { id: string } | undefined;
    const conversationId = conversation?.id ?? id("conversation");
    if (!conversation) {
      this.database.prepare(`
        INSERT INTO conversations (
          id, mission_id, run_id, step_id, conversation_type, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'guided', ?, ?)
      `).run(conversationId, action.missionId, action.runId, action.stepId, now, now);
    }
    const latest = this.database.prepare(`
      SELECT created_at FROM messages WHERE conversation_id = ?
      ORDER BY created_at DESC, id DESC LIMIT 1
    `).get(conversationId) as { created_at: string } | undefined;
    const createdAt = latest && Date.parse(latest.created_at) >= Date.parse(now)
      ? new Date(Date.parse(latest.created_at) + 1).toISOString()
      : now;
    const messageId = id("message");
    this.database.prepare(`
      INSERT INTO messages (
        id, conversation_id, role, body, structured_content_json, created_at
      ) VALUES (?, ?, 'assistant', ?, ?, ?)
    `).run(
      messageId,
      conversationId,
      `The authorized specialist completed this exact step.\n\nObserved result: ${interpreted}\n\nThe result was recorded before advancing. Any next consequential action will be explained and will require a new exact Guided decision.`,
      canonicalJson({
        kind: "guided_execution_interpretation",
        stepId: action.stepId,
        actionId: action.id,
        guidedDecisionId: action.guidedDecisionId,
        actionFingerprint: action.fingerprint,
        summary: interpreted,
        observations: [interpreted],
        evidenceIds: verifiedEvidenceIds,
        evidenceId: verifiedEvidenceIds[0] ?? null,
        executionPerformed: true,
        planMutated: false,
        nextConsequentialActionRequiresDecision: true,
      }),
      createdAt,
    );
    this.database.prepare("UPDATE conversations SET updated_at = ? WHERE id = ?")
      .run(createdAt, conversationId);
    for (const evidenceId of verifiedEvidenceIds) {
      const already = this.database.prepare(`
        SELECT 1 AS present FROM evidence_chain_events
        WHERE evidence_id = ? AND event_type = 'interpreted'
          AND json_extract(details_json, '$.actionId') = ? LIMIT 1
      `).get(evidenceId, action.id) as { present: number } | undefined;
      if (!already) {
        this.database.prepare(`
          INSERT INTO evidence_chain_events (
            id, evidence_id, event_type, actor, details_json, occurred_at
          ) VALUES (?, ?, 'interpreted', ?, ?, ?)
        `).run(
          id("evidence-chain"),
          evidenceId,
          interpreterId,
          canonicalJson({ actionId: action.id, messageId, actionFingerprint: action.fingerprint }),
          createdAt,
        );
      }
    }
    this.events.append({
      missionId: action.missionId,
      runId: action.runId,
      journey: "guided",
      eventType: "guided.execution_interpreted",
      actorType: "agent",
      actorId: interpreterId,
      summary: "Specialist result was interpreted and recorded before Guided advancement",
      payload: {
        stepId: action.stepId,
        actionId: action.id,
        guidedDecisionId: action.guidedDecisionId,
        actionFingerprint: action.fingerprint,
        evidenceIds: verifiedEvidenceIds,
        messageId,
      },
      sensitivity: "private",
    });
    return messageId;
  }

  assertLease(runId: string, lease: RunLeaseToken, now: string): void {
    const row = this.database.prepare(`
      SELECT version, lease_owner, lease_expires_at FROM runs WHERE id = ?
    `).get(runId) as { version: number; lease_owner: string | null; lease_expires_at: string | null } | undefined;
    if (
      !row || row.version !== lease.fence || row.lease_owner !== lease.ownerId ||
      row.lease_expires_at !== lease.expiresAt || Date.parse(lease.expiresAt) <= Date.parse(now)
    ) {
      throw new CommandRuntimeError(
        409,
        "stale_run_lease",
        `The run lease changed during planning (db fence ${row?.version ?? "missing"}, result fence ${lease.fence})`, {
        humanMessage: "Another worker now owns this run; this planning result was discarded.",
        category: "conflict",
        retryable: true,
        },
      );
    }
  }

  private validateAgents(plan: MissionPlanDraft): void {
    for (const step of plan.steps) {
      const agent = this.database.prepare("SELECT status FROM agents WHERE id = ?")
        .get(step.assignedAgentId) as { status: string } | undefined;
      if (!agent || agent.status === "offline" || agent.status === "quarantined") {
        throw new CommandRuntimeError(409, "assigned_agent_unavailable", `Agent ${step.assignedAgentId} is unavailable`, {
          humanMessage: `The planner assigned ${step.assignedAgentId}, but that specialist is not executable.`,
          category: "dependency_missing",
          remediation: "Restore the specialist or request a plan using a healthy capable agent.",
        });
      }
    }
  }

  assertAutonomousPlanInContract(runId: string, plan: MissionPlanDraft): void {
    const contract = this.database.prepare(`
      SELECT mc.state, mc.action_policy_json
      FROM runs r JOIN mission_contracts mc ON mc.id = r.contract_id
      WHERE r.id = ?
    `).get(runId) as { state: string; action_policy_json: string } | undefined;
    if (!contract || contract.state !== "confirmed") {
      throw new CommandRuntimeError(409, "autonomous_contract_not_confirmed", "Autonomous contract is not confirmed", {
        humanMessage: "Autonomous planning cannot execute without the confirmed contract.",
        category: "policy_denied",
      });
    }
    const policy = parseObject(contract.action_policy_json);
    const normalizePolicyValue = (value: string): string => value.trim().toLowerCase();
    const allowed = new Set(
      (Array.isArray(policy.allowedActionClasses) ? policy.allowedActionClasses : [])
        .filter((item): item is string => typeof item === "string")
        .map(normalizePolicyValue)
        .filter(Boolean),
    );
    const prohibited = new Set(
      (Array.isArray(policy.prohibitedActionClasses) ? policy.prohibitedActionClasses : [])
        .filter((item): item is string => typeof item === "string")
        .map(normalizePolicyValue)
        .filter(Boolean),
    );
    const destructivePolicy = typeof policy.destructivePolicy === "string"
      ? normalizePolicyValue(policy.destructivePolicy)
      : "";
    const boundedDestructiveTargets = new Set(
      (Array.isArray(policy.boundedDestructiveTargets) ? policy.boundedDestructiveTargets : [])
        .filter((item): item is string => typeof item === "string")
        .map((item) => item.trim())
        .filter(Boolean),
    );
    const specialists = new Set(
      (Array.isArray(policy.specialistAgentIds) ? policy.specialistAgentIds : [])
        .filter((item): item is string => typeof item === "string")
        .map((item) => item.trim())
        .filter(Boolean),
    );
    if (specialists.size === 0) {
      throw new CommandRuntimeError(409, "autonomous_specialist_pool_missing", "Autonomous contract has no signed specialist pool", {
        humanMessage: "Safe-stopped: this contract predates the exact specialist boundary and cannot execute autonomously.",
        category: "policy_denied",
        remediation: "Create a versioned contract amendment or a new Autonomous run with at least one reviewed compatible specialist.",
      });
    }
    const targets = new Set(
      (this.database.prepare(`
        SELECT target FROM mission_targets WHERE mission_id = (
          SELECT mission_id FROM runs WHERE id = ?
        ) AND disposition = 'allowed'
      `).all(runId) as Array<{ target: string }>).map((row) => row.target.trim()),
    );
    for (const step of plan.steps) {
      const actionType = normalizePolicyValue(step.action.actionType);
      const actionClass = normalizePolicyValue(step.action.actionClass);
      const actionTarget = step.action.target.trim();
      if (!evaluateDestructiveAuthorization({
        destructive: step.action.destructive,
        policy: destructivePolicy,
        target: actionTarget,
        boundedTargets: [...boundedDestructiveTargets],
      }).allowed) {
        throw new CommandRuntimeError(
          409,
          "autonomous_destructive_action_not_authorized",
          "Plan contains a destructive action that is not authorized by the signed contract",
          {
            humanMessage: `Safe-stopped: ${step.title} is destructive and the signed contract does not explicitly authorize destructive actions.`,
            category: "policy_denied",
            details: {
              step: step.title,
              actionType,
              actionClass,
              destructivePolicy: destructivePolicy || "missing",
            },
            remediation: "Use a non-destructive in-contract alternative or create a versioned contract amendment before a new run.",
          },
        );
      }
      if (
        !allowed.has(actionType) ||
        !allowed.has(actionClass) ||
        prohibited.has(actionType) ||
        prohibited.has(actionClass) ||
        !targets.has(actionTarget) ||
        !specialists.has(step.assignedAgentId)
      ) {
        throw new CommandRuntimeError(409, "autonomous_plan_outside_contract", "Plan contains an out-of-contract action", {
          humanMessage: `Safe-stopped: ${step.title} is outside the signed action or target boundary.`,
          category: "scope_conflict",
          details: {
            step: step.title,
            actionType,
            actionClass,
            target: step.action.target,
            assignedAgentId: step.assignedAgentId,
          },
          remediation: "Use an in-contract alternative or create a versioned contract amendment before a new run.",
        });
      }
    }
  }

  persistPlanRecords(input: {
    mission: PlanningMission;
    run: PlanningRun;
    lease: RunLeaseToken;
    plan: MissionPlanDraft;
    now: string;
    decisionTtlMs: number;
    guidedRecovery?: GuidedRecoveryContext;
  }): PersistedPlanResult {
    this.assertLease(input.run.id, input.lease, input.now);
    this.validateAgents(input.plan);
    if (input.run.journey === "autonomous") this.assertAutonomousPlanInContract(input.run.id, input.plan);
    if (input.guidedRecovery) {
      if (input.run.journey !== "guided" || input.guidedRecovery.failedActionId === "") {
        throw new CommandRuntimeError(409, "guided_recovery_context_invalid", "Guided recovery context is invalid");
      }
      const nextSignature = semanticActionSignature(input.plan.steps[0]!.action);
      if (nextSignature === input.guidedRecovery.semanticActionSignature) {
        throw new CommandRuntimeError(409, "guided_recovery_action_unchanged", "Recovery repeated the failed represented action", {
          humanMessage: `Recovery was blocked because it proposed the same ${input.guidedRecovery.actionType} action and parameters that already failed.`,
          category: "deterministic_tool_error",
          remediation: "Choose a materially different in-scope action or add new evidence before requesting another bounded replan.",
        });
      }
      const pending = this.database.prepare(`
        SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
        ORDER BY created_at, id LIMIT 1
      `).get(input.run.id) as { id: string } | undefined;
      if (pending) {
        throw new CommandRuntimeError(409, "guided_recovery_decision_conflict", "A pending Guided decision already exists", {
          humanMessage: "Recovery stopped because another exact Guided decision is already pending.",
          category: "conflict",
          remediation: "Resolve or cancel the existing decision before creating a different recovery action.",
        });
      }
    }

    const version = (input.run.currentPlanVersion ?? 0) + 1;
    const planHash = hashJson({ strategy: input.plan.strategySummary, steps: input.plan.steps });
    const previous = this.database.prepare(`
      SELECT id, plan_hash FROM plans WHERE run_id = ? ORDER BY version DESC LIMIT 1
    `).get(input.run.id) as { id: string; plan_hash: string } | undefined;
    if (previous?.plan_hash === planHash) {
      throw new CommandRuntimeError(409, "equivalent_replan", "The proposed replan is materially identical", {
        humanMessage: "Recovery produced the same plan and was stopped instead of looping.",
        category: "deterministic_tool_error",
        remediation: "Provide materially new facts or choose a different strategy.",
      });
    }

    const planId = id("plan");
    this.database.prepare(`
      INSERT INTO plans (
        id, run_id, version, status, strategy_summary, rationale_summary,
        plan_hash, created_by, created_at, activated_at
      ) VALUES (?, ?, ?, 'active', ?, ?, ?, 'runtime-planner', ?, ?)
    `).run(
      planId,
      input.run.id,
      version,
      input.plan.strategySummary,
      input.plan.rationaleSummary,
      planHash,
      input.now,
      input.now,
    );
    if (previous) {
      this.database.prepare("UPDATE plans SET status = 'superseded' WHERE id = ?")
        .run(previous.id);
      this.database.prepare(`
        UPDATE plan_steps SET status = 'cancelled', ended_at = COALESCE(ended_at, ?), updated_at = ?
        WHERE plan_id = ? AND status IN (
          'pending', 'ready', 'running', 'waiting_guided_decision', 'blocked', 'recovering'
        )
      `).run(input.now, input.now, previous.id);
      this.database.prepare(`
        UPDATE assignments SET status = 'cancelled', ended_at = COALESCE(ended_at, ?), updated_at = ?
        WHERE step_id IN (SELECT id FROM plan_steps WHERE plan_id = ?)
          AND status IN ('queued', 'active', 'blocked')
      `).run(input.now, input.now, previous.id);
    }

    const stepIds = input.plan.steps.map(() => id("step"));
    const assignmentIds = input.plan.steps.map(() => id("assignment"));
    const insertStep = this.database.prepare(`
      INSERT INTO plan_steps (
        id, plan_id, run_id, ordinal, phase, title, objective, status,
        success_criteria_json, dependencies_json, action_class, risk_class,
        assigned_agent_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertAssignment = this.database.prepare(`
      INSERT INTO assignments (
        id, run_id, step_id, agent_id, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    const insertRepresentation = this.database.prepare(`
      INSERT INTO mission_constraints (
        id, mission_id, constraint_type, value_json, source, created_at
      ) VALUES (?, ?, 'represented_action', ?, ?, ?)
    `);
    for (let ordinal = 0; ordinal < input.plan.steps.length; ordinal += 1) {
      const step = input.plan.steps[ordinal]!;
      const dependencyIds = (step.dependencyOrdinals ?? []).map((dependency) => stepIds[dependency]!);
      const status = ordinal === 0 ? "ready" : "pending";
      insertStep.run(
        stepIds[ordinal], planId, input.run.id, ordinal, step.phase, step.title,
        step.objective, status, canonicalJson(step.successCriteria), canonicalJson(dependencyIds),
        step.action.actionClass, step.riskClass, step.assignedAgentId, input.now, input.now,
      );
      insertAssignment.run(
        assignmentIds[ordinal], input.run.id, stepIds[ordinal], step.assignedAgentId,
        ordinal === 0 ? "queued" : "queued", input.now, input.now,
      );
      insertRepresentation.run(
        id("constraint"), input.mission.id,
        canonicalJson({
          action: step.action,
          explanation: step.explanation,
          rationale: step.rationale,
          reversibility: step.reversibility,
          dependencies: dependencyIds,
        }),
        stepIds[ordinal],
        input.now,
      );
    }

    const first = input.plan.steps[0]!;
    const firstIntent = this.toIntent({
      missionId: input.mission.id,
      runId: input.run.id,
      planVersion: version,
      stepId: stepIds[0]!,
      assignmentId: assignmentIds[0]!,
      action: first.action,
    });
    let guidedDecisionId: string | null = null;
    if (input.run.journey === "guided") {
      guidedDecisionId = this.createGuidedDecision({
        missionId: input.mission.id,
        runId: input.run.id,
        stepId: stepIds[0]!,
        intent: firstIntent,
        rationale: input.guidedRecovery
          ? `Recovery after ${input.guidedRecovery.errorCategory}; the failed action will not be repeated.\n\n${first.explanation}\n\nWhy this materially different step matters: ${first.rationale}`
          : `${first.explanation}\n\nWhy this matters: ${first.rationale}`,
        riskClass: first.riskClass,
        reversibility: first.reversibility,
        now: input.now,
        expiresAt: new Date(Date.parse(input.now) + input.decisionTtlMs).toISOString(),
      });
      this.persistGuidedExplanation({
        missionId: input.mission.id,
        runId: input.run.id,
        stepId: stepIds[0]!,
        planId,
        step: first,
        decisionId: guidedDecisionId,
        now: input.now,
        ...(input.guidedRecovery ? { recovery: input.guidedRecovery } : {}),
      });
      if (input.guidedRecovery) {
        this.events.append({
          missionId: input.mission.id,
          runId: input.run.id,
          journey: "guided",
          eventType: "guided.commander.recovery_ready",
          actorType: "agent",
          actorId: "runtime-planner",
          summary: "A materially different Guided recovery step is explained and waiting for one exact decision",
          payload: {
            decisionId: guidedDecisionId,
            stepId: stepIds[0]!,
            recoveryOfActionId: input.guidedRecovery.failedActionId,
            failedActionFingerprint: input.guidedRecovery.actionFingerprint,
            recoveryActionFingerprint: fingerprintAction(firstIntent).hash,
            errorCategory: input.guidedRecovery.errorCategory,
            automaticRepeatPermitted: false,
          },
        });
      }
    }

    this.database.prepare(`
      UPDATE runs SET current_plan_id = ?, current_step_id = ?, current_owner_id = ?,
        progress = 0, next_action_summary = ?, updated_at = ? WHERE id = ?
    `).run(
      planId,
      stepIds[0],
      first.assignedAgentId,
      input.run.journey === "autonomous"
        ? first.action.intentSummary
        : `Waiting for the exact Guided decision: ${first.title}`,
      input.now,
      input.run.id,
    );
    this.events.append({
      missionId: input.mission.id,
      runId: input.run.id,
      journey: input.run.journey,
      eventType: "plan.activated",
      actorType: "agent",
      actorId: "runtime-planner",
      summary: `Plan v${version} activated with ${input.plan.steps.length} bounded steps`,
      payload: {
        planId,
        version,
        planHash,
        stepCount: input.plan.steps.length,
        strategySummary: input.plan.strategySummary,
      },
    });
    return {
      planId,
      version,
      firstStepId: stepIds[0]!,
      firstAssignmentId: assignmentIds[0]!,
      firstIntent,
      guidedDecisionId,
      planHash,
    };
  }

  toIntent(input: {
    missionId: string;
    runId: string;
    planVersion: number;
    stepId: string;
    assignmentId: string;
    action: PlannedAction;
  }): PersistedPlanResult["firstIntent"] {
    return {
      missionId: input.missionId,
      runId: input.runId,
      stepId: input.stepId,
      assignmentId: input.assignmentId,
      planVersion: input.planVersion,
      actionType: input.action.actionType,
      actionClass: input.action.actionClass,
      target: input.action.target,
      arguments: input.action.arguments,
      intentSummary: input.action.intentSummary,
      kind: input.action.kind,
      idempotent: input.action.idempotent,
      destructive: input.action.destructive,
    };
  }

  private createGuidedDecision(input: {
    missionId: string;
    runId: string;
    stepId: string;
    intent: DurableActionIntent;
    rationale: string;
    riskClass: string;
    reversibility: string;
    now: string;
    expiresAt: string;
  }): string {
    const pending = this.database.prepare(`
      SELECT id FROM guided_decisions
      WHERE run_id = ? AND status = 'pending'
      ORDER BY created_at, id LIMIT 1
    `).get(input.runId) as { id: string } | undefined;
    if (pending) {
      throw new CommandRuntimeError(409, "guided_pending_decision_conflict", "A Guided run may have only one pending decision", {
        humanMessage: "The run already has an unresolved exact Guided decision and no second decision was created.",
        category: "conflict",
        remediation: "Resolve or cancel the current Guided decision before preparing another represented step.",
      });
    }
    const decisionId = id("decision");
    const fingerprint = fingerprintAction(input.intent).hash;
    this.database.prepare(`
      INSERT INTO guided_decisions (
        id, mission_id, run_id, step_id, requested_action_fingerprint,
        requested_parameters_json, rationale, risk_class, reversibility,
        status, expires_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
    `).run(
      decisionId,
      input.missionId,
      input.runId,
      input.stepId,
      fingerprint,
      canonicalJson(input.intent),
      input.rationale,
      input.riskClass,
      input.reversibility,
      input.expiresAt,
      input.now,
    );
    this.events.append({
      missionId: input.missionId,
      runId: input.runId,
      journey: "guided",
      eventType: "guided.decision_requested",
      actorType: "agent",
      actorId: "runtime-planner",
      summary: `Guided step explained and waiting for one exact decision`,
      payload: {
        decisionId,
        stepId: input.stepId,
        actionFingerprint: fingerprint,
        expiresAt: input.expiresAt,
      },
    });
    return decisionId;
  }

  private persistGuidedExplanation(input: {
    missionId: string;
    runId: string;
    stepId: string;
    planId: string;
    step: MissionPlanDraft["steps"][number];
    decisionId: string;
    now: string;
    recovery?: GuidedRecoveryContext;
  }): void {
    const conversation = this.database.prepare(`
      SELECT id FROM conversations WHERE run_id = ? AND conversation_type = 'guided'
      ORDER BY created_at LIMIT 1
    `).get(input.runId) as { id: string } | undefined;
    const conversationId = conversation?.id ?? id("conversation");
    if (!conversation) {
      this.database.prepare(`
        INSERT INTO conversations (
          id, mission_id, run_id, step_id, conversation_type, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'guided', ?, ?)
      `).run(conversationId, input.missionId, input.runId, input.stepId, input.now, input.now);
    }
    this.database.prepare(`
      INSERT INTO messages (
        id, conversation_id, role, body, structured_content_json, created_at
      ) VALUES (?, ?, 'assistant', ?, ?, ?)
    `).run(
      id("message"),
      conversationId,
      input.recovery
        ? `Recovery after ${input.recovery.errorCategory}: the previous action was not repeated.\n\n${input.step.explanation}\n\nRecommended materially different step: ${input.step.title}\n\n${input.step.rationale}\n\nThis recovery remains paused until you decide on the exact represented action.`
        : `${input.step.explanation}\n\nRecommended next step: ${input.step.title}\n\n${input.step.rationale}`,
      canonicalJson({
        kind: input.recovery ? "guided_recovery_step" : "guided_step",
        planId: input.planId,
        stepId: input.stepId,
        decisionId: input.decisionId,
        ...(input.recovery ? {
          recoveryOfActionId: input.recovery.failedActionId,
          failedActionFingerprint: input.recovery.actionFingerprint,
          errorCategory: input.recovery.errorCategory,
          nextConsequentialActionRequiresDecision: true,
        } : {}),
        objective: input.step.objective,
        prerequisites: input.step.dependencyOrdinals ?? [],
        risk: input.step.riskClass,
        reversibility: input.step.reversibility,
        action: input.step.action,
        expectedSuccess: input.step.successCriteria,
      }),
      input.now,
    );
  }

  getStepIntent(stepId: string): PersistedPlanResult["firstIntent"] {
    const row = this.database.prepare(`
      SELECT ps.id, ps.run_id, ps.plan_id, ps.assigned_agent_id, p.version,
        r.mission_id, mc.value_json AS representation_json,
        a.id AS assignment_id
      FROM plan_steps ps
      JOIN plans p ON p.id = ps.plan_id
      JOIN runs r ON r.id = ps.run_id
      JOIN mission_constraints mc ON mc.source = ps.id AND mc.constraint_type = 'represented_action'
      JOIN assignments a ON a.step_id = ps.id AND a.run_id = ps.run_id
        AND a.agent_id = ps.assigned_agent_id
      WHERE ps.id = ?
      ORDER BY a.created_at DESC, a.id DESC LIMIT 1
    `).get(stepId) as {
      id: string; run_id: string; mission_id: string; version: number;
      representation_json: string; assignment_id: string;
    } | undefined;
    if (!row) throw new CommandRuntimeError(404, "step_not_found", `Step not found: ${stepId}`);
    const represented = parseRepresentation(row.representation_json);
    return this.toIntent({
      missionId: row.mission_id,
      runId: row.run_id,
      planVersion: row.version,
      stepId: row.id,
      assignmentId: row.assignment_id,
      action: represented.action,
    });
  }

  markStepRunning(stepId: string, now: string): void {
    const result = this.database.prepare(`
      UPDATE plan_steps SET status = 'running', started_at = COALESCE(started_at, ?), updated_at = ?
      WHERE id = ? AND status IN ('ready', 'waiting_guided_decision')
    `).run(now, now, stepId);
    if (result.changes !== 1) {
      const row = this.database.prepare("SELECT status FROM plan_steps WHERE id = ?")
        .get(stepId) as { status: string } | undefined;
      if (row?.status !== "running") {
        throw new CommandRuntimeError(409, "step_not_ready", "The represented step is not ready to execute", {
          humanMessage: "This step changed before execution and was not repeated.",
          category: "conflict",
        });
      }
    }
    this.database.prepare(`
      UPDATE assignments SET status = 'active', started_at = COALESCE(started_at, ?), updated_at = ?
      WHERE step_id = ? AND status = 'queued'
    `).run(now, now, stepId);
  }

  private stepForDecision(stepId: string): {
    missionId: string;
    runId: string;
    planId: string;
    planVersion: number;
    step: MissionPlanDraft["steps"][number];
    intent: PersistedPlanResult["firstIntent"];
  } {
    const stored = this.database.prepare(`
      SELECT ps.*, p.version, r.mission_id, mc.value_json AS representation_json
      FROM plan_steps ps
      JOIN plans p ON p.id = ps.plan_id
      JOIN runs r ON r.id = ps.run_id
      JOIN mission_constraints mc ON mc.source = ps.id AND mc.constraint_type = 'represented_action'
      WHERE ps.id = ?
    `).get(stepId) as StepRow & {
      run_id: string; plan_id: string; version: number; mission_id: string;
    } | undefined;
    if (!stored) throw new CommandRuntimeError(404, "step_not_found", `Step not found: ${stepId}`);
    const represented = parseRepresentation(stored.representation_json);
    const intent = this.getStepIntent(stepId);
    return {
      missionId: stored.mission_id,
      runId: stored.run_id,
      planId: stored.plan_id,
      planVersion: stored.version,
      intent,
      step: {
        phase: stored.phase,
        title: stored.title,
        objective: stored.objective,
        explanation: represented.explanation,
        rationale: represented.rationale,
        successCriteria: jsonArray(stored.success_criteria_json),
        assignedAgentId: stored.assigned_agent_id ?? "",
        riskClass: (stored.risk_class ?? "low") as MissionPlanDraft["steps"][number]["riskClass"],
        reversibility: represented.reversibility,
        action: represented.action,
      },
    };
  }

  createDecisionForStep(stepId: string, now: string, decisionTtlMs: number): {
    decisionId: string;
    intent: PersistedPlanResult["firstIntent"];
  } {
    const existing = this.database.prepare(`
      SELECT id FROM guided_decisions WHERE step_id = ? AND status = 'pending'
      ORDER BY created_at DESC LIMIT 1
    `).get(stepId) as { id: string } | undefined;
    const details = this.stepForDecision(stepId);
    if (existing) return { decisionId: existing.id, intent: details.intent };
    const decisionId = this.createGuidedDecision({
      missionId: details.missionId,
      runId: details.runId,
      stepId,
      intent: details.intent,
      rationale: `${details.step.explanation}\n\nWhy this matters: ${details.step.rationale}`,
      riskClass: details.step.riskClass,
      reversibility: details.step.reversibility,
      now,
      expiresAt: new Date(Date.parse(now) + decisionTtlMs).toISOString(),
    });
    this.persistGuidedExplanation({
      missionId: details.missionId,
      runId: details.runId,
      stepId,
      planId: details.planId,
      step: details.step,
      decisionId,
      now,
    });
    return { decisionId, intent: details.intent };
  }

  advanceSuccessfulStep(input: {
    runId: string;
    stepId: string;
    actionId: string;
    journey: Journey;
    now: string;
    decisionTtlMs: number;
  }): StepAdvanceResult {
    const current = this.database.prepare(`
      SELECT ps.plan_id, ps.ordinal, p.version, r.mission_id
      FROM plan_steps ps JOIN plans p ON p.id = ps.plan_id
      JOIN runs r ON r.id = ps.run_id
      WHERE ps.id = ? AND ps.run_id = ?
    `).get(input.stepId, input.runId) as {
      plan_id: string; ordinal: number; version: number; mission_id: string;
    } | undefined;
    if (!current) throw new CommandRuntimeError(404, "step_not_found", "Completed step is not part of this run");
    this.database.prepare(`
      UPDATE plan_steps SET status = 'completed', ended_at = ?, updated_at = ? WHERE id = ?
    `).run(input.now, input.now, input.stepId);
    this.database.prepare(`
      UPDATE assignments SET status = 'completed', ended_at = ?, updated_at = ? WHERE step_id = ?
    `).run(input.now, input.now, input.stepId);
    const counts = this.database.prepare(`
      SELECT COUNT(*) AS total,
        SUM(CASE WHEN status IN ('completed', 'skipped') THEN 1 ELSE 0 END) AS complete
      FROM plan_steps WHERE plan_id = ?
    `).get(current.plan_id) as { total: number; complete: number };
    const next = this.database.prepare(`
      SELECT id, title, assigned_agent_id FROM plan_steps
      WHERE plan_id = ? AND ordinal > ? AND status = 'pending'
      ORDER BY ordinal LIMIT 1
    `).get(current.plan_id, current.ordinal) as {
      id: string; title: string; assigned_agent_id: string;
    } | undefined;
    let guidedDecisionId: string | null = null;
    let nextIntent: PersistedPlanResult["firstIntent"] | null = null;
    if (next) {
      this.database.prepare(`
        UPDATE plan_steps SET status = 'ready', updated_at = ? WHERE id = ?
      `).run(input.now, next.id);
      if (input.journey === "guided") {
        const prepared = this.createDecisionForStep(next.id, input.now, input.decisionTtlMs);
        guidedDecisionId = prepared.decisionId;
        nextIntent = prepared.intent;
        this.database.prepare(`
          UPDATE plan_steps SET status = 'waiting_guided_decision', updated_at = ? WHERE id = ?
        `).run(input.now, next.id);
      } else {
        nextIntent = this.getStepIntent(next.id);
      }
      this.database.prepare(`
        UPDATE runs SET current_step_id = ?, current_owner_id = ?, progress = ?,
          next_action_summary = ?, updated_at = ? WHERE id = ?
      `).run(
        next.id,
        next.assigned_agent_id,
        counts.total > 0 ? counts.complete / counts.total : 0,
        input.journey === "guided" ? `Waiting for exact decision: ${next.title}` : nextIntent!.intentSummary,
        input.now,
        input.runId,
      );
    } else {
      this.database.prepare(`
        UPDATE plans SET status = 'completed' WHERE id = ?
      `).run(current.plan_id);
      this.database.prepare(`
        UPDATE runs SET progress = 1, next_action_summary = 'Validate mission success criteria',
          updated_at = ? WHERE id = ?
      `).run(input.now, input.runId);
    }
    const event = this.events.append({
      missionId: current.mission_id,
      runId: input.runId,
      journey: input.journey,
      eventType: "step.completed",
      actorType: "worker",
      summary: next
        ? `Step completed; ${input.journey === "guided" ? "the next explained decision is ready" : "the next Autonomous action is ready"}`
        : "All planned steps completed; success validation started",
      payload: {
        stepId: input.stepId,
        actionId: input.actionId,
        nextStepId: next?.id ?? null,
        guidedDecisionId,
        progress: counts.total > 0 ? counts.complete / counts.total : 1,
      },
    });
    return {
      completed: !next,
      nextStepId: next?.id ?? null,
      nextIntent,
      guidedDecisionId,
      eventSequence: event.sequence,
    };
  }

  /**
   * Resolve one exact, currently represented Guided decision as skipped.
   *
   * This method deliberately creates no action or evidence record. The skipped
   * step and its queued assignment are terminalized, then the next dependency-
   * eligible represented step is prepared. Callers must wrap this mutation with
   * the durable run-fence/checkpoint update in the same IMMEDIATE transaction.
   */
  skipGuidedStep(input: {
    decisionId: string;
    actorId: string;
    reason: string;
    now: string;
    decisionTtlMs: number;
  }): GuidedSkipAdvanceResult {
    const decision = this.getDecision(input.decisionId);
    if (decision.status !== "pending") {
      throw new CommandRuntimeError(
        409,
        "guided_decision_not_pending",
        "Only the current pending Guided decision can be skipped",
      );
    }
    const representedIntent = this.getStepIntent(decision.stepId);
    const actualFingerprint = fingerprintAction(representedIntent).hash;
    const representedParameters = canonicalJson(representedIntent);
    const requestedParameters = canonicalJson(decision.requestedParameters);
    if (
      actualFingerprint !== decision.actionFingerprint ||
      representedParameters !== requestedParameters
    ) {
      throw new CommandRuntimeError(409, "guided_action_changed", "The represented Guided action changed", {
        humanMessage: "The decision no longer represents the exact current step and cannot be skipped from this card.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and decide on the newly represented step.",
      });
    }
    const current = this.database.prepare(`
      SELECT ps.plan_id, ps.ordinal, ps.status AS step_status,
        r.mission_id, r.journey, r.status AS run_status, r.current_step_id
      FROM plan_steps ps
      JOIN runs r ON r.id = ps.run_id
      WHERE ps.id = ? AND ps.run_id = ?
    `).get(decision.stepId, decision.runId) as {
      plan_id: string;
      ordinal: number;
      step_status: string;
      mission_id: string;
      journey: Journey;
      run_status: RunState;
      current_step_id: string | null;
    } | undefined;
    if (!current || current.journey !== "guided") {
      throw new CommandRuntimeError(409, "guided_decision_scope_mismatch", "Decision is not in a Guided run");
    }
    if (
      current.run_status !== "waiting_guided_decision" ||
      current.current_step_id !== decision.stepId ||
      current.step_status !== "waiting_guided_decision"
    ) {
      throw new CommandRuntimeError(409, "guided_decision_not_current", "Decision is not the current represented Guided step", {
        humanMessage: "This decision is stale and no longer owns the Guided checkpoint.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and use the current decision card.",
      });
    }
    const existingAction = this.database.prepare(`
      SELECT id FROM actions WHERE guided_decision_id = ? LIMIT 1
    `).get(decision.id) as { id: string } | undefined;
    if (existingAction) {
      throw new CommandRuntimeError(409, "guided_decision_already_consumed", "A represented action already exists for this decision", {
        humanMessage: "The exact step has already entered execution and cannot be relabeled as skipped.",
        category: "conflict",
      });
    }

    const parameterHash = hashJson(decision.requestedParameters);
    const decisionUpdate = this.database.prepare(`
      UPDATE guided_decisions
      SET status = 'cancelled', decision_actor = ?, decision_reason = ?, decided_at = ?
      WHERE id = ? AND status = 'pending'
    `).run(input.actorId, input.reason, input.now, decision.id);
    if (decisionUpdate.changes !== 1) {
      throw new CommandRuntimeError(409, "guided_decision_conflict", "Decision changed concurrently");
    }
    const stepUpdate = this.database.prepare(`
      UPDATE plan_steps SET status = 'skipped', ended_at = ?, updated_at = ?
      WHERE id = ? AND status = 'waiting_guided_decision'
    `).run(input.now, input.now, decision.stepId);
    if (stepUpdate.changes !== 1) {
      throw new CommandRuntimeError(409, "guided_step_conflict", "Represented step changed concurrently");
    }
    const assignmentUpdate = this.database.prepare(`
      UPDATE assignments SET status = 'cancelled', ended_at = ?, updated_at = ?
      WHERE step_id = ? AND status = 'queued'
    `).run(input.now, input.now, decision.stepId);
    if (assignmentUpdate.changes !== 1) {
      throw new CommandRuntimeError(409, "guided_assignment_conflict", "Queued Guided assignment changed concurrently");
    }

    this.events.append({
      missionId: decision.missionId,
      runId: decision.runId,
      journey: "guided",
      eventType: "guided.decision_skipped",
      actorType: "operator",
      actorId: input.actorId,
      summary: "Operator skipped the exact represented Guided step without executing it",
      payload: {
        decisionId: decision.id,
        stepId: decision.stepId,
        actionFingerprint: decision.actionFingerprint,
        parameterHash,
        reason: input.reason,
        actionCreated: false,
        evidenceCreated: false,
      },
      sensitivity: "private",
    });

    const counts = this.database.prepare(`
      SELECT COUNT(*) AS total,
        SUM(CASE WHEN status IN ('completed', 'skipped') THEN 1 ELSE 0 END) AS complete
      FROM plan_steps WHERE plan_id = ?
    `).get(current.plan_id) as { total: number; complete: number };
    const next = this.database.prepare(`
      SELECT candidate.id, candidate.title, candidate.assigned_agent_id
      FROM plan_steps candidate
      WHERE candidate.plan_id = ? AND candidate.ordinal > ? AND candidate.status = 'pending'
        AND NOT EXISTS (
          SELECT 1
          FROM json_each(candidate.dependencies_json) dependency_ref
          JOIN plan_steps dependency ON dependency.id = dependency_ref.value
          WHERE dependency.status NOT IN ('completed', 'skipped')
        )
      ORDER BY candidate.ordinal
      LIMIT 1
    `).get(current.plan_id, current.ordinal) as {
      id: string;
      title: string;
      assigned_agent_id: string | null;
    } | undefined;
    const unresolved = this.database.prepare(`
      SELECT COUNT(*) AS count FROM plan_steps
      WHERE plan_id = ? AND status = 'pending'
    `).get(current.plan_id) as { count: number };
    if (!next && unresolved.count > 0) {
      throw new CommandRuntimeError(409, "guided_step_dependencies_blocked", "No dependency-eligible Guided step remains", {
        humanMessage: "The selected step was not skipped because the remaining plan has unresolved dependencies.",
        category: "conflict",
        remediation: "Review or amend the plan before choosing another step.",
      });
    }

    let guidedDecisionId: string | null = null;
    if (next) {
      this.database.prepare(`
        UPDATE plan_steps SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'pending'
      `).run(input.now, next.id);
      const prepared = this.createDecisionForStep(next.id, input.now, input.decisionTtlMs);
      guidedDecisionId = prepared.decisionId;
      this.database.prepare(`
        UPDATE plan_steps SET status = 'waiting_guided_decision', updated_at = ?
        WHERE id = ? AND status = 'ready'
      `).run(input.now, next.id);
      this.database.prepare(`
        UPDATE runs SET current_step_id = ?, current_owner_id = ?, progress = ?,
          next_action_summary = ?, updated_at = ? WHERE id = ?
      `).run(
        next.id,
        next.assigned_agent_id,
        counts.total > 0 ? counts.complete / counts.total : 0,
        `Waiting for exact decision: ${next.title}`,
        input.now,
        decision.runId,
      );
    } else {
      this.database.prepare("UPDATE plans SET status = 'completed' WHERE id = ?")
        .run(current.plan_id);
      this.database.prepare(`
        UPDATE runs SET progress = 1, current_step_id = NULL, current_owner_id = NULL,
          next_action_summary = 'Validate mission success criteria', updated_at = ? WHERE id = ?
      `).run(input.now, decision.runId);
    }

    this.appendAudit({
      missionId: decision.missionId,
      runId: decision.runId,
      actorId: input.actorId,
      action: "guided.decision_skipped",
      resourceType: "guided_decision",
      resourceId: decision.id,
      reason: input.reason,
      details: {
        stepId: decision.stepId,
        actionFingerprint: decision.actionFingerprint,
        parameterHash,
        nextDecisionId: guidedDecisionId,
        actionCreated: false,
        evidenceCreated: false,
      },
      now: input.now,
    });
    const latest = this.database.prepare(`
      SELECT last_sequence FROM run_event_sequences WHERE run_id = ?
    `).get(decision.runId) as { last_sequence: number };
    return {
      completed: !next,
      skippedStepId: decision.stepId,
      nextStepId: next?.id ?? null,
      guidedDecisionId,
      eventSequence: latest.last_sequence,
      actionFingerprint: decision.actionFingerprint,
      parameterHash,
    };
  }

  createManualAction(input: {
    decision: GuidedDecisionProjection;
    summary: string;
    now: string;
  }): string {
    const intent = this.getStepIntent(input.decision.stepId);
    const actualFingerprint = fingerprintAction(intent).hash;
    if (actualFingerprint !== input.decision.actionFingerprint) {
      throw new CommandRuntimeError(409, "guided_action_changed", "The represented Guided action changed", {
        humanMessage: "The action no longer matches the decision card and needs a new decision.",
        category: "conflict",
      });
    }
    const actions = new ActionRepository(this.database);
    const action = actions.create({
      intent,
      fingerprint: actualFingerprint,
      guidedDecisionId: input.decision.id,
      now: input.now,
    });
    const completed = actions.complete({
      actionId: action.id,
      success: true,
      summary: input.summary,
      progressSignature: progressSignature({
        stepStates: { [input.decision.stepId]: "completed" },
        verifiedWorkerResultIds: [action.id],
      }),
      now: input.now,
    });
    this.events.append({
      missionId: input.decision.missionId,
      runId: input.decision.runId,
      journey: "guided",
      eventType: "action.completed",
      actorType: "operator",
      summary: "Operator supplied the result for the represented manual action",
      payload: {
        actionId: completed.id,
        actionFingerprint: completed.fingerprint,
        actionKind: "manual",
        meaningfulProgress: true,
        progressDimensions: ["step_state", "verified_result"],
        progressSignatureAfter: completed.progressSignature,
        completedAt: input.now,
        errorCategory: null,
        loopKinds: [],
        directive: "continue",
      },
    });
    return action.id;
  }

  /**
   * Retain one immutable, content-addressed record for an accepted Guided
   * manual result. Operator attestation is explicit in provenance and is the
   * verification basis; raw content remains in the private evidence record,
   * never in semantic events or audit prose.
   */
  createManualEvidence(input: {
    decision: GuidedDecisionProjection;
    actionId: string;
    actorId: string;
    content: string;
    now: string;
  }): ManualEvidenceReceipt {
    const action = new ActionRepository(this.database).get(input.actionId);
    if (
      action.missionId !== input.decision.missionId ||
      action.runId !== input.decision.runId ||
      action.stepId !== input.decision.stepId ||
      action.guidedDecisionId !== input.decision.id
    ) {
      throw new CommandRuntimeError(409, "manual_evidence_action_mismatch", "Manual evidence does not match its represented action", {
        humanMessage: "The manual result could not be linked to the unchanged Guided action.",
        category: "conflict",
      });
    }
    const contentHash = createHash("sha256").update(input.content, "utf8").digest("hex");
    const byteSize = Buffer.byteLength(input.content, "utf8");
    const existing = this.database.prepare(`
      SELECT id, content_hash FROM evidence
      WHERE action_id = ? AND evidence_type = 'guided_manual_result'
      ORDER BY created_at, id LIMIT 1
    `).get(input.actionId) as { id: string; content_hash: string } | undefined;
    if (existing) {
      if (existing.content_hash !== contentHash) {
        throw new CommandRuntimeError(409, "manual_evidence_immutable_conflict", "A different result is already retained for this action", {
          humanMessage: "This exact Guided action already has an immutable manual result.",
          category: "conflict",
        });
      }
      return {
        id: existing.id,
        contentHash,
        byteSize,
        verificationState: "verified",
        deduplicated: true,
      };
    }

    const evidenceId = id("evidence");
    const provenance = {
      method: "operator_attestation",
      operatorId: input.actorId,
      decisionId: input.decision.id,
      representedActionFingerprint: input.decision.actionFingerprint,
      actionId: action.id,
      contentAddressedBy: "sha256",
      byteSize,
      contentRetainedInPrivateEvidence: true,
      contentExcludedFromSemanticEvents: true,
    };
    this.database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, action_id, source, acquired_at,
        target, evidence_type, content_hash, provenance_json, confidence,
        sensitivity, verification_state, summary, extracted_text,
        artifact_id, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, 'guided.operator_manual_result', ?, ?,
        'guided_manual_result', ?, ?, 0.8, 'private', 'verified', ?, ?, NULL, ?, ?)
    `).run(
      evidenceId,
      input.decision.missionId,
      input.decision.runId,
      input.decision.stepId,
      action.id,
      input.now,
      action.target || null,
      contentHash,
      canonicalJson(provenance),
      "Operator supplied the result for an exact Guided action",
      input.content,
      input.actorId,
      input.now,
    );
    const insertChain = this.database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);
    insertChain.run(
      id("evidence-chain"),
      evidenceId,
      "acquired",
      input.actorId,
      canonicalJson({ actionId: action.id, decisionId: input.decision.id, contentHash, byteSize }),
      input.now,
    );
    insertChain.run(
      id("evidence-chain"),
      evidenceId,
      "verified",
      input.actorId,
      canonicalJson({ method: "operator_attestation", actionFingerprint: input.decision.actionFingerprint }),
      input.now,
    );
    this.events.append({
      missionId: input.decision.missionId,
      runId: input.decision.runId,
      journey: "guided",
      eventType: "evidence.guided_manual_result_acquired",
      actorType: "operator",
      actorId: input.actorId,
      summary: "Operator supplied private evidence for an exact Guided action",
      payload: {
        evidenceId,
        decisionId: input.decision.id,
        stepId: input.decision.stepId,
        actionId: action.id,
        contentHash,
        byteSize,
        verificationState: "verified",
      },
      sensitivity: "private",
      redaction: { operatorSuppliedContent: "retained_in_private_evidence_only" },
    });
    this.appendAudit({
      missionId: input.decision.missionId,
      runId: input.decision.runId,
      actorId: input.actorId,
      action: "evidence.guided_manual_result_acquired",
      resourceType: "evidence",
      resourceId: evidenceId,
      reason: "Retained operator-attested evidence for the exact Guided action",
      details: {
        decisionId: input.decision.id,
        stepId: input.decision.stepId,
        actionId: action.id,
        contentHash,
        byteSize,
        verificationState: "verified",
      },
      now: input.now,
    });
    return { id: evidenceId, contentHash, byteSize, verificationState: "verified", deduplicated: false };
  }

  /** Create an immutable verified derivative of reviewed source evidence. */
  promoteInterpretedGuidedEvidence(input: {
    decision: GuidedDecisionProjection;
    actionId: string;
    evidenceId: string;
    actorId: string;
    now: string;
  }): ManualEvidenceReceipt {
    const action = new ActionRepository(this.database).get(input.actionId);
    if (
      action.missionId !== input.decision.missionId ||
      action.runId !== input.decision.runId ||
      action.stepId !== input.decision.stepId ||
      action.guidedDecisionId !== input.decision.id
    ) {
      throw new CommandRuntimeError(409, "manual_evidence_action_mismatch", "Reviewed evidence does not match its represented action", {
        humanMessage: "The reviewed observation could not be linked to the unchanged Guided action.",
        category: "conflict",
      });
    }
    const row = this.database.prepare(`
      SELECT mission_id, run_id, step_id, action_id, evidence_type,
        content_hash, provenance_json, verification_state, target,
        sensitivity, extracted_text
      FROM evidence WHERE id = ?
    `).get(input.evidenceId) as {
      mission_id: string;
      run_id: string | null;
      step_id: string | null;
      action_id: string | null;
      evidence_type: string;
      content_hash: string;
      provenance_json: string;
      verification_state: string;
      target: string | null;
      sensitivity: "public" | "internal" | "private" | "restricted";
      extracted_text: string | null;
    } | undefined;
    if (!row) {
      throw new CommandRuntimeError(404, "guided_evidence_not_found", "Reviewed Guided evidence was not found", {
        category: "not_found",
      });
    }
    const provenance = parseObject(row.provenance_json);
    const interpreted = this.database.prepare(`
      SELECT details_json FROM evidence_chain_events
      WHERE evidence_id = ? AND event_type = 'interpreted'
      ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get(input.evidenceId) as { details_json: string } | undefined;
    if (
      row.mission_id !== input.decision.missionId ||
      row.run_id !== input.decision.runId ||
      row.step_id !== input.decision.stepId ||
      row.evidence_type !== "guided_text_result" ||
      row.action_id !== null ||
      row.verification_state !== "unverified" ||
      provenance.representedActionFingerprint !== input.decision.actionFingerprint ||
      !interpreted
    ) {
      throw new CommandRuntimeError(409, "guided_evidence_scope_conflict", "Reviewed evidence does not belong to this exact Guided decision", {
        humanMessage: "Interpret output from the current exact action before completing this step.",
        category: "scope_conflict",
        remediation: "Refresh the Guided workspace and submit output for the unchanged represented step.",
      });
    }
    const existing = this.database.prepare(`
      SELECT id FROM evidence
      WHERE action_id = ? AND evidence_type = 'guided_manual_result'
        AND json_extract(provenance_json, '$.originalEvidenceId') = ?
      ORDER BY created_at, id LIMIT 1
    `).get(action.id, input.evidenceId) as { id: string } | undefined;
    if (existing) {
      return {
        id: existing.id,
        contentHash: row.content_hash,
        byteSize: Number(provenance.byteSize ?? 0),
        verificationState: "verified",
        deduplicated: true,
      };
    }
    const interpretation = parseObject(interpreted.details_json);
    const interpretationSummary = typeof interpretation.summary === "string"
      ? interpretation.summary
      : "Operator reviewed the Guided result interpretation";
    const verifiedEvidenceId = id("evidence");
    const byteSize = Number(provenance.byteSize ?? Buffer.byteLength(row.extracted_text ?? "", "utf8"));
    this.database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, action_id, source, acquired_at,
        target, evidence_type, content_hash, provenance_json, confidence,
        sensitivity, verification_state, summary, extracted_text,
        artifact_id, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, 'guided.operator_manual_result', ?, ?,
        'guided_manual_result', ?, ?, 0.8, ?, 'verified', ?, ?, NULL, ?, ?)
    `).run(
      verifiedEvidenceId,
      input.decision.missionId,
      input.decision.runId,
      input.decision.stepId,
      action.id,
      input.now,
      row.target,
      row.content_hash,
      canonicalJson({
        method: "operator_attestation_after_interpretation",
        originalEvidenceId: input.evidenceId,
        originalContentHash: row.content_hash,
        interpretationMessageId: interpretation.assistantMessageId ?? null,
        contextPackId: interpretation.contextPackId ?? null,
        operatorAttestedAt: input.now,
        operatorId: input.actorId,
        decisionId: input.decision.id,
        actionId: action.id,
        representedActionFingerprint: input.decision.actionFingerprint,
        byteSize,
      }),
      row.sensitivity,
      interpretationSummary,
      row.extracted_text,
      input.actorId,
      input.now,
    );
    this.database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'derived', ?, ?, ?), (?, ?, 'verified', ?, ?, ?)
    `).run(
      id("evidence-chain"),
      verifiedEvidenceId,
      input.actorId,
      canonicalJson({ originalEvidenceId: input.evidenceId, contentHash: row.content_hash }),
      input.now,
      id("evidence-chain"),
      verifiedEvidenceId,
      input.actorId,
      canonicalJson({
        method: "operator_attestation_after_interpretation",
        decisionId: input.decision.id,
        actionId: action.id,
        actionFingerprint: input.decision.actionFingerprint,
      }),
      input.now,
    );
    this.events.append({
      missionId: input.decision.missionId,
      runId: input.decision.runId,
      journey: "guided",
      eventType: "evidence.guided_interpretation_verified",
      actorType: "operator",
      actorId: input.actorId,
      summary: "Operator accepted the interpretation and verified evidence for the exact Guided action",
      payload: {
        evidenceId: verifiedEvidenceId,
        originalEvidenceId: input.evidenceId,
        decisionId: input.decision.id,
        stepId: input.decision.stepId,
        actionId: action.id,
        contentHash: row.content_hash,
        verificationState: "verified",
      },
      sensitivity: "private",
    });
    this.appendAudit({
      missionId: input.decision.missionId,
      runId: input.decision.runId,
      actorId: input.actorId,
      action: "evidence.guided_interpretation_verified",
      resourceType: "evidence",
      resourceId: verifiedEvidenceId,
      reason: "Operator accepted the persisted interpretation for the exact Guided action",
      details: {
        decisionId: input.decision.id,
        stepId: input.decision.stepId,
        actionId: action.id,
        contentHash: row.content_hash,
        originalEvidenceId: input.evidenceId,
      },
      now: input.now,
    });
    return {
      id: verifiedEvidenceId,
      contentHash: row.content_hash,
      byteSize,
      verificationState: "verified",
      deduplicated: false,
    };
  }

  getDecision(decisionId: string): GuidedDecisionProjection {
    const row = this.database.prepare("SELECT * FROM guided_decisions WHERE id = ?")
      .get(decisionId) as DecisionRow | undefined;
    if (!row) throw new CommandRuntimeError(404, "guided_decision_not_found", `Decision not found: ${decisionId}`);
    return mapDecision(row);
  }

  /**
   * Resolve the one pending decision that currently owns a Guided checkpoint.
   *
   * This assertion is intentionally repository-owned so HTTP handlers, direct
   * engine calls, crash continuations, and future adapters cannot validate only
   * a decision row while overlooking a changed run, plan, or represented step.
   */
  requireCurrentPendingDecision(decisionId: string): GuidedDecisionProjection {
    const decision = this.getDecision(decisionId);
    if (decision.status !== "pending") {
      throw new CommandRuntimeError(409, "guided_decision_not_pending", "Only a pending Guided decision can use this control", {
        humanMessage: "This exact-step control is stale. Refresh the current Guided checkpoint.",
        category: "conflict",
      });
    }

    const boundary = this.database.prepare(`
      SELECT r.mission_id, r.journey, r.status AS run_status,
        r.current_plan_id, r.current_step_id,
        ps.run_id AS step_run_id, ps.plan_id AS step_plan_id,
        ps.status AS step_status,
        p.run_id AS plan_run_id, p.status AS plan_status,
        (
          SELECT COUNT(*) FROM guided_decisions pending
          WHERE pending.run_id = gd.run_id AND pending.status = 'pending'
        ) AS pending_count
      FROM guided_decisions gd
      JOIN runs r ON r.id = gd.run_id
      JOIN plan_steps ps ON ps.id = gd.step_id
      JOIN plans p ON p.id = ps.plan_id
      WHERE gd.id = ?
    `).get(decision.id) as {
      mission_id: string;
      journey: Journey;
      run_status: RunState;
      current_plan_id: string | null;
      current_step_id: string | null;
      step_run_id: string;
      step_plan_id: string;
      step_status: string;
      plan_run_id: string;
      plan_status: string;
      pending_count: number;
    } | undefined;

    if (!boundary) {
      throw new CommandRuntimeError(409, "guided_step_stale", "The represented Guided step is no longer current", {
        humanMessage: "This exact-step control no longer resolves to a current Guided run, plan, and step.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and use the one current decision card.",
      });
    }
    if (boundary.pending_count !== 1) {
      throw new CommandRuntimeError(409, "guided_pending_decision_conflict", "Guided decision ownership is ambiguous", {
        humanMessage: "The run does not have exactly one pending Guided decision, so no decision was applied.",
        category: "conflict",
        remediation: "Keep the run blocked and reconcile its Guided decisions before resuming.",
      });
    }
    if (
      boundary.journey !== "guided" ||
      boundary.mission_id !== decision.missionId ||
      boundary.run_status !== "waiting_guided_decision" ||
      boundary.current_step_id !== decision.stepId ||
      boundary.current_plan_id !== boundary.step_plan_id ||
      boundary.step_run_id !== decision.runId ||
      boundary.plan_run_id !== decision.runId ||
      boundary.plan_status !== "active" ||
      boundary.step_status !== "waiting_guided_decision"
    ) {
      throw new CommandRuntimeError(409, "guided_step_stale", "The represented Guided step is no longer current", {
        humanMessage: "This exact-step control is stale. Review the current Guided checkpoint before deciding.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and use the one current decision card.",
      });
    }

    const representedIntent = this.getStepIntent(decision.stepId);
    if (
      fingerprintAction(representedIntent).hash !== decision.actionFingerprint ||
      canonicalJson(representedIntent) !== canonicalJson(decision.requestedParameters)
    ) {
      throw new CommandRuntimeError(409, "guided_action_changed", "The represented Guided action changed", {
        humanMessage: "The decision no longer represents the exact current fingerprint and parameters.",
        category: "conflict",
        remediation: "Refresh the Guided workspace and decide on the newly represented action.",
      });
    }
    return decision;
  }

  listDecisions(options: { status?: string; runId?: string; query?: string; limit?: number } = {}): GuidedDecisionProjection[] {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (options.status) { clauses.push("status = ?"); params.push(options.status); }
    if (options.runId) { clauses.push("run_id = ?"); params.push(options.runId); }
    if (options.query) {
      clauses.push(`instr(lower(
        id || ' ' || mission_id || ' ' || run_id || ' ' || step_id || ' ' ||
        rationale || ' ' || risk_class || ' ' || status
      ), lower(?)) > 0`);
      params.push(options.query);
    }
    const limit = options.limit ?? 100;
    params.push(limit);
    return (this.database.prepare(`
      SELECT * FROM guided_decisions ${clauses.length ? `WHERE ${clauses.join(" AND ")}` : ""}
      ORDER BY created_at DESC, id DESC LIMIT ?
    `).all(...params) as DecisionRow[]).map(mapDecision);
  }

  listPlans(runId: string): StoredPlan[] {
    const plans = this.database.prepare("SELECT * FROM plans WHERE run_id = ? ORDER BY version DESC")
      .all(runId) as PlanRow[];
    return plans.map((plan) => {
      const steps = this.database.prepare(`
        SELECT ps.*, mc.value_json AS representation_json
        FROM plan_steps ps
        LEFT JOIN mission_constraints mc
          ON mc.source = ps.id AND mc.constraint_type = 'represented_action'
        WHERE ps.plan_id = ? ORDER BY ps.ordinal
      `).all(plan.id) as StepRow[];
      return mapPlan(plan, steps);
    });
  }

  getRunProjection(runId: string): RuntimeRunProjection {
    const row = this.database.prepare(`
      SELECT r.*, m.name AS mission_name, m.objective
      FROM runs r JOIN missions m ON m.id = r.mission_id WHERE r.id = ?
    `).get(runId) as Record<string, unknown> | undefined;
    if (!row) throw new CommandRuntimeError(404, "run_not_found", `Run not found: ${runId}`);
    return mapRunProjection(row);
  }

  listRunProjections(options: {
    readonly query?: string;
    readonly journey?: Journey;
    readonly status?: RunState;
    readonly limit?: number;
  } = {}): RuntimeRunProjection[] {
    const limit = options.limit ?? 50;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new RangeError("run projection limit must be between 1 and 100");
    }
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (options.journey) { clauses.push("r.journey = ?"); params.push(options.journey); }
    if (options.status) { clauses.push("r.status = ?"); params.push(options.status); }
    if (options.query) {
      clauses.push(`instr(lower(
        r.id || ' ' || r.mission_id || ' ' || m.name || ' ' || m.objective || ' ' ||
        r.status || ' ' || coalesce(r.current_step_id, '') || ' ' ||
        coalesce(r.current_owner_id, '') || ' ' || coalesce(r.next_action_summary, '')
      ), lower(?)) > 0`);
      params.push(options.query);
    }
    const rows = this.database.prepare(`
      SELECT r.*, m.name AS mission_name, m.objective
      FROM runs r JOIN missions m ON m.id = r.mission_id
      ${clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : ""}
      ORDER BY r.updated_at DESC, r.id DESC LIMIT ?
    `).all(...params, limit) as Array<Record<string, unknown>>;
    return rows.map(mapRunProjection);
  }

  getMissionRuntime(missionId: string): {
    mission: PlanningMission;
    runs: readonly RuntimeRunProjection[];
  } {
    const mission = this.getMission(missionId);
    const ids = this.database.prepare("SELECT id FROM runs WHERE mission_id = ? ORDER BY created_at DESC")
      .all(missionId) as Array<{ id: string }>;
    return { mission, runs: ids.map((row) => this.getRunProjection(row.id)) };
  }

  findIdempotent(scope: string, key: string, request: unknown): JsonValue | undefined {
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(idempotencyKey(scope, key)) as { value_json: string } | undefined;
    if (!row) return undefined;
    const stored = JSON.parse(row.value_json) as StoredIdempotency;
    if (stored.requestHash !== hashJson(request)) {
      throw new CommandRuntimeError(409, "idempotency_key_conflict", "Idempotency key was reused with a different request", {
        humanMessage: "This command key already belongs to another mutation.",
        category: "conflict",
      });
    }
    if (stored.status === "pending") {
      throw new CommandRuntimeError(409, "idempotency_request_in_progress", "The mutation is already in progress", {
        humanMessage: "This exact command is already being processed by a fenced worker.",
        retryable: true,
        category: "conflict",
        remediation: `Retry after ${stored.leaseExpiresAt}; the same key will return the accepted result once durable.`,
      });
    }
    return stored.response;
  }

  /**
   * Reserve an async runtime mutation before execution. The reservation closes
   * the pre-check/commit/cache gap and prevents two HTTP workers from invoking
   * the same cancellation concurrently. An abandoned claim is reclaimable
   * only after its bounded lease expires.
   */
  claimIdempotent(
    scope: string,
    key: string,
    request: unknown,
    actorId: string,
    now: string,
    leaseMs = 30_000,
  ): RuntimeIdempotencyClaim {
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 5 * 60_000) {
      throw new RangeError("Runtime idempotency lease must be between 1,000 and 300,000 ms");
    }
    const nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs)) throw new RangeError("Runtime idempotency timestamp is invalid");
    const settingKey = idempotencyKey(scope, key);
    const requestHash = hashJson(request);
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(settingKey) as { value_json: string } | undefined;
    if (row) {
      const stored = JSON.parse(row.value_json) as StoredIdempotency;
      if (stored.requestHash !== requestHash) {
        throw new CommandRuntimeError(409, "idempotency_key_conflict", "Idempotency key was reused with a different request", {
          humanMessage: "This command key already belongs to another mutation.",
          category: "conflict",
        });
      }
      if (stored.status !== "pending") return { kind: "completed", response: stored.response };
      if (Date.parse(stored.leaseExpiresAt) > nowMs) {
        return { kind: "in_progress", leaseExpiresAt: stored.leaseExpiresAt };
      }
    }

    const ownerToken = randomUUID();
    const leaseExpiresAt = new Date(nowMs + leaseMs).toISOString();
    const value = canonicalJson({ requestHash, status: "pending", ownerToken, leaseExpiresAt });
    this.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
        version = settings.version + 1, updated_by = excluded.updated_by,
        updated_at = excluded.updated_at
    `).run(settingKey, value, actorId, now);
    return { kind: "claimed", ownerToken };
  }

  heartbeatIdempotentClaim(
    scope: string,
    key: string,
    request: unknown,
    ownerToken: string,
    actorId: string,
    now: string,
    leaseMs = 30_000,
  ): string {
    if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 5 * 60_000) {
      throw new RangeError("Runtime idempotency lease must be between 1,000 and 300,000 ms");
    }
    const nowMs = Date.parse(now);
    if (!Number.isFinite(nowMs)) throw new RangeError("Runtime idempotency timestamp is invalid");
    const settingKey = idempotencyKey(scope, key);
    const requestHash = hashJson(request);
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(settingKey) as { value_json: string } | undefined;
    if (!row) {
      throw new CommandRuntimeError(409, "idempotency_claim_missing", "The runtime mutation claim no longer exists", {
        category: "conflict",
      });
    }
    const stored = JSON.parse(row.value_json) as StoredIdempotency;
    if (stored.requestHash !== requestHash || stored.status !== "pending" || stored.ownerToken !== ownerToken) {
      throw new CommandRuntimeError(409, "idempotency_claim_fence_lost", "The runtime mutation claim belongs to another worker", {
        humanMessage: "This worker no longer owns the command reservation.",
        retryable: true,
        category: "conflict",
      });
    }
    const leaseExpiresAt = new Date(nowMs + leaseMs).toISOString();
    this.database.prepare(`
      UPDATE settings SET value_json = ?, version = version + 1,
        updated_by = ?, updated_at = ? WHERE key = ?
    `).run(
      canonicalJson({ ...stored, leaseExpiresAt }),
      actorId,
      now,
      settingKey,
    );
    return leaseExpiresAt;
  }

  completeIdempotentClaim(
    scope: string,
    key: string,
    request: unknown,
    response: JsonValue,
    ownerToken: string,
    actorId: string,
    now: string,
  ): JsonValue {
    const settingKey = idempotencyKey(scope, key);
    const requestHash = hashJson(request);
    const row = this.database.prepare("SELECT value_json FROM settings WHERE key = ?")
      .get(settingKey) as { value_json: string } | undefined;
    if (!row) {
      throw new CommandRuntimeError(409, "idempotency_claim_missing", "The runtime mutation has no durable idempotency claim", {
        humanMessage: "The command reservation was lost before its result could be committed.",
        category: "conflict",
        remediation: "Retry with a new command key after refreshing canonical run state.",
      });
    }
    const stored = JSON.parse(row.value_json) as StoredIdempotency;
    if (stored.requestHash !== requestHash) {
      throw new CommandRuntimeError(409, "idempotency_key_conflict", "Idempotency key was reused with a different request", {
        humanMessage: "This command key already belongs to another mutation.",
        category: "conflict",
      });
    }
    if (stored.status !== "pending") return stored.response;
    if (stored.ownerToken !== ownerToken) {
      throw new CommandRuntimeError(409, "idempotency_claim_fence_lost", "The runtime mutation claim belongs to another worker", {
        humanMessage: "This worker's command reservation expired and was fenced by a newer owner.",
        retryable: true,
        category: "conflict",
        remediation: "Retry the same command key to obtain the canonical accepted result.",
      });
    }
    this.database.prepare(`
      UPDATE settings SET value_json = ?, version = version + 1,
        updated_by = ?, updated_at = ? WHERE key = ?
    `).run(
      canonicalJson({ requestHash, status: "completed", response }),
      actorId,
      now,
      settingKey,
    );
    return response;
  }

  storeIdempotent(scope: string, key: string, request: unknown, response: JsonValue, actorId: string, now: string): void {
    this.database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES (?, ?, 'private', 1, ?, ?)
    `).run(
      idempotencyKey(scope, key),
      canonicalJson({ requestHash: hashJson(request), response }),
      actorId,
      now,
    );
  }

  appendAudit(input: {
    missionId: string;
    runId: string;
    actorId: string;
    action: string;
    resourceType: string;
    resourceId: string;
    reason: string;
    details?: JsonValue;
    now: string;
  }): void {
    const scope = this.database.prepare(`
      SELECT r.journey AS run_journey, m.journey AS mission_journey
      FROM missions m LEFT JOIN runs r ON r.id = ?
      WHERE m.id = ?
    `).get(input.runId, input.missionId) as {
      run_journey: Journey | null;
      mission_journey: Journey;
    } | undefined;
    if (!scope || !scope.run_journey || scope.run_journey !== scope.mission_journey) {
      throw new CommandRuntimeError(409, "audit_journey_scope_mismatch", "Audit scope has no single canonical journey");
    }
    const journey = scope.run_journey;
    const previous = this.database.prepare(`
      SELECT record_hash FROM audit_records ORDER BY occurred_at DESC, id DESC LIMIT 1
    `).get() as { record_hash: string } | undefined;
    const auditId = id("audit");
    const details = input.details ?? {};
    const recordHash = hashJson({
      id: auditId,
      previousHash: previous?.record_hash ?? null,
      journey,
      ...input,
      details,
    });
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action, resource_type,
        resource_id, reason, details_json, previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, 'operator', ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      auditId, input.missionId, input.runId, journey, input.actorId, input.action,
      input.resourceType, input.resourceId, input.reason, canonicalJson(details),
      previous?.record_hash ?? null, recordHash, input.now,
    );
  }

  transaction<T>(operation: () => T): T {
    return inImmediateTransaction(this.database, operation);
  }
}

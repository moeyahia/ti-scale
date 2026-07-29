import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { ACTION_CLASS_DEFINITIONS } from "../domain/action-class-registry";
import { evaluateDestructiveAuthorization } from "../domain/destructive-policy";
import { isActionClassId } from "../domain/catalog-ids";
import { EventRepository } from "../events/EventRepository";
import type { JsonValue as EventJsonValue } from "../events/types";
import { planContentFingerprint, planVersionReceiptHash } from "../command-runtime/PlanFingerprint";
import { RuntimeRepository } from "../command-runtime/RuntimeRepository";
import type { PlannedStep } from "../command-runtime/types";
import { ActionRepository, CheckpointRepository, RunRepository } from "../orchestration";
import type {
  ApplyPlanChangeInput,
  CreatePlanChangeInput,
  EditPlanChangeInput,
  FinalizePlanChangeInflightInput,
  NormalizedPlanChange,
  PlanChangeActor,
  PlanChangeAffectedWorkStopReceipt,
  PlanChangeAffectedRefs,
  PlanChangeBudgetImpact,
  PlanChangeDependencyImpact,
  PlanChangeDiffEntry,
  PlanChangeInflightImpact,
  PlanChangeInflightResolution,
  PlanChangeJson,
  PlanChangeOperation,
  PlanChangePolicyValidation,
  PlanChangeReadinessImpact,
  PlanChangeRequest,
  RejectPlanChangeInput,
  ResolvePlanChangeInflightInput,
} from "./types";
import { PlanChangeError } from "./types";
import { PlanChangeRepository, type PersistPlanChangeEvaluation } from "./PlanChangeRepository";
import { validatePersistedPlanStepRepresentation } from "./validation";

interface RunRow {
  readonly id: string;
  readonly mission_id: string;
  readonly journey: "autonomous" | "guided";
  readonly status: string;
  readonly current_plan_id: string | null;
  readonly current_step_id: string | null;
  readonly contract_id: string | null;
  readonly lease_owner: string | null;
  readonly started_at: string | null;
  readonly version: number;
}

interface PlanRow {
  readonly id: string;
  readonly run_id: string;
  readonly version: number;
  readonly status: string;
  readonly strategy_summary: string;
  readonly rationale_summary: string | null;
}

interface StepRow {
  readonly id: string;
  readonly ordinal: number;
  readonly phase: string;
  readonly title: string;
  readonly objective: string;
  readonly status: string;
  readonly success_criteria_json: string;
  readonly dependencies_json: string;
  readonly action_class: string | null;
  readonly risk_class: string | null;
  readonly assigned_agent_id: string | null;
  readonly representation_json: string | null;
}

interface WorkingStep {
  readonly logicalId: string;
  readonly sourceStepId: string | null;
  readonly sourceStatus: string | null;
  phase: string;
  title: string;
  objective: string;
  successCriteria: string[];
  dependencyStepIds: string[];
  actionClass: string | null;
  riskClass: string | null;
  assignedAgentId: string | null;
  representation: PlanChangeJson | null;
}

interface WorkingPlan {
  strategySummary: string;
  rationaleSummary: string | null;
  steps: WorkingStep[];
}

interface Evaluation extends PersistPlanChangeEvaluation {
  readonly workingPlan: WorkingPlan;
}

const SAFE_BASE_STEP_STATES = new Set(["pending", "ready"]);
const RISK_CLASSES = new Set(["low", "medium", "high", "critical"]);
const DEFAULT_ACTION_POLICY = new Map(ACTION_CLASS_DEFINITIONS.map((entry) => [entry.id, entry.defaultPolicyState]));
const INFLIGHT_SETTLE_TIMEOUT_MS = 5 * 60 * 1_000;

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonical(value: PlanChangeJson): string {
  const sort = (item: PlanChangeJson): PlanChangeJson => {
    if (Array.isArray(item)) return item.map(sort);
    if (item && typeof item === "object") {
      return Object.fromEntries(Object.entries(item).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, sort(child)]));
    }
    return item;
  };
  return JSON.stringify(sort(value));
}

function parseStringArray(value: string, label: string): string[] {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw corrupt(label); }
  if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== "string")) throw corrupt(label);
  return [...parsed];
}

function parseJsonValue(value: string, label: string): PlanChangeJson {
  try { return jsonValue(JSON.parse(value)); } catch { throw corrupt(label); }
}

function parseObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch { return {}; }
}

function corrupt(label: string): PlanChangeError {
  return new PlanChangeError("plan_change_source_corrupt", `${label} is malformed`, "state_conflict", 500, "Run database integrity verification and reconcile the source plan before changing it.");
}

function conflict(code: string, message: string, remediation: string): PlanChangeError {
  return new PlanChangeError(code, message, "state_conflict", 409, remediation);
}

function jsonValue(value: unknown): PlanChangeJson {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new TypeError("Value is not JSON-safe");
  return JSON.parse(serialized) as PlanChangeJson;
}

function isJsonObject(value: PlanChangeJson | null | undefined): value is { readonly [key: string]: PlanChangeJson } {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Deterministic plan-amendment service. It normalizes and validates operator
 * intent but never invokes a provider, tool, worker, or execution adapter.
 */
export class PlanChangeService {
  readonly repository: PlanChangeRepository;
  private readonly events: EventRepository;

  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
    idFactory?: (prefix: string) => string,
  ) {
    this.repository = new PlanChangeRepository(database, idFactory);
    this.events = new EventRepository(database);
    this.reconcileExpiredInflightResolutions();
  }

  list(runId: string): readonly PlanChangeRequest[] {
    this.run(runId);
    return this.repository.listForRun(runId);
  }

  get(requestId: string): PlanChangeRequest {
    return this.repository.get(requestId);
  }

  propose(input: CreatePlanChangeInput, actor: PlanChangeActor): PlanChangeRequest {
    return inImmediateTransaction(this.database, () => {
      const run = this.run(input.runId);
      if (run.mission_id !== input.missionId) throw this.scopeConflict("Run does not belong to the supplied mission");
      const plan = this.plan(input.basePlanId);
      this.assertPlanScope(plan, run);
      this.assertOptimisticVersions(run, plan, input.expectedRunVersion, input.expectedPlanVersion);
      this.assertMutableRun(run);
      const evaluation = this.evaluate(run, plan, input.operations);
      const request = this.repository.create({
        missionId: input.missionId,
        runId: input.runId,
        basePlanId: input.basePlanId,
        requestedBy: `${actor.type}:${actor.id}`,
        ...(input.requestText ? { requestText: input.requestText } : {}),
        evaluation,
        now: this.clock().toISOString(),
      });
      this.recordTransition(request, actor, "plan_change.proposed", "Plan amendment proposal was normalized and checked without executing work.", {
        status: request.status,
        diffCount: request.structuredDiff.length,
        safeToApply: request.inflightImpact.safeToApply,
      });
      return request;
    });
  }

  edit(input: EditPlanChangeInput, actor: PlanChangeActor): PlanChangeRequest {
    return inImmediateTransaction(this.database, () => {
      const current = this.repository.get(input.requestId);
      const run = this.run(current.runId);
      const plan = this.plan(current.basePlanId);
      this.assertOptimisticVersions(run, plan, input.expectedRunVersion, input.expectedPlanVersion);
      if (current.version !== input.expectedRequestVersion) throw conflict("plan_change_version_conflict", "Plan change request changed before this edit", "Reload the proposal and reapply the edit to its latest version.");
      this.assertOpenRequest(current);
      const evaluation = this.evaluate(run, plan, input.operations);
      const request = this.repository.edit({
        requestId: input.requestId,
        expectedVersion: input.expectedRequestVersion,
        ...(input.requestText ?? current.requestText
          ? { requestText: input.requestText ?? current.requestText ?? undefined }
          : {}),
        evaluation,
      });
      this.recordTransition(request, actor, "plan_change.edited", "Plan amendment proposal was edited and fully revalidated.", {
        previousVersion: current.version,
        version: request.version,
        status: request.status,
        diffCount: request.structuredDiff.length,
      });
      return request;
    });
  }

  reject(input: RejectPlanChangeInput, actor: PlanChangeActor): PlanChangeRequest {
    return inImmediateTransaction(this.database, () => {
      const current = this.repository.get(input.requestId);
      if (current.version !== input.expectedRequestVersion) throw conflict("plan_change_version_conflict", "Plan change request changed before this rejection", "Reload the proposal before rejecting it.");
      this.assertOpenRequest(current);
      const request = this.repository.resolve({
        requestId: current.id,
        expectedVersion: current.version,
        status: "rejected",
        resolvedAt: this.clock().toISOString(),
      });
      this.recordTransition(request, actor, "plan_change.rejected", "Plan amendment proposal was rejected; no plan or execution state changed.", { reason: input.reason });
      return request;
    });
  }

  getInflightResolution(requestId: string): PlanChangeInflightResolution | undefined {
    this.reconcileExpiredInflightResolutions();
    this.repository.get(requestId);
    return this.repository.getInflightResolution(requestId);
  }

  /**
   * Establish one durable amendment boundary and fence new dispatch. When
   * cancellation is selected, a separate trusted runtime call stops the exact
   * captured children before `confirmAffectedCancellation` closes their
   * canonical records.
   */
  beginInflightResolution(
    input: ResolvePlanChangeInflightInput,
    actor: PlanChangeActor,
  ): PlanChangeInflightResolution {
    return inImmediateTransaction(this.database, () => {
      const current = this.repository.get(input.requestId);
      if (current.version !== input.expectedRequestVersion) {
        throw conflict(
          "plan_change_version_conflict",
          "Plan change request changed before in-flight resolution",
          "Reload the exact proposal and affected work before choosing a resolution.",
        );
      }
      this.assertOpenRequest(current);
      const existing = this.repository.getInflightResolution(current.id);
      if (existing) {
        if (
          existing.mode === input.mode
          && existing.requestedBy === `${actor.type}:${actor.id}`
          && existing.reason === input.reason
        ) {
          return existing;
        }
        throw conflict(
          "plan_change_resolution_exists",
          "This proposal already has a represented in-flight resolution",
          "Open the existing resolution and continue from its canonical status.",
        );
      }
      const run = this.run(current.runId);
      const plan = this.plan(current.basePlanId);
      this.assertOptimisticVersions(
        run,
        plan,
        input.expectedRunVersion,
        input.expectedPlanVersion,
      );
      if (run.current_plan_id !== plan.id || plan.status !== "active") {
        throw conflict(
          "plan_change_base_plan_stale",
          "The base plan is no longer active",
          "Create a fresh proposal against the current active plan.",
        );
      }
      const evaluation = this.evaluate(
        run,
        plan,
        current.normalizedChange.operations,
      );
      const impact = evaluation.inflightImpact;
      if (impact.safeToApply || !impact.requiresCancellation) {
        throw conflict(
          "plan_change_resolution_not_required",
          "The proposal no longer intersects represented work",
          "Reload the proposal and review its current exact diff before applying.",
        );
      }
      const option = impact.resolutionOptions.find((candidate) =>
        candidate.mode === input.mode);
      if (!option?.enabled) {
        throw conflict(
          "plan_change_resolution_option_unavailable",
          option?.disabledReason ?? "The selected resolution is not available",
          "Choose one enabled represented resolution after reviewing affected work.",
        );
      }
      const now = this.clock().toISOString();
      const parked = this.database.prepare(`
        UPDATE runs SET status = 'blocked',
          status_reason = ?, next_action_summary = ?,
          updated_at = ?, version = version + 1
        WHERE id = ? AND version = ?
          AND status NOT IN ('completed', 'failed', 'cancelled')
      `).run(
        input.mode === "checkpoint_finish_idempotent_work"
          ? "Operator amendment checkpoint: finishing only the represented repeat-safe work."
          : "Operator amendment checkpoint: stopping only the represented affected work.",
        "Resolve the displayed in-flight amendment boundary",
        now,
        run.id,
        run.version,
      );
      if (parked.changes !== 1) {
        throw conflict(
          "plan_change_run_version_conflict",
          "Run state changed before the amendment dispatch fence was established",
          "Reload the run and review its exact active work.",
        );
      }
      const invalidated = this.closeQueuedAffectedWork(impact, actor, now);
      const started = this.events.append({
        runId: current.runId,
        missionId: current.missionId,
        journey: current.policyValidation.journey,
        eventType: "plan_change.inflight_resolution_started",
        occurredAt: now,
        actorType: "operator",
        actorId: actor.id,
        summary: input.mode === "checkpoint_finish_idempotent_work"
          ? "The run will finish only the captured repeat-safe work before a fresh plan review."
          : "Dispatch was fenced and an exact affected-work stop was requested; trusted runtime confirmation is still pending.",
        payload: JSON.parse(JSON.stringify({
          requestId: current.id,
          mode: input.mode,
          affectedActionIds: impact.affectedActions.map((action) => action.id),
          affectedAttackAttemptIds: impact.affectedAttackAttempts.map((attempt) => attempt.id),
          unaffectedActionIds: impact.unaffectedActions.map((action) => action.id),
          invalidated,
          dispatchFenced: true,
          signedContractChanged: false,
        })) as EventJsonValue,
        schemaVersion: 1,
        sensitivity: "internal",
        redaction: {},
      });
      const durableRun = new RunRepository(this.database).get(current.runId);
      const checkpoint = new CheckpointRepository(
        this.database,
        new ActionRepository(this.database),
      ).create({
        run: durableRun,
        eventSequence: started.sequence,
        now,
        inFlightClassification: input.mode,
      });
      const resolution = this.repository.createInflightResolution({
        requestId: current.id,
        missionId: current.missionId,
        runId: current.runId,
        basePlanId: current.basePlanId,
        mode: input.mode,
        status: "waiting_for_terminal_work",
        affectedStepIds: impact.affectedSubgraphStepIds,
        affectedAssignmentIds: [
          ...impact.activeAssignmentIds,
          ...impact.queuedAssignmentIdsToCancel,
        ],
        affectedActionIds: impact.affectedActions.map((action) => action.id),
        affectedAttackAttemptIds: impact.affectedAttackAttempts.map((attempt) => attempt.id),
        affectedDecisionIds: impact.pendingDecisionIds,
        sourceCheckpointId: checkpoint.id,
        sourceCheckpointStateHash: checkpoint.stateHash,
        sourceCheckpointEventSequence: checkpoint.eventSequence,
        requestedBy: `${actor.type}:${actor.id}`,
        reason: input.reason,
        settleDeadlineAt: new Date(
          Date.parse(now) + INFLIGHT_SETTLE_TIMEOUT_MS,
        ).toISOString(),
        now,
      });
      this.recordTransition(
        current,
        actor,
        "plan_change.inflight_resolution_checkpointed",
        "The exact in-flight amendment boundary was checkpointed without changing the signed mission contract.",
        {
          resolutionId: resolution.id,
          mode: resolution.mode,
          checkpointId: checkpoint.id,
          checkpointStateHash: checkpoint.stateHash,
          checkpointEventSequence: checkpoint.eventSequence,
          settleDeadlineAt: resolution.settleDeadlineAt,
          affectedStepIds: resolution.affectedStepIds,
          affectedAssignmentIds: resolution.affectedAssignmentIds,
          affectedActionIds: resolution.affectedActionIds,
          unaffectedActionIds: impact.unaffectedActiveActionIds,
          invalidated,
          dispatchFenced: true,
          signedContractChanged: false,
        },
      );
      return resolution;
    });
  }

  /**
   * Called only after the injected trusted runtime port confirms that the
   * exact represented child process set has stopped. Keeping this separate
   * from `beginInflightResolution` prevents database labels from racing ahead
   * of real process termination.
   */
  confirmAffectedCancellation(
    requestId: string,
    expectedResolutionVersion: number,
    actor: PlanChangeActor,
    receipt: PlanChangeAffectedWorkStopReceipt,
  ): PlanChangeInflightResolution {
    return inImmediateTransaction(this.database, () => {
      const request = this.repository.get(requestId);
      const resolution = this.repository.getInflightResolution(requestId);
      if (!resolution) {
        throw new PlanChangeError(
          "plan_change_resolution_not_found",
          "No in-flight resolution exists for this proposal",
          "not_found",
          404,
          "Start the represented cancellation boundary first.",
        );
      }
      if (resolution.mode !== "checkpoint_cancel_affected_work") {
        throw conflict(
          "plan_change_resolution_mode_conflict",
          "This boundary is configured to finish repeat-safe work, not cancel it",
          "Continue waiting for the displayed work or prepare a new proposal after the boundary resolves.",
        );
      }
      if (resolution.status !== "waiting_for_terminal_work") return resolution;
      if (resolution.version !== expectedResolutionVersion) {
        throw conflict(
          "plan_change_resolution_version_conflict",
          "In-flight resolution changed before cancellation confirmation",
          "Reload the amendment boundary before confirming process cleanup.",
        );
      }
      const now = this.clock().toISOString();
      const verifiedReceipt = this.verifyAffectedCancellationReceipt(
        resolution,
        receipt,
      );
      const closed = this.closeCapturedAffectedWork(
        now,
        verifiedReceipt,
      );
      const heartbeat = this.repository.heartbeatInflightResolution({
        requestId,
        expectedVersion: resolution.version,
        now,
      });
      this.recordTransition(
        request,
        actor,
        "plan_change.affected_work_cancelled",
        "The trusted runtime confirmed the exact affected child set stopped before canonical records were closed.",
        {
          resolutionId: resolution.id,
          stoppedActionIds: verifiedReceipt.stoppedActionIds,
          stoppedAssignmentIds: verifiedReceipt.stoppedAssignmentIds,
          stoppedAttackAttemptIds: verifiedReceipt.stoppedAttackAttemptIds,
          stoppedStepIds: verifiedReceipt.stoppedStepIds,
          closed,
          fullRunCancelled: false,
          dispatchFenced: true,
        },
      );
      return heartbeat;
    });
  }

  finalizeInflightResolution(
    input: FinalizePlanChangeInflightInput,
    actor: PlanChangeActor,
  ): {
    readonly resolution: PlanChangeInflightResolution;
    readonly request: PlanChangeRequest;
    readonly guidedDecisionId: string | null;
  } {
    this.reconcileExpiredInflightResolutions();
    return inImmediateTransaction(this.database, () => {
      const source = this.repository.get(input.requestId);
      const resolution = this.repository.getInflightResolution(source.id);
      if (!resolution) {
        throw new PlanChangeError(
          "plan_change_resolution_not_found",
          "No in-flight resolution exists for this proposal",
          "not_found",
          404,
          "Start one represented resolution from the current proposal.",
        );
      }
      if (resolution.status === "ready_for_review" && resolution.freshRequestId) {
        return {
          resolution,
          request: this.repository.get(resolution.freshRequestId),
          guidedDecisionId: null,
        };
      }
      if (resolution.status === "failed") {
        throw conflict(
          "plan_change_resolution_failed",
          resolution.failureReason
            ?? "The in-flight amendment boundary failed before it settled",
          "Inspect the preserved checkpoint and choose a new bounded recovery action.",
        );
      }
      if (resolution.version !== input.expectedResolutionVersion) {
        throw conflict(
          "plan_change_resolution_version_conflict",
          "In-flight resolution changed before finalization",
          "Reload the amendment boundary before completing it.",
        );
      }
      const terminal = new Set([
        "succeeded",
        "failed",
        "cancelled",
        "timed_out",
        "denied",
      ]);
      const actionRows = resolution.affectedActionIds.map((actionId) =>
        this.database.prepare(`
          SELECT id, step_id, assignment_id, status
          FROM actions WHERE id = ? AND run_id = ?
        `).get(actionId, resolution.runId) as {
          readonly id: string;
          readonly step_id: string | null;
          readonly assignment_id: string | null;
          readonly status: string;
        } | undefined);
      if (
        actionRows.some((row) => !row)
        || actionRows.some((row) => !terminal.has(row!.status))
      ) {
        throw conflict(
          "plan_change_resolution_work_still_running",
          "Captured repeat-safe work has not reached a durable terminal result",
          "Wait for the displayed actions to finish, then complete this boundary. No next action will dispatch meanwhile.",
        );
      }
      const unrelatedActive = this.database.prepare(`
        SELECT id FROM actions
        WHERE run_id = ? AND status IN ('queued', 'running')
          AND id NOT IN (
            SELECT value FROM json_each(?)
          )
        ORDER BY created_at, id
      `).all(
        resolution.runId,
        JSON.stringify(resolution.affectedActionIds),
      ) as Array<{ readonly id: string }>;
      if (unrelatedActive.length > 0) {
        throw conflict(
          "plan_change_unaffected_work_still_running",
          "Unrelated work is still reaching its terminal result and was not cancelled",
          "Wait for the displayed unaffected work to finish. The amendment dispatch fence remains active.",
        );
      }
      const unrelatedAssignments = this.database.prepare(`
        SELECT id FROM assignments
        WHERE run_id = ? AND status IN ('queued', 'active', 'blocked')
          AND id NOT IN (
            SELECT value FROM json_each(?)
          )
        ORDER BY created_at, id
      `).all(
        resolution.runId,
        JSON.stringify(resolution.affectedAssignmentIds),
      ) as Array<{ readonly id: string }>;
      if (unrelatedAssignments.length > 0) {
        throw conflict(
          "plan_change_unaffected_assignment_still_active",
          "An unrelated specialist assignment is still settling and was not cancelled",
          "Wait for the displayed unaffected assignment to finish. The amendment dispatch fence remains active.",
        );
      }
      const now = this.clock().toISOString();
      for (const row of actionRows) {
        if (!row || row.status !== "succeeded" || !row.step_id) continue;
        this.database.prepare(`
          UPDATE plan_steps SET status = 'completed',
            ended_at = COALESCE(ended_at, ?), updated_at = ?
          WHERE id = ? AND run_id = ?
            AND status IN ('ready', 'running', 'blocked', 'recovering')
        `).run(now, now, row.step_id, resolution.runId);
        if (row.assignment_id) {
          this.database.prepare(`
            UPDATE assignments SET status = 'completed',
              ended_at = COALESCE(ended_at, ?),
              lease_owner = NULL, lease_acquired_at = NULL,
              last_heartbeat_at = NULL, lease_expires_at = NULL,
              updated_at = ?
            WHERE id = ? AND run_id = ?
              AND status IN ('queued', 'active', 'blocked')
          `).run(now, now, row.assignment_id, resolution.runId);
        }
      }
      const invalidatedContinuations = this.database.prepare(`
        UPDATE runtime_continuations
        SET status = 'cancelled', lease_owner = NULL,
          lease_expires_at = NULL, completed_at = ?,
          updated_at = ?,
          last_error = 'Superseded by reviewed plan amendment boundary'
        WHERE run_id = ?
          AND status IN ('pending', 'processing')
          AND kind IN (
            'action_result_to_advance',
            'guided_failure_to_recover',
            'autonomous_retry_to_dispatch'
          )
          AND source_id IN (
            SELECT id FROM actions
            WHERE run_id = ? AND step_id IN (
              SELECT id FROM plan_steps WHERE plan_id = ?
            )
          )
      `).run(
        now,
        now,
        resolution.runId,
        resolution.runId,
        resolution.basePlanId,
      ).changes;
      const runBefore = this.run(resolution.runId);
      const parked = this.database.prepare(`
        UPDATE runs SET status = 'blocked',
          status_reason = ?, next_action_summary = ?,
          lease_owner = NULL, lease_acquired_at = NULL,
          last_heartbeat_at = NULL, lease_expires_at = NULL,
          updated_at = ?, version = version + 1
        WHERE id = ? AND version = ?
          AND status NOT IN ('completed', 'failed', 'cancelled')
      `).run(
        "Captured in-flight work settled; fresh plan amendment awaits exact review.",
        "Review and apply the fresh exact plan diff",
        now,
        resolution.runId,
        runBefore.version,
      );
      if (parked.changes !== 1) {
        throw conflict(
          "plan_change_run_version_conflict",
          "Run state changed before the amendment boundary could be parked",
          "Reload the current run and resolution.",
        );
      }
      const run = this.run(resolution.runId);
      const plan = this.plan(resolution.basePlanId);
      const evaluation = this.evaluate(
        run,
        plan,
        source.normalizedChange.operations,
      );
      if (
        !evaluation.dependencyImpact.valid
        || !evaluation.policyValidation.valid
        || !evaluation.readinessImpact.valid
        || !evaluation.inflightImpact.safeToApply
      ) {
        throw conflict(
          "plan_change_resolution_revalidation_failed",
          "The fresh amendment no longer passes dependency, scope, policy, readiness, or in-flight validation",
          "Review the changed runtime boundary and prepare a corrected proposal.",
        );
      }
      const cancelled = this.repository.resolve({
        requestId: source.id,
        expectedVersion: source.version,
        status: "cancelled",
        resolvedAt: now,
      });
      const fresh = this.repository.create({
        missionId: source.missionId,
        runId: source.runId,
        basePlanId: source.basePlanId,
        requestedBy: `${actor.type}:${actor.id}`,
        ...(source.requestText ? { requestText: source.requestText } : {}),
        evaluation,
        now,
      });
      const completed = this.repository.resolveInflightResolution({
        requestId: source.id,
        expectedVersion: resolution.version,
        freshRequestId: fresh.id,
        now,
      });
      // Guided receives its next exact represented action only after this
      // fresh proposal is explicitly reviewed and applied. Creating a
      // decision here would bind parameters from an unapplied plan.
      const guidedDecisionId = null;
      const settled = this.events.append({
        runId: fresh.runId,
        missionId: fresh.missionId,
        journey: fresh.policyValidation.journey,
        eventType: "plan_change.inflight_resolution_completed",
        occurredAt: now,
        actorType: "operator",
        actorId: actor.id,
        summary: "Affected work reached a durable boundary and a fresh exact plan proposal is ready for review.",
        payload: {
          resolutionId: completed.id,
          sourceRequestId: cancelled.id,
          freshRequestId: fresh.id,
          guidedDecisionId,
          invalidatedContinuations,
          dependencyValid: fresh.dependencyImpact.valid,
          policyValid: fresh.policyValidation.valid,
          readinessValid: fresh.readinessImpact.valid,
          inflightSafe: fresh.inflightImpact.safeToApply,
          signedContractChanged: false,
        },
        schemaVersion: 1,
        sensitivity: "internal",
        redaction: {},
      });
      const checkpoint = new CheckpointRepository(
        this.database,
        new ActionRepository(this.database),
      ).create({
        run: new RunRepository(this.database).get(fresh.runId),
        eventSequence: settled.sequence,
        now,
        inFlightClassification: "plan_change_review_ready",
      });
      this.recordTransition(
        fresh,
        actor,
        "plan_change.fresh_review_created",
        "A fresh proposal was produced after affected work settled; it was not applied automatically.",
        {
          resolutionId: completed.id,
          sourceRequestId: cancelled.id,
          checkpointId: checkpoint.id,
          guidedDecisionId,
          signedContractChanged: false,
          executionStarted: false,
        },
      );
      return { resolution: completed, request: fresh, guidedDecisionId };
    });
  }

  apply(input: ApplyPlanChangeInput, actor: PlanChangeActor): {
    readonly request: PlanChangeRequest;
    readonly resultPlanId: string;
    readonly resultPlanVersion: number;
    readonly guidedDecisionId: string | null;
  } {
    return inImmediateTransaction(this.database, () => {
      const current = this.repository.get(input.requestId);
      if (current.version !== input.expectedRequestVersion) throw conflict("plan_change_version_conflict", "Plan change request changed before apply", "Reload and review the latest proposal and impact analysis.");
      this.assertValidatedRequest(current);
      const run = this.run(current.runId);
      const plan = this.plan(current.basePlanId);
      this.assertOptimisticVersions(run, plan, input.expectedRunVersion, input.expectedPlanVersion);
      if (run.current_plan_id !== plan.id || plan.status !== "active") {
        throw conflict("plan_change_base_plan_stale", "The base plan is no longer the active run plan", "Create a new proposal against the current active plan; stale diffs are never reinterpreted.");
      }
      const evaluation = this.evaluate(run, plan, current.normalizedChange.operations);
      if (!evaluation.dependencyImpact.valid) throw conflict("plan_change_dependency_invalid", "The proposed dependency graph is invalid", "Correct dependency ordering and cycles before applying the proposal.");
      if (!evaluation.policyValidation.valid) throw new PlanChangeError("plan_change_policy_denied", "The proposed plan is outside the current mission policy", "policy_denied", 409, "Remove prohibited action classes or create a separately reviewed contract amendment.");
      if (!evaluation.readinessImpact.valid) throw new PlanChangeError("plan_change_readiness_failed", "The proposed plan references unavailable specialists", "dependency_missing", 409, "Choose available declared specialists before applying the plan.");
      if (!evaluation.inflightImpact.safeToApply) throw conflict("plan_change_inflight_work", "The plan cannot change while represented work is in flight", "Checkpoint and pause or cancel affected work explicitly, then create a fresh proposal against the resulting state.");
      if (evaluation.structuredDiff.length === 0) throw conflict("plan_change_no_effect", "The proposal no longer changes the base plan", "Edit or reject the no-op proposal.");
      const reviewed = jsonValue({
        structuredDiff: current.structuredDiff,
        dependencyImpact: current.dependencyImpact,
        policyValidation: current.policyValidation,
        readinessImpact: current.readinessImpact,
        budgetImpact: current.budgetImpact,
        inflightImpact: current.inflightImpact,
      });
      const recomputed = jsonValue({
        structuredDiff: evaluation.structuredDiff,
        dependencyImpact: evaluation.dependencyImpact,
        policyValidation: evaluation.policyValidation,
        readinessImpact: evaluation.readinessImpact,
        budgetImpact: evaluation.budgetImpact,
        inflightImpact: evaluation.inflightImpact,
      });
      if (canonical(reviewed) !== canonical(recomputed)) {
        throw conflict(
          "plan_change_review_drift",
          "The reviewed plan comparison or impact changed before apply",
          "Prepare a fresh proposal and review its exact diff, policy, readiness, dependency, budget, and in-flight impact before applying it.",
        );
      }

      const resultPlanId = this.repository.nextId("plan");
      const resultPlanVersion = (this.database.prepare("SELECT COALESCE(MAX(version), 0) + 1 AS version FROM plans WHERE run_id = ?").get(run.id) as { readonly version: number }).version;
      const now = this.clock().toISOString();
      const contentHash = this.contentFingerprint(evaluation.workingPlan);
      const planHash = planVersionReceiptHash({
        runId: run.id,
        planId: resultPlanId,
        version: resultPlanVersion,
        contentHash,
      });
      this.database.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, rationale_summary,
          plan_hash, content_hash, content_hash_version,
          created_by, created_at, activated_at
        ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, 1, ?, ?, ?)
      `).run(resultPlanId, run.id, resultPlanVersion, evaluation.workingPlan.strategySummary, evaluation.workingPlan.rationaleSummary, planHash, contentHash, `${actor.type}:${actor.id}`, now, now);

      const idMap = new Map(evaluation.workingPlan.steps.map((step) => [step.logicalId, this.repository.nextId("step")]));
      const insertStep = this.database.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          success_criteria_json, dependencies_json, action_class, risk_class,
          assigned_agent_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const insertVersion = this.database.prepare(`
        INSERT INTO plan_step_versions (
          id, plan_step_id, plan_id, version, snapshot_json, snapshot_hash,
          change_request_id, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const insertAssignment = this.database.prepare(`
        INSERT INTO assignments (id, run_id, step_id, agent_id, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      const insertRepresentation = this.database.prepare(`
        INSERT INTO mission_constraints (
          id, mission_id, constraint_type, value_json, source, created_at
        ) VALUES (?, ?, 'represented_action', ?, ?, ?)
      `);
      const changedSubgraph = this.affectedBaseStepIds(
        this.workingPlan(plan),
        current.normalizedChange.operations,
      );
      const carriedTerminal = new Set(evaluation.workingPlan.steps
        .filter((step) =>
          step.sourceStepId !== null
          && !changedSubgraph.has(step.logicalId)
          && (step.sourceStatus === "completed" || step.sourceStatus === "skipped"))
        .map((step) => step.logicalId));
      let firstReadyStepId: string | null = null;
      evaluation.workingPlan.steps.forEach((step, ordinal) => {
        const stepId = idMap.get(step.logicalId)!;
        const dependencies = step.dependencyStepIds.map((dependency) => idMap.get(dependency)!);
        const status = carriedTerminal.has(step.logicalId)
          ? step.sourceStatus!
          : step.dependencyStepIds.every((dependency) => carriedTerminal.has(dependency))
            ? "ready"
            : "pending";
        if (!firstReadyStepId && status === "ready") firstReadyStepId = stepId;
        const stepSnapshot = {
          sourceStepId: step.sourceStepId,
          sourceStatus: step.sourceStatus,
          carriedTerminalResult: carriedTerminal.has(step.logicalId),
          logicalId: step.logicalId,
          ordinal,
          phase: step.phase,
          title: step.title,
          objective: step.objective,
          successCriteria: step.successCriteria,
          dependencyStepIds: step.dependencyStepIds,
          actionClass: step.actionClass,
          riskClass: step.riskClass,
          assignedAgentId: step.assignedAgentId,
          representation: step.representation,
        } satisfies PlanChangeJson;
        insertStep.run(stepId, resultPlanId, run.id, ordinal, step.phase, step.title, step.objective, status, JSON.stringify(step.successCriteria), JSON.stringify(dependencies), step.actionClass, step.riskClass, step.assignedAgentId, now, now);
        insertVersion.run(this.repository.nextId("plan_step_version"), stepId, resultPlanId, resultPlanVersion, JSON.stringify(stepSnapshot), sha256(canonical(stepSnapshot)), current.id, `${actor.type}:${actor.id}`, now);
        const representation = this.remapRepresentation(step, dependencies);
        insertRepresentation.run(this.repository.nextId("constraint"), run.mission_id, JSON.stringify(representation), stepId, now);
        if (step.assignedAgentId) {
          insertAssignment.run(
            this.repository.nextId("assignment"),
            run.id,
            stepId,
            step.assignedAgentId,
            carriedTerminal.has(step.logicalId) ? "completed" : "queued",
            now,
            now,
          );
        }
      });

      this.database.prepare(`
        UPDATE assignments SET status = 'cancelled', ended_at = ?, updated_at = ?
        WHERE step_id IN (SELECT id FROM plan_steps WHERE plan_id = ?) AND status = 'queued'
      `).run(now, now, plan.id);
      this.database.prepare(`
        UPDATE plan_steps SET status = 'cancelled', ended_at = ?, updated_at = ?
        WHERE plan_id = ? AND status IN ('pending', 'ready')
      `).run(now, now, plan.id);
      this.database.prepare("UPDATE plans SET status = 'superseded' WHERE id = ? AND status = 'active'").run(plan.id);
      const updatedRun = this.database.prepare(`
        UPDATE runs SET current_plan_id = ?, current_step_id = ?, replan_count = replan_count + 1,
          updated_at = ?, version = version + 1
        WHERE id = ? AND version = ? AND current_plan_id = ?
      `).run(resultPlanId, firstReadyStepId, now, run.id, run.version, plan.id);
      if (updatedRun.changes !== 1) throw conflict("plan_change_run_version_conflict", "Run state changed during plan activation", "Reload the run before creating another proposal.");
      let guidedDecisionId: string | null = null;
      const resolvedBoundary = this.database.prepare(`
        SELECT id FROM plan_change_inflight_resolutions
        WHERE fresh_request_id = ? AND status = 'ready_for_review'
      `).get(current.id) as { readonly id: string } | undefined;
      if (
        resolvedBoundary
        && run.journey === "guided"
        && firstReadyStepId
      ) {
        const prepared = new RuntimeRepository(this.database)
          .createDecisionForStep(firstReadyStepId, now, 24 * 60 * 60 * 1_000);
        guidedDecisionId = prepared.decisionId;
        this.database.prepare(`
          UPDATE plan_steps SET status = 'waiting_guided_decision',
            updated_at = ? WHERE id = ? AND status = 'ready'
        `).run(now, firstReadyStepId);
        this.database.prepare(`
          UPDATE runs SET status = 'waiting_guided_decision',
            status_reason = ?,
            next_action_summary = ?,
            updated_at = ?, version = version + 1
          WHERE id = ? AND current_plan_id = ?
        `).run(
          "The reviewed plan amendment is active and its next exact Guided action awaits the operator.",
          "Review the next represented Guided action",
          now,
          run.id,
          resultPlanId,
        );
      }
      const request = this.repository.resolve({
        requestId: current.id,
        expectedVersion: current.version,
        status: "applied",
        resultPlanId,
        resolvedAt: now,
      });
      this.recordTransition(request, actor, "plan_change.applied", "A reviewed plan version was activated without starting or replaying any action.", {
        basePlanId: plan.id,
        resultPlanId,
        resultPlanVersion,
        contentHash,
        cancelledQueuedAssignmentIds: evaluation.inflightImpact.queuedAssignmentIdsToCancel,
        carriedTerminalStepIds: [...carriedTerminal].sort(),
        guidedDecisionId,
        autonomousRemainsPaused: run.journey === "autonomous"
          && Boolean(resolvedBoundary),
        executionStarted: false,
      });
      return {
        request,
        resultPlanId,
        resultPlanVersion,
        guidedDecisionId,
      };
    });
  }

  private evaluate(run: RunRow, plan: PlanRow, operations: readonly PlanChangeOperation[]): Evaluation {
    const base = this.workingPlan(plan);
    this.assertWorkingPlanIntegrity(base, true);
    const working = this.clone(base);
    this.applyOperations(working, operations, plan);
    this.assertWorkingPlanIntegrity(working);
    const dependencyImpact = this.dependencyImpact(base, working, operations);
    const policyValidation = this.policyValidation(run, working);
    const readinessImpact = this.readinessImpact(working);
    const structuredDiff = this.diff(base, working);
    if (structuredDiff.length === 0) throw conflict("plan_change_no_effect", "The structured amendment does not change the base plan", "Change at least one plan or step value, or reject the proposal.");
    const affectedRefs = this.affectedRefs(operations, structuredDiff, working);
    const inflightImpact = this.inflightImpact(run, plan, base, operations);
    const addedSteps = structuredDiff.filter((entry) => entry.kind === "add" && /^steps\[[^\]]+\]$/u.test(entry.path)).length;
    const removedSteps = structuredDiff.filter((entry) => entry.kind === "remove" && /^steps\[[^\]]+\]$/u.test(entry.path)).length;
    const budgetImpact: PlanChangeBudgetImpact = {
      addedSteps,
      removedSteps,
      netStepChange: addedSteps - removedSteps,
      durationEstimate: "not_observed",
      costEstimate: "not_observed",
      explanation: "No measured duration or provider-cost estimate is available for this deterministic amendment; the UI must not invent one.",
    };
    const valid = dependencyImpact.valid && policyValidation.valid && readinessImpact.valid && inflightImpact.safeToApply;
    const normalizedChange: NormalizedPlanChange = {
      summary: this.interpretation(operations, structuredDiff),
      operations,
    };
    return {
      normalizedChange,
      structuredDiff,
      affectedRefs,
      dependencyImpact,
      policyValidation,
      readinessImpact,
      budgetImpact,
      inflightImpact,
      status: valid ? "validated" : "proposed",
      workingPlan: working,
    };
  }

  private workingPlan(plan: PlanRow): WorkingPlan {
    const rows = this.database.prepare(`
      SELECT id, ordinal, phase, title, objective, status, success_criteria_json,
        dependencies_json, action_class, risk_class, assigned_agent_id,
        (SELECT value_json FROM mission_constraints
          WHERE source = plan_steps.id AND constraint_type = 'represented_action'
          LIMIT 1) AS representation_json
      FROM plan_steps WHERE plan_id = ? ORDER BY ordinal, id
    `).all(plan.id) as StepRow[];
    return {
      strategySummary: plan.strategy_summary,
      rationaleSummary: plan.rationale_summary,
      steps: rows.map((row) => ({
        logicalId: row.id,
        sourceStepId: row.id,
        sourceStatus: row.status,
        phase: row.phase,
        title: row.title,
        objective: row.objective,
        successCriteria: parseStringArray(row.success_criteria_json, `success criteria for ${row.id}`),
        dependencyStepIds: parseStringArray(row.dependencies_json, `dependencies for ${row.id}`),
        actionClass: row.action_class,
        riskClass: row.risk_class,
        assignedAgentId: row.assigned_agent_id,
        representation: row.representation_json === null ? null : parseJsonValue(row.representation_json, `represented action for ${row.id}`),
      })),
    };
  }

  private clone(plan: WorkingPlan): WorkingPlan {
    return { strategySummary: plan.strategySummary, rationaleSummary: plan.rationaleSummary, steps: plan.steps.map((step) => ({ ...step, successCriteria: [...step.successCriteria], dependencyStepIds: [...step.dependencyStepIds], representation: step.representation === null ? null : jsonValue(step.representation) })) };
  }

  private applyOperations(plan: WorkingPlan, operations: readonly PlanChangeOperation[], basePlan: PlanRow): void {
    const find = (stepId: string): WorkingStep => {
      const step = plan.steps.find((candidate) => candidate.logicalId === stepId);
      if (!step) throw conflict("plan_change_step_not_found", `Plan step is not present in the amended graph: ${stepId}`, "Use a step from the current base plan or an earlier draft step in this proposal.");
      return step;
    };
    for (const operation of operations) {
      if (operation.kind === "restore_plan_version") {
        const targetPlan = this.planForRun(operation.targetPlanId, basePlan.run_id);
        if (targetPlan.version !== operation.targetPlanVersion) {
          throw conflict(
            "plan_change_restore_history_stale",
            `Historical plan version changed from the selected v${operation.targetPlanVersion}`,
            "Refresh immutable plan history and select the visible version again before preparing a rollback.",
          );
        }
        if (targetPlan.id === basePlan.id || targetPlan.version >= basePlan.version || targetPlan.status !== "superseded") {
          throw conflict(
            "plan_change_restore_target_invalid",
            "Only an earlier superseded plan from this run can be restored",
            "Select a lower historical version from the current run. The active plan is never restored over itself.",
          );
        }
        const historical = this.workingPlan(targetPlan);
        this.assertWorkingPlanIntegrity(historical, true);
        plan.strategySummary = historical.strategySummary;
        plan.rationaleSummary = historical.rationaleSummary;
        plan.steps = this.clone(historical).steps;
      } else if (operation.kind === "update_plan") {
        if (operation.strategySummary !== undefined) plan.strategySummary = operation.strategySummary;
        if (operation.rationaleSummary !== undefined) plan.rationaleSummary = operation.rationaleSummary;
      } else if (operation.kind === "update_step") {
        const step = find(operation.stepId);
        if (operation.phase !== undefined) step.phase = operation.phase;
        if (operation.title !== undefined) step.title = operation.title;
        if (operation.objective !== undefined) step.objective = operation.objective;
        if (operation.successCriteria !== undefined) step.successCriteria = [...operation.successCriteria];
        if (operation.actionClass !== undefined) step.actionClass = operation.actionClass;
        if (operation.actionClass !== undefined && isJsonObject(step.representation)) {
          const representation = step.representation;
          const action = representation.action;
          if (isJsonObject(action)) {
            step.representation = { ...representation, action: { ...action, actionClass: operation.actionClass } };
          }
        }
        if (operation.riskClass !== undefined) step.riskClass = operation.riskClass;
        if (operation.assignedAgentId !== undefined) step.assignedAgentId = operation.assignedAgentId;
      } else if (operation.kind === "add_step") {
        if (plan.steps.some((step) => step.logicalId === operation.clientStepId)) throw conflict("plan_change_step_id_conflict", `Draft step ID is already used: ${operation.clientStepId}`, "Use a unique draft- step identifier.");
        const step: WorkingStep = {
          logicalId: operation.clientStepId,
          sourceStepId: null,
          sourceStatus: null,
          phase: operation.phase,
          title: operation.title,
          objective: operation.objective,
          successCriteria: [...operation.successCriteria],
          dependencyStepIds: [...operation.dependencyStepIds],
          actionClass: operation.actionClass,
          riskClass: operation.riskClass,
          assignedAgentId: operation.assignedAgentId,
          representation: this.representation(operation.representation, operation.actionClass),
        };
        if (operation.afterStepId === null || operation.afterStepId === undefined) plan.steps.push(step);
        else plan.steps.splice(plan.steps.indexOf(find(operation.afterStepId)) + 1, 0, step);
      } else if (operation.kind === "remove_step") {
        const index = plan.steps.indexOf(find(operation.stepId));
        plan.steps.splice(index, 1);
        if (plan.steps.length === 0) throw conflict("plan_change_empty_plan", "A plan must retain at least one bounded step", "Keep or add at least one step before removing this one.");
      } else if (operation.kind === "reorder_steps") {
        const current = new Set(plan.steps.map((step) => step.logicalId));
        if (operation.orderedStepIds.length !== current.size || operation.orderedStepIds.some((id) => !current.has(id))) {
          throw conflict("plan_change_reorder_incomplete", "Reorder must include every amended plan step exactly once", "Reload the proposal and provide the complete visible step order.");
        }
        plan.steps = operation.orderedStepIds.map(find);
      } else if (operation.kind === "set_dependencies") {
        find(operation.stepId).dependencyStepIds = [...operation.dependencyStepIds];
      } else {
        const step = find(operation.stepId);
        step.representation = this.representation(operation.representation, step.actionClass);
      }
    }
  }

  private assertWorkingPlanIntegrity(plan: WorkingPlan, requireCanonicalDependencies = false): void {
    if (plan.steps.length === 0) {
      throw conflict("plan_change_empty_plan", "A plan must retain at least one bounded step", "Choose a non-empty historical version or reconcile its missing steps before preparing a rollback.");
    }
    if (new Set(plan.steps.map((step) => step.logicalId)).size !== plan.steps.length) {
      throw conflict("plan_change_source_corrupt", "The plan contains duplicate step identities", "Run database integrity verification and reconcile the immutable plan history before changing it.");
    }
    for (const step of plan.steps) {
      if (!step.phase.trim() || !step.title.trim() || !step.objective.trim()) {
        throw conflict("plan_change_source_corrupt", `Step ${step.logicalId} has incomplete descriptive fields`, "Reconcile the immutable plan history before preparing or applying a plan change.");
      }
      if (!step.actionClass || !isActionClassId(step.actionClass) || !step.riskClass || !RISK_CLASSES.has(step.riskClass)) {
        throw conflict("plan_change_source_corrupt", `Step ${step.logicalId} has an invalid action or risk classification`, "Reconcile the step against the canonical action and risk registries before preparing a rollback.");
      }
      try {
        validatePersistedPlanStepRepresentation(
          step.representation,
          `represented action for ${step.logicalId}`,
          step.actionClass,
          requireCanonicalDependencies ? step.dependencyStepIds : undefined,
        );
      } catch (error) {
        if (!(error instanceof PlanChangeError)) throw error;
        throw conflict(
          "plan_change_representation_corrupt",
          `Step ${step.logicalId} has an invalid represented action and cannot be restored`,
          "Reconcile the immutable action projection, remove sensitive content, and prepare a fresh reviewed proposal.",
        );
      }
    }
  }

  private dependencyImpact(base: WorkingPlan, working: WorkingPlan, operations: readonly PlanChangeOperation[]): PlanChangeDependencyImpact {
    const ordinal = new Map(working.steps.map((step, index) => [step.logicalId, index]));
    const issues: string[] = [];
    for (const step of working.steps) {
      if (new Set(step.dependencyStepIds).size !== step.dependencyStepIds.length) issues.push(`${step.logicalId} repeats a dependency`);
      for (const dependency of step.dependencyStepIds) {
        if (!ordinal.has(dependency)) issues.push(`${step.logicalId} depends on missing step ${dependency}`);
        else if (dependency === step.logicalId) issues.push(`${step.logicalId} depends on itself`);
        else if (ordinal.get(dependency)! >= ordinal.get(step.logicalId)!) issues.push(`${step.logicalId} must appear after dependency ${dependency}`);
      }
    }
    const baseDependencies = canonical(base.steps.map((step) => ({ id: step.logicalId, dependencies: step.dependencyStepIds })));
    const nextDependencies = canonical(working.steps.map((step) => ({ id: step.logicalId, dependencies: step.dependencyStepIds })));
    return {
      valid: issues.length === 0,
      changed: baseDependencies !== nextDependencies,
      reordered: operations.some((operation) => operation.kind === "reorder_steps" || operation.kind === "restore_plan_version")
        && canonical(base.steps.map((step) => step.logicalId)) !== canonical(working.steps.map((step) => step.logicalId)),
      issues,
    };
  }

  private policyValidation(run: RunRow, working: WorkingPlan): PlanChangePolicyValidation {
    const classes = [...new Set(working.steps.map((step) => step.actionClass).filter((entry): entry is string => Boolean(entry)))].sort();
    const prohibited: string[] = [];
    const reasonSet = new Set<string>();
    if (working.steps.some((step) => !step.actionClass)) reasonSet.add("Every step requires a canonical action class before activation.");
    const targetRows = this.database.prepare(`
      SELECT target, normalized_target, disposition FROM mission_targets
      WHERE mission_id = ? ORDER BY disposition, normalized_target
    `).all(run.mission_id) as Array<{ readonly target: string; readonly normalized_target: string; readonly disposition: "allowed" | "prohibited" }>;
    const targetsFor = (disposition: "allowed" | "prohibited") => new Set(targetRows
      .filter((row) => row.disposition === disposition)
      .flatMap((row) => [row.target.trim(), row.normalized_target.trim()])
      .filter(Boolean));
    const allowedTargets = targetsFor("allowed");
    const prohibitedTargets = targetsFor("prohibited");
    if (allowedTargets.size === 0) reasonSet.add("The mission has no normalized allowed target for a represented plan action.");
    const exactActions = working.steps.map((step) => ({ step, action: this.exactAction(step) }));
    for (const { step, action } of exactActions) {
      if (!action) {
        reasonSet.add(`Step ${step.logicalId} has no valid exact represented action.`);
        continue;
      }
      const actionTarget = typeof action.target === "string" ? action.target.trim() : "";
      if (!actionTarget || !allowedTargets.has(actionTarget) || prohibitedTargets.has(actionTarget)) {
        reasonSet.add(`Step ${step.logicalId} targets ${actionTarget || "an unspecified target"}, which is outside the mission's normalized allowed scope.`);
      }
      if (action.actionClass !== step.actionClass) {
        reasonSet.add(`Step ${step.logicalId} has an action-class mismatch between its plan record and represented action.`);
      }
    }
    let contractId: string | null = null;
    if (run.journey === "autonomous") {
      if (!run.contract_id) reasonSet.add("Autonomous plan changes require the run's confirmed versioned contract.");
      else {
        const contract = this.database.prepare("SELECT id, state, action_policy_json FROM mission_contracts WHERE id = ?").get(run.contract_id) as { readonly id: string; readonly state: string; readonly action_policy_json: string } | undefined;
        if (!contract || contract.state !== "confirmed") reasonSet.add("The Autonomous contract is missing, revoked, draft, or superseded.");
        else {
          contractId = contract.id;
          const policy = parseObject(contract.action_policy_json);
          const normalize = (value: string) => value.trim().toLowerCase();
          const allowed = new Set(Array.isArray(policy.allowedActionClasses) ? policy.allowedActionClasses.filter((entry): entry is string => typeof entry === "string").map(normalize) : []);
          const denied = new Set(Array.isArray(policy.prohibitedActionClasses) ? policy.prohibitedActionClasses.filter((entry): entry is string => typeof entry === "string").map(normalize) : []);
          const specialists = new Set(Array.isArray(policy.specialistAgentIds) ? policy.specialistAgentIds.filter((entry): entry is string => typeof entry === "string").map((entry) => entry.trim()).filter(Boolean) : []);
          const destructivePolicy = typeof policy.destructivePolicy === "string" ? policy.destructivePolicy : undefined;
          const boundedTargets = Array.isArray(policy.boundedDestructiveTargets) ? policy.boundedDestructiveTargets.filter((entry): entry is string => typeof entry === "string") : [];
          for (const actionClass of classes) if (!allowed.has(normalize(actionClass)) || denied.has(normalize(actionClass))) prohibited.push(actionClass);
          if (prohibited.length) reasonSet.add("One or more action classes are not pre-authorized by the signed Autonomous contract.");
          if (specialists.size === 0) reasonSet.add("The signed Autonomous contract has no explicit specialist pool.");
          for (const { step, action } of exactActions) {
            if (!action) continue;
            const actionType = typeof action.actionType === "string" ? normalize(action.actionType) : "";
            const actionTarget = typeof action.target === "string" ? action.target.trim() : "";
            const destructive = action.destructive === true;
            const argumentsValue = isJsonObject(action.arguments) ? action.arguments : null;
            const reviewedLocalProcess = argumentsValue?.executionBinding === "reviewed_local_process"
              && typeof argumentsValue.toolId === "string"
              && normalize(argumentsValue.toolId) === actionType;
            if (!actionType || (!reviewedLocalProcess
              && (!allowed.has(actionType) || denied.has(actionType)))) {
              reasonSet.add(`Step ${step.logicalId} action type ${actionType || "is unspecified"} is not pre-authorized by the signed Autonomous contract.`);
            }
            if (!step.assignedAgentId || !specialists.has(step.assignedAgentId)) {
              reasonSet.add(`Step ${step.logicalId} specialist is outside the signed Autonomous specialist pool.`);
            }
            if (!evaluateDestructiveAuthorization({ destructive, policy: destructivePolicy, target: actionTarget, boundedTargets }).allowed) {
              reasonSet.add(`Step ${step.logicalId} contains a destructive action outside the signed bounded-lab destructive policy.`);
            }
          }
        }
      }
    } else {
      for (const actionClass of classes) {
        if (!isActionClassId(actionClass) || DEFAULT_ACTION_POLICY.get(actionClass) === "prohibited") prohibited.push(actionClass);
      }
      if (prohibited.length) reasonSet.add("Guided plans cannot include platform-default prohibited action classes without a separately reviewed policy amendment.");
    }
    const reasons = [...reasonSet];
    return { valid: reasons.length === 0, journey: run.journey, contractId, checkedActionClasses: classes, prohibitedActionClasses: prohibited, reasons };
  }

  private readinessImpact(working: WorkingPlan): PlanChangeReadinessImpact {
    const agents = [...new Set(working.steps.map((step) => step.assignedAgentId).filter((entry): entry is string => Boolean(entry)))].sort();
    const unavailable: string[] = [];
    const reasons: string[] = [];
    if (working.steps.some((step) => !step.assignedAgentId)) reasons.push("Every step requires an explicit specialist assignment before activation.");
    if (working.steps.some((step) => !this.exactAction(step))) reasons.push("Every activated step requires a valid exact represented action.");
    for (const agentId of agents) {
      const row = this.database.prepare("SELECT status FROM agents WHERE id = ?").get(agentId) as { readonly status: string } | undefined;
      if (!row || row.status === "offline" || row.status === "quarantined") unavailable.push(agentId);
    }
    if (unavailable.length) reasons.push("One or more assigned specialists are unavailable or quarantined.");
    return { valid: reasons.length === 0, checkedAgentIds: agents, unavailableAgentIds: unavailable, reasons };
  }

  private closeQueuedAffectedWork(
    impact: PlanChangeInflightImpact,
    actor: PlanChangeActor,
    now: string,
  ): PlanChangeJson {
    const queuedActionIds = impact.affectedActions
      .filter((action) => action.status === "queued")
      .map((action) => action.id);
    const queuedAttemptIds = impact.affectedAttackAttempts
      .filter((attempt) => attempt.status !== "running")
      .map((attempt) => attempt.id);
    const runFor = (sql: string, ids: readonly string[], ...prefix: unknown[]) =>
      ids.length === 0
        ? 0
        : this.database.prepare(
          sql.replace("/* ids */", ids.map(() => "?").join(", ")),
        ).run(...prefix, ...ids).changes;
    const toolCalls = runFor(`
      UPDATE tool_calls SET status = 'cancelled',
        error_category = COALESCE(error_category, 'operator_rejection'),
        ended_at = COALESCE(ended_at, ?)
      WHERE status = 'queued' AND action_id IN (/* ids */)
    `, queuedActionIds, now);
    const actions = runFor(`
      UPDATE actions SET status = 'cancelled',
        result_summary = COALESCE(
          result_summary,
          'Cancelled before dispatch by a represented plan amendment'
        ),
        error_category = COALESCE(error_category, 'operator_rejection'),
        ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE status = 'queued' AND id IN (/* ids */)
    `, queuedActionIds, now, now);
    const assignments = runFor(`
      UPDATE assignments SET status = 'cancelled',
        ended_at = COALESCE(ended_at, ?),
        lease_owner = NULL, lease_acquired_at = NULL,
        last_heartbeat_at = NULL, lease_expires_at = NULL,
        updated_at = ?
      WHERE status = 'queued' AND id IN (/* ids */)
    `, impact.queuedAssignmentIdsToCancel, now, now);
    const attempts = runFor(`
      UPDATE attack_attempts SET status = 'cancelled',
        outcome_summary = COALESCE(
          outcome_summary,
          'Cancelled before execution by a represented plan amendment'
        ),
        ended_at = COALESCE(ended_at, ?), updated_at = ?,
        version = version + 1
      WHERE status IN ('planned', 'ready', 'blocked', 'waiting_conditions')
        AND id IN (/* ids */)
    `, queuedAttemptIds, now, now);
    const decisions = runFor(`
      UPDATE guided_decisions SET status = 'cancelled',
        decision_actor = ?, decision_reason = ?, decided_at = ?
      WHERE status = 'pending' AND id IN (/* ids */)
    `, impact.pendingDecisionIds, actor.id,
      "Invalidated by the exact affected plan-amendment subgraph", now);
    const steps = runFor(`
      UPDATE plan_steps SET status = 'cancelled',
        ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE status IN ('pending', 'ready', 'waiting_guided_decision')
        AND id IN (/* ids */)
        AND NOT EXISTS (
          SELECT 1 FROM actions active
          WHERE active.step_id = plan_steps.id AND active.status = 'running'
        )
    `, impact.affectedSubgraphStepIds, now, now);
    return {
      queuedActionIds,
      queuedAssignmentIds: impact.queuedAssignmentIdsToCancel,
      queuedAttackAttemptIds: queuedAttemptIds,
      pendingDecisionIds: impact.pendingDecisionIds,
      counts: { toolCalls, actions, assignments, attempts, decisions, steps },
    };
  }

  private verifyAffectedCancellationReceipt(
    resolution: PlanChangeInflightResolution,
    receipt: PlanChangeAffectedWorkStopReceipt,
  ): PlanChangeAffectedWorkStopReceipt {
    const normalizeReceiptIds = (
      values: readonly string[],
      label: string,
    ): readonly string[] => {
      const trimmed = values.map((value) => value.trim());
      const normalized = [...new Set(trimmed.filter(Boolean))].sort();
      if (
        normalized.length !== values.length
        || trimmed.some((value) => value.length === 0)
      ) {
        throw conflict(
          "plan_change_cancellation_receipt_mismatch",
          `Trusted runtime returned duplicate or empty ${label} identities`,
          "Keep the dispatch fence active and inspect the exact runtime cancellation receipt.",
        );
      }
      return normalized;
    };
    const assertExact = (
      label: string,
      expectedInput: readonly string[],
      actualInput: readonly string[],
    ): void => {
      const expected = [...expectedInput].sort();
      const actual = [...actualInput].sort();
      if (
        expected.length !== actual.length
        || expected.some((id, index) => id !== actual[index])
      ) {
        throw conflict(
          "plan_change_cancellation_receipt_mismatch",
          `Trusted runtime did not prove the exact live ${label} set`,
          "Keep the dispatch fence active and reconcile the displayed action, assignment, attempt, and step identities.",
        );
      }
    };
    const actionRows = this.database.prepare(`
      SELECT id, step_id, assignment_id FROM actions
      WHERE run_id = ? AND status = 'running'
        AND id IN (SELECT value FROM json_each(?))
      ORDER BY id
    `).all(
      resolution.runId,
      JSON.stringify(resolution.affectedActionIds),
    ) as Array<{
      readonly id: string;
      readonly step_id: string | null;
      readonly assignment_id: string | null;
    }>;
    const expectedActionIds = actionRows.map((row) => row.id);
    const actionAssignmentIds = new Set(actionRows
      .map((row) => row.assignment_id)
      .filter((value): value is string => value !== null));
    const actionStepIds = new Set(actionRows
      .map((row) => row.step_id)
      .filter((value): value is string => value !== null));
    const expectedAssignmentIds = (this.database.prepare(`
      SELECT id FROM assignments
      WHERE run_id = ? AND status IN ('active', 'blocked')
        AND id IN (SELECT value FROM json_each(?))
      ORDER BY id
    `).all(
      resolution.runId,
      JSON.stringify(resolution.affectedAssignmentIds),
    ) as Array<{ readonly id: string }>).map((row) => row.id);
    const expectedStepIds = (this.database.prepare(`
      SELECT id FROM plan_steps
      WHERE run_id = ?
        AND status IN (
          'pending', 'ready', 'running', 'waiting_guided_decision',
          'blocked', 'recovering'
        )
        AND id IN (SELECT value FROM json_each(?))
      ORDER BY id
    `).all(
      resolution.runId,
      JSON.stringify(resolution.affectedStepIds),
    ) as Array<{ readonly id: string }>).map((row) => row.id);
    const runningAttemptRows = this.database.prepare(`
      SELECT id, step_id FROM attack_attempts
      WHERE run_id = ? AND status = 'running'
        AND id IN (SELECT value FROM json_each(?))
      ORDER BY id
    `).all(
      resolution.runId,
      JSON.stringify(resolution.affectedAttackAttemptIds),
    ) as Array<{ readonly id: string; readonly step_id: string | null }>;
    const unmappedAssignment = expectedAssignmentIds.find((id) =>
      !actionAssignmentIds.has(id));
    const unmappedStep = expectedStepIds.find((id) => !actionStepIds.has(id));
    const unmappedAttempt = runningAttemptRows.find((row) =>
      row.step_id === null || !actionStepIds.has(row.step_id));
    if (unmappedAssignment || unmappedStep || unmappedAttempt) {
      throw conflict(
        "plan_change_unmapped_live_child",
        "At least one live assignment, attack attempt, or step has no stopped action proving its process boundary",
        "Keep the dispatch fence active and reconcile the orphaned runtime child before closing canonical records.",
      );
    }
    const verified: PlanChangeAffectedWorkStopReceipt = {
      stoppedActionIds: normalizeReceiptIds(receipt.stoppedActionIds, "action"),
      stoppedAssignmentIds: normalizeReceiptIds(
        receipt.stoppedAssignmentIds,
        "assignment",
      ),
      stoppedAttackAttemptIds: normalizeReceiptIds(
        receipt.stoppedAttackAttemptIds,
        "attack-attempt",
      ),
      stoppedStepIds: normalizeReceiptIds(receipt.stoppedStepIds, "step"),
    };
    assertExact("action", expectedActionIds, verified.stoppedActionIds);
    assertExact(
      "assignment",
      expectedAssignmentIds,
      verified.stoppedAssignmentIds,
    );
    assertExact(
      "attack-attempt",
      runningAttemptRows.map((row) => row.id),
      verified.stoppedAttackAttemptIds,
    );
    assertExact("step", expectedStepIds, verified.stoppedStepIds);
    return verified;
  }

  private closeCapturedAffectedWork(
    now: string,
    receipt: PlanChangeAffectedWorkStopReceipt,
  ): PlanChangeJson {
    const runFor = (sql: string, ids: readonly string[], ...prefix: unknown[]) =>
      ids.length === 0
        ? 0
        : this.database.prepare(
          sql.replace("/* ids */", ids.map(() => "?").join(", ")),
        ).run(...prefix, ...ids).changes;
    const toolCalls = runFor(`
      UPDATE tool_calls SET status = 'cancelled',
        error_category = COALESCE(error_category, 'operator_rejection'),
        ended_at = COALESCE(ended_at, ?)
      WHERE status IN ('queued', 'running') AND action_id IN (/* ids */)
    `, receipt.stoppedActionIds, now);
    const actions = runFor(`
      UPDATE actions SET status = 'cancelled',
        result_summary = COALESCE(
          result_summary,
          'Trusted runtime confirmed this affected child stopped'
        ),
        error_category = COALESCE(error_category, 'operator_rejection'),
        ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE status IN ('queued', 'running') AND id IN (/* ids */)
    `, receipt.stoppedActionIds, now, now);
    const attempts = runFor(`
      UPDATE attack_attempts SET status = 'cancelled',
        outcome_summary = COALESCE(
          outcome_summary,
          'Affected execution was stopped at a represented amendment boundary'
        ),
        ended_at = COALESCE(ended_at, ?), updated_at = ?,
        version = version + 1
      WHERE status IN ('planned', 'ready', 'running', 'blocked', 'waiting_conditions')
        AND id IN (/* ids */)
    `, receipt.stoppedAttackAttemptIds, now, now);
    const assignments = runFor(`
      UPDATE assignments SET status = 'cancelled',
        ended_at = COALESCE(ended_at, ?),
        lease_owner = NULL, lease_acquired_at = NULL,
        last_heartbeat_at = NULL, lease_expires_at = NULL,
        updated_at = ?
      WHERE status IN ('queued', 'active', 'blocked') AND id IN (/* ids */)
    `, receipt.stoppedAssignmentIds, now, now);
    const steps = runFor(`
      UPDATE plan_steps SET status = 'cancelled',
        ended_at = COALESCE(ended_at, ?), updated_at = ?
      WHERE status IN (
        'pending', 'ready', 'running', 'waiting_guided_decision',
        'blocked', 'recovering'
      ) AND id IN (/* ids */)
    `, receipt.stoppedStepIds, now, now);
    return {
      counts: { toolCalls, actions, attempts, assignments, steps },
    };
  }

  private affectedBaseStepIds(
    base: WorkingPlan,
    operations: readonly PlanChangeOperation[],
  ): ReadonlySet<string> {
    const baseIds = new Set(base.steps.map((step) => step.logicalId));
    const affected = new Set<string>();
    for (const operation of operations) {
      if (
        operation.kind === "update_plan"
        || operation.kind === "restore_plan_version"
        || operation.kind === "reorder_steps"
      ) {
        baseIds.forEach((stepId) => affected.add(stepId));
      } else if (
        operation.kind === "update_step"
        || operation.kind === "remove_step"
        || operation.kind === "set_dependencies"
        || operation.kind === "set_represented_action"
      ) {
        if (baseIds.has(operation.stepId)) affected.add(operation.stepId);
      }
    }
    // A changed prerequisite changes the meaning and safe ordering of every
    // dependent step, so the affected boundary is the transitive descendant
    // closure in the immutable base graph.
    let expanded = true;
    while (expanded) {
      expanded = false;
      for (const step of base.steps) {
        if (
          !affected.has(step.logicalId)
          && step.dependencyStepIds.some((dependency) => affected.has(dependency))
        ) {
          affected.add(step.logicalId);
          expanded = true;
        }
      }
    }
    return affected;
  }

  private inflightImpact(
    run: RunRow,
    plan: PlanRow,
    base: WorkingPlan,
    operations: readonly PlanChangeOperation[],
  ): PlanChangeInflightImpact {
    const affectedStepSet = this.affectedBaseStepIds(base, operations);
    const stepRows = this.database.prepare(`
      SELECT id, status FROM plan_steps
      WHERE plan_id = ?
        AND status IN ('running', 'waiting_guided_decision', 'blocked', 'recovering')
      ORDER BY ordinal
    `).all(plan.id) as Array<{ readonly id: string; readonly status: string }>;
    const activeStepIds = stepRows
      .filter((row) => affectedStepSet.has(row.id))
      .map((row) => row.id);
    const unaffectedActiveStepIds = stepRows
      .filter((row) => !affectedStepSet.has(row.id))
      .map((row) => row.id);
    const assignmentRows = this.database.prepare(`
      SELECT id, step_id, status FROM assignments
      WHERE run_id = ? AND status IN ('queued', 'active', 'blocked')
      ORDER BY created_at, id
    `).all(run.id) as Array<{
      readonly id: string;
      readonly step_id: string | null;
      readonly status: "queued" | "active" | "blocked";
    }>;
    const affectedAssignmentRows = assignmentRows.filter((row) =>
      row.step_id !== null && affectedStepSet.has(row.step_id));
    const unaffectedAssignmentRows = assignmentRows.filter((row) =>
      row.step_id === null || !affectedStepSet.has(row.step_id));
    const activeAssignmentIds = affectedAssignmentRows
      .filter((row) => row.status !== "queued")
      .map((row) => row.id);
    const unaffectedActiveAssignmentIds = unaffectedAssignmentRows
      .filter((row) => row.status !== "queued")
      .map((row) => row.id);
    const queuedAssignmentIds = affectedAssignmentRows
      .filter((row) => row.status === "queued")
      .map((row) => row.id);
    const allActionRows = this.database.prepare(`
      SELECT id, step_id, assignment_id, action_type, action_class, intent_summary,
        scoped_target, status,
        json_extract(normalized_arguments_json, '$.orchestration.idempotent') AS idempotent,
        json_extract(normalized_arguments_json, '$.orchestration.destructive') AS destructive
      FROM actions
      WHERE run_id = ? AND status IN ('queued', 'running')
      ORDER BY created_at, id
    `).all(run.id) as Array<{
      readonly id: string;
      readonly step_id: string | null;
      readonly assignment_id: string | null;
      readonly action_type: string;
      readonly action_class: string;
      readonly intent_summary: string;
      readonly scoped_target: string | null;
      readonly status: "queued" | "running";
      readonly idempotent: number | boolean | null;
      readonly destructive: number | boolean | null;
    }>;
    const allActions = allActionRows.map((row) => ({
      id: row.id,
      stepId: row.step_id,
      actionType: row.action_type,
      actionClass: row.action_class,
      intentSummary: row.intent_summary,
      target: row.scoped_target,
      status: row.status,
      idempotent: row.idempotent === 1 || row.idempotent === true,
      destructive: row.destructive === 1 || row.destructive === true,
    }));
    const affectedActions = allActions.filter((action) =>
      action.stepId !== null && affectedStepSet.has(action.stepId));
    const unaffectedActions = allActions.filter((action) =>
      action.stepId === null || !affectedStepSet.has(action.stepId));
    const activeActionIds = affectedActions.map((action) => action.id);
    const unaffectedActiveActionIds = unaffectedActions.map((action) => action.id);
    const decisionRows = this.database.prepare(`
      SELECT id, step_id FROM guided_decisions
      WHERE run_id = ? AND status = 'pending'
        AND COALESCE(json_extract(requested_parameters_json, '$.kind'), '')
          <> 'plan_change_review'
      ORDER BY id
    `).all(run.id) as Array<{ readonly id: string; readonly step_id: string }>;
    const pendingDecisionIds = decisionRows
      .filter((row) => affectedStepSet.has(row.step_id))
      .map((row) => row.id);
    const unaffectedPendingDecisionIds = decisionRows
      .filter((row) => !affectedStepSet.has(row.step_id))
      .map((row) => row.id);
    const allAttackAttempts = (this.database.prepare(`
      SELECT id, step_id, objective, technique_name, action_class, status,
        target_asset_id, target_service_id
      FROM attack_attempts
      WHERE run_id = ?
        AND status IN ('planned', 'ready', 'running', 'blocked', 'waiting_conditions')
      ORDER BY created_at, id
    `).all(run.id) as Array<{
      readonly id: string;
      readonly step_id: string | null;
      readonly objective: string;
      readonly technique_name: string;
      readonly action_class: string;
      readonly status: string;
      readonly target_asset_id: string | null;
      readonly target_service_id: string | null;
    }>).map((row) => ({
      id: row.id,
      stepId: row.step_id,
      objective: row.objective,
      techniqueName: row.technique_name,
      actionClass: row.action_class,
      status: row.status,
      targetAssetId: row.target_asset_id,
      targetServiceId: row.target_service_id,
    }));
    const affectedAttackAttempts = allAttackAttempts.filter((attempt) =>
      attempt.stepId !== null && affectedStepSet.has(attempt.stepId));
    const unaffectedAttackAttempts = allAttackAttempts.filter((attempt) =>
      attempt.stepId === null || !affectedStepSet.has(attempt.stepId));
    const hasCheckpoint = Boolean(this.database.prepare("SELECT id FROM checkpoints WHERE run_id = ? ORDER BY event_sequence DESC LIMIT 1").get(run.id));
    const preExecutionStatus = run.status === "queued" || run.status === "awaiting_contract_confirmation" || (run.status === "planning" && !run.lease_owner);
    const reviewedAmendmentBoundary = Boolean(this.database.prepare(`
      SELECT 1 FROM plan_change_inflight_resolutions
      WHERE run_id = ? AND base_plan_id = ?
        AND status IN ('waiting_for_terminal_work', 'ready_for_review')
      ORDER BY created_at DESC LIMIT 1
    `).get(run.id, plan.id))
      && run.status === "blocked"
      && activeActionIds.length === 0
      && activeAssignmentIds.length === 0
      && pendingDecisionIds.length === 0;
    const requiresCheckpoint = run.started_at !== null && !hasCheckpoint;
    const reasons: string[] = [];
    if (!preExecutionStatus && !reviewedAmendmentBoundary) reasons.push(`Run status ${run.status} is not a safe pre-execution or checkpointed amendment state.`);
    if (run.lease_owner) reasons.push(`Run lease is owned by ${run.lease_owner}; this service will not cancel or reinterpret its work.`);
    if (activeStepIds.length) reasons.push("One or more base-plan steps have left pending/ready state.");
    if (activeAssignmentIds.length) reasons.push("One or more specialist assignments are active or blocked.");
    if (activeActionIds.length) reasons.push("One or more represented actions are queued or running.");
    if (pendingDecisionIds.length) reasons.push("A Guided decision still binds parameters from the base plan.");
    if (unaffectedActiveActionIds.length || unaffectedActiveAssignmentIds.length) {
      reasons.push("Unrelated work is still settling and will remain untouched; plan activation waits for its terminal result.");
    }
    if (requiresCheckpoint) reasons.push("Started work has no durable checkpoint for an amendment boundary.");
    const runningAffectedActions = affectedActions.filter((action) =>
      action.status === "running");
    const runningAffectedActionIds = new Set(runningAffectedActions.map((action) =>
      action.id));
    const runningAffectedRows = allActionRows.filter((row) =>
      runningAffectedActionIds.has(row.id));
    const mappedAssignmentIds = new Set(runningAffectedRows
      .map((row) => row.assignment_id)
      .filter((value): value is string => value !== null));
    const mappedStepIds = new Set(runningAffectedRows
      .map((row) => row.step_id)
      .filter((value): value is string => value !== null));
    const cancellationChildrenMapped =
      activeAssignmentIds.every((id) => mappedAssignmentIds.has(id))
      && activeStepIds.every((id) => mappedStepIds.has(id))
      && affectedAttackAttempts
        .filter((attempt) => attempt.status === "running")
        .every((attempt) =>
          attempt.stepId !== null && mappedStepIds.has(attempt.stepId));
    const finishEligible = runningAffectedActions.length > 0
      && runningAffectedActions.every((action) =>
        action.idempotent && !action.destructive)
      && activeAssignmentIds.length <= runningAffectedActions.length;
    const unrelatedRunningAction = unaffectedActions.some((action) =>
      action.status === "running");
    const hasCancellableAffectedLiveChildren =
      activeStepIds.length > 0
      || activeAssignmentIds.length > 0
      || runningAffectedActions.length > 0
      || pendingDecisionIds.length > 0
      || affectedAttackAttempts.some((attempt) => attempt.status === "running");
    const cancelEligible =
      hasCancellableAffectedLiveChildren
      && !unrelatedRunningAction
      && cancellationChildrenMapped;
    return {
      safeToApply: reasons.length === 0,
      runStatus: run.status,
      leaseOwner: run.lease_owner,
      affectedSubgraphStepIds: [...affectedStepSet].sort(),
      activeStepIds,
      unaffectedActiveStepIds,
      activeAssignmentIds,
      unaffectedActiveAssignmentIds,
      activeActionIds,
      unaffectedActiveActionIds,
      pendingDecisionIds,
      unaffectedPendingDecisionIds,
      queuedAssignmentIdsToCancel: queuedAssignmentIds,
      affectedActions,
      unaffectedActions,
      affectedAttackAttempts,
      unaffectedAttackAttempts,
      resolutionOptions: [
        {
          mode: "checkpoint_finish_idempotent_work",
          label: "Checkpoint and finish repeat-safe work",
          consequence: "Stops new dispatch, lets only the displayed repeat-safe actions reach a real terminal result, then creates a fresh diff for review.",
          enabled: finishEligible,
          disabledReason: finishEligible
            ? null
            : "Every active action must be explicitly repeat-safe, non-destructive, and matched to the affected assignments.",
        },
        {
          mode: "checkpoint_cancel_affected_work",
          label: "Checkpoint and cancel affected work",
          consequence: "Uses the trusted runtime cancellation boundary, closes only the displayed work, then creates a fresh diff for review.",
          enabled: cancelEligible,
          disabledReason: cancelEligible
            ? null
            : !hasCancellableAffectedLiveChildren
              ? "No affected live child requires runtime cancellation."
              : unrelatedRunningAction
              ? "An unrelated running child is present and this runtime exposes only run-scoped process cancellation; Ti-Scale will not stop unrelated work."
              : "A live assignment, attack attempt, or step is not mapped to a running affected action, so process termination cannot yet be proven.",
        },
      ],
      requiresCheckpoint,
      requiresCancellation: hasCancellableAffectedLiveChildren,
      reasons,
    };
  }

  private diff(base: WorkingPlan, working: WorkingPlan): readonly PlanChangeDiffEntry[] {
    const entries: PlanChangeDiffEntry[] = [];
    const add = (kind: PlanChangeDiffEntry["kind"], path: string, label: string, before: unknown, after: unknown) => entries.push({ kind, path, label, before: jsonValue(before), after: jsonValue(after) });
    if (base.strategySummary !== working.strategySummary) add("replace", "strategySummary", "Strategy summary", base.strategySummary, working.strategySummary);
    if (base.rationaleSummary !== working.rationaleSummary) add("replace", "rationaleSummary", "Plan rationale", base.rationaleSummary, working.rationaleSummary);
    const baseMap = new Map(base.steps.map((step, ordinal) => [step.logicalId, { step, ordinal }]));
    const nextMap = new Map(working.steps.map((step, ordinal) => [step.logicalId, { step, ordinal }]));
    for (const [id, previous] of baseMap) if (!nextMap.has(id)) add("remove", `steps[${id}]`, `Remove ${previous.step.title}`, previous.step, null);
    for (const [id, next] of nextMap) {
      const previous = baseMap.get(id);
      if (!previous) { add("add", `steps[${id}]`, `Add ${next.step.title}`, null, next.step); continue; }
      if (previous.ordinal !== next.ordinal) add("move", `steps[${id}].ordinal`, `${next.step.title} order`, previous.ordinal, next.ordinal);
      for (const [field, label] of [["phase", "Phase"], ["title", "Title"], ["objective", "Objective"], ["successCriteria", "Success criteria"], ["dependencyStepIds", "Dependencies"], ["actionClass", "Action class"], ["riskClass", "Risk class"], ["assignedAgentId", "Assigned specialist"], ["representation", "Exact represented action"]] as const) {
        if (canonical(jsonValue(previous.step[field])) !== canonical(jsonValue(next.step[field]))) add("replace", `steps[${id}].${field}`, `${next.step.title}: ${label}`, previous.step[field], next.step[field]);
      }
    }
    return entries;
  }

  private affectedRefs(operations: readonly PlanChangeOperation[], diff: readonly PlanChangeDiffEntry[], working: WorkingPlan): PlanChangeAffectedRefs {
    const stepIds = new Set<string>();
    const added = new Set<string>();
    const removed = new Set<string>();
    for (const operation of operations) {
      if (operation.kind === "restore_plan_version") working.steps.forEach((step) => stepIds.add(step.logicalId));
      if ("stepId" in operation) stepIds.add(operation.stepId);
      if (operation.kind === "add_step") { added.add(operation.clientStepId); stepIds.add(operation.clientStepId); }
      if (operation.kind === "remove_step") removed.add(operation.stepId);
      if (operation.kind === "reorder_steps") operation.orderedStepIds.forEach((id) => stepIds.add(id));
    }
    for (const entry of diff) {
      const match = /^steps\[([^\]]+)\]$/u.exec(entry.path);
      if (entry.kind === "remove" && match?.[1]) {
        removed.add(match[1]);
        stepIds.add(match[1]);
      }
    }
    return {
      stepIds: [...stepIds].sort(),
      addedClientStepIds: [...added].sort(),
      removedStepIds: [...removed].sort(),
      agentIds: [...new Set(working.steps.map((step) => step.assignedAgentId).filter((id): id is string => Boolean(id)))].sort(),
      actionClasses: [...new Set(working.steps.map((step) => step.actionClass).filter((id): id is string => Boolean(id)))].sort(),
    };
  }

  private interpretation(operations: readonly PlanChangeOperation[], diff: readonly PlanChangeDiffEntry[]): string {
    const restore = operations.find((operation) => operation.kind === "restore_plan_version");
    if (restore?.kind === "restore_plan_version") {
      return `Restore historical plan v${restore.targetPlanVersion} as a new immutable version after reviewing ${diff.length} exact field or graph differences. No action will execute as part of this plan-version change.`;
    }
    const counts = new Map<string, number>();
    for (const operation of operations) counts.set(operation.kind, (counts.get(operation.kind) ?? 0) + 1);
    const labels = [...counts.entries()].map(([kind, count]) => `${count} ${kind.replaceAll("_", " ")}`).join(", ");
    return `Apply ${diff.length} exact field or graph differences from ${labels}. No action will execute as part of this plan-version change.`;
  }

  private contentFingerprint(plan: WorkingPlan): string {
    const ordinals = new Map(plan.steps.map((step, ordinal) => [step.logicalId, ordinal]));
    const steps = plan.steps.map((step): PlannedStep => {
      if (!isJsonObject(step.representation) || !isJsonObject(step.representation.action)) {
        throw conflict("plan_change_representation_corrupt", `Step ${step.logicalId} has no exact represented action`, "Reconcile the immutable plan history before applying a plan change.");
      }
      const action = step.representation.action;
      const dependencyOrdinals = step.dependencyStepIds.map((dependencyId) => {
        const ordinal = ordinals.get(dependencyId);
        if (ordinal === undefined) throw conflict("plan_change_dependency_invalid", `Dependency ${dependencyId} is missing`, "Correct the dependency graph before applying the plan.");
        return ordinal;
      });
      return {
        phase: step.phase,
        title: step.title,
        objective: step.objective,
        explanation: String(step.representation.explanation),
        rationale: String(step.representation.rationale),
        successCriteria: step.successCriteria,
        dependencyOrdinals,
        assignedAgentId: step.assignedAgentId!,
        riskClass: step.riskClass as PlannedStep["riskClass"],
        reversibility: String(step.representation.reversibility),
        action: {
          actionType: String(action.actionType),
          actionClass: step.actionClass!,
          target: String(action.target),
          arguments: action.arguments as Readonly<Record<string, unknown>>,
          intentSummary: String(action.intentSummary),
          kind: action.kind as PlannedStep["action"]["kind"],
          idempotent: action.idempotent as boolean,
          destructive: action.destructive as boolean,
        },
      };
    });
    return planContentFingerprint({ strategySummary: plan.strategySummary, steps });
  }

  private exactAction(step: WorkingStep): { readonly [key: string]: PlanChangeJson } | null {
    if (!isJsonObject(step.representation) || !isJsonObject(step.representation.action)) return null;
    return step.representation.action;
  }

  private representation(
    input: Extract<PlanChangeOperation, { readonly kind: "add_step" | "set_represented_action" }>["representation"],
    actionClass: string | null,
  ): PlanChangeJson {
    return jsonValue({
      action: { ...input.action, actionClass },
      explanation: input.explanation,
      rationale: input.rationale,
      reversibility: input.reversibility,
      dependencies: [],
    });
  }

  private remapRepresentation(step: WorkingStep, dependencyIds: readonly string[]): PlanChangeJson {
    if (!isJsonObject(step.representation)) {
      throw conflict("plan_change_representation_missing", `Step ${step.logicalId} has no exact represented action`, "Complete the step's exact action representation in a separately reviewed proposal before activation.");
    }
    const action = step.representation.action;
    if (!isJsonObject(action)) {
      throw conflict("plan_change_representation_corrupt", `Step ${step.logicalId} has an invalid represented action`, "Reconcile the base plan representation before applying this proposal.");
    }
    return {
      ...step.representation,
      action: { ...action, actionClass: step.actionClass },
      dependencies: [...dependencyIds],
    };
  }

  private reconcileExpiredInflightResolutions(): void {
    const now = this.clock().toISOString();
    const expired = this.database.prepare(`
      SELECT plan_change_request_id, version
      FROM plan_change_inflight_resolutions
      WHERE status = 'waiting_for_terminal_work'
        AND settle_deadline_at <= ?
      ORDER BY settle_deadline_at, id
    `).all(now) as Array<{
      readonly plan_change_request_id: string;
      readonly version: number;
    }>;
    for (const row of expired) {
      inImmediateTransaction(this.database, () => {
        const current = this.repository.getInflightResolution(
          row.plan_change_request_id,
        );
        if (
          !current
          || current.status !== "waiting_for_terminal_work"
          || current.version !== row.version
          || current.settleDeadlineAt > now
        ) return;
        const request = this.repository.get(row.plan_change_request_id);
        const failureReason = "The affected work did not settle before the bounded five-minute amendment deadline.";
        const failed = this.repository.failInflightResolution({
          requestId: row.plan_change_request_id,
          expectedVersion: row.version,
          failureReason,
          now,
        });
        this.database.prepare(`
          UPDATE runs SET status = 'blocked', status_reason = ?,
            next_action_summary = ?, updated_at = ?, version = version + 1
          WHERE id = ? AND status NOT IN ('completed', 'failed', 'cancelled')
        `).run(
          failureReason,
          "Inspect the preserved amendment checkpoint and choose a bounded recovery",
          now,
          failed.runId,
        );
        this.recordTransition(
          request,
          { id: "plan-change-settlement-supervisor", type: "admin" },
          "plan_change.inflight_resolution_timed_out",
          failureReason,
          {
            resolutionId: failed.id,
            settleDeadlineAt: failed.settleDeadlineAt,
            lastHeartbeatAt: failed.lastHeartbeatAt,
            dispatchRemainsFenced: true,
            signedContractChanged: false,
          },
        );
      });
    }
  }

  private run(runId: string): RunRow {
    const row = this.database.prepare(`SELECT id, mission_id, journey, status, current_plan_id, current_step_id, contract_id, lease_owner, started_at, version FROM runs WHERE id = ?`).get(runId) as RunRow | undefined;
    if (!row) throw new PlanChangeError("plan_change_run_not_found", `Run not found: ${runId}`, "not_found", 404, "Refresh the mission and use a canonical run link.");
    return row;
  }

  private plan(planId: string): PlanRow {
    const row = this.database.prepare("SELECT id, run_id, version, status, strategy_summary, rationale_summary FROM plans WHERE id = ?").get(planId) as PlanRow | undefined;
    if (!row) throw new PlanChangeError("plan_change_plan_not_found", `Plan not found: ${planId}`, "not_found", 404, "Refresh the selected run and choose its current plan.");
    return row;
  }

  private planForRun(planId: string, runId: string): PlanRow {
    const row = this.database.prepare("SELECT id, run_id, version, status, strategy_summary, rationale_summary FROM plans WHERE id = ? AND run_id = ?").get(planId, runId) as PlanRow | undefined;
    if (!row) throw new PlanChangeError("plan_change_plan_not_found", "Historical plan was not found in this run", "not_found", 404, "Refresh the selected run and choose one of its visible historical plans.");
    return row;
  }

  private assertPlanScope(plan: PlanRow, run: RunRow): void {
    if (plan.run_id !== run.id) throw this.scopeConflict("Base plan does not belong to the supplied run");
  }

  private scopeConflict(message: string): PlanChangeError {
    return new PlanChangeError("plan_change_scope_conflict", message, "scope_conflict", 409, "Use mission, run, and plan identifiers from the same authorized workspace.");
  }

  private assertOptimisticVersions(run: RunRow, plan: PlanRow, expectedRunVersion: number, expectedPlanVersion: number): void {
    this.assertPlanScope(plan, run);
    if (run.version !== expectedRunVersion) throw conflict("plan_change_run_version_conflict", `Run version ${run.version} does not match expected version ${expectedRunVersion}`, "Reload the run and review changed in-flight state before resubmitting.");
    if (plan.version !== expectedPlanVersion) throw conflict("plan_change_plan_version_conflict", `Plan version ${plan.version} does not match expected version ${expectedPlanVersion}`, "Reload the current plan before resubmitting the amendment.");
  }

  private assertMutableRun(run: RunRow): void {
    if (["completed", "failed", "cancelled"].includes(run.status)) throw conflict("plan_change_terminal_run", "Terminal runs cannot accept plan amendments", "Create a new run from the durable mission instead.");
  }

  private assertOpenRequest(request: PlanChangeRequest): void {
    if (request.status !== "proposed" && request.status !== "validated") throw conflict("plan_change_already_resolved", `Plan change request is already ${request.status}`, "Open the resulting plan or create a new proposal.");
  }

  private assertValidatedRequest(request: PlanChangeRequest): void {
    if (request.status !== "validated") {
      throw conflict(
        "plan_change_not_validated",
        `Plan change request is ${request.status}, not validated`,
        "Resolve every displayed policy, dependency, readiness, and in-flight blocker, then save a new reviewed proposal version before applying it.",
      );
    }
  }

  private recordTransition(request: PlanChangeRequest, actor: PlanChangeActor, eventType: string, summary: string, details: PlanChangeJson): void {
    const now = this.clock().toISOString();
    this.events.append({
      runId: request.runId,
      missionId: request.missionId,
      eventType,
      occurredAt: now,
      actorType: "operator",
      actorId: actor.id,
      summary,
      payload: JSON.parse(JSON.stringify({
        requestId: request.id,
        basePlanId: request.basePlanId,
        requestVersion: request.version,
        details,
      })) as EventJsonValue,
      schemaVersion: 1,
      sensitivity: "internal",
      redaction: {},
    });
    const previous = this.database.prepare("SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1").get() as { readonly record_hash: string } | undefined;
    const auditId = `audit_${randomUUID()}`;
    const auditBody = {
      id: auditId,
      missionId: request.missionId,
      runId: request.runId,
      journey: request.policyValidation.journey,
      actorType: actor.type,
      actorId: actor.id,
      action: eventType,
      resourceType: "plan_change_request",
      resourceId: request.id,
      reason: summary,
      details,
      previousHash: previous?.record_hash ?? null,
      occurredAt: now,
    } satisfies PlanChangeJson;
    const recordHash = sha256(`${previous?.record_hash ?? ""}\n${canonical(auditBody)}`);
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json, previous_hash,
        record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'plan_change_request', ?, ?, ?, ?, ?, ?)
    `).run(auditId, request.missionId, request.runId, request.policyValidation.journey, actor.type, actor.id, eventType, request.id, summary, JSON.stringify(details), previous?.record_hash ?? null, recordHash, now);
  }
}

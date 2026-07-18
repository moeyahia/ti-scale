import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { ACTION_CLASS_DEFINITIONS } from "../domain/action-class-registry";
import { evaluateDestructiveAuthorization } from "../domain/destructive-policy";
import { isActionClassId } from "../domain/catalog-ids";
import { EventRepository } from "../events/EventRepository";
import type { JsonValue as EventJsonValue } from "../events/types";
import type {
  ApplyPlanChangeInput,
  CreatePlanChangeInput,
  EditPlanChangeInput,
  NormalizedPlanChange,
  PlanChangeActor,
  PlanChangeAffectedRefs,
  PlanChangeBudgetImpact,
  PlanChangeDependencyImpact,
  PlanChangeDiffEntry,
  PlanChangeInflightImpact,
  PlanChangeJson,
  PlanChangeOperation,
  PlanChangePolicyValidation,
  PlanChangeReadinessImpact,
  PlanChangeRequest,
  RejectPlanChangeInput,
} from "./types";
import { PlanChangeError } from "./types";
import { PlanChangeRepository, type PersistPlanChangeEvaluation } from "./PlanChangeRepository";

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
const DEFAULT_ACTION_POLICY = new Map(ACTION_CLASS_DEFINITIONS.map((entry) => [entry.id, entry.defaultPolicyState]));

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

  apply(input: ApplyPlanChangeInput, actor: PlanChangeActor): { readonly request: PlanChangeRequest; readonly resultPlanId: string; readonly resultPlanVersion: number } {
    return inImmediateTransaction(this.database, () => {
      const current = this.repository.get(input.requestId);
      if (current.version !== input.expectedRequestVersion) throw conflict("plan_change_version_conflict", "Plan change request changed before apply", "Reload and review the latest proposal and impact analysis.");
      this.assertOpenRequest(current);
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

      const resultPlanId = this.repository.nextId("plan");
      const resultPlanVersion = (this.database.prepare("SELECT COALESCE(MAX(version), 0) + 1 AS version FROM plans WHERE run_id = ?").get(run.id) as { readonly version: number }).version;
      const now = this.clock().toISOString();
      const snapshot = this.planSnapshot(evaluation.workingPlan);
      const planHash = sha256(canonical(snapshot));
      this.database.prepare(`
        INSERT INTO plans (id, run_id, version, status, strategy_summary, rationale_summary, plan_hash, created_by, created_at, activated_at)
        VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
      `).run(resultPlanId, run.id, resultPlanVersion, evaluation.workingPlan.strategySummary, evaluation.workingPlan.rationaleSummary, planHash, `${actor.type}:${actor.id}`, now, now);

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
        VALUES (?, ?, ?, ?, 'queued', ?, ?)
      `);
      const insertRepresentation = this.database.prepare(`
        INSERT INTO mission_constraints (
          id, mission_id, constraint_type, value_json, source, created_at
        ) VALUES (?, ?, 'represented_action', ?, ?, ?)
      `);
      let firstReadyStepId: string | null = null;
      evaluation.workingPlan.steps.forEach((step, ordinal) => {
        const stepId = idMap.get(step.logicalId)!;
        const dependencies = step.dependencyStepIds.map((dependency) => idMap.get(dependency)!);
        const status = dependencies.length === 0 ? "ready" : "pending";
        if (!firstReadyStepId && status === "ready") firstReadyStepId = stepId;
        const stepSnapshot = {
          sourceStepId: step.sourceStepId,
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
        if (step.assignedAgentId) insertAssignment.run(this.repository.nextId("assignment"), run.id, stepId, step.assignedAgentId, now, now);
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
        cancelledQueuedAssignmentIds: evaluation.inflightImpact.queuedAssignmentIdsToCancel,
        executionStarted: false,
      });
      return { request, resultPlanId, resultPlanVersion };
    });
  }

  private evaluate(run: RunRow, plan: PlanRow, operations: readonly PlanChangeOperation[]): Evaluation {
    const base = this.workingPlan(plan);
    const working = this.clone(base);
    this.applyOperations(working, operations);
    const dependencyImpact = this.dependencyImpact(base, working, operations);
    const policyValidation = this.policyValidation(run, working);
    const readinessImpact = this.readinessImpact(working);
    const inflightImpact = this.inflightImpact(run, plan);
    const structuredDiff = this.diff(base, working);
    if (structuredDiff.length === 0) throw conflict("plan_change_no_effect", "The structured amendment does not change the base plan", "Change at least one plan or step value, or reject the proposal.");
    const affectedRefs = this.affectedRefs(operations, structuredDiff, working);
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

  private applyOperations(plan: WorkingPlan, operations: readonly PlanChangeOperation[]): void {
    const find = (stepId: string): WorkingStep => {
      const step = plan.steps.find((candidate) => candidate.logicalId === stepId);
      if (!step) throw conflict("plan_change_step_not_found", `Plan step is not present in the amended graph: ${stepId}`, "Use a step from the current base plan or an earlier draft step in this proposal.");
      return step;
    };
    for (const operation of operations) {
      if (operation.kind === "update_plan") {
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
      reordered: operations.some((operation) => operation.kind === "reorder_steps"),
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
            if (!actionType || !allowed.has(actionType) || denied.has(actionType)) {
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

  private inflightImpact(run: RunRow, plan: PlanRow): PlanChangeInflightImpact {
    const activeStepIds = (this.database.prepare(`SELECT id FROM plan_steps WHERE plan_id = ? AND status NOT IN ('pending', 'ready') ORDER BY ordinal`).all(plan.id) as Array<{ readonly id: string }>).map((row) => row.id);
    const activeAssignmentIds = (this.database.prepare("SELECT id FROM assignments WHERE run_id = ? AND status IN ('active', 'blocked') ORDER BY id").all(run.id) as Array<{ readonly id: string }>).map((row) => row.id);
    const queuedAssignmentIds = (this.database.prepare(`SELECT id FROM assignments WHERE run_id = ? AND status = 'queued' AND step_id IN (SELECT id FROM plan_steps WHERE plan_id = ?) ORDER BY id`).all(run.id, plan.id) as Array<{ readonly id: string }>).map((row) => row.id);
    const activeActionIds = (this.database.prepare("SELECT id FROM actions WHERE run_id = ? AND status IN ('queued', 'running') ORDER BY id").all(run.id) as Array<{ readonly id: string }>).map((row) => row.id);
    const pendingDecisionIds = (this.database.prepare("SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending' ORDER BY id").all(run.id) as Array<{ readonly id: string }>).map((row) => row.id);
    const hasCheckpoint = Boolean(this.database.prepare("SELECT id FROM checkpoints WHERE run_id = ? ORDER BY event_sequence DESC LIMIT 1").get(run.id));
    const preExecutionStatus = run.status === "queued" || run.status === "awaiting_contract_confirmation" || (run.status === "planning" && !run.lease_owner);
    const requiresCheckpoint = run.started_at !== null && !hasCheckpoint;
    const reasons: string[] = [];
    if (!preExecutionStatus) reasons.push(`Run status ${run.status} is not a safe pre-execution amendment state.`);
    if (run.lease_owner) reasons.push(`Run lease is owned by ${run.lease_owner}; this service will not cancel or reinterpret its work.`);
    if (activeStepIds.length) reasons.push("One or more base-plan steps have left pending/ready state.");
    if (activeAssignmentIds.length) reasons.push("One or more specialist assignments are active or blocked.");
    if (activeActionIds.length) reasons.push("One or more represented actions are queued or running.");
    if (pendingDecisionIds.length) reasons.push("A Guided decision still binds parameters from the base plan.");
    if (requiresCheckpoint) reasons.push("Started work has no durable checkpoint for an amendment boundary.");
    return {
      safeToApply: reasons.length === 0,
      runStatus: run.status,
      leaseOwner: run.lease_owner,
      activeStepIds,
      activeAssignmentIds,
      activeActionIds,
      pendingDecisionIds,
      queuedAssignmentIdsToCancel: queuedAssignmentIds,
      requiresCheckpoint,
      requiresCancellation: activeStepIds.length + activeAssignmentIds.length + activeActionIds.length + pendingDecisionIds.length > 0,
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
      if ("stepId" in operation) stepIds.add(operation.stepId);
      if (operation.kind === "add_step") { added.add(operation.clientStepId); stepIds.add(operation.clientStepId); }
      if (operation.kind === "remove_step") removed.add(operation.stepId);
      if (operation.kind === "reorder_steps") operation.orderedStepIds.forEach((id) => stepIds.add(id));
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
    const counts = new Map<string, number>();
    for (const operation of operations) counts.set(operation.kind, (counts.get(operation.kind) ?? 0) + 1);
    const labels = [...counts.entries()].map(([kind, count]) => `${count} ${kind.replaceAll("_", " ")}`).join(", ");
    return `Apply ${diff.length} exact field or graph differences from ${labels}. No action will execute as part of this plan-version change.`;
  }

  private planSnapshot(plan: WorkingPlan): PlanChangeJson {
    return jsonValue({ strategySummary: plan.strategySummary, rationaleSummary: plan.rationaleSummary, steps: plan.steps });
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

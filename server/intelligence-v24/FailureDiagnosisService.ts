import type { SqliteDatabase } from "../db";
import { invalid, stateConflict } from "./errors";
import { FailureDiagnosisRepository, type FailureRepositoryOptions } from "./FailureDiagnosisRepository";
import {
  FAILURE_CATEGORIES,
  FAILURE_OPERATOR_ACTION_KINDS,
  type CreateFailureDiagnosisInput,
  type FailureCategory,
  type FailureDiagnosis,
  type FailureDiagnosisState,
  type FailureOperatorAction,
  type FailureOperatorActionKind,
  type FailureReference,
  type JsonValue,
  type OperationalActor,
  type ResolveFailureDiagnosisInput,
} from "./types";
import { identifier, sanitizedJson, text } from "./validation";

const FAILURE_CATEGORY_SET = new Set<string>(FAILURE_CATEGORIES);
const TRANSIENT_CATEGORIES = new Set<FailureCategory>([
  "mcp_unavailable",
  "provider_unavailable",
  "rate_limit",
  "target_unreachable",
  "timeout",
  "worker_lost",
]);
const ACTIONS = new Set<FailureOperatorActionKind>(FAILURE_OPERATOR_ACTION_KINDS);

function actor(value: OperationalActor): OperationalActor {
  return { id: identifier(value.id, "actor.id"), type: value.type };
}

function optionalId(value: string | undefined, label: string): string | undefined {
  return value === undefined ? undefined : identifier(value, label);
}

function optionalText(value: string | undefined, label: string, maximum = 2_000): string | undefined {
  return value === undefined ? undefined : text(value, label, maximum);
}

function normalizeActions(actions: readonly FailureOperatorAction[], retryable: boolean): readonly FailureOperatorAction[] {
  if (actions.length === 0 || actions.length > 20) {
    throw invalid("operator_actions_required", "Failure diagnosis requires 1-20 valid operator actions");
  }
  const seen = new Set<FailureOperatorActionKind>();
  return actions.map((action) => {
    if (!ACTIONS.has(action.kind) || seen.has(action.kind)) {
      throw invalid("invalid_operator_action", "Failure diagnosis actions must be valid and unique");
    }
    if (action.kind === "retry_bounded" && !retryable) {
      throw invalid("unsafe_retry_action", "A non-retryable failure cannot offer a retry action");
    }
    seen.add(action.kind);
    return {
      kind: action.kind,
      label: text(action.label, "operatorAction.label", 300),
      consequence: text(action.consequence, "operatorAction.consequence", 1_000),
      requiresConfirmation: action.requiresConfirmation,
    };
  });
}

function normalizeReferences(references: readonly FailureReference[]): readonly FailureReference[] {
  if (references.length > 100) throw invalid("too_many_preserved_references", "Failure diagnosis preserves at most 100 references");
  const seen = new Set<string>();
  return references.map((reference) => {
    const id = identifier(reference.id, "preservedReference.id");
    const key = `${reference.kind}:${id}`;
    if (seen.has(key)) throw invalid("duplicate_preserved_reference", "Preserved failure references must be unique");
    seen.add(key);
    return { kind: reference.kind, id, meaning: text(reference.meaning, "preservedReference.meaning", 1_000) };
  });
}

/** Structured, explainable failure persistence and recovery-read service. */
export class FailureDiagnosisService {
  readonly repository: FailureDiagnosisRepository;

  constructor(database: SqliteDatabase, options: FailureRepositoryOptions = {}) {
    this.repository = new FailureDiagnosisRepository(database, options);
  }

  create(input: CreateFailureDiagnosisInput): FailureDiagnosis {
    if (!FAILURE_CATEGORY_SET.has(input.category)) throw invalid("invalid_failure_category", "Failure category is not canonical");
    if (input.retryable && !TRANSIENT_CATEGORIES.has(input.category)) {
      throw invalid("invalid_retryability", "Only explicitly transient failure categories may be marked retryable");
    }
    const missionId = identifier(input.missionId, "missionId");
    const runId = optionalId(input.runId, "runId");
    const stepId = optionalId(input.stepId, "stepId");
    const assignmentId = optionalId(input.assignmentId, "assignmentId");
    const actionId = optionalId(input.actionId, "actionId");
    const attackAttemptId = optionalId(input.attackAttemptId, "attackAttemptId");
    const subjectId = identifier(input.subjectId, "subjectId");
    const createdBy = actor(input.actor);
    const now = this.repository.now();
    const retryHistory = sanitizedJson(input.retryHistory ?? []).value;
    const progress = sanitizedJson(input.progressBeforeFailure ?? {}).value;
    const preserved = normalizeReferences(input.preservedReferences ?? []);
    const automaticRecovery = sanitizedJson(input.automaticRecovery ?? []).value;
    const operatorActions = normalizeActions(input.operatorActions, input.retryable);
    return this.repository.transaction(() => {
      this.repository.assertSubject({
        missionId,
        ...(runId ? { runId } : {}),
        ...(stepId ? { stepId } : {}),
        ...(assignmentId ? { assignmentId } : {}),
        ...(actionId ? { actionId } : {}),
        ...(attackAttemptId ? { attackAttemptId } : {}),
        subjectType: input.subjectType,
        subjectId,
      });
      const lastSuccessEventId = optionalId(input.lastSuccessEventId, "lastSuccessEventId");
      if (lastSuccessEventId) this.repository.assertEventScope(lastSuccessEventId, missionId, runId);
      const rawErrorLogId = optionalId(input.rawErrorLogId, "rawErrorLogId");
      if (rawErrorLogId) this.repository.assertErrorLogScope(rawErrorLogId, missionId, runId);
      const id = this.repository.nextId("failure");
      const diagnosis = this.repository.insert({
        id,
        mission_id: missionId,
        run_id: runId ?? null,
        step_id: stepId ?? null,
        assignment_id: assignmentId ?? null,
        action_id: actionId ?? null,
        attack_attempt_id: attackAttemptId ?? null,
        subject_type: input.subjectType,
        subject_id: subjectId,
        human_reason: text(input.humanReason, "humanReason", 4_000),
        category: input.category,
        code: identifier(input.code, "code"),
        originating_component: identifier(input.originatingComponent, "originatingComponent"),
        last_success_event_id: lastSuccessEventId ?? null,
        failed_component_ref: optionalText(input.failedComponentRef, "failedComponentRef", 1_000) ?? null,
        target_summary: optionalText(input.targetSummary, "targetSummary", 2_000) ?? null,
        policy_or_dependency: optionalText(input.policyOrDependency, "policyOrDependency", 2_000) ?? null,
        raw_error_log_id: rawErrorLogId ?? null,
        retry_history_json: this.repository.serialize(retryHistory),
        progress_before_failure_json: this.repository.serialize(progress),
        preserved_refs_json: this.repository.serialize(preserved as unknown as JsonValue),
        retryable: input.retryable ? 1 : 0,
        automatic_recovery_json: this.repository.serialize(automaticRecovery),
        remediation: text(input.remediation, "remediation", 4_000),
        operator_actions_json: this.repository.serialize(operatorActions as unknown as JsonValue),
        objective_impact: text(input.objectiveImpact, "objectiveImpact", 4_000),
        state: input.terminal ? "terminal" : "active",
        created_at: now,
        resolved_at: null,
      });
      this.repository.audit.append({
        missionId,
        ...(runId ? { runId } : {}),
        actor: createdBy,
        action: "failure_diagnosis.created",
        resourceType: "failure_diagnosis",
        resourceId: id,
        reason: diagnosis.humanReason,
        details: {
          subjectType: diagnosis.subjectType,
          subjectId: diagnosis.subjectId,
          category: diagnosis.category,
          code: diagnosis.code,
          retryable: diagnosis.retryable,
          operatorActions: diagnosis.operatorActions.map((action) => action.kind),
        },
        occurredAt: now,
      });
      return diagnosis;
    });
  }

  get(diagnosisId: string): FailureDiagnosis {
    return this.repository.get(identifier(diagnosisId, "diagnosisId"));
  }

  listForRun(
    runId: string,
    states: readonly FailureDiagnosisState[] = ["active", "terminal"],
    limit = 100,
  ): readonly FailureDiagnosis[] {
    return this.repository.listForRun(identifier(runId, "runId"), states, limit);
  }

  resolve(input: ResolveFailureDiagnosisInput): FailureDiagnosis {
    const diagnosisId = identifier(input.diagnosisId, "diagnosisId");
    const resolvedBy = actor(input.actor);
    const now = this.repository.now();
    return this.repository.transaction(() => {
      const current = this.repository.get(diagnosisId);
      if (current.state !== "active" && current.state !== "terminal") {
        throw stateConflict(
          `Failure diagnosis in state ${current.state} cannot be resolved`,
          "Select an active or terminal diagnosis that still requires an operator-verified resolution.",
        );
      }
      const declaredAction = current.operatorActions.find((action) => action.kind === input.actionKind);
      if (!declaredAction) {
        throw invalid(
          "undeclared_failure_resolution_action",
          "The selected recovery action was not declared by this failure diagnosis",
          "Refresh the diagnosis and select one of its server-declared operator actions.",
        );
      }
      if (input.confirmed !== true) {
        throw invalid(
          "failure_resolution_confirmation_required",
          "Failure resolution requires explicit confirmation of the declared action and verified outcome",
          "Confirm only after the selected declared action was completed and its outcome was verified.",
        );
      }
      const verifiedOutcome = text(input.verifiedOutcome, "verifiedOutcome", 4_000);
      if (verifiedOutcome.length < 16) {
        throw invalid(
          "failure_resolution_outcome_too_short",
          "verifiedOutcome must contain at least 16 characters explaining what changed and how it was verified",
          "Record an attributable outcome before resolving the diagnosis.",
        );
      }
      const resolution = `Declared recovery action: ${declaredAction.kind} — ${declaredAction.label}. Operator-verified outcome: ${verifiedOutcome}`;
      const resolved = this.repository.resolve(diagnosisId, now);
      this.repository.audit.append({
        missionId: current.missionId,
        ...(current.runId ? { runId: current.runId } : {}),
        actor: resolvedBy,
        action: "failure_diagnosis.resolved",
        resourceType: "failure_diagnosis",
        resourceId: diagnosisId,
        reason: resolution,
        details: {
          from: current.state,
          to: resolved.state,
          category: current.category,
          code: current.code,
          actionKind: declaredAction.kind,
          actionLabel: declaredAction.label,
          actionRequiresConfirmation: declaredAction.requiresConfirmation,
          verifiedOutcome,
          confirmed: true,
        },
        occurredAt: now,
      });
      return resolved;
    });
  }
}

import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { missing, scopeConflict, stateConflict } from "./errors";
import type {
  FailureDiagnosis,
  FailureDiagnosisState,
  FailureOperatorAction,
  FailureReference,
  JsonValue,
} from "./types";
import { AuditTrailWriter } from "./AuditTrailWriter";
import { canonicalJson, parseJson } from "./validation";

interface FailureRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly step_id: string | null;
  readonly assignment_id: string | null;
  readonly action_id: string | null;
  readonly attack_attempt_id: string | null;
  readonly subject_type: FailureDiagnosis["subjectType"];
  readonly subject_id: string;
  readonly human_reason: string;
  readonly category: FailureDiagnosis["category"];
  readonly code: string;
  readonly originating_component: string;
  readonly last_success_event_id: string | null;
  readonly failed_component_ref: string | null;
  readonly target_summary: string | null;
  readonly policy_or_dependency: string | null;
  readonly raw_error_log_id: string | null;
  readonly retry_history_json: string;
  readonly progress_before_failure_json: string;
  readonly preserved_refs_json: string;
  readonly retryable: number;
  readonly automatic_recovery_json: string;
  readonly remediation: string;
  readonly operator_actions_json: string;
  readonly objective_impact: string;
  readonly state: FailureDiagnosisState;
  readonly created_at: string;
  readonly resolved_at: string | null;
}

function mapFailure(row: FailureRow): FailureDiagnosis {
  return {
    id: row.id,
    missionId: row.mission_id,
    ...(row.run_id ? { runId: row.run_id } : {}),
    ...(row.step_id ? { stepId: row.step_id } : {}),
    ...(row.assignment_id ? { assignmentId: row.assignment_id } : {}),
    ...(row.action_id ? { actionId: row.action_id } : {}),
    ...(row.attack_attempt_id ? { attackAttemptId: row.attack_attempt_id } : {}),
    subjectType: row.subject_type,
    subjectId: row.subject_id,
    humanReason: row.human_reason,
    category: row.category,
    code: row.code,
    originatingComponent: row.originating_component,
    ...(row.last_success_event_id ? { lastSuccessEventId: row.last_success_event_id } : {}),
    ...(row.failed_component_ref ? { failedComponentRef: row.failed_component_ref } : {}),
    ...(row.target_summary ? { targetSummary: row.target_summary } : {}),
    ...(row.policy_or_dependency ? { policyOrDependency: row.policy_or_dependency } : {}),
    ...(row.raw_error_log_id ? { rawErrorLogId: row.raw_error_log_id } : {}),
    retryHistory: parseJson(row.retry_history_json),
    progressBeforeFailure: parseJson(row.progress_before_failure_json),
    preservedReferences: parseJson(row.preserved_refs_json) as unknown as readonly FailureReference[],
    retryable: row.retryable === 1,
    automaticRecovery: parseJson(row.automatic_recovery_json),
    remediation: row.remediation,
    operatorActions: parseJson(row.operator_actions_json) as unknown as readonly FailureOperatorAction[],
    objectiveImpact: row.objective_impact,
    state: row.state,
    createdAt: row.created_at,
    ...(row.resolved_at ? { resolvedAt: row.resolved_at } : {}),
  };
}

export interface FailureRepositoryOptions {
  readonly clock?: () => Date;
  readonly idFactory?: (prefix: string) => string;
}

/** Canonical persistence and read boundary for structured failure diagnoses. */
export class FailureDiagnosisRepository {
  readonly clock: () => Date;
  readonly idFactory: (prefix: string) => string;
  readonly audit: AuditTrailWriter;

  constructor(readonly database: SqliteDatabase, options: FailureRepositoryOptions = {}) {
    this.clock = options.clock ?? (() => new Date());
    this.idFactory = options.idFactory ?? ((prefix) => `${prefix}_${randomUUID()}`);
    this.audit = new AuditTrailWriter(database, this.idFactory);
  }

  transaction<T>(operation: () => T): T {
    return inImmediateTransaction(this.database, operation);
  }

  nextId(prefix: string): string {
    return this.idFactory(prefix);
  }

  now(): string {
    return this.clock().toISOString();
  }

  insert(row: FailureRow): FailureDiagnosis {
    this.database.prepare(`
      INSERT INTO failure_diagnoses (
        id, mission_id, run_id, step_id, assignment_id, action_id,
        attack_attempt_id, subject_type, subject_id, human_reason, category,
        code, originating_component, last_success_event_id, failed_component_ref,
        target_summary, policy_or_dependency, raw_error_log_id, retry_history_json,
        progress_before_failure_json, preserved_refs_json, retryable,
        automatic_recovery_json, remediation, operator_actions_json,
        objective_impact, state, created_at, resolved_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      row.id, row.mission_id, row.run_id, row.step_id, row.assignment_id,
      row.action_id, row.attack_attempt_id, row.subject_type, row.subject_id,
      row.human_reason, row.category, row.code, row.originating_component,
      row.last_success_event_id, row.failed_component_ref, row.target_summary,
      row.policy_or_dependency, row.raw_error_log_id, row.retry_history_json,
      row.progress_before_failure_json, row.preserved_refs_json, row.retryable,
      row.automatic_recovery_json, row.remediation, row.operator_actions_json,
      row.objective_impact, row.state, row.created_at, row.resolved_at,
    );
    return mapFailure(row);
  }

  get(id: string): FailureDiagnosis {
    const row = this.row(id);
    return mapFailure(row);
  }

  row(id: string): FailureRow {
    const row = this.database.prepare("SELECT * FROM failure_diagnoses WHERE id = ?")
      .get(id) as FailureRow | undefined;
    if (!row) throw missing("failure_diagnosis");
    return row;
  }

  listForRun(runId: string, states: readonly FailureDiagnosisState[] = ["active", "terminal"], limit = 100): readonly FailureDiagnosis[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      throw new RangeError("Failure diagnosis limit must be 1 through 200");
    }
    if (states.length === 0) return [];
    const placeholders = states.map(() => "?").join(", ");
    const rows = this.database.prepare(`
      SELECT * FROM failure_diagnoses WHERE run_id = ? AND state IN (${placeholders})
      ORDER BY created_at DESC, id DESC LIMIT ?
    `).all(runId, ...states, limit) as FailureRow[];
    return rows.map(mapFailure);
  }

  resolve(id: string, resolvedAt: string): FailureDiagnosis {
    const result = this.database.prepare(`
      UPDATE failure_diagnoses SET state = 'resolved', resolved_at = ?
      WHERE id = ? AND state IN ('active', 'terminal')
    `).run(resolvedAt, id);
    if (result.changes !== 1) {
      const row = this.row(id);
      throw stateConflict(`Failure diagnosis in state ${row.state} cannot be resolved`);
    }
    return this.get(id);
  }

  assertMissionRun(missionId: string, runId?: string): void {
    if (!this.database.prepare("SELECT 1 FROM missions WHERE id = ?").get(missionId)) throw missing("mission");
    if (runId) {
      const row = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?")
        .get(runId) as { mission_id: string } | undefined;
      if (!row || row.mission_id !== missionId) throw scopeConflict("Failure run does not belong to the mission");
    }
  }

  assertSubject(input: {
    missionId: string;
    runId?: string;
    stepId?: string;
    assignmentId?: string;
    actionId?: string;
    attackAttemptId?: string;
    subjectType: FailureDiagnosis["subjectType"];
    subjectId: string;
  }): void {
    this.assertMissionRun(input.missionId, input.runId);
    const expected = {
      mission: input.missionId,
      run: input.runId,
      step: input.stepId,
      assignment: input.assignmentId,
      action: input.actionId,
      attack_attempt: input.attackAttemptId,
    }[input.subjectType];
    if (!expected || expected !== input.subjectId) {
      throw scopeConflict("Failure subject ID does not match its typed canonical reference");
    }
    if (input.stepId) {
      const row = this.database.prepare(`
        SELECT r.mission_id, ps.run_id FROM plan_steps ps JOIN runs r ON r.id = ps.run_id WHERE ps.id = ?
      `).get(input.stepId) as { mission_id: string; run_id: string } | undefined;
      if (!row || row.mission_id !== input.missionId || row.run_id !== input.runId) {
        throw scopeConflict("Failure step does not belong to the mission and run");
      }
    }
    if (input.assignmentId) {
      const row = this.database.prepare("SELECT run_id, step_id FROM assignments WHERE id = ?")
        .get(input.assignmentId) as { run_id: string; step_id: string | null } | undefined;
      if (!row || row.run_id !== input.runId || (input.stepId && row.step_id !== input.stepId)) {
        throw scopeConflict("Failure assignment does not belong to the run and step");
      }
    }
    if (input.actionId) {
      const row = this.database.prepare("SELECT mission_id, run_id, step_id FROM actions WHERE id = ?")
        .get(input.actionId) as { mission_id: string; run_id: string; step_id: string | null } | undefined;
      if (
        !row || row.mission_id !== input.missionId || row.run_id !== input.runId ||
        (input.stepId && row.step_id !== input.stepId)
      ) throw scopeConflict("Failure action does not belong to the mission, run, and step");
    }
    if (input.attackAttemptId) {
      const row = this.database.prepare("SELECT mission_id, run_id, step_id FROM attack_attempts WHERE id = ?")
        .get(input.attackAttemptId) as { mission_id: string; run_id: string; step_id: string | null } | undefined;
      if (
        !row || row.mission_id !== input.missionId || row.run_id !== input.runId ||
        (input.stepId && row.step_id !== input.stepId)
      ) throw scopeConflict("Failure attack attempt does not belong to the mission, run, and step");
    }
  }

  assertEventScope(eventId: string, missionId: string, runId?: string): void {
    const row = this.database.prepare("SELECT mission_id, run_id FROM events WHERE id = ?")
      .get(eventId) as { mission_id: string | null; run_id: string | null } | undefined;
    if (!row || row.mission_id !== missionId || row.run_id !== (runId ?? null)) {
      throw scopeConflict("Last-success event does not belong to the failure mission and run");
    }
  }

  assertErrorLogScope(logId: string, missionId: string, runId?: string): void {
    const row = this.database.prepare(`
      SELECT mission_id, run_id, severity FROM engagement_log_records WHERE id = ?
    `).get(logId) as { mission_id: string; run_id: string | null; severity: string } | undefined;
    if (!row || row.mission_id !== missionId || row.run_id !== (runId ?? null)) {
      throw scopeConflict("Raw error log does not belong to the failure mission and run");
    }
    if (row.severity !== "error" && row.severity !== "critical") {
      throw scopeConflict("Raw error reference must identify an error or critical engagement log");
    }
  }

  serialize(value: JsonValue): string {
    return canonicalJson(value);
  }
}

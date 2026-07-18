import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import type {
  PlanChangeAffectedRefs,
  PlanChangeBudgetImpact,
  PlanChangeDependencyImpact,
  PlanChangeDiffEntry,
  PlanChangeInflightImpact,
  PlanChangePolicyValidation,
  PlanChangeReadinessImpact,
  PlanChangeRequest,
  PlanChangeStatus,
  NormalizedPlanChange,
} from "./types";
import { PlanChangeError } from "./types";

interface PlanChangeRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly base_plan_id: string;
  readonly base_plan_version: number;
  readonly requested_by: string;
  readonly request_text: string | null;
  readonly normalized_change_json: string;
  readonly structured_diff_json: string;
  readonly affected_refs_json: string;
  readonly dependency_impact_json: string;
  readonly policy_validation_json: string;
  readonly readiness_impact_json: string;
  readonly budget_impact_json: string;
  readonly inflight_impact_json: string;
  readonly status: PlanChangeStatus;
  readonly result_plan_id: string | null;
  readonly created_at: string;
  readonly resolved_at: string | null;
  readonly version: number;
}

export interface PersistPlanChangeEvaluation {
  readonly normalizedChange: NormalizedPlanChange;
  readonly structuredDiff: readonly PlanChangeDiffEntry[];
  readonly affectedRefs: PlanChangeAffectedRefs;
  readonly dependencyImpact: PlanChangeDependencyImpact;
  readonly policyValidation: PlanChangePolicyValidation;
  readonly readinessImpact: PlanChangeReadinessImpact;
  readonly budgetImpact: PlanChangeBudgetImpact;
  readonly inflightImpact: PlanChangeInflightImpact;
  readonly status: Extract<PlanChangeStatus, "proposed" | "validated">;
}

function json<T>(value: string, label: string): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    throw new PlanChangeError("plan_change_record_corrupt", `${label} is not valid JSON`, "state_conflict", 500, "Run database integrity verification before retrying this operation.");
  }
}

function map(row: PlanChangeRow): PlanChangeRequest {
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    basePlanId: row.base_plan_id,
    basePlanVersion: row.base_plan_version,
    requestedBy: row.requested_by,
    requestText: row.request_text,
    normalizedChange: json(row.normalized_change_json, "normalized plan change"),
    structuredDiff: json(row.structured_diff_json, "structured plan diff"),
    affectedRefs: json(row.affected_refs_json, "affected plan references"),
    dependencyImpact: json(row.dependency_impact_json, "dependency impact"),
    policyValidation: json(row.policy_validation_json, "policy validation"),
    readinessImpact: json(row.readiness_impact_json, "readiness impact"),
    budgetImpact: json(row.budget_impact_json, "budget impact"),
    inflightImpact: json(row.inflight_impact_json, "in-flight impact"),
    status: row.status,
    resultPlanId: row.result_plan_id,
    createdAt: row.created_at,
    resolvedAt: row.resolved_at,
    version: row.version,
  };
}

/** Prepared-statement repository over the migration-010 plan-change tables. */
export class PlanChangeRepository {
  constructor(
    readonly database: SqliteDatabase,
    private readonly idFactory: (prefix: string) => string = (prefix) => `${prefix}_${randomUUID()}`,
  ) {}

  nextId(prefix: string): string {
    return this.idFactory(prefix);
  }

  get(requestId: string): PlanChangeRequest {
    const row = this.database.prepare(`
      SELECT pcr.*, p.version AS base_plan_version
      FROM plan_change_requests pcr
      JOIN plans p ON p.id = pcr.base_plan_id
      WHERE pcr.id = ?
    `).get(requestId) as PlanChangeRow | undefined;
    if (!row) throw new PlanChangeError("plan_change_not_found", `Plan change request not found: ${requestId}`, "not_found", 404, "Refresh the selected run and use a canonical plan-change link.");
    return map(row);
  }

  listForRun(runId: string): readonly PlanChangeRequest[] {
    return (this.database.prepare(`
      SELECT pcr.*, p.version AS base_plan_version
      FROM plan_change_requests pcr
      JOIN plans p ON p.id = pcr.base_plan_id
      WHERE pcr.run_id = ?
      ORDER BY pcr.created_at DESC, pcr.id DESC
    `).all(runId) as PlanChangeRow[]).map(map);
  }

  create(input: {
    readonly missionId: string;
    readonly runId: string;
    readonly basePlanId: string;
    readonly requestedBy: string;
    readonly requestText?: string;
    readonly evaluation: PersistPlanChangeEvaluation;
    readonly now: string;
  }): PlanChangeRequest {
    const id = this.nextId("plan_change");
    const evaluation = input.evaluation;
    this.database.prepare(`
      INSERT INTO plan_change_requests (
        id, mission_id, run_id, base_plan_id, requested_by, request_text,
        normalized_change_json, structured_diff_json, affected_refs_json,
        dependency_impact_json, policy_validation_json, readiness_impact_json,
        budget_impact_json, inflight_impact_json, status, created_at, version
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `).run(
      id, input.missionId, input.runId, input.basePlanId, input.requestedBy,
      input.requestText ?? null,
      JSON.stringify(evaluation.normalizedChange), JSON.stringify(evaluation.structuredDiff),
      JSON.stringify(evaluation.affectedRefs), JSON.stringify(evaluation.dependencyImpact),
      JSON.stringify(evaluation.policyValidation), JSON.stringify(evaluation.readinessImpact),
      JSON.stringify(evaluation.budgetImpact), JSON.stringify(evaluation.inflightImpact),
      evaluation.status, input.now,
    );
    return this.get(id);
  }

  edit(input: {
    readonly requestId: string;
    readonly expectedVersion: number;
    readonly requestText?: string;
    readonly evaluation: PersistPlanChangeEvaluation;
  }): PlanChangeRequest {
    const result = this.database.prepare(`
      UPDATE plan_change_requests SET
        request_text = ?, normalized_change_json = ?, structured_diff_json = ?,
        affected_refs_json = ?, dependency_impact_json = ?, policy_validation_json = ?,
        readiness_impact_json = ?, budget_impact_json = ?, inflight_impact_json = ?,
        status = ?, version = version + 1
      WHERE id = ? AND version = ? AND status IN ('proposed', 'validated')
    `).run(
      input.requestText ?? null,
      JSON.stringify(input.evaluation.normalizedChange), JSON.stringify(input.evaluation.structuredDiff),
      JSON.stringify(input.evaluation.affectedRefs), JSON.stringify(input.evaluation.dependencyImpact),
      JSON.stringify(input.evaluation.policyValidation), JSON.stringify(input.evaluation.readinessImpact),
      JSON.stringify(input.evaluation.budgetImpact), JSON.stringify(input.evaluation.inflightImpact),
      input.evaluation.status, input.requestId, input.expectedVersion,
    );
    if (result.changes !== 1) throw new PlanChangeError("plan_change_version_conflict", "Plan change request changed before this edit", "state_conflict", 409, "Reload the proposal and reapply the edit to its latest version.");
    return this.get(input.requestId);
  }

  resolve(input: {
    readonly requestId: string;
    readonly expectedVersion: number;
    readonly status: "rejected" | "applied";
    readonly resultPlanId?: string;
    readonly resolvedAt: string;
  }): PlanChangeRequest {
    const result = this.database.prepare(`
      UPDATE plan_change_requests SET status = ?, result_plan_id = ?, resolved_at = ?, version = version + 1
      WHERE id = ? AND version = ? AND status IN ('proposed', 'validated')
    `).run(input.status, input.resultPlanId ?? null, input.resolvedAt, input.requestId, input.expectedVersion);
    if (result.changes !== 1) throw new PlanChangeError("plan_change_version_conflict", "Plan change request changed before this decision", "state_conflict", 409, "Reload the proposal before applying or rejecting it.");
    return this.get(input.requestId);
  }
}

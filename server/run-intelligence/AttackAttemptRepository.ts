import type { SqliteDatabase } from "../db";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import { canonicalJson, parseJsonArray, parseJsonObject } from "./serialization";
import {
  RunIntelligenceError,
  type AttackAttempt,
  type AttackAttemptEvidenceLink,
  type AttackAttemptEvidenceRelationship,
  type AttackAttemptStatus,
  type CreateAttackAttemptInput,
  type ToolFailureSignal,
} from "./types";

interface AttackAttemptRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly plan_id: string | null;
  readonly step_id: string | null;
  readonly target_asset_id: string | null;
  readonly target_service_id: string | null;
  readonly objective: string;
  readonly technique_id: string | null;
  readonly technique_name: string;
  readonly action_class: string;
  readonly prerequisites_json: string;
  readonly normalized_parameters_json: string;
  readonly status: AttackAttemptStatus;
  readonly outcome_summary: string | null;
  readonly failure_category: string | null;
  readonly failure_diagnosis_id: string | null;
  readonly assigned_agent_id: string | null;
  readonly model_assignment_id: string | null;
  readonly started_at: string | null;
  readonly ended_at: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly version: number;
}

interface EvidenceLinkRow {
  readonly evidence_id: string;
  readonly relationship: AttackAttemptEvidenceRelationship;
  readonly verification_state: AttackAttemptEvidenceLink["verificationState"];
  readonly confidence: number;
  readonly content_hash: string;
  readonly created_at: string;
}

interface EvidenceReferenceRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly verification_state: AttackAttemptEvidenceLink["verificationState"];
  readonly confidence: number;
  readonly content_hash: string;
  readonly provenance_json: string;
}

interface ToolFailureRow {
  readonly tool_call_id: string;
  readonly tool_status: "failed" | "timed_out" | "denied";
  readonly error_category: string | null;
  readonly attempt_status: AttackAttemptStatus;
}

interface CountRow {
  readonly count: number;
}

function mapEvidence(row: EvidenceLinkRow): AttackAttemptEvidenceLink {
  return {
    evidenceId: row.evidence_id,
    relationship: row.relationship,
    verificationState: row.verification_state,
    confidence: row.confidence,
    contentHash: row.content_hash,
    createdAt: row.created_at,
  };
}

export class AttackAttemptRepository {
  constructor(private readonly database: SqliteDatabase) {}

  get(id: string): AttackAttempt {
    const row = this.database.prepare("SELECT * FROM attack_attempts WHERE id = ?").get(id) as AttackAttemptRow | undefined;
    if (!row) throw new RunIntelligenceError("attack_attempt_not_found", `Attack attempt not found: ${id}`);
    const evidence = this.database.prepare(`
      SELECT aae.evidence_id, aae.relationship, e.verification_state,
        e.confidence, e.content_hash, aae.created_at
      FROM attack_attempt_evidence aae
      JOIN evidence e ON e.id = aae.evidence_id
      WHERE aae.attack_attempt_id = ?
      ORDER BY aae.created_at, aae.evidence_id, aae.relationship
    `).all(id) as EvidenceLinkRow[];
    return {
      id: row.id,
      missionId: row.mission_id,
      runId: row.run_id,
      planId: row.plan_id,
      stepId: row.step_id,
      targetAssetId: row.target_asset_id,
      targetServiceId: row.target_service_id,
      objective: row.objective,
      techniqueId: row.technique_id,
      techniqueName: row.technique_name,
      actionClass: row.action_class,
      prerequisites: parseJsonArray(row.prerequisites_json, `Attack attempt ${id} prerequisites`),
      normalizedParameters: parseJsonObject(row.normalized_parameters_json, `Attack attempt ${id} parameters`),
      status: row.status,
      outcomeSummary: row.outcome_summary,
      failureCategory: row.failure_category,
      failureDiagnosisId: row.failure_diagnosis_id,
      assignedAgentId: row.assigned_agent_id,
      modelAssignmentId: row.model_assignment_id,
      startedAt: row.started_at,
      endedAt: row.ended_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      version: row.version,
      evidence: evidence.map(mapEvidence),
    };
  }

  listForRun(runId: string): AttackAttempt[] {
    const rows = this.database.prepare(`
      SELECT id FROM attack_attempts WHERE run_id = ? ORDER BY created_at, id
    `).all(runId) as Array<{ readonly id: string }>;
    return rows.map(({ id }) => this.get(id));
  }

  assertCreateReferences(input: CreateAttackAttemptInput): void {
    const run = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?").get(input.runId) as
      | { readonly mission_id: string }
      | undefined;
    if (!run) throw new RunIntelligenceError("run_not_found", `Run not found: ${input.runId}`);
    if (run.mission_id !== input.missionId) {
      throw new RunIntelligenceError("run_mission_mismatch", "Attack attempt run does not belong to the supplied mission");
    }
    if (input.planId) {
      const plan = this.database.prepare("SELECT run_id FROM plans WHERE id = ?").get(input.planId) as
        | { readonly run_id: string }
        | undefined;
      if (!plan || plan.run_id !== input.runId) {
        throw new RunIntelligenceError("plan_run_mismatch", "Attack attempt plan does not belong to the supplied run");
      }
    }
    if (input.stepId) {
      const step = this.database.prepare("SELECT run_id, plan_id FROM plan_steps WHERE id = ?").get(input.stepId) as
        | { readonly run_id: string; readonly plan_id: string }
        | undefined;
      if (!step || step.run_id !== input.runId || (input.planId !== undefined && step.plan_id !== input.planId)) {
        throw new RunIntelligenceError("step_run_mismatch", "Attack attempt step does not belong to the supplied run and plan");
      }
    }
    for (const [kind, nodeId] of [["asset", input.targetAssetId], ["service", input.targetServiceId]] as const) {
      if (!nodeId) continue;
      const node = this.database.prepare("SELECT mission_id, run_id, node_type FROM topology_nodes WHERE id = ?").get(nodeId) as
        | { readonly mission_id: string; readonly run_id: string | null; readonly node_type: string }
        | undefined;
      if (!node || node.mission_id !== input.missionId || (node.run_id !== null && node.run_id !== input.runId)) {
        throw new RunIntelligenceError(`target_${kind}_mismatch`, `Attack attempt target ${kind} is outside the run mission`);
      }
    }
    if (input.assignedAgentId) {
      const agent = this.database.prepare("SELECT id FROM agents WHERE id = ?").get(input.assignedAgentId);
      if (!agent) throw new RunIntelligenceError("agent_not_found", `Assigned agent not found: ${input.assignedAgentId}`);
    }
    if (input.modelAssignmentId) {
      const assignment = this.database.prepare(`
        SELECT agent_id, mission_id, run_id FROM agent_model_assignments WHERE id = ?
      `).get(input.modelAssignmentId) as
        | { readonly agent_id: string; readonly mission_id: string | null; readonly run_id: string | null }
        | undefined;
      if (
        !assignment
        || (assignment.mission_id !== null && assignment.mission_id !== input.missionId)
        || (assignment.run_id !== null && assignment.run_id !== input.runId)
        || (input.assignedAgentId !== undefined && assignment.agent_id !== input.assignedAgentId)
      ) {
        throw new RunIntelligenceError("model_assignment_mismatch", "Model assignment does not resolve to this attempt context");
      }
    }
  }

  insert(input: CreateAttackAttemptInput & { readonly id: string; readonly now: string }): AttackAttempt {
    this.database.prepare(`
      INSERT INTO attack_attempts (
        id, mission_id, run_id, plan_id, step_id, target_asset_id,
        target_service_id, objective, technique_id, technique_name,
        action_class, prerequisites_json, normalized_parameters_json,
        status, assigned_agent_id, model_assignment_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?, ?, ?)
    `).run(
      input.id,
      input.missionId,
      input.runId,
      input.planId ?? null,
      input.stepId ?? null,
      input.targetAssetId ?? null,
      input.targetServiceId ?? null,
      input.objective,
      input.techniqueId ?? null,
      input.techniqueName,
      input.actionClass,
      canonicalJson(input.prerequisites ?? []),
      canonicalJson(input.normalizedParameters ?? {}),
      input.assignedAgentId ?? null,
      input.modelAssignmentId ?? null,
      input.now,
      input.now,
    );
    return this.get(input.id);
  }

  evidenceReference(attempt: AttackAttempt, evidenceId: string): EvidenceReferenceRow {
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, verification_state, confidence,
        content_hash, provenance_json
      FROM evidence WHERE id = ?
    `).get(evidenceId) as EvidenceReferenceRow | undefined;
    if (!row) throw new RunIntelligenceError("evidence_not_found", `Evidence not found: ${evidenceId}`);
    if (row.mission_id !== attempt.missionId || (row.run_id !== null && row.run_id !== attempt.runId)) {
      throw new RunIntelligenceError("evidence_scope_mismatch", "Attack-attempt evidence is outside the attempt mission or run");
    }
    if (row.verification_state === "rejected") {
      throw new RunIntelligenceError("evidence_rejected", "Rejected evidence cannot support an attack attempt");
    }
    const provenance = parseJsonObject(row.provenance_json, `Evidence ${evidenceId} provenance`);
    if (Object.keys(provenance).length === 0) {
      throw new RunIntelligenceError("evidence_provenance_missing", "Attack-attempt evidence requires canonical provenance");
    }
    return row;
  }

  linkEvidence(
    attemptId: string,
    evidenceId: string,
    relationship: AttackAttemptEvidenceRelationship,
    now: string,
  ): void {
    this.database.prepare(`
      INSERT INTO attack_attempt_evidence (
        attack_attempt_id, evidence_id, relationship, created_at
      ) VALUES (?, ?, ?, ?)
      ON CONFLICT (attack_attempt_id, evidence_id, relationship) DO NOTHING
    `).run(attemptId, evidenceId, relationship, now);
  }

  updateStatus(input: {
    readonly attemptId: string;
    readonly expectedVersion: number;
    readonly fromStatuses: readonly AttackAttemptStatus[];
    readonly status: AttackAttemptStatus;
    readonly outcomeSummary?: string;
    readonly failureCategory?: string;
    readonly failureDiagnosisId?: string;
    readonly startedAt?: string;
    readonly endedAt?: string;
    readonly now: string;
  }): AttackAttempt {
    const placeholders = input.fromStatuses.map(() => "?").join(", ");
    const result = this.database.prepare(`
      UPDATE attack_attempts SET
        status = ?,
        outcome_summary = COALESCE(?, outcome_summary),
        failure_category = ?,
        failure_diagnosis_id = COALESCE(?, failure_diagnosis_id),
        started_at = COALESCE(started_at, ?),
        ended_at = COALESCE(?, ended_at),
        updated_at = ?,
        version = version + 1
      WHERE id = ? AND version = ? AND status IN (${placeholders})
    `).run(
      input.status,
      input.outcomeSummary ?? null,
      input.failureCategory ?? null,
      input.failureDiagnosisId ?? null,
      input.startedAt ?? null,
      input.endedAt ?? null,
      input.now,
      input.attemptId,
      input.expectedVersion,
      ...input.fromStatuses,
    );
    if (result.changes !== 1) {
      throw new RunIntelligenceError(
        "attack_attempt_transition_conflict",
        "Attack attempt state or version changed; reload it before applying an outcome",
      );
    }
    return this.get(input.attemptId);
  }

  observeToolFailure(attemptId: string, toolCallId: string): ToolFailureSignal {
    const row = this.database.prepare(`
      SELECT tc.id AS tool_call_id, tc.status AS tool_status,
        tc.error_category, aa.status AS attempt_status
      FROM attack_attempts aa
      JOIN engagement_log_records elr
        ON elr.attack_attempt_id = aa.id AND elr.tool_call_id = ?
      JOIN tool_calls tc ON tc.id = elr.tool_call_id
      JOIN actions a ON a.id = tc.action_id AND a.run_id = aa.run_id
      WHERE aa.id = ? AND tc.status IN ('failed', 'timed_out', 'denied')
      ORDER BY elr.occurred_at DESC, elr.id DESC
      LIMIT 1
    `).get(toolCallId, attemptId) as ToolFailureRow | undefined;
    if (!row) {
      throw new RunIntelligenceError(
        "tool_failure_not_attributable",
        "The failed tool call is not canonically linked to this attack attempt",
      );
    }
    return {
      attemptId,
      toolCallId: row.tool_call_id,
      toolStatus: row.tool_status,
      errorCategory: row.error_category,
      attackAttemptStatus: row.attempt_status,
      attackAttemptOutcomeChanged: false,
      reason: "tool_process_failure_is_not_attack_outcome",
    };
  }

  countVerifiedOutcomeEvidence(attemptId: string): number {
    const row = this.database.prepare(`
      SELECT COUNT(*) AS count
      FROM attack_attempt_evidence aae
      JOIN evidence e ON e.id = aae.evidence_id
      WHERE aae.attack_attempt_id = ?
        AND aae.relationship IN ('supports', 'outcome')
        AND ${verifiedEvidenceSql("e")}
    `).get(attemptId) as CountRow;
    return Number(row.count);
  }
}

import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import {
  AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
  AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION,
  AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION,
  AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
  AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION,
  AUTONOMOUS_USER_ACCESS_PROOF_SUCCESS_CRITERION,
  autonomousMaterialObjectiveSuccessCriteria,
} from "../domain/autonomous-outcome-registry";
import { digestCanonicalJson } from "../mcp";
import { MemoryRepository, SecondBrainService } from "../memory";
import type {
  MissionCompletionEvaluation,
  MissionOutcomeEvaluatorInput,
  MissionOutcomeEvaluatorPort,
} from "../command-runtime";
import { CommandRuntimeError } from "../command-runtime/types";
import type { AutonomousCriterionOutcome } from "./types";

export const LOCAL_VERIFIED_EVIDENCE_EVALUATOR_ID =
  "ti-scale.local-verified-evidence-outcome-evaluator";
export const LOCAL_AUTONOMOUS_OUTCOME_EVALUATOR_CONTRACT_SCHEMA_VERSION =
  "ti-scale.autonomous-outcome-evaluator.v1" as const;
export const AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION =
  "ti-scale.success-criterion-reference.v1" as const;
export const AUTONOMOUS_CRITERION_OUTCOME_PROVENANCE_SCHEMA_VERSION =
  "ti-scale.autonomous-criterion-outcome-provenance.v1" as const;

interface EvidenceRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly step_id: string | null;
  readonly content_hash: string;
  readonly source: string;
  readonly target: string | null;
  readonly evidence_type: string;
  readonly action_id: string | null;
  readonly action_status: string | null;
  readonly action_type: string | null;
  readonly action_class: string | null;
  readonly action_mission_id: string | null;
  readonly action_run_id: string | null;
  readonly action_step_id: string | null;
  readonly action_target: string | null;
  readonly provenance_json: string;
}

interface CriterionReference {
  readonly schemaVersion: typeof AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION;
  readonly criterionId: string;
  readonly outcome: "achieved" | "not_applicable";
}

interface OutcomeEventRow {
  readonly action_id: string;
  readonly action_status: string;
  readonly action_fingerprint: string;
  readonly action_mission_id: string;
  readonly action_run_id: string;
  readonly payload_json: string;
}

interface VerifiedOutcomeProvenance {
  readonly criterionId: string;
  readonly sourceEvidenceIds: readonly string[];
}

function normalizedCriterion(value: string): string {
  return value.trim().normalize("NFKC").replace(/\s+/gu, " ").toLocaleLowerCase("en-US");
}

/** Stable ID that evidence producers can place in provenance without copying criterion prose. */
export function autonomousSuccessCriterionId(criterion: string): string {
  const normalized = normalizedCriterion(criterion);
  if (!normalized) throw new TypeError("Success criterion is required");
  return `criterion_${createHash("sha256").update(normalized, "utf8").digest("hex")}`;
}

interface TerminalCriterionAuthority {
  readonly actionType: string;
  readonly actionClass: string;
  readonly evidenceType: string;
}

const TERMINAL_CRITERION_AUTHORITIES: ReadonlyMap<
string,
TerminalCriterionAuthority
> = new Map([
  [
    autonomousSuccessCriterionId(
      AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
    ),
    {
      actionType: "ti-scale:autonomous-script-exploit-validation",
      actionClass: "exploit_validation",
      evidenceType: "exploit_validation_result",
    },
  ],
  [
    autonomousSuccessCriterionId(
      AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION,
    ),
    {
      actionType: "autonomous_linux_session_identity_v1",
      actionClass: "command_session_execution",
      evidenceType: "session_command_outcome",
    },
  ],
  [
    autonomousSuccessCriterionId(
      AUTONOMOUS_USER_ACCESS_PROOF_SUCCESS_CRITERION,
    ),
    {
      actionType: "autonomous_linux_user_flag_proof_v1",
      actionClass: "data_access_impact_validation",
      evidenceType: "privilege_access_proof",
    },
  ],
  [
    autonomousSuccessCriterionId(AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION),
    {
      actionType: "autonomous_linux_privilege_escalation_v1",
      actionClass: "privilege_escalation",
      evidenceType: "privilege_access_proof",
    },
  ],
  [
    autonomousSuccessCriterionId(
      AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION,
    ),
    {
      actionType: "autonomous_linux_root_flag_proof_v1",
      actionClass: "data_access_impact_validation",
      evidenceType: "privilege_access_proof",
    },
  ],
  [
    autonomousSuccessCriterionId(
      AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
    ),
    {
      actionType: "autonomous_linux_session_cleanup_v1",
      actionClass: "cleanup_restoration",
      evidenceType: "session_command_outcome",
    },
  ],
]);

function exists(
  database: SqliteDatabase,
  sql: string,
  ...parameters: readonly unknown[]
): boolean {
  return (database.prepare(sql).get(...parameters) as {
    readonly present: number;
  } | undefined)?.present === 1;
}

/**
 * Terminal full-path criteria carry stronger authority than ordinary
 * evidence-backed criteria. A favorable reference is eligible only when the
 * evidence was produced by the exact reviewed action and has its matching
 * canonical proof row. This prevents generic or finding-linked evidence from
 * asserting session, privilege, flag, exploit-impact, or cleanup completion.
 */
function canonicalTerminalEvidence(
  database: SqliteDatabase,
  criterionId: string,
  evidence: EvidenceRow,
): boolean {
  const authority = TERMINAL_CRITERION_AUTHORITIES.get(criterionId);
  if (!authority) return true;
  if (
    evidence.action_id === null
    || evidence.action_status !== "succeeded"
    || evidence.action_type !== authority.actionType
    || evidence.action_class !== authority.actionClass
    || evidence.evidence_type !== authority.evidenceType
    || evidence.action_mission_id !== evidence.mission_id
    || evidence.action_run_id !== evidence.run_id
    || evidence.action_step_id !== evidence.step_id
    || evidence.action_target !== evidence.target
  ) {
    return false;
  }

  if (criterionId === autonomousSuccessCriterionId(
    AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
  )) {
    return evidence.source === "local:independent-http-outcome-observer"
      && exists(database, `
        SELECT 1 AS present
        FROM attack_attempt_evidence link
        JOIN attack_attempts attempt ON attempt.id = link.attack_attempt_id
        JOIN topology_nodes target ON target.id = attempt.target_asset_id
        WHERE link.evidence_id = ? AND link.relationship = 'outcome'
          AND attempt.mission_id = ? AND attempt.run_id = ?
          AND attempt.step_id = ? AND attempt.status = 'succeeded'
          AND attempt.action_class = 'exploit_validation'
          AND target.mission_id = attempt.mission_id
          AND target.run_id = attempt.run_id
          AND target.scope_status = 'allowed'
          AND target.normalized_identity = ?
          AND json_extract(?, '$.schemaVersion')
            = 'ti-scale.exploit-outcome-observation.v1'
          AND json_extract(?, '$.matched') = 1
      `, evidence.id, evidence.mission_id, evidence.run_id, evidence.step_id,
      evidence.target, evidence.provenance_json, evidence.provenance_json);
  }

  if (criterionId === autonomousSuccessCriterionId(
    AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION,
  )) {
    return [
      "candidate_bound_identity_observer",
      "independent_loopback_identity_observer",
    ].includes(evidence.source)
      && exists(database, `
        SELECT 1 AS present
        FROM session_identity_observations observation
        JOIN session_artifacts session
          ON session.id = observation.session_artifact_id
        JOIN candidate_linux_post_exploit_specs spec
          ON spec.id = session.post_exploit_spec_id
        WHERE observation.evidence_id = ? AND observation.action_id = ?
          AND observation.observer_kind = 'user_identity'
          AND observation.principal = spec.expected_principal
          AND observation.uid = spec.expected_uid
          AND observation.uid > 0
          AND session.opened_by_action_id = observation.action_id
          AND session.mission_id = ? AND session.run_id = ?
          AND session.step_id = ? AND session.exact_target = ?
      `, evidence.id, evidence.action_id, evidence.mission_id, evidence.run_id,
      evidence.step_id, evidence.target);
  }

  if (criterionId === autonomousSuccessCriterionId(
    AUTONOMOUS_USER_ACCESS_PROOF_SUCCESS_CRITERION,
  )) {
    return evidence.source === "candidate_bound_hash_only_observer"
      && exists(database, `
        SELECT 1 AS present
        FROM session_flag_proofs proof
        JOIN session_artifacts session
          ON session.id = proof.session_artifact_id
        JOIN candidate_linux_post_exploit_specs spec
          ON spec.id = session.post_exploit_spec_id
        WHERE proof.evidence_id = ? AND proof.action_id = ?
          AND proof.proof_kind = 'user_flag'
          AND proof.declared_path = spec.declared_user_flag_path
          AND session.mission_id = ? AND session.run_id = ?
          AND session.exact_target = ?
      `, evidence.id, evidence.action_id, evidence.mission_id, evidence.run_id,
      evidence.target);
  }

  if (criterionId === autonomousSuccessCriterionId(
    AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION,
  )) {
    return [
      "candidate_bound_root_identity_observer",
      "independent_loopback_root_identity",
    ].includes(evidence.source)
      && exists(database, `
        SELECT 1 AS present
        FROM session_identity_observations observation
        JOIN session_artifacts session
          ON session.id = observation.session_artifact_id
        WHERE observation.evidence_id = ? AND observation.action_id = ?
          AND observation.observer_kind = 'root_identity'
          AND observation.principal = 'root'
          AND observation.uid = 0 AND observation.gid = 0
          AND session.mission_id = ? AND session.run_id = ?
          AND session.exact_target = ?
          AND session.access_level = 'root'
          AND session.status IN ('privileged', 'closing', 'closed')
      `, evidence.id, evidence.action_id, evidence.mission_id, evidence.run_id,
      evidence.target);
  }

  if (criterionId === autonomousSuccessCriterionId(
    AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION,
  )) {
    return [
      "candidate_bound_root_flag_hash_observer",
      "loopback_root_flag_hash_observer",
    ].includes(evidence.source)
      && exists(database, `
        SELECT 1 AS present
        FROM session_flag_proofs proof
        JOIN session_artifacts session
          ON session.id = proof.session_artifact_id
        WHERE proof.evidence_id = ? AND proof.action_id = ?
          AND proof.proof_kind = 'root_flag'
          AND proof.declared_path = '/root/root.txt'
          AND session.mission_id = ? AND session.run_id = ?
          AND session.exact_target = ?
          AND session.access_level = 'root'
          AND session.status IN ('privileged', 'closing', 'closed')
      `, evidence.id, evidence.action_id, evidence.mission_id, evidence.run_id,
      evidence.target);
  }

  return evidence.source === "candidate_bound_session_cleanup"
    && exists(database, `
      SELECT 1 AS present
      FROM session_artifacts session
      WHERE session.id = json_extract(?, '$.sessionArtifactId')
        AND json_extract(?, '$.schemaVersion')
          = 'ti-scale.autonomous-session-cleanup-evidence.v1'
        AND json_extract(?, '$.postExploitSpecId')
          = session.post_exploit_spec_id
        AND json_extract(?, '$.exactTarget') = session.exact_target
        AND json_extract(?, '$.activeLeaseRemaining') = 0
        AND json_extract(?, '$.cleanupReceiptSha256')
          GLOB '[0-9a-f][0-9a-f]*'
        AND json_extract(?, '$.cleanupReceiptSha256')
          NOT GLOB '*[^0-9a-f]*'
        AND length(json_extract(?, '$.cleanupReceiptSha256')) = 64
        AND session.mission_id = ? AND session.run_id = ?
        AND session.exact_target = ?
        AND session.status = 'closed' AND session.closed_at IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM session_artifact_leases lease
          WHERE lease.session_artifact_id = session.id
            AND lease.released_at IS NULL
        )
    `, evidence.provenance_json, evidence.provenance_json,
    evidence.provenance_json, evidence.provenance_json,
    evidence.provenance_json, evidence.provenance_json,
    evidence.provenance_json, evidence.provenance_json,
    evidence.mission_id, evidence.run_id,
    evidence.target);
}

function plainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function criterionReferences(value: string): readonly CriterionReference[] {
  try {
    const provenance = JSON.parse(value) as unknown;
    if (!plainRecord(provenance) || !Array.isArray(provenance.successCriterionReferences)) return [];
    return provenance.successCriterionReferences.flatMap((candidate) => {
      if (!plainRecord(candidate)) return [];
      const expected = ["criterionId", "outcome", "schemaVersion"];
      const keys = Object.keys(candidate).sort();
      if (
        keys.length !== expected.length
        || keys.some((key, index) => key !== expected[index])
        || candidate.schemaVersion !== AUTONOMOUS_SUCCESS_CRITERION_REFERENCE_SCHEMA_VERSION
        || typeof candidate.criterionId !== "string"
        || !/^criterion_[a-f0-9]{64}$/u.test(candidate.criterionId)
        || (candidate.outcome !== "achieved" && candidate.outcome !== "not_applicable")
      ) return [];
      return [candidate as unknown as CriterionReference];
    });
  } catch {
    return [];
  }
}

function verifiedNotApplicableOutcome(
  row: OutcomeEventRow,
  missionId: string,
  runId: string,
  completed: ReadonlySet<string>,
  eligibleEvidenceById: ReadonlyMap<string, EvidenceRow>,
): VerifiedOutcomeProvenance | null {
  try {
    const payload = JSON.parse(row.payload_json) as unknown;
    if (!plainRecord(payload)
      || payload.schemaVersion !== AUTONOMOUS_CRITERION_OUTCOME_PROVENANCE_SCHEMA_VERSION
      || payload.method !== "verified_source_evidence_not_applicable"
      || payload.missionId !== missionId || payload.runId !== runId
      || payload.actionId !== row.action_id || row.action_status !== "succeeded"
      || row.action_mission_id !== missionId || row.action_run_id !== runId
      || !completed.has(row.action_id)
      || payload.actionFingerprint !== row.action_fingerprint
      || typeof payload.criterionId !== "string"
      || !/^criterion_[a-f0-9]{64}$/u.test(payload.criterionId)
      || payload.outcome !== "not_applicable"
      || !Array.isArray(payload.sourceEvidenceIds)
      || !Array.isArray(payload.sourceEvidenceContentHashes)
      || payload.sourceEvidenceIds.length < 1
      || payload.sourceEvidenceIds.length !== payload.sourceEvidenceContentHashes.length
      || typeof payload.contextPackId !== "string"
      || typeof payload.resultSha256 !== "string"
      || typeof payload.outcomeReceiptSha256 !== "string") return null;
    const sourceEvidenceIds = payload.sourceEvidenceIds as unknown[];
    const sourceHashes = payload.sourceEvidenceContentHashes as unknown[];
    if (sourceEvidenceIds.some((id) => typeof id !== "string")
      || sourceHashes.some((hash) => typeof hash !== "string")
      || sourceEvidenceIds.some((id, index) =>
        eligibleEvidenceById.get(id as string)?.id !== id
        || eligibleEvidenceById.get(id as string)?.content_hash !== sourceHashes[index])) return null;
    const { outcomeReceiptSha256, ...body } = payload;
    if (digestCanonicalJson(body, { maxBytes: 2 * 1024 * 1024, maxDepth: 24 }).sha256
      !== outcomeReceiptSha256) return null;
    return {
      criterionId: payload.criterionId,
      sourceEvidenceIds: sourceEvidenceIds as string[],
    };
  } catch {
    return null;
  }
}

function evaluationError(
  code: string,
  humanMessage: string,
  remediation: string,
): CommandRuntimeError {
  return new CommandRuntimeError(409, code, humanMessage, {
    humanMessage: `Safe-stopped: ${humanMessage}`,
    retryable: false,
    category: "evidence_insufficient",
    remediation,
  });
}

/**
 * Local deterministic outcome evaluator. It never reads Engagement Logs,
 * provider prose, stdout, or unverified evidence. A criterion is supported
 * only by an explicit stable criterion reference in canonical verified
 * evidence provenance. Verified findings may establish the support path, but
 * cannot replace the linked verified evidence.
 */
export class LocalVerifiedEvidenceOutcomeEvaluator implements MissionOutcomeEvaluatorPort {
  readonly autonomousContract = Object.freeze({
    schemaVersion: LOCAL_AUTONOMOUS_OUTCOME_EVALUATOR_CONTRACT_SCHEMA_VERSION,
    evaluatorId: LOCAL_VERIFIED_EVIDENCE_EVALUATOR_ID,
    evidenceAuthority: "verified_evidence_only" as const,
    successAuthority: "criteria_evaluation_only" as const,
    providerContact: false as const,
  });
  readonly #brain: SecondBrainService;

  constructor(private readonly database: SqliteDatabase) {
    this.#brain = new SecondBrainService(new MemoryRepository(database));
  }

  async evaluate(
    input: MissionOutcomeEvaluatorInput,
    signal: AbortSignal,
  ): Promise<MissionCompletionEvaluation> {
    if (signal.aborted) throw new DOMException("Autonomous evaluation was cancelled", "AbortError");
    if (input.mission.journey !== "autonomous" || input.run.journey !== "autonomous") {
      throw evaluationError(
        "local_autonomous_evaluator_journey_mismatch",
        "the Autonomous evidence evaluator was invoked for another journey.",
        "Use the journey-specific evaluator; journey conversion cannot happen implicitly.",
      );
    }
    const plan = this.database.prepare(`
      SELECT p.id FROM plans p
      JOIN runs r ON r.id = p.run_id AND r.current_plan_id = p.id
      WHERE p.id = ? AND p.run_id = ? AND p.status IN ('active', 'completed')
    `).get(input.planId, input.run.id) as { id: string } | undefined;
    if (!plan) {
      throw evaluationError(
        "local_autonomous_evaluation_plan_not_current",
        "the exact plan changed before local outcome evaluation.",
        "Evaluate only the current immutable plan version from its durable checkpoint.",
      );
    }
    const pack = new MemoryRepository(this.database).requireContextPack(
      input.brainContext.contextPackId,
    );
    if (
      pack.missionId !== input.mission.id || pack.runId !== input.run.id
      || pack.journey !== "autonomous"
    ) {
      throw evaluationError(
        "local_autonomous_evaluation_context_mismatch",
        "the evaluation Context Pack belongs to another mission, run, or journey.",
        "Refresh the exact scope-safe evaluation Context Pack before evaluating.",
      );
    }

    const completed = new Set(input.completedActionIds);
    const evidence = this.database.prepare(`
      SELECT e.id, e.mission_id, e.run_id, e.step_id, e.content_hash,
        e.source, e.target, e.evidence_type, e.action_id,
        a.status AS action_status, a.action_type, a.action_class,
        a.mission_id AS action_mission_id, a.run_id AS action_run_id,
        a.step_id AS action_step_id, a.scoped_target AS action_target,
        e.provenance_json
      FROM evidence e
      LEFT JOIN actions a ON a.id = e.action_id
      WHERE e.mission_id = ? AND e.run_id = ? AND ${verifiedEvidenceSql("e")}
      ORDER BY e.acquired_at, e.id
    `).all(input.mission.id, input.run.id) as EvidenceRow[];
    const verifiedFindingEvidence = new Set((this.database.prepare(`
      SELECT DISTINCT fe.evidence_id
      FROM findings f
      JOIN finding_evidence fe ON fe.finding_id = f.id AND fe.relationship = 'supports'
      JOIN evidence e ON e.id = fe.evidence_id
      WHERE f.mission_id = ? AND f.run_id = ? AND f.review_status = 'verified'
        AND e.mission_id = f.mission_id AND e.run_id = f.run_id
        AND ${verifiedEvidenceSql("e")}
    `).all(input.mission.id, input.run.id) as Array<{ evidence_id: string }>)
      .map(({ evidence_id }) => evidence_id));

    const eligibleEvidence = evidence.filter((record) =>
      (record.action_id !== null
        && record.action_status === "succeeded"
        && completed.has(record.action_id))
      || verifiedFindingEvidence.has(record.id));
    const eligibleEvidenceById = new Map(eligibleEvidence.map((record) => [record.id, record]));
    const notApplicableOutcomes = (this.database.prepare(`
      SELECT a.id AS action_id, a.status AS action_status,
        a.fingerprint AS action_fingerprint,
        a.mission_id AS action_mission_id, a.run_id AS action_run_id,
        ev.payload_json
      FROM events ev JOIN actions a ON a.id = json_extract(ev.payload_json, '$.actionId')
      WHERE ev.mission_id = ? AND ev.run_id = ?
        AND ev.journey = 'autonomous'
        AND ev.event_type = 'autonomous_criterion_not_applicable'
      ORDER BY ev.sequence, ev.id
    `).all(input.mission.id, input.run.id) as OutcomeEventRow[]).flatMap((row) => {
      const verified = verifiedNotApplicableOutcome(
        row,
        input.mission.id,
        input.run.id,
        completed,
        eligibleEvidenceById,
      );
      return verified ? [verified] : [];
    });
    const materialObjectiveCriteria = autonomousMaterialObjectiveSuccessCriteria(
      input.mission.objective,
    );
    const criteriaToEvaluate = [
      ...input.mission.successCriteria,
      ...materialObjectiveCriteria,
    ].filter((criterion, index, values) => {
      const normalized = normalizedCriterion(criterion);
      return values.findIndex((candidate) =>
        normalizedCriterion(candidate) === normalized) === index;
    });
    const objectiveDerivedCriterionIds = new Set(
      materialObjectiveCriteria.map(autonomousSuccessCriterionId),
    );
    const criteria = criteriaToEvaluate.map((criterion) => {
      const criterionId = autonomousSuccessCriterionId(criterion);
      const support = eligibleEvidence.flatMap((record) =>
        criterionReferences(record.provenance_json)
          .filter((reference) => reference.criterionId === criterionId)
          .filter(() => canonicalTerminalEvidence(
            this.database,
            criterionId,
            record,
          ))
          .map((reference) => ({ evidenceId: record.id, outcome: reference.outcome })));
      const achieved = [...new Set(support
        .filter(({ outcome }) => outcome === "achieved")
        .map(({ evidenceId }) => evidenceId))];
      const notApplicable = [...new Set(support
        .filter(({ outcome }) => outcome === "not_applicable")
        .map(({ evidenceId }) => evidenceId)
        .concat(notApplicableOutcomes
          .filter((outcome) => outcome.criterionId === criterionId)
          .filter((outcome) => outcome.sourceEvidenceIds.every((evidenceId) => {
            const record = eligibleEvidenceById.get(evidenceId);
            return record !== undefined && canonicalTerminalEvidence(
              this.database,
              criterionId,
              record,
            );
          }))
          .flatMap((outcome) => outcome.sourceEvidenceIds)))];
      let outcome: AutonomousCriterionOutcome = "not_achieved";
      let explanation: string;
      let evidenceIds: readonly string[] = [];
      if (achieved.length > 0 && notApplicable.length > 0) {
        explanation = "Conflicting verified records mark this criterion both achieved and not applicable. The evaluator refused to choose a favorable result until the conflict is reviewed.";
        evidenceIds = [...new Set([...achieved, ...notApplicable])];
      } else if (achieved.length > 0) {
        outcome = "achieved";
        explanation = "Canonical verified evidence explicitly links this stable success-criterion ID to an achieved outcome. Any action-linked evidence came from an exact succeeded action in this run.";
        evidenceIds = achieved;
      } else if (notApplicable.length > 0) {
        outcome = "not_applicable";
        explanation = "Canonical verified evidence explicitly establishes that this criterion is not applicable to the observed authorized environment. It is excluded from success, not treated as achieved.";
        evidenceIds = notApplicable;
      } else {
        const supportExplanation = eligibleEvidence.length === 0
          ? "No eligible verified evidence exists for this run. Raw logs, provider prose, unverified observations, and successful process exits cannot satisfy a mission criterion."
          : "Eligible verified evidence exists, but none explicitly links this stable success-criterion ID to an achieved or not-applicable outcome.";
        explanation = objectiveDerivedCriterionIds.has(criterionId)
          ? `The authorized objective requires this material outcome even if an older or manually submitted contract omitted it. ${supportExplanation}`
          : supportExplanation;
      }
      return {
        criterion,
        outcome,
        satisfied: outcome === "achieved",
        explanation,
        evidenceIds,
      };
    });
    const achievedCount = criteria.filter(({ outcome }) => outcome === "achieved").length;
    const notApplicableCount = criteria.filter(({ outcome }) => outcome === "not_applicable").length;
    const notAchievedCount = criteria.filter(({ outcome }) => outcome === "not_achieved").length;
    const success = criteria.length > 0 && achievedCount > 0 && notAchievedCount === 0;

    for (const item of pack.items) {
      this.#brain.recordContextUse(pack.id, {
        nodeId: item.nodeId,
        used: false,
        relevanceReason: item.relevanceReason,
        ignoredReason: "The local evaluator used only canonical success criteria, verified evidence provenance, exact succeeded actions, and verified finding links; memory did not change the outcome.",
      });
    }

    return {
      success,
      summary: criteria.length === 0
        ? "Failed safely: the mission has no measurable success criteria, so Ti-Scale cannot declare completion."
        : success
          ? `Completed autonomously with verified support: ${achievedCount} criteria achieved and ${notApplicableCount} explicitly not applicable.`
          : `Failed safely: ${notAchievedCount} criteria remain unsupported; ${achievedCount} are achieved and ${notApplicableCount} are explicitly not applicable.`,
      criteria,
      // Evaluation is fully local and deterministic. Preserve an exact zero
      // usage receipt so finite provider budgets remain enforceable without
      // inventing a provider turn.
      providerUsage: {
        providerTurns: 0,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        billedCostUsd: 0,
        exactTokenUsage: true,
        exactCostUsage: true,
      },
    };
  }
}

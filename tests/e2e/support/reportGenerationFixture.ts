import { createHash } from "node:crypto";
import { createDatabaseConnection, inImmediateTransaction } from "../../../server/db";
import { E2E_DATABASE_PATH } from "./environment";
import { normalizeFixtureNamespace } from "./fixtureNamespace";

const FIXTURE_TIME = "2026-07-20T06:00:00.000Z";
const OPERATOR_ID = "e2e-local-operator";

export interface ReportGenerationFixture {
  readonly namespace: string;
  readonly missionId: string;
  readonly missionName: string;
  readonly runId: string;
  readonly reportVersion: number;
  readonly verifiedEvidenceId: string;
  readonly verifiedFindingId: string;
  readonly secretMarker: string;
  readonly markdownArtifactId: string;
  readonly jsonArtifactId: string;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function reportArtifactId(
  missionId: string,
  runId: string,
  reportVersion: number,
  format: "markdown" | "json",
): string {
  return `report_${sha256(`${missionId}\n${runId}\n${reportVersion}\n${format}`).slice(0, 40)}`;
}

/**
 * Creates only canonical V2 records in the per-invocation Playwright database.
 * The browser still invokes the real report service and downloads its real
 * content-addressed artifacts; this fixture never materializes report files.
 */
export function createReportGenerationFixture(instanceId: string): ReportGenerationFixture {
  if (!E2E_DATABASE_PATH) throw new Error("Report-generation E2E requires the isolated V2 database path");
  const namespace = normalizeFixtureNamespace(instanceId);
  const suffix = sha256(namespace).slice(0, 12);
  const missionId = `mission-report-generation-${suffix}`;
  const runId = `run-report-generation-${suffix}`;
  const planId = `plan-report-generation-${suffix}`;
  const stepId = `step-report-generation-${suffix}`;
  const verifiedEvidenceId = `evidence-report-generation-${suffix}`;
  const verifiedFindingId = `finding-report-generation-${suffix}`;
  const evaluationId = `evaluation-report-generation-${suffix}`;
  const missionName = `Canonical report delivery ${suffix}`;
  const secretMarker = `fixture-secret-${suffix}`;
  const reportVersion = 1;
  const database = createDatabaseConnection({
    filename: E2E_DATABASE_PATH,
    fileMustExist: true,
    busyTimeoutMs: 120_000,
  });

  try {
    inImmediateTransaction(database, () => {
      database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          engagement_id, scope_json, success_criteria_json,
          retention_policy_json, memory_policy_json, created_by, version,
          created_at, updated_at
        ) VALUES (?, ?, ?, 'guided', 'completed', 'verified', ?, ?, ?, '{}',
          '{}', ?, 1, ?, ?)
      `).run(
        missionId,
        missionName,
        `Assess the exact approved local fixture. password=${secretMarker}`,
        `engagement-report-generation-${suffix}`,
        JSON.stringify({ allowedTargets: [`report-${suffix}.example.test`] }),
        JSON.stringify(["Retain one independently verified service result"]),
        OPERATOR_ID,
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, status_reason,
          current_plan_id, current_step_id, next_action_summary,
          budget_json, budget_usage_json, started_at, ended_at,
          created_at, updated_at, version
        ) VALUES (?, ?, 'guided', 'completed', 1,
          'The bounded fixture completed with one verified result.', ?, ?,
          'Generate the canonical redacted report', '{}', '{}', ?, ?, ?, ?, 1)
      `).run(
        runId,
        missionId,
        planId,
        stepId,
        FIXTURE_TIME,
        FIXTURE_TIME,
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
      database.prepare("INSERT INTO run_event_sequences (run_id, last_sequence) VALUES (?, 0)")
        .run(runId);
      database.prepare(`
        INSERT INTO plans (
          id, run_id, version, status, strategy_summary, rationale_summary,
          plan_hash, created_by, created_at, activated_at
        ) VALUES (?, ?, 1, 'completed', 'Inspect one approved service',
          'Use a bounded read-only observation and independent verification.',
          ?, ?, ?, ?)
      `).run(planId, runId, sha256(planId), OPERATOR_ID, FIXTURE_TIME, FIXTURE_TIME);
      database.prepare(`
        INSERT INTO plan_steps (
          id, plan_id, run_id, ordinal, phase, title, objective, status,
          success_criteria_json, dependencies_json, action_class, risk_class,
          created_at, updated_at
        ) VALUES (?, ?, ?, 0, 'reconnaissance', 'Inspect the approved service',
          'Retain one attributable service observation.', 'completed', ?, '[]',
          'port_service_enumeration', 'network', ?, ?)
      `).run(
        stepId,
        planId,
        runId,
        JSON.stringify(["One independently verified observation is retained"]),
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
      database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, step_id, source, acquired_at, target,
          evidence_type, content_hash, provenance_json, confidence,
          sensitivity, verification_state, summary, extracted_text,
          created_by, created_at
        ) VALUES (?, ?, ?, ?, 'reviewed:local-fixture', ?, ?,
          'service_version_fingerprint', ?, '{}', 0.98, 'private', 'verified',
          'The approved fixture exposed one independently verified service.',
          'raw body excluded from canonical reports', ?, ?)
      `).run(
        verifiedEvidenceId,
        missionId,
        runId,
        stepId,
        FIXTURE_TIME,
        `report-${suffix}.example.test`,
        sha256(verifiedEvidenceId),
        OPERATOR_ID,
        FIXTURE_TIME,
      );
      database.prepare(`
        INSERT INTO findings (
          id, mission_id, run_id, title, severity, confidence, affected_scope,
          description, impact, remediation, review_status, version,
          created_at, updated_at
        ) VALUES (?, ?, ?, 'Verified fixture service', 'informational', 0.98, ?,
          'One approved service was independently verified.',
          'The result supplies an attributable baseline.',
          'Retain the bounded verification record.', 'verified', 1, ?, ?)
      `).run(
        verifiedFindingId,
        missionId,
        runId,
        `report-${suffix}.example.test`,
        FIXTURE_TIME,
        FIXTURE_TIME,
      );
      database.prepare(`
        INSERT INTO finding_evidence (finding_id, evidence_id, relationship, added_at)
        VALUES (?, ?, 'supports', ?)
      `).run(verifiedFindingId, verifiedEvidenceId, FIXTURE_TIME);
      database.prepare(`
        INSERT INTO run_evaluations (
          id, mission_id, run_id, journey, scores_json, metrics_json,
          retrospective, evidence_coverage, created_by, created_at
        ) VALUES (?, ?, ?, 'guided', '{"objectiveCompletion":1}',
          '{"verifiedEvidence":1}',
          'The exact objective completed with independently verified evidence.',
          1, 'local-evaluator', ?)
      `).run(evaluationId, missionId, runId, FIXTURE_TIME);
    });
  } finally {
    database.close();
  }

  return {
    namespace,
    missionId,
    missionName,
    runId,
    reportVersion,
    verifiedEvidenceId,
    verifiedFindingId,
    secretMarker,
    markdownArtifactId: reportArtifactId(missionId, runId, reportVersion, "markdown"),
    jsonArtifactId: reportArtifactId(missionId, runId, reportVersion, "json"),
  };
}

import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { RunComparisonService } from "../RunComparisonService";

const T0 = "2026-07-15T08:00:00.000Z";
const T1 = "2026-07-15T09:00:00.000Z";
const T2 = "2026-07-15T10:00:00.000Z";
const T3 = "2026-07-15T11:00:00.000Z";

function setup(): SqliteDatabase {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  return database;
}

function mission(database: SqliteDatabase, id: string, engagementId: string | null, journey: "autonomous" | "guided" = "autonomous"): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      created_by, created_at, updated_at
    ) VALUES (?, ?, 'Authorized comparison fixture', ?, 'completed', 'verified', ?, 'operator', ?, ?)
  `).run(id, id, journey, engagementId, T0, T0);
}

function evaluation(database: SqliteDatabase, input: {
  missionId: string;
  runId: string;
  evaluationId: string;
  endedAt: string;
  journey?: "autonomous" | "guided";
  status?: "completed" | "failed" | "cancelled";
  durationMs?: number;
  repeatedActionRate?: number;
  evidenceCoverage?: number;
  objectiveCompletion?: number;
  timeToFirstMeaningfulEvidenceMs?: number;
  noProgressActionCount?: number;
  recoverySuccessRate?: number;
  operatorInterventionCount?: number;
  memoryContextPrecision?: number;
  preferenceCorrectionRate?: number;
  toolCallSuccessRate?: number;
}): void {
  const journey = input.journey ?? "autonomous";
  const status = input.status ?? "completed";
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, budget_json, budget_usage_json,
      started_at, ended_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, '{}', '{}', ?, ?, ?, ?)
  `).run(input.runId, input.missionId, journey, status, T0, input.endedAt, T0, input.endedAt);
  database.prepare(`
    INSERT INTO run_evaluations (
      id, mission_id, run_id, journey, scores_json, metrics_json,
      retrospective, evidence_coverage, created_by, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'Canonical fixture', ?, 'evaluator', ?)
  `).run(
    input.evaluationId,
    input.missionId,
    input.runId,
    journey,
    JSON.stringify({
      objectiveCompletion: input.objectiveCompletion ?? (status === "completed" ? 1 : 0),
      evidenceQuality: input.evidenceCoverage ?? 1,
      policyCompliance: 1,
      journeyAdherence: 1,
    }),
    JSON.stringify({
      terminalStatus: status,
      durationMs: input.durationMs ?? 60_000,
      timeToFirstMeaningfulEvidenceMs: input.timeToFirstMeaningfulEvidenceMs ?? 30_000,
      noProgressActionCount: input.noProgressActionCount ?? 0,
      repeatedActionRate: input.repeatedActionRate ?? 0,
      retryRate: 0,
      recoverySuccessRate: input.recoverySuccessRate ?? 1,
      operatorInterventionCount: input.operatorInterventionCount ?? 0,
      memoryContextPrecision: input.memoryContextPrecision ?? 1,
      preferenceCorrectionRate: input.preferenceCorrectionRate ?? 0,
      toolCallSuccessRate: input.toolCallSuccessRate ?? 1,
      providerTokens: 100,
      estimatedCost: 0,
    }),
    input.evidenceCoverage ?? 1,
    input.endedAt,
  );
}

function compare(database: SqliteDatabase, input: {
  evaluationId: string; runId: string; missionId: string; engagementId: string | null;
  endedAt: string; status?: "completed" | "failed" | "cancelled";
  durationMs?: number; repeatedActionRate?: number; evidenceCoverage?: number; objectiveCompletion?: number;
  timeToFirstMeaningfulEvidenceMs?: number; noProgressActionCount?: number;
  recoverySuccessRate?: number; operatorInterventionCount?: number;
  memoryContextPrecision?: number; preferenceCorrectionRate?: number; toolCallSuccessRate?: number;
}) {
  return new RunComparisonService(database).record({
    evaluationId: input.evaluationId,
    runId: input.runId,
    missionId: input.missionId,
    engagementId: input.engagementId,
    journey: "autonomous",
    terminalStatus: input.status ?? "completed",
    endedAt: input.endedAt,
    evaluationCreatedAt: input.endedAt,
    scores: {
      objectiveCompletion: input.objectiveCompletion ?? 1,
      evidenceQuality: input.evidenceCoverage ?? 1,
      policyCompliance: 1,
      journeyAdherence: 1,
    },
    metrics: {
      durationMs: input.durationMs ?? 60_000,
      timeToFirstMeaningfulEvidenceMs: input.timeToFirstMeaningfulEvidenceMs ?? 30_000,
      noProgressActionCount: input.noProgressActionCount ?? 0,
      repeatedActionRate: input.repeatedActionRate ?? 0,
      retryRate: 0,
      recoverySuccessRate: input.recoverySuccessRate ?? 1,
      operatorInterventionCount: input.operatorInterventionCount ?? 0,
      memoryContextPrecision: input.memoryContextPrecision ?? 1,
      preferenceCorrectionRate: input.preferenceCorrectionRate ?? 0,
      toolCallSuccessRate: input.toolCallSuccessRate ?? 1,
      providerTokens: 100,
      estimatedCost: 0,
    },
    evidenceCoverage: input.evidenceCoverage ?? 1,
  });
}

describe("RunComparisonService", () => {
  test("persists an explicit insufficient-data comparison when no in-scope prior evaluation exists", () => {
    const database = setup();
    try {
      mission(database, "mission-current", "engagement-a");
      evaluation(database, { missionId: "mission-current", runId: "run-current", evaluationId: "evaluation-current", endedAt: T2 });
      const result = compare(database, {
        evaluationId: "evaluation-current", runId: "run-current", missionId: "mission-current",
        engagementId: "engagement-a", endedAt: T2,
      });
      expect(result).toMatchObject({
        status: "insufficient_data",
        reason: "no_prior_same_scope_evaluation",
        priorRunId: null,
        metrics: [],
      });
      expect(result.summary).toContain("Insufficient comparable data");
      expect(database.prepare("SELECT comparison_status, reason FROM run_evaluation_comparisons").get())
        .toEqual({ comparison_status: "insufficient_data", reason: "no_prior_same_scope_evaluation" });
    } finally { database.close(); }
  });

  test("prefers same-mission continuity and records only measured directional deltas", () => {
    const database = setup();
    try {
      mission(database, "mission-current", "engagement-a");
      mission(database, "mission-other", "engagement-a");
      evaluation(database, {
        missionId: "mission-current", runId: "run-same-mission", evaluationId: "evaluation-same-mission",
        endedAt: T1, durationMs: 120_000, repeatedActionRate: 0.5, evidenceCoverage: 0.5,
        timeToFirstMeaningfulEvidenceMs: 90_000, noProgressActionCount: 3,
        recoverySuccessRate: 0, operatorInterventionCount: 2,
        memoryContextPrecision: 0.5, preferenceCorrectionRate: 0.5, toolCallSuccessRate: 0.5,
      });
      evaluation(database, {
        missionId: "mission-other", runId: "run-newer-engagement", evaluationId: "evaluation-newer-engagement",
        endedAt: T2, durationMs: 30_000, repeatedActionRate: 0, evidenceCoverage: 1,
      });
      evaluation(database, {
        missionId: "mission-current", runId: "run-current", evaluationId: "evaluation-current",
        endedAt: T3, durationMs: 60_000, repeatedActionRate: 0.25, evidenceCoverage: 0.75,
      });

      const result = compare(database, {
        evaluationId: "evaluation-current", runId: "run-current", missionId: "mission-current",
        engagementId: "engagement-a", endedAt: T3, durationMs: 60_000,
        repeatedActionRate: 0.25, evidenceCoverage: 0.75,
        timeToFirstMeaningfulEvidenceMs: 20_000, noProgressActionCount: 1,
        recoverySuccessRate: 1, operatorInterventionCount: 0,
        memoryContextPrecision: 1, preferenceCorrectionRate: 0, toolCallSuccessRate: 1,
      });
      expect(result).toMatchObject({
        status: "available",
        basis: "same_mission_and_journey",
        priorRunId: "run-same-mission",
        terminalStatusMatch: true,
      });
      expect(result.metrics.find((metric) => metric.key === "durationMs")).toMatchObject({
        prior: 120_000, current: 60_000, delta: -60_000, movement: "favorable",
      });
      expect(result.metrics.find((metric) => metric.key === "evidenceCoverage")).toMatchObject({
        prior: 0.5, current: 0.75, delta: 0.25, movement: "favorable",
      });
      expect(result.metrics.find((metric) => metric.key === "timeToFirstMeaningfulEvidenceMs")).toMatchObject({
        prior: 90_000, current: 20_000, delta: -70_000, movement: "favorable",
      });
      expect(result.metrics.find((metric) => metric.key === "noProgressActionCount")).toMatchObject({
        prior: 3, current: 1, delta: -2, movement: "favorable",
      });
      expect(result.metrics.find((metric) => metric.key === "memoryContextPrecision")).toMatchObject({
        prior: 0.5, current: 1, delta: 0.5, movement: "favorable",
      });
      expect(result.metrics.find((metric) => metric.key === "preferenceCorrectionRate")).toMatchObject({
        prior: 0.5, current: 0, delta: -0.5, movement: "favorable",
      });
      expect(result.summary).toContain("does not establish that the system improved");
      expect(result.summary).not.toContain("mission-current");
      expect(result.summary).not.toContain("engagement-a");
      expect(() => database.prepare(`
        UPDATE run_evaluation_comparisons SET summary = 'tampered'
        WHERE evaluation_id = 'evaluation-current'
      `).run()).toThrow("run evaluation comparisons are immutable");
      expect(() => database.prepare(`
        DELETE FROM run_evaluation_comparisons WHERE evaluation_id = 'evaluation-current'
      `).run()).toThrow("run evaluation comparisons are immutable");
      expect(new RunComparisonService(database).record({
        evaluationId: "evaluation-current", runId: "run-current", missionId: "mission-current",
        engagementId: "engagement-a", journey: "autonomous", terminalStatus: "completed",
        endedAt: T3, evaluationCreatedAt: T3, scores: {}, metrics: {}, evidenceCoverage: 0,
      })).toEqual(result);
    } finally { database.close(); }
  });

  test("uses same-engagement journey fallback but never crosses an engagement", () => {
    const database = setup();
    try {
      mission(database, "mission-a-prior", "engagement-a");
      mission(database, "mission-b-prior", "engagement-b");
      mission(database, "mission-current", "engagement-a");
      evaluation(database, { missionId: "mission-a-prior", runId: "run-a", evaluationId: "evaluation-a", endedAt: T1 });
      evaluation(database, { missionId: "mission-b-prior", runId: "run-b", evaluationId: "evaluation-b", endedAt: T2 });
      evaluation(database, { missionId: "mission-current", runId: "run-current", evaluationId: "evaluation-current", endedAt: T3 });
      const result = compare(database, {
        evaluationId: "evaluation-current", runId: "run-current", missionId: "mission-current",
        engagementId: "engagement-a", endedAt: T3,
      });
      expect(result).toMatchObject({
        status: "available",
        basis: "same_engagement_and_journey",
        priorRunId: "run-a",
      });
      expect(result.priorRunId).not.toBe("run-b");
    } finally { database.close(); }
  });
});

import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { EventRepository } from "../../events";
import {
  findRejectableSecrets,
  findReusableContentIdentifiers,
} from "../AttackLesson";
import { AttackChainLearningService, canonicalLessonMemoryNodeId } from "../AttackChainLessonRepository";
import { RunLearningService } from "../RunLearningService";

const NOW = "2026-07-15T12:00:00.000Z";
const STARTED = "2026-07-15T11:55:00.000Z";
const HASH = "a".repeat(64);

function setup(): { database: SqliteDatabase; learning: RunLearningService } {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  return {
    database,
    learning: new RunLearningService(database, {
      clock: () => new Date(NOW),
      events: new EventRepository(database),
    }),
  };
}

function seedMission(database: SqliteDatabase, id: string, journey: "autonomous" | "guided", engagementId: string | null): void {
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status, engagement_id,
      success_criteria_json, memory_policy_json, created_by, created_at, updated_at
    ) VALUES (?, 'HTB CredSmith 10.10.10.10',
      'Collect token=do-not-retain from secretbox.htb', ?, 'active', 'verified', ?,
      '["Retain verified evidence"]', '{}', 'operator', ?, ?)
  `).run(id, journey, engagementId, STARTED, STARTED);
}

function seedTerminalRun(
  database: SqliteDatabase,
  input: {
    missionId: string;
    runId: string;
    journey: "autonomous" | "guided";
    status: "completed" | "failed" | "cancelled";
    evidenceId?: string;
    duplicateActions?: boolean;
  },
): void {
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, budget_json, budget_usage_json,
      retry_count, replan_count, status_reason, started_at, ended_at,
      created_at, updated_at, version
    ) VALUES (?, ?, ?, ?, '{"wallClockMs":600000,"providerTokens":1000}',
      '{"providerTokens":100}', 0, 0, 'Terminal fixture', ?, ?, ?, ?, 1)
  `).run(input.runId, input.missionId, input.journey, input.status, STARTED, NOW, STARTED, NOW);
  if (input.status !== "cancelled") {
    const insert = database.prepare(`
      INSERT INTO actions (
        id, mission_id, run_id, action_type, action_class, fingerprint,
        normalized_arguments_json, status, intent_summary, result_summary,
        retry_count, started_at, ended_at, created_at, updated_at
      ) VALUES (?, ?, ?, 'scan', 'reconnaissance', ?, '{}', ?,
        'Bounded specialist action', 'Canonical result', 0, ?, ?, ?, ?)
    `);
    insert.run(
      `${input.runId}-action-1`, input.missionId, input.runId, "same-fingerprint",
      input.status === "completed" ? "succeeded" : "failed", STARTED, NOW, STARTED, NOW,
    );
    if (input.duplicateActions) {
      insert.run(
        `${input.runId}-action-2`, input.missionId, input.runId, "same-fingerprint",
        "succeeded", STARTED, NOW, STARTED, NOW,
      );
    }
  }
  if (input.evidenceId) {
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, created_by, created_at
      ) VALUES (?, ?, ?, 'specialist', ?, '10.10.10.10', 'service_observation',
        ?, '{}', 1, 'restricted', 'verified',
        'Raw evidence may mention secretbox.htb and must not enter the lesson',
        'agent-recon', ?)
    `).run(input.evidenceId, input.missionId, input.runId, NOW, HASH, NOW);
  }
}

function seedCanonicalToolCallWithSensitiveValues(database: SqliteDatabase, runId: string): void {
  const actionId = `${runId}-action-1`;
  database.prepare(`
    UPDATE actions SET normalized_arguments_json = ? WHERE id = ?
  `).run(JSON.stringify({
    input: {
      mcpServer: "authorized-recon",
      toolName: "nmap",
      arguments: {
        target: "10.10.10.10",
        ports: [22, 80, 443],
        flags: ["-sV", "-sC"],
        outputPath: "/tmp/CredSmith-nmap.txt",
        username: "administrator",
        password: "candidate-password-do-not-retain",
        command: "nmap -sV -sC -p 22,80,443 10.10.10.10 -oN /tmp/CredSmith-nmap.txt",
        sourceNote: "HTB CredSmith walkthrough reference",
      },
    },
    orchestration: { target: "credsmith.htb", kind: "tool", idempotent: true },
  }), actionId);
  database.prepare(`
    INSERT INTO tool_calls (
      id, action_id, provider, tool_name, normalized_arguments_json,
      status, output_summary, started_at, ended_at, created_at
    ) VALUES (?, ?, 'mcp', 'nmap', ?, 'succeeded',
      'Canonical tool result', ?, ?, ?)
  `).run(`${runId}-tool-call-1`, actionId, JSON.stringify({
    host: "10.10.10.10",
    ports: [22, 80, 443],
    versionDetection: true,
    defaultScripts: true,
    wordlistPath: "/root/engagements/CredSmith/users.txt",
    token: "bearer-do-not-retain",
  }), STARTED, NOW, STARTED);
}

describe("RunLearningService", () => {
  test("does not treat successful MCP output as evidence or research signal", () => {
    const { database, learning } = setup();
    try {
      seedMission(database, "mission-raw", "autonomous", "engagement-raw");
      seedTerminalRun(database, {
        missionId: "mission-raw",
        runId: "run-raw",
        journey: "autonomous",
        status: "completed",
      });
      const insert = database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, created_by, created_at
        ) VALUES (?, 'mission-raw', 'run-raw', 'mcp:scanner.run', ?, '10.10.10.10', ?, ?,
          '{"processSucceeded":true,"verificationBasis":"none"}', 0.95, 'private',
          'verified', ?, 'runtime', ?)
      `);
      insert.run("raw-command", NOW, "command_output", "b".repeat(64), "Raw command output", NOW);
      insert.run("legacy-tool-result", NOW, "tool_result", "c".repeat(64), "Legacy successful tool output", NOW);

      const evaluation = learning.recordTerminalEvaluation({
        runId: "run-raw",
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        outcome: {
          success: true,
          summary: "A process returned successfully",
          criteria: [{
            criterion: "Retain verified evidence",
            satisfied: true,
            explanation: "The tool returned output",
            evidenceIds: ["raw-command", "legacy-tool-result"],
          }],
        },
      });

      expect(evaluation.evidenceCoverage).toBe(0);
      expect(evaluation.scores.evidenceQuality).toBe(0);
      expect(evaluation.metrics).toMatchObject({
        evidenceCount: 0,
        verifiedEvidenceCount: 0,
        timeToFirstMeaningfulEvidenceMs: null,
      });
      expect(evaluation.proposedLessonIds).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("stores one real evaluation and one evidence-gated, privacy-safe, unverified candidate", () => {
    const { database, learning } = setup();
    try {
      seedMission(database, "mission-a", "autonomous", "engagement-a");
      seedTerminalRun(database, {
        missionId: "mission-a",
        runId: "run-a",
        journey: "autonomous",
        status: "completed",
        evidenceId: "evidence-a",
        duplicateActions: true,
      });
      const outcome = {
        success: true,
        summary: "Validated by canonical evidence",
        criteria: [{
          criterion: "Retain verified evidence",
          satisfied: true,
          explanation: "Evidence exists",
          evidenceIds: ["evidence-a"],
        }],
      } as const;

      const first = learning.recordTerminalEvaluation({
        runId: "run-a",
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        outcome,
      });
      const replay = learning.recordTerminalEvaluation({
        runId: "run-a",
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        outcome,
      });

      expect(replay.id).toBe(first.id);
      expect(first.evidenceCoverage).toBe(1);
      expect(first.scores).toMatchObject({
        objectiveCompletion: 1,
        evidenceQuality: 1,
        journeyAdherence: 1,
        repeatedActionAvoidance: 0.5,
      });
      expect(first.metrics).toMatchObject({
        timeToFirstMeaningfulEvidenceMs: 300_000,
        actionCount: 2,
        actionsWithMeaningfulProgress: 0,
        noProgressActionCount: 2,
        uniqueActionFingerprints: 1,
        verifiedEvidenceCount: 1,
        autonomousUserWaitCount: 0,
        operatorInterventionCount: 0,
        memoryContextPrecision: null,
        preferenceCorrectionRate: null,
      });
      expect(first.comparison).toMatchObject({
        status: "insufficient_data",
        reason: "no_prior_same_scope_evaluation",
        metrics: [],
      });
      expect(database.prepare("SELECT COUNT(*) AS count FROM run_evaluations").get())
        .toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM events WHERE event_type = 'run.evaluation_recorded'").get())
        .toEqual({ count: 1 });

      const lesson = database.prepare("SELECT * FROM lessons").get() as Record<string, unknown>;
      expect(lesson.status).toBe("proposed");
      expect(lesson.authoring_agent_id).toBe("run-evaluator");
      expect(lesson.reviewed_by).toBeNull();
      const statement = String(lesson.statement);
      expect(statement).not.toContain("CredSmith");
      expect(statement).not.toContain("10.10.10.10");
      expect(statement).not.toContain("secretbox");
      expect(statement).not.toContain("token");
      expect(findRejectableSecrets(statement)).toEqual([]);
      expect(findReusableContentIdentifiers(statement)).toEqual([]);
      expect(database.prepare("SELECT COUNT(*) AS count FROM lesson_evidence").get())
        .toEqual({ count: 2 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM lesson_attack_chain_details").get())
        .toEqual({ count: 1 });
      const chainItems = database.prepare(`
        SELECT item_type, content FROM lesson_attack_chain_items ORDER BY item_type, ordinal
      `).all() as Array<{ item_type: string; content: string }>;
      expect(chainItems.some((item) => item.item_type === "ordered_step" && item.content.includes("<TARGET_HOST>"))).toBe(true);
      expect(chainItems.some((item) => item.item_type === "validation_checkpoint")).toBe(true);
      expect(chainItems.some((item) => item.item_type === "failure_recovery")).toBe(true);
      expect(chainItems.some((item) => item.item_type === "public_reference")).toBe(true);
      expect(chainItems.map((item) => item.content).join("\n")).not.toContain("CredSmith");
      expect(chainItems.map((item) => item.content).join("\n")).not.toContain("10.10.10.10");
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes WHERE node_type IN ('evaluation', 'lesson')").get())
        .toEqual({ count: 2 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_edges WHERE edge_type = 'produced'").get())
        .toEqual({ count: 1 });
      expect(() => database.prepare(`
        UPDATE lessons SET status = 'verified', reviewed_by = authoring_agent_id,
          reviewed_at = ?, updated_at = ? WHERE id = ?
      `).run(NOW, NOW, lesson.id)).toThrow();
    } finally {
      database.close();
    }
  });

  test("deduplicates a reusable candidate inside one engagement while preserving each run as provenance", () => {
    const { database, learning } = setup();
    try {
      seedMission(database, "mission-b", "autonomous", "engagement-shared");
      seedTerminalRun(database, {
        missionId: "mission-b", runId: "run-b1", journey: "autonomous",
        status: "completed", evidenceId: "evidence-b1",
      });
      seedTerminalRun(database, {
        missionId: "mission-b", runId: "run-b2", journey: "autonomous",
        status: "completed", evidenceId: "evidence-b2",
      });
      for (const [runId, evidenceId] of [["run-b1", "evidence-b1"], ["run-b2", "evidence-b2"]] as const) {
        learning.recordTerminalEvaluation({
          runId,
          terminalStatus: "completed",
          createdBy: "outcome-evaluator",
          outcome: {
            success: true,
            summary: "Validated",
            criteria: [{ criterion: "Evidence", satisfied: true, explanation: "Verified", evidenceIds: [evidenceId] }],
          },
        });
      }
      expect(database.prepare("SELECT COUNT(*) AS count FROM run_evaluations").get()).toEqual({ count: 2 });
      const secondEvaluation = learning.recordTerminalEvaluation({
        runId: "run-b2",
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        outcome: {
          success: true,
          summary: "Validated",
          criteria: [{ criterion: "Evidence", satisfied: true, explanation: "Verified", evidenceIds: ["evidence-b2"] }],
        },
      });
      expect(secondEvaluation.comparison).toMatchObject({
        status: "available",
        basis: "same_mission_and_journey",
        priorRunId: "run-b1",
      });
      expect(secondEvaluation.comparison.summary).toContain("does not establish that the system improved");
      expect(database.prepare("SELECT COUNT(*) AS count FROM lessons").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(DISTINCT run_id) AS count FROM lesson_evidence WHERE run_id IS NOT NULL").get())
        .toEqual({ count: 2 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_edges WHERE edge_type = 'produced'").get())
        .toEqual({ count: 2 });
    } finally {
      database.close();
    }
  });

  test("records failed and cancelled evaluations, proposes only an evidence-linked failed-attempt candidate", () => {
    const { database, learning } = setup();
    try {
      seedMission(database, "mission-c", "guided", null);
      seedTerminalRun(database, {
        missionId: "mission-c", runId: "run-failed", journey: "guided", status: "failed",
      });
      seedTerminalRun(database, {
        missionId: "mission-c", runId: "run-cancelled", journey: "guided", status: "cancelled",
      });
      const failed = learning.recordTerminalEvaluation({
        runId: "run-failed", terminalStatus: "failed", createdBy: "run-supervisor",
      });
      const cancelled = learning.recordTerminalEvaluation({
        runId: "run-cancelled", terminalStatus: "cancelled", createdBy: "run-supervisor",
      });

      expect(failed.scores.objectiveCompletion).toBe(0);
      expect(cancelled.proposedLessonIds).toEqual([]);
      expect(database.prepare("SELECT COUNT(*) AS count FROM run_evaluations").get()).toEqual({ count: 2 });
      expect(database.prepare("SELECT lesson_type, status FROM lessons").get())
        .toEqual({ lesson_type: "failed_attempt", status: "proposed" });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM lesson_evidence
        WHERE run_id = 'run-failed' AND evidence_id IS NULL AND relationship = 'supports'
      `).get()).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });

  test("round-trips only parameterized canonical action semantics after independent verification", () => {
    const { database, learning } = setup();
    try {
      seedMission(database, "mission-d", "autonomous", "engagement-d");
      seedTerminalRun(database, {
        missionId: "mission-d",
        runId: "run-d",
        journey: "autonomous",
        status: "completed",
        evidenceId: "evidence-d",
      });
      seedCanonicalToolCallWithSensitiveValues(database, "run-d");

      const evaluation = learning.recordTerminalEvaluation({
        runId: "run-d",
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        outcome: {
          success: true,
          summary: "Validated by immutable evidence",
          criteria: [{
            criterion: "Retain verified evidence",
            satisfied: true,
            explanation: "Verified evidence exists",
            evidenceIds: ["evidence-d"],
          }],
        },
      });
      const lessonId = evaluation.proposedLessonIds[0]!;
      const attackChains = new AttackChainLearningService(database, { clock: () => new Date(NOW) });

      expect(database.prepare("SELECT status FROM lessons WHERE id = ?").get(lessonId))
        .toEqual({ status: "proposed" });
      expect(attackChains.verifiedPlanningContext({ engagementId: "engagement-d" })).toBe("");

      const items = database.prepare(`
        SELECT item_type, content FROM lesson_attack_chain_items
        ORDER BY item_type, ordinal
      `).all() as Array<{ item_type: string; content: string }>;
      const retained = items.map((item) => item.content).join("\n");
      const step = items.find((item) => item.item_type === "ordered_step")?.content ?? "";
      expect(step).toContain("Use nmap through the assigned specialist");
      expect(step).toContain("<TARGET_HOST>");
      expect(step).toContain("<PORTS>");
      expect(step).toContain("<OUTPUT_PATH>");
      expect(step).toContain("<WORDLIST_PATH>");
      expect(step).toContain("<USER_REF>");
      expect(step).toContain("<CREDENTIAL_REF>");
      expect(step).toContain("service and version detection (-sV)");
      expect(step).toContain("default safe script set (-sC)");
      expect(items.some((item) => item.item_type === "public_reference" && item.content === "https://nmap.org/book/man.html"))
        .toBe(true);
      expect(items.some((item) => item.item_type === "anti_reuse_warning" && item.content.includes("quarantined")))
        .toBe(true);
      for (const forbidden of [
        "10.10.10.10", "credsmith", "htb", "administrator", "candidate-password",
        "bearer-do-not-retain", "/tmp", "/root", "nmap -sV -sC -p",
      ]) {
        expect(retained.toLocaleLowerCase("en-US")).not.toContain(forbidden.toLocaleLowerCase("en-US"));
      }
      expect(findRejectableSecrets(retained)).toEqual([]);

      database.prepare(`
        UPDATE lessons SET status = 'under_review', reviewed_by = NULL,
          reviewed_at = NULL, updated_at = ? WHERE id = ?
      `).run(NOW, lessonId);
      expect(attackChains.verifiedPlanningContext({ engagementId: "engagement-d" })).toBe("");
      expect(() => database.prepare(`
        UPDATE lessons SET status = 'verified', reviewed_by = authoring_agent_id,
          reviewed_at = ?, updated_at = ? WHERE id = ?
      `).run(NOW, NOW, lessonId)).toThrow();
      database.prepare(`
        UPDATE lessons SET status = 'verified', reviewed_by = 'independent-security-reviewer',
          reviewed_at = ?, updated_at = ? WHERE id = ?
      `).run(NOW, NOW, lessonId);
      attackChains.synchronizeMemoryLifecycle(lessonId, "verified", "independent-security-reviewer");

      const context = attackChains.verifiedPlanningContext({ engagementId: "engagement-d" });
      expect(context).toContain("VERIFIED EXECUTABLE ATTACK CHAINS (independently approved)");
      expect(context).toContain("service and version detection (-sV)");
      expect(context).toContain("default safe script set (-sC)");
      expect(context).toContain("https://nmap.org/book/man.html");
      expect(context).toContain("<TARGET_HOST>");
      expect(context).not.toMatch(/10\.10\.10\.10|credsmith|administrator|candidate-password|bearer-do-not-retain|\/tmp|\/root/iu);
      const memoryNode = database.prepare(`
        SELECT lifecycle_status, retention_policy_json
        FROM memory_nodes WHERE id = ?
      `).get(canonicalLessonMemoryNodeId(lessonId)) as {
        lifecycle_status: string;
        retention_policy_json: string;
      };
      expect(memoryNode.lifecycle_status).toBe("verified");
      expect(JSON.parse(memoryNode.retention_policy_json)).toMatchObject({
        allowAutonomous: true,
        allowGuided: true,
      });
    } finally {
      database.close();
    }
  });
});

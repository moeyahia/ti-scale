import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { EventRepository } from "../../events";
import {
  BrainContextService,
  canonicalMissionMemoryNodeId,
  canonicalRunMemoryNodeId,
} from "../../brain-runtime";
import {
  findRejectableSecrets,
  findReusableContentIdentifiers,
} from "../AttackLesson";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { CANONICAL_REPORT_ARTIFACT_TYPES } from "../../reports";
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

function connectHealthyVaultWithCurrentNodes(
  database: SqliteDatabase,
  nodeIds: readonly string[],
): void {
  const connectionId = "vault-learning-dedup";
  database.prepare(`
    INSERT INTO vault_connections (
      id, vault_path, display_name, status, sync_scope_json,
      permission_granted_at, last_sync_at, created_at, updated_at
    ) VALUES (?, ?, 'Learning deduplication Vault', 'connected', '{}', ?, ?, ?, ?)
  `).run(
    connectionId,
    `/tmp/${connectionId}`,
    NOW,
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id,
      reason, details_json, record_hash, occurred_at
    ) VALUES (?, 'operator', 'operator:test', 'vault.health.verified',
      'vault_connection', ?, 'Disposable Vault round trip passed', '{}', ?, ?)
  `).run(
    `audit-${connectionId}`,
    connectionId,
    "f".repeat(64),
    NOW,
  );
  const insertSync = database.prepare(`
    INSERT INTO vault_sync_state (
      id, connection_id, node_id, relative_path, database_version,
      vault_content_hash, database_content_hash, status,
      last_scanned_at, last_synced_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'synced', ?, ?)
  `);
  for (const nodeId of nodeIds) {
    const current = database.prepare(`
      SELECT node.version, version.content_hash
      FROM memory_nodes node
      JOIN memory_versions version
        ON version.node_id = node.id AND version.version = node.version
      WHERE node.id = ?
    `).get(nodeId) as {
      readonly version: number;
      readonly content_hash: string;
    };
    insertSync.run(
      `sync-${nodeId}`,
      connectionId,
      nodeId,
      `70 Lessons/${nodeId}.md`,
      current.version,
      current.content_hash,
      current.content_hash,
      NOW,
      NOW,
    );
  }
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
  test("counts one recovery entry without counting the matching exit transition twice", () => {
    const { database, learning } = setup();
    try {
      seedMission(database, "mission-recovery-metrics", "autonomous", null);
      seedTerminalRun(database, {
        missionId: "mission-recovery-metrics",
        runId: "run-recovery-metrics",
        journey: "autonomous",
        status: "completed",
      });
      const events = new EventRepository(database);
      events.append({
        id: "event-recovery-entered",
        runId: "run-recovery-metrics",
        eventType: "run.state_changed",
        actorType: "system",
        summary: "running -> recovering: bounded retry scheduled",
        payload: { from: "running", to: "recovering" },
        occurredAt: NOW,
      });
      events.append({
        id: "event-recovery-exited",
        runId: "run-recovery-metrics",
        eventType: "run.state_changed",
        actorType: "system",
        summary: "recovering -> running: bounded retry resumed",
        payload: { from: "recovering", to: "running" },
        occurredAt: NOW,
      });

      const evaluation = learning.recordTerminalEvaluation({
        runId: "run-recovery-metrics",
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        outcome: {
          success: true,
          summary: "The bounded retry recovered and the mission completed.",
          criteria: [],
        },
      });

      expect(evaluation.metrics).toMatchObject({
        recoveryCount: 1,
        recoverySuccessRate: 1,
      });
    } finally {
      database.close();
    }
  });

  test("counts the canonical Markdown and JSON report artifacts as one complete report package", () => {
    const { database, learning } = setup();
    try {
      seedMission(database, "mission-report-metrics", "autonomous", null);
      seedTerminalRun(database, {
        missionId: "mission-report-metrics",
        runId: "run-report-metrics",
        journey: "autonomous",
        status: "completed",
      });
      for (const [index, artifactType] of Object.values(
        CANONICAL_REPORT_ARTIFACT_TYPES,
      ).entries()) {
        database.prepare(`
          INSERT INTO artifacts (
            id, mission_id, run_id, journey, artifact_type, storage_uri,
            content_hash, byte_size, media_type, sensitivity, metadata_json,
            created_at
          ) VALUES (?, 'mission-report-metrics', 'run-report-metrics',
            'autonomous', ?, ?, ?, 1, 'application/octet-stream',
            'private', '{}', ?)
        `).run(
          `artifact-report-metrics-${index}`,
          artifactType,
          `memory://report-metrics/${index}`,
          String(index + 1).repeat(64),
          NOW,
        );
      }

      const evaluation = learning.recordTerminalEvaluation({
        runId: "run-report-metrics",
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        outcome: {
          success: true,
          summary: "The bounded mission completed.",
          criteria: [],
        },
      });
      expect(evaluation.metrics).toMatchObject({
        artifactCount: 2,
        reportCount: 2,
      });
      expect(evaluation.scores.reportQuality).toBe(1);
    } finally {
      database.close();
    }
  });

  test("links terminal evaluations to canonical mission/run memory and projects only after commit", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const projected: string[][] = [];
    const learning = new RunLearningService(database, {
      clock: () => new Date(NOW),
      events: new EventRepository(database),
      projectMemoryNodes: (nodeIds) => {
        expect(database.inTransaction).toBe(false);
        projected.push([...nodeIds]);
      },
    });
    try {
      seedMission(database, "mission-graph", "guided", "engagement-graph");
      seedTerminalRun(database, {
        missionId: "mission-graph",
        runId: "run-graph",
        journey: "guided",
        status: "completed",
      });

      const first = learning.recordTerminalEvaluation({
        runId: "run-graph",
        terminalStatus: "completed",
        createdBy: "run-supervisor",
      });
      const replay = learning.recordTerminalEvaluation({
        runId: "run-graph",
        terminalStatus: "completed",
        createdBy: "run-supervisor",
      });

      expect(replay.id).toBe(first.id);
      const missionNodeId = canonicalMissionMemoryNodeId("mission-graph");
      const runNodeId = canonicalRunMemoryNodeId("run-graph");
      const evaluationNode = database.prepare(`
        SELECT id, scope, engagement_id, mission_id, sensitivity, lifecycle_status
        FROM memory_nodes WHERE node_type = 'evaluation'
      `).get() as {
        id: string;
        scope: string;
        engagement_id: string | null;
        mission_id: string | null;
        sensitivity: string;
        lifecycle_status: string;
      };
      expect(database.prepare(`
        SELECT id, node_type, scope, engagement_id, mission_id, sensitivity, lifecycle_status
        FROM memory_nodes WHERE id IN (?, ?) ORDER BY node_type
      `).all(missionNodeId, runNodeId)).toEqual([
        {
          id: missionNodeId,
          node_type: "mission",
          scope: "mission",
          engagement_id: "engagement-graph",
          mission_id: "mission-graph",
          sensitivity: "private",
          lifecycle_status: "verified",
        },
        {
          id: runNodeId,
          node_type: "run",
          scope: "mission",
          engagement_id: "engagement-graph",
          mission_id: "mission-graph",
          sensitivity: "private",
          lifecycle_status: "verified",
        },
      ]);
      expect(evaluationNode).toMatchObject({
        scope: "mission",
        mission_id: "mission-graph",
        sensitivity: "private",
        lifecycle_status: "verified",
      });
      expect(database.prepare(`
        SELECT source_node_id, edge_type, target_node_id
        FROM memory_edges ORDER BY edge_type, source_node_id
      `).all()).toEqual([
        {
          source_node_id: runNodeId,
          edge_type: "belongs_to",
          target_node_id: missionNodeId,
        },
        {
          source_node_id: evaluationNode.id,
          edge_type: "derived_from",
          target_node_id: runNodeId,
        },
      ]);
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get()).toEqual({ count: 3 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get()).toEqual({ count: 2 });
      expect(projected).toEqual([]);
      const firstProjection = learning.projectTerminalMemory("run-graph");
      const replayProjection = learning.projectTerminalMemory("run-graph");
      expect(firstProjection).toEqual([missionNodeId, runNodeId, evaluationNode.id]);
      expect(replayProjection).toEqual(firstProjection);
      expect(projected).toHaveLength(2);
      for (const nodeIds of projected) {
        expect(nodeIds).toEqual([missionNodeId, runNodeId, evaluationNode.id]);
      }
    } finally {
      database.close();
    }
  });

  test("keeps the canonical evaluation committed when the optional Vault sink fails", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const learning = new RunLearningService(database, {
      clock: () => new Date(NOW),
      projectMemoryNodes: () => {
        expect(database.inTransaction).toBe(false);
        throw new Error("optional Vault offline");
      },
    });
    try {
      seedMission(database, "mission-vault-offline", "guided", null);
      seedTerminalRun(database, {
        missionId: "mission-vault-offline",
        runId: "run-vault-offline",
        journey: "guided",
        status: "completed",
      });
      expect(() => learning.recordTerminalEvaluation({
        runId: "run-vault-offline",
        terminalStatus: "completed",
        createdBy: "run-supervisor",
      })).not.toThrow();
      expect(() => learning.projectTerminalMemory("run-vault-offline"))
        .toThrow("optional Vault offline");
      expect(database.prepare("SELECT COUNT(*) AS count FROM run_evaluations").get())
        .toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_nodes").get())
        .toEqual({ count: 3 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM memory_edges").get())
        .toEqual({ count: 2 });
    } finally {
      database.close();
    }
  });

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
      expect(evaluation.scores).toMatchObject({
        objectiveCompletion: 1,
        verifiedObjectiveCompletion: 0,
        evidenceQuality: 0,
      });
      expect(evaluation.metrics).toMatchObject({
        completionBasis: "canonical_result_without_verified_evidence",
        evidenceCount: 0,
        verifiedEvidenceCount: 0,
        timeToFirstMeaningfulEvidenceMs: null,
      });
      expect(evaluation.retrospective).toContain("workflow-complete from a canonical result only");
      expect(evaluation.retrospective).toContain("Engagement Log output was not counted as evidence");
      expect(evaluation.proposedLessonIds).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("records a bounded Guided check as workflow-complete without claiming evidence verification", () => {
    const { database, learning } = setup();
    try {
      seedMission(database, "mission-guided-check", "guided", "engagement-guided-check");
      seedTerminalRun(database, {
        missionId: "mission-guided-check",
        runId: "run-guided-check",
        journey: "guided",
        status: "completed",
      });

      const evaluation = learning.recordTerminalEvaluation({
        runId: "run-guided-check",
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        outcome: {
          success: true,
          summary: "The exact represented connectivity check returned a bounded result",
          criteria: [{
            criterion: "Exact reviewed local result received",
            satisfied: true,
            explanation: "The exact action and terminal tool receipt are correlated",
            evidenceIds: [],
          }],
        },
      });

      expect(evaluation.scores).toMatchObject({
        objectiveCompletion: 1,
        verifiedObjectiveCompletion: 0,
        successCriteriaCoverage: 1,
        evidenceQuality: 0,
      });
      expect(evaluation.metrics).toMatchObject({
        completionBasis: "canonical_result_without_verified_evidence",
        evidenceCount: 0,
        verifiedEvidenceCount: 0,
        findingCount: 0,
        verifiedFindingCount: 0,
      });
      expect(evaluation.evidenceCoverage).toBe(0);
      expect(evaluation.retrospective).toContain("workflow-complete from a canonical result only");
      expect(evaluation.proposedLessonIds).toEqual([]);
    } finally {
      database.close();
    }
  });

  test("does not infer objective completion from terminal status without an outcome evaluation", () => {
    const { database, learning } = setup();
    try {
      seedMission(database, "mission-terminal-only", "guided", null);
      seedTerminalRun(database, {
        missionId: "mission-terminal-only",
        runId: "run-terminal-only",
        journey: "guided",
        status: "completed",
      });
      const evaluation = learning.recordTerminalEvaluation({
        runId: "run-terminal-only",
        terminalStatus: "completed",
        createdBy: "run-supervisor",
      });
      expect(evaluation.scores).toMatchObject({
        objectiveCompletion: 0,
        verifiedObjectiveCompletion: null,
        successCriteriaCoverage: 0,
      });
      expect(evaluation.metrics).toMatchObject({ completionBasis: "outcome_not_evaluated" });
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
        verifiedObjectiveCompletion: 1,
        evidenceQuality: 1,
        journeyAdherence: 1,
        repeatedActionAvoidance: 0.5,
      });
      expect(first.metrics).toMatchObject({
        completionBasis: "verified_evidence",
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

  test("uses an exact reviewed lesson and its explicit failure contradiction instead of proposing a duplicate", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const memory = new MemoryRepository(database, { clock: () => new Date(NOW) });
    const brain = new BrainContextService({
      database,
      secondBrain: new SecondBrainService(memory),
    });
    const learning = new RunLearningService(database, {
      clock: () => new Date(NOW),
      events: new EventRepository(database),
    });
    try {
      seedMission(database, "mission-memory-dedup", "autonomous", "engagement-memory-dedup");
      seedTerminalRun(database, {
        missionId: "mission-memory-dedup",
        runId: "run-memory-prior",
        journey: "autonomous",
        status: "completed",
        evidenceId: "evidence-memory-prior",
      });
      seedTerminalRun(database, {
        missionId: "mission-memory-dedup",
        runId: "run-memory-current",
        journey: "autonomous",
        status: "completed",
        evidenceId: "evidence-memory-current",
      });
      const statement = "For comparable authorized reconnaissance work, use bounded specialist steps and require verified evidence before declaring success.";
      database.prepare(`
        INSERT INTO lessons (
          id, statement, lesson_type, applicability_scope, confidence,
          expected_benefit, risk, status, authoring_agent_id, reviewed_by,
          reviewed_at, created_at, updated_at
        ) VALUES (
          'lesson-reviewed-dedup', ?, 'attack_chain', 'global', 0.9,
          'Prevent duplicate learning', 'Requires matching evidence',
          'verified', 'lesson-author', 'independent-reviewer', ?, ?, ?
        )
      `).run(statement, NOW, NOW, NOW);
      database.prepare(`
        INSERT INTO lesson_evidence (
          lesson_id, evidence_id, relationship, rationale, created_at
        ) VALUES (
          'lesson-reviewed-dedup', 'evidence-memory-prior', 'supports',
          'Independent verified evidence supports the reviewed lesson.', ?
        )
      `).run(NOW);
      const lessonNode = memory.createNode({
        id: canonicalLessonMemoryNodeId("lesson-reviewed-dedup"),
        nodeType: "lesson",
        title: "Reviewed bounded reconnaissance lesson",
        summary: statement,
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.9,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: {
          method: "derived",
          explanation: "Projected from an independently reviewed evidence-linked lesson.",
          sources: [{ sourceType: "lesson", sourceId: "lesson-reviewed-dedup", acquiredAt: NOW }],
        },
        authorType: "system",
        authorId: "lesson-projector",
        retentionPolicy: { allowAutonomous: true, allowGuided: true },
      });
      const failureNode = memory.createNode({
        id: "failure-reviewed-contradiction",
        nodeType: "failure",
        title: "Reviewed reconnaissance counterexample",
        summary: "A prior bounded sequence failed despite matching prerequisites.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.9,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: {
          method: "evidence",
          explanation: "The failure is linked to immutable verified evidence.",
          sources: [{ sourceType: "evidence", sourceId: "evidence-memory-prior", acquiredAt: NOW }],
        },
        authorType: "system",
        authorId: "failure-projector",
        retentionPolicy: { allowAutonomous: true, allowGuided: true },
      });
      const unrelatedFailureNode = memory.createNode({
        id: "failure-reviewed-unrelated",
        nodeType: "failure",
        title: "Unrelated reviewed failure",
        summary: "This failure has no explicit contradiction relationship to the selected lesson.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.9,
        lifecycleStatus: "verified",
        confirmationState: "not_required",
        provenance: {
          method: "evidence",
          explanation: "The unrelated failure is evidence-linked but not applicable to the exact lesson.",
          sources: [{ sourceType: "evidence", sourceId: "evidence-memory-prior", acquiredAt: NOW }],
        },
        authorType: "system",
        authorId: "failure-projector",
        retentionPolicy: { allowAutonomous: true, allowGuided: true },
      });
      database.prepare(`
        UPDATE memory_sources SET evidence_id = 'evidence-memory-prior'
        WHERE node_id IN (?, ?) AND source_type = 'evidence'
      `).run(failureNode.id, unrelatedFailureNode.id);
      memory.createEdge({
        id: "edge-reviewed-contradiction",
        sourceNodeId: failureNode.id,
        targetNodeId: lessonNode.id,
        edgeType: "contradicts",
        title: "Reviewed counterexample",
        summary: "The evidence-linked failure remains an explicit counterexample to the reviewed lesson.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.9,
        lifecycleStatus: "verified",
        provenance: {
          method: "evidence",
          explanation: "Independent evidence review preserved this contradiction.",
          sources: [{ sourceType: "evidence", sourceId: "evidence-memory-prior", acquiredAt: NOW }],
        },
        explanation: "The contradiction must remain visible when the lesson is reused.",
        authorType: "system",
        authorId: "failure-projector",
      });
      connectHealthyVaultWithCurrentNodes(database, [
        lessonNode.id,
        failureNode.id,
        unrelatedFailureNode.id,
      ]);
      const items = [
        {
          node: lessonNode,
          score: 1,
          relevanceReason: "Exact reviewed lesson statement match.",
          signals: ["exact"] as const,
        },
        {
          node: failureNode,
          score: 0.9,
          relevanceReason: "Explicit contradiction to the reviewed lesson.",
          signals: ["graph"] as const,
        },
        {
          node: unrelatedFailureNode,
          score: 0.8,
          relevanceReason: "Other failure memory retrieved for comparison.",
          signals: ["recent"] as const,
        },
      ];
      const pack = memory.persistContextPack({
        id: "context-terminal-lesson-dedup",
        missionId: "mission-memory-dedup",
        runId: "run-memory-current",
        journey: "autonomous",
        purpose: "Lesson proposal: focused deterministic deduplication fixture.",
        queryRedacted: "Retrieve reviewed lesson and failure context.",
        scopePolicy: {
          engagementId: "engagement-memory-dedup",
          missionId: "mission-memory-dedup",
          allowGlobal: true,
          journey: "autonomous",
          maximumSensitivity: "private",
          allowedNodeTypes: ["lesson", "failure"],
          allowedStatuses: ["confirmed", "verified"],
          contextBudget: 4_000,
          limit: 12,
          graphDepth: 2,
        },
        contextBudget: 4_000,
        createdBy: "run-evaluator",
        items,
      });
      const context = {
        hook: "lesson_proposal" as const,
        status: "ready" as const,
        contextPack: pack,
        items,
        auditRecordId: "audit-terminal-lesson-dedup",
      };
      const application = learning.compileTerminalLessonMemoryApplication({
        runId: "run-memory-current",
        terminalStatus: "completed",
        context,
      });
      expect(application).toMatchObject({
        disposition: "reuse_verified_lesson_with_contradiction",
        reusedLessonId: "lesson-reviewed-dedup",
        usedNodeIds: [failureNode.id, lessonNode.id].sort(),
        contradictionNodeIds: [failureNode.id],
      });
      brain.recordContextDispositions(context, application.contextDispositions);

      const evaluation = learning.recordTerminalEvaluation({
        runId: "run-memory-current",
        terminalStatus: "completed",
        createdBy: "outcome-evaluator",
        terminalLessonMemoryApplication: application,
        outcome: {
          success: true,
          summary: "Validated",
          criteria: [{
            criterion: "Evidence",
            satisfied: true,
            explanation: "Verified",
            evidenceIds: ["evidence-memory-current"],
          }],
        },
      });

      expect(evaluation.proposedLessonIds).toEqual([]);
      expect(database.prepare("SELECT COUNT(*) AS count FROM lessons").get()).toEqual({ count: 1 });
      expect(database.prepare(`
        SELECT status, reviewed_by FROM lessons WHERE id = 'lesson-reviewed-dedup'
      `).get()).toEqual({ status: "verified", reviewed_by: "independent-reviewer" });
      const dispositions = database.prepare(`
        SELECT node_id, used, influence_summary, ignored_reason
        FROM memory_context_items WHERE context_pack_id = ?
        ORDER BY node_id
      `).all(pack.id) as Array<{
        node_id: string;
        used: number;
        influence_summary: string | null;
        ignored_reason: string | null;
      }>;
      expect(dispositions.map(({ node_id, used }) => ({ node_id, used }))).toEqual([
        { node_id: failureNode.id, used: 1 },
        { node_id: unrelatedFailureNode.id, used: 0 },
        { node_id: lessonNode.id, used: 1 },
      ]);
      expect(dispositions[0]?.influence_summary).toContain("contradiction");
      expect(dispositions[0]?.ignored_reason).toBeNull();
      expect(dispositions[1]?.influence_summary).toBeNull();
      expect(dispositions[1]?.ignored_reason).toContain("explicit confirmed or verified contradiction");
      expect(dispositions[2]?.influence_summary).toContain("suppressed a duplicate");
      expect(dispositions[2]?.ignored_reason).toBeNull();
      expect(database.prepare(`
        SELECT edge.source_node_id, edge.edge_type, target.node_type AS target_type
        FROM memory_edges edge
        JOIN memory_nodes target ON target.id = edge.target_node_id
        WHERE edge.source_node_id = ? AND edge.edge_type = 'used_in'
      `).get(lessonNode.id)).toEqual({
        source_node_id: lessonNode.id,
        edge_type: "used_in",
        target_type: "evaluation",
      });
      expect(database.prepare(`
        SELECT outcome, context_pack_id FROM lesson_usage
        WHERE lesson_id = 'lesson-reviewed-dedup' AND run_id = 'run-memory-current'
      `).get()).toEqual({
        outcome: "duplicate_suppressed_with_contradiction_preserved",
        context_pack_id: pack.id,
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM events
        WHERE run_id = 'run-memory-current' AND event_type = 'learning.lesson_reused'
      `).get()).toEqual({ count: 1 });
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

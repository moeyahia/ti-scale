import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { AttackChainLearningService, type AttackChainDetailInput } from "../AttackChainLessonRepository";

const NOW = "2026-07-15T15:00:00.000Z";

function setup(): { database: SqliteDatabase; service: AttackChainLearningService } {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at
    ) VALUES ('mission-chain', 'Authorized assessment', 'Retain reusable learning',
      'autonomous', 'completed', 'verified', 'operator', ?, ?)
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, budget_json, budget_usage_json,
      status_reason, started_at, ended_at, created_at, updated_at, version
    ) VALUES ('run-chain', 'mission-chain', 'autonomous', 'completed', '{}', '{}',
      'Completed', ?, ?, ?, ?, 1)
  `).run(NOW, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, evidence_type,
      content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES ('evidence-chain', 'mission-chain', 'run-chain', 'specialist', ?,
      'service_observation', ?, '{}', 1, 'private', 'verified',
      'Verified retained result', 'agent-recon', ?)
  `).run(NOW, "b".repeat(64), NOW);
  database.prepare(`
    INSERT INTO lessons (
      id, statement, lesson_type, applicability_scope, mission_id,
      confidence, expected_benefit, risk, status, authoring_agent_id,
      created_at, updated_at
    ) VALUES ('lesson-chain', 'Validate service identity with independent evidence',
      'attack_chain', 'mission', 'mission-chain', 0.85,
      'Reduce unsupported technique selection',
      'Requires independent evidence review', 'proposed', 'run-evaluator', ?, ?)
  `).run(NOW, NOW);
  return {
    database,
    service: new AttackChainLearningService(database, { clock: () => new Date(NOW) }),
  };
}

function validInput(overrides: Partial<AttackChainDetailInput> = {}): AttackChainDetailInput {
  return {
    title: "Validate service identity with independent evidence",
    techniqueName: "Service identity validation",
    techniqueCategory: "recon",
    summary: "Correlate bounded read-only observations before selecting a technique.",
    prerequisites: ["Confirmed authorization and normalized target scope"],
    observedSignals: ["A distinct service response is retained as verified evidence"],
    orderedSteps: [
      "Use nmap service detection against <TARGET_HOST>.",
      "Compare the retained service observation with the expected protocol behavior.",
    ],
    tools: ["nmap"],
    publicReferences: ["https://nmap.org/book/man-version-detection.html"],
    validationCheckpoints: ["Confirm a verified evidence ID records the expected protocol response"],
    failureRecovery: ["If no new evidence is produced, classify the failure and change conditions before one bounded retry"],
    antiReuseWarnings: ["Do not treat one unverified banner as proof"],
    expectedOutcome: "Service identity uncertainty is reduced with retained evidence",
    reuseGuidance: "Apply only when authorization and the prerequisite signal match",
    confidence: 0.85,
    scope: "mission",
    sources: [{
      sourceType: "run_evaluation",
      sourceId: "evaluation-chain",
      sourceHash: "c".repeat(64),
      runId: "run-chain",
      evidenceId: "evidence-chain",
    }],
    ...overrides,
  };
}

describe("AttackChainLearningService", () => {
  test("retains normalized executable details but retrieves them only after independent verification", () => {
    const { database, service } = setup();
    try {
      const details = service.retainCandidateDetails("lesson-chain", validInput(), "run-evaluator");
      expect(details.version).toBe(1);
      expect(details.items.filter((item) => item.type === "ordered_step").map((item) => item.content))
        .toEqual([...validInput().orderedSteps]);
      expect(details.items.some((item) => item.type === "public_reference")).toBe(true);
      expect(details.items.some((item) => item.type === "validation_checkpoint")).toBe(true);
      expect(details.items.some((item) => item.type === "failure_recovery")).toBe(true);
      expect(details.sources).toMatchObject([{
        sourceType: "run_evaluation",
        sourceId: "evaluation-chain",
        runId: "run-chain",
        evidenceId: "evidence-chain",
      }]);
      expect(service.verifiedPlanningContext({ missionId: "mission-chain" })).toBe("");

      database.prepare(`
        INSERT INTO lesson_evidence (
          lesson_id, evidence_id, relationship, rationale, created_at
        ) VALUES ('lesson-chain', 'evidence-chain', 'supports', 'Verified support', ?)
      `).run(NOW);
      database.prepare(`
        INSERT INTO lesson_evidence (
          lesson_id, run_id, relationship, rationale, created_at
        ) VALUES ('lesson-chain', 'run-chain', 'supports', 'Source run', ?)
      `).run(NOW);
      database.prepare(`
        UPDATE lessons SET status = 'under_review', updated_at = ? WHERE id = 'lesson-chain'
      `).run(NOW);
      database.prepare(`
        UPDATE lessons SET status = 'verified', reviewed_by = 'reviewer-independent',
          reviewed_at = ?, updated_at = ? WHERE id = 'lesson-chain'
      `).run(NOW, NOW);
      const memoryNodeId = service.synchronizeMemoryLifecycle(
        "lesson-chain", "verified", "reviewer-independent",
      );

      const context = service.verifiedPlanningContext({ missionId: "mission-chain" });
      expect(context).toContain("VERIFIED EXECUTABLE ATTACK CHAINS");
      expect(context).toContain("ordered chain");
      expect(context).toContain("<TARGET_HOST>");
      expect(context).toContain("tools: nmap");
      expect(context).toContain("nmap.org/book/man-version-detection.html");
      expect(context).toContain("failure recovery");
      expect(context).not.toContain("HTB");
      expect(database.prepare(`
        SELECT lifecycle_status, confirmation_state, body FROM memory_nodes WHERE id = ?
      `).get(memoryNodeId)).toMatchObject({
        lifecycle_status: "verified",
        confirmation_state: "not_required",
      });
      expect((database.prepare("SELECT body FROM memory_nodes WHERE id = ?").get(memoryNodeId) as { body: string }).body)
        .toContain("Ordered steps:");
      expect(() => service.retainCandidateDetails("lesson-chain", validInput(), "run-evaluator"))
        .toThrow("verified attack-chain details are immutable");
    } finally {
      database.close();
    }
  });

  test("rejects box/target content, walkthrough references, and literal command operands", () => {
    const { database, service } = setup();
    try {
      expect(() => service.retainCandidateDetails("lesson-chain", validInput({
        summary: "Use the CredSmith HTB box path at 10.10.10.10",
      }), "run-evaluator")).toThrow();
      expect(() => service.retainCandidateDetails("lesson-chain", validInput({
        publicReferences: ["https://example.org/htb-credsmith-walkthrough"],
      }), "run-evaluator")).toThrow();
      expect(() => service.retainCandidateDetails("lesson-chain", validInput({
        orderedSteps: ["nmap -sV victim"],
      }), "run-evaluator")).toThrow("placeholders");
      expect(() => service.retainCandidateDetails("lesson-chain", validInput({
        orderedSteps: ["nmap -sV <TARGET_HOST> -oN /tmp/target.txt"],
      }), "run-evaluator")).toThrow();
      expect(database.prepare("SELECT COUNT(*) AS count FROM lesson_attack_chain_details").get())
        .toEqual({ count: 0 });
    } finally {
      database.close();
    }
  });

  test("database verification gate rejects incomplete or non-evidence-backed attack chains", () => {
    const { database } = setup();
    try {
      database.prepare("UPDATE lessons SET status='under_review', updated_at=? WHERE id='lesson-chain'").run(NOW);
      expect(() => database.prepare(`
        UPDATE lessons SET status='verified', reviewed_by='reviewer-independent',
          reviewed_at=?, updated_at=? WHERE id='lesson-chain'
      `).run(NOW, NOW)).toThrow("complete executable details");
    } finally {
      database.close();
    }
  });
});

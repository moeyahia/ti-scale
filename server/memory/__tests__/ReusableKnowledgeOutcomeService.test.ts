import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { AuditTrailWriter } from "../../intelligence-v24/AuditTrailWriter";
import { MemoryRepository } from "../MemoryRepository";
import {
  ReusableKnowledgeOutcomeError,
  ReusableKnowledgeOutcomeService,
} from "../ReusableKnowledgeOutcomeService";

const NOW = "2026-07-21T12:00:00.000Z";

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function createFixture() {
  const database = createDatabaseConnection({ filename: ":memory:" });
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at
    ) VALUES ('mission-outcomes', 'Outcome fixture', 'Validate reusable knowledge',
      'autonomous', 'completed', 'verified', 'operator-test', ?, ?)
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, created_at, updated_at
    ) VALUES ('run-outcomes', 'mission-outcomes', 'autonomous', 'completed', ?, ?)
  `).run(NOW, NOW);

  const repository = new MemoryRepository(database, { clock: () => new Date(NOW) });
  const nodeInput = (id: string, title: string, body: string) => ({
    id,
    nodeType: "attack_procedure" as const,
    title,
    summary: "Operator-reviewed reusable procedure knowledge.",
    body,
    scope: { kind: "global" as const },
    sensitivity: "internal" as const,
    confidence: 0.96,
    lifecycleStatus: "verified" as const,
    confirmationState: "confirmed" as const,
    provenance: {
      method: "derived" as const,
      explanation: "Generalized from a locally reviewed canonical attack attempt.",
      sources: [{
        sourceType: "review_receipt",
        sourceId: `source-${id}`,
        acquiredAt: NOW,
      }],
    },
    authorType: "operator" as const,
    authorId: "operator-test",
  });
  const procedure = repository.createNode(nodeInput(
    `mem_${"1".repeat(32)}`,
    "Bounded reusable validation procedure",
    "Verify the expected service state, run one bounded validation, and retain the result.",
  ));
  const unrelated = repository.createNode(nodeInput(
    `mem_${"2".repeat(32)}`,
    "Unrelated reusable procedure",
    "A separately reviewed procedure that was not used by the fixture attempts.",
  ));
  const historicalClaim = repository.createNode({
    ...nodeInput(
      `mem_${"3".repeat(32)}`,
      "Historical reported failure",
      JSON.stringify({ status: "failed", note: "Historical prose is not canonical proof." }),
    ),
    nodeType: "outcome" as const,
  });

  seedAttempt(database, "attempt-success", "succeeded", procedure.id);
  seedAttempt(database, "attempt-failed", "failed", procedure.id);
  seedEvidence(database, "evidence-success", "attempt-success");
  seedEvidence(database, "evidence-failed", "attempt-failed");

  return {
    database,
    procedureId: procedure.id,
    unrelatedId: unrelated.id,
    historicalClaimId: historicalClaim.id,
  };
}

function seedAttempt(
  database: SqliteDatabase,
  id: string,
  status: "succeeded" | "failed",
  procedureNodeId: string,
): void {
  database.prepare(`
    INSERT INTO attack_attempts (
      id, mission_id, run_id, objective, technique_name, action_class,
      prerequisites_json, normalized_parameters_json, status,
      outcome_summary, failure_category, ended_at, created_at, updated_at
    ) VALUES (?, 'mission-outcomes', 'run-outcomes',
      'Validate a bounded reusable procedure', 'Bounded validation',
      'exploit-validation', '[]', '{}', ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    status,
    status === "succeeded" ? "The represented validation succeeded." : "The represented validation failed safely.",
    status === "failed" ? "deterministic_tool_error" : null,
    NOW,
    NOW,
    NOW,
  );
  database.prepare(`
    INSERT INTO attack_attempt_knowledge_contexts (
      attack_attempt_id, procedure_node_id, product_node_ids_json,
      version_node_ids_json, stack_node_ids_json, prerequisite_node_ids_json,
      observed_state_node_ids_json, normalized_parameters_json,
      created_at, updated_at
    ) VALUES (?, ?, '[]', '[]', '[]', '[]', '[]', '{}', ?, ?)
  `).run(id, procedureNodeId, NOW, NOW);
}

function seedEvidence(
  database: SqliteDatabase,
  id: string,
  attemptId: string,
  options: {
    readonly evidenceType?: string;
    readonly verificationState?: "unverified" | "verified";
    readonly custody?: boolean;
    readonly link?: boolean;
  } = {},
): void {
  const evidenceType = options.evidenceType ?? "exploit_validation_result";
  const verificationState = options.verificationState ?? "verified";
  database.prepare(`
    INSERT INTO evidence (
      id, mission_id, run_id, source, acquired_at, target, evidence_type,
      content_hash, provenance_json, confidence, sensitivity,
      verification_state, summary, created_by, created_at
    ) VALUES (?, 'mission-outcomes', 'run-outcomes', 'local-evaluator', ?,
      'redacted reusable fixture', ?, ?, '{}', 0.98, 'internal', ?,
      'Locally verified result for the exact represented attempt.', 'worker-test', ?)
  `).run(id, NOW, evidenceType, sha256(id), verificationState, NOW);
  if (options.custody !== false) {
    database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'verified', 'local-evaluator', '{}', ?)
    `).run(`custody-${id}`, id, NOW);
  }
  if (options.link !== false) {
    database.prepare(`
      INSERT INTO attack_attempt_evidence (
        attack_attempt_id, evidence_id, relationship, created_at
      ) VALUES (?, ?, 'outcome', ?)
    `).run(attemptId, id, NOW);
  }
}

function expectOutcomeError(
  action: () => unknown,
  code: ReusableKnowledgeOutcomeError["code"],
): void {
  try {
    action();
    throw new Error("Expected reusable outcome classification to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(ReusableKnowledgeOutcomeError);
    expect((error as ReusableKnowledgeOutcomeError).code).toBe(code);
  }
}

describe("ReusableKnowledgeOutcomeService", () => {
  test("derives many-to-many success and failed tags only from canonical attempts and verified evidence", () => {
    const fixture = createFixture();
    try {
      const service = new ReusableKnowledgeOutcomeService(
        fixture.database,
        () => new Date(NOW),
      );
      service.bind({
        memoryNodeId: fixture.procedureId,
        attackAttemptId: "attempt-success",
        evidenceIds: ["evidence-success"],
        actorId: "operator-test",
        actorType: "operator",
        reason: "Reviewed the exact attempt and its verified result.",
      });
      const summary = service.bind({
        memoryNodeId: fixture.procedureId,
        attackAttemptId: "attempt-failed",
        evidenceIds: ["evidence-failed"],
        actorId: "operator-test",
        actorType: "operator",
        reason: "Reviewed the exact failure and retained its verified result.",
      });

      expect(summary).toEqual({
        memoryNodeId: fixture.procedureId,
        outcomeTags: ["success", "failed"],
        classification: "classified",
        successAttemptCount: 1,
        failedAttemptCount: 1,
        evidenceCount: 2,
      });

      service.bind({
        memoryNodeId: fixture.procedureId,
        attackAttemptId: "attempt-success",
        evidenceIds: ["evidence-success"],
        actorId: "operator-test",
        actorType: "operator",
        reason: "The duplicate request is idempotent.",
      });
      expect(fixture.database.prepare(
        "SELECT COUNT(*) AS count FROM reusable_knowledge_outcome_links",
      ).get()).toEqual({ count: 2 });
      expect(fixture.database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'reusable_knowledge.outcome_classified'
      `).get()).toEqual({ count: 2 });
    } finally {
      fixture.database.close();
    }
  });

  test("rejects an unrelated reusable node even when an audit receipt and evidence are otherwise valid", () => {
    const fixture = createFixture();
    try {
      const service = new ReusableKnowledgeOutcomeService(fixture.database);
      expectOutcomeError(() => service.bind({
        memoryNodeId: fixture.unrelatedId,
        attackAttemptId: "attempt-success",
        evidenceIds: ["evidence-success"],
        actorId: "operator-test",
        reason: "This node was not part of the reviewed attempt context.",
      }), "reviewed_knowledge_binding_required");

      const forgedId = "knowledge_outcome_forged_context";
      const auditId = new AuditTrailWriter(fixture.database).append({
        missionId: "mission-outcomes",
        runId: "run-outcomes",
        actor: { type: "operator", id: "operator-test" },
        action: "reusable_knowledge.outcome_classified",
        resourceType: "reusable_knowledge_outcome_link",
        resourceId: forgedId,
        reason: "Attempted direct insertion for a node outside the reviewed binding.",
        details: {},
        occurredAt: NOW,
      });
      const auditHash = (fixture.database.prepare(
        "SELECT record_hash FROM audit_records WHERE id = ?",
      ).get(auditId) as { record_hash: string }).record_hash;
      expect(() => fixture.database.prepare(`
        INSERT INTO reusable_knowledge_outcome_links (
          id, memory_node_id, attack_attempt_id, evidence_id, outcome_tag,
          actor_id, reason, audit_record_id, audit_record_hash, created_at
        ) VALUES (?, ?, 'attempt-success', 'evidence-success', 'success',
          'operator-test', ?, ?, ?, ?)
      `).run(
        forgedId,
        fixture.unrelatedId,
        "Attempted direct insertion for a node outside the reviewed binding.",
        auditId,
        auditHash,
        NOW,
      )).toThrow("reviewed attempt membership");
    } finally {
      fixture.database.close();
    }
  });

  test("leaves historical outcome prose unclassified and rejects weak evidence", () => {
    const fixture = createFixture();
    try {
      const service = new ReusableKnowledgeOutcomeService(fixture.database);
      expect(service.summary(fixture.historicalClaimId)).toEqual({
        memoryNodeId: fixture.historicalClaimId,
        outcomeTags: [],
        classification: "unclassified",
        successAttemptCount: 0,
        failedAttemptCount: 0,
        evidenceCount: 0,
      });

      seedEvidence(fixture.database, "evidence-command", "attempt-success", {
        evidenceType: "command_output",
      });
      seedEvidence(fixture.database, "evidence-unverified", "attempt-success", {
        verificationState: "unverified",
      });
      seedEvidence(fixture.database, "evidence-no-custody", "attempt-success", {
        custody: false,
      });
      seedEvidence(fixture.database, "evidence-no-link", "attempt-success", {
        link: false,
      });
      for (const evidenceId of [
        "evidence-command",
        "evidence-unverified",
        "evidence-no-custody",
        "evidence-no-link",
      ]) {
        expectOutcomeError(() => service.bind({
          memoryNodeId: fixture.procedureId,
          attackAttemptId: "attempt-success",
          evidenceIds: [evidenceId],
          actorId: "operator-test",
          reason: "Weak evidence must not classify reusable knowledge.",
        }), "verified_outcome_evidence_required");
      }
    } finally {
      fixture.database.close();
    }
  });

  test("locks the classified attempt, evidence, reviewed context, custody, and outcome link", () => {
    const fixture = createFixture();
    try {
      const service = new ReusableKnowledgeOutcomeService(fixture.database);
      service.bind({
        memoryNodeId: fixture.procedureId,
        attackAttemptId: "attempt-success",
        evidenceIds: ["evidence-success"],
        actorId: "operator-test",
        reason: "Create an immutable classification fixture.",
      });

      expect(() => fixture.database.prepare(`
        UPDATE attack_attempt_knowledge_contexts
        SET context_pack_id = NULL, updated_at = ?
        WHERE attack_attempt_id = 'attempt-success'
      `).run("2026-07-21T13:00:00.000Z")).toThrow("knowledge binding is immutable");
      expect(() => fixture.database.prepare(`
        DELETE FROM attack_attempt_knowledge_contexts
        WHERE attack_attempt_id = 'attempt-success'
      `).run()).toThrow("knowledge binding is immutable");
      expect(() => fixture.database.prepare(`
        UPDATE attack_attempts SET status = 'failed'
        WHERE id = 'attempt-success'
      `).run()).toThrow("attack attempt outcome is immutable");
      expect(() => fixture.database.prepare(`
        UPDATE evidence SET verification_state = 'disputed'
        WHERE id = 'evidence-success'
      `).run()).toThrow("outcome evidence is immutable");
      expect(() => fixture.database.prepare(`
        DELETE FROM attack_attempt_evidence
        WHERE attack_attempt_id = 'attempt-success' AND evidence_id = 'evidence-success'
      `).run()).toThrow("evidence binding is immutable");
      expect(() => fixture.database.prepare(`
        DELETE FROM evidence_chain_events WHERE evidence_id = 'evidence-success'
      `).run()).toThrow("evidence custody is immutable");
      expect(() => fixture.database.prepare(`
        UPDATE reusable_knowledge_outcome_links SET reason = 'changed'
      `).run()).toThrow("outcome links are immutable");
      expect(() => fixture.database.prepare(`
        DELETE FROM reusable_knowledge_outcome_links
      `).run()).toThrow("outcome links are immutable");
    } finally {
      fixture.database.close();
    }
  });

  test("migration 33 never backfills classifications from a legacy outcome node body", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    try {
      migrateDatabase(database, DATABASE_MIGRATIONS.filter(({ version }) => version <= 32));
      const repository = new MemoryRepository(database, { clock: () => new Date(NOW) });
      const historical = repository.createNode({
        id: `mem_${"4".repeat(32)}`,
        nodeType: "outcome",
        title: "Historical text reported a failed result",
        summary: "This claim has no canonical attack-attempt outcome binding.",
        body: JSON.stringify({ status: "failed", outcome: "failed" }),
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.9,
        lifecycleStatus: "verified",
        confirmationState: "confirmed",
        provenance: {
          method: "derived",
          explanation: "Legacy text-only fixture",
          sources: [{ sourceType: "fixture", sourceId: "historical-outcome", acquiredAt: NOW }],
        },
        authorType: "operator",
        authorId: "operator-test",
      });

      migrateDatabase(database);
      expect(fixtureCount(database, "reusable_knowledge_outcome_links")).toBe(0);
      expect(new ReusableKnowledgeOutcomeService(database).summary(historical.id).outcomeTags)
        .toEqual([]);
    } finally {
      database.close();
    }
  });
});

function fixtureCount(database: SqliteDatabase, table: string): number {
  return Number((database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as {
    count: number;
  }).count);
}

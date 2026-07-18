import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { BrainContextHookError, BrainContextService } from "../../brain-runtime";
import { MemoryRepository, SecondBrainService } from "../../memory";
import { AttackAttemptService } from "../AttackAttemptService";

const NOW = "2026-07-16T12:00:00.000Z";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function fixture(journey: "autonomous" | "guided", memoryPolicy: object = {}) {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  const missionId = `mission-attempt-${journey}`;
  const runId = `run-attempt-${journey}`;
  const planId = `plan-attempt-${journey}`;
  const stepId = `step-attempt-${journey}`;
  const assetId = `asset-attempt-${journey}`;
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at
    ) VALUES (?, 'Attempt Brain fixture', 'Validate one represented attempt', ?,
      'active', 'verified', ?, 'operator:test', ?, ?)
  `).run(missionId, journey, JSON.stringify(memoryPolicy), NOW, NOW);
  database.prepare(`
    INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
    VALUES (?, ?, ?, 'running', ?, ?)
  `).run(runId, missionId, journey, NOW, NOW);
  database.prepare(`
    INSERT INTO plans (id, run_id, version, status, strategy_summary, plan_hash, created_by, created_at)
    VALUES (?, ?, 1, 'active', 'Represent one bounded validation', ?, 'planner:test', ?)
  `).run(planId, runId, "a".repeat(64), NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'validation', 'Validate service', 'Reduce uncertainty', 'ready', ?, ?)
  `).run(stepId, planId, runId, NOW, NOW);
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, properties_json, confidence,
      verification_state, sensitivity, first_seen_at, last_seen_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'asset', 'Disposable asset', 'disposable-asset', 'allowed',
      'active', '{}', 1, 'verified', 'internal', ?, ?, ?, ?)
  `).run(assetId, missionId, runId, NOW, NOW, NOW, NOW);
  return { database, missionId, runId, planId, stepId, assetId };
}

function brain(database: SqliteDatabase, unavailable = false): BrainContextService {
  return new BrainContextService({
    database,
    secondBrain: new SecondBrainService(new MemoryRepository(database)),
    ...(unavailable ? {
      availability: () => ({
        available: false,
        code: "brain_offline",
        explanation: "The local Brain is offline.",
      }),
    } : {}),
  });
}

describe("AttackAttemptService Brain lifecycle seam", () => {
  test("persists attack-attempt context before the represented attempt starts", () => {
    const scope = fixture("guided");
    new MemoryRepository(scope.database).createNode({
      id: "memory-attempt-readiness",
      nodeType: "lesson",
      title: "Bounded service validation prerequisites",
      summary: "Confirm the represented target and technique before starting an attack attempt.",
      scope: { kind: "mission", missionId: scope.missionId },
      sensitivity: "internal",
      confidence: 0.9,
      lifecycleStatus: "verified",
      confirmationState: "not_required",
      provenance: {
        method: "derived",
        explanation: "Derived from a prior locally evaluated disposable-lab attempt.",
        sources: [{ sourceType: "run_evaluation", sourceId: "evaluation-attempt-readiness", acquiredAt: NOW }],
      },
      authorType: "agent",
      authorId: "run-evaluator",
      retentionPolicy: { allowAutonomous: true, allowGuided: true },
    });
    const context = brain(scope.database);
    const service = new AttackAttemptService(scope.database, () => new Date(NOW), context);
    const attempt = service.create({
      missionId: scope.missionId,
      runId: scope.runId,
      planId: scope.planId,
      stepId: scope.stepId,
      targetAssetId: scope.assetId,
      objective: "Validate the represented service condition",
      techniqueName: "Bounded service validation",
      actionClass: "exploit_validation",
    });
    const ready = service.transition({ attemptId: attempt.id, expectedVersion: 1, status: "ready" });
    const running = service.transition({
      attemptId: attempt.id,
      expectedVersion: ready.version,
      status: "running",
      actorId: "specialist-agent",
      actorType: "agent",
    });
    expect(running.status).toBe("running");
    expect(context.coverage({ missionId: scope.missionId, runId: scope.runId })).toMatchObject({
      coveredHooks: ["attack_attempt"],
      invocations: [{ hook: "attack_attempt", status: "ready", retrievedCount: 1 }],
    });
    expect(scope.database.prepare(`
      SELECT COUNT(*) AS count FROM memory_context_packs
      WHERE run_id = ? AND step_id = ?
    `).get(scope.runId, scope.stepId)).toEqual({ count: 1 });
    expect(scope.database.prepare(`
      SELECT used, influence_summary, ignored_reason
      FROM memory_context_items
      WHERE node_id = ?
    `).get("memory-attempt-readiness")).toEqual({
      used: 0,
      influence_summary: null,
      ignored_reason: expect.stringContaining("did not silently change"),
    });
  });

  test("fails closed before start when required Autonomous Brain context is unavailable", () => {
    const scope = fixture("autonomous", {
      allowedScopes: ["verified_lessons"],
      exactContextNodeIds: [],
    });
    const context = brain(scope.database, true);
    const service = new AttackAttemptService(scope.database, () => new Date(NOW), context);
    const attempt = service.create({
      missionId: scope.missionId,
      runId: scope.runId,
      planId: scope.planId,
      stepId: scope.stepId,
      targetAssetId: scope.assetId,
      objective: "Validate the represented service condition",
      techniqueName: "Bounded service validation",
      actionClass: "exploit_validation",
    });
    const ready = service.transition({ attemptId: attempt.id, expectedVersion: 1, status: "ready" });
    expect(() => service.transition({
      attemptId: attempt.id,
      expectedVersion: ready.version,
      status: "running",
    })).toThrow(BrainContextHookError);
    expect(service.get(attempt.id).status).toBe("ready");
    expect(context.coverage({ missionId: scope.missionId, runId: scope.runId })).toMatchObject({
      coveredHooks: ["attack_attempt"],
      invocations: [{ hook: "attack_attempt", status: "blocked", contextPackId: null }],
    });
  });
});

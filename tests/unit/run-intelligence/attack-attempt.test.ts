import { describe, expect, test } from "bun:test";
import {
  AttackAttemptService,
  ReconDigitalTwinService,
} from "../../../server/run-intelligence";
import {
  AGENT_ONE_ID,
  MISSION_ID,
  NOW,
  PLAN_ID,
  RUN_ID,
  STEP_TWO_ID,
  createTestDatabase,
  insertEvidence,
  insertFailedToolCall,
} from "./fixtures";

function createAsset(database: ReturnType<typeof createTestDatabase>, evidenceId: string): string {
  const twin = new ReconDigitalTwinService(database, () => new Date(NOW));
  return twin.createNode({
    missionId: MISSION_ID,
    runId: RUN_ID,
    nodeType: "asset",
    primaryLabel: "fixture-host",
    normalizedIdentity: `fixture-host-${evidenceId}`,
    scopeStatus: "allowed",
    lifecycleState: "observed",
    properties: { address: "fixture.local" },
    provenance: {
      method: "structured_fixture_parser",
      sourceRef: evidenceId,
      sourceAgentId: AGENT_ONE_ID,
      sourceTool: "fixture-parser",
    },
    confidence: 0.9,
    verificationState: "verified",
    sensitivity: "internal",
    firstSeenAt: NOW,
    lastSeenAt: NOW,
    evidence: [{ evidenceId, relationship: "supports" }],
  }).id;
}

describe("first-class AttackAttempt semantics", () => {
  test("a failed tool process does not silently become a failed attack attempt", () => {
    const database = createTestDatabase();
    try {
      insertEvidence(database, { id: "evidence-attempt-target" });
      const assetId = createAsset(database, "evidence-attempt-target");
      const attempts = new AttackAttemptService(database, () => new Date(NOW));
      let attempt = attempts.create({
        missionId: MISSION_ID,
        runId: RUN_ID,
        planId: PLAN_ID,
        stepId: STEP_TWO_ID,
        targetAssetId: assetId,
        objective: "Determine whether the bounded technique meets its prerequisite",
        techniqueId: "fixture-technique",
        techniqueName: "Bounded fixture validation",
        actionClass: "exploit_validation",
        assignedAgentId: AGENT_ONE_ID,
        normalizedParameters: { target: "canonical-asset-reference" },
      });
      expect(attempt.status).toBe("planned");
      attempt = attempts.transition({ attemptId: attempt.id, expectedVersion: attempt.version, status: "ready" });
      attempt = attempts.transition({ attemptId: attempt.id, expectedVersion: attempt.version, status: "running" });

      const failedTool = insertFailedToolCall(database, attempt.id);
      const signal = attempts.observeToolFailure(attempt.id, failedTool.toolCallId);
      expect(signal).toEqual({
        attemptId: attempt.id,
        toolCallId: failedTool.toolCallId,
        toolStatus: "failed",
        errorCategory: "deterministic_tool_error",
        attackAttemptStatus: "running",
        attackAttemptOutcomeChanged: false,
        reason: "tool_process_failure_is_not_attack_outcome",
      });
      expect(attempts.get(attempt.id)).toMatchObject({ status: "running", version: attempt.version });

      const classified = attempts.complete({
        attemptId: attempt.id,
        expectedVersion: attempt.version,
        outcome: "failed",
        outcomeSummary: "The technique failed because its prerequisite was not established.",
        failureCategory: "prerequisite_not_met",
      });
      expect(classified).toMatchObject({
        status: "failed",
        failureCategory: "prerequisite_not_met",
      });
      expect(classified.version).toBe(attempt.version + 1);
    } finally {
      database.close();
    }
  });

  test("successful attempt classification requires verified attributable outcome evidence", () => {
    const database = createTestDatabase();
    try {
      insertEvidence(database, { id: "evidence-target-verified" });
      insertEvidence(database, { id: "evidence-outcome-unverified", verificationState: "unverified" });
      insertEvidence(database, { id: "evidence-outcome-verified", verificationState: "verified" });
      const assetId = createAsset(database, "evidence-target-verified");
      const attempts = new AttackAttemptService(database, () => new Date(NOW));
      let attempt = attempts.create({
        missionId: MISSION_ID,
        runId: RUN_ID,
        targetAssetId: assetId,
        objective: "Classify one evidence-backed bounded outcome",
        techniqueName: "Evidence gate fixture",
        actionClass: "exploit_validation",
      });
      attempt = attempts.transition({ attemptId: attempt.id, expectedVersion: attempt.version, status: "ready" });
      attempt = attempts.transition({ attemptId: attempt.id, expectedVersion: attempt.version, status: "running" });

      expect(() => attempts.complete({
        attemptId: attempt.id,
        expectedVersion: attempt.version,
        outcome: "succeeded",
        outcomeSummary: "An unverified observation must not prove success.",
        evidence: [{ evidenceId: "evidence-outcome-unverified", relationship: "outcome" }],
      })).toThrow("requires verified");
      expect(attempts.get(attempt.id).evidence).toHaveLength(0);

      const completed = attempts.complete({
        attemptId: attempt.id,
        expectedVersion: attempt.version,
        outcome: "succeeded",
        outcomeSummary: "Verified evidence established the bounded outcome.",
        evidence: [{ evidenceId: "evidence-outcome-verified", relationship: "outcome" }],
      });
      expect(completed.status).toBe("succeeded");
      expect(completed.evidence).toEqual([
        expect.objectContaining({
          evidenceId: "evidence-outcome-verified",
          relationship: "outcome",
          verificationState: "verified",
        }),
      ]);
    } finally {
      database.close();
    }
  });

  test("creation and transitions enforce canonical target scope and optimistic versions", () => {
    const database = createTestDatabase();
    try {
      insertEvidence(database, { id: "evidence-scope" });
      const assetId = createAsset(database, "evidence-scope");
      const attempts = new AttackAttemptService(database, () => new Date(NOW));
      expect(() => attempts.create({
        missionId: MISSION_ID,
        runId: RUN_ID,
        objective: "Missing target",
        techniqueName: "No target",
        actionClass: "exploit_validation",
      })).toThrow("canonical target");

      const attempt = attempts.create({
        missionId: MISSION_ID,
        runId: RUN_ID,
        targetAssetId: assetId,
        objective: "Remain in canonical target scope",
        techniqueName: "Scope fixture",
        actionClass: "exploit_validation",
      });
      expect(() => attempts.transition({
        attemptId: attempt.id,
        expectedVersion: 99,
        status: "ready",
      })).toThrow("version changed");
      const ready = attempts.transition({ attemptId: attempt.id, expectedVersion: attempt.version, status: "ready" });
      expect(() => attempts.transition({
        attemptId: ready.id,
        expectedVersion: ready.version,
        status: "cancelled",
      })).not.toThrow();
      expect(attempts.listForRun(RUN_ID)).toHaveLength(1);
    } finally {
      database.close();
    }
  });
});

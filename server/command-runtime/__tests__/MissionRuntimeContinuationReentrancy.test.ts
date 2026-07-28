import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { FailureDiagnosisService } from "../../intelligence-v24/FailureDiagnosisService";
import type { DurableAction } from "../../orchestration";
import {
  createMissionRuntime,
  type MissionOutcomeEvaluatorPort,
  type MissionPlannerPort,
  type ResultAwareExecutionPort,
} from "..";

const NOW = "2026-07-24T20:00:00.000Z";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

class CapturingExecution implements ResultAwareExecutionPort {
  readonly dispatched: DurableAction[] = [];

  async dispatch(action: DurableAction): Promise<void> {
    this.dispatched.push(action);
  }

  async resume(): Promise<void> {}
  async cancelRun(): Promise<void> {}
}

function seed(database: SqliteDatabase) {
  const missionId = "mission-continuation-reentrancy";
  const runId = "run-continuation-reentrancy";
  const agentId = "agent-continuation-reentrancy";
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (?, 'Continuation reentrancy fixture',
      'Prove a successful retry child can advance after its parent continuation unwinds',
      'guided', 'active', 'verified', '{}', 'operator:test', ?, ?, 'ti_scale')
  `).run(missionId, NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-continuation-reentrancy', ?, 'lab.internal', 'domain',
      'allowed', 'lab.internal', ?)
  `).run(missionId, NOW);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (?, 'recon-specialist', 'Recon specialist', 'available',
      'test-1', ?, ?)
  `).run(agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version,
      control_plane
    ) VALUES (?, ?, 'guided', 'planning', 0, 'Create one represented step',
      '{"wallClockMs":60000,"toolCalls":4,"providerTurns":0,"retries":1,"replans":0,"concurrency":1}',
      '{}', ?, ?, 1, 'ti_scale')
  `).run(runId, missionId, NOW, NOW);
  return { missionId, runId, agentId };
}

const evaluator: MissionOutcomeEvaluatorPort = {
  async evaluate() {
    return {
      success: true,
      summary: "The recovered represented step completed.",
      criteria: [],
    };
  },
};

function planner(agentId: string): MissionPlannerPort {
  return {
    async plan() {
      return {
        strategySummary: "Run one bounded represented service check",
        rationaleSummary: "The exact retry lineage remains durable and reviewable",
        steps: [{
          phase: "Reconnaissance",
          title: "Inspect the approved service",
          objective: "Confirm one bounded response",
          explanation: "The specialist performs one represented read-only check.",
          rationale: "A bounded check establishes current service behavior.",
          successCriteria: ["One bounded response is retained"],
          dependencyOrdinals: [],
          assignedAgentId: agentId,
          riskClass: "low",
          reversibility: "Read-only and immediately reversible",
          action: {
            actionType: "service_probe",
            actionClass: "port_service_enumeration",
            target: "lab.internal",
            arguments: { target: "lab.internal", port: 443 },
            intentSummary: "Inspect the approved service once",
            kind: "tool",
            idempotent: true,
            destructive: false,
          },
        }],
      };
    },
  };
}

describe("MissionRuntimeEngine continuation reentrancy", () => {
  test("leaves a successful retry child durable until its active parent handler unwinds", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database);
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner: planner(fixture.agentId),
      outcomeEvaluator: evaluator,
      execution,
      workerId: "continuation-reentrancy-worker",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    const continuationProcessing = (
      runtime as unknown as {
        continuationProcessing: Map<string, Promise<void>>;
      }
    ).continuationProcessing;

    try {
      await runtime.processRunNow(fixture.runId);
      const decision = database.prepare(`
        SELECT id FROM guided_decisions
        WHERE run_id = ? AND status = 'pending'
      `).get(fixture.runId) as { id: string };
      const retryChild = await runtime.approveGuidedDecision(
        decision.id,
        "operator:test",
        "Run this exact represented read-only step",
      );
      expect(execution.dispatched).toHaveLength(1);

      database.prepare(`
        INSERT INTO actions (
          id, mission_id, run_id, step_id, assignment_id, action_type,
          action_class, fingerprint, normalized_arguments_json, scoped_target,
          status, intent_summary, result_summary, error_category, retry_count,
          guided_decision_id, context_pack_id, started_at, ended_at, created_at,
          updated_at
        )
        SELECT 'action-continuation-retry-parent', mission_id, run_id, step_id,
          assignment_id, action_type, action_class, fingerprint,
          normalized_arguments_json, scoped_target, 'failed', intent_summary,
          'The first bounded transport attempt failed transiently.',
          'transient_network', 0, guided_decision_id, context_pack_id,
          started_at, ?, ?, ?
        FROM actions WHERE id = ?
      `).run(NOW, NOW, NOW, retryChild.id);
      database.prepare(`
        UPDATE actions
        SET parent_action_id = 'action-continuation-retry-parent'
        WHERE id = ?
      `).run(retryChild.id);
      const diagnosis = new FailureDiagnosisService(database, {
        clock: () => new Date(NOW),
      }).create({
        missionId: fixture.missionId,
        runId: fixture.runId,
        stepId: retryChild.stepId,
        actionId: "action-continuation-retry-parent",
        subjectType: "action",
        subjectId: "action-continuation-retry-parent",
        humanReason:
          "The first represented service check failed because the target connection ended transiently.",
        category: "target_unreachable",
        code: "fixture_transient_network",
        originatingComponent: "command-runtime.reviewed-action-execution",
        failedComponentRef: "service_probe",
        targetSummary:
          "The failed predecessor and its bounded retry used the same represented lab target.",
        policyOrDependency:
          "The persisted retry continuation kept the original target, parameters, action class, and step.",
        retryHistory: [{
          attempt: 1,
          actionId: "action-continuation-retry-parent",
          directive: "retry",
        }],
        progressBeforeFailure: { uncertainty: 1 },
        preservedReferences: [],
        retryable: true,
        automaticRecovery: {
          directive: "retry",
          retryPersisted: true,
        },
        remediation:
          "Use only the persisted bounded retry after its configured backoff.",
        operatorActions: [{
          kind: "retry_bounded",
          label: "Use the bounded retry",
          consequence:
            "Consumes only the persisted retry continuation without changing scope or parameters.",
          requiresConfirmation: false,
        }],
        objectiveImpact:
          "The predecessor did not advance the objective while its exact retry remained pending.",
        terminal: false,
        actor: {
          id: "continuation-reentrancy-worker",
          type: "worker",
        },
      });

      // Model the direct result callback that occurs while the same run's
      // autonomous_retry_to_dispatch parent continuation is still active.
      continuationProcessing.set(fixture.runId, new Promise<void>(() => {}));
      let timeout: ReturnType<typeof setTimeout> | undefined;
      const receipt = await Promise.race([
        runtime.acceptExecutionResult({
          actionId: retryChild.id,
          runId: fixture.runId,
          actionFingerprint: retryChild.fingerprint,
          success: true,
          summary: "The unchanged bounded retry returned an attributable response.",
          progress: { uncertainty: 0.25 },
        }),
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(
            () => reject(new Error("Successful retry child self-awaited its active parent continuation")),
            250,
          );
        }),
      ]);
      if (timeout) clearTimeout(timeout);

      expect(receipt.accepted).toBe(true);
      expect(database.prepare(`
        SELECT status FROM runtime_continuations
        WHERE run_id = ? AND kind = 'action_result_to_advance'
          AND source_id = ?
      `).get(fixture.runId, retryChild.id)).toEqual({ status: "pending" });
      expect(database.prepare(`
        SELECT status FROM plan_steps WHERE id = ?
      `).get(retryChild.stepId)).toEqual({ status: "running" });
      expect(database.prepare(`
        SELECT state, resolved_at FROM failure_diagnoses WHERE id = ?
      `).get(diagnosis.id)).toEqual({
        state: "active",
        resolved_at: null,
      });

      continuationProcessing.delete(fixture.runId);
      expect(await runtime.replayContinuations(
        fixture.runId,
        ["action_result_to_advance"],
      )).toBe(1);
      expect(database.prepare(`
        SELECT status FROM plan_steps WHERE id = ?
      `).get(retryChild.stepId)).toEqual({ status: "completed" });
      expect(database.prepare(`
        SELECT status FROM runtime_continuations
        WHERE run_id = ? AND kind = 'action_result_to_advance'
          AND source_id = ?
      `).get(fixture.runId, retryChild.id)).toEqual({ status: "completed" });
      expect(database.prepare(`
        SELECT state, resolved_at FROM failure_diagnoses WHERE id = ?
      `).get(diagnosis.id)).toEqual({
        state: "resolved",
        resolved_at: NOW,
      });
      expect(database.prepare(`
        SELECT actor_type, actor_id,
          json_extract(details_json, '$.resolutionMode') AS resolution_mode,
          json_extract(details_json, '$.predecessorActionId') AS predecessor_id,
          json_extract(details_json, '$.successfulActionId') AS successor_id
        FROM audit_records
        WHERE action = 'failure_diagnosis.resolved' AND resource_id = ?
      `).get(diagnosis.id)).toEqual({
        actor_type: "worker",
        actor_id: "continuation-reentrancy-worker",
        resolution_mode: "automatic_bounded_retry",
        predecessor_id: "action-continuation-retry-parent",
        successor_id: retryChild.id,
      });
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM events
        WHERE run_id = ?
          AND event_type = 'failure_diagnosis.automatic_retry_resolved'
          AND json_extract(payload_json, '$.successfulActionId') = ?
      `).get(fixture.runId, retryChild.id)).toEqual({ count: 1 });

      expect(await runtime.replayContinuations(
        fixture.runId,
        ["action_result_to_advance"],
      )).toBe(0);
      expect(database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'failure_diagnosis.resolved' AND resource_id = ?
      `).get(diagnosis.id)).toEqual({ count: 1 });
    } finally {
      continuationProcessing.delete(fixture.runId);
      await runtime.stop();
    }
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import type { DurableAction } from "../../orchestration";
import { MemoryRepository } from "../../memory";
import {
  CommandRuntimeError,
  createMissionRuntime,
  type MissionOutcomeEvaluatorPort,
  type MissionPlannerPort,
  type ResultAwareExecutionPort,
} from "..";

const NOW = "2026-07-23T01:00:00.000Z";
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

class CapturingExecution implements ResultAwareExecutionPort {
  readonly dispatched: DurableAction[] = [];
  async dispatch(action: DurableAction, _signal: AbortSignal): Promise<void> {
    this.dispatched.push(action);
  }
  async resume(_action: DurableAction, _signal: AbortSignal): Promise<void> {}
  async cancelRun(_runId: string, _reason: string): Promise<void> {}
}

function seed(database: SqliteDatabase, suffix: string) {
  const missionId = `mission-agent-tool-${suffix}`;
  const runId = `run-agent-tool-${suffix}`;
  const agentId = `agent-recon-${suffix}`;
  database.prepare(`
    INSERT INTO missions (
      id, engagement_id, name, objective, journey, status, authorization_status,
      memory_policy_json,
      created_by, created_at, updated_at, control_plane
    ) VALUES (
      ?, ?, 'Agent tool memory mission', 'Inspect one approved local service',
      'guided', 'active', 'verified', '{}',
      'operator:test', ?, ?, 'ti_scale'
    )
  `).run(missionId, `engagement-agent-tool-${suffix}`, NOW, NOW);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES (?, ?, 'lab.internal', 'domain', 'allowed', 'lab.internal', ?)
  `).run(`target-agent-tool-${suffix}`, missionId, NOW);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (?, 'recon-specialist', 'Recon specialist', 'available', 'test-1', ?, ?)
  `).run(agentId, NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version, control_plane
    ) VALUES (
      ?, ?, 'guided', 'planning', 0, 'Create one represented step',
      '{"wallClockMs":60000,"toolCalls":10,"providerTurns":10,"retries":1,"replans":1,"concurrency":1}',
      '{}', ?, ?, 1, 'ti_scale'
    )
  `).run(runId, missionId, NOW, NOW);
  return {
    missionId,
    runId,
    agentId,
    engagementId: `engagement-agent-tool-${suffix}`,
  };
}

function planner(agentId: string): MissionPlannerPort {
  return {
    async plan() {
      return {
        strategySummary: "Inspect one bounded approved service",
        rationaleSummary: "One exact read-only service probe is sufficient",
        steps: [{
          phase: "Reconnaissance",
          title: "Inspect approved HTTPS service",
          objective: "Confirm whether the approved service responds",
          explanation: "The represented specialist performs one local read-only check.",
          rationale: "The result determines whether more assessment is useful.",
          successCriteria: ["One bounded response is recorded"],
          dependencyOrdinals: [],
          assignedAgentId: agentId,
          riskClass: "low" as const,
          reversibility: "Read-only",
          action: {
            actionType: "service_probe",
            actionClass: "port_service_enumeration",
            target: "lab.internal",
            arguments: { target: "lab.internal", port: 443, timeoutMs: 2_000 },
            intentSummary: "Inspect the approved HTTPS service once",
            kind: "tool" as const,
            idempotent: true,
            destructive: false,
          },
        }],
      };
    },
  };
}

const evaluator: MissionOutcomeEvaluatorPort = {
  async evaluate() {
    throw new Error("This dispatch-boundary test does not complete the action");
  },
};

function createTypedMemory(input: {
  readonly database: SqliteDatabase;
  readonly missionId: string;
  readonly engagementId: string;
  readonly suffix: string;
  readonly hook: "assignment_acceptance" | "tool_selection";
  readonly verdict: "compatible" | "incompatible" | "missing_dependency";
  readonly agentId: string;
}) {
  const nodeId = `memory-agent-tool-${input.suffix}`;
  const memory = new MemoryRepository(input.database, {
    clock: () => new Date(NOW),
    createId: () => nodeId,
  });
  const node = memory.createNode({
    nodeType: input.hook === "assignment_acceptance" ? "agent" : "tool",
    title: input.hook === "assignment_acceptance"
      ? `${input.agentId} service probe capability compatibility`
      : "service_probe port_service_enumeration prerequisite compatibility",
    summary: input.verdict === "missing_dependency"
      ? "Typed local capability metadata records a missing represented dependency."
      : "Typed local capability metadata attests the represented selection.",
    scope: { kind: "engagement", engagementId: input.engagementId },
    sensitivity: "private",
    confidence: 1,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "operator_statement",
      explanation: "Operator reviewed local capability metadata.",
      sources: [{
        sourceType: "mission",
        sourceId: input.missionId,
        acquiredAt: NOW,
      }],
    },
    authorType: "operator",
    authorId: "operator:test",
    retentionPolicy: {
      allowGuided: true,
      journeys: ["guided"],
      agentToolDecision: {
        schemaVersion: "1",
        match: {
          hooks: [input.hook],
          ...(input.hook === "assignment_acceptance" ? { agentIds: [input.agentId] } : {}),
          actionTypes: ["service_probe"],
          actionClasses: ["port_service_enumeration"],
        },
        effect: {
          verdict: input.verdict,
          reasonCode: `reviewed.${input.verdict}`,
        },
      },
    },
  });
  const connectionId = `vault-agent-tool-${input.suffix}`;
  input.database.prepare(`
    INSERT INTO vault_connections (
      id, vault_path, display_name, status, sync_scope_json,
      permission_granted_at, last_sync_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'connected', '{}', ?, ?, ?, ?)
  `).run(
    connectionId,
    `/tmp/agent-tool-runtime-${input.suffix}`,
    `Agent tool runtime ${input.suffix}`,
    NOW,
    NOW,
    NOW,
    NOW,
  );
  input.database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id,
      reason, details_json, record_hash, occurred_at
    ) VALUES (?, 'operator', 'operator:test', 'vault.health.verified',
      'vault_connection', ?, 'Disposable Vault round trip passed',
      '{"checks":{"write":true,"read":true,"rename":true,"delete":true}}',
      ?, ?)
  `).run(
    `audit-vault-agent-tool-${input.suffix}`,
    connectionId,
    "f".repeat(64),
    NOW,
  );
  input.database.prepare(`
    INSERT INTO vault_sync_state (
      id, connection_id, node_id, relative_path, database_version,
      vault_content_hash, database_content_hash, status,
      last_scanned_at, last_synced_at
    ) VALUES (?, ?, ?, ?, 1, ?, ?, 'synced', ?, ?)
  `).run(
    `vault-state-agent-tool-${input.suffix}`,
    connectionId,
    node.id,
    `40 Tools and Capabilities/${input.suffix}.md`,
    "a".repeat(64),
    "a".repeat(64),
    NOW,
    NOW,
  );
  return node;
}

function pendingDecision(database: SqliteDatabase, runId: string): string {
  const row = database.prepare(`
    SELECT id FROM guided_decisions
    WHERE run_id = ? AND status = 'pending'
    ORDER BY created_at, id LIMIT 1
  `).get(runId) as { id: string } | undefined;
  if (!row) throw new Error("Expected one pending Guided decision");
  return row.id;
}

describe("MissionRuntimeEngine agent/tool memory boundary", () => {
  test("uses synchronized compatible assignment memory and dispatches the exact unchanged represented action", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database, "compatible");
    const node = createTypedMemory({
      database,
      ...fixture,
      suffix: "compatible",
      hook: "assignment_acceptance",
      verdict: "compatible",
    });
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner: planner(fixture.agentId),
      outcomeEvaluator: evaluator,
      execution,
      workerId: "agent-tool-runtime-compatible",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      const action = await runtime.approveGuidedDecision(
        pendingDecision(database, fixture.runId),
        "operator:test",
        "Run this exact represented read-only action",
      );
      expect(execution.dispatched).toHaveLength(1);
      expect(action.target).toBe("lab.internal");
      expect(action.actionType).toBe("service_probe");
      expect(action.actionClass).toBe("port_service_enumeration");
      expect(action.arguments).toEqual({
        target: "lab.internal",
        port: 443,
        timeoutMs: 2_000,
      });
      const receipt = database.prepare(`
        SELECT id, details_json FROM audit_records
        WHERE action = 'brain.agent_tool_memory.decision'
          AND json_extract(details_json, '$.hook') = 'assignment_acceptance'
          AND json_extract(details_json, '$.decision') = 'attest_compatible'
        ORDER BY rowid DESC LIMIT 1
      `).get() as { id: string; details_json: string };
      const details = JSON.parse(receipt.details_json) as Record<string, unknown>;
      expect(details.appliedNodeIds).toEqual([node.id]);
      expect(details.representationUnchanged).toBe(true);
      expect(details.scopeExpanded).toBe(false);
      expect(details.toolChanged).toBe(false);
      expect(details.argumentsChanged).toBe(false);
      expect(details.providerExposureCreated).toBe(false);
      expect(database.prepare(`
        SELECT used FROM memory_context_items
        WHERE node_id = ? AND influence_summary LIKE 'Typed synchronized Vault memory%'
        ORDER BY rowid DESC LIMIT 1
      `).get(node.id)).toEqual({ used: 1 });
    } finally {
      await runtime.stop();
    }
  });

  test("vetoes a represented tool with a known missing dependency before dispatch", async () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const fixture = seed(database, "missing");
    const node = createTypedMemory({
      database,
      ...fixture,
      suffix: "missing",
      hook: "tool_selection",
      verdict: "missing_dependency",
    });
    const execution = new CapturingExecution();
    const runtime = createMissionRuntime({
      database,
      planner: planner(fixture.agentId),
      outcomeEvaluator: evaluator,
      execution,
      workerId: "agent-tool-runtime-missing",
      leaseTtlMs: 2_000,
      now: () => new Date(NOW),
    });
    try {
      await runtime.processRunNow(fixture.runId);
      let failure: unknown;
      try {
        await runtime.approveGuidedDecision(
          pendingDecision(database, fixture.runId),
          "operator:test",
          "Run this exact represented read-only action",
        );
      } catch (error) {
        failure = error;
      }
      expect(failure).toBeInstanceOf(CommandRuntimeError);
      expect((failure as CommandRuntimeError).code).toBe("agent_memory_dependency_missing");
      expect((failure as CommandRuntimeError).options.details).toEqual(expect.objectContaining({
        appliedNodeIds: [node.id],
        representationUnchanged: true,
        targetContacted: false,
      }));
      expect(execution.dispatched).toEqual([]);
      expect(database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?")
        .get(fixture.runId)).toEqual({ count: 0 });
      const receipt = database.prepare(`
        SELECT details_json FROM audit_records
        WHERE action = 'brain.agent_tool_memory.decision'
          AND json_extract(details_json, '$.hook') = 'tool_selection'
        ORDER BY rowid DESC LIMIT 1
      `).get() as { details_json: string };
      expect(JSON.parse(receipt.details_json)).toEqual(expect.objectContaining({
        decision: "veto_missing_dependency",
        appliedNodeIds: [node.id],
        representationUnchanged: true,
        scopeExpanded: false,
        toolChanged: false,
        actionClassChanged: false,
        argumentsChanged: false,
        providerExposureCreated: false,
      }));
    } finally {
      await runtime.stop();
    }
  });
});

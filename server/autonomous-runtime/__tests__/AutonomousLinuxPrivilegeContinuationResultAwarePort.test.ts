import { createHash } from "node:crypto";
import { afterEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import { digestCanonicalJson } from "../../mcp";
import { ActionRepository } from "../../orchestration";
import {
  AutonomousLinuxPrivilegeContinuationResultAwarePort,
  autonomousLinuxPrivilegeContinuationToolCallId,
} from "../AutonomousLinuxPrivilegeContinuationResultAwarePort";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS,
  AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
  createAutonomousLinuxPrivilegeActionArguments,
} from "../CandidateLinuxPrivilegeContinuation";
import {
  AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION,
  type CandidateLinuxPrivilegeContinuationRuntime,
  type CandidateLinuxPrivilegeRuntimeResult,
} from "../CandidateLinuxPrivilegeContinuationRuntime";

const NOW = "2026-07-23T22:00:00.000Z";
const RAW_ROOT_FLAG = "e0bd755c351647c7867324205b5d2de8";
const ROOT_FLAG_SHA256 = createHash("sha256")
  .update(RAW_ROOT_FLAG, "utf8").digest("hex");
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function hash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function databaseWithAction(): Readonly<{
  database: SqliteDatabase;
  action: ReturnType<ActionRepository["create"]>;
}> {
  const database = createDatabaseConnection({
    filename: ":memory:",
    verifyIntegrity: false,
  });
  databases.push(database);
  migrateDatabase(database);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      memory_policy_json, created_by, created_at, updated_at, control_plane
    ) VALUES (
      'mission-root-delivery', 'Root delivery proof',
      'Verify durable replay without repeating privilege work.',
      'autonomous', 'active', 'verified', '{}',
      'operator:test', ?, ?, 'ti_scale'
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, progress, status_reason,
      budget_json, budget_usage_json, created_at, updated_at, version,
      control_plane
    ) VALUES (
      'run-root-delivery', 'mission-root-delivery', 'autonomous',
      'running', 0.75, 'Privilege continuation is running.',
      '{}', '{}', ?, ?, 1, 'ti_scale'
    )
  `).run(NOW, NOW);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, content_hash, content_hash_version,
      created_by, created_at, activated_at
    ) VALUES (
      'plan-root-delivery', 'run-root-delivery', 1, 'active',
      'Candidate-bound root delivery proof',
      'Exercise only the durable result boundary.',
      ?, ?, 1, 'runtime-planner', ?, ?
    )
  `).run("1".repeat(64), "2".repeat(64), NOW, NOW);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, started_at, created_at, updated_at
    ) VALUES (
      'step-root-delivery', 'plan-root-delivery', 'run-root-delivery',
      0, 'privilege_escalation', 'Verify root identity',
      'Exercise durable result delivery.', 'running',
      '[]', '[]', 'privilege_escalation', 'critical',
      NULL, ?, ?, ?
    )
  `).run(NOW, NOW, NOW);
  const argumentsValue = createAutonomousLinuxPrivilegeActionArguments({
    actionType: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
    postExploitSpecId: "post-exploit-root-delivery",
    sessionArtifactId: "session-root-delivery",
  });
  const action = new ActionRepository(database).create({
    intent: {
      missionId: "mission-root-delivery",
      runId: "run-root-delivery",
      stepId: "step-root-delivery",
      planVersion: 1,
      actionType: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
      actionClass: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_CLASS,
      arguments: argumentsValue,
      target: "127.0.0.1",
      intentSummary:
        "Attempt the fixed candidate privilege path and independently verify root.",
      kind: "tool",
      idempotent: false,
      destructive: false,
    },
    fingerprint: hash(JSON.stringify(argumentsValue)),
    now: NOW,
  });
  return Object.freeze({ database, action });
}

function runtimeResult(
  actionId: string,
): CandidateLinuxPrivilegeRuntimeResult {
  const unsigned = Object.freeze({
    schemaVersion: AUTONOMOUS_LINUX_PRIVILEGE_RUNTIME_RESULT_SCHEMA_VERSION,
    actionId,
    actionType: AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
    sessionArtifactId: "session-root-delivery",
    contextPackId: "context-root-delivery",
    evidenceIds: Object.freeze(["evidence-root-delivery"]),
    privilegeReceiptSha256: "3".repeat(64),
    rootIdentityObservationSha256: "4".repeat(64),
    cleanupCompleted: false,
    summary:
      "A separate identity observer verified the root principal with UID and GID zero.",
  });
  return Object.freeze({
    ...unsigned,
    resultSha256: digestCanonicalJson(
      unsigned,
      { maxBytes: 64 * 1_024, maxDepth: 12 },
    ).sha256,
  });
}

function fakeRuntime(options?: Readonly<{
  waitForCancel?: boolean;
}>): Readonly<{
  runtime: CandidateLinuxPrivilegeContinuationRuntime;
  counts: { execute: number; cleanup: number };
}> {
  const counts = { execute: 0, cleanup: 0 };
  const runtime = {
    execute: async (action: { readonly id: string }, signal: AbortSignal) => {
      counts.execute += 1;
      if (options?.waitForCancel) {
        await new Promise<never>((_resolve, reject) => {
          const cancel = () => reject(Object.assign(
            new Error("Candidate privilege operation was cancelled."),
            { code: "autonomous_linux_privilege_cancelled" },
          ));
          if (signal.aborted) cancel();
          else signal.addEventListener("abort", cancel, { once: true });
        });
      }
      return runtimeResult(action.id);
    },
    cleanupRun: async () => {
      counts.cleanup += 1;
      return 1;
    },
  } as unknown as CandidateLinuxPrivilegeContinuationRuntime;
  return Object.freeze({ runtime, counts });
}

describe("durable candidate Linux privilege result delivery", () => {
  test("restart terminalizes an orphaned running invocation without repeating the target operation", async () => {
    const seeded = databaseWithAction();
    const fake = fakeRuntime();
    const invocationId = autonomousLinuxPrivilegeContinuationToolCallId(
      seeded.action.id,
    );
    seeded.database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, normalized_arguments_json,
        status, started_at, created_at
      ) VALUES (?, ?, 'candidate-loopback-linux-session', ?, '{}',
        'running', ?, ?)
    `).run(
      invocationId,
      seeded.action.id,
      AUTONOMOUS_LINUX_PRIVILEGE_ESCALATION_ACTION_TYPE,
      NOW,
      NOW,
    );
    const delivered: Array<{ readonly success: boolean; readonly code?: string }> = [];
    const restarted = new AutonomousLinuxPrivilegeContinuationResultAwarePort({
      database: seeded.database,
      runtime: fake.runtime,
      now: () => new Date(NOW),
    });
    restarted.bindResultSink({
      acceptExecutionResult: async (result) => {
        delivered.push({
          success: result.success,
          ...(result.failure?.code ? { code: result.failure.code } : {}),
        });
        return {
          accepted: true,
          duplicate: false,
          actionId: result.actionId,
          runId: result.runId,
          runState: "recovering",
          nextAction: null,
        };
      },
    });

    expect(await restarted.replayPendingResults()).toBe(1);
    expect(fake.counts.execute).toBe(0);
    expect(delivered).toEqual([{
      success: false,
      code: "autonomous_linux_privilege_restart_review_required",
    }]);
    expect(seeded.database.prepare(`
      SELECT status, error_category FROM tool_calls WHERE id = ?
    `).get(invocationId)).toEqual({
      status: "failed",
      error_category: "worker_lost",
    });
  });

  test("restart replays the terminal result without repeating the privilege operation", async () => {
    const seeded = databaseWithAction();
    const fake = fakeRuntime();
    let failedDelivery = 0;
    const first = new AutonomousLinuxPrivilegeContinuationResultAwarePort({
      database: seeded.database,
      runtime: fake.runtime,
      now: () => new Date(NOW),
    });
    first.bindResultSink({
      acceptExecutionResult: async () => {
        failedDelivery += 1;
        throw new Error("simulated process loss after durable commit");
      },
    });
    await first.dispatch(seeded.action, new AbortController().signal);
    expect(failedDelivery).toBe(1);
    expect(fake.counts.execute).toBe(1);

    let accepted = 0;
    const restarted = new AutonomousLinuxPrivilegeContinuationResultAwarePort({
      database: seeded.database,
      runtime: fake.runtime,
      now: () => new Date(NOW),
    });
    restarted.bindResultSink({
      acceptExecutionResult: async (result) => {
        accepted += 1;
        return {
          accepted: result.success,
          duplicate: false,
          actionId: result.actionId,
          runId: result.runId,
          runState: "running",
          nextAction: null,
        };
      },
    });
    expect(await restarted.replayPendingResults()).toBe(1);
    expect(accepted).toBe(1);
    expect(fake.counts.execute).toBe(1);
    await restarted.resume(seeded.action, new AbortController().signal);
    expect(fake.counts.execute).toBe(1);

    const stored = seeded.database.prepare(`
      SELECT redacted_payload_json FROM tool_calls WHERE id = ?
    `).get(autonomousLinuxPrivilegeContinuationToolCallId(
      seeded.action.id,
    )) as { readonly redacted_payload_json: string };
    expect(stored.redacted_payload_json).not.toContain(RAW_ROOT_FLAG);
    expect(stored.redacted_payload_json).not.toContain(ROOT_FLAG_SHA256);
    expect(JSON.parse(stored.redacted_payload_json)).toMatchObject({
      resultAccepted: true,
      deliveryAttemptCount: 2,
    });
  });

  test("cancellation aborts the in-flight operation and invokes bounded run cleanup", async () => {
    const seeded = databaseWithAction();
    const fake = fakeRuntime({ waitForCancel: true });
    const port = new AutonomousLinuxPrivilegeContinuationResultAwarePort({
      database: seeded.database,
      runtime: fake.runtime,
      now: () => new Date(NOW),
    });
    port.bindResultSink({
      acceptExecutionResult: async (result) => ({
        accepted: result.success,
        duplicate: false,
        actionId: result.actionId,
        runId: result.runId,
        runState: "running",
        nextAction: null,
      }),
    });
    const dispatch = port.dispatch(
      seeded.action,
      new AbortController().signal,
    );
    while (fake.counts.execute === 0) await Bun.sleep(1);
    await port.cancelRun(seeded.action.runId, "operator cancelled fixture");
    await dispatch;
    expect(fake.counts.execute).toBe(1);
    expect(fake.counts.cleanup).toBe(1);
    expect(seeded.database.prepare(`
      SELECT status FROM tool_calls WHERE id = ?
    `).get(autonomousLinuxPrivilegeContinuationToolCallId(
      seeded.action.id,
    ))).toEqual({ status: "cancelled" });
  });
});

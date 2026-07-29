import { afterEach, describe, expect, test } from "bun:test";
import { createServer as createTcpServer } from "node:net";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ControlPlaneLeaseService } from "../../control-plane";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  ActionRepository,
  DurableRunCoordinator,
  ExecutionBoundaryError,
  type DurableAction,
  type DurableActionIntent,
} from "../../orchestration";
import { fingerprintAction } from "../../supervisor";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import {
  DirectProcessLocalToolInvocationAdapter,
  LocalToolCapabilityManifest,
  OperationalTruthLocalToolOutputRecorder,
  ReviewedLocalToolExecutionPort,
  type LocalProcessToolResult,
} from "../index";

const NOW = new Date("2026-07-19T12:00:00.000Z");
const TOOL_ID = "kali:ping-host-liveness";
const TARGET = "127.0.0.1";
const MANIFEST_PATH = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const BWRAP_SHA256 = "042763bc80c8a895a497e6f801af003d585ea5588a580f7a4349d9ab2aa22980";

const databases: SqliteDatabase[] = [];
const roots: string[] = [];

function closeTrackedDatabase(database: SqliteDatabase): void {
  const index = databases.indexOf(database);
  if (index >= 0) databases.splice(index, 1);
  database.close();
}

async function waitForAssertion(assertion: () => void, attempts = 100): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      assertion();
      return;
    } catch (error) {
      lastError = error;
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
  }
  throw lastError;
}

afterEach(async () => {
  for (const database of databases.splice(0)) database.close();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function seededBoundary(input: {
  journey?: "guided" | "autonomous";
  evidenceExpectations?: readonly string[];
  capabilityActionClassIds?: readonly string[];
  failAfterOutputProjection?: boolean;
  persistDatabase?: boolean;
  crashAfterTerminalCommit?: (context: Readonly<{
    invocationId: string;
    actionId: string;
    runId: string;
  }>) => void;
} = {}) {
  const journey = input.journey ?? "guided";
  const root = await mkdtemp(join(tmpdir(), "ti-scale-local-port-"));
  roots.push(root);
  await mkdir(join(root, "mission"));
  const databaseFilename = input.persistDatabase ? join(root, "ti-scale.sqlite") : ":memory:";
  const database = createDatabaseConnection({ filename: databaseFilename });
  databases.push(database);
  migrateDatabase(database);
  const now = NOW.toISOString();
  const fingerprint = "f".repeat(64);
  const envelope = {
    schemaVersion: "ti-scale.reviewed-local-tool-action.v1",
    executionBinding: "reviewed_local_process",
    toolId: TOOL_ID,
    parameters: { workspace: "/engagements/mission", target: TARGET },
  } as const;

  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at, control_plane
    ) VALUES ('mission-local', 'Local mission', 'Verify one loopback action', ?,
      'active', 'verified', 'operator:test', ?, ?, 'ti_scale')
  `).run(journey, now, now);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-local', 'mission-local', ?, 'host', 'allowed', ?, ?)
  `).run(TARGET, TARGET, now);
  if (journey === "guided") {
    database.prepare(`
      INSERT INTO mission_constraints (
        id, mission_id, constraint_type, value_json, source, created_at
      ) VALUES ('constraint-guided-local', 'mission-local', 'guided_collaboration', ?, 'operator', ?)
    `).run(JSON.stringify({
      explanationDepth: "balanced",
      executionPreference: "single_step_agent",
      evidenceExpectations: input.evidenceExpectations ?? [],
    }), now);
  }
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, tool_policy_json, version, created_at, updated_at
    ) VALUES ('ReconScout', 'reconnaissance', 'ReconScout', 'available', ?, 'test-1', ?, ?)
  `).run(JSON.stringify({
    allowedTools: [TOOL_ID], deniedTools: [], approvalRequiredTools: [],
  }), now, now);
  database.prepare(`
    INSERT INTO agent_capabilities (
      agent_id, capability, source, enabled, metadata_json
    )
    VALUES ('ReconScout', ?, 'reviewed-local-manifest', 1, ?)
  `).run(TOOL_ID, JSON.stringify({
    toolId: TOOL_ID,
    actionClassIds: input.capabilityActionClassIds ?? ["active_host_discovery"],
    executionBinding: "reviewed_local_process",
  }));
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id,
      current_owner_id, progress, status_reason, next_action_summary,
      budget_json, budget_usage_json, started_at, created_at, updated_at,
      version, control_plane
    ) VALUES ('run-local', 'mission-local', ?, 'running', 'plan-local', 'step-local',
      'ReconScout', 0.1, 'Running one exact local action', 'Interpret the bounded result',
      '{}', '{}', ?, ?, ?, 1, 'ti_scale')
  `).run(journey, now, now, now);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      created_by, created_at, activated_at
    ) VALUES ('plan-local', 'run-local', 1, 'active',
      'Run one represented local action', ?, 'planner:test', ?, ?)
  `).run("a".repeat(64), now, now);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      assigned_agent_id, created_at, updated_at
    ) VALUES ('step-local', 'plan-local', 'run-local', 0, 'reconnaissance',
      'Loopback liveness', 'Verify one reviewed local result', 'running',
      'ReconScout', ?, ?)
  `).run(now, now);
  database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
      last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at
    ) VALUES ('assignment-local', 'run-local', 'step-local', 'ReconScout',
      'active', 'worker:test', ?, ?, '2026-07-19T12:05:00.000Z', ?, ?, ?)
  `).run(now, now, now, now, now);
  if (journey === "guided") {
    database.prepare(`
      INSERT INTO guided_decisions (
        id, mission_id, run_id, step_id, requested_action_fingerprint,
        requested_parameters_json, rationale, risk_class, reversibility,
        status, decision_actor, decision_reason, decided_at, expires_at, created_at
      ) VALUES ('decision-local', 'mission-local', 'run-local', 'step-local', ?, ?,
        'Run this exact represented loopback check', 'low', 'Read-only and bounded',
        'approved', 'operator:test', 'Approved one exact action', ?,
        '2026-07-19T13:00:00.000Z', ?)
    `).run(fingerprint, JSON.stringify(envelope.parameters), now, now);
  }
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, assignment_id, action_type,
      action_class, fingerprint, normalized_arguments_json, scoped_target,
      status, intent_summary, guided_decision_id, contract_id, started_at, created_at, updated_at
    ) VALUES ('action-local', 'mission-local', 'run-local', 'step-local',
      'assignment-local', ?, 'active_host_discovery', ?, ?, ?, 'running',
      'Run one exact reviewed local action', ?, NULL, ?, ?, ?)
  `).run(
    TOOL_ID,
    fingerprint,
    JSON.stringify({
      input: envelope,
      orchestration: {
        target: TARGET, kind: "tool", idempotent: true, destructive: false, planVersion: 1,
      },
    }),
    TARGET,
    journey === "guided" ? "decision-local" : null,
    now,
    now,
    now,
  );

  const leaseService = new ControlPlaneLeaseService(database);
  const leaseToken = "local-process-port-test-token";
  leaseService.acquire({
    runId: "run-local",
    controlPlane: "ti_scale",
    leaseOwner: "runtime:test",
    leaseToken,
    ttlMs: 5 * 60_000,
    now: NOW,
  });
  const manifest = new LocalToolCapabilityManifest(
    JSON.parse(await readFile(MANIFEST_PATH, "utf8")),
  );
  const resolver = new EngagementWorkspaceResolver([{
    logicalRoot: "/engagements",
    runtimeRoot: root,
  }]);
  const adapter = new DirectProcessLocalToolInvocationAdapter({
    manifest,
    workspaceResolver: resolver,
    sandboxExecutable: { path: "/usr/bin/bwrap", expectedSha256: BWRAP_SHA256 },
  });
  const action = new ActionRepository(database).get("action-local");
  const outputRecorder = new OperationalTruthLocalToolOutputRecorder(database, manifest);
  const executionOutputRecorder = input.failAfterOutputProjection
    ? {
        record(result: LocalProcessToolResult) {
          outputRecorder.record(result);
          throw new Error("simulated crash before the tool-call terminal receipt");
        },
      }
    : outputRecorder;
  const port = new ReviewedLocalToolExecutionPort({
    database,
    executionJourney: "guided",
    manifest,
    adapter,
    workspaceResolver: resolver,
    outputRecorder: executionOutputRecorder,
    assertControlPlaneAuthority: (runId) => leaseService.assertMutationAuthority({
      runId,
      controlPlane: "ti_scale",
      leaseOwner: "runtime:test",
      leaseToken,
      now: NOW,
    }),
    now: () => NOW,
    ...(input.crashAfterTerminalCommit
      ? { crashAfterTerminalCommit: input.crashAfterTerminalCommit }
      : {}),
  });
  return {
    database,
    databaseFilename,
    port,
    action,
    outputRecorder,
    manifest,
    resolver,
    leaseToken,
  };
}

describe("ReviewedLocalToolExecutionPort", () => {
  test("executes one exact Guided decision and persists terminal operational truth before runtime evaluation", async () => {
    const { database, port, action, outputRecorder } = await seededBoundary();
    let resolveResult!: () => void;
    const resultAccepted = new Promise<void>((resolve) => { resolveResult = resolve; });
    port.bindResultSink({
      async acceptExecutionResult(result) {
        expect(result).toMatchObject({ actionId: action.id, runId: action.runId, success: true });
        const persistedToolCall = database.prepare(`
          SELECT status, provider, mcp_server_id, normalized_arguments_json FROM tool_calls
        `).get() as {
          status: string;
          provider: string;
          mcp_server_id: string | null;
          normalized_arguments_json: string;
        };
        expect(persistedToolCall).toMatchObject({
          status: "succeeded",
          provider: "reviewed-local-process",
          mcp_server_id: null,
        });
        expect(JSON.parse(persistedToolCall.normalized_arguments_json)).toMatchObject({
          schemaVersion: "ti-scale.local-process-tool-invocation.v1",
          target: TARGET,
        });
        resolveResult();
        return {
          accepted: true,
          duplicate: false,
          actionId: action.id,
          runId: action.runId,
          runState: "running",
          nextAction: null,
        };
      },
    });
    await port.dispatch(action, new AbortController().signal);
    await resultAccepted;
    expect(database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get())
      .toEqual({ count: 1 });
    const observation = database.prepare(`
      SELECT o.verification_state, o.observation_type, o.normalized_value_json,
        source.parser_id, source.parser_version, log.action_id, log.tool_call_id
      FROM observations o
      JOIN observation_log_sources source ON source.observation_id = o.id
      JOIN engagement_log_records log ON log.id = source.log_record_id
    `).get() as Record<string, string>;
    expect(observation).toMatchObject({
      verification_state: "unverified",
      observation_type: "host_liveness",
      parser_id: "ti-scale.reviewed-local-tool-normalizer",
      parser_version: "1.1.0",
      action_id: "action-local",
      tool_call_id: expect.stringContaining("local_tool_"),
    });
    expect(JSON.parse(observation.normalized_value_json)).toMatchObject({
      missionId: "mission-local",
      runId: "run-local",
      stepId: "step-local",
      actionId: "action-local",
      target: TARGET,
      missionTargetId: "target-local",
      result: { host: TARGET, responded: true, received: 2 },
      provenance: { actionId: "action-local" },
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get())
      .toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get())
      .toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM artifacts").get())
      .toEqual({ count: 0 });

    const retained = database.prepare(`
      SELECT l.id AS log_id, l.technical_payload_json, tc.id AS invocation_id
      FROM engagement_log_records l
      JOIN tool_calls tc ON tc.id = l.tool_call_id
    `).get() as {
      readonly log_id: string;
      readonly technical_payload_json: string;
      readonly invocation_id: string;
    };
    const retainedPayload = JSON.parse(retained.technical_payload_json) as {
      readonly outputSha256: string;
    };
    const replay: LocalProcessToolResult = {
      invocationId: retained.invocation_id,
      action,
      toolId: TOOL_ID,
      startedAt: NOW.toISOString(),
      endedAt: NOW.toISOString(),
      wallClockMs: 0,
      exitCode: 0,
      signal: null,
      termination: "exited",
      spawnErrorCode: null,
      stdout: "a replay must not be stored",
      stderr: "",
      observedOutputBytes: 27,
      retainedOutputBytes: 27,
      outputSha256: retainedPayload.outputSha256,
      outputTruncated: false,
      executable: {
        sourcePath: "/usr/bin/ping",
        sourceSha256: "a".repeat(64),
        snapshotSha256: "a".repeat(64),
        sandboxPath: "/run/ti-scale/tool",
      },
      sandbox: {
        executablePath: "/usr/bin/bwrap",
        executableSha256: "b".repeat(64),
        shell: false,
        environmentSha256: "c".repeat(64),
      },
    };
    const replayed = await outputRecorder.record(replay);
    expect(replayed.logRecordId).toBe(retained.log_id);
    expect(database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get())
      .toEqual({ count: 1 });
    port.close();
  }, 20_000);

  test("reopens the durable database and redelivers an unacknowledged terminal result after the commit crash window", async () => {
    let resolveCommitted!: (context: Readonly<{
      invocationId: string;
      actionId: string;
      runId: string;
    }>) => void;
    const terminalCommitted = new Promise<Readonly<{
      invocationId: string;
      actionId: string;
      runId: string;
    }>>((resolve) => { resolveCommitted = resolve; });
    const fixture = await seededBoundary({
      persistDatabase: true,
      evidenceExpectations: ["asset_discovery_proof"],
      crashAfterTerminalCommit(context) {
        resolveCommitted(context);
        throw new Error("simulated process crash after terminal commit");
      },
    });
    fixture.port.bindResultSink({
      async acceptExecutionResult() {
        throw new Error("the pre-crash runtime must not receive this result");
      },
    });

    await fixture.port.dispatch(fixture.action, new AbortController().signal);
    const committed = await terminalCommitted;
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(committed).toMatchObject({ actionId: fixture.action.id, runId: fixture.action.runId });
    const beforeRestart = fixture.database.prepare(`
      SELECT status, error_category, output_summary, redacted_payload_json
      FROM tool_calls WHERE id = ?
    `).get(committed.invocationId) as Record<string, string | null>;
    expect(beforeRestart).toMatchObject({
      status: "succeeded",
      error_category: null,
      output_summary: expect.stringContaining("completed"),
    });
    expect(JSON.parse(beforeRestart.redacted_payload_json!)).toMatchObject({
      resultAccepted: false,
      duplicateResult: false,
      deliveryAttemptCount: 0,
      deliveryResult: {
        schemaVersion: "ti-scale.local-tool-result-delivery.v1",
        actionId: fixture.action.id,
        runId: fixture.action.runId,
        actionFingerprint: fixture.action.fingerprint,
        success: true,
      },
    });
    expect(fixture.database.prepare("SELECT status FROM actions WHERE id = 'action-local'").get())
      .toEqual({ status: "running" });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: 1 });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM observations").get())
      .toEqual({ count: 1 });
    expect(fixture.database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get())
      .toEqual({ count: 1 });

    fixture.port.close();
    closeTrackedDatabase(fixture.database);
    const restartedDatabase = createDatabaseConnection({ filename: fixture.databaseFilename });
    databases.push(restartedDatabase);
    const restartedAdapter = new DirectProcessLocalToolInvocationAdapter({
      manifest: fixture.manifest,
      workspaceResolver: fixture.resolver,
      sandboxExecutable: { path: "/usr/bin/bwrap", expectedSha256: BWRAP_SHA256 },
    });
    const restartedLeaseService = new ControlPlaneLeaseService(restartedDatabase);
    const restarted = new ReviewedLocalToolExecutionPort({
      database: restartedDatabase,
      executionJourney: "guided",
      manifest: fixture.manifest,
      adapter: restartedAdapter,
      workspaceResolver: fixture.resolver,
      outputRecorder: new OperationalTruthLocalToolOutputRecorder(restartedDatabase, fixture.manifest),
      assertControlPlaneAuthority: (runId) => restartedLeaseService.assertMutationAuthority({
        runId,
        controlPlane: "ti_scale",
        leaseOwner: "runtime:test",
        leaseToken: fixture.leaseToken,
        now: NOW,
      }),
      now: () => NOW,
    });
    const insertExcludedPendingResult = (
      suffix: string,
      journey: "guided" | "autonomous",
      controlPlane: "legacy" | "ti_scale",
    ) => {
      const missionId = `mission-${suffix}`;
      const runId = `run-${suffix}`;
      const actionId = `action-${suffix}`;
      const invocationId = `local_tool_${suffix}`;
      const fingerprint = suffix.padEnd(64, suffix.at(0) ?? "e").slice(0, 64);
      restartedDatabase.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status,
          created_by, created_at, updated_at, control_plane
        ) VALUES (?, ?, ?, ?, 'active', 'verified', 'test:excluded', ?, ?, ?)
      `).run(missionId, suffix, suffix, journey, NOW.toISOString(), NOW.toISOString(), controlPlane);
      restartedDatabase.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, budget_json, budget_usage_json,
          created_at, updated_at, version, control_plane
        ) VALUES (?, ?, ?, 'running', 0, '{}', '{}', ?, ?, 1, ?)
      `).run(runId, missionId, journey, NOW.toISOString(), NOW.toISOString(), controlPlane);
      restartedDatabase.prepare(`
        INSERT INTO actions (
          id, mission_id, run_id, action_type, action_class, fingerprint,
          normalized_arguments_json, status, intent_summary, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'active_host_discovery', ?, '{}', 'running', ?, ?, ?)
      `).run(actionId, missionId, runId, TOOL_ID, fingerprint, suffix, NOW.toISOString(), NOW.toISOString());
      restartedDatabase.prepare(`
        INSERT INTO tool_calls (
          id, action_id, provider, tool_name, normalized_arguments_json, status,
          output_summary, redacted_payload_json, started_at, ended_at, created_at
        ) VALUES (?, ?, 'reviewed-local-process', ?, '{}', 'succeeded', ?, ?, ?, ?, ?)
      `).run(
        invocationId,
        actionId,
        TOOL_ID,
        suffix,
        JSON.stringify({
          ...JSON.parse(beforeRestart.redacted_payload_json!),
          deliveryResult: {
            ...JSON.parse(beforeRestart.redacted_payload_json!).deliveryResult,
            actionId,
            runId,
            actionFingerprint: fingerprint,
          },
        }),
        NOW.toISOString(),
        NOW.toISOString(),
        NOW.toISOString(),
      );
      return invocationId;
    };
    const autonomousPending = insertExcludedPendingResult("autonomous", "autonomous", "ti_scale");
    const legacyPending = insertExcludedPendingResult("legacy", "guided", "legacy");
    let deliveries = 0;
    restarted.bindResultSink({
      async acceptExecutionResult(result) {
        deliveries += 1;
        expect(result.actionId).toBe(fixture.action.id);
        expect(result.success).toBe(true);
        restartedDatabase.prepare(`
          UPDATE actions SET status = 'succeeded', result_summary = ?, ended_at = ?, updated_at = ?
          WHERE id = ? AND status = 'running'
        `).run(result.summary, NOW.toISOString(), NOW.toISOString(), result.actionId);
        return {
          accepted: true,
          duplicate: false,
          actionId: result.actionId,
          runId: result.runId,
          runState: "running",
          nextAction: null,
        };
      },
    });

    expect(await restarted.replayPendingResults()).toBe(1);
    expect(await restarted.replayPendingResults()).toBe(0);
    expect(deliveries).toBe(1);
    for (const excluded of [legacyPending, autonomousPending]) {
      const payload = JSON.parse((restartedDatabase.prepare(`
        SELECT redacted_payload_json FROM tool_calls WHERE id = ?
      `).get(excluded) as { redacted_payload_json: string }).redacted_payload_json);
      expect(payload).toMatchObject({ resultAccepted: false, deliveryAttemptCount: 0 });
    }
    const afterRestart = restartedDatabase.prepare(`
      SELECT status, error_category, output_summary, redacted_payload_json
      FROM tool_calls WHERE id = ?
    `).get(committed.invocationId) as Record<string, string | null>;
    expect(afterRestart).toMatchObject({
      status: "succeeded",
      error_category: null,
      output_summary: beforeRestart.output_summary,
    });
    expect(JSON.parse(afterRestart.redacted_payload_json!)).toMatchObject({
      resultAccepted: true,
      duplicateResult: false,
      deliveryAttemptCount: 1,
      deliveryLastError: null,
    });
    expect(restartedDatabase.prepare("SELECT status FROM actions WHERE id = 'action-local'").get())
      .toEqual({ status: "succeeded" });
    expect(restartedDatabase.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: 1 });
    expect(restartedDatabase.prepare("SELECT COUNT(*) AS count FROM observations").get())
      .toEqual({ count: 1 });
    expect(restartedDatabase.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get())
      .toEqual({ count: 1 });
    restarted.close();
  }, 20_000);

  test("keeps succeeded tool and action truth when the runtime commits but loses its acknowledgement", async () => {
    const { database, port, action } = await seededBoundary();
    let resolveRuntimeCommit!: () => void;
    const runtimeCommitted = new Promise<void>((resolve) => { resolveRuntimeCommit = resolve; });
    const unbind = port.bindResultSink({
      async acceptExecutionResult(result) {
        database.prepare(`
          UPDATE actions SET status = 'succeeded', result_summary = ?, ended_at = ?, updated_at = ?
          WHERE id = ? AND status = 'running'
        `).run(result.summary, NOW.toISOString(), NOW.toISOString(), result.actionId);
        resolveRuntimeCommit();
        throw new Error("simulated acknowledgement loss after runtime commit");
      },
    });
    await port.dispatch(action, new AbortController().signal);
    await runtimeCommitted;
    await waitForAssertion(() => {
      const payload = JSON.parse((database.prepare(`
        SELECT redacted_payload_json FROM tool_calls
      `).get() as { redacted_payload_json: string }).redacted_payload_json);
      expect(payload.deliveryLastError).toBe("runtime_result_delivery_failed");
    });

    const afterLostAcknowledgement = database.prepare(`
      SELECT status, error_category, output_summary, redacted_payload_json FROM tool_calls
    `).get() as Record<string, string | null>;
    expect(afterLostAcknowledgement).toMatchObject({
      status: "succeeded",
      error_category: null,
      output_summary: expect.stringContaining("completed"),
    });
    expect(database.prepare("SELECT status FROM actions WHERE id = ?").get(action.id))
      .toEqual({ status: "succeeded" });
    expect(JSON.parse(afterLostAcknowledgement.redacted_payload_json!)).toMatchObject({
      resultAccepted: false,
      duplicateResult: false,
      deliveryAttemptCount: 1,
      deliveryLastError: "runtime_result_delivery_failed",
    });

    unbind();
    let duplicateDeliveries = 0;
    port.bindResultSink({
      async acceptExecutionResult(result) {
        duplicateDeliveries += 1;
        expect(result).toMatchObject({ actionId: action.id, success: true });
        return {
          accepted: true,
          duplicate: true,
          actionId: result.actionId,
          runId: result.runId,
          runState: "running",
          nextAction: null,
        };
      },
    });
    expect(await port.replayPendingResults()).toBe(1);
    expect(await port.replayPendingResults()).toBe(0);
    expect(duplicateDeliveries).toBe(1);
    const afterReplay = database.prepare(`
      SELECT status, error_category, output_summary, redacted_payload_json FROM tool_calls
    `).get() as Record<string, string | null>;
    expect(afterReplay).toMatchObject({
      status: "succeeded",
      error_category: null,
      output_summary: afterLostAcknowledgement.output_summary,
    });
    expect(JSON.parse(afterReplay.redacted_payload_json!)).toMatchObject({
      resultAccepted: true,
      duplicateResult: true,
      deliveryAttemptCount: 2,
      deliveryLastError: null,
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get())
      .toEqual({ count: 1 });
    port.close();
  }, 20_000);

  test("completes a refused TCP check as a negative observation instead of failing the run", async () => {
    const closedTcp = createTcpServer();
    const closedPort = await new Promise<number>((resolve, reject) => {
      closedTcp.once("error", reject);
      closedTcp.listen(0, "127.0.0.1", () => {
        closedTcp.off("error", reject);
        resolve((closedTcp.address() as { port: number }).port);
      });
    });
    await new Promise<void>((resolve) => closedTcp.close(() => resolve()));

    const { database, port } = await seededBoundary();
    const toolId = "kali:ncat-tcp-connect";
    const target = `tcp://127.0.0.1:${closedPort}`;
    const parameters = {
      workspace: "/engagements/mission",
      target: "127.0.0.1",
      port: closedPort,
    };
    database.prepare(`
      UPDATE mission_targets SET target = ?, normalized_target = ?
      WHERE id = 'target-local'
    `).run(target, target);
    database.prepare(`
      UPDATE agents SET tool_policy_json = ? WHERE id = 'ReconScout'
    `).run(JSON.stringify({
      allowedTools: [toolId], deniedTools: [], approvalRequiredTools: [],
    }));
    database.prepare(`
      UPDATE agent_capabilities SET capability = ? WHERE agent_id = 'ReconScout'
    `).run(toolId);
    database.prepare(`
      UPDATE guided_decisions SET requested_parameters_json = ? WHERE id = 'decision-local'
    `).run(JSON.stringify(parameters));
    database.prepare(`
      UPDATE actions SET action_type = ?, normalized_arguments_json = ?, scoped_target = ?
      WHERE id = 'action-local'
    `).run(toolId, JSON.stringify({
      input: {
        schemaVersion: "ti-scale.reviewed-local-tool-action.v1",
        executionBinding: "reviewed_local_process",
        toolId,
        parameters,
      },
      orchestration: {
        target, kind: "tool", idempotent: true, destructive: false, planVersion: 1,
      },
    }), target);
    const action = new ActionRepository(database).get("action-local");

    let resolveResult!: () => void;
    const resultAccepted = new Promise<void>((resolve) => { resolveResult = resolve; });
    port.bindResultSink({
      async acceptExecutionResult(result) {
        expect(result).toMatchObject({
          actionId: action.id,
          runId: action.runId,
          success: true,
        });
        expect(result.summary).toContain("valid negative observation");
        resolveResult();
        return {
          accepted: true,
          duplicate: false,
          actionId: action.id,
          runId: action.runId,
          runState: "running",
          nextAction: null,
        };
      },
    });
    await port.dispatch(action, new AbortController().signal);
    await resultAccepted;

    expect(database.prepare(`
      SELECT status, error_category, provider FROM tool_calls
    `).get()).toEqual({
      status: "succeeded",
      error_category: null,
      provider: "reviewed-local-process",
    });
    const log = database.prepare(`
      SELECT severity, human_summary, technical_payload_json
      FROM engagement_log_records
    `).get() as {
      severity: string;
      human_summary: string;
      technical_payload_json: string;
    };
    expect(log.severity).toBe("notice");
    expect(log.human_summary).toContain("valid negative observation");
    expect(JSON.parse(log.technical_payload_json)).toMatchObject({
      semanticOutcome: "negative_observation",
      exitCode: 1,
      termination: "exited",
    });
    const observation = database.prepare(`
      SELECT observation_type, statement, confidence, verification_state,
        normalized_value_json FROM observations
    `).get() as Record<string, string | number>;
    expect(observation).toMatchObject({
      observation_type: "tcp_connectivity",
      confidence: 0.9,
      verification_state: "unverified",
      statement: expect.stringContaining("was refused"),
    });
    expect(JSON.parse(String(observation.normalized_value_json))).toMatchObject({
      semanticOutcome: "negative_observation",
      target,
      actionId: "action-local",
      missionTargetId: "target-local",
      result: {
        host: "127.0.0.1",
        port: closedPort,
        connectionEstablished: false,
        refusalObserved: true,
      },
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    port.close();
  }, 20_000);

  test("proposes an unverified candidate only for an exact mission-selected evidence type", async () => {
    const { database, port, action } = await seededBoundary({
      evidenceExpectations: ["asset_discovery_proof"],
    });
    let resolveResult!: () => void;
    const resultAccepted = new Promise<void>((resolve) => { resolveResult = resolve; });
    port.bindResultSink({
      async acceptExecutionResult(result) {
        expect(result.success).toBeTrue();
        resolveResult();
        return {
          accepted: true,
          duplicate: false,
          actionId: action.id,
          runId: action.runId,
          runState: "running",
          nextAction: null,
        };
      },
    });
    await port.dispatch(action, new AbortController().signal);
    await resultAccepted;

    expect(database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT c.evidence_type, c.state, c.proposed_by, c.promoted_evidence_id,
        o.verification_state, source.log_record_id
      FROM evidence_candidates c
      JOIN observations o ON o.id = c.observation_id
      JOIN observation_log_sources source ON source.observation_id = o.id
    `).get()).toMatchObject({
      evidence_type: "asset_discovery_proof",
      state: "candidate",
      proposed_by: "ReconScout",
      promoted_evidence_id: null,
      verification_state: "unverified",
      log_record_id: expect.stringContaining("log_"),
    });
    port.close();
  }, 20_000);

  test("does not propose a candidate when mission evidence policy does not match the reviewed tool", async () => {
    const { database, port, action } = await seededBoundary({
      evidenceExpectations: ["port_service_scan_result"],
    });
    let resolveResult!: () => void;
    const resultAccepted = new Promise<void>((resolve) => { resolveResult = resolve; });
    port.bindResultSink({
      async acceptExecutionResult() {
        resolveResult();
        return {
          accepted: true,
          duplicate: false,
          actionId: action.id,
          runId: action.runId,
          runState: "running",
          nextAction: null,
        };
      },
    });
    await port.dispatch(action, new AbortController().signal);
    await resultAccepted;
    expect(database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get()).toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence").get()).toEqual({ count: 0 });
    port.close();
  }, 20_000);

  test("atomically rolls back operational truth when terminal tool-call persistence cannot complete", async () => {
    const { database, port, action } = await seededBoundary({
      failAfterOutputProjection: true,
    });
    let resolveResult!: () => void;
    const resultAccepted = new Promise<void>((resolve) => { resolveResult = resolve; });
    port.bindResultSink({
      async acceptExecutionResult(result) {
        expect(result).toMatchObject({
          actionId: action.id,
          success: false,
          failureCategory: "dependency_missing",
          failure: { code: "engagement_log_retention_failed" },
        });
        resolveResult();
        return {
          accepted: true,
          duplicate: false,
          actionId: action.id,
          runId: action.runId,
          runState: "running",
          nextAction: null,
        };
      },
    });
    await port.dispatch(action, new AbortController().signal);
    await resultAccepted;
    expect(database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records").get())
      .toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM observations").get())
      .toEqual({ count: 0 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates").get())
      .toEqual({ count: 0 });
    expect(database.prepare(`
      SELECT status, error_category FROM tool_calls
    `).get()).toEqual({
      status: "failed",
      error_category: "dependency_missing",
    });
    port.close();
  }, 20_000);

  test("fails closed for Autonomous work without a signed current contract", async () => {
    const { database, port, action } = await seededBoundary({ journey: "autonomous" });
    port.bindResultSink({
      async acceptExecutionResult() { throw new Error("must not execute"); },
    });
    await expect(port.dispatch(action, new AbortController().signal))
      .rejects.toMatchObject({ code: "autonomous_action_no_longer_authorized" });
    expect(database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
    port.close();
  });

  test("requires a new action identity for recovery instead of replaying an accepted process", async () => {
    const { database, port, action } = await seededBoundary();
    await expect(port.resume(action, new AbortController().signal))
      .rejects.toMatchObject({ code: "resume_requires_new_attempt" });
    expect(database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
    port.close();
  });

  test("rejects a tool/action-class mismatch before reserving a process", async () => {
    const { database, port } = await seededBoundary();
    database.prepare(`
      UPDATE actions SET action_class = 'destructive_data_system_modification'
      WHERE id = 'action-local'
    `).run();
    const changed = new ActionRepository(database).get("action-local");
    port.bindResultSink({
      async acceptExecutionResult() { throw new Error("must not execute"); },
    });
    await expect(port.dispatch(changed, new AbortController().signal))
      .rejects.toMatchObject({
        code: "action_local_tool_policy_denied",
        failureCategory: "policy_denied",
      });
    expect(database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
    port.close();
  });

  test("rejects a reviewed local tool when projected capability metadata maps it to another action class", async () => {
    const { database, port, action } = await seededBoundary({
      capabilityActionClassIds: ["port_service_enumeration"],
    });
    port.bindResultSink({
      async acceptExecutionResult() { throw new Error("must not execute"); },
    });
    await expect(port.dispatch(action, new AbortController().signal))
      .rejects.toMatchObject({
        code: "action_local_tool_policy_denied",
        failureCategory: "policy_denied",
      });
    expect(database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get())
      .toEqual({ count: 0 });
    port.close();
  });

  test("retains a typed pre-dispatch boundary diagnosis instead of collapsing it to unknown", async () => {
    const { database, port } = await seededBoundary();
    port.close();
    database.prepare("DELETE FROM actions WHERE id = 'action-local'").run();
    database.prepare(`
      UPDATE assignments SET status = 'queued', started_at = NULL, ended_at = NULL
      WHERE id = 'assignment-local'
    `).run();
    database.prepare(`
      UPDATE plan_steps SET status = 'ready', started_at = NULL, ended_at = NULL
      WHERE id = 'step-local'
    `).run();
    const intent: DurableActionIntent = {
      missionId: "mission-local",
      runId: "run-local",
      stepId: "step-local",
      assignmentId: "assignment-local",
      planVersion: 1,
      actionType: TOOL_ID,
      actionClass: "active_host_discovery",
      arguments: {
        schemaVersion: "ti-scale.reviewed-local-tool-action.v1",
        executionBinding: "reviewed_local_process",
        toolId: TOOL_ID,
        parameters: { workspace: "/engagements/mission", target: TARGET },
      },
      target: TARGET,
      intentSummary: "Run one exact reviewed local action",
      kind: "tool",
      idempotent: true,
      destructive: false,
    };
    database.prepare(`
      UPDATE guided_decisions SET requested_action_fingerprint = ?
      WHERE id = 'decision-local'
    `).run(fingerprintAction(intent).hash);
    const coordinator = new DurableRunCoordinator(database, {
      async dispatch() {
        expect(database.prepare(`
          SELECT status, lease_owner, lease_acquired_at, last_heartbeat_at, lease_expires_at
          FROM assignments WHERE id = 'assignment-local'
        `).get()).toEqual({
          status: "active",
          lease_owner: "worker:test",
          lease_acquired_at: NOW.toISOString(),
          last_heartbeat_at: NOW.toISOString(),
          lease_expires_at: new Date(NOW.getTime() + (5 * 60_000)).toISOString(),
        });
        throw new ExecutionBoundaryError(
          "target_binding_changed",
          "scope_conflict",
          "Compiled local tool target differs from the canonical authorized action target.",
        );
      },
      async resume() {},
      async cancelRun() {},
    }, {
      now: () => NOW,
      leaseTtlMs: 5 * 60_000,
    });
    const lease = coordinator.acquireRunLease("run-local", "worker:test");

    await expect(coordinator.startAction({
      lease,
      intent,
      guidedDecisionId: "decision-local",
    })).rejects.toMatchObject({
      code: "target_binding_changed",
      message: "Compiled local tool target differs from the canonical authorized action target.",
    });
    expect(database.prepare(`
      SELECT status, error_category, result_summary FROM actions
      WHERE run_id = 'run-local' ORDER BY created_at DESC LIMIT 1
    `).get()).toEqual({
      status: "failed",
      error_category: "scope_conflict",
      result_summary: "Execution boundary stopped this action: Compiled local tool target differs from the canonical authorized action target.",
    });
    expect(database.prepare(`
      SELECT status, ended_at FROM plan_steps WHERE id = 'step-local'
    `).get()).toEqual({ status: "blocked", ended_at: null });
    expect(database.prepare(`
      SELECT status, lease_owner, lease_acquired_at, last_heartbeat_at, lease_expires_at
      FROM assignments WHERE id = 'assignment-local'
    `).get()).toEqual({
      status: "blocked",
      lease_owner: null,
      lease_acquired_at: null,
      last_heartbeat_at: null,
      lease_expires_at: null,
    });
  });

  test("cancellation cannot leave a reviewed local tool-call ghost-active", async () => {
    const { database, port } = await seededBoundary();
    database.prepare(`
      INSERT INTO tool_calls (
        id, action_id, provider, tool_name, normalized_arguments_json,
        status, started_at, created_at
      ) VALUES ('local_tool_cancel_test', 'action-local', 'reviewed-local-process',
        ?, '{}', 'running', ?, ?)
    `).run(TOOL_ID, NOW.toISOString(), NOW.toISOString());
    await port.cancelRun("run-local", "operator cancellation");
    expect(database.prepare(`
      SELECT status, output_summary FROM tool_calls WHERE id = 'local_tool_cancel_test'
    `).get()).toEqual({
      status: "cancelled",
      output_summary: "Run cancellation terminated the reviewed local process before a result was accepted.",
    });
    port.close();
  });
});

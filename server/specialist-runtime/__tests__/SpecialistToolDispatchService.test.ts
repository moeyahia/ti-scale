import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ControlPlaneLeaseService } from "../../control-plane";
import type { ExecutionResultSink } from "../../command-runtime";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { digestCanonicalJson, type McpCapabilityAttestation } from "../../mcp";
import { ActionRepository, type DurableAction } from "../../orchestration";
import {
  EngagementWorkspaceResolver,
  ToolExecutionPreflightService,
  type ToolExecutionPreflightEnvironment,
} from "../../system-capabilities";
import {
  SpecialistToolAdapterError,
  SpecialistToolDispatchError,
  SpecialistToolDispatchService,
  specialistDispatchRecordPrefix,
  type SpecialistMcpToolBinding,
  type SpecialistToolInvocation,
  type SpecialistToolInvocationAdapter,
  type SpecialistToolInvocationResult,
  type SpecialistToolInvocationResultSink,
} from "../SpecialistToolDispatchService";

const NOW = new Date("2026-07-18T22:00:00.000Z");
const TARGET = "10.129.39.191";
const BOARD_SCHEMA = Object.freeze({
  type: "object",
  additionalProperties: false,
  required: ["missionId", "title", "details"],
  properties: {
    missionId: { type: "string", minLength: 1, maxLength: 128 },
    title: { type: "string", minLength: 4, maxLength: 200 },
    details: { type: "string", minLength: 10, maxLength: 4_000 },
  },
} as const);
const NMAP_SCHEMA = Object.freeze({
  type: "object",
  additionalProperties: false,
  required: ["target", "workingDirectory"],
  properties: {
    target: { type: "string", minLength: 1, maxLength: 255 },
    workingDirectory: { type: "string", minLength: 2, maxLength: 1_024 },
  },
} as const);

const databases: SqliteDatabase[] = [];
const temporaryDirectories: string[] = [];

afterEach(async () => {
  for (const database of databases.splice(0)) database.close();
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

class RecordingAdapter implements SpecialistToolInvocationAdapter {
  readonly contract = {
    schemaVersion: "ti-scale.specialist-tool-invocation-adapter.v1",
    adapterId: "specialist-test-adapter",
    toolSelection: "exact_persisted_binding_only",
    resultDelivery: "bound_execution_result_sink",
    cancellation: "run_scoped_cooperative",
    shellInterpolation: false,
    publicProviderToolExecution: false,
  } as const;
  dispatchCount = 0;
  cancelCount = 0;
  invocation: SpecialistToolInvocation | undefined;
  error: Error | undefined;
  private resultSink?: SpecialistToolInvocationResultSink;

  bindResultSink(sink: SpecialistToolInvocationResultSink): () => void {
    this.resultSink = sink;
    return () => {
      if (this.resultSink === sink) this.resultSink = undefined;
    };
  }

  emitResult(result: SpecialistToolInvocationResult) {
    if (!this.resultSink) throw new Error("test result sink is not bound");
    return this.resultSink.acceptSpecialistToolResult(result);
  }

  async dispatch(invocation: SpecialistToolInvocation): Promise<void> {
    this.dispatchCount += 1;
    this.invocation = invocation;
    if (this.error) throw this.error;
  }

  async cancelRun(): Promise<void> {
    this.cancelCount += 1;
  }
}

function attestation(
  serverId: string,
  toolName: string,
  schema: Readonly<Record<string, unknown>>,
): McpCapabilityAttestation {
  const schemaDigest = digestCanonicalJson(schema, { maxBytes: 64 * 1_024, maxDepth: 32 });
  const unsigned = {
    schemaVersion: "ti-scale.mcp-capability-attestation.v1",
    connectionId: serverId,
    transport: "stdio",
    server: { name: serverId, version: "test-1" },
    protocolVersion: "2025-06-18",
    capabilities: { toolsListChanged: false },
    configurationSha256: "c".repeat(64),
    tools: [{
      name: toolName,
      description: "One exact test-bound specialist tool.",
      inputSchema: schema,
      inputSchemaSha256: schemaDigest.sha256,
      inputSchemaBytes: schemaDigest.bytes,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    }],
    attestedAt: "2026-07-18T21:59:00.000Z",
    expiresAt: "2026-07-18T22:05:00.000Z",
    executionAuthorization: "none",
  } as const;
  return {
    ...unsigned,
    manifestSha256: digestCanonicalJson(unsigned, {
      maxBytes: 64 * 1024 * 1024,
      maxDepth: 256,
    }).sha256,
  };
}

interface SeededBoundary {
  readonly database: SqliteDatabase;
  readonly action: DurableAction;
  readonly authority: () => ReturnType<ControlPlaneLeaseService["assertMutationAuthority"]>;
}

function seedBoundary(input: {
  readonly serverId: string;
  readonly toolName: string;
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly actionClass?: string;
  readonly toolActionClassIds?: readonly string[];
  readonly idempotent?: boolean;
  readonly allowed?: boolean;
  readonly runtimeBindingAgentId?: string;
}): SeededBoundary {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  const now = NOW.toISOString();
  const fingerprint = "f".repeat(64);

  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at, control_plane
    ) VALUES (
      'mission-reapertwo', 'ReaperTwo', 'Assess the current authorized HTB target',
      'guided', 'active', 'verified', 'operator:test', ?, ?, 'ti_scale'
    )
  `).run(now, now);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-reapertwo', 'mission-reapertwo', ?, 'host', 'allowed', ?, ?)
  `).run(TARGET, TARGET, now);
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, tool_policy_json, configuration_json,
      version, created_at, updated_at
    ) VALUES (
      'ReconScout', 'reconnaissance', 'ReconScout', 'available', ?, ?,
      'test-1', ?, ?
    )
  `).run(JSON.stringify({
    allowedTools: input.allowed === false ? [] : [input.toolName],
    deniedTools: [],
    approvalRequiredTools: [],
  }), JSON.stringify({
    userFacing: true,
    productAgent: true,
    runtimeBindingAgentIds: input.runtimeBindingAgentId
      ? [input.runtimeBindingAgentId]
      : [],
  }), now, now);
  database.prepare(`
    INSERT INTO agent_capabilities (
      agent_id, capability, source, enabled, metadata_json
    ) VALUES (
      'ReconScout', ?, 'runtime-manifest-tool-binding', 1, ?
    )
  `).run(input.toolName, JSON.stringify({
    toolId: input.toolName,
    actionClassIds: input.toolActionClassIds ?? ["active_host_discovery"],
    runtimeBindingAgentId: input.runtimeBindingAgentId ?? "ReconScout",
    productAgentId: "ReconScout",
  }));
  if (input.runtimeBindingAgentId) {
    database.prepare(`
      INSERT INTO agents (
        id, role, display_name, status, tool_policy_json, configuration_json,
        version, created_at, updated_at
      ) VALUES (?, 'runtime adapter', 'Internal runtime adapter', 'available', ?,
        '{"userFacing":false,"internalComponent":true}', 'test-1', ?, ?)
    `).run(
      input.runtimeBindingAgentId,
      JSON.stringify({
        allowedTools: [input.toolName],
        deniedTools: [],
        approvalRequiredTools: [],
      }),
      now,
      now,
    );
    database.prepare(`
      INSERT INTO agent_capabilities (
        agent_id, capability, source, enabled, metadata_json
      ) VALUES (
        ?, ?, 'runtime-manifest-tool-binding', 1, ?
      )
    `).run(input.runtimeBindingAgentId, input.toolName, JSON.stringify({
      toolId: input.toolName,
      actionClassIds: input.toolActionClassIds ?? ["active_host_discovery"],
      runtimeBindingAgentId: input.runtimeBindingAgentId,
    }));
  }
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, current_plan_id, current_step_id,
      current_owner_id, progress, status_reason, next_action_summary,
      budget_json, budget_usage_json, started_at, created_at, updated_at,
      version, control_plane
    ) VALUES (
      'run-reapertwo', 'mission-reapertwo', 'guided', 'running',
      'plan-reapertwo', 'step-reapertwo', 'ReconScout', 0.1,
      'Executing one represented action', 'Wait for its attributable result',
      '{}', '{}', ?, ?, ?, 1, 'ti_scale'
    )
  `).run(now, now, now);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      created_by, created_at, activated_at
    ) VALUES (
      'plan-reapertwo', 'run-reapertwo', 1, 'active',
      'Run one bounded specialist action', ?, 'planner:test', ?, ?
    )
  `).run("a".repeat(64), now, now);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      assigned_agent_id, created_at, updated_at
    ) VALUES (
      'step-reapertwo', 'plan-reapertwo', 'run-reapertwo', 0,
      'reconnaissance', 'Current-IP baseline', 'Collect attributable current-IP facts',
      'running', 'ReconScout', ?, ?
    )
  `).run(now, now);
  database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
      last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at
    ) VALUES (
      'assignment-reapertwo', 'run-reapertwo', 'step-reapertwo', 'ReconScout',
      'active', 'worker:test', ?, ?, '2026-07-18T22:05:00.000Z', ?, ?, ?
    )
  `).run(now, now, now, now, now);
  database.prepare(`
    INSERT INTO guided_decisions (
      id, mission_id, run_id, step_id, requested_action_fingerprint,
      requested_parameters_json, rationale, risk_class, reversibility,
      status, decision_actor, decision_reason, decided_at, expires_at, created_at
    ) VALUES (
      'decision-reapertwo', 'mission-reapertwo', 'run-reapertwo',
      'step-reapertwo', ?, '{}', 'Run this exact represented specialist action',
      'low', 'Bounded and reversible', 'approved', 'operator:test',
      'Approved one exact action', ?, '2026-07-18T23:00:00.000Z', ?
    )
  `).run(fingerprint, now, now);
  database.prepare(`
    INSERT INTO actions (
      id, mission_id, run_id, step_id, assignment_id, action_type,
      action_class, fingerprint, normalized_arguments_json, scoped_target,
      status, intent_summary, guided_decision_id, started_at, created_at, updated_at
    ) VALUES (
      'action-reapertwo', 'mission-reapertwo', 'run-reapertwo',
      'step-reapertwo', 'assignment-reapertwo', ?, ?, ?, ?, ?,
      'running', 'Run one exact specialist action', 'decision-reapertwo', ?, ?, ?
    )
  `).run(
    input.toolName,
    input.actionClass ?? "active_host_discovery",
    fingerprint,
    JSON.stringify({
      input: {
        mcpServer: input.serverId,
        toolName: input.toolName,
        parameters: input.parameters,
      },
      orchestration: {
        target: TARGET,
        kind: "tool",
        idempotent: input.idempotent === true,
        destructive: false,
        planVersion: 1,
      },
    }),
    TARGET,
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO mcp_servers (
      id, name, transport, status, capabilities_json, policy_json,
      last_checked_at, created_at, updated_at
    ) VALUES (?, ?, 'stdio', 'healthy', ?, ?, ?, ?, ?)
  `).run(
    input.serverId,
    input.serverId,
    JSON.stringify([input.toolName]),
    JSON.stringify({
      schemaVersion: "ti-scale.specialist-mcp-execution-policy.v1",
      enabled: true,
      startPermitted: true,
      executionAuthorization: "signed_contract_specialist_action",
      autonomousExecution: true,
      exactInventoryRequired: true,
      directCommanderToolsAllowed: false,
      assignedAgents: [input.runtimeBindingAgentId ?? "ReconScout"],
    }),
    now,
    now,
    now,
  );

  const leaseService = new ControlPlaneLeaseService(database);
  const leaseToken = "specialist-dispatch-test-token";
  leaseService.acquire({
    runId: "run-reapertwo",
    controlPlane: "ti_scale",
    leaseOwner: "runtime:test",
    leaseToken,
    ttlMs: 5 * 60_000,
    now: NOW,
  });
  return {
    database,
    action: new ActionRepository(database).get("action-reapertwo"),
    authority: () => leaseService.assertMutationAuthority({
      runId: "run-reapertwo",
      controlPlane: "ti_scale",
      leaseOwner: "runtime:test",
      leaseToken,
      now: NOW,
    }),
  };
}

async function workspaceResolver(): Promise<{
  resolver: EngagementWorkspaceResolver;
  runtimeWorkspace: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "ti-scale-specialist-dispatch-"));
  temporaryDirectories.push(root);
  const runtimeWorkspace = join(root, "reapertwo");
  await mkdir(runtimeWorkspace);
  return {
    resolver: new EngagementWorkspaceResolver([{
      logicalRoot: "/root/htb/boxes",
      runtimeRoot: root,
    }]),
    runtimeWorkspace,
  };
}

function boundaryService(input: {
  readonly seeded: SeededBoundary;
  readonly binding: SpecialistMcpToolBinding;
  readonly adapter: RecordingAdapter;
  readonly resolver: EngagementWorkspaceResolver;
  readonly toolPreflight?: ToolExecutionPreflightService;
  readonly authority?: SeededBoundary["authority"];
  readonly resultSink?: ExecutionResultSink;
  readonly bindResultSink?: boolean;
}): SpecialistToolDispatchService {
  const service = new SpecialistToolDispatchService({
    database: input.seeded.database,
    assertControlPlaneAuthority: input.authority ?? input.seeded.authority,
    resolveBinding: (serverId, toolName) => (
      serverId === input.binding.serverId && toolName === input.binding.toolName
        ? input.binding
        : undefined
    ),
    adapter: input.adapter,
    workspaceResolver: input.resolver,
    ...(input.toolPreflight ? { toolPreflight: input.toolPreflight } : {}),
    actorId: "specialist-dispatch:test",
    now: () => NOW,
  });
  if (input.bindResultSink !== false) {
    service.bindResultSink(input.resultSink ?? {
      async acceptExecutionResult(result) {
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
  }
  return service;
}

describe("fail-closed specialist tool dispatch boundary", () => {
  test("keeps the product specialist as audit owner while resolving its exact internal MCP binding", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "Current-IP baseline",
      details: "Create one bounded task from the represented product assignment.",
    };
    const runtimeBindingAgentId = "specialist:autonomous-safe-recon";
    const seeded = seedBoundary({
      serverId: "mission-board",
      toolName: "board_create_task",
      parameters,
      runtimeBindingAgentId,
    });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    });

    await service.dispatch(seeded.action, new AbortController().signal);

    expect(adapter.dispatchCount).toBe(1);
    expect(seeded.database.prepare(`
      SELECT ass.agent_id AS assignment_agent_id,
        step.assigned_agent_id AS step_agent_id
      FROM assignments ass
      JOIN plan_steps step ON step.id = ass.step_id
      WHERE ass.id = 'assignment-reapertwo'
    `).get()).toEqual({
      assignment_agent_id: "ReconScout",
      step_agent_id: "ReconScout",
    });
    expect(seeded.database.prepare(`
      SELECT json_extract(policy_json, '$.assignedAgents[0]') AS binding_agent_id
      FROM mcp_servers WHERE id = 'mission-board'
    `).get()).toEqual({ binding_agent_id: runtimeBindingAgentId });
  });

  test("dispatches only the exact persisted, attested, policy-authorized binding and replays acceptance without a duplicate side effect", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const binding = {
      serverId: "mission-board",
      toolName: "board_create_task",
      attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
    } satisfies SpecialistMcpToolBinding;
    const service = boundaryService({ seeded, binding, adapter, resolver: workspace.resolver });

    await service.dispatch(seeded.action, new AbortController().signal);
    await service.dispatch(seeded.action, new AbortController().signal);

    expect(adapter.dispatchCount).toBe(1);
    expect(adapter.invocation).toMatchObject({
      action: { id: "action-reapertwo", target: TARGET },
      binding: { serverId: "mission-board", toolName: "board_create_task" },
      arguments: parameters,
    });
    expect(adapter.invocation?.inputSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(seeded.database.prepare(`
      SELECT status, normalized_arguments_json FROM tool_calls
    `).get()).toMatchObject({ status: "running" });
    const stored = seeded.database.prepare(`
      SELECT key, value_json FROM settings WHERE key LIKE ?
    `).get(`${specialistDispatchRecordPrefix()}%`) as { key: string; value_json: string };
    expect(stored.key).toMatch(/^idempotency\.specialist-tool-dispatch\.[a-f0-9]{64}$/);
    expect(JSON.parse(stored.value_json)).toMatchObject({ state: "accepted", actionId: "action-reapertwo" });
    expect(stored.value_json).not.toContain("ReaperTwo current-IP baseline");
  });

  test("forwards only the exact accepted invocation through the bound runtime result sink", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const forwarded: unknown[] = [];
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
      resultSink: {
        async acceptExecutionResult(result) {
          forwarded.push(result);
          return {
            accepted: true,
            duplicate: false,
            actionId: result.actionId,
            runId: result.runId,
            runState: "running",
            nextAction: "Await canonical completion",
          };
        },
      },
    });

    await service.dispatch(seeded.action, new AbortController().signal);
    const invocationId = adapter.invocation!.invocationId;
    const result = {
      actionId: seeded.action.id,
      runId: seeded.action.runId,
      actionFingerprint: seeded.action.fingerprint,
      success: true,
      summary: "The exact specialist result was accepted by the runtime boundary.",
      progress: { stepStates: { [seeded.action.stepId]: "completed" } },
    } as const;
    await expect(adapter.emitResult({ invocationId: "another-tool-call", result }))
      .rejects.toMatchObject({ code: "result_binding_invalid" });
    expect(forwarded).toHaveLength(0);

    await expect(adapter.emitResult({ invocationId, result })).resolves.toMatchObject({
      accepted: true,
      actionId: seeded.action.id,
      runId: seeded.action.runId,
    });
    expect(forwarded).toEqual([result]);
  });

  test("rejects an adapter contract that permits shell or public-provider tool execution", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    (adapter as unknown as { contract: Record<string, unknown> }).contract = {
      ...adapter.contract,
      shellInterpolation: true,
      publicProviderToolExecution: true,
    };
    expect(() => boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    })).toThrow("exact production boundary");
  });

  test("cannot reserve or dispatch work before the runtime binds terminal result delivery", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      bindResultSink: false,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "result_sink_unbound",
    });
    expect(adapter.dispatchCount).toBe(0);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
  });

  test("persists one board HTTP 400 diagnosis and durably suppresses the unchanged request", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    adapter.error = new SpecialistToolAdapterError("opaque transport failure", {
      httpStatus: 400,
      transportCode: "HTTPError: HTTP Error 400: Bad Request",
      attemptCount: 5,
    });
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    });

    const first = service.dispatch(seeded.action, new AbortController().signal);
    await expect(first).rejects.toMatchObject({
      code: "dispatch_rejected",
      options: { retryable: false },
    });
    const diagnosis = seeded.database.prepare(`
      SELECT id, category, code, human_reason, retryable, progress_before_failure_json
      FROM failure_diagnoses
    `).get() as Record<string, unknown>;
    expect(diagnosis).toMatchObject({
      category: "invalid_input",
      code: "mcp_http_400_contract_rejected",
      retryable: 0,
    });
    expect(diagnosis.human_reason).toContain("repeating identical parameters is disabled");
    expect(JSON.parse(String(diagnosis.progress_before_failure_json))).toMatchObject({
      inputSchemaValidated: true,
      targetContact: "not_established",
      acceptedToolResult: false,
    });
    expect(adapter.dispatchCount).toBe(1);

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "unchanged_request_suppressed",
      options: { diagnosisId: diagnosis.id, retryable: false },
    });
    expect(adapter.dispatchCount).toBe(1);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: 1 });
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 1 });
    expect(JSON.parse((seeded.database.prepare(`
      SELECT value_json FROM settings WHERE key LIKE ?
    `).get(`${specialistDispatchRecordPrefix()}%`) as { value_json: string }).value_json)).toMatchObject({
      state: "failed_deterministic",
      diagnosisId: diagnosis.id,
    });
  });

  test("resolves the stable engagement workspace and persists the observed Nmap NoNewPrivs failure before adapter dispatch", async () => {
    const parameters = { target: TARGET, workingDirectory: "/root/htb/boxes/ReaperTwo" };
    const seeded = seedBoundary({ serverId: "recon-mcp", toolName: "nmap_scan", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    let checkedWorkspace: string | undefined;
    const environment: ToolExecutionPreflightEnvironment = {
      isolation: {
        networkEnforced: true,
        filesystemWritesEnforced: true,
        immutableSnapshotEnforced: true,
      },
      inspectExecutable: async () => ({
        state: "ready",
        identity: {
          sha256: "a".repeat(64),
          device: "1",
          inode: "2",
          sizeBytes: 1024,
          mode: 0o755,
          uid: 0,
          gid: 0,
        },
      }),
      inspectWorkingDirectory: async (path) => {
        checkedWorkspace = path;
        return path === workspace.runtimeWorkspace;
      },
      readNoNewPrivileges: async () => true,
      execute: async () => ({
        exitCode: null,
        signal: null,
        stdout: "",
        stderr: "/usr/bin/nmap: exec: /usr/lib/nmap/nmap: Operation not permitted\n",
        timedOut: false,
        outputLimitExceeded: false,
        executableIdentity: {
          sha256: "a".repeat(64),
          device: "1",
          inode: "2",
          sizeBytes: 1024,
          mode: 0o755,
          uid: 0,
          gid: 0,
        },
        spawnErrorCode: "EPERM",
      }),
    };
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      toolPreflight: new ToolExecutionPreflightService({ environment, clock: () => NOW }),
      binding: {
        serverId: "recon-mcp",
        toolName: "nmap_scan",
        attestation: attestation("recon-mcp", "nmap_scan", NMAP_SCHEMA),
        localTool: {
          logicalWorkspaceParameter: "workingDirectory",
          preflight: {
            toolId: "kali:nmap",
            displayName: "Nmap",
            executablePath: "/usr/bin/nmap",
            probeArguments: ["--version"],
            ttlMs: 60_000,
          },
        },
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "dispatch_rejected",
      options: { retryable: false },
    });
    expect(checkedWorkspace).toBe(workspace.runtimeWorkspace);
    expect(adapter.dispatchCount).toBe(0);
    expect(seeded.database.prepare(`
      SELECT category, code, failed_component_ref, target_summary
      FROM failure_diagnoses
    `).get()).toMatchObject({
      category: "dependency_missing",
      code: "no_new_privileges_capability_conflict",
      failed_component_ref: "kali:nmap",
      target_summary: "No mission target, provider, or MCP arguments were supplied. The startup check failed before action dispatch; external contact was not independently measured unless the receipt records enforced network isolation.",
    });
    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "unchanged_request_suppressed",
    });
    expect(adapter.dispatchCount).toBe(0);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: 1 });
  });

  test("rejects missing current control-plane authority without creating execution or failure records", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      authority: () => { throw new Error("lease unavailable"); },
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "control_plane_authority_invalid",
    });
    expect(adapter.dispatchCount).toBe(0);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: 0 });
    expect(seeded.database.prepare(`
      SELECT COUNT(*) AS count FROM settings WHERE key LIKE ?
    `).get(`${specialistDispatchRecordPrefix()}%`)).toEqual({ count: 0 });
  });

  test("rechecks the specialist MCP and tool policy immediately before dispatch", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({
      serverId: "mission-board",
      toolName: "board_create_task",
      parameters,
      allowed: false,
    });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "specialist_tool_policy_denied",
    });
    expect(adapter.dispatchCount).toBe(0);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
  });

  test("rejects a tool whose exact manifest metadata does not implement the persisted action class", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({
      serverId: "mission-board",
      toolName: "board_create_task",
      actionClass: "active_host_discovery",
      toolActionClassIds: ["os_technology_fingerprinting"],
      parameters,
    });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal))
      .rejects.toMatchObject({ code: "specialist_tool_policy_denied" });
    expect(adapter.dispatchCount).toBe(0);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get())
      .toEqual({ count: 0 });
  });

  test("does not treat a discovery-only public MCP policy as specialist execution authorization", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    seeded.database.prepare(`
      UPDATE mcp_servers SET policy_json = ? WHERE id = 'mission-board'
    `).run(JSON.stringify({
      enabled: true,
      startPermitted: true,
      executionAuthorization: "none",
      autonomousExecution: false,
      exactInventoryRequired: true,
      directCommanderToolsAllowed: false,
      assignedAgents: ["ReconScout"],
    }));
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "specialist_tool_policy_denied",
    });
    expect(adapter.dispatchCount).toBe(0);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
  });

  test("turns an exact attested-schema mismatch into a field-level diagnosis before transport", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      details: "This deliberately omits the exact title required by the attested schema.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "dispatch_rejected",
      options: { retryable: false },
    });
    expect(adapter.dispatchCount).toBe(0);
    const diagnosis = seeded.database.prepare(`
      SELECT code, human_reason, progress_before_failure_json FROM failure_diagnoses
    `).get() as { code: string; human_reason: string; progress_before_failure_json: string };
    expect(diagnosis.code).toBe("mcp_preflight_input_invalid");
    expect(diagnosis.human_reason).toContain("/title: Provide the required “title” field.");
    expect(JSON.parse(diagnosis.progress_before_failure_json)).toMatchObject({
      inputSchemaValidated: false,
      targetContact: false,
      acceptedToolResult: false,
    });
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 1 });
  });

  test("does not redispatch the same action after a transient MCP failure; a bounded recovery action is required", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    adapter.error = new SpecialistToolAdapterError("service unavailable", {
      httpStatus: 503,
      transportCode: "service unavailable",
      attemptCount: 1,
    });
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: attestation("mission-board", "board_create_task", BOARD_SCHEMA),
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "dispatch_rejected",
      options: { retryable: true },
    });
    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "dispatch_already_in_progress",
      options: { retryable: false },
    });
    expect(adapter.dispatchCount).toBe(1);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: 1 });
    expect(JSON.parse((seeded.database.prepare(`
      SELECT value_json FROM settings WHERE key LIKE ?
    `).get(`${specialistDispatchRecordPrefix()}%`) as { value_json: string }).value_json)).toMatchObject({
      state: "failed_transient",
      actionId: "action-reapertwo",
    });
  });

  test("rejects an expired or future-dated capability attestation before any durable dispatch reservation", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({ serverId: "mission-board", toolName: "board_create_task", parameters });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const valid = attestation("mission-board", "board_create_task", BOARD_SCHEMA);
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: {
          ...valid,
          attestedAt: "2026-07-18T22:01:00.000Z",
          expiresAt: "2026-07-18T22:02:00.000Z",
        },
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects.toMatchObject({
      code: "binding_attestation_invalid",
    });
    expect(adapter.dispatchCount).toBe(0);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get()).toEqual({ count: 0 });
    expect(seeded.database.prepare(`
      SELECT COUNT(*) AS count FROM settings WHERE key LIKE ?
    `).get(`${specialistDispatchRecordPrefix()}%`)).toEqual({ count: 0 });
  });

  test("rejects a modified MCP attestation that retains a plausible stale manifest hash", async () => {
    const parameters = {
      missionId: "mission-reapertwo",
      title: "ReaperTwo current-IP baseline",
      details: "Create one current-IP task and keep historical results explicitly stale.",
    };
    const seeded = seedBoundary({
      serverId: "mission-board",
      toolName: "board_create_task",
      parameters,
    });
    const workspace = await workspaceResolver();
    const adapter = new RecordingAdapter();
    const valid = attestation("mission-board", "board_create_task", BOARD_SCHEMA);
    const service = boundaryService({
      seeded,
      adapter,
      resolver: workspace.resolver,
      binding: {
        serverId: "mission-board",
        toolName: "board_create_task",
        attestation: {
          ...valid,
          tools: valid.tools.map((tool) => ({
            ...tool,
            description: "Modified after the signed manifest was created.",
          })),
        },
      },
    });

    await expect(service.dispatch(seeded.action, new AbortController().signal)).rejects
      .toMatchObject({ code: "binding_attestation_invalid" });
    expect(adapter.dispatchCount).toBe(0);
    expect(seeded.database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get())
      .toEqual({ count: 0 });
    expect(seeded.database.prepare(`
      SELECT COUNT(*) AS count FROM settings WHERE key LIKE ?
    `).get(`${specialistDispatchRecordPrefix()}%`)).toEqual({ count: 0 });
  });

  test("production remains fail-closed because the additive boundary is not mounted without a reviewed transport", async () => {
    const source = await readFile(new URL("../../index.ts", import.meta.url), "utf8");
    expect(source).toContain("createUnavailableExecutionRouter");
    expect(source).toContain("inspectAutonomousRuntimeComposition");
    expect(source).not.toContain("SpecialistToolDispatchService");
  });
});

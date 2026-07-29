import { createHash } from "node:crypto";
import { afterEach, describe, expect, test } from "bun:test";
import type {
  ProductionAutonomousLocalProcessExecutionFactory,
} from "../../app/AutonomousRuntimeComposition";
import type { ResultAwareExecutionPort } from "../../command-runtime";
import { ControlPlaneLeaseService } from "../../control-plane";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  ActionRepository,
  type DurableAction,
  type DurableActionIntent,
} from "../../orchestration";
import { fingerprintAction } from "../../supervisor";
import {
  AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
  AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
  AUTONOMOUS_WINDOWS_IDENTITY_EXECUTION_CONTRACT,
  AUTONOMOUS_WINDOWS_IDENTITY_PRODUCT_AGENT_ID,
  AutonomousWindowsIdentityExecutionFactory,
  WindowsIdentityAutonomousExecutionPort,
} from "../WindowsIdentityAutonomousExecutionPort";
import { WindowsIdentityToolPack } from "../WindowsIdentityToolPack";
import type {
  CompiledWindowsIdentityInvocation,
  WindowsIdentityExecutionAdapter,
  WindowsIdentityRawResult,
  WindowsIdentityToolReadinessReceipt,
} from "../types";

const NOW = new Date("2026-07-25T12:00:00.000Z");
const TARGET = "127.0.0.1";
const WORKSPACE = "/engagements/autonomous-identity";
const CONTRACT_HASH = "c".repeat(64);
const DELEGATED_LOCAL_PROCESS_CONTRACT = Object.freeze({
  schemaVersion: "ti-scale.autonomous-local-process-execution.v1" as const,
  adapterId: "ti-scale:test-autonomous-safe-recon-base",
  executionBinding: "reviewed_local_process" as const,
  directArgv: true as const,
  shell: false as const,
  resultDelivery: "bound_execution_result_sink" as const,
  cancellation: "run_scoped_cooperative" as const,
  publicProviderToolExecution: false as const,
});

const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function rawResult(
  invocation: CompiledWindowsIdentityInvocation,
  cancelled = false,
): WindowsIdentityRawResult {
  const stdout = cancelled
    ? ""
    : "SMB 127.0.0.1 445 LOOPBACK [*] Windows Server 2022 Build 20348 (domain:LAB) (signing:True) (SMBv1:False)\n";
  const stderr = "";
  const outputSha256 = createHash("sha256")
    .update(stdout)
    .update("\u0000")
    .update(stderr)
    .digest("hex");
  return {
    schemaVersion: "ti-scale.windows-identity-result.v1",
    toolId: invocation.toolId,
    actionFingerprint: invocation.actionFingerprint,
    exitCode: cancelled ? null : 0,
    signal: cancelled ? "SIGTERM" : null,
    stdout,
    stderr,
    observedOutputBytes: Buffer.byteLength(stdout),
    retainedOutputBytes: Buffer.byteLength(stdout),
    outputSha256,
    outputTruncated: false,
    timedOut: false,
    cancelled,
    startedAt: NOW.toISOString(),
    endedAt: NOW.toISOString(),
    receipt: {
      schemaVersion: "ti-scale.windows-identity-execution-receipt.v1",
      adapterId: "ti-scale:test-autonomous-windows-identity",
      toolId: invocation.toolId,
      actionFingerprint: invocation.actionFingerprint,
      runId: invocation.action.runId,
      executableSha256: invocation.executableSha256,
      sandboxExecutableSha256: "d".repeat(64),
      logicalWorkspace: invocation.logicalWorkspace,
      credentialReferenceId: null,
      directArgv: true,
      shell: false,
      targetReadOnly: true,
      workspaceConfined: true,
      credentialsMountedReadOnly: true,
      outputRedacted: true,
      outputSha256,
      startedAt: NOW.toISOString(),
      endedAt: NOW.toISOString(),
      wallClockMs: 1,
      exitCode: cancelled ? null : 0,
      signal: cancelled ? "SIGTERM" : null,
      timedOut: false,
      cancelled,
      outputTruncated: false,
      grantsAuthorization: false,
    },
  };
}

class LoopbackAutonomousIdentityAdapter
implements WindowsIdentityExecutionAdapter {
  readonly adapterId = "ti-scale:test-autonomous-windows-identity";
  readonly invocations: CompiledWindowsIdentityInvocation[] = [];
  hold = false;
  cancellationCount = 0;
  private pending?: Readonly<{
    invocation: CompiledWindowsIdentityInvocation;
    resolve: (value: WindowsIdentityRawResult) => void;
  }>;

  readiness(): WindowsIdentityToolReadinessReceipt | null {
    return null;
  }

  execute(
    invocation: CompiledWindowsIdentityInvocation,
    signal: AbortSignal,
  ): Promise<WindowsIdentityRawResult> {
    this.invocations.push(invocation);
    if (!this.hold) return Promise.resolve(rawResult(invocation));
    return new Promise((resolve) => {
      this.pending = { invocation, resolve };
      signal.addEventListener(
        "abort",
        () => resolve(rawResult(invocation, true)),
        { once: true },
      );
    });
  }

  async cancelRun(): Promise<void> {
    this.cancellationCount += 1;
    const pending = this.pending;
    this.pending = undefined;
    if (pending) pending.resolve(rawResult(pending.invocation, true));
  }
}

function waitFor(assertion: () => void, attempts = 200): Promise<void> {
  return new Promise((resolve, reject) => {
    let attempt = 0;
    const inspect = () => {
      try {
        assertion();
        resolve();
      } catch (error) {
        attempt += 1;
        if (attempt >= attempts) {
          reject(error);
          return;
        }
        setTimeout(inspect, 5);
      }
    };
    inspect();
  });
}

function seed(): Readonly<{
  database: SqliteDatabase;
  action: DurableAction;
  lease: ControlPlaneLeaseService;
  leaseToken: string;
}> {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  const now = NOW.toISOString();
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      created_by, created_at, updated_at, control_plane
    ) VALUES (
      'mission-autonomous-identity', 'Anonymous SMB identity',
      'Read one authorized host SMB identity', 'autonomous', 'active',
      'verified', 'operator:test', ?, ?, 'ti_scale'
    )
  `).run(now, now);
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition,
      normalized_target, created_at
    ) VALUES (
      'target-autonomous-identity', 'mission-autonomous-identity', ?,
      'ip', 'allowed', ?, ?
    )
  `).run(TARGET, TARGET, now);
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (
      'contract-autonomous-identity', 'mission-autonomous-identity', 1,
      'confirmed', ?, '{}', ?, '{"toolCalls":1}', '{"conditions":[]}',
      '[]', '[]', 'operator:test', ?, ?
    )
  `).run(
    CONTRACT_HASH,
    JSON.stringify({
      allowedActionClasses: [AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS],
      prohibitedActionClasses: [],
      destructivePolicy: "prohibited",
      boundedDestructiveTargets: [],
      specialistAgentIds: [AUTONOMOUS_WINDOWS_IDENTITY_PRODUCT_AGENT_ID],
    }),
    now,
    now,
  );
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, tool_policy_json, configuration_json,
      version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, 'active-directory', 'AD Attack Mapper', 'available', ?, '{}',
      'test-v1', ?, ?, ?)
  `).run(
    AUTONOMOUS_WINDOWS_IDENTITY_PRODUCT_AGENT_ID,
    JSON.stringify({
      allowedTools: [AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID],
      deniedTools: [],
      approvalRequiredTools: [],
    }),
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO agent_capabilities (
      agent_id, capability, source, enabled, metadata_json
    ) VALUES (?, ?, 'autonomous-identity-test', 1, ?)
  `).run(
    AUTONOMOUS_WINDOWS_IDENTITY_PRODUCT_AGENT_ID,
    AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    JSON.stringify({
      toolId: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
      actionClassId: AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
      executionBinding: "reviewed_local_process",
    }),
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, current_plan_id,
      current_step_id, current_owner_id, progress, status_reason,
      budget_json, budget_usage_json, started_at, created_at, updated_at,
      version, control_plane, contract_version_bound, contract_hash_bound
    ) VALUES (
      'run-autonomous-identity', 'mission-autonomous-identity', 'autonomous',
      'running', 'contract-autonomous-identity', 'plan-autonomous-identity',
      'step-autonomous-identity', ?, 0.2, 'Run one anonymous SMB summary',
      '{"toolCalls":1}', '{}', ?, ?, ?, 1, 'ti_scale', 1, ?
    )
  `).run(
    AUTONOMOUS_WINDOWS_IDENTITY_PRODUCT_AGENT_ID,
    now,
    now,
    now,
    CONTRACT_HASH,
  );
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash,
      created_by, created_at, activated_at
    ) VALUES (
      'plan-autonomous-identity', 'run-autonomous-identity', 1, 'active',
      'Run one exact anonymous SMB identity summary', ?,
      'planner:test', ?, ?
    )
  `).run("a".repeat(64), now, now);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      action_class, assigned_agent_id, created_at, updated_at
    ) VALUES (
      'step-autonomous-identity', 'plan-autonomous-identity',
      'run-autonomous-identity', 0, 'anonymous_smb_identity_summary',
      'Read SMB identity', 'Collect an unverified SMB identity observation',
      'running', ?, ?, ?, ?
    )
  `).run(
    AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
    AUTONOMOUS_WINDOWS_IDENTITY_PRODUCT_AGENT_ID,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, lease_owner,
      lease_acquired_at, last_heartbeat_at, lease_expires_at,
      started_at, created_at, updated_at
    ) VALUES (
      'assignment-autonomous-identity', 'run-autonomous-identity',
      'step-autonomous-identity', ?, 'active', 'worker:test', ?, ?,
      '2026-07-25T12:05:00.000Z', ?, ?, ?
    )
  `).run(
    AUTONOMOUS_WINDOWS_IDENTITY_PRODUCT_AGENT_ID,
    now,
    now,
    now,
    now,
    now,
  );
  const envelope = Object.freeze({
    schemaVersion: "ti-scale.reviewed-local-tool-action.v1" as const,
    executionBinding: "reviewed_local_process" as const,
    toolId: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    parameters: Object.freeze({
      authenticationMode: "anonymous",
      operation: "smb_identity_summary",
      target: TARGET,
      workspace: WORKSPACE,
    }),
  });
  const intent: DurableActionIntent = {
    missionId: "mission-autonomous-identity",
    runId: "run-autonomous-identity",
    stepId: "step-autonomous-identity",
    assignmentId: "assignment-autonomous-identity",
    planVersion: 1,
    actionType: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    actionClass: AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
    target: TARGET,
    arguments: envelope,
    kind: "tool",
    intentSummary: "Read the exact approved host's anonymous SMB identity",
    idempotent: true,
    destructive: false,
  };
  const action = new ActionRepository(database).create({
    intent,
    fingerprint: fingerprintAction(intent).hash,
    contractId: "contract-autonomous-identity",
    now,
  });
  const lease = new ControlPlaneLeaseService(database);
  const leaseToken = "autonomous-identity-test-token";
  lease.acquire({
    runId: action.runId,
    controlPlane: "ti_scale",
    leaseOwner: "runtime:test",
    leaseToken,
    ttlMs: 5 * 60_000,
    now: NOW,
  });
  return { database, action, lease, leaseToken };
}

function execution(
  seeded: ReturnType<typeof seed>,
  adapter: WindowsIdentityExecutionAdapter,
): WindowsIdentityAutonomousExecutionPort {
  return new WindowsIdentityAutonomousExecutionPort({
    database: seeded.database,
    pack: new WindowsIdentityToolPack(),
    adapter,
    assertControlPlaneAuthority: (runId) =>
      seeded.lease.assertMutationAuthority({
        runId,
        controlPlane: "ti_scale",
        leaseOwner: "runtime:test",
        leaseToken: seeded.leaseToken,
        now: NOW,
      }),
    now: () => NOW,
  });
}

function noOpExecutionPort(): ResultAwareExecutionPort {
  return {
    async dispatch() {},
    async resume() {},
    async cancelRun() {},
  };
}

function delegatedFactory(
  contract: unknown = DELEGATED_LOCAL_PROCESS_CONTRACT,
): ProductionAutonomousLocalProcessExecutionFactory {
  return {
    localProcessContract: contract,
    create: () => noOpExecutionPort(),
  } as unknown as ProductionAutonomousLocalProcessExecutionFactory;
}

describe("AutonomousWindowsIdentityExecutionFactory trust boundary", () => {
  test("accepts one exact immutable delegated contract before exposing and creating the composite route", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    databases.push(database);
    migrateDatabase(database);
    const factory = new AutonomousWindowsIdentityExecutionFactory(
      delegatedFactory(),
      {
        pack: new WindowsIdentityToolPack(),
        adapter: new LoopbackAutonomousIdentityAdapter(),
        now: () => NOW,
      },
    );

    expect(factory.localProcessContract).toBe(
      AUTONOMOUS_WINDOWS_IDENTITY_EXECUTION_CONTRACT,
    );
    const port = factory.create({
      database,
      assertControlPlaneAuthority() {
        throw new Error("No action was authorized in this composition test");
      },
    });
    expect(typeof port.dispatch).toBe("function");
    expect(typeof port.resume).toBe("function");
    expect(typeof port.cancelRun).toBe("function");
  });

  test("rejects mutable, malformed, self-referential, and changed delegated contracts", () => {
    const exactButMutable = {
      ...DELEGATED_LOCAL_PROCESS_CONTRACT,
    };
    const malformed = Object.freeze({
      ...DELEGATED_LOCAL_PROCESS_CONTRACT,
      shell: true,
    });
    const extraAuthorityClaim = Object.freeze({
      ...DELEGATED_LOCAL_PROCESS_CONTRACT,
      grantsMissionExecution: true,
    });
    const selfReferential = Object.freeze({
      ...DELEGATED_LOCAL_PROCESS_CONTRACT,
      adapterId:
        AUTONOMOUS_WINDOWS_IDENTITY_EXECUTION_CONTRACT.adapterId,
    });
    for (const contract of [
      exactButMutable,
      malformed,
      extraAuthorityClaim,
      selfReferential,
    ]) {
      expect(() => new AutonomousWindowsIdentityExecutionFactory(
        delegatedFactory(contract),
        {
          pack: new WindowsIdentityToolPack(),
          adapter: new LoopbackAutonomousIdentityAdapter(),
          now: () => NOW,
        },
      )).toThrow("Autonomous Windows/identity composition");
    }

    const mutableFactory = delegatedFactory() as unknown as {
      localProcessContract: unknown;
      create: ProductionAutonomousLocalProcessExecutionFactory["create"];
    };
    const factory = new AutonomousWindowsIdentityExecutionFactory(
      mutableFactory as ProductionAutonomousLocalProcessExecutionFactory,
      {
        pack: new WindowsIdentityToolPack(),
        adapter: new LoopbackAutonomousIdentityAdapter(),
        now: () => NOW,
      },
    );
    mutableFactory.localProcessContract = Object.freeze({
      ...DELEGATED_LOCAL_PROCESS_CONTRACT,
      adapterId: "ti-scale:test-replaced-safe-recon-base",
    });
    expect(() => factory.create({
      database: {} as SqliteDatabase,
      assertControlPlaneAuthority() {
        throw new Error("No action was authorized in this composition test");
      },
    })).toThrow("changed delegated local-process execution contract");
  });
});

describe("WindowsIdentityAutonomousExecutionPort", () => {
  test("executes only the exact anonymous NXC action and retains logs plus unverified observations without evidence", async () => {
    const seeded = seed();
    const adapter = new LoopbackAutonomousIdentityAdapter();
    const port = execution(seeded, adapter);
    let accepted = false;
    port.bindResultSink({
      async acceptExecutionResult(result) {
        expect(result).toMatchObject({
          actionId: seeded.action.id,
          runId: seeded.action.runId,
          actionFingerprint: seeded.action.fingerprint,
          success: true,
        });
        accepted = true;
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

    await port.dispatch(seeded.action, new AbortController().signal);
    await waitFor(() => expect(accepted).toBeTrue());

    expect(adapter.invocations).toHaveLength(1);
    expect(adapter.invocations[0]).toMatchObject({
      journey: "autonomous",
      toolId: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
      operation: "smb_identity_summary",
      target: TARGET,
      logicalWorkspace: WORKSPACE,
      credentialReference: null,
      credentialBindingReceipt: null,
      directArgv: true,
      shell: false,
      targetReadOnly: true,
      evidencePromotion: "none",
    });
    expect(adapter.invocations[0]!.arguments).toEqual(expect.arrayContaining([
      "--no-write-check",
      "--no-bruteforce",
      "-u",
      "-p",
    ]));
    expect(adapter.invocations[0]!.arguments.at(-3)).toBe("");
    expect(adapter.invocations[0]!.arguments.at(-1)).toBe("");

    const call = seeded.database.prepare(`
      SELECT provider, tool_name, status, normalized_arguments_json,
        redacted_payload_json
      FROM tool_calls WHERE action_id = ?
    `).get(seeded.action.id) as {
      provider: string;
      tool_name: string;
      status: string;
      normalized_arguments_json: string;
      redacted_payload_json: string;
    };
    expect(call).toMatchObject({
      provider: "reviewed-autonomous-windows-identity-process",
      tool_name: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
      status: "succeeded",
    });
    expect(JSON.parse(call.normalized_arguments_json)).toMatchObject({
      executionBinding: "reviewed_local_process",
      toolId: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
      parameters: {
        authenticationMode: "anonymous",
        operation: "smb_identity_summary",
        target: TARGET,
        workspace: WORKSPACE,
      },
    });
    expect(JSON.parse(call.redacted_payload_json)).toMatchObject({
      resultAccepted: true,
      evidenceCandidateIds: [],
    });
    expect(seeded.database.prepare(`
      SELECT domain, record_type, severity FROM engagement_log_records
      WHERE action_id = ?
    `).get(seeded.action.id)).toEqual({
      domain: "windows_identity",
      record_type: "tool_result",
      severity: "notice",
    });
    expect(seeded.database.prepare(`
      SELECT observation_type, verification_state, source_tool
      FROM observations WHERE run_id = ?
    `).get(seeded.action.runId)).toEqual({
      observation_type: "smb_host_identity",
      verification_state: "unverified",
      source_tool: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    });
    expect(seeded.database.prepare(
      "SELECT COUNT(*) AS count FROM evidence_candidates WHERE run_id = ?",
    ).get(seeded.action.runId)).toEqual({ count: 0 });
    expect(seeded.database.prepare(
      "SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?",
    ).get(seeded.action.runId)).toEqual({ count: 0 });
  });

  test("replays a committed terminal result after a lost acknowledgement without duplicating operational truth", async () => {
    const seeded = seed();
    const adapter = new LoopbackAutonomousIdentityAdapter();
    const port = execution(seeded, adapter);
    let failedDeliveryObserved = false;
    const unbind = port.bindResultSink({
      async acceptExecutionResult() {
        failedDeliveryObserved = true;
        throw new Error("simulated acknowledgement loss");
      },
    });
    await port.dispatch(seeded.action, new AbortController().signal);
    await waitFor(() => {
      expect(failedDeliveryObserved).toBeTrue();
      const payload = JSON.parse((seeded.database.prepare(`
        SELECT redacted_payload_json FROM tool_calls WHERE action_id = ?
      `).get(seeded.action.id) as { redacted_payload_json: string })
        .redacted_payload_json);
      expect(payload).toMatchObject({
        resultAccepted: false,
        deliveryAttemptCount: 1,
        deliveryLastError: "runtime_result_delivery_failed",
      });
    });
    unbind();
    let replayed = 0;
    port.bindResultSink({
      async acceptExecutionResult(result) {
        replayed += 1;
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
    expect(replayed).toBe(1);
    expect(seeded.database.prepare(`
      SELECT COUNT(*) AS count FROM engagement_log_records WHERE action_id = ?
    `).get(seeded.action.id)).toEqual({ count: 1 });
    expect(seeded.database.prepare(`
      SELECT COUNT(*) AS count FROM observations WHERE run_id = ?
    `).get(seeded.action.runId)).toEqual({ count: 1 });
    expect(seeded.database.prepare(
      "SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?",
    ).get(seeded.action.runId)).toEqual({ count: 0 });
  });

  test("resume leaves a rejected committed result pending without contacting the target again", async () => {
    const seeded = seed();
    const adapter = new LoopbackAutonomousIdentityAdapter();
    const port = execution(seeded, adapter);
    let deliveryAttempts = 0;
    port.bindResultSink({
      async acceptExecutionResult() {
        deliveryAttempts += 1;
        throw new Error("simulated unavailable mission runtime");
      },
    });

    await port.dispatch(seeded.action, new AbortController().signal);
    await waitFor(() => expect(deliveryAttempts).toBe(1));
    await port.resume(seeded.action, new AbortController().signal);

    expect(deliveryAttempts).toBe(2);
    expect(adapter.invocations).toHaveLength(1);
    const call = seeded.database.prepare(`
      SELECT status, redacted_payload_json FROM tool_calls
      WHERE action_id = ?
    `).get(seeded.action.id) as {
      status: string;
      redacted_payload_json: string;
    };
    expect(call.status).toBe("succeeded");
    expect(JSON.parse(call.redacted_payload_json)).toMatchObject({
      deliveryState: "pending",
      resultAccepted: false,
      deliveryAttemptCount: 2,
      deliveryLastError: "runtime_result_delivery_failed",
      deliveryTerminalMessage: null,
    });
    expect(seeded.database.prepare(`
      SELECT COUNT(*) AS count FROM engagement_log_records WHERE action_id = ?
    `).get(seeded.action.id)).toEqual({ count: 1 });
  });

  test("cancellation settles without ordinary failure delivery or recovery execution", async () => {
    const seeded = seed();
    const adapter = new LoopbackAutonomousIdentityAdapter();
    adapter.hold = true;
    const port = execution(seeded, adapter);
    let delivered = 0;
    port.bindResultSink({
      async acceptExecutionResult(result) {
        delivered += 1;
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

    await port.dispatch(seeded.action, new AbortController().signal);
    await waitFor(() => expect(adapter.invocations).toHaveLength(1));
    await port.cancelRun(seeded.action.runId, "operator cancelled fixture");
    await Bun.sleep(10);

    expect(adapter.cancellationCount).toBe(1);
    expect(delivered).toBe(0);
    expect(seeded.database.prepare(`
      SELECT status, error_category, redacted_payload_json
      FROM tool_calls WHERE action_id = ?
    `).get(seeded.action.id)).toEqual({
      status: "cancelled",
      error_category: null,
      redacted_payload_json: null,
    });
    expect(seeded.database.prepare(`
      SELECT COUNT(*) AS count FROM engagement_log_records WHERE action_id = ?
    `).get(seeded.action.id)).toEqual({ count: 0 });

    await port.resume(seeded.action, new AbortController().signal);
    expect(adapter.invocations).toHaveLength(1);
    expect(delivered).toBe(0);
  });

  test("stops durable pending-result delivery after eight attempts with operator-readable metadata", async () => {
    const seeded = seed();
    const adapter = new LoopbackAutonomousIdentityAdapter();
    const port = execution(seeded, adapter);
    let deliveryAttempts = 0;
    port.bindResultSink({
      async acceptExecutionResult() {
        deliveryAttempts += 1;
        throw new Error("simulated unavailable mission runtime");
      },
    });

    await port.dispatch(seeded.action, new AbortController().signal);
    await waitFor(() => expect(deliveryAttempts).toBe(1));
    for (let attempt = 1; attempt < 8; attempt += 1) {
      expect(await port.replayPendingResults()).toBe(0);
    }

    expect(deliveryAttempts).toBe(8);
    expect(await port.replayPendingResults()).toBe(0);
    await port.resume(seeded.action, new AbortController().signal);
    expect(deliveryAttempts).toBe(8);
    expect(adapter.invocations).toHaveLength(1);

    const call = seeded.database.prepare(`
      SELECT output_summary, redacted_payload_json FROM tool_calls
      WHERE action_id = ?
    `).get(seeded.action.id) as {
      output_summary: string;
      redacted_payload_json: string;
    };
    expect(JSON.parse(call.redacted_payload_json)).toMatchObject({
      deliveryState: "retry_exhausted",
      resultAccepted: false,
      duplicateResult: false,
      deliveryAttemptCount: 8,
      deliveryLastError: "runtime_result_delivery_failed",
      deliveryTerminalMessage: expect.stringContaining(
        "stopped after 8 unsuccessful attempts",
      ),
    });
    expect(call.output_summary).toContain(
      "stopped after 8 unsuccessful attempts",
    );
  });

  test("rejects a changed action before adapter execution", async () => {
    const seeded = seed();
    const adapter = new LoopbackAutonomousIdentityAdapter();
    const port = execution(seeded, adapter);
    port.bindResultSink({
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
    const changed: DurableAction = {
      ...seeded.action,
      arguments: {
        ...seeded.action.arguments,
        parameters: {
          ...(seeded.action.arguments.parameters as Record<string, unknown>),
          authenticationMode: "credential_reference",
        },
      },
    };
    await expect(
      port.dispatch(changed, new AbortController().signal),
    ).rejects.toThrow(
      "Only the exact running canonical anonymous NetExec action",
    );
    expect(adapter.invocations).toHaveLength(0);
    expect(seeded.database.prepare(
      "SELECT COUNT(*) AS count FROM tool_calls",
    ).get()).toEqual({ count: 0 });
  });
});

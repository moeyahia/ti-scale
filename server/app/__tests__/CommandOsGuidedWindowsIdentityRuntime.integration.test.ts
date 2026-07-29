import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createServer, type Server } from "node:http";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CompositeGuidedExecutionPort,
  FailClosedManualExecutionPort,
  LocalGuidedManualPlanner,
  createProductionGuidedCompositeRuntime,
  localGuidedManualAgentProjection,
  type MissionRuntimeEngine,
} from "../../command-runtime";
import { emptyRuntimeSourceManifests } from "../../domain";
import { RunRepository } from "../../orchestration";
import { createMissionRuntimeV2Router } from "../../routes/missionRuntimeV2Routes";
import {
  WINDOWS_IDENTITY_READINESS_SCHEMA_VERSION,
  WindowsIdentityCapabilityRegistry,
  WindowsIdentityGuidedExecutionPort,
  type CompiledWindowsIdentityInvocation,
  type WindowsIdentityExecutionAdapter,
  type WindowsIdentityRawResult,
  type WindowsIdentityToolId,
  type WindowsIdentityToolReadinessReceipt,
} from "../../windows-identity-tools";
import {
  applyWindowsIdentityRuntimeProjection,
  projectWindowsIdentityRuntime,
} from "../WindowsIdentityRuntimeComposition";
import { sanitizeJson } from "../../operations/validation";
import { createCommandOsApplication, type CommandOsApplication } from "../CommandOsApplication";
import type { RuntimeProjectionInput } from "../RuntimeProjectionService";

const applications: CommandOsApplication[] = [];
const runtimes: MissionRuntimeEngine[] = [];
const servers: Server[] = [];
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(runtimes.splice(0).map((runtime) => runtime.stop()));
  await Promise.all(servers.splice(0).map((server) =>
    new Promise<void>((resolve) => server.close(() => resolve()))));
  await Promise.all(applications.splice(0).map((application) => application.stop()));
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function baselineProjection(): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: false,
      delegationEnforced: false,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: false,
      specialistsConfigured: 0,
      providers: [],
      mcp: {
        enabled: false,
        executionMode: "disabled",
        startPermitted: false,
        configuredServers: 0,
        runnableServers: 0,
        missingDependencies: 0,
        missingSecrets: 0,
      },
      eventStream: "healthy",
      secondBrain: "healthy",
      legacyExecutionEnabled: false,
      guidedManualPlanning: {
        status: "ready",
        plannerId: "ti-scale.local-guided-manual-planner",
        executionMode: "manual_only",
        targetInteraction: "operator_only",
        providerContact: false,
        toolDispatch: false,
        reason: "Manual representation remains the fail-closed fallback.",
      },
    },
    agents: [localGuidedManualAgentProjection()],
    mcpServers: [],
    capabilityManifests: emptyRuntimeSourceManifests(),
  };
}

function receipt(
  registry: WindowsIdentityCapabilityRegistry,
  toolId: WindowsIdentityToolId,
): WindowsIdentityToolReadinessReceipt {
  const definition = registry.pack.resolveTool(toolId)!;
  const now = new Date();
  return {
    schemaVersion: WINDOWS_IDENTITY_READINESS_SCHEMA_VERSION,
    toolId,
    executablePath: definition.executable.path,
    expectedExecutableSha256: definition.executable.sha256,
    observedExecutableSha256: definition.executable.sha256,
    registryBindingSha256: "a".repeat(64),
    preflightBindingSha256: "b".repeat(64),
    status: "ready",
    code: "ready",
    directArgv: true,
    shell: false,
    targetContact: false,
    workspaceConfinementReady: true,
    credentialIsolationReady: true,
    outputBoundReady: true,
    cancellationReady: true,
    explanation: "Fixture binding is ready.",
    remediation: null,
    observedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60_000).toISOString(),
    grantsMissionExecution: false,
  };
}

class LoopbackIdentityAdapter implements WindowsIdentityExecutionAdapter {
  readonly adapterId = "ti-scale:test-windows-identity";
  hold = false;
  cancelCount = 0;
  startedCount = 0;
  private pending?: {
    invocation: CompiledWindowsIdentityInvocation;
    resolve: (result: WindowsIdentityRawResult) => void;
  };

  readiness(): WindowsIdentityToolReadinessReceipt | null {
    return null;
  }

  private result(
    invocation: CompiledWindowsIdentityInvocation,
    cancelled = false,
  ): WindowsIdentityRawResult {
    const startedAt = new Date().toISOString();
    const stdout = cancelled
      ? ""
      : "Disk|IPC$|Remote IPC\nAuthorization: Bearer fixture-secret\n";
    const stderr = "";
    const outputSha256 = createHash("sha256")
      .update(stdout).update("\u0000").update(stderr).digest("hex");
    const endedAt = new Date().toISOString();
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
      startedAt,
      endedAt,
      receipt: {
        schemaVersion: "ti-scale.windows-identity-execution-receipt.v1",
        adapterId: this.adapterId,
        toolId: invocation.toolId,
        actionFingerprint: invocation.actionFingerprint,
        runId: invocation.action.runId,
        executableSha256: invocation.executableSha256,
        sandboxExecutableSha256: "c".repeat(64),
        logicalWorkspace: invocation.logicalWorkspace,
        credentialReferenceId: null,
        directArgv: true,
        shell: false,
        targetReadOnly: true,
        workspaceConfined: true,
        credentialsMountedReadOnly: true,
        outputRedacted: true,
        outputSha256,
        startedAt,
        endedAt,
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

  execute(
    invocation: CompiledWindowsIdentityInvocation,
    signal: AbortSignal,
  ): Promise<WindowsIdentityRawResult> {
    this.startedCount += 1;
    if (!this.hold) return Promise.resolve(this.result(invocation));
    return new Promise((resolve) => {
      this.pending = { invocation, resolve };
      signal.addEventListener("abort", () => resolve(this.result(invocation, true)), { once: true });
    });
  }

  async cancelRun(): Promise<void> {
    this.cancelCount += 1;
    const pending = this.pending;
    this.pending = undefined;
    if (pending) pending.resolve(this.result(pending.invocation, true));
  }
}

async function waitFor(predicate: () => boolean, message: string): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(message);
}

async function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-guided-identity-"));
  roots.push(root);
  const registry = new WindowsIdentityCapabilityRegistry();
  const readyReceipt = receipt(registry, "kali:smbclient-share-list");
  const activation = {
    schemaVersion: "ti-scale.windows-identity-activation-snapshot.v1" as const,
    status: "ready" as const,
    checkedAt: new Date().toISOString(),
    adapterId: "ti-scale:test-windows-identity",
    readyToolIds: ["kali:smbclient-share-list"],
    receipts: [readyReceipt],
    reason: "One anonymous loopback-safe fixture binding is ready.",
  };
  const identityProjection = projectWindowsIdentityRuntime({
    baselineManifests: emptyRuntimeSourceManifests(),
    registry,
    activation,
  });
  const projection = applyWindowsIdentityRuntimeProjection(
    baselineProjection(),
    identityProjection,
  );
  let runtime: MissionRuntimeEngine | undefined;
  const application = createCommandOsApplication({
    databasePath: join(root, "ti-scale.sqlite"),
    readinessProviders: () => [],
    runtimeProjection: () => projection,
    resolveActor: () => "operator:test",
    assertRunMutationLease: ({ runId }) => runtime?.assertControlPlaneMutationAuthority(runId),
    projectionIntervalMs: 60_000,
  });
  applications.push(application);
  const adapter = new LoopbackIdentityAdapter();
  const identityExecution = new WindowsIdentityGuidedExecutionPort({
    database: application.database,
    pack: registry.pack,
    adapter,
    assertControlPlaneAuthority: (runId) => {
      if (!runtime) throw new Error("Runtime authority is unavailable");
      return runtime.assertControlPlaneMutationAuthority(runId);
    },
  });
  const execution = new CompositeGuidedExecutionPort(
    new FailClosedManualExecutionPort(),
    identityExecution,
  );
  runtime = createProductionGuidedCompositeRuntime({
    database: application.database,
    brainContext: application.brainContext,
    fallbackPlanner: new LocalGuidedManualPlanner(),
    windowsIdentityPack: registry.pack,
    windowsIdentityLogicalWorkspace: "/engagements",
    readReadyWindowsIdentityToolIds: () => new Set(["kali:smbclient-share-list"]),
    execution,
    workerId: "guided-windows-identity-integration",
  });
  runtimes.push(runtime);
  const web = express();
  web.use(express.json({ limit: "1mb" }));
  web.use(application.router);
  web.use(createMissionRuntimeV2Router({ runtime, resolveActor: () => "operator:test" }));
  const server = createServer(web);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Fixture server did not bind");
  application.start();
  await runtime.start();
  return {
    application,
    adapter,
    identityExecution,
    runtime,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

async function createMission(baseUrl: string, suffix: string) {
  const response = await fetch(`${baseUrl}/api/v2/missions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": `windows-identity-create-${suffix}`,
    },
    body: JSON.stringify({
      journey: "guided",
      launch: true,
      authorizationConfirmed: true,
      title: `Windows identity fixture ${suffix}`,
      objective: "Read the SMB share list from the exact authorized loopback host",
      target: "127.0.0.1",
      engagementId: `eng-windows-identity-${suffix}`,
      explanationDepth: "balanced",
      executionPreference: "single_step_agent",
      evidenceExpectations: [],
      guidedWindowsIdentity: {
        operation: "smb_share_list",
        authenticationMode: "anonymous",
        credentialReference: null,
      },
    }),
  });
  const body = await response.json() as Record<string, any>;
  if (!response.ok) throw new Error(`${response.status}: ${JSON.stringify(body)}`);
  return body;
}

describe("single-engine Guided Windows/identity integration", () => {
  test("requires the exact decision, projects it consumed, redacts logs, and creates zero evidence", async () => {
    const { application, adapter, identityExecution, runtime, baseUrl } = await fixture();
    const created = await createMission(baseUrl, "exact-decision-0001");
    const runId = created.run.id as string;
    await waitFor(
      () => runtime.repository.getRunProjection(runId).status === "waiting_guided_decision",
      "Run did not reach waiting_guided_decision",
    );
    expect(adapter.startedCount).toBe(0);
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM actions WHERE run_id = ?").get(runId))
      .toEqual({ count: 0 });
    expect(application.database.prepare(`
      SELECT COUNT(*) AS count FROM tool_calls tc
      JOIN actions a ON a.id = tc.action_id WHERE a.run_id = ?
    `).get(runId)).toEqual({ count: 0 });

    const decisionRow = application.database.prepare(`
      SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
    `).get(runId) as { id: string };
    const decision = runtime.repository.requireCurrentPendingDecision(decisionRow.id);
    const rejected = await fetch(`${baseUrl}/api/v2/guided-decisions/${decision.id}/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "windows-identity-wrong-decision-0001",
      },
      body: JSON.stringify({
        expectedFingerprint: "0".repeat(64),
        expectedParameters: sanitizeJson(decision.requestedParameters),
        reason: "This deliberately mismatched decision must not execute",
      }),
    });
    expect(rejected.status).toBe(409);
    expect(adapter.startedCount).toBe(0);

    const approved = await fetch(`${baseUrl}/api/v2/guided-decisions/${decision.id}/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "windows-identity-right-decision-0001",
      },
      body: JSON.stringify({
        expectedFingerprint: decision.actionFingerprint,
        expectedParameters: sanitizeJson(decision.requestedParameters),
        reason: "Run only this exact anonymous SMB share-list step",
      }),
    });
    if (!approved.ok) {
      throw new Error(`Guided decision approval failed (${approved.status}): ${await approved.text()}`);
    }
    expect(approved.status).toBe(200);
    await waitFor(
      () => runtime.repository.getRunProjection(runId).status === "completed",
      "Run did not complete",
    );
    expect(adapter.startedCount).toBe(1);
    expect(new RunRepository(application.database).guidedDecision(decision.id)?.status).toBe("consumed");
    expect(application.database.prepare(`
      SELECT provider, tool_name, status FROM tool_calls
      WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
    `).get(runId)).toEqual({
      provider: "reviewed-windows-identity-process",
      tool_name: "kali:smbclient-share-list",
      status: "succeeded",
    });
    const log = application.database.prepare(`
      SELECT domain, technical_payload_json FROM engagement_log_records WHERE run_id = ?
    `).get(runId) as { domain: string; technical_payload_json: string };
    expect(log.domain).toBe("windows_identity");
    expect(log.technical_payload_json).not.toContain("fixture-secret");
    expect(log.technical_payload_json).toContain("Authorization: [REDACTED]");
    expect(application.database.prepare(`
      SELECT verification_state, source_tool FROM observations WHERE run_id = ?
    `).get(runId)).toEqual({
      verification_state: "unverified",
      source_tool: "kali:smbclient-share-list",
    });
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates WHERE run_id = ?").get(runId))
      .toEqual({ count: 0 });
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?").get(runId))
      .toEqual({ count: 0 });
    const delivery = application.database.prepare(`
      SELECT redacted_payload_json FROM tool_calls
      WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
    `).get(runId) as { redacted_payload_json: string };
    const duplicate = await runtime.acceptExecutionResult(
      JSON.parse(delivery.redacted_payload_json).executionResult,
    );
    expect(duplicate).toMatchObject({ accepted: true, duplicate: true, runState: "completed" });
    expect(await identityExecution.replayPendingResults()).toBe(0);
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM engagement_log_records WHERE run_id = ?").get(runId))
      .toEqual({ count: 1 });
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM observations WHERE run_id = ?").get(runId))
      .toEqual({ count: 1 });
  }, 30_000);

  test("propagates run cancellation to the identity adapter without creating evidence", async () => {
    const { application, adapter, runtime, baseUrl } = await fixture();
    adapter.hold = true;
    const created = await createMission(baseUrl, "cancellation-0002");
    const runId = created.run.id as string;
    await waitFor(
      () => runtime.repository.getRunProjection(runId).status === "waiting_guided_decision",
      "Run did not reach waiting_guided_decision",
    );
    const decisionRow = application.database.prepare(`
      SELECT id FROM guided_decisions WHERE run_id = ? AND status = 'pending'
    `).get(runId) as { id: string };
    const decision = runtime.repository.requireCurrentPendingDecision(decisionRow.id);
    const approved = await fetch(`${baseUrl}/api/v2/guided-decisions/${decision.id}/approve`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "windows-identity-cancel-approve-0002",
      },
      body: JSON.stringify({
        expectedFingerprint: decision.actionFingerprint,
        expectedParameters: sanitizeJson(decision.requestedParameters),
        reason: "Start only this exact cancellable read",
      }),
    });
    if (!approved.ok) {
      throw new Error(`Guided decision approval failed (${approved.status}): ${await approved.text()}`);
    }
    expect(approved.status).toBe(200);
    await waitFor(() => adapter.startedCount === 1, "Identity adapter did not start");
    await runtime.cancelRun(
      runId,
      "operator:test",
      "Stop the bounded identity read",
      "windows-identity-cancel-command-0002",
    );
    await waitFor(
      () => runtime.repository.getRunProjection(runId).status === "cancelled",
      "Run did not cancel",
    );
    expect(adapter.cancelCount).toBeGreaterThanOrEqual(1);
    expect(application.database.prepare(`
      SELECT status FROM tool_calls
      WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
    `).get(runId)).toEqual({ status: "cancelled" });
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence_candidates WHERE run_id = ?").get(runId))
      .toEqual({ count: 0 });
    expect(application.database.prepare("SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?").get(runId))
      .toEqual({ count: 0 });
  }, 30_000);
});

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { createConnection, createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import {
  LocalToolCapabilityManifest,
  parseLocalToolCapabilityManifestDocument,
  type LocalProcessAdapterReadinessReceipt,
  type LocalProcessToolInvocation,
  type LocalProcessToolResult,
  type LocalProcessToolResultSink,
  type LocalToolActivationReceipt,
  type ReviewedLocalProcessInvocationAdapter,
} from "../../local-tools";
import {
  ActionRepository,
  REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
  type DurableAction,
} from "../../orchestration";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import type { ExecutionResult } from "../../command-runtime";
import {
  AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
  AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
} from "../../domain";
import {
  AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_NMAP_PATH,
  AUTONOMOUS_FULL_TCP_NMAP_SHA256,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AutonomousGeneralSafeReconExecutionFactory,
  LocalAutonomousContractPlanner,
  LocalVerifiedEvidenceOutcomeEvaluator,
  createAutonomousFullTcpBaselineManifest,
  createAutonomousGeneralSafeReconPlanningPolicy,
  type AutonomousDnsSafeReconConfiguration,
  type AutonomousFullTcpPlanningConfiguration,
  type AutonomousIpSafeReconConfiguration,
} from "..";
import { digestCanonicalJson } from "../../mcp";
import { buildRuntimeCapabilityProjection } from "../../domain";
import type { LoadedTrustedJson } from "../../trusted-runtime-config";
import type {
  ToolBindingReadinessReceipt,
  ToolBindingReadinessSnapshot,
} from "../../system-capabilities";
import type { LocalGuidedToolActivationSnapshot } from "../../app/LocalGuidedToolActivationCoordinator";
import type { RuntimeProjectionInput } from "../../app/RuntimeProjectionService";
import {
  AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
  attestAutonomousDnsSpecialistHeartbeat,
  attestLocalDeterministicAutonomousDnsProvider,
  composeAutonomousDnsActivation,
  parseAutonomousDnsRuntimeConfiguration,
  type AutonomousDnsRuntimeConfiguration,
} from "../../app/AutonomousDnsActivationCoordinator";

const NOW = new Date("2026-07-22T12:00:00.000Z");
const TARGET = "127.0.0.1";
const MISSION_ID = "mission-autonomous-general-loopback";
const RUN_ID = "run-autonomous-general-loopback";
const PLAN_ID = "plan-autonomous-general-loopback";
const STEP_ID = "step-autonomous-general-full-tcp";
const CONTRACT_ID = "contract-autonomous-general-loopback";
const CONTRACT_HASH = "c".repeat(64);
const MODEL_HASH = "a".repeat(64);
const AGENT_ID = "specialist:autonomous-general-recon";
const PRODUCT_AGENT_ID = "ReconScout";
const OWNER = "runtime:autonomous-general-loopback";
const CRITERION = AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION;

const databases: SqliteDatabase[] = [];
const roots: string[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) =>
    server.close(() => resolve()))));
  for (const database of databases.splice(0)) database.close();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function database(): SqliteDatabase {
  const value = createDatabaseConnection({ filename: ":memory:" });
  databases.push(value);
  migrateDatabase(value);
  return value;
}

function generalManifest(): LocalToolCapabilityManifest {
  const base = parseLocalToolCapabilityManifestDocument(JSON.parse(readFileSync(
    new URL("../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json", import.meta.url),
    "utf8",
  )) as unknown);
  const full = createAutonomousFullTcpBaselineManifest();
  const fullTools = full.list().map(({ bindingSha256: _bindingSha256, ...tool }) => tool);
  return new LocalToolCapabilityManifest({
    ...base,
    manifestVersion: "autonomous-general-safe-recon-loopback-v1",
    tools: [...base.tools, ...fullTools],
  });
}

function configurations(workspace: string): Readonly<{
  dns: AutonomousDnsSafeReconConfiguration;
  ip: AutonomousIpSafeReconConfiguration;
  fullTcp: AutonomousFullTcpPlanningConfiguration;
}> {
  const common = {
    policyId: "reviewed-autonomous-general-loopback-v1",
    agentId: AGENT_ID,
    providerId: "provider:local-deterministic-general-loopback",
    modelId: "policy:local-general-loopback-v1",
    modelConfigurationHash: MODEL_HASH,
    logicalWorkspace: workspace,
  } as const;
  return {
    dns: {
      ...common,
      bindingId: "binding:autonomous-general-dns-loopback-v1",
      recordType: "A",
      successCriterion: AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
    },
    ip: {
      ...common,
      livenessBindingId: "binding:autonomous-general-liveness-loopback-v1",
      serviceScanBindingId: "binding:autonomous-general-bounded-services-unused-v1",
      ports: [22, 80, 443],
      livenessSuccessCriterion: AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
      serviceScanSuccessCriterion: AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
    },
    fullTcp: {
      ...common,
      bindingId: "binding:autonomous-general-full-tcp-loopback-v2",
      successCriterion: CRITERION,
    },
  };
}

function seed(db: SqliteDatabase, workspace: string): DurableAction {
  const now = NOW.toISOString();
  db.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      success_criteria_json, memory_policy_json, created_by, created_at,
      updated_at, control_plane
    ) VALUES (?, 'Autonomous general loopback', 'Verify exact-IP Full-TCP evidence',
      'autonomous', 'active', 'verified', ?, '{}', 'operator:test', ?, ?, 'ti_scale')
  `).run(MISSION_ID, JSON.stringify([CRITERION]), now, now);
  db.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, disposition, normalized_target, created_at
    ) VALUES ('target-general-loopback', ?, ?, 'ip', 'allowed', ?, ?)
  `).run(MISSION_ID, TARGET, TARGET, now);
  db.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, 'autonomous-safe-reconnaissance-specialist', 'General Recon', 'available',
      '{}', ?, '{}', 'test-v1', ?, ?, ?)
  `).run(AGENT_ID, JSON.stringify({
    allowedTools: [
      AUTONOMOUS_IP_LIVENESS_TOOL_ID,
      AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    ],
    deniedTools: [],
    approvalRequiredTools: [],
  }), now, now, now);
  for (const toolId of [
    AUTONOMOUS_IP_LIVENESS_TOOL_ID,
    AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  ]) {
    db.prepare(`
      INSERT INTO agent_capabilities (agent_id, capability, source, enabled)
      VALUES (?, ?, 'live-route-attestation', 1)
    `).run(AGENT_ID, toolId);
  }
  db.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{"toolCalls":3,"retries":0}',
      '{"conditions":[]}', '["machine_readable_export","pdf_html_markdown_report"]',
      '[]', 'operator:test', ?, ?)
  `).run(CONTRACT_ID, MISSION_ID, CONTRACT_HASH, JSON.stringify({
    allowedActionClasses: [
      AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
      AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
    ],
    prohibitedActionClasses: [],
    destructivePolicy: "prohibited",
    boundedDestructiveTargets: [],
    evidenceRequirements: ["port_service_scan_result", "service_version_fingerprint"],
    specialistAgentIds: [AGENT_ID],
  }), now, now);
  db.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, current_plan_id,
      current_step_id, progress, status_reason, budget_json, budget_usage_json,
      started_at, created_at, updated_at, version, control_plane,
      contract_version_bound, contract_hash_bound
    ) VALUES (?, ?, 'autonomous', 'running', ?, ?, ?, 0, 'Run exact-IP Full-TCP',
      '{"toolCalls":3,"retries":0}', '{}', ?, ?, ?, 1, 'ti_scale', 1, ?)
  `).run(RUN_ID, MISSION_ID, CONTRACT_ID, PLAN_ID, STEP_ID, now, now, now, CONTRACT_HASH);
  db.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, rationale_summary,
      plan_hash, created_by, created_at, activated_at
    ) VALUES (?, ?, 1, 'active', 'Exact-IP Full-TCP baseline',
      'Reviewed composite binding', ?, 'mission-planner', ?, ?)
  `).run(PLAN_ID, RUN_ID, "d".repeat(64), now, now);
  db.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      success_criteria_json, dependencies_json, action_class, risk_class,
      assigned_agent_id, started_at, created_at, updated_at
    ) VALUES (?, ?, ?, 0, 'full_tcp_baseline', 'Create exact-IP full TCP baseline',
      'Retain deterministic verified evidence', 'running', ?, '[]', ?, 'medium',
      ?, ?, ?, ?)
  `).run(
    STEP_ID,
    PLAN_ID,
    RUN_ID,
    JSON.stringify([CRITERION]),
    AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
    AGENT_ID,
    now,
    now,
    now,
  );
  db.prepare(`
    INSERT INTO assignments (
      id, run_id, step_id, agent_id, status, lease_owner, lease_acquired_at,
      last_heartbeat_at, lease_expires_at, started_at, created_at, updated_at
    ) VALUES ('assignment-general-loopback', ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
  `).run(
    RUN_ID,
    STEP_ID,
    AGENT_ID,
    OWNER,
    now,
    now,
    new Date(NOW.getTime() + 60_000).toISOString(),
    now,
    now,
    now,
  );
  db.prepare(`
    INSERT INTO control_plane_leases (
      run_id, control_plane, lease_owner, lease_token_hash, acquired_at,
      heartbeat_at, expires_at, released_at, version
    ) VALUES (?, 'ti_scale', ?, ?, ?, ?, ?, NULL, 1)
  `).run(
    RUN_ID,
    OWNER,
    "f".repeat(64),
    now,
    now,
    new Date(NOW.getTime() + 60_000).toISOString(),
  );
  return new ActionRepository(db).create({
    intent: {
      missionId: MISSION_ID,
      runId: RUN_ID,
      stepId: STEP_ID,
      assignmentId: "assignment-general-loopback",
      planVersion: 1,
      actionType: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
      actionClass: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
      arguments: {
        schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
        executionBinding: "reviewed_local_process",
        toolId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
        parameters: { workspace, target: TARGET },
      },
      target: TARGET,
      intentSummary: "Create exact-IP Full-TCP loopback baseline",
      kind: "tool",
      idempotent: true,
      destructive: false,
    },
    fingerprint: "9".repeat(64),
    contractId: CONTRACT_ID,
    now,
  });
}

function projectProductAgentOwner(db: SqliteDatabase): void {
  const now = NOW.toISOString();
  db.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, provider_policy_json, tool_policy_json,
      configuration_json, version, last_heartbeat_at, created_at, updated_at
    ) VALUES (?, 'reconnaissance', 'ReconScout', 'available', '{}', ?, ?,
      'test-product-v1', ?, ?, ?)
  `).run(
    PRODUCT_AGENT_ID,
    JSON.stringify({
      allowedTools: [AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE],
      deniedTools: [],
      approvalRequiredTools: [],
    }),
    JSON.stringify({
      userFacing: true,
      productAgent: true,
      runtimeBindingAgentIds: [AGENT_ID],
    }),
    now,
    now,
    now,
  );
  db.prepare(`
    INSERT INTO agent_capabilities (agent_id, capability, source, enabled)
    VALUES (?, ?, 'product-agent-roster', 1)
  `).run(PRODUCT_AGENT_ID, AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE);
  db.prepare("UPDATE plan_steps SET assigned_agent_id = ? WHERE id = ?")
    .run(PRODUCT_AGENT_ID, STEP_ID);
  db.prepare("UPDATE assignments SET agent_id = ? WHERE step_id = ?")
    .run(PRODUCT_AGENT_ID, STEP_ID);
  const contract = db.prepare(`
    SELECT action_policy_json FROM mission_contracts WHERE id = ?
  `).get(CONTRACT_ID) as { readonly action_policy_json: string };
  const actionPolicy = JSON.parse(contract.action_policy_json) as Record<string, unknown>;
  db.prepare(`
    UPDATE mission_contracts SET action_policy_json = ? WHERE id = ?
  `).run(JSON.stringify({
    ...actionPolicy,
    specialistAgentIds: [PRODUCT_AGENT_ID],
  }), CONTRACT_ID);
}

function outputHash(stdout: string, stderr: string): string {
  return createHash("sha256").update(stdout).update("\u0000").update(stderr).digest("hex");
}

function nmapOutput(port: number, versioned: boolean): string {
  return [
    "Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-22 12:00 UTC",
    `Nmap scan report for ${TARGET}`,
    "Host is up (0.0010s latency).",
    "PORT    STATE SERVICE VERSION",
    `${port}/tcp open  http${versioned ? "    disposable-loopback 1.0" : ""}`,
    "Nmap done: 1 IP address (1 host up) scanned in 0.01 seconds",
    "",
  ].join("\n");
}

async function canConnect(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host: TARGET, port });
    socket.once("connect", () => { socket.destroy(); resolve(true); });
    socket.once("error", () => resolve(false));
  });
}

class LoopbackFullTcpAdapter implements ReviewedLocalProcessInvocationAdapter {
  private sink?: LocalProcessToolResultSink;
  readonly dispatches: LocalProcessToolInvocation[] = [];

  constructor(
    private readonly manifest: LocalToolCapabilityManifest,
    private readonly port: number,
    private readonly behavior: "verified" | "invalid_discovery" = "verified",
  ) {}

  bindResultSink(sink: LocalProcessToolResultSink): () => void {
    if (this.sink) throw new Error("sink already bound");
    this.sink = sink;
    return () => { if (this.sink === sink) this.sink = undefined; };
  }

  async readinessReceipt(now = NOW, ttlMs = 60_000): Promise<LocalProcessAdapterReadinessReceipt> {
    const unsigned = {
      schemaVersion: "ti-scale.local-process-adapter-readiness.v1" as const,
      adapterId: "test:autonomous-general-loopback",
      manifestSha256: this.manifest.descriptor.manifestSha256,
      sandboxExecutableSha256: "b".repeat(64),
      tools: this.manifest.list().map((tool) => ({
        toolId: tool.toolId,
        bindingSha256: tool.bindingSha256,
        expectedExecutableSha256: tool.executable.expectedSha256,
        installationReceiptSha256: "3".repeat(64),
      })),
      sandboxExecutableIdentity: {
        sha256: "b".repeat(64), device: "1", inode: "2", sizeBytes: 1,
        mode: 0o755, uid: 0, gid: 0,
      },
      boundary: {
        platform: "linux" as const,
        directArgv: true as const,
        shell: false as const,
        fixedEnvironmentSha256: "e".repeat(64),
        workspaceResolver: true as const,
        filesystemSandbox: "bubblewrap_minimal_read_only_host_workspace_write" as const,
        totalOutputBound: true as const,
        cooperativeCancellation: true as const,
        processGroupCleanup: true as const,
        resultSinkBound: true as const,
        targetContact: false as const,
      },
      observedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
      grantsMissionExecution: false as const,
    };
    return { ...unsigned, receiptSha256: digest(unsigned) };
  }

  async dispatch(invocation: LocalProcessToolInvocation, _signal: AbortSignal): Promise<void> {
    this.dispatches.push(invocation);
    if (!this.sink || !await canConnect(this.port)) throw new Error("loopback listener unavailable");
    const stdout = this.behavior === "invalid_discovery"
      && invocation.toolId === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID
      ? [
          "Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-22 12:00 UTC",
          `Nmap scan report for ${TARGET}`,
          "Host is up (0.0010s latency).",
          "PORT    STATE SERVICE VERSION",
          `${this.port}/tcp open  http`,
          // Deliberately omit the deterministic one-host completion line.
          "",
        ].join("\n")
      : nmapOutput(this.port, invocation.toolId === AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID);
    const bytes = Buffer.byteLength(stdout);
    const result: LocalProcessToolResult = {
      invocationId: invocation.invocationId,
      action: invocation.action,
      toolId: invocation.toolId,
      startedAt: NOW.toISOString(),
      endedAt: new Date(NOW.getTime() + 100).toISOString(),
      wallClockMs: 100,
      exitCode: 0,
      signal: null,
      termination: "exited",
      spawnErrorCode: null,
      stdout,
      stderr: "",
      observedOutputBytes: bytes,
      retainedOutputBytes: bytes,
      outputSha256: outputHash(stdout, ""),
      outputTruncated: false,
      executable: {
        sourcePath: AUTONOMOUS_FULL_TCP_NMAP_PATH,
        sourceSha256: AUTONOMOUS_FULL_TCP_NMAP_SHA256,
        snapshotSha256: AUTONOMOUS_FULL_TCP_NMAP_SHA256,
        sandboxPath: "/run/ti-scale/tool",
      },
      sandbox: {
        executablePath: "/usr/bin/bwrap",
        executableSha256: "b".repeat(64),
        shell: false,
        environmentSha256: "e".repeat(64),
      },
    };
    await this.sink.acceptLocalProcessToolResult(result);
  }

  async cancelRun(): Promise<void> {}
}

function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function baselineProjection(): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: false,
      delegationEnforced: false,
      noHandsCommanderEnforced: false,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
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
    },
    agents: [],
    mcpServers: [],
  };
}

function trustedGeneralConfiguration(
  config: ReturnType<typeof configurations>,
): LoadedTrustedJson<AutonomousDnsRuntimeConfiguration> {
  const document = {
    schemaVersion: AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
    configurationVersion: "general-loopback-v1",
    dns: config.dns,
    ipRecon: config.ip,
    fullTcpBaseline: config.fullTcp,
    localProcess: { adapterId: "test:autonomous-general-loopback" },
    specialist: {
      id: AGENT_ID,
      label: "Autonomous general reconnaissance specialist",
      workerId: "worker:autonomous-general-loopback",
      version: "general-loopback-v1",
      heartbeatTtlMs: 60_000,
    },
    provider: {
      id: config.dns.providerId,
      label: "Local deterministic general reconnaissance policy",
      modelId: config.dns.modelId,
      modelConfigurationHash: config.dns.modelConfigurationHash,
      policyVersion: "general-loopback-v1",
      attestationTtlMs: 60_000,
    },
  };
  const value = parseAutonomousDnsRuntimeConfiguration(document);
  return {
    value,
    receipt: {
      schemaVersion: "ti-scale.trusted-local-file-receipt.v1",
      sourcePath: "/etc/ti-scale/trusted/autonomous-general-loopback.json",
      trustRoot: "/etc/ti-scale/trusted",
      sourceSha256: "d".repeat(64),
      canonicalSha256: digestCanonicalJson(value, {
        maxBytes: 256 * 1_024,
        maxDepth: 24,
      }).sha256,
      byteSize: Buffer.byteLength(JSON.stringify(document)),
      ownerUid: process.geteuid?.() ?? process.getuid?.() ?? 0,
      ownerGid: process.getegid?.() ?? process.getgid?.() ?? 0,
      mode: 0o600,
      device: "1",
      inode: "2",
    },
  };
}

const GENERAL_ACTIVATED_TOOL_IDS = Object.freeze([
  "kali:host-dns-query",
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
]);

function generalActivationReceipt(
  manifest: LocalToolCapabilityManifest,
  toolId: string,
): LocalToolActivationReceipt {
  const tool = manifest.resolve(toolId)!;
  return {
    schemaVersion: "ti-scale.local-tool-activation-receipt.v1",
    manifestSha256: manifest.descriptor.manifestSha256,
    toolId,
    bindingSha256: tool.bindingSha256,
    preflightBindingSha256: "b".repeat(64),
    executableSha256: tool.executable.expectedSha256,
    installationReady: true,
    isolatedProbeReady: true,
    invocationAdapterReady: true,
    workspaceConfinementReady: true,
    resultSinkReady: true,
    cancellationReady: true,
    observedAt: new Date(NOW.getTime() - 1_000).toISOString(),
    expiresAt: new Date(NOW.getTime() + 59_000).toISOString(),
  };
}

function generalBindingReceipt(
  manifest: LocalToolCapabilityManifest,
  toolId: string,
): ToolBindingReadinessReceipt {
  const tool = manifest.resolve(toolId)!;
  return {
    schemaVersion: "ti-scale.tool-binding-readiness-receipt.v2",
    registryVersion: "general-loopback-v1",
    registrySha256: "1".repeat(64),
    runtimeManifestSha256: "2".repeat(64),
    toolId,
    registryBindingSha256: "3".repeat(64),
    preflightBindingSha256: "b".repeat(64),
    status: "ready",
    code: "ready",
    checkedAt: new Date(NOW.getTime() - 1_000).toISOString(),
    expiresAt: new Date(NOW.getTime() + 59_000).toISOString(),
    probeBoundary: {
      shell: false,
      targetArgumentsSupplied: false,
      providerArgumentsSupplied: false,
      mcpArgumentsSupplied: false,
      networkIsolationEnforced: true,
      filesystemWriteIsolationEnforced: true,
      immutableSnapshotExecutionEnforced: true,
      externalContact: "not_measured",
    },
    executableIdentity: {
      sha256: tool.executable.expectedSha256,
      device: "1",
      inode: "3",
      sizeBytes: 2_048,
      mode: 0o755,
      uid: 0,
      gid: 0,
    },
    grantsMissionExecution: false,
    privilegeBoundary: {
      noNewPrivileges: true,
      capabilityTransitionConflictObserved: false,
    },
    explanation: "Target-free general loopback readiness fixture.",
    remediation: null,
    execution: {
      exitCode: 0,
      signal: null,
      spawnErrorCode: null,
      outputBytes: 12,
      outputSha256: "4".repeat(64),
    },
  };
}

function generalLocalActivation(
  manifest: LocalToolCapabilityManifest,
): LocalGuidedToolActivationSnapshot {
  const activationReceipts = GENERAL_ACTIVATED_TOOL_IDS.map((toolId) =>
    generalActivationReceipt(manifest, toolId));
  const receipts = GENERAL_ACTIVATED_TOOL_IDS.map((toolId) =>
    generalBindingReceipt(manifest, toolId));
  const toolBindingReadiness: ToolBindingReadinessSnapshot = {
    schemaVersion: "ti-scale.tool-binding-readiness-snapshot.v2",
    checkedAt: NOW.toISOString(),
    readOnly: true,
    grantsMissionExecution: false,
    probeBoundary: receipts[0]!.probeBoundary,
    registry: {
      schemaVersion: "ti-scale.tool-binding-registry.v1",
      registryVersion: "general-loopback-v1",
      registrySha256: "1".repeat(64),
      runtimeManifestSha256: "2".repeat(64),
      registeredBindingCount: receipts.length,
      runtimeToolCount: receipts.length,
      boundRuntimeToolCount: receipts.length,
      runtimeToolsWithoutLocalBinding: 0,
      sourceOfTruth: "runtime-manifest-aligned-local-bindings",
    },
    accounting: {
      registered: receipts.length,
      attempted: receipts.length,
      reported: receipts.length,
      missing: 0,
      unexpected: 0,
      ready: receipts.length,
      unavailable: 0,
      fresh: receipts.length,
      stale: 0,
      complete: true,
      current: true,
    },
    receipts,
  };
  const unsigned = {
    schemaVersion: "ti-scale.local-process-adapter-readiness.v1" as const,
    adapterId: "test:autonomous-general-loopback",
    manifestSha256: manifest.descriptor.manifestSha256,
    sandboxExecutableSha256: "b".repeat(64),
    tools: GENERAL_ACTIVATED_TOOL_IDS.map((toolId) => {
      const tool = manifest.resolve(toolId)!;
      return {
        toolId,
        bindingSha256: tool.bindingSha256,
        expectedExecutableSha256: tool.executable.expectedSha256,
        installationReceiptSha256: "5".repeat(64),
      };
    }),
    sandboxExecutableIdentity: {
      sha256: "b".repeat(64), device: "1", inode: "2", sizeBytes: 1,
      mode: 0o755, uid: 0, gid: 0,
    },
    boundary: {
      platform: "linux" as const,
      directArgv: true as const,
      shell: false as const,
      fixedEnvironmentSha256: "e".repeat(64),
      workspaceResolver: true as const,
      filesystemSandbox: "bubblewrap_minimal_read_only_host_workspace_write" as const,
      totalOutputBound: true as const,
      cooperativeCancellation: true as const,
      processGroupCleanup: true as const,
      resultSinkBound: true as const,
      targetContact: false as const,
    },
    observedAt: new Date(NOW.getTime() - 1_000).toISOString(),
    expiresAt: new Date(NOW.getTime() + 59_000).toISOString(),
    grantsMissionExecution: false as const,
  };
  return {
    schemaVersion: "ti-scale.local-guided-tool-activation-snapshot.v1",
    status: "ready",
    checkedAt: NOW.toISOString(),
    reason: "Complete target-free general Safe Recon activation fixture.",
    activationReceipts,
    installationReceipts: [],
    toolBindingReadiness,
    adapterReadiness: {
      ...unsigned,
      receiptSha256: digestCanonicalJson(unsigned, {
        maxBytes: 512 * 1_024,
        maxDepth: 24,
      }).sha256,
    },
    workspaceConfinementReady: true,
    runtimeResultSinkReady: true,
  };
}

describe("Autonomous general Safe Recon", () => {
  test("replaces the bounded service binding with one exact-IP composite binding", () => {
    const manifest = generalManifest();
    const config = configurations("/engagements/general-loopback");
    const policy = createAutonomousGeneralSafeReconPlanningPolicy(
      config.dns,
      config.ip,
      config.fullTcp,
      manifest,
    );
    expect(policy.bindings.map((binding) => ({
      actionClassId: binding.actionClassId,
      toolId: "toolId" in binding ? binding.toolId : binding.toolName,
      targetKinds: binding.targetKinds,
    }))).toEqual([{
      actionClassId: "dns_domain_certificate_discovery",
      toolId: "kali:host-dns-query",
      targetKinds: ["domain"],
    }, {
      actionClassId: AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
      toolId: AUTONOMOUS_IP_LIVENESS_TOOL_ID,
      targetKinds: ["ip", "domain"],
    }, {
      actionClassId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
      toolId: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
      targetKinds: ["ip"],
    }]);
  });

  test("composes the trusted live route from physical phase receipts while exposing only the virtual composite", () => {
    const manifest = generalManifest();
    const configValues = configurations("/engagements/general-loopback");
    const config = trustedGeneralConfiguration(configValues);
    const activation = generalLocalActivation(manifest);
    const db = database();
    const policy = createAutonomousGeneralSafeReconPlanningPolicy(
      configValues.dns,
      configValues.ip,
      configValues.fullTcp,
      manifest,
    );
    const planner = new LocalAutonomousContractPlanner({
      database: db,
      policy,
      readRuntimeProjection: baselineProjection,
      now: () => NOW,
    });
    const evaluator = new LocalVerifiedEvidenceOutcomeEvaluator(db);
    const providerAttestation = attestLocalDeterministicAutonomousDnsProvider({
      configuration: config,
      planner,
      evaluator,
      now: NOW,
    });
    const heartbeat = attestAutonomousDnsSpecialistHeartbeat({
      configuration: config,
      manifest,
      activationReceipt: activation.activationReceipts[0]!,
      activationReceipts: activation.activationReceipts,
      adapterContract: AUTONOMOUS_GENERAL_SAFE_RECON_EXECUTION_CONTRACT,
      now: NOW,
    });
    const result = composeAutonomousDnsActivation({
      database: db,
      baselineProjection: baselineProjection(),
      manifest,
      localActivation: activation,
      configuration: config,
      providerAttestation,
      specialistHeartbeat: heartbeat,
      localProcessTransport: new LoopbackFullTcpAdapter(manifest, 1),
      workspaceResolver: new EngagementWorkspaceResolver([{
        logicalRoot: "/engagements",
        runtimeRoot: "/tmp",
      }]),
      now: NOW,
    });
    if (result.status === "blocked") {
      throw new Error(`General live composition blocked: ${JSON.stringify(result.blockers)}`);
    }
    expect(result.composition).toMatchObject({
      status: "ready",
      readyActionClassIds: [
        "active_host_discovery",
        "dns_domain_certificate_discovery",
        "port_service_enumeration",
      ],
    });
    expect(result.adapters.execution).toBeInstanceOf(AutonomousGeneralSafeReconExecutionFactory);
    const manifests = result.projection.capabilityManifests!;
    const agent = manifests.agents.find(({ id }) => id === AGENT_ID)!;
    expect(agent.toolIds).toEqual([
      "kali:host-dns-query",
      AUTONOMOUS_IP_LIVENESS_TOOL_ID,
      AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    ]);
    expect(agent.toolIds).not.toContain(AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID);
    expect(agent.toolIds).not.toContain(AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID);
    expect(agent.deliverableIds).toEqual([
      "machine_readable_export",
      "pdf_html_markdown_report",
    ]);
    expect(heartbeat.tools?.map(({ toolId }) => toolId)).toEqual([
      ...GENERAL_ACTIVATED_TOOL_IDS,
    ]);
    const virtual = manifests.tools.find(({ id }) =>
      id === AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE);
    expect(virtual).toMatchObject({
      available: true,
      locallyPolicyEnforced: true,
      requiresModel: false,
      executionJourneys: ["autonomous"],
      actionClassIds: [AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS],
      evidenceTypeIds: ["port_service_scan_result", "service_version_fingerprint"],
    });
    const capability = buildRuntimeCapabilityProjection(manifests);
    expect(capability.deliverables.machine_readable_export).toMatchObject({
      availability: "supported",
      producerAgentIds: [AGENT_ID],
    });
    expect(capability.deliverables.pdf_html_markdown_report).toMatchObject({
      availability: "supported",
      producerAgentIds: [AGENT_ID],
    });
    expect(capability.deliverables.executive_summary.availability).toBe("unsupported");
    expect(capability.deliverables.technical_findings.availability).toBe("unsupported");
  });

  test("promotes Full-TCP evidence with a product-owned plan and its exact internal runtime binding", async () => {
    const server = createServer((socket) => socket.end());
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, TARGET, () => resolve());
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("missing loopback port");
    const root = await mkdtemp(join(tmpdir(), "ti-scale-general-loopback-"));
    roots.push(root);
    const workspace = join(root, "engagement");
    await mkdir(workspace, { mode: 0o700 });
    const manifest = generalManifest();
    const config = configurations(workspace);
    const db = database();
    const action = seed(db, workspace);
    projectProductAgentOwner(db);
    const adapter = new LoopbackFullTcpAdapter(manifest, address.port);
    const factory = new AutonomousGeneralSafeReconExecutionFactory({
      manifest,
      dnsConfiguration: config.dns,
      ipConfiguration: config.ip,
      fullTcpConfiguration: config.fullTcp,
      adapter,
      workspaceResolver: new EngagementWorkspaceResolver([{
        logicalRoot: root,
        runtimeRoot: root,
      }]),
      now: () => NOW,
    });
    const port = factory.create({
      database: db,
      assertControlPlaneAuthority: () => ({
        runId: RUN_ID,
        controlPlane: "ti_scale",
        leaseOwner: OWNER,
        acquiredAt: NOW.toISOString(),
        heartbeatAt: NOW.toISOString(),
        expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
        version: 1,
      }),
    });
    const delivered: ExecutionResult[] = [];
    port.bindResultSink?.({
      async acceptExecutionResult(result) {
        delivered.push(result);
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "running",
          nextAction: null,
          evidenceIds: result.progress.evidenceIds ?? [],
        };
      },
    });
    await port.dispatch(action, new AbortController().signal);

    expect(adapter.dispatches.map(({ toolId }) => toolId)).toEqual([
      AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
      AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
    ]);
    expect(delivered).toHaveLength(1);
    expect(delivered[0]?.success).toBe(true);
    expect(db.prepare(`
      SELECT ps.assigned_agent_id, a.agent_id
      FROM plan_steps ps
      JOIN assignments a ON a.step_id = ps.id
      WHERE ps.id = ?
    `).get(STEP_ID)).toEqual({
      assigned_agent_id: PRODUCT_AGENT_ID,
      agent_id: PRODUCT_AGENT_ID,
    });
    expect(db.prepare("SELECT COUNT(*) AS count FROM evidence WHERE run_id = ? AND verification_state = 'verified'")
      .get(RUN_ID)).toEqual({ count: 2 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM evidence_chain_events")
      .get()).toEqual({ count: 4 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM topology_nodes WHERE run_id = ? AND verification_state = 'verified'")
      .get(RUN_ID)).toEqual({ count: 2 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM topology_edges WHERE verification_state = 'verified'")
      .get()).toEqual({ count: 1 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM topology_evidence_links")
      .get()).toEqual({ count: 6 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM guided_decisions")
      .get()).toEqual({ count: 0 });
    expect(db.prepare("SELECT COUNT(*) AS count FROM cve_applicability_records")
      .get()).toEqual({ count: 0 });
    factory.close();
  });

  test("durably delivers an invalid Full-TCP process result as a supervised failure instead of leaving the composite running", async () => {
    const server = createServer((socket) => socket.end());
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, TARGET, () => resolve());
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("missing loopback port");
    const root = await mkdtemp(join(tmpdir(), "ti-scale-general-invalid-full-tcp-"));
    roots.push(root);
    const workspace = join(root, "engagement");
    await mkdir(workspace, { mode: 0o700 });
    const manifest = generalManifest();
    const config = configurations(workspace);
    const db = database();
    const action = seed(db, workspace);
    const adapter = new LoopbackFullTcpAdapter(manifest, address.port, "invalid_discovery");
    const factory = new AutonomousGeneralSafeReconExecutionFactory({
      manifest,
      dnsConfiguration: config.dns,
      ipConfiguration: config.ip,
      fullTcpConfiguration: config.fullTcp,
      adapter,
      workspaceResolver: new EngagementWorkspaceResolver([{
        logicalRoot: root,
        runtimeRoot: root,
      }]),
      now: () => NOW,
    });
    const port = factory.create({
      database: db,
      assertControlPlaneAuthority: () => ({
        runId: RUN_ID,
        controlPlane: "ti_scale",
        leaseOwner: OWNER,
        acquiredAt: NOW.toISOString(),
        heartbeatAt: NOW.toISOString(),
        expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
        version: 1,
      }),
    });
    const delivered: ExecutionResult[] = [];
    port.bindResultSink?.({
      async acceptExecutionResult(result) {
        delivered.push(result);
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "blocked",
          nextAction: null,
        };
      },
    });

    await expect(port.dispatch(action, new AbortController().signal)).resolves.toBeUndefined();

    expect(adapter.dispatches.map(({ toolId }) => toolId)).toEqual([
      AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
    ]);
    expect(delivered).toHaveLength(1);
    expect(delivered[0]).toMatchObject({
      actionId: action.id,
      runId: RUN_ID,
      success: false,
      failureCategory: "evidence_insufficient",
      failure: {
        source: "tool",
        code: "full_tcp_discovery_output_unverified",
      },
      progress: {},
    });
    expect(delivered[0]?.summary).toContain("failed safely");
    const terminal = db.prepare(`
      SELECT status, error_category,
        json_extract(redacted_payload_json, '$.resultAccepted') AS accepted,
        json_extract(redacted_payload_json, '$.deliveryResult.success') AS success
      FROM tool_calls WHERE tool_name = ?
    `).get(AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE);
    expect(terminal).toEqual({
      status: "failed",
      error_category: "evidence_insufficient",
      accepted: 1,
      success: 0,
    });
    expect(db.prepare("SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?").get(RUN_ID))
      .toEqual({ count: 0 });
    expect(await port.replayPendingResults?.()).toBe(0);
    factory.close();
  });

  test("turns a post-scan owner-fence rejection into a replayable worker-loss result", async () => {
    const server = createServer((socket) => socket.end());
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, TARGET, () => resolve());
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("missing loopback port");
    const root = await mkdtemp(join(tmpdir(), "ti-scale-general-owner-fence-"));
    roots.push(root);
    const workspace = join(root, "engagement");
    await mkdir(workspace, { mode: 0o700 });
    const manifest = generalManifest();
    const config = configurations(workspace);
    const db = database();
    const action = seed(db, workspace);
    db.prepare(`
      UPDATE control_plane_leases SET expires_at = ? WHERE run_id = ?
    `).run(NOW.toISOString(), RUN_ID);
    const adapter = new LoopbackFullTcpAdapter(manifest, address.port);
    const factory = new AutonomousGeneralSafeReconExecutionFactory({
      manifest,
      dnsConfiguration: config.dns,
      ipConfiguration: config.ip,
      fullTcpConfiguration: config.fullTcp,
      adapter,
      workspaceResolver: new EngagementWorkspaceResolver([{
        logicalRoot: root,
        runtimeRoot: root,
      }]),
      now: () => NOW,
    });
    const port = factory.create({
      database: db,
      assertControlPlaneAuthority: () => ({
        runId: RUN_ID,
        controlPlane: "ti_scale",
        leaseOwner: OWNER,
        acquiredAt: NOW.toISOString(),
        heartbeatAt: NOW.toISOString(),
        expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
        version: 1,
      }),
    });
    const deliveryAttempts: ExecutionResult[] = [];
    const unbindUnavailableSink = port.bindResultSink?.({
      async acceptExecutionResult(result) {
        deliveryAttempts.push(result);
        throw new Error("simulated runtime acknowledgement loss");
      },
    });

    await expect(port.dispatch(action, new AbortController().signal)).resolves.toBeUndefined();

    expect(adapter.dispatches.map(({ toolId }) => toolId)).toEqual([
      AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
      AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
    ]);
    expect(deliveryAttempts).toHaveLength(1);
    expect(deliveryAttempts[0]).toMatchObject({
      actionId: action.id,
      success: false,
      failureCategory: "worker_lost",
      failure: { code: "full_tcp_owner_fence_invalid" },
    });
    expect(db.prepare(`
      SELECT status, error_category,
        json_extract(redacted_payload_json, '$.resultAccepted') AS accepted,
        json_extract(redacted_payload_json, '$.deliveryLastError') AS delivery_error
      FROM tool_calls WHERE tool_name = ?
    `).get(AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE)).toEqual({
      status: "failed",
      error_category: "worker_lost",
      accepted: 0,
      delivery_error: "runtime_result_delivery_failed",
    });

    unbindUnavailableSink?.();
    const replayed: ExecutionResult[] = [];
    port.bindResultSink?.({
      async acceptExecutionResult(result) {
        replayed.push(result);
        return {
          actionId: result.actionId,
          runId: result.runId,
          accepted: true,
          duplicate: false,
          runState: "recovering",
          nextAction: "Recover from the last checkpoint",
        };
      },
    });
    expect(await port.replayPendingResults?.()).toBe(1);
    expect(replayed).toHaveLength(1);
    expect(db.prepare(`
      SELECT status, error_category,
        json_extract(redacted_payload_json, '$.resultAccepted') AS accepted
      FROM tool_calls WHERE tool_name = ?
    `).get(AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE)).toEqual({
      status: "failed",
      error_category: "worker_lost",
      accepted: 1,
    });
    expect(db.prepare("SELECT COUNT(*) AS count FROM evidence WHERE run_id = ?").get(RUN_ID))
      .toEqual({ count: 0 });
    factory.close();
  });
});

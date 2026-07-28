import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, test } from "bun:test";
import type {
  LocalProcessAdapterReadinessReceipt,
  LocalProcessToolInvocation,
  LocalProcessToolResult,
  LocalProcessToolResultSink,
} from "../../local-tools";
import {
  LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
  LocalToolCapabilityManifest,
} from "../../local-tools";
import type { DurableAction } from "../../orchestration";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import {
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
  AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
  AUTONOMOUS_FULL_TCP_DISCOVERY_MAX_RATE,
  AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
  AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH,
  AUTONOMOUS_FULL_TCP_NMAP_PATH,
  AUTONOMOUS_FULL_TCP_NMAP_SHA256,
  AUTONOMOUS_FULL_TCP_PORT_RANGE,
  AUTONOMOUS_FULL_TCP_SERVICE_MAX_RATE,
  AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
  AUTONOMOUS_SAFE_IP_RECON_DEFAULT_PORTS,
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  AutonomousFullTcpBaselineError,
  AutonomousFullTcpBaselineExecution,
  createAutonomousFullTcpAuthorizationReceipt,
  createAutonomousFullTcpBaselineManifest,
  createAutonomousFullTcpBaselinePolicy,
  normalizeAutonomousFullTcpServiceBatch,
  type AutonomousFullTcpBaselineConfiguration,
  type ReviewedFullTcpBaselineInvocationAdapter,
} from "..";

const NOW = new Date("2026-07-20T12:00:00.000Z");
const TARGET = "192.0.2.55";
const MODEL_HASH = "a".repeat(64);
const CONTRACT_HASH = "c".repeat(64);
const temporaryRoots: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function configuration(workspace: string): AutonomousFullTcpBaselineConfiguration {
  return {
    policyId: "reviewed-autonomous-full-tcp-v1",
    bindingId: "binding:autonomous-full-tcp-baseline-v1",
    agentId: "specialist:autonomous-full-tcp-recon",
    providerId: "provider:local-deterministic-full-tcp",
    modelId: "policy:local-full-tcp-v1",
    modelConfigurationHash: MODEL_HASH,
    logicalWorkspace: workspace,
  };
}

function action(target = TARGET): DurableAction {
  return {
    id: "action-full-tcp-1",
    missionId: "mission-full-tcp-1",
    runId: "run-full-tcp-1",
    stepId: "step-full-tcp-1",
    actionType: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_TYPE,
    actionClass: AUTONOMOUS_FULL_TCP_BASELINE_ACTION_CLASS,
    fingerprint: "f".repeat(64),
    arguments: {},
    target,
    kind: "tool",
    intentSummary: "Create one reviewed full TCP baseline",
    status: "running",
    idempotent: true,
    destructive: false,
    guidedDecisionId: null,
    contractId: "contract-full-tcp-1",
    contextPackId: "context-full-tcp-1",
    resultSummary: null,
    errorCategory: null,
    retryCount: 0,
    progressSignature: null,
    createdAt: NOW.toISOString(),
    startedAt: NOW.toISOString(),
    endedAt: null,
  };
}

function authorization(target = TARGET) {
  return createAutonomousFullTcpAuthorizationReceipt({
    missionId: "mission-full-tcp-1",
    runId: "run-full-tcp-1",
    contractId: "contract-full-tcp-1",
    contractHash: CONTRACT_HASH,
    exactAllowedTargets: [target],
    prohibitedTargets: [],
    issuedAt: new Date(NOW.getTime() - 1_000).toISOString(),
    expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
  });
}

function outputHash(stdout: string, stderr: string): string {
  return createHash("sha256").update(stdout).update("\u0000").update(stderr).digest("hex");
}

function nmapOutput(target: string, rows: readonly string[]): string {
  return [
    "Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-20 12:00 UTC",
    `Nmap scan report for ${target}`,
    "Host is up (0.0040s latency).",
    ...(rows.length === 0 ? ["All 65535 scanned ports on 192.0.2.55 are in ignored states."] : [
      "PORT    STATE SERVICE VERSION",
      ...rows,
    ]),
    "Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds",
    "",
  ].join("\n");
}

function processResult(
  invocation: LocalProcessToolInvocation,
  stdout: string,
  stderr = "",
): LocalProcessToolResult {
  const bytes = Buffer.byteLength(stdout) + Buffer.byteLength(stderr);
  return {
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
    stderr,
    observedOutputBytes: bytes,
    retainedOutputBytes: bytes,
    outputSha256: outputHash(stdout, stderr),
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
}

class FakeAdapter implements ReviewedFullTcpBaselineInvocationAdapter {
  sink?: LocalProcessToolResultSink;
  readonly dispatches: LocalProcessToolInvocation[] = [];
  readonly cancellations: { runId: string; reason: string }[] = [];
  readinessCalls = 0;
  holdResults = false;
  discoveryRows: string[] = [
    "22/tcp  open  ssh",
    "443/tcp open  https",
  ];

  constructor(
    private readonly manifestSha256: string,
    private readonly bindingSha256: ReadonlyMap<string, string>,
  ) {}

  bindResultSink(sink: LocalProcessToolResultSink): () => void {
    if (this.sink) throw new Error("sink already bound");
    this.sink = sink;
    return () => { this.sink = undefined; };
  }

  async readinessReceipt(now = NOW, ttlMs = 60_000): Promise<LocalProcessAdapterReadinessReceipt> {
    this.readinessCalls += 1;
    return {
      schemaVersion: "ti-scale.local-process-adapter-readiness.v1",
      adapterId: "test:full-tcp-adapter",
      manifestSha256: this.manifestSha256,
      sandboxExecutableSha256: "b".repeat(64),
      tools: [AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID, AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID].map((toolId) => ({
        toolId,
        bindingSha256: this.bindingSha256.get(toolId)!,
        expectedExecutableSha256: AUTONOMOUS_FULL_TCP_NMAP_SHA256,
        installationReceiptSha256: "3".repeat(64),
      })),
      sandboxExecutableIdentity: {
        sha256: "b".repeat(64),
        device: "1",
        inode: "2",
        sizeBytes: 1,
        mode: 0o755,
        uid: 0,
        gid: 0,
      },
      boundary: {
        platform: "linux",
        directArgv: true,
        shell: false,
        fixedEnvironmentSha256: "e".repeat(64),
        workspaceResolver: true,
        filesystemSandbox: "bubblewrap_minimal_read_only_host_workspace_write",
        totalOutputBound: true,
        cooperativeCancellation: true,
        processGroupCleanup: true,
        resultSinkBound: true,
        targetContact: false,
      },
      observedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
      grantsMissionExecution: false,
      receiptSha256: "4".repeat(64),
    };
  }

  async dispatch(invocation: LocalProcessToolInvocation, _signal: AbortSignal): Promise<void> {
    this.dispatches.push(invocation);
    if (this.holdResults) return;
    if (!this.sink) throw new Error("missing sink");
    if (invocation.toolId === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID) {
      await this.sink.acceptLocalProcessToolResult(processResult(
        invocation,
        nmapOutput(TARGET, this.discoveryRows),
      ));
      return;
    }
    const ports = String(invocation.parameters.ports).split(",").map(Number);
    const rows = ports.map((port) => port === 22
      ? "22/tcp  open  ssh    OpenSSH 9.7"
      : port === 443
        ? "443/tcp open  https  nginx 1.26.1"
        : `${port}/tcp open unknown synthetic-${port}`);
    await this.sink.acceptLocalProcessToolResult(processResult(
      invocation,
      nmapOutput(TARGET, rows),
    ));
  }

  async cancelRun(runId: string, reason: string): Promise<void> {
    this.cancellations.push({ runId, reason });
  }
}

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "ti-scale-full-tcp-"));
  temporaryRoots.push(root);
  const workspace = join(root, "engagement");
  await mkdir(workspace, { mode: 0o700 });
  const manifest = createAutonomousFullTcpBaselineManifest();
  const adapter = new FakeAdapter(
    manifest.descriptor.manifestSha256,
    new Map(manifest.list().map(({ toolId, bindingSha256 }) => [toolId, bindingSha256])),
  );
  const execution = new AutonomousFullTcpBaselineExecution({
    manifest,
    configuration: configuration(workspace),
    adapter,
    workspaceResolver: new EngagementWorkspaceResolver([{
      logicalRoot: root,
      runtimeRoot: root,
    }]),
    now: () => NOW,
  });
  return { root, workspace, manifest, adapter, execution };
}

describe("reviewed Autonomous full-TCP baseline", () => {
  test("rejects a manifest whose argv or execution bounds drift from the exact reviewed binding", () => {
    const reviewed = createAutonomousFullTcpBaselineManifest();
    const tools = reviewed.list().map(({ bindingSha256: _bindingSha256, ...tool }) =>
      tool.toolId === AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID
        ? { ...tool, execution: { ...tool.execution, timeoutMs: tool.execution.timeoutMs + 1 } }
        : tool);
    const drifted = new LocalToolCapabilityManifest({
      schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
      manifestVersion: "drifted-full-tcp-test-v1",
      specialist: reviewed.specialist,
      tools,
    });

    expect(() => createAutonomousFullTcpBaselinePolicy(configuration("/engagements/demo"), drifted))
      .toThrow("exact reviewed full-TCP baseline boundary");
  });

  test("defines a distinct capability-free two-phase policy without widening Safe Recon", () => {
    const manifest = createAutonomousFullTcpBaselineManifest();
    const policy = createAutonomousFullTcpBaselinePolicy(configuration("/engagements/box"), manifest);
    expect(AUTONOMOUS_SAFE_IP_RECON_DEFAULT_PORTS).toEqual([
      22, 53, 80, 88, 135, 139, 389, 443, 445, 636, 3389, 5985, 8080, 8443,
    ]);
    expect(AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID).toBe("kali:nmap-tcp-connect-service-scan");
    expect(policy.executionBinding).toBe("reviewed_full_tcp_baseline");
    expect(policy.bindingId).not.toBe("binding-autonomous-ip-services-v1");
    expect(policy.schemaVersion).toBe("ti-scale.autonomous-full-tcp-baseline-policy.v2");
    expect(manifest.descriptor.manifestVersion).toBe("autonomous-full-tcp-baseline-v2");
    expect(policy.evidence.autoPromotion).toBeTrue();
    expect(policy.evidence.promotionAuthority)
      .toBe("deterministic_general_recon_verifier_only");
    expect(policy.evidence.rawProcessOutputPromoted).toBeFalse();
    expect(policy.targetContract).toEqual({
      exactSingleAuthorizedHost: true,
      cidrAccepted: false,
      rangeAccepted: false,
      targetBatchAccepted: false,
    });
    expect(manifest.list()).toHaveLength(2);
    expect(manifest.list().every(({ executable }) =>
      executable.path === AUTONOMOUS_FULL_TCP_NMAP_PATH
      && executable.expectedSha256 === AUTONOMOUS_FULL_TCP_NMAP_SHA256
      && executable.fileCapabilities === "none")).toBeTrue();
  });

  test("compiles exact direct argv with a complete range and discovered-port-only -sV", () => {
    const manifest = createAutonomousFullTcpBaselineManifest();
    const discovery = manifest.compileInvocation(AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID, {
      workspace: "/engagements/box",
      target: TARGET,
    });
    expect(discovery.shell).toBeFalse();
    expect(discovery.arguments).toEqual([
      "-n", "-Pn", "-sT", "--open", "-p", AUTONOMOUS_FULL_TCP_PORT_RANGE,
      "--max-retries", "1", "--max-rate", String(AUTONOMOUS_FULL_TCP_DISCOVERY_MAX_RATE),
      "--max-parallelism", "64", "--host-timeout", "8m",
      "--max-rtt-timeout", "2s", "--", TARGET,
    ]);
    expect(discovery.arguments).not.toContain("-sS");
    expect(discovery.arguments).not.toContain("-O");
    expect(discovery.arguments).not.toContain("-sC");

    const service = manifest.compileInvocation(AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID, {
      workspace: "/engagements/box",
      target: TARGET,
      ports: "22,443",
    });
    expect(service.arguments).toEqual([
      "-n", "-Pn", "-sT", "--open", "-p", "22,443", "-sV", "--version-light",
      "--max-retries", "1", "--max-rate", String(AUTONOMOUS_FULL_TCP_SERVICE_MAX_RATE),
      "--max-parallelism", "32", "--host-timeout", "4m",
      "--max-rtt-timeout", "2s", "--", TARGET,
    ]);
    expect(() => manifest.compileInvocation(AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID, {
      workspace: "/engagements/box",
      target: TARGET,
      ports: "1-65535",
    })).toThrow("ranges and option syntax are not allowed");
    expect(() => manifest.compileInvocation(AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID, {
      workspace: "/engagements/box",
      target: "192.0.2.0/24",
    })).toThrow("one normalized IP address or hostname");
  });

  test("readiness is target-free and attests process-group cancellation without dispatching", async () => {
    const { execution, adapter } = await harness();
    const receipt = await execution.readiness();
    expect(receipt.status).toBe("ready");
    expect(receipt.boundary.targetContact).toBeFalse();
    expect(receipt.boundary.processGroupCleanup).toBeTrue();
    expect(adapter.readinessCalls).toBe(1);
    expect(adapter.dispatches).toHaveLength(0);
    execution.close();
  });

  test("executes discovery then targeted versioning and writes timestamped confined artifacts", async () => {
    const { execution, adapter, workspace } = await harness();
    const result = await execution.execute({ action: action(), authorization: authorization() }, new AbortController().signal);
    expect(adapter.dispatches.map(({ toolId }) => toolId)).toEqual([
      AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
      AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
    ]);
    expect(adapter.dispatches[1]?.parameters.ports).toBe("22,443");
    expect(String(adapter.dispatches[1]?.parameters.ports).split(",")).toEqual(
      [...new Set(result.discovery.normalized.openPorts)].map(String),
    );
    expect(result.discovery.normalized.openPorts).toEqual([22, 443]);
    expect(result.ports).toEqual([
      { port: 22, transport: "tcp", state: "open", service: "ssh", version: "OpenSSH 9.7" },
      { port: 443, transport: "tcp", state: "open", service: "https", version: "nginx 1.26.1" },
    ]);
    expect(result.verification.state).toBe("verified");
    expect(result.evidence.eligibleForExplicitPromotion).toBeTrue();
    expect(result.evidence.automaticallyPromoted).toBeFalse();
    expect(result.evidence.evidenceIds).toEqual([]);
    expect(result.artifacts.length).toBe(5);
    for (const artifact of result.artifacts) {
      expect(artifact.relativePath).toMatch(/^scans\/20260720T120000Z_full_tcp_baseline_/u);
      expect(artifact.logicalPath.startsWith(workspace)).toBeTrue();
      expect(await readFile(join(workspace, artifact.relativePath))).toBeDefined();
    }
    const structured = JSON.parse(await readFile(
      join(workspace, result.artifacts.at(-1)!.relativePath),
      "utf8",
    )) as Record<string, unknown>;
    expect(structured.resultSha256).toBe(result.resultSha256);
    execution.close();
  });

  test("treats zero open ports as a complete baseline and skips -sV", async () => {
    const { execution, adapter } = await harness();
    adapter.discoveryRows = [];
    const result = await execution.execute({ action: action(), authorization: authorization() }, new AbortController().signal);
    expect(adapter.dispatches).toHaveLength(1);
    expect(result.discoveredOpenPortCount).toBe(0);
    expect(result.serviceVersionBatches).toEqual([]);
    expect(result.verification.discoveredPortCoverageComplete).toBeTrue();
    expect(result.evidence.automaticallyPromoted).toBeFalse();
    execution.close();
  });

  test("chunks every discovered port without truncating the phase-two set", async () => {
    const { execution, adapter } = await harness();
    adapter.discoveryRows = Array.from(
      { length: AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH + 1 },
      (_, index) => `${index + 1}/tcp open unknown`,
    );
    const result = await execution.execute({ action: action(), authorization: authorization() }, new AbortController().signal);
    expect(adapter.dispatches).toHaveLength(3);
    expect(String(adapter.dispatches[1]?.parameters.ports).split(",")).toHaveLength(
      AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH,
    );
    expect(adapter.dispatches[2]?.parameters.ports).toBe(String(
      AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH + 1,
    ));
    expect(result.discoveredOpenPortCount).toBe(AUTONOMOUS_FULL_TCP_MAX_VERSION_PORTS_PER_BATCH + 1);
    expect(result.serviceVersionBatches).toHaveLength(2);
    execution.close();
  });

  test("rejects an out-of-set service result instead of making it evidence", () => {
    const invocation = {
      schemaVersion: "ti-scale.local-process-tool-invocation.v1" as const,
      invocationId: "full_tcp_test",
      action: action(),
      toolId: AUTONOMOUS_FULL_TCP_SERVICE_TOOL_ID,
      parameters: { workspace: "/engagements/box", target: TARGET, ports: "22" },
      inputSha256: "a".repeat(64),
      resolvedWorkspacePath: "/runtime/engagements/box",
    };
    const result = processResult(invocation, nmapOutput(TARGET, [
      "22/tcp  open ssh OpenSSH 9.7",
      "443/tcp open https nginx 1.26.1",
    ]));
    expect(() => normalizeAutonomousFullTcpServiceBatch(TARGET, 1, [22], result))
      .toThrow(AutonomousFullTcpBaselineError);
  });

  test("duplicate discovery rows fail closed before phase two instead of being silently repeated", async () => {
    const { execution, adapter, workspace } = await harness();
    adapter.discoveryRows = [
      "22/tcp open ssh",
      "22/tcp open ssh",
    ];
    await expect(execution.execute(
      { action: action(), authorization: authorization() },
      new AbortController().signal,
    )).rejects.toMatchObject({ code: "full_tcp_discovery_output_unverified" });
    expect(adapter.dispatches.map(({ toolId }) => toolId)).toEqual([
      AUTONOMOUS_FULL_TCP_DISCOVERY_TOOL_ID,
    ]);
    const files = await readdir(join(workspace, "scans"), { recursive: true });
    expect(files.some((name) => String(name).endsWith("baseline-result.json"))).toBeFalse();
    execution.close();
  });

  test("rejects CIDR and overlapping prohibited authorization before any target contact", async () => {
    const { execution, adapter } = await harness();
    await expect(execution.execute({
      action: action("192.0.2.0/24"),
      authorization: authorization(TARGET),
    }, new AbortController().signal)).rejects.toMatchObject({
      code: "full_tcp_target_not_single_host",
    });
    const prohibited = createAutonomousFullTcpAuthorizationReceipt({
      missionId: "mission-full-tcp-1",
      runId: "run-full-tcp-1",
      contractId: "contract-full-tcp-1",
      contractHash: CONTRACT_HASH,
      exactAllowedTargets: [TARGET],
      prohibitedTargets: [TARGET],
      issuedAt: new Date(NOW.getTime() - 1_000).toISOString(),
      expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
    });
    await expect(execution.execute({ action: action(), authorization: prohibited }, new AbortController().signal))
      .rejects.toMatchObject({ code: "full_tcp_action_boundary_mismatch" });
    expect(adapter.dispatches).toHaveLength(0);
    execution.close();
  });

  test("cancellation calls the adapter cleanup boundary and returns a precise terminal error", async () => {
    const { execution, adapter, workspace } = await harness();
    adapter.holdResults = true;
    const controller = new AbortController();
    const pending = execution.execute({ action: action(), authorization: authorization() }, controller.signal);
    while (adapter.dispatches.length === 0) {
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    controller.abort("operator requested stop");
    await expect(pending).rejects.toMatchObject({ code: "full_tcp_cancelled", phase: "cancellation" });
    expect(adapter.cancellations.some(({ runId }) => runId === "run-full-tcp-1")).toBeTrue();
    const files = await readdir(join(workspace, "scans"), { recursive: true });
    expect(files.some((name) => String(name).endsWith("baseline-result.json"))).toBeFalse();
    execution.close();
  });
});

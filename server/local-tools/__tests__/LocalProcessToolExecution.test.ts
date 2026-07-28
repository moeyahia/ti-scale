import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createTcpServer, type Server as TcpServer, type Socket } from "node:net";
import { chmod, copyFile, mkdtemp, mkdir, open, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { digestCanonicalJson } from "../../mcp/canonicalJson";
import type { DurableAction } from "../../orchestration";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import {
  DirectProcessLocalToolInvocationAdapter,
  LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
  LocalToolCapabilityManifest,
  LocalToolInstallationPreflight,
  LocalProcessToolExecutionError,
  classifyReviewedLocalToolResult,
  type LocalProcessToolInvocation,
  type LocalProcessToolResult,
} from "../index";

const MANIFEST_PATH = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const BWRAP_SHA256 = "042763bc80c8a895a497e6f801af003d585ea5588a580f7a4349d9ab2aa22980";

const roots: string[] = [];
const httpServers: HttpServer[] = [];
const tcpServers: TcpServer[] = [];

afterEach(async () => {
  for (const server of httpServers.splice(0)) {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }
  for (const server of tcpServers.splice(0)) await new Promise<void>((resolve) => server.close(() => resolve()));
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "ti-scale-local-exec-"));
  roots.push(root);
  await mkdir(join(root, "mission"));
  const manifest = new LocalToolCapabilityManifest(
    JSON.parse(await readFile(MANIFEST_PATH, "utf8")),
  );
  const workspaceResolver = new EngagementWorkspaceResolver([{
    logicalRoot: "/engagements",
    runtimeRoot: root,
  }]);
  const adapter = new DirectProcessLocalToolInvocationAdapter({
    manifest,
    workspaceResolver,
    sandboxExecutable: { path: "/usr/bin/bwrap", expectedSha256: BWRAP_SHA256 },
  });
  return { adapter, manifest, workspaceResolver, workspace: "/engagements/mission" };
}

async function sha256File(path: string): Promise<string> {
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk as Buffer);
  return digest.digest("hex");
}

async function largeNcatFixture(trailingBytes = 64 * 1024 * 1024) {
  const root = await mkdtemp(join(tmpdir(), "ti-scale-local-exec-large-"));
  roots.push(root);
  await mkdir(join(root, "mission"));
  const executablePath = join(root, "ncat-large-reviewed");
  await copyFile("/usr/bin/ncat", executablePath);
  const handle = await open(executablePath, "r+");
  try {
    const metadata = await handle.stat();
    await handle.truncate(metadata.size + trailingBytes);
  } finally {
    await handle.close();
  }
  await chmod(executablePath, 0o555);
  const expectedSha256 = await sha256File(executablePath);
  const manifestDocument = JSON.parse(await readFile(MANIFEST_PATH, "utf8")) as {
    tools: Array<Record<string, any>>;
  };
  const ncat = manifestDocument.tools.find(({ toolId }) =>
    toolId === "kali:ncat-tcp-connect")!;
  ncat.executable.path = executablePath;
  ncat.executable.expectedSha256 = expectedSha256;
  const manifest = new LocalToolCapabilityManifest(manifestDocument);
  const workspaceResolver = new EngagementWorkspaceResolver([{
    logicalRoot: "/engagements",
    runtimeRoot: root,
  }]);
  const adapter = new DirectProcessLocalToolInvocationAdapter({
    manifest,
    workspaceResolver,
    sandboxExecutable: { path: "/usr/bin/bwrap", expectedSha256: BWRAP_SHA256 },
  });
  return {
    adapter,
    executableSizeBytes: (await handleStat(executablePath)).size,
    manifest,
    workspace: "/engagements/mission",
    workspaceResolver,
  };
}

async function handleStat(path: string): Promise<{ readonly size: number }> {
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat();
    return { size: metadata.size };
  } finally {
    await handle.close();
  }
}

async function waitForResource(
  predicate: () => boolean,
  message: string,
): Promise<void> {
  for (let attempt = 0; attempt < 10_000; attempt += 1) {
    if (predicate()) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(message);
}

function action(
  id: string,
  target: string,
  actionClass: DurableAction["actionClass"] = "active_host_discovery",
): DurableAction {
  return {
    id,
    missionId: "mission_local_execution",
    runId: "run_local_execution",
    stepId: "step_local_execution",
    actionType: "reviewed_local_process",
    actionClass,
    fingerprint: `fingerprint_${id}`,
    arguments: {},
    target,
    kind: "tool",
    intentSummary: "Run one reviewed local process against the exact represented target.",
    status: "running",
    idempotent: true,
    destructive: false,
    guidedDecisionId: "guided_decision_local_execution",
    contractId: null,
    contextPackId: null,
    resultSummary: null,
    errorCategory: null,
    retryCount: 0,
    progressSignature: null,
    createdAt: "2026-07-19T12:00:00.000Z",
    startedAt: "2026-07-19T12:00:00.000Z",
    endedAt: null,
  };
}

function invocation(input: Readonly<{
  id: string;
  toolId: string;
  parameters: Readonly<Record<string, unknown>>;
  target: string;
  resolvedWorkspacePath: string;
  actionClass?: DurableAction["actionClass"];
}>): LocalProcessToolInvocation {
  return {
    schemaVersion: LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
    invocationId: input.id,
    action: action(`action_${input.id}`, input.target, input.actionClass),
    toolId: input.toolId,
    parameters: input.parameters,
    inputSha256: digestCanonicalJson(input.parameters, { maxBytes: 256 * 1_024, maxDepth: 32 }).sha256,
    resolvedWorkspacePath: input.resolvedWorkspacePath,
  };
}

async function execute(
  adapter: DirectProcessLocalToolInvocationAdapter,
  input: LocalProcessToolInvocation,
  signal = new AbortController().signal,
): Promise<LocalProcessToolResult> {
  let resolveResult!: (result: LocalProcessToolResult) => void;
  const result = new Promise<LocalProcessToolResult>((resolve) => { resolveResult = resolve; });
  const unbind = adapter.bindResultSink({
    async acceptLocalProcessToolResult(value) { resolveResult(value); },
  });
  try {
    await adapter.dispatch(input, signal);
    return await Promise.race([
      result,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("local process result timed out")), 15_000)),
    ]);
  } finally {
    unbind();
  }
}

function listenHttp(server: HttpServer): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve((server.address() as { port: number }).port);
    });
  });
}

function listenTcp(server: TcpServer): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve((server.address() as { port: number }).port);
    });
  });
}

async function within<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

describe("DirectProcessLocalToolInvocationAdapter", () => {
  test("binds fresh target-free readiness to actual executable identities", async () => {
    const { adapter } = await fixture();
    const unbind = adapter.bindResultSink({ async acceptLocalProcessToolResult() {} });
    const receipt = await adapter.readinessReceipt(new Date("2026-07-19T12:00:00.000Z"));
    unbind();
    expect(receipt.tools.map(({ toolId }) => toolId).sort()).toEqual([
      "kali:curl-http-metadata",
      "kali:host-dns-query",
      "kali:ncat-tcp-connect",
      "kali:ping-host-liveness",
    ]);
    expect(receipt.tools.every(({ installationReceiptSha256 }) => /^[a-f0-9]{64}$/u.test(installationReceiptSha256))).toBeTrue();
    expect(receipt.sandboxExecutableIdentity.sha256).toBe(BWRAP_SHA256);
    expect(receipt.boundary.targetContact).toBeFalse();
    expect(receipt.grantsMissionExecution).toBeFalse();
  });

  test("executes the four reviewed tools only against loopback/local resolver targets", async () => {
    const { adapter, workspaceResolver, workspace } = await fixture();
    const resolved = await workspaceResolver.resolve(workspace);
    expect(resolved.status).toBe("resolved");
    const resolvedWorkspacePath = resolved.resolvedPath!;

    const http = createHttpServer((_request, response) => {
      response.writeHead(204, { "X-Execution-Boundary": "loopback" });
      response.end();
    });
    httpServers.push(http);
    const httpPort = await listenHttp(http);
    const httpUrl = `http://127.0.0.1:${httpPort}/health`;
    const curl = await execute(adapter, invocation({
      id: "invoke_curl_loopback",
      toolId: "kali:curl-http-metadata",
      parameters: { workspace, url: httpUrl },
      target: httpUrl,
      resolvedWorkspacePath,
    }));
    expect(curl).toMatchObject({ termination: "exited", exitCode: 0, outputTruncated: false });
    expect(curl.stdout).toContain("204");

    const host = await execute(adapter, invocation({
      id: "invoke_host_local_resolver",
      toolId: "kali:host-dns-query",
      parameters: { workspace, name: "localhost", recordType: "A" },
      target: "LOCALHOST.",
      resolvedWorkspacePath,
    }));
    expect(host).toMatchObject({ termination: "exited", exitCode: 0 });
    expect(host.stdout).toContain("127.0.0.1");

    const ping = await execute(adapter, invocation({
      id: "invoke_ping_loopback",
      toolId: "kali:ping-host-liveness",
      parameters: { workspace, target: "127.0.0.1" },
      target: "127.0.0.1",
      resolvedWorkspacePath,
    }));
    expect(ping).toMatchObject({ termination: "exited", exitCode: 0 });
    expect(ping.stdout).toContain("127.0.0.1");

    const tcp = createTcpServer((socket) => socket.end());
    tcpServers.push(tcp);
    const tcpPort = await listenTcp(tcp);
    const ncat = await execute(adapter, invocation({
      id: "invoke_ncat_loopback",
      toolId: "kali:ncat-tcp-connect",
      parameters: { workspace, target: "127.0.0.1", port: tcpPort },
      target: `tcp://127.0.0.1:${tcpPort}`,
      resolvedWorkspacePath,
    }));
    expect(ncat).toMatchObject({ termination: "exited", exitCode: 0 });
    expect(`${ncat.stdout}\n${ncat.stderr}`).toContain("Connected");
  }, 30_000);

  test("streams a large reviewed executable without starving the event loop and releases aborted snapshots", async () => {
    const {
      adapter,
      executableSizeBytes,
      manifest,
      workspace,
      workspaceResolver,
    } = await largeNcatFixture();
    const resolvedWorkspacePath = (await workspaceResolver.resolve(workspace)).resolvedPath!;
    const preflight = new LocalToolInstallationPreflight();
    expect(await preflight.inspectAsync(manifest, "kali:ncat-tcp-connect"))
      .toMatchObject({ status: "ready", code: "ready" });

    const tcp = createTcpServer((socket) => socket.end());
    tcpServers.push(tcp);
    const tcpPort = await listenTcp(tcp);
    let eventLoopTurns = 0;
    const heartbeat = setInterval(() => { eventLoopTurns += 1; }, 1);
    try {
      const successful = execute(adapter, invocation({
        id: "invoke_ncat_large_streamed",
        toolId: "kali:ncat-tcp-connect",
        parameters: { workspace, target: "127.0.0.1", port: tcpPort },
        target: `tcp://127.0.0.1:${tcpPort}`,
        resolvedWorkspacePath,
      }));
      await waitForResource(
        () => adapter.resourceSnapshot().activeSnapshotBytes >= executableSizeBytes,
        "large executable snapshot was never observable as an active bounded resource",
      );
      const turnsAtActiveSnapshot = eventLoopTurns;
      await waitForResource(
        () => adapter.resourceSnapshot().activeSnapshotDescriptors === 0,
        "successful executable snapshots did not close after child inheritance",
      );
      const completed = await successful;
      expect(completed).toMatchObject({ termination: "exited", exitCode: 0 });
      expect(eventLoopTurns - turnsAtActiveSnapshot).toBeGreaterThan(0);
      expect(adapter.resourceSnapshot()).toMatchObject({
        activeSnapshotDescriptors: 0,
        activeSnapshotBytes: 0,
      });
    } finally {
      clearInterval(heartbeat);
    }

    const controller = new AbortController();
    const cancelled = execute(adapter, invocation({
      id: "invoke_ncat_large_cancelled",
      toolId: "kali:ncat-tcp-connect",
      parameters: { workspace, target: "127.0.0.1", port: tcpPort },
      target: `tcp://127.0.0.1:${tcpPort}`,
      resolvedWorkspacePath,
    }), controller.signal);
    await waitForResource(
      () => adapter.resourceSnapshot().activeSnapshotBytes >= executableSizeBytes,
      "cancellable executable snapshot was never observable as an active bounded resource",
    );
    controller.abort("cancel the bounded snapshot fixture");
    await expect(cancelled).rejects.toMatchObject({ code: "invocation_cancelled" });
    expect(adapter.resourceSnapshot()).toMatchObject({
      activeSnapshotDescriptors: 0,
      activeSnapshotBytes: 0,
    });
  }, 60_000);

  test("repeated real dispatch closes every ephemeral executable snapshot", async () => {
    const { adapter, workspaceResolver, workspace } = await fixture();
    const resolvedWorkspacePath = (await workspaceResolver.resolve(workspace)).resolvedPath!;
    const tcp = createTcpServer();
    const tcpPort = await listenTcp(tcp);
    await new Promise<void>((resolve) => tcp.close(() => resolve()));
    const before = adapter.resourceSnapshot();
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const result = await execute(adapter, invocation({
        id: `invoke_ncat_repeated_${String(attempt).padStart(2, "0")}`,
        toolId: "kali:ncat-tcp-connect",
        parameters: { workspace, target: "127.0.0.1", port: tcpPort },
        target: `tcp://127.0.0.1:${tcpPort}`,
        resolvedWorkspacePath,
      }));
      expect(result).toMatchObject({ termination: "exited", exitCode: 1 });
      expect(classifyReviewedLocalToolResult(result)).toMatchObject({
        success: true,
        outcome: "negative_observation",
      });
      expect(adapter.resourceSnapshot()).toMatchObject({
        activeSnapshotDescriptors: 0,
        activeSnapshotBytes: 0,
      });
    }
    const after = adapter.resourceSnapshot();
    expect(after.sealedSnapshotsCreated - before.sealedSnapshotsCreated).toBe(40);
    expect(after.sealedSnapshotBytesCopied - before.sealedSnapshotBytesCopied)
      .toBeGreaterThan(0);
  }, 60_000);

  test("executes the explicitly activated capability-free nmap binding as a bounded loopback TCP-connect scan", async () => {
    const root = await mkdtemp(join(tmpdir(), "ti-scale-nmap-exec-"));
    roots.push(root);
    await mkdir(join(root, "mission"));
    const executablePath = join(root, "nmap-capability-free");
    await copyFile("/usr/lib/nmap/nmap", executablePath);
    await chmod(executablePath, 0o555);
    const manifestDocument = JSON.parse(await readFile(MANIFEST_PATH, "utf8")) as {
      tools: Array<Record<string, any>>;
    };
    const nmap = manifestDocument.tools.find(({ toolId }) =>
      toolId === "kali:nmap-tcp-connect-service-scan")!;
    nmap.activation = "enabled";
    nmap.activationReason = null;
    nmap.executable.path = executablePath;
    const manifest = new LocalToolCapabilityManifest(manifestDocument);
    expect(new LocalToolInstallationPreflight().inspect(
      manifest,
      "kali:nmap-tcp-connect-service-scan",
    )).toMatchObject({
      status: "ready",
      fileCapabilitiesPresent: false,
      noNewPrivilegesCompatible: true,
      probeBoundary: { toolExecuted: false, targetArgumentsSupplied: false },
    });
    const workspaceResolver = new EngagementWorkspaceResolver([{
      logicalRoot: "/engagements",
      runtimeRoot: root,
    }]);
    const adapter = new DirectProcessLocalToolInvocationAdapter({
      manifest,
      workspaceResolver,
      sandboxExecutable: { path: "/usr/bin/bwrap", expectedSha256: BWRAP_SHA256 },
    });
    const http = createHttpServer((_request, response) => {
      response.writeHead(204, { "Server": "ti-scale-loopback-fixture" });
      response.end();
    });
    httpServers.push(http);
    const port = await listenHttp(http);
    const workspace = "/engagements/mission";
    const resolvedWorkspacePath = (await workspaceResolver.resolve(workspace)).resolvedPath!;
    const scan = await execute(adapter, invocation({
      id: "invoke_nmap_loopback",
      toolId: "kali:nmap-tcp-connect-service-scan",
      parameters: { workspace, target: "127.0.0.1", ports: String(port) },
      target: "127.0.0.1",
      actionClass: "port_service_enumeration",
      resolvedWorkspacePath,
    }));
    expect(scan).toMatchObject({
      termination: "exited",
      exitCode: 0,
      outputTruncated: false,
      executable: {
        sourcePath: executablePath,
        sourceSha256: "5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f",
        snapshotSha256: "5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f",
      },
      sandbox: { shell: false },
    });
    expect(scan.stdout).toContain(`${port}/tcp`);
    expect(scan.stdout).toContain("open");
    expect(classifyReviewedLocalToolResult(scan)).toMatchObject({
      success: true,
      outcome: "positive_observation",
    });
  }, 30_000);

  test("retains expected negative reconnaissance answers as completed observations", async () => {
    const { adapter, workspaceResolver, workspace } = await fixture();
    const resolvedWorkspacePath = (await workspaceResolver.resolve(workspace)).resolvedPath!;

    const http = createHttpServer((_request, response) => {
      response.writeHead(404, { "X-Expected-Observation": "not-found" });
      response.end();
    });
    httpServers.push(http);
    const httpPort = await listenHttp(http);
    const httpUrl = `http://127.0.0.1:${httpPort}/missing`;
    const curl = await execute(adapter, invocation({
      id: "invoke_curl_http_error",
      toolId: "kali:curl-http-metadata",
      parameters: { workspace, url: httpUrl },
      target: httpUrl,
      resolvedWorkspacePath,
    }));
    expect(curl).toMatchObject({ termination: "exited", exitCode: 22 });
    expect(classifyReviewedLocalToolResult(curl)).toMatchObject({
      success: true,
      outcome: "negative_observation",
    });

    const dns = await execute(adapter, invocation({
      id: "invoke_dns_no_record",
      toolId: "kali:host-dns-query",
      parameters: {
        workspace,
        name: "definitely-not-present-tiscale.invalid",
        recordType: "A",
      },
      target: "definitely-not-present-tiscale.invalid",
      resolvedWorkspacePath,
    }));
    expect(dns).toMatchObject({ termination: "exited", exitCode: 1 });
    expect(`${dns.stdout}\n${dns.stderr}`).toContain("NXDOMAIN");
    expect(classifyReviewedLocalToolResult(dns)).toMatchObject({
      success: true,
      outcome: "negative_observation",
    });

    const ping = await execute(adapter, invocation({
      id: "invoke_ping_no_reply",
      toolId: "kali:ping-host-liveness",
      parameters: { workspace, target: "192.0.2.1" },
      target: "192.0.2.1",
      resolvedWorkspacePath,
    }));
    expect(ping).toMatchObject({ termination: "exited", exitCode: 1 });
    expect(ping.stdout).toContain("0 received");
    expect(classifyReviewedLocalToolResult(ping)).toMatchObject({
      success: true,
      outcome: "negative_observation",
    });

    const closedTcp = createTcpServer();
    const closedPort = await listenTcp(closedTcp);
    await new Promise<void>((resolve) => closedTcp.close(() => resolve()));
    const ncat = await execute(adapter, invocation({
      id: "invoke_ncat_refused",
      toolId: "kali:ncat-tcp-connect",
      parameters: { workspace, target: "127.0.0.1", port: closedPort },
      target: `tcp://127.0.0.1:${closedPort}`,
      resolvedWorkspacePath,
    }));
    expect(ncat).toMatchObject({ termination: "exited", exitCode: 1 });
    expect(`${ncat.stdout}\n${ncat.stderr}`).toContain("Connection refused");
    expect(classifyReviewedLocalToolResult(ncat)).toMatchObject({
      success: true,
      outcome: "negative_observation",
    });
  }, 45_000);

  test("keeps process-integrity failures and unrecognised exits as runtime failures", () => {
    const base: LocalProcessToolResult = {
      invocationId: "invoke_classification_fixture",
      action: action("action_classification_fixture", "127.0.0.1"),
      toolId: "kali:ncat-tcp-connect",
      startedAt: "2026-07-19T12:00:00.000Z",
      endedAt: "2026-07-19T12:00:01.000Z",
      wallClockMs: 1_000,
      exitCode: 1,
      signal: null,
      termination: "exited",
      spawnErrorCode: null,
      stdout: "",
      stderr: "Ncat: Connection refused.\n",
      observedOutputBytes: 26,
      retainedOutputBytes: 26,
      outputSha256: "a".repeat(64),
      outputTruncated: false,
      executable: {
        sourcePath: "/usr/bin/ncat",
        sourceSha256: "b".repeat(64),
        snapshotSha256: "b".repeat(64),
        sandboxPath: "/run/ti-scale/tool",
      },
      sandbox: {
        executablePath: "/usr/bin/bwrap",
        executableSha256: "c".repeat(64),
        shell: false,
        environmentSha256: "d".repeat(64),
      },
    };

    expect(classifyReviewedLocalToolResult({
      ...base,
      termination: "timed_out",
    })).toMatchObject({ success: false, outcome: "execution_failure", category: "timeout" });
    expect(classifyReviewedLocalToolResult({
      ...base,
      termination: "output_limit",
    })).toMatchObject({ success: false, outcome: "execution_failure", code: "local_tool_output_limit" });
    expect(classifyReviewedLocalToolResult({
      ...base,
      termination: "spawn_error",
      spawnErrorCode: "ENOENT",
    })).toMatchObject({ success: false, outcome: "execution_failure", code: "ENOENT" });
    expect(classifyReviewedLocalToolResult({
      ...base,
      signal: "SIGKILL",
    })).toMatchObject({ success: false, outcome: "execution_failure", category: "process_crash" });
    expect(classifyReviewedLocalToolResult({
      ...base,
      exitCode: 2,
    })).toMatchObject({
      success: false,
      outcome: "execution_failure",
      category: "deterministic_tool_error",
      code: "local_tool_exit_2",
    });
    expect(classifyReviewedLocalToolResult({
      ...base,
      toolId: "kali:host-dns-query",
      stdout: "",
      stderr: "connection timed out; no servers could be reached\n",
    })).toMatchObject({ success: false, outcome: "execution_failure" });
  });

  test("rejects route-aware target drift and refuses duplicate resume", async () => {
    const { adapter, workspaceResolver, workspace } = await fixture();
    const resolvedWorkspacePath = (await workspaceResolver.resolve(workspace)).resolvedPath!;
    const changedPort = invocation({
      id: "invoke_target_drift",
      toolId: "kali:ncat-tcp-connect",
      parameters: { workspace, target: "127.0.0.1", port: 8443 },
      target: "tcp://127.0.0.1:443",
      resolvedWorkspacePath,
    });
    adapter.bindResultSink({ async acceptLocalProcessToolResult() {} });
    await expect(adapter.dispatch(changedPort, new AbortController().signal))
      .rejects.toMatchObject({ code: "target_binding_changed" });
    await expect(adapter.resume(changedPort, new AbortController().signal))
      .rejects.toMatchObject({ code: "resume_requires_new_attempt" });
  });

  test("cancellation terminates the process group without delivering a stale result", async () => {
    const { adapter, workspaceResolver, workspace } = await fixture();
    const resolvedWorkspacePath = (await workspaceResolver.resolve(workspace)).resolvedPath!;
    let requestStarted!: () => void;
    const requestStart = new Promise<void>((resolve) => { requestStarted = resolve; });
    let allConnectionsClosed!: () => void;
    const connectionsClosed = new Promise<void>((resolve) => { allConnectionsClosed = resolve; });
    const sockets = new Set<Socket>();
    const http = createHttpServer(() => requestStarted());
    http.on("connection", (socket) => {
      sockets.add(socket);
      socket.once("close", () => {
        sockets.delete(socket);
        if (sockets.size === 0) allConnectionsClosed();
      });
    });
    httpServers.push(http);
    const port = await listenHttp(http);
    let delivered = false;
    adapter.bindResultSink({ async acceptLocalProcessToolResult() { delivered = true; } });
    const cancelledInvocation = invocation({
      id: "invoke_cancelled_curl",
      toolId: "kali:curl-http-metadata",
      parameters: { workspace, url: `http://127.0.0.1:${port}/wait` },
      target: `http://127.0.0.1:${port}/wait`,
      resolvedWorkspacePath,
    });
    await adapter.dispatch(cancelledInvocation, new AbortController().signal);
    await within(requestStart, 1_000, "the reviewed curl process did not reach the loopback fixture");
    expect(sockets.size).toBe(1);
    await within(
      adapter.cancelRun("run_local_execution", "test cancellation"),
      2_500,
      "local process cancellation did not reap the sandbox process group",
    );
    await within(connectionsClosed, 500, "the cancelled sandbox retained its loopback connection");
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
    expect(sockets.size).toBe(0);
    expect(delivered).toBeFalse();
    await expect(adapter.dispatch(cancelledInvocation, new AbortController().signal))
      .rejects.toMatchObject({ code: "duplicate_invocation" });
  });
});

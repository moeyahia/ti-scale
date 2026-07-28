import { afterEach, describe, expect, test } from "bun:test";
import { createServer, type Server } from "node:http";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
  LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
  DirectProcessLocalToolInvocationAdapter,
  LocalToolCapabilityManifest,
  classifyReviewedLocalToolResult,
  normalizeReviewedLocalToolObservation,
  type LocalProcessToolInvocation,
  type LocalProcessToolResult,
  type LocalToolCapabilityManifestDocument,
} from "../../local-tools";
import { digestCanonicalJson } from "../../mcp/canonicalJson";
import {
  REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
  type DurableAction,
} from "../../orchestration";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import { composeReviewedWebAssessmentLocalManifest } from "../WebAssessmentCapabilityIntegration";

const BASELINE_MANIFEST_PATH = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const BWRAP_SHA256 = "042763bc80c8a895a497e6f801af003d585ea5588a580f7a4349d9ab2aa22980";
const LOGICAL_WORKSPACE = "/engagements/web-loopback";

const roots: string[] = [];
const servers: Server[] = [];
const sockets = new Set<Socket>();

afterEach(async () => {
  for (const socket of sockets) socket.destroy();
  sockets.clear();
  for (const server of servers.splice(0)) {
    server.closeAllConnections?.();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function listen(server: Server): Promise<number> {
  servers.push(server);
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve((server.address() as { readonly port: number }).port);
    });
  });
}

function action(
  id: string,
  toolId: string,
  actionClass: DurableAction["actionClass"],
  target: string,
  parameters: Readonly<Record<string, unknown>>,
): DurableAction {
  return {
    id,
    missionId: "mission_web_loopback",
    runId: "run_web_loopback",
    stepId: `step_${id}`,
    actionType: toolId,
    actionClass,
    fingerprint: `fingerprint_${id}`,
    arguments: {
      schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
      executionBinding: "reviewed_local_process",
      toolId,
      parameters,
    },
    target,
    kind: "tool",
    intentSummary: "Run one bounded reviewed web check against the exact loopback target.",
    status: "running",
    idempotent: true,
    destructive: false,
    guidedDecisionId: `decision_${id}`,
    contractId: null,
    contextPackId: null,
    resultSummary: null,
    errorCategory: null,
    retryCount: 0,
    progressSignature: null,
    createdAt: "2026-07-20T09:00:00.000Z",
    startedAt: "2026-07-20T09:00:00.000Z",
    endedAt: null,
  };
}

function invocation(input: Readonly<{
  invocationId: string;
  toolId: string;
  actionClass: DurableAction["actionClass"];
  target: string;
  parameters: Readonly<Record<string, unknown>>;
  resolvedWorkspacePath: string;
}>): LocalProcessToolInvocation {
  return {
    schemaVersion: LOCAL_PROCESS_INVOCATION_SCHEMA_VERSION,
    invocationId: input.invocationId,
    action: action(
      `action_${input.invocationId}`,
      input.toolId,
      input.actionClass,
      input.target,
      input.parameters,
    ),
    toolId: input.toolId,
    parameters: input.parameters,
    inputSha256: digestCanonicalJson(input.parameters, {
      maxBytes: 256 * 1_024,
      maxDepth: 32,
    }).sha256,
    resolvedWorkspacePath: input.resolvedWorkspacePath,
  };
}

class ResultCollector {
  readonly delivered: LocalProcessToolResult[] = [];
  private readonly waiting = new Map<string, {
    readonly resolve: (result: LocalProcessToolResult) => void;
    readonly reject: (error: Error) => void;
    readonly timeout: ReturnType<typeof setTimeout>;
  }>();

  readonly sink = {
    acceptLocalProcessToolResult: async (result: LocalProcessToolResult): Promise<void> => {
      this.delivered.push(result);
      const pending = this.waiting.get(result.invocationId);
      if (!pending) return;
      clearTimeout(pending.timeout);
      this.waiting.delete(result.invocationId);
      pending.resolve(result);
    },
  };

  expect(invocationId: string, timeoutMs = 35_000): Promise<LocalProcessToolResult> {
    if (this.waiting.has(invocationId)) throw new Error(`Duplicate wait for ${invocationId}`);
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.waiting.delete(invocationId);
        reject(new Error(`No process result was delivered for ${invocationId}`));
      }, timeoutMs);
      this.waiting.set(invocationId, { resolve, reject, timeout });
    });
  }

  dispose(): void {
    for (const [invocationId, pending] of this.waiting) {
      clearTimeout(pending.timeout);
      pending.reject(new Error(`Result collector disposed while waiting for ${invocationId}`));
    }
    this.waiting.clear();
  }
}

async function fixture(input: Readonly<{ readonly webTimeoutMs?: number }> = {}) {
  const runtimeRoot = await mkdtemp(join(tmpdir(), "ti-scale-web-process-"));
  roots.push(runtimeRoot);
  await mkdir(join(runtimeRoot, "web-loopback"));
  const baselineDocument = JSON.parse(
    await readFile(BASELINE_MANIFEST_PATH, "utf8"),
  ) as LocalToolCapabilityManifestDocument;
  const exactComposed = composeReviewedWebAssessmentLocalManifest(
    new LocalToolCapabilityManifest(baselineDocument),
  );
  const manifest = input.webTimeoutMs === undefined
    ? exactComposed
    : new LocalToolCapabilityManifest({
        schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
        manifestVersion: `${exactComposed.descriptor.manifestVersion}-timeout-test`,
        specialist: baselineDocument.specialist,
        tools: exactComposed.list().map(({ bindingSha256: _bindingSha256, ...tool }) => ({
          ...tool,
          execution: tool.toolId.startsWith("kali:whatweb-")
            ? { ...tool.execution, timeoutMs: input.webTimeoutMs! }
            : tool.execution,
        })),
      });
  const workspaceResolver = new EngagementWorkspaceResolver([{
    logicalRoot: "/engagements",
    runtimeRoot,
  }]);
  const resolvedWorkspacePath = (await workspaceResolver.resolve(LOGICAL_WORKSPACE)).resolvedPath!;
  const adapter = new DirectProcessLocalToolInvocationAdapter({
    manifest,
    workspaceResolver,
    sandboxExecutable: { path: "/usr/bin/bwrap", expectedSha256: BWRAP_SHA256 },
  });
  const collector = new ResultCollector();
  const unbind = adapter.bindResultSink(collector.sink);
  return {
    adapter,
    collector,
    exactComposed,
    manifest,
    resolvedWorkspacePath,
    dispose() {
      collector.dispose();
      unbind();
    },
  };
}

async function dispatchAndWait(
  adapter: DirectProcessLocalToolInvocationAdapter,
  collector: ResultCollector,
  request: LocalProcessToolInvocation,
  signal = new AbortController().signal,
): Promise<LocalProcessToolResult> {
  const result = collector.expect(request.invocationId);
  try {
    await adapter.dispatch(request, signal);
    return await result;
  } catch (error) {
    collector.dispose();
    throw error;
  }
}

describe("reviewed web-assessment real process boundary", () => {
  test("runs exact WhatWeb and FFUF bindings through sealed Bubblewrap snapshots and normalizes sink results", async () => {
    const web = createServer((request, response) => {
      const pathname = new URL(request.url ?? "/", "http://loopback.test").pathname;
      if (pathname === "/admin") {
        response.writeHead(403, { Server: "Ti-Scale-Loopback/9.0", "X-Powered-By": "FixtureCore" });
        response.end("restricted\n");
        return;
      }
      if (pathname === "/health") {
        response.writeHead(200, { Server: "Ti-Scale-Loopback/9.0" });
        response.end("healthy\n");
        return;
      }
      if (pathname === "/") {
        response.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          Server: "Ti-Scale-Loopback/9.0",
          "X-Powered-By": "FixtureCore",
        });
        response.end("<!doctype html><html><head><title>Ti-Scale Loopback</title></head><body>ready</body></html>");
        return;
      }
      response.writeHead(404, { Server: "Ti-Scale-Loopback/9.0" });
      response.end("missing\n");
    });
    const port = await listen(web);
    const baseUrl = `http://127.0.0.1:${port}/`;
    const runtime = await fixture();
    try {
      expect(runtime.exactComposed.resolve("kali:whatweb-bounded-fingerprint")?.activation)
        .toBe("enabled");
      expect(runtime.exactComposed.resolve("kali:ffuf-bounded-content-discovery")?.activation)
        .toBe("enabled");
      const readiness = await runtime.adapter.readinessReceipt(
        new Date("2026-07-20T09:00:00.000Z"),
      );
      expect(readiness.manifestSha256).toBe(runtime.exactComposed.descriptor.manifestSha256);
      expect(readiness.tools.map(({ toolId }) => toolId)).toEqual(expect.arrayContaining([
        "kali:whatweb-bounded-fingerprint",
        "kali:ffuf-bounded-content-discovery",
      ]));
      expect(readiness.boundary).toMatchObject({
        directArgv: true,
        shell: false,
        filesystemSandbox: "bubblewrap_minimal_read_only_host_workspace_write",
        totalOutputBound: true,
        cooperativeCancellation: true,
        processGroupCleanup: true,
        resultSinkBound: true,
        targetContact: false,
      });

      const whatwebRequest = invocation({
        invocationId: "invoke_whatweb_loopback",
        toolId: "kali:whatweb-bounded-fingerprint",
        actionClass: "os_technology_fingerprinting",
        target: baseUrl,
        parameters: { workspace: LOGICAL_WORKSPACE, url: baseUrl },
        resolvedWorkspacePath: runtime.resolvedWorkspacePath,
      });
      const whatweb = await dispatchAndWait(runtime.adapter, runtime.collector, whatwebRequest);
      expect(whatweb).toMatchObject({
        termination: "exited",
        exitCode: 0,
        outputTruncated: false,
        executable: {
          sourcePath: "/usr/bin/whatweb",
          sourceSha256: "63f001c7433a1ed4e910bcfdad28969bca0cefb3ec0a48a6b555c67aaf9fb382",
          snapshotSha256: "63f001c7433a1ed4e910bcfdad28969bca0cefb3ec0a48a6b555c67aaf9fb382",
          sandboxPath: "/run/ti-scale/tool",
        },
        sandbox: { executablePath: "/usr/bin/bwrap", executableSha256: BWRAP_SHA256, shell: false },
      });
      expect(whatweb.stdout).toContain("Ti-Scale Loopback");
      const whatwebClassification = classifyReviewedLocalToolResult(whatweb);
      expect(whatwebClassification).toMatchObject({ success: true, outcome: "positive_observation" });
      const whatwebObservation = normalizeReviewedLocalToolObservation(whatweb, whatwebClassification);
      expect(whatwebObservation).toMatchObject({
        observationType: "web_technology_fingerprint",
        completeForCandidate: false,
        normalizedValue: {
          toolCallId: "invoke_whatweb_loopback",
          target: baseUrl,
          result: { url: baseUrl, requestBudget: 1, redirectFollowed: false },
        },
      });
      expect((whatwebObservation!.normalizedValue.result.signals as readonly unknown[]).length)
        .toBeGreaterThanOrEqual(2);

      const ffufRequest = invocation({
        invocationId: "invoke_ffuf_loopback",
        toolId: "kali:ffuf-bounded-content-discovery",
        actionClass: "web_content_endpoint_discovery_fuzzing",
        target: baseUrl,
        parameters: { workspace: LOGICAL_WORKSPACE, url: baseUrl },
        resolvedWorkspacePath: runtime.resolvedWorkspacePath,
      });
      const ffuf = await dispatchAndWait(runtime.adapter, runtime.collector, ffufRequest);
      expect(ffuf).toMatchObject({
        termination: "exited",
        exitCode: 0,
        outputTruncated: false,
        executable: {
          sourcePath: "/usr/bin/ffuf",
          sourceSha256: "4dd9cf7e19abd92440922a28399c948be8d49308f1ca7f1222ef33f2d026313c",
          snapshotSha256: "4dd9cf7e19abd92440922a28399c948be8d49308f1ca7f1222ef33f2d026313c",
          sandboxPath: "/run/ti-scale/tool",
        },
      });
      const ffufClassification = classifyReviewedLocalToolResult(ffuf);
      expect(ffufClassification).toMatchObject({ success: true, outcome: "positive_observation" });
      const ffufObservation = normalizeReviewedLocalToolObservation(ffuf, ffufClassification);
      expect(ffufObservation).toMatchObject({
        observationType: "web_endpoint_discovery",
        completeForCandidate: false,
        normalizedValue: {
          toolCallId: "invoke_ffuf_loopback",
          target: baseUrl,
          result: {
            baseUrl,
            fixedDictionaryVersion: "ti-scale.web-paths.v1",
            requestBudget: 14,
            matchCount: 2,
            recursive: false,
            redirectFollowed: false,
          },
        },
      });
      const matches = ffufObservation!.normalizedValue.result.matches as readonly { readonly url: string }[];
      expect(matches.map(({ url }) => url).sort()).toEqual([
        `${baseUrl}admin`,
        `${baseUrl}health`,
      ]);
      expect(runtime.collector.delivered.map(({ invocationId }) => invocationId)).toEqual([
        "invoke_whatweb_loopback",
        "invoke_ffuf_loopback",
      ]);
    } finally {
      runtime.dispose();
    }
  }, 45_000);

  test("cancellation terminates a hanging FFUF process group without delivering a stale result", async () => {
    let requestObserved!: () => void;
    const observed = new Promise<void>((resolve) => { requestObserved = resolve; });
    const web = createServer(() => requestObserved());
    const port = await listen(web);
    const baseUrl = `http://127.0.0.1:${port}/`;
    const runtime = await fixture();
    try {
      const request = invocation({
        invocationId: "invoke_ffuf_cancelled",
        toolId: "kali:ffuf-bounded-content-discovery",
        actionClass: "web_content_endpoint_discovery_fuzzing",
        target: baseUrl,
        parameters: { workspace: LOGICAL_WORKSPACE, url: baseUrl },
        resolvedWorkspacePath: runtime.resolvedWorkspacePath,
      });
      await runtime.adapter.dispatch(request, new AbortController().signal);
      await Promise.race([
        observed,
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("FFUF did not contact the loopback fixture")), 10_000)),
      ]);
      await runtime.adapter.cancelRun("run_web_loopback", "integration cancellation");
      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(runtime.collector.delivered).toHaveLength(0);
    } finally {
      runtime.dispose();
    }
  }, 20_000);

  test("the process deadline delivers one classified timeout and no target observation", async () => {
    const web = createServer(() => undefined);
    const port = await listen(web);
    const baseUrl = `http://127.0.0.1:${port}/`;
    // The exact pack's normal 15-second deadline is shortened only in this
    // deterministic failure fixture; executable, argv, staged input, sandbox,
    // and normalization paths remain the composed production implementation.
    const runtime = await fixture({ webTimeoutMs: 1_000 });
    try {
      const request = invocation({
        invocationId: "invoke_whatweb_timeout",
        toolId: "kali:whatweb-bounded-fingerprint",
        actionClass: "os_technology_fingerprinting",
        target: baseUrl,
        parameters: { workspace: LOGICAL_WORKSPACE, url: baseUrl },
        resolvedWorkspacePath: runtime.resolvedWorkspacePath,
      });
      const result = await dispatchAndWait(runtime.adapter, runtime.collector, request);
      expect(result).toMatchObject({ termination: "timed_out", outputTruncated: false });
      const classification = classifyReviewedLocalToolResult(result);
      expect(classification).toMatchObject({
        success: false,
        outcome: "execution_failure",
        category: "timeout",
        code: "local_tool_timeout",
      });
      expect(normalizeReviewedLocalToolObservation(result, classification)).toBeNull();
      expect(runtime.collector.delivered).toHaveLength(1);
    } finally {
      runtime.dispose();
    }
  }, 15_000);
});

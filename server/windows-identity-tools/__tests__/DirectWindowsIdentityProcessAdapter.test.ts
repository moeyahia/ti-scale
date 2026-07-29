import { createHash } from "node:crypto";
import { createServer, type Server, type Socket } from "node:net";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION } from "../../orchestration";
import { fingerprintAction, type ActionIntent, type GuidedDecision } from "../../supervisor";
import { EngagementWorkspaceResolver } from "../../system-capabilities";
import { DirectWindowsIdentityProcessAdapter } from "../DirectWindowsIdentityProcessAdapter";
import { WindowsIdentityToolPack } from "../WindowsIdentityToolPack";
import {
  WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
  WindowsIdentityBoundaryError,
  type CompiledWindowsIdentityInvocation,
  type WindowsIdentityActionRequest,
  type WindowsIdentityCredentialBindingReceipt,
  type WindowsIdentityCredentialMaterialResolver,
  type WindowsIdentityMissionBoundary,
  type WindowsIdentityToolId,
  type WindowsIdentityToolReadinessReceipt,
} from "../types";

const NOW = new Date("2026-07-20T10:00:00.000Z");
const BWRAP = "/usr/bin/bwrap";
const LOGICAL_ROOT = "/engagements";
const LOGICAL_WORKSPACE = `${LOGICAL_ROOT}/identity-fixture`;
const LDAP_PORT = 389;
const LOOPBACK_BIND_ATTEMPTS = 16;

async function sha256(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function request(
  operation: WindowsIdentityActionRequest["operation"],
  runId: string,
  overrides: Partial<WindowsIdentityActionRequest> = {},
): WindowsIdentityActionRequest {
  return {
    schemaVersion: WINDOWS_IDENTITY_ACTION_SCHEMA_VERSION,
    missionId: `mission-${runId}`,
    runId,
    stepId: `step-${runId}`,
    planVersion: 1,
    journey: "guided",
    operation,
    target: "127.0.0.1",
    logicalWorkspace: LOGICAL_WORKSPACE,
    authenticationMode: "anonymous",
    credentialReference: null,
    ...overrides,
  };
}

function representedAction(
  pack: WindowsIdentityToolPack,
  value: WindowsIdentityActionRequest,
): ActionIntent {
  const definition = pack.resolveOperation(value.operation)!;
  return {
    missionId: value.missionId,
    runId: value.runId,
    stepId: value.stepId,
    planVersion: value.planVersion,
    actionType: definition.toolId,
    actionClass: definition.actionClassId,
    target: value.target,
    arguments: {
      schemaVersion: value.schemaVersion,
      executionBinding: "reviewed_windows_identity_process",
      operation: value.operation,
      toolId: definition.toolId,
      authenticationMode: value.authenticationMode,
      credentialReference: value.credentialReference,
      logicalWorkspace: value.logicalWorkspace,
    },
  };
}

function missionBoundary(
  pack: WindowsIdentityToolPack,
  value: WindowsIdentityActionRequest,
): WindowsIdentityMissionBoundary {
  const fingerprint = fingerprintAction(representedAction(pack, value)).hash;
  const decision: GuidedDecision = {
    id: `decision-${value.runId}`,
    missionId: value.missionId,
    runId: value.runId,
    stepId: value.stepId,
    journey: "guided",
    actionFingerprint: fingerprint,
    status: "authorized",
    authorizedAt: NOW.toISOString(),
    expiresAt: "2026-07-20T10:30:00.000Z",
    version: 1,
  };
  return {
    authorizationVerified: true,
    allowedTargets: [value.target],
    prohibitedTargets: [],
    allowedActionClassIds: ["active_directory_identity_operations"],
    prohibitedActionClassIds: [],
    guidedDecision: decision,
  };
}

function credentialReceipt(
  pack: WindowsIdentityToolPack,
  value: WindowsIdentityActionRequest,
): WindowsIdentityCredentialBindingReceipt {
  return {
    schemaVersion: "ti-scale.windows-identity-credential-binding.v1",
    referenceId: value.credentialReference!.id,
    runId: value.runId,
    actionFingerprint: fingerprintAction(representedAction(pack, value)).hash,
    availableViews: ["samba_auth_file"],
    mountedReadOnly: true,
    privateToProcess: true,
    expiresAt: "2026-07-20T10:30:00.000Z",
    grantsAuthorization: false,
  };
}

function compile(
  pack: WindowsIdentityToolPack,
  value: WindowsIdentityActionRequest,
  binding: WindowsIdentityCredentialBindingReceipt | null = null,
): CompiledWindowsIdentityInvocation {
  return pack.compile({
    request: value,
    missionBoundary: missionBoundary(pack, value),
    credentialBindingReceipt: binding,
    now: NOW,
  });
}

function compileAutonomousNxc(
  pack: WindowsIdentityToolPack,
  runId: string,
): CompiledWindowsIdentityInvocation {
  const value = request("smb_identity_summary", runId, {
    journey: "autonomous",
  });
  const persistedAction: ActionIntent = {
    missionId: value.missionId,
    runId: value.runId,
    stepId: value.stepId,
    planVersion: value.planVersion,
    actionType: "kali:nxc-smb-summary",
    actionClass: "active_directory_identity_operations",
    target: value.target,
    arguments: {
      schemaVersion: REVIEWED_LOCAL_TOOL_ACTION_SCHEMA_VERSION,
      executionBinding: "reviewed_local_process",
      toolId: "kali:nxc-smb-summary",
      parameters: {
        authenticationMode: "anonymous",
        operation: "smb_identity_summary",
        target: value.target,
        workspace: value.logicalWorkspace,
      },
    },
  };
  return pack.compile({
    request: value,
    persistedAction,
    missionBoundary: {
      authorizationVerified: true,
      allowedTargets: [value.target],
      prohibitedTargets: [],
      allowedActionClassIds: ["active_directory_identity_operations"],
      prohibitedActionClassIds: [],
      guidedDecision: null,
      autonomousContract: {
        runId: value.runId,
        version: 1,
        status: "signed",
        allowedActionTypes: ["active_directory_identity_operations"],
        prohibitedActionTypes: [],
        allowedTargets: [value.target],
      },
    },
    credentialBindingReceipt: null,
    now: NOW,
  });
}

function readiness(
  pack: WindowsIdentityToolPack,
  toolId: WindowsIdentityToolId,
): WindowsIdentityToolReadinessReceipt {
  const definition = pack.resolveTool(toolId)!;
  return {
    schemaVersion: "ti-scale.windows-identity-readiness.v1",
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
    explanation: "Loopback-only behavioral fixture passed.",
    remediation: null,
    observedAt: "2026-07-20T09:59:00.000Z",
    expiresAt: "2026-07-20T11:00:00.000Z",
    grantsMissionExecution: false,
  };
}

async function fixture(
  options: Readonly<{
    runtimeTimeoutCapMs?: number;
    runtimeOutputCapBytes?: number;
    credentialResolver?: WindowsIdentityCredentialMaterialResolver;
  }> = {},
) {
  const root = await mkdtemp(join(tmpdir(), "ti-scale-identity-adapter-"));
  const workspace = join(root, "identity-fixture");
  await mkdir(workspace, { mode: 0o700 });
  const pack = new WindowsIdentityToolPack();
  const adapter = new DirectWindowsIdentityProcessAdapter({
    workspaceResolver: new EngagementWorkspaceResolver([{
      logicalRoot: LOGICAL_ROOT,
      runtimeRoot: root,
    }]),
    credentialResolver: options.credentialResolver,
    sandboxExecutable: { path: BWRAP, expectedSha256: await sha256(BWRAP) },
    runtimeTimeoutCapMs: options.runtimeTimeoutCapMs,
    runtimeOutputCapBytes: options.runtimeOutputCapBytes,
    now: () => NOW,
  });
  return {
    root,
    workspace,
    pack,
    adapter,
    async dispose() { await rm(root, { recursive: true, force: true }); },
  };
}

interface HeldLoopback {
  readonly address: string;
  readonly port: typeof LDAP_PORT;
  sockets: Set<Socket>;
  connected: Promise<void>;
  close(): Promise<void>;
}

type AdapterFixture = Awaited<ReturnType<typeof fixture>>;

function isolatedLoopbackCandidates(): readonly string[] {
  const processNamespace = process.pid % (254 * 254);
  const secondOctet = Math.floor(processNamespace / 254) + 1;
  const thirdOctet = (processNamespace % 254) + 1;
  return Object.freeze(Array.from(
    { length: LOOPBACK_BIND_ATTEMPTS },
    (_, index) => `127.${secondOctet}.${thirdOctet}.${index + 1}`,
  ));
}

async function closeLoopbackServer(server: Server, sockets: Set<Socket>): Promise<void> {
  for (const socket of sockets) socket.destroy();
  if (!server.listening) {
    server.removeAllListeners();
    return;
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function disposePartialSetup(
  endpoint: HeldLoopback | undefined,
  active: AdapterFixture | undefined,
): Promise<void> {
  const results = await Promise.allSettled([
    endpoint?.close() ?? Promise.resolve(),
    active?.dispose() ?? Promise.resolve(),
  ]);
  const failures = results.flatMap((result) =>
    result.status === "rejected" ? [result.reason] : []);
  if (failures.length > 0) {
    throw new AggregateError(failures, "Failed to release Windows identity adapter test resources");
  }
}

async function holdIsolatedLoopbackLdap(): Promise<HeldLoopback> {
  const collisions: string[] = [];
  for (const address of isolatedLoopbackCandidates()) {
    const sockets = new Set<Socket>();
    let markConnected: (() => void) | undefined;
    const connected = new Promise<void>((resolve) => { markConnected = resolve; });
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      markConnected?.();
      markConnected = undefined;
    });
    let listening: boolean;
    try {
      listening = await new Promise<boolean>((resolve, reject) => {
        const onError = (error: NodeJS.ErrnoException): void => {
          server.off("listening", onListening);
          if (error.code === "EADDRINUSE" || error.code === "EADDRNOTAVAIL") {
            collisions.push(`${address}:${LDAP_PORT} (${error.code})`);
            resolve(false);
            return;
          }
          reject(error);
        };
        const onListening = (): void => {
          server.off("error", onError);
          resolve(true);
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen({ host: address, port: LDAP_PORT, exclusive: true });
      });
    } catch (error) {
      await closeLoopbackServer(server, sockets);
      throw error;
    }
    if (!listening) {
      await closeLoopbackServer(server, sockets);
      continue;
    }
    return {
      address,
      port: LDAP_PORT,
      sockets,
      connected,
      async close() {
        await closeLoopbackServer(server, sockets);
      },
    };
  }
  throw new Error(
    `Unable to reserve an isolated loopback LDAP endpoint after ${LOOPBACK_BIND_ATTEMPTS} attempts: ${collisions.join(", ")}`,
  );
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("Timed out waiting for bounded process cleanup");
    await Bun.sleep(10);
  }
}

describe("DirectWindowsIdentityProcessAdapter", () => {
  test("accepts only the prepared anonymous Autonomous NetExec envelope at the final adapter boundary", async () => {
    const active = await fixture({ runtimeTimeoutCapMs: 1_000 });
    try {
      const invocation = compileAutonomousNxc(active.pack, "run-autonomous-nxc");
      active.adapter.acceptReadinessReceipts([readiness(active.pack, invocation.toolId)]);
      expect(invocation).toMatchObject({
        journey: "autonomous",
        toolId: "kali:nxc-smb-summary",
        credentialReference: null,
        directArgv: true,
        shell: false,
        targetReadOnly: true,
        evidencePromotion: "none",
      });
      expect(invocation.arguments).toContain("--no-write-check");
      expect(invocation.arguments).toContain("--no-bruteforce");
      const result = await active.adapter.execute(invocation, new AbortController().signal);
      expect(result.receipt).toMatchObject({
        toolId: "kali:nxc-smb-summary",
        runId: "run-autonomous-nxc",
        credentialReferenceId: null,
        directArgv: true,
        shell: false,
        targetReadOnly: true,
        workspaceConfined: true,
        credentialsMountedReadOnly: true,
        outputRedacted: true,
        grantsAuthorization: false,
      });
    } finally {
      await active.dispose();
    }
  });

  test("rechecks the exact target, fingerprint, direct argv, no-shell shape, and scope-derived invocation before spawn", async () => {
    const active = await fixture();
    try {
      const invocation = compile(active.pack, request("smb_share_list", "run-shape"));
      active.adapter.acceptReadinessReceipts([readiness(active.pack, invocation.toolId)]);
      expect(invocation).toMatchObject({
        target: "127.0.0.1",
        directArgv: true,
        shell: false,
        targetReadOnly: true,
        evidencePromotion: "none",
      });
      expect(invocation.arguments).toContain("--list=127.0.0.1");
      expect(() => compile(active.pack, request("smb_share_list", "run-injection", {
        target: "127.0.0.1;touch-pwned",
      }))).toThrow("canonical IP address or lowercase hostname");

      const tampered = { ...invocation, target: "127.0.0.2" } as CompiledWindowsIdentityInvocation;
      try {
        await active.adapter.execute(tampered, new AbortController().signal);
        throw new Error("expected modified invocation rejection");
      } catch (error) {
        expect(error).toBeInstanceOf(WindowsIdentityBoundaryError);
        expect((error as WindowsIdentityBoundaryError).code)
          .toBe("windows_identity_tool_identity_changed");
      }
      expect(await Array.fromAsync(new Bun.Glob("**/*").scan({ cwd: active.workspace })))
        .toEqual([]);
    } finally {
      await active.dispose();
    }
  });

  test("stops a loopback LDAP read at the fixed timeout and returns a bounded terminal receipt", async () => {
    let endpoint: HeldLoopback | undefined;
    let active: AdapterFixture | undefined;
    try {
      const ldapEndpoint = await holdIsolatedLoopbackLdap();
      endpoint = ldapEndpoint;
      active = await fixture({ runtimeTimeoutCapMs: 120 });
      const invocation = compile(active.pack, request("ldap_root_dse", "run-timeout", {
        target: ldapEndpoint.address,
      }));
      active.adapter.acceptReadinessReceipts([readiness(active.pack, invocation.toolId)]);
      expect(invocation.target).toBe(ldapEndpoint.address);
      expect(invocation.arguments[invocation.arguments.indexOf("-H") + 1])
        .toBe(`ldap://${ldapEndpoint.address}:${LDAP_PORT}`);
      const result = await active.adapter.execute(invocation, new AbortController().signal);
      expect(result).toMatchObject({
        timedOut: true,
        cancelled: false,
        outputTruncated: false,
        receipt: {
          timedOut: true,
          cancelled: false,
          directArgv: true,
          shell: false,
          workspaceConfined: true,
        },
      });
      expect(result.retainedOutputBytes).toBeLessThanOrEqual(invocation.maximumOutputBytes);
      await waitFor(() => ldapEndpoint.sockets.size === 0);
    } finally {
      await disposePartialSetup(endpoint, active);
    }
  });

  test("cancels the detached process group for one run and waits until its loopback connection closes", async () => {
    let endpoint: HeldLoopback | undefined;
    let active: AdapterFixture | undefined;
    try {
      const ldapEndpoint = await holdIsolatedLoopbackLdap();
      endpoint = ldapEndpoint;
      active = await fixture({ runtimeTimeoutCapMs: 5_000 });
      const invocation = compile(active.pack, request("ldap_root_dse", "run-cancel", {
        target: ldapEndpoint.address,
      }));
      active.adapter.acceptReadinessReceipts([readiness(active.pack, invocation.toolId)]);
      expect(invocation.target).toBe(ldapEndpoint.address);
      expect(invocation.arguments[invocation.arguments.indexOf("-H") + 1])
        .toBe(`ldap://${ldapEndpoint.address}:${LDAP_PORT}`);
      const execution = active.adapter.execute(invocation, new AbortController().signal);
      await Promise.race([
        ldapEndpoint.connected,
        Bun.sleep(2_000).then(() => { throw new Error("LDAP fixture never received the loopback connection"); }),
      ]);
      await active.adapter.cancelRun(invocation.action.runId, "behavioral cancellation fixture");
      const result = await execution;
      expect(result.cancelled).toBeTrue();
      expect(result.timedOut).toBeFalse();
      expect(result.receipt.cancelled).toBeTrue();
      await waitFor(() => ldapEndpoint.sockets.size === 0);
    } finally {
      await disposePartialSetup(endpoint, active);
    }
  });

  test("caps retained output, records the truncation, and never promotes raw output to evidence", async () => {
    const active = await fixture({ runtimeOutputCapBytes: 8 });
    try {
      const invocation = compile(active.pack, request("smb_share_list", "run-output"));
      active.adapter.acceptReadinessReceipts([readiness(active.pack, invocation.toolId)]);
      const result = await active.adapter.execute(invocation, new AbortController().signal);
      expect(result.outputTruncated).toBeTrue();
      expect(result.observedOutputBytes).toBeGreaterThan(8);
      expect(result.retainedOutputBytes).toBe(8);
      expect(Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr)).toBeLessThanOrEqual(8);
      expect(result.receipt.outputTruncated).toBeTrue();
    } finally {
      await active.dispose();
    }
  });

  test("mounts an opaque Samba credential file privately and returns no host path or secret material", async () => {
    const root = await mkdtemp(join(tmpdir(), "ti-scale-identity-credential-"));
    const credentialPath = join(root, "samba-auth");
    const secret = "fixture-only-password-Z9!";
    await writeFile(credentialPath, `username = fixture-user\npassword = ${secret}\ndomain = WORKGROUP\n`, {
      mode: 0o400,
    });
    const calls: unknown[] = [];
    let expectedReceipt: WindowsIdentityCredentialBindingReceipt;
    const resolver: WindowsIdentityCredentialMaterialResolver = {
      async resolve(input) {
        calls.push(structuredClone(input));
        return {
          receipt: expectedReceipt,
          files: { samba_auth_file: credentialPath },
        };
      },
    };
    const active = await fixture({ credentialResolver: resolver });
    try {
      const value = request("smb_share_list", "run-credential", {
        authenticationMode: "credential_reference",
        credentialReference: { kind: "systemd_credential_bundle", id: "credential-fixture-1" },
      });
      expectedReceipt = credentialReceipt(active.pack, value);
      const invocation = compile(active.pack, value, expectedReceipt);
      active.adapter.acceptReadinessReceipts([readiness(active.pack, invocation.toolId)]);
      const before = await readFile(credentialPath, "utf8");
      const result = await active.adapter.execute(invocation, new AbortController().signal);
      expect(calls).toEqual([{
        reference: { kind: "systemd_credential_bundle", id: "credential-fixture-1" },
        runId: value.runId,
        actionFingerprint: invocation.actionFingerprint,
        requiredViews: ["samba_auth_file"],
      }]);
      expect(result.receipt).toMatchObject({
        credentialReferenceId: "credential-fixture-1",
        credentialsMountedReadOnly: true,
        outputRedacted: true,
        grantsAuthorization: false,
      });
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain(secret);
      expect(serialized).not.toContain(credentialPath);
      expect(await readFile(credentialPath, "utf8")).toBe(before);
      expect((await stat(credentialPath)).mode & 0o777).toBe(0o400);
    } finally {
      await active.dispose();
      await rm(root, { recursive: true, force: true });
    }
  });
});

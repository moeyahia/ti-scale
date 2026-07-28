import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { describe, expect, test } from "bun:test";
import type { RuntimeSourceManifests } from "../../domain";
import {
  CapabilitySelfTestService,
  EngagementWorkspaceResolver,
  ToolBindingReadinessRunner,
  ToolExecutionPreflightService,
  type CapabilityLocalHealthSnapshot,
  type ToolExecutableIdentity,
  type ToolExecutionPreflightEnvironment,
} from "../../system-capabilities";
import {
  DirectWindowsIdentityProcessAdapter,
  WindowsIdentityCapabilityRegistry,
} from "../../windows-identity-tools";
import type { RuntimeProjectionInput } from "../RuntimeProjectionService";
import {
  activateWindowsIdentityRuntime,
  applyWindowsIdentityRuntimeProjection,
  drainWindowsIdentityReadinessResources,
  projectWindowsIdentityRuntime,
} from "../WindowsIdentityRuntimeComposition";

const NOW = new Date("2026-07-20T10:00:00.000Z");
const EMPTY_MANIFESTS: RuntimeSourceManifests = Object.freeze({
  riskClasses: [],
  evidenceKinds: [],
  capabilities: [],
  tools: [],
  mcpServers: [],
  agents: [],
  providers: [],
});

async function identity(path: string): Promise<ToolExecutableIdentity> {
  const metadata = await lstat(path, { bigint: true });
  return {
    sha256: createHash("sha256").update(await readFile(path)).digest("hex"),
    device: metadata.dev.toString(),
    inode: metadata.ino.toString(),
    sizeBytes: Number(metadata.size),
    mode: Number(metadata.mode & 0o7777n),
    uid: Number(metadata.uid),
    gid: Number(metadata.gid),
  };
}

async function readyRunner(registry: WindowsIdentityCapabilityRegistry): Promise<ToolBindingReadinessRunner> {
  const identities = new Map<string, ToolExecutableIdentity>();
  for (const definition of registry.pack.definitions) {
    identities.set(definition.executable.path, await identity(definition.executable.path));
  }
  const environment: ToolExecutionPreflightEnvironment = {
    isolation: {
      networkEnforced: true,
      filesystemWritesEnforced: true,
      immutableSnapshotEnforced: true,
    },
    async inspectExecutable(path) {
      const executable = identities.get(path);
      return executable ? { state: "ready", identity: executable } : { state: "missing" };
    },
    async inspectWorkingDirectory() { return true; },
    async readNoNewPrivileges() { return true; },
    async execute(input) {
      return {
        exitCode: input.executablePath === "/usr/bin/nxc" ? 1 : 0,
        signal: null,
        stdout: "reviewed version fixture\n",
        stderr: "",
        timedOut: false,
        outputLimitExceeded: false,
        executableIdentity: input.expectedExecutableIdentity,
      };
    },
  };
  return new ToolBindingReadinessRunner(
    registry.createToolBindingRegistry(),
    new ToolExecutionPreflightService({ environment, clock: () => NOW }),
    () => NOW,
  );
}

async function adapter(
  registry: WindowsIdentityCapabilityRegistry,
  expectedSandboxSha256?: string,
): Promise<DirectWindowsIdentityProcessAdapter> {
  const workspaceRoot = "/tmp";
  return new DirectWindowsIdentityProcessAdapter({
    workspaceResolver: new EngagementWorkspaceResolver([{
      logicalRoot: "/engagements",
      runtimeRoot: workspaceRoot,
    }]),
    sandboxExecutable: {
      path: "/usr/bin/bwrap",
      expectedSha256: expectedSandboxSha256
        ?? createHash("sha256").update(await readFile("/usr/bin/bwrap")).digest("hex"),
    },
    now: () => NOW,
  });
}

function baseline(): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
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
    capabilityManifests: EMPTY_MANIFESTS,
  };
}

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

describe("Windows identity runtime composition", () => {
  test("closes the owned probe environment only after runner, activation, and refresh drain", async () => {
    const runner = deferred();
    const activation = deferred();
    const refresh = deferred();
    const events: string[] = [];
    const draining = drainWindowsIdentityReadinessResources({
      runner: {
        stop() {
          events.push("runner-stop-started");
          return runner.promise.then(() => { events.push("runner-drained"); });
        },
      },
      initialActivation: activation.promise.then(() => { events.push("activation-drained"); }),
      refreshInFlight: refresh.promise.then(() => { events.push("refresh-drained"); }),
      probeEnvironment: { close() { events.push("environment-closed"); } },
    });
    await Promise.resolve();
    expect(events).toEqual(["runner-stop-started"]);
    runner.resolve();
    await Promise.resolve();
    expect(events).not.toContain("environment-closed");
    activation.resolve();
    await Promise.resolve();
    expect(events).not.toContain("environment-closed");
    refresh.resolve();
    await draining;
    expect(events).toEqual([
      "runner-stop-started",
      "runner-drained",
      "activation-drained",
      "refresh-drained",
      "environment-closed",
    ]);
  });

  test("still closes the owned probe environment after all work settles when one stage rejects", async () => {
    const runner = deferred();
    const refresh = deferred();
    let closed = false;
    const failure = new Error("bounded readiness fixture failed");
    const draining = drainWindowsIdentityReadinessResources({
      runner: { stop: () => runner.promise },
      refreshInFlight: refresh.promise,
      initialActivation: Promise.reject(failure),
      probeEnvironment: { close() { closed = true; } },
    });
    await Promise.resolve();
    expect(closed).toBeFalse();
    runner.resolve();
    await Promise.resolve();
    expect(closed).toBeFalse();
    refresh.resolve();
    await expect(draining).rejects.toBe(failure);
    expect(closed).toBeTrue();
  });

  test("joins target-free executable receipts to real adapter receipts without granting mission execution", async () => {
    const registry = new WindowsIdentityCapabilityRegistry();
    const processAdapter = await adapter(registry);
    const runner = await readyRunner(registry);
    const activation = await activateWindowsIdentityRuntime({
      registry,
      runner,
      adapter: processAdapter,
      now: NOW,
    });
    expect(activation.status).toBe("ready");
    expect(activation.readyToolIds).toEqual([
      "kali:ldapsearch-root-dse",
      "kali:rpcclient-domain-info",
      "kali:smbclient-share-list",
    ]);
    expect(activation.receipts).toHaveLength(4);
    expect(activation.receipts.every(({ targetContact, grantsMissionExecution }) =>
      targetContact === false && grantsMissionExecution === false)).toBeTrue();
    expect(activation.receipts.find(({ toolId }) => toolId === "kali:nxc-smb-summary"))
      .toMatchObject({
        status: "unavailable",
        code: "windows_identity_adapter_not_bounded",
        credentialIsolationReady: false,
      });

    const projection = projectWindowsIdentityRuntime({
      baselineManifests: EMPTY_MANIFESTS,
      registry,
      activation,
      now: NOW,
    });
    expect(projection.agent).toMatchObject({
      status: "available",
      toolPolicy: {
        allowedTools: activation.readyToolIds,
        deniedTools: ["kali:nxc-smb-summary"],
        exactGuidedDecisionRequired: true,
      },
      configuration: {
        executionMode: "guided_exact_step",
        directArgv: true,
        shell: false,
        credentialDelivery: "opaque_read_only_private_files",
        evidencePromotion: "explicit_only",
      },
    });
    const composed = applyWindowsIdentityRuntimeProjection(baseline(), projection);
    expect(composed.readiness.specialistsConfigured).toBe(1);
    expect(composed.capabilityManifests?.tools.filter(({ available }) => available)).toHaveLength(3);
    expect(processAdapter.readiness("kali:smbclient-share-list")?.status).toBe("ready");
    expect(processAdapter.readiness("kali:nxc-smb-summary")).toBeNull();

    const localHealth = {
      checkedAt: NOW.toISOString(),
      database: {
        healthy: true,
        integrity: ["ok"],
        integrityStatus: "verified",
        integrityCheckedAt: NOW.toISOString(),
        integritySource: "startup",
        journalMode: "wal",
        foreignKeys: true,
        busyTimeoutMs: 5_000,
        currentMigration: 60,
        pendingOutbox: 0,
        checkedAt: NOW.toISOString(),
      },
      eventStream: { started: true, subscribers: 0 },
      secondBrain: {
        health: "healthy",
        databaseHealthy: true,
        canonicalStoreAvailable: true,
        lexicalIndexAvailable: true,
        lexicalIndexSynchronized: true,
        vaultProjection: {
          status: "healthy",
          configuredConnections: 1,
          connectedConnections: 1,
          reachableConnections: 1,
          healthVerifiedConnections: 1,
          reason: "The bounded fixture Vault is healthy.",
        },
        reason: "The bounded fixture Brain is healthy.",
      },
    } satisfies CapabilityLocalHealthSnapshot;
    const selfTests = new CapabilitySelfTestService({
      repository: { read: () => localHealth },
      readRuntimeProjection: () => composed,
      readToolExecutionPreflight: (toolId) =>
        runner.readToolExecutionPreflight(toolId),
      clock: () => NOW,
    }).snapshot();
    for (const toolId of activation.readyToolIds) {
      expect(selfTests.results.find(({ component }) => component.id === toolId))
        .toMatchObject({
          status: "pass",
          availability: "available",
          freshness: { state: "fresh" },
        });
    }
    expect(selfTests.results.find(({ component }) =>
      component.id === "kali:nxc-smb-summary")).toMatchObject({
      status: "fail",
      availability: "unavailable",
    });
  });

  test("keeps every tool and the specialist unavailable when the sandbox identity cannot be attested", async () => {
    const registry = new WindowsIdentityCapabilityRegistry();
    const processAdapter = await adapter(registry, "f".repeat(64));
    const activation = await activateWindowsIdentityRuntime({
      registry,
      runner: await readyRunner(registry),
      adapter: processAdapter,
      now: NOW,
    });
    expect(activation).toMatchObject({
      status: "unavailable",
      readyToolIds: [],
    });
    expect(activation.receipts).toHaveLength(4);
    expect(activation.receipts.every(({ status, grantsMissionExecution }) =>
      status === "unavailable" && grantsMissionExecution === false)).toBeTrue();
    const projection = projectWindowsIdentityRuntime({
      baselineManifests: EMPTY_MANIFESTS,
      registry,
      activation,
      now: NOW,
    });
    expect(projection.agent.status).toBe("offline");
    expect(projection.agent.toolPolicy.allowedTools).toEqual([]);
    expect(projection.agent.toolPolicy.deniedTools).toEqual([
      "kali:ldapsearch-root-dse",
      "kali:nxc-smb-summary",
      "kali:rpcclient-domain-info",
      "kali:smbclient-share-list",
    ]);
    expect(applyWindowsIdentityRuntimeProjection(baseline(), projection)
      .readiness.specialistsConfigured).toBe(0);
  });

  test("rejects a readiness runner from a different reviewed registry", async () => {
    const registry = new WindowsIdentityCapabilityRegistry();
    const mismatched = new WindowsIdentityCapabilityRegistry();
    const original = mismatched.createToolBindingRegistry.bind(mismatched);
    Object.defineProperty(mismatched, "createToolBindingRegistry", {
      value: () => {
        const bound = original();
        return Object.freeze({
          ...bound,
          descriptor: { ...bound.descriptor, registrySha256: "0".repeat(64) },
        });
      },
    });
    await expect(activateWindowsIdentityRuntime({
      registry,
      runner: await readyRunner(mismatched),
      adapter: await adapter(registry),
      now: NOW,
    })).rejects.toThrow("different reviewed registry");
  });
});

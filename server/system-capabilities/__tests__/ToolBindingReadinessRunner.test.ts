import { describe, expect, test } from "bun:test";
import type { RuntimeProjectionInput } from "../../app/RuntimeProjectionService";
import type { RuntimeSourceManifests } from "../../domain";
import fixture from "./fixtures/tool-binding-registry.v1.json";
import type { CapabilityLocalHealthSnapshot } from "../CapabilitySelfTestRepository";
import { CapabilitySelfTestService } from "../CapabilitySelfTestService";
import {
  ToolBindingReadinessRunner,
  type ToolBindingReadinessTimerEnvironment,
} from "../ToolBindingReadinessRunner";
import { ToolBindingRegistry } from "../ToolBindingRegistry";
import {
  ToolExecutionPreflightService,
  type ToolExecutionPreflightResult,
  type ToolExecutionPreflightSpec,
  type ToolExecutionPreflightEnvironment,
  type ToolExecutableIdentity,
  type ToolProbeExecutionResult,
} from "../ToolExecutionPreflight";

const EXECUTABLE_IDENTITY: ToolExecutableIdentity = Object.freeze({
  sha256: "a".repeat(64),
  device: "1",
  inode: "2",
  sizeBytes: 1024,
  mode: 0o755,
  uid: 0,
  gid: 0,
});

function manifests(toolIds: readonly string[] = ["kali:curl", "kali:nmap"]): RuntimeSourceManifests {
  return {
    riskClasses: [{
      id: "read-only",
      label: "Read only",
      actionClassIds: ["passive_intelligence_osint"],
    }],
    evidenceKinds: [],
    capabilities: [],
    tools: toolIds.map((id) => ({
      id,
      label: id === "kali:nmap" ? "Nmap" : "Curl",
      available: true,
      locallyPolicyEnforced: true,
      requiresModel: false,
      actionClassIds: ["passive_intelligence_osint"],
      evidenceTypeIds: [],
      riskClassIds: ["read-only"],
    })),
    mcpServers: [],
    agents: [],
    providers: [],
  };
}

function output(overrides: Partial<ToolProbeExecutionResult> = {}): ToolProbeExecutionResult {
  return {
    exitCode: 0,
    signal: null,
    stdout: "tool version 1.0\n",
    stderr: "",
    timedOut: false,
    outputLimitExceeded: false,
    executableIdentity: EXECUTABLE_IDENTITY,
    ...overrides,
  };
}

function environment(
  overrides: Partial<ToolExecutionPreflightEnvironment> = {},
): ToolExecutionPreflightEnvironment {
  return {
    isolation: {
      networkEnforced: true,
      filesystemWritesEnforced: true,
      immutableSnapshotEnforced: true,
    },
    inspectExecutable: async () => ({ state: "ready", identity: EXECUTABLE_IDENTITY }),
    inspectWorkingDirectory: async () => true,
    readNoNewPrivileges: async () => true,
    execute: async () => output(),
    ...overrides,
  };
}

function oneBinding(overrides: Record<string, unknown> = {}): unknown {
  return {
    schemaVersion: "ti-scale.tool-binding-registry.v1",
    registryVersion: "test-v1",
    bindings: [{
      toolId: "kali:nmap",
      executablePath: "/usr/bin/nmap",
      probeArguments: ["--version"],
      expectedExitCodes: [0],
      timeoutMs: 2_000,
      maximumOutputBytes: 16_384,
      ttlMs: 60_000,
      ...overrides,
    }],
  };
}

function runnerFor(
  document: unknown,
  env: ToolExecutionPreflightEnvironment,
  clock: () => Date = () => new Date("2026-07-18T22:00:00.000Z"),
  runtimeManifests = manifests(["kali:nmap"]),
): ToolBindingReadinessRunner {
  return new ToolBindingReadinessRunner(
    new ToolBindingRegistry(document, runtimeManifests),
    new ToolExecutionPreflightService({ environment: env, clock }),
    clock,
  );
}

function runtimeProjection(capabilityManifests: RuntimeSourceManifests): RuntimeProjectionInput {
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
    capabilityManifests,
  };
}

function localHealth(checkedAt: string): CapabilityLocalHealthSnapshot {
  return {
    checkedAt,
    database: {
      healthy: true,
      integrity: ["ok"],
      integrityStatus: "verified",
      integrityCheckedAt: checkedAt,
      integritySource: "startup",
      journalMode: "wal",
      foreignKeys: true,
      busyTimeoutMs: 5_000,
      currentMigration: 15,
      pendingOutbox: 0,
      checkedAt,
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
        reason: "healthy fixture",
      },
      reason: "healthy fixture",
    },
  };
}

describe("ToolBindingRegistry", () => {
  test("loads a versioned fixture only after every local binding matches a runtime tool manifest", () => {
    const registry = new ToolBindingRegistry(fixture, manifests());
    expect(registry.descriptor).toMatchObject({
      schemaVersion: "ti-scale.tool-binding-registry.v1",
      registryVersion: "fixture-2026.07.18",
      registeredBindingCount: 2,
      runtimeToolCount: 2,
      boundRuntimeToolCount: 2,
      runtimeToolsWithoutLocalBinding: 0,
      sourceOfTruth: "runtime-manifest-aligned-local-bindings",
    });
    expect(registry.descriptor.registrySha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(registry.descriptor.runtimeManifestSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(registry.list().map(({ toolId }) => toolId)).toEqual(["kali:curl", "kali:nmap"]);
    expect(Object.isFrozen(registry.list())).toBe(true);
    expect(Object.isFrozen(registry.resolve("kali:nmap"))).toBe(true);
  });

  test("rejects duplicate runtime tool IDs before any probe can run", () => {
    const duplicate = structuredClone(fixture) as typeof fixture;
    duplicate.bindings[1] = { ...duplicate.bindings[0] };
    expect(() => new ToolBindingRegistry(duplicate, manifests()))
      .toThrow("duplicate tool ID kali:curl");
  });

  test("rejects bindings missing from the runtime manifest and structurally invalid manifests", () => {
    expect(() => new ToolBindingRegistry(oneBinding({ toolId: "kali:unknown" }), manifests(["kali:nmap"])))
      .toThrow("not present in the current runtime tool manifest");
    const invalid = manifests(["kali:nmap"]);
    expect(() => new ToolBindingRegistry(oneBinding(), {
      ...invalid,
      tools: [invalid.tools[0]!, invalid.tools[0]!],
    })).toThrow("duplicate id kali:nmap");
  });

  test("keeps remote MCP tools outside the local executable registry", () => {
    const runtime = manifests(["kali:nmap"]);
    const remote: RuntimeSourceManifests = {
      ...runtime,
      tools: [{ ...runtime.tools[0]!, mcpServerId: "mcp:scanner" }],
      mcpServers: [{
        id: "mcp:scanner",
        label: "Reviewed scanner MCP",
        status: "healthy",
        toolIds: ["kali:nmap"],
      }],
    };
    expect(() => new ToolBindingRegistry(oneBinding(), remote))
      .toThrow("remote/MCP-backed and cannot be probed as a local executable");
  });

  test("rejects unreviewed arguments, relative executables, implicit limits, and hidden fields", () => {
    expect(() => new ToolBindingRegistry(
      oneBinding({ toolId: "runtime:session-token" }),
      manifests(["runtime:session-token"]),
    )).toThrow("requires a stable public runtime tool ID");
    expect(() => new ToolBindingRegistry(oneBinding({ probeArguments: ["--version", "10.0.0.1"] }), manifests(["kali:nmap"])))
      .toThrow("exactly one reviewed version/help argument");
    expect(() => new ToolBindingRegistry(oneBinding({ probeArguments: ["--script", "vuln"] }), manifests(["kali:nmap"])))
      .toThrow("exactly one reviewed version/help argument");
    expect(() => new ToolBindingRegistry(oneBinding({ executablePath: "nmap" }), manifests(["kali:nmap"])))
      .toThrow("absolute non-control path");
    expect(() => new ToolBindingRegistry(oneBinding({ timeoutMs: undefined }), manifests(["kali:nmap"])))
      .toThrow("timeoutMs must be an integer");
    expect(() => new ToolBindingRegistry(oneBinding({ target: "10.0.0.1" }), manifests(["kali:nmap"])))
      .toThrow("must contain exactly");
  });
});

describe("ToolBindingReadinessRunner", () => {
  test("runs every binding sequentially and produces complete immutable secret-free accounting", async () => {
    const calls: Array<{ path: string; arguments: readonly string[] }> = [];
    let active = 0;
    let peak = 0;
    const env = environment({
      execute: async (input) => {
        active += 1;
        peak = Math.max(peak, active);
        calls.push({ path: input.executablePath, arguments: input.arguments });
        await Promise.resolve();
        active -= 1;
        return input.executablePath.endsWith("nmap")
          ? output({ stdout: "Nmap version 7.99\nBearer sk-never-return-this\n" })
          : output({ stdout: "curl 8.0\n" });
      },
    });
    const clock = () => new Date("2026-07-18T22:00:00.000Z");
    const runner = runnerFor(fixture, env, clock, manifests());
    const snapshot = await runner.runAll();

    expect(peak).toBe(1);
    expect(calls).toEqual([
      { path: "/usr/bin/curl", arguments: ["--version"] },
      { path: "/usr/bin/nmap", arguments: ["--version"] },
    ]);
    expect(snapshot).toMatchObject({
      schemaVersion: "ti-scale.tool-binding-readiness-snapshot.v2",
      readOnly: true,
      grantsMissionExecution: false,
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
      accounting: {
        registered: 2,
        attempted: 2,
        reported: 2,
        missing: 0,
        unexpected: 0,
        ready: 2,
        unavailable: 0,
        fresh: 2,
        stale: 0,
        complete: true,
        current: true,
      },
    });
    const serialized = JSON.stringify(snapshot);
    expect(serialized).not.toContain("sk-never-return-this");
    expect(serialized).not.toContain("Bearer");
    expect(serialized).not.toContain("/usr/bin/nmap");
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.accounting)).toBe(true);
    expect(Object.isFrozen(snapshot.receipts[0])).toBe(true);
    expect(runner.readToolExecutionPreflight("kali:nmap")).toMatchObject({
      status: "ready",
      probeBoundary: { targetArgumentsSupplied: false, shell: false },
      executableIdentity: EXECUTABLE_IDENTITY,
    });
  });

  test.each([
    ["missing", "executable_missing"],
    ["not_regular", "executable_not_regular_file"],
    ["not_executable", "executable_not_executable"],
  ] as const)("accounts for a %s executable without attempting it", async (state, code) => {
    let executed = false;
    const runner = runnerFor(oneBinding(), environment({
      inspectExecutable: async () => ({ state }),
      execute: async () => {
        executed = true;
        return output();
      },
    }));
    const snapshot = await runner.runAll();
    expect(executed).toBe(false);
    expect(snapshot.accounting).toMatchObject({
      registered: 1,
      attempted: 1,
      reported: 1,
      unavailable: 1,
      complete: true,
      current: true,
    });
    expect(snapshot.receipts[0]).toMatchObject({ status: "unavailable", code });
  });

  test.each([
    ["startup_probe_timeout", { timedOut: true }],
    ["startup_probe_output_limit", { outputLimitExceeded: true, stdout: "x".repeat(20_000) }],
    ["startup_probe_empty", { stdout: "", stderr: "" }],
    ["startup_probe_failed", { exitCode: 2, stderr: "bad option" }],
  ] as const)("classifies and accounts for %s", async (code, overrides) => {
    const runner = runnerFor(oneBinding(), environment({
      execute: async () => output(overrides),
    }));
    const snapshot = await runner.runAll();
    expect(snapshot.accounting).toMatchObject({
      registered: 1,
      attempted: 1,
      reported: 1,
      unavailable: 1,
      complete: true,
    });
    expect(snapshot.receipts[0]).toMatchObject({ status: "unavailable", code });
  });

  test("surfaces only an observed NoNewPrivs capability-transition conflict", async () => {
    const runner = runnerFor(oneBinding(), environment({
      readNoNewPrivileges: async () => true,
      execute: async () => output({
        exitCode: null,
        stdout: "",
        stderr: "exec: operation not permitted",
        spawnErrorCode: "EPERM",
      }),
    }));
    const snapshot = await runner.runAll();
    expect(snapshot.receipts[0]).toMatchObject({
      code: "no_new_privileges_capability_conflict",
      privilegeBoundary: {
        noNewPrivileges: true,
        capabilityTransitionConflictObserved: true,
      },
    });
  });

  test("retains complete accounting but refuses to call expired receipts current", async () => {
    let now = new Date("2026-07-18T22:00:00.000Z");
    const clock = () => now;
    const runner = runnerFor(oneBinding({ ttlMs: 1_000 }), environment(), clock);
    const fresh = await runner.runAll();
    expect(fresh.accounting).toMatchObject({ complete: true, current: true, fresh: 1, stale: 0 });

    now = new Date("2026-07-18T22:00:01.000Z");
    const stale = runner.snapshot();
    expect(stale.accounting).toMatchObject({ complete: true, current: false, fresh: 0, stale: 1 });
    expect(stale.receipts[0]).toBe(fresh.receipts[0]);
  });

  test("single-flights concurrent startup requests instead of duplicating probes", async () => {
    let calls = 0;
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const runner = runnerFor(oneBinding(), environment({
      execute: async () => {
        calls += 1;
        await gate;
        return output();
      },
    }));
    const first = runner.runAll();
    const second = runner.runAll();
    release?.();
    const [left, right] = await Promise.all([first, second]);
    expect(calls).toBe(1);
    expect(left).toBe(right);
  });

  test("stops after the current bounded probe and never starts the next binding", async () => {
    const calls: string[] = [];
    let release: (() => void) | undefined;
    let entered: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const runner = runnerFor(fixture, environment({
      execute: async (input) => {
        calls.push(input.executablePath);
        entered?.();
        await gate;
        return output();
      },
    }), undefined, manifests());

    const active = runner.runAll();
    await started;
    const stopping = runner.stop();
    release?.();
    const [runSnapshot, stopSnapshot] = await Promise.all([active, stopping]);

    expect(calls).toEqual(["/usr/bin/curl"]);
    expect(runSnapshot.accounting).toMatchObject({
      registered: 2,
      attempted: 1,
      reported: 1,
      missing: 1,
      complete: false,
      current: false,
    });
    expect(stopSnapshot).toEqual(runSnapshot);
    await runner.runAll();
    expect(calls).toHaveLength(1);
  });

  test("refreshes before the shortest receipt TTL and clears the timer on stop", async () => {
    let probes = 0;
    let resolveSecondWave: (() => void) | undefined;
    const secondWave = new Promise<void>((resolve) => { resolveSecondWave = resolve; });
    let scheduled: (() => void) | undefined;
    const delays: number[] = [];
    let resolveSecondTimer: (() => void) | undefined;
    const secondTimer = new Promise<void>((resolve) => { resolveSecondTimer = resolve; });
    let cleared = 0;
    const timers: ToolBindingReadinessTimerEnvironment = {
      set(callback, delayMs) {
        scheduled = callback;
        delays.push(delayMs);
        if (delays.length === 2) resolveSecondTimer?.();
        return { callback };
      },
      clear() { cleared += 1; },
    };
    const runtimeManifests = manifests();
    const runner = new ToolBindingReadinessRunner(
      new ToolBindingRegistry(fixture, runtimeManifests),
      new ToolExecutionPreflightService({
        environment: environment({
          execute: async () => {
            probes += 1;
            if (probes === 4) resolveSecondWave?.();
            return output();
          },
        }),
        clock: () => new Date("2026-07-18T22:00:00.000Z"),
      }),
      () => new Date("2026-07-18T22:00:00.000Z"),
      timers,
    );

    await runner.startMonitoring();
    expect(probes).toBe(2);
    expect(delays).toEqual([30_000]);
    scheduled?.();
    await Promise.all([secondWave, secondTimer]);
    expect(probes).toBe(4);
    expect(delays).toEqual([30_000, 30_000]);
    await runner.stop();
    expect(cleared).toBe(1);
  });

  test("feeds the exact cached preflight into a fully activated CapabilitySelfTest without a second probe", async () => {
    const now = new Date("2026-07-18T22:00:00.000Z");
    const runtimeManifests = manifests(["kali:nmap"]);
    let probes = 0;
    const runner = runnerFor(oneBinding(), environment({
      execute: async () => {
        probes += 1;
        return output();
      },
    }), () => now, runtimeManifests);
    await runner.runAll();

    const preflight = runner.readToolExecutionPreflight("kali:nmap");
    expect(preflight).toBeDefined();
    const activation = {
      schemaVersion: "ti-scale.local-tool-activation-receipt.v1" as const,
      source: "local_guided_tool_activation" as const,
      manifestSha256: "d".repeat(64),
      toolBindingSha256: runner.registry.resolve("kali:nmap")!.bindingSha256,
      preflightBindingSha256: preflight!.bindingSha256,
      executableSha256: preflight!.executableIdentity!.sha256,
      observedAt: now.toISOString(),
      expiresAt: preflight!.expiresAt,
    };
    const activatedManifests: RuntimeSourceManifests = {
      ...runtimeManifests,
      tools: runtimeManifests.tools.map((tool) => ({
        ...tool,
        dependencies: [
          "operator-activation",
          "executable-integrity",
          "isolated-target-free-readiness",
          "direct-argv-adapter",
          "workspace-confinement",
          "result-sink",
          "cancellation",
        ].map((id) => ({ id, ready: true, attestation: activation })),
      })),
    };

    const preflightOnly = new CapabilitySelfTestService({
      repository: { read: () => localHealth(now.toISOString()) },
      readRuntimeProjection: () => runtimeProjection(runtimeManifests),
      readToolExecutionPreflight: (toolId) => runner.readToolExecutionPreflight(toolId),
      clock: () => now,
    }).snapshot();
    expect(preflightOnly.results.find(({ component }) => component.id === "kali:nmap"))
      .toMatchObject({
        testKind: "manifest_dependency",
        status: "fail",
        availability: "unavailable",
      });

    const snapshot = new CapabilitySelfTestService({
      repository: { read: () => localHealth(now.toISOString()) },
      readRuntimeProjection: () => runtimeProjection(activatedManifests),
      readToolExecutionPreflight: (toolId) => runner.readToolExecutionPreflight(toolId),
      clock: () => now,
    }).snapshot();

    expect(probes).toBe(1);
    expect(snapshot.results.find(({ component }) => component.id === "kali:nmap"))
      .toMatchObject({
        testKind: "local_executable_attestation",
        status: "pass",
        availability: "available",
        freshness: { state: "fresh" },
      });
    expect(snapshot.accounting).toMatchObject({
      complete: true,
      registered: { tools: 1 },
      reported: { tools: 1 },
    });
  });

  test("contains unexpected local runner errors without leaking them or losing accounting", async () => {
    const runner = runnerFor(oneBinding(), environment({
      inspectExecutable: async () => { throw new Error("Bearer sk-never-return-this"); },
    }));
    const snapshot = await runner.runAll();
    expect(snapshot.accounting).toMatchObject({
      registered: 1,
      attempted: 1,
      reported: 1,
      unavailable: 1,
      complete: true,
    });
    expect(snapshot.receipts[0]).toMatchObject({
      code: "readiness_runner_error",
      status: "unavailable",
      probeBoundary: {
        targetArgumentsSupplied: false,
        providerArgumentsSupplied: false,
        mcpArgumentsSupplied: false,
        externalContact: "not_measured",
      },
    });
    expect(JSON.stringify(snapshot)).not.toContain("sk-never-return-this");
  });

  test("rejects a forged ready result whose binding digest does not match the reviewed probe", async () => {
    const clock = () => new Date("2026-07-18T22:00:00.000Z");
    const honest = new ToolExecutionPreflightService({
      environment: environment(),
      clock,
    });
    class ForgedPreflight extends ToolExecutionPreflightService {
      override async check(spec: ToolExecutionPreflightSpec): Promise<ToolExecutionPreflightResult> {
        return {
          ...await honest.check(spec),
          bindingSha256: "b".repeat(64),
        };
      }
    }
    const runner = new ToolBindingReadinessRunner(
      new ToolBindingRegistry(oneBinding(), manifests(["kali:nmap"])),
      new ForgedPreflight(),
      clock,
    );

    const snapshot = await runner.runAll();
    expect(snapshot.accounting).toMatchObject({
      registered: 1,
      attempted: 1,
      reported: 1,
      ready: 0,
      unavailable: 1,
      complete: true,
    });
    expect(snapshot.receipts[0]).toMatchObject({
      status: "unavailable",
      code: "readiness_runner_error",
      preflightBindingSha256: null,
    });
  });

  test("does not copy an untrusted spawn error value into the immutable receipt", async () => {
    const runner = runnerFor(oneBinding(), environment({
      execute: async () => output({
        exitCode: null,
        stdout: "",
        stderr: "",
        spawnErrorCode: "sk-never-return-this",
      }),
    }));
    const snapshot = await runner.runAll();
    expect(snapshot.receipts[0]?.execution.spawnErrorCode).toBeNull();
    expect(JSON.stringify(snapshot)).not.toContain("sk-never-return-this");
  });
});

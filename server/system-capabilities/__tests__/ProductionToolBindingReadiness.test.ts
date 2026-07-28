import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildRuntimeCapabilityProjection, type RuntimeSourceManifests } from "../../domain";
import { MissionIntakeService } from "../../intake";
import { createProductionToolBindingReadiness } from "../ProductionToolBindingReadiness";
import {
  ToolExecutionPreflightService,
  type ToolExecutionPreflightEnvironment,
} from "../ToolExecutionPreflight";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { force: true, recursive: true });
});

function manifests(tool: RuntimeSourceManifests["tools"][number] | undefined): RuntimeSourceManifests {
  return {
    riskClasses: tool ? [{
      id: "read-only",
      label: "Read only",
      actionClassIds: ["passive_intelligence_osint"],
    }] : [],
    evidenceKinds: [],
    capabilities: tool ? [{
      id: "recon-capability",
      label: "Recon capability",
      actionClassIds: ["passive_intelligence_osint"],
    }] : [],
    tools: tool ? [tool] : [],
    mcpServers: tool?.mcpServerId ? [{
      id: tool.mcpServerId,
      label: "Remote inventory",
      status: "healthy",
      toolIds: [tool.id],
    }] : [],
    agents: tool ? [{
      id: "recon-agent",
      label: "Recon agent",
      available: true,
      capabilityIds: ["recon-capability"],
      toolIds: [tool.id],
      modelRefs: [],
    }] : [],
    providers: [],
  };
}

function localTool(): RuntimeSourceManifests["tools"][number] {
  return {
    id: "kali:curl",
    label: "Curl",
    available: true,
    locallyPolicyEnforced: true,
    requiresModel: false,
    actionClassIds: ["passive_intelligence_osint"],
    evidenceTypeIds: [],
    riskClassIds: ["read-only"],
  };
}

function writeRegistry(value: unknown): string {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-tool-registry-"));
  roots.push(root);
  const path = join(root, "registry.json");
  writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
  return path;
}

function registryDocument(executablePath = "/usr/bin/curl"): unknown {
  return {
    schemaVersion: "ti-scale.tool-binding-registry.v1",
    registryVersion: "production-test-v1",
    bindings: [{
      toolId: "kali:curl",
      executablePath,
      probeArguments: ["--version"],
      expectedExitCodes: [0],
      timeoutMs: 2_000,
      maximumOutputBytes: 16_384,
      ttlMs: 60_000,
    }],
  };
}

function isolatedPreflight(
  clock: () => Date,
  overrides: Partial<ToolExecutionPreflightEnvironment> = {},
): ToolExecutionPreflightService {
  return new ToolExecutionPreflightService({
    clock,
    environment: {
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
      inspectWorkingDirectory: async () => true,
      readNoNewPrivileges: async () => true,
      execute: async () => ({
        exitCode: 0,
        signal: null,
        stdout: "curl 8.0\n",
        stderr: "",
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
      }),
      ...overrides,
    },
  });
}

describe("production tool binding readiness", () => {
  test("uses a truthful empty registry when the runtime declares no local tools", async () => {
    const readiness = createProductionToolBindingReadiness({ manifests: manifests(undefined) });
    expect(readiness.configured).toBe(false);
    expect((await readiness.runner.runAll()).accounting).toMatchObject({
      registered: 0,
      attempted: 0,
      reported: 0,
      complete: true,
      current: true,
    });
  });

  test("fails closed when an available local runtime tool lacks a reviewed binding", () => {
    expect(() => createProductionToolBindingReadiness({ manifests: manifests(localTool()) }))
      .toThrow("1 available local runtime tool binding is missing");
  });

  test("loads a bounded absolute registry and aligns it to the runtime manifest", () => {
    const path = writeRegistry(registryDocument());
    const readiness = createProductionToolBindingReadiness({
      manifests: manifests(localTool()),
      registryPath: path,
    });
    expect(readiness.configured).toBe(true);
    expect(readiness.runner.registry.descriptor).toMatchObject({
      registeredBindingCount: 1,
      runtimeToolCount: 1,
      runtimeToolsWithoutLocalBinding: 0,
    });
  });

  test("does not require a local executable binding for a remote MCP tool", () => {
    const remote = { ...localTool(), mcpServerId: "mcp:read-only" };
    const readiness = createProductionToolBindingReadiness({ manifests: manifests(remote) });
    expect(readiness.runner.registry.descriptor).toMatchObject({
      registeredBindingCount: 0,
      runtimeToolCount: 1,
      runtimeToolsWithoutLocalBinding: 0,
    });
    const projected = readiness.projectManifests(manifests(remote));
    expect(projected.tools[0]).toMatchObject({
      available: false,
      dependencies: [{ id: "exact-mcp-tool-identity", ready: false }],
    });
    expect(buildRuntimeCapabilityProjection(projected).actionClasses.passive_intelligence_osint)
      .toMatchObject({ enforcementReady: false, availableToolIds: [] });
  });

  test("preserves a remote tool only when its full server-qualified ID matches exactly", () => {
    const remote = {
      ...localTool(),
      id: "mcp:read-only/curl",
      mcpServerId: "mcp:read-only",
    };
    const runtime = manifests(remote);
    const readiness = createProductionToolBindingReadiness({ manifests: runtime });
    expect(readiness.projectManifests(runtime).tools[0]).toEqual(remote);
  });

  test("rejects a qualified prefix with no stable tool-name suffix", () => {
    const remote = {
      ...localTool(),
      id: "mcp:read-only/",
      mcpServerId: "mcp:read-only",
    };
    const runtime = manifests(remote);
    const projected = createProductionToolBindingReadiness({ manifests: runtime })
      .projectManifests(runtime);
    expect(projected.tools[0]).toMatchObject({
      available: false,
      dependencies: [{ id: "exact-mcp-tool-identity", ready: false }],
    });
  });

  test.each([
    ["duplicate", ["mcp:read-only/curl", "mcp:read-only/curl"]],
    ["extra", ["mcp:read-only/curl", "mcp:read-only/unassigned"]],
    ["foreign-prefix", ["mcp:read-only/curl", "mcp:other/tool"]],
    ["bare-name", ["mcp:read-only/curl", "unqualified-tool"]],
    ["missing", []],
  ] as const)("withdraws every tool on a server whose closed inventory is %s", (_case, toolIds) => {
    const remote = {
      ...localTool(),
      id: "mcp:read-only/curl",
      mcpServerId: "mcp:read-only",
    };
    const extraId = toolIds.find((toolId) => toolId !== remote.id);
    const runtime: RuntimeSourceManifests = {
      ...manifests(remote),
      riskClasses: [{
        id: "read-only",
        label: "Read only",
        actionClassIds: ["passive_intelligence_osint", "active_host_discovery"],
      }],
      tools: [
        remote,
        ...(extraId ? [{
          ...localTool(),
          id: extraId,
          label: "Unassigned inventory fixture",
          available: false,
          actionClassIds: ["active_host_discovery"],
        }] : []),
      ],
      mcpServers: [{
        id: "mcp:read-only",
        label: "Remote inventory",
        status: "healthy",
        toolIds,
      }],
      agents: [{
        id: "recon-agent",
        label: "Recon agent",
        available: true,
        capabilityIds: ["recon-capability"],
        toolIds: [remote.id],
        modelRefs: [],
      }],
    };
    const readiness = createProductionToolBindingReadiness({ manifests: runtime });
    const projected = readiness.projectManifests(runtime);
    const projectedRemote = projected.tools.find(({ id }) => id === remote.id);
    expect(projectedRemote).toMatchObject({ available: false });
    expect(projectedRemote?.dependencies).toContainEqual({
      id: "exact-mcp-tool-identity",
      ready: false,
    });
    expect(buildRuntimeCapabilityProjection(projected).actionClasses.passive_intelligence_osint)
      .toMatchObject({ enforcementReady: false, availableToolIds: [] });
  });

  test("withdraws all assigned tools when even one is absent from the server inventory", () => {
    const first = {
      ...localTool(),
      id: "mcp:read-only/first",
      mcpServerId: "mcp:read-only",
    };
    const second = { ...first, id: "mcp:read-only/second" };
    const runtime: RuntimeSourceManifests = {
      ...manifests(first),
      tools: [first, second],
      mcpServers: [{
        id: "mcp:read-only",
        label: "Remote inventory",
        status: "healthy",
        toolIds: [first.id],
      }],
      agents: [{
        id: "recon-agent",
        label: "Recon agent",
        available: true,
        capabilityIds: ["recon-capability"],
        toolIds: [first.id, second.id],
        modelRefs: [],
      }],
    };
    const projected = createProductionToolBindingReadiness({ manifests: runtime })
      .projectManifests(runtime);
    expect(projected.tools.map(({ available }) => available)).toEqual([false, false]);
    expect(buildRuntimeCapabilityProjection(projected).actionClasses.passive_intelligence_osint)
      .toMatchObject({ enforcementReady: false, availableToolIds: [] });
  });

  test("withdraws both servers when two IDs claim the same normalized MCP namespace", () => {
    const first = {
      ...localTool(),
      id: "mcp:read-only/first",
      mcpServerId: "read-only",
    };
    const second = {
      ...localTool(),
      id: "mcp:read-only/second",
      mcpServerId: "mcp:read-only",
    };
    const runtime: RuntimeSourceManifests = {
      ...manifests(first),
      tools: [first, second],
      mcpServers: [
        {
          id: "read-only",
          label: "First namespace owner",
          status: "healthy",
          toolIds: [first.id],
        },
        {
          id: "mcp:read-only",
          label: "Aliased namespace owner",
          status: "healthy",
          toolIds: [second.id],
        },
      ],
      agents: [{
        id: "recon-agent",
        label: "Recon agent",
        available: true,
        capabilityIds: ["recon-capability"],
        toolIds: [first.id, second.id],
        modelRefs: [],
      }],
    };

    const projected = createProductionToolBindingReadiness({ manifests: runtime })
      .projectManifests(runtime);
    expect(projected.tools.map(({ available }) => available)).toEqual([false, false]);
    expect(projected.tools.every((tool) => tool.dependencies?.some((dependency) =>
      dependency.id === "exact-mcp-tool-identity" && !dependency.ready))).toBe(true);
    expect(buildRuntimeCapabilityProjection(projected).actionClasses.passive_intelligence_osint)
      .toMatchObject({ enforcementReady: false, availableToolIds: [] });
  });

  test("rejects relative and malformed registry sources without echoing their content", () => {
    expect(() => createProductionToolBindingReadiness({
      manifests: manifests(undefined),
      registryPath: "relative.json",
    })).toThrow("must be an absolute path");
    const path = writeRegistry("Bearer sk-never-return-this");
    expect(() => createProductionToolBindingReadiness({
      manifests: manifests(undefined),
      registryPath: path,
    })).toThrow("Tool binding registry must be a plain object");
  });

  test("rejects symlinked and writable registry paths before parsing", () => {
    const target = writeRegistry(registryDocument());
    const root = mkdtempSync(join(tmpdir(), "ti-scale-tool-registry-link-"));
    roots.push(root);
    const link = join(root, "registry-link.json");
    symlinkSync(target, link);
    expect(() => createProductionToolBindingReadiness({
      manifests: manifests(localTool()),
      registryPath: link,
    })).toThrow("regular non-symlink file");

    chmodSync(target, 0o622);
    expect(() => createProductionToolBindingReadiness({
      manifests: manifests(localTool()),
      registryPath: target,
    })).toThrow("trusted owner");
  });

  test("awaits complete accounting and keeps missing or failed local receipts unavailable", async () => {
    const runtime = manifests(localTool());
    const path = writeRegistry(registryDocument());
    const now = new Date("2026-07-18T23:00:00.000Z");
    const readiness = createProductionToolBindingReadiness({
      manifests: runtime,
      registryPath: path,
      clock: () => now,
      preflight: isolatedPreflight(() => now, {
        inspectExecutable: async () => ({ state: "missing" }),
      }),
    });

    expect(() => readiness.assertCompleteInitialWave(readiness.runner.snapshot()))
      .toThrow("complete registry accounting");
    expect(readiness.projectManifests(runtime).tools[0]).toMatchObject({
      available: false,
      dependencies: [{ id: "local-tool-binding-readiness", ready: false }],
    });

    const initial = await readiness.runner.startMonitoring();
    readiness.assertCompleteInitialWave(initial);
    expect(() => readiness.assertCompleteInitialWave({
      ...initial,
      accounting: { ...initial.accounting, attempted: 0 },
    })).toThrow("complete registry accounting");
    expect(initial.accounting).toMatchObject({
      registered: 1,
      reported: 1,
      unavailable: 1,
      complete: true,
      current: true,
    });
    const projected = readiness.projectManifests(runtime, now);
    expect(projected.tools[0]).toMatchObject({ available: false });
    const capability = buildRuntimeCapabilityProjection(projected)
      .actionClasses.passive_intelligence_osint;
    expect(capability).toMatchObject({ enforcementReady: false, availableToolIds: [] });
    const intakeRegistry = new MissionIntakeService({ readRuntimeManifests: () => projected })
      .snapshot("autonomous", "safe_recon")
      .actionClasses;
    const intakeClass = intakeRegistry.classes.passive_intelligence_osint;
    expect(intakeClass.capability).toMatchObject({ enforcementReady: false, availableToolIds: [] });
    expect(intakeClass.policyState).toBe("prohibited");
    expect(intakeRegistry.autonomousLaunchReady).toBe(false);
    expect(intakeRegistry.launchBlockingReasons).toContain(
      "No supported, locally enforced action class is available for Autonomous execution.",
    );
    await readiness.runner.stop();
  });

  test("accepts only a fresh isolated identity-bound receipt and withdraws it on expiry or manifest drift", async () => {
    const runtime = manifests(localTool());
    const path = writeRegistry(registryDocument());
    let now = new Date("2026-07-18T23:00:00.000Z");
    const readiness = createProductionToolBindingReadiness({
      manifests: runtime,
      registryPath: path,
      clock: () => now,
      preflight: isolatedPreflight(() => now),
    });
    const initial = await readiness.runner.startMonitoring();
    readiness.assertCompleteInitialWave(initial);

    const ready = readiness.projectManifests(runtime, now);
    expect(ready.tools[0]).toMatchObject({
      available: true,
      dependencies: [{ id: "local-tool-binding-readiness", ready: true }],
    });
    expect(buildRuntimeCapabilityProjection(ready).actionClasses.passive_intelligence_osint)
      .toMatchObject({ enforcementReady: true, availableToolIds: ["kali:curl"] });

    now = new Date("2026-07-18T23:01:00.000Z");
    expect(readiness.projectManifests(runtime, now).tools[0])
      .toMatchObject({ available: false });
    const drifted: RuntimeSourceManifests = {
      ...runtime,
      tools: [{ ...runtime.tools[0]!, label: "Changed after review" }],
    };
    expect(readiness.projectManifests(drifted, new Date("2026-07-18T23:00:30.000Z")).tools[0])
      .toMatchObject({ available: false });
    await readiness.runner.stop();
  });

  test("does not promote a successful non-isolated version probe", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-tool-probe-"));
    roots.push(root);
    const executable = join(root, "version-fixture");
    writeFileSync(executable, "#!/bin/sh\nprintf 'fixture 1.0\\n'\n", { mode: 0o700 });
    const runtime = manifests(localTool());
    const readiness = createProductionToolBindingReadiness({
      manifests: runtime,
      registryPath: writeRegistry(registryDocument(executable)),
    });
    const snapshot = await readiness.runner.runAll();
    expect(snapshot.receipts[0]).toMatchObject({
      status: "unavailable",
      code: "startup_probe_isolation_unavailable",
      probeBoundary: {
        networkIsolationEnforced: false,
        filesystemWriteIsolationEnforced: false,
        immutableSnapshotExecutionEnforced: false,
        externalContact: "not_measured",
      },
    });
    expect(readiness.projectManifests(runtime).tools[0]).toMatchObject({ available: false });
  });
});

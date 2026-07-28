import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  truncateSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BubblewrapToolProbeEnvironment,
  LocalToolCapabilityManifest,
  parseBubblewrapProbeSandboxDescriptor,
} from "../index";
import {
  ToolBindingRegistry,
  ToolExecutionPreflightService,
} from "../../system-capabilities";

const TOOL_TEMPLATE = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const SANDBOX_TEMPLATE = new URL(
  "../../../deployment/runtime-config/bubblewrap-probe-sandbox.v1.json",
  import.meta.url,
);

function fixture() {
  const manifest = new LocalToolCapabilityManifest(
    JSON.parse(readFileSync(TOOL_TEMPLATE, "utf8")),
  );
  const registry = new ToolBindingRegistry(
    manifest.toToolBindingRegistryDocument(),
    manifest.toRuntimeSourceManifests(),
  );
  const descriptor = parseBubblewrapProbeSandboxDescriptor(
    JSON.parse(readFileSync(SANDBOX_TEMPLATE, "utf8")),
  );
  return { manifest, registry, descriptor };
}

describe("BubblewrapToolProbeEnvironment", () => {
  test("runs only the reviewed curl version probe from a sealed snapshot with no network namespace", async () => {
    const { registry, descriptor } = fixture();
    const environment = new BubblewrapToolProbeEnvironment(descriptor);
    try {
      const service = new ToolExecutionPreflightService({
        environment,
        clock: () => new Date("2026-07-19T12:00:00.000Z"),
      });
      const result = await service.check(registry.toPreflightSpec("kali:curl-http-metadata")!);
      expect(result).toMatchObject({
        toolId: "kali:curl-http-metadata",
        status: "ready",
        code: "ready",
        probeBoundary: {
          shell: false,
          targetArgumentsSupplied: false,
          providerArgumentsSupplied: false,
          mcpArgumentsSupplied: false,
          networkIsolationEnforced: true,
          filesystemWriteIsolationEnforced: true,
          immutableSnapshotExecutionEnforced: true,
        },
      });
      expect(result.executableIdentity?.sha256)
        .toBe("d31f01bb019e875d23a2978106f53c5f14b750a65a0669dca0d4367466625bfd");
      expect(result.execution.outputBytes).toBeGreaterThan(0);
      expect(result.execution.outputBytes).toBeLessThanOrEqual(16_384);
    } finally {
      environment.close();
    }
  });

  test("refuses a drifted bubblewrap helper hash", async () => {
    const { registry, descriptor } = fixture();
    const environment = new BubblewrapToolProbeEnvironment({
      ...descriptor,
      expectedSha256: "0".repeat(64),
    });
    try {
      const result = await new ToolExecutionPreflightService({ environment })
        .check(registry.toPreflightSpec("kali:curl-http-metadata")!);
      expect(result.status).toBe("unavailable");
      expect(result.code).toBe("executable_identity_changed");
      expect(result.execution.outputBytes).toBe(0);
    } finally {
      environment.close();
    }
  });

  test("runs the reviewed capability-free nmap version probe without target arguments", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-nmap-probe-"));
    try {
      const executablePath = join(root, "nmap-capability-free");
      copyFileSync("/usr/lib/nmap/nmap", executablePath);
      chmodSync(executablePath, 0o555);
      const document = JSON.parse(readFileSync(TOOL_TEMPLATE, "utf8")) as {
        tools: Array<Record<string, any>>;
      };
      const nmap = document.tools.find(({ toolId }) =>
        toolId === "kali:nmap-tcp-connect-service-scan")!;
      nmap.activation = "enabled";
      nmap.activationReason = null;
      nmap.executable.path = executablePath;
      const manifest = new LocalToolCapabilityManifest(document);
      const registry = new ToolBindingRegistry(
        manifest.toToolBindingRegistryDocument(),
        manifest.toRuntimeSourceManifests(),
      );
      const descriptor = parseBubblewrapProbeSandboxDescriptor(
        JSON.parse(readFileSync(SANDBOX_TEMPLATE, "utf8")),
      );
      const environment = new BubblewrapToolProbeEnvironment(descriptor);
      try {
        const probe = await new ToolExecutionPreflightService({ environment })
          .check(registry.toPreflightSpec("kali:nmap-tcp-connect-service-scan")!);
        expect(probe).toMatchObject({
          status: "ready",
          code: "ready",
          executableIdentity: {
            sha256: "5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f",
          },
          probeBoundary: {
            shell: false,
            targetArgumentsSupplied: false,
            networkIsolationEnforced: true,
            filesystemWriteIsolationEnforced: true,
            immutableSnapshotExecutionEnforced: true,
          },
        });
        expect(probe.execution.outputBytes).toBeGreaterThan(0);
      } finally {
        environment.close();
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("reuses one bounded immutable snapshot across repeated readiness waves and releases it", async () => {
    const { registry, descriptor } = fixture();
    const environment = new BubblewrapToolProbeEnvironment(descriptor);
    const service = new ToolExecutionPreflightService({ environment });
    const spec = registry.toPreflightSpec("kali:curl-http-metadata")!;

    for (let wave = 0; wave < 20; wave += 1) {
      expect((await service.check(spec)).status).toBe("ready");
    }

    const resources = environment.resourceSnapshot();
    expect(resources).toMatchObject({
      cachedExecutableSnapshots: 1,
      cachedExecutableBytes: statSync("/usr/bin/curl").size,
      immutableSnapshotBuilds: 1,
      closed: false,
    });
    expect(resources.immutableSnapshotCacheHits).toBeGreaterThanOrEqual(20);

    environment.close();
    expect(environment.resourceSnapshot()).toMatchObject({
      cachedExecutableSnapshots: 0,
      cachedExecutableBytes: 0,
      immutableSnapshotBuilds: 1,
      closed: true,
    });
    environment.close();
  });

  test("streams a large immutable snapshot without monopolizing the event loop", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-large-probe-"));
    const { descriptor } = fixture();
    const environment = new BubblewrapToolProbeEnvironment(descriptor);
    try {
      const executablePath = join(root, "large-nmap-snapshot");
      copyFileSync("/usr/lib/nmap/nmap", executablePath);
      truncateSync(executablePath, 32 * 1024 * 1024);
      chmodSync(executablePath, 0o555);
      let eventLoopTurns = 0;
      const timer = setInterval(() => { eventLoopTurns += 1; }, 1);
      try {
        const inspected = await environment.inspectExecutable(executablePath);
        expect(inspected.state).toBe("ready");
      } finally {
        clearInterval(timer);
      }
      expect(eventLoopTurns).toBeGreaterThan(0);
      expect(environment.resourceSnapshot()).toMatchObject({
        cachedExecutableSnapshots: 1,
        cachedExecutableBytes: 32 * 1024 * 1024,
        immutableSnapshotBuilds: 1,
      });
    } finally {
      environment.close();
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects descriptors that permit file capabilities or PATH lookup", () => {
    const { descriptor } = fixture();
    expect(() => parseBubblewrapProbeSandboxDescriptor({
      ...descriptor,
      fileCapabilities: "any",
    })).toThrow("must not carry Linux file capabilities");
    expect(() => parseBubblewrapProbeSandboxDescriptor({
      ...descriptor,
      executablePath: "bwrap",
    })).toThrow("absolute safe file path");
  });
});

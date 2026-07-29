import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase, type SqliteDatabase } from "../../db";
import { MissionIntakeService } from "../../intake";
import { MissionRepository } from "../../missions";
import {
  AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
  AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
  AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
  emptyRuntimeSourceManifests,
} from "../../domain";
import {
  LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
  LocalToolCapabilityManifest,
  parseBubblewrapProbeSandboxDescriptor,
  type LocalToolActivationReceipt,
} from "../../local-tools";
import { digestCanonicalJson } from "../../mcp";
import {
  CapabilitySelfTestService,
  EngagementWorkspaceResolver,
  ToolBindingReadinessRunner,
  ToolExecutionPreflightService,
  type ToolExecutableIdentity,
  type ToolExecutionPreflightEnvironment,
  type ToolExecutionPreflightResult,
} from "../../system-capabilities";
import type { TrustedLocalFileReceipt } from "../../trusted-runtime-config";
import {
  AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
  AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
  AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
  AUTONOMOUS_IP_LIVENESS_TOOL_ID,
  AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
  AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
  AUTONOMOUS_LOCAL_SAFE_RECON_ADAPTER_ID,
} from "../../autonomous-runtime";
import {
  AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
  DirectWindowsIdentityProcessAdapter,
  WindowsIdentityCapabilityRegistry,
} from "../../windows-identity-tools";
import {
  AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
  parseAutonomousDnsRuntimeConfiguration,
} from "../AutonomousDnsActivationCoordinator";
import { AutonomousDnsRuntimeLifecycle } from "../AutonomousDnsRuntimeLifecycle";
import {
  activateWindowsIdentityRuntime,
  applyWindowsIdentityRuntimeProjection,
  projectWindowsIdentityRuntime,
  type WindowsIdentityActivationSnapshot,
} from "../WindowsIdentityRuntimeComposition";
import type { LoadedLocalGuidedToolConfiguration } from "../LocalGuidedToolConfiguration";
import {
  applyLocalGuidedToolRuntimeProjection,
  projectLocalGuidedToolRuntime,
} from "../LocalGuidedToolRuntimeProjection";
import {
  RuntimeProjectionService,
  type RuntimeProjectionInput,
} from "../RuntimeProjectionService";

const TEMPLATE = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const NMAP_ENABLED_TEMPLATE = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json",
  import.meta.url,
);
const SANDBOX_TEMPLATE = new URL(
  "../../../deployment/runtime-config/bubblewrap-probe-sandbox.v1.json",
  import.meta.url,
);

function trustedFileReceipt(sourceSha256: string): TrustedLocalFileReceipt {
  return {
    schemaVersion: "ti-scale.trusted-local-file-receipt.v1",
    sourcePath: "/reviewed/config.json",
    trustRoot: "/reviewed",
    sourceSha256,
    canonicalSha256: sourceSha256,
    byteSize: 2,
    ownerUid: process.geteuid?.() ?? process.getuid?.() ?? 0,
    ownerGid: process.getegid?.() ?? process.getgid?.() ?? 0,
    mode: 0o600,
    device: "1",
    inode: "1",
  };
}

function emptyBaseline(): RuntimeProjectionInput {
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
    capabilityManifests: emptyRuntimeSourceManifests(),
  };
}

function activationReceipt(
  manifest: LocalToolCapabilityManifest,
  toolId: string,
  observedAt = "2026-07-20T03:00:00.000Z",
  expiresAt = "2026-07-20T03:01:00.000Z",
): LocalToolActivationReceipt {
  const tool = manifest.resolve(toolId)!;
  return {
    schemaVersion: LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
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
    observedAt,
    expiresAt,
  };
}

function readyPreflight(
  manifest: LocalToolCapabilityManifest,
  toolId: string,
  checkedAt: string,
  expiresAt: string,
): ToolExecutionPreflightResult {
  const tool = manifest.resolve(toolId)!;
  return {
    schemaVersion: "ti-scale.tool-execution-preflight.v2",
    toolId,
    status: "ready",
    code: "ready",
    checkedAt,
    expiresAt,
    bindingSha256: "b".repeat(64),
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
      inode: "2",
      sizeBytes: 1_024,
      mode: 0o755,
      uid: 0,
      gid: 0,
    },
    noNewPrivileges: true,
    explanation: "The exact target-free startup probe passed.",
    remediation: null,
    execution: {
      exitCode: 0,
      signal: null,
      spawnErrorCode: null,
      outputBytes: 10,
      outputSha256: "c".repeat(64),
    },
  };
}

function executableIdentity(path: string): ToolExecutableIdentity {
  const metadata = lstatSync(path, { bigint: true });
  return {
    sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
    device: metadata.dev.toString(),
    inode: metadata.ino.toString(),
    sizeBytes: Number(metadata.size),
    mode: Number(metadata.mode & 0o7777n),
    uid: Number(metadata.uid),
    gid: Number(metadata.gid),
  };
}

async function readyWindowsIdentityFixture(
  now: Date,
): Promise<Readonly<{
  registry: WindowsIdentityCapabilityRegistry;
  adapter: DirectWindowsIdentityProcessAdapter;
  activation: WindowsIdentityActivationSnapshot;
}>> {
  const registry = new WindowsIdentityCapabilityRegistry();
  const identities = new Map<string, ToolExecutableIdentity>();
  for (const definition of registry.pack.definitions) {
    identities.set(
      definition.executable.path,
      executableIdentity(definition.executable.path),
    );
  }
  const environment: ToolExecutionPreflightEnvironment = {
    isolation: {
      networkEnforced: true,
      filesystemWritesEnforced: true,
      immutableSnapshotEnforced: true,
    },
    async inspectExecutable(path) {
      const identity = identities.get(path);
      return identity ? { state: "ready", identity } : { state: "missing" };
    },
    async inspectWorkingDirectory() {
      return true;
    },
    async readNoNewPrivileges() {
      return true;
    },
    async execute(input) {
      return {
        exitCode: input.executablePath === "/usr/bin/nxc" ? 1 : 0,
        signal: null,
        stdout: "target-free readiness fixture\n",
        stderr: "",
        timedOut: false,
        outputLimitExceeded: false,
        executableIdentity: input.expectedExecutableIdentity,
      };
    },
  };
  const adapter = new DirectWindowsIdentityProcessAdapter({
    workspaceResolver: new EngagementWorkspaceResolver([{
      logicalRoot: "/engagements",
      runtimeRoot: "/tmp",
    }]),
    sandboxExecutable: {
      path: "/usr/bin/bwrap",
      expectedSha256: executableIdentity("/usr/bin/bwrap").sha256,
    },
    now: () => now,
  });
  const activation = await activateWindowsIdentityRuntime({
    registry,
    runner: new ToolBindingReadinessRunner(
      registry.createToolBindingRegistry(),
      new ToolExecutionPreflightService({
        environment,
        clock: () => now,
      }),
      () => now,
    ),
    adapter,
    now,
  });
  if (activation.status !== "ready") {
    throw new Error(
      `Windows identity fixture did not activate: ${activation.reason}`,
    );
  }
  return { registry, adapter, activation };
}

describe("AutonomousDnsRuntimeLifecycle projection freshness", () => {
  test("re-reads the Guided baseline and downgrades an activation receipt at its expiry", () => {
    const manifest = new LocalToolCapabilityManifest(
      JSON.parse(readFileSync(TEMPLATE, "utf8")),
    );
    const toolId = "kali:host-dns-query";
    const receipt = activationReceipt(manifest, toolId);
    let now = new Date("2026-07-20T03:00:30.000Z");
    let baselineReads = 0;
    const readBaselineProjection = (): RuntimeProjectionInput => {
      baselineReads += 1;
      return applyLocalGuidedToolRuntimeProjection(
        emptyBaseline(),
        projectLocalGuidedToolRuntime({
          baselineManifests: emptyRuntimeSourceManifests(),
          manifest,
          activationReceipts: [receipt],
          adapterId: "ti-scale:reviewed-local-process",
          now,
        }),
      );
    };
    const lifecycle = new AutonomousDnsRuntimeLifecycle({
      database: {} as SqliteDatabase,
      readBaselineProjection,
      productionConfiguration: {
        status: "unconfigured",
        reason: "Autonomous DNS is not configured in this fixture.",
      },
      localToolConfiguration: {
        status: "unconfigured",
        reason: "The lifecycle has no separate Autonomous local-tool configuration.",
      },
      now: () => now,
    });

    expect(lifecycle.projection().readiness.guidedLocalToolExecution).toMatchObject({
      status: "ready",
      readyToolIds: [toolId],
      expiresAt: "2026-07-20T03:01:00.000Z",
    });

    now = new Date("2026-07-20T03:01:00.000Z");
    const expired = lifecycle.projection();
    expect(expired.readiness.guidedLocalToolExecution).toMatchObject({
      status: "unavailable",
      readyToolIds: [],
    });
    expect(expired.agents.find(({ id }) => id === manifest.specialist.id)?.status).toBe("offline");
    expect(expired.capabilityManifests?.tools.find(({ id }) => id === toolId)?.available).toBeFalse();
    expect(baselineReads).toBe(3);
  });

  test("keeps an unrelated Guided Nmap self-test joined to its owning activation wave", () => {
    const manifest = new LocalToolCapabilityManifest(
      JSON.parse(readFileSync(NMAP_ENABLED_TEMPLATE, "utf8")),
    );
    const nmapToolId = "kali:nmap-tcp-connect-service-scan";
    const now = new Date("2026-07-20T03:00:00.000Z");
    const dnsReceipt = activationReceipt(
      manifest,
      AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
      "2026-07-20T02:59:55.000Z",
      "2026-07-20T03:00:30.000Z",
    );
    const guidedNmapReceipt = activationReceipt(
      manifest,
      nmapToolId,
      "2026-07-20T02:59:40.000Z",
      "2026-07-20T03:00:30.000Z",
    );
    const projected = applyLocalGuidedToolRuntimeProjection(
      emptyBaseline(),
      projectLocalGuidedToolRuntime({
        baselineManifests: emptyRuntimeSourceManifests(),
        manifest,
        activationReceipts: [dnsReceipt, guidedNmapReceipt],
        adapterId: "ti-scale:reviewed-local-process",
        now,
      }),
    );
    const lifecycle = new AutonomousDnsRuntimeLifecycle({
      database: {} as SqliteDatabase,
      readBaselineProjection: () => projected,
      productionConfiguration: {
        status: "unconfigured",
        reason: "The production-shaped fixture injects only a content-free activation reader.",
      },
      localToolConfiguration: {
        status: "unconfigured",
        reason: "No process is launched by this self-test fixture.",
      },
      now: () => now,
    });
    const autonomousWavePreflight = (toolId: string) => readyPreflight(
      manifest,
      toolId,
      "2026-07-20T02:59:50.000Z",
      "2026-07-20T03:00:40.000Z",
    );
    const guidedNmapPreflight = readyPreflight(
      manifest,
      nmapToolId,
      "2026-07-20T02:59:30.000Z",
      "2026-07-20T03:00:40.000Z",
    );
    Object.defineProperty(lifecycle, "snapshotValue", {
      configurable: true,
      writable: true,
      value: {
        ...lifecycle.snapshot(),
        status: "ready",
        projection: projected,
      },
    });
    Object.defineProperty(lifecycle, "projectedPreflights", {
      configurable: true,
      writable: true,
      value: new Map([
        [
          AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
          autonomousWavePreflight(AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID),
        ],
        [nmapToolId, guidedNmapPreflight],
      ]),
    });

    // The published lifecycle generation carries both its Autonomous DNS
    // preflight and the exact Guided baseline preflight used by the frozen
    // composite projection. Neither is read from a mutable runner.
    expect(lifecycle.readToolExecutionPreflight(nmapToolId))
      .toBe(guidedNmapPreflight);
    expect(lifecycle.readToolExecutionPreflight(AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID))
      .toMatchObject({ toolId: AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID });

    const selfTests = new CapabilitySelfTestService({
      repository: {
        read: () => ({
          checkedAt: now.toISOString(),
          database: {
            healthy: true,
            integrity: ["ok"],
            integrityStatus: "verified",
            integrityCheckedAt: now.toISOString(),
            integritySource: "startup",
            journalMode: "wal",
            foreignKeys: true,
            busyTimeoutMs: 5_000,
            currentMigration: 16,
            pendingOutbox: 0,
            checkedAt: now.toISOString(),
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
              reason: "A persisted round-trip receipt is present.",
            },
            reason: "Canonical memory is available.",
          },
        }),
      },
      readRuntimeProjection: () => projected,
      readToolExecutionPreflight: (toolId) =>
        lifecycle.readToolExecutionPreflight(toolId)
        ?? (toolId === nmapToolId ? guidedNmapPreflight : undefined),
      clock: () => now,
    }).snapshot();
    expect(selfTests.results.find(({ component }) => component.id === nmapToolId))
      .toMatchObject({ status: "pass", availability: "available", freshness: { state: "fresh" } });
    const dependencies = selfTests.results.filter(({ component }) =>
      component.kind === "tool_dependency"
      && component.id.startsWith(`${nmapToolId}/`));
    expect(dependencies).toHaveLength(7);
    expect(dependencies.every(({ status, availability, freshness }) =>
      status === "pass"
      && availability === "available"
      && freshness.state === "fresh")).toBeTrue();
  });

  test("mounts the production lifecycle only after one current DNS, ping, and bounded Nmap activation wave", async () => {
    const runtimeRoot = mkdtempSync(join(tmpdir(), "ti-scale-autonomous-safe-recon-lifecycle-"));
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    const manifest = new LocalToolCapabilityManifest(
      JSON.parse(readFileSync(NMAP_ENABLED_TEMPLATE, "utf8")),
    );
    const probeSandbox = parseBubblewrapProbeSandboxDescriptor(
      JSON.parse(readFileSync(SANDBOX_TEMPLATE, "utf8")),
    );
    const now = new Date("2026-07-20T06:30:00.000Z");
    const modelConfigurationHash = "a".repeat(64);
    const runtimeConfiguration = parseAutonomousDnsRuntimeConfiguration({
      schemaVersion: AUTONOMOUS_DNS_RUNTIME_CONFIGURATION_SCHEMA_VERSION,
      configurationVersion: "safe-recon-lifecycle-test-v1",
      dns: {
        policyId: "reviewed-autonomous-local-safe-recon-v2",
        bindingId: "binding-autonomous-dns-a-v2",
        agentId: "specialist:autonomous-safe-recon",
        providerId: "provider:local-deterministic-safe-recon",
        modelId: "policy:local-safe-recon-v2",
        modelConfigurationHash,
        logicalWorkspace: "/engagements/safe-recon",
        recordType: "A",
        successCriterion: AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
      },
      ipRecon: {
        policyId: "reviewed-autonomous-local-safe-recon-v2",
        livenessBindingId: "binding-autonomous-ip-liveness-v1",
        serviceScanBindingId: "binding-autonomous-ip-services-v1",
        agentId: "specialist:autonomous-safe-recon",
        providerId: "provider:local-deterministic-safe-recon",
        modelId: "policy:local-safe-recon-v2",
        modelConfigurationHash,
        logicalWorkspace: "/engagements/safe-recon",
        ports: [22, 80, 443],
        livenessSuccessCriterion: AUTONOMOUS_HOST_LIVENESS_SUCCESS_CRITERION,
        serviceScanSuccessCriterion: AUTONOMOUS_PORT_SERVICE_SCAN_SUCCESS_CRITERION,
      },
      localProcess: { adapterId: AUTONOMOUS_LOCAL_SAFE_RECON_ADAPTER_ID },
      specialist: {
        id: "specialist:autonomous-safe-recon",
        label: "Autonomous Safe Recon specialist",
        workerId: "worker:autonomous-safe-recon-test",
        version: "test-v1",
        heartbeatTtlMs: 60_000,
      },
      provider: {
        id: "provider:local-deterministic-safe-recon",
        label: "Local deterministic Safe Recon policy",
        modelId: "policy:local-safe-recon-v2",
        modelConfigurationHash,
        policyVersion: "test-v1",
        attestationTtlMs: 60_000,
      },
    });
    const canonicalSha256 = digestCanonicalJson(runtimeConfiguration, {
      maxBytes: 256 * 1_024,
      maxDepth: 24,
    }).sha256;
    const localToolConfiguration: LoadedLocalGuidedToolConfiguration = {
      status: "loaded",
      manifest,
      probeSandbox,
      workspaceMappings: {
        schemaVersion: "ti-scale.engagement-workspace-mappings.v1",
        mappingVersion: "safe-recon-lifecycle-test-v1",
        mappings: [{ logicalRoot: "/engagements", runtimeRoot }],
      },
      receipts: {
        capabilityManifest: trustedFileReceipt(manifest.descriptor.manifestSha256),
        probeSandbox: trustedFileReceipt(probeSandbox.expectedSha256),
        workspaceMappings: trustedFileReceipt("c".repeat(64)),
      },
    };
    const timers = {
      set: () => Symbol("suppressed-lifecycle-timer"),
      clear: () => undefined,
    };
    const windowsIdentity = await readyWindowsIdentityFixture(now);
    let windowsIdentityActivation:
      WindowsIdentityActivationSnapshot | undefined;
    const readBaselineProjection = (): RuntimeProjectionInput => {
      const baseline = emptyBaseline();
      return windowsIdentityActivation
        ? applyWindowsIdentityRuntimeProjection(
            baseline,
            projectWindowsIdentityRuntime({
              baselineManifests:
                baseline.capabilityManifests
                ?? emptyRuntimeSourceManifests(),
              registry: windowsIdentity.registry,
              activation: windowsIdentityActivation,
              now,
            }),
          )
        : baseline;
    };
    const materializedProjection = new RuntimeProjectionService({
      database,
      read: readBaselineProjection,
      clock: () => now,
    });
    materializedProjection.projectNow();
    let publicationCount = 0;
    let rejectCapabilityMemoryProjection = false;
    let lifecycle!: AutonomousDnsRuntimeLifecycle;
    lifecycle = new AutonomousDnsRuntimeLifecycle({
      database,
      readBaselineProjection,
      publishProjection: (projection) => {
        // The newly ready generation must reach the canonical specialist read
        // model while public lifecycle/runtime access is still fail-closed.
        if (publicationCount === 0) {
          expect(lifecycle.snapshot().status).not.toBe("ready");
          expect(lifecycle.runtime()).toBeUndefined();
        }
        materializedProjection.projectNow(projection);
        if (rejectCapabilityMemoryProjection) {
          throw new Error("Current capability memory did not reach the connected Vault");
        }
        publicationCount += 1;
      },
      productionConfiguration: {
        status: "loaded",
        runtime: {
          value: runtimeConfiguration,
          receipt: {
            ...trustedFileReceipt("d".repeat(64)),
            sourcePath: "/reviewed/autonomous-safe-recon.json",
            canonicalSha256,
            byteSize: Buffer.byteLength(JSON.stringify(runtimeConfiguration), "utf8"),
          },
        },
      },
      localToolConfiguration,
      // An optional Windows/identity route without a current activation wave
      // must not withdraw unrelated Safe Recon. Contracts that request its
      // action class still fail readiness because no live binding is
      // projected into this generation.
      windowsIdentityAutonomous: {
        registry: windowsIdentity.registry,
        adapter: windowsIdentity.adapter,
        logicalWorkspace: "/engagements",
        readActivation: () => windowsIdentityActivation,
      },
      now: () => now,
      timers,
    });

    const fencedDuringProvisioning = new AutonomousDnsRuntimeLifecycle({
      database,
      readBaselineProjection: emptyBaseline,
      productionConfiguration: {
        status: "loaded",
        runtime: {
          value: runtimeConfiguration,
          receipt: {
            ...trustedFileReceipt("e".repeat(64)),
            sourcePath: "/reviewed/autonomous-safe-recon-fenced.json",
            canonicalSha256,
            byteSize: Buffer.byteLength(JSON.stringify(runtimeConfiguration), "utf8"),
          },
        },
      },
      localToolConfiguration,
      now: () => now,
      timers,
    });
    const fencedStart = fencedDuringProvisioning.start();
    fencedDuringProvisioning.beginStop();
    const fencedSnapshot = await fencedStart;
    expect(fencedSnapshot.status).not.toBe("ready");
    expect(fencedDuringProvisioning.runtime()).toBeUndefined();
    await fencedDuringProvisioning.stop();

    try {
      const mounted = await lifecycle.start();
      expect(mounted).toMatchObject({
        status: "ready",
        runtimeMounted: true,
        runtimeStarted: true,
        localActivationStatus: "ready",
        composition: { status: "ready" },
      });
      expect(lifecycle.runtime()).toBeDefined();
      expect(publicationCount).toBe(1);
      const provisionedWorkspace = statSync(join(runtimeRoot, "safe-recon"));
      expect(provisionedWorkspace.isDirectory()).toBeTrue();
      expect(provisionedWorkspace.mode & 0o777).toBe(0o700);
      for (const actionClassId of [
        AUTONOMOUS_DNS_SAFE_RECON_ACTION_CLASS,
        AUTONOMOUS_IP_LIVENESS_ACTION_CLASS,
        AUTONOMOUS_IP_SERVICE_SCAN_ACTION_CLASS,
      ]) {
        expect(mounted.composition.readyActionClassIds).toContain(actionClassId);
      }
      expect(mounted.composition.readyActionClassIds).not.toContain(
        AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
      );
      const initiallyMountedRuntime = lifecycle.runtime();
      windowsIdentityActivation = windowsIdentity.activation;
      const afterIdentityBecameReady = await lifecycle.refresh();
      expect(afterIdentityBecameReady.status).toBe("ready");
      expect(lifecycle.runtime()).toBe(initiallyMountedRuntime);
      expect(afterIdentityBecameReady.composition.readyActionClassIds)
        .not.toContain(AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS);
      expect(afterIdentityBecameReady.projection.capabilityManifests?.tools.find(
        ({ id }) => id === "kali:nxc-smb-summary",
      )).toMatchObject({
        available: true,
        executionJourneys: ["guided"],
      });
      for (const toolId of [
        AUTONOMOUS_DNS_SAFE_RECON_TOOL_ID,
        AUTONOMOUS_IP_LIVENESS_TOOL_ID,
        AUTONOMOUS_IP_SERVICE_SCAN_TOOL_ID,
      ]) {
        expect(lifecycle.readToolExecutionPreflight(toolId)).toMatchObject({
          toolId,
          status: "ready",
          code: "ready",
        });
      }

      // Regression: immediately after lifecycle.start() returns (before any
      // periodic projection timer), intake resolution and the DB-backed team
      // preview must name the same exact current specialist generation.
      const intake = new MissionIntakeService({
        readRuntimeManifests: () => lifecycle.projection().capabilityManifests!,
        clock: () => now,
      });
      const resolved = intake.resolve({
        journey: "autonomous",
        authorizationAcknowledged: true,
        targets: [{ value: "127.0.0.1" }],
      });
      if (resolved.request.journey !== "autonomous") {
        throw new Error("Autonomous lifecycle fixture resolved a Guided request");
      }
      expect(resolved.request.contract.specialistAgentIds).toEqual([
        "ReconScout",
      ]);
      const execution = new MissionRepository(database, () => now)
        .autonomousExecutionPreview(resolved.request);
      expect(execution.team.invalidSelectedAgentIds).toEqual([]);
      expect(execution.team.effectiveAgentIds).toEqual([
        "ReconScout",
      ]);
      expect(execution.providers.filter(({ compatible }) => compatible).map(({ id }) => id))
        .toEqual([runtimeConfiguration.provider.id]);

      // Any synchronous post-projection failure (including the required
      // capability-memory/Vault bridge) rejects the new generation and
      // withdraws executable Autonomous readiness instead of admitting a
      // runtime with a stale or missing decision-memory boundary.
      rejectCapabilityMemoryProjection = true;
      const rejected = await lifecycle.refresh();
      expect(rejected).toMatchObject({
        status: "blocked",
        runtimeMounted: false,
        runtimeStarted: false,
        reason: "Current capability memory did not reach the connected Vault",
      });
      expect(lifecycle.runtime()).toBeUndefined();
      expect(publicationCount).toBe(2);
    } finally {
      await lifecycle.stop();
      database.close();
      rmSync(runtimeRoot, { recursive: true, force: true });
    }
  }, 30_000);
});

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { describe, expect, test } from "bun:test";
import {
  buildRuntimeCapabilityProjection,
  emptyRuntimeSourceManifests,
  type RuntimeSourceManifests,
} from "../../domain";
import {
  EngagementWorkspaceResolver,
  ToolBindingReadinessRunner,
  ToolExecutionPreflightService,
  type ToolExecutableIdentity,
  type ToolExecutionPreflightEnvironment,
} from "../../system-capabilities";
import {
  AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
  AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
  AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID,
  DirectWindowsIdentityProcessAdapter,
  WindowsIdentityCapabilityRegistry,
} from "../../windows-identity-tools";
import {
  composeAutonomousWindowsIdentityProjection,
  inspectAutonomousWindowsIdentityComposition,
} from "../AutonomousWindowsIdentityRuntimeComposition";
import type { RuntimeProjectionInput } from "../RuntimeProjectionService";
import {
  activateWindowsIdentityRuntime,
  applyWindowsIdentityRuntimeProjection,
  projectWindowsIdentityRuntime,
} from "../WindowsIdentityRuntimeComposition";

const NOW = new Date("2026-07-25T10:00:00.000Z");
const PROVIDER_ID = "provider:local-deterministic-dns";
const MODEL_ID = "policy:dns-safe-recon-v1";
const MODEL_CONFIGURATION_HASH = "a".repeat(64);

async function executableIdentity(path: string): Promise<ToolExecutableIdentity> {
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

async function readyRunner(
  registry: WindowsIdentityCapabilityRegistry,
): Promise<ToolBindingReadinessRunner> {
  const identities = new Map<string, ToolExecutableIdentity>();
  for (const definition of registry.pack.definitions) {
    identities.set(
      definition.executable.path,
      await executableIdentity(definition.executable.path),
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
      return identity
        ? { state: "ready", identity }
        : { state: "missing" };
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
  return new ToolBindingReadinessRunner(
    registry.createToolBindingRegistry(),
    new ToolExecutionPreflightService({
      environment,
      clock: () => NOW,
    }),
    () => NOW,
  );
}

async function processAdapter(): Promise<DirectWindowsIdentityProcessAdapter> {
  return new DirectWindowsIdentityProcessAdapter({
    workspaceResolver: new EngagementWorkspaceResolver([{
      logicalRoot: "/engagements",
      runtimeRoot: "/tmp",
    }]),
    sandboxExecutable: {
      path: "/usr/bin/bwrap",
      expectedSha256: createHash("sha256")
        .update(await readFile("/usr/bin/bwrap"))
        .digest("hex"),
    },
    now: () => NOW,
  });
}

function baseline(manifests: RuntimeSourceManifests): RuntimeProjectionInput {
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
    capabilityManifests: manifests,
  };
}

function withLocalProvider(
  manifests: RuntimeSourceManifests,
): RuntimeSourceManifests {
  return Object.freeze({
    ...manifests,
    providers: Object.freeze([
      ...manifests.providers,
      Object.freeze({
        id: PROVIDER_ID,
        authenticated: true,
        healthy: true,
        catalogObservedAt: NOW.toISOString(),
        models: Object.freeze([Object.freeze({
          id: MODEL_ID,
          displayName: "Local deterministic planning policy",
          executionBoundary: "local_deterministic_policy" as const,
          toolCalling: false,
          structuredOutput: true,
          enforcement: "enforced_executor" as const,
          compatibleActionClassIds: Object.freeze([]),
          disclosureClasses: Object.freeze(["local_only"]),
        })]),
      }),
    ]),
  });
}

describe("Autonomous Windows identity runtime composition", () => {
  test("advertises only the exact anonymous NXC route after the receipt, adapter, planner, and local provider join is current", async () => {
    const registry = new WindowsIdentityCapabilityRegistry();
    const adapter = await processAdapter();
    const activation = await activateWindowsIdentityRuntime({
      registry,
      runner: await readyRunner(registry),
      adapter,
      now: NOW,
    });
    expect(activation.status).toBe("ready");
    const binding = {
      registry,
      adapter,
      activation,
      logicalWorkspace: "/engagements",
    };
    expect(inspectAutonomousWindowsIdentityComposition(binding, NOW))
      .toMatchObject({
        status: "ready",
        receipt: {
          toolId: AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
          status: "ready",
          targetContact: false,
          grantsMissionExecution: false,
        },
      });

    const guided = projectWindowsIdentityRuntime({
      baselineManifests: emptyRuntimeSourceManifests(),
      registry,
      activation,
      now: NOW,
    });
    const manifests = withLocalProvider(guided.capabilityManifests);
    const guidedBaseline = applyWindowsIdentityRuntimeProjection(
      baseline(manifests),
      { ...guided, capabilityManifests: manifests },
    );
    const autonomous = composeAutonomousWindowsIdentityProjection(
      guidedBaseline,
      {
        binding,
        providerId: PROVIDER_ID,
        modelId: MODEL_ID,
        modelConfigurationHash: MODEL_CONFIGURATION_HASH,
        executionAdapterId:
          "ti-scale:autonomous-windows-identity-composite",
        now: NOW,
      },
    );
    const nxc = autonomous.capabilityManifests?.tools.find(
      ({ id }) => id === AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    );
    expect(nxc).toMatchObject({
      available: true,
      missionSelectable: true,
      locallyPolicyEnforced: true,
      executionJourneys: ["autonomous", "guided"],
    });
    const otherIdentityTools = autonomous.capabilityManifests?.tools.filter(
      ({ id }) =>
        id.startsWith("kali:")
        && id !== AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    ) ?? [];
    expect(otherIdentityTools).toHaveLength(3);
    expect(otherIdentityTools.every(({ executionJourneys }) =>
      executionJourneys?.length === 1
      && executionJourneys[0] === "guided")).toBeTrue();
    expect(autonomous.agents.find(
      ({ id }) => id === AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID,
    )).toMatchObject({
      status: "available",
      lastHeartbeatAt: activation.receipts.find(
        ({ toolId }) => toolId === AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
      )?.observedAt,
      toolPolicy: {
        exactGuidedDecisionRequired: true,
        exactAutonomousContractRequired: true,
      },
      configuration: {
        schemaVersion: "ti-scale.autonomous-specialist-runtime.v1",
        executionMode: "reviewed_local_process",
        adapterId:
          "ti-scale:autonomous-windows-identity-composite",
        toolSelection: "exact_persisted_binding_only",
        resultDelivery: "bound_execution_result_sink",
        shellInterpolation: false,
        publicProviderToolExecution: false,
      },
    });
    const provider = autonomous.capabilityManifests?.providers.find(
      ({ id }) => id === PROVIDER_ID,
    );
    expect(provider?.models.find(({ id }) => id === MODEL_ID)
      ?.compatibleActionClassIds).toContain(
        AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS,
      );
    const capability = buildRuntimeCapabilityProjection(
      autonomous.capabilityManifests!,
      NOW,
    );
    const identityAction = capability.actionClasses[
      AUTONOMOUS_NXC_SMB_SUMMARY_ACTION_CLASS
    ];
    expect(identityAction).toMatchObject({
      availability: "supported",
      availableAgentIds: [AUTONOMOUS_WINDOWS_IDENTITY_RUNTIME_AGENT_ID],
      locallyEnforcedToolIds: [AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID],
      enforcementReady: true,
    });
    expect(identityAction.availableToolIds).toContain(
      AUTONOMOUS_NXC_SMB_SUMMARY_TOOL_ID,
    );
  });

  test("blocks stale receipts and rejects an adapter that did not produce the activation wave", async () => {
    const registry = new WindowsIdentityCapabilityRegistry();
    const adapter = await processAdapter();
    const activation = await activateWindowsIdentityRuntime({
      registry,
      runner: await readyRunner(registry),
      adapter,
      now: NOW,
    });
    const binding = {
      registry,
      adapter,
      activation,
      logicalWorkspace: "/engagements",
    };
    expect(inspectAutonomousWindowsIdentityComposition(
      binding,
      new Date(NOW.getTime() + 61_000),
    )).toMatchObject({
      status: "blocked",
      code: "autonomous_windows_identity_receipt_stale",
    });
    expect(inspectAutonomousWindowsIdentityComposition({
      ...binding,
      adapter: await processAdapter(),
    }, NOW)).toMatchObject({
      status: "blocked",
      code: "autonomous_windows_identity_adapter_mismatch",
    });
  });
});

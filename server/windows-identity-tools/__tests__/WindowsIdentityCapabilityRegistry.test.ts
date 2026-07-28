import { describe, expect, test } from "bun:test";
import type { RuntimeSourceManifests } from "../../domain";
import type { ToolBindingReadinessReceipt } from "../../system-capabilities";
import {
  WindowsIdentityCapabilityRegistry,
  windowsIdentityReadinessReceipt,
} from "../WindowsIdentityCapabilityRegistry";

const CHECKED = "2026-07-20T09:00:00.000Z";
const EXPIRES = "2026-07-20T09:01:00.000Z";

function genericReceipt(
  registry: WindowsIdentityCapabilityRegistry,
  toolId: string,
  observedSha256: string,
): ToolBindingReadinessReceipt {
  const binding = registry.createToolBindingRegistry().resolve(toolId)!;
  return {
    schemaVersion: "ti-scale.tool-binding-readiness-receipt.v2",
    registryVersion: registry.descriptor.registryVersion,
    registrySha256: registry.createToolBindingRegistry().descriptor.registrySha256,
    runtimeManifestSha256:
      registry.createToolBindingRegistry().descriptor.runtimeManifestSha256,
    toolId,
    registryBindingSha256: binding.bindingSha256,
    preflightBindingSha256: "a".repeat(64),
    status: "ready",
    code: "ready",
    checkedAt: CHECKED,
    expiresAt: EXPIRES,
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
      sha256: observedSha256,
      device: "1",
      inode: "2",
      sizeBytes: 1_024,
      mode: 0o755,
      uid: 0,
      gid: 0,
    },
    grantsMissionExecution: false,
    privilegeBoundary: {
      noNewPrivileges: true,
      capabilityTransitionConflictObserved: false,
    },
    explanation: "Target-free isolated version probe passed.",
    remediation: null,
    execution: {
      exitCode: 0,
      signal: null,
      spawnErrorCode: null,
      outputBytes: 10,
      outputSha256: "b".repeat(64),
    },
  };
}

const adapter = Object.freeze({
  workspaceConfinementReady: true,
  credentialIsolationReady: true,
  outputBoundReady: true,
  cancellationReady: true,
});

describe("Windows identity capability registry", () => {
  test("registers all exact target-free probes including LDAP -VV and NetExec exit 1", () => {
    const registry = new WindowsIdentityCapabilityRegistry();
    const bindings = registry.createToolBindingRegistry().list();
    expect(bindings).toHaveLength(4);
    expect(bindings.find(({ toolId }) => toolId === "kali:ldapsearch-root-dse")
      ?.probeArguments).toEqual(["-VV"]);
    expect(bindings.find(({ toolId }) => toolId === "kali:nxc-smb-summary")
      ?.expectedExitCodes).toEqual([0, 1]);
  });

  test("projects tools available only from fresh exact-hash and complete adapter receipts", () => {
    const registry = new WindowsIdentityCapabilityRegistry();
    const receipts = registry.pack.definitions.map((definition) =>
      windowsIdentityReadinessReceipt({
        definition,
        binding: genericReceipt(registry, definition.toolId, definition.executable.sha256),
        adapter,
      }));
    expect(receipts.every(({ status, grantsMissionExecution }) =>
      status === "ready" && grantsMissionExecution === false)).toBeTrue();
    const manifests = registry.toRuntimeSourceManifests(
      receipts,
      new Date("2026-07-20T09:00:30.000Z"),
    );
    expect(manifests.tools.every(({ available }) => available)).toBeTrue();
    expect(manifests.tools.every(({ executionJourneys }) =>
      JSON.stringify(executionJourneys) === JSON.stringify(["guided"]))).toBeTrue();
    expect(manifests.tools.every(({ dependencies }) =>
      dependencies?.every(({ attestation }) =>
        attestation?.schemaVersion === "ti-scale.local-tool-activation-receipt.v1"
        && attestation.source === "local_guided_tool_activation"
        && attestation.manifestSha256 === registry.descriptor.manifestSha256
        && attestation.preflightBindingSha256 === "a".repeat(64)
        && attestation.executableSha256.length === 64
        && attestation.observedAt === CHECKED
        && attestation.expiresAt === EXPIRES) === true)).toBeTrue();
    expect(manifests.agents[0]).toMatchObject({
      id: "specialist:windows-identity",
      available: true,
    });
    expect(registry.toRuntimeSourceManifests(
      receipts,
      new Date("2026-07-20T09:01:00.000Z"),
    ).tools.every(({ available }) => available === false)).toBeTrue();
  });

  test("reports executable drift and incomplete adapter proof as precise blockers", () => {
    const registry = new WindowsIdentityCapabilityRegistry();
    const definition = registry.pack.definitions[0]!;
    const drift = windowsIdentityReadinessReceipt({
      definition,
      binding: genericReceipt(registry, definition.toolId, "f".repeat(64)),
      adapter,
    });
    expect(drift).toMatchObject({
      status: "unavailable",
      code: "windows_identity_tool_identity_changed",
      remediation: "Review the installed package version and pin its new executable SHA-256 before activation.",
    });
    const unbounded = windowsIdentityReadinessReceipt({
      definition,
      binding: genericReceipt(registry, definition.toolId, definition.executable.sha256),
      adapter: { ...adapter, cancellationReady: false },
    });
    expect(unbounded).toMatchObject({
      status: "unavailable",
      code: "windows_identity_adapter_not_bounded",
      cancellationReady: false,
    });
  });

  test("composes with the existing network risk class without duplicating it", () => {
    const registry = new WindowsIdentityCapabilityRegistry();
    const base: RuntimeSourceManifests = {
      riskClasses: [{
        id: "ti-scale:network",
        label: "Authorized network interaction",
        actionClassIds: ["active_host_discovery"],
      }],
      evidenceKinds: [],
      capabilities: [],
      tools: [],
      mcpServers: [],
      agents: [],
      providers: [],
    };
    const composed = registry.composeRuntimeSourceManifests(base);
    expect(composed.riskClasses).toEqual([{
      id: "ti-scale:network",
      label: "Authorized network interaction",
      actionClassIds: [
        "active_directory_identity_operations",
        "active_host_discovery",
      ],
    }]);
    expect(composed.tools).toHaveLength(4);
    expect(composed.tools.every(({ available }) => available === false)).toBeTrue();
  });
});

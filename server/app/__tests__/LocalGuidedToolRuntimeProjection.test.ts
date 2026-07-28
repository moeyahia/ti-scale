import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { buildRuntimeCapabilityProjection, emptyRuntimeSourceManifests } from "../../domain";
import {
  LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
  LocalToolCapabilityManifest,
  type LocalToolActivationReceipt,
} from "../../local-tools";
import {
  applyLocalGuidedToolRuntimeProjection,
  projectLocalGuidedToolRuntime,
} from "../LocalGuidedToolRuntimeProjection";
import type { RuntimeProjectionInput } from "../RuntimeProjectionService";

const TEMPLATE = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const NMAP_ENABLED_TEMPLATE = new URL(
  "../../../deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json",
  import.meta.url,
);
const NOW = new Date("2026-07-19T12:00:00.000Z");

function manifest(): LocalToolCapabilityManifest {
  return new LocalToolCapabilityManifest(JSON.parse(readFileSync(TEMPLATE, "utf8")));
}

function fullyEnabledManifest(): LocalToolCapabilityManifest {
  return new LocalToolCapabilityManifest(
    JSON.parse(readFileSync(NMAP_ENABLED_TEMPLATE, "utf8")),
  );
}

function receipt(
  source: LocalToolCapabilityManifest,
  toolId: string,
  overrides: Partial<LocalToolActivationReceipt> = {},
): LocalToolActivationReceipt {
  const tool = source.resolve(toolId)!;
  return {
    schemaVersion: LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
    manifestSha256: source.descriptor.manifestSha256,
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
    observedAt: "2026-07-19T11:59:00.000Z",
    expiresAt: "2026-07-19T12:05:00.000Z",
    ...overrides,
  };
}

function baseline(): RuntimeProjectionInput {
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

describe("local Guided tool runtime projection", () => {
  test("stays offline and keeps MCP accounting empty without activation receipts", () => {
    const source = manifest();
    const projection = projectLocalGuidedToolRuntime({
      baselineManifests: emptyRuntimeSourceManifests(),
      manifest: source,
      activationReceipts: [],
      adapterId: null,
      now: NOW,
    });
    expect(projection.readiness).toMatchObject({
      status: "unavailable",
      readyToolIds: [],
      mcpTransport: false,
    });
    expect(projection.agent).toMatchObject({ status: "offline" });
    expect(projection.capabilityManifests.mcpServers).toEqual([]);
    expect(projection.capabilityManifests.tools.every(({ available }) => !available)).toBeTrue();
  });

  test("projects only tools with current six-gate activation receipts", () => {
    const source = manifest();
    const receipts = source.list().map(({ toolId }, index) => receipt(
      source,
      toolId,
      index === 1 ? { expiresAt: "2026-07-19T11:59:59.000Z" } : {},
    ));
    const projection = projectLocalGuidedToolRuntime({
      baselineManifests: emptyRuntimeSourceManifests(),
      manifest: source,
      activationReceipts: receipts,
      adapterId: "ti-scale:reviewed-local-process",
      now: NOW,
    });
    expect(projection.readiness).toMatchObject({
      status: "ready",
      exactDecisionRequired: true,
      mcpTransport: false,
      readyToolIds: [
        "kali:curl-http-metadata",
        "kali:ncat-tcp-connect",
        "kali:ping-host-liveness",
      ],
      checkedAt: "2026-07-19T11:59:00.000Z",
      expiresAt: "2026-07-19T12:05:00.000Z",
    });
    expect(projection.agent.toolPolicy).toMatchObject({
      allowedTools: projection.readiness.readyToolIds,
      deniedTools: [
        "kali:host-dns-query",
        "kali:nmap-tcp-connect-service-scan",
      ],
      exactGuidedDecisionRequired: true,
    });
    expect(projection.agent.capabilities.map(({ name }) => name).sort()).toEqual(
      source.list().map(({ toolId }) => toolId).sort(),
    );
    expect(projection.agent.lastHeartbeatAt).toBeNull();
    expect(projection.capabilityManifests.mcpServers).toEqual([]);
    expect(projection.capabilityManifests.tools
      .filter(({ available }) => available)
      .every((tool) => tool.dependencies?.every((dependency) =>
        dependency.attestation?.schemaVersion === LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION
        && dependency.attestation.source === "local_guided_tool_activation"
        && dependency.attestation.preflightBindingSha256 === "b".repeat(64)
        && dependency.attestation.observedAt === "2026-07-19T11:59:00.000Z"
        && dependency.attestation.expiresAt === "2026-07-19T12:05:00.000Z")))
      .toBeTrue();

    const applied = applyLocalGuidedToolRuntimeProjection(baseline(), projection);
    expect(applied.readiness).toMatchObject({
      specialistsConfigured: 1,
      guidedLocalToolExecution: { status: "ready" },
      mcp: { configuredServers: 0, runnableServers: 0 },
    });
  });

  test("projects every receipt-ready reviewed binding while preserving its exact journey authority", () => {
    const source = fullyEnabledManifest();
    const projection = projectLocalGuidedToolRuntime({
      baselineManifests: emptyRuntimeSourceManifests(),
      manifest: source,
      activationReceipts: source.list().map(({ toolId }) => receipt(source, toolId)),
      adapterId: "ti-scale:reviewed-local-process",
      now: NOW,
    });
    const capabilities = buildRuntimeCapabilityProjection(projection.capabilityManifests);

    expect(source.descriptor).toMatchObject({ toolCount: 5, enabledToolCount: 5 });
    expect(projection.readiness.readyToolIds).toEqual([
      "kali:curl-http-metadata",
      "kali:host-dns-query",
      "kali:ncat-tcp-connect",
      "kali:nmap-tcp-connect-service-scan",
      "kali:ping-host-liveness",
    ]);
    expect(capabilities.actionClasses.web_crawling_page_capture).toMatchObject({
      availability: "supported",
      availableToolIds: ["kali:curl-http-metadata"],
      enforcementReady: false,
    });
    expect(capabilities.actionClasses.dns_domain_certificate_discovery).toMatchObject({
      availability: "supported",
      availableToolIds: ["kali:host-dns-query"],
      enforcementReady: false,
    });
    expect(capabilities.actionClasses.active_host_discovery).toMatchObject({
      availability: "supported",
      availableToolIds: ["kali:ncat-tcp-connect", "kali:ping-host-liveness"],
      enforcementReady: false,
    });
    expect(capabilities.actionClasses.port_service_enumeration).toMatchObject({
      availability: "supported",
      availableToolIds: [
        "kali:ncat-tcp-connect",
        "kali:nmap-tcp-connect-service-scan",
      ],
      enforcementReady: false,
    });
    expect(Object.values(capabilities.actionClasses)
      .filter(({ availableToolIds }) => availableToolIds.length > 0)
      .every(({ readinessReasons }) => readinessReasons.some((reason) =>
        reason.includes("not Autonomous execution")))).toBeTrue();
  });

  test("rejects duplicate receipts and fleet ID collisions", () => {
    const source = manifest();
    const duplicate = receipt(source, source.list()[0]!.toolId);
    expect(() => projectLocalGuidedToolRuntime({
      baselineManifests: emptyRuntimeSourceManifests(),
      manifest: source,
      activationReceipts: [duplicate, duplicate],
      adapterId: "ti-scale:reviewed-local-process",
      now: NOW,
    })).toThrow("duplicate tool IDs");

    const projection = projectLocalGuidedToolRuntime({
      baselineManifests: emptyRuntimeSourceManifests(),
      manifest: source,
      activationReceipts: [],
      adapterId: null,
      now: NOW,
    });
    expect(() => applyLocalGuidedToolRuntimeProjection({
      ...baseline(),
      agents: [projection.agent],
    }, projection)).toThrow("stable ID collision");
  });
});

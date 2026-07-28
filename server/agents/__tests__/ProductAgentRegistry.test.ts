import { describe, expect, test } from "bun:test";
import type { RuntimeSourceManifests } from "../../domain";
import type { FleetAgentProjection } from "../../app/RuntimeProjectionService";
import {
  PRODUCT_AGENT_REGISTRY,
  PRODUCT_AGENT_ROSTER_VERSION,
  productAgentIdsForRuntimeManifestAgent,
  projectProductAgentRoster,
} from "../ProductAgentRegistry";

const EXPECTED_AGENT_IDS = [
  "ReconScout",
  "WebBreaker",
  "CredSmith",
  "ADAttackMapper",
  "CloudSentinel",
  "ReverseSage",
  "FuzzSmith",
  "OSINTSeeker",
  "SecretHunter",
  "SessionRunner",
  "ReportSmith",
  "VulnIntel",
] as const;

function binding(): FleetAgentProjection {
  return {
    id: "runtime-safe-assessment",
    role: "reviewed-local-process-adapter",
    displayName: "Reviewed safe assessment adapter",
    status: "available",
    providerPolicy: {
      providerId: "local-deterministic",
      modelId: "policy-v1",
    },
    toolPolicy: {
      allowedTools: ["kali:host", "kali:curl", "local:cve-applicability"],
    },
    configuration: {
      adapterId: "reviewed-safe-assessment-v1",
    },
    version: "binding-v1",
    lastHeartbeatAt: "2026-07-23T12:00:00.000Z",
    capabilities: [{
      name: "kali:host",
      source: "live-route-attestation",
      enabled: true,
      metadata: { actionClassId: "dns_domain_certificate_discovery" },
    }, {
      name: "kali:curl",
      source: "live-route-attestation",
      enabled: true,
      metadata: { actionClassId: "web_crawling_page_capture" },
    }, {
      name: "local:cve-applicability",
      source: "live-route-attestation",
      enabled: true,
      metadata: { actionClassId: "cve_intelligence_applicability_validation" },
    }, {
      name: "unavailable:cloud",
      source: "live-route-attestation",
      enabled: false,
      metadata: { actionClassId: "cloud_container_kubernetes_assessment" },
    }],
  };
}

function manifests(): RuntimeSourceManifests {
  return {
    riskClasses: [],
    evidenceKinds: [],
    capabilities: [],
    tools: [{
      id: "kali:host",
      label: "Authorized host discovery",
      available: true,
      locallyPolicyEnforced: true,
      actionClassIds: ["dns_domain_certificate_discovery"],
      evidenceTypeIds: [],
      riskClassIds: [],
    }, {
      id: "kali:curl",
      label: "Authorized web capture",
      available: true,
      locallyPolicyEnforced: true,
      actionClassIds: ["web_crawling_page_capture"],
      evidenceTypeIds: [],
      riskClassIds: [],
    }, {
      id: "local:cve-applicability",
      label: "Local CVE applicability",
      available: true,
      locallyPolicyEnforced: true,
      actionClassIds: ["cve_intelligence_applicability_validation"],
      evidenceTypeIds: [],
      riskClassIds: [],
    }, {
      id: "unavailable:cloud",
      label: "Unavailable cloud assessment",
      available: false,
      locallyPolicyEnforced: true,
      actionClassIds: ["cloud_container_kubernetes_assessment"],
      evidenceTypeIds: [],
      riskClassIds: [],
    }],
    mcpServers: [],
    providers: [],
    agents: [{
      id: "runtime-safe-assessment",
      label: "Reviewed safe assessment adapter",
      available: true,
      capabilityIds: [],
      toolIds: [
        "kali:host",
        "kali:curl",
        "local:cve-applicability",
        "unavailable:cloud",
      ],
      deliverableIds: ["machine_readable_export", "pdf_html_markdown_report"],
      modelRefs: [],
    }],
  };
}

describe("standalone product agent registry", () => {
  test("defines exactly the twelve stable product specialists with audited domain metadata", () => {
    expect(PRODUCT_AGENT_REGISTRY.map(({ id }) => id)).toEqual([...EXPECTED_AGENT_IDS]);
    expect(new Set(PRODUCT_AGENT_REGISTRY.map(({ id }) => id)).size).toBe(12);
    expect(PRODUCT_AGENT_REGISTRY.every(({ role, domains, description, capabilities }) =>
      role.length > 10
      && domains.length > 0
      && description.length > 40
      && capabilities.length > 0)).toBe(true);
    const capabilityIds = PRODUCT_AGENT_REGISTRY.flatMap(({ capabilities }) =>
      capabilities.map(({ id }) => id));
    expect(new Set(capabilityIds).size).toBe(capabilityIds.length);
    expect(PRODUCT_AGENT_REGISTRY.find(({ id }) => id === "ReconScout")?.capabilities
      .flatMap(({ actionClassIds }) => actionClassIds)).toEqual([
        "active_host_discovery",
        "dns_domain_certificate_discovery",
        "port_service_enumeration",
        "os_technology_fingerprinting",
      ]);
    expect(PRODUCT_AGENT_REGISTRY.find(({ id }) => id === "VulnIntel")?.capabilities
      .flatMap(({ actionClassIds }) => actionClassIds)).toEqual([
        "vulnerability_configuration_assessment",
        "cve_intelligence_applicability_validation",
      ]);
  });

  test("maps live DNS, web, CVE, and report bindings to product roles without making unavailable domains ready", () => {
    const projected = projectProductAgentRoster({
      agents: [binding()],
      capabilityManifests: manifests(),
    });
    expect(projected).toHaveLength(13);
    const userFacing = projected.filter(({ configuration }) =>
      configuration.userFacing === true);
    expect(userFacing.map(({ id }) => id)).toEqual([...EXPECTED_AGENT_IDS]);
    expect(userFacing.every(({ configuration }) =>
      configuration.schemaVersion === PRODUCT_AGENT_ROSTER_VERSION)).toBe(true);

    expect(userFacing.find(({ id }) => id === "ReconScout")).toMatchObject({
      status: "available",
      capabilities: expect.arrayContaining([
        expect.objectContaining({ name: "kali:host", enabled: true }),
      ]),
    });
    expect(userFacing.find(({ id }) => id === "WebBreaker")).toMatchObject({
      status: "available",
      capabilities: expect.arrayContaining([
        expect.objectContaining({ name: "kali:curl", enabled: true }),
      ]),
    });
    expect(userFacing.find(({ id }) => id === "VulnIntel")).toMatchObject({
      status: "available",
      capabilities: expect.arrayContaining([
        expect.objectContaining({ name: "local:cve-applicability", enabled: true }),
      ]),
    });
    expect(userFacing.find(({ id }) => id === "ReportSmith")).toMatchObject({
      status: "available",
      capabilities: expect.arrayContaining([
        expect.objectContaining({
          name: "deliverable:pdf_html_markdown_report",
          enabled: true,
        }),
      ]),
    });
    expect(userFacing.find(({ id }) => id === "CloudSentinel")).toMatchObject({
      status: "offline",
      capabilities: expect.arrayContaining([
        expect.objectContaining({ name: "unavailable:cloud", enabled: false }),
      ]),
    });
    expect(userFacing.find(({ id }) => id === "SessionRunner")?.status).toBe("offline");

    const internal = projected.find(({ id }) => id === "runtime-safe-assessment");
    expect(internal?.configuration).toMatchObject({
      userFacing: false,
      productAgent: false,
      internalComponent: true,
      projectedProductAgentIds: [
        "ReconScout",
        "WebBreaker",
        "CloudSentinel",
        "ReportSmith",
        "VulnIntel",
      ],
    });
  });

  test("withdraws all readiness when no current runtime binding exists", () => {
    const projected = projectProductAgentRoster({ agents: [] });
    expect(projected).toHaveLength(12);
    expect(projected.every(({ status }) => status === "offline")).toBe(true);
    expect(projected.every(({ configuration }) =>
      configuration.userFacing === true
      && configuration.productAgent === true)).toBe(true);
    expect(projected.flatMap(({ capabilities }) => capabilities)
      .every(({ enabled }) => enabled === false)).toBe(true);
  });

  test("materializes an exact executable manifest tool when the runtime capability uses a different ID", () => {
    const runtimeAgent: FleetAgentProjection = {
      id: "ReconScout",
      role: "reconnaissance",
      displayName: "Recon Scout",
      status: "available",
      providerPolicy: {},
      toolPolicy: {
        allowedTools: ["tool-active-host-discovery"],
        deniedTools: [],
        approvalRequiredTools: [],
      },
      configuration: {},
      version: "reviewed-1",
      capabilities: [{
        name: "cap-recon",
        source: "reviewed",
        enabled: true,
      }],
    };
    const runtimeManifests: RuntimeSourceManifests = {
      riskClasses: [],
      evidenceKinds: [],
      capabilities: [{
        id: "cap-recon",
        label: "Reconnaissance",
        actionClassIds: ["active_host_discovery"],
      }],
      tools: [{
        id: "tool-active-host-discovery",
        label: "Bounded active host discovery",
        available: true,
        locallyPolicyEnforced: true,
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: [],
        riskClassIds: [],
        mcpServerId: "specialist-mcp",
      }],
      mcpServers: [{
        id: "specialist-mcp",
        label: "Specialist MCP",
        status: "healthy",
        toolIds: ["tool-active-host-discovery"],
      }],
      agents: [{
        id: "ReconScout",
        label: "Recon Scout",
        available: true,
        capabilityIds: ["cap-recon"],
        toolIds: ["tool-active-host-discovery"],
        modelRefs: [],
      }],
      providers: [],
    };

    const projected = projectProductAgentRoster({
      agents: [runtimeAgent],
      capabilityManifests: runtimeManifests,
    });
    const recon = projected.find(({ id }) => id === "ReconScout");
    expect(recon?.toolPolicy).toMatchObject({
      allowedTools: ["tool-active-host-discovery"],
    });
    expect(recon?.capabilities).toEqual(expect.arrayContaining([
      expect.objectContaining({
        name: "tool-active-host-discovery",
        source: "runtime-manifest-tool-binding",
        enabled: true,
      }),
    ]));
  });

  test("keeps generic capability IDs descriptive and fails exact tool readiness closed", () => {
    const runtimeAgent: FleetAgentProjection = {
      id: "specialist:recon",
      role: "reconnaissance",
      displayName: "Recon adapter",
      status: "available",
      providerPolicy: {},
      toolPolicy: {
        allowedTools: ["tool-active-host-discovery"],
        deniedTools: [],
        approvalRequiredTools: [],
      },
      configuration: { executionMounted: true },
      version: "reviewed-1",
      capabilities: [{
        name: "cap-recon",
        source: "reviewed",
        enabled: true,
      }],
    };
    const runtimeManifests: RuntimeSourceManifests = {
      riskClasses: [],
      evidenceKinds: [],
      capabilities: [{
        id: "cap-recon",
        label: "Reconnaissance",
        actionClassIds: ["active_host_discovery"],
      }],
      tools: [{
        id: "tool-active-host-discovery",
        label: "Bounded active host discovery",
        available: true,
        locallyPolicyEnforced: true,
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: [],
        riskClassIds: [],
        mcpServerId: "specialist-mcp",
      }],
      mcpServers: [{
        id: "specialist-mcp",
        label: "Specialist MCP",
        status: "healthy",
        toolIds: ["tool-active-host-discovery"],
      }],
      agents: [{
        id: "specialist:recon",
        label: "Recon adapter",
        available: true,
        capabilityIds: ["cap-recon"],
        toolIds: ["tool-active-host-discovery"],
        modelRefs: [],
      }],
      providers: [],
    };
    const project = (
      agent: FleetAgentProjection,
      manifests: RuntimeSourceManifests,
    ) => projectProductAgentRoster({
      agents: [agent],
      capabilityManifests: manifests,
    }).find(({ id }) => id === "ReconScout")!;

    const ready = project(runtimeAgent, runtimeManifests);
    expect(ready.toolPolicy).toMatchObject({
      allowedTools: ["tool-active-host-discovery"],
    });
    expect(ready.capabilities.find(({ name }) => name === "cap-recon")).toMatchObject({
      enabled: true,
    });

    const cases = [
      {
        name: "unavailable tool",
        agent: runtimeAgent,
        manifests: {
          ...runtimeManifests,
          tools: runtimeManifests.tools.map((tool) => ({ ...tool, available: false })),
        },
      },
      {
        name: "denied tool",
        agent: {
          ...runtimeAgent,
          toolPolicy: {
            allowedTools: ["tool-active-host-discovery"],
            deniedTools: ["tool-active-host-discovery"],
            approvalRequiredTools: [],
          },
        },
        manifests: runtimeManifests,
      },
      {
        name: "approval-required tool",
        agent: {
          ...runtimeAgent,
          toolPolicy: {
            allowedTools: ["tool-active-host-discovery"],
            deniedTools: [],
            approvalRequiredTools: ["tool-active-host-discovery"],
          },
        },
        manifests: runtimeManifests,
      },
      {
        name: "unhealthy MCP",
        agent: runtimeAgent,
        manifests: {
          ...runtimeManifests,
          mcpServers: runtimeManifests.mcpServers.map((server) => ({
            ...server,
            status: "degraded" as const,
          })),
        },
      },
      {
        name: "tool absent from MCP inventory",
        agent: runtimeAgent,
        manifests: {
          ...runtimeManifests,
          mcpServers: runtimeManifests.mcpServers.map((server) => ({
            ...server,
            toolIds: [],
          })),
        },
      },
      {
        name: "runtime capability disabled",
        agent: {
          ...runtimeAgent,
          capabilities: runtimeAgent.capabilities.map((capability) => ({
            ...capability,
            enabled: false,
          })),
        },
        manifests: runtimeManifests,
      },
      {
        name: "wrong agent tool assignment",
        agent: runtimeAgent,
        manifests: {
          ...runtimeManifests,
          agents: runtimeManifests.agents.map((agent) => ({
            ...agent,
            toolIds: [],
          })),
        },
      },
    ] as const;
    for (const item of cases) {
      const recon = project(item.agent, item.manifests);
      expect(recon.toolPolicy, item.name).toMatchObject({ allowedTools: [] });
      expect(
        recon.capabilities.find(({ name }) => name === "recon.asset-discovery"),
        item.name,
      ).toMatchObject({ enabled: false });
      expect(recon.status, item.name).toBe("offline");
    }
  });

  test("materializes the exact tool on the internal runtime binding as well as its product owner", () => {
    const runtimeAgent: FleetAgentProjection = {
      id: "specialist:recon",
      role: "reconnaissance",
      displayName: "Recon adapter",
      status: "available",
      providerPolicy: {},
      toolPolicy: {
        allowedTools: ["tool-active-host-discovery"],
        deniedTools: [],
        approvalRequiredTools: [],
      },
      configuration: { executionMounted: true },
      version: "reviewed-1",
      capabilities: [{
        name: "cap-recon",
        source: "reviewed",
        enabled: true,
      }],
    };
    const runtimeManifests: RuntimeSourceManifests = {
      riskClasses: [],
      evidenceKinds: [],
      capabilities: [{
        id: "cap-recon",
        label: "Reconnaissance",
        actionClassIds: ["active_host_discovery"],
      }],
      tools: [{
        id: "tool-active-host-discovery",
        label: "Bounded active host discovery",
        available: true,
        locallyPolicyEnforced: true,
        actionClassIds: ["active_host_discovery"],
        evidenceTypeIds: [],
        riskClassIds: [],
        mcpServerId: "specialist-mcp",
      }],
      mcpServers: [{
        id: "specialist-mcp",
        label: "Specialist MCP",
        status: "healthy",
        toolIds: ["tool-active-host-discovery"],
      }],
      agents: [{
        id: "specialist:recon",
        label: "Recon adapter",
        available: true,
        capabilityIds: ["cap-recon"],
        toolIds: ["tool-active-host-discovery"],
        modelRefs: [],
      }],
      providers: [],
    };
    const projected = projectProductAgentRoster({
      agents: [runtimeAgent],
      capabilityManifests: runtimeManifests,
    });
    for (const agentId of ["ReconScout", "specialist:recon"]) {
      expect(projected.find(({ id }) => id === agentId)?.capabilities).toEqual(
        expect.arrayContaining([expect.objectContaining({
          name: "tool-active-host-discovery",
          source: "runtime-manifest-tool-binding",
          enabled: true,
          metadata: expect.objectContaining({
            actionClassIds: ["active_host_discovery"],
            runtimeBindingAgentId: "specialist:recon",
          }),
        })]),
      );
    }
  });

  test("does not count offline, quarantined, or explicitly unmounted definition rows as runtime bindings", () => {
    for (const candidate of [
      { status: "offline" as const, configuration: {} },
      { status: "quarantined" as const, configuration: {} },
      { status: "available" as const, configuration: { executionMounted: false } },
    ]) {
      const projected = projectProductAgentRoster({
        agents: [{
          ...binding(),
          status: candidate.status,
          configuration: candidate.configuration,
        }],
        capabilityManifests: manifests(),
      });
      const recon = projected.find(({ id }) => id === "ReconScout");
      expect(recon).toMatchObject({
        status: "offline",
        configuration: {
          runtimeBindingAgentIds: [],
          readiness: {
            boundAdapterCount: 0,
            enabledCapabilityCount: 0,
          },
        },
      });
      const report = projected.find(({ id }) => id === "ReportSmith");
      expect(report).toMatchObject({
        status: "offline",
        toolPolicy: { allowedTools: [] },
        configuration: {
          runtimeBindingAgentIds: [],
          readiness: {
            boundAdapterCount: 0,
            enabledCapabilityCount: 0,
          },
        },
      });
      expect(report?.capabilities.some(({ name, enabled }) =>
        name.startsWith("deliverable:") && enabled)).toBe(false);
    }
  });

  test("maps internal manifest model references to stable compatible product roles", () => {
    const runtimeManifests: RuntimeSourceManifests = {
      riskClasses: [],
      evidenceKinds: [],
      mcpServers: [],
      providers: [{
        id: "local-provider",
        authenticated: true,
        healthy: true,
        catalogObservedAt: "2026-07-23T12:00:00.000Z",
        models: [{
          id: "policy-v1",
          displayName: "Local policy",
          toolCalling: false,
          structuredOutput: true,
          enforcement: "enforced_executor",
          compatibleActionClassIds: [
            "dns_domain_certificate_discovery",
            "port_service_enumeration",
          ],
          disclosureClasses: ["local"],
        }],
      }],
      capabilities: [{
        id: "capability:safe-recon",
        label: "Safe reconnaissance",
        actionClassIds: [
          "dns_domain_certificate_discovery",
          "port_service_enumeration",
        ],
      }],
      tools: [{
        id: "local:safe-recon",
        label: "Safe reconnaissance",
        available: true,
        locallyPolicyEnforced: true,
        actionClassIds: ["port_service_enumeration"],
        evidenceTypeIds: ["port_service_scan_result"],
        riskClassIds: [],
      }],
      agents: [{
        id: "specialist:autonomous-safe-recon",
        label: "Internal autonomous safe recon adapter",
        available: true,
        capabilityIds: ["capability:safe-recon"],
        toolIds: ["local:safe-recon"],
        modelRefs: [{ providerId: "local-provider", modelId: "policy-v1" }],
      }],
    };
    expect(productAgentIdsForRuntimeManifestAgent(
      runtimeManifests.agents[0]!,
      runtimeManifests,
    )).toEqual(["ReconScout"]);
    expect(productAgentIdsForRuntimeManifestAgent(
      {
        ...runtimeManifests.agents[0]!,
        capabilityIds: [],
        toolIds: [],
        actionClassIds: ["cve_intelligence_applicability_validation"],
        deliverableIds: ["pdf_html_markdown_report"],
      },
      runtimeManifests,
    )).toEqual(["ReportSmith", "VulnIntel"]);
  });
});

import { describe, expect, test } from "bun:test";

import {
  ACTION_CLASS_IDS,
  ACTION_POLICY_STATES,
  EVIDENCE_TYPE_IDS,
  applyMissionTemplate,
  assertAutonomousRegistryLaunchReady,
  assertJourney,
  assertTemplatePreservedTargetScope,
  autonomousActionDisposition,
  buildActionClassRegistry,
  buildDeliverableRegistry,
  buildEvidenceTypeRegistry,
  buildMissionTemplateRegistry,
  buildRuntimeCapabilityProjection,
  isJourney,
  MISSION_TEMPLATES,
} from "../../../server/domain";
import { completeRuntimeManifests } from "./fixtures";

describe("two-journey invariant", () => {
  test("accepts exactly autonomous and guided", () => {
    expect(isJourney("autonomous")).toBe(true);
    expect(isJourney("guided")).toBe(true);
    expect(isJourney("ask")).toBe(false);
    expect(isJourney("direct")).toBe(false);
    expect(isJourney("observe")).toBe(false);
    expect(() => assertJourney("approval")).toThrow("exactly autonomous or guided");
  });
});

describe("runtime-derived registries", () => {
  test("maps tools, MCP, agents, risks, evidence, and enforced provider models", () => {
    const projection = buildRuntimeCapabilityProjection(completeRuntimeManifests());
    const mapping = projection.actionClasses.port_service_enumeration;

    expect(mapping.availability).toBe("supported");
    expect(mapping.agentIds).toEqual(["test-specialist"]);
    expect(mapping.toolIds).toEqual(["policy-gated-tool"]);
    expect(mapping.mcpServerIds).toEqual(["test-mcp"]);
    expect(mapping.riskClassIds).toEqual(["runtime-risk"]);
    expect(mapping.enforcedProviderModelRefs).toEqual(["test-provider/test-model"]);
    expect(mapping.enforcementReady).toBe(true);
    expect(projection.sourceCounts.models).toBe(1);
  });

  test("rejects manifest references that are not in the canonical catalogs", () => {
    const manifests = completeRuntimeManifests();
    const invalid = {
      ...manifests,
      tools: [
        {
          ...manifests.tools[0]!,
          actionClassIds: ["ui_only_action_that_runtime_does_not_know"],
        },
      ],
    };

    expect(() => buildRuntimeCapabilityProjection(invalid)).toThrow(
      "unknown registry ids",
    );
  });

  test("requires every planner-visible composite to name exact non-composite local constituents", () => {
    const manifests = completeRuntimeManifests();
    const physical = {
      ...manifests.tools[0]!,
      id: "kali:physical-phase",
      mcpServerId: undefined,
      requiresModel: false,
      executionJourneys: ["guided"] as const,
    };
    const composite = {
      ...manifests.tools[0]!,
      id: "ti-scale:planner-composite",
      mcpServerId: undefined,
      requiresModel: false,
      executionJourneys: ["autonomous"] as const,
      constituentToolIds: [physical.id],
    };
    expect(() => buildRuntimeCapabilityProjection({
      ...manifests,
      tools: [...manifests.tools, composite, physical],
    })).not.toThrow();
    expect(() => buildRuntimeCapabilityProjection({
      ...manifests,
      tools: [...manifests.tools, { ...composite, constituentToolIds: ["kali:missing-phase"] }],
    })).toThrow("Runtime manifests contain broken references");
    expect(() => buildRuntimeCapabilityProjection({
      ...manifests,
      tools: [...manifests.tools, physical, { ...composite, constituentToolIds: [composite.id] }],
    })).toThrow("Runtime manifests contain broken references");
  });

  test("marks mapped capabilities unavailable when their MCP is offline", () => {
    const projection = buildRuntimeCapabilityProjection(
      completeRuntimeManifests({ mcpStatus: "offline" }),
    );
    const mapping = projection.actionClasses.active_host_discovery;
    expect(mapping.availability).toBe("unavailable");
    expect(mapping.enforcementReady).toBe(false);
    expect(mapping.readinessReasons).toContain(
      "policy-gated-tool requires MCP server test-mcp, which is offline; restore that exact server and repeat its inventory attestation.",
    );
  });

  test("does not manufacture readiness by cross-joining an unbound agent and installed tool", () => {
    const manifests = completeRuntimeManifests();
    const projection = buildRuntimeCapabilityProjection({
      ...manifests,
      agents: manifests.agents.map((agent) => ({ ...agent, toolIds: [] })),
    });
    const mapping = projection.actionClasses.port_service_enumeration;

    // The installed/healthy tool remains visible for operator diagnosis, but
    // there is no executable specialist -> tool route for this action class.
    expect(mapping.toolIds).toEqual(["policy-gated-tool"]);
    expect(mapping.availableToolIds).toEqual(["policy-gated-tool"]);
    expect(mapping.agentIds).toEqual(["test-specialist"]);
    expect(mapping.availableAgentIds).toEqual([]);
    expect(mapping.providerModelRefs).toEqual([]);
    expect(mapping.availability).toBe("unavailable");
    expect(mapping.enforcementReady).toBe(false);
    expect(mapping.readinessReasons).toContain(
      "No declared agent is bound to the mapped tool: policy-gated-tool.",
    );
  });

  test("names the exact unavailable dependency instead of reporting a generic tool block", () => {
    const manifests = completeRuntimeManifests();
    const projection = buildRuntimeCapabilityProjection({
      ...manifests,
      tools: manifests.tools.map((tool) => ({
        ...tool,
        dependencies: [{ id: "isolated-target-free-readiness", ready: false }],
      })),
    });
    const mapping = projection.actionClasses.active_host_discovery;

    expect(mapping.availability).toBe("unavailable");
    expect(mapping.availableToolIds).toEqual([]);
    expect(mapping.enforcementReady).toBe(false);
    expect(mapping.readinessReasons).toContain(
      "policy-gated-tool is waiting for dependency: isolated-target-free-readiness.",
    );
    expect(mapping.readinessReasons.join(" ")).not.toContain(
      "All mapped tools or dependencies are unavailable",
    );
  });

  test("keeps a receipt-ready Guided binding visible without presenting it as Autonomous", () => {
    const manifests = completeRuntimeManifests();
    const projection = buildRuntimeCapabilityProjection({
      ...manifests,
      tools: manifests.tools.map((tool) => ({
        ...tool,
        mcpServerId: undefined,
        requiresModel: false,
        executionJourneys: ["guided"] as const,
      })),
      mcpServers: [],
    });
    const mapping = projection.actionClasses.port_service_enumeration;

    expect(mapping.availability).toBe("supported");
    expect(mapping.availableToolIds).toEqual(["policy-gated-tool"]);
    expect(mapping.locallyEnforcedToolIds).toEqual([]);
    expect(mapping.enforcementReady).toBe(false);
    expect(mapping.readinessReasons).toContain(
      "Ready tool policy-gated-tool is approved for guided execution, not Autonomous execution.",
    );
  });

  test("promotes the same joined model-free binding only when Autonomous is explicitly approved", () => {
    const manifests = completeRuntimeManifests();
    const projection = buildRuntimeCapabilityProjection({
      ...manifests,
      tools: manifests.tools.map((tool) => ({
        ...tool,
        mcpServerId: undefined,
        requiresModel: false,
        executionJourneys: ["autonomous", "guided"] as const,
      })),
      mcpServers: [],
    });
    const mapping = projection.actionClasses.port_service_enumeration;

    expect(mapping.availability).toBe("supported");
    expect(mapping.availableAgentIds).toEqual(["test-specialist"]);
    expect(mapping.availableToolIds).toEqual(["policy-gated-tool"]);
    expect(mapping.locallyEnforcedToolIds).toEqual(["policy-gated-tool"]);
    expect(mapping.enforcementReady).toBe(true);
    expect(mapping.readinessReasons).toEqual([]);
  });

  test("builds evidence and deliverable readiness from the supplied projection", () => {
    const projection = buildRuntimeCapabilityProjection(completeRuntimeManifests());
    const evidence = buildEvidenceTypeRegistry(projection);
    const deliverables = buildDeliverableRegistry(projection);

    expect(evidence.types.http_exchange.capability.availability).toBe("supported");
    expect(evidence.types.http_exchange.capability.producerToolIds).toEqual([
      "policy-gated-tool",
    ]);
    expect(deliverables.deliverables.evidence_bundle.capability.availability).toBe(
      "supported",
    );
  });

  test("keeps unsupported evidence inspectable but removes it from runtime recommendations", () => {
    const manifests = completeRuntimeManifests();
    const supportedEvidenceTypeIds = [
      "asset_discovery_proof",
      "port_service_scan_result",
    ] as const;
    const projection = buildRuntimeCapabilityProjection({
      ...manifests,
      evidenceKinds: manifests.evidenceKinds.map((item) => ({
        ...item,
        evidenceTypeIds: supportedEvidenceTypeIds,
      })),
      tools: manifests.tools.map((item) => ({
        ...item,
        evidenceTypeIds: supportedEvidenceTypeIds,
      })),
    });
    const evidence = buildEvidenceTypeRegistry(projection);
    const template = buildMissionTemplateRegistry(projection).templates.safe_recon;

    expect(template.recommendedEvidenceTypeIds).toEqual(supportedEvidenceTypeIds);
    expect(template.unavailableEvidenceTypeIds).toEqual([
      "service_version_fingerprint",
      "http_exchange",
      "endpoint_discovery_result",
      "os_platform_fingerprint",
      "dns_certificate_record",
    ]);
    expect(Object.keys(evidence.types)).toHaveLength(EVIDENCE_TYPE_IDS.length);
    expect(evidence.types.os_platform_fingerprint.capability.availability).toBe("unsupported");
    expect(evidence.types.os_platform_fingerprint.immutableHashRequired).toBe(true);
    expect(evidence.types.dns_certificate_record.chainOfCustodyRequired).toBe(true);
  });
});

describe("action policy registry", () => {
  test("resolves every supported Autonomous class without an inherited state", () => {
    const projection = buildRuntimeCapabilityProjection(completeRuntimeManifests());
    const registry = buildActionClassRegistry({
      journey: "autonomous",
      presetId: "safe_recon",
      destructivePolicy: "prohibited",
      projection,
      authorizedTargetIds: ["target-1"],
    });

    for (const id of ACTION_CLASS_IDS) {
      expect(ACTION_POLICY_STATES).toContain(registry.classes[id].policyState);
      expect(registry.classes[id].policyState).not.toBe("inherited_default");
    }
    expect(registry.classes.denial_of_service_disruption.policyState).toBe("prohibited");
    expect(registry.classes.destructive_modification.policyState).toBe("prohibited");
    expect(registry.classes.persistence.policyState).toBe("prohibited");
    expect(autonomousActionDisposition(registry, "passive_intelligence_osint")).toBe(
      "execute_inside_contract",
    );
    expect(autonomousActionDisposition(registry, "exploit_validation")).toBe(
      "safe_stop_or_choose_in_scope_alternative",
    );
    expect(autonomousActionDisposition(registry, "destructive_modification")).toBe(
      "deny_prohibited",
    );
    expect(assertAutonomousRegistryLaunchReady(registry)).toBe(registry);
  });

  test("blocks explicitly pre-authorized Autonomous work without an enforced executor", () => {
    const projection = buildRuntimeCapabilityProjection(
      completeRuntimeManifests({ enforcement: "observe_only_executor" }),
    );
    const registry = buildActionClassRegistry({
      journey: "autonomous",
      presetId: "safe_recon",
      destructivePolicy: "prohibited",
      projection,
      authorizedTargetIds: ["target-1"],
      overrides: { passive_intelligence_osint: "pre_authorized" },
    });

    expect(registry.autonomousLaunchReady).toBe(false);
    expect(registry.launchBlockingReasons.join(" ")).toContain("no locally enforced executor");
    expect(registry.launchBlockingReasons.join(" ")).toContain("Passive intelligence and OSINT");
    expect(registry.launchBlockingReasons.join(" ")).toContain("policy-gated-tool");
    expect(registry.launchBlockingReasons.join(" ")).toContain("enforced-executor model");
    expect(registry.launchBlockingReasons.join(" ")).not.toContain("passive_intelligence_osint");
    expect(() => assertAutonomousRegistryLaunchReady(registry)).toThrow("not executable");
  });

  test("carries exact dependency remediation into an explicit Autonomous blocker", () => {
    const manifests = completeRuntimeManifests();
    const projection = buildRuntimeCapabilityProjection({
      ...manifests,
      tools: manifests.tools.map((tool) => ({
        ...tool,
        dependencies: [{ id: "workspace-confinement", ready: false }],
      })),
    });
    const registry = buildActionClassRegistry({
      journey: "autonomous",
      presetId: "custom",
      destructivePolicy: "prohibited",
      projection,
      authorizedTargetIds: ["target-1"],
      overrides: { active_host_discovery: "pre_authorized" },
    });

    expect(registry.autonomousLaunchReady).toBe(false);
    expect(registry.classes.active_host_discovery.capability.toolIds).toEqual([
      "policy-gated-tool",
    ]);
    expect(registry.launchBlockingReasons.join(" ")).toContain(
      "policy-gated-tool is waiting for dependency: workspace-confinement",
    );
  });

  test("never enables destructive execution from a preset alone", () => {
    const projection = buildRuntimeCapabilityProjection(completeRuntimeManifests());
    const registry = buildActionClassRegistry({
      journey: "autonomous",
      presetId: "full_authorized_lab_compromise",
      destructivePolicy: "prohibited",
      projection,
      authorizedTargetIds: ["lab-1"],
    });

    expect(registry.classes.destructive_modification.policyState).toBe("prohibited");
    expect(registry.classes.denial_of_service_disruption.policyState).toBe("prohibited");
  });

  test("blocks a Full Authorized Lab Compromise preset instead of silently reducing it to recon", () => {
    const manifests = completeRuntimeManifests();
    const safeReconClasses = [
      "active_host_discovery",
      "dns_domain_certificate_discovery",
      "port_service_enumeration",
    ] as const;
    const projection = buildRuntimeCapabilityProjection({
      ...manifests,
      tools: manifests.tools.map((tool) => ({
        ...tool,
        actionClassIds: safeReconClasses,
      })),
    });
    const registry = buildActionClassRegistry({
      journey: "autonomous",
      presetId: "full_authorized_lab_compromise",
      destructivePolicy: "prohibited",
      projection,
      authorizedTargetIds: ["lab-1"],
    });

    expect(registry.autonomousLaunchReady).toBe(false);
    expect(registry.classes.exploit_validation.policyState).toBe("pre_authorized");
    expect(registry.classes.privilege_escalation.policyState).toBe("pre_authorized");
    expect(registry.launchBlockingReasons.join(" ")).toContain(
      "selected Full Authorized Lab Compromise preset requires this class",
    );
    expect(() => assertAutonomousRegistryLaunchReady(registry)).toThrow("not executable");
  });

  test("keeps the HTB Web Full Path explicit and blocks until every full-path binding is ready", () => {
    const manifests = completeRuntimeManifests();
    const assessmentClasses = [
      "active_host_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
      "web_crawling_page_capture",
      "web_content_endpoint_discovery_fuzzing",
      "vulnerability_configuration_assessment",
      "cve_intelligence_applicability_validation",
    ] as const;
    const projection = buildRuntimeCapabilityProjection({
      ...manifests,
      tools: manifests.tools.map((tool) => ({
        ...tool,
        actionClassIds: assessmentClasses,
      })),
    });
    const registry = buildActionClassRegistry({
      journey: "autonomous",
      presetId: "htb_web_full_path",
      destructivePolicy: "bounded_lab_only",
      projection,
      authorizedTargetIds: ["lab-1"],
      boundedDestructiveTargetIds: ["lab-1"],
    });

    expect(registry.autonomousLaunchReady).toBe(false);
    expect(registry.classes.exploit_validation.policyState).toBe("pre_authorized");
    expect(registry.classes.privilege_escalation.policyState).toBe("pre_authorized");
    expect(registry.classes.command_session_execution.policyState).toBe("pre_authorized");
    expect(registry.classes.data_access_impact_validation.policyState).toBe(
      "pre_authorized",
    );
    expect(registry.classes.cleanup_restoration.policyState).toBe("pre_authorized");
    expect(registry.classes.passive_intelligence_osint.policyState).toBe("prohibited");
    expect(registry.launchBlockingReasons.join(" ")).toContain(
      "selected HTB Web Full Path preset requires this class",
    );
  });

  test("requires named authorized lab targets for an explicit destructive override", () => {
    const projection = buildRuntimeCapabilityProjection(completeRuntimeManifests());
    const blocked = buildActionClassRegistry({
      journey: "autonomous",
      presetId: "custom",
      destructivePolicy: "bounded_lab_only",
      projection,
      authorizedTargetIds: ["lab-1"],
      overrides: { destructive_modification: "pre_authorized" },
    });
    expect(blocked.classes.destructive_modification.policyState).toBe("prohibited");
    expect(blocked.autonomousLaunchReady).toBe(false);

    const bounded = buildActionClassRegistry({
      journey: "autonomous",
      presetId: "custom",
      destructivePolicy: "bounded_lab_only",
      projection,
      authorizedTargetIds: ["lab-1"],
      boundedDestructiveTargetIds: ["lab-1"],
      overrides: { destructive_modification: "pre_authorized" },
    });
    expect(bounded.classes.destructive_modification.policyState).toBe("pre_authorized");

    expect(() =>
      buildActionClassRegistry({
        journey: "autonomous",
        presetId: "custom",
        destructivePolicy: "bounded_lab_only",
        projection,
        authorizedTargetIds: ["lab-1"],
        boundedDestructiveTargetIds: ["outside-scope"],
      }),
    ).toThrow("outside supplied authorization");
  });
});

describe("versioned mission templates", () => {
  test("derive readiness from runtime capabilities and never supply target scope", () => {
    const projection = buildRuntimeCapabilityProjection(completeRuntimeManifests());
    const registry = buildMissionTemplateRegistry(projection);
    const template = registry.templates.external_web_assessment;
    const suppliedTargets = [
      { id: "target-1", type: "url" as const, value: "https://approved.example.test" },
      { id: "target-2", type: "domain" as const, value: "api.example.test", excluded: true },
    ];

    expect(template.unsupportedActionClassIds).toEqual([]);
    const applied = applyMissionTemplate(template, "guided", suppliedTargets);
    assertTemplatePreservedTargetScope(suppliedTargets, applied);
    expect(applied.targets).toEqual(suppliedTargets);
    expect(applied.targets).not.toBe(suppliedTargets);
    expect(applied.generatedObjective).not.toContain("another-target");
  });

  test("every template supports only the two canonical journeys", () => {
    for (const template of MISSION_TEMPLATES) {
      expect(template.supportedJourneys.length).toBeGreaterThan(0);
      for (const journey of template.supportedJourneys) {
        expect(["autonomous", "guided"]).toContain(journey);
      }
    }
  });
});

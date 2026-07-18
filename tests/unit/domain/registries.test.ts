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

  test("marks mapped capabilities unavailable when their MCP is offline", () => {
    const projection = buildRuntimeCapabilityProjection(
      completeRuntimeManifests({ mcpStatus: "offline" }),
    );
    expect(projection.actionClasses.active_host_discovery.availability).toBe("unavailable");
    expect(projection.actionClasses.active_host_discovery.enforcementReady).toBe(false);
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
    expect(registry.launchBlockingReasons.join(" ")).not.toContain("passive_intelligence_osint");
    expect(() => assertAutonomousRegistryLaunchReady(registry)).toThrow("not executable");
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

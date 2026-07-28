import { describe, expect, test } from "bun:test";
import { MissionIntakeService, MissionIntakeValidationError } from "../../../server/intake";
import { ACTION_CLASS_IDS } from "../../../server/domain/catalog-ids";
import {
  AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
  AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION,
  AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION,
  AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
  AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION,
  AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  AUTONOMOUS_USER_ACCESS_PROOF_SUCCESS_CRITERION,
} from "../../../server/domain/autonomous-outcome-registry";
import { completeRuntimeManifests } from "../domain/fixtures";

const EXACT_IP_AGENT_ID = "specialist:autonomous-safe-recon";
const EXACT_IP_PROVIDER_ID = "provider:local-deterministic-safe-recon";
const EXACT_IP_MODEL_ID = "policy:local-safe-recon-v2";

function exactIpRuntimeManifests() {
  const manifests = completeRuntimeManifests();
  return {
    ...manifests,
    agents: manifests.agents.map((agent) => ({
      ...agent,
      id: EXACT_IP_AGENT_ID,
      modelRefs: [{ providerId: EXACT_IP_PROVIDER_ID, modelId: EXACT_IP_MODEL_ID }],
    })),
    providers: manifests.providers.map((provider) => ({
      ...provider,
      id: EXACT_IP_PROVIDER_ID,
      models: provider.models.map((model) => ({ ...model, id: EXACT_IP_MODEL_ID })),
    })),
  };
}

const service = new MissionIntakeService({
  readRuntimeManifests: () => completeRuntimeManifests(),
  clock: () => new Date("2026-07-16T12:00:00.000Z"),
});

describe("MissionIntakeService", () => {
  test("fails closed instead of signing a merely compatible but Autonomous-unready model fallback", () => {
    const base = completeRuntimeManifests();
    const unready = {
      ...base,
      providers: base.providers.map((provider) => ({
        ...provider,
        models: provider.models.map((model) => ({
          ...model,
          executionBoundary: "provider_tool_calling" as const,
          toolCalling: false,
        })),
      })),
    };
    const unreadyService = new MissionIntakeService({
      readRuntimeManifests: () => unready,
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
    });

    expect(() => unreadyService.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "portal.example.test" }],
      specialistAgentIds: ["ReconScout"],
    })).toThrow(
      "No current Autonomous-ready model configuration is available for selected specialist ReconScout",
    );
  });

  test("resolves the minimal Autonomous intake into a complete conservative contract", () => {
    const resolved = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.0/24" }],
    });

    expect(resolved.request.journey).toBe("autonomous");
    if (resolved.request.journey !== "autonomous") throw new Error("Expected Autonomous request");
    expect(resolved.autonomousOutcome).toMatchObject({
      id: "assessment",
      label: "Autonomous Assessment",
      requiredTerminalSuccessCriteria: [],
      requiredActionClassIds: [],
    });
    expect(resolved.request.contract.outcomeProfile).toBe("assessment");
    expect(resolved.request.title).toBe("Safe Recon — 10.10.10.0/24 — 2026-07-16");
    expect(resolved.request.objective).toContain("Authorized scope: 10.10.10.0/24");
    expect(resolved.request.successCriteria.length).toBeGreaterThan(0);
    expect(resolved.request.contract.deliverables.length).toBeGreaterThan(0);
    expect(resolved.request.contract.evidenceRequirements).toEqual([]);
    expect(resolved.request.contract.safeStopConditions).toContain("budget_reached");
    expect(resolved.request.contract.toolCallBudget).toBe(resolved.budget.toolCallBudget);
    expect(resolved.request.contract.destructivePolicy).toBe("prohibited");
    expect(resolved.request.contract.planningSelection).toEqual({
      route: "local_deterministic",
      plannerId: "ti-scale.local-autonomous-contract-planner.v1",
      enforcementMode: "local_policy",
      disclosureClass: "local_only",
      executionAuthority: "none",
    });
    expect(resolved.request.contract.memoryScopes).toEqual([
      "confirmed_preferences",
      "verified_lessons",
      "confirmed_attack_knowledge",
      "verified_attack_knowledge",
    ]);
    expect(resolved.mandatorySafeStopIds).toContain("target_outside_authorized_scope");
    expect(resolved.inferredFields).toContain("title");
    expect(resolved.inferredFields).toContain("memoryScopes");
    expect(resolved.inferredFields).toContain("planningSelection");
    expect(resolved.normalizedTargets[0]?.type).toBe("cidr");
    expect(resolved.limitations.join(" ")).toContain("No target-compatible reviewed outcome producer");
  });

  test("defaults Custom Autonomous intake to the canonical terminal report pair", () => {
    const resolved = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      templateId: "custom",
    });
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Expected Autonomous request");
    }

    expect(resolved.request.contract.deliverables).toEqual([
      ...AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
    ]);
    expect(resolved.inferredFields).toContain("deliverables");
  });

  test("reviews and preserves a distinct provider-advisory planning selection", () => {
    const reviewed: unknown[] = [];
    const planningService = new MissionIntakeService({
      readRuntimeManifests: exactIpRuntimeManifests,
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
      modelConfigurations: {
        resolveAutonomousAssignments(input) {
          return {
            observedAt: "2026-07-16T12:00:00.000Z",
            selections: [...input.specialistAgentIds]
              .sort((left, right) => left.localeCompare(right))
              .map((agentId) => ({
                agentId,
                primaryConfigurationId: `modelcfg_execution_${agentId}`,
                fallbackConfigurationId: null,
              })),
            receipts: [],
          };
        },
        validateAutonomousPlanningSelection(selection) {
          reviewed.push(selection);
          return { ready: true } as never;
        },
      },
    });
    const planningSelection = {
      route: "provider_advisory",
      agentId: "Commander",
      primaryConfigurationId: "modelcfg_planning_primary",
      fallbackConfigurationId: "modelcfg_planning_fallback",
      enforcementMode: "advisor_only",
      disclosureClass: "sanitized_internal",
      executionAuthority: "none",
    } as const;
    const resolved = planningService.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      planningSelection,
    });
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Expected an Autonomous request");
    }
    expect(reviewed).toEqual([planningSelection]);
    expect(resolved.request.contract.planningSelection).toEqual(
      planningSelection,
    );
    expect(resolved.inferredFields).not.toContain("planningSelection");
  });

  test("fails closed when provider-backed planning cannot be reviewed", () => {
    expect(() => service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      planningSelection: {
        route: "provider_advisory",
        agentId: "Commander",
        primaryConfigurationId: "modelcfg_planning_primary",
        fallbackConfigurationId: null,
        enforcementMode: "advisor_only",
        disclosureClass: "public_only",
        executionAuthority: "none",
      },
    })).toThrow("live planning-model catalog is unavailable");
  });

  test("fails closed when the reviewed planning model is present but not ready", () => {
    const unavailable = new MissionIntakeService({
      readRuntimeManifests: exactIpRuntimeManifests,
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
      modelConfigurations: {
        resolveAutonomousAssignments() {
          throw new Error("Execution assignment resolution must not run after planning admission fails");
        },
        validateAutonomousPlanningSelection() {
          return {
            ready: false,
            reasons: ["The primary planning provider health state is degraded."],
          } as never;
        },
      },
    });
    expect(() => unavailable.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      planningSelection: {
        route: "provider_advisory",
        agentId: "Commander",
        primaryConfigurationId: "modelcfg_planning_primary",
        fallbackConfigurationId: null,
        enforcementMode: "advisor_only",
        disclosureClass: "public_only",
        executionAuthority: "none",
      },
    })).toThrow("primary planning provider health state is degraded");
  });

  test("defaults only target-compatible executable outcomes for exact IP and domain scopes", () => {
    const ipService = new MissionIntakeService({
      readRuntimeManifests: exactIpRuntimeManifests,
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
    });
    const ip = ipService.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
    });
    if (ip.request.journey !== "autonomous") throw new Error("Expected Autonomous request");
    expect(ip.request.contract.allowedActionClasses).toEqual([
      "active_host_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
      "web_crawling_page_capture",
      "web_content_endpoint_discovery_fuzzing",
      "cve_intelligence_applicability_validation",
    ]);
    expect(ip.request.contract.allowedActionClasses).not.toContain(
      "dns_domain_certificate_discovery",
    );
    expect(ip.request.successCriteria).toEqual([
      "The exact approved host has one verified bounded liveness result",
      "The exact approved host has one verified result for the reviewed TCP port set",
      "Every responding derived HTTP origin has one verified bounded technology fingerprint result",
      "Every HTTP origin derived from the verified TCP baseline has one verified bounded metadata result",
      "Every responding derived HTTP origin has one verified bounded endpoint-discovery result",
      "Every verified service product/version observation has one conservative, authoritative-source-backed CVE applicability assessment",
    ]);
    expect(ip.request.contract.evidenceRequirements).toEqual([
      "asset_discovery_proof",
      "port_service_scan_result",
      "service_version_fingerprint",
      "http_exchange",
      "endpoint_discovery_result",
      "cve_applicability",
    ]);
    expect(ip.request.contract.specialistAgentIds).toEqual([
      "ReconScout",
      "VulnIntel",
      "WebBreaker",
    ]);
    expect(ip.request.contract.agentModelAssignments.map(({ agentId }) => agentId))
      .toEqual(["ReconScout", "VulnIntel", "WebBreaker"]);
    expect(ip.request.contract.agentModelAssignments.every(
      ({ primaryConfigurationId, fallbackConfigurationId }) =>
        primaryConfigurationId.length > 0
        && fallbackConfigurationId !== primaryConfigurationId,
    )).toBe(true);
    expect(ip.inferredFields).toContain("agentModelAssignments");
    expect(ip.request.contract.providerPolicy).toBe("automatic_enforcing_only");
    const endpointCapability = ip.policyMatrix.classes.web_content_endpoint_discovery_fuzzing
      .capability;
    expect(endpointCapability.availableAgentIds).toEqual([EXACT_IP_AGENT_ID]);
    expect(endpointCapability.providerModelRefs).toEqual([
      `${EXACT_IP_PROVIDER_ID}/${EXACT_IP_MODEL_ID}`,
    ]);

    const domain = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "portal.example.test" }],
    });
    if (domain.request.journey !== "autonomous") throw new Error("Expected Autonomous request");
    expect(domain.request.contract.allowedActionClasses).toEqual([
      "dns_domain_certificate_discovery",
    ]);
    expect(domain.request.successCriteria).toEqual([
      "The exact DNS A query has one verified result for the authorized domain",
    ]);
    expect(domain.request.contract.evidenceRequirements).toEqual(["dns_certificate_record"]);
  });

  test("preserves partial model overrides and materializes every remaining selected specialist exactly", () => {
    const calls: unknown[] = [];
    const exact = new MissionIntakeService({
      readRuntimeManifests: exactIpRuntimeManifests,
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
      modelConfigurations: {
        resolveAutonomousAssignments(input) {
          calls.push(input);
          return {
            observedAt: "2026-07-16T12:00:00.000Z",
            selections: [...input.specialistAgentIds]
              .sort((left, right) => left.localeCompare(right))
              .map((agentId) =>
                input.overrides?.find((item) => item.agentId === agentId) ?? {
                  agentId,
                  primaryConfigurationId: `modelcfg_recommended_${agentId}`,
                  fallbackConfigurationId: null,
                }),
            receipts: [],
          };
        },
      },
    });
    const partial = exact.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      specialistAgentIds: ["VulnIntel", "ReconScout"],
      agentModelAssignments: [{
        agentId: "ReconScout",
        primaryConfigurationId: "modelcfg_operator_recon",
        fallbackConfigurationId: "modelcfg_operator_recon_fallback",
      }],
    });
    if (partial.request.journey !== "autonomous") {
      throw new Error("Expected an Autonomous request");
    }
    expect(calls[0]).toMatchObject({
      specialistAgentIds: ["ReconScout", "VulnIntel"],
      overrides: [{
        agentId: "ReconScout",
        primaryConfigurationId: "modelcfg_operator_recon",
        fallbackConfigurationId: "modelcfg_operator_recon_fallback",
      }],
    });
    expect(partial.request.contract.agentModelAssignments).toEqual([
      {
        agentId: "ReconScout",
        primaryConfigurationId: "modelcfg_operator_recon",
        fallbackConfigurationId: "modelcfg_operator_recon_fallback",
      },
      {
        agentId: "VulnIntel",
        primaryConfigurationId: "modelcfg_recommended_VulnIntel",
        fallbackConfigurationId: null,
      },
    ]);
    expect(partial.inferredFields).toContain("agentModelAssignments");

    const complete = exact.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      specialistAgentIds: ["VulnIntel", "ReconScout"],
      agentModelAssignments: [
        {
          agentId: "VulnIntel",
          primaryConfigurationId: "modelcfg_operator_vuln",
          fallbackConfigurationId: null,
        },
        {
          agentId: "ReconScout",
          primaryConfigurationId: "modelcfg_operator_recon",
          fallbackConfigurationId: null,
        },
      ],
    });
    expect(complete.inferredFields).not.toContain("agentModelAssignments");
  });

  test("keeps Full Authorized Lab Compromise requirements explicit instead of silently reducing them to recon", () => {
    const manifests = exactIpRuntimeManifests();
    const reconOnly = new MissionIntakeService({
      readRuntimeManifests: () => ({
        ...manifests,
        tools: manifests.tools.map((tool) => ({
          ...tool,
          actionClassIds: tool.actionClassIds.filter((actionClassId) => [
            "active_host_discovery",
            "port_service_enumeration",
            "os_technology_fingerprinting",
            "web_crawling_page_capture",
            "web_content_endpoint_discovery_fuzzing",
            "cve_intelligence_applicability_validation",
          ].includes(actionClassId)),
        })),
      }),
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
    });
    const resolved = reconOnly.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      templateId: "full_authorized_lab_compromise",
    });
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Expected Autonomous request");
    }
    expect(resolved.autonomousOutcome).toMatchObject({
      id: "complete_engagement",
      label: "Complete Autonomous Engagement",
      requiredTerminalSuccessCriteria:
        AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
    });
    expect(resolved.request.contract.outcomeProfile)
      .toBe("complete_engagement");
    expect(resolved.policyMatrix.classes.exploit_validation.policyState)
      .toBe("pre_authorized");
    expect(resolved.policyMatrix.classes.privilege_escalation.policyState)
      .toBe("pre_authorized");
    expect(resolved.request.contract.allowedActionClasses).toContain(
      "exploit_validation",
    );
    expect(resolved.request.contract.allowedActionClasses).toContain(
      "privilege_escalation",
    );
    expect(resolved.request.successCriteria).toEqual(
      expect.arrayContaining([
        AUTONOMOUS_EXPLOIT_VALIDATION_SUCCESS_CRITERION,
        AUTONOMOUS_SESSION_IDENTITY_SUCCESS_CRITERION,
        AUTONOMOUS_USER_ACCESS_PROOF_SUCCESS_CRITERION,
        AUTONOMOUS_PRIVILEGE_SUCCESS_CRITERION,
        AUTONOMOUS_ROOT_ACCESS_PROOF_SUCCESS_CRITERION,
        AUTONOMOUS_SESSION_CLEANUP_SUCCESS_CRITERION,
      ]),
    );
    expect(resolved.request.contract.evidenceRequirements).toEqual(
      expect.arrayContaining([
        "exploit_validation_result",
        "session_command_outcome",
        "privilege_access_proof",
      ]),
    );
    expect(resolved.policyMatrix.autonomousLaunchReady).toBe(false);
    expect(resolved.policyMatrix.launchBlockingReasons.join(" ")).toContain(
      "Full Authorized Lab Compromise preset requires this class",
    );
  });

  test("keeps HTB Web Full Path exact and non-launchable without every attested full-path binding", () => {
    const manifests = exactIpRuntimeManifests();
    const modelAssignmentCalls: unknown[] = [];
    const htb = new MissionIntakeService({
      readRuntimeManifests: () => ({
        ...manifests,
        tools: manifests.tools.map((tool) => ({
          ...tool,
          actionClassIds: tool.actionClassIds.filter(
            (actionClassId) => actionClassId !== "exploit_validation",
          ),
        })),
      }),
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
      modelConfigurations: {
        resolveAutonomousAssignments(input) {
          modelAssignmentCalls.push(input);
          return {
            observedAt: "2026-07-16T12:00:00.000Z",
            selections: [...input.specialistAgentIds]
              .sort((left, right) => left.localeCompare(right))
              .map((agentId) => ({
                agentId,
                primaryConfigurationId: `modelcfg_ready_${agentId}`,
                fallbackConfigurationId: null,
              })),
            receipts: [],
          };
        },
      },
    });
    const resolved = htb.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      templateId: "htb_web_full_path",
      environmentClassification: "htb",
    });
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Expected Autonomous request");
    }

    expect(resolved.autonomousOutcome?.id).toBe("complete_engagement");
    expect(resolved.request.contract.outcomeProfile)
      .toBe("complete_engagement");
    expect(resolved.request.contract.allowedActionClasses).toEqual([
      "active_host_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
      "web_crawling_page_capture",
      "web_content_endpoint_discovery_fuzzing",
      "vulnerability_configuration_assessment",
      "cve_intelligence_applicability_validation",
      "exploit_validation",
      "command_session_execution",
      "privilege_escalation",
      "data_access_impact_validation",
      "cleanup_restoration",
    ]);
    expect(resolved.request.contract.allowedActionClasses).toContain(
      "command_session_execution",
    );
    expect(resolved.request.contract.allowedActionClasses).toContain(
      "privilege_escalation",
    );
    expect(modelAssignmentCalls).toHaveLength(1);
    const modelAssignmentCall = modelAssignmentCalls[0] as {
      readonly requiredActionClassIds: readonly (typeof ACTION_CLASS_IDS)[number][];
    };
    const signedAllowedActionClasses =
      resolved.request.contract.allowedActionClasses;
    const enforcementReadySignedActionClassIds = ACTION_CLASS_IDS.filter(
      (actionClassId) =>
        signedAllowedActionClasses.includes(actionClassId)
        && resolved.policyMatrix.classes[actionClassId].capability
          .enforcementReady,
    );
    expect(modelAssignmentCall.requiredActionClassIds).toEqual(
      enforcementReadySignedActionClassIds,
    );
    expect(modelAssignmentCall.requiredActionClassIds).not.toContain(
      "exploit_validation",
    );
    expect(resolved.policyMatrix.classes.exploit_validation.capability.enforcementReady)
      .toBe(false);
    expect(resolved.request.contract.allowedActionClasses).toContain(
      "exploit_validation",
    );
    expect(resolved.request.successCriteria.slice(
      -AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA.length,
    )).toEqual([...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA]);
    expect(resolved.request.successCriteria).not.toEqual(
      expect.arrayContaining([
        "Any validation result is classified only from independent custody-verified target-impact evidence, never process output alone.",
        "User and root objectives are proven with independent identity observations and hash-only flag receipts.",
      ]),
    );
    expect(resolved.policyMatrix.autonomousLaunchReady).toBe(false);
    expect(resolved.policyMatrix.launchBlockingReasons.join(" ")).toContain(
      "selected HTB Web Full Path preset requires this class",
    );
  });

  test("does not silently reduce the generated HTB full-path objective when post-exploit classes are prohibited", () => {
    const manifests = exactIpRuntimeManifests();
    const assessment = new MissionIntakeService({
      readRuntimeManifests: () => manifests,
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
    });
    const assessmentActionClasses = new Set([
      "active_host_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
      "web_crawling_page_capture",
      "web_content_endpoint_discovery_fuzzing",
      "vulnerability_configuration_assessment",
      "cve_intelligence_applicability_validation",
      "exploit_validation",
    ]);
    const actionPolicyOverrides = Object.fromEntries(
      ACTION_CLASS_IDS.map((actionClassId) => [
        actionClassId,
        assessmentActionClasses.has(actionClassId)
          ? "pre_authorized"
          : "prohibited",
      ]),
    ) as Record<
      (typeof ACTION_CLASS_IDS)[number],
      "pre_authorized" | "prohibited"
    >;

    const resolved = assessment.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      templateId: "htb_web_full_path",
      environmentClassification: "htb",
      actionPolicyOverrides,
    });
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Expected Autonomous request");
    }

    expect(resolved.request.contract.allowedActionClasses).toEqual([
      "active_host_discovery",
      "port_service_enumeration",
      "os_technology_fingerprinting",
      "web_crawling_page_capture",
      "web_content_endpoint_discovery_fuzzing",
      "vulnerability_configuration_assessment",
      "cve_intelligence_applicability_validation",
      "exploit_validation",
    ]);
    expect(resolved.request.successCriteria).toEqual([
      "The exact approved host has one verified bounded liveness result",
      "The exact approved host has one verified result for the reviewed TCP port set",
      "Every responding derived HTTP origin has one verified bounded technology fingerprint result",
      "Every HTTP origin derived from the verified TCP baseline has one verified bounded metadata result",
      "Every responding derived HTTP origin has one verified bounded endpoint-discovery result",
      "Every responding HTTP origin derived from verified current-run evidence has one completed bounded read-only vulnerability and configuration assessment",
      "Every verified service product/version observation has one conservative, authoritative-source-backed CVE applicability assessment",
      ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
    ]);
    expect(resolved.inferredFields).toContain("successCriteria");
    expect(resolved.limitations.join(" ")).toContain(
      "will not silently reduce this mission to reconnaissance",
    );
    expect(resolved.policyMatrix.classes.exploit_validation.policyState)
      .toBe("pre_authorized");
    expect(resolved.policyMatrix.classes.command_session_execution.policyState)
      .toBe("prohibited");
    expect(resolved.policyMatrix.classes.data_access_impact_validation.policyState)
      .toBe("prohibited");
    expect(resolved.policyMatrix.classes.privilege_escalation.policyState)
      .toBe("prohibited");
    expect(resolved.policyMatrix.classes.cleanup_restoration.policyState)
      .toBe("prohibited");
  });

  test("preserves explicit user and root objectives as canonical terminal criteria instead of silently completing recon", () => {
    const intake = new MissionIntakeService({
      readRuntimeManifests: exactIpRuntimeManifests,
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
    });
    const resolved = intake.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      objective:
        "Map the approved host, prove user/root access, and capture both flags.",
      successCriteria: [
        "The approved host has an evidence-backed service inventory",
      ],
    });
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Expected Autonomous request");
    }

    expect(resolved.request.successCriteria).toEqual([
      "The approved host has an evidence-backed service inventory",
      ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
    ]);
    expect(resolved.inferredFields).toContain("successCriteria");
    expect(resolved.limitations).toEqual(expect.arrayContaining([
      expect.stringContaining(
        "Ti-Scale added the matching evidence-backed success criteria",
      ),
      expect.stringContaining("will not silently reduce this mission to reconnaissance"),
    ]));
    expect(resolved.limitations.join(" ")).toContain(
      "command_session_execution",
    );
    expect(resolved.limitations.join(" ")).toContain("privilege_escalation");
  });

  test("does not infer execution outcomes from an explicitly prohibited exploit or access clause", () => {
    const intake = new MissionIntakeService({
      readRuntimeManifests: exactIpRuntimeManifests,
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
    });
    const resolved = intake.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      objective:
        "Identify exploitable services, but do not execute exploitation or attempt user/root access.",
    });
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Expected Autonomous request");
    }

    expect(resolved.request.successCriteria).not.toEqual(
      expect.arrayContaining([
        ...AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
      ]),
    );
    expect(resolved.limitations.join(" ")).not.toContain(
      "will not silently reduce this mission to reconnaissance",
    );
  });

  test("preserves an explicit operator action-class override outside inferred defaults", () => {
    const resolved = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      actionPolicyOverrides: { cve_intelligence_applicability_validation: "pre_authorized" },
    });
    if (resolved.request.journey !== "autonomous") throw new Error("Expected Autonomous request");
    expect(resolved.request.contract.allowedActionClasses).toContain(
      "cve_intelligence_applicability_validation",
    );
    expect(resolved.policyMatrix.classes.cve_intelligence_applicability_validation.policySource).toBe(
      "operator_override",
    );
  });

  test("defaults only supported evidence while preserving explicit operator requirements", () => {
    const manifests = completeRuntimeManifests();
    const supportedEvidenceTypeIds = [
      "asset_discovery_proof",
      "port_service_scan_result",
    ] as const;
    const constrained = new MissionIntakeService({
      readRuntimeManifests: () => ({
        ...manifests,
        evidenceKinds: manifests.evidenceKinds.map((item) => ({
          ...item,
          evidenceTypeIds: supportedEvidenceTypeIds,
        })),
        tools: manifests.tools.map((item) => ({
          ...item,
          evidenceTypeIds: supportedEvidenceTypeIds,
        })),
      }),
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
    });

    const snapshot = constrained.snapshot();
    expect(snapshot.templates.templates.safe_recon.recommendedEvidenceTypeIds).toEqual(
      supportedEvidenceTypeIds,
    );
    expect(snapshot.evidenceTypes.types.os_platform_fingerprint.capability.availability).toBe(
      "unsupported",
    );
    const resolved = constrained.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
    });
    expect(resolved.evidenceTypeIds).toEqual(supportedEvidenceTypeIds);

    const explicit = constrained.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      evidenceTypeIds: ["os_platform_fingerprint"],
    });
    expect(explicit.evidenceTypeIds).toEqual(["os_platform_fingerprint"]);
  });

  test("resolves minimal Guided intake without forcing the Autonomous contract form", () => {
    const resolved = service.resolve({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "https://portal.example.test" }],
      templateId: "external_web_assessment",
    });

    expect(resolved.request.journey).toBe("guided");
    if (resolved.request.journey !== "guided") throw new Error("Expected Guided request");
    expect(resolved.request.target).toBe("https://portal.example.test");
    expect(resolved.request.title).toContain("External Web Assessment");
    expect(resolved.request.explanationDepth).toBe("balanced");
    expect(resolved.request.executionPreference).toBe("manual");
    expect(resolved.inferredFields).not.toContain("memoryScopes");
  });

  test("adds engagement-isolated memory only when an explicit engagement is supplied", () => {
    const resolved = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.0/24" }],
      engagementId: "eng-authorized-lab",
    });

    if (resolved.request.journey !== "autonomous") throw new Error("Expected Autonomous request");
    expect(resolved.request.contract.memoryScopes).toEqual([
      "confirmed_preferences",
      "verified_lessons",
      "confirmed_attack_knowledge",
      "verified_attack_knowledge",
      "engagement_memory",
    ]);
  });

  test("templates preserve exact supplied target scope", () => {
    const resolved = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [
        { value: "portal.example.test" },
        { value: "admin.example.test", excluded: true },
      ],
      templateId: "external_web_assessment",
    });
    if (resolved.request.journey !== "autonomous") throw new Error("Expected Autonomous request");
    expect(resolved.request.authorization.allowedTargets).toEqual(["portal.example.test"]);
    expect(resolved.request.authorization.prohibitedTargets).toEqual(["admin.example.test"]);
  });

  test("rejects missing authorization and targets with actionable issues", () => {
    expect(() => service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: false,
      targets: [],
    })).toThrow(MissionIntakeValidationError);
    try {
      service.resolve({ journey: "autonomous", authorizationAcknowledged: true, targets: [] });
    } catch (error) {
      expect(error).toBeInstanceOf(MissionIntakeValidationError);
      expect((error as MissionIntakeValidationError).issues[0]).toContain("target");
    }
  });

  test("fails closed when no runtime manifest is connected", () => {
    const unavailable = new MissionIntakeService({
      clock: () => new Date("2026-07-16T12:00:00.000Z"),
    });
    const snapshot = unavailable.snapshot();
    expect(snapshot.source.status).toBe("unavailable");
    expect(snapshot.actionClasses.autonomousLaunchReady).toBe(false);
    const resolved = unavailable.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "lab:authorized" }],
    });
    expect(resolved.limitations.join(" ")).toContain("No attested runtime capability manifest");
    expect(resolved.limitations.join(" ")).toContain("No target-compatible reviewed outcome producer");
    expect(resolved.limitations).toHaveLength(2);
    expect(resolved.policyMatrix.autonomousLaunchReady).toBe(false);
    expect(Object.values(resolved.policyMatrix.classes).every(
      ({ policyState }) => policyState !== "pre_authorized",
    )).toBe(true);
  });

  test("allows bounded destructive policy only for an exact normalized disposable lab target", () => {
    const base = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "lab:customer-portal-sandbox" }],
    });
    const labTarget = base.normalizedTargets[0];
    expect(labTarget?.type).toBe("lab_environment");
    const resolved = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "lab:customer-portal-sandbox" }],
      destructivePolicy: "bounded_lab_only",
      boundedDestructiveTargetIds: [labTarget!.id],
    });
    if (resolved.request.journey !== "autonomous") throw new Error("Expected Autonomous request");
    expect(resolved.request.contract.boundedDestructiveTargets).toEqual(["lab:customer-portal-sandbox"]);
  });

  test("preserves an HTB IP as a host while allowing an explicit exact disposable-lab binding", () => {
    const base = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      environmentClassification: "htb",
      targets: [{ value: "10.129.39.191" }],
    });
    const host = base.normalizedTargets[0]!;
    expect(host.type).toBe("host");

    const resolved = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      environmentClassification: "htb",
      targets: [{ value: "10.129.39.191" }],
      destructivePolicy: "bounded_lab_only",
      boundedDestructiveTargetIds: [host.id],
      actionPolicyOverrides: { exploit_validation: "pre_authorized" },
      memoryScopes: ["verified_attack_knowledge"],
    });
    if (resolved.request.journey !== "autonomous") throw new Error("Expected Autonomous request");
    expect(resolved.normalizedTargets[0]?.type).toBe("host");
    expect(resolved.request.authorization.environmentClassification).toBe("htb");
    expect(resolved.request.contract.boundedDestructiveTargets).toEqual(["10.129.39.191"]);
    expect(resolved.request.contract.allowedActionClasses).toContain("exploit_validation");
  });

  test("rejects an exact ordinary host as a bounded lab-only target", () => {
    for (const environmentClassification of ["client_or_public", "internal"] as const) {
      const base = service.resolve({
        journey: "autonomous",
        authorizationAcknowledged: true,
        environmentClassification,
        targets: [{ value: "10.129.39.191" }],
      });
      expect(() => service.resolve({
        journey: "autonomous",
        authorizationAcknowledged: true,
        environmentClassification,
        targets: [{ value: "10.129.39.191" }],
        destructivePolicy: "bounded_lab_only",
        boundedDestructiveTargetIds: [base.normalizedTargets[0]!.id],
      })).toThrow("explicitly classified as non-disposable");
    }
  });

  test("rejects bounded destructive policy without a named disposable lab target", () => {
    const base = service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.0/24" }],
    });
    expect(() => service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.0/24" }],
      destructivePolicy: "bounded_lab_only",
      boundedDestructiveTargetIds: [base.normalizedTargets[0]!.id],
    })).toThrow("is not an exact host or disposable lab target");
    expect(() => service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "lab:customer-portal-sandbox" }],
      destructivePolicy: "bounded_lab_only",
    })).toThrow("Named disposable lab targets are required");
  });

  test("rejects stale bounded targets when the destructive policy is not bounded", () => {
    expect(() => service.resolve({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "lab:customer-portal-sandbox" }],
      destructivePolicy: "prohibited",
      boundedDestructiveTargetIds: ["target_stale"],
    })).toThrow("only with the bounded lab-only destructive policy");
  });

  test("all free-text intake fields have a useful example", () => {
    const fields = service.snapshot().fields;
    expect(fields.length).toBeGreaterThan(0);
    for (const field of fields) {
      expect(field.purpose.trim().length).toBeGreaterThan(20);
      expect(field.example.trim().length).toBeGreaterThan(5);
    }
  });
});

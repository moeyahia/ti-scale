import { describe, expect, test } from "bun:test";
import { MissionIntakeValidationError, validateMissionIntakeRequest } from "../../../server/intake";

describe("mission intake validation", () => {
  test("accepts only authorization, target, and journey", () => {
    expect(validateMissionIntakeRequest({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "lab:authorized" }],
    })).toEqual({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "lab:authorized" }],
    });
  });

  test("rejects unknown registry values before resolution", () => {
    expect(() => validateMissionIntakeRequest({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      templateId: "invented-template",
      actionPolicyOverrides: { invented_action: "pre_authorized" },
    })).toThrow(MissionIntakeValidationError);
  });

  test("accepts structured advanced policy values", () => {
    const result = validateMissionIntakeRequest({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "lab:target", type: "lab_environment" }],
      templateId: "safe_recon",
      budgetPresetId: "quick",
      destructivePolicy: "validate_without_executing",
      actionPolicyOverrides: { active_host_discovery: "guided_only" },
    });
    expect(result.budgetPresetId).toBe("quick");
    expect(result.actionPolicyOverrides?.active_host_discovery).toBe("guided_only");
  });

  test("accepts deterministic partial model overrides and rejects ambiguous assignment authority", () => {
    expect(validateMissionIntakeRequest({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      agentModelAssignments: [
        {
          agentId: "VulnIntel",
          primaryConfigurationId: "modelcfg_vuln",
          fallbackConfigurationId: null,
        },
        {
          agentId: "ReconScout",
          primaryConfigurationId: "modelcfg_recon",
          fallbackConfigurationId: "modelcfg_recon_fallback",
        },
      ],
    }).agentModelAssignments).toEqual([
      {
        agentId: "ReconScout",
        primaryConfigurationId: "modelcfg_recon",
        fallbackConfigurationId: "modelcfg_recon_fallback",
      },
      {
        agentId: "VulnIntel",
        primaryConfigurationId: "modelcfg_vuln",
        fallbackConfigurationId: null,
      },
    ]);

    const invalidAssignments: unknown[] = [
      [{
        agentId: "ReconScout",
        primaryConfigurationId: "modelcfg_recon",
      }],
      [{
        agentId: "ReconScout",
        primaryConfigurationId: "modelcfg_recon",
        fallbackConfigurationId: "modelcfg_recon",
      }],
      [
        {
          agentId: "ReconScout",
          primaryConfigurationId: "modelcfg_recon",
          fallbackConfigurationId: null,
        },
        {
          agentId: "ReconScout",
          primaryConfigurationId: "modelcfg_other",
          fallbackConfigurationId: null,
        },
      ],
      [{
        agentId: "ReconScout",
        primaryConfigurationId: "modelcfg_recon",
        fallbackConfigurationId: null,
        preferenceId: "mutable-authority-is-not-signed",
      }],
    ];
    for (const agentModelAssignments of invalidAssignments) {
      expect(() => validateMissionIntakeRequest({
        journey: "autonomous",
        authorizationAcknowledged: true,
        targets: [{ value: "10.10.10.10" }],
        agentModelAssignments,
      })).toThrow(MissionIntakeValidationError);
    }
    expect(() => validateMissionIntakeRequest({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      agentModelAssignments: [{
        agentId: "ReconScout",
        primaryConfigurationId: "modelcfg_recon",
        fallbackConfigurationId: null,
      }],
    })).toThrow(MissionIntakeValidationError);
  });

  test("keeps Autonomous plan construction separate, closed, and authority-free", () => {
    const providerSelection = {
      route: "provider_advisory",
      agentId: "Commander",
      primaryConfigurationId: "modelcfg_planning_primary",
      fallbackConfigurationId: "modelcfg_planning_fallback",
      enforcementMode: "advisor_only",
      disclosureClass: "sanitized_internal",
      executionAuthority: "none",
    } as const;
    expect(validateMissionIntakeRequest({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      planningSelection: providerSelection,
    }).planningSelection).toEqual(providerSelection);

    const invalidSelections: unknown[] = [
      {
        ...providerSelection,
        enforcementMode: "enforced_executor",
      },
      {
        ...providerSelection,
        executionAuthority: "tools",
      },
      {
        ...providerSelection,
        disclosureClass: "secret",
      },
      {
        ...providerSelection,
        fallbackConfigurationId: providerSelection.primaryConfigurationId,
      },
      {
        ...providerSelection,
        toolAllowlist: ["execute_terminal"],
      },
    ];
    for (const planningSelection of invalidSelections) {
      expect(() => validateMissionIntakeRequest({
        journey: "autonomous",
        authorizationAcknowledged: true,
        targets: [{ value: "10.10.10.10" }],
        planningSelection,
      })).toThrow(MissionIntakeValidationError);
    }
    expect(() => validateMissionIntakeRequest({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.10.10.10" }],
      planningSelection: providerSelection,
    })).toThrow(MissionIntakeValidationError);
  });

  test("accepts a closed Autonomous environment classification and rejects unknown or Guided values", () => {
    expect(validateMissionIntakeRequest({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.129.39.191" }],
      environmentClassification: "htb",
    }).environmentClassification).toBe("htb");
    expect(() => validateMissionIntakeRequest({
      journey: "autonomous",
      authorizationAcknowledged: true,
      targets: [{ value: "10.129.39.191" }],
      environmentClassification: "production_like",
    })).toThrow(MissionIntakeValidationError);
    expect(() => validateMissionIntakeRequest({
      journey: "guided",
      authorizationAcknowledged: true,
      targets: [{ value: "10.129.39.191" }],
      environmentClassification: "htb",
    })).toThrow(MissionIntakeValidationError);
  });
});

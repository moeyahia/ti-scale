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
});

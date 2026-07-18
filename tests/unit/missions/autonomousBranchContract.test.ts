import { describe, expect, test } from "bun:test";
import { MissionIntakeService } from "../../../server/intake";
import type { AutonomousMissionRequest } from "../../../src/domain/types/commandOs";
import type { IntakeRegistrySnapshot } from "../../../src/domain/types/intake";
import {
  projectAutonomousRegistryFields,
  registryFieldsFromAutonomousRequest,
} from "../../../src/features/missions/autonomousBranchContract";

function requestWith(
  contract: Partial<AutonomousMissionRequest["contract"]>,
): AutonomousMissionRequest {
  return {
    journey: "autonomous",
    launch: true,
    title: "Registry projection fixture",
    objective: "Verify that a versioned branch uses only the current structured contract registry.",
    successCriteria: ["The projected successor contract retains exact authority."],
    authorization: {
      allowedTargets: ["lab:registry-projection"],
      prohibitedTargets: [],
      authorizationConfirmed: true,
    },
    contract: {
      allowedActionClasses: [],
      prohibitedActionClasses: [],
      destructivePolicy: "prohibited",
      boundedDestructiveTargets: [],
      evidenceRequirements: [],
      timeBudgetMinutes: 30,
      tokenBudget: 10_000,
      costBudget: 1,
      retryBudget: 1,
      replanBudget: 1,
      concurrencyLimit: 1,
      evidenceStorageBudgetBytes: 1024 ** 2,
      artifactStorageBudgetBytes: 1024 ** 2,
      notificationPolicy: "in_app_only",
      reportingFormat: "ti_scale_json",
      dataHandlingPolicy: "local_private",
      retentionPolicy: "operator_managed",
      providerPolicy: "automatic_enforcing_only",
      toolPolicy: "contract_allowlist",
      specialistAgentIds: [],
      memoryScopes: [],
      contextNodeIds: [],
      safeStopConditions: [],
      deliverables: [],
      ...contract,
    },
  };
}

describe("Autonomous branch structured contract projection", () => {
  test("reconciles IDs and labels, preserves historical unknowns, and emits canonical registry IDs", () => {
    const registry = new MissionIntakeService().snapshot("autonomous", "custom") as unknown as IntakeRegistrySnapshot;
    const actions = Object.values(registry.actionClasses.classes);
    const evidence = Object.values(registry.evidenceTypes.types);
    const optionalStops = registry.safeStops.optional;
    const deliverables = Object.values(registry.deliverables.deliverables);
    const source = requestWith({
      allowedActionClasses: [actions[0]!.id, "historical_allowed_action"],
      prohibitedActionClasses: [actions[1]!.label, "historical_prohibited_action"],
      evidenceRequirements: [evidence[0]!.label, "historical_evidence_rule"],
      safeStopConditions: [optionalStops[0]!.label, registry.safeStops.mandatory[0]!.id],
      deliverables: [deliverables[0]!.label, "historical_deliverable"],
    });

    const fields = registryFieldsFromAutonomousRequest(source, registry);
    expect(fields.actionPolicyStates[actions[0]!.id]).toBe("pre_authorized");
    expect(fields.actionPolicyStates[actions[1]!.id]).toBe("prohibited");
    expect(fields.actionPolicyStates[actions[2]!.id]).toBe("inherited_default");
    expect(fields.evidenceTypeIds).toEqual([evidence[0]!.id]);
    expect(fields.optionalSafeStopIds).toEqual([optionalStops[0]!.id]);
    expect(fields.deliverableIds).toEqual([deliverables[0]!.id]);
    expect(fields.unmatchedAllowedActionClasses).toEqual(["historical_allowed_action"]);
    expect(fields.unmatchedProhibitedActionClasses).toEqual(["historical_prohibited_action"]);
    expect(fields.unmatchedSafeStopConditions).toEqual([registry.safeStops.mandatory[0]!.id]);

    const projected = projectAutonomousRegistryFields({
      ...fields,
      actionPolicyStates: {
        ...fields.actionPolicyStates,
        [actions[0]!.id]: "guided_only",
        [actions[1]!.id]: "pre_authorized",
      },
    }, registry);
    expect(projected.allowedActionClasses).toContain(actions[1]!.id);
    expect(projected.allowedActionClasses).toContain("historical_allowed_action");
    expect(projected.allowedActionClasses).not.toContain(actions[0]!.id);
    expect(projected.prohibitedActionClasses).toContain(actions[0]!.id);
    expect(projected.prohibitedActionClasses).toContain("historical_prohibited_action");
    expect(projected.evidenceRequirements).toEqual([evidence[0]!.id, "historical_evidence_rule"]);
    expect(projected.safeStopConditions).toEqual([optionalStops[0]!.id, registry.safeStops.mandatory[0]!.id]);
    expect(projected.deliverables).toEqual([deliverables[0]!.id, "historical_deliverable"]);
  });

  test("never introduces mandatory platform stops as removable mission-specific selections", () => {
    const registry = new MissionIntakeService().snapshot("autonomous", "custom") as unknown as IntakeRegistrySnapshot;
    const fields = registryFieldsFromAutonomousRequest(requestWith({}), registry);
    expect(fields.optionalSafeStopIds).toEqual([]);
    expect(fields.unmatchedSafeStopConditions).toEqual([]);
    expect(projectAutonomousRegistryFields(fields, registry).safeStopConditions).toEqual([]);
    expect(registry.safeStops.mandatory.every((stop) => stop.userRemovable === false)).toBe(true);
  });
});

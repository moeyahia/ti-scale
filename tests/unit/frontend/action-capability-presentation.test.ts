import { describe, expect, test } from "bun:test";
import type { IntakeActionClass } from "../../../src/domain/types/intake";
import { actionCapabilityPresentation } from "../../../src/features/missions/actionCapabilityPresentation";

function action(
  availability: IntakeActionClass["capability"]["availability"],
  enforcementReady = false,
): IntakeActionClass {
  return {
    id: "active_host_discovery",
    label: "Active host discovery",
    plainLanguageDescription: "Check which approved hosts respond.",
    technicalDescription: "Run an approved liveness probe.",
    riskBand: "low",
    likelySideEffects: [],
    defaultPolicyState: "guided_only",
    defaultEvidenceTypeIds: [],
    destructiveOrDisruptive: false,
    policyState: "guided_only",
    policySource: "platform_default",
    capability: {
      availability,
      riskClassIds: ["network"],
      agentIds: ["recon-scout"],
      availableAgentIds: availability === "supported" ? ["recon-scout"] : [],
      toolIds: ["kali:ping-host-liveness"],
      availableToolIds: availability === "supported" ? ["kali:ping-host-liveness"] : [],
      mcpServerIds: [],
      providerModelRefs: [],
      enforcedProviderModelRefs: [],
      locallyEnforcedToolIds: enforcementReady ? ["kali:ping-host-liveness"] : [],
      evidenceTypeIds: ["host_asset_discovery_proof"],
      enforcementReady,
      readinessReasons: [],
    },
    launchBlockingReasons: [],
  };
}

describe("action capability presentation", () => {
  test("calls an absent implementation not implemented", () => {
    expect(actionCapabilityPresentation(action("unsupported"), "autonomous"))
      .toMatchObject({ label: "Not implemented" });
  });

  test("calls a registered but unhealthy path temporarily unavailable", () => {
    expect(actionCapabilityPresentation(action("unavailable"), "autonomous"))
      .toMatchObject({ label: "Temporarily unavailable" });
  });

  test("distinguishes a Guided mapping from an Autonomous executor", () => {
    const mapped = action("supported", false);
    expect(actionCapabilityPresentation(mapped, "autonomous"))
      .toMatchObject({ label: "Guided path only" });
    expect(actionCapabilityPresentation(mapped, "guided"))
      .toMatchObject({ label: "Guided mapping available" });
  });

  test("labels a reviewed Autonomous executor accurately", () => {
    expect(actionCapabilityPresentation(action("supported", true), "autonomous"))
      .toMatchObject({ label: "Autonomous-ready" });
  });
});

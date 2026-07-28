import { describe, expect, test } from "bun:test";

import {
  buildResolvedContractChecklist,
  checklistSourceLabel,
} from "../../../src/features/missions/missionIntakeChecklist";
import type {
  IntakeRegistrySnapshot,
  ResolvedMissionIntake,
} from "../../../src/domain/types/intake";

function fixture(): {
  readonly resolved: ResolvedMissionIntake;
  readonly registry: IntakeRegistrySnapshot;
} {
  const resolved = {
    policyMatrix: {
      classes: {
        recon: {
          id: "recon",
          label: "Reachability checks",
          policyState: "pre_authorized",
          policySource: "preset",
        },
        exploit: {
          id: "exploit",
          label: "Exploit validation",
          policyState: "guided_only",
          policySource: "operator_override",
        },
        destroy: {
          id: "destroy",
          label: "Destructive modification",
          policyState: "prohibited",
          policySource: "platform_default",
        },
      },
    },
    deliverableIds: ["technical_findings", "unregistered_legacy_export"],
    evidenceTypeIds: ["service_version_fingerprint"],
    mandatorySafeStopIds: ["scope_violation"],
    optionalSafeStopIds: ["target_unreachable"],
    budget: {
      label: "Standard",
      timeBudgetMinutes: 120,
      toolCallBudget: 400,
    },
    inferredFields: ["evidenceRequirements", "budget"],
  } as unknown as ResolvedMissionIntake;
  const registry = {
    deliverables: {
      deliverables: {
        technical_findings: { label: "Technical findings" },
      },
    },
    evidenceTypes: {
      types: {
        service_version_fingerprint: { label: "Service and version fingerprint" },
      },
    },
    safeStops: {
      mandatory: [{ id: "scope_violation", label: "Target outside scope" }],
      optional: [{ id: "target_unreachable", label: "Target became unreachable" }],
    },
  } as unknown as IntakeRegistrySnapshot;
  return { resolved, registry };
}

describe("resolved mission operating-contract checklist", () => {
  test("uses exact normalized selections and exposes their source", () => {
    const { resolved, registry } = fixture();
    const checklist = buildResolvedContractChecklist(resolved, registry);

    expect(checklist.actionPolicy.source).toBe("operator_selection");
    expect(checklist.actionPolicy.groups).toEqual([
      {
        state: "pre_authorized",
        label: "Pre-authorized",
        items: [{ id: "recon", label: "Reachability checks" }],
      },
      {
        state: "guided_only",
        label: "Guided only / not autonomous",
        items: [{ id: "exploit", label: "Exploit validation" }],
      },
      {
        state: "prohibited",
        label: "Prohibited",
        items: [{ id: "destroy", label: "Destructive modification" }],
      },
    ]);
    expect(checklist.deliverables).toEqual({
      source: "operator_selection",
      items: [
        { id: "technical_findings", label: "Technical findings" },
        { id: "unregistered_legacy_export", label: "unregistered_legacy_export" },
      ],
    });
    expect(checklist.evidence).toEqual({
      source: "recommended_default",
      items: [{ id: "service_version_fingerprint", label: "Service and version fingerprint" }],
    });
    expect(checklist.optionalSafeStops.source).toBe("operator_selection");
    expect(checklist.mandatorySafeStops).toEqual({
      source: "platform_invariant",
      items: [{ id: "scope_violation", label: "Target outside scope" }],
    });
    expect(checklist.budget).toEqual({
      source: "recommended_default",
      label: "Standard · 120 min · 400 tool calls",
    });
  });

  test("renders source language without implying operator authorship", () => {
    expect(checklistSourceLabel("recommended_default")).toBe("Recommended default");
    expect(checklistSourceLabel("operator_selection")).toBe("Operator selected");
    expect(checklistSourceLabel("platform_invariant")).toBe("Always enforced");
  });
});

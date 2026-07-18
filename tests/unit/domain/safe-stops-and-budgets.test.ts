import { describe, expect, test } from "bun:test";
import {
  MANDATORY_PLATFORM_SAFE_STOPS,
  MISSION_BUDGET_PRESETS,
  OPTIONAL_MISSION_SAFE_STOPS,
  SAFE_STOP_DEFINITIONS,
  missionBudgetPreset,
} from "../../../server/domain";
import {
  MISSION_TEMPLATE_IDS,
  buildMissionTemplateRegistry,
} from "../../../server/domain/mission-template-registry";
import { buildRuntimeCapabilityProjection } from "../../../server/domain/source-manifest-adapters";
import { completeRuntimeManifests } from "./fixtures";

describe("safe-stop and budget registries", () => {
  test("keeps platform stops mandatory and operator options removable", () => {
    expect(MANDATORY_PLATFORM_SAFE_STOPS.every((item) => item.mandatory && !item.userRemovable)).toBe(true);
    expect(OPTIONAL_MISSION_SAFE_STOPS.every((item) => !item.mandatory && item.userRemovable)).toBe(true);
    expect(new Set(SAFE_STOP_DEFINITIONS.map(({ id }) => id)).size).toBe(SAFE_STOP_DEFINITIONS.length);
  });

  test("every template recommendation resolves to an optional registered stop", () => {
    const registry = buildMissionTemplateRegistry(
      buildRuntimeCapabilityProjection(completeRuntimeManifests()),
    );
    const optional = new Set(OPTIONAL_MISSION_SAFE_STOPS.map(({ id }) => id));
    for (const templateId of MISSION_TEMPLATE_IDS) {
      for (const id of registry.templates[templateId].recommendedOptionalSafeStops) {
        expect(optional.has(id)).toBe(true);
      }
    }
  });

  test("presets expose bounded operational dimensions and custom starts from Standard", () => {
    expect(MISSION_BUDGET_PRESETS.quick.timeBudgetMinutes).toBeLessThan(MISSION_BUDGET_PRESETS.standard.timeBudgetMinutes);
    expect(MISSION_BUDGET_PRESETS.standard.timeBudgetMinutes).toBeLessThan(MISSION_BUDGET_PRESETS.deep.timeBudgetMinutes);
    for (const value of Object.values(MISSION_BUDGET_PRESETS)) {
      expect(value.retryBudget).toBeLessThanOrEqual(2);
      expect(value.replanBudget).toBeLessThanOrEqual(2);
      expect(value.concurrencyLimit).toBeGreaterThan(0);
      expect(value.maximumArtifactBytes).toBeLessThanOrEqual(value.artifactStorageBudgetBytes);
    }
    expect(missionBudgetPreset("custom")).toBe(MISSION_BUDGET_PRESETS.standard);
  });
});

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { ATTACK_CENTRIC_REUSABLE_NODE_TYPES } from "../../memory/types";
import {
  ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY,
  ATTACK_BRAIN_ATLAS_NODE_TYPES,
  BRAIN_ATLAS_REGIONS,
  OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY,
  assertAttackBrainAtlasMappingRegistryComplete,
  assertOperatorProfileBrainAtlasMappingRegistryComplete,
  operatorProfileBrainAtlasMapping,
} from "../AttackBrainAtlasMappingRegistry";
import {
  generateBrainAtlasConfiguration,
  validateBrainAtlasConfiguration,
} from "../BrainAtlasProfile";
import { BRAIN_ATLAS_PINNED_RELEASE } from "../ObsidianPluginManager";

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

describe("Attack Brain Atlas mapping registry", () => {
  test("maps every canonical reusable attack type exactly once", () => {
    expect(() => assertAttackBrainAtlasMappingRegistryComplete()).not.toThrow();
    expect(new Set(ATTACK_BRAIN_ATLAS_NODE_TYPES)).toEqual(new Set(ATTACK_CENTRIC_REUSABLE_NODE_TYPES));
    expect(ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY).toHaveLength(ATTACK_CENTRIC_REUSABLE_NODE_TYPES.length);
    expect(new Set(ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.map((item) => item.nodeType)).size)
      .toBe(ATTACK_CENTRIC_REUSABLE_NODE_TYPES.length);
    expect(new Set(ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.map((item) => item.region)))
      .toEqual(new Set(BRAIN_ATLAS_REGIONS));
  });

  test("maps only consent-bound Operator Profile identities without admitting operational entities", () => {
    expect(() => assertOperatorProfileBrainAtlasMappingRegistryComplete()).not.toThrow();
    expect(OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY).toHaveLength(3);
    expect(operatorProfileBrainAtlasMapping({ id: "mem_operator_profile", nodeType: "operator" })?.region)
      .toBe("frontal");
    expect(operatorProfileBrainAtlasMapping({ id: "mem_preference_profile", nodeType: "preference" })?.region)
      .toBe("frontal");
    expect(operatorProfileBrainAtlasMapping({ id: "mem_prefdomain_brain_graph", nodeType: "entity" })?.region)
      .toBe("frontal");
    expect(operatorProfileBrainAtlasMapping({ id: "operational-target", nodeType: "target" })).toBeUndefined();
    expect(operatorProfileBrainAtlasMapping({ id: "operational-asset", nodeType: "asset" })).toBeUndefined();
    expect(operatorProfileBrainAtlasMapping({ id: "mem_unrelated_entity", nodeType: "entity" })).toBeUndefined();
  });

  test("deployment profile is generated from the registry and pinned release", () => {
    const data = JSON.parse(readFileSync(resolve("deployment/obsidian/brain-atlas/data.json"), "utf8"));
    const release = JSON.parse(readFileSync(resolve("deployment/obsidian/brain-atlas/release.json"), "utf8"));
    const generated = generateBrainAtlasConfiguration();
    const validation = validateBrainAtlasConfiguration(data);
    expect(validation.registryNodeTypeCount).toBe(ATTACK_CENTRIC_REUSABLE_NODE_TYPES.length);
    expect(validation.operatorProfileMappingCount).toBe(OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY.length);
    expect(validation.kindMappingCount).toBe(
      ATTACK_CENTRIC_REUSABLE_NODE_TYPES.length + OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY.length,
    );
    expect(validation.regionMappingCount).toBe(validation.kindMappingCount);
    expect(data.frontmatterRegionValueMap["operator_profile_class:operator"]).toBe("frontal");
    expect(data.frontmatterRegionValueMap["operator_profile_class:preference"]).toBe("frontal");
    expect(data.frontmatterRegionValueMap["operator_profile_class:application_domain"]).toBe("frontal");
    expect(data.frontmatterRegionValueMap["type:entity"]).toBeUndefined();
    expect(data.frontmatterRegionValueMap["type:target"]).toBeUndefined();
    expect(data.frontmatterRegionValueMap["type:asset"]).toBeUndefined();
    expect(canonical(data)).toBe(canonical(generated));
    expect(canonical(release)).toBe(canonical(BRAIN_ATLAS_PINNED_RELEASE));
  });

  test("reconciles owned mappings without erasing operator visual settings", () => {
    const generated = generateBrainAtlasConfiguration({
      palette: "graphite",
      performancePreset: "balanced",
      pinnedNodePositions: { "41 Attack Vectors/example.md": { x: 1, y: 2, z: 3 } },
      futureSetting: { retained: true },
      frontmatterKindValueMap: {
        "type:attack_vector": "incident",
        "kind:operator_extension": "project",
      },
      frontmatterRegionValueMap: {
        "type:attack_vector": "stem",
        "kind:operator_extension": "temporal",
      },
    }) as Record<string, unknown>;
    expect(generated.palette).toBe("graphite");
    expect(generated.performancePreset).toBe("balanced");
    expect(generated.pinnedNodePositions).toEqual({ "41 Attack Vectors/example.md": { x: 1, y: 2, z: 3 } });
    expect(generated.futureSetting).toEqual({ retained: true });
    expect((generated.frontmatterKindValueMap as Record<string, string>)["type:attack_vector"]).toBe("workThread");
    expect((generated.frontmatterKindValueMap as Record<string, string>)["kind:operator_extension"]).toBe("project");
    expect((generated.frontmatterRegionValueMap as Record<string, string>)["type:attack_vector"]).toBe("frontal");
    expect((generated.frontmatterRegionValueMap as Record<string, string>)["kind:operator_extension"]).toBe("temporal");
    expect(() => validateBrainAtlasConfiguration(generated)).not.toThrow();
  });
});

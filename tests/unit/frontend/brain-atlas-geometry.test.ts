import { describe, expect, test } from "bun:test";
import {
  ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY,
  ATTACK_BRAIN_ATLAS_NODE_TYPES,
  attackBrainAtlasMapping,
} from "../../../shared/AttackBrainAtlasMappingRegistry";
import type { MemoryNodeSummary, MemoryNodeType } from "../../../src/domain/types/brain";
import {
  BRAIN_ATLAS_REGIONS,
  BRAIN_ATLAS_FISSURE_HALF_WIDTH,
  BRAIN_ATLAS_REGION_DEFINITIONS,
  brainAtlasProjection,
  brainAtlasRegionCounts,
  brainAtlasRegionForNode,
  brainAtlasRegionForNodeType,
  buildBrainAtlasCloud,
  buildBrainAtlasGuideSegments,
  graphPointToBrainAtlasPosition,
  projectBrainAtlasPoint,
} from "../../../src/features/brain/brainAtlasGeometry";
import { detectBrainAtlasRenderer, parseBrainAtlasColor } from "../../../src/features/brain/BrainAtlasWebGLRenderer";
import type { GraphPoint } from "../../../src/features/brain/graphUtils";

function node(nodeType: MemoryNodeType, index: number): MemoryNodeSummary {
  return {
    id: `atlas-node-${nodeType}-${index}`,
    nodeType,
    title: `${nodeType} ${index}`,
    summary: "Bounded attack-knowledge atlas fixture",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.95,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    version: 1,
    pinned: false,
    createdAt: "2099-01-01T00:00:00.000Z",
    updatedAt: "2099-01-01T00:00:00.000Z",
    edgeCount: 2,
    sourceCount: 1,
  };
}

function repeated(nodeType: MemoryNodeType, count: number): MemoryNodeSummary[] {
  return Array.from({ length: count }, (_, index) => node(nodeType, index));
}

describe("six-region attack-knowledge brain geometry", () => {
  test("uses the shared Vault mapping as the single authority for all reusable node types", () => {
    expect(ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY).toHaveLength(ATTACK_BRAIN_ATLAS_NODE_TYPES.length);
    for (const mapping of ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY) {
      expect(attackBrainAtlasMapping(mapping.nodeType)).toEqual(mapping);
      expect(brainAtlasRegionForNodeType(mapping.nodeType)).toBe(mapping.region);
    }
  });

  test("places only consent-bound Operator Profile identities in the frontal region", () => {
    expect(brainAtlasRegionForNode(node("operator", 1))).toBe("frontal");
    expect(brainAtlasRegionForNode(node("preference", 1))).toBe("frontal");
    expect(brainAtlasRegionForNode({
      ...node("entity", 1),
      id: "mem_prefdomain_brain_graph",
    })).toBe("frontal");
    expect(brainAtlasRegionForNode(node("entity", 1))).toBe("stem");
    expect(brainAtlasRegionForNode(node("target", 1))).toBe("stem");
    expect(brainAtlasRegionForNode(node("asset", 1))).toBe("stem");
  });

  test("reproduces the audited 68-node six-region migration distribution", () => {
    const migrated = [
      ...repeated("attack_procedure", 3),
      ...repeated("attack_technique", 10),
      ...repeated("attack_vector", 1),
      ...repeated("exact_version_fingerprint", 10),
      ...repeated("framework", 1),
      ...repeated("operating_system", 4),
      ...repeated("runtime", 4),
      ...repeated("technology_product", 3),
      ...repeated("failure_mode", 6),
      ...repeated("operational_hazard", 1),
      ...repeated("recovery_pattern", 1),
      ...repeated("discovery_pattern", 4),
      ...repeated("cve", 1),
      ...repeated("script_artifact", 11),
      ...repeated("health_check", 1),
      ...repeated("topology_pattern", 2),
      ...repeated("topology_role", 3),
      ...repeated("attribute", 2),
    ];
    expect(migrated).toHaveLength(68);
    expect(brainAtlasRegionCounts(migrated)).toEqual({
      frontal: 14,
      parietal: 22,
      temporal: 8,
      occipital: 5,
      cerebellum: 12,
      stem: 7,
    });
  });

  test("builds a deterministic anatomical cloud covering all six regions", () => {
    const first = buildBrainAtlasCloud();
    const second = buildBrainAtlasCloud();
    expect(first).toHaveLength(1_648);
    expect(first).toEqual(second);
    expect(new Set(first.map((point) => point.region))).toEqual(new Set(BRAIN_ATLAS_REGIONS));
    expect(first.every((point) => [point.x, point.y, point.z, point.twinklePhase, point.twinkleFrequency]
      .every(Number.isFinite))).toBe(true);
  });

  test("forms two balanced cerebral hemispheres with a visible sagittal cleft and descending cord", () => {
    const cloud = buildBrainAtlasCloud();
    const cortex = cloud.filter((point) => point.region !== "stem" && point.region !== "cerebellum");
    const left = cortex.filter((point) => point.x < 0);
    const right = cortex.filter((point) => point.x > 0);
    expect(left).toHaveLength(700);
    expect(right).toHaveLength(700);
    expect(Math.min(...cortex.map((point) => Math.abs(point.x)))).toBeGreaterThanOrEqual(BRAIN_ATLAS_FISSURE_HALF_WIDTH);
    expect(Math.min(...left.map((point) => point.x))).toBeLessThan(-0.9);
    expect(Math.max(...right.map((point) => point.x))).toBeGreaterThan(0.9);

    const projection = brainAtlasProjection(900, 600, 1, { x: -0.08, y: 0 });
    const projectedCortex = cortex.map((point) => projectBrainAtlasPoint(projection, point));
    const leftPixels = projectedCortex.filter((point) => point.x < 450);
    const rightPixels = projectedCortex.filter((point) => point.x > 450);
    expect(leftPixels.length).toBeGreaterThan(650);
    expect(rightPixels.length).toBeGreaterThan(650);
    expect(Math.min(...projectedCortex.map((point) => Math.abs(point.x - 450)))).toBeGreaterThan(10);

    const guides = buildBrainAtlasGuideSegments();
    expect(guides.filter((segment) => segment.kind === "hemisphere-outline")).toHaveLength(84);
    expect(guides.filter((segment) => segment.kind === "fissure")).toHaveLength(4);
    const cord = guides.filter((segment) => segment.kind === "spinal-cord");
    expect(cord).toHaveLength(30);
    expect(Math.min(...cord.flatMap((segment) => [segment.from.y, segment.to.y]))).toBeLessThan(-1.4);
  });

  test("mirrors every cortical node region while keeping nodes out of the fissure", () => {
    for (const region of ["frontal", "parietal", "temporal", "occipital", "cerebellum"] as const) {
      expect(BRAIN_ATLAS_REGION_DEFINITIONS[region].mirrored).toBe(true);
    }
    const positions = Array.from({ length: 48 }, (_, index) => {
      const memory = node("attack_technique", index);
      return graphPointToBrainAtlasPosition({
        id: memory.id,
        x: 360 + index,
        y: 240 - index,
        depth: (index % 10) / 10,
        radius: 8,
        cluster: "attack",
      }, memory, 900, 600);
    });
    expect(positions.some((position) => position.x < 0)).toBe(true);
    expect(positions.some((position) => position.x > 0)).toBe(true);
    expect(positions.every((position) => Math.abs(position.x) >= BRAIN_ATLAS_FISSURE_HALF_WIDTH + 0.035)).toBe(true);
  });

  test("projects the same model point through a real rotating perspective camera", () => {
    const memory = node("attack_technique", 1);
    const point: GraphPoint = {
      id: memory.id,
      x: 360,
      y: 240,
      depth: 0.3,
      radius: 8,
      cluster: "attack",
    };
    const model = graphPointToBrainAtlasPosition(point, memory, 900, 600);
    const front = projectBrainAtlasPoint(brainAtlasProjection(900, 600, 1, { x: -0.08, y: 0 }), model);
    const rotated = projectBrainAtlasPoint(brainAtlasProjection(900, 600, 1.4, { x: 0.22, y: 0.8 }), model);
    expect(front.visible).toBe(true);
    expect(rotated.visible).toBe(true);
    expect([rotated.x, rotated.y, rotated.depth, rotated.scale]).not.toEqual([front.x, front.y, front.depth, front.scale]);
  });

  test("parses CSS colors and fails closed to Canvas 2D outside a browser", () => {
    expect(parseBrainAtlasColor("#804020", [0, 0, 0, 0])).toEqual([128 / 255, 64 / 255, 32 / 255, 1]);
    expect(parseBrainAtlasColor("rgba(255, 128, 0, 0.5)", [0, 0, 0, 0])).toEqual([1, 128 / 255, 0, 0.5]);
    expect(parseBrainAtlasColor("not-a-color", [0.1, 0.2, 0.3, 1])).toEqual([0.1, 0.2, 0.3, 1]);
    expect(detectBrainAtlasRenderer()).toBe("canvas2d");
  });
});

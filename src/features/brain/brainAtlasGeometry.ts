/*
 * Anatomical shape and projection principles adapted from Brain Atlas 0.2.1.
 * Copyright (c) 2026 colorpulse6, licensed under MIT.
 * See /THIRD_PARTY_NOTICES.md for the complete notice.
 *
 * Ti-Scale's attack-knowledge taxonomy, typed/directed relationship model,
 * region assignment, accessibility surface, and interaction state are original
 * integration code. This module stays DOM/WebGL-free so both renderers and
 * unit tests use exactly the same six-region geometry.
 */
import type { MemoryNodeSummary, MemoryNodeType } from "../../domain/types/brain";
import {
  ATTACK_BRAIN_ATLAS_NODE_TYPES,
  BRAIN_ATLAS_REGIONS,
  attackBrainAtlasMapping,
  operatorProfileBrainAtlasMapping,
  type AttackBrainAtlasNodeType,
  type BrainAtlasRegion,
} from "../../../shared/AttackBrainAtlasMappingRegistry";
import { BRAIN_CLUSTER_ANCHORS, nodeCluster, type GraphPoint } from "./graphUtils";

export { BRAIN_ATLAS_REGIONS };
export type { BrainAtlasRegion };

export interface BrainAtlasVector3 {
  readonly x: number;
  readonly y: number;
  readonly z: number;
}

export interface BrainAtlasCloudPoint extends BrainAtlasVector3 {
  readonly region: BrainAtlasRegion;
  readonly twinklePhase: number;
  readonly twinkleFrequency: number;
}

export type BrainAtlasGuideKind = "hemisphere-outline" | "fissure" | "spinal-cord";

export interface BrainAtlasGuideSegment {
  readonly from: BrainAtlasVector3;
  readonly to: BrainAtlasVector3;
  readonly kind: BrainAtlasGuideKind;
}

export interface BrainAtlasRegionDefinition {
  readonly center: BrainAtlasVector3;
  readonly radius: number;
  readonly label: string;
  readonly code: string;
  readonly semantic: string;
  readonly mirrored?: boolean;
}

export const BRAIN_ATLAS_REGION_DEFINITIONS: Readonly<Record<BrainAtlasRegion, Readonly<BrainAtlasRegionDefinition>>> = Object.freeze({
  frontal: Object.freeze({ center: Object.freeze({ x: 0.43, y: 0.20, z: 0.52 }), radius: 0.46, label: "Frontal", code: "FRO", semantic: "Attack vectors and procedures", mirrored: true }),
  parietal: Object.freeze({ center: Object.freeze({ x: 0.42, y: 0.50, z: -0.10 }), radius: 0.42, label: "Parietal", code: "PAR", semantic: "Technology and version fingerprints", mirrored: true }),
  temporal: Object.freeze({ center: Object.freeze({ x: 0.65, y: -0.15, z: 0.10 }), radius: 0.32, label: "Temporal", code: "TEM", semantic: "Outcomes, failures, hazards, recovery, and lessons", mirrored: true }),
  occipital: Object.freeze({ center: Object.freeze({ x: 0.40, y: 0.07, z: -0.66 }), radius: 0.34, label: "Occipital", code: "OCC", semantic: "Vulnerabilities, discovery, evidence, and research", mirrored: true }),
  cerebellum: Object.freeze({ center: Object.freeze({ x: 0.30, y: -0.55, z: -0.58 }), radius: 0.29, label: "Cerebellum", code: "CER", semantic: "Procedure versions, scripts, tools, health checks, and remediation", mirrored: true }),
  stem: Object.freeze({ center: Object.freeze({ x: 0, y: -0.86, z: -0.10 }), radius: 0.14, label: "Brain stem", code: "STM", semantic: "Topology, prerequisites, and reusable attributes" }),
});

/** A real empty sagittal cleft remains visible even before guides are drawn. */
export const BRAIN_ATLAS_FISSURE_HALF_WIDTH = 0.075;

const REUSABLE_ATTACK_NODE_TYPES = new Set<string>(ATTACK_BRAIN_ATLAS_NODE_TYPES);

// Compatibility placement for legacy/provenance nodes. Reusable attack-memory
// types never use this table: their authoritative region comes from the shared
// registry that also drives the native Vault projection.
const NON_REUSABLE_REGION: Readonly<Partial<Record<MemoryNodeType, BrainAtlasRegion>>> = Object.freeze({
  tactic: "frontal",
  technique: "frontal",
  procedure: "frontal",
  decision: "frontal",
  evidence: "occipital",
  finding: "occipital",
  artifact: "occipital",
  report: "occipital",
  source: "occipital",
  tool: "cerebellum",
  mcp_capability: "cerebellum",
  agent: "cerebellum",
  failure: "temporal",
  recovery: "temporal",
  evaluation: "temporal",
  lesson: "temporal",
  operator: "stem",
  preference: "stem",
  mission: "stem",
  run: "stem",
  plan: "stem",
  phase: "stem",
  step: "stem",
  target: "stem",
  asset: "stem",
  entity: "stem",
});

/**
 * One authoritative display classification for native Vault and web anatomy.
 * Unknown future types fail closed into the stem rather than appearing in an
 * arbitrary cortical lobe.
 */
export function brainAtlasRegionForNodeType(nodeType: MemoryNodeType): BrainAtlasRegion {
  if (REUSABLE_ATTACK_NODE_TYPES.has(nodeType)) {
    return attackBrainAtlasMapping(nodeType as AttackBrainAtlasNodeType).region;
  }
  return NON_REUSABLE_REGION[nodeType] ?? "stem";
}

export function brainAtlasRegionForNode(
  node: Pick<MemoryNodeSummary, "id" | "nodeType">,
): BrainAtlasRegion {
  // Only the stable, consent-backed Operator Profile identities receive the
  // frontal classification. Generic entities, targets, assets, and other
  // operational provenance continue to fail closed into the stem.
  return operatorProfileBrainAtlasMapping(node)?.region
    ?? brainAtlasRegionForNodeType(node.nodeType);
}

export function brainAtlasRegionCounts(
  nodes: readonly Pick<MemoryNodeSummary, "id" | "nodeType">[],
): Record<BrainAtlasRegion, number> {
  const counts = Object.fromEntries(BRAIN_ATLAS_REGIONS.map((region) => [region, 0])) as Record<BrainAtlasRegion, number>;
  nodes.forEach((node) => { counts[brainAtlasRegionForNode(node)] += 1; });
  return counts;
}

function stableHash(value: string): number {
  let result = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    result ^= value.charCodeAt(index);
    result = Math.imul(result, 16777619);
  }
  return result >>> 0;
}

function brainSurfacePoint(side: -1 | 1, theta: number, phi: number, foldAmplitude = 0.026): BrainAtlasVector3 {
  const cosPhi = Math.cos(phi);
  const sinPhi = Math.sin(phi);
  const cosTheta = Math.cos(theta);
  const sinTheta = Math.sin(theta);
  // Each side is a separate lateral half-ellipsoid. abs(sin(theta)) retains a
  // crisp medial cleft instead of letting one fused sphere cross x=0.
  let x = side * (BRAIN_ATLAS_FISSURE_HALF_WIDTH + 0.86 * cosPhi * Math.abs(sinTheta));
  let z = 0.92 * cosPhi * cosTheta;
  let y = 0.12 + 0.82 * sinPhi;

  if (z < -0.45) z -= 0.05 * (-z - 0.45);
  if (z > 0.38 && y > -0.08) x *= 1 + 0.05 * Math.min(0.7, z * (y + 0.45));
  if (y < -0.40) y = -0.40 + (y + 0.40) * 0.48;

  const fold = foldAmplitude * (
    Math.sin(theta * 11 + phi * 7)
    + 0.55 * Math.sin(theta * 17 - phi * 5)
    + 0.35 * Math.sin(theta * 5 + phi * 13)
  );
  const radius = Math.hypot(x, y, z) || 1;
  return {
    x: side * Math.max(BRAIN_ATLAS_FISSURE_HALF_WIDTH, Math.abs(x + (x / radius) * fold)),
    y: y + (y / radius) * fold,
    z: z + (z / radius) * fold,
  };
}

function cerebellumSurfacePoint(side: -1 | 1, theta: number, phi: number): BrainAtlasVector3 {
  const cosPhi = Math.cos(phi);
  const ridge = 0.02 * Math.sin(theta * 14 + phi * 9);
  return {
    x: side * (0.045 + (0.37 + ridge) * cosPhi * Math.abs(Math.sin(theta))),
    y: -0.55 + 0.26 * Math.sin(phi),
    z: -0.58 + (0.28 + ridge) * cosPhi * Math.cos(theta),
  };
}

export function brainAtlasRegionForSurfacePoint(point: BrainAtlasVector3): BrainAtlasRegion {
  if (point.y < -0.50 && Math.abs(point.z) < 0.45 && Math.abs(point.x) < 0.065) return "stem";
  if (point.z > 0.28) return "frontal";
  if (point.z < -0.46) return "occipital";
  if (point.y < -0.06) return "temporal";
  return "parietal";
}

/** Builds the same bounded anatomical point cloud for WebGL2 and Canvas2D. */
export function buildBrainAtlasCloud(surfaceCount = 1_400, cerebellumCount = 220, stemCount = 28): BrainAtlasCloudPoint[] {
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  const surface = Array.from({ length: Math.max(0, surfaceCount) }, (_, index) => {
    const ratio = (index + 0.5) / Math.max(1, surfaceCount);
    const phi = Math.asin(2 * ratio - 1);
    const theta = (goldenAngle * index) % (Math.PI * 2);
    const side: -1 | 1 = index % 2 === 0 ? -1 : 1;
    const point = brainSurfacePoint(side, theta, phi);
    return {
      ...point,
      region: brainAtlasRegionForSurfacePoint(point),
      twinklePhase: (index * 0.731) % (Math.PI * 2),
      twinkleFrequency: 0.4 + (index % 9) / 12,
    };
  });
  const cerebellum = Array.from({ length: Math.max(0, cerebellumCount) }, (_, index) => {
    const ratio = (index + 0.5) / Math.max(1, cerebellumCount);
    const phi = Math.asin(2 * ratio - 1);
    const theta = (goldenAngle * index) % (Math.PI * 2);
    const side: -1 | 1 = index % 2 === 0 ? -1 : 1;
    return {
      ...cerebellumSurfacePoint(side, theta, phi),
      region: "cerebellum" as const,
      twinklePhase: (index * 0.91) % (Math.PI * 2),
      twinkleFrequency: 0.5 + (index % 5) / 8,
    };
  });
  const stem = Array.from({ length: Math.max(0, stemCount) }, (_, index) => {
    const ratio = index / Math.max(1, stemCount);
    const jitter = ((index * 1.31) % 1) - 0.5;
    return {
      x: jitter * 0.075,
      y: -0.62 - ratio * 0.76,
      z: -0.10 + jitter * 0.05,
      region: "stem" as const,
      twinklePhase: index * 0.55,
      twinkleFrequency: 0.3,
    };
  });
  return [...surface, ...cerebellum, ...stem];
}

/**
 * Shared 3D anatomical framing for both renderers. These segments describe
 * anatomy only; graph relationships still come exclusively from MemoryEdge.
 */
export function buildBrainAtlasGuideSegments(outlineSteps = 42, spineSteps = 12): BrainAtlasGuideSegment[] {
  const segments: BrainAtlasGuideSegment[] = [];
  for (const side of [-1, 1] as const) {
    let previous: BrainAtlasVector3 | undefined;
    for (let index = 0; index <= Math.max(8, outlineSteps); index += 1) {
      const angle = index / Math.max(8, outlineSteps) * Math.PI * 2;
      const point = {
        x: side * (BRAIN_ATLAS_FISSURE_HALF_WIDTH + 0.43 * (1 + Math.cos(angle))),
        y: 0.12 + 0.82 * Math.sin(angle),
        z: 0.08,
      };
      if (previous) segments.push({ from: previous, to: point, kind: "hemisphere-outline" });
      previous = point;
    }
    const fissureTop = { x: side * BRAIN_ATLAS_FISSURE_HALF_WIDTH, y: 0.88, z: 0.12 };
    const fissureMiddle = { x: side * BRAIN_ATLAS_FISSURE_HALF_WIDTH, y: 0.20, z: 0.17 };
    const fissureBottom = { x: side * BRAIN_ATLAS_FISSURE_HALF_WIDTH, y: -0.44, z: 0.08 };
    segments.push(
      { from: fissureTop, to: fissureMiddle, kind: "fissure" },
      { from: fissureMiddle, to: fissureBottom, kind: "fissure" },
    );
  }
  for (let index = 0; index < Math.max(4, spineSteps); index += 1) {
    const startRatio = index / Math.max(4, spineSteps);
    const endRatio = (index + 1) / Math.max(4, spineSteps);
    const fromY = -0.58 - startRatio * 0.83;
    const toY = -0.58 - endRatio * 0.83;
    const fromHalfWidth = 0.055 - startRatio * 0.022;
    const toHalfWidth = 0.055 - endRatio * 0.022;
    for (const side of [-1, 1] as const) {
      segments.push({
        from: { x: side * fromHalfWidth, y: fromY, z: -0.08 },
        to: { x: side * toHalfWidth, y: toY, z: -0.08 },
        kind: "spinal-cord",
      });
    }
    if (index % 2 === 0) {
      segments.push({
        from: { x: -fromHalfWidth, y: fromY, z: -0.08 },
        to: { x: fromHalfWidth, y: fromY, z: -0.08 },
        kind: "spinal-cord",
      });
    }
  }
  return segments;
}

/**
 * Place one canonical graph node inside its semantic anatomical region. The
 * persisted 2D layout contributes a bounded offset, so user-pinned positions
 * remain meaningful without allowing a memory to cross regions.
 */
export function graphPointToBrainAtlasPosition(
  point: GraphPoint,
  node: Pick<MemoryNodeSummary, "id" | "nodeType" | "edgeCount" | "pinned">,
  width: number,
  height: number,
): BrainAtlasVector3 {
  const region = brainAtlasRegionForNode(node);
  const definition = BRAIN_ATLAS_REGION_DEFINITIONS[region];
  const seed = stableHash(node.id);
  const first = (seed & 0xffff) / 0xffff;
  const second = ((seed >>> 16) & 0xffff) / 0xffff;
  const third = ((Math.imul(seed, 31) >>> 0) & 0xffff) / 0xffff;
  const theta = first * Math.PI * 2;
  const phi = Math.acos(2 * second - 1);
  const densityRadius = definition.radius * (node.edgeCount >= 8 ? 0.28 + third * 0.16 : 0.34 + third * 0.42);
  const anchor = BRAIN_CLUSTER_ANCHORS[nodeCluster(node)];
  const normalizedOffsetX = Math.max(-1, Math.min(1, (point.x / Math.max(1, width) - anchor.x) / Math.max(0.02, anchor.spreadX)));
  const normalizedOffsetY = Math.max(-1, Math.min(1, (point.y / Math.max(1, height) - anchor.y) / Math.max(0.02, anchor.spreadY)));
  let centerX = definition.center.x;
  const side: -1 | 1 = first > 0.5 ? 1 : -1;
  if (definition.mirrored) centerX = side * definition.center.x;
  const lobeOffset = definition.radius * 0.22;
  let x = centerX + densityRadius * Math.sin(phi) * Math.cos(theta) + normalizedOffsetX * lobeOffset;
  if (definition.mirrored) {
    const cleft = region === "cerebellum" ? 0.055 : BRAIN_ATLAS_FISSURE_HALF_WIDTH + 0.035;
    x = side * Math.max(cleft, Math.abs(x));
  }
  return {
    x,
    y: definition.center.y + densityRadius * Math.sin(phi) * Math.sin(theta) - normalizedOffsetY * lobeOffset,
    z: definition.center.z + densityRadius * Math.cos(phi) + point.depth * definition.radius * 0.10,
  };
}

export interface BrainAtlasProjection {
  readonly rotationX: number;
  readonly rotationY: number;
  readonly zoom: number;
  readonly width: number;
  readonly height: number;
  readonly distance: number;
  readonly scale: number;
}

export interface BrainAtlasProjectedPoint {
  readonly x: number;
  readonly y: number;
  readonly depth: number;
  readonly scale: number;
  readonly visible: boolean;
}

export function brainAtlasProjection(
  width: number,
  height: number,
  zoom: number,
  rotation: Readonly<{ x: number; y: number }>,
): BrainAtlasProjection {
  return {
    rotationX: rotation.x,
    rotationY: rotation.y,
    zoom,
    width,
    height,
    distance: 3.4,
    scale: Math.min(width, height) * 0.32 * zoom,
  };
}

/** CPU twin of the shader projection, used only for hit-testing and labels. */
export function projectBrainAtlasPoint(
  projection: BrainAtlasProjection,
  point: BrainAtlasVector3,
): BrainAtlasProjectedPoint {
  const cosY = Math.cos(projection.rotationY);
  const sinY = Math.sin(projection.rotationY);
  const cosX = Math.cos(projection.rotationX);
  const sinX = Math.sin(projection.rotationX);
  const rotatedX = point.x * cosY + point.z * sinY;
  const firstDepth = -point.x * sinY + point.z * cosY;
  const rotatedY = point.y * cosX - firstDepth * sinX;
  const depth = point.y * sinX + firstDepth * cosX;
  const denominator = projection.distance + depth;
  const perspective = projection.scale / denominator;
  return {
    x: projection.width / 2 + rotatedX * perspective * projection.distance,
    y: projection.height / 2 - projection.height * 0.04 - rotatedY * perspective * projection.distance,
    depth,
    scale: projection.distance / denominator,
    visible: denominator > 0.25,
  };
}

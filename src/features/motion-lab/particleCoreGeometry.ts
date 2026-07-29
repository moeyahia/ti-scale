export const PARTICLE_CORE_CLUSTER_COUNT = 14;

export interface ParticleCoreGeometryData {
  readonly positions: Float32Array;
  readonly normals: Float32Array;
  readonly explodeDirections: Float32Array;
  readonly clusterIds: Float32Array;
  readonly pointSizes: Float32Array;
  readonly tones: Float32Array;
  readonly seeds: Float32Array;
  readonly pointCount: number;
  readonly clusterPointCounts: readonly number[];
}

interface Vec3 {
  readonly x: number;
  readonly y: number;
  readonly z: number;
}

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
const TAU = Math.PI * 2;
const SHELL_RADIUS = 2.44;
const APERTURE_AXIS = normalize({ x: 0.47, y: -0.1, z: 0.877 });
const APERTURE_U = normalize(cross({ x: 0, y: 1, z: 0 }, APERTURE_AXIS));
const APERTURE_V = normalize(cross(APERTURE_AXIS, APERTURE_U));

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.max(minimum, Math.min(maximum, value));
}

function dot(left: Vec3, right: Vec3): number {
  return left.x * right.x + left.y * right.y + left.z * right.z;
}

function cross(left: Vec3, right: Vec3): Vec3 {
  return {
    x: left.y * right.z - left.z * right.y,
    y: left.z * right.x - left.x * right.z,
    z: left.x * right.y - left.y * right.x,
  };
}

function length(value: Vec3): number {
  return Math.hypot(value.x, value.y, value.z);
}

function normalize(value: Vec3): Vec3 {
  const magnitude = Math.max(1e-8, length(value));
  return { x: value.x / magnitude, y: value.y / magnitude, z: value.z / magnitude };
}

function scale(value: Vec3, factor: number): Vec3 {
  return { x: value.x * factor, y: value.y * factor, z: value.z * factor };
}

function add(...values: readonly Vec3[]): Vec3 {
  return values.reduce<Vec3>((sum, value) => ({
    x: sum.x + value.x,
    y: sum.y + value.y,
    z: sum.z + value.z,
  }), { x: 0, y: 0, z: 0 });
}

function hash(index: number, salt: number): number {
  const value = Math.sin(index * 127.1 + salt * 311.7) * 43_758.545_312_3;
  return value - Math.floor(value);
}

function apertureAngle(normal: Vec3): number {
  return Math.acos(clamp(dot(normal, APERTURE_AXIS), -1, 1));
}

function apertureAzimuth(normal: Vec3): number {
  return Math.atan2(dot(normal, APERTURE_V), dot(normal, APERTURE_U));
}

function clusterFor(normal: Vec3): number {
  // Seven equal azimuthal sectors across each hemisphere keep all fourteen
  // clusters contiguous and similarly weighted even though the aperture axis
  // is deliberately off-centre.
  const azimuth = (Math.atan2(normal.z, normal.x) + TAU) % TAU;
  const sector = Math.min(6, Math.floor((azimuth / TAU) * 7));
  return sector + (normal.y < 0 ? 7 : 0);
}

function clusterDirection(clusterId: number): Vec3 {
  const sector = clusterId % 7;
  const lower = clusterId >= 7;
  const azimuth = (sector / 7) * TAU + (lower ? 0.16 : -0.1);
  return normalize({
    x: Math.cos(azimuth) * 1.08,
    y: lower ? -0.72 : 0.72,
    z: Math.sin(azimuth) * 0.88 + 0.14,
  });
}

function deformShell(normal: Vec3, microVariation: number): Vec3 {
  const angle = apertureAngle(normal);
  const azimuth = apertureAzimuth(normal);
  const cavity = Math.exp(-Math.pow(angle / 0.63, 2));
  const rim = Math.exp(-Math.pow((angle - 0.54) / 0.2, 2));
  const tangent = normalize(cross(APERTURE_AXIS, normal));
  const harmonic = Math.sin(azimuth * 3.0 + normal.y * 4.2) * 0.014;
  const radius = SHELL_RADIUS * (1 - cavity * 0.52 + rim * 0.075 + harmonic + microVariation * 0.006);
  const twist = scale(tangent, cavity * (0.14 + angle * 0.22));
  const recessed = scale(APERTURE_AXIS, -cavity * 0.18);
  const point = add(scale(normal, radius), twist, recessed);
  return {
    x: point.x * 1.02,
    y: point.y,
    z: point.z * 0.98,
  };
}

function pushPoint(
  target: {
    positions: number[];
    normals: number[];
    explodeDirections: number[];
    clusterIds: number[];
    pointSizes: number[];
    tones: number[];
    seeds: number[];
    clusterPointCounts: number[];
  },
  normal: Vec3,
  sourceIndex: number,
  position: Vec3,
  sizeBias: number,
  toneBias: number,
): void {
  const clusterId = clusterFor(normal);
  const direction = clusterDirection(clusterId);
  const light = clamp(dot(normal, normalize({ x: -0.42, y: 0.58, z: 0.69 })) * 0.5 + 0.5, 0, 1);
  const apertureHighlight = Math.exp(-Math.pow((apertureAngle(normal) - 0.49) / 0.2, 2));
  const seed = hash(sourceIndex, 7);
  target.positions.push(position.x, position.y, position.z);
  target.normals.push(normal.x, normal.y, normal.z);
  target.explodeDirections.push(direction.x, direction.y, direction.z);
  target.clusterIds.push(clusterId);
  target.pointSizes.push(1.28 + hash(sourceIndex, 3) * 1.36 + sizeBias);
  target.tones.push(clamp(0.12 + light * 0.54 + apertureHighlight * 0.18 + (seed - 0.5) * 0.13 + toneBias, 0.05, 0.98));
  target.seeds.push(seed);
  target.clusterPointCounts[clusterId] = (target.clusterPointCounts[clusterId] ?? 0) + 1;
}

/**
 * Build an original particle-shell sculpture with a recessed, twisted aperture.
 * The output is deterministic so visual receipts and cluster motion can be
 * reproduced without loading a model, texture, or remote asset.
 */
export function createParticleCoreGeometry(shellSamples = 9_000, rimSamples = 1_300): ParticleCoreGeometryData {
  const target = {
    positions: [] as number[],
    normals: [] as number[],
    explodeDirections: [] as number[],
    clusterIds: [] as number[],
    pointSizes: [] as number[],
    tones: [] as number[],
    seeds: [] as number[],
    clusterPointCounts: Array.from({ length: PARTICLE_CORE_CLUSTER_COUNT }, () => 0),
  };

  const boundedShellSamples = Math.max(1_400, Math.min(22_000, Math.floor(shellSamples)));
  for (let index = 0; index < boundedShellSamples; index += 1) {
    const y = 1 - 2 * ((index + 0.5) / boundedShellSamples);
    const radial = Math.sqrt(Math.max(0, 1 - y * y));
    const azimuth = index * GOLDEN_ANGLE + (hash(index, 1) - 0.5) * 0.018;
    const normal = normalize({ x: Math.cos(azimuth) * radial, y, z: Math.sin(azimuth) * radial });
    const angle = apertureAngle(normal);
    // A small deterministic negative space prevents the cavity from reading as
    // a shaded solid sphere. Its uneven edge gives the opening a machined,
    // living quality rather than copying a perfect circular cutout.
    const openingBoundary = 0.25
      + Math.sin(apertureAzimuth(normal) * 1.4 + 0.7) * 0.035
      + (hash(index, 9) - 0.5) * 0.025;
    if (angle < openingBoundary) continue;
    pushPoint(target, normal, index, deformShell(normal, hash(index, 5) - 0.5), 0, 0);
  }

  const boundedRimSamples = Math.max(280, Math.min(4_000, Math.floor(rimSamples)));
  for (let index = 0; index < boundedRimSamples; index += 1) {
    const turn = (index / boundedRimSamples) * TAU * 8.5;
    const lane = index % 7;
    const laneOffset = (lane - 3) * 0.023;
    const angle = 0.25 + (index / boundedRimSamples) * 0.39 + laneOffset;
    const ringDirection = add(
      scale(APERTURE_AXIS, Math.cos(angle)),
      scale(APERTURE_U, Math.sin(angle) * Math.cos(turn)),
      scale(APERTURE_V, Math.sin(angle) * Math.sin(turn)),
    );
    const normal = normalize(ringDirection);
    const position = deformShell(normal, Math.sin(turn * 0.37) * 0.5);
    pushPoint(target, normal, boundedShellSamples + index, position, 0.34, 0.08);
  }

  // A recessed inner particle field makes the aperture read as genuine depth
  // on the light canvas. It remains part of the same geometry and draw call.
  const innerSamples = Math.max(120, Math.round(boundedRimSamples * 0.16));
  for (let index = 0; index < innerSamples; index += 1) {
    const normalizedRadius = Math.sqrt((index + 0.5) / innerSamples);
    const angle = 0.025 + normalizedRadius * 0.205;
    const turn = index * GOLDEN_ANGLE;
    const normal = normalize(add(
      scale(APERTURE_AXIS, Math.cos(angle)),
      scale(APERTURE_U, Math.sin(angle) * Math.cos(turn)),
      scale(APERTURE_V, Math.sin(angle) * Math.sin(turn)),
    ));
    const inward = 1.12 + normalizedRadius * 0.19;
    const spiralTangent = normalize(cross(APERTURE_AXIS, normal));
    const position = add(
      scale(normal, inward),
      scale(APERTURE_AXIS, -0.24),
      scale(spiralTangent, Math.sin(turn * 0.17) * 0.035),
    );
    pushPoint(
      target,
      normal,
      boundedShellSamples + boundedRimSamples + index,
      position,
      -0.1,
      -0.18,
    );
  }

  return {
    positions: new Float32Array(target.positions),
    normals: new Float32Array(target.normals),
    explodeDirections: new Float32Array(target.explodeDirections),
    clusterIds: new Float32Array(target.clusterIds),
    pointSizes: new Float32Array(target.pointSizes),
    tones: new Float32Array(target.tones),
    seeds: new Float32Array(target.seeds),
    pointCount: target.clusterIds.length,
    clusterPointCounts: target.clusterPointCounts,
  };
}

export const particleCoreClusterLabels = [
  "Crown arc I",
  "Crown arc II",
  "Crown arc III",
  "Crown arc IV",
  "Crown arc V",
  "Crown arc VI",
  "Crown arc VII",
  "Foundation arc I",
  "Foundation arc II",
  "Foundation arc III",
  "Foundation arc IV",
  "Foundation arc V",
  "Foundation arc VI",
  "Foundation arc VII",
] as const;

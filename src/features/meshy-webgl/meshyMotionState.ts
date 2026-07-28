import type {
  MeshyAssemblyState,
  MeshyPartTransform,
  MeshyVector3,
  MeshyWebglPart,
} from "./meshyWebglManifest";

export const MESHY_ASSEMBLY_SEQUENCE: readonly MeshyAssemblyState[] = [
  "assembled",
  "exploded",
  "chassis",
  "section-formation",
] as const;

export const MESHY_TRANSITION_DURATION_MS = 1_200;

export interface MeshyMotionPresentation {
  readonly from: MeshyAssemblyState;
  readonly to: MeshyAssemblyState;
  readonly progress: number;
  readonly revision: number;
}

export interface MeshyResolvedTransform {
  readonly position: MeshyVector3;
  readonly rotationRadians: MeshyVector3;
  readonly scale: MeshyVector3;
}

export const IDENTITY_TRANSFORM: MeshyResolvedTransform = Object.freeze({
  position: Object.freeze({ x: 0, y: 0, z: 0 }),
  rotationRadians: Object.freeze({ x: 0, y: 0, z: 0 }),
  scale: Object.freeze({ x: 1, y: 1, z: 1 }),
});

export function clampUnit(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

function mix(left: number, right: number, progress: number): number {
  return left + (right - left) * progress;
}

function mixVector(left: MeshyVector3, right: MeshyVector3, progress: number): MeshyVector3 {
  return {
    x: mix(left.x, right.x, progress),
    y: mix(left.y, right.y, progress),
    z: mix(left.z, right.z, progress),
  };
}

/** A finite, non-overshooting mechanical easing curve. */
export function mechanicalEase(progress: number): number {
  const value = clampUnit(progress);
  return value < 0.5
    ? 4 * value * value * value
    : 1 - Math.pow(-2 * value + 2, 3) / 2;
}

export function settledMeshyMotion(state: MeshyAssemblyState = "assembled", revision = 0): MeshyMotionPresentation {
  return { from: state, to: state, progress: 1, revision };
}

export function beginMeshyTransition(
  current: MeshyMotionPresentation,
  target: MeshyAssemblyState,
): MeshyMotionPresentation {
  const settled = current.progress >= 1 ? current.to : current.progress >= 0.5 ? current.to : current.from;
  if (settled === target) return settledMeshyMotion(target, current.revision + 1);
  return { from: settled, to: target, progress: 0, revision: current.revision + 1 };
}

export function advanceMeshyTransition(
  current: MeshyMotionPresentation,
  elapsedMs: number,
  durationMs = MESHY_TRANSITION_DURATION_MS,
): MeshyMotionPresentation {
  if (current.progress >= 1 || current.from === current.to) return settledMeshyMotion(current.to, current.revision);
  const progress = clampUnit(current.progress + Math.max(0, elapsedMs) / Math.max(1, durationMs));
  return progress >= 1
    ? settledMeshyMotion(current.to, current.revision)
    : { ...current, progress };
}

export function adjacentMeshyState(state: MeshyAssemblyState, direction: -1 | 1): MeshyAssemblyState {
  const index = MESHY_ASSEMBLY_SEQUENCE.indexOf(state);
  return MESHY_ASSEMBLY_SEQUENCE[Math.min(MESHY_ASSEMBLY_SEQUENCE.length - 1, Math.max(0, index + direction))]!;
}

export function transformForPartState(part: MeshyWebglPart, state: MeshyAssemblyState): MeshyResolvedTransform {
  if (state === "assembled") return IDENTITY_TRANSFORM;
  if (state === "exploded") {
    return {
      position: {
        x: part.localNormal.x * part.explodeDistance,
        y: part.localNormal.y * part.explodeDistance,
        z: part.localNormal.z * part.explodeDistance,
      },
      rotationRadians: IDENTITY_TRANSFORM.rotationRadians,
      scale: IDENTITY_TRANSFORM.scale,
    };
  }
  const authored: MeshyPartTransform = state === "chassis" ? part.chassis : part.sectionFormation;
  return authored;
}

export function resolvePartTransform(
  part: MeshyWebglPart,
  presentation: MeshyMotionPresentation,
): MeshyResolvedTransform {
  const from = transformForPartState(part, presentation.from);
  const to = transformForPartState(part, presentation.to);
  const progress = mechanicalEase(presentation.progress);
  return {
    position: mixVector(from.position, to.position, progress),
    rotationRadians: mixVector(from.rotationRadians, to.rotationRadians, progress),
    scale: mixVector(from.scale, to.scale, progress),
  };
}

import type { BrainAtlasRegion } from "./brainAtlasGeometry";

/**
 * Canonical visual-only sizing for the particle graph. The drawn nodes are
 * intentionally smaller than the layout radius, while the pointer hit area
 * remains a 44 CSS-pixel target. Graph topology and evidence semantics never
 * depend on these values.
 */
export const BRAIN_NODE_VISUAL_SCALE = 0.82;
export const BRAIN_NODE_MIN_VISUAL_RADIUS_PX = 3.25;
export const BRAIN_NODE_HIT_RADIUS_PX = 22;

export const BRAIN_AMBIENT_PARTICLE_ALPHA: Readonly<Record<BrainAtlasRegion, number>> = Object.freeze({
  frontal: 0.62,
  parietal: 0.62,
  temporal: 0.62,
  occipital: 0.62,
  cerebellum: 0.68,
  stem: 0.74,
});

export function brainNodeVisualRadius(baseRadius: number, projectionScale = 1): number {
  return Math.max(BRAIN_NODE_MIN_VISUAL_RADIUS_PX, baseRadius * projectionScale * BRAIN_NODE_VISUAL_SCALE);
}

export function brainNodeVisualDiameter(baseRadius: number): number {
  return Math.max(BRAIN_NODE_MIN_VISUAL_RADIUS_PX * 2, baseRadius * 2 * BRAIN_NODE_VISUAL_SCALE);
}

export function brainNodeHitRadius(renderedRadius: number): number {
  return Math.max(BRAIN_NODE_HIT_RADIUS_PX, renderedRadius + 4);
}

export interface BrainNodeHitCandidate {
  readonly id: string;
  readonly x: number;
  readonly y: number;
  /** Radius after projection, in CSS pixels. */
  readonly radius: number;
  /** Smaller projected depth values are visually nearer to the camera. */
  readonly depth?: number;
  readonly visible?: boolean;
}

/**
 * Resolve overlapping accessible hit areas by proximity instead of render or
 * insertion order. This preserves the 44px pointer target while ensuring that
 * clicking a visible node centre selects that node, even in a dense cloud.
 */
export function nearestBrainNodeHit(
  candidates: readonly BrainNodeHitCandidate[],
  cursor: Readonly<{ x: number; y: number }>,
): string | undefined {
  return candidates
    .flatMap((candidate) => {
      if (candidate.visible === false
        || !Number.isFinite(candidate.x)
        || !Number.isFinite(candidate.y)
        || !Number.isFinite(candidate.radius)) return [];
      const distance = Math.hypot(cursor.x - candidate.x, cursor.y - candidate.y);
      if (distance > brainNodeHitRadius(Math.max(0, candidate.radius))) return [];
      return [{ candidate, distance }];
    })
    .sort((left, right) => (
      left.distance - right.distance
      || (left.candidate.depth ?? 0) - (right.candidate.depth ?? 0)
      || left.candidate.id.localeCompare(right.candidate.id)
    ))[0]?.candidate.id;
}

/**
 * Collapsed clusters retain a stable logical hit target while the rendered
 * three-dimensional particle cloud rotates. The visible projected node
 * remains the primary target everywhere else; this stable aggregate target
 * prevents an intentional cluster click from turning into a camera drag
 * between animation frames.
 */
export function stableCollapsedClusterHit(
  candidates: readonly BrainNodeHitCandidate[],
  cursor: Readonly<{ x: number; y: number }>,
): string | undefined {
  return nearestBrainNodeHit(
    candidates.filter((candidate) => candidate.id.startsWith("cluster:")),
    cursor,
  );
}

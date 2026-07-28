import { PARTICLE_CORE_CLUSTER_COUNT } from "./particleCoreGeometry";

export interface ParticleModuleDefinition {
  readonly id: string;
  readonly label: string;
  readonly summary: string;
  readonly href: string;
}
/**
 * The fourteen targets are real Ti-Scale product surfaces. The review route
 * turns each existing particle cluster into one of these addressable modules;
 * it does not invent dashboard data or decorative controls.
 */
export const particleModuleDefinitions: readonly ParticleModuleDefinition[] = [
  { id: "overview", label: "Overview", summary: "Command Center and system readiness", href: "/" },
  { id: "missions", label: "Missions", summary: "Durable objectives, runs, and plans", href: "/missions" },
  { id: "live", label: "Live Operations", summary: "Active run supervision and recovery", href: "/live" },
  { id: "guided", label: "Guided Workspace", summary: "Represented steps and operator decisions", href: "/guided" },
  { id: "decisions", label: "Decisions", summary: "Guided choices and safe-stop review", href: "/decisions" },
  { id: "evidence", label: "Evidence", summary: "Verified intelligence and provenance", href: "/intelligence/evidence" },
  { id: "findings", label: "Findings", summary: "Evidence-linked conclusions", href: "/intelligence/findings" },
  { id: "agents", label: "Agents", summary: "Fleet capability and assignment health", href: "/agents" },
  { id: "brain", label: "Second Brain", summary: "Owned memory and context use", href: "/brain" },
  { id: "brain-graph", label: "Brain Graph", summary: "Memory paths and mission clusters", href: "/brain/graph" },
  { id: "learning", label: "Learning", summary: "Evidence-gated lessons and research", href: "/learning" },
  { id: "observability", label: "Observability", summary: "Events, traces, and component health", href: "/observability" },
  { id: "reports", label: "Reports", summary: "Mission deliverables and exports", href: "/reports" },
  { id: "system", label: "System", summary: "Connections, policy, and settings", href: "/system" },
] as const;

export interface ParticleModuleTargetData {
  readonly positions: Float32Array;
  readonly clusterCentres: readonly (readonly [number, number, number])[];
}

function fractional(value: number): number {
  return value - Math.floor(value);
}

function cardCentre(clusterId: number): readonly [number, number, number] {
  if (clusterId >= 12) {
    return [clusterId === 12 ? -0.86 : 0.86, -1.56, 0.03] as const;
  }
  const column = clusterId % 4;
  const row = Math.floor(clusterId / 4);
  return [-2.58 + column * 1.72, 1.43 - row * 1.01, 0.03 + row * 0.018] as const;
}

/**
 * Map every approved particle to a deterministic panel position. Most points
 * form a restrained halftone face; a stable subset traces each sharp panel
 * perimeter so the final state reads as module geometry rather than fourteen
 * unrelated point clouds.
 */
export function createParticleModuleTargets(
  clusterIds: Float32Array,
  seeds: Float32Array,
): ParticleModuleTargetData {
  if (clusterIds.length !== seeds.length) {
    throw new Error("Particle module targets require one seed for every cluster ID");
  }
  const counts = Array.from({ length: PARTICLE_CORE_CLUSTER_COUNT }, () => 0);
  clusterIds.forEach((value) => {
    const clusterId = Math.round(value);
    if (clusterId < 0 || clusterId >= PARTICLE_CORE_CLUSTER_COUNT) {
      throw new Error("Particle module targets received an unknown cluster ID");
    }
    counts[clusterId] = (counts[clusterId] ?? 0) + 1;
  });
  if (counts.some((count) => count === 0)) {
    throw new Error("Particle module targets require all fourteen core clusters");
  }

  const cursors = Array.from({ length: PARTICLE_CORE_CLUSTER_COUNT }, () => 0);
  const positions = new Float32Array(clusterIds.length * 3);
  const centres = particleModuleDefinitions.map((_, clusterId) => cardCentre(clusterId));
  const cardWidth = 1.48;
  const cardHeight = 0.76;

  for (let pointIndex = 0; pointIndex < clusterIds.length; pointIndex += 1) {
    const clusterId = Math.round(clusterIds[pointIndex] ?? 0);
    const ordinal = cursors[clusterId] ?? 0;
    cursors[clusterId] = ordinal + 1;
    const seed = seeds[pointIndex] ?? 0;
    const centre = centres[clusterId] ?? [0, 0, 0];
    const family = ordinal % 11;
    const progression = fractional((ordinal + 0.5) * 0.61803398875 + seed * 0.37);
    let localX: number;
    let localY: number;

    if (family >= 7) {
      // Four perimeter families create the machined single-pixel silhouette.
      const side = family - 7;
      if (side === 0) {
        localX = (progression - 0.5) * cardWidth;
        localY = -cardHeight / 2;
      } else if (side === 1) {
        localX = cardWidth / 2;
        localY = (progression - 0.5) * cardHeight;
      } else if (side === 2) {
        localX = (0.5 - progression) * cardWidth;
        localY = cardHeight / 2;
      } else {
        localX = -cardWidth / 2;
        localY = (0.5 - progression) * cardHeight;
      }
    } else {
      // Low-discrepancy face samples retain the approved halftone material.
      localX = (fractional(ordinal * 0.754877666 + seed * 0.21) - 0.5) * cardWidth * 0.91;
      localY = (fractional(ordinal * 0.569840291 + seed * 0.43) - 0.5) * cardHeight * 0.79;
    }

    const offset = pointIndex * 3;
    positions[offset] = centre[0] + localX;
    positions[offset + 1] = centre[1] + localY;
    positions[offset + 2] = centre[2] + (seed - 0.5) * 0.025;
  }

  return { positions, clusterCentres: centres };
}

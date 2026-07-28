interface ParticlePoint {
  readonly x: number;
  readonly y: number;
  readonly radius: number;
  readonly tone: 1 | 2 | 3 | 4;
}

const VIEWBOX_CENTER = 180;

function rounded(value: number): number {
  return Math.round(value * 10) / 10;
}

function ringPoints(
  count: number,
  baseRadius: number,
  xScale: number,
  yScale: number,
  phase: number,
): ParticlePoint[] {
  return Array.from({ length: count }, (_, index) => {
    const angle = phase + (index / count) * Math.PI * 2;
    const contour = baseRadius
      + Math.sin(angle * 3 + phase) * (baseRadius * 0.08)
      + Math.cos(angle * 5 - phase) * (baseRadius * 0.035);
    return {
      x: rounded(VIEWBOX_CENTER + Math.cos(angle) * contour * xScale),
      y: rounded(VIEWBOX_CENTER + Math.sin(angle) * contour * yScale),
      radius: 1.15 + (index % 5) * 0.17,
      tone: ((index + Math.round(phase * 10)) % 4 + 1) as ParticlePoint["tone"],
    };
  });
}

function fieldPoints(count: number): ParticlePoint[] {
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  return Array.from({ length: count }, (_, index) => {
    const ratio = (index + 0.65) / count;
    const angle = index * goldenAngle + 0.36;
    const contour = 51 + Math.sqrt(ratio) * 71 + Math.sin(index * 1.91) * 4.5;
    return {
      x: rounded(VIEWBOX_CENTER + Math.cos(angle) * contour * 1.06),
      y: rounded(VIEWBOX_CENTER + Math.sin(angle) * contour * 0.77),
      radius: 0.9 + (index % 7) * 0.12,
      tone: ((index * 3) % 4 + 1) as ParticlePoint["tone"],
    };
  });
}

export const PARTICLE_BOOT_GROUPS = Object.freeze([
  Object.freeze(ringPoints(52, 128, 1.04, 0.77, 0.12)),
  Object.freeze(ringPoints(36, 87, 1.11, 0.7, 0.58)),
  Object.freeze(fieldPoints(40)),
  Object.freeze(ringPoints(24, 43, 1.2, 0.62, 0.3)),
]);

export const PARTICLE_BOOT_COUNT = PARTICLE_BOOT_GROUPS.reduce(
  (total, group) => total + group.length,
  0,
);

/**
 * A dependency-free startup mark. The final SVG geometry is deterministic so
 * the loader paints immediately, remains testable, and never pulls WebGL or
 * Three.js onto the critical path.
 */
export function ParticleBootMark() {
  return (
    <svg
      className="ti-boot-particle-mark"
      data-ti-boot-particle-mark="forming-core"
      data-ti-boot-particle-count={PARTICLE_BOOT_COUNT}
      viewBox="0 0 360 360"
      focusable="false"
      aria-hidden="true"
    >
      <ellipse className="ti-boot-particle-mark__datum" cx="180" cy="180" rx="155" ry="116" />
      {PARTICLE_BOOT_GROUPS.map((group, groupIndex) => (
        <g
          className={`ti-boot-particle-mark__group ti-boot-particle-mark__group--${groupIndex + 1}`}
          key={groupIndex}
        >
          {group.map((particle, particleIndex) => (
            <circle
              className={`ti-boot-particle-mark__particle ti-boot-particle-mark__particle--tone-${particle.tone}`}
              cx={particle.x}
              cy={particle.y}
              r={particle.radius}
              key={`${groupIndex}-${particleIndex}`}
            />
          ))}
        </g>
      ))}
      <g className="ti-boot-particle-mark__aperture">
        <path d="M151 178c7-25 27-40 52-35 18 4 31 17 36 35-8 23-27 37-51 34-19-2-32-15-37-34Z" />
        <path d="M164 178c5-14 17-22 31-20 12 2 21 10 25 20-5 13-16 20-29 19-13-1-22-8-27-19Z" />
      </g>
      <path className="ti-boot-particle-mark__scan" d="M42 180H318" pathLength="1" />
    </svg>
  );
}

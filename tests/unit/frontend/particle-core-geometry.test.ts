import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  createParticleCoreGeometry,
  particleCoreClusterLabels,
  PARTICLE_CORE_CLUSTER_COUNT,
} from "../../../src/features/motion-lab/particleCoreGeometry";

const pageSource = readFileSync(new URL("../../../src/features/motion-lab/ParticleCoreReviewPage.tsx", import.meta.url), "utf8");
const runtimeSource = readFileSync(new URL("../../../src/features/motion-lab/ParticleCoreRuntime.tsx", import.meta.url), "utf8");
const cssSource = readFileSync(new URL("../../../src/features/motion-lab/particle-core-review.css", import.meta.url), "utf8");
const routeSource = readFileSync(new URL("../../../src/app/router/RouteView.tsx", import.meta.url), "utf8");
const moduleSource = readFileSync(new URL("../../../src/app/router/routeModules.ts", import.meta.url), "utf8");
const routeCasesSource = readFileSync(new URL("../../e2e/support/routes.ts", import.meta.url), "utf8");
const bundleBudgetSource = readFileSync(new URL("../../../scripts/meshy-webgl-bundle-budget.ts", import.meta.url), "utf8");

describe("Ti-Scale operator-approved particle core", () => {
  test("builds one deterministic recessed shell with fourteen populated motion clusters", () => {
    const first = createParticleCoreGeometry(3_600, 560);
    const second = createParticleCoreGeometry(3_600, 560);
    expect(first.pointCount).toBeGreaterThan(3_800);
    expect(first.clusterPointCounts).toHaveLength(PARTICLE_CORE_CLUSTER_COUNT);
    expect(first.clusterPointCounts.every((count) => count > 100)).toBe(true);
    expect([...first.positions]).toEqual([...second.positions]);
    expect([...first.clusterIds]).toEqual([...second.clusterIds]);
    expect(particleCoreClusterLabels).toHaveLength(PARTICLE_CORE_CLUSTER_COUNT);
  });

  test("emits bounded finite GPU attributes and normalized explosion vectors", () => {
    const geometry = createParticleCoreGeometry(2_800, 420);
    expect(geometry.positions).toHaveLength(geometry.pointCount * 3);
    expect(geometry.normals).toHaveLength(geometry.pointCount * 3);
    expect(geometry.explodeDirections).toHaveLength(geometry.pointCount * 3);
    expect(geometry.clusterIds).toHaveLength(geometry.pointCount);
    expect(geometry.pointSizes).toHaveLength(geometry.pointCount);
    expect(geometry.tones).toHaveLength(geometry.pointCount);
    expect(geometry.seeds).toHaveLength(geometry.pointCount);
    expect([...geometry.positions].every(Number.isFinite)).toBe(true);
    expect([...geometry.pointSizes].every((value) => value >= 1.1 && value <= 3.5)).toBe(true);
    expect([...geometry.tones].every((value) => value >= 0 && value <= 1)).toBe(true);
    expect([...geometry.clusterIds].every((value) => Number.isInteger(value) && value >= 0 && value < 14)).toBe(true);
    for (let offset = 0; offset < geometry.explodeDirections.length; offset += 3) {
      const magnitude = Math.hypot(
        geometry.explodeDirections[offset] ?? 0,
        geometry.explodeDirections[offset + 1] ?? 0,
        geometry.explodeDirections[offset + 2] ?? 0,
      );
      expect(magnitude).toBeWithin(0.999, 1.001);
    }
  });

  test("creates a material cavity rather than an undeformed decorative sphere", () => {
    const geometry = createParticleCoreGeometry(4_200, 700);
    const radii: number[] = [];
    for (let offset = 0; offset < geometry.positions.length; offset += 3) {
      radii.push(Math.hypot(
        geometry.positions[offset] ?? 0,
        geometry.positions[offset + 1] ?? 0,
        geometry.positions[offset + 2] ?? 0,
      ));
    }
    expect(Math.min(...radii)).toBeLessThan(1.55);
    expect(Math.max(...radii)).toBeGreaterThan(2.45);
  });

  test("keeps the approved field local, inspectable, light-mode, and independently routed", () => {
    expect(routeSource).toContain('pathname === "/motion-lab/particle-core"');
    expect(routeSource).toContain('pathname === "/motion-lab/webgl") route = <Redirect to="/motion-lab/particle-core" />');
    expect(routeSource).toContain('pathname === "/motion-lab/assembly") route = <Redirect to="/motion-lab/particle-core" />');
    expect(moduleSource).toContain('import("../../features/motion-lab/ParticleCoreReviewPage")');
    expect(moduleSource).toContain('pathname === "/motion-lab/webgl") return loadParticleCoreReviewPage');
    expect(moduleSource).toContain('pathname === "/motion-lab/assembly") return loadParticleCoreReviewPage');
    expect(moduleSource).not.toContain('import("../../features/meshy-webgl/MeshyWebglPage")');
    expect(routeCasesSource).toContain('{ id: "motion-lab-particle-core", path: "/motion-lab/particle-core" }');
    expect(routeCasesSource).toContain('{ id: "motion-lab-webgl-retired-alias", path: "/motion-lab/webgl", expectedPath: "/motion-lab/particle-core" }');
    expect(routeCasesSource).toContain('{ id: "motion-lab-assembly-retired-alias", path: "/motion-lab/assembly", expectedPath: "/motion-lab/particle-core" }');
    expect(pageSource).toContain('data-review-boundary="approved-geometry"');
    expect(pageSource).toContain("Operator-approved particle geometry.");
    expect(pageSource).toContain("This deterministic field is now the active Ti-Scale Command Center artwork.");
    expect(pageSource).toContain('aria-label="Particle cluster separation"');
    expect(pageSource).toContain("prefers-reduced-motion: reduce");
    expect(runtimeSource).toContain("createParticleCoreGeometry()");
    expect(runtimeSource).toContain("WebGLRenderer");
    expect(runtimeSource).not.toMatch(/https?:\/\//u);
    expect(runtimeSource).not.toContain("GLTFLoader");
    expect(bundleBudgetSource).toContain("ParticleCoreReviewPage: 24 * 1024");
    expect(bundleBudgetSource).toContain("ParticleCoreRuntime: 150 * 1024");
    expect(bundleBudgetSource).toContain('const ACTIVE_WEBGL_CHUNKS');
    expect(bundleBudgetSource).toContain('approvedMeshyDeliveryPresent');
    expect(cssSource).toContain("#f3f1ed");
    expect(cssSource).toContain("@media (prefers-reduced-motion: reduce)");
    expect(cssSource).not.toContain("repeating-linear-gradient");
    expect(cssSource).not.toMatch(/\b(?:green|neon|orange)\b/iu);
  });
});

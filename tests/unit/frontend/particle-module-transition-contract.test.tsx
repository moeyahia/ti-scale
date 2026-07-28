import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { createParticleCoreGeometry } from "../../../src/features/motion-lab/particleCoreGeometry";
import {
  createParticleModuleTargets,
  particleModuleDefinitions,
} from "../../../src/features/motion-lab/particleModuleGeometry";

const pageSource = readFileSync(new URL("../../../src/features/motion-lab/ParticleModuleTransitionPage.tsx", import.meta.url), "utf8");
const runtimeSource = readFileSync(new URL("../../../src/features/motion-lab/ParticleCoreRuntime.tsx", import.meta.url), "utf8");
const cssSource = readFileSync(new URL("../../../src/features/motion-lab/particle-module-transition.css", import.meta.url), "utf8");
const overviewSource = readFileSync(new URL("../../../src/features/overview/OverviewPage.tsx", import.meta.url), "utf8");
const routeSource = readFileSync(new URL("../../../src/app/router/RouteView.tsx", import.meta.url), "utf8");
const moduleSource = readFileSync(new URL("../../../src/app/router/routeModules.ts", import.meta.url), "utf8");
const motionLabSource = readFileSync(new URL("../../../src/features/motion-lab/MotionLabPage.tsx", import.meta.url), "utf8");
const routeCasesSource = readFileSync(new URL("../../e2e/support/routes.ts", import.meta.url), "utf8");

describe("Ti-Scale review-only particle-to-module transition", () => {
  test("maps all fourteen approved clusters to real, unique product destinations", () => {
    expect(particleModuleDefinitions).toHaveLength(14);
    expect(new Set(particleModuleDefinitions.map((module) => module.id)).size).toBe(14);
    expect(new Set(particleModuleDefinitions.map((module) => module.href)).size).toBe(14);
    expect(particleModuleDefinitions.every((module) => module.href.startsWith("/"))).toBe(true);
    expect(particleModuleDefinitions.map((module) => module.label)).toEqual([
      "Overview", "Missions", "Live Operations", "Guided Workspace", "Decisions", "Evidence", "Findings",
      "Agents", "Second Brain", "Brain Graph", "Learning", "Observability", "Reports", "System",
    ]);
  });

  test("creates deterministic finite card targets without replacing particle identity", () => {
    const core = createParticleCoreGeometry(3_600, 560);
    const first = createParticleModuleTargets(core.clusterIds, core.seeds);
    const second = createParticleModuleTargets(core.clusterIds, core.seeds);
    expect(first.positions).toHaveLength(core.pointCount * 3);
    expect(first.clusterCentres).toHaveLength(14);
    expect([...first.positions]).toEqual([...second.positions]);
    expect([...first.positions].every(Number.isFinite)).toBe(true);
    expect(Math.min(...first.positions)).toBeGreaterThan(-3.5);
    expect(Math.max(...first.positions)).toBeLessThan(3.5);
    const uniqueCentres = new Set(first.clusterCentres.map((centre) => centre.join("/")));
    expect(uniqueCentres.size).toBe(14);
  });

  test("fails closed for mismatched or incomplete geometry inputs", () => {
    expect(() => createParticleModuleTargets(new Float32Array([0, 1]), new Float32Array([0]))).toThrow(
      "one seed for every cluster ID",
    );
    expect(() => createParticleModuleTargets(new Float32Array([0, 1]), new Float32Array([0, 1]))).toThrow(
      "all fourteen core clusters",
    );
  });

  test("keeps the canonical route lazy, review-only, local, and absent from Overview composition", () => {
    expect(routeSource).toContain('pathname === "/motion-lab/particle-module-transition"');
    expect(moduleSource).toContain('import("../../features/motion-lab/ParticleModuleTransitionPage")');
    expect(moduleSource).toContain('pathname === "/motion-lab/particle-module-transition"');
    expect(routeCasesSource).toContain('{ id: "motion-lab-particle-module-transition", path: "/motion-lab/particle-module-transition" }');
    expect(motionLabSource).toContain('href="/motion-lab/particle-module-transition"');
    expect(motionLabSource).toContain("Review particle-to-module transition");
    expect(pageSource).toContain('data-review-boundary="review-only"');
    expect(pageSource).toContain("Review only · not integrated into Overview");
    expect(pageSource).toContain("particleModuleDefinitions.map");
    expect(pageSource).toContain("prefers-reduced-motion: reduce");
    expect(pageSource).not.toMatch(/<img|\.glb|\.avif|\.webp|https?:\/\//u);
    expect(overviewSource).not.toContain("ParticleModuleTransitionPage");
    expect(overviewSource).not.toContain("particle-module-transition");
  });

  test("morphs the approved one-draw-call field and pauses animation while hidden", () => {
    expect(runtimeSource).toContain("createParticleCoreGeometry()");
    expect(runtimeSource).toContain("createParticleModuleTargets(data.clusterIds, data.seeds)");
    expect(runtimeSource).toContain('geometry.setAttribute("aModuleTarget"');
    expect(runtimeSource).toContain("uModuleProgress");
    expect(runtimeSource).toContain('state.host.dataset.animationState');
    expect(runtimeSource).toContain('"paused-hidden"');
    expect(runtimeSource).toContain("if (!visible)");
    expect(runtimeSource).not.toContain("GLTFLoader");
    expect(cssSource).toContain("scroll-snap-type: y mandatory");
    expect(cssSource).toContain("@media (prefers-reduced-motion: reduce)");
    expect(cssSource).not.toContain("repeating-linear-gradient");
  });
});

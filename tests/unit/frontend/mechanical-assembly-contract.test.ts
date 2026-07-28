import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../../../src/design-system/tokens/ti-scale.css", import.meta.url), "utf8");
const routeCss = readFileSync(new URL("../../../src/app/router/mechanical-transitions.css", import.meta.url), "utf8");
const overview = readFileSync(new URL("../../../src/features/overview/OverviewPage.tsx", import.meta.url), "utf8");
const particle = readFileSync(new URL("../../../src/features/overview/CommandCenterParticleCore.tsx", import.meta.url), "utf8");
const particleRuntime = readFileSync(new URL("../../../src/features/motion-lab/ParticleCoreRuntime.tsx", import.meta.url), "utf8");
const particleRuntimeCss = readFileSync(new URL("../../../src/features/motion-lab/particle-core-runtime.css", import.meta.url), "utf8");
const primitives = readFileSync(new URL("../../../src/design-system/components/Primitives.tsx", import.meta.url), "utf8");
const assembly = readFileSync(new URL("../../../src/design-system/hooks/useMechanicalAssembly.ts", import.meta.url), "utf8");

describe("Ti-Scale mechanical assembly contract", () => {
  test("mounts the operator-approved procedural core as the Command Center artwork", () => {
    expect(overview).toContain("<CommandCenterParticleCore />");
    expect(overview).not.toContain("CommandCenterAmbient");
    expect(particle).toContain('data-ti-transformer-core="true"');
    expect(particle).toContain('data-ti-exploded-model="approved-particle-core"');
    expect(particle).toContain('data-ti-particle-artwork="operator-approved"');
    expect(particle).toContain('import("../motion-lab/ParticleCoreRuntime")');
    expect(particle).not.toContain("<picture");
    expect(particle).not.toContain("assetUrl(");
    expect(particle).not.toContain("GLTFLoader");
  });

  test("renders one local point field and bypasses the retired facet/GLB transfer", () => {
    expect(particleRuntime.match(/new Points\(/gu)).toHaveLength(1);
    expect(particleRuntime).toContain('points.name = "TI_SCALE_PARTICLE_CORE_14_CLUSTER_SCULPTURE"');
    expect(particleRuntime).toContain('host.dataset.drawCalls = String(drawCalls)');
    expect(particleRuntime).toContain("createParticleCoreGeometry()");
    expect(particleRuntime).not.toContain("GLTFLoader");
    expect(particleRuntime).not.toMatch(/https?:\/\//u);
    expect(assembly).toContain('core.dataset.tiExplodedModel === "approved-particle-core"');
    expect(assembly).toContain('root.dataset.tiCoreTransferState = "particle-core-approved"');
    expect(assembly).toContain('root.dataset.tiTransferCount = "0"');
  });

  test("deploys real command modules from the core and settles them after assembly", () => {
    expect(overview).toContain("useMechanicalAssembly()");
    expect(overview).toContain('data-ti-assembly-root="command-center"');
    expect(overview).toContain('data-ti-module="conduit"');
    expect(overview).toContain('data-ti-origin="left"');
    expect(overview).toContain('data-ti-origin="right"');
    expect(css).toContain('[data-ti-assembly="active"] [data-ti-module][data-ti-phase="assembling"]');
    const assemblingRule = css.match(/\[data-ti-assembly="active"\] \[data-ti-module\]\[data-ti-phase="assembling"\] \{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    expect(assemblingRule).toContain("pointer-events: none;");
    const lockedRule = css.match(/\[data-ti-assembly="active"\] \[data-ti-module\]\[data-ti-phase="locked"\] \{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    expect(lockedRule).toContain("pointer-events: auto;");
    expect(css).toContain("@keyframes ti-module-assemble");
    expect(css).toContain("@keyframes ti-conduit-deploy");
    expect(assembly).toContain('event.animationName !== "ti-module-assemble"');
    expect(assembly).toContain('module.dataset.tiPhase === "assembling" && lockTimers.has(module)');
    expect(assembly.indexOf('module.dataset.tiPhase === "assembling" && lockTimers.has(module)'))
      .toBeLessThan(assembly.indexOf('module.dataset.tiPhase = "assembling"'));
    expect(assembly).toContain('root.addEventListener("animationcancel", settleCompletedAnimation)');
    expect(assembly).toContain('module.dataset.tiPhase = "locked"');
    expect(assembly).toContain("MODULE_LOCK_SAFETY_MS");
    expect(assembly).toContain("module.dataset.tiOrder");
    expect(assembly).not.toContain(".style.setProperty");
    expect(assembly).not.toContain(".style.");
    expect(css).toContain("will-change: auto;");
    expect(css).not.toContain("will-change: transform, opacity, clip-path, filter;");
    expect(css).toContain("will-change: transform, opacity;");
    expect(particle).not.toContain("style={");
    expect(particle).not.toContain(".style.setProperty");
    expect(assembly).toContain("new MutationObserver");
    expect(assembly).toContain("record.addedNodes");
    expect(assembly).toContain("registerAddedModule");
  });

  test("keeps the retired measured-facet path isolated behind the approved-particle early return", () => {
    expect(assembly.indexOf('core.dataset.tiExplodedModel === "approved-particle-core"'))
      .toBeLessThan(assembly.indexOf('startCoreTransfer("release")'));
    expect(assembly).toContain("mapFacetDestinations");
    expect(assembly).toContain("moduleDestinationName");
    expect(assembly).toContain("destination.dataset.tiTransformDestination = name");
    expect(assembly).toContain("facet.dataset.tiDestination = destinationName");
    expect(assembly).toContain("const sourceRect = mapping.facet.getBoundingClientRect()");
    expect(assembly).toContain("const destinationRect = mapping.destination.getBoundingClientRect()");
    expect(assembly).toContain("ghost.dataset.tiSourceAnchor = measuredAnchor(sourceRect)");
    expect(assembly).toContain('layer.dataset.tiCoreTransferLayer = direction');
    expect(assembly).toContain("ghost.animate([");
    expect(assembly).toContain("animation.cancel()");
    expect(assembly).toContain('startCoreTransfer("recall")');
    expect(css).toContain(".ti-core-transfer-ghost--8");
  });

  test("uses accessible controls while their visible actuator mechanics remain decorative", () => {
    expect(primitives).toContain("<button");
    expect(primitives).toContain('className="os-button__mechanism" aria-hidden="true"');
    expect(primitives).toContain("<AppLink");
    expect(css).toContain("@keyframes ti-actuator-charge");
    expect(css).toContain("min-height: 44px");
  });

  test("halts viewport choreography when hidden and removes it for reduced motion", () => {
    expect(assembly).toContain('document.visibilityState === "hidden"');
    expect(assembly).toContain("observer?.disconnect()");
    expect(assembly).toContain('reducedMotion.addEventListener("change"');
    expect(assembly).toContain('reducedMotion.removeEventListener("change"');
    const reduced = css.match(/@media \(prefers-reduced-motion: reduce\)\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    expect(reduced).toContain(".ti-core-transfer-layer { display: none !important; }");
    expect(reduced).toContain(".ti-command-particle-core__brace");
    expect(particleRuntimeCss).toContain("@media (prefers-reduced-motion: reduce)");
    expect(particleRuntimeCss).toContain("animation: none;");
    expect(reduced).toContain("[data-ti-module]");
    expect(css.match(/\binfinite\b/gu)?.length).toBe(1);
  });

  test("keeps a rendered route silhouette across every mechanical commit frame", () => {
    expect(routeCss).toContain('html[data-route-transition="committing"] .ti-route-surface');
    expect(routeCss).toContain("opacity: .28;");
    expect(routeCss.match(/opacity: 0;/gu)?.length ?? 0).toBeGreaterThan(0);
    expect(routeCss).toContain("@keyframes ti-route-native-assemble");
  });
});

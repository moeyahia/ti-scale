import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../../../src/design-system/tokens/ti-scale.css", import.meta.url), "utf8");
const overview = readFileSync(new URL("../../../src/features/overview/OverviewPage.tsx", import.meta.url), "utf8");
const particle = readFileSync(new URL("../../../src/features/overview/CommandCenterParticleCore.tsx", import.meta.url), "utf8");
const particleRuntime = readFileSync(new URL("../../../src/features/motion-lab/ParticleCoreRuntime.tsx", import.meta.url), "utf8");
const shell = readFileSync(new URL("../../../src/app/shell/AppShell.tsx", import.meta.url), "utf8");

describe("Ti-Scale materially intelligent motion contract", () => {
  test("removes shell and hero grid/HUD primitives", () => {
    const shellBlock = css.match(/\.ti-scale\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    expect(shellBlock).toContain("background: var(--os-canvas);");
    expect(shellBlock).not.toContain("background-size:");
    expect(shellBlock).not.toContain("linear-gradient(var(--os-graph-grid)");
    for (const retiredPrimitive of [
      "ti-scale-core__field",
      "ti-scale-core__guide",
      "ti-scale-core__orbit",
      "ti-scale-core__node",
      "ti-guide-draw",
      "ti-orbit-calibrate",
    ]) {
      expect(`${particle}\n${css}`).not.toContain(retiredPrimitive);
    }
    expect(css).not.toContain("repeating-linear-gradient(135deg");
  });

  test("uses the approved local field, lazy renderer, and state choreography", () => {
    expect(particle).toContain('data-ti-particle-artwork="operator-approved"');
    expect(particle).toContain('import("../motion-lab/ParticleCoreRuntime")');
    expect(particle).toContain('BOOT_BOUNDARY_SELECTOR');
    expect(particle).toContain('bootBoundary.dataset.tiBootPhase === BOOT_COMPLETE_PHASE');
    expect(particle).toContain('attributeFilter: ["data-ti-boot-phase"]');
    expect(particle.indexOf('bootBoundary.dataset.tiBootPhase === BOOT_COMPLETE_PHASE'))
      .toBeLessThan(particle.indexOf("queueRuntime();"));
    expect(particle).toContain("Materializing approved particle core");
    expect(particleRuntime).toContain("uPointer");
    expect(particleRuntime).toContain("uHover");
    expect(particleRuntime).toContain("state.host.dataset.hoverActive");
    expect(css).toContain("@keyframes ti-title-materialize");
    expect(css).toContain("@keyframes ti-command-particle-materialize");
    expect(css).toContain("@keyframes ti-value-resolve");
    expect(overview).toContain("ti-command-hero__title-line");
    expect(overview).toContain("key={data.summary.activeMissions}");
    expect(css.match(/\binfinite\b/gu)?.length).toBe(1);
  });

  test("pauses hidden tabs and removes nonessential motion for reduced-motion users", () => {
    expect(shell).toContain('data-motion-state={motionState}');
    expect(shell).toContain('document.addEventListener("visibilitychange"');
    expect(css).toContain('.ti-scale[data-motion-state="paused"] *');
    const reduced = css.match(/@media \(prefers-reduced-motion: reduce\)\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    expect(reduced).toContain(".ti-core-transfer-layer { display: none !important; }");
    expect(reduced).toContain(".ti-command-particle-core__brace");
    expect(reduced).toContain(".ti-command-hero__title-line > span");
    expect(reduced).toContain("animation: none !important;");
    expect(particle).toContain("autoRotate={!reducedMotion}");
    expect(particle).toContain("hoverEnabled={!reducedMotion}");
  });

  test("keeps decorative braces inert while exposing one named keyboard and pointer surface", () => {
    expect(particle).toContain('aria-hidden="true"');
    expect(particleRuntime).toContain('renderer.domElement.setAttribute("role", "application")');
    expect(particleRuntime).toContain('renderer.domElement.setAttribute("aria-label", ariaLabel)');
    expect(particleRuntime).toContain('renderer.domElement.addEventListener("pointermove", onPointerMove)');
    expect(particleRuntime).toContain('renderer.domElement.addEventListener("keydown", onKeyDown)');
    expect(css).toContain("@media (hover: hover) and (pointer: fine)");
    expect(css).toContain("min-height: 44px");
  });

  test("keeps actuator depth out of WebKit's negative-z perspective compositor path", () => {
    const button = css.match(/\.os-button\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    const face = css.match(/\.os-button::before\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    const disabled = css.match(/\.os-button:disabled,[^\{]*\{(?<body>[\s\S]*?)\}/u)?.groups?.body ?? "";
    const paletteLayer = css.match(/\.os-palette-layer\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    expect(button).toContain("transform: none;");
    expect(button).not.toContain("isolation: isolate;");
    expect(button).not.toContain("translateZ(0)");
    expect(button).not.toContain("filter 260ms");
    expect(face).toContain("z-index: 0;");
    expect(disabled).not.toContain("filter:");
    expect(paletteLayer).not.toContain("backdrop-filter:");
    expect(css).not.toContain("perspective(320px)");
  });
});

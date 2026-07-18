import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../../../src/design-system/tokens/ti-scale.css", import.meta.url), "utf8");
const media = readFileSync(new URL("../../../src/design-system/components/BrandMedia.tsx", import.meta.url), "utf8");
const overview = readFileSync(new URL("../../../src/features/overview/OverviewPage.tsx", import.meta.url), "utf8");
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
      expect(`${media}\n${css}`).not.toContain(retiredPrimitive);
    }
    expect(css).not.toContain("repeating-linear-gradient(135deg");
  });

  test("uses finite titanium assembly, adaptive depth, and state choreography", () => {
    expect(media).toContain('className="ti-scale-core__architecture"');
    expect(media.match(/ti-scale-core__plate ti-scale-core__plate--/gu)).toHaveLength(3);
    expect(media).toContain("--ti-light-x");
    expect(media).toContain("--ti-depth-x");
    expect(css).toContain("@keyframes ti-title-materialize");
    expect(css).toContain("@keyframes ti-plate-arrive-far");
    expect(css).toContain("@keyframes ti-titanium-light-sweep");
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
    expect(reduced).toContain(".ti-scale-core__sheen,");
    expect(reduced).toContain(".ti-scale-core__shards { display: none !important; }");
    expect(reduced).toContain(".ti-command-hero__title-line > span");
    expect(reduced).toContain("animation: none !important;");
    expect(reduced).toContain("--ti-depth-x: 0px !important;");
  });

  test("keeps decorative motion inert to pointer and keyboard input", () => {
    expect(media).toContain('aria-hidden="true"');
    expect(css).toMatch(/\.ti-scale-core__architecture\s*\{[\s\S]*?pointer-events:\s*none;/u);
    expect(css).toMatch(/\.ti-scale-core__sheen\s*\{[\s\S]*?pointer-events:\s*none;/u);
    expect(css).toContain("@media (hover: hover) and (pointer: fine)");
    expect(css).toContain("min-height: 44px");
  });
});

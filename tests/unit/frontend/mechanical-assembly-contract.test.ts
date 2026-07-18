import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../../../src/design-system/tokens/ti-scale.css", import.meta.url), "utf8");
const media = readFileSync(new URL("../../../src/design-system/components/BrandMedia.tsx", import.meta.url), "utf8");
const overview = readFileSync(new URL("../../../src/features/overview/OverviewPage.tsx", import.meta.url), "utf8");
const primitives = readFileSync(new URL("../../../src/design-system/components/Primitives.tsx", import.meta.url), "utf8");
const assembly = readFileSync(new URL("../../../src/design-system/hooks/useMechanicalAssembly.ts", import.meta.url), "utf8");

describe("Ti-Scale mechanical assembly contract", () => {
  test("assembles the titanium core from a finite eight-part mechanism", () => {
    expect(media).toContain('data-ti-transformer-core="true"');
    expect(media).toContain("Array.from({ length: 8 }");
    expect(media).toContain("ti-scale-core__hud--north");
    expect(css).toContain("@keyframes ti-transformer-shard-lock");
    expect(css).toContain("@keyframes ti-hud-brace-lock");
    expect(css).toContain("animation: ti-transformer-shard-lock 1480ms");
  });

  test("deploys real command modules from the core and settles them after assembly", () => {
    expect(overview).toContain("useMechanicalAssembly()");
    expect(overview).toContain('data-ti-assembly-root="command-center"');
    expect(overview).toContain('data-ti-module="conduit"');
    expect(overview).toContain('data-ti-origin="left"');
    expect(overview).toContain('data-ti-origin="right"');
    expect(css).toContain('[data-ti-assembly="active"] [data-ti-module][data-ti-phase="assembling"]');
    expect(css).toContain("@keyframes ti-module-assemble");
    expect(css).toContain("@keyframes ti-conduit-deploy");
    expect(assembly).toContain('event.animationName !== "ti-module-assemble"');
    expect(assembly).toContain('module.dataset.tiPhase = "locked"');
    expect(assembly).toContain("new MutationObserver");
    expect(assembly).toContain("record.addedNodes");
    expect(assembly).toContain("registerAddedModule");
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
    expect(reduced).toContain(".ti-scale-core__shards { display: none !important; }");
    expect(reduced).toContain("[data-ti-module]");
    expect(css.match(/\binfinite\b/gu)?.length).toBe(1);
  });
});

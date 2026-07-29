import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../../../src/design-system/tokens/titanium-controls.css", import.meta.url), "utf8");
const primitives = readFileSync(new URL("../../../src/design-system/components/Primitives.tsx", import.meta.url), "utf8");

describe("titanium module chassis contract", () => {
  test("provides four deterministic asymmetric plate tokens", () => {
    for (const variant of ["keel", "aero", "prism", "truss"]) {
      expect(css).toContain(`--ti-plate-${variant}: polygon(`);
      expect(css).toContain(`[data-ti-plate="${variant}"]`);
    }
    expect(primitives).toContain('export const titaniumPlateVariants = ["keel", "aero", "prism", "truss"] as const;');
    expect(primitives).toContain("resolveTitaniumPlateVariant");
  });

  test("keeps the semantic card and disclosure plane unclipped", () => {
    const cardBlock = css.match(/\.os-card\[data-ti-plate\]\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    const chassisBlock = css.match(/\.os-card__chassis\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body ?? "";
    expect(css).toMatch(/\.os-card\[data-ti-plate\][\s\S]*?overflow:\s*visible;/u);
    expect(css).toMatch(/\.os-card__chassis\s*\{[\s\S]*?clip-path:\s*var\(--ti-plate-shape\);/u);
    expect(chassisBlock).toContain("z-index: 0;");
    expect(cardBlock).not.toContain("isolation: isolate;");
    expect(css).toMatch(/\.os-titanium-select__listbox\s*\{[\s\S]*?z-index:\s*var\(--os-z-portal-disclosure\);/u);
    expect(primitives).toContain('data-ti-chassis="module" aria-hidden="true"');
    expect(primitives).not.toContain("style={{");
  });

  test("keeps the high-churn intake contract on a static paint plane", () => {
    expect(css).toContain(".os-contract-form > .os-card[data-ti-plate]");
    expect(css).toContain("> .os-card__chassis { display: none; }");
    expect(css).toMatch(/\.os-contract-form > \.os-card\[data-ti-plate\]::before,[\s\S]*?\.os-contract-form > \.os-card\[data-ti-plate\]::after/u);
  });

  test("uses one finite transform-and-opacity hover mechanism with a static reduced-motion state", () => {
    expect(css).toContain("@media (hover: hover) and (pointer: fine)");
    expect(css).toContain("transition-property: transform, opacity;");
    expect(css).toContain(".os-card__fastener { transform: rotate(135deg); }");
    expect(css).toContain(".os-card__specular-seam");
    expect(css).toContain("@media (prefers-reduced-motion: reduce)");
    expect(css).toContain("transition: none !important;");
    expect(css).toContain("transform: rotate(45deg) !important;");
    expect(css).not.toContain("ti-chassis-infinite");
  });
});

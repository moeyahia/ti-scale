import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const tokenCss = readFileSync(new URL("../../../src/design-system/tokens/ti-scale.css", import.meta.url), "utf8");
const featureCss = readFileSync(new URL("../../../src/design-system/tokens/feature-surfaces.css", import.meta.url), "utf8");
const graphCanvas = readFileSync(new URL("../../../src/features/brain/MemoryGraphCanvas.tsx", import.meta.url), "utf8");
const appComposition = readFileSync(new URL("../../../src/App.tsx", import.meta.url), "utf8");
const applicationEntry = readFileSync(new URL("../../../src/main.tsx", import.meta.url), "utf8");
const indexHtml = readFileSync(new URL("../../../index.html", import.meta.url), "utf8");
const webManifest = JSON.parse(readFileSync(new URL("../../../public/manifest.webmanifest", import.meta.url), "utf8")) as {
  background_color?: string;
  theme_color?: string;
};
const playwrightConfig = readFileSync(new URL("../../../playwright.config.ts", import.meta.url), "utf8");

function token(name: string): string {
  const match = tokenCss.match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})\\s*;`, "u"));
  if (!match?.[1]) throw new Error(`Theme token --${name} is missing or is not a six-digit color`);
  return match[1];
}

function luminance(hex: string): number {
  const channels = hex.slice(1).match(/../gu)?.map((pair) => Number.parseInt(pair, 16) / 255);
  if (!channels || channels.length !== 3) throw new Error(`Cannot calculate luminance for ${hex}`);
  const [red, green, blue] = channels.map((channel) => (
    channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
  ));
  return (0.2126 * red!) + (0.7152 * green!) + (0.0722 * blue!);
}

function contrast(first: string, second: string): number {
  const [lighter, darker] = [luminance(first), luminance(second)].sort((left, right) => right - left);
  return (lighter! + 0.05) / (darker! + 0.05);
}

describe("Ti-Scale editorial titanium theme contract", () => {
  test("publishes warm light browser metadata and removes the former dark and neon surfaces", () => {
    expect(indexHtml).toContain('<meta name="theme-color" content="#fffefa" />');
    expect(indexHtml).toContain('<meta name="color-scheme" content="light" />');
    expect(webManifest).toMatchObject({ background_color: "#f4f2ee", theme_color: "#fffefa" });
    expect(tokenCss).toContain("color-scheme: light");
    expect(playwrightConfig).toContain('colorScheme: "light"');

    const productionThemeSources = [tokenCss, featureCss, graphCanvas].join("\n").toLowerCase();
    for (const retiredSurface of ["#080b0d", "#090d0f", "#0a0e14", "#b8f341", "#526f00", "rgba(8,11,13", "rgba(13,17,20"]) {
      expect(productionThemeSources).not.toContain(retiredSurface);
    }
  });

  test("uses titanium neutrals rather than green as the product identity", () => {
    expect(token("os-accent")).toBe("#343a40");
    expect(token("os-accent-bright")).toBe("#a99576");
    expect(token("os-metal")).toBe("#6c737a");
    expect(token("os-success")).toBe("#46525e");

    const brandContract = [tokenCss, featureCss].join("\n").toLowerCase();
    for (const retiredGreen of ["acid-lime", "chartreuse", "neon-green", "#b8f341", "#526f00"]) {
      expect(brandContract).not.toContain(retiredGreen);
    }
  });

  test("keeps the standalone V2 style graph isolated from legacy UI and global CSS", () => {
    const standaloneSources = [appComposition, applicationEntry, tokenCss, featureCss].join("\n").toLowerCase();
    for (const forbiddenImport of ["../webapp", "legacy/index.css", 'import "./index.css"']) {
      expect(standaloneSources).not.toContain(forbiddenImport);
    }
    expect(appComposition).toContain('import "./design-system/tokens/ti-scale.css"');
    expect(appComposition).toContain('import "./design-system/tokens/feature-surfaces.css"');
  });

  test("keeps all compact text and semantic colors AA-readable on operational surfaces", () => {
    const surface = token("os-surface-1");
    const canvas = token("os-canvas");
    for (const foreground of [
      "os-text",
      "os-text-secondary",
      "os-text-muted",
      "os-accent",
      "os-info",
      "os-success",
      "os-warning",
      "os-danger",
      "os-violet",
    ]) {
      expect(contrast(token(foreground), surface), `${foreground} on surface`).toBeGreaterThanOrEqual(4.5);
      expect(contrast(token(foreground), canvas), `${foreground} on canvas`).toBeGreaterThanOrEqual(4.5);
    }
    expect(contrast(token("os-on-accent"), token("os-accent")), "primary action label").toBeGreaterThanOrEqual(4.5);
    expect(contrast(token("os-focus"), surface), "focus indicator").toBeGreaterThanOrEqual(3);
  });

  test("keeps titanium technology cues token-driven and bounded motion optional", () => {
    expect(tokenCss).toContain("--os-canvas: #f4f2ee;");
    expect(tokenCss).toContain("--os-surface-1: #fffefa;");
    expect(tokenCss).toContain("--os-metal: #6c737a;");
    expect(tokenCss).toContain("--os-metal-warm: #8d795b;");
    expect(tokenCss).toContain("--os-graph-grid:");
    const shellBlock = tokenCss.match(/\.ti-scale\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body;
    expect(shellBlock).toContain("background: var(--os-canvas);");
    expect(shellBlock).not.toContain("background-size:");
    expect(shellBlock).not.toContain("linear-gradient(var(--os-graph-grid)");
    const authBlock = featureCss.match(/\.os-auth-shell\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body;
    expect(authBlock).toContain("background: var(--os-canvas);");
    expect(authBlock).not.toContain("background-size:");
    expect(graphCanvas).toContain('color("--os-graph-canvas"');
    expect(graphCanvas).toContain('node: color("--os-graph-node-titanium"');
    expect(graphCanvas).not.toContain("theme.grid");
    expect(graphCanvas).toContain('data-background-grid="removed"');
    expect(graphCanvas).toContain('data-background-artwork="removed"');
    expect(graphCanvas).toContain('data-anatomy-silhouette="removed"');
    expect(graphCanvas).toContain('data-spinal-silhouette="removed"');
    expect(graphCanvas).toContain('data-visual-theme="dark-titanium"');
    const graphWorkspaceBlock = featureCss.match(/\.ti-scale \.brain-graph-workspace\s*\{(?<body>[\s\S]*?)\n\}/u)?.groups?.body;
    expect(graphWorkspaceBlock).toContain("--os-graph-canvas:#0b1015;");
    expect(graphWorkspaceBlock).toContain("color-scheme:dark;");
    expect(graphWorkspaceBlock).not.toContain("--os-graph-grid");
    expect(graphCanvas).toContain('data-brain-anatomy="particle-cloud-3d"');
    expect(graphCanvas).toContain('data-node-language="unified-titanium-dots"');
    expect(graphCanvas).toContain('data-region-taxonomy="attack-knowledge"');
    expect(graphCanvas).toContain('data-renderer={rendererMode}');
    expect(graphCanvas).toContain('window.matchMedia("(prefers-reduced-motion: reduce)")');
    expect(graphCanvas).toContain('document.addEventListener("visibilitychange"');
    expect(graphCanvas).toContain("window.requestAnimationFrame(draw)");
    expect(graphCanvas).toContain("buildNeuronSignalRoutes(displayNodes, displayEdges, selectedId)");
    expect(tokenCss).toContain("@keyframes os-assembly-in");
    expect(tokenCss).toContain("@keyframes os-data-transfer");
    expect(tokenCss.match(/\binfinite\b/gu)?.length).toBe(1);
    expect(tokenCss).toContain("@media (prefers-reduced-motion: reduce)");
  });

  test("constrains stacked operational sections to the mobile content track", () => {
    expect(featureCss).toContain(
      ".ti-scale .os-section-stack { min-width:0; grid-template-columns:minmax(0,1fr); }",
    );
  });

  test("renders the in-flight plan boundary as a readable responsive titanium surface", () => {
    expect(featureCss).toContain(".os-plan-change-resolution {");
    expect(featureCss).toContain("box-shadow: inset 3px 0 0 var(--os-accent);");
    expect(featureCss).toContain(".os-plan-change-work-grid,");
    expect(featureCss).toContain(".os-plan-change-resolution-options {");
    expect(featureCss).toContain("grid-template-columns: repeat(2, minmax(0, 1fr));");
    expect(featureCss).toContain(".os-plan-change-work-grid li strong,");
    expect(featureCss).toContain(".os-plan-change-work-grid li span,");
    expect(featureCss).toContain(".os-plan-change-work-grid li small {");
    expect(featureCss).toContain(".os-plan-change-resolution-options { grid-template-columns: 1fr; }");
  });
});

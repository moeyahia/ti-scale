import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  BRAIN_AMBIENT_PARTICLE_ALPHA,
  BRAIN_NODE_HIT_RADIUS_PX,
  BRAIN_NODE_VISUAL_SCALE,
  brainNodeHitRadius,
  brainNodeVisualDiameter,
  brainNodeVisualRadius,
  nearestBrainNodeHit,
  stableCollapsedClusterHit,
} from "../../../src/features/brain/brainVisualLanguage";

const root = resolve(import.meta.dir, "../../..");
const canvasSource = readFileSync(resolve(root, "src/features/brain/MemoryGraphCanvas.tsx"), "utf8");
const webglSource = readFileSync(resolve(root, "src/features/brain/BrainAtlasWebGLRenderer.ts"), "utf8");
const featureCss = readFileSync(resolve(root, "src/design-system/tokens/feature-surfaces.css"), "utf8");

function luminance(hex: string): number {
  const channels = hex.match(/[a-f\d]{2}/giu)?.map((value) => Number.parseInt(value, 16) / 255) ?? [];
  return channels.reduce((sum, channel, index) => {
    const linear = channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
    return sum + linear * [0.2126, 0.7152, 0.0722][index]!;
  }, 0);
}

function contrast(foreground: string, background: string): number {
  const [lighter, darker] = [luminance(foreground), luminance(background)].sort((left, right) => right - left);
  return (lighter! + 0.05) / (darker! + 0.05);
}

describe("Brain particle visual language", () => {
  test("draws smaller unified nodes while retaining 44px pointer targets", () => {
    expect(BRAIN_NODE_VISUAL_SCALE).toBeGreaterThan(0.7);
    expect(BRAIN_NODE_VISUAL_SCALE).toBeLessThan(1);
    expect(brainNodeVisualRadius(10, 1)).toBe(8.2);
    expect(brainNodeVisualDiameter(10)).toBe(16.4);
    expect(BRAIN_NODE_HIT_RADIUS_PX * 2).toBe(44);
    expect(brainNodeHitRadius(brainNodeVisualRadius(10))).toBe(BRAIN_NODE_HIT_RADIUS_PX);
  });

  test("selects the nearest visible node when 44px hit areas overlap", () => {
    const candidates = [
      { id: "farther-pointer", x: 105, y: 100, radius: 5, depth: -0.4 },
      { id: "nearest-pointer", x: 101, y: 100, radius: 5, depth: 0.4 },
      { id: "hidden-at-centre", x: 100, y: 100, radius: 5, visible: false },
    ] as const;
    expect(nearestBrainNodeHit(candidates, { x: 100, y: 100 })).toBe("nearest-pointer");
    expect(nearestBrainNodeHit(candidates, { x: 200, y: 200 })).toBeUndefined();
  });

  test("uses projected depth and then stable identity for exact-distance ties", () => {
    expect(nearestBrainNodeHit([
      { id: "behind", x: 100, y: 100, radius: 5, depth: 0.4 },
      { id: "front", x: 100, y: 100, radius: 5, depth: -0.4 },
    ], { x: 100, y: 100 })).toBe("front");
    expect(nearestBrainNodeHit([
      { id: "z-node", x: 100, y: 100, radius: 5 },
      { id: "a-node", x: 100, y: 100, radius: 5 },
    ], { x: 100, y: 100 })).toBe("a-node");
  });

  test("keeps collapsed aggregate nodes deterministic while the visible particle projection rotates", () => {
    const logicalLayout = [
      { id: "canonical-neighbor", x: 101, y: 100, radius: 5 },
      { id: "cluster:operator", x: 104, y: 100, radius: 6 },
    ] as const;
    expect(stableCollapsedClusterHit(logicalLayout, { x: 100, y: 100 })).toBe("cluster:operator");
    expect(stableCollapsedClusterHit([
      { id: "canonical-only", x: 100, y: 100, radius: 6 },
    ], { x: 100, y: 100 })).toBeUndefined();
  });

  test("uses visibly brighter ambient particles across every retained region", () => {
    expect(Object.keys(BRAIN_AMBIENT_PARTICLE_ALPHA)).toEqual([
      "frontal", "parietal", "temporal", "occipital", "cerebellum", "stem",
    ]);
    expect(Math.min(...Object.values(BRAIN_AMBIENT_PARTICLE_ALPHA))).toBeGreaterThanOrEqual(0.62);
    expect(featureCss).toContain("--os-graph-cloud:#e2e9ee;");
    expect(featureCss).toContain("--os-graph-node-titanium:#f0f4f7;");
  });

  test("renders only particles, canonical nodes, and real edges without anatomy artwork", () => {
    expect(canvasSource).not.toContain("buildBrainAtlasGuideSegments");
    expect(canvasSource).not.toContain("drawBrainAnatomy");
    expect(webglSource).not.toContain("buildBrainAtlasGuideSegments");
    expect(webglSource).not.toContain("drawAnatomicalGuides");
    expect(canvasSource).not.toContain("brain-anatomy-legend");
    expect(featureCss).not.toContain(".brain-anatomy-legend");
    expect(featureCss).toContain("background-image:none!important;");
    expect(canvasSource).toContain('data-category-color-legend="removed"');
  });

  test("freezes the GPU particle clock when reduced motion is active", () => {
    expect(canvasSource).toContain("time: motionEnabled ? now : 0,");
    expect(canvasSource).not.toContain("time: now,");
  });

  test("keeps every selected-memory inspector action readable on dark titanium", () => {
    expect(featureCss).toContain(".brain-inspector-actions .os-button");
    expect(featureCss).toContain(".brain-inspector-actions .os-button:hover");
    expect(featureCss).toContain(".brain-inspector-actions .os-button:focus-visible");
    expect(featureCss).toContain(".brain-inspector-actions .os-button:active::before");
    expect(featureCss).toContain('.brain-inspector-actions .os-button[aria-disabled="true"]');
    expect(contrast("#f3f7f9", "#1b242d")).toBeGreaterThan(4.5);
    expect(contrast("#aab5bd", "#151c23")).toBeGreaterThan(4.5);
  });

  test("keeps compact outcome evidence readable on the dark titanium summary", () => {
    const outcomeSurfaces = [
      ["#5d6973", "#f4f4f1"],
      ["#5d6973", "#f5f5f2"],
      ["#b9def2", "#1c2b35"],
      ["#ff9aac", "#262129"],
      ["#aab7c0", "#1c232a"],
      ["#b9def2", "#1a2229"],
      ["#ff9aac", "#1a2229"],
      ["#d1c3ec", "#1a2229"],
      ["#b8c3cb", "#1a2229"],
    ] as const;
    for (const [foreground, background] of outcomeSurfaces) {
      expect(contrast(foreground, background)).toBeGreaterThanOrEqual(4.5);
    }
    expect(featureCss).toContain(".brain-outcome-summary .brain-outcome-badge--success { color:#b9def2; }");
    expect(featureCss).toContain(".brain-outcome-summary .brain-outcome-badge--failed { color:#ff9aac; }");
    expect(featureCss).toContain(".brain-outcome-summary .brain-reported-outcome-badge--mixed { color:#d1c3ec; }");
    expect(featureCss).toContain(".brain-outcome-badge--unclassified { border-color:rgba(94,106,116,.28); background:rgba(102,114,124,.07); color:#5d6973; }");
    expect(featureCss).toContain(".brain-reported-outcome-badge--not_reported { border-color:rgba(94,106,116,.28); color:#5d6973; }");
    expect(featureCss.toLowerCase()).not.toContain("green");
  });
});

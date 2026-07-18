import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { PRIMARY_NAVIGATION } from "../../../src/app/router/routes";
import accessibilityInventory from "../../accessibility-state-inventory.json";

const source = readFileSync(
  new URL("../../e2e/accessibility-axe.spec.ts", import.meta.url),
  "utf8",
);
const tokenSource = readFileSync(
  new URL("../../../src/design-system/tokens/ti-scale.css", import.meta.url),
  "utf8",
);

const MATERIAL_STATES = [
  "overview-command-palette-open",
  "autonomous-intake-scope",
  "guided-intake-scope",
  "versioned-plan-workspace",
  "guided-waiting-decision",
  "evidence-review",
  "finding-review",
  "second-brain-graph-canvas",
  "second-brain-graph-table",
  "connected-obsidian-vault",
  "blocked-run-failure-diagnosis",
  "learning-research",
  "observability-trace-review",
  "report-review",
  "system-policies",
  "system-settings",
] as const;

type Rgb = readonly [number, number, number];

function hexToken(name: string): Rgb {
  const value = tokenSource.match(new RegExp(`--${name}:\\s*#([0-9a-f]{6})`, "iu"))?.[1];
  if (!value) throw new Error(`Missing six-digit color token --${name}`);
  return [0, 2, 4].map((offset) => Number.parseInt(value.slice(offset, offset + 2), 16)) as unknown as Rgb;
}

function rgbaToken(name: string): { readonly rgb: Rgb; readonly alpha: number } {
  const value = tokenSource.match(new RegExp(
    `--${name}:\\s*rgba\\(\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*,\\s*([0-9]+)\\s*,\\s*([0-9.]+)\\s*\\)`,
    "iu",
  ));
  if (!value) throw new Error(`Missing rgba color token --${name}`);
  return {
    rgb: [Number(value[1]), Number(value[2]), Number(value[3])],
    alpha: Number(value[4]),
  };
}

function composite(foreground: Rgb, background: Rgb, alpha: number): Rgb {
  return foreground.map((channel, index) => Math.round(
    channel * alpha + background[index]! * (1 - alpha),
  )) as unknown as Rgb;
}

function luminance(color: Rgb): number {
  const linear = color.map((channel) => {
    const value = channel / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * linear[0]! + 0.7152 * linear[1]! + 0.0722 * linear[2]!;
}

function contrast(first: Rgb, second: Rgb): number {
  const a = luminance(first);
  const b = luminance(second);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

describe("automated accessibility gate policy", () => {
  test("keeps every axe WCAG A/AA rule enabled and fails on every violation", () => {
    expect(accessibilityInventory.wcagTags).toEqual([
      "wcag2a",
      "wcag2aa",
      "wcag21a",
      "wcag21aa",
      "wcag22aa",
    ]);
    expect(source).toContain('runOnly: { type: "tag", values: input.tags }');
    expect(source).toContain("iframes: true");
    expect(source).toContain("page.addInitScript({ path: AXE_MIN_PATH })");
    expect(source).toContain("runtime.version !== input.expectedVersion");
    expect(source).toContain("MAX_RUNTIME_EVALUATION_SOURCE_BYTES");
    expect(source).not.toContain("AxeBuilder");
    expect(source).not.toContain("page.evaluate(this.script())");
    expect(source).not.toContain(".disableRules(");
    expect(source).not.toContain(".exclude(");
    expect(source).toContain("violations,");
    expect(source).toContain(").toEqual([]);");
  });

  test("machine-readable inventory exactly covers primary routes and bounded high-risk states", () => {
    expect(accessibilityInventory.schemaVersion).toBe(1);
    const ids = accessibilityInventory.states.map((state) => state.id);
    expect(new Set(ids).size).toBe(ids.length);

    const primary = accessibilityInventory.states
      .filter((state) => state.kind === "primary-initial")
      .map((state) => state.route);
    expect(primary).toEqual(PRIMARY_NAVIGATION.map((item) => item.path));

    const material = accessibilityInventory.states
      .filter((state) => state.kind === "material")
      .map((state) => state.id);
    expect(material).toEqual([...MATERIAL_STATES]);
    expect(accessibilityInventory.states).toHaveLength(PRIMARY_NAVIGATION.length + MATERIAL_STATES.length);

    for (const state of accessibilityInventory.states) {
      expect(state.id.length).toBeGreaterThan(0);
      expect(state.route.startsWith("/")).toBe(true);
      expect(state.surface.length).toBeGreaterThan(0);
      expect(state.fixture.length).toBeGreaterThan(0);
      expect(source).toContain(`\"${state.id}\"`);
    }
  });

  test("danger status text keeps AA contrast on selected data rows", () => {
    const surface = hexToken("os-surface-1");
    const selectedOverlay = rgbaToken("os-accent-soft");
    const dangerOverlay = rgbaToken("os-danger-soft");
    const selectedRow = composite(selectedOverlay.rgb, surface, selectedOverlay.alpha);
    const dangerPill = composite(dangerOverlay.rgb, selectedRow, dangerOverlay.alpha);
    expect(contrast(hexToken("os-danger-text"), dangerPill)).toBeGreaterThanOrEqual(4.5);
    expect(tokenSource).toContain("color: var(--os-danger-text)");
  });

  test("Brain graph accessibility waits for the worker in development and immutable release builds", () => {
    expect(source).toContain('response.url().includes("memoryGraphLayout.worker")');
    expect(source).not.toContain('/src/workers/memoryGraphLayout.worker.ts');
  });
});

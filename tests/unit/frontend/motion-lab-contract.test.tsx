import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import MotionLabPage from "../../../src/features/motion-lab/MotionLabPage";
import {
  MOTION_LAB_MANIFEST_PATH,
  parseMotionLabManifest,
} from "../../../src/features/motion-lab/motionManifest";

const manifestJson = JSON.parse(readFileSync(new URL(`../../../public/${MOTION_LAB_MANIFEST_PATH}`, import.meta.url), "utf8")) as unknown;
const pageSource = readFileSync(new URL("../../../src/features/motion-lab/MotionLabPage.tsx", import.meta.url), "utf8");
const motionCss = readFileSync(new URL("../../../src/features/motion-lab/motion-lab.css", import.meta.url), "utf8");
const routeSource = readFileSync(new URL("../../../src/app/router/RouteView.tsx", import.meta.url), "utf8");
const moduleSource = readFileSync(new URL("../../../src/app/router/routeModules.ts", import.meta.url), "utf8");

describe("Ti-Scale isolated motion review", () => {
  test("parses only real, local, ordered Higgsfield assets", () => {
    const manifest = parseMotionLabManifest(manifestJson);
    expect(manifest.status).toBe("ready");
    expect(manifest.stages.map((stage) => stage.id)).toEqual([
      "locked-assembled",
      "engineering-explosion",
      "architectural-chassis",
    ]);
    expect(manifest.stages.every((stage) => stage.imagePath.startsWith("brand-v2/optimized/higgsfield-motion/"))).toBe(true);
    expect(manifest.stages[0]?.width).toBe(2560);
    expect(manifest.motion).toEqual(expect.objectContaining({
      path: "brand-v2/optimized/higgsfield-motion/04-transformation-titanium-matte-1440p.mp4",
      mimeType: "video/mp4",
      durationSeconds: 15.042,
    }));
  });

  test("accepts a highest-quality local video receipt without a code change", () => {
    const manifest = parseMotionLabManifest({
      ...(manifestJson as Record<string, unknown>),
      status: "ready",
      motion: {
        path: "brand-v2/source/higgsfield-motion/04-transformation-4k.mp4",
        mimeType: "video/mp4",
        durationSeconds: 9.4,
        posterPath: "brand-v2/source/higgsfield-motion/01-locked-assembled-b00afa65.png",
        width: 3840,
        height: 2160,
      },
    });
    expect(manifest.motion).toEqual(expect.objectContaining({
      path: "brand-v2/source/higgsfield-motion/04-transformation-4k.mp4",
      durationSeconds: 9.4,
    }));
  });

  test("rejects remote, escaping, malformed, and duplicate media declarations", () => {
    const input = manifestJson as Record<string, unknown>;
    const stages = input.stages as Array<Record<string, unknown>>;
    expect(() => parseMotionLabManifest({ ...input, stages: [{ ...stages[0], imagePath: "https://example.test/core.png" }] })).toThrow("must stay inside");
    expect(() => parseMotionLabManifest({ ...input, stages: [{ ...stages[0], imagePath: "brand-v2/source/higgsfield-motion/../secret.png" }] })).toThrow("must stay inside");
    expect(() => parseMotionLabManifest({ ...input, stages: [stages[0], stages[0]] })).toThrow("duplicate IDs");
    expect(() => parseMotionLabManifest({ ...input, motion: { path: "brand-v2/source/higgsfield-motion/a.mov", mimeType: "video/quicktime" } })).toThrow("motion.mimeType");
  });

  test("renders an honest pre-manifest state and keeps the review route lazy and isolated", () => {
    const markup = renderToStaticMarkup(<MotionLabPage />);
    expect(markup).toContain("TI-SCALE · MOTION LAB");
    expect(markup).toContain("Generation in progress");
    expect(markup).toContain('role="status"');
    expect(routeSource).toContain('pathname === "/motion-lab"');
    expect(moduleSource).toContain('import("../../features/motion-lab/MotionLabPage")');
    expect(moduleSource).toContain('pathname === "/motion-lab"');
  });

  test("owns paginated, scrubbable, reduced-motion and touch/keyboard controls without synthetic artwork", () => {
    expect(pageSource).toContain('aria-label="Titanium motion review stage"');
    expect(pageSource).toContain('aria-label="Motion timeline"');
    expect(pageSource).toContain('aria-label="Previous motion stage"');
    expect(pageSource).toContain('aria-label="Next motion stage"');
    expect(pageSource).toContain('aria-label={playing ? "Pause motion" : "Play motion"}');
    expect(pageSource).toContain("onWheel={onWheel}");
    expect(pageSource).toContain("onTouchStart={onTouchStart}");
    expect(pageSource).toContain("onKeyDown={onKeyDown}");
    expect(pageSource).toContain("prefers-reduced-motion: reduce");
    expect(motionCss).toContain("@media (prefers-reduced-motion: reduce)");
    expect(motionCss).not.toContain("repeating-linear-gradient");
    expect(motionCss).not.toContain("background-image");
    expect(motionCss).not.toContain("mix-blend-mode");
    expect(motionCss).not.toMatch(/\b(?:green|neon|lime)\b/iu);
    expect(pageSource).not.toContain("<svg");
    expect(pageSource).not.toContain("mock");
  });
});

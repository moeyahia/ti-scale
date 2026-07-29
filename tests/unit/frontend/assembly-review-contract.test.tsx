import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { MeshStandardMaterial } from "three";
import AssemblyReviewPage from "../../../src/features/motion-lab/AssemblyReviewPage";
import {
  assertEmbeddedReviewGlb,
  cloneReviewMeshMaterial,
  countVisibleReviewPixels,
} from "../../../src/features/motion-lab/AssemblyReviewRuntime";
import {
  ASSEMBLY_REVIEW_MANIFEST_PATH,
  parseAssemblyReviewManifest,
} from "../../../src/features/motion-lab/assemblyReviewManifest";

const packageManifest = JSON.parse(
  readFileSync(new URL("../../../package.json", import.meta.url), "utf8"),
) as { name?: unknown };
const manifestPath = new URL(`../../../public/${ASSEMBLY_REVIEW_MANIFEST_PATH}`, import.meta.url);
const manifestJson = JSON.parse(readFileSync(manifestPath, "utf8")) as unknown;
const manifest = parseAssemblyReviewManifest(manifestJson);
const runtimeSource = readFileSync(new URL("../../../src/features/motion-lab/AssemblyReviewRuntime.tsx", import.meta.url), "utf8");
const pageSource = readFileSync(new URL("../../../src/features/motion-lab/AssemblyReviewPage.tsx", import.meta.url), "utf8");
const routeSource = readFileSync(new URL("../../../src/app/router/RouteView.tsx", import.meta.url), "utf8");
const routeModuleSource = readFileSync(new URL("../../../src/app/router/routeModules.ts", import.meta.url), "utf8");
const motionLabSource = readFileSync(new URL("../../../src/features/motion-lab/MotionLabPage.tsx", import.meta.url), "utf8");
const routeCasesSource = readFileSync(new URL("../../e2e/support/routes.ts", import.meta.url), "utf8");
const bundleBudgetSource = readFileSync(new URL("../../../scripts/meshy-webgl-bundle-budget.ts", import.meta.url), "utf8");
const stagingSource = readFileSync(new URL("../../../scripts/stage-14-element-review.ts", import.meta.url), "utf8");

describe("Ti-Scale locked 14-element assembly review", () => {
  test("parses exactly 14 content-addressed models and 26 owner-bound fasteners inside fixed budgets", () => {
    expect(manifest.status).toBe("review-candidate");
    expect(manifest.reviewBoundary).toBe("Review candidate — not approved for hero");
    expect(manifest.models).toHaveLength(14);
    expect(manifest.fasteners).toHaveLength(26);
    expect(new Set(manifest.models.map((model) => model.id)).size).toBe(14);
    expect(new Set(manifest.fasteners.map((fastener) => fastener.id)).size).toBe(26);
    expect(manifest.models.reduce((sum, model) => sum + model.triangleCount, 0)).toBe(5_334);
    expect(manifest.models.reduce((sum, model) => sum + model.meshPrimitiveCount, 0)).toBe(41);
    expect(manifest.models.reduce((sum, model) => sum + model.bytes, 0)).toBe(587_532);
    expect(manifest.fasteners.every((fastener) => manifest.models.some((model) => model.id === fastener.owner))).toBe(true);
    expect(manifest.models.every((model) => model.path.endsWith(`${model.sha256.slice(0, 12)}.glb`))).toBe(true);
    expect(manifest.fastenerGeometry).toEqual(expect.objectContaining({ kind: "instanced-low-profile-cap", count: 26 }));
    expect(manifest.visualIntegrity).toEqual(expect.objectContaining({
      expectedModelMeshCount: 41,
      minimumDrawCalls: 42,
      minimumVisibleModelCoverage: 0.03,
    }));
  });

  test("the public review copies are byte-for-byte identical to every locked digest", () => {
    for (const model of manifest.models) {
      const bytes = readFileSync(new URL(`../../../public/${model.path}`, import.meta.url));
      expect(bytes.byteLength, model.id).toBe(model.bytes);
      expect(createHash("sha256").update(bytes).digest("hex"), model.id).toBe(model.sha256);
      const copy = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(copy).set(bytes);
      assertEmbeddedReviewGlb(copy);
    }
  });

  test("fails closed on approval drift, path escape, digest drift, missing models, and unowned hardware", () => {
    const value = manifestJson as Record<string, unknown>;
    const models = value.models as Array<Record<string, unknown>>;
    const fasteners = value.fasteners as Array<Record<string, unknown>>;
    expect(() => parseAssemblyReviewManifest({ ...value, status: "operator-approved" })).toThrow("review-candidate");
    expect(() => parseAssemblyReviewManifest({ ...value, reviewBoundary: "Approved" })).toThrow("reviewBoundary");
    expect(() => parseAssemblyReviewManifest({ ...value, models: [{ ...models[0], path: "../escape.glb" }, ...models.slice(1)] })).toThrow("must stay inside");
    expect(() => parseAssemblyReviewManifest({ ...value, models: [{ ...models[0], sha256: "0".repeat(64) }, ...models.slice(1)] })).toThrow("content addressed");
    expect(() => parseAssemblyReviewManifest({ ...value, models: models.slice(1) })).toThrow("14 unique locked models");
    expect(() => parseAssemblyReviewManifest({ ...value, fasteners: [{ ...fasteners[0], owner: "UNKNOWN" }, ...fasteners.slice(1)] })).toThrow("model owner");
  });

  test("keeps element 01 derivation explicit and all other transforms canonical", () => {
    const first = manifest.models[0]!;
    expect(first.id).toBe("NW_TI_OVERPLATE_02");
    expect(first.pivot.pixel).toEqual([678.5, 176.5]);
    expect(first.canonicalization.uniformScale).toBeCloseTo(0.454501938, 8);
    expect(first.pivot.provenance).toContain("F09/F10 midpoint");
    expect(manifest.models.slice(1).every((model) => model.canonicalization.uniformScale === 1)).toBe(true);
    expect(manifest.models.every((model) => model.assembly.quaternion.w === 1)).toBe(true);
  });

  test("preserves scalar material shape and detects model-only framebuffer coverage", () => {
    const scalar = new MeshStandardMaterial({ color: "#8c949d" });
    const scalarClone = cloneReviewMeshMaterial(scalar);
    expect(Array.isArray(scalarClone)).toBe(false);
    expect(scalarClone).not.toBe(scalar);

    const second = new MeshStandardMaterial({ color: "#24282d" });
    const arrayClone = cloneReviewMeshMaterial([scalar, second]);
    expect(Array.isArray(arrayClone)).toBe(true);
    if (!Array.isArray(arrayClone)) throw new Error("The array material clone lost its array shape.");
    expect(arrayClone).toHaveLength(2);
    expect(arrayClone[0]).not.toBe(scalar);
    expect(arrayClone[1]).not.toBe(second);

    const blank = new Uint8Array([243, 241, 237, 255, 243, 241, 237, 255]);
    const withSurface = new Uint8Array([243, 241, 237, 255, 42, 49, 57, 255]);
    expect(countVisibleReviewPixels(blank)).toBe(0);
    expect(countVisibleReviewPixels(withSurface)).toBe(1);
    expect(() => countVisibleReviewPixels(new Uint8Array(3))).toThrow("visual integrity buffer");

    scalar.dispose();
    second.dispose();
    arrayClone.forEach((material) => material.dispose());
    if (!Array.isArray(scalarClone)) scalarClone.dispose();
    expect(runtimeSource).toContain("state.fasteners.visible = false");
    expect(runtimeSource).toContain("gl.readPixels");
    expect(runtimeSource).toContain("visible plate coverage was");
    expect(runtimeSource).toContain("state.target.copy(sphere.center)");
    expect(runtimeSource).toContain("horizontalHalfFov");
    expect(runtimeSource).toContain("corner.project(state.camera)");
    expect(runtimeSource).toContain('state.host.dataset.projectedFasteners = "26"');
  });

  test("retains the rejected candidate as provenance while its route redirects to particle core", () => {
    expect(routeSource).toContain('pathname === "/motion-lab/assembly") route = <Redirect to="/motion-lab/particle-core" />');
    expect(routeModuleSource).toContain('pathname === "/motion-lab/assembly") return loadParticleCoreReviewPage');
    expect(routeModuleSource).not.toContain('import("../../features/motion-lab/AssemblyReviewPage")');
    expect(motionLabSource).not.toContain('href="/motion-lab/assembly"');
    expect(motionLabSource).not.toContain("Review 14-element assembly");
    expect(routeCasesSource).toContain('{ id: "motion-lab-assembly-retired-alias", path: "/motion-lab/assembly", expectedPath: "/motion-lab/particle-core" }');
    const activeChunks = bundleBudgetSource.match(/const ACTIVE_WEBGL_CHUNKS[\s\S]+?\] as const\);/u)?.[0] ?? "";
    expect(activeChunks).not.toContain("AssemblyReviewPage");
    expect(activeChunks).not.toContain("AssemblyReviewRuntime");
    expect(pageSource).toContain("{resolved.reviewBoundary}");
    expect(pageSource).toContain('aria-label="Assembly explosion progress"');
    expect(pageSource).toContain('aria-label="Accessible assembly element list"');
    expect(pageSource).toContain('aria-label={`Inspect element');
    expect(runtimeSource).toContain("new InstancedMesh");
    expect(runtimeSource).toContain("crypto.subtle.digest");
    expect(runtimeSource).toContain("manifest.fastenerGeometry.count");
    expect(runtimeSource).toContain("model.explosion.unseatWorld");
    expect(runtimeSource).not.toContain("Math.random");
    expect(stagingSource).toContain('generatedAt: asString(lock.locked_at');
    expect(stagingSource).toContain("await copyFile(sourcePath, stagedPath)");
    expect(renderToStaticMarkup(<AssemblyReviewPage />)).toContain("Verifying the locked 14-element assembly manifest");
    expect(packageManifest.name).toBe("@ti-scale/platform");
  });
});

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import MeshyWebglPage from "../../../src/features/meshy-webgl/MeshyWebglPage";
import {
  adjacentMeshyState,
  advanceMeshyTransition,
  beginMeshyTransition,
  resolvePartTransform,
  settledMeshyMotion,
} from "../../../src/features/meshy-webgl/meshyMotionState";
import {
  APPROVED_IDENTITY_SOURCE_PATH,
  MESHY_WEBGL_LIMITS,
  parseApprovedMeshyWebglManifest,
  type MeshyWebglManifest,
} from "../../../src/features/meshy-webgl/meshyWebglManifest";

const pageSource = readFileSync(new URL("../../../src/features/meshy-webgl/MeshyWebglPage.tsx", import.meta.url), "utf8");
const runtimeSource = readFileSync(new URL("../../../src/features/meshy-webgl/MeshyWebglRuntime.tsx", import.meta.url), "utf8");
const css = readFileSync(new URL("../../../src/features/meshy-webgl/meshy-webgl.css", import.meta.url), "utf8");
const bundleBudgetSource = readFileSync(new URL("../../../scripts/meshy-webgl-bundle-budget.ts", import.meta.url), "utf8");
const serverSource = readFileSync(new URL("../../../server/index.ts", import.meta.url), "utf8");
const contentSecurityPolicySource = readFileSync(new URL("../../../server/security/ContentSecurityPolicy.ts", import.meta.url), "utf8");
const packageJson = JSON.parse(readFileSync(new URL("../../../package.json", import.meta.url), "utf8")) as {
  dependencies: Record<string, string>;
};

function transform(x = 0, y = 0, z = 0) {
  return {
    position: { x, y, z },
    rotationRadians: { x: 0, y: 0, z: 0 },
    scale: { x: 1, y: 1, z: 1 },
  };
}

function approvedManifest(): Record<string, unknown> {
  const sha256 = "a".repeat(64);
  return {
    schemaVersion: 1,
    status: "operator-approved",
    identitySourcePath: APPROVED_IDENTITY_SOURCE_PATH,
    approval: {
      receiptId: "approval_operator_0001",
      approvedAt: "2026-07-18T17:00:00Z",
      approvedBy: "operator",
    },
    model: {
      path: `brand-v2/optimized/meshy-webgl/ti-scale-core-${sha256.slice(0, 12)}.glb`,
      sha256,
      bytes: 1_024,
      triangleCount: 120_000,
      maximumTextureDimension: 2_048,
      container: "glb-embedded",
      compression: "meshopt",
    },
    camera: {
      position: { x: 0, y: 0, z: 6 },
      target: { x: 0, y: 0, z: 0 },
      fieldOfViewDegrees: 34,
      near: 0.1,
      far: 100,
    },
    fallback: {
      path: APPROVED_IDENTITY_SOURCE_PATH,
      alt: "Approved layered titanium, graphite, and gold core.",
      width: 1344,
      height: 768,
    },
    parts: [
      {
        id: "upper-plate",
        nodeName: "TiScale_UpperPlate",
        sectionId: "command",
        localNormal: { x: 0, y: 1, z: 0 },
        explodeDistance: 1.5,
        chassis: transform(-1, 0.5, 0),
        sectionFormation: transform(-2, 1, 0),
      },
      {
        id: "lower-plate",
        nodeName: "TiScale_LowerPlate",
        sectionId: "intelligence",
        localNormal: { x: 0, y: -1, z: 0 },
        explodeDistance: 1.25,
        chassis: transform(1, -0.5, 0),
        sectionFormation: transform(2, -1, 0),
      },
    ],
  };
}

describe("operator-gated Meshy WebGL foundation", () => {
  test("accepts only a content-addressed, bounded, operator-approved GLB receipt", () => {
    const manifest = parseApprovedMeshyWebglManifest(approvedManifest());
    expect(manifest.status).toBe("operator-approved");
    expect(manifest.identitySourcePath).toBe(APPROVED_IDENTITY_SOURCE_PATH);
    expect(manifest.model.path).toContain(manifest.model.sha256.slice(0, 12));
    expect(manifest.model.bytes).toBeLessThanOrEqual(MESHY_WEBGL_LIMITS.maximumModelBytes);
    expect(manifest.model.triangleCount).toBeLessThanOrEqual(MESHY_WEBGL_LIMITS.maximumTriangles);
    expect(manifest.parts).toHaveLength(2);
  });

  test("rejects candidates, identity substitutions, unversioned paths, and delivery-budget overruns", () => {
    const input = approvedManifest();
    expect(() => parseApprovedMeshyWebglManifest({ ...input, status: "candidate" })).toThrow("operator-approved");
    expect(() => parseApprovedMeshyWebglManifest({ ...input, identitySourcePath: "brand-v2/source/other.png" })).toThrow("approved Ti-Scale identity");
    expect(() => parseApprovedMeshyWebglManifest({
      ...input,
      model: { ...(input.model as Record<string, unknown>), path: "brand-v2/optimized/meshy-webgl/model.glb" },
    })).toThrow("content-addressed");
    expect(() => parseApprovedMeshyWebglManifest({
      ...input,
      model: { ...(input.model as Record<string, unknown>), bytes: MESHY_WEBGL_LIMITS.maximumModelBytes + 1 },
    })).toThrow("delivery budget");
    expect(() => parseApprovedMeshyWebglManifest({
      ...input,
      fallback: { ...(input.fallback as Record<string, unknown>), path: "brand-v2/optimized/higgsfield-motion/03-destination-transparent.webp" },
    })).toThrow("approved identity source");
  });

  test("moves authored parts along local normals and reverses through deterministic assembly states", () => {
    const manifest = parseApprovedMeshyWebglManifest(approvedManifest());
    const upper = manifest.parts[0]!;
    const exploding = beginMeshyTransition(settledMeshyMotion("assembled"), "exploded");
    const halfway = advanceMeshyTransition(exploding, 600, 1_200);
    const resolved = resolvePartTransform(upper, halfway);
    expect(resolved.position.x).toBe(0);
    expect(resolved.position.y).toBeCloseTo(0.75, 5);
    expect(resolved.position.z).toBe(0);
    expect(advanceMeshyTransition(halfway, 600, 1_200)).toEqual(expect.objectContaining({
      from: "exploded",
      to: "exploded",
      progress: 1,
    }));
    expect(adjacentMeshyState("assembled", -1)).toBe("assembled");
    expect(adjacentMeshyState("assembled", 1)).toBe("exploded");
    expect(adjacentMeshyState("section-formation", -1)).toBe("chassis");
    expect(beginMeshyTransition(settledMeshyMotion("section-formation"), "assembled")).toEqual(expect.objectContaining({
      from: "section-formation",
      to: "assembled",
      progress: 0,
    }));
  });

  test("renders the approved static identity while the asset gate is unresolved", () => {
    const markup = renderToStaticMarkup(<MeshyWebglPage />);
    expect(markup).toContain("Material transformation runtime");
    expect(markup).toContain("3D runtime gated");
    expect(markup).toContain(APPROVED_IDENTITY_SOURCE_PATH);
    expect(markup).toContain("Checking for an operator-approved 3D model");
    expect(markup).not.toContain("canvas");
  });

  test("keeps Three.js in a nested lazy chunk and enforces bounded, shadow-free rendering", () => {
    expect(pageSource).toContain('import("./MeshyWebglRuntime")');
    expect(pageSource).not.toContain('from "@react-three/fiber"');
    expect(runtimeSource).toContain("Math.min(globalThis.devicePixelRatio || 1, MESHY_WEBGL_LIMITS.maximumDevicePixelRatio)");
    expect(runtimeSource).toContain("renderer.setAnimationLoop(null)");
    expect(runtimeSource).toContain("renderer.shadowMap.enabled = false");
    expect(runtimeSource).toContain("renderer.forceContextLoss()");
    expect(runtimeSource).toContain('import("three/addons/loaders/GLTFLoader.js")');
    expect(runtimeSource).toContain('import("three/addons/libs/meshopt_decoder.module.js")');
    expect(runtimeSource).not.toContain("<mesh");
    expect(runtimeSource).not.toContain("Geometry />");
    expect(runtimeSource).not.toContain("Grid");
    expect(runtimeSource).not.toContain("ContactShadow");
    expect(runtimeSource).not.toContain("castShadow={true}");
    expect(css).not.toContain("linear-gradient");
    expect(css).not.toContain("box-shadow");
    expect(css).not.toContain("filter: drop-shadow");
    expect(bundleBudgetSource).toContain("MeshyWebglRuntime: 150 * 1024");
    expect(bundleBudgetSource).toContain("gzipSync(output.code");
    expect(bundleBudgetSource).toContain("Unapproved Meshy candidate files are inside Vite's public directory");
    expect(bundleBudgetSource).toContain('brand-v2/optimized/meshy-webgl');
    expect(bundleBudgetSource).toContain("must have exactly one optimized GLB and one approval manifest");
    expect(bundleBudgetSource).toContain('createHash("sha256")');
    expect(serverSource).toContain("media-src 'self' blob:");
    expect(serverSource).toContain("applicationConnectSourceDirective(),");
    expect(contentSecurityPolicySource).toContain("return \"connect-src 'self' blob:\";");
    expect(packageJson.dependencies["@react-three/fiber"]).toBeUndefined();
    expect(packageJson.dependencies.three).toBe("0.185.1");
  });
});

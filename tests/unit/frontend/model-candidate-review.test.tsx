import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { parseModelCandidateReview } from "../../../src/domain/schemas/modelCandidateReview";
import ModelCandidateReviewPage from "../../../src/features/motion-lab/ModelCandidateReviewPage";
import { assertReviewGlb } from "../../../src/features/motion-lab/CandidateModelRuntime";

const pageSource = readFileSync(new URL("../../../src/features/motion-lab/ModelCandidateReviewPage.tsx", import.meta.url), "utf8");
const runtimeSource = readFileSync(new URL("../../../src/features/motion-lab/CandidateModelRuntime.tsx", import.meta.url), "utf8");
const routeSource = readFileSync(new URL("../../../src/app/router/RouteView.tsx", import.meta.url), "utf8");

function availableReview(): Record<string, unknown> {
  const asset = (id: string, kind: string, mimeType: string, extra: Record<string, unknown>) => ({
    id,
    kind,
    label: id,
    description: `Review asset ${id}`,
    mimeType,
    bytes: 1_024,
    sha256: "a".repeat(64),
    url: `/api/v2/motion-lab/review/assets/${id}`,
    ...extra,
  });
  return {
    schemaVersion: 1,
    availability: "available",
    candidateId: "pilot-review-01",
    status: "candidate",
    reviewState: "unreviewed",
    title: "Isolated component pilot",
    summary: "Review-only comparison",
    generatedAt: "2026-07-18T19:31:36.000Z",
    provenance: { imageTaskId: "image-01", modelTaskId: "model-01", imageCredits: 9, modelCredits: 30 },
    approval: { authority: "operator", receiptId: null, decidedAt: null },
    assets: [
      asset("source-view-a", "source-image", "image/png", { width: 655, height: 768 }),
      asset("source-view-b", "source-image", "image/png", { width: 655, height: 768 }),
      asset("turntable-fallback", "turntable-image", "image/jpeg", { width: 1744, height: 1308 }),
      asset("model-glb", "model-glb", "model/gltf-binary", { triangleCount: 56_063, vertexCount: 35_545 }),
    ],
  };
}

function minimalGlb(descriptor: Record<string, unknown>): ArrayBuffer {
  const encoded = new TextEncoder().encode(JSON.stringify(descriptor));
  const paddedLength = Math.ceil(encoded.length / 4) * 4;
  const bytes = new Uint8Array(20 + paddedLength);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x4654_6c67, true);
  view.setUint32(4, 2, true);
  view.setUint32(8, bytes.length, true);
  view.setUint32(12, paddedLength, true);
  view.setUint32(16, 0x4e4f_534a, true);
  bytes.fill(0x20, 20);
  bytes.set(encoded, 20);
  return bytes.buffer as ArrayBuffer;
}

describe("isolated Motion Lab model candidate review", () => {
  test("strictly parses the authenticated manifest and preserves operator-owned approval", () => {
    const review = parseModelCandidateReview(availableReview());
    expect(review).toMatchObject({
      availability: "available",
      status: "candidate",
      reviewState: "unreviewed",
      approval: { authority: "operator", receiptId: null },
    });
    expect(review.availability === "available" && review.assets).toHaveLength(4);
    expect(() => parseModelCandidateReview({ ...availableReview(), status: "approved", reviewState: "approved" })).toThrow("operator approval receipt");
    const escaped = availableReview();
    const assets = escaped.assets as Array<Record<string, unknown>>;
    expect(() => parseModelCandidateReview({
      ...escaped,
      assets: [{ ...assets[0], url: "https://example.test/source.png" }, ...assets.slice(1)],
    })).toThrow("authenticated review-only API route");
  });

  test("accepts only embedded GLB 2.0 containers at the browser boundary", () => {
    expect(() => assertReviewGlb(minimalGlb({ asset: { version: "2.0" }, buffers: [] }))).not.toThrow();
    expect(() => assertReviewGlb(minimalGlb({ asset: { version: "2.0" }, buffers: [{ uri: "remote.bin" }] }))).toThrow("secondary asset requests");
    expect(() => assertReviewGlb(new ArrayBuffer(12))).toThrow("bounded GLB");
  });

  test("starts with no canvas and lazy-loads the candidate renderer only after operator intent", () => {
    const markup = renderToStaticMarkup(<ModelCandidateReviewPage />);
    expect(markup).toContain("Loading the isolated 3D candidate review");
    expect(markup).not.toContain("canvas");
    expect(pageSource).toContain('import("./CandidateModelRuntime")');
    expect(pageSource).toContain("This is a review surface, not an approval action.");
    expect(pageSource).toContain("Nothing on this page can place the model in the hero");
    expect(runtimeSource).toContain("renderer.shadowMap.enabled = false");
    expect(runtimeSource).toContain("renderer.forceContextLoss()");
    expect(runtimeSource).toContain("The candidate GLB may not make secondary asset requests");
    expect(routeSource).toContain('pathname === "/motion-lab/candidates"');
  });
});

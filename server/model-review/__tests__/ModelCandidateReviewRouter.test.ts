import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import express from "express";
import {
  MODEL_CANDIDATE_REVIEW_API,
  MODEL_CANDIDATE_REVIEW_MANIFEST,
  createModelCandidateReviewRouter,
  parseModelCandidateReviewManifest,
} from "..";

const directories: string[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function digest(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), ".ti-scale-model-review-"));
  directories.push(root);
  const files = {
    sourceA: new Uint8Array([1, 2, 3]),
    sourceB: new Uint8Array([4, 5, 6]),
    turntable: new Uint8Array([7, 8, 9]),
    model: new Uint8Array([10, 11, 12, 13]),
  };
  writeFileSync(join(root, "source-a.png"), files.sourceA);
  writeFileSync(join(root, "source-b.png"), files.sourceB);
  writeFileSync(join(root, "turntable.jpg"), files.turntable);
  writeFileSync(join(root, "model.glb"), files.model);
  const manifest = {
    schemaVersion: 1,
    candidateId: "candidate-review-01",
    status: "candidate",
    reviewState: "unreviewed",
    title: "Isolated titanium component",
    summary: "Operator-only comparison of source images and generated geometry.",
    generatedAt: "2026-07-18T19:31:36.000Z",
    provenance: {
      imageTaskId: "image-task-01",
      modelTaskId: "model-task-01",
      imageCredits: 9,
      modelCredits: 30,
    },
    approval: { authority: "operator", receiptId: null, decidedAt: null },
    assets: [
      { id: "source-view-a", kind: "source-image", label: "Source A", description: "First source", mimeType: "image/png", relativePath: "source-a.png", bytes: files.sourceA.length, sha256: digest(files.sourceA), width: 10, height: 20 },
      { id: "source-view-b", kind: "source-image", label: "Source B", description: "Second source", mimeType: "image/png", relativePath: "source-b.png", bytes: files.sourceB.length, sha256: digest(files.sourceB), width: 10, height: 20 },
      { id: "turntable-fallback", kind: "turntable-image", label: "Turntable", description: "Static fallback", mimeType: "image/jpeg", relativePath: "turntable.jpg", bytes: files.turntable.length, sha256: digest(files.turntable), width: 20, height: 20 },
      { id: "model-glb", kind: "model-glb", label: "Model", description: "Review model", mimeType: "model/gltf-binary", relativePath: "model.glb", bytes: files.model.length, sha256: digest(files.model), triangleCount: 12, vertexCount: 10 },
    ],
  };
  writeFileSync(join(root, MODEL_CANDIDATE_REVIEW_MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`);
  return { root, manifest, files };
}

async function harness(reviewRoot?: string) {
  const app = express();
  app.use(createModelCandidateReviewRouter(reviewRoot ? { reviewRoot } : {}));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await once(server, "listening");
  const port = (server.address() as AddressInfo).port;
  return `http://127.0.0.1:${port}`;
}

describe("isolated model candidate review boundary", () => {
  test("reports an optional unconfigured boundary without exposing a static asset root", async () => {
    const origin = await harness();
    const response = await fetch(`${origin}${MODEL_CANDIDATE_REVIEW_API}`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(response.headers.get("x-ti-scale-review-only")).toBe("true");
    expect(await response.json()).toMatchObject({ schemaVersion: 1, availability: "not_configured" });
  });

  test("validates every file once and serves only manifest-addressed review assets", async () => {
    const { root, files } = fixture();
    const origin = await harness(root);
    const response = await fetch(`${origin}${MODEL_CANDIDATE_REVIEW_API}`);
    const manifest = await response.json() as Record<string, any>;
    expect(manifest).toMatchObject({
      schemaVersion: 1,
      availability: "available",
      status: "candidate",
      reviewState: "unreviewed",
      approval: { authority: "operator", receiptId: null },
    });
    expect(manifest.assets).toHaveLength(4);
    expect(JSON.stringify(manifest)).not.toContain(root);
    expect(JSON.stringify(manifest)).not.toContain("relativePath");

    const image = await fetch(`${origin}${MODEL_CANDIDATE_REVIEW_API}/assets/source-view-a`);
    expect(image.status).toBe(200);
    expect(image.headers.get("content-type")).toContain("image/png");
    expect(image.headers.get("cache-control")).toBe("private, no-store");
    expect(new Uint8Array(await image.arrayBuffer())).toEqual(files.sourceA);
    expect((await fetch(`${origin}${MODEL_CANDIDATE_REVIEW_API}/assets/../../etc/passwd`)).status).toBe(404);
    expect((await fetch(`${origin}${MODEL_CANDIDATE_REVIEW_API}/assets/unknown`)).status).toBe(404);
  });

  test("rejects promotion without an operator receipt, path escape, and post-manifest tampering", () => {
    const { root, manifest } = fixture();
    expect(() => parseModelCandidateReviewManifest({
      ...manifest,
      status: "approved",
      reviewState: "approved",
    })).toThrow("operator approval receipt");
    expect(() => parseModelCandidateReviewManifest({
      ...manifest,
      assets: [
        { ...manifest.assets[0], relativePath: "../outside.png" },
        ...manifest.assets.slice(1),
      ],
    })).toThrow("configured review root");
    writeFileSync(join(root, "model.glb"), new Uint8Array([99, 98, 97, 96]));
    expect(() => createModelCandidateReviewRouter({ reviewRoot: root })).toThrow("SHA-256 integrity");
  });

  test("is mounted only after the standalone API authentication middleware", () => {
    const serverSource = readFileSync(new URL("../../index.ts", import.meta.url), "utf8");
    const authentication = serverSource.indexOf('web.use("/api/v2", (request, response, next) =>');
    const review = serverSource.indexOf("web.use(createModelCandidateReviewRouter");
    expect(authentication).toBeGreaterThan(-1);
    expect(review).toBeGreaterThan(authentication);
  });
});

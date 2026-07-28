import { expect, test } from "./support/playwright";
import { createHash } from "node:crypto";

const TEST_ID = "e2e.motion-lab.candidate-review";
const REVIEW_API = "/api/v2/motion-lab/review";
const TRANSPARENT_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M/wHwAF/gL+Av4j2QAAAABJRU5ErkJggg==",
  "base64",
);

function reviewGlb(): Buffer {
  const binary = Buffer.alloc(44);
  const positions = new Float32Array([-1, -1, 0, 1, -1, 0, 0, 1, 0]);
  Buffer.from(positions.buffer).copy(binary, 0);
  new Uint16Array(binary.buffer, binary.byteOffset + 36, 3).set([0, 1, 2]);
  const descriptor = {
    asset: { version: "2.0", generator: "Ti-Scale review fixture" },
    scene: 0,
    scenes: [{ nodes: [0] }],
    nodes: [{ name: "ReviewTriangle", mesh: 0 }],
    meshes: [{ primitives: [{ attributes: { POSITION: 0 }, indices: 1 }] }],
    buffers: [{ byteLength: binary.byteLength }],
    bufferViews: [
      { buffer: 0, byteOffset: 0, byteLength: 36, target: 34962 },
      { buffer: 0, byteOffset: 36, byteLength: 6, target: 34963 },
    ],
    accessors: [
      { bufferView: 0, componentType: 5126, count: 3, type: "VEC3", min: [-1, -1, 0], max: [1, 1, 0] },
      { bufferView: 1, componentType: 5123, count: 3, type: "SCALAR" },
    ],
  };
  const json = Buffer.from(JSON.stringify(descriptor));
  const jsonLength = Math.ceil(json.length / 4) * 4;
  const total = 12 + 8 + jsonLength + 8 + binary.length;
  const glb = Buffer.alloc(total, 0x20);
  glb.writeUInt32LE(0x4654_6c67, 0);
  glb.writeUInt32LE(2, 4);
  glb.writeUInt32LE(total, 8);
  glb.writeUInt32LE(jsonLength, 12);
  glb.writeUInt32LE(0x4e4f_534a, 16);
  json.copy(glb, 20);
  const binaryHeader = 20 + jsonLength;
  glb.writeUInt32LE(binary.length, binaryHeader);
  glb.writeUInt32LE(0x004e_4942, binaryHeader + 4);
  binary.copy(glb, binaryHeader + 8);
  return glb;
}

const REVIEW_GLB = reviewGlb();

function manifest() {
  const asset = (id: string, kind: string, mimeType: string, extra: Record<string, unknown>) => ({
    id,
    kind,
    label: id === "source-view-a" ? "Source view A" : id === "source-view-b" ? "Source view B" : id,
    description: `Review-only ${id}`,
    mimeType,
    bytes: kind === "model-glb" ? REVIEW_GLB.byteLength : TRANSPARENT_PNG.byteLength,
    sha256: kind === "model-glb" ? createHash("sha256").update(REVIEW_GLB).digest("hex") : "a".repeat(64),
    url: `${REVIEW_API}/assets/${id}`,
    ...extra,
  });
  return {
    schemaVersion: 1,
    availability: "available",
    candidateId: "pilot-review-01",
    status: "candidate",
    reviewState: "unreviewed",
    title: "North-west titanium ribbon — per-part pilot",
    summary: "Review the two generated sources and resulting model together.",
    generatedAt: "2026-07-18T19:31:36.000Z",
    provenance: { imageTaskId: "image-task-01", modelTaskId: "model-task-01", imageCredits: 9, modelCredits: 30 },
    approval: { authority: "operator", receiptId: null, decidedAt: null },
    assets: [
      asset("source-view-a", "source-image", "image/png", { width: 655, height: 768 }),
      asset("source-view-b", "source-image", "image/png", { width: 655, height: 768 }),
      asset("turntable-fallback", "turntable-image", "image/jpeg", { width: 1744, height: 1308 }),
      asset("model-glb", "model-glb", "model/gltf-binary", { triangleCount: 1, vertexCount: 3 }),
    ],
  };
}

async function installFixture(page: import("@playwright/test").Page, modelRequests: string[]) {
  await page.route(`**${REVIEW_API}`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(manifest()),
  }));
  await page.route(`**${REVIEW_API}/assets/*`, (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/model-glb")) {
      modelRequests.push(path);
      return route.fulfill({ status: 200, contentType: "model/gltf-binary", body: REVIEW_GLB });
    }
    return route.fulfill({ status: 200, contentType: "image/png", body: TRANSPARENT_PNG });
  });
}

test(`${TEST_ID} compares both source outputs and downloads no GLB before explicit review intent`, async ({ page, browserAudit }) => {
  const modelRequests: string[] = [];
  await installFixture(page, modelRequests);
  await page.goto("/motion-lab", { waitUntil: "domcontentloaded" });
  const candidateLink = page.getByRole("link", { name: "Review 3D pilot", exact: true });
  await expect(candidateLink).toBeVisible();
  await candidateLink.click();
  await expect(page).toHaveURL(/\/motion-lab\/candidates$/u);

  await expect(page.getByRole("heading", { level: 1, name: "North-west titanium ribbon — per-part pilot", exact: true })).toBeVisible();
  await expect(page.getByText("Candidate · unreviewed", { exact: true })).toBeVisible();
  await expect(page.getByText("This is a review surface, not an approval action.", { exact: true })).toBeVisible();
  await expect(page.getByRole("tab", { name: /Source view A/u })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("img", { name: /Source view A/u })).toBeVisible();
  expect(modelRequests).toEqual([]);

  await page.getByRole("tab", { name: /Source view B/u }).click();
  await expect(page.getByRole("img", { name: /Source view B/u })).toBeVisible();
  expect(modelRequests).toEqual([]);

  await page.getByRole("tab", { name: /3D candidate/u }).click();
  await expect(page.getByRole("img", { name: /turntable-fallback/u })).toBeVisible();
  await expect(page.getByText("The 3D model has not been downloaded. Load it only when you are ready to inspect it.", { exact: true })).toBeVisible();
  expect(modelRequests).toEqual([]);

  await page.getByRole("button", { name: "Load 3D candidate", exact: true }).click();
  await expect.poll(() => modelRequests.length).toBe(1);
  await expect(page.getByText("Candidate model verified against its review manifest. It remains unapproved.", { exact: true })).toBeVisible();
  await expect(page.locator("canvas")).toHaveCount(1);
  const play = page.getByRole("button", { name: "Play turntable", exact: true });
  await play.click();
  await expect(page.getByRole("button", { name: "Pause turntable", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Pause turntable", exact: true }).click();
  await page.getByRole("button", { name: "Rotate candidate left", exact: true }).click();
  await page.getByRole("button", { name: "Rotate candidate right", exact: true }).click();
  await page.getByRole("button", { name: "Reset candidate view", exact: true }).click();
  await browserAudit.waitForPageApiSettlement(page);
});

test(`${TEST_ID} uses the static turntable and exposes no model loader under reduced motion`, async ({ page, browserAudit }) => {
  const modelRequests: string[] = [];
  await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
  await installFixture(page, modelRequests);
  await page.goto("/motion-lab/candidates", { waitUntil: "domcontentloaded" });
  await page.getByRole("tab", { name: /3D candidate/u }).click();
  await expect(page.getByText("Reduced motion is active. The verified twelve-angle contact sheet is shown instead of live rotation.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Load 3D candidate", exact: true })).toHaveCount(0);
  await expect(page.locator("canvas")).toHaveCount(0);
  expect(modelRequests).toEqual([]);
  await browserAudit.waitForPageApiSettlement(page);
});

test(`${TEST_ID} clears the shell header and hides the skip link until keyboard focus`, async ({ page, browserAudit }) => {
  const modelRequests: string[] = [];
  await installFixture(page, modelRequests);
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.goto("/motion-lab/candidates", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { level: 1, name: "North-west titanium ribbon — per-part pilot", exact: true })).toBeVisible();

  const assertReadableGeometry = async () => {
    const geometry = await page.evaluate(() => {
      const topbar = document.querySelector<HTMLElement>(".os-topbar")?.getBoundingClientRect();
      const pageHeader = document.querySelector<HTMLElement>(".candidate-review > .os-page-header")?.getBoundingClientRect();
      const title = document.querySelector<HTMLElement>(".candidate-review > .os-page-header h1")?.getBoundingClientRect();
      const boundary = document.querySelector<HTMLElement>(".candidate-review__decision-boundary")?.getBoundingClientRect();
      if (!topbar || !pageHeader || !title || !boundary) return null;
      return {
        topbarBottom: topbar.bottom,
        pageHeaderTop: pageHeader.top,
        titleLeft: title.left,
        titleRight: title.right,
        boundaryLeft: boundary.left,
        boundaryRight: boundary.right,
        viewportWidth: window.innerWidth,
      };
    });
    expect(geometry).not.toBeNull();
    expect(geometry!.pageHeaderTop).toBeGreaterThanOrEqual(geometry!.topbarBottom + 12);
    expect(geometry!.titleLeft).toBeGreaterThanOrEqual(0);
    expect(geometry!.titleRight).toBeLessThanOrEqual(geometry!.viewportWidth);
    expect(geometry!.boundaryLeft).toBeGreaterThanOrEqual(0);
    expect(geometry!.boundaryRight).toBeLessThanOrEqual(geometry!.viewportWidth);
  };

  await assertReadableGeometry();
  await page.setViewportSize({ width: 1024, height: 768 });
  await assertReadableGeometry();

  const skipLink = page.getByRole("link", { name: "Skip to content", exact: true });
  await expect(skipLink).toHaveCSS("opacity", "0");
  await expect(skipLink).toHaveCSS("pointer-events", "none");
  await expect(skipLink).toHaveCSS("overflow", "hidden");
  expect(await skipLink.evaluate((element) => {
    const style = getComputedStyle(element);
    return { width: style.width, height: style.height, clipPath: style.clipPath };
  })).toEqual({ width: "1px", height: "1px", clipPath: "inset(50%)" });
  await skipLink.focus();
  await expect(skipLink).toBeFocused();
  await expect(skipLink).toHaveCSS("opacity", "1");
  await expect(skipLink).toHaveCSS("pointer-events", "auto");
  const focusedSkipBounds = await skipLink.boundingBox();
  expect(focusedSkipBounds).not.toBeNull();
  expect(focusedSkipBounds!.y).toBeGreaterThanOrEqual(0);
  expect(focusedSkipBounds!.y + focusedSkipBounds!.height).toBeLessThanOrEqual(768);
  await page.locator("#ti-scale-content").focus();
  await expect(skipLink).toHaveCSS("opacity", "0");
  await expect(skipLink).toHaveCSS("pointer-events", "none");
  expect(modelRequests).toEqual([]);
  await browserAudit.waitForPageApiSettlement(page);
});

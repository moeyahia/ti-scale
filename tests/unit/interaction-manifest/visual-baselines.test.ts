import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import manifestJson from "../../interaction-manifest.json";
import baselineRegistry from "../../interaction-manifest/visual-baselines.json";
import { validateInteractionManifest } from "../../interaction-manifest/schema";

const root = resolve(import.meta.dirname, "../../..");
const manifest = validateInteractionManifest(manifestJson);

describe("Ti-Scale approved visual baseline registry", () => {
  test("reverse-maps every declared baseline to the exact represented material interactions", () => {
    expect(baselineRegistry.schemaVersion).toBe(1);
    expect(baselineRegistry.approvalScope).toBe("automated-drift-baseline");
    expect(baselineRegistry.humanReleaseApproval).toBe(false);
    expect(baselineRegistry.scope).toContain("do not imply cross-browser visual approval or release sign-off");
    expect(baselineRegistry.baselines).toHaveLength(13);

    const registryIds = baselineRegistry.baselines.map((baseline) => baseline.id);
    const mappedIds = manifest.entries.flatMap((entry) => entry.screenshotsRequired);
    expect(new Set(registryIds).size).toBe(registryIds.length);
    expect([...new Set(mappedIds)].sort()).toEqual([...registryIds].sort());
    expect(manifest.entries.filter((entry) => entry.screenshotsRequired.length > 0)).toHaveLength(30);
    expect(manifest.entries.filter((entry) => entry.screenshotsRequired.length === 0)).toHaveLength(465);

    for (const baseline of baselineRegistry.baselines) {
      expect(baseline.id).toMatch(/^visual\.[a-z0-9][a-z0-9.-]+$/u);
      expect(baseline.project).toBe("chromium-1440");
      expect(baseline.viewport).toBe("1440x900");
      expect(baseline.platform).toBe("linux");
      expect(baseline.state.length).toBeGreaterThan(30);
      expect(baseline.normalizedFields.length).toBeGreaterThan(0);

      const reverseMapped = manifest.entries
        .filter((entry) => entry.screenshotsRequired.includes(baseline.id))
        .map((entry) => entry.id)
        .sort();
      expect(reverseMapped, baseline.id).toEqual([...baseline.interactionIds].sort());
      for (const interactionId of baseline.interactionIds) {
        const entry = manifest.entries.find((candidate) => candidate.id === interactionId);
        expect(entry, `${baseline.id} -> ${interactionId}`).toBeDefined();
        expect(entry?.testIds, interactionId).toContain(baseline.testId);
        expect(entry?.browsers, interactionId).toContain("chromium");
        expect(entry?.viewports, interactionId).toContain(baseline.viewport);
      }
    }
  });

  test("integrity-binds each mapping to its browser assertion and exact PNG bytes", () => {
    for (const baseline of baselineRegistry.baselines) {
      const snapshotStem = baseline.snapshotName.replace(/\.png$/u, "");
      const sourceName = baseline.sourceFile.split("/").at(-1);
      expect(sourceName, baseline.sourceFile).toBeTruthy();
      expect(baseline.baselinePath, baseline.id).toBe(
        `tests/e2e/${sourceName}-snapshots/${snapshotStem}-${baseline.project}-${baseline.platform}.png`,
      );
      const sourcePath = resolve(root, baseline.sourceFile);
      const baselinePath = resolve(root, baseline.baselinePath);
      expect(existsSync(sourcePath), baseline.sourceFile).toBe(true);
      expect(existsSync(baselinePath), baseline.baselinePath).toBe(true);

      const source = readFileSync(sourcePath, "utf8");
      expect(source, baseline.id).toContain(baseline.id);
      expect(source, baseline.snapshotName).toContain(baseline.snapshotName);
      expect(source, baseline.testId).toContain(baseline.testId);
      expect(source, baseline.sourceFile).toContain("toHaveScreenshot");

      const png = readFileSync(baselinePath);
      expect(png.subarray(0, 8).toString("hex"), baseline.baselinePath).toBe("89504e470d0a1a0a");
      expect(png.byteLength, baseline.baselinePath).toBe(baseline.byteSize);
      expect(png.readUInt32BE(16), baseline.baselinePath).toBe(baseline.pixelWidth);
      expect(png.readUInt32BE(20), baseline.baselinePath).toBe(baseline.pixelHeight);
      expect(createHash("sha256").update(png).digest("hex"), baseline.baselinePath).toBe(baseline.sha256);
    }
  });
});

import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import manifestJson from "../../interaction-manifest.json";
import baselineRegistry from "../../interaction-manifest/visual-baselines.json";
import { validateInteractionManifest } from "../../interaction-manifest/schema";

const root = resolve(import.meta.dirname, "../../..");
const manifest = validateInteractionManifest(manifestJson);
type PendingVisualBaseline = {
  id: string;
  interactionIds: readonly string[];
  testId: string;
  carrierTitle: string;
  sourceFile: string;
  project: string;
  viewport: string;
  platform: string;
  snapshotName: string;
  state: string;
  normalizedFields: readonly string[];
  captureReason: string;
};
const pendingBaselines = baselineRegistry.pendingBaselines as readonly PendingVisualBaseline[];
const PROJECT_VIEWPORTS = {
  "chromium-1440": "1440x900",
  "android-chromium-390": "390x844",
} as const;
const AUTONOMOUS_REVIEW_INTERACTION_IDS = [
  "autonomous-intake.scope.template",
  "autonomous-intake.scope.targets",
  "autonomous-intake.scope.environment-classification",
  "autonomous-intake.outcome.title",
  "autonomous-intake.outcome.objective",
  "autonomous-intake.contract.recommended-defaults",
  "autonomous-intake.contract.budget",
  "autonomous-intake.contract.action-classes",
  "autonomous-intake.contract.deliverables",
  "autonomous-intake.contract.evidence",
  "autonomous-intake.contract.safe-stops",
  "autonomous-intake.team.specialists",
  "autonomous-intake.review.launch-blocked-guard",
] as const;
const EVIDENCE_VERIFICATION_INTERACTION_IDS = [
  "operational-truth.begin-validation",
  "operational-truth.verify.reason",
  "operational-truth.verify.source",
  "operational-truth.verify.target",
  "operational-truth.verify.acquired-at",
  "operational-truth.verify.confidence",
  "operational-truth.verify.method",
  "operational-truth.verify.explanation",
  "operational-truth.verify.custody-actor",
  "operational-truth.verify.custody-time",
  "operational-truth.verify.additional-requirements",
  "operational-truth.verify.confirmation",
  "operational-truth.verify.submit",
] as const;

describe("Ti-Scale approved and pending visual baseline registry", () => {
  test("bounds the Autonomous intake baseline to outputs visible in the final review receipt", () => {
    const baseline = baselineRegistry.baselines.find(
      ({ id }) => id === "visual.autonomous-intake.minimal-review.chromium-1440",
    );
    expect(baseline).toBeDefined();
    expect(baseline?.interactionIds).toEqual([...AUTONOMOUS_REVIEW_INTERACTION_IDS]);
    expect(baseline?.state).toContain("bounded post-reset review receipt");
    expect(baselineRegistry.scope).toContain("do not imply coverage of earlier intake edit controls");

    const deliberatelyUnmappedEditStates = [
      "autonomous-intake.scope.authorization",
      "autonomous-intake.outcome.success-criteria",
      "autonomous-intake.contract.destructive-policy",
      "autonomous-intake.contract.bounded-lab-target",
      "autonomous-intake.contract.deliverable-controls",
      "autonomous-intake.contract.evidence-controls",
      "autonomous-intake.contract.safe-stop-controls",
      "autonomous-intake.team.recommended",
      "autonomous-intake.context.scopes",
      "autonomous-intake.context.memories",
      "autonomous-intake.readiness.audit-checks",
    ];
    for (const id of deliberatelyUnmappedEditStates) {
      const entry = manifest.entries.find((candidate) => candidate.id === id);
      expect(entry, id).toBeDefined();
      expect(entry?.screenshotsRequired, id).not.toContain(baseline?.id);
    }
  });

  test("maps Begin validation only to its directly visible non-evidence verification result", () => {
    const baseline = baselineRegistry.baselines.find(
      ({ id }) => id === "visual.operational-truth.evidence-verification.chromium-1440",
    );
    expect(baseline).toBeDefined();
    expect(baseline?.interactionIds).toEqual([...EVIDENCE_VERIFICATION_INTERACTION_IDS]);
    expect(baseline?.state).toContain("candidate remains non-evidence");
    expect(baseline?.state).toContain("before the separate verification mutation");

    for (const id of [
      "operational-truth.candidate-select",
      "operational-truth.decision-reason",
      "operational-truth.reject-candidate",
      "operational-truth.demote-evidence",
      "operational-truth.provenance-disclosure",
      "operational-truth.custody-disclosures",
    ]) {
      const entry = manifest.entries.find((candidate) => candidate.id === id);
      expect(entry, id).toBeDefined();
      expect(entry?.screenshotsRequired, id).not.toContain(baseline?.id);
    }
  });

  test("reverse-maps every declared baseline to the exact represented material interactions", () => {
    expect(baselineRegistry.schemaVersion).toBe(2);
    expect(baselineRegistry.approvalScope).toBe("automated-drift-baseline");
    expect(baselineRegistry.humanReleaseApproval).toBe(false);
    expect(baselineRegistry.scope).toContain("do not imply cross-browser visual approval or release sign-off");
    expect(baselineRegistry.baselines).toHaveLength(21);
    expect(baselineRegistry.pendingBaselines).toHaveLength(0);

    const approvedIds = baselineRegistry.baselines.map((baseline) => baseline.id);
    const pendingIds = pendingBaselines.map((baseline) => baseline.id);
    const registryIds = [...approvedIds, ...pendingIds];
    const carrierKeys = baselineRegistry.baselines.map(
      (baseline) => `${baseline.sourceFile}\u0000${baseline.carrierTitle}\u0000${baseline.project}`,
    );
    expect(new Set(carrierKeys).size).toBe(16);
    const mappedIds = manifest.entries.flatMap((entry) => entry.screenshotsRequired);
    expect(new Set(registryIds).size).toBe(registryIds.length);
    expect([...new Set(mappedIds)].sort()).toEqual([...registryIds].sort());
    const mappedEntryCount = manifest.entries.filter((entry) => entry.screenshotsRequired.length > 0).length;
    const unmappedEntryCount = manifest.entries.length - mappedEntryCount;
    const registeredInteractionIds = new Set(
      [...baselineRegistry.baselines, ...pendingBaselines]
        .flatMap((baseline) => baseline.interactionIds),
    );
    expect(mappedEntryCount).toBe(registeredInteractionIds.size);
    expect(unmappedEntryCount).toBe(manifest.entries.length - registeredInteractionIds.size);
    expect(manifest.knownGaps).toContainEqual(expect.stringContaining(
      `The remaining ${unmappedEntryCount} entries have no mapped baseline`,
    ));

    for (const baseline of baselineRegistry.baselines) {
      expect(baseline.id).toMatch(/^visual\.[a-z0-9][a-z0-9.-]+$/u);
      expect(Object.keys(PROJECT_VIEWPORTS)).toContain(baseline.project);
      expect(baseline.viewport).toBe(
        PROJECT_VIEWPORTS[baseline.project as keyof typeof PROJECT_VIEWPORTS],
      );
      expect(baseline.platform).toBe("linux");
      expect(baseline.state.length).toBeGreaterThan(30);
      expect(baseline.normalizedFields.length).toBeGreaterThan(0);
      expect(baseline.carrierTitle.length).toBeGreaterThan(20);
      expect(
        readFileSync(resolve(root, baseline.sourceFile), "utf8"),
        `${baseline.id} carrier title`,
      ).toContain(baseline.carrierTitle);

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

    for (const pending of pendingBaselines) {
      expect(pending.id).toMatch(/^visual\.[a-z0-9][a-z0-9.-]+$/u);
      expect(Object.keys(PROJECT_VIEWPORTS)).toContain(pending.project);
      expect(pending.viewport).toBe(
        PROJECT_VIEWPORTS[pending.project as keyof typeof PROJECT_VIEWPORTS],
      );
      expect(pending.platform).toBe("linux");
      expect(pending.state.length).toBeGreaterThan(30);
      expect(pending.normalizedFields.length).toBeGreaterThan(0);
      expect(pending.carrierTitle.length).toBeGreaterThan(20);
      expect(pending.captureReason).toContain("browser capture");
      expect("baselinePath" in pending).toBe(false);
      expect("sha256" in pending).toBe(false);

      const reverseMapped = manifest.entries
        .filter((entry) => entry.screenshotsRequired.includes(pending.id))
        .map((entry) => entry.id)
        .sort();
      expect(reverseMapped, pending.id).toEqual([...pending.interactionIds].sort());
      const source = readFileSync(resolve(root, pending.sourceFile), "utf8");
      expect(source, pending.id).toContain(pending.id);
      expect(source, pending.snapshotName).toContain(pending.snapshotName);
      expect(source, pending.testId).toContain(pending.testId);
      expect(source, pending.carrierTitle).toContain(pending.carrierTitle);
      expect(source, pending.sourceFile).toContain("toHaveScreenshot");
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
      expect(source, baseline.carrierTitle).toContain(baseline.carrierTitle);
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

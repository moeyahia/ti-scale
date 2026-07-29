import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import manifestJson from "../../interaction-manifest.json";
import schemaJson from "../../interaction-manifest.schema.json";
import { PRIMARY_NAVIGATION, USER_MANUAL_NAVIGATION } from "../../../src/app/router/routes";
import { ACTION_CLASS_IDS } from "../../../server/domain/catalog-ids";
import { bindManifestTestIdsToPlaywrightResults } from "../../interaction-manifest/activationReceipts";
import { INTERACTION_MANIFEST_NAMESPACE, interactionAccessibleLocator, validateInteractionManifest } from "../../interaction-manifest/schema";

const manifest = validateInteractionManifest(manifestJson);
const E2E_SPEC_ROOT = fileURLToPath(new URL("../../e2e/", import.meta.url));

function filesUnder(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = join(root, entry.name);
    return entry.isDirectory() ? filesUnder(path) : [path];
  });
}

describe("Ti-Scale interaction manifest", () => {
  test("is schema-valid and unique while reporting the current audited state", () => {
    expect(manifest.namespace).toBe(INTERACTION_MANIFEST_NAMESPACE);
    expect(manifest.entries).toHaveLength(830);
    expect(new Set(manifest.entries.map((entry) => entry.id)).size).toBe(manifest.entries.length);
    expect(new Set(manifest.entries.map((entry) => entry.controlId)).size).toBe(manifest.entries.length);
    expect(manifest.scope).toContain("shell navigation");
    expect(manifest.scope).toContain("complete currently rendered initial static-route inventory");
    const overviewRetry = manifest.entries.find((entry) => entry.id === "overview.read-retry");
    expect(overviewRetry).toMatchObject({
      route: "/",
      controlId: "overview-read-retry",
      accessible: { role: "button", name: "Try again", match: "exact" },
      testIds: ["e2e.overview.read-retry.pointer", "e2e.overview.read-retry.keyboard"],
    });
  });

  test("JSON schema and executable validator require the release-audit fields", () => {
    const entrySchema = (schemaJson.properties.entries.items as { required: string[] });
    const accessibleRoleSchema = schemaJson.properties.entries.items.properties.accessible.properties.role as { enum: string[] };
    const screenshotSchema = schemaJson.properties.entries.items.properties.screenshotsRequired as {
      uniqueItems: boolean;
      items: { pattern: string };
    };
    const requiredModalitiesSchema = schemaJson.properties.entries.items.properties.requiredModalities as {
      oneOf: Array<{ const: string[] }>;
    };
    expect(entrySchema.required).toEqual(expect.arrayContaining([
      "route", "surface", "requiredState", "controlId", "accessible", "controlType", "options",
      "keyboardAction", "pointerAction", "expectedStateTransition", "expectedApiOrEventSideEffect",
      "states", "classification", "screenshotsRequired", "browsers", "viewports", "testIds",
    ]));
    expect(accessibleRoleSchema.enum).toContain("application");
    expect(accessibleRoleSchema.enum).toContain("listbox");
    expect(screenshotSchema.uniqueItems).toBe(true);
    expect(screenshotSchema.items.pattern).toBe("^visual\\.[a-z0-9][a-z0-9.-]+$");
    expect(requiredModalitiesSchema.oneOf.map((candidate) => candidate.const)).toEqual([
      ["pointer", "keyboard"],
      ["assertion"],
    ]);
    expect(schemaJson.properties.knownGaps).toMatchObject({
      type: "array",
      uniqueItems: true,
      items: { minLength: 1, pattern: "\\S" },
    });
    expect(validateInteractionManifest({ ...manifestJson, knownGaps: [] }).knownGaps).toEqual([]);
    expect(() => validateInteractionManifest({ ...manifestJson, knownGaps: ["   "] })).toThrow("manifest.knownGaps");
    expect(() => validateInteractionManifest({
      ...manifestJson,
      knownGaps: ["Unresolved release gap", "Unresolved release gap"],
    })).toThrow("must not contain duplicate gaps");
    expect(() => validateInteractionManifest({ ...manifestJson, namespace: "external-source.invalid" })).toThrow("manifest.namespace");
    expect(() => validateInteractionManifest({ ...manifestJson, entries: [manifestJson.entries[0], manifestJson.entries[0]] })).toThrow("duplicates");
    expect(() => validateInteractionManifest({
      ...manifestJson,
      entries: [{ ...manifestJson.entries[0], screenshotsRequired: ["unregistered-screen.png"] }],
    })).toThrow("invalid visual baseline ID");
    expect(() => validateInteractionManifest({
      ...manifestJson,
      entries: [{ ...manifestJson.entries[0], screenshotsRequired: ["visual.shell.initial", "visual.shell.initial"] }],
    })).toThrow("screenshotsRequired duplicates visual.shell.initial");
    expect(validateInteractionManifest({
      ...manifestJson,
      entries: [{
        ...manifestJson.entries[0],
        controlType: "disabled-launch-guard",
        requiredModalities: ["assertion"],
      }],
    }).entries[0]?.requiredModalities).toEqual(["assertion"]);
    expect(() => validateInteractionManifest({
      ...manifestJson,
      entries: [{
        ...manifestJson.entries[0],
        controlType: "disabled-launch-guard",
      }],
    })).toThrow('disabled-launch-guard requires requiredModalities ["assertion"]');
    expect(() => validateInteractionManifest({
      ...manifestJson,
      entries: [{
        ...manifestJson.entries[0],
        requiredModalities: ["pointer"],
      }],
    })).toThrow('requiredModalities must be exactly ["pointer", "keyboard"] or ["assertion"]');
  });

  test("accounts for every current primary navigation destination", () => {
    const navigation = manifest.entries.filter((entry) => entry.id.startsWith("nav."));
    const expected = [...PRIMARY_NAVIGATION, USER_MANUAL_NAVIGATION].map((item) => `${item.label}|${item.path}`).sort();
    const actual = navigation.map((entry) => `${entry.accessible.name}|${entry.expectedStateTransition.replace("Navigate to ", "")}`).sort();
    expect(actual).toEqual(expected);
  });

  test("inventories the bounded Research Lab draft and stop lifecycle", () => {
    const expected = [
      { id: "research.initial-read-retry", locator: "button", name: "Try again", options: 1, testIds: ["e2e.research-lab.initial-read-retry.pointer", "e2e.research-lab.initial-read-retry.keyboard"] },
      { id: "research.owner-acknowledgement", locator: "checkbox", name: "^I own this campaign and its promotion decisions.+$", options: 1, testIds: ["e2e.research-lab.bounded-campaign-lifecycle"] },
      { id: "research.allowed-strategy-paths", locator: "native-summary", name: "Allowed strategy paths", options: 3, testIds: ["e2e.research-lab.bounded-campaign-lifecycle"] },
      { id: "research.create-draft", locator: "button", name: "Create bounded draft", options: 3, testIds: ["e2e.research-lab.bounded-campaign-lifecycle"] },
      { id: "research.campaign-controls", locator: "native-summary", name: "Stop campaign", options: 1, testIds: ["e2e.research-lab.bounded-campaign-lifecycle"] },
      { id: "research.stop-reason", locator: "textbox", name: "Reason for stopping", options: 1, testIds: ["e2e.research-lab.bounded-campaign-lifecycle"] },
      { id: "research.stop-campaign", locator: "button", name: "Stop campaign", options: 1, testIds: ["e2e.research-lab.bounded-campaign-lifecycle"] },
      { id: "research.mutation-retry", locator: "button", name: "Try again", options: 2, testIds: ["e2e.research-lab.retryable-mutations"] },
      { id: "research.mutation-refresh", locator: "button", name: "Refresh campaign state", options: 1, testIds: ["e2e.research-lab.optimistic-conflict"] },
      { id: "research.setup-disclosures", locator: "native-summary", name: "^(?:Review exact bounded experiment|Exact one-operation strategy patch|Immutable execution hashes)$", options: 3, testIds: ["e2e.research-lab.bounded-experiment-controls"] },
      { id: "research.setup-approval", locator: "checkbox", name: "^I approve this exact charter, patch, fixture, and budget.+$", options: 1, testIds: ["e2e.research-lab.bounded-experiment-controls"] },
      { id: "research.setup-queue", locator: "button", name: "Approve and queue candidate", options: 1, testIds: ["e2e.research-lab.bounded-experiment-controls"] },
      { id: "research.setup-retry", locator: "button", name: "Try again", options: 1, testIds: ["e2e.research-lab.bounded-experiment-controls"] },
      { id: "research.setup-refresh", locator: "button", name: "Refresh exact setup bindings", options: 1, testIds: ["e2e.research-lab.setup-optimistic-conflict"] },
      { id: "research.experiment-seed", locator: "textbox", name: "Reproducible seed", options: 1, testIds: ["e2e.research-lab.bounded-experiment-controls"] },
      { id: "research.experiment-start", locator: "button", name: "Run development fixture", options: 1, testIds: ["e2e.research-lab.bounded-experiment-controls", "e2e.research-lab.authoritative-worker-completion"] },
      { id: "research.experiment-cancel-reason", locator: "textbox", name: "Cancellation reason", options: 1, testIds: ["e2e.research-lab.bounded-experiment-controls"] },
      { id: "research.experiment-cancel", locator: "button", name: "Cancel bounded run", options: 1, testIds: ["e2e.research-lab.bounded-experiment-controls"] },
      { id: "research.experiment-mutation-retry", locator: "button", name: "Try again", options: 2, testIds: ["e2e.research-lab.experiment-mutation-retry"] },
      { id: "research.experiment-canonical-refresh", locator: "button", name: "Refresh canonical run state", options: 2, testIds: ["e2e.research-lab.experiment-response-loss-reconciliation"] },
      { id: "research.experiment-discard-retained-request", locator: "button", name: "Discard retained request", options: 2, testIds: ["e2e.research-lab.experiment-mutation-retry", "e2e.research-lab.experiment-response-loss-reconciliation"] },
      { id: "research.promotion-history", locator: "native-summary", name: "Immutable transition history", options: 1, testIds: ["e2e.research-lab.complete-promotion-lifecycle"] },
      { id: "research.promotion-rationale", locator: "textbox", name: "Decision rationale", options: 1, testIds: ["e2e.research-lab.complete-promotion-lifecycle"] },
      { id: "research.promotion-evidence", locator: "textbox", name: "Evidence or receipt references", options: 1, testIds: ["e2e.research-lab.complete-promotion-lifecycle"] },
      { id: "research.promotion-canary-bounds", locator: "spinbutton", name: "^(?:Maximum missions|Maximum minutes)$", options: 2, testIds: ["e2e.research-lab.complete-promotion-lifecycle"] },
      { id: "research.promotion-rollback-target", locator: "radio", name: "^research-promotion-.+-strategy-prior.+$", options: 1, testIds: ["e2e.research-lab.complete-promotion-lifecycle"] },
      { id: "research.promotion-actions", locator: "button", name: "^(?:Approve for isolated shadow|Reject after human review|Start isolated shadow|Approve bounded canary|Start bounded canary|Verify strategy|Reject candidate|Mark strategy stale|Supersede strategy|Roll back by forward activation)$", options: 10, testIds: ["e2e.research-lab.complete-promotion-lifecycle", "e2e.research-lab.promotion-action-matrix"] },
      { id: "research.promotion-uncertain-refresh", locator: "button", name: "Refresh lifecycle state", options: 1, testIds: ["e2e.research-lab.promotion-response-loss"] },
      { id: "research.promotion-refresh", locator: "button", name: "Refresh lifecycle state", options: 1, testIds: ["e2e.research-lab.promotion-reliability"] },
      { id: "research.promotion-mutation-retry", locator: "button", name: "Try again", options: 1, testIds: ["e2e.research-lab.promotion-reliability"] },
      { id: "research.promotion-discard-retained-decision", locator: "button", name: "Discard retained decision", options: 1, testIds: ["e2e.research-lab.promotion-reliability", "e2e.research-lab.promotion-response-loss"] },
    ] as const;
    const entries = manifest.entries.filter((entry) => entry.id.startsWith("research."));
    expect(entries).toHaveLength(expected.length);
    for (const item of expected) {
      const entry = entries.find((candidate) => candidate.id === item.id);
      expect(entry, item.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route).toBe("/learning?view=research");
      expect(entry.accessible).toMatchObject({ name: item.name });
      expect(interactionAccessibleLocator(entry.accessible)).toBe(item.locator);
      expect(entry.options).toHaveLength(item.options);
      expect(entry.testIds).toEqual(item.testIds);
    }
    expect(manifest.knownGaps.some((gap) => gap.includes("all three human-owned bounded Research Lab draft/stop lifecycles"))).toBe(true);
    expect(manifest.knownGaps.some((gap) => gap.includes("Research Lab mutation-conflict/error injection"))).toBe(false);
    expect(manifest.knownGaps.some((gap) => gap.includes("signed human-review, shadow, bounded-canary, verification, rejection, stale, supersession, and forward-rollback promotion controls now have canonical browser paths"))).toBe(true);
    expect(manifest.knownGaps.some((gap) => gap.includes("remaining Research setup/run controls"))).toBe(false);
    expect(manifest.knownGaps.some((gap) => gap.includes("authoritative local-worker completion"))).toBe(true);
    expect(manifest.knownGaps.some((gap) => gap.includes("canonical outcome reconciliation without mutation replay"))).toBe(true);
    expect(manifest.knownGaps.some((gap) => gap.includes("authoritative worker completion in the browser"))).toBe(false);
    expect(manifest.knownGaps.some((gap) => gap.includes("exact run-start and cancellation retry preservation"))).toBe(false);
    expect(manifest.knownGaps.some((gap) => gap.includes("response-loss reconciliation"))).toBe(false);
    expect(manifest.knownGaps.some((gap) => gap.includes("experiment/holdout/shadow/canary/promotion/rollback lifecycle remain explicit release gaps"))).toBe(false);
  });

  test("every literal browser activation names a real manifest entry", () => {
    const manifestIds = new Set(manifest.entries.map(({ id }) => id));
    const referencedIds = [...new Set(
      filesUnder(E2E_SPEC_ROOT)
        .filter((path) => path.endsWith(".spec.ts"))
        .flatMap((path) => [
          ...readFileSync(path, "utf8")
            .matchAll(/manifestEntryId:\s*"([^"]+)"/gu),
        ].map((match) => match[1]!)),
    )].sort();
    expect(referencedIds.length).toBeGreaterThan(0);
    expect(referencedIds.filter((id) => !manifestIds.has(id))).toEqual([]);
    expect(referencedIds).toContain("research.promotion-actions");
    expect(referencedIds).toContain("research.promotion-uncertain-refresh");
  });

  test("inventories the operator-approved particle core in production and its local inspector", () => {
    const testId = "e2e.motion-lab.particle-core";
    const expectedIds = [
      "motion-lab.particle-core-review-link",
      "particle-core.cluster-selection",
      "particle-core.camera",
      "particle-core.state",
      "particle-core.scrubber",
      "particle-core.orbital-drift",
      "particle-core.reduced-motion",
      "particle-core.field-toggle",
      "particle-core.field-close",
      "particle-core.return",
      "particle-core.canvas",
      "particle-core.runtime-retry",
    ] as const;
    const entries = manifest.entries.filter((entry) => expectedIds.includes(entry.id as typeof expectedIds[number]));
    expect(entries).toHaveLength(expectedIds.length);
    expect(entries.map((entry) => entry.id)).toEqual([...expectedIds]);
    for (const entry of entries) {
      expect(entry.testIds, entry.id).toContain(testId);
      expect(entry.screenshotsRequired, entry.id).toEqual([]);
      expect(entry.browsers, entry.id).toEqual(expect.arrayContaining(["chromium", "firefox", "webkit"]));
      expect(entry.viewports, entry.id).toEqual(expect.arrayContaining(["360x800", "1440x900", "200%"]));
    }
    expect(entries.find((entry) => entry.id === "particle-core.cluster-selection")?.options).toHaveLength(15);
    expect(entries.find((entry) => entry.id === "particle-core.camera")?.options).toHaveLength(5);
    expect(entries.find((entry) => entry.id === "particle-core.state")?.options).toEqual(["Assembled", "Expansion", "Exploded"]);
    expect(interactionAccessibleLocator(entries.find((entry) => entry.id === "particle-core.canvas")!.accessible)).toBe("application");
    expect(entries.find((entry) => entry.id === "particle-core.runtime-retry")?.requiredState).toContain("Material error state");
    expect(entries.find((entry) => entry.id === "particle-core.field-close")?.requiredState).toContain("Material state");

    const overview = manifest.entries.find((entry) => entry.id === "overview.particle-core");
    expect(overview).toBeDefined();
    expect(overview?.route).toBe("/");
    expect(interactionAccessibleLocator(overview!.accessible)).toBe("application");
    expect(overview?.accessible.name).toContain("interactive titanium particle core");
    expect(overview?.accessible.name).toContain("reduced-motion state");
    expect(overview?.options).toEqual([
      "Local hover repulsion",
      "Pointer drag orbit",
      "Wheel zoom",
      "Arrow-key rotation",
      "+/- zoom",
      "Home reset",
    ]);
    expect(overview?.testIds).toEqual(["e2e.overview.particle-core"]);
    const motionLabLink = entries.find((entry) => entry.id === "motion-lab.particle-core-review-link");
    expect(motionLabLink?.accessible.name).toBe("Inspect active particle core");
    expect(motionLabLink?.expectedStateTransition).toContain("same approved geometry");
  });

  test("inventories the isolated particle-to-module review without implying production integration", () => {
    const testId = "e2e.motion-lab.particle-module-transition";
    const expectedIds = [
      "motion-lab.particle-module-transition-link",
      "particle-module-transition.phase-navigation",
      "particle-module-transition.phase-step",
      "particle-module-transition.return",
      "particle-module-transition.canvas",
      "particle-module-transition.module-links",
      "particle-module-transition.runtime-retry",
    ] as const;
    const entries = manifest.entries.filter((entry) => expectedIds.includes(entry.id as typeof expectedIds[number]));
    expect(entries.map((entry) => entry.id)).toEqual([...expectedIds]);
    for (const entry of entries) {
      expect(entry.testIds, entry.id).toContain(testId);
      expect(entry.screenshotsRequired, entry.id).toEqual([]);
      expect(entry.expectedApiOrEventSideEffect, entry.id).toBeNull();
    }
    expect(entries.find((entry) => entry.id === "particle-module-transition.phase-navigation")?.options).toHaveLength(4);
    expect(entries.find((entry) => entry.id === "particle-module-transition.module-links")?.options).toHaveLength(14);
    expect(entries.find((entry) => entry.id === "motion-lab.particle-module-transition-link")?.expectedStateTransition)
      .toContain("without changing the approved Overview experience");
    expect(interactionAccessibleLocator(entries.find((entry) => entry.id === "particle-module-transition.canvas")!.accessible)).toBe("application");
  });

  test("represents compact navigation without exposing the closed sidebar to focus", () => {
    const entry = manifest.entries.find((candidate) => candidate.id === "shell.mobile-navigation");
    expect(entry?.accessible).toEqual({ role: "button", name: "^(?:Open|Close) navigation$", match: "regex" });
    expect(entry?.options).toEqual(["Open navigation", "Close navigation", "Close with Escape"]);
    expect(entry?.requiredState).toContain("excluded from focus and accessibility until opened");
    expect(entry?.testIds).toEqual(["e2e.shell.mobile-navigation", "e2e.manifest.coverage-audit"]);
  });

  test("exposes exactly Autonomous and Guided as journey options", () => {
    const journeys = new Set(manifest.entries.flatMap((entry) => entry.options).filter((option) => option === "Autonomous" || option === "Guided"));
    expect([...journeys].sort()).toEqual(["Autonomous", "Guided"]);
  });

  test("inventories provider-independent exact-step Commander guidance without execution authority", () => {
    const entries = manifest.entries.filter((entry) => entry.id.startsWith("guided-commander."));
    expect(entries.map((entry) => entry.id)).toEqual([
      "guided-commander.explain-more",
      "guided-commander.show-next-step",
      "guided-commander.use-another-approach",
    ]);
    for (const entry of entries) {
      expect(entry.route).toBe("/guided/:missionId");
      expect(entry.requiredState).toContain("one exact pending Guided decision");
      expect(entry.expectedStateTransition).toMatch(/without mutating|unchanged|only authorization boundary/u);
      expect(entry.expectedApiOrEventSideEffect).toContain("no provider, tool, or target contact");
      expect(entry.testIds).toEqual(["e2e.guided-provider-free-capabilities"]);
    }
  });

  test("accounts for every registry-driven intake step and collection in both journeys", () => {
    for (const journey of ["autonomous", "guided"] as const) {
      const entries = manifest.entries.filter((entry) => entry.route === `/missions/new/${journey}`);
      const steps = journey === "autonomous"
        ? ["Scope", "Outcome", "Contract", "Team", "Context", "Review"]
        : ["Scope", "Outcome", "Contract", "Review"];
      for (const step of steps) {
        expect(entries.some((entry) => entry.surface.includes(step) || entry.requiredState.toLocaleLowerCase("en-US").includes(step.toLocaleLowerCase("en-US")))).toBe(true);
      }
      expect(entries.find((entry) => entry.id === `${journey}-intake.scope.template`)?.options).toHaveLength(8);
      if (journey === "autonomous") {
        expect(entries.find((entry) => entry.id === "autonomous-intake.contract.action-classes")?.options).toEqual(["Open", "Close"]);
        expect(entries.find((entry) => entry.id === "autonomous-intake.contract.action-class-controls")?.options).toHaveLength(26);
        expect(entries.find((entry) => entry.id === "autonomous-intake.contract.deliverables")?.options).toEqual(["Open", "Close"]);
        expect(entries.find((entry) => entry.id === "autonomous-intake.contract.evidence")?.options).toEqual(["Open", "Close"]);
        expect(entries.find((entry) => entry.id === "autonomous-intake.contract.safe-stops")?.options).toEqual(["Open", "Close"]);
        expect(entries.find((entry) => entry.id === "autonomous-intake.contract.deliverable-controls")?.options).toHaveLength(15);
        expect(entries.find((entry) => entry.id === "autonomous-intake.contract.evidence-controls")?.options).toHaveLength(21);
        expect(entries.find((entry) => entry.id === "autonomous-intake.contract.safe-stop-controls")?.options).toHaveLength(10);
      } else {
        expect(entries.find((entry) => entry.id === "guided-intake.contract.action-classes")?.options).toHaveLength(26);
        expect(entries.find((entry) => entry.id === "guided-intake.contract.deliverables")?.options).toHaveLength(15);
        expect(entries.find((entry) => entry.id === "guided-intake.contract.evidence")?.options).toHaveLength(21);
        expect(entries.find((entry) => entry.id === "guided-intake.contract.safe-stops")?.options).toHaveLength(10);
      }
    }
    expect(manifest.entries.find((entry) => entry.id === "autonomous-intake.contract.action-class-controls")?.options)
      .toEqual(manifest.entries.find((entry) => entry.id === "guided-intake.contract.action-classes")?.options);
    expect(manifest.entries.find((entry) => entry.id === "autonomous-intake.team.specialists")?.controlType)
      .toBe("runtime-specialist-checkbox-collection");
    expect(manifest.entries.find((entry) => entry.id === "autonomous-intake.context.memories")?.controlType)
      .toBe("scope-safe-memory-checkbox-collection");
    expect(manifest.entries.find((entry) => entry.id === "autonomous-intake.context.scopes")?.options)
      .toEqual([
        "Confirmed operator preferences",
        "Verified operational lessons",
        "Confirmed historical attack knowledge",
        "Verified attack safety knowledge",
        "Engagement-isolated knowledge",
      ]);
  });

  test("binds every Guided local ExploitDB control to the dedicated browser proof", () => {
    const expectedIds = [
      "guided-intake.outcome.local-exploit-none",
      "guided-intake.outcome.local-exploit-cve",
      "guided-intake.outcome.local-exploit-technology",
      "guided-intake.outcome.local-exploit-cve-id",
      "guided-intake.outcome.local-exploit-product",
      "guided-intake.outcome.local-exploit-version",
      "guided-intake.outcome.local-exploit-platform",
      "guided-intake.outcome.local-exploit-maximum-results",
    ] as const;
    const entries = manifest.entries.filter((entry) =>
      expectedIds.includes(entry.id as typeof expectedIds[number])
    );
    expect(entries.map((entry) => entry.id)).toEqual([...expectedIds]);
    for (const entry of entries) {
      expect(entry.route).toBe("/missions/new/guided");
      expect(entry.requiredState.startsWith("Fixture required:")).toBe(true);
      expect(entry.testIds).toEqual([
        "e2e.mission-intake.guided-local-exploit-intelligence",
      ]);
      expect(entry.expectedApiOrEventSideEffect).not.toContain("provider call");
      expect(entry.screenshotsRequired).toEqual([]);
    }
  });

  test("binds every Autonomous action-class selector to exactly one canonical registry ID", () => {
    const prefix = "autonomous-intake.contract.action-policy-state.";
    const entries = manifest.entries.filter((entry) => entry.id.startsWith(prefix));
    expect(entries).toHaveLength(ACTION_CLASS_IDS.length);
    expect(entries.map((entry) => entry.id.slice(prefix.length))).toEqual([...ACTION_CLASS_IDS]);
    expect(new Set(entries.map((entry) => entry.controlId)).size).toBe(ACTION_CLASS_IDS.length);
    for (const entry of entries) {
      expect(entry.controlType).toBe("action-policy-select");
      expect(entry.options).toEqual([
        "Pre-authorized",
        "Guided only / not autonomous",
        "Prohibited",
        "Inherited default",
      ]);
      expect(entry.expectedApiOrEventSideEffect).toBeNull();
      expect(entry.testIds).toEqual(["e2e.autonomous-intake.contract-normalization"]);
    }
  });

  test("inventories mounted mission truth controls and distinguishes dedicated fixture coverage", () => {
    const runIntelligence = manifest.entries.filter((entry) => entry.id.startsWith("run-intelligence."));
    const operationalTruth = manifest.entries.filter((entry) => entry.id.startsWith("operational-truth."));
    const failureDiagnosis = manifest.entries.filter((entry) => entry.id.startsWith("failure-diagnosis."));
    const planChanges = manifest.entries.filter((entry) => entry.id.startsWith("plan-change."));
    const directPlanChanges = manifest.entries.filter((entry) => entry.id.startsWith("plan-direct."));
    const cveApplicability = manifest.entries.filter((entry) => entry.id.startsWith("cve-applicability."));
    const artifactIntelligence = manifest.entries.filter((entry) => entry.id.startsWith("artifact-intelligence."));
    const topologyInteractions = runIntelligence.filter((entry) => /\.(?:plan|live)-topology\./u.test(entry.id));
    const dynamicFixtureEntries = [
      ...runIntelligence, ...operationalTruth, ...failureDiagnosis, ...planChanges, ...directPlanChanges, ...cveApplicability, ...artifactIntelligence,
    ];

    expect(runIntelligence).toHaveLength(42);
    expect(operationalTruth).toHaveLength(25);
    expect(failureDiagnosis).toHaveLength(9);
    expect(planChanges).toHaveLength(22);
    expect(directPlanChanges).toHaveLength(46);
    expect(cveApplicability).toHaveLength(9);
    expect(artifactIntelligence).toHaveLength(14);
    expect(dynamicFixtureEntries).toHaveLength(167);
    expect(new Set(dynamicFixtureEntries.map((entry) => entry.route))).toEqual(new Set([
      "/missions/:missionId/runs/:runId",
      "/missions/:missionId/runs/:runId?tab=plan",
      "/missions/:missionId/runs/:runId?tab=plan&node=:nodeId&cve=:recordId",
      "/missions/:missionId/runs/:runId?tab=evidence",
      "/live/:runId",
    ]));
    for (const entry of dynamicFixtureEntries) {
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.route).toContain(":");
    }
    const dedicated = dynamicFixtureEntries.filter((entry) => !entry.testIds.includes("e2e.manifest.coverage-audit"));
    const unresolved = dynamicFixtureEntries.filter((entry) => entry.testIds.includes("e2e.manifest.coverage-audit"));
    expect(topologyInteractions).toHaveLength(36);
    expect(dedicated.map((entry) => entry.id)).toEqual(dynamicFixtureEntries.map((entry) => entry.id));
    expect(dedicated).toHaveLength(167);
    expect(unresolved).toHaveLength(0);
    expect(unresolved.every((entry) => entry.testIds.length === 1)).toBe(true);
    const fixtureRequiredEntryCount = manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:")).length;
    expect(fixtureRequiredEntryCount).toBe(608);
    expect(manifest.scope).toContain(`All ${fixtureRequiredEntryCount} fixture-required groups`);
    expect(manifest.knownGaps.some((gap) =>
      gap.includes(`All ${fixtureRequiredEntryCount} entries`)
      && gap.includes("dedicated canonical fixture source traversal")
    )).toBe(true);
    expect(manifest.knownGaps.some((gap) => gap.includes("full browser matrix"))).toBe(true);
  });

  test("maps every run intervention and recovery control only to its six dedicated fixture paths", () => {
    const entries = manifest.entries.filter((entry) => entry.id.startsWith("run-intervention.") || entry.id.startsWith("run-recovery."));
    const expected = [
      { id: "run-intervention.reason", testIds: ["e2e.run-intervention.control-plane-rejection", "e2e.run-intervention.pause-resume-replay", "e2e.run-intervention.cancel-no-ghost"] },
      { id: "run-intervention.pause", testIds: ["e2e.run-intervention.control-plane-rejection", "e2e.run-intervention.pause-resume-replay"] },
      { id: "run-intervention.cancel", testIds: ["e2e.run-intervention.cancel-no-ghost"] },
      { id: "run-recovery.reason", testIds: ["e2e.run-intervention.pause-resume-replay", "e2e.run-recovery.reassign-terminate"] },
      { id: "run-recovery.resume", testIds: ["e2e.run-intervention.pause-resume-replay"] },
      { id: "run-recovery.strategy", testIds: ["e2e.run-recovery.replan-boundary-replay"] },
      { id: "run-recovery.replan", testIds: ["e2e.run-recovery.replan-boundary-replay"] },
      { id: "run-recovery.specialist", testIds: ["e2e.run-recovery.reassign-terminate"] },
      { id: "run-recovery.capability", testIds: ["e2e.run-recovery.reassign-terminate"] },
      { id: "run-recovery.reassign", testIds: ["e2e.run-recovery.reassign-terminate"] },
      { id: "run-recovery.change-provider", testIds: ["e2e.run-recovery.reassign-terminate"] },
      { id: "run-recovery.terminate", testIds: ["e2e.run-recovery.reassign-terminate"] },
      { id: "run-recovery.exact-attempt", testIds: ["e2e.run-recovery.exact-mutation-retry-reconcile"] },
      { id: "run-recovery.discard-attempt", testIds: ["e2e.run-recovery.exact-mutation-retry-reconcile"] },
    ] as const;
    const allowedTestIds = new Set([
      "e2e.run-intervention.control-plane-rejection",
      "e2e.run-intervention.pause-resume-replay",
      "e2e.run-intervention.cancel-no-ghost",
      "e2e.run-recovery.replan-boundary-replay",
      "e2e.run-recovery.reassign-terminate",
      "e2e.run-recovery.exact-mutation-retry-reconcile",
    ]);

    expect(entries).toHaveLength(14);
    expect(entries.map((entry) => entry.id)).toEqual(expected.map((entry) => entry.id));
    for (const expectedEntry of expected) {
      const entry = entries.find((candidate) => candidate.id === expectedEntry.id);
      expect(entry, expectedEntry.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route, entry.id).toBe("/live/:runId");
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.testIds, entry.id).toEqual(expectedEntry.testIds);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), entry.id).toBe(false);
      expect(entry.testIds.every((testId) => allowedTestIds.has(testId)), entry.id).toBe(true);
    }
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
  });

  test("binds the hidden command-palette controls to material record, run, memory, and degraded browser paths", () => {
    const entries = manifest.entries.filter((entry) => entry.id.startsWith("command-palette."));
    const expectedIds = [
      "command-palette.search",
      "command-palette.results",
      "command-palette.journey-results",
      "command-palette.navigation-results",
      "command-palette.mission-results",
      "command-palette.run-results",
      "command-palette.decision-results",
      "command-palette.agent-results",
      "command-palette.memory-results",
      "command-palette.run-commands",
      "command-palette.editor-back",
      "command-palette.run-reason",
      "command-palette.cancel-confirmation",
      "command-palette.run-confirm",
      "command-palette.memory-command",
      "command-palette.memory-type",
      "command-palette.memory-scope",
      "command-palette.memory-sensitivity",
      "command-palette.memory-title",
      "command-palette.memory-summary",
      "command-palette.memory-create",
      "command-palette.memory-inbox",
    ];
    const allowedTestIds = new Set([
      "e2e.command-palette.search-record-families",
      "e2e.command-palette.autonomous-search",
      "e2e.command-palette.run-control",
      "e2e.command-palette.memory-candidate",
      "e2e.command-palette.partial-data",
      "e2e.command-palette.navigation-destinations",
      "e2e.command-palette.editor-rejections",
    ]);
    expect(entries.map((entry) => entry.id)).toEqual(expectedIds);
    expect(entries).toHaveLength(22);
    expect(entries.every((entry) => entry.requiredState.startsWith("Fixture required:"))).toBe(true);
    expect(entries.every((entry) => entry.testIds.length >= 1 && entry.testIds.length <= 3)).toBe(true);
    expect(entries.every((entry) => entry.testIds.every((testId) => allowedTestIds.has(testId)))).toBe(true);
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    expect(entries.find((entry) => entry.id === "command-palette.results")?.accessible).toEqual({
      role: "listbox",
      name: "Command results",
      match: "exact",
    });
    for (const id of [
      "command-palette.search",
      "command-palette.results",
      "command-palette.agent-results",
      "command-palette.memory-results",
    ]) {
      expect(entries.find((entry) => entry.id === id)?.testIds).toContain("e2e.command-palette.partial-data");
    }
    for (const id of ["command-palette.mission-results", "command-palette.run-results"]) {
      expect(entries.find((entry) => entry.id === id)?.testIds)
        .toContain("e2e.command-palette.autonomous-search");
    }
    expect(entries.find((entry) => entry.id === "command-palette.mission-results")?.options)
      .toEqual(expect.arrayContaining([
        "Open the exact represented Guided mission",
        "Open the exact represented Autonomous mission with pointer input",
        "Refresh the stable Autonomous mission URL",
        "Traverse back and forward without changing its identity",
        "Omit only mission results when the mission query domain fails",
      ]));
    expect(entries.find((entry) => entry.id === "command-palette.run-results")?.options)
      .toEqual(expect.arrayContaining([
        "Open the exact represented Guided run with keyboard input",
        "Open the exact represented Autonomous run with keyboard input",
        "Refresh the stable Autonomous live-run URL",
        "Omit only run results when the run query domain fails",
      ]));
    expect(entries.find((entry) => entry.id === "command-palette.editor-back")?.testIds)
      .toEqual([
        "e2e.command-palette.run-control",
        "e2e.command-palette.memory-candidate",
        "e2e.command-palette.editor-rejections",
      ]);
    const navigationEntry = entries.find((entry) => entry.id === "command-palette.navigation-results");
    expect(navigationEntry).toMatchObject({
      options: [...PRIMARY_NAVIGATION, USER_MANUAL_NAVIGATION].map((item) => item.label),
      testIds: ["e2e.command-palette.search-record-families", "e2e.command-palette.navigation-destinations"],
    });
    const navigationName = new RegExp(navigationEntry?.accessible.name ?? "(?!)", "u");
    for (const item of [...PRIMARY_NAVIGATION, USER_MANUAL_NAVIGATION]) {
      expect(navigationName.test(`${item.label} Navigate to ${item.label}`), item.label).toBe(true);
    }
    for (const id of [
      "command-palette.run-commands",
      "command-palette.run-reason",
      "command-palette.run-confirm",
      "command-palette.memory-command",
      "command-palette.memory-type",
      "command-palette.memory-scope",
      "command-palette.memory-sensitivity",
      "command-palette.memory-title",
      "command-palette.memory-summary",
      "command-palette.memory-create",
    ]) {
      expect(entries.find((entry) => entry.id === id)?.testIds, id)
        .toContain("e2e.command-palette.editor-rejections");
    }
    expect(entries.find((entry) => entry.id === "command-palette.run-confirm")?.options)
      .toEqual(["Confirm pause", "Confirm resume", "Confirm cancel"]);
    expect(entries.find((entry) => entry.id === "command-palette.memory-create")?.expectedApiOrEventSideEffect)
      .toContain("Idempotency-Key");
    expect(manifest.knownGaps.some((gap) => gap.includes("command-palette material-state slice"))).toBe(true);
    expect(manifest.knownGaps.some((gap) => gap.includes("Autonomous mission/run search records"))).toBe(false);
  });

  test("inventories Decisions and Intelligence control families against only their dedicated fixture sources", () => {
    const decisions = manifest.entries.filter((entry) => entry.id.startsWith("decisions."));
    const intelligence = manifest.entries.filter((entry) => entry.id.startsWith("intelligence."));
    const entries = [...decisions, ...intelligence];
    const allowedTestIds = new Set([
      "e2e.decisions.read-filter-pagination",
      "e2e.decisions.cards-controls-deep-links",
      "e2e.decisions.alias-empty-retry",
      "e2e.intelligence.evidence-list-detail-export",
      "e2e.intelligence.findings-list-detail-controls",
      "e2e.intelligence.artifacts-list-detail-controls",
      "e2e.intelligence.empty-error-retry",
      "e2e.intelligence.artifact-verified-download",
      "e2e.intelligence.artifact-delivery-reconciliation",
    ]);
    const relationshipFamilies = [
      {
        id: "intelligence.relationship.list-mission-links",
        route: "/intelligence/:view",
        name: "^decisionintelligence[a-f0-9]{12} canonical intelligence fixture$",
        options: ["Evidence-row mission", "Finding-row mission", "Artifact-row mission"],
        testIds: [
          "e2e.intelligence.evidence-list-detail-export",
          "e2e.intelligence.findings-list-detail-controls",
          "e2e.intelligence.artifacts-list-detail-controls",
        ],
      },
      {
        id: "intelligence.relationship.detail-mission-links",
        route: "/intelligence/:view/:recordId",
        name: "^decisionintelligence[a-f0-9]{12} (?:canonical intelligence fixture|archived intelligence mission|imported intelligence without a run)$",
        options: ["Evidence owner", "Finding owner", "Artifact owner", "Archived evidence owner", "Imported relationless-record owner"],
        testIds: [
          "e2e.intelligence.evidence-list-detail-export",
          "e2e.intelligence.findings-list-detail-controls",
          "e2e.intelligence.artifacts-list-detail-controls",
        ],
      },
      {
        id: "intelligence.relationship.detail-run-links",
        route: "/intelligence/:view/:recordId",
        name: "^run-(?:intelligence-lists|archived-intelligence)-e2e-[a-z0-9-]+$",
        options: ["Evidence run", "Finding run", "Artifact run", "Archived completed run"],
        testIds: [
          "e2e.intelligence.evidence-list-detail-export",
          "e2e.intelligence.findings-list-detail-controls",
          "e2e.intelligence.artifacts-list-detail-controls",
        ],
      },
      {
        id: "intelligence.relationship.evidence-artifact-link",
        route: "/intelligence/evidence/:evidenceId",
        name: "^(?:network_map|quarantined_capture)_decisionintelligence[a-f0-9]{12}$",
        options: ["Open same-mission artifact metadata", "Open quarantined artifact metadata without content delivery"],
        testIds: ["e2e.intelligence.evidence-list-detail-export"],
      },
      {
        id: "intelligence.relationship.finding-evidence-links",
        route: "/intelligence/findings/:findingId",
        name: "^decisionintelligence[a-f0-9]{12} verified HTTPS service fingerprint$",
        options: ["Open linked evidence detail", "Inspect evidence verification state"],
        testIds: ["e2e.intelligence.findings-list-detail-controls"],
      },
      {
        id: "intelligence.relationship.artifact-evidence-links",
        route: "/intelligence/artifacts/:artifactId",
        name: "^decisionintelligence[a-f0-9]{12} verified HTTPS service fingerprint$",
        options: ["Open referencing evidence detail", "Inspect evidence verification state"],
        testIds: ["e2e.intelligence.artifacts-list-detail-controls"],
      },
    ] as const;

    expect(decisions).toHaveLength(16);
    expect(intelligence).toHaveLength(24);
    expect(entries).toHaveLength(40);
    expect(new Set(decisions.map((entry) => entry.route))).toEqual(new Set(["/decisions"]));
    expect(new Set(intelligence.map((entry) => entry.route))).toEqual(new Set([
      "/intelligence/:view",
      "/intelligence/:view/:recordId",
      "/intelligence/evidence",
      "/intelligence/evidence/:evidenceId",
      "/intelligence/findings",
      "/intelligence/findings/:findingId",
      "/intelligence/artifacts/:artifactId",
    ]));
    const relationships = intelligence.filter((entry) => entry.id.startsWith("intelligence.relationship."));
    expect(relationships).toHaveLength(relationshipFamilies.length);
    for (const expectedEntry of relationshipFamilies) {
      const entry = relationships.find((candidate) => candidate.id === expectedEntry.id);
      expect(entry, expectedEntry.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route, entry.id).toBe(expectedEntry.route);
      expect("role" in entry.accessible ? entry.accessible.role : entry.accessible.locator, entry.id).toBe("link");
      expect(entry.accessible.name, entry.id).toBe(expectedEntry.name);
      expect(entry.accessible.match, entry.id).toBe("regex");
      expect(entry.options, entry.id).toEqual(expectedEntry.options);
      expect(entry.testIds, entry.id).toEqual(expectedEntry.testIds);
    }
    for (const entry of entries) {
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), entry.id).toBe(false);
      expect(entry.testIds.every((testId) => allowedTestIds.has(testId)), entry.id).toBe(true);
    }
    const findingReviewSubmission = intelligence.find(
      (entry) => entry.id === "intelligence.finding.record",
    );
    expect(findingReviewSubmission?.options).toEqual([
      "Verify with linked evidence",
      "Reopen a verified finding",
      "Move a draft finding under review",
      "Reject a reviewed finding",
      "Attempt an audited evidence-gate override without reviewer permission",
    ]);
    expect(findingReviewSubmission?.expectedApiOrEventSideEffect)
      .toContain("each accepted transition increments the version");
    expect(findingReviewSubmission?.states.disabled).toContain("at least 12");
    expect(findingReviewSubmission?.testIds)
      .toEqual(["e2e.intelligence.findings-list-detail-controls"]);
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(608);
  });

  test("inventories Second Brain home, inbox, graph, and graph-return families against only their dedicated fixture sources", () => {
    const allHome = manifest.entries.filter((entry) => entry.id.startsWith("brain.home."));
    const home = allHome.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const staticHome = allHome.filter((entry) => !entry.requiredState.startsWith("Fixture required:"));
    const allInbox = manifest.entries.filter((entry) => entry.id.startsWith("brain.inbox."));
    const inbox = allInbox.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const staticInbox = allInbox.filter((entry) => !entry.requiredState.startsWith("Fixture required:"));
    const allGraph = manifest.entries.filter((entry) => entry.id.startsWith("brain.graph."));
    const graph = allGraph.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const staticGraph = allGraph.filter((entry) => !entry.requiredState.startsWith("Fixture required:"));
    const graphReturn = manifest.entries.filter((entry) => entry.id === "brain.node.show-in-graph");
    const entries = [...home, ...inbox, ...graph, ...graphReturn];
    const allowedTestIds = new Set([
      "e2e.brain-home.navigation-and-populated",
      "e2e.brain-home.search-filters-node",
      "e2e.brain-home.empty",
      "e2e.brain-home.summary-retry",
      "e2e.brain-home.nodes-retry",
      "e2e.brain-home.pagination",
      "e2e.brain-inbox.confirm",
      "e2e.brain-inbox.edit-scope-confirm",
      "e2e.brain-inbox.reject",
      "e2e.brain-inbox.reject-do-not-relearn",
      "e2e.brain-inbox.empty-navigation-retry",
      "e2e.brain-inbox.pagination",
      "e2e.brain-inbox.attack-promotion",
      "e2e.brain-inbox.attack-promotion-retries",
      "e2e.brain-graph.error-empty-retry",
      "e2e.brain-graph.global-empty-inbox",
      "e2e.brain-graph.global-reviewed-boundary",
      "e2e.brain-graph.controls-filters-views",
      "e2e.brain-graph.outcome-tags",
      "e2e.brain-graph.canvas-table-inspector",
      "e2e.brain-graph.motion-and-signals",
      "e2e.brain-graph.atlas-renderer",
      "e2e.brain-graph.atlas-fallback",
      "e2e.brain-graph.visual-canvas-table",
      "e2e.brain-graph.deep-links-history",
      "e2e.brain-graph.private-source-custody",
      "e2e.brain-graph.inspector-context-retry",
    ]);

    expect(home).toHaveLength(14);
    expect(inbox).toHaveLength(27);
    expect(graph).toHaveLength(54);
    expect(staticHome.map((entry) => entry.id)).toEqual(["brain.home.operator-preferences"]);
    expect(staticInbox.map((entry) => entry.id)).toEqual(["brain.inbox.operator-preferences"]);
    expect(staticGraph.map((entry) => entry.id)).toEqual([
      "brain.graph.date-range",
      "brain.graph.operator-preferences",
    ]);
    expect([...staticHome, ...staticInbox, ...staticGraph]
      .every((entry) => entry.testIds.includes("e2e.manifest.coverage-audit"))).toBe(true);
    expect(graphReturn).toHaveLength(1);
    expect(entries).toHaveLength(96);
    expect(new Set(home.map((entry) => entry.route))).toEqual(new Set(["/brain"]));
    expect(new Set(inbox.map((entry) => entry.route))).toEqual(new Set(["/brain/inbox"]));
    expect(new Set(graph.map((entry) => entry.route))).toEqual(new Set(["/brain/graph"]));
    expect(new Set(graphReturn.map((entry) => entry.route))).toEqual(new Set(["/brain/nodes/:memoryNodeId"]));
    for (const entry of entries) {
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), entry.id).toBe(false);
      expect(entry.testIds.every((testId) => allowedTestIds.has(testId)), entry.id).toBe(true);
    }
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    expect(graph.find((entry) => entry.id === "brain.graph.canvas")?.accessible.role).toBe("application");
    expect(home.find((entry) => entry.id === "brain.home.node-links")?.accessible.name)
      .toBe("^Open memory .+ \\([A-Za-z0-9._:-]+\\)$");
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(608);
  });

  test("inventories the authenticated Operator Preferences route and its populated profile links", () => {
    const entries = manifest.entries.filter((entry) => entry.id.startsWith("brain.preferences."));
    const populated = entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const staticEntries = entries.filter((entry) => !entry.requiredState.startsWith("Fixture required:"));

    expect(entries.map((entry) => entry.id)).toEqual([
      "brain.preferences.navigation",
      "brain.preferences.operator-graph",
      "brain.preferences.memory-record",
      "brain.preferences.show-in-graph",
      "brain.preferences.empty-inbox",
      "brain.preferences.retry.read",
    ]);
    expect(entries.every((entry) => entry.route === "/brain/preferences")).toBe(true);
    expect(populated.map((entry) => entry.id)).toEqual([
      "brain.preferences.memory-record",
      "brain.preferences.show-in-graph",
      "brain.preferences.retry.read",
    ]);
    expect(populated.map((entry) => entry.testIds)).toEqual([
      ["e2e.brain-preferences.confirmed-profile"],
      ["e2e.brain-preferences.confirmed-profile"],
      ["e2e.brain.read-retry-accessibility"],
    ]);
    expect(staticEntries.map((entry) => entry.id)).toEqual([
      "brain.preferences.navigation",
      "brain.preferences.operator-graph",
      "brain.preferences.empty-inbox",
    ]);
    expect(staticEntries.every((entry) => entry.testIds.includes("e2e.manifest.coverage-audit"))).toBe(true);
  });

  test("maps all Brain node controls only to graph, lifecycle, and targeted Vault fixture paths", () => {
    const allEntries = manifest.entries.filter((entry) => entry.id.startsWith("brain.node."));
    const entries = allEntries.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const staticEntries = allEntries.filter((entry) => !entry.requiredState.startsWith("Fixture required:"));
    const expected = [
      { id: "brain.node.show-in-graph", testIds: ["e2e.brain-graph.deep-links-history"] },
      { id: "brain.node.provenance-load-more", testIds: ["e2e.brain-node.provenance-pagination"] },
      { id: "brain.node.private-source-load-more", testIds: ["e2e.brain-node.provenance-pagination"] },
      { id: "brain.node.context-use", testIds: ["e2e.brain-node.lifecycle-controls", "e2e.brain-node.navigation-and-vault-controls"] },
      { id: "brain.node.private-source-mission", testIds: ["e2e.brain-node.private-source-custody"] },
      { id: "brain.node.private-source-run", testIds: ["e2e.brain-node.private-source-custody"] },
      { id: "brain.node.private-source-evidence", testIds: ["e2e.brain-node.private-source-custody"] },
      { id: "brain.node.private-source-artifact", testIds: ["e2e.brain-node.private-source-custody"] },
      { id: "brain.node.private-source-reference", testIds: ["e2e.brain-node.private-source-custody"] },
      { id: "brain.node.operational-hazard.reset-review-toggle", testIds: ["e2e.brain-node.operational-hazard"] },
      { id: "brain.node.operational-hazard.reset-run", testIds: ["e2e.brain-node.operational-hazard"] },
      { id: "brain.node.operational-hazard.reset-minimum", testIds: ["e2e.brain-node.operational-hazard"] },
      { id: "brain.node.operational-hazard.reset-boundary", testIds: ["e2e.brain-node.operational-hazard"] },
      { id: "brain.node.operational-hazard.reset-record", testIds: ["e2e.brain-node.operational-hazard"] },
      { id: "brain.node.operational-hazard.references", testIds: ["e2e.brain-node.operational-hazard"] },
      { id: "brain.node.correct.open", testIds: ["e2e.brain-node.lifecycle-controls"] },
      { id: "brain.node.correct.fields", testIds: ["e2e.brain-node.lifecycle-controls"] },
      { id: "brain.node.correct.sensitivity", testIds: ["e2e.brain-node.lifecycle-controls"] },
      { id: "brain.node.correct.cancel", testIds: ["e2e.brain-node.lifecycle-controls"] },
      { id: "brain.node.correct.save", testIds: ["e2e.brain-node.lifecycle-controls"] },
      { id: "brain.node.pin", testIds: ["e2e.brain-node.lifecycle-controls", "e2e.brain-node.conflict-forget"] },
      { id: "brain.node.expiry-input", testIds: ["e2e.brain-node.lifecycle-controls"] },
      { id: "brain.node.expiry-set", testIds: ["e2e.brain-node.lifecycle-controls"] },
      { id: "brain.node.dispute-reason", testIds: ["e2e.brain-node.lifecycle-controls"] },
      { id: "brain.node.dispute", testIds: ["e2e.brain-node.lifecycle-controls"] },
      { id: "brain.node.vault-selection", testIds: ["e2e.brain-node.vault-export-deep-link"] },
      { id: "brain.node.vault-export", testIds: ["e2e.brain-node.vault-export-deep-link"] },
      { id: "brain.node.vault-open", testIds: ["e2e.brain-node.vault-export-deep-link"] },
      { id: "brain.node.forget-reason", testIds: ["e2e.brain-node.conflict-forget"] },
      { id: "brain.node.forget-confirmation", testIds: ["e2e.brain-node.conflict-forget"] },
      { id: "brain.node.forget", testIds: ["e2e.brain-node.conflict-forget"] },
      { id: "brain.node.navigation", testIds: ["e2e.brain-node.navigation-and-vault-controls"] },
      { id: "brain.node.retry.record", testIds: ["e2e.brain-node.read-recovery"] },
      { id: "brain.node.retry.vault", testIds: ["e2e.brain-node.read-recovery"] },
      { id: "brain.node.retry.context-pack", testIds: ["e2e.brain-node.read-recovery"] },
      { id: "brain.node.retry.mutation-reconcile", testIds: ["e2e.brain-node.conflict-forget"] },
      { id: "brain.node.open-vault-controls", testIds: ["e2e.brain-node.navigation-and-vault-controls"] },
      { id: "brain.node.context.path-link", testIds: ["e2e.brain-node.navigation-and-vault-controls"] },
      { id: "brain.node.context.node-link", testIds: ["e2e.brain-node.navigation-and-vault-controls"] },
      { id: "brain.node.relationship-link", testIds: ["e2e.brain-node.navigation-and-vault-controls"] },
    ] as const;
    const allowedTestIds = new Set([
      "e2e.brain-graph.deep-links-history",
      "e2e.brain-node.provenance-pagination",
      "e2e.brain-node.lifecycle-controls",
      "e2e.brain-node.conflict-forget",
      "e2e.brain-node.vault-export-deep-link",
      "e2e.brain-node.operational-hazard",
      "e2e.brain-node.private-source-custody",
      "e2e.brain-node.read-recovery",
      "e2e.brain-node.navigation-and-vault-controls",
    ]);

    expect(entries).toHaveLength(40);
    expect(staticEntries).toEqual([]);
    expect(entries.map((entry) => entry.id)).toEqual(expected.map((entry) => entry.id));
    for (const expectedEntry of expected) {
      const entry = entries.find((candidate) => candidate.id === expectedEntry.id);
      expect(entry, expectedEntry.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route, entry.id).toBe("/brain/nodes/:memoryNodeId");
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.testIds, entry.id).toEqual(expectedEntry.testIds);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), entry.id).toBe(false);
      expect(entry.testIds.every((testId) => allowedTestIds.has(testId)), entry.id).toBe(true);
    }
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    const targetedVaultVisual = entries.filter((entry) => entry.screenshotsRequired.length > 0);
    expect(targetedVaultVisual.map((entry) => entry.id)).toEqual([
      "brain.node.vault-selection",
      "brain.node.vault-export",
      "brain.node.vault-open",
    ]);
    expect(new Set(targetedVaultVisual.flatMap((entry) => entry.screenshotsRequired))).toEqual(new Set([
      "visual.brain-node.vault-exported.chromium-1440",
    ]));
  });

  test("inventories every Memory Control Center control against only its three dedicated fixture sources", () => {
    const allEntries = manifest.entries.filter((entry) => entry.id.startsWith("brain.control."));
    const entries = allEntries.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const staticEntries = allEntries.filter((entry) => !entry.requiredState.startsWith("Fixture required:"));
    const controls = "e2e.brain-control.all-controls-save-reload";
    const conflict = "e2e.brain-control.version-conflict-retry";
    const invariants = "e2e.brain-control.locked-invariants";
    const readRetries = "e2e.brain.read-retry-accessibility";
    const expected = [
      { id: "brain.control.navigation", role: "link", name: "^(?:Home|Graph|Memory Inbox|Controls|Obsidian Vault)$", options: ["Home", "Graph", "Memory Inbox", "Controls", "Obsidian Vault"], testIds: [controls] },
      { id: "brain.control.export-sync", role: "link", name: "Export or sync", options: ["Open Obsidian Vault export and synchronization"], testIds: [controls] },
      { id: "brain.control.enabled", role: "checkbox", name: "Enable memory retention and retrieval", options: ["Enabled", "Disabled"], testIds: [controls] },
      { id: "brain.control.preference-policy", role: "combobox", name: "Personal preference learning", options: ["Candidate only — always review", "Disabled"], testIds: [controls] },
      { id: "brain.control.operational-memory", role: "checkbox", name: "Retain evidence-backed operational knowledge", options: ["Retain", "Do not retain"], testIds: [controls] },
      { id: "brain.control.retention", role: "combobox", name: "Default retention", options: ["30 days", "90 days", "1 year", "3 years", "No automatic expiry"], testIds: [controls, conflict] },
      { id: "brain.control.autonomous-use", role: "checkbox", name: "Allow permitted confirmed memory in Autonomous runs", options: ["Allow permitted confirmed memory", "Do not allow memory use"], testIds: [controls] },
      { id: "brain.control.guided-use", role: "checkbox", name: "Allow confirmed preferences and knowledge in Guided missions", options: ["Allow confirmed preferences and knowledge", "Do not allow memory use"], testIds: [controls] },
      { id: "brain.control.sync-scope", role: "combobox", name: "Synchronization scope", options: ["Disabled", "Confirmed nodes", "Confirmed and verified nodes"], testIds: [controls] },
      { id: "brain.control.invariant.isolation", role: "checkbox", name: "Strict engagement isolation", options: ["Always enabled"], testIds: [controls, invariants] },
      { id: "brain.control.invariant.secrets", role: "checkbox", name: "Never retain credentials, tokens, private keys, or authentication material", options: ["Always enabled"], testIds: [controls, invariants] },
      { id: "brain.control.save", role: "button", name: "Save memory controls", options: ["Save represented changes", "Save unchanged canonical policy to sanitize unknown stored fields"], testIds: [controls, conflict, invariants] },
      { id: "brain.control.conflict-retry", role: "button", name: "Try again", options: ["Refresh canonical version and retry the unchanged represented draft once"], testIds: [conflict] },
      { id: "brain.control.retry.read", role: "button", name: "Retry memory controls", options: ["Retry only the canonical memory controls"], testIds: [readRetries] },
    ] as const;
    const allowedTestIds = new Set([controls, conflict, invariants, readRetries]);

    expect(entries).toHaveLength(14);
    expect(staticEntries.map((entry) => entry.id)).toEqual(["brain.control.operator-preferences"]);
    expect(staticEntries[0]?.testIds).toEqual(["e2e.manifest.coverage-audit"]);
    expect(entries.map((entry) => entry.id)).toEqual(expected.map((entry) => entry.id));
    for (const expectedEntry of expected) {
      const entry = entries.find((candidate) => candidate.id === expectedEntry.id);
      expect(entry, expectedEntry.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route, entry.id).toBe("/brain/control");
      expect(entry.accessible.name, entry.id).toBe(expectedEntry.name);
      expect("role" in entry.accessible ? entry.accessible.role : entry.accessible.locator, entry.id).toBe(expectedEntry.role);
      expect(entry.options, entry.id).toEqual(expectedEntry.options);
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.testIds, entry.id).toEqual(expectedEntry.testIds);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), entry.id).toBe(false);
      expect(entry.testIds.every((testId) => allowedTestIds.has(testId)), entry.id).toBe(true);
    }
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(608);
  });

  test("inventories the mounted Vault lifecycle against dedicated isolated fixture sources", () => {
    const allEntries = manifest.entries.filter((entry) => entry.id.startsWith("brain.vault."));
    const entries = allEntries.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const presetTestId = "e2e.brain-vault.attack-knowledge-preset";
    const presetEntries = allEntries.filter((entry) => entry.id.startsWith("brain.vault.attack-preset-"));
    const disconnectTestId = "e2e.brain-vault.disconnect-projection";
    const disconnectEntries = allEntries.filter((entry) => entry.id.startsWith("brain.vault.disconnect-"));
    const staticEntries = allEntries.filter((entry) => (
      !entry.requiredState.startsWith("Fixture required:")
      && !entry.id.startsWith("brain.vault.attack-preset-")
      && !entry.id.startsWith("brain.vault.disconnect-")
    ));
    const roundTrip = "e2e.brain-vault.round-trip-connect-reload";
    const pathRetry = "e2e.brain-vault.path-denial-retry";
    const projectionLifecycle = "e2e.brain-vault.sync-import-export-portable";
    const conflicts = "e2e.brain-vault.conflict-resolution";
    const degradedRecovery = "e2e.brain-vault.degraded-recovery";
    const recovery = "e2e.brain-vault.repair-reindex-recovery";
    const readRetries = "e2e.brain.read-retry-accessibility";
    const operationRetries = "e2e.brain-vault.operation-retries";
    const expected = [
      { id: "brain.vault.display-name", role: "textbox", name: "Display name", options: ["Disposable fixture display name"], testIds: [roundTrip] },
      { id: "brain.vault.relative-path", role: "textbox", name: "Path inside the allowed root", options: ["Valid relative path", "Traversal path rejected", "Corrected valid relative path"], testIds: [roundTrip, pathRetry] },
      { id: "brain.vault.filesystem-permission", role: "checkbox", name: "Grant explicit filesystem permission", options: ["Grant explicit permission for the selected Vault candidate"], testIds: [roundTrip, pathRetry] },
      { id: "brain.vault.round-trip-health", role: "button", name: "Test write, read, rename, and delete", options: ["Verify valid relative path", "Reject traversal without disclosing absolute paths", "Retry after deliberate safe path correction"], testIds: [roundTrip, pathRetry] },
      { id: "brain.vault.connect-verified", role: "button", name: "Connect verified vault", options: ["Disabled before matching round-trip proof", "Connect after matching round-trip proof"], testIds: [roundTrip] },
      { id: "brain.vault.connection-health", role: "button", name: "Test connection", options: ["Recheck a connected Vault", "Recover a degraded connection after a successful proof"], testIds: [degradedRecovery] },
      { id: "brain.vault.disconnect-open", role: "button", name: "Disconnect projection", options: ["Open the represented connection's disconnect review"], testIds: [disconnectTestId] },
      { id: "brain.vault.repair", role: "button", name: "Repair vault", options: ["Reconcile valid managed records", "Quarantine malformed notes", "Preserve canonical memory for missing projections", "Preserve open conflicts", "Reject symlinks", "Fail closed while offline"], testIds: [recovery] },
      { id: "brain.vault.reindex", role: "button", name: "Reindex vault", options: ["Parse bounded current managed notes", "Refresh represented canonical search rows", "Preserve open conflicts and SQLite source-of-truth"], testIds: [recovery] },
      { id: "brain.vault.synchronize", role: "button", name: "Synchronize", options: ["Project a canonical-only edit", "Import a Vault-only edit", "Create a visible conflict for concurrent edits"], testIds: [projectionLifecycle, conflicts] },
      { id: "brain.vault.export", role: "button", name: "Export canonical notes", options: ["Export every accessible note in the connection scope"], testIds: [projectionLifecycle, conflicts] },
      { id: "brain.vault.import", role: "button", name: "Import operator edits", options: ["Import valid operator edits", "Quarantine malformed notes according to backend policy"], testIds: [projectionLifecycle] },
      { id: "brain.vault.portable-export", role: "button", name: "Portable ZIP disabled", options: ["No archive creation is available"], testIds: [projectionLifecycle] },
      { id: "brain.vault.sync-state-details", role: "native-summary", name: "Note synchronization state", options: ["Open tracked note state", "Close tracked note state"], testIds: [projectionLifecycle] },
      { id: "brain.vault.open-native", role: "link", name: "^(?:Open vault in Obsidian|Open .+ in Obsidian)$", options: ["Open Vault root", "Open represented projected note"], testIds: [projectionLifecycle] },
      { id: "brain.vault.conflict-keep-database", role: "button", name: "Keep database version", options: ["Select the represented canonical database version"], testIds: [conflicts] },
      { id: "brain.vault.conflict-keep-vault", role: "button", name: "Keep vault version", options: ["Select the represented operator Vault version"], testIds: [conflicts] },
      { id: "brain.vault.retry.snapshot", role: "button", name: "Retry Vault snapshot", options: ["Retry only the canonical Vault snapshot"], testIds: [readRetries] },
      { id: "brain.vault.retry.preset-preview", role: "button", name: "Retry Attack Knowledge Vault preview", options: ["Retry only the registry-owned preset preview"], testIds: [readRetries] },
      { id: "brain.vault.preset-health-retry", role: "button", name: "Retry preset path health check", options: ["Retry preset path health check"], testIds: [operationRetries] },
      { id: "brain.vault.custom-health-retry", role: "button", name: "Retry custom Vault path health check", options: ["Retry custom Vault path health check"], testIds: [operationRetries] },
      { id: "brain.vault.connect-retry", role: "button", name: "Retry Vault connection", options: ["Retry Vault connection"], testIds: [operationRetries] },
      { id: "brain.vault.retry.repair", role: "button", name: "Retry Vault repair", options: ["Retry the same version-pinned repair after the path is restored"], testIds: [recovery] },
      { id: "brain.vault.reindex-retry", role: "button", name: "Retry Vault reindex", options: ["Retry Vault reindex"], testIds: [operationRetries] },
      { id: "brain.vault.reconcile-retry", role: "button", name: "Retry Vault status refresh", options: ["Retry Vault status refresh"], testIds: [operationRetries] },
      { id: "brain.vault.recovery-details", role: "native-summary", name: "Recovery details", options: ["Open issue details", "Close issue details"], testIds: [recovery] },
    ] as const;
    const expectedPreset = [
      { id: "brain.vault.attack-preset-categories", role: "native-summary", name: "Review projected categories and folders" },
      { id: "brain.vault.attack-preset-confirmed", role: "checkbox", name: "Include operator-confirmed attack knowledge" },
      { id: "brain.vault.attack-preset-operator-profile", role: "checkbox", name: "Include Operator Preferences and Profile" },
      { id: "brain.vault.attack-preset-permission", role: "checkbox", name: "Grant Attack Knowledge Vault filesystem permission" },
      { id: "brain.vault.attack-preset-acknowledgement", role: "checkbox", name: "Acknowledge Attack Knowledge Vault activation" },
      { id: "brain.vault.attack-preset-health", role: "button", name: "Test preset path" },
      { id: "brain.vault.attack-preset-activate", role: "button", name: "Activate Attack Knowledge Vault" },
      { id: "brain.vault.attack-preset-amend-acknowledgement", role: "checkbox", name: "Acknowledge Attack Knowledge Vault confirmed scope amendment" },
      { id: "brain.vault.attack-preset-amend", role: "button", name: "Apply confirmed knowledge scope" },
      { id: "brain.vault.attack-preset-operator-profile-acknowledgement", role: "checkbox", name: "Acknowledge Operator Profile Vault scope amendment" },
      { id: "brain.vault.attack-preset-operator-profile-amend", role: "button", name: "Add Operator Profile to Vault" },
    ] as const;
    const expectedDisconnect = [
      { id: "brain.vault.disconnect-open", role: "button", name: "Disconnect projection" },
      { id: "brain.vault.disconnect-reason", role: "textbox", name: "Reason for disconnecting" },
      { id: "brain.vault.disconnect-acknowledgement", role: "checkbox", name: "Acknowledge Vault disconnect effects" },
      { id: "brain.vault.disconnect-degraded-acknowledgement", role: "checkbox", name: "Allow controlled degraded Obsidian projection" },
      { id: "brain.vault.disconnect-cancel", role: "button", name: "Cancel" },
      { id: "brain.vault.disconnect-confirm", role: "button", name: "Disconnect Vault projection" },
    ] as const;
    const allowedTestIds = new Set([
      roundTrip,
      pathRetry,
      projectionLifecycle,
      conflicts,
      degradedRecovery,
      recovery,
      disconnectTestId,
      readRetries,
      operationRetries,
    ]);

    expect(entries).toHaveLength(26);
    expect(presetEntries.map((entry) => entry.id)).toEqual(expectedPreset.map((entry) => entry.id));
    for (const expectedEntry of expectedPreset) {
      const entry = presetEntries.find((candidate) => candidate.id === expectedEntry.id);
      expect(entry, expectedEntry.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route, entry.id).toBe("/brain/vault");
      expect(entry.accessible.name, entry.id).toBe(expectedEntry.name);
      expect("role" in entry.accessible ? entry.accessible.role : entry.accessible.locator, entry.id).toBe(expectedEntry.role);
      expect(entry.requiredState.length, entry.id).toBeGreaterThan(40);
      expect(entry.testIds, entry.id).toEqual([presetTestId]);
      expect(entry.screenshotsRequired, entry.id).toEqual([]);
    }
    expect(disconnectEntries.map((entry) => entry.id)).toEqual(expectedDisconnect.map((entry) => entry.id));
    for (const expectedEntry of expectedDisconnect) {
      const entry = disconnectEntries.find((candidate) => candidate.id === expectedEntry.id);
      expect(entry, expectedEntry.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route, entry.id).toBe("/brain/vault");
      expect(entry.accessible.name, entry.id).toBe(expectedEntry.name);
      expect("role" in entry.accessible ? entry.accessible.role : entry.accessible.locator, entry.id).toBe(expectedEntry.role);
      expect(entry.testIds, entry.id).toEqual([disconnectTestId]);
      expect(entry.screenshotsRequired, entry.id).toEqual([]);
    }
    expect(staticEntries.map((entry) => entry.id)).toEqual([
      "brain.vault.navigation",
      "brain.vault.operator-preferences",
    ]);
    expect(staticEntries.every((entry) => (
      entry.testIds.length === 1 && entry.testIds[0] === "e2e.brain-vault.navigation"
    ))).toBe(true);
    expect(entries.map((entry) => entry.id)).toEqual(expected.map((entry) => entry.id));
    for (const expectedEntry of expected) {
      const entry = entries.find((candidate) => candidate.id === expectedEntry.id);
      expect(entry, expectedEntry.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route, entry.id).toBe("/brain/vault");
      expect(entry.accessible.name, entry.id).toBe(expectedEntry.name);
      expect("role" in entry.accessible ? entry.accessible.role : entry.accessible.locator, entry.id).toBe(expectedEntry.role);
      expect(entry.options, entry.id).toEqual(expectedEntry.options);
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.testIds, entry.id).toEqual(expectedEntry.testIds);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), entry.id).toBe(false);
      expect(entry.testIds.every((testId) => allowedTestIds.has(testId)), entry.id).toBe(true);
    }
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    const remainingVaultGap = manifest.knownGaps.find((gap) => gap.includes("service-process restart"));
    expect(remainingVaultGap).toContain("installed Obsidian host");
    expect(remainingVaultGap).not.toContain("Vault navigation activation");
    expect(remainingVaultGap).not.toContain("Vault repair/reindex");
    expect(remainingVaultGap).not.toContain("offline recovery");
    const visualEntries = entries.filter((entry) => entry.screenshotsRequired.length > 0);
    expect(visualEntries.map((entry) => entry.id)).toEqual([
      "brain.vault.relative-path",
      "brain.vault.round-trip-health",
      "brain.vault.connect-verified",
      "brain.vault.connection-health",
      "brain.vault.repair",
      "brain.vault.reindex",
      "brain.vault.synchronize",
      "brain.vault.conflict-keep-database",
      "brain.vault.conflict-keep-vault",
    ]);
    expect(new Set(visualEntries.flatMap((entry) => entry.screenshotsRequired)).size).toBe(6);
    const unmappedVisualEntryCount = manifest.entries.filter((entry) => entry.screenshotsRequired.length === 0).length;
    expect(unmappedVisualEntryCount).toBe(774);
    expect(manifest.knownGaps.some((gap) =>
      gap.includes("Twenty-one deterministic project-scoped")
      && gap.includes(`remaining ${unmappedVisualEntryCount} entries`)
    )).toBe(true);
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(608);
  });

  test("inventories System controls against only existing dedicated System fixture sources", () => {
    const allEntries = manifest.entries.filter((entry) => (
      entry.id.startsWith("system.") && !entry.id.startsWith("system.model.")
    ));
    const entries = allEntries.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const staticEntries = allEntries.filter((entry) => !entry.requiredState.startsWith("Fixture required:"));
    const expected = [
      { id: "system.navigation.tabs", route: "/system/:view", locator: "link", name: "^(?:Connections|Policies|Settings status)$", testIds: ["e2e.system.routes-and-tabs"] },
      { id: "system.connections.provider-pagination", route: "/system/connections", locator: "button", name: "^(?:First page|Next page)$", testIds: ["e2e.system.routes-and-tabs", "e2e.system.connections-controls"] },
      { id: "system.connections.capability-refresh", route: "/system/connections", locator: "button", name: "^Refresh(?:ing)? readiness records$", testIds: ["e2e.system.connections-controls"] },
      { id: "system.connections.capability-authorization-details", route: "/system/connections", locator: "native-summary", name: "Read-only authorization detail", testIds: ["e2e.system.connections-controls"] },
      { id: "system.connections.mcp-status", route: "/system/connections", locator: "combobox", name: "Status", testIds: ["e2e.system.routes-and-tabs", "e2e.system.connections-controls"] },
      { id: "system.connections.mcp-details", route: "/system/connections", locator: "native-summary", name: "Capabilities and policy", testIds: ["e2e.system.routes-and-tabs", "e2e.system.connections-controls"] },
      { id: "system.connections.mcp-pagination", route: "/system/connections", locator: "button", name: "^(?:First page|Next page)$", testIds: ["e2e.system.routes-and-tabs", "e2e.system.connections-controls"] },
      { id: "system.policies.document-details", route: "/system/policies", locator: "native-summary", name: "Redacted policy document", testIds: ["e2e.system.policies-controls"] },
      { id: "system.policies.pagination", route: "/system/policies", locator: "button", name: "^(?:First page|Next page)$", testIds: ["e2e.system.policies-controls"] },
      { id: "system.settings.openapi-contract", route: "/system/settings", locator: "link", name: "Open API contract", testIds: ["e2e.system.settings-controls"] },
      { id: "system.settings.event-contract", route: "/system/settings", locator: "link", name: "Open event contract", testIds: ["e2e.system.settings-controls"] },
      { id: "system.query.retry", route: "/system/:view", locator: "button", name: "Try again", testIds: ["e2e.system.connections-retry"] },
      { id: "system.openrouter.state", route: "/system/connections", locator: "combobox", name: "OpenRouter connection state", testIds: ["e2e.system.openrouter-connection"] },
      { id: "system.openrouter.model", route: "/system/connections", locator: "textbox", name: "Exact OpenRouter model", testIds: ["e2e.system.openrouter-connection"] },
      { id: "system.openrouter.credential", route: "/system/connections", locator: "textbox", name: "^(Replace )?OpenRouter credential$", testIds: ["e2e.system.openrouter-connection"] },
      { id: "system.openrouter.save", route: "/system/connections", locator: "button", name: "^(Save connection|Saving private connection)$", testIds: ["e2e.system.openrouter-connection"] },
      { id: "system.openrouter.attestation", route: "/system/connections", locator: "button", name: "^(Verify connection & refresh catalog|Verifying provider and model)$", testIds: ["e2e.system.openrouter-connection"] },
    ] as const;
    const allowedTestIds = new Set([
      "e2e.system.routes-and-tabs",
      "e2e.system.connections-controls",
      "e2e.system.connections-retry",
      "e2e.system.policies-controls",
      "e2e.system.settings-controls",
      "e2e.system.openrouter-connection",
    ]);

    expect(entries).toHaveLength(17);
    expect(staticEntries.map((entry) => entry.id)).toEqual([
      "system.surface-navigation",
      "system.status-filter",
      "system.settings.metrics",
    ]);
    expect(staticEntries.every((entry) => entry.testIds.includes("e2e.manifest.coverage-audit"))).toBe(true);
    expect(manifest.entries.find((entry) => entry.id === "system.settings.metrics")?.testIds)
      .toEqual(["e2e.manifest.coverage-audit", "e2e.system.settings-controls"]);
    expect(entries.map((entry) => entry.id)).toEqual(expected.map((entry) => entry.id));
    for (const expectedEntry of expected) {
      const entry = entries.find((candidate) => candidate.id === expectedEntry.id);
      expect(entry, expectedEntry.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route, entry.id).toBe(expectedEntry.route);
      expect(entry.accessible.name, entry.id).toBe(expectedEntry.name);
      expect("role" in entry.accessible ? entry.accessible.role : entry.accessible.locator, entry.id).toBe(expectedEntry.locator);
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.testIds, entry.id).toEqual(expectedEntry.testIds);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), entry.id).toBe(false);
      expect(entry.testIds.every((testId) => allowedTestIds.has(testId)), entry.id).toBe(true);
    }
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    expect(new Set(entries.map((entry) => entry.route))).toEqual(new Set([
      "/system/:view",
      "/system/connections",
      "/system/policies",
      "/system/settings",
    ]));
    expect(manifest.entries.find((entry) => entry.id === "system.query.retry")?.options).toEqual([
      "Retry the failed capability readiness query",
      "Retry the failed provider history query",
      "Retry the failed MCP registry query",
      "Retry the failed policy projection query",
      "Retry the failed system health query",
      "Retry the failed settings policy inventory query",
    ]);
    expect(manifest.knownGaps.some((gap) => gap.includes("health-error retry"))).toBe(false);
    expect(manifest.knownGaps.some((gap) => gap.includes("non-MCP query-retry states"))).toBe(false);
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(608);
    expect(manifest.knownGaps.some((gap) => gap.includes("System health-metric activation"))).toBe(false);
  });

  test("inventories Overview shortcuts and every Mission Portfolio control family against only existing portfolio fixtures", () => {
    const entries = manifest.entries.filter((entry) => entry.id.startsWith("overview.portfolio.") || entry.id.startsWith("mission-portfolio."));
    const expected = [
      { id: "overview.portfolio.shortcuts", route: "/", locator: "link", name: "^(?:View portfolio|Inspect fleet|Open Brain|Connections)$", testIds: ["e2e.overview.portfolio-shortcuts"] },
      { id: "overview.portfolio.mission-links", route: "/", locator: "link", name: "^Open active mission .+ \\([A-Za-z0-9._:-]+\\)$", testIds: ["e2e.overview.mission-row-links"] },
      { id: "mission-portfolio.create-links", route: "/missions", locator: "link", name: "^(?:New mission|Create mission)$", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.search.query", route: "/missions", locator: "textbox", name: "Mission, phase, run, or next action", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.search.apply", route: "/missions", locator: "button", name: "Apply filters", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.journey", route: "/missions", locator: "combobox", name: "Journey", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.run-state", route: "/missions", locator: "combobox", name: "Run state", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.view", route: "/missions", locator: "combobox", name: "View", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.risk", route: "/missions", locator: "combobox", name: "Current risk", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.evidence", route: "/missions", locator: "combobox", name: "Evidence", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.finding-severity", route: "/missions", locator: "combobox", name: "Finding severity", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.decision-state", route: "/missions", locator: "combobox", name: "Decision state", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.recovery-state", route: "/missions", locator: "combobox", name: "Recovery state", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.engagement", route: "/missions", locator: "textbox", name: "Engagement", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.target", route: "/missions", locator: "textbox", name: "Target", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.agent", route: "/missions", locator: "textbox", name: "Agent / owner ID", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.provider", route: "/missions", locator: "textbox", name: "Provider", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.filter.dates", route: "/missions", locator: "native-date-input", name: "^(?:Updated from|Updated to)$", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.advanced-disclosure", route: "/missions", locator: "native-summary", name: "More canonical filters", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.mission-links", route: "/missions", locator: "link", name: "^Open mission .+ \\([A-Za-z0-9._:-]+\\)$", testIds: ["e2e.mission-portfolio.filters-saved-view", "e2e.mission-portfolio.pagination-deep-links"] },
      { id: "mission-portfolio.pagination", route: "/missions", locator: "button", name: "^(?:First page|Next page)$", testIds: ["e2e.mission-portfolio.pagination-deep-links"] },
      { id: "mission-portfolio.selection.row", route: "/missions", locator: "checkbox", name: "^Select mission .+ \\([A-Za-z0-9._:-]+\\)$", testIds: ["e2e.mission-portfolio.filters-saved-view", "e2e.mission-portfolio.bulk-actions", "e2e.mission-portfolio.bulk-failures"] },
      { id: "mission-portfolio.selection.all", route: "/missions", locator: "checkbox", name: "^Select all [0-9]+ visible missions$", testIds: ["e2e.mission-portfolio.pagination-deep-links", "e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.saved-view.name", route: "/missions", locator: "textbox", name: "Saved view name", testIds: ["e2e.mission-portfolio.filters-saved-view", "e2e.mission-portfolio.saved-view-failures"] },
      { id: "mission-portfolio.saved-view.save", route: "/missions", locator: "button", name: "Save view", testIds: ["e2e.mission-portfolio.filters-saved-view", "e2e.mission-portfolio.saved-view-failures"] },
      { id: "mission-portfolio.saved-view.apply", route: "/missions", locator: "button", name: "^Canonical saved portfolio .+$", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.saved-view.delete", route: "/missions", locator: "button", name: "^Delete saved view (?:Canonical|Failure-safe) saved portfolio .+$", testIds: ["e2e.mission-portfolio.filters-saved-view", "e2e.mission-portfolio.saved-view-failures"] },
      { id: "mission-portfolio.bulk.export", route: "/missions", locator: "button", name: "Export redacted metadata", testIds: ["e2e.mission-portfolio.bulk-actions", "e2e.mission-portfolio.bulk-failures"] },
      { id: "mission-portfolio.bulk.archive", route: "/missions", locator: "button", name: "Archive terminal missions", testIds: ["e2e.mission-portfolio.bulk-actions", "e2e.mission-portfolio.bulk-failures"] },
      { id: "mission-portfolio.bulk.dialog-cancel", route: "/missions", locator: "button", name: "Cancel", testIds: ["e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.bulk.dialog-confirm", route: "/missions", locator: "button", name: "^(?:Confirm|Retry) (?:export|archive)$", testIds: ["e2e.mission-portfolio.bulk-actions", "e2e.mission-portfolio.bulk-failures"] },
      { id: "mission-portfolio.bulk.outcome", route: "/missions", locator: "native-summary", name: "Per-mission outcomes", testIds: ["e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.retry", route: "/missions", locator: "button", name: "Try again", testIds: ["e2e.mission-portfolio.retry"] },
    ] as const;
    const allowedTestIds = new Set([
      "e2e.overview.portfolio-shortcuts",
      "e2e.overview.mission-row-links",
      "e2e.mission-portfolio.filters-saved-view",
      "e2e.mission-portfolio.pagination-deep-links",
      "e2e.mission-portfolio.saved-view-failures",
      "e2e.mission-portfolio.bulk-failures",
      "e2e.mission-portfolio.bulk-actions",
      "e2e.mission-portfolio.retry",
    ]);
    const filterOptions = new Map<string, readonly string[]>([
      ["mission-portfolio.filter.journey", ["All", "Autonomous", "Guided"]],
      ["mission-portfolio.filter.run-state", ["All", "queued", "planning", "awaiting contract confirmation", "running", "waiting guided decision", "blocked", "recovering", "completed", "failed", "cancelled"]],
      ["mission-portfolio.filter.view", ["Table", "Compact board"]],
      ["mission-portfolio.filter.risk", ["All", "informational", "low", "medium", "high", "critical"]],
      ["mission-portfolio.filter.evidence", ["All", "Has evidence", "No evidence"]],
      ["mission-portfolio.filter.finding-severity", ["All", "informational", "low", "medium", "high", "critical"]],
      ["mission-portfolio.filter.decision-state", ["All", "pending", "approved", "manual", "alternative", "rejected", "expired", "cancelled"]],
      ["mission-portfolio.filter.recovery-state", ["All", "Recovering", "Blocked", "No recovery state"]],
    ]);

    expect(entries).toHaveLength(33);
    expect(entries.map((entry) => entry.id)).toEqual(expected.map((entry) => entry.id));
    for (const expectedEntry of expected) {
      const entry = entries.find((candidate) => candidate.id === expectedEntry.id);
      expect(entry, expectedEntry.id).toBeDefined();
      if (!entry) continue;
      expect(entry.route, entry.id).toBe(expectedEntry.route);
      expect(entry.accessible.name, entry.id).toBe(expectedEntry.name);
      expect("role" in entry.accessible ? entry.accessible.role : entry.accessible.locator, entry.id).toBe(expectedEntry.locator);
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.testIds, entry.id).toEqual(expectedEntry.testIds);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), entry.id).toBe(false);
      expect(entry.testIds.every((testId) => allowedTestIds.has(testId)), entry.id).toBe(true);
    }
    for (const [entryId, options] of filterOptions) {
      expect(entries.find((entry) => entry.id === entryId)?.options, entryId).toEqual(options);
    }
    expect(entries.find((entry) => entry.id === "mission-portfolio.saved-view.save")?.options).toEqual([
      "Save current filters and presentation",
      "Retry the exact failed write",
    ]);
    expect(entries.find((entry) => entry.id === "mission-portfolio.saved-view.delete")?.options).toEqual([
      "Delete the selected saved view",
      "Retry the exact failed delete",
    ]);
    expect(entries.find((entry) => entry.id === "mission-portfolio.bulk.dialog-confirm")?.options).toEqual([
      "Confirm export",
      "Confirm archive",
      "Retry export",
      "Retry archive",
    ]);
    expect(manifest.knownGaps.some((gap) => gap.includes("saved-view and bulk-operation failure paths"))).toBe(false);
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    expect(new Set(entries.filter((entry) => entry.id.startsWith("overview.")).map((entry) => entry.route))).toEqual(new Set(["/"]));
    expect(new Set(entries.filter((entry) => entry.id.startsWith("mission-portfolio.")).map((entry) => entry.route))).toEqual(new Set(["/missions"]));
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(608);
  });

  test("assigns every dynamic journey, agent, trace, and report family to a dedicated canonical browser path", () => {
    const expected = [
      { id: "guided-workspace.mission-links", route: "/guided", locator: "link", name: "^Open Guided mission .+ \\([A-Za-z0-9._:-]+\\)$", testIds: ["e2e.journey-portfolios.row-links"] },
      { id: "live-operations.run-links", route: "/live", locator: "link", name: "^Open Autonomous run .+ \\([A-Za-z0-9._:-]+\\)$", testIds: ["e2e.journey-portfolios.row-links"] },
      { id: "agents.list-profile-links", route: "/agents", locator: "link", name: "^Open agent .+ \\([A-Za-z0-9._:-]+\\)$", testIds: ["e2e.operational-lists.agents-pagination-detail"] },
      { id: "agents.list-pagination", route: "/agents", locator: "button", name: "^(?:First|Next) page of agents$", testIds: ["e2e.operational-lists.agents-pagination-detail"] },
      { id: "observability.trace-list-selectors", route: "/observability", locator: "button", name: "^Inspect trace .+ \\([A-Za-z0-9._:-]+\\)$", testIds: ["e2e.operational-lists.trace-pagination-detail"] },
      { id: "observability.trace-list-pagination", route: "/observability", locator: "button", name: "^(?:First|Next) page of traces$", testIds: ["e2e.operational-lists.trace-pagination-detail"] },
      { id: "reports.list-detail-links", route: "/reports", locator: "link", name: "^Open report .+ \\([A-Za-z0-9._:-]+\\)$", testIds: ["e2e.operational-lists.reports-pagination-detail"] },
      { id: "reports.list-pagination", route: "/reports", locator: "button", name: "^(?:First|Next) page of reports$", testIds: ["e2e.operational-lists.reports-pagination-detail"] },
    ] as const;
    const entries = expected.map((item) => manifest.entries.find((entry) => entry.id === item.id));
    expect(entries.every(Boolean)).toBe(true);
    entries.forEach((entry, index) => {
      if (!entry) return;
      const item = expected[index];
      expect(entry.route, item.id).toBe(item.route);
      expect("role" in entry.accessible ? entry.accessible.role : entry.accessible.locator, item.id).toBe(item.locator);
      expect(entry.accessible.name, item.id).toBe(item.name);
      expect(entry.requiredState.startsWith("Fixture required:"), item.id).toBe(true);
      expect(entry.testIds, item.id).toEqual(item.testIds);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), item.id).toBe(false);
    });
    expect(new Set(entries.flatMap((entry) => entry?.testIds ?? []))).toEqual(new Set([
      "e2e.journey-portfolios.row-links",
      "e2e.operational-lists.agents-pagination-detail",
      "e2e.operational-lists.trace-pagination-detail",
      "e2e.operational-lists.reports-pagination-detail",
    ]));
  });

  test("maps every workspace and per-agent model-assignment control to its dedicated browser proof", () => {
    const expected = [
      ["agents.model.configure-links", "/agents", "link", "^LLM settings for .+$", ["e2e.agent-model-settings.canonical-roster"]],
      ["agents.model.provider", "/agents/:agentId", "combobox", "^.+ provider$", ["e2e.agent-model-settings.configuration", "e2e.agent-model-settings.fail-closed", "e2e.agent-model-settings.real-backend-persistence"]],
      ["agents.model.primary", "/agents/:agentId", "combobox", "^.+ primary model$", ["e2e.agent-model-settings.configuration", "e2e.agent-model-settings.fail-closed", "e2e.agent-model-settings.real-backend-persistence"]],
      ["agents.model.reasoning", "/agents/:agentId", "combobox", "^.+ reasoning effort$", ["e2e.agent-model-settings.configuration", "e2e.agent-model-settings.fail-closed", "e2e.agent-model-settings.real-backend-persistence"]],
      ["agents.model.fallback", "/agents/:agentId", "combobox", "^.+ fallback model$", ["e2e.agent-model-settings.configuration", "e2e.agent-model-settings.fail-closed", "e2e.agent-model-settings.real-backend-persistence"]],
      ["agents.model.reason", "/agents/:agentId", "textbox", "Reason for this assignment", ["e2e.agent-model-settings.configuration", "e2e.agent-model-settings.fail-closed", "e2e.agent-model-settings.real-backend-persistence"]],
      ["agents.model.save", "/agents/:agentId", "button", "Save agent assignment", ["e2e.agent-model-settings.configuration", "e2e.agent-model-settings.fail-closed", "e2e.agent-model-settings.real-backend-persistence"]],
      ["agents.model.conflict-retry", "/agents/:agentId", "button", "Try again", ["e2e.agent-model-settings.fail-closed"]],
      ["agents.model.open-workspace-default", "/agents/:agentId", "link", "Open workspace model settings", ["e2e.agent-model-settings.fail-closed"]],
      ["agents.model.load-retry", "/agents/:agentId", "button", "Try again", ["e2e.agent-model-settings.fail-closed"]],
      ["agents.advisory.provider", "/agents/:agentId", "combobox", "^.+ advisory provider$", ["e2e.agent-model-settings.advisory"]],
      ["agents.advisory.primary", "/agents/:agentId", "combobox", "^.+ advisory primary model$", ["e2e.agent-model-settings.advisory"]],
      ["agents.advisory.reasoning", "/agents/:agentId", "combobox", "^.+ advisory reasoning effort$", ["e2e.agent-model-settings.advisory"]],
      ["agents.advisory.fallback", "/agents/:agentId", "combobox", "^.+ advisory fallback model$", ["e2e.agent-model-settings.advisory"]],
      ["agents.advisory.reason", "/agents/:agentId", "textbox", "Reason for this advisory assignment", ["e2e.agent-model-settings.advisory"]],
      ["agents.advisory.save", "/agents/:agentId", "button", "Save advisory assignment", ["e2e.agent-model-settings.advisory"]],
      ["system.model.provider", "/system/settings", "combobox", "Workspace default provider", ["e2e.agent-model-settings.global-default"]],
      ["system.model.primary", "/system/settings", "combobox", "Workspace default primary model", ["e2e.agent-model-settings.global-default"]],
      ["system.model.reasoning", "/system/settings", "combobox", "Workspace default reasoning effort", ["e2e.agent-model-settings.global-default"]],
      ["system.model.fallback", "/system/settings", "combobox", "Workspace default fallback model", ["e2e.agent-model-settings.global-default"]],
      ["system.model.reason", "/system/settings", "textbox", "Reason for this assignment", ["e2e.agent-model-settings.global-default"]],
      ["system.model.save", "/system/settings", "button", "Save workspace default", ["e2e.agent-model-settings.global-default"]],
      ["system.model.load-retry", "/system/settings", "button", "Try again", ["e2e.agent-model-settings.global-default"]],
    ] as const;
    const entries = manifest.entries.filter((entry) => (
      entry.id.startsWith("agents.model.")
      || entry.id.startsWith("agents.advisory.")
      || entry.id.startsWith("system.model.")
    ));
    expect(entries).toHaveLength(expected.length);
    expected.forEach(([id, route, role, name, testIds]) => {
      const entry = entries.find((candidate) => candidate.id === id);
      expect(entry, id).toBeDefined();
      if (!entry) return;
      expect(entry.route, id).toBe(route);
      expect(entry.requiredState.startsWith("Fixture required:"), id).toBe(true);
      expect("role" in entry.accessible ? entry.accessible.role : entry.accessible.locator, id).toBe(role);
      expect(entry.accessible.name, id).toBe(name);
      expect(entry.testIds, id).toEqual([...testIds]);
      expect(entry.testIds.includes("e2e.manifest.coverage-audit"), id).toBe(false);
    });
  });

  test("declares the required browser and viewport matrix on every current entry", () => {
    const requiredBrowsers = ["chromium", "firefox", "webkit", "chromium-enterprise", "android-chromium", "iphone-webkit", "tablet-chromium"];
    const requiredViewports = ["360x800", "390x844", "768x1024", "1024x768", "1280x800", "1440x900", "1920x1080", "2560x1440", "200%"];
    for (const entry of manifest.entries) {
      if (entry.id === "shell.mobile-navigation") {
        expect(entry.browsers).toEqual(["chromium", "android-chromium", "iphone-webkit", "tablet-chromium"]);
        expect(entry.viewports).toEqual(["360x800", "390x844", "768x1024", "200%"]);
        continue;
      }
      expect(entry.browsers).toEqual(expect.arrayContaining(requiredBrowsers));
      expect(entry.viewports).toEqual(expect.arrayContaining(requiredViewports));
    }
  });

  test("does not treat test-ID source text as executed browser coverage", () => {
    const bindings = bindManifestTestIdsToPlaywrightResults(manifest, []);
    expect(bindings.boundTestIds).toEqual([]);
    expect(bindings.missingTestIds).toEqual([...new Set(manifest.entries.flatMap((entry) => entry.testIds))].sort());
    expect(bindings.undeclaredTestIds).toEqual([]);
  });
});

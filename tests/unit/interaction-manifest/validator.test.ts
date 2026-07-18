import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import manifestJson from "../../interaction-manifest.json";
import schemaJson from "../../interaction-manifest.schema.json";
import { PRIMARY_NAVIGATION, USER_MANUAL_NAVIGATION } from "../../../src/app/router/routes";
import { INTERACTION_MANIFEST_NAMESPACE, validateInteractionManifest } from "../../interaction-manifest/schema";

const manifest = validateInteractionManifest(manifestJson);
const root = resolve(import.meta.dirname, "../../..");

function files(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const path = resolve(directory, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

describe("Ti-Scale interaction manifest", () => {
  test("is schema-valid, unique, and explicitly incomplete", () => {
    expect(manifest.namespace).toBe(INTERACTION_MANIFEST_NAMESPACE);
    expect(manifest.entries).toHaveLength(495);
    expect(new Set(manifest.entries.map((entry) => entry.id)).size).toBe(manifest.entries.length);
    expect(new Set(manifest.entries.map((entry) => entry.controlId)).size).toBe(manifest.entries.length);
    expect(manifest.knownGaps.length).toBeGreaterThan(0);
    expect(manifest.scope).toContain("shell navigation");
    expect(manifest.scope).toContain("complete currently rendered initial static-route inventory");
  });

  test("JSON schema and executable validator require the release-audit fields", () => {
    const entrySchema = (schemaJson.properties.entries.items as { required: string[] });
    const accessibleRoleSchema = schemaJson.properties.entries.items.properties.accessible.properties.role as { enum: string[] };
    const screenshotSchema = schemaJson.properties.entries.items.properties.screenshotsRequired as {
      uniqueItems: boolean;
      items: { pattern: string };
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
  });

  test("accounts for every current primary navigation destination", () => {
    const navigation = manifest.entries.filter((entry) => entry.id.startsWith("nav."));
    const expected = [...PRIMARY_NAVIGATION, USER_MANUAL_NAVIGATION].map((item) => `${item.label}|${item.path}`).sort();
    const actual = navigation.map((entry) => `${entry.accessible.name}|${entry.expectedStateTransition.replace("Navigate to ", "")}`).sort();
    expect(actual).toEqual(expected);
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

  test("accounts for every registry-driven intake step and collection in both journeys", () => {
    for (const journey of ["autonomous", "guided"] as const) {
      const entries = manifest.entries.filter((entry) => entry.route === `/missions/new/${journey}`);
      const steps = journey === "autonomous"
        ? ["Scope", "Outcome", "Contract", "Team", "Context", "Review"]
        : ["Scope", "Outcome", "Contract", "Review"];
      for (const step of steps) {
        expect(entries.some((entry) => entry.surface.includes(step) || entry.requiredState.toLocaleLowerCase("en-US").includes(step.toLocaleLowerCase("en-US")))).toBe(true);
      }
      expect(entries.find((entry) => entry.id === `${journey}-intake.scope.template`)?.options).toHaveLength(7);
      expect(entries.find((entry) => entry.id === `${journey}-intake.contract.action-classes`)?.options).toHaveLength(26);
      expect(entries.find((entry) => entry.id === `${journey}-intake.contract.deliverables`)?.options).toHaveLength(15);
      expect(entries.find((entry) => entry.id === `${journey}-intake.contract.evidence`)?.options).toHaveLength(21);
      expect(entries.find((entry) => entry.id === `${journey}-intake.contract.safe-stops`)?.options).toHaveLength(10);
    }
    expect(manifest.entries.find((entry) => entry.id === "autonomous-intake.team.specialists")?.controlType)
      .toBe("runtime-specialist-checkbox-collection");
    expect(manifest.entries.find((entry) => entry.id === "autonomous-intake.context.memories")?.controlType)
      .toBe("scope-safe-memory-checkbox-collection");
    expect(manifest.entries.find((entry) => entry.id === "autonomous-intake.context.scopes")?.options)
      .toEqual(["Confirmed operator preferences", "Verified operational lessons", "Engagement-isolated knowledge"]);
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

    expect(runIntelligence).toHaveLength(16);
    expect(operationalTruth).toHaveLength(25);
    expect(failureDiagnosis).toHaveLength(9);
    expect(planChanges).toHaveLength(13);
    expect(directPlanChanges).toHaveLength(46);
    expect(cveApplicability).toHaveLength(3);
    expect(artifactIntelligence).toHaveLength(14);
    expect(dynamicFixtureEntries).toHaveLength(126);
    expect(new Set(dynamicFixtureEntries.map((entry) => entry.route))).toEqual(new Set([
      "/missions/:missionId/runs/:runId",
      "/missions/:missionId/runs/:runId?tab=plan",
      "/missions/:missionId/runs/:runId?tab=evidence",
      "/live/:runId",
    ]));
    for (const entry of dynamicFixtureEntries) {
      expect(entry.requiredState.startsWith("Fixture required:"), entry.id).toBe(true);
      expect(entry.route).toContain(":");
    }
    const dedicated = dynamicFixtureEntries.filter((entry) => !entry.testIds.includes("e2e.manifest.coverage-audit"));
    const unresolved = dynamicFixtureEntries.filter((entry) => entry.testIds.includes("e2e.manifest.coverage-audit"));
    expect(topologyInteractions).toHaveLength(10);
    expect(dedicated.map((entry) => entry.id)).toEqual(dynamicFixtureEntries.map((entry) => entry.id));
    expect(dedicated).toHaveLength(126);
    expect(unresolved).toHaveLength(0);
    expect(unresolved.every((entry) => entry.testIds.length === 1)).toBe(true);
    expect(manifest.knownGaps.some((gap) => gap.includes("All 384 entries") && gap.includes("dedicated canonical fixture source traversal"))).toBe(true);
    expect(manifest.knownGaps.some((gap) => gap.includes("full browser matrix"))).toBe(true);
  });

  test("maps every run intervention and recovery control only to its five dedicated fixture paths", () => {
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
    ] as const;
    const allowedTestIds = new Set([
      "e2e.run-intervention.control-plane-rejection",
      "e2e.run-intervention.pause-resume-replay",
      "e2e.run-intervention.cancel-no-ghost",
      "e2e.run-recovery.replan-boundary-replay",
      "e2e.run-recovery.reassign-terminate",
    ]);

    expect(entries).toHaveLength(12);
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
      "e2e.command-palette.run-control",
      "e2e.command-palette.memory-candidate",
      "e2e.command-palette.partial-data",
    ]);
    expect(entries.map((entry) => entry.id)).toEqual(expectedIds);
    expect(entries).toHaveLength(22);
    expect(entries.every((entry) => entry.requiredState.startsWith("Fixture required:"))).toBe(true);
    expect(entries.every((entry) => entry.testIds.length >= 1 && entry.testIds.length <= 2)).toBe(true);
    expect(entries.every((entry) => entry.testIds.every((testId) => allowedTestIds.has(testId)))).toBe(true);
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    expect(entries.find((entry) => entry.id === "command-palette.results")?.accessible).toEqual({
      role: "listbox",
      name: "Command results",
      match: "exact",
    });
    for (const id of ["command-palette.search", "command-palette.results", "command-palette.agent-results", "command-palette.memory-results"]) {
      expect(entries.find((entry) => entry.id === id)?.testIds).toContain("e2e.command-palette.partial-data");
    }
    expect(entries.find((entry) => entry.id === "command-palette.editor-back")?.testIds)
      .toEqual(["e2e.command-palette.run-control", "e2e.command-palette.memory-candidate"]);
    expect(entries.find((entry) => entry.id === "command-palette.run-confirm")?.options)
      .toEqual(["Confirm pause", "Confirm resume", "Confirm cancel"]);
    expect(entries.find((entry) => entry.id === "command-palette.memory-create")?.expectedApiOrEventSideEffect)
      .toContain("Idempotency-Key");
    expect(manifest.knownGaps.some((gap) => gap.includes("command-palette material-state slice"))).toBe(true);
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
        name: "^decisionintelligence[a-f0-9]{12} (?:canonical intelligence fixture|imported intelligence without a run)$",
        options: ["Evidence owner", "Finding owner", "Artifact owner", "Imported relationless-record owner"],
        testIds: [
          "e2e.intelligence.evidence-list-detail-export",
          "e2e.intelligence.findings-list-detail-controls",
          "e2e.intelligence.artifacts-list-detail-controls",
        ],
      },
      {
        id: "intelligence.relationship.detail-run-links",
        route: "/intelligence/:view/:recordId",
        name: "^run-intelligence-lists-e2e-[a-z0-9-]+$",
        options: ["Evidence run", "Finding run", "Artifact run"],
        testIds: [
          "e2e.intelligence.evidence-list-detail-export",
          "e2e.intelligence.findings-list-detail-controls",
          "e2e.intelligence.artifacts-list-detail-controls",
        ],
      },
      {
        id: "intelligence.relationship.evidence-artifact-link",
        route: "/intelligence/evidence/:evidenceId",
        name: "^network_map_decisionintelligence[a-f0-9]{12}$",
        options: ["Open same-mission artifact metadata"],
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
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(384);
  });

  test("inventories Second Brain home, inbox, graph, and graph-return families against only their dedicated fixture sources", () => {
    const home = manifest.entries.filter((entry) => entry.id.startsWith("brain.home."));
    const inbox = manifest.entries.filter((entry) => entry.id.startsWith("brain.inbox."));
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
      "e2e.brain-graph.error-empty-retry",
      "e2e.brain-graph.global-empty-inbox",
      "e2e.brain-graph.controls-filters-views",
      "e2e.brain-graph.canvas-table-inspector",
      "e2e.brain-graph.visual-canvas-table",
      "e2e.brain-graph.deep-links-history",
    ]);

    expect(home).toHaveLength(14);
    expect(inbox).toHaveLength(17);
    expect(graph).toHaveLength(45);
    expect(staticGraph.map((entry) => entry.id)).toEqual([
      "brain.graph.date-range",
    ]);
    expect(staticGraph.every((entry) => entry.testIds.includes("e2e.manifest.coverage-audit"))).toBe(true);
    expect(graphReturn).toHaveLength(1);
    expect(entries).toHaveLength(77);
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
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(384);
  });

  test("maps all Brain node controls only to graph, lifecycle, and targeted Vault fixture paths", () => {
    const entries = manifest.entries.filter((entry) => entry.id.startsWith("brain.node."));
    const expected = [
      { id: "brain.node.show-in-graph", testIds: ["e2e.brain-graph.deep-links-history"] },
      { id: "brain.node.context-use", testIds: ["e2e.brain-node.lifecycle-controls"] },
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
    ] as const;
    const allowedTestIds = new Set([
      "e2e.brain-graph.deep-links-history",
      "e2e.brain-node.lifecycle-controls",
      "e2e.brain-node.conflict-forget",
      "e2e.brain-node.vault-export-deep-link",
    ]);

    expect(entries).toHaveLength(18);
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
    const entries = manifest.entries.filter((entry) => entry.id.startsWith("brain.control."));
    const controls = "e2e.brain-control.all-controls-save-reload";
    const conflict = "e2e.brain-control.version-conflict-retry";
    const invariants = "e2e.brain-control.locked-invariants";
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
    ] as const;
    const allowedTestIds = new Set([controls, conflict, invariants]);

    expect(entries).toHaveLength(13);
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
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(384);
  });

  test("inventories the mounted Vault lifecycle against dedicated isolated fixture sources", () => {
    const allEntries = manifest.entries.filter((entry) => entry.id.startsWith("brain.vault."));
    const entries = allEntries.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const staticEntries = allEntries.filter((entry) => !entry.requiredState.startsWith("Fixture required:"));
    const roundTrip = "e2e.brain-vault.round-trip-connect-reload";
    const pathRetry = "e2e.brain-vault.path-denial-retry";
    const projectionLifecycle = "e2e.brain-vault.sync-import-export-portable";
    const conflicts = "e2e.brain-vault.conflict-resolution";
    const degradedRecovery = "e2e.brain-vault.degraded-recovery";
    const recovery = "e2e.brain-vault.repair-reindex-recovery";
    const expected = [
      { id: "brain.vault.display-name", role: "textbox", name: "Display name", options: ["Disposable fixture display name"], testIds: [roundTrip] },
      { id: "brain.vault.relative-path", role: "textbox", name: "Path inside the allowed root", options: ["Valid relative path", "Traversal path rejected", "Corrected valid relative path"], testIds: [roundTrip, pathRetry] },
      { id: "brain.vault.filesystem-permission", role: "checkbox", name: "Grant explicit filesystem permission", options: ["Grant explicit permission for the selected Vault candidate"], testIds: [roundTrip, pathRetry] },
      { id: "brain.vault.round-trip-health", role: "button", name: "Test write, read, rename, and delete", options: ["Verify valid relative path", "Reject traversal without disclosing absolute paths", "Retry after deliberate safe path correction"], testIds: [roundTrip, pathRetry] },
      { id: "brain.vault.connect-verified", role: "button", name: "Connect verified vault", options: ["Disabled before matching round-trip proof", "Connect after matching round-trip proof"], testIds: [roundTrip] },
      { id: "brain.vault.connection-health", role: "button", name: "Test connection", options: ["Recheck a connected Vault", "Recover a degraded connection after a successful proof"], testIds: [degradedRecovery] },
      { id: "brain.vault.repair", role: "button", name: "Repair vault", options: ["Reconcile valid managed records", "Quarantine malformed notes", "Mark missing projections without recreating them", "Preserve open conflicts", "Reject symlinks", "Fail closed while offline"], testIds: [recovery] },
      { id: "brain.vault.reindex", role: "button", name: "Reindex vault", options: ["Parse bounded current managed notes", "Refresh represented canonical search rows", "Preserve open conflicts and SQLite source-of-truth"], testIds: [recovery] },
      { id: "brain.vault.synchronize", role: "button", name: "Synchronize", options: ["Project a canonical-only edit", "Import a Vault-only edit", "Create a visible conflict for concurrent edits"], testIds: [projectionLifecycle, conflicts] },
      { id: "brain.vault.export", role: "button", name: "Export canonical notes", options: ["Export every accessible note in the connection scope"], testIds: [projectionLifecycle, conflicts] },
      { id: "brain.vault.import", role: "button", name: "Import operator edits", options: ["Import valid operator edits", "Quarantine malformed notes according to backend policy"], testIds: [projectionLifecycle] },
      { id: "brain.vault.portable-export", role: "button", name: "Create portable ZIP", options: ["Create one scoped ZIP and provenance manifest"], testIds: [projectionLifecycle] },
      { id: "brain.vault.portable-download", role: "link", name: "Download portable ZIP", options: ["Download the exact generated ZIP"], testIds: [projectionLifecycle] },
      { id: "brain.vault.sync-state-details", role: "native-summary", name: "Note synchronization state", options: ["Open tracked note state", "Close tracked note state"], testIds: [projectionLifecycle] },
      { id: "brain.vault.open-native", role: "link", name: "^(?:Open vault in Obsidian|Open .+ in Obsidian)$", options: ["Open Vault root", "Open represented projected note"], testIds: [projectionLifecycle] },
      { id: "brain.vault.conflict-keep-database", role: "button", name: "Keep database version", options: ["Select the represented canonical database version"], testIds: [conflicts] },
      { id: "brain.vault.conflict-keep-vault", role: "button", name: "Keep vault version", options: ["Select the represented operator Vault version"], testIds: [conflicts] },
    ] as const;
    const allowedTestIds = new Set([roundTrip, pathRetry, projectionLifecycle, conflicts, degradedRecovery, recovery]);

    expect(entries).toHaveLength(17);
    expect(staticEntries.map((entry) => entry.id)).toEqual(["brain.vault.navigation"]);
    expect(staticEntries[0]?.testIds).toEqual(["e2e.manifest.coverage-audit"]);
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
    expect(manifest.entries.filter((entry) => entry.screenshotsRequired.length === 0)).toHaveLength(465);
    expect(manifest.knownGaps.some((gap) => gap.includes("Thirteen deterministic Chromium 1440") && gap.includes("remaining 465 entries"))).toBe(true);
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(384);
  });

  test("inventories the ten System control families against only existing dedicated System fixture sources", () => {
    const allEntries = manifest.entries.filter((entry) => entry.id.startsWith("system."));
    const entries = allEntries.filter((entry) => entry.requiredState.startsWith("Fixture required:"));
    const staticEntries = allEntries.filter((entry) => !entry.requiredState.startsWith("Fixture required:"));
    const expected = [
      { id: "system.navigation.tabs", route: "/system/:view", locator: "link", name: "^(?:Connections|Policies|Settings status)$", testIds: ["e2e.system.routes-and-tabs"] },
      { id: "system.connections.provider-pagination", route: "/system/connections", locator: "button", name: "^(?:First page|Next page)$", testIds: ["e2e.system.routes-and-tabs", "e2e.system.connections-controls"] },
      { id: "system.connections.mcp-status", route: "/system/connections", locator: "combobox", name: "Status", testIds: ["e2e.system.routes-and-tabs", "e2e.system.connections-controls"] },
      { id: "system.connections.mcp-details", route: "/system/connections", locator: "native-summary", name: "Capabilities and policy", testIds: ["e2e.system.routes-and-tabs", "e2e.system.connections-controls"] },
      { id: "system.connections.mcp-pagination", route: "/system/connections", locator: "button", name: "^(?:First page|Next page)$", testIds: ["e2e.system.routes-and-tabs", "e2e.system.connections-controls"] },
      { id: "system.policies.document-details", route: "/system/policies", locator: "native-summary", name: "Redacted policy document", testIds: ["e2e.system.policies-controls"] },
      { id: "system.policies.pagination", route: "/system/policies", locator: "button", name: "^(?:First page|Next page)$", testIds: ["e2e.system.policies-controls"] },
      { id: "system.settings.openapi-contract", route: "/system/settings", locator: "link", name: "Open API contract", testIds: ["e2e.system.settings-controls"] },
      { id: "system.settings.event-contract", route: "/system/settings", locator: "link", name: "Open event contract", testIds: ["e2e.system.settings-controls"] },
      { id: "system.query.retry", route: "/system/connections", locator: "button", name: "Try again", testIds: ["e2e.system.connections-retry"] },
    ] as const;
    const allowedTestIds = new Set([
      "e2e.system.routes-and-tabs",
      "e2e.system.connections-controls",
      "e2e.system.connections-retry",
      "e2e.system.policies-controls",
      "e2e.system.settings-controls",
    ]);

    expect(entries).toHaveLength(10);
    expect(staticEntries.map((entry) => entry.id)).toEqual([
      "system.surface-navigation",
      "system.status-filter",
      "system.settings.metrics",
    ]);
    expect(staticEntries.every((entry) => entry.testIds.includes("e2e.manifest.coverage-audit"))).toBe(true);
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
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(384);
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
      { id: "mission-portfolio.selection.row", route: "/missions", locator: "checkbox", name: "^Select mission .+ \\([A-Za-z0-9._:-]+\\)$", testIds: ["e2e.mission-portfolio.filters-saved-view", "e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.selection.all", route: "/missions", locator: "checkbox", name: "^Select all [0-9]+ visible missions$", testIds: ["e2e.mission-portfolio.pagination-deep-links", "e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.saved-view.name", route: "/missions", locator: "textbox", name: "Saved view name", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.saved-view.save", route: "/missions", locator: "button", name: "Save view", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.saved-view.apply", route: "/missions", locator: "button", name: "^Canonical saved portfolio .+$", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.saved-view.delete", route: "/missions", locator: "button", name: "^Delete saved view Canonical saved portfolio .+$", testIds: ["e2e.mission-portfolio.filters-saved-view"] },
      { id: "mission-portfolio.bulk.export", route: "/missions", locator: "button", name: "Export redacted metadata", testIds: ["e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.bulk.archive", route: "/missions", locator: "button", name: "Archive terminal missions", testIds: ["e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.bulk.dialog-cancel", route: "/missions", locator: "button", name: "Cancel", testIds: ["e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.bulk.dialog-confirm", route: "/missions", locator: "button", name: "^Confirm (?:export|archive)$", testIds: ["e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.bulk.outcome", route: "/missions", locator: "native-summary", name: "Per-mission outcomes", testIds: ["e2e.mission-portfolio.bulk-actions"] },
      { id: "mission-portfolio.retry", route: "/missions", locator: "button", name: "Try again", testIds: ["e2e.mission-portfolio.retry"] },
    ] as const;
    const allowedTestIds = new Set([
      "e2e.overview.portfolio-shortcuts",
      "e2e.overview.mission-row-links",
      "e2e.mission-portfolio.filters-saved-view",
      "e2e.mission-portfolio.pagination-deep-links",
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
    expect(new Set(entries.flatMap((entry) => entry.testIds))).toEqual(allowedTestIds);
    expect(new Set(entries.filter((entry) => entry.id.startsWith("overview.")).map((entry) => entry.route))).toEqual(new Set(["/"]));
    expect(new Set(entries.filter((entry) => entry.id.startsWith("mission-portfolio.")).map((entry) => entry.route))).toEqual(new Set(["/missions"]));
    expect(manifest.entries.filter((entry) => entry.requiredState.startsWith("Fixture required:"))).toHaveLength(384);
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

  test("declares for every manifest entry a test ID present in E2E source", () => {
    const e2eText = files(resolve(root, "tests/e2e"))
      .filter((path) => path.endsWith(".spec.ts"))
      .map((path) => readFileSync(path, "utf8"))
      .join("\n");
    for (const entry of manifest.entries) {
      for (const testId of entry.testIds) expect(e2eText).toContain(testId);
    }
  });
});

import { describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  INTERACTION_ACTIVATION_SENTINEL,
  INTERACTION_ACTIVATION_SCHEMA_VERSION,
  RELEASE_INTERACTION_PROJECT_ALLOWLIST,
  activationReceiptKey,
  bindManifestTestIdsToPlaywrightResults,
  buildInteractionActivationSourceSet,
  buildExpectedInteractionActivations,
  createInteractionActivationIntent,
  interactionActivationSourceSetHash,
  materializeInteractionActivationReceipts,
  projectScopeForName,
  resolveInteractionActivationOutputPath,
  validateInteractionActivationCoverage,
  validateInteractionActivationIntentEnvelope,
  validateInteractionActivationSourceSet,
  writeInteractionActivationArtifactAtomically,
  type InteractionActivationIntent,
  type InteractionActivationSourceSet,
  type InteractionPlaywrightResultRecord,
} from "../../interaction-manifest/activationReceipts";
import manifestJson from "../../interaction-manifest.json";
import { validateInteractionManifest } from "../../interaction-manifest/schema";
import {
  declaredInteractionActivationHelperSources,
  interactionActivationSourceDeclarations,
} from "../../e2e/support/interactionActivationSourceDeclarations";

const MANIFEST_HASH = "a".repeat(64);
const SOURCE_HASH = "b".repeat(64);
function sourceSetForHash(hash: string): InteractionActivationSourceSet {
  const files = [{
    path: "tests/e2e/activation-receipts.spec.ts",
    role: "test" as const,
    hash,
  }];
  return {
    hash: interactionActivationSourceSetHash(files),
    files,
  };
}

const SOURCE_SET = sourceSetForHash(SOURCE_HASH);
const PROJECT = { project: "chromium-1440", browser: "chromium", viewport: "1440x900", coverageClass: "general" } as const;
const productionManifest = validateInteractionManifest(manifestJson);

const manifest = validateInteractionManifest({
  schemaVersion: 1,
  application: "TI-SCALE // COMMAND INTELLIGENCE",
  namespace: "ti-scale",
  scope: "Focused receipt contract fixture",
  knownGaps: ["The focused fixture is not a release coverage claim."],
  entries: [
    {
      id: "fixture.selector",
      route: "/fixture",
      surface: "Fixture",
      requiredState: "Fixture required: selector populated with two represented options",
      controlId: "fixture-selector",
      accessible: { role: "combobox", name: "Fixture selector", match: "exact" },
      controlType: "selection",
      options: ["Option one", "Option two"],
      keyboardAction: "Focus and choose the option with the keyboard",
      pointerAction: "Open and choose the option with the pointer",
      expectedStateTransition: "The represented selection changes",
      expectedApiOrEventSideEffect: null,
      states: { loading: "Loading is visible", disabled: "Disabled is explained", error: "Error is actionable" },
      classification: "reversible",
      screenshotsRequired: [],
      browsers: ["chromium"],
      viewports: ["1440x900"],
      testIds: ["e2e.fixture.selector"],
    },
    {
      id: "fixture.activate",
      route: "/fixture",
      surface: "Fixture",
      requiredState: "Fixture required: activation target rendered",
      controlId: "fixture-activate",
      accessible: { role: "button", name: "Activate fixture", match: "exact" },
      controlType: "button",
      options: [],
      keyboardAction: "Focus and press Enter",
      pointerAction: "Click the button",
      expectedStateTransition: "The represented target activates",
      expectedApiOrEventSideEffect: null,
      states: { loading: "Loading is visible", disabled: "Disabled is explained", error: "Error is actionable" },
      classification: "read-only",
      screenshotsRequired: [],
      browsers: ["chromium"],
      viewports: ["1440x900"],
      testIds: ["e2e.fixture.activate"],
    },
  ],
});

const guardManifest = validateInteractionManifest({
  ...manifest,
  entries: [{
    ...manifest.entries[1]!,
    id: "fixture.blocked-guard",
    requiredState: "Fixture required: launch remains blocked and cannot create a mission",
    controlId: "fixture-blocked-guard",
    accessible: { role: "button", name: "Launch blocked fixture", match: "exact" },
    controlType: "disabled-launch-guard",
    requiredModalities: ["assertion"],
    keyboardAction: "Confirm the disabled control cannot receive keyboard activation",
    pointerAction: "Confirm the disabled control cannot receive pointer activation",
    expectedStateTransition: "The launch remains blocked and no mission is created",
    testIds: ["e2e.fixture.blocked-guard"],
  }],
});

function intent(
  manifestEntryId: "fixture.selector" | "fixture.activate",
  option: string,
  modality: "pointer" | "keyboard",
  ordinal: number,
  playwrightTestId = "pw-test-1",
  manifestHash = MANIFEST_HASH,
  sourceHash = SOURCE_HASH,
): InteractionActivationIntent {
  const entry = manifest.entries.find((candidate) => candidate.id === manifestEntryId)!;
  return createInteractionActivationIntent({
    manifest,
    manifestEntryId,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId: entry.testIds[0]!,
    playwrightTestId,
    playwrightProject: PROJECT.project,
    manifestHash,
    sourceHash,
    sourceSet: sourceSetForHash(sourceHash),
    ordinal,
  });
}

function guardIntent(
  modality: "pointer" | "keyboard" | "assertion",
  ordinal = 0,
): InteractionActivationIntent {
  const entry = guardManifest.entries[0]!;
  return createInteractionActivationIntent({
    manifest: guardManifest,
    manifestEntryId: entry.id,
    controlId: entry.controlId,
    option: INTERACTION_ACTIVATION_SENTINEL,
    materialState: entry.requiredState,
    modality,
    testId: entry.testIds[0]!,
    playwrightTestId: "pw-test-1",
    playwrightProject: PROJECT.project,
    manifestHash: MANIFEST_HASH,
    sourceHash: SOURCE_HASH,
    sourceSet: SOURCE_SET,
    ordinal,
  });
}

function materialize(
  intents: readonly InteractionActivationIntent[],
  status: "passed" | "failed" = "passed",
  playwrightTestId = "pw-test-1",
  manifestHash = MANIFEST_HASH,
  sourceHash = SOURCE_HASH,
) {
  return materializeInteractionActivationReceipts(intents, {
    playwrightTestId,
    playwrightProject: PROJECT.project,
    title: "exact activation fixture",
    titlePath: [PROJECT.project, "activation-receipts.test.ts", "exact activation fixture"],
    sourceFile: "/workspace/tests/e2e/activation-receipts.spec.ts",
    sourceLine: 12,
    sourceColumn: 1,
    sourceHash,
    sourceSet: sourceSetForHash(sourceHash),
    retry: 0,
    expectedStatus: "passed",
    status,
    manifestHash,
  });
}

describe("source-bound interaction activation receipts", () => {
  test("expands every explicit option and the activation sentinel across both modalities", () => {
    const expected = buildExpectedInteractionActivations(manifest, MANIFEST_HASH, [PROJECT]);
    expect(expected).toHaveLength(6);
    expect(expected.filter((item) => item.controlId === "fixture-selector").map((item) => `${item.option}:${item.modality}`)).toEqual([
      "Option one:pointer",
      "Option one:keyboard",
      "Option two:pointer",
      "Option two:keyboard",
    ]);
    expect(expected.filter((item) => item.controlId === "fixture-activate").map((item) => `${item.option}:${item.modality}`)).toEqual([
      `${INTERACTION_ACTIVATION_SENTINEL}:pointer`,
      `${INTERACTION_ACTIVATION_SENTINEL}:keyboard`,
    ]);
  });

  test("accepts only exact passing receipts bound to actual Playwright result records", () => {
    const allIntents = [
      intent("fixture.selector", "Option one", "pointer", 0),
      intent("fixture.selector", "Option one", "keyboard", 1),
      intent("fixture.selector", "Option two", "pointer", 2),
      intent("fixture.selector", "Option two", "keyboard", 3),
      intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 4),
      intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "keyboard", 5),
    ];
    const actual = materialize(allIntents);
    const report = validateInteractionActivationCoverage({
      manifest,
      manifestHash: MANIFEST_HASH,
      projects: [PROJECT],
      receipts: actual.receipts,
      records: [actual.record],
      requiredProjects: [PROJECT.project],
    });
    expect(report.complete).toBe(true);
    expect(report.expectedReceiptCount).toBe(6);
    expect(report.passingReceiptCount).toBe(6);
    expect(report.missingReceiptCount).toBe(0);
    expect(report.expectedActivationCount).toBe(6);
    expect(report.passingActivationCount).toBe(6);
    expect(report.missingActivationCount).toBe(0);
    expect(report.expectedAssertionCount).toBe(0);
    expect(report.passingAssertionCount).toBe(0);
    expect(report.missingAssertionCount).toBe(0);
    expect(report.testIdBindings.boundTestIds).toEqual(["e2e.fixture.activate", "e2e.fixture.selector"]);
  });

  test("expands a disabled launch guard into one assertion receipt instead of fake activations", () => {
    const expected = buildExpectedInteractionActivations(guardManifest, MANIFEST_HASH, [PROJECT]);
    expect(expected).toHaveLength(1);
    expect(expected[0]).toMatchObject({
      manifestEntryId: "fixture.blocked-guard",
      controlId: "fixture-blocked-guard",
      option: INTERACTION_ACTIVATION_SENTINEL,
      modality: "assertion",
    });
    expect(() => guardIntent("pointer")).toThrow("does not require pointer receipts");
    expect(() => guardIntent("keyboard")).toThrow("does not require keyboard receipts");

    const actual = materialize([guardIntent("assertion")]);
    const report = validateInteractionActivationCoverage({
      manifest: guardManifest,
      manifestHash: MANIFEST_HASH,
      projects: [PROJECT],
      receipts: actual.receipts,
      records: [actual.record],
      requiredProjects: [PROJECT.project],
    });
    expect(report.complete).toBe(true);
    expect(report.expectedReceiptCount).toBe(1);
    expect(report.passingReceiptCount).toBe(1);
    expect(report.expectedActivationCount).toBe(0);
    expect(report.passingActivationCount).toBe(0);
    expect(report.expectedAssertionCount).toBe(1);
    expect(report.passingAssertionCount).toBe(1);
    expect(report.missingAssertionCount).toBe(0);
  });

  test("rejects a forged pointer receipt for an assertion-only guard", () => {
    const forgedIntent: InteractionActivationIntent = {
      ...guardIntent("assertion"),
      modality: "pointer",
    };
    const actual = materialize([forgedIntent]);
    const report = validateInteractionActivationCoverage({
      manifest: guardManifest,
      manifestHash: MANIFEST_HASH,
      projects: [PROJECT],
      receipts: actual.receipts,
      records: [actual.record],
      requiredProjects: [PROJECT.project],
    });
    expect(report.complete).toBe(false);
    expect(report.passingReceiptCount).toBe(0);
    expect(report.missingReceiptCount).toBe(1);
    expect(report.missingAssertionCount).toBe(1);
    expect(report.invalidReceiptErrors.some((error) => error.includes("modality is not required"))).toBe(true);
  });

  test("fails coverage when an explicit option/modality activation is missing", () => {
    const partial = materialize([
      intent("fixture.selector", "Option one", "pointer", 0),
      intent("fixture.selector", "Option one", "keyboard", 1),
      intent("fixture.selector", "Option two", "pointer", 2),
      intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 3),
      intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "keyboard", 4),
    ]);
    const report = validateInteractionActivationCoverage({
      manifest,
      manifestHash: MANIFEST_HASH,
      projects: [PROJECT],
      receipts: partial.receipts,
      records: [partial.record],
      requiredProjects: [PROJECT.project],
    });
    expect(report.complete).toBe(false);
    expect(report.missingActivationCount).toBe(1);
    expect(report.missingActivations[0]).toMatchObject({
      controlId: "fixture-selector",
      option: "Option two",
      modality: "keyboard",
      playwrightProject: PROJECT.project,
    });
  });

  test("does not bind a declared test ID by substring", () => {
    const actual = materialize([intent("fixture.selector", "Option one", "pointer", 0)]);
    const misleadingRecord: InteractionPlaywrightResultRecord = {
      ...actual.record,
      declaredTestIds: ["prefix-e2e.fixture.activate-suffix"],
    };
    const bindings = bindManifestTestIdsToPlaywrightResults(manifest, [misleadingRecord]);
    expect(bindings.boundTestIds).toEqual([]);
    expect(bindings.missingTestIds).toEqual(["e2e.fixture.activate", "e2e.fixture.selector"]);
    expect(bindings.undeclaredTestIds).toEqual(["prefix-e2e.fixture.activate-suffix"]);
  });

  test("a failed Playwright result and stale source binding cannot satisfy activation coverage", () => {
    const stale = {
      ...intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 0),
      sourceHash: "c".repeat(64),
    };
    const actual = materialize([stale], "failed");
    expect(actual.receipts[0]).toMatchObject({
      result: "fail",
      playwrightStatus: "failed",
    });
    expect(actual.receipts[0]?.validationErrors).toContain("intent source hash does not match the executed test source");
    const report = validateInteractionActivationCoverage({
      manifest,
      manifestHash: MANIFEST_HASH,
      projects: [PROJECT],
      receipts: actual.receipts,
      records: [actual.record],
      requiredProjects: [PROJECT.project],
    });
    expect(report.complete).toBe(false);
    expect(report.failedReceiptCount).toBe(1);
    expect(report.invalidReceiptErrors.some((error) => error.includes("source hash"))).toBe(true);
  });

  test("deduplicates coverage without colliding two legitimate executions", () => {
    const baselineIntents = [
      intent("fixture.selector", "Option one", "pointer", 0),
      intent("fixture.selector", "Option one", "keyboard", 1),
      intent("fixture.selector", "Option two", "pointer", 2),
      intent("fixture.selector", "Option two", "keyboard", 3),
      intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 4),
      intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "keyboard", 5),
    ];
    const first = materialize(baselineIntents);
    const secondIntent = intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 0, "pw-test-2");
    const second = materialize([secondIntent], "passed", "pw-test-2");
    expect(first.receipts[4]?.receiptKey).not.toBe(second.receipts[0]?.receiptKey);
    const report = validateInteractionActivationCoverage({
      manifest,
      manifestHash: MANIFEST_HASH,
      projects: [PROJECT],
      receipts: [...first.receipts, ...second.receipts],
      records: [first.record, second.record],
      requiredProjects: [PROJECT.project],
    });
    expect(report.complete).toBe(true);
    expect(report.passingActivationCount).toBe(6);
    expect(report.duplicateReceiptKeys).toEqual([]);
  });

  test("uses one execution identity for a pass/fail pair and rejects the duplicate evidence", () => {
    const actual = materialize([intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 0)]);
    const passed = actual.receipts[0]!;
    const failed = { ...passed, result: "fail" as const };
    expect(activationReceiptKey(passed)).toBe(activationReceiptKey(failed));
    const report = validateInteractionActivationCoverage({
      manifest,
      manifestHash: MANIFEST_HASH,
      projects: [PROJECT],
      receipts: [passed, failed],
      records: [actual.record],
      requiredProjects: [PROJECT.project],
    });
    expect(report.complete).toBe(false);
    expect(report.duplicateReceiptKeys).toEqual([passed.receiptKey]);
    expect(report.failedReceiptCount).toBe(1);
    expect(report.passingActivationCount).toBe(1);
  });

  test("keeps the manifest entry and Playwright execution in the receipt identity", () => {
    const actual = materialize([intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 0)]);
    const base = actual.receipts[0]!;
    const sameControlDifferentEntry = { ...base, manifestEntryId: "fixture.other-entry" };
    const sameEntryDifferentExecution = {
      ...base,
      playwrightTestId: "pw-test-2",
      playwrightRecordId: "pw-test-2:0",
    };
    expect(activationReceiptKey(base)).not.toBe(activationReceiptKey(sameControlDifferentEntry));
    expect(activationReceiptKey(base)).not.toBe(activationReceiptKey(sameEntryDifferentExecution));
  });

  test("rejects stale manifest binding independently of stale source binding", () => {
    const staleManifestIntent = intent(
      "fixture.activate",
      INTERACTION_ACTIVATION_SENTINEL,
      "pointer",
      0,
      "pw-test-1",
      "c".repeat(64),
    );
    const actual = materialize([staleManifestIntent]);
    expect(actual.receipts[0]?.result).toBe("fail");
    expect(actual.receipts[0]?.validationErrors).toContain("intent manifest hash does not match the audited manifest");
  });

  test("cannot claim completeness from a filtered project run", () => {
    const allIntents = [
      intent("fixture.selector", "Option one", "pointer", 0),
      intent("fixture.selector", "Option one", "keyboard", 1),
      intent("fixture.selector", "Option two", "pointer", 2),
      intent("fixture.selector", "Option two", "keyboard", 3),
      intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 4),
      intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "keyboard", 5),
    ];
    const actual = materialize(allIntents);
    const report = validateInteractionActivationCoverage({
      manifest,
      manifestHash: MANIFEST_HASH,
      projects: [PROJECT],
      receipts: actual.receipts,
      records: [actual.record],
      requiredProjects: RELEASE_INTERACTION_PROJECT_ALLOWLIST,
    });
    expect(report.complete).toBe(false);
    expect(report.missingActivationCount).toBe(0);
    expect(report.missingRequiredProjects).toContain("firefox-1440");
    expect(report.missingRequiredProjects).toContain("brain-renderer-chromium-1440");
  });

  test("scopes the dedicated Brain renderer project to its renderer receipt class", () => {
    const brainProject = projectScopeForName("brain-renderer-chromium-1440")!;
    const generalProject = projectScopeForName("chromium-1440")!;
    const brainExpected = buildExpectedInteractionActivations(productionManifest, MANIFEST_HASH, [brainProject]);
    const generalExpected = buildExpectedInteractionActivations(productionManifest, MANIFEST_HASH, [generalProject]);
    expect(brainExpected.length).toBeGreaterThan(0);
    expect(brainExpected.length).toBeLessThan(generalExpected.length);
    expect(new Set(brainExpected.map((item) => item.manifestEntryId))).toEqual(new Set([
      "brain.graph.canvas",
      "brain.graph.region-toggle",
      "brain.graph.labels-toggle",
      "brain.graph.regions-all",
      "brain.graph.regions-none",
    ]));
  });

  test("rejects malformed intent envelopes before they can become receipts", () => {
    expect(() => validateInteractionActivationIntentEnvelope({
      schemaVersion: INTERACTION_ACTIVATION_SCHEMA_VERSION,
      kind: "interaction-activation-intents",
      intents: [{ ...intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 0), sourceHash: "not-a-hash" }],
    })).toThrow("lowercase SHA-256 digest");
    expect(() => createInteractionActivationIntent({
      manifest,
      manifestEntryId: "fixture.selector",
      controlId: "fixture-selector",
      option: "Undeclared option",
      materialState: manifest.entries[0]!.requiredState,
      modality: "pointer",
      testId: "e2e.fixture.selector",
      playwrightTestId: "pw-test-1",
      playwrightProject: PROJECT.project,
      manifestHash: MANIFEST_HASH,
      sourceHash: SOURCE_HASH,
      sourceSet: SOURCE_SET,
      ordinal: 0,
    })).toThrow("does not declare option");
  });

  test("binds the seven Autonomous intake specs to both physical helper implementations", () => {
    const declarations = interactionActivationSourceDeclarations();
    expect([...declarations.keys()].sort()).toEqual([
      "tests/e2e/autonomous-intake-agent-model-assignments.spec.ts",
      "tests/e2e/autonomous-intake-context.spec.ts",
      "tests/e2e/autonomous-intake-contract-normalization.spec.ts",
      "tests/e2e/autonomous-intake-launch.spec.ts",
      "tests/e2e/autonomous-intake-readiness.spec.ts",
      "tests/e2e/autonomous-intake-scope-outcome-navigation.spec.ts",
      "tests/e2e/autonomous-intake-team-readiness.spec.ts",
    ]);
    for (const [testSourceFile, helpers] of declarations) {
      expect(helpers).toEqual([
        "tests/e2e/support/autonomousIntake.ts",
        "tests/e2e/support/titaniumSelect.ts",
      ]);
      expect(declaredInteractionActivationHelperSources({
        sourceRoot: "/workspace",
        testSourceFile: `/workspace/${testSourceFile}`,
      })).toEqual(helpers);
    }
    expect(declaredInteractionActivationHelperSources({
      sourceRoot: "/workspace",
      testSourceFile: "/workspace/tests/e2e/existing-unbound.spec.ts",
    })).toEqual([]);
  });

  test("builds one deterministic source set and preserves spec-only tests", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-activation-source-set-"));
    try {
      mkdirSync(join(root, "tests", "e2e", "support"), { recursive: true });
      const testSource = join(root, "tests", "e2e", "fixture.spec.ts");
      const helperSource = join(root, "tests", "e2e", "support", "fixture.ts");
      writeFileSync(testSource, "test implementation\n");
      writeFileSync(helperSource, "helper implementation\n");
      const first = buildInteractionActivationSourceSet({
        sourceRoot: root,
        testSourceFile: testSource,
        helperSourceFiles: ["tests/e2e/support/fixture.ts"],
      });
      const second = buildInteractionActivationSourceSet({
        sourceRoot: root,
        testSourceFile: "tests/e2e/fixture.spec.ts",
        helperSourceFiles: [helperSource],
      });
      expect(first).toEqual(second);
      expect(first.files.map(({ path, role }) => `${role}:${path}`)).toEqual([
        "test:tests/e2e/fixture.spec.ts",
        "helper:tests/e2e/support/fixture.ts",
      ]);
      expect(validateInteractionActivationSourceSet(first)).toEqual(first);

      const specOnly = buildInteractionActivationSourceSet({
        sourceRoot: root,
        testSourceFile: testSource,
      });
      expect(specOnly.files).toHaveLength(1);
      expect(specOnly.files[0]?.role).toBe("test");
      expect(validateInteractionActivationSourceSet(specOnly)).toEqual(specOnly);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects missing, out-of-root, symlinked, and duplicate helper declarations", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-activation-source-root-"));
    const outside = mkdtempSync(join(tmpdir(), "ti-scale-activation-source-outside-"));
    try {
      mkdirSync(join(root, "tests", "e2e", "support"), { recursive: true });
      const testSource = join(root, "tests", "e2e", "fixture.spec.ts");
      const helperSource = join(root, "tests", "e2e", "support", "fixture.ts");
      const outsideHelper = join(outside, "outside.ts");
      writeFileSync(testSource, "test implementation\n");
      writeFileSync(helperSource, "helper implementation\n");
      writeFileSync(outsideHelper, "outside helper\n");
      symlinkSync(outsideHelper, join(root, "tests", "e2e", "support", "escaped.ts"));

      expect(() => buildInteractionActivationSourceSet({
        sourceRoot: root,
        testSourceFile: testSource,
        helperSourceFiles: ["tests/e2e/support/missing.ts"],
      })).toThrow("does not exist");
      expect(() => buildInteractionActivationSourceSet({
        sourceRoot: root,
        testSourceFile: testSource,
        helperSourceFiles: [outsideHelper],
      })).toThrow("must be below");
      expect(() => buildInteractionActivationSourceSet({
        sourceRoot: root,
        testSourceFile: testSource,
        helperSourceFiles: ["tests/e2e/support/escaped.ts"],
      })).toThrow("must be a regular file");
      expect(() => buildInteractionActivationSourceSet({
        sourceRoot: root,
        testSourceFile: testSource,
        helperSourceFiles: [helperSource, "tests/e2e/support/fixture.ts"],
      })).toThrow("duplicate path");
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  test("rejects stale helper bytes even when the primary test source is unchanged", () => {
    const oldHelperHash = "c".repeat(64);
    const currentHelperHash = "d".repeat(64);
    const sourceFiles = [
      {
        path: "tests/e2e/activation-receipts.spec.ts",
        role: "test" as const,
        hash: SOURCE_HASH,
      },
      {
        path: "tests/e2e/support/fixture.ts",
        role: "helper" as const,
        hash: oldHelperHash,
      },
    ];
    const staleSourceSet: InteractionActivationSourceSet = {
      hash: interactionActivationSourceSetHash(sourceFiles),
      files: sourceFiles,
    };
    const currentSourceFiles = sourceFiles.map((source) => (
      source.role === "helper" ? { ...source, hash: currentHelperHash } : source
    ));
    const currentSourceSet: InteractionActivationSourceSet = {
      hash: interactionActivationSourceSetHash(currentSourceFiles),
      files: currentSourceFiles,
    };
    const staleIntent = {
      ...intent("fixture.activate", INTERACTION_ACTIVATION_SENTINEL, "pointer", 0),
      sourceSet: staleSourceSet,
    };
    const actual = materializeInteractionActivationReceipts([staleIntent], {
      playwrightTestId: "pw-test-1",
      playwrightProject: PROJECT.project,
      title: "stale helper fixture",
      titlePath: [PROJECT.project, "activation-receipts.test.ts", "stale helper fixture"],
      sourceFile: "/workspace/tests/e2e/activation-receipts.spec.ts",
      sourceLine: 12,
      sourceColumn: 1,
      sourceHash: SOURCE_HASH,
      sourceSet: currentSourceSet,
      retry: 0,
      expectedStatus: "passed",
      status: "passed",
      manifestHash: MANIFEST_HASH,
    });
    expect(actual.receipts[0]?.result).toBe("fail");
    expect(actual.receipts[0]?.validationErrors).toContain(
      "intent source set does not match the executed test and helper sources",
    );
  });

  test("writes one atomic artifact only below the isolated results root", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-interaction-receipts-"));
    try {
      const output = join(root, "nested", "receipt.json");
      writeInteractionActivationArtifactAtomically({
        outputFile: output,
        isolatedRoot: root,
        body: "{\"complete\":false}\n",
      });
      expect(readFileSync(output, "utf8")).toBe("{\"complete\":false}\n");
      expect(readdirSync(join(root, "nested"))).toEqual(["receipt.json"]);
      expect(() => resolveInteractionActivationOutputPath(join(root, "..", "escaped.json"), root)).toThrow("below");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects a symlinked output directory", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-interaction-receipts-root-"));
    const outside = mkdtempSync(join(tmpdir(), "ti-scale-interaction-receipts-outside-"));
    try {
      symlinkSync(outside, join(root, "redirect"), "dir");
      expect(() => writeInteractionActivationArtifactAtomically({
        outputFile: join(root, "redirect", "receipt.json"),
        isolatedRoot: root,
        body: "{}\n",
      })).toThrow("real directory");
      expect(readdirSync(outside)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });
});

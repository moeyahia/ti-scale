import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import {
  createOperationalListsFixture,
  type OperationalListsFixture,
} from "./support/operationalListsFixture";
import {
  advanceRunInterventionRecoveryVersion,
  createRunInterventionRecoveryFixture,
  type RunInterventionRecoveryFixture,
} from "./support/runInterventionRecoveryFixture";
import { waitForInteractiveApplication } from "./support/applicationReadiness";
import { expect, test, type Locator, type Page } from "./support/playwright";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";

const TEST_IDS = {
  agents: "e2e.dynamic-disclosures.agents",
  live: "e2e.dynamic-disclosures.live",
  mission: "e2e.dynamic-disclosures.mission",
} as const;

const AGENT_MANIFEST_IDS = [
  "agents.runtime-bound-policies",
  "agents.provider-tool-policy",
] as const;

const LIVE_MANIFEST_IDS = [
  "live.technical-plan-wording",
  "live.normalized-action-wording",
  "live.technical-event-detail",
  "live.technical-action-detail",
  "live.technical-recovery-wording",
] as const;

const MISSION_MANIFEST_IDS = [
  "mission.technical-plan-wording",
  "mission.normalized-action-wording",
  "mission.technical-event-detail",
  "mission.technical-action-detail",
  "run-workspace.technical-plan-wording",
  "run-workspace.normalized-action-wording",
  "run-workspace.technical-event-detail",
  "run-workspace.technical-action-detail",
] as const;

const manifest = validateInteractionManifest(JSON.parse(
  readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8"),
) as unknown);

let agentsFixture: OperationalListsFixture;
let liveFixture: RunInterventionRecoveryFixture;

test.describe.configure({ mode: "serial" });

test.beforeAll(({}, testInfo) => {
  agentsFixture = createOperationalListsFixture(
    canonicalFixtureNamespace(testInfo, "dynamic-disclosures-agents"),
  );
  liveFixture = createRunInterventionRecoveryFixture(
    "replan",
    canonicalFixtureNamespace(testInfo, "dynamic-disclosures-live"),
  );
  // The live disclosure fixture needs one attributable semantic event in
  // addition to its persisted plan, represented action, and recovery state.
  advanceRunInterventionRecoveryVersion(liveFixture);
});

function activation(
  manifestEntryId: string,
  option: string,
  modality: "pointer" | "keyboard",
  testId: string,
): InteractionActivationInput {
  const entry = manifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`Dynamic disclosure manifest entry ${manifestEntryId} is missing`);
  if (!entry.options.includes(option)) {
    throw new Error(`Dynamic disclosure manifest entry ${manifestEntryId} does not declare ${option}`);
  }
  if (!entry.testIds.includes(testId)) {
    throw new Error(`Dynamic disclosure manifest entry ${manifestEntryId} is not assigned to ${testId}`);
  }
  return {
    manifestEntryId,
    controlId: entry.controlId,
    option,
    materialState: entry.requiredState,
    modality,
    testId,
  };
}

async function activateSummary(summary: Locator, modality: "pointer" | "keyboard"): Promise<void> {
  if (modality === "keyboard") {
    await summary.focus();
    await summary.press("Enter");
  } else {
    await summary.click();
  }
}

async function exerciseDisclosure(
  interactionActivation: InteractionActivationRecorder,
  scope: Locator | Page,
  label: string,
  manifestEntryId: string,
  option: string,
  modality: "pointer" | "keyboard",
  testId: string,
): Promise<void> {
  const entry = manifest.entries.find((candidate) => candidate.id === manifestEntryId);
  if (!entry) throw new Error(`Dynamic disclosure manifest entry ${manifestEntryId} is missing`);
  const summary = scope.locator(
    `summary[data-control-id="${entry.controlId}"]`,
  ).first();
  const details = summary.locator("..");
  await expect(summary).toHaveText(label);
  await expect(details).not.toHaveAttribute("open", "");
  await interactionActivation.activate(
    activation(manifestEntryId, option, modality, testId),
    async () => {
      await activateSummary(summary, modality);
      await expect(details).toHaveAttribute("open", "");
      await expect(details.locator("pre")).not.toBeEmpty();
      await activateSummary(summary, modality);
      await expect(details).not.toHaveAttribute("open", "");
    },
  );
}

test(`${TEST_IDS.agents} opens and closes both canonical agent-policy disclosures`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  for (const id of AGENT_MANIFEST_IDS) {
    expect(manifest.entries.some((entry) => entry.id === id && entry.testIds.includes(TEST_IDS.agents))).toBe(true);
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    const destination = `/agents/${encodeURIComponent(agentsFixture.agentIds[0]!)}`;
    if (page.url() === "about:blank") {
      await page.goto(destination, { waitUntil: "domcontentloaded" });
    } else {
      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => page.goto(destination, { waitUntil: "domcontentloaded" }),
      );
    }
    await waitForInteractiveApplication(page);
    const detail = page.getByRole("complementary", { name: "Selected agent detail", exact: true });
    await expect(detail.getByRole("heading", {
      name: agentsFixture.agentNames[0]!,
      exact: true,
    })).toBeVisible();
    await exerciseDisclosure(
      interactionActivation,
      detail,
      "Bound provider and tool policies",
      "agents.runtime-bound-policies",
      "Inspect bound provider and tool policies",
      modality,
      TEST_IDS.agents,
    );
    await exerciseDisclosure(
      interactionActivation,
      detail,
      "Provider and tool policy",
      "agents.provider-tool-policy",
      "Inspect resolved provider, tool, and configuration policy",
      modality,
      TEST_IDS.agents,
    );
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

test(`${TEST_IDS.live} opens and closes plan, event, action, and recovery technical disclosures`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(120_000);
  for (const id of LIVE_MANIFEST_IDS) {
    expect(manifest.entries.some((entry) => entry.id === id && entry.testIds.includes(TEST_IDS.live))).toBe(true);
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    const destination = `/live/${encodeURIComponent(liveFixture.runId)}`;
    if (page.url() === "about:blank") {
      await page.goto(destination, { waitUntil: "domcontentloaded" });
    } else {
      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => page.goto(destination, { waitUntil: "domcontentloaded" }),
      );
    }
    await waitForInteractiveApplication(page);
    await expect(page.getByRole("heading", {
      name: "Plan and agent ownership",
      exact: true,
    })).toBeVisible();
    await expect(page.locator(".os-recovery-panel")).toBeVisible();

    await exerciseDisclosure(
      interactionActivation,
      page,
      "Technical plan wording",
      "live.technical-plan-wording",
      "Inspect raw plan strategy and rationale",
      modality,
      TEST_IDS.live,
    );
    await exerciseDisclosure(
      interactionActivation,
      page,
      "Normalized action and original wording",
      "live.normalized-action-wording",
      "Inspect normalized step action and original narrative",
      modality,
      TEST_IDS.live,
    );
    await exerciseDisclosure(
      interactionActivation,
      page,
      "Technical event detail",
      "live.technical-event-detail",
      "Inspect raw event payload and correlation",
      modality,
      TEST_IDS.live,
    );
    await exerciseDisclosure(
      interactionActivation,
      page,
      "Technical action detail and original wording",
      "live.technical-action-detail",
      "Inspect raw action identity, wording, and correlation",
      modality,
      TEST_IDS.live,
    );
    await exerciseDisclosure(
      interactionActivation,
      page,
      "Technical recovery wording",
      "live.technical-recovery-wording",
      "Inspect raw recovery diagnosis and proposal wording",
      modality,
      TEST_IDS.live,
    );
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

test(`${TEST_IDS.mission} keeps mission and run deep-link technical disclosures inspectable`, async ({
  page,
  browserAudit,
  interactionActivation,
}) => {
  test.setTimeout(180_000);
  for (const id of MISSION_MANIFEST_IDS) {
    expect(manifest.entries.some((entry) => entry.id === id && entry.testIds.includes(TEST_IDS.mission))).toBe(true);
  }

  const routeFamilies = [
    {
      prefix: "mission",
      base: `/missions/${encodeURIComponent(liveFixture.missionId)}`,
    },
    {
      prefix: "run-workspace",
      base: `/missions/${encodeURIComponent(liveFixture.missionId)}/runs/${encodeURIComponent(liveFixture.runId)}`,
    },
  ] as const;

  for (const routeFamily of routeFamilies) {
    for (const modality of ["pointer", "keyboard"] as const) {
      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => page.goto(`${routeFamily.base}?tab=plan`, { waitUntil: "domcontentloaded" }),
      );
      await waitForInteractiveApplication(page);
      await browserAudit.waitForPageApiSettlement(page, { quietMs: 500 });
      await expect(page.locator(
        `[data-control-id="${routeFamily.prefix}-technical-plan-wording"]`,
      )).toBeVisible();
      await exerciseDisclosure(
        interactionActivation,
        page,
        "Technical plan wording",
        `${routeFamily.prefix}.technical-plan-wording`,
        "Inspect raw plan strategy and rationale",
        modality,
        TEST_IDS.mission,
      );
      await exerciseDisclosure(
        interactionActivation,
        page,
        "Normalized action and original wording",
        `${routeFamily.prefix}.normalized-action-wording`,
        "Inspect normalized step action and original narrative",
        modality,
        TEST_IDS.mission,
      );

      await browserAudit.withExpectedDocumentNavigationTeardown(
        page,
        () => page.goto(`${routeFamily.base}?tab=history`, { waitUntil: "domcontentloaded" }),
      );
      await waitForInteractiveApplication(page);
      await browserAudit.waitForPageApiSettlement(page, { quietMs: 500 });
      await expect(page.locator(
        `[data-control-id="${routeFamily.prefix}-technical-event-detail"]`,
      )).toBeVisible();
      await exerciseDisclosure(
        interactionActivation,
        page,
        "Technical event detail",
        `${routeFamily.prefix}.technical-event-detail`,
        "Inspect raw event payload and correlation",
        modality,
        TEST_IDS.mission,
      );
      await exerciseDisclosure(
        interactionActivation,
        page,
        "Technical action detail and original wording",
        `${routeFamily.prefix}.technical-action-detail`,
        "Inspect raw action identity, wording, and correlation",
        modality,
        TEST_IDS.mission,
      );
    }
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

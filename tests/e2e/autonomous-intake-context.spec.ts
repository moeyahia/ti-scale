import type {
  AutonomousContextCandidate,
  AutonomousMissionPreflight,
} from "../../src/domain/types/commandOs";
import type { ResolvedMissionIntake } from "../../server/intake/types";
import {
  activateAutonomousIntake,
  advanceAutonomousIntake,
  autonomousIntakeGroup,
  autonomousTitaniumSelect,
  chooseAutonomousTitaniumOption,
  createIntakeRequestLedger,
  type IntakeReceiptContext,
} from "./support/autonomousIntake";
import { createAutonomousIntakeAdvancedFixture } from "./support/autonomousIntakeAdvancedFixture";
import { createMissionIntakeDynamicFixture } from "./support/missionIntakeDynamicFixture";
import {
  expect,
  test,
  type Locator,
  type Page,
} from "./support/playwright";

const TEST_ID = "e2e.autonomous-intake.context";
const MEMORY_OPTION =
  "Each eligible confirmed preference or verified lesson returned by preflight; excluded IDs remain visibly unavailable";
const CLEAR_OPTION =
  "Create an empty Context Pack when the contract permits degraded memory use";
const MEMORY_SCOPES = [
  ["Confirmed operator preferences", "confirmed_preferences"],
  ["Verified operational lessons", "verified_lessons"],
  ["Confirmed historical attack knowledge", "confirmed_attack_knowledge"],
  ["Verified attack safety knowledge", "verified_attack_knowledge"],
  ["Engagement-isolated knowledge", "engagement_memory"],
] as const;

function regexLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function contextCandidateCheckbox(
  context: Locator,
  candidate: AutonomousContextCandidate,
): Locator {
  return context.getByRole("checkbox", {
    name: new RegExp(
      `^${regexLiteral(candidate.title)}\\s+${regexLiteral(candidate.summary)}(?:\\s|$)`,
      "u",
    ),
  });
}

async function openContext(
  page: Page,
  engagementId?: string,
): Promise<{
  readonly context: Locator;
  readonly preflight: AutonomousMissionPreflight;
}> {
  await page.goto("/missions/new/autonomous");
  await chooseAutonomousTitaniumOption(
    autonomousTitaniumSelect(page, /Environment classification/u),
    "local_disposable_lab",
    "keyboard",
  );
  await page
    .getByLabel("Authorized targets or environment references", { exact: false })
    .fill("127.0.0.1");
  if (engagementId) {
    const boundary = page.locator("details").filter({
      has: page.getByText("Excluded targets and engagement boundary", { exact: true }),
    });
    await boundary.locator(":scope > summary").click();
    await boundary
      .getByLabel("Existing engagement ID", { exact: false })
      .fill(engagementId);
  }
  await page
    .getByRole("checkbox", {
      name: /I confirm these targets and the selected action policy are authorized/u,
    })
    .check();
  await advanceAutonomousIntake(page, "Outcome and collaboration");
  await advanceAutonomousIntake(page, "Autonomous operating contract");
  const teamAdvance = await advanceAutonomousIntake(
    page,
    "Specialist team and execution readiness",
    { expectPreflight: true },
  );
  if (!teamAdvance.preflight) {
    throw new Error("Team step did not receive Autonomous preflight");
  }
  const teamPreflight =
    await teamAdvance.preflight.json() as AutonomousMissionPreflight;
  const unavailableRecommendation = teamPreflight.execution.team.candidates
    .find(({ id }) => id === "ReconScout");
  expect(unavailableRecommendation).toMatchObject({
    compatible: false,
  });
  expect(unavailableRecommendation?.incompatibilityReasons.join(" "))
    .toContain("No live catalog configuration is currently executable");
  expect(teamPreflight.execution.team.recommendedAgentIds)
    .not.toContain("ReconScout");
  await expect(
    autonomousIntakeGroup(
      page,
      "Specialist team and execution readiness",
    ).getByRole("checkbox", { name: /^ReconScout/u }),
  ).toBeDisabled();
  const advanced = await advanceAutonomousIntake(
    page,
    "Second Brain context",
    { expectPreflight: true },
  );
  if (!advanced.preflight) throw new Error("Context step did not receive Autonomous preflight");
  return {
    context: autonomousIntakeGroup(page, "Second Brain context"),
    preflight: await advanced.preflight.json() as AutonomousMissionPreflight,
  };
}

test(`${TEST_ID} enforces scope-safe candidate retrieval and exact Context Pack selection`, async ({
  page,
  request,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(240_000);
  const dynamic = createMissionIntakeDynamicFixture(testInfo.testId);
  const fixture = createAutonomousIntakeAdvancedFixture(testInfo.testId);
  const ledger = createIntakeRequestLedger(page);
  const receipts: IntakeReceiptContext = {
    recorder: interactionActivation,
    testId: TEST_ID,
  };
  try {
    const withoutEngagement = await openContext(page);
    const disabledEngagementScope = autonomousIntakeGroup(
      page,
      "Memory scopes allowed for this mission",
    ).getByRole("checkbox", { name: /Engagement-isolated knowledge/u });
    await expect(disabledEngagementScope).toBeDisabled();
    await expect(disabledEngagementScope).not.toBeChecked();
    expect(withoutEngagement.preflight.context.candidates.map(({ id }) => id))
      .not.toContain(fixture.eligibleNodes.at(-1)?.id);
    await expect(
      withoutEngagement.context.getByText(
        fixture.eligibleNodes.at(-1)!.title,
        { exact: true },
      ),
    ).toHaveCount(0);

    const { context, preflight } = await openContext(page, fixture.engagementId);
    const scopes = autonomousIntakeGroup(
      page,
      "Memory scopes allowed for this mission",
    );
    for (const [label] of MEMORY_SCOPES) {
      const checkbox = scopes.getByRole("checkbox", {
        name: new RegExp(label, "u"),
      });
      await expect(checkbox).toBeEnabled();
      await expect(checkbox).toBeChecked();
      await activateAutonomousIntake(
        receipts,
        "autonomous-intake.context.scopes",
        label,
        "pointer",
        async () => {
          await checkbox.click();
          await expect(checkbox).not.toBeChecked();
        },
      );
      await activateAutonomousIntake(
        receipts,
        "autonomous-intake.context.scopes",
        label,
        "keyboard",
        async () => {
          await checkbox.focus();
          await checkbox.press("Space");
          await expect(checkbox).toBeChecked();
        },
      );
    }

    const candidateIds = preflight.context.candidates.map(({ id }) => id);
    expect(candidateIds).toContain(dynamic.memoryNodeId);
    for (const node of fixture.eligibleNodes) expect(candidateIds).toContain(node.id);
    expect(candidateIds).not.toContain(fixture.crossEngagementNode.id);
    for (const node of fixture.ineligibleNodes) expect(candidateIds).not.toContain(node.id);
    await expect(
      context.getByText(fixture.crossEngagementNode.title, { exact: true }),
    ).toHaveCount(0);
    for (const node of fixture.ineligibleNodes) {
      await expect(context.getByText(node.title, { exact: true })).toHaveCount(0);
    }

    const candidateControls = preflight.context.candidates.map((candidate) =>
      contextCandidateCheckbox(context, candidate));
    await expect(context.locator("label.os-check-field")).toHaveCount(
      preflight.context.candidates.length + MEMORY_SCOPES.length,
    );
    const initial = await Promise.all(
      candidateControls.map((checkbox) => checkbox.isChecked()),
    );
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.context.memories",
      MEMORY_OPTION,
      "pointer",
      async () => {
        for (let index = 0; index < candidateControls.length; index += 1) {
          const checkbox = candidateControls[index]!;
          await checkbox.click();
          await expect(checkbox).toBeChecked({ checked: !initial[index] });
        }
        await expect(
          context.getByText(fixture.crossEngagementNode.title, { exact: true }),
        ).toHaveCount(0);
        for (const node of fixture.ineligibleNodes) {
          await expect(context.getByText(node.title, { exact: true })).toHaveCount(0);
        }
      },
    );
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.context.memories",
      MEMORY_OPTION,
      "keyboard",
      async () => {
        for (let index = 0; index < candidateControls.length; index += 1) {
          const checkbox = candidateControls[index]!;
          await checkbox.focus();
          await checkbox.press("Space");
          await expect(checkbox).toBeChecked({ checked: initial[index] });
        }
        await expect(
          context.getByText(fixture.crossEngagementNode.title, { exact: true }),
        ).toHaveCount(0);
        for (const node of fixture.ineligibleNodes) {
          await expect(context.getByText(node.title, { exact: true })).toHaveCount(0);
        }
      },
    );

    const clear = context.getByRole("button", {
      name: "Use no retained context",
      exact: true,
    });
    for (const modality of ["pointer", "keyboard"] as const) {
      for (const checkbox of candidateControls) await checkbox.check();
      await activateAutonomousIntake(
        receipts,
        "autonomous-intake.context.clear",
        CLEAR_OPTION,
        modality,
        async () => {
          if (modality === "pointer") {
            await clear.click();
          } else {
            await clear.focus();
            await clear.press("Enter");
          }
          for (const checkbox of candidateControls) {
            await expect(checkbox).not.toBeChecked();
          }
        },
      );
    }

    for (const checkbox of candidateControls) await checkbox.check();
    const selectedNodeIds = preflight.context.candidates.map(({ id }) => id);
    const advanced = await advanceAutonomousIntake(
      page,
      "Review the resolved mission",
      { expectPreflight: true },
    );
    if (!advanced.preflight) throw new Error("Review step did not receive Autonomous preflight");
    const resolved = await advanced.resolved.json() as ResolvedMissionIntake;
    if (resolved.request.journey !== "autonomous") {
      throw new Error("Expected a resolved Autonomous mission request");
    }
    expect(resolved.request.authorization.engagementId).toBe(fixture.engagementId);
    expect(resolved.request.contract.memoryScopes).toEqual(
      MEMORY_SCOPES.map(([, id]) => id),
    );
    expect(resolved.request.contract.contextNodeIds).toEqual(selectedNodeIds);
    const checked = await advanced.preflight.json() as AutonomousMissionPreflight;
    expect(checked.context.selectedNodeIds).toEqual(selectedNodeIds);
    expect(checked.context.invalidSelectedNodeIds).toEqual([]);

    const invalidIds = [
      fixture.crossEngagementNode.id,
      ...fixture.ineligibleNodes.map(({ id }) => id),
    ];
    const invalidRequest = {
      ...resolved.request,
      contract: {
        ...resolved.request.contract,
        contextNodeIds: [...selectedNodeIds, ...invalidIds],
      },
    };
    const csrfToken = (await page.context().cookies())
      .find(({ name }) => name === "ti_scale_csrf")
      ?.value;
    expect(csrfToken).toBeTruthy();
    const invalidResponse = await browserAudit.request(request, {
      method: "POST",
      url: "/api/v2/missions/autonomous/preflight",
      options: {
        data: invalidRequest,
        headers: { "X-Ti-Scale-CSRF": csrfToken! },
      },
    });
    expect(invalidResponse.status(), await invalidResponse.text()).toBe(200);
    const invalidPreflight = await invalidResponse.json() as AutonomousMissionPreflight;
    expect(invalidPreflight.context.selectedNodeIds).toEqual(selectedNodeIds);
    expect(new Set(invalidPreflight.context.invalidSelectedNodeIds)).toEqual(
      new Set(invalidIds),
    );
    expect(invalidPreflight.context.candidates.map(({ id }) => id))
      .not.toContain(fixture.crossEngagementNode.id);
    for (const id of fixture.ineligibleNodes.map(({ id }) => id)) {
      expect(invalidPreflight.context.candidates.map((candidate) => candidate.id))
        .not.toContain(id);
    }
    expect(ledger.count("POST", "/api/v2/missions")).toBe(0);
  } finally {
    ledger.dispose();
  }
});

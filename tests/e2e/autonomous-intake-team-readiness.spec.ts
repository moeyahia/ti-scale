import type { AutonomousMissionPreflight } from "../../src/domain/types/commandOs";
import {
  activateAutonomousIntake,
  advanceAutonomousIntake,
  autonomousIntakeGroup,
  autonomousTitaniumSelect,
  chooseAutonomousTitaniumOption,
  createIntakeRequestLedger,
  installIntakeApiProxy,
  type IntakeReceiptContext,
} from "./support/autonomousIntake";
import { createMissionIntakeDynamicFixture } from "./support/missionIntakeDynamicFixture";
import { startReadyAutonomousIntakeBackend } from "./support/readyAutonomousIntakeBackendController";
import {
  expect,
  test,
  type Locator,
  type Page,
} from "./support/playwright";

const TEST_ID = "e2e.autonomous-intake.team-readiness";
const TEAM_OPTION =
  "Each preflight specialist candidate: toggle when compatible; assert disabled with reasons when incompatible";
const RECOMMENDED_OPTION =
  "Select the current runtime-recommended compatible specialists";

function candidateRow(team: Locator, displayName: string): Locator {
  return team
    .locator("label.os-check-field")
    .filter({ hasText: displayName });
}

async function selectedCandidateIds(
  team: Locator,
  preflight: AutonomousMissionPreflight,
): Promise<string[]> {
  const selected: string[] = [];
  for (const candidate of preflight.execution.team.candidates) {
    if (await candidateRow(team, candidate.displayName).getByRole("checkbox").isChecked()) {
      selected.push(candidate.id);
    }
  }
  return selected;
}

async function openTeam(page: Page): Promise<{
  readonly team: Locator;
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
  await page
    .getByRole("checkbox", {
      name: /I confirm these targets and the selected action policy are authorized/u,
    })
    .check();
  await advanceAutonomousIntake(page, "Outcome and collaboration");
  await advanceAutonomousIntake(page, "Autonomous operating contract");
  const advanced = await advanceAutonomousIntake(
    page,
    "Specialist team and execution readiness",
    { expectPreflight: true },
  );
  if (!advanced.preflight) throw new Error("Team step did not receive Autonomous preflight");
  return {
    team: autonomousIntakeGroup(page, "Specialist team and execution readiness"),
    preflight: await advanced.preflight.json() as AutonomousMissionPreflight,
  };
}

test(`${TEST_ID} refreshes a stable specialist attestation instead of retaining expired fixture data`, async ({}, testInfo) => {
  const fixture = createMissionIntakeDynamicFixture(testInfo.testId, {
    preseedExpiredAttestation: true,
  });
  expect(fixture.agentId).toBe("ReconScout");
});

test(`${TEST_ID} traverses the exact live specialist and provider boundary`, async ({
  page,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(180_000);
  const backend = await startReadyAutonomousIntakeBackend(testInfo.testId, {
    profile: "team_boundary",
  });
  const proxy = await installIntakeApiProxy(page, backend.baseUrl);
  const ledger = createIntakeRequestLedger(page);
  const receipts: IntakeReceiptContext = {
    recorder: interactionActivation,
    testId: TEST_ID,
  };
  try {
    const { team, preflight } = await openTeam(page);
    const candidates = preflight.execution.team.candidates;
    const compatible = candidates.filter((candidate) => candidate.compatible);
    const incompatible = candidates.filter((candidate) => !candidate.compatible);

    expect(candidates.length).toBeGreaterThan(1);
    expect(compatible.map(({ id }) => id)).toContain("ReconScout");
    expect(incompatible.length).toBeGreaterThan(0);
    await expect(team.locator("label.os-check-field")).toHaveCount(candidates.length);

    for (const candidate of candidates) {
      const row = candidateRow(team, candidate.displayName);
      await expect(row).toHaveCount(1);
      await expect(row.getByText(candidate.role, { exact: true })).toBeVisible();
      await expect(row).toContainText(
        `${candidate.runnableTools.length} reviewed tools · ${candidate.mcpServerIds.length} MCP servers`,
      );
      const checkbox = row.getByRole("checkbox");
      if (candidate.compatible) {
        await expect(checkbox).toBeEnabled();
      } else {
        await expect(checkbox).toBeDisabled();
        await expect(checkbox).not.toBeChecked();
        expect(candidate.incompatibilityReasons.length).toBeGreaterThan(0);
        for (const reason of candidate.incompatibilityReasons) {
          await expect(row).toContainText(reason);
        }
      }
    }

    const initialChecked = new Map<string, boolean>();
    for (const candidate of compatible) {
      initialChecked.set(
        candidate.id,
        await candidateRow(team, candidate.displayName).getByRole("checkbox").isChecked(),
      );
    }
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.team.specialists",
      TEAM_OPTION,
      "pointer",
      async () => {
        for (const candidate of compatible) {
          const checkbox = candidateRow(team, candidate.displayName).getByRole("checkbox");
          await checkbox.click();
          await expect(checkbox).toBeChecked({
            checked: !initialChecked.get(candidate.id),
          });
        }
        for (const candidate of incompatible) {
          const row = candidateRow(team, candidate.displayName);
          await expect(row.getByRole("checkbox")).toBeDisabled();
          for (const reason of candidate.incompatibilityReasons) {
            await expect(row).toContainText(reason);
          }
        }
      },
    );
    await activateAutonomousIntake(
      receipts,
      "autonomous-intake.team.specialists",
      TEAM_OPTION,
      "keyboard",
      async () => {
        for (const candidate of compatible) {
          const checkbox = candidateRow(team, candidate.displayName).getByRole("checkbox");
          await checkbox.focus();
          await checkbox.press("Space");
          await expect(checkbox).toBeChecked({
            checked: initialChecked.get(candidate.id),
          });
        }
        for (const candidate of incompatible) {
          const row = candidateRow(team, candidate.displayName);
          await expect(row.getByRole("checkbox")).toBeDisabled();
          for (const reason of candidate.incompatibilityReasons) {
            await expect(row).toContainText(reason);
          }
        }
      },
    );

    const recommended = page.getByRole("button", {
      name: "Use recommended team",
      exact: true,
    });
    for (const modality of ["pointer", "keyboard"] as const) {
      for (const candidate of compatible) {
        await candidateRow(team, candidate.displayName).getByRole("checkbox").uncheck();
      }
      await activateAutonomousIntake(
        receipts,
        "autonomous-intake.team.recommended",
        RECOMMENDED_OPTION,
        modality,
        async () => {
          if (modality === "pointer") {
            await recommended.click();
          } else {
            await recommended.focus();
            await recommended.press("Enter");
          }
          expect(await selectedCandidateIds(team, preflight)).toEqual(
            preflight.execution.team.recommendedAgentIds,
          );
        },
      );
    }

    const providerList = team.locator("ul.os-review-list");
    await expect(providerList.getByRole("listitem")).toHaveCount(
      preflight.execution.providers.length,
    );
    for (const provider of preflight.execution.providers) {
      const row = providerList
        .getByRole("listitem")
        .filter({
          has: page.getByText(provider.id, { exact: true }),
        });
      await expect(row).toHaveCount(1);
      await expect(row).toContainText(provider.reason);
      await expect(row).toContainText(
        provider.enforcesAutonomousBoundary
          ? "Local runtime enforcement available"
          : "Advisor/observe-only for this contract",
      );
    }

    const advanced = await advanceAutonomousIntake(
      page,
      "Second Brain context",
      { expectPreflight: true },
    );
    if (!advanced.preflight) throw new Error("Context step did not receive Autonomous preflight");
    const submitted = advanced.preflight.request().postDataJSON() as {
      readonly contract: { readonly specialistAgentIds: readonly string[] };
    };
    expect(submitted.contract.specialistAgentIds).toEqual(
      preflight.execution.team.recommendedAgentIds,
    );
    const checked = await advanced.preflight.json() as AutonomousMissionPreflight;
    expect(checked.execution.team.selectedAgentIds).toEqual(
      preflight.execution.team.recommendedAgentIds,
    );
    expect(checked.execution.team.effectiveAgentIds).toEqual(
      preflight.execution.team.recommendedAgentIds,
    );
    expect(checked.execution.team.invalidSelectedAgentIds).toEqual([]);
    expect(ledger.count("POST", "/api/v2/missions")).toBe(0);
  } finally {
    ledger.dispose();
    await proxy.dispose();
    await backend.stop();
  }
});

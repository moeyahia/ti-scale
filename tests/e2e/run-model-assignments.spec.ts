import { expect, test } from "./support/playwright";
import { createAutonomousActivationProofFixture } from "./support/autonomousActivationProofFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_ID = "e2e.run-model-assignments.readback";

test(`${TEST_ID} shows exact immutable execution and planning receipts on the mission Summary`, async ({
  page,
  browserAudit,
}, testInfo) => {
  const fixture = createAutonomousActivationProofFixture(
    canonicalFixtureNamespace(testInfo, "run-model-assignments"),
    {
      planningRoute: "provider_advisory",
      receiptState: "valid",
    },
  );
  const readbackPath =
    `/api/v2/runs/${fixture.runId}/model-assignments`;
  const readback = page.waitForResponse((response) =>
    response.request().method() === "GET"
    && new URL(response.url()).pathname === readbackPath
    && response.status() === 200
  );

  await page.goto(
    `/missions/${encodeURIComponent(fixture.missionId)}/runs/${encodeURIComponent(fixture.runId)}`,
    { waitUntil: "domcontentloaded" },
  );
  const payload = await (await readback).json() as {
    readonly activeRunPinning: string;
    readonly items: readonly {
      readonly assignment: {
        readonly agentId: string;
        readonly purpose: string;
        readonly pinned: boolean;
      };
    }[];
  };
  expect(payload.activeRunPinning).toBe("immutable");
  expect(payload.items).toHaveLength(2);
  expect(payload.items.map(({ assignment }) => assignment.purpose).sort())
    .toEqual(["execution", "planning"]);
  expect(payload.items.every(({ assignment }) => assignment.pinned)).toBe(true);

  let panel = page.getByRole("region", {
    name: "Current run model routing",
    exact: true,
  });
  await expect(panel).toBeVisible();
  await expect(panel).toContainText("2 pinned");
  await expect(panel).toContainText("Current run configuration");
  await expect(panel).toContainText("Pinned provider and model routes");
  await expect(panel).toContainText("Execution configuration");
  await expect(panel).toContainText("Planning configuration");
  await expect(panel).toContainText("Execution pin");
  await expect(panel).toContainText("Advisory pin");
  await expect(panel).toContainText("e2e-provider");
  await expect(panel).toContainText("Sanitized Internal");
  await expect(panel).toContainText("Execution and advisory configurations remain distinct");
  const advisoryReceipt = panel.getByRole("listitem", {
    name: / planning model configuration receipt$/u,
  });
  await expect(advisoryReceipt).toContainText("No execution authority.");
  await expect(advisoryReceipt).toContainText(
    "planning, explanation, and critique only",
  );
  await expect(advisoryReceipt).toContainText(
    "specialist execution remains separately pinned and enforced",
  );
  await expect(panel).toContainText("Change future defaults from Agent Fleet");
  await expect(panel).toContainText(
    "never rewrites an active run’s provider/model configuration",
  );
  await expect(panel).not.toContainText("Current run authority");
  await expect(panel).not.toContainText("provider/model authority");
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 750 });
});

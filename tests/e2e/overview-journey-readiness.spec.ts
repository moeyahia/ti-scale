import { expect, test, type Locator } from "./support/playwright";

const TEST_ID = "e2e.overview.journey-readiness";
const RETRY_CASES = [
  { input: "pointer", testId: "e2e.overview.read-retry.pointer" },
  { input: "keyboard", testId: "e2e.overview.read-retry.keyboard" },
] as const;

async function activate(control: Locator, input: "keyboard" | "pointer"): Promise<void> {
  if (input === "keyboard") {
    await control.focus();
    await expect(control).toBeFocused();
    await control.press("Enter");
    return;
  }
  await control.click();
}

test.describe(`${TEST_ID} truthful journey status`, () => {
  test("shows usable Guided separately from unavailable Autonomous", async ({ page, browserAudit }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });

    const band = page.getByRole("region", { name: "Guided missions are available", exact: true });
    await expect(band).toBeVisible();
    await expect(band.getByText("Autonomous Unavailable", { exact: true })).toBeVisible();
    await expect(band.getByText("Guided Manual-only ready", { exact: true })).toBeVisible();
    await expect(page.getByText("Launch blockers require attention", { exact: true })).toHaveCount(0);
    await expect(page.getByLabel(/Readiness score/u)).toHaveCount(0);

    const guided = page.getByRole("article").filter({
      has: page.getByRole("heading", { level: 2, name: "Start Guided Mission", exact: true }),
    });
    await expect(guided.getByText("Manual-only ready", { exact: true })).toBeVisible();
    await expect(guided.getByText("0 launch blockers", { exact: true })).toBeVisible();
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });
});

for (const { input, testId } of RETRY_CASES) {
  test(`${testId} explains one failed overview read and retries the canonical snapshot`, async ({ page, browserAudit }) => {
    test.setTimeout(60_000);
    browserAudit.expectHttpResponse(page, {
      id: `overview.initial-unavailable.${input}`,
      transport: "browser",
      method: "GET",
      pathname: "/api/v2/overview",
      query: {},
      status: 503,
      occurrences: 1,
      reason: `Exercise the Command Center's exact ${input} retry path once.`,
    });
    let failedOnce = false;
    await page.route("**/api/v2/overview", async (route) => {
      if (!failedOnce && route.request().method() === "GET") {
        failedOnce = true;
        await route.fulfill({
          status: 503,
          contentType: "application/json; charset=utf-8",
          body: JSON.stringify({
            error: {
              code: "overview_fixture_temporarily_unavailable",
              message: "The canonical Command Center snapshot is temporarily unavailable",
              humanMessage: "The Command Center could not read the current operational snapshot.",
              retryable: true,
              category: "dependency",
              remediation: "Retry after the local operational projection recovers.",
              traceId: `trace-overview-retry-${input}`,
              timestamp: "2099-07-21T20:00:00.000Z",
            },
          }),
        });
        return;
      }
      await route.fallback();
    });

    await page.goto("/", { waitUntil: "domcontentloaded" });
    const alert = page.getByRole("alert");
    await expect(alert).toContainText("The Command Center could not read the current operational snapshot.");
    await expect(alert).toContainText("Retry after the local operational projection recovers.");
    await expect(alert).toContainText(`Trace trace-overview-retry-${input}`);
    await expect(page.getByRole("region", { name: "Guided missions are available", exact: true })).toHaveCount(0);

    await page.unroute("**/api/v2/overview");
    const recoveredRead = page.waitForResponse((response) => response.request().method() === "GET"
      && new URL(response.url()).pathname === "/api/v2/overview"
      && response.status() === 200);
    await activate(alert.getByRole("button", { name: "Try again", exact: true }), input);
    expect((await recoveredRead).status()).toBe(200);
    await expect(alert).toHaveCount(0);
    await expect(page.getByRole("region", { name: "Guided missions are available", exact: true })).toBeVisible();
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
  });
}

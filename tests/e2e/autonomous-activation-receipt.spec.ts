import {
  expect,
  test,
  type Locator,
  type Page,
  type TestInfo,
} from "./support/playwright";
import type { BrowserAuditController } from "./support/browserAudit";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
} from "./support/interactionActivationFixture";
import {
  createAutonomousActivationProofFixture,
  type AutonomousActivationProofFixture,
} from "./support/autonomousActivationProofFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";

const TEST_ID = "e2e.autonomous-run.activation-receipt";
type Modality = "keyboard" | "pointer";

const controls = {
  refresh: {
    entry: "autonomous-run.activation-proof.refresh",
    id: "autonomous-activation-proof-refresh",
    state: "Fixture required: an Autonomous run is open with either no aggregate activation receipt or one current immutable receipt",
  },
  review: {
    entry: "autonomous-run.activation-proof.review",
    id: "autonomous-activation-proof-review",
    state: "Fixture required: an Autonomous run has a current valid, expired, or integrity-failed aggregate activation receipt",
  },
  close: {
    entry: "autonomous-run.activation-proof.close",
    id: "autonomous-activation-proof-close",
    state: "Fixture required: an exact run-scoped activation receipt detail is open",
  },
  retry: {
    entry: "autonomous-run.activation-proof.detail-retry",
    id: "autonomous-activation-proof-detail-retry",
    state: "Fixture required: the exact activation-proof detail request failed without cached data",
  },
  hashes: {
    entry: "autonomous-run.activation-proof.hashes",
    id: "autonomous-activation-proof-technical-hashes",
    state: "Fixture required: an exact activation proof with contract, runtime, context, model, tool-route, and binding hashes is open",
  },
} as const;

function activation(
  control: (typeof controls)[keyof typeof controls],
  option: string,
  _materialState: string,
  modality: Modality,
): InteractionActivationInput {
  return {
    manifestEntryId: control.entry,
    controlId: control.id,
    option,
    materialState: control.state,
    modality,
    testId: TEST_ID,
  };
}

async function activate(control: Locator, modality: Modality): Promise<void> {
  if (modality === "pointer") {
    await control.click();
    return;
  }
  await control.focus();
  await expect(control).toBeFocused();
  await control.press("Enter");
}

function runRoute(fixture: AutonomousActivationProofFixture): string {
  return `/live/${encodeURIComponent(fixture.runId)}`;
}

async function openRun(
  page: Page,
  browserAudit: BrowserAuditController,
  fixture: AutonomousActivationProofFixture,
): Promise<Locator> {
  await page.goto(runRoute(fixture), { waitUntil: "domcontentloaded" });
  const panel = page.getByRole("region", {
    name: "Autonomous activation proof",
    exact: true,
  });
  await expect(panel).toBeVisible();
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 500 });
  const overflow = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(
    overflow.scrollWidth,
    "Activation proof must not create horizontal page overflow",
  ).toBeLessThanOrEqual(overflow.clientWidth + 1);
  return panel;
}

async function refreshProof(
  page: Page,
  panel: Locator,
  fixture: AutonomousActivationProofFixture,
  recorder: InteractionActivationRecorder,
  option: string,
  materialState: string,
  modality: Modality,
): Promise<void> {
  const runRead = page.waitForResponse((response) =>
    response.request().method() === "GET"
    && new URL(response.url()).pathname === `/api/v2/runs/${fixture.runId}`
    && response.status() === 200
  );
  const historyRead = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET"
      && url.pathname ===
        `/api/v2/runs/${fixture.runId}/autonomous-activation-receipts`
      && url.searchParams.get("limit") === "100"
      && response.status() === 200;
  });
  await recorder.activate(
    activation(controls.refresh, option, materialState, modality),
    async () => {
      await activate(
        panel.getByRole("button", {
          name: "Refresh activation proof",
          exact: true,
        }),
        modality,
      );
      await Promise.all([runRead, historyRead]);
    },
  );
}

async function openDetail(
  page: Page,
  panel: Locator,
  fixture: AutonomousActivationProofFixture,
  recorder: InteractionActivationRecorder,
  option: string,
  materialState: string,
  modality: Modality,
): Promise<Locator> {
  if (!fixture.receiptId) throw new Error("A receipt fixture is required");
  const detailRead = page.waitForResponse((response) =>
    response.request().method() === "GET"
    && new URL(response.url()).pathname ===
      `/api/v2/runs/${fixture.runId}/autonomous-activation-receipts/${fixture.receiptId}`
    && response.status() === 200
  );
  await recorder.activate(
    activation(controls.review, option, materialState, modality),
    async () => {
      await activate(
        panel.getByRole("button", {
          name: "Review activation proof",
          exact: true,
        }),
        modality,
      );
      await detailRead;
    },
  );
  await expect(page).toHaveURL(new RegExp(
    `activationReceipt=${encodeURIComponent(fixture.receiptId)}`,
    "u",
  ));
  const detail = panel.getByRole("region", {
    name: "Autonomous activation proof detail",
    exact: true,
  });
  await expect(detail).toBeVisible();
  await expect(detail).toBeFocused();
  return detail;
}

async function closeDetail(
  page: Page,
  panel: Locator,
  detail: Locator,
  recorder: InteractionActivationRecorder,
  modality: Modality,
): Promise<void> {
  await recorder.activate(
    activation(
      controls.close,
      "Close current detail while preserving other URL state",
      "Exact run-scoped activation proof detail open",
      modality,
    ),
    async () => {
      await activate(
        detail.getByRole("button", {
          name: "Close activation proof",
          exact: true,
        }),
        modality,
      );
      await expect(detail).toHaveCount(0);
      expect(new URL(page.url()).searchParams.has("activationReceipt"))
        .toBe(false);
      await expect(panel.getByRole("button", {
        name: "Review activation proof",
        exact: true,
      })).toBeFocused();
    },
  );
}

async function toggleHashes(
  detail: Locator,
  recorder: InteractionActivationRecorder,
  modality: Modality,
): Promise<void> {
  const disclosure = detail.locator(
    "#autonomous-activation-proof-technical-hashes",
  );
  const summary = disclosure.locator("summary");
  for (const [option, open] of [
    ["Open technical activation hashes", true],
    ["Close technical activation hashes", false],
  ] as const) {
    await recorder.activate(
      activation(
        controls.hashes,
        option,
        "Schema-valid immutable activation proof detail",
        modality,
      ),
      async () => {
        await activate(summary, modality);
        await expect(disclosure).toHaveJSProperty("open", open);
      },
    );
  }
}

function fixture(
  testInfo: TestInfo,
  name: string,
  options: Parameters<typeof createAutonomousActivationProofFixture>[1],
): AutonomousActivationProofFixture {
  return createAutonomousActivationProofFixture(
    canonicalFixtureNamespace(testInfo, name),
    options,
  );
}

test(`${TEST_ID} proves missing, local, provider, expired, detail, and retry states`, async ({
  page,
  browserAudit,
  interactionActivation,
}, testInfo) => {
  test.setTimeout(240_000);
  await page.emulateMedia({ reducedMotion: "reduce" });

  const missing = fixture(testInfo, "activation-proof-missing", {
    planningRoute: "local_deterministic",
    receiptState: "missing",
  });
  const provider = fixture(testInfo, "activation-proof-provider", {
    planningRoute: "provider_advisory",
    receiptState: "valid",
  });
  const local = fixture(testInfo, "activation-proof-local", {
    planningRoute: "local_deterministic",
    receiptState: "valid",
  });
  const expired = fixture(testInfo, "activation-proof-expired", {
    planningRoute: "provider_advisory",
    receiptState: "expired",
  });

  let panel = await openRun(page, browserAudit, missing);
  await expect(panel.getByText("Not issued", { exact: true })).toBeVisible();
  await expect(panel).toContainText(
    "The absence of a receipt is never treated as permission.",
  );
  await expect(panel.getByRole("button", {
    name: "Review activation proof",
    exact: true,
  })).toHaveCount(0);
  for (const modality of ["pointer", "keyboard"] as const) {
    await refreshProof(
      page,
      panel,
      missing,
      interactionActivation,
      "Refresh missing/pending proof state",
      "Autonomous run without an aggregate activation receipt",
      modality,
    );
  }

  panel = await openRun(page, browserAudit, provider);
  await expect(panel.getByText("Verified", { exact: true })).toBeVisible();
  await expect(panel).toContainText("Provider advisory plan selection");
  for (const modality of ["pointer", "keyboard"] as const) {
    await refreshProof(
      page,
      panel,
      provider,
      interactionActivation,
      "Refresh current proof and bounded history",
      "Autonomous run with a current verified receipt",
      modality,
    );
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    panel = await openRun(page, browserAudit, provider);
    const detail = await openDetail(
      page,
      panel,
      provider,
      interactionActivation,
      "Review provider advisory proof",
      "Current provider advisory activation proof",
      modality,
    );
    await expect(detail).toContainText("assignment-planning-");
    await expect(detail).toContainText("e2e-nmap-service-scan");
    await toggleHashes(detail, interactionActivation, modality);
    await closeDetail(
      page,
      panel,
      detail,
      interactionActivation,
      modality,
    );
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    panel = await openRun(page, browserAudit, local);
    await expect(panel).toContainText("Local deterministic plan construction");
    const detail = await openDetail(
      page,
      panel,
      local,
      interactionActivation,
      "Review local deterministic proof",
      "Current local deterministic activation proof",
      modality,
    );
    await expect(detail).toContainText("No provider model — local planner");
  }

  for (const modality of ["pointer", "keyboard"] as const) {
    panel = await openRun(page, browserAudit, expired);
    await expect(panel.getByText("Expired", { exact: true })).toBeVisible();
    await expect(panel).toContainText("Re-run Autonomous readiness");
    const detail = await openDetail(
      page,
      panel,
      expired,
      interactionActivation,
      "Review expired or drifted proof",
      "Expired aggregate activation proof",
      modality,
    );
    await expect(detail.getByText("Expired", { exact: true })).toBeVisible();
  }

  panel = await openRun(page, browserAudit, provider);
  if (!provider.receiptId) throw new Error("Provider receipt is missing");
  await openDetail(
    page,
    panel,
    provider,
    interactionActivation,
    "Review provider advisory proof",
    "Provider proof before direct browser refresh",
    "pointer",
  );
  await browserAudit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.reload({ waitUntil: "domcontentloaded" }),
  );
  await expect(page).toHaveURL(new RegExp(
    `activationReceipt=${encodeURIComponent(provider.receiptId)}`,
    "u",
  ));
  await expect(page.getByRole("region", {
    name: "Autonomous activation proof detail",
    exact: true,
  })).toContainText("e2e-nmap-service-scan");

  const unavailableReceiptId = `missing-${provider.receiptId}`;
  const unavailablePath =
    `/api/v2/runs/${provider.runId}/autonomous-activation-receipts/${unavailableReceiptId}`;
  browserAudit.expectHttpResponse(page, {
    id: `activation-proof-detail-missing-${testInfo.project.name}`,
    transport: "browser",
    method: "GET",
    pathname: unavailablePath,
    query: {},
    status: 404,
    occurrences: 3,
    reason: "Exercise the exact run-scoped immutable receipt retry state.",
  });
  await page.goto(
    `${runRoute(provider)}?activationReceipt=${encodeURIComponent(unavailableReceiptId)}`,
    { waitUntil: "domcontentloaded" },
  );
  const detailError = page.getByRole("region", {
    name: "Autonomous activation proof detail",
    exact: true,
  }).getByRole("alert");
  await expect(detailError).toContainText(
    "Activation proof detail is unavailable.",
  );
  for (const modality of ["pointer", "keyboard"] as const) {
    const failedRead = page.waitForResponse((response) =>
      response.request().method() === "GET"
      && new URL(response.url()).pathname === unavailablePath
      && response.status() === 404
    );
    await interactionActivation.activate(
      activation(
        controls.retry,
        "Retry the exact run-scoped immutable receipt read",
        "Exact activation-proof detail read failed without cached data",
        modality,
      ),
      async () => {
        await activate(
          detailError.getByRole("button", {
            name: "Retry activation proof detail",
            exact: true,
          }),
          modality,
        );
        await failedRead;
        await expect(detailError).toContainText(
          "Activation proof detail is unavailable.",
        );
      },
    );
  }

  await browserAudit.waitForPageApiSettlement(page, { quietMs: 700 });
});

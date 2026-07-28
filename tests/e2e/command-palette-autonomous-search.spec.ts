import { readFileSync } from "node:fs";
import { validateInteractionManifest } from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import {
  createAutonomousCommandPaletteFixture,
  type AutonomousCommandPaletteFixture,
} from "./support/autonomousCommandPaletteFixture";
import { canonicalFixtureNamespace } from "./support/fixtureNamespace";
import { expect, test, type Locator, type Page, type Request } from "./support/playwright";

const TEST_ID = "e2e.command-palette.autonomous-search";
const MANIFEST_IDS = [
  "command-palette.search",
  "command-palette.results",
  "command-palette.mission-results",
  "command-palette.run-results",
] as const;
const manifest = validateInteractionManifest(JSON.parse(
  readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8"),
) as unknown);

let fixture: AutonomousCommandPaletteFixture;

test.beforeEach(({}, testInfo) => {
  fixture = createAutonomousCommandPaletteFixture(canonicalFixtureNamespace(
    testInfo,
    `autonomous-command-palette-${testInfo.testId}`,
  ));
});

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function pathname(request: Request): string {
  return new URL(request.url()).pathname;
}

function manifestEntry(id: typeof MANIFEST_IDS[number]): void {
  if (!manifest.entries.some((entry) => entry.id === id && entry.testIds.includes(TEST_ID))) {
    throw new Error(`Command palette manifest entry ${id} is not assigned to ${TEST_ID}`);
  }
}

async function waitForPaletteSearch(dialog: Locator): Promise<void> {
  await expect(dialog.locator("[role='status'][aria-live='polite']"))
    .toHaveText(/\d+ commands? available/u, { timeout: 15_000 });
}

async function openPalette(page: Page): Promise<Locator> {
  const initialCollections = ["/api/v2/missions", "/api/v2/runs", "/api/v2/decisions", "/api/v2/agents"];
  const initialResponses = initialCollections.map((path) => page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET" && url.pathname === path &&
      url.searchParams.get("limit") === "100" && !url.searchParams.has("query");
  }));
  const trigger = page.getByRole("button", { name: "Search or run a command", exact: true });
  await expect(trigger).toBeVisible();
  await trigger.click();
  const dialog = page.getByRole("dialog", { name: "Command palette", exact: true });
  await expect(dialog).toBeVisible();
  const search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  await expect(search).toBeFocused();
  for (const response of await Promise.all(initialResponses)) expect(response.status()).toBe(200);
  await waitForPaletteSearch(dialog);
  return dialog;
}

async function assertMissionDestination(page: Page): Promise<void> {
  await expect(page.getByRole("heading", { name: fixture.missionLabel, exact: true })).toBeVisible();
  await expect(page.getByText("Autonomous mission", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("region", { name: "Selected run status", exact: true }))
    .toContainText("Planning autonomously");
  await expect(page.getByRole("region", { name: "Mission workspace", exact: true })).toBeVisible();
}

async function assertRunDestination(page: Page): Promise<void> {
  await expect(page.getByRole("heading", { name: fixture.missionLabel, exact: true })).toBeVisible();
  await expect(page.getByText("Autonomous run", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("region", { name: "Selected run status", exact: true }))
    .toContainText("Planning autonomously");
  await expect(page.getByRole("heading", { name: "Plan and agent ownership", exact: true })).toBeVisible();
}

test(`${TEST_ID} preserves exact V2 Autonomous search identities and names partial domains`, async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  for (const id of MANIFEST_IDS) manifestEntry(id);
  const missionPath = "/api/v2/missions";
  const runPath = "/api/v2/runs";
  const audit = new BrowserAudit(page, {
    allowEventStreamNavigationAbort: true,
    expectedHttpResponses: [
      {
        id: "command-palette.autonomous-missions-query-partial",
        transport: "browser",
        method: "GET",
        pathname: missionPath,
        query: { query: fixture.missionToken, limit: "100" },
        status: 503,
        occurrences: 1,
        reason: "Prove a failed mission query omits the prior Autonomous row without fabricating a route.",
      },
      {
        id: "command-palette.autonomous-runs-query-partial",
        transport: "browser",
        method: "GET",
        pathname: runPath,
        query: { query: fixture.runToken, limit: "100" },
        status: 503,
        occurrences: 1,
        reason: "Prove a failed run query omits the prior Autonomous row without fabricating a route.",
      },
    ],
  });

  await page.goto("/manual", { waitUntil: "domcontentloaded" });
  let dialog = await openPalette(page);
  let search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  const missionResponse = page.waitForResponse(async (response) => {
    const url = new URL(response.url());
    if (response.request().method() !== "GET" || url.pathname !== missionPath ||
      url.searchParams.get("query") !== fixture.missionToken || url.searchParams.get("limit") !== "100") return false;
    const payload = await response.json() as {
      items?: Array<{ id?: unknown; journey?: unknown; runId?: unknown }>;
    };
    return payload.items?.some((item) => item.id === fixture.missionId &&
      item.journey === "autonomous" && item.runId === fixture.runId) === true;
  });
  await search.fill(fixture.missionToken);
  expect((await missionResponse).status()).toBe(200);
  await waitForPaletteSearch(dialog);
  const missionOption = dialog.getByRole("option", {
    name: new RegExp(`^${escapeRegex(fixture.missionLabel)}.*Autonomous mission.*planning$`, "u"),
  }).first();
  await expect(missionOption).toBeVisible();
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  await missionOption.click();
  const canonicalMissionPath = `/missions/${encodeURIComponent(fixture.missionId)}`;
  await expect(page).toHaveURL((url) => url.pathname === canonicalMissionPath && url.search === "");
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  await assertMissionDestination(page);

  const reloadedMission = page.waitForResponse(async (response) => {
    if (response.request().method() !== "GET" ||
      pathname(response.request()) !== `/api/v2/missions/${fixture.missionId}/runtime`) return false;
    const payload = await response.json() as {
      mission?: { id?: unknown; journey?: unknown };
      runs?: Array<{ id?: unknown }>;
    };
    return payload.mission?.id === fixture.missionId && payload.mission.journey === "autonomous" &&
      payload.runs?.some((run) => run.id === fixture.runId) === true;
  });
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await reloadedMission).status()).toBe(200);
  await assertMissionDestination(page);
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  await audit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
  await expect(page).toHaveURL((url) => url.pathname === "/manual" && url.search === "");
  await audit.withExpectedHistoryTraversal(page, () => page.goForward({ waitUntil: "domcontentloaded" }));
  await expect(page).toHaveURL((url) => url.pathname === canonicalMissionPath && url.search === "");
  await assertMissionDestination(page);
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });

  // The command palette is global. Keep the already-settled live-run document
  // for the degraded-domain pass so this assertion tests search reconciliation
  // rather than replaying the intentionally animated application bootstrap.
  dialog = await openPalette(page);
  search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  const runResponse = page.waitForResponse(async (response) => {
    const url = new URL(response.url());
    if (response.request().method() !== "GET" || url.pathname !== runPath ||
      url.searchParams.get("query") !== fixture.runToken || url.searchParams.get("limit") !== "100") return false;
    const payload = await response.json() as {
      items?: Array<{ id?: unknown; missionId?: unknown; journey?: unknown }>;
    };
    return payload.items?.some((item) => item.id === fixture.runId &&
      item.missionId === fixture.missionId && item.journey === "autonomous") === true;
  });
  await search.fill(fixture.runToken);
  expect((await runResponse).status()).toBe(200);
  await waitForPaletteSearch(dialog);
  const runOption = dialog.getByRole("option", {
    name: new RegExp(`^${escapeRegex(fixture.missionLabel)}.*Autonomous run.*${escapeRegex(fixture.runId)}$`, "u"),
  }).first();
  await expect(runOption).toBeVisible();
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  for (let index = 0; index < 20 && await runOption.getAttribute("aria-selected") !== "true"; index += 1) {
    await search.press("ArrowDown");
  }
  await expect(runOption).toHaveAttribute("aria-selected", "true");
  await search.press("Enter");
  const canonicalRunPath = `/live/${encodeURIComponent(fixture.runId)}`;
  await expect(page).toHaveURL((url) => url.pathname === canonicalRunPath && url.search === "");
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  await assertRunDestination(page);

  const reloadedRun = page.waitForResponse(async (response) => {
    if (response.request().method() !== "GET" || pathname(response.request()) !== `/api/v2/runs/${fixture.runId}`) return false;
    const payload = await response.json() as {
      run?: { id?: unknown; missionId?: unknown; journey?: unknown };
    };
    return payload.run?.id === fixture.runId && payload.run.missionId === fixture.missionId &&
      payload.run.journey === "autonomous";
  });
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.reload({ waitUntil: "domcontentloaded" }));
  expect((await reloadedRun).status()).toBe(200);
  await assertRunDestination(page);
  await audit.waitForPageApiSettlement(page, { quietMs: 1_000 });

  await page.route((url) => url.pathname === missionPath &&
    url.searchParams.get("query") === fixture.missionToken && url.searchParams.get("limit") === "100", (route) =>
    route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: {
      code: "fixture_mission_search_unavailable",
      message: "Mission search unavailable",
      humanMessage: "Mission search is temporarily unavailable.",
      retryable: true,
      category: "dependency_unavailable",
      details: {},
      traceId: "trace-autonomous-palette-mission-partial",
      remediation: "Retry after the canonical mission projection recovers.",
      timestamp: new Date().toISOString(),
    } }) }));
  await page.route((url) => url.pathname === runPath &&
    url.searchParams.get("query") === fixture.runToken && url.searchParams.get("limit") === "100", (route) =>
    route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: {
      code: "fixture_run_search_unavailable",
      message: "Run search unavailable",
      humanMessage: "Run search is temporarily unavailable.",
      retryable: true,
      category: "dependency_unavailable",
      details: {},
      traceId: "trace-autonomous-palette-run-partial",
      remediation: "Retry after the canonical run projection recovers.",
      timestamp: new Date().toISOString(),
    } }) }));

  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto("/manual", { waitUntil: "domcontentloaded" }));
  dialog = await openPalette(page);
  search = dialog.getByRole("combobox", {
    name: "Search commands, missions, runs, decisions, agents, and Second Brain",
    exact: true,
  });
  await search.fill(fixture.missionToken);
  await waitForPaletteSearch(dialog);
  await expect(dialog.getByRole("status").filter({ hasText: "Search results are unavailable for: missions" }))
    .toBeVisible();
  await expect(dialog.getByRole("option", {
    name: new RegExp(`^${escapeRegex(fixture.missionLabel)}.*Autonomous mission`, "u"),
  })).toHaveCount(0);

  await search.fill(fixture.runToken);
  await waitForPaletteSearch(dialog);
  await expect(dialog.getByRole("status").filter({ hasText: "Search results are unavailable for: runs" }))
    .toBeVisible();
  await expect(dialog.getByRole("option", {
    name: new RegExp(`^${escapeRegex(fixture.missionLabel)}.*Autonomous run`, "u"),
  })).toHaveCount(0);

  // Clearing the remote query proves that an authoritative local command
  // remains available after both remote domains degrade, without starting a
  // second asynchronous remote search whose completion is irrelevant here.
  await search.fill("");
  await waitForPaletteSearch(dialog);
  await expect(dialog.getByRole("option", {
    name: /^Observability.*Navigate to Observability$/u,
  })).toBeVisible();
  // The settled empty-query status above is the UI receipt. `assertClean`
  // immediately below independently rejects any in-flight required API work;
  // do not add a second quiet-period wait that can race the audited page's
  // fixture-owned close after the last browser assertion.
  await audit.assertClean(testInfo);
});

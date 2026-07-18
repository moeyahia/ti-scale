import { expect, test, type Page } from "./support/playwright";
import { readFileSync } from "node:fs";
import { validateInteractionManifest, type InteractionManifestEntry } from "../interaction-manifest/schema";

const manifestJson = JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown;
const manifest = validateInteractionManifest(manifestJson);
const NAVIGATION_TEST_ID = "e2e.shell.navigation";
const PALETTE_TEST_ID = "e2e.shell.command-palette";
const NOTIFICATION_TEST_ID = "e2e.shell.notifications";
const OVERVIEW_JOURNEY_TEST_ID = "e2e.overview.journey-entry";
const SELECTION_TEST_ID = "e2e.mission-journey.selection";

function nameMatcher(entry: InteractionManifestEntry): string | RegExp {
  return entry.accessible.match === "regex" ? new RegExp(entry.accessible.name) : entry.accessible.name;
}

async function openMobileNavigation(page: Page): Promise<void> {
  if ((page.viewportSize()?.width ?? 1440) > 820) return;
  await page.getByRole("button", { name: "Open navigation" }).click();
}

async function expectPath(page: Page, transition: string): Promise<void> {
  const expected = transition.replace(/^Navigate to /u, "");
  await expect.poll(() => new URL(page.url()).pathname).toBe(expected);
}

test.describe("manifested shell interactions", () => {
  const navigation = manifest.entries.filter((entry) => entry.id.startsWith("nav."));
  for (const entry of navigation) {
    test(`${NAVIGATION_TEST_ID} ${entry.id}`, async ({ page, browserAudit }) => {
      await page.goto(entry.route);
      await page.getByRole("heading", { level: 1 }).first().waitFor({ state: "visible" });
      await browserAudit.waitForPageApiSettlement(page);
      await openMobileNavigation(page);
      if (!entry.accessible.role) throw new Error(`Navigation manifest entry ${entry.id} is not role-addressable`);
      const control = page
        .getByLabel("Primary navigation")
        .getByRole(entry.accessible.role, { name: nameMatcher(entry), exact: entry.accessible.match === "exact" });
      await expect(control).toBeVisible();
      await control.click();
      await expectPath(page, entry.expectedStateTransition);
      await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
      await browserAudit.waitForPageApiSettlement(page);
    });
  }

  test(`${NAVIGATION_TEST_ID} product mark returns home`, async ({ page, browserAudit }) => {
    const entry = manifest.entries.find((item) => item.id === "shell.home")!;
    await page.goto(entry.route);
    await browserAudit.waitForPageApiSettlement(page);
    const link = page.getByRole("link", { name: entry.accessible.name, exact: true });
    await link.focus();
    await page.keyboard.press("Enter");
    await expectPath(page, entry.expectedStateTransition);
    await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
    await browserAudit.waitForPageApiSettlement(page);
  });

  test(`${PALETTE_TEST_ID} pointer and keyboard open, focus, and close`, async ({ page, browserAudit }) => {
    await page.goto("/manual");
    await browserAudit.waitForPageApiSettlement(page);
    const trigger = page.getByRole("button", { name: "Search or run a command", exact: true });
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: "Command palette" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("combobox")).toBeFocused();
    await browserAudit.waitForPageApiSettlement(page);
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
    await page.keyboard.press("Control+k");
    await expect(dialog).toBeVisible();
    await browserAudit.waitForPageApiSettlement(page);
    await page.keyboard.press("Escape");
    await expect(trigger).toBeFocused();
  });

  test(`${NOTIFICATION_TEST_ID} dialog restores focus after Escape`, async ({ page }) => {
    await page.goto("/manual");
    const trigger = page.getByRole("button", { name: /^Notifications, [0-9]+ unread$/u });
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: "In-app notifications" });
    await expect(dialog).toBeVisible();
    await expect(page.getByRole("button", { name: "Close notifications" })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(trigger).toBeFocused();
  });
});

test.describe("manifested two-journey entry", () => {
  for (const id of ["overview.compose-autonomous-contract", "overview.create-guided-mission"] as const) {
    test(`${OVERVIEW_JOURNEY_TEST_ID} ${id}`, async ({ page, browserAudit }) => {
      const entry = manifest.entries.find((item) => item.id === id)!;
      await page.goto(entry.route);
      const link = page.getByRole("link", { name: nameMatcher(entry), exact: true });
      await expect(link).toBeVisible();
      await link.click();
      await expectPath(page, entry.expectedStateTransition);
      await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
      await browserAudit.waitForPageApiSettlement(page);
    });
  }

  for (const id of ["journey-selection.autonomous", "journey-selection.guided"] as const) {
    test(`${SELECTION_TEST_ID} ${id}`, async ({ page, browserAudit }) => {
      const entry = manifest.entries.find((item) => item.id === id)!;
      await page.goto(entry.route);
      const link = page.getByRole("link", { name: nameMatcher(entry), exact: true });
      await link.focus();
      await page.keyboard.press("Enter");
      await expectPath(page, entry.expectedStateTransition);
      await expect(page.getByRole("heading", { level: 1 }).first()).toBeVisible();
      await browserAudit.waitForPageApiSettlement(page);
    });
  }
});

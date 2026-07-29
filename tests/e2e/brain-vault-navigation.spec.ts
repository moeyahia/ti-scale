import { expect, test, type Locator, type Page } from "./support/playwright";

const TEST_ID = "e2e.brain-vault.navigation";

const DESTINATIONS = [
  { label: "Home", href: "/brain", heading: "Second Brain" },
  { label: "Graph", href: "/brain/graph", heading: "Memory Graph" },
  { label: "Operator Preferences", href: "/brain/preferences", heading: "Operator Preferences" },
  { label: "Memory Inbox", href: "/brain/inbox", heading: "Memory Inbox" },
  { label: "Controls", href: "/brain/control", heading: "Memory Control Center" },
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

async function expectVault(page: Page): Promise<void> {
  await expect(page).toHaveURL("/brain/vault");
  await expect(page.getByRole("heading", { level: 1, name: "Obsidian Vault", exact: true })).toBeVisible();
  // Returning through browser history remounts the Vault data providers. Do
  // not leave the page again until the required policy preview has settled;
  // otherwise rapid navigation can cancel a canonical read and conceal a
  // genuine route-readiness race behind net::ERR_ABORTED.
  await expect(page.locator(".brain-attack-vault-preset")
    .getByRole("heading", { level: 2, name: "Ti-Scale Attack Knowledge Vault", exact: true }))
    .toBeVisible();
  const current = page.getByRole("navigation", { name: "Second Brain", exact: true })
    .getByRole("link", { name: "Obsidian Vault", exact: true });
  await expect(current).toHaveAttribute("href", "/brain/vault");
  await expect(current).toHaveAttribute("aria-current", "page");
}

test(`${TEST_ID} activates every Vault navigation option with pointer and keyboard without changing Vault scope`, async ({ page, browserAudit }) => {
  test.setTimeout(180_000);
  await page.goto("/brain/vault", { waitUntil: "domcontentloaded" });
  await expectVault(page);
  await browserAudit.waitForPageApiSettlement(page, { quietMs: 1_000 });

  for (const input of ["pointer", "keyboard"] as const) {
    for (const destination of DESTINATIONS) {
      const navigation = page.getByRole("navigation", { name: "Second Brain", exact: true });
      const link = navigation.getByRole("link", { name: destination.label, exact: true });
      await expect(link).toHaveAttribute("href", destination.href);
      await activate(link, input);
      await expect(page).toHaveURL(destination.href);
      await expect(page.getByRole("heading", { level: 1, name: destination.heading, exact: true })).toBeVisible();
      await browserAudit.waitForPageApiSettlement(page, { quietMs: 1_000 });
      await browserAudit.withExpectedHistoryTraversal(page, () => page.goBack({ waitUntil: "domcontentloaded" }));
      await expectVault(page);
      await browserAudit.waitForPageApiSettlement(page, { quietMs: 500 });
    }

    const current = page.getByRole("navigation", { name: "Second Brain", exact: true })
      .getByRole("link", { name: "Obsidian Vault", exact: true });
    await activate(current, input);
    await expectVault(page);
    await browserAudit.waitForPageApiSettlement(page, { quietMs: 1_000 });
  }
});

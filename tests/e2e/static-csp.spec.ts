import { expect, test } from "./support/playwright";
import {
  applicationStyleSourceDirective,
  WEBKIT_SCREENSHOT_SYNC_STYLE,
} from "../../server/security/ContentSecurityPolicy";

declare global {
  interface Window {
    __tiScaleCspProbe?: {
      readonly inlineStyleInsertions: string[];
      readonly violations: Array<{
        readonly blockedUri: string;
        readonly effectiveDirective: string;
        readonly violatedDirective: string;
      }>;
    };
  }
}

test("keeps the static Agents route CSP-clean while WebKit synchronizes a screenshot", async ({
  page,
}, testInfo) => {
  await page.addInitScript(() => {
    const probe = {
      inlineStyleInsertions: [] as string[],
      violations: [] as Array<{
        blockedUri: string;
        effectiveDirective: string;
        violatedDirective: string;
      }>,
    };
    window.__tiScaleCspProbe = probe;

    document.addEventListener("securitypolicyviolation", (event) => {
      probe.violations.push({
        blockedUri: event.blockedURI,
        effectiveDirective: event.effectiveDirective,
        violatedDirective: event.violatedDirective,
      });
    });

    new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (node instanceof HTMLStyleElement) {
            probe.inlineStyleInsertions.push(node.textContent ?? "");
          }
        }
      }
    }).observe(document, { childList: true, subtree: true });
  });

  const response = await page.goto("/agents", { waitUntil: "domcontentloaded" });
  expect(response?.status()).toBe(200);
  const contentSecurityPolicy = (await response?.allHeaders())?.["content-security-policy"];
  expect(contentSecurityPolicy).toContain(applicationStyleSourceDirective());
  expect(contentSecurityPolicy).not.toContain("'unsafe-inline'");
  await expect(page.getByRole("heading", { level: 1, name: "Agents", exact: true })).toBeVisible();
  await expect(page.locator("[style]")).toHaveCount(0);
  await expect(page.locator("style")).toHaveCount(0);

  await page.screenshot({ animations: "allow" });
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => resolve())));

  const diagnostics = await page.evaluate(() => window.__tiScaleCspProbe);
  expect(diagnostics).toBeDefined();
  expect(diagnostics?.violations).toEqual([]);
  expect(await page.locator("[style]").count()).toBe(0);
  expect(await page.locator("style").count()).toBe(0);

  if (testInfo.project.name.startsWith("webkit")) {
    expect(diagnostics?.inlineStyleInsertions).toContain(WEBKIT_SCREENSHOT_SYNC_STYLE);
  } else {
    expect(diagnostics?.inlineStyleInsertions).toEqual([]);
  }
});

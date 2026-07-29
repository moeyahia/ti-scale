import { expect, test, type Page } from "./support/playwright";

const TEST_ID = "e2e.boot-sequence";

interface BootFrameAudit {
  bootNodes: number;
  heroNodes: number;
  heroAssemblyStarts: number;
  phases: string[];
  heroOpacity: number[];
  cspViolations: string[];
}

async function installBootAudit(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const audit: BootFrameAudit = {
      bootNodes: 0,
      heroNodes: 0,
      heroAssemblyStarts: 0,
      phases: [],
      heroOpacity: [],
      cspViolations: [],
    };
    const instrumentedWindow = window as Window & { __tiBootFrameAudit?: BootFrameAudit };
    instrumentedWindow.__tiBootFrameAudit = audit;
    const seenBoots = new WeakSet<Element>();
    const seenHeroes = new WeakSet<Element>();
    const assembledHeroes = new WeakSet<Element>();

    const inspect = (root: ParentNode) => {
      const candidates = root instanceof Element ? [root, ...root.querySelectorAll("*")] : [...root.querySelectorAll("*")];
      for (const candidate of candidates) {
        if (candidate.matches("[data-ti-boot-sequence='startup']") && !seenBoots.has(candidate)) {
          seenBoots.add(candidate);
          audit.bootNodes += 1;
        }
        if (candidate.matches("[data-ti-module='hero']") && !seenHeroes.has(candidate)) {
          seenHeroes.add(candidate);
          audit.heroNodes += 1;
        }
      }
    };

    new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (node instanceof Element) inspect(node);
        }
        if (record.type === "attributes" && record.target instanceof HTMLElement) {
          const phase = record.target.dataset.tiBootPhase;
          if (phase && audit.phases.at(-1) !== phase) audit.phases.push(phase);
          if (
            record.target.matches("[data-ti-module='hero']")
            && record.target.dataset.tiPhase === "assembling"
            && !assembledHeroes.has(record.target)
          ) {
            assembledHeroes.add(record.target);
            audit.heroAssemblyStarts += 1;
          }
        }
      }
    }).observe(document, {
      attributes: true,
      attributeFilter: ["data-ti-boot-phase", "data-ti-phase"],
      childList: true,
      subtree: true,
    });

    document.addEventListener("securitypolicyviolation", (event) => {
      audit.cspViolations.push(`${event.violatedDirective}:${event.blockedURI}`);
    });

    let opacitySamples = 0;
    const sample = () => {
      const hero = document.querySelector<HTMLElement>("[data-ti-module='hero']");
      if (hero) {
        const opacity = Number.parseFloat(getComputedStyle(hero).opacity);
        if (Number.isFinite(opacity)) audit.heroOpacity.push(opacity);
      }
      opacitySamples += 1;
      const bootComplete = document.querySelector<HTMLElement>("[data-ti-boot-boundary='startup']")
        ?.dataset.tiBootPhase === "complete";
      if (!bootComplete && opacitySamples < 64) window.setTimeout(sample, 64);
    };
    window.setTimeout(sample, 0);
  });
}

async function readBootAudit(page: Page): Promise<BootFrameAudit> {
  return page.evaluate(() => (
    (window as Window & { __tiBootFrameAudit?: BootFrameAudit }).__tiBootFrameAudit ?? {
      bootNodes: 0,
      heroNodes: 0,
      heroAssemblyStarts: 0,
      phases: [],
      heroOpacity: [],
      cspViolations: [],
    }
  ));
}

function expectForwardOnlyPhases(phases: string[]): void {
  const order = new Map([
    ["orbiting", 0],
    ["aligning", 1],
    ["locked", 2],
    ["handoff", 3],
    ["complete", 4],
  ]);
  const ranks = phases.map((phase) => order.get(phase) ?? -1);
  expect(ranks.every((rank, index) => index === 0 || rank >= ranks[index - 1]!)).toBe(true);
}

test.describe(`${TEST_ID} first document boundary`, () => {
  test("forms once, hands to one hero without a 1→0→1 flash, and never replays on route change", async ({ page }) => {
    await installBootAudit(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    const boundary = page.locator("[data-ti-boot-boundary='startup']");
    const sequence = page.locator("[data-ti-boot-sequence='startup']");
    await expect(boundary).toHaveAttribute("data-ti-boot-sequence-count", "1");
    await expect(boundary).toHaveAttribute("data-ti-boot-phase", "complete", { timeout: 4_000 });
    await expect(sequence).toHaveCount(1);
    await expect(sequence).toHaveAttribute("hidden", "");
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await expect(page.locator("[data-ti-transformer-core='true']")).toHaveCount(1);
    await expect(page.locator("[data-ti-module='hero']")).toHaveCSS("opacity", "1");
    await page.waitForTimeout(180);

    const firstAudit = await readBootAudit(page);
    expect(firstAudit.bootNodes).toBe(1);
    expect(firstAudit.heroNodes).toBe(1);
    expect(firstAudit.heroAssemblyStarts).toBe(1);
    expect(firstAudit.phases).toContain("locked");
    expect(firstAudit.phases.at(-1)).toBe("complete");
    expectForwardOnlyPhases(firstAudit.phases);
    expect(firstAudit.cspViolations).toEqual([]);
    const firstOpaqueFrame = firstAudit.heroOpacity.findIndex((opacity) => opacity >= 0.98);
    expect(firstOpaqueFrame).toBeGreaterThanOrEqual(0);
    expect(firstAudit.heroOpacity.slice(firstOpaqueFrame).every((opacity) => opacity >= 0.95)).toBe(true);

    const boundaryHandle = await boundary.elementHandle();
    const missionLink = page.locator(".os-sidebar").getByRole("link", { name: "Missions", exact: true });
    const navigationTrigger = page.getByRole("button", { name: "Open navigation", exact: true });
    if (await navigationTrigger.isVisible()) {
      await navigationTrigger.click();
      await expect(navigationTrigger).toHaveAttribute("aria-expanded", "true");
    }
    await expect(missionLink).toBeVisible();
    await missionLink.click();
    await expect(page).toHaveURL(/\/missions$/u);
    await expect(page.getByRole("heading", { level: 1, name: "Missions", exact: true })).toBeVisible();
    expect(await boundaryHandle?.evaluate((element) => element.isConnected)).toBe(true);
    await expect(sequence).toHaveCount(1);
    await expect(sequence).toHaveAttribute("hidden", "");
    const routedAudit = await readBootAudit(page);
    expect(routedAudit.bootNodes).toBe(1);
    expectForwardOnlyPhases(routedAudit.phases);
    expect(routedAudit.cspViolations).toEqual([]);
  });

  test("starts already formed with reduced motion and exposes pending status without a focus trap", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
    await page.route("**/api/v2/auth/session", async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 450));
      await route.continue();
    });
    await installBootAudit(page);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    const boundary = page.locator("[data-ti-boot-boundary='startup']");
    const sequence = page.locator("[data-ti-boot-sequence='startup']");
    await expect(boundary).toHaveAttribute("data-ti-boot-phase", "locked");
    await expect(sequence.locator(".ti-boot-particle-mark__particle").first()).toHaveCSS("animation-name", "none");
    await expect(sequence.locator("[data-ti-boot-particle-mark='forming-core']")).toHaveAttribute(
      "data-ti-boot-particle-count",
      "152",
    );
    await expect(sequence.getByText("Command core formed · Startup still in progress", { exact: true })).toBeVisible();
    await expect(sequence.getByText(/elapsed · Next: Command Center/u)).toBeVisible();
    await expect(page.locator(".ti-boot-boundary__application")).toHaveAttribute("inert", "");
    expect(await page.evaluate(() => document.activeElement === document.body)).toBe(true);

    await expect(boundary).toHaveAttribute("data-ti-boot-phase", "complete", { timeout: 2_500 });
    await expect(sequence).toHaveCount(1);
    await expect(sequence).toHaveAttribute("hidden", "");
    await expect(page.getByRole("heading", { level: 1, name: "Command Center", exact: true })).toBeVisible();
    await expect(page.locator(".ti-boot-boundary__application")).not.toHaveAttribute("inert", "");
    const audit = await readBootAudit(page);
    expect(audit.bootNodes).toBe(1);
    expect(audit.phases.at(-1)).toBe("complete");
    expectForwardOnlyPhases(audit.phases);
    expect(audit.cspViolations).toEqual([]);
  });
});

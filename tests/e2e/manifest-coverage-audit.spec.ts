import { expect, test, type Page } from "./support/playwright";
import { readFileSync } from "node:fs";
import {
  interactionAccessibleLocator,
  validateInteractionManifest,
  type InteractionManifestEntry,
} from "../interaction-manifest/schema";
import { BrowserAudit } from "./support/browserAudit";
import { parseE2EProfile } from "./support/e2eProfile";
import { STATIC_ROUTE_CASES } from "./support/routes";
import { selectTitaniumOption } from "./support/titaniumSelect";

const TEST_ID = "e2e.manifest.coverage-audit";
const IPHONE_GRAPH_TEARDOWN_IMAGE = "/brand-v2/optimized/empty-brain-512.avif";
const MANIFEST_EMPTY_MISSION_SCOPE = "__manifest-coverage-empty-scope__";
const DEDICATED_RESEARCH_CAMPAIGN_STATE_ENTRY_IDS = new Set([
  "research.campaign-controls",
  "research.stop-reason",
  "research.stop-campaign",
]);
const DEDICATED_MATERIAL_STATE_TEST_ID_BY_ENTRY_ID = new Map([
  // The procedural renderer's healthy initial state cannot also expose its
  // precise unavailable-WebGL recovery action or an already-open fallback
  // panel. Its dedicated spec creates both states and traverses them. The
  // canvas itself is also owned there because renderer availability varies by
  // browser/host and must not be fabricated by the generic static crawl.
  ["particle-core.runtime-retry", "e2e.motion-lab.particle-core"],
  ["particle-core.field-close", "e2e.motion-lab.particle-core"],
  ["particle-core.canvas", "e2e.motion-lab.particle-core"],
  ["overview.particle-core", "e2e.overview.particle-core"],
  ["particle-module-transition.canvas", "e2e.motion-lab.particle-module-transition"],
  ["particle-module-transition.module-links", "e2e.motion-lab.particle-module-transition"],
  ["particle-module-transition.runtime-retry", "e2e.motion-lab.particle-module-transition"],
]);
// Use the same validated profile contract as Playwright configuration. A
// second ad-hoc environment variable here previously let a release-profile
// run report `enforced: false` even though its declared profile required
// complete manifest coverage.
const enforce = parseE2EProfile().enforceManifest;
const manifestJson = JSON.parse(readFileSync(new URL("../interaction-manifest.json", import.meta.url), "utf8")) as unknown;
const manifest = validateInteractionManifest(manifestJson);

const PROJECT_MANIFEST_MATRIX: Readonly<Record<string, { readonly browser: string; readonly viewport: string }>> = {
  "chromium-1440": { browser: "chromium", viewport: "1440x900" },
  "firefox-1440": { browser: "firefox", viewport: "1440x900" },
  "webkit-1440": { browser: "webkit", viewport: "1440x900" },
  "chromium-enterprise-1440": { browser: "chromium-enterprise", viewport: "1440x900" },
  "android-chromium-390": { browser: "android-chromium", viewport: "390x844" },
  "iphone-webkit-390": { browser: "iphone-webkit", viewport: "390x844" },
  "tablet-chromium-768": { browser: "tablet-chromium", viewport: "768x1024" },
  "chromium-360": { browser: "chromium", viewport: "360x800" },
  "chromium-1024": { browser: "chromium", viewport: "1024x768" },
  "chromium-1280": { browser: "chromium", viewport: "1280x800" },
  "chromium-1920": { browser: "chromium", viewport: "1920x1080" },
  "chromium-2560": { browser: "chromium", viewport: "2560x1440" },
  "chromium-200-percent-zoom": { browser: "chromium", viewport: "200%" },
};

interface RenderedControl {
  readonly route: string;
  readonly locator: string;
  readonly name: string;
  readonly tag: string;
  readonly href?: string;
  readonly disabled: boolean;
}

function routeMatches(pattern: string, concrete: string): boolean {
  const expected = new URL(pattern, "http://ti-scale.local");
  const actual = new URL(concrete, "http://ti-scale.local");
  // `/system` is a declared compatibility alias that renders the canonical
  // Connections surface without redirecting. Its dynamic controls therefore
  // satisfy the same manifest entries as `/system/connections`, while direct
  // `/system` entries continue to match normally.
  const actualPathname = actual.pathname === "/system" && expected.pathname === "/system/connections"
    ? "/system/connections"
    : actual.pathname;
  const expectedSegments = expected.pathname.split("/");
  const actualSegments = actualPathname.split("/");
  if (expectedSegments.length !== actualSegments.length) return false;
  if (!expectedSegments.every((segment, index) => segment.startsWith(":") || segment === actualSegments[index])) return false;
  for (const [key, value] of expected.searchParams) {
    const actualValue = actual.searchParams.get(key);
    if (actualValue === null || (!value.startsWith(":") && actualValue !== value)) return false;
  }
  return true;
}

function matches(entry: InteractionManifestEntry, control: RenderedControl): boolean {
  const global = entry.surface.startsWith("Global application shell") || entry.surface.startsWith("Primary navigation");
  if (!global && !routeMatches(entry.route, control.route)) return false;
  if (interactionAccessibleLocator(entry.accessible) !== control.locator) return false;
  return entry.accessible.match === "regex"
    ? new RegExp(entry.accessible.name).test(control.name)
    : entry.accessible.name === control.name;
}

async function controlsOnCurrentPage(page: Page, route: string): Promise<RenderedControl[]> {
  return page.locator('a[href], button, summary, input:not([type="hidden"]), select, textarea, [role="application"], [role="tab"], [role="menuitem"], [role="listbox"], [role="option"]').evaluateAll((elements, currentRoute) => {
    const normalized = (value: string | null | undefined) => (value ?? "").replace(/\s+/gu, " ").trim();
    const labelledBy = (element: Element) => normalized((element.getAttribute("aria-labelledby") ?? "")
      .split(/\s+/u)
      .filter(Boolean)
      .map((id) => document.getElementById(id)?.textContent ?? "")
      .join(" "));
    const labelText = (element: Element) => {
      if (!(element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement)) return "";
      const label = element.labels?.[0];
      if (!label) return "";
      // The accessible name of a labelled form control does not include the
      // embedded control's option/value subtree. Clone the label and remove
      // every labellable descendant before normalizing its human label. This
      // keeps the audit aligned with getByRole/getByLabel instead of producing
      // synthetic names such as `JourneyAllAutonomousGuided`.
      const clone = label.cloneNode(true) as HTMLLabelElement;
      clone.querySelectorAll("input, select, textarea, button").forEach((control) => control.remove());
      return normalized(clone.textContent);
    };
    return elements
      .filter((element) => {
        if (!(element instanceof HTMLElement) || element.offsetParent === null || element.getAttribute("aria-hidden") === "true") return false;
        const style = window.getComputedStyle(element);
        return style.display !== "none" && style.visibility !== "hidden";
      })
      .map((element) => {
        const explicitRole = element.getAttribute("role");
        const tag = element.tagName.toLocaleLowerCase("en-US");
        const inputType = element instanceof HTMLInputElement ? element.type : "";
        const locator = inputType === "date" || inputType === "datetime-local"
          ? "native-date-input"
          : inputType === "range"
            ? "slider"
          : explicitRole
            ?? (tag === "a" ? "link"
            : tag === "summary" ? "native-summary"
              : tag === "button" ? "button"
              : tag === "select" ? "combobox"
                : tag === "textarea" ? "textbox"
                  : inputType === "checkbox" || inputType === "radio" ? inputType
                    : tag === "input" ? "textbox" : tag);
        const name = normalized(element.getAttribute("aria-label"))
          || labelledBy(element)
          || labelText(element)
          || normalized(element.textContent)
          || normalized(element.getAttribute("title"))
          || normalized(element.getAttribute("placeholder"));
        return {
          route: currentRoute,
          locator,
          name,
          tag,
          href: element instanceof HTMLAnchorElement ? element.getAttribute("href") ?? undefined : undefined,
          disabled: element instanceof HTMLButtonElement || element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement
            ? element.disabled : false,
        };
      });
  }, route);
}

async function renderedControls(
  page: Page,
  route: string,
  audit: BrowserAudit,
  expectedPreNavigationOptionalImagePath?: string,
): Promise<RenderedControl[]> {
  // This generic crawl owns static controls. Fixture specs own interaction
  // coverage for returned Intelligence records, relationships, and cursor
  // pages. Pin these list reads to a valid, deliberately absent mission scope
  // so records accumulated by earlier release tests cannot leak into this
  // crawl and make its result order-dependent.
  const navigationRoute = [
    "/intelligence/evidence",
    "/intelligence/findings",
    "/intelligence/artifacts",
  ].includes(route)
    ? `${route}?missionId=${encodeURIComponent(MANIFEST_EMPTY_MISSION_SCOPE)}`
    : route;
  await audit.withExpectedDocumentNavigationTeardown(
    page,
    () => page.goto(navigationRoute, { waitUntil: "domcontentloaded" }),
    expectedPreNavigationOptionalImagePath ? { expectedPreNavigationOptionalImagePath } : undefined,
  );
  await page.getByRole("heading", { level: 1 }).first().waitFor({ state: "visible" });
  await audit.waitForPageApiSettlement(page);
  const controls = await controlsOnCurrentPage(page, route);
  if (route === "/manual") {
    const navigationTrigger = page.getByRole("button", { name: "Open navigation", exact: true });
    if (await navigationTrigger.isVisible()) {
      await navigationTrigger.click();
      await expect(page.getByRole("complementary", { name: "Primary navigation", exact: true })).toBeVisible();
      controls.push(...await controlsOnCurrentPage(page, route));
    }
  }
  return controls;
}

async function openVisibleDetails(page: Page): Promise<void> {
  for (let index = 0; index < 20; index += 1) {
    const summary = page.locator("details:not([open]) > summary:visible").first();
    if (await summary.count() === 0) return;
    await summary.click();
  }
  throw new Error("Mission intake contains more nested disclosures than the bounded coverage audit permits");
}

async function advanceIntake(page: Page, nextGroupName: string): Promise<void> {
  const resolved = page.waitForResponse((response) => response.url().endsWith("/api/v2/registries/intake/resolve") && response.request().method() === "POST");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  expect((await resolved).status()).toBe(200);
  await expect(page.getByRole("group", { name: nextGroupName, exact: true })).toBeVisible();
}

async function renderedIntakeControls(page: Page, route: string, audit: BrowserAudit): Promise<RenderedControl[]> {
  const journey = route.endsWith("/autonomous") ? "Autonomous" : "Guided";
  const controls: RenderedControl[] = [];
  await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(route, { waitUntil: "domcontentloaded" }));
  await expect(page.getByRole("group", { name: "Authorization and exact scope", exact: true })).toBeVisible();
  await openVisibleDetails(page);
  controls.push(...await controlsOnCurrentPage(page, route));
  if (journey === "Autonomous") {
    // The bounded destructive-policy state is intentionally available only
    // after the operator explicitly classifies the environment as disposable.
    // Keep the generic manifest crawl truthful by entering that represented
    // scope state instead of expecting a lab target checkbox under the safe
    // default `client_or_public` classification.
    await selectTitaniumOption(
      page.getByRole("combobox", { name: "Environment classification", exact: false }),
      "htb",
      "pointer",
    );
  }
  await page.getByLabel("Authorized targets or environment references", { exact: false }).fill(`lab:manifest-audit-${journey.toLocaleLowerCase("en-US")}`);
  await page.getByRole("checkbox", { name: /I confirm these targets/u }).check();
  await advanceIntake(page, "Outcome and collaboration");
  await openVisibleDetails(page);
  controls.push(...await controlsOnCurrentPage(page, route));
  await advanceIntake(page, journey === "Autonomous" ? "Autonomous operating contract" : "Guided proposal boundaries");
  await selectTitaniumOption(
    page.getByRole("combobox", { name: "Destructive-action policy", exact: false }),
    "bounded_lab_only",
    "pointer",
  );
  await page.getByRole("group", { name: "Named disposable lab targets", exact: true }).getByRole("checkbox").check();
  await openVisibleDetails(page);
  controls.push(...await controlsOnCurrentPage(page, route));
  if (journey === "Autonomous") {
    await advanceIntake(page, "Specialist team and execution readiness");
    controls.push(...await controlsOnCurrentPage(page, route));
    await advanceIntake(page, "Second Brain context");
    controls.push(...await controlsOnCurrentPage(page, route));
  }
  await advanceIntake(page, "Review the resolved mission");
  controls.push(...await controlsOnCurrentPage(page, route));
  return controls;
}

test(`${TEST_ID} discovers rendered controls and reports exact initial coverage accounting`, async ({ page }, testInfo) => {
  // This is a deterministic 29-route plus four-step intake traversal, not a
  // single-page assertion. Keep per-action expectations strict while giving
  // the complete mobile/WebKit audit an explicit end-to-end wall-clock bound.
  test.setTimeout(120_000);
  const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
  const controls: RenderedControl[] = [];
  for (const route of STATIC_ROUTE_CASES.filter((item) => !item.expectedPath)) {
    // Mobile WebKit can schedule the lazy empty-Brain AVIF from the old graph
    // document at the same instant this deliberate document crawl advances to
    // the inbox. Authorize only that exact page-bound, one-shot transition;
    // BrowserAudit still requires the exact Request identity, old-document
    // referrer, and observed replacement document request before accepting it.
    const expectedPreNavigationOptionalImagePath = testInfo.project.name === "iphone-webkit-390"
      && new URL(page.url()).pathname === "/brain/graph"
      && route.path === "/brain/inbox"
      ? IPHONE_GRAPH_TEARDOWN_IMAGE
      : undefined;
    controls.push(...await (["/missions/new/autonomous", "/missions/new/guided"].includes(route.path)
      ? renderedIntakeControls(page, route.path, audit)
      : renderedControls(page, route.path, audit, expectedPreNavigationOptionalImagePath)));
  }
  // `/learning` intentionally defaults to verified lessons. Research is a
  // material query-state surface with its own always-rendered ownership,
  // strategy, and bounded-draft controls, so crawl that canonical URL too.
  // Campaign stop controls remain owned by the dedicated mutation fixture
  // because they require a persisted nonterminal campaign.
  controls.push(...await renderedControls(page, "/learning?view=research", audit));
  await page.context().clearCookies();
  controls.push(...await renderedControls(page, "/", audit));

  const projectMatrix = PROJECT_MANIFEST_MATRIX[testInfo.project.name];
  if (!projectMatrix) throw new Error(`The manifest audit has no browser/viewport mapping for ${testInfo.project.name}`);
  const applicableEntries = manifest.entries.filter((entry) =>
    entry.browsers.includes(projectMatrix.browser) && entry.viewports.includes(projectMatrix.viewport));
  const unique = [...new Map(controls.map((control) => [`${control.route}|${control.locator}|${control.name}|${control.href ?? ""}`, control])).values()];
  const covered = unique.filter((control) => applicableEntries.some((entry) => matches(entry, control)));
  const missing = unique.filter((control) => !applicableEntries.some((entry) => matches(entry, control)));
  const unmatched = applicableEntries.filter((entry) => !unique.some((control) => matches(entry, control)));
  const unmatchedFixtureEntries = unmatched.filter((entry) =>
    entry.requiredState.startsWith("Fixture required:"));
  const unresolvedFixtureEntries = unmatchedFixtureEntries.filter((entry) =>
    entry.testIds.includes(TEST_ID));
  // An entry owned by a dedicated browser test is intentionally absent from
  // this generic static-state crawl even when its material state is described
  // without the legacy `Fixture required:` prefix. Test ownership, rather
  // than wording convention, is the durable source of truth.
  const dedicatedFixtureEntries = unmatched.filter((entry) =>
    entry.testIds.length > 0 && !entry.testIds.includes(TEST_ID));
  const dedicatedResearchCampaignStateEntries = unmatched.filter((entry) =>
    DEDICATED_RESEARCH_CAMPAIGN_STATE_ENTRY_IDS.has(entry.id)
    && entry.testIds.includes("e2e.research-lab.bounded-campaign-lifecycle")
    && !entry.testIds.includes(TEST_ID));
  const dedicatedMaterialStateEntries = unmatched.filter((entry) =>
    entry.testIds.includes(DEDICATED_MATERIAL_STATE_TEST_ID_BY_ENTRY_ID.get(entry.id) ?? "")
    && !entry.testIds.includes(TEST_ID));
  // Dedicated fixture specs own their exact rendered states, including static
  // routes such as Decisions and Intelligence lists. This generic crawl omits
  // only those dedicated groups; anything still assigned here remains stale.
  const stale = unmatched.filter((entry) =>
    !dedicatedFixtureEntries.includes(entry)
    && !dedicatedResearchCampaignStateEntries.includes(entry)
    && !dedicatedMaterialStateEntries.includes(entry));
  const report = {
    enforced: enforce,
    manifestEntries: manifest.entries.length,
    applicableManifestEntries: applicableEntries.length,
    renderedUniqueControls: unique.length,
    renderedControlsCovered: covered.length,
    renderedControlsMissing: missing.length,
    unresolvedFixtureEntryCount: unresolvedFixtureEntries.length,
    unresolvedFixtureEntries: unresolvedFixtureEntries.map((entry) => entry.id),
    staleManifestEntries: stale.map((entry) => entry.id),
    missing,
  };
  await testInfo.attach("interaction-manifest-coverage.json", {
    body: Buffer.from(JSON.stringify(report, null, 2)),
    contentType: "application/json",
  });
  expect(stale, JSON.stringify(report, null, 2)).toEqual([]);
  if (enforce) {
    expect(missing, JSON.stringify(report, null, 2)).toEqual([]);
    expect(unresolvedFixtureEntries, JSON.stringify(report, null, 2)).toEqual([]);
  }
  await audit.assertClean(testInfo);
});

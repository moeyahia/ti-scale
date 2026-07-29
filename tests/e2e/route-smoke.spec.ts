import { expect, test, type Page, type Request } from "./support/playwright";
import { BrowserAudit } from "./support/browserAudit";
import { isResolvedDocumentNavigationStatus } from "./support/browserAuditPolicy";
import {
  classifyGeneratedHrefNavigation,
  recognizedInternalPath,
  STATIC_ROUTE_CASES,
  type GeneratedHrefNavigationKind,
} from "./support/routes";

const TEST_ID = "e2e.route.smoke";

function isBoundedApiRequest(request: Request): boolean {
  const pathname = new URL(request.url()).pathname;
  return pathname.startsWith("/api/v2") && pathname !== "/api/v2/events/stream";
}

class RequiredApiTracker {
  private activeGeneration = 0;
  private awaitingGeneration: number | undefined;
  private readonly requestGeneration = new Map<Request, number>();
  private readonly pendingByGeneration = new Map<number, Set<Request>>();
  private readonly seenPathsByGeneration = new Map<number, Set<string>>();
  private readonly activityRevisionByGeneration = new Map<number, number>();

  private static readonly REQUIRED_SHELL_PATHS = [
    "/api/v2/notifications",
    "/api/v2/notifications/unread-count",
  ] as const;

  constructor(private readonly page: Page) {
    page.on("request", (request) => {
      if (request.isNavigationRequest() && request.frame() === page.mainFrame()) {
        if (this.awaitingGeneration !== undefined) {
          this.activeGeneration = this.awaitingGeneration;
          this.awaitingGeneration = undefined;
          this.bumpActivity(this.activeGeneration);
        }
        return;
      }
      if (!isBoundedApiRequest(request)) return;
      const generation = this.activeGeneration;
      if (generation === 0) return;
      this.requestGeneration.set(request, generation);
      const pending = this.pendingByGeneration.get(generation) ?? new Set<Request>();
      pending.add(request);
      this.pendingByGeneration.set(generation, pending);
      const seenPaths = this.seenPathsByGeneration.get(generation) ?? new Set<string>();
      seenPaths.add(new URL(request.url()).pathname);
      this.seenPathsByGeneration.set(generation, seenPaths);
      this.bumpActivity(generation);
    });
    const finish = (request: Request) => {
      const generation = this.requestGeneration.get(request);
      if (generation === undefined) return;
      this.pendingByGeneration.get(generation)?.delete(request);
      this.bumpActivity(generation);
      this.requestGeneration.delete(request);
    };
    page.on("requestfinished", finish);
    page.on("requestfailed", finish);
  }

  private bumpActivity(generation: number): void {
    this.activityRevisionByGeneration.set(
      generation,
      (this.activityRevisionByGeneration.get(generation) ?? 0) + 1,
    );
  }

  private requiredState(generation: number) {
    const pending = [...(this.pendingByGeneration.get(generation) ?? [])]
      .map((request) => request.url())
      .sort();
    const seenPaths = this.seenPathsByGeneration.get(generation) ?? new Set<string>();
    return {
      documentActivated: this.activeGeneration === generation && this.awaitingGeneration === undefined,
      pending,
      missingShellPaths: RequiredApiTracker.REQUIRED_SHELL_PATHS
        .filter((pathname) => !seenPaths.has(pathname)),
    };
  }

  beginNavigation(): number {
    if (this.awaitingGeneration !== undefined) {
      throw new Error(`Document generation ${this.awaitingGeneration} never began`);
    }
    const generation = this.activeGeneration + 1;
    this.awaitingGeneration = generation;
    this.pendingByGeneration.set(generation, new Set<Request>());
    this.seenPathsByGeneration.set(generation, new Set<string>());
    this.activityRevisionByGeneration.set(generation, 0);
    return generation;
  }

  async settle(route: string, generation: number): Promise<void> {
    // The heading may render before shell queries are scheduled. Bind requests
    // to one document generation, require the global shell queries to appear,
    // and then cross two browser paint frames plus one task boundary without
    // any generation activity. A late request changes the revision and
    // restarts the drain. This prevents navigation from cancelling required
    // work without charging every generated route a fixed quiet-period tax.
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      await expect.poll(
        () => this.requiredState(generation),
        {
          message: `Required route data must settle before leaving ${route}`,
          timeout: Math.max(1, deadline - Date.now()),
          intervals: [10, 20, 50, 100],
        },
      ).toEqual({ documentActivated: true, pending: [], missingShellPaths: [] });
      const revision = this.activityRevisionByGeneration.get(generation) ?? 0;
      await this.page.evaluate(() => new Promise<void>((resolve) => {
        let settled = false;
        const finish = (): void => {
          if (settled) return;
          settled = true;
          window.clearTimeout(fallback);
          window.setTimeout(resolve, 0);
        };
        // Headless Firefox can suppress requestAnimationFrame even while the
        // document is fully rendered. Preserve the two-paint fence when the
        // engine supplies frames, but never let that browser policy consume
        // the entire test timeout. The revision check below still rejects any
        // API activity scheduled before or during this bounded task fence.
        const fallback = window.setTimeout(finish, 250);
        requestAnimationFrame(() => requestAnimationFrame(finish));
      }));
      const stateAfterFence = this.requiredState(generation);
      if (
        revision === (this.activityRevisionByGeneration.get(generation) ?? 0) &&
        stateAfterFence.documentActivated &&
        stateAfterFence.pending.length === 0 &&
        stateAfterFence.missingShellPaths.length === 0
      ) return;
    }
    expect(
      { ...this.requiredState(generation), stableAcrossSchedulingFence: false },
      `Required route data must settle before leaving ${route}`,
    ).toEqual({
      documentActivated: true,
      pending: [],
      missingShellPaths: [],
      stableAcrossSchedulingFence: true,
    });
  }
}

async function settleDeferredParticleRuntime(page: Page): Promise<void> {
  const overviewField = page.locator("[data-ti-transformer-core='true']");
  if (await overviewField.count() === 1) {
    await expect.poll(
      () => overviewField.getAttribute("data-ti-particle-status"),
      { message: "The deferred Overview particle runtime must settle before document teardown", timeout: 20_000 },
    ).not.toBe("loading");
  }

  const reviewField = page.locator("main.particle-core-review, main.particle-module-transition");
  if (await reviewField.count() === 1) {
    await expect(
      reviewField.locator("canvas").or(reviewField.getByRole("alert")),
      "A particle review must finish loading or expose its precise fallback before document teardown",
    ).toBeVisible({ timeout: 20_000 });
  }
}

test.describe(`${TEST_ID} static route, console, network, and layout contract`, () => {
  for (const route of STATIC_ROUTE_CASES) {
    test(`${route.id} renders at ${route.path}`, async ({ page }, testInfo) => {
      // This suite owns route, API, console, link, and layout integrity. Keep
      // its document startup deterministic under parallel browser load; the
      // complete default-motion handoff is exercised independently by the
      // boot and mechanical-transition suites (including Firefox repeats).
      await page.emulateMedia({ reducedMotion: "reduce", colorScheme: "light" });
      const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
      const requiredApi = new RequiredApiTracker(page);
      const generation = requiredApi.beginNavigation();
      const response = await page.goto(route.path, { waitUntil: "domcontentloaded" });
      expect(response?.status(), "The document request itself must resolve").toBe(200);
      await expect(page.locator("main#ti-scale-content")).toBeVisible();
      await expect(page.locator("main#ti-scale-content h1").first()).toBeVisible();
      await expect(page.getByText("Command surface not found", { exact: true })).toHaveCount(0);
      if (route.expectedPath) await expect.poll(() => new URL(page.url()).pathname).toBe(route.expectedPath);
      await requiredApi.settle(route.path, generation);
      const overflow = await page.evaluate(() => ({
        clientWidth: document.documentElement.clientWidth,
        scrollWidth: document.documentElement.scrollWidth,
      }));
      expect(overflow.scrollWidth, `Unexpected horizontal overflow on ${route.path}`).toBeLessThanOrEqual(overflow.clientWidth + 1);
      await audit.assertClean(testInfo);
    });
  }

  test("every generated internal href belongs to the route contract", async ({ page }, testInfo) => {
    test.setTimeout(120_000);
    // This is an exhaustive document-navigation and href-integrity crawl, not
    // an animation test. Replaying the finite startup choreography for every
    // document would consume the entire pre-crawl budget before the generated
    // URL set is known. Reduced motion is a supported product state and makes
    // the route contract deterministic; default-motion behavior is covered by
    // the dedicated boot and mechanical-transition browser suites.
    await page.emulateMedia({ reducedMotion: "reduce" });
    const audit = new BrowserAudit(page, { allowEventStreamNavigationAbort: true });
    const requiredApi = new RequiredApiTracker(page);
    const hrefs = new Set<string>();
    for (const route of STATIC_ROUTE_CASES) {
      const generation = requiredApi.beginNavigation();
      await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(route.path, { waitUntil: "domcontentloaded" }));
      await page.locator("main#ti-scale-content h1").first().waitFor({ state: "visible" });
      await requiredApi.settle(route.path, generation);
      await settleDeferredParticleRuntime(page);
      const current = await page.locator("a[href]").evaluateAll((links) => links.map((link) => link.getAttribute("href") ?? ""));
      current.forEach((href) => hrefs.add(href));
    }
    const malformed = [...hrefs].filter((href) => !href || href.includes("undefined") || href.includes("null"));
    const unknown = [...hrefs].filter((href) => {
      if (!href.startsWith("/") || href.startsWith("/api/v2")) return false;
      return !recognizedInternalPath(new URL(href, "http://127.0.0.1").pathname);
    });
    await testInfo.attach("generated-internal-hrefs.json", {
      body: Buffer.from(JSON.stringify([...hrefs].sort(), null, 2)),
      contentType: "application/json",
    });
    expect(malformed).toEqual([]);
    expect(unknown).toEqual([]);

    const crawlableHrefs = [...hrefs].sort()
      .filter((href) => href.startsWith("/") && !href.startsWith("/api/v2"));
    const crawlTimeoutMs = Math.min(
      300_000,
      Math.max(120_000, 30_000 + (crawlableHrefs.length * 750)),
    );
    // The release fixture can legitimately expose hundreds of distinct deep
    // links. Keep exhaustive direct-navigation coverage bounded per generated
    // URL instead of silently truncating the data or applying one fixed suite
    // timeout regardless of the canonical route count.
    test.setTimeout(crawlTimeoutMs);
    await testInfo.attach("generated-internal-href-crawl-budget.json", {
      body: Buffer.from(JSON.stringify({
        generatedHrefCount: hrefs.size,
        crawlableHrefCount: crawlableHrefs.length,
        timeoutMs: crawlTimeoutMs,
      }, null, 2)),
      contentType: "application/json",
    });
    const crawled: Array<{
      href: string;
      navigationKind: GeneratedHrefNavigationKind;
      pathname: string;
      status: number | null;
    }> = [];
    for (const href of crawlableHrefs) {
      const target = new URL(href, page.url());
      const targetLocation = `${target.pathname}${target.search}${target.hash}`;
      const navigationKind = classifyGeneratedHrefNavigation(page.url(), target.href);
      let status: number | null = null;
      if (navigationKind === "document") {
        const generation = requiredApi.beginNavigation();
        const response = await audit.withExpectedDocumentNavigationTeardown(page, () => page.goto(
          targetLocation,
          { waitUntil: "domcontentloaded" },
        ));
        status = response?.status() ?? null;
        expect(
          isResolvedDocumentNavigationStatus(status),
          `Generated route ${href} must resolve its document (received HTTP ${String(status)})`,
        ).toBe(true);
        await requiredApi.settle(href, generation);
      } else if (navigationKind === "same-document") {
        let documentRequestUrl: string | undefined;
        const observeRequest = (request: Request): void => {
          if (request.isNavigationRequest() && request.frame() === page.mainFrame()) {
            documentRequestUrl = request.url();
          }
        };
        page.on("request", observeRequest);
        let response: Awaited<ReturnType<Page["goto"]>> | undefined;
        try {
          response = await page.goto(targetLocation, { waitUntil: "domcontentloaded" });
          await page.waitForTimeout(0);
        } finally {
          page.off("request", observeRequest);
        }
        expect(
          response,
          `Generated route ${href} is a same-document fragment transition and must not issue an HTTP document request`,
        ).toBeNull();
        expect(
          documentRequestUrl,
          `Generated route ${href} unexpectedly replaced the current document`,
        ).toBeUndefined();
      }
      crawled.push({ href, navigationKind, pathname: target.pathname, status });
      await expect.poll(
        () => {
          const current = new URL(page.url());
          return `${current.pathname}${current.search}${current.hash}`;
        },
        { message: `Generated route ${href} must preserve its exact path, query, and fragment` },
      ).toBe(targetLocation);
      await expect(page.locator("main#ti-scale-content h1").first(), `Generated route ${href} must render a named surface`).toBeVisible();
      await expect(page.getByText("Command surface not found", { exact: true }), `Generated route ${href} must be recognized`).toHaveCount(0);
      if (target.hash) {
        const fragmentId = decodeURIComponent(target.hash.slice(1));
        expect(
          await page.evaluate((id) => document.getElementById(id) !== null, fragmentId),
          `Generated route ${href} must point to an element in the rendered document`,
        ).toBe(true);
      }
      await settleDeferredParticleRuntime(page);
    }
    await testInfo.attach("generated-internal-href-crawl.json", {
      body: Buffer.from(JSON.stringify(crawled, null, 2)),
      contentType: "application/json",
    });
    await audit.assertClean(testInfo);
  });
});

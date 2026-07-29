import { expect, test } from "./support/playwright";
import {
  crossDocumentStaleEventSourceCloseCanary,
  hungPageCloseAuditCanary,
  hungRequestFinalizationCanary,
  immediatePageCloseRequestRaceCanary,
  inFlightRequestSealCanary,
  pageWorldUnavailableAuditCanary,
  rapidExplicitEventSourceCloseCanary,
  undeclaredDownloadCanary,
  unwrappedEventSourceNavigationCanary,
  unsolicitedPopupCanary,
} from "./support/browserAuditNegativeCanary";

const POPUP_PATH = "/api/v2/audit-canary/popup";
const EXPLICIT_STREAM_RUN_ID = "audit-canary-explicit-close";
const CANARY_HOST_PATH = "/audit-boundary/host";

test("e2e.audit-boundary.popup-initial-response captures a popup before its initial response", async ({
  browserAudit,
  context,
  page,
}) => {
  browserAudit.expectHttpResponse(page, {
    id: "audit-boundary.popup-initial-response",
    transport: "browser",
    method: "GET",
    pathname: POPUP_PATH,
    query: {},
    status: 503,
    occurrences: 1,
    reason: "Prove the context-scoped listener captures a popup's initial response before the page event.",
  });
  browserAudit.expectPopup(page, POPUP_PATH);
  await context.route(`**${CANARY_HOST_PATH}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><title>Browser audit canary host</title>",
  }));
  await context.route(`**${POPUP_PATH}`, async (route) => {
    await route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "audit_boundary_canary",
          humanMessage: "The isolated popup canary is intentionally unavailable.",
          retryable: true,
          category: "test_fixture",
          remediation: "Consume this exact prospective audit receipt.",
          traceId: "trace-audit-boundary-popup",
          timestamp: "2099-07-16T00:00:00.000Z",
        },
      }),
    });
  });
  await page.goto(CANARY_HOST_PATH, { waitUntil: "load" });
  const popupPromise = context.waitForEvent("page");
  const responsePromise = context.waitForEvent("response", (response) => new URL(response.url()).pathname === POPUP_PATH);
  await page.evaluate((path) => { window.open(path, "_blank", "noopener"); }, POPUP_PATH);
  const [popup, response] = await Promise.all([popupPromise, responsePromise]);
  expect(response.status()).toBe(503);
  await popup.waitForLoadState("domcontentloaded");
  await expect.poll(() => context.pages().length).toBe(2);
  await context.unroute(`**${POPUP_PATH}`);
  await context.unroute(`**${CANARY_HOST_PATH}`);
  // Leave the popup open deliberately. The audit lifecycle must seal and
  // close every page before it serializes the final receipt.
});

test("e2e.audit-boundary.event-source-explicit-close correlates the exact request, close receipt, and Firefox console", async ({
  page,
}) => {
  await page.route(`**${CANARY_HOST_PATH}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><title>Browser audit stream host</title>",
  }));
  await page.goto(CANARY_HOST_PATH, { waitUntil: "load" });
  const expected = `/api/v2/events/stream?runId=${encodeURIComponent(EXPLICIT_STREAM_RUN_ID)}&afterSequence=0`;
  const expectedUrl = new URL(expected, page.url()).href;
  const streamResponse = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === "GET" && `${url.pathname}${url.search}` === expected;
  });
  const streamRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return request.method() === "GET" && `${url.pathname}${url.search}` === expected;
  });
  await page.evaluate((url) => {
    const runtime = window as unknown as Window & { __auditCanaryEventSource?: EventSource };
    runtime.__auditCanaryEventSource = new EventSource(url, { withCredentials: true });
  }, expected);
  await streamRequest;
  expect((await streamResponse).status()).toBe(200);
  await page.evaluate(() => {
    const runtime = window as unknown as Window & { __auditCanaryEventSource?: EventSource };
    runtime.__auditCanaryEventSource?.close();
    delete runtime.__auditCanaryEventSource;
  });
  await expect.poll(() => page.evaluate(() => {
    const runtime = window as unknown as Window & {
      __tiScaleEventStreamCloseReceipts?: Array<{ url: string }>;
    };
    return runtime.__tiScaleEventStreamCloseReceipts?.map((receipt) => receipt.url) ?? [];
  })).toContain(expectedUrl);
  // Audit finalization proves the subsequent request terminal event and any
  // Firefox console echo correlate to this exact close receipt.
});

test("e2e.audit-boundary.page-world-unavailable keeps receipt reconciliation and teardown out of the page", async ({
  baseURL,
  browser,
}) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  await expect(pageWorldUnavailableAuditCanary(browser, baseURL)).resolves.toEqual({
    evaluateCalls: 0,
    pageClosed: true,
  });
});

test("e2e.audit-boundary.hung-page-close fails fast once and preserves ordinary request defects", async ({
  baseURL,
  browser,
}, testInfo) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  await expect(hungPageCloseAuditCanary(browser, baseURL, testInfo)).resolves.toEqual({
    closeCalls: 1,
    contextClosed: true,
    issues: [
      {
        kind: "pageerror",
        message: "Browser-audit audited-page-1 close exceeded the 2000ms deadline; this exact page will not be retried",
        method: undefined,
        url: new URL("/audit-boundary/hung-page-close-host", baseURL).href,
      },
      {
        kind: "requestfailed",
        message: "Browser audit detached with an unresolved request",
        method: "GET",
        url: new URL("/api/v2/audit-boundary/hung-page-close", baseURL).href,
      },
    ],
  });
});

test("e2e.audit-boundary.event-source-rapid-explicit-close joins the exact established request and lifecycle pair", async ({
  baseURL,
  browser,
  context,
}) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  const result = await rapidExplicitEventSourceCloseCanary(browser, baseURL, await context.storageState());
  const expectedFailure = {
    chromium: "net::ERR_ABORTED",
    firefox: "NS_ERROR_ABORT",
    webkit: "Load request cancelled",
  }[browser.browserType().name()];
  expect(result).toEqual({
    requestUrl: new URL(
      "/api/v2/events/stream?runId=audit-canary-rapid-close&afterSequence=0",
      baseURL,
    ).href,
    failureText: expectedFailure,
    pageClosed: true,
  });
});

test("e2e.audit-boundary.immediate-page-close resolves only the EventSource request emitted inside close", async ({
  baseURL,
  browser,
}, testInfo) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  await expect(immediatePageCloseRequestRaceCanary(browser, baseURL, testInfo)).resolves.toEqual({
    streamRequestUrl: new URL(
      "/api/v2/events/stream?runId=audit-canary-immediate-page-close&afterSequence=0",
      baseURL,
    ).href,
    ordinaryRequestIssue: {
      message: "Browser audit detached with an unresolved request",
      method: "GET",
      url: new URL("/api/v2/audit-boundary/immediate-page-close", baseURL).href,
    },
    pageClosed: true,
  });
});

test("e2e.audit-boundary.unwrapped-event-source-navigation-negative-canary rejects an unreceipted exact stream abort", async ({
  baseURL,
  browser,
  context,
}, testInfo) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  const messages = await unwrappedEventSourceNavigationCanary(
    browser,
    baseURL,
    await context.storageState(),
    testInfo,
  );
  expect(messages).toContainEqual(expect.stringContaining(
    "tracked EventSource request had no correlated close, navigation, or page-close receipt",
  ));
});

test("e2e.audit-boundary.cross-document-event-source-close-negative-canary rejects a stale exact-URL ordinal receipt", async ({
  baseURL,
  browser,
  context,
}, testInfo) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  const messages = await crossDocumentStaleEventSourceCloseCanary(
    browser,
    baseURL,
    await context.storageState(),
    testInfo,
  );
  expect(messages).toHaveLength(1);
  expect(messages.filter((message) => message.includes(
    "tracked EventSource request had no correlated close, navigation, or page-close receipt",
  ))).toHaveLength(1);
});

test("e2e.audit-boundary.unsolicited-popup-negative-canary rejects a popup without prospective opener authority", async ({
  baseURL,
  browser,
}) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  const messages = await unsolicitedPopupCanary(browser, baseURL);
  expect(messages).toContainEqual(expect.stringContaining("Unsolicited popup opened from an audited page"));
});

test("e2e.audit-boundary.undeclared-download-negative-canary rejects a successful undeclared download", async ({
  baseURL,
  browser,
}) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  const messages = await undeclaredDownloadCanary(browser, baseURL);
  expect(messages).toContainEqual(expect.stringContaining("Download was not prospectively declared for this page"));
});

test("e2e.audit-boundary.in-flight-request-seal waits for exact request identity and rejects late work", async ({
  baseURL,
  browser,
}, testInfo) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  await expect(inFlightRequestSealCanary(browser, baseURL, testInfo)).resolves.toEqual({
    waited: true,
    rejectedAfterSeal: true,
  });
});

test("e2e.audit-boundary.hung-request-negative-canary bounds finalization and records the exact request", async ({
  baseURL,
  browser,
}, testInfo) => {
  if (!baseURL) throw new Error("The browser-audit canary requires the configured V2 base URL");
  const messages = await hungRequestFinalizationCanary(browser, baseURL, testInfo);
  expect(messages).toContainEqual(expect.stringMatching(
    /^Audited API request api-request-1 exceeded the \d+ms browser-audit finalization drain$/u,
  ));
});

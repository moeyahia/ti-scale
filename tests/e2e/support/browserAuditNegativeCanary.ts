import type {
  APIRequestContext,
  APIResponse,
  Browser,
  BrowserContext,
  Download,
  Route,
  TestInfo,
} from "@playwright/test";
import { BrowserAuditSession, installBrowserAuditRuntimeInstrumentation } from "./browserAudit";

async function isolatedAudit(
  browser: Browser,
  storageState?: Awaited<ReturnType<BrowserContext["storageState"]>>,
): Promise<{
  readonly context: BrowserContext;
  readonly session: BrowserAuditSession;
}> {
  const context = await browser.newContext(storageState === undefined ? undefined : { storageState });
  await installBrowserAuditRuntimeInstrumentation(context);
  const session = BrowserAuditSession.forContext(context, { allowEventStreamNavigationAbort: true });
  return { context, session };
}

async function withCanaryDeadline<T>(operation: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} exceeded ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function pageWorldUnavailableAuditCanary(
  browser: Browser,
  baseUrl: string,
): Promise<{ readonly evaluateCalls: number; readonly pageClosed: boolean }> {
  const { context, session } = await isolatedAudit(browser);
  const hostPath = "/audit-boundary/unavailable-page-world-host";
  await context.route(`**${hostPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><title>Browser audit unavailable page-world host</title>",
  }));
  const page = await context.newPage();
  session.attach(page);
  await page.goto(new URL(hostPath, baseUrl).href, { waitUntil: "load" });
  const originalDescriptor = Object.getOwnPropertyDescriptor(page, "evaluate");
  let evaluateCalls = 0;
  Object.defineProperty(page, "evaluate", {
    configurable: true,
    value: () => {
      evaluateCalls += 1;
      return new Promise<never>(() => undefined);
    },
  });
  try {
    await withCanaryDeadline(session.assertObservedClean(), 2_000, "Browser-audit assertion");
    await withCanaryDeadline(session.closeAuditedPage(page), 2_000, "Browser-audit page teardown");
    return { evaluateCalls, pageClosed: page.isClosed() };
  } finally {
    if (originalDescriptor) Object.defineProperty(page, "evaluate", originalDescriptor);
    else delete (page as unknown as { evaluate?: unknown }).evaluate;
    session.dispose();
    await context.close().catch(() => undefined);
  }
}

export async function hungPageCloseAuditCanary(
  browser: Browser,
  baseUrl: string,
  testInfo: TestInfo,
): Promise<{
  readonly closeCalls: number;
  readonly contextClosed: boolean;
  readonly issues: ReadonlyArray<{
    readonly kind: string;
    readonly message: string;
    readonly method: string | undefined;
    readonly url: string | undefined;
  }>;
}> {
  const { context, session } = await isolatedAudit(browser);
  const hostPath = "/audit-boundary/hung-page-close-host";
  const ordinaryPath = "/api/v2/audit-boundary/hung-page-close";
  const expectedHostUrl = new URL(hostPath, baseUrl).href;
  const expectedOrdinaryUrl = new URL(ordinaryPath, baseUrl).href;
  let releaseOrdinaryRequest!: () => void;
  const ordinaryRequestHeld = new Promise<void>((resolve) => { releaseOrdinaryRequest = resolve; });
  let resolveOrdinaryRouteEntered!: () => void;
  const ordinaryRouteEntered = new Promise<void>((resolve) => { resolveOrdinaryRouteEntered = resolve; });
  await context.route(`**${hostPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><title>Hung page-close host</title>",
  }));
  await context.route(`**${ordinaryPath}`, async (route) => {
    resolveOrdinaryRouteEntered();
    await ordinaryRequestHeld;
    await route.abort().catch(() => undefined);
  });
  const page = await context.newPage();
  session.attach(page);
  await page.goto(expectedHostUrl, { waitUntil: "load" });
  const ordinaryRequest = context.waitForEvent("request", (request) => request.url() === expectedOrdinaryUrl);
  await page.evaluate((url) => { void fetch(url).catch(() => undefined); }, ordinaryPath);
  await withCanaryDeadline(
    Promise.all([ordinaryRequest, ordinaryRouteEntered]),
    2_000,
    "Hung-close ordinary API request",
  );
  const originalCloseDescriptor = Object.getOwnPropertyDescriptor(page, "close");
  let closeCalls = 0;
  let contextClosed = false;
  Object.defineProperty(page, "close", {
    configurable: true,
    value: (): Promise<void> => {
      closeCalls += 1;
      return new Promise<void>(() => undefined);
    },
  });
  try {
    await withCanaryDeadline(
      session.closeAuditedPage(page),
      3_000,
      "Hung browser-audit page close",
    );
    try {
      await session.finalize(testInfo);
      throw new Error("A hung page close incorrectly passed browser-audit finalization");
    } catch (error) {
      const issues = session.unexpected.map((issue) => ({
        kind: issue.kind,
        message: issue.message,
        method: issue.method,
        url: issue.url,
      }));
      const closeIssues = issues.filter((issue) => (
        issue.kind === "pageerror"
        && issue.url === expectedHostUrl
        && issue.message === "Browser-audit audited-page-1 close exceeded the 2000ms deadline; this exact page will not be retried"
      ));
      const ordinaryIssues = issues.filter((issue) => (
        issue.kind === "requestfailed"
        && issue.url === expectedOrdinaryUrl
        && issue.method === "GET"
        && issue.message === "Browser audit detached with an unresolved request"
      ));
      if (closeCalls !== 1 || issues.length !== 2 || closeIssues.length !== 1 || ordinaryIssues.length !== 1) {
        throw error;
      }
      releaseOrdinaryRequest();
      session.dispose();
      await withCanaryDeadline(context.close(), 2_000, "Context teardown after hung page close");
      contextClosed = page.isClosed() && context.pages().length === 0;
      return { closeCalls, contextClosed, issues };
    }
  } finally {
    releaseOrdinaryRequest();
    if (originalCloseDescriptor) Object.defineProperty(page, "close", originalCloseDescriptor);
    else delete (page as unknown as { close?: unknown }).close;
    session.dispose();
    if (!contextClosed) await context.close().catch(() => undefined);
  }
}

export async function rapidExplicitEventSourceCloseCanary(
  browser: Browser,
  baseUrl: string,
  storageState: Awaited<ReturnType<BrowserContext["storageState"]>>,
): Promise<{
  readonly requestUrl: string;
  readonly failureText: string;
  readonly pageClosed: boolean;
}> {
  const { context, session } = await isolatedAudit(browser, storageState);
  const hostPath = "/audit-boundary/rapid-event-source-close-host";
  const streamPath = "/api/v2/events/stream?runId=audit-canary-rapid-close&afterSequence=0";
  const expectedStreamUrl = new URL(streamPath, baseUrl).href;
  await context.route(`**${hostPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: `<!doctype html>
      <button id="rapid-close" type="button">Open and close stream</button>
      <script>
        document.getElementById("rapid-close").addEventListener("click", () => {
          const stream = new EventSource(${JSON.stringify(streamPath)}, { withCredentials: true });
          setTimeout(() => stream.close(), 250);
        });
      </script>`,
  }));
  const page = await context.newPage();
  session.attach(page);
  try {
    await page.goto(new URL(hostPath, baseUrl).href, { waitUntil: "load" });
    const request = withCanaryDeadline(
      context.waitForEvent("request", (candidate) => candidate.url() === expectedStreamUrl),
      7_000,
      "Rapid-close EventSource request",
    );
    const failure = withCanaryDeadline(
      context.waitForEvent("requestfailed", (candidate) => candidate.url() === expectedStreamUrl),
      7_000,
      "Rapid-close EventSource failure",
    );
    await page.locator("#rapid-close").click();
    const [observedRequest, observedFailure] = await Promise.all([request, failure]);
    await withCanaryDeadline(session.assertObservedClean(), 2_000, "Rapid-close browser-audit assertion");
    await withCanaryDeadline(session.closeAuditedPage(page), 2_000, "Rapid-close browser-audit page teardown");
    return {
      requestUrl: observedRequest.url(),
      failureText: observedFailure.failure()?.errorText ?? "",
      pageClosed: page.isClosed(),
    };
  } finally {
    if (!page.isClosed()) await session.closeAuditedPage(page).catch(() => undefined);
    session.dispose();
    await context.close().catch(() => undefined);
  }
}

export async function immediatePageCloseRequestRaceCanary(
  browser: Browser,
  baseUrl: string,
  testInfo: TestInfo,
): Promise<{
  readonly streamRequestUrl: string;
  readonly ordinaryRequestIssue: {
    readonly message: string;
    readonly method: string | undefined;
    readonly url: string | undefined;
  };
  readonly pageClosed: boolean;
}> {
  const { context, session } = await isolatedAudit(browser);
  const hostPath = "/audit-boundary/immediate-page-close-request-race-host";
  const streamPath = "/api/v2/events/stream?runId=audit-canary-immediate-page-close&afterSequence=0";
  const ordinaryPath = "/api/v2/audit-boundary/immediate-page-close";
  const expectedStreamUrl = new URL(streamPath, baseUrl).href;
  const expectedOrdinaryUrl = new URL(ordinaryPath, baseUrl).href;
  let releaseHeldRequests!: () => void;
  const heldRequests = new Promise<void>((resolve) => { releaseHeldRequests = resolve; });
  let heldRouteCount = 0;
  let resolveBothRoutesHeld!: () => void;
  const bothRoutesHeld = new Promise<void>((resolve) => { resolveBothRoutesHeld = resolve; });
  const holdUntilPageClose = async (route: Route): Promise<void> => {
    heldRouteCount += 1;
    if (heldRouteCount === 2) resolveBothRoutesHeld();
    await heldRequests;
    await route.abort().catch(() => undefined);
  };
  await context.route(`**${hostPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><title>Immediate page-close request race host</title>",
  }));
  await context.route(`**${streamPath}`, holdUntilPageClose);
  await context.route(`**${ordinaryPath}`, holdUntilPageClose);
  const page = await context.newPage();
  session.attach(page);
  await page.goto(new URL(hostPath, baseUrl).href, { waitUntil: "load" });
  const nativeClose = page.close.bind(page);
  const originalCloseDescriptor = Object.getOwnPropertyDescriptor(page, "close");
  let streamRequestUrl: string | undefined;
  let closeInjectionRan = false;
  // This canary-only hook places both requests after closeAuditedPage's first
  // snapshot, but before the native page-close receipt resolves.
  Object.defineProperty(page, "close", {
    configurable: true,
    value: async (...args: Parameters<typeof nativeClose>): Promise<void> => {
      if (!closeInjectionRan) {
        closeInjectionRan = true;
        const streamRequest = withCanaryDeadline(
          context.waitForEvent("request", (request) => request.url() === expectedStreamUrl),
          2_000,
          "Immediate-close EventSource request",
        );
        const ordinaryRequest = withCanaryDeadline(
          context.waitForEvent("request", (request) => request.url() === expectedOrdinaryUrl),
          2_000,
          "Immediate-close ordinary API request",
        );
        await page.evaluate(({ ordinaryUrl, streamUrl }) => {
          const runtime = window as unknown as Window & { __auditImmediateCloseStream?: EventSource };
          runtime.__auditImmediateCloseStream = new EventSource(streamUrl);
          void fetch(ordinaryUrl).catch(() => undefined);
        }, { ordinaryUrl: ordinaryPath, streamUrl: streamPath });
        const [observedStream] = await Promise.all([
          streamRequest,
          ordinaryRequest,
          withCanaryDeadline(bothRoutesHeld, 2_000, "Immediate-close held request routes"),
        ]);
        streamRequestUrl = observedStream.url();
      }
      await nativeClose(...args);
    },
  });
  try {
    await withCanaryDeadline(
      session.closeAuditedPage(page),
      3_000,
      "Immediate-close browser-audit page teardown",
    );
    releaseHeldRequests();
    try {
      await session.finalize(testInfo);
      throw new Error("Immediate page close incorrectly waived the ordinary API request");
    } catch (error) {
      const ordinaryIssues = session.unexpected.filter((issue) => issue.url === expectedOrdinaryUrl);
      const streamIssues = session.unexpected.filter((issue) => issue.url === expectedStreamUrl);
      if (
        streamRequestUrl !== expectedStreamUrl
        || !page.isClosed()
        || session.unexpected.length !== 1
        || ordinaryIssues.length !== 1
        || ordinaryIssues[0]?.method !== "GET"
        || streamIssues.length !== 0
      ) throw error;
      const ordinaryIssue = ordinaryIssues[0]!;
      return {
        streamRequestUrl,
        ordinaryRequestIssue: {
          message: ordinaryIssue.message,
          method: ordinaryIssue.method,
          url: ordinaryIssue.url,
        },
        pageClosed: true,
      };
    }
  } finally {
    releaseHeldRequests();
    if (originalCloseDescriptor) Object.defineProperty(page, "close", originalCloseDescriptor);
    else delete (page as unknown as { close?: unknown }).close;
    session.dispose();
    await context.close().catch(() => undefined);
  }
}

export async function unsolicitedPopupCanary(browser: Browser, baseUrl: string): Promise<readonly string[]> {
  const { context, session } = await isolatedAudit(browser);
  const hostPath = "/audit-boundary/negative-popup-host";
  const popupPath = "/audit-boundary/negative-popup-target";
  await context.route(`**${hostPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><button id='open-popup'>Open</button><script>document.getElementById('open-popup').addEventListener('click',()=>window.open('/audit-boundary/negative-popup-target','_blank'))</script>",
  }));
  await context.route(`**${popupPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><title>Undeclared popup</title>",
  }));
  const page = await context.newPage();
  session.attach(page);
  try {
    await page.goto(new URL(hostPath, baseUrl).href, { waitUntil: "load" });
    const popup = page.waitForEvent("popup");
    await page.locator("#open-popup").click();
    const opened = await popup;
    await opened.waitForLoadState("load");
    await opened.close();
    return session.unexpected.map((issue) => issue.message);
  } finally {
    session.dispose();
    await context.close().catch(() => undefined);
  }
}

export async function undeclaredDownloadCanary(browser: Browser, baseUrl: string): Promise<readonly string[]> {
  const { context, session } = await isolatedAudit(browser);
  const hostPath = "/audit-boundary/negative-download-host";
  await context.route(`**${hostPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><button id='download'>Download</button><script>document.getElementById('download').addEventListener('click',()=>{const url=URL.createObjectURL(new Blob(['undeclared download canary'],{type:'application/octet-stream'}));const link=document.createElement('a');link.href=url;link.download='undeclared-canary.bin';link.click();URL.revokeObjectURL(url)})</script>",
  }));
  const page = await context.newPage();
  session.attach(page);
  try {
    await page.goto(new URL(hostPath, baseUrl).href, { waitUntil: "load" });
    const download = page.waitForEvent("download");
    await page.locator("#download").click();
    await expectSuccessfulDownload(await download);
    return session.unexpected.map((issue) => issue.message);
  } finally {
    session.dispose();
    await context.close().catch(() => undefined);
  }
}

export async function sameUrlWrongPageDownloadCanary(
  browser: Browser,
  baseUrl: string,
  options: {
    readonly attachmentPath?: string;
    readonly storageState?: Awaited<ReturnType<BrowserContext["storageState"]>>;
    readonly requireSuccessfulDownload?: boolean;
  } = {},
): Promise<readonly string[]> {
  const { context, session } = await isolatedAudit(browser, options.storageState);
  const hostPath = "/audit-boundary/wrong-page-download-host";
  const attachmentPath = options.attachmentPath ?? "/api/v2/audit-boundary/wrong-page-download.bin";
  await context.route(`**${hostPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: `<!doctype html><a id="download" download href="${attachmentPath}">Download</a>`,
  }));
  const authorizedPage = await context.newPage();
  const wrongPage = await context.newPage();
  session.attach(authorizedPage);
  session.attach(wrongPage);
  try {
    await Promise.all([
      authorizedPage.goto(new URL(hostPath, baseUrl).href, { waitUntil: "load" }),
      wrongPage.goto(new URL(hostPath, baseUrl).href, { waitUntil: "load" }),
    ]);
    session.expectVerifiedDownload(authorizedPage, attachmentPath);
    const downloadEvent = wrongPage.waitForEvent("download");
    await wrongPage.locator("#download").click();
    const download = await downloadEvent;
    const expectedUrl = new URL(attachmentPath, baseUrl).href;
    if (download.url() !== expectedUrl) {
      throw new Error(`The wrong-page canary observed ${download.url()} instead of ${expectedUrl}`);
    }
    if (options.requireSuccessfulDownload) await expectSuccessfulDownload(download);
    else await download.failure();
    return session.unexpected.map((issue) => issue.message);
  } finally {
    session.dispose();
    await context.close().catch(() => undefined);
  }
}

export async function unwrappedEventSourceNavigationCanary(
  browser: Browser,
  baseUrl: string,
  storageState: Awaited<ReturnType<BrowserContext["storageState"]>>,
  testInfo: TestInfo,
): Promise<readonly string[]> {
  const { context, session } = await isolatedAudit(browser, storageState);
  const firstPath = "/audit-boundary/unwrapped-navigation-stream-host";
  const secondPath = "/audit-boundary/unwrapped-navigation-destination";
  const streamPath = "/api/v2/events/stream?runId=audit-canary-unwrapped-navigation&afterSequence=0";
  await context.route(`**${firstPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><title>Unwrapped navigation stream host</title>",
  }));
  await context.route(`**${secondPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><title>Unwrapped navigation destination</title>",
  }));
  const page = await context.newPage();
  session.attach(page);
  try {
    await page.goto(new URL(firstPath, baseUrl).href, { waitUntil: "load" });
    const exactStreamUrl = new URL(streamPath, baseUrl).href;
    const streamRequestPromise = page.waitForRequest((request) => (
      request.method() === "GET" && request.url() === exactStreamUrl
    ));
    const streamResponsePromise = page.waitForResponse((response) => (
      response.request().method() === "GET" && response.url() === exactStreamUrl
    ));
    await page.evaluate((url) => {
      const runtime = window as unknown as Window & { __auditUnwrappedNavigationStream?: EventSource };
      runtime.__auditUnwrappedNavigationStream = new EventSource(url, { withCredentials: true });
    }, exactStreamUrl);
    const streamRequest = await streamRequestPromise;
    if ((await streamResponsePromise).status() !== 200) {
      throw new Error("The unwrapped-navigation canary did not establish its exact EventSource request");
    }
    const failedRequestPromise = page.waitForEvent("requestfailed", (request) => request === streamRequest);
    // This is deliberately not wrapped. The negative canary proves an exact
    // old-document EventSource abort remains a defect without a prospective
    // navigation boundary, even when URL, page, and request are otherwise known.
    await page.goto(new URL(secondPath, baseUrl).href, { waitUntil: "load" });
    if (await failedRequestPromise !== streamRequest) {
      throw new Error("The unwrapped-navigation canary did not observe the exact EventSource request failure");
    }
    try {
      await session.finalize(testInfo);
      throw new Error("An unwrapped document navigation incorrectly passed browser-audit finalization");
    } catch (error) {
      const messages = session.unexpected.map((issue) => issue.message);
      if (!messages.some((message) => message.includes(
        "tracked EventSource request had no correlated close, navigation, or page-close receipt",
      ))) throw error;
      return messages;
    }
  } finally {
    session.dispose();
    await context.close().catch(() => undefined);
  }
}

export async function crossDocumentStaleEventSourceCloseCanary(
  browser: Browser,
  baseUrl: string,
  storageState: Awaited<ReturnType<BrowserContext["storageState"]>>,
  testInfo: TestInfo,
): Promise<readonly string[]> {
  const { context, session } = await isolatedAudit(browser, storageState);
  const firstPath = "/audit-boundary/cross-document-stream-source";
  const secondPath = "/audit-boundary/cross-document-stream-destination";
  const streamPath = "/api/v2/events/stream?runId=audit-canary-cross-document&afterSequence=0";
  const exactStreamUrl = new URL(streamPath, baseUrl).href;
  await context.route(`**${firstPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: `<!doctype html>
      <button id="replace-document" type="button">Replace document</button>
      <script>
        const oldDocumentStream = new EventSource(${JSON.stringify(streamPath)});
        document.getElementById("replace-document").addEventListener("click", () => {
          oldDocumentStream.close();
          location.assign(${JSON.stringify(secondPath)});
        });
      </script>`,
  }));
  await context.route(`**${secondPath}`, (route) => route.fulfill({
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: `<!doctype html>
      <title>Cross-document stream destination</title>
      <script>
        const NativeEventSource = Object.getPrototypeOf(window.EventSource);
        window.__auditNativeCrossDocumentStream = new NativeEventSource(${JSON.stringify(streamPath)});
      </script>`,
  }));
  const page = await context.newPage();
  session.attach(page);
  try {
    const firstRequestPromise = context.waitForEvent("request", (request) => request.url() === exactStreamUrl);
    const firstResponsePromise = context.waitForEvent("response", (response) => response.url() === exactStreamUrl);
    await page.goto(new URL(firstPath, baseUrl).href, { waitUntil: "load" });
    const firstRequest = await withCanaryDeadline(
      firstRequestPromise,
      3_000,
      "Old-document wrapped EventSource request",
    );
    const firstResponse = await withCanaryDeadline(
      firstResponsePromise,
      3_000,
      "Old-document wrapped EventSource response",
    );
    if (firstResponse.request() !== firstRequest || firstResponse.status() !== 200) {
      throw new Error("Old-document EventSource did not establish its exact 200 response");
    }
    const firstFailurePromise = context.waitForEvent("requestfailed", (request) => request === firstRequest);
    const secondRequestPromise = context.waitForEvent("request", (request) => (
      request !== firstRequest && request.url() === exactStreamUrl
    ));
    const secondResponsePromise = context.waitForEvent("response", (response) => (
      response.request() !== firstRequest && response.url() === exactStreamUrl
    ));
    await Promise.all([
      page.waitForURL(new URL(secondPath, baseUrl).href, { waitUntil: "load" }),
      page.locator("#replace-document").click(),
    ]);
    const secondRequest = await withCanaryDeadline(
      secondRequestPromise,
      3_000,
      "New-document unwrapped EventSource request",
    );
    const secondResponse = await withCanaryDeadline(
      secondResponsePromise,
      3_000,
      "New-document unwrapped EventSource response",
    );
    if (secondResponse.request() !== secondRequest || secondResponse.status() !== 200) {
      throw new Error("New-document EventSource did not establish its exact 200 response");
    }
    const secondFailurePromise = context.waitForEvent("requestfailed", (request) => request === secondRequest);
    await page.evaluate(() => {
      const runtime = window as unknown as Window & { __auditNativeCrossDocumentStream?: EventSource };
      runtime.__auditNativeCrossDocumentStream?.close();
      delete runtime.__auditNativeCrossDocumentStream;
    });
    await withCanaryDeadline(
      Promise.all([firstFailurePromise, secondFailurePromise]),
      3_000,
      "Cross-document EventSource failures",
    );
    try {
      await session.finalize(testInfo);
      throw new Error("A stale old-document EventSource close receipt incorrectly authorized the new document request");
    } catch (error) {
      const messages = session.unexpected.map((issue) => issue.message);
      const unreceipted = messages.filter((message) => message.includes(
        "tracked EventSource request had no correlated close, navigation, or page-close receipt",
      ));
      if (messages.length !== 1 || unreceipted.length !== 1) throw error;
      return messages;
    }
  } finally {
    session.dispose();
    await context.close().catch(() => undefined);
  }
}

async function expectSuccessfulDownload(download: Download): Promise<void> {
  // The event itself is the browser's successful download initiation receipt;
  // the canary intentionally avoids saving or retaining the payload.
  if (await download.failure() !== null) {
    throw new Error("The undeclared-download canary did not produce the expected browser Download identity");
  }
}

export async function inFlightRequestSealCanary(
  browser: Browser,
  baseUrl: string,
  testInfo: TestInfo,
): Promise<{ readonly waited: boolean; readonly rejectedAfterSeal: boolean }> {
  const { context, session } = await isolatedAudit(browser);
  const page = await context.newPage();
  session.attach(page);
  let resolveFetch!: (response: APIResponse) => void;
  const response = new Promise<APIResponse>((resolve) => { resolveFetch = resolve; });
  const api = {
    fetch: () => response,
  } as unknown as APIRequestContext;
  const exactUrl = new URL("/api/v2/audit-boundary/in-flight", baseUrl).href;
  const pending = session.request(api, { method: "GET", url: exactUrl });
  let finalized = false;
  const finalization = session.finalize(testInfo).then(() => { finalized = true; });
  await Promise.resolve();
  const waited = !finalized;
  let rejectedAfterSeal = false;
  try {
    session.request(api, { method: "GET", url: exactUrl });
  } catch (error) {
    rejectedAfterSeal = error instanceof Error && error.message.includes("after browser-audit sealing");
  }
  resolveFetch({
    url: () => exactUrl,
    status: () => 200,
    statusText: () => "OK",
  } as APIResponse);
  await pending;
  await finalization;
  session.dispose();
  await context.close();
  return { waited, rejectedAfterSeal };
}

export async function hungRequestFinalizationCanary(
  browser: Browser,
  baseUrl: string,
  testInfo: TestInfo,
): Promise<readonly string[]> {
  const { context, session } = await isolatedAudit(browser);
  const page = await context.newPage();
  session.attach(page);
  const api = {
    fetch: () => new Promise<APIResponse>(() => undefined),
  } as unknown as APIRequestContext;
  const exactUrl = new URL("/api/v2/audit-boundary/hung", baseUrl).href;
  void session.request(api, { method: "GET", url: exactUrl });
  try {
    await session.finalize(testInfo);
    throw new Error("A hung audited API request incorrectly passed finalization");
  } catch (error) {
    if (!(error instanceof Error) || !session.unexpected.some((issue) => issue.message.includes("finalization drain"))) {
      throw error;
    }
    return session.unexpected.map((issue) => issue.message);
  } finally {
    session.dispose();
    await context.close().catch(() => undefined);
  }
}

export type BrowserIssueKind = "console" | "pageerror" | "requestfailed" | "response";

export interface BrowserIssueLike {
  readonly kind: BrowserIssueKind;
  readonly message: string;
  readonly url?: string;
  readonly method?: string;
}

export type HistoryTraversalReceipt = "missing" | "same-document" | "document-request";

/**
 * Classifies the independently observed browser receipts for a history
 * traversal. Engines may restore a same-URL history entry through a real
 * main-frame document Request, or traverse an SPA/BFCache entry through a URL
 * transition without a Request. Only the correlated document Request permits
 * teardown-cancellation handling; a same-document/BFCache transition cannot
 * make an unrelated failed request disappear from the audit.
 */
export function classifyHistoryTraversalReceipt(input: {
  readonly startingUrl: string;
  readonly observedUrl?: string;
  readonly mainFrameTransitionObserved: boolean;
  readonly documentNavigationRequestObserved: boolean;
}): HistoryTraversalReceipt {
  if (input.documentNavigationRequestObserved) return "document-request";
  if (
    input.mainFrameTransitionObserved
    && input.observedUrl !== undefined
    && input.observedUrl !== input.startingUrl
  ) return "same-document";
  return "missing";
}

const EVENT_STREAM_PATH = "/api/v2/events/stream";
const EXPECTED_EVENT_STREAM_ABORTS = new Set([
  "net::ERR_ABORTED",
  "NS_ERROR_ABORT",
  "NS_BINDING_ABORTED",
  "Load request cancelled",
]);
const WEBKIT_VERIFIED_DOWNLOAD_NAVIGATION_ABORT = "Provisiolal navigation canceled.";
const OPTIONAL_IMAGE_PATH = /^\/brand-v2\/optimized\/[A-Za-z0-9._-]+\.(?:avif|webp)$/u;
const FIREFOX_EVENT_STREAM_CONSOLE = /^\[JavaScript Error: "The connection to ([^"\s]+) was interrupted while the page was loading\." \{file: "([^"]+)" line: \d+\}\]$/u;
const DEV_EVENT_STREAM_SOURCE_PATH = "/src/data/events/EventStreamProvider.tsx";
const PRODUCTION_ENTRY_SOURCE_PATH = /^\/assets\/index-[A-Za-z0-9_-]{8}\.js$/u;
const PLAYWRIGHT_INIT_SCRIPT_SOURCE = "debugger eval code";

function pathname(url: string): string | undefined {
  try {
    return new URL(url, "http://127.0.0.1").pathname;
  } catch {
    return undefined;
  }
}

function pathAndQuery(url: string): string | undefined {
  try {
    const parsed = new URL(url, "http://127.0.0.1");
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return undefined;
  }
}

function isEventStreamConsoleSource(path: string | undefined): boolean {
  return path === DEV_EVENT_STREAM_SOURCE_PATH
    || (path !== undefined && PRODUCTION_ENTRY_SOURCE_PATH.test(path));
}

/**
 * Returns the exact stream URL embedded in Firefox's EventSource teardown
 * console message. The injected Playwright close-receipt wrapper is permitted
 * as a source only so the caller can correlate this candidate to a same-page,
 * same-URL request/close receipt. This function alone never suppresses an
 * issue.
 */
export function correlatableEventStreamConsoleUrl(
  issue: BrowserIssueLike,
  expectedOrigin: string,
): string | undefined {
  if (issue.kind !== "console" || !issue.url || !expectedOrigin) return undefined;
  const match = FIREFOX_EVENT_STREAM_CONSOLE.exec(issue.message);
  if (!match) return undefined;
  const streamUrl = match[1];
  const embeddedSource = match[2];
  if (!streamUrl || !embeddedSource || embeddedSource !== issue.url) return undefined;
  try {
    const parsed = new URL(streamUrl);
    if (parsed.origin !== expectedOrigin || parsed.pathname !== EVENT_STREAM_PATH) return undefined;
    const sourceAccepted = embeddedSource === PLAYWRIGHT_INIT_SCRIPT_SOURCE
      || isEventStreamConsoleSource(pathname(embeddedSource));
    return sourceAccepted ? parsed.href : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Browser engines use different names when the application intentionally
 * closes its live event stream during navigation or effect replacement.
 * Keep this allowlist exact: other endpoints and other network failures must
 * remain visible to the browser audit.
 */
export function isExpectedEventStreamTeardown(
  issue: BrowserIssueLike,
  options: {
    readonly enabled: boolean;
    readonly expectedOrigin: string;
    readonly requestSuperseded: boolean;
    readonly pageClosing: boolean;
  },
): boolean {
  if (!options.enabled || !options.expectedOrigin) return false;

  if (!options.requestSuperseded && !options.pageClosing) return false;

  if (issue.kind === "requestfailed") {
    if (issue.method !== "GET" || !EXPECTED_EVENT_STREAM_ABORTS.has(issue.message) || issue.url === undefined) return false;
    try {
      const parsed = new URL(issue.url);
      return parsed.origin === options.expectedOrigin && parsed.pathname === EVENT_STREAM_PATH;
    } catch {
      return false;
    }
  }

  if (issue.kind !== "console" || !issue.url) return false;
  const exactUrl = correlatableEventStreamConsoleUrl(issue, options.expectedOrigin);
  return exactUrl !== undefined && issue.url !== PLAYWRIGHT_INIT_SCRIPT_SOURCE;
}

/**
 * Browsers may report a successful top-level attachment download as an aborted
 * document navigation. The WebKit-only spelling below is eligible only after
 * the caller has independently bound the exact Playwright Request and Download
 * identities; a path declaration alone can never opt into it. The test must
 * still assert the Download object and downloaded content separately.
 */
export function isExpectedVerifiedDownloadNavigation(
  issue: BrowserIssueLike,
  expectedPaths: readonly string[],
  expectedOrigin?: string,
  options: { readonly exactRequestAndDownloadIdentityVerified?: boolean } = {},
): boolean {
  if (issue.kind !== "requestfailed" || issue.url === undefined) return false;
  if (issue.method !== "GET") return false;
  const browserAbort = EXPECTED_EVENT_STREAM_ABORTS.has(issue.message)
    || (
      options.exactRequestAndDownloadIdentityVerified === true
      && issue.message === WEBKIT_VERIFIED_DOWNLOAD_NAVIGATION_ABORT
    );
  if (!browserAbort) return false;
  if (expectedOrigin) {
    try {
      if (new URL(issue.url).origin !== expectedOrigin) return false;
    } catch {
      return false;
    }
  }
  const failedPath = pathAndQuery(issue.url);
  return failedPath !== undefined && expectedPaths.includes(failedPath);
}

/**
 * Browsers report in-flight same-origin GETs cancelled by a deliberate
 * document reload either as request failures or, on mobile WebKit, page
 * errors. Accept that engine bookkeeping only during a repeated top-level
 * navigation, within a tightly bounded window, for the exact current host and
 * `/api/v2/` prefix. Mutations, ordinary API/CORS failures, initial-load
 * failures, console errors, and other origins remain release-failing.
 */
export function isExpectedWebKitDocumentFetchTeardown(
  issue: BrowserIssueLike,
  options: {
    readonly enabled: boolean;
    readonly expectedOrigin: string;
  },
): boolean {
  if (!options.enabled || !options.expectedOrigin) return false;
  const expected = new URL(options.expectedOrigin);
  if (issue.kind === "requestfailed") {
    if (issue.method !== "GET" || !EXPECTED_EVENT_STREAM_ABORTS.has(issue.message) || !issue.url) return false;
    try {
      const url = new URL(issue.url);
      return url.origin === expected.origin && url.pathname.startsWith("/api/v2/");
    } catch {
      return false;
    }
  }
  if (issue.kind !== "pageerror") return false;
  const prefix = `/${expected.host}/api/v2/`;
  return issue.message.startsWith(prefix)
    && issue.message.endsWith(" due to access control checks.")
    && !issue.message.includes("\n");
}

/**
 * Proves that one prospectively declared image request belongs to the old
 * document. This deliberately does not recognize an image namespace: the
 * caller must name one exact path before navigation, the request must carry
 * the exact old-document referrer, and no replacement document request may
 * have been observed yet.
 */
export function isExpectedOldDocumentOptionalImageRequest(options: {
  readonly expectedOrigin: string;
  readonly expectedPath: string;
  readonly startingDocumentUrl: string;
  readonly requestUrl: string;
  readonly requestReferrer?: string;
  readonly method: string;
  readonly resourceType: string;
  readonly replacementDocumentObserved: boolean;
}): boolean {
  if (
    !options.expectedOrigin
    || !options.expectedPath
    || options.method !== "GET"
    || options.resourceType !== "image"
    || options.replacementDocumentObserved
    || !OPTIONAL_IMAGE_PATH.test(options.expectedPath)
  ) return false;
  try {
    const expectedOrigin = new URL(options.expectedOrigin).origin;
    const startingDocument = new URL(options.startingDocumentUrl);
    const request = new URL(options.requestUrl);
    const referrer = options.requestReferrer ? new URL(options.requestReferrer) : undefined;
    return startingDocument.origin === expectedOrigin
      && request.origin === expectedOrigin
      && `${request.pathname}${request.search}` === options.expectedPath
      && request.hash === ""
      && referrer?.href === startingDocument.href;
  } catch {
    return false;
  }
}

/**
 * A lazy, noncritical production image can still be in flight when an audited
 * full-document navigation replaces its owner. Accept only the exact browser
 * cancellation for the one prospectively declared path. The caller must also
 * bind this issue to the exact old-document Playwright Request identity and
 * independently prove the replacement document navigation; this predicate
 * alone never excuses an initial-load failure or an HTTP error response.
 */
export function isExpectedOptionalMediaNavigationTeardown(
  issue: BrowserIssueLike,
  options: {
    readonly enabled: boolean;
    readonly expectedOrigin: string;
    readonly expectedPath?: string;
  },
): boolean {
  if (!options.enabled || !options.expectedOrigin || !options.expectedPath) return false;
  if (
    issue.kind !== "requestfailed"
    || issue.method !== "GET"
    || !EXPECTED_EVENT_STREAM_ABORTS.has(issue.message)
    || !issue.url
  ) return false;
  try {
    const url = new URL(issue.url);
    return url.origin === new URL(options.expectedOrigin).origin
      && `${url.pathname}${url.search}` === options.expectedPath
      && url.hash === ""
      && OPTIONAL_IMAGE_PATH.test(options.expectedPath);
  } catch {
    return false;
  }
}

/**
 * A repeated browser navigation may expose the successful cached document as
 * its 304 revalidation response (notably in Firefox). The rendered route is
 * still asserted separately; no other success, redirect, or error code is
 * accepted by the route crawl.
 */
export function isResolvedDocumentNavigationStatus(status: number | null): boolean {
  return status === 200 || status === 304;
}

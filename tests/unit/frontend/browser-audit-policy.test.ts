import { describe, expect, test } from "bun:test";
import {
  classifyHistoryTraversalReceipt,
  correlatableEventStreamConsoleUrl,
  isExpectedEventStreamTeardown,
  isExpectedOldDocumentOptionalImageRequest,
  isExpectedOptionalMediaNavigationTeardown,
  isExpectedWebKitDocumentFetchTeardown,
  isExpectedVerifiedDownloadNavigation,
  isResolvedDocumentNavigationStatus,
  type BrowserIssueLike,
} from "../../e2e/support/browserAuditPolicy";

const streamAbort = (message: string, url = "http://127.0.0.1:43140/api/v2/events/stream"): BrowserIssueLike => ({
  kind: "requestfailed",
  message,
  url,
  method: "GET",
});

const streamBoundary = {
  enabled: true,
  expectedOrigin: "http://127.0.0.1:43140",
  requestSuperseded: true,
  pageClosing: false,
} as const;

describe("cross-browser-safe browser audit policy", () => {
  test("requires a document-request or URL-transition receipt and grants teardown authority only to the document request", () => {
    const base = {
      startingUrl: "http://127.0.0.1:43140/brain/nodes/mem-one",
      observedUrl: "http://127.0.0.1:43140/brain/graph?selected=mem-one",
      mainFrameTransitionObserved: true,
      documentNavigationRequestObserved: false,
    } as const;
    expect(classifyHistoryTraversalReceipt(base)).toBe("same-document");
    expect(classifyHistoryTraversalReceipt({ ...base, documentNavigationRequestObserved: true })).toBe("document-request");
    expect(classifyHistoryTraversalReceipt({ ...base, mainFrameTransitionObserved: false })).toBe("missing");
    expect(classifyHistoryTraversalReceipt({ ...base, observedUrl: base.startingUrl })).toBe("missing");
    expect(classifyHistoryTraversalReceipt({
      ...base,
      observedUrl: base.startingUrl,
      mainFrameTransitionObserved: false,
      documentNavigationRequestObserved: true,
    })).toBe("document-request");
    expect(classifyHistoryTraversalReceipt({ ...base, observedUrl: undefined })).toBe("missing");
  });

  test("extracts an exact Firefox stream-console URL for receipt correlation without suppressing init-script output alone", () => {
    const instrumented: BrowserIssueLike = {
      kind: "console",
      message: "[JavaScript Error: \"The connection to http://127.0.0.1:43140/api/v2/events/stream?lastEventId=run%3A42 was interrupted while the page was loading.\" {file: \"debugger eval code\" line: 6}]",
      url: "debugger eval code",
    };
    expect(correlatableEventStreamConsoleUrl(instrumented, "http://127.0.0.1:43140"))
      .toBe("http://127.0.0.1:43140/api/v2/events/stream?lastEventId=run%3A42");
    expect(isExpectedEventStreamTeardown(instrumented, streamBoundary)).toBe(false);
    expect(correlatableEventStreamConsoleUrl(instrumented, "http://localhost:43140")).toBeUndefined();
    expect(correlatableEventStreamConsoleUrl({
      ...instrumented,
      message: instrumented.message.replace("/events/stream?", "/events/gap?"),
    }, "http://127.0.0.1:43140")).toBeUndefined();
    expect(correlatableEventStreamConsoleUrl({
      ...instrumented,
      url: "another eval source",
    }, "http://127.0.0.1:43140")).toBeUndefined();
  });

  test("accepts only exact Chromium, Firefox, and WebKit event-stream teardown failures when opted in", () => {
    expect(isExpectedEventStreamTeardown(streamAbort("net::ERR_ABORTED"), streamBoundary)).toBe(true);
    expect(isExpectedEventStreamTeardown(streamAbort("NS_ERROR_ABORT"), streamBoundary)).toBe(true);
    expect(isExpectedEventStreamTeardown(streamAbort("NS_BINDING_ABORTED"), streamBoundary)).toBe(true);
    expect(isExpectedEventStreamTeardown(streamAbort("Load request cancelled"), streamBoundary)).toBe(true);
    expect(isExpectedEventStreamTeardown(
      streamAbort("NS_ERROR_ABORT", "http://127.0.0.1:43140/api/v2/events/stream?lastEventId=v2.cursor"),
      streamBoundary,
    )).toBe(true);
    expect(isExpectedEventStreamTeardown(
      streamAbort("Load request cancelled", "http://127.0.0.1:43140/api/v2/events/stream?lastEventId=v2.webkit-cursor"),
      streamBoundary,
    )).toBe(true);
    expect(isExpectedEventStreamTeardown({
      kind: "console",
      message: "[JavaScript Error: \"The connection to http://127.0.0.1:43140/api/v2/events/stream was interrupted while the page was loading.\" {file: \"http://127.0.0.1:43140/src/data/events/EventStreamProvider.tsx\" line: 217}]",
      url: "http://127.0.0.1:43140/src/data/events/EventStreamProvider.tsx",
    }, streamBoundary)).toBe(true);
    expect(isExpectedEventStreamTeardown({
      kind: "console",
      message: "[JavaScript Error: \"The connection to http://127.0.0.1:43241/api/v2/events/stream was interrupted while the page was loading.\" {file: \"http://127.0.0.1:43241/assets/index-DRoTPhsw.js\" line: 34}]",
      url: "http://127.0.0.1:43241/assets/index-DRoTPhsw.js",
    }, { ...streamBoundary, expectedOrigin: "http://127.0.0.1:43241" })).toBe(true);
  });

  test("does not suppress other required network failures or non-stream requests", () => {
    expect(isExpectedEventStreamTeardown(streamAbort("NS_ERROR_ABORT"), { ...streamBoundary, enabled: false })).toBe(false);
    expect(isExpectedEventStreamTeardown(streamAbort("NS_ERROR_CONNECTION_REFUSED"), streamBoundary)).toBe(false);
    expect(isExpectedEventStreamTeardown(streamAbort("NS_ERROR_ABORTED"), streamBoundary)).toBe(false);
    expect(isExpectedEventStreamTeardown(streamAbort("Load request canceled"), streamBoundary)).toBe(false);
    expect(isExpectedEventStreamTeardown(
      streamAbort("NS_ERROR_ABORT", "http://127.0.0.1:43140/api/v2/events/replay"),
      streamBoundary,
    )).toBe(false);
    for (const apiPath of [
      "/api/v2/events/gap",
      "/api/v2/health",
      "/api/v2/missions",
    ]) {
      expect(isExpectedEventStreamTeardown(
        streamAbort("Load request cancelled", `http://127.0.0.1:43140${apiPath}`),
        streamBoundary,
      )).toBe(false);
    }
    expect(isExpectedEventStreamTeardown({
      kind: "response",
      message: "NS_ERROR_ABORT",
      url: "http://127.0.0.1:43140/api/v2/events/stream",
    }, streamBoundary)).toBe(false);
    expect(isExpectedEventStreamTeardown({
      kind: "console",
      message: "[JavaScript Error: \"The connection to http://127.0.0.1:43140/api/v2/events/stream was interrupted while the page was loading.\" {file: \"http://127.0.0.1:43140/src/data/events/OtherProvider.tsx\" line: 217}]",
      url: "http://127.0.0.1:43140/src/data/events/OtherProvider.tsx",
    }, streamBoundary)).toBe(false);
    expect(isExpectedEventStreamTeardown({
      kind: "console",
      message: "[JavaScript Error: \"The connection to http://127.0.0.1:43140/api/v2/events/gap was interrupted while the page was loading.\" {file: \"http://127.0.0.1:43140/src/data/events/EventStreamProvider.tsx\" line: 217}]",
      url: "http://127.0.0.1:43140/src/data/events/EventStreamProvider.tsx",
    }, streamBoundary)).toBe(false);
    for (const source of [
      "/assets/index-DRoTPhs.js",
      "/assets/index-DRoTPhsw0.js",
      "/assets/index.js",
      "/assets/index-DRoTPhsw.css",
      "/assets/RunWorkspace-DRoTPhsw.js",
      "/public/assets/index-DRoTPhsw.js",
    ]) {
      expect(isExpectedEventStreamTeardown({
        kind: "console",
        message: `[JavaScript Error: \"The connection to http://127.0.0.1:43241/api/v2/events/stream was interrupted while the page was loading.\" {file: \"http://127.0.0.1:43241${source}\" line: 34}]`,
        url: `http://127.0.0.1:43241${source}`,
      }, { ...streamBoundary, expectedOrigin: "http://127.0.0.1:43241" })).toBe(false);
    }
    expect(isExpectedEventStreamTeardown({
      kind: "console",
      message: "[JavaScript Error: \"The connection to http://127.0.0.1:43241/api/v2/events/stream was interrupted while the page was loading.\" {file: \"http://127.0.0.1:43241/assets/index-DRoTPhsw.js\" line: 34}]",
      url: "http://127.0.0.1:43241/assets/index-AbCdEf12.js",
    }, { ...streamBoundary, expectedOrigin: "http://127.0.0.1:43241" })).toBe(false);
    expect(isExpectedEventStreamTeardown({ ...streamAbort("net::ERR_ABORTED"), method: "POST" }, streamBoundary)).toBe(false);
    expect(isExpectedEventStreamTeardown(streamAbort("net::ERR_ABORTED", "http://localhost:43140/api/v2/events/stream"), streamBoundary)).toBe(false);
    expect(isExpectedEventStreamTeardown(streamAbort("net::ERR_ABORTED"), { ...streamBoundary, requestSuperseded: false })).toBe(false);
    expect(isExpectedEventStreamTeardown(streamAbort("net::ERR_ABORTED"), {
      ...streamBoundary,
      requestSuperseded: false,
      pageClosing: true,
    })).toBe(true);
  });

  test("accepts only a fresh or cache-revalidated document response", () => {
    expect(isResolvedDocumentNavigationStatus(200)).toBe(true);
    expect(isResolvedDocumentNavigationStatus(304)).toBe(true);

    for (const status of [null, 0, 201, 204, 206, 301, 302, 307, 308, 400, 404, 500]) {
      expect(isResolvedDocumentNavigationStatus(status)).toBe(false);
    }
  });

  test("accepts only an exact, test-verified download navigation path", () => {
    const downloadPath = "/api/v2/intelligence/evidence/runs/run-one/export";
    expect(isExpectedVerifiedDownloadNavigation({
      kind: "requestfailed",
      message: "net::ERR_ABORTED",
      method: "GET",
      url: `http://127.0.0.1:43140${downloadPath}`,
    }, [downloadPath], "http://127.0.0.1:43140")).toBe(true);
    expect(isExpectedVerifiedDownloadNavigation({
      kind: "requestfailed",
      message: "NS_BINDING_ABORTED",
      method: "GET",
      url: `http://127.0.0.1:43140${downloadPath}?unexpected=true`,
    }, [downloadPath], "http://127.0.0.1:43140")).toBe(false);
    const webkitPortableDownloadAbort = {
      kind: "requestfailed" as const,
      message: "Provisiolal navigation canceled.",
      method: "GET",
      url: `http://127.0.0.1:43140${downloadPath}`,
    };
    expect(isExpectedVerifiedDownloadNavigation(
      webkitPortableDownloadAbort,
      [downloadPath],
      "http://127.0.0.1:43140",
    )).toBe(false);
    expect(isExpectedVerifiedDownloadNavigation(
      webkitPortableDownloadAbort,
      [downloadPath],
      "http://127.0.0.1:43140",
      { exactRequestAndDownloadIdentityVerified: true },
    )).toBe(true);
    expect(isExpectedVerifiedDownloadNavigation(
      { ...webkitPortableDownloadAbort, message: "Provisional navigation canceled." },
      [downloadPath],
      "http://127.0.0.1:43140",
      { exactRequestAndDownloadIdentityVerified: true },
    )).toBe(false);
    expect(isExpectedVerifiedDownloadNavigation(
      { ...webkitPortableDownloadAbort, url: "http://127.0.0.1:43140/api/v2/brain/vault/portable-exports/other.zip" },
      [downloadPath],
      "http://127.0.0.1:43140",
      { exactRequestAndDownloadIdentityVerified: true },
    )).toBe(false);
    expect(isExpectedVerifiedDownloadNavigation(
      { ...webkitPortableDownloadAbort, url: `http://localhost:43140${downloadPath}` },
      [downloadPath],
      "http://127.0.0.1:43140",
      { exactRequestAndDownloadIdentityVerified: true },
    )).toBe(false);

    for (const issue of [
      { kind: "requestfailed" as const, message: "net::ERR_FAILED", method: "GET", url: `http://127.0.0.1:43140${downloadPath}` },
      { kind: "response" as const, message: "HTTP 404", url: `http://127.0.0.1:43140${downloadPath}` },
      { kind: "requestfailed" as const, message: "net::ERR_ABORTED", method: "POST", url: `http://127.0.0.1:43140${downloadPath}` },
      { kind: "requestfailed" as const, message: "net::ERR_ABORTED", method: "GET", url: "http://127.0.0.1:43140/api/v2/intelligence/evidence/runs/another/export" },
      { kind: "requestfailed" as const, message: "net::ERR_ABORTED", method: "GET", url: `http://localhost:43140${downloadPath}` },
    ]) expect(isExpectedVerifiedDownloadNavigation(issue, [downloadPath], "http://127.0.0.1:43140")).toBe(false);
  });

  test("classifies only exact same-host WebKit fetch teardown during a repeated document navigation", () => {
    const issue: BrowserIssueLike = {
      kind: "pageerror",
      message: "/127.0.0.1:43140/api/v2/runs/run-one due to access control checks.",
    };
    const valid = {
      enabled: true,
      expectedOrigin: "http://127.0.0.1:43140",
    };
    expect(isExpectedWebKitDocumentFetchTeardown(issue, valid)).toBe(true);
    expect(isExpectedWebKitDocumentFetchTeardown(issue, { ...valid, enabled: false })).toBe(false);
    expect(isExpectedWebKitDocumentFetchTeardown(issue, { ...valid, expectedOrigin: "http://localhost:43140" })).toBe(false);
    expect(isExpectedWebKitDocumentFetchTeardown({ ...issue, kind: "console" }, valid)).toBe(false);
    expect(isExpectedWebKitDocumentFetchTeardown({
      kind: "requestfailed",
      message: "net::ERR_ABORTED",
      method: "GET",
      url: "http://127.0.0.1:43140/api/v2/runs/run-one",
    }, valid)).toBe(true);
    expect(isExpectedWebKitDocumentFetchTeardown({
      kind: "requestfailed",
      message: "net::ERR_ABORTED",
      method: "POST",
      url: "http://127.0.0.1:43140/api/v2/runs/run-one",
    }, valid)).toBe(false);
    expect(isExpectedWebKitDocumentFetchTeardown({
      kind: "requestfailed",
      message: "net::ERR_FAILED",
      method: "GET",
      url: "http://127.0.0.1:43140/api/v2/runs/run-one",
    }, valid)).toBe(false);
    expect(isExpectedWebKitDocumentFetchTeardown({
      kind: "requestfailed",
      message: "net::ERR_ABORTED",
      method: "GET",
      url: "http://localhost:43140/api/v2/runs/run-one",
    }, valid)).toBe(false);
    expect(isExpectedWebKitDocumentFetchTeardown({
      ...issue,
      message: "/127.0.0.1:43140/api/v1/runs/run-one due to access control checks.",
    }, valid)).toBe(false);
    expect(isExpectedWebKitDocumentFetchTeardown({
      ...issue,
      message: "/127.0.0.1:43140/api/v2/runs/run-one due to access control checks.\nreal error",
    }, valid)).toBe(false);
  });

  test("binds only the exact prospectively declared old-document image request", () => {
    const valid = {
      expectedOrigin: "http://127.0.0.1:43140",
      expectedPath: "/brand-v2/optimized/empty-brain-512.avif",
      startingDocumentUrl: "http://127.0.0.1:43140/brain/graph",
      requestUrl: "http://127.0.0.1:43140/brand-v2/optimized/empty-brain-512.avif",
      requestReferrer: "http://127.0.0.1:43140/brain/graph",
      method: "GET",
      resourceType: "image",
      replacementDocumentObserved: false,
    } as const;
    expect(isExpectedOldDocumentOptionalImageRequest(valid)).toBe(true);
    for (const candidate of [
      { ...valid, expectedPath: "/brand-v2/optimized/another-image.avif" },
      { ...valid, requestUrl: "http://127.0.0.1:43140/brand-v2/optimized/another-image.avif" },
      { ...valid, requestReferrer: "http://127.0.0.1:43140/brain/inbox" },
      { ...valid, requestReferrer: undefined },
      { ...valid, replacementDocumentObserved: true },
      { ...valid, method: "POST" },
      { ...valid, resourceType: "fetch" },
      { ...valid, requestUrl: "http://localhost:43140/brand-v2/optimized/empty-brain-512.avif" },
      { ...valid, expectedPath: "/brand-v2/optimized/empty-brain-512.avif?cache=miss" },
      { ...valid, expectedPath: "/brand-v2/optimized/onboarding.webm" },
    ]) expect(isExpectedOldDocumentOptionalImageRequest(candidate)).toBe(false);
  });

  test("classifies cancellation only for the exact prospectively declared image path", () => {
    const valid = {
      enabled: true,
      expectedOrigin: "http://127.0.0.1:43140",
      expectedPath: "/brand-v2/optimized/empty-brain-512.avif",
    } as const;
    const issue: BrowserIssueLike = {
      kind: "requestfailed",
      message: "net::ERR_ABORTED",
      method: "GET",
      url: "http://127.0.0.1:43140/brand-v2/optimized/empty-brain-512.avif",
    };
    expect(isExpectedOptionalMediaNavigationTeardown(issue, valid)).toBe(true);
    for (const candidate of [
      { ...issue, kind: "response" as const },
      { ...issue, method: "POST" },
      { ...issue, message: "net::ERR_FAILED" },
      { ...issue, url: "http://localhost:43140/brand-v2/optimized/empty-brain-512.avif" },
      { ...issue, url: "http://127.0.0.1:43140/brand-v2/optimized/another-image.avif" },
      { ...issue, url: "http://127.0.0.1:43140/brand-v2/source/empty-brain-512.avif" },
      { ...issue, url: "http://127.0.0.1:43140/assets/index-AbCdEf12.js" },
      { ...issue, url: "http://127.0.0.1:43140/brand-v2/optimized/empty-brain-512.svg" },
      { ...issue, url: "http://127.0.0.1:43140/brand-v2/optimized/empty-brain-512.avif?cache=miss" },
    ]) expect(isExpectedOptionalMediaNavigationTeardown(candidate, valid)).toBe(false);
    expect(isExpectedOptionalMediaNavigationTeardown(issue, { ...valid, enabled: false })).toBe(false);
    expect(isExpectedOptionalMediaNavigationTeardown(issue, { ...valid, expectedPath: undefined })).toBe(false);
    expect(isExpectedOptionalMediaNavigationTeardown(issue, {
      ...valid,
      expectedPath: "/brand-v2/optimized/another-image.avif",
    })).toBe(false);
  });
});

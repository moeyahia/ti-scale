import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import {
  arch,
  cpus,
  platform,
  release,
  totalmem,
} from "node:os";
import { resolve } from "node:path";
import {
  evaluateWebVitalBudget,
  maximumClsSessionWindow,
  WEB_VITAL_BUDGETS,
  WEB_VITAL_SAMPLE_COUNT,
  webVitalP75,
  type LayoutShiftSample,
  type WebVitalBudget,
  type WebVitalSample,
} from "../performance/webVitalsBudget";
import {
  PERFORMANCE_BUILD_PROVENANCE_SCHEMA,
  directoryTreeManifest,
  classifyObservedResourceUrl,
  observedResourceIntegrityFailure,
  performanceBuildBaselinePath,
  performanceSourceBaselinePath,
  publishAtomicTextExclusive,
  readPerformanceBuildBaseline,
  readPerformanceSourceBaseline,
  sameFileTreeSummary,
  sourceTreeManifest,
  staticResponseIntegrityFailures,
  summarizeFileTree,
  type FileTreeManifest,
  type FileTreeManifestSummary,
} from "../performance/performanceProvenance";
import {
  E2E_AUTH_STATE,
  E2E_DATA_ROOT,
  E2E_RUN_ID,
} from "./support/environment";
import {
  expect,
  test,
  withAuditedIsolatedBrowserContext,
  type Browser,
  type BrowserContext,
  type CDPSession,
  type Page,
  type Request as PlaywrightRequest,
  type Response,
  type TestInfo,
} from "./support/playwright";

interface BrowserVitalState {
  fcpMs: number | null;
  lcpMs: number | null;
  lcpLastUpdatedAtMs: number | null;
  layoutShifts: LayoutShiftSample[];
  interactionDurations: Record<string, number>;
  longTaskCount: number;
  longTaskTotalMs: number;
  longTaskMaximumMs: number;
  resourceTimingBufferFull: boolean;
  observerErrors: string[];
}

interface BrowserVitalSnapshot extends WebVitalSample {
  readonly observedInteractionCount: number;
  readonly eventTimingFloorMs: 16;
  readonly inpMeasurement: "synthetic-command-palette";
  readonly lcpQuietBeforeInteractionMs: number;
  readonly layoutShifts: readonly LayoutShiftSample[];
  readonly longTaskCount: number;
  readonly longTaskTotalMs: number;
  readonly longTaskMaximumMs: number;
  readonly resourceTimingBufferFull: boolean;
  readonly observerErrors: readonly string[];
  readonly resourceUrls: readonly string[];
  readonly servedDocument: ObservedStaticResponseDigest;
  readonly servedStaticResponses: readonly ObservedStaticResponseDigest[];
  readonly resourceExclusions: readonly ObservedResourceExclusion[];
  readonly responseIntegrityFailures: readonly string[];
}

interface PerformanceEnvironment {
  readonly name: WebVitalBudget["environment"];
  readonly viewport: { readonly width: number; readonly height: number };
  readonly deviceScaleFactor: number;
  readonly isMobile: boolean;
  readonly hasTouch: boolean;
  readonly cpuThrottleRate: number;
  readonly network: {
    readonly latencyMs: number;
    readonly downloadBytesPerSecond: number;
    readonly uploadBytesPerSecond: number;
    readonly connectionType: "none" | "cellular3g";
  };
}

interface AssetDigest {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}

interface ObservedStaticResponseDigest extends AssetDigest {
  readonly sample: number;
  readonly requestUrl: string;
  readonly status: number;
  readonly resourceType: string;
  readonly fromServiceWorker: boolean;
}

interface ObservedResourceExclusion {
  readonly sample: number;
  readonly requestUrl: string;
  readonly classification:
    | "dynamic-api"
    | "external-origin"
    | "non-http";
  readonly reason: string;
}

interface ObservedNetworkEvidence {
  readonly document: ObservedStaticResponseDigest;
  readonly staticResponses: readonly ObservedStaticResponseDigest[];
  readonly exclusions: readonly ObservedResourceExclusion[];
  readonly integrityFailures: readonly string[];
}

interface FailedObservedRequest {
  readonly request: PlaywrightRequest;
  readonly errorText: string;
}

const LCP_QUIET_PERIOD_MS = 2_000;
const API_SETTLEMENT_QUIET_MS = 500;
const RESOURCE_TIMING_BUFFER_SIZE = 10_000;

const environments: readonly PerformanceEnvironment[] = Object.freeze([
  Object.freeze({
    name: "desktop",
    viewport: Object.freeze({ width: 1440, height: 900 }),
    deviceScaleFactor: 1,
    isMobile: false,
    hasTouch: false,
    cpuThrottleRate: 1,
    network: Object.freeze({
      latencyMs: 0,
      downloadBytesPerSecond: -1,
      uploadBytesPerSecond: -1,
      connectionType: "none",
    }),
  }),
  Object.freeze({
    name: "mid-tier-mobile",
    viewport: Object.freeze({ width: 390, height: 844 }),
    deviceScaleFactor: 2.75,
    isMobile: true,
    hasTouch: true,
    cpuThrottleRate: 4,
    network: Object.freeze({
      latencyMs: 150,
      downloadBytesPerSecond: 200_000,
      uploadBytesPerSecond: 93_750,
      connectionType: "cellular3g",
    }),
  }),
]);

function installVitalObservers(resourceTimingBufferSize: number): void {
  const state: BrowserVitalState = {
    fcpMs: null,
    lcpMs: null,
    lcpLastUpdatedAtMs: null,
    layoutShifts: [],
    interactionDurations: {},
    longTaskCount: 0,
    longTaskTotalMs: 0,
    longTaskMaximumMs: 0,
    resourceTimingBufferFull: false,
    observerErrors: [],
  };
  (window as typeof window & { __tiScaleWebVitals?: BrowserVitalState }).__tiScaleWebVitals = state;
  performance.setResourceTimingBufferSize(resourceTimingBufferSize);
  performance.addEventListener("resourcetimingbufferfull", () => {
    state.resourceTimingBufferFull = true;
    state.observerErrors.push(
      `resource: the ${resourceTimingBufferSize}-entry Resource Timing buffer was exhausted`,
    );
  });

  const observe = (
    type: string,
    callback: (entries: readonly PerformanceEntry[]) => void,
    options: PerformanceObserverInit = { type, buffered: true },
  ): void => {
    try {
      const observer = new PerformanceObserver((list) => callback(list.getEntries()));
      observer.observe(options);
    } catch (error) {
      state.observerErrors.push(
        `${type}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  };

  observe("paint", (entries) => {
    for (const entry of entries) {
      if (entry.name === "first-contentful-paint") state.fcpMs = entry.startTime;
    }
  });
  observe("largest-contentful-paint", (entries) => {
    for (const entry of entries) {
      state.lcpMs = entry.startTime;
      state.lcpLastUpdatedAtMs = performance.now();
    }
  });
  observe("layout-shift", (entries) => {
    for (const entry of entries) {
      const shift = entry as PerformanceEntry & {
        readonly hadRecentInput?: boolean;
        readonly value?: number;
      };
      state.layoutShifts.push({
        startTime: entry.startTime,
        value: shift.value ?? 0,
        hadRecentInput: shift.hadRecentInput ?? false,
      });
    }
  });
  observe("event", (entries) => {
    for (const entry of entries) {
      const event = entry as PerformanceEntry & {
        readonly interactionId?: number;
      };
      if (!event.interactionId) continue;
      const key = String(event.interactionId);
      state.interactionDurations[key] = Math.max(
        state.interactionDurations[key] ?? 0,
        event.duration,
      );
    }
  }, {
    type: "event",
    buffered: true,
    durationThreshold: 16,
  } as PerformanceObserverInit & { readonly durationThreshold: number });
  observe("longtask", (entries) => {
    for (const entry of entries) {
      state.longTaskCount += 1;
      state.longTaskTotalMs += entry.duration;
      state.longTaskMaximumMs = Math.max(state.longTaskMaximumMs, entry.duration);
    }
  });
}

function finiteMetric(value: number | null, label: string): number {
  if (value === null || !Number.isFinite(value) || value < 0) {
    throw new Error(`${label} was not captured as a finite non-negative metric`);
  }
  return value;
}

async function configureColdContext(
  context: BrowserContext,
  page: Page,
  environment: PerformanceEnvironment,
): Promise<CDPSession> {
  const cdp = await context.newCDPSession(page);
  await cdp.send("Network.enable");
  await cdp.send("Network.setCacheDisabled", { cacheDisabled: true });
  await cdp.send("Emulation.setCPUThrottlingRate", {
    rate: environment.cpuThrottleRate,
  });
  await cdp.send("Network.emulateNetworkConditions", {
    offline: false,
    latency: environment.network.latencyMs,
    downloadThroughput: environment.network.downloadBytesPerSecond,
    uploadThroughput: environment.network.uploadBytesPerSecond,
    connectionType: environment.network.connectionType,
  });
  return cdp;
}

async function captureObservedNetworkEvidence(
  sample: number,
  baseURL: string,
  build: FileTreeManifest,
  navigationResponse: Response | null,
  observedRequests: readonly PlaywrightRequest[],
  observedResponses: readonly Response[],
  failedRequests: readonly FailedObservedRequest[],
  resourceUrls: readonly string[],
): Promise<ObservedNetworkEvidence> {
  if (!navigationResponse) {
    throw new Error(`Sample ${sample}: the measured navigation returned no document response`);
  }
  const origin = new URL(baseURL).origin;
  const documentUrl = new URL(navigationResponse.url());
  documentUrl.hash = "";
  if (documentUrl.origin !== origin) {
    throw new Error(
      `Sample ${sample}: the measured document escaped the configured origin: ${documentUrl}`,
    );
  }
  const documentBytes = await navigationResponse.body();
  const document = Object.freeze({
    sample,
    requestUrl: documentUrl.toString(),
    path: "index.html",
    status: navigationResponse.status(),
    resourceType: navigationResponse.request().resourceType(),
    fromServiceWorker: navigationResponse.fromServiceWorker(),
    bytes: documentBytes.byteLength,
    sha256: createHash("sha256").update(documentBytes).digest("hex"),
  });
  const staticResponses: ObservedStaticResponseDigest[] = [];
  const exclusions: ObservedResourceExclusion[] = [];
  const integrityFailures: string[] = [];
  const capturedStaticUrls = new Set<string>();
  const exclusionKeys = new Set<string>();
  const responseRequests = new Set(
    observedResponses.map((response) => response.request()),
  );
  const failedRequestMap = new Map(
    failedRequests.map(({ request, errorText }) => [request, errorText] as const),
  );

  if (document.status !== 200) {
    integrityFailures.push(
      `Sample ${sample}: measured document returned HTTP ${document.status}`,
    );
  }
  integrityFailures.push(...staticResponseIntegrityFailures(build, [document])
    .map((failure) => `Sample ${sample}: ${failure}`));

  const addExclusion = (
    classification: Extract<
      ReturnType<typeof classifyObservedResourceUrl>,
      { readonly kind: "dynamic-api" | "external-origin" | "non-http" }
    >,
  ): void => {
    const key = `${classification.kind}\0${classification.requestUrl}`;
    if (exclusionKeys.has(key)) return;
    exclusionKeys.add(key);
    exclusions.push(Object.freeze({
      sample,
      requestUrl: classification.requestUrl,
      classification: classification.kind,
      reason: classification.reason,
    }));
  };
  const recordClassificationFailure = (
    classification: ReturnType<typeof classifyObservedResourceUrl>,
    prefix: string,
  ): void => {
    const failure = observedResourceIntegrityFailure(classification);
    if (failure) integrityFailures.push(`Sample ${sample}: ${prefix}${failure}`);
  };

  const responseSnapshot = observedResponses.filter((response) =>
    response !== navigationResponse);
  for (const response of responseSnapshot) {
    const classification = classifyObservedResourceUrl(
      response.url(),
      baseURL,
      build,
    );
    if (
      classification.kind === "dynamic-api"
      || classification.kind === "external-origin"
      || classification.kind === "non-http"
    ) {
      addExclusion(classification);
      recordClassificationFailure(classification, "");
      continue;
    }
    if (
      classification.kind === "invalid"
      || classification.kind === "unclassified-same-origin"
    ) {
      recordClassificationFailure(classification, "");
      continue;
    }

    capturedStaticUrls.add(classification.requestUrl);
    let bytes: Buffer;
    try {
      bytes = await response.body();
    } catch (error) {
      integrityFailures.push(
        `Sample ${sample}: could not read observed static response ${classification.requestUrl}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      continue;
    }
    const digest = Object.freeze({
      sample,
      requestUrl: classification.requestUrl,
      path: classification.path,
      status: response.status(),
      resourceType: response.request().resourceType(),
      fromServiceWorker: response.fromServiceWorker(),
      bytes: bytes.byteLength,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    staticResponses.push(digest);
    if (digest.status !== 200) {
      integrityFailures.push(
        `Sample ${sample}: observed static response ${digest.requestUrl} returned HTTP ${digest.status}`,
      );
    }
    integrityFailures.push(...staticResponseIntegrityFailures(build, [digest])
      .map((failure) =>
        `Sample ${sample}: ${failure} (${classification.requestUrl})`));
  }

  for (const request of observedRequests) {
    if (responseRequests.has(request)) continue;
    const classification = classifyObservedResourceUrl(
      request.url(),
      baseURL,
      build,
    );
    if (
      classification.kind === "dynamic-api"
      || classification.kind === "external-origin"
      || classification.kind === "non-http"
    ) {
      addExclusion(classification);
      recordClassificationFailure(classification, "");
      continue;
    }
    if (
      classification.kind === "invalid"
      || classification.kind === "unclassified-same-origin"
    ) {
      recordClassificationFailure(classification, "");
      continue;
    }
    const failureText = failedRequestMap.get(request);
    integrityFailures.push(
      failureText
        ? `Sample ${sample}: static build request failed before a complete response (${failureText}): ${classification.requestUrl}`
        : `Sample ${sample}: static build request remained pending without a response: ${classification.requestUrl}`,
    );
  }

  for (const url of resourceUrls) {
    const classification = classifyObservedResourceUrl(url, baseURL, build);
    if (
      classification.kind === "dynamic-api"
      || classification.kind === "external-origin"
      || classification.kind === "non-http"
    ) {
      addExclusion(classification);
      recordClassificationFailure(classification, "Resource Timing reported ");
      continue;
    }
    if (
      classification.kind === "invalid"
      || classification.kind === "unclassified-same-origin"
    ) {
      recordClassificationFailure(classification, "Resource Timing reported ");
      continue;
    }
    if (!capturedStaticUrls.has(classification.requestUrl)) {
      integrityFailures.push(
        `Sample ${sample}: Resource Timing reported static build URL without a captured response body: ${classification.requestUrl}`,
      );
    }
  }

  return Object.freeze({
    document,
    staticResponses: Object.freeze(staticResponses),
    exclusions: Object.freeze(exclusions),
    integrityFailures: Object.freeze([...new Set(integrityFailures)]),
  });
}

async function measuredNavigation(
  browser: Browser,
  baseURL: string,
  environment: PerformanceEnvironment,
  sample: number,
  testInfo: TestInfo,
  build: FileTreeManifest,
): Promise<BrowserVitalSnapshot> {
  return withAuditedIsolatedBrowserContext(
    browser,
    testInfo,
    {
      context: {
        storageState: E2E_AUTH_STATE,
        viewport: environment.viewport,
        screen: environment.viewport,
        deviceScaleFactor: environment.deviceScaleFactor,
        isMobile: environment.isMobile,
        hasTouch: environment.hasTouch,
        colorScheme: "light",
        locale: "en-US",
        timezoneId: "UTC",
        reducedMotion: "no-preference",
        serviceWorkers: "allow",
      },
      audit: {
        allowEventStreamNavigationAbort: true,
      },
    },
    async ({ context, browserAudit, createPage }) => {
      const page = await createPage();
      const observedRequests: PlaywrightRequest[] = [];
      const observedResponses: Response[] = [];
      const failedRequests: FailedObservedRequest[] = [];
      const observeRequest = (request: PlaywrightRequest): void => {
        observedRequests.push(request);
      };
      const observeResponse = (response: Response): void => {
        observedResponses.push(response);
      };
      const observeRequestFailure = (request: PlaywrightRequest): void => {
        failedRequests.push(Object.freeze({
          request,
          errorText: request.failure()?.errorText ?? "unknown network failure",
        }));
      };
      context.on("request", observeRequest);
      context.on("response", observeResponse);
      context.on("requestfailed", observeRequestFailure);
      let navigationResponse: Response | null = null;
      let cdp: CDPSession | undefined;
      try {
        cdp = await configureColdContext(context, page, environment);
        await page.addInitScript(
          installVitalObservers,
          RESOURCE_TIMING_BUFFER_SIZE,
        );
        navigationResponse = await page.goto(new URL("/", baseURL).toString(), {
          waitUntil: "domcontentloaded",
          timeout: 60_000,
        });
        await page.waitForLoadState("load", { timeout: 60_000 });
        await expect(
          page.getByRole("heading", { level: 1, name: "Command Center", exact: true }),
        ).toBeVisible({ timeout: 30_000 });
        await page.evaluate(async () => {
          await document.fonts.ready;
        });
        await browserAudit.waitForPageApiSettlement(page, {
          timeoutMs: 30_000,
          quietMs: API_SETTLEMENT_QUIET_MS,
        });
    await page.waitForFunction((quietPeriodMs) => {
      const state = (
        window as typeof window & { __tiScaleWebVitals?: BrowserVitalState }
      ).__tiScaleWebVitals;
      return Boolean(
        state
        && state.fcpMs !== null
        && state.lcpMs !== null
        && state.lcpLastUpdatedAtMs !== null
        && document.readyState === "complete"
        && document.fonts.status === "loaded"
        && performance.now() - state.lcpLastUpdatedAtMs >= quietPeriodMs,
      );
    }, LCP_QUIET_PERIOD_MS, { timeout: 30_000 });
    const lcpQuietBeforeInteractionMs = await page.evaluate(() => {
      const state = (
        window as typeof window & { __tiScaleWebVitals?: BrowserVitalState }
      ).__tiScaleWebVitals;
      if (state?.lcpLastUpdatedAtMs === null || state?.lcpLastUpdatedAtMs === undefined) {
        throw new Error("The last LCP observation time is unavailable");
      }
      return performance.now() - state.lcpLastUpdatedAtMs;
    });
    expect(
      lcpQuietBeforeInteractionMs,
      "LCP must remain unchanged for the full quiet interval before synthetic input",
    ).toBeGreaterThanOrEqual(LCP_QUIET_PERIOD_MS);

    await page.getByRole("button", {
      name: "Search or run a command",
      exact: true,
    }).click();
    await expect(
      page.getByRole("dialog", { name: "Command palette", exact: true }),
    ).toBeVisible();
    // Opening the global palette intentionally starts the mission, run,
    // decision, and agent reads that populate its command inventory. Under the
    // mobile network profile those reads can outlive the click itself. Let the
    // exact audited requests finish before Escape so the measured interaction
    // does not manufacture page-close/component-cleanup aborts.
    await browserAudit.waitForPageApiSettlement(page, {
      timeoutMs: 30_000,
      quietMs: API_SETTLEMENT_QUIET_MS,
    });
    await page.keyboard.press("Escape");
    await expect(
      page.getByRole("dialog", { name: "Command palette", exact: true }),
    ).toHaveCount(0);
    // Prove that closing the palette does not start follow-up API work before
    // this cold page is handed back to the audited context owner.
    await browserAudit.waitForPageApiSettlement(page, {
      timeoutMs: 30_000,
      quietMs: API_SETTLEMENT_QUIET_MS,
    });
    await page.evaluate(() => new Promise<void>((resolveFrame) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolveFrame()));
    }));
    await page.waitForTimeout(250);

    const metrics = await page.evaluate(({ sampleNumber }) => {
      const state = (
        window as typeof window & { __tiScaleWebVitals?: BrowserVitalState }
      ).__tiScaleWebVitals;
      if (!state) throw new Error("The Web Vitals observer state is unavailable");
      const navigation = performance.getEntriesByType("navigation")[0] as
        | PerformanceNavigationTiming
        | undefined;
      if (!navigation) throw new Error("Navigation timing is unavailable");
      const interactionDurations = Object.values(state.interactionDurations);
      const measuredInp = interactionDurations.length > 0
        ? Math.max(...interactionDurations)
        : 16;
      return {
        sample: sampleNumber,
        navigationStartEpochMs: performance.timeOrigin,
        domContentLoadedMs: navigation.domContentLoadedEventEnd,
        loadEventMs: navigation.loadEventEnd,
        fcpMs: state.fcpMs,
        lcpMs: state.lcpMs,
        inpMs: measuredInp,
        observedInteractionCount: interactionDurations.length,
        eventTimingFloorMs: 16 as const,
        inpMeasurement: "synthetic-command-palette" as const,
        layoutShifts: state.layoutShifts,
        longTaskCount: state.longTaskCount,
        longTaskTotalMs: state.longTaskTotalMs,
        longTaskMaximumMs: state.longTaskMaximumMs,
        resourceTimingBufferFull: state.resourceTimingBufferFull,
        observerErrors: state.observerErrors,
        resourceUrls: performance
          .getEntriesByType("resource")
          .map((entry) => entry.name),
      };
    }, { sampleNumber: sample }).then((snapshot) => ({
      ...snapshot,
      lcpQuietBeforeInteractionMs: finiteMetric(
        lcpQuietBeforeInteractionMs,
        "LCP quiet interval",
      ),
      fcpMs: finiteMetric(snapshot.fcpMs, "FCP"),
      lcpMs: finiteMetric(snapshot.lcpMs, "LCP"),
      inpMs: finiteMetric(snapshot.inpMs, "INP"),
      cls: finiteMetric(
        maximumClsSessionWindow(snapshot.layoutShifts),
        "CLS",
      ),
      domContentLoadedMs: finiteMetric(
        snapshot.domContentLoadedMs,
        "DOMContentLoaded",
      ),
      loadEventMs: finiteMetric(snapshot.loadEventMs, "load event"),
      longTaskTotalMs: finiteMetric(snapshot.longTaskTotalMs, "long-task total"),
      longTaskMaximumMs: finiteMetric(
        snapshot.longTaskMaximumMs,
        "maximum long task",
      ),
    }));
    context.off("request", observeRequest);
    context.off("response", observeResponse);
    context.off("requestfailed", observeRequestFailure);
    const network = await captureObservedNetworkEvidence(
      sample,
      baseURL,
      build,
      navigationResponse,
      [...observedRequests],
      [...observedResponses],
      [...failedRequests],
      metrics.resourceUrls,
    );
        return Object.freeze({
          ...metrics,
          servedDocument: network.document,
          servedStaticResponses: network.staticResponses,
          resourceExclusions: network.exclusions,
          responseIntegrityFailures: network.integrityFailures,
        });
      } finally {
        context.off("request", observeRequest);
        context.off("response", observeResponse);
        context.off("requestfailed", observeRequestFailure);
        if (cdp) await cdp.detach().catch(() => undefined);
      }
    },
  );
}

function requiredMetadataString(
  testInfo: TestInfo,
  key: string,
): string {
  const value = (testInfo.config.metadata as Record<string, unknown>)[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Performance project metadata ${key} is unavailable`);
  }
  return value;
}

function invocationBuildBaseline(
  evidenceRoot: string,
  build: FileTreeManifest,
): FileTreeManifestSummary {
  const path = performanceBuildBaselinePath(evidenceRoot);
  if (!existsSync(path)) {
    try {
      publishAtomicTextExclusive(
        path,
        `${JSON.stringify({
          schemaVersion: PERFORMANCE_BUILD_PROVENANCE_SCHEMA,
          runId: E2E_RUN_ID,
          measuredAt: new Date().toISOString(),
          build: summarizeFileTree(build),
          releaseCandidateEligible: false,
        }, null, 2)}\n`,
      );
    } catch (error) {
      if (
        typeof error !== "object"
        || error === null
        || !("code" in error)
        || error.code !== "EEXIST"
      ) throw error;
    }
  }
  return readPerformanceBuildBaseline(path, E2E_RUN_ID).build;
}

function runtimeMetadata(): Readonly<Record<string, unknown>> {
  const processors = cpus();
  return Object.freeze({
    node: process.version,
    nodeVersions: Object.freeze({ ...process.versions }),
    host: Object.freeze({
      platform: platform(),
      release: release(),
      architecture: arch(),
      logicalCpuCount: processors.length,
      cpuModel: processors[0]?.model ?? "unavailable",
      totalMemoryBytes: totalmem(),
    }),
  });
}

test.describe("production-byte browser Web Vitals budget", () => {
  test.setTimeout(10 * 60_000);

  for (const environment of environments) {
    test(`performance.web-vitals.${environment.name}`, async ({
      browser,
    }, testInfo) => {
      expect(
        browser.browserType().name(),
        "The Web Vitals gate requires Chromium performance APIs and CDP throttling",
      ).toBe("chromium");
      const baseURL = testInfo.project.use.baseURL;
      if (typeof baseURL !== "string") {
        throw new Error("The Web Vitals project must provide an absolute baseURL");
      }
      const managedBuildRoot = requiredMetadataString(
        testInfo,
        "managedStaticBuildRoot",
      );
      const evidenceRoot = requiredMetadataString(
        testInfo,
        "performanceEvidenceRoot",
      );
      const buildBeforeSampling = directoryTreeManifest(managedBuildRoot);
      const sharedBuildBaseline = invocationBuildBaseline(
        evidenceRoot,
        buildBeforeSampling,
      );
      const buildMatchedBaselineBeforeSampling = sameFileTreeSummary(
        sharedBuildBaseline,
        summarizeFileTree(buildBeforeSampling),
      );

      const samples: BrowserVitalSnapshot[] = [];
      for (let sample = 1; sample <= WEB_VITAL_SAMPLE_COUNT; sample += 1) {
        samples.push(await measuredNavigation(
          browser,
          baseURL,
          environment,
          sample,
          testInfo,
          buildBeforeSampling,
        ));
      }
      const buildAfterSampling = directoryTreeManifest(managedBuildRoot);
      const buildStable = sameFileTreeSummary(
        summarizeFileTree(buildBeforeSampling),
        summarizeFileTree(buildAfterSampling),
      );
      const buildMatchedBaselineAfterSampling = sameFileTreeSummary(
        sharedBuildBaseline,
        summarizeFileTree(buildAfterSampling),
      );
      const percentiles = webVitalP75(samples);
      const budget = WEB_VITAL_BUDGETS[environment.name];
      const failures = evaluateWebVitalBudget(percentiles, budget);
      const observerErrors = [...new Set(
        samples.flatMap(({ observerErrors: errors }) => errors),
      )];
      const servedDocuments = samples.map(({ servedDocument }) => servedDocument);
      const servedStaticResponses = samples.flatMap(
        ({ servedStaticResponses: responses }) => responses,
      );
      const resourceExclusions = samples.flatMap(
        ({ resourceExclusions: exclusions }) => exclusions,
      );
      const sourceBaseline = readPerformanceSourceBaseline(
        performanceSourceBaselinePath(E2E_DATA_ROOT, E2E_RUN_ID),
        E2E_RUN_ID,
      );
      const observedSource = summarizeFileTree(sourceTreeManifest(resolve(".")));
      const sourceStable = sameFileTreeSummary(
        sourceBaseline.source,
        observedSource,
      );
      const observedStaticBytes = [
        ...servedDocuments,
        ...servedStaticResponses,
      ];
      const integrityFailures = [
        ...(sourceStable
          ? []
          : [
            `Source changed after the pre-build manifest: ${sourceBaseline.source.treeSha256} -> ${observedSource.treeSha256}`,
          ]),
        ...(buildStable
          ? []
          : [
            `Invocation-owned build changed during browser sampling: ${buildBeforeSampling.treeSha256} -> ${buildAfterSampling.treeSha256}`,
          ]),
        ...(buildMatchedBaselineBeforeSampling
          ? []
          : [
            `Invocation-owned build differed from the shared run baseline before ${environment.name} sampling: ${sharedBuildBaseline.treeSha256} -> ${buildBeforeSampling.treeSha256}`,
          ]),
        ...(buildMatchedBaselineAfterSampling
          ? []
          : [
            `Invocation-owned build differed from the shared run baseline after ${environment.name} sampling: ${sharedBuildBaseline.treeSha256} -> ${buildAfterSampling.treeSha256}`,
          ]),
        ...samples.flatMap(({ responseIntegrityFailures: sampleFailures }) =>
          sampleFailures),
        ...staticResponseIntegrityFailures(
          buildAfterSampling,
          observedStaticBytes,
        ).map((failure) => `Post-sampling manifest check: ${failure}`),
      ];
      const evidence = {
        schemaVersion: "ti-scale.web-vitals.v3",
        measuredAt: new Date().toISOString(),
        runId: E2E_RUN_ID,
        environment,
        browser: {
          name: browser.browserType().name(),
          version: browser.version(),
        },
        sampling: {
          coldContextCount: WEB_VITAL_SAMPLE_COUNT,
          percentileMethod: "nearest-rank",
          cacheDisabled: true,
          resourceTimingBufferSize: RESOURCE_TIMING_BUFFER_SIZE,
          apiSettlementQuietMs: API_SETTLEMENT_QUIET_MS,
          lcpQuietBeforeInteractionMs: LCP_QUIET_PERIOD_MS,
          userInteraction:
            "Synthetic command-palette INP: after document, fonts, Overview API work, and LCP settle, open the Command Palette, settle its exact mission/run/decision/agent inventory reads, close it with Escape, and prove the closed state remains API-quiet.",
          inpFloor:
            "When Chromium reports no event over its 16 ms Event Timing threshold, INP is conservatively recorded as 16 ms.",
        },
        budget,
        samples,
        percentiles,
        longTasks: {
          count: samples.reduce((total, sample) => total + sample.longTaskCount, 0),
          maximumMs: Math.max(...samples.map(({ longTaskMaximumMs }) => longTaskMaximumMs)),
        },
        runtime: {
          ...runtimeMetadata(),
          buildLauncher: sourceBaseline.launcher,
        },
        sourceIntegrity: {
          preBuild: sourceBaseline.source,
          postSampling: observedSource,
          stable: sourceStable,
        },
        buildIntegrity: {
          rootKind: "invocation-owned-disposable",
          invocationBaseline: sharedBuildBaseline,
          beforeSampling: summarizeFileTree(buildBeforeSampling),
          afterSampling: summarizeFileTree(buildAfterSampling),
          stable: buildStable
            && buildMatchedBaselineBeforeSampling
            && buildMatchedBaselineAfterSampling,
          completeManifest: buildAfterSampling,
        },
        observedDocuments: servedDocuments,
        observedStaticResponses: servedStaticResponses,
        resourceExclusions,
        observedResponseSetSha256: createHash("sha256")
          .update(JSON.stringify({
            documents: servedDocuments,
            staticResponses: servedStaticResponses,
            exclusions: resourceExclusions,
          }))
          .digest("hex"),
        observerErrors,
        integrityFailures,
        result: failures.length === 0
          && observerErrors.length === 0
          && integrityFailures.length === 0
          ? "pass"
          : "fail",
        failures,
        releaseAttestation: {
          releaseCandidateEligible: false,
          reason:
            "This local invocation-owned production build is performance evidence only; soak, preview acceptance, visual approval, and human sign-off remain separate gates.",
        },
      };
      const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
      const outputPath = resolve(
        evidenceRoot,
        `${environment.name}.web-vitals.json`,
      );
      publishAtomicTextExclusive(outputPath, serialized);
      await testInfo.attach(`web-vitals-${environment.name}.json`, {
        body: Buffer.from(serialized),
        contentType: "application/json",
      });

      expect(observerErrors, "Every required PerformanceObserver must initialize").toEqual([]);
      expect(
        integrityFailures,
        integrityFailures.join("\n"),
      ).toEqual([]);
      expect(
        failures,
        failures.map(({ message }) => message).join("\n"),
      ).toEqual([]);
    });
  }

  test("performance.provenance.dedicated-worker-static-response", async ({
    browser,
  }, testInfo) => {
    const baseURL = testInfo.project.use.baseURL;
    if (typeof baseURL !== "string") {
      throw new Error("The Web Vitals project must provide an absolute baseURL");
    }
    const managedBuildRoot = requiredMetadataString(
      testInfo,
      "managedStaticBuildRoot",
    );
    const evidenceRoot = requiredMetadataString(
      testInfo,
      "performanceEvidenceRoot",
    );
    const build = directoryTreeManifest(managedBuildRoot);
    expect(
      sameFileTreeSummary(invocationBuildBaseline(evidenceRoot, build), summarizeFileTree(build)),
      "The dedicated-worker coverage proof must use the invocation-wide build",
    ).toBe(true);

    await withAuditedIsolatedBrowserContext(
      browser,
      testInfo,
      {
        context: {
          storageState: E2E_AUTH_STATE,
          serviceWorkers: "allow",
        },
        audit: {
          allowEventStreamNavigationAbort: true,
        },
      },
      async ({ context, createPage }) => {
        const responses: Response[] = [];
        const target = new URL(
          `/manifest.webmanifest?worker-provenance=${encodeURIComponent(E2E_RUN_ID)}`,
          baseURL,
        ).toString();
        let workerResponseBody: Promise<Buffer> | undefined;
        const observeResponse = (response: Response): void => {
          responses.push(response);
          if (response.url() === target) {
            // Start the trusted Playwright-side body read while the dedicated
            // worker still owns its network target. The worker remains alive
            // until this promise is verified below.
            workerResponseBody = response.body();
          }
        };
        context.on("response", observeResponse);
        try {
          const page = await createPage();
          await page.goto(new URL("/", baseURL).toString(), {
            waitUntil: "domcontentloaded",
          });
          const workerState = await page.evaluateHandle(() => {
            const source = `
          self.onmessage = async (event) => {
            try {
              const response = await fetch(event.data, { cache: "no-store" });
              const bytes = await response.arrayBuffer();
              self.postMessage({ ok: response.ok, bytes: bytes.byteLength });
            } catch (error) {
              self.postMessage({ ok: false, error: String(error) });
            }
          };
        `;
            const objectUrl = URL.createObjectURL(new Blob([source], {
              type: "text/javascript",
            }));
            const worker = new Worker(objectUrl);
            return { objectUrl, worker };
          });
          try {
            const workerResult = await workerState.evaluate(async (
              { worker },
              url,
            ) => {
              return await new Promise<{
                readonly ok: boolean;
                readonly bytes?: number;
                readonly error?: string;
              }>((resolveResult, rejectResult) => {
                const timeout = window.setTimeout(() => {
                  rejectResult(new Error("Dedicated-worker fetch did not complete"));
                }, 10_000);
                worker.onmessage = (event: MessageEvent) => {
                  window.clearTimeout(timeout);
                  resolveResult(event.data);
                };
                worker.onerror = (event) => {
                  window.clearTimeout(timeout);
                  rejectResult(new Error(event.message));
                };
                worker.postMessage(url);
              });
            }, target);
            expect(workerResult.ok, workerResult.error).toBe(true);

            const response = responses.find((candidate) => candidate.url() === target);
            expect(
              response,
              "BrowserContext response capture must include dedicated-worker fetches",
            ).toBeDefined();
            const classification = classifyObservedResourceUrl(target, baseURL, build);
            expect(classification).toMatchObject({
              kind: "static-build",
              path: "manifest.webmanifest",
            });
            if (!response || classification.kind !== "static-build") {
              throw new Error("The dedicated-worker static response was not classifiable");
            }
            expect(
              workerResponseBody,
              "The dedicated-worker response body must be captured before terminating its network target",
            ).toBeDefined();
            const bytes = await workerResponseBody!;
            expect(staticResponseIntegrityFailures(build, [{
              path: classification.path,
              bytes: bytes.byteLength,
              sha256: createHash("sha256").update(bytes).digest("hex"),
            }])).toEqual([]);
          } finally {
            await workerState.evaluate(({ objectUrl, worker }) => {
              worker.terminate();
              URL.revokeObjectURL(objectUrl);
            });
            await workerState.dispose();
          }
        } finally {
          context.off("response", observeResponse);
        }
      },
    );
  });
});

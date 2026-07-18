import {
  expect,
  type APIRequestContext,
  type APIResponse,
  type BrowserContext,
  type ConsoleMessage,
  type Download,
  type Frame,
  type Page,
  type Request as PlaywrightRequest,
  type Response as PlaywrightResponse,
  type TestInfo,
  type WebError,
} from "@playwright/test";
import { randomUUID } from "node:crypto";
import {
  classifyHistoryTraversalReceipt,
  correlatableEventStreamConsoleUrl,
  isExpectedEventStreamTeardown,
  isExpectedOldDocumentOptionalImageRequest,
  isExpectedOptionalMediaNavigationTeardown,
  isExpectedWebKitDocumentFetchTeardown,
  isExpectedVerifiedDownloadNavigation,
  type BrowserIssueLike,
} from "./browserAuditPolicy";
import {
  ExpectedHttpResponseLedger,
  canonicalUrlQuery,
  type AuditedHttpMethod,
  type ExpectedHttpResponseSpec,
  type HttpResponseConsumption,
} from "./expectedHttpResponseLedger";

export type E2EAuditProfile = "development" | "release" | "degraded";
type BrowserIssue = BrowserIssueLike & {
  readonly method?: string;
  readonly status?: number;
};

export interface BrowserAuditOptions {
  readonly allowEventStreamNavigationAbort?: boolean;
  readonly verifiedDownloadPaths?: readonly string[];
  readonly expectedHttpResponses?: readonly ExpectedHttpResponseSpec[];
}

export interface DocumentNavigationTeardownOptions {
  /**
   * One exact old-document image request that this navigation is expected to
   * cancel. The declaration is prospective, page-bound, and one-shot. It may
   * remain unused when the engine finishes or never starts the lazy request;
   * bound and consumed state remains visible in the audit report.
   */
  readonly expectedPreNavigationOptionalImagePath?: string;
}

export interface PageApiSettlementOptions {
  /** Maximum time to wait for required same-origin V2 requests to finish. */
  readonly timeoutMs?: number;
  /**
   * Request-free interval required before settlement. This catches request
   * fan-out started by a component immediately after its first render.
   */
  readonly quietMs?: number;
}

export interface AuditedApiRequest {
  readonly method: AuditedHttpMethod;
  readonly url: string;
  readonly expectedResponseId?: string;
  readonly options?: Parameters<APIRequestContext["fetch"]>[1];
}

export interface BrowserAuditController {
  expectHttpResponse(page: Page, spec: ExpectedHttpResponseSpec): string;
  expectPopup(opener: Page, exactUrl: string): string;
  expectVerifiedDownload(page: Page, pathname: string): void;
  expectGeneratedDownload(page: Page, suggestedFilename: string): void;
  verifyDownload(page: Page, download: Download, pathname: string): Promise<void>;
  verifyGeneratedDownload(page: Page, download: Download, suggestedFilename: string): Promise<void>;
  request(api: APIRequestContext, audited: AuditedApiRequest): Promise<APIResponse>;
  waitForPageApiSettlement(page: Page, options?: PageApiSettlementOptions): Promise<void>;
  withExpectedDocumentNavigationTeardown<T>(
    page: Page,
    operation: () => Promise<T>,
    options?: DocumentNavigationTeardownOptions,
  ): Promise<T>;
  withExpectedHistoryTraversal<T>(page: Page, operation: () => Promise<T>): Promise<T>;
}

interface PageAuditState {
  readonly auditId: string;
  mainFrameNavigationCount: number;
}

interface ContextListenerSet {
  readonly request: (request: PlaywrightRequest) => void;
  readonly console: (message: ConsoleMessage) => void;
  readonly requestfailed: (request: PlaywrightRequest) => void;
  readonly requestfinished: (request: PlaywrightRequest) => void;
  readonly response: (response: PlaywrightResponse) => void;
  readonly weberror: (error: WebError) => void;
}

interface VerifiedDownloadExpectation {
  readonly id: string;
  readonly kind: "api-path";
  readonly pathname: string;
  readonly page: Page;
  readonly preexistingEventStreamRequests: Set<PlaywrightRequest>;
  request?: PlaywrightRequest;
  observedDownload?: Download;
  observedUrl?: string;
  verifiedUrl?: string;
  identityMode?: "request-and-download" | "download-event";
  cancellationObserved: boolean;
}

interface GeneratedDownloadExpectation {
  readonly id: string;
  readonly kind: "generated";
  readonly suggestedFilename: string;
  readonly page: Page;
  observedDownload?: Download;
  observedUrl?: string;
  verifiedUrl?: string;
}

type DownloadExpectation = VerifiedDownloadExpectation | GeneratedDownloadExpectation;

interface PopupExpectation {
  readonly id: string;
  readonly opener: Page;
  readonly exactUrl: string;
  popup?: Page;
  observedUrl?: string;
}

interface AuditedApiRequestInFlight {
  readonly id: string;
  readonly method: AuditedHttpMethod;
  readonly url: string;
  readonly completion: Promise<void>;
}

interface EventStreamRequestBoundary {
  readonly request: PlaywrightRequest;
  readonly page: Page;
  readonly frame: Frame;
  readonly url: string;
  readonly instanceOrdinal: number;
  createdReceipt?: PageBoundEventStreamCreatedReceipt;
  explicitCloseReceipt?: PageBoundEventStreamClosedReceipt;
}

interface EventStreamCancellationReceipt {
  readonly page: Page;
  readonly url: string;
  consoleObserved: boolean;
}

interface PageCloseEventStreamReceipt {
  readonly page: Page;
  readonly url: string;
}

interface NavigationBoundary {
  readonly id: string;
  readonly page: Page;
  readonly startedAtNavigationCount: number;
  readonly startingDocumentUrl: string;
  readonly preexistingRequests: Set<PlaywrightRequest>;
  readonly optionalImageExpectation?: OptionalImageNavigationExpectation;
  readonly pendingFailures: Array<{
    readonly request: PlaywrightRequest;
    readonly page: Page;
    readonly issue: BrowserIssue;
    readonly eventStream: boolean;
  }>;
  navigationObserved: boolean;
  completed: boolean;
}

interface OptionalImageNavigationExpectation {
  readonly id: string;
  readonly page: Page;
  readonly exactPath: string;
  readonly startingDocumentUrl: string;
  request?: PlaywrightRequest;
  cancellationObserved: boolean;
}

interface HistoryTraversalBoundary extends NavigationBoundary {
  readonly startingUrl: string;
  observedUrl?: string;
  documentNavigationRequest?: PlaywrightRequest;
}

interface ActiveBrowserRequest {
  readonly page: Page;
  readonly url: string;
  readonly method: string;
  readonly resourceType: string;
  readonly referrer?: string;
}

interface PendingEventStreamFailure {
  readonly request: PlaywrightRequest;
  readonly page: Page;
  readonly issue: BrowserIssue;
  readonly observedAt: number;
}

interface EventStreamLifecycleIdentity {
  readonly url: string;
  readonly documentId: string;
  readonly instanceId: string;
  readonly instanceOrdinal: number;
  readonly documentStartedAt: number;
  readonly createdAt: number;
}

interface EventStreamCreatedReceipt extends EventStreamLifecycleIdentity {
  readonly kind: "created";
}

interface EventStreamClosedReceipt extends EventStreamLifecycleIdentity {
  readonly kind: "closed";
  readonly closedAt: number;
}

type EventStreamLifecycleReceipt = EventStreamCreatedReceipt | EventStreamClosedReceipt;
type AuthenticatedEventStreamLifecycleReceipt = EventStreamLifecycleReceipt & { readonly auditToken: string };
type PageBoundEventStreamCreatedReceipt = EventStreamCreatedReceipt & { readonly page: Page; readonly frame: Frame };
type PageBoundEventStreamClosedReceipt = EventStreamClosedReceipt & { readonly page: Page; readonly frame: Frame };
type PageBoundEventStreamLifecycleReceipt =
  | PageBoundEventStreamCreatedReceipt
  | PageBoundEventStreamClosedReceipt;

interface PageBoundEventStreamLifecyclePair {
  readonly created: PageBoundEventStreamCreatedReceipt;
  readonly closed: PageBoundEventStreamClosedReceipt;
}

const EVENT_STREAM_CLOSE_RECEIPTS = "__tiScaleEventStreamCloseReceipts";
const EVENT_STREAM_LIFECYCLE_BINDING = "__tiScaleReportEventStreamLifecycle";

const sessions = new WeakMap<BrowserContext, BrowserAuditSession>();
const pendingEventStreamLifecycleReceipts = new WeakMap<
  BrowserContext,
  PageBoundEventStreamLifecycleReceipt[]
>();
const instrumentedContexts = new WeakSet<BrowserContext>();
const BROWSER_AUDIT_PAGE_CLOSE_DEADLINE_MS = 2_000;

function isEventStreamLifecycleReceipt(value: unknown): value is AuthenticatedEventStreamLifecycleReceipt {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<EventStreamLifecycleReceipt>;
  const commonValid = (candidate.kind === "created" || candidate.kind === "closed")
    && typeof (candidate as Partial<AuthenticatedEventStreamLifecycleReceipt>).auditToken === "string"
    && ((candidate as Partial<AuthenticatedEventStreamLifecycleReceipt>).auditToken?.length ?? 0) > 0
    && typeof candidate.url === "string"
    && candidate.url.length > 0
    && typeof candidate.documentId === "string"
    && candidate.documentId.length > 0
    && typeof candidate.instanceId === "string"
    && candidate.instanceId.length > 0
    && Number.isSafeInteger(candidate.instanceOrdinal)
    && (candidate.instanceOrdinal ?? 0) > 0
    && typeof candidate.documentStartedAt === "number"
    && Number.isFinite(candidate.documentStartedAt)
    && typeof candidate.createdAt === "number"
    && Number.isFinite(candidate.createdAt)
    && candidate.documentStartedAt <= candidate.createdAt;
  if (!commonValid) return false;
  return candidate.kind === "created" || (
    typeof (candidate as Partial<EventStreamClosedReceipt>).closedAt === "number"
    && Number.isFinite((candidate as Partial<EventStreamClosedReceipt>).closedAt)
    && ((candidate as Partial<EventStreamClosedReceipt>).closedAt ?? -1) >= candidate.createdAt!
  );
}

function deliverEventStreamLifecycleReceipt(
  context: BrowserContext,
  receipt: PageBoundEventStreamLifecycleReceipt,
): void {
  const session = sessions.get(context);
  if (session) {
    session.recordEventStreamLifecycleReceipt(receipt);
    return;
  }
  const pending = pendingEventStreamLifecycleReceipts.get(context) ?? [];
  pending.push(receipt);
  pendingEventStreamLifecycleReceipts.set(context, pending);
}

export function eventStreamLifecyclePairCausallyMatchesRequest(input: {
  readonly receiptUrl: string;
  readonly receiptOrdinal: number;
  readonly documentStartedAt: number;
  readonly closedAt: number;
  readonly requestUrl: string;
  readonly requestOrdinal: number;
  readonly requestStartedAt: number;
}): boolean {
  return input.receiptUrl === input.requestUrl
    && input.receiptOrdinal === input.requestOrdinal
    && Number.isFinite(input.requestStartedAt)
    && input.requestStartedAt >= input.documentStartedAt
    && input.requestStartedAt <= input.closedAt;
}

export function e2eAuditProfile(environment: NodeJS.ProcessEnv = process.env): E2EAuditProfile {
  const profile = environment.TI_SCALE_E2E_PROFILE?.trim() || "development";
  if (profile !== "development" && profile !== "release" && profile !== "degraded") {
    throw new Error(`TI_SCALE_E2E_PROFILE must be development, release, or degraded; received ${profile}`);
  }
  if (profile !== "degraded" && environment.TI_SCALE_E2E_REQUIRE_API === "0") {
    throw new Error("Required V2 API auditing can be relaxed only by the explicit degraded profile");
  }
  return profile;
}

function category(url = ""): "api" | "optional-media" | "required" {
  try {
    const pathname = new URL(url, "http://127.0.0.1").pathname;
    if (pathname.startsWith("/api/v2")) return "api";
    if (pathname.startsWith("/brand-v2/")) return "optional-media";
  } catch {
    // An unparseable URL remains required and visible in the audit.
  }
  return "required";
}

function issueForResponse(input: {
  readonly method: string;
  readonly status: number;
  readonly statusText: string;
  readonly url: string;
}): BrowserIssue {
  return {
    kind: "response",
    message: `HTTP ${input.status} ${input.statusText}`.trim(),
    url: input.url,
    method: input.method,
    status: input.status,
  };
}

function defectMessage(consumption: Exclude<HttpResponseConsumption, { kind: "ignored-success" | "consumed" }>): string {
  if (consumption.kind === "extra") {
    return `Expected failure ${consumption.expectationId} occurred more often than declared`;
  }
  if (consumption.kind === "mismatch") return consumption.mismatch.reason;
  return "HTTP failure was not declared before the request";
}

const CHROMIUM_HTTP_CONSOLE = /^Failed to load resource: the server responded with a status of (\d{3}) \([^)\r\n]+\)$/u;

/**
 * Records only explicit `EventSource.close()` calls in the owning document.
 * Navigation cancellation is correlated separately to pre-navigation request
 * identities, so this queue cannot excuse ordinary network loss or a stale
 * stream request.
 */
export async function installBrowserAuditRuntimeInstrumentation(context: BrowserContext): Promise<void> {
  if (instrumentedContexts.has(context)) return;
  const lifecycleToken = randomUUID();
  await context.exposeBinding(EVENT_STREAM_LIFECYCLE_BINDING, ({ page, frame }, value: unknown) => {
    if (!isEventStreamLifecycleReceipt(value) || value.auditToken !== lifecycleToken) {
      sessions.get(context)?.recordRuntimeInstrumentationDefect(
        page,
        "Browser audit received an unauthenticated or malformed EventSource lifecycle receipt",
      );
      return false;
    }
    const { auditToken: _, ...receipt } = value;
    deliverEventStreamLifecycleReceipt(context, { ...receipt, page, frame });
    return true;
  });
  await context.addInitScript(({ receiptKey, bindingName, lifecycleToken: privateLifecycleToken }) => {
    type RuntimeWindow = Window & Record<string, unknown>;
    type PrivateEventStreamIdentity = {
      readonly url: string;
      readonly documentId: string;
      readonly instanceId: string;
      readonly instanceOrdinal: number;
      readonly documentStartedAt: number;
      readonly createdAt: number;
      closedAt?: number;
    };
    const runtimeWindow = window as unknown as RuntimeWindow;
    runtimeWindow[receiptKey] = [];
    const reportLifecycle = runtimeWindow[bindingName] as undefined | (
      (receipt: AuthenticatedEventStreamLifecycleReceipt) => Promise<unknown>
    );
    const NativeEventSource = window.EventSource;
    const browserClock = (): number => performance.timeOrigin + performance.now();
    const documentStartedAt = performance.timeOrigin;
    const privateId = (): string => {
      if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
      const bytes = new Uint32Array(4);
      crypto.getRandomValues(bytes);
      return [...bytes].map((part) => part.toString(16).padStart(8, "0")).join("");
    };
    const documentId = privateId();
    const instanceOrdinals = new Map<string, number>();
    const privateInstances = new WeakMap<EventSource, PrivateEventStreamIdentity>();
    const sendLifecycle = (receipt: EventStreamLifecycleReceipt): void => {
      if (typeof reportLifecycle === "function") {
        void reportLifecycle({ ...receipt, auditToken: privateLifecycleToken }).catch(() => undefined);
      }
    };
    class AuditedEventSource extends NativeEventSource {
      constructor(url: string | URL, eventSourceInitDict?: EventSourceInit) {
        super(url, eventSourceInitDict);
        const nextOrdinal = (instanceOrdinals.get(this.url) ?? 0) + 1;
        instanceOrdinals.set(this.url, nextOrdinal);
        const identity: PrivateEventStreamIdentity = {
          url: this.url,
          documentId,
          instanceId: privateId(),
          instanceOrdinal: nextOrdinal,
          documentStartedAt,
          createdAt: browserClock(),
        };
        privateInstances.set(this, identity);
        sendLifecycle({ kind: "created", ...identity });
      }

      override close(): void {
        const identity = privateInstances.get(this);
        if (identity && identity.closedAt === undefined) {
          const closedAt = browserClock();
          identity.closedAt = closedAt;
          const receipts = runtimeWindow[receiptKey] as Array<{
            readonly url: string;
            readonly closedAt: number;
            readonly instanceOrdinal: number;
          }>;
          receipts.push({
            url: identity.url,
            closedAt,
            instanceOrdinal: identity.instanceOrdinal,
          });
          sendLifecycle({ kind: "closed", ...identity, closedAt });
        }
        super.close();
      }
    }
    window.EventSource = AuditedEventSource;
  }, {
    receiptKey: EVENT_STREAM_CLOSE_RECEIPTS,
    bindingName: EVENT_STREAM_LIFECYCLE_BINDING,
    lifecycleToken,
  });
  instrumentedContexts.add(context);
}

export class BrowserAuditSession {
  readonly unexpected: BrowserIssue[] = [];
  readonly degradedApi: BrowserIssue[] = [];
  readonly optionalMedia: BrowserIssue[] = [];
  readonly expectedNavigationCancellations: BrowserIssue[] = [];
  readonly expectedDownloadCancellations: BrowserIssue[] = [];
  readonly expectedHttpResponses: BrowserIssue[] = [];
  readonly expectedHttpConsoleEchoes: Array<{
    readonly issue: BrowserIssue;
    readonly expectationId: string;
    readonly occurrence: number;
  }> = [];
  readonly expectedResponseLedger: ExpectedHttpResponseLedger;

  readonly profile: E2EAuditProfile;
  readonly requireApi: boolean;

  private allowEventStreamNavigationAbort = false;
  private readonly expectedOrigin: string;
  private readonly downloadExpectations: DownloadExpectation[] = [];
  private readonly popupExpectations: PopupExpectation[] = [];
  private readonly popupNavigationRequests = new WeakMap<PlaywrightRequest, PopupExpectation>();
  private readonly pendingDownloadCancellations: Array<{
    readonly page: Page;
    readonly request: PlaywrightRequest;
    readonly expectationId: string;
    readonly issue: BrowserIssue;
  }> = [];
  private readonly pageStates = new Map<Page, PageAuditState>();
  private readonly popupListeners = new Map<Page, (popup: Page) => void>();
  private readonly downloadListeners = new Map<Page, (download: Download) => void>();
  private readonly contextListeners: ContextListenerSet;
  private readonly activeDocumentNavigationTeardown = new Map<Page, NavigationBoundary>();
  private readonly activeHistoryTraversal = new Map<Page, HistoryTraversalBoundary>();
  private readonly activeRequests = new Map<PlaywrightRequest, ActiveBrowserRequest>();
  private readonly navigationRequestBoundaries = new WeakMap<PlaywrightRequest, NavigationBoundary>();
  private readonly optionalImageNavigationExpectations: OptionalImageNavigationExpectation[] = [];
  private readonly closingPages = new Set<Page>();
  private readonly pageCloseAttempts = new WeakSet<Page>();
  private readonly pendingHttpConsoleEchoes: Array<{
    readonly issue: BrowserIssue;
    readonly status: number;
    readonly page: Page | undefined;
  }> = [];
  private readonly receiptPages = new Map<string, Page | undefined>();
  private readonly expectedResponsePages = new Map<string, Page>();
  private readonly pendingExpectedResponsePageMismatches: Array<{
    readonly issue: BrowserIssue;
    readonly expectationId: string;
    readonly occurrence: number;
    readonly expectedPage: Page;
    readonly observedPage: Page | undefined;
    readonly observedUrl: string;
  }> = [];
  private readonly eventStreamRequests = new Map<PlaywrightRequest, EventStreamRequestBoundary>();
  private readonly eventStreamRequestOrdinals = new Map<Frame, Map<string, number>>();
  private readonly eventStreamCancellations: EventStreamCancellationReceipt[] = [];
  private readonly pageCloseEventStreamReceipts: PageCloseEventStreamReceipt[] = [];
  private readonly pendingEventStreamFailures: PendingEventStreamFailure[] = [];
  private readonly pendingEventStreamCreatedReceipts: PageBoundEventStreamCreatedReceipt[] = [];
  private readonly pendingEventStreamClosedReceipts: PageBoundEventStreamClosedReceipt[] = [];
  private readonly pendingEventStreamLifecyclePairs: PageBoundEventStreamLifecyclePair[] = [];
  private readonly pendingEventStreamConsoles: Array<{ readonly page: Page | undefined; readonly issue: BrowserIssue }> = [];
  private readonly seenRequests = new WeakSet<PlaywrightRequest>();
  private readonly seenRequestFailures = new WeakSet<PlaywrightRequest>();
  private readonly seenRequestFinished = new WeakSet<PlaywrightRequest>();
  private readonly pageCloseResolvedRequests = new WeakSet<PlaywrightRequest>();
  private readonly seenResponses = new WeakSet<PlaywrightResponse>();
  private readonly seenConsoleMessages = new WeakSet<ConsoleMessage>();
  private readonly usedConsoleReceiptKeys = new Set<string>();
  private readonly inFlightApiRequests = new Map<string, AuditedApiRequestInFlight>();
  private readonly expiredApiRequestIds = new Set<string>();
  private readonly auditedApiRequestReceipts: Array<{
    readonly id: string;
    readonly method: AuditedHttpMethod;
    readonly requestedUrl: string;
    readonly responseUrl?: string;
    readonly status?: number;
    readonly outcome: "completed" | "failed";
  }> = [];
  private auditedPageCount = 0;
  private navigationBoundarySequence = 0;
  private popupExpectationSequence = 0;
  private downloadExpectationSequence = 0;
  private apiRequestSequence = 0;
  private sealed = false;
  private finalized = false;
  private readonly onContextPage: (page: Page) => void;

  private constructor(private readonly context: BrowserContext, options: BrowserAuditOptions = {}) {
    this.profile = e2eAuditProfile();
    this.requireApi = this.profile !== "degraded";
    this.expectedOrigin = new URL(
      process.env.TI_SCALE_E2E_BASE_URL ?? "http://127.0.0.1:43140",
    ).origin;
    this.expectedResponseLedger = new ExpectedHttpResponseLedger(this.expectedOrigin);
    this.contextListeners = {
      request: (request) => this.handleRequest(request),
      console: (message) => this.handleConsole(message),
      requestfailed: (request) => this.handleRequestFailed(request),
      requestfinished: (request) => this.handleRequestFinished(request),
      response: (response) => this.handleResponse(response),
      weberror: (error) => {
        const page = error.page() ?? undefined;
        if (page) this.attach(page);
        this.add(page, { kind: "pageerror", message: error.error().message });
      },
    };
    this.onContextPage = (page) => {
      if (!this.sealed) {
        this.attach(page);
        return;
      }
      if (!this.pageStates.has(page)) this.attach(page);
      void page.close().catch(() => undefined);
    };
    this.context.on("request", this.contextListeners.request);
    this.context.on("console", this.contextListeners.console);
    this.context.on("requestfailed", this.contextListeners.requestfailed);
    this.context.on("requestfinished", this.contextListeners.requestfinished);
    this.context.on("response", this.contextListeners.response);
    this.context.on("weberror", this.contextListeners.weberror);
    this.context.on("page", this.onContextPage);
    this.configure(options);
  }

  static forContext(context: BrowserContext, options: BrowserAuditOptions = {}): BrowserAuditSession {
    const existing = sessions.get(context);
    if (existing) {
      existing.configure(options);
      return existing;
    }
    const created = new BrowserAuditSession(context, options);
    sessions.set(context, created);
    for (const page of context.pages()) created.attach(page);
    for (const receipt of pendingEventStreamLifecycleReceipts.get(context) ?? []) {
      created.recordEventStreamLifecycleReceipt(receipt);
    }
    pendingEventStreamLifecycleReceipts.delete(context);
    return created;
  }

  /**
   * Receives browser-side EventSource creation and close lifecycle receipts
   * through Playwright's context binding. This path deliberately avoids
   * evaluating the page: a wedged or replacing document must never block
   * navigation or audit finalization.
   */
  recordEventStreamLifecycleReceipt(receipt: PageBoundEventStreamLifecycleReceipt): void {
    if (receipt.page.context() !== this.context) {
      this.unexpected.push({
        kind: "pageerror",
        message: "Browser audit received an EventSource lifecycle receipt from another context",
        url: receipt.url,
      });
      return;
    }
    this.attach(receipt.page);
    if (receipt.kind === "created") {
      const matchingCloseIndexes = this.pendingEventStreamClosedReceipts
        .map((closed, index) => this.eventStreamCreatedReceiptMatchesClosed(receipt, closed) ? index : -1)
        .filter((index) => index >= 0);
      if (matchingCloseIndexes.length > 1) {
        this.recordRuntimeInstrumentationDefect(
          receipt.page,
          "Browser audit found ambiguous close receipts for one private EventSource creation",
        );
      } else if (matchingCloseIndexes.length === 1) {
        const [closed] = this.pendingEventStreamClosedReceipts.splice(matchingCloseIndexes[0]!, 1);
        this.bindOrQueueEventStreamLifecyclePair({ created: receipt, closed });
      } else {
        this.pendingEventStreamCreatedReceipts.push(receipt);
      }
    } else {
      const matchingCreatedIndexes = this.pendingEventStreamCreatedReceipts
        .map((created, index) => this.eventStreamCreatedReceiptMatchesClosed(created, receipt) ? index : -1)
        .filter((index) => index >= 0);
      if (matchingCreatedIndexes.length > 1) {
        this.recordRuntimeInstrumentationDefect(
          receipt.page,
          "Browser audit found ambiguous creation receipts for one private EventSource close",
        );
      } else if (matchingCreatedIndexes.length === 1) {
        const [created] = this.pendingEventStreamCreatedReceipts.splice(matchingCreatedIndexes[0]!, 1);
        this.bindOrQueueEventStreamLifecyclePair({ created, closed: receipt });
      } else {
        // A close is never authoritative by URL or ordinal alone. It remains
        // pending until its exact private instanceId has a creation receipt.
        this.pendingEventStreamClosedReceipts.push(receipt);
      }
    }
    this.consumePendingIntentionalEventStreamFailures();
  }

  private eventStreamCreatedReceiptMatchesClosed(
    created: PageBoundEventStreamCreatedReceipt,
    closed: PageBoundEventStreamClosedReceipt,
  ): boolean {
    return created.page === closed.page
      && created.frame === closed.frame
      && created.documentId === closed.documentId
      && created.instanceId === closed.instanceId
      && created.url === closed.url
      && created.instanceOrdinal === closed.instanceOrdinal
      && created.documentStartedAt === closed.documentStartedAt
      && created.createdAt === closed.createdAt;
  }

  private eventStreamLifecyclePairMatchesBoundary(
    pair: PageBoundEventStreamLifecyclePair,
    boundary: EventStreamRequestBoundary,
  ): boolean {
    return boundary.page === pair.created.page
      && boundary.frame === pair.created.frame
      && eventStreamLifecyclePairCausallyMatchesRequest({
        receiptUrl: pair.created.url,
        receiptOrdinal: pair.created.instanceOrdinal,
        documentStartedAt: pair.created.documentStartedAt,
        closedAt: pair.closed.closedAt,
        requestUrl: boundary.url,
        requestOrdinal: boundary.instanceOrdinal,
        requestStartedAt: boundary.request.timing().startTime,
      });
  }

  private bindOrQueueEventStreamLifecyclePair(pair: PageBoundEventStreamLifecyclePair): void {
    const candidates = [...this.eventStreamRequests.values()].filter((boundary) => (
      boundary.createdReceipt === undefined
      && boundary.explicitCloseReceipt === undefined
      && this.eventStreamLifecyclePairMatchesBoundary(pair, boundary)
    ));
    if (candidates.length > 1) {
      this.recordRuntimeInstrumentationDefect(
        pair.created.page,
        "Browser audit found ambiguous requests for one private EventSource lifecycle pair",
      );
      return;
    }
    if (candidates.length === 0) {
      this.pendingEventStreamLifecyclePairs.push(pair);
      return;
    }
    candidates[0]!.createdReceipt = pair.created;
    candidates[0]!.explicitCloseReceipt = pair.closed;
  }

  private bindPendingEventStreamLifecyclePair(boundary: EventStreamRequestBoundary): void {
    if (boundary.createdReceipt !== undefined || boundary.explicitCloseReceipt !== undefined) return;
    const matchingIndexes = this.pendingEventStreamLifecyclePairs
      .map((pair, index) => this.eventStreamLifecyclePairMatchesBoundary(pair, boundary) ? index : -1)
      .filter((index) => index >= 0);
    if (matchingIndexes.length === 0) return;
    if (matchingIndexes.length > 1) {
      this.recordRuntimeInstrumentationDefect(
        boundary.page,
        `Browser audit found ambiguous private EventSource lifecycle pairs for ${boundary.url}`,
      );
      return;
    }
    const index = matchingIndexes[0]!;
    const [pair] = this.pendingEventStreamLifecyclePairs.splice(index, 1);
    boundary.createdReceipt = pair.created;
    boundary.explicitCloseReceipt = pair.closed;
  }

  recordRuntimeInstrumentationDefect(page: Page, message: string): void {
    this.attach(page);
    this.unexpected.push({ kind: "pageerror", message, url: page.url() });
  }

  configure(options: BrowserAuditOptions): void {
    if (options.allowEventStreamNavigationAbort) this.allowEventStreamNavigationAbort = true;
    if ((options.verifiedDownloadPaths?.length ?? 0) > 0) {
      throw new Error("Verified downloads must be registered through a page-bound BrowserAudit facade");
    }
    if ((options.expectedHttpResponses?.length ?? 0) > 0) {
      throw new Error("Expected HTTP responses must be registered through a page-bound BrowserAudit facade");
    }
  }

  attach(page: Page): void {
    if (this.pageStates.has(page)) return;
    if (this.sealed) {
      this.unexpected.push({
        kind: "pageerror",
        message: "A page opened after the browser audit began finalization",
        url: page.url(),
      });
    }
    const auditId = `audited-page-${this.auditedPageCount + 1}`;
    this.pageStates.set(page, {
      auditId,
      mainFrameNavigationCount: 0,
    });
    this.eventStreamRequestOrdinals.set(page.mainFrame(), new Map());
    const popupListener = (popup: Page) => this.handlePopup(page, popup);
    const downloadListener = (download: Download) => this.handleDownload(page, download);
    page.on("popup", popupListener);
    page.on("download", downloadListener);
    this.popupListeners.set(page, popupListener);
    this.downloadListeners.set(page, downloadListener);
    this.auditedPageCount += 1;
  }

  private handlePopup(opener: Page, popup: Page): void {
    this.attach(popup);
    const currentUrl = popup.url();
    const pendingForOpener = this.popupExpectations.filter((entry) => entry.opener === opener && entry.popup === undefined);
    const expectation = pendingForOpener.find((entry) => currentUrl !== "about:blank" && entry.exactUrl === currentUrl)
      ?? (currentUrl === "about:blank" ? pendingForOpener[0] : undefined);
    if (!expectation) {
      this.unexpected.push({
        kind: "pageerror",
        message: `Unsolicited popup opened from an audited page: ${currentUrl}`,
        url: currentUrl,
      });
      return;
    }
    expectation.popup = popup;
    if (currentUrl !== "about:blank") this.observePopupUrl(expectation, currentUrl);
    this.reconcileExpectedResponsePageForPopup(expectation);
  }

  private reconcileExpectedResponsePageForPopup(expectation: PopupExpectation): void {
    if (!expectation.popup) return;
    for (let index = this.pendingExpectedResponsePageMismatches.length - 1; index >= 0; index -= 1) {
      const pending = this.pendingExpectedResponsePageMismatches[index];
      if (
        !pending
        || pending.expectedPage !== expectation.opener
        || (pending.observedPage !== undefined && pending.observedPage !== expectation.popup)
        || pending.observedUrl !== expectation.exactUrl
      ) continue;
      this.pendingExpectedResponsePageMismatches.splice(index, 1);
    }
  }

  private observePopupUrl(expectation: PopupExpectation, observedUrl: string): void {
    if (expectation.observedUrl !== undefined) {
      if (expectation.observedUrl !== observedUrl) {
        this.unexpected.push({
          kind: "pageerror",
          message: `Authorized popup ${expectation.id} navigated from ${expectation.observedUrl} to undeclared ${observedUrl}`,
          url: observedUrl,
        });
      }
      return;
    }
    expectation.observedUrl = observedUrl;
    if (observedUrl !== expectation.exactUrl) {
      this.unexpected.push({
        kind: "pageerror",
        message: `Authorized popup ${expectation.id} opened ${observedUrl} instead of ${expectation.exactUrl}`,
        url: observedUrl,
      });
    }
  }

  private handleDownload(page: Page, download: Download): void {
    const url = download.url();
    const suggestedFilename = download.suggestedFilename();
    const expectation = this.downloadExpectations.find((entry) => {
      if (entry.page !== page || entry.observedDownload !== undefined) return false;
      if (entry.kind === "generated") {
        return entry.suggestedFilename === suggestedFilename && url.startsWith(`blob:${this.expectedOrigin}/`);
      }
      try {
        const parsed = new URL(url);
        return parsed.origin === this.expectedOrigin && `${parsed.pathname}${parsed.search}` === entry.pathname;
      } catch {
        return false;
      }
    });
    if (!expectation) {
      this.unexpected.push({
        kind: "requestfailed",
        message: `Download was not prospectively declared for this page: ${suggestedFilename}`,
        url,
        method: "GET",
      });
      return;
    }
    expectation.observedDownload = download;
    expectation.observedUrl = url;
  }

  private bindVerifiedDownloadRequest(page: Page, request: PlaywrightRequest): boolean {
    if (
      request.method() !== "GET"
      || !request.isNavigationRequest()
      || request.frame() !== page.mainFrame()
    ) return false;
    let parsed: URL;
    try {
      parsed = new URL(request.url());
    } catch {
      return false;
    }
    if (parsed.origin !== this.expectedOrigin) return false;
    const exactPath = `${parsed.pathname}${parsed.search}`;
    const candidates = this.downloadExpectations.filter((entry): entry is VerifiedDownloadExpectation => (
      entry.kind === "api-path"
      && entry.page === page
      && entry.pathname === exactPath
      && entry.request === undefined
      && entry.verifiedUrl === undefined
    ));
    if (candidates.length !== 1) return false;
    candidates[0]!.request = request;
    return true;
  }

  private stageVerifiedDownloadCancellation(
    page: Page,
    request: PlaywrightRequest,
    issue: BrowserIssue,
  ): boolean {
    const expectation = this.downloadExpectations.find((entry): entry is VerifiedDownloadExpectation => (
      entry.kind === "api-path"
      && entry.page === page
      && entry.request === request
    ));
    if (!expectation || !isExpectedVerifiedDownloadNavigation(
      issue,
      [expectation.pathname],
      this.expectedOrigin,
      { exactRequestAndDownloadIdentityVerified: true },
    )) return false;

    if (expectation.observedDownload !== undefined && expectation.verifiedUrl !== undefined) {
      if (expectation.cancellationObserved) {
        this.unexpected.push({ ...issue, message: `${issue.message}: duplicate verified-download navigation cancellation` });
      } else {
        expectation.cancellationObserved = true;
        this.expectedDownloadCancellations.push(issue);
        this.reconcileVerifiedDownloadEventStreamCancellations(expectation);
      }
      return true;
    }

    this.pendingDownloadCancellations.push({
      page,
      request,
      expectationId: expectation.id,
      issue,
    });
    return true;
  }

  private reconcileVerifiedDownloadEventStreamCancellations(
    expectation: VerifiedDownloadExpectation,
  ): void {
    // WebKit's provisional attachment navigation may cancel the document's
    // already-open EventSource. This is deliberately identity based: only
    // streams snapshotted before the declaration can be correlated, and only
    // after the exact request, Download object, and provisional cancellation
    // have all been verified. A replacement/reconnected stream is excluded.
    if (
      expectation.observedDownload === undefined
      || expectation.verifiedUrl === undefined
      || !expectation.cancellationObserved
    ) return;
    for (let index = this.pendingEventStreamFailures.length - 1; index >= 0; index -= 1) {
      const pending = this.pendingEventStreamFailures[index];
      if (
        !pending
        || pending.page !== expectation.page
        || !expectation.preexistingEventStreamRequests.has(pending.request)
      ) continue;
      this.pendingEventStreamFailures.splice(index, 1);
      this.acceptNavigationCancellation(pending.request, pending.page, pending.issue, true);
    }
  }

  private pageForRequest(request: PlaywrightRequest): Page | undefined {
    try {
      return request.frame().page();
    } catch {
      return undefined;
    }
  }

  private bindOptionalImageNavigationRequest(
    boundary: NavigationBoundary,
    request: PlaywrightRequest,
    active: ActiveBrowserRequest,
  ): boolean {
    const expectation = boundary.optionalImageExpectation;
    if (
      !expectation
      || expectation.request !== undefined
      || active.page !== boundary.page
      || request.isNavigationRequest()
      || request.frame() !== boundary.page.mainFrame()
      || !isExpectedOldDocumentOptionalImageRequest({
        expectedOrigin: this.expectedOrigin,
        expectedPath: expectation.exactPath,
        startingDocumentUrl: boundary.startingDocumentUrl,
        requestUrl: active.url,
        requestReferrer: active.referrer,
        method: active.method,
        resourceType: active.resourceType,
        replacementDocumentObserved: boundary.navigationObserved,
      })
    ) return false;
    expectation.request = request;
    boundary.preexistingRequests.add(request);
    this.navigationRequestBoundaries.set(request, boundary);
    return true;
  }

  private handleRequest(request: PlaywrightRequest): void {
    if (this.pageCloseResolvedRequests.has(request)) return;
    if (this.seenRequests.has(request)) return;
    this.seenRequests.add(request);
    const page = this.pageForRequest(request);
    if (request.isNavigationRequest()) {
      const popupCandidates = this.popupExpectations.filter((entry) => (
        entry.exactUrl === request.url()
        && entry.observedUrl === undefined
        && page !== entry.opener
        && (entry.popup === undefined || entry.popup === page)
      ));
      if (popupCandidates.length === 1) this.popupNavigationRequests.set(request, popupCandidates[0]!);
    }
    if (!page) return;
    this.attach(page);
    const active: ActiveBrowserRequest = {
      page,
      url: request.url(),
      method: request.method(),
      resourceType: request.resourceType(),
      referrer: request.headers()["referer"],
    };
    this.activeRequests.set(request, active);
    const state = this.pageStates.get(page)!;
    const requestFrame = request.frame();
    const activeNavigationBoundary = this.activeDocumentNavigationTeardown.get(page);
    if (activeNavigationBoundary) {
      this.bindOptionalImageNavigationRequest(activeNavigationBoundary, request, active);
    }
    const exactDeclaredDownloadRequest = this.bindVerifiedDownloadRequest(page, request);
    if (request.isNavigationRequest() && !exactDeclaredDownloadRequest) {
      // The runtime wrapper resets its ordinal map for every new frame
      // document. Mirror that identity boundary for main frames and iframes.
      this.eventStreamRequestOrdinals.set(requestFrame, new Map());
    }
    if (
      request.isNavigationRequest()
      && requestFrame === page.mainFrame()
      && !exactDeclaredDownloadRequest
    ) {
      state.mainFrameNavigationCount += 1;
      const popupExpectation = this.popupExpectations.find((entry) => entry.popup === page);
      if (popupExpectation) this.observePopupUrl(popupExpectation, request.url());
      const boundary = this.activeDocumentNavigationTeardown.get(page);
      if (boundary && state.mainFrameNavigationCount > boundary.startedAtNavigationCount) {
        boundary.navigationObserved = true;
      }
      const historyBoundary = this.activeHistoryTraversal.get(page);
      if (historyBoundary && historyBoundary.documentNavigationRequest === undefined) {
        historyBoundary.documentNavigationRequest = request;
        // Bind cancellation eligibility only after this exact main-frame
        // document request exists. Same-document and BFCache traversals never
        // receive this waiver merely because their URL changed.
        for (const preexistingRequest of historyBoundary.preexistingRequests) {
          this.navigationRequestBoundaries.set(preexistingRequest, historyBoundary);
        }
      }
    }
    try {
      const url = new URL(request.url());
      if (
        this.allowEventStreamNavigationAbort
        && request.method() === "GET"
        && url.origin === this.expectedOrigin
        && url.pathname === "/api/v2/events/stream"
      ) {
        const ordinals = this.eventStreamRequestOrdinals.get(requestFrame) ?? new Map<string, number>();
        const instanceOrdinal = (ordinals.get(url.href) ?? 0) + 1;
        ordinals.set(url.href, instanceOrdinal);
        this.eventStreamRequestOrdinals.set(requestFrame, ordinals);
        const boundary: EventStreamRequestBoundary = {
          request,
          page,
          frame: requestFrame,
          url: url.href,
          instanceOrdinal,
        };
        this.eventStreamRequests.set(request, boundary);
        this.bindPendingEventStreamLifecyclePair(boundary);
        this.consumePendingIntentionalEventStreamFailures();
      }
    } catch {
      // Unparseable request URLs remain visible if they later fail.
    }
  }

  private handleRequestFinished(request: PlaywrightRequest): void {
    if (this.seenRequestFinished.has(request)) return;
    this.seenRequestFinished.add(request);
    this.activeRequests.delete(request);
    this.eventStreamRequests.delete(request);
  }

  private handleConsole(message: ConsoleMessage): void {
    if (this.seenConsoleMessages.has(message)) return;
    this.seenConsoleMessages.add(message);
    if (message.type() !== "error") return;
    const page = message.page() ?? undefined;
    if (page) this.attach(page);
    const location = message.location();
    const text = message.text();
    const inferredUrl = location.url || text.match(/https?:\/\/[^\s)]+/u)?.[0];
    const issue = { kind: "console" as const, message: text, url: inferredUrl };
    const correlatableStreamUrl = correlatableEventStreamConsoleUrl(issue, this.expectedOrigin);
    if (isExpectedEventStreamTeardown(issue, {
      enabled: this.allowEventStreamNavigationAbort,
      expectedOrigin: this.expectedOrigin,
      requestSuperseded: true,
      pageClosing: false,
    }) || (this.allowEventStreamNavigationAbort && correlatableStreamUrl !== undefined)) {
      if (!this.consumeExpectedEventStreamConsole(page, issue)) {
        this.pendingEventStreamConsoles.push({ page, issue });
      }
      return;
    }
    const status = Number(CHROMIUM_HTTP_CONSOLE.exec(text)?.[1]);
    if (inferredUrl && Number.isInteger(status) && status >= 400 && category(inferredUrl) === "api") {
      if (!this.consumeExpectedConsoleEcho(issue, status, page)) this.pendingHttpConsoleEchoes.push({ issue, status, page });
      return;
    }
    this.add(page, issue);
  }

  private handleRequestFailed(request: PlaywrightRequest): void {
    if (this.pageCloseResolvedRequests.has(request)) {
      this.activeRequests.delete(request);
      this.eventStreamRequests.delete(request);
      return;
    }
    if (this.seenRequestFailures.has(request)) return;
    this.seenRequestFailures.add(request);
    const page = this.pageForRequest(request);
    if (page) this.attach(page);
    const issue: BrowserIssue = {
      kind: "requestfailed",
      message: request.failure()?.errorText ?? "Request failed without a browser reason",
      url: request.url(),
      method: request.method(),
    };
    const streamBoundary = this.eventStreamRequests.get(request);
    if (streamBoundary) this.bindPendingEventStreamLifecyclePair(streamBoundary);
    const navigationBoundary = this.navigationRequestBoundaries.get(request);
    const boundedPage = streamBoundary?.page ?? page;
    const activeHistoryBoundary = boundedPage === undefined
      ? undefined
      : this.activeHistoryTraversal.get(boundedPage);
    // Firefox may report an old-document cancellation just before it exposes
    // the main-frame Request for the history traversal. Stage only an exact
    // request identity that existed when this exact boundary opened; the
    // boundary later accepts it only if a document Request actually appears.
    const cancellationBoundary = navigationBoundary ?? (
      activeHistoryBoundary?.preexistingRequests.has(request)
        ? activeHistoryBoundary
        : undefined
    );
    const pageClosing = boundedPage !== undefined && this.closingPages.has(boundedPage);
    const exactStreamAbort = streamBoundary !== undefined && isExpectedEventStreamTeardown(issue, {
      enabled: this.allowEventStreamNavigationAbort,
      expectedOrigin: this.expectedOrigin,
      requestSuperseded: true,
      pageClosing: false,
    });
    const exactNavigationAbort = cancellationBoundary !== undefined && isExpectedWebKitDocumentFetchTeardown(issue, {
      enabled: true,
      expectedOrigin: this.expectedOrigin,
    });
    const exactOptionalMediaAbort = cancellationBoundary !== undefined
      && cancellationBoundary.optionalImageExpectation?.request === request
      && isExpectedOptionalMediaNavigationTeardown(issue, {
        enabled: true,
        expectedOrigin: this.expectedOrigin,
        expectedPath: cancellationBoundary.optionalImageExpectation.exactPath,
      });

    this.activeRequests.delete(request);

    if (page && this.stageVerifiedDownloadCancellation(page, request, issue)) return;

    if (cancellationBoundary && boundedPage && (exactStreamAbort || exactNavigationAbort || exactOptionalMediaAbort)) {
      if (this.navigationBoundaryCanAcceptCancellation(cancellationBoundary)) {
        this.acceptNavigationCancellation(request, boundedPage, issue, exactStreamAbort);
      } else {
        cancellationBoundary.pendingFailures.push({
          request,
          page: boundedPage,
          issue,
          eventStream: exactStreamAbort,
        });
      }
      return;
    }
    if (streamBoundary && boundedPage && exactStreamAbort && pageClosing) {
      this.acceptNavigationCancellation(request, boundedPage, issue, true);
      return;
    }
    if (streamBoundary && boundedPage && exactStreamAbort) {
      const pending = { request, page: boundedPage, issue, observedAt: Date.now() };
      if (!this.consumeIntentionalEventStreamClose(pending)) {
        this.pendingEventStreamFailures.push(pending);
        for (const expectation of this.downloadExpectations) {
          if (
            expectation.kind === "api-path"
            && expectation.page === boundedPage
            && expectation.preexistingEventStreamRequests.has(request)
          ) this.reconcileVerifiedDownloadEventStreamCancellations(expectation);
        }
      }
      return;
    }
    this.eventStreamRequests.delete(request);
    this.add(page, issue);
  }

  private handleResponse(response: PlaywrightResponse): void {
    if (this.seenResponses.has(response)) return;
    this.seenResponses.add(response);
    if (response.status() < 400) return;
    const request = response.request();
    const page = this.pageForRequest(request);
    if (page) this.attach(page);
    const issue = issueForResponse({
      method: request.method(),
      status: response.status(),
      statusText: response.statusText(),
      url: response.url(),
    });
    const consumption = this.expectedResponseLedger.observe({
      transport: "browser",
      method: request.method(),
      url: response.url(),
      status: response.status(),
    });
    if (consumption.kind === "consumed") {
      this.expectedHttpResponses.push(issue);
      const expectedPage = this.expectedResponsePages.get(consumption.receipt.expectationId);
      if (expectedPage !== undefined && expectedPage !== page) {
        const popupBoundary = this.popupNavigationRequests.get(request);
        if (!(popupBoundary && popupBoundary.opener === expectedPage && popupBoundary.exactUrl === response.url())) {
          this.pendingExpectedResponsePageMismatches.push({
            issue,
            expectationId: consumption.receipt.expectationId,
            occurrence: consumption.receipt.occurrence,
            expectedPage,
            observedPage: page,
            observedUrl: response.url(),
          });
          for (const popupExpectation of this.popupExpectations) {
            this.reconcileExpectedResponsePageForPopup(popupExpectation);
          }
        }
      }
      this.receiptPages.set(`${consumption.receipt.expectationId}\u0000${consumption.receipt.occurrence}`, page);
      this.reconcilePendingHttpConsoleEchoes();
      return;
    }
    if (consumption.kind === "extra" || consumption.kind === "mismatch") {
      this.unexpected.push({ ...issue, message: `${issue.message}: ${defectMessage(consumption)}` });
      return;
    }
    this.add(page, issue);
  }

  async withExpectedDocumentNavigationTeardown<T>(
    page: Page,
    operation: () => Promise<T>,
    options: DocumentNavigationTeardownOptions = {},
  ): Promise<T> {
    if (this.finalized || this.sealed) throw new Error("Cannot open a navigation-teardown boundary after browser-audit sealing");
    if (this.activeDocumentNavigationTeardown.has(page) || this.activeHistoryTraversal.has(page)) {
      throw new Error("A navigation boundary is already active for this page");
    }
    this.attach(page);
    // Reconcile context-bound EventSource.close() receipts before the exact
    // pre-navigation request snapshot. This never evaluates the page being
    // replaced, so a browser-world stall cannot block the navigation boundary.
    await this.reconcileIntentionalEventStreamClosuresForPage(page);
    const state = this.pageStates.get(page)!;
    const startingDocumentUrl = page.url();
    const exactOptionalImagePath = options.expectedPreNavigationOptionalImagePath === undefined
      ? undefined
      : this.validateExactOptionalImagePath(options.expectedPreNavigationOptionalImagePath);
    const optionalImageExpectation: OptionalImageNavigationExpectation | undefined = exactOptionalImagePath === undefined
      ? undefined
      : {
        id: `navigation-${this.navigationBoundarySequence + 1}:optional-image`,
        page,
        exactPath: exactOptionalImagePath,
        startingDocumentUrl,
        cancellationObserved: false,
      };
    const boundary: NavigationBoundary = {
      id: `navigation-${++this.navigationBoundarySequence}`,
      page,
      startedAtNavigationCount: state.mainFrameNavigationCount,
      startingDocumentUrl,
      preexistingRequests: new Set(),
      optionalImageExpectation,
      pendingFailures: [],
      navigationObserved: false,
      completed: false,
    };
    if (optionalImageExpectation) this.optionalImageNavigationExpectations.push(optionalImageExpectation);
    for (const [request, active] of this.activeRequests) {
      if (active.page !== page) continue;
      if (this.isNavigationTeardownEligibleApiRequest(active)) {
        boundary.preexistingRequests.add(request);
        this.navigationRequestBoundaries.set(request, boundary);
        continue;
      }
      this.bindOptionalImageNavigationRequest(boundary, request, active);
    }
    this.activeDocumentNavigationTeardown.set(page, boundary);
    let result!: T;
    let operationError: unknown;
    try {
      result = await operation();
    } catch (error) {
      operationError = error;
    } finally {
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      this.activeDocumentNavigationTeardown.delete(page);
    }
    boundary.completed = true;
    if (!boundary.navigationObserved) {
      for (const pending of boundary.pendingFailures.splice(0)) this.add(pending.page, pending.issue);
      const message = `${boundary.id} did not observe a top-level document navigation`;
      this.unexpected.push({ kind: "pageerror", message, url: page.url() });
      if (operationError === undefined) throw new Error(message);
    }
    for (const pending of boundary.pendingFailures.splice(0)) {
      this.acceptNavigationCancellation(pending.request, pending.page, pending.issue, pending.eventStream);
    }
    if (operationError !== undefined) throw operationError;
    return result;
  }

  /**
   * Wait for the exact page's required V2 API work to finish before an
   * assertion or teardown. This is deliberately audit-backed rather than a
   * `networkidle` shortcut: the event stream remains long-lived, while every
   * other same-origin `/api/v2/` request must produce its normal
   * `requestfinished`/`requestfailed` receipt. Nothing is removed from the
   * audit and a timeout reports the precise outstanding request identities.
   */
  async waitForPageApiSettlement(
    page: Page,
    options: PageApiSettlementOptions = {},
  ): Promise<void> {
    if (this.finalized || this.sealed) {
      throw new Error("Cannot wait for page API settlement after browser-audit sealing");
    }
    this.attach(page);
    const timeoutMs = options.timeoutMs ?? 10_000;
    const quietMs = options.quietMs ?? 100;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) {
      throw new Error("Page API settlement timeout must be an integer between 100 and 30000ms");
    }
    if (!Number.isSafeInteger(quietMs) || quietMs < 0 || quietMs > 1_000 || quietMs >= timeoutMs) {
      throw new Error("Page API settlement quiet period must be an integer between 0 and 1000ms and shorter than the timeout");
    }

    const startedAt = Date.now();
    let quietSince: number | undefined;
    while (Date.now() - startedAt < timeoutMs) {
      if (page.isClosed()) throw new Error("Audited page closed before its required V2 API requests settled");
      const pending = [...this.activeRequests.values()].filter((active) => {
        if (active.page !== page) return false;
        try {
          const url = new URL(active.url);
          return url.origin === this.expectedOrigin
            && url.pathname.startsWith("/api/v2/")
            && url.pathname !== "/api/v2/events/stream";
        } catch {
          return false;
        }
      });
      if (pending.length === 0) {
        quietSince ??= Date.now();
        if (Date.now() - quietSince >= quietMs) return;
      } else {
        quietSince = undefined;
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 20));
    }

    const pending = [...this.activeRequests.values()]
      .filter((active) => {
        if (active.page !== page) return false;
        try {
          const url = new URL(active.url);
          return url.origin === this.expectedOrigin
            && url.pathname.startsWith("/api/v2/")
            && url.pathname !== "/api/v2/events/stream";
        } catch {
          return false;
        }
      })
      .map((active) => `${active.method} ${active.url}`)
      .sort();
    throw new Error(
      pending.length > 0
        ? `Required V2 API requests did not settle within ${timeoutMs}ms: ${pending.join(", ")}`
        : `Required V2 API requests did not remain settled for ${quietMs}ms within the ${timeoutMs}ms boundary`,
    );
  }

  async withExpectedHistoryTraversal<T>(page: Page, operation: () => Promise<T>): Promise<T> {
    if (this.finalized || this.sealed) throw new Error("Cannot open a history-traversal boundary after browser-audit sealing");
    if (this.activeDocumentNavigationTeardown.has(page) || this.activeHistoryTraversal.has(page)) {
      throw new Error("A navigation boundary is already active for this page");
    }
    this.attach(page);
    await this.reconcileIntentionalEventStreamClosuresForPage(page);
    const state = this.pageStates.get(page)!;
    const boundary: HistoryTraversalBoundary = {
      id: `history-traversal-${++this.navigationBoundarySequence}`,
      page,
      startedAtNavigationCount: state.mainFrameNavigationCount,
      startingUrl: page.url(),
      startingDocumentUrl: page.url(),
      preexistingRequests: new Set(),
      pendingFailures: [],
      navigationObserved: false,
      completed: false,
    };
    for (const [request, active] of this.activeRequests) {
      if (active.page !== page || !this.isNavigationTeardownEligibleApiRequest(active)) continue;
      boundary.preexistingRequests.add(request);
    }
    const observeMainFrameTransition = (frame: Frame): void => {
      if (frame !== page.mainFrame() || frame.url() === boundary.startingUrl) return;
      boundary.navigationObserved = true;
      boundary.observedUrl = frame.url();
    };
    this.activeHistoryTraversal.set(page, boundary);
    page.on("framenavigated", observeMainFrameTransition);
    let result!: T;
    let operationError: unknown;
    try {
      result = await operation();
    } catch (error) {
      operationError = error;
    } finally {
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      page.off("framenavigated", observeMainFrameTransition);
      this.activeHistoryTraversal.delete(page);
    }
    boundary.completed = true;
    const receipt = classifyHistoryTraversalReceipt({
      startingUrl: boundary.startingUrl,
      observedUrl: boundary.observedUrl,
      mainFrameTransitionObserved: boundary.navigationObserved,
      documentNavigationRequestObserved: boundary.documentNavigationRequest !== undefined,
    });
    if (receipt === "missing") {
      for (const pending of boundary.pendingFailures.splice(0)) this.add(pending.page, pending.issue);
      const message = `${boundary.id} did not observe a main-frame document request or history URL transition`;
      this.unexpected.push({ kind: "pageerror", message, url: page.url() });
      if (operationError === undefined) throw new Error(message);
    } else if (receipt === "document-request") {
      for (const pending of boundary.pendingFailures.splice(0)) {
        this.acceptNavigationCancellation(pending.request, pending.page, pending.issue, pending.eventStream);
      }
    } else {
      // A same-document/BFCache receipt proves traversal, not teardown. Any
      // cancellation staged without a document request remains a real defect.
      for (const pending of boundary.pendingFailures.splice(0)) this.add(pending.page, pending.issue);
    }
    if (operationError !== undefined) throw operationError;
    return result;
  }

  async closeAuditedPage(page: Page): Promise<void> {
    if (page.isClosed() || this.pageCloseAttempts.has(page)) return;
    // Reconcile context-bound EventSource.close() receipts before taking the
    // exact page-close stream snapshot. No page-world command is required.
    await this.reconcileIntentionalEventStreamClosuresForPage(page);
    this.pageCloseAttempts.add(page);
    const pageState = this.pageStates.get(page);
    const auditId = pageState?.auditId ?? "unattached-page";
    const closingUrl = page.url();
    const exactOpenStreams = new Map<PlaywrightRequest, string>();
    const captureExactOpenStreams = (): void => {
      for (const [request, active] of this.activeRequests) {
        if (active.page !== page || this.eventStreamRequests.get(request)?.page !== page) continue;
        exactOpenStreams.set(request, active.url);
      }
    };
    captureExactOpenStreams();
    this.closingPages.add(page);
    try {
      let closeDeadline: ReturnType<typeof setTimeout> | undefined;
      const closeOutcome = await Promise.race([
        Promise.resolve()
          .then(() => page.close({ reason: `Browser audit closing ${auditId}` }))
          .then(
            () => ({ kind: "closed" as const }),
            (error: unknown) => ({ kind: "failed" as const, error }),
        ),
        new Promise<{ readonly kind: "timed-out" }>((resolve) => {
          closeDeadline = setTimeout(
            () => resolve({ kind: "timed-out" }),
            BROWSER_AUDIT_PAGE_CLOSE_DEADLINE_MS,
          );
        }),
      ]);
      if (closeDeadline) clearTimeout(closeDeadline);
      if (closeOutcome.kind === "timed-out") {
        this.unexpected.push({
          kind: "pageerror",
          message: `Browser-audit ${auditId} close exceeded the ${BROWSER_AUDIT_PAGE_CLOSE_DEADLINE_MS}ms deadline; this exact page will not be retried`,
          url: closingUrl,
        });
        return;
      }
      if (closeOutcome.kind === "failed") {
        this.unexpected.push({
          kind: "pageerror",
          message: `Browser-audit ${auditId} close failed; this exact page will not be retried: ${closeOutcome.error instanceof Error ? closeOutcome.error.message : String(closeOutcome.error)}`,
          url: closingUrl,
        });
        return;
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      // A stream may be emitted by the browser while `page.close()` is in
      // progress, after the pre-close snapshot but before the close receipt
      // resolves. It is still causally owned by this exact page and cannot
      // outlive the successful close. Capture that bounded race without
      // waiving any ordinary API request or any stream owned by another page.
      captureExactOpenStreams();
      // Firefox and WebKit do not consistently emit requestfinished or
      // requestfailed for an EventSource when the owning page closes. The
      // successful page.close() call is the lifecycle receipt, and only the
      // exact request identities observed before that call completed are
      // resolved.
      for (const [request, url] of exactOpenStreams) {
        if (!this.activeRequests.has(request)) continue;
        this.pageCloseResolvedRequests.add(request);
        this.activeRequests.delete(request);
        this.eventStreamRequests.delete(request);
        this.pageCloseEventStreamReceipts.push({ page, url });
      }
    } finally {
      this.closingPages.delete(page);
    }
  }

  private validateExactOptionalImagePath(path: string): string {
    if (!path.startsWith("/")) throw new Error("Optional-image navigation teardown requires one exact root-relative path");
    try {
      const parsed = new URL(path, this.expectedOrigin);
      if (
        parsed.origin !== this.expectedOrigin
        || parsed.hash !== ""
        || parsed.search !== ""
        || parsed.pathname !== path
        || !/^\/brand-v2\/optimized\/[A-Za-z0-9._-]+\.(?:avif|webp)$/u.test(parsed.pathname)
      ) throw new Error("invalid");
    } catch {
      throw new Error(`Invalid optional-image navigation teardown path: ${path}`);
    }
    return path;
  }

  private isNavigationTeardownEligibleApiRequest(request: ActiveBrowserRequest): boolean {
    if (request.method !== "GET") return false;
    try {
      const url = new URL(request.url);
      return url.origin === this.expectedOrigin && url.pathname.startsWith("/api/v2/");
    } catch {
      return false;
    }
  }

  private navigationBoundaryCanAcceptCancellation(boundary: NavigationBoundary): boolean {
    if ("startingUrl" in boundary) {
      return (boundary as HistoryTraversalBoundary).documentNavigationRequest !== undefined;
    }
    return boundary.navigationObserved;
  }

  private acceptNavigationCancellation(
    request: PlaywrightRequest,
    page: Page,
    issue: BrowserIssue,
    eventStream: boolean,
  ): void {
    const boundary = this.navigationRequestBoundaries.get(request);
    if (boundary?.optionalImageExpectation?.request === request) {
      boundary.optionalImageExpectation.cancellationObserved = true;
    }
    // Classification is terminal for this exact request identity. Keeping it
    // in activeRequests would report the same request both as an expected
    // lifecycle cancellation and as unresolved during audit detachment.
    this.activeRequests.delete(request);
    this.eventStreamRequests.delete(request);
    this.expectedNavigationCancellations.push(issue);
    if (!eventStream || !issue.url) return;
    this.eventStreamCancellations.push({ page, url: issue.url, consoleObserved: false });
    this.reconcilePendingEventStreamConsoles();
  }

  private async reconcileIntentionalEventStreamClosures(): Promise<void> {
    for (const page of this.pageStates.keys()) {
      await this.reconcileIntentionalEventStreamClosuresForPage(page);
    }
  }

  private async reconcileIntentionalEventStreamClosuresForPage(page: Page): Promise<void> {
    if (page.isClosed()) return;
    // Browser-side close receipts arrive through the context binding. Yield
    // once so a receipt sent by the preceding browser operation can be
    // delivered, without issuing a command into a page that may be wedged or
    // about to navigate.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    this.consumePendingIntentionalEventStreamFailures();
  }

  private consumePendingIntentionalEventStreamFailures(): void {
    for (let index = this.pendingEventStreamFailures.length - 1; index >= 0; index -= 1) {
      const failure = this.pendingEventStreamFailures[index];
      if (!failure || !this.consumeIntentionalEventStreamClose(failure)) continue;
      this.pendingEventStreamFailures.splice(index, 1);
    }
  }

  private consumeIntentionalEventStreamClose(failure: PendingEventStreamFailure): boolean {
    const boundary = this.eventStreamRequests.get(failure.request);
    if (!boundary?.explicitCloseReceipt) return false;
    this.acceptNavigationCancellation(failure.request, failure.page, failure.issue, true);
    return true;
  }

  expectHttpResponse(page: Page, spec: ExpectedHttpResponseSpec): string {
    if (this.finalized || this.sealed) throw new Error("Cannot register an expected HTTP response after browser-audit sealing");
    this.attach(page);
    const id = this.expectedResponseLedger.register(spec);
    this.expectedResponsePages.set(id, page);
    return id;
  }

  expectPopup(opener: Page, exactUrl: string): string {
    if (this.finalized || this.sealed) throw new Error("Cannot authorize a popup after browser-audit sealing");
    this.attach(opener);
    const resolved = new URL(exactUrl, this.expectedOrigin);
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") {
      throw new Error("Popup authorization requires one exact HTTP(S) URL");
    }
    if (resolved.username || resolved.password) throw new Error("Popup authorization cannot include URL credentials");
    if (this.popupExpectations.some((entry) => (
      entry.opener === opener && entry.exactUrl === resolved.href && entry.popup === undefined
    ))) throw new Error(`A popup authorization is already pending for ${resolved.href}`);
    const id = `popup-${++this.popupExpectationSequence}`;
    this.popupExpectations.push({ id, opener, exactUrl: resolved.href });
    return id;
  }

  expectVerifiedDownload(page: Page, pathname: string): void {
    if (this.finalized || this.sealed) throw new Error("Cannot register a verified download after browser-audit sealing");
    if (!pathname.startsWith("/api/v2/")) throw new Error("Verified download exceptions require an exact /api/v2/ path");
    if (pathname.includes("?")) throw new Error("Verified download exceptions must not contain an unverified query");
    this.attach(page);
    if (this.downloadExpectations.some((entry) => (
      entry.kind === "api-path" && entry.page === page && entry.pathname === pathname && entry.verifiedUrl === undefined
    ))) {
      throw new Error(`A verified download is already pending for ${pathname}`);
    }
    this.downloadExpectations.push({
      id: `download-${++this.downloadExpectationSequence}`,
      kind: "api-path",
      pathname,
      page,
      preexistingEventStreamRequests: new Set(
        [...this.eventStreamRequests.entries()]
          .filter(([request, boundary]) => boundary.page === page && this.activeRequests.has(request))
          .map(([request]) => request),
      ),
      cancellationObserved: false,
    });
  }

  expectGeneratedDownload(page: Page, suggestedFilename: string): void {
    if (this.finalized || this.sealed) throw new Error("Cannot register a generated download after browser-audit sealing");
    this.attach(page);
    if (!suggestedFilename || suggestedFilename.includes("/") || suggestedFilename.includes("\\")) {
      throw new Error("Generated downloads require one exact safe suggested filename");
    }
    if (this.downloadExpectations.some((entry) => (
      entry.kind === "generated"
      && entry.page === page
      && entry.suggestedFilename === suggestedFilename
      && entry.verifiedUrl === undefined
    ))) throw new Error(`A generated download is already pending for ${suggestedFilename}`);
    this.downloadExpectations.push({
      id: `download-${++this.downloadExpectationSequence}`,
      kind: "generated",
      suggestedFilename,
      page,
    });
  }

  async verifyDownload(page: Page, download: Download, pathname: string): Promise<void> {
    if (this.finalized || this.sealed) throw new Error("Cannot verify a download after browser-audit sealing");
    if (download.page() !== page) {
      const message = `Verified download for ${pathname} originated from a different page`;
      this.unexpected.push({ kind: "requestfailed", message, url: download.url(), method: "GET" });
      throw new Error(message);
    }
    const expectation = this.downloadExpectations.find((entry): entry is VerifiedDownloadExpectation => (
      entry.kind === "api-path"
      && entry.page === page
      && entry.pathname === pathname
      && entry.observedDownload === download
      && entry.verifiedUrl === undefined
    ));
    if (!expectation) {
      const message = `No prospectively declared page-bound download event exists for ${pathname}`;
      this.unexpected.push({ kind: "requestfailed", message, url: download.url(), method: "GET" });
      throw new Error(message);
    }
    const url = new URL(download.url());
    if (url.origin !== this.expectedOrigin || `${url.pathname}${url.search}` !== pathname) {
      const message = `Verified download resolved to ${url.href} instead of ${this.expectedOrigin}${pathname}`;
      this.unexpected.push({ kind: "requestfailed", message, url: url.href, method: "GET" });
      throw new Error(message);
    }
    // Chromium's release-static handling of an anchor with the `download`
    // attribute can emit a page-bound Playwright Download without exposing a
    // Request event at all. The Download object is still a concrete browser
    // identity, already bound prospectively to this exact page/path. Keep the
    // absence explicit: this mode can verify delivery, but cannot authorize a
    // request-failure or EventSource cancellation (those still require the
    // exact Playwright Request identity in stageVerifiedDownloadCancellation).
    expectation.identityMode = expectation.request === undefined
      ? "download-event"
      : "request-and-download";
    expectation.verifiedUrl = url.href;
    for (let index = this.pendingDownloadCancellations.length - 1; index >= 0; index -= 1) {
      const pending = this.pendingDownloadCancellations[index];
      if (
        !pending
        || pending.page !== page
        || pending.expectationId !== expectation.id
        || pending.request !== expectation.request
      ) continue;
      if (!isExpectedVerifiedDownloadNavigation(
        pending.issue,
        [pathname],
        this.expectedOrigin,
        { exactRequestAndDownloadIdentityVerified: true },
      )) continue;
      if (expectation.cancellationObserved) {
        this.unexpected.push({ ...pending.issue, message: `${pending.issue.message}: duplicate verified-download navigation cancellation` });
      } else {
        expectation.cancellationObserved = true;
        this.expectedDownloadCancellations.push(pending.issue);
      }
      this.pendingDownloadCancellations.splice(index, 1);
    }
    this.reconcileVerifiedDownloadEventStreamCancellations(expectation);
  }

  async verifyGeneratedDownload(page: Page, download: Download, suggestedFilename: string): Promise<void> {
    if (this.finalized || this.sealed) throw new Error("Cannot verify a generated download after browser-audit sealing");
    if (download.page() !== page) {
      const message = `Generated download ${suggestedFilename} originated from a different page`;
      this.unexpected.push({ kind: "requestfailed", message, url: download.url(), method: "GET" });
      throw new Error(message);
    }
    const expectation = this.downloadExpectations.find((entry): entry is GeneratedDownloadExpectation => (
      entry.kind === "generated"
      && entry.page === page
      && entry.suggestedFilename === suggestedFilename
      && entry.observedDownload === download
      && entry.verifiedUrl === undefined
    ));
    if (!expectation) {
      const message = `No prospectively declared page-bound generated download exists for ${suggestedFilename}`;
      this.unexpected.push({ kind: "requestfailed", message, url: download.url(), method: "GET" });
      throw new Error(message);
    }
    const url = download.url();
    if (!url.startsWith(`blob:${this.expectedOrigin}/`) || download.suggestedFilename() !== suggestedFilename) {
      const message = `Generated download did not match exact origin and filename declaration ${suggestedFilename}`;
      this.unexpected.push({ kind: "requestfailed", message, url, method: "GET" });
      throw new Error(message);
    }
    expectation.verifiedUrl = url;
  }

  request(api: APIRequestContext, audited: AuditedApiRequest): Promise<APIResponse> {
    if (this.finalized || this.sealed) throw new Error("Cannot issue an audited API request after browser-audit sealing");
    const requestedUrl = new URL(audited.url, this.expectedOrigin);
    if (requestedUrl.origin !== this.expectedOrigin) {
      throw new Error(`Audited API requests must stay on the exact V2 origin ${this.expectedOrigin}`);
    }
    const id = `api-request-${++this.apiRequestSequence}`;
    const execution = this.executeAuditedApiRequest(id, api, audited, requestedUrl.href);
    const completion = execution.then(
      () => undefined,
      () => undefined,
    ).finally(() => {
      this.inFlightApiRequests.delete(id);
    });
    this.inFlightApiRequests.set(id, {
      id,
      method: audited.method,
      url: requestedUrl.href,
      completion,
    });
    return execution;
  }

  private async executeAuditedApiRequest(
    id: string,
    api: APIRequestContext,
    audited: AuditedApiRequest,
    requestedUrl: string,
  ): Promise<APIResponse> {
    let response: APIResponse;
    try {
      response = await api.fetch(audited.url, {
        ...audited.options,
        method: audited.method,
      });
    } catch (error) {
      if (this.expiredApiRequestIds.has(id)) throw error;
      this.auditedApiRequestReceipts.push({
        id,
        method: audited.method,
        requestedUrl,
        outcome: "failed",
      });
      this.unexpected.push({
        kind: "requestfailed",
        message: error instanceof Error ? error.message : "Audited API request failed without an Error object",
        url: audited.url,
        method: audited.method,
      });
      throw error;
    }
    if (this.expiredApiRequestIds.has(id)) return response;
    const responseUrl = new URL(response.url());
    if (responseUrl.origin !== this.expectedOrigin) {
      this.unexpected.push({
        kind: "response",
        message: `Audited API request ${id} resolved outside the exact V2 origin`,
        url: response.url(),
        method: audited.method,
        status: response.status(),
      });
    }
    this.auditedApiRequestReceipts.push({
      id,
      method: audited.method,
      requestedUrl,
      responseUrl: response.url(),
      status: response.status(),
      outcome: "completed",
    });
    const consumption = this.expectedResponseLedger.observe({
      transport: "api-request",
      method: audited.method,
      url: response.url(),
      status: response.status(),
    }, audited.expectedResponseId);
    if (response.status() >= 400) {
      const issue = issueForResponse({
        method: audited.method,
        status: response.status(),
        statusText: response.statusText(),
        url: response.url(),
      });
      if (consumption.kind === "consumed") this.expectedHttpResponses.push(issue);
      else if (consumption.kind === "extra" || consumption.kind === "mismatch") {
        this.unexpected.push({ ...issue, message: `${issue.message}: ${defectMessage(consumption)}` });
      } else this.classify(issue);
    } else if (consumption.kind === "mismatch") {
      this.unexpected.push({
        kind: "response",
        message: `HTTP ${response.status()} did not satisfy expected failure ${audited.expectedResponseId ?? "(missing id)"}`,
        url: response.url(),
        method: audited.method,
        status: response.status(),
      });
    }
    return response;
  }

  private async drainInFlightApiRequests(deadlineMs: number): Promise<void> {
    if (this.inFlightApiRequests.size === 0) return;
    const current = [...this.inFlightApiRequests.values()];
    let timer: ReturnType<typeof setTimeout> | undefined;
    const completed = await Promise.race([
      Promise.all(current.map((entry) => entry.completion)).then(() => true),
      new Promise<false>((resolve) => { timer = setTimeout(() => resolve(false), deadlineMs); }),
    ]);
    if (timer) clearTimeout(timer);
    if (completed) return;
    for (const entry of current) {
      if (!this.inFlightApiRequests.has(entry.id)) continue;
      this.expiredApiRequestIds.add(entry.id);
      this.inFlightApiRequests.delete(entry.id);
      this.auditedApiRequestReceipts.push({
        id: entry.id,
        method: entry.method,
        requestedUrl: entry.url,
        outcome: "failed",
      });
      this.unexpected.push({
        kind: "requestfailed",
        message: `Audited API request ${entry.id} exceeded the ${deadlineMs}ms browser-audit finalization drain`,
        url: entry.url,
        method: entry.method,
      });
    }
  }

  async assertObservedClean(): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    await this.reconcileIntentionalEventStreamClosures();
    this.reconcilePendingEventStreamConsoles();
    const report = this.report();
    expect({
      unexpected: report.unexpected,
      pendingEventStreamFailures: report.pendingEventStreamFailures,
      pendingEventStreamConsoles: report.pendingEventStreamConsoles,
      extraExpectedHttpResponses: report.expectedResponseLedger.extras,
      expectedHttpResponseMismatches: report.expectedResponseLedger.mismatches,
      pendingExpectedResponsePageMismatches: report.pendingExpectedResponsePageMismatches,
      inFlightApiRequests: report.inFlightApiRequests,
      unusedPopupAuthorizations: report.popupAuthorizations.filter((entry) => entry.observedUrl === undefined),
      unverifiedDownloads: report.downloadExpectations.filter((entry) => entry.verifiedUrl === undefined),
    }, JSON.stringify(report, null, 2)).toEqual({
      unexpected: [],
      pendingEventStreamFailures: [],
      pendingEventStreamConsoles: [],
      extraExpectedHttpResponses: [],
      expectedHttpResponseMismatches: [],
      pendingExpectedResponsePageMismatches: [],
      inFlightApiRequests: [],
      unusedPopupAuthorizations: [],
      unverifiedDownloads: [],
    });
  }

  async finalize(testInfo: TestInfo): Promise<void> {
    if (this.finalized) return;
    this.sealed = true;
    const requestDrainDeadlineMs = Math.max(100, Math.min(1_000, Math.floor(testInfo.timeout * 0.05)));
    await this.drainInFlightApiRequests(requestDrainDeadlineMs);
    await this.reconcileIntentionalEventStreamClosures();
    for (const page of this.context.pages()) {
      try {
        await this.closeAuditedPage(page);
      } catch (error) {
        this.unexpected.push({
          kind: "pageerror",
          message: `Browser-audit page close failed: ${error instanceof Error ? error.message : String(error)}`,
          url: page.url(),
        });
      }
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
    this.reconcilePendingHttpConsoleEchoes();
    this.reconcilePendingEventStreamConsoles();
    for (const pending of this.pendingExpectedResponsePageMismatches.splice(0)) {
      this.unexpected.push({
        ...pending.issue,
        message: `${pending.issue.message}: expected failure ${pending.expectationId} came from an unauthorized page`,
      });
    }
    for (const pending of this.pendingHttpConsoleEchoes.splice(0)) this.classify(pending.issue);
    for (const pending of this.pendingEventStreamConsoles.splice(0)) this.classify(pending.issue);
    for (const pending of this.pendingEventStreamFailures.splice(0)) {
      this.classify({
        ...pending.issue,
        message: `${pending.issue.message} [tracked EventSource request had no correlated close, navigation, or page-close receipt]`,
      });
    }
    for (const pending of this.pendingDownloadCancellations.splice(0)) this.classify(pending.issue);
    for (const active of this.activeRequests.values()) {
      this.unexpected.push({
        kind: "requestfailed",
        message: "Browser audit detached with an unresolved request",
        url: active.url,
        method: active.method,
      });
    }
    this.detachListeners();
    this.finalized = true;
    const report = this.report();
    await testInfo.attach("browser-audit.json", {
      body: Buffer.from(JSON.stringify(report, null, 2)),
      contentType: "application/json",
    });
    expect({
      unexpected: report.unexpected,
      pendingEventStreamFailures: report.pendingEventStreamFailures,
      extraExpectedHttpResponses: report.expectedResponseLedger.extras,
      expectedHttpResponseMismatches: report.expectedResponseLedger.mismatches,
      unexpectedLedgerResponses: report.expectedResponseLedger.unexpected,
      unusedExpectedHttpResponses: report.expectedResponseLedger.unused,
      inFlightApiRequests: report.inFlightApiRequests,
      unusedPopupAuthorizations: report.popupAuthorizations.filter((entry) => entry.observedUrl === undefined),
      unverifiedDownloads: report.downloadExpectations.filter((entry) => entry.verifiedUrl === undefined),
    }, JSON.stringify(report, null, 2)).toEqual({
      unexpected: [],
      pendingEventStreamFailures: [],
      extraExpectedHttpResponses: [],
      expectedHttpResponseMismatches: [],
      unexpectedLedgerResponses: [],
      unusedExpectedHttpResponses: [],
      inFlightApiRequests: [],
      unusedPopupAuthorizations: [],
      unverifiedDownloads: [],
    });
  }

  dispose(): void {
    this.sealed = true;
    this.detachListeners();
    sessions.delete(this.context);
  }

  private detachListeners(): void {
    this.context.off("page", this.onContextPage);
    this.context.off("request", this.contextListeners.request);
    this.context.off("console", this.contextListeners.console);
    this.context.off("requestfailed", this.contextListeners.requestfailed);
    this.context.off("requestfinished", this.contextListeners.requestfinished);
    this.context.off("response", this.contextListeners.response);
    this.context.off("weberror", this.contextListeners.weberror);
    for (const [page, listener] of this.popupListeners) page.off("popup", listener);
    for (const [page, listener] of this.downloadListeners) page.off("download", listener);
    this.popupListeners.clear();
    this.downloadListeners.clear();
    this.eventStreamRequestOrdinals.clear();
    this.pageStates.clear();
    this.activeRequests.clear();
  }

  private add(page: Page | undefined, issue: BrowserIssue): void {
    this.classify(issue);
  }

  private classify(issue: BrowserIssue): void {
    const requestCategory = category(issue.url);
    if (this.profile === "degraded" && requestCategory === "api") this.degradedApi.push(issue);
    else if (this.profile === "degraded" && requestCategory === "optional-media") this.optionalMedia.push(issue);
    else this.unexpected.push(issue);
  }

  private consumeExpectedConsoleEcho(issue: BrowserIssue, status: number, page: Page | undefined): boolean {
    if (!issue.url) return false;
    const parsed = new URL(issue.url, "http://127.0.0.1");
    const query = canonicalUrlQuery(parsed.href);
    const exactUnusedReceipts = this.expectedResponseLedger.receipts.filter((receipt) => {
      if (
        receipt.transport !== "browser"
        || receipt.status !== status
        || receipt.pathname !== parsed.pathname
        || receipt.query !== query
      ) return false;
      const key = `${receipt.expectationId}\u0000${receipt.occurrence}`;
      return this.receiptPages.has(key) && !this.usedConsoleReceiptKeys.has(key);
    });
    const samePageReceipts = page === undefined ? [] : exactUnusedReceipts.filter((receipt) => (
      this.receiptPages.get(`${receipt.expectationId}\u0000${receipt.occurrence}`) === page
    ));
    const candidates = samePageReceipts.length > 0
      ? samePageReceipts
      : exactUnusedReceipts.length === 1
        ? exactUnusedReceipts
        : [];
    // Some engines omit or misattribute ConsoleMessage.page() for a top-level
    // popup response. Fall back only when the exact URL/status has one and
    // only one unused receipt; cross-page ambiguity remains release-failing.
    if (candidates.length !== 1) return false;
    const receipt = candidates[0]!;
    const key = `${receipt.expectationId}\u0000${receipt.occurrence}`;
    this.usedConsoleReceiptKeys.add(key);
    this.expectedHttpConsoleEchoes.push({
      issue,
      expectationId: receipt.expectationId,
      occurrence: receipt.occurrence,
    });
    return true;
  }

  private consumeExpectedEventStreamConsole(page: Page | undefined, issue: BrowserIssue): boolean {
    const streamUrl = correlatableEventStreamConsoleUrl(issue, this.expectedOrigin);
    if (page === undefined || streamUrl === undefined) return false;
    const samePageAndUrl = this.eventStreamCancellations.filter((entry) => (
      entry.page === page && entry.url === streamUrl && !entry.consoleObserved
    ));
    // Firefox emits these messages in request-cancellation order. Consume the
    // oldest unused receipt for the exact page and exact stream URL so several
    // deliberate document navigations remain individually accounted for.
    const receipt = samePageAndUrl[0];
    if (!receipt) return false;
    receipt.consoleObserved = true;
    this.expectedNavigationCancellations.push(issue);
    return true;
  }

  private reconcilePendingEventStreamConsoles(): void {
    for (let index = this.pendingEventStreamConsoles.length - 1; index >= 0; index -= 1) {
      const pending = this.pendingEventStreamConsoles[index];
      if (!pending || !this.consumeExpectedEventStreamConsole(pending.page, pending.issue)) continue;
      this.pendingEventStreamConsoles.splice(index, 1);
    }
  }

  private reconcilePendingHttpConsoleEchoes(): void {
    for (let index = this.pendingHttpConsoleEchoes.length - 1; index >= 0; index -= 1) {
      const pending = this.pendingHttpConsoleEchoes[index];
      if (!pending || !this.consumeExpectedConsoleEcho(pending.issue, pending.status, pending.page)) continue;
      this.pendingHttpConsoleEchoes.splice(index, 1);
    }
  }

  private report() {
    return {
      profile: this.profile,
      requireApi: this.requireApi,
      pagesAudited: this.auditedPageCount,
      unexpected: this.unexpected,
      degradedApi: this.degradedApi,
      optionalMedia: this.optionalMedia,
      expectedNavigationCancellations: this.expectedNavigationCancellations,
      expectedDownloadCancellations: this.expectedDownloadCancellations,
      expectedHttpResponses: this.expectedHttpResponses,
      expectedHttpConsoleEchoes: this.expectedHttpConsoleEchoes,
      pendingHttpConsoleEchoes: this.pendingHttpConsoleEchoes,
      pendingExpectedResponsePageMismatches: this.pendingExpectedResponsePageMismatches.map((entry) => ({
        expectationId: entry.expectationId,
        occurrence: entry.occurrence,
        observedUrl: entry.observedUrl,
      })),
      pendingEventStreamConsoles: this.pendingEventStreamConsoles,
      pendingEventStreamFailures: this.pendingEventStreamFailures.map((entry) => ({
        issue: entry.issue,
        observedAt: entry.observedAt,
      })),
      unresolvedRequests: [...this.activeRequests.values()].map(({ url, method }) => ({ url, method })),
      eventStreamCancellations: this.eventStreamCancellations.map((entry) => ({
        url: entry.url,
        consoleObserved: entry.consoleObserved,
      })),
      pageCloseEventStreamReceipts: this.pageCloseEventStreamReceipts.map((entry) => ({ url: entry.url })),
      optionalImageNavigationExpectations: this.optionalImageNavigationExpectations.map((entry) => ({
        id: entry.id,
        exactPath: entry.exactPath,
        startingDocumentUrl: entry.startingDocumentUrl,
        requestBound: entry.request !== undefined,
        cancellationObserved: entry.cancellationObserved,
      })),
      unmatchedEventStreamCreatedReceipts: this.pendingEventStreamCreatedReceipts.map((entry) => ({
        url: entry.url,
        instanceOrdinal: entry.instanceOrdinal,
        documentStartedAt: entry.documentStartedAt,
        createdAt: entry.createdAt,
      })),
      unmatchedIntentionalEventStreamCloseReceipts: this.pendingEventStreamClosedReceipts.map((entry) => ({
        url: entry.url,
        closedAt: entry.closedAt,
        instanceOrdinal: entry.instanceOrdinal,
        documentStartedAt: entry.documentStartedAt,
        createdAt: entry.createdAt,
      })),
      unmatchedEventStreamLifecyclePairs: this.pendingEventStreamLifecyclePairs.map((entry) => ({
        url: entry.created.url,
        instanceOrdinal: entry.created.instanceOrdinal,
        documentStartedAt: entry.created.documentStartedAt,
        createdAt: entry.created.createdAt,
        closedAt: entry.closed.closedAt,
      })),
      unboundEventStreamRequests: [...this.eventStreamRequests.values()]
        .filter((entry) => entry.createdReceipt === undefined || entry.explicitCloseReceipt === undefined)
        .map((entry) => ({
          url: entry.url,
          instanceOrdinal: entry.instanceOrdinal,
          requestStartedAt: entry.request.timing().startTime,
        })),
      popupAuthorizations: this.popupExpectations.map((entry) => ({
        id: entry.id,
        exactUrl: entry.exactUrl,
        observedUrl: entry.observedUrl,
      })),
      downloadExpectations: this.downloadExpectations.map((entry) => entry.kind === "api-path" ? {
        id: entry.id,
        kind: entry.kind,
        pathname: entry.pathname,
        observedUrl: entry.observedUrl,
        verifiedUrl: entry.verifiedUrl,
        identityMode: entry.identityMode,
        requestIdentityUnavailable: entry.identityMode === undefined
          ? undefined
          : entry.identityMode === "download-event",
        cancellationObserved: entry.cancellationObserved,
        preexistingEventStreamRequestCount: entry.preexistingEventStreamRequests.size,
      } : {
        id: entry.id,
        kind: entry.kind,
        suggestedFilename: entry.suggestedFilename,
        observedUrl: entry.observedUrl,
        verifiedUrl: entry.verifiedUrl,
      }),
      inFlightApiRequests: [...this.inFlightApiRequests.values()].map(({ id, method, url }) => ({ id, method, url })),
      auditedApiRequestReceipts: this.auditedApiRequestReceipts,
      expectedResponseLedger: {
        declarations: this.expectedResponseLedger.report(),
        receipts: this.expectedResponseLedger.receipts,
        extras: this.expectedResponseLedger.extras,
        mismatches: this.expectedResponseLedger.mismatches,
        unexpected: this.expectedResponseLedger.unexpected,
        unused: this.expectedResponseLedger.unused(),
      },
    };
  }
}

/**
 * Compatibility facade for existing tests. Every facade for a context shares
 * one session and therefore installs no duplicate listeners or partial audit
 * windows. New tests should prefer the automatic `browserAudit` fixture.
 */
export class BrowserAudit {
  private readonly session: BrowserAuditSession;

  constructor(private readonly page: Page, options: BrowserAuditOptions = {}) {
    const { verifiedDownloadPaths = [], expectedHttpResponses = [], ...sessionOptions } = options;
    this.session = BrowserAuditSession.forContext(page.context(), sessionOptions);
    this.session.attach(page);
    for (const pathname of verifiedDownloadPaths) this.session.expectVerifiedDownload(page, pathname);
    for (const expected of expectedHttpResponses) this.session.expectHttpResponse(page, expected);
  }

  get unexpected(): readonly BrowserIssue[] { return this.session.unexpected; }
  get degradedApi(): readonly BrowserIssue[] { return this.session.degradedApi; }
  get optionalMedia(): readonly BrowserIssue[] { return this.session.optionalMedia; }
  get expectedNavigationCancellations(): readonly BrowserIssue[] { return this.session.expectedNavigationCancellations; }
  get expectedDownloadCancellations(): readonly BrowserIssue[] { return this.session.expectedDownloadCancellations; }
  get expectedHttpResponses(): readonly BrowserIssue[] { return this.session.expectedHttpResponses; }

  expectHttpResponse(spec: ExpectedHttpResponseSpec): string { return this.session.expectHttpResponse(this.page, spec); }
  expectPopup(exactUrl: string): string { return this.session.expectPopup(this.page, exactUrl); }
  expectVerifiedDownload(pathname: string): void { this.session.expectVerifiedDownload(this.page, pathname); }
  expectGeneratedDownload(suggestedFilename: string): void {
    this.session.expectGeneratedDownload(this.page, suggestedFilename);
  }
  verifyDownload(download: Download, pathname: string): Promise<void> {
    return this.session.verifyDownload(this.page, download, pathname);
  }
  verifyGeneratedDownload(download: Download, suggestedFilename: string): Promise<void> {
    return this.session.verifyGeneratedDownload(this.page, download, suggestedFilename);
  }
  request(api: APIRequestContext, audited: AuditedApiRequest): Promise<APIResponse> { return this.session.request(api, audited); }
  waitForPageApiSettlement(page: Page, options?: PageApiSettlementOptions): Promise<void> {
    return this.session.waitForPageApiSettlement(page, options);
  }
  withExpectedDocumentNavigationTeardown<T>(
    page: Page,
    operation: () => Promise<T>,
    options?: DocumentNavigationTeardownOptions,
  ): Promise<T> {
    return this.session.withExpectedDocumentNavigationTeardown(page, operation, options);
  }
  withExpectedHistoryTraversal<T>(page: Page, operation: () => Promise<T>): Promise<T> {
    return this.session.withExpectedHistoryTraversal(page, operation);
  }

  async assertClean(_testInfo: TestInfo): Promise<void> {
    await this.session.assertObservedClean();
  }
}

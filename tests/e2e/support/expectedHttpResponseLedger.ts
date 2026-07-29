export type HttpTransport = "browser" | "api-request";

export type AuditedHttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

export type ExactQuery = Readonly<Record<string, string | readonly string[]>>;

export interface ExpectedHttpResponseSpec {
  readonly id: string;
  readonly transport: HttpTransport;
  readonly method: AuditedHttpMethod;
  readonly pathname: string;
  /** Exact query parameters. An empty object explicitly means no query. */
  readonly query: ExactQuery;
  readonly status: number;
  readonly occurrences: number;
  readonly reason: string;
}

export interface HttpResponseObservation {
  readonly transport: HttpTransport;
  readonly method: string;
  readonly url: string;
  readonly status: number;
}

export interface ExpectedHttpResponseReceipt {
  readonly expectationId: string;
  readonly occurrence: number;
  readonly transport: HttpTransport;
  readonly method: AuditedHttpMethod;
  readonly origin: string;
  readonly pathname: string;
  readonly query: string;
  readonly status: number;
  readonly observedUrl: string;
}

export interface ExpectedHttpResponseReportEntry {
  readonly spec: ExpectedHttpResponseSpec;
  readonly expectedOrigin?: string;
  readonly canonicalQuery: string;
  readonly consumed: number;
  readonly remaining: number;
}

export interface ExpectedHttpResponseMismatch {
  readonly expectationId: string;
  readonly expected: ExpectedHttpResponseReportEntry;
  readonly observed: ReturnType<typeof normalizeObservation>;
  readonly reason: string;
}

export type HttpResponseConsumption =
  | { readonly kind: "ignored-success" }
  | { readonly kind: "consumed"; readonly receipt: ExpectedHttpResponseReceipt }
  | { readonly kind: "extra"; readonly observed: ReturnType<typeof normalizeObservation>; readonly expectationId: string }
  | { readonly kind: "mismatch"; readonly mismatch: ExpectedHttpResponseMismatch }
  | { readonly kind: "unexpected"; readonly observed: ReturnType<typeof normalizeObservation> };

interface MutableExpectation {
  readonly spec: ExpectedHttpResponseSpec;
  readonly canonicalQuery: string;
  consumed: number;
}

function validId(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{2,159}$/u.test(value);
}

function normalizeMethod(method: string): AuditedHttpMethod {
  const normalized = method.trim().toUpperCase();
  if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(normalized)) {
    throw new Error(`Unsupported audited HTTP method: ${method}`);
  }
  return normalized as AuditedHttpMethod;
}

function entriesFromQuery(query: ExactQuery): [string, string][] {
  const entries: [string, string][] = [];
  for (const [key, rawValue] of Object.entries(query)) {
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    for (const value of values) entries.push([key, String(value)]);
  }
  return entries;
}

function canonicalEntries(entries: readonly [string, string][]): string {
  return [...entries]
    .sort(([leftKey, leftValue], [rightKey, rightValue]) =>
      leftKey.localeCompare(rightKey) || leftValue.localeCompare(rightValue))
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
}

export function canonicalQuery(query: ExactQuery): string {
  return canonicalEntries(entriesFromQuery(query));
}

export function canonicalUrlQuery(url: string): string {
  const parsed = new URL(url, "http://127.0.0.1");
  return canonicalEntries([...parsed.searchParams.entries()]);
}

function signature(input: {
  readonly transport: HttpTransport;
  readonly method: string;
  readonly origin?: string;
  readonly pathname: string;
  readonly query: string;
  readonly status: number;
}): string {
  return [input.transport, normalizeMethod(input.method), input.origin ?? "", input.pathname, input.query, input.status].join("\u0000");
}

export function normalizeObservation(observation: HttpResponseObservation): {
  readonly transport: HttpTransport;
  readonly method: AuditedHttpMethod;
  readonly origin: string;
  readonly pathname: string;
  readonly query: string;
  readonly status: number;
  readonly url: string;
} {
  const parsed = new URL(observation.url, "http://127.0.0.1");
  return {
    transport: observation.transport,
    method: normalizeMethod(observation.method),
    origin: parsed.origin,
    pathname: parsed.pathname,
    query: canonicalUrlQuery(parsed.href),
    status: observation.status,
    url: parsed.href,
  };
}

function validateSpec(spec: ExpectedHttpResponseSpec): ExpectedHttpResponseSpec {
  if (!validId(spec.id)) throw new Error(`Expected HTTP response id is invalid: ${spec.id}`);
  if (!spec.pathname.startsWith("/api/v2/")) {
    throw new Error(`Expected HTTP response ${spec.id} must use an exact /api/v2/ pathname`);
  }
  if (!Number.isInteger(spec.status) || spec.status < 400 || spec.status > 599) {
    throw new Error(`Expected HTTP response ${spec.id} must use a 4xx or 5xx status`);
  }
  if (!Number.isInteger(spec.occurrences) || spec.occurrences < 1 || spec.occurrences > 20) {
    throw new Error(`Expected HTTP response ${spec.id} occurrences must be between 1 and 20`);
  }
  if (spec.reason.trim().length < 12) {
    throw new Error(`Expected HTTP response ${spec.id} requires a precise reason`);
  }
  normalizeMethod(spec.method);
  canonicalQuery(spec.query);
  return spec;
}

export class ExpectedHttpResponseLedger {
  readonly receipts: ExpectedHttpResponseReceipt[] = [];
  readonly extras: Array<{ readonly expectationId: string; readonly observed: ReturnType<typeof normalizeObservation> }> = [];
  readonly mismatches: ExpectedHttpResponseMismatch[] = [];
  readonly unexpected: Array<ReturnType<typeof normalizeObservation>> = [];

  private readonly byId = new Map<string, MutableExpectation>();
  private readonly bySignature = new Map<string, MutableExpectation>();

  readonly expectedOrigin?: string;

  constructor(expectedOrigin?: string) {
    if (expectedOrigin === undefined) return;
    const parsed = new URL(expectedOrigin);
    if (parsed.origin === "null") throw new Error(`Expected HTTP response origin is invalid: ${expectedOrigin}`);
    this.expectedOrigin = parsed.origin;
  }

  register(spec: ExpectedHttpResponseSpec): string {
    validateSpec(spec);
    if (this.byId.has(spec.id)) throw new Error(`Duplicate expected HTTP response id: ${spec.id}`);
    const canonical = canonicalQuery(spec.query);
    const key = signature({ ...spec, origin: this.expectedOrigin, query: canonical });
    if (this.bySignature.has(key)) {
      throw new Error(`Ambiguous expected HTTP response signature for ${spec.id}; use one entry with an exact occurrence count`);
    }
    const entry: MutableExpectation = { spec, canonicalQuery: canonical, consumed: 0 };
    this.byId.set(spec.id, entry);
    this.bySignature.set(key, entry);
    return spec.id;
  }

  observe(observation: HttpResponseObservation, expectationId?: string): HttpResponseConsumption {
    const normalized = normalizeObservation(observation);
    if (observation.status < 400 && !expectationId) return { kind: "ignored-success" };
    if (expectationId) {
      const expected = this.byId.get(expectationId);
      if (!expected) {
        const mismatch: ExpectedHttpResponseMismatch = {
          expectationId,
          expected: {
            spec: {
              id: expectationId,
              transport: normalized.transport,
              method: normalized.method,
              pathname: normalized.pathname,
              query: {},
              status: normalized.status,
              occurrences: 0,
              reason: "Expectation id was not registered before the request.",
            },
            expectedOrigin: this.expectedOrigin,
            canonicalQuery: "",
            consumed: 0,
            remaining: 0,
          },
          observed: normalized,
          reason: "Expectation id was not registered before the request.",
        };
        this.mismatches.push(mismatch);
        return { kind: "mismatch", mismatch };
      }
      const expectedSignature = signature({
        ...expected.spec,
        origin: this.expectedOrigin,
        query: expected.canonicalQuery,
      });
      const observedSignature = signature({
        ...normalized,
        origin: this.expectedOrigin === undefined ? undefined : normalized.origin,
      });
      if (expectedSignature !== observedSignature) {
        const mismatch: ExpectedHttpResponseMismatch = {
          expectationId,
          expected: this.reportEntry(expected),
          observed: normalized,
          reason: "Observed origin, method, path, query, transport, or status did not match the declared failure.",
        };
        this.mismatches.push(mismatch);
        return { kind: "mismatch", mismatch };
      }
    }

    if (observation.status < 400) return { kind: "ignored-success" };

    const key = signature({
      ...normalized,
      origin: this.expectedOrigin === undefined ? undefined : normalized.origin,
    });
    const expected = this.bySignature.get(key);
    if (!expected) {
      this.unexpected.push(normalized);
      return { kind: "unexpected", observed: normalized };
    }
    if (expected.consumed >= expected.spec.occurrences) {
      const extra = { expectationId: expected.spec.id, observed: normalized };
      this.extras.push(extra);
      return { kind: "extra", ...extra };
    }
    expected.consumed += 1;
    const receipt: ExpectedHttpResponseReceipt = {
      expectationId: expected.spec.id,
      occurrence: expected.consumed,
      transport: normalized.transport,
      method: normalized.method,
      origin: normalized.origin,
      pathname: normalized.pathname,
      query: normalized.query,
      status: normalized.status,
      observedUrl: normalized.url,
    };
    this.receipts.push(receipt);
    return { kind: "consumed", receipt };
  }

  report(): ExpectedHttpResponseReportEntry[] {
    return [...this.byId.values()].map((entry) => this.reportEntry(entry));
  }

  unused(): ExpectedHttpResponseReportEntry[] {
    return this.report().filter((entry) => entry.remaining > 0);
  }

  hasObservedDefects(): boolean {
    return this.extras.length > 0 || this.mismatches.length > 0 || this.unexpected.length > 0;
  }

  hasFinalDefects(): boolean {
    return this.hasObservedDefects() || this.unused().length > 0;
  }

  private reportEntry(entry: MutableExpectation): ExpectedHttpResponseReportEntry {
    return {
      spec: entry.spec,
      expectedOrigin: this.expectedOrigin,
      canonicalQuery: entry.canonicalQuery,
      consumed: entry.consumed,
      remaining: entry.spec.occurrences - entry.consumed,
    };
  }
}

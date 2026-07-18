import { describe, expect, test } from "bun:test";
import {
  ExpectedHttpResponseLedger,
  canonicalQuery,
  type ExpectedHttpResponseSpec,
} from "../../e2e/support/expectedHttpResponseLedger";

const expected = (overrides: Partial<ExpectedHttpResponseSpec> = {}): ExpectedHttpResponseSpec => ({
  id: "brain.summary.initial-unavailable",
  transport: "browser",
  method: "GET",
  pathname: "/api/v2/brain/summary",
  query: {},
  status: 503,
  occurrences: 1,
  reason: "Exercise the precise retry state once.",
  ...overrides,
});

describe("exact expected HTTP response ledger", () => {
  test("consumes one exact browser failure and emits a receipt", () => {
    const ledger = new ExpectedHttpResponseLedger();
    ledger.register(expected());
    expect(ledger.observe({
      transport: "browser",
      method: "GET",
      url: "http://127.0.0.1:43140/api/v2/brain/summary",
      status: 503,
    }).kind).toBe("consumed");
    expect(ledger.receipts).toEqual([expect.objectContaining({
      expectationId: "brain.summary.initial-unavailable",
      occurrence: 1,
      origin: "http://127.0.0.1:43140",
      query: "",
    })]);
    expect(ledger.unused()).toEqual([]);
    expect(ledger.hasFinalDefects()).toBe(false);
  });

  test("canonicalizes query key, value, and duplicate ordering", () => {
    expect(canonicalQuery({ state: ["z", "a"], limit: "20" })).toBe("limit=20&state=a&state=z");
    const ledger = new ExpectedHttpResponseLedger();
    ledger.register(expected({
      id: "metrics.initial-unavailable",
      pathname: "/api/v2/runs/run-one/intelligence/metrics/snapshots",
      query: { state: ["z", "a"], limit: "20" },
    }));
    expect(ledger.observe({
      transport: "browser",
      method: "get",
      url: "http://127.0.0.1/api/v2/runs/run-one/intelligence/metrics/snapshots?state=a&limit=20&state=z",
      status: 503,
    }).kind).toBe("consumed");
  });

  test("records wrong method, path, query, transport, and status as exact mismatches", () => {
    const variants = [
      { transport: "browser" as const, method: "POST", url: "http://local/api/v2/brain/summary", status: 503 },
      { transport: "browser" as const, method: "GET", url: "http://local/api/v2/brain/nodes", status: 503 },
      { transport: "browser" as const, method: "GET", url: "http://local/api/v2/brain/summary?limit=1", status: 503 },
      { transport: "api-request" as const, method: "GET", url: "http://local/api/v2/brain/summary", status: 503 },
      { transport: "browser" as const, method: "GET", url: "http://local/api/v2/brain/summary", status: 500 },
    ];
    for (const [index, observation] of variants.entries()) {
      const ledger = new ExpectedHttpResponseLedger();
      const id = `brain.summary.mismatch-${index}`;
      ledger.register(expected({ id }));
      expect(ledger.observe(observation, id).kind).toBe("mismatch");
      expect(ledger.mismatches).toHaveLength(1);
      expect(ledger.unused()).toHaveLength(1);
    }
  });

  test("does not let an identical external browser response consume an origin-bound declaration", () => {
    const ledger = new ExpectedHttpResponseLedger("http://127.0.0.1:43140");
    ledger.register(expected());

    const result = ledger.observe({
      transport: "browser",
      method: "GET",
      url: "https://external.example/api/v2/brain/summary",
      status: 503,
    });

    expect(result.kind).toBe("unexpected");
    expect(ledger.receipts).toEqual([]);
    expect(ledger.unexpected).toEqual([expect.objectContaining({
      origin: "https://external.example",
      pathname: "/api/v2/brain/summary",
      status: 503,
    })]);
    expect(ledger.unused()).toEqual([expect.objectContaining({
      expectedOrigin: "http://127.0.0.1:43140",
      consumed: 0,
      remaining: 1,
    })]);
  });

  test("records a foreign-origin direct API response as an explicit expectation mismatch", () => {
    const ledger = new ExpectedHttpResponseLedger("http://127.0.0.1:43140/api/v2/");
    const id = ledger.register(expected({ transport: "api-request" }));

    const result = ledger.observe({
      transport: "api-request",
      method: "GET",
      url: "http://127.0.0.1:43141/api/v2/brain/summary",
      status: 503,
    }, id);

    expect(result.kind).toBe("mismatch");
    expect(ledger.receipts).toEqual([]);
    expect(ledger.mismatches).toEqual([expect.objectContaining({
      expectationId: id,
      expected: expect.objectContaining({
        expectedOrigin: "http://127.0.0.1:43140",
      }),
      observed: expect.objectContaining({
        origin: "http://127.0.0.1:43141",
      }),
      reason: expect.stringContaining("origin"),
    })]);
    expect(ledger.unused()).toHaveLength(1);
  });

  test("does not retroactively excuse an earlier unexpected response", () => {
    const ledger = new ExpectedHttpResponseLedger();
    expect(ledger.observe({
      transport: "browser",
      method: "GET",
      url: "http://local/api/v2/brain/summary",
      status: 503,
    }).kind).toBe("unexpected");
    ledger.register(expected());
    expect(ledger.unexpected).toHaveLength(1);
    expect(ledger.unused()).toHaveLength(1);
    expect(ledger.hasFinalDefects()).toBe(true);
  });

  test("fails unused, extra, duplicate-id, and ambiguous-signature declarations", () => {
    const unused = new ExpectedHttpResponseLedger();
    unused.register(expected());
    expect(unused.unused()).toHaveLength(1);
    expect(unused.hasFinalDefects()).toBe(true);

    const extra = new ExpectedHttpResponseLedger();
    extra.register(expected());
    const observation = {
      transport: "browser" as const,
      method: "GET",
      url: "http://local/api/v2/brain/summary",
      status: 503,
    };
    expect(extra.observe(observation).kind).toBe("consumed");
    expect(extra.observe(observation).kind).toBe("extra");
    expect(extra.extras).toHaveLength(1);

    const duplicate = new ExpectedHttpResponseLedger();
    duplicate.register(expected());
    expect(() => duplicate.register(expected())).toThrow("Duplicate expected HTTP response id");
    expect(() => duplicate.register(expected({ id: "brain.summary.same-signature" }))).toThrow("Ambiguous expected HTTP response signature");
  });

  test("consumes an explicit count exactly and rejects invalid declarations", () => {
    const ledger = new ExpectedHttpResponseLedger();
    ledger.register(expected({ occurrences: 2 }));
    const observation = {
      transport: "browser" as const,
      method: "GET",
      url: "http://local/api/v2/brain/summary",
      status: 503,
    };
    expect(ledger.observe(observation).kind).toBe("consumed");
    expect(ledger.unused()[0]?.remaining).toBe(1);
    expect(ledger.observe(observation).kind).toBe("consumed");
    expect(ledger.unused()).toEqual([]);

    expect(() => new ExpectedHttpResponseLedger().register(expected({ pathname: "/external/api" }))).toThrow("/api/v2/");
    expect(() => new ExpectedHttpResponseLedger().register(expected({ status: 200 }))).toThrow("4xx or 5xx");
    expect(() => new ExpectedHttpResponseLedger().register(expected({ occurrences: 0 }))).toThrow("occurrences");
    expect(() => new ExpectedHttpResponseLedger().register(expected({ reason: "too short" }))).toThrow("precise reason");
  });
});

/// <reference lib="dom" />

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  fetchOperationalHazardResetTotals,
  reportOperationalHazardResetMinimum,
} from "../../../src/data/api/brain";
import {
  parseOperationalHazardAggregateObservationResult,
  parseOperationalHazardResetTotals,
} from "../../../src/domain/schemas/brain";
import type { MemoryUsage } from "../../../src/domain/types/brain";
import {
  OperationalHazardResetDraftKey,
  operationalHazardRunContexts,
} from "../../../src/features/brain/hazardAttribution";

const timestamp = "2026-07-20T16:00:00.000Z";
const totalsPayload = {
  missionId: "mission/reset review",
  runId: "run/reset review",
  exactAttributableResetCount: 2,
  operatorReportedResetMinimum: 11,
  minimumUnattributedResetCount: 9,
};

let originalFetch: typeof globalThis.fetch;
let originalDocument: PropertyDescriptor | undefined;
let calls: Array<{ readonly path: string; readonly init?: RequestInit }>;
let responses: unknown[];

beforeEach(() => {
  originalFetch = globalThis.fetch;
  originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  calls = [];
  responses = [];
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { cookie: "ti_scale_csrf=hazard-reset-csrf" },
  });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ path: typeof input === "string" ? input : input.toString(), init });
    const payload = responses.shift();
    if (payload === undefined) throw new Error("No operational-hazard response remains");
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Request-Id": "request-hazard-reset" },
    });
  }) as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
  else Reflect.deleteProperty(globalThis, "document");
});

describe("Operational-hazard reset review contract", () => {
  test("parses exact, aggregate, and unresolved counts without redistributing the aggregate", () => {
    expect(parseOperationalHazardResetTotals(totalsPayload)).toEqual(totalsPayload);
    expect(() => parseOperationalHazardResetTotals({
      ...totalsPayload,
      minimumUnattributedResetCount: 11,
    })).toThrow("unattributed reset minimum");

    const result = parseOperationalHazardAggregateObservationResult({
      observation: {
        id: "hazagg-one",
        missionId: totalsPayload.missionId,
        runId: totalsPayload.runId,
        reportedMinimum: 11,
        statementEventId: "event-one",
        reportedAt: timestamp,
      },
      totals: totalsPayload,
      replayed: false,
    });
    expect(result.totals).toMatchObject({
      exactAttributableResetCount: 2,
      operatorReportedResetMinimum: 11,
      minimumUnattributedResetCount: 9,
    });
  });

  test("derives selectable run scopes only from persisted Context Pack usage and deduplicates them", () => {
    const usage: MemoryUsage[] = [{
      contextPackId: "pack-new",
      missionId: "mission-one",
      runId: "run-one",
      purpose: "Recovery review",
      used: true,
      relevanceReason: "Exact hazard match",
      createdAt: "2026-07-20T16:00:00.000Z",
    }, {
      contextPackId: "pack-old",
      missionId: "mission-one",
      runId: "run-one",
      purpose: "Older duplicate",
      used: true,
      relevanceReason: "Exact hazard match",
      createdAt: "2026-07-19T16:00:00.000Z",
    }, {
      contextPackId: "pack-global",
      purpose: "No run scope",
      used: false,
      relevanceReason: "Not used",
      createdAt: "2026-07-21T16:00:00.000Z",
    }];
    expect(operationalHazardRunContexts(usage)).toEqual([{
      missionId: "mission-one",
      runId: "run-one",
      purpose: "Recovery review",
      createdAt: "2026-07-20T16:00:00.000Z",
    }]);
  });

  test("uses the authenticated run-scoped routes and sends only the aggregate lower bound", async () => {
    responses.push(totalsPayload, {
      observation: {
        id: "hazagg-one",
        missionId: totalsPayload.missionId,
        runId: totalsPayload.runId,
        reportedMinimum: 11,
        statementEventId: "event-one",
        reportedAt: timestamp,
      },
      totals: totalsPayload,
      replayed: false,
    });
    await fetchOperationalHazardResetTotals(
      totalsPayload.missionId,
      totalsPayload.runId,
      new AbortController().signal,
    );
    await reportOperationalHazardResetMinimum({
      missionId: totalsPayload.missionId,
      runId: totalsPayload.runId,
      reportedMinimum: 11,
    }, "hazard-reset-idempotency-one");

    expect(calls.map((call) => call.path)).toEqual([
      "/api/v2/missions/mission%2Freset%20review/runs/run%2Freset%20review/operational-hazards/reset-totals",
      "/api/v2/missions/mission%2Freset%20review/runs/run%2Freset%20review/operational-hazards/reset-minimum-observations",
    ]);
    expect(calls[1]?.init?.method).toBe("POST");
    expect(JSON.parse(String(calls[1]?.init?.body))).toEqual({ reportedMinimum: 11 });
    const headers = new Headers(calls[1]?.init?.headers);
    expect(headers.get("Idempotency-Key")).toBe("hazard-reset-idempotency-one");
    expect(headers.get("X-Ti-Scale-CSRF")).toBe("hazard-reset-csrf");
  });

  test("reuses one idempotency key when an ambiguous response is retried", async () => {
    const draft = {
      missionId: "mission-one",
      runId: "run-one",
      reportedMinimum: 11,
    };
    const keys = new OperationalHazardResetDraftKey();
    let generated = 0;
    let requestCount = 0;
    const observedKeys: string[] = [];
    globalThis.fetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      requestCount += 1;
      observedKeys.push(new Headers(init?.headers).get("Idempotency-Key") ?? "");
      if (requestCount === 1) throw new TypeError("Connection closed after the server may have committed");
      return new Response(JSON.stringify({
        observation: {
          id: "hazagg-replayed",
          ...draft,
          statementEventId: "event-replayed",
          reportedAt: timestamp,
        },
        totals: {
          missionId: draft.missionId,
          runId: draft.runId,
          exactAttributableResetCount: 2,
          operatorReportedResetMinimum: 11,
          minimumUnattributedResetCount: 9,
        },
        replayed: true,
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    }) as typeof globalThis.fetch;
    const attempt = () => reportOperationalHazardResetMinimum(
      draft,
      keys.keyFor(draft, () => `hazard-ambiguous-${++generated}`),
    );

    await expect(attempt()).rejects.toThrow("Connection closed");
    const replay = await attempt();
    expect(replay.replayed).toBe(true);
    expect(observedKeys).toEqual(["hazard-ambiguous-1", "hazard-ambiguous-1"]);
    expect(generated).toBe(1);

    keys.confirm(draft);
    expect(keys.keyFor(draft, () => `hazard-ambiguous-${++generated}`)).toBe("hazard-ambiguous-2");
  });

  test("rejects zero, negative, fractional, and unsafe aggregate reports before a request", async () => {
    for (const reportedMinimum of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() => reportOperationalHazardResetMinimum({
        missionId: "mission-one",
        runId: "run-one",
        reportedMinimum,
      })).toThrow("positive whole number");
    }
    expect(calls).toHaveLength(0);
  });
});

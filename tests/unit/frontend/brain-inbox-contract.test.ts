/// <reference lib="dom" />

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import {
  fetchMemoryCandidates,
  fetchMemoryNodes,
  rejectMemoryCandidate,
} from "../../../src/data/api/brain";
import type { MemoryCandidate } from "../../../src/domain/types/brain";
import {
  memoryCandidateEditorDefaults,
  memoryMutationErrorDetails,
} from "../../../src/features/brain/BrainInboxPage";
import { CursorControls } from "../../../src/features/runs/OperationalSurface";

const candidate: MemoryCandidate = {
  id: "candidate/one",
  nodeType: "preference",
  title: "Prefer evidence-led explanations",
  summary: "Explain why each retained record matters.",
  body: "Use direct operational language and link canonical evidence.",
  scope: { kind: "mission", engagementId: "engagement-one", missionId: "mission-one" },
  sensitivity: "private",
  confidence: 0.9,
  provenance: {
    method: "operator_statement",
    explanation: "The operator supplied this bounded candidate.",
    sources: [{ sourceType: "message", sourceId: "message-one", acquiredAt: "2026-07-16T10:00:00.000Z" }],
  },
  status: "pending",
  proposedBy: "agent-one",
  createdAt: "2026-07-16T10:00:00.000Z",
};

interface FetchCall { readonly path: string; readonly init?: RequestInit }

let originalFetch: typeof globalThis.fetch;
let originalDocument: PropertyDescriptor | undefined;
let calls: FetchCall[];
let responses: unknown[];

beforeEach(() => {
  originalFetch = globalThis.fetch;
  originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  calls = [];
  responses = [];
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { cookie: "ti_scale_csrf=csrf-proof" },
  });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ path: typeof input === "string" ? input : input.toString(), init });
    const payload = responses.shift();
    if (payload === undefined) throw new Error("No mocked Second Brain response remains");
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Request-Id": "request-brain-one" },
    });
  }) as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
  else Reflect.deleteProperty(globalThis, "document");
});

describe("Memory Inbox mutation contract", () => {
  test("sends opaque cursors with the active Brain search and exact-run scope", async () => {
    responses.push(
      { schemaVersion: "2.4", items: [], nextCursor: null, totalReturned: 0 },
      { items: [], nextCursor: null },
    );
    const signal = new AbortController().signal;

    await fetchMemoryNodes({
      query: "verified service",
      nodeType: "evidence",
      status: "verified",
      sensitivity: "internal",
      cursor: "node-cursor-one",
      limit: 50,
    }, signal);
    await fetchMemoryCandidates({
      missionId: "mission-one",
      runId: "run-one",
      cursor: "candidate-cursor-one",
      limit: 50,
    }, signal);

    const nodeRequest = new URL(calls[0]!.path, "http://ti-scale.local");
    expect(Object.fromEntries(nodeRequest.searchParams)).toEqual({
      query: "verified service",
      nodeType: "evidence",
      status: "verified",
      sensitivity: "internal",
      cursor: "node-cursor-one",
      limit: "50",
    });
    const candidateRequest = new URL(calls[1]!.path, "http://ti-scale.local");
    expect(Object.fromEntries(candidateRequest.searchParams)).toEqual({
      missionId: "mission-one",
      runId: "run-one",
      cursor: "candidate-cursor-one",
      limit: "50",
    });
  });

  test("renders bounded First and Next controls with the correct availability", () => {
    const firstPage = renderToStaticMarkup(CursorControls({
      nextCursor: "next-page",
      onChange: () => undefined,
    }));
    expect(firstPage).toMatch(/<button[^>]*aria-label="First page"[^>]*disabled=""/);
    expect(firstPage).toMatch(/<button(?![^>]*disabled)[^>]*aria-label="Next page"/);

    const terminalPage = renderToStaticMarkup(CursorControls({
      cursor: "current-page",
      nextCursor: null,
      onChange: () => undefined,
    }));
    expect(terminalPage).toMatch(/<button(?![^>]*disabled)[^>]*aria-label="First page"/);
    expect(terminalPage).toMatch(/<button[^>]*aria-label="Next page"[^>]*disabled=""/);
  });

  test("keeps ordinary rejection distinct from reject-and-do-not-relearn", async () => {
    responses.push(
      { schemaVersion: "2.4", candidateId: "candidate/one", status: "rejected" },
      { schemaVersion: "2.4", candidateId: "candidate/one", status: "suppressed", suppressionId: "suppression-one" },
    );

    expect(await rejectMemoryCandidate("candidate/one", "Incorrect observation", false)).toEqual({ status: "rejected" });
    expect(await rejectMemoryCandidate("candidate/one", "Never retain this observation", true)).toEqual({
      status: "suppressed",
      suppressionId: "suppression-one",
    });
    expect(calls.map((call) => call.path)).toEqual([
      "/api/v2/brain/candidates/candidate%2Fone/reject",
      "/api/v2/brain/candidates/candidate%2Fone/reject",
    ]);
    expect(calls.map((call) => JSON.parse(String(call.init?.body)))).toEqual([
      { reason: "Incorrect observation", doNotRelearn: false },
      { reason: "Never retain this observation", doNotRelearn: true },
    ]);
    expect(calls.every((call) => new Headers(call.init?.headers).get("Idempotency-Key"))).toBe(true);
    expect(calls.every((call) => new Headers(call.init?.headers).get("X-Ti-Scale-CSRF") === "csrf-proof"))
      .toBe(true);
  });

  test("restores every canonical editor value when edits are discarded", () => {
    expect(memoryCandidateEditorDefaults(candidate)).toEqual({
      title: candidate.title,
      summary: candidate.summary,
      body: candidate.body,
      sensitivity: "private",
      scopeKind: "mission",
      engagementId: "engagement-one",
      missionId: "mission-one",
    });
  });

  test("prefers the structured human mutation error and preserves remediation and trace", () => {
    const error = Object.assign(new Error("Internal candidate mutation failed"), {
      humanMessage: "The candidate could not be confirmed against its current canonical version.",
      remediation: "Refresh the Memory Inbox and retry the represented candidate.",
      traceId: "trace-memory-candidate-one",
    });
    expect(memoryMutationErrorDetails(error)).toEqual({
      message: "The candidate could not be confirmed against its current canonical version.",
      remediation: "Refresh the Memory Inbox and retry the represented candidate.",
      traceId: "trace-memory-candidate-one",
    });
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { fetchJourneyRuns } from "../../../src/data/api/runtimeV2";
import { parseRunPage } from "../../../src/domain/schemas/runtimeV2";
import { LIVE_RUN_STATE_OPTIONS } from "../../../src/features/live-operations/LiveOperationsPage";
import { runStatusLabel } from "../../../src/features/runs/runStatus";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function installFetchMock(
  implementation: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
): void {
  const preconnect: typeof fetch.preconnect = typeof originalFetch.preconnect === "function"
    ? originalFetch.preconnect.bind(originalFetch)
    : () => undefined;
  globalThis.fetch = Object.assign(implementation, { preconnect });
}

const autonomousRun = {
  id: "run-autonomous-visible",
  missionId: "mission-autonomous-visible",
  missionName: "Older active Autonomous mission",
  objective: "Retain the authorized operational checkpoint.",
  journey: "autonomous",
  status: "running",
  statusReason: "Executing inside the signed contract",
  progress: 0.35,
  nextAction: "Collect the next unique observation",
  currentPlanId: "plan-autonomous-visible",
  currentStepId: "step-autonomous-visible",
  currentOwnerId: "ReconScout",
  lastHeartbeatAt: "2026-07-20T00:00:00.000Z",
  leaseExpiresAt: null,
  startedAt: "2026-07-19T23:59:00.000Z",
  endedAt: null,
  createdAt: "2026-07-19T23:58:00.000Z",
  updatedAt: "2026-07-20T00:00:00.000Z",
  version: 3,
} as const;

describe("runtime V2 journey-run client", () => {
  test("keeps Live Operations filters and Autonomous status language aligned with canonical states", () => {
    expect(LIVE_RUN_STATE_OPTIONS).toEqual([
      { value: "queued", label: "Queued" },
      { value: "planning", label: "Planning" },
      { value: "awaiting_contract_confirmation", label: "Awaiting contract confirmation" },
      { value: "running", label: "Executing" },
      { value: "blocked", label: "Safe-stopped" },
      { value: "recovering", label: "Recovering" },
      { value: "completed", label: "Completed" },
      { value: "failed", label: "Failed safely" },
      { value: "cancelled", label: "Cancelled" },
    ]);
    expect(runStatusLabel({ journey: "autonomous", status: "blocked", statusReason: "Action is outside the signed contract." }))
      .toBe("Safe-stopped: outside contract");
    expect(runStatusLabel({ journey: "autonomous", status: "blocked", statusReason: "Required MCP server is unavailable." }))
      .toBe("Safe-stopped");
    expect(runStatusLabel({ journey: "autonomous", status: "failed", statusReason: "Worker integrity failed." }))
      .toBe("Failed safely");
    expect(runStatusLabel({ journey: "autonomous", status: "completed", statusReason: null }))
      .toBe("Completed autonomously");
  });

  test("loads Live Operations from the server-filtered operational run projection", async () => {
    const calls: string[] = [];
    installFetchMock(async (input, init) => {
      calls.push(String(input));
      expect(init?.method).toBe("GET");
      return new Response(JSON.stringify({
        schemaVersion: "2.4",
        items: [autonomousRun],
        nextCursor: "opaque-next-page",
      }), {
        status: 200,
        headers: { "content-type": "application/json", "x-request-id": "request-live-runs" },
      });
    });

    const result = await fetchJourneyRuns("autonomous", { view: "operational" });
    expect(calls).toEqual([
      "/api/v2/runs?journey=autonomous&view=operational&limit=50",
    ]);
    expect(result).toEqual({
      runs: [autonomousRun],
      failures: [],
      nextCursor: "opaque-next-page",
    });
  });

  test("uses an exact server status instead of the operational view for terminal filters", async () => {
    const calls: string[] = [];
    installFetchMock(async (input) => {
      calls.push(String(input));
      return new Response(JSON.stringify({ schemaVersion: "2.4", items: [], nextCursor: null }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    expect(await fetchJourneyRuns("autonomous", {
      status: "completed",
      cursor: "opaque-current-page",
      limit: 25,
    })).toEqual({ runs: [], failures: [], nextCursor: null });
    expect(calls).toEqual([
      "/api/v2/runs?journey=autonomous&status=completed&cursor=opaque-current-page&limit=25",
    ]);
  });

  test("does not silently turn an unfiltered journey portfolio into an operational-only view", async () => {
    const calls: string[] = [];
    installFetchMock(async (input) => {
      calls.push(String(input));
      return new Response(JSON.stringify({ schemaVersion: "2.4", items: [], nextCursor: null }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

    await fetchJourneyRuns("guided");
    expect(calls).toEqual(["/api/v2/runs?journey=guided&limit=50"]);
  });

  test("requires an explicit cursor field in the typed run-page contract", () => {
    expect(() => parseRunPage({ schemaVersion: "2.4", items: [autonomousRun] }))
      .toThrow("run page nextCursor");
    expect(parseRunPage({ schemaVersion: "2.4", items: [], nextCursor: null }))
      .toEqual({ schemaVersion: "2.4", items: [], nextCursor: null });
  });
});

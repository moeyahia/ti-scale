import { afterEach, describe, expect, test } from "bun:test";
import { operationsApi } from "../../../src/data/api/operations";
import { parseReportGeneration } from "../../../src/domain/schemas/operations";

const HASH = "a".repeat(64);
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

function generation() {
  return {
    schemaVersion: "2.4",
    reportSchemaVersion: "2.4-report.1",
    missionId: "mission-report",
    runId: "run-report",
    reportVersion: 2,
    sourceSnapshotHash: HASH,
    snapshotThrough: "2026-07-20T05:10:00.000Z",
    idempotent: true,
    artifacts: [
      { id: "report-markdown", format: "markdown", mediaType: "text/markdown; charset=utf-8", contentHash: HASH, byteSize: 100, downloadUrl: "/api/v2/reports/report-markdown/download" },
      { id: "report-json", format: "json", mediaType: "application/json; charset=utf-8", contentHash: HASH, byteSize: 200, downloadUrl: "/api/v2/reports/report-json/download" },
    ],
  } as const;
}

describe("canonical report browser boundary", () => {
  test("validates the immutable paired-artifact response", () => {
    expect(parseReportGeneration(generation()).artifacts.map((item) => item.format)).toEqual(["markdown", "json"]);
    expect(() => parseReportGeneration({ ...generation(), idempotent: false })).toThrow("not idempotent");
    expect(() => parseReportGeneration({ ...generation(), artifacts: [{ ...generation().artifacts[0], format: "html" }] })).toThrow("format is invalid");
  });

  test("uses the authenticated mutation and exact download paths", async () => {
    let captured: { path: string; method: string; key: string | null; body: string } | undefined;
    globalThis.fetch = (async (input, init) => {
      const headers = new Headers(init?.headers);
      captured = {
        path: String(input),
        method: String(init?.method),
        key: headers.get("Idempotency-Key"),
        body: String(init?.body),
      };
      return new Response(JSON.stringify(generation()), {
        status: 201,
        headers: { "content-type": "application/json", "x-request-id": "report-client" },
      });
    }) as typeof fetch;
    const result = await operationsApi.generateReport("run-report", 2, "report:run-report:2");
    expect(result.reportVersion).toBe(2);
    expect(captured).toEqual({
      path: "/api/v2/reports/runs/run-report/generate",
      method: "POST",
      key: "report:run-report:2",
      body: '{"reportVersion":2}',
    });
    expect(operationsApi.reportDownloadUrl("report-markdown")).toBe("/api/v2/reports/report-markdown/download");
  });
});

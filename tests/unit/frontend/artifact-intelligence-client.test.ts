import { afterEach, describe, expect, test } from "bun:test";
import { pageCapturesApi } from "../../../src/data/api/pageCaptures";
import { scriptArtifactsApi } from "../../../src/data/api/scriptArtifacts";
import { parsePageCaptureDetail, parsePageCaptureList } from "../../../src/domain/schemas/pageCaptures";
import { parseScriptArtifactDetail, parseScriptArtifactList } from "../../../src/domain/schemas/scriptArtifacts";

const NOW = "2026-07-16T19:00:00.000Z";
const HASH = "a".repeat(64);
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

function script(source = "print('ready')\n") {
  return {
    id: "script-v1", missionId: "mission-artifacts", runId: "run-artifacts", planId: "plan-artifacts", stepId: "step-artifacts",
    artifactId: "artifact-script-v1", name: "recon/probe.py", language: "python", version: 1,
    contentHash: HASH, byteSize: 15, mediaType: "text/x-python", sensitivity: "internal",
    laymanExplanation: "Reads one retained fixture.", technicalPurpose: "Parses an offline fixture without network access.",
    inputs: [{ name: "PATH", description: "Retained fixture path.", required: true, sensitivity: "ordinary" }],
    expectedOutputs: [{ label: "Marker", description: "A normalized marker.", successRecognition: "ready", failureRecognition: "No marker" }],
    requirements: { prerequisites: ["Python 3"], dependencies: ["Standard library"] },
    touches: { files: ["Fixture path"], network: [], services: [] },
    risk: { riskClass: "low", sideEffects: ["No execution from this record"], reversibility: "Read only" },
    cleanupNotes: "No cleanup", secretsHandling: "No secrets", evidenceExpectations: ["Separate test result"],
    validation: { state: "unvalidated", summary: "Not executed", tests: [] },
    provenance: { origin: "agent_generated", explanation: "Proposed for review", sourceRefs: ["plan-step:step-artifacts"], authorAgentId: "agent-web", createdBy: "operator", createdByType: "operator" },
    diff: { toVersion: 1, contentHash: HASH, sourceChanged: true, changedFields: ["source"], commonPrefixLines: 0, commonSuffixLines: 0, removedLineCount: 0, addedLineCount: 1, changeSummary: "Initial version" },
    storageUri: `ti-scale-script://sha256/${HASH}`, createdBy: "operator", createdAt: NOW,
    source,
  };
}

function capture(redactionState: "not_required" | "pending" = "not_required") {
  const visible = redactionState === "not_required";
  return {
    id: `capture-${redactionState}`, missionId: "mission-artifacts", runId: "run-artifacts", planId: "plan-artifacts", stepId: "step-artifacts", stepTitle: "Capture landing page",
    assetNodeId: "asset-web", assetLabel: "web-01", serviceNodeId: "service-https", serviceLabel: "HTTPS",
    normalizedUrl: "https://fixture.example.test/app/login?view=compact", responseStatus: 200, title: "Fixture Sign In",
    viewport: { width: 1440, height: 900, deviceScaleFactor: 1, isMobile: false, fullPage: false },
    screenshot: { artifactId: "artifact-page", contentHash: HASH, mediaType: "image/png", byteSize: 1200 }, contentHash: "b".repeat(64), screenshotHash: HASH,
    certificate: { protocol: "TLSv1.3", subjectCommonName: "fixture.example.test", fingerprintSha256: "c".repeat(64), verified: true },
    site: { contentType: "text/html", contentLength: 4096, serverProduct: "fixture/2.4", technologies: ["Fixture UI"], securityHeaders: [{ name: "content-security-policy", value: "default-src 'self'" }] },
    related: { evidenceIds: ["evidence-page"], observationIds: [], findingIds: ["finding-page"] }, capturedByAgentId: "agent-web", capturedByAgentName: "Web specialist",
    captureTool: "playwright.page.screenshot", sensitivity: "internal", redactionState, capturedAt: NOW, createdAt: NOW,
    gallery: { label: "Fixture Sign In", previewArtifactId: visible ? "artifact-page" : null, fullPageArtifactId: null, previewAvailable: visible, redactionState },
  };
}

function scriptSummary() {
  const { source: _source, ...summary } = script();
  return summary;
}

describe("strict ScriptArtifact browser boundary", () => {
  test("accepts immutable summary/detail records and rejects extra fields or a broken version chain", () => {
    const canonical = script();
    expect(parseScriptArtifactList({ schemaVersion: "2.4", items: [scriptSummary()] }).items[0]?.contentHash).toBe(HASH);
    expect(parseScriptArtifactDetail({ schemaVersion: "2.4", record: canonical }).record.source).toContain("ready");
    expect(() => parseScriptArtifactDetail({ schemaVersion: "2.4", record: { ...canonical, execute: true } })).toThrow("unsupported field execute");
    expect(() => parseScriptArtifactDetail({ schemaVersion: "2.4", record: { ...canonical, version: 2 } })).toThrow("diff does not match");
  });

  test("uses only mission-scoped authenticated read paths and validates limits", async () => {
    const canonical = script();
    const calls: string[] = [];
    globalThis.fetch = (async (input, init) => {
      calls.push(`${init?.method}:${String(input)}`);
      const detail = String(input).endsWith("/script-v1");
      return new Response(JSON.stringify(detail
        ? { schemaVersion: "2.4", record: canonical }
        : { schemaVersion: "2.4", items: [scriptSummary()] }), { status: 200, headers: { "content-type": "application/json", "x-request-id": "script-client" } });
    }) as typeof fetch;
    expect((await scriptArtifactsApi.list("mission-artifacts", { runId: "run-artifacts", limit: 25 })).items).toHaveLength(1);
    expect((await scriptArtifactsApi.detail("mission-artifacts", "script-v1")).record.source).toContain("ready");
    expect(calls).toEqual([
      "GET:/api/v2/missions/mission-artifacts/script-artifacts?runId=run-artifacts&limit=25",
      "GET:/api/v2/missions/mission-artifacts/script-artifacts/script-v1",
    ]);
    expect(() => scriptArtifactsApi.list("mission-artifacts", { limit: 101 })).toThrow("1 through 100");
  });
});

describe("strict PageCapture browser boundary", () => {
  test("accepts visible and pending gallery projections and rejects unsafe preview state", () => {
    expect(parsePageCaptureDetail({ schemaVersion: "2.4", record: capture() }).record.gallery.previewAvailable).toBe(true);
    expect(parsePageCaptureList({ schemaVersion: "2.4", items: [capture("pending")] }).items[0]?.gallery.previewArtifactId).toBeNull();
    expect(() => parsePageCaptureDetail({ schemaVersion: "2.4", record: { ...capture("pending"), gallery: { ...capture("pending").gallery, previewAvailable: true, previewArtifactId: "artifact-page" } } })).toThrow("gallery projection is inconsistent");
    expect(() => parsePageCaptureDetail({ schemaVersion: "2.4", record: { ...capture(), rawHtml: "<secret>" } })).toThrow("unsupported field rawHtml");
  });

  test("uses mission/run-scoped read paths and refuses an unbounded list", async () => {
    const canonical = capture(); const calls: string[] = [];
    globalThis.fetch = (async (input, init) => {
      calls.push(`${init?.method}:${String(input)}`);
      const detail = String(input).endsWith("/capture-not_required");
      return new Response(JSON.stringify(detail ? { schemaVersion: "2.4", record: canonical } : { schemaVersion: "2.4", items: [canonical] }), { status: 200, headers: { "content-type": "application/json", "x-request-id": "capture-client" } });
    }) as typeof fetch;
    expect((await pageCapturesApi.list("mission-artifacts", { runId: "run-artifacts", limit: 50 })).items).toHaveLength(1);
    expect((await pageCapturesApi.detail("mission-artifacts", "capture-not_required")).record.responseStatus).toBe(200);
    expect(calls).toEqual([
      "GET:/api/v2/missions/mission-artifacts/intelligence/page-captures?runId=run-artifacts&limit=50",
      "GET:/api/v2/missions/mission-artifacts/intelligence/page-captures/capture-not_required",
    ]);
    expect(() => pageCapturesApi.list("mission-artifacts", { limit: 0 })).toThrow("1 through 100");
  });
});

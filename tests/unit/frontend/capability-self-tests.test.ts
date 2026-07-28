import { describe, expect, test } from "bun:test";
import { parseCapabilitySelfTestSnapshot } from "../../../src/domain/schemas/capabilitySelfTests";

function fixture() {
  return {
    schemaVersion: "2.4",
    checkedAt: "2026-07-18T21:00:00.000Z",
    readOnly: true,
    grantsMissionExecution: false,
    accounting: {
      runtimeRegistryRead: true,
      manifestValid: true,
      complete: true,
      registered: { providers: 1, mcpServers: 1, tools: 1, toolDependencies: 1 },
      reported: { providers: 1, mcpServers: 1, tools: 1, toolDependencies: 1 },
    },
    summary: {
      total: 2,
      pass: 1,
      degraded: 0,
      fail: 1,
      available: 1,
      degradedAvailability: 0,
      unavailable: 1,
      unsupported: 0,
    },
    results: [
      {
        id: "self-test:mcp_server:001:public-nvd",
        component: { kind: "mcp_server", id: "public-nvd", label: "MCP server · public-nvd" },
        testKind: "runtime_attestation",
        status: "pass",
        availability: "available",
        checkedAt: "2026-07-18T21:00:00.000Z",
        freshness: {
          state: "fresh",
          observedAt: "2026-07-18T20:59:58.000Z",
          expiresAt: "2026-07-18T21:04:58.000Z",
          maximumAgeMs: 300_000,
        },
        explanation: "The exact public NVD tool inventory is freshly attested.",
        remediation: null,
        executionAuthorization: {
          state: "not_granted",
          grantsMissionExecution: false,
          explanation: "Readiness alone does not grant mission execution.",
        },
      },
      {
        id: "self-test:tool:001:public-nvd/get-cve-details",
        component: { kind: "tool", id: "public-nvd/get-cve-details", label: "Registered tool · public-nvd/get-cve-details" },
        testKind: "manifest_dependency",
        status: "fail",
        availability: "unavailable",
        checkedAt: "2026-07-18T21:00:00.000Z",
        freshness: { state: "unknown", observedAt: null, expiresAt: null, maximumAgeMs: null },
        explanation: "The registered tool has no target-free executable preflight receipt.",
        remediation: "Complete the local executable and schema attestation before mission use.",
        executionAuthorization: {
          state: "not_granted",
          grantsMissionExecution: false,
          explanation: "Readiness alone does not grant mission execution.",
        },
      },
    ],
  };
}

describe("capability self-test frontend contract", () => {
  test("accepts a reconciled, read-only, non-authorizing snapshot", () => {
    const parsed = parseCapabilitySelfTestSnapshot(fixture());
    expect(parsed.accounting.complete).toBe(true);
    expect(parsed.results.map((result) => result.component.kind)).toEqual(["mcp_server", "tool"]);
    expect(parsed.results.every((result) => result.executionAuthorization.grantsMissionExecution === false)).toBe(true);
  });

  test("rejects a response that claims readiness grants execution", () => {
    const input = fixture();
    expect(() => parseCapabilitySelfTestSnapshot({ ...input, grantsMissionExecution: true }))
      .toThrow("must be read-only and non-authorizing");
    expect(() => parseCapabilitySelfTestSnapshot({
      ...input,
      results: [{
        ...input.results[0],
        executionAuthorization: {
          ...input.results[0]?.executionAuthorization,
          grantsMissionExecution: true,
        },
      }, input.results[1]],
    })).toThrow("must not grant mission execution");
  });

  test("rejects inconsistent summary accounting and unknown fields", () => {
    const input = fixture();
    expect(() => parseCapabilitySelfTestSnapshot({
      ...input,
      summary: { ...input.summary, pass: 2 },
    })).toThrow("does not reconcile");
    expect(() => parseCapabilitySelfTestSnapshot({ ...input, rawSecret: "must-not-render" }))
      .toThrow("unsupported field rawSecret");
  });
});

import { describe, expect, test } from "bun:test";
import { parseRuntimeReadiness } from "../../../src/domain/schemas/runtimeReadiness";

function payload(providers: Record<string, unknown>, options: {
  guidedToolExecution?: "ready" | "unavailable";
  mcp?: Record<string, unknown>;
} = {}) {
  return {
    schemaVersion: "2.4",
    status: "degraded",
    execution: {
      autonomous: "unavailable",
      guided: "unavailable",
      ...(options.guidedToolExecution === undefined
        ? {}
        : { guidedToolExecution: options.guidedToolExecution }),
      actionBoundaryActive: false,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
    },
    dependencies: {
      providers,
      ...(options.mcp === undefined ? {} : { mcp: options.mcp }),
    },
    checkedAt: "2026-07-18T05:30:00.000Z",
  };
}

describe("runtime readiness provider initialization contract", () => {
  test("parses the additive probing state and operator-readable reason", () => {
    expect(parseRuntimeReadiness(payload({
      status: "unavailable",
      initializing: true,
      probing: 1,
      reason: "Live provider attestation is in progress; execution remains unavailable until it succeeds.",
      declared: 5,
      callable: 0,
      enforcing: 0,
      guidedCapable: 0,
    })).dependencies.providers).toEqual({
      status: "unavailable",
      initializing: true,
      probing: 1,
      reason: "Live provider attestation is in progress; execution remains unavailable until it succeeds.",
      declared: 5,
      callable: 0,
      enforcing: 0,
      guidedCapable: 0,
    });
  });

  test("keeps older V2.4 readiness payloads parseable with safe defaults", () => {
    const result = parseRuntimeReadiness(payload({
      status: "available",
      declared: 1,
      callable: 1,
      enforcing: 1,
      guidedCapable: 1,
    }));
    expect(result.dependencies.providers).toMatchObject({
      initializing: false,
      probing: 0,
      reason: null,
    });
    expect(result.execution.guidedToolExecution).toBe("unavailable");
    expect(result.dependencies.mcp).toEqual({
      status: "unavailable",
      initializing: false,
      probingServers: 0,
      reason: null,
      configuredServers: 0,
      runnableServers: 0,
      executionMode: "disabled",
    });
  });

  test("retains precise MCP probing and Guided tool-execution readiness", () => {
    const result = parseRuntimeReadiness(payload({
      status: "available",
      declared: 1,
      callable: 1,
      enforcing: 1,
      guidedCapable: 1,
    }, {
      guidedToolExecution: "unavailable",
      mcp: {
        status: "unavailable",
        initializing: true,
        probingServers: 3,
        reason: "Live MCP route attestation is in progress.",
        configuredServers: 4,
        runnableServers: 0,
        executionMode: "enabled",
      },
    }));
    expect(result.execution.guidedToolExecution).toBe("unavailable");
    expect(result.dependencies.mcp).toEqual({
      status: "unavailable",
      initializing: true,
      probingServers: 3,
      reason: "Live MCP route attestation is in progress.",
      configuredServers: 4,
      runnableServers: 0,
      executionMode: "enabled",
    });
  });
});

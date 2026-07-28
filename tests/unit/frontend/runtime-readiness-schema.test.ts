import { describe, expect, test } from "bun:test";
import { parseRuntimeReadiness } from "../../../src/domain/schemas/runtimeReadiness";

function payload(providers: Record<string, unknown>, options: {
  guided?: unknown;
  autonomous?: unknown;
  guidedToolExecution?: unknown;
  localCommanderGuidance?: unknown;
  mcp?: Record<string, unknown>;
  secondBrain?: Record<string, unknown>;
} = {}) {
  return {
    schemaVersion: "2.4",
    status: "degraded",
    execution: {
      autonomous: options.autonomous ?? "unavailable",
      guided: options.guided ?? "unavailable",
      ...(options.guidedToolExecution === undefined
        ? {}
        : { guidedToolExecution: options.guidedToolExecution }),
      ...(options.localCommanderGuidance === undefined
        ? {}
        : { localCommanderGuidance: options.localCommanderGuidance }),
      actionBoundaryActive: false,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
    },
    dependencies: {
      providers,
      ...(options.mcp === undefined ? {} : { mcp: options.mcp }),
      ...(options.secondBrain === undefined ? {} : { secondBrain: options.secondBrain }),
    },
    checkedAt: "2026-07-18T05:30:00.000Z",
  };
}

describe("runtime readiness provider initialization contract", () => {
  test("accepts manual_only only for the Guided execution boundary", () => {
    const result = parseRuntimeReadiness(payload({
      status: "unavailable",
      declared: 0,
      callable: 0,
      enforcing: 0,
      guidedCapable: 0,
    }, { guided: "manual_only" }));

    expect(result.execution.guided).toBe("manual_only");
    expect(() => parseRuntimeReadiness(payload({
      status: "unavailable",
      declared: 0,
      callable: 0,
      enforcing: 0,
      guidedCapable: 0,
    }, { autonomous: "manual_only" }))).toThrow("autonomous execution must be ready or unavailable");
    expect(() => parseRuntimeReadiness(payload({
      status: "unavailable",
      declared: 0,
      callable: 0,
      enforcing: 0,
      guidedCapable: 0,
    }, { guidedToolExecution: "manual_only" }))).toThrow("Guided tool execution must be ready or unavailable");
    expect(() => parseRuntimeReadiness(payload({
      status: "unavailable",
      declared: 0,
      callable: 0,
      enforcing: 0,
      guidedCapable: 0,
    }, { localCommanderGuidance: "manual_only" }))).toThrow("Local Commander guidance must be ready or unavailable");
  });

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
    expect(result.execution.localCommanderGuidance).toBe("unavailable");
    expect(result.dependencies.mcp).toEqual({
      status: "unavailable",
      initializing: false,
      probingServers: 0,
      reason: null,
      configuredServers: 0,
      runnableServers: 0,
      executionMode: "disabled",
    });
    expect(result.dependencies.secondBrain).toEqual({
      status: "unknown",
      canonicalStoreAvailable: false,
      reason: null,
    });
  });

  test("parses provider-independent local Commander guidance explicitly", () => {
    const result = parseRuntimeReadiness(payload({
      status: "unavailable",
      declared: 0,
      callable: 0,
      enforcing: 0,
      guidedCapable: 0,
    }, {
      guided: "manual_only",
      localCommanderGuidance: "ready",
    }));
    expect(result.execution.localCommanderGuidance).toBe("ready");
    expect(result.dependencies.providers.guidedCapable).toBe(0);
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

  test("parses canonical Second Brain readiness independently from its optional Vault projection", () => {
    const result = parseRuntimeReadiness(payload({
      status: "unavailable",
      declared: 0,
      callable: 0,
      enforcing: 0,
      guidedCapable: 0,
    }, {
      secondBrain: {
        status: "degraded",
        canonicalStoreAvailable: true,
        reason: "Canonical memory is ready while an optional Vault projection is offline.",
        vaultProjection: { status: "degraded" },
      },
    }));
    expect(result.dependencies.secondBrain).toEqual({
      status: "degraded",
      canonicalStoreAvailable: true,
      reason: "Canonical memory is ready while an optional Vault projection is offline.",
    });
  });
});

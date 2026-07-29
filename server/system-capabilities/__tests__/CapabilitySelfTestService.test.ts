import { describe, expect, test } from "bun:test";
import type { RuntimeProjectionInput } from "../../app/RuntimeProjectionService";
import {
  createRuntimeAdapterAttestation,
  runtimeAdapterReceiptSha256,
  type RuntimeAdapterAttestation,
  type RuntimeSourceManifests,
} from "../../domain";
import type {
  CapabilityLocalHealthReader,
  CapabilityLocalHealthSnapshot,
} from "../CapabilitySelfTestRepository";
import { CapabilitySelfTestService } from "../CapabilitySelfTestService";
import type { ToolExecutionPreflightResult } from "../ToolExecutionPreflight";

const NOW = new Date("2026-07-18T20:00:00.000Z");

function localHealth(overrides: Partial<CapabilityLocalHealthSnapshot> = {}): CapabilityLocalHealthSnapshot {
  return {
    checkedAt: NOW.toISOString(),
    database: {
      healthy: true,
      integrity: ["ok"],
      integrityStatus: "verified",
      integrityCheckedAt: NOW.toISOString(),
      integritySource: "startup",
      journalMode: "wal",
      foreignKeys: true,
      busyTimeoutMs: 5_000,
      currentMigration: 15,
      pendingOutbox: 0,
      checkedAt: NOW.toISOString(),
    },
    eventStream: { started: true, subscribers: 0 },
    secondBrain: {
      health: "healthy",
      databaseHealthy: true,
      canonicalStoreAvailable: true,
      lexicalIndexAvailable: true,
      lexicalIndexSynchronized: true,
      vaultProjection: {
        status: "healthy",
        configuredConnections: 1,
        connectedConnections: 1,
        reachableConnections: 1,
        healthVerifiedConnections: 1,
        reason: "internal path and receipt details must not leave the health boundary",
      },
      reason: "internal Brain diagnostics must not leave the health boundary",
    },
    ...overrides,
  };
}

function manifests(): RuntimeSourceManifests {
  return {
    riskClasses: [{
      id: "read-only",
      label: "Read only",
      actionClassIds: ["passive_intelligence_osint"],
    }],
    evidenceKinds: [{
      id: "observation",
      label: "Observation",
      evidenceTypeIds: ["asset_discovery_proof"],
    }],
    capabilities: [],
    tools: [
      {
        id: "mcp:mcp-ready/registry-inspector",
        label: "Registry inspector with raw payload Bearer sk-never-return-this",
        available: true,
        locallyPolicyEnforced: true,
        requiresModel: false,
        actionClassIds: ["passive_intelligence_osint"],
        evidenceTypeIds: ["asset_discovery_proof"],
        riskClassIds: ["read-only"],
        mcpServerId: "mcp-ready",
        dependencies: [{ id: "local-manifest", ready: true }],
      },
      {
        id: "mcp:mcp-offline/unavailable-tool",
        label: "Unavailable tool",
        available: false,
        locallyPolicyEnforced: true,
        requiresModel: false,
        actionClassIds: ["passive_intelligence_osint"],
        evidenceTypeIds: ["asset_discovery_proof"],
        riskClassIds: ["read-only"],
        mcpServerId: "mcp-offline",
        dependencies: [{ id: "missing-local-dependency", ready: false }],
      },
    ],
    mcpServers: [
      { id: "mcp-ready", label: "Ready MCP", status: "healthy", toolIds: ["mcp:mcp-ready/registry-inspector"] },
      { id: "mcp-offline", label: "Offline MCP", status: "offline", toolIds: ["mcp:mcp-offline/unavailable-tool"] },
    ],
    agents: [],
    providers: [
      {
        id: "provider-ready",
        authenticated: true,
        healthy: true,
        catalogObservedAt: "2026-07-18T19:59:40.000Z",
        models: [],
      },
      {
        id: "provider-disabled",
        authenticated: false,
        healthy: false,
        catalogObservedAt: "2026-07-18T19:59:40.000Z",
        models: [],
      },
    ],
  };
}

function runtime(): RuntimeProjectionInput {
  return {
    readiness: {
      actionBoundaryActive: true,
      delegationEnforced: true,
      noHandsCommanderEnforced: true,
      directCommanderToolsDenied: true,
      specialistAssignmentRequired: true,
      specialistsConfigured: 1,
      providers: [
        {
          id: "provider-ready",
          health: "healthy",
          configured: true,
          authenticated: true,
          callable: true,
          attestedAt: "2026-07-18T19:59:30.000Z",
          expiresAt: "2026-07-18T20:04:30.000Z",
          supportsGuided: true,
          enforcesAutonomousBoundary: false,
          reportsExactTokenUsage: true,
          reportsExactCostUsage: false,
          reason: "Bearer sk-never-return-this and unrestricted raw provider payload",
        },
        {
          id: "provider-disabled",
          health: "unhealthy",
          configured: false,
          authenticated: false,
          callable: false,
          supportsGuided: false,
          enforcesAutonomousBoundary: false,
          reportsExactTokenUsage: false,
          reportsExactCostUsage: false,
          reason: "password=never-return-this",
        },
      ],
      mcp: {
        enabled: true,
        executionMode: "enabled",
        startPermitted: true,
        configuredServers: 2,
        runnableServers: 1,
        missingDependencies: 1,
        missingSecrets: 1,
      },
      eventStream: "healthy",
      secondBrain: "healthy",
      legacyExecutionEnabled: false,
    },
    agents: [{
      id: "agent-secret-fixture",
      role: "fixture",
      displayName: "Fixture",
      status: "available",
      providerPolicy: { authorization: "Bearer sk-never-return-this" },
      toolPolicy: { cookie: "never-return-this" },
      configuration: { rawPayload: "never-return-this" },
      version: "1",
      capabilities: [],
    }],
    mcpServers: [
      {
        id: "mcp-ready",
        name: "Ready MCP",
        transport: "local",
        endpointRedacted: "https://example.invalid/?token=never-return-this",
        status: "healthy",
        capabilities: ["mcp:mcp-ready/registry-inspector"],
        policy: { authorization: "Bearer sk-never-return-this" },
        lastCheckedAt: "2026-07-18T19:59:30.000Z",
      },
      {
        id: "mcp-offline",
        name: "Offline MCP",
        transport: "local",
        status: "offline",
        capabilities: ["mcp:mcp-offline/unavailable-tool"],
        policy: {},
        lastCheckedAt: "2026-07-18T19:59:30.000Z",
      },
    ],
    capabilityManifests: manifests(),
  };
}

function service(
  input = runtime(),
  local = localHealth(),
  readToolExecutionPreflight?: (toolId: string) => ToolExecutionPreflightResult | undefined,
): CapabilitySelfTestService {
  const repository: CapabilityLocalHealthReader = { read: () => local };
  return new CapabilitySelfTestService({
    repository,
    readRuntimeProjection: () => input,
    ...(readToolExecutionPreflight ? { readToolExecutionPreflight } : {}),
    clock: () => NOW,
  });
}

function readyLocalPreflight(toolId: string): ToolExecutionPreflightResult {
  return {
    schemaVersion: "ti-scale.tool-execution-preflight.v2",
    toolId,
    status: "ready",
    code: "ready",
    checkedAt: "2026-07-18T19:59:30.000Z",
    expiresAt: "2026-07-18T20:00:30.000Z",
    bindingSha256: "b".repeat(64),
    probeBoundary: {
      shell: false,
      targetArgumentsSupplied: false,
      providerArgumentsSupplied: false,
      mcpArgumentsSupplied: false,
      networkIsolationEnforced: true,
      filesystemWriteIsolationEnforced: true,
      immutableSnapshotExecutionEnforced: true,
      externalContact: "not_measured",
    },
    executableIdentity: {
      sha256: "a".repeat(64),
      device: "1",
      inode: "2",
      sizeBytes: 1_024,
      mode: 0o755,
      uid: 0,
      gid: 0,
    },
    noNewPrivileges: true,
    explanation: "The exact target-free startup probe passed.",
    remediation: null,
    execution: {
      exitCode: 0,
      signal: null,
      spawnErrorCode: null,
      outputBytes: 10,
      outputSha256: "c".repeat(64),
    },
  };
}

function runtimeAdapterAttestation(
  input: Readonly<{
    toolId?: string;
    dependencyId?: string;
    parentBindingSha256?: string;
    observedAt?: string;
    executionJourneys?: readonly ("autonomous" | "guided")[];
  }> = {},
  expiresAt = "2026-07-18T20:00:30.000Z",
) {
  return createRuntimeAdapterAttestation({
    toolId: input.toolId ?? "runtime:reviewed-adapter",
    ...(input.dependencyId ? { dependencyId: input.dependencyId } : {}),
    ...(input.parentBindingSha256
      ? { parentBindingSha256: input.parentBindingSha256 }
      : {}),
    executionJourneys: input.executionJourneys ?? ["autonomous"],
    binding: {
      configurationSha256: "1".repeat(64),
      providerReceiptSha256: "2".repeat(64),
      localManifestSha256: "3".repeat(64),
      componentReceiptSha256s: ["4".repeat(64)],
    },
    observedAt: input.observedAt ?? "2026-07-18T19:59:30.000Z",
    expiresAt,
  });
}

function withReissuedLifetime(
  attestation: RuntimeAdapterAttestation,
  observedAt: string,
  expiresAt: string,
): RuntimeAdapterAttestation {
  const unsigned = {
    ...attestation,
    observedAt,
    expiresAt,
  };
  const { receiptSha256: _ignoredReceipt, ...withoutReceipt } = unsigned;
  return {
    ...withoutReceipt,
    receiptSha256: runtimeAdapterReceiptSha256(withoutReceipt),
  };
}

function withRuntimeAdapter(
  input: RuntimeProjectionInput,
  options: Readonly<{
    expiresAt?: string;
    omitParentAttestation?: boolean;
    omitDependencyAttestation?: boolean;
    withoutDependencies?: boolean;
  }> = {},
): RuntimeProjectionInput {
  const baseManifests = input.capabilityManifests ?? manifests();
  const parent = runtimeAdapterAttestation({}, options.expiresAt);
  const dependency = runtimeAdapterAttestation({
    dependencyId: "reviewed-runtime-component",
    parentBindingSha256: parent.bindingSha256,
  }, options.expiresAt);
  return {
    ...input,
    capabilityManifests: {
      ...baseManifests,
      tools: [
        ...baseManifests.tools,
        {
          id: "runtime:reviewed-adapter",
          label: "Reviewed in-process adapter",
          available: true,
          locallyPolicyEnforced: true,
          requiresModel: false,
          executionJourneys: ["autonomous"],
          actionClassIds: ["passive_intelligence_osint"],
          evidenceTypeIds: ["asset_discovery_proof"],
          riskClassIds: ["read-only"],
          ...(options.omitParentAttestation
            ? {}
            : { runtimeAdapterAttestation: parent }),
          dependencies: options.withoutDependencies
            ? []
            : [{
                id: "reviewed-runtime-component",
                ready: true,
                ...(options.omitDependencyAttestation
                  ? {}
                  : { runtimeAdapterAttestation: dependency }),
              }],
        },
      ],
    },
  };
}

describe("CapabilitySelfTestService", () => {
  test("does not classify disconnected Vault history as an active degraded projection", () => {
    const base = localHealth();
    const snapshot = service(runtime(), {
      ...base,
      secondBrain: {
        ...base.secondBrain,
        vaultProjection: {
          status: "not_configured",
          configuredConnections: 1,
          connectedConnections: 0,
          reachableConnections: 0,
          healthVerifiedConnections: 0,
          reason: "One disconnected connection remains available as read-only history.",
        },
      },
    }).snapshot();
    expect(snapshot.results.find(({ component }) => component.kind === "obsidian_vault"))
      .toMatchObject({
        status: "fail",
        availability: "unavailable",
        explanation: "No active Obsidian Vault projection is configured. The canonical Second Brain remains a separate local dependency.",
      });
  });

  test("accounts for every registered dependency without promoting unavailable components", () => {
    const snapshot = service().snapshot();
    expect(snapshot).toMatchObject({
      schemaVersion: "2.4",
      readOnly: true,
      grantsMissionExecution: false,
      accounting: {
        runtimeRegistryRead: true,
        manifestValid: true,
        complete: true,
        registered: { providers: 2, mcpServers: 2, tools: 2, toolDependencies: 2 },
        reported: { providers: 2, mcpServers: 2, tools: 2, toolDependencies: 2 },
      },
    });
    expect(snapshot.results.find(({ component }) => component.id === "provider-ready"))
      .toMatchObject({ status: "pass", availability: "available" });
    expect(snapshot.results.find(({ component }) => component.id === "provider-disabled"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
    expect(snapshot.results.find(({ component }) => component.id === "mcp-offline"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
    const unavailableTool = snapshot.results.find(
      ({ component }) => component.id === "mcp:mcp-offline/unavailable-tool",
    );
    expect(unavailableTool).toMatchObject({ status: "fail", availability: "unavailable" });
    expect(unavailableTool?.explanation).toContain(
      "waiting for dependency: missing-local-dependency",
    );
    expect(unavailableTool?.explanation).toContain(
      "requires MCP server mcp-offline",
    );
    expect(unavailableTool?.remediation).toContain(
      "Restore only the named dependency",
    );
    expect(unavailableTool?.remediation).toContain(
      "Restore that exact server",
    );
    expect(snapshot.results.find(({ component }) => component.id === "mcp:mcp-offline/unavailable-tool/missing-local-dependency"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
  });

  test("never returns source reasons, endpoints, policy payloads, secrets, or execution authority", () => {
    const snapshot = service().snapshot();
    const serialized = JSON.stringify(snapshot);
    expect(serialized).not.toContain("sk-never-return-this");
    expect(serialized).not.toContain("never-return-this");
    expect(serialized).not.toContain("example.invalid");
    expect(serialized).not.toContain("unrestricted raw provider payload");
    expect(snapshot.results.every(({ executionAuthorization }) =>
      executionAuthorization.state === "not_granted"
      && executionAuthorization.grantsMissionExecution === false)).toBe(true);
  });

  test("accepts a remote tool only through its exact fresh MCP inventory", () => {
    const snapshot = service().snapshot();
    expect(snapshot.results.find(({ component }) => component.id === "mcp:mcp-ready/registry-inspector"))
      .toMatchObject({
        status: "pass",
        availability: "available",
        testKind: "runtime_attestation",
        freshness: { state: "fresh" },
      });
    expect(snapshot.results.find(({ component }) =>
      component.id === "mcp:mcp-ready/registry-inspector/local-manifest"))
      .toMatchObject({
        status: "pass",
        availability: "available",
        freshness: { state: "fresh" },
      });
  });

  test("covers every ready MCP tool dependency with its exact fresh inventory receipt", () => {
    const input = runtime();
    const source = input.capabilityManifests!;
    const toolId = "mcp:mcp-ready/registry-inspector";
    const dependencyIds = ["exact-live-attestation", "mission-scoped-read-adapter"] as const;
    const snapshot = service({
      ...input,
      capabilityManifests: {
        ...source,
        tools: source.tools.map((tool) => tool.id === toolId
          ? {
              ...tool,
              dependencies: dependencyIds.map((id) => ({ id, ready: true })),
            }
          : tool),
      },
    }).snapshot();

    expect(snapshot.results.find(({ component }) => component.id === toolId))
      .toMatchObject({ status: "pass", availability: "available", freshness: { state: "fresh" } });
    const dependencyRows = snapshot.results.filter(({ component }) =>
      dependencyIds.some((dependencyId) => component.id === `${toolId}/${dependencyId}`));
    expect(dependencyRows).toHaveLength(dependencyIds.length);
    expect(dependencyRows.every(({ status, availability, freshness }) =>
      status === "pass"
      && availability === "available"
      && freshness.state === "fresh")).toBe(true);
  });

  test("reports local enforcement dependencies fresh only when they join the exact activation and executable receipts", () => {
    const input = runtime();
    const source = input.capabilityManifests!;
    const toolId = "kali:host-dns-query";
    const attestation = {
      schemaVersion: "ti-scale.local-tool-activation-receipt.v1" as const,
      source: "local_guided_tool_activation" as const,
      manifestSha256: "d".repeat(64),
      toolBindingSha256: "e".repeat(64),
      preflightBindingSha256: "b".repeat(64),
      executableSha256: "a".repeat(64),
      observedAt: "2026-07-18T19:59:35.000Z",
      expiresAt: "2026-07-18T20:00:30.000Z",
    };
    const localTool = {
      ...source.tools[0]!,
      id: toolId,
      label: "Host DNS query",
      mcpServerId: undefined,
      dependencies: [
        { id: "executable-integrity", ready: true, attestation },
        { id: "workspace-confinement", ready: true, attestation },
      ],
    };
    const snapshot = service({
      ...input,
      capabilityManifests: { ...source, tools: [...source.tools, localTool] },
    }, localHealth(), (requestedToolId) => requestedToolId === toolId
      ? readyLocalPreflight(toolId)
      : undefined).snapshot();

    for (const dependencyId of ["executable-integrity", "workspace-confinement"]) {
      expect(snapshot.results.find(({ component }) =>
        component.id === `${toolId}/${dependencyId}`)).toMatchObject({
          status: "pass",
          availability: "available",
          freshness: {
            state: "fresh",
            observedAt: "2026-07-18T19:59:35.000Z",
            expiresAt: "2026-07-18T20:00:30.000Z",
          },
        });
    }
    expect(snapshot.results.find(({ component }) => component.id === toolId))
      .toMatchObject({ status: "pass", availability: "available" });

    const mismatched = service({
      ...input,
      capabilityManifests: {
        ...source,
        tools: [...source.tools, {
          ...localTool,
          dependencies: [{
            id: "executable-integrity",
            ready: true,
            attestation: { ...attestation, executableSha256: "f".repeat(64) },
          }],
        }],
      },
    }, localHealth(), (requestedToolId) => requestedToolId === toolId
      ? readyLocalPreflight(toolId)
      : undefined).snapshot();
    expect(mismatched.results.find(({ component }) =>
      component.id === `${toolId}/executable-integrity`)).toMatchObject({
      status: "degraded",
      availability: "degraded",
    });
    expect(mismatched.results.find(({ component }) => component.id === toolId))
      .toMatchObject({ status: "fail", availability: "unavailable" });

    const mismatchedPreflightBinding = service({
      ...input,
      capabilityManifests: {
        ...source,
        tools: [...source.tools, {
          ...localTool,
          dependencies: [{
            id: "direct-argv-adapter",
            ready: true,
            attestation: { ...attestation, preflightBindingSha256: "f".repeat(64) },
          }],
        }],
      },
    }, localHealth(), (requestedToolId) => requestedToolId === toolId
      ? readyLocalPreflight(toolId)
      : undefined).snapshot();
    expect(mismatchedPreflightBinding.results.find(({ component }) =>
      component.id === `${toolId}/direct-argv-adapter`)).toMatchObject({
      status: "degraded",
      availability: "degraded",
    });
    expect(mismatchedPreflightBinding.results.find(({ component }) => component.id === toolId))
      .toMatchObject({ status: "fail", availability: "unavailable" });

    const futureDated = service({
      ...input,
      capabilityManifests: {
        ...source,
        tools: [...source.tools, {
          ...localTool,
          dependencies: [{
            id: "result-sink",
            ready: true,
            attestation: {
              ...attestation,
              observedAt: "2026-07-18T20:00:10.000Z",
              expiresAt: "2026-07-18T20:00:20.000Z",
            },
          }],
        }],
      },
    }, localHealth(), (requestedToolId) => requestedToolId === toolId
      ? readyLocalPreflight(toolId)
      : undefined).snapshot();
    expect(futureDated.results.find(({ component }) => component.id === toolId))
      .toMatchObject({ status: "fail", availability: "unavailable" });
    expect(futureDated.results.find(({ component }) => component.id === `${toolId}/result-sink`))
      .toMatchObject({ status: "degraded", availability: "degraded" });

    const stale = service({
      ...input,
      capabilityManifests: {
        ...source,
        tools: [...source.tools, {
          ...localTool,
          dependencies: [{
            id: "workspace-confinement",
            ready: true,
            attestation: {
              ...attestation,
              expiresAt: "2026-07-18T19:59:59.999Z",
            },
          }],
        }],
      },
    }, localHealth(), (requestedToolId) => requestedToolId === toolId
      ? readyLocalPreflight(toolId)
      : undefined).snapshot();
    expect(stale.results.find(({ component }) =>
      component.id === `${toolId}/workspace-confinement`)).toMatchObject({
        status: "fail",
        availability: "unavailable",
        freshness: { state: "stale" },
      });
  });

  test("accepts an in-process adapter only through distinct current composition receipts", () => {
    const snapshot = service(withRuntimeAdapter(runtime())).snapshot();
    expect(snapshot.results.find(
      ({ component }) => component.id === "runtime:reviewed-adapter",
    )).toMatchObject({
      testKind: "runtime_attestation",
      status: "pass",
      availability: "available",
      freshness: {
        state: "fresh",
        observedAt: "2026-07-18T19:59:30.000Z",
        expiresAt: "2026-07-18T20:00:30.000Z",
      },
    });
    expect(snapshot.results.find(
      ({ component }) =>
        component.id === "runtime:reviewed-adapter/reviewed-runtime-component",
    )).toMatchObject({
      testKind: "runtime_attestation",
      status: "pass",
      availability: "available",
    });
  });

  test("accepts a freshly bound in-process adapter with no subordinate components", () => {
    const snapshot = service(withRuntimeAdapter(runtime(), {
      withoutDependencies: true,
    })).snapshot();
    expect(snapshot.results.find(
      ({ component }) => component.id === "runtime:reviewed-adapter",
    )).toMatchObject({
      testKind: "runtime_attestation",
      status: "pass",
      availability: "available",
      freshness: { state: "fresh" },
    });
    expect(snapshot.results.some(
      ({ component }) => component.kind === "tool_dependency"
        && component.id.startsWith("runtime:reviewed-adapter/"),
    )).toBeFalse();
  });

  test("withdraws an in-process adapter after its composition receipts expire", () => {
    const snapshot = service(withRuntimeAdapter(runtime(), {
      expiresAt: "2026-07-18T19:59:59.000Z",
    })).snapshot();
    expect(snapshot.results.find(
      ({ component }) => component.id === "runtime:reviewed-adapter",
    )).toMatchObject({
      testKind: "runtime_attestation",
      status: "fail",
      availability: "unavailable",
      freshness: { state: "stale" },
    });
  });

  test.each([
    {
      case: "future-dated",
      observedAt: "2026-07-18T20:00:10.000Z",
      expiresAt: "2026-07-18T20:00:30.000Z",
      freshness: "fresh",
    },
    {
      case: "expired",
      observedAt: "2026-07-18T19:58:30.000Z",
      expiresAt: "2026-07-18T19:59:59.000Z",
      freshness: "stale",
    },
  ])("rejects an in-process adapter receipt that is $case", ({
    observedAt,
    expiresAt,
    freshness: expectedFreshness,
  }) => {
    const input = runtime();
    const source = input.capabilityManifests!;
    const parent = runtimeAdapterAttestation({ observedAt }, expiresAt);
    const dependency = runtimeAdapterAttestation({
      dependencyId: "reviewed-runtime-component",
      parentBindingSha256: parent.bindingSha256,
      observedAt,
    }, expiresAt);
    const snapshot = service({
      ...input,
      capabilityManifests: {
        ...source,
        tools: [...source.tools, {
          id: "runtime:reviewed-adapter",
          label: "Reviewed in-process adapter",
          available: true,
          locallyPolicyEnforced: true,
          requiresModel: false,
          executionJourneys: ["autonomous"],
          actionClassIds: ["passive_intelligence_osint"],
          evidenceTypeIds: ["asset_discovery_proof"],
          riskClassIds: ["read-only"],
          runtimeAdapterAttestation: parent,
          dependencies: [{
            id: "reviewed-runtime-component",
            ready: true,
            runtimeAdapterAttestation: dependency,
          }],
        }],
      },
    }).snapshot();

    expect(snapshot.results.find(
      ({ component }) => component.id === "runtime:reviewed-adapter",
    )).toMatchObject({
      status: "fail",
      availability: "unavailable",
      freshness: { state: expectedFreshness },
    });
  });

  test("rejects a cryptographically reissued runtime receipt whose lifetime exceeds the five-minute bound", () => {
    const input = runtime();
    const source = input.capabilityManifests!;
    const validParent = runtimeAdapterAttestation();
    const excessiveParent = withReissuedLifetime(
      validParent,
      "2026-07-18T19:59:30.000Z",
      "2026-07-18T20:09:30.001Z",
    );
    const validDependency = runtimeAdapterAttestation({
      dependencyId: "reviewed-runtime-component",
      parentBindingSha256: validParent.bindingSha256,
    });
    const excessiveDependency = withReissuedLifetime(
      validDependency,
      "2026-07-18T19:59:30.000Z",
      "2026-07-18T20:09:30.001Z",
    );
    const snapshot = service({
      ...input,
      capabilityManifests: {
        ...source,
        tools: [...source.tools, {
          id: "runtime:reviewed-adapter",
          label: "Reviewed in-process adapter",
          available: true,
          locallyPolicyEnforced: true,
          requiresModel: false,
          executionJourneys: ["autonomous"],
          actionClassIds: ["passive_intelligence_osint"],
          evidenceTypeIds: ["asset_discovery_proof"],
          riskClassIds: ["read-only"],
          runtimeAdapterAttestation: excessiveParent,
          dependencies: [{
            id: "reviewed-runtime-component",
            ready: true,
            runtimeAdapterAttestation: excessiveDependency,
          }],
        }],
      },
    }).snapshot();

    expect(snapshot.accounting.manifestValid).toBeFalse();
    expect(snapshot.results.find(
      ({ component }) => component.id === "runtime:reviewed-adapter",
    )).toMatchObject({ status: "fail", availability: "unavailable" });
  });

  test("rejects valid receipts when a foreign parent or sibling dependency is swapped into the manifest", () => {
    const input = runtime();
    const source = input.capabilityManifests!;
    const reviewedParent = runtimeAdapterAttestation();
    const foreignParent = runtimeAdapterAttestation({
      toolId: "runtime:foreign-adapter",
    });
    const first = runtimeAdapterAttestation({
      dependencyId: "first-component",
      parentBindingSha256: reviewedParent.bindingSha256,
    });
    const second = runtimeAdapterAttestation({
      dependencyId: "second-component",
      parentBindingSha256: reviewedParent.bindingSha256,
    });
    const tool = {
      id: "runtime:reviewed-adapter",
      label: "Reviewed in-process adapter",
      available: true,
      locallyPolicyEnforced: true,
      requiresModel: false,
      executionJourneys: ["autonomous"] as const,
      actionClassIds: ["passive_intelligence_osint"],
      evidenceTypeIds: ["asset_discovery_proof"],
      riskClassIds: ["read-only"],
      dependencies: [{
        id: "first-component",
        ready: true,
        runtimeAdapterAttestation: first,
      }, {
        id: "second-component",
        ready: true,
        runtimeAdapterAttestation: second,
      }],
    };
    const adversarialCases = [{
      runtimeAdapterAttestation: foreignParent,
      dependencies: tool.dependencies,
    }, {
      runtimeAdapterAttestation: reviewedParent,
      dependencies: [{
        ...tool.dependencies[0]!,
        runtimeAdapterAttestation: second,
      }, {
        ...tool.dependencies[1]!,
        runtimeAdapterAttestation: first,
      }],
    }];
    for (const adversarial of adversarialCases) {
      const snapshot = service({
        ...input,
        capabilityManifests: {
          ...source,
          tools: [...source.tools, {
            ...tool,
            ...adversarial,
          }],
        },
      }).snapshot();
      expect(snapshot.accounting.manifestValid).toBeFalse();
      expect(snapshot.results.find(
        ({ component }) => component.id === "runtime:reviewed-adapter",
      )).toMatchObject({ status: "fail", availability: "unavailable" });
    }
  });

  test("changes the parent binding for every component receipt-hash change", () => {
    const base = runtimeAdapterAttestation();
    for (const componentSha256 of ["5".repeat(64), "6".repeat(64), "7".repeat(64)]) {
      const changed = createRuntimeAdapterAttestation({
        toolId: base.toolId,
        executionJourneys: base.executionJourneys,
        binding: {
          ...base.binding,
          componentReceiptSha256s: [componentSha256],
        },
        observedAt: base.observedAt,
        expiresAt: base.expiresAt,
      });
      expect(changed.bindingSha256).not.toBe(base.bindingSha256);
      expect(changed.receiptSha256).not.toBe(base.receiptSha256);
    }
  });

  test("does not promote a registry-only in-process adapter claim", () => {
    const snapshot = service(withRuntimeAdapter(runtime(), {
      omitParentAttestation: true,
      omitDependencyAttestation: true,
    })).snapshot();
    expect(snapshot.results.find(
      ({ component }) => component.id === "runtime:reviewed-adapter",
    )).toMatchObject({
      status: "fail",
      availability: "unavailable",
      freshness: { state: "unknown" },
    });
  });

  test("rejects an orphan in-process dependency receipt structurally", () => {
    const snapshot = service(withRuntimeAdapter(runtime(), {
      omitParentAttestation: true,
    })).snapshot();
    expect(snapshot.accounting.manifestValid).toBeFalse();
    expect(snapshot.results.find(
      ({ component }) => component.id === "runtime:reviewed-adapter",
    )).toMatchObject({
      status: "fail",
      availability: "unavailable",
    });
  });

  test("attests planner-visible composites only through every exact constituent receipt", () => {
    const input = runtime();
    const source = input.capabilityManifests!;
    const attestation = {
      schemaVersion: "ti-scale.local-tool-activation-receipt.v1" as const,
      source: "local_guided_tool_activation" as const,
      manifestSha256: "d".repeat(64),
      toolBindingSha256: "e".repeat(64),
      preflightBindingSha256: "b".repeat(64),
      executableSha256: "a".repeat(64),
      observedAt: "2026-07-18T19:59:35.000Z",
      expiresAt: "2026-07-18T20:00:30.000Z",
    };
    const constituent = (id: string) => ({
      ...source.tools[0]!,
      id,
      label: id,
      mcpServerId: undefined,
      requiresModel: false,
      executionJourneys: ["guided"] as const,
      dependencies: [{ id: "executable-integrity", ready: true, attestation }],
    });
    const first = constituent("kali:composite-phase-one");
    const second = constituent("kali:composite-phase-two");
    const composite = {
      ...source.tools[0]!,
      id: "ti-scale:planner-visible-composite",
      label: "Planner-visible composite",
      mcpServerId: undefined,
      requiresModel: false,
      executionJourneys: ["autonomous"] as const,
      constituentToolIds: [first.id, second.id],
      dependencies: [{ id: "composite-action-boundary", ready: true, attestation }],
    };
    const projection: RuntimeProjectionInput = {
      ...input,
      capabilityManifests: {
        ...source,
        tools: [...source.tools, composite, second, first],
      },
    };
    const requested: string[] = [];
    const snapshot = service(projection, localHealth(), (toolId) => {
      requested.push(toolId);
      return toolId === first.id || toolId === second.id
        ? readyLocalPreflight(toolId)
        : undefined;
    }).snapshot();
    expect(snapshot.results.find(({ component }) => component.id === composite.id))
      .toMatchObject({
        testKind: "local_executable_attestation",
        status: "pass",
        availability: "available",
        freshness: { state: "fresh" },
      });
    expect(snapshot.results.find(({ component }) =>
      component.id === `${composite.id}/composite-action-boundary`)).toMatchObject({
      status: "pass",
      availability: "available",
      freshness: { state: "fresh" },
    });
    expect(requested).not.toContain(composite.id);

    const missingSecond = service(projection, localHealth(), (toolId) =>
      toolId === first.id ? readyLocalPreflight(toolId) : undefined).snapshot();
    const failedComposite = missingSecond.results.find(({ component }) => component.id === composite.id);
    expect(failedComposite).toMatchObject({ status: "fail", availability: "unavailable" });
    expect(failedComposite?.explanation).toContain(second.id);
  });

  test("withdraws every Autonomous composite backed by a stale or unenforced constituent", () => {
    const input = runtime();
    const source = input.capabilityManifests!;
    const freshAttestation = {
      schemaVersion: "ti-scale.local-tool-activation-receipt.v1" as const,
      source: "local_guided_tool_activation" as const,
      manifestSha256: "d".repeat(64),
      toolBindingSha256: "e".repeat(64),
      preflightBindingSha256: "b".repeat(64),
      executableSha256: "a".repeat(64),
      observedAt: "2026-07-18T19:59:35.000Z",
      expiresAt: "2026-07-18T20:00:30.000Z",
    };
    const constituent = (
      id: string,
      options: Readonly<{ stale?: boolean; policyEnforced?: boolean }> = {},
    ) => ({
      ...source.tools[0]!,
      id,
      label: id,
      available: true,
      locallyPolicyEnforced: options.policyEnforced ?? true,
      mcpServerId: undefined,
      requiresModel: false,
      executionJourneys: ["guided"] as const,
      dependencies: [{
        id: "executable-integrity",
        ready: true,
        attestation: options.stale
          ? { ...freshAttestation, expiresAt: "2026-07-18T19:59:59.999Z" }
          : freshAttestation,
      }],
    });
    const fresh = constituent("kali:composite-fresh-constituent");
    const stale = constituent("kali:composite-stale-constituent", { stale: true });
    const unenforced = constituent("kali:composite-unenforced-constituent", {
      policyEnforced: false,
    });
    const composite = (id: string, blockedConstituentId: string) => ({
      ...source.tools[0]!,
      id,
      label: id,
      available: true,
      locallyPolicyEnforced: true,
      mcpServerId: undefined,
      requiresModel: false,
      executionJourneys: ["autonomous"] as const,
      constituentToolIds: [fresh.id, blockedConstituentId],
      dependencies: [],
    });
    const staleComposite = composite("ti-scale:stale-autonomous-composite", stale.id);
    const unenforcedComposite = composite(
      "ti-scale:unenforced-autonomous-composite",
      unenforced.id,
    );
    const snapshot = service({
      ...input,
      capabilityManifests: {
        ...source,
        tools: [
          ...source.tools,
          staleComposite,
          unenforcedComposite,
          fresh,
          stale,
          unenforced,
        ],
      },
    }, localHealth(), (toolId) => [fresh.id, stale.id, unenforced.id].includes(toolId)
      ? readyLocalPreflight(toolId)
      : undefined).snapshot();

    const autonomousComposites = [staleComposite, unenforcedComposite];
    for (const advertised of autonomousComposites) {
      const row = snapshot.results.find(({ component }) => component.id === advertised.id);
      expect(row).toMatchObject({ status: "fail", availability: "unavailable" });
      expect(row?.freshness.state).not.toBe("fresh");
      expect(row?.explanation).toContain(advertised.constituentToolIds[1]!);
    }
  });

  test("rejects a ready local receipt whose embedded tool identity does not match its registry key", () => {
    const input = runtime();
    const source = input.capabilityManifests!;
    const localTool = {
      ...source.tools[0]!,
      id: "kali:nmap",
      label: "Nmap",
      mcpServerId: undefined,
      dependencies: [],
    };
    const snapshot = service({
      ...input,
      capabilityManifests: { ...source, tools: [...source.tools, localTool] },
    }, localHealth(), () => ({
      schemaVersion: "ti-scale.tool-execution-preflight.v2",
      toolId: "kali:different-tool",
      status: "ready",
      code: "ready",
      checkedAt: "2026-07-18T19:59:30.000Z",
      expiresAt: "2026-07-18T20:00:30.000Z",
      bindingSha256: "b".repeat(64),
      probeBoundary: {
        shell: false,
        targetArgumentsSupplied: false,
        providerArgumentsSupplied: false,
        mcpArgumentsSupplied: false,
        networkIsolationEnforced: true,
        filesystemWriteIsolationEnforced: true,
        immutableSnapshotExecutionEnforced: true,
        externalContact: "not_measured",
      },
      executableIdentity: {
        sha256: "a".repeat(64),
        device: "1",
        inode: "2",
        sizeBytes: 1024,
        mode: 0o755,
        uid: 0,
        gid: 0,
      },
      noNewPrivileges: true,
      explanation: "Bearer sk-never-return-this",
      remediation: "password=never-return-this",
      execution: {
        exitCode: 0,
        signal: null,
        spawnErrorCode: null,
        outputBytes: 10,
        outputSha256: "c".repeat(64),
      },
    })).snapshot();

    expect(snapshot.results.find(({ component }) => component.id === "kali:nmap"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
    expect(JSON.stringify(snapshot)).not.toContain("never-return-this");
  });

  test.each([
    ["incomplete", []],
    ["over-broad", ["mcp:mcp-ready/registry-inspector", "mcp:mcp-ready/undeclared-tool"]],
  ] as const)("fails the MCP server and its tool when the runtime inventory is %s", (_case, capabilities) => {
    const input = runtime();
    const snapshot = service({
      ...input,
      mcpServers: input.mcpServers.map((server) => server.id === "mcp-ready"
        ? { ...server, capabilities }
        : server),
    }).snapshot();
    expect(snapshot.results.find(({ component }) => component.id === "mcp-ready"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
    expect(snapshot.results.find(({ component }) => component.id === "mcp:mcp-ready/registry-inspector"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
  });

  test("accepts a fresh mission-scoped read-only MCP adapter without claiming generic execution", () => {
    const input = runtime();
    const snapshot = service({
      ...input,
      readiness: {
        ...input.readiness,
        mcp: {
          ...input.readiness.mcp,
          enabled: false,
          executionMode: "disabled",
          startPermitted: false,
          runnableServers: 0,
        },
      },
      mcpServers: input.mcpServers.map((server) => server.id === "mcp-ready"
        ? {
            ...server,
            policy: {
              missionScopedReadAdapter: true,
              readOnly: true,
              targetInteraction: false,
              attested: true,
              executionAuthorization: "none",
              expiresAt: "2026-07-18T20:01:00.000Z",
              manifestSha256: "a".repeat(64),
            },
          }
        : server),
    }).snapshot();
    expect(snapshot.results.find(({ component }) => component.id === "mcp-ready"))
      .toMatchObject({ status: "pass", availability: "available" });
    expect(snapshot.results.find(({ component }) => component.id === "mcp:mcp-ready/registry-inspector"))
      .toMatchObject({ status: "pass", availability: "available" });
    expect(snapshot.grantsMissionExecution).toBe(false);
  });

  test("withdraws a mission-scoped read adapter when its attestation receipt expires", () => {
    const input = runtime();
    const snapshot = service({
      ...input,
      readiness: {
        ...input.readiness,
        mcp: {
          ...input.readiness.mcp,
          enabled: false,
          executionMode: "disabled",
          startPermitted: false,
          runnableServers: 0,
        },
      },
      mcpServers: input.mcpServers.map((server) => server.id === "mcp-ready"
        ? {
            ...server,
            policy: {
              missionScopedReadAdapter: true,
              readOnly: true,
              targetInteraction: false,
              attested: true,
              executionAuthorization: "none",
              expiresAt: "2026-07-18T19:59:59.999Z",
              manifestSha256: "a".repeat(64),
            },
          }
        : server),
    }).snapshot();
    expect(snapshot.results.find(({ component }) => component.id === "mcp-ready"))
      .toMatchObject({ status: "fail", availability: "unavailable", freshness: { state: "stale" } });
    expect(snapshot.results.find(({ component }) => component.id === "mcp:mcp-ready/registry-inspector"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
  });

  test("rejects an exact-looking MCP inventory whose qualified prefix belongs to another server", () => {
    const input = runtime();
    const wrongId = "mcp:other-server/registry-inspector";
    const source = input.capabilityManifests!;
    const snapshot = service({
      ...input,
      mcpServers: input.mcpServers.map((server) => server.id === "mcp-ready"
        ? { ...server, capabilities: [wrongId] }
        : server),
      capabilityManifests: {
        ...source,
        tools: source.tools.map((tool) => tool.id === "mcp:mcp-ready/registry-inspector"
          ? { ...tool, id: wrongId }
          : tool),
        mcpServers: source.mcpServers.map((server) => server.id === "mcp-ready"
          ? { ...server, toolIds: [wrongId] }
          : server),
      },
    }).snapshot();

    expect(snapshot.accounting.manifestValid).toBe(true);
    expect(snapshot.results.find(({ component }) => component.id === "mcp-ready"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
    expect(snapshot.results.find(({ component }) => component.id === wrongId))
      .toMatchObject({ status: "fail", availability: "unavailable" });
  });

  test("does not substitute provider catalog freshness for a runtime attestation", () => {
    const input = runtime();
    const providers = input.readiness.providers.map((provider) => {
      if (provider.id !== "provider-ready") return provider;
      const {
        attestedAt: _ignoredAttestation,
        expiresAt: _ignoredExpiry,
        ...withoutAttestation
      } = provider;
      return withoutAttestation;
    });
    const snapshot = service({
      ...input,
      readiness: { ...input.readiness, providers },
    }).snapshot();
    expect(snapshot.results.find(({ component }) => component.id === "provider-ready"))
      .toMatchObject({
        status: "degraded",
        availability: "degraded",
        freshness: { state: "unknown", observedAt: null },
      });
  });

  test("never reports structurally invalid manifests as complete", () => {
    const input = runtime();
    const invalidManifests = manifests();
    const snapshot = service({
      ...input,
      capabilityManifests: {
        ...invalidManifests,
        providers: [...invalidManifests.providers, invalidManifests.providers[0]!],
      },
    }).snapshot();
    expect(snapshot.accounting).toMatchObject({
      runtimeRegistryRead: true,
      manifestValid: false,
      complete: false,
    });
    expect(snapshot.results.find(({ component }) => component.kind === "registry"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
    expect(snapshot.results
      .filter(({ component }) => ["provider", "mcp_server", "tool", "tool_dependency"]
        .includes(component.kind))
      .every(({ status, availability }) =>
        status === "fail" && availability === "unavailable")).toBe(true);
  });

  test("withdraws every server and tool when MCP IDs alias the same namespace", () => {
    const input = runtime();
    const source = input.capabilityManifests!;
    const aliasServerId = "mcp:mcp-ready";
    const aliasToolId = "mcp:mcp-ready/alias-inspector";
    const snapshot = service({
      ...input,
      mcpServers: [
        ...input.mcpServers,
        {
          id: aliasServerId,
          name: "Aliased namespace owner",
          transport: "local",
          status: "healthy",
          capabilities: [aliasToolId],
          policy: {},
          lastCheckedAt: "2026-07-18T19:59:30.000Z",
        },
      ],
      capabilityManifests: {
        ...source,
        tools: [
          ...source.tools,
          {
            ...source.tools[0]!,
            id: aliasToolId,
            label: "Aliased inventory tool",
            mcpServerId: aliasServerId,
          },
        ],
        mcpServers: [
          ...source.mcpServers,
          {
            id: aliasServerId,
            label: "Aliased namespace owner",
            status: "healthy",
            toolIds: [aliasToolId],
          },
        ],
      },
    }).snapshot();

    expect(snapshot.accounting.manifestValid).toBe(true);
    for (const componentId of [
      "mcp-ready",
      aliasServerId,
      "mcp:mcp-ready/registry-inspector",
      aliasToolId,
    ]) {
      expect(snapshot.results.find(({ component }) => component.id === componentId))
        .toMatchObject({ status: "fail", availability: "unavailable" });
    }
  });

  test("reports an absent runtime registry as incomplete instead of inventing capabilities", () => {
    const { capabilityManifests: _ignored, ...withoutManifests } = runtime();
    const snapshot = service(withoutManifests).snapshot();
    expect(snapshot.accounting).toMatchObject({
      runtimeRegistryRead: false,
      manifestValid: false,
      complete: false,
      registered: { providers: 2, mcpServers: 2, tools: 0, toolDependencies: 0 },
    });
    expect(snapshot.results.find(({ component }) => component.kind === "registry"))
      .toMatchObject({ status: "fail", availability: "unavailable" });
  });

  test("contains local health-reader failure without leaking the thrown payload", () => {
    const repository: CapabilityLocalHealthReader = {
      read(): CapabilityLocalHealthSnapshot {
        throw new Error("Bearer sk-never-return-this raw database payload");
      },
    };
    const snapshot = new CapabilitySelfTestService({
      repository,
      readRuntimeProjection: runtime,
      clock: () => NOW,
    }).snapshot();
    const localKinds = new Set(["database", "event_stream", "second_brain", "obsidian_vault"]);
    expect(snapshot.results.filter(({ component }) => localKinds.has(component.kind)))
      .toHaveLength(4);
    expect(snapshot.results.filter(({ component }) => localKinds.has(component.kind))
      .every(({ availability }) => availability === "unavailable")).toBe(true);
    expect(JSON.stringify(snapshot)).not.toContain("sk-never-return-this");
  });
});

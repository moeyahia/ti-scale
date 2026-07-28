import { describe, expect, test } from "bun:test";
import {
  PUBLIC_NVD_SERVER_NAME,
  PUBLIC_NVD_SERVER_VERSION,
  PUBLIC_NVD_TOOL_NAME,
} from "../../mcp-public-nvd";
import {
  PUBLIC_NVD_MCP_CONNECTION_ID,
  PUBLIC_NVD_INPUT_SCHEMA_SHA256,
  PUBLIC_NVD_OUTPUT_SCHEMA_SHA256,
} from "../PublicNvdMcpConfiguration";
import {
  createProductionPublicNvdMcpBoundary,
  createProductionPublicNvdMcpRuntime,
  PublicNvdMcpRuntime,
} from "../PublicNvdMcpRuntime";
import { PublicNvdToolBoundaryError } from "../PublicNvdMcpToolClient";
import type { McpCapabilityAttestation } from "../types";

const ATTESTED_AT = "2026-07-18T18:00:00.000Z";
const EXPIRES_AT = "2026-07-18T18:01:00.000Z";

function exactAttestation(): McpCapabilityAttestation {
  return {
    schemaVersion: "ti-scale.mcp-capability-attestation.v1",
    connectionId: PUBLIC_NVD_MCP_CONNECTION_ID,
    transport: "streamable-http",
    server: { name: PUBLIC_NVD_SERVER_NAME, version: PUBLIC_NVD_SERVER_VERSION },
    protocolVersion: "2025-11-25",
    capabilities: { toolsListChanged: false },
    configurationSha256: "a".repeat(64),
    tools: [{
      name: PUBLIC_NVD_TOOL_NAME,
      inputSchema: { type: "object" },
      inputSchemaSha256: PUBLIC_NVD_INPUT_SCHEMA_SHA256,
      inputSchemaBytes: 128,
      outputSchemaSha256: PUBLIC_NVD_OUTPUT_SCHEMA_SHA256,
      outputSchemaBytes: 512,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    }],
    manifestSha256: "b".repeat(64),
    attestedAt: ATTESTED_AT,
    expiresAt: EXPIRES_AT,
    executionAuthorization: "none",
  };
}

describe("PublicNvdMcpRuntime", () => {
  test("reports unavailable and performs no attestation or network-capable client call without its credential", async () => {
    let refreshCalls = 0;
    const runtime = new PublicNvdMcpRuntime({
      client: { async refreshAttestation() { refreshCalls += 1; return exactAttestation(); } },
      credentialAvailable: () => false,
      now: () => new Date(ATTESTED_AT),
    });
    expect(await runtime.refreshNow()).toMatchObject({
      status: "unavailable",
      credentialMounted: false,
      attested: false,
      toolNames: [],
      lastCheckedAt: ATTESTED_AT,
    });
    expect(refreshCalls).toBe(0);
  });

  test("shows probing while the exact check is pending and ready only after exact live attestation", async () => {
    let resolveAttestation!: (value: McpCapabilityAttestation) => void;
    const pendingAttestation = new Promise<McpCapabilityAttestation>((resolve) => {
      resolveAttestation = resolve;
    });
    const runtime = new PublicNvdMcpRuntime({
      client: { refreshAttestation: () => pendingAttestation },
      credentialAvailable: () => true,
      now: () => new Date(ATTESTED_AT),
    });
    const refresh = runtime.refreshNow();
    expect(runtime.snapshot()).toMatchObject({
      status: "probing",
      credentialMounted: true,
      attested: false,
      toolNames: [],
    });
    resolveAttestation(exactAttestation());
    expect(await refresh).toMatchObject({
      status: "ready",
      credentialMounted: true,
      attested: true,
      toolNames: [PUBLIC_NVD_TOOL_NAME],
      attestedAt: ATTESTED_AT,
      expiresAt: EXPIRES_AT,
      manifestSha256: "b".repeat(64),
    });
  });

  test("reports degraded and advertises no capability when exact attestation fails", async () => {
    const runtime = new PublicNvdMcpRuntime({
      client: {
        async refreshAttestation() {
          throw new PublicNvdToolBoundaryError(
            "ATTESTATION_REJECTED",
            "untrusted sidecar detail that must not be projected",
            false,
          );
        },
      },
      credentialAvailable: () => true,
      now: () => new Date(ATTESTED_AT),
    });
    const state = await runtime.refreshNow();
    expect(state).toMatchObject({
      status: "degraded",
      credentialMounted: true,
      attested: false,
      toolNames: [],
    });
    expect(state.reason).not.toContain("untrusted sidecar detail");
  });

  test("withdraws capabilities as soon as the attestation expires", async () => {
    let now = new Date(ATTESTED_AT);
    const runtime = new PublicNvdMcpRuntime({
      client: { refreshAttestation: async () => exactAttestation() },
      credentialAvailable: () => true,
      now: () => now,
    });
    await runtime.refreshNow();
    now = new Date(EXPIRES_AT);
    expect(runtime.snapshot()).toMatchObject({
      status: "degraded",
      attested: false,
      toolNames: [],
      expiresAt: EXPIRES_AT,
    });
  });

  test("rejects schema drift even when the server name and read-only annotations still match", async () => {
    const exact = exactAttestation();
    const drifted: McpCapabilityAttestation = {
      ...exact,
      tools: [{
        ...exact.tools[0]!,
        outputSchemaSha256: "c".repeat(64),
      }],
    };
    const runtime = new PublicNvdMcpRuntime({
      client: { refreshAttestation: async () => drifted },
      credentialAvailable: () => true,
      now: () => new Date(ATTESTED_AT),
    });
    expect(await runtime.refreshNow()).toMatchObject({
      status: "degraded",
      attested: false,
      toolNames: [],
    });
  });

  test("keeps production composition fail-closed when the credential directory is invalid", async () => {
    const runtime = createProductionPublicNvdMcpRuntime({
      environment: { CREDENTIALS_DIRECTORY: "relative/untrusted" },
      now: () => new Date(ATTESTED_AT),
    });
    expect(await runtime.refreshNow()).toMatchObject({
      status: "unavailable",
      credentialMounted: false,
      attested: false,
      toolNames: [],
    });
  });

  test("shares one fail-closed production client without granting invocation before attestation", async () => {
    const boundary = createProductionPublicNvdMcpBoundary({
      environment: { CREDENTIALS_DIRECTORY: "relative/untrusted" },
      now: () => new Date(ATTESTED_AT),
    });
    expect(await boundary.runtime.refreshNow()).toMatchObject({
      status: "unavailable",
      credentialMounted: false,
      attested: false,
    });
    expect(boundary.readAttestation()).toBeUndefined();
    await expect(boundary.client.getCveDetails(
      "CVE-2021-44228",
      new AbortController().signal,
    )).rejects.toMatchObject({
      name: "PublicNvdToolBoundaryError",
      code: "NOT_ATTESTED",
      retryable: true,
    });
  });
});

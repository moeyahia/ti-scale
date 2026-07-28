import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";
import {
  PUBLIC_NVD_SERVER_NAME,
  PUBLIC_NVD_SERVER_VERSION,
  PUBLIC_NVD_TOOL_NAME,
} from "../mcp-public-nvd";
import { parseMcpServerConnectionConfig } from "./config";
import type { McpStreamableHttpConnectionConfig } from "./types";

export const PUBLIC_NVD_MCP_CONNECTION_ID = "public-nvd";
export const PUBLIC_NVD_MCP_CREDENTIAL_ID = "public-nvd-mcp-token";

/**
 * These digests bind the reviewed client policy to the exact JSON Schemas
 * advertised by ti-scale-public-nvd v0.1.0. A schema change must update the
 * server version, these values, and the live-contract regression test in one
 * reviewed change.
 */
export const PUBLIC_NVD_INPUT_SCHEMA_SHA256 =
  "350b96a4f41d4a0a6c7115d731bfe81cc96041a07e89064ca238a181415e6e28";
export const PUBLIC_NVD_OUTPUT_SCHEMA_SHA256 =
  "d487735d60e808447476c718a5523e76a1843ecc98a745295b82ce9ebf9b9438";

export interface PublicNvdMcpConnectionOptions {
  readonly port?: number;
  readonly ttlMs?: number;
  readonly timeoutMs?: number;
}

function boundedPort(value: number | undefined): number {
  const port = value ?? 43_142;
  if (!Number.isSafeInteger(port) || port < 1_024 || port > 65_535) {
    throw new RangeError("Public NVD MCP port must be between 1024 and 65535");
  }
  return port;
}

/**
 * Closed, loopback-only connection policy for the isolated public-NVD
 * sidecar. It does not contain a credential value; the transport receives the
 * bearer header from one credential ID in systemd's private mount.
 */
export function createPublicNvdMcpConnectionConfig(
  options: PublicNvdMcpConnectionOptions = {},
): McpStreamableHttpConnectionConfig {
  const port = boundedPort(options.port);
  return parseMcpServerConnectionConfig({
    id: PUBLIC_NVD_MCP_CONNECTION_ID,
    displayName: "Official public NVD intelligence",
    enabled: true,
    transport: "streamable-http",
    endpoint: `http://127.0.0.1:${port}/mcp`,
    allowInsecureLoopback: true,
    headerCredentials: {
      Authorization: {
        id: PUBLIC_NVD_MCP_CREDENTIAL_ID,
        scheme: "Bearer",
      },
    },
    expectedServer: {
      name: PUBLIC_NVD_SERVER_NAME,
      version: PUBLIC_NVD_SERVER_VERSION,
    },
    toolInventory: {
      requiredTools: [{
        name: PUBLIC_NVD_TOOL_NAME,
        inputSchemaSha256: PUBLIC_NVD_INPUT_SCHEMA_SHA256,
        outputSchemaSha256: PUBLIC_NVD_OUTPUT_SCHEMA_SHA256,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true,
        },
      }],
      allowAdditionalTools: false,
      minimumToolCount: 1,
    },
    attestation: {
      ttlMs: options.ttlMs ?? 60_000,
      timeoutMs: options.timeoutMs ?? 5_000,
      maxPages: 1,
      maxTools: 1,
      maxSchemaBytes: 64 * 1024,
      maxSchemaDepth: 32,
      maxManifestBytes: 256 * 1024,
      maxInboundMessageBytes: 512 * 1024,
      acceptedProtocolVersions: [LATEST_PROTOCOL_VERSION],
    },
  }) as McpStreamableHttpConnectionConfig;
}

import { describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createPublicNvdMcpServer } from "../../mcp-public-nvd";
import { digestCanonicalJson } from "../canonicalJson";
import {
  createPublicNvdMcpConnectionConfig,
  PUBLIC_NVD_INPUT_SCHEMA_SHA256,
  PUBLIC_NVD_OUTPUT_SCHEMA_SHA256,
} from "../PublicNvdMcpConfiguration";

async function liveInventory(): Promise<{
  readonly client: Client;
  readonly server: McpServer;
}> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createPublicNvdMcpServer({
    client: {
      async getCveDetails() {
        throw new Error("Schema discovery must never invoke the tool");
      },
    },
  });
  await server.connect(serverTransport);
  const client = new Client(
    { name: "ti-scale-public-nvd-schema-test", version: "0.1.0" },
    { capabilities: {} },
  );
  await client.connect(clientTransport);
  return { client, server };
}

describe("public NVD closed MCP configuration", () => {
  test("permits only the exact authenticated loopback endpoint and one reviewed tool", () => {
    const config = createPublicNvdMcpConnectionConfig();
    expect(config).toMatchObject({
      id: "public-nvd",
      endpoint: "http://127.0.0.1:43142/mcp",
      allowInsecureLoopback: true,
      headerCredentials: {
        Authorization: {
          id: "public-nvd-mcp-token",
          scheme: "Bearer",
        },
      },
      expectedServer: { name: "ti-scale-public-nvd", version: "0.1.0" },
      toolInventory: {
        allowAdditionalTools: false,
        minimumToolCount: 1,
        requiredTools: [{
          name: "get_cve_details",
          inputSchemaSha256: PUBLIC_NVD_INPUT_SCHEMA_SHA256,
          outputSchemaSha256: PUBLIC_NVD_OUTPUT_SCHEMA_SHA256,
          annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: true,
          },
        }],
      },
      attestation: { maxPages: 1, maxTools: 1 },
    });
    expect(() => createPublicNvdMcpConnectionConfig({ port: 80 })).toThrow(RangeError);
    expect(() => createPublicNvdMcpConnectionConfig({ port: 65_536 })).toThrow(RangeError);
  });

  test("pins both schema digests to the exact live server inventory", async () => {
    const connection = await liveInventory();
    try {
      const listed = await connection.client.listTools();
      expect(listed.tools).toHaveLength(1);
      const tool = listed.tools[0]!;
      expect(digestCanonicalJson(tool.inputSchema, {
        maxBytes: 64 * 1024,
        maxDepth: 32,
      }).sha256).toBe(PUBLIC_NVD_INPUT_SCHEMA_SHA256);
      expect(digestCanonicalJson(tool.outputSchema, {
        maxBytes: 64 * 1024,
        maxDepth: 32,
      }).sha256).toBe(PUBLIC_NVD_OUTPUT_SCHEMA_SHA256);
    } finally {
      await connection.client.close();
      await connection.server.close();
    }
  });
});

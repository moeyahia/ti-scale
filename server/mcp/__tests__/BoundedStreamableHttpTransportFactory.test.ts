import { describe, expect, test } from "bun:test";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BoundedStreamableHttpTransportFactory,
  McpTransportBoundaryError,
} from "../BoundedStreamableHttpTransportFactory";
import { SystemdCredentialStore } from "../SystemdCredentialStore";
import type { McpStreamableHttpConnectionConfig } from "../types";

const endpoint = "http://127.0.0.1:43152/mcp";

function config(): McpStreamableHttpConnectionConfig {
  return {
    id: "public-nvd",
    displayName: "Public NVD",
    enabled: true,
    transport: "streamable-http",
    endpoint,
    allowInsecureLoopback: true,
    headerEnvironment: { "x-ti-scale-sidecar": "TI_SCALE_TEST_MCP_TOKEN" },
    expectedServer: { name: "ti-scale-public-nvd", version: "1.0.0" },
    toolInventory: { requiredTools: [{ name: "get_cve_details" }], allowAdditionalTools: false, minimumToolCount: 1 },
    attestation: {
      ttlMs: 60_000,
      timeoutMs: 5_000,
      maxPages: 1,
      maxTools: 1,
      maxSchemaBytes: 8_192,
      maxSchemaDepth: 12,
      maxManifestBytes: 32_768,
      maxInboundMessageBytes: 1_024,
      acceptedProtocolVersions: ["2025-11-25"],
    },
  };
}

function rpcResult(id: number): Response {
  return Response.json({ jsonrpc: "2.0", id, result: {} });
}

describe("BoundedStreamableHttpTransportFactory", () => {
  test("injects bearer authentication from a systemd credential ID without an environment secret", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-mcp-credential-"));
    try {
      writeFileSync(join(directory, "public-nvd-mcp-token"), "opaque-systemd-token\n", { mode: 0o400 });
      const base = config();
      const credentialConfig: McpStreamableHttpConnectionConfig = {
        ...base,
        headerEnvironment: undefined,
        headerCredentials: {
          Authorization: { id: "public-nvd-mcp-token", scheme: "Bearer" },
        },
      };
      let captured: Request | undefined;
      const factory = new BoundedStreamableHttpTransportFactory({
        credentialStore: new SystemdCredentialStore(directory),
        environment: {},
        fetch: (async (input, init) => {
          captured = new Request(input, init);
          return new Response(null, { status: 307 });
        }),
      });
      const transport = await factory.create(credentialConfig, {
        signal: new AbortController().signal,
        maxInboundMessageBytes: 1_024,
      });
      await transport.start();
      await expect(transport.send({ jsonrpc: "2.0", id: 1, method: "ping" }))
        .rejects.toMatchObject({ code: "TRANSPORT_REDIRECT_DENIED" });
      expect(captured?.headers.get("authorization")).toBe("Bearer opaque-systemd-token");
      await transport.close();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("does not make a network request when the systemd credential is unavailable", async () => {
    const base = config();
    const credentialConfig: McpStreamableHttpConnectionConfig = {
      ...base,
      headerEnvironment: undefined,
      headerCredentials: { Authorization: { id: "public-nvd-mcp-token", scheme: "Bearer" } },
    };
    let networkCalls = 0;
    const factory = new BoundedStreamableHttpTransportFactory({
      environment: {},
      fetch: async () => {
        networkCalls += 1;
        return new Response(null, { status: 500 });
      },
    });
    await expect(factory.create(credentialConfig, {
      signal: new AbortController().signal,
      maxInboundMessageBytes: 1_024,
    })).rejects.toMatchObject({ code: "TRANSPORT_CONFIG_INVALID" });
    expect(networkCalls).toBe(0);
  });

  test("pins the endpoint, injects only configured headers, and denies redirects", async () => {
    let captured: Request | undefined;
    const factory = new BoundedStreamableHttpTransportFactory({
      environment: { TI_SCALE_TEST_MCP_TOKEN: "opaque-sidecar-token" },
      fetch: (async (input, init) => {
        captured = new Request(input, init);
        return new Response(null, { status: 307, headers: { location: "http://127.0.0.1:9/mcp" } });
      }),
    });
    const abort = new AbortController();
    const transport = await factory.create(config(), { signal: abort.signal, maxInboundMessageBytes: 1_024 });
    await transport.start();
    await expect(transport.send({ jsonrpc: "2.0", id: 1, method: "ping" })).rejects.toMatchObject({
      code: "TRANSPORT_REDIRECT_DENIED",
    });
    expect(captured?.url).toBe(endpoint);
    expect(captured?.headers.get("x-ti-scale-sidecar")).toBe("opaque-sidecar-token");
    await transport.close();
  });

  test("rejects a declared response larger than the pre-parse limit", async () => {
    const factory = new BoundedStreamableHttpTransportFactory({
      environment: { TI_SCALE_TEST_MCP_TOKEN: "opaque-sidecar-token" },
      fetch: (async () => new Response("{}", {
        status: 200,
        headers: { "content-type": "application/json", "content-length": "2048" },
      })),
    });
    const transport = await factory.create(config(), {
      signal: new AbortController().signal,
      maxInboundMessageBytes: 1_024,
    });
    await transport.start();
    await expect(transport.send({ jsonrpc: "2.0", id: 1, method: "ping" })).rejects.toBeInstanceOf(
      McpTransportBoundaryError,
    );
    await transport.close();
  });

  test("rejects a streamed response after it crosses the pre-parse limit", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(800));
        controller.enqueue(new Uint8Array(800));
        controller.close();
      },
    });
    const factory = new BoundedStreamableHttpTransportFactory({
      environment: { TI_SCALE_TEST_MCP_TOKEN: "opaque-sidecar-token" },
      fetch: (async () => new Response(body, {
        status: 200,
        headers: { "content-type": "application/json" },
      })),
    });
    const transport = await factory.create(config(), {
      signal: new AbortController().signal,
      maxInboundMessageBytes: 1_024,
    });
    await transport.start();
    await expect(transport.send({ jsonrpc: "2.0", id: 1, method: "ping" })).rejects.toMatchObject({
      code: "TRANSPORT_RESPONSE_TOO_LARGE",
    });
    await transport.close();
  });

  test("rejects an outbound JSON-RPC body larger than the same bounded envelope", async () => {
    let called = false;
    const factory = new BoundedStreamableHttpTransportFactory({
      environment: { TI_SCALE_TEST_MCP_TOKEN: "opaque-sidecar-token" },
      fetch: (async () => {
        called = true;
        return rpcResult(1);
      }),
    });
    const transport = await factory.create(config(), {
      signal: new AbortController().signal,
      maxInboundMessageBytes: 1_024,
    });
    await transport.start();
    const message = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "get_cve_details", arguments: { cve_id: `CVE-${"1".repeat(2_000)}` } },
    } as unknown as JSONRPCMessage;
    await expect(transport.send(message)).rejects.toMatchObject({ code: "TRANSPORT_REQUEST_TOO_LARGE" });
    expect(called).toBe(false);
    await transport.close();
  });

  test("fails closed when a configured credential reference is absent", async () => {
    const factory = new BoundedStreamableHttpTransportFactory({ environment: {} });
    await expect(factory.create(config(), {
      signal: new AbortController().signal,
      maxInboundMessageBytes: 1_024,
    })).rejects.toMatchObject({ code: "TRANSPORT_CONFIG_INVALID" });
  });

  test("closes an active transport when the owning operation is cancelled", async () => {
    const abort = new AbortController();
    const factory = new BoundedStreamableHttpTransportFactory({
      environment: { TI_SCALE_TEST_MCP_TOKEN: "opaque-sidecar-token" },
      fetch: (async (_input, init) => {
        if (init?.signal?.aborted) throw new DOMException("Aborted", "AbortError");
        await new Promise<void>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
        });
        return rpcResult(1);
      }),
    });
    const transport = await factory.create(config(), { signal: abort.signal, maxInboundMessageBytes: 1_024 });
    await transport.start();
    const pending = transport.send({ jsonrpc: "2.0", id: 1, method: "ping" });
    abort.abort();
    await expect(pending).rejects.toHaveProperty("name", "AbortError");
    await transport.close();
  });
});

import { describe, expect, test } from "bun:test";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  LATEST_PROTOCOL_VERSION,
  ListToolsRequestSchema,
  type ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { digestCanonicalJson } from "../canonicalJson";
import { parseMcpServerConnectionConfig } from "../config";
import {
  McpCapabilityAttester,
  isMcpAttestationCurrentForConfig,
  isMcpAttestationFresh,
} from "../McpCapabilityAttester";
import type {
  McpAttestationTransportFactory,
  McpServerConnectionConfig,
} from "../types";

const NOW = new Date("2026-07-18T12:00:00.000Z");
const TARGET_SCHEMA = {
  type: "object" as const,
  properties: {
    target: { type: "string", minLength: 1 },
    timeoutMs: { type: "integer", minimum: 100, maximum: 30_000 },
  },
  required: ["target"],
  additionalProperties: false,
};
const TARGET_SCHEMA_HASH = digestCanonicalJson(TARGET_SCHEMA, {
  maxBytes: 64 * 1024,
  maxDepth: 32,
}).sha256;
const OUTPUT_SCHEMA = {
  type: "object" as const,
  properties: { reachable: { type: "boolean" } },
  required: ["reachable"],
  additionalProperties: false,
};
const OUTPUT_SCHEMA_HASH = digestCanonicalJson(OUTPUT_SCHEMA, {
  maxBytes: 64 * 1024,
  maxDepth: 32,
}).sha256;

function connection(
  overrides: Partial<McpServerConnectionConfig> = {},
): McpServerConnectionConfig {
  return {
    id: "recon-mcp",
    displayName: "Recon MCP",
    enabled: true,
    transport: "streamable-http",
    endpoint: "https://mcp.test.invalid/mcp",
    allowInsecureLoopback: false,
    headerEnvironment: { Authorization: "TEST_MCP_AUTHORIZATION" },
    expectedServer: { name: "fake-recon", version: "1.2.3" },
    toolInventory: {
      requiredTools: [{
        name: "inspect_target",
        inputSchemaSha256: TARGET_SCHEMA_HASH,
        annotations: { readOnlyHint: true, destructiveHint: false },
      }],
      allowAdditionalTools: true,
      minimumToolCount: 1,
    },
    attestation: {
      ttlMs: 60_000,
      timeoutMs: 2_000,
      maxPages: 4,
      maxTools: 8,
      maxSchemaBytes: 64 * 1024,
      maxSchemaDepth: 32,
      maxManifestBytes: 512 * 1024,
      maxInboundMessageBytes: 512 * 1024,
      acceptedProtocolVersions: [LATEST_PROTOCOL_VERSION],
    },
    ...overrides,
  } as McpServerConnectionConfig;
}

interface FakeServerOptions {
  readonly name?: string;
  readonly version?: string;
  readonly declareToolsCapability?: boolean;
  readonly listTools?: (
    cursor: string | undefined,
  ) => ListToolsResult | Promise<ListToolsResult>;
}

async function fakeServer(options: FakeServerOptions = {}): Promise<{
  readonly factory: McpAttestationTransportFactory;
  readonly wasInitialized: () => boolean;
}> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  let initialized = false;
  const declareTools = options.declareToolsCapability ?? true;
  const server = new Server(
    { name: options.name ?? "fake-recon", version: options.version ?? "1.2.3" },
    { capabilities: declareTools ? { tools: { listChanged: true } } : {} },
  );
  server.oninitialized = () => {
    initialized = true;
  };
  if (declareTools) {
    server.setRequestHandler(ListToolsRequestSchema, async (request) =>
      await options.listTools?.(request.params?.cursor) ?? {
        tools: [{
          name: "inspect_target",
          title: "Inspect target",
          description: "Reads target metadata without changing the target.",
          inputSchema: TARGET_SCHEMA,
          outputSchema: OUTPUT_SCHEMA,
          execution: { taskSupport: "forbidden" },
          annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: false,
          },
        }],
      });
  }
  await server.connect(serverTransport);

  let created = false;
  return {
    factory: {
      async create(): Promise<Transport> {
        if (created) throw new Error("Fake transport is single-use");
        created = true;
        return clientTransport;
      },
    },
    wasInitialized: () => initialized,
  };
}

describe("MCP capability attestation", () => {
  test("binds initialize and paginated tools/list results into a fresh immutable manifest", async () => {
    let listRequests = 0;
    const fake = await fakeServer({
      listTools(cursor) {
        listRequests += 1;
        if (!cursor) {
          return {
            tools: [{
              name: "inspect_target",
              title: "Inspect target",
              description: "Reads target metadata without changing the target.",
              inputSchema: TARGET_SCHEMA,
              outputSchema: OUTPUT_SCHEMA,
              execution: { taskSupport: "forbidden" },
              annotations: { readOnlyHint: true, destructiveHint: false },
            }],
            nextCursor: "page-2",
          };
        }
        return {
          tools: [{
            name: "read_certificate",
            inputSchema: { type: "object", properties: { host: { type: "string" } } },
          }],
        };
      },
    });

    const outcome = await new McpCapabilityAttester(fake.factory, { now: () => NOW })
      .attest(connection());

    expect(outcome.status).toBe("attested");
    if (outcome.status !== "attested") throw new Error("Expected successful attestation");
    expect(fake.wasInitialized()).toBe(true);
    expect(listRequests).toBe(2);
    expect(outcome.attestation).toMatchObject({
      schemaVersion: "ti-scale.mcp-capability-attestation.v1",
      connectionId: "recon-mcp",
      server: { name: "fake-recon", version: "1.2.3" },
      protocolVersion: LATEST_PROTOCOL_VERSION,
      capabilities: { toolsListChanged: true },
      attestedAt: "2026-07-18T12:00:00.000Z",
      expiresAt: "2026-07-18T12:01:00.000Z",
      executionAuthorization: "none",
    });
    expect(outcome.attestation.tools.map((tool) => tool.name))
      .toEqual(["inspect_target", "read_certificate"]);
    expect(outcome.attestation.tools[0]?.inputSchemaSha256).toBe(TARGET_SCHEMA_HASH);
    expect(outcome.attestation.tools[0]?.outputSchemaSha256).toBe(OUTPUT_SCHEMA_HASH);
    expect(outcome.attestation.tools[0]?.taskSupport).toBe("forbidden");
    expect(outcome.attestation.tools[1]?.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    });
    expect(outcome.attestation.manifestSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(outcome.attestation)).toBe(true);
    expect(Object.isFrozen(outcome.attestation.tools)).toBe(true);
    expect(Object.isFrozen(outcome.attestation.tools[0]?.inputSchema.properties)).toBe(true);
    expect(isMcpAttestationFresh(outcome.attestation, NOW)).toBe(true);
    expect(isMcpAttestationFresh(
      outcome.attestation,
      new Date("2026-07-18T12:00:59.999Z"),
    )).toBe(true);
    expect(isMcpAttestationFresh(
      outcome.attestation,
      new Date("2026-07-18T12:01:00.000Z"),
    )).toBe(false);
    expect(isMcpAttestationCurrentForConfig(outcome.attestation, connection(), NOW)).toBe(true);
    expect(isMcpAttestationCurrentForConfig(outcome.attestation, {
      ...connection(),
      endpoint: "https://changed.test.invalid/mcp",
    }, NOW)).toBe(false);
    expect(isMcpAttestationFresh({
      ...outcome.attestation,
      server: { ...outcome.attestation.server, version: "tampered" },
    }, NOW)).toBe(false);
  });

  test("hashes semantically identical schemas identically regardless of key order", () => {
    const reordered = {
      required: ["target"],
      additionalProperties: false,
      properties: {
        timeoutMs: { maximum: 30_000, minimum: 100, type: "integer" },
        target: { minLength: 1, type: "string" },
      },
      type: "object",
    };
    expect(digestCanonicalJson(reordered, { maxBytes: 64 * 1024, maxDepth: 32 }).sha256)
      .toBe(TARGET_SCHEMA_HASH);
  });

  test("rejects identity drift, missing capabilities, and missing required tools", async () => {
    const identity = await fakeServer({ name: "different-server" });
    const identityOutcome = await new McpCapabilityAttester(identity.factory, { now: () => NOW })
      .attest(connection());
    expect(identityOutcome).toMatchObject({
      status: "rejected",
      rejection: { code: "SERVER_IDENTITY_MISMATCH", retryable: false },
    });

    const noTools = await fakeServer({ declareToolsCapability: false });
    const noToolsOutcome = await new McpCapabilityAttester(noTools.factory, { now: () => NOW })
      .attest(connection());
    expect(noToolsOutcome).toMatchObject({
      status: "rejected",
      rejection: { code: "TOOLS_CAPABILITY_MISSING", retryable: false },
    });

    const missing = await fakeServer({
      listTools: () => ({
        tools: [{ name: "another_tool", inputSchema: { type: "object" } }],
      }),
    });
    const missingOutcome = await new McpCapabilityAttester(missing.factory, { now: () => NOW })
      .attest(connection());
    expect(missingOutcome).toMatchObject({
      status: "rejected",
      rejection: { code: "REQUIRED_TOOL_MISSING", retryable: false },
    });
  });

  test("rejects schema drift and unexpected tools under a closed inventory", async () => {
    const drift = await fakeServer({
      listTools: () => ({
        tools: [{
          name: "inspect_target",
          inputSchema: { type: "object", properties: { changed: { type: "boolean" } } },
          annotations: { readOnlyHint: true, destructiveHint: false },
        }],
      }),
    });
    const driftOutcome = await new McpCapabilityAttester(drift.factory, { now: () => NOW })
      .attest(connection());
    expect(driftOutcome).toMatchObject({
      status: "rejected",
      rejection: { code: "TOOL_SCHEMA_MISMATCH", retryable: false },
    });

    const extra = await fakeServer({
      listTools: () => ({
        tools: [
          {
            name: "inspect_target",
            inputSchema: TARGET_SCHEMA,
            annotations: { readOnlyHint: true, destructiveHint: false },
          },
          { name: "surprise", inputSchema: { type: "object" } },
        ],
      }),
    });
    const closedInventory = connection({
      toolInventory: {
        ...connection().toolInventory,
        allowAdditionalTools: false,
      },
    });
    const extraOutcome = await new McpCapabilityAttester(extra.factory, { now: () => NOW })
      .attest(closedInventory);
    expect(extraOutcome).toMatchObject({
      status: "rejected",
      rejection: { code: "UNEXPECTED_TOOL", retryable: false },
    });
  });

  test("pins output schema and task-support semantics when policy requires them", async () => {
    const outputDrift = await fakeServer();
    const outputOutcome = await new McpCapabilityAttester(outputDrift.factory, { now: () => NOW })
      .attest(connection({
        toolInventory: {
          ...connection().toolInventory,
          requiredTools: [{
            ...connection().toolInventory.requiredTools[0]!,
            outputSchemaSha256: "0".repeat(64),
          }],
        },
      }));
    expect(outputOutcome).toMatchObject({
      status: "rejected",
      rejection: { code: "TOOL_SCHEMA_MISMATCH", retryable: false },
    });

    const taskDrift = await fakeServer();
    const taskOutcome = await new McpCapabilityAttester(taskDrift.factory, { now: () => NOW })
      .attest(connection({
        toolInventory: {
          ...connection().toolInventory,
          requiredTools: [{
            ...connection().toolInventory.requiredTools[0]!,
            taskSupport: "required",
          }],
        },
      }));
    expect(taskOutcome).toMatchObject({
      status: "rejected",
      rejection: { code: "TOOL_ANNOTATION_MISMATCH", retryable: false },
    });
  });

  test("rejects repeated pagination cursors and duplicate tool names", async () => {
    const repeatedCursor = await fakeServer({
      listTools: (cursor) => ({
        tools: [{
          name: cursor === undefined ? "inspect_target" : "second_page",
          inputSchema: TARGET_SCHEMA,
        }],
        nextCursor: "same-cursor",
      }),
    });
    const cursorOutcome = await new McpCapabilityAttester(
      repeatedCursor.factory,
      { now: () => NOW },
    ).attest(connection());
    expect(cursorOutcome).toMatchObject({
      status: "rejected",
      rejection: { code: "TOOLS_PAGINATION_INVALID", retryable: false },
    });

    const duplicate = await fakeServer({
      listTools: () => ({
        tools: [
          { name: "inspect_target", inputSchema: TARGET_SCHEMA },
          { name: "inspect_target", inputSchema: TARGET_SCHEMA },
        ],
      }),
    });
    const duplicateOutcome = await new McpCapabilityAttester(
      duplicate.factory,
      { now: () => NOW },
    ).attest(connection());
    expect(duplicateOutcome).toMatchObject({
      status: "rejected",
      rejection: { code: "TOOL_INVENTORY_INVALID", retryable: false },
    });
  });

  test("does not treat an empty pagination cursor as end-of-list", async () => {
    const emptyCursor = await fakeServer({
      listTools: (cursor) => cursor === undefined
        ? {
            tools: [{
              name: "inspect_target",
              inputSchema: TARGET_SCHEMA,
              annotations: { readOnlyHint: true, destructiveHint: false },
            }],
            nextCursor: "",
          }
        : {
            tools: [{ name: "hidden_extra", inputSchema: { type: "object" } }],
          },
    });
    const outcome = await new McpCapabilityAttester(emptyCursor.factory, { now: () => NOW })
      .attest(connection({
        toolInventory: {
          ...connection().toolInventory,
          allowAdditionalTools: false,
        },
      }));
    expect(outcome).toMatchObject({
      status: "rejected",
      rejection: { code: "UNEXPECTED_TOOL", retryable: false },
    });
  });

  test("validates configuration before asking a transport provider to connect", async () => {
    let transportRequests = 0;
    const factory: McpAttestationTransportFactory = {
      async create(): Promise<Transport> {
        transportRequests += 1;
        throw new Error("must not be called");
      },
    };
    const unsafe = {
      ...connection(),
      endpoint: "http://mcp.example.test/mcp",
      allowInsecureLoopback: true,
    };
    const outcome = await new McpCapabilityAttester(factory, { now: () => NOW }).attest(unsafe);
    expect(outcome).toMatchObject({
      status: "rejected",
      rejection: { code: "CONFIG_INVALID", retryable: false },
    });
    expect(transportRequests).toBe(0);

    expect(() => parseMcpServerConnectionConfig({
      ...connection(),
      endpoint: "https://user:secret@mcp.example.test/mcp",
    })).toThrow();
    expect(() => parseMcpServerConnectionConfig({
      ...connection(),
      headerEnvironment: { Host: "TEST_MCP_HOST" },
    })).toThrow();
  });

  test("uses one absolute timeout across every tools/list page", async () => {
    let pages = 0;
    const slowPages = await fakeServer({
      async listTools() {
        pages += 1;
        await Bun.sleep(60);
        return {
          tools: [{ name: `page_${pages}`, inputSchema: { type: "object" } }],
          nextCursor: pages < 4 ? `cursor-${pages}` : undefined,
        };
      },
    });
    const outcome = await new McpCapabilityAttester(slowPages.factory, { now: () => NOW })
      .attest(connection({
        attestation: { ...connection().attestation, timeoutMs: 100 },
        toolInventory: {
          requiredTools: [],
          allowAdditionalTools: true,
          minimumToolCount: 0,
        },
      }));
    expect(outcome).toMatchObject({
      status: "rejected",
      rejection: { code: "ATTESTATION_TIMEOUT", retryable: true },
    });
    expect(pages).toBeLessThan(4);
  });

  test("times out a transport that never initializes and remains fail closed", async () => {
    let closed = false;
    const hangingTransport: Transport = {
      async start(): Promise<void> {
        await new Promise<void>(() => undefined);
      },
      async send(): Promise<void> {},
      async close(): Promise<void> {
        closed = true;
      },
    };
    const outcome = await new McpCapabilityAttester({
      async create(_config, context): Promise<Transport> {
        expect(context.signal.aborted).toBe(false);
        return hangingTransport;
      },
    }, { now: () => NOW }).attest(connection({
      attestation: { ...connection().attestation, timeoutMs: 100 },
    }));

    expect(outcome).toMatchObject({
      status: "rejected",
      rejection: { code: "ATTESTATION_TIMEOUT", retryable: true },
    });
    expect(closed).toBe(true);
  });
});

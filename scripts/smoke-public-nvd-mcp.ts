import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import {
  PUBLIC_NVD_MCP_BIND,
  PUBLIC_NVD_MCP_DEFAULT_PORT,
  PUBLIC_NVD_MCP_PATH,
  loadPublicNvdBearerToken,
} from "../server/mcp-public-nvd/PublicNvdHttpSidecar";
import {
  CveIdSchema,
  PUBLIC_NVD_SERVER_NAME,
  PUBLIC_NVD_SERVER_VERSION,
  PUBLIC_NVD_TOOL_NAME,
  PublicNvdCveDetailSchema,
} from "../server/mcp-public-nvd/types";
import {
  PUBLIC_NVD_INPUT_SCHEMA_SHA256,
  PUBLIC_NVD_OUTPUT_SCHEMA_SHA256,
} from "../server/mcp/PublicNvdMcpConfiguration";
import { digestCanonicalJson } from "../server/mcp/canonicalJson";

const DEFAULT_SOURCE_CREDENTIAL = "/etc/ti-scale-mcp-nvd/mcp-token";

interface SmokeOptions {
  readonly tokenFile: string;
  readonly cveId?: string;
}

function usage(): string {
  return [
    "Usage: bun run scripts/smoke-public-nvd-mcp.ts [options]",
    "",
    "Authenticate to the fixed loopback MCP endpoint and verify its reviewed tool contract.",
    "The bearer credential is read into memory and is never displayed.",
    "",
    `  --token-file PATH  Credential source (default: ${DEFAULT_SOURCE_CREDENTIAL})`,
    "  --cve CVE-ID      Also perform one live public NVD lookup",
    "  --help            Show this help",
  ].join("\n");
}

function parseArguments(argv: readonly string[]): SmokeOptions {
  let tokenFile = DEFAULT_SOURCE_CREDENTIAL;
  let cveId: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    }
    if (argument === "--token-file") {
      const value = argv[index + 1];
      if (!value) throw new Error("--token-file requires a value");
      tokenFile = value;
      index += 1;
      continue;
    }
    if (argument === "--cve") {
      const value = argv[index + 1];
      if (!value) throw new Error("--cve requires a value");
      cveId = CveIdSchema.parse(value);
      index += 1;
      continue;
    }
    throw new Error(`Unknown option: ${argument}`);
  }
  return { tokenFile, ...(cveId ? { cveId } : {}) };
}

async function smoke(options: SmokeOptions): Promise<void> {
  const credential = loadPublicNvdBearerToken(options.tokenFile);
  const endpoint = new URL(
    `http://${PUBLIC_NVD_MCP_BIND}:${PUBLIC_NVD_MCP_DEFAULT_PORT}${PUBLIC_NVD_MCP_PATH}`,
  );
  const transport = new StreamableHTTPClientTransport(endpoint, {
    requestInit: {
      headers: { Authorization: `Bearer ${Buffer.from(credential).toString("utf8")}` },
      redirect: "error",
    },
    reconnectionOptions: {
      initialReconnectionDelay: 250,
      maxReconnectionDelay: 250,
      reconnectionDelayGrowFactor: 1,
      maxRetries: 0,
    },
  });
  const client = new Client(
    { name: "ti-scale-public-nvd-smoke", version: "0.1.0" },
    { capabilities: {} },
  );

  try {
    await client.connect(transport);
    const listed = await client.listTools();
    const server = client.getServerVersion();
    if (server?.name !== PUBLIC_NVD_SERVER_NAME || server.version !== PUBLIC_NVD_SERVER_VERSION) {
      throw new Error("The sidecar identity does not match the reviewed server release");
    }
    if (
      listed.tools.length !== 1
      || listed.nextCursor !== undefined
      || listed.tools[0]?.name !== PUBLIC_NVD_TOOL_NAME
    ) {
      throw new Error("The sidecar did not advertise the reviewed one-tool contract");
    }
    const tool = listed.tools[0];
    const inputSchemaSha256 = digestCanonicalJson(tool.inputSchema, {
      maxBytes: 64 * 1024,
      maxDepth: 32,
    }).sha256;
    const outputSchemaSha256 = tool.outputSchema
      ? digestCanonicalJson(tool.outputSchema, { maxBytes: 64 * 1024, maxDepth: 32 }).sha256
      : undefined;
    const annotations = tool.annotations;
    if (
      inputSchemaSha256 !== PUBLIC_NVD_INPUT_SCHEMA_SHA256
      || outputSchemaSha256 !== PUBLIC_NVD_OUTPUT_SCHEMA_SHA256
      || annotations?.readOnlyHint !== true
      || annotations.destructiveHint !== false
      || annotations.idempotentHint !== true
      || annotations.openWorldHint !== true
    ) {
      throw new Error("The sidecar did not advertise the reviewed read-only policy");
    }
    process.stdout.write(`MCP transport ready on ${endpoint.href}\n`);
    process.stdout.write(`Reviewed tool available: ${PUBLIC_NVD_TOOL_NAME} (read-only, no target interaction)\n`);

    if (options.cveId) {
      const called = CallToolResultSchema.parse(await client.callTool({
        name: PUBLIC_NVD_TOOL_NAME,
        arguments: { cveId: options.cveId },
      }));
      if (called.isError) throw new Error("The live public NVD lookup returned a bounded error");
      const detail = PublicNvdCveDetailSchema.parse(called.structuredContent);
      process.stdout.write(
        `${detail.cveId} retrieved from NVD; external text is ${detail.description.lifecycle}; target interaction is disabled.\n`,
      );
    }
  } finally {
    credential.fill(0);
    await client.close().catch(() => undefined);
  }
}

try {
  await smoke(parseArguments(process.argv.slice(2)));
} catch {
  process.stderr.write("Public NVD MCP smoke check failed safely. No credential value was displayed.\n");
  process.exitCode = 1;
}

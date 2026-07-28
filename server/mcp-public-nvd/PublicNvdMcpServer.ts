import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  PUBLIC_NVD_SERVER_NAME,
  PUBLIC_NVD_SERVER_VERSION,
  PUBLIC_NVD_TOOL_NAME,
  PublicNvdCveDetailSchema,
  PublicNvdError,
  PublicNvdToolInputSchema,
  type PublicNvdLookupPort,
} from "./types";
import { PublicNvdClient } from "./PublicNvdClient";

export interface PublicNvdMcpServerOptions {
  readonly client?: PublicNvdLookupPort;
}

function operatorSummary(detail: Awaited<ReturnType<PublicNvdLookupPort["getCveDetails"]>>): string {
  const strongest = [...detail.cvss].sort((left, right) => right.baseScore - left.baseScore)[0];
  const score = strongest
    ? ` NVD reports a ${strongest.baseSeverity.toLowerCase()} CVSS score of ${strongest.baseScore}.`
    : " NVD did not provide a usable CVSS score in this record.";
  return `Retrieved the official public NVD record for ${detail.cveId}.${score} `
    + "The external description remains quarantined until locally reviewed. No assessed target was contacted.";
}

function errorResult(error: unknown) {
  const failure = error instanceof PublicNvdError
    ? error
    : new PublicNvdError(
        "invalid_response",
        "The public NVD result could not be processed safely. No target was contacted.",
        false,
      );
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: failure.humanMessage }],
    _meta: {
      "ti-scale/errorCode": failure.code,
      "ti-scale/retryable": failure.retryable,
      "ti-scale/targetInteraction": false,
      ...(failure.retryAfterMs !== undefined
        ? { "ti-scale/retryAfterMs": failure.retryAfterMs }
        : {}),
    },
  };
}

export function createPublicNvdMcpServer(
  options: PublicNvdMcpServerOptions = {},
): McpServer {
  const client = options.client ?? new PublicNvdClient();
  const server = new McpServer(
    { name: PUBLIC_NVD_SERVER_NAME, version: PUBLIC_NVD_SERVER_VERSION },
    { capabilities: { tools: { listChanged: false } } },
  );

  server.registerTool(
    PUBLIC_NVD_TOOL_NAME,
    {
      title: "Look up an official CVE record",
      description:
        "Look up one CVE in the official public NVD service so Ti-Scale can confirm its description, severity, and sources. This read-only step never contacts the assessed target.",
      inputSchema: PublicNvdToolInputSchema,
      outputSchema: PublicNvdCveDetailSchema,
      annotations: {
        title: "Look up an official CVE record",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      _meta: {
        "ti-scale/actionClass": "cve_intelligence_applicability_validation",
        "ti-scale/targetInteraction": false,
        "ti-scale/trustBoundary": "external_untrusted",
      },
    },
    async ({ cveId }) => {
      try {
        const detail = await client.getCveDetails(cveId);
        return {
          content: [{ type: "text", text: operatorSummary(detail) }],
          structuredContent: detail,
          _meta: {
            "ti-scale/targetInteraction": false,
            "ti-scale/externalTextState": "quarantined",
          },
        };
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  return server;
}

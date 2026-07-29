import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from "node:crypto";
import {
  PUBLIC_NVD_SERVER_NAME,
  PUBLIC_NVD_SERVER_VERSION,
  PUBLIC_NVD_TOOL_NAME,
  PublicNvdCveDetailSchema,
  PublicNvdToolInputSchema,
  type PublicNvdCveDetail,
} from "../mcp-public-nvd";
import { digestCanonicalJson } from "./canonicalJson";
import { hashMcpServerConnectionConfig, McpCapabilityAttester } from "./McpCapabilityAttester";
import type {
  McpAttestationTransportFactory,
  McpCapabilityAttestation,
  McpStreamableHttpConnectionConfig,
} from "./types";

const CLIENT_INFO = Object.freeze({ name: "ti-scale-public-nvd-broker", version: "0.1.0" });
const MAXIMUM_CLEANUP_WAIT_MS = 1_000;

export type PublicNvdToolBoundaryErrorCode =
  | "ABORTED"
  | "ATTESTATION_EXPIRED"
  | "ATTESTATION_REJECTED"
  | "INVENTORY_DRIFT"
  | "INVOCATION_FAILED"
  | "NOT_ATTESTED"
  | "RESULT_INVALID"
  | "SERVER_ERROR";

export class PublicNvdToolBoundaryError extends Error {
  constructor(
    readonly code: PublicNvdToolBoundaryErrorCode,
    message: string,
    readonly retryable: boolean,
    readonly retryAfterMs?: number,
  ) {
    super(message);
    this.name = "PublicNvdToolBoundaryError";
  }
}

export interface PublicNvdToolInvocationReceipt {
  readonly schemaVersion: "ti-scale.mcp-tool-invocation-receipt.v1";
  readonly invocationId: string;
  readonly connectionId: string;
  readonly toolName: typeof PUBLIC_NVD_TOOL_NAME;
  readonly configurationSha256: string;
  readonly capabilityManifestSha256: string;
  readonly inputSha256: string;
  readonly resultSha256: string;
  readonly authorizationPolicy: "ti-scale.public-nvd-exact-tool.v1";
  readonly targetInteraction: false;
  readonly startedAt: string;
  readonly completedAt: string;
}

export interface PublicNvdToolInvocation {
  readonly detail: PublicNvdCveDetail;
  readonly summary: string;
  readonly receipt: PublicNvdToolInvocationReceipt;
}

export interface PublicNvdMcpToolClientOptions {
  readonly config: McpStreamableHttpConnectionConfig;
  readonly transportFactory: McpAttestationTransportFactory;
  readonly invocationTimeoutMs?: number;
  readonly now?: () => Date;
}

function textSummary(content: ReturnType<typeof CallToolResultSchema.parse>["content"]): string {
  const summary = content
    .filter((item): item is Extract<(typeof content)[number], { type: "text" }> => item.type === "text")
    .map((item) => item.text.trim())
    .filter(Boolean)
    .join("\n");
  if (!summary || Buffer.byteLength(summary, "utf8") > 16 * 1024) {
    throw new PublicNvdToolBoundaryError(
      "RESULT_INVALID",
      "The public NVD sidecar returned an invalid operator summary",
      false,
    );
  }
  return summary;
}

function serverFailure(result: ReturnType<typeof CallToolResultSchema.parse>): PublicNvdToolBoundaryError {
  const metadata = result._meta && typeof result._meta === "object"
    ? result._meta as Record<string, unknown>
    : {};
  const retryable = metadata["ti-scale/retryable"] === true;
  const retryAfter = metadata["ti-scale/retryAfterMs"];
  return new PublicNvdToolBoundaryError(
    "SERVER_ERROR",
    textSummary(result.content),
    retryable,
    typeof retryAfter === "number" && Number.isSafeInteger(retryAfter) && retryAfter >= 0
      ? retryAfter
      : undefined,
  );
}

async function closeClientWithin(client: Client, timeoutMs: number): Promise<void> {
  const cleanupMs = Math.min(timeoutMs, MAXIMUM_CLEANUP_WAIT_MS);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const close = client.close().catch(() => undefined);
  try {
    await Promise.race([
      close,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, cleanupMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export class PublicNvdMcpToolClient {
  private readonly config: McpStreamableHttpConnectionConfig;
  private readonly attester: McpCapabilityAttester;
  private readonly transportFactory: McpAttestationTransportFactory;
  private readonly invocationTimeoutMs: number;
  private readonly now: () => Date;
  private attestation?: McpCapabilityAttestation;

  constructor(options: PublicNvdMcpToolClientOptions) {
    this.config = options.config;
    this.transportFactory = options.transportFactory;
    this.attester = new McpCapabilityAttester(options.transportFactory, { now: options.now });
    this.invocationTimeoutMs = options.invocationTimeoutMs ?? 15_000;
    this.now = options.now ?? (() => new Date());
    if (!Number.isSafeInteger(this.invocationTimeoutMs) || this.invocationTimeoutMs < 100 || this.invocationTimeoutMs > 120_000) {
      throw new RangeError("Public NVD invocation timeout must be 100 ms through 120 seconds");
    }
  }

  get currentAttestation(): McpCapabilityAttestation | undefined {
    return this.attestation;
  }

  async refreshAttestation(): Promise<McpCapabilityAttestation> {
    const outcome = await this.attester.attest(this.config);
    if (outcome.status !== "attested") {
      this.attestation = undefined;
      throw new PublicNvdToolBoundaryError(
        "ATTESTATION_REJECTED",
        outcome.rejection.humanMessage,
        outcome.rejection.retryable,
      );
    }
    this.attestation = outcome.attestation;
    return outcome.attestation;
  }

  private liveAttestation(): McpCapabilityAttestation {
    const attestation = this.attestation;
    if (!attestation) {
      throw new PublicNvdToolBoundaryError(
        "NOT_ATTESTED",
        "The public NVD MCP route has not completed capability attestation",
        true,
      );
    }
    if (Date.parse(attestation.expiresAt) <= this.now().getTime()) {
      throw new PublicNvdToolBoundaryError(
        "ATTESTATION_EXPIRED",
        "The public NVD MCP capability attestation has expired",
        true,
      );
    }
    if (attestation.configurationSha256 !== hashMcpServerConnectionConfig(this.config)) {
      throw new PublicNvdToolBoundaryError(
        "INVENTORY_DRIFT",
        "The public NVD MCP connection changed after attestation",
        false,
      );
    }
    return attestation;
  }

  async getCveDetails(cveId: string, signal: AbortSignal): Promise<PublicNvdToolInvocation> {
    const input = PublicNvdToolInputSchema.parse({ cveId });
    const attestation = this.liveAttestation();
    const expectedTool = attestation.tools.find((tool) => tool.name === PUBLIC_NVD_TOOL_NAME);
    if (!expectedTool || attestation.tools.length !== 1) {
      throw new PublicNvdToolBoundaryError(
        "INVENTORY_DRIFT",
        "The public NVD MCP attestation does not contain the exact reviewed tool inventory",
        false,
      );
    }

    const controller = new AbortController();
    const propagateAbort = (): void => controller.abort(signal.reason);
    if (signal.aborted) propagateAbort();
    else signal.addEventListener("abort", propagateAbort, { once: true });
    const timeout = setTimeout(() => controller.abort("Public NVD MCP invocation timed out"), this.invocationTimeoutMs);
    const startedAt = this.now().toISOString();
    let client: Client | undefined;
    try {
      const transport = await this.transportFactory.create(this.config, {
        signal: controller.signal,
        maxInboundMessageBytes: this.config.attestation.maxInboundMessageBytes,
      });
      client = new Client(CLIENT_INFO, { capabilities: {} });
      await client.connect(transport, {
        signal: controller.signal,
        timeout: this.invocationTimeoutMs,
        maxTotalTimeout: this.invocationTimeoutMs,
      });
      if (
        client.getServerVersion()?.name !== PUBLIC_NVD_SERVER_NAME ||
        client.getServerVersion()?.version !== PUBLIC_NVD_SERVER_VERSION
      ) {
        throw new PublicNvdToolBoundaryError(
          "INVENTORY_DRIFT",
          "The public NVD MCP server identity changed after attestation",
          false,
        );
      }
      const listed = await client.listTools(undefined, {
        signal: controller.signal,
        timeout: this.invocationTimeoutMs,
        maxTotalTimeout: this.invocationTimeoutMs,
      });
      const listedTool = listed.tools[0];
      const inputDigest = listedTool
        ? digestCanonicalJson(listedTool.inputSchema, {
            maxBytes: this.config.attestation.maxSchemaBytes,
            maxDepth: this.config.attestation.maxSchemaDepth,
          })
        : undefined;
      const outputDigest = listedTool?.outputSchema
        ? digestCanonicalJson(listedTool.outputSchema, {
            maxBytes: this.config.attestation.maxSchemaBytes,
            maxDepth: this.config.attestation.maxSchemaDepth,
          })
        : undefined;
      if (
        listed.tools.length !== 1 || listed.nextCursor !== undefined ||
        listedTool?.name !== PUBLIC_NVD_TOOL_NAME ||
        inputDigest?.sha256 !== expectedTool.inputSchemaSha256 ||
        outputDigest?.sha256 !== expectedTool.outputSchemaSha256 ||
        listedTool.annotations?.readOnlyHint !== true ||
        listedTool.annotations?.destructiveHint !== false ||
        listedTool.annotations?.idempotentHint !== true ||
        listedTool.annotations?.openWorldHint !== true
      ) {
        throw new PublicNvdToolBoundaryError(
          "INVENTORY_DRIFT",
          "The public NVD MCP tool contract changed after attestation",
          false,
        );
      }

      const result = CallToolResultSchema.parse(await client.callTool({
        name: PUBLIC_NVD_TOOL_NAME,
        arguments: input,
      }, CallToolResultSchema, {
        signal: controller.signal,
        timeout: this.invocationTimeoutMs,
        maxTotalTimeout: this.invocationTimeoutMs,
      }));
      if (result.isError === true) throw serverFailure(result);
      const detail = PublicNvdCveDetailSchema.parse(result.structuredContent);
      if (detail.cveId !== input.cveId || detail.targetInteraction !== false) {
        throw new PublicNvdToolBoundaryError(
          "RESULT_INVALID",
          "The public NVD MCP result did not match the exact requested CVE boundary",
          false,
        );
      }
      const summary = textSummary(result.content);
      const completedAt = this.now().toISOString();
      const inputSha256 = digestCanonicalJson(input, { maxBytes: 4_096, maxDepth: 8 }).sha256;
      const resultSha256 = digestCanonicalJson(detail, {
        maxBytes: this.config.attestation.maxInboundMessageBytes,
        maxDepth: 32,
      }).sha256;
      return {
        detail,
        summary,
        receipt: {
          schemaVersion: "ti-scale.mcp-tool-invocation-receipt.v1",
          invocationId: `mcp_call_${randomUUID()}`,
          connectionId: this.config.id,
          toolName: PUBLIC_NVD_TOOL_NAME,
          configurationSha256: attestation.configurationSha256,
          capabilityManifestSha256: attestation.manifestSha256,
          inputSha256,
          resultSha256,
          authorizationPolicy: "ti-scale.public-nvd-exact-tool.v1",
          targetInteraction: false,
          startedAt,
          completedAt,
        },
      };
    } catch (error) {
      if (error instanceof PublicNvdToolBoundaryError) throw error;
      if (controller.signal.aborted || signal.aborted || (error instanceof Error && error.name === "AbortError")) {
        throw new PublicNvdToolBoundaryError("ABORTED", "The public NVD MCP call was cancelled", true);
      }
      throw new PublicNvdToolBoundaryError(
        "INVOCATION_FAILED",
        "The public NVD MCP call could not be completed safely",
        true,
      );
    } finally {
      clearTimeout(timeout);
      signal.removeEventListener("abort", propagateAbort);
      // Abort the transport before cleanup and bound cleanup itself. A stuck
      // close must not hold an operator cancellation or completed lookup past
      // the invocation deadline.
      if (!controller.signal.aborted) controller.abort("Public NVD MCP invocation finished");
      if (client) await closeClientWithin(client, this.invocationTimeoutMs);
    }
  }
}

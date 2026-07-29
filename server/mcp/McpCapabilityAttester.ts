import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Transport, TransportSendOptions } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  ErrorCode,
  McpError,
  type JSONRPCMessage,
  type MessageExtraInfo,
} from "@modelcontextprotocol/sdk/types.js";
import { performance } from "node:perf_hooks";
import { ZodError } from "zod";
import { CanonicalJsonError, digestCanonicalJson } from "./canonicalJson";
import { parseMcpServerConnectionConfig } from "./config";
import type {
  McpAttestationOutcome,
  McpAttestationRejectionCode,
  McpAttestationTransportFactory,
  McpCapabilityAttestation,
  McpServerConnectionConfig,
  McpToolCapabilityAttestation,
} from "./types";

const CLIENT_INFO = Object.freeze({ name: "ti-scale-mcp-attester", version: "0.1.0" });

type Phase = "configuration" | "transport" | "initialize" | "tools-list" | "validation";

class AttestationFailure extends Error {
  constructor(
    readonly code: McpAttestationRejectionCode,
    message: string,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = "AttestationFailure";
  }
}

class AttestationTimeout extends Error {
  constructor() {
    super("MCP capability attestation exceeded its bounded timeout");
    this.name = "AttestationTimeout";
  }
}

class AttestationDeadline {
  private readonly expiresAt: number;

  constructor(timeoutMs: number) {
    this.expiresAt = performance.now() + timeoutMs;
  }

  remainingMs(): number {
    const remaining = Math.ceil(this.expiresAt - performance.now());
    if (remaining <= 0) throw new AttestationTimeout();
    return remaining;
  }
}

/** Captures the negotiated version without reaching into SDK internals. */
class ProtocolTrackingTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void;
  negotiatedProtocolVersion?: string;

  constructor(private readonly transport: Transport) {}

  get sessionId(): string | undefined {
    return this.transport.sessionId;
  }

  async start(): Promise<void> {
    this.transport.onclose = () => this.onclose?.();
    this.transport.onerror = (error) => this.onerror?.(error);
    this.transport.onmessage = (message, extra) => this.onmessage?.(message, extra);
    await this.transport.start();
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    await this.transport.send(message, options);
  }

  async close(): Promise<void> {
    await this.transport.close();
  }

  setProtocolVersion(version: string): void {
    this.negotiatedProtocolVersion = version;
    this.transport.setProtocolVersion?.(version);
  }
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, abort: AbortController): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      abort.abort();
      reject(new AttestationTimeout());
    }, timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function normalizedAnnotations(tool: {
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
}): McpToolCapabilityAttestation["annotations"] {
  const annotations = tool.annotations;
  return Object.freeze({
    ...(annotations?.title !== undefined ? { title: annotations.title } : {}),
    readOnlyHint: annotations?.readOnlyHint ?? false,
    destructiveHint: annotations?.destructiveHint ?? true,
    idempotentHint: annotations?.idempotentHint ?? false,
    openWorldHint: annotations?.openWorldHint ?? true,
  });
}

function deepFreezeJson<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value as Record<string, unknown>)) {
      deepFreezeJson(nested);
    }
    Object.freeze(value);
  }
  return value;
}

function cloneSchema(schema: Record<string, unknown>): Readonly<Record<string, unknown>> {
  return deepFreezeJson(JSON.parse(JSON.stringify(schema)) as Record<string, unknown>);
}

function toolAttestation(
  tool: {
    name: string;
    title?: string;
    description?: string;
    inputSchema: Record<string, unknown> & { type: "object" };
    outputSchema?: Record<string, unknown> & { type: "object" };
    execution?: { taskSupport?: "optional" | "required" | "forbidden" };
    annotations?: {
      title?: string;
      readOnlyHint?: boolean;
      destructiveHint?: boolean;
      idempotentHint?: boolean;
      openWorldHint?: boolean;
    };
  },
  config: McpServerConnectionConfig,
): McpToolCapabilityAttestation {
  const limits = {
    maxBytes: config.attestation.maxSchemaBytes,
    maxDepth: config.attestation.maxSchemaDepth,
  };
  let input;
  let output;
  try {
    input = digestCanonicalJson(tool.inputSchema, limits);
    output = tool.outputSchema ? digestCanonicalJson(tool.outputSchema, limits) : undefined;
  } catch (error) {
    if (error instanceof CanonicalJsonError) {
      throw new AttestationFailure(
        "TOOL_SCHEMA_INVALID",
        `Tool ${tool.name} has an input or output schema that cannot be safely attested`,
        false,
      );
    }
    throw error;
  }
  return Object.freeze({
    name: tool.name,
    ...(tool.title !== undefined ? { title: tool.title } : {}),
    ...(tool.description !== undefined ? { description: tool.description } : {}),
    inputSchema: cloneSchema(tool.inputSchema),
    inputSchemaSha256: input.sha256,
    inputSchemaBytes: input.bytes,
    ...(output ? {
      outputSchemaSha256: output.sha256,
      outputSchemaBytes: output.bytes,
    } : {}),
    ...(tool.execution?.taskSupport
      ? { taskSupport: tool.execution.taskSupport }
      : {}),
    annotations: normalizedAnnotations(tool),
  });
}

function validateToolInventory(
  tools: readonly McpToolCapabilityAttestation[],
  config: McpServerConnectionConfig,
): void {
  if (tools.length < config.toolInventory.minimumToolCount) {
    throw new AttestationFailure(
      "TOOL_INVENTORY_INVALID",
      `Server returned ${tools.length} tools; policy requires at least ${config.toolInventory.minimumToolCount}`,
      false,
    );
  }

  const toolsByName = new Map(tools.map((tool) => [tool.name, tool]));
  const expectedNames = new Set(config.toolInventory.requiredTools.map((tool) => tool.name));
  for (const expected of config.toolInventory.requiredTools) {
    const actual = toolsByName.get(expected.name);
    if (!actual) {
      throw new AttestationFailure(
        "REQUIRED_TOOL_MISSING",
        `Required tool ${expected.name} was not advertised by the initialized MCP server`,
        false,
      );
    }
    if (expected.inputSchemaSha256 && actual.inputSchemaSha256 !== expected.inputSchemaSha256) {
      throw new AttestationFailure(
        "TOOL_SCHEMA_MISMATCH",
        `Required tool ${expected.name} advertised an unapproved input schema`,
        false,
      );
    }
    if (expected.outputSchemaSha256 && actual.outputSchemaSha256 !== expected.outputSchemaSha256) {
      throw new AttestationFailure(
        "TOOL_SCHEMA_MISMATCH",
        `Required tool ${expected.name} advertised an unapproved output schema`,
        false,
      );
    }
    if (expected.taskSupport !== undefined && actual.taskSupport !== expected.taskSupport) {
      throw new AttestationFailure(
        "TOOL_ANNOTATION_MISMATCH",
        `Required tool ${expected.name} did not match the expected task-support contract`,
        false,
      );
    }
    for (const [key, expectedValue] of Object.entries(expected.annotations ?? {})) {
      const actualValue = actual.annotations[key as keyof typeof actual.annotations];
      if (actualValue !== expectedValue) {
        throw new AttestationFailure(
          "TOOL_ANNOTATION_MISMATCH",
          `Required tool ${expected.name} did not match the expected ${key} annotation`,
          false,
        );
      }
    }
  }

  if (!config.toolInventory.allowAdditionalTools) {
    const unexpected = tools.find((tool) => !expectedNames.has(tool.name));
    if (unexpected) {
      throw new AttestationFailure(
        "UNEXPECTED_TOOL",
        `Server advertised tool ${unexpected.name}, which is outside the configured inventory`,
        false,
      );
    }
  }
}

function classifyUnexpected(phase: Phase, error: unknown): AttestationFailure {
  if (error instanceof AttestationFailure) return error;
  if (error instanceof AttestationTimeout
    || (error instanceof Error && error.name === "AbortError")
    || (error instanceof McpError && error.code === ErrorCode.RequestTimeout)) {
    return new AttestationFailure("ATTESTATION_TIMEOUT", "MCP capability attestation timed out", true);
  }
  if (phase === "configuration") {
    return new AttestationFailure(
      "CONFIG_INVALID",
      "MCP connection configuration did not pass fail-closed validation",
      false,
    );
  }
  if (phase === "transport") {
    return new AttestationFailure("TRANSPORT_UNAVAILABLE", "MCP transport could not be created", true);
  }
  if (phase === "initialize") {
    return new AttestationFailure("INITIALIZATION_FAILED", "MCP initialization did not complete successfully", true);
  }
  if (phase === "tools-list") {
    return new AttestationFailure("TOOLS_LIST_FAILED", "MCP tools/list did not complete successfully", true);
  }
  if (error instanceof ZodError) {
    return new AttestationFailure(
      "TOOL_INVENTORY_INVALID",
      "MCP server returned capability data that failed protocol validation",
      false,
    );
  }
  return new AttestationFailure("TOOL_INVENTORY_INVALID", "MCP capability inventory was rejected", false);
}

export function hashMcpServerConnectionConfig(input: unknown): string {
  const config = parseMcpServerConnectionConfig(input);
  return digestCanonicalJson(config, {
    maxBytes: 16 * 1024 * 1024,
    maxDepth: 64,
  }).sha256;
}

export interface McpCapabilityAttesterOptions {
  readonly now?: () => Date;
}

export class McpCapabilityAttester {
  private readonly now: () => Date;

  constructor(
    private readonly transportFactory: McpAttestationTransportFactory,
    options: McpCapabilityAttesterOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
  }

  async attest(input: unknown): Promise<McpAttestationOutcome> {
    let phase: Phase = "configuration";
    let config: McpServerConnectionConfig | undefined;
    let client: Client | undefined;
    let transport: ProtocolTrackingTransport | undefined;
    let outcome: McpAttestationOutcome;
    const abort = new AbortController();
    let deadline: AttestationDeadline | undefined;

    try {
      config = parseMcpServerConnectionConfig(input);
      if (!config.enabled) {
        throw new AttestationFailure(
          "CONFIG_DISABLED",
          `MCP connection ${config.id} is disabled and cannot be attested`,
          false,
        );
      }
      deadline = new AttestationDeadline(config.attestation.timeoutMs);

      phase = "transport";
      const createPromise = this.transportFactory.create(config, {
        signal: abort.signal,
        maxInboundMessageBytes: config.attestation.maxInboundMessageBytes,
      });
      void createPromise.then((createdTransport) => {
        if (abort.signal.aborted) void createdTransport.close().catch(() => undefined);
      }, () => undefined);
      const underlying = await withTimeout(
        createPromise,
        deadline.remainingMs(),
        abort,
      );
      transport = new ProtocolTrackingTransport(underlying);
      client = new Client(CLIENT_INFO, { capabilities: {} });

      phase = "initialize";
      const initializeTimeout = deadline.remainingMs();
      await withTimeout(
        client.connect(transport, {
          signal: abort.signal,
          timeout: initializeTimeout,
          maxTotalTimeout: initializeTimeout,
        }),
        initializeTimeout,
        abort,
      );

      const server = client.getServerVersion();
      const capabilities = client.getServerCapabilities();
      const protocolVersion = transport.negotiatedProtocolVersion;
      if (!server || server.name !== config.expectedServer.name
        || (config.expectedServer.version !== undefined
          && server.version !== config.expectedServer.version)) {
        throw new AttestationFailure(
          "SERVER_IDENTITY_MISMATCH",
          "Initialized MCP server identity did not match the configured identity",
          false,
        );
      }
      if (!protocolVersion || !config.attestation.acceptedProtocolVersions.includes(protocolVersion)) {
        throw new AttestationFailure(
          "PROTOCOL_NOT_ALLOWED",
          "Initialized MCP protocol version is outside the configured allowlist",
          false,
        );
      }
      if (!capabilities?.tools) {
        throw new AttestationFailure(
          "TOOLS_CAPABILITY_MISSING",
          "Initialized MCP server did not declare the tools capability",
          false,
        );
      }

      phase = "tools-list";
      const tools: McpToolCapabilityAttestation[] = [];
      const seenToolNames = new Set<string>();
      let cumulativeSchemaBytes = 0;
      const seenCursors = new Set<string>();
      let cursor: string | undefined;
      for (let page = 0; ; page += 1) {
        if (page >= config.attestation.maxPages) {
          throw new AttestationFailure(
            "TOOLS_PAGINATION_INVALID",
            "MCP tools/list exceeded the configured page limit",
            false,
          );
        }
        const listTimeout = deadline.remainingMs();
        const response = await withTimeout(
          client.listTools(cursor !== undefined ? { cursor } : undefined, {
            signal: abort.signal,
            timeout: listTimeout,
            maxTotalTimeout: listTimeout,
          }),
          listTimeout,
          abort,
        );
        if (tools.length + response.tools.length > config.attestation.maxTools) {
          throw new AttestationFailure(
            "TOOL_INVENTORY_INVALID",
            "MCP server advertised more tools than the configured attestation limit",
            false,
          );
        }
        for (const advertised of response.tools) {
          if (seenToolNames.has(advertised.name)) {
            throw new AttestationFailure(
              "TOOL_INVENTORY_INVALID",
              `MCP server advertised duplicate tool name ${advertised.name}`,
              false,
            );
          }
          seenToolNames.add(advertised.name);
          const attestedTool = toolAttestation(advertised, config);
          cumulativeSchemaBytes += attestedTool.inputSchemaBytes
            + (attestedTool.outputSchemaBytes ?? 0);
          if (cumulativeSchemaBytes > config.attestation.maxManifestBytes) {
            throw new AttestationFailure(
              "TOOL_INVENTORY_INVALID",
              "MCP tool schemas exceed the configured cumulative manifest limit",
              false,
            );
          }
          tools.push(attestedTool);
        }
        if (response.nextCursor === undefined) break;
        if (seenCursors.has(response.nextCursor)) {
          throw new AttestationFailure(
            "TOOLS_PAGINATION_INVALID",
            "MCP tools/list returned a repeated cursor",
            false,
          );
        }
        seenCursors.add(response.nextCursor);
        cursor = response.nextCursor;
      }

      phase = "validation";
      tools.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
      validateToolInventory(tools, config);

      const attestedAt = this.now();
      const expiresAt = new Date(attestedAt.getTime() + config.attestation.ttlMs);
      const configurationSha256 = hashMcpServerConnectionConfig(config);
      const manifest = {
        schemaVersion: "ti-scale.mcp-capability-attestation.v1" as const,
        connectionId: config.id,
        transport: config.transport,
        server: { name: server.name, version: server.version },
        protocolVersion,
        capabilities: { toolsListChanged: capabilities.tools.listChanged === true },
        configurationSha256,
        tools,
        attestedAt: attestedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        executionAuthorization: "none" as const,
      };
      const manifestSha256 = digestCanonicalJson(manifest, {
        maxBytes: config.attestation.maxManifestBytes,
        maxDepth: config.attestation.maxSchemaDepth + 4,
      }).sha256;
      const attestation: McpCapabilityAttestation = Object.freeze({
        ...manifest,
        tools: Object.freeze(tools),
        server: Object.freeze(manifest.server),
        capabilities: Object.freeze(manifest.capabilities),
        manifestSha256,
      });
      outcome = Object.freeze({ status: "attested", attestation });
    } catch (error) {
      const failure = classifyUnexpected(phase, error);
      outcome = Object.freeze({
        status: "rejected",
        rejection: Object.freeze({
          code: failure.code,
          humanMessage: failure.message,
          retryable: failure.retryable,
          rejectedAt: this.now().toISOString(),
        }),
      });
    }

    if (client) {
      try {
        await withTimeout(
          client.close(),
          Math.min(config?.attestation.timeoutMs ?? 1_000, 5_000),
          new AbortController(),
        );
      } catch {
        if (outcome.status === "attested") {
          outcome = Object.freeze({
            status: "rejected",
            rejection: Object.freeze({
              code: "TRANSPORT_CLOSE_FAILED",
              humanMessage: "MCP capability transport did not close cleanly after attestation",
              retryable: true,
              rejectedAt: this.now().toISOString(),
            }),
          });
        }
      }
    } else if (transport) {
      try {
        await transport.close();
      } catch {
        // There is no successful attestation to revoke in this branch.
      }
    }
    return outcome;
  }
}

export function isMcpAttestationFresh(
  attestation: McpCapabilityAttestation,
  now: Date = new Date(),
): boolean {
  const issued = Date.parse(attestation.attestedAt);
  const expires = Date.parse(attestation.expiresAt);
  const current = now.getTime();
  return isMcpAttestationIntegrityValid(attestation)
    && Number.isFinite(issued)
    && Number.isFinite(expires)
    && expires > issued
    && current >= issued
    && current < expires;
}

export function isMcpAttestationIntegrityValid(
  attestation: McpCapabilityAttestation,
): boolean {
  try {
    const { manifestSha256, ...unsigned } = attestation;
    const recomputed = digestCanonicalJson(unsigned, {
      maxBytes: 64 * 1024 * 1024,
      maxDepth: 256,
    }).sha256;
    return /^[a-f0-9]{64}$/.test(manifestSha256) && recomputed === manifestSha256;
  } catch {
    return false;
  }
}

export function isMcpAttestationCurrentForConfig(
  attestation: McpCapabilityAttestation,
  config: unknown,
  now: Date = new Date(),
): boolean {
  try {
    return isMcpAttestationFresh(attestation, now)
      && attestation.configurationSha256 === hashMcpServerConnectionConfig(config);
  } catch {
    return false;
  }
}

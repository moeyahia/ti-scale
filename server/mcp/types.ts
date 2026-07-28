import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

export type McpConnectionTransport = "streamable-http" | "stdio";

export interface McpExpectedServerIdentity {
  readonly name: string;
  readonly version?: string;
}

export interface McpExpectedTool {
  readonly name: string;
  readonly inputSchemaSha256?: string;
  readonly outputSchemaSha256?: string;
  readonly taskSupport?: "optional" | "required" | "forbidden";
  readonly annotations?: Readonly<{
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  }>;
}

export interface McpToolInventoryPolicy {
  readonly requiredTools: readonly McpExpectedTool[];
  readonly allowAdditionalTools: boolean;
  readonly minimumToolCount: number;
}

export interface McpAttestationPolicy {
  readonly ttlMs: number;
  readonly timeoutMs: number;
  readonly maxPages: number;
  readonly maxTools: number;
  readonly maxSchemaBytes: number;
  readonly maxSchemaDepth: number;
  readonly maxManifestBytes: number;
  /** Transport providers must enforce this limit before parsing a wire message. */
  readonly maxInboundMessageBytes: number;
  readonly acceptedProtocolVersions: readonly string[];
}

interface McpServerConnectionBase {
  readonly id: string;
  readonly displayName: string;
  readonly enabled: boolean;
  readonly expectedServer: McpExpectedServerIdentity;
  readonly toolInventory: McpToolInventoryPolicy;
  readonly attestation: McpAttestationPolicy;
}

export interface McpHeaderCredentialReference {
  readonly id: string;
  readonly scheme?: string;
}

/** Secret values are never part of this descriptor or an attestation. */
export interface McpStreamableHttpConnectionConfig extends McpServerConnectionBase {
  readonly transport: "streamable-http";
  readonly endpoint: string;
  readonly allowInsecureLoopback: boolean;
  /** Compatibility path for non-sensitive or separately reviewed references. */
  readonly headerEnvironment?: Readonly<Record<string, string>>;
  /** Preferred production path: a credential ID in systemd's private mount. */
  readonly headerCredentials?: Readonly<Record<string, McpHeaderCredentialReference>>;
}

/**
 * This descriptor does not start a process. A separately reviewed transport
 * provider may use it to launch one exact executable with `shell: false`.
 */
export interface McpStdioConnectionConfig extends McpServerConnectionBase {
  readonly transport: "stdio";
  readonly executable: string;
  readonly args: readonly string[];
  readonly workingDirectory?: string;
  readonly environmentVariableNames: readonly string[];
  readonly shell: false;
}

export type McpServerConnectionConfig =
  | McpStreamableHttpConnectionConfig
  | McpStdioConnectionConfig;

export interface McpAttestationTransportFactory {
  /**
   * Creates a protocol transport only. The attester never invokes tools.
   * Implementations remain outside this bounded capability slice.
   */
  create(
    config: McpServerConnectionConfig,
    context: Readonly<{
      signal: AbortSignal;
      maxInboundMessageBytes: number;
    }>,
  ): Promise<Transport>;
}

export interface McpToolAnnotationsAttestation {
  readonly title?: string;
  readonly readOnlyHint?: boolean;
  readonly destructiveHint?: boolean;
  readonly idempotentHint?: boolean;
  readonly openWorldHint?: boolean;
}

export interface McpToolCapabilityAttestation {
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly inputSchema: Readonly<Record<string, unknown>>;
  readonly inputSchemaSha256: string;
  readonly inputSchemaBytes: number;
  readonly outputSchemaSha256?: string;
  readonly outputSchemaBytes?: number;
  readonly taskSupport?: "optional" | "required" | "forbidden";
  /** MCP annotations are untrusted advisory metadata, not policy authority. */
  readonly annotations: McpToolAnnotationsAttestation;
}

export interface McpCapabilityAttestation {
  readonly schemaVersion: "ti-scale.mcp-capability-attestation.v1";
  readonly connectionId: string;
  readonly transport: McpConnectionTransport;
  readonly server: Readonly<{
    name: string;
    version: string;
  }>;
  readonly protocolVersion: string;
  readonly capabilities: Readonly<{
    toolsListChanged: boolean;
  }>;
  /** Binds the attestation to the validated endpoint, identity, and policy. */
  readonly configurationSha256: string;
  readonly tools: readonly McpToolCapabilityAttestation[];
  readonly manifestSha256: string;
  readonly attestedAt: string;
  readonly expiresAt: string;
  /** Capability discovery alone never authorizes a tool invocation. */
  readonly executionAuthorization: "none";
}

export type McpAttestationRejectionCode =
  | "CONFIG_INVALID"
  | "CONFIG_DISABLED"
  | "TRANSPORT_UNAVAILABLE"
  | "INITIALIZATION_FAILED"
  | "SERVER_IDENTITY_MISMATCH"
  | "PROTOCOL_NOT_ALLOWED"
  | "TOOLS_CAPABILITY_MISSING"
  | "TOOLS_LIST_FAILED"
  | "TOOLS_PAGINATION_INVALID"
  | "TOOL_INVENTORY_INVALID"
  | "TOOL_SCHEMA_INVALID"
  | "REQUIRED_TOOL_MISSING"
  | "TOOL_SCHEMA_MISMATCH"
  | "TOOL_ANNOTATION_MISMATCH"
  | "UNEXPECTED_TOOL"
  | "ATTESTATION_TIMEOUT"
  | "TRANSPORT_CLOSE_FAILED";

export interface McpAttestationRejection {
  readonly code: McpAttestationRejectionCode;
  readonly humanMessage: string;
  readonly retryable: boolean;
  readonly rejectedAt: string;
}

export type McpAttestationOutcome =
  | Readonly<{
    status: "attested";
    attestation: McpCapabilityAttestation;
  }>
  | Readonly<{
    status: "rejected";
    rejection: McpAttestationRejection;
  }>;

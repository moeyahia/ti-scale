import { SUPPORTED_PROTOCOL_VERSIONS } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import type { McpServerConnectionConfig } from "./types";

const ID_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const ENVIRONMENT_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;
const CREDENTIAL_ID_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;
const AUTH_SCHEME_PATTERN = /^[A-Za-z][A-Za-z0-9._~-]{0,31}$/;
const HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const RESERVED_PROTOCOL_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "mcp-protocol-version",
  "mcp-session-id",
  "transfer-encoding",
]);

const expectedToolSchema = z.object({
  name: z.string().trim().min(1).max(128),
  inputSchemaSha256: z.string().regex(SHA256_PATTERN).optional(),
  outputSchemaSha256: z.string().regex(SHA256_PATTERN).optional(),
  taskSupport: z.enum(["optional", "required", "forbidden"]).optional(),
  annotations: z.object({
    readOnlyHint: z.boolean().optional(),
    destructiveHint: z.boolean().optional(),
    idempotentHint: z.boolean().optional(),
    openWorldHint: z.boolean().optional(),
  }).strict().optional(),
}).strict();

const commonSchema = z.object({
  id: z.string().regex(ID_PATTERN),
  displayName: z.string().trim().min(1).max(120),
  enabled: z.boolean(),
  expectedServer: z.object({
    name: z.string().trim().min(1).max(128),
    version: z.string().trim().min(1).max(128).optional(),
  }).strict(),
  toolInventory: z.object({
    requiredTools: z.array(expectedToolSchema).max(512),
    allowAdditionalTools: z.boolean(),
    minimumToolCount: z.number().int().min(0).max(10_000),
  }).strict(),
  attestation: z.object({
    ttlMs: z.number().int().min(1_000).max(24 * 60 * 60 * 1_000),
    timeoutMs: z.number().int().min(100).max(120_000),
    maxPages: z.number().int().min(1).max(1_000),
    maxTools: z.number().int().min(1).max(10_000),
    maxSchemaBytes: z.number().int().min(128).max(8 * 1024 * 1024),
    maxSchemaDepth: z.number().int().min(2).max(128),
    maxManifestBytes: z.number().int().min(1_024).max(64 * 1024 * 1024),
    maxInboundMessageBytes: z.number().int().min(1_024).max(64 * 1024 * 1024),
    acceptedProtocolVersions: z.array(z.string().min(1)).min(1).max(16),
  }).strict(),
});

const streamableHttpSchema = commonSchema.extend({
  transport: z.literal("streamable-http"),
  endpoint: z.string().url(),
  allowInsecureLoopback: z.boolean(),
  headerEnvironment: z.record(
    z.string().regex(HEADER_NAME_PATTERN),
    z.string().regex(ENVIRONMENT_NAME_PATTERN),
  ).optional(),
  headerCredentials: z.record(
    z.string().regex(HEADER_NAME_PATTERN),
    z.object({
      id: z.string().regex(CREDENTIAL_ID_PATTERN),
      scheme: z.string().regex(AUTH_SCHEME_PATTERN).optional(),
    }).strict(),
  ).optional(),
}).strict();

const stdioSchema = commonSchema.extend({
  transport: z.literal("stdio"),
  executable: z.string().startsWith("/").min(2).max(4_096),
  args: z.array(z.string().max(16_384)).max(512),
  workingDirectory: z.string().startsWith("/").min(2).max(4_096).optional(),
  environmentVariableNames: z.array(z.string().regex(ENVIRONMENT_NAME_PATTERN)).max(256),
  shell: z.literal(false),
}).strict();

export const McpServerConnectionConfigSchema = z.discriminatedUnion("transport", [
  streamableHttpSchema,
  stdioSchema,
]).superRefine((config, context) => {
  const requiredNames = config.toolInventory.requiredTools.map((tool) => tool.name);
  if (new Set(requiredNames).size !== requiredNames.length) {
    context.addIssue({
      code: "custom",
      path: ["toolInventory", "requiredTools"],
      message: "Required tool names must be unique",
    });
  }

  const accepted = config.attestation.acceptedProtocolVersions;
  for (const version of accepted) {
    if (!SUPPORTED_PROTOCOL_VERSIONS.includes(version)) {
      context.addIssue({
        code: "custom",
        path: ["attestation", "acceptedProtocolVersions"],
        message: `Protocol version ${version} is not supported by the pinned MCP SDK`,
      });
    }
  }
  if (new Set(accepted).size !== accepted.length) {
    context.addIssue({
      code: "custom",
      path: ["attestation", "acceptedProtocolVersions"],
      message: "Accepted protocol versions must be unique",
    });
  }

  if (config.toolInventory.minimumToolCount > config.attestation.maxTools) {
    context.addIssue({
      code: "custom",
      path: ["toolInventory", "minimumToolCount"],
      message: "Minimum tool count cannot exceed the attestation tool limit",
    });
  }
  if (config.toolInventory.requiredTools.length > config.attestation.maxTools) {
    context.addIssue({
      code: "custom",
      path: ["toolInventory", "requiredTools"],
      message: "Required tool count cannot exceed the attestation tool limit",
    });
  }

  if (config.transport === "streamable-http") {
    const endpoint = new URL(config.endpoint);
    if (endpoint.username || endpoint.password) {
      context.addIssue({
        code: "custom",
        path: ["endpoint"],
        message: "MCP endpoint URLs must not contain credentials",
      });
    }
    const loopback = endpoint.protocol === "http:"
      && ["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname);
    if (endpoint.protocol !== "https:" && (!loopback || !config.allowInsecureLoopback)) {
      context.addIssue({
        code: "custom",
        path: ["endpoint"],
        message: "Remote MCP endpoints require HTTPS; HTTP is allowed only for an explicitly enabled loopback endpoint",
      });
    }
    const environmentHeaders = Object.keys(config.headerEnvironment ?? {});
    const credentialHeaders = Object.keys(config.headerCredentials ?? {});
    const headers = [...environmentHeaders, ...credentialHeaders];
    if (headers.length > 128) {
      context.addIssue({
        code: "custom",
        path: ["headerEnvironment"],
        message: "At most 128 environment-backed headers may be configured",
      });
    }
    const reserved = headers.find((header) => RESERVED_PROTOCOL_HEADERS.has(header.toLowerCase()));
    if (reserved) {
      context.addIssue({
        code: "custom",
        path: ["headerEnvironment", reserved],
        message: `${reserved} is controlled by the MCP transport and cannot be overridden`,
      });
    }
    const duplicate = environmentHeaders.find((header) =>
      credentialHeaders.some((candidate) => candidate.toLowerCase() === header.toLowerCase()));
    if (duplicate) {
      context.addIssue({
        code: "custom",
        path: ["headerCredentials", duplicate],
        message: `${duplicate} cannot use both environment and systemd credential sources`,
      });
    }
  } else if (new Set(config.environmentVariableNames).size !== config.environmentVariableNames.length) {
    context.addIssue({
      code: "custom",
      path: ["environmentVariableNames"],
      message: "Environment variable names must be unique",
    });
  }
});

export function parseMcpServerConnectionConfig(input: unknown): McpServerConnectionConfig {
  return McpServerConnectionConfigSchema.parse(input) as McpServerConnectionConfig;
}

import { createHash } from "node:crypto";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import type { McpToolCapabilityAttestation } from "../mcp/types";
import type {
  CreateFailureDiagnosisInput,
  FailureCategory,
  FailureOperatorAction,
  FailureReference,
  OperationalActor,
} from "../intelligence-v24/types";

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const MAXIMUM_INPUT_BYTES = 256 * 1024;
const MAXIMUM_SCHEMA_DEPTH = 32;
const MAXIMUM_ISSUES = 32;
const ANNOTATION_KEYS = new Set([
  "$schema",
  "$id",
  "$anchor",
  "title",
  "description",
  "default",
  "examples",
  "deprecated",
  "readOnly",
  "writeOnly",
]);
const VALIDATION_KEYS = new Set([
  "$ref",
  "$defs",
  "definitions",
  "type",
  "nullable",
  "properties",
  "required",
  "additionalProperties",
  "minProperties",
  "maxProperties",
  "items",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minLength",
  "maxLength",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
  "enum",
  "const",
  "allOf",
  "anyOf",
  "oneOf",
]);

export type McpToolInvocationPreflightCode =
  | "ready"
  | "tool_name_mismatch"
  | "schema_binding_mismatch"
  | "schema_unsupported"
  | "input_not_json"
  | "input_too_large"
  | "input_invalid";

export type McpToolInputIssueCode =
  | "required"
  | "additional_property"
  | "type"
  | "enum"
  | "const"
  | "minimum"
  | "maximum"
  | "multiple_of"
  | "min_length"
  | "max_length"
  | "min_items"
  | "max_items"
  | "unique_items"
  | "min_properties"
  | "max_properties"
  | "all_of"
  | "any_of"
  | "one_of"
  | "schema";

export interface McpToolInputIssue {
  readonly path: string;
  readonly code: McpToolInputIssueCode;
  readonly message: string;
}

export interface McpToolInvocationPreflightResult {
  readonly schemaVersion: "ti-scale.mcp-tool-invocation-preflight.v1";
  readonly status: "ready" | "rejected";
  readonly code: McpToolInvocationPreflightCode;
  readonly serverId: string;
  readonly toolName: string;
  readonly attestedToolName: string;
  readonly inputSchemaSha256: string;
  readonly inputSha256: string | null;
  readonly inputBytes: number | null;
  /**
   * Preflight rejection proves that no target contact began. Once the MCP
   * transport was invoked, absence of an accepted result does not prove
   * whether the remote tool contacted its target.
   */
  readonly targetContact: false | "not_established";
  readonly executionAuthorization: "none";
  readonly issues: readonly McpToolInputIssue[];
  readonly explanation: string;
  readonly remediation: string | null;
}

interface ValidationContext {
  readonly rootSchema: Readonly<Record<string, unknown>>;
  readonly issues: McpToolInputIssue[];
  readonly refStack: Set<string>;
}

type JsonSchema = boolean | Readonly<Record<string, unknown>>;

function pointer(path: string, key: string | number): string {
  const escaped = String(key).replaceAll("~", "~0").replaceAll("/", "~1");
  return `${path}/${escaped}`;
}

function plainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function issue(
  context: ValidationContext,
  path: string,
  code: McpToolInputIssueCode,
  message: string,
): void {
  if (context.issues.length < MAXIMUM_ISSUES) context.issues.push({ path: path || "/", code, message });
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  try {
    return digestCanonicalJson(left, { maxBytes: MAXIMUM_INPUT_BYTES, maxDepth: MAXIMUM_SCHEMA_DEPTH }).canonicalJson
      === digestCanonicalJson(right, { maxBytes: MAXIMUM_INPUT_BYTES, maxDepth: MAXIMUM_SCHEMA_DEPTH }).canonicalJson;
  } catch {
    return false;
  }
}

function valueType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (plainRecord(value)) return "object";
  if (typeof value === "number" && Number.isInteger(value)) return "integer";
  return typeof value;
}

function matchesType(value: unknown, expected: string): boolean {
  switch (expected) {
    case "null": return value === null;
    case "array": return Array.isArray(value);
    case "object": return plainRecord(value);
    case "integer": return typeof value === "number" && Number.isSafeInteger(value);
    case "number": return typeof value === "number" && Number.isFinite(value);
    case "string": return typeof value === "string";
    case "boolean": return typeof value === "boolean";
    default: return false;
  }
}

function integerKeyword(schema: Readonly<Record<string, unknown>>, key: string): number | undefined {
  const value = schema[key];
  return Number.isSafeInteger(value) && (value as number) >= 0 ? value as number : undefined;
}

function numberKeyword(schema: Readonly<Record<string, unknown>>, key: string): number | undefined {
  const value = schema[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function localReference(root: Readonly<Record<string, unknown>>, reference: string): JsonSchema | undefined {
  if (reference === "#") return root;
  if (!reference.startsWith("#/")) return undefined;
  let current: unknown = root;
  for (const encoded of reference.slice(2).split("/")) {
    const key = encoded.replaceAll("~1", "/").replaceAll("~0", "~");
    if (!plainRecord(current) || !(key in current)) return undefined;
    current = current[key];
  }
  return typeof current === "boolean" || plainRecord(current) ? current : undefined;
}

function validateSchemaValue(
  schema: JsonSchema,
  value: unknown,
  path: string,
  context: ValidationContext,
  depth: number,
): void {
  if (context.issues.length >= MAXIMUM_ISSUES) return;
  if (depth > MAXIMUM_SCHEMA_DEPTH) {
    issue(context, path, "schema", "The attested input schema exceeds the supported validation depth.");
    return;
  }
  if (schema === true) return;
  if (schema === false) {
    issue(context, path, "schema", "This field is not accepted by the attested tool contract.");
    return;
  }

  const reference = schema.$ref;
  if (reference !== undefined) {
    if (typeof reference !== "string" || context.refStack.has(reference)) {
      issue(context, path, "schema", "The attested tool schema contains an invalid or cyclic local reference.");
      return;
    }
    const target = localReference(context.rootSchema, reference);
    if (target === undefined) {
      issue(context, path, "schema", "The attested tool schema references an unavailable local definition.");
      return;
    }
    context.refStack.add(reference);
    validateSchemaValue(target, value, path, context, depth + 1);
    context.refStack.delete(reference);
  }

  const branches = (key: "allOf" | "anyOf" | "oneOf"): readonly JsonSchema[] | undefined => {
    const item = schema[key];
    return Array.isArray(item) && item.every((entry) => typeof entry === "boolean" || plainRecord(entry))
      ? item as readonly JsonSchema[]
      : undefined;
  };
  const allOf = branches("allOf");
  if (allOf) {
    const before = context.issues.length;
    for (const branch of allOf) validateSchemaValue(branch, value, path, context, depth + 1);
    if (context.issues.length > before && allOf.length > 1) {
      issue(context, path, "all_of", "The value does not satisfy every required part of the tool contract.");
    }
  }
  for (const kind of ["anyOf", "oneOf"] as const) {
    const options = branches(kind);
    if (!options) continue;
    let valid = 0;
    for (const option of options) {
      const branchContext: ValidationContext = {
        rootSchema: context.rootSchema,
        issues: [],
        refStack: new Set(context.refStack),
      };
      validateSchemaValue(option, value, path, branchContext, depth + 1);
      if (branchContext.issues.length === 0) valid += 1;
    }
    if ((kind === "anyOf" && valid < 1) || (kind === "oneOf" && valid !== 1)) {
      issue(
        context,
        path,
        kind === "anyOf" ? "any_of" : "one_of",
        kind === "anyOf"
          ? "The value does not match any accepted tool-input shape."
          : "The value must match exactly one accepted tool-input shape.",
      );
    }
  }

  const declaredType = schema.type;
  const allowedTypes = typeof declaredType === "string"
    ? [declaredType]
    : Array.isArray(declaredType) && declaredType.every((entry) => typeof entry === "string")
      ? declaredType
      : [];
  if (schema.nullable === true && !allowedTypes.includes("null")) allowedTypes.push("null");
  if (allowedTypes.length > 0 && !allowedTypes.some((type) => matchesType(value, type))) {
    issue(context, path, "type", `Expected ${allowedTypes.join(" or ")}; received ${valueType(value)}.`);
    return;
  }

  if (Array.isArray(schema.enum) && !schema.enum.some((entry) => canonicalEqual(entry, value))) {
    issue(context, path, "enum", "The value is not one of the tool's accepted options.");
  }
  if ("const" in schema && !canonicalEqual(schema.const, value)) {
    issue(context, path, "const", "The value does not match the fixed value required by the tool contract.");
  }

  if (typeof value === "string") {
    const minimum = integerKeyword(schema, "minLength");
    const maximum = integerKeyword(schema, "maxLength");
    const length = [...value].length;
    if (minimum !== undefined && length < minimum) issue(context, path, "min_length", `Enter at least ${minimum} character${minimum === 1 ? "" : "s"}.`);
    if (maximum !== undefined && length > maximum) issue(context, path, "max_length", `Enter no more than ${maximum} characters.`);
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    const minimum = numberKeyword(schema, "minimum");
    const maximum = numberKeyword(schema, "maximum");
    const exclusiveMinimum = numberKeyword(schema, "exclusiveMinimum");
    const exclusiveMaximum = numberKeyword(schema, "exclusiveMaximum");
    const multipleOf = numberKeyword(schema, "multipleOf");
    if (minimum !== undefined && value < minimum) issue(context, path, "minimum", `Enter a number greater than or equal to ${minimum}.`);
    if (maximum !== undefined && value > maximum) issue(context, path, "maximum", `Enter a number less than or equal to ${maximum}.`);
    if (exclusiveMinimum !== undefined && value <= exclusiveMinimum) issue(context, path, "minimum", `Enter a number greater than ${exclusiveMinimum}.`);
    if (exclusiveMaximum !== undefined && value >= exclusiveMaximum) issue(context, path, "maximum", `Enter a number less than ${exclusiveMaximum}.`);
    if (multipleOf !== undefined && multipleOf > 0) {
      const quotient = value / multipleOf;
      if (Math.abs(quotient - Math.round(quotient)) > Number.EPSILON * 16) {
        issue(context, path, "multiple_of", `Enter a multiple of ${multipleOf}.`);
      }
    }
  }

  if (Array.isArray(value)) {
    const minimum = integerKeyword(schema, "minItems");
    const maximum = integerKeyword(schema, "maxItems");
    if (minimum !== undefined && value.length < minimum) issue(context, path, "min_items", `Provide at least ${minimum} item${minimum === 1 ? "" : "s"}.`);
    if (maximum !== undefined && value.length > maximum) issue(context, path, "max_items", `Provide no more than ${maximum} items.`);
    if (schema.uniqueItems === true) {
      const digests = value.map((entry) => {
        try {
          return digestCanonicalJson(entry, { maxBytes: MAXIMUM_INPUT_BYTES, maxDepth: MAXIMUM_SCHEMA_DEPTH }).sha256;
        } catch {
          return undefined;
        }
      });
      if (new Set(digests).size !== digests.length) issue(context, path, "unique_items", "Provide each list item only once.");
    }
    const itemSchema = schema.items;
    if (typeof itemSchema === "boolean" || plainRecord(itemSchema)) {
      value.forEach((entry, index) => validateSchemaValue(itemSchema, entry, pointer(path, index), context, depth + 1));
    }
  }

  if (plainRecord(value)) {
    const properties = plainRecord(schema.properties) ? schema.properties : {};
    const required = Array.isArray(schema.required)
      ? schema.required.filter((entry): entry is string => typeof entry === "string")
      : [];
    for (const key of required) {
      if (!(key in value)) issue(context, pointer(path, key), "required", `Provide the required “${key}” field.`);
    }
    for (const [key, entry] of Object.entries(value)) {
      const propertySchema = properties[key];
      if (typeof propertySchema === "boolean" || plainRecord(propertySchema)) {
        validateSchemaValue(propertySchema, entry, pointer(path, key), context, depth + 1);
      } else if (schema.additionalProperties === false) {
        issue(context, pointer(path, key), "additional_property", `Remove the unsupported “${key}” field.`);
      } else if (typeof schema.additionalProperties === "boolean" || plainRecord(schema.additionalProperties)) {
        validateSchemaValue(schema.additionalProperties, entry, pointer(path, key), context, depth + 1);
      }
    }
    const minimum = integerKeyword(schema, "minProperties");
    const maximum = integerKeyword(schema, "maxProperties");
    const count = Object.keys(value).length;
    if (minimum !== undefined && count < minimum) issue(context, path, "min_properties", `Provide at least ${minimum} field${minimum === 1 ? "" : "s"}.`);
    if (maximum !== undefined && count > maximum) issue(context, path, "max_properties", `Provide no more than ${maximum} fields.`);
  }
}

function unsupportedSchemaKeywords(schema: unknown, path = "", depth = 0): readonly McpToolInputIssue[] {
  if (depth > MAXIMUM_SCHEMA_DEPTH) return [{ path: path || "/", code: "schema", message: "The attested schema exceeds the supported depth." }];
  if (typeof schema === "boolean") return [];
  if (!plainRecord(schema)) return [{ path: path || "/", code: "schema", message: "The attested schema contains a non-object schema node." }];
  const found: McpToolInputIssue[] = [];
  for (const key of Object.keys(schema)) {
    if (!ANNOTATION_KEYS.has(key) && !VALIDATION_KEYS.has(key) && !key.startsWith("x-")) {
      found.push({ path: pointer(path, key), code: "schema", message: `The attested schema uses unsupported keyword “${key}”.` });
    }
  }
  const malformed = (key: string, valid: boolean): void => {
    if (!valid && key in schema && found.length < MAXIMUM_ISSUES) {
      found.push({
        path: pointer(path, key),
        code: "schema",
        message: `The attested schema has an invalid “${key}” constraint.`,
      });
    }
  };
  const knownTypes = new Set(["null", "array", "object", "integer", "number", "string", "boolean"]);
  malformed("$ref", typeof schema.$ref === "string" && schema.$ref.startsWith("#"));
  malformed("$defs", plainRecord(schema.$defs));
  malformed("definitions", plainRecord(schema.definitions));
  malformed("type", typeof schema.type === "string"
    ? knownTypes.has(schema.type)
    : Array.isArray(schema.type)
      && schema.type.length > 0
      && new Set(schema.type).size === schema.type.length
      && schema.type.every((entry) => typeof entry === "string" && knownTypes.has(entry)));
  malformed("nullable", typeof schema.nullable === "boolean");
  malformed("properties", plainRecord(schema.properties));
  malformed("required", Array.isArray(schema.required)
    && new Set(schema.required).size === schema.required.length
    && schema.required.every((entry) => typeof entry === "string"));
  malformed("additionalProperties", typeof schema.additionalProperties === "boolean" || plainRecord(schema.additionalProperties));
  malformed("items", typeof schema.items === "boolean" || plainRecord(schema.items));
  malformed("uniqueItems", typeof schema.uniqueItems === "boolean");
  for (const key of ["minProperties", "maxProperties", "minItems", "maxItems", "minLength", "maxLength"] as const) {
    malformed(key, Number.isSafeInteger(schema[key]) && (schema[key] as number) >= 0);
  }
  for (const key of ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"] as const) {
    malformed(key, typeof schema[key] === "number" && Number.isFinite(schema[key]));
  }
  malformed("multipleOf", typeof schema.multipleOf === "number" && Number.isFinite(schema.multipleOf) && schema.multipleOf > 0);
  malformed("enum", Array.isArray(schema.enum) && schema.enum.length > 0);
  for (const key of ["allOf", "anyOf", "oneOf"] as const) {
    malformed(key, Array.isArray(schema[key])
      && schema[key].length > 0
      && schema[key].every((entry) => typeof entry === "boolean" || plainRecord(entry)));
  }
  const nested: unknown[] = [];
  if (plainRecord(schema.properties)) nested.push(...Object.values(schema.properties));
  if (plainRecord(schema.$defs)) nested.push(...Object.values(schema.$defs));
  if (plainRecord(schema.definitions)) nested.push(...Object.values(schema.definitions));
  if (typeof schema.items === "boolean" || plainRecord(schema.items)) nested.push(schema.items);
  if (typeof schema.additionalProperties === "boolean" || plainRecord(schema.additionalProperties)) nested.push(schema.additionalProperties);
  for (const key of ["allOf", "anyOf", "oneOf"] as const) {
    if (Array.isArray(schema[key])) nested.push(...schema[key] as unknown[]);
  }
  for (const entry of nested) {
    if (found.length >= MAXIMUM_ISSUES) break;
    found.push(...unsupportedSchemaKeywords(entry, path, depth + 1).slice(0, MAXIMUM_ISSUES - found.length));
  }
  return found;
}

function rejection(input: Omit<McpToolInvocationPreflightResult, "schemaVersion" | "status" | "targetContact" | "executionAuthorization">): McpToolInvocationPreflightResult {
  return {
    schemaVersion: "ti-scale.mcp-tool-invocation-preflight.v1",
    status: "rejected",
    targetContact: false,
    executionAuthorization: "none",
    ...input,
  };
}

/**
 * Validates one exact tool invocation against its fresh attested MCP schema.
 * It returns hashes and field-level diagnostics, never argument values.
 */
export function preflightMcpToolInvocation(input: {
  readonly serverId: string;
  readonly requestedToolName: string;
  readonly attestedTool: McpToolCapabilityAttestation;
  readonly arguments: unknown;
  readonly maximumInputBytes?: number;
}): McpToolInvocationPreflightResult {
  if (!PUBLIC_ID.test(input.serverId) || !PUBLIC_ID.test(input.requestedToolName)) {
    throw new Error("MCP invocation preflight requires stable public server and tool IDs");
  }
  const schemaSha256 = input.attestedTool.inputSchemaSha256;
  const maximumInputBytes = input.maximumInputBytes ?? MAXIMUM_INPUT_BYTES;
  if (!Number.isSafeInteger(maximumInputBytes) || maximumInputBytes < 1_024 || maximumInputBytes > MAXIMUM_INPUT_BYTES) {
    throw new RangeError("MCP invocation input limit must be 1024 through 262144 bytes");
  }
  let inputDigest: ReturnType<typeof digestCanonicalJson> | undefined;
  try {
    inputDigest = digestCanonicalJson(input.arguments, { maxBytes: maximumInputBytes, maxDepth: MAXIMUM_SCHEMA_DEPTH });
  } catch (error) {
    const tooLarge = error instanceof Error && /bytes; limit/iu.test(error.message);
    return rejection({
      code: tooLarge ? "input_too_large" : "input_not_json",
      serverId: input.serverId,
      toolName: input.requestedToolName,
      attestedToolName: input.attestedTool.name,
      inputSchemaSha256: schemaSha256,
      inputSha256: null,
      inputBytes: null,
      issues: [{
        path: "/",
        code: "schema",
        message: tooLarge
          ? "The tool input exceeds the reviewed size limit."
          : "The tool input is not a finite, acyclic plain JSON value.",
      }],
      explanation: "The MCP tool was not called because its parameters could not be represented safely.",
      remediation: "Rebuild the arguments as a bounded plain JSON object that contains only fields declared by the tool contract.",
    });
  }
  const base = {
    serverId: input.serverId,
    toolName: input.requestedToolName,
    attestedToolName: input.attestedTool.name,
    inputSchemaSha256: schemaSha256,
    inputSha256: inputDigest.sha256,
    inputBytes: inputDigest.bytes,
  };
  if (input.requestedToolName !== input.attestedTool.name) {
    return rejection({
      ...base,
      code: "tool_name_mismatch",
      issues: [{ path: "/", code: "schema", message: "The requested tool name does not match the attested MCP tool." }],
      explanation: "The MCP tool was not called because the requested binding differs from the attested tool inventory.",
      remediation: "Refresh capability attestation and select the exact reviewed server/tool binding.",
    });
  }
  let actualSchemaSha256: string;
  try {
    actualSchemaSha256 = digestCanonicalJson(input.attestedTool.inputSchema, {
      maxBytes: Math.max(input.attestedTool.inputSchemaBytes, 1),
      maxDepth: MAXIMUM_SCHEMA_DEPTH,
    }).sha256;
  } catch {
    actualSchemaSha256 = "";
  }
  if (!/^[a-f0-9]{64}$/u.test(schemaSha256) || actualSchemaSha256 !== schemaSha256) {
    return rejection({
      ...base,
      code: "schema_binding_mismatch",
      issues: [{ path: "/", code: "schema", message: "The input schema no longer matches its attested hash." }],
      explanation: "The MCP tool was not called because its input contract changed after capability attestation.",
      remediation: "Quarantine the stale binding and obtain a fresh, reviewed MCP capability attestation.",
    });
  }
  const unsupported = unsupportedSchemaKeywords(input.attestedTool.inputSchema).slice(0, MAXIMUM_ISSUES);
  if (unsupported.length > 0) {
    return rejection({
      ...base,
      code: "schema_unsupported",
      issues: unsupported,
      explanation: "The MCP tool was not called because its attested schema uses constraints this local validator cannot enforce exactly.",
      remediation: "Add reviewed validator support for the reported schema constraints before enabling this tool.",
    });
  }
  const issues: McpToolInputIssue[] = [];
  validateSchemaValue(input.attestedTool.inputSchema, input.arguments, "", {
    rootSchema: input.attestedTool.inputSchema,
    issues,
    refStack: new Set(),
  }, 0);
  if (issues.length > 0) {
    return rejection({
      ...base,
      code: "input_invalid",
      issues,
      explanation: `The MCP tool was not called because ${issues.length} parameter constraint${issues.length === 1 ? " was" : "s were"} not satisfied.`,
      remediation: "Correct the listed fields and create a new invocation fingerprint; do not repeat the unchanged request.",
    });
  }
  return {
    schemaVersion: "ti-scale.mcp-tool-invocation-preflight.v1",
    status: "ready",
    code: "ready",
    ...base,
    targetContact: false,
    executionAuthorization: "none",
    issues: [],
    explanation: "The parameters match the exact attested MCP input schema. Runtime policy and action authorization are still required before dispatch.",
    remediation: null,
  };
}

export interface McpToolFailureSignal {
  readonly httpStatus?: number;
  readonly transportCode?: string;
  readonly attemptCount?: number;
  readonly retryAfterMs?: number;
}

export interface McpToolFailureContext {
  readonly missionId: string;
  readonly runId: string;
  readonly stepId?: string;
  readonly actionId?: string;
  readonly subjectType?: "run" | "step" | "action";
  readonly subjectId?: string;
  readonly targetSummary?: string;
  readonly lastSuccessEventId?: string;
  readonly rawErrorLogId?: string;
  readonly preservedReferences?: readonly FailureReference[];
  readonly actor: OperationalActor;
}

function retryActions(): readonly FailureOperatorAction[] {
  return [
    {
      kind: "test_connection",
      label: "Test the MCP connection",
      consequence: "Runs a bounded, non-target capability check before any retry.",
      requiresConfirmation: false,
    },
    {
      kind: "retry_bounded",
      label: "Retry once after readiness passes",
      consequence: "Dispatches one bounded retry only after the dependency is healthy and the retry window is open.",
      requiresConfirmation: true,
    },
    {
      kind: "use_compatible_fallback",
      label: "Use a reviewed fallback",
      consequence: "Changes the binding only after the alternative passes schema, policy, and readiness checks.",
      requiresConfirmation: true,
    },
  ];
}

function correctionActions(): readonly FailureOperatorAction[] {
  return [
    {
      kind: "amend_plan",
      label: "Correct the represented tool request",
      consequence: "Creates a new structured request and fingerprint after the invalid fields are corrected.",
      requiresConfirmation: true,
    },
    {
      kind: "configure_dependency",
      label: "Refresh the MCP tool contract",
      consequence: "Re-attests the exact server and schema before another invocation is allowed.",
      requiresConfirmation: true,
    },
    {
      kind: "use_compatible_fallback",
      label: "Use a reviewed compatible tool",
      consequence: "Selects another tool only after its own exact contract and policy checks pass.",
      requiresConfirmation: true,
    },
  ];
}

function failureClassification(signal: McpToolFailureSignal): Readonly<{
  category: FailureCategory;
  code: string;
  retryable: boolean;
  reason: string;
  remediation: string;
  actions: readonly FailureOperatorAction[];
}> {
  const status = signal.httpStatus;
  if (status === 400 || status === 409 || status === 422) {
    return {
      category: status === 400 || status === 422 ? "invalid_input" : "deterministic_tool_error",
      code: status === 400 ? "mcp_http_400_contract_rejected" : `mcp_http_${status}_request_rejected`,
      retryable: false,
      reason: `The MCP server rejected the request with HTTP ${status}. This is a deterministic request or binding problem, not a temporary outage.`,
      remediation: "Inspect the field-level preflight result and refresh the attested tool contract. Change the request before another dispatch.",
      actions: correctionActions(),
    };
  }
  if (status === 401) {
    return {
      category: "authentication_missing",
      code: "mcp_http_401_authentication_missing",
      retryable: false,
      reason: "The MCP server rejected its configured authentication. No tool result was accepted.",
      remediation: "Repair the MCP credential through the secret-management boundary, then obtain a fresh readiness attestation.",
      actions: correctionActions().slice(1),
    };
  }
  if (status === 403) {
    return {
      category: "policy_denied",
      code: "mcp_http_403_policy_denied",
      retryable: false,
      reason: "The MCP server refused this invocation under its current authorization or policy boundary.",
      remediation: "Review the exact authorization and tool policy. Do not retry or broaden scope automatically.",
      actions: correctionActions(),
    };
  }
  if (status === 408 || status === 504) {
    return {
      category: "timeout",
      code: `mcp_http_${status}_timeout`,
      retryable: true,
      reason: `The MCP request exceeded its bounded deadline (HTTP ${status}).`,
      remediation: "Test the MCP connection and use at most one bounded retry after readiness succeeds.",
      actions: retryActions(),
    };
  }
  if (status === 429) {
    return {
      category: "rate_limit",
      code: "mcp_http_429_rate_limit",
      retryable: true,
      reason: "The MCP service temporarily refused the request because its allowed request rate is currently exhausted.",
      remediation: signal.retryAfterMs !== undefined
        ? `Wait at least ${signal.retryAfterMs} ms, then test readiness before one bounded retry.`
        : "Honor the service retry window, then test readiness before one bounded retry.",
      actions: retryActions(),
    };
  }
  if (status !== undefined && status >= 500) {
    return {
      category: "mcp_unavailable",
      code: `mcp_http_${status}_unavailable`,
      retryable: true,
      reason: `The MCP service was unavailable while processing the request (HTTP ${status}).`,
      remediation: "Test service health and use one bounded retry or a reviewed fallback after the dependency recovers.",
      actions: retryActions(),
    };
  }
  return {
    category: "mcp_unavailable",
    code: "mcp_transport_unavailable",
    retryable: true,
    reason: "The MCP transport ended before a valid tool result was received.",
    remediation: "Test the exact MCP connection and use one bounded retry only after readiness succeeds.",
    actions: retryActions(),
  };
}

/** Converts a rejected preflight or MCP transport response into canonical FailureDiagnosis input. */
export function mcpToolFailureDiagnosisInput(
  preflight: McpToolInvocationPreflightResult,
  signal: McpToolFailureSignal,
  context: McpToolFailureContext,
): CreateFailureDiagnosisInput {
  const subjectType = context.subjectType ?? (context.actionId ? "action" : context.stepId ? "step" : "run");
  const expectedSubjectId = subjectType === "action" ? context.actionId : subjectType === "step" ? context.stepId : context.runId;
  const subjectId = context.subjectId ?? expectedSubjectId;
  if (!subjectId || subjectId !== expectedSubjectId) {
    throw new Error("MCP failure subject does not match its canonical context");
  }
  const attempts = signal.attemptCount ?? 1;
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 1_000) {
    throw new RangeError("MCP failure attempt count must be 1 through 1000");
  }
  const invalidBeforeDispatch = preflight.status === "rejected";
  const classification = invalidBeforeDispatch
    ? {
        category: "invalid_input" as const,
        code: `mcp_preflight_${preflight.code}`,
        retryable: false,
        reason: preflight.explanation,
        remediation: preflight.remediation ?? "Correct the represented parameters before another dispatch.",
        actions: correctionActions(),
      }
    : failureClassification(signal);
  const issueSummary = preflight.issues.slice(0, 5).map(({ path, message }) => `${path}: ${message}`);
  const board400Explanation = !invalidBeforeDispatch && signal.httpStatus === 400
    ? `${preflight.serverId} rejected ${preflight.toolName} with HTTP 400 after the payload passed its locally attested input schema. The server has an additional constraint or its binding changed; repeating identical parameters is disabled.`
    : classification.reason;
  return {
    missionId: context.missionId,
    runId: context.runId,
    ...(context.stepId ? { stepId: context.stepId } : {}),
    ...(context.actionId ? { actionId: context.actionId } : {}),
    subjectType,
    subjectId,
    humanReason: issueSummary.length > 0
      ? `${board400Explanation} ${issueSummary.join(" ")}`
      : board400Explanation,
    category: classification.category,
    code: classification.code,
    originatingComponent: "mcp-tool-runtime",
    ...(context.lastSuccessEventId ? { lastSuccessEventId: context.lastSuccessEventId } : {}),
    failedComponentRef: `${preflight.serverId}/${preflight.toolName}`,
    targetSummary: context.targetSummary ?? (invalidBeforeDispatch
      ? "The tool was not dispatched and no target interaction began."
      : "The MCP request did not produce an accepted tool result."),
    policyOrDependency: `Exact tool schema ${preflight.inputSchemaSha256}; parameter receipt ${preflight.inputSha256 ?? "unavailable"}.`,
    ...(context.rawErrorLogId ? { rawErrorLogId: context.rawErrorLogId } : {}),
    retryHistory: Array.from({ length: Math.min(attempts, 20) }, (_, index) => ({
      attempt: index + 1,
      outcome: invalidBeforeDispatch ? "preflight_rejected" : `http_${signal.httpStatus ?? "transport"}`,
      unchangedInputSha256: preflight.inputSha256,
    })),
    progressBeforeFailure: {
      inputSchemaValidated: preflight.status === "ready",
      targetContact: invalidBeforeDispatch ? false : "not_established",
      acceptedToolResult: false,
    },
    preservedReferences: context.preservedReferences ?? [],
    retryable: classification.retryable,
    automaticRecovery: {
      attempted: false,
      repeatedUnchangedDispatchSuppressed: !classification.retryable,
      attemptCount: attempts,
      transportCodeSha256: signal.transportCode
        ? createHash("sha256").update(signal.transportCode, "utf8").digest("hex")
        : null,
    },
    remediation: classification.remediation,
    operatorActions: classification.actions,
    objectiveImpact: invalidBeforeDispatch
      ? "The affected step did not start. Existing mission state, evidence, and artifacts remain unchanged."
      : "The affected step did not receive a valid result. Prior mission progress remains preserved for recovery or amendment.",
    actor: context.actor,
  };
}

import { createHash } from "node:crypto";
import { isAbsolute, resolve, sep } from "node:path";
import { isIP } from "node:net";
import {
  buildRuntimeCapabilityProjection,
  isActionClassId,
  isEvidenceTypeId,
  type ActionClassId,
  type EvidenceTypeId,
  type RuntimeSourceManifests,
} from "../domain";
import { EVIDENCE_TYPE_DEFINITIONS } from "../domain/evidence-type-registry";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import {
  TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
  type ToolBindingRegistryDocument,
} from "../system-capabilities/ToolBindingRegistry";

export const LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION =
  "ti-scale.local-tool-capability-manifest.v1" as const;
export const LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION =
  "ti-scale.local-tool-activation-receipt.v1" as const;

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const PARAMETER_NAME = /^[a-z][A-Za-z0-9]{0,63}$/u;
const VERSION = /^[A-Za-z0-9._-]{1,80}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const SECRET_VALUE = /(?:\bBearer\s+\S+|(?:sk|rk|pk)-[A-Za-z0-9_-]{8,}|-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----|(?:api[-_]?key|authorization|cookie|password|private[-_]?key|secret|session[-_]?token)\s*[:=]\s*\S+)/iu;
const SAFE_PROBE_ARGUMENTS = new Set(["--version", "-V", "version", "-version", "--help", "-h"]);
const ARGUMENT_SEMANTICS = [
  "logical_workspace",
  "authorized_target",
  "authorized_single_host",
  "authorized_http_url",
  "authorized_canonical_http_url",
  "authorized_http_base_url",
  "authorized_dns_name",
  "tcp_port",
  "tcp_port_set",
  "dns_record_type",
] as const;
export const MAX_REVIEWED_TCP_PORT_SET_SIZE = 1_024 as const;
export const LOCAL_TOOL_ROUTE_INTENTS = [
  "dns_query",
  "host_liveness",
  "http_metadata",
  "tcp_connect",
  "port_scan",
  "full_tcp_discovery",
  "targeted_service_version",
  "web_fingerprint",
  "web_content_discovery",
  "vulnerability_scan",
] as const;
export const LOCAL_TOOL_TARGET_KINDS = ["domain", "url", "ip_or_host"] as const;

export type LocalToolArgumentSemantic = (typeof ARGUMENT_SEMANTICS)[number];
export type LocalToolArgumentType = "string" | "integer" | "enum";
export type LocalToolRouteIntent = (typeof LOCAL_TOOL_ROUTE_INTENTS)[number];
export type LocalToolTargetKind = (typeof LOCAL_TOOL_TARGET_KINDS)[number];

export interface LocalToolArgumentDefinition {
  readonly name: string;
  readonly type: LocalToolArgumentType;
  readonly semantic: LocalToolArgumentSemantic;
  readonly required: true;
  readonly minimum: number;
  readonly maximum: number;
  readonly allowedValues: readonly string[];
}

export interface LocalToolArgvTemplateEntry {
  readonly kind: "literal" | "parameter" | "parameter_suffix";
  readonly value: string;
  readonly suffix?: string;
}

export interface LocalToolCapabilityRecord {
  readonly toolId: string;
  readonly label: string;
  readonly activation: "enabled" | "disabled";
  readonly activationReason: string | null;
  readonly executable: Readonly<{
    readonly path: string;
    readonly expectedSha256: string;
    /** File capabilities conflict with the service's NoNewPrivileges boundary. */
    readonly fileCapabilities: "none";
  }>;
  readonly dependencyFiles?: readonly Readonly<{
    readonly path: string;
    readonly expectedSha256: string;
    readonly executable: boolean;
  }>[];
  readonly probe: Readonly<{
    readonly arguments: readonly [string];
    readonly expectedExitCodes: readonly number[];
    readonly timeoutMs: number;
    readonly maximumOutputBytes: number;
    readonly ttlMs: number;
  }>;
  readonly routing: Readonly<{
    readonly intent: LocalToolRouteIntent;
    readonly targetKind: LocalToolTargetKind;
  }>;
  readonly execution: Readonly<{
    readonly transport: "direct_spawn_argv";
    readonly shell: false;
    readonly noNewPrivilegesRequired: true;
    readonly networkPolicy: "authorized_scope_only";
    readonly filesystemWritePolicy: "resolved_workspace_only";
    readonly environmentPolicy: "fixed_minimal";
    readonly logicalWorkspaceParameter: string;
    readonly timeoutMs: number;
    readonly maximumOutputBytes: number;
    readonly terminationGraceMs: number;
  }>;
  readonly stagedInput?: LocalToolStagedInputDefinition;
  readonly parameters: readonly LocalToolArgumentDefinition[];
  readonly argvTemplate: readonly LocalToolArgvTemplateEntry[];
  readonly actionClassIds: readonly ActionClassId[];
  readonly evidenceTypeIds: readonly EvidenceTypeId[];
  readonly riskClassIds: readonly string[];
}

export type LocalToolStagedInputDefinition =
  | Readonly<{ readonly kind: "none" }>
  | Readonly<{
      readonly kind: "fixed_lines";
      readonly mountPath: string;
      readonly lines: readonly string[];
      readonly contentSha256: string;
    }>;

export interface ReviewedLocalToolCapability extends LocalToolCapabilityRecord {
  readonly bindingSha256: string;
}

export interface LocalToolCapabilityManifestDocument {
  readonly schemaVersion: typeof LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION;
  readonly manifestVersion: string;
  readonly specialist: Readonly<{ readonly id: string; readonly label: string }>;
  readonly tools: readonly LocalToolCapabilityRecord[];
}

export interface LocalToolCapabilityManifestDescriptor {
  readonly schemaVersion: typeof LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION;
  readonly manifestVersion: string;
  readonly manifestSha256: string;
  readonly specialistId: string;
  readonly toolCount: number;
  readonly enabledToolCount: number;
  readonly sourceOfTruth: "reviewed-local-tool-capability-manifest";
}

/**
 * A configuration document never makes a tool executable. The runtime must
 * provide a fresh, manifest-bound receipt proving every enforcement boundary.
 */
export interface LocalToolActivationReceipt {
  readonly schemaVersion: typeof LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION;
  readonly manifestSha256: string;
  readonly toolId: string;
  readonly bindingSha256: string;
  /** Exact hash of the bounded startup-probe specification used in this activation wave. */
  readonly preflightBindingSha256: string | null;
  readonly executableSha256: string;
  readonly installationReady: boolean;
  readonly isolatedProbeReady: boolean;
  readonly invocationAdapterReady: boolean;
  readonly workspaceConfinementReady: boolean;
  readonly resultSinkReady: boolean;
  readonly cancellationReady: boolean;
  readonly observedAt: string;
  readonly expiresAt: string;
}

export interface CompiledLocalToolInvocation {
  readonly toolId: string;
  readonly executablePath: string;
  readonly expectedExecutableSha256: string;
  readonly arguments: readonly string[];
  readonly stagedInput: LocalToolStagedInputDefinition;
  readonly logicalWorkspace: string;
  readonly bindingSha256: string;
  readonly shell: false;
  readonly environment: Readonly<{
    readonly HOME: "/nonexistent";
    readonly LANG: "C.UTF-8";
    readonly LC_ALL: "C.UTF-8";
  }>;
  readonly timeoutMs: number;
  readonly maximumOutputBytes: number;
  readonly terminationGraceMs: number;
  readonly scopeEnforcementRequired: true;
  readonly authorizationGranted: false;
}

type JsonRecord = Record<string, unknown>;

function plainRecord(value: unknown, label: string): JsonRecord {
  if (value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype
      && Object.getPrototypeOf(value) !== null)) {
    throw new Error(`${label} must be a plain object`);
  }
  return value as JsonRecord;
}

function exactKeys(value: JsonRecord, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${label} must contain exactly: ${canonical.join(", ")}`);
  }
}

function safeText(value: unknown, label: string, maximum = 240): string {
  if (typeof value !== "string"
    || value !== value.trim()
    || value.length < 1
    || value.length > maximum
    || CONTROL_CHARACTERS.test(value)
    || SECRET_VALUE.test(value)) {
    throw new Error(`${label} must be safe non-secret text`);
  }
  return value;
}

function publicId(value: unknown, label: string): string {
  const parsed = safeText(value, label, 200);
  if (!PUBLIC_ID.test(parsed)) throw new Error(`${label} must be a stable public ID`);
  return parsed;
}

function integer(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function uniqueStrings(
  value: unknown,
  label: string,
  options: Readonly<{ minimum?: number; maximum?: number; ids?: boolean }> = {},
): readonly string[] {
  const minimum = options.minimum ?? 1;
  const maximum = options.maximum ?? 128;
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new Error(`${label} must contain ${minimum} to ${maximum} values`);
  }
  const parsed = value.map((entry, index) => options.ids
    ? publicId(entry, `${label}[${index}]`)
    : safeText(entry, `${label}[${index}]`, 200));
  if (new Set(parsed).size !== parsed.length) throw new Error(`${label} contains duplicates`);
  return Object.freeze(parsed);
}

function parseParameter(value: unknown, toolId: string, index: number): LocalToolArgumentDefinition {
  const label = `Tool ${toolId} parameters[${index}]`;
  const record = plainRecord(value, label);
  exactKeys(record, ["allowedValues", "maximum", "minimum", "name", "required", "semantic", "type"], label);
  const name = safeText(record.name, `${label}.name`, 64);
  if (!PARAMETER_NAME.test(name)) throw new Error(`${label}.name is invalid`);
  const type = record.type;
  if (type !== "string" && type !== "integer" && type !== "enum") {
    throw new Error(`${label}.type is unsupported`);
  }
  const semantic = record.semantic;
  if (typeof semantic !== "string"
    || !(ARGUMENT_SEMANTICS as readonly string[]).includes(semantic)) {
    throw new Error(`${label}.semantic is unsupported`);
  }
  if (record.required !== true) throw new Error(`${label}.required must be true`);
  const expectedType: LocalToolArgumentType = semantic === "tcp_port"
    ? "integer"
    : semantic === "dns_record_type"
      ? "enum"
      : "string";
  if (type !== expectedType) throw new Error(`${label}.type does not match its semantic`);
  const minimum = integer(record.minimum, type === "integer" ? 1 : 1, type === "integer" ? 65_535 : 4_096, `${label}.minimum`);
  const maximum = integer(record.maximum, minimum, type === "integer" ? 65_535 : 4_096, `${label}.maximum`);
  const allowedValues = uniqueStrings(record.allowedValues, `${label}.allowedValues`, {
    minimum: type === "enum" ? 1 : 0,
    maximum: 64,
  });
  if (type !== "enum" && allowedValues.length !== 0) {
    throw new Error(`${label}.allowedValues is permitted only for enum parameters`);
  }
  return Object.freeze({
    name,
    type,
    semantic: semantic as LocalToolArgumentSemantic,
    required: true,
    minimum,
    maximum,
    allowedValues,
  });
}

function parseArgvEntry(value: unknown, toolId: string, index: number): LocalToolArgvTemplateEntry {
  const label = `Tool ${toolId} argvTemplate[${index}]`;
  const record = plainRecord(value, label);
  exactKeys(record, record.kind === "parameter_suffix"
    ? ["kind", "suffix", "value"]
    : ["kind", "value"], label);
  if (record.kind !== "literal" && record.kind !== "parameter" && record.kind !== "parameter_suffix") {
    throw new Error(`${label}.kind is unsupported`);
  }
  const parsed = safeText(record.value, `${label}.value`, 256);
  if ((record.kind === "parameter" || record.kind === "parameter_suffix") && !PARAMETER_NAME.test(parsed)) {
    throw new Error(`${label}.value must identify one declared parameter`);
  }
  if (record.kind === "parameter_suffix") {
    const suffix = safeText(record.suffix, `${label}.suffix`, 32);
    if (suffix !== "FUZZ") throw new Error(`${label}.suffix is not a reviewed suffix`);
    return Object.freeze({ kind: record.kind, value: parsed, suffix });
  }
  return Object.freeze({ kind: record.kind, value: parsed });
}

function parseStagedInput(value: unknown, toolId: string): LocalToolStagedInputDefinition | undefined {
  if (value === undefined) return undefined;
  const label = `Tool ${toolId}.stagedInput`;
  const record = plainRecord(value, label);
  if (record.kind === "none") {
    exactKeys(record, ["kind"], label);
    return Object.freeze({ kind: "none" as const });
  }
  exactKeys(record, ["contentSha256", "kind", "lines", "mountPath"], label);
  if (record.kind !== "fixed_lines") throw new Error(`${label}.kind is unsupported`);
  const mountPath = safeText(record.mountPath, `${label}.mountPath`, 4_096);
  if (!mountPath.startsWith("/run/ti-scale-input/")
    || mountPath === "/run/ti-scale-input/"
    || resolve(mountPath) !== mountPath) {
    throw new Error(`${label}.mountPath must be a normalized file below /run/ti-scale-input`);
  }
  const lines = uniqueStrings(record.lines, `${label}.lines`, { minimum: 1, maximum: 1_024 });
  if (lines.some((line) => line.includes("\n") || line.includes("\r"))) {
    throw new Error(`${label}.lines must contain one bounded value per entry`);
  }
  const bytes = Buffer.from(`${lines.join("\n")}\n`, "utf8");
  if (bytes.length > 64 * 1_024) throw new Error(`${label}.lines exceed the 65536-byte staging limit`);
  if (typeof record.contentSha256 !== "string"
    || !SHA256.test(record.contentSha256)
    || createHash("sha256").update(bytes).digest("hex") !== record.contentSha256) {
    throw new Error(`${label}.contentSha256 does not match the canonical fixed-line content`);
  }
  return Object.freeze({
    kind: "fixed_lines" as const,
    mountPath,
    lines,
    contentSha256: record.contentSha256,
  });
}

function parseDependencyFiles(value: unknown, toolId: string): LocalToolCapabilityRecord["dependencyFiles"] {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) {
    throw new Error(`Tool ${toolId}.dependencyFiles must contain one to 64 reviewed files`);
  }
  const dependencies = value.map((entry, index) => {
    const label = `Tool ${toolId}.dependencyFiles[${index}]`;
    const record = plainRecord(entry, label);
    exactKeys(record, ["executable", "expectedSha256", "path"], label);
    const path = safeText(record.path, `${label}.path`, 4_096);
    if (!isAbsolute(path) || resolve(path) === resolve(sep)) {
      throw new Error(`${label}.path must be a non-root absolute path`);
    }
    if (typeof record.expectedSha256 !== "string" || !SHA256.test(record.expectedSha256)) {
      throw new Error(`${label}.expectedSha256 must be a lowercase SHA-256`);
    }
    if (typeof record.executable !== "boolean") throw new Error(`${label}.executable must be boolean`);
    return Object.freeze({ path, expectedSha256: record.expectedSha256, executable: record.executable });
  });
  if (new Set(dependencies.map(({ path }) => path)).size !== dependencies.length) {
    throw new Error(`Tool ${toolId}.dependencyFiles contains duplicate paths`);
  }
  return Object.freeze(dependencies);
}

function actionClasses(value: unknown, toolId: string): readonly ActionClassId[] {
  const values = uniqueStrings(value, `Tool ${toolId} actionClassIds`, { ids: true });
  for (const item of values) {
    if (!isActionClassId(item)) throw new Error(`Tool ${toolId} has unknown action class ${item}`);
  }
  return values as readonly ActionClassId[];
}

function evidenceTypes(value: unknown, toolId: string): readonly EvidenceTypeId[] {
  const values = uniqueStrings(value, `Tool ${toolId} evidenceTypeIds`, { ids: true });
  for (const item of values) {
    if (!isEvidenceTypeId(item)) throw new Error(`Tool ${toolId} has unknown evidence type ${item}`);
  }
  return values as readonly EvidenceTypeId[];
}

function parseTool(value: unknown, index: number): ReviewedLocalToolCapability {
  const label = `Local tool ${index + 1}`;
  const record = plainRecord(value, label);
  const requiredKeys = [
    "actionClassIds",
    "activation",
    "activationReason",
    "argvTemplate",
    "evidenceTypeIds",
    "executable",
    "execution",
    "label",
    "parameters",
    "probe",
    "riskClassIds",
    "routing",
    "toolId",
  ];
  exactKeys(record, [
    ...requiredKeys,
    ...(record.stagedInput === undefined ? [] : ["stagedInput"]),
    ...(record.dependencyFiles === undefined ? [] : ["dependencyFiles"]),
  ], label);
  const toolId = publicId(record.toolId, `${label}.toolId`);
  const displayName = safeText(record.label, `${label}.label`);
  if (record.activation !== "enabled" && record.activation !== "disabled") {
    throw new Error(`Tool ${toolId}.activation is unsupported`);
  }
  const activationReason = record.activationReason;
  if ((record.activation === "enabled" && activationReason !== null)
    || (record.activation === "disabled"
      && (typeof activationReason !== "string" || !activationReason.trim()))) {
    throw new Error(`Tool ${toolId}.activationReason must explain only a disabled binding`);
  }
  const safeActivationReason = activationReason === null
    ? null
    : safeText(activationReason, `Tool ${toolId}.activationReason`, 500);

  const executable = plainRecord(record.executable, `Tool ${toolId}.executable`);
  exactKeys(executable, ["expectedSha256", "fileCapabilities", "path"], `Tool ${toolId}.executable`);
  const executablePath = safeText(executable.path, `Tool ${toolId}.executable.path`, 4_096);
  if (!isAbsolute(executablePath) || executablePath === resolve(sep)) {
    throw new Error(`Tool ${toolId}.executable.path must be an absolute file path`);
  }
  if (typeof executable.expectedSha256 !== "string" || !SHA256.test(executable.expectedSha256)) {
    throw new Error(`Tool ${toolId}.executable.expectedSha256 must be a lowercase SHA-256`);
  }
  if (executable.fileCapabilities !== "none") {
    throw new Error(`Tool ${toolId} must not depend on Linux file capabilities`);
  }

  const probe = plainRecord(record.probe, `Tool ${toolId}.probe`);
  exactKeys(probe, ["arguments", "expectedExitCodes", "maximumOutputBytes", "timeoutMs", "ttlMs"], `Tool ${toolId}.probe`);
  if (!Array.isArray(probe.arguments)
    || probe.arguments.length !== 1
    || typeof probe.arguments[0] !== "string"
    || !SAFE_PROBE_ARGUMENTS.has(probe.arguments[0])) {
    throw new Error(`Tool ${toolId}.probe.arguments requires one reviewed version/help argument`);
  }
  const expectedExitCodes = uniqueStrings(
    Array.isArray(probe.expectedExitCodes) ? probe.expectedExitCodes.map(String) : probe.expectedExitCodes,
    `Tool ${toolId}.probe.expectedExitCodes`,
    { minimum: 1, maximum: 8 },
  ).map((code, exitIndex) => integer(Number(code), 0, 255, `Tool ${toolId}.probe.expectedExitCodes[${exitIndex}]`));

  const routing = plainRecord(record.routing, `Tool ${toolId}.routing`);
  exactKeys(routing, ["intent", "targetKind"], `Tool ${toolId}.routing`);
  if (typeof routing.intent !== "string"
    || !(LOCAL_TOOL_ROUTE_INTENTS as readonly string[]).includes(routing.intent)) {
    throw new Error(`Tool ${toolId}.routing.intent is unsupported`);
  }
  if (typeof routing.targetKind !== "string"
    || !(LOCAL_TOOL_TARGET_KINDS as readonly string[]).includes(routing.targetKind)) {
    throw new Error(`Tool ${toolId}.routing.targetKind is unsupported`);
  }

  const execution = plainRecord(record.execution, `Tool ${toolId}.execution`);
  exactKeys(execution, [
    "environmentPolicy",
    "filesystemWritePolicy",
    "logicalWorkspaceParameter",
    "maximumOutputBytes",
    "networkPolicy",
    "noNewPrivilegesRequired",
    "shell",
    "terminationGraceMs",
    "timeoutMs",
    "transport",
  ], `Tool ${toolId}.execution`);
  if (execution.transport !== "direct_spawn_argv"
    || execution.shell !== false
    || execution.noNewPrivilegesRequired !== true
    || execution.networkPolicy !== "authorized_scope_only"
    || execution.filesystemWritePolicy !== "resolved_workspace_only"
    || execution.environmentPolicy !== "fixed_minimal") {
    throw new Error(`Tool ${toolId}.execution does not satisfy the reviewed local boundary`);
  }
  const logicalWorkspaceParameter = safeText(
    execution.logicalWorkspaceParameter,
    `Tool ${toolId}.execution.logicalWorkspaceParameter`,
    64,
  );
  if (!PARAMETER_NAME.test(logicalWorkspaceParameter)) {
    throw new Error(`Tool ${toolId}.execution.logicalWorkspaceParameter is invalid`);
  }

  if (!Array.isArray(record.parameters) || record.parameters.length < 2 || record.parameters.length > 32) {
    throw new Error(`Tool ${toolId}.parameters must contain two to 32 definitions`);
  }
  const parameters = record.parameters.map((entry, parameterIndex) =>
    parseParameter(entry, toolId, parameterIndex));
  if (new Set(parameters.map(({ name }) => name)).size !== parameters.length) {
    throw new Error(`Tool ${toolId}.parameters contains duplicate names`);
  }
  const workspace = parameters.find(({ name }) => name === logicalWorkspaceParameter);
  if (workspace?.semantic !== "logical_workspace") {
    throw new Error(`Tool ${toolId} requires one matching logical workspace parameter`);
  }
  if (parameters.filter(({ semantic }) => semantic === "logical_workspace").length !== 1) {
    throw new Error(`Tool ${toolId} must declare exactly one logical workspace parameter`);
  }
  if (!parameters.some(({ semantic }) => semantic.startsWith("authorized_"))) {
    throw new Error(`Tool ${toolId} must declare an explicit authorized target parameter`);
  }

  if (!Array.isArray(record.argvTemplate)
    || record.argvTemplate.length < 1
    || record.argvTemplate.length > 128) {
    throw new Error(`Tool ${toolId}.argvTemplate must contain one to 128 entries`);
  }
  const argvTemplate = record.argvTemplate.map((entry, argvIndex) =>
    parseArgvEntry(entry, toolId, argvIndex));
  const referenced = argvTemplate
    .filter(({ kind }) => kind === "parameter" || kind === "parameter_suffix")
    .map(({ value: name }) => name);
  if (referenced.includes(logicalWorkspaceParameter)) {
    throw new Error(`Tool ${toolId} must use its logical workspace only as a resolved working directory`);
  }
  const argvParameters = parameters
    .filter(({ name }) => name !== logicalWorkspaceParameter)
    .map(({ name }) => name)
    .sort();
  if (new Set(referenced).size !== referenced.length
    || [...referenced].sort().join("\u0000") !== argvParameters.join("\u0000")) {
    throw new Error(`Tool ${toolId}.argvTemplate must reference every non-workspace parameter exactly once`);
  }

  const stagedInput = parseStagedInput(record.stagedInput, toolId);
  const dependencyFiles = parseDependencyFiles(record.dependencyFiles, toolId);
  const parsed: LocalToolCapabilityRecord = Object.freeze({
    toolId,
    label: displayName,
    activation: record.activation,
    activationReason: safeActivationReason,
    executable: Object.freeze({
      path: executablePath,
      expectedSha256: executable.expectedSha256,
      fileCapabilities: "none",
    }),
    ...(dependencyFiles ? { dependencyFiles } : {}),
    probe: Object.freeze({
      arguments: Object.freeze([probe.arguments[0]]) as readonly [string],
      expectedExitCodes: Object.freeze(expectedExitCodes),
      timeoutMs: integer(probe.timeoutMs, 100, 5_000, `Tool ${toolId}.probe.timeoutMs`),
      maximumOutputBytes: integer(probe.maximumOutputBytes, 128, 32 * 1_024, `Tool ${toolId}.probe.maximumOutputBytes`),
      ttlMs: integer(probe.ttlMs, 1_000, 5 * 60_000, `Tool ${toolId}.probe.ttlMs`),
    }),
    routing: Object.freeze({
      intent: routing.intent as LocalToolRouteIntent,
      targetKind: routing.targetKind as LocalToolTargetKind,
    }),
    execution: Object.freeze({
      transport: "direct_spawn_argv",
      shell: false,
      noNewPrivilegesRequired: true,
      networkPolicy: "authorized_scope_only",
      filesystemWritePolicy: "resolved_workspace_only",
      environmentPolicy: "fixed_minimal",
      logicalWorkspaceParameter,
      timeoutMs: integer(execution.timeoutMs, 1_000, 15 * 60_000, `Tool ${toolId}.execution.timeoutMs`),
      maximumOutputBytes: integer(execution.maximumOutputBytes, 1_024, 16 * 1_024 * 1_024, `Tool ${toolId}.execution.maximumOutputBytes`),
      terminationGraceMs: integer(execution.terminationGraceMs, 100, 5_000, `Tool ${toolId}.execution.terminationGraceMs`),
    }),
    ...(stagedInput ? { stagedInput } : {}),
    parameters: Object.freeze(parameters),
    argvTemplate: Object.freeze(argvTemplate),
    actionClassIds: actionClasses(record.actionClassIds, toolId),
    evidenceTypeIds: evidenceTypes(record.evidenceTypeIds, toolId),
    riskClassIds: uniqueStrings(record.riskClassIds, `Tool ${toolId} riskClassIds`, { ids: true }),
  });
  const bindingSha256 = digestCanonicalJson(parsed, { maxBytes: 128 * 1_024, maxDepth: 16 }).sha256;
  return Object.freeze({ ...parsed, bindingSha256 });
}

function parseDocument(input: unknown): Readonly<{
  manifestVersion: string;
  specialist: Readonly<{ readonly id: string; readonly label: string }>;
  tools: readonly ReviewedLocalToolCapability[];
  manifestSha256: string;
}> {
  const record = plainRecord(input, "Local tool capability manifest");
  exactKeys(record, ["manifestVersion", "schemaVersion", "specialist", "tools"], "Local tool capability manifest");
  if (record.schemaVersion !== LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION) {
    throw new Error(`Unsupported local tool capability schema: ${String(record.schemaVersion)}`);
  }
  const manifestVersion = safeText(record.manifestVersion, "Local tool capability manifestVersion", 80);
  if (!VERSION.test(manifestVersion)) throw new Error("Local tool capability manifestVersion is invalid");
  const specialistRecord = plainRecord(record.specialist, "Local tool capability specialist");
  exactKeys(specialistRecord, ["id", "label"], "Local tool capability specialist");
  const specialist = Object.freeze({
    id: publicId(specialistRecord.id, "Local tool capability specialist.id"),
    label: safeText(specialistRecord.label, "Local tool capability specialist.label"),
  });
  if (!Array.isArray(record.tools) || record.tools.length < 1 || record.tools.length > 128) {
    throw new Error("Local tool capability manifest requires one to 128 tools");
  }
  const tools = record.tools.map(parseTool).sort((left, right) => left.toolId.localeCompare(right.toolId));
  if (new Set(tools.map(({ toolId }) => toolId)).size !== tools.length) {
    throw new Error("Local tool capability manifest contains duplicate tool IDs");
  }
  const enabledRoutes = tools
    .filter(({ activation }) => activation === "enabled")
    .map(({ routing }) => `${routing.intent}/${routing.targetKind}`);
  if (new Set(enabledRoutes).size !== enabledRoutes.length) {
    throw new Error("Local tool capability manifest contains an ambiguous enabled route");
  }
  const canonical = {
    schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    manifestVersion,
    specialist,
    tools: tools.map(({ bindingSha256: _bindingSha256, ...tool }) => tool),
  };
  return Object.freeze({
    manifestVersion,
    specialist,
    tools: Object.freeze(tools),
    manifestSha256: digestCanonicalJson(canonical, { maxBytes: 2 * 1_024 * 1_024, maxDepth: 32 }).sha256,
  });
}

/** Strict plain-document parser used by the trusted JSON loader. */
export function parseLocalToolCapabilityManifestDocument(
  input: unknown,
): LocalToolCapabilityManifestDocument {
  const parsed = parseDocument(input);
  return deepFreeze({
    schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
    manifestVersion: parsed.manifestVersion,
    specialist: parsed.specialist,
    tools: parsed.tools.map(({ bindingSha256: _bindingSha256, ...tool }) => tool),
  });
}

function validTimestamp(value: string): number | null {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function activationReady(
  manifestSha256: string,
  tool: ReviewedLocalToolCapability,
  receipt: LocalToolActivationReceipt | undefined,
  now: Date,
): boolean {
  if (!receipt || receipt.schemaVersion !== LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION) return false;
  const observedAt = validTimestamp(receipt.observedAt);
  const expiresAt = validTimestamp(receipt.expiresAt);
  return tool.activation === "enabled"
    && receipt.manifestSha256 === manifestSha256
    && receipt.toolId === tool.toolId
    && receipt.bindingSha256 === tool.bindingSha256
    && typeof receipt.preflightBindingSha256 === "string"
    && /^[a-f0-9]{64}$/u.test(receipt.preflightBindingSha256)
    && receipt.executableSha256 === tool.executable.expectedSha256
    && observedAt !== null
    && observedAt <= now.getTime()
    && expiresAt !== null
    && expiresAt > now.getTime()
    && expiresAt > observedAt
    && receipt.installationReady
    && receipt.isolatedProbeReady
    && receipt.invocationAdapterReady
    && receipt.workspaceConfinementReady
    && receipt.resultSinkReady
    && receipt.cancellationReady;
}

function evidenceLabel(id: EvidenceTypeId): string {
  return EVIDENCE_TYPE_DEFINITIONS.find((item) => item.id === id)?.label ?? id;
}

function mergeUnique<T extends { readonly id: string }>(
  kind: string,
  left: readonly T[],
  right: readonly T[],
): readonly T[] {
  const result = new Map(left.map((record) => [record.id, record]));
  for (const record of right) {
    const existing = result.get(record.id);
    if (existing !== undefined) {
      const leftHash = digestCanonicalJson(existing, { maxBytes: 512 * 1_024, maxDepth: 32 }).sha256;
      const rightHash = digestCanonicalJson(record, { maxBytes: 512 * 1_024, maxDepth: 32 }).sha256;
      if (leftHash !== rightHash) throw new Error(`Local tool composition conflicts with ${kind} ${record.id}`);
    } else {
      result.set(record.id, record);
    }
  }
  return Object.freeze([...result.values()]);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

function validateParameter(definition: LocalToolArgumentDefinition, value: unknown): string {
  if (definition.type === "integer") {
    if (!Number.isSafeInteger(value)
      || (value as number) < definition.minimum
      || (value as number) > definition.maximum) {
      throw new Error(`${definition.name} must be an integer between ${definition.minimum} and ${definition.maximum}`);
    }
    return String(value);
  }
  if (typeof value !== "string"
    || value !== value.trim()
    || value.length < definition.minimum
    || value.length > definition.maximum
    || CONTROL_CHARACTERS.test(value)
    || SECRET_VALUE.test(value)) {
    throw new Error(`${definition.name} does not satisfy its reviewed string boundary`);
  }
  if (definition.type === "enum") {
    if (!definition.allowedValues.includes(value)) throw new Error(`${definition.name} is not an allowed value`);
    return value;
  }
  if (definition.semantic === "logical_workspace") {
    const normalized = resolve(value);
    if (!isAbsolute(value) || normalized !== value || normalized === resolve(sep)) {
      throw new Error(`${definition.name} must be one normalized absolute logical workspace`);
    }
  } else if (definition.semantic === "authorized_http_url"
    || definition.semantic === "authorized_canonical_http_url"
    || definition.semantic === "authorized_http_base_url") {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new Error(`${definition.name} must be an absolute HTTP or HTTPS URL`);
    }
    if (!['http:', 'https:'].includes(url.protocol)
      || url.username !== ""
      || url.password !== ""
      || !url.hostname) {
      throw new Error(`${definition.name} must be an HTTP/S URL without embedded credentials`);
    }
    if ((definition.semantic === "authorized_canonical_http_url"
      || definition.semantic === "authorized_http_base_url")
      && (url.href !== value || url.search !== "" || url.hash !== "")) {
      throw new Error(`${definition.name} must be one canonical HTTP/S URL without query text or a fragment`);
    }
    if (definition.semantic === "authorized_http_base_url" && !url.pathname.endsWith("/")) {
      throw new Error(`${definition.name} must be a canonical HTTP/S base URL ending in '/'`);
    }
  } else if (definition.semantic === "authorized_dns_name") {
    const name = value.endsWith(".") ? value.slice(0, -1) : value;
    const labels = name.split(".");
    if (name.length > 253
      || labels.some((part) => !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(part))) {
      throw new Error(`${definition.name} must be a normalized DNS name`);
    }
  } else if (definition.semantic === "authorized_target") {
    if (value.startsWith("-") || !/^[A-Za-z0-9._:/\[\]-]+$/u.test(value)) {
      throw new Error(`${definition.name} must be one normalized target token`);
    }
  } else if (definition.semantic === "authorized_single_host") {
    const labels = value.split(".");
    const normalizedDnsName = value.length <= 253
      && labels.every((part) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(part));
    const nmapNumericRangeLabel = labels.some((part) => /^\d{1,5}-\d{1,5}$/u.test(part));
    if (value.startsWith("-")
      || nmapNumericRangeLabel
      || (isIP(value) === 0 && !normalizedDnsName)) {
      throw new Error(`${definition.name} must be one normalized IP address or hostname without a range, CIDR, scheme, or port`);
    }
  } else if (definition.semantic === "tcp_port_set") {
    if (!/^[1-9][0-9]{0,4}(?:,[1-9][0-9]{0,4})*$/u.test(value)) {
      throw new Error(`${definition.name} must contain only comma-separated individual TCP ports; ranges and option syntax are not allowed`);
    }
    const ports = value.split(",").map(Number);
    if (ports.length > MAX_REVIEWED_TCP_PORT_SET_SIZE) {
      throw new Error(`${definition.name} may contain at most ${MAX_REVIEWED_TCP_PORT_SET_SIZE} TCP ports`);
    }
    if (ports.some((port) => !Number.isSafeInteger(port) || port < 1 || port > 65_535)) {
      throw new Error(`${definition.name} contains a TCP port outside 1-65535`);
    }
    const canonical = [...new Set(ports)].sort((left, right) => left - right).join(",");
    if (canonical !== value) {
      throw new Error(`${definition.name} must be unique and in canonical ascending order without leading zeros`);
    }
  }
  return value;
}

export class LocalToolCapabilityManifest {
  private readonly records: ReadonlyMap<string, ReviewedLocalToolCapability>;
  private readonly tools: readonly ReviewedLocalToolCapability[];
  readonly descriptor: LocalToolCapabilityManifestDescriptor;
  readonly specialist: Readonly<{ readonly id: string; readonly label: string }>;

  constructor(input: unknown) {
    const parsed = parseDocument(input);
    this.records = new Map(parsed.tools.map((tool) => [tool.toolId, tool]));
    this.tools = parsed.tools;
    this.specialist = parsed.specialist;
    this.descriptor = Object.freeze({
      schemaVersion: LOCAL_TOOL_CAPABILITY_MANIFEST_SCHEMA_VERSION,
      manifestVersion: parsed.manifestVersion,
      manifestSha256: parsed.manifestSha256,
      specialistId: parsed.specialist.id,
      toolCount: parsed.tools.length,
      enabledToolCount: parsed.tools.filter(({ activation }) => activation === "enabled").length,
      sourceOfTruth: "reviewed-local-tool-capability-manifest",
    });
  }

  list(): readonly ReviewedLocalToolCapability[] {
    return this.tools;
  }

  resolve(toolId: string): ReviewedLocalToolCapability | undefined {
    return this.records.get(toolId);
  }

  resolveRoute(
    intent: LocalToolRouteIntent,
    targetKind: LocalToolTargetKind,
  ): ReviewedLocalToolCapability | undefined {
    return this.tools.find((tool) => tool.activation === "enabled"
      && tool.routing.intent === intent
      && tool.routing.targetKind === targetKind);
  }

  toToolBindingRegistryDocument(): ToolBindingRegistryDocument {
    return deepFreeze({
      schemaVersion: TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
      registryVersion: this.descriptor.manifestVersion,
      bindings: this.tools
        .filter(({ activation }) => activation === "enabled")
        .map((tool) => ({
          toolId: tool.toolId,
          executablePath: tool.executable.path,
          probeArguments: tool.probe.arguments,
          expectedExitCodes: tool.probe.expectedExitCodes,
          timeoutMs: tool.probe.timeoutMs,
          maximumOutputBytes: tool.probe.maximumOutputBytes,
          ttlMs: tool.probe.ttlMs,
        })),
    });
  }

  compileInvocation(
    toolId: string,
    input: Readonly<Record<string, unknown>>,
  ): CompiledLocalToolInvocation {
    const tool = this.resolve(toolId);
    if (!tool) throw new Error(`Unknown reviewed local tool ${toolId}`);
    if (tool.activation !== "enabled") throw new Error(`Local tool ${toolId} is operator-disabled`);
    const expectedKeys = tool.parameters.map(({ name }) => name).sort();
    const actualKeys = Object.keys(input).sort();
    if (actualKeys.length !== expectedKeys.length
      || actualKeys.some((key, index) => key !== expectedKeys[index])) {
      throw new Error(`Local tool ${toolId} arguments must contain exactly: ${expectedKeys.join(", ")}`);
    }
    const normalized = new Map(tool.parameters.map((definition) => [
      definition.name,
      validateParameter(definition, input[definition.name]),
    ]));
    const logicalWorkspace = normalized.get(tool.execution.logicalWorkspaceParameter)!;
    const args = tool.argvTemplate.map((entry) => entry.kind === "literal"
      ? entry.value
      : entry.kind === "parameter_suffix"
        ? `${normalized.get(entry.value)!}${entry.suffix!}`
        : normalized.get(entry.value)!);
    return deepFreeze({
      toolId,
      executablePath: tool.executable.path,
      expectedExecutableSha256: tool.executable.expectedSha256,
      arguments: args,
      stagedInput: tool.stagedInput ?? { kind: "none" },
      logicalWorkspace,
      bindingSha256: tool.bindingSha256,
      shell: false,
      environment: {
        HOME: "/nonexistent",
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
      },
      timeoutMs: tool.execution.timeoutMs,
      maximumOutputBytes: tool.execution.maximumOutputBytes,
      terminationGraceMs: tool.execution.terminationGraceMs,
      scopeEnforcementRequired: true,
      authorizationGranted: false,
    });
  }

  toRuntimeSourceManifests(
    receipts: readonly LocalToolActivationReceipt[] = [],
    now: Date = new Date(),
  ): RuntimeSourceManifests {
    const receiptsByTool = new Map(receipts.map((receipt) => [receipt.toolId, receipt]));
    const available = new Map(this.tools.map((tool) => [
      tool.toolId,
      activationReady(this.descriptor.manifestSha256, tool, receiptsByTool.get(tool.toolId), now),
    ]));
    const riskIds = [...new Set(this.tools.flatMap(({ riskClassIds }) => riskClassIds))].sort();
    const evidenceIds = [...new Set(this.tools.flatMap(({ evidenceTypeIds }) => evidenceTypeIds))].sort() as EvidenceTypeId[];
    const capabilities = this.tools.map((tool) => ({
      id: `capability:${tool.toolId}`,
      label: `${tool.label} capability`,
      actionClassIds: tool.actionClassIds,
      evidenceTypeIds: tool.evidenceTypeIds,
    }));
    const manifests: RuntimeSourceManifests = deepFreeze({
      riskClasses: riskIds.map((id) => ({
        id,
        label: id === "ti-scale:read-only" ? "Read-only" : "Authorized network interaction",
        actionClassIds: [...new Set(this.tools
          .filter(({ riskClassIds }) => riskClassIds.includes(id))
          .flatMap(({ actionClassIds }) => actionClassIds))],
      })),
      evidenceKinds: evidenceIds.map((id) => ({
        id: `local-evidence:${id}`,
        label: evidenceLabel(id),
        evidenceTypeIds: [id],
      })),
      capabilities,
      tools: this.tools.map((tool) => {
        const receipt = receiptsByTool.get(tool.toolId);
        const observedAt = receipt ? validTimestamp(receipt.observedAt) : null;
        const expiresAt = receipt ? validTimestamp(receipt.expiresAt) : null;
        const receiptBoundToTool = receipt !== undefined
          && receipt.schemaVersion === LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION
          && receipt.manifestSha256 === this.descriptor.manifestSha256
          && receipt.toolId === tool.toolId
          && receipt.bindingSha256 === tool.bindingSha256
          && typeof receipt.preflightBindingSha256 === "string"
          && /^[a-f0-9]{64}$/u.test(receipt.preflightBindingSha256)
          && receipt.executableSha256 === tool.executable.expectedSha256
          && observedAt !== null
          && expiresAt !== null
          && expiresAt > observedAt;
        const attestation = receiptBoundToTool ? {
          schemaVersion: LOCAL_TOOL_ACTIVATION_RECEIPT_SCHEMA_VERSION,
          source: "local_guided_tool_activation" as const,
          manifestSha256: receipt.manifestSha256,
          toolBindingSha256: receipt.bindingSha256,
          preflightBindingSha256: receipt.preflightBindingSha256,
          executableSha256: receipt.executableSha256,
          observedAt: receipt.observedAt,
          expiresAt: receipt.expiresAt,
        } : undefined;
        const dependency = (id: string, ready: boolean) => ({
          id,
          ready,
          ...(attestation ? { attestation } : {}),
        });
        return {
          id: tool.toolId,
          label: tool.label,
          available: available.get(tool.toolId) === true,
          locallyPolicyEnforced: true,
          requiresModel: false,
          // This manifest powers exact represented Guided decisions. A
          // separate Autonomous composition must explicitly promote one
          // reviewed binding after its provider/specialist receipts pass.
          executionJourneys: ["guided"] as const,
          actionClassIds: tool.actionClassIds,
          evidenceTypeIds: tool.evidenceTypeIds,
          riskClassIds: tool.riskClassIds,
          dependencies: [
            dependency("operator-activation", tool.activation === "enabled"),
            dependency("executable-integrity", receipt?.installationReady === true),
            dependency("isolated-target-free-readiness", receipt?.isolatedProbeReady === true),
            dependency("direct-argv-adapter", receipt?.invocationAdapterReady === true),
            dependency("workspace-confinement", receipt?.workspaceConfinementReady === true),
            dependency("result-sink", receipt?.resultSinkReady === true),
            dependency("cancellation", receipt?.cancellationReady === true),
          ],
        };
      }),
      mcpServers: [],
      agents: [{
        id: this.specialist.id,
        label: this.specialist.label,
        available: [...available.values()].some(Boolean),
        capabilityIds: capabilities.map(({ id }) => id),
        actionClassIds: [...new Set(this.tools.flatMap(({ actionClassIds }) => actionClassIds))],
        toolIds: this.tools.map(({ toolId }) => toolId),
        modelRefs: [],
      }],
      providers: [],
    });
    buildRuntimeCapabilityProjection(manifests);
    return manifests;
  }

  composeRuntimeSourceManifests(
    base: RuntimeSourceManifests,
    receipts: readonly LocalToolActivationReceipt[] = [],
    now: Date = new Date(),
  ): RuntimeSourceManifests {
    buildRuntimeCapabilityProjection(base);
    const local = this.toRuntimeSourceManifests(receipts, now);
    const composed: RuntimeSourceManifests = deepFreeze({
      riskClasses: mergeUnique("risk class", base.riskClasses, local.riskClasses),
      evidenceKinds: mergeUnique("evidence kind", base.evidenceKinds, local.evidenceKinds),
      capabilities: mergeUnique("capability", base.capabilities, local.capabilities),
      tools: mergeUnique("tool", base.tools, local.tools),
      mcpServers: mergeUnique("MCP server", base.mcpServers, local.mcpServers),
      agents: mergeUnique("agent", base.agents, local.agents),
      providers: mergeUnique("provider", base.providers, local.providers),
    });
    buildRuntimeCapabilityProjection(composed);
    return composed;
  }
}

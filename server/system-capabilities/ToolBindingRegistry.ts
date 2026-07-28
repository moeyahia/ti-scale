import { isAbsolute } from "node:path";
import {
  buildRuntimeCapabilityProjection,
  type RuntimeSourceManifests,
  type RuntimeToolManifest,
} from "../domain";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import type { ToolExecutionPreflightSpec } from "./ToolExecutionPreflight";

export const TOOL_BINDING_REGISTRY_SCHEMA_VERSION =
  "ti-scale.tool-binding-registry.v1" as const;

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const SECRET_SHAPED_ID = /(?:^|[-_.:/])(?:api[-_]?key|authorization|cookie|credential|pass(?:word)?|private[-_]?key|secret|session[-_]?token|token)(?:[-_.:/]|$)|(?:sk|rk|pk)-[A-Za-z0-9_-]{8,}|-----BEGIN/iu;
const REGISTRY_VERSION = /^[A-Za-z0-9._-]{1,80}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const SECRET_VALUE = /(?:\bBearer\s+\S+|(?:sk|rk|pk)-[A-Za-z0-9_-]{8,}|-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----|(?:api[-_]?key|authorization|cookie|password|private[-_]?key|secret|session[-_]?token)\s*[:=]\s*\S+)/iu;
const REVIEWED_PROBE_ARGUMENTS = new Set([
  "--version",
  "-V",
  "-VV",
  "version",
  "-version",
  "--help",
  "-h",
]);
const DOCUMENT_KEYS = ["bindings", "registryVersion", "schemaVersion"] as const;
const BINDING_KEYS = [
  "executablePath",
  "expectedExitCodes",
  "maximumOutputBytes",
  "probeArguments",
  "timeoutMs",
  "toolId",
  "ttlMs",
] as const;

export interface ToolBindingRegistryDocument {
  readonly schemaVersion: typeof TOOL_BINDING_REGISTRY_SCHEMA_VERSION;
  readonly registryVersion: string;
  readonly bindings: readonly ToolBindingRegistryRecord[];
}

/**
 * Fully resolved startup probe. Optional fields are deliberately absent so a
 * reviewed registry cannot change behavior through implicit defaults.
 */
export interface ToolBindingRegistryRecord {
  readonly toolId: string;
  readonly executablePath: string;
  readonly probeArguments: readonly [string];
  readonly expectedExitCodes: readonly number[];
  readonly timeoutMs: number;
  readonly maximumOutputBytes: number;
  readonly ttlMs: number;
}

export interface ReviewedLocalToolBinding extends ToolBindingRegistryRecord {
  readonly displayName: string;
  readonly bindingSha256: string;
}

export interface ToolBindingRegistryDescriptor {
  readonly schemaVersion: typeof TOOL_BINDING_REGISTRY_SCHEMA_VERSION;
  readonly registryVersion: string;
  readonly registrySha256: string;
  /** Digest of the local-tool subset only; remote inventories have independent attestations. */
  readonly runtimeManifestSha256: string;
  readonly registeredBindingCount: number;
  readonly runtimeToolCount: number;
  readonly boundRuntimeToolCount: number;
  /** Runtime tools may be remote/MCP-backed; absence here does not imply a missing local binding. */
  readonly runtimeToolsWithoutLocalBinding: number;
  readonly sourceOfTruth: "runtime-manifest-aligned-local-bindings";
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null);
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length
    || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${label} must contain exactly: ${canonical.join(", ")}`);
  }
}

function integerWithin(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function validateExpectedExitCodes(value: unknown, toolId: string): readonly number[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 8) {
    throw new Error(`Tool binding ${toolId} expectedExitCodes must contain one to eight values`);
  }
  const codes = value.map((entry, index) =>
    integerWithin(entry, 0, 255, `Tool binding ${toolId} expectedExitCodes[${index}]`));
  if (new Set(codes).size !== codes.length) {
    throw new Error(`Tool binding ${toolId} expectedExitCodes contains duplicates`);
  }
  return Object.freeze(codes);
}

function safeRuntimeLabel(tool: RuntimeToolManifest): string {
  const label = tool.label.trim();
  if (!label || label.length > 200 || CONTROL_CHARACTERS.test(label) || SECRET_VALUE.test(label)) {
    throw new Error(`Runtime tool ${tool.id} does not have a safe public display label`);
  }
  return label;
}

function parseBinding(
  value: unknown,
  index: number,
  runtimeTools: ReadonlyMap<string, RuntimeToolManifest>,
): ReviewedLocalToolBinding {
  if (!plainRecord(value)) throw new Error(`Tool binding ${index + 1} must be a plain object`);
  assertExactKeys(value, BINDING_KEYS, `Tool binding ${index + 1}`);

  const toolId = value.toolId;
  if (typeof toolId !== "string"
    || toolId !== toolId.trim()
    || !PUBLIC_ID.test(toolId)
    || SECRET_SHAPED_ID.test(toolId)) {
    throw new Error(`Tool binding ${index + 1} requires a stable public runtime tool ID`);
  }
  const runtimeTool = runtimeTools.get(toolId);
  if (!runtimeTool) {
    throw new Error(`Tool binding ${toolId} is not present in the current runtime tool manifest`);
  }
  if (runtimeTool.mcpServerId !== undefined) {
    throw new Error(`Tool binding ${toolId} is remote/MCP-backed and cannot be probed as a local executable`);
  }
  const executablePath = value.executablePath;
  if (typeof executablePath !== "string"
    || executablePath.length > 4_096
    || !isAbsolute(executablePath)
    || CONTROL_CHARACTERS.test(executablePath)) {
    throw new Error(`Tool binding ${toolId} executablePath must be an absolute non-control path`);
  }
  if (!Array.isArray(value.probeArguments)
    || value.probeArguments.length !== 1
    || typeof value.probeArguments[0] !== "string"
    || !REVIEWED_PROBE_ARGUMENTS.has(value.probeArguments[0])) {
    throw new Error(`Tool binding ${toolId} requires exactly one reviewed version/help argument`);
  }

  const record = {
    toolId,
    displayName: safeRuntimeLabel(runtimeTool),
    executablePath,
    probeArguments: Object.freeze([value.probeArguments[0]]) as readonly [string],
    expectedExitCodes: validateExpectedExitCodes(value.expectedExitCodes, toolId),
    // Registry limits are intentionally narrower than the reusable preflight boundary.
    timeoutMs: integerWithin(value.timeoutMs, 100, 5_000, `Tool binding ${toolId} timeoutMs`),
    maximumOutputBytes: integerWithin(
      value.maximumOutputBytes,
      128,
      32 * 1_024,
      `Tool binding ${toolId} maximumOutputBytes`,
    ),
    ttlMs: integerWithin(value.ttlMs, 1_000, 5 * 60_000, `Tool binding ${toolId} ttlMs`),
  };
  const bindingSha256 = digestCanonicalJson(record, {
    maxBytes: 16 * 1_024,
    maxDepth: 8,
  }).sha256;
  return Object.freeze({ ...record, bindingSha256 });
}

export function runtimeLocalToolManifestSha256(manifests: RuntimeSourceManifests): string {
  return digestCanonicalJson({
    tools: [...manifests.tools]
      .filter(({ mcpServerId }) => mcpServerId === undefined)
      .map((tool) => ({
        id: tool.id,
        label: tool.label,
        available: tool.available,
        locallyPolicyEnforced: tool.locallyPolicyEnforced,
        requiresModel: tool.requiresModel ?? null,
        actionClassIds: [...tool.actionClassIds].sort(),
        evidenceTypeIds: [...tool.evidenceTypeIds].sort(),
        riskClassIds: [...tool.riskClassIds].sort(),
        mcpServerId: tool.mcpServerId ?? null,
        dependencies: [...(tool.dependencies ?? [])]
          .map((dependency) => ({ id: dependency.id, ready: dependency.ready }))
          .sort((left, right) => left.id.localeCompare(right.id)),
      }))
      .sort((left, right) => left.id.localeCompare(right.id)),
  }, { maxBytes: 512 * 1_024, maxDepth: 16 }).sha256;
}

function parseDocument(
  input: unknown,
  manifests: RuntimeSourceManifests,
): Readonly<{
  registryVersion: string;
  registrySha256: string;
  bindings: readonly ReviewedLocalToolBinding[];
}> {
  // Reuse the canonical domain validation before accepting any binding ID.
  buildRuntimeCapabilityProjection(manifests);
  if (!plainRecord(input)) throw new Error("Tool binding registry must be a plain object");
  assertExactKeys(input, DOCUMENT_KEYS, "Tool binding registry");
  if (input.schemaVersion !== TOOL_BINDING_REGISTRY_SCHEMA_VERSION) {
    throw new Error(`Unsupported tool binding registry schema: ${String(input.schemaVersion)}`);
  }
  if (typeof input.registryVersion !== "string"
    || input.registryVersion !== input.registryVersion.trim()
    || !REGISTRY_VERSION.test(input.registryVersion)) {
    throw new Error("Tool binding registry requires a stable version");
  }
  if (!Array.isArray(input.bindings) || input.bindings.length > 512) {
    throw new Error("Tool binding registry bindings must be an array of at most 512 entries");
  }
  const runtimeTools = new Map(manifests.tools.map((tool) => [tool.id, tool]));
  const bindings = input.bindings.map((entry, index) => parseBinding(entry, index, runtimeTools));
  const seen = new Set<string>();
  for (const binding of bindings) {
    if (seen.has(binding.toolId)) {
      throw new Error(`Tool binding registry contains duplicate tool ID ${binding.toolId}`);
    }
    seen.add(binding.toolId);
  }
  bindings.sort((left, right) => left.toolId.localeCompare(right.toolId));
  const canonicalDocument = {
    schemaVersion: TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
    registryVersion: input.registryVersion,
    bindings: bindings.map(({ displayName: _label, bindingSha256: _digest, ...binding }) => binding),
  };
  return Object.freeze({
    registryVersion: input.registryVersion,
    registrySha256: digestCanonicalJson(canonicalDocument, {
      maxBytes: 512 * 1_024,
      maxDepth: 16,
    }).sha256,
    bindings: Object.freeze(bindings),
  });
}

/**
 * Runtime-manifest-aligned source of truth for exact local executable probes.
 * It does not add tools, change capability metadata, or grant execution.
 */
export class ToolBindingRegistry {
  private readonly records: ReadonlyMap<string, ReviewedLocalToolBinding>;
  private readonly ordered: readonly ReviewedLocalToolBinding[];
  readonly descriptor: ToolBindingRegistryDescriptor;

  constructor(input: unknown, manifests: RuntimeSourceManifests) {
    const parsed = parseDocument(input, manifests);
    this.ordered = parsed.bindings;
    this.records = new Map(parsed.bindings.map((binding) => [binding.toolId, binding]));
    const localRuntimeTools = manifests.tools.filter(({ mcpServerId }) => mcpServerId === undefined);
    this.descriptor = Object.freeze({
      schemaVersion: TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
      registryVersion: parsed.registryVersion,
      registrySha256: parsed.registrySha256,
      runtimeManifestSha256: runtimeLocalToolManifestSha256(manifests),
      registeredBindingCount: parsed.bindings.length,
      runtimeToolCount: manifests.tools.length,
      boundRuntimeToolCount: parsed.bindings.length,
      runtimeToolsWithoutLocalBinding: localRuntimeTools.length - parsed.bindings.length,
      sourceOfTruth: "runtime-manifest-aligned-local-bindings",
    });
  }

  list(): readonly ReviewedLocalToolBinding[] {
    return this.ordered;
  }

  resolve(toolId: string): ReviewedLocalToolBinding | undefined {
    return this.records.get(toolId);
  }

  isAlignedWith(manifests: RuntimeSourceManifests): boolean {
    try {
      buildRuntimeCapabilityProjection(manifests);
      return runtimeLocalToolManifestSha256(manifests)
        === this.descriptor.runtimeManifestSha256;
    } catch {
      return false;
    }
  }

  toPreflightSpec(toolId: string): ToolExecutionPreflightSpec | undefined {
    const binding = this.resolve(toolId);
    if (!binding) return undefined;
    return {
      toolId: binding.toolId,
      displayName: binding.displayName,
      executablePath: binding.executablePath,
      probeArguments: binding.probeArguments,
      expectedExitCodes: binding.expectedExitCodes,
      timeoutMs: binding.timeoutMs,
      maximumOutputBytes: binding.maximumOutputBytes,
      ttlMs: binding.ttlMs,
    };
  }
}

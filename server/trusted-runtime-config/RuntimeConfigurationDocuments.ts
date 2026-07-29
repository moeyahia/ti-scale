import { isAbsolute, resolve, sep } from "node:path";
import {
  buildRuntimeCapabilityProjection,
  type RuntimeSourceManifests,
} from "../domain";
import {
  validateLocalAutonomousPlanningPolicy,
  type LocalAutonomousPlanningPolicy,
} from "../autonomous-runtime";
import {
  EngagementWorkspaceResolver,
  type EngagementWorkspaceMapping,
} from "../system-capabilities/EngagementWorkspaceResolver";

export const RUNTIME_SOURCE_MANIFEST_DOCUMENT_SCHEMA_VERSION =
  "ti-scale.runtime-source-manifests.v1" as const;
export const ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION =
  "ti-scale.engagement-workspace-mappings.v1" as const;

const PUBLIC_ID = /^[A-Za-z0-9._:@/-]{1,200}$/u;
const DOCUMENT_VERSION = /^[A-Za-z0-9._-]{1,80}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const SECRET_VALUE = /(?:\bBearer\s+\S+|(?:^|[^A-Za-z0-9])(?:sk|rk|pk)-[A-Za-z0-9_-]{8,}|-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----|(?:api[-_]?key|authorization|cookie|password|private[-_]?key|secret|session[-_]?token)\s*[:=]\s*\S+)/iu;

export interface RuntimeSourceManifestDocument {
  readonly schemaVersion: typeof RUNTIME_SOURCE_MANIFEST_DOCUMENT_SCHEMA_VERSION;
  readonly manifestVersion: string;
  readonly manifests: RuntimeSourceManifests;
}

export interface EngagementWorkspaceMappingsDocument {
  readonly schemaVersion: typeof ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION;
  readonly mappingVersion: string;
  readonly mappings: readonly EngagementWorkspaceMapping[];
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

function keys(
  value: JsonRecord,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value);
  const accepted = new Set([...required, ...optional]);
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  const unexpected = actual.filter((key) => !accepted.has(key));
  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `${label} has invalid fields (missing: ${missing.join(", ") || "none"}; unexpected: ${unexpected.join(", ") || "none"})`,
    );
  }
}

function text(value: unknown, label: string, maximum = 1_000): string {
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

function id(value: unknown, label: string): string {
  const normalized = text(value, label, 200);
  if (!PUBLIC_ID.test(normalized)) throw new Error(`${label} must be a stable public ID`);
  return normalized;
}

function version(value: unknown, label: string): string {
  const normalized = text(value, label, 80);
  if (!DOCUMENT_VERSION.test(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function bool(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be boolean`);
  return value;
}

function integer(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function list(
  value: unknown,
  label: string,
  options: { readonly maximum?: number; readonly allowEmpty?: boolean; readonly ids?: boolean } = {},
): readonly string[] {
  const maximum = options.maximum ?? 2_048;
  if (!Array.isArray(value)
    || (!options.allowEmpty && value.length === 0)
    || value.length > maximum) {
    throw new Error(`${label} must contain ${options.allowEmpty ? "zero" : "one"} to ${maximum} values`);
  }
  const result = value.map((item, index) => options.ids
    ? id(item, `${label}[${index}]`)
    : text(item, `${label}[${index}]`));
  if (new Set(result).size !== result.length) throw new Error(`${label} contains duplicates`);
  return Object.freeze(result);
}

function records(value: unknown, label: string, maximum: number): readonly unknown[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new Error(`${label} must be an array of at most ${maximum} records`);
  }
  return value;
}

function timestamp(value: unknown, label: string): string {
  const normalized = text(value, label, 100);
  const time = Date.parse(normalized);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== normalized) {
    throw new Error(`${label} must be a normalized UTC timestamp`);
  }
  return normalized;
}

function optionalList(
  record: JsonRecord,
  key: string,
  label: string,
  options: Parameters<typeof list>[2] = {},
): readonly string[] | undefined {
  return Object.prototype.hasOwnProperty.call(record, key)
    ? list(record[key], label, options)
    : undefined;
}

function parseRisk(value: unknown, index: number): RuntimeSourceManifests["riskClasses"][number] {
  const record = plainRecord(value, `riskClasses[${index}]`);
  keys(record, ["actionClassIds", "id", "label"], [], `riskClasses[${index}]`);
  return Object.freeze({
    id: id(record.id, `riskClasses[${index}].id`),
    label: text(record.label, `riskClasses[${index}].label`, 240),
    actionClassIds: list(record.actionClassIds, `riskClasses[${index}].actionClassIds`, { ids: true }),
  });
}

function parseEvidenceKind(
  value: unknown,
  index: number,
): RuntimeSourceManifests["evidenceKinds"][number] {
  const record = plainRecord(value, `evidenceKinds[${index}]`);
  keys(record, ["evidenceTypeIds", "id", "label"], [], `evidenceKinds[${index}]`);
  return Object.freeze({
    id: id(record.id, `evidenceKinds[${index}].id`),
    label: text(record.label, `evidenceKinds[${index}].label`, 240),
    evidenceTypeIds: list(record.evidenceTypeIds, `evidenceKinds[${index}].evidenceTypeIds`, { ids: true }),
  });
}

function parseCapability(
  value: unknown,
  index: number,
): RuntimeSourceManifests["capabilities"][number] {
  const record = plainRecord(value, `capabilities[${index}]`);
  keys(
    record,
    ["actionClassIds", "id", "label"],
    ["deliverableIds", "evidenceTypeIds"],
    `capabilities[${index}]`,
  );
  const evidenceTypeIds = optionalList(record, "evidenceTypeIds", `capabilities[${index}].evidenceTypeIds`, { ids: true, allowEmpty: true });
  const deliverableIds = optionalList(record, "deliverableIds", `capabilities[${index}].deliverableIds`, { ids: true, allowEmpty: true });
  return Object.freeze({
    id: id(record.id, `capabilities[${index}].id`),
    label: text(record.label, `capabilities[${index}].label`, 240),
    actionClassIds: list(record.actionClassIds, `capabilities[${index}].actionClassIds`, { ids: true }),
    ...(evidenceTypeIds === undefined ? {} : { evidenceTypeIds }),
    ...(deliverableIds === undefined ? {} : { deliverableIds }),
  });
}

function parseDependency(
  value: unknown,
  toolIndex: number,
  index: number,
): NonNullable<RuntimeSourceManifests["tools"][number]["dependencies"]>[number] {
  const record = plainRecord(value, `tools[${toolIndex}].dependencies[${index}]`);
  keys(record, ["id", "ready"], [], `tools[${toolIndex}].dependencies[${index}]`);
  return Object.freeze({
    id: id(record.id, `tools[${toolIndex}].dependencies[${index}].id`),
    ready: bool(record.ready, `tools[${toolIndex}].dependencies[${index}].ready`),
  });
}

function parseTool(value: unknown, index: number): RuntimeSourceManifests["tools"][number] {
  const record = plainRecord(value, `tools[${index}]`);
  keys(
    record,
    ["actionClassIds", "available", "evidenceTypeIds", "id", "label", "locallyPolicyEnforced", "riskClassIds"],
    ["deliverableIds", "dependencies", "executionJourneys", "mcpServerId", "requiresModel"],
    `tools[${index}]`,
  );
  const deliverableIds = optionalList(record, "deliverableIds", `tools[${index}].deliverableIds`, { ids: true, allowEmpty: true });
  const dependencies = Object.prototype.hasOwnProperty.call(record, "dependencies")
    ? records(record.dependencies, `tools[${index}].dependencies`, 128)
      .map((entry, dependencyIndex) => parseDependency(entry, index, dependencyIndex))
    : undefined;
  if (dependencies && new Set(dependencies.map(({ id }) => id)).size !== dependencies.length) {
    throw new Error(`tools[${index}].dependencies contains duplicate IDs`);
  }
  return Object.freeze({
    id: id(record.id, `tools[${index}].id`),
    label: text(record.label, `tools[${index}].label`, 240),
    available: bool(record.available, `tools[${index}].available`),
    locallyPolicyEnforced: bool(record.locallyPolicyEnforced, `tools[${index}].locallyPolicyEnforced`),
    ...(Object.prototype.hasOwnProperty.call(record, "requiresModel")
      ? { requiresModel: bool(record.requiresModel, `tools[${index}].requiresModel`) }
      : {}),
    ...(Object.prototype.hasOwnProperty.call(record, "executionJourneys")
      ? {
          executionJourneys: list(
            record.executionJourneys,
            `tools[${index}].executionJourneys`,
            { ids: true },
          ).map((journey) => {
            if (journey !== "autonomous" && journey !== "guided") {
              throw new Error(`tools[${index}].executionJourneys contains unsupported journey ${journey}`);
            }
            return journey;
          }),
        }
      : {}),
    actionClassIds: list(record.actionClassIds, `tools[${index}].actionClassIds`, { ids: true }),
    evidenceTypeIds: list(record.evidenceTypeIds, `tools[${index}].evidenceTypeIds`, { ids: true, allowEmpty: true }),
    ...(deliverableIds === undefined ? {} : { deliverableIds }),
    riskClassIds: list(record.riskClassIds, `tools[${index}].riskClassIds`, { ids: true }),
    ...(Object.prototype.hasOwnProperty.call(record, "mcpServerId")
      ? { mcpServerId: id(record.mcpServerId, `tools[${index}].mcpServerId`) }
      : {}),
    ...(dependencies === undefined ? {} : { dependencies: Object.freeze(dependencies) }),
  });
}

function parseMcpServer(
  value: unknown,
  index: number,
): RuntimeSourceManifests["mcpServers"][number] {
  const record = plainRecord(value, `mcpServers[${index}]`);
  keys(record, ["id", "label", "status", "toolIds"], [], `mcpServers[${index}]`);
  const status = text(record.status, `mcpServers[${index}].status`, 32);
  if (!["healthy", "degraded", "offline", "unconfigured"].includes(status)) {
    throw new Error(`mcpServers[${index}].status is unsupported`);
  }
  return Object.freeze({
    id: id(record.id, `mcpServers[${index}].id`),
    label: text(record.label, `mcpServers[${index}].label`, 240),
    status: status as RuntimeSourceManifests["mcpServers"][number]["status"],
    toolIds: list(record.toolIds, `mcpServers[${index}].toolIds`, { ids: true, allowEmpty: true }),
  });
}

function parseModelRef(value: unknown, agentIndex: number, index: number) {
  const record = plainRecord(value, `agents[${agentIndex}].modelRefs[${index}]`);
  keys(record, ["modelId", "providerId"], [], `agents[${agentIndex}].modelRefs[${index}]`);
  return Object.freeze({
    providerId: id(record.providerId, `agents[${agentIndex}].modelRefs[${index}].providerId`),
    modelId: id(record.modelId, `agents[${agentIndex}].modelRefs[${index}].modelId`),
  });
}

function parseAgent(value: unknown, index: number): RuntimeSourceManifests["agents"][number] {
  const record = plainRecord(value, `agents[${index}]`);
  keys(
    record,
    ["available", "capabilityIds", "id", "label", "modelRefs", "toolIds"],
    ["actionClassIds", "deliverableIds"],
    `agents[${index}]`,
  );
  const modelRefs = records(record.modelRefs, `agents[${index}].modelRefs`, 256)
    .map((entry, refIndex) => parseModelRef(entry, index, refIndex));
  const modelRefIds = modelRefs.map(({ providerId, modelId }) => `${providerId}/${modelId}`);
  if (new Set(modelRefIds).size !== modelRefIds.length) {
    throw new Error(`agents[${index}].modelRefs contains duplicates`);
  }
  const actionClassIds = optionalList(record, "actionClassIds", `agents[${index}].actionClassIds`, { ids: true, allowEmpty: true });
  const deliverableIds = optionalList(record, "deliverableIds", `agents[${index}].deliverableIds`, { ids: true, allowEmpty: true });
  return Object.freeze({
    id: id(record.id, `agents[${index}].id`),
    label: text(record.label, `agents[${index}].label`, 240),
    available: bool(record.available, `agents[${index}].available`),
    capabilityIds: list(record.capabilityIds, `agents[${index}].capabilityIds`, { ids: true, allowEmpty: true }),
    ...(actionClassIds === undefined ? {} : { actionClassIds }),
    toolIds: list(record.toolIds, `agents[${index}].toolIds`, { ids: true, allowEmpty: true }),
    ...(deliverableIds === undefined ? {} : { deliverableIds }),
    modelRefs: Object.freeze(modelRefs),
  });
}

function parseProviderModel(
  value: unknown,
  providerIndex: number,
  index: number,
): RuntimeSourceManifests["providers"][number]["models"][number] {
  const record = plainRecord(value, `providers[${providerIndex}].models[${index}]`);
  keys(
    record,
    ["compatibleActionClassIds", "disclosureClasses", "displayName", "enforcement", "id", "structuredOutput", "toolCalling"],
    ["contextLimit", "executionBoundary", "reasoningEfforts"],
    `providers[${providerIndex}].models[${index}]`,
  );
  const enforcement = text(record.enforcement, `providers[${providerIndex}].models[${index}].enforcement`, 32);
  if (!["enforced_executor", "observe_only_executor", "advisor_only"].includes(enforcement)) {
    throw new Error(`providers[${providerIndex}].models[${index}].enforcement is unsupported`);
  }
  const reasoningEfforts = optionalList(
    record,
    "reasoningEfforts",
    `providers[${providerIndex}].models[${index}].reasoningEfforts`,
    { ids: true, allowEmpty: true, maximum: 32 },
  );
  const executionBoundary = Object.prototype.hasOwnProperty.call(
    record,
    "executionBoundary",
  )
    ? text(
        record.executionBoundary,
        `providers[${providerIndex}].models[${index}].executionBoundary`,
        64,
      )
    : "provider_tool_calling";
  if (
    executionBoundary !== "provider_tool_calling"
    && executionBoundary !== "local_deterministic_policy"
  ) {
    throw new Error(
      `providers[${providerIndex}].models[${index}].executionBoundary is unsupported`,
    );
  }
  return Object.freeze({
    id: id(record.id, `providers[${providerIndex}].models[${index}].id`),
    displayName: text(record.displayName, `providers[${providerIndex}].models[${index}].displayName`, 240),
    executionBoundary,
    toolCalling: bool(record.toolCalling, `providers[${providerIndex}].models[${index}].toolCalling`),
    structuredOutput: bool(record.structuredOutput, `providers[${providerIndex}].models[${index}].structuredOutput`),
    enforcement: enforcement as RuntimeSourceManifests["providers"][number]["models"][number]["enforcement"],
    compatibleActionClassIds: list(
      record.compatibleActionClassIds,
      `providers[${providerIndex}].models[${index}].compatibleActionClassIds`,
      { ids: true, allowEmpty: true },
    ),
    disclosureClasses: list(
      record.disclosureClasses,
      `providers[${providerIndex}].models[${index}].disclosureClasses`,
      { ids: true, allowEmpty: true, maximum: 128 },
    ),
    ...(Object.prototype.hasOwnProperty.call(record, "contextLimit")
      ? { contextLimit: integer(record.contextLimit, 1, 100_000_000, `providers[${providerIndex}].models[${index}].contextLimit`) }
      : {}),
    ...(reasoningEfforts === undefined ? {} : { reasoningEfforts }),
  });
}

function parseProvider(
  value: unknown,
  index: number,
): RuntimeSourceManifests["providers"][number] {
  const record = plainRecord(value, `providers[${index}]`);
  keys(record, ["authenticated", "catalogObservedAt", "healthy", "id", "models"], [], `providers[${index}]`);
  return Object.freeze({
    id: id(record.id, `providers[${index}].id`),
    authenticated: bool(record.authenticated, `providers[${index}].authenticated`),
    healthy: bool(record.healthy, `providers[${index}].healthy`),
    catalogObservedAt: timestamp(record.catalogObservedAt, `providers[${index}].catalogObservedAt`),
    models: Object.freeze(records(record.models, `providers[${index}].models`, 1_024)
      .map((entry, modelIndex) => parseProviderModel(entry, index, modelIndex))),
  });
}

function parseManifests(input: unknown): RuntimeSourceManifests {
  const record = plainRecord(input, "Runtime source manifests");
  keys(
    record,
    ["agents", "capabilities", "evidenceKinds", "mcpServers", "providers", "riskClasses", "tools"],
    [],
    "Runtime source manifests",
  );
  const manifests: RuntimeSourceManifests = Object.freeze({
    riskClasses: Object.freeze(records(record.riskClasses, "riskClasses", 128).map(parseRisk)),
    evidenceKinds: Object.freeze(records(record.evidenceKinds, "evidenceKinds", 128).map(parseEvidenceKind)),
    capabilities: Object.freeze(records(record.capabilities, "capabilities", 512).map(parseCapability)),
    tools: Object.freeze(records(record.tools, "tools", 4_096).map(parseTool)),
    mcpServers: Object.freeze(records(record.mcpServers, "mcpServers", 512).map(parseMcpServer)),
    agents: Object.freeze(records(record.agents, "agents", 512).map(parseAgent)),
    providers: Object.freeze(records(record.providers, "providers", 128).map(parseProvider)),
  });
  // Reuse the canonical registry/cross-reference validator. A file never
  // becomes a runtime source merely because its JSON shape was parseable.
  buildRuntimeCapabilityProjection(manifests);
  return manifests;
}

export function parseRuntimeSourceManifestDocument(input: unknown): RuntimeSourceManifestDocument {
  const record = plainRecord(input, "Runtime source manifest document");
  keys(record, ["manifestVersion", "manifests", "schemaVersion"], [], "Runtime source manifest document");
  if (record.schemaVersion !== RUNTIME_SOURCE_MANIFEST_DOCUMENT_SCHEMA_VERSION) {
    throw new Error(`Unsupported runtime source manifest schema: ${String(record.schemaVersion)}`);
  }
  return Object.freeze({
    schemaVersion: RUNTIME_SOURCE_MANIFEST_DOCUMENT_SCHEMA_VERSION,
    manifestVersion: version(record.manifestVersion, "Runtime source manifest version"),
    manifests: parseManifests(record.manifests),
  });
}

export function parseLocalAutonomousPlanningPolicy(input: unknown): LocalAutonomousPlanningPolicy {
  // The planner owns the canonical exact-key, registry, risk, evidence,
  // secret-shaped parameter, and ambiguity rules. The loader cannot broaden it.
  return validateLocalAutonomousPlanningPolicy(input as LocalAutonomousPlanningPolicy);
}

function workspacePath(value: unknown, label: string): string {
  const path = text(value, label, 4_096);
  if (!isAbsolute(path)) throw new Error(`${label} must be absolute`);
  const normalized = resolve(path);
  if (normalized === resolve(sep)) throw new Error(`${label} must be narrower than the filesystem root`);
  return normalized;
}

export function parseEngagementWorkspaceMappingsDocument(
  input: unknown,
): EngagementWorkspaceMappingsDocument {
  const record = plainRecord(input, "Engagement workspace mappings document");
  keys(record, ["mappingVersion", "mappings", "schemaVersion"], [], "Engagement workspace mappings document");
  if (record.schemaVersion !== ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION) {
    throw new Error(`Unsupported engagement workspace mapping schema: ${String(record.schemaVersion)}`);
  }
  const mappings = records(record.mappings, "Workspace mappings", 32).map((value, index) => {
    const mapping = plainRecord(value, `mappings[${index}]`);
    keys(mapping, ["logicalRoot", "runtimeRoot"], [], `mappings[${index}]`);
    return Object.freeze({
      logicalRoot: workspacePath(mapping.logicalRoot, `mappings[${index}].logicalRoot`),
      runtimeRoot: workspacePath(mapping.runtimeRoot, `mappings[${index}].runtimeRoot`),
    });
  });
  if (mappings.length === 0) throw new Error("Workspace mappings requires at least one record");
  if (new Set(mappings.map(({ runtimeRoot }) => runtimeRoot)).size !== mappings.length) {
    throw new Error("Workspace runtime roots must be unique");
  }
  // Reuse the production resolver's normalization and logical-root ambiguity checks.
  new EngagementWorkspaceResolver(mappings);
  return Object.freeze({
    schemaVersion: ENGAGEMENT_WORKSPACE_MAPPINGS_SCHEMA_VERSION,
    mappingVersion: version(record.mappingVersion, "Workspace mapping version"),
    mappings: Object.freeze(mappings),
  });
}

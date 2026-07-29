import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";
import { digestCanonicalJson } from "../mcp/canonicalJson";
import {
  assertReusableMemoryText,
  assertReusableMemoryUnknown,
  REUSABLE_MEMORY_LIMITS,
} from "./ReusableMemorySafety";

export const OPERATOR_PREFERENCE_MANIFEST_SCHEMA_VERSION =
  "ti-scale.operator-preferences.v2" as const;

export const OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY =
  "authorization_scope_privacy_evidence_and_runtime_safety_remain_enforced" as const;

export const OPERATOR_PREFERENCE_CATEGORIES = [
  "autonomy",
  "brain",
  "communication",
  "deployment",
  "documentation",
  "memory",
  "model_selection",
  "product",
  "roadmap",
  "visual",
] as const;

export type OperatorPreferenceCategory =
  (typeof OPERATOR_PREFERENCE_CATEGORIES)[number];

const MAXIMUM_MANIFEST_BYTES = 256 * 1_024;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/u;
const PREFERENCE_KEY = /^[a-z][a-z0-9_.-]{0,119}$/u;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u;

export const OPERATOR_PREFERENCE_APPLIES_TO = [
  "autonomy_presentation",
  "brain_anatomy",
  "brain_graph",
  "controls",
  "deployment_architecture",
  "documentation",
  "evidence_presentation",
  "guided_explanations",
  "main_interface",
  "memory_provenance",
  "memory_taxonomy",
  "mobile_roadmap",
  "model_selection",
  "motion",
  "outcome_classification",
  "preference_controls",
  "product_identity",
  "reports",
  "repository_architecture",
  "visual_identity",
] as const;

export type OperatorPreferenceAppliesTo =
  (typeof OPERATOR_PREFERENCE_APPLIES_TO)[number];

export interface OperatorPreferenceManifestItem {
  readonly id: string;
  readonly preferenceKey: string;
  readonly category: OperatorPreferenceCategory;
  readonly title: string;
  readonly summary: string;
  readonly body: string;
  readonly value: Readonly<Record<string, unknown>>;
  readonly appliesTo: readonly OperatorPreferenceAppliesTo[];
  readonly sensitivity: "internal" | "private";
  readonly consentPolicy: "explicit_operator_confirmation";
}

export interface OperatorPreferenceManifest {
  readonly schemaVersion: typeof OPERATOR_PREFERENCE_MANIFEST_SCHEMA_VERSION;
  readonly manifestVersion: string;
  readonly operatorId: string;
  readonly retentionPolicy: Readonly<{
    durableOnly: true;
    excludeOneTimeCommands: true;
    excludeTargetSpecificData: true;
    excludeCredentialsAndSecrets: true;
  }>;
  readonly safetyBoundary: typeof OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY;
  readonly source: Readonly<{
    sourceType: "operator_instruction_manifest";
    sourceId: string;
    acquiredAt: string;
  }>;
  readonly preferences: readonly OperatorPreferenceManifestItem[];
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, label: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)
      || (Object.getPrototypeOf(value) !== Object.prototype
        && Object.getPrototypeOf(value) !== null)) {
    throw new Error(`${label} must be a plain object`);
  }
  return value as JsonRecord;
}

function exactKeys(value: JsonRecord, expected: readonly string[], label: string): void {
  const allowed = new Set(expected);
  const missing = expected.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  const unexpected = Object.keys(value).filter((key) => !allowed.has(key));
  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `${label} has invalid fields (missing: ${missing.join(", ") || "none"}; unexpected: ${unexpected.join(", ") || "none"})`,
    );
  }
}

function text(value: unknown, label: string, maximum: number, pattern?: RegExp): string {
  if (typeof value !== "string" || value !== value.trim() || !value || value.length > maximum
      || (pattern && !pattern.test(value))) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function timestamp(value: unknown, label: string): string {
  const parsed = text(value, label, 40);
  if (!Number.isFinite(Date.parse(parsed)) || !parsed.endsWith("Z")) {
    throw new Error(`${label} must be an ISO-8601 UTC timestamp`);
  }
  return parsed;
}

function stringArray<T extends string>(
  value: unknown,
  label: string,
  allowed: readonly T[],
): readonly T[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
    throw new Error(`${label} must contain one to 16 values`);
  }
  const result = value.map((item, index) => {
    if (typeof item !== "string" || !allowed.includes(item as T)) {
      throw new Error(`${label}[${index}] is invalid`);
    }
    return item as T;
  });
  if (new Set(result).size !== result.length) throw new Error(`${label} contains duplicates`);
  return Object.freeze(result);
}

function preferenceValue(value: unknown, label: string): Readonly<Record<string, unknown>> {
  const parsed = record(value, label);
  const digest = digestCanonicalJson(parsed, { maxBytes: 16 * 1_024, maxDepth: 8 });
  assertReusableMemoryUnknown(parsed, label, 16 * 1_024);
  if (digest.canonicalJson === "{}") throw new Error(`${label} must not be empty`);
  return Object.freeze(parsed);
}

function parsePreference(value: unknown, index: number): OperatorPreferenceManifestItem {
  const label = `preferences[${index}]`;
  const input = record(value, label);
  exactKeys(input, [
    "appliesTo",
    "body",
    "category",
    "consentPolicy",
    "id",
    "preferenceKey",
    "sensitivity",
    "summary",
    "title",
    "value",
  ], label);
  if (input.consentPolicy !== "explicit_operator_confirmation") {
    throw new Error(`${label}.consentPolicy must be explicit_operator_confirmation`);
  }
  if (input.sensitivity !== "internal" && input.sensitivity !== "private") {
    throw new Error(`${label}.sensitivity must be internal or private`);
  }
  const item = Object.freeze({
    id: text(input.id, `${label}.id`, 120, IDENTIFIER),
    preferenceKey: text(input.preferenceKey, `${label}.preferenceKey`, 120, PREFERENCE_KEY),
    category: (() => {
      if (typeof input.category !== "string"
          || !OPERATOR_PREFERENCE_CATEGORIES.includes(input.category as OperatorPreferenceCategory)) {
        throw new Error(`${label}.category is invalid`);
      }
      return input.category as OperatorPreferenceCategory;
    })(),
    title: text(input.title, `${label}.title`, REUSABLE_MEMORY_LIMITS.title),
    summary: text(input.summary, `${label}.summary`, REUSABLE_MEMORY_LIMITS.summary),
    body: text(input.body, `${label}.body`, REUSABLE_MEMORY_LIMITS.body),
    value: preferenceValue(input.value, `${label}.value`),
    appliesTo: stringArray(
      input.appliesTo,
      `${label}.appliesTo`,
      OPERATOR_PREFERENCE_APPLIES_TO,
    ),
    sensitivity: input.sensitivity,
    consentPolicy: "explicit_operator_confirmation" as const,
  });
  assertReusableMemoryText([
    { field: `${label}.title`, value: item.title, maximumBytes: REUSABLE_MEMORY_LIMITS.title },
    { field: `${label}.summary`, value: item.summary, maximumBytes: REUSABLE_MEMORY_LIMITS.summary },
    { field: `${label}.body`, value: item.body, maximumBytes: REUSABLE_MEMORY_LIMITS.body },
  ]);
  return item;
}

/** Strict, data-only parsing. The manifest cannot carry code, tools, or policy overrides. */
export function parseOperatorPreferenceManifest(value: unknown): OperatorPreferenceManifest {
  const input = record(value, "Operator preference manifest");
  exactKeys(
    input,
    [
      "manifestVersion",
      "operatorId",
      "preferences",
      "retentionPolicy",
      "safetyBoundary",
      "schemaVersion",
      "source",
    ],
    "Operator preference manifest",
  );
  if (input.schemaVersion !== OPERATOR_PREFERENCE_MANIFEST_SCHEMA_VERSION) {
    throw new Error("Operator preference manifest schemaVersion is unsupported");
  }
  if (input.safetyBoundary !== OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY) {
    throw new Error("Operator preference manifest safetyBoundary is unsupported");
  }
  const retentionPolicy = record(
    input.retentionPolicy,
    "Operator preference manifest retentionPolicy",
  );
  exactKeys(retentionPolicy, [
    "durableOnly",
    "excludeOneTimeCommands",
    "excludeTargetSpecificData",
    "excludeCredentialsAndSecrets",
  ], "Operator preference manifest retentionPolicy");
  for (const key of [
    "durableOnly",
    "excludeOneTimeCommands",
    "excludeTargetSpecificData",
    "excludeCredentialsAndSecrets",
  ] as const) {
    if (retentionPolicy[key] !== true) {
      throw new Error(`Operator preference manifest retentionPolicy.${key} must be true`);
    }
  }
  const source = record(input.source, "Operator preference manifest source");
  exactKeys(source, ["acquiredAt", "sourceId", "sourceType"], "Operator preference manifest source");
  if (source.sourceType !== "operator_instruction_manifest") {
    throw new Error("Operator preference manifest sourceType is unsupported");
  }
  if (!Array.isArray(input.preferences) || input.preferences.length < 1 || input.preferences.length > 100) {
    throw new Error("Operator preference manifest must contain one to 100 preferences");
  }
  const preferences = input.preferences.map(parsePreference);
  if (new Set(preferences.map(({ id }) => id)).size !== preferences.length) {
    throw new Error("Operator preference manifest contains duplicate preference IDs");
  }
  if (new Set(preferences.map(({ preferenceKey }) => preferenceKey)).size !== preferences.length) {
    throw new Error("Operator preference manifest contains duplicate preference keys");
  }
  return Object.freeze({
    schemaVersion: OPERATOR_PREFERENCE_MANIFEST_SCHEMA_VERSION,
    manifestVersion: text(input.manifestVersion, "manifestVersion", 80, VERSION),
    operatorId: text(input.operatorId, "operatorId", 120, IDENTIFIER),
    retentionPolicy: Object.freeze({
      durableOnly: true as const,
      excludeOneTimeCommands: true as const,
      excludeTargetSpecificData: true as const,
      excludeCredentialsAndSecrets: true as const,
    }),
    safetyBoundary: OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY,
    source: Object.freeze({
      sourceType: "operator_instruction_manifest" as const,
      sourceId: text(source.sourceId, "source.sourceId", 120, IDENTIFIER),
      acquiredAt: timestamp(source.acquiredAt, "source.acquiredAt"),
    }),
    preferences: Object.freeze(preferences),
  });
}

export function loadTrustedOperatorPreferenceManifest(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<OperatorPreferenceManifest> {
  return loadTrustedJson(
    { ...reference, maximumBytes: MAXIMUM_MANIFEST_BYTES },
    parseOperatorPreferenceManifest,
  );
}

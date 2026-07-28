import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";

export const HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION =
  "ti-scale.historical-source-roots.v1" as const;
export const HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION =
  "ti-scale.historical-source-roots.v2" as const;

export const HISTORICAL_SOURCE_ROOT_MODES = [
  "children",
  "engagement-root",
  "history-root",
] as const;

export type HistoricalSourceRootMode = (typeof HISTORICAL_SOURCE_ROOT_MODES)[number];

const CONFIGURATION_VERSION = /^[A-Za-z0-9._-]{1,80}$/u;
const ROOT_ID = /^[A-Za-z0-9._-]{1,120}$/u;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/u;
const MAXIMUM_CONFIGURATION_BYTES = 64 * 1_024;

export interface HistoricalSourceRootDefinition {
  readonly id: string;
  /** Absolute operator-owned historical source boundary. */
  readonly path: string;
  /**
   * children: safe direct children are engagement roots.
   * engagement-root: this exact directory is one engagement root.
   * history-root: deterministic runtime/provider history only; never creates
   * engagement manifests from its directory structure.
   */
  readonly mode: HistoricalSourceRootMode;
  /** Required roots fail closed when absent instead of silently shrinking coverage. */
  readonly required: true;
}

export interface HistoricalSourceRootConfiguration {
  readonly schemaVersion:
    | typeof HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION
    | typeof HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION;
  readonly configurationVersion: string;
  readonly roots: readonly HistoricalSourceRootDefinition[];
}

export interface ResolvedHistoricalSourceRoots {
  readonly childrenRoots: readonly string[];
  readonly engagementRoots: readonly string[];
  readonly historyRoots: readonly string[];
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

function exactKeys(value: JsonRecord, required: readonly string[], label: string): void {
  const actual = Object.keys(value);
  const expected = new Set(required);
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  const unexpected = actual.filter((key) => !expected.has(key));
  if (missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `${label} has invalid fields (missing: ${missing.join(", ") || "none"}; unexpected: ${unexpected.join(", ") || "none"})`,
    );
  }
}

function safeText(value: unknown, label: string, pattern: RegExp): string {
  if (typeof value !== "string" || value !== value.trim() || !pattern.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function absoluteRoot(value: unknown, label: string): string {
  if (typeof value !== "string" || value !== value.trim() || value.length > 4_096
      || CONTROL_CHARACTERS.test(value) || !isAbsolute(value)) {
    throw new Error(`${label} must be a normalized absolute path without control characters`);
  }
  const normalized = resolve(value);
  if (normalized !== value || normalized === resolve(sep)) {
    throw new Error(`${label} must be normalized and narrower than the filesystem root`);
  }
  return normalized;
}

function parseRoot(
  value: unknown,
  index: number,
  schemaVersion: HistoricalSourceRootConfiguration["schemaVersion"],
): HistoricalSourceRootDefinition {
  const input = record(value, `roots[${index}]`);
  exactKeys(input, ["id", "mode", "path", "required"], `roots[${index}]`);
  if (!HISTORICAL_SOURCE_ROOT_MODES.includes(input.mode as HistoricalSourceRootMode)) {
    throw new Error(
      `roots[${index}].mode must be children, engagement-root, or history-root`,
    );
  }
  if (
    schemaVersion === HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION
    && input.mode !== "children"
  ) {
    throw new Error(`roots[${index}].mode must be children for the v1 schema`);
  }
  if (input.required !== true) {
    throw new Error(`roots[${index}].required must be true`);
  }
  return Object.freeze({
    id: safeText(input.id, `roots[${index}].id`, ROOT_ID),
    path: absoluteRoot(input.path, `roots[${index}].path`),
    mode: input.mode as HistoricalSourceRootMode,
    required: true as const,
  });
}

function pathsOverlap(left: string, right: string): boolean {
  return left === right
    || left.startsWith(`${right}${sep}`)
    || right.startsWith(`${left}${sep}`);
}

/** Parse a strict data-only manifest. It cannot add files, commands, or glob rules. */
export function parseHistoricalSourceRootConfiguration(
  value: unknown,
): HistoricalSourceRootConfiguration {
  const input = record(value, "Historical source-root configuration");
  exactKeys(
    input,
    ["configurationVersion", "roots", "schemaVersion"],
    "Historical source-root configuration",
  );
  if (
    input.schemaVersion !== HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION
    && input.schemaVersion !== HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION
  ) {
    throw new Error("Historical source-root configuration schemaVersion is unsupported");
  }
  const schemaVersion = input.schemaVersion;
  const maximumRoots = schemaVersion === HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION ? 32 : 64;
  if (!Array.isArray(input.roots) || input.roots.length < 1 || input.roots.length > maximumRoots) {
    throw new Error(`Historical source-root configuration must contain one to ${maximumRoots} roots`);
  }
  const roots = input.roots.map((root, index) => parseRoot(root, index, schemaVersion));
  if (new Set(roots.map(({ id }) => id)).size !== roots.length) {
    throw new Error("Historical source-root configuration contains duplicate root IDs");
  }
  if (new Set(roots.map(({ path }) => path)).size !== roots.length) {
    throw new Error("Historical source-root configuration contains duplicate root paths");
  }
  for (let left = 0; left < roots.length; left += 1) {
    for (let right = left + 1; right < roots.length; right += 1) {
      if (pathsOverlap(roots[left]!.path, roots[right]!.path)) {
        throw new Error(
          "Historical source-root configuration contains overlapping root paths",
        );
      }
    }
  }
  return Object.freeze({
    schemaVersion,
    configurationVersion: safeText(
      input.configurationVersion,
      "configurationVersion",
      CONFIGURATION_VERSION,
    ),
    roots: Object.freeze(roots),
  });
}

/**
 * Load one deployment-reviewed manifest by exact byte hash. The shared trusted
 * loader rejects symlinks, writable path components, owner drift, file changes,
 * oversized JSON, and a SHA mismatch before parsing.
 */
export function loadTrustedHistoricalSourceRootConfiguration(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<HistoricalSourceRootConfiguration> {
  return loadTrustedJson(
    { ...reference, maximumBytes: MAXIMUM_CONFIGURATION_BYTES },
    parseHistoricalSourceRootConfiguration,
  );
}

/**
 * Required roots are checked once before migration discovery. Requested paths
 * are retained so the canonical importer can still record aliases and physical
 * identities in its immutable inventory receipt.
 */
export function requiredHistoricalParentRoots(
  configuration: HistoricalSourceRootConfiguration,
): readonly string[] {
  if (configuration.roots.some(({ mode }) => mode !== "children")) {
    throw new Error(
      "requiredHistoricalParentRoots supports only children roots; use resolveRequiredHistoricalSourceRoots for v2 manifests",
    );
  }
  return resolveRequiredHistoricalSourceRoots(configuration).childrenRoots;
}

/**
 * Validate all required v2 source boundaries once and route them to the
 * canonical migration service without allowing manifest-defined parser or
 * command overrides.
 */
export function resolveRequiredHistoricalSourceRoots(
  configuration: HistoricalSourceRootConfiguration,
): ResolvedHistoricalSourceRoots {
  for (const root of configuration.roots) {
    let canonical: string;
    try {
      canonical = realpathSync(root.path);
    } catch {
      throw new Error(`Required historical source root is unavailable: ${root.id}`);
    }
    const state = lstatSync(canonical);
    if (!state.isDirectory()) {
      throw new Error(`Required historical source root is not a directory: ${root.id}`);
    }
  }
  return Object.freeze({
    childrenRoots: Object.freeze(
      configuration.roots.filter(({ mode }) => mode === "children").map(({ path }) => path),
    ),
    engagementRoots: Object.freeze(
      configuration.roots.filter(({ mode }) => mode === "engagement-root").map(({ path }) => path),
    ),
    historyRoots: Object.freeze(
      configuration.roots.filter(({ mode }) => mode === "history-root").map(({ path }) => path),
    ),
  });
}

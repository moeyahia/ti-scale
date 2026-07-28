import { createHash } from "node:crypto";
import {
  ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY,
  BRAIN_ATLAS_KINDS,
  BRAIN_ATLAS_REGIONS,
  OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY,
  assertAttackBrainAtlasMappingRegistryComplete,
  type BrainAtlasKind,
  type BrainAtlasRegion,
} from "./AttackBrainAtlasMappingRegistry";

export type BrainAtlasConfiguration = Readonly<Record<string, unknown>>;

export interface BrainAtlasConfigurationValidation {
  readonly valid: true;
  readonly registryNodeTypeCount: number;
  readonly operatorProfileMappingCount: number;
  readonly kindMappingCount: number;
  readonly regionMappingCount: number;
  readonly missingKindMappings: readonly string[];
  readonly missingRegionMappings: readonly string[];
  readonly invalidKindMappings: readonly string[];
  readonly invalidRegionMappings: readonly string[];
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function stringRecord(value: unknown, label: string): Record<string, string> {
  if (value === undefined) return {};
  const parsed = object(value, label);
  if (Object.values(parsed).some((item) => typeof item !== "string")) {
    throw new TypeError(`${label} values must be strings`);
  }
  return parsed as Record<string, string>;
}

function stringList(value: unknown, fallback: readonly string[], label: string): string[] {
  if (value === undefined) return [...fallback];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item.trim())) {
    throw new TypeError(`${label} must be a non-empty string list`);
  }
  return [...new Set([...fallback, ...(value as string[])])];
}

function optionalString(value: unknown, fallback: string, label: string): string {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must be a string`);
  return value;
}

function optionalBoolean(value: unknown, fallback: boolean, label: string): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new TypeError(`${label} must be a boolean`);
  return value;
}

function optionalInteger(
  value: unknown,
  fallback: number,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new TypeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return Number(value);
}

function managedKindMappings(): Record<string, BrainAtlasKind> {
  return Object.fromEntries([
    ...ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.map((mapping) => [
      `type:${mapping.nodeType}`,
      mapping.kind,
    ] as const),
    ...OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY.map((mapping) => [
      mapping.selector,
      mapping.kind,
    ] as const),
  ]) as Record<string, BrainAtlasKind>;
}

function managedRegionMappings(): Record<string, BrainAtlasRegion> {
  return Object.fromEntries([
    ...ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.map((mapping) => [
      `type:${mapping.nodeType}`,
      mapping.region,
    ] as const),
    ...OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY.map((mapping) => [
      mapping.selector,
      mapping.region,
    ] as const),
  ]) as Record<string, BrainAtlasRegion>;
}

function managedFolderMappings(): Record<string, BrainAtlasRegion> {
  // A folder is only a fallback. Some folders intentionally contain more
  // specific frontmatter regions (for example a cerebellum procedure version
  // beside frontal techniques), so retain the folder's primary first mapping.
  const result: Record<string, BrainAtlasRegion> = {};
  for (const mapping of ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY) {
    result[mapping.folder] ??= mapping.region;
  }
  return result;
}

/**
 * Reconcile Ti-Scale-owned classification fields while retaining operator
 * choices such as palette, renderer, pinned positions, lobe visibility, note
 * overrides, and future Brain Atlas settings this version does not know.
 */
export function generateBrainAtlasConfiguration(
  existing: unknown = {},
): BrainAtlasConfiguration {
  assertAttackBrainAtlasMappingRegistryComplete();
  const source = object(existing, "Brain Atlas configuration");
  const enabled = source.enabledLobes === undefined
    ? {}
    : object(source.enabledLobes, "Brain Atlas enabledLobes");
  const enabledLobes = Object.fromEntries(BRAIN_ATLAS_REGIONS.map((region) => [
    region,
    optionalBoolean(enabled[region], true, `Brain Atlas enabledLobes.${region}`),
  ]));

  return {
    ...source,
    palette: optionalString(source.palette, "daylight", "Brain Atlas palette"),
    performancePreset: optionalString(
      source.performancePreset,
      "smooth",
      "Brain Atlas performancePreset",
    ),
    frontmatterKindKeys: stringList(
      source.frontmatterKindKeys,
      ["kind", "type", "category"],
      "Brain Atlas frontmatterKindKeys",
    ),
    frontmatterKindValueMap: {
      ...stringRecord(source.frontmatterKindValueMap, "Brain Atlas frontmatterKindValueMap"),
      ...managedKindMappings(),
    },
    tagKindMap: stringRecord(source.tagKindMap, "Brain Atlas tagKindMap"),
    folderKindMap: stringRecord(source.folderKindMap, "Brain Atlas folderKindMap"),
    frontmatterRegionKeys: stringList(
      source.frontmatterRegionKeys,
      ["brain_region", "brainRegion", "lobe", "region"],
      "Brain Atlas frontmatterRegionKeys",
    ),
    frontmatterRegionValueMap: {
      ...stringRecord(source.frontmatterRegionValueMap, "Brain Atlas frontmatterRegionValueMap"),
      ...managedRegionMappings(),
    },
    tagRegionMap: stringRecord(source.tagRegionMap, "Brain Atlas tagRegionMap"),
    folderRegionMap: {
      ...stringRecord(source.folderRegionMap, "Brain Atlas folderRegionMap"),
      ...managedFolderMappings(),
    },
    noteRegionMap: stringRecord(source.noteRegionMap, "Brain Atlas noteRegionMap"),
    treatDateFilesAsDaily: optionalBoolean(
      source.treatDateFilesAsDaily,
      false,
      "Brain Atlas treatDateFilesAsDaily",
    ),
    honorDailyNotesFormat: optionalBoolean(
      source.honorDailyNotesFormat,
      false,
      "Brain Atlas honorDailyNotesFormat",
    ),
    dailyNoteDateFormat: optionalString(
      source.dailyNoteDateFormat,
      "YYYY-MM-DD",
      "Brain Atlas dailyNoteDateFormat",
    ),
    nodeCap: optionalInteger(source.nodeCap, 1_500, 1, 10_000, "Brain Atlas nodeCap"),
    edgeCap: optionalInteger(source.edgeCap, 4_000, 1, 20_000, "Brain Atlas edgeCap"),
    idleAutoRotate: optionalBoolean(source.idleAutoRotate, true, "Brain Atlas idleAutoRotate"),
    showLobeLabels: optionalBoolean(source.showLobeLabels, true, "Brain Atlas showLobeLabels"),
    showLegendChip: optionalBoolean(source.showLegendChip, true, "Brain Atlas showLegendChip"),
    enabledLobes,
    clickAction: optionalString(source.clickAction, "current", "Brain Atlas clickAction"),
    hubThresholdPercent: optionalInteger(
      source.hubThresholdPercent,
      6,
      1,
      100,
      "Brain Atlas hubThresholdPercent",
    ),
    pinnedNodePositions: source.pinnedNodePositions === undefined
      ? {}
      : object(source.pinnedNodePositions, "Brain Atlas pinnedNodePositions"),
    defaultKind: optionalString(source.defaultKind, "concept", "Brain Atlas defaultKind"),
    inferKindsFromLinks: optionalBoolean(
      source.inferKindsFromLinks,
      false,
      "Brain Atlas inferKindsFromLinks",
    ),
    rendererMode: optionalString(source.rendererMode, "auto", "Brain Atlas rendererMode"),
  };
}

export function validateBrainAtlasConfiguration(
  value: unknown,
): BrainAtlasConfigurationValidation {
  assertAttackBrainAtlasMappingRegistryComplete();
  const config = object(value, "Brain Atlas configuration");
  const kindMap = stringRecord(config.frontmatterKindValueMap, "Brain Atlas frontmatterKindValueMap");
  const regionMap = stringRecord(config.frontmatterRegionValueMap, "Brain Atlas frontmatterRegionValueMap");
  const allowedKinds = new Set<string>(BRAIN_ATLAS_KINDS);
  const allowedRegions = new Set<string>(BRAIN_ATLAS_REGIONS);
  const missingKindMappings: string[] = [];
  const missingRegionMappings: string[] = [];
  const invalidKindMappings: string[] = [];
  const invalidRegionMappings: string[] = [];
  for (const mapping of ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY) {
    const key = `type:${mapping.nodeType}`;
    if (!(key in kindMap)) missingKindMappings.push(mapping.nodeType);
    else if (kindMap[key] !== mapping.kind || !allowedKinds.has(kindMap[key]!)) {
      invalidKindMappings.push(mapping.nodeType);
    }
    if (!(key in regionMap)) missingRegionMappings.push(mapping.nodeType);
    else if (regionMap[key] !== mapping.region || !allowedRegions.has(regionMap[key]!)) {
      invalidRegionMappings.push(mapping.nodeType);
    }
  }
  for (const mapping of OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY) {
    const key = mapping.selector;
    if (!(key in kindMap)) missingKindMappings.push(`operator_profile:${mapping.profileClass}`);
    else if (kindMap[key] !== mapping.kind || !allowedKinds.has(kindMap[key]!)) {
      invalidKindMappings.push(`operator_profile:${mapping.profileClass}`);
    }
    if (!(key in regionMap)) missingRegionMappings.push(`operator_profile:${mapping.profileClass}`);
    else if (regionMap[key] !== mapping.region || !allowedRegions.has(regionMap[key]!)) {
      invalidRegionMappings.push(`operator_profile:${mapping.profileClass}`);
    }
  }
  const failures = [
    ...missingKindMappings,
    ...missingRegionMappings,
    ...invalidKindMappings,
    ...invalidRegionMappings,
  ];
  if (failures.length > 0) {
    throw new Error(`Brain Atlas configuration does not match the attack-memory registry: ${failures.join(", ")}`);
  }
  return {
    valid: true,
    registryNodeTypeCount: ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.length,
    operatorProfileMappingCount: OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY.length,
    kindMappingCount: ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.length
      + OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY.length,
    regionMappingCount: ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.length
      + OPERATOR_PROFILE_BRAIN_ATLAS_MAPPING_REGISTRY.length,
    missingKindMappings,
    missingRegionMappings,
    invalidKindMappings,
    invalidRegionMappings,
  };
}

export function serializeBrainAtlasConfiguration(value: unknown): string {
  const generated = generateBrainAtlasConfiguration(value);
  validateBrainAtlasConfiguration(generated);
  return `${JSON.stringify(generated, null, 2)}\n`;
}

export function brainAtlasConfigurationHash(value: unknown): string {
  return createHash("sha256").update(serializeBrainAtlasConfiguration(value), "utf8").digest("hex");
}

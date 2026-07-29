import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { hashJson } from "../orchestration/serialization";
import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config";
import {
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION,
  HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION,
  HISTORICAL_SOURCE_ROOT_MODES,
  type HistoricalSourceRootConfiguration,
  type HistoricalSourceRootMode,
} from "./HistoricalSourceRootConfiguration";

export const HISTORICAL_SOURCE_DELTA_EXECUTION_PLAN_SCHEMA_VERSION =
  "ti_scale.historical_source_delta_execution_plan/v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_IDENTIFIER = /^[A-Za-z0-9._-]{1,120}$/u;
const MAXIMUM_PLAN_BYTES = 8 * 1024 * 1024;

export type HistoricalDeltaDisposition = "new" | "changed";
export type HistoricalParserEligibility =
  | "semantic_parser_eligible"
  | "custody_only"
  | "quarantined";
export type HistoricalSourceSensitivity =
  | "locally_screened"
  | "local_only_record_sanitization_required"
  | "quarantined_sensitive"
  | "quarantined_oversized"
  | "quarantined_unsafe_name"
  | "non_dereferenced_symlink";

export interface HistoricalSourceDeltaAdmission {
  readonly rootId: string;
  readonly path: string;
  readonly sourceHash: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly sourceDevice: number;
  readonly sourceInode: number;
  readonly classification: string;
  readonly objectKind: "accepted" | "quarantined" | "source" | "symlink";
  readonly parserEligibility: HistoricalParserEligibility;
  readonly sensitivity: HistoricalSourceSensitivity;
  readonly disposition: HistoricalDeltaDisposition;
}

export interface HistoricalSourceDeltaBaselineBinding {
  readonly completedMigrationCount: number;
  readonly sourceObjectCount: number;
  readonly inventoryReceiptCount: number;
  readonly inventoryReceiptSetHash: string;
}

export interface HistoricalSourceDeltaExecutionPlanBody {
  readonly schemaVersion: typeof HISTORICAL_SOURCE_DELTA_EXECUTION_PLAN_SCHEMA_VERSION;
  readonly publicPlanHash: string;
  readonly configuration: {
    readonly schemaVersion: HistoricalSourceRootConfiguration["schemaVersion"];
    readonly version: string;
    readonly sha256: string;
    readonly roots: readonly {
      readonly id: string;
      readonly path: string;
      readonly mode: HistoricalSourceRootMode;
    }[];
  };
  readonly boundary: {
    readonly plannedAt: string;
    readonly settleSeconds: number;
    readonly cutoffAt: string;
  };
  readonly baseline: HistoricalSourceDeltaBaselineBinding;
  readonly delta: {
    readonly files: number;
    readonly bytes: number;
    readonly inventoryHash: string;
  };
  readonly admissions: readonly HistoricalSourceDeltaAdmission[];
  readonly safety: {
    readonly disclosure: "private_local_only";
    readonly exactPathAdmissionRequired: true;
    readonly revalidateEverySource: true;
    readonly failOnConfigurationDrift: true;
    readonly failOnBaselineDrift: true;
    readonly failOnSourceDrift: true;
    readonly activeWriterAdmission: false;
  };
}

export interface HistoricalSourceDeltaExecutionPlan extends HistoricalSourceDeltaExecutionPlanBody {
  readonly planHash: string;
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, label: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as JsonRecord;
}

function exactKeys(value: JsonRecord, keys: readonly string[], label: string): void {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  const missing = keys.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  const unexpected = actual.filter((key) => !expected.has(key));
  if (missing.length || unexpected.length) {
    throw new Error(`${label} has invalid fields`);
  }
}

function text(value: unknown, label: string, maximum = 4_096): string {
  if (typeof value !== "string" || value !== value.trim() || value.length < 1
      || value.length > maximum || /[\u0000-\u001F\u007F]/u.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function digest(value: unknown, label: string): string {
  const result = text(value, label, 64);
  if (!SHA256.test(result)) throw new Error(`${label} must be a lowercase SHA-256`);
  return result;
}

function count(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(value);
}

function timestamp(value: unknown, label: string): string {
  const result = text(value, label, 64);
  if (!Number.isFinite(Date.parse(result)) || new Date(result).toISOString() !== result) {
    throw new Error(`${label} must be a canonical ISO timestamp`);
  }
  return result;
}

function absolutePath(value: unknown, label: string): string {
  const result = text(value, label);
  if (!isAbsolute(result) || resolve(result) !== result || result === resolve(sep)) {
    throw new Error(`${label} must be a normalized absolute path below the filesystem root`);
  }
  return result;
}

function parseBaseline(value: unknown): HistoricalSourceDeltaBaselineBinding {
  const input = record(value, "baseline");
  exactKeys(input, [
    "completedMigrationCount", "inventoryReceiptCount", "inventoryReceiptSetHash",
    "sourceObjectCount",
  ], "baseline");
  return Object.freeze({
    completedMigrationCount: count(input.completedMigrationCount, "baseline.completedMigrationCount"),
    sourceObjectCount: count(input.sourceObjectCount, "baseline.sourceObjectCount"),
    inventoryReceiptCount: count(input.inventoryReceiptCount, "baseline.inventoryReceiptCount"),
    inventoryReceiptSetHash: digest(input.inventoryReceiptSetHash, "baseline.inventoryReceiptSetHash"),
  });
}

function parseAdmission(value: unknown, index: number): HistoricalSourceDeltaAdmission {
  const label = `admissions[${index}]`;
  const input = record(value, label);
  exactKeys(input, [
    "byteSize", "classification", "disposition", "modifiedAt", "objectKind", "parserEligibility",
    "path", "rootId", "sensitivity", "sourceDevice", "sourceHash", "sourceInode",
  ], label);
  const rootId = text(input.rootId, `${label}.rootId`, 120);
  if (!SAFE_IDENTIFIER.test(rootId)) throw new Error(`${label}.rootId is invalid`);
  const objectKinds = ["accepted", "quarantined", "source", "symlink"] as const;
  const parserEligibility = ["semantic_parser_eligible", "custody_only", "quarantined"] as const;
  const sensitivity = [
    "locally_screened", "local_only_record_sanitization_required", "quarantined_sensitive",
    "quarantined_oversized", "quarantined_unsafe_name", "non_dereferenced_symlink",
  ] as const;
  if (!objectKinds.includes(input.objectKind as (typeof objectKinds)[number])) {
    throw new Error(`${label}.objectKind is invalid`);
  }
  if (!parserEligibility.includes(input.parserEligibility as (typeof parserEligibility)[number])) {
    throw new Error(`${label}.parserEligibility is invalid`);
  }
  if (!sensitivity.includes(input.sensitivity as (typeof sensitivity)[number])) {
    throw new Error(`${label}.sensitivity is invalid`);
  }
  if (input.disposition !== "new" && input.disposition !== "changed") {
    throw new Error(`${label}.disposition is invalid`);
  }
  return Object.freeze({
    rootId,
    path: absolutePath(input.path, `${label}.path`),
    sourceHash: digest(input.sourceHash, `${label}.sourceHash`),
    byteSize: count(input.byteSize, `${label}.byteSize`),
    modifiedAt: timestamp(input.modifiedAt, `${label}.modifiedAt`),
    sourceDevice: count(input.sourceDevice, `${label}.sourceDevice`),
    sourceInode: count(input.sourceInode, `${label}.sourceInode`),
    classification: text(input.classification, `${label}.classification`, 160),
    objectKind: input.objectKind as HistoricalSourceDeltaAdmission["objectKind"],
    parserEligibility: input.parserEligibility as HistoricalParserEligibility,
    sensitivity: input.sensitivity as HistoricalSourceSensitivity,
    disposition: input.disposition,
  });
}

export function parseHistoricalSourceDeltaExecutionPlan(
  value: unknown,
): HistoricalSourceDeltaExecutionPlan {
  const input = record(value, "Historical source delta execution plan");
  exactKeys(input, [
    "admissions", "baseline", "boundary", "configuration", "delta", "planHash",
    "publicPlanHash", "safety", "schemaVersion",
  ], "Historical source delta execution plan");
  if (input.schemaVersion !== HISTORICAL_SOURCE_DELTA_EXECUTION_PLAN_SCHEMA_VERSION) {
    throw new Error("Historical source delta execution plan schemaVersion is unsupported");
  }
  const configuration = record(input.configuration, "configuration");
  exactKeys(configuration, ["roots", "schemaVersion", "sha256", "version"], "configuration");
  if (configuration.schemaVersion !== HISTORICAL_SOURCE_ROOT_CONFIGURATION_SCHEMA_VERSION
      && configuration.schemaVersion !== HISTORICAL_SOURCE_ROOT_CONFIGURATION_V2_SCHEMA_VERSION) {
    throw new Error("configuration.schemaVersion is invalid");
  }
  if (!Array.isArray(configuration.roots) || configuration.roots.length < 1 || configuration.roots.length > 64) {
    throw new Error("configuration.roots must contain one to 64 roots");
  }
  const roots = configuration.roots.map((value, index) => {
    const root = record(value, `configuration.roots[${index}]`);
    exactKeys(root, ["id", "mode", "path"], `configuration.roots[${index}]`);
    const id = text(root.id, `configuration.roots[${index}].id`, 120);
    if (!SAFE_IDENTIFIER.test(id)) throw new Error(`configuration.roots[${index}].id is invalid`);
    if (!HISTORICAL_SOURCE_ROOT_MODES.includes(root.mode as HistoricalSourceRootMode)) {
      throw new Error(`configuration.roots[${index}].mode is invalid`);
    }
    return Object.freeze({
      id,
      path: absolutePath(root.path, `configuration.roots[${index}].path`),
      mode: root.mode as HistoricalSourceRootMode,
    });
  });
  if (new Set(roots.map(({ id }) => id)).size !== roots.length
      || new Set(roots.map(({ path }) => path)).size !== roots.length) {
    throw new Error("configuration.roots contains duplicates");
  }
  const boundary = record(input.boundary, "boundary");
  exactKeys(boundary, ["cutoffAt", "plannedAt", "settleSeconds"], "boundary");
  const settleSeconds = count(boundary.settleSeconds, "boundary.settleSeconds");
  if (settleSeconds < 60 || settleSeconds > 86_400) {
    throw new Error("boundary.settleSeconds is outside the safe range");
  }
  const plannedAt = timestamp(boundary.plannedAt, "boundary.plannedAt");
  const cutoffAt = timestamp(boundary.cutoffAt, "boundary.cutoffAt");
  if (new Date(Date.parse(plannedAt) - settleSeconds * 1_000).toISOString() !== cutoffAt) {
    throw new Error("boundary.cutoffAt does not match plannedAt and settleSeconds");
  }
  const delta = record(input.delta, "delta");
  exactKeys(delta, ["bytes", "files", "inventoryHash"], "delta");
  if (!Array.isArray(input.admissions) || input.admissions.length > 100_000) {
    throw new Error("admissions must be an array of at most 100000 entries");
  }
  const admissions = input.admissions.map(parseAdmission).sort((left, right) =>
    left.rootId.localeCompare(right.rootId) || left.path.localeCompare(right.path));
  if (new Set(admissions.map(({ path }) => path)).size !== admissions.length) {
    throw new Error("admissions contains duplicate paths");
  }
  const files = count(delta.files, "delta.files");
  const bytes = count(delta.bytes, "delta.bytes");
  if (files !== admissions.length
      || bytes !== admissions.reduce((sum, admission) => sum + admission.byteSize, 0)) {
    throw new Error("delta counts do not match admissions");
  }
  const rootIds = new Set(roots.map(({ id }) => id));
  if (admissions.some(({ rootId }) => !rootIds.has(rootId))) {
    throw new Error("admissions references an unknown rootId");
  }
  const safety = record(input.safety, "safety");
  exactKeys(safety, [
    "activeWriterAdmission", "disclosure", "exactPathAdmissionRequired", "failOnBaselineDrift",
    "failOnConfigurationDrift", "failOnSourceDrift", "revalidateEverySource",
  ], "safety");
  if (safety.disclosure !== "private_local_only"
      || safety.exactPathAdmissionRequired !== true
      || safety.revalidateEverySource !== true
      || safety.failOnConfigurationDrift !== true
      || safety.failOnBaselineDrift !== true
      || safety.failOnSourceDrift !== true
      || safety.activeWriterAdmission !== false) {
    throw new Error("safety contract is invalid");
  }
  const body: HistoricalSourceDeltaExecutionPlanBody = Object.freeze({
    schemaVersion: HISTORICAL_SOURCE_DELTA_EXECUTION_PLAN_SCHEMA_VERSION,
    publicPlanHash: digest(input.publicPlanHash, "publicPlanHash"),
    configuration: Object.freeze({
      schemaVersion: configuration.schemaVersion as HistoricalSourceRootConfiguration["schemaVersion"],
      version: text(configuration.version, "configuration.version", 80),
      sha256: digest(configuration.sha256, "configuration.sha256"),
      roots: Object.freeze(roots),
    }),
    boundary: Object.freeze({ plannedAt, settleSeconds, cutoffAt }),
    baseline: parseBaseline(input.baseline),
    delta: Object.freeze({
      files,
      bytes,
      inventoryHash: digest(delta.inventoryHash, "delta.inventoryHash"),
    }),
    admissions: Object.freeze(admissions),
    safety: Object.freeze({
      disclosure: "private_local_only" as const,
      exactPathAdmissionRequired: true as const,
      revalidateEverySource: true as const,
      failOnConfigurationDrift: true as const,
      failOnBaselineDrift: true as const,
      failOnSourceDrift: true as const,
      activeWriterAdmission: false as const,
    }),
  });
  const planHash = digest(input.planHash, "planHash");
  if (hashJson(body) !== planHash) throw new Error("Historical source delta execution plan self-hash mismatch");
  return Object.freeze({ ...body, planHash });
}

export function createHistoricalSourceDeltaExecutionPlan(
  body: HistoricalSourceDeltaExecutionPlanBody,
): HistoricalSourceDeltaExecutionPlan {
  return parseHistoricalSourceDeltaExecutionPlan({ ...body, planHash: hashJson(body) });
}

export function historicalDeltaAdmissionInventoryHash(
  admissions: readonly HistoricalSourceDeltaAdmission[],
): string {
  return hashJson(admissions.map((item) => ({
    rootId: item.rootId,
    pathIdentity: createHash("sha256").update(`${item.rootId}\0${item.path}`, "utf8").digest("hex"),
    sourceHash: item.sourceHash,
    byteSize: item.byteSize,
    classification: item.classification,
    objectKind: item.objectKind,
    parserEligibility: item.parserEligibility,
    sensitivity: item.sensitivity,
  })).sort((left, right) =>
    left.rootId.localeCompare(right.rootId)
    || left.pathIdentity.localeCompare(right.pathIdentity)
    || left.sourceHash.localeCompare(right.sourceHash)));
}

function isInside(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

export function sealHistoricalSourceDeltaExecutionPlan(input: {
  readonly path: string;
  readonly plan: HistoricalSourceDeltaExecutionPlan;
  readonly sourceRoots: readonly string[];
}): { readonly sourceSha256: string; readonly planHash: string; readonly byteSize: number; readonly mode: "0600" } {
  const path = resolve(input.path);
  if (input.sourceRoots.some((root) => isInside(realpathSync(resolve(root)), path))) {
    throw new Error("Private delta plan must be outside every historical source root");
  }
  const parent = dirname(path);
  const parentState = lstatSync(parent);
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  if (!parentState.isDirectory() || parentState.isSymbolicLink() || realpathSync(parent) !== parent
      || ![0, currentUid].includes(parentState.uid) || (parentState.mode & 0o022) !== 0) {
    throw new Error("Private delta plan parent must be a trusted non-writable real directory");
  }
  const bytes = Buffer.from(`${JSON.stringify(input.plan, null, 2)}\n`, "utf8");
  if (bytes.length > MAXIMUM_PLAN_BYTES) throw new Error("Private delta plan exceeds 8 MiB");
  const descriptor = openSync(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
    0o600,
  );
  try {
    writeFileSync(descriptor, bytes);
    fchmodSync(descriptor, 0o600);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  const state = statSync(path);
  if ((state.mode & 0o777) !== 0o600) throw new Error("Private delta plan mode is not 0600");
  return Object.freeze({
    sourceSha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
    planHash: input.plan.planHash,
    byteSize: state.size,
    mode: "0600" as const,
  });
}

export function loadTrustedHistoricalSourceDeltaExecutionPlan(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<HistoricalSourceDeltaExecutionPlan> {
  const loaded = loadTrustedJson(
    { ...reference, maximumBytes: MAXIMUM_PLAN_BYTES },
    parseHistoricalSourceDeltaExecutionPlan,
  );
  if (loaded.receipt.mode !== 0o600) {
    throw new Error("Historical source delta execution plan mode must be 0600");
  }
  return loaded;
}

export function assertHistoricalSourceDeltaPlanConfiguration(input: {
  readonly plan: HistoricalSourceDeltaExecutionPlan;
  readonly configuration: HistoricalSourceRootConfiguration;
  readonly configurationSha256: string;
}): void {
  if (input.plan.configuration.sha256 !== input.configurationSha256
      || input.plan.configuration.schemaVersion !== input.configuration.schemaVersion
      || input.plan.configuration.version !== input.configuration.configurationVersion) {
    throw new Error("Reviewed delta plan configuration binding does not match the loaded configuration");
  }
  const configuredRoots = input.configuration.roots.map(({ id, path, mode }) => ({ id, path, mode }));
  if (hashJson(configuredRoots) !== hashJson(input.plan.configuration.roots)) {
    throw new Error("Reviewed delta plan root binding does not match the loaded configuration");
  }
}

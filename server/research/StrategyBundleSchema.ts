import { canonicalJson, deepFreeze, hashCanonical, type JsonPrimitive, type JsonValue } from "./canonical";

export interface StrategyBundle {
  readonly schemaVersion: "1";
  readonly loopControl: {
    readonly maxIdenticalFingerprints: number;
    readonly noProgressActionLimit: number;
    readonly maxAutomaticReplans: number;
    readonly transientRetryLimit: number;
  };
  readonly specialistRouting: {
    readonly minimumCapabilityScore: number;
    readonly maxConcurrentAssignments: number;
    readonly handoffPenalty: number;
    readonly preferSpecialists: boolean;
  };
  readonly memoryRetrieval: {
    readonly maxContextItems: number;
    readonly minimumConfidence: number;
    readonly recencyWeight: number;
    readonly graphWeight: number;
    readonly lexicalWeight: number;
  };
  readonly planDecomposition: {
    readonly maxSteps: number;
    readonly maxDepth: number;
    readonly maxParallelBranches: number;
  };
  readonly evidenceStrategy: {
    readonly candidateConfidenceFloor: number;
    readonly requireCrossSourceForHighSeverity: boolean;
  };
  readonly reportStructure: {
    readonly maxExecutiveFindings: number;
    readonly includeEvidenceCoverage: boolean;
  };
  readonly providerRouting: {
    readonly latencyWeight: number;
    readonly costWeight: number;
    readonly qualityWeight: number;
  };
  readonly safety: {
    readonly authorizationScopeMode: "signed_contract_only";
    readonly toolAllowlistMode: "immutable";
    readonly destructiveActionPolicy: "immutable";
    readonly secretHandling: "local_policy_only";
    readonly providerDisclosurePolicy: "immutable";
    readonly evidenceIntegrity: "immutable";
    readonly approvalRules: "immutable";
    readonly auditRetention: "append_only";
    readonly evaluatorAndBenchmark: "immutable";
    readonly deployment: "human_only";
    readonly productionSourceCode: "immutable";
    readonly engagementIsolation: true;
    readonly commanderDirectExecutionAllowed: false;
  };
}

export const DEFAULT_STRATEGY_BUNDLE: StrategyBundle = deepFreeze({
  schemaVersion: "1",
  loopControl: {
    maxIdenticalFingerprints: 3,
    noProgressActionLimit: 3,
    maxAutomaticReplans: 2,
    transientRetryLimit: 2,
  },
  specialistRouting: {
    minimumCapabilityScore: 0.7,
    maxConcurrentAssignments: 4,
    handoffPenalty: 0.1,
    preferSpecialists: true,
  },
  memoryRetrieval: {
    maxContextItems: 12,
    minimumConfidence: 0.65,
    recencyWeight: 0.3,
    graphWeight: 0.4,
    lexicalWeight: 0.3,
  },
  planDecomposition: {
    maxSteps: 32,
    maxDepth: 6,
    maxParallelBranches: 4,
  },
  evidenceStrategy: {
    candidateConfidenceFloor: 0.7,
    requireCrossSourceForHighSeverity: true,
  },
  reportStructure: {
    maxExecutiveFindings: 8,
    includeEvidenceCoverage: true,
  },
  providerRouting: {
    latencyWeight: 0.25,
    costWeight: 0.25,
    qualityWeight: 0.5,
  },
  safety: {
    authorizationScopeMode: "signed_contract_only",
    toolAllowlistMode: "immutable",
    destructiveActionPolicy: "immutable",
    secretHandling: "local_policy_only",
    providerDisclosurePolicy: "immutable",
    evidenceIntegrity: "immutable",
    approvalRules: "immutable",
    auditRetention: "append_only",
    evaluatorAndBenchmark: "immutable",
    deployment: "human_only",
    productionSourceCode: "immutable",
    engagementIsolation: true,
    commanderDirectExecutionAllowed: false,
  },
});

export const MUTABLE_STRATEGY_PATHS = [
  "/loopControl/maxIdenticalFingerprints",
  "/loopControl/noProgressActionLimit",
  "/loopControl/maxAutomaticReplans",
  "/loopControl/transientRetryLimit",
  "/specialistRouting/minimumCapabilityScore",
  "/specialistRouting/maxConcurrentAssignments",
  "/specialistRouting/handoffPenalty",
  "/specialistRouting/preferSpecialists",
  "/memoryRetrieval/maxContextItems",
  "/memoryRetrieval/minimumConfidence",
  "/memoryRetrieval/recencyWeight",
  "/memoryRetrieval/graphWeight",
  "/memoryRetrieval/lexicalWeight",
  "/planDecomposition/maxSteps",
  "/planDecomposition/maxDepth",
  "/planDecomposition/maxParallelBranches",
  "/evidenceStrategy/candidateConfidenceFloor",
  "/evidenceStrategy/requireCrossSourceForHighSeverity",
  "/reportStructure/maxExecutiveFindings",
  "/reportStructure/includeEvidenceCoverage",
  "/providerRouting/latencyWeight",
  "/providerRouting/costWeight",
  "/providerRouting/qualityWeight",
] as const;

export type MutableStrategyPath = (typeof MUTABLE_STRATEGY_PATHS)[number];

export const FORBIDDEN_STRATEGY_PATH_PREFIXES = [
  "/safety",
  "/authorization",
  "/authorizationScope",
  "/toolAllowlist",
  "/toolAllowlists",
  "/destructiveActionPolicy",
  "/secretHandling",
  "/providerDisclosurePolicy",
  "/evidenceIntegrity",
  "/approvalRules",
  "/auditRetention",
  "/evaluator",
  "/benchmark",
  "/deployment",
  "/productionSource",
  "/productionSourceCode",
] as const;

export interface StrategyPatchOperation {
  readonly op: "replace" | "test";
  readonly path: MutableStrategyPath;
  readonly value: JsonPrimitive;
}

export interface StrategyPatchViolation {
  readonly index: number;
  readonly code:
    | "invalid_operation"
    | "invalid_path"
    | "forbidden_path"
    | "dimension_not_approved"
    | "invalid_value"
    | "test_failed"
    | "bundle_invalid";
  readonly message: string;
}

export interface StrategyPatchValidation {
  readonly valid: boolean;
  readonly normalizedPatch: readonly StrategyPatchOperation[];
  readonly violations: readonly StrategyPatchViolation[];
}

export interface StrategyPatchPolicy {
  readonly approvedMutablePaths: readonly MutableStrategyPath[];
  readonly forbiddenPathPrefixes?: readonly string[];
  readonly maxOperations: number;
}

const mutablePathSet = new Set<string>(MUTABLE_STRATEGY_PATHS);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isForbiddenPath(path: string, extra: readonly string[]): boolean {
  if (path.includes("__proto__") || path.includes("constructor") || path.includes("prototype")) {
    return true;
  }
  return [...FORBIDDEN_STRATEGY_PATH_PREFIXES, ...extra].some(
    (prefix) => path === prefix || path.startsWith(`${prefix}/`),
  );
}

function valueRule(path: MutableStrategyPath, value: unknown): string | undefined {
  const integer = (minimum: number, maximum: number): string | undefined =>
    typeof value === "number" && Number.isSafeInteger(value) && value >= minimum && value <= maximum
      ? undefined
      : `Value must be an integer from ${minimum} through ${maximum}.`;
  const ratio = (): string | undefined =>
    typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1
      ? undefined
      : "Value must be a finite number from 0 through 1.";

  switch (path) {
    case "/loopControl/maxIdenticalFingerprints": return integer(1, 5);
    case "/loopControl/noProgressActionLimit": return integer(1, 10);
    case "/loopControl/maxAutomaticReplans": return integer(0, 5);
    case "/loopControl/transientRetryLimit": return integer(0, 5);
    case "/specialistRouting/maxConcurrentAssignments": return integer(1, 16);
    case "/memoryRetrieval/maxContextItems": return integer(1, 32);
    case "/planDecomposition/maxSteps": return integer(1, 100);
    case "/planDecomposition/maxDepth": return integer(1, 10);
    case "/planDecomposition/maxParallelBranches": return integer(1, 16);
    case "/reportStructure/maxExecutiveFindings": return integer(1, 50);
    case "/specialistRouting/preferSpecialists":
    case "/evidenceStrategy/requireCrossSourceForHighSeverity":
    case "/reportStructure/includeEvidenceCoverage":
      return typeof value === "boolean" ? undefined : "Value must be boolean.";
    default:
      return ratio();
  }
}

export function validateStrategyPatch(
  input: unknown,
  policy: StrategyPatchPolicy,
): StrategyPatchValidation {
  const violations: StrategyPatchViolation[] = [];
  const normalizedPatch: StrategyPatchOperation[] = [];
  if (!Array.isArray(input)) {
    return {
      valid: false,
      normalizedPatch,
      violations: [{ index: -1, code: "invalid_operation", message: "JSON Patch must be an array." }],
    };
  }
  if (input.length === 0 || input.length > policy.maxOperations) {
    violations.push({
      index: -1,
      code: "invalid_operation",
      message: `Patch must contain 1 through ${policy.maxOperations} operations.`,
    });
  }
  const approved = new Set<string>(policy.approvedMutablePaths);
  const replacedPaths = new Set<string>();
  for (const [index, raw] of input.entries()) {
    if (!isRecord(raw) || (raw.op !== "replace" && raw.op !== "test")) {
      violations.push({
        index,
        code: "invalid_operation",
        message: "Only JSON Patch replace and test operations are permitted.",
      });
      continue;
    }
    if (typeof raw.path !== "string" || !raw.path.startsWith("/")) {
      violations.push({ index, code: "invalid_path", message: "Patch path must be a JSON Pointer." });
      continue;
    }
    if (isForbiddenPath(raw.path, policy.forbiddenPathPrefixes ?? [])) {
      violations.push({
        index,
        code: "forbidden_path",
        message: `Patch path ${raw.path} is an immutable safety or evaluation surface.`,
      });
      continue;
    }
    if (!mutablePathSet.has(raw.path)) {
      violations.push({
        index,
        code: "invalid_path",
        message: `Patch path ${raw.path} is not in the typed StrategyBundle mutable surface.`,
      });
      continue;
    }
    if (!approved.has(raw.path)) {
      violations.push({
        index,
        code: "dimension_not_approved",
        message: `Patch path ${raw.path} is outside the approved research dimension.`,
      });
      continue;
    }
    const path = raw.path as MutableStrategyPath;
    if (raw.op === "replace" && replacedPaths.has(path)) {
      violations.push({
        index,
        code: "invalid_operation",
        message: `Patch may replace ${path} only once; use one explicit candidate value.`,
      });
      continue;
    }
    const valueViolation = valueRule(path, raw.value);
    if (valueViolation !== undefined) {
      violations.push({ index, code: "invalid_value", message: valueViolation });
      continue;
    }
    if (raw.op === "replace") replacedPaths.add(path);
    normalizedPatch.push({ op: raw.op, path, value: raw.value as JsonPrimitive });
  }
  return { valid: violations.length === 0, normalizedPatch, violations };
}

function readPath(bundle: StrategyBundle, path: MutableStrategyPath): JsonPrimitive {
  const [section, property] = path.slice(1).split("/") as [keyof StrategyBundle, string];
  const value = (bundle[section] as unknown as Record<string, JsonPrimitive>)[property];
  return value;
}

function writePath(bundle: StrategyBundle, path: MutableStrategyPath, value: JsonPrimitive): void {
  const [section, property] = path.slice(1).split("/") as [keyof StrategyBundle, string];
  (bundle[section] as unknown as Record<string, JsonPrimitive>)[property] = value;
}

export function validateStrategyBundle(bundle: StrategyBundle): readonly string[] {
  const errors: string[] = [];
  if (bundle.schemaVersion !== "1") errors.push("Unsupported StrategyBundle schema version.");
  for (const path of MUTABLE_STRATEGY_PATHS) {
    const violation = valueRule(path, readPath(bundle, path));
    if (violation !== undefined) errors.push(`${path}: ${violation}`);
  }
  if (
    bundle.memoryRetrieval.recencyWeight +
      bundle.memoryRetrieval.graphWeight +
      bundle.memoryRetrieval.lexicalWeight <=
    0
  ) {
    errors.push("Memory retrieval weights must have a positive sum.");
  }
  if (
    bundle.providerRouting.latencyWeight +
      bundle.providerRouting.costWeight +
      bundle.providerRouting.qualityWeight <=
    0
  ) {
    errors.push("Provider routing weights must have a positive sum.");
  }
  if (canonicalJson(bundle.safety as unknown as JsonValue) !== canonicalJson(DEFAULT_STRATEGY_BUNDLE.safety as unknown as JsonValue)) {
    errors.push("Strategy safety invariants differ from the immutable baseline.");
  }
  return errors;
}

export interface AppliedStrategyPatch {
  readonly bundle: StrategyBundle;
  readonly bundleHash: string;
  readonly patchHash: string;
}

export function applyStrategyPatch(
  baseline: StrategyBundle,
  input: unknown,
  policy: StrategyPatchPolicy,
): AppliedStrategyPatch {
  const validation = validateStrategyPatch(input, policy);
  if (!validation.valid) {
    throw new Error(`Strategy patch rejected: ${validation.violations.map(({ message }) => message).join("; ")}`);
  }
  const next = structuredClone(baseline) as StrategyBundle;
  for (const [index, operation] of validation.normalizedPatch.entries()) {
    if (operation.op === "test") {
      if (!Object.is(readPath(next, operation.path), operation.value)) {
        throw new Error(`Strategy patch test failed at operation ${index} for ${operation.path}.`);
      }
      continue;
    }
    writePath(next, operation.path, operation.value);
  }
  const errors = validateStrategyBundle(next);
  if (errors.length > 0) throw new Error(`Strategy bundle rejected: ${errors.join("; ")}`);
  const frozen = deepFreeze(next);
  return {
    bundle: frozen,
    bundleHash: hashCanonical(frozen as unknown as JsonValue),
    patchHash: hashCanonical(validation.normalizedPatch as unknown as JsonValue),
  };
}

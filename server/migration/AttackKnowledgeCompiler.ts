import { createHash, createHmac, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  ATTACK_CENTRIC_EDGE_TYPES,
  attackKnowledgeOperationalLocatorCategories,
  findReusableMemorySecretCategories,
  isAttackCentricReusableNodeType,
  MemoryRepository,
  memoryContentHash,
  validateAttackCentricReusableNode,
  validateAttackCentricEdgeEndpoints,
  type AttackCentricEdgeType,
  type AttackCentricReusableNodeType,
  type CreateMemoryCandidateInput,
  type MemoryNodeType,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";

type Primitive = string | number | boolean;
type SourceClass = "current" | "historical";
type StackNodeType = Extract<AttackCentricReusableNodeType,
  "operating_system" | "kernel" | "framework" | "runtime" | "database" |
  "firewall" | "waf" | "proxy" | "security_control" | "topology_pattern" |
  "topology_role">;

const STACK_TYPES: ReadonlySet<string> = new Set([
  "operating_system", "kernel", "framework", "runtime", "database",
  "firewall", "waf", "proxy", "security_control",
]);
const SHA256 = /^[a-f0-9]{64}$/u;
const ABSOLUTE_PATH = /(?:^|\s)(?:\/(?:[^/\s]+\/)+[^\s]+|[A-Za-z]:\\[^\r\n]+)/u;
const HOSTISH = /\b(?:host|server|node|web|db|dc|client|target|box)[-_]?\d+\b/iu;
const DOMAIN = /\b(?:[a-z0-9-]+\.)+(?:internal|local|lan|htb|com|net|org|io|dev|app|cloud|corp)\b/iu;
const JOURNEY = /\b(?:autonomous|guided)\s+(?:mission|run|journey|mode)\b/iu;
const FORBIDDEN_KEYS = new Set([
  "target", "targetid", "targetname", "targetip", "ip", "ipaddress", "cidr",
  "hostname", "domain", "box", "boxname", "client", "clientname", "customer",
  "engagement", "engagementid", "mission", "missionid", "run", "runid", "journey",
  "rawlog", "rawoutput", "commandoutput", "credential", "credentials", "secret",
  "password", "token", "cookie",
]);

export interface AttackKnowledgePrivateSource {
  /** Read only while deriving a keyed receipt; never persisted or returned. */
  readonly privateSourceReference: string;
  /** Optional private labels used only to prevent those labels entering reusable content. */
  readonly privateLabels?: readonly string[];
  readonly sourceClass: SourceClass;
  readonly sourceHash: string;
  readonly observedAt: string;
  readonly evidenceCount: number;
  /** Private canonical evidence bindings; IDs never enter reusable node content. */
  readonly canonicalEvidenceIds?: readonly string[];
}

export interface OperationalHazardKnowledge {
  readonly kind: "operational_hazard";
  readonly product: { readonly name: string; readonly exactVersion: string };
  readonly stack: readonly {
    readonly nodeType: StackNodeType;
    readonly name: string;
    readonly exactVersion: string;
  }[];
  readonly procedure: {
    readonly name: string;
    readonly version: string;
    readonly orderedSteps: readonly string[];
    readonly normalizedParameters: Readonly<Record<string, Primitive>>;
    readonly prerequisites: readonly string[];
  };
  /** Reusable execution artifacts. Paths and target-bound configuration are forbidden. */
  readonly scriptArtifacts?: readonly {
    readonly name: string;
    readonly version: string;
    readonly contentHash: string;
    readonly language: string;
    readonly purpose: string;
  }[];
  /** Evidence-backed observations that remain useful when the target identity changes. */
  readonly discoveries?: readonly {
    readonly name: string;
    readonly summary: string;
    readonly evidenceContentHashes: readonly string[];
  }[];
  /**
   * Reported worked/failed results. These remain supporting/unclassified
   * until linked to a canonical terminal AttackAttempt and verified evidence.
   * Failures can still carry a reusable failure mechanism.
   */
  readonly outcomes?: readonly {
    readonly name: string;
    readonly status: "worked" | "failed";
    readonly summary: string;
    readonly evidenceContentHashes: readonly string[];
    readonly failureMode?: string;
  }[];
  readonly hazard: {
    readonly name: string;
    readonly observedSymptom: string;
    readonly affectedComponent: string;
    readonly unaffectedComponents?: readonly string[];
    readonly survivingHealthSignals?: readonly string[];
    readonly stateBefore: string;
    readonly stateAfter: string;
    readonly unsafeRetryConditions: readonly string[];
    readonly healthGate: readonly string[];
    readonly retryValidConditions?: readonly string[];
    readonly recoveryActionSummary: string;
    readonly recoveryCost?: {
      readonly exactProcedureResetCount?: number;
      readonly operatorReportedResetCountMinimum?: number;
      readonly serviceRecycleCount?: number;
      readonly downtimeMs?: number;
      readonly operatorMinutes?: number;
      readonly requiresDisposableTargetReset?: boolean;
    };
    readonly saferAlternative: {
      readonly name: string;
      readonly orderedSteps: readonly string[];
      readonly reviewedBinding?: {
        readonly version: string;
        readonly normalizedParameters: Readonly<Record<string, Primitive>>;
        readonly sourceLoad?: number;
        readonly sourceConcurrency?: number;
        readonly sourceTimingWindowMs?: number;
        readonly load?: number;
        readonly concurrency?: number;
        readonly timingWindowMs?: number;
      };
      readonly retryConditionEvidence?: readonly {
        readonly statement: string;
        readonly evidenceKey: string;
      }[];
    };
    readonly loadMinimum?: number;
    readonly concurrencyMinimum?: number;
    readonly timingWindowMs?: number;
    readonly freshUntil?: string;
  };
  readonly corroboration: {
    readonly exactProcedureAttemptCount: number;
    readonly exactProcedureReproducibilityCount: number;
    readonly exactProcedureEvidenceCount: number;
  };
}

/** General reusable facts use the same receipt without procedure-only counts. */
export interface ReusableAttackFactKnowledge {
  readonly kind: "reusable_fact";
  readonly nodeType: AttackCentricReusableNodeType;
  readonly title: string;
  readonly summary: string;
  readonly body?: string;
}

/**
 * A bounded, evidence-derived set of reusable facts whose relationships were
 * observed in one hash-verified source. Roles are local to this bundle. The
 * compiler validates every endpoint and never joins facts across source files.
 */
export interface ReusableAttackBundleKnowledge {
  readonly kind: "reusable_bundle";
  readonly facts: readonly {
    readonly role: string;
    readonly nodeType: AttackCentricReusableNodeType;
    readonly title: string;
    readonly summary: string;
    readonly body?: string;
  }[];
  readonly edges: readonly {
    readonly sourceRole: string;
    readonly edgeType: AttackCentricEdgeType;
    readonly targetRole: string;
  }[];
}

export interface AttackKnowledgeCompilerInput {
  readonly source: AttackKnowledgePrivateSource;
  readonly knowledge: OperationalHazardKnowledge | ReusableAttackFactKnowledge | ReusableAttackBundleKnowledge;
  readonly confidence: number;
}

export interface AttackKnowledgeReconciliation {
  readonly bundleCount: number;
  readonly receiptCount: number;
  readonly bundleReceiptCount: number;
  readonly candidateRegistryCount: number;
  readonly bundleCandidateCount: number;
  readonly edgeProposalCount: number;
  readonly pendingCandidateCount: number;
  readonly reviewedCandidateCount: number;
  readonly interruptedRunCount: number;
  readonly quarantineCount: number;
  readonly orphanedCandidateLinks: number;
}

export interface AttackKnowledgeCompileResult {
  readonly status: "dry_run" | "staged" | "quarantined";
  readonly dryRun: boolean;
  readonly bundleFingerprint?: string;
  readonly bundleId?: string;
  readonly provenanceReceiptId?: string;
  readonly candidateIds: readonly string[];
  readonly candidatesCreated: number;
  readonly candidatesReused: number;
  readonly edgeProposalsStaged: number;
  readonly reasonCategories?: readonly string[];
  readonly exactProcedureCounts: {
    readonly attempts: number;
    readonly reproducibleOutcomes: number;
    readonly evidenceItems: number;
    readonly exactResets: number;
    readonly operatorReportedAggregateResetMinimum: number | null;
  };
  readonly reconciliation: AttackKnowledgeReconciliation;
}

/**
 * One compiler result produced inside an explicitly bounded historical-import
 * batch. Global reconciliation is deliberately absent until the batch closes;
 * callers receive the exact final snapshot from `finish()` instead.
 */
export type AttackKnowledgeDeferredCompileResult = Omit<AttackKnowledgeCompileResult, "reconciliation">;

export interface AttackKnowledgeDeferredReconciliationResult {
  readonly reconciliation: AttackKnowledgeReconciliation;
  readonly compilations: number;
  readonly compilerRunsReconciled: number;
  readonly reconciliationPasses: 1;
}

export interface AttackKnowledgeDeferredReconciliationBatch {
  readonly maxCompilations: number;
  compile(
    raw: unknown,
    options?: { readonly dryRun?: boolean; readonly interruptAfterCandidateWrites?: number },
  ): AttackKnowledgeDeferredCompileResult;
  /** Close the batch exactly once and perform its single global reconciliation. */
  finish(): AttackKnowledgeDeferredReconciliationResult;
}

type AttackKnowledgeCompilationMode =
  | { readonly kind: "immediate" }
  | {
    readonly kind: "deferred";
    readonly reconciliationMarker: string;
    readonly recordCompilerRun: (runId: string) => void;
  };

export class AttackKnowledgeCompilerInterruptedError extends Error {
  constructor(
    readonly bundleFingerprint: string,
    readonly checkpointOrdinal: number,
  ) {
    super("Attack knowledge compilation was interrupted after a durable checkpoint");
    this.name = "AttackKnowledgeCompilerInterruptedError";
  }
}

class CompilerInputError extends TypeError {
  constructor(readonly categories: readonly string[]) {
    super("Private engagement knowledge did not pass the reusable-memory boundary");
    this.name = "CompilerInputError";
  }
}

interface NormalizedSource {
  readonly privateSourceReference: string;
  readonly privateLabels: readonly string[];
  readonly sourceClass: SourceClass;
  readonly sourceHash: string;
  readonly observedAt: string;
  readonly evidenceCount: number;
  readonly canonicalEvidenceIds: readonly string[];
}

interface NormalizedInput {
  readonly source: NormalizedSource;
  readonly knowledge: OperationalHazardKnowledge | ReusableAttackFactKnowledge | ReusableAttackBundleKnowledge;
  readonly confidence: number;
}

interface CandidateBlueprint {
  readonly role: string;
  readonly input: Omit<CreateMemoryCandidateInput, "id">;
}

interface EdgeProposal {
  readonly sourceRole: string;
  readonly edgeType: AttackCentricEdgeType;
  readonly targetRole: string;
}

interface AggregateCounts {
  readonly attempts: number;
  readonly reproducibleOutcomes: number;
  readonly evidenceItems: number;
  readonly exactResets: number;
  readonly operatorReportedAggregateResetMinimum: number | null;
}

interface BundleRow {
  readonly id: string;
  readonly status: "staged" | "materialized";
  readonly exact_procedure_attempt_count: number;
  readonly exact_procedure_reproducibility_count: number;
  readonly exact_procedure_evidence_count: number;
  readonly exact_procedure_reset_count: number;
  readonly operator_reported_reset_count_minimum: number | null;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeString(value: unknown, category = "invalid_structure"): string {
  if (typeof value !== "string" || !value.trim()) throw new CompilerInputError([category]);
  return value.trim().normalize("NFKC");
}

function integer(value: unknown, minimum: number, category = "invalid_count"): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum) throw new CompilerInputError([category]);
  return Number(value);
}

function optionalInteger(value: unknown, minimum: number): number | undefined {
  if (value === undefined) return undefined;
  return integer(value, minimum);
}

function optionalFinite(value: unknown, minimum: number): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum) {
    throw new CompilerInputError(["invalid_count"]);
  }
  return value;
}

function timestamp(value: unknown): string {
  const parsed = Date.parse(normalizeString(value, "invalid_timestamp"));
  if (!Number.isFinite(parsed)) throw new CompilerInputError(["invalid_timestamp"]);
  return new Date(parsed).toISOString();
}

function strictObject(
  value: unknown,
  allowed: ReadonlySet<string>,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CompilerInputError(["invalid_structure"]);
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !allowed.has(key))) {
    throw new CompilerInputError(["ambiguous_or_unsupported_field"]);
  }
  return record;
}

function stringList(value: unknown, minimum = 1): readonly string[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > 128) {
    throw new CompilerInputError(["invalid_structure"]);
  }
  return value.map((item) => normalizeString(item));
}

function sha256List(value: unknown, minimum = 1): readonly string[] {
  const hashes = stringList(value, minimum).map((item) => item.toLowerCase());
  if (hashes.some((item) => !SHA256.test(item)) || new Set(hashes).size !== hashes.length) {
    throw new CompilerInputError(["invalid_evidence_hash"]);
  }
  return [...hashes].sort();
}

function primitiveRecord(value: unknown): Readonly<Record<string, Primitive>> {
  const record = strictObject(value, new Set(Object.keys((value ?? {}) as Record<string, unknown>)));
  if (Object.keys(record).length > 64) throw new CompilerInputError(["invalid_structure"]);
  const result: Record<string, Primitive> = {};
  for (const [rawKey, rawValue] of Object.entries(record).sort(([a], [b]) => a.localeCompare(b))) {
    const key = normalizeString(rawKey);
    if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(key) ||
        !["string", "number", "boolean"].includes(typeof rawValue) ||
        (typeof rawValue === "number" && !Number.isFinite(rawValue))) {
      throw new CompilerInputError(["invalid_normalized_parameter"]);
    }
    result[key] = typeof rawValue === "string" ? normalizeString(rawValue) : rawValue as number | boolean;
  }
  return result;
}

function compactKey(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

function scanReusableBoundary(value: unknown, privateLabels: readonly string[]): readonly string[] {
  const categories = new Set<string>();
  const labels = privateLabels.map((item) => item.trim().normalize("NFKC").toLowerCase()).filter(Boolean);
  const visit = (item: unknown): void => {
    if (typeof item === "string") {
      attackKnowledgeOperationalLocatorCategories(item).forEach((category) => categories.add(category));
      findReusableMemorySecretCategories(item).forEach((category) => categories.add(category));
      if (ABSOLUTE_PATH.test(item)) categories.add("absolute_private_path");
      if (HOSTISH.test(item)) categories.add("bare_hostname");
      if (DOMAIN.test(item) && !/\b(?:ASP\.NET|Node\.js)\b/u.test(item)) categories.add("private_domain");
      if (JOURNEY.test(item)) categories.add("journey_metadata");
      const lower = item.toLowerCase();
      if (labels.some((label) => label.length >= 3 && lower.includes(label))) categories.add("private_label");
      return;
    }
    if (Array.isArray(item)) return item.forEach(visit);
    if (item && typeof item === "object") {
      for (const [key, nested] of Object.entries(item as Record<string, unknown>)) {
        if (FORBIDDEN_KEYS.has(compactKey(key))) categories.add("forbidden_operational_field");
        visit(nested);
      }
    }
  };
  visit(value);
  return [...categories].sort();
}

function normalizeInput(raw: unknown): NormalizedInput {
  const root = strictObject(raw, new Set(["source", "knowledge", "confidence"]));
  const source = strictObject(root.source, new Set([
    "privateSourceReference", "privateLabels", "sourceClass", "sourceHash", "observedAt", "evidenceCount",
    "canonicalEvidenceIds",
  ]));
  const privateSourceReference = normalizeString(source.privateSourceReference, "missing_private_source_reference");
  const privateLabels = source.privateLabels === undefined ? [] : stringList(source.privateLabels, 0);
  const sourceClass = source.sourceClass;
  if (sourceClass !== "current" && sourceClass !== "historical") {
    throw new CompilerInputError(["invalid_source_class"]);
  }
  const sourceHash = normalizeString(source.sourceHash, "invalid_source_hash").toLowerCase();
  if (!SHA256.test(sourceHash)) throw new CompilerInputError(["invalid_source_hash"]);
  const observedAt = timestamp(source.observedAt);
  const evidenceCount = integer(source.evidenceCount, 1, "insufficient_evidence");
  const canonicalEvidenceIds = source.canonicalEvidenceIds === undefined
    ? []
    : stringList(source.canonicalEvidenceIds, 1).map((value) => {
        if (!/^[A-Za-z0-9._:@/-]{1,300}$/u.test(value)) {
          throw new CompilerInputError(["invalid_evidence_id"]);
        }
        return value;
      }).sort();
  if (new Set(canonicalEvidenceIds).size !== canonicalEvidenceIds.length) {
    throw new CompilerInputError(["duplicate_evidence_id"]);
  }
  const confidence = root.confidence;
  if (typeof confidence !== "number" || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new CompilerInputError(["invalid_confidence"]);
  }

  const knowledgeRaw = strictObject(root.knowledge, new Set([
    "kind", "product", "stack", "procedure", "scriptArtifacts", "discoveries", "outcomes",
    "hazard", "corroboration",
    "nodeType", "title", "summary", "body", "facts", "edges",
  ]));
  const boundaryCategories = scanReusableBoundary(knowledgeRaw, privateLabels);
  if (boundaryCategories.length > 0) throw new CompilerInputError(boundaryCategories);

  let knowledge: OperationalHazardKnowledge | ReusableAttackFactKnowledge | ReusableAttackBundleKnowledge;
  if (knowledgeRaw.kind === "reusable_fact") {
    const nodeType = normalizeString(knowledgeRaw.nodeType) as MemoryNodeType;
    if (!isAttackCentricReusableNodeType(nodeType)) throw new CompilerInputError(["unsupported_reusable_node_type"]);
    knowledge = {
      kind: "reusable_fact",
      nodeType,
      title: normalizeString(knowledgeRaw.title),
      summary: normalizeString(knowledgeRaw.summary),
      ...(knowledgeRaw.body === undefined ? {} : { body: normalizeString(knowledgeRaw.body) }),
    };
  } else if (knowledgeRaw.kind === "reusable_bundle") {
    if (!Array.isArray(knowledgeRaw.facts) || knowledgeRaw.facts.length < 2 || knowledgeRaw.facts.length > 128) {
      throw new CompilerInputError(["invalid_reusable_bundle_facts"]);
    }
    const roles = new Set<string>();
    const facts = knowledgeRaw.facts.map((rawFact) => {
      const item = strictObject(rawFact, new Set(["role", "nodeType", "title", "summary", "body"]));
      const role = normalizeString(item.role);
      if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(role) || roles.has(role)) {
        throw new CompilerInputError(["invalid_reusable_bundle_role"]);
      }
      roles.add(role);
      const nodeType = normalizeString(item.nodeType) as MemoryNodeType;
      if (!isAttackCentricReusableNodeType(nodeType)) {
        throw new CompilerInputError(["unsupported_reusable_node_type"]);
      }
      return {
        role,
        nodeType,
        title: normalizeString(item.title),
        summary: normalizeString(item.summary),
        ...(item.body === undefined ? {} : { body: normalizeString(item.body) }),
      };
    });
    if (!Array.isArray(knowledgeRaw.edges) || knowledgeRaw.edges.length < 1 || knowledgeRaw.edges.length > 256) {
      throw new CompilerInputError(["invalid_reusable_bundle_edges"]);
    }
    const edgeTypes = new Set<string>(ATTACK_CENTRIC_EDGE_TYPES);
    const edgeIdentities = new Set<string>();
    const nodeTypeByRole = new Map(facts.map((item) => [item.role, item.nodeType]));
    const edges = knowledgeRaw.edges.map((rawEdge) => {
      const edge = strictObject(rawEdge, new Set(["sourceRole", "edgeType", "targetRole"]));
      const sourceRole = normalizeString(edge.sourceRole);
      const targetRole = normalizeString(edge.targetRole);
      const edgeType = normalizeString(edge.edgeType) as AttackCentricEdgeType;
      if (!roles.has(sourceRole) || !roles.has(targetRole) || !edgeTypes.has(edgeType)) {
        throw new CompilerInputError(["invalid_reusable_bundle_edge"]);
      }
      const identity = `${sourceRole}\0${edgeType}\0${targetRole}`;
      if (edgeIdentities.has(identity)) throw new CompilerInputError(["duplicate_reusable_bundle_edge"]);
      edgeIdentities.add(identity);
      try {
        validateAttackCentricEdgeEndpoints(edgeType, nodeTypeByRole.get(sourceRole)!, nodeTypeByRole.get(targetRole)!);
      } catch {
        throw new CompilerInputError(["invalid_reusable_bundle_edge"]);
      }
      return { sourceRole, edgeType, targetRole };
    });
    knowledge = {
      kind: "reusable_bundle",
      facts: facts.sort((left, right) => left.role.localeCompare(right.role)),
      edges: edges.sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))),
    };
  } else if (knowledgeRaw.kind === "operational_hazard") {
    const product = strictObject(knowledgeRaw.product, new Set(["name", "exactVersion"]));
    if (!Array.isArray(knowledgeRaw.stack) || knowledgeRaw.stack.length === 0 || knowledgeRaw.stack.length > 32) {
      throw new CompilerInputError(["missing_stack_evidence"]);
    }
    const stack = knowledgeRaw.stack.map((rawComponent) => {
      const component = strictObject(rawComponent, new Set(["nodeType", "name", "exactVersion"]));
      const nodeType = normalizeString(component.nodeType) as StackNodeType;
      if (!STACK_TYPES.has(nodeType)) throw new CompilerInputError(["unsupported_stack_type"]);
      return {
        nodeType,
        name: normalizeString(component.name),
        exactVersion: normalizeString(component.exactVersion, "missing_exact_version"),
      };
    });
    const procedure = strictObject(knowledgeRaw.procedure, new Set([
      "name", "version", "orderedSteps", "normalizedParameters", "prerequisites",
    ]));
    const scriptArtifacts = knowledgeRaw.scriptArtifacts === undefined
      ? []
      : (() => {
          if (!Array.isArray(knowledgeRaw.scriptArtifacts) || knowledgeRaw.scriptArtifacts.length > 32) {
            throw new CompilerInputError(["invalid_script_artifacts"]);
          }
          return knowledgeRaw.scriptArtifacts.map((rawArtifact) => {
            const artifact = strictObject(rawArtifact, new Set([
              "name", "version", "contentHash", "language", "purpose",
            ]));
            const contentHash = normalizeString(artifact.contentHash, "invalid_evidence_hash").toLowerCase();
            if (!SHA256.test(contentHash)) throw new CompilerInputError(["invalid_evidence_hash"]);
            return {
              name: normalizeString(artifact.name),
              version: normalizeString(artifact.version),
              contentHash,
              language: normalizeString(artifact.language),
              purpose: normalizeString(artifact.purpose),
            };
          });
        })();
    const discoveries = knowledgeRaw.discoveries === undefined
      ? []
      : (() => {
          if (!Array.isArray(knowledgeRaw.discoveries) || knowledgeRaw.discoveries.length > 64) {
            throw new CompilerInputError(["invalid_discoveries"]);
          }
          return knowledgeRaw.discoveries.map((rawDiscovery) => {
            const discovery = strictObject(rawDiscovery, new Set(["name", "summary", "evidenceContentHashes"]));
            return {
              name: normalizeString(discovery.name),
              summary: normalizeString(discovery.summary),
              evidenceContentHashes: sha256List(discovery.evidenceContentHashes),
            };
          });
        })();
    const outcomes = knowledgeRaw.outcomes === undefined
      ? []
      : (() => {
          if (!Array.isArray(knowledgeRaw.outcomes) || knowledgeRaw.outcomes.length > 64) {
            throw new CompilerInputError(["invalid_outcomes"]);
          }
          return knowledgeRaw.outcomes.map((rawOutcome) => {
            const outcome = strictObject(rawOutcome, new Set([
              "name", "status", "summary", "evidenceContentHashes", "failureMode",
            ]));
            if (outcome.status !== "worked" && outcome.status !== "failed") {
              throw new CompilerInputError(["invalid_outcome_status"]);
            }
            if (outcome.status === "worked" && outcome.failureMode !== undefined) {
              throw new CompilerInputError(["invalid_outcome_failure_mode"]);
            }
            const status: "worked" | "failed" = outcome.status === "worked" ? "worked" : "failed";
            return {
              name: normalizeString(outcome.name),
              status,
              summary: normalizeString(outcome.summary),
              evidenceContentHashes: sha256List(outcome.evidenceContentHashes),
              ...(outcome.failureMode === undefined ? {} : { failureMode: normalizeString(outcome.failureMode) }),
            };
          });
        })();
    const hazard = strictObject(knowledgeRaw.hazard, new Set([
      "name", "observedSymptom", "affectedComponent", "stateBefore", "stateAfter",
      "unaffectedComponents", "survivingHealthSignals", "unsafeRetryConditions", "healthGate",
      "retryValidConditions", "recoveryActionSummary", "recoveryCost",
      "saferAlternative", "loadMinimum", "concurrencyMinimum", "timingWindowMs", "freshUntil",
    ]));
    const recoveryCost = strictObject(hazard.recoveryCost ?? {}, new Set([
      "exactProcedureResetCount", "operatorReportedResetCountMinimum", "serviceRecycleCount",
      "downtimeMs", "operatorMinutes", "requiresDisposableTargetReset",
    ]));
    const alternative = strictObject(hazard.saferAlternative, new Set([
      "name", "orderedSteps", "reviewedBinding", "retryConditionEvidence",
    ]));
    const alternativeBinding = alternative.reviewedBinding === undefined
      ? undefined
      : strictObject(alternative.reviewedBinding, new Set([
        "version", "normalizedParameters", "sourceLoad", "sourceConcurrency",
        "sourceTimingWindowMs", "load", "concurrency", "timingWindowMs",
      ]));
    const retryConditionEvidence = alternative.retryConditionEvidence === undefined
      ? undefined
      : (() => {
          if (!Array.isArray(alternative.retryConditionEvidence)
            || alternative.retryConditionEvidence.length === 0
            || alternative.retryConditionEvidence.length > 128) {
            throw new CompilerInputError(["invalid_retry_condition_evidence"]);
          }
          const keys = new Set<string>();
          return alternative.retryConditionEvidence.map((rawCondition) => {
            const condition = strictObject(rawCondition, new Set(["statement", "evidenceKey"]));
            const evidenceKey = normalizeString(condition.evidenceKey);
            if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(evidenceKey) || keys.has(evidenceKey)) {
              throw new CompilerInputError(["invalid_retry_condition_evidence"]);
            }
            keys.add(evidenceKey);
            return {
              statement: normalizeString(condition.statement),
              evidenceKey,
            };
          });
        })();
    const corroboration = strictObject(knowledgeRaw.corroboration, new Set([
      "exactProcedureAttemptCount", "exactProcedureReproducibilityCount", "exactProcedureEvidenceCount",
    ]));
    const attempts = integer(corroboration.exactProcedureAttemptCount, 1, "insufficient_evidence");
    const reproducible = integer(corroboration.exactProcedureReproducibilityCount, 1, "insufficient_evidence");
    const exactEvidence = integer(corroboration.exactProcedureEvidenceCount, 1, "insufficient_evidence");
    const exactResets = optionalInteger(recoveryCost.exactProcedureResetCount, 0) ?? 0;
    const operatorResetMinimum = optionalInteger(recoveryCost.operatorReportedResetCountMinimum, 0);
    if (attempts < reproducible || exactEvidence < reproducible || evidenceCount < exactEvidence ||
        (operatorResetMinimum !== undefined && operatorResetMinimum < exactResets)) {
      throw new CompilerInputError(["inconsistent_corroboration"]);
    }
    if (recoveryCost.requiresDisposableTargetReset !== undefined &&
        typeof recoveryCost.requiresDisposableTargetReset !== "boolean") {
      throw new CompilerInputError(["invalid_recovery_cost"]);
    }
    knowledge = {
      kind: "operational_hazard",
      product: {
        name: normalizeString(product.name),
        exactVersion: normalizeString(product.exactVersion, "missing_exact_version"),
      },
      stack,
      procedure: {
        name: normalizeString(procedure.name),
        version: normalizeString(procedure.version, "missing_procedure_version"),
        orderedSteps: stringList(procedure.orderedSteps, 2),
        normalizedParameters: primitiveRecord(procedure.normalizedParameters),
        prerequisites: stringList(procedure.prerequisites),
      },
      ...(scriptArtifacts.length ? { scriptArtifacts } : {}),
      ...(discoveries.length ? { discoveries } : {}),
      ...(outcomes.length ? { outcomes } : {}),
      hazard: {
        name: normalizeString(hazard.name),
        observedSymptom: normalizeString(hazard.observedSymptom),
        affectedComponent: normalizeString(hazard.affectedComponent),
        ...(hazard.unaffectedComponents === undefined
          ? {}
          : { unaffectedComponents: stringList(hazard.unaffectedComponents) }),
        ...(hazard.survivingHealthSignals === undefined
          ? {}
          : { survivingHealthSignals: stringList(hazard.survivingHealthSignals) }),
        stateBefore: normalizeString(hazard.stateBefore),
        stateAfter: normalizeString(hazard.stateAfter),
        unsafeRetryConditions: stringList(hazard.unsafeRetryConditions),
        healthGate: stringList(hazard.healthGate),
        ...(hazard.retryValidConditions === undefined
          ? {}
          : { retryValidConditions: stringList(hazard.retryValidConditions) }),
        recoveryActionSummary: normalizeString(hazard.recoveryActionSummary),
        recoveryCost: {
          ...(exactResets > 0 ? { exactProcedureResetCount: exactResets } : {}),
          ...(operatorResetMinimum === undefined ? {} : { operatorReportedResetCountMinimum: operatorResetMinimum }),
          ...(optionalInteger(recoveryCost.serviceRecycleCount, 0) === undefined ? {} : { serviceRecycleCount: Number(recoveryCost.serviceRecycleCount) }),
          ...(optionalInteger(recoveryCost.downtimeMs, 0) === undefined ? {} : { downtimeMs: Number(recoveryCost.downtimeMs) }),
          ...(optionalInteger(recoveryCost.operatorMinutes, 0) === undefined ? {} : { operatorMinutes: Number(recoveryCost.operatorMinutes) }),
          ...(recoveryCost.requiresDisposableTargetReset === undefined ? {} : { requiresDisposableTargetReset: recoveryCost.requiresDisposableTargetReset }),
        },
        saferAlternative: {
          name: normalizeString(alternative.name),
          orderedSteps: stringList(alternative.orderedSteps),
          ...(alternativeBinding === undefined
            ? {}
            : {
              reviewedBinding: {
                version: normalizeString(alternativeBinding.version, "missing_alternative_procedure_version"),
                normalizedParameters: primitiveRecord(alternativeBinding.normalizedParameters),
                ...(optionalFinite(alternativeBinding.sourceLoad, 0) === undefined
                  ? {}
                  : { sourceLoad: Number(alternativeBinding.sourceLoad) }),
                ...(optionalInteger(alternativeBinding.sourceConcurrency, 1) === undefined
                  ? {}
                  : { sourceConcurrency: Number(alternativeBinding.sourceConcurrency) }),
                ...(optionalInteger(alternativeBinding.sourceTimingWindowMs, 0) === undefined
                  ? {}
                  : { sourceTimingWindowMs: Number(alternativeBinding.sourceTimingWindowMs) }),
                ...(optionalFinite(alternativeBinding.load, 0) === undefined
                  ? {}
                  : { load: Number(alternativeBinding.load) }),
                ...(optionalInteger(alternativeBinding.concurrency, 1) === undefined
                  ? {}
                  : { concurrency: Number(alternativeBinding.concurrency) }),
                ...(optionalInteger(alternativeBinding.timingWindowMs, 0) === undefined
                  ? {}
                  : { timingWindowMs: Number(alternativeBinding.timingWindowMs) }),
              },
            }),
          ...(retryConditionEvidence === undefined ? {} : { retryConditionEvidence }),
        },
        ...(optionalFinite(hazard.loadMinimum, 0) === undefined ? {} : { loadMinimum: Number(hazard.loadMinimum) }),
        ...(optionalInteger(hazard.concurrencyMinimum, 1) === undefined ? {} : { concurrencyMinimum: Number(hazard.concurrencyMinimum) }),
        ...(optionalInteger(hazard.timingWindowMs, 0) === undefined ? {} : { timingWindowMs: Number(hazard.timingWindowMs) }),
        ...(hazard.freshUntil === undefined ? {} : { freshUntil: timestamp(hazard.freshUntil) }),
      },
      corroboration: {
        exactProcedureAttemptCount: attempts,
        exactProcedureReproducibilityCount: reproducible,
        exactProcedureEvidenceCount: exactEvidence,
      },
    };
  } else {
    throw new CompilerInputError(["unsupported_knowledge_kind"]);
  }
  return {
    source: {
      privateSourceReference,
      privateLabels,
      sourceClass,
      sourceHash,
      observedAt,
      evidenceCount,
      canonicalEvidenceIds,
    },
    knowledge,
    confidence,
  };
}

function semanticKnowledge(input: NormalizedInput): unknown {
  return { schemaVersion: 1, knowledge: input.knowledge.kind === "operational_hazard"
    ? {
      ...input.knowledge,
      discoveries: input.knowledge.discoveries?.map(({ evidenceContentHashes: _support, ...discovery }) => discovery),
      outcomes: input.knowledge.outcomes?.map(({ evidenceContentHashes: _support, ...outcome }) => outcome),
      corroboration: undefined, hazard: {
        ...input.knowledge.hazard,
        recoveryCost: {
          ...input.knowledge.hazard.recoveryCost,
          exactProcedureResetCount: undefined,
          operatorReportedResetCountMinimum: undefined,
        },
      } }
    : input.knowledge };
}

function inputCounts(input: NormalizedInput): AggregateCounts {
  if (input.knowledge.kind !== "operational_hazard") {
    return { attempts: 0, reproducibleOutcomes: 0, evidenceItems: 0, exactResets: 0, operatorReportedAggregateResetMinimum: null };
  }
  return {
    attempts: input.knowledge.corroboration.exactProcedureAttemptCount,
    reproducibleOutcomes: input.knowledge.corroboration.exactProcedureReproducibilityCount,
    evidenceItems: input.knowledge.corroboration.exactProcedureEvidenceCount,
    exactResets: input.knowledge.hazard.recoveryCost?.exactProcedureResetCount ?? 0,
    operatorReportedAggregateResetMinimum:
      input.knowledge.hazard.recoveryCost?.operatorReportedResetCountMinimum ?? null,
  };
}

function bundleCounts(row: BundleRow): AggregateCounts {
  return {
    attempts: row.exact_procedure_attempt_count,
    reproducibleOutcomes: row.exact_procedure_reproducibility_count,
    evidenceItems: row.exact_procedure_evidence_count,
    exactResets: row.exact_procedure_reset_count,
    operatorReportedAggregateResetMinimum: row.operator_reported_reset_count_minimum,
  };
}

function privateSourceClass(raw: unknown): SourceClass | "unknown" {
  if (raw && typeof raw === "object") {
    const source = (raw as Record<string, unknown>).source;
    if (source && typeof source === "object") {
      const value = (source as Record<string, unknown>).sourceClass;
      if (value === "current" || value === "historical") return value;
    }
  }
  return "unknown";
}

/**
 * Local deterministic compiler. It never reads a Vault and never creates
 * confirmed/verified nodes, graph edges, or hazard profiles. Its only semantic
 * output is the existing operator-review candidate queue.
 */
export class AttackKnowledgeCompiler {
  readonly #memory: MemoryRepository;
  readonly #clock: () => Date;
  readonly #key: Buffer;

  constructor(
    private readonly database: SqliteDatabase,
    options: { readonly receiptHmacKey: string | Buffer; readonly clock?: () => Date },
  ) {
    this.#key = Buffer.isBuffer(options.receiptHmacKey)
      ? Buffer.from(options.receiptHmacKey)
      : Buffer.from(options.receiptHmacKey, "utf8");
    if (this.#key.byteLength < 32) throw new TypeError("Attack knowledge receipt HMAC key must contain at least 32 bytes");
    this.#clock = options.clock ?? (() => new Date());
    this.#memory = new MemoryRepository(database, { clock: this.#clock });
  }

  compile(
    raw: unknown,
    options: { readonly dryRun?: boolean; readonly interruptAfterCandidateWrites?: number } = {},
  ): AttackKnowledgeCompileResult {
    return this.#compile(raw, options, { kind: "immediate" });
  }

  /**
   * Historical importers can stage a bounded set of compiler requests without
   * paying for global COUNT/JOIN reconciliation after every record. Ordinary
   * `compile()` remains immediate and unchanged. A deferred batch is one-shot,
   * bounded, and fails closed if it is used after completion.
   */
  beginDeferredReconciliationBatch(
    options: { readonly maxCompilations: number },
  ): AttackKnowledgeDeferredReconciliationBatch {
    if (!Number.isSafeInteger(options.maxCompilations) || options.maxCompilations < 1) {
      throw new TypeError("Deferred attack-knowledge batch maxCompilations must be a positive safe integer");
    }
    const batchId = `akdr_${this.#hmac(canonicalJson({
      nonce: randomUUID(),
      startedAt: this.#clock().toISOString(),
    }))}`;
    const reconciliationMarker = canonicalJson({ deferredReconciliationBatch: batchId });
    const runIds = new Set<string>();
    let compilations = 0;
    let finished = false;
    let finishing = false;

    return {
      maxCompilations: options.maxCompilations,
      compile: (raw, compileOptions = {}) => {
        if (finished) throw new Error("Deferred attack-knowledge reconciliation batch is already finished");
        if (compilations >= options.maxCompilations) {
          throw new RangeError("Deferred attack-knowledge reconciliation batch exceeded its compilation bound");
        }
        compilations += 1;
        return this.#compile(raw, compileOptions, {
          kind: "deferred",
          reconciliationMarker,
          recordCompilerRun: (runId) => runIds.add(runId),
        });
      },
      finish: () => {
        if (finished || finishing) throw new Error("Deferred attack-knowledge reconciliation batch is already finished");
        finishing = true;
        try {
          // This is the sole global reconciliation pass for the bounded batch.
          const reconciliation = this.reconcile();
          let compilerRunsReconciled = 0;
          if (runIds.size > 0) {
            compilerRunsReconciled = inImmediateTransaction(this.database, () => {
              const changes = this.database.prepare(`
                UPDATE attack_knowledge_compiler_runs
                SET reconciliation_json = ?, updated_at = ?
                WHERE status = 'staged' AND reconciliation_json = ?
              `).run(
                canonicalJson(reconciliation),
                this.#clock().toISOString(),
                reconciliationMarker,
              ).changes;
              if (changes !== runIds.size) {
                throw new Error("Deferred attack-knowledge compiler-run reconciliation lost batch ownership");
              }
              return changes;
            });
          }
          finished = true;
          return {
            reconciliation,
            compilations,
            compilerRunsReconciled,
            reconciliationPasses: 1,
          };
        } finally {
          finishing = false;
        }
      },
    };
  }

  #compile(
    raw: unknown,
    options: { readonly dryRun?: boolean; readonly interruptAfterCandidateWrites?: number },
    mode: { readonly kind: "immediate" },
  ): AttackKnowledgeCompileResult;
  #compile(
    raw: unknown,
    options: { readonly dryRun?: boolean; readonly interruptAfterCandidateWrites?: number },
    mode: {
      readonly kind: "deferred";
      readonly reconciliationMarker: string;
      readonly recordCompilerRun: (runId: string) => void;
    },
  ): AttackKnowledgeDeferredCompileResult;
  #compile(
    raw: unknown,
    options: { readonly dryRun?: boolean; readonly interruptAfterCandidateWrites?: number },
    mode: AttackKnowledgeCompilationMode,
  ): AttackKnowledgeCompileResult | AttackKnowledgeDeferredCompileResult {
    let input: NormalizedInput;
    try {
      input = normalizeInput(raw);
    } catch (error) {
      if (!(error instanceof CompilerInputError)) throw error;
      return this.#quarantine(raw, error.categories, options.dryRun === true, mode.kind);
    }
    const sanitized = semanticKnowledge(input);
    const bundleFingerprint = sha256(canonicalJson(sanitized));
    const bundleId = `akb_${bundleFingerprint}`;
    let canonicalEvidence: readonly {
      readonly id: string;
      readonly contentHash: string;
      readonly acquiredAt: string;
    }[];
    try {
      canonicalEvidence = this.#canonicalEvidence(input.source.canonicalEvidenceIds);
      this.#validateEvidenceSupport(input, canonicalEvidence);
    } catch (error) {
      if (!(error instanceof CompilerInputError)) throw error;
      return this.#quarantine(raw, error.categories, options.dryRun === true, mode.kind);
    }
    const receiptDigest = this.#hmac(canonicalJson({
      sourceClass: input.source.sourceClass,
      sourceHash: input.source.sourceHash,
      canonicalEvidence,
    }));
    const receiptId = `akpr_${receiptDigest}`;
    const requestFingerprint = this.#hmac(`${bundleFingerprint}\0${receiptDigest}`);
    const runId = `akcr_${requestFingerprint}`;
    const counts = inputCounts(input);
    const edgeProposals = this.#edgeProposals(input);
    try {
      this.#validateEdgeProposals(
        edgeProposals,
        this.#blueprints(input, bundleId, [receiptId], counts),
      );
    } catch {
      return this.#quarantine(raw, ["invalid_edge_proposal"], options.dryRun === true, mode.kind);
    }

    if (options.dryRun) {
      const projected = this.#projectedCounts(bundleId, receiptId, counts);
      const blueprints = this.#blueprints(input, bundleId, [receiptId], projected);
      const existing = blueprints.filter(({ input: candidate }) => this.#candidateFingerprint(candidate) in this.#candidateRegistry()).length;
      const result: AttackKnowledgeDeferredCompileResult = {
        status: "dry_run",
        dryRun: true,
        bundleFingerprint,
        bundleId,
        provenanceReceiptId: receiptId,
        candidateIds: [],
        candidatesCreated: blueprints.length - existing,
        candidatesReused: existing,
        edgeProposalsStaged: edgeProposals.length,
        exactProcedureCounts: projected,
      };
      return mode.kind === "immediate" ? { ...result, reconciliation: this.reconcile() } : result;
    }

    const now = this.#clock().toISOString();
    try {
      inImmediateTransaction(this.database, () => {
        const existingReceipt = this.database.prepare(`
          SELECT source_class, source_hash, evidence_count, observed_at
          FROM attack_knowledge_provenance_receipts WHERE id = ?
        `).get(receiptId) as Record<string, unknown> | undefined;
        if (existingReceipt && (
          existingReceipt.source_class !== input.source.sourceClass ||
          existingReceipt.source_hash !== input.source.sourceHash ||
          Number(existingReceipt.evidence_count) !== input.source.evidenceCount ||
          existingReceipt.observed_at !== input.source.observedAt
        )) throw new CompilerInputError(["immutable_receipt_mismatch"]);
        this.database.prepare(`
          INSERT INTO attack_knowledge_provenance_receipts (
            id, source_class, source_hash, evidence_count, observed_at, created_at
          ) VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO NOTHING
        `).run(receiptId, input.source.sourceClass, input.source.sourceHash,
          input.source.evidenceCount, input.source.observedAt, now);
        const existingBundle = this.database.prepare(`
          SELECT sanitized_bundle_json FROM attack_knowledge_bundles WHERE id = ?
        `).get(bundleId) as { sanitized_bundle_json: string } | undefined;
        const sanitizedJson = canonicalJson(sanitized);
        if (existingBundle && existingBundle.sanitized_bundle_json !== sanitizedJson) {
          throw new CompilerInputError(["semantic_fingerprint_collision"]);
        }
        this.database.prepare(`
          INSERT INTO attack_knowledge_bundles (
            id, semantic_fingerprint, sanitized_bundle_json, status,
            first_observed_at, last_observed_at, created_at, updated_at
          ) VALUES (?, ?, ?, 'staged', ?, ?, ?, ?)
          ON CONFLICT(id) DO NOTHING
        `).run(bundleId, bundleFingerprint, sanitizedJson, input.source.observedAt,
          input.source.observedAt, now, now);
        const linked = this.database.prepare(`
          INSERT INTO attack_knowledge_bundle_receipts (
            bundle_id, receipt_id, exact_procedure_attempt_count,
            exact_procedure_reproducibility_count, exact_procedure_evidence_count,
            exact_procedure_reset_count, operator_reported_reset_count_minimum, linked_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(bundle_id, receipt_id) DO NOTHING
        `).run(bundleId, receiptId, counts.attempts, counts.reproducibleOutcomes,
          counts.evidenceItems, counts.exactResets,
          counts.operatorReportedAggregateResetMinimum, now).changes;
        const bindEvidence = this.database.prepare(`
          INSERT INTO attack_knowledge_bundle_evidence_bindings (
            bundle_id, receipt_id, evidence_id, content_hash, acquired_at, bound_at
          ) VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(bundle_id, evidence_id) DO NOTHING
        `);
        for (const evidence of canonicalEvidence) {
          bindEvidence.run(
            bundleId,
            receiptId,
            evidence.id,
            evidence.contentHash,
            evidence.acquiredAt,
            now,
          );
        }
        this.#refreshBundleAggregates(bundleId, linked > 0, now);
        this.database.prepare(`
          INSERT INTO attack_knowledge_compiler_runs (
            id, request_fingerprint, bundle_id, receipt_id, source_class,
            status, checkpoint_ordinal, reconciliation_json, started_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, 'compiling', 0, '{}', ?, ?)
          ON CONFLICT(id) DO UPDATE SET status = 'compiling', updated_at = excluded.updated_at
        `).run(runId, requestFingerprint, bundleId, receiptId, input.source.sourceClass, now, now);
      });
    } catch (error) {
      if (!(error instanceof CompilerInputError)) throw error;
      return this.#quarantine(raw, error.categories, false, mode.kind);
    }

    const aggregate = bundleCounts(this.#requireBundle(bundleId));
    const receiptIds = (this.database.prepare(`
      SELECT receipt_id FROM attack_knowledge_bundle_receipts
      WHERE bundle_id = ? ORDER BY receipt_id
    `).all(bundleId) as Array<{ receipt_id: string }>).map(({ receipt_id }) => receipt_id);
    const blueprints = this.#blueprints(input, bundleId, receiptIds, aggregate);
    const candidateIds: string[] = [];
    let created = 0;
    let reused = 0;
    let processed = 0;
    for (const blueprint of blueprints) {
      const result = inImmediateTransaction(this.database, () => this.#stageCandidate(bundleId, blueprint, processed, now));
      candidateIds.push(result.candidateId);
      result.created ? created += 1 : reused += 1;
      processed += 1;
      this.database.prepare(`
        UPDATE attack_knowledge_compiler_runs
        SET checkpoint_ordinal = ?, updated_at = ? WHERE id = ?
      `).run(processed, this.#clock().toISOString(), runId);
      if (options.interruptAfterCandidateWrites !== undefined && created >= options.interruptAfterCandidateWrites) {
        this.database.prepare(`
          UPDATE attack_knowledge_compiler_runs SET status = 'interrupted', updated_at = ? WHERE id = ?
        `).run(this.#clock().toISOString(), runId);
        throw new AttackKnowledgeCompilerInterruptedError(bundleFingerprint, processed);
      }
    }
    const nodeTypeByRole = new Map(blueprints.map((blueprint) => [blueprint.role, blueprint.input.nodeType]));
    inImmediateTransaction(this.database, () => {
      const insert = this.database.prepare(`
        INSERT INTO attack_knowledge_bundle_edges (
          bundle_id, edge_key, source_role, target_role, edge_type
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(bundle_id, edge_key) DO NOTHING
      `);
      for (const proposal of edgeProposals) {
        const sourceType = nodeTypeByRole.get(proposal.sourceRole);
        const targetType = nodeTypeByRole.get(proposal.targetRole);
        if (!sourceType || !targetType) throw new Error("Attack knowledge edge proposal references a missing candidate role");
        validateAttackCentricEdgeEndpoints(proposal.edgeType, sourceType, targetType);
        const edgeKey = `ake_${sha256(canonicalJson(proposal)).slice(0, 48)}`;
        insert.run(bundleId, edgeKey, proposal.sourceRole, proposal.targetRole, proposal.edgeType);
      }
    });
    const result: AttackKnowledgeDeferredCompileResult = {
      status: "staged",
      dryRun: false,
      bundleFingerprint,
      bundleId,
      provenanceReceiptId: receiptId,
      candidateIds,
      candidatesCreated: created,
      candidatesReused: reused,
      edgeProposalsStaged: edgeProposals.length,
      exactProcedureCounts: aggregate,
    };
    if (mode.kind === "deferred") {
      this.database.prepare(`
        UPDATE attack_knowledge_compiler_runs
        SET status = 'staged', checkpoint_ordinal = ?, reconciliation_json = ?,
            updated_at = ?, completed_at = ? WHERE id = ?
      `).run(
        processed,
        mode.reconciliationMarker,
        now,
        now,
        runId,
      );
      mode.recordCompilerRun(runId);
      return result;
    }

    const reconciliation = this.reconcile();
    this.database.prepare(`
      UPDATE attack_knowledge_compiler_runs
      SET status = 'staged', checkpoint_ordinal = ?, reconciliation_json = ?,
          updated_at = ?, completed_at = ? WHERE id = ?
    `).run(processed, canonicalJson(reconciliation), now, now, runId);
    return { ...result, reconciliation: this.reconcile() };
  }

  reconcile(): AttackKnowledgeReconciliation {
    const count = (sql: string): number => Number((this.database.prepare(sql).get() as { count: number }).count);
    return {
      bundleCount: count("SELECT COUNT(*) AS count FROM attack_knowledge_bundles"),
      receiptCount: count("SELECT COUNT(*) AS count FROM attack_knowledge_provenance_receipts"),
      bundleReceiptCount: count("SELECT COUNT(*) AS count FROM attack_knowledge_bundle_receipts"),
      candidateRegistryCount: count("SELECT COUNT(*) AS count FROM attack_knowledge_candidate_registry"),
      bundleCandidateCount: count("SELECT COUNT(*) AS count FROM attack_knowledge_bundle_candidates"),
      edgeProposalCount: count("SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges"),
      pendingCandidateCount: count(`SELECT COUNT(*) AS count FROM attack_knowledge_candidate_registry r
        JOIN memory_candidates c ON c.id = r.candidate_id WHERE c.status = 'pending'`),
      reviewedCandidateCount: count(`SELECT COUNT(*) AS count FROM attack_knowledge_candidate_registry r
        JOIN memory_candidates c ON c.id = r.candidate_id WHERE c.status != 'pending'`),
      interruptedRunCount: count("SELECT COUNT(*) AS count FROM attack_knowledge_compiler_runs WHERE status = 'interrupted'"),
      quarantineCount: count("SELECT COUNT(*) AS count FROM attack_knowledge_quarantine_records"),
      orphanedCandidateLinks: count(`SELECT COUNT(*) AS count FROM attack_knowledge_bundle_candidates bc
        LEFT JOIN attack_knowledge_candidate_registry r ON r.content_fingerprint = bc.content_fingerprint
        LEFT JOIN memory_candidates c ON c.id = r.candidate_id WHERE c.id IS NULL`),
    };
  }

  #hmac(value: string): string {
    return createHmac("sha256", this.#key).update(value, "utf8").digest("hex");
  }

  #canonicalEvidence(ids: readonly string[]): readonly {
    readonly id: string;
    readonly contentHash: string;
    readonly acquiredAt: string;
  }[] {
    return ids.map((evidenceId) => {
      const row = this.database.prepare(`
        SELECT e.id, e.content_hash, e.acquired_at
        FROM evidence e
        WHERE e.id = ? AND e.verification_state = 'verified'
          AND lower(trim(e.evidence_type)) <> 'command_output'
          AND EXISTS (
            SELECT 1 FROM evidence_chain_events custody
            WHERE custody.evidence_id = e.id AND custody.event_type = 'verified'
          )
      `).get(evidenceId) as {
        readonly id: string;
        readonly content_hash: string;
        readonly acquired_at: string;
      } | undefined;
      if (!row || !SHA256.test(row.content_hash)) {
        throw new CompilerInputError(["canonical_evidence_unverified"]);
      }
      return { id: row.id, contentHash: row.content_hash, acquiredAt: row.acquired_at };
    });
  }

  #validateEvidenceSupport(
    input: NormalizedInput,
    evidence: readonly { readonly contentHash: string }[],
  ): void {
    if (input.knowledge.kind !== "operational_hazard") return;
    const available = new Set(evidence.map(({ contentHash }) => contentHash));
    const required = [
      ...(input.knowledge.scriptArtifacts ?? []).map(({ contentHash }) => contentHash),
      ...(input.knowledge.discoveries ?? []).flatMap(({ evidenceContentHashes }) => evidenceContentHashes),
      ...(input.knowledge.outcomes ?? []).flatMap(({ evidenceContentHashes }) => evidenceContentHashes),
    ];
    if (required.some((hash) => !available.has(hash))) {
      throw new CompilerInputError(["canonical_evidence_support_missing"]);
    }
  }

  #quarantine(
    raw: unknown,
    rawCategories: readonly string[],
    dryRun: boolean,
    reconciliationMode: "immediate" | "deferred",
  ): AttackKnowledgeCompileResult | AttackKnowledgeDeferredCompileResult {
    const reasonCategories = [...new Set(rawCategories)].sort();
    let canonical = "unserializable_input";
    try { canonical = canonicalJson(raw); } catch { /* digest only a constant */ }
    const fingerprint = this.#hmac(canonical);
    if (!dryRun) {
      const now = this.#clock().toISOString();
      this.database.prepare(`
        INSERT INTO attack_knowledge_quarantine_records (
          fingerprint, source_class, reason_categories_json, occurrence_count,
          first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, 1, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
          occurrence_count = occurrence_count + 1,
          last_seen_at = excluded.last_seen_at
      `).run(fingerprint, privateSourceClass(raw), canonicalJson(reasonCategories), now, now);
    }
    const result: AttackKnowledgeDeferredCompileResult = {
      status: "quarantined",
      dryRun,
      candidateIds: [],
      candidatesCreated: 0,
      candidatesReused: 0,
      edgeProposalsStaged: 0,
      reasonCategories,
      exactProcedureCounts: {
        attempts: 0, reproducibleOutcomes: 0, evidenceItems: 0, exactResets: 0,
        operatorReportedAggregateResetMinimum: null,
      },
    };
    return reconciliationMode === "immediate" ? { ...result, reconciliation: this.reconcile() } : result;
  }

  #requireBundle(bundleId: string): BundleRow {
    const row = this.database.prepare("SELECT * FROM attack_knowledge_bundles WHERE id = ?")
      .get(bundleId) as BundleRow | undefined;
    if (!row) throw new Error("Attack knowledge bundle was not found");
    return row;
  }

  #refreshBundleAggregates(bundleId: string, newReceipt: boolean, now: string): void {
    const aggregate = this.database.prepare(`
      SELECT
        COALESCE(SUM(exact_procedure_attempt_count), 0) AS attempts,
        COALESCE(SUM(exact_procedure_reproducibility_count), 0) AS reproducible,
        COALESCE(SUM(exact_procedure_evidence_count), 0) AS evidence,
        COALESCE(SUM(exact_procedure_reset_count), 0) AS resets,
        MAX(operator_reported_reset_count_minimum) AS operator_min,
        MIN(r.observed_at) AS first_observed,
        MAX(r.observed_at) AS last_observed
      FROM attack_knowledge_bundle_receipts br
      JOIN attack_knowledge_provenance_receipts r ON r.id = br.receipt_id
      WHERE br.bundle_id = ?
    `).get(bundleId) as Record<string, unknown>;
    this.database.prepare(`
      UPDATE attack_knowledge_bundles SET
        exact_procedure_attempt_count = ?, exact_procedure_reproducibility_count = ?,
        exact_procedure_evidence_count = ?, exact_procedure_reset_count = ?,
        operator_reported_reset_count_minimum = ?, first_observed_at = ?,
        last_observed_at = ?, status = CASE WHEN ? = 1 THEN 'staged' ELSE status END,
        materialized_at = CASE WHEN ? = 1 THEN NULL ELSE materialized_at END,
        updated_at = ? WHERE id = ?
    `).run(Number(aggregate.attempts), Number(aggregate.reproducible), Number(aggregate.evidence),
      Number(aggregate.resets), aggregate.operator_min === null ? null : Number(aggregate.operator_min),
      String(aggregate.first_observed), String(aggregate.last_observed), newReceipt ? 1 : 0,
      newReceipt ? 1 : 0, now, bundleId);
  }

  #projectedCounts(bundleId: string, receiptId: string, incoming: AggregateCounts): AggregateCounts {
    const current = this.database.prepare("SELECT * FROM attack_knowledge_bundles WHERE id = ?")
      .get(bundleId) as BundleRow | undefined;
    if (!current) return incoming;
    const linked = this.database.prepare(`
      SELECT 1 AS present FROM attack_knowledge_bundle_receipts WHERE bundle_id = ? AND receipt_id = ?
    `).get(bundleId, receiptId);
    if (linked) return bundleCounts(current);
    return {
      attempts: current.exact_procedure_attempt_count + incoming.attempts,
      reproducibleOutcomes: current.exact_procedure_reproducibility_count + incoming.reproducibleOutcomes,
      evidenceItems: current.exact_procedure_evidence_count + incoming.evidenceItems,
      exactResets: current.exact_procedure_reset_count + incoming.exactResets,
      operatorReportedAggregateResetMinimum: Math.max(
        current.operator_reported_reset_count_minimum ?? 0,
        incoming.operatorReportedAggregateResetMinimum ?? 0,
      ) || null,
    };
  }

  #candidateRegistry(): Record<string, string> {
    const rows = this.database.prepare(`
      SELECT content_fingerprint, candidate_id FROM attack_knowledge_candidate_registry
    `).all() as Array<{ content_fingerprint: string; candidate_id: string }>;
    return Object.fromEntries(rows.map((row) => [row.content_fingerprint, row.candidate_id]));
  }

  #candidateFingerprint(input: Omit<CreateMemoryCandidateInput, "id">): string {
    return memoryContentHash({
      nodeType: input.nodeType,
      title: input.title,
      summary: input.summary,
      body: input.body ?? "",
      scope: input.scope,
    });
  }

  #stageCandidate(
    bundleId: string,
    blueprint: CandidateBlueprint,
    ordinal: number,
    now: string,
  ): { readonly candidateId: string; readonly created: boolean } {
    const fingerprint = this.#candidateFingerprint(blueprint.input);
    const registry = this.database.prepare(`
      SELECT candidate_id FROM attack_knowledge_candidate_registry WHERE content_fingerprint = ?
    `).get(fingerprint) as { candidate_id: string } | undefined;
    let candidateId = registry?.candidate_id;
    let created = false;
    if (!candidateId) {
      candidateId = `mcand_ak_${fingerprint.slice(0, 48)}`;
      validateAttackCentricReusableNode({
        nodeType: blueprint.input.nodeType,
        title: blueprint.input.title,
        summary: blueprint.input.summary,
        body: blueprint.input.body ?? "",
        scope: blueprint.input.scope,
        provenance: blueprint.input.provenance,
        authorType: "system",
        lifecycleStatus: "candidate",
        confirmationState: "pending",
      });
      this.#memory.createCandidate({ ...blueprint.input, id: candidateId });
      this.database.prepare(`
        INSERT INTO attack_knowledge_candidate_registry (
          content_fingerprint, candidate_id, node_type, created_at
        ) VALUES (?, ?, ?, ?)
      `).run(fingerprint, candidateId, blueprint.input.nodeType, now);
      created = true;
    }
    this.database.prepare(`
      INSERT INTO attack_knowledge_bundle_candidates (
        bundle_id, role, content_fingerprint, required, ordinal, linked_at
      ) VALUES (?, ?, ?, 1, ?, ?)
      ON CONFLICT(bundle_id, role) DO UPDATE SET
        content_fingerprint = excluded.content_fingerprint,
        ordinal = excluded.ordinal,
        linked_at = excluded.linked_at
    `).run(bundleId, blueprint.role, fingerprint, ordinal, now);
    return { candidateId, created };
  }

  #blueprints(
    input: NormalizedInput,
    bundleId: string,
    receiptIds: readonly string[],
    counts: AggregateCounts,
  ): readonly CandidateBlueprint[] {
    const provenance = {
      method: "derived" as const,
      explanation: "Generalized locally from private evidence; source identity is represented only by opaque receipts.",
      sources: receiptIds.map((sourceId) => ({
        sourceType: "attack_knowledge_receipt",
        sourceId,
        acquiredAt: input.source.observedAt,
        sourceHash: sha256(`${bundleId}\0${sourceId}`),
      })),
    };
    const candidate = (
      role: string,
      nodeType: AttackCentricReusableNodeType,
      title: string,
      summary: string,
      body: unknown,
    ): CandidateBlueprint => ({
      role,
      input: {
        nodeType,
        title,
        summary,
        body: typeof body === "string" ? body : canonicalJson(body),
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: input.confidence,
        provenance,
        proposedBy: "attack-knowledge-compiler",
      },
    });
    if (input.knowledge.kind === "reusable_fact") {
      return [candidate("fact", input.knowledge.nodeType, input.knowledge.title,
        input.knowledge.summary, input.knowledge.body ?? input.knowledge.summary)];
    }
    if (input.knowledge.kind === "reusable_bundle") {
      return input.knowledge.facts.map((item) => candidate(
        item.role,
        item.nodeType,
        item.title,
        item.summary,
        item.body ?? item.summary,
      ));
    }
    const knowledge = input.knowledge;
    const stackConstraints = [
      { nodeType: "technology_product", name: knowledge.product.name, exactVersion: knowledge.product.exactVersion },
      ...knowledge.stack,
    ];
    const result: CandidateBlueprint[] = [
      candidate("product", "technology_product", knowledge.product.name,
        `Reusable product identity for ${knowledge.product.name}.`, { exactVersion: knowledge.product.exactVersion }),
      candidate("product.version", "exact_version_fingerprint", `${knowledge.product.name} ${knowledge.product.exactVersion}`,
        `Exact observed version fingerprint for ${knowledge.product.name}.`, { exactVersion: knowledge.product.exactVersion }),
      candidate("procedure", "attack_procedure", knowledge.procedure.name,
        `Reusable bounded procedure: ${knowledge.procedure.name}.`, {
          procedureVersion: knowledge.procedure.version,
          orderedSequence: knowledge.procedure.orderedSteps,
          normalizedBoundedParameters: knowledge.procedure.normalizedParameters,
        }),
      candidate("procedure.version", "procedure_version", `${knowledge.procedure.name} ${knowledge.procedure.version}`,
        `Exact reviewed procedure version for ${knowledge.procedure.name}.`, {
          procedure: knowledge.procedure.name,
          version: knowledge.procedure.version,
        }),
    ];
    if (knowledge.hazard.saferAlternative.reviewedBinding) {
      result.push(candidate(
        "alternative.version",
        "procedure_version",
        `${knowledge.hazard.saferAlternative.name} ${knowledge.hazard.saferAlternative.reviewedBinding.version}`,
        `Exact reviewed safer-alternative version for ${knowledge.hazard.saferAlternative.name}.`,
        {
          procedure: knowledge.hazard.saferAlternative.name,
          version: knowledge.hazard.saferAlternative.reviewedBinding.version,
          normalizedBoundedParameters: knowledge.hazard.saferAlternative.reviewedBinding.normalizedParameters,
        },
      ));
    }
    knowledge.stack.forEach((component, index) => {
      result.push(candidate(`stack.${index}`, component.nodeType, component.name,
        `Reusable ${component.nodeType.replaceAll("_", " ")} stack component.`, { exactVersion: component.exactVersion }));
      result.push(candidate(`stack.${index}.version`, "exact_version_fingerprint",
        `${component.name} ${component.exactVersion}`, `Exact observed version fingerprint for ${component.name}.`,
        { exactVersion: component.exactVersion }));
    });
    knowledge.procedure.prerequisites.forEach((item, index) => result.push(candidate(
      `prerequisite.${index}`, "prerequisite", item, "Required condition for the reviewed procedure.", item,
    )));
    knowledge.scriptArtifacts?.forEach((artifact, index) => result.push(candidate(
      `script.${index}`,
      "script_artifact",
      `${artifact.name} ${artifact.version}`,
      artifact.purpose,
      {
        name: artifact.name,
        version: artifact.version,
        contentHash: artifact.contentHash,
        language: artifact.language,
        purpose: artifact.purpose,
      },
    )));
    knowledge.discoveries?.forEach((discovery, index) => result.push(candidate(
      `discovery.${index}`,
      "discovery_pattern",
      discovery.name,
      discovery.summary,
      { observation: discovery.summary },
    )));
    knowledge.outcomes?.forEach((outcome, index) => {
      result.push(candidate(
        `outcome.${index}`,
        "outcome",
        outcome.name,
        outcome.summary,
        {
          reportedStatus: outcome.status,
          outcomeClassification: "unclassified",
          classificationBasis: "compiler_report_only",
          summary: outcome.summary,
        },
      ));
      if (outcome.failureMode) {
        result.push(candidate(
          `outcome.${index}.failure`,
          "failure_mode",
          outcome.failureMode,
          `Reusable failure mode observed for ${outcome.name}.`,
          { mechanism: outcome.failureMode },
        ));
      }
    });
    knowledge.hazard.unaffectedComponents?.forEach((component, index) => result.push(candidate(
      `unaffected.${index}`,
      "attribute",
      `${component} remained healthy`,
      "Reusable unaffected-component signal observed during the failure.",
      { unaffectedComponent: component },
    )));
    knowledge.hazard.survivingHealthSignals?.forEach((signal, index) => result.push(candidate(
      `surviving-health.${index}`,
      "health_check",
      signal,
      "Health signal that continued to pass while the affected component stalled.",
      { survivingHealthSignal: signal },
    )));
    knowledge.hazard.retryValidConditions?.forEach((condition, index) => result.push(candidate(
      `retry-valid.${index}`,
      "health_check",
      condition,
      "Condition that must be freshly proven before a distinct safer attempt is eligible.",
      { retryValidCondition: condition },
    )));
    result.push(
      candidate("state", "target_state_transition", `${knowledge.hazard.stateBefore} → ${knowledge.hazard.stateAfter}`,
        "Reusable state transition observed after the exact procedure.", {
          stateBefore: knowledge.hazard.stateBefore,
          stateAfter: knowledge.hazard.stateAfter,
          symptom: knowledge.hazard.observedSymptom,
        }),
      candidate("health", "health_check", `${knowledge.hazard.affectedComponent} health gate`,
        "A harmless gate that must pass before another procedure attempt.", {
          orderedChecks: knowledge.hazard.healthGate,
        }),
      candidate("recovery", "recovery_pattern", knowledge.hazard.recoveryActionSummary,
        "Reviewed recovery pattern for the generalized operational hazard.", {
          action: knowledge.hazard.recoveryActionSummary,
          cost: knowledge.hazard.recoveryCost ?? {},
        }),
      candidate("alternative", "attack_procedure", knowledge.hazard.saferAlternative.name,
        "A safer bounded alternative to the procedure that produced the hazard.", {
          orderedSequence: knowledge.hazard.saferAlternative.orderedSteps,
        }),
      candidate("hazard", "operational_hazard", knowledge.hazard.name,
        `Do not blindly retry ${knowledge.procedure.name} when its health gate is failing.`, {
          stackAndVersionConstraints: stackConstraints,
          exactProcedure: {
            name: knowledge.procedure.name,
            version: knowledge.procedure.version,
            orderedSequence: knowledge.procedure.orderedSteps,
            normalizedBoundedParameters: knowledge.procedure.normalizedParameters,
            prerequisites: knowledge.procedure.prerequisites,
          },
          state: {
            before: knowledge.hazard.stateBefore,
            after: knowledge.hazard.stateAfter,
            symptom: knowledge.hazard.observedSymptom,
            affectedComponent: knowledge.hazard.affectedComponent,
            unaffectedComponents: knowledge.hazard.unaffectedComponents ?? [],
            survivingHealthSignals: knowledge.hazard.survivingHealthSignals ?? [],
          },
          exactProcedureCorroboration: {
            attemptCount: counts.attempts,
            reproducibleOutcomeCount: counts.reproducibleOutcomes,
            evidenceItemCount: counts.evidenceItems,
            exactResetCount: counts.exactResets,
          },
          operatorReportedAggregateResetMinimum: counts.operatorReportedAggregateResetMinimum,
          unsafeRetryConditions: knowledge.hazard.unsafeRetryConditions,
          healthGate: knowledge.hazard.healthGate,
          retryValidConditions: knowledge.hazard.retryValidConditions ?? [],
          recovery: {
            action: knowledge.hazard.recoveryActionSummary,
            cost: knowledge.hazard.recoveryCost ?? {},
          },
          saferAlternative: knowledge.hazard.saferAlternative,
          applicability: {
            loadMinimum: knowledge.hazard.loadMinimum ?? null,
            concurrencyMinimum: knowledge.hazard.concurrencyMinimum ?? null,
            timingWindowMs: knowledge.hazard.timingWindowMs ?? null,
          },
          freshness: {
            observedAt: input.source.observedAt,
            freshUntil: knowledge.hazard.freshUntil ?? null,
          },
          opaqueProvenanceReceiptIds: receiptIds,
        }),
    );
    return result;
  }

  #edgeProposals(input: NormalizedInput): readonly EdgeProposal[] {
    if (input.knowledge.kind === "reusable_bundle") return input.knowledge.edges;
    if (input.knowledge.kind !== "operational_hazard") return [];
    const knowledge = input.knowledge;
    const proposals: EdgeProposal[] = [
      { sourceRole: "product", edgeType: "has_exact_version", targetRole: "product.version" },
      { sourceRole: "procedure", edgeType: "has_exact_version", targetRole: "procedure.version" },
      { sourceRole: "procedure", edgeType: "tested_against", targetRole: "product" },
      { sourceRole: "procedure", edgeType: "tested_against", targetRole: "product.version" },
      { sourceRole: "procedure", edgeType: "caused", targetRole: "hazard" },
      { sourceRole: "procedure.version", edgeType: "caused", targetRole: "hazard" },
      { sourceRole: "procedure", edgeType: "safe_when", targetRole: "health" },
      { sourceRole: "hazard", edgeType: "leaves_in_state", targetRole: "state" },
      { sourceRole: "hazard", edgeType: "requires_recovery", targetRole: "recovery" },
      { sourceRole: "hazard", edgeType: "safe_when", targetRole: "health" },
      { sourceRole: "hazard", edgeType: "mitigated_by", targetRole: "recovery" },
      { sourceRole: "hazard", edgeType: "mitigated_by", targetRole: "health" },
      { sourceRole: "alternative", edgeType: "alternative_to", targetRole: "procedure" },
    ];
    if (knowledge.hazard.saferAlternative.reviewedBinding) {
      proposals.push({
        sourceRole: "alternative",
        edgeType: "has_exact_version",
        targetRole: "alternative.version",
      });
    }
    knowledge.stack.forEach((component, index) => {
      const role = `stack.${index}`;
      proposals.push({ sourceRole: role, edgeType: "has_exact_version", targetRole: `${role}.version` });
      proposals.push({ sourceRole: "procedure", edgeType: "tested_against", targetRole: role });
      proposals.push({ sourceRole: "procedure", edgeType: "tested_against", targetRole: `${role}.version` });
      if (component.nodeType === "operating_system" || component.nodeType === "kernel") {
        proposals.push({ sourceRole: "product", edgeType: "runs_on", targetRole: role });
      } else if (component.nodeType === "framework") {
        proposals.push({ sourceRole: "product", edgeType: "built_with", targetRole: role });
      } else if (component.nodeType === "runtime") {
        proposals.push({ sourceRole: "product", edgeType: "uses_runtime", targetRole: role });
      } else if (component.nodeType === "database") {
        proposals.push({ sourceRole: "product", edgeType: "uses_database", targetRole: role });
      } else if (["firewall", "waf", "proxy", "security_control"].includes(component.nodeType)) {
        proposals.push({ sourceRole: "product", edgeType: "protected_by", targetRole: role });
      }
    });
    knowledge.procedure.prerequisites.forEach((_item, index) => {
      proposals.push({ sourceRole: "procedure", edgeType: "requires", targetRole: `prerequisite.${index}` });
    });
    knowledge.scriptArtifacts?.forEach((_artifact, index) => {
      const scriptRole = `script.${index}`;
      proposals.push({ sourceRole: "procedure", edgeType: "implemented_by", targetRole: scriptRole });
      proposals.push({ sourceRole: "procedure.version", edgeType: "implemented_by", targetRole: scriptRole });
      proposals.push({ sourceRole: scriptRole, edgeType: "tested_against", targetRole: "product" });
      proposals.push({ sourceRole: scriptRole, edgeType: "tested_against", targetRole: "product.version" });
      knowledge.stack.forEach((_component, stackIndex) => {
        proposals.push({ sourceRole: scriptRole, edgeType: "tested_against", targetRole: `stack.${stackIndex}` });
        proposals.push({ sourceRole: scriptRole, edgeType: "tested_against", targetRole: `stack.${stackIndex}.version` });
      });
    });
    knowledge.discoveries?.forEach((_discovery, index) => {
      proposals.push({ sourceRole: "product", edgeType: "discovered_by", targetRole: `discovery.${index}` });
    });
    knowledge.outcomes?.forEach((outcome, index) => {
      const outcomeRole = `outcome.${index}`;
      proposals.push({ sourceRole: "procedure", edgeType: "produces_outcome", targetRole: outcomeRole });
      knowledge.scriptArtifacts?.forEach((_artifact, scriptIndex) => {
        proposals.push({ sourceRole: `script.${scriptIndex}`, edgeType: "produces_outcome", targetRole: outcomeRole });
      });
      if (outcome.failureMode) {
        proposals.push({ sourceRole: outcomeRole, edgeType: "failed_because", targetRole: `${outcomeRole}.failure` });
        proposals.push({ sourceRole: `${outcomeRole}.failure`, edgeType: "recovered_with", targetRole: "recovery" });
      }
    });
    knowledge.hazard.unaffectedComponents?.forEach((_component, index) => {
      proposals.push({ sourceRole: "hazard", edgeType: "safe_when", targetRole: `unaffected.${index}` });
    });
    knowledge.hazard.survivingHealthSignals?.forEach((_signal, index) => {
      proposals.push({ sourceRole: "hazard", edgeType: "safe_when", targetRole: `surviving-health.${index}` });
    });
    knowledge.hazard.retryValidConditions?.forEach((_condition, index) => {
      proposals.push({ sourceRole: "procedure", edgeType: "safe_when", targetRole: `retry-valid.${index}` });
      proposals.push({ sourceRole: "hazard", edgeType: "safe_when", targetRole: `retry-valid.${index}` });
    });
    return proposals.sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  }

  #validateEdgeProposals(
    proposals: readonly EdgeProposal[],
    blueprints: readonly CandidateBlueprint[],
  ): void {
    const nodeTypeByRole = new Map(blueprints.map((blueprint) => [blueprint.role, blueprint.input.nodeType]));
    for (const proposal of proposals) {
      const sourceType = nodeTypeByRole.get(proposal.sourceRole);
      const targetType = nodeTypeByRole.get(proposal.targetRole);
      if (!sourceType || !targetType) throw new TypeError("Attack knowledge edge proposal references a missing candidate role");
      validateAttackCentricEdgeEndpoints(proposal.edgeType, sourceType, targetType);
    }
  }
}

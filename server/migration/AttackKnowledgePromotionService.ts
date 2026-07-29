import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  isAttackCentricReusableNodeType,
  MemoryRepository,
  memoryContentHash,
  OperationalHazardProfileRepository,
  type AttackCentricEdgeType,
  type AttackCentricReusableNodeType,
  type MemoryCandidate,
  type MemoryEdge,
  type MemoryNode,
  type OperationalHazardProfile,
  type OperationalHazardProfileInput,
  validateAttackCentricEdgeEndpoints,
  validateAttackCentricReusableNode,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";
import { verifiedEvidenceSql } from "../domain/evidence-semantics";
import { AttackKnowledgeEvidenceProvenanceGuard } from "./AttackKnowledgeEvidenceProvenanceGuard";

const SHA256 = /^[a-f0-9]{64}$/u;
const REVIEWED_CANDIDATE_STATUSES: ReadonlySet<MemoryCandidate["status"]> = new Set([
  "confirmed",
  "edited_confirmed",
  "merged",
]);
const REVIEWED_NODE_LIFECYCLES: ReadonlySet<MemoryNode["lifecycleStatus"]> = new Set([
  "confirmed",
  "verified",
]);

type BundleKind = "operational_hazard" | "reusable_fact" | "reusable_bundle";
type EdgeAction = "create" | "reuse" | "blocked";
type ProfileAction = "create" | "update" | "reuse" | "blocked";
type Primitive = string | number | boolean;

interface BundleRow {
  readonly id: string;
  readonly semantic_fingerprint: string;
  readonly sanitized_bundle_json: string;
  readonly status: "staged" | "materialized";
  readonly exact_procedure_attempt_count: number;
  readonly exact_procedure_reproducibility_count: number;
  readonly exact_procedure_evidence_count: number;
  readonly exact_procedure_reset_count: number;
  readonly operator_reported_reset_count_minimum: number | null;
  readonly first_observed_at: string;
  readonly last_observed_at: string;
}

interface CandidateLinkRow {
  readonly role: string;
  readonly content_fingerprint: string;
  readonly required: number;
  readonly ordinal: number;
  readonly candidate_id: string;
  readonly registry_node_type: string;
}

interface EdgeProposalRow {
  readonly edge_key: string;
  readonly source_role: string;
  readonly target_role: string;
  readonly edge_type: AttackCentricEdgeType;
  readonly materialized_edge_id: string | null;
}

interface ExistingEdgeRow {
  readonly id: string;
  readonly source_node_id: string;
  readonly target_node_id: string;
  readonly edge_type: AttackCentricEdgeType;
  readonly scope: string;
  readonly engagement_id: string | null;
  readonly mission_id: string | null;
  readonly lifecycle_status: MemoryEdge["lifecycleStatus"];
  readonly author_type: MemoryEdge["authorType"];
  readonly version: number;
}

interface PromotionReceiptRow {
  readonly id: string;
  readonly bundle_id: string;
  readonly promotion_sequence: number;
  readonly review_hash: string;
  readonly review_document_json: string;
  readonly actor_id: string;
  readonly candidate_resolution_json: string;
  readonly edge_ids_json: string;
  readonly hazard_profile_node_id: string | null;
  readonly hazard_profile_version: number | null;
  readonly audit_record_id: string;
  readonly audit_record_hash: string;
  readonly promoted_at: string;
}

interface SanitizedStackComponent {
  readonly nodeType: AttackCentricReusableNodeType;
  readonly name: string;
  readonly exactVersion: string;
}

interface SanitizedOperationalHazardKnowledge {
  readonly kind: "operational_hazard";
  readonly product: { readonly name: string; readonly exactVersion: string };
  readonly stack: readonly SanitizedStackComponent[];
  readonly procedure: {
    readonly name: string;
    readonly version: string;
    readonly orderedSteps: readonly string[];
    readonly normalizedParameters: Readonly<Record<string, Primitive>>;
    readonly prerequisites: readonly string[];
  };
  readonly scriptArtifacts?: readonly {
    readonly name: string;
    readonly version: string;
    readonly contentHash: string;
    readonly language: string;
    readonly purpose: string;
  }[];
  readonly discoveries?: readonly {
    readonly name: string;
    readonly summary: string;
  }[];
  readonly outcomes?: readonly {
    readonly name: string;
    readonly status: "worked" | "failed";
    readonly summary: string;
    readonly failureMode?: string;
  }[];
  readonly hazard: {
    readonly name: string;
    readonly observedSymptom: string;
    readonly affectedComponent: string;
    readonly stateBefore: string;
    readonly stateAfter: string;
    readonly unaffectedComponents?: readonly string[];
    readonly survivingHealthSignals?: readonly string[];
    readonly unsafeRetryConditions: readonly string[];
    readonly healthGate: readonly string[];
    readonly retryValidConditions?: readonly string[];
    readonly recoveryActionSummary: string;
    readonly recoveryCost?: Readonly<Record<string, unknown>>;
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
}

interface SanitizedReusableFactKnowledge {
  readonly kind: "reusable_fact";
  readonly nodeType: AttackCentricReusableNodeType;
  readonly title: string;
  readonly summary: string;
  readonly body?: string;
}

interface SanitizedReusableBundleKnowledge {
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

type SanitizedKnowledge = SanitizedOperationalHazardKnowledge | SanitizedReusableFactKnowledge | SanitizedReusableBundleKnowledge;

export interface AttackKnowledgePromotionBlocker {
  readonly code:
    | "candidate_unreviewed"
    | "candidate_resolution_missing"
    | "candidate_type_mismatch"
    | "candidate_fingerprint_mismatch"
    | "node_not_operator_reviewed"
    | "node_not_reusable"
    | "node_not_confirmed"
    | "node_not_global"
    | "node_content_invalid"
    | "edge_endpoint_unresolved"
    | "edge_type_invalid"
    | "edge_conflict"
    | "profile_invalid"
    | "promotion_retry_contract_incomplete"
    | "verification_evidence_missing"
    | "verification_evidence_invalid";
  readonly role?: string;
  readonly edgeKey?: string;
  readonly message: string;
}

export interface AttackKnowledgeCandidateDiff {
  readonly role: string;
  readonly ordinal: number;
  readonly required: boolean;
  readonly expectedNodeType: string;
  readonly contentFingerprint: string;
  readonly candidateId: string;
  readonly candidateStatus: MemoryCandidate["status"] | "missing";
  readonly reviewedBy: string | null;
  readonly reviewedAt: string | null;
  readonly proposedNode: {
    readonly id: string;
    readonly nodeType: string;
    readonly version: number;
    readonly contentHash: string;
    readonly title: string;
    readonly summary: string;
    readonly body: string;
    readonly scope: MemoryNode["scope"];
    readonly sensitivity: MemoryNode["sensitivity"];
    readonly confidence: number;
    readonly lifecycleStatus: MemoryNode["lifecycleStatus"];
    readonly confirmationState: MemoryNode["confirmationState"];
    readonly authorType: MemoryNode["authorType"];
    readonly authorId: string | null;
  } | null;
}

export interface AttackKnowledgeEdgeDiff {
  readonly edgeKey: string;
  readonly sourceRole: string;
  readonly targetRole: string;
  readonly edgeType: AttackCentricEdgeType;
  readonly sourceNodeId: string | null;
  readonly targetNodeId: string | null;
  readonly action: EdgeAction;
  readonly materializedEdgeId: string | null;
  readonly existingEdgeVersion: number | null;
}

export interface AttackKnowledgeProfileDiff {
  readonly action: ProfileAction;
  readonly hazardNodeId: string | null;
  readonly expectedVersion: number | null;
  readonly current: OperationalHazardProfileInput | null;
  readonly desired: OperationalHazardProfileInput | null;
}

export interface AttackKnowledgeVerificationEvidenceDiff {
  readonly id: string;
  readonly contentHash: string;
  readonly evidenceType: string;
  readonly acquiredAt: string;
  readonly verificationState: "verified";
}

export interface AttackKnowledgePromotionReviewDocument {
  readonly schemaVersion: 2;
  readonly bundle: {
    readonly id: string;
    readonly semanticFingerprint: string;
    readonly kind: BundleKind;
    readonly exactProcedureCounts: {
      readonly attempts: number;
      readonly reproducibleOutcomes: number;
      readonly evidenceItems: number;
      readonly exactResets: number;
      readonly operatorReportedAggregateResetMinimum: number | null;
    };
    readonly firstObservedAt: string;
    readonly lastObservedAt: string;
  };
  readonly candidates: readonly AttackKnowledgeCandidateDiff[];
  readonly edges: readonly AttackKnowledgeEdgeDiff[];
  readonly operationalHazardProfile: AttackKnowledgeProfileDiff | null;
  readonly verification: {
    readonly minimumEvidenceItems: number;
    readonly evidence: readonly AttackKnowledgeVerificationEvidenceDiff[];
  };
}

export interface AttackKnowledgePromotionPreview {
  readonly ready: boolean;
  readonly replay: boolean;
  readonly reviewHash: string;
  readonly blockers: readonly AttackKnowledgePromotionBlocker[];
  readonly review: AttackKnowledgePromotionReviewDocument;
}

export interface AttackKnowledgePromotionResult {
  readonly status: "materialized" | "replayed";
  readonly receiptId: string;
  readonly bundleId: string;
  readonly reviewHash: string;
  readonly auditRecordId: string;
  readonly edgeIds: readonly string[];
  readonly hazardProfileNodeId: string | null;
  readonly hazardProfileVersion: number | null;
  readonly promotedAt: string;
}

export class AttackKnowledgePromotionError extends Error {
  constructor(
    readonly code:
      | "promotion_invalid_request"
      | "promotion_bundle_not_found"
      | "promotion_not_ready"
      | "promotion_stale_review"
      | "promotion_replay_conflict"
      | "promotion_retry_contract_incomplete"
      | "promotion_integrity_mismatch",
    message: string,
    readonly blockers: readonly AttackKnowledgePromotionBlocker[] = [],
  ) {
    super(message);
    this.name = "AttackKnowledgePromotionError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function parseJson<T>(value: string, label: string): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    throw new AttackKnowledgePromotionError(
      "promotion_integrity_mismatch",
      `${label} is malformed`,
    );
  }
}

function assertActor(value: string): string {
  const actor = value.trim().normalize("NFKC");
  if (!actor || Buffer.byteLength(actor, "utf8") > 256) {
    throw new AttackKnowledgePromotionError(
      "promotion_invalid_request",
      "An explicit operator actor is required",
    );
  }
  return actor;
}

function assertReviewHash(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!SHA256.test(normalized)) {
    throw new AttackKnowledgePromotionError(
      "promotion_invalid_request",
      "The expected review hash must be a lowercase SHA-256 digest",
    );
  }
  return normalized;
}

function evidenceIds(value: readonly string[]): readonly string[] {
  if (!Array.isArray(value) || value.length > 100) {
    throw new AttackKnowledgePromotionError(
      "promotion_invalid_request",
      "Verification evidence IDs must be a bounded array",
    );
  }
  const normalized = value.map((item) => {
    const id = typeof item === "string" ? item.trim() : "";
    if (!/^[A-Za-z0-9._:@/-]{1,300}$/u.test(id)) {
      throw new AttackKnowledgePromotionError(
        "promotion_invalid_request",
        "A verification evidence ID is invalid",
      );
    }
    return id;
  });
  if (new Set(normalized).size !== normalized.length) {
    throw new AttackKnowledgePromotionError(
      "promotion_invalid_request",
      "Verification evidence IDs contain duplicates",
    );
  }
  return Object.freeze([...normalized].sort());
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", `${label} is malformed`);
  }
  return value as Record<string, unknown>;
}

function stringValue(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", `${label} is malformed`);
  }
  return value;
}

function stringArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", `${label} is malformed`);
  }
  return value as readonly string[];
}

function optionalSafeNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function sanitizedKnowledge(bundle: BundleRow): SanitizedKnowledge {
  const root = object(parseJson<unknown>(bundle.sanitized_bundle_json, "Attack knowledge bundle"), "Attack knowledge bundle");
  if (root.schemaVersion !== 1) {
    throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Unsupported attack knowledge bundle schema");
  }
  const knowledge = object(root.knowledge, "Attack knowledge payload");
  if (knowledge.kind === "reusable_fact") {
    const nodeType = stringValue(knowledge.nodeType, "Reusable fact node type") as AttackCentricReusableNodeType;
    if (!isAttackCentricReusableNodeType(nodeType)) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Reusable fact type is not reusable attack knowledge");
    }
    return {
      kind: "reusable_fact",
      nodeType,
      title: stringValue(knowledge.title, "Reusable fact title"),
      summary: stringValue(knowledge.summary, "Reusable fact summary"),
      ...(typeof knowledge.body === "string" ? { body: knowledge.body } : {}),
    };
  }
  if (knowledge.kind === "reusable_bundle") {
    if (!Array.isArray(knowledge.facts) || knowledge.facts.length < 2 || knowledge.facts.length > 128 ||
        !Array.isArray(knowledge.edges) || knowledge.edges.length < 1 || knowledge.edges.length > 256) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Reusable attack bundle is malformed");
    }
    const roles = new Set<string>();
    const facts = knowledge.facts.map((value, index) => {
      const item = object(value, `Reusable bundle fact ${index}`);
      const role = stringValue(item.role, `Reusable bundle fact ${index} role`);
      const nodeType = stringValue(item.nodeType, `Reusable bundle fact ${index} type`) as AttackCentricReusableNodeType;
      if (!/^[A-Za-z][A-Za-z0-9._-]{0,127}$/u.test(role) || roles.has(role) || !isAttackCentricReusableNodeType(nodeType)) {
        throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Reusable bundle fact role or type is invalid");
      }
      roles.add(role);
      return {
        role,
        nodeType,
        title: stringValue(item.title, `Reusable bundle fact ${index} title`),
        summary: stringValue(item.summary, `Reusable bundle fact ${index} summary`),
        ...(typeof item.body === "string" ? { body: item.body } : {}),
      };
    });
    const nodeTypes = new Map(facts.map((item) => [item.role, item.nodeType]));
    const edgeIdentities = new Set<string>();
    const edges = knowledge.edges.map((value, index) => {
      const item = object(value, `Reusable bundle edge ${index}`);
      const sourceRole = stringValue(item.sourceRole, `Reusable bundle edge ${index} source`);
      const targetRole = stringValue(item.targetRole, `Reusable bundle edge ${index} target`);
      const edgeType = stringValue(item.edgeType, `Reusable bundle edge ${index} type`) as AttackCentricEdgeType;
      const sourceType = nodeTypes.get(sourceRole);
      const targetType = nodeTypes.get(targetRole);
      const identity = `${sourceRole}\0${edgeType}\0${targetRole}`;
      if (!sourceType || !targetType || edgeIdentities.has(identity)) {
        throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Reusable bundle edge endpoint is invalid");
      }
      edgeIdentities.add(identity);
      try { validateAttackCentricEdgeEndpoints(edgeType, sourceType, targetType); }
      catch {
        throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Reusable bundle edge type is invalid");
      }
      return { sourceRole, edgeType, targetRole };
    });
    return { kind: "reusable_bundle", facts, edges };
  }
  if (knowledge.kind !== "operational_hazard") {
    throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Unsupported attack knowledge kind");
  }
  const product = object(knowledge.product, "Hazard product");
  const procedure = object(knowledge.procedure, "Hazard procedure");
  const hazard = object(knowledge.hazard, "Operational hazard");
  const saferAlternative = object(hazard.saferAlternative, "Safer alternative");
  const reviewedAlternativeBinding = saferAlternative.reviewedBinding === undefined
    ? undefined
    : object(saferAlternative.reviewedBinding, "Reviewed safer-alternative binding");
  const alternativeParameters = reviewedAlternativeBinding === undefined
    ? undefined
    : object(reviewedAlternativeBinding.normalizedParameters, "Reviewed safer-alternative parameters");
  if (alternativeParameters) {
    for (const parameter of Object.values(alternativeParameters)) {
      if (!["string", "number", "boolean"].includes(typeof parameter)) {
        throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Reviewed safer-alternative parameters are malformed");
      }
    }
  }
  const retryConditionEvidence = saferAlternative.retryConditionEvidence === undefined
    ? undefined
    : (() => {
        if (!Array.isArray(saferAlternative.retryConditionEvidence)
          || saferAlternative.retryConditionEvidence.length === 0) {
          throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Reviewed retry-condition evidence is malformed");
        }
        return saferAlternative.retryConditionEvidence.map((value, index) => {
          const condition = object(value, `Reviewed retry condition ${index}`);
          return {
            statement: stringValue(condition.statement, `Reviewed retry condition ${index} statement`),
            evidenceKey: stringValue(condition.evidenceKey, `Reviewed retry condition ${index} evidence key`),
          };
        });
      })();
  if (!Array.isArray(knowledge.stack) || knowledge.stack.length === 0) {
    throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Operational hazard stack is malformed");
  }
  const stack = knowledge.stack.map((value, index) => {
    const component = object(value, `Stack component ${index}`);
    const nodeType = stringValue(component.nodeType, `Stack component ${index} type`) as AttackCentricReusableNodeType;
    if (!isAttackCentricReusableNodeType(nodeType)) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Operational hazard stack type is not reusable");
    }
    return {
      nodeType,
      name: stringValue(component.name, `Stack component ${index} name`),
      exactVersion: stringValue(component.exactVersion, `Stack component ${index} version`),
    };
  });
  const parameters = object(procedure.normalizedParameters, "Normalized procedure parameters");
  for (const parameter of Object.values(parameters)) {
    if (!["string", "number", "boolean"].includes(typeof parameter)) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Normalized procedure parameters are malformed");
    }
  }
  const scriptArtifacts = knowledge.scriptArtifacts === undefined
    ? undefined
    : (() => {
        if (!Array.isArray(knowledge.scriptArtifacts)) {
          throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Script artifacts are malformed");
        }
        return knowledge.scriptArtifacts.map((value, index) => {
          const artifact = object(value, `Script artifact ${index}`);
          const contentHash = stringValue(artifact.contentHash, `Script artifact ${index} content hash`);
          if (!SHA256.test(contentHash)) {
            throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Script artifact content hash is malformed");
          }
          return {
            name: stringValue(artifact.name, `Script artifact ${index} name`),
            version: stringValue(artifact.version, `Script artifact ${index} version`),
            contentHash,
            language: stringValue(artifact.language, `Script artifact ${index} language`),
            purpose: stringValue(artifact.purpose, `Script artifact ${index} purpose`),
          };
        });
      })();
  const discoveries = knowledge.discoveries === undefined
    ? undefined
    : (() => {
        if (!Array.isArray(knowledge.discoveries)) {
          throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Discoveries are malformed");
        }
        return knowledge.discoveries.map((value, index) => {
          const discovery = object(value, `Discovery ${index}`);
          return {
            name: stringValue(discovery.name, `Discovery ${index} name`),
            summary: stringValue(discovery.summary, `Discovery ${index} summary`),
          };
        });
      })();
  const outcomes = knowledge.outcomes === undefined
    ? undefined
    : (() => {
        if (!Array.isArray(knowledge.outcomes)) {
          throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Outcomes are malformed");
        }
        return knowledge.outcomes.map((value, index) => {
          const outcome = object(value, `Outcome ${index}`);
          if (outcome.status !== "worked" && outcome.status !== "failed") {
            throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Outcome status is malformed");
          }
          const status: "worked" | "failed" = outcome.status;
          return {
            name: stringValue(outcome.name, `Outcome ${index} name`),
            status,
            summary: stringValue(outcome.summary, `Outcome ${index} summary`),
            ...(typeof outcome.failureMode === "string"
              ? { failureMode: stringValue(outcome.failureMode, `Outcome ${index} failure mode`) }
              : {}),
          };
        });
      })();
  return {
    kind: "operational_hazard",
    product: {
      name: stringValue(product.name, "Product name"),
      exactVersion: stringValue(product.exactVersion, "Product version"),
    },
    stack,
    procedure: {
      name: stringValue(procedure.name, "Procedure name"),
      version: stringValue(procedure.version, "Procedure version"),
      orderedSteps: stringArray(procedure.orderedSteps, "Procedure steps"),
      normalizedParameters: parameters as Readonly<Record<string, Primitive>>,
      prerequisites: stringArray(procedure.prerequisites, "Procedure prerequisites"),
    },
    ...(scriptArtifacts?.length ? { scriptArtifacts } : {}),
    ...(discoveries?.length ? { discoveries } : {}),
    ...(outcomes?.length ? { outcomes } : {}),
    hazard: {
      name: stringValue(hazard.name, "Hazard name"),
      observedSymptom: stringValue(hazard.observedSymptom, "Hazard symptom"),
      affectedComponent: stringValue(hazard.affectedComponent, "Affected component"),
      stateBefore: stringValue(hazard.stateBefore, "State before"),
      stateAfter: stringValue(hazard.stateAfter, "State after"),
      ...(hazard.unaffectedComponents === undefined
        ? {}
        : { unaffectedComponents: stringArray(hazard.unaffectedComponents, "Unaffected components") }),
      ...(hazard.survivingHealthSignals === undefined
        ? {}
        : { survivingHealthSignals: stringArray(hazard.survivingHealthSignals, "Surviving health signals") }),
      unsafeRetryConditions: stringArray(hazard.unsafeRetryConditions, "Unsafe retry conditions"),
      healthGate: stringArray(hazard.healthGate, "Health gate"),
      ...(hazard.retryValidConditions === undefined
        ? {}
        : { retryValidConditions: stringArray(hazard.retryValidConditions, "Retry-valid conditions") }),
      recoveryActionSummary: stringValue(hazard.recoveryActionSummary, "Recovery action"),
      ...(hazard.recoveryCost && typeof hazard.recoveryCost === "object" && !Array.isArray(hazard.recoveryCost)
        ? { recoveryCost: hazard.recoveryCost as Readonly<Record<string, unknown>> }
        : {}),
      saferAlternative: {
        name: stringValue(saferAlternative.name, "Alternative name"),
        orderedSteps: stringArray(saferAlternative.orderedSteps, "Alternative steps"),
        ...(reviewedAlternativeBinding && alternativeParameters
          ? {
            reviewedBinding: {
              version: stringValue(reviewedAlternativeBinding.version, "Alternative version"),
              normalizedParameters: alternativeParameters as Readonly<Record<string, Primitive>>,
              ...(optionalSafeNumber(reviewedAlternativeBinding.sourceLoad) === undefined
                ? {}
                : { sourceLoad: Number(reviewedAlternativeBinding.sourceLoad) }),
              ...(optionalSafeNumber(reviewedAlternativeBinding.sourceConcurrency) === undefined
                ? {}
                : { sourceConcurrency: Number(reviewedAlternativeBinding.sourceConcurrency) }),
              ...(optionalSafeNumber(reviewedAlternativeBinding.sourceTimingWindowMs) === undefined
                ? {}
                : { sourceTimingWindowMs: Number(reviewedAlternativeBinding.sourceTimingWindowMs) }),
              ...(optionalSafeNumber(reviewedAlternativeBinding.load) === undefined
                ? {}
                : { load: Number(reviewedAlternativeBinding.load) }),
              ...(optionalSafeNumber(reviewedAlternativeBinding.concurrency) === undefined
                ? {}
                : { concurrency: Number(reviewedAlternativeBinding.concurrency) }),
              ...(optionalSafeNumber(reviewedAlternativeBinding.timingWindowMs) === undefined
                ? {}
                : { timingWindowMs: Number(reviewedAlternativeBinding.timingWindowMs) }),
            },
          }
          : {}),
        ...(retryConditionEvidence ? { retryConditionEvidence } : {}),
      },
      ...(optionalSafeNumber(hazard.loadMinimum) === undefined ? {} : { loadMinimum: Number(hazard.loadMinimum) }),
      ...(optionalSafeNumber(hazard.concurrencyMinimum) === undefined ? {} : { concurrencyMinimum: Number(hazard.concurrencyMinimum) }),
      ...(optionalSafeNumber(hazard.timingWindowMs) === undefined ? {} : { timingWindowMs: Number(hazard.timingWindowMs) }),
      ...(typeof hazard.freshUntil === "string" ? { freshUntil: hazard.freshUntil } : {}),
    },
  };
}

function expectedTypes(knowledge: SanitizedKnowledge): ReadonlyMap<string, AttackCentricReusableNodeType> {
  if (knowledge.kind === "reusable_fact") return new Map([["fact", knowledge.nodeType]]);
  if (knowledge.kind === "reusable_bundle") {
    return new Map(knowledge.facts.map((item) => [item.role, item.nodeType]));
  }
  const roles = new Map<string, AttackCentricReusableNodeType>([
    ["product", "technology_product"],
    ["product.version", "exact_version_fingerprint"],
    ["procedure", "attack_procedure"],
    ["procedure.version", "procedure_version"],
    ["state", "target_state_transition"],
    ["health", "health_check"],
    ["recovery", "recovery_pattern"],
    ["alternative", "attack_procedure"],
    ["hazard", "operational_hazard"],
  ]);
  if (knowledge.hazard.saferAlternative.reviewedBinding) {
    roles.set("alternative.version", "procedure_version");
  }
  knowledge.stack.forEach((component, index) => {
    roles.set(`stack.${index}`, component.nodeType);
    roles.set(`stack.${index}.version`, "exact_version_fingerprint");
  });
  knowledge.procedure.prerequisites.forEach((_value, index) => {
    roles.set(`prerequisite.${index}`, "prerequisite");
  });
  knowledge.scriptArtifacts?.forEach((_value, index) => {
    roles.set(`script.${index}`, "script_artifact");
  });
  knowledge.discoveries?.forEach((_value, index) => {
    roles.set(`discovery.${index}`, "discovery_pattern");
  });
  knowledge.outcomes?.forEach((outcome, index) => {
    roles.set(`outcome.${index}`, "outcome");
    if (outcome.failureMode) roles.set(`outcome.${index}.failure`, "failure_mode");
  });
  knowledge.hazard.unaffectedComponents?.forEach((_value, index) => {
    roles.set(`unaffected.${index}`, "attribute");
  });
  knowledge.hazard.survivingHealthSignals?.forEach((_value, index) => {
    roles.set(`surviving-health.${index}`, "health_check");
  });
  knowledge.hazard.retryValidConditions?.forEach((_value, index) => {
    roles.set(`retry-valid.${index}`, "health_check");
  });
  return roles;
}

function profileComparable(profile: OperationalHazardProfile): OperationalHazardProfileInput {
  const {
    version: _version,
    createdAt: _createdAt,
    updatedAt: _updatedAt,
    receiptBackedOccurrenceCount: _receiptBackedOccurrenceCount,
    ...input
  } = profile;
  return input;
}

function edgeIdentity(sourceNodeId: string, edgeType: string, targetNodeId: string): string {
  return `medge_${sha256(canonicalJson({ sourceNodeId, edgeType, targetNodeId }))}`;
}

function edgeLabel(edgeType: string): string {
  return edgeType.split("_").map((word) => `${word.slice(0, 1).toUpperCase()}${word.slice(1)}`).join(" ");
}

/**
 * Explicit operator gate between compiler candidates and reusable graph state.
 * Preview is read-only; promote re-runs that preview under BEGIN IMMEDIATE and
 * accepts only the exact reviewed digest.
 */
export class AttackKnowledgePromotionService {
  readonly #memory: MemoryRepository;
  readonly #profiles: OperationalHazardProfileRepository;
  readonly #evidenceProvenance: AttackKnowledgeEvidenceProvenanceGuard;
  readonly #clock: () => Date;

  constructor(
    private readonly database: SqliteDatabase,
    options: { readonly clock?: () => Date } = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#memory = new MemoryRepository(database, { clock: this.#clock });
    this.#profiles = new OperationalHazardProfileRepository(database, { clock: this.#clock });
    this.#evidenceProvenance = new AttackKnowledgeEvidenceProvenanceGuard(database);
  }

  preview(
    bundleFingerprint: string,
    verificationEvidenceIds: readonly string[] = [],
  ): AttackKnowledgePromotionPreview {
    const normalized = bundleFingerprint.trim().toLowerCase();
    if (!SHA256.test(normalized)) {
      throw new AttackKnowledgePromotionError(
        "promotion_invalid_request",
        "Bundle fingerprint must be a lowercase SHA-256 digest",
      );
    }
    const bundle = this.#requireBundle(normalized);
    if (bundle.status === "materialized") {
      const receipt = this.#latestReceipt(bundle.id);
      if (!receipt) {
        throw new AttackKnowledgePromotionError(
          "promotion_integrity_mismatch",
          "Materialized attack knowledge is missing its immutable promotion receipt",
        );
      }
      this.#verifyReceipt(bundle, receipt);
      const review = parseJson<AttackKnowledgePromotionReviewDocument>(
        receipt.review_document_json,
        "Promotion review document",
      );
      return { ready: true, replay: true, reviewHash: receipt.review_hash, blockers: [], review };
    }
    return this.#buildPreview(bundle, evidenceIds(verificationEvidenceIds));
  }

  promote(input: {
    readonly bundleFingerprint: string;
    readonly actor: string;
    readonly expectedReviewHash: string;
    readonly verificationEvidenceIds: readonly string[];
  }): AttackKnowledgePromotionResult {
    const actor = assertActor(input.actor);
    const expectedReviewHash = assertReviewHash(input.expectedReviewHash);
    const verificationEvidenceIds = evidenceIds(input.verificationEvidenceIds);
    const bundleFingerprint = input.bundleFingerprint.trim().toLowerCase();
    if (!SHA256.test(bundleFingerprint)) {
      throw new AttackKnowledgePromotionError(
        "promotion_invalid_request",
        "Bundle fingerprint must be a lowercase SHA-256 digest",
      );
    }
    return inImmediateTransaction(this.database, () => {
      const bundle = this.#requireBundle(bundleFingerprint);
      const replay = this.database.prepare(`
        SELECT * FROM attack_knowledge_promotion_receipts
        WHERE bundle_id = ? AND review_hash = ?
      `).get(bundle.id, expectedReviewHash) as PromotionReceiptRow | undefined;
      if (replay) {
        const latest = this.#latestReceipt(bundle.id);
        if (!latest || latest.id !== replay.id || replay.actor_id !== actor) {
          throw new AttackKnowledgePromotionError(
            "promotion_replay_conflict",
            "This promotion receipt belongs to a different operator review or has been superseded",
          );
        }
        this.#verifyReceipt(bundle, replay);
        const replayReview = parseJson<AttackKnowledgePromotionReviewDocument>(
          replay.review_document_json,
          "Promotion review document",
        );
        if (canonicalJson(replayReview.verification.evidence.map(({ id }) => id).sort())
          !== canonicalJson(verificationEvidenceIds)) {
          throw new AttackKnowledgePromotionError(
            "promotion_replay_conflict",
            "This promotion receipt was verified against a different canonical evidence set",
          );
        }
        return this.#resultFromReceipt(replay, "replayed");
      }
      if (bundle.status !== "staged") {
        throw new AttackKnowledgePromotionError(
          "promotion_replay_conflict",
          "The materialized bundle does not match the supplied review hash",
        );
      }
      const preview = this.#buildPreview(bundle, verificationEvidenceIds);
      if (!preview.ready) {
        throw new AttackKnowledgePromotionError(
          "promotion_not_ready",
          "Every staged candidate must be explicitly reviewed before promotion",
          preview.blockers,
        );
      }
      if (preview.reviewHash !== expectedReviewHash) {
        throw new AttackKnowledgePromotionError(
          "promotion_stale_review",
          "The reviewed candidate, edge, or profile diff changed; preview and approve the new hash",
        );
      }

      const now = this.#clock().toISOString();
      const verificationAudit = this.#appendVerificationAudit({
        actor,
        bundle,
        review: preview.review,
        reviewHash: preview.reviewHash,
        occurredAt: now,
      });
      for (const candidate of preview.review.candidates) {
        const nodeId = candidate.proposedNode?.id;
        if (!nodeId) {
          throw new AttackKnowledgePromotionError(
            "promotion_integrity_mismatch",
            "A reviewed candidate lost its durable node before verification",
          );
        }
        const node = this.#memory.requireNode(nodeId);
        if (node.lifecycleStatus === "verified") continue;
        this.#memory.verifyAttackKnowledgeNodeForPromotion(nodeId, {
          bundleId: bundle.id,
          reviewHash: preview.reviewHash,
          verificationAuditId: verificationAudit.id,
          verificationAuditHash: verificationAudit.hash,
          evidence: preview.review.verification.evidence.map((evidence) => ({
            id: evidence.id,
            contentHash: evidence.contentHash,
            acquiredAt: evidence.acquiredAt,
          })),
          actor,
        });
      }
      const edgeIds = preview.review.edges.map((edge) => this.#materializeEdge(bundle, edge, actor));
      const profile = this.#materializeProfile(preview.review.operationalHazardProfile);
      const audit = this.#appendAudit({
        actor,
        bundle,
        reviewHash: preview.reviewHash,
        candidateCount: preview.review.candidates.length,
        edgeIds,
        profile,
        verificationAudit,
        occurredAt: now,
      });

      for (let index = 0; index < preview.review.edges.length; index += 1) {
        const edge = preview.review.edges[index]!;
        this.database.prepare(`
          UPDATE attack_knowledge_bundle_edges
          SET materialized_edge_id = ?, materialized_at = ?
          WHERE bundle_id = ? AND edge_key = ?
        `).run(edgeIds[index], now, bundle.id, edge.edgeKey);
      }
      this.database.prepare(`
        UPDATE attack_knowledge_bundles
        SET status = 'materialized', materialized_at = ?, updated_at = ?
        WHERE id = ? AND status = 'staged'
      `).run(now, now, bundle.id);
      this.database.prepare(`
        UPDATE attack_knowledge_compiler_runs
        SET status = 'materialized', updated_at = ?, completed_at = ?
        WHERE bundle_id = ?
      `).run(now, now, bundle.id);

      const sequence = Number((this.database.prepare(`
        SELECT COALESCE(MAX(promotion_sequence), 0) + 1 AS sequence
        FROM attack_knowledge_promotion_receipts WHERE bundle_id = ?
      `).get(bundle.id) as { sequence: number }).sequence);
      const receiptId = `akprom_${preview.reviewHash}`;
      this.database.prepare(`
        INSERT INTO attack_knowledge_promotion_receipts (
          id, bundle_id, promotion_sequence, review_hash, review_document_json,
          actor_id, candidate_resolution_json, edge_ids_json,
          hazard_profile_node_id, hazard_profile_version,
          audit_record_id, audit_record_hash, promoted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        receiptId,
        bundle.id,
        sequence,
        preview.reviewHash,
        canonicalJson(preview.review),
        actor,
        canonicalJson(preview.review.candidates),
        canonicalJson(edgeIds),
        profile?.hazardNodeId ?? null,
        profile?.version ?? null,
        audit.id,
        audit.hash,
        now,
      );
      const receipt = this.database.prepare(`
        SELECT * FROM attack_knowledge_promotion_receipts WHERE id = ?
      `).get(receiptId) as PromotionReceiptRow;
      return this.#resultFromReceipt(receipt, "materialized");
    });
  }

  #buildPreview(
    bundle: BundleRow,
    verificationEvidenceIds: readonly string[],
  ): AttackKnowledgePromotionPreview {
    const knowledge = sanitizedKnowledge(bundle);
    const roleTypes = expectedTypes(knowledge);
    const blockers: AttackKnowledgePromotionBlocker[] = [];
    const links = this.database.prepare(`
      SELECT bc.role, bc.content_fingerprint, bc.required, bc.ordinal,
        registry.candidate_id, registry.node_type AS registry_node_type
      FROM attack_knowledge_bundle_candidates bc
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = bc.content_fingerprint
      WHERE bc.bundle_id = ? ORDER BY bc.ordinal, bc.role
    `).all(bundle.id) as CandidateLinkRow[];
    const actualRoles = new Set(links.map((link) => link.role));
    for (const role of roleTypes.keys()) {
      if (!actualRoles.has(role)) {
        blockers.push({ code: "candidate_resolution_missing", role, message: "A staged candidate role is missing" });
      }
    }
    for (const role of actualRoles) {
      if (!roleTypes.has(role)) {
        blockers.push({ code: "candidate_type_mismatch", role, message: "An unexpected candidate role was staged" });
      }
    }

    const candidates: AttackKnowledgeCandidateDiff[] = [];
    const nodeByRole = new Map<string, MemoryNode>();
    for (const link of links) {
      const expectedNodeType = roleTypes.get(link.role) ?? link.registry_node_type;
      const candidate = this.#memory.getCandidate(link.candidate_id);
      const node = candidate?.proposedNodeId ? this.#memory.getNode(candidate.proposedNodeId) : undefined;
      if (!candidate || !REVIEWED_CANDIDATE_STATUSES.has(candidate.status)) {
        blockers.push({ code: "candidate_unreviewed", role: link.role, message: "The candidate has not been explicitly confirmed by an operator" });
      }
      if (!candidate?.proposedNodeId || !candidate.reviewedBy || !candidate.reviewedAt || !node) {
        blockers.push({ code: "candidate_resolution_missing", role: link.role, message: "The reviewed candidate does not resolve to a durable memory node" });
      }
      if (candidate && memoryContentHash(candidate) !== link.content_fingerprint) {
        blockers.push({ code: "candidate_fingerprint_mismatch", role: link.role, message: "The staged candidate fingerprint no longer matches the candidate inbox record" });
      }
      if (
        candidate
        && (candidate.nodeType !== expectedNodeType
          || candidate.nodeType !== link.registry_node_type
          || node?.nodeType !== candidate.nodeType)
      ) {
        blockers.push({ code: "candidate_type_mismatch", role: link.role, message: "The candidate, registry, and reviewed node types do not match" });
      }
      if (node && !isAttackCentricReusableNodeType(node.nodeType)) {
        blockers.push({ code: "node_not_reusable", role: link.role, message: "The reviewed node is not reusable attack knowledge" });
      }
      if (node && !REVIEWED_NODE_LIFECYCLES.has(node.lifecycleStatus)) {
        blockers.push({ code: "node_not_confirmed", role: link.role, message: "The reviewed node is not confirmed or verified" });
      }
      if (node && node.confirmationState !== "confirmed") {
        blockers.push({ code: "node_not_confirmed", role: link.role, message: "The reviewed node lacks confirmed operator consent" });
      }
      if (node && node.authorType !== "operator") {
        blockers.push({ code: "node_not_operator_reviewed", role: link.role, message: "The materialized node was not authored through an operator review" });
      }
      if (node && (node.scope.kind !== "global" || node.scope.engagementId || node.scope.missionId)) {
        blockers.push({ code: "node_not_global", role: link.role, message: "Reusable attack knowledge must remain globally scoped" });
      }
      if (node) {
        try {
          validateAttackCentricReusableNode(node);
        } catch {
          blockers.push({ code: "node_content_invalid", role: link.role, message: "The reviewed node violates the reusable-memory privacy boundary" });
        }
      }
      if (node && !blockers.some((blocker) => blocker.role === link.role)) nodeByRole.set(link.role, node);
      candidates.push({
        role: link.role,
        ordinal: Number(link.ordinal),
        required: link.required === 1,
        expectedNodeType,
        contentFingerprint: link.content_fingerprint,
        candidateId: link.candidate_id,
        candidateStatus: candidate?.status ?? "missing",
        reviewedBy: candidate?.reviewedBy ?? null,
        reviewedAt: candidate?.reviewedAt ?? null,
        proposedNode: node ? {
          id: node.id,
          nodeType: node.nodeType,
          version: node.version,
          contentHash: memoryContentHash(node),
          title: node.title,
          summary: node.summary,
          body: node.body,
          scope: node.scope,
          sensitivity: node.sensitivity,
          confidence: node.confidence,
          lifecycleStatus: node.lifecycleStatus,
          confirmationState: node.confirmationState,
          authorType: node.authorType,
          authorId: node.authorId ?? null,
        } : null,
      });
    }

    const edgeRows = this.database.prepare(`
      SELECT edge_key, source_role, target_role, edge_type, materialized_edge_id
      FROM attack_knowledge_bundle_edges WHERE bundle_id = ?
      ORDER BY edge_key
    `).all(bundle.id) as EdgeProposalRow[];
    const edges = edgeRows.map((proposal): AttackKnowledgeEdgeDiff => {
      const source = nodeByRole.get(proposal.source_role);
      const target = nodeByRole.get(proposal.target_role);
      if (!source || !target) {
        blockers.push({ code: "edge_endpoint_unresolved", edgeKey: proposal.edge_key, message: "A staged edge endpoint is not backed by a reviewed node" });
        return {
          edgeKey: proposal.edge_key,
          sourceRole: proposal.source_role,
          targetRole: proposal.target_role,
          edgeType: proposal.edge_type,
          sourceNodeId: source?.id ?? null,
          targetNodeId: target?.id ?? null,
          action: "blocked",
          materializedEdgeId: null,
          existingEdgeVersion: null,
        };
      }
      try {
        validateAttackCentricEdgeEndpoints(proposal.edge_type, source.nodeType, target.nodeType);
      } catch {
        blockers.push({ code: "edge_type_invalid", edgeKey: proposal.edge_key, message: "The staged edge type is incompatible with its reviewed endpoints" });
        return {
          edgeKey: proposal.edge_key,
          sourceRole: proposal.source_role,
          targetRole: proposal.target_role,
          edgeType: proposal.edge_type,
          sourceNodeId: source.id,
          targetNodeId: target.id,
          action: "blocked",
          materializedEdgeId: null,
          existingEdgeVersion: null,
        };
      }
      const existing = this.database.prepare(`
        SELECT id, source_node_id, target_node_id, edge_type, scope,
          engagement_id, mission_id, lifecycle_status, author_type, version
        FROM memory_edges
        WHERE source_node_id = ? AND edge_type = ? AND target_node_id = ?
          AND lifecycle_status != 'forgotten'
        ORDER BY version DESC LIMIT 1
      `).get(source.id, proposal.edge_type, target.id) as ExistingEdgeRow | undefined;
      if (existing && (
        existing.scope !== "global"
        || existing.engagement_id !== null
        || existing.mission_id !== null
        || !REVIEWED_NODE_LIFECYCLES.has(existing.lifecycle_status)
        || existing.author_type !== "operator"
      )) {
        blockers.push({ code: "edge_conflict", edgeKey: proposal.edge_key, message: "An unreviewed or non-global relationship conflicts with this staged edge" });
        return {
          edgeKey: proposal.edge_key,
          sourceRole: proposal.source_role,
          targetRole: proposal.target_role,
          edgeType: proposal.edge_type,
          sourceNodeId: source.id,
          targetNodeId: target.id,
          action: "blocked",
          materializedEdgeId: existing.id,
          existingEdgeVersion: existing.version,
        };
      }
      return {
        edgeKey: proposal.edge_key,
        sourceRole: proposal.source_role,
        targetRole: proposal.target_role,
        edgeType: proposal.edge_type,
        sourceNodeId: source.id,
        targetNodeId: target.id,
        action: existing ? "reuse" : "create",
        materializedEdgeId: existing?.id ?? edgeIdentity(source.id, proposal.edge_type, target.id),
        existingEdgeVersion: existing?.version ?? null,
      };
    });

    let operationalHazardProfile: AttackKnowledgeProfileDiff | null = null;
    if (knowledge.kind === "operational_hazard") {
      try {
        const desired = this.#profileInput(bundle, knowledge, nodeByRole);
        const current = this.#profiles.get(desired.hazardNodeId);
        const currentInput = current ? profileComparable(current) : null;
        operationalHazardProfile = {
          action: current
            ? canonicalJson(currentInput) === canonicalJson(desired) ? "reuse" : "update"
            : "create",
          hazardNodeId: desired.hazardNodeId,
          expectedVersion: current?.version ?? null,
          current: currentInput,
          desired,
        };
      } catch (error) {
        blockers.push(error instanceof AttackKnowledgePromotionError
            && error.code === "promotion_retry_contract_incomplete"
          ? { code: "promotion_retry_contract_incomplete", message: error.message }
          : { code: "profile_invalid", message: "The operational-hazard profile cannot be built from the reviewed node set" });
        operationalHazardProfile = {
          action: "blocked",
          hazardNodeId: nodeByRole.get("hazard")?.id ?? null,
          expectedVersion: null,
          current: null,
          desired: null,
        };
      }
    }

    const minimumEvidenceItems = knowledge.kind === "operational_hazard"
      ? Math.max(1, Number(bundle.exact_procedure_evidence_count))
      : 1;
    const verificationEvidence: AttackKnowledgeVerificationEvidenceDiff[] = [];
    if (verificationEvidenceIds.length < minimumEvidenceItems) {
      blockers.push({
        code: "verification_evidence_missing",
        message: `This review requires at least ${minimumEvidenceItems} canonical verified evidence item${minimumEvidenceItems === 1 ? "" : "s"}`,
      });
    }
    for (const evidenceId of verificationEvidenceIds) {
      const row = this.database.prepare(`
        SELECT e.id, e.content_hash, e.evidence_type, e.acquired_at,
          binding.evidence_id AS bound_evidence_id,
          CASE WHEN (${verifiedEvidenceSql("e")}) AND EXISTS (
            SELECT 1 FROM evidence_chain_events custody
            WHERE custody.evidence_id = e.id AND custody.event_type = 'verified'
          ) THEN 1 ELSE 0 END AS canonical_verified
        FROM evidence e
        LEFT JOIN attack_knowledge_bundle_evidence_bindings binding
          ON binding.bundle_id = ? AND binding.evidence_id = e.id
          AND binding.content_hash = e.content_hash
          AND binding.acquired_at = e.acquired_at
        WHERE e.id = ?
      `).get(bundle.id, evidenceId) as {
        readonly id: string;
        readonly content_hash: string;
        readonly evidence_type: string;
        readonly acquired_at: string;
        readonly bound_evidence_id: string | null;
        readonly canonical_verified: number;
      } | undefined;
      if (!row || row.bound_evidence_id !== row.id
        || row.canonical_verified !== 1 || !SHA256.test(row.content_hash)) {
        blockers.push({
          code: "verification_evidence_invalid",
          message: `Evidence ${evidenceId} is missing, mutable operational output, or lacks canonical verification custody`,
        });
        continue;
      }
      verificationEvidence.push({
        id: row.id,
        contentHash: row.content_hash,
        evidenceType: row.evidence_type,
        acquiredAt: row.acquired_at,
        verificationState: "verified",
      });
    }
    if (knowledge.kind === "operational_hazard" && verificationEvidenceIds.length > 0) {
      const provenance = this.#evidenceProvenance.assess(bundle.id, verificationEvidenceIds);
      if (!provenance.valid) {
        blockers.push({
          code: "verification_evidence_invalid",
          message: "Canonical evidence is not bound to the exact current occurrence or approved historical import that produced this hazard",
        });
      }
    }

    const review: AttackKnowledgePromotionReviewDocument = {
      schemaVersion: 2,
      bundle: {
        id: bundle.id,
        semanticFingerprint: bundle.semantic_fingerprint,
        kind: knowledge.kind,
        exactProcedureCounts: {
          attempts: Number(bundle.exact_procedure_attempt_count),
          reproducibleOutcomes: Number(bundle.exact_procedure_reproducibility_count),
          evidenceItems: Number(bundle.exact_procedure_evidence_count),
          exactResets: Number(bundle.exact_procedure_reset_count),
          operatorReportedAggregateResetMinimum: bundle.operator_reported_reset_count_minimum === null
            ? null
            : Number(bundle.operator_reported_reset_count_minimum),
        },
        firstObservedAt: bundle.first_observed_at,
        lastObservedAt: bundle.last_observed_at,
      },
      candidates,
      edges,
      operationalHazardProfile,
      verification: {
        minimumEvidenceItems,
        evidence: verificationEvidence,
      },
    };
    return {
      ready: blockers.length === 0,
      replay: false,
      reviewHash: sha256(canonicalJson(review)),
      blockers,
      review,
    };
  }

  #profileInput(
    bundle: BundleRow,
    knowledge: SanitizedOperationalHazardKnowledge,
    nodeByRole: ReadonlyMap<string, MemoryNode>,
  ): OperationalHazardProfileInput {
    const required = (role: string): MemoryNode => {
      const node = nodeByRole.get(role);
      if (!node) throw new Error(`Missing reviewed node role ${role}`);
      return node;
    };
    const stackNodeIds = knowledge.stack.map((_item, index) => required(`stack.${index}`).id).sort();
    const versionNodeIds = [
      required("product.version").id,
      ...knowledge.stack.map((_item, index) => required(`stack.${index}.version`).id),
    ].sort();
    const prerequisiteNodeIds = knowledge.procedure.prerequisites
      .map((_item, index) => required(`prerequisite.${index}`).id)
      .sort();
    const sanitizedCost = knowledge.hazard.recoveryCost ?? {};
    const recoveryCost: NonNullable<OperationalHazardProfileInput["recoveryCost"]> = {
      resetCount: Number(bundle.exact_procedure_reset_count),
      ...(bundle.operator_reported_reset_count_minimum === null
        ? {}
        : { operatorReportedResetCountMinimum: Number(bundle.operator_reported_reset_count_minimum) }),
      ...(typeof sanitizedCost.serviceRecycleCount === "number"
        ? { serviceRecycleCount: sanitizedCost.serviceRecycleCount }
        : {}),
      ...(typeof sanitizedCost.downtimeMs === "number" ? { downtimeMs: sanitizedCost.downtimeMs } : {}),
      ...(typeof sanitizedCost.operatorMinutes === "number" ? { operatorMinutes: sanitizedCost.operatorMinutes } : {}),
      ...(typeof sanitizedCost.requiresDisposableTargetReset === "boolean"
        ? { requiresDisposableTargetReset: sanitizedCost.requiresDisposableTargetReset }
        : {}),
    };
    const state = required("state");
    const health = required("health");
    const safeRetryGate = [...new Set([
      ...knowledge.hazard.healthGate,
      ...(knowledge.hazard.retryValidConditions ?? []),
    ])];
    const reviewedBinding = knowledge.hazard.saferAlternative.reviewedBinding;
    const reviewedConditions = knowledge.hazard.saferAlternative.retryConditionEvidence;
    if (
      !reviewedBinding
      || reviewedBinding.sourceLoad === undefined
      || reviewedBinding.sourceConcurrency === undefined
      || reviewedBinding.sourceTimingWindowMs === undefined
      || reviewedBinding.load === undefined
      || reviewedBinding.concurrency === undefined
      || reviewedBinding.timingWindowMs === undefined
      || !reviewedConditions
      || reviewedConditions.length !== safeRetryGate.length
      || reviewedConditions.some((condition, index) => condition.statement !== safeRetryGate[index])
    ) {
      throw new AttackKnowledgePromotionError(
        "promotion_retry_contract_incomplete",
        "Promotion requires the exact reviewed source/alternative execution bindings and one local-evidence key for every safe-retry condition",
      );
    }
    const alternative = required("alternative");
    const alternativeVersion = required("alternative.version");
    return {
      hazardNodeId: required("hazard").id,
      procedureNodeId: required("procedure").id,
      procedureVersionNodeId: required("procedure.version").id,
      productNodeIds: [required("product").id],
      versionNodeIds,
      stackNodeIds,
      prerequisiteNodeIds,
      observedStateNodeIds: [health.id, state.id].sort(),
      orderedSteps: knowledge.procedure.orderedSteps,
      normalizedParameters: knowledge.procedure.normalizedParameters,
      ...(knowledge.hazard.loadMinimum === undefined ? {} : { loadMinimum: knowledge.hazard.loadMinimum }),
      ...(knowledge.hazard.concurrencyMinimum === undefined ? {} : { concurrencyMinimum: knowledge.hazard.concurrencyMinimum }),
      ...(knowledge.hazard.timingWindowMs === undefined ? {} : { timingWindowMs: knowledge.hazard.timingWindowMs }),
      observedSymptom: knowledge.hazard.observedSymptom,
      affectedComponent: knowledge.hazard.affectedComponent,
      stateBefore: knowledge.hazard.stateBefore,
      stateAfter: knowledge.hazard.stateAfter,
      stateTransitionNodeId: state.id,
      reproducibilityCount: Number(bundle.exact_procedure_reproducibility_count),
      attemptCount: Number(bundle.exact_procedure_attempt_count),
      recoveryPatternNodeId: required("recovery").id,
      recoveryActionSummary: knowledge.hazard.recoveryActionSummary,
      recoveryCost,
      unsafeRetryConditions: knowledge.hazard.unsafeRetryConditions,
      // A restored baseline is necessary but not sufficient when the original
      // procedure itself is known-bad. Persist both the recovery health checks
      // and the explicit conditions that make one materially distinct future
      // attempt eligible, preserving their reviewed order and removing exact
      // duplicates. The runtime therefore cannot treat "the page responds" as
      // permission to repeat the same hanging sequence.
      safeRetryGate,
      alternativeSequence: knowledge.hazard.saferAlternative.orderedSteps,
      alternativeProcedureNodeId: alternative.id,
      reviewedRetryContract: {
        schema: "ti_scale.operational_hazard_retry_contract/v1",
        alternativeKind: "explicit_alternative",
        source: {
          procedureNodeId: required("procedure").id,
          procedureVersionNodeId: required("procedure.version").id,
          normalizedParameters: knowledge.procedure.normalizedParameters,
          load: reviewedBinding.sourceLoad,
          concurrency: reviewedBinding.sourceConcurrency,
          timingWindowMs: reviewedBinding.sourceTimingWindowMs,
        },
        alternative: {
          procedureNodeId: alternative.id,
          procedureVersionNodeId: alternativeVersion.id,
          normalizedParameters: reviewedBinding.normalizedParameters,
          load: reviewedBinding.load,
          concurrency: reviewedBinding.concurrency,
          timingWindowMs: reviewedBinding.timingWindowMs,
        },
        retryValidConditions: reviewedConditions.map((condition, index) => ({
          id: `reviewed_condition_${index + 1}`,
          statement: condition.statement,
          evidenceKey: condition.evidenceKey,
        })),
      },
      applicabilityConstraints: {
        requireExactProcedureVersion: true,
        requireVerifiedVersionRelationship: false,
        requireAllStackNodes: true,
        requireAllPrerequisites: true,
        requireObservedState: true,
      },
      confidence: required("hazard").confidence,
      observedAt: bundle.last_observed_at,
      ...(knowledge.hazard.freshUntil ? { freshUntil: knowledge.hazard.freshUntil } : {}),
    };
  }

  #materializeEdge(bundle: BundleRow, diff: AttackKnowledgeEdgeDiff, actor: string): string {
    if (
      diff.action === "blocked"
      || !diff.sourceNodeId
      || !diff.targetNodeId
      || !diff.materializedEdgeId
    ) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "A blocked edge reached materialization");
    }
    if (diff.action === "reuse") {
      const existing = this.database.prepare(`
        SELECT id, lifecycle_status, version FROM memory_edges
        WHERE id = ? AND source_node_id = ? AND edge_type = ? AND target_node_id = ?
          AND scope = 'global' AND engagement_id IS NULL AND mission_id IS NULL
          AND lifecycle_status IN ('confirmed', 'verified') AND author_type = 'operator'
      `).get(
        diff.materializedEdgeId,
        diff.sourceNodeId,
        diff.edgeType,
        diff.targetNodeId,
      ) as { id: string; lifecycle_status: "confirmed" | "verified"; version: number } | undefined;
      if (!existing) throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "A reviewed reusable edge changed before promotion");
      if (existing.lifecycle_status === "confirmed") {
        const changed = this.database.prepare(`
          UPDATE memory_edges SET lifecycle_status = 'verified', author_type = 'operator',
            author_id = ?, version = version + 1, updated_at = ?
          WHERE id = ? AND version = ? AND lifecycle_status = 'confirmed'
        `).run(actor, this.#clock().toISOString(), existing.id, existing.version).changes;
        if (changed !== 1) {
          throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "A reviewed reusable edge changed during verification");
        }
      }
      return existing.id;
    }
    const label = edgeLabel(diff.edgeType);
    const edge = this.#memory.createEdge({
      id: diff.materializedEdgeId,
      sourceNodeId: diff.sourceNodeId,
      targetNodeId: diff.targetNodeId,
      edgeType: diff.edgeType,
      title: label,
      summary: "Operator-verified reusable attack-knowledge relationship.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: Math.min(
        this.#memory.requireNode(diff.sourceNodeId).confidence,
        this.#memory.requireNode(diff.targetNodeId).confidence,
      ),
      lifecycleStatus: "verified",
      provenance: {
        method: "derived",
        explanation: "Materialized from an exact evidence-backed operator-reviewed attack-knowledge promotion.",
        sources: [{
          sourceType: "attack_knowledge_bundle",
          sourceId: bundle.id,
          sourceHash: bundle.semantic_fingerprint,
          acquiredAt: bundle.last_observed_at,
        }],
      },
      explanation: `The operator verified the staged ${diff.edgeType} relationship against the promotion review evidence.`,
      authorType: "operator",
      authorId: actor,
    });
    if (edge.lifecycleStatus !== "verified") {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "A promoted edge was not stored as verified");
    }
    return edge.id;
  }

  #materializeProfile(diff: AttackKnowledgeProfileDiff | null): OperationalHazardProfile | null {
    if (!diff) return null;
    if (diff.action === "blocked" || !diff.desired) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "A blocked hazard profile reached materialization");
    }
    if (diff.action === "create") return this.#profiles.create(diff.desired);
    if (diff.action === "update") {
      if (diff.expectedVersion === null) {
        throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Hazard profile update is missing its expected version");
      }
      return this.#profiles.update(diff.desired, diff.expectedVersion);
    }
    const existing = this.#profiles.require(diff.desired.hazardNodeId);
    if (canonicalJson(profileComparable(existing)) !== canonicalJson(diff.desired)) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "A reviewed hazard profile changed before promotion");
    }
    return existing;
  }

  #appendVerificationAudit(input: {
    readonly actor: string;
    readonly bundle: BundleRow;
    readonly review: AttackKnowledgePromotionReviewDocument;
    readonly reviewHash: string;
    readonly occurredAt: string;
  }): { readonly id: string; readonly hash: string } {
    const previous = this.database.prepare("SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1")
      .get() as { record_hash: string } | undefined;
    const id = `audit_akverify_${input.reviewHash.slice(0, 40)}`;
    const details = canonicalJson({
      bundleFingerprint: input.bundle.semantic_fingerprint,
      reviewHash: input.reviewHash,
      evidenceIds: input.review.verification.evidence.map(({ id: evidenceId }) => evidenceId).sort(),
      evidence: input.review.verification.evidence.map((evidence) => ({
        id: evidence.id,
        contentHash: evidence.contentHash,
        evidenceType: evidence.evidenceType,
        acquiredAt: evidence.acquiredAt,
      })),
      candidateNodes: input.review.candidates.map((candidate) => ({
        role: candidate.role,
        nodeId: candidate.proposedNode?.id ?? null,
        version: candidate.proposedNode?.version ?? null,
        contentHash: candidate.proposedNode?.contentHash ?? null,
      })),
    });
    const hash = sha256(canonicalJson({
      id,
      actor: input.actor,
      action: "attack_knowledge.verification_approved",
      resourceType: "attack_knowledge_bundle",
      resourceId: input.bundle.id,
      reason: "Operator approved the exact candidate graph and canonical evidence set for verification",
      details,
      missionId: null,
      runId: null,
      journey: null,
      previousHash: previous?.record_hash ?? null,
      occurredAt: input.occurredAt,
    }));
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json, previous_hash,
        record_hash, occurred_at
      ) VALUES (?, NULL, NULL, NULL, 'operator', ?,
        'attack_knowledge.verification_approved', 'attack_knowledge_bundle', ?,
        'Operator approved the exact candidate graph and canonical evidence set for verification',
        ?, ?, ?, ?)
    `).run(
      id,
      input.actor,
      input.bundle.id,
      details,
      previous?.record_hash ?? null,
      hash,
      input.occurredAt,
    );
    return { id, hash };
  }

  #appendAudit(input: {
    readonly actor: string;
    readonly bundle: BundleRow;
    readonly reviewHash: string;
    readonly candidateCount: number;
    readonly edgeIds: readonly string[];
    readonly profile: OperationalHazardProfile | null;
    readonly verificationAudit: { readonly id: string; readonly hash: string };
    readonly occurredAt: string;
  }): { readonly id: string; readonly hash: string } {
    const previous = this.database.prepare("SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1")
      .get() as { record_hash: string } | undefined;
    const id = `audit_akpromotion_${input.reviewHash.slice(0, 40)}`;
    const details = canonicalJson({
      bundleFingerprint: input.bundle.semantic_fingerprint,
      reviewHash: input.reviewHash,
      verificationAuditId: input.verificationAudit.id,
      verificationAuditHash: input.verificationAudit.hash,
      candidateCount: input.candidateCount,
      edgeCount: input.edgeIds.length,
      edgeIds: [...input.edgeIds].sort(),
      hazardProfileNodeId: input.profile?.hazardNodeId ?? null,
      hazardProfileVersion: input.profile?.version ?? null,
      exactProcedureCounts: {
        attempts: Number(input.bundle.exact_procedure_attempt_count),
        reproducibleOutcomes: Number(input.bundle.exact_procedure_reproducibility_count),
        evidenceItems: Number(input.bundle.exact_procedure_evidence_count),
        exactResets: Number(input.bundle.exact_procedure_reset_count),
        operatorReportedAggregateResetMinimum: input.bundle.operator_reported_reset_count_minimum === null
          ? null
          : Number(input.bundle.operator_reported_reset_count_minimum),
      },
    });
    const hash = sha256(canonicalJson({
      id,
      actor: input.actor,
      action: "attack_knowledge.promoted",
      resourceType: "attack_knowledge_bundle",
      resourceId: input.bundle.id,
      reason: "Exact evidence-verified operator-reviewed attack knowledge materialized atomically",
      details,
      missionId: null,
      runId: null,
      journey: null,
      previousHash: previous?.record_hash ?? null,
      occurredAt: input.occurredAt,
    }));
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json, previous_hash,
        record_hash, occurred_at
      ) VALUES (?, NULL, NULL, NULL, 'operator', ?, 'attack_knowledge.promoted',
        'attack_knowledge_bundle', ?,
        'Exact evidence-verified operator-reviewed attack knowledge materialized atomically', ?, ?, ?, ?)
    `).run(
      id,
      input.actor,
      input.bundle.id,
      details,
      previous?.record_hash ?? null,
      hash,
      input.occurredAt,
    );
    return { id, hash };
  }

  #verifyReceipt(bundle: BundleRow, receipt: PromotionReceiptRow): void {
    if (bundle.status !== "materialized" || receipt.bundle_id !== bundle.id) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Promotion receipt bundle state is inconsistent");
    }
    const review = parseJson<AttackKnowledgePromotionReviewDocument>(
      receipt.review_document_json,
      "Promotion review document",
    );
    if (review.schemaVersion !== 2
      || sha256(canonicalJson(review)) !== receipt.review_hash) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Promotion review receipt hash is invalid");
    }
    if (review.bundle.kind === "operational_hazard") {
      const provenance = this.#evidenceProvenance.assess(
        bundle.id,
        review.verification.evidence.map(({ id }) => id),
      );
      if (!provenance.valid) {
        throw new AttackKnowledgePromotionError(
          "promotion_integrity_mismatch",
          "Promotion evidence no longer has its exact current-occurrence or approved historical-import provenance",
        );
      }
    }
    const audit = this.database.prepare(`
      SELECT record_hash, details_json FROM audit_records WHERE id = ?
    `).get(receipt.audit_record_id) as { record_hash: string; details_json: string } | undefined;
    if (!audit || audit.record_hash !== receipt.audit_record_hash) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Promotion audit receipt is invalid");
    }
    const promotionDetails = parseJson<Record<string, unknown>>(
      audit.details_json,
      "Promotion audit details",
    );
    const verificationAuditId = stringValue(
      promotionDetails.verificationAuditId,
      "Verification audit ID",
    );
    const verificationAuditHash = stringValue(
      promotionDetails.verificationAuditHash,
      "Verification audit hash",
    );
    const verificationAudit = this.database.prepare(`
      SELECT action, resource_id, record_hash, details_json FROM audit_records WHERE id = ?
    `).get(verificationAuditId) as {
      readonly action: string;
      readonly resource_id: string | null;
      readonly record_hash: string;
      readonly details_json: string;
    } | undefined;
    if (!verificationAudit
      || verificationAudit.action !== "attack_knowledge.verification_approved"
      || verificationAudit.resource_id !== bundle.id
      || verificationAudit.record_hash !== verificationAuditHash) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Verification audit receipt is invalid");
    }
    const verificationDetails = parseJson<Record<string, unknown>>(
      verificationAudit.details_json,
      "Verification audit details",
    );
    if (verificationDetails.reviewHash !== receipt.review_hash
      || canonicalJson(verificationDetails.evidenceIds)
        !== canonicalJson(review.verification.evidence.map(({ id }) => id).sort())) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Verification audit no longer matches the reviewed evidence set");
    }
    for (const evidence of review.verification.evidence) {
      const canonical = this.database.prepare(`
        SELECT e.id FROM evidence e
        JOIN attack_knowledge_bundle_evidence_bindings binding
          ON binding.bundle_id = ? AND binding.evidence_id = e.id
          AND binding.content_hash = e.content_hash
          AND binding.acquired_at = e.acquired_at
        WHERE e.id = ? AND e.content_hash = ?
          AND e.acquired_at = ? AND (${verifiedEvidenceSql("e")})
          AND EXISTS (
            SELECT 1 FROM evidence_chain_events custody
            WHERE custody.evidence_id = e.id AND custody.event_type = 'verified'
          )
      `).get(bundle.id, evidence.id, evidence.contentHash, evidence.acquiredAt);
      if (!canonical) throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Promotion evidence is missing or no longer canonical");
    }
    for (const candidate of review.candidates) {
      const nodeId = candidate.proposedNode?.id;
      if (!nodeId) throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Promotion candidate node mapping is incomplete");
      const node = this.database.prepare(`
        SELECT lifecycle_status, confirmation_state FROM memory_nodes WHERE id = ?
      `).get(nodeId) as { lifecycle_status: string; confirmation_state: string } | undefined;
      if (!node || node.lifecycle_status !== "verified" || node.confirmation_state !== "confirmed") {
        throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "A promoted attack-knowledge node is no longer verified");
      }
    }
    const edgeIds = parseJson<readonly string[]>(receipt.edge_ids_json, "Promotion edge IDs");
    const stagedEdges = this.database.prepare(`
      SELECT materialized_edge_id FROM attack_knowledge_bundle_edges
      WHERE bundle_id = ? ORDER BY edge_key
    `).all(bundle.id) as Array<{ materialized_edge_id: string | null }>;
    if (
      stagedEdges.some((edge) => !edge.materialized_edge_id)
      || canonicalJson(stagedEdges.map((edge) => edge.materialized_edge_id)) !== canonicalJson(edgeIds)
    ) {
      throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "Promotion edge mappings do not match the immutable receipt");
    }
    for (const edgeId of edgeIds) {
      const edge = this.database.prepare(`
        SELECT id FROM memory_edges WHERE id = ?
          AND scope = 'global' AND lifecycle_status = 'verified'
      `).get(edgeId);
      if (!edge) throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "A promoted edge is missing or no longer verified");
    }
    if (receipt.hazard_profile_node_id) {
      const profile = this.#profiles.get(receipt.hazard_profile_node_id);
      if (!profile || profile.version !== receipt.hazard_profile_version) {
        throw new AttackKnowledgePromotionError("promotion_integrity_mismatch", "The promoted operational-hazard profile changed unexpectedly");
      }
    }
  }

  #requireBundle(fingerprint: string): BundleRow {
    const bundle = this.database.prepare(`
      SELECT * FROM attack_knowledge_bundles WHERE semantic_fingerprint = ?
    `).get(fingerprint) as BundleRow | undefined;
    if (!bundle) {
      throw new AttackKnowledgePromotionError(
        "promotion_bundle_not_found",
        "The staged attack knowledge bundle was not found",
      );
    }
    return bundle;
  }

  #latestReceipt(bundleId: string): PromotionReceiptRow | undefined {
    return this.database.prepare(`
      SELECT * FROM attack_knowledge_promotion_receipts
      WHERE bundle_id = ? ORDER BY promotion_sequence DESC LIMIT 1
    `).get(bundleId) as PromotionReceiptRow | undefined;
  }

  #resultFromReceipt(
    receipt: PromotionReceiptRow,
    status: AttackKnowledgePromotionResult["status"],
  ): AttackKnowledgePromotionResult {
    return {
      status,
      receiptId: receipt.id,
      bundleId: receipt.bundle_id,
      reviewHash: receipt.review_hash,
      auditRecordId: receipt.audit_record_id,
      edgeIds: parseJson<readonly string[]>(receipt.edge_ids_json, "Promotion edge IDs"),
      hazardProfileNodeId: receipt.hazard_profile_node_id,
      hazardProfileVersion: receipt.hazard_profile_version,
      promotedAt: receipt.promoted_at,
    };
  }
}

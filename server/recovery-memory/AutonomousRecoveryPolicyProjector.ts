import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  MemoryRepository,
  type MemoryNode,
  type MemoryRetentionPolicy,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";
import type { FailureCategory } from "../supervisor";
import { AUTONOMOUS_RECOVERY_MEMORY_SCHEMA_VERSION } from "./types";

const POLICY_KEY = "autonomousRecovery";
const PROJECTOR_VERSION = "1" as const;
const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_BINDING_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}$/u;
const RECEIPT_SOURCE = /^akpr_[A-Za-z0-9._:@/-]+$/u;
const VERIFICATION_SOURCE = /^akverify_[a-f0-9]{64}$/u;
const SYSTEM_ACTOR = "system:autonomous-recovery-policy-projector";

type ProjectionIgnoredReason =
  | "not_verified_and_confirmed"
  | "not_connected_vault_backed"
  | "promotion_or_evidence_provenance_invalid"
  | "body_schema_invalid"
  | "failure_mode_not_mapped"
  | "strict_procedure_binding_missing"
  | "policy_already_current";

interface PromotionProofRow {
  readonly promotion_receipt_id: string;
  readonly bundle_id: string;
  readonly review_hash: string;
  readonly audit_record_id: string;
  readonly audit_record_hash: string;
  readonly promoted_at: string;
}

interface ProcedureBinding {
  readonly procedureNodeId: string;
  readonly procedureVersionNodeId?: string;
  readonly actionType: string;
  readonly actionClass: string;
}

interface DerivedRecoveryPolicy {
  readonly schemaVersion: typeof AUTONOMOUS_RECOVERY_MEMORY_SCHEMA_VERSION;
  readonly match: Readonly<{
    failureCategories?: readonly FailureCategory[];
    actionTypes?: readonly string[];
    actionClasses?: readonly string[];
  }>;
  readonly effects: Readonly<{
    denyRetry?: true;
    minimumBackoffMs?: number;
  }>;
}

interface FailureModeMapping {
  readonly category: FailureCategory;
  readonly minimumBackoffMs: number;
}

/**
 * Closed mappings from exact structured values emitted by the historical
 * compiler to existing supervisor categories. Ambiguous historical labels
 * are deliberately not projected.
 */
const FAILURE_MODE_MAPPINGS: Readonly<Record<string, FailureModeMapping>> = {
  "Application or system hang": { category: "timeout", minimumBackoffMs: 15_000 },
  "Execution timeout": { category: "timeout", minimumBackoffMs: 5_000 },
  "Process or system crash": { category: "process_crash", minimumBackoffMs: 15_000 },
  "Service became unavailable": { category: "transient_network", minimumBackoffMs: 10_000 },
};

export interface AutonomousRecoveryPolicyProjectionReport {
  readonly schemaVersion: "ti-scale.autonomous-recovery-policy-projection.v1";
  readonly projectorVersion: typeof PROJECTOR_VERSION;
  readonly scanned: number;
  readonly eligible: number;
  readonly projected: number;
  readonly unchanged: number;
  readonly changedNodeIds: readonly string[];
  readonly ignored: Readonly<Record<string, ProjectionIgnoredReason>>;
  readonly auditRecordId?: string;
  readonly vaultProjectionRequested: boolean;
}

export interface AutonomousRecoveryPolicyProjectorOptions {
  readonly clock?: () => Date;
  readonly idFactory?: (prefix: string) => string;
  readonly projectMemoryNodes?: (nodeIds: readonly string[]) => void;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedKeys = new Set(allowed);
  return Object.keys(value).every((key) => allowedKeys.has(key));
}

function nonEmptyBoundedString(value: unknown, maximum = 1_000): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= maximum;
}

function boundedStringArray(value: unknown, maximumItems = 64): value is readonly string[] {
  return Array.isArray(value)
    && value.length > 0
    && value.length <= maximumItems
    && value.every((item) => nonEmptyBoundedString(item));
}

function parseJsonBody(body: string): Record<string, unknown> | undefined {
  try {
    return object(JSON.parse(body));
  } catch {
    return undefined;
  }
}

/** Parse compiler-owned fields only; titles, summaries, and prose are absent. */
export function structuredFailureMode(body: string): string | undefined {
  const value = parseJsonBody(body);
  if (!value) return undefined;
  if ("failureMode" in value) {
    if (!hasOnlyKeys(value, [
      "failureMode", "causeCategory", "product", "exactVersion", "procedure", "associationKey",
    ])) return undefined;
    if (!nonEmptyBoundedString(value.failureMode, 256)) return undefined;
    for (const optional of [
      "causeCategory", "product", "exactVersion", "procedure", "associationKey",
    ] as const) {
      if (value[optional] !== undefined && !nonEmptyBoundedString(value[optional], 512)) return undefined;
    }
    return value.failureMode;
  }
  if (!hasOnlyKeys(value, ["mechanism"]) || Object.keys(value).length !== 1) return undefined;
  return nonEmptyBoundedString(value.mechanism, 256) ? value.mechanism : undefined;
}

/**
 * Hazard bodies are only an eligibility schema check. Effects come from
 * canonical procedure/action bindings, never from body text.
 */
export function structuredOperationalHazardBody(body: string): boolean {
  const value = parseJsonBody(body);
  if (!value) return false;
  if ("unsafeRetryCondition" in value) {
    if (!hasOnlyKeys(value, ["unsafeRetryCondition", "matchingRequired", "associationKey"])) return false;
    if (!nonEmptyBoundedString(value.unsafeRetryCondition, 2_000)) return false;
    if (!boundedStringArray(value.matchingRequired, 16)) return false;
    return value.associationKey === undefined || nonEmptyBoundedString(value.associationKey, 512);
  }
  const expectedKeys = [
    "stackAndVersionConstraints", "exactProcedure", "state", "exactProcedureCorroboration",
    "operatorReportedAggregateResetMinimum", "unsafeRetryConditions", "healthGate",
    "retryValidConditions", "recovery", "saferAlternative", "applicability", "freshness",
    "opaqueProvenanceReceiptIds",
  ] as const;
  if (
    !hasOnlyKeys(value, expectedKeys)
    || Object.keys(value).length !== expectedKeys.length
    || !Array.isArray(value.stackAndVersionConstraints)
    || !object(value.exactProcedure)
    || !object(value.state)
    || !object(value.exactProcedureCorroboration)
    || !boundedStringArray(value.unsafeRetryConditions)
    || !boundedStringArray(value.healthGate)
    || !Array.isArray(value.retryValidConditions)
    || !object(value.recovery)
    || !object(value.saferAlternative)
    || !object(value.applicability)
    || !object(value.freshness)
    || !boundedStringArray(value.opaqueProvenanceReceiptIds)
  ) return false;
  const procedure = object(value.exactProcedure)!;
  if (!hasOnlyKeys(procedure, [
    "name", "version", "orderedSequence", "normalizedBoundedParameters", "prerequisites",
  ])) return false;
  return nonEmptyBoundedString(procedure.name, 500)
    && nonEmptyBoundedString(procedure.version, 500)
    && boundedStringArray(procedure.orderedSequence)
    && object(procedure.normalizedBoundedParameters) !== undefined
    && boundedStringArray(procedure.prerequisites);
}

function exactPolicy(
  failure: FailureModeMapping | undefined,
  binding: ProcedureBinding | undefined,
): DerivedRecoveryPolicy | undefined {
  if (!failure && !binding) return undefined;
  return {
    schemaVersion: AUTONOMOUS_RECOVERY_MEMORY_SCHEMA_VERSION,
    match: {
      ...(failure ? { failureCategories: [failure.category] } : {}),
      ...(binding ? {
        actionTypes: [binding.actionType.toLocaleLowerCase("en-US")],
        actionClasses: [binding.actionClass.toLocaleLowerCase("en-US")],
      } : {}),
    },
    effects: {
      ...(binding ? { denyRetry: true as const } : {}),
      ...(failure ? { minimumBackoffMs: failure.minimumBackoffMs } : {}),
    },
  };
}

/**
 * Idempotently converts evidence-promoted historical failure facts into the
 * typed recovery policy already consumed by MissionRuntimeEngine.
 */
export class AutonomousRecoveryPolicyProjector {
  readonly #memory: MemoryRepository;
  readonly #clock: () => Date;
  readonly #idFactory: (prefix: string) => string;
  readonly #projectMemoryNodes?: (nodeIds: readonly string[]) => void;

  constructor(
    readonly database: SqliteDatabase,
    options: AutonomousRecoveryPolicyProjectorOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#idFactory = options.idFactory ?? ((prefix) => `${prefix}_${randomUUID()}`);
    this.#projectMemoryNodes = options.projectMemoryNodes;
    this.#memory = new MemoryRepository(database, { clock: this.#clock });
  }

  project(): AutonomousRecoveryPolicyProjectionReport {
    const nodeIds = (this.database.prepare(`
      SELECT id FROM memory_nodes
      WHERE node_type IN ('failure_mode', 'operational_hazard')
        AND lifecycle_status != 'forgotten'
      ORDER BY id
    `).all() as Array<{ readonly id: string }>).map(({ id }) => id);
    const ignored: Record<string, ProjectionIgnoredReason> = {};
    const changedNodeIds: string[] = [];
    let eligible = 0;
    let unchanged = 0;
    let auditRecordId: string | undefined;

    inImmediateTransaction(this.database, () => {
      const changes: Array<{
        readonly nodeId: string;
        readonly fromVersion: number;
        readonly toVersion: number;
        readonly promotionReceiptId: string;
        readonly reviewHash: string;
        readonly policyHash: string;
      }> = [];
      for (const nodeId of nodeIds) {
        const node = this.#memory.requireNode(nodeId);
        if (node.lifecycleStatus !== "verified" || node.confirmationState !== "confirmed") {
          ignored[node.id] = "not_verified_and_confirmed";
          continue;
        }
        if (!this.#isConnectedVaultBacked(node.id)) {
          ignored[node.id] = "not_connected_vault_backed";
          continue;
        }
        const proof = this.#promotionProof(node);
        if (!proof) {
          ignored[node.id] = "promotion_or_evidence_provenance_invalid";
          continue;
        }

        let failure: FailureModeMapping | undefined;
        if (node.nodeType === "failure_mode") {
          const failureMode = structuredFailureMode(node.body);
          if (!failureMode) {
            ignored[node.id] = "body_schema_invalid";
            continue;
          }
          failure = FAILURE_MODE_MAPPINGS[failureMode];
          if (!failure) {
            ignored[node.id] = "failure_mode_not_mapped";
            continue;
          }
        } else if (!structuredOperationalHazardBody(node.body)) {
          ignored[node.id] = "body_schema_invalid";
          continue;
        }

        const binding = this.#strictProcedureBinding(node);
        const policy = exactPolicy(failure, binding);
        if (!policy) {
          ignored[node.id] = "strict_procedure_binding_missing";
          continue;
        }
        eligible += 1;
        if (canonicalJson(node.retentionPolicy[POLICY_KEY] ?? null) === canonicalJson(policy)) {
          ignored[node.id] = "policy_already_current";
          unchanged += 1;
          continue;
        }
        const retentionPolicy: MemoryRetentionPolicy = {
          ...node.retentionPolicy,
          [POLICY_KEY]: policy,
        };
        const updated = this.#memory.correctNode(node.id, {
          retentionPolicy,
          // Preserve the operator-reviewed knowledge authorship. The separate
          // hash-linked projection audit identifies this system operation.
          authorType: node.authorType,
          ...(node.authorId ? { authorId: node.authorId } : {}),
          changeReason: "Projected evidence-verified historical failure knowledge into a bounded Autonomous recovery policy.",
        });
        changedNodeIds.push(node.id);
        changes.push({
          nodeId: node.id,
          fromVersion: node.version,
          toVersion: updated.version,
          promotionReceiptId: proof.promotion_receipt_id,
          reviewHash: proof.review_hash,
          policyHash: sha256(canonicalJson(policy)),
        });
      }
      if (changes.length > 0) auditRecordId = this.#appendAudit(changes);
    });

    if (changedNodeIds.length > 0) this.#projectMemoryNodes?.(changedNodeIds);
    return {
      schemaVersion: "ti-scale.autonomous-recovery-policy-projection.v1",
      projectorVersion: PROJECTOR_VERSION,
      scanned: nodeIds.length,
      eligible,
      projected: changedNodeIds.length,
      unchanged,
      changedNodeIds,
      ignored,
      ...(auditRecordId ? { auditRecordId } : {}),
      vaultProjectionRequested: changedNodeIds.length > 0 && Boolean(this.#projectMemoryNodes),
    };
  }

  #isConnectedVaultBacked(nodeId: string): boolean {
    return Boolean(this.database.prepare(`
      SELECT 1 AS eligible
      FROM vault_connections connection
      JOIN vault_sync_state sync ON sync.connection_id = connection.id
      WHERE connection.status = 'connected' AND sync.node_id = ? AND sync.status = 'synced'
      LIMIT 1
    `).get(nodeId));
  }

  #promotionProof(node: MemoryNode): PromotionProofRow | undefined {
    const receiptSource = node.provenance.sources.find((source) =>
      source.sourceType === "attack_knowledge_receipt"
      && RECEIPT_SOURCE.test(source.sourceId)
      && Boolean(source.sourceHash && SHA256.test(source.sourceHash)));
    const verificationSource = node.provenance.sources.find((source) =>
      source.sourceType === "attack_knowledge_verification"
      && VERIFICATION_SOURCE.test(source.sourceId)
      && Boolean(source.sourceHash && SHA256.test(source.sourceHash)));
    if (!receiptSource || !verificationSource) return undefined;
    return this.database.prepare(`
      SELECT promotion.id AS promotion_receipt_id, promotion.bundle_id,
        promotion.review_hash, promotion.audit_record_id,
        promotion.audit_record_hash, promotion.promoted_at
      FROM attack_knowledge_promotion_receipts promotion,
        json_each(promotion.candidate_resolution_json) candidate
      JOIN audit_records promotion_audit
        ON promotion_audit.id = promotion.audit_record_id
        AND promotion_audit.record_hash = promotion.audit_record_hash
        AND promotion_audit.action = 'attack_knowledge.promoted'
      WHERE json_extract(candidate.value, '$.proposedNode.id') = ?
        AND json_extract(candidate.value, '$.proposedNode.nodeType') = ?
        AND promotion.review_hash = substr(?, length('akverify_') + 1)
        AND EXISTS (
          SELECT 1 FROM attack_knowledge_bundle_receipts source_receipt
          WHERE source_receipt.bundle_id = promotion.bundle_id
            AND source_receipt.receipt_id = ?
        )
        AND EXISTS (
          SELECT 1 FROM audit_records verification_audit
          WHERE verification_audit.record_hash = ?
            AND verification_audit.action = 'attack_knowledge.verification_approved'
            AND verification_audit.resource_type = 'attack_knowledge_bundle'
            AND verification_audit.resource_id = promotion.bundle_id
            AND json_extract(verification_audit.details_json, '$.reviewHash') =
              promotion.review_hash
        )
        AND EXISTS (
          SELECT 1 FROM memory_versions version
          WHERE version.node_id = ?
            AND version.content_hash = json_extract(candidate.value, '$.proposedNode.contentHash')
        )
        AND EXISTS (
          SELECT 1
          FROM memory_sources source
          JOIN evidence canonical ON canonical.id = source.evidence_id
          JOIN attack_knowledge_bundle_evidence_bindings binding
            ON binding.bundle_id = promotion.bundle_id
            AND binding.evidence_id = canonical.id
            AND binding.content_hash = canonical.content_hash
            AND binding.acquired_at = canonical.acquired_at
          WHERE source.node_id = ?
            AND source.source_type = 'attack_knowledge_evidence_binding'
            AND source.source_hash = canonical.content_hash
            AND canonical.verification_state = 'verified'
            AND lower(trim(canonical.evidence_type)) <> 'command_output'
            AND EXISTS (
              SELECT 1 FROM evidence_chain_events custody
              WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified'
            )
        )
      ORDER BY promotion.promoted_at DESC, promotion.id DESC
      LIMIT 1
    `).get(
      node.id,
      node.nodeType,
      verificationSource.sourceId,
      receiptSource.sourceId,
      verificationSource.sourceHash!,
      node.id,
      node.id,
    ) as PromotionProofRow | undefined;
  }

  #strictProcedureBinding(node: MemoryNode): ProcedureBinding | undefined {
    const procedures = node.nodeType === "operational_hazard"
      ? this.#hazardProcedures(node.id)
      : this.#failureProcedures(node.id);
    if (procedures.length !== 1) return undefined;
    const procedure = procedures[0]!;
    const rows = this.database.prepare(`
      SELECT DISTINCT binding.action_type, binding.action_class
      FROM attack_attempt_knowledge_contexts context
      JOIN attack_attempt_action_bindings binding
        ON binding.attack_attempt_id = context.attack_attempt_id
      WHERE context.procedure_node_id = ?
        AND (? IS NULL OR context.procedure_version_node_id = ?)
      ORDER BY binding.action_type, binding.action_class
    `).all(
      procedure.procedureNodeId,
      procedure.procedureVersionNodeId ?? null,
      procedure.procedureVersionNodeId ?? null,
    ) as Array<{ readonly action_type: string; readonly action_class: string }>;
    if (rows.length !== 1) return undefined;
    const actionType = rows[0]!.action_type.trim();
    const actionClass = rows[0]!.action_class.trim();
    if (!SAFE_BINDING_VALUE.test(actionType) || !SAFE_BINDING_VALUE.test(actionClass)) return undefined;
    return { ...procedure, actionType, actionClass };
  }

  #hazardProcedures(nodeId: string): readonly {
    readonly procedureNodeId: string;
    readonly procedureVersionNodeId?: string;
  }[] {
    const profile = this.database.prepare(`
      SELECT procedure_node_id, procedure_version_node_id
      FROM operational_hazard_profiles WHERE node_id = ?
    `).get(nodeId) as {
      readonly procedure_node_id: string;
      readonly procedure_version_node_id: string | null;
    } | undefined;
    if (profile) {
      return [{
        procedureNodeId: profile.procedure_node_id,
        ...(profile.procedure_version_node_id
          ? { procedureVersionNodeId: profile.procedure_version_node_id }
          : {}),
      }];
    }
    const rows = this.database.prepare(`
      SELECT DISTINCT source.id AS procedure_node_id
      FROM memory_edges edge
      JOIN memory_nodes source ON source.id = edge.source_node_id
      WHERE edge.target_node_id = ? AND edge.edge_type = 'caused'
        AND edge.lifecycle_status = 'verified'
        AND source.node_type = 'attack_procedure'
        AND source.lifecycle_status = 'verified'
      ORDER BY source.id
    `).all(nodeId) as Array<{ readonly procedure_node_id: string }>;
    return rows.map((row) => ({ procedureNodeId: row.procedure_node_id }));
  }

  #failureProcedures(nodeId: string): readonly {
    readonly procedureNodeId: string;
    readonly procedureVersionNodeId?: string;
  }[] {
    const rows = this.database.prepare(`
      SELECT DISTINCT procedure.id AS procedure_node_id
      FROM memory_edges failure_edge
      JOIN memory_nodes outcome ON outcome.id = failure_edge.source_node_id
      JOIN memory_edges procedure_edge
        ON procedure_edge.target_node_id = outcome.id
        AND procedure_edge.edge_type = 'produces_outcome'
        AND procedure_edge.lifecycle_status = 'verified'
      JOIN memory_nodes procedure ON procedure.id = procedure_edge.source_node_id
      WHERE failure_edge.target_node_id = ?
        AND failure_edge.edge_type = 'failed_because'
        AND failure_edge.lifecycle_status = 'verified'
        AND outcome.node_type = 'outcome' AND outcome.lifecycle_status = 'verified'
        AND procedure.node_type = 'attack_procedure'
        AND procedure.lifecycle_status = 'verified'
      ORDER BY procedure.id
    `).all(nodeId) as Array<{ readonly procedure_node_id: string }>;
    return rows.map((row) => ({ procedureNodeId: row.procedure_node_id }));
  }

  #appendAudit(changes: readonly {
    readonly nodeId: string;
    readonly fromVersion: number;
    readonly toVersion: number;
    readonly promotionReceiptId: string;
    readonly reviewHash: string;
    readonly policyHash: string;
  }[]): string {
    const occurredAt = this.#clock().toISOString();
    const details = {
      schemaVersion: "ti-scale.autonomous-recovery-policy-projection.v1",
      projectorVersion: PROJECTOR_VERSION,
      changedNodes: [...changes].sort((left, right) => left.nodeId.localeCompare(right.nodeId)),
      sourceTextParsed: false,
      targetsIntroduced: false,
      toolsIntroduced: false,
      actionClassesIntroduced: false,
      broadRetryDenialPermitted: false,
    } as const;
    const previous = this.database.prepare(
      "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
    ).get() as { readonly record_hash: string } | undefined;
    const resourceId = sha256(canonicalJson(details));
    const id = this.#idFactory("audit_recovery_policy_projection");
    const body = {
      id, missionId: null, runId: null, journey: null,
      actorType: "system", actorId: SYSTEM_ACTOR,
      action: "memory.autonomous_recovery_policy_projected",
      resourceType: "memory_projection", resourceId,
      reason: "Evidence-verified structured historical failures were projected into bounded recovery constraints.",
      details, previousHash: previous?.record_hash ?? null, occurredAt,
    };
    const recordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(body)}`);
    this.database.prepare(`
      INSERT INTO audit_records (
        id, mission_id, run_id, journey, actor_type, actor_id, action,
        resource_type, resource_id, reason, details_json, previous_hash,
        record_hash, occurred_at
      ) VALUES (?, NULL, NULL, NULL, 'system', ?,
        'memory.autonomous_recovery_policy_projected', 'memory_projection', ?,
        'Evidence-verified structured historical failures were projected into bounded recovery constraints.',
        ?, ?, ?, ?)
    `).run(
      id, SYSTEM_ACTOR, resourceId, canonicalJson(details),
      previous?.record_hash ?? null, recordHash, occurredAt,
    );
    return id;
  }
}

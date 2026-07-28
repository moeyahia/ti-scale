import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import {
  canonicalReusableKnowledgeOutcomeTags,
  type ReusableKnowledgeOutcomeSummary,
  type ReusableKnowledgeOutcomeTag,
} from "../domain/reusable-knowledge-outcomes";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import type { OperationalActor } from "../intelligence-v24/types";
import { findReusableMemorySecretCategories } from "./ReusableMemorySafety";
import { isAttackCentricReusableNodeType, type MemoryNodeType } from "./types";
import { assertIdentifier } from "./validation";

const MAX_EVIDENCE_PER_BINDING = 100;
const ACTOR = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;

interface MemoryBoundaryRow {
  readonly node_type: MemoryNodeType;
  readonly scope: string;
  readonly engagement_id: string | null;
  readonly mission_id: string | null;
  readonly lifecycle_status: string;
  readonly confirmation_state: string;
}

interface AttemptOutcomeRow {
  readonly status: string;
  readonly mission_id: string;
  readonly run_id: string;
}

interface CountRow {
  readonly outcome_tag: ReusableKnowledgeOutcomeTag;
  readonly attack_attempt_count: number;
  readonly evidence_count: number;
}

export class ReusableKnowledgeOutcomeError extends Error {
  constructor(
    readonly code:
      | "invalid_outcome_binding"
      | "reusable_memory_required"
      | "reviewed_knowledge_binding_required"
      | "terminal_attack_outcome_required"
      | "verified_outcome_evidence_required",
    message: string,
  ) {
    super(message);
    this.name = "ReusableKnowledgeOutcomeError";
  }
}

function actor(value: string): string {
  const normalized = value.normalize("NFKC").trim();
  if (!ACTOR.test(normalized)) {
    throw new ReusableKnowledgeOutcomeError(
      "invalid_outcome_binding",
      "A bounded actor identifier is required for reusable outcome classification",
    );
  }
  return normalized;
}

function timestamp(value: string): string {
  if (!Number.isFinite(Date.parse(value))) {
    throw new ReusableKnowledgeOutcomeError(
      "invalid_outcome_binding",
      "Reusable outcome classification time must be an ISO timestamp",
    );
  }
  return new Date(value).toISOString();
}

function reason(value: string): string {
  const normalized = value.normalize("NFKC").trim();
  if (!normalized || Buffer.byteLength(normalized, "utf8") > 1_200) {
    throw new ReusableKnowledgeOutcomeError(
      "invalid_outcome_binding",
      "A concise classification reason is required",
    );
  }
  if (findReusableMemorySecretCategories(normalized).length > 0) {
    throw new ReusableKnowledgeOutcomeError(
      "invalid_outcome_binding",
      "Reusable outcome classification reasons must not contain authentication material",
    );
  }
  return normalized;
}

function linkId(
  memoryNodeId: string,
  attackAttemptId: string,
  evidenceId: string,
  outcomeTag: ReusableKnowledgeOutcomeTag,
): string {
  const digest = createHash("sha256")
    .update(`${memoryNodeId}\0${attackAttemptId}\0${evidenceId}\0${outcomeTag}`, "utf8")
    .digest("hex");
  return `knowledge_outcome_${digest}`;
}

function tagFromAttempt(status: string): ReusableKnowledgeOutcomeTag {
  if (status === "succeeded") return "success";
  if (status === "failed") return "failed";
  throw new ReusableKnowledgeOutcomeError(
    "terminal_attack_outcome_required",
    "Reusable knowledge can be classified only from a canonical succeeded or failed attack attempt",
  );
}

/**
 * Binds reusable knowledge to canonical, evidence-backed terminal outcomes.
 * Callers never supply the tag: it is derived from the immutable AttackAttempt
 * status, preventing UI text or historical prose from becoming authority.
 */
export class ReusableKnowledgeOutcomeService {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  bind(input: {
    readonly memoryNodeId: string;
    readonly attackAttemptId: string;
    readonly evidenceIds: readonly string[];
    readonly actorId: string;
    readonly actorType?: OperationalActor["type"];
    readonly reason: string;
    readonly createdAt?: string;
  }): ReusableKnowledgeOutcomeSummary {
    assertIdentifier(input.memoryNodeId, "reusable memory node ID");
    assertIdentifier(input.attackAttemptId, "attack attempt ID");
    const evidenceIds = [...new Set(input.evidenceIds)];
    if (evidenceIds.length < 1 || evidenceIds.length > MAX_EVIDENCE_PER_BINDING) {
      throw new ReusableKnowledgeOutcomeError(
        "invalid_outcome_binding",
        `Reusable outcome classification requires between 1 and ${MAX_EVIDENCE_PER_BINDING} evidence items`,
      );
    }
    evidenceIds.forEach((id) => assertIdentifier(id, "outcome evidence ID"));
    const actorId = actor(input.actorId);
    const actorType = input.actorType ?? "system";
    if (!["operator", "agent", "worker", "system"].includes(actorType)) {
      throw new ReusableKnowledgeOutcomeError(
        "invalid_outcome_binding",
        "Reusable outcome classification actor type is invalid",
      );
    }
    const classificationReason = reason(input.reason);
    const createdAt = timestamp(input.createdAt ?? this.clock().toISOString());

    const memory = this.database.prepare(`
      SELECT node_type, scope, engagement_id, mission_id,
        lifecycle_status, confirmation_state
      FROM memory_nodes WHERE id = ?
    `).get(input.memoryNodeId) as MemoryBoundaryRow | undefined;
    if (
      !memory
      || !isAttackCentricReusableNodeType(memory.node_type)
      || memory.scope !== "global"
      || memory.engagement_id !== null
      || memory.mission_id !== null
      || memory.lifecycle_status !== "verified"
      || memory.confirmation_state !== "confirmed"
    ) {
      throw new ReusableKnowledgeOutcomeError(
        "reusable_memory_required",
        "Outcome classification requires verified, operator-confirmed knowledge in the global reusable boundary",
      );
    }

    const attempt = this.database.prepare(
      "SELECT status, mission_id, run_id FROM attack_attempts WHERE id = ?",
    ).get(input.attackAttemptId) as AttemptOutcomeRow | undefined;
    if (!attempt) {
      throw new ReusableKnowledgeOutcomeError(
        "terminal_attack_outcome_required",
        "Canonical attack attempt was not found",
      );
    }
    const outcomeTag = tagFromAttempt(attempt.status);

    const reviewedMembership = this.database.prepare(`
      SELECT 1 AS present
      FROM attack_attempt_knowledge_contexts context
      WHERE context.attack_attempt_id = @attackAttemptId
        AND (
          context.procedure_node_id = @memoryNodeId
          OR context.procedure_version_node_id = @memoryNodeId
          OR EXISTS (
            SELECT 1 FROM json_each(context.product_node_ids_json) member
            WHERE member.value = @memoryNodeId
          )
          OR EXISTS (
            SELECT 1 FROM json_each(context.version_node_ids_json) member
            WHERE member.value = @memoryNodeId
          )
          OR EXISTS (
            SELECT 1 FROM json_each(context.stack_node_ids_json) member
            WHERE member.value = @memoryNodeId
          )
          OR EXISTS (
            SELECT 1 FROM json_each(context.prerequisite_node_ids_json) member
            WHERE member.value = @memoryNodeId
          )
          OR EXISTS (
            SELECT 1 FROM json_each(context.observed_state_node_ids_json) member
            WHERE member.value = @memoryNodeId
          )
        )
    `).get({
      attackAttemptId: input.attackAttemptId,
      memoryNodeId: input.memoryNodeId,
    });
    if (!reviewedMembership) {
      throw new ReusableKnowledgeOutcomeError(
        "reviewed_knowledge_binding_required",
        "The reusable node was not part of this attack attempt's immutable reviewed knowledge binding",
      );
    }

    const qualifyingEvidence = this.database.prepare(`
      SELECT proof.id
      FROM attack_attempts attempt
      JOIN attack_attempt_evidence attempt_proof
        ON attempt_proof.attack_attempt_id = attempt.id
       AND attempt_proof.relationship IN ('supports', 'outcome')
      JOIN evidence proof ON proof.id = attempt_proof.evidence_id
      WHERE attempt.id = ?
        AND proof.id = ?
        AND proof.mission_id = attempt.mission_id
        AND proof.run_id = attempt.run_id
        AND proof.verification_state = 'verified'
        AND lower(trim(proof.evidence_type)) <> 'command_output'
        AND EXISTS (
          SELECT 1 FROM evidence_chain_events custody
          WHERE custody.evidence_id = proof.id
            AND custody.event_type = 'verified'
        )
    `);
    for (const evidenceId of evidenceIds) {
      if (!qualifyingEvidence.get(input.attackAttemptId, evidenceId)) {
        throw new ReusableKnowledgeOutcomeError(
          "verified_outcome_evidence_required",
          "Every reusable outcome tag requires verified, custody-backed supporting or outcome evidence linked to the exact attack attempt",
        );
      }
    }

    inImmediateTransaction(this.database, () => {
      const audit = new AuditTrailWriter(this.database);
      const insert = this.database.prepare(`
        INSERT INTO reusable_knowledge_outcome_links (
          id, memory_node_id, attack_attempt_id, evidence_id,
          outcome_tag, actor_id, reason, audit_record_id,
          audit_record_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const evidenceId of evidenceIds) {
        const id = linkId(
          input.memoryNodeId,
          input.attackAttemptId,
          evidenceId,
          outcomeTag,
        );
        const existing = this.database.prepare(
          "SELECT 1 AS present FROM reusable_knowledge_outcome_links WHERE id = ?",
        ).get(id);
        if (existing) continue;
        const auditRecordId = audit.append({
          missionId: attempt.mission_id,
          runId: attempt.run_id,
          actor: { type: actorType, id: actorId },
          action: "reusable_knowledge.outcome_classified",
          resourceType: "reusable_knowledge_outcome_link",
          resourceId: id,
          reason: classificationReason,
          details: {
            memoryNodeId: input.memoryNodeId,
            attackAttemptId: input.attackAttemptId,
            evidenceId,
            outcomeTag,
            derivation: "canonical_terminal_attack_attempt_and_verified_evidence",
          },
          occurredAt: createdAt,
        });
        const auditRecord = this.database.prepare(
          "SELECT record_hash FROM audit_records WHERE id = ?",
        ).get(auditRecordId) as { readonly record_hash: string };
        insert.run(
          id,
          input.memoryNodeId,
          input.attackAttemptId,
          evidenceId,
          outcomeTag,
          actorId,
          classificationReason,
          auditRecordId,
          auditRecord.record_hash,
          createdAt,
        );
      }
    });
    return this.summary(input.memoryNodeId);
  }

  summary(memoryNodeId: string): ReusableKnowledgeOutcomeSummary {
    assertIdentifier(memoryNodeId, "reusable memory node ID");
    const rows = this.database.prepare(`
      SELECT outcome_tag, attack_attempt_count, evidence_count
      FROM reusable_knowledge_outcome_counts
      WHERE memory_node_id = ?
      ORDER BY outcome_tag
    `).all(memoryNodeId) as CountRow[];
    const tags = canonicalReusableKnowledgeOutcomeTags(
      rows.map(({ outcome_tag }) => outcome_tag),
    );
    const row = (tag: ReusableKnowledgeOutcomeTag) => rows.find(
      ({ outcome_tag }) => outcome_tag === tag,
    );
    return {
      memoryNodeId,
      outcomeTags: tags,
      classification: tags.length > 0 ? "classified" : "unclassified",
      successAttemptCount: Number(row("success")?.attack_attempt_count ?? 0),
      failedAttemptCount: Number(row("failed")?.attack_attempt_count ?? 0),
      evidenceCount: rows.reduce(
        (total, item) => total + Number(item.evidence_count),
        0,
      ),
    };
  }
}

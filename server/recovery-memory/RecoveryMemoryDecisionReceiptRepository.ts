import { createHash, randomUUID } from "node:crypto";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import { canonicalJson } from "../orchestration/serialization";
import type {
  CompiledAutonomousRecoveryMemory,
  RecoveryMemoryAppliedEffect,
  RecoveryMemoryDecisionReceipt,
  RecoveryMemoryDecisionSnapshot,
} from "./types";

interface PersistReceiptInput {
  readonly compiled: CompiledAutonomousRecoveryMemory;
  readonly actionId: string;
  readonly stepId: string;
  readonly baseline: RecoveryMemoryDecisionSnapshot;
  readonly resolved: RecoveryMemoryDecisionSnapshot;
  readonly effects: readonly RecoveryMemoryAppliedEffect[];
  readonly appliedNodeIds: readonly string[];
  readonly additionalIgnoredReasons?: Readonly<Record<string, string>>;
  readonly createdAt: string;
}

function hash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

/** Persists the decision and exact Context Pack dispositions atomically. */
export class RecoveryMemoryDecisionReceiptRepository {
  constructor(private readonly database: SqliteDatabase) {}

  persist(input: PersistReceiptInput): RecoveryMemoryDecisionReceipt {
    return inImmediateTransaction(this.database, () => this.persistWithinTransaction(input));
  }

  private persistWithinTransaction(input: PersistReceiptInput): RecoveryMemoryDecisionReceipt {
    const pack = this.database.prepare(`
      SELECT mission_id, run_id, step_id, action_id, journey
      FROM memory_context_packs WHERE id = ?
    `).get(input.compiled.contextPackId) as {
      mission_id: string | null;
      run_id: string | null;
      step_id: string | null;
      action_id: string | null;
      journey: string;
    } | undefined;
    if (
      !pack || pack.journey !== "autonomous" ||
      pack.mission_id !== input.compiled.missionId || pack.run_id !== input.compiled.runId ||
      pack.step_id !== input.stepId || pack.action_id !== input.actionId
    ) throw new TypeError("Recovery memory receipt Context Pack boundary does not match the failed action");

    const itemRows = this.database.prepare(`
      SELECT node_id FROM memory_context_items WHERE context_pack_id = ? ORDER BY rank, node_id
    `).all(input.compiled.contextPackId) as Array<{ node_id: string }>;
    const itemIds = itemRows.map((row) => row.node_id);
    const available = new Set(itemIds);
    const appliedNodeIds = [...new Set(input.appliedNodeIds)].sort();
    if (appliedNodeIds.some((id) => !available.has(id))) {
      throw new TypeError("Applied recovery memory must be a subset of the persisted Context Pack");
    }
    const candidateNodeIds = [...new Set(input.compiled.candidates.map((item) => item.nodeId))].sort();
    if (candidateNodeIds.some((id) => !available.has(id))) {
      throw new TypeError("Compiled recovery memory candidates must be in the persisted Context Pack");
    }
    const applied = new Set(appliedNodeIds);
    const ignoredNodeIds = itemIds.filter((id) => !applied.has(id)).sort();
    const ignoredReasons: Record<string, string> = {};
    for (const nodeId of ignoredNodeIds) {
      ignoredReasons[nodeId] = input.compiled.ignored[nodeId]
        ?? input.additionalIgnoredReasons?.[nodeId]
        ?? "Eligible typed recovery memory did not change the final bounded recovery decision.";
    }
    const effects = [...new Set(input.effects)].sort() as RecoveryMemoryAppliedEffect[];
    const body = {
      schemaVersion: input.compiled.schemaVersion,
      compilerVersion: input.compiled.compilerVersion,
      hook: input.compiled.hook,
      missionId: input.compiled.missionId,
      runId: input.compiled.runId,
      actionId: input.actionId,
      stepId: input.stepId,
      contextPackId: input.compiled.contextPackId,
      failureCategory: input.compiled.failureCategory,
      baseline: input.baseline,
      resolved: input.resolved,
      effects,
      candidateNodeIds,
      appliedNodeIds,
      ignoredNodeIds,
      ignoredReasons,
      createdAt: input.createdAt,
    };
    const receiptHash = hash(body);
    const existing = this.database.prepare(`
      SELECT id FROM recovery_memory_decision_receipts
      WHERE action_id = ? AND context_pack_id = ? AND hook = ?
    `).get(input.actionId, input.compiled.contextPackId, input.compiled.hook) as { id: string } | undefined;
    const id = existing?.id ?? `recovery_memory_receipt_${randomUUID()}`;
    if (!existing) {
      this.database.prepare(`
        INSERT INTO recovery_memory_decision_receipts (
          id, schema_version, compiler_version, hook, mission_id, run_id,
          action_id, step_id, context_pack_id, failure_category,
          baseline_decision_json, resolved_decision_json, effects_json,
          candidate_node_ids_json, applied_node_ids_json, ignored_node_ids_json,
          ignored_reasons_json, receipt_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, input.compiled.schemaVersion, input.compiled.compilerVersion,
        input.compiled.hook, input.compiled.missionId, input.compiled.runId,
        input.actionId, input.stepId, input.compiled.contextPackId,
        input.compiled.failureCategory, canonicalJson(input.baseline),
        canonicalJson(input.resolved), canonicalJson(effects),
        canonicalJson(candidateNodeIds), canonicalJson(appliedNodeIds),
        canonicalJson(ignoredNodeIds), canonicalJson(ignoredReasons),
        receiptHash, input.createdAt,
      );
    }

    const influence = `Recovery memory constrained the decision: ${effects.join(", ")}. It did not add scope, tools, targets, or actions.`;
    for (const row of itemRows) {
      const used = applied.has(row.node_id);
      const result = this.database.prepare(`
        UPDATE memory_context_items SET used = ?, influence_summary = ?, ignored_reason = ?
        WHERE context_pack_id = ? AND node_id = ?
      `).run(
        used ? 1 : 0,
        used ? influence : null,
        used ? null : ignoredReasons[row.node_id],
        input.compiled.contextPackId,
        row.node_id,
      );
      if (result.changes !== 1) throw new Error("Recovery memory Context Pack disposition was not persisted");
    }
    return { id, ...body, receiptHash };
  }
}

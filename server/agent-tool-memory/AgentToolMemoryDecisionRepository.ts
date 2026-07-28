import { createHash, randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import type { JsonValue } from "../intelligence-v24/types";
import { canonicalJson } from "../orchestration/serialization";
import type {
  AgentToolMemoryDecisionReceipt,
  CompiledAgentToolMemoryDecision,
} from "./types";
import { activeConnectedVaultBackedNodeIds } from "../memory";

function hash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function parseObject(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  return parsed as Record<string, unknown>;
}

export class AgentToolMemoryDecisionRepository {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  /** Only nodes synchronized to a currently connected operator Vault qualify. */
  activeVaultBackedNodeIds(contextPackId: string): ReadonlySet<string> {
    return activeConnectedVaultBackedNodeIds(this.database, contextPackId);
  }

  persist(input: {
    readonly compiled: CompiledAgentToolMemoryDecision;
    readonly actorId: string;
  }): AgentToolMemoryDecisionReceipt {
    return inImmediateTransaction(this.database, () => {
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
        !pack || pack.mission_id !== input.compiled.missionId
        || pack.run_id !== input.compiled.runId || pack.step_id !== input.compiled.stepId
        || pack.action_id !== null || pack.journey !== input.compiled.journey
      ) throw new TypeError("Agent/tool memory receipt Context Pack boundary is not canonical");

      const brainAudit = this.database.prepare(`
        SELECT mission_id, run_id, journey, action, resource_id, details_json
        FROM audit_records WHERE id = ?
      `).get(input.compiled.brainAuditRecordId) as {
        mission_id: string | null;
        run_id: string | null;
        journey: string | null;
        action: string;
        resource_id: string | null;
        details_json: string;
      } | undefined;
      const brainAuditDetails = brainAudit ? parseObject(brainAudit.details_json) : {};
      if (
        !brainAudit || brainAudit.mission_id !== input.compiled.missionId
        || brainAudit.run_id !== input.compiled.runId
        || brainAudit.journey !== input.compiled.journey
        || brainAudit.action !== "brain.context_hook.invoked"
        || brainAudit.resource_id !== input.compiled.contextPackId
        || brainAuditDetails.hook !== input.compiled.hook
        || brainAuditDetails.contextPackId !== input.compiled.contextPackId
      ) throw new TypeError("Agent/tool memory receipt Brain audit boundary is not canonical");

      const itemRows = this.database.prepare(`
        SELECT node_id FROM memory_context_items
        WHERE context_pack_id = ? ORDER BY rank, node_id
      `).all(input.compiled.contextPackId) as Array<{ node_id: string }>;
      const itemIds = itemRows.map((row) => row.node_id);
      const available = new Set(itemIds);
      const candidateNodeIds = [...new Set(input.compiled.candidates.map((candidate) => candidate.nodeId))].sort();
      const appliedNodeIds = [...new Set(input.compiled.appliedNodeIds)].sort();
      if (
        candidateNodeIds.some((nodeId) => !available.has(nodeId))
        || appliedNodeIds.some((nodeId) => !candidateNodeIds.includes(nodeId))
      ) throw new TypeError("Agent/tool memory candidates and applied nodes must remain inside the Context Pack");

      const applied = new Set(appliedNodeIds);
      const ignoredNodeIds = itemIds.filter((nodeId) => !applied.has(nodeId)).sort();
      const ignoredReasons: Record<string, string> = {};
      for (const nodeId of ignoredNodeIds) {
        ignoredReasons[nodeId] = input.compiled.ignored[nodeId]
          ?? "A higher-priority typed verdict determined the unchanged represented selection.";
      }
      const id = `audit_agent_tool_memory_${randomUUID()}`;
      const createdAt = this.clock().toISOString();
      const body = {
        id,
        schemaVersion: input.compiled.schemaVersion,
        compilerVersion: input.compiled.compilerVersion,
        hook: input.compiled.hook,
        journey: input.compiled.journey,
        contextPackId: input.compiled.contextPackId,
        brainAuditRecordId: input.compiled.brainAuditRecordId,
        missionId: input.compiled.missionId,
        engagementId: input.compiled.engagementId,
        runId: input.compiled.runId,
        stepId: input.compiled.stepId,
        selection: input.compiled.selection,
        decision: input.compiled.decision,
        candidateNodeIds,
        appliedNodeIds,
        ignoredNodeIds,
        ignoredReasons,
        representationUnchanged: true as const,
        scopeExpanded: false as const,
        toolChanged: false as const,
        actionClassChanged: false as const,
        argumentsChanged: false as const,
        providerExposureCreated: false as const,
        createdAt,
      };
      const receiptHash = hash(body);
      const auditDetails = JSON.parse(canonicalJson({ ...body, receiptHash })) as JsonValue;
      const audit = new AuditTrailWriter(this.database, () => id);
      const decisionAuditRecordId = audit.append({
        missionId: input.compiled.missionId,
        runId: input.compiled.runId,
        actor: { type: "agent", id: input.actorId },
        action: "brain.agent_tool_memory.decision",
        resourceType: "agent_tool_memory_decision",
        resourceId: id,
        reason: input.compiled.decision === "no_applicable_memory"
          ? "No eligible synchronized typed memory applied; the represented selection remained unchanged."
          : input.compiled.decision === "attest_compatible"
            ? "Synchronized typed memory attested the already represented selection without changing it."
            : "Synchronized typed memory vetoed the already represented selection before target contact.",
        details: auditDetails,
        occurredAt: createdAt,
      });
      if (decisionAuditRecordId !== id) {
        throw new Error("Agent/tool memory decision audit ID did not match its receipt ID");
      }

      const influence = input.compiled.decision === "attest_compatible"
        ? "Typed synchronized Vault memory attested the already represented agent/tool selection; no field changed."
        : "Typed synchronized Vault memory vetoed the already represented agent/tool selection before dispatch; no field changed.";
      for (const row of itemRows) {
        const used = applied.has(row.node_id);
        const result = this.database.prepare(`
          UPDATE memory_context_items
          SET used = ?, influence_summary = ?, ignored_reason = ?
          WHERE context_pack_id = ? AND node_id = ?
        `).run(
          used ? 1 : 0,
          used ? influence : null,
          used ? null : ignoredReasons[row.node_id],
          input.compiled.contextPackId,
          row.node_id,
        );
        if (result.changes !== 1) {
          throw new Error("Agent/tool memory Context Pack disposition was not persisted");
        }
      }

      return {
        ...body,
        decisionAuditRecordId,
        receiptHash,
      };
    });
  }
}

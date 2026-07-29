import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import type { ObsidianVaultBridge, VaultBulkExportResult } from "../vault";

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

export interface ApprovedLegacyVaultProjectionInput {
  readonly migrationId: string;
  readonly expectedReconciliationHash: string;
  readonly expectedProjectionHash: string;
  readonly connectionId: string;
  readonly approvedBy: string;
}

export type ApprovedLegacyVaultProjectionPreviewInput = Omit<
  ApprovedLegacyVaultProjectionInput,
  "approvedBy" | "expectedProjectionHash"
>;

export interface ApprovedLegacyVaultProjectionPreview {
  readonly migrationId: string;
  readonly reconciliationHash: string;
  readonly connectionId: string;
  readonly connectionDisplayName: string;
  readonly mappedNodeCount: number;
  readonly eligibleNodeCount: number;
  readonly excludedNodeCount: number;
  readonly projectionHash: string;
  readonly projectedNodeIds: readonly string[];
}

export interface ApprovedLegacyVaultProjectionResult {
  readonly approvalId: string;
  readonly projectionHash: string;
  readonly projectedNodeIds: readonly string[];
  readonly export: VaultBulkExportResult;
}

/**
 * Explicit post-reconciliation gate. This service is deliberately separate
 * from migration so importing historical state can never mutate a live Vault.
 */
export class ApprovedLegacyVaultProjectionService {
  constructor(
    private readonly database: SqliteDatabase,
    private readonly bridge: ObsidianVaultBridge,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  private ensureSchema(): void {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS legacy_vault_projection_approvals (
        id TEXT PRIMARY KEY,
        migration_id TEXT NOT NULL REFERENCES legacy_migration_runs(id) ON DELETE RESTRICT,
        reconciliation_hash TEXT NOT NULL,
        projection_hash TEXT NOT NULL,
        connection_id TEXT NOT NULL REFERENCES vault_connections(id) ON DELETE RESTRICT,
        approved_by TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('approved', 'completed', 'failed')),
        projected_node_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(projected_node_ids_json)),
        result_json TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
        approved_at TEXT NOT NULL,
        completed_at TEXT,
        UNIQUE (migration_id, reconciliation_hash, connection_id)
      ) STRICT;
    `);
    const columns = this.database.prepare("PRAGMA table_info(legacy_vault_projection_approvals)")
      .all() as Array<{ name: string }>;
    if (!columns.some((column) => column.name === "projection_hash")) {
      this.database.exec("ALTER TABLE legacy_vault_projection_approvals ADD COLUMN projection_hash TEXT NOT NULL DEFAULT ''");
    }
  }

  /** Validate and select the exact projection without writing SQLite or Vault state. */
  preview(input: ApprovedLegacyVaultProjectionPreviewInput): ApprovedLegacyVaultProjectionPreview {
    if (!/^[a-f0-9]{64}$/u.test(input.expectedReconciliationHash)) throw new TypeError("Reconciliation hash must be a lowercase SHA-256");
    const reconciliation = this.database.prepare(`
      SELECT r.status, q.report_hash
      FROM legacy_migration_runs r
      JOIN legacy_migration_reconciliation q ON q.migration_id = r.id
      WHERE r.id = ?
    `).get(input.migrationId) as { status: string; report_hash: string } | undefined;
    if (!reconciliation || reconciliation.status !== "completed") {
      throw new Error("Legacy migration must be completed and reconciled before Vault projection");
    }
    if (reconciliation.report_hash !== input.expectedReconciliationHash) {
      throw new Error("Reconciliation hash does not match the completed migration");
    }
    const connection = this.bridge.requireConnection(input.connectionId);
    if (connection.status !== "connected") {
      throw new Error("Vault projection requires an active connected Obsidian vault");
    }
    const mapped = (this.database.prepare(`
      SELECT node_id FROM legacy_engagement_brain_nodes
      WHERE migration_id = ? ORDER BY node_id
    `).all(input.migrationId) as Array<{ node_id: string }>).map((row) => row.node_id);
    const exportable = new Set(this.bridge.previewExportableNodeIds(input.connectionId));
    const nodeIds = mapped.filter((id) => exportable.has(id));
    const projectionHash = sha256(canonical(nodeIds));
    return {
      migrationId: input.migrationId,
      reconciliationHash: reconciliation.report_hash,
      connectionId: connection.id,
      connectionDisplayName: connection.displayName,
      mappedNodeCount: mapped.length,
      eligibleNodeCount: nodeIds.length,
      excludedNodeCount: mapped.length - nodeIds.length,
      projectionHash,
      projectedNodeIds: nodeIds,
    };
  }

  async project(input: ApprovedLegacyVaultProjectionInput): Promise<ApprovedLegacyVaultProjectionResult> {
    if (!input.approvedBy.trim()) throw new TypeError("Vault projection approver is required");
    if (!/^[a-f0-9]{64}$/u.test(input.expectedProjectionHash)) throw new TypeError("Projection hash must be a lowercase SHA-256");
    const preview = this.preview(input);
    if (preview.projectionHash !== input.expectedProjectionHash) {
      throw new Error("Projection hash does not match the current eligible imported-node selection; run a new dry-run preview");
    }
    if (preview.eligibleNodeCount === 0) {
      throw new Error("No imported engagement memory nodes are eligible for this Vault connection and memory policy");
    }
    // A connected record is not enough for a destructive projection boundary:
    // prove the existing Vault can still write/read/rename/delete immediately
    // before recording approval or publishing notes.
    const connection = this.bridge.requireConnection(input.connectionId);
    this.bridge.verifyExistingVaultPath(connection.vaultPath);
    this.ensureSchema();
    const nodeIds = preview.projectedNodeIds;
    const approvalId = `legacy_vault_approval_${sha256(`${input.migrationId}\0${input.expectedReconciliationHash}\0${input.connectionId}`).slice(0, 40)}`;
    const approvedAt = this.clock().toISOString();
    this.database.prepare(`
      INSERT INTO legacy_vault_projection_approvals (
        id, migration_id, reconciliation_hash, projection_hash, connection_id, approved_by,
        status, projected_node_ids_json, approved_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'approved', ?, ?)
      ON CONFLICT(migration_id, reconciliation_hash, connection_id) DO UPDATE SET
        approved_by = excluded.approved_by,
        projection_hash = excluded.projection_hash,
        status = CASE WHEN legacy_vault_projection_approvals.status = 'completed' THEN 'completed' ELSE 'approved' END,
        projected_node_ids_json = excluded.projected_node_ids_json
    `).run(
      approvalId,
      input.migrationId,
      input.expectedReconciliationHash,
      input.expectedProjectionHash,
      input.connectionId,
      input.approvedBy.trim(),
      JSON.stringify(nodeIds),
      approvedAt,
    );
    try {
      const result = await this.bridge.exportNodes(input.connectionId, nodeIds);
      const completedAt = this.clock().toISOString();
      const projectionStatus = result.counts.failed > 0 ? "failed" : "completed";
      this.database.prepare(`
        UPDATE legacy_vault_projection_approvals
        SET status=?, result_json=?, completed_at=? WHERE id=?
      `).run(projectionStatus, canonical(result), completedAt, approvalId);
      if (projectionStatus === "completed") {
        this.appendAudit({
          approvalId,
          migrationId: input.migrationId,
          connectionId: input.connectionId,
          reconciliationHash: input.expectedReconciliationHash,
          projectionHash: input.expectedProjectionHash,
          projectedNodes: nodeIds.length,
          approvedBy: input.approvedBy.trim(),
          occurredAt: completedAt,
        });
      }
      return { approvalId, projectionHash: input.expectedProjectionHash, projectedNodeIds: nodeIds, export: result };
    } catch (error) {
      this.database.prepare(`
        UPDATE legacy_vault_projection_approvals
        SET status='failed', result_json=?, completed_at=? WHERE id=?
      `).run(canonical({ error: error instanceof Error ? error.name : "unknown" }), this.clock().toISOString(), approvalId);
      throw error;
    }
  }

  private appendAudit(input: {
    approvalId: string;
    migrationId: string;
    connectionId: string;
    reconciliationHash: string;
    projectionHash: string;
    projectedNodes: number;
    approvedBy: string;
    occurredAt: string;
  }): void {
    const previous = this.database.prepare("SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1")
      .get() as { record_hash: string } | undefined;
    const details = canonical({
      migrationId: input.migrationId,
      connectionId: input.connectionId,
      reconciliationHash: input.reconciliationHash,
      projectionHash: input.projectionHash,
      projectedNodes: input.projectedNodes,
    });
    const recordHash = sha256(canonical({
      id: input.approvalId,
      actor: input.approvedBy,
      action: "legacy_vault_projection_approved",
      details,
      previousHash: previous?.record_hash ?? null,
      occurredAt: input.occurredAt,
    }));
    this.database.prepare(`
      INSERT OR IGNORE INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id, reason,
        details_json, previous_hash, record_hash, occurred_at
      ) VALUES (?, 'operator', ?, 'legacy_vault_projection_approved', 'data_migration', ?,
        'Exact reconciliation approved for atomic Obsidian projection', ?, ?, ?, ?)
    `).run(
      `audit_${input.approvalId}_${input.projectionHash.slice(0, 16)}`,
      input.approvedBy,
      input.migrationId,
      details,
      previous?.record_hash ?? null,
      recordHash,
      input.occurredAt,
    );
  }
}

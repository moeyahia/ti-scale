import type { SqliteDatabase } from "../db";
import {
  isAttackCentricReusableNodeType,
  type MemoryNode,
} from "./types";

export const AUTONOMOUS_CONFIRMATION_REJECTION =
  "Autonomous influence rejected because this reusable memory is not explicitly confirmed.";

export const AUTONOMOUS_ACTIVE_VAULT_REJECTION =
  "Autonomous influence rejected because this memory is not synchronized at its current version to an active connected and health-verified Obsidian Vault, or has an unresolved Vault conflict.";

export const AUTONOMOUS_LIFECYCLE_REJECTION =
  "Autonomous influence rejected because this memory is stale, disputed, superseded, forgotten, or expired.";

/**
 * Canonical facts whose confirmation state is `not_required` remain eligible.
 * Reusable operator preferences and attack knowledge require explicit
 * confirmation independently of lifecycle verification.
 */
export function autonomousMemoryConfirmationEligible(
  node: Pick<MemoryNode, "nodeType" | "confirmationState">,
): boolean {
  if (node.confirmationState === "pending" || node.confirmationState === "rejected") {
    return false;
  }
  if (
    node.nodeType === "preference"
    || isAttackCentricReusableNodeType(node.nodeType)
  ) {
    return node.confirmationState === "confirmed";
  }
  return node.confirmationState === "confirmed"
    || node.confirmationState === "not_required";
}

/**
 * Returns only Context Pack nodes whose current database version and content
 * hash match a synchronized note in a currently connected Vault. A stale sync
 * row or an unresolved conflict cannot authorize claimed agent influence.
 */
export function activeConnectedVaultBackedNodeIds(
  database: SqliteDatabase,
  contextPackId: string,
): ReadonlySet<string> {
  const rows = database.prepare(`
    SELECT DISTINCT item.node_id
    FROM memory_context_items item
    JOIN memory_nodes node ON node.id = item.node_id
    JOIN vault_sync_state sync
      ON sync.node_id = item.node_id
      AND sync.status = 'synced'
      AND sync.database_version = node.version
      AND sync.vault_content_hash IS NOT NULL
      AND sync.vault_content_hash = sync.database_content_hash
    JOIN vault_connections connection
      ON connection.id = sync.connection_id
      AND connection.status = 'connected'
    WHERE item.context_pack_id = ?
      AND node.lifecycle_status IN ('confirmed', 'verified')
      AND (node.expires_at IS NULL OR node.expires_at > ?)
      AND EXISTS (
        SELECT 1 FROM audit_records health
        WHERE health.resource_type = 'vault_connection'
          AND health.resource_id = connection.id
          AND health.action = 'vault.health.verified'
      )
      AND NOT EXISTS (
        SELECT 1 FROM vault_conflicts conflict
        WHERE conflict.sync_state_id = sync.id AND conflict.status = 'open'
      )
    ORDER BY item.node_id
  `).all(contextPackId, new Date().toISOString()) as Array<{ readonly node_id: string }>;
  return new Set(rows.map(({ node_id }) => node_id));
}

/**
 * Preflight/runtime exact-selection form of the same active Vault invariant.
 * It is intentionally bounded by caller-provided stable node IDs and does not
 * make the Vault the transactional source of truth.
 */
export function activeConnectedVaultBackedMemoryNodeIds(
  database: SqliteDatabase,
  nodeIds: readonly string[],
): ReadonlySet<string> {
  if (nodeIds.length === 0) return new Set();
  const statement = database.prepare(`
    SELECT 1
    FROM memory_nodes node
    JOIN vault_sync_state sync
      ON sync.node_id = node.id
      AND sync.status = 'synced'
      AND sync.database_version = node.version
      AND sync.vault_content_hash IS NOT NULL
      AND sync.vault_content_hash = sync.database_content_hash
    JOIN vault_connections connection
      ON connection.id = sync.connection_id
      AND connection.status = 'connected'
    WHERE node.id = ?
      AND node.lifecycle_status IN ('confirmed', 'verified')
      AND (node.expires_at IS NULL OR node.expires_at > ?)
      AND EXISTS (
        SELECT 1 FROM audit_records health
        WHERE health.resource_type = 'vault_connection'
          AND health.resource_id = connection.id
          AND health.action = 'vault.health.verified'
      )
      AND NOT EXISTS (
        SELECT 1 FROM vault_conflicts conflict
        WHERE conflict.sync_state_id = sync.id AND conflict.status = 'open'
      )
    LIMIT 1
  `);
  const now = new Date().toISOString();
  return new Set([...new Set(nodeIds)].filter((nodeId) =>
    Boolean(statement.get(nodeId, now))));
}

/**
 * Revalidates the two conditions that may change between retrieval and
 * attribution. Returning a reason converts a requested `used` disposition into
 * an explicit, inspectable rejection at the canonical persistence boundary.
 */
export function autonomousInfluenceRejection(
  database: SqliteDatabase,
  contextPackId: string,
  nodeId: string,
): string | undefined {
  const row = database.prepare(`
    SELECT pack.journey, node.node_type, node.confirmation_state,
      node.lifecycle_status, node.expires_at
    FROM memory_context_packs pack
    JOIN memory_context_items item ON item.context_pack_id = pack.id
    JOIN memory_nodes node ON node.id = item.node_id
    WHERE pack.id = ? AND item.node_id = ?
  `).get(contextPackId, nodeId) as {
    readonly journey: "autonomous" | "guided";
    readonly node_type: MemoryNode["nodeType"];
    readonly confirmation_state: MemoryNode["confirmationState"];
    readonly lifecycle_status: MemoryNode["lifecycleStatus"];
    readonly expires_at: string | null;
  } | undefined;
  if (!row || row.journey !== "autonomous") return undefined;
  if (
    !["confirmed", "verified"].includes(row.lifecycle_status)
    || (row.expires_at !== null && row.expires_at <= new Date().toISOString())
  ) {
    return AUTONOMOUS_LIFECYCLE_REJECTION;
  }
  if (!autonomousMemoryConfirmationEligible({
    nodeType: row.node_type,
    confirmationState: row.confirmation_state,
  })) {
    return AUTONOMOUS_CONFIRMATION_REJECTION;
  }
  if (!activeConnectedVaultBackedNodeIds(database, contextPackId).has(nodeId)) {
    return AUTONOMOUS_ACTIVE_VAULT_REJECTION;
  }
  return undefined;
}

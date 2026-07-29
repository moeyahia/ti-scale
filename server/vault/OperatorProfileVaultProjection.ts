import type { SqliteDatabase } from "../db/types";
import type { MemoryNode } from "../memory/types";

/**
 * Explicit marker carried only by the reviewed Attack Knowledge Vault preset.
 * A generic or legacy Vault connection never receives operator-profile notes
 * merely because it has an otherwise broad node-type scope.
 */
export const OPERATOR_PROFILE_VAULT_PROJECTION_POLICY =
  "explicit_operator_preferences_v1" as const;

export const OPERATOR_PROFILE_VAULT_NODE_TYPES = [
  "operator",
  "preference",
  // Application-domain nodes are the controlled `applies_to` destinations
  // produced by OperatorPreferenceImportService. Arbitrary entity nodes are
  // never eligible.
  "entity",
] as const satisfies readonly MemoryNode["nodeType"][];

export const OPERATOR_PROFILE_VAULT_FOLDER = "10 Operator" as const;

export function vaultScopeIncludesOperatorProfile(
  syncScope: Readonly<Record<string, unknown>>,
): boolean {
  const value = syncScope.operatorProfileProjection;
  return Array.isArray(value)
    && value.length === 1
    && value[0] === OPERATOR_PROFILE_VAULT_PROJECTION_POLICY
    && operatorProfileVaultOperatorId(syncScope) !== undefined;
}

export function operatorProfileVaultOperatorId(
  syncScope: Readonly<Record<string, unknown>>,
): string | undefined {
  const value = syncScope.operatorIds;
  if (!Array.isArray(value) || value.length !== 1 || typeof value[0] !== "string") return undefined;
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/u.test(value[0]) ? value[0] : undefined;
}

function commonOperatorProfileBoundary(node: MemoryNode): boolean {
  return node.scope.kind === "global"
    && !node.scope.engagementId
    && !node.scope.missionId
    && node.lifecycleStatus === "confirmed"
    && node.confirmationState === "confirmed"
    && node.authorType === "operator"
    && (node.sensitivity === "internal" || node.sensitivity === "private")
    && !node.expiresAt;
}

/**
 * A profile projection is derived from the canonical explicit-consent tables,
 * not from a title, folder, or caller-provided node type. This keeps mission
 * entities and target identifiers outside the Vault even though the importer
 * uses the generic `entity` type for its finite application-domain vocabulary.
 */
export function isOperatorProfileVaultNodeAllowed(
  database: SqliteDatabase,
  node: MemoryNode,
  operatorId: string,
): boolean {
  if (!commonOperatorProfileBoundary(node) || node.authorId !== operatorId) return false;

  if (node.nodeType === "preference") {
    return Boolean(database.prepare(`
      SELECT 1
      FROM preference_profiles profile
      WHERE profile.source_node_id = ?
        AND profile.scope = 'global'
        AND profile.engagement_id IS NULL
        AND profile.mission_type IS NULL
        AND profile.confirmation_state = 'confirmed'
        AND profile.consent_policy = 'explicit_operator_confirmation'
        AND profile.confidence = 1
        AND profile.expires_at IS NULL
        AND profile.operator_id = ?
      LIMIT 1
    `).get(node.id, operatorId));
  }

  if (node.nodeType === "operator") {
    return Boolean(database.prepare(`
      SELECT 1
      FROM memory_edges_safe edge
      JOIN memory_nodes preference ON preference.id = edge.target_node_id
      JOIN preference_profiles profile ON profile.source_node_id = preference.id
      WHERE edge.source_node_id = ?
        AND edge.edge_type = 'prefers'
        AND edge.lifecycle_status = 'confirmed'
        AND edge.author_type = 'operator'
        AND edge.scope = 'global'
        AND edge.engagement_id IS NULL
        AND edge.mission_id IS NULL
        AND preference.node_type = 'preference'
        AND preference.lifecycle_status = 'confirmed'
        AND preference.confirmation_state = 'confirmed'
        AND preference.author_type = 'operator'
        AND profile.scope = 'global'
        AND profile.engagement_id IS NULL
        AND profile.mission_type IS NULL
        AND profile.confirmation_state = 'confirmed'
        AND profile.consent_policy = 'explicit_operator_confirmation'
        AND profile.expires_at IS NULL
        AND profile.operator_id = ?
      LIMIT 1
    `).get(node.id, operatorId));
  }

  if (node.nodeType === "entity") {
    return Boolean(database.prepare(`
      SELECT 1
      FROM memory_edges_safe edge
      JOIN memory_nodes preference ON preference.id = edge.source_node_id
      JOIN preference_profiles profile ON profile.source_node_id = preference.id
      JOIN memory_sources domain_source ON domain_source.node_id = edge.target_node_id
      WHERE edge.target_node_id = ?
        AND edge.edge_type = 'applies_to'
        AND edge.lifecycle_status = 'confirmed'
        AND edge.author_type = 'operator'
        AND edge.scope = 'global'
        AND edge.engagement_id IS NULL
        AND edge.mission_id IS NULL
        AND preference.node_type = 'preference'
        AND preference.lifecycle_status = 'confirmed'
        AND preference.confirmation_state = 'confirmed'
        AND preference.author_type = 'operator'
        AND profile.scope = 'global'
        AND profile.engagement_id IS NULL
        AND profile.mission_type IS NULL
        AND profile.confirmation_state = 'confirmed'
        AND profile.consent_policy = 'explicit_operator_confirmation'
        AND profile.expires_at IS NULL
        AND domain_source.source_type = 'operator_instruction_manifest'
        AND profile.operator_id = ?
      LIMIT 1
    `).get(node.id, operatorId));
  }

  return false;
}

export function operatorProfileVaultEligibleNodeIds(
  database: SqliteDatabase,
  operatorId: string,
): readonly string[] {
  const rows = database.prepare(`
    SELECT DISTINCT candidate.id
    FROM memory_nodes candidate
    WHERE candidate.node_type IN ('operator', 'preference', 'entity')
      AND candidate.scope = 'global'
      AND candidate.engagement_id IS NULL
      AND candidate.mission_id IS NULL
      AND candidate.lifecycle_status = 'confirmed'
      AND candidate.confirmation_state = 'confirmed'
      AND candidate.author_type = 'operator'
      AND candidate.sensitivity IN ('internal', 'private')
      AND candidate.expires_at IS NULL
      AND candidate.author_id = ?
    ORDER BY candidate.updated_at DESC, candidate.id
  `).all(operatorId) as Array<{ id: string }>;

  // The finite pre-filter avoids a full memory graph scan while this exact
  // predicate remains the authority for every returned node.
  return rows.flatMap(({ id }) => (
    isOperatorProfileVaultNodeIdAllowed(database, id, operatorId) ? [id] : []
  ));
}

export function isOperatorProfileVaultNodeIdAllowed(
  database: SqliteDatabase,
  nodeId: string,
  operatorId: string,
): boolean {
  const row = database.prepare(`SELECT node_type AS nodeType FROM memory_nodes WHERE id = ?`).get(nodeId) as {
    nodeType: MemoryNode["nodeType"];
  } | undefined;
  if (!row) return false;

  if (row.nodeType === "preference") {
    return Boolean(database.prepare(`
      SELECT 1 FROM memory_nodes node
      JOIN preference_profiles profile ON profile.source_node_id = node.id
      WHERE node.id = ? AND node.node_type = 'preference'
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.lifecycle_status = 'confirmed' AND node.confirmation_state = 'confirmed'
        AND node.author_type = 'operator' AND node.sensitivity IN ('internal', 'private')
        AND node.expires_at IS NULL AND node.author_id = ?
        AND profile.scope = 'global' AND profile.engagement_id IS NULL
        AND profile.mission_type IS NULL AND profile.confirmation_state = 'confirmed'
        AND profile.consent_policy = 'explicit_operator_confirmation'
        AND profile.confidence = 1 AND profile.expires_at IS NULL
        AND profile.operator_id = ?
      LIMIT 1
    `).get(nodeId, operatorId, operatorId));
  }
  if (row.nodeType === "operator") {
    return Boolean(database.prepare(`
      SELECT 1 FROM memory_nodes node
      JOIN memory_edges_safe edge ON edge.source_node_id = node.id
      JOIN memory_nodes preference ON preference.id = edge.target_node_id
      JOIN preference_profiles profile ON profile.source_node_id = preference.id
      WHERE node.id = ? AND node.node_type = 'operator'
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.lifecycle_status = 'confirmed' AND node.confirmation_state = 'confirmed'
        AND node.author_type = 'operator' AND node.sensitivity IN ('internal', 'private')
        AND node.expires_at IS NULL AND node.author_id = ?
        AND edge.edge_type = 'prefers' AND edge.lifecycle_status = 'confirmed'
        AND edge.author_type = 'operator' AND edge.scope = 'global'
        AND edge.engagement_id IS NULL AND edge.mission_id IS NULL
        AND preference.node_type = 'preference' AND preference.lifecycle_status = 'confirmed'
        AND preference.confirmation_state = 'confirmed' AND preference.author_type = 'operator'
        AND profile.scope = 'global' AND profile.engagement_id IS NULL
        AND profile.mission_type IS NULL AND profile.confirmation_state = 'confirmed'
        AND profile.consent_policy = 'explicit_operator_confirmation'
        AND profile.expires_at IS NULL AND profile.operator_id = ?
      LIMIT 1
    `).get(nodeId, operatorId, operatorId));
  }
  if (row.nodeType === "entity") {
    return Boolean(database.prepare(`
      SELECT 1 FROM memory_nodes node
      JOIN memory_edges_safe edge ON edge.target_node_id = node.id
      JOIN memory_nodes preference ON preference.id = edge.source_node_id
      JOIN preference_profiles profile ON profile.source_node_id = preference.id
      JOIN memory_sources domain_source ON domain_source.node_id = node.id
      WHERE node.id = ? AND node.node_type = 'entity'
        AND node.scope = 'global' AND node.engagement_id IS NULL AND node.mission_id IS NULL
        AND node.lifecycle_status = 'confirmed' AND node.confirmation_state = 'confirmed'
        AND node.author_type = 'operator' AND node.sensitivity IN ('internal', 'private')
        AND node.expires_at IS NULL AND node.author_id = ?
        AND edge.edge_type = 'applies_to' AND edge.lifecycle_status = 'confirmed'
        AND edge.author_type = 'operator' AND edge.scope = 'global'
        AND edge.engagement_id IS NULL AND edge.mission_id IS NULL
        AND preference.node_type = 'preference' AND preference.lifecycle_status = 'confirmed'
        AND preference.confirmation_state = 'confirmed' AND preference.author_type = 'operator'
        AND profile.scope = 'global' AND profile.engagement_id IS NULL
        AND profile.mission_type IS NULL AND profile.confirmation_state = 'confirmed'
        AND profile.consent_policy = 'explicit_operator_confirmation'
        AND profile.expires_at IS NULL AND profile.operator_id = ?
        AND domain_source.source_type = 'operator_instruction_manifest'
      LIMIT 1
    `).get(nodeId, operatorId, operatorId));
  }
  return false;
}

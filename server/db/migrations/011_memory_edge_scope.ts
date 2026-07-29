import type { Migration } from "../types";

/**
 * Memory edges originally retained only the scope kind. That made a validated
 * mission or engagement scope impossible to reconstruct when neither endpoint
 * carried the same identifier. Persist the complete canonical scope and
 * normalize older rows to the narrowest scope their endpoint provenance can
 * still prove.
 */
export const memoryEdgeScopeMigration: Migration = {
  version: 11,
  name: "memory_edge_scope_identity",
  sql: `
ALTER TABLE memory_edges ADD COLUMN engagement_id TEXT;
ALTER TABLE memory_edges ADD COLUMN mission_id TEXT REFERENCES missions(id) ON DELETE SET NULL;

UPDATE memory_edges
SET engagement_id = COALESCE(
  (SELECT engagement_id FROM memory_nodes WHERE id = memory_edges.source_node_id),
  (SELECT engagement_id FROM memory_nodes WHERE id = memory_edges.target_node_id)
)
WHERE scope IN ('engagement', 'mission');

UPDATE memory_edges
SET mission_id = COALESCE(
  (SELECT mission_id FROM memory_nodes WHERE id = memory_edges.source_node_id),
  (SELECT mission_id FROM memory_nodes WHERE id = memory_edges.target_node_id)
)
WHERE scope = 'mission';

-- Historical rows cannot recover an explicit mission identifier when both
-- endpoints were engagement-scoped. Preserve their proven engagement boundary
-- instead of inventing a mission or leaving an unreadable record.
UPDATE memory_edges
SET scope = 'engagement'
WHERE scope = 'mission' AND mission_id IS NULL AND engagement_id IS NOT NULL;

UPDATE memory_edges
SET scope = 'global'
WHERE scope != 'global' AND engagement_id IS NULL AND mission_id IS NULL;

CREATE INDEX idx_memory_edges_scope_engagement ON memory_edges(scope, engagement_id, updated_at);
CREATE INDEX idx_memory_edges_scope_mission ON memory_edges(scope, mission_id, updated_at);
`,
};

import type { Migration } from "../types";

/** Immutable taxonomy snapshot bound into migration v21's checksum. */
export const V21_REUSABLE_MEMORY_NODE_TYPES = [
  "technology_product",
  "exact_version_fingerprint",
  "version_range_fingerprint",
  "operating_system",
  "kernel",
  "framework",
  "runtime",
  "database",
  "firewall",
  "waf",
  "proxy",
  "security_control",
  "topology_pattern",
  "topology_role",
  "cve",
  "advisory",
  "cwe",
  "misconfiguration",
  "attack_vector",
  "prerequisite",
  "attribute",
  "discovery_pattern",
  "fingerprint_pattern",
  "script_artifact",
  "tool_artifact",
  "outcome",
  "failure_mode",
  "alternative",
  "evidence_pattern",
  "validation_pattern",
  "detection",
  "remediation",
  "strategy",
  "research",
  "procedure_version",
  "operational_hazard",
  "target_state_transition",
  "recovery_pattern",
  "health_check",
  "attack_tactic",
  "attack_technique",
  "attack_procedure",
  "attack_lesson",
] as const;

const reusableTypesSql = V21_REUSABLE_MEMORY_NODE_TYPES
  .map((nodeType) => `'${nodeType.replaceAll("'", "''")}'`)
  .join(", ");

/**
 * Quarantine historical relationships that cross the reusable/private memory
 * boundary. The original row remains available for reconciliation and audit,
 * but every graph/retrieval/Vault read uses memory_edges_safe.
 */
export const reusableMemoryEdgePrivacyBoundaryMigration: Migration = {
  version: 21,
  name: "reusable_memory_edge_privacy_boundary",
  sql: String.raw`
CREATE TABLE memory_edge_privacy_quarantine (
  edge_id TEXT PRIMARY KEY REFERENCES memory_edges(id) ON DELETE CASCADE,
  reason_code TEXT NOT NULL CHECK (reason_code = 'reusable_private_boundary'),
  source_node_type TEXT NOT NULL,
  target_node_type TEXT NOT NULL,
  detected_at TEXT NOT NULL
) STRICT;

INSERT INTO memory_edge_privacy_quarantine (
  edge_id, reason_code, source_node_type, target_node_type, detected_at
)
SELECT edge.id, 'reusable_private_boundary', source.node_type, target.node_type,
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM memory_edges edge
JOIN memory_nodes source ON source.id = edge.source_node_id
JOIN memory_nodes target ON target.id = edge.target_node_id
WHERE (source.node_type IN (${reusableTypesSql}))
   <> (target.node_type IN (${reusableTypesSql}));

CREATE INDEX idx_memory_edge_privacy_quarantine_reason
  ON memory_edge_privacy_quarantine(reason_code, detected_at DESC);

CREATE TRIGGER memory_edges_quarantine_reusable_private_insert
AFTER INSERT ON memory_edges
WHEN (
  (SELECT node_type IN (${reusableTypesSql}) FROM memory_nodes WHERE id = new.source_node_id)
  <>
  (SELECT node_type IN (${reusableTypesSql}) FROM memory_nodes WHERE id = new.target_node_id)
)
BEGIN
  INSERT OR IGNORE INTO memory_edge_privacy_quarantine (
    edge_id, reason_code, source_node_type, target_node_type, detected_at
  ) VALUES (
    new.id,
    'reusable_private_boundary',
    (SELECT node_type FROM memory_nodes WHERE id = new.source_node_id),
    (SELECT node_type FROM memory_nodes WHERE id = new.target_node_id),
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  );
END;

CREATE VIEW memory_edges_safe AS
SELECT edge.*
FROM memory_edges edge
WHERE NOT EXISTS (
  SELECT 1 FROM memory_edge_privacy_quarantine quarantine
  WHERE quarantine.edge_id = edge.id
);
`,
};

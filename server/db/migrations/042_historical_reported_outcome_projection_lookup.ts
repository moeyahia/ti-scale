import type { Migration } from "../types";

/**
 * Make reported historical outcome projection start from the requested memory
 * node instead of rescanning every immutable source claim for every Vault
 * note. This is an additive lookup index only; it does not rewrite canonical
 * memory, claims, or Vault state and therefore requires no safety snapshot.
 */
export const historicalReportedOutcomeProjectionLookupMigration: Migration = {
  version: 42,
  name: "historical_reported_outcome_projection_lookup",
  sql: String.raw`
CREATE INDEX idx_memory_candidates_proposed_node_id
  ON memory_candidates(proposed_node_id, id)
  WHERE proposed_node_id IS NOT NULL;
`,
};

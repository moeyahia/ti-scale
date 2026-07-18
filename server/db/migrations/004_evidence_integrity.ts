import type { Migration } from "../types";

export const evidenceIntegrityMigration: Migration = {
  version: 4,
  name: "evidence_chain_integrity",
  sql: String.raw`
CREATE UNIQUE INDEX idx_evidence_guided_manual_action_unique
ON evidence(action_id)
WHERE evidence_type = 'guided_manual_result';

CREATE TRIGGER evidence_chain_events_no_update
BEFORE UPDATE ON evidence_chain_events BEGIN
  SELECT RAISE(ABORT, 'evidence chain events are immutable');
END;

CREATE TRIGGER evidence_chain_events_no_delete
BEFORE DELETE ON evidence_chain_events BEGIN
  SELECT RAISE(ABORT, 'evidence chain events are immutable');
END;
`,
};

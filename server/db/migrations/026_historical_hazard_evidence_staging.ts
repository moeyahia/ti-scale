import type { Migration } from "../types";

/**
 * Durable, resumable staging for a deliberately selected subset of private
 * historical operational-hazard records. Source paths stay in the protected
 * backup manifest; the canonical database retains only opaque source keys and
 * immutable hashes. Evidence candidates are never verified by this workflow.
 */
export const historicalHazardEvidenceStagingMigration: Migration = {
  version: 26,
  name: "historical_hazard_evidence_staging",
  sql: String.raw`
CREATE TABLE historical_hazard_import_jobs (
  id TEXT PRIMARY KEY,
  request_fingerprint TEXT NOT NULL UNIQUE CHECK (length(request_fingerprint) = 64),
  preview_hash TEXT NOT NULL UNIQUE CHECK (length(preview_hash) = 64),
  source_manifest_hash TEXT NOT NULL CHECK (length(source_manifest_hash) = 64),
  private_label_hashes_json TEXT NOT NULL CHECK (
    json_valid(private_label_hashes_json)
    AND json_type(private_label_hashes_json) = 'array'
    AND json_array_length(private_label_hashes_json) BETWEEN 1 AND 32
  ),
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT REFERENCES runs(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN (
    'staging', 'interrupted', 'candidates_staged', 'bundle_staged'
  )),
  source_count INTEGER NOT NULL CHECK (source_count BETWEEN 1 AND 64),
  source_bytes INTEGER NOT NULL CHECK (source_bytes >= 0),
  checkpoint_ordinal INTEGER NOT NULL DEFAULT 0 CHECK (
    checkpoint_ordinal >= 0 AND checkpoint_ordinal <= source_count
  ),
  protected_manifest_ref TEXT NOT NULL,
  protected_manifest_hash TEXT NOT NULL CHECK (length(protected_manifest_hash) = 64),
  approved_by TEXT NOT NULL CHECK (length(trim(approved_by)) > 0),
  approved_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  CHECK ((status IN ('candidates_staged', 'bundle_staged')) = (completed_at IS NOT NULL))
) STRICT;

CREATE TABLE historical_hazard_import_sources (
  job_id TEXT NOT NULL REFERENCES historical_hazard_import_jobs(id) ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  selection_key TEXT NOT NULL CHECK (length(selection_key) = 64),
  source_hash TEXT NOT NULL CHECK (length(source_hash) = 64),
  byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
  modified_at TEXT NOT NULL,
  evidence_type TEXT NOT NULL CHECK (length(trim(evidence_type)) > 0),
  protected_backup_ref TEXT NOT NULL,
  artifact_id TEXT UNIQUE REFERENCES artifacts(id) ON DELETE RESTRICT,
  candidate_id TEXT UNIQUE REFERENCES evidence_candidates(id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'candidate_staged')),
  staged_at TEXT,
  PRIMARY KEY (job_id, ordinal),
  UNIQUE (job_id, selection_key),
  CHECK (
    (status = 'pending' AND artifact_id IS NULL AND candidate_id IS NULL AND staged_at IS NULL)
    OR
    (status = 'candidate_staged' AND artifact_id IS NOT NULL AND candidate_id IS NOT NULL AND staged_at IS NOT NULL)
  )
) WITHOUT ROWID, STRICT;

CREATE TABLE historical_hazard_import_bundle_links (
  job_id TEXT PRIMARY KEY REFERENCES historical_hazard_import_jobs(id) ON DELETE RESTRICT,
  bundle_id TEXT NOT NULL REFERENCES attack_knowledge_bundles(id) ON DELETE RESTRICT,
  provenance_receipt_id TEXT NOT NULL,
  source_hash TEXT NOT NULL CHECK (length(source_hash) = 64),
  binding_preview_hash TEXT NOT NULL CHECK (length(binding_preview_hash) = 64),
  evidence_ids_json TEXT NOT NULL CHECK (
    json_valid(evidence_ids_json) AND json_type(evidence_ids_json) = 'array'
  ),
  actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
  bound_at TEXT NOT NULL,
  FOREIGN KEY (bundle_id, provenance_receipt_id)
    REFERENCES attack_knowledge_bundle_receipts(bundle_id, receipt_id) ON DELETE RESTRICT,
  UNIQUE (bundle_id, binding_preview_hash)
) STRICT;

CREATE INDEX idx_historical_hazard_jobs_status_updated
  ON historical_hazard_import_jobs(status, updated_at DESC);
CREATE INDEX idx_historical_hazard_sources_status
  ON historical_hazard_import_sources(job_id, status, ordinal);
CREATE INDEX idx_historical_hazard_sources_hash
  ON historical_hazard_import_sources(source_hash, job_id);

CREATE TRIGGER historical_hazard_import_job_scope_insert
BEFORE INSERT ON historical_hazard_import_jobs
WHEN NEW.run_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM runs WHERE id = NEW.run_id AND mission_id = NEW.mission_id
)
BEGIN
  SELECT RAISE(ABORT, 'historical hazard import run is outside its mission');
END;

CREATE TRIGGER historical_hazard_import_jobs_no_delete
BEFORE DELETE ON historical_hazard_import_jobs BEGIN
  SELECT RAISE(ABORT, 'historical hazard import jobs are retained for reconciliation');
END;

CREATE TRIGGER historical_hazard_import_sources_no_delete
BEFORE DELETE ON historical_hazard_import_sources BEGIN
  SELECT RAISE(ABORT, 'historical hazard import sources are retained for reconciliation');
END;

CREATE TRIGGER historical_hazard_import_source_transition
BEFORE UPDATE ON historical_hazard_import_sources
WHEN OLD.job_id IS NOT NEW.job_id
  OR OLD.ordinal IS NOT NEW.ordinal
  OR OLD.selection_key IS NOT NEW.selection_key
  OR OLD.source_hash IS NOT NEW.source_hash
  OR OLD.byte_size IS NOT NEW.byte_size
  OR OLD.modified_at IS NOT NEW.modified_at
  OR OLD.evidence_type IS NOT NEW.evidence_type
  OR OLD.protected_backup_ref IS NOT NEW.protected_backup_ref
  OR OLD.status = 'candidate_staged'
  OR NEW.status <> 'candidate_staged'
BEGIN
  SELECT RAISE(ABORT, 'historical hazard source transition is immutable or invalid');
END;

CREATE TRIGGER historical_hazard_bundle_links_no_update
BEFORE UPDATE ON historical_hazard_import_bundle_links BEGIN
  SELECT RAISE(ABORT, 'historical hazard bundle links are immutable');
END;

CREATE TRIGGER historical_hazard_bundle_links_no_delete
BEFORE DELETE ON historical_hazard_import_bundle_links BEGIN
  SELECT RAISE(ABORT, 'historical hazard bundle links are immutable');
END;

CREATE TRIGGER historical_hazard_bundle_link_integrity
BEFORE INSERT ON historical_hazard_import_bundle_links
WHEN 'candidates_staged' IS NOT (
    SELECT status FROM historical_hazard_import_jobs WHERE id = NEW.job_id
  )
  OR NEW.source_hash IS NOT (
    SELECT source_hash FROM attack_knowledge_provenance_receipts
    WHERE id = NEW.provenance_receipt_id
  )
  OR json_array_length(NEW.evidence_ids_json) < 1
  OR EXISTS (
    SELECT 1 FROM json_each(NEW.evidence_ids_json) selected
    WHERE NOT EXISTS (
      SELECT 1
      FROM historical_hazard_import_sources imported
      JOIN evidence_candidates candidate ON candidate.id = imported.candidate_id
      JOIN evidence canonical ON canonical.id = candidate.promoted_evidence_id
      WHERE imported.job_id = NEW.job_id
        AND canonical.id = selected.value
        AND candidate.state = 'promoted'
        AND canonical.verification_state = 'verified'
        AND lower(trim(canonical.evidence_type)) <> 'command_output'
        AND EXISTS (
          SELECT 1 FROM evidence_chain_events custody
          WHERE custody.evidence_id = canonical.id AND custody.event_type = 'verified'
        )
    )
  )
  OR EXISTS (
    SELECT value, COUNT(*) AS occurrences
    FROM json_each(NEW.evidence_ids_json)
    GROUP BY value HAVING occurrences > 1
  )
BEGIN
  SELECT RAISE(ABORT, 'historical hazard bundle link requires exact independently verified evidence');
END;
`,
};

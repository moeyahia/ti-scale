import type { Migration } from "../types";

export const followUpContextMigration: Migration = {
  version: 8,
  name: "follow_up_run_context_selections",
  sql: String.raw`
CREATE TABLE run_context_selections (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL REFERENCES memory_nodes(id) ON DELETE RESTRICT,
  lesson_id TEXT NOT NULL REFERENCES lessons(id) ON DELETE RESTRICT,
  selection_type TEXT NOT NULL CHECK (selection_type IN ('verified_lesson')),
  selected_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  selected_at TEXT NOT NULL,
  UNIQUE (run_id, node_id),
  UNIQUE (run_id, lesson_id)
) STRICT;

CREATE INDEX idx_run_context_selections_run_type
  ON run_context_selections(run_id, selection_type, selected_at);

CREATE TRIGGER run_context_selections_immutable_update
BEFORE UPDATE ON run_context_selections
BEGIN
  SELECT RAISE(ABORT, 'run context selections are immutable');
END;

CREATE TRIGGER run_context_selections_immutable_delete
BEFORE DELETE ON run_context_selections
WHEN EXISTS (SELECT 1 FROM runs WHERE id = OLD.run_id)
BEGIN
  SELECT RAISE(ABORT, 'run context selections are immutable');
END;

-- Bind every contract-backed run to the exact contract revision it launched
-- under. Reading the mutable contract row at action time is insufficient:
-- changing its version/hash after planning would otherwise redefine the run's
-- authority in place.
ALTER TABLE runs ADD COLUMN contract_version_bound INTEGER;
ALTER TABLE runs ADD COLUMN contract_hash_bound TEXT;

UPDATE runs
SET contract_version_bound = (
      SELECT version FROM mission_contracts WHERE id = runs.contract_id
    ),
    contract_hash_bound = (
      SELECT contract_hash FROM mission_contracts WHERE id = runs.contract_id
    )
WHERE contract_id IS NOT NULL;

CREATE TRIGGER runs_bind_contract_after_insert
AFTER INSERT ON runs
WHEN NEW.contract_id IS NOT NULL
  AND (NEW.contract_version_bound IS NULL OR NEW.contract_hash_bound IS NULL)
BEGIN
  UPDATE runs
  SET contract_version_bound = (
        SELECT version FROM mission_contracts WHERE id = NEW.contract_id
      ),
      contract_hash_bound = (
        SELECT contract_hash FROM mission_contracts WHERE id = NEW.contract_id
      )
  WHERE id = NEW.id;
END;

CREATE TRIGGER runs_contract_binding_immutable
BEFORE UPDATE OF contract_id, contract_version_bound, contract_hash_bound ON runs
WHEN OLD.contract_id IS NOT NEW.contract_id
  OR (OLD.contract_version_bound IS NOT NULL
    AND OLD.contract_version_bound IS NOT NEW.contract_version_bound)
  OR (OLD.contract_hash_bound IS NOT NULL
    AND OLD.contract_hash_bound IS NOT NEW.contract_hash_bound)
BEGIN
  SELECT RAISE(ABORT, 'run contract binding is immutable');
END;

CREATE TABLE mission_contract_snapshots (
  contract_id TEXT PRIMARY KEY REFERENCES mission_contracts(id) ON DELETE CASCADE,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
  source_contract_id TEXT REFERENCES mission_contracts(id) ON DELETE RESTRICT,
  request_json TEXT NOT NULL CHECK (json_valid(request_json)),
  amendment_reason TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_contract_snapshots_mission_source
  ON mission_contract_snapshots(mission_id, source_contract_id, created_at);

CREATE TRIGGER mission_contract_snapshots_immutable_update
BEFORE UPDATE ON mission_contract_snapshots
BEGIN
  SELECT RAISE(ABORT, 'mission contract snapshots are immutable');
END;

CREATE TRIGGER mission_contract_snapshots_immutable_delete
BEFORE DELETE ON mission_contract_snapshots
BEGIN
  SELECT RAISE(ABORT, 'mission contract snapshots are immutable');
END;

CREATE TABLE run_branches (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  source_run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE RESTRICT,
  branch_mode TEXT NOT NULL CHECK (branch_mode IN ('unchanged_contract', 'contract_amendment')),
  source_contract_id TEXT NOT NULL REFERENCES mission_contracts(id) ON DELETE RESTRICT,
  target_contract_id TEXT NOT NULL REFERENCES mission_contracts(id) ON DELETE RESTRICT,
  reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX idx_run_branches_source_created
  ON run_branches(source_run_id, created_at);

CREATE INDEX idx_run_branches_mission_created
  ON run_branches(mission_id, created_at);

CREATE TRIGGER run_branches_immutable_update
BEFORE UPDATE ON run_branches
BEGIN
  SELECT RAISE(ABORT, 'run branch records are immutable');
END;

CREATE TRIGGER run_branches_immutable_delete
BEFORE DELETE ON run_branches
BEGIN
  SELECT RAISE(ABORT, 'run branch records are immutable');
END;

-- Durable, owner-fenced runtime continuations close the commit-to-next-work
-- gap. A continuation is written in the same transaction as the state change
-- that requires it, then may be reclaimed after a worker/process lease expires.
CREATE TABLE runtime_continuations (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN (
    'plan_ready_to_dispatch',
    'autonomous_retry_to_dispatch',
    'guided_approval_to_dispatch',
    'action_result_to_advance',
    'guided_failure_to_recover',
    'evaluation_pending',
    'cancellation_finalize_pending',
    'resume_recovery_pending'
  )),
  source_id TEXT NOT NULL CHECK (length(trim(source_id)) > 0),
  payload_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload_json)),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'processing', 'completed', 'cancelled')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  available_at TEXT NOT NULL,
  lease_owner TEXT,
  lease_expires_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  UNIQUE (run_id, kind, source_id),
  CHECK (
    (status = 'processing' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR
    (status <> 'processing' AND lease_owner IS NULL AND lease_expires_at IS NULL)
  ),
  CHECK ((status = 'completed' AND completed_at IS NOT NULL) OR status <> 'completed')
) STRICT;

CREATE INDEX idx_runtime_continuations_ready
  ON runtime_continuations(status, available_at, lease_expires_at, created_at);

CREATE INDEX idx_runtime_continuations_run_status
  ON runtime_continuations(run_id, status, created_at);

-- Bulk Obsidian projection and crash-resume resolve durable state by
-- connection and canonical node. This keeps a 50,000-note export O(n).
CREATE INDEX idx_vault_sync_connection_node
  ON vault_sync_state(connection_id, node_id)
  WHERE node_id IS NOT NULL;

-- Notification delivery is shared, but read state belongs to the authenticated
-- viewer. The legacy notifications.read_at column intentionally remains as an
-- expand-phase compatibility field; canonical reads and writes use only these
-- actor-scoped receipts. Ambiguous legacy global reads are not inherited by an
-- arbitrary actor.
CREATE TABLE notification_read_receipts (
  notification_id TEXT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
  actor_type TEXT NOT NULL CHECK (actor_type IN (
    'operator', 'reviewer', 'admin', 'agent', 'system'
  )),
  actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) > 0),
  read_at TEXT NOT NULL,
  PRIMARY KEY (notification_id, actor_type, actor_id)
) STRICT;

CREATE INDEX idx_notification_read_receipts_actor_read
  ON notification_read_receipts(actor_type, actor_id, read_at, notification_id);

-- Notification reads begin with the small, cursor-ordered projection and
-- resolve the source event by primary key. Without these indexes an inbox
-- request can scan and sort the complete append-only event history.
CREATE INDEX idx_notifications_created_time
  ON notifications(created_at DESC, id DESC);

CREATE INDEX idx_notifications_read_time
  ON notifications(read_at, created_at DESC, id DESC);
`,
};

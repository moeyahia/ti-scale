import type { Migration } from "../types";

/**
 * Durable, fenced read/write exclusion for the canonical database.
 *
 * Shared writer leases let bounded maintenance see every registered writer.
 * The maintenance lease is exclusive and prevents a covered writer from
 * starting after the release gate has taken its final snapshot. Expired rows
 * remain as audit history; monotonically increasing fencing tokens prevent a
 * restarted or delayed process from reusing stale authority.
 */
export const canonicalDatabaseLeasesMigration: Migration = {
  version: 35,
  name: "canonical_database_leases",
  requiresVerifiedBackup: true,
  sql: String.raw`
CREATE TABLE canonical_database_lease_fence (
  resource_id TEXT PRIMARY KEY CHECK (resource_id = 'canonical_database'),
  next_fencing_token INTEGER NOT NULL CHECK (next_fencing_token > 0)
) WITHOUT ROWID, STRICT;

INSERT INTO canonical_database_lease_fence (resource_id, next_fencing_token)
VALUES ('canonical_database', 1);

CREATE TABLE canonical_database_leases (
  id TEXT PRIMARY KEY,
  resource_id TEXT NOT NULL CHECK (resource_id = 'canonical_database'),
  mode TEXT NOT NULL CHECK (mode IN ('writer', 'maintenance')),
  owner_id TEXT NOT NULL CHECK (length(trim(owner_id)) BETWEEN 1 AND 256),
  operation TEXT NOT NULL CHECK (length(trim(operation)) BETWEEN 1 AND 256),
  fencing_token INTEGER NOT NULL UNIQUE CHECK (fencing_token > 0),
  acquired_at TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  released_at TEXT,
  release_reason TEXT CHECK (
    release_reason IS NULL OR length(trim(release_reason)) BETWEEN 1 AND 256
  ),
  CHECK (julianday(expires_at) > julianday(acquired_at)),
  CHECK (
    (released_at IS NULL AND release_reason IS NULL)
    OR (released_at IS NOT NULL AND release_reason IS NOT NULL)
  )
) STRICT;

CREATE UNIQUE INDEX idx_canonical_database_active_maintenance
  ON canonical_database_leases(resource_id)
  WHERE mode = 'maintenance' AND released_at IS NULL;
CREATE INDEX idx_canonical_database_active_writers
  ON canonical_database_leases(mode, released_at, expires_at, id);
CREATE INDEX idx_canonical_database_lease_owner
  ON canonical_database_leases(owner_id, operation, acquired_at);

CREATE TRIGGER canonical_database_lease_identity_immutable
BEFORE UPDATE OF
  resource_id, mode, owner_id, operation, fencing_token, acquired_at
ON canonical_database_leases
WHEN OLD.resource_id IS NOT NEW.resource_id
  OR OLD.mode IS NOT NEW.mode
  OR OLD.owner_id IS NOT NEW.owner_id
  OR OLD.operation IS NOT NEW.operation
  OR OLD.fencing_token IS NOT NEW.fencing_token
  OR OLD.acquired_at IS NOT NEW.acquired_at
BEGIN
  SELECT RAISE(ABORT, 'canonical database lease identity is immutable');
END;

CREATE TRIGGER canonical_database_lease_no_reopen
BEFORE UPDATE ON canonical_database_leases
WHEN OLD.released_at IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'released canonical database lease is immutable');
END;

CREATE TRIGGER canonical_database_lease_expiry_monotonic
BEFORE UPDATE OF expires_at ON canonical_database_leases
WHEN julianday(NEW.expires_at) < julianday(OLD.expires_at)
BEGIN
  SELECT RAISE(ABORT, 'canonical database lease expiry cannot move backward');
END;

CREATE TRIGGER canonical_database_lease_no_delete
BEFORE DELETE ON canonical_database_leases BEGIN
  SELECT RAISE(ABORT, 'canonical database lease history is retained');
END;
`,
};

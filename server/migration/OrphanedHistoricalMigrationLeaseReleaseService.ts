import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { canonicalJson, sha256 } from "../intelligence-v24/validation";
import { CanonicalDatabaseLeaseService } from "../maintenance";
import { detectActiveLegacyMigrationProcessIds } from "./FailedLegacyMigrationReconciliationService";

const ELIGIBLE_OWNER_ID = "operator:historical-migration";
const ELIGIBLE_OPERATION = "historical-engagement-import";
const RELEASE_REASON = "orphaned_historical_import_recovery";
const AUDIT_ACTION = "canonical_database_lease.orphaned_historical_import_released";

interface LeaseRow {
  readonly id: string;
  readonly resource_id: string;
  readonly mode: string;
  readonly owner_id: string;
  readonly operation: string;
  readonly fencing_token: number;
  readonly acquired_at: string;
  readonly heartbeat_at: string;
  readonly expires_at: string;
  readonly released_at: string | null;
  readonly release_reason: string | null;
}

interface MigrationRow {
  readonly id: string;
  readonly status: string;
  readonly database_path: string;
  readonly error_summary: string | null;
  readonly started_at: string;
  readonly completed_at: string | null;
  readonly pending_sources: number;
  readonly importing_sources: number;
}

export interface OrphanedHistoricalMigrationLeaseReleasePreview {
  readonly lease: {
    readonly id: string;
    readonly fencingToken: number;
    readonly mode: "writer";
    readonly ownerId: typeof ELIGIBLE_OWNER_ID;
    readonly operation: typeof ELIGIBLE_OPERATION;
    readonly acquiredAt: string;
    readonly heartbeatAt: string;
    readonly expiresAt: string;
  };
  readonly databasePathHash: string;
  readonly matchingImporterProcessIds: readonly number[];
  readonly associatedMigrations: readonly {
    readonly id: string;
    readonly status: "failed" | "completed";
    readonly startedAt: string;
    readonly completedAt: string;
    readonly pendingSources: 0;
    readonly importingSources: 0;
  }[];
  readonly releaseReason: typeof RELEASE_REASON;
  readonly previewHash: string;
}

export interface ReleaseOrphanedHistoricalMigrationLeaseInput {
  readonly leaseId: string;
  readonly fencingToken: number;
  readonly expectedPreviewHash: string;
  readonly actorId: string;
  readonly reason: string;
  readonly acknowledged: boolean;
}

export interface OrphanedHistoricalMigrationLeaseReleaseResult {
  readonly status: "released";
  readonly leaseId: string;
  readonly fencingToken: number;
  readonly releasedAt: string;
  readonly releaseReason: typeof RELEASE_REASON;
  readonly associatedMigrationIds: readonly string[];
  readonly previewHash: string;
  readonly auditRecordId: string;
  readonly auditRecordHash: string;
}

export interface OrphanedHistoricalMigrationLeaseReleaseServiceOptions {
  readonly clock?: () => Date;
  readonly createId?: () => string;
  readonly databasePath?: string;
  readonly activeMigrationProcessIds?: () => readonly number[];
}

function boundedText(value: string, label: string, maximum: number): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError(`${label} must contain 1 to ${maximum} printable characters`);
  }
  return normalized;
}

function identifier(value: string, label: string): string {
  const normalized = boundedText(value, label, 256);
  if (!/^[a-z0-9][a-z0-9_.:-]*$/iu.test(normalized)) {
    throw new TypeError(`${label} contains unsupported characters`);
  }
  return normalized;
}

function fencingToken(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError("Fencing token must be a positive safe integer");
  }
  return value;
}

function timestamp(value: string | null, label: string): string {
  if (!value || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${label} is missing a valid timestamp`);
  }
  return new Date(value).toISOString();
}

function normalizedDatabasePath(value: string): string {
  return value === ":memory:" || value.startsWith("file::memory:") ? value : resolve(value);
}

/**
 * Releases only the exact, known writer identity used by the configured
 * historical engagement importer. This is an emergency recovery boundary for
 * an importer process that has exited after making its migration metadata
 * terminal but before its finally block released the durable writer lease.
 */
export class OrphanedHistoricalMigrationLeaseReleaseService {
  readonly #clock: () => Date;
  readonly #createId: () => string;
  readonly #databasePath: string;
  readonly #activeMigrationProcessIds: () => readonly number[];

  constructor(
    readonly database: SqliteDatabase,
    options: OrphanedHistoricalMigrationLeaseReleaseServiceOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? (() => `audit_orphaned_import_lease_${randomUUID()}`);
    this.#databasePath = normalizedDatabasePath(options.databasePath ?? database.name);
    this.#activeMigrationProcessIds = options.activeMigrationProcessIds
      ?? (() => detectActiveLegacyMigrationProcessIds("/proc", process.pid, this.#databasePath));
    if (!CanonicalDatabaseLeaseService.schemaAvailable(database)) {
      throw new Error("Orphaned historical-migration lease recovery requires canonical database migration 35");
    }
  }

  preview(input: {
    readonly leaseId: string;
    readonly fencingToken: number;
  }): OrphanedHistoricalMigrationLeaseReleasePreview {
    this.#assertNoImporterProcess();
    return this.#buildPreview(input, this.#clock().toISOString());
  }

  release(
    input: ReleaseOrphanedHistoricalMigrationLeaseInput,
  ): OrphanedHistoricalMigrationLeaseReleaseResult {
    if (!input.acknowledged) {
      throw new Error("Orphaned historical-migration lease release requires explicit acknowledgement");
    }
    const actorId = identifier(input.actorId, "Actor ID");
    const reason = boundedText(input.reason, "Lease-release reason", 1_000);
    if (!/^[a-f0-9]{64}$/u.test(input.expectedPreviewHash)) {
      throw new TypeError("Expected preview hash must be a lowercase SHA-256 digest");
    }
    this.#assertNoImporterProcess();
    const releasedAt = this.#clock().toISOString();

    return inImmediateTransaction(this.database, () => {
      const preview = this.#buildPreview(input, releasedAt);
      if (preview.previewHash !== input.expectedPreviewHash) {
        throw new Error("Orphaned lease release preview changed; review the current proof before retrying");
      }
      const update = this.database.prepare(`
        UPDATE canonical_database_leases
        SET released_at = ?, release_reason = ?
        WHERE id = ? AND fencing_token = ?
          AND resource_id = 'canonical_database'
          AND mode = 'writer'
          AND owner_id = ? AND operation = ?
          AND released_at IS NULL
          AND julianday(expires_at) > julianday(?)
      `).run(
        releasedAt,
        RELEASE_REASON,
        preview.lease.id,
        preview.lease.fencingToken,
        ELIGIBLE_OWNER_ID,
        ELIGIBLE_OPERATION,
        releasedAt,
      );
      if (update.changes !== 1) {
        throw new Error("Exact historical-import lease identity changed before release");
      }

      const previous = this.database.prepare(
        "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
      ).get() as { readonly record_hash: string } | undefined;
      const auditRecordId = identifier(this.#createId(), "Audit record ID");
      const details = {
        schemaVersion: "ti-scale.orphaned-historical-migration-lease-release.v1",
        disposition: "released_orphaned_historical_import_writer",
        previewHash: preview.previewHash,
        lease: preview.lease,
        databasePathHash: preview.databasePathHash,
        matchingImporterProcessIds: preview.matchingImporterProcessIds,
        associatedMigrations: preview.associatedMigrations,
        releaseReason: RELEASE_REASON,
        sourceStateVerifiedTerminal: true,
        serviceRuntimeLeaseReleasePermitted: false,
      } as const;
      const hashBody = {
        id: auditRecordId,
        actorType: "operator",
        actorId,
        action: AUDIT_ACTION,
        resourceType: "canonical_database_lease",
        resourceId: preview.lease.id,
        reason,
        details,
        missionId: null,
        runId: null,
        journey: null,
        previousHash: previous?.record_hash ?? null,
        occurredAt: releasedAt,
      } as const;
      const auditRecordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(hashBody)}`);
      this.database.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, journey, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json, previous_hash,
          record_hash, occurred_at
        ) VALUES (?, NULL, NULL, NULL, 'operator', ?, ?,
          'canonical_database_lease', ?, ?, ?, ?, ?, ?)
      `).run(
        auditRecordId,
        actorId,
        AUDIT_ACTION,
        preview.lease.id,
        reason,
        canonicalJson(details),
        previous?.record_hash ?? null,
        auditRecordHash,
        releasedAt,
      );
      return Object.freeze({
        status: "released" as const,
        leaseId: preview.lease.id,
        fencingToken: preview.lease.fencingToken,
        releasedAt,
        releaseReason: RELEASE_REASON,
        associatedMigrationIds: Object.freeze(preview.associatedMigrations.map(({ id }) => id)),
        previewHash: preview.previewHash,
        auditRecordId,
        auditRecordHash,
      });
    });
  }

  #assertNoImporterProcess(): void {
    const active = [...this.#activeMigrationProcessIds()].sort((left, right) => left - right);
    if (active.length > 0) {
      throw new Error(`A matching historical importer process is still active (${active.join(", ")})`);
    }
  }

  #buildPreview(
    input: { readonly leaseId: string; readonly fencingToken: number },
    now: string,
  ): OrphanedHistoricalMigrationLeaseReleasePreview {
    const leaseId = identifier(input.leaseId, "Lease ID");
    const exactFencingToken = fencingToken(input.fencingToken);
    const row = this.database.prepare(`
      SELECT id, resource_id, mode, owner_id, operation, fencing_token,
        acquired_at, heartbeat_at, expires_at, released_at, release_reason
      FROM canonical_database_leases WHERE id = ?
    `).get(leaseId) as LeaseRow | undefined;
    if (!row) throw new Error("Unknown canonical database lease");
    if (Number(row.fencing_token) !== exactFencingToken) {
      throw new Error("Canonical database lease fencing token does not match");
    }
    if (row.resource_id !== "canonical_database" || row.mode !== "writer"
        || row.owner_id !== ELIGIBLE_OWNER_ID || row.operation !== ELIGIBLE_OPERATION) {
      throw new Error("Lease is not the exact supported historical-engagement importer writer; service, runtime, maintenance, and unknown leases are never released");
    }
    if (row.released_at !== null || Date.parse(row.expires_at) <= Date.parse(now)) {
      throw new Error("Historical-import lease is not active and unexpired");
    }
    const acquiredAt = timestamp(row.acquired_at, "Lease acquisition");
    const heartbeatAt = timestamp(row.heartbeat_at, "Lease heartbeat");
    const expiresAt = timestamp(row.expires_at, "Lease expiry");
    if (Date.parse(heartbeatAt) < Date.parse(acquiredAt)
        || Date.parse(expiresAt) <= Date.parse(acquiredAt)
        || Date.parse(acquiredAt) > Date.parse(now)) {
      throw new Error("Historical-import lease timestamps are inconsistent");
    }

    const migrationRows = this.database.prepare(`
      SELECT run.id, run.status, run.database_path, run.error_summary,
        run.started_at, run.completed_at,
        COALESCE(SUM(CASE WHEN source.status = 'pending' THEN 1 ELSE 0 END), 0) AS pending_sources,
        COALESCE(SUM(CASE WHEN source.status = 'importing' THEN 1 ELSE 0 END), 0) AS importing_sources
      FROM legacy_migration_runs AS run
      LEFT JOIN legacy_migration_sources AS source ON source.migration_id = run.id
      GROUP BY run.id
      ORDER BY run.started_at, run.id
    `).all() as MigrationRow[];
    const associated = migrationRows.filter((migration) => {
      if (normalizedDatabasePath(migration.database_path) !== this.#databasePath) return false;
      const started = Date.parse(migration.started_at);
      const completed = migration.completed_at ? Date.parse(migration.completed_at) : Number.POSITIVE_INFINITY;
      return Number.isFinite(started)
        && started <= Date.parse(now)
        && completed >= Date.parse(acquiredAt);
    });
    if (associated.length === 0) {
      throw new Error("No migration run overlaps the exact historical-import lease interval");
    }
    const migrations = associated.map((migration) => {
      if (migration.status !== "failed" && migration.status !== "completed") {
        throw new Error(`Associated migration ${migration.id} is not terminal failed/completed`);
      }
      const startedAt = timestamp(migration.started_at, `Associated migration ${migration.id} start`);
      const completedAt = timestamp(migration.completed_at, `Associated migration ${migration.id} completion`);
      if (Date.parse(completedAt) > Date.parse(now) || Date.parse(completedAt) < Date.parse(startedAt)) {
        throw new Error(`Associated migration ${migration.id} has inconsistent terminal timestamps`);
      }
      if (migration.status === "failed" && !migration.error_summary?.trim()) {
        throw new Error(`Associated failed migration ${migration.id} has no terminal error summary`);
      }
      const pendingSources = Number(migration.pending_sources);
      const importingSources = Number(migration.importing_sources);
      if (pendingSources !== 0 || importingSources !== 0) {
        throw new Error(`Associated migration ${migration.id} retains pending/importing sources`);
      }
      return Object.freeze({
        id: identifier(migration.id, "Associated migration ID"),
        status: migration.status,
        startedAt,
        completedAt,
        pendingSources: 0 as const,
        importingSources: 0 as const,
      });
    });
    const lease = Object.freeze({
      id: leaseId,
      fencingToken: exactFencingToken,
      mode: "writer" as const,
      ownerId: ELIGIBLE_OWNER_ID,
      operation: ELIGIBLE_OPERATION,
      acquiredAt,
      heartbeatAt,
      expiresAt,
    });
    const unsigned = {
      lease,
      databasePathHash: sha256(this.#databasePath),
      matchingImporterProcessIds: Object.freeze([] as number[]),
      associatedMigrations: Object.freeze(migrations),
      releaseReason: RELEASE_REASON,
    } as const;
    return Object.freeze({ ...unsigned, previewHash: sha256(canonicalJson(unsigned)) });
  }
}

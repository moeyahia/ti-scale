import { randomUUID } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { canonicalJson, sha256 } from "../intelligence-v24/validation";
import { CanonicalDatabaseLeaseService } from "./CanonicalDatabaseLeaseService";

const RESOURCE_ID = "canonical_database";
const SERVICE_OPERATION = "standalone-service-runtime";
const SERVICE_OWNER = /^ti-scale-service:([1-9][0-9]*)$/u;
const RELEASE_REASON = "stopped_service_owner_absent";
const AUDIT_ACTION = "canonical_database_lease.stopped_service_owner_reconciled";

interface LeaseRow {
  readonly id: string;
  readonly mode: string;
  readonly owner_id: string;
  readonly operation: string;
  readonly fencing_token: number;
  readonly acquired_at: string;
  readonly heartbeat_at: string;
  readonly expires_at: string;
}

export interface ServiceProcessBoundarySnapshot {
  readonly activeState: string;
  readonly mainPid: number;
  readonly controlGroup: string;
  readonly controlGroupProcessIds: readonly number[];
  readonly portListening: boolean;
}

export interface StoppedServiceRuntimeLeaseReconciliationInput {
  readonly actorId: string;
  readonly boundaryId: string;
  readonly preStop: ServiceProcessBoundarySnapshot;
  readonly stopped: ServiceProcessBoundarySnapshot;
}

export interface StoppedServiceRuntimeLeaseNotRequired {
  readonly status: "not_required";
  readonly inspectedAt: string;
}

export interface StoppedServiceRuntimeLeaseReleased {
  readonly status: "released";
  readonly leaseId: string;
  readonly fencingToken: number;
  readonly ownerPid: number;
  readonly releasedAt: string;
  readonly releaseReason: typeof RELEASE_REASON;
  readonly auditRecordId: string;
  readonly auditRecordHash: string;
}

export type StoppedServiceRuntimeLeaseReconciliationResult =
  | StoppedServiceRuntimeLeaseNotRequired
  | StoppedServiceRuntimeLeaseReleased;

export interface StoppedServiceRuntimeLeaseReconciliationServiceOptions {
  readonly clock?: () => Date;
  readonly createId?: () => string;
  readonly processExists?: (pid: number) => boolean;
}

function boundedText(value: string, label: string, maximum = 256): string {
  const normalized = value.trim();
  if (!normalized || normalized.length > maximum || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError(`${label} must contain 1 to ${maximum} printable characters`);
  }
  return normalized;
}

function identifier(value: string, label: string): string {
  const normalized = boundedText(value, label);
  if (!/^[a-z0-9][a-z0-9_.:-]*$/iu.test(normalized)) {
    throw new TypeError(`${label} contains unsupported characters`);
  }
  return normalized;
}

function normalizedProcessIds(values: readonly number[], label: string): readonly number[] {
  const normalized = [...new Set(values)];
  if (normalized.some((pid) => !Number.isSafeInteger(pid) || pid < 1)) {
    throw new TypeError(`${label} must contain only positive process IDs`);
  }
  return Object.freeze(normalized.sort((left, right) => left - right));
}

function operatingSystemProcessExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(error instanceof Error && "code" in error && error.code === "ESRCH");
  }
}

function ownerPid(ownerId: string): number | undefined {
  const match = ownerId.match(SERVICE_OWNER);
  if (!match) return undefined;
  const pid = Number(match[1]);
  return Number.isSafeInteger(pid) && pid > 0 ? pid : undefined;
}

function assertStoppedBoundary(
  preStop: ServiceProcessBoundarySnapshot,
  stopped: ServiceProcessBoundarySnapshot,
): readonly number[] {
  const preStopPids = normalizedProcessIds(
    preStop.controlGroupProcessIds,
    "Pre-stop service cgroup process IDs",
  );
  const stoppedPids = normalizedProcessIds(
    stopped.controlGroupProcessIds,
    "Stopped service cgroup process IDs",
  );
  if (!preStop.controlGroup.trim() || preStop.controlGroup !== stopped.controlGroup) {
    throw new Error("Stopped-service lease reconciliation requires one unchanged systemd cgroup identity");
  }
  if (preStopPids.length === 0) {
    throw new Error("Stopped-service lease reconciliation requires a nonempty pre-stop service cgroup");
  }
  if (
    stopped.activeState !== "inactive"
    || stopped.mainPid !== 0
    || stoppedPids.length !== 0
    || stopped.portListening
  ) {
    throw new Error("Stopped-service lease reconciliation requires an inactive, empty, non-listening service boundary");
  }
  return preStopPids;
}

/**
 * Narrow crash reconciliation for the service's own writer lease. The caller
 * must already have stopped systemd and proved that no process holds the
 * canonical SQLite files. This service changes nothing unless exactly one
 * active lease exists, it is the standalone service lease, its PID was in the
 * captured pre-stop cgroup, and that exact PID is now absent.
 */
export class StoppedServiceRuntimeLeaseReconciliationService {
  readonly #clock: () => Date;
  readonly #createId: () => string;
  readonly #processExists: (pid: number) => boolean;

  constructor(
    readonly database: SqliteDatabase,
    options: StoppedServiceRuntimeLeaseReconciliationServiceOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? (() => `audit_stopped_service_lease_${randomUUID()}`);
    this.#processExists = options.processExists ?? operatingSystemProcessExists;
    if (!CanonicalDatabaseLeaseService.schemaAvailable(database)) {
      throw new Error("Stopped-service lease reconciliation requires canonical database migration 35");
    }
  }

  reconcile(
    input: StoppedServiceRuntimeLeaseReconciliationInput,
  ): StoppedServiceRuntimeLeaseReconciliationResult {
    const actorId = identifier(input.actorId, "Lease-reconciliation actor ID");
    const boundaryId = identifier(input.boundaryId, "Lease-reconciliation boundary ID");
    const inspectedAt = this.#clock().toISOString();

    return inImmediateTransaction(this.database, () => {
      const active = this.database.prepare(`
        SELECT id, mode, owner_id, operation, fencing_token, acquired_at,
          heartbeat_at, expires_at
        FROM canonical_database_leases
        WHERE resource_id = ? AND released_at IS NULL
          AND julianday(expires_at) > julianday(?)
        ORDER BY mode, fencing_token, id
      `).all(RESOURCE_ID, inspectedAt) as LeaseRow[];
      if (active.length === 0) {
        return Object.freeze({ status: "not_required" as const, inspectedAt });
      }
      const preStopProcessIds = assertStoppedBoundary(input.preStop, input.stopped);
      if (active.length !== 1) {
        throw new Error(
          "Stopped-service lease reconciliation refuses while any additional canonical database lease is active",
        );
      }
      const lease = active[0]!;
      const pid = ownerPid(lease.owner_id);
      if (lease.mode !== "writer" || lease.operation !== SERVICE_OPERATION || pid === undefined) {
        throw new Error("The active canonical database lease is not the exact standalone service writer");
      }
      if (!preStopProcessIds.includes(pid)) {
        throw new Error("Standalone service lease owner PID was not present in the captured pre-stop cgroup");
      }
      if (this.#processExists(pid)) {
        throw new Error("Standalone service lease owner PID is still present after systemd stop");
      }

      const update = this.database.prepare(`
        UPDATE canonical_database_leases
        SET released_at = ?, release_reason = ?
        WHERE id = ? AND fencing_token = ?
          AND resource_id = ? AND mode = 'writer'
          AND owner_id = ? AND operation = ?
          AND released_at IS NULL
          AND julianday(expires_at) > julianday(?)
      `).run(
        inspectedAt,
        RELEASE_REASON,
        lease.id,
        lease.fencing_token,
        RESOURCE_ID,
        lease.owner_id,
        SERVICE_OPERATION,
        inspectedAt,
      );
      if (update.changes !== 1) {
        throw new Error("Standalone service lease identity changed before stopped-boundary reconciliation");
      }

      const previous = this.database.prepare(
        "SELECT record_hash FROM audit_records ORDER BY rowid DESC LIMIT 1",
      ).get() as { readonly record_hash: string } | undefined;
      const auditRecordId = identifier(this.#createId(), "Lease-reconciliation audit record ID");
      const details = {
        schemaVersion: "ti-scale.stopped-service-runtime-lease-reconciliation.v1",
        disposition: "released_orphaned_standalone_service_writer",
        boundaryId,
        lease: {
          id: lease.id,
          mode: "writer",
          ownerId: lease.owner_id,
          operation: SERVICE_OPERATION,
          fencingToken: lease.fencing_token,
          acquiredAt: lease.acquired_at,
          heartbeatAt: lease.heartbeat_at,
          expiresAt: lease.expires_at,
        },
        preStop: {
          activeState: input.preStop.activeState,
          mainPid: input.preStop.mainPid,
          controlGroup: input.preStop.controlGroup,
          controlGroupProcessIds: preStopProcessIds,
          portListening: input.preStop.portListening,
        },
        stopped: {
          activeState: input.stopped.activeState,
          mainPid: input.stopped.mainPid,
          controlGroup: input.stopped.controlGroup,
          controlGroupProcessIds: [] as readonly number[],
          portListening: input.stopped.portListening,
        },
        ownerPid: pid,
        ownerProcessProvenAbsent: true,
        canonicalDatabaseHandlesProvenAbsentByCaller: true,
        additionalActiveLeases: 0,
        releaseReason: RELEASE_REASON,
      } as const;
      const hashBody = {
        id: auditRecordId,
        actorType: "system",
        actorId,
        action: AUDIT_ACTION,
        resourceType: "canonical_database_lease",
        resourceId: lease.id,
        reason: "The stopped service process exited before releasing its exact canonical writer lease",
        details,
        missionId: null,
        runId: null,
        journey: null,
        previousHash: previous?.record_hash ?? null,
        occurredAt: inspectedAt,
      } as const;
      const auditRecordHash = sha256(`${previous?.record_hash ?? ""}\n${canonicalJson(hashBody)}`);
      this.database.prepare(`
        INSERT INTO audit_records (
          id, mission_id, run_id, journey, actor_type, actor_id, action,
          resource_type, resource_id, reason, details_json, previous_hash,
          record_hash, occurred_at
        ) VALUES (?, NULL, NULL, NULL, 'system', ?, ?,
          'canonical_database_lease', ?, ?, ?, ?, ?, ?)
      `).run(
        auditRecordId,
        actorId,
        AUDIT_ACTION,
        lease.id,
        hashBody.reason,
        canonicalJson(details),
        previous?.record_hash ?? null,
        auditRecordHash,
        inspectedAt,
      );
      return Object.freeze({
        status: "released" as const,
        leaseId: lease.id,
        fencingToken: lease.fencing_token,
        ownerPid: pid,
        releasedAt: inspectedAt,
        releaseReason: RELEASE_REASON,
        auditRecordId,
        auditRecordHash,
      });
    });
  }
}

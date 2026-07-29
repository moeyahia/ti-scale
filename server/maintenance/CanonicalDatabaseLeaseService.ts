import { randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { createDatabaseConnection } from "../db/connection";

export type CanonicalDatabaseLeaseMode = "writer" | "maintenance";

export interface CanonicalDatabaseLeaseHandle {
  readonly id: string;
  readonly mode: CanonicalDatabaseLeaseMode;
  readonly ownerId: string;
  readonly operation: string;
  readonly fencingToken: number;
  readonly acquiredAt: string;
  readonly expiresAt: string;
}

export interface CanonicalDatabaseLeaseSnapshot extends CanonicalDatabaseLeaseHandle {
  readonly heartbeatAt: string;
}

export interface CanonicalDatabaseLeaseServiceOptions {
  readonly clock?: () => Date;
  readonly createId?: () => string;
  /** A file outside SQLite keeps maintenance exclusion intact across DB replacement. */
  readonly maintenanceMarkerPath?: string | null;
  /**
   * Release/rollback-only escape hatch for restoring a pre-lease-schema
   * database while an exclusive maintenance marker is held. The default
   * remains fail-closed: ordinary maintenance may not replace the canonical
   * database with one that cannot participate in lease fencing.
   */
  readonly allowReplacementWithoutLeaseSchema?: boolean;
}

export interface AcquireCanonicalDatabaseLeaseInput {
  readonly ownerId: string;
  readonly operation: string;
  readonly ttlMs?: number;
}

/**
 * Cooperative heartbeat for synchronous bounded work. Timer heartbeats cannot
 * run while a CPU/SQLite-heavy operation owns the JavaScript thread, so long
 * loops must call renew at their durable checkpoints. Every renewal rechecks
 * the exact lease ID, owner, mode, operation, and fencing token.
 */
export interface CanonicalDatabaseLeaseHeartbeat {
  renew(): CanonicalDatabaseLeaseHandle;
  assertActive(): CanonicalDatabaseLeaseSnapshot;
  currentHandle(): CanonicalDatabaseLeaseHandle;
}

const RESOURCE_ID = "canonical_database";
export const CANONICAL_DATABASE_LEASE_SCHEMA_VERSION = 35;
export const DEFAULT_CANONICAL_DATABASE_LEASE_TTL_MS = 10 * 60_000;
const MINIMUM_TTL_MS = 1_000;
const MAXIMUM_TTL_MS = 60 * 60_000;

interface LeaseRow {
  readonly id: string;
  readonly mode: CanonicalDatabaseLeaseMode;
  readonly owner_id: string;
  readonly operation: string;
  readonly fencing_token: number;
  readonly acquired_at: string;
  readonly heartbeat_at: string;
  readonly expires_at: string;
  readonly released_at: string | null;
  readonly release_reason: string | null;
}

interface MaintenanceMarker {
  readonly schemaVersion: "ti-scale.canonical-maintenance-marker.v1";
  readonly id: string;
  readonly ownerId: string;
  readonly operation: string;
  readonly fencingToken: number;
  readonly acquiredAt: string;
  readonly expiresAt: string;
}

interface FileIdentity {
  readonly device: number;
  readonly inode: number;
  readonly path: string;
}

export class CanonicalDatabaseLeaseConflictError extends Error {
  constructor(readonly active: readonly CanonicalDatabaseLeaseSnapshot[]) {
    super(`Canonical database lease is unavailable; ${active.length} active lease${active.length === 1 ? "" : "s"} remain`);
    this.name = "CanonicalDatabaseLeaseConflictError";
  }
}

export class CanonicalDatabaseLeaseLostError extends Error {
  constructor(message = "Canonical database lease is no longer active") {
    super(message);
    this.name = "CanonicalDatabaseLeaseLostError";
  }
}

function boundedText(value: string, label: string): string {
  const result = value.trim();
  if (!result || result.length > 256 || /[\u0000-\u001f\u007f]/u.test(result)) {
    throw new TypeError(`${label} must contain 1 to 256 printable characters`);
  }
  return result;
}

function ttl(value: number | undefined): number {
  const result = value ?? DEFAULT_CANONICAL_DATABASE_LEASE_TTL_MS;
  if (!Number.isSafeInteger(result) || result < MINIMUM_TTL_MS || result > MAXIMUM_TTL_MS) {
    throw new RangeError(`Canonical database lease TTL must be between ${MINIMUM_TTL_MS} and ${MAXIMUM_TTL_MS} milliseconds`);
  }
  return result;
}

function addMilliseconds(source: Date, milliseconds: number): string {
  return new Date(source.getTime() + milliseconds).toISOString();
}

function snapshot(row: LeaseRow): CanonicalDatabaseLeaseSnapshot {
  return Object.freeze({
    id: row.id,
    mode: row.mode,
    ownerId: row.owner_id,
    operation: row.operation,
    fencingToken: Number(row.fencing_token),
    acquiredAt: row.acquired_at,
    heartbeatAt: row.heartbeat_at,
    expiresAt: row.expires_at,
  });
}

/**
 * Durable shared-writer/exclusive-maintenance lease for one SQLite database.
 * Every state transition is serialized through BEGIN IMMEDIATE. A handle is
 * useful only while its exact owner, mode, ID, and monotonic fencing token are
 * still active.
 */
export class CanonicalDatabaseLeaseService {
  readonly #clock: () => Date;
  readonly #createId: () => string;
  readonly #maintenanceMarkerPath: string | null;
  readonly #databaseFileIdentity: FileIdentity | null;
  readonly #allowReplacementWithoutLeaseSchema: boolean;

  constructor(
    readonly database: SqliteDatabase,
    options: CanonicalDatabaseLeaseServiceOptions = {},
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#createId = options.createId ?? (() => `canonical_lease_${randomUUID()}`);
    this.#maintenanceMarkerPath = options.maintenanceMarkerPath === undefined
      ? this.#defaultMaintenanceMarkerPath()
      : options.maintenanceMarkerPath === null
        ? null
        : resolve(options.maintenanceMarkerPath);
    this.#allowReplacementWithoutLeaseSchema = options.allowReplacementWithoutLeaseSchema ?? false;
    this.#databaseFileIdentity = this.#captureDatabaseFileIdentity();
    this.assertSchemaAvailable();
  }

  static schemaAvailable(database: SqliteDatabase): boolean {
    const tables = database.prepare(`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name IN (
        'canonical_database_lease_fence', 'canonical_database_leases'
      )
      ORDER BY name
    `).all() as Array<{ name: string }>;
    return tables.length === 2;
  }

  assertSchemaAvailable(): void {
    if (!CanonicalDatabaseLeaseService.schemaAvailable(this.database)) {
      throw new Error(
        "Canonical database lease schema is unavailable; writer and maintenance operations fail closed until migration 35 is installed",
      );
    }
  }

  acquireWriter(input: AcquireCanonicalDatabaseLeaseInput): CanonicalDatabaseLeaseHandle {
    return this.#acquire("writer", input);
  }

  acquireMaintenance(input: AcquireCanonicalDatabaseLeaseInput): CanonicalDatabaseLeaseHandle {
    return this.#acquire("maintenance", input);
  }

  listActive(): readonly CanonicalDatabaseLeaseSnapshot[] {
    return this.#listActiveAt(this.#clock().toISOString());
  }

  #listActiveAt(now: string): readonly CanonicalDatabaseLeaseSnapshot[] {
    return (this.database.prepare(`
      SELECT id, mode, owner_id, operation, fencing_token, acquired_at,
        heartbeat_at, expires_at, released_at, release_reason
      FROM canonical_database_leases
      WHERE resource_id = ? AND released_at IS NULL
        AND julianday(expires_at) > julianday(?)
      ORDER BY mode, fencing_token, id
    `).all(RESOURCE_ID, now) as LeaseRow[]).map(snapshot);
  }

  assertActive(handle: CanonicalDatabaseLeaseHandle): CanonicalDatabaseLeaseSnapshot {
    return inImmediateTransaction(this.database, () => this.assertActiveInCurrentTransaction(handle));
  }

  /** Call from an already-open database transaction immediately before writes. */
  assertActiveInCurrentTransaction(
    handle: CanonicalDatabaseLeaseHandle,
  ): CanonicalDatabaseLeaseSnapshot {
    const now = this.#clock().toISOString();
    const row = this.#row(handle.id);
    if (!row || row.released_at !== null || Date.parse(row.expires_at) <= Date.parse(now)) {
      throw new CanonicalDatabaseLeaseLostError();
    }
    if (
      row.mode !== handle.mode
      || row.owner_id !== handle.ownerId
      || row.operation !== handle.operation
      || Number(row.fencing_token) !== handle.fencingToken
    ) {
      throw new CanonicalDatabaseLeaseLostError("Canonical database fencing token or ownership no longer matches");
    }
    if (handle.mode === "maintenance") this.#assertMarkerMatches(handle, now);
    else this.#assertNoActiveMaintenanceMarker(now);
    return snapshot(row);
  }

  renew(
    handle: CanonicalDatabaseLeaseHandle,
    ttlMs = DEFAULT_CANONICAL_DATABASE_LEASE_TTL_MS,
  ): CanonicalDatabaseLeaseHandle {
    const duration = ttl(ttlMs);
    return inImmediateTransaction(this.database, () => {
      const active = this.assertActiveInCurrentTransaction(handle);
      const now = this.#clock();
      const expiresAt = addMilliseconds(now, duration);
      if (handle.mode === "maintenance") {
        this.#replaceMaintenanceMarker({
          schemaVersion: "ti-scale.canonical-maintenance-marker.v1",
          id: active.id,
          ownerId: active.ownerId,
          operation: active.operation,
          fencingToken: active.fencingToken,
          acquiredAt: active.acquiredAt,
          expiresAt,
        });
      }
      const result = this.database.prepare(`
        UPDATE canonical_database_leases
        SET heartbeat_at = ?, expires_at = ?
        WHERE id = ? AND fencing_token = ? AND released_at IS NULL
      `).run(now.toISOString(), expiresAt, handle.id, handle.fencingToken);
      if (result.changes !== 1) throw new CanonicalDatabaseLeaseLostError();
      return Object.freeze({
        id: active.id,
        mode: active.mode,
        ownerId: active.ownerId,
        operation: active.operation,
        fencingToken: active.fencingToken,
        acquiredAt: active.acquiredAt,
        expiresAt,
      });
    });
  }

  release(handle: CanonicalDatabaseLeaseHandle, reason = "completed"): boolean {
    const releaseReason = boundedText(reason, "Canonical database lease release reason");
    if (handle.mode === "maintenance") this.#releaseReplacementMirror(handle, releaseReason);
    return inImmediateTransaction(this.database, () => {
      const row = this.#row(handle.id);
      if (!row) throw new CanonicalDatabaseLeaseLostError("Canonical database lease does not exist");
      if (row.released_at !== null) {
        if (row.release_reason === "expired") throw new CanonicalDatabaseLeaseLostError();
        if (handle.mode === "maintenance") this.#removeMaintenanceMarker(handle);
        return false;
      }
      this.assertActiveInCurrentTransaction(handle);
      const result = this.database.prepare(`
        UPDATE canonical_database_leases
        SET released_at = ?, release_reason = ?
        WHERE id = ? AND fencing_token = ? AND released_at IS NULL
      `).run(this.#clock().toISOString(), releaseReason, handle.id, handle.fencingToken);
      if (result.changes !== 1) throw new CanonicalDatabaseLeaseLostError();
      if (handle.mode === "maintenance") this.#removeMaintenanceMarker(handle);
      return true;
    });
  }

  /**
   * Completes an intentional canonical-database replacement after the caller
   * has asserted the lease, closed the original SQLite connection, and
   * atomically installed the replacement while the sidecar marker remained.
   * This avoids any read/write through an unlinked WAL connection.
   */
  releaseAfterDatabaseReplacement(
    handle: CanonicalDatabaseLeaseHandle,
    reason = "database_replacement_completed",
  ): boolean {
    if (handle.mode !== "maintenance") {
      throw new CanonicalDatabaseLeaseLostError("Only a maintenance lease can fence canonical database replacement");
    }
    const releaseReason = boundedText(reason, "Canonical database lease release reason");
    if (this.database.open) {
      throw new CanonicalDatabaseLeaseLostError(
        "Original SQLite connection must be closed before completing canonical database replacement",
      );
    }
    const original = this.#databaseFileIdentity;
    if (!original) throw new CanonicalDatabaseLeaseLostError("Canonical database file identity is unavailable");
    let current: ReturnType<typeof statSync>;
    try { current = statSync(original.path); }
    catch { throw new CanonicalDatabaseLeaseLostError("Canonical database path disappeared during replacement"); }
    if (Number(current.dev) === original.device && Number(current.ino) === original.inode) {
      throw new CanonicalDatabaseLeaseLostError("Canonical database path was not replaced");
    }
    const now = this.#clock().toISOString();
    this.#assertMarkerMatches(handle, now);

    const inspection = createDatabaseConnection({
      filename: original.path,
      readonly: true,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    let replacementHasLeaseSchema: boolean;
    try {
      replacementHasLeaseSchema = CanonicalDatabaseLeaseService.schemaAvailable(inspection);
    } finally {
      inspection.close();
    }
    if (!replacementHasLeaseSchema && !this.#allowReplacementWithoutLeaseSchema) {
      throw new CanonicalDatabaseLeaseLostError("Replacement canonical database lacks the lease schema");
    }
    if (replacementHasLeaseSchema) {
      const replacement = createDatabaseConnection({
        filename: original.path,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      try {
        inImmediateTransaction(replacement, () => {
          replacement.prepare(`
            UPDATE canonical_database_leases
            SET released_at = ?, release_reason = 'superseded_by_database_restore'
            WHERE mode = 'maintenance' AND released_at IS NULL AND id <> ?
          `).run(now, handle.id);
          const row = replacement.prepare(`
            SELECT id, mode, owner_id, operation, fencing_token, released_at
            FROM canonical_database_leases WHERE id = ?
          `).get(handle.id) as Pick<LeaseRow,
            "id" | "mode" | "owner_id" | "operation" | "fencing_token" | "released_at"
          > | undefined;
          if (!row) return;
          if (
            row.mode !== handle.mode || row.owner_id !== handle.ownerId
            || row.operation !== handle.operation
            || Number(row.fencing_token) !== handle.fencingToken
          ) throw new CanonicalDatabaseLeaseLostError("Replacement database contains a conflicting maintenance fence");
          if (row.released_at !== null) return;
          const result = replacement.prepare(`
            UPDATE canonical_database_leases
            SET released_at = ?, release_reason = ?
            WHERE id = ? AND fencing_token = ? AND released_at IS NULL
          `).run(now, releaseReason, handle.id, handle.fencingToken);
          if (result.changes !== 1) throw new CanonicalDatabaseLeaseLostError();
        });
      } finally {
        replacement.close();
      }
    }
    this.#removeMaintenanceMarker(handle);
    return true;
  }

  #acquire(
    mode: CanonicalDatabaseLeaseMode,
    input: AcquireCanonicalDatabaseLeaseInput,
  ): CanonicalDatabaseLeaseHandle {
    const ownerId = boundedText(input.ownerId, "Canonical database lease owner");
    const operation = boundedText(input.operation, "Canonical database lease operation");
    const duration = ttl(input.ttlMs);
    let claimedMarker: MaintenanceMarker | undefined;
    try {
      return inImmediateTransaction(this.database, () => {
      const now = this.#clock();
      const nowIso = now.toISOString();
      this.#assertNoActiveMaintenanceMarker(nowIso);
      this.#expireStale(nowIso);
      const active = this.#listActiveAt(nowIso);
      const conflicts = mode === "maintenance"
        ? active
        : active.filter((lease) => lease.mode === "maintenance");
      if (conflicts.length > 0) throw new CanonicalDatabaseLeaseConflictError(conflicts);

      const fence = this.database.prepare(`
        SELECT next_fencing_token AS token
        FROM canonical_database_lease_fence WHERE resource_id = ?
      `).get(RESOURCE_ID) as { token: number } | undefined;
      const fencingToken = Number(fence?.token ?? 0);
      if (!Number.isSafeInteger(fencingToken) || fencingToken < 1) {
        throw new Error("Canonical database fencing counter is unavailable or exhausted");
      }
      const counterUpdate = this.database.prepare(`
        UPDATE canonical_database_lease_fence
        SET next_fencing_token = next_fencing_token + 1
        WHERE resource_id = ? AND next_fencing_token = ?
      `).run(RESOURCE_ID, fencingToken);
      if (counterUpdate.changes !== 1) {
        throw new Error("Canonical database fencing counter changed unexpectedly");
      }
      const id = boundedText(this.#createId(), "Canonical database lease ID");
      const expiresAt = addMilliseconds(now, duration);
      if (mode === "maintenance") {
        claimedMarker = {
          schemaVersion: "ti-scale.canonical-maintenance-marker.v1",
          id,
          ownerId,
          operation,
          fencingToken,
          acquiredAt: nowIso,
          expiresAt,
        };
        this.#claimMaintenanceMarker(claimedMarker);
      }
      this.database.prepare(`
        INSERT INTO canonical_database_leases (
          id, resource_id, mode, owner_id, operation, fencing_token,
          acquired_at, heartbeat_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        RESOURCE_ID,
        mode,
        ownerId,
        operation,
        fencingToken,
        nowIso,
        nowIso,
        expiresAt,
      );
      return Object.freeze({
        id,
        mode,
        ownerId,
        operation,
        fencingToken,
        acquiredAt: nowIso,
        expiresAt,
      });
      });
    } catch (error) {
      if (claimedMarker) {
        try { this.#removeMaintenanceMarker(claimedMarker); }
        catch { /* An uncertain marker remains fail-closed until its TTL. */ }
      }
      throw error;
    }
  }

  #expireStale(now: string): void {
    this.database.prepare(`
      UPDATE canonical_database_leases
      SET released_at = ?, release_reason = 'expired'
      WHERE resource_id = ? AND released_at IS NULL
        AND julianday(expires_at) <= julianday(?)
    `).run(now, RESOURCE_ID, now);
  }

  #row(id: string): LeaseRow | undefined {
    return this.database.prepare(`
      SELECT id, mode, owner_id, operation, fencing_token, acquired_at,
        heartbeat_at, expires_at, released_at, release_reason
      FROM canonical_database_leases WHERE id = ?
    `).get(id) as LeaseRow | undefined;
  }

  #defaultMaintenanceMarkerPath(): string | null {
    const name = this.database.name;
    if (!name || name === ":memory:" || name.startsWith("file::memory:")) return null;
    return resolve(`${name}.maintenance-lock.json`);
  }

  #readMaintenanceMarker(): MaintenanceMarker | undefined {
    const path = this.#maintenanceMarkerPath;
    if (!path || !existsSync(path)) return undefined;
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new CanonicalDatabaseLeaseLostError("Canonical maintenance marker is not a safe regular file");
    }
    let value: unknown;
    try { value = JSON.parse(readFileSync(path, "utf8")); }
    catch { throw new CanonicalDatabaseLeaseLostError("Canonical maintenance marker is malformed"); }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new CanonicalDatabaseLeaseLostError("Canonical maintenance marker is malformed");
    }
    const marker = value as Partial<MaintenanceMarker>;
    if (
      marker.schemaVersion !== "ti-scale.canonical-maintenance-marker.v1"
      || typeof marker.id !== "string"
      || typeof marker.ownerId !== "string"
      || typeof marker.operation !== "string"
      || !Number.isSafeInteger(marker.fencingToken)
      || typeof marker.acquiredAt !== "string"
      || typeof marker.expiresAt !== "string"
      || !Number.isFinite(Date.parse(marker.acquiredAt))
      || !Number.isFinite(Date.parse(marker.expiresAt))
    ) throw new CanonicalDatabaseLeaseLostError("Canonical maintenance marker is malformed");
    return marker as MaintenanceMarker;
  }

  #assertNoActiveMaintenanceMarker(now: string): void {
    const marker = this.#readMaintenanceMarker();
    if (!marker) return;
    if (Date.parse(marker.expiresAt) <= Date.parse(now)) {
      this.#removeMaintenanceMarker(marker);
      return;
    }
    throw new CanonicalDatabaseLeaseConflictError([Object.freeze({
      id: marker.id,
      mode: "maintenance",
      ownerId: marker.ownerId,
      operation: marker.operation,
      fencingToken: marker.fencingToken,
      acquiredAt: marker.acquiredAt,
      heartbeatAt: marker.acquiredAt,
      expiresAt: marker.expiresAt,
    })]);
  }

  #assertMarkerMatches(
    handle: Pick<CanonicalDatabaseLeaseHandle, "id" | "ownerId" | "operation" | "fencingToken">,
    now: string,
  ): void {
    if (!this.#maintenanceMarkerPath) return;
    const marker = this.#readMaintenanceMarker();
    if (
      !marker
      || Date.parse(marker.expiresAt) <= Date.parse(now)
      || marker.id !== handle.id
      || marker.ownerId !== handle.ownerId
      || marker.operation !== handle.operation
      || marker.fencingToken !== handle.fencingToken
    ) throw new CanonicalDatabaseLeaseLostError("Canonical maintenance marker no longer matches the fenced lease");
  }

  #claimMaintenanceMarker(marker: MaintenanceMarker): void {
    const path = this.#maintenanceMarkerPath;
    if (!path) return;
    let descriptor: number | undefined;
    try {
      descriptor = openSync(path, "wx", 0o600);
      writeFileSync(descriptor, `${JSON.stringify(marker)}\n`, "utf8");
      fsyncSync(descriptor);
    } catch (error) {
      if (descriptor !== undefined) closeSync(descriptor);
      if (existsSync(path)) {
        const active = this.#readMaintenanceMarker();
        if (active) throw new CanonicalDatabaseLeaseConflictError([Object.freeze({
          id: active.id,
          mode: "maintenance",
          ownerId: active.ownerId,
          operation: active.operation,
          fencingToken: active.fencingToken,
          acquiredAt: active.acquiredAt,
          heartbeatAt: active.acquiredAt,
          expiresAt: active.expiresAt,
        })]);
      }
      throw error;
    }
    if (descriptor !== undefined) closeSync(descriptor);
  }

  #replaceMaintenanceMarker(marker: MaintenanceMarker): void {
    const path = this.#maintenanceMarkerPath;
    if (!path) return;
    this.#assertMarkerMatches(marker, this.#clock().toISOString());
    const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
    try {
      writeFileSync(temporary, `${JSON.stringify(marker)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
      renameSync(temporary, path);
    } finally {
      if (existsSync(temporary)) unlinkSync(temporary);
    }
  }

  #removeMaintenanceMarker(handle: Pick<CanonicalDatabaseLeaseHandle, "id" | "ownerId" | "operation" | "fencingToken">): void {
    const path = this.#maintenanceMarkerPath;
    if (!path || !existsSync(path)) return;
    const marker = this.#readMaintenanceMarker();
    if (
      !marker
      || marker.id !== handle.id
      || marker.ownerId !== handle.ownerId
      || marker.operation !== handle.operation
      || marker.fencingToken !== handle.fencingToken
    ) throw new CanonicalDatabaseLeaseLostError("Canonical maintenance marker ownership no longer matches");
    unlinkSync(path);
  }

  #captureDatabaseFileIdentity(): FileIdentity | null {
    const name = this.database.name;
    if (!name || name === ":memory:" || name.startsWith("file::memory:")) return null;
    const path = resolve(name);
    try {
      const metadata = statSync(path);
      return { device: Number(metadata.dev), inode: Number(metadata.ino), path };
    } catch {
      return null;
    }
  }

  #releaseReplacementMirror(
    handle: CanonicalDatabaseLeaseHandle,
    reason: string,
  ): void {
    const original = this.#databaseFileIdentity;
    if (!original) return;
    let current: ReturnType<typeof statSync>;
    try { current = statSync(original.path); }
    catch { throw new CanonicalDatabaseLeaseLostError("Canonical database path disappeared while maintenance was active"); }
    if (Number(current.dev) === original.device && Number(current.ino) === original.inode) return;

    const replacement = createDatabaseConnection({
      filename: original.path,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try {
      if (!CanonicalDatabaseLeaseService.schemaAvailable(replacement)) {
        throw new CanonicalDatabaseLeaseLostError("Replacement canonical database lacks the lease schema");
      }
      inImmediateTransaction(replacement, () => {
        // A restored snapshot can contain the maintenance row that protected
        // its original backup. The current sidecar marker proves this process
        // owns the replacement boundary, so those snapshot-era rows are stale.
        replacement.prepare(`
          UPDATE canonical_database_leases
          SET released_at = ?, release_reason = 'superseded_by_database_restore'
          WHERE mode = 'maintenance' AND released_at IS NULL AND id <> ?
        `).run(this.#clock().toISOString(), handle.id);
        const row = replacement.prepare(`
          SELECT id, mode, owner_id, operation, fencing_token, released_at
          FROM canonical_database_leases WHERE id = ?
        `).get(handle.id) as Pick<LeaseRow,
          "id" | "mode" | "owner_id" | "operation" | "fencing_token" | "released_at"
        > | undefined;
        if (!row) return;
        if (
          row.mode !== "maintenance"
          || row.owner_id !== handle.ownerId
          || row.operation !== handle.operation
          || Number(row.fencing_token) !== handle.fencingToken
        ) throw new CanonicalDatabaseLeaseLostError("Replacement database contains a conflicting maintenance fence");
        if (row.released_at !== null) return;
        const result = replacement.prepare(`
          UPDATE canonical_database_leases
          SET released_at = ?, release_reason = ?
          WHERE id = ? AND fencing_token = ? AND released_at IS NULL
        `).run(this.#clock().toISOString(), reason, handle.id, handle.fencingToken);
        if (result.changes !== 1) throw new CanonicalDatabaseLeaseLostError();
      });
    } finally {
      replacement.close();
    }
  }
}

export async function withCanonicalWriterLease<T>(
  database: SqliteDatabase,
  input: AcquireCanonicalDatabaseLeaseInput,
  operation: (
    handle: CanonicalDatabaseLeaseHandle,
    leases: CanonicalDatabaseLeaseService,
    heartbeat: CanonicalDatabaseLeaseHeartbeat,
  ) => T | Promise<T>,
  options: CanonicalDatabaseLeaseServiceOptions = {},
): Promise<T> {
  const leases = new CanonicalDatabaseLeaseService(database, options);
  let handle = leases.acquireWriter(input);
  const ttlMs = ttl(input.ttlMs);
  const heartbeatMs = Math.max(1_000, Math.floor(ttlMs / 3));
  let heartbeatFailure: unknown;
  const assertHeartbeatHealthy = (): void => {
    if (heartbeatFailure) throw heartbeatFailure;
  };
  const renew = (): CanonicalDatabaseLeaseHandle => {
    assertHeartbeatHealthy();
    try {
      handle = leases.renew(handle, ttlMs);
      return handle;
    } catch (error) {
      heartbeatFailure = error;
      throw error;
    }
  };
  const control: CanonicalDatabaseLeaseHeartbeat = Object.freeze({
    renew,
    assertActive: () => {
      assertHeartbeatHealthy();
      return leases.assertActive(handle);
    },
    currentHandle: () => handle,
  });
  const heartbeat = setInterval(() => {
    try { renew(); }
    catch (error) { heartbeatFailure = error; }
  }, heartbeatMs);
  heartbeat.unref?.();
  let operationFailed = false;
  try {
    const result = await operation(handle, leases, control);
    assertHeartbeatHealthy();
    control.assertActive();
    return result;
  } catch (error) {
    operationFailed = true;
    throw error;
  } finally {
    clearInterval(heartbeat);
    try { leases.release(handle, heartbeatFailure ? "lease_lost" : operationFailed ? "failed" : "completed"); }
    catch (releaseError) {
      // Preserve the original failure, but never report success when the
      // durable ownership boundary could not be released cleanly.
      if (!operationFailed) throw releaseError;
    }
  }
}

export async function withCanonicalMaintenanceLease<T>(
  database: SqliteDatabase,
  input: AcquireCanonicalDatabaseLeaseInput,
  operation: (
    handle: CanonicalDatabaseLeaseHandle,
    leases: CanonicalDatabaseLeaseService,
  ) => T | Promise<T>,
  options: CanonicalDatabaseLeaseServiceOptions = {},
): Promise<T> {
  const leases = new CanonicalDatabaseLeaseService(database, options);
  let handle = leases.acquireMaintenance(input);
  const ttlMs = ttl(input.ttlMs);
  const heartbeatMs = Math.max(1_000, Math.floor(ttlMs / 3));
  let heartbeatFailure: unknown;
  const heartbeat = setInterval(() => {
    try { handle = leases.renew(handle, ttlMs); }
    catch (error) { heartbeatFailure = error; }
  }, heartbeatMs);
  heartbeat.unref?.();
  let operationFailed = false;
  try {
    const result = await operation(handle, leases);
    if (heartbeatFailure) throw heartbeatFailure;
    leases.assertActive(handle);
    return result;
  } catch (error) {
    operationFailed = true;
    throw error;
  } finally {
    clearInterval(heartbeat);
    try { leases.release(handle, heartbeatFailure ? "lease_lost" : operationFailed ? "failed" : "completed"); }
    catch (releaseError) {
      // The marker remains fail-closed until expiry if ownership is uncertain.
      if (!operationFailed) throw releaseError;
    }
  }
}

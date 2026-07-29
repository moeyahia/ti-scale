import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";

export const CONTROL_PLANES = ["legacy", "ti_scale"] as const;
export type ControlPlane = (typeof CONTROL_PLANES)[number];

export type ControlPlaneLeaseErrorCode =
  | "run_not_found"
  | "control_plane_mismatch"
  | "journey_unsupported"
  | "lease_conflict"
  | "lease_missing"
  | "lease_expired"
  | "lease_token_invalid"
  | "lease_fence_invalid"
  | "lease_owner_invalid";

export class ControlPlaneLeaseError extends Error {
  constructor(
    readonly code: ControlPlaneLeaseErrorCode,
    message: string,
    readonly retryable = false,
  ) {
    super(message);
    this.name = "ControlPlaneLeaseError";
  }
}

export interface ControlPlaneLease {
  readonly runId: string;
  readonly controlPlane: ControlPlane;
  readonly leaseOwner: string;
  readonly acquiredAt: string;
  readonly heartbeatAt: string;
  readonly expiresAt: string;
  readonly version: number;
}

interface LeaseRow {
  run_id: string;
  control_plane: ControlPlane;
  lease_owner: string;
  lease_token_hash: string;
  acquired_at: string;
  heartbeat_at: string;
  expires_at: string;
  released_at: string | null;
  version: number;
}

interface RunRow {
  id: string;
  control_plane: ControlPlane;
  mission_control_plane: ControlPlane;
}

export interface AcquireControlPlaneLeaseInput {
  readonly runId: string;
  readonly controlPlane: ControlPlane;
  readonly leaseOwner: string;
  readonly leaseToken?: string;
  readonly ttlMs?: number;
  readonly now?: Date;
}

export interface AcquiredControlPlaneLease {
  readonly lease: ControlPlaneLease;
  /** Returned only when the service generated the token. Persist it in the owning worker, never in logs. */
  readonly leaseToken?: string;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/u;
const MIN_TTL_MS = 1_000;
const MAX_TTL_MS = 5 * 60_000;
const DEFAULT_TTL_MS = 30_000;

function stableIdentifier(value: string, label: string): string {
  const normalized = value.trim();
  if (!IDENTIFIER.test(normalized)) {
    throw new ControlPlaneLeaseError(
      label === "lease owner" ? "lease_owner_invalid" : "run_not_found",
      `${label} is invalid`,
    );
  }
  return normalized;
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function tokenMatches(token: string, expectedHash: string): boolean {
  const actual = Buffer.from(tokenHash(token), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function leaseFromRow(row: LeaseRow): ControlPlaneLease {
  return {
    runId: row.run_id,
    controlPlane: row.control_plane,
    leaseOwner: row.lease_owner,
    acquiredAt: row.acquired_at,
    heartbeatAt: row.heartbeat_at,
    expiresAt: row.expires_at,
    version: row.version,
  };
}

function requireTtl(ttlMs = DEFAULT_TTL_MS): number {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < MIN_TTL_MS || ttlMs > MAX_TTL_MS) {
    throw new RangeError(`Control-plane lease TTL must be between ${MIN_TTL_MS} and ${MAX_TTL_MS} ms`);
  }
  return ttlMs;
}

/**
 * Enforces single-control-plane mutation authority for every V2-native run.
 * The raw lease token is never written to SQLite; only its SHA-256 digest is
 * retained. Callers must assert authority immediately before each mutation.
 */
export class ControlPlaneLeaseService {
  constructor(private readonly database: SqliteDatabase) {}

  acquire(input: AcquireControlPlaneLeaseInput): AcquiredControlPlaneLease {
    const runId = stableIdentifier(input.runId, "run ID");
    const leaseOwner = stableIdentifier(input.leaseOwner, "lease owner");
    const ttlMs = requireTtl(input.ttlMs);
    const now = input.now ?? new Date();
    if (!Number.isFinite(now.getTime())) throw new RangeError("Lease acquisition time is invalid");
    const nowIso = now.toISOString();
    const expiresAt = new Date(now.getTime() + ttlMs).toISOString();
    const generated = input.leaseToken === undefined;
    const leaseToken = input.leaseToken ?? randomUUID();
    if (leaseToken.length < 16 || leaseToken.length > 1_024) {
      throw new ControlPlaneLeaseError("lease_token_invalid", "Lease token length is invalid");
    }

    const lease = inImmediateTransaction(this.database, () => {
      const run = this.database.prepare(
        `SELECT r.id, r.control_plane, m.control_plane AS mission_control_plane
         FROM runs r JOIN missions m ON m.id = r.mission_id WHERE r.id = ?`,
      ).get(runId) as RunRow | undefined;
      if (!run) throw new ControlPlaneLeaseError("run_not_found", `Run ${runId} does not exist`);
      if (
        run.control_plane !== input.controlPlane ||
        run.mission_control_plane !== input.controlPlane
      ) {
        throw new ControlPlaneLeaseError(
          "control_plane_mismatch",
          `Run ${runId} and its mission are not exclusively owned by ${input.controlPlane}`,
        );
      }

      const existing = this.database.prepare(
        "SELECT * FROM control_plane_leases WHERE run_id = ?",
      ).get(runId) as LeaseRow | undefined;
      const active = existing && existing.released_at === null && Date.parse(existing.expires_at) > now.getTime();
      if (active) {
        const sameAuthority = existing.control_plane === input.controlPlane
          && existing.lease_owner === leaseOwner
          && tokenMatches(leaseToken, existing.lease_token_hash);
        if (!sameAuthority) {
          throw new ControlPlaneLeaseError(
            "lease_conflict",
            `Run ${runId} is already controlled by ${existing.lease_owner}`,
            true,
          );
        }
        this.database.prepare(`
          UPDATE control_plane_leases
          SET heartbeat_at = ?, expires_at = ?, version = version + 1
          WHERE run_id = ?
        `).run(nowIso, expiresAt, runId);
      } else if (existing) {
        this.database.prepare(`
          UPDATE control_plane_leases
          SET control_plane = ?, lease_owner = ?, lease_token_hash = ?,
              acquired_at = ?, heartbeat_at = ?, expires_at = ?, released_at = NULL,
              version = version + 1
          WHERE run_id = ?
        `).run(
          input.controlPlane,
          leaseOwner,
          tokenHash(leaseToken),
          nowIso,
          nowIso,
          expiresAt,
          runId,
        );
      } else {
        this.database.prepare(`
          INSERT INTO control_plane_leases (
            run_id, control_plane, lease_owner, lease_token_hash,
            acquired_at, heartbeat_at, expires_at, released_at, version
          ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1)
        `).run(
          runId,
          input.controlPlane,
          leaseOwner,
          tokenHash(leaseToken),
          nowIso,
          nowIso,
          expiresAt,
        );
      }

      return leaseFromRow(this.database.prepare(
        "SELECT * FROM control_plane_leases WHERE run_id = ?",
      ).get(runId) as LeaseRow);
    });

    return { lease, ...(generated ? { leaseToken } : {}) };
  }

  assertMutationAuthority(input: {
    readonly runId: string;
    readonly controlPlane: ControlPlane;
    readonly leaseOwner: string;
    readonly leaseToken: string;
    readonly now?: Date;
  }): ControlPlaneLease {
    const runId = stableIdentifier(input.runId, "run ID");
    const owner = stableIdentifier(input.leaseOwner, "lease owner");
    const now = input.now ?? new Date();
    const run = this.database.prepare(
      `SELECT r.id, r.control_plane, m.control_plane AS mission_control_plane
       FROM runs r JOIN missions m ON m.id = r.mission_id WHERE r.id = ?`,
    ).get(runId) as RunRow | undefined;
    if (!run) throw new ControlPlaneLeaseError("run_not_found", `Run ${runId} does not exist`);
    if (
      run.control_plane !== input.controlPlane ||
      run.mission_control_plane !== input.controlPlane
    ) {
      throw new ControlPlaneLeaseError(
        "control_plane_mismatch",
        `Run ${runId} and its mission are not exclusively owned by ${input.controlPlane}`,
      );
    }
    const row = this.database.prepare(
      "SELECT * FROM control_plane_leases WHERE run_id = ? AND released_at IS NULL",
    ).get(runId) as LeaseRow | undefined;
    if (!row) throw new ControlPlaneLeaseError("lease_missing", `Run ${runId} has no active control-plane lease`);
    if (Date.parse(row.expires_at) <= now.getTime()) {
      throw new ControlPlaneLeaseError("lease_expired", `Run ${runId} control-plane lease expired`, true);
    }
    if (
      row.control_plane !== input.controlPlane
      || row.lease_owner !== owner
      || !tokenMatches(input.leaseToken, row.lease_token_hash)
    ) {
      throw new ControlPlaneLeaseError("lease_token_invalid", `Run ${runId} mutation authority is invalid`);
    }
    return leaseFromRow(row);
  }

  /**
   * Revalidates the non-secret lease proof returned by a trusted, server-side
   * lease holder. The holder must first prove possession of the raw token via
   * `assertMutationAuthority`; HTTP callers never receive or submit that token.
   * Comparing every persisted field, especially `version`, fences a proof that
   * was valid before a heartbeat, release, expiry, or controller takeover.
   */
  assertCurrentLeaseProof(proof: ControlPlaneLease, now: Date = new Date()): ControlPlaneLease {
    const runId = stableIdentifier(proof.runId, "run ID");
    if (!Number.isFinite(now.getTime())) throw new RangeError("Lease proof time is invalid");
    const row = this.database.prepare(
      "SELECT * FROM control_plane_leases WHERE run_id = ? AND released_at IS NULL",
    ).get(runId) as LeaseRow | undefined;
    if (!row) throw new ControlPlaneLeaseError("lease_missing", `Run ${runId} has no active control-plane lease`);
    if (Date.parse(row.expires_at) <= now.getTime()) {
      throw new ControlPlaneLeaseError("lease_expired", `Run ${runId} control-plane lease expired`, true);
    }
    const current = leaseFromRow(row);
    if (
      proof.controlPlane !== current.controlPlane
      || proof.leaseOwner !== current.leaseOwner
      || proof.acquiredAt !== current.acquiredAt
      || proof.heartbeatAt !== current.heartbeatAt
      || proof.expiresAt !== current.expiresAt
      || proof.version !== current.version
    ) {
      throw new ControlPlaneLeaseError(
        "lease_fence_invalid",
        `Run ${runId} control-plane lease proof is stale`,
        true,
      );
    }
    return current;
  }

  heartbeat(input: AcquireControlPlaneLeaseInput & { readonly leaseToken: string }): ControlPlaneLease {
    return this.acquire(input).lease;
  }

  release(input: {
    readonly runId: string;
    readonly controlPlane: ControlPlane;
    readonly leaseOwner: string;
    readonly leaseToken: string;
    readonly now?: Date;
  }): void {
    // Release is cleanup, not mission control. It remains allowed after an
    // explicit ownership transfer so an old Ti-Scale process can retire only
    // its own token without touching the legacy-owned mission or run rows.
    const runId = stableIdentifier(input.runId, "run ID");
    const owner = stableIdentifier(input.leaseOwner, "lease owner");
    const row = this.database.prepare(
      "SELECT * FROM control_plane_leases WHERE run_id = ? AND released_at IS NULL",
    ).get(runId) as LeaseRow | undefined;
    if (
      !row || row.control_plane !== input.controlPlane ||
      row.lease_owner !== owner || !tokenMatches(input.leaseToken, row.lease_token_hash)
    ) {
      throw new ControlPlaneLeaseError("lease_token_invalid", `Run ${runId} release authority is invalid`);
    }
    const authority = leaseFromRow(row);
    const releasedAt = (input.now ?? new Date()).toISOString();
    const result = this.database.prepare(`
      UPDATE control_plane_leases
      SET released_at = ?, heartbeat_at = ?, version = version + 1
      WHERE run_id = ? AND version = ? AND released_at IS NULL
    `).run(releasedAt, releasedAt, authority.runId, authority.version);
    if (result.changes !== 1) {
      throw new ControlPlaneLeaseError(
        "lease_conflict",
        `Run ${authority.runId} lease changed while it was being released`,
        true,
      );
    }
  }
}

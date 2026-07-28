import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";

const SHA256 = /^[a-f0-9]{64}$/u;

export const ACTIVE_VAULT_HEALTH_MAXIMUM_AGE_MS = 5 * 60_000;

interface VaultCompositionRow {
  readonly id: string;
  readonly vault_path: string;
  readonly status: "disconnected" | "connecting" | "connected" | "degraded" | "error";
  readonly updated_at: string;
  readonly health_details_json: string | null;
  readonly health_record_hash: string | null;
  readonly health_occurred_at: string | null;
}

interface VaultHealthProofDetails {
  readonly connectionId: string;
  readonly connectionUpdatedAt: string;
  readonly pathFingerprint: string;
  readonly checks: {
    readonly write: true;
    readonly read: true;
    readonly rename: true;
    readonly delete: true;
  };
}

export interface UsableActiveVault {
  /** Internal stable connection key. No filesystem path is returned. */
  readonly connectionId: string;
  /** Content-free digest binding connection, canonical path, version, and proof. */
  readonly compositionSha256: string;
}

export interface ActiveVaultComposition {
  readonly configuredConnections: number;
  readonly activeConnections: number;
  readonly connectedConnections: number;
  readonly reachableConnections: number;
  readonly healthVerifiedConnections: number;
  readonly usableVaults: readonly UsableActiveVault[];
  readonly activeVaultSetSha256: string;
}

export interface ActiveVaultCompositionOptions {
  /**
   * This must resolve an already-existing configured Vault through the current
   * sandbox. It must not create, repair, or otherwise write to the filesystem.
   */
  readonly resolveExistingVaultPath?: (vaultPath: string) => string;
  readonly now?: Date;
  readonly maximumHealthAgeMs?: number;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function activeVaultPathFingerprint(resolvedVaultPath: string): string {
  return sha256(`vault-path:${resolvedVaultPath}`);
}

function validDate(value: string): number | undefined {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return undefined;
  try {
    return new Date(parsed).toISOString() === value ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function proofDetails(
  value: string | null,
): VaultHealthProofDetails | undefined {
  if (!value || Buffer.byteLength(value, "utf8") > 16_384) return undefined;
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    const record = parsed as Record<string, unknown>;
    const checks = record.checks;
    if (!checks || typeof checks !== "object" || Array.isArray(checks)) return undefined;
    const checkRecord = checks as Record<string, unknown>;
    if (
      typeof record.connectionId !== "string"
      || typeof record.connectionUpdatedAt !== "string"
      || typeof record.pathFingerprint !== "string"
      || !SHA256.test(record.pathFingerprint)
      || checkRecord.write !== true
      || checkRecord.read !== true
      || checkRecord.rename !== true
      || checkRecord.delete !== true
    ) return undefined;
    return {
      connectionId: record.connectionId,
      connectionUpdatedAt: record.connectionUpdatedAt,
      pathFingerprint: record.pathFingerprint,
      checks: { write: true, read: true, rename: true, delete: true },
    };
  } catch {
    return undefined;
  }
}

/**
 * The single read-only authority for active Obsidian Vault composition.
 *
 * A Vault is usable only when its current configured path resolves through the
 * current sandbox and the newest persisted health receipt proves the exact
 * connection ID, canonical path fingerprint, and connection version. Proofs
 * from the future or outside the bounded freshness window fail closed.
 */
export function readActiveVaultComposition(
  database: SqliteDatabase,
  options: ActiveVaultCompositionOptions = {},
): ActiveVaultComposition {
  const now = options.now ?? new Date();
  const nowMs = now.getTime();
  const maximumHealthAgeMs =
    options.maximumHealthAgeMs ?? ACTIVE_VAULT_HEALTH_MAXIMUM_AGE_MS;
  if (
    !Number.isFinite(nowMs)
    || !Number.isSafeInteger(maximumHealthAgeMs)
    || maximumHealthAgeMs < 1
    || maximumHealthAgeMs > 24 * 60 * 60_000
  ) throw new TypeError("Active Vault composition time bounds are invalid");

  const rows = database.prepare(`
    SELECT
      connection.id,
      connection.vault_path,
      connection.status,
      connection.updated_at,
      health.details_json AS health_details_json,
      health.record_hash AS health_record_hash,
      health.occurred_at AS health_occurred_at
    FROM vault_connections connection
    LEFT JOIN audit_records health ON health.rowid = (
      SELECT candidate.rowid
      FROM audit_records candidate
      WHERE candidate.resource_type = 'vault_connection'
        AND candidate.resource_id = connection.id
        AND candidate.action = 'vault.health.verified'
      ORDER BY candidate.occurred_at DESC, candidate.rowid DESC
      LIMIT 1
    )
    ORDER BY connection.id
  `).all() as readonly VaultCompositionRow[];

  const activeConnections = rows.filter(({ status }) => status !== "disconnected");
  const connectedConnections = rows.filter(({ status }) => status === "connected");
  let reachableConnections = 0;
  let healthVerifiedConnections = 0;
  const usableVaults: UsableActiveVault[] = [];

  if (options.resolveExistingVaultPath) {
    for (const row of connectedConnections) {
      let resolvedPath: string;
      try {
        resolvedPath = options.resolveExistingVaultPath(row.vault_path);
        if (!resolvedPath.trim() || resolvedPath.includes("\u0000")) continue;
        reachableConnections += 1;
      } catch {
        continue;
      }

      const details = proofDetails(row.health_details_json);
      const proofMs = row.health_occurred_at
        ? validDate(row.health_occurred_at)
        : undefined;
      const connectionVersionMs = validDate(row.updated_at);
      const proofIsCurrent =
        details !== undefined
        && proofMs !== undefined
        && connectionVersionMs !== undefined
        && proofMs >= connectionVersionMs
        && proofMs <= nowMs
        && nowMs - proofMs <= maximumHealthAgeMs
        && details.connectionId === row.id
        && details.connectionUpdatedAt === row.updated_at
        && details.pathFingerprint === activeVaultPathFingerprint(resolvedPath)
        && row.health_record_hash !== null
        && SHA256.test(row.health_record_hash);
      if (!proofIsCurrent) continue;

      healthVerifiedConnections += 1;
      usableVaults.push(Object.freeze({
        connectionId: row.id,
        compositionSha256: sha256(JSON.stringify({
          connectionId: row.id,
          connectionUpdatedAt: row.updated_at,
          pathFingerprint: details.pathFingerprint,
          proofOccurredAt: row.health_occurred_at,
          proofRecordHash: row.health_record_hash,
        })),
      }));
    }
  }

  usableVaults.sort((left, right) =>
    left.connectionId < right.connectionId
      ? -1
      : left.connectionId > right.connectionId
        ? 1
        : 0);
  const activeVaultSetSha256 = sha256(JSON.stringify(
    usableVaults.map(({ compositionSha256 }) => compositionSha256),
  ));

  return Object.freeze({
    configuredConnections: rows.length,
    activeConnections: activeConnections.length,
    connectedConnections: connectedConnections.length,
    reachableConnections,
    healthVerifiedConnections,
    usableVaults: Object.freeze(usableVaults),
    activeVaultSetSha256,
  });
}

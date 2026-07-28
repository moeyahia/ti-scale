import { getDatabaseHealth, type SqliteDatabase } from "../db";
import { getMemoryControlPolicy, type SecondBrainService } from "../memory";
import {
  readActiveVaultComposition,
  type ActiveVaultCompositionOptions,
} from "../vault/ActiveVaultComposition";
import type { ComponentHealth } from "./RuntimeReadiness";

export interface SecondBrainRuntimeHealth {
  readonly health: ComponentHealth;
  readonly databaseHealthy: boolean;
  readonly canonicalStoreAvailable: boolean;
  readonly lexicalIndexAvailable: boolean;
  readonly lexicalIndexSynchronized: boolean;
  /** Persisted Obsidian projections are optional; canonical memory remains SQLite-owned. */
  readonly vaultProjection: {
    readonly status: "not_configured" | "healthy" | "degraded";
    readonly configuredConnections: number;
    readonly connectedConnections: number;
    readonly reachableConnections: number;
    readonly healthVerifiedConnections: number;
    readonly reason: string;
  };
  readonly reason: string;
}

export interface SecondBrainRuntimeHealthOptions {
  /**
   * Read-only path verifier supplied by the configured Vault sandbox. The
   * health probe deliberately cannot create a directory or run a write test.
   * A connected projection is considered usable only after the normal Vault
   * connection workflow has recorded its round-trip audit receipt.
   */
  readonly resolveExistingVaultPath?: (vaultPath: string) => string;
  /** Deterministic clock seam for bounded persisted health-proof validation. */
  readonly now?: Date;
  readonly maximumVaultHealthAgeMs?: number;
}

/**
 * Mission execution consumes canonical SQLite memory, policy, context, and
 * lexical retrieval. Obsidian is an optional projection and is intentionally
 * excluded from this readiness value.
 */
export function canonicalSecondBrainHealth(
  runtime: SecondBrainRuntimeHealth,
): ComponentHealth {
  if (
    runtime.health === "unhealthy"
    || !runtime.databaseHealthy
    || !runtime.canonicalStoreAvailable
  ) return "unhealthy";
  if (!runtime.lexicalIndexAvailable || !runtime.lexicalIndexSynchronized) {
    return "degraded";
  }
  return "healthy";
}

type VaultProjectionHealth = SecondBrainRuntimeHealth["vaultProjection"];

const NO_VAULT_PROJECTION: VaultProjectionHealth = Object.freeze({
  status: "not_configured",
  configuredConnections: 0,
  connectedConnections: 0,
  reachableConnections: 0,
  healthVerifiedConnections: 0,
  reason: "No Obsidian Vault projection is configured; the canonical Second Brain remains available locally.",
});

const REQUIRED_CANONICAL_TABLES = [
  "memory_nodes",
  "memory_edges",
  "memory_sources",
  "memory_versions",
  "memory_candidates",
  "memory_embeddings",
  "memory_context_packs",
  "memory_context_items",
  "memory_suppressions",
  "preference_profiles",
  "preference_observations",
  "vault_connections",
  "vault_sync_state",
  "vault_conflicts",
  "lessons",
  "lesson_evidence",
  "lesson_usage",
  "settings",
] as const;

const REQUIRED_MEMORY_FTS_TRIGGERS = [
  "memory_nodes_fts_insert",
  "memory_nodes_fts_delete",
  "memory_nodes_fts_update",
] as const;

interface MemoryIndexSentinelRow {
  readonly rowid: number;
  readonly searchable_text: string;
}

const MEMORY_INDEX_BOUNDARY_SAMPLE_SIZE = 4;

function tableNames(database: SqliteDatabase): Set<string> {
  const rows = database.prepare(`
    SELECT name FROM sqlite_master
    WHERE type IN ('table', 'view')
  `).all() as Array<{ readonly name: string }>;
  return new Set(rows.map(({ name }) => name));
}

/**
 * Verify the trigger-maintained FTS path without scanning either canonical
 * memory or the complete FTS index. Runtime health is called by readiness and
 * periodic projections, so a full cardinality comparison can monopolize the
 * SQLite connection for seconds on a large imported Brain.
 *
 * The maintenance triggers protect future writes. A fixed-size sample from
 * both rowid boundaries then proves that the FTS index can resolve real
 * canonical records without a content scan. A complete FTS integrity check
 * remains a diagnostic/maintenance operation and must never run on a live
 * request or projection path.
 */
function lexicalIndexHasBoundedSynchronizationProof(database: SqliteDatabase): boolean {
  const triggers = database.prepare(`
    SELECT name FROM sqlite_master
    WHERE type = 'trigger'
      AND name IN (?, ?, ?)
  `).all(...REQUIRED_MEMORY_FTS_TRIGGERS) as Array<{ readonly name: string }>;
  if (triggers.length !== REQUIRED_MEMORY_FTS_TRIGGERS.length) return false;

  const sentinelSql = `
    SELECT rowid, title || ' ' || summary || ' ' || body AS searchable_text
    FROM memory_nodes
    ORDER BY rowid __DIRECTION__
    LIMIT ?
  `;
  const sentinels = ["ASC", "DESC"]
    .flatMap((direction) => database
      .prepare(sentinelSql.replace("__DIRECTION__", direction))
      .all(MEMORY_INDEX_BOUNDARY_SAMPLE_SIZE) as MemoryIndexSentinelRow[]);

  const checked = new Set<number>();
  for (const sentinel of sentinels) {
    if (checked.has(sentinel.rowid)) continue;
    checked.add(sentinel.rowid);
    const token = sentinel.searchable_text.match(/[A-Za-z0-9]+/)?.[0];
    if (!token) continue;
    const indexed = database.prepare(`
      SELECT rowid FROM memory_nodes_fts
      WHERE memory_nodes_fts MATCH ? AND rowid = ?
      LIMIT 1
    `).get(`"${token}"`, sentinel.rowid) as { readonly rowid: number } | undefined;
    if (indexed?.rowid !== sentinel.rowid) return false;
  }
  return true;
}

function vaultProjectionHealth(
  database: SqliteDatabase,
  options: SecondBrainRuntimeHealthOptions,
): VaultProjectionHealth {
  const compositionOptions: ActiveVaultCompositionOptions = {
    ...(options.resolveExistingVaultPath
      ? { resolveExistingVaultPath: options.resolveExistingVaultPath }
      : {}),
    ...(options.now ? { now: options.now } : {}),
    ...(options.maximumVaultHealthAgeMs !== undefined
      ? { maximumHealthAgeMs: options.maximumVaultHealthAgeMs }
      : {}),
  };
  const composition = readActiveVaultComposition(database, compositionOptions);
  if (composition.configuredConnections === 0) return NO_VAULT_PROJECTION;

  // `disconnected` remains durable read-only history and is excluded from the
  // authoritative active composition.
  const archivedCount =
    composition.configuredConnections - composition.activeConnections;
  const usableConnections = composition.usableVaults.length;
  const projectionReady = usableConnections > 0;
  const archiveSuffix = archivedCount > 0
    ? ` ${archivedCount} disconnected connection${archivedCount === 1 ? " is" : "s are"} retained as read-only history.`
    : "";

  let reason: string;
  let status: VaultProjectionHealth["status"];
  if (composition.activeConnections === 0) {
    status = "not_configured";
    reason = `No active Obsidian Vault projection is configured; ${archivedCount} disconnected connection${archivedCount === 1 ? " remains" : "s remain"} available as read-only history.`;
  } else if (!options.resolveExistingVaultPath) {
    status = "degraded";
    reason = "Active Vault connections exist, but this process has no configured Vault sandbox for read-only path verification.";
  } else if (projectionReady) {
    status = "healthy";
    const attentionCount = composition.activeConnections - usableConnections;
    reason = `${usableConnections} active Obsidian Vault connection${usableConnections === 1 ? " is" : "s are"} connected, reachable, and round-trip verified.${attentionCount > 0
      ? ` ${attentionCount} additional active connection${attentionCount === 1 ? " requires" : "s require"} attention.`
      : ""}${archiveSuffix}`;
  } else if (composition.connectedConnections === 0) {
    status = "degraded";
    reason = "Active Vault connections exist, but none is currently connected.";
  } else if (composition.reachableConnections !== composition.connectedConnections) {
    status = "degraded";
    reason = "At least one connected Vault path is unavailable or outside the configured Vault sandbox.";
  } else if (composition.healthVerifiedConnections !== composition.connectedConnections) {
    status = "degraded";
    reason = "At least one connected Vault is missing a fresh write/read/rename/delete proof bound to its current connection version and path.";
  } else {
    status = "degraded";
    reason = "No active Vault connection has both a reachable path and a persisted round-trip verification receipt.";
  }

  return Object.freeze({
    status,
    configuredConnections: composition.configuredConnections,
    connectedConnections: composition.connectedConnections,
    reachableConnections: composition.reachableConnections,
    healthVerifiedConnections: composition.healthVerifiedConnections,
    reason,
  });
}

function withVaultProjection(
  health: Omit<SecondBrainRuntimeHealth, "vaultProjection">,
  vaultProjection: VaultProjectionHealth,
): SecondBrainRuntimeHealth {
  return { ...health, vaultProjection };
}

/**
 * Reads Second Brain availability from the canonical store that the runtime
 * actually uses. This probe is deliberately read-only and fail-closed:
 * malformed policy or an inaccessible canonical table makes memory
 * unavailable, while a missing/out-of-sync FTS projection is reported as a
 * degraded retrieval path without pretending that durable graph records were
 * lost.
 */
export function getSecondBrainRuntimeHealth(
  database: SqliteDatabase,
  secondBrain: SecondBrainService,
  options: SecondBrainRuntimeHealthOptions = {},
): SecondBrainRuntimeHealth {
  let databaseHealthy = false;
  let vaultProjection = NO_VAULT_PROJECTION;
  try {
    const databaseHealth = getDatabaseHealth(database);
    databaseHealthy = databaseHealth.healthy;
    if (!databaseHealth.healthy) {
      return withVaultProjection({
        health: "unhealthy",
        databaseHealthy: false,
        canonicalStoreAvailable: false,
        lexicalIndexAvailable: false,
        lexicalIndexSynchronized: false,
        reason: "The canonical Ti-Scale database did not pass its integrity and foreign-key checks.",
      }, vaultProjection);
    }

    const tables = tableNames(database);
    const missing = REQUIRED_CANONICAL_TABLES.filter((name) => !tables.has(name));
    if (missing.length > 0) {
      return withVaultProjection({
        health: "unhealthy",
        databaseHealthy: true,
        canonicalStoreAvailable: false,
        lexicalIndexAvailable: tables.has("memory_nodes_fts"),
        lexicalIndexSynchronized: false,
        reason: `The canonical Second Brain schema is incomplete: ${missing.join(", ")}.`,
      }, vaultProjection);
    }

    vaultProjection = vaultProjectionHealth(database, options);

    try {
      // Decoding the operator-owned policy and traversing the public service
      // façade proves the canonical Brain path, not merely table existence.
      getMemoryControlPolicy(database);
      secondBrain.retrieve("", {
        journey: "guided",
        maximumSensitivity: "public",
        allowGlobal: false,
        contextBudget: 0,
        limit: 1,
        graphDepth: 0,
        exactNodeIds: [],
        exactNodeIdsOnly: true,
      });
    } catch {
      return withVaultProjection({
        health: "unhealthy",
        databaseHealthy: true,
        canonicalStoreAvailable: true,
        lexicalIndexAvailable: tables.has("memory_nodes_fts"),
        lexicalIndexSynchronized: false,
        reason: "The canonical Brain store exists, but its policy or context service could not be read safely.",
      }, vaultProjection);
    }

    if (!tables.has("memory_nodes_fts")) {
      return withVaultProjection({
        health: "degraded",
        databaseHealthy: true,
        canonicalStoreAvailable: true,
        lexicalIndexAvailable: false,
        lexicalIndexSynchronized: false,
        reason: "Canonical Brain records are available, but the local lexical index is unavailable.",
      }, vaultProjection);
    }

    try {
      if (!lexicalIndexHasBoundedSynchronizationProof(database)) {
        return withVaultProjection({
          health: "degraded",
          databaseHealthy: true,
          canonicalStoreAvailable: true,
          lexicalIndexAvailable: true,
          lexicalIndexSynchronized: false,
          reason: "Canonical Brain records are available, but the lexical index maintenance or sampled synchronization proof failed.",
        }, vaultProjection);
      }
    } catch {
      return withVaultProjection({
        health: "degraded",
        databaseHealthy: true,
        canonicalStoreAvailable: true,
        lexicalIndexAvailable: false,
        lexicalIndexSynchronized: false,
        reason: "Canonical Brain records are available, but the local lexical index could not be queried.",
      }, vaultProjection);
    }

    return withVaultProjection({
      health: vaultProjection.status === "degraded" ? "degraded" : "healthy",
      databaseHealthy: true,
      canonicalStoreAvailable: true,
      lexicalIndexAvailable: true,
      lexicalIndexSynchronized: true,
      reason: vaultProjection.status === "degraded"
        ? `The canonical Second Brain is available, but its Obsidian projection is degraded. ${vaultProjection.reason}`
        : "The canonical Second Brain graph, policy, context service, and local lexical index are available.",
    }, vaultProjection);
  } catch {
    return withVaultProjection({
      health: "unhealthy",
      databaseHealthy,
      canonicalStoreAvailable: false,
      lexicalIndexAvailable: false,
      lexicalIndexSynchronized: false,
      reason: "The canonical Second Brain health probe failed closed.",
    }, vaultProjection);
  }
}

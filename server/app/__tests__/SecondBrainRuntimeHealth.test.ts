import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository, SecondBrainService } from "../../memory";
import {
  canonicalSecondBrainHealth,
  getSecondBrainRuntimeHealth,
} from "../SecondBrainRuntimeHealth";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-brain-health-"));
  temporaryDirectories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "ti-scale.sqlite") });
  migrateDatabase(database);
  const secondBrain = new SecondBrainService(new MemoryRepository(database));
  return { database, secondBrain };
}

function healthProofDetails(
  connectionId: string,
  resolvedPath: string,
  connectionUpdatedAt: string,
  overrides: {
    readonly checks?: Record<string, boolean>;
    readonly pathFingerprint?: string;
    readonly connectionUpdatedAt?: string;
  } = {},
): string {
  return JSON.stringify({
    connectionId,
    connectionUpdatedAt: overrides.connectionUpdatedAt ?? connectionUpdatedAt,
    pathFingerprint: overrides.pathFingerprint ?? createHash("sha256")
      .update(`vault-path:${resolvedPath}`, "utf8")
      .digest("hex"),
    checks: overrides.checks ?? {
      write: true,
      read: true,
      rename: true,
      delete: true,
    },
  });
}

function seedConnectedVault(
  database: ReturnType<typeof fixture>["database"],
  input: {
    readonly id: string;
    readonly path: string;
    readonly updatedAt: string;
    readonly proofAt: string;
    readonly details?: string;
  },
): void {
  database.prepare(`
    INSERT INTO vault_connections (
      id, vault_path, display_name, status, sync_scope_json,
      permission_granted_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'connected', '{}', ?, ?, ?)
  `).run(
    input.id,
    input.path,
    input.id,
    input.updatedAt,
    input.updatedAt,
    input.updatedAt,
  );
  database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id,
      reason, details_json, record_hash, occurred_at
    ) VALUES (?, 'operator', 'operator', 'vault.health.verified',
      'vault_connection', ?, 'Round trip passed', ?, ?, ?)
  `).run(
    `audit-${input.id}`,
    input.id,
    input.details ?? healthProofDetails(input.id, input.path, input.updatedAt),
    createHash("sha256").update(`proof:${input.id}`).digest("hex"),
    input.proofAt,
  );
}

describe("canonical Second Brain runtime health", () => {
  test("reports healthy only after the canonical graph, policy, service, and FTS path are queryable", () => {
    const { database, secondBrain } = fixture();
    expect(getSecondBrainRuntimeHealth(database, secondBrain)).toEqual({
      health: "healthy",
      databaseHealthy: true,
      canonicalStoreAvailable: true,
      lexicalIndexAvailable: true,
      lexicalIndexSynchronized: true,
      vaultProjection: {
        status: "not_configured",
        configuredConnections: 0,
        connectedConnections: 0,
        reachableConnections: 0,
        healthVerifiedConnections: 0,
        reason: "No Obsidian Vault projection is configured; the canonical Second Brain remains available locally.",
      },
      reason: "The canonical Second Brain graph, policy, context service, and local lexical index are available.",
    });
    database.close();
  });

  test("reports a persisted, reachable, round-trip-verified Obsidian projection without exposing its path", () => {
    const { database, secondBrain } = fixture();
    const vaultPath = "/var/lib/ti-scale/vaults/Ti-Scale-Brain";
    database.prepare(`
      INSERT INTO vault_connections (
        id, vault_path, display_name, status, sync_scope_json,
        permission_granted_at, created_at, updated_at
      ) VALUES (?, ?, 'Primary Brain', 'connected', '{}', ?, ?, ?)
    `).run(
      "vault-primary",
      vaultPath,
      "2026-07-18T18:00:00.000Z",
      "2026-07-18T18:00:00.000Z",
      "2026-07-18T18:00:00.000Z",
    );
    database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id,
        reason, details_json, record_hash, occurred_at
      ) VALUES (?, 'operator', 'operator', 'vault.health.verified',
        'vault_connection', ?, 'Round trip passed', ?, ?, ?)
    `).run(
      "audit-vault-health",
      "vault-primary",
      healthProofDetails(
        "vault-primary",
        vaultPath,
        "2026-07-18T18:00:00.000Z",
      ),
      "a".repeat(64),
      "2026-07-18T18:01:00.000Z",
    );

    const health = getSecondBrainRuntimeHealth(database, secondBrain, {
      now: new Date("2026-07-18T18:02:00.000Z"),
      resolveExistingVaultPath(path) {
        expect(path).toBe(vaultPath);
        return path;
      },
    });
    expect(health).toMatchObject({
      health: "healthy",
      vaultProjection: {
        status: "healthy",
        configuredConnections: 1,
        connectedConnections: 1,
        reachableConnections: 1,
        healthVerifiedConnections: 1,
      },
    });
    expect(JSON.stringify(health)).not.toContain(vaultPath);
    database.close();
  });

  test("keeps a verified active projection healthy while retaining disconnected Vault history", () => {
    const { database, secondBrain } = fixture();
    const activePath = "/var/lib/ti-scale/vaults/Attack-Knowledge-Vault";
    database.prepare(`
      INSERT INTO vault_connections (
        id, vault_path, display_name, status, sync_scope_json,
        permission_granted_at, created_at, updated_at
      ) VALUES
        ('vault-active', ?, 'Attack Knowledge Vault', 'connected', '{}', ?, ?, ?),
        ('vault-archived', '/var/lib/ti-scale/vaults/Legacy-Brain', 'Legacy Brain', 'disconnected', '{}', ?, ?, ?)
    `).run(
      activePath,
      "2026-07-20T20:00:00.000Z",
      "2026-07-20T20:00:00.000Z",
      "2026-07-20T20:00:00.000Z",
      "2026-07-19T20:00:00.000Z",
      "2026-07-19T20:00:00.000Z",
      "2026-07-20T19:00:00.000Z",
    );
    database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id,
        reason, details_json, record_hash, occurred_at
      ) VALUES ('audit-vault-active', 'operator', 'operator', 'vault.health.verified',
        'vault_connection', 'vault-active', 'Round trip passed', ?, ?, ?)
    `).run(
      healthProofDetails(
        "vault-active",
        activePath,
        "2026-07-20T20:00:00.000Z",
      ),
      "c".repeat(64),
      "2026-07-20T20:01:00.000Z",
    );

    const resolved: string[] = [];
    const health = getSecondBrainRuntimeHealth(database, secondBrain, {
      now: new Date("2026-07-20T20:02:00.000Z"),
      resolveExistingVaultPath(path) {
        resolved.push(path);
        return path;
      },
    });
    expect(health).toMatchObject({
      health: "healthy",
      vaultProjection: {
        status: "healthy",
        configuredConnections: 2,
        connectedConnections: 1,
        reachableConnections: 1,
        healthVerifiedConnections: 1,
      },
    });
    expect(resolved).toEqual([activePath]);
    expect(health.vaultProjection.reason).toContain("1 disconnected connection is retained as read-only history");
    database.close();
  });

  test("treats disconnected-only Vault records as archived history rather than degraded runtime", () => {
    const { database, secondBrain } = fixture();
    database.prepare(`
      INSERT INTO vault_connections (
        id, vault_path, display_name, status, sync_scope_json,
        permission_granted_at, created_at, updated_at
      ) VALUES ('vault-archived', '/var/lib/ti-scale/vaults/Legacy-Brain',
        'Legacy Brain', 'disconnected', '{}', ?, ?, ?)
    `).run(
      "2026-07-19T20:00:00.000Z",
      "2026-07-19T20:00:00.000Z",
      "2026-07-20T19:00:00.000Z",
    );

    const health = getSecondBrainRuntimeHealth(database, secondBrain, {
      resolveExistingVaultPath() {
        throw new Error("An archived Vault must not be probed");
      },
    });
    expect(health).toMatchObject({
      health: "healthy",
      vaultProjection: {
        status: "not_configured",
        configuredConnections: 1,
        connectedConnections: 0,
        reachableConnections: 0,
        healthVerifiedConnections: 0,
      },
    });
    expect(health.vaultProjection.reason).toContain("available as read-only history");
    database.close();
  });

  test("separates canonical mission readiness from an unavailable optional Vault projection", () => {
    const { database, secondBrain } = fixture();
    database.prepare(`
      INSERT INTO vault_connections (
        id, vault_path, display_name, status, sync_scope_json,
        permission_granted_at, created_at, updated_at
      ) VALUES ('vault-offline', '/configured/vault', 'Offline Brain', 'connected', '{}', ?, ?, ?)
    `).run(
      "2026-07-18T18:00:00.000Z",
      "2026-07-18T18:00:00.000Z",
      "2026-07-18T18:00:00.000Z",
    );
    database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, action, resource_type, resource_id,
        details_json, record_hash, occurred_at
      ) VALUES ('audit-vault-offline', 'operator', 'vault.health.verified',
        'vault_connection', 'vault-offline', ?, ?, ?)
    `).run(
      healthProofDetails(
        "vault-offline",
        "/configured/vault",
        "2026-07-18T18:00:00.000Z",
      ),
      "b".repeat(64),
      "2026-07-18T18:01:00.000Z",
    );

    const health = getSecondBrainRuntimeHealth(database, secondBrain, {
      now: new Date("2026-07-18T18:02:00.000Z"),
      resolveExistingVaultPath() {
        throw new Error("offline fixture");
      },
    });
    expect(health).toMatchObject({
      health: "degraded",
      canonicalStoreAvailable: true,
      lexicalIndexSynchronized: true,
      vaultProjection: {
        status: "degraded",
        configuredConnections: 1,
        connectedConnections: 1,
        reachableConnections: 0,
        healthVerifiedConnections: 0,
      },
    });
    expect(canonicalSecondBrainHealth(health)).toBe("healthy");
    expect(health.reason).toContain("Obsidian projection is degraded");
    expect(health.vaultProjection.reason).toContain("unavailable or outside");
    database.close();
  });

  test("rejects a path or connection version changed after its proof", () => {
    const { database, secondBrain } = fixture();
    seedConnectedVault(database, {
      id: "vault-changed",
      path: "/vault/original",
      updatedAt: "2026-07-22T10:00:00.000Z",
      proofAt: "2026-07-22T10:01:00.000Z",
    });
    database.prepare(`
      UPDATE vault_connections
      SET vault_path = '/vault/replaced', updated_at = '2026-07-22T10:01:30.000Z'
      WHERE id = 'vault-changed'
    `).run();

    const health = getSecondBrainRuntimeHealth(database, secondBrain, {
      now: new Date("2026-07-22T10:02:00.000Z"),
      resolveExistingVaultPath(path) {
        return path;
      },
    });
    expect(health.vaultProjection).toMatchObject({
      status: "degraded",
      reachableConnections: 1,
      healthVerifiedConnections: 0,
    });
    expect(health.vaultProjection.reason).toContain("current connection version and path");
    database.close();
  });

  test("rejects stale and future-dated health proofs", () => {
    const cases = [
      {
        id: "vault-stale",
        path: "/vault/stale",
        updatedAt: "2026-07-22T09:00:00.000Z",
        proofAt: "2026-07-22T09:01:00.000Z",
      },
      {
        id: "vault-future",
        path: "/vault/future",
        updatedAt: "2026-07-22T10:03:00.000Z",
        proofAt: "2026-07-22T10:03:00.000Z",
      },
    ] as const;
    for (const input of cases) {
      const { database, secondBrain } = fixture();
      seedConnectedVault(database, input);
      const health = getSecondBrainRuntimeHealth(database, secondBrain, {
        now: new Date("2026-07-22T10:02:00.000Z"),
        maximumVaultHealthAgeMs: 5 * 60_000,
        resolveExistingVaultPath(path) {
          return path;
        },
      });
      expect(health.vaultProjection).toMatchObject({
        status: "degraded",
        healthVerifiedConnections: 0,
      });
      database.close();
    }
  });

  test("requires every exact round-trip check and rejects missing proof fields", () => {
    const cases = [
      {
        id: "vault-false-check",
        path: "/vault/false-check",
        details: healthProofDetails(
          "vault-false-check",
          "/vault/false-check",
          "2026-07-22T10:00:00.000Z",
          { checks: { write: true, read: true, rename: false, delete: true } },
        ),
      },
      {
        id: "vault-missing-checks",
        path: "/vault/missing-checks",
        details: JSON.stringify({
          connectionId: "vault-missing-checks",
          connectionUpdatedAt: "2026-07-22T10:00:00.000Z",
          pathFingerprint: "d".repeat(64),
        }),
      },
    ] as const;
    for (const input of cases) {
      const { database, secondBrain } = fixture();
      seedConnectedVault(database, {
        ...input,
        updatedAt: "2026-07-22T10:00:00.000Z",
        proofAt: "2026-07-22T10:01:00.000Z",
      });
      const health = getSecondBrainRuntimeHealth(database, secondBrain, {
        now: new Date("2026-07-22T10:02:00.000Z"),
        resolveExistingVaultPath(path) {
          return path;
        },
      });
      expect(health.vaultProjection.healthVerifiedConnections).toBe(0);
      database.close();
    }
  });

  test("keeps a mixed set usable while excluding an unreachable Vault", () => {
    const { database, secondBrain } = fixture();
    seedConnectedVault(database, {
      id: "vault-healthy",
      path: "/vault/healthy",
      updatedAt: "2026-07-22T10:00:00.000Z",
      proofAt: "2026-07-22T10:01:00.000Z",
    });
    seedConnectedVault(database, {
      id: "vault-removed",
      path: "/vault/removed",
      updatedAt: "2026-07-22T10:00:00.000Z",
      proofAt: "2026-07-22T10:01:00.000Z",
    });

    const health = getSecondBrainRuntimeHealth(database, secondBrain, {
      now: new Date("2026-07-22T10:02:00.000Z"),
      resolveExistingVaultPath(path) {
        if (path.endsWith("/removed")) throw new Error("removed");
        return path;
      },
    });
    expect(health.vaultProjection).toMatchObject({
      status: "healthy",
      connectedConnections: 2,
      reachableConnections: 1,
      healthVerifiedConnections: 1,
    });
    expect(health.vaultProjection.reason).toContain(
      "1 additional active connection requires attention",
    );
    database.close();
  });

  test("reports degraded when durable Brain records remain available but FTS is unavailable", () => {
    const { database, secondBrain } = fixture();
    database.exec("DROP TABLE memory_nodes_fts");
    const health = getSecondBrainRuntimeHealth(database, secondBrain);
    expect(health).toMatchObject({
      health: "degraded",
      databaseHealthy: true,
      canonicalStoreAvailable: true,
      lexicalIndexAvailable: false,
      lexicalIndexSynchronized: false,
    });
    expect(health.reason).toContain("lexical index is unavailable");
    expect(canonicalSecondBrainHealth(health)).toBe("degraded");
    database.close();
  });

  test("fails the bounded synchronization proof when an FTS maintenance trigger is missing", () => {
    const { database, secondBrain } = fixture();
    database.exec("DROP TRIGGER memory_nodes_fts_insert");
    const health = getSecondBrainRuntimeHealth(database, secondBrain);
    expect(health).toMatchObject({
      health: "degraded",
      databaseHealthy: true,
      canonicalStoreAvailable: true,
      lexicalIndexAvailable: true,
      lexicalIndexSynchronized: false,
    });
    expect(health.reason).toContain("sampled synchronization proof failed");
    expect(canonicalSecondBrainHealth(health)).toBe("degraded");
    database.close();
  });

  test("fails the bounded synchronization proof when a canonical boundary row is absent from FTS", () => {
    const { database, secondBrain } = fixture();
    secondBrain.repository.createNode({
      id: "mem_brain_health_sentinel",
      nodeType: "source",
      title: "Titanium lexical sentinel",
      summary: "A deterministic searchable health fixture.",
      body: "This record proves the bounded lexical lookup path.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "confirmed",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "Created by the runtime health boundary test.",
        sources: [{
          sourceType: "operator_note",
          sourceId: "brain-health-test-source",
          acquiredAt: "2026-07-22T00:00:00.000Z",
        }],
      },
      authorType: "operator",
      authorId: "operator:test",
    });
    database.prepare(`
      INSERT INTO memory_nodes_fts(memory_nodes_fts, rowid, title, summary, body)
      SELECT 'delete', rowid, title, summary, body
      FROM memory_nodes WHERE id = ?
    `).run("mem_brain_health_sentinel");

    const health = getSecondBrainRuntimeHealth(database, secondBrain);
    expect(health).toMatchObject({
      health: "degraded",
      lexicalIndexAvailable: true,
      lexicalIndexSynchronized: false,
    });
    expect(health.reason).toContain("sampled synchronization proof failed");
    database.close();
  });

  test("fails closed when the canonical Brain policy cannot be decoded", () => {
    const { database, secondBrain } = fixture();
    database.prepare(`
      INSERT INTO settings (key, value_json, sensitivity, version, updated_by, updated_at)
      VALUES ('memory.control.global', '{}', 'private', 1, 'test', '2026-07-18T18:00:00.000Z')
    `).run();
    const health = getSecondBrainRuntimeHealth(database, secondBrain);
    expect(health).toMatchObject({
      health: "unhealthy",
      databaseHealthy: true,
      canonicalStoreAvailable: true,
      lexicalIndexSynchronized: false,
    });
    expect(health.reason).toContain("policy or context service could not be read safely");
    expect(canonicalSecondBrainHealth(health)).toBe("unhealthy");
    database.close();
  });
});

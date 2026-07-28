import { afterEach, describe, expect, test } from "bun:test";
import { EventEmitter } from "node:events";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  type FSWatcher,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import { readActiveVaultComposition } from "../ActiveVaultComposition";
import { ObsidianVaultBridge } from "../ObsidianVaultBridge";
import { ObsidianVaultWatcher } from "../ObsidianVaultWatcher";
import { VaultPathPolicy } from "../VaultPathPolicy";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "active-vault-health-"));
  temporaryDirectories.push(directory);
  const database = createDatabaseConnection({
    filename: join(directory, "brain.sqlite"),
  });
  migrateDatabase(database);
  let nowMs = Date.parse("2026-07-24T12:00:00.000Z");
  const clock = () => new Date(nowMs);
  const memory = new MemoryRepository(database, { clock });
  const paths = new VaultPathPolicy(join(directory, "vaults"));
  const bridge = new ObsidianVaultBridge(database, memory, paths, { clock });
  const connection = bridge.connect({
    id: "vault-active-health",
    vaultPath: "Attack-Knowledge-Vault",
    displayName: "Attack Knowledge Vault",
    permissionGranted: true,
  });
  return {
    database,
    memory,
    paths,
    bridge,
    connection,
    now: () => new Date(nowMs),
    nowMs: () => nowMs,
    advance(milliseconds: number) {
      nowMs += milliseconds;
    },
  };
}

describe("active Vault health-proof lifecycle", () => {
  test("keeps sync activity separate from the connection configuration version", () => {
    const value = fixture();
    try {
      const initialVersion = value.connection.updatedAt;
      value.advance(60_000);
      const proof = value.bridge.refreshConnectionHealthProof(
        value.connection.id,
      );
      expect(proof.connectionUpdatedAt).toBe(initialVersion);

      const node = value.memory.createNode({
        id: `mem_${"a".repeat(64)}`,
        nodeType: "attack_procedure",
        title: "Bounded service validation",
        summary: "Validate one exact service behavior.",
        body: "Retain the exact current evidence and bounded result.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 1,
        lifecycleStatus: "verified",
        confirmationState: "confirmed",
        provenance: {
          method: "operator_statement",
          explanation: "Reviewed by the local operator.",
          sources: [{
            sourceType: "operator_note",
            sourceId: "source-active-vault-health",
            acquiredAt: value.now().toISOString(),
          }],
        },
        authorType: "operator",
        authorId: "operator-test",
      });
      value.advance(60_000);
      const exported = value.bridge.exportNode(value.connection.id, node.id);
      expect(readFileSync(
        join(value.connection.vaultPath, exported.relativePath),
        "utf8",
      )).toContain("Bounded service validation");

      const current = value.bridge.requireConnection(value.connection.id);
      expect(current.updatedAt).toBe(initialVersion);
      expect(current.lastSyncAt).toBe(value.now().toISOString());
      expect(readActiveVaultComposition(value.database, {
        now: value.now(),
        resolveExistingVaultPath: (path) =>
          value.paths.resolveExistingVault(path),
      }).usableVaults).toHaveLength(1);

      value.bridge.markConnectionHealth(value.connection.id, "degraded");
      value.bridge.markConnectionHealth(value.connection.id, "connected");
      expect(value.bridge.requireConnection(value.connection.id).updatedAt)
        .toBe(initialVersion);
    } finally {
      value.database.close();
    }
  });

  test("watcher renews a true proof before expiry and restores an expired receipt", async () => {
    const value = fixture();
    const fake = new EventEmitter() as EventEmitter & {
      close: () => void;
      closed: boolean;
    };
    fake.closed = false;
    fake.close = () => {
      fake.closed = true;
    };
    const watcher = new ObsidianVaultWatcher(
      value.database,
      value.bridge,
      {
        connectionRefreshMs: 300_000,
        healthProofRefreshMs: 4 * 60_000,
        clock: value.nowMs,
        watchFactory: () => fake as unknown as FSWatcher,
      },
    );
    try {
      watcher.start();
      expect(value.database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'vault.health.verified'
          AND resource_id = ?
      `).get(value.connection.id)).toEqual({ count: 1 });

      value.advance(3 * 60_000);
      watcher.refreshHealthProofs([value.connection.id]);
      expect(value.database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'vault.health.verified'
          AND resource_id = ?
      `).get(value.connection.id)).toEqual({ count: 1 });

      value.advance((2 * 60_000) + 1);
      expect(readActiveVaultComposition(value.database, {
        now: value.now(),
        resolveExistingVaultPath: (path) =>
          value.paths.resolveExistingVault(path),
      }).usableVaults).toHaveLength(0);

      watcher.refreshHealthProofs([value.connection.id]);
      expect(readActiveVaultComposition(value.database, {
        now: value.now(),
        resolveExistingVaultPath: (path) =>
          value.paths.resolveExistingVault(path),
      }).usableVaults).toHaveLength(1);
      expect(value.database.prepare(`
        SELECT COUNT(*) AS count FROM audit_records
        WHERE action = 'vault.health.verified'
          AND resource_id = ?
      `).get(value.connection.id)).toEqual({ count: 2 });

      const latest = value.database.prepare(`
        SELECT details_json FROM audit_records
        WHERE action = 'vault.health.verified'
          AND resource_id = ?
        ORDER BY occurred_at DESC, rowid DESC LIMIT 1
      `).get(value.connection.id) as { readonly details_json: string };
      expect(JSON.parse(latest.details_json)).toEqual({
        connectionId: value.connection.id,
        connectionUpdatedAt: value.connection.updatedAt,
        pathFingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
        checks: {
          write: true,
          read: true,
          rename: true,
          delete: true,
        },
      });
    } finally {
      await watcher.stop();
      value.database.close();
    }
  });

  test("marks a removed configured path degraded without trying to recreate it", async () => {
    const value = fixture();
    rmSync(value.connection.vaultPath, { recursive: true, force: true });
    const errors: Error[] = [];
    const watcher = new ObsidianVaultWatcher(
      value.database,
      value.bridge,
      {
        clock: value.nowMs,
        onError(error) {
          errors.push(error);
        },
        watchFactory: () => {
          throw new Error("A removed path must not be watched");
        },
      },
    );
    try {
      expect(() => watcher.start()).not.toThrow();
      const state = value.database.prepare(`
        SELECT status, updated_at FROM vault_connections WHERE id = ?
      `).get(value.connection.id);
      expect(state).toEqual({
        status: "degraded",
        updated_at: value.connection.updatedAt,
      });
      expect(errors.length).toBeGreaterThan(0);
    } finally {
      await watcher.stop();
      value.database.close();
    }
  });

  test("queued sync cannot reactivate a degraded Vault recreated at the same path", async () => {
    const value = fixture();
    const node = value.memory.createNode({
      id: `mem_${"b".repeat(64)}`,
      nodeType: "attack_procedure",
      title: "Exact health-gated procedure",
      summary: "One queued note must not restore Vault health.",
      body: "Original operator-reviewed procedure.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      lifecycleStatus: "verified",
      confirmationState: "confirmed",
      provenance: {
        method: "operator_statement",
        explanation: "Reviewed by the local operator.",
        sources: [{
          sourceType: "operator_note",
          sourceId: "source-recreated-vault",
          acquiredAt: value.now().toISOString(),
        }],
      },
      authorType: "operator",
      authorId: "operator-test",
    });
    const exported = value.bridge.exportNode(value.connection.id, node.id);
    value.bridge.refreshConnectionHealthProof(value.connection.id);
    const originalPath = join(
      value.connection.vaultPath,
      exported.relativePath,
    );
    const editedText = readFileSync(originalPath, "utf8").replace(
      "Original operator-reviewed procedure.",
      "Operator edit queued after the path was recreated.",
    );
    const configurationVersion = value.bridge.requireConnection(
      value.connection.id,
    ).updatedAt;

    rmSync(value.connection.vaultPath, { recursive: true, force: true });
    const missingWatcher = new ObsidianVaultWatcher(
      value.database,
      value.bridge,
      {
        clock: value.nowMs,
        watchFactory: () => {
          throw new Error("Removed Vault must not be watched");
        },
      },
    );
    try {
      missingWatcher.start();
      expect(value.database.prepare(`
        SELECT status FROM vault_connections WHERE id = ?
      `).get(value.connection.id)).toEqual({ status: "degraded" });
    } finally {
      await missingWatcher.stop();
    }

    mkdirSync(dirname(originalPath), { recursive: true });
    writeFileSync(originalPath, editedText, "utf8");
    const fake = new EventEmitter() as EventEmitter & {
      close: () => void;
    };
    fake.close = () => undefined;
    let listener:
      | ((eventType: string, filename: string | Buffer | null) => void)
      | undefined;
    const recreatedWatcher = new ObsidianVaultWatcher(
      value.database,
      value.bridge,
      {
        debounceMs: 10,
        yieldMs: 0,
        clock: value.nowMs,
        watchFactory: (_root, callback) => {
          listener = callback;
          return fake as unknown as FSWatcher;
        },
      },
    );
    try {
      recreatedWatcher.start();
      listener?.("change", exported.relativePath);
      await new Promise((resolve) => setTimeout(resolve, 30));
      await recreatedWatcher.waitForIdle();

      expect(value.memory.requireNode(node.id).body)
        .toContain("queued after the path was recreated");
      const connection = value.bridge.requireExistingConnection(
        value.connection.id,
      );
      expect(connection.status).toBe("degraded");
      expect(connection.updatedAt).toBe(configurationVersion);
      expect(readActiveVaultComposition(value.database, {
        now: value.now(),
        resolveExistingVaultPath: (path) =>
          value.paths.resolveExistingVault(path),
      }).usableVaults).toHaveLength(0);
    } finally {
      await recreatedWatcher.stop();
      value.database.close();
    }
  });
});

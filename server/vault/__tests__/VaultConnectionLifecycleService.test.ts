import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory/MemoryRepository";
import { ObsidianVaultBridge } from "../ObsidianVaultBridge";
import {
  VaultConnectionLifecycleService,
  VaultConnectionVersionConflictError,
  VaultLastHealthyConnectionError,
} from "../VaultConnectionLifecycleService";
import { VaultPathPolicy } from "../VaultPathPolicy";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function snapshotFiles(root: string): Record<string, string> {
  const result: Record<string, string> = {};
  const visit = (path: string): void => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) visit(child);
      else if (entry.isFile()) {
        result[relative(root, child)] = createHash("sha256").update(readFileSync(child)).digest("hex");
      }
    }
  };
  visit(root);
  return result;
}

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "vault-lifecycle-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  const root = join(directory, "vaults");
  const bridge = new ObsidianVaultBridge(
    database,
    new MemoryRepository(database),
    new VaultPathPolicy(root),
  );
  const old = bridge.connect({
    id: "vault-old",
    vaultPath: "Ti-Scale-Brain",
    displayName: "Ti-Scale Brain",
    permissionGranted: true,
  });
  writeFileSync(join(old.vaultPath, "operator-note.md"), "# Operator note\n\nPreserve these exact bytes.\n", { mode: 0o600 });
  return { database, root, bridge, old };
}

function recordHealth(
  database: ReturnType<typeof createDatabaseConnection>,
  connectionId: string,
  sequence: number,
) {
  database.prepare(`
    INSERT INTO audit_records (
      id, actor_type, actor_id, action, resource_type, resource_id, reason,
      details_json, previous_hash, record_hash, occurred_at
    ) VALUES (?, 'operator', 'operator-test', 'vault.health.verified',
      'vault_connection', ?, 'Round trip passed', '{}', NULL, ?, ?)
  `).run(
    `audit-health-${sequence}`,
    connectionId,
    createHash("sha256").update(`health-${sequence}`).digest("hex"),
    `2026-07-20T18:0${sequence}:00.000Z`,
  );
}

describe("VaultConnectionLifecycleService", () => {
  test("disconnects metadata only when a health-verified replacement remains", () => {
    const fixtureState = fixture();
    try {
      const replacement = fixtureState.bridge.connect({
        id: "vault-attack-knowledge",
        vaultPath: "Attack-Knowledge-Vault",
        displayName: "Ti-Scale Attack Knowledge Vault",
        permissionGranted: true,
      });
      recordHealth(fixtureState.database, fixtureState.old.id, 1);
      recordHealth(fixtureState.database, replacement.id, 2);
      fixtureState.database.prepare(`
        INSERT INTO missions (
          id, name, objective, journey, status, authorization_status, created_by,
          created_at, updated_at
        ) VALUES ('mission-active', 'Active mission', 'Use canonical memory safely',
          'guided', 'active', 'verified', 'operator-test', ?, ?)
      `).run("2026-07-20T18:03:00.000Z", "2026-07-20T18:03:00.000Z");
      fixtureState.database.prepare(`
        INSERT INTO runs (id, mission_id, journey, status, created_at, updated_at)
        VALUES ('run-active', 'mission-active', 'guided', 'running', ?, ?)
      `).run("2026-07-20T18:03:00.000Z", "2026-07-20T18:03:00.000Z");
      const before = snapshotFiles(fixtureState.root);
      const service = new VaultConnectionLifecycleService(fixtureState.database, fixtureState.bridge, {
        clock: () => new Date("2026-07-20T18:04:00.000Z"),
      });

      const result = service.disconnect({
        connectionId: fixtureState.old.id,
        expectedUpdatedAt: fixtureState.old.updatedAt,
        allowProjectionDegraded: false,
      });

      expect(result).toMatchObject({
        previousStatus: "connected",
        projectionState: "healthy",
        replacementConnectionId: replacement.id,
        activeRunCount: 1,
        activeRunImpact: "canonical_brain_unaffected",
        syncStopped: true,
        filesDeleted: 0,
        notesRewritten: 0,
        connection: { id: fixtureState.old.id, status: "disconnected" },
      });
      expect(snapshotFiles(fixtureState.root)).toEqual(before);
      expect(() => fixtureState.bridge.requireConnection(fixtureState.old.id)).toThrow("disconnected");
      expect(() => fixtureState.bridge.recoverQuarantineIntents(fixtureState.old.id)).toThrow("disconnected");
      expect(fixtureState.bridge.requireConnection(replacement.id).status).toBe("connected");
    } finally {
      fixtureState.database.close();
    }
  });

  test("requires controlled-degraded acknowledgement for the last healthy projection", () => {
    const fixtureState = fixture();
    try {
      recordHealth(fixtureState.database, fixtureState.old.id, 1);
      const service = new VaultConnectionLifecycleService(fixtureState.database, fixtureState.bridge);
      expect(() => service.disconnect({
        connectionId: fixtureState.old.id,
        expectedUpdatedAt: fixtureState.old.updatedAt,
        allowProjectionDegraded: false,
      })).toThrow(VaultLastHealthyConnectionError);
      expect(fixtureState.bridge.requireConnection(fixtureState.old.id).status).toBe("connected");

      const result = service.disconnect({
        connectionId: fixtureState.old.id,
        expectedUpdatedAt: fixtureState.old.updatedAt,
        allowProjectionDegraded: true,
      });
      expect(result.projectionState).toBe("degraded");
      expect(result.connection.status).toBe("disconnected");
    } finally {
      fixtureState.database.close();
    }
  });

  test("rejects a stale connection version without changing status", () => {
    const fixtureState = fixture();
    try {
      const service = new VaultConnectionLifecycleService(fixtureState.database, fixtureState.bridge);
      expect(() => service.disconnect({
        connectionId: fixtureState.old.id,
        expectedUpdatedAt: "2026-07-19T00:00:00.000Z",
        allowProjectionDegraded: true,
      })).toThrow(VaultConnectionVersionConflictError);
      expect(fixtureState.bridge.requireConnection(fixtureState.old.id).status).toBe("connected");
    } finally {
      fixtureState.database.close();
    }
  });
});

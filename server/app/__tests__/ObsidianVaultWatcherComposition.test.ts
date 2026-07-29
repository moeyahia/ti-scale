import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  type FSWatcher,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository, updateMemoryControlPolicy } from "../../memory";
import { ObsidianVaultBridge, VaultPathPolicy } from "../../vault";
import {
  createProductionObsidianVaultWatcher,
} from "../ObsidianVaultWatcherComposition";

interface FakeWatch {
  readonly watcher: FSWatcher;
  readonly emitChange: (relativePath: string) => void;
  readonly closed: () => boolean;
  readonly capture: (
    callback: (eventType: string, filename: string | Buffer | null) => void,
  ) => void;
}

function fakeWatch(): FakeWatch {
  const emitter = new EventEmitter();
  let listener: ((eventType: string, filename: string | Buffer | null) => void) | undefined;
  let isClosed = false;
  const watcher = emitter as EventEmitter & { close(): void };
  watcher.close = () => { isClosed = true; };
  return {
    watcher: watcher as unknown as FSWatcher,
    emitChange: (relativePath) => listener?.("change", relativePath),
    closed: () => isClosed,
    capture(callback) { listener = callback; },
  };
}

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-vault-watcher-composition-"));
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  const memory = new MemoryRepository(database);
  const bridge = new ObsidianVaultBridge(
    database,
    memory,
    new VaultPathPolicy(join(directory, "vaults")),
  );
  const connection = bridge.connect({
    id: "vault-production-composition",
    vaultPath: "Operator-Brain",
    displayName: "Operator Brain",
    syncScope: {},
    permissionGranted: true,
  });
  return { directory, database, memory, bridge, connection };
}

function createTechnique(memory: MemoryRepository) {
  const id = `mem_${createHash("sha256").update("production-watcher-technique").digest("hex")}`;
  return memory.createNode({
    id,
    nodeType: "attack_technique",
    title: "Bounded endpoint discovery",
    summary: "A reviewed endpoint-discovery technique.",
    body: "Use the reviewed initial endpoint procedure.",
    scope: { kind: "global" },
    sensitivity: "private",
    confidence: 0.98,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: {
      method: "operator_statement",
      explanation: "Confirmed in the production-composition fixture",
      sources: [{
        sourceType: "message",
        sourceId: "watcher-composition-source",
        acquiredAt: "2026-07-22T10:00:00.000Z",
      }],
    },
    authorType: "operator",
    authorId: "operator:test",
  });
}

describe("production Obsidian Vault watcher composition", () => {
  test("does not compose without an explicit Vault bridge and watches neither disconnected nor policy-disabled Vaults", async () => {
    const value = fixture();
    try {
      expect(createProductionObsidianVaultWatcher({ database: value.database })).toBeUndefined();

      value.database.prepare(`
        UPDATE vault_connections SET status = 'disconnected' WHERE id = ?
      `).run(value.connection.id);
      let disconnectedFactoryCalls = 0;
      const disconnected = createProductionObsidianVaultWatcher({
        database: value.database,
        bridge: value.bridge,
        watcherOptions: {
          watchFactory: () => {
            disconnectedFactoryCalls += 1;
            return fakeWatch().watcher;
          },
        },
      });
      expect(disconnected).toBeDefined();
      disconnected?.start();
      expect(disconnected?.watchedConnectionCount).toBe(0);
      expect(disconnectedFactoryCalls).toBe(0);
      await disconnected?.stop();

      value.database.prepare(`
        UPDATE vault_connections SET status = 'connected' WHERE id = ?
      `).run(value.connection.id);
      const current = value.bridge.memoryControlPolicy();
      updateMemoryControlPolicy({
        database: value.database,
        expectedVersion: current.version,
        actor: "operator:test",
        policy: { ...current, obsidianSyncScope: "disabled" },
      });
      let disabledFactoryCalls = 0;
      const disabled = createProductionObsidianVaultWatcher({
        database: value.database,
        bridge: value.bridge,
        watcherOptions: {
          watchFactory: () => {
            disabledFactoryCalls += 1;
            return fakeWatch().watcher;
          },
        },
      });
      disabled?.start();
      expect(disabled?.watchedConnectionCount).toBe(0);
      expect(disabledFactoryCalls).toBe(0);
      await disabled?.stop();
    } finally {
      value.database.close();
      rmSync(value.directory, { recursive: true, force: true });
    }
  });

  test("drains a pending connected edit during shutdown and a fresh process watcher resumes later edits", async () => {
    const value = fixture();
    try {
      const node = createTechnique(value.memory);
      const exported = value.bridge.exportNode(value.connection.id, node.id);
      const notePath = join(value.connection.vaultPath, exported.relativePath);

      const firstWatch = fakeWatch();
      const first = createProductionObsidianVaultWatcher({
        database: value.database,
        bridge: value.bridge,
        watcherOptions: {
          debounceMs: 1_000,
          yieldMs: 0,
          watchFactory: (_root, callback) => {
            firstWatch.capture(callback);
            return firstWatch.watcher;
          },
        },
      });
      if (!first) throw new Error("Expected configured production watcher");
      first.start();
      expect(first.watchedConnectionCount).toBe(1);
      writeFileSync(
        notePath,
        readFileSync(notePath, "utf8").replace(
          "Use the reviewed initial endpoint procedure.",
          "Use the operator-refined endpoint procedure.",
        ),
      );
      firstWatch.emitChange(exported.relativePath);
      expect(first.pendingCount).toBe(1);

      first.beginStop();
      await first.stop();
      expect(firstWatch.closed()).toBe(true);
      expect(first.pendingCount).toBe(0);
      expect(value.memory.requireNode(node.id)).toMatchObject({
        body: "Use the operator-refined endpoint procedure.",
        version: 2,
      });

      value.bridge.exportNode(value.connection.id, node.id);
      const secondWatch = fakeWatch();
      const restarted = createProductionObsidianVaultWatcher({
        database: value.database,
        bridge: value.bridge,
        watcherOptions: {
          debounceMs: 10,
          yieldMs: 0,
          watchFactory: (_root, callback) => {
            secondWatch.capture(callback);
            return secondWatch.watcher;
          },
        },
      });
      if (!restarted) throw new Error("Expected restarted production watcher");
      restarted.start();
      writeFileSync(
        notePath,
        readFileSync(notePath, "utf8").replace(
          "Use the operator-refined endpoint procedure.",
          "Use the restart-verified endpoint procedure.",
        ),
      );
      secondWatch.emitChange(exported.relativePath);
      await new Promise((resolve) => setTimeout(resolve, 30));
      await restarted.waitForIdle();
      expect(value.memory.requireNode(node.id)).toMatchObject({
        body: "Use the restart-verified endpoint procedure.",
        version: 3,
      });
      await restarted.stop();
      expect(secondWatch.closed()).toBe(true);
    } finally {
      value.database.close();
      rmSync(value.directory, { recursive: true, force: true });
    }
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db/index";
import { MemoryRepository, type MemoryProvenance } from "../../memory/index";
import { ObsidianVaultBridge, type BridgeOptions } from "../ObsidianVaultBridge";
import { VaultPathPolicy } from "../VaultPathPolicy";
import { DuplicateVaultProjectionError, VaultRecoveryRepository, VaultSearchIndexIntegrityError } from "../VaultRecoveryRepository";
import { VaultRecoveryService } from "../VaultRecoveryService";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function provenance(id: string): MemoryProvenance {
  return {
    method: "operator_statement",
    explanation: "Authorized recovery test memory",
    sources: [{ sourceType: "test", sourceId: id, acquiredAt: "2026-07-17T00:00:00.000Z" }],
  };
}

function setup(bridgeOptions: BridgeOptions = {}) {
  const directory = mkdtempSync(join(tmpdir(), "vault-recovery-test-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "recovery.sqlite") });
  migrateDatabase(database);
  const memory = new MemoryRepository(database);
  const paths = new VaultPathPolicy(join(directory, "vaults"));
  const bridge = new ObsidianVaultBridge(database, memory, paths, bridgeOptions);
  const connection = bridge.connect({
    id: "vault-recovery",
    vaultPath: "Brain",
    displayName: "Recovery Brain",
    permissionGranted: true,
  });
  const node = memory.createNode({
    id: "mem-recovery",
    nodeType: "procedure",
    title: "Indexable recovery procedure",
    summary: "Canonical recovery search projection",
    body: "The canonical body must never be replaced by repair or reindex.",
    scope: { kind: "global" },
    sensitivity: "private",
    confidence: 1,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: provenance("recovery-source"),
    authorType: "operator",
    authorId: "operator-recovery",
  });
  const exported = bridge.exportNode(connection.id, node.id, new Set([node.id]));
  const repository = new VaultRecoveryRepository(database);
  const service = new VaultRecoveryService(repository, memory, bridge, paths);
  return {
    database,
    memory,
    paths,
    bridge,
    repository,
    service,
    connectionId: connection.id,
    nodeId: node.id,
    relativePath: exported.relativePath,
    notePath: join(connection.vaultPath, exported.relativePath),
    vaultPath: connection.vaultPath,
  };
}

function currentVersion(database: ReturnType<typeof createDatabaseConnection>): string {
  return (database.prepare("SELECT updated_at FROM vault_connections WHERE id = 'vault-recovery'").get() as { updated_at: string }).updated_at;
}

function run(
  fixture: ReturnType<typeof setup>,
  operation: "repair" | "reindex",
) {
  return fixture.service.run({
    operation,
    connectionId: fixture.connectionId,
    expectedUpdatedAt: currentVersion(fixture.database),
    allowedNodeIds: new Set([fixture.nodeId]),
  });
}

describe("VaultRecoveryService", () => {
  test("repairs metadata and incrementally refreshes only represented canonical searchable rows", () => {
    const fixture = setup();
    try {
      const repair = run(fixture, "repair");
      expect(repair).toMatchObject({
        operation: "repair",
        status: "completed",
        counts: { synced: 1, errors: 0, quarantined: 0 },
        progress: { discovered: 1, processed: 1, remaining: 0 },
      });
      expect(repair.message).toContain("no operator edits were overwritten");

      const reindex = run(fixture, "reindex");
      expect(reindex).toMatchObject({
        operation: "reindex",
        status: "completed",
        counts: { indexed: 1, synced: 1, errors: 0 },
      });
      expect((fixture.database.prepare(`
        SELECT COUNT(*) AS count FROM memory_nodes_fts WHERE memory_nodes_fts MATCH 'Indexable'
      `).get() as { count: number }).count).toBe(1);
      expect(fixture.memory.requireNode(fixture.nodeId).body).toBe("The canonical body must never be replaced by repair or reindex.");
    } finally {
      fixture.database.close();
    }
  });

  test("stops on FTS integrity failure without launching a global rebuild", () => {
    const fixture = setup();
    try {
      const row = fixture.database.prepare("SELECT rowid FROM memory_nodes WHERE id = ?").get(fixture.nodeId) as { rowid: number };
      fixture.database.prepare("DELETE FROM memory_nodes_fts WHERE rowid = ?").run(row.rowid);
      const versionBefore = currentVersion(fixture.database);
      expect(() => run(fixture, "reindex")).toThrow(VaultSearchIndexIntegrityError);
      expect(currentVersion(fixture.database)).toBe(versionBefore);
      expect((fixture.database.prepare(`
        SELECT COUNT(*) AS count FROM memory_nodes_fts WHERE memory_nodes_fts MATCH 'Indexable'
      `).get() as { count: number }).count).toBe(0);
      expect(fixture.memory.requireNode(fixture.nodeId).body).toBe("The canonical body must never be replaced by repair or reindex.");
    } finally {
      fixture.database.close();
    }
  });

  test("marks a missing managed note without recreating it or changing canonical memory", () => {
    const fixture = setup();
    try {
      rmSync(fixture.notePath);
      const result = run(fixture, "repair");
      expect(result).toMatchObject({
        status: "partial",
        counts: { missing: 1, databaseAhead: 1 },
      });
      expect(existsSync(fixture.notePath)).toBe(false);
      expect(fixture.memory.requireNode(fixture.nodeId).body).toBe("The canonical body must never be replaced by repair or reindex.");
      const state = fixture.database.prepare(`
        SELECT status, error_message FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
      `).get(fixture.connectionId, fixture.nodeId) as { status: string; error_message: string };
      expect(state.status).toBe("database_ahead");
      expect(state.error_message).toContain("Synchronize or export");
    } finally {
      fixture.database.close();
    }
  });

  test("copies malformed managed notes to durable quarantine without removing the operator source", () => {
    const fixture = setup();
    try {
      const malformed = "not valid Obsidian frontmatter\noperator text remains recoverable\n";
      writeFileSync(fixture.notePath, malformed, "utf8");
      const result = run(fixture, "repair");
      expect(result).toMatchObject({ status: "partial", counts: { quarantined: 1 } });
      expect(readFileSync(fixture.notePath, "utf8")).toBe(malformed);
      const quarantined = fixture.database.prepare(`
        SELECT status, error_message FROM vault_sync_state WHERE connection_id = ? AND relative_path = ?
      `).get(fixture.connectionId, fixture.relativePath) as { status: string; error_message: string };
      expect(quarantined.status).toBe("quarantined");
      expect(quarantined.error_message).toContain("exact-byte guarded private quarantine copy");
      expect(quarantined.error_message).toContain("recovery metadata is content-free");
      const quarantineFiles = readdirSync(join(fixture.vaultPath, ".ti-scale", "quarantine"));
      expect(quarantineFiles.filter((name) => name.endsWith(".md"))).toHaveLength(1);
      expect(quarantineFiles.filter((name) => name.endsWith(".receipt.json"))).toHaveLength(1);
      expect(readFileSync(join(fixture.vaultPath, ".ti-scale", "quarantine", quarantineFiles.find((name) => name.endsWith(".md"))!), "utf8")).toBe(malformed);
      expect(fixture.memory.requireNode(fixture.nodeId).body).toBe("The canonical body must never be replaced by repair or reindex.");
    } finally {
      fixture.database.close();
    }
  });

  test("never quarantines a note that changed after inspection", () => {
    let managedReads = 0;
    let notePath = "";
    const fixture = setup({
      beforeManagedRead: (path) => {
        if (path !== notePath) return;
        managedReads += 1;
        if (managedReads === 2) writeFileSync(path, "operator changed this file before quarantine\n", "utf8");
      },
    });
    notePath = fixture.notePath;
    try {
      writeFileSync(fixture.notePath, "malformed before guarded quarantine\n", "utf8");
      const result = run(fixture, "repair");
      expect(result).toMatchObject({ status: "partial", counts: { quarantined: 0, errors: 1 } });
      expect(result.issues).toContainEqual(expect.objectContaining({ category: "concurrent_change" }));
      expect(readFileSync(fixture.notePath, "utf8")).toBe("operator changed this file before quarantine\n");
      expect(readdirSync(join(fixture.vaultPath, ".ti-scale", "quarantine"))).toEqual([]);
    } finally {
      fixture.database.close();
    }
  });

  test("reconciles a verified quarantine copy after failure between copy and marker commit", () => {
    let failAfterCopy = true;
    const fixture = setup({
      afterQuarantineCopy: () => {
        if (failAfterCopy) {
          failAfterCopy = false;
          throw new Error("simulated process loss after durable copy");
        }
      },
    });
    try {
      const malformed = "malformed crash recovery note\n";
      writeFileSync(fixture.notePath, malformed, "utf8");
      const first = run(fixture, "repair");
      expect(first).toMatchObject({ status: "partial", counts: { quarantined: 0, errors: 1 } });
      expect(first.issues).toContainEqual(expect.objectContaining({ category: "quarantine_recovery" }));
      expect(readFileSync(fixture.notePath, "utf8")).toBe(malformed);

      const second = run(fixture, "repair");
      expect(second).toMatchObject({ status: "partial", counts: { quarantined: 1, errors: 0 } });
      const intent = fixture.database.prepare(`
        SELECT value_json FROM settings WHERE key LIKE 'brain.vault.quarantine_intent.%'
      `).get() as { value_json: string };
      expect(JSON.parse(intent.value_json)).toMatchObject({ status: "committed", connectionId: fixture.connectionId });
      expect(readFileSync(fixture.notePath, "utf8")).toBe(malformed);
    } finally {
      fixture.database.close();
    }
  });

  test("flags every duplicate stable-ID projection without choosing a winner", () => {
    const fixture = setup();
    try {
      const duplicateRelative = "10 Operator/duplicate-projection.md";
      const duplicatePath = join(fixture.vaultPath, duplicateRelative);
      const original = readFileSync(fixture.notePath, "utf8");
      writeFileSync(duplicatePath, original, "utf8");
      const result = run(fixture, "repair");
      expect(result).toMatchObject({ status: "partial", counts: { pending: 2 } });
      expect(result.issues.filter((issue) => issue.category === "duplicate_projection")).toHaveLength(2);
      expect(readFileSync(fixture.notePath, "utf8")).toBe(original);
      expect(readFileSync(duplicatePath, "utf8")).toBe(original);
      expect((fixture.database.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state
        WHERE connection_id = ? AND node_id = ?
      `).get(fixture.connectionId, fixture.nodeId) as { count: number }).count).toBe(0);
    } finally {
      fixture.database.close();
    }
  });

  test("repository validation rejects any duplicate projection surviving reconciliation", () => {
    const fixture = setup();
    try {
      fixture.database.prepare(`
        INSERT INTO vault_sync_state (
          id, connection_id, node_id, relative_path, status
        ) VALUES ('vsync-duplicate-race', ?, ?, '10 Operator/race-duplicate.md', 'pending')
      `).run(fixture.connectionId, fixture.nodeId);
      const version = currentVersion(fixture.database);
      expect(() => fixture.repository.complete({
        connectionId: fixture.connectionId,
        expectedUpdatedAt: version,
        connectionStatus: "degraded",
        updates: [],
        indexNodeIds: [],
      })).toThrow(DuplicateVaultProjectionError);
      expect(currentVersion(fixture.database)).toBe(version);
    } finally {
      fixture.database.close();
    }
  });

  test("reports a per-file permission diagnosis without quarantine or mutation", () => {
    let notePath = "";
    const fixture = setup({
      beforeManagedRead: (path) => {
        if (path !== notePath) return;
        throw Object.assign(new Error("permission denied"), { code: "EACCES" });
      },
    });
    notePath = fixture.notePath;
    try {
      const before = readFileSync(fixture.notePath, "utf8");
      const result = run(fixture, "repair");
      expect(result).toMatchObject({ status: "partial", counts: { quarantined: 0, errors: 1 } });
      expect(result.issues).toContainEqual(expect.objectContaining({
        category: "permission_denied",
        relativePath: fixture.relativePath,
      }));
      expect(readFileSync(fixture.notePath, "utf8")).toBe(before);
      expect(readdirSync(join(fixture.vaultPath, ".ti-scale", "quarantine"))).toEqual([]);
    } finally {
      fixture.database.close();
    }
  });

  test("preserves an open conflict without changing either represented version", () => {
    const fixture = setup();
    try {
      const original = readFileSync(fixture.notePath, "utf8");
      writeFileSync(fixture.notePath, original.replace("The canonical body", "The operator Vault body"), "utf8");
      fixture.memory.correctNode(fixture.nodeId, {
        body: "The changed canonical body remains separate from the operator Vault body.",
        authorType: "operator",
        authorId: "operator-recovery",
        changeReason: "Create recovery conflict fixture",
      });
      const conflict = fixture.bridge.syncNode(fixture.connectionId, fixture.nodeId, "operator-recovery", new Set([fixture.nodeId]));
      expect(conflict.status).toBe("conflict");
      const vaultBefore = readFileSync(fixture.notePath, "utf8");
      const canonicalBefore = fixture.memory.requireNode(fixture.nodeId).body;

      const result = run(fixture, "reindex");
      expect(result).toMatchObject({
        status: "partial",
        counts: { conflictsPreserved: 1, indexed: 1 },
      });
      expect(readFileSync(fixture.notePath, "utf8")).toBe(vaultBefore);
      expect(fixture.memory.requireNode(fixture.nodeId).body).toBe(canonicalBefore);
      expect((fixture.database.prepare(`
        SELECT COUNT(*) AS count FROM vault_conflicts WHERE connection_id = ? AND status = 'open'
      `).get(fixture.connectionId) as { count: number }).count).toBe(1);
    } finally {
      fixture.database.close();
    }
  });

  test("does not follow a managed symlink or modify its outside target", () => {
    const fixture = setup();
    try {
      const outside = join(fixture.vaultPath, "outside-note.md");
      const linked = join(fixture.vaultPath, "10 Operator", "linked-note.md");
      writeFileSync(outside, "outside target must remain unchanged", "utf8");
      symlinkSync(outside, linked);
      const result = run(fixture, "repair");
      expect(result.status).toBe("partial");
      expect(result.counts.errors).toBe(1);
      expect(result.issues).toContainEqual(expect.objectContaining({ category: "unsafe_path", relativePath: "10 Operator/linked-note.md" }));
      expect(readFileSync(outside, "utf8")).toBe("outside target must remain unchanged");
      expect(existsSync(linked)).toBe(true);
    } finally {
      fixture.database.close();
    }
  });

  test("fails closed when the configured Vault is offline and enforces optimistic versioning", () => {
    const fixture = setup();
    try {
      const staleVersion = currentVersion(fixture.database);
      const first = run(fixture, "repair");
      expect(first.connectionVersion).not.toBe(staleVersion);
      expect(() => fixture.service.run({
        operation: "repair",
        connectionId: fixture.connectionId,
        expectedUpdatedAt: staleVersion,
        allowedNodeIds: new Set([fixture.nodeId]),
      })).toThrow("Vault connection version does not match");

      const offline = `${fixture.vaultPath}-offline`;
      renameSync(fixture.vaultPath, offline);
      expect(() => run(fixture, "repair")).toThrow("Configured vault is not an existing directory");
      expect(existsSync(fixture.vaultPath)).toBe(false);
      expect(existsSync(offline)).toBe(true);
    } finally {
      fixture.database.close();
    }
  });
});

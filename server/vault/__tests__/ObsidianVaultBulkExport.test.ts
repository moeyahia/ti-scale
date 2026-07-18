import { afterEach, describe, expect, spyOn, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  getMemoryControlPolicy,
  MemoryRepository,
  type MemoryNodeType,
  updateMemoryControlPolicy,
} from "../../memory";
import {
  ObsidianVaultBridge,
  parseObsidianNote,
  VaultBulkExportAbortError,
  VaultPathPolicy,
} from "../index";
import { runVaultCli } from "../cli";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function setup(syncScope: Record<string, unknown> = {}) {
  const directory = mkdtempSync(join(tmpdir(), "obsidian-bulk-export-test-"));
  temporaryDirectories.push(directory);
  const databasePath = join(directory, "canonical.sqlite");
  const allowedRoot = join(directory, "allowed-vaults");
  const database = createDatabaseConnection({ filename: databasePath });
  migrateDatabase(database);
  const memory = new MemoryRepository(database);
  const paths = new VaultPathPolicy(allowedRoot);
  const bridge = new ObsidianVaultBridge(database, memory, paths);
  const connection = bridge.connect({
    id: "vault-bulk-test",
    vaultPath: "Ti-Scale-Brain",
    displayName: "Bulk export test",
    syncScope,
    permissionGranted: true,
  });
  return { directory, databasePath, allowedRoot, database, memory, paths, bridge, connection };
}

function addNode(memory: MemoryRepository, index: number, nodeType: MemoryNodeType = "technique") {
  return memory.createNode({
    id: `bulk-node-${String(index).padStart(4, "0")}`,
    nodeType,
    title: `Bulk node ${index}`,
    summary: `Bounded export fixture ${index}`,
    body: `Canonical body ${index}.`,
    scope: { kind: "global" },
    sensitivity: "private",
    confidence: 0.9,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Disposable bulk-export unit fixture",
      sources: [{
        sourceType: "test_fixture",
        sourceId: `bulk-source-${index}`,
        acquiredAt: "2026-07-15T00:00:00.000Z",
      }],
    },
    authorType: "system",
    authorId: "bulk-export-test",
  });
}

describe("Obsidian vault bulk export", () => {
  test("projects high-fanout produced edges as safe artifact backlinks", () => {
    const { database, memory, bridge, connection } = setup();
    try {
      const run = addNode(memory, 90_000, "run");
      const artifacts = Array.from({ length: 40 }, (_, offset) => {
        const artifact = addNode(memory, 91_000 + offset, "artifact");
        memory.createEdge({
          sourceNodeId: run.id,
          targetNodeId: artifact.id,
          edgeType: "produced",
          title: `Run produced ${artifact.id}`,
          summary: "High-fanout Vault projection fixture",
          scope: { kind: "global" },
          sensitivity: "private",
          confidence: 0.95,
          lifecycleStatus: "verified",
          provenance: run.provenance,
          explanation: "High-fanout relationship ".padEnd(4_000, "x"),
          authorType: "system",
          authorId: "bulk-export-test",
        });
        return artifact;
      });

      const runText = bridge.renderNode(run.id, connection).text;
      expect(Buffer.byteLength(runText)).toBeLessThan(128 * 1024);
      expect(runText).not.toContain("ti-scale-edge:produced");

      const artifactText = bridge.renderNode(artifacts[0]!.id, connection).text;
      expect(artifactText).toContain(`ti-scale-backlink:produced:${run.id}`);
      expect(artifactText).toContain("[[22 Runs/");
      expect(parseObsidianNote(artifactText).edges).toHaveLength(0);

      const portableText = bridge.renderNode(
        artifacts[0]!.id,
        connection,
        new Set([artifacts[0]!.id]),
      ).text;
      expect(portableText).not.toContain(run.id);
    } finally {
      database.close();
    }
  });

  test("does not backlink an artifact to a source excluded by the Vault scope", () => {
    const { database, memory, bridge, connection } = setup({ nodeTypes: ["artifact"] });
    try {
      const run = addNode(memory, 92_000, "run");
      const artifact = addNode(memory, 92_001, "artifact");
      memory.createEdge({
        sourceNodeId: run.id,
        targetNodeId: artifact.id,
        edgeType: "produced",
        title: "Scoped production edge",
        summary: "The source note is outside this connection's projection",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.95,
        lifecycleStatus: "confirmed",
        provenance: run.provenance,
        explanation: "Scope filtering must prevent a dangling or disclosed backlink",
        authorType: "system",
        authorId: "bulk-export-test",
      });
      const text = bridge.renderNode(artifact.id, connection).text;
      expect(text).not.toContain(run.id);
      expect(text).not.toContain("ti-scale-backlink:");
    } finally {
      database.close();
    }
  });

  test("keeps the enlarged engagement projection bounded at 100,000 notes", async () => {
    const { database, bridge, connection } = setup();
    try {
      const admitted = Array.from({ length: 50_001 }, (_, index) => `admitted-node-${index}`);
      const controller = new AbortController();
      controller.abort();
      await expect(bridge.exportNodes(connection.id, admitted, { signal: controller.signal })).rejects
        .toBeInstanceOf(VaultBulkExportAbortError);

      const oversized = Array.from({ length: 100_001 }, (_, index) => `oversized-node-${index}`);
      await expect(bridge.exportNodes(connection.id, oversized)).rejects.toThrow(
        "limited to 100000 canonical notes",
      );
    } finally {
      database.close();
    }
  });

  test("exports atomically with bounded progress then skips current versions", async () => {
    const { database, memory, bridge, connection } = setup();
    try {
      for (let index = 0; index < 24; index += 1) addNode(memory, index);
      expect(database.prepare(`
        SELECT name FROM sqlite_master
        WHERE type = 'index' AND name = 'idx_vault_sync_connection_node'
      `).get()).toEqual({ name: "idx_vault_sync_connection_node" });
      const progress: number[] = [];
      const ids = bridge.exportableNodeIds(connection.id);
      const first = await bridge.exportNodes(connection.id, ids, {
        concurrency: 4,
        progressInterval: 5,
        onProgress: (item) => { progress.push(item.processed); },
      });
      expect(first).toMatchObject({ total: 24, processed: 24, remaining: 0 });
      expect(first.counts).toEqual({
        synced: 24,
        skipped: 0,
        databaseAhead: 0,
        vaultAhead: 0,
        conflicts: 0,
        quarantined: 0,
        failed: 0,
      });
      expect(progress.at(-1)).toBe(24);
      expect((database.prepare("SELECT COUNT(*) AS count FROM vault_sync_state WHERE connection_id = ? AND status = 'synced'").get(connection.id) as { count: number }).count).toBe(24);
      for (const id of ids) {
        const projection = bridge.renderNode(id);
        const path = join(connection.vaultPath, projection.relativePath);
        expect(readFileSync(path, "utf8")).toBe(projection.text);
        expect(statSync(path).mode & 0o777).toBe(0o600);
      }

      const resumed = await bridge.exportNodes(connection.id, ids, { concurrency: 8 });
      expect(resumed.counts.skipped).toBe(24);
      expect(resumed.counts.synced).toBe(0);
    } finally {
      database.close();
    }
  });

  test("the CLI full export uses the resumable bulk path", async () => {
    const fixture = setup();
    const { database, memory, connection } = fixture;
    for (let index = 0; index < 6; index += 1) addNode(memory, index);
    database.close();
    const stdout = spyOn(process.stdout, "write").mockImplementation(() => true);
    const stderr = spyOn(process.stderr, "write").mockImplementation(() => true);
    try {
      const code = await runVaultCli([
        "export",
        "--db", fixture.databasePath,
        "--vault-root", fixture.allowedRoot,
        "--connection", connection.id,
        "--concurrency", "2",
        "--progress-interval", "2",
        "--quiet",
      ]);
      expect(code).toBe(0);
      const output = stdout.mock.calls.map((call) => String(call[0])).join("");
      const parsed = JSON.parse(output) as {
        status: string;
        result: { processed: number; counts: { synced: number; failed: number } };
      };
      expect(parsed).toMatchObject({
        status: "completed",
        result: { processed: 6, counts: { synced: 6, failed: 0 } },
      });
      expect(stderr).not.toHaveBeenCalled();
    } finally {
      stdout.mockRestore();
      stderr.mockRestore();
    }
  });

  test("durably resumes completed notes after cancellation and database reopen", async () => {
    const { databasePath, allowedRoot, database, memory, bridge, connection } = setup();
    const controller = new AbortController();
    try {
      for (let index = 0; index < 60; index += 1) addNode(memory, index);
      let aborted: VaultBulkExportAbortError | undefined;
      try {
        await bridge.exportNodes(connection.id, bridge.exportableNodeIds(connection.id), {
          concurrency: 3,
          progressInterval: 1,
          signal: controller.signal,
          onProgress: (progress) => {
            if (progress.processed >= 11) controller.abort();
          },
        });
      } catch (error) {
        if (!(error instanceof VaultBulkExportAbortError)) throw error;
        aborted = error;
      }
      expect(aborted).toBeDefined();
      expect(aborted!.result.processed).toBeGreaterThanOrEqual(11);
      expect(aborted!.result.processed).toBeLessThan(60);
      const durableBeforeClose = (database.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state
        WHERE connection_id = ? AND status = 'synced'
      `).get(connection.id) as { count: number }).count;
      expect(durableBeforeClose).toBe(aborted!.result.counts.synced);
    } finally {
      database.close();
    }

    const reopened = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      const resumedBridge = new ObsidianVaultBridge(
        reopened,
        new MemoryRepository(reopened),
        new VaultPathPolicy(allowedRoot),
      );
      const resumed = await resumedBridge.exportNodes(
        connection.id,
        resumedBridge.exportableNodeIds(connection.id),
        { concurrency: 4 },
      );
      expect(resumed.processed).toBe(60);
      expect(resumed.counts.skipped).toBeGreaterThanOrEqual(11);
      expect(resumed.counts.synced + resumed.counts.skipped).toBe(60);
      expect((reopened.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state
        WHERE connection_id = ? AND status = 'synced'
      `).get(connection.id) as { count: number }).count).toBe(60);
    } finally {
      reopened.close();
    }
  });

  test("preserves unmanaged and concurrently edited notes as conflicts", async () => {
    const fixture = setup();
    const { database, memory, bridge, connection } = fixture;
    try {
      const existing = addNode(memory, 1);
      const unmanaged = addNode(memory, 2);
      bridge.exportNode(connection.id, existing.id);
      const existingProjection = bridge.renderNode(existing.id);
      const existingPath = join(connection.vaultPath, existingProjection.relativePath);
      writeFileSync(existingPath, existingProjection.text.replace("Canonical body 1.", "Operator vault edit."));
      memory.correctNode(existing.id, {
        body: "New canonical database edit.",
        authorType: "agent",
        authorId: "bulk-export-test",
        changeReason: "Create a two-sided conflict fixture",
      });

      const unmanagedProjection = bridge.renderNode(unmanaged.id);
      const unmanagedPath = join(connection.vaultPath, unmanagedProjection.relativePath);
      writeFileSync(
        unmanagedPath,
        unmanagedProjection.text.replace("Canonical body 2.", "Existing unmanaged operator note."),
      );
      const result = await bridge.exportNodes(
        connection.id,
        [existing.id, unmanaged.id],
        { concurrency: 2, progressInterval: 1 },
      );
      expect(result.counts.conflicts).toBe(2);
      expect(result.counts.synced).toBe(0);
      expect(readFileSync(existingPath, "utf8")).toContain("Operator vault edit");
      expect(readFileSync(unmanagedPath, "utf8")).toContain("Existing unmanaged operator note");
      expect((database.prepare("SELECT COUNT(*) AS count FROM vault_conflicts WHERE status = 'open'").get() as { count: number }).count).toBe(2);
    } finally {
      database.close();
    }
  });

  test("enforces connection scope and rejects symlinked projection paths", async () => {
    const { directory, database, memory, bridge, connection } = setup({
      lifecycleStatuses: ["confirmed"],
      nodeTypes: ["technique"],
    });
    try {
      const allowed = addNode(memory, 1, "technique");
      const denied = addNode(memory, 2, "report");
      expect(bridge.exportableNodeIds(connection.id)).toEqual([allowed.id]);
      const deniedResult = await bridge.exportNodes(connection.id, [denied.id]);
      expect(deniedResult.counts.failed).toBe(1);
      expect(deniedResult.issues[0]?.message).toContain("outside this vault connection");

      const attackFolder = join(connection.vaultPath, "41 Attack Paths");
      rmSync(attackFolder, { recursive: true, force: true });
      const outside = join(directory, "outside-projection");
      mkdirSync(outside);
      symlinkSync(outside, attackFolder, "dir");
      const unsafe = await bridge.exportNodes(connection.id, [allowed.id]);
      expect(unsafe.counts.failed).toBe(1);
      expect(readdirSync(outside)).toEqual([]);
      expect(existsSync(join(outside, "bulk-node-1--bulk-node-0001.md"))).toBe(false);
    } finally {
      database.close();
    }
  });

  test("detects a vault edit made during async fsync instead of overwriting it", async () => {
    const fixture = setup();
    const { database, memory, connection } = fixture;
    try {
      const node = addNode(memory, 9);
      fixture.bridge.exportNode(connection.id, node.id);
      const projection = fixture.bridge.renderNode(node.id);
      const path = join(connection.vaultPath, projection.relativePath);
      memory.correctNode(node.id, {
        body: "Canonical edit racing with the vault.",
        authorType: "agent",
        authorId: "bulk-export-test",
        changeReason: "Exercise async destination race guard",
      });

      class RacingPolicy extends VaultPathPolicy {
        changed = false;

        override async atomicWriteAsync(...args: Parameters<VaultPathPolicy["atomicWriteAsync"]>) {
          const [root, relativePath, content, expectation] = args;
          return super.atomicWriteAsync(root, relativePath, content, {
            ...expectation,
            beforePublish: async () => {
              await expectation.beforePublish?.();
              if (!this.changed) {
                this.changed = true;
                // At this seam the expected destination has already been
                // captured in a guard and the public name is intentionally
                // empty. Recreating it must win over bridge publication.
                writeFileSync(
                  path,
                  projection.text.replace("Canonical body 9.", "Late operator edit."),
                );
              }
            },
          });
        }
      }
      const racingBridge = new ObsidianVaultBridge(
        database,
        memory,
        new RacingPolicy(fixture.allowedRoot),
      );
      const result = await racingBridge.exportNodes(connection.id, [node.id]);
      expect(result.counts.conflicts).toBe(1);
      expect(result.counts.failed).toBe(0);
      expect(readFileSync(path, "utf8")).toContain("Late operator edit");
      expect(readFileSync(path, "utf8")).not.toContain("Canonical edit racing");
    } finally {
      database.close();
    }
  });

  test("the synchronous export path cannot clobber a note recreated during publication", () => {
    const fixture = setup();
    const { database, memory, connection } = fixture;
    try {
      const node = addNode(memory, 11);
      fixture.bridge.exportNode(connection.id, node.id);
      const projection = fixture.bridge.renderNode(node.id);
      const path = join(connection.vaultPath, projection.relativePath);
      memory.correctNode(node.id, {
        body: "Canonical synchronous update.",
        authorType: "agent",
        authorId: "bulk-export-test",
        changeReason: "Exercise synchronous no-clobber publication",
      });

      class SynchronousRacingPolicy extends VaultPathPolicy {
        changed = false;

        override atomicWrite(...args: Parameters<VaultPathPolicy["atomicWrite"]>) {
          const [root, relativePath, content, expectation] = args;
          if (!expectation) return super.atomicWrite(...args);
          return super.atomicWrite(root, relativePath, content, {
            ...expectation,
            beforePublish: () => {
              const prior = expectation.beforePublish?.();
              if (prior && typeof (prior as Promise<void>).then === "function") {
                throw new Error("Unexpected async hook in synchronous test");
              }
              if (!this.changed) {
                this.changed = true;
                writeFileSync(
                  path,
                  projection.text.replace("Canonical body 11.", "Synchronous late operator edit."),
                );
              }
            },
          });
        }
      }
      const racingBridge = new ObsidianVaultBridge(
        database,
        memory,
        new SynchronousRacingPolicy(fixture.allowedRoot),
      );
      const result = racingBridge.exportNode(connection.id, node.id);
      expect(result.status).toBe("conflict");
      expect(readFileSync(path, "utf8")).toContain("Synchronous late operator edit");
      expect(readFileSync(path, "utf8")).not.toContain("Canonical synchronous update");
    } finally {
      database.close();
    }
  });

  test("watcher sync preserves a second vault edit and opens a truthful conflict", () => {
    const fixture = setup();
    const { database, memory, connection } = fixture;
    try {
      const node = addNode(memory, 13);
      const exported = fixture.bridge.exportNode(connection.id, node.id);
      const path = join(connection.vaultPath, exported.relativePath);
      const original = readFileSync(path, "utf8");
      const importedEdit = original.replace(
        "Canonical body 13.",
        "First operator edit accepted by the watcher.",
      );
      const lateEdit = importedEdit.replace(
        "First operator edit accepted by the watcher.",
        "Second operator edit made during normalization.",
      );
      writeFileSync(path, importedEdit);

      class WatcherVaultRacingPolicy extends VaultPathPolicy {
        changed = false;

        override atomicWrite(...args: Parameters<VaultPathPolicy["atomicWrite"]>) {
          const [root, relativePath, content, expectation] = args;
          if (!expectation) return super.atomicWrite(...args);
          return super.atomicWrite(root, relativePath, content, {
            ...expectation,
            beforePublish: () => {
              const prior = expectation.beforePublish?.();
              if (prior && typeof (prior as Promise<void>).then === "function") {
                throw new Error("Unexpected async hook in synchronous watcher test");
              }
              if (!this.changed) {
                this.changed = true;
                writeFileSync(path, lateEdit);
              }
            },
          });
        }
      }
      const racingBridge = new ObsidianVaultBridge(
        database,
        memory,
        new WatcherVaultRacingPolicy(fixture.allowedRoot),
      );
      const result = racingBridge.syncChangedPath(
        connection.id,
        exported.relativePath,
        "operator:bulk-export-test",
      );
      expect(result).toMatchObject({ status: "conflict" });
      expect(readFileSync(path, "utf8")).toContain("Second operator edit made during normalization");
      expect(memory.requireNode(node.id).body).toContain("First operator edit accepted by the watcher");
      expect(memory.requireNode(node.id).body).not.toContain("Second operator edit made during normalization");
      expect(database.prepare(`
        SELECT status FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
      `).get(connection.id, node.id)).toEqual({ status: "conflict" });
      const conflict = database.prepare(`
        SELECT status, vault_version_text AS vaultText
        FROM vault_conflicts WHERE node_id = ?
      `).get(node.id) as { status: string; vaultText: string };
      expect(conflict.status).toBe("open");
      expect(conflict.vaultText).toContain("Second operator edit made during normalization");
    } finally {
      database.close();
    }
  });

  test("watcher sync records canonical races as database-ahead and resumes safely", () => {
    const fixture = setup();
    const { database, memory, connection } = fixture;
    try {
      const node = addNode(memory, 14);
      const exported = fixture.bridge.exportNode(connection.id, node.id);
      const path = join(connection.vaultPath, exported.relativePath);
      const importedEdit = readFileSync(path, "utf8").replace(
        "Canonical body 14.",
        "Operator edit versioned before the canonical race.",
      );
      writeFileSync(path, importedEdit);

      class WatcherCanonicalRacingPolicy extends VaultPathPolicy {
        changed = false;

        override atomicWrite(...args: Parameters<VaultPathPolicy["atomicWrite"]>) {
          const [root, relativePath, content, expectation] = args;
          if (!expectation) return super.atomicWrite(...args);
          return super.atomicWrite(root, relativePath, content, {
            ...expectation,
            beforeRename: () => {
              if (!this.changed) {
                this.changed = true;
                memory.correctNode(node.id, {
                  body: "Concurrent canonical edit created after the vault import.",
                  authorType: "agent",
                  authorId: "bulk-export-test",
                  changeReason: "Exercise watcher canonical publication race",
                });
              }
              const prior = expectation.beforeRename?.();
              if (prior && typeof (prior as Promise<void>).then === "function") {
                throw new Error("Unexpected async hook in synchronous watcher test");
              }
            },
          });
        }
      }
      const racingBridge = new ObsidianVaultBridge(
        database,
        memory,
        new WatcherCanonicalRacingPolicy(fixture.allowedRoot),
      );
      const raced = racingBridge.syncChangedPath(
        connection.id,
        exported.relativePath,
        "operator:bulk-export-test",
      );
      expect(raced).toMatchObject({ status: "database_ahead" });
      expect(readFileSync(path, "utf8")).toBe(importedEdit);
      expect(memory.requireNode(node.id)).toMatchObject({
        version: 3,
        body: "Concurrent canonical edit created after the vault import.",
      });
      expect(memory.listVersions(node.id)[1]?.body).toBe(
        "Operator edit versioned before the canonical race.",
      );
      expect(database.prepare(`
        SELECT status, database_version AS databaseVersion
        FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
      `).get(connection.id, node.id)).toEqual({
        status: "database_ahead",
        databaseVersion: 3,
      });

      const resumed = racingBridge.syncNode(
        connection.id,
        node.id,
        "operator:bulk-export-test",
      );
      expect(resumed.status).toBe("synced");
      expect(readFileSync(path, "utf8")).toContain(
        "Concurrent canonical edit created after the vault import.",
      );
    } finally {
      database.close();
    }
  });

  test("stale conflict resolution remains open when the vault changes during publication", () => {
    const fixture = setup();
    const { database, memory, connection } = fixture;
    try {
      const node = addNode(memory, 12);
      const exported = fixture.bridge.exportNode(connection.id, node.id);
      const path = join(connection.vaultPath, exported.relativePath);
      const original = readFileSync(path, "utf8");
      const reviewedVaultText = original.replace("Canonical body 12.", "Reviewed vault-side edit.");
      writeFileSync(path, reviewedVaultText);
      memory.correctNode(node.id, {
        body: "Database edit before conflict review.",
        authorType: "agent",
        authorId: "bulk-export-test",
        changeReason: "Create stale conflict-resolution fixture",
      });
      const conflict = fixture.bridge.syncNode(connection.id, node.id, "operator:bulk-export-test");
      expect(conflict.status).toBe("conflict");
      expect(conflict.conflictId).toBeDefined();
      const merged = reviewedVaultText.replace(
        "Reviewed vault-side edit.",
        "Operator-approved merged conflict content.",
      );

      class ConflictResolutionRacingPolicy extends VaultPathPolicy {
        changed = false;

        override atomicWrite(...args: Parameters<VaultPathPolicy["atomicWrite"]>) {
          const [root, relativePath, content, expectation] = args;
          if (!expectation) return super.atomicWrite(...args);
          return super.atomicWrite(root, relativePath, content, {
            ...expectation,
            beforePublish: () => {
              const prior = expectation.beforePublish?.();
              if (prior && typeof (prior as Promise<void>).then === "function") {
                throw new Error("Unexpected async hook in synchronous conflict test");
              }
              if (!this.changed) {
                this.changed = true;
                writeFileSync(
                  path,
                  reviewedVaultText.replace("Reviewed vault-side edit.", "Late edit after conflict review."),
                );
              }
            },
          });
        }
      }
      const racingBridge = new ObsidianVaultBridge(
        database,
        memory,
        new ConflictResolutionRacingPolicy(fixture.allowedRoot),
      );
      const resolution = racingBridge.resolveConflict(
        conflict.conflictId!,
        "merged",
        "operator:bulk-export-test",
        merged,
      );
      expect(resolution.status).toBe("conflict");
      expect(resolution.conflictId).toBe(conflict.conflictId);
      expect(readFileSync(path, "utf8")).toContain("Late edit after conflict review");
      expect(memory.requireNode(node.id).body).toContain("Operator-approved merged conflict content");
      expect(database.prepare(`
        SELECT status FROM vault_conflicts WHERE id = ?
      `).get(conflict.conflictId)).toEqual({ status: "open" });
      expect(database.prepare(`
        SELECT status FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
      `).get(connection.id, node.id)).toEqual({ status: "conflict" });
      expect((database.prepare(`
        SELECT vault_version_text AS text FROM vault_conflicts WHERE id = ?
      `).get(conflict.conflictId) as { text: string }).text).toContain("Late edit after conflict review");
    } finally {
      database.close();
    }
  });

  test("surfaces a canonical version race as database-ahead and resumes safely", async () => {
    const fixture = setup();
    const { database, memory, connection } = fixture;
    try {
      const node = addNode(memory, 10);
      fixture.bridge.exportNode(connection.id, node.id);
      const projection = fixture.bridge.renderNode(node.id);
      const path = join(connection.vaultPath, projection.relativePath);
      memory.correctNode(node.id, {
        body: "Canonical version queued for bulk projection.",
        authorType: "agent",
        authorId: "bulk-export-test",
        changeReason: "Ensure the bulk path enters an atomic write",
      });

      class CanonicalRacingPolicy extends VaultPathPolicy {
        changed = false;

        override async atomicWriteAsync(...args: Parameters<VaultPathPolicy["atomicWriteAsync"]>) {
          const [root, relativePath, content, expectation] = args;
          return super.atomicWriteAsync(root, relativePath, content, {
            ...expectation,
            beforeRename: async () => {
              if (!this.changed) {
                this.changed = true;
                memory.correctNode(node.id, {
                  body: "Canonical version created during async fsync.",
                  authorType: "agent",
                  authorId: "bulk-export-test",
                  changeReason: "Exercise canonical pre-rename version guard",
                });
              }
              await expectation.beforeRename?.();
            },
          });
        }
      }
      const racingBridge = new ObsidianVaultBridge(
        database,
        memory,
        new CanonicalRacingPolicy(fixture.allowedRoot),
      );
      const raced = await racingBridge.exportNodes(connection.id, [node.id]);
      expect(raced.counts.databaseAhead).toBe(1);
      expect(raced.counts.synced).toBe(0);
      expect(readFileSync(path, "utf8")).toContain("Canonical body 10");
      expect(readFileSync(path, "utf8")).not.toContain("created during async fsync");
      expect((database.prepare(`
        SELECT status, database_version AS version FROM vault_sync_state
        WHERE connection_id = ? AND node_id = ?
      `).get(connection.id, node.id) as { status: string; version: number })).toEqual({
        status: "database_ahead",
        version: 3,
      });

      const resumed = await racingBridge.exportNodes(connection.id, [node.id]);
      expect(resumed.counts.synced).toBe(1);
      expect(readFileSync(path, "utf8")).toContain("Canonical version created during async fsync");
    } finally {
      database.close();
    }
  });

  test("stops on live policy revocation and never reports the connection healthy", async () => {
    const fixture = setup();
    const { database, memory, connection } = fixture;
    try {
      for (let index = 0; index < 12; index += 1) addNode(memory, index);
      class RevokingPolicy extends VaultPathPolicy {
        revoked = false;

        override async atomicWriteAsync(...args: Parameters<VaultPathPolicy["atomicWriteAsync"]>) {
          if (!this.revoked) {
            this.revoked = true;
            const current = getMemoryControlPolicy(database);
            updateMemoryControlPolicy({
              database,
              expectedVersion: current.version,
              actor: "operator:bulk-export-test",
              policy: { ...current, enabled: false, obsidianSyncScope: "disabled" },
            });
          }
          return super.atomicWriteAsync(...args);
        }
      }
      const revokingBridge = new ObsidianVaultBridge(
        database,
        memory,
        new RevokingPolicy(fixture.allowedRoot),
      );
      let stopped: unknown;
      try {
        await revokingBridge.exportNodes(connection.id, revokingBridge.exportableNodeIds(connection.id), {
          concurrency: 2,
          progressInterval: 1,
        });
      } catch (error) {
        stopped = error;
      }
      expect(stopped).toMatchObject({ name: "VaultBulkExportPolicyError" });
      expect((database.prepare("SELECT status FROM vault_connections WHERE id = ?").get(connection.id) as { status: string }).status).toBe("degraded");
      expect((database.prepare("SELECT COUNT(*) AS count FROM vault_sync_state WHERE connection_id = ?").get(connection.id) as { count: number }).count).toBe(0);
    } finally {
      database.close();
    }
  });

  test("renders only confirmed or verified outgoing edge targets", () => {
    const { database, memory, bridge } = setup();
    try {
      const source = addNode(memory, 20);
      const confirmedTarget = addNode(memory, 21);
      const candidateEdgeTarget = addNode(memory, 22);
      const candidateTarget = memory.createNode({
        id: "bulk-candidate-target",
        nodeType: "technique",
        title: "Candidate target",
        summary: "This target is not confirmed",
        body: "Candidate targets must not enter confirmed projections.",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.5,
        lifecycleStatus: "candidate",
        confirmationState: "pending",
        provenance: source.provenance,
        authorType: "agent",
        authorId: "bulk-export-test",
      });
      memory.createEdge({
        sourceNodeId: source.id,
        targetNodeId: confirmedTarget.id,
        edgeType: "depends_on",
        title: "Confirmed dependency",
        summary: "Confirmed relationship",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.9,
        lifecycleStatus: "confirmed",
        provenance: source.provenance,
        explanation: "Confirmed relationship",
        authorType: "operator",
      });
      memory.createEdge({
        sourceNodeId: source.id,
        targetNodeId: candidateTarget.id,
        edgeType: "supports",
        title: "Confirmed edge to candidate target",
        summary: "Target lifecycle still blocks projection",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.5,
        lifecycleStatus: "confirmed",
        provenance: source.provenance,
        explanation: "A confirmed edge cannot promote a candidate target",
        authorType: "operator",
      });
      memory.createEdge({
        sourceNodeId: source.id,
        targetNodeId: candidateEdgeTarget.id,
        edgeType: "similar_to",
        title: "Candidate relationship",
        summary: "Candidate relationship",
        scope: { kind: "global" },
        sensitivity: "private",
        confidence: 0.5,
        lifecycleStatus: "candidate",
        provenance: source.provenance,
        explanation: "Candidate relationship must not enter the projection",
        authorType: "agent",
      });
      const rendered = bridge.renderNode(source.id).text;
      expect(rendered).toContain(`ti-scale-edge:depends_on:${confirmedTarget.id}`);
      expect(rendered).not.toContain(candidateTarget.id);
      expect(rendered).not.toContain(candidateEdgeTarget.id);
      expect(rendered).not.toContain("Candidate relationship");
    } finally {
      database.close();
    }
  });
});

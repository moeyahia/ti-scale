import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createHash } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createDatabaseConnection,
  DATABASE_MIGRATIONS,
  migrateDatabase,
} from "../../db";
import type { Migration } from "../../db/types";
import { BrainContextService } from "../../brain-runtime/BrainContextService";
import { CanonicalMemoryReconciliationService } from "../../brain-runtime/CanonicalMemoryReconciliationService";
import { ObsidianVaultBridge } from "../../vault/ObsidianVaultBridge";
import { VaultPathPolicy } from "../../vault/VaultPathPolicy";
import { MemoryRepository } from "../MemoryRepository";
import { SecondBrainService } from "../SecondBrainService";
import { createSecondBrainRouter } from "../SecondBrainRouter";

const NOW = "2026-07-20T00:00:00.000Z";
const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function opaqueId(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

function migrationsThrough(version: number): readonly Migration[] {
  return DATABASE_MIGRATIONS.filter((migration) => migration.version <= version);
}

describe("reusable/private memory edge privacy boundary", () => {
  test("quarantines a legacy edge before graph, Vault, and provider-context reads", async () => {
    const directory = mkdtempSync(join(tmpdir(), "memory-edge-boundary-"));
    directories.push(directory);
    const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
    try {
      migrateDatabase(database, migrationsThrough(20));
      const repository = new MemoryRepository(database, { clock: () => new Date(NOW) });
      const reusable = repository.createNode({
        id: opaqueId("reusable-procedure"),
        nodeType: "attack_procedure",
        title: "Bounded application-worker validation",
        summary: "A generalized procedure that requires a healthy worker before a bounded retry.",
        body: "Use a parameterized artifact and stop when the health gate fails.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.95,
        lifecycleStatus: "verified",
        confirmationState: "confirmed",
        provenance: {
          method: "derived",
          explanation: "Generalized locally from a private receipt",
          sources: [{ sourceType: "private_receipt", sourceId: "receipt-private-a", acquiredAt: NOW }],
        },
        authorType: "operator",
        authorId: "operator-reviewer",
        retentionPolicy: { publicProviderDisclosure: "sanitized" },
      });
      const privateTarget = repository.createNode({
        id: "private-operational-target",
        nodeType: "target",
        title: "Private current target",
        summary: "Private operational identity that must never become reusable context.",
        body: "Private target detail.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.95,
        lifecycleStatus: "verified",
        confirmationState: "confirmed",
        provenance: {
          method: "observation",
          explanation: "Private operational fixture",
          sources: [{ sourceType: "private_record", sourceId: "private-target-source", acquiredAt: NOW }],
        },
        authorType: "operator",
        authorId: "operator-reviewer",
        retentionPolicy: { publicProviderDisclosure: "sanitized" },
      });

      // Simulate a row written by a pre-boundary build or direct legacy import.
      database.prepare(`
        INSERT INTO memory_edges (
          id, source_node_id, target_node_id, edge_type, title, summary, scope,
          sensitivity, confidence, lifecycle_status, provenance_json, explanation,
          author_type, author_id, version, expires_at, created_at, updated_at,
          engagement_id, mission_id
        ) VALUES (?, ?, ?, 'supports', 'Legacy support', 'Legacy cross-boundary relation',
          'global', 'internal', 0.9, 'verified', ?, 'Legacy relationship',
          'operator', 'legacy-import', 1, NULL, ?, ?, NULL, NULL)
      `).run(
        "legacy-cross-boundary-edge",
        reusable.id,
        privateTarget.id,
        JSON.stringify(reusable.provenance),
        NOW,
        NOW,
      );

      migrateDatabase(database);
      expect(database.prepare(`
        SELECT edge_id, reason_code, source_node_type, target_node_type
        FROM memory_edge_privacy_quarantine WHERE edge_id = ?
      `).get("legacy-cross-boundary-edge")).toEqual({
        edge_id: "legacy-cross-boundary-edge",
        reason_code: "reusable_private_boundary",
        source_node_type: "attack_procedure",
        target_node_type: "target",
      });
      expect(repository.listEdges(reusable.id)).toEqual([]);
      expect(new CanonicalMemoryReconciliationService(database).analyze().privacyQuarantinedEdges)
        .toEqual([expect.objectContaining({ edgeId: "legacy-cross-boundary-edge" })]);

      const secondBrain = new SecondBrainService(repository);
      const contextPack = secondBrain.retrieveAndPersistContext({
        query: "bounded application worker validation",
        queryRedacted: "bounded application worker validation",
        policy: {
          journey: "guided",
          allowGlobal: true,
          maximumSensitivity: "internal",
          allowedStatuses: ["verified"],
          contextBudget: 4_000,
          limit: 10,
          graphDepth: 1,
          exactNodeIds: [reusable.id],
        },
        purpose: "Privacy-boundary regression",
        createdBy: "operator-reviewer",
      });
      expect(contextPack.items.map((item) => item.nodeId)).toContain(reusable.id);
      expect(contextPack.items.map((item) => item.nodeId)).not.toContain(privateTarget.id);
      const envelope = new BrainContextService({ database, secondBrain }).providerContext({
        hook: "planning",
        status: "ready",
        contextPack,
        items: contextPack.items.map((item) => ({
          node: repository.requireNode(item.nodeId),
          relevanceReason: item.relevanceReason,
        })),
        auditRecordId: "audit-boundary-fixture",
      });
      expect(envelope.items.map((item) => item.nodeId)).toContain(reusable.id);
      expect(envelope.items.map((item) => item.nodeId)).not.toContain(privateTarget.id);

      const vaultRoot = join(directory, "vaults");
      const vault = new ObsidianVaultBridge(database, repository, new VaultPathPolicy(vaultRoot));
      const connection = vault.connect({
        id: "vault-boundary",
        vaultPath: "Attack-Brain",
        displayName: "Attack Brain",
        permissionGranted: true,
      });
      const exported = vault.exportNode(connection.id, reusable.id);
      const exportedText = readFileSync(join(connection.vaultPath, exported.relativePath), "utf8");
      expect(exportedText).not.toContain(privateTarget.id);
      expect(exportedText).not.toContain("legacy-cross-boundary-edge");

      const unsafeImport = `${exportedText}\n## Relationships\n\n- [[Private current target]] <!-- ti-scale-edge:supports:${privateTarget.id} -->\n`;
      writeFileSync(join(connection.vaultPath, exported.relativePath), unsafeImport, "utf8");
      expect(() => vault.importNote(connection.id, exported.relativePath, "operator-reviewer", true))
        .toThrow("cannot cross the reusable/private memory boundary");

      const app = express();
      app.use(createSecondBrainRouter({
        database,
        resolveActor: () => "operator-reviewer",
        resolveAccess: () => ({ maximumSensitivity: "internal", allowGlobal: true }),
      }));
      const server = app.listen(0, "127.0.0.1");
      servers.push(server);
      await new Promise<void>((resolve) => server.once("listening", resolve));
      const port = (server.address() as AddressInfo).port;
      const response = await fetch(
        `http://127.0.0.1:${port}/api/v2/brain/graph?view=local&nodeId=${encodeURIComponent(reusable.id)}&depth=1&limit=50`,
      );
      expect(response.status).toBe(200);
      const graph = await response.json() as {
        nodes: Array<{ id: string }>;
        edges: Array<{ id: string }>;
      };
      expect(graph.nodes.map((node) => node.id)).toEqual([reusable.id]);
      expect(graph.edges).toEqual([]);
    } finally {
      database.close();
    }
  });
});

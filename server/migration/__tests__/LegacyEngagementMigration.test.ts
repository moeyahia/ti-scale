import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import { ObsidianVaultBridge, parseObsidianNote, VaultPathPolicy } from "../../vault";
import { ApprovedLegacyVaultProjectionService } from "../ApprovedLegacyVaultProjectionService";
import {
  canonicalizeLegacySourceRoots,
  discoverLegacyEngagements,
} from "../LegacyEngagementDiscovery";
import { LegacyMigrationService } from "../LegacyMigrationService";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "ti-scale-engagement-migration-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function write(path: string, content: string | Uint8Array): void {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, content, { mode: 0o600 });
}

function createEngagement(root: string): { engagement: string; secret: string } {
  const engagement = join(root, "customer-portal");
  write(join(engagement, "scans/service.nmap"), [
    "Nmap scan report for portal.example.test (192.0.2.45)",
    "Host is up (0.0040s latency).",
    "PORT    STATE SERVICE VERSION",
    "443/tcp open  https   nginx 1.24",
    "Running: Linux 5.X",
    "",
  ].join("\n"));
  write(join(engagement, "report/report.md"), "# Historical report\nReview required.\n");
  write(join(engagement, "loot/public.txt"), "non-secret historical username: analyst\n");
  write(join(engagement, "notes/overview.md"), "Authorized-history note with no inferred current authorization.\n");
  write(join(engagement, "scripts/check.sh"), "#!/bin/sh\nprintf 'read-only check'\n");
  write(join(engagement, "captures/page.png"), new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]));
  write(join(engagement, "evidence/proof.txt"), "Potential support awaiting claim validation.\n");
  write(join(engagement, "logs/raw.log"), "stdout is a troubleshooting log, not verified evidence\n");
  const secret = "provider-secret-value-123";
  write(join(engagement, "notes/operator.txt"), `access_token=${secret}\n`);
  write(join(engagement, "loot/password.txt"), "password=must-not-import\n");
  symlinkSync(join(engagement, "notes/overview.md"), join(engagement, "notes/linked.md"));
  return { engagement, secret };
}

function createCanonicalDatabase(path: string): void {
  const database = createDatabaseConnection({ filename: path });
  try { migrateDatabase(database); }
  finally { database.close(); }
}

function count(database: ReturnType<typeof createDatabaseConnection>, table: string): number {
  return (database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
}

function markdownFiles(root: string): string[] {
  if (!existsSync(root)) return [];
  const output: string[] = [];
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop()!;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile() && entry.name.endsWith(".md")) output.push(path);
    }
  }
  return output.sort();
}

describe("historical engagement discovery", () => {
  test("canonicalizes physical aliases and creates a stable secret-safe classified manifest", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    mkdirSync(legacy, { recursive: true });
    const fixture = createEngagement(legacy);
    const alias = join(directory, "legacy-alias");
    symlinkSync(legacy, alias, "dir");

    const roots = canonicalizeLegacySourceRoots([legacy, alias]);
    expect(roots.roots).toHaveLength(1);
    expect(roots.aliases).toHaveLength(1);
    expect(roots.missing).toHaveLength(0);

    const first = await discoverLegacyEngagements([legacy, alias]);
    const second = await discoverLegacyEngagements([alias, legacy]);
    expect(first.manifests).toHaveLength(1);
    expect(first.manifests[0]!.id).toBe(second.manifests[0]!.id);
    expect(first.manifests[0]!.sha256).toBe(second.manifests[0]!.sha256);
    expect(first.manifests[0]!.files.map((file) => file.kind).sort()).toEqual([
      "capture", "evidence", "log", "loot", "note", "recon", "report", "script",
    ]);
    expect(first.excluded.filter((item) => item.absolutePath.startsWith(fixture.engagement))).toHaveLength(3);
    expect(first.excluded.map((item) => item.category).sort()).toEqual([
      "sensitive_content", "symlink", "unsafe_name",
    ]);
    expect(first.manifests[0]!.files.every((file) => file.sha256.length === 64)).toBe(true);
  });

  test("treats an explicitly selected engagement directory as one engagement", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    mkdirSync(legacy, { recursive: true });
    const fixture = createEngagement(legacy);

    const discovery = await discoverLegacyEngagements([fixture.engagement], { rootMode: "self" });

    expect(discovery.manifests).toHaveLength(1);
    expect(discovery.manifests[0]!.engagementName).toBe("customer-portal");
    expect(discovery.manifests[0]!.engagementDirectory).toBe(fixture.engagement);
    expect(discovery.manifests[0]!.files.map((file) => file.relativePath)).toContain("scans/service.nmap");
    expect(discovery.manifests[0]!.files.some((file) => file.relativePath.startsWith("scans/"))).toBe(true);
  });
});

describe("historical engagement import and approved Vault projection", () => {
  test("imports an explicit engagement root as one canonical mission", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const output = join(directory, "migration-output");
    const databasePath = join(directory, "ti-scale.sqlite");
    mkdirSync(legacy, { recursive: true });
    const fixture = createEngagement(legacy);
    createCanonicalDatabase(databasePath);

    await new LegacyMigrationService({
      databasePath,
      sourceRoots: [],
      engagementRoots: [fixture.engagement],
      outputDirectory: output,
    }).run();

    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(count(database, "missions")).toBe(1);
      expect(count(database, "runs")).toBe(1);
      expect(count(database, "legacy_engagement_manifests")).toBe(1);
      expect((database.prepare("SELECT name FROM missions").get() as { name: string }).name).toBe("customer-portal");
      expect(count(database, "artifacts")).toBe(9);
    } finally {
      database.close();
    }
  });

  test("imports once, preserves log/evidence semantics, projects a connected Brain, and gates Vault writes", async () => {
    const directory = temporaryDirectory();
    const legacy = join(directory, "legacy");
    const output = join(directory, "migration-output");
    const databasePath = join(directory, "ti-scale.sqlite");
    mkdirSync(legacy, { recursive: true });
    const fixture = createEngagement(legacy);
    const alias = join(directory, "legacy-alias");
    symlinkSync(legacy, alias, "dir");
    createCanonicalDatabase(databasePath);
    const originalLog = readFileSync(join(fixture.engagement, "logs/raw.log"));

    const dryRun = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy, alias],
      outputDirectory: output,
      dryRun: true,
    }).run();
    expect(dryRun.report.engagementDiscovery).toMatchObject({
      manifests: 1,
      classifiedFiles: 8,
      quarantinedPaths: 3,
    });
    expect(dryRun.report.engagementDiscovery?.rootAliases).toHaveLength(1);
    expect(dryRun.report.targets).toEqual({});

    const first = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [legacy, alias],
      outputDirectory: output,
    }).run();
    expect(first.report.counts).toMatchObject({ sources: 1, imported: 9, quarantined: 3 });
    expect(first.report.engagementDiscovery?.rootAliases).toHaveLength(1);
    expect(readFileSync(join(fixture.engagement, "logs/raw.log")).equals(originalLog)).toBe(true);

    let reconciliationHash: string;
    const database = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(count(database, "missions")).toBe(1);
      expect(count(database, "runs")).toBe(1);
      expect(count(database, "artifacts")).toBe(9);
      expect(count(database, "engagement_log_records")).toBe(1);
      expect(count(database, "evidence_candidates")).toBe(2);
      expect(count(database, "evidence")).toBe(0);
      expect(count(database, "memory_nodes")).toBe(16);
      expect(count(database, "memory_edges")).toBe(17);
      expect(count(database, "legacy_engagement_manifests")).toBe(1);
      expect(count(database, "legacy_migration_quarantine")).toBe(3);
      expect((database.prepare("SELECT authorization_status FROM missions").get() as { authorization_status: string }).authorization_status).toBe("unverified");
      expect((database.prepare("SELECT control_plane FROM missions").get() as { control_plane: string }).control_plane).toBe("legacy");
      expect((database.prepare("SELECT status FROM runs").get() as { status: string }).status).toBe("blocked");
      expect((database.prepare("SELECT control_plane FROM runs").get() as { control_plane: string }).control_plane).toBe("legacy");
      expect((database.prepare("SELECT technical_payload_json FROM engagement_log_records").get() as { technical_payload_json: string }).technical_payload_json)
        .toContain('"rawOutputIsEvidence":false');
      expect((database.prepare("SELECT COUNT(*) AS count FROM memory_edges WHERE lifecycle_status='verified'").get() as { count: number }).count).toBe(15);
      const assetObservation = database.prepare(`
        SELECT title, summary, body FROM memory_nodes WHERE node_type = 'asset'
      `).get() as { title: string; summary: string; body: string };
      expect(assetObservation.title).toContain("192.0.2.45");
      expect(assetObservation.summary).toContain("current reachability is unverified");
      expect(assetObservation.body).toContain("portal.example.test");
      const serviceObservation = database.prepare(`
        SELECT title, summary, body FROM memory_nodes WHERE node_type = 'entity'
      `).get() as { title: string; summary: string; body: string };
      expect(serviceObservation.title).toContain("192.0.2.45:443/tcp");
      expect(serviceObservation.body).toContain("nginx 1.24");
      expect((database.prepare(`
        SELECT COUNT(*) AS count FROM memory_edges
        WHERE edge_type = 'belongs_to'
          AND source_node_id = (SELECT id FROM memory_nodes WHERE node_type = 'entity')
          AND target_node_id = (SELECT id FROM memory_nodes WHERE node_type = 'asset')
      `).get() as { count: number }).count).toBe(1);
      const verifiedNodes = (database.prepare("SELECT id FROM memory_nodes WHERE lifecycle_status='verified'").all() as Array<{ id: string }>).map((row) => row.id);
      const visibleEdgeNodes = new Set((database.prepare(`
        SELECT source_node_id AS id FROM memory_edges WHERE lifecycle_status='verified'
        UNION SELECT target_node_id AS id FROM memory_edges WHERE lifecycle_status='verified'
      `).all() as Array<{ id: string }>).map((row) => row.id));
      expect(verifiedNodes.every((id) => visibleEdgeNodes.has(id))).toBe(true);
      const canonicalText = (database.prepare(`
        SELECT title || ' ' || summary || ' ' || body AS text FROM memory_nodes
        UNION ALL SELECT human_summary || ' ' || technical_payload_json FROM engagement_log_records
      `).all() as Array<{ text: string }>).map((row) => row.text).join("\n");
      expect(canonicalText).not.toContain(fixture.secret);
      reconciliationHash = (database.prepare(`
        SELECT report_hash FROM legacy_migration_reconciliation WHERE migration_id = ?
      `).get(first.migrationId) as { report_hash: string }).report_hash;
    } finally {
      database.close();
    }

    const second = await new LegacyMigrationService({
      databasePath,
      sourceRoots: [alias, legacy],
      outputDirectory: output,
    }).run();
    expect(second.report.counts).toMatchObject({ sources: 1, imported: 0, deduplicated: 12, quarantined: 0 });
    const afterSecond = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      expect(count(afterSecond, "missions")).toBe(1);
      expect(count(afterSecond, "runs")).toBe(1);
      expect(count(afterSecond, "artifacts")).toBe(9);
      expect(count(afterSecond, "memory_nodes")).toBe(16);
      expect(count(afterSecond, "memory_edges")).toBe(17);
    } finally {
      afterSecond.close();
    }

    const writable = createDatabaseConnection({ filename: databasePath, fileMustExist: true });
    try {
      const allowedVaults = join(directory, "allowed-vaults");
      const bridge = new ObsidianVaultBridge(
        writable,
        new MemoryRepository(writable),
        new VaultPathPolicy(allowedVaults),
      );
      const connection = bridge.connect({
        id: "legacy-projection-test",
        vaultPath: "Ti-Scale-Brain",
        displayName: "Imported engagement Brain",
        permissionGranted: true,
      });
      const approval = new ApprovedLegacyVaultProjectionService(writable, bridge);
      const preview = approval.preview({
        migrationId: first.migrationId,
        expectedReconciliationHash: reconciliationHash!,
        connectionId: connection.id,
      });
      expect(preview.eligibleNodeCount).toBe(14);
      expect(preview.projectionHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(markdownFiles(connection.vaultPath)).toHaveLength(0);
      await expect(approval.project({
        migrationId: first.migrationId,
        expectedReconciliationHash: "0".repeat(64),
        expectedProjectionHash: preview.projectionHash,
        connectionId: connection.id,
        approvedBy: "operator-test",
      })).rejects.toThrow("does not match");
      expect(markdownFiles(connection.vaultPath)).toHaveLength(0);

      writable.prepare("UPDATE vault_connections SET status='disconnected' WHERE id=?").run(connection.id);
      await expect(approval.project({
        migrationId: first.migrationId,
        expectedReconciliationHash: reconciliationHash!,
        expectedProjectionHash: preview.projectionHash,
        connectionId: connection.id,
        approvedBy: "operator-test",
      })).rejects.toThrow("active connected");
      expect(markdownFiles(connection.vaultPath)).toHaveLength(0);
      writable.prepare("UPDATE vault_connections SET status='connected' WHERE id=?").run(connection.id);

      const projected = await approval.project({
        migrationId: first.migrationId,
        expectedReconciliationHash: reconciliationHash!,
        expectedProjectionHash: preview.projectionHash,
        connectionId: connection.id,
        approvedBy: "operator-test",
      });
      expect(projected.projectedNodeIds).toHaveLength(14);
      expect(projected.export).toMatchObject({ total: 14, processed: 14 });
      expect(projected.export.counts).toMatchObject({ synced: 14, failed: 0, conflicts: 0 });
      const notes = markdownFiles(connection.vaultPath);
      expect(notes).toHaveLength(14);
      const parsed = notes.map((path) => ({ path, note: parseObsidianNote(readFileSync(path, "utf8")) }));
      expect(parsed.every((item) => item.note.aliases.includes(item.note.id))).toBe(true);
      const run = parsed.find((item) => item.note.nodeType === "run");
      expect(run).toBeDefined();
      expect(run!.note.edges).toHaveLength(1);
      expect(run!.note.edges[0]).toMatchObject({ edgeType: "belongs_to" });
      const artifacts = parsed.filter((item) => item.note.nodeType === "artifact");
      expect(artifacts).toHaveLength(9);
      expect(parsed.filter((item) => item.note.nodeType === "asset")).toHaveLength(1);
      expect(parsed.filter((item) => item.note.nodeType === "entity")).toHaveLength(1);
      for (const artifact of artifacts) {
        expect(readFileSync(artifact.path, "utf8"))
          .toContain(`<!-- ti-scale-backlink:produced:${run!.note.id} -->`);
      }
      expect(readFileSync(run!.path, "utf8")).toContain("[[");
      expect(notes.map((path) => readFileSync(path, "utf8")).join("\n")).not.toContain(fixture.secret);
      expect(count(writable, "legacy_vault_projection_approvals")).toBe(1);
      expect((writable.prepare("SELECT status FROM legacy_vault_projection_approvals").get() as { status: string }).status).toBe("completed");
    } finally {
      writable.close();
    }
  });
});

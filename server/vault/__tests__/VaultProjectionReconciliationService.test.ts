import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory";
import {
  attackKnowledgeVaultSyncScope,
  ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
  ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
} from "../AttackKnowledgeVaultPreset";
import { ObsidianVaultBridge } from "../ObsidianVaultBridge";
import { VaultPathPolicy } from "../VaultPathPolicy";
import { VaultProjectionReconciliationService } from "../VaultProjectionReconciliationService";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function id(label: string): string {
  return `mem_${createHash("sha256").update(label).digest("hex")}`;
}

function setup() {
  const root = mkdtempSync(join(tmpdir(), "vault-projection-reconciliation-"));
  directories.push(root);
  const databasePath = join(root, "ti-scale.sqlite");
  const vaultRoot = join(root, "vaults");
  const database = createDatabaseConnection({ filename: databasePath });
  migrateDatabase(database);
  const memory = new MemoryRepository(database, {
    clock: () => new Date("2026-07-22T12:00:00.000Z"),
  });
  const paths = new VaultPathPolicy(vaultRoot);
  const bridge = new ObsidianVaultBridge(database, memory, paths, {
    clock: () => new Date("2026-07-22T12:00:00.000Z"),
  });
  const connection = bridge.connect({
    id: "vault-attack-knowledge-reconciliation",
    vaultPath: ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
    displayName: ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
    syncScope: attackKnowledgeVaultSyncScope({ includeConfirmed: true }),
    permissionGranted: true,
  });
  const provenance = {
    method: "operator_statement" as const,
    explanation: "Explicitly reviewed reusable attack knowledge fixture.",
    sources: [{
      sourceType: "test_fixture",
      sourceId: "vault-projection-reconciliation",
      acquiredAt: "2026-07-22T12:00:00.000Z",
    }],
  };
  const technology = memory.createNode({
    id: id("technology"),
    nodeType: "technology_product",
    title: "Reusable web platform",
    summary: "A reusable product identity without target locators.",
    body: "Match this product identity before selecting a bounded procedure.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 1,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance,
    authorType: "operator",
    authorId: "operator:test",
  });
  const procedure = memory.createNode({
    id: id("procedure"),
    nodeType: "attack_procedure",
    title: "Bounded validation procedure",
    summary: "Check product applicability before one reversible validation step.",
    body: "Stop when the health check fails and retain only normalized outcomes.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 1,
    lifecycleStatus: "confirmed",
    confirmationState: "confirmed",
    provenance,
    authorType: "operator",
    authorId: "operator:test",
  });
  memory.createEdge({
    sourceNodeId: procedure.id,
    targetNodeId: technology.id,
    edgeType: "depends_on",
    title: "Procedure requires a matching technology",
    summary: "The procedure is applicable only to the matching reusable product identity.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 1,
    lifecycleStatus: "confirmed",
    provenance,
    explanation: "An exact technology match is a prerequisite for this procedure.",
    authorType: "operator",
    authorId: "operator:test",
  });
  const service = new VaultProjectionReconciliationService(database, bridge, paths, {
    clock: () => new Date("2026-07-22T12:00:00.000Z"),
  });
  return {
    root,
    databasePath,
    vaultRoot,
    database,
    memory,
    paths,
    bridge,
    connection,
    service,
    technology,
    procedure,
    provenance,
  };
}

function receiptFiles(vaultPath: string): string[] {
  const directory = join(vaultPath, ".ti-scale", "projection-receipts");
  return existsSync(directory) ? readdirSync(directory).sort() : [];
}

describe("VaultProjectionReconciliationService", () => {
  test("previews read-only, projects the complete eligible set, resolves links, and replays idempotently", async () => {
    const fixture = setup();
    try {
      const preview = fixture.service.preview(fixture.connection.id);
      expect(preview).toMatchObject({
        eligibleNodeCount: 2,
        trackedNodeCount: 0,
        currentNodeCount: 0,
        writeRequiredNodeCount: 2,
        attentionRequiredNodeCount: 0,
        readyForExecution: true,
        issueCount: 0,
      });
      expect(preview.planHash).toMatch(/^[a-f0-9]{64}$/u);
      expect((fixture.database.prepare("SELECT COUNT(*) AS count FROM vault_sync_state").get() as { count: number }).count).toBe(0);
      expect(receiptFiles(fixture.connection.vaultPath)).toEqual([]);

      const first = await fixture.service.execute({
        connectionId: fixture.connection.id,
        expectedPlanHash: preview.planHash,
        approvedBy: "operator:test",
        exportOptions: { concurrency: 2, progressInterval: 1 },
      });
      expect(first).toMatchObject({
        status: "completed",
        expectedPlanHash: preview.planHash,
        export: { processed: 2, counts: { synced: 2, failed: 0, conflicts: 0 } },
        reconciliation: {
          status: "complete",
          eligibleNodeCount: 2,
          syncedNodeCount: 2,
          managedMarkdownCount: 2,
          untrackedManagedMarkdownCount: 0,
          unresolvedWikilinkCount: 0,
          unsafeContentCount: 0,
        },
      });
      expect(first.receiptHash).toMatch(/^[a-f0-9]{64}$/u);
      const receiptPath = join(fixture.connection.vaultPath, first.receiptRelativePath);
      expect(statSync(receiptPath).mode & 0o777).toBe(0o600);
      expect(JSON.parse(readFileSync(receiptPath, "utf8"))).toMatchObject({
        receiptHash: first.receiptHash,
        status: "completed",
      });
      const procedurePath = join(
        fixture.connection.vaultPath,
        fixture.bridge.renderNode(fixture.procedure.id, fixture.connection).relativePath,
      );
      expect(readFileSync(procedurePath, "utf8")).toContain("[[20 Technology Products/");

      const resumedPreview = fixture.service.preview(fixture.connection.id);
      expect(resumedPreview.planHash).toBe(preview.planHash);
      expect(resumedPreview).toMatchObject({ currentNodeCount: 2, writeRequiredNodeCount: 0 });
      const replay = await fixture.service.execute({
        connectionId: fixture.connection.id,
        expectedPlanHash: resumedPreview.planHash,
        approvedBy: "operator:test",
      });
      expect(replay.status).toBe("completed");
      expect(replay.export.counts).toMatchObject({ skipped: 2, synced: 0, failed: 0 });
      expect(receiptFiles(fixture.connection.vaultPath)).toHaveLength(2);
    } finally {
      fixture.database.close();
    }
  });

  test("rejects a stale reviewed plan before writing notes or receipts", async () => {
    const fixture = setup();
    try {
      const preview = fixture.service.preview(fixture.connection.id);
      fixture.memory.correctNode(fixture.procedure.id, {
        summary: "A corrected reusable procedure changes the reviewed projection.",
        authorType: "operator",
        authorId: "operator:test",
        changeReason: "Exercise stale projection-plan rejection",
      });
      await expect(fixture.service.execute({
        connectionId: fixture.connection.id,
        expectedPlanHash: preview.planHash,
        approvedBy: "operator:test",
      })).rejects.toThrow("plan changed after review");
      expect((fixture.database.prepare("SELECT COUNT(*) AS count FROM vault_sync_state").get() as { count: number }).count).toBe(0);
      expect(receiptFiles(fixture.connection.vaultPath)).toEqual([]);
    } finally {
      fixture.database.close();
    }
  });

  test("treats canonical node and edge changes as a safe database-ahead projection", async () => {
    const fixture = setup();
    try {
      const initial = fixture.service.preview(fixture.connection.id);
      await fixture.service.execute({
        connectionId: fixture.connection.id,
        expectedPlanHash: initial.planHash,
        approvedBy: "operator:test",
      });
      const technique = fixture.memory.createNode({
        id: id("technique"),
        nodeType: "attack_technique",
        title: "Bounded application validation",
        summary: "A reusable validation technique selected only after a confirmed product match.",
        body: "Use one reversible request, verify health, and stop before repeating a destabilizing action.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 1,
        lifecycleStatus: "confirmed",
        confirmationState: "confirmed",
        provenance: fixture.provenance,
        authorType: "operator",
        authorId: "operator:test",
      });
      fixture.memory.createEdge({
        sourceNodeId: fixture.procedure.id,
        targetNodeId: technique.id,
        edgeType: "classified_as",
        title: "Procedure is classified as the bounded technique",
        summary: "The procedure is one reusable implementation of the confirmed technique.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 1,
        lifecycleStatus: "confirmed",
        provenance: fixture.provenance,
        explanation: "The canonical graph gained a reviewed reusable relationship.",
        authorType: "operator",
        authorId: "operator:test",
      });

      const changed = fixture.service.preview(fixture.connection.id);
      expect(changed.planHash).not.toBe(initial.planHash);
      expect(changed).toMatchObject({
        eligibleNodeCount: 3,
        currentNodeCount: 1,
        writeRequiredNodeCount: 2,
        attentionRequiredNodeCount: 0,
        readyForExecution: true,
      });
      const projected = await fixture.service.execute({
        connectionId: fixture.connection.id,
        expectedPlanHash: changed.planHash,
        approvedBy: "operator:test",
      });
      expect(projected.status).toBe("completed");
      expect(projected.reconciliation).toMatchObject({
        status: "complete",
        eligibleNodeCount: 3,
        syncedNodeCount: 3,
        unresolvedWikilinkCount: 0,
      });
    } finally {
      fixture.database.close();
    }
  });

  test("preserves an unmanaged operator note and blocks execution until conflict recovery", async () => {
    const fixture = setup();
    try {
      const rendered = fixture.bridge.renderNode(fixture.procedure.id, fixture.connection);
      const path = join(fixture.connection.vaultPath, rendered.relativePath);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, rendered.text.replace(
        "Stop when the health check fails",
        "Operator-authored content must remain untouched",
      ), { mode: 0o600 });
      const before = readFileSync(path, "utf8");
      const preview = fixture.service.preview(fixture.connection.id);
      expect(preview).toMatchObject({
        eligibleNodeCount: 2,
        attentionRequiredNodeCount: 1,
        readyForExecution: false,
      });
      expect(preview.issues).toContainEqual(expect.objectContaining({ category: "content_mismatch" }));
      await expect(fixture.service.execute({
        connectionId: fixture.connection.id,
        expectedPlanHash: preview.planHash,
        approvedBy: "operator:test",
      })).rejects.toThrow("requires conflict or connection recovery");
      expect(readFileSync(path, "utf8")).toBe(before);
      expect(receiptFiles(fixture.connection.vaultPath)).toEqual([]);
    } finally {
      fixture.database.close();
    }
  });

  test("reconciliation detects changed content and unresolved native wikilinks", async () => {
    const fixture = setup();
    try {
      const preview = fixture.service.preview(fixture.connection.id);
      await fixture.service.execute({
        connectionId: fixture.connection.id,
        expectedPlanHash: preview.planHash,
        approvedBy: "operator:test",
      });
      const state = fixture.database.prepare(`
        SELECT relative_path FROM vault_sync_state
        WHERE connection_id = ? AND node_id = ?
      `).get(fixture.connection.id, fixture.procedure.id) as { relative_path: string };
      const path = join(fixture.connection.vaultPath, state.relative_path);
      writeFileSync(path, `${readFileSync(path, "utf8")}\n[[42 Techniques and Procedures/missing-procedure]]\n`);
      const result = fixture.service.reconcile(fixture.connection.id, preview.planHash);
      expect(result.status).toBe("attention_required");
      expect(result.unresolvedWikilinkCount).toBe(1);
      expect(result.issues).toEqual(expect.arrayContaining([
        expect.objectContaining({ category: "content_mismatch" }),
        expect.objectContaining({ category: "unresolved_wikilink" }),
      ]));
    } finally {
      fixture.database.close();
    }
  });

  test("ordinary sync verification does not report a pending import as healthy", () => {
    const fixture = setup();
    try {
      const pendingPath = "00 Inbox/operator-draft.md";
      writeFileSync(join(fixture.connection.vaultPath, pendingPath), "operator draft\n", { mode: 0o600 });
      fixture.database.prepare(`
        INSERT INTO vault_sync_state (
          id, connection_id, node_id, relative_path, status
        ) VALUES ('vsync-pending-health', ?, NULL, ?, 'pending')
      `).run(fixture.connection.id, pendingPath);
      const verified = fixture.bridge.verifyConnection(fixture.connection.id);
      expect(verified.counts.pending).toBe(1);
      expect(verified.healthy).toBe(false);
      const preview = fixture.service.preview(fixture.connection.id);
      expect(preview).toMatchObject({
        readyForExecution: false,
        attentionRequiredNodeCount: 1,
      });
      expect(preview.issues).toEqual(expect.arrayContaining([
        expect.objectContaining({ category: "unexpected_state", relativePath: pendingPath }),
      ]));
    } finally {
      fixture.database.close();
    }
  });

  test("CLI preview opens the canonical database read-only and creates no lease or projection state", async () => {
    const fixture = setup();
    const databasePath = fixture.databasePath;
    const vaultRoot = fixture.vaultRoot;
    const connectionId = fixture.connection.id;
    fixture.database.close();
    const child = Bun.spawn([
      process.execPath,
      "run",
      "server/vault/vault-projection-reconciliation-cli.ts",
      "preview",
      "--db", databasePath,
      "--vault-root", vaultRoot,
      "--connection", connectionId,
    ], {
      cwd: process.cwd(),
      env: process.env,
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(exitCode).toBe(0);
    expect(stderr).toBe("");
    expect(JSON.parse(stdout)).toMatchObject({ eligibleNodeCount: 2, readyForExecution: true });
    const verified = createDatabaseConnection({ filename: databasePath, readonly: true, fileMustExist: true });
    try {
      expect(verified.prepare("SELECT COUNT(*) AS count FROM canonical_database_leases").get()).toEqual({ count: 0 });
      expect(verified.prepare("SELECT COUNT(*) AS count FROM vault_sync_state").get()).toEqual({ count: 0 });
    } finally {
      verified.close();
    }
  });
});

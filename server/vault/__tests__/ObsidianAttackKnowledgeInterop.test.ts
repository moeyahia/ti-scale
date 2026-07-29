import { afterEach, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import {
  ATTACK_CENTRIC_REUSABLE_NODE_TYPES,
  MemoryRepository,
  type AttackCentricReusableNodeType,
} from "../../memory";
import { attackBrainAtlasMapping } from "../AttackBrainAtlasMappingRegistry";
import { attackKnowledgeVaultSyncScope } from "../AttackKnowledgeVaultPreset";
import { parseObsidianNote } from "../ObsidianMarkdown";
import { ObsidianVaultBridge } from "../ObsidianVaultBridge";
import { VaultPathPolicy } from "../VaultPathPolicy";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "obsidian-attack-interop-"));
  temporaryDirectories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  const repository = new MemoryRepository(database, {
    clock: () => new Date("2026-07-20T21:00:00.000Z"),
  });
  const pathPolicy = new VaultPathPolicy(join(directory, "vault-root"));
  const bridge = new ObsidianVaultBridge(database, repository, pathPolicy);
  const connection = bridge.connect({
    vaultPath: "Attack-Knowledge-Vault",
    displayName: "Ti-Scale Attack Knowledge Vault",
    syncScope: attackKnowledgeVaultSyncScope(),
    permissionGranted: true,
  });
  return { database, repository, bridge, connection };
}

function addAttackNode(
  repository: MemoryRepository,
  sequence: number,
  nodeType: AttackCentricReusableNodeType,
  title: string,
) {
  return repository.createNode({
    id: `mem_${sequence.toString(16).padStart(32, "0")}`,
    nodeType,
    title,
    summary: `Reviewed reusable knowledge item ${sequence}.`,
    body: "Generalized, address-free technical knowledge with reviewed provenance.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.98,
    lifecycleStatus: "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Operator-reviewed promotion receipt retained in canonical storage.",
      sources: [{
        sourceType: "private_receipt",
        sourceId: `akverify_${sequence.toString(16).padStart(64, "0")}`,
        acquiredAt: "2026-07-20T21:00:00.000Z",
      }],
    },
    authorType: "operator",
    authorId: "operator-brain-atlas-test",
  });
}

function visibleMarkdownFiles(root: string, current = root): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    // This mirrors Obsidian/native file-browser visibility: any dot-prefixed
    // path component is hidden from the user-facing note corpus.
    if (entry.name.startsWith(".")) continue;
    const absolute = join(current, entry.name);
    if (entry.isDirectory()) files.push(...visibleMarkdownFiles(root, absolute));
    else if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) {
      files.push(relative(root, absolute));
    }
  }
  return files.sort();
}

describe("Attack Knowledge Vault and Brain Atlas interoperability", () => {
  test("exports 68 visible notes with exact shared brain-region metadata", () => {
    const { database, repository, bridge, connection } = setup();
    try {
      const nodes = Array.from({ length: 68 }, (_, index) => {
        const sequence = index + 1;
        const nodeType = ATTACK_CENTRIC_REUSABLE_NODE_TYPES[
          index % ATTACK_CENTRIC_REUSABLE_NODE_TYPES.length
        ]!;
        const title = index === 0
          ? ".NET Runtime"
          : index === 1
            ? ".NET Execution Component"
            : `Reusable ${nodeType.replaceAll("_", " ")} ${sequence}`;
        return addAttackNode(repository, sequence, nodeType, title);
      });

      for (const node of nodes) {
        const result = bridge.exportNode(connection.id, node.id);
        expect(result.status).toBe("synced");
        expect(basename(result.relativePath).startsWith(".")).toBe(false);
      }

      const files = visibleMarkdownFiles(connection.vaultPath);
      expect(files).toHaveLength(68);
      expect(files.filter((path) => basename(path).startsWith("dot-net-"))).toHaveLength(2);
      for (const path of files) {
        const note = parseObsidianNote(readFileSync(join(connection.vaultPath, path), "utf8"));
        expect(note.brainRegion).toBe(
          attackBrainAtlasMapping(note.nodeType as AttackCentricReusableNodeType).region,
        );
      }
    } finally {
      database.close();
    }
  });

  test("moves a tracked legacy dot-leading note to its visible canonical path without clobbering", () => {
    const { database, repository, bridge, connection } = setup();
    try {
      const node = addAttackNode(repository, 1, "runtime", ".NET Runtime");
      const initial = bridge.exportNode(connection.id, node.id);
      expect(basename(initial.relativePath).startsWith("dot-net-")).toBe(true);
      const canonicalPath = join(connection.vaultPath, initial.relativePath);
      const legacyRelativePath = join(
        dirname(initial.relativePath),
        basename(initial.relativePath).replace(/^dot-net-/u, ".net-"),
      );
      const legacyPath = join(connection.vaultPath, legacyRelativePath);
      renameSync(canonicalPath, legacyPath);
      database.prepare(`
        UPDATE vault_sync_state SET relative_path = ?
        WHERE connection_id = ? AND node_id = ?
      `).run(legacyRelativePath, connection.id, node.id);

      const migrated = bridge.exportNode(connection.id, node.id);
      expect(migrated.status).toBe("synced");
      expect(migrated.relativePath).toBe(initial.relativePath);
      expect(existsSync(canonicalPath)).toBe(true);
      expect(existsSync(legacyPath)).toBe(false);
      expect(database.prepare(`
        SELECT relative_path AS relativePath FROM vault_sync_state
        WHERE connection_id = ? AND node_id = ?
      `).get(connection.id, node.id)).toEqual({ relativePath: initial.relativePath });
    } finally {
      database.close();
    }
  });

  test("reprojects inbound wikilinks when a linked target moves from a hidden legacy path", () => {
    const { database, repository, bridge, connection } = setup();
    try {
      const source = addAttackNode(repository, 1, "technology_product", "Managed Web Platform");
      const target = addAttackNode(repository, 2, "runtime", ".NET Runtime");
      repository.createEdge({
        sourceNodeId: source.id,
        targetNodeId: target.id,
        edgeType: "built_with",
        title: "Managed Web Platform uses .NET Runtime",
        summary: "Reviewed reusable technology-stack relationship.",
        scope: { kind: "global" },
        sensitivity: "internal",
        confidence: 0.98,
        lifecycleStatus: "verified",
        provenance: {
          method: "derived",
          explanation: "Operator-reviewed relationship promotion receipt.",
          sources: [{
            sourceType: "private_receipt",
            sourceId: `akverify_edge_${"2".padStart(48, "0")}`,
            acquiredAt: "2026-07-20T21:00:00.000Z",
          }],
        },
        explanation: "The platform is implemented on this reviewed runtime.",
        authorType: "operator",
        authorId: "operator-brain-atlas-test",
      });

      const targetInitial = bridge.exportNode(connection.id, target.id);
      const canonicalTargetPath = join(connection.vaultPath, targetInitial.relativePath);
      const legacyTargetRelativePath = join(
        dirname(targetInitial.relativePath),
        basename(targetInitial.relativePath).replace(/^dot-net-/u, ".net-"),
      );
      const legacyTargetPath = join(connection.vaultPath, legacyTargetRelativePath);
      renameSync(canonicalTargetPath, legacyTargetPath);
      database.prepare(`
        UPDATE vault_sync_state SET relative_path = ?
        WHERE connection_id = ? AND node_id = ?
      `).run(legacyTargetRelativePath, connection.id, target.id);

      const sourceInitial = bridge.exportNode(connection.id, source.id);
      const sourcePath = join(connection.vaultPath, sourceInitial.relativePath);
      const legacyLinkTarget = legacyTargetRelativePath.slice(0, -3);
      expect(readFileSync(sourcePath, "utf8")).toContain(
        `[[${legacyLinkTarget}|.NET Runtime]]`,
      );

      const targetMigrated = bridge.exportNode(connection.id, target.id);
      expect(targetMigrated).toMatchObject({
        status: "synced",
        relativePath: targetInitial.relativePath,
      });
      const canonicalLinkTarget = targetInitial.relativePath.slice(0, -3);
      const refreshedSource = readFileSync(sourcePath, "utf8");
      expect(refreshedSource).toContain(`[[${canonicalLinkTarget}|.NET Runtime]]`);
      expect(refreshedSource).not.toContain(`[[${legacyLinkTarget}|.NET Runtime]]`);
      expect(database.prepare(`
        SELECT status, error_message AS errorMessage FROM vault_sync_state
        WHERE connection_id = ? AND node_id = ?
      `).get(connection.id, source.id)).toEqual({ status: "synced", errorMessage: null });
    } finally {
      database.close();
    }
  });

  test("preserves an operator-edited hidden legacy note for explicit reconciliation", () => {
    const { database, repository, bridge, connection } = setup();
    try {
      const node = addAttackNode(repository, 1, "runtime", ".NET Runtime");
      const initial = bridge.exportNode(connection.id, node.id);
      const canonicalPath = join(connection.vaultPath, initial.relativePath);
      const legacyRelativePath = join(
        dirname(initial.relativePath),
        basename(initial.relativePath).replace(/^dot-net-/u, ".net-"),
      );
      const legacyPath = join(connection.vaultPath, legacyRelativePath);
      renameSync(canonicalPath, legacyPath);
      database.prepare(`
        UPDATE vault_sync_state SET relative_path = ?
        WHERE connection_id = ? AND node_id = ?
      `).run(legacyRelativePath, connection.id, node.id);
      writeFileSync(
        legacyPath,
        readFileSync(legacyPath, "utf8").replace(
          "Generalized, address-free technical knowledge with reviewed provenance.",
          "Operator edited this legacy note before filename reconciliation.",
        ),
      );

      const result = bridge.exportNode(connection.id, node.id);
      expect(result.status).toBe("vault_ahead");
      expect(result.relativePath).toBe(legacyRelativePath);
      expect(existsSync(legacyPath)).toBe(true);
      expect(existsSync(canonicalPath)).toBe(false);
    } finally {
      database.close();
    }
  });
});

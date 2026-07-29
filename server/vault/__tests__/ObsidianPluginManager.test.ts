import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { createHash } from "node:crypto";
import {
  chownSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory/MemoryRepository";
import { createSecondBrainRouter } from "../../memory/SecondBrainRouter";
import { OperatorPreferenceImportService } from "../../memory/OperatorPreferenceImportService";
import {
  OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY,
  parseOperatorPreferenceManifest,
} from "../../memory/OperatorPreferenceManifest";
import type { TrustedLocalFileReceipt } from "../../trusted-runtime-config";
import { attackKnowledgeVaultSyncScope } from "../AttackKnowledgeVaultPreset";
import { ObsidianVaultBridge } from "../ObsidianVaultBridge";
import {
  ObsidianPluginManager,
  type BrainAtlasPinnedRelease,
} from "../ObsidianPluginManager";
import { writePortableZip } from "../PortableZip";
import { VaultPathPolicy } from "../VaultPathPolicy";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function hash(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "brain-atlas-manager-"));
  directories.push(root);
  const database = createDatabaseConnection({ filename: join(root, "brain.sqlite") });
  migrateDatabase(database);
  const policy = new VaultPathPolicy(join(root, "vaults"));
  const repository = new MemoryRepository(database);
  const bridge = new ObsidianVaultBridge(database, repository, policy);
  const connection = bridge.connect({
    vaultPath: "Attack-Knowledge-Vault",
    displayName: "Ti-Scale Attack Knowledge Vault",
    syncScope: attackKnowledgeVaultSyncScope(),
    permissionGranted: true,
  });
  const source = join(root, "source");
  mkdirSync(source, { recursive: true });
  const manifest = Buffer.from(JSON.stringify({
    id: "brain-atlas",
    name: "Brain Atlas",
    version: "9.9.9-test",
    minAppVersion: "1.5.0",
  }));
  const main = Buffer.from("/* deterministic test plugin */\n");
  const styles = Buffer.from(".brain-atlas-test { display: block; }\n");
  const license = Buffer.from("MIT test fixture\n");
  for (const [name, bytes] of [["manifest.json", manifest], ["main.js", main], ["styles.css", styles], ["LICENSE", license]] as const) {
    writeFileSync(join(source, name), bytes);
  }
  const release: BrainAtlasPinnedRelease = {
    pluginId: "brain-atlas",
    version: "9.9.9-test",
    repository: "https://example.invalid/brain-atlas-test",
    commit: "a".repeat(40),
    license: "MIT",
    minimumObsidianVersion: "1.5.0",
    assets: { "main.js": hash(main), "manifest.json": hash(manifest), "styles.css": hash(styles) },
    licenseFile: { name: "LICENSE", sha256: hash(license) },
  };
  const manager = new ObsidianPluginManager({
    database,
    pathPolicy: policy,
    release,
    clock: () => new Date("2026-07-20T20:00:00.000Z"),
  });
  return {
    root, database, repository, policy, bridge, connection, source, release, manager,
  };
}

function addExplicitOperatorProfile(database: ReturnType<typeof createDatabaseConnection>) {
  const manifest = parseOperatorPreferenceManifest({
    schemaVersion: "ti-scale.operator-preferences.v2",
    manifestVersion: "brain-atlas-health-profile-v1",
    operatorId: "operator:test",
    retentionPolicy: {
      durableOnly: true,
      excludeOneTimeCommands: true,
      excludeTargetSpecificData: true,
      excludeCredentialsAndSecrets: true,
    },
    safetyBoundary: OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY,
    source: {
      sourceType: "operator_instruction_manifest",
      sourceId: "brain-atlas-health-profile",
      acquiredAt: "2026-07-20T20:00:00.000Z",
    },
    preferences: [{
      id: "technical-readable",
      preferenceKey: "communication.technical_readability",
      category: "communication",
      title: "Readable technical language",
      summary: "Keep accurate explanations readable without making them simplistic.",
      body: "Explain purpose, operational meaning, evidence, and useful technical detail.",
      value: { style: "technical_readable" },
      appliesTo: ["guided_explanations"],
      sensitivity: "private",
      consentPolicy: "explicit_operator_confirmation",
    }],
  });
  const receipt: TrustedLocalFileReceipt = {
    schemaVersion: "ti-scale.trusted-local-file-receipt.v1",
    sourcePath: "/trusted/brain-atlas-health-profile.json",
    trustRoot: "/trusted",
    sourceSha256: "a".repeat(64),
    canonicalSha256: "b".repeat(64),
    byteSize: 1_024,
    ownerUid: 0,
    ownerGid: 0,
    mode: 0o644,
    device: "1",
    inode: "2",
  };
  const service = new OperatorPreferenceImportService(database, {
    clock: () => new Date("2026-07-20T20:00:00.000Z"),
  });
  const preview = service.preview({ manifest, receipt, actorId: "operator:test" });
  const result = service.execute({
    manifest,
    receipt,
    actorId: "operator:test",
    expectedPreviewHash: preview.previewHash,
    reason: "Operator approved this explicit profile for Brain Atlas health tests",
  });
  return {
    operatorNodeId: result.operatorNodeId,
    preferenceNodeId: result.nodeIds[0]!,
    applicabilityNodeId: preview.graph.applicability[0]!.id,
  };
}

describe("ObsidianPluginManager", () => {
  test("installs the pinned plugin forward-only while preserving unrelated plugins and user settings", () => {
    const state = fixture();
    const obsidian = join(state.connection.vaultPath, ".obsidian");
    const otherPlugin = join(obsidian, "plugins", "operator-plugin");
    const atlas = join(obsidian, "plugins", "brain-atlas");
    mkdirSync(otherPlugin, { recursive: true });
    mkdirSync(atlas, { recursive: true });
    writeFileSync(join(otherPlugin, "main.js"), "operator-owned-plugin");
    writeFileSync(join(obsidian, "community-plugins.json"), JSON.stringify(["operator-plugin"]));
    const workspace = Buffer.from('{"operatorLayout":true}\n');
    writeFileSync(join(obsidian, "workspace.json"), workspace);
    writeFileSync(join(atlas, "operator-note.txt"), "preserve me");
    writeFileSync(join(atlas, "data.json"), JSON.stringify({
      palette: "graphite",
      pinnedNodePositions: { "note.md": { x: 4, y: 5, z: 6 } },
      futureSetting: "preserved",
      frontmatterKindValueMap: { "type:attack_vector": "incident" },
      frontmatterRegionValueMap: { "type:attack_vector": "stem" },
    }));
    if (process.getuid?.() === 0) {
      // Reproduce an administrative install over a directory that the
      // restricted service account could not traverse.
      chownSync(join(obsidian, "plugins"), 65_534, 65_534);
      chownSync(atlas, 65_534, 65_534);
    }

    const result = state.manager.installBrainAtlas({
      sourceDirectory: state.source,
      actor: "operator:test",
      connectionId: state.connection.id,
    });
    expect(result.status).toBe("updated");
    expect(result.health.healthy).toBe(true);
    expect(readFileSync(join(otherPlugin, "main.js"), "utf8")).toBe("operator-owned-plugin");
    expect(readFileSync(join(atlas, "operator-note.txt"), "utf8")).toBe("preserve me");
    expect(readFileSync(join(obsidian, "workspace.json"))).toEqual(workspace);
    expect(JSON.parse(readFileSync(join(obsidian, "community-plugins.json"), "utf8")))
      .toEqual(["operator-plugin", "brain-atlas"]);
    const data = JSON.parse(readFileSync(join(atlas, "data.json"), "utf8"));
    expect(data.palette).toBe("graphite");
    expect(data.pinnedNodePositions).toEqual({ "note.md": { x: 4, y: 5, z: 6 } });
    expect(data.futureSetting).toBe("preserved");
    expect(data.frontmatterKindValueMap["type:attack_vector"]).toBe("workThread");
    expect(data.frontmatterRegionValueMap["type:attack_vector"]).toBe("frontal");
    expect(existsSync(join(atlas, "release.json"))).toBe(true);
    expect(readdirSync(join(obsidian, "plugins")).some((name) => name.includes(".brain-atlas.previous-"))).toBe(false);
    const vaultOwner = statSync(state.connection.vaultPath);
    for (const managedPath of [
      obsidian,
      join(obsidian, "plugins"),
      atlas,
      join(atlas, "main.js"),
      join(obsidian, "community-plugins.json"),
    ]) {
      const owner = statSync(managedPath);
      expect({ uid: owner.uid, gid: owner.gid }).toEqual({
        uid: vaultOwner.uid,
        gid: vaultOwner.gid,
      });
    }
    state.database.close();
  });

  test("never leaves a restorable previous-plugin directory when publication fails", () => {
    const state = fixture();
    const plugins = join(state.connection.vaultPath, ".obsidian", "plugins");
    const atlas = join(plugins, "brain-atlas");
    mkdirSync(atlas, { recursive: true });
    writeFileSync(join(atlas, "old-main.js"), "superseded plugin");
    Object.defineProperty(state.policy, "atomicWriteBytes", {
      configurable: true,
      value: () => {
        throw new Error("forced community-plugin publication failure");
      },
    });

    expect(() => state.manager.installBrainAtlas({
      sourceDirectory: state.source,
      actor: "operator:test",
      connectionId: state.connection.id,
    })).toThrow("forced community-plugin publication failure");
    expect(readdirSync(plugins).filter((name) => (
      name.includes(".brain-atlas.previous-") || name.includes(".brain-atlas.install-")
    ))).toEqual([]);
    state.database.close();
  });

  test("maps every exact Operator Profile projection node while excluding unrelated operational entities", () => {
    const state = fixture();
    const profile = addExplicitOperatorProfile(state.database);
    const createNode = (input: {
      id: string;
      nodeType: "attack_procedure" | "entity" | "target";
      title: string;
      lifecycleStatus: "confirmed" | "verified";
    }) => state.repository.createNode({
      ...input,
      summary: `Reviewed knowledge for ${input.title}.`,
      body: "A bounded test record with no secret or raw target payload.",
      scope: { kind: "global" },
      sensitivity: "internal",
      confidence: 1,
      confirmationState: "confirmed",
      provenance: {
        method: "derived",
        explanation: "Reviewed test provenance.",
        sources: [{
          sourceType: "private_receipt",
          sourceId: `receipt_${input.id}`,
          acquiredAt: "2026-07-20T20:00:00.000Z",
        }],
      },
      authorType: "operator",
      authorId: "operator:test",
    });
    createNode({
      id: `mem_${"9".repeat(32)}`,
      nodeType: "attack_procedure",
      title: "Bounded reusable procedure",
      lifecycleStatus: "verified",
    });
    createNode({
      id: `mem_${"8".repeat(32)}`,
      nodeType: "entity",
      title: "Unrelated operational entity",
      lifecycleStatus: "confirmed",
    });
    createNode({
      id: "operational-target-atlas-health",
      nodeType: "target",
      title: "Unrelated operational target",
      lifecycleStatus: "confirmed",
    });
    state.database.prepare(`
      UPDATE vault_connections SET sync_scope_json = ? WHERE id = ?
    `).run(JSON.stringify(attackKnowledgeVaultSyncScope({
      includeConfirmed: true,
      includeOperatorProfile: true,
      operatorProfileId: "operator:test",
    })), state.connection.id);

    state.manager.installBrainAtlas({
      sourceDirectory: state.source,
      actor: "operator:test",
      connectionId: state.connection.id,
    });
    const health = state.manager.health(state.connection.id);
    expect(health.healthy).toBe(true);
    expect(health.knowledge).toMatchObject({
      nodeCount: 4,
      mappedNodeCount: 4,
      unmappedNodeCount: 0,
      typedEdgeCount: 2,
      uniqueUndirectedPairCount: 2,
    });
    expect(health.knowledge.regionNodeCounts.frontal).toBe(4);
    expect(health.configuration).toMatchObject({
      registryNodeTypeCount: 43,
      operatorProfileMappingCount: 3,
      kindMappingCount: 46,
      regionMappingCount: 46,
    });
    expect(profile).toEqual({
      operatorNodeId: expect.stringMatching(/^mem_operator_/u),
      preferenceNodeId: expect.stringMatching(/^mem_/u),
      applicabilityNodeId: expect.stringMatching(/^mem_prefdomain_/u),
    });
    const data = JSON.parse(readFileSync(
      join(state.connection.vaultPath, ".obsidian/plugins/brain-atlas/data.json"),
      "utf8",
    ));
    expect(data.frontmatterRegionValueMap["operator_profile_class:operator"]).toBe("frontal");
    expect(data.frontmatterRegionValueMap["operator_profile_class:preference"]).toBe("frontal");
    expect(data.frontmatterRegionValueMap["operator_profile_class:application_domain"]).toBe("frontal");
    expect(data.frontmatterRegionValueMap["type:entity"]).toBeUndefined();
    expect(data.frontmatterRegionValueMap["type:target"]).toBeUndefined();
    state.database.close();
  });

  test("detects asset tampering without mutating the Vault", () => {
    const state = fixture();
    state.manager.installBrainAtlas({ sourceDirectory: state.source, actor: "operator:test" });
    const main = join(state.connection.vaultPath, ".obsidian/plugins/brain-atlas/main.js");
    writeFileSync(main, "tampered");
    const before = readFileSync(main);
    const health = state.manager.health();
    expect(health.healthy).toBe(false);
    expect(health.status).toBe("degraded");
    expect(health.issues.some((issue) => issue.code === "asset_hash_mismatch")).toBe(true);
    expect(readFileSync(main)).toEqual(before);
    state.database.close();
  });

  test("serves the same read-only health receipt through the versioned Brain API", async () => {
    const state = fixture();
    state.manager.installBrainAtlas({ sourceDirectory: state.source, actor: "operator:test" });
    const app = express();
    app.use(express.json());
    app.use(createSecondBrainRouter({
      database: state.database,
      resolveActor: () => "operator:test",
      resolveAccess: () => ({ maximumSensitivity: "restricted", allowGlobal: true, allEngagements: true }),
      vaultPathPolicy: state.policy,
      vaultBridge: state.bridge,
      obsidianPluginManager: state.manager,
    }));
    const server = app.listen(0);
    try {
      const port = (server.address() as AddressInfo).port;
      const response = await fetch(`http://127.0.0.1:${port}/api/v2/brain/vault/brain-atlas`);
      expect(response.status).toBe(200);
      const payload = await response.json() as {
        schemaVersion: string;
        enabled: boolean;
        health: ReturnType<ObsidianPluginManager["health"]>;
      };
      expect(payload.schemaVersion).toBe("2.4");
      expect(payload.enabled).toBe(true);
      expect(payload.health.healthy).toBe(true);
      expect(payload.health.expectedVersion).toBe(state.release.version);
      expect(JSON.stringify(payload)).not.toContain(state.connection.vaultPath);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      state.database.close();
    }
  });

  test("rejects an unpinned source before changing an existing plugin", () => {
    const state = fixture();
    state.manager.installBrainAtlas({ sourceDirectory: state.source, actor: "operator:test" });
    const atlas = join(state.connection.vaultPath, ".obsidian/plugins/brain-atlas");
    const previous = readFileSync(join(atlas, "main.js"));
    writeFileSync(join(state.source, "main.js"), "wrong release");
    expect(() => state.manager.installBrainAtlas({ sourceDirectory: state.source, actor: "operator:test" }))
      .toThrow("does not match the pinned release");
    expect(readFileSync(join(atlas, "main.js"))).toEqual(previous);
    state.database.close();
  });

  test("keeps the pinned Brain Atlas profile local while portable handoff stays disabled", async () => {
    const state = fixture();
    state.manager.installBrainAtlas({ sourceDirectory: state.source, actor: "operator:test" });
    await expect(state.bridge.createPortableExport(
      state.connection.id,
      [],
      "operator:test",
      { includeBrainAtlasProfile: true },
    )).rejects.toThrow(
      "Portable Vault ZIP creation is disabled by operator no-backup policy",
    );
    expect(existsSync(join(
      state.connection.vaultPath,
      ".ti-scale",
      "exports",
    ))).toBe(false);
    expect(state.manager.health().healthy).toBe(true);
    state.database.close();
  });

  test("portable ZIP writer rejects before creating an archive", async () => {
    const root = mkdtempSync(join(tmpdir(), "brain-atlas-zip-deny-"));
    directories.push(root);
    const destination = join(root, "denied.zip");
    await expect(writePortableZip([{
      name: "note.md",
      data: "never archived",
    }], destination)).rejects.toThrow(
      "Portable Vault ZIP creation is disabled by operator no-backup policy",
    );
    expect(existsSync(destination)).toBe(false);
  });
});

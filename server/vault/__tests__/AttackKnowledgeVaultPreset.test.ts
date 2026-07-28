import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import { MemoryRepository } from "../../memory/MemoryRepository";
import { createSecondBrainRouter } from "../../memory/SecondBrainRouter";
import { OperatorPreferenceImportService } from "../../memory/OperatorPreferenceImportService";
import {
  OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY,
  parseOperatorPreferenceManifest,
} from "../../memory/OperatorPreferenceManifest";
import type { MemoryNodeType } from "../../memory/types";
import type { TrustedLocalFileReceipt } from "../../trusted-runtime-config";
import { ObsidianVaultBridge } from "../ObsidianVaultBridge";
import { parseObsidianNote } from "../ObsidianMarkdown";
import { VaultPathPolicy } from "../VaultPathPolicy";
import {
  AttackKnowledgeVaultPolicyService,
  AttackKnowledgeVaultScopeAmendmentConflictError,
} from "../AttackKnowledgeVaultPolicyService";
import { ObsidianPluginManager } from "../ObsidianPluginManager";
import {
  ATTACK_KNOWLEDGE_VAULT_ALLOWED_SENSITIVITIES,
  ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
  ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
  assertAttackKnowledgeVaultNodeAllowed,
  attackKnowledgeVaultPolicyHash,
  attackKnowledgeVaultPresetPreview,
  attackKnowledgeVaultSyncScope,
} from "../AttackKnowledgeVaultPreset";

const directories: string[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true }));
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "attack-vault-preset-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "brain.sqlite") });
  migrateDatabase(database);
  const repository = new MemoryRepository(database, {
    clock: () => new Date("2026-07-20T18:00:00.000Z"),
  });
  const vaultRoot = join(directory, "vault-root");
  const pathPolicy = new VaultPathPolicy(vaultRoot);
  const bridge = new ObsidianVaultBridge(database, repository, pathPolicy);
  return { database, repository, vaultRoot, pathPolicy, bridge };
}

function memoryId(sequence: number): string {
  return `mem_${sequence.toString(16).padStart(32, "0")}`;
}

function addNode(
  repository: MemoryRepository,
  sequence: number,
  nodeType: MemoryNodeType,
  title: string,
  options: {
    lifecycleStatus?: "confirmed" | "verified";
    sensitivity?: "public" | "internal" | "private" | "restricted";
    scope?: { kind: "global" } | { kind: "engagement"; engagementId: string };
  } = {},
) {
  return repository.createNode({
    id: nodeType === "mission" || nodeType === "run" || nodeType === "target"
      ? `operational-${nodeType}-${sequence}`
      : memoryId(sequence),
    nodeType,
    title,
    summary: `Reusable, generalized knowledge about ${title.toLocaleLowerCase("en-US")}.`,
    body: "Technology- and procedure-centered knowledge with no target, mission, address, credential, or raw payload.",
    scope: options.scope ?? { kind: "global" },
    sensitivity: options.sensitivity ?? "internal",
    confidence: 0.98,
    lifecycleStatus: options.lifecycleStatus ?? "verified",
    confirmationState: "confirmed",
    provenance: {
      method: "derived",
      explanation: "Operator-reviewed promotion receipt retained in the private canonical store.",
      sources: [{
        sourceType: "private_receipt",
        sourceId: `akverify_${sequence.toString(16).padStart(64, "0")}`,
        acquiredAt: "2026-07-20T18:00:00.000Z",
      }],
    },
    authorType: "operator",
    authorId: "operator-attack-vault-test",
  });
}

function addEdge(
  repository: MemoryRepository,
  sourceNodeId: string,
  targetNodeId: string,
  edgeType: "has_exact_version" | "built_with" | "applicable_to" | "implemented_by" | "produces_outcome" | "failed_because" | "recovered_with",
  sequence: number,
) {
  repository.createEdge({
    id: `edge-attack-vault-${sequence}`,
    sourceNodeId,
    targetNodeId,
    edgeType,
    title: `${edgeType.replaceAll("_", " ")} relationship`,
    summary: "Generalized reusable relationship.",
    scope: { kind: "global" },
    sensitivity: "internal",
    confidence: 0.98,
    lifecycleStatus: "verified",
    provenance: {
      method: "derived",
      explanation: "Operator-reviewed relationship promotion receipt.",
      sources: [{
        sourceType: "private_receipt",
        sourceId: `akverify_edge_${sequence.toString(16).padStart(48, "0")}`,
        acquiredAt: "2026-07-20T18:00:00.000Z",
      }],
    },
    explanation: "The source and destination are linked by reviewed reusable knowledge.",
    authorType: "operator",
    authorId: "operator-attack-vault-test",
  });
}

function addExplicitOperatorProfile(database: ReturnType<typeof createDatabaseConnection>) {
  const manifest = parseOperatorPreferenceManifest({
    schemaVersion: "ti-scale.operator-preferences.v2",
    manifestVersion: "operator-profile-vault-test-v1",
    operatorId: "operator-attack-vault-test",
    retentionPolicy: {
      durableOnly: true,
      excludeOneTimeCommands: true,
      excludeTargetSpecificData: true,
      excludeCredentialsAndSecrets: true,
    },
    safetyBoundary: OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY,
    source: {
      sourceType: "operator_instruction_manifest",
      sourceId: "operator-profile-vault-test",
      acquiredAt: "2026-07-20T18:00:00.000Z",
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
    sourcePath: "/trusted/operator-profile-vault-test.json",
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
    clock: () => new Date("2026-07-20T18:00:00.000Z"),
  });
  const preview = service.preview({
    manifest,
    receipt,
    actorId: "operator-attack-vault-test",
  });
  const result = service.execute({
    manifest,
    receipt,
    actorId: "operator-attack-vault-test",
    expectedPreviewHash: preview.previewHash,
    reason: "Operator approved this explicit profile for Vault projection tests",
  });
  return {
    operatorNodeId: result.operatorNodeId,
    preferenceNodeId: result.nodeIds[0]!,
    applicabilityNodeId: preview.graph.applicability[0]!.id,
  };
}

describe("Attack Knowledge Vault preset", () => {
  test("amends the same confirmed Vault to a connected explicit Operator Profile without admitting operational entities", () => {
    const { database, repository, bridge, vaultRoot } = fixture();
    const attack = addNode(repository, 1, "attack_procedure", "Confirmed bounded procedure", {
      lifecycleStatus: "confirmed",
    });
    const profile = addExplicitOperatorProfile(database);
    const unrelatedEntity = addNode(repository, 70, "entity", "10.129.39.191", {
      lifecycleStatus: "confirmed",
    });
    const operationalTarget = addNode(repository, 71, "target", "10.129.39.191", {
      lifecycleStatus: "confirmed",
    });
    const connection = bridge.connect({
      vaultPath: ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
      displayName: ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
      syncScope: attackKnowledgeVaultSyncScope({ includeConfirmed: true }),
      permissionGranted: true,
    });
    const original = bridge.requireConnection(connection.id);
    const preview = attackKnowledgeVaultPresetPreview(database, {
      includeConfirmed: true,
      includeOperatorProfile: true,
      operatorProfileId: "operator-attack-vault-test",
    });
    expect(preview.operatorProfileScopeUpgrade).toMatchObject({
      connectionId: connection.id,
      eligibleNodeCountBefore: 1,
      eligibleNodeCountAfter: 4,
      eligibleNodeDelta: 3,
      operatorProfileNodeCount: 3,
    });
    expect(preview.projection.folders).toContain("10 Operator");
    expect(preview.projection.nodeTypes).toEqual(expect.arrayContaining([
      "operator", "preference", "entity",
    ]));

    const service = new AttackKnowledgeVaultPolicyService(database, bridge, {
      clock: () => new Date("2026-07-20T18:10:00.000Z"),
    });
    const upgrade = preview.operatorProfileScopeUpgrade!;
    const result = service.includeOperatorProfile({
      connectionId: connection.id,
      expectedUpdatedAt: original.updatedAt,
      expectedCurrentPolicyHash: upgrade.currentPolicyHash,
      expectedTargetPolicyHash: upgrade.targetPolicyHash,
      actor: "operator-attack-vault-test",
      reason: "Project the explicit consent-backed Operator Profile into this connected Vault",
      operatorProfileAcknowledged: true,
    });
    expect(result).toMatchObject({
      connection: { id: connection.id, vaultPath: connection.vaultPath },
      eligibleNodeDelta: 3,
      operatorProfileNodeCount: 3,
      operatorProfileFolder: "10 Operator",
      operatorProfileFolderCreated: true,
      connectionIdChanged: false,
      vaultPathChanged: false,
      filesDeleted: 0,
      notesWritten: 0,
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM vault_connections").get()).toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'vault.attack_knowledge_preset.operator_profile_scope_amended'
    `).get()).toEqual({ count: 1 });

    const exportable = bridge.exportableNodeIds(connection.id);
    expect(exportable).toEqual(expect.arrayContaining([
      attack.id,
      profile.operatorNodeId,
      profile.preferenceNodeId,
      profile.applicabilityNodeId,
    ]));
    expect(exportable).not.toEqual(expect.arrayContaining([unrelatedEntity.id, operationalTarget.id]));
    expect(() => bridge.exportNode(connection.id, unrelatedEntity.id)).toThrow("private operational provenance");
    expect(() => bridge.exportNode(connection.id, operationalTarget.id)).toThrow("private operational provenance");

    for (const nodeId of [profile.operatorNodeId, profile.preferenceNodeId, profile.applicabilityNodeId]) {
      expect(bridge.exportNode(connection.id, nodeId).status).toBe("synced");
    }
    const states = database.prepare(`
      SELECT node_id, relative_path FROM vault_sync_state
      WHERE connection_id = ? AND node_id IN (?, ?, ?)
      ORDER BY node_id
    `).all(
      connection.id,
      profile.operatorNodeId,
      profile.preferenceNodeId,
      profile.applicabilityNodeId,
    ) as Array<{ node_id: string; relative_path: string }>;
    expect(states).toHaveLength(3);
    expect(states.every(({ relative_path }) => relative_path.startsWith("10 Operator/"))).toBe(true);
    const markdown = states.map(({ relative_path }) => (
      readFileSync(join(vaultRoot, ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH, relative_path), "utf8")
    )).join("\n");
    const projectedProfile = states.map(({ relative_path }) => parseObsidianNote(
      readFileSync(join(vaultRoot, ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH, relative_path), "utf8"),
    ));
    expect(projectedProfile.every((note) => note.brainRegion === "frontal")).toBe(true);
    expect(projectedProfile.map((note) => note.operatorProfileClass).sort()).toEqual([
      "application_domain",
      "operator",
      "preference",
    ]);
    expect(markdown).toContain("prefers");
    expect(markdown).toContain("applies_to");
    expect(markdown).toContain("Readable technical language");
    expect(markdown).not.toContain("10.129.39.191");

    const generic = bridge.connect({
      vaultPath: "generic-vault",
      displayName: "Generic Vault",
      syncScope: {
        nodeTypes: ["operator", "preference", "entity"],
        scopeKinds: ["global"],
        lifecycleStatuses: ["confirmed"],
        sensitivities: ["private", "internal"],
      },
      permissionGranted: true,
    });
    expect(() => bridge.exportNode(generic.id, profile.preferenceNodeId)).toThrow("private operational provenance");
    const otherOperator = bridge.connect({
      vaultPath: "other-operator-vault",
      displayName: "Other Operator Vault",
      syncScope: attackKnowledgeVaultSyncScope({
        includeConfirmed: true,
        includeOperatorProfile: true,
        operatorProfileId: "another-operator",
      }),
      permissionGranted: true,
    });
    expect(() => bridge.exportNode(otherOperator.id, profile.preferenceNodeId))
      .toThrow("private operational provenance");
    database.close();
  });

  test("amends verified-only to verified-plus-confirmed in place with one optimistic audit receipt", () => {
    const { database, repository, bridge, vaultRoot, pathPolicy } = fixture();
    const verified = addNode(repository, 1, "attack_procedure", "Verified bounded procedure");
    const confirmed = addNode(repository, 2, "failure_mode", "Confirmed retry failure", {
      lifecycleStatus: "confirmed",
    });
    const connection = bridge.connect({
      vaultPath: ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
      displayName: ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
      syncScope: attackKnowledgeVaultSyncScope(),
      permissionGranted: true,
    });
    bridge.exportNode(connection.id, verified.id);
    const currentConnection = bridge.requireConnection(connection.id);
    const vaultPath = join(vaultRoot, ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH);
    const filesBefore = readdirSync(vaultPath, { recursive: true }).map(String).sort();
    const service = new AttackKnowledgeVaultPolicyService(database, bridge, {
      clock: () => new Date("2026-07-20T18:05:00.000Z"),
    });
    const preview = attackKnowledgeVaultPresetPreview(database, { includeConfirmed: true });
    expect(preview.confirmedScopeUpgrade).toMatchObject({
      connectionId: connection.id,
      expectedUpdatedAt: currentConnection.updatedAt,
      eligibleNodeCountBefore: 1,
      eligibleNodeCountAfter: 2,
      eligibleNodeDelta: 1,
    });
    const result = service.includeConfirmed({
      connectionId: connection.id,
      expectedUpdatedAt: currentConnection.updatedAt,
      expectedCurrentPolicyHash: attackKnowledgeVaultPolicyHash(),
      expectedTargetPolicyHash: attackKnowledgeVaultPolicyHash({ includeConfirmed: true }),
      actor: "operator-attack-vault-test",
      reason: "Include reviewed confirmed attack knowledge in this exact existing Vault",
      amendmentAcknowledged: true,
    });
    expect(result.connection.id).toBe(connection.id);
    expect(result.connection.vaultPath).toBe(connection.vaultPath);
    expect(result.connection.syncScope).toEqual(attackKnowledgeVaultSyncScope({ includeConfirmed: true }));
    expect(result).toMatchObject({
      eligibleNodeCountBefore: 1,
      eligibleNodeCountAfter: 2,
      eligibleNodeDelta: 1,
      connectionIdChanged: false,
      vaultPathChanged: false,
      filesDeleted: 0,
      notesWritten: 0,
    });
    expect(readdirSync(vaultPath, { recursive: true }).map(String).sort()).toEqual(filesBefore);
    expect(database.prepare("SELECT COUNT(*) AS count FROM vault_connections").get()).toEqual({ count: 1 });
    const audit = database.prepare(`
      SELECT actor_id, action, reason, details_json, record_hash
      FROM audit_records WHERE id = ?
    `).get(result.auditRecordId) as Record<string, string>;
    expect(audit.actor_id).toBe("operator-attack-vault-test");
    expect(audit.action).toBe("vault.attack_knowledge_preset.scope_amended");
    expect(audit.reason).toContain("confirmed attack knowledge");
    expect(audit.record_hash).toMatch(/^[a-f0-9]{64}$/u);
    expect(JSON.parse(audit.details_json)).toMatchObject({
      connectionId: connection.id,
      connectionIdChanged: false,
      vaultPathChanged: false,
      filesDeleted: 0,
      notesWritten: 0,
    });
    expect(bridge.exportableNodeIds(connection.id)).toEqual(expect.arrayContaining([verified.id, confirmed.id]));
    expect(attackKnowledgeVaultPresetPreview(database, { includeConfirmed: true }).alreadyActiveConnectionId).toBe(connection.id);
    const atlas = new ObsidianPluginManager({ database, pathPolicy }).health(connection.id);
    expect(atlas.connection?.id).toBe(connection.id);
    expect(atlas.issues.some(({ code }) => code === "attack_vault_not_connected")).toBe(false);
    expect(() => service.includeConfirmed({
      connectionId: connection.id,
      expectedUpdatedAt: currentConnection.updatedAt,
      expectedCurrentPolicyHash: attackKnowledgeVaultPolicyHash(),
      expectedTargetPolicyHash: attackKnowledgeVaultPolicyHash({ includeConfirmed: true }),
      actor: "operator-attack-vault-test",
      reason: "Attempt a stale second scope amendment for regression coverage",
      amendmentAcknowledged: true,
    })).toThrow(AttackKnowledgeVaultScopeAmendmentConflictError);
    database.close();
  });

  test("projects only a linked verified reusable attack graph into attack-centric folders", () => {
    const { database, repository, bridge, vaultRoot } = fixture();
    const product = addNode(repository, 1, "technology_product", "Managed web execution engine");
    const version = addNode(repository, 2, "exact_version_fingerprint", "Execution engine release 12.2");
    const stack = addNode(repository, 3, "framework", "Managed server-side application framework");
    const vector = addNode(repository, 4, "attack_vector", "Server-side expression execution vector");
    const procedure = addNode(repository, 5, "attack_procedure", "Bounded expression validation procedure");
    const script = addNode(repository, 6, "script_artifact", "Bounded validation driver v3");
    const outcome = addNode(repository, 7, "outcome", "Execution worker stopped responding");
    const failure = addNode(repository, 8, "failure_mode", "Unbounded worker-state corruption");
    const recovery = addNode(repository, 9, "recovery_pattern", "Recycle disposable execution worker");
    addEdge(repository, product.id, version.id, "has_exact_version", 1);
    addEdge(repository, product.id, stack.id, "built_with", 2);
    addEdge(repository, vector.id, product.id, "applicable_to", 3);
    addEdge(repository, procedure.id, product.id, "applicable_to", 4);
    addEdge(repository, procedure.id, script.id, "implemented_by", 5);
    addEdge(repository, procedure.id, outcome.id, "produces_outcome", 6);
    addEdge(repository, outcome.id, failure.id, "failed_because", 7);
    addEdge(repository, failure.id, recovery.id, "recovered_with", 8);

    const mission = addNode(repository, 100, "mission", "Disposable box engagement");
    const run = addNode(repository, 101, "run", "Autonomous journey run");
    const target = addNode(repository, 102, "target", "10.129.39.191");
    const restricted = addNode(repository, 103, "attack_procedure", "Restricted local-only procedure", {
      sensitivity: "restricted",
    });
    const confirmed = addNode(repository, 104, "attack_procedure", "Confirmed but not independently verified procedure", {
      lifecycleStatus: "confirmed",
    });

    const connection = bridge.connect({
      vaultPath: ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
      displayName: ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
      syncScope: attackKnowledgeVaultSyncScope(),
      permissionGranted: true,
    });
    for (const node of [product, version, stack, vector, script, outcome, failure, recovery, procedure]) {
      expect(() => assertAttackKnowledgeVaultNodeAllowed(node)).not.toThrow();
      expect(bridge.exportNode(connection.id, node.id).status).toBe("synced");
    }
    for (const node of [mission, run, target, restricted, confirmed]) {
      expect(() => assertAttackKnowledgeVaultNodeAllowed(node)).toThrow();
      expect(() => bridge.exportNode(connection.id, node.id)).toThrow();
    }

    const procedureState = database.prepare(`
      SELECT relative_path FROM vault_sync_state WHERE connection_id = ? AND node_id = ?
    `).get(connection.id, procedure.id) as { relative_path: string };
    expect(procedureState.relative_path.startsWith("42 Techniques and Procedures/")).toBe(true);
    const procedureMarkdown = readFileSync(join(vaultRoot, ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH, procedureState.relative_path), "utf8");
    expect(procedureMarkdown).toContain("implemented_by");
    expect(procedureMarkdown).toContain("applicable_to");
    expect(procedureMarkdown).toContain("produces_outcome");
    expect(procedureMarkdown).not.toContain("10.129.39.191");
    expect(procedureMarkdown).not.toContain("Autonomous journey");

    const preview = attackKnowledgeVaultPresetPreview(database);
    expect(preview.projection.policyEligibleNodeCount).toBe(9);
    expect(preview.projection.excludedOperationalNodeCount).toBe(3);
    expect(preview.projection.scopeKinds).toEqual(["global"]);
    expect(preview.projection.lifecycleStatuses).toEqual(["verified"]);
    expect(preview.projection.sensitivities).toEqual(ATTACK_KNOWLEDGE_VAULT_ALLOWED_SENSITIVITIES);
    expect(preview.projection.folders).toEqual(expect.arrayContaining([
      "20 Technology Products",
      "41 Attack Vectors",
      "42 Techniques and Procedures",
      "45 Scripts and Tools",
      "51 Operational Hazards",
      "52 Recovery and Alternatives",
    ]));
    database.close();
  });

  test("previews without writes and activates only an acknowledged hash-pinned policy", async () => {
    const { database, repository, pathPolicy, bridge, vaultRoot } = fixture();
    addNode(repository, 1, "attack_procedure", "Verified bounded validation procedure");
    addNode(repository, 2, "failure_mode", "Confirmed bounded retry failure", {
      lifecycleStatus: "confirmed",
    });
    addExplicitOperatorProfile(database);
    const app = express();
    app.use(express.json());
    app.use(createSecondBrainRouter({
      database,
      resolveActor: () => "operator-attack-vault-test",
      resolveAccess: () => ({
        maximumSensitivity: "restricted",
        allowGlobal: true,
        allEngagements: true,
      }),
      vaultPathPolicy: pathPolicy,
      vaultBridge: bridge,
    }));
    const server = app.listen(0);
    servers.push(server);
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const previewResponse = await fetch(`${url}/api/v2/brain/vault/attack-knowledge-preset?includeConfirmed=false`);
    expect(previewResponse.status).toBe(200);
    const previewPayload = await previewResponse.json() as {
      enabled: boolean;
      preset: ReturnType<typeof attackKnowledgeVaultPresetPreview>;
    };
    expect(previewPayload.enabled).toBe(true);
    expect(previewPayload.preset.policyHash).toBe(attackKnowledgeVaultPolicyHash());
    expect(previewPayload.preset.operatorProfileAvailability).toEqual({
      requested: false,
      available: true,
      status: "available",
      eligibleNodeCount: 3,
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM vault_connections").get()).toEqual({ count: 0 });
    expect(existsSync(join(vaultRoot, ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH))).toBe(false);

    const request = (body: Record<string, unknown>, key: string) => fetch(
      `${url}/api/v2/brain/vault/attack-knowledge-preset/activate`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify(body),
      },
    );
    const missingAcknowledgement = await request({
      expectedPolicyHash: previewPayload.preset.policyHash,
      includeConfirmed: false,
      permissionGranted: true,
    }, "attack-vault-missing-ack");
    expect(missingAcknowledgement.status).toBe(400);
    const stalePolicy = await request({
      expectedPolicyHash: "0".repeat(64),
      includeConfirmed: false,
      permissionGranted: true,
      activationAcknowledged: true,
    }, "attack-vault-stale-policy");
    expect(stalePolicy.status).toBe(409);
    expect(database.prepare("SELECT COUNT(*) AS count FROM vault_connections").get()).toEqual({ count: 0 });

    const activated = await request({
      expectedPolicyHash: previewPayload.preset.policyHash,
      includeConfirmed: false,
      permissionGranted: true,
      activationAcknowledged: true,
    }, "attack-vault-activate-reviewed");
    expect(activated.status).toBe(201);
    const activatedPayload = await activated.json() as { connection: { id: string; syncScope: Record<string, unknown> } };
    expect(activatedPayload.connection.syncScope).toEqual(attackKnowledgeVaultSyncScope());
    expect(existsSync(join(vaultRoot, ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH))).toBe(true);
    expect(database.prepare("SELECT COUNT(*) AS count FROM vault_connections").get()).toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'vault.attack_knowledge_preset.activated'
    `).get()).toEqual({ count: 1 });
    expect(database.prepare("SELECT COUNT(*) AS count FROM vault_sync_state").get()).toEqual({ count: 0 });

    const repeat = await request({
      expectedPolicyHash: previewPayload.preset.policyHash,
      includeConfirmed: false,
      permissionGranted: true,
      activationAcknowledged: true,
    }, "attack-vault-activate-safe-repeat");
    expect(repeat.status).toBe(201);
    expect(database.prepare("SELECT COUNT(*) AS count FROM vault_connections").get()).toEqual({ count: 1 });

    const confirmedPreviewResponse = await fetch(`${url}/api/v2/brain/vault/attack-knowledge-preset?includeConfirmed=true`);
    expect(confirmedPreviewResponse.status).toBe(200);
    const confirmedPreview = await confirmedPreviewResponse.json() as {
      preset: ReturnType<typeof attackKnowledgeVaultPresetPreview>;
    };
    expect(confirmedPreview.preset.confirmedScopeUpgrade).toMatchObject({
      connectionId: activatedPayload.connection.id,
      eligibleNodeCountBefore: 1,
      eligibleNodeCountAfter: 2,
      eligibleNodeDelta: 1,
    });
    expect(confirmedPreview.preset.operatorProfileAvailability).toMatchObject({
      requested: false,
      available: true,
      eligibleNodeCount: 3,
    });
    const upgrade = confirmedPreview.preset.confirmedScopeUpgrade!;
    const missingAmendmentAcknowledgement = await fetch(`${url}/api/v2/brain/vault/attack-knowledge-preset/amend`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "attack-vault-amend-missing-ack" },
      body: JSON.stringify({
        connectionId: upgrade.connectionId,
        expectedUpdatedAt: upgrade.expectedUpdatedAt,
        expectedCurrentPolicyHash: upgrade.currentPolicyHash,
        expectedTargetPolicyHash: upgrade.targetPolicyHash,
        includeConfirmed: true,
        permissionGranted: true,
        reason: "Attempt an unacknowledged confirmed knowledge scope amendment",
      }),
    });
    expect(missingAmendmentAcknowledgement.status).toBe(400);
    const staleAmendmentPolicy = await fetch(`${url}/api/v2/brain/vault/attack-knowledge-preset/amend`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "attack-vault-amend-stale-policy" },
      body: JSON.stringify({
        connectionId: upgrade.connectionId,
        expectedUpdatedAt: upgrade.expectedUpdatedAt,
        expectedCurrentPolicyHash: upgrade.currentPolicyHash,
        expectedTargetPolicyHash: "0".repeat(64),
        includeConfirmed: true,
        permissionGranted: true,
        amendmentAcknowledged: true,
        reason: "Attempt a stale confirmed knowledge scope amendment",
      }),
    });
    expect(staleAmendmentPolicy.status).toBe(409);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'vault.attack_knowledge_preset.scope_amended'
    `).get()).toEqual({ count: 0 });
    const amended = await fetch(`${url}/api/v2/brain/vault/attack-knowledge-preset/amend`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "attack-vault-amend-confirmed" },
      body: JSON.stringify({
        connectionId: upgrade.connectionId,
        expectedUpdatedAt: upgrade.expectedUpdatedAt,
        expectedCurrentPolicyHash: upgrade.currentPolicyHash,
        expectedTargetPolicyHash: upgrade.targetPolicyHash,
        includeConfirmed: true,
        permissionGranted: true,
        amendmentAcknowledged: true,
        reason: "Include reviewed confirmed attack knowledge in this existing Vault",
      }),
    });
    expect(amended.status).toBe(200);
    const amendedPayload = await amended.json() as {
      connection: { id: string; syncScope: Record<string, unknown> };
      result: Record<string, unknown>;
    };
    expect(amendedPayload.connection.id).toBe(activatedPayload.connection.id);
    expect(amendedPayload.connection.syncScope).toEqual(attackKnowledgeVaultSyncScope({ includeConfirmed: true }));
    expect(amendedPayload.result).toMatchObject({
      eligibleNodeDelta: 1,
      connectionIdChanged: false,
      vaultPathChanged: false,
      filesDeleted: 0,
      notesWritten: 0,
    });
    expect(database.prepare("SELECT COUNT(*) AS count FROM vault_connections").get()).toEqual({ count: 1 });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'vault.attack_knowledge_preset.scope_amended'
    `).get()).toEqual({ count: 1 });
    const amendedReplay = await fetch(`${url}/api/v2/brain/vault/attack-knowledge-preset/amend`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "attack-vault-amend-confirmed" },
      body: JSON.stringify({
        connectionId: upgrade.connectionId,
        expectedUpdatedAt: upgrade.expectedUpdatedAt,
        expectedCurrentPolicyHash: upgrade.currentPolicyHash,
        expectedTargetPolicyHash: upgrade.targetPolicyHash,
        includeConfirmed: true,
        permissionGranted: true,
        amendmentAcknowledged: true,
        reason: "Include reviewed confirmed attack knowledge in this existing Vault",
      }),
    });
    expect(amendedReplay.status).toBe(200);
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'vault.attack_knowledge_preset.scope_amended'
    `).get()).toEqual({ count: 1 });

    const operatorProfilePreviewResponse = await fetch(
      `${url}/api/v2/brain/vault/attack-knowledge-preset?includeConfirmed=true&includeOperatorProfile=true`,
    );
    expect(operatorProfilePreviewResponse.status).toBe(200);
    const operatorProfilePreview = await operatorProfilePreviewResponse.json() as {
      preset: ReturnType<typeof attackKnowledgeVaultPresetPreview>;
    };
    expect(operatorProfilePreview.preset.operatorProfileScopeUpgrade).toMatchObject({
      connectionId: activatedPayload.connection.id,
      eligibleNodeDelta: 3,
      operatorProfileNodeCount: 3,
    });
    const operatorUpgrade = operatorProfilePreview.preset.operatorProfileScopeUpgrade!;
    const operatorAmendment = await fetch(`${url}/api/v2/brain/vault/attack-knowledge-preset/amend`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "attack-vault-amend-operator-profile" },
      body: JSON.stringify({
        connectionId: operatorUpgrade.connectionId,
        expectedUpdatedAt: operatorUpgrade.expectedUpdatedAt,
        expectedCurrentPolicyHash: operatorUpgrade.currentPolicyHash,
        expectedTargetPolicyHash: operatorUpgrade.targetPolicyHash,
        includeConfirmed: true,
        includeOperatorProfile: true,
        permissionGranted: true,
        operatorProfileAcknowledged: true,
        reason: "Include the explicit consent-backed Operator Profile in this existing Vault",
      }),
    });
    expect(operatorAmendment.status).toBe(200);
    const operatorAmendmentPayload = await operatorAmendment.json() as {
      connection: { id: string; syncScope: Record<string, unknown> };
      result: Record<string, unknown>;
    };
    expect(operatorAmendmentPayload.connection.id).toBe(activatedPayload.connection.id);
    expect(operatorAmendmentPayload.connection.syncScope).toEqual(attackKnowledgeVaultSyncScope({
      includeConfirmed: true,
      includeOperatorProfile: true,
      operatorProfileId: "operator-attack-vault-test",
    }));
    expect(operatorAmendmentPayload.result).toMatchObject({
      operatorProfileNodeCount: 3,
      notesWritten: 0,
      filesDeleted: 0,
    });
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'vault.attack_knowledge_preset.operator_profile_scope_amended'
    `).get()).toEqual({ count: 1 });

    const refusedSecondVariant = await request({
      expectedPolicyHash: previewPayload.preset.policyHash,
      includeConfirmed: false,
      permissionGranted: true,
      activationAcknowledged: true,
    }, "attack-vault-refuse-second-variant");
    expect(refusedSecondVariant.status).toBe(409);
    expect(database.prepare("SELECT COUNT(*) AS count FROM vault_connections").get()).toEqual({ count: 1 });

    const reservedGeneric = await fetch(`${url}/api/v2/brain/vault/connect`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "attack-vault-reserved-generic" },
      body: JSON.stringify({
        vaultPath: ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
        displayName: ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
        permissionGranted: true,
        syncScope: {},
      }),
    });
    expect(reservedGeneric.status).toBe(409);

    const normalizedReservedGeneric = await fetch(`${url}/api/v2/brain/vault/connect`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "attack-vault-normalized-reserved-generic" },
      body: JSON.stringify({
        vaultPath: `./${ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH}`,
        displayName: "Broad custom connection",
        permissionGranted: true,
        syncScope: {},
      }),
    });
    expect(normalizedReservedGeneric.status).toBe(409);
    database.close();
  });

  test("reports an empty authenticated Operator Profile before selection and keeps an impossible request schema-valid", async () => {
    const { database, pathPolicy, bridge } = fixture();
    const connection = bridge.connect({
      vaultPath: ATTACK_KNOWLEDGE_VAULT_RELATIVE_PATH,
      displayName: ATTACK_KNOWLEDGE_VAULT_DISPLAY_NAME,
      syncScope: attackKnowledgeVaultSyncScope({ includeConfirmed: true }),
      permissionGranted: true,
    });
    const app = express();
    app.use(express.json());
    app.use(createSecondBrainRouter({
      database,
      resolveActor: () => "operator-with-empty-profile",
      resolveAccess: () => ({
        maximumSensitivity: "restricted",
        allowGlobal: true,
        allEngagements: true,
      }),
      vaultPathPolicy: pathPolicy,
      vaultBridge: bridge,
    }));
    const server = app.listen(0);
    servers.push(server);
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const defaultResponse = await fetch(
      `${url}/api/v2/brain/vault/attack-knowledge-preset?includeConfirmed=true&includeOperatorProfile=false`,
    );
    expect(defaultResponse.status).toBe(200);
    const defaultPayload = await defaultResponse.json() as {
      preset: ReturnType<typeof attackKnowledgeVaultPresetPreview>;
    };
    expect(defaultPayload.preset.activePreset?.connectionId).toBe(connection.id);
    expect(defaultPayload.preset.operatorProfileAvailability).toEqual({
      requested: false,
      available: false,
      status: "no_eligible_confirmed_profile",
      eligibleNodeCount: 0,
    });

    const selectedResponse = await fetch(
      `${url}/api/v2/brain/vault/attack-knowledge-preset?includeConfirmed=true&includeOperatorProfile=true`,
    );
    expect(selectedResponse.status).toBe(200);
    const selectedPayload = await selectedResponse.json() as {
      preset: ReturnType<typeof attackKnowledgeVaultPresetPreview>;
    };
    expect(selectedPayload.preset.operatorProfileAvailability).toEqual({
      requested: true,
      available: false,
      status: "no_eligible_confirmed_profile",
      eligibleNodeCount: 0,
    });
    expect(selectedPayload.preset.projection.operatorProfileIncluded).toBe(false);
    expect(selectedPayload.preset.projection.operatorProfileNodeCount).toBe(0);
    expect(selectedPayload.preset.projection.nodeTypes).not.toContain("preference");
    expect(selectedPayload.preset.operatorProfileScopeUpgrade).toBeUndefined();
    expect(selectedPayload.preset.policyHash).toBe(attackKnowledgeVaultPolicyHash({ includeConfirmed: true }));
    expect(database.prepare(`
      SELECT COUNT(*) AS count FROM audit_records
      WHERE action = 'vault.attack_knowledge_preset.operator_profile_scope_amended'
    `).get()).toEqual({ count: 0 });
    database.close();
  });
});

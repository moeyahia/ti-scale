import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createDatabaseConnection, migrateDatabase } from "../../db";
import type { TrustedLocalFileReceipt } from "../../trusted-runtime-config";
import {
  OPERATOR_PREFERENCE_MANIFEST_SCHEMA_VERSION,
  OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY,
  loadTrustedOperatorPreferenceManifest,
  parseOperatorPreferenceManifest,
} from "../OperatorPreferenceManifest";
import { OperatorPreferenceImportService } from "../OperatorPreferenceImportService";

const NOW = "2026-07-21T12:00:00.000Z";
const SOURCE_SHA = createHash("sha256").update("reviewed operator manifest", "utf8").digest("hex");
const CANONICAL_SHA = createHash("sha256").update("canonical operator manifest", "utf8").digest("hex");
const REVIEWED_MANIFEST_PATH = resolve(
  import.meta.dir,
  "../../../deployment/runtime-config/operator-preferences.v2.json",
);
const REVIEWED_MANIFEST_SHA = "2235aaee064c2017e031ec20bd657bc1af5432f96032d8b1f3d7c91c76e87aac";
const directories: string[] = [];

afterEach(() => directories.splice(0).forEach((directory) => {
  rmSync(directory, { recursive: true, force: true });
}));

function manifest(overrides: Record<string, unknown> = {}) {
  return parseOperatorPreferenceManifest({
    schemaVersion: OPERATOR_PREFERENCE_MANIFEST_SCHEMA_VERSION,
    manifestVersion: "operator-preferences-test-v1",
    operatorId: "operator-test",
    retentionPolicy: {
      durableOnly: true,
      excludeOneTimeCommands: true,
      excludeTargetSpecificData: true,
      excludeCredentialsAndSecrets: true,
    },
    safetyBoundary: OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY,
    source: {
      sourceType: "operator_instruction_manifest",
      sourceId: "operator-thread-test",
      acquiredAt: "2026-07-21T11:00:00.000Z",
    },
    preferences: [{
      id: "technical-readable",
      preferenceKey: "communication.technical_readability",
      category: "communication",
      title: "Readable technical language",
      summary: "Keep accurate explanations readable without making them simplistic.",
      body: "Explain purpose, operational meaning, evidence, and useful technical detail.",
      value: { style: "technical_readable", evidenceFirst: true },
      appliesTo: ["guided_explanations", "evidence_presentation"],
      sensitivity: "private",
      consentPolicy: "explicit_operator_confirmation",
    }],
    ...overrides,
  });
}

function receipt(): TrustedLocalFileReceipt {
  return {
    schemaVersion: "ti-scale.trusted-local-file-receipt.v1",
    sourcePath: "/trusted/operator-preferences.json",
    trustRoot: "/trusted",
    sourceSha256: SOURCE_SHA,
    canonicalSha256: CANONICAL_SHA,
    byteSize: 1_024,
    ownerUid: 0,
    ownerGid: 0,
    mode: 0o644,
    device: "1",
    inode: "2",
  };
}

function setup() {
  const directory = mkdtempSync(join(tmpdir(), "operator-preference-import-"));
  directories.push(directory);
  const database = createDatabaseConnection({ filename: join(directory, "memory.sqlite") });
  migrateDatabase(database);
  return { database, service: new OperatorPreferenceImportService(database, { clock: () => new Date(NOW) }) };
}

describe("OperatorPreferenceImportService", () => {
  test("pins the complete v2 manifest and its durable safety boundaries", () => {
    const source = readFileSync(REVIEWED_MANIFEST_PATH);
    expect(createHash("sha256").update(source).digest("hex")).toBe(REVIEWED_MANIFEST_SHA);
    const loaded = loadTrustedOperatorPreferenceManifest({
      path: REVIEWED_MANIFEST_PATH,
      trustRoot: resolve(import.meta.dir, "../../../deployment/runtime-config"),
      expectedSha256: REVIEWED_MANIFEST_SHA,
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
    });
    expect(loaded.value).toMatchObject({
      schemaVersion: "ti-scale.operator-preferences.v2",
      retentionPolicy: {
        durableOnly: true,
        excludeOneTimeCommands: true,
        excludeTargetSpecificData: true,
        excludeCredentialsAndSecrets: true,
      },
      safetyBoundary: OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY,
    });
    expect(loaded.value.preferences).toHaveLength(20);
    expect(new Set(loaded.value.preferences.map(({ category }) => category))).toEqual(new Set([
      "autonomy",
      "brain",
      "communication",
      "deployment",
      "documentation",
      "memory",
      "model_selection",
      "product",
      "roadmap",
      "visual",
    ]));
    expect(loaded.value.preferences.map(({ preferenceKey }) => preferenceKey)).toEqual(
      expect.arrayContaining([
        "brain.active_obsidian_vault",
        "brain.agent_context_use",
        "deployment.public_repository",
        "documentation.standalone_product",
        "memory.attack_outcome_classification",
        "memory.operator_preference_category",
        "memory.private_source_linkage",
        "model_selection.quality_first",
        "product.standalone_delivery",
        "visual.brain_anatomy",
      ]),
    );
    const fixture = setup();
    try {
      const preview = fixture.service.preview({
        manifest: loaded.value,
        receipt: loaded.receipt,
        actorId: "local-operator",
      });
      expect(preview.preferenceCount).toBe(20);
      expect(preview.items.every(({ candidateDisposition }) => candidateDisposition === "missing"))
        .toBe(true);
      expect(preview.items.find(({ preferenceKey }) => preferenceKey === "memory.private_source_linkage"))
        .toMatchObject({
          category: "memory",
          profile: {
            value: {
              category: "memory",
              appliesTo: expect.arrayContaining(["memory_provenance"]),
            },
          },
        });
      expect(fixture.database.prepare("SELECT COUNT(*) count FROM memory_nodes").get())
        .toEqual({ count: 0 });
    } finally {
      fixture.database.close();
    }
  });

  test("loads only the exact reviewed manifest bytes", () => {
    const directory = mkdtempSync(join(tmpdir(), "operator-preference-manifest-"));
    directories.push(directory);
    chmodSync(directory, 0o700);
    const path = join(directory, "preferences.json");
    const source = JSON.stringify(manifest());
    writeFileSync(path, source, { encoding: "utf8", mode: 0o600 });
    const digest = createHash("sha256").update(source, "utf8").digest("hex");
    expect(loadTrustedOperatorPreferenceManifest({
      path,
      trustRoot: directory,
      expectedSha256: digest,
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
    }).receipt.sourceSha256).toBe(digest);
    expect(() => loadTrustedOperatorPreferenceManifest({
      path,
      trustRoot: directory,
      expectedSha256: "0".repeat(64),
      allowedOwnerUids: [process.geteuid?.() ?? process.getuid?.() ?? 0],
    })).toThrow(/reviewed SHA-256/i);
  });

  test("previews exact confirmed nodes without writing, then imports idempotently through canonical memory services", () => {
    const fixture = setup();
    try {
      const input = { manifest: manifest(), receipt: receipt(), actorId: "operator-test" };
      const preview = fixture.service.preview(input);
      expect(preview).toMatchObject({
        schemaVersion: "ti-scale.operator-preference-import-preview.v1",
        manifestSha256: SOURCE_SHA,
        preferenceCount: 1,
        items: [{
          preferenceId: "technical-readable",
          candidateDisposition: "missing",
          node: {
            nodeType: "preference",
            lifecycleStatus: "confirmed",
            confirmationState: "confirmed",
            authorType: "operator",
            authorId: "operator-test",
          },
          profile: {
            preferenceKey: "communication.technical_readability",
            confirmationState: "confirmed",
            consentPolicy: "explicit_operator_confirmation",
          },
        }],
      });
      expect(preview.previewHash).toMatch(/^[a-f0-9]{64}$/u);
      expect(fixture.database.prepare("SELECT COUNT(*) count FROM memory_candidates").get()).toEqual({ count: 0 });
      expect(fixture.database.prepare("SELECT COUNT(*) count FROM preference_profiles").get()).toEqual({ count: 0 });

      const result = fixture.service.execute({
        ...input,
        expectedPreviewHash: preview.previewHash,
        reason: "Operator approved the reviewed preference manifest",
      });
      expect(result).toMatchObject({
        createdCandidates: 1,
        confirmedCandidates: 1,
        replayedCandidates: 0,
        createdProfiles: 1,
        createdObservations: 1,
        createdAudits: 1,
        operatorNodeId: expect.stringMatching(/^mem_operator_[a-f0-9]{48}$/u),
        createdGraphNodes: 3,
        replayedGraphNodes: 0,
        createdGraphEdges: 3,
        replayedGraphEdges: 0,
      });
      expect(result.nodeIds).toHaveLength(1);
      expect(fixture.database.prepare(`
        SELECT node_type, scope, sensitivity, lifecycle_status, confirmation_state,
          author_type, author_id FROM memory_nodes WHERE node_type = 'preference'
      `).get()).toEqual({
        node_type: "preference",
        scope: "global",
        sensitivity: "private",
        lifecycle_status: "confirmed",
        confirmation_state: "confirmed",
        author_type: "operator",
        author_id: "operator-test",
      });
      expect(fixture.database.prepare(`
        SELECT confirmation_state, confidence, consent_policy, source_node_id
        FROM preference_profiles
      `).get()).toMatchObject({
        confirmation_state: "confirmed",
        confidence: 1,
        consent_policy: "explicit_operator_confirmation",
        source_node_id: result.nodeIds[0],
      });
      expect(fixture.database.prepare(`
        SELECT consent_state, confidence, source_type FROM preference_observations
      `).get()).toEqual({
        consent_state: "granted",
        confidence: 1,
        source_type: "operator_instruction_manifest",
      });
      expect(fixture.database.prepare(`
        SELECT actor_type, actor_id, action, resource_type, resource_id,
          details_json, record_hash FROM audit_records
        WHERE action = 'memory.preference.confirmed_from_manifest'
      `).get()).toMatchObject({
        actor_type: "operator",
        actor_id: "operator-test",
        resource_type: "memory_node",
        resource_id: result.nodeIds[0],
        details_json: expect.stringContaining(`"manifestSha256":"${SOURCE_SHA}"`),
        record_hash: expect.stringMatching(/^[a-f0-9]{64}$/u),
      });
      expect(fixture.database.prepare(`
        SELECT source_type, source_hash, excerpt_redacted FROM memory_sources
        WHERE node_id = ?
      `).get(result.nodeIds[0]!)).toMatchObject({
        source_type: "operator_instruction_manifest",
        source_hash: SOURCE_SHA,
        excerpt_redacted: "Keep accurate explanations readable without making them simplistic.",
      });

      const replayPreview = fixture.service.preview(input);
      expect(replayPreview.previewHash).toBe(preview.previewHash);
      expect(replayPreview.items[0]).toMatchObject({
        candidateDisposition: "confirmed",
        nodeId: result.nodeIds[0],
      });
      const replay = fixture.service.execute({
        ...input,
        expectedPreviewHash: preview.previewHash,
        reason: "Operator approved the reviewed preference manifest",
      });
      expect(replay).toMatchObject({
        createdCandidates: 0,
        confirmedCandidates: 0,
        replayedCandidates: 1,
        createdProfiles: 0,
        replayedProfiles: 1,
        createdObservations: 0,
        replayedObservations: 1,
        createdAudits: 0,
        replayedAudits: 1,
        createdGraphNodes: 0,
        replayedGraphNodes: 3,
        createdGraphEdges: 0,
        replayedGraphEdges: 3,
      });
      expect(fixture.database.prepare("SELECT COUNT(*) count FROM memory_nodes").get()).toEqual({ count: 4 });
      expect(fixture.database.prepare("SELECT COUNT(*) count FROM memory_edges").get()).toEqual({ count: 3 });
      for (const table of ["memory_candidates", "preference_profiles", "preference_observations"]) {
        expect(fixture.database.prepare(`SELECT COUNT(*) count FROM ${table}`).get()).toEqual({ count: 1 });
      }
      expect(fixture.database.prepare(`
        SELECT source_node_id, edge_type, target_node_id, lifecycle_status,
          author_type, author_id FROM memory_edges ORDER BY edge_type, target_node_id
      `).all()).toEqual(expect.arrayContaining([
        expect.objectContaining({
          source_node_id: result.operatorNodeId,
          edge_type: "prefers",
          target_node_id: result.nodeIds[0],
          lifecycle_status: "confirmed",
          author_type: "operator",
          author_id: "operator-test",
        }),
        expect.objectContaining({ edge_type: "applies_to", source_node_id: result.nodeIds[0] }),
      ]));
      expect(fixture.database.prepare(`
        SELECT COUNT(*) count FROM audit_records
        WHERE action = 'memory.preference.confirmed_from_manifest'
      `).get()).toEqual({ count: 1 });
    } finally {
      fixture.database.close();
    }
  });

  test("fails closed on actor drift and stale preview authorization", () => {
    const fixture = setup();
    try {
      const input = { manifest: manifest(), receipt: receipt(), actorId: "operator-test" };
      expect(() => fixture.service.preview({ ...input, actorId: "different-operator" }))
        .toThrow(/operator does not match/i);
      expect(() => fixture.service.execute({
        ...input,
        expectedPreviewHash: "0".repeat(64),
        reason: "Operator approved the reviewed preference manifest",
      })).toThrow(/preview changed/i);
      expect(fixture.database.prepare("SELECT COUNT(*) count FROM memory_nodes").get()).toEqual({ count: 0 });
    } finally {
      fixture.database.close();
    }
  });

  test("rejects secret-bearing preference text before preview or persistence", () => {
    const source = {
      schemaVersion: OPERATOR_PREFERENCE_MANIFEST_SCHEMA_VERSION,
      manifestVersion: "operator-preferences-secret-test-v1",
      operatorId: "operator-test",
      retentionPolicy: {
        durableOnly: true,
        excludeOneTimeCommands: true,
        excludeTargetSpecificData: true,
        excludeCredentialsAndSecrets: true,
      },
      safetyBoundary: OPERATOR_PREFERENCE_MANIFEST_SAFETY_BOUNDARY,
      source: {
        sourceType: "operator_instruction_manifest",
        sourceId: "operator-thread-test",
        acquiredAt: "2026-07-21T11:00:00.000Z",
      },
      preferences: [{
        id: "unsafe-preference",
        preferenceKey: "communication.unsafe",
        category: "communication",
        title: "Unsafe retained value",
        summary: "Never retain authentication material.",
        body: "api_key = sk-example-realsecretvalue123456789",
        value: { style: "unsafe" },
        appliesTo: ["guided_explanations"],
        sensitivity: "private",
        consentPolicy: "explicit_operator_confirmation",
      }],
    };
    expect(() => parseOperatorPreferenceManifest(source)).toThrow(/credentials|authentication material/i);
  });

  test("rejects v1, unknown categories, and any relaxed durable-retention boundary", () => {
    const valid = manifest();
    expect(() => parseOperatorPreferenceManifest({ ...valid, schemaVersion: "ti-scale.operator-preferences.v1" }))
      .toThrow(/schemaVersion is unsupported/i);
    expect(() => parseOperatorPreferenceManifest({
      ...valid,
      retentionPolicy: { ...valid.retentionPolicy, excludeOneTimeCommands: false },
    })).toThrow(/excludeOneTimeCommands must be true/i);
    expect(() => parseOperatorPreferenceManifest({
      ...valid,
      preferences: [{ ...valid.preferences[0], category: "runtime_policy" }],
    })).toThrow(/category is invalid/i);
  });
});

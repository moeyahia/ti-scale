import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import type { SqliteDatabase } from "../../db";
import {
  FileScriptSourceStore,
  MemoryScriptSourceStore,
  ScriptArtifactError,
  ScriptArtifactService,
  scriptSourceStoreCompositionReceiptValid,
  scriptContentHash,
  type CreateScriptArtifactInput,
} from "..";
import {
  AGENT_ONE_ID,
  createTestDatabase,
  MISSION_ID,
  NOW,
  PLAN_ID,
  RUN_ID,
  STEP_ONE_ID,
} from "../../../tests/unit/run-intelligence/fixtures";

const CLOCK = "2026-07-16T13:00:00.000Z";
const ACTOR = { id: "operator-script-reviewer", type: "operator" as const };
const TARGET_ID = "asset-script-target";
const ATTEMPT_ID = "attempt-script-source";

function seedScope(database: SqliteDatabase): void {
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label, normalized_identity,
      scope_status, lifecycle_state, confidence, verification_state,
      originating_agent_id, sensitivity, first_seen_at, last_seen_at,
      created_at, updated_at
    ) VALUES (?, ?, ?, 'asset', 'fixture-web', '10.10.10.10', 'allowed',
      'observed', 0.95, 'verified', ?, 'internal', ?, ?, ?, ?)
  `).run(TARGET_ID, MISSION_ID, RUN_ID, AGENT_ONE_ID, NOW, NOW, NOW, NOW);
  database.prepare(`
    INSERT INTO attack_attempts (
      id, mission_id, run_id, plan_id, step_id, target_asset_id,
      objective, technique_name, action_class, status, assigned_agent_id,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'Collect bounded response metadata',
      'Fixture metadata probe', 'web_crawling_page_capture', 'planned', ?, ?, ?)
  `).run(ATTEMPT_ID, MISSION_ID, RUN_ID, PLAN_ID, STEP_ONE_ID, TARGET_ID, AGENT_ONE_ID, NOW, NOW);
}

function input(overrides: Partial<CreateScriptArtifactInput> = {}): CreateScriptArtifactInput {
  return {
    missionId: MISSION_ID,
    runId: RUN_ID,
    planId: PLAN_ID,
    stepId: STEP_ONE_ID,
    attackAttemptId: ATTEMPT_ID,
    targetNodeId: TARGET_ID,
    name: "recon/http_probe.py",
    language: "python",
    source: [
      "#!/usr/bin/env python3",
      "import os",
      "token = os.environ[\"TARGET_TOKEN\"]",
      "print(\"ready\")",
      "",
    ].join("\n"),
    laymanExplanation: "Collects one bounded response marker from the selected authorized fixture.",
    technicalPurpose: "Reads a runtime credential reference and emits one deterministic readiness marker.",
    inputs: [{
      name: "TARGET_TOKEN",
      description: "Opaque runtime reference supplied by the authorized operator.",
      required: true,
      sensitivity: "secret_reference",
    }],
    expectedOutputs: [{
      label: "Readiness marker",
      description: "One line indicating that local input validation completed.",
      successRecognition: "The exact line ready is present.",
      failureRecognition: "The process exits before printing the readiness marker.",
    }],
    prerequisites: ["Python 3 is available in the approved isolated environment."],
    dependencies: ["Standard-library os module."],
    touches: {
      files: [],
      network: ["The selected authorized fixture endpoint when execution is separately approved."],
      services: ["Fixture HTTPS service."],
    },
    sideEffects: ["No execution occurs when this artifact version is created."],
    riskClass: "low",
    reversibility: "Creating this record is reversible by excluding it from future plans; immutable history remains auditable.",
    cleanupNotes: "No target cleanup is needed because this service does not execute the source.",
    secretsHandling: "Read the opaque token from an approved environment variable at runtime and never persist its value.",
    evidenceExpectations: ["A separately authorized test result must be linked before tested or approved status."],
    validation: {
      state: "unvalidated",
      summary: "Source is documented but has not been executed or represented as tested.",
      tests: [],
    },
    provenance: {
      origin: "agent_generated",
      explanation: "Recon specialist proposed this bounded helper for operator review.",
      sourceRefs: ["plan-step:step-intelligence-1"],
      authorAgentId: AGENT_ONE_ID,
    },
    sensitivity: "internal",
    ...overrides,
  };
}

describe("ScriptArtifactService", () => {
  test("persists a real source artifact, immutable version, audit, and event without execution", () => {
    const database = createTestDatabase();
    try {
      seedScope(database);
      const store = new MemoryScriptSourceStore();
      const service = new ScriptArtifactService(database, store, () => new Date(CLOCK));
      const created = service.create(input(), ACTOR);

      expect(created).toMatchObject({
        missionId: MISSION_ID,
        runId: RUN_ID,
        planId: PLAN_ID,
        stepId: STEP_ONE_ID,
        attackAttemptId: ATTEMPT_ID,
        targetNodeId: TARGET_ID,
        name: "recon/http_probe.py",
        version: 1,
        language: "python",
        createdBy: ACTOR.id,
      });
      expect(created.contentHash).toBe(scriptContentHash(created.source));
      expect(created.diff).toMatchObject({
        toVersion: 1,
        sourceChanged: true,
      });
      expect(created.diff.previousScriptArtifactId).toBeUndefined();
      expect(service.get(created.id)).toEqual(created);
      expect(service.list({ missionId: MISSION_ID, runId: RUN_ID, stepId: STEP_ONE_ID })).toEqual([
        expect.objectContaining({ id: created.id, contentHash: created.contentHash }),
      ]);

      const artifact = database.prepare(`
        SELECT artifact_type, storage_uri, content_hash, byte_size, metadata_json
        FROM artifacts WHERE id = ?
      `).get(created.artifactId) as Record<string, unknown>;
      expect(artifact).toMatchObject({
        artifact_type: "generated_script_source",
        storage_uri: `ti-scale-script://sha256/${created.contentHash}`,
        content_hash: created.contentHash,
        byte_size: Buffer.byteLength(created.source, "utf8"),
      });
      expect(String(artifact.metadata_json)).not.toContain(created.source);
      expect((database.prepare("SELECT COUNT(*) AS count FROM actions").get() as { count: number }).count).toBe(0);
      expect((database.prepare("SELECT COUNT(*) AS count FROM tool_calls").get() as { count: number }).count).toBe(0);
      const event = database.prepare("SELECT summary, payload_json FROM events WHERE event_type = 'script_artifact.created'").get() as { summary: string; payload_json: string };
      expect(event.summary).toContain("no execution was performed");
      expect(JSON.parse(event.payload_json)).toMatchObject({ executionPerformed: false, contentHash: created.contentHash });
      const audit = database.prepare("SELECT action, record_hash, details_json FROM audit_records WHERE resource_id = ?").get(created.id) as { action: string; record_hash: string; details_json: string };
      expect(audit.action).toBe("script_artifact.created");
      expect(audit.record_hash).toHaveLength(64);
      expect(JSON.parse(audit.details_json)).toMatchObject({ executionPerformed: false });
    } finally { database.close(); }
  });

  test("creates a new immutable version with exact hash and bounded line-diff metadata", () => {
    const database = createTestDatabase();
    try {
      seedScope(database);
      const service = new ScriptArtifactService(database, new MemoryScriptSourceStore(), () => new Date(CLOCK));
      const first = service.create(input(), ACTOR);
      const secondSource = first.source.replace("print(\"ready\")", "print(\"ready:v2\")");
      const versionInput = {
        scriptArtifactId: first.id,
        expectedVersion: 1,
        changeSummary: "Make the readiness marker version-specific for deterministic test parsing.",
        language: "python",
        source: secondSource,
        laymanExplanation: first.laymanExplanation,
        technicalPurpose: first.technicalPurpose,
        inputs: first.inputs,
        expectedOutputs: [{ ...first.expectedOutputs[0]!, successRecognition: "The exact line ready:v2 is present." }],
        prerequisites: first.requirements.prerequisites,
        dependencies: first.requirements.dependencies,
        touches: first.touches,
        sideEffects: first.risk.sideEffects,
        riskClass: first.risk.riskClass,
        reversibility: first.risk.reversibility,
        cleanupNotes: first.cleanupNotes,
        secretsHandling: first.secretsHandling,
        evidenceExpectations: first.evidenceExpectations,
        validation: first.validation,
        provenance: {
          origin: "modified",
          explanation: "Operator accepted one source and output-recognition amendment.",
          sourceRefs: [`script-artifact:${first.id}`],
          authorAgentId: AGENT_ONE_ID,
        },
        sensitivity: "internal",
      } as const;
      const second = service.createVersion(versionInput, ACTOR);

      expect(second.version).toBe(2);
      expect(second.id).not.toBe(first.id);
      expect(second.artifactId).not.toBe(first.artifactId);
      expect(second.contentHash).not.toBe(first.contentHash);
      expect(second.diff).toMatchObject({
        previousScriptArtifactId: first.id,
        fromVersion: 1,
        toVersion: 2,
        previousContentHash: first.contentHash,
        sourceChanged: true,
        removedLineCount: 1,
        addedLineCount: 1,
      });
      expect(second.diff.changedFields).toEqual(expect.arrayContaining(["source", "expectedOutputs", "provenance"]));
      expect(service.get(first.id).source).toBe(first.source);
      expect(service.get(second.id).source).toBe(secondSource);
      expect(service.list({ missionId: MISSION_ID, name: first.name })).toHaveLength(2);
      expect(() => service.createVersion({
        ...versionInput,
        changeSummary: "Stale edit.",
      }, ACTOR)).toThrow("changed after it was loaded");
    } finally { database.close(); }
  });

  test("rejects embedded credentials, unsafe source paths, and mismatched target scope before persistence", () => {
    const database = createTestDatabase();
    try {
      seedScope(database);
      database.prepare(`
        INSERT INTO runs (
          id, mission_id, journey, status, progress, created_at, updated_at
        ) VALUES ('run-other-script', ?, 'autonomous', 'running', 0, ?, ?)
      `).run(MISSION_ID, NOW, NOW);
      database.prepare(`
        INSERT INTO topology_nodes (
          id, mission_id, run_id, node_type, primary_label, normalized_identity,
          scope_status, lifecycle_state, confidence, verification_state,
          sensitivity, first_seen_at, last_seen_at, created_at, updated_at
        ) VALUES ('asset-other-run', ?, 'run-other-script', 'asset', 'other',
          '10.10.10.20', 'allowed', 'observed', 0.8, 'corroborated',
          'internal', ?, ?, ?, ?)
      `).run(MISSION_ID, NOW, NOW, NOW, NOW);
      const service = new ScriptArtifactService(database, new MemoryScriptSourceStore(), () => new Date(CLOCK));

      expect(() => service.create(input({
        source: "#!/usr/bin/env python3\npassword = \"hunter2\"\n",
      }), ACTOR)).toThrow("literal assigned to a credential-like field");
      expect(() => service.create(input({
        source: "#!/usr/bin/env python3\nAWS_SECRET_ACCESS_KEY = \"fixture-credential-value\"\n",
      }), ACTOR)).toThrow("literal assigned to a credential-like field");
      expect(() => service.create(input({ name: "../http_probe.py" }), ACTOR)).toThrow("unsafe or ambiguous path component");
      expect(() => service.create(input({ targetNodeId: "asset-other-run", attackAttemptId: undefined }), ACTOR)).toThrow("outside the script mission/run");
      expect((database.prepare("SELECT COUNT(*) AS count FROM script_artifacts").get() as { count: number }).count).toBe(0);
      expect((database.prepare("SELECT COUNT(*) AS count FROM artifacts").get() as { count: number }).count).toBe(0);
    } finally { database.close(); }
  });

  test("requires scoped test artifacts for tested status and rejects writes to a legacy control plane", () => {
    const database = createTestDatabase();
    try {
      seedScope(database);
      const service = new ScriptArtifactService(database, new MemoryScriptSourceStore(), () => new Date(CLOCK));
      expect(() => service.create(input({
        validation: {
          state: "tested",
          summary: "One isolated fixture test passed.",
          tests: [{ name: "fixture smoke test", status: "passed", summary: "Fixture returned the expected marker." }],
        },
      }), ACTOR)).toThrow("require passed tests and a canonical test-result artifact");

      database.prepare(`
        INSERT INTO artifacts (
          id, mission_id, run_id, step_id, journey, artifact_type, storage_uri,
          content_hash, byte_size, media_type, sensitivity, metadata_json, created_at
        ) VALUES ('artifact-script-test', ?, ?, ?, 'autonomous', 'script_test_result',
          'fixture-test://artifact-script-test', ?, 120, 'application/json',
          'internal', '{}', ?)
      `).run(MISSION_ID, RUN_ID, STEP_ONE_ID, "c".repeat(64), NOW);
      const tested = service.create(input({
        validation: {
          state: "tested",
          summary: "One isolated fixture test passed; this record does not execute the script.",
          tests: [{ name: "fixture smoke test", status: "passed", summary: "Fixture returned the expected marker." }],
          testArtifactId: "artifact-script-test",
        },
      }), ACTOR);
      expect(tested.validation).toMatchObject({ state: "tested", testArtifactId: "artifact-script-test" });

      database.prepare("UPDATE missions SET control_plane = 'legacy' WHERE id = ?").run(MISSION_ID);
      expect(() => service.create(input({ name: "recon/second_probe.py" }), ACTOR)).toThrow("Legacy-controlled missions are read-only");
    } finally { database.close(); }
  });

  test("filesystem source store uses a hash-only path and verifies every read", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-script-store-"));
    try {
      const store = new FileScriptSourceStore(root);
      const compositionNow = new Date("2026-07-16T13:00:00.000Z");
      const composition = store.inspectComposition(compositionNow);
      expect(composition).toMatchObject({
        storeId: "file-content-addressed-v1",
        immutableContentAddressed: true,
        localFilesystem: true,
        targetInteraction: false,
        executionAuthority: "none",
      });
      expect(scriptSourceStoreCompositionReceiptValid(
        composition,
        compositionNow,
      )).toBe(true);
      expect(JSON.stringify(composition)).not.toContain(root);
      expect(scriptSourceStoreCompositionReceiptValid(
        composition,
        new Date("2026-07-16T13:01:00.000Z"),
      )).toBe(false);
      const source = "#!/bin/sh\nprintf '%s\\n' ready\n";
      const hash = scriptContentHash(source);
      const stored = store.put(hash, source);
      expect(stored.storageUri).toBe(`ti-scale-script://sha256/${hash}`);
      expect(store.read(stored.storageUri, hash)).toBe(source);
      const storedPath = join(root, hash.slice(0, 2), hash);
      expect(readFileSync(storedPath, "utf8")).toBe(source);
      expect(() => store.read("ti-scale-script://sha256/" + "d".repeat(64), hash)).toThrow(ScriptArtifactError);
      writeFileSync(storedPath, "tampered", "utf8");
      expect(() => store.read(stored.storageUri, hash)).toThrow("failed SHA-256 verification");
      expect(() => new FileScriptSourceStore("relative/script-store")).toThrow("explicit absolute path");
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

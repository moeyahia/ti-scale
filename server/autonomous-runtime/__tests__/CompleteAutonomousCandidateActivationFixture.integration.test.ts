import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
} from "../../db";
import { MemoryRepository } from "../../memory";
import { ObsidianVaultBridge } from "../../vault/ObsidianVaultBridge";
import { VaultPathPolicy } from "../../vault/VaultPathPolicy";
import {
  COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE,
  COMPLETE_AUTONOMOUS_CANDIDATE_EXPLOIT_SOURCE,
  prepareCompleteAutonomousCandidateActivationFixture,
} from "../testing/CompleteAutonomousCandidateActivationFixture";
import {
  COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
} from "../testing/CompleteAutonomousCandidateProcedureProviderSource";
import {
  COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION,
  COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_DATABASE,
  completeAutonomousCandidatePreparationUsage,
  parseCompleteAutonomousCandidatePreparationArguments,
} from "../../../scripts/prepare-complete-autonomous-candidate-activation";

const roots: string[] = [];

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-complete-activation-"));
  roots.push(root);
  const databasePath = join(root, "ti-scale.sqlite");
  const database = createDatabaseConnection({ filename: databasePath });
  migrateDatabase(database);
  const vaultSandboxRoot = join(root, "vaults");
  const clock = () => new Date("2026-07-28T20:45:00.000Z");
  const paths = new VaultPathPolicy(vaultSandboxRoot);
  const bridge = new ObsidianVaultBridge(
    database,
    new MemoryRepository(database, { clock }),
    paths,
    { clock },
  );
  const connection = bridge.connect({
    id: "vault:complete-autonomous-fixture-test",
    vaultPath: "Attack-Knowledge-Vault",
    displayName: "Complete Autonomous Fixture Test Vault",
    permissionGranted: true,
  });
  const activationSourceRoot = join(root, "activation-source");
  mkdirSync(activationSourceRoot, { mode: 0o700 });
  const executables = [
    ["adapter", "#!/bin/sh\nexit 70\n"],
    ["broker", "#!/bin/sh\nexit 71\n"],
    ["register", "#!/bin/sh\nexit 72\n"],
  ] as const;
  const sources = Object.fromEntries(executables.map(([name, source]) => {
    const path = join(activationSourceRoot, name);
    writeFileSync(path, source, { encoding: "utf8", mode: 0o700 });
    return [name, { path, sha256: sha256(source) }];
  })) as Record<string, { path: string; sha256: string }>;
  return {
    root,
    database,
    databasePath,
    vaultSandboxRoot,
    connection,
    activationSourceRoot,
    sources,
    clock,
  };
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("complete Autonomous candidate activation fixture", () => {
  it("requires explicit execution and cannot be redirected to another database", () => {
    expect(completeAutonomousCandidatePreparationUsage()).toContain(
      COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION,
    );
    expect(COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION).toContain(
      COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_DATABASE,
    );
    expect(COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION).toContain(
      "127.0.0.2:8080 FIXTURE SEED",
    );
    expect(parseCompleteAutonomousCandidatePreparationArguments([
      "--execute",
      "--confirm-fixture-seed",
      COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION,
    ])).toMatchObject({
      execute: true,
      confirmation:
        COMPLETE_AUTONOMOUS_CANDIDATE_FIXTURE_SEED_CONFIRMATION,
      databasePath: COMPLETE_AUTONOMOUS_CANDIDATE_PRODUCTION_DATABASE,
    });
    expect(() => parseCompleteAutonomousCandidatePreparationArguments([]))
      .toThrow("Usage:");
    expect(() => parseCompleteAutonomousCandidatePreparationArguments([
      "--execute",
      "--database-path",
      "/tmp/other.sqlite",
    ])).toThrow("Usage:");
    expect(() => parseCompleteAutonomousCandidatePreparationArguments([
      "--execute",
      "--confirm-fixture-seed",
      "I understand",
    ])).toThrow("Usage:");
  });

  it("idempotently seeds canonical review, approved source, Brain, real Vault projection, and exact activation inputs", () => {
    const value = fixture();
    try {
      const input = {
        database: value.database,
        databasePath: value.databasePath,
        vaultSandboxRoot: value.vaultSandboxRoot,
        activationSourceRoot: value.activationSourceRoot,
        adapterPath: value.sources.adapter!.path,
        adapterSha256: value.sources.adapter!.sha256,
        brokerPath: value.sources.broker!.path,
        brokerSha256: value.sources.broker!.sha256,
        registerPath: value.sources.register!.path,
        registerSha256: value.sources.register!.sha256,
        serviceGid: 1_234,
        serviceUid: 0,
        expectedVaultPath: value.connection.vaultPath,
        expectedVaultDisplayName: value.connection.displayName,
        now: value.clock,
      } as const;
      const first = prepareCompleteAutonomousCandidateActivationFixture(input);
      const second =
        prepareCompleteAutonomousCandidateActivationFixture(input);

      expect(second).toEqual(first);
      expect(first).toMatchObject({
        status: "prepared",
        fixtureOnly: true,
        noBackupCreated: true,
        deploymentPerformed: false,
        serviceRestarted: false,
        databaseSchemaVersion: 63,
        capabilityScope: "exact_disposable_fixture_only",
        supportedTarget: "127.0.0.2:8080",
        generalExternalTargetSupport: false,
        generalMissionReadinessEligible: false,
        targetScopedReadinessRequired: true,
        vaultConnectionId: value.connection.id,
        vaultPath: value.connection.vaultPath,
        vaultProjectionStatus: "complete",
        bindingId: COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
        postExploitSpecId:
          "post-exploit-spec:reviewed-complete-autonomous-fixture-v1",
      });
      expect(first.brainNodeIds).toHaveLength(6);
      expect(new Set(first.brainNodeIds).size).toBe(6);
      expect(first.source.adapterSha256).toBe(value.sources.adapter!.sha256);
      expect(first.source.procedureSha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(first.manifestSha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(
        first.registration.environment
          .TI_SCALE_CANDIDATE_LINUX_MANIFEST_SHA256,
      ).toBe(first.manifestSha256);
      expect(first.installer.sourceVerifyArguments[0]).toBe("source-verify");
      expect(first.installer.installArguments.at(-1)).toBe("--execute");
      expect(readFileSync(first.source.procedurePath, "utf8"))
        .not.toBe(COMPLETE_AUTONOMOUS_CANDIDATE_EXPLOIT_SOURCE);

      const script = value.database.prepare(`
        SELECT script.id, artifact.storage_uri, script.content_hash,
          script.validation_state, script.run_id, script.target_node_id
        FROM script_artifacts script
        JOIN artifacts artifact ON artifact.id = script.artifact_id
        WHERE script.id = ?
      `).get(first.scriptArtifactId);
      expect(script).toMatchObject({
        id: first.scriptArtifactId,
        content_hash: first.scriptContentSha256,
        validation_state: "approved",
        run_id: COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.runId,
        target_node_id:
          COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.assetId,
      });
      expect((script as { storage_uri: string }).storage_uri)
        .toMatch(/^ti-scale-script:\/\/sha256\/[a-f0-9]{64}$/u);

      const observer = value.database.prepare(`
        SELECT request_json, assertion_json, status
        FROM exploit_outcome_observer_specs WHERE id = ?
      `).get(first.observerSpecId) as {
        request_json: string;
        assertion_json: string;
        status: string;
      };
      expect(observer.status).toBe("active");
      expect(JSON.parse(observer.request_json)).toMatchObject({
        port: 8_080,
        method: "GET",
        path: "/.%2e/.%2e/fixture-impact",
      });
      expect(JSON.parse(observer.assertion_json)).toMatchObject({
        statusCodes: [200],
        bodyContains: expect.arrayContaining([
          "TI_SCALE_LOOPBACK_FIXTURE_READ_ONLY_IMPACT",
        ]),
        headerEquals: {},
      });

      const projected = value.database.prepare(`
        SELECT COUNT(*) AS count FROM vault_sync_state
        WHERE connection_id = ? AND status = 'synced'
          AND node_id IN (${first.brainNodeIds.map(() => "?").join(",")})
      `).get(value.connection.id, ...first.brainNodeIds) as { count: number };
      expect(projected.count).toBe(6);

      const notes = value.database.prepare(`
        SELECT title, summary, body, retention_policy_json,
          provenance_json, author_id
        FROM memory_nodes
        WHERE id IN (${first.brainNodeIds.map(() => "?").join(",")})
        ORDER BY id
      `).all(...first.brainNodeIds) as Array<{
        title: string;
        summary: string;
        body: string;
        retention_policy_json: string;
        provenance_json: string;
        author_id: string;
      }>;
      expect(notes).toHaveLength(6);
      for (const note of notes) {
        expect(note.title.startsWith("[DISPOSABLE FIXTURE ONLY] ")).toBe(true);
        expect(note.summary.startsWith(
          "Disposable exact-target proof record; excluded from general HTB, external-target, Autonomous, and Guided reuse. ",
        )).toBe(true);
        expect(JSON.parse(note.body)).toMatchObject({
          fixtureOnly: true,
          capabilityScope: "exact_disposable_fixture_only",
          generalExternalTargetSupport: false,
        });
        expect(JSON.parse(note.retention_policy_json)).toMatchObject({
          fixtureOnly: true,
          capabilityScope: "exact_disposable_fixture_only",
          generalExternalTargetSupport: false,
          allowAutonomous: false,
          allowGuided: false,
        });
        expect(JSON.parse(note.provenance_json)).toMatchObject({
          explanation: expect.stringContaining(
            "disposable complete-Autonomous proof fixture",
          ),
          sources: expect.arrayContaining([
            expect.objectContaining({
              sourceType: "fixture_seed",
              sourceId: "complete-autonomous-fixture-v1",
            }),
          ]),
        });
        expect(note.author_id).toBe("operator:system-fixture");
      }

      const seeded = value.database.prepare(`
        SELECT mission.name AS mission_name, mission.objective,
          cve.title AS cve_title, cve.description AS cve_description
        FROM missions mission
        JOIN cve_applicability_records cve
          ON cve.mission_id = mission.id
        WHERE mission.id = ?
      `).get(
        COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.missionId,
      ) as {
        mission_name: string;
        objective: string;
        cve_title: string;
        cve_description: string;
      };
      expect(seeded.mission_name.startsWith(
        "[DISPOSABLE FIXTURE ONLY]",
      )).toBe(true);
      expect(seeded.objective).toContain(
        "does not establish general HTB or external-target capability",
      );
      expect(seeded.cve_title.startsWith(
        "[DISPOSABLE FIXTURE ONLY]",
      )).toBe(true);
      expect(seeded.cve_description).toContain(
        "must not be generalized to an external target",
      );
    } finally {
      value.database.close();
    }
  });

  it("refuses any database below the exact schema-63 boundary", () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-schema-refusal-"));
    roots.push(root);
    const database = createDatabaseConnection({
      filename: join(root, "old.sqlite"),
    });
    try {
      migrateDatabase(database, []);
      expect(() => prepareCompleteAutonomousCandidateActivationFixture({
        database,
        databasePath: join(root, "old.sqlite"),
        vaultSandboxRoot: join(root, "vaults"),
        activationSourceRoot: join(root, "source"),
        adapterPath: join(root, "source", "adapter"),
        adapterSha256: "a".repeat(64),
        brokerPath: join(root, "source", "broker"),
        brokerSha256: "b".repeat(64),
        registerPath: join(root, "source", "register"),
        registerSha256: "c".repeat(64),
        serviceGid: 1,
      })).toThrow("exact forward-only schema 63");
    } finally {
      database.close();
    }
  });
});

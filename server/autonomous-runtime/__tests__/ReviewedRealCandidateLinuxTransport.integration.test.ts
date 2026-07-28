import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
  type SqliteDatabase,
} from "../../db";
import {
  digestCanonicalJson,
} from "../../mcp";
import {
  MemoryScriptSourceStore,
  ScriptArtifactService,
} from "../../script-artifacts";
import {
  ExploitOutcomeObserverSpecService,
} from "../AutonomousExploitOutcomeObserver";
import {
  CandidateLinuxPostExploitSpecRegistry,
  candidateLinuxPostExploitSpecificationHash,
} from "../CandidateLinuxPostExploitSpecRegistry";
import {
  CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION,
  CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
  CandidateLinuxTransportBindingRegistry,
  loadTrustedCandidateLinuxTransportBindingManifest,
  type CandidateLinuxTransportRequest,
} from "../CandidateLinuxTransportBindingRegistry";
import {
  startCandidateLinuxTransportBroker,
} from "../CandidateLinuxTransportBroker";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
  REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
  ReviewedRealCandidateLinuxTransportHandler,
  loadTrustedReviewedRealCandidateLinuxProfile,
  parseReviewedRealCandidateLinuxProfile,
  registerReviewedRealCandidateLinuxPostExploitSpec,
  reviewedRealCandidateLinuxOperations,
  startReviewedRealCandidateLinuxAdapter,
} from "../ReviewedRealCandidateLinuxTransport";

const NOW = new Date("2026-07-25T12:00:00.000Z");
const MISSION_ID = "mission-reviewed-real-transport";
const RUN_ID = "run-reviewed-real-transport";
const CONTRACT_ID = "contract-reviewed-real-transport";
const OBSERVER_ID = "observer-reviewed-real-transport";
const SPEC_ID = "post-exploit-reviewed-real-transport";
const DERIVED_SPEC_ID =
  "post-exploit-reviewed-real-transport-current-run";
const BINDING_ID = "binding.reviewed-real-candidate.v1";
const PRINCIPAL = "operator";
const USER_FLAG_PATH = "/home/operator/user.txt";
const roots: string[] = [];
const databases: SqliteDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function hashFile(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function seedDatabase(): Readonly<{
  database: SqliteDatabase;
  scriptArtifactId: string;
  scriptContentHash: string;
}> {
  const database = createDatabaseConnection({ filename: ":memory:" });
  databases.push(database);
  migrateDatabase(database);
  const now = NOW.toISOString();
  database.prepare(`
    INSERT INTO agents (
      id, role, display_name, status, version, created_at, updated_at
    ) VALUES (
      'SessionRunner', 'post-exploit', 'SessionRunner', 'available', '1', ?, ?
    )
  `).run(now, now);
  database.prepare(`
    INSERT INTO missions (
      id, name, objective, journey, status, authorization_status,
      scope_json, success_criteria_json, memory_policy_json, created_by,
      created_at, updated_at, control_plane
    ) VALUES (?, 'Reviewed real transport source boundary',
      'Verify the installed typed transport composition without target contact.',
      'autonomous', 'active', 'verified', ?, '[]', '{}', 'operator:test',
      ?, ?, 'ti_scale')
  `).run(
    MISSION_ID,
    JSON.stringify({
      allowedTargets: ["10.129.10.20"],
      prohibitedTargets: [],
      environmentClassification: "htb",
    }),
    now,
    now,
  );
  database.prepare(`
    INSERT INTO mission_contracts (
      id, mission_id, version, state, contract_hash, authorization_json,
      action_policy_json, budgets_json, safe_stop_json, deliverables_json,
      memory_scopes_json, confirmed_by, confirmed_at, created_at
    ) VALUES (?, ?, 1, 'confirmed', ?, '{}', ?, '{}', '{}', '[]', '[]',
      'operator:test', ?, ?)
  `).run(
    CONTRACT_ID,
    MISSION_ID,
    "c".repeat(64),
    JSON.stringify({
      allowedActionClasses: [
        "exploit_validation",
        "command_session_execution",
        "data_access_impact_validation",
        "privilege_escalation",
        "cleanup_restoration",
      ],
      prohibitedActionClasses: [],
    }),
    now,
    now,
  );
  database.prepare(`
    INSERT INTO runs (
      id, mission_id, journey, status, contract_id, progress, budget_json,
      budget_usage_json, started_at, created_at, updated_at, version,
      control_plane, contract_version_bound, contract_hash_bound
    ) VALUES (?, ?, 'autonomous', 'running', ?, 0, '{}', '{}', ?, ?, ?, 1,
      'ti_scale', 1, ?)
  `).run(
    RUN_ID,
    MISSION_ID,
    CONTRACT_ID,
    now,
    now,
    now,
    "c".repeat(64),
  );
  const source = [
    "#!/usr/bin/env python3",
    "# Reviewed source identity only; this test performs no target execution.",
    "print('candidate')",
    "",
  ].join("\n");
  const testArtifactId = "artifact-reviewed-real-source-test";
  database.prepare(`
    INSERT INTO artifacts (
      id, mission_id, run_id, journey, artifact_type, storage_uri, content_hash,
      byte_size, media_type, sensitivity, metadata_json, created_at
    ) VALUES (?, ?, ?, 'autonomous', 'script_test_result',
      'memory://reviewed-real-source-test', ?, 128, 'application/json',
      'internal', ?, ?)
  `).run(
    testArtifactId,
    MISSION_ID,
    RUN_ID,
    createHash("sha256")
      .update("reviewed-real-source-test", "utf8")
      .digest("hex"),
    JSON.stringify({
      status: "passed",
      targetContact: false,
      publicProvider: false,
    }),
    now,
  );
  const script = new ScriptArtifactService(
    database,
    new MemoryScriptSourceStore(),
    () => NOW,
  ).create({
    missionId: MISSION_ID,
    runId: RUN_ID,
    name: "reviewed-real-candidate.py",
    language: "python",
    source,
    laymanExplanation:
      "Represents the already reviewed candidate whose post-exploit transport is installed separately.",
    technicalPurpose:
      "Bind one immutable ScriptArtifact identity to the closed real-candidate transport profile.",
    inputs: [],
    expectedOutputs: [{
      label: "Reviewed candidate marker",
      description:
        "One deterministic marker used only to bind the immutable source identity.",
      successRecognition: "The exact reviewed marker is emitted.",
      failureRecognition: "The process does not emit the exact marker.",
    }],
    prerequisites: ["Independent current evidence and outcome observer"],
    dependencies: [],
    touches: { files: [], network: [], services: [] },
    sideEffects: [
      "A real execution may establish only the separately reviewed candidate session represented by its profile.",
    ],
    riskClass: "high",
    reversibility: "The source is immutable and is not executed by this test.",
    cleanupNotes: "Cleanup is a separate represented typed operation.",
    secretsHandling:
      "No credential, token, cookie, or flag content is stored in the profile.",
    evidenceExpectations: [
      "Only independent verified target evidence may satisfy the engagement.",
    ],
    validation: {
      state: "approved",
      summary: "Operator-reviewed immutable source identity.",
      tests: [{
        name: "source review",
        status: "passed",
        summary: "The source identity was reviewed without target contact.",
      }],
      testArtifactId,
    },
    provenance: {
      origin: "operator_authored",
      explanation: "Explicit operator-reviewed candidate source.",
      sourceRefs: ["review:real-candidate-source"],
    },
    sensitivity: "internal",
  }, { id: "operator:test", type: "operator" });
  new ExploitOutcomeObserverSpecService(database, () => NOW).register({
    id: OBSERVER_ID,
    scriptArtifactId: script.id,
    scriptContentHash: script.contentHash,
    cveId: "CVE-2024-9999",
    request: {
      scheme: "http",
      port: 8080,
      method: "GET",
      path: "/ti-scale/impact",
      timeoutMs: 2_000,
      maxResponseBytes: 32 * 1_024,
      tlsVerification: "strict",
    },
    assertion: {
      statusCodes: [200],
      bodyContains: ["impact-confirmed"],
      headerEquals: {},
      match: "all",
    },
    createdBy: "operator:test",
  });
  return Object.freeze({
    database,
    scriptArtifactId: script.id,
    scriptContentHash: script.contentHash,
  });
}

function buildFixture(): Readonly<{
  root: string;
  database: SqliteDatabase;
  loadedProfile: ReturnType<
    typeof loadTrustedReviewedRealCandidateLinuxProfile
  >;
  loadedManifest: ReturnType<
    typeof loadTrustedCandidateLinuxTransportBindingManifest
  >;
  adapterExecutableSha256: string;
}> {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-reviewed-real-transport-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const { database, scriptArtifactId, scriptContentHash } = seedDatabase();
  const adapterExecutablePath = join(root, "candidate-adapter");
  const brokerExecutablePath = join(root, "candidate-broker");
  writeFileSync(
    adapterExecutablePath,
    "#!/usr/bin/env node\n// hash-pinned candidate adapter boundary\n",
    { mode: 0o500 },
  );
  writeFileSync(
    brokerExecutablePath,
    "#!/usr/bin/env node\n// hash-pinned candidate broker boundary\n",
    { mode: 0o500 },
  );
  const adapterExecutableSha256 = hashFile(adapterExecutablePath);
  const specHash = candidateLinuxPostExploitSpecificationHash({
    exploitOutcomeObserverSpecId: OBSERVER_ID,
    scriptArtifactId,
    scriptContentHash,
    transportType: "candidate_runtime_session_v1",
    transportBindingId: BINDING_ID,
    transportOrigin: null,
    expectedPrincipal: PRINCIPAL,
    expectedUid: 1_000,
    declaredUserFlagPath: USER_FLAG_PATH,
  });
  const profile = {
    schemaVersion: REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
    profileId: "profile.reviewed-real-candidate.v1",
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    bindingId: BINDING_ID,
    postExploitSpec: {
      id: SPEC_ID,
      expectedSha256: specHash,
      exploitOutcomeObserverSpecId: OBSERVER_ID,
      scriptArtifactId,
      expectedPrincipal: PRINCIPAL,
      expectedUid: 1_000,
      declaredUserFlagPath: USER_FLAG_PATH,
      declaredRootFlagPath: "/root/root.txt",
    },
    adapter: {
      executablePath: adapterExecutablePath,
      executableSha256: adapterExecutableSha256,
      socketPath: join(root, "candidate-adapter.sock"),
      socketGid: process.getgid?.() ?? 0,
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
    },
    boundary: {
      typedOperationsOnly: true,
      genericCommand: false,
      shell: false,
      argv: false,
      payload: false,
      credentialsFromRuntime: false,
      exactTargetFromCanonicalAction: true,
      succeededAttackAttemptRequired: true,
      derivedCurrentRunSpecOnly: true,
      publicProvider: false,
      hashOnlyFlagProofs: true,
    },
    operations: reviewedRealCandidateLinuxOperations(),
  };
  const profilePath = join(root, "profile.json");
  const profileBytes = `${JSON.stringify(profile)}\n`;
  writeFileSync(profilePath, profileBytes, { mode: 0o600 });
  const profileSha256 = createHash("sha256")
    .update(profileBytes)
    .digest("hex");
  const manifest = {
    schemaVersion: CANDIDATE_LINUX_TRANSPORT_BINDING_MANIFEST_SCHEMA_VERSION,
    bundleVersion: "reviewed-real-source-test-v1",
    broker: {
      executablePath: brokerExecutablePath,
      executableSha256: hashFile(brokerExecutablePath),
      socketPath: join(root, "candidate-broker.sock"),
      socketGid: process.getgid?.() ?? 0,
      protocolVersion: CANDIDATE_LINUX_TRANSPORT_PROTOCOL_VERSION,
    },
    boundary: {
      typedOperationsOnly: true,
      genericCommand: false,
      shell: false,
      argv: false,
      payload: false,
      credentials: false,
      exactTargetFromCanonicalAction: true,
      succeededAttackAttemptRequired: true,
      publicProvider: false,
    },
    bindings: [{
      bindingId: BINDING_ID,
      postExploitSpecId: SPEC_ID,
      postExploitSpecSha256: specHash,
      candidateClass: "reviewed_real_candidate_v1",
      handlerProfilePath: profilePath,
      handlerProfileSha256: profileSha256,
      realTargetSupport: true,
      operations: reviewedRealCandidateLinuxOperations(),
    }],
  };
  const manifestPath = join(root, "manifest.json");
  const manifestBytes = `${JSON.stringify(manifest)}\n`;
  writeFileSync(manifestPath, manifestBytes, { mode: 0o600 });
  const manifestSha256 = createHash("sha256")
    .update(manifestBytes)
    .digest("hex");
  const allowedOwnerUids = [process.getuid?.() ?? 0];
  return Object.freeze({
    root,
    database,
    adapterExecutableSha256,
    loadedProfile: loadTrustedReviewedRealCandidateLinuxProfile({
      path: profilePath,
      trustRoot: root,
      expectedSha256: profileSha256,
      allowedOwnerUids,
    }),
    loadedManifest: loadTrustedCandidateLinuxTransportBindingManifest({
      path: manifestPath,
      trustRoot: root,
      expectedSha256: manifestSha256,
      allowedOwnerUids,
    }),
  });
}

describe("reviewed real-candidate Linux transport source boundary", () => {
  test("registers the exact spec and becomes ready only through two live pinned attestations", async () => {
    const fixture = buildFixture();
    const binding = fixture.loadedManifest.value.bindings[0]!;
    const created = registerReviewedRealCandidateLinuxPostExploitSpec({
      database: fixture.database,
      loadedProfile: fixture.loadedProfile,
      binding,
      createdBy: "operator:test",
      now: () => NOW,
    });
    expect(created).toMatchObject({
      id: SPEC_ID,
      specHash: binding.postExploitSpecSha256,
      transportType: "candidate_runtime_session_v1",
      transportBindingId: BINDING_ID,
      transportOrigin: null,
    });

    const operations: string[] = [];
    const adapter = await startReviewedRealCandidateLinuxAdapter({
      loadedProfile: fixture.loadedProfile,
      now: () => NOW,
      implementation: {
        bindingId: BINDING_ID,
        postExploitSpecId: SPEC_ID,
        profileSha256: fixture.loadedProfile.receipt.sourceSha256,
        adapterExecutableSha256: fixture.adapterExecutableSha256,
        candidateClass: "reviewed_real_candidate_v1",
        realTargetSupport: true,
        async handle(request) {
          operations.push(request.operation);
          expect([
            "command",
            "argv",
            "shell",
            "payload",
            "credentials",
            "secret",
          ].some((field) => Object.hasOwn(request, field))).toBeFalse();
          return Object.freeze({
            accepted: true,
            operation: request.operation,
            sessionArtifactId: request.sessionArtifactId,
          });
        },
      },
    });
    const handler = new ReviewedRealCandidateLinuxTransportHandler({
      loadedProfile: fixture.loadedProfile,
      binding,
      now: () => NOW,
    });
    const registry = new CandidateLinuxTransportBindingRegistry({
      database: fixture.database,
      loadedManifest: fixture.loadedManifest,
      now: () => NOW,
    });
    expect(registry.readiness()).toMatchObject({
      status: "blocked",
      missionExecutionReady: false,
    });
    const broker = await startCandidateLinuxTransportBroker({
      manifest: fixture.loadedManifest.value,
      manifestSha256: fixture.loadedManifest.receipt.sourceSha256,
      authorizer: registry,
      handlers: [handler],
      now: () => NOW,
    });
    try {
      await registry.attest();
      expect(registry.readiness()).toMatchObject({
        status: "ready",
        readinessScope: "reviewed_real_candidate",
        missionExecutionReady: true,
        bindingCapabilities: [{
          bindingId: BINDING_ID,
          candidateClass: "reviewed_real_candidate_v1",
          realTargetSupport: true,
        }],
      });

      const common = {
        transportBindingId: BINDING_ID,
        postExploitSpecId: DERIVED_SPEC_ID,
        sessionArtifactId: "session-reviewed-real-source-boundary",
        exactTarget: "10.129.10.20",
      };
      expect(handler.acceptsPostExploitSpecId(SPEC_ID)).toBeFalse();
      expect(handler.acceptsPostExploitSpecId(DERIVED_SPEC_ID)).toBeTrue();
      const requests: CandidateLinuxTransportRequest[] = [
        { ...common, operation: "open" },
        { ...common, operation: "observe_identity" },
        {
          ...common,
          operation: "prove_user_flag_hash",
          declaredPath: USER_FLAG_PATH,
        },
        { ...common, operation: "close" },
        {
          ...common,
          operation: "privilege_escalation",
          actionId: "action-reviewed-real-privilege",
          candidateBindingHash: "a".repeat(64),
          leaseFencingToken: 1,
        },
        {
          ...common,
          operation: "observe_root_identity",
          actionId: "action-reviewed-real-privilege",
          candidateBindingHash: "a".repeat(64),
          leaseFencingToken: 1,
        },
        {
          ...common,
          operation: "prove_root_flag_hash",
          actionId: "action-reviewed-real-root-proof",
          candidateBindingHash: "a".repeat(64),
          leaseFencingToken: 1,
          declaredPath: "/root/root.txt",
        },
        {
          ...common,
          operation: "cleanup",
          candidateBindingHash: "a".repeat(64),
          leaseFencingToken: 1,
          reason: "Close the exact represented candidate session.",
        },
      ];
      for (const request of requests) {
        await handler.handle(request, new AbortController().signal);
      }
      expect(operations).toEqual([
        ...reviewedRealCandidateLinuxOperations(),
      ]);
    } finally {
      await broker.close();
      await adapter.close();
    }
  });

  test("rejects profile authority widening and a real-labelled handler without live attestation", async () => {
    const fixture = buildFixture();
    expect(() =>
      parseReviewedRealCandidateLinuxProfile({
        ...fixture.loadedProfile.value,
        boundary: {
          ...fixture.loadedProfile.value.boundary,
          genericCommand: true,
        },
      })
    ).toThrow("boundary.genericCommand must equal false");

    const binding = fixture.loadedManifest.value.bindings[0]!;
    registerReviewedRealCandidateLinuxPostExploitSpec({
      database: fixture.database,
      loadedProfile: fixture.loadedProfile,
      binding,
      createdBy: "operator:test",
      now: () => NOW,
    });
    const registry = new CandidateLinuxTransportBindingRegistry({
      database: fixture.database,
      loadedManifest: fixture.loadedManifest,
      now: () => NOW,
    });
    await expect(startCandidateLinuxTransportBroker({
      manifest: fixture.loadedManifest.value,
      manifestSha256: fixture.loadedManifest.receipt.sourceSha256,
      authorizer: registry,
      handlers: [{
        bindingId: BINDING_ID,
        postExploitSpecId: SPEC_ID,
        candidateClass: "reviewed_real_candidate_v1",
        handlerProfileSha256:
          fixture.loadedProfile.receipt.sourceSha256,
        realTargetSupport: true,
        async handle() {
          return {};
        },
      }],
      now: () => NOW,
    })).rejects.toThrow(
      "Every reviewed real-candidate binding requires a live adapter attestation",
    );
    expect(registry.missionExecutionReady()).toBeFalse();
  });

  test("accepts only the byte-identical current-run spec clone, never the source review template", () => {
    const fixture = buildFixture();
    const binding = fixture.loadedManifest.value.bindings[0]!;
    registerReviewedRealCandidateLinuxPostExploitSpec({
      database: fixture.database,
      loadedProfile: fixture.loadedProfile,
      binding,
      createdBy: "operator:test",
      now: () => NOW,
    });
    const sourceScriptId =
      fixture.loadedProfile.value.postExploitSpec.scriptArtifactId;
    const derivedScriptId = "script-reviewed-real-current-run";
    fixture.database.prepare(`
      INSERT INTO script_artifacts (
        id, mission_id, run_id, plan_id, step_id, attack_attempt_id,
        target_node_id, artifact_id, name, language, version, content_hash,
        layman_explanation, technical_purpose, inputs_json,
        expected_outputs_json, prerequisites_json, touches_json,
        side_effects_json, cleanup_notes, secrets_handling,
        evidence_expectations_json, validation_state, test_artifact_id,
        created_by, created_at
      )
      SELECT ?, mission_id, run_id, plan_id, step_id, attack_attempt_id,
        target_node_id, artifact_id, 'reviewed-real-current-run.py',
        language, version, content_hash, layman_explanation,
        technical_purpose, inputs_json, expected_outputs_json,
        prerequisites_json, touches_json, side_effects_json, cleanup_notes,
        secrets_handling, evidence_expectations_json, validation_state,
        test_artifact_id, 'system:current-run-materialization', created_at
      FROM script_artifacts
      WHERE id = ?
    `).run(derivedScriptId, sourceScriptId);
    const observer = new ExploitOutcomeObserverSpecService(
      fixture.database,
      () => NOW,
    ).clone(sourceScriptId, derivedScriptId);
    expect(observer).toBeDefined();
    const specs = new CandidateLinuxPostExploitSpecRegistry(
      fixture.database,
      () => NOW,
    );
    const derived = specs.clone(
      sourceScriptId,
      derivedScriptId,
      observer!.id,
      { missionId: MISSION_ID, runId: RUN_ID },
    );
    expect(derived).toBeDefined();

    const registry = new CandidateLinuxTransportBindingRegistry({
      database: fixture.database,
      loadedManifest: fixture.loadedManifest,
      now: () => NOW,
    });
    expect(registry.acceptsPostExploitSpec(BINDING_ID, SPEC_ID)).toBeFalse();
    expect(
      registry.acceptsPostExploitSpec(BINDING_ID, derived!.id),
    ).toBeTrue();

    expect(() => fixture.database.prepare(`
      UPDATE candidate_linux_post_exploit_specs
      SET created_by = 'operator:unrelated'
      WHERE id = ?
    `).run(derived!.id)).toThrow(
      "candidate Linux post-exploit authority is immutable",
    );
    expect(
      registry.acceptsPostExploitSpec(BINDING_ID, derived!.id),
    ).toBeTrue();
  });

  test("propagates cancellation to the candidate-specific adapter without a second request", async () => {
    const fixture = buildFixture();
    const binding = fixture.loadedManifest.value.bindings[0]!;
    registerReviewedRealCandidateLinuxPostExploitSpec({
      database: fixture.database,
      loadedProfile: fixture.loadedProfile,
      binding,
      createdBy: "operator:test",
      now: () => NOW,
    });
    let calls = 0;
    let cancelled = false;
    const adapter = await startReviewedRealCandidateLinuxAdapter({
      loadedProfile: fixture.loadedProfile,
      now: () => NOW,
      implementation: {
        bindingId: BINDING_ID,
        postExploitSpecId: SPEC_ID,
        profileSha256: fixture.loadedProfile.receipt.sourceSha256,
        adapterExecutableSha256: fixture.adapterExecutableSha256,
        candidateClass: "reviewed_real_candidate_v1",
        realTargetSupport: true,
        async handle(_request, signal) {
          calls += 1;
          await new Promise<void>((resolve, reject) => {
            const timer = setTimeout(resolve, 5_000);
            signal.addEventListener("abort", () => {
              clearTimeout(timer);
              cancelled = true;
              reject(new Error("cancelled"));
            }, { once: true });
          });
          return {};
        },
      },
    });
    const handler = new ReviewedRealCandidateLinuxTransportHandler({
      loadedProfile: fixture.loadedProfile,
      binding,
      now: () => NOW,
    });
    try {
      await handler.attest();
      const controller = new AbortController();
      const pending = handler.handle({
        operation: "open",
        transportBindingId: BINDING_ID,
        postExploitSpecId: DERIVED_SPEC_ID,
        sessionArtifactId: "session-reviewed-real-cancel",
        exactTarget: "10.129.10.20",
      }, controller.signal);
      await Bun.sleep(20);
      controller.abort();
      await expect(pending).rejects.toThrow("cancelled");
      await Bun.sleep(20);
      expect(calls).toBe(1);
      expect(cancelled).toBeTrue();
    } finally {
      await adapter.close();
    }
  });

  test("the profile hash is bound into the local adapter attestation receipt", async () => {
    const fixture = buildFixture();
    const adapter = await startReviewedRealCandidateLinuxAdapter({
      loadedProfile: fixture.loadedProfile,
      now: () => NOW,
      implementation: {
        bindingId: BINDING_ID,
        postExploitSpecId: SPEC_ID,
        profileSha256: fixture.loadedProfile.receipt.sourceSha256,
        adapterExecutableSha256: fixture.adapterExecutableSha256,
        candidateClass: "reviewed_real_candidate_v1",
        realTargetSupport: true,
        async handle() {
          return {};
        },
      },
    });
    try {
      const handler = new ReviewedRealCandidateLinuxTransportHandler({
        loadedProfile: fixture.loadedProfile,
        binding: fixture.loadedManifest.value.bindings[0]!,
        now: () => NOW,
      });
      const attestation = await handler.attest();
      const { receiptSha256, ...unsigned } = attestation;
      expect(receiptSha256).toBe(
        digestCanonicalJson(
          unsigned,
          { maxBytes: 64 * 1_024, maxDepth: 16 },
        ).sha256,
      );
      expect(attestation).toMatchObject({
        profileSha256: fixture.loadedProfile.receipt.sourceSha256,
        adapterExecutableSha256: fixture.adapterExecutableSha256,
        candidateClass: "reviewed_real_candidate_v1",
        realTargetSupport: true,
      });
    } finally {
      await adapter.close();
    }
  });
});

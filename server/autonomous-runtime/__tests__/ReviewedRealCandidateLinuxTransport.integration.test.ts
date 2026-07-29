import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
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
  AttackAttemptService,
} from "../../run-intelligence";
import { canonicalObject } from "../../run-intelligence/serialization";
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
  exactCandidateLinuxTargetScope,
} from "../CandidateLinuxTargetScope";
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
import {
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
} from "../AutonomousExploitValidationEligibility";
import {
  AUTONOMOUS_REUSABLE_EXPLOIT_MATERIALIZATION_SCHEMA_VERSION,
  type AutonomousReusableExploitMaterializationResult,
} from "../AutonomousReusableExploitCandidateMaterializer";
import {
  RunScopedReviewedCandidateLinuxProcedureAdmission,
  RunScopedReviewedCandidateLinuxProcedureActivationBridge,
  RunScopedReviewedCandidateLinuxProcedureActivationError,
  RunScopedReviewedCandidateLinuxProcedurePublisher,
  RunScopedReviewedCandidateLinuxSpecRegistrar,
} from "../RunScopedReviewedCandidateLinuxProcedureActivation";

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
const PLAN_ID = "plan-reviewed-real-transport-current";
const STEP_ID = "step-reviewed-real-transport-current";
const TARGET_NODE_ID = "asset-reviewed-real-transport-current";
const EXACT_TARGET = "10.129.10.20";
const TARGET_SCOPE = exactCandidateLinuxTargetScope(EXACT_TARGET);
const CURRENT_OBSERVER_ID = "observer-reviewed-real-transport-current";
const CURRENT_TEST_ARTIFACT_ID =
  "artifact-reviewed-real-transport-current-test";
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
  sourceStore: MemoryScriptSourceStore;
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
  const sourceStore = new MemoryScriptSourceStore();
  const script = new ScriptArtifactService(
    database,
    sourceStore,
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
    sourceStore,
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
  sourceStore: MemoryScriptSourceStore;
}> {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-reviewed-real-transport-"));
  roots.push(root);
  chmodSync(root, 0o700);
  const {
    database,
    sourceStore,
    scriptArtifactId,
    scriptContentHash,
  } = seedDatabase();
  const adapterExecutablePath = join(root, "candidate-adapter");
  const brokerExecutablePath = join(root, "candidate-broker");
  const procedureExecutablePath = join(root, "candidate-procedure");
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
  writeFileSync(
    procedureExecutablePath,
    runScopedProcedureSource(),
    { mode: 0o500 },
  );
  const adapterExecutableSha256 = hashFile(adapterExecutablePath);
  const procedureExecutableSha256 = hashFile(procedureExecutablePath);
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
    targetScope: TARGET_SCOPE,
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
    procedure: {
      executablePath: procedureExecutablePath,
      executableSha256: procedureExecutableSha256,
      protocolVersion:
        "ti-scale.reviewed-real-candidate-linux-procedure.v1",
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
      targetScope: TARGET_SCOPE,
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
    sourceStore,
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

function runScopedProcedureSource(): string {
  return `#!/usr/bin/env bun
import { createHash } from "node:crypto";

const OPERATIONS = ${JSON.stringify(reviewedRealCandidateLinuxOperations())};
const BOUNDARY = ${JSON.stringify({
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
})};
const NOW = ${JSON.stringify(NOW.toISOString())};
const encode = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(encode).join(",") + "]";
  return "{" + Object.keys(value).sort().map((key) =>
    JSON.stringify(key) + ":" + encode(value[key])).join(",") + "}";
};
const digest = (value) =>
  createHash("sha256").update(encode(value), "utf8").digest("hex");
const output = (result) =>
  process.stdout.write(JSON.stringify({ ok: true, result }) + "\\n");
const envelope = JSON.parse((await Bun.stdin.text()).trim());
if (envelope.operation === "attest") {
  const unsigned = {
    schemaVersion:
      "ti-scale.reviewed-real-candidate-linux-procedure-attestation.v1",
    protocolVersion:
      "ti-scale.reviewed-real-candidate-linux-procedure.v1",
    profileSha256: envelope.profileSha256,
    procedureExecutableSha256: envelope.procedureExecutableSha256,
    bindingId: envelope.bindingId,
    postExploitSpecId: envelope.postExploitSpecId,
    scriptArtifactId: envelope.scriptArtifactId,
    exploitOutcomeObserverSpecId: envelope.exploitOutcomeObserverSpecId,
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: envelope.targetScope,
    operations: OPERATIONS,
    boundary: BOUNDARY,
    observedAt: NOW,
    expiresAt: new Date(Date.parse(NOW) + 60_000).toISOString(),
  };
  output({ ...unsigned, receiptSha256: digest(unsigned) });
} else if (envelope.operation === "conformance") {
  const cases = [
    { operation: "open", result: { accepted: true } },
    {
      operation: "observe_identity",
      result: {
        principal: ${JSON.stringify(PRINCIPAL)},
        uid: 1000,
        gid: 1000,
        groups: [${JSON.stringify(PRINCIPAL)}],
      },
    },
    {
      operation: "prove_user_flag_hash",
      result: { sha256: "1".repeat(64), byteSize: 32 },
    },
    { operation: "close", result: { closed: true } },
    { operation: "privilege_escalation", result: { accepted: true } },
    {
      operation: "observe_root_identity",
      result: { principal: "root", uid: 0, gid: 0, groups: ["root"] },
    },
    {
      operation: "prove_root_flag_hash",
      result: { sha256: "2".repeat(64), byteSize: 32 },
    },
    { operation: "cleanup", result: { closed: true } },
  ];
  const unsigned = {
    schemaVersion:
      "ti-scale.reviewed-real-candidate-linux-procedure-conformance.v1",
    protocolVersion:
      "ti-scale.reviewed-real-candidate-linux-procedure.v1",
    profileSha256: envelope.profileSha256,
    procedureExecutableSha256: envelope.procedureExecutableSha256,
    bindingId: envelope.bindingId,
    postExploitSpecId: envelope.postExploitSpecId,
    scriptArtifactId: envelope.scriptArtifactId,
    exploitOutcomeObserverSpecId: envelope.exploitOutcomeObserverSpecId,
    targetScope: envelope.targetScope,
    cases,
  };
  output({ ...unsigned, receiptSha256: digest(unsigned) });
} else if (
  envelope.operation === "invoke"
  && envelope.request?.operation === "open"
  && envelope.request?.exactTarget === ${JSON.stringify(EXACT_TARGET)}
  && envelope.request?.transportBindingId === ${JSON.stringify(BINDING_ID)}
) {
  if (Object.keys(envelope.request).some((field) =>
    ["command", "argv", "shell", "payload", "credentials", "secret"]
      .includes(field))) {
    throw new Error("request widened");
  }
  output({ accepted: true });
} else {
  throw new Error("unsupported exact procedure request");
}
`;
}

async function seedRunScopedCandidate(
  fixture: ReturnType<typeof buildFixture>,
) {
  const database = fixture.database;
  const now = NOW.toISOString();
  const procedureRoot = fixture.root;
  const procedurePath =
    fixture.loadedProfile.value.procedure.executablePath;
  const procedureSha256 =
    fixture.loadedProfile.value.procedure.executableSha256;
  const binding = fixture.loadedManifest.value.bindings[0]!;
  registerReviewedRealCandidateLinuxPostExploitSpec({
    database,
    loadedProfile: fixture.loadedProfile,
    binding,
    createdBy: "operator:test",
    now: () => NOW,
  });
  database.prepare(`
    INSERT INTO mission_targets (
      id, mission_id, target, target_type, normalized_target, disposition,
      metadata_json, created_at
    ) VALUES ('target-reviewed-real-current', ?, ?, 'ip', ?, 'allowed', '{}', ?)
  `).run(MISSION_ID, EXACT_TARGET, EXACT_TARGET, now);
  database.prepare(`
    INSERT INTO plans (
      id, run_id, version, status, strategy_summary, plan_hash, created_by,
      created_at, activated_at
    ) VALUES (?, ?, 1, 'active',
      'Current evidence-backed reviewed candidate validation', ?,
      'local-planner', ?, ?)
  `).run(PLAN_ID, RUN_ID, "d".repeat(64), now, now);
  database.prepare(`
    INSERT INTO plan_steps (
      id, plan_id, run_id, ordinal, phase, title, objective, status,
      action_class, risk_class, created_at, updated_at
    ) VALUES (?, ?, ?, 1, 'Exploit validation',
      'Validate current reviewed candidate',
      'Bind the current ScriptArtifact and exact target before dispatch.',
      'running', 'exploit_validation', 'high', ?, ?)
  `).run(STEP_ID, PLAN_ID, RUN_ID, now, now);
  database.prepare(`
    UPDATE runs SET current_plan_id = ?, updated_at = ?, version = version + 1
    WHERE id = ?
  `).run(PLAN_ID, now, RUN_ID);
  database.prepare(`
    INSERT INTO topology_nodes (
      id, mission_id, run_id, node_type, primary_label,
      normalized_identity, scope_status, lifecycle_state, properties_json,
      confidence, verification_state, sensitivity, first_seen_at,
      last_seen_at, created_at, updated_at
    ) VALUES (?, ?, ?, 'asset', ?, ?, 'allowed', 'validated', '{}', 1,
      'verified', 'internal', ?, ?, ?, ?)
  `).run(
    TARGET_NODE_ID,
    MISSION_ID,
    RUN_ID,
    EXACT_TARGET,
    EXACT_TARGET,
    now,
    now,
    now,
    now,
  );
  database.prepare(`
    INSERT INTO artifacts (
      id, mission_id, run_id, step_id, journey, artifact_type, storage_uri,
      content_hash, byte_size, media_type, sensitivity, metadata_json,
      created_at
    ) VALUES (?, ?, ?, ?, 'autonomous', 'script_test_result',
      'memory://reviewed-real-current-test', ?, 192, 'application/json',
      'internal', ?, ?)
  `).run(
    CURRENT_TEST_ARTIFACT_ID,
    MISSION_ID,
    RUN_ID,
    STEP_ID,
    "e".repeat(64),
    JSON.stringify({
      status: "passed",
      sourceScriptArtifactId:
        fixture.loadedProfile.value.postExploitSpec.scriptArtifactId,
      validatedScriptContentHash:
        (fixture.database.prepare(`
          SELECT content_hash FROM script_artifacts WHERE id = ?
        `).get(
          fixture.loadedProfile.value.postExploitSpec.scriptArtifactId,
        ) as Readonly<{ content_hash: string }>).content_hash,
      independentlyValidated: true,
      targetContact: false,
    }),
    now,
  );
  const scripts = new ScriptArtifactService(
    database,
    fixture.sourceStore,
    () => NOW,
  );
  const reviewedExploit = scripts.get(
    fixture.loadedProfile.value.postExploitSpec.scriptArtifactId,
  );
  const currentScript = scripts.create({
    missionId: MISSION_ID,
    runId: RUN_ID,
    planId: PLAN_ID,
    stepId: STEP_ID,
    targetNodeId: TARGET_NODE_ID,
    name: "reviewed-real-current-run.py",
    language: reviewedExploit.language,
    source: reviewedExploit.source,
    laymanExplanation:
      "Preserves the exact reviewed exploit bytes for this run.",
    technicalPurpose:
      "Bind the byte-identical reviewed exploit to current-run evidence while execution remains delegated to a distinct provider.",
    inputs: [],
    expectedOutputs: [{
      label: "Typed candidate response",
      description: "One schema-bound response for the represented operation.",
      successRecognition: "The response matches the reviewed protocol.",
      failureRecognition: "The response is absent or differs from the schema.",
    }],
    prerequisites: ["Current-run exact evidence and represented action"],
    dependencies: [],
    touches: { files: [], network: [], services: [] },
    sideEffects: ["Execution is unavailable until the separate provider is admitted and activated."],
    riskClass: "high",
    reversibility: "The cleanup operation closes the exact candidate session.",
    cleanupNotes: "Use only the typed cleanup operation.",
    secretsHandling: "No credential or flag content is persisted.",
    evidenceExpectations: ["Independent target evidence remains required."],
    validation: {
      state: "approved",
      summary: "The exact current-run exploit bytes passed local validation.",
      tests: [{
        name: "candidate protocol",
        status: "passed",
        summary: "The reviewed exploit bytes and outcome observer match.",
      }],
      testArtifactId: CURRENT_TEST_ARTIFACT_ID,
    },
    provenance: {
      origin: "agent_generated",
      explanation: "Current-run deterministic candidate materialization.",
      sourceRefs: [
        fixture.loadedProfile.value.postExploitSpec.scriptArtifactId,
      ],
      authorAgentId: "SessionRunner",
    },
    sensitivity: "internal",
  }, { id: "SessionRunner", type: "agent" });
  const observers = new ExploitOutcomeObserverSpecService(
    database,
    () => NOW,
  );
  const sourceObserver = observers.getForScript(
    fixture.loadedProfile.value.postExploitSpec.scriptArtifactId,
  );
  expect(sourceObserver).toBeDefined();
  const observer = observers.register({
    id: CURRENT_OBSERVER_ID,
    scriptArtifactId: currentScript.id,
    scriptContentHash: currentScript.contentHash,
    cveId: sourceObserver!.cveId,
    request: sourceObserver!.request,
    assertion: sourceObserver!.assertion,
    createdBy: "system:current-run-candidate-observer",
  });
  const materialization = Object.freeze({
    schemaVersion:
      AUTONOMOUS_REUSABLE_EXPLOIT_MATERIALIZATION_SCHEMA_VERSION,
    candidate: Object.freeze({
      scriptArtifactId:
        fixture.loadedProfile.value.postExploitSpec.scriptArtifactId,
      scriptContentHash: reviewedExploit.contentHash,
      cveApplicabilityId: "cve-app-reviewed-real-current",
      versionEvidenceId: "evidence-reviewed-real-current-version",
      versionEvidenceHash: "7".repeat(64),
      targetNodeId: TARGET_NODE_ID,
      vaultConnectionId: "vault-reviewed-real-current",
      interpreterBindingId: "python3-reviewed-v1",
      memory: Object.freeze({
        scriptNodeId: "memory-reviewed-real-script",
        procedureNodeId: "memory-reviewed-real-procedure",
        cveNodeId: "memory-reviewed-real-cve",
        productNodeId: "memory-reviewed-real-product",
        versionNodeId: "memory-reviewed-real-version",
      }),
    }),
    sourceScriptArtifactId:
      fixture.loadedProfile.value.postExploitSpec.scriptArtifactId,
    materializedScriptArtifactId: currentScript.id,
    materializedScriptContentHash: currentScript.contentHash,
    validationReceiptId: "receipt-reviewed-real-current-validation",
    validationReceiptSha256: "8".repeat(64),
    validationArtifactId: CURRENT_TEST_ARTIFACT_ID,
    outcomeObserverSpecId: observer.id,
    outcomeObserverSpecHash: observer.specHash,
    contextPackId: "context-reviewed-real-current",
    vaultConnectionId: "vault-reviewed-real-current",
    memoryNodeIds: Object.freeze(["memory-reviewed-real-script"]),
    codeGenerated: false,
    sourceCreation: "historical_byte_identical_reuse",
    arbitraryCodeGeneration: false,
    publicProvider: false,
    targetContactDuringMaterialization: false,
    createdAt: now,
  }) satisfies AutonomousReusableExploitMaterializationResult;
  const admission = await new RunScopedReviewedCandidateLinuxProcedureAdmission({
    database,
    loadedProfile: fixture.loadedProfile,
    now: () => NOW,
  }).admit({
    missionId: MISSION_ID,
    runId: RUN_ID,
    materialization,
    signal: new AbortController().signal,
  });
  expect(admission).not.toBeNull();
  expect(admission!.postExploitSpecId).not.toBe(SPEC_ID);
  const source = database.prepare(`
    SELECT content_hash FROM script_artifacts WHERE id = ?
  `).get(currentScript.id) as { readonly content_hash: string };
  const representedArguments = canonicalObject({
    schemaVersion: "ti-scale.autonomous-exploit-validation-arguments.v1",
    candidates: [{
      scriptArtifactId: currentScript.id,
      scriptContentHash: source.content_hash,
      targetNodeId: TARGET_NODE_ID,
    }],
  });
  const attempts = new AttackAttemptService(database, () => NOW);
  const created = attempts.create({
    missionId: MISSION_ID,
    runId: RUN_ID,
    planId: PLAN_ID,
    stepId: STEP_ID,
    targetAssetId: TARGET_NODE_ID,
    objective: "Validate the exact current evidence-backed candidate.",
    techniqueName: "Evidence-matched exact-version exploit validation",
    actionClass: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
    prerequisites: [currentScript.id],
    normalizedParameters: representedArguments,
    representedActionBinding: {
      actionType: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
      actionClass: AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
      normalizedArguments: representedArguments,
      scopedTarget: EXACT_TARGET,
    },
  });
  const attempt = attempts.transition({
    attemptId: created.id,
    expectedVersion: created.version,
    status: "ready",
    reason:
      "Current evidence, current ScriptArtifact, exact target, and represented action are bound.",
  });
  return Object.freeze({
    procedureRoot,
    procedurePath,
    procedureSha256,
    procedureAdmissionId: admission!.admissionId,
    scriptArtifactId: currentScript.id,
    observerId: observer.id,
    postExploitSpecId: admission!.postExploitSpecId,
    representedActionBindingHash:
      attempt.representedActionBinding!.bindingHash,
    attackAttemptId: attempt.id,
  });
}

describe("reviewed real-candidate Linux transport source boundary", () => {
  test("accepts the exact valid post-exploit profile field set", () => {
    const fixture = buildFixture();
    expect(
      parseReviewedRealCandidateLinuxProfile(fixture.loadedProfile.value),
    ).toEqual(fixture.loadedProfile.value);
    expect(Object.keys(
      fixture.loadedProfile.value.postExploitSpec,
    ).sort()).toEqual([
      "declaredRootFlagPath",
      "declaredUserFlagPath",
      "expectedPrincipal",
      "expectedSha256",
      "expectedUid",
      "exploitOutcomeObserverSpecId",
      "id",
      "scriptArtifactId",
    ]);
  });

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
        targetScope: fixture.loadedProfile.value.targetScope,
        async attest() {},
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
        activationModel: "run_scoped_after_discovery",
        candidateProcedurePresentAtLaunch: true,
        procedureProviderPresentAtLaunch: true,
        runScopedProcedureActivationPresentAtLaunch: false,
        missionExecutionReady: false,
        bindingCapabilities: [{
          bindingId: BINDING_ID,
          candidateClass: "reviewed_real_candidate_v1",
          realTargetSupport: true,
          targetScope: TARGET_SCOPE,
        }],
      });
      expect(registry.conditionalPlanningReady()).toBeTrue();
      expect(registry.missionExecutionReadyForTargets([EXACT_TARGET]))
        .toBeTrue();
      expect(registry.missionExecutionReadyForTargets(["127.0.0.3"]))
        .toBeFalse();
      expect(registry.missionExecutionReadyForTargets(["10.129.39.191"]))
        .toBeFalse();
      await expect(registry.invoke({
        operation: "open",
        transportBindingId: BINDING_ID,
        postExploitSpecId: DERIVED_SPEC_ID,
        sessionArtifactId: "session-unrelated-target",
        exactTarget: "127.0.0.3",
      }, new AbortController().signal)).rejects.toThrow(
        "exact target scope",
      );

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

  test("treats an attested provider bridge as conditional launch readiness without claiming a run activation exists", async () => {
    const fixture = buildFixture();
    const binding = fixture.loadedManifest.value.bindings[0]!;
    registerReviewedRealCandidateLinuxPostExploitSpec({
      database: fixture.database,
      loadedProfile: fixture.loadedProfile,
      binding,
      createdBy: "operator:test",
      now: () => NOW,
    });
    const procedureRoot = join(fixture.root, "procedures");
    mkdirSync(procedureRoot, { mode: 0o700 });
    const bridge =
      new RunScopedReviewedCandidateLinuxProcedureActivationBridge({
        database: fixture.database,
        loadedProfile: fixture.loadedProfile,
        procedureTrustRoot: procedureRoot,
        now: () => NOW,
      });
    expect(bridge.inspectComposition()).toMatchObject({
      status: "blocked",
      conditionalCapability: true,
      candidateProcedurePresentAtLaunch: true,
      procedureProviderPresentAtLaunch: true,
      runScopedProcedureActivationPresentAtLaunch: false,
      grantsRunDispatch: false,
    });
    const adapter = await startReviewedRealCandidateLinuxAdapter({
      loadedProfile: fixture.loadedProfile,
      implementation: bridge,
      now: () => NOW,
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
    expect(registry.missionExecutionReady()).toBeFalse();
    const broker = await startCandidateLinuxTransportBroker({
      manifest: fixture.loadedManifest.value,
      manifestSha256: fixture.loadedManifest.receipt.sourceSha256,
      authorizer: registry,
      handlers: [handler],
      now: () => NOW,
    });
    try {
      await registry.attest();
      expect(bridge.inspectComposition()).toMatchObject({
        status: "ready",
        code: "run_scoped_candidate_bridge_ready",
        conditionalCapability: true,
        candidateProcedurePresentAtLaunch: true,
        procedureProviderPresentAtLaunch: true,
        runScopedProcedureActivationPresentAtLaunch: false,
        grantsRunDispatch: false,
      });
      expect(registry.readiness()).toMatchObject({
        status: "ready",
        readinessScope: "reviewed_real_candidate",
        activationModel: "run_scoped_after_discovery",
        candidateProcedurePresentAtLaunch: true,
        procedureProviderPresentAtLaunch: true,
        runScopedProcedureActivationPresentAtLaunch: false,
        missionExecutionReady: false,
      });
      expect(fixture.database.prepare(`
        SELECT COUNT(*) AS count
        FROM reviewed_candidate_linux_procedure_activations
      `).get()).toEqual({ count: 0 });
      expect(bridge.executionReadiness(
        RUN_ID,
        DERIVED_SPEC_ID,
      )).toMatchObject({
        status: "blocked",
        code: "run_scoped_candidate_procedure_missing",
      });
      await expect(bridge.handle({
        operation: "open",
        transportBindingId: BINDING_ID,
        postExploitSpecId: DERIVED_SPEC_ID,
        sessionArtifactId: "session-before-run-activation",
        exactTarget: EXACT_TARGET,
      }, new AbortController().signal)).rejects.toMatchObject({
        name: "RunScopedReviewedCandidateLinuxProcedureActivationError",
        code: "activation_missing",
      });
    } finally {
      await broker.close();
      await adapter.close();
    }
  });

  test("refuses launch readiness when migration-63 provider admission lineage is unavailable", async () => {
    const fixture = buildFixture();
    const binding = fixture.loadedManifest.value.bindings[0]!;
    registerReviewedRealCandidateLinuxPostExploitSpec({
      database: fixture.database,
      loadedProfile: fixture.loadedProfile,
      binding,
      createdBy: "operator:test",
      now: () => NOW,
    });
    fixture.database.exec(`
      DROP TRIGGER
        trg_reviewed_candidate_procedure_admission_lineage_insert
    `);
    const procedureRoot = join(fixture.root, "procedures");
    mkdirSync(procedureRoot, { mode: 0o700 });
    const bridge =
      new RunScopedReviewedCandidateLinuxProcedureActivationBridge({
        database: fixture.database,
        loadedProfile: fixture.loadedProfile,
        procedureTrustRoot: procedureRoot,
        now: () => NOW,
      });
    await expect(
      bridge.attest(new AbortController().signal),
    ).rejects.toMatchObject({
      name: "RunScopedReviewedCandidateLinuxProcedureActivationError",
      code: "bridge_unavailable",
      message:
        "Run-scoped provider admission schema is unavailable: trg_reviewed_candidate_procedure_admission_lineage_insert",
    });
    expect(bridge.inspectComposition()).toMatchObject({
      status: "blocked",
      grantsRunDispatch: false,
    });
  });

  test("activates one exact run procedure idempotently, resumes by re-attestation, and rejects cross-run reuse", async () => {
    const fixture = buildFixture();
    const current = await seedRunScopedCandidate(fixture);
    const bridge =
      new RunScopedReviewedCandidateLinuxProcedureActivationBridge({
        database: fixture.database,
        loadedProfile: fixture.loadedProfile,
        procedureTrustRoot: current.procedureRoot,
        now: () => NOW,
      });
    await bridge.attest(new AbortController().signal);
    const input = {
      missionId: MISSION_ID,
      runId: RUN_ID,
      planId: PLAN_ID,
      stepId: STEP_ID,
      attackAttemptId: current.attackAttemptId,
      targetNodeId: TARGET_NODE_ID,
      exactTarget: EXACT_TARGET,
      scriptArtifactId: current.scriptArtifactId,
      postExploitSpecId: current.postExploitSpecId,
      representedActionBindingHash:
        current.representedActionBindingHash,
      procedureAdmissionId: current.procedureAdmissionId,
      procedureExecutablePath: current.procedurePath,
      procedureExecutableSha256: current.procedureSha256,
      idempotencyKey: "activate-current-run-candidate-v1",
      actor: { id: "system:procedure-activator", type: "system" as const },
    };
    const sourceScript = fixture.database.prepare(`
      SELECT content_hash FROM script_artifacts WHERE id = ?
    `).get(
      fixture.loadedProfile.value.postExploitSpec.scriptArtifactId,
    ) as { readonly content_hash: string };
    expect(current.procedureSha256).not.toBe(sourceScript.content_hash);
    expect(sourceScript.content_hash).toBe(
      (fixture.database.prepare(`
        SELECT content_hash FROM script_artifacts WHERE id = ?
      `).get(current.scriptArtifactId) as { readonly content_hash: string })
        .content_hash,
    );
    expect(bridge.executionReadiness(
      RUN_ID,
      current.postExploitSpecId,
    )).toMatchObject({
      status: "blocked",
      code: "run_scoped_candidate_procedure_missing",
    });
    await expect(bridge.handle({
      operation: "open",
      transportBindingId: BINDING_ID,
      postExploitSpecId: current.postExploitSpecId,
      sessionArtifactId: "session-current-before-activation",
      exactTarget: EXACT_TARGET,
    }, new AbortController().signal)).rejects.toBeInstanceOf(
      RunScopedReviewedCandidateLinuxProcedureActivationError,
    );

    const first = await bridge.activate(
      input,
      new AbortController().signal,
    );
    expect(first).toMatchObject({
      reused: false,
      activation: {
        missionId: MISSION_ID,
        runId: RUN_ID,
        planId: PLAN_ID,
        stepId: STEP_ID,
        attackAttemptId: current.attackAttemptId,
        targetNodeId: TARGET_NODE_ID,
        exactTarget: EXACT_TARGET,
        postExploitSpecId: current.postExploitSpecId,
        scriptArtifactId: current.scriptArtifactId,
        representedActionBindingHash:
          current.representedActionBindingHash,
        procedureExecutableSha256: current.procedureSha256,
        status: "active",
      },
    });
    expect(first.runScopedAttestationHash)
      .toMatch(/^[a-f0-9]{64}$/u);
    expect(bridge.executionReadiness(
      RUN_ID,
      current.postExploitSpecId,
    )).toMatchObject({
      status: "ready",
      code: "run_scoped_candidate_procedure_ready",
      activationId: first.activation.id,
    });
    expect(await bridge.handle({
      operation: "open",
      transportBindingId: BINDING_ID,
      postExploitSpecId: current.postExploitSpecId,
      sessionArtifactId: "session-current-after-activation",
      exactTarget: EXACT_TARGET,
    }, new AbortController().signal)).toEqual({
      accepted: true,
      sessionArtifactId: "session-current-after-activation",
    });

    const replay = await bridge.activate(
      input,
      new AbortController().signal,
    );
    expect(replay.reused).toBeTrue();
    expect(replay.activation.id).toBe(first.activation.id);
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count
      FROM reviewed_candidate_linux_procedure_activations
    `).get()).toEqual({ count: 1 });

    const resumed =
      new RunScopedReviewedCandidateLinuxProcedureActivationBridge({
        database: fixture.database,
        loadedProfile: fixture.loadedProfile,
        procedureTrustRoot: current.procedureRoot,
        now: () => NOW,
      });
    const resumedReplay = await resumed.activate(
      input,
      new AbortController().signal,
    );
    expect(resumedReplay.reused).toBeTrue();
    expect(resumedReplay.activation.id).toBe(first.activation.id);
    expect(await resumed.handle({
      operation: "open",
      transportBindingId: BINDING_ID,
      postExploitSpecId: current.postExploitSpecId,
      sessionArtifactId: "session-current-after-resume",
      exactTarget: EXACT_TARGET,
    }, new AbortController().signal)).toEqual({
      accepted: true,
      sessionArtifactId: "session-current-after-resume",
    });
    expect(resumed.executionReadiness(
      "run-other-reviewed-real",
      current.postExploitSpecId,
    )).toMatchObject({
      status: "blocked",
      code: "run_scoped_candidate_procedure_missing",
      activationId: null,
    });
    await expect(resumed.activate({
      ...input,
      runId: "run-other-reviewed-real",
      idempotencyKey: "activate-other-run-candidate-v1",
    }, new AbortController().signal)).rejects.toMatchObject({
      name: "RunScopedReviewedCandidateLinuxProcedureActivationError",
      code: "activation_scope_invalid",
    });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count
      FROM reviewed_candidate_linux_procedure_activations
    `).get()).toEqual({ count: 1 });
  });

  test("pre-dispatch coordinator activates only the already admitted distinct provider idempotently", async () => {
    const fixture = buildFixture();
    const current = await seedRunScopedCandidate(fixture);
    const bridge =
      new RunScopedReviewedCandidateLinuxProcedureActivationBridge({
        database: fixture.database,
        loadedProfile: fixture.loadedProfile,
        procedureTrustRoot: current.procedureRoot,
        now: () => NOW,
      });
    const publisher =
      new RunScopedReviewedCandidateLinuxProcedurePublisher({
        database: fixture.database,
        loadedProfile: fixture.loadedProfile,
        bridge,
      });
    const activationInput = {
      missionId: MISSION_ID,
      runId: RUN_ID,
      planId: PLAN_ID,
      stepId: STEP_ID,
      attackAttemptId: current.attackAttemptId,
      targetNodeId: TARGET_NODE_ID,
      exactTarget: EXACT_TARGET,
      scriptArtifactId: current.scriptArtifactId,
      exploitOutcomeObserverSpecId: current.observerId,
      postExploitSpecId: current.postExploitSpecId,
      representedActionBindingHash:
        current.representedActionBindingHash,
    };
    await publisher.activate(
      activationInput,
      new AbortController().signal,
    );
    const activation = fixture.database.prepare(`
      SELECT procedure_executable_path, procedure_executable_sha256,
        script_content_hash, status
      FROM reviewed_candidate_linux_procedure_activations
      WHERE run_id = ? AND step_id = ?
    `).get(RUN_ID, STEP_ID) as Readonly<{
      procedure_executable_path: string;
      procedure_executable_sha256: string;
      script_content_hash: string;
      status: string;
    }>;
    expect(activation).toMatchObject({
      procedure_executable_sha256: current.procedureSha256,
      status: "active",
    });
    expect(activation.procedure_executable_path)
      .toBe(fixture.loadedProfile.value.procedure.executablePath);
    expect(hashFile(activation.procedure_executable_path))
      .toBe(current.procedureSha256);
    expect(activation.procedure_executable_sha256)
      .not.toBe(activation.script_content_hash);
    expect(activation.script_content_hash).toBe(
      (fixture.database.prepare(`
        SELECT content_hash FROM script_artifacts WHERE id = ?
      `).get(current.scriptArtifactId) as { readonly content_hash: string })
        .content_hash,
    );

    const resumedBridge =
      new RunScopedReviewedCandidateLinuxProcedureActivationBridge({
        database: fixture.database,
        loadedProfile: fixture.loadedProfile,
        procedureTrustRoot: current.procedureRoot,
        now: () => NOW,
      });
    const resumedPublisher =
      new RunScopedReviewedCandidateLinuxProcedurePublisher({
        database: fixture.database,
        loadedProfile: fixture.loadedProfile,
        bridge: resumedBridge,
      });
    await resumedPublisher.activate(
      activationInput,
      new AbortController().signal,
    );
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count
      FROM reviewed_candidate_linux_procedure_activations
      WHERE run_id = ? AND step_id = ?
    `).get(RUN_ID, STEP_ID)).toEqual({ count: 1 });
    expect(resumedBridge.executionReadiness(
      RUN_ID,
      current.postExploitSpecId,
    )).toMatchObject({
      status: "ready",
      code: "run_scoped_candidate_procedure_ready",
    });
  });

  test("rejects unpinned providers, mismatched action custody, and cancelled activation without persisting authority", async () => {
    const fixture = buildFixture();
    const current = await seedRunScopedCandidate(fixture);
    const bridge =
      new RunScopedReviewedCandidateLinuxProcedureActivationBridge({
        database: fixture.database,
        loadedProfile: fixture.loadedProfile,
        procedureTrustRoot: current.procedureRoot,
        now: () => NOW,
      });
    const base = {
      missionId: MISSION_ID,
      runId: RUN_ID,
      planId: PLAN_ID,
      stepId: STEP_ID,
      attackAttemptId: current.attackAttemptId,
      targetNodeId: TARGET_NODE_ID,
      exactTarget: EXACT_TARGET,
      scriptArtifactId: current.scriptArtifactId,
      postExploitSpecId: current.postExploitSpecId,
      representedActionBindingHash:
        current.representedActionBindingHash,
      procedureAdmissionId: current.procedureAdmissionId,
      procedureExecutablePath: current.procedurePath,
      procedureExecutableSha256: current.procedureSha256,
      idempotencyKey: "activate-rejection-candidate-v1",
      actor: { id: "system:procedure-activator", type: "system" as const },
    };
    await expect(bridge.activate({
      ...base,
      representedActionBindingHash: "0".repeat(64),
    }, new AbortController().signal)).rejects.toMatchObject({
      name: "RunScopedReviewedCandidateLinuxProcedureActivationError",
      code: "activation_scope_invalid",
    });
    const unrelatedPath = join(
      current.procedureRoot,
      "unrelated-candidate",
    );
    writeFileSync(
      unrelatedPath,
      `${runScopedProcedureSource()}\n// unrelated executable bytes\n`,
      { mode: 0o500 },
    );
    await expect(bridge.activate({
      ...base,
      procedureExecutablePath: unrelatedPath,
      procedureExecutableSha256: hashFile(unrelatedPath),
      idempotencyKey: "activate-unrelated-candidate-v1",
    }, new AbortController().signal)).rejects.toThrow(
      "Procedure executable must equal the distinct path and hash pinned by the reviewed profile",
    );
    await expect(bridge.activate({
      ...base,
      procedureExecutablePath:
        fixture.loadedProfile.value.adapter.executablePath,
    }, new AbortController().signal)).rejects.toThrow(
      "Procedure executable must equal the distinct path and hash pinned by the reviewed profile",
    );
    const cancelled = new AbortController();
    cancelled.abort();
    await expect(bridge.activate(
      base,
      cancelled.signal,
    )).rejects.toMatchObject({
      name: "RunScopedReviewedCandidateLinuxProcedureActivationError",
      code: "activation_stale",
    });
    expect(fixture.database.prepare(`
      SELECT COUNT(*) AS count
      FROM reviewed_candidate_linux_procedure_activations
    `).get()).toEqual({ count: 0 });
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
        targetScope: fixture.loadedProfile.value.targetScope,
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
        targetScope: fixture.loadedProfile.value.targetScope,
        async attest() {},
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
        targetScope: fixture.loadedProfile.value.targetScope,
        async attest() {},
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

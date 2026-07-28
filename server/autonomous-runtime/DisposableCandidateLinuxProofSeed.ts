import { createHash } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { digestCanonicalJson } from "../mcp";
import {
  FileScriptSourceStore,
  ScriptArtifactService,
} from "../script-artifacts";
import {
  resolveV2ScriptSourceRoot,
} from "../app";

export const DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED = Object.freeze({
  missionId: "mission:system-disposable-linux-proof-v1",
  testArtifactId: "artifact:system-disposable-linux-proof-tests-v1",
  scriptName: "fixtures/disposable_linux_candidate.py",
  observerSpecId: "observer:disposable-linux-proof-v1",
  postExploitSpecId: "post-exploit:disposable-linux-proof-v1",
  transportBindingId: "candidate.disposable-local-linux.v1",
  cveId: "CVE-2021-41773",
  exactTarget: "127.0.0.2",
  expectedPrincipal: "candidate",
  expectedUid: 1001,
  declaredUserFlagPath: "/home/candidate/user.txt",
} as const);

const SOURCE = [
  "#!/usr/bin/env python3",
  "\"\"\"Disposable Ti-Scale candidate marker; no target operation occurs here.\"\"\"",
  "import argparse",
  "import ipaddress",
  "import json",
  "parser = argparse.ArgumentParser()",
  "parser.add_argument('--target', required=True)",
  "target = parser.parse_args().target",
  "address = ipaddress.ip_address(target)",
  "if not address.is_loopback:",
  "    raise SystemExit('fixture target must be loopback')",
  "print(json.dumps({'fixtureOnly': True, 'targetValidated': str(address)}))",
  "",
].join("\n");

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export interface DisposableCandidateLinuxProofSeedReceipt {
  readonly schemaVersion:
    "ti-scale.disposable-candidate-linux-proof-seed-receipt.v1";
  readonly status: "created" | "already_current";
  readonly fixtureOnly: true;
  readonly realTargetSupport: false;
  readonly postExploitSpecId: string;
  readonly postExploitSpecSha256: string;
  readonly transportBindingId: string;
  readonly scriptArtifactId: string;
  readonly scriptContentSha256: string;
  readonly observerSpecId: string;
}

function current(
  database: SqliteDatabase,
): Omit<DisposableCandidateLinuxProofSeedReceipt, "schemaVersion" | "status">
| undefined {
  const seed = DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED;
  const row = database.prepare(`
    SELECT spec.id AS post_exploit_spec_id, spec.spec_hash,
      spec.transport_binding_id, spec.transport_type, spec.transport_origin,
      spec.expected_principal, spec.expected_uid,
      spec.declared_user_flag_path, spec.declared_root_flag_path,
      spec.status AS spec_status, observer.id AS observer_spec_id,
      observer.status AS observer_status,
      script.id AS script_artifact_id, script.content_hash,
      script.validation_state
    FROM candidate_linux_post_exploit_specs spec
    JOIN exploit_outcome_observer_specs observer
      ON observer.id = spec.exploit_outcome_observer_spec_id
      AND observer.script_artifact_id = spec.script_artifact_id
    JOIN script_artifacts script ON script.id = spec.script_artifact_id
    WHERE spec.id = ?
  `).get(seed.postExploitSpecId) as {
    readonly post_exploit_spec_id: string;
    readonly spec_hash: string;
    readonly transport_binding_id: string;
    readonly transport_type: string;
    readonly transport_origin: string | null;
    readonly expected_principal: string;
    readonly expected_uid: number;
    readonly declared_user_flag_path: string;
    readonly declared_root_flag_path: string;
    readonly spec_status: string;
    readonly observer_spec_id: string;
    readonly observer_status: string;
    readonly script_artifact_id: string;
    readonly content_hash: string;
    readonly validation_state: string;
  } | undefined;
  if (!row) return undefined;
  if (
    row.transport_binding_id !== seed.transportBindingId
    || row.transport_type !== "candidate_runtime_session_v1"
    || row.transport_origin !== null
    || row.expected_principal !== seed.expectedPrincipal
    || row.expected_uid !== seed.expectedUid
    || row.declared_user_flag_path !== seed.declaredUserFlagPath
    || row.declared_root_flag_path !== "/root/root.txt"
    || row.spec_status !== "active"
    || row.observer_spec_id !== seed.observerSpecId
    || row.observer_status !== "active"
    || row.content_hash !== sha256(SOURCE)
    || row.validation_state !== "approved"
  ) {
    throw new Error(
      "The disposable candidate seed IDs already exist with different authority",
    );
  }
  return Object.freeze({
    fixtureOnly: true,
    realTargetSupport: false,
    postExploitSpecId: row.post_exploit_spec_id,
    postExploitSpecSha256: row.spec_hash,
    transportBindingId: row.transport_binding_id,
    scriptArtifactId: row.script_artifact_id,
    scriptContentSha256: row.content_hash,
    observerSpecId: row.observer_spec_id,
  });
}

export function seedDisposableCandidateLinuxProof(input: Readonly<{
  database: SqliteDatabase;
  databasePath: string;
  scriptSourceRoot?: string;
  now?: () => Date;
}>): DisposableCandidateLinuxProofSeedReceipt {
  const existing = current(input.database);
  if (existing) {
    return Object.freeze({
      schemaVersion:
        "ti-scale.disposable-candidate-linux-proof-seed-receipt.v1",
      status: "already_current",
      ...existing,
    });
  }
  const partial = input.database.prepare(`
    SELECT
      EXISTS(SELECT 1 FROM missions WHERE id = ?) AS mission_present,
      EXISTS(SELECT 1 FROM exploit_outcome_observer_specs WHERE id = ?)
        AS observer_present
  `).get(
    DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED.missionId,
    DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED.observerSpecId,
  ) as { readonly mission_present: number; readonly observer_present: number };
  if (partial.mission_present || partial.observer_present) {
    throw new Error(
      "A partial disposable candidate seed exists; reconcile it before retrying",
    );
  }
  const seed = DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED;
  const now = (input.now ?? (() => new Date()))().toISOString();
  const store = new FileScriptSourceStore(resolveV2ScriptSourceRoot(
    input.databasePath,
    input.scriptSourceRoot,
  ));
  const created = inImmediateTransaction(input.database, () => {
    input.database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, status, authorization_status,
        scope_json, success_criteria_json, retention_policy_json,
        memory_policy_json, created_by, version, created_at, updated_at,
        control_plane
      ) VALUES (?, 'Disposable candidate proof catalogue',
        'Hold one harmless local fixture used only to prove the typed Autonomous execution path.',
        'autonomous', 'archived', 'verified',
        '{"fixtureOnly":true,"realTargetSupport":false}',
        '[]', '{"fixtureOnly":true}', '{"fixtureOnly":true}',
        'operator:system-fixture', 1, ?, ?, 'ti_scale')
    `).run(seed.missionId, now, now);
    const testMaterial =
      "Exact-source review: loopback-only validation, no network, command, shell, payload, credential, or file-read surface.";
    input.database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, step_id, action_id, journey, artifact_type,
        storage_uri, content_hash, byte_size, media_type, sensitivity,
        metadata_json, created_at
      ) VALUES (?, ?, NULL, NULL, NULL, 'autonomous',
        'script_test_result', 'fixture://disposable-linux-source-review-v1',
        ?, ?, 'text/plain', 'internal',
        '{"fixtureOnly":true,"realTargetSupport":false}', ?)
    `).run(
      seed.testArtifactId,
      seed.missionId,
      sha256(testMaterial),
      Buffer.byteLength(testMaterial),
      now,
    );
    const scripts = new ScriptArtifactService(
      input.database,
      store,
      () => new Date(now),
    );
    const script = scripts.create({
      missionId: seed.missionId,
      name: seed.scriptName,
      language: "python",
      source: SOURCE,
      laymanExplanation:
        "Checks that the supplied fixture address is local and emits a typed marker; it does not touch a target.",
      technicalPurpose:
        "Provide an immutable, harmless script identity for the disposable production-path proof.",
      inputs: [{
        name: "target",
        description: "One broker-supplied loopback address.",
        required: true,
        sensitivity: "ordinary",
      }],
      expectedOutputs: [{
        label: "Fixture marker",
        description: "Canonical JSON confirming only that loopback input validation ran.",
        successRecognition:
          "The marker reports fixtureOnly and the exact loopback target.",
        failureRecognition:
          "Any non-loopback input or execution error stops the fixture proof.",
      }],
      prerequisites: [
        "The run is explicitly classified as a disposable local fixture.",
      ],
      dependencies: ["Python 3 standard library"],
      touches: { files: [], network: [], services: [] },
      sideEffects: ["None; the script validates an address in memory."],
      riskClass: "low",
      reversibility: "No state is changed.",
      cleanupNotes: "No script cleanup is required.",
      secretsHandling: "No credentials or secret references are accepted.",
      evidenceExpectations: [
        "Script completion is not target-impact evidence.",
        "A separate local observer must establish the fixture outcome.",
      ],
      validation: {
        state: "approved",
        summary:
          "The exact immutable fixture source passed a deterministic no-I/O review.",
        tests: [{
          name: "fixture-only source boundary",
          status: "passed",
          summary:
            "Static validation confirmed loopback input checking and no network, subprocess, shell, credential, or file-read operation.",
        }],
        testArtifactId: seed.testArtifactId,
      },
      provenance: {
        origin: "operator_authored",
        explanation:
          "Created only to prove Ti-Scale's typed candidate session path.",
        sourceRefs: [seed.testArtifactId],
      },
      sensitivity: "internal",
    }, { id: "operator:system-fixture", type: "operator" });
    const observerRequest = {
      scheme: "http",
      host: seed.exactTarget,
      port: 43149,
      method: "GET",
      path: "/ti-scale/disposable/impact",
      fixtureOnly: true,
    };
    const observerAssertion = {
      statusCodes: [200],
      bodyContains: ["TI_SCALE_DISPOSABLE_LOCAL_IMPACT"],
      fixtureOnly: true,
    };
    const observerHash = digestCanonicalJson({
      scriptArtifactId: script.id,
      scriptContentHash: script.contentHash,
      cveId: seed.cveId,
      request: observerRequest,
      assertion: observerAssertion,
      fixtureOnly: true,
      realTargetSupport: false,
    }, { maxBytes: 32 * 1_024, maxDepth: 16 }).sha256;
    input.database.prepare(`
      INSERT INTO exploit_outcome_observer_specs (
        id, script_artifact_id, script_content_hash, cve_id,
        observer_type, request_json, assertion_json, spec_hash,
        status, created_by, created_at
      ) VALUES (?, ?, ?, ?, 'http_response_assertion', ?, ?, ?,
        'active', 'operator:system-fixture', ?)
    `).run(
      seed.observerSpecId,
      script.id,
      script.contentHash,
      seed.cveId,
      JSON.stringify(observerRequest),
      JSON.stringify(observerAssertion),
      observerHash,
      now,
    );
    const specificationMaterial = {
      observerSpecId: seed.observerSpecId,
      scriptArtifactId: script.id,
      scriptContentHash: script.contentHash,
      transportType: "candidate_runtime_session_v1",
      transportBindingId: seed.transportBindingId,
      expectedPrincipal: seed.expectedPrincipal,
      expectedUid: seed.expectedUid,
      declaredUserFlagPath: seed.declaredUserFlagPath,
      declaredRootFlagPath: "/root/root.txt",
      fixtureOnly: true,
      realTargetSupport: false,
    };
    const specHash = digestCanonicalJson(
      specificationMaterial,
      { maxBytes: 32 * 1_024, maxDepth: 16 },
    ).sha256;
    input.database.prepare(`
      INSERT INTO candidate_linux_post_exploit_specs (
        id, exploit_outcome_observer_spec_id, script_artifact_id,
        transport_type, transport_binding_id, transport_origin,
        open_path, identity_path, user_flag_proof_path, privilege_path,
        root_identity_path, root_flag_proof_path, cleanup_path,
        expected_principal, expected_uid, declared_user_flag_path,
        declared_root_flag_path, spec_hash, status, created_by, created_at
      ) VALUES (?, ?, ?, 'candidate_runtime_session_v1', ?, NULL,
        '/ti-scale/session/open', '/ti-scale/session/identity',
        '/ti-scale/session/user-flag-proof',
        '/ti-scale/session/privilege-escalation',
        '/ti-scale/session/root-identity',
        '/ti-scale/session/root-flag-proof',
        '/ti-scale/session/cleanup', ?, ?, ?, '/root/root.txt', ?,
        'active', 'operator:system-fixture', ?)
    `).run(
      seed.postExploitSpecId,
      seed.observerSpecId,
      script.id,
      seed.transportBindingId,
      seed.expectedPrincipal,
      seed.expectedUid,
      seed.declaredUserFlagPath,
      specHash,
      now,
    );
    return Object.freeze({
      fixtureOnly: true as const,
      realTargetSupport: false as const,
      postExploitSpecId: seed.postExploitSpecId,
      postExploitSpecSha256: specHash,
      transportBindingId: seed.transportBindingId,
      scriptArtifactId: script.id,
      scriptContentSha256: script.contentHash,
      observerSpecId: seed.observerSpecId,
    });
  });
  return Object.freeze({
    schemaVersion:
      "ti-scale.disposable-candidate-linux-proof-seed-receipt.v1",
    status: "created",
    ...created,
  });
}

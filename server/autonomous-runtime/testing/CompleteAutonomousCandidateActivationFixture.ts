import { createHash } from "node:crypto";
import {
  chmodSync,
  chownSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import {
  prepareReviewedRealCandidateLinuxActivation,
} from "../../../scripts/release/ReviewedRealCandidateLinuxActivationBundle";
import {
  resolveV2ScriptSourceRoot,
} from "../../app/V2ArtifactPaths";
import {
  inImmediateTransaction,
  listAppliedMigrations,
  type SqliteDatabase,
} from "../../db";
import { MemoryRepository } from "../../memory";
import { digestCanonicalJson } from "../../mcp/canonicalJson";
import {
  FileScriptSourceStore,
  ScriptArtifactService,
  type ScriptArtifactDetail,
} from "../../script-artifacts";
import {
  readActiveVaultComposition,
} from "../../vault/ActiveVaultComposition";
import { ObsidianVaultBridge } from "../../vault/ObsidianVaultBridge";
import {
  VaultProjectionReconciliationService,
} from "../../vault/VaultProjectionReconciliationService";
import { VaultPathPolicy } from "../../vault/VaultPathPolicy";
import {
  candidateLinuxPostExploitSpecificationHash,
} from "../CandidateLinuxPostExploitSpecRegistry";
import {
  exactCandidateLinuxTargetScope,
} from "../CandidateLinuxTargetScope";
import {
  REUSABLE_EXPLOIT_PROCEDURE_ONBOARDING_SCHEMA_VERSION,
  ReusableExploitProcedureOnboardingService,
  type ReusableExploitProcedureOnboardingResult,
} from "../ReusableExploitProcedureOnboardingService";
import {
  parseReviewedRealCandidateLinuxProfile,
  REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
  REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
  REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
  type ReviewedRealCandidateLinuxProfile,
} from "../ReviewedRealCandidateLinuxTransport";
import {
  DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
  DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER,
  DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER_HEADER,
  DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
  DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
  DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
  DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
  DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
  DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
} from "./DisposableCompleteAutonomousTarget";
import {
  COMPLETE_AUTONOMOUS_CANDIDATE_ADAPTER_PATH,
  COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
  COMPLETE_AUTONOMOUS_CANDIDATE_GENERAL_EXTERNAL_TARGET_SUPPORT,
  COMPLETE_AUTONOMOUS_CANDIDATE_PROCEDURE_PATH,
  COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET,
  COMPLETE_AUTONOMOUS_SOURCE_POST_EXPLOIT_SPEC_ID,
  renderCompleteAutonomousCandidateProcedureProvider,
} from "./CompleteAutonomousCandidateProcedureProviderSource";

export const COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE =
  Object.freeze({
    missionId: "mission:system-complete-autonomous-source-v1",
    contractId: "contract:system-complete-autonomous-source-v1",
    runId: "run:system-complete-autonomous-source-v1",
    assetId: "asset:complete-autonomous-fixture-127-0-0-2",
    serviceId: "service:complete-autonomous-fixture-http-8080",
    evidenceId: "evidence:complete-autonomous-fixture-apache-2-4-49",
    evidenceCustodyId:
      "custody:complete-autonomous-fixture-apache-2-4-49-verified",
    cveApplicabilityId:
      "cveapp:complete-autonomous-fixture-cve-2021-41773",
    testArtifactId:
      "artifact:complete-autonomous-fixture-exploit-source-tests-v1",
    scriptName: "fixtures/reviewed_complete_autonomous_cve_2021_41773.py",
    profileId: "profile:reviewed-complete-autonomous-fixture-v1",
    reviewedAt: "2026-07-28T20:30:00.000Z",
  } as const);

export const COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_BUNDLE_VERSION =
  "complete-autonomous-fixture-v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const FIXTURE_SCHEMA_VERSION = 63;
const OPERATIONS = Object.freeze([
  "open",
  "observe_identity",
  "prove_user_flag_hash",
  "close",
  "privilege_escalation",
  "observe_root_identity",
  "prove_root_flag_hash",
  "cleanup",
] as const);
const BOUNDARY = Object.freeze({
  typedOperationsOnly: true as const,
  genericCommand: false as const,
  shell: false as const,
  argv: false as const,
  payload: false as const,
  credentialsFromRuntime: false as const,
  exactTargetFromCanonicalAction: true as const,
  succeededAttackAttemptRequired: true as const,
  derivedCurrentRunSpecOnly: true as const,
  publicProvider: false as const,
  hashOnlyFlagProofs: true as const,
});

const EXPLOIT_SOURCE = [
  "#!/usr/bin/python3.13",
  "\"\"\"Reviewed fixture-only CVE-2021-41773 impact-marker validation.\"\"\"",
  "import argparse",
  "import http.client",
  "import ipaddress",
  "import json",
  "",
  "parser = argparse.ArgumentParser(allow_abbrev=False)",
  "parser.add_argument('--target', action='append', required=True)",
  "arguments = parser.parse_args()",
  "if len(arguments.target) != 1:",
  "    raise SystemExit('exactly one target is required')",
  "target = str(ipaddress.ip_address(arguments.target[0]))",
  `if target != ${JSON.stringify(DISPOSABLE_COMPLETE_AUTONOMOUS_HOST)}:`,
  "    raise SystemExit('target is outside the reviewed fixture')",
  `connection = http.client.HTTPConnection(target, ${DISPOSABLE_COMPLETE_AUTONOMOUS_PORT}, timeout=3)`,
  "try:",
  `    connection.request('GET', ${JSON.stringify(DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH)}, headers={${JSON.stringify(DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER_HEADER)}: ${JSON.stringify(DISPOSABLE_COMPLETE_AUTONOMOUS_FIXTURE_MARKER)}})`,
  "    response = connection.getresponse()",
  "    body = response.read(16385)",
  "finally:",
  "    connection.close()",
  "if len(body) > 16384 or response.status != 200:",
  "    raise SystemExit('reviewed fixture impact response was not bounded success')",
  "document = json.loads(body.decode('utf-8'))",
  `if document.get('marker') != ${JSON.stringify(DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER)} or document.get('fixtureOnly') is not True:`,
  "    raise SystemExit('reviewed fixture impact marker was not disclosed')",
  "print(json.dumps({'fixtureOnly': True, 'processReceiptOnly': True, 'impactMarkerMatched': True}, separators=(',', ':')))",
  "",
].join("\n");

const VERSION_EVIDENCE = Object.freeze({
  fixtureOnly: true,
  target: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
  port: DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
  transport: "tcp",
  product: DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
  exactVersion: DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
  verificationMethod: "actively_verified",
  versionEndpoint: "/version",
});
const VERSION_EVIDENCE_HASH = digestCanonicalJson(
  VERSION_EVIDENCE,
  { maxBytes: 16 * 1_024, maxDepth: 8 },
).sha256;
const CONTRACT_DOCUMENT = Object.freeze({
  fixtureOnly: true,
  priorReviewedSourceOnly: true,
  target: `${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}:${DISPOSABLE_COMPLETE_AUTONOMOUS_PORT}`,
  actionClass: "bounded_exploit_validation",
  cveId: DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
});
const CONTRACT_HASH = digestCanonicalJson(
  CONTRACT_DOCUMENT,
  { maxBytes: 16 * 1_024, maxDepth: 8 },
).sha256;

export interface CompleteAutonomousCandidateActivationSourceFiles {
  readonly trustRoot: string;
  readonly profilePath: string;
  readonly adapterPath: string;
  readonly adapterSha256: string;
  readonly procedurePath: string;
  readonly procedureSha256: string;
  readonly brokerPath: string;
  readonly brokerSha256: string;
  readonly registerPath: string;
  readonly registerSha256: string;
}

export interface CompleteAutonomousCandidateActivationFixtureInput {
  readonly database: SqliteDatabase;
  readonly databasePath: string;
  readonly vaultSandboxRoot: string;
  readonly activationSourceRoot: string;
  readonly adapterPath: string;
  readonly adapterSha256: string;
  readonly brokerPath: string;
  readonly brokerSha256: string;
  readonly registerPath: string;
  readonly registerSha256: string;
  readonly serviceGid: number;
  readonly serviceUid?: number;
  readonly scriptSourceRoot?: string;
  readonly expectedVaultConnectionId?: string;
  readonly expectedVaultPath?: string;
  readonly expectedVaultDisplayName?: string;
  readonly bundleVersion?: string;
  readonly now?: () => Date;
}

export interface CompleteAutonomousCandidateActivationFixtureReceipt {
  readonly schemaVersion:
    "ti-scale.complete-autonomous-candidate-activation-fixture.v1";
  readonly status: "prepared";
  readonly fixtureOnly: true;
  readonly noBackupCreated: true;
  readonly deploymentPerformed: false;
  readonly serviceRestarted: false;
  readonly databaseSchemaVersion: 63;
  readonly capabilityScope: "exact_disposable_fixture_only";
  readonly supportedTarget:
    typeof COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET;
  readonly generalExternalTargetSupport: false;
  readonly generalMissionReadinessEligible: false;
  readonly targetScopedReadinessRequired: true;
  readonly missionId: string;
  readonly runId: string;
  readonly contractId: string;
  readonly contractHash: string;
  readonly scriptArtifactId: string;
  readonly scriptContentSha256: string;
  readonly observerSpecId: string;
  readonly observerSpecSha256: string;
  readonly onboardingId: string;
  readonly onboardingSha256: string;
  readonly brainNodeIds: readonly string[];
  readonly vaultConnectionId: string;
  readonly vaultPath: string;
  readonly vaultProjectionStatus: "complete";
  readonly postExploitSpecId: string;
  readonly postExploitSpecSha256: string;
  readonly bindingId: string;
  readonly profileSha256: string;
  readonly manifestSha256: string;
  readonly source: CompleteAutonomousCandidateActivationSourceFiles;
  readonly installer: Readonly<{
    readonly executable: string;
    readonly sourceVerifyArguments: readonly string[];
    readonly installArguments: readonly string[];
  }>;
  readonly registration: Readonly<{
    readonly executable: string;
    readonly environment: Readonly<Record<string, string>>;
    readonly arguments: readonly [];
  }>;
}

interface SeedIdentityRow {
  readonly mission_name: string;
  readonly mission_objective: string;
  readonly mission_status: string;
  readonly authorization_status: string;
  readonly mission_control_plane: string;
  readonly contract_state: string;
  readonly contract_hash: string;
  readonly contract_version: number;
  readonly run_status: string;
  readonly run_progress: number;
  readonly run_control_plane: string;
  readonly contract_id: string;
  readonly contract_version_bound: number;
  readonly contract_hash_bound: string;
  readonly asset_scope_status: string;
  readonly asset_verification_state: string;
  readonly service_scope_status: string;
  readonly service_verification_state: string;
  readonly service_properties_json: string;
  readonly evidence_hash: string;
  readonly evidence_state: string;
  readonly evidence_type: string;
  readonly evidence_provenance_json: string;
  readonly cve_id: string;
  readonly cve_title: string;
  readonly cve_description: string;
  readonly component: string;
  readonly detected_version: string;
  readonly applicability: string;
  readonly cve_confidence: number;
  readonly version_evidence_id: string;
  readonly test_hash: string;
}

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(value);
}

function assertSha256(value: string, label: string): string {
  if (!SHA256.test(value)) throw new TypeError(`${label} must be a SHA-256`);
  return value;
}

function assertSchema63(database: SqliteDatabase): void {
  const migrations = listAppliedMigrations(database);
  if (
    migrations.length !== FIXTURE_SCHEMA_VERSION
    || migrations.at(-1)?.version !== FIXTURE_SCHEMA_VERSION
    || migrations.some(({ version }, index) => version !== index + 1)
  ) {
    throw new Error(
      "Complete Autonomous fixture preparation requires the exact forward-only schema 63 database",
    );
  }
}

function seedIdentity(database: SqliteDatabase): SeedIdentityRow | undefined {
  const seed = COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE;
  return database.prepare(`
    SELECT mission.name AS mission_name, mission.objective AS mission_objective,
      mission.status AS mission_status,
      mission.authorization_status, mission.control_plane AS mission_control_plane,
      contract.state AS contract_state, contract.contract_hash,
      contract.version AS contract_version,
      run.status AS run_status, run.progress AS run_progress,
      run.control_plane AS run_control_plane, run.contract_id,
      run.contract_version_bound, run.contract_hash_bound,
      asset.scope_status AS asset_scope_status,
      asset.verification_state AS asset_verification_state,
      service.scope_status AS service_scope_status,
      service.verification_state AS service_verification_state,
      service.properties_json AS service_properties_json,
      evidence.content_hash AS evidence_hash,
      evidence.verification_state AS evidence_state,
      evidence.evidence_type, evidence.provenance_json AS evidence_provenance_json,
      cve.cve_id, cve.title AS cve_title,
      cve.description AS cve_description,
      cve.component, cve.detected_version,
      cve.applicability, cve.confidence AS cve_confidence,
      cve.version_evidence_id, test.content_hash AS test_hash
    FROM missions mission
    JOIN mission_contracts contract ON contract.id = ?
      AND contract.mission_id = mission.id
    JOIN runs run ON run.id = ? AND run.mission_id = mission.id
    JOIN topology_nodes asset ON asset.id = ?
      AND asset.mission_id = mission.id AND asset.run_id = run.id
    JOIN topology_nodes service ON service.id = ?
      AND service.mission_id = mission.id AND service.run_id = run.id
    JOIN evidence evidence ON evidence.id = ?
      AND evidence.mission_id = mission.id AND evidence.run_id = run.id
    JOIN cve_applicability_records cve ON cve.id = ?
      AND cve.mission_id = mission.id AND cve.run_id = run.id
    JOIN artifacts test ON test.id = ?
      AND test.mission_id = mission.id AND test.run_id = run.id
    WHERE mission.id = ?
  `).get(
    seed.contractId,
    seed.runId,
    seed.assetId,
    seed.serviceId,
    seed.evidenceId,
    seed.cveApplicabilityId,
    seed.testArtifactId,
    seed.missionId,
  ) as SeedIdentityRow | undefined;
}

function assertSeedIdentity(database: SqliteDatabase): void {
  const seed = COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE;
  const row = seedIdentity(database);
  const serviceProperties = canonicalJson({
    fixtureOnly: true,
    exactTarget: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
    port: DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
    transport: "tcp",
    product: DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
    version: DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
  });
  const evidenceProvenance = canonicalJson({
    method: "actively_verified",
    fixtureOnly: true,
    verificationEndpoint:
      `http://${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}:${DISPOSABLE_COMPLETE_AUTONOMOUS_PORT}/version`,
  });
  const testMaterial =
    "Reviewed exact argv: --target only; fixed loopback HTTP impact path/header; no shell, command, credential, service, or file input.";
  if (
    !row
    || row.mission_name
      !== "[DISPOSABLE FIXTURE ONLY] Complete Autonomous source proof"
    || row.mission_objective
      !== "Retain one explicitly labeled disposable loopback fixture source for an exact-target Autonomous execution proof. This record does not establish general HTB or external-target capability."
    || row.mission_status !== "archived"
    || row.authorization_status !== "verified"
    || row.mission_control_plane !== "ti_scale"
    || row.contract_state !== "confirmed"
    || row.contract_hash !== CONTRACT_HASH
    || row.contract_version !== 1
    || row.run_status !== "completed"
    || row.run_progress !== 1
    || row.run_control_plane !== "ti_scale"
    || row.contract_id !== seed.contractId
    || row.contract_version_bound !== 1
    || row.contract_hash_bound !== CONTRACT_HASH
    || row.asset_scope_status !== "allowed"
    || row.asset_verification_state !== "verified"
    || row.service_scope_status !== "allowed"
    || row.service_verification_state !== "verified"
    || row.service_properties_json !== serviceProperties
    || row.evidence_hash !== VERSION_EVIDENCE_HASH
    || row.evidence_state !== "verified"
    || row.evidence_type !== "service_version_fingerprint"
    || row.evidence_provenance_json !== evidenceProvenance
    || row.cve_id !== DISPOSABLE_COMPLETE_AUTONOMOUS_CVE
    || row.cve_title
      !== `[DISPOSABLE FIXTURE ONLY] ${DISPOSABLE_COMPLETE_AUTONOMOUS_CVE} applicability`
    || row.cve_description
      !== "Disposable fixture applicability is pinned to one actively verified local Apache HTTP Server 2.4.49 service and must not be generalized to an external target."
    || row.component !== DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT
    || row.detected_version !== DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION
    || row.applicability !== "confirmed"
    || row.cve_confidence !== 0.99
    || row.version_evidence_id !== seed.evidenceId
    || row.test_hash !== sha256(testMaterial)
  ) {
    throw new Error(
      "The complete Autonomous fixture seed is partial or differs from the exact reviewed authority",
    );
  }
  const links = database.prepare(`
    SELECT
      EXISTS(SELECT 1 FROM evidence_chain_events
        WHERE id = ? AND evidence_id = ? AND event_type = 'verified')
        AS custody,
      EXISTS(SELECT 1 FROM topology_evidence_links
        WHERE subject_type = 'node' AND subject_id = ?
          AND evidence_id = ? AND relationship = 'supports') AS topology
  `).get(
    seed.evidenceCustodyId,
    seed.evidenceId,
    seed.assetId,
    seed.evidenceId,
  ) as { readonly custody: number; readonly topology: number };
  if (links.custody !== 1 || links.topology !== 1) {
    throw new Error("The fixture evidence custody or topology binding drifted");
  }
}

function seedCanonicalPriorReview(database: SqliteDatabase): "created" | "replayed" {
  const seed = COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE;
  const missionPresent = database.prepare(
    "SELECT 1 AS present FROM missions WHERE id = ?",
  ).get(seed.missionId);
  if (missionPresent) {
    assertSeedIdentity(database);
    return "replayed";
  }
  const collisions = database.prepare(`
    SELECT
      EXISTS(SELECT 1 FROM mission_contracts WHERE id = ?) AS contract_present,
      EXISTS(SELECT 1 FROM runs WHERE id = ?) AS run_present,
      EXISTS(SELECT 1 FROM topology_nodes WHERE id IN (?, ?)) AS topology_present,
      EXISTS(SELECT 1 FROM evidence WHERE id = ?) AS evidence_present,
      EXISTS(SELECT 1 FROM cve_applicability_records WHERE id = ?) AS cve_present,
      EXISTS(SELECT 1 FROM artifacts WHERE id = ?) AS artifact_present
  `).get(
    seed.contractId,
    seed.runId,
    seed.assetId,
    seed.serviceId,
    seed.evidenceId,
    seed.cveApplicabilityId,
    seed.testArtifactId,
  ) as Record<string, number>;
  if (Object.values(collisions).some((value) => value !== 0)) {
    throw new Error(
      "A partial complete Autonomous fixture identity exists; no row was changed",
    );
  }
  const now = seed.reviewedAt;
  const testMaterial =
    "Reviewed exact argv: --target only; fixed loopback HTTP impact path/header; no shell, command, credential, service, or file input.";
  inImmediateTransaction(database, () => {
    database.prepare(`
      INSERT INTO missions (
        id, name, objective, journey, status, authorization_status,
        scope_json, success_criteria_json, retention_policy_json,
        memory_policy_json, created_by, version, created_at, updated_at,
        control_plane
      ) VALUES (?, '[DISPOSABLE FIXTURE ONLY] Complete Autonomous source proof',
        'Retain one explicitly labeled disposable loopback fixture source for an exact-target Autonomous execution proof. This record does not establish general HTB or external-target capability.',
        'autonomous', 'archived', 'verified', ?, ?, ?, ?,
        'operator:system-fixture', 1, ?, ?, 'ti_scale')
    `).run(
      seed.missionId,
      canonicalJson({
        fixtureOnly: true,
        exactTarget: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
        exactPort: DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
      }),
      canonicalJson([{
        fixtureOnly: true,
        criterion:
          "Independent observer confirms only the fixed read-only impact marker.",
      }]),
      canonicalJson({ fixtureOnly: true, reusableReviewedSource: true }),
      canonicalJson({
        fixtureOnly: true,
        reusableOnlyWhenConfirmedAndVerified: true,
      }),
      now,
      now,
    );
    database.prepare(`
      INSERT INTO mission_contracts (
        id, mission_id, version, state, contract_hash,
        authorization_json, action_policy_json, budgets_json,
        safe_stop_json, deliverables_json, memory_scopes_json,
        confirmed_by, confirmed_at, created_at
      ) VALUES (?, ?, 1, 'confirmed', ?, ?, ?, ?, ?, ?, ?,
        'operator:system-fixture', ?, ?)
    `).run(
      seed.contractId,
      seed.missionId,
      CONTRACT_HASH,
      canonicalJson({
        fixtureOnly: true,
        exactTargets: [DISPOSABLE_COMPLETE_AUTONOMOUS_HOST],
        exactPorts: [DISPOSABLE_COMPLETE_AUTONOMOUS_PORT],
      }),
      canonicalJson({
        fixtureOnly: true,
        allowed: ["bounded_exploit_validation"],
        arbitraryCommands: false,
        credentials: false,
      }),
      canonicalJson({ fixtureOnly: true, maximumActions: 1 }),
      canonicalJson({ fixtureOnly: true, stopOnUnexpectedResponse: true }),
      canonicalJson({
        fixtureOnly: true,
        required: ["independent_http_response_assertion"],
      }),
      canonicalJson(["confirmed_and_verified_reusable_knowledge"]),
      now,
      now,
    );
    database.prepare(`
      INSERT INTO runs (
        id, mission_id, journey, status, contract_id, progress,
        status_reason, budget_json, budget_usage_json, started_at, ended_at,
        created_at, updated_at, version, control_plane,
        contract_version_bound, contract_hash_bound
      ) VALUES (?, ?, 'autonomous', 'completed', ?, 1,
        'Prior fixture-only source review completed without granting current mission authority.',
        ?, ?, ?, ?, ?, ?, 1, 'ti_scale', 1, ?)
    `).run(
      seed.runId,
      seed.missionId,
      seed.contractId,
      canonicalJson({ fixtureOnly: true }),
      canonicalJson({ fixtureOnly: true, actions: 0 }),
      now,
      now,
      now,
      now,
      CONTRACT_HASH,
    );
    database.prepare(`
      INSERT INTO topology_nodes (
        id, mission_id, run_id, node_type, primary_label,
        normalized_identity, scope_status, lifecycle_state, properties_json,
        confidence, verification_state, sensitivity,
        first_seen_at, last_seen_at, created_at, updated_at
      ) VALUES
        (?, ?, ?, 'asset', 'Disposable complete Autonomous target',
          ?, 'allowed', 'validated', ?, 1, 'verified', 'internal',
          ?, ?, ?, ?),
        (?, ?, ?, 'service', 'Apache HTTP fixture service 2.4.49',
          ?, 'allowed', 'validated', ?, 1, 'verified', 'internal',
          ?, ?, ?, ?)
    `).run(
      seed.assetId,
      seed.missionId,
      seed.runId,
      DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
      canonicalJson({
        fixtureOnly: true,
        exactTarget: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
      }),
      now,
      now,
      now,
      now,
      seed.serviceId,
      seed.missionId,
      seed.runId,
      `${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}:${DISPOSABLE_COMPLETE_AUTONOMOUS_PORT}/tcp`,
      canonicalJson({
        fixtureOnly: true,
        exactTarget: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
        port: DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
        transport: "tcp",
        product: DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
        version: DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
      }),
      now,
      now,
      now,
      now,
    );
    database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, source, acquired_at, target, evidence_type,
        content_hash, provenance_json, confidence, sensitivity,
        verification_state, summary, extracted_text, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'service_version_fingerprint', ?, ?,
        1, 'internal', 'verified',
        'Exact fixture service version was actively verified.',
        ?, 'operator:system-fixture', ?)
    `).run(
      seed.evidenceId,
      seed.missionId,
      seed.runId,
      `fixture-http://${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}:${DISPOSABLE_COMPLETE_AUTONOMOUS_PORT}/version`,
      now,
      DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
      VERSION_EVIDENCE_HASH,
      canonicalJson({
        method: "actively_verified",
        fixtureOnly: true,
        verificationEndpoint:
          `http://${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}:${DISPOSABLE_COMPLETE_AUTONOMOUS_PORT}/version`,
      }),
      `${DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT} ${DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION}`,
      now,
    );
    database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'verified', 'operator:system-fixture', ?, ?)
    `).run(
      seed.evidenceCustodyId,
      seed.evidenceId,
      canonicalJson({
        fixtureOnly: true,
        exactEvidenceSha256: VERSION_EVIDENCE_HASH,
      }),
      now,
    );
    database.prepare(`
      INSERT INTO topology_evidence_links (
        subject_type, subject_id, evidence_id, relationship, created_at
      ) VALUES ('node', ?, ?, 'supports', ?)
    `).run(seed.assetId, seed.evidenceId, now);
    database.prepare(`
      INSERT INTO cve_applicability_records (
        id, mission_id, run_id, asset_node_id, service_node_id, cve_id,
        title, description, component, detected_version, affected_range,
        cpe_or_package_json, applicability, confidence, reasoning_summary,
        cvss_json, cwe_json, source_links_json, source_retrieved_at,
        source_version, version_evidence_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?,
        '[DISPOSABLE FIXTURE ONLY] CVE-2021-41773 applicability',
        'Disposable fixture applicability is pinned to one actively verified local Apache HTTP Server 2.4.49 service and must not be generalized to an external target.',
        ?, ?, '2.4.49', ?, 'confirmed', 0.99,
        'Exact actively verified product/version evidence and the official NVD record establish this fixture candidate.',
        ?, ?, ?, ?, 'nvd-reviewed-fixture-v1', ?, ?, ?)
    `).run(
      seed.cveApplicabilityId,
      seed.missionId,
      seed.runId,
      seed.assetId,
      seed.serviceId,
      DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
      DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
      DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
      canonicalJson({
        fixtureOnly: true,
        cpe: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
      }),
      canonicalJson({ fixtureOnly: true }),
      canonicalJson(["CWE-22"]),
      canonicalJson([{
        kind: "nvd",
        url:
          `https://nvd.nist.gov/vuln/detail/${DISPOSABLE_COMPLETE_AUTONOMOUS_CVE}`,
        label: DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
      }]),
      now,
      seed.evidenceId,
      now,
      now,
    );
    database.prepare(`
      INSERT INTO artifacts (
        id, mission_id, run_id, journey, artifact_type, storage_uri,
        content_hash, byte_size, media_type, sensitivity, metadata_json,
        created_at
      ) VALUES (?, ?, ?, 'autonomous', 'script_test_result', ?, ?, ?,
        'text/plain', 'internal', ?, ?)
    `).run(
      seed.testArtifactId,
      seed.missionId,
      seed.runId,
      "fixture://complete-autonomous/reviewed-exploit-source-tests-v1",
      sha256(testMaterial),
      Buffer.byteLength(testMaterial, "utf8"),
      canonicalJson({
        fixtureOnly: true,
        exactArgv: ["--target"],
        exactTarget: DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
        arbitraryCommand: false,
      }),
      now,
    );
  });
  assertSeedIdentity(database);
  return "created";
}

function ensureScript(
  input: CompleteAutonomousCandidateActivationFixtureInput,
  clock: () => Date,
): {
  readonly script: ScriptArtifactDetail;
  readonly scripts: ScriptArtifactService;
} {
  const root = resolveV2ScriptSourceRoot(
    input.databasePath,
    input.scriptSourceRoot,
  );
  const sourceHash = sha256(EXPLOIT_SOURCE);
  const shard = join(root, sourceHash.slice(0, 2));
  const stored = join(shard, sourceHash);
  const rootExisted = existsSync(root);
  const shardExisted = existsSync(shard);
  const storedExisted = existsSync(stored);
  const store = new FileScriptSourceStore(root);
  const scripts = new ScriptArtifactService(input.database, store, clock);
  const seed = COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE;
  const latest = scripts.repository.latest(seed.missionId, seed.scriptName);
  const script = latest
    ? scripts.get(latest.id)
    : scripts.create({
      missionId: seed.missionId,
      runId: seed.runId,
      targetNodeId: seed.assetId,
      name: seed.scriptName,
      language: "python",
      source: EXPLOIT_SOURCE,
      laymanExplanation:
        "Makes one fixed read-only request to the disposable loopback fixture and checks its fixed impact marker.",
      technicalPurpose:
        "Validate the exact Apache HTTP Server 2.4.49/CVE-2021-41773 fixture candidate; process output is never outcome evidence.",
      inputs: [{
        name: "target",
        description:
          "The confinement broker supplies the one exact reviewed target as --target.",
        required: true,
        sensitivity: "ordinary",
      }],
      expectedOutputs: [{
        label: "Non-authoritative process receipt",
        description:
          "Bounded JSON confirms only that the reviewed source matched the fixture response.",
        successRecognition:
          "The process exits zero after matching the exact fixture marker.",
        failureRecognition:
          "Any target, status, size, JSON, or marker mismatch exits nonzero.",
      }],
      prerequisites: [
        `Exact ${DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT} ${DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION} evidence is verified.`,
        `${DISPOSABLE_COMPLETE_AUTONOMOUS_CVE} applicability remains confirmed.`,
      ],
      dependencies: ["Python 3.13 standard library"],
      touches: {
        files: [],
        network: [
          `${DISPOSABLE_COMPLETE_AUTONOMOUS_HOST}:${DISPOSABLE_COMPLETE_AUTONOMOUS_PORT}${DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH}`,
        ],
        services: [],
      },
      sideEffects: [
        "One fixture-only request arms the fixed read-only impact marker for independent observation.",
      ],
      riskClass: "medium",
      reversibility:
        "The disposable target owns all transient marker/session state and is destroyed after proof.",
      cleanupNotes:
        "The exploit source creates no file, process, account, or credential state.",
      secretsHandling:
        "No credential, secret reference, environment value, or arbitrary runtime parameter is accepted.",
      evidenceExpectations: [
        "A separate active HTTP observer must repeat the exact impact request without the fixture trigger header.",
        "Only the independent observer result may establish exploit success.",
      ],
      validation: {
        state: "approved",
        summary:
          "Operator review confirmed the immutable --target-only source, fixed host/port/path/header, response bounds, and absence of command or credential surfaces.",
        tests: [{
          name: "closed exact-target source boundary",
          status: "passed",
          summary:
            "Only one --target value equal to 127.0.0.2 is accepted; all network semantics are source constants.",
        }],
        testArtifactId: seed.testArtifactId,
      },
      provenance: {
        origin: "operator_authored",
        explanation:
          "Fixture-only source authored and reviewed for the complete Autonomous live-path proof.",
        sourceRefs: [seed.testArtifactId, seed.evidenceId],
      },
      sensitivity: "internal",
    }, { id: "operator:system-fixture", type: "operator" });
  if (
    script.missionId !== seed.missionId
    || script.runId !== seed.runId
    || script.targetNodeId !== seed.assetId
    || script.name !== seed.scriptName
    || script.language !== "python"
    || script.source !== EXPLOIT_SOURCE
    || script.contentHash !== sourceHash
    || script.validation.state !== "approved"
    || script.validation.testArtifactId !== seed.testArtifactId
  ) {
    throw new Error(
      "Existing complete Autonomous exploit ScriptArtifact differs from the exact approved source",
    );
  }
  if (input.serviceUid !== undefined) {
    for (const [path, existed, mode] of [
      [root, rootExisted, 0o700],
      [shard, shardExisted, 0o700],
      [stored, storedExisted, 0o600],
    ] as const) {
      const metadata = lstatSync(path);
      if (
        !existed
        && (
          metadata.uid !== input.serviceUid
          || metadata.gid !== input.serviceGid
        )
      ) {
        chownSync(path, input.serviceUid, input.serviceGid);
      }
      chmodSync(path, mode);
      const current = lstatSync(path);
      if (
        current.uid !== input.serviceUid
        || current.gid !== input.serviceGid
        || (current.mode & 0o777) !== mode
      ) {
        throw new Error(
          "Canonical exploit source storage is not readable by the configured Ti-Scale service identity",
        );
      }
    }
  }
  return Object.freeze({ script, scripts });
}

function onboard(
  input: CompleteAutonomousCandidateActivationFixtureInput,
  scripts: ScriptArtifactService,
  script: ScriptArtifactDetail,
  vaultConnectionId: string,
  clock: () => Date,
): {
  readonly service: ReusableExploitProcedureOnboardingService;
  readonly result: ReusableExploitProcedureOnboardingResult;
} {
  const seed = COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE;
  const service = new ReusableExploitProcedureOnboardingService({
    database: input.database,
    scripts,
    clock,
  });
  const result = service.onboard(
    seed.missionId,
    script.id,
    {
      schemaVersion:
        REUSABLE_EXPLOIT_PROCEDURE_ONBOARDING_SCHEMA_VERSION,
      scriptContentHash: script.contentHash,
      cveApplicabilityId: seed.cveApplicabilityId,
      expectedCveUpdatedAt: seed.reviewedAt,
      cveId: DISPOSABLE_COMPLETE_AUTONOMOUS_CVE,
      product: DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT,
      exactVersion: DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION,
      versionEvidenceId: seed.evidenceId,
      versionEvidenceHash: VERSION_EVIDENCE_HASH,
      procedure: {
        name: "Reviewed Apache 2.4.49 fixture path-normalization validation",
        version: "1.0.0",
        summary:
          "Runs one immutable fixture-only validation and delegates success authority to an independent fixed HTTP observer.",
        orderedSteps: [
          "Accept exactly one confinement-broker --target value.",
          "Require the exact confinement-broker reviewed fixture target.",
          "Request the fixed reviewed impact path with the fixed fixture trigger marker.",
          "Treat process completion as non-authoritative.",
          "Independently repeat the fixed impact GET without any trigger or action header.",
        ],
        prerequisites: [
          `Verified ${DISPOSABLE_COMPLETE_AUTONOMOUS_PRODUCT} ${DISPOSABLE_COMPLETE_AUTONOMOUS_VERSION} evidence.`,
          `Confirmed ${DISPOSABLE_COMPLETE_AUTONOMOUS_CVE} applicability.`,
        ],
        expectedOutcome:
          `The independent HTTP observer receives status 200 and ${DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER}.`,
      },
      observer: {
        type: "http_response_assertion",
        request: {
          scheme: "http",
          port: DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
          method: "GET",
          path: DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_PATH,
          timeoutMs: 2_000,
          maxResponseBytes: 16_384,
          tlsVerification: "strict",
        },
        assertion: {
          statusCodes: [200],
          bodyContains: [
            DISPOSABLE_COMPLETE_AUTONOMOUS_IMPACT_MARKER,
            "\"observationRole\":\"independent_outcome_observation\"",
          ],
          headerEquals: {},
          match: "all",
        },
      },
      vaultConnectionId,
      reason:
        "Publish the exact fixture-only approved source, evidence, CVE, procedure, and independent observer as confirmed reusable attack knowledge.",
      acknowledgeNoExecutionOrMissionAuthority: true,
    },
    { id: "operator:system-fixture", type: "operator" },
  );
  return Object.freeze({ service, result });
}

const FIXTURE_NOTE_TITLE_PREFIX = "[DISPOSABLE FIXTURE ONLY] " as const;
const FIXTURE_NOTE_SUMMARY_PREFIX =
  "Disposable exact-target proof record; excluded from general HTB, external-target, Autonomous, and Guided reuse. " as const;

/**
 * The generic reusable-procedure onboarding service creates a six-node graph.
 * This fixture must never let those otherwise valid records look like broadly
 * reusable attack knowledge. Keep the immutable graph/provenance IDs, but make
 * every human-visible note explicit and disable both journey retrieval paths.
 */
function markFixtureGraph(
  input: CompleteAutonomousCandidateActivationFixtureInput,
  onboarding: ReusableExploitProcedureOnboardingResult,
  clock: () => Date,
): void {
  const memory = new MemoryRepository(input.database, { clock });
  for (const nodeId of onboarding.graph.nodeIds) {
    const node = memory.getNode(nodeId, true);
    if (!node) {
      throw new Error(`Fixture Brain node is missing: ${nodeId}`);
    }
    const alreadyMarked =
      node.retentionPolicy.fixtureOnly === true
      && node.retentionPolicy.capabilityScope
        === "exact_disposable_fixture_only"
      && node.retentionPolicy.generalExternalTargetSupport === false
      && node.retentionPolicy.allowAutonomous === false
      && node.retentionPolicy.allowGuided === false;
    if (alreadyMarked) {
      const body = JSON.parse(node.body) as Record<string, unknown>;
      if (
        !node.title.startsWith(FIXTURE_NOTE_TITLE_PREFIX)
        || !node.summary.startsWith(FIXTURE_NOTE_SUMMARY_PREFIX)
        || body.fixtureOnly !== true
        || body.capabilityScope !== "exact_disposable_fixture_only"
        || body.generalExternalTargetSupport !== false
        || !node.provenance.sources.some(
          ({ sourceType, sourceId }) =>
            sourceType === "fixture_seed"
            && sourceId === COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_BUNDLE_VERSION,
        )
      ) {
        throw new Error(
          `Fixture Brain node has a partial or misleading truth label: ${nodeId}`,
        );
      }
      continue;
    }
    if (
      node.title.startsWith(FIXTURE_NOTE_TITLE_PREFIX)
      || node.summary.startsWith(FIXTURE_NOTE_SUMMARY_PREFIX)
      || node.retentionPolicy.fixtureOnly !== undefined
      || node.retentionPolicy.generalExternalTargetSupport !== undefined
    ) {
      throw new Error(
        `Fixture Brain node has a partial or conflicting truth label: ${nodeId}`,
      );
    }
    const sourceRecord = JSON.parse(node.body) as unknown;
    memory.correctNode(node.id, {
      title: `${FIXTURE_NOTE_TITLE_PREFIX}${node.title}`,
      summary: `${FIXTURE_NOTE_SUMMARY_PREFIX}${node.summary}`,
      body: canonicalJson({
        fixtureOnly: true,
        capabilityScope: "exact_disposable_fixture_only",
        generalExternalTargetSupport: false,
        sourceRecord,
      }),
      retentionPolicy: {
        ...node.retentionPolicy,
        allowAutonomous: false,
        allowGuided: false,
        fixtureOnly: true,
        capabilityScope: "exact_disposable_fixture_only",
        generalExternalTargetSupport: false,
      },
      additionalProvenanceSources: [{
        sourceType: "fixture_seed",
        sourceId:
          COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_BUNDLE_VERSION,
        sourceHash: CONTRACT_HASH,
        acquiredAt:
          COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.reviewedAt,
      }],
      provenanceExplanation:
        "This operator-reviewed node was generated only by the disposable complete-Autonomous proof fixture. It is not evidence of general HTB or external-target capability and is excluded from mission retrieval.",
      authorType: "operator",
      authorId: "operator:system-fixture",
      changeReason:
        "Apply explicit disposable-fixture provenance and disable mission reuse",
    });
  }
}

function discoverVault(
  input: CompleteAutonomousCandidateActivationFixtureInput,
  paths: VaultPathPolicy,
): {
  readonly id: string;
  readonly path: string;
  readonly displayName: string;
} {
  const rows = input.database.prepare(`
    SELECT id, vault_path, display_name
    FROM vault_connections
    WHERE status = 'connected'
    ORDER BY id
  `).all() as Array<{
    readonly id: string;
    readonly vault_path: string;
    readonly display_name: string;
  }>;
  const expectedPath = input.expectedVaultPath
    ? paths.resolveExistingVault(input.expectedVaultPath)
    : undefined;
  const matches = rows.filter((row) => {
    if (
      input.expectedVaultConnectionId
      && row.id !== input.expectedVaultConnectionId
    ) return false;
    if (
      input.expectedVaultDisplayName
      && row.display_name !== input.expectedVaultDisplayName
    ) return false;
    try {
      const actual = paths.resolveExistingVault(row.vault_path);
      return expectedPath === undefined || actual === expectedPath;
    } catch {
      return false;
    }
  });
  if (matches.length !== 1) {
    throw new Error(
      "Exactly one existing connected Vault must match the reviewed fixture preparation boundary",
    );
  }
  const match = matches[0]!;
  return Object.freeze({
    id: match.id,
    path: paths.resolveExistingVault(match.vault_path),
    displayName: match.display_name,
  });
}

function projectExactVault(
  input: CompleteAutonomousCandidateActivationFixtureInput,
  vault: { readonly id: string; readonly path: string },
  service: ReusableExploitProcedureOnboardingService,
  onboarding: ReusableExploitProcedureOnboardingResult,
  paths: VaultPathPolicy,
  clock: () => Date,
): void {
  const memory = new MemoryRepository(input.database, { clock });
  const bridge = new ObsidianVaultBridge(
    input.database,
    memory,
    paths,
    { clock },
  );
  const connection = bridge.requireConnection(vault.id);
  if (connection.status !== "connected" || connection.vaultPath !== vault.path) {
    throw new Error("The chosen Vault connection changed before projection");
  }
  bridge.verifyExistingVaultPath(vault.path);
  const allowed = new Set(onboarding.graph.nodeIds);
  for (const nodeId of onboarding.graph.nodeIds) {
    const exported = bridge.exportNode(vault.id, nodeId, allowed);
    if (exported.status !== "synced") {
      throw new Error(
        `Vault projection for ${nodeId} did not finish synchronized`,
      );
    }
    if (input.serviceUid !== undefined) {
      const path = paths.resolveRelative(vault.path, exported.relativePath);
      const metadata = lstatSync(path);
      if (metadata.uid !== input.serviceUid || metadata.gid !== input.serviceGid) {
        chownSync(path, input.serviceUid, input.serviceGid);
      }
      chmodSync(path, 0o600);
    }
  }
  const projection = service.verifyVaultProjection(
    vault.id,
    onboarding.graph.nodeIds,
  );
  service.recordVaultProjection(
    onboarding,
    { id: "operator:system-fixture", type: "operator" },
    projection,
  );
  const reconciliation = new VaultProjectionReconciliationService(
    input.database,
    bridge,
    paths,
    { clock },
  ).reconcile(vault.id);
  if (reconciliation.status !== "complete") {
    throw new Error(
      `The exact chosen Vault requires reconciliation (${reconciliation.issueCount} issue(s))`,
    );
  }
  bridge.refreshConnectionHealthProof(
    vault.id,
    "operator:complete-autonomous-fixture-preparer",
  );
  if (!bridge.verifyConnection(vault.id).healthy) {
    throw new Error("The exact chosen Vault failed synchronized read-back");
  }
  const composition = readActiveVaultComposition(input.database, {
    now: clock(),
    resolveExistingVaultPath: (path) => paths.resolveExistingVault(path),
  });
  if (
    !composition.usableVaults.some(
      ({ connectionId }) => connectionId === vault.id,
    )
  ) {
    throw new Error(
      "The exact chosen Vault did not enter the health-verified active composition",
    );
  }
}

function assertSourceRoot(rootValue: string): string {
  if (!isAbsolute(rootValue)) {
    throw new TypeError("Activation source root must be absolute");
  }
  const root = resolve(rootValue);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const metadata = lstatSync(root);
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || realpathSync(root) !== root
    || (metadata.mode & 0o022) !== 0
  ) {
    throw new Error("Activation source root is not owner-controlled");
  }
  return root;
}

function ensureSourceFile(
  root: string,
  name: string,
  bytes: Buffer,
  mode: number,
): { readonly path: string; readonly sha256: string } {
  const path = resolve(root, name);
  if (!path.startsWith(`${root}${sep}`) || dirname(path) !== root) {
    throw new Error("Activation source path escaped its trust root");
  }
  const expectedSha256 = sha256(bytes);
  if (existsSync(path)) {
    const metadata = lstatSync(path);
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || (metadata.mode & 0o777) !== mode
      || sha256(readFileSync(path)) !== expectedSha256
    ) {
      throw new Error(
        `Existing activation source ${name} differs; no file was replaced`,
      );
    }
  } else {
    writeFileSync(path, bytes, { flag: "wx", mode });
    chmodSync(path, mode);
  }
  return Object.freeze({ path, sha256: expectedSha256 });
}

function assertExternalSourceFile(
  root: string,
  pathValue: string,
  expectedSha256: string,
): string {
  const path = resolve(pathValue);
  if (!path.startsWith(`${root}${sep}`)) {
    throw new Error("Reviewed executable source must remain inside its trust root");
  }
  const metadata = lstatSync(path);
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || (metadata.mode & 0o111) === 0
    || (metadata.mode & 0o022) !== 0
    || sha256(readFileSync(path)) !== assertSha256(expectedSha256, path)
  ) {
    throw new Error(`Reviewed executable source failed its hash/mode pin: ${path}`);
  }
  return path;
}

function activationSources(
  input: CompleteAutonomousCandidateActivationFixtureInput,
  script: ScriptArtifactDetail,
  onboarding: ReusableExploitProcedureOnboardingResult,
): {
  readonly profile: ReviewedRealCandidateLinuxProfile;
  readonly profileSha256: string;
  readonly source: CompleteAutonomousCandidateActivationSourceFiles;
} {
  const root = assertSourceRoot(input.activationSourceRoot);
  const adapterPath = assertExternalSourceFile(
    root,
    input.adapterPath,
    input.adapterSha256,
  );
  const brokerPath = assertExternalSourceFile(
    root,
    input.brokerPath,
    input.brokerSha256,
  );
  const registerPath = assertExternalSourceFile(
    root,
    input.registerPath,
    input.registerSha256,
  );
  const providerBytes = Buffer.from(
    renderCompleteAutonomousCandidateProcedureProvider({
      scriptArtifactId: script.id,
      exploitOutcomeObserverSpecId: onboarding.observerSpecId,
    }),
    "utf8",
  );
  const provider = ensureSourceFile(root, "procedure-provider.v1", providerBytes, 0o700);
  const postExploitSpecSha256 =
    candidateLinuxPostExploitSpecificationHash({
      exploitOutcomeObserverSpecId: onboarding.observerSpecId,
      scriptArtifactId: script.id,
      scriptContentHash: script.contentHash,
      transportType: "candidate_runtime_session_v1",
      transportBindingId: COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
      transportOrigin: null,
      expectedPrincipal: "fixtureuser",
      expectedUid: 1_000,
      declaredUserFlagPath: "/home/fixtureuser/user.txt",
    });
  const profileValue = {
    schemaVersion: REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
    profileId:
      COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.profileId,
    candidateClass: "reviewed_real_candidate_v1",
    // The reviewed-provider v1 schema uses this technical discriminator for
    // its typed adapter protocol. It is not a general capability claim. The
    // fixture receipt below is authoritative for product readiness and limits
    // this provider to one exact disposable target.
    realTargetSupport: true,
    targetScope: exactCandidateLinuxTargetScope(
      DISPOSABLE_COMPLETE_AUTONOMOUS_HOST,
      {
        transport: "tcp",
        port: DISPOSABLE_COMPLETE_AUTONOMOUS_PORT,
      },
    ),
    bindingId: COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
    postExploitSpec: {
      id: COMPLETE_AUTONOMOUS_SOURCE_POST_EXPLOIT_SPEC_ID,
      expectedSha256: postExploitSpecSha256,
      exploitOutcomeObserverSpecId: onboarding.observerSpecId,
      scriptArtifactId: script.id,
      expectedPrincipal: "fixtureuser",
      expectedUid: 1_000,
      declaredUserFlagPath: "/home/fixtureuser/user.txt",
      declaredRootFlagPath: "/root/root.txt",
    },
    adapter: {
      executablePath: COMPLETE_AUTONOMOUS_CANDIDATE_ADAPTER_PATH,
      executableSha256: input.adapterSha256,
      socketPath:
        "/run/ti-scale-candidate-linux-reviewed/adapter.sock",
      socketGid: input.serviceGid,
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
    },
    procedure: {
      executablePath: COMPLETE_AUTONOMOUS_CANDIDATE_PROCEDURE_PATH,
      executableSha256: provider.sha256,
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
    },
    boundary: BOUNDARY,
    operations: OPERATIONS,
  };
  const profile = parseReviewedRealCandidateLinuxProfile(profileValue);
  const profileBytes = Buffer.from(
    `${JSON.stringify(profile, null, 2)}\n`,
    "utf8",
  );
  const profileFile = ensureSourceFile(
    root,
    "profile.v1.json",
    profileBytes,
    0o600,
  );
  return Object.freeze({
    profile,
    profileSha256: profileFile.sha256,
    source: Object.freeze({
      trustRoot: root,
      profilePath: profileFile.path,
      adapterPath,
      adapterSha256: input.adapterSha256,
      procedurePath: provider.path,
      procedureSha256: provider.sha256,
      brokerPath,
      brokerSha256: input.brokerSha256,
      registerPath,
      registerSha256: input.registerSha256,
    }),
  });
}

function installerArguments(
  operation: "source-verify" | "install",
  input: CompleteAutonomousCandidateActivationFixtureInput,
  profileSha256: string,
  source: CompleteAutonomousCandidateActivationSourceFiles,
): readonly string[] {
  return Object.freeze([
    operation,
    "--bundle-version",
    input.bundleVersion
      ?? COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_BUNDLE_VERSION,
    "--database-path",
    input.databasePath,
    "--service-gid",
    String(input.serviceGid),
    "--source-trust-root",
    source.trustRoot,
    "--profile-path",
    source.profilePath,
    "--profile-sha256",
    profileSha256,
    "--adapter-path",
    source.adapterPath,
    "--adapter-sha256",
    source.adapterSha256,
    "--procedure-path",
    source.procedurePath,
    "--procedure-sha256",
    source.procedureSha256,
    "--broker-path",
    source.brokerPath,
    "--broker-sha256",
    source.brokerSha256,
    "--register-path",
    source.registerPath,
    "--register-sha256",
    source.registerSha256,
    ...(operation === "install" ? ["--execute"] : []),
  ]);
}

/**
 * Explicit fixture-only preparation. It seeds reviewed historical authority,
 * writes immutable source inputs, and performs a real targeted Vault
 * projection. It never installs files, registers the candidate specification,
 * starts/reloads services, deploys, restarts Ti-Scale, or creates a backup.
 */
export function prepareCompleteAutonomousCandidateActivationFixture(
  input: CompleteAutonomousCandidateActivationFixtureInput,
): CompleteAutonomousCandidateActivationFixtureReceipt {
  if (
    !isAbsolute(input.databasePath)
    || !isAbsolute(input.vaultSandboxRoot)
    || !Number.isSafeInteger(input.serviceGid)
    || input.serviceGid < 1
    || (
      input.serviceUid !== undefined
      && (!Number.isSafeInteger(input.serviceUid) || input.serviceUid < 0)
    )
  ) {
    throw new TypeError("Fixture database, Vault, or service identity is invalid");
  }
  assertSchema63(input.database);
  const clock = input.now ?? (() => new Date());
  seedCanonicalPriorReview(input.database);
  const paths = new VaultPathPolicy(input.vaultSandboxRoot);
  const vault = discoverVault(input, paths);
  const { script, scripts } = ensureScript(input, clock);
  const { service, result: onboarding } = onboard(
    input,
    scripts,
    script,
    vault.id,
    clock,
  );
  markFixtureGraph(input, onboarding, clock);
  projectExactVault(
    input,
    vault,
    service,
    onboarding,
    paths,
    clock,
  );
  const activation = activationSources(input, script, onboarding);
  const sourceVerifyArguments = installerArguments(
    "source-verify",
    input,
    activation.profileSha256,
    activation.source,
  );
  const installArguments = installerArguments(
    "install",
    input,
    activation.profileSha256,
    activation.source,
  );
  const bundleVersion = input.bundleVersion
    ?? COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_BUNDLE_VERSION;
  const preparedActivation =
    prepareReviewedRealCandidateLinuxActivation({
      bundleVersion,
      database: input.database,
      databasePath: input.databasePath,
      serviceGid: input.serviceGid,
      source: {
        trustRoot: activation.source.trustRoot,
        profilePath: activation.source.profilePath,
        profileSha256: activation.profileSha256,
        adapterExecutablePath: activation.source.adapterPath,
        adapterExecutableSha256: activation.source.adapterSha256,
        procedureExecutablePath: activation.source.procedurePath,
        procedureExecutableSha256: activation.source.procedureSha256,
        brokerExecutablePath: activation.source.brokerPath,
        brokerExecutableSha256: activation.source.brokerSha256,
        registerExecutablePath: activation.source.registerPath,
        registerExecutableSha256: activation.source.registerSha256,
      },
    });
  if (
    preparedActivation.receipt.backupCreated !== false
    || preparedActivation.receipt.databaseMutated !== false
    || preparedActivation.receipt.systemdReloaded !== false
    || preparedActivation.receipt.servicesStarted !== false
    || preparedActivation.receipt.sourceAuthority.missionId
      !== COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.missionId
    || preparedActivation.receipt.sourceAuthority.runId
      !== COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.runId
    || preparedActivation.receipt.sourceAuthority.contractHash
      !== CONTRACT_HASH
  ) {
    throw new Error(
      "Existing activation installer preparation did not preserve the fixture's exact no-mutation source authority",
    );
  }
  return Object.freeze({
    schemaVersion:
      "ti-scale.complete-autonomous-candidate-activation-fixture.v1",
    status: "prepared",
    fixtureOnly: true,
    noBackupCreated: true,
    deploymentPerformed: false,
    serviceRestarted: false,
    databaseSchemaVersion: 63,
    capabilityScope: "exact_disposable_fixture_only",
    supportedTarget: COMPLETE_AUTONOMOUS_CANDIDATE_SUPPORTED_TARGET,
    generalExternalTargetSupport:
      COMPLETE_AUTONOMOUS_CANDIDATE_GENERAL_EXTERNAL_TARGET_SUPPORT,
    generalMissionReadinessEligible: false,
    targetScopedReadinessRequired: true,
    missionId:
      COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.missionId,
    runId: COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.runId,
    contractId:
      COMPLETE_AUTONOMOUS_CANDIDATE_ACTIVATION_FIXTURE.contractId,
    contractHash: CONTRACT_HASH,
    scriptArtifactId: script.id,
    scriptContentSha256: script.contentHash,
    observerSpecId: onboarding.observerSpecId,
    observerSpecSha256: onboarding.observerSpecHash,
    onboardingId: onboarding.onboardingId,
    onboardingSha256: onboarding.onboardingHash,
    brainNodeIds: Object.freeze([...onboarding.graph.nodeIds]),
    vaultConnectionId: vault.id,
    vaultPath: vault.path,
    vaultProjectionStatus: "complete",
    postExploitSpecId:
      activation.profile.postExploitSpec.id,
    postExploitSpecSha256:
      activation.profile.postExploitSpec.expectedSha256,
    bindingId: COMPLETE_AUTONOMOUS_CANDIDATE_BINDING_ID,
    profileSha256: activation.profileSha256,
    manifestSha256: preparedActivation.manifestSha256,
    source: activation.source,
    installer: Object.freeze({
      executable:
        "/root/ti-scale/scripts/install-reviewed-real-candidate-linux-activation.ts",
      sourceVerifyArguments,
      installArguments,
    }),
    registration: Object.freeze({
      executable:
        "/usr/local/libexec/ti-scale/reviewed-real-candidate-linux-register",
      environment: Object.freeze({
        TI_SCALE_CANDIDATE_LINUX_TRUST_ROOT:
          "/etc/ti-scale/candidate-linux-reviewed",
        TI_SCALE_CANDIDATE_LINUX_MANIFEST_PATH:
          "/etc/ti-scale/candidate-linux-reviewed/manifest.v1.json",
        TI_SCALE_CANDIDATE_LINUX_MANIFEST_SHA256:
          preparedActivation.manifestSha256,
        TI_SCALE_DATABASE_PATH: input.databasePath,
      }),
      arguments: Object.freeze([]) as readonly [],
    }),
  });
}

export {
  CONTRACT_HASH as COMPLETE_AUTONOMOUS_CANDIDATE_CONTRACT_SHA256,
  EXPLOIT_SOURCE as COMPLETE_AUTONOMOUS_CANDIDATE_EXPLOIT_SOURCE,
  VERSION_EVIDENCE_HASH as COMPLETE_AUTONOMOUS_CANDIDATE_VERSION_EVIDENCE_SHA256,
};

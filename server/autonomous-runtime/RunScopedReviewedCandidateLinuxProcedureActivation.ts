import { createHash } from "node:crypto";
import { lstatSync } from "node:fs";
import { isIP } from "node:net";
import {
  isAbsolute,
  resolve,
} from "node:path";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import { digestCanonicalJson } from "../mcp";
import type { LoadedTrustedJson } from "../trusted-runtime-config";
import {
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS,
  AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE,
} from "./AutonomousExploitValidationEligibility";
import {
  CandidateLinuxPostExploitSpecRegistry,
  candidateLinuxPostExploitSpecificationHash,
} from "./CandidateLinuxPostExploitSpecRegistry";
import type {
  CandidateLinuxTransportRequest,
} from "./CandidateLinuxTransportBindingRegistry";
import {
  HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider,
  ProcedureBackedReviewedRealCandidateLinuxAdapterImplementation,
  type ReviewedRealCandidateLinuxProcedureAttestation,
  type ReviewedRealCandidateLinuxProcedureConformance,
} from "./ReviewedRealCandidateLinuxProcedureAdapter";
import type {
  ReviewedRealCandidateLinuxAdapterImplementation,
  ReviewedRealCandidateLinuxProfile,
} from "./ReviewedRealCandidateLinuxTransport";
import type {
  AutonomousPostReconCandidateProcedureAdmissionPort,
  AutonomousPostReconCandidateProcedureActivationPort,
} from "./AutonomousPostReconExploitExpansion";
import {
  candidateLinuxTargetScopeMatches,
  candidateLinuxTargetScopesEqual,
  parseCandidateLinuxTargetScope,
  type CandidateLinuxTargetScope,
} from "./CandidateLinuxTargetScope";

export const RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ACTIVATION_SCHEMA_VERSION =
  "ti-scale.run-scoped-reviewed-candidate-linux-procedure-activation.v1" as const;
export const RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ATTESTATION_SCHEMA_VERSION =
  "ti-scale.run-scoped-reviewed-candidate-linux-procedure-attestation.v1" as const;
export const RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_BRIDGE_READINESS_SCHEMA_VERSION =
  "ti-scale.run-scoped-reviewed-candidate-linux-bridge-readiness.v1" as const;
export const RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ADMISSION_SCHEMA_VERSION =
  "ti-scale.run-scoped-reviewed-candidate-linux-procedure-admission.v1" as const;

const SHA256 = /^[a-f0-9]{64}$/u;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/u;
const CONTROL = /[\u0000-\u001F\u007F]/u;
const COMPOSITION_TTL_MS = 5 * 60_000;

export interface RunScopedReviewedCandidateLinuxProcedureActivationInput {
  readonly missionId: string;
  readonly runId: string;
  readonly planId: string;
  readonly stepId: string;
  readonly attackAttemptId: string;
  readonly targetNodeId: string;
  readonly exactTarget: string;
  readonly scriptArtifactId: string;
  readonly postExploitSpecId: string;
  readonly representedActionBindingHash: string;
  readonly procedureAdmissionId: string;
  readonly procedureExecutablePath: string;
  readonly procedureExecutableSha256: string;
  readonly idempotencyKey: string;
  readonly actor: Readonly<{
    readonly id: string;
    readonly type: "operator" | "agent" | "worker" | "system";
  }>;
}

export interface RunScopedReviewedCandidateLinuxProcedureActivation {
  readonly schemaVersion:
    typeof RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ACTIVATION_SCHEMA_VERSION;
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly planId: string;
  readonly stepId: string;
  readonly attackAttemptId: string;
  readonly targetNodeId: string;
  readonly exactTarget: string;
  readonly targetScope: CandidateLinuxTargetScope;
  readonly sourcePostExploitSpecId: string;
  readonly postExploitSpecId: string;
  readonly scriptArtifactId: string;
  readonly scriptContentHash: string;
  readonly exploitOutcomeObserverSpecId: string;
  readonly exploitOutcomeObserverSpecHash: string;
  readonly scriptValidationArtifactId: string;
  readonly scriptValidationArtifactHash: string;
  readonly representedActionBindingHash: string;
  readonly procedureAdmissionId: string;
  readonly profileId: string;
  readonly profileSha256: string;
  readonly transportBindingId: string;
  readonly procedureExecutablePath: string;
  readonly procedureExecutableSha256: string;
  readonly status: "active" | "revoked";
  readonly activatedBy: string;
  readonly activatedAt: string;
  readonly activationReceiptHash: string;
}

export interface RunScopedReviewedCandidateLinuxProcedureActivationResult {
  readonly activation: RunScopedReviewedCandidateLinuxProcedureActivation;
  readonly providerAttestation:
    ReviewedRealCandidateLinuxProcedureAttestation;
  readonly runScopedAttestationHash: string;
  readonly reused: boolean;
}

export interface RunScopedReviewedCandidateLinuxBridgeReadiness {
  readonly schemaVersion:
    typeof RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_BRIDGE_READINESS_SCHEMA_VERSION;
  readonly status: "ready" | "blocked";
  readonly code:
    | "run_scoped_candidate_bridge_ready"
    | "run_scoped_candidate_bridge_unattested";
  readonly reason: string;
  readonly conditionalCapability: true;
  /**
   * Compatibility field: this now means that the distinct, profile-pinned
   * procedure provider is installed at launch. It does not grant dispatch.
   */
  readonly candidateProcedurePresentAtLaunch: true;
  readonly procedureProviderPresentAtLaunch: true;
  readonly runScopedProcedureActivationPresentAtLaunch: false;
  readonly grantsRunDispatch: false;
  readonly profileSha256: string;
  readonly transportBindingId: string;
  readonly targetScope: CandidateLinuxTargetScope;
  readonly observedAt: string | null;
  readonly expiresAt: string | null;
}

export interface RunScopedReviewedCandidateLinuxExecutionReadiness {
  readonly status: "ready" | "blocked";
  readonly code:
    | "run_scoped_candidate_procedure_ready"
    | "run_scoped_candidate_procedure_missing"
    | "run_scoped_candidate_procedure_unattested";
  readonly reason: string;
  readonly runId: string;
  readonly postExploitSpecId: string;
  readonly activationId: string | null;
  readonly attestationExpiresAt: string | null;
  readonly targetScope: CandidateLinuxTargetScope;
}

interface ActivationRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly plan_id: string;
  readonly step_id: string;
  readonly attack_attempt_id: string;
  readonly target_node_id: string;
  readonly exact_target: string;
  readonly source_post_exploit_spec_id: string;
  readonly post_exploit_spec_id: string;
  readonly script_artifact_id: string;
  readonly script_content_hash: string;
  readonly exploit_outcome_observer_spec_id: string;
  readonly exploit_outcome_observer_spec_hash: string;
  readonly script_validation_artifact_id: string;
  readonly script_validation_artifact_hash: string;
  readonly represented_action_binding_hash: string;
  readonly procedure_admission_id: string | null;
  readonly profile_id: string;
  readonly profile_sha256: string;
  readonly transport_binding_id: string;
  readonly procedure_executable_path: string;
  readonly procedure_executable_sha256: string;
  readonly idempotency_key_hash: string;
  readonly status: "active" | "revoked";
  readonly activated_by: string;
  readonly activated_at: string;
  readonly activation_receipt_hash: string;
  readonly activation_receipt_json: string;
}

interface AdmissionRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly source_post_exploit_spec_id: string;
  readonly post_exploit_spec_id: string;
  readonly source_script_artifact_id: string;
  readonly script_artifact_id: string;
  readonly script_content_hash: string;
  readonly exploit_outcome_observer_spec_id: string;
  readonly exploit_outcome_observer_spec_hash: string;
  readonly profile_id: string;
  readonly profile_sha256: string;
  readonly transport_binding_id: string;
  readonly procedure_executable_path: string;
  readonly procedure_executable_sha256: string;
  readonly procedure_protocol_version: string;
  readonly provider_attestation_json: string;
  readonly provider_attestation_hash: string;
  readonly provider_conformance_json: string;
  readonly provider_conformance_hash: string;
  readonly admission_receipt_json: string;
  readonly admission_receipt_hash: string;
  readonly idempotency_key_hash: string;
  readonly status: "admitted" | "revoked";
  readonly admitted_by: string;
  readonly admitted_at: string;
}

export interface RunScopedReviewedCandidateLinuxProcedureAdmissionRecord {
  readonly schemaVersion:
    typeof RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ADMISSION_SCHEMA_VERSION;
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly sourcePostExploitSpecId: string;
  readonly postExploitSpecId: string;
  readonly sourceScriptArtifactId: string;
  readonly scriptArtifactId: string;
  readonly scriptContentHash: string;
  readonly exploitOutcomeObserverSpecId: string;
  readonly exploitOutcomeObserverSpecHash: string;
  readonly profileId: string;
  readonly profileSha256: string;
  readonly transportBindingId: string;
  readonly procedureExecutablePath: string;
  readonly procedureExecutableSha256: string;
  readonly procedureProtocolVersion: string;
  readonly providerAttestationHash: string;
  readonly providerConformanceHash: string;
  readonly admissionReceiptHash: string;
  readonly status: "admitted" | "revoked";
  readonly admittedBy: string;
  readonly admittedAt: string;
  readonly targetScope: CandidateLinuxTargetScope;
}

interface AuthorityRow {
  readonly mission_id: string;
  readonly run_id: string;
  readonly plan_id: string;
  readonly step_id: string;
  readonly target_node_id: string;
  readonly exact_target: string;
  readonly script_artifact_id: string;
  readonly script_content_hash: string;
  readonly script_name: string;
  readonly script_validation_state: string;
  readonly script_test_artifact_id: string | null;
  readonly validation_artifact_hash: string;
  readonly validation_artifact_type: string;
  readonly spec_id: string;
  readonly spec_hash: string;
  readonly spec_created_by: string;
  readonly spec_status: string;
  readonly spec_transport_type: string;
  readonly spec_transport_binding_id: string;
  readonly observer_id: string;
  readonly observer_hash: string;
  readonly observer_status: string;
  readonly observer_script_hash: string;
  readonly observer_cve_id: string;
  readonly observer_type: string;
  readonly observer_request_json: string;
  readonly observer_assertion_json: string;
  readonly source_spec_id: string;
  readonly source_spec_hash: string;
  readonly source_script_id: string;
  readonly source_script_hash: string;
  readonly source_observer_id: string;
  readonly source_observer_status: string;
  readonly source_observer_script_hash: string;
  readonly source_observer_cve_id: string;
  readonly source_observer_type: string;
  readonly source_observer_request_json: string;
  readonly source_observer_assertion_json: string;
  readonly source_expected_principal: string;
  readonly source_expected_uid: number;
  readonly source_declared_user_flag_path: string;
  readonly source_declared_root_flag_path: string;
  readonly expected_principal: string;
  readonly expected_uid: number;
  readonly declared_user_flag_path: string;
  readonly action_type: string;
  readonly action_class: string;
  readonly normalized_arguments_json: string;
  readonly scoped_target: string;
  readonly action_binding_hash: string;
  readonly prerequisites_json: string;
  readonly attempt_status: string;
}

function stableId(prefix: string, values: readonly string[]): string {
  return `${prefix}_${createHash("sha256")
    .update(values.join("\u0000"), "utf8")
    .digest("hex")
    .slice(0, 44)}`;
}

function digest(value: unknown): string {
  return digestCanonicalJson(
    value,
    { maxBytes: 256 * 1_024, maxDepth: 24 },
  ).sha256;
}

function id(value: string, label: string): string {
  if (!ID.test(value)) throw new TypeError(`${label} is invalid`);
  return value;
}

function hash(value: string, label: string): string {
  if (!SHA256.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256`);
  }
  return value;
}

function safeActor(
  actor: RunScopedReviewedCandidateLinuxProcedureActivationInput["actor"],
): RunScopedReviewedCandidateLinuxProcedureActivationInput["actor"] {
  if (
    !ID.test(actor.id)
    || !["operator", "agent", "worker", "system"].includes(actor.type)
  ) {
    throw new TypeError("Activation actor is invalid");
  }
  return actor;
}

function keyHash(value: string): string {
  if (
    value !== value.trim()
    || value.length < 8
    || value.length > 256
    || CONTROL.test(value)
  ) {
    throw new TypeError(
      "Procedure activation idempotency key must contain 8 through 256 safe characters",
    );
  }
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function parseObject(
  value: string,
  label: string,
): Readonly<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error();
    }
    return parsed as Readonly<Record<string, unknown>>;
  } catch {
    throw new Error(`${label} is not a canonical object`);
  }
}

function parseArray(value: string, label: string): readonly unknown[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) throw new Error();
    return parsed;
  } catch {
    throw new Error(`${label} is not a canonical array`);
  }
}

function activation(
  row: ActivationRow,
): RunScopedReviewedCandidateLinuxProcedureActivation {
  const targetScope = parseCandidateLinuxTargetScope(
    parseObject(row.activation_receipt_json, "Activation receipt").targetScope,
  );
  return Object.freeze({
    schemaVersion:
      RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ACTIVATION_SCHEMA_VERSION,
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    planId: row.plan_id,
    stepId: row.step_id,
    attackAttemptId: row.attack_attempt_id,
    targetNodeId: row.target_node_id,
    exactTarget: row.exact_target,
    targetScope,
    sourcePostExploitSpecId: row.source_post_exploit_spec_id,
    postExploitSpecId: row.post_exploit_spec_id,
    scriptArtifactId: row.script_artifact_id,
    scriptContentHash: row.script_content_hash,
    exploitOutcomeObserverSpecId:
      row.exploit_outcome_observer_spec_id,
    exploitOutcomeObserverSpecHash:
      row.exploit_outcome_observer_spec_hash,
    scriptValidationArtifactId: row.script_validation_artifact_id,
    scriptValidationArtifactHash: row.script_validation_artifact_hash,
    representedActionBindingHash: row.represented_action_binding_hash,
    procedureAdmissionId: row.procedure_admission_id!,
    profileId: row.profile_id,
    profileSha256: row.profile_sha256,
    transportBindingId: row.transport_binding_id,
    procedureExecutablePath: row.procedure_executable_path,
    procedureExecutableSha256: row.procedure_executable_sha256,
    status: row.status,
    activatedBy: row.activated_by,
    activatedAt: row.activated_at,
    activationReceiptHash: row.activation_receipt_hash,
  });
}

function admittedProcedure(
  row: AdmissionRow,
): RunScopedReviewedCandidateLinuxProcedureAdmissionRecord {
  const targetScope = parseCandidateLinuxTargetScope(
    parseObject(row.admission_receipt_json, "Admission receipt").targetScope,
  );
  return Object.freeze({
    schemaVersion:
      RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ADMISSION_SCHEMA_VERSION,
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    sourcePostExploitSpecId: row.source_post_exploit_spec_id,
    postExploitSpecId: row.post_exploit_spec_id,
    sourceScriptArtifactId: row.source_script_artifact_id,
    scriptArtifactId: row.script_artifact_id,
    scriptContentHash: row.script_content_hash,
    exploitOutcomeObserverSpecId:
      row.exploit_outcome_observer_spec_id,
    exploitOutcomeObserverSpecHash:
      row.exploit_outcome_observer_spec_hash,
    profileId: row.profile_id,
    profileSha256: row.profile_sha256,
    transportBindingId: row.transport_binding_id,
    procedureExecutablePath: row.procedure_executable_path,
    procedureExecutableSha256: row.procedure_executable_sha256,
    procedureProtocolVersion: row.procedure_protocol_version,
    providerAttestationHash: row.provider_attestation_hash,
    providerConformanceHash: row.provider_conformance_hash,
    admissionReceiptHash: row.admission_receipt_hash,
    status: row.status,
    admittedBy: row.admitted_by,
    admittedAt: row.admitted_at,
    targetScope,
  });
}

export class RunScopedReviewedCandidateLinuxProcedureActivationError
extends Error {
  constructor(
    readonly code:
      | "bridge_unavailable"
      | "activation_scope_invalid"
      | "activation_conflict"
      | "activation_missing"
      | "activation_stale",
    message: string,
  ) {
    super(message);
    this.name = "RunScopedReviewedCandidateLinuxProcedureActivationError";
  }
}

function reject(
  code: RunScopedReviewedCandidateLinuxProcedureActivationError["code"],
  message: string,
): never {
  throw new RunScopedReviewedCandidateLinuxProcedureActivationError(
    code,
    message,
  );
}

/**
 * Registers the typed transport contract only for the byte-identical
 * current-run materialization of the source candidate pinned by the profile.
 * An unrelated exploit ScriptArtifact cannot borrow this procedure provider.
 */
export class RunScopedReviewedCandidateLinuxSpecRegistrar {
  readonly #registry: CandidateLinuxPostExploitSpecRegistry;
  readonly #profile: ReviewedRealCandidateLinuxProfile;

  constructor(input: Readonly<{
    database: SqliteDatabase;
    loadedProfile: LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>;
    now?: () => Date;
  }>) {
    this.#profile = input.loadedProfile.value;
    this.#registry = new CandidateLinuxPostExploitSpecRegistry(
      input.database,
      input.now,
    );
    const source = this.#registry.getForScript(
      this.#profile.postExploitSpec.scriptArtifactId,
    );
    if (
      !source
      || source.id !== this.#profile.postExploitSpec.id
      || source.specHash !== this.#profile.postExploitSpec.expectedSha256
      || source.status !== "active"
      || source.transportType !== "candidate_runtime_session_v1"
      || source.transportBindingId !== this.#profile.bindingId
    ) {
      reject(
        "bridge_unavailable",
        "The reviewed source profile must be registered before a candidate-specific run specification can be derived",
      );
    }
  }

  register(input: Readonly<{
    missionId: string;
    runId: string;
    scriptArtifactId: string;
    exploitOutcomeObserverSpecId: string;
  }>) {
    id(input.missionId, "Mission ID");
    id(input.runId, "Run ID");
    id(input.scriptArtifactId, "ScriptArtifact ID");
    id(
      input.exploitOutcomeObserverSpecId,
      "Exploit outcome observer spec ID",
    );
    const record = this.#registry.clone(
      this.#profile.postExploitSpec.scriptArtifactId,
      input.scriptArtifactId,
      input.exploitOutcomeObserverSpecId,
      {
        missionId: input.missionId,
        runId: input.runId,
      },
    );
    if (!record) {
      reject(
        "activation_scope_invalid",
        "The exact profile-pinned source candidate has no typed specification to derive",
      );
    }
    return record;
  }
}

/**
 * Target-free pre-plan admission for the exact profile-pinned candidate.
 *
 * The provider executable is a separate immutable artifact pinned by the
 * reviewed profile. Admission first verifies its live attestation and all
 * eight closed result schemas without sending a target or invoke request.
 * Only after that succeeds may this service derive the current-run typed spec
 * and persist the immutable admission consumed by plan construction.
 */
export class RunScopedReviewedCandidateLinuxProcedureAdmission
implements AutonomousPostReconCandidateProcedureAdmissionPort {
  readonly #profile: ReviewedRealCandidateLinuxProfile;
  readonly #profileSha256: string;
  readonly #registrar: RunScopedReviewedCandidateLinuxSpecRegistrar;
  readonly #allowedOwnerUids: readonly number[];
  readonly #now: () => Date;
  readonly #events: EventRepository;
  readonly #audit: AuditTrailWriter;

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    loadedProfile: LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>;
    allowedProcedureOwnerUids?: readonly number[];
    now?: () => Date;
  }>) {
    this.#profile = options.loadedProfile.value;
    this.#profileSha256 = hash(
      options.loadedProfile.receipt.sourceSha256,
      "Profile SHA-256",
    );
    const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
    this.#allowedOwnerUids = Object.freeze([
      ...new Set(options.allowedProcedureOwnerUids ?? [0, currentUid]),
    ]);
    if (
      this.#allowedOwnerUids.length < 1
      || this.#allowedOwnerUids.length > 8
      || this.#allowedOwnerUids.some((uid) =>
        !Number.isSafeInteger(uid) || uid < 0)
    ) {
      throw new TypeError("Procedure admission owner allowlist is invalid");
    }
    this.#now = options.now ?? (() => new Date());
    this.#registrar = new RunScopedReviewedCandidateLinuxSpecRegistrar({
      database: options.database,
      loadedProfile: options.loadedProfile,
      now: this.#now,
    });
    this.#events = new EventRepository(options.database);
    this.#audit = new AuditTrailWriter(options.database);
  }

  async admit(
    input: Parameters<
      AutonomousPostReconCandidateProcedureAdmissionPort["admit"]
    >[0],
  ): Promise<Awaited<ReturnType<
    AutonomousPostReconCandidateProcedureAdmissionPort["admit"]
  >>> {
    if (
      input.materialization.sourceScriptArtifactId
        !== this.#profile.postExploitSpec.scriptArtifactId
    ) {
      return null;
    }
    if (input.signal.aborted) {
      reject(
        "activation_stale",
        "Candidate provider admission was cancelled before conformance",
      );
    }
    const materialized = this.#candidateAuthority({
      missionId: input.missionId,
      runId: input.runId,
      scriptArtifactId:
        input.materialization.materializedScriptArtifactId,
      scriptContentHash:
        input.materialization.materializedScriptContentHash,
      observerSpecId: input.materialization.outcomeObserverSpecId ?? "",
      observerSpecHash: input.materialization.outcomeObserverSpecHash ?? "",
    });
    const existing = this.#rowForScript(
      input.materialization.materializedScriptArtifactId,
    );
    if (existing) {
      this.#assertExistingAdmission(existing, materialized);
      return Object.freeze({
        admissionId: existing.id,
        postExploitSpecId: existing.post_exploit_spec_id,
        postExploitSpecHash: materialized.derivedSpecHash,
        conformanceReceiptHash: existing.provider_conformance_hash,
      });
    }

    const provider =
      new HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider({
        profile: this.#profile,
        profileSha256: this.#profileSha256,
        procedureExecutablePath:
          this.#profile.procedure.executablePath,
        procedureExecutableSha256:
          this.#profile.procedure.executableSha256,
        allowedOwnerUids: this.#allowedOwnerUids,
        timeoutMs: 15_000,
        maximumConcurrency: 1,
        now: this.#now,
      });
    const bounded = new AbortController();
    const cancel = () => bounded.abort(input.signal.reason);
    input.signal.addEventListener("abort", cancel, { once: true });
    const timer = setTimeout(() => {
      bounded.abort(
        new Error("Candidate provider admission exceeded 15 seconds"),
      );
    }, 15_000);
    let attestation: ReviewedRealCandidateLinuxProcedureAttestation;
    let conformance: ReviewedRealCandidateLinuxProcedureConformance;
    try {
      attestation = await provider.attest(bounded.signal);
      conformance = await provider.conform(bounded.signal);
    } finally {
      clearTimeout(timer);
      input.signal.removeEventListener("abort", cancel);
    }
    if (input.signal.aborted || bounded.signal.aborted) {
      reject(
        "activation_stale",
        "Candidate provider admission was cancelled before persistence",
      );
    }

    // This is deliberately the only current-run spec registrar on the
    // reviewed-provider path, and it runs only after target-free conformance.
    const spec = this.#registrar.register({
      missionId: input.missionId,
      runId: input.runId,
      scriptArtifactId:
        input.materialization.materializedScriptArtifactId,
      exploitOutcomeObserverSpecId: materialized.observerSpecId,
    });
    const admittedAt = this.#now().toISOString();
    const admissionId = stableId("candidate_procedure_admission", [
      input.runId,
      input.materialization.materializedScriptArtifactId,
      this.#profileSha256,
      this.#profile.procedure.executableSha256,
    ]);
    const idempotencyKeyHash = digest({
      runId: input.runId,
      scriptArtifactId:
        input.materialization.materializedScriptArtifactId,
      profileSha256: this.#profileSha256,
    });
    const admissionReceipt = Object.freeze({
      schemaVersion:
        RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ADMISSION_SCHEMA_VERSION,
      id: admissionId,
      missionId: input.missionId,
      runId: input.runId,
      sourcePostExploitSpecId: this.#profile.postExploitSpec.id,
      postExploitSpecId: spec.id,
      sourceScriptArtifactId:
        this.#profile.postExploitSpec.scriptArtifactId,
      scriptArtifactId:
        input.materialization.materializedScriptArtifactId,
      scriptContentHash:
        input.materialization.materializedScriptContentHash,
      exploitOutcomeObserverSpecId: materialized.observerSpecId,
      exploitOutcomeObserverSpecHash: materialized.observerSpecHash,
      profileId: this.#profile.profileId,
      profileSha256: this.#profileSha256,
      transportBindingId: this.#profile.bindingId,
      procedureExecutablePath:
        this.#profile.procedure.executablePath,
      procedureExecutableSha256:
        this.#profile.procedure.executableSha256,
      procedureProtocolVersion:
        this.#profile.procedure.protocolVersion,
      providerAttestationHash: attestation.receiptSha256,
      providerConformanceHash: conformance.receiptSha256,
      targetScope: this.#profile.targetScope,
      conformanceOperations: conformance.cases.map(
        ({ operation }) => operation,
      ),
      targetContact: false as const,
      invokeCalled: false as const,
      genericCommand: false as const,
      shell: false as const,
      argv: false as const,
      payload: false as const,
      admittedBy: "system:autonomous-post-recon-procedure-admission",
      admittedAt,
    });
    const admissionReceiptHash = digest(admissionReceipt);
    const row = inImmediateTransaction(this.options.database, () => {
      const prior = this.#rowForScript(
        input.materialization.materializedScriptArtifactId,
      );
      if (prior) {
        this.#assertExistingAdmission(prior, {
          ...materialized,
          derivedSpecId: spec.id,
          derivedSpecHash: spec.specHash,
        });
        return prior;
      }
      this.options.database.prepare(`
        INSERT INTO reviewed_candidate_linux_procedure_admissions (
          id, mission_id, run_id, source_post_exploit_spec_id,
          post_exploit_spec_id, source_script_artifact_id,
          script_artifact_id, script_content_hash,
          exploit_outcome_observer_spec_id,
          exploit_outcome_observer_spec_hash,
          profile_id, profile_sha256, transport_binding_id,
          procedure_executable_path, procedure_executable_sha256,
          procedure_protocol_version, provider_attestation_json,
          provider_attestation_hash, provider_conformance_json,
          provider_conformance_hash, admission_receipt_json,
          admission_receipt_hash, idempotency_key_hash, status,
          admitted_by, admitted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, 'admitted', ?, ?)
      `).run(
        admissionId,
        input.missionId,
        input.runId,
        this.#profile.postExploitSpec.id,
        spec.id,
        this.#profile.postExploitSpec.scriptArtifactId,
        input.materialization.materializedScriptArtifactId,
        input.materialization.materializedScriptContentHash,
        materialized.observerSpecId,
        materialized.observerSpecHash,
        this.#profile.profileId,
        this.#profileSha256,
        this.#profile.bindingId,
        this.#profile.procedure.executablePath,
        this.#profile.procedure.executableSha256,
        this.#profile.procedure.protocolVersion,
        JSON.stringify(attestation),
        attestation.receiptSha256,
        JSON.stringify(conformance),
        conformance.receiptSha256,
        JSON.stringify(admissionReceipt),
        admissionReceiptHash,
        idempotencyKeyHash,
        "system:autonomous-post-recon-procedure-admission",
        admittedAt,
      );
      const created = this.#rowForScript(
        input.materialization.materializedScriptArtifactId,
      );
      if (!created) {
        reject(
          "activation_stale",
          "Candidate provider admission was not durably created",
        );
      }
      this.#audit.append({
        missionId: input.missionId,
        runId: input.runId,
        actor: {
          id: "system:autonomous-post-recon-procedure-admission",
          type: "system",
        },
        action: "candidate_linux.procedure_admitted",
        resourceType: "reviewed_candidate_linux_procedure_admission",
        resourceId: created.id,
        reason:
          "Admitted a distinct profile-pinned provider only after target-free validation of all eight typed result schemas.",
        details: {
          scriptArtifactId: created.script_artifact_id,
          scriptContentHash: created.script_content_hash,
          procedureExecutableSha256:
            created.procedure_executable_sha256,
          providerConformanceHash:
            created.provider_conformance_hash,
          admissionReceiptHash: created.admission_receipt_hash,
          targetContact: false,
          grantsPlanAuthority: true,
          grantsDispatchAuthority: false,
        },
        occurredAt: admittedAt,
      });
      this.#events.append({
        missionId: input.missionId,
        runId: input.runId,
        eventType: "candidate_linux.procedure_admitted",
        actorType: "system",
        actorId: "system:autonomous-post-recon-procedure-admission",
        summary:
          "The exact candidate now has a distinct reviewed provider whose eight closed result schemas passed target-free conformance.",
        payload: {
          admissionId: created.id,
          scriptArtifactId: created.script_artifact_id,
          postExploitSpecId: created.post_exploit_spec_id,
          scriptContentHash: created.script_content_hash,
          procedureExecutableSha256:
            created.procedure_executable_sha256,
          providerConformanceHash:
            created.provider_conformance_hash,
          targetContact: false,
          grantsDispatchAuthority: false,
        },
        schemaVersion: 1,
        sensitivity: "internal",
        occurredAt: admittedAt,
        outboxTopic: "run.candidate-procedure-admissions",
      });
      return created;
    });
    return Object.freeze({
      admissionId: row.id,
      postExploitSpecId: row.post_exploit_spec_id,
      postExploitSpecHash: spec.specHash,
      conformanceReceiptHash: row.provider_conformance_hash,
    });
  }

  getForScript(
    scriptArtifactId: string,
  ): RunScopedReviewedCandidateLinuxProcedureAdmissionRecord | undefined {
    id(scriptArtifactId, "ScriptArtifact ID");
    const row = this.#rowForScript(scriptArtifactId);
    return row ? admittedProcedure(row) : undefined;
  }

  #providerAuthority(): void {
    if (
      this.#profile.procedure.protocolVersion
        !== "ti-scale.reviewed-real-candidate-linux-procedure.v1"
      || this.#profile.procedure.executableSha256
        === this.#candidateSourceHash()
    ) {
      reject(
        "bridge_unavailable",
        "The reviewed profile must pin a distinct closed procedure provider",
      );
    }
  }

  #candidateSourceHash(): string {
    const row = this.options.database.prepare(`
      SELECT content_hash FROM script_artifacts WHERE id = ?
    `).get(this.#profile.postExploitSpec.scriptArtifactId) as
      | { readonly content_hash: string }
      | undefined;
    if (!row || !SHA256.test(row.content_hash)) {
      reject(
        "bridge_unavailable",
        "The reviewed source ScriptArtifact is unavailable",
      );
    }
    return row.content_hash;
  }

  #candidateAuthority(input: Readonly<{
    missionId: string;
    runId: string;
    scriptArtifactId: string;
    scriptContentHash: string;
    observerSpecId: string;
    observerSpecHash: string;
  }>): Readonly<{
    observerSpecId: string;
    observerSpecHash: string;
    derivedSpecId: string;
    derivedSpecHash: string;
  }> {
    this.#providerAuthority();
    id(input.missionId, "Mission ID");
    id(input.runId, "Run ID");
    id(input.scriptArtifactId, "ScriptArtifact ID");
    id(input.observerSpecId, "Exploit observer spec ID");
    hash(input.scriptContentHash, "ScriptArtifact hash");
    hash(input.observerSpecHash, "Exploit observer spec hash");
    const row = this.options.database.prepare(`
      SELECT source_spec.id AS source_spec_id,
        source_spec.spec_hash AS source_spec_hash,
        source_script.content_hash AS source_script_hash,
        script.content_hash AS script_hash,
        script.validation_state,
        script.test_artifact_id,
        observer.id AS observer_id,
        observer.spec_hash AS observer_hash,
        observer.script_content_hash AS observer_script_hash,
        observer.status AS observer_status,
        derived.id AS derived_spec_id,
        derived.spec_hash AS derived_spec_hash
      FROM candidate_linux_post_exploit_specs AS source_spec
      JOIN script_artifacts AS source_script
        ON source_script.id = source_spec.script_artifact_id
      JOIN script_artifacts AS script
        ON script.id = ?
        AND script.mission_id = ?
        AND script.run_id = ?
      JOIN exploit_outcome_observer_specs AS observer
        ON observer.id = ?
        AND observer.script_artifact_id = script.id
      LEFT JOIN candidate_linux_post_exploit_specs AS derived
        ON derived.script_artifact_id = script.id
      WHERE source_spec.id = ?
      LIMIT 1
    `).get(
      input.scriptArtifactId,
      input.missionId,
      input.runId,
      input.observerSpecId,
      this.#profile.postExploitSpec.id,
    ) as Readonly<{
      source_spec_id: string;
      source_spec_hash: string;
      source_script_hash: string;
      script_hash: string;
      validation_state: string;
      test_artifact_id: string | null;
      observer_id: string;
      observer_hash: string;
      observer_script_hash: string;
      observer_status: string;
      derived_spec_id: string | null;
      derived_spec_hash: string | null;
    }> | undefined;
    const derivedSpecHash = row?.derived_spec_hash ?? "";
    if (
      !row
      || row.source_spec_id !== this.#profile.postExploitSpec.id
      || row.source_spec_hash
        !== this.#profile.postExploitSpec.expectedSha256
      || row.source_script_hash !== input.scriptContentHash
      || row.script_hash !== input.scriptContentHash
      || row.validation_state !== "approved"
      || !row.test_artifact_id
      || row.observer_id !== input.observerSpecId
      || row.observer_hash !== input.observerSpecHash
      || row.observer_script_hash !== input.scriptContentHash
      || row.observer_status !== "active"
      || (
        row.derived_spec_id !== null
        && !SHA256.test(derivedSpecHash)
      )
    ) {
      reject(
        "activation_scope_invalid",
        "Candidate admission requires the exact byte-identical profile source, current-run validation, and independent matching observer",
      );
    }
    return Object.freeze({
      observerSpecId: row.observer_id,
      observerSpecHash: row.observer_hash,
      derivedSpecId: row.derived_spec_id ?? "",
      derivedSpecHash,
    });
  }

  #rowForScript(scriptArtifactId: string): AdmissionRow | undefined {
    return this.options.database.prepare(`
      SELECT * FROM reviewed_candidate_linux_procedure_admissions
      WHERE script_artifact_id = ?
      LIMIT 1
    `).get(scriptArtifactId) as AdmissionRow | undefined;
  }

  #assertExistingAdmission(
    row: AdmissionRow,
    authority: Readonly<{
      observerSpecId: string;
      observerSpecHash: string;
      derivedSpecId: string;
      derivedSpecHash: string;
    }>,
  ): void {
    if (
      row.status !== "admitted"
      || row.source_post_exploit_spec_id
        !== this.#profile.postExploitSpec.id
      || row.source_script_artifact_id
        !== this.#profile.postExploitSpec.scriptArtifactId
      || row.exploit_outcome_observer_spec_id
        !== authority.observerSpecId
      || row.exploit_outcome_observer_spec_hash
        !== authority.observerSpecHash
      || (
        authority.derivedSpecId
        && row.post_exploit_spec_id !== authority.derivedSpecId
      )
      || row.profile_id !== this.#profile.profileId
      || row.profile_sha256 !== this.#profileSha256
      || row.transport_binding_id !== this.#profile.bindingId
      || row.procedure_executable_path
        !== this.#profile.procedure.executablePath
      || row.procedure_executable_sha256
        !== this.#profile.procedure.executableSha256
      || row.procedure_protocol_version
        !== this.#profile.procedure.protocolVersion
      || !candidateLinuxTargetScopesEqual(
        parseCandidateLinuxTargetScope(
          parseObject(
            row.admission_receipt_json,
            "Existing procedure admission receipt",
          ).targetScope,
        ),
        this.#profile.targetScope,
      )
    ) {
      reject(
        "activation_conflict",
        "The current-run candidate is already bound to a different procedure admission",
      );
    }
  }
}

/**
 * Conditional, run-scoped real-candidate procedure bridge.
 *
 * Product launch only attests this closed bridge and its source profile. A
 * procedure becomes dispatchable later, after the database joins one current
 * run's evidence-backed ScriptArtifact, candidate observer/spec, represented
 * AttackAttempt, exact target, local validation artifact, and hash-pinned
 * executable. No command, argv, payload, credential, or arbitrary proof path
 * crosses this service.
 */
export class RunScopedReviewedCandidateLinuxProcedureActivationBridge
implements ReviewedRealCandidateLinuxAdapterImplementation {
  readonly bindingId: string;
  readonly postExploitSpecId: string;
  readonly profileSha256: string;
  readonly adapterExecutableSha256: string;
  readonly candidateClass = "reviewed_real_candidate_v1" as const;
  readonly realTargetSupport = true as const;
  readonly targetScope: CandidateLinuxTargetScope;

  readonly #profile: ReviewedRealCandidateLinuxProfile;
  readonly #procedureTrustRoot: string;
  readonly #allowedOwnerUids: readonly number[];
  readonly #now: () => Date;
  readonly #events: EventRepository;
  readonly #audit: AuditTrailWriter;
  #compositionObservedAt?: string;
  #compositionExpiresAt?: string;
  readonly #processAttestations = new Set<string>();

  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    loadedProfile: LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>;
    procedureTrustRoot: string;
    adapterExecutableSha256?: string;
    allowedProcedureOwnerUids?: readonly number[];
    now?: () => Date;
  }>) {
    this.#profile = options.loadedProfile.value;
    this.bindingId = this.#profile.bindingId;
    this.postExploitSpecId = this.#profile.postExploitSpec.id;
    this.targetScope = this.#profile.targetScope;
    this.profileSha256 = hash(
      options.loadedProfile.receipt.sourceSha256,
      "Profile SHA-256",
    );
    this.adapterExecutableSha256 = hash(
      options.adapterExecutableSha256
        ?? this.#profile.adapter.executableSha256,
      "Adapter executable SHA-256",
    );
    if (
      this.adapterExecutableSha256
        !== this.#profile.adapter.executableSha256
    ) {
      throw new Error(
        "Run-scoped procedure bridge does not match the adapter profile",
      );
    }
    this.#procedureTrustRoot = resolve(options.procedureTrustRoot);
    if (
      !isAbsolute(options.procedureTrustRoot)
      || options.procedureTrustRoot !== this.#procedureTrustRoot
      || CONTROL.test(options.procedureTrustRoot)
    ) {
      throw new TypeError(
        "Procedure trust root must be one canonical absolute path",
      );
    }
    const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
    this.#allowedOwnerUids = Object.freeze([
      ...new Set(options.allowedProcedureOwnerUids ?? [0, currentUid]),
    ]);
    if (
      this.#allowedOwnerUids.length < 1
      || this.#allowedOwnerUids.length > 8
      || this.#allowedOwnerUids.some((uid) =>
        !Number.isSafeInteger(uid) || uid < 0)
    ) {
      throw new TypeError("Procedure owner allowlist is invalid");
    }
    this.#now = options.now ?? (() => new Date());
    this.#events = new EventRepository(options.database);
    this.#audit = new AuditTrailWriter(options.database);
    this.#assertTrustRoot();
  }

  inspectComposition(
    now: Date = this.#now(),
  ): RunScopedReviewedCandidateLinuxBridgeReadiness {
    const ready = Boolean(
      this.#compositionObservedAt
      && this.#compositionExpiresAt
      && Date.parse(this.#compositionExpiresAt) > now.getTime(),
    );
    return Object.freeze({
      schemaVersion:
        RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_BRIDGE_READINESS_SCHEMA_VERSION,
      status: ready ? "ready" : "blocked",
      code: ready
        ? "run_scoped_candidate_bridge_ready"
        : "run_scoped_candidate_bridge_unattested",
      reason: ready
        ? "The distinct hash-pinned procedure provider and conditional bridge are installed and attested. Each run remains dispatch-blocked until its exact provider admission, activation, and current attestation exist."
        : "The conditional real-candidate bridge has not completed a current local composition attestation.",
      conditionalCapability: true,
      candidateProcedurePresentAtLaunch: true,
      procedureProviderPresentAtLaunch: true,
      runScopedProcedureActivationPresentAtLaunch: false,
      grantsRunDispatch: false,
      profileSha256: this.profileSha256,
      transportBindingId: this.bindingId,
      targetScope: this.targetScope,
      observedAt: ready ? this.#compositionObservedAt! : null,
      expiresAt: ready ? this.#compositionExpiresAt! : null,
    });
  }

  /**
   * Attests only the bridge, trusted root, source profile, and schema. It
   * intentionally succeeds with zero run activations.
   */
  async attest(signal: AbortSignal): Promise<void> {
    if (signal.aborted) {
      reject(
        "bridge_unavailable",
        "Run-scoped procedure bridge attestation was cancelled",
      );
    }
    this.#assertTrustRoot();
    this.#requireSourceProfileAuthority();
    const requiredSchemaObjects = [
      ["table", "reviewed_candidate_linux_procedure_activations"],
      ["table", "reviewed_candidate_linux_procedure_admissions"],
      ["trigger", "trg_reviewed_candidate_procedure_admission_lineage_insert"],
      ["trigger", "trg_reviewed_candidate_procedure_admission_immutable"],
      ["trigger", "trg_reviewed_candidate_procedure_activation_lineage_insert"],
      [
        "trigger",
        "trg_reviewed_candidate_procedure_activation_admission_immutable",
      ],
    ] as const;
    const missingSchemaObject = requiredSchemaObjects.find(
      ([type, name]) => !this.options.database.prepare(`
        SELECT 1 FROM sqlite_schema
        WHERE type = ? AND name = ?
      `).get(type, name),
    );
    if (missingSchemaObject) {
      reject(
        "bridge_unavailable",
        `Run-scoped provider admission schema is unavailable: ${missingSchemaObject[1]}`,
      );
    }
    const observed = this.#now();
    this.#compositionObservedAt = observed.toISOString();
    this.#compositionExpiresAt =
      new Date(observed.getTime() + COMPOSITION_TTL_MS).toISOString();
  }

  executionReadiness(
    runId: string,
    postExploitSpecId: string,
    now: Date = this.#now(),
  ): RunScopedReviewedCandidateLinuxExecutionReadiness {
    id(runId, "Run ID");
    id(postExploitSpecId, "Post-exploit spec ID");
    const row = this.#rowForSpec(postExploitSpecId);
    if (!row || row.run_id !== runId || row.status !== "active") {
      return Object.freeze({
        status: "blocked",
        code: "run_scoped_candidate_procedure_missing",
        reason:
          "This run has no active procedure activation for the represented candidate step.",
        runId,
        postExploitSpecId,
        activationId: null,
        attestationExpiresAt: null,
        targetScope: this.targetScope,
      });
    }
    const latest = this.#latestAttestation(row.id);
    if (!latest || Date.parse(latest.expires_at) <= now.getTime()) {
      return Object.freeze({
        status: "blocked",
        code: "run_scoped_candidate_procedure_unattested",
        reason:
          "The run-scoped procedure activation exists, but its candidate-specific attestation is missing or expired.",
        runId,
        postExploitSpecId,
        activationId: row.id,
        attestationExpiresAt: latest?.expires_at ?? null,
        targetScope: this.targetScope,
      });
    }
    return Object.freeze({
      status: "ready",
      code: "run_scoped_candidate_procedure_ready",
      reason:
        "The exact run, step, target, action binding, ScriptArtifact, observer, procedure hash, and current attestation are present.",
      runId,
      postExploitSpecId,
      activationId: row.id,
      attestationExpiresAt: latest.expires_at,
      targetScope: this.targetScope,
    });
  }

  async activate(
    input: RunScopedReviewedCandidateLinuxProcedureActivationInput,
    signal: AbortSignal,
  ): Promise<RunScopedReviewedCandidateLinuxProcedureActivationResult> {
    if (signal.aborted) {
      reject(
        "activation_stale",
        "Run-scoped procedure activation was cancelled before validation",
      );
    }
    const normalized = this.#validateInput(input);
    if (this.inspectComposition().status !== "ready") {
      await this.attest(signal);
    }
    const authority = this.#requireActivationAuthority(normalized);
    const provider = this.#provider(
      normalized.procedureExecutablePath,
      normalized.procedureExecutableSha256,
    );
    const providerAttestation = await provider.attest(signal);
    if (signal.aborted) {
      reject(
        "activation_stale",
        "Run-scoped procedure activation was cancelled before custody was committed",
      );
    }
    const activatedAt = this.#now().toISOString();
    const idempotencyKeyHash = keyHash(normalized.idempotencyKey);
    const activationId = stableId("candidate_procedure_activation", [
      normalized.runId,
      normalized.attackAttemptId,
      normalized.postExploitSpecId,
      normalized.procedureExecutableSha256,
    ]);
    const receipt = Object.freeze({
      schemaVersion:
        RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ACTIVATION_SCHEMA_VERSION,
      id: activationId,
      missionId: normalized.missionId,
      runId: normalized.runId,
      planId: normalized.planId,
      stepId: normalized.stepId,
      attackAttemptId: normalized.attackAttemptId,
      targetNodeId: normalized.targetNodeId,
      exactTarget: normalized.exactTarget,
      sourcePostExploitSpecId: this.postExploitSpecId,
      postExploitSpecId: normalized.postExploitSpecId,
      scriptArtifactId: normalized.scriptArtifactId,
      scriptContentHash: authority.script_content_hash,
      exploitOutcomeObserverSpecId: authority.observer_id,
      exploitOutcomeObserverSpecHash: authority.observer_hash,
      scriptValidationArtifactId: authority.script_test_artifact_id!,
      scriptValidationArtifactHash: authority.validation_artifact_hash,
      representedActionBindingHash:
        normalized.representedActionBindingHash,
      procedureAdmissionId: normalized.procedureAdmissionId,
      profileId: this.#profile.profileId,
      profileSha256: this.profileSha256,
      transportBindingId: this.bindingId,
      procedureExecutablePath: normalized.procedureExecutablePath,
      procedureExecutableSha256: normalized.procedureExecutableSha256,
      targetScope: this.targetScope,
      conditionalCapabilityAtLaunch: true as const,
      runScopedDispatchOnly: true as const,
      genericCommand: false as const,
      shell: false as const,
      argv: false as const,
      payload: false as const,
      credentialsFromRuntime: false as const,
      activatedBy: normalized.actor.id,
      activatedAt,
    });
    const activationReceiptHash = digest(receipt);
    const persisted = inImmediateTransaction(this.options.database, () => {
      const bySpec = this.#rowForSpec(normalized.postExploitSpecId);
      const byKey = this.options.database.prepare(`
        SELECT * FROM reviewed_candidate_linux_procedure_activations
        WHERE run_id = ? AND idempotency_key_hash = ?
      `).get(
        normalized.runId,
        idempotencyKeyHash,
      ) as ActivationRow | undefined;
      const existing = bySpec ?? byKey;
      if (existing) {
        this.#assertIdempotentActivation(existing, {
          activationId,
          input: normalized,
          authority,
          idempotencyKeyHash,
        });
        const attestationHash = this.#persistAttestation(
          existing,
          providerAttestation,
          activatedAt,
        );
        return Object.freeze({
          row: existing,
          attestationHash,
          reused: true,
        });
      }
      this.options.database.prepare(`
        INSERT INTO reviewed_candidate_linux_procedure_activations (
          id, mission_id, run_id, plan_id, step_id, attack_attempt_id,
          target_node_id, exact_target, source_post_exploit_spec_id,
          post_exploit_spec_id, script_artifact_id, script_content_hash,
          exploit_outcome_observer_spec_id,
          exploit_outcome_observer_spec_hash,
          script_validation_artifact_id,
          script_validation_artifact_hash,
          represented_action_binding_hash, profile_id, profile_sha256,
          procedure_admission_id,
          transport_binding_id, procedure_executable_path,
          procedure_executable_sha256, idempotency_key_hash, status,
          activation_receipt_json, activation_receipt_hash, activated_by,
          activated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
      `).run(
        activationId,
        normalized.missionId,
        normalized.runId,
        normalized.planId,
        normalized.stepId,
        normalized.attackAttemptId,
        normalized.targetNodeId,
        normalized.exactTarget,
        this.postExploitSpecId,
        normalized.postExploitSpecId,
        normalized.scriptArtifactId,
        authority.script_content_hash,
        authority.observer_id,
        authority.observer_hash,
        authority.script_test_artifact_id,
        authority.validation_artifact_hash,
        normalized.representedActionBindingHash,
        this.#profile.profileId,
        this.profileSha256,
        normalized.procedureAdmissionId,
        this.bindingId,
        normalized.procedureExecutablePath,
        normalized.procedureExecutableSha256,
        idempotencyKeyHash,
        JSON.stringify(receipt),
        activationReceiptHash,
        normalized.actor.id,
        activatedAt,
      );
      const created = this.#rowForSpec(normalized.postExploitSpecId);
      if (!created) {
        reject(
          "activation_stale",
          "Run-scoped procedure activation was not durably created",
        );
      }
      const attestationHash = this.#persistAttestation(
        created,
        providerAttestation,
        activatedAt,
      );
      this.#audit.append({
        missionId: normalized.missionId,
        runId: normalized.runId,
        actor: normalized.actor,
        action: "candidate_linux.procedure_activated",
        resourceType: "reviewed_candidate_linux_procedure_activation",
        resourceId: created.id,
        reason:
          "Activated one independently attested candidate procedure for the exact represented run step.",
        details: {
          planId: normalized.planId,
          stepId: normalized.stepId,
          attackAttemptId: normalized.attackAttemptId,
          targetNodeId: normalized.targetNodeId,
          exactTarget: normalized.exactTarget,
          scriptArtifactId: normalized.scriptArtifactId,
          postExploitSpecId: normalized.postExploitSpecId,
          procedureAdmissionId: normalized.procedureAdmissionId,
          procedureExecutableSha256:
            normalized.procedureExecutableSha256,
          activationReceiptHash,
          grantsCrossRunAuthority: false,
        },
        occurredAt: activatedAt,
      });
      this.#events.append({
        missionId: normalized.missionId,
        runId: normalized.runId,
        eventType: "candidate_linux.procedure_activated",
        actorType: normalized.actor.type,
        actorId: normalized.actor.id,
        summary:
          "The exact candidate step now has a hash-pinned, independently attested run-scoped procedure.",
        payload: {
          activationId: created.id,
          planId: normalized.planId,
          stepId: normalized.stepId,
          attackAttemptId: normalized.attackAttemptId,
          targetNodeId: normalized.targetNodeId,
          scriptArtifactId: normalized.scriptArtifactId,
          postExploitSpecId: normalized.postExploitSpecId,
          procedureAdmissionId: normalized.procedureAdmissionId,
          procedureExecutableSha256:
            normalized.procedureExecutableSha256,
          activationReceiptHash,
          dispatchScope: "this_run_only",
        },
        schemaVersion: 1,
        sensitivity: "internal",
        occurredAt: activatedAt,
        outboxTopic: "run.candidate-procedure-activations",
      });
      return Object.freeze({
        row: created,
        attestationHash,
        reused: false,
      });
    });
    this.#processAttestations.add(persisted.row.id);
    return Object.freeze({
      activation: activation(persisted.row),
      providerAttestation,
      runScopedAttestationHash: persisted.attestationHash,
      reused: persisted.reused,
    });
  }

  async handle(
    request: CandidateLinuxTransportRequest,
    signal: AbortSignal,
  ): Promise<unknown> {
    if (
      request.transportBindingId !== this.bindingId
      || request.postExploitSpecId === this.postExploitSpecId
      || !candidateLinuxTargetScopeMatches(
        this.targetScope,
        request.exactTarget,
      )
    ) {
      reject(
        "activation_scope_invalid",
        "Candidate procedure request is outside the conditional bridge identity",
      );
    }
    const row = this.#rowForSpec(request.postExploitSpecId);
    if (!row || row.status !== "active") {
      reject(
        "activation_missing",
        "Candidate procedure dispatch is blocked until this run's exact activation exists",
      );
    }
    if (row.exact_target !== request.exactTarget) {
      reject(
        "activation_scope_invalid",
        "Candidate procedure target differs from the activated canonical target",
      );
    }
    this.#requireActivationAuthority({
      missionId: row.mission_id,
      runId: row.run_id,
      planId: row.plan_id,
      stepId: row.step_id,
      attackAttemptId: row.attack_attempt_id,
      targetNodeId: row.target_node_id,
      exactTarget: row.exact_target,
      scriptArtifactId: row.script_artifact_id,
      postExploitSpecId: row.post_exploit_spec_id,
      representedActionBindingHash: row.represented_action_binding_hash,
      procedureAdmissionId: row.procedure_admission_id ?? "",
      procedureExecutablePath: row.procedure_executable_path,
      procedureExecutableSha256: row.procedure_executable_sha256,
    });
    const provider = this.#provider(
      row.procedure_executable_path,
      row.procedure_executable_sha256,
    );
    if (!this.#processAttestations.has(row.id)) {
      const attestation = await provider.attest(signal);
      inImmediateTransaction(this.options.database, () => {
        this.#persistAttestation(row, attestation, this.#now().toISOString());
      });
      this.#processAttestations.add(row.id);
    }
    const implementation =
      new ProcedureBackedReviewedRealCandidateLinuxAdapterImplementation({
        profile: this.#profile,
        profileSha256: this.profileSha256,
        adapterExecutableSha256: this.adapterExecutableSha256,
        provider,
        now: this.#now,
      });
    return await implementation.handle(request, signal);
  }

  #validateInput(
    input: RunScopedReviewedCandidateLinuxProcedureActivationInput,
  ): RunScopedReviewedCandidateLinuxProcedureActivationInput {
    for (const [label, value] of [
      ["Mission ID", input.missionId],
      ["Run ID", input.runId],
      ["Plan ID", input.planId],
      ["Step ID", input.stepId],
      ["AttackAttempt ID", input.attackAttemptId],
      ["Target node ID", input.targetNodeId],
      ["ScriptArtifact ID", input.scriptArtifactId],
      ["Post-exploit spec ID", input.postExploitSpecId],
      ["Procedure admission ID", input.procedureAdmissionId],
    ] as const) id(value, label);
    hash(
      input.representedActionBindingHash,
      "Represented action binding hash",
    );
    hash(input.procedureExecutableSha256, "Procedure executable SHA-256");
    if (isIP(input.exactTarget) === 0) {
      throw new TypeError(
        "Run-scoped candidate procedure activation requires one canonical IP target",
      );
    }
    if (!candidateLinuxTargetScopeMatches(this.targetScope, input.exactTarget)) {
      throw new TypeError(
        "Run-scoped candidate procedure activation target is outside the reviewed provider scope",
      );
    }
    const path = resolve(input.procedureExecutablePath);
    if (
      !isAbsolute(input.procedureExecutablePath)
      || path !== input.procedureExecutablePath
      || CONTROL.test(path)
      || path !== this.#profile.procedure.executablePath
      || input.procedureExecutableSha256
        !== this.#profile.procedure.executableSha256
    ) {
      throw new TypeError(
        "Procedure executable must equal the distinct path and hash pinned by the reviewed profile",
      );
    }
    keyHash(input.idempotencyKey);
    safeActor(input.actor);
    return Object.freeze({ ...input, procedureExecutablePath: path });
  }

  #requireSourceProfileAuthority(): void {
    const profile = this.#profile;
    const row = this.options.database.prepare(`
      SELECT spec.id, spec.spec_hash, spec.transport_binding_id,
        spec.transport_type, spec.status,
        script.id AS script_id, script.content_hash AS script_hash,
        script.validation_state,
        observer.id AS observer_id,
        observer.script_content_hash AS observer_script_hash,
        observer.status AS observer_status
      FROM candidate_linux_post_exploit_specs AS spec
      JOIN script_artifacts AS script
        ON script.id = spec.script_artifact_id
      JOIN exploit_outcome_observer_specs AS observer
        ON observer.id = spec.exploit_outcome_observer_spec_id
        AND observer.script_artifact_id = script.id
      WHERE spec.id = ?
      LIMIT 1
    `).get(profile.postExploitSpec.id) as
      | Readonly<Record<string, string>>
      | undefined;
    if (
      !row
      || row.id !== profile.postExploitSpec.id
      || row.spec_hash !== profile.postExploitSpec.expectedSha256
      || row.transport_binding_id !== profile.bindingId
      || row.transport_type !== "candidate_runtime_session_v1"
      || row.status !== "active"
      || row.script_id !== profile.postExploitSpec.scriptArtifactId
      || row.validation_state !== "approved"
      || row.observer_id
        !== profile.postExploitSpec.exploitOutcomeObserverSpecId
      || row.observer_script_hash !== row.script_hash
      || row.observer_status !== "active"
    ) {
      reject(
        "bridge_unavailable",
        "The conditional bridge source profile is not backed by its active hash-matched ScriptArtifact, observer, and typed specification",
      );
    }
  }

  #requireActivationAuthority(
    input: Omit<
      RunScopedReviewedCandidateLinuxProcedureActivationInput,
      "idempotencyKey" | "actor"
    > & Partial<Pick<
      RunScopedReviewedCandidateLinuxProcedureActivationInput,
      "idempotencyKey" | "actor"
    >>,
  ): AuthorityRow {
    const row = this.options.database.prepare(`
      SELECT mission.id AS mission_id, run.id AS run_id, plan.id AS plan_id,
        step.id AS step_id, target.id AS target_node_id,
        scope.normalized_target AS exact_target,
        script.id AS script_artifact_id,
        script.content_hash AS script_content_hash,
        script.name AS script_name,
        script.validation_state AS script_validation_state,
        script.test_artifact_id AS script_test_artifact_id,
        validation.content_hash AS validation_artifact_hash,
        validation.artifact_type AS validation_artifact_type,
        spec.id AS spec_id, spec.spec_hash AS spec_hash,
        spec.created_by AS spec_created_by,
        spec.status AS spec_status,
        spec.transport_type AS spec_transport_type,
        spec.transport_binding_id AS spec_transport_binding_id,
        observer.id AS observer_id, observer.spec_hash AS observer_hash,
        observer.status AS observer_status,
        observer.script_content_hash AS observer_script_hash,
        observer.cve_id AS observer_cve_id,
        observer.observer_type AS observer_type,
        observer.request_json AS observer_request_json,
        observer.assertion_json AS observer_assertion_json,
        source_spec.id AS source_spec_id,
        source_spec.spec_hash AS source_spec_hash,
        source_script.id AS source_script_id,
        source_script.content_hash AS source_script_hash,
        source_observer.id AS source_observer_id,
        source_observer.status AS source_observer_status,
        source_observer.script_content_hash AS source_observer_script_hash,
        source_observer.cve_id AS source_observer_cve_id,
        source_observer.observer_type AS source_observer_type,
        source_observer.request_json AS source_observer_request_json,
        source_observer.assertion_json AS source_observer_assertion_json,
        source_spec.expected_principal AS source_expected_principal,
        source_spec.expected_uid AS source_expected_uid,
        source_spec.declared_user_flag_path
          AS source_declared_user_flag_path,
        source_spec.declared_root_flag_path
          AS source_declared_root_flag_path,
        spec.expected_principal, spec.expected_uid,
        spec.declared_user_flag_path,
        action_binding.action_type, action_binding.action_class,
        action_binding.normalized_arguments_json,
        action_binding.scoped_target,
        action_binding.binding_hash AS action_binding_hash,
        attempt.prerequisites_json,
        attempt.status AS attempt_status
      FROM missions AS mission
      JOIN runs AS run
        ON run.id = ?
        AND run.mission_id = mission.id
        AND run.journey = 'autonomous'
        AND run.control_plane = 'ti_scale'
        AND run.status IN ('planning', 'running', 'recovering')
        AND run.current_plan_id = ?
      JOIN mission_contracts AS contract
        ON contract.id = run.contract_id
        AND contract.mission_id = mission.id
        AND contract.state = 'confirmed'
        AND contract.version = run.contract_version_bound
        AND contract.contract_hash = run.contract_hash_bound
      JOIN plans AS plan
        ON plan.id = ?
        AND plan.run_id = run.id
        AND plan.status = 'active'
      JOIN plan_steps AS step
        ON step.id = ?
        AND step.plan_id = plan.id
        AND step.run_id = run.id
      JOIN topology_nodes AS target
        ON target.id = ?
        AND target.mission_id = mission.id
        AND target.run_id = run.id
        AND target.scope_status = 'allowed'
        AND target.verification_state = 'verified'
      JOIN mission_targets AS scope
        ON scope.mission_id = mission.id
        AND scope.disposition = 'allowed'
        AND scope.normalized_target = ?
        AND scope.normalized_target IN (
          target.normalized_identity, target.primary_label
        )
      JOIN script_artifacts AS script
        ON script.id = ?
        AND script.mission_id = mission.id
        AND script.run_id = run.id
        AND (script.plan_id IS NULL OR script.plan_id = plan.id)
        AND (script.step_id IS NULL OR script.step_id = step.id)
        AND (
          script.target_node_id IS NULL
          OR script.target_node_id = target.id
        )
        AND script.validation_state = 'approved'
        AND script.test_artifact_id IS NOT NULL
      JOIN artifacts AS validation
        ON validation.id = script.test_artifact_id
        AND validation.mission_id = mission.id
        AND validation.run_id = run.id
        AND (
          validation.step_id IS NULL
          OR validation.step_id = step.id
        )
        AND validation.artifact_type IN (
          'script_test_result', 'generated_script_test', 'test_result'
        )
      JOIN candidate_linux_post_exploit_specs AS spec
        ON spec.id = ?
        AND spec.script_artifact_id = script.id
        AND spec.transport_type = 'candidate_runtime_session_v1'
        AND spec.transport_binding_id = ?
        AND spec.status = 'active'
      JOIN exploit_outcome_observer_specs AS observer
        ON observer.id = spec.exploit_outcome_observer_spec_id
        AND observer.script_artifact_id = script.id
        AND observer.script_content_hash = script.content_hash
        AND observer.status = 'active'
      JOIN candidate_linux_post_exploit_specs AS source_spec
        ON source_spec.id = ?
        AND source_spec.transport_type = 'candidate_runtime_session_v1'
        AND source_spec.transport_binding_id = spec.transport_binding_id
        AND source_spec.status = 'active'
        AND spec.created_by IN (
          'system:cloned-from:' || source_spec.id,
          'system:validated-candidate-from:' || source_spec.id
        )
      JOIN script_artifacts AS source_script
        ON source_script.id = source_spec.script_artifact_id
        AND source_script.validation_state = 'approved'
      JOIN exploit_outcome_observer_specs AS source_observer
        ON source_observer.id =
          source_spec.exploit_outcome_observer_spec_id
        AND source_observer.script_artifact_id = source_script.id
        AND source_observer.status = 'active'
      JOIN attack_attempts AS attempt
        ON attempt.id = ?
        AND attempt.mission_id = mission.id
        AND attempt.run_id = run.id
        AND attempt.plan_id = plan.id
        AND attempt.step_id = step.id
        AND attempt.target_asset_id = target.id
        AND attempt.action_class = 'exploit_validation'
        AND attempt.status IN ('ready', 'running')
      JOIN attack_attempt_action_bindings AS action_binding
        ON action_binding.attack_attempt_id = attempt.id
        AND action_binding.action_class = attempt.action_class
        AND action_binding.scoped_target = scope.normalized_target
        AND action_binding.binding_hash = ?
      WHERE mission.id = ?
        AND mission.journey = 'autonomous'
        AND mission.control_plane = 'ti_scale'
        AND mission.authorization_status = 'verified'
        AND EXISTS (
          SELECT 1
          FROM json_each(
            json_extract(
              contract.action_policy_json,
              '$.allowedActionClasses'
            )
          )
          WHERE value = 'exploit_validation'
        )
      LIMIT 1
    `).get(
      input.runId,
      input.planId,
      input.planId,
      input.stepId,
      input.targetNodeId,
      input.exactTarget,
      input.scriptArtifactId,
      input.postExploitSpecId,
      this.bindingId,
      this.postExploitSpecId,
      input.attackAttemptId,
      input.representedActionBindingHash,
      input.missionId,
    ) as AuthorityRow | undefined;
    if (!row) {
      reject(
        "activation_scope_invalid",
        "Procedure activation does not match the current authorized run, plan, step, target, validated ScriptArtifact, candidate observer/spec, and represented AttackAttempt",
      );
    }
    const prerequisites = parseArray(
      row.prerequisites_json,
      "AttackAttempt prerequisites",
    );
    const argumentsObject = parseObject(
      row.normalized_arguments_json,
      "Represented exploit-validation arguments",
    );
    const candidates = argumentsObject.candidates;
    const exactCandidate = Array.isArray(candidates)
      && candidates.some((candidate) => {
        if (
          !candidate
          || typeof candidate !== "object"
          || Array.isArray(candidate)
        ) return false;
        const value = candidate as Readonly<Record<string, unknown>>;
        return value.scriptArtifactId === row.script_artifact_id
          && value.scriptContentHash === row.script_content_hash
          && value.targetNodeId === row.target_node_id;
      });
    const expectedSpecHash = candidateLinuxPostExploitSpecificationHash({
      exploitOutcomeObserverSpecId: row.observer_id,
      scriptArtifactId: row.script_artifact_id,
      scriptContentHash: row.script_content_hash,
      transportType: "candidate_runtime_session_v1",
      transportBindingId: this.bindingId,
      transportOrigin: null,
      expectedPrincipal: row.expected_principal,
      expectedUid: row.expected_uid,
      declaredUserFlagPath: row.declared_user_flag_path,
    });
    const latest = this.options.database.prepare(`
      SELECT id FROM script_artifacts
      WHERE mission_id = ? AND name = ?
      ORDER BY version DESC, created_at DESC, id
      LIMIT 1
    `).get(row.mission_id, row.script_name) as
      | { readonly id: string }
      | undefined;
    const admission = this.options.database.prepare(`
      SELECT * FROM reviewed_candidate_linux_procedure_admissions
      WHERE id = ?
      LIMIT 1
    `).get(input.procedureAdmissionId) as AdmissionRow | undefined;
    if (
      row.mission_id !== input.missionId
      || row.run_id !== input.runId
      || row.plan_id !== input.planId
      || row.step_id !== input.stepId
      || row.target_node_id !== input.targetNodeId
      || row.exact_target !== input.exactTarget
      || row.script_artifact_id !== input.scriptArtifactId
      || row.spec_id !== input.postExploitSpecId
      || row.source_spec_id !== this.postExploitSpecId
      || row.source_spec_hash !== this.#profile.postExploitSpec.expectedSha256
      || row.source_script_id
        !== this.#profile.postExploitSpec.scriptArtifactId
      || row.source_observer_id
        !== this.#profile.postExploitSpec.exploitOutcomeObserverSpecId
      || row.spec_hash !== expectedSpecHash
      || row.spec_created_by
        !== `system:cloned-from:${this.postExploitSpecId}`
      || row.spec_status !== "active"
      || row.spec_transport_type !== "candidate_runtime_session_v1"
      || row.spec_transport_binding_id !== this.bindingId
      || row.script_validation_state !== "approved"
      || !row.script_test_artifact_id
      || !SHA256.test(row.validation_artifact_hash)
      || ![
        "script_test_result",
        "generated_script_test",
        "test_result",
      ].includes(row.validation_artifact_type)
      || row.observer_status !== "active"
      || row.observer_script_hash !== row.script_content_hash
      || row.source_observer_status !== "active"
      || row.source_observer_script_hash !== row.source_script_hash
      || row.expected_principal !== row.source_expected_principal
      || row.expected_uid !== row.source_expected_uid
      || row.declared_user_flag_path
        !== row.source_declared_user_flag_path
      || row.source_declared_root_flag_path !== "/root/root.txt"
      || !admission
      || admission.status !== "admitted"
      || admission.mission_id !== row.mission_id
      || admission.run_id !== row.run_id
      || admission.source_post_exploit_spec_id !== row.source_spec_id
      || admission.post_exploit_spec_id !== row.spec_id
      || admission.script_artifact_id !== row.script_artifact_id
      || admission.script_content_hash !== row.script_content_hash
      || admission.exploit_outcome_observer_spec_id !== row.observer_id
      || admission.exploit_outcome_observer_spec_hash !== row.observer_hash
      || admission.profile_id !== this.#profile.profileId
      || admission.profile_sha256 !== this.profileSha256
      || admission.transport_binding_id !== this.bindingId
      || admission.procedure_executable_path
        !== input.procedureExecutablePath
      || admission.procedure_executable_sha256
        !== input.procedureExecutableSha256
      || !candidateLinuxTargetScopesEqual(
        parseCandidateLinuxTargetScope(
          parseObject(
            admission.admission_receipt_json,
            "Procedure admission receipt",
          ).targetScope,
        ),
        this.targetScope,
      )
      || row.action_type !== AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_TYPE
      || row.action_class !== AUTONOMOUS_EXPLOIT_VALIDATION_ACTION_CLASS
      || row.scoped_target !== input.exactTarget
      || row.action_binding_hash !== input.representedActionBindingHash
      || !["ready", "running"].includes(row.attempt_status)
      || !prerequisites.includes(row.script_artifact_id)
      || !exactCandidate
      || latest?.id !== row.script_artifact_id
    ) {
      reject(
        "activation_scope_invalid",
        "Procedure activation custody differs from the immutable current-run candidate and its represented exact-target action",
      );
    }
    return row;
  }

  #assertTrustRoot(): void {
    const metadata = lstatSync(this.#procedureTrustRoot);
    if (
      !metadata.isDirectory()
      || metadata.isSymbolicLink()
      || !this.#allowedOwnerUids.includes(metadata.uid)
      || (metadata.mode & 0o022) !== 0
    ) {
      reject(
        "bridge_unavailable",
        "The run-scoped procedure trust root is not owner-controlled",
      );
    }
  }

  #provider(
    path: string,
    executableSha256: string,
  ): HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider {
    return new HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider({
      profile: this.#profile,
      profileSha256: this.profileSha256,
      procedureExecutablePath: path,
      procedureExecutableSha256: executableSha256,
      allowedOwnerUids: this.#allowedOwnerUids,
      now: this.#now,
      maximumConcurrency: 1,
    });
  }

  #rowForSpec(postExploitSpecId: string): ActivationRow | undefined {
    return this.options.database.prepare(`
      SELECT * FROM reviewed_candidate_linux_procedure_activations
      WHERE post_exploit_spec_id = ?
      LIMIT 1
    `).get(postExploitSpecId) as ActivationRow | undefined;
  }

  #latestAttestation(
    activationId: string,
  ): { readonly expires_at: string } | undefined {
    return this.options.database.prepare(`
      SELECT expires_at
      FROM reviewed_candidate_linux_procedure_attestations
      WHERE activation_id = ?
      ORDER BY expires_at DESC, observed_at DESC, id DESC
      LIMIT 1
    `).get(activationId) as
      | { readonly expires_at: string }
      | undefined;
  }

  #assertIdempotentActivation(
    existing: ActivationRow,
    expected: Readonly<{
      activationId: string;
      input: RunScopedReviewedCandidateLinuxProcedureActivationInput;
      authority: AuthorityRow;
      idempotencyKeyHash: string;
    }>,
  ): void {
    const input = expected.input;
    if (
      existing.id !== expected.activationId
      || existing.mission_id !== input.missionId
      || existing.run_id !== input.runId
      || existing.plan_id !== input.planId
      || existing.step_id !== input.stepId
      || existing.attack_attempt_id !== input.attackAttemptId
      || existing.target_node_id !== input.targetNodeId
      || existing.exact_target !== input.exactTarget
      || existing.source_post_exploit_spec_id !== this.postExploitSpecId
      || existing.post_exploit_spec_id !== input.postExploitSpecId
      || existing.script_artifact_id !== input.scriptArtifactId
      || existing.script_content_hash
        !== expected.authority.script_content_hash
      || existing.exploit_outcome_observer_spec_id
        !== expected.authority.observer_id
      || existing.exploit_outcome_observer_spec_hash
        !== expected.authority.observer_hash
      || existing.script_validation_artifact_id
        !== expected.authority.script_test_artifact_id
      || existing.script_validation_artifact_hash
        !== expected.authority.validation_artifact_hash
      || existing.represented_action_binding_hash
        !== input.representedActionBindingHash
      || existing.procedure_admission_id
        !== input.procedureAdmissionId
      || existing.profile_id !== this.#profile.profileId
      || existing.profile_sha256 !== this.profileSha256
      || existing.transport_binding_id !== this.bindingId
      || existing.procedure_executable_path
        !== input.procedureExecutablePath
      || existing.procedure_executable_sha256
        !== input.procedureExecutableSha256
      || existing.idempotency_key_hash !== expected.idempotencyKeyHash
      || existing.status !== "active"
    ) {
      reject(
        "activation_conflict",
        "The idempotency key or candidate spec is already bound to a different run-scoped procedure activation",
      );
    }
  }

  #persistAttestation(
    row: ActivationRow,
    provider: ReviewedRealCandidateLinuxProcedureAttestation,
    recordedAt: string,
  ): string {
    const runScoped = Object.freeze({
      schemaVersion:
        RUN_SCOPED_REVIEWED_CANDIDATE_LINUX_PROCEDURE_ATTESTATION_SCHEMA_VERSION,
      activationId: row.id,
      missionId: row.mission_id,
      runId: row.run_id,
      planId: row.plan_id,
      stepId: row.step_id,
      attackAttemptId: row.attack_attempt_id,
      targetNodeId: row.target_node_id,
      exactTarget: row.exact_target,
      postExploitSpecId: row.post_exploit_spec_id,
      scriptArtifactId: row.script_artifact_id,
      scriptContentHash: row.script_content_hash,
      representedActionBindingHash: row.represented_action_binding_hash,
      procedureAdmissionId: row.procedure_admission_id,
      profileSha256: row.profile_sha256,
      procedureExecutableSha256: row.procedure_executable_sha256,
      providerReceiptHash: provider.receiptSha256,
      targetScope: this.targetScope,
      observedAt: provider.observedAt,
      expiresAt: provider.expiresAt,
      grantsCrossRunAuthority: false as const,
      genericCommand: false as const,
      shell: false as const,
      argv: false as const,
      payload: false as const,
      credentialsFromRuntime: false as const,
    });
    const runScopedReceiptHash = digest(runScoped);
    const attestationId = stableId("candidate_procedure_attestation", [
      row.id,
      runScopedReceiptHash,
    ]);
    this.options.database.prepare(`
      INSERT OR IGNORE INTO
        reviewed_candidate_linux_procedure_attestations (
          id, activation_id, provider_receipt_hash, provider_receipt_json,
          run_scoped_receipt_hash, run_scoped_receipt_json,
          observed_at, expires_at, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      attestationId,
      row.id,
      provider.receiptSha256,
      JSON.stringify(provider),
      runScopedReceiptHash,
      JSON.stringify(runScoped),
      provider.observedAt,
      provider.expiresAt,
      recordedAt,
    );
    return runScopedReceiptHash;
  }
}

/**
 * Production pre-dispatch coordinator for one already admitted candidate.
 *
 * It never publishes or executes exploit ScriptArtifact bytes. The immutable
 * pre-plan admission supplies the distinct profile-pinned procedure path/hash;
 * this coordinator only renews live attestation and activates that exact
 * admission for the represented run step before action reservation.
 */
export class RunScopedReviewedCandidateLinuxProcedurePublisher
implements AutonomousPostReconCandidateProcedureActivationPort {
  constructor(private readonly options: Readonly<{
    database: SqliteDatabase;
    loadedProfile: LoadedTrustedJson<ReviewedRealCandidateLinuxProfile>;
    bridge: RunScopedReviewedCandidateLinuxProcedureActivationBridge;
  }>) {
    if (
      options.bridge.bindingId !== options.loadedProfile.value.bindingId
      || options.bridge.profileSha256
        !== options.loadedProfile.receipt.sourceSha256
    ) {
      throw new Error(
        "Procedure publisher and activation bridge do not share the reviewed profile",
      );
    }
  }

  async activate(input: Readonly<{
    missionId: string;
    runId: string;
    planId: string;
    stepId: string;
    attackAttemptId: string;
    targetNodeId: string;
    exactTarget: string;
    scriptArtifactId: string;
    exploitOutcomeObserverSpecId: string;
    postExploitSpecId: string;
    representedActionBindingHash: string;
  }>, runtimeSignal: AbortSignal): Promise<void> {
    if (runtimeSignal.aborted) {
      reject(
        "activation_stale",
        "Candidate procedure activation was cancelled before it started",
      );
    }
    const admission = this.options.database.prepare(`
      SELECT * FROM reviewed_candidate_linux_procedure_admissions
      WHERE run_id = ?
        AND script_artifact_id = ?
        AND post_exploit_spec_id = ?
      LIMIT 1
    `).get(
      input.runId,
      input.scriptArtifactId,
      input.postExploitSpecId,
    ) as AdmissionRow | undefined;
    if (
      !admission
      || admission.status !== "admitted"
      || admission.mission_id !== input.missionId
      || admission.run_id !== input.runId
      || admission.script_artifact_id !== input.scriptArtifactId
      || admission.exploit_outcome_observer_spec_id
        !== input.exploitOutcomeObserverSpecId
      || admission.post_exploit_spec_id !== input.postExploitSpecId
      || admission.profile_id
        !== this.options.loadedProfile.value.profileId
      || admission.profile_sha256
        !== this.options.loadedProfile.receipt.sourceSha256
      || admission.transport_binding_id
        !== this.options.loadedProfile.value.bindingId
      || admission.procedure_executable_path
        !== this.options.loadedProfile.value.procedure.executablePath
      || admission.procedure_executable_sha256
        !== this.options.loadedProfile.value.procedure.executableSha256
    ) {
      reject(
        "activation_scope_invalid",
        "Procedure activation requires the exact immutable pre-plan provider admission",
      );
    }
    const bounded = new AbortController();
    const cancel = () => bounded.abort(runtimeSignal.reason);
    runtimeSignal.addEventListener("abort", cancel, { once: true });
    const timer = setTimeout(() => {
      bounded.abort(
        new Error("Candidate procedure activation exceeded 15 seconds"),
      );
    }, 15_000);
    try {
      await this.options.bridge.activate({
        missionId: input.missionId,
        runId: input.runId,
        planId: input.planId,
        stepId: input.stepId,
        attackAttemptId: input.attackAttemptId,
        targetNodeId: input.targetNodeId,
        exactTarget: input.exactTarget,
        scriptArtifactId: input.scriptArtifactId,
        postExploitSpecId: admission.post_exploit_spec_id,
        representedActionBindingHash:
          input.representedActionBindingHash,
        procedureAdmissionId: admission.id,
        procedureExecutablePath:
          admission.procedure_executable_path,
        procedureExecutableSha256:
          admission.procedure_executable_sha256,
        idempotencyKey:
          `runtime:${input.runId}:${input.attackAttemptId}:${admission.id}`,
        actor: {
          id: "system:autonomous-post-recon-procedure-activator",
          type: "system",
        },
      }, bounded.signal);
    } finally {
      clearTimeout(timer);
      runtimeSignal.removeEventListener("abort", cancel);
    }
  }
}

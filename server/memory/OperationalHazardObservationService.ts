import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { EventRepository } from "../events/EventRepository";
import type { JsonValue } from "../events/types";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import type { OperationalActor } from "../intelligence-v24/types";
import { ActionRepository, type DurableAction } from "../orchestration";
import {
  AttackKnowledgeCompiler,
  type AttackKnowledgeCompileResult,
  type OperationalHazardKnowledge,
} from "../migration/AttackKnowledgeCompiler";
import { canonicalJson } from "../orchestration/serialization";

const SHA256 = /^[a-f0-9]{64}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;
const RESET_EVENT_TYPE = "operational_hazard.reset_verified";
const AGGREGATE_EVENT_TYPE = "operational_hazard.aggregate_reset_minimum_reported";
const RESET_RUNTIME_CONTRACT_SCHEMA = "ti_scale.operational_hazard_reset/v1";
const RESET_PROOF_SCHEMA = "ti_scale.operational_reset/v1";
const RESET_EVALUATOR = "local-operational-reset-evaluator";
const HEALTH_PROOF_SCHEMA = "ti_scale.operational_health/v1";
const RESET_CONTROL_RECEIPT_SCHEMA = "ti_scale.reset_control_receipt/v1";
const RESET_CONTROL_RECEIPT_ISSUER = "local-reset-controller";

function isSqliteBusy(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as { readonly code?: unknown; readonly errno?: unknown };
  if (
    typeof candidate.code === "string"
    && (candidate.code === "SQLITE_BUSY" || candidate.code.startsWith("SQLITE_BUSY_"))
  ) {
    return true;
  }
  // SQLite extended result codes retain the primary result in the low byte.
  return typeof candidate.errno === "number" && (candidate.errno & 0xff) === 5;
}

interface AttemptRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly status: string;
  readonly target_asset_id: string | null;
  readonly target_service_id: string | null;
}

interface EventRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly event_type: string;
  readonly occurred_at: string;
  readonly payload_json: string;
}

interface RecoveryActionRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly status: string;
  readonly action_type: string;
  readonly normalized_arguments_json: string;
  readonly scoped_target: string | null;
}

interface OccurrenceRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly attack_attempt_id: string;
  readonly recovery_action_id: string;
  readonly recovery_event_id: string;
  readonly target_asset_id: string | null;
  readonly target_service_id: string | null;
  readonly target_context_fingerprint: string;
  readonly reset_control_receipt_id: string;
  readonly reset_control_receipt_hash: string;
  readonly evidence_ids_json: string;
  readonly bundle_id: string;
  readonly provenance_receipt_id: string;
  readonly knowledge_hash: string;
  readonly observed_at: string;
  readonly created_at: string;
  readonly request_hash: string;
}

interface AggregateRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly reported_minimum: number;
  readonly statement_event_id: string;
  readonly reported_at: string;
  readonly request_hash: string;
}

interface VerifiedResetEvidence {
  readonly rows: readonly { readonly id: string; readonly content_hash: string }[];
  readonly resetControlReceiptId: string;
  readonly resetControlReceiptFingerprint: string;
}

export interface OperationalResetControlReceipt {
  readonly id: string;
  readonly receiptKeyHash: string;
  readonly missionId: string;
  readonly runId: string;
  readonly recoveryActionId: string;
  readonly targetAssetId: string | null;
  readonly targetServiceId: string | null;
  readonly targetContextFingerprint: string;
  readonly receiptFingerprint: string;
  readonly postResetHealthEvidenceId: string;
  readonly issuedAt: string;
}

export interface OperationalResetAuthorization {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly recoveryActionId: string;
  readonly targetContextFingerprint: string;
  readonly expiresAt: string;
}

interface OperationalResetAuthorizationRow {
  readonly id: string;
  readonly authorization_key_hash: string;
  readonly authorization_hmac: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly recovery_action_id: string;
  readonly target_asset_id: string | null;
  readonly target_service_id: string | null;
  readonly target_context_fingerprint: string;
  readonly issued_by: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly created_at: string;
}

interface OperationalResetControlReceiptRow {
  readonly id: string;
  readonly receipt_key_hash: string;
  readonly receipt_hmac: string;
  readonly authorization_id: string;
  readonly mission_id: string;
  readonly run_id: string;
  readonly recovery_action_id: string;
  readonly target_asset_id: string | null;
  readonly target_service_id: string | null;
  readonly target_context_fingerprint: string;
  readonly controller_id_hash: string;
  readonly reset_operation_id_hash: string;
  readonly target_generation_id_hash: string;
  readonly receipt_fingerprint: string;
  readonly post_reset_health_evidence_id: string;
  readonly issued_by: string;
  readonly issued_at: string;
  readonly created_at: string;
}

export interface OperationalHazardResetEventPayload {
  readonly attackAttemptId: string;
  readonly recoveryActionId: string;
  readonly resetKind: "target_reset";
  readonly targetContextFingerprint: string;
  readonly resetControlReceiptId: string;
  readonly resetControlReceiptFingerprint: string;
  readonly verifiedEvidenceIds: readonly string[];
  readonly hazardNodeId?: string;
  readonly knowledge?: OperationalHazardKnowledge;
  readonly confidence?: number;
}

export interface OperationalHazardOccurrence {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly attackAttemptId: string;
  readonly recoveryActionId: string;
  readonly recoveryEventId: string;
  readonly targetContextFingerprint: string;
  readonly resetControlReceiptId: string;
  readonly resetControlReceiptHash: string;
  readonly verifiedEvidenceIds: readonly string[];
  readonly bundleId: string;
  readonly provenanceReceiptId: string;
  readonly knowledgeHash: string;
  readonly observedAt: string;
  readonly createdAt: string;
}

export interface OperationalHazardResetTotals {
  readonly missionId: string;
  readonly runId: string;
  readonly exactAttributableResetCount: number;
  readonly operatorReportedResetMinimum: number | null;
  readonly minimumUnattributedResetCount: number;
}

export interface RecordOperationalHazardOccurrenceResult {
  readonly occurrence: OperationalHazardOccurrence;
  readonly compile: Pick<AttackKnowledgeCompileResult,
    "status" | "bundleFingerprint" | "candidateIds" | "candidatesCreated" |
    "candidatesReused" | "edgeProposalsStaged" | "exactProcedureCounts">;
  readonly totals: OperationalHazardResetTotals;
  readonly replayed: boolean;
}

export interface OperationalHazardAggregateObservation {
  readonly id: string;
  readonly missionId: string;
  readonly runId: string;
  readonly reportedMinimum: number;
  readonly statementEventId: string;
  readonly reportedAt: string;
}

export class OperationalHazardObservationError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly category: "invalid_input" | "not_found" | "scope_conflict" |
      "evidence_insufficient" | "conflict" | "policy_denied" = "invalid_input",
  ) {
    super(message);
    this.name = "OperationalHazardObservationError";
  }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function secureSha256Equal(actual: unknown, expected: string): boolean {
  if (typeof actual !== "string" || !SHA256.test(actual) || !SHA256.test(expected)) return false;
  return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

export function operationalHazardTargetContextFingerprint(input: {
  readonly missionId: string;
  readonly runId: string;
  readonly targetAssetId: string | null;
  readonly targetServiceId: string | null;
}): string {
  if (!input.targetAssetId && !input.targetServiceId) {
    throw new OperationalHazardObservationError(
      "hazard_target_context_required",
      "An exact reset occurrence requires a canonical target asset or service",
      "evidence_insufficient",
    );
  }
  return sha256(canonicalJson({
    missionId: id(input.missionId, "Mission ID"),
    runId: id(input.runId, "Run ID"),
    targetAssetId: input.targetAssetId ? id(input.targetAssetId, "Target asset ID") : null,
    targetServiceId: input.targetServiceId ? id(input.targetServiceId, "Target service ID") : null,
  }));
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new OperationalHazardObservationError("hazard_observation_invalid", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function id(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9._:@/-]{1,300}$/u.test(value)) {
    throw new OperationalHazardObservationError("hazard_observation_invalid", `${label} is invalid`);
  }
  return value;
}

function ids(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) {
    throw new OperationalHazardObservationError("hazard_observation_invalid", `${label} must contain 1 through 100 canonical IDs`);
  }
  const result = [...new Set(value.map((item) => id(item, label)))];
  if (result.length !== value.length) {
    throw new OperationalHazardObservationError("hazard_observation_invalid", `${label} contains duplicates`);
  }
  return result.sort();
}

function confidence(value: unknown): number {
  if (value === undefined) return 0.8;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new OperationalHazardObservationError("hazard_observation_invalid", "confidence must be between 0 and 1");
  }
  return value;
}

function containsPublicModelAttribution(value: unknown): boolean {
  if (typeof value === "string") {
    return /(?:public[_ -]?model|public[_ -]?llm|provider[_ -]?turn|model[_ -]?self[_ -]?report|openai|anthropic|openrouter|gemini|grok|xai)/iu.test(value);
  }
  if (Array.isArray(value)) return value.some(containsPublicModelAttribution);
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).some(([key, item]) =>
      containsPublicModelAttribution(key) || containsPublicModelAttribution(item));
  }
  return false;
}

export interface ResetControlReceipt {
  readonly schema: typeof RESET_CONTROL_RECEIPT_SCHEMA;
  readonly issuer: typeof RESET_CONTROL_RECEIPT_ISSUER;
  readonly controllerId: string;
  readonly resetOperationId: string;
  readonly targetGenerationId: string;
  readonly authenticator: string;
}

export interface TrustedOperationalResetCompletion {
  readonly schema: "ti_scale.trusted_reset_completion/v1";
  readonly missionId: string;
  readonly runId: string;
  readonly recoveryActionId: string;
  readonly attackAttemptId: string;
  readonly targetContextFingerprint: string;
  readonly preReset: {
    readonly observedAt: string;
    readonly baselineRestored: false;
    readonly measurementHash: string;
  };
  readonly postReset: {
    readonly observedAt: string;
    readonly resetCompleted: true;
    readonly baselineRestored: true;
    readonly measurementHash: string;
  };
  readonly resetControlReceipt: ResetControlReceipt;
  readonly completionAuthenticator: string;
}

function resetControlReceipt(value: unknown): ResetControlReceipt {
  const receipt = object(value, "Reset-control receipt");
  const allowed = new Set([
    "schema", "issuer", "controllerId", "resetOperationId", "targetGenerationId", "authenticator",
  ]);
  if (Object.keys(receipt).some((key) => !allowed.has(key))) {
    throw new OperationalHazardObservationError(
      "hazard_reset_control_receipt_invalid",
      "The reset-control receipt contains unsupported fields",
      "evidence_insufficient",
    );
  }
  if (
    receipt.schema !== RESET_CONTROL_RECEIPT_SCHEMA
    || receipt.issuer !== RESET_CONTROL_RECEIPT_ISSUER
  ) {
    throw new OperationalHazardObservationError(
      "hazard_reset_control_receipt_invalid",
      "A trusted local reset-control receipt is required",
      "evidence_insufficient",
    );
  }
  const authenticator = id(receipt.authenticator, "Reset-control authenticator");
  if (!SHA256.test(authenticator)) {
    throw new OperationalHazardObservationError(
      "hazard_reset_control_receipt_invalid",
      "The reset-control receipt authenticator is invalid",
      "evidence_insufficient",
    );
  }
  return {
    schema: RESET_CONTROL_RECEIPT_SCHEMA,
    issuer: RESET_CONTROL_RECEIPT_ISSUER,
    controllerId: id(receipt.controllerId, "Reset controller ID"),
    resetOperationId: id(receipt.resetOperationId, "Reset operation ID"),
    targetGenerationId: id(receipt.targetGenerationId, "Target generation ID"),
    authenticator,
  };
}

function resetControlReceiptFingerprint(receipt: ResetControlReceipt): string {
  return sha256(canonicalJson({
    schema: receipt.schema,
    issuer: receipt.issuer,
    controllerId: receipt.controllerId,
    resetOperationId: receipt.resetOperationId,
    targetGenerationId: receipt.targetGenerationId,
  }));
}

export class OperationalResetControlAttestor {
  readonly #key: Buffer;

  constructor(hmacKey: string | Buffer) {
    this.#key = Buffer.isBuffer(hmacKey) ? Buffer.from(hmacKey) : Buffer.from(hmacKey, "utf8");
    if (this.#key.byteLength < 32) {
      throw new TypeError("Operational reset-control attestor key must contain at least 32 bytes");
    }
  }

  attest(input: {
    readonly controllerId: string;
    readonly resetOperationId: string;
    readonly targetGenerationId: string;
    readonly missionId: string;
    readonly runId: string;
    readonly recoveryActionId: string;
    readonly targetContextFingerprint: string;
  }): ResetControlReceipt {
    const claims = {
      schema: RESET_CONTROL_RECEIPT_SCHEMA,
      issuer: RESET_CONTROL_RECEIPT_ISSUER,
      controllerId: id(input.controllerId, "Reset controller ID"),
      resetOperationId: id(input.resetOperationId, "Reset operation ID"),
      targetGenerationId: id(input.targetGenerationId, "Target generation ID"),
    } as const;
    return {
      ...claims,
      authenticator: this.#authenticationFor(claims, input),
    };
  }

  verify(
    receipt: ResetControlReceipt,
    scope: {
      readonly missionId: string;
      readonly runId: string;
      readonly recoveryActionId: string;
      readonly targetContextFingerprint: string;
    },
  ): void {
    const expected = this.#authenticationFor(receipt, scope);
    if (!secureSha256Equal(receipt.authenticator, expected)) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_authentication_invalid",
        "The reset-control receipt was not authenticated by the trusted local reset controller for this exact action and target",
        "evidence_insufficient",
      );
    }
  }

  authenticateCompletion(
    completion: Omit<TrustedOperationalResetCompletion, "completionAuthenticator">,
  ): string {
    return createHmac("sha256", this.#key)
      .update(canonicalJson(completion))
      .digest("hex");
  }

  verifyCompletion(completion: TrustedOperationalResetCompletion): void {
    const { completionAuthenticator, ...claims } = completion;
    if (
      !secureSha256Equal(completionAuthenticator, this.authenticateCompletion(claims))
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_completion_authentication_invalid",
        "The complete local reset measurement envelope failed server-only authentication",
        "evidence_insufficient",
      );
    }
  }

  #authenticationFor(
    receipt: Pick<ResetControlReceipt, "schema" | "issuer" | "controllerId" | "resetOperationId" | "targetGenerationId">,
    scope: {
      readonly missionId: string;
      readonly runId: string;
      readonly recoveryActionId: string;
      readonly targetContextFingerprint: string;
    },
  ): string {
    return createHmac("sha256", this.#key).update(canonicalJson({
      schema: receipt.schema,
      issuer: receipt.issuer,
      controllerId: receipt.controllerId,
      resetOperationId: receipt.resetOperationId,
      targetGenerationId: receipt.targetGenerationId,
      missionId: id(scope.missionId, "Mission ID"),
      runId: id(scope.runId, "Run ID"),
      recoveryActionId: id(scope.recoveryActionId, "Recovery action ID"),
      targetContextFingerprint: id(scope.targetContextFingerprint, "Target-context fingerprint"),
    })).digest("hex");
  }
}

/**
 * Adapter-side boundary. A reviewed local reset controller calls this only
 * after its own control-plane operation and local health measurements finish.
 * Provider/tool prose never receives the server key and cannot construct this
 * authenticated completion envelope.
 */
export class TrustedLocalResetControllerAdapter {
  readonly #attestor: OperationalResetControlAttestor;

  constructor(hmacKey: string | Buffer) {
    this.#attestor = new OperationalResetControlAttestor(hmacKey);
  }

  attestCompletion(input: Omit<TrustedOperationalResetCompletion,
    "schema" | "resetControlReceipt" | "completionAuthenticator"> & {
    readonly controllerId: string;
    readonly resetOperationId: string;
    readonly targetGenerationId: string;
  }): TrustedOperationalResetCompletion {
    const allowedKeys = new Set([
      "missionId", "runId", "recoveryActionId", "attackAttemptId",
      "targetContextFingerprint", "preReset", "postReset", "controllerId",
      "resetOperationId", "targetGenerationId",
    ]);
    if (Object.keys(object(input, "Trusted reset-controller input"))
      .some((key) => !allowedKeys.has(key))) {
      throw new OperationalHazardObservationError(
        "hazard_reset_completion_invalid",
        "The trusted reset-controller input contains unsupported fields",
        "evidence_insufficient",
      );
    }
    if (
      input.preReset.baselineRestored !== false
      || input.postReset.baselineRestored !== true
      || input.postReset.resetCompleted !== true
      || !SHA256.test(input.preReset.measurementHash)
      || !SHA256.test(input.postReset.measurementHash)
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_health_pair_invalid",
        "The trusted local reset controller requires a down-before and restored-after measurement pair",
        "evidence_insufficient",
      );
    }
    const completion = {
      schema: "ti_scale.trusted_reset_completion/v1",
      missionId: id(input.missionId, "Mission ID"),
      runId: id(input.runId, "Run ID"),
      recoveryActionId: id(input.recoveryActionId, "Recovery action ID"),
      attackAttemptId: id(input.attackAttemptId, "Attack-attempt ID"),
      targetContextFingerprint: id(input.targetContextFingerprint, "Target-context fingerprint"),
      preReset: input.preReset,
      postReset: input.postReset,
      resetControlReceipt: this.#attestor.attest({
        controllerId: input.controllerId,
        resetOperationId: input.resetOperationId,
        targetGenerationId: input.targetGenerationId,
        missionId: input.missionId,
        runId: input.runId,
        recoveryActionId: input.recoveryActionId,
        targetContextFingerprint: input.targetContextFingerprint,
      }),
    } as const;
    return {
      ...completion,
      completionAuthenticator: this.#attestor.authenticateCompletion(completion),
    };
  }
}

/** Writes only normalized local health evidence from an authenticated adapter envelope. */
export class OperationalResetHealthEvidenceRecorder {
  readonly #attestor: OperationalResetControlAttestor;

  constructor(private readonly database: SqliteDatabase, hmacKey: string | Buffer) {
    this.#attestor = new OperationalResetControlAttestor(hmacKey);
  }

  record(action: DurableAction, value: unknown): readonly [string, string] | undefined {
    if (!["target_reset", "environment_reset"].includes(action.actionType)) {
      if (value !== undefined) {
        throw new OperationalHazardObservationError(
          "hazard_reset_completion_unexpected",
          "A non-reset action cannot submit a reset-controller completion envelope",
          "scope_conflict",
        );
      }
      return undefined;
    }
    const rawEnvelope = object(value, "Trusted reset-controller completion");
    const envelopeKeys = new Set([
      "schema", "missionId", "runId", "recoveryActionId", "attackAttemptId",
      "targetContextFingerprint", "preReset", "postReset", "resetControlReceipt",
      "completionAuthenticator",
    ]);
    if (Object.keys(rawEnvelope).some((key) => !envelopeKeys.has(key))) {
      throw new OperationalHazardObservationError(
        "hazard_reset_completion_invalid",
        "The reset-controller completion contains unsupported fields",
        "evidence_insufficient",
      );
    }
    const envelope = rawEnvelope as unknown as TrustedOperationalResetCompletion;
    if (
      envelope.schema !== "ti_scale.trusted_reset_completion/v1"
      || envelope.missionId !== action.missionId || envelope.runId !== action.runId
      || envelope.recoveryActionId !== action.id
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_completion_scope_mismatch",
        "The trusted reset-controller completion does not match this exact action and run",
        "scope_conflict",
      );
    }
    const contract = object(action.arguments.operationalHazardReset, "Operational-hazard reset contract");
    const attackAttemptId = id(contract.attackAttemptId, "Attack-attempt ID");
    const preEvidenceId = id(contract.preResetHealthEvidenceId, "Pre-reset health evidence ID");
    const postEvidenceId = id(contract.postResetHealthEvidenceId, "Post-reset health evidence ID");
    if (envelope.attackAttemptId !== attackAttemptId) {
      throw new OperationalHazardObservationError(
        "hazard_reset_completion_scope_mismatch",
        "The trusted reset-controller completion names another attack attempt",
        "scope_conflict",
      );
    }
    const attempt = this.database.prepare(`
      SELECT target_asset_id, target_service_id FROM attack_attempts
      WHERE id = ? AND mission_id = ? AND run_id = ?
    `).get(attackAttemptId, action.missionId, action.runId) as {
      readonly target_asset_id: string | null; readonly target_service_id: string | null;
    } | undefined;
    if (!attempt) {
      throw new OperationalHazardObservationError(
        "hazard_attack_attempt_not_found",
        "The reset-controller completion has no canonical attack attempt",
        "not_found",
      );
    }
    const targetContextFingerprint = operationalHazardTargetContextFingerprint({
      missionId: action.missionId,
      runId: action.runId,
      targetAssetId: attempt.target_asset_id,
      targetServiceId: attempt.target_service_id,
    });
    if (envelope.targetContextFingerprint !== targetContextFingerprint) {
      throw new OperationalHazardObservationError(
        "hazard_reset_completion_scope_mismatch",
        "The reset-controller completion names another canonical target context",
        "scope_conflict",
      );
    }
    const pre = object(envelope.preReset, "Pre-reset measurement");
    const post = object(envelope.postReset, "Post-reset measurement");
    if (
      Object.keys(pre).some((key) => !["observedAt", "baselineRestored", "measurementHash"].includes(key))
      || Object.keys(post).some((key) => !["observedAt", "resetCompleted", "baselineRestored", "measurementHash"].includes(key))
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_completion_invalid",
        "Reset health measurements contain unsupported fields",
        "evidence_insufficient",
      );
    }
    if (
      pre.baselineRestored !== false || post.baselineRestored !== true
      || post.resetCompleted !== true || typeof pre.observedAt !== "string"
      || typeof post.observedAt !== "string" || !SHA256.test(String(pre.measurementHash))
      || !SHA256.test(String(post.measurementHash))
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_health_pair_invalid",
        "The authenticated reset completion does not contain a valid down-before and restored-after local measurement pair",
        "evidence_insufficient",
      );
    }
    const receipt = resetControlReceipt(envelope.resetControlReceipt);
    this.#attestor.verifyCompletion(envelope);
    this.#attestor.verify(receipt, {
      missionId: action.missionId,
      runId: action.runId,
      recoveryActionId: action.id,
      targetContextFingerprint,
    });
    const startedAt = Date.parse(action.startedAt ?? "");
    const endedAt = Date.parse(action.endedAt ?? "");
    const preAt = Date.parse(String(pre.observedAt));
    const postAt = Date.parse(String(post.observedAt));
    if (
      !Number.isFinite(startedAt) || !Number.isFinite(endedAt)
      || !Number.isFinite(preAt) || !Number.isFinite(postAt)
      || preAt < startedAt || preAt >= postAt || postAt > endedAt
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_health_timeline_invalid",
        "Reset health measurements must be ordered inside the exact canonical action interval",
        "evidence_insufficient",
      );
    }
    const receiptFingerprint = resetControlReceiptFingerprint(receipt);
    this.#insertHealthEvidence({
      id: preEvidenceId,
      action,
      acquiredAt: String(pre.observedAt),
      contentHash: String(pre.measurementHash),
      provenance: {
        healthAssessment: {
          schema: HEALTH_PROOF_SCHEMA,
          phase: "before_reset",
          baselineRestored: false,
          attackAttemptId,
          recoveryActionId: action.id,
          targetContextFingerprint,
        },
      },
    });
    this.#insertHealthEvidence({
      id: postEvidenceId,
      action,
      acquiredAt: String(post.observedAt),
      contentHash: String(post.measurementHash),
      provenance: {
        healthAssessment: {
          schema: HEALTH_PROOF_SCHEMA,
          phase: "after_reset",
          resetCompleted: true,
          baselineRestored: true,
          attackAttemptId,
          recoveryActionId: action.id,
          targetContextFingerprint,
          resetControlReceipt: receipt,
          resetControlReceiptFingerprint: receiptFingerprint,
        },
      },
    });
    return [preEvidenceId, postEvidenceId];
  }

  #insertHealthEvidence(input: {
    readonly id: string;
    readonly action: DurableAction;
    readonly acquiredAt: string;
    readonly contentHash: string;
    readonly provenance: Readonly<Record<string, unknown>>;
  }): void {
    if (!Number.isFinite(Date.parse(input.acquiredAt))) {
      throw new OperationalHazardObservationError(
        "hazard_reset_health_pair_invalid",
        "Local reset health measurement timestamp is invalid",
        "evidence_insufficient",
      );
    }
    const provenanceJson = canonicalJson(input.provenance);
    const existing = this.database.prepare(`
      SELECT mission_id, run_id, action_id, evidence_type, content_hash,
        provenance_json, verification_state, source, created_by
      FROM evidence WHERE id = ?
    `).get(input.id) as LocalHealthProofRow | undefined;
    if (existing) {
      if (
        existing.mission_id !== input.action.missionId || existing.run_id !== input.action.runId
        || existing.action_id !== input.action.id || existing.evidence_type !== "health_check_result"
        || existing.content_hash !== input.contentHash || existing.verification_state !== "verified"
        || existing.source !== RESET_EVALUATOR || existing.created_by !== RESET_EVALUATOR
        || canonicalJson(JSON.parse(existing.provenance_json)) !== provenanceJson
      ) {
        throw new OperationalHazardObservationError(
          "hazard_reset_health_evidence_conflict",
          "The deterministic local health evidence identity already names different content",
          "conflict",
        );
      }
      return;
    }
    this.database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, action_id, source, acquired_at,
        target, evidence_type, content_hash, provenance_json, confidence,
        sensitivity, verification_state, summary, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'health_check_result', ?, ?, 1,
        'private', 'verified', ?, ?, ?)
    `).run(
      input.id, input.action.missionId, input.action.runId, input.action.stepId,
      input.action.id, RESET_EVALUATOR, input.acquiredAt, input.action.target,
      input.contentHash, provenanceJson,
      "Authenticated local reset-controller health measurement",
      RESET_EVALUATOR, input.acquiredAt,
    );
    this.database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'verified', ?, ?, ?)
    `).run(
      `chain_${sha256(`verified\0${input.id}`)}`,
      input.id,
      RESET_EVALUATOR,
      canonicalJson({ evaluator: RESET_EVALUATOR, schema: HEALTH_PROOF_SCHEMA }),
      input.acquiredAt,
    );
  }
}

function mapOccurrence(row: OccurrenceRow): OperationalHazardOccurrence {
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    attackAttemptId: row.attack_attempt_id,
    recoveryActionId: row.recovery_action_id,
    recoveryEventId: row.recovery_event_id,
    targetContextFingerprint: row.target_context_fingerprint,
    resetControlReceiptId: row.reset_control_receipt_id,
    resetControlReceiptHash: row.reset_control_receipt_hash,
    verifiedEvidenceIds: JSON.parse(row.evidence_ids_json) as string[],
    bundleId: row.bundle_id,
    provenanceReceiptId: row.provenance_receipt_id,
    knowledgeHash: row.knowledge_hash,
    observedAt: row.observed_at,
    createdAt: row.created_at,
  };
}

function mapAggregate(row: AggregateRow): OperationalHazardAggregateObservation {
  return {
    id: row.id,
    missionId: row.mission_id,
    runId: row.run_id,
    reportedMinimum: row.reported_minimum,
    statementEventId: row.statement_event_id,
    reportedAt: row.reported_at,
  };
}

function mapResetControlReceipt(row: OperationalResetControlReceiptRow): OperationalResetControlReceipt {
  return {
    id: row.id,
    receiptKeyHash: row.receipt_key_hash,
    missionId: row.mission_id,
    runId: row.run_id,
    recoveryActionId: row.recovery_action_id,
    targetAssetId: row.target_asset_id,
    targetServiceId: row.target_service_id,
    targetContextFingerprint: row.target_context_fingerprint,
    receiptFingerprint: row.receipt_fingerprint,
    postResetHealthEvidenceId: row.post_reset_health_evidence_id,
    issuedAt: row.issued_at,
  };
}

/**
 * Server-only issuance boundary for a physical reset receipt. Public models,
 * tools, and raw evidence can describe a reset, but only this HMAC-bound row
 * can authorize an exact physical-reset count.
 */
export class OperationalResetControlReceiptIssuer {
  readonly #key: Buffer;

  constructor(private readonly database: SqliteDatabase, hmacKey: string | Buffer) {
    this.#key = Buffer.isBuffer(hmacKey) ? Buffer.from(hmacKey) : Buffer.from(hmacKey, "utf8");
    if (this.#key.byteLength < 32) {
      throw new TypeError("Operational reset-control receipt HMAC key must contain at least 32 bytes");
    }
  }

  authorizeBeforeDispatch(action: DurableAction, ttlMs = 60 * 60 * 1_000): OperationalResetAuthorization | undefined {
    if (!["target_reset", "environment_reset"].includes(action.actionType)) return undefined;
    if (action.status !== "running") {
      throw new OperationalHazardObservationError(
        "hazard_reset_authorization_timing_invalid",
        "A physical reset must receive its one-use server authorization before dispatch",
        "policy_denied",
      );
    }
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 24 * 60 * 60 * 1_000) {
      throw new RangeError("Reset authorization TTL must be 1000 through 86400000 ms");
    }
    const contract = object(action.arguments.operationalHazardReset, "Operational-hazard reset contract");
    if (contract.schemaVersion !== RESET_RUNTIME_CONTRACT_SCHEMA) {
      throw new OperationalHazardObservationError(
        "hazard_reset_contract_invalid",
        "Reset authorization requires the exact represented reset-contract schema",
        "evidence_insufficient",
      );
    }
    const attemptId = id(contract.attackAttemptId, "Attack-attempt ID");
    const attempt = this.database.prepare(`
      SELECT mission_id, run_id, target_asset_id, target_service_id
      FROM attack_attempts WHERE id = ?
    `).get(attemptId) as {
      readonly mission_id: string; readonly run_id: string;
      readonly target_asset_id: string | null; readonly target_service_id: string | null;
    } | undefined;
    if (
      !attempt || attempt.mission_id !== action.missionId || attempt.run_id !== action.runId
      || (contract.targetAssetId ?? null) !== attempt.target_asset_id
      || (contract.targetServiceId ?? null) !== attempt.target_service_id
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_target_binding_mismatch",
        "Reset authorization does not match the exact failed attempt and target",
        "scope_conflict",
      );
    }
    const targetContextFingerprint = operationalHazardTargetContextFingerprint({
      missionId: action.missionId,
      runId: action.runId,
      targetAssetId: attempt.target_asset_id,
      targetServiceId: attempt.target_service_id,
    });
    const issuedAt = action.startedAt ?? action.createdAt;
    const expiresAt = new Date(Date.parse(issuedAt) + ttlMs).toISOString();
    const authorizationKeyHash = this.#hmac(canonicalJson({
      kind: "one_use_reset_authorization",
      missionId: action.missionId,
      runId: action.runId,
      recoveryActionId: action.id,
      targetContextFingerprint,
    }));
    const authorizationId = `resetauth_${authorizationKeyHash}`;
    const signed = {
      id: authorizationId,
      authorizationKeyHash,
      missionId: action.missionId,
      runId: action.runId,
      recoveryActionId: action.id,
      targetAssetId: attempt.target_asset_id,
      targetServiceId: attempt.target_service_id,
      targetContextFingerprint,
      issuedBy: RESET_CONTROL_RECEIPT_ISSUER,
      issuedAt,
      expiresAt,
    };
    const authorizationHmac = this.#hmac(canonicalJson(signed));
    this.database.prepare(`
      INSERT OR IGNORE INTO operational_reset_authorizations (
        id, authorization_key_hash, authorization_hmac, mission_id, run_id,
        recovery_action_id, target_asset_id, target_service_id,
        target_context_fingerprint, issued_by, issued_at, expires_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      authorizationId, authorizationKeyHash, authorizationHmac,
      action.missionId, action.runId, action.id,
      attempt.target_asset_id, attempt.target_service_id, targetContextFingerprint,
      RESET_CONTROL_RECEIPT_ISSUER, issuedAt, expiresAt, issuedAt,
    );
    const row = this.#authorizationForAction(action.id);
    if (!row || !secureSha256Equal(row.authorization_hmac, authorizationHmac) || !this.#authorizationMatches(row, signed)) {
      throw new OperationalHazardObservationError(
        "hazard_reset_authorization_conflict",
        "The canonical reset action already names a different one-use reset authorization",
        "conflict",
      );
    }
    return {
      id: row.id,
      missionId: row.mission_id,
      runId: row.run_id,
      recoveryActionId: row.recovery_action_id,
      targetContextFingerprint: row.target_context_fingerprint,
      expiresAt: row.expires_at,
    };
  }

  issueFromCompletedReset(action: DurableAction): OperationalResetControlReceipt {
    if (action.status !== "succeeded" || !["target_reset", "environment_reset"].includes(action.actionType)) {
      throw new OperationalHazardObservationError(
        "hazard_recovery_action_invalid",
        "A reset-control receipt requires one succeeded canonical reset action",
        "evidence_insufficient",
      );
    }
    const contract = object(action.arguments.operationalHazardReset, "Operational-hazard reset contract");
    const attemptId = id(contract.attackAttemptId, "Attack-attempt ID");
    const postEvidenceId = id(contract.postResetHealthEvidenceId, "Post-reset health evidence ID");
    const attempt = this.database.prepare(`
      SELECT mission_id, run_id, target_asset_id, target_service_id
      FROM attack_attempts WHERE id = ?
    `).get(attemptId) as {
      readonly mission_id: string; readonly run_id: string;
      readonly target_asset_id: string | null; readonly target_service_id: string | null;
    } | undefined;
    if (
      !attempt || attempt.mission_id !== action.missionId || attempt.run_id !== action.runId
      || (contract.targetAssetId ?? null) !== attempt.target_asset_id
      || (contract.targetServiceId ?? null) !== attempt.target_service_id
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_target_binding_mismatch",
        "The reset-control receipt does not match the exact failed attempt and target",
        "scope_conflict",
      );
    }
    const targetContextFingerprint = operationalHazardTargetContextFingerprint({
      missionId: action.missionId,
      runId: action.runId,
      targetAssetId: attempt.target_asset_id,
      targetServiceId: attempt.target_service_id,
    });
    const authorization = this.#authorizationForAction(action.id);
    if (!authorization) {
      throw new OperationalHazardObservationError(
        "hazard_reset_authorization_required",
        "No one-use server authorization was issued before this reset action was dispatched",
        "policy_denied",
      );
    }
    this.#verifyAuthorization(authorization, {
      action,
      targetAssetId: attempt.target_asset_id,
      targetServiceId: attempt.target_service_id,
      targetContextFingerprint,
    });
    const post = this.database.prepare(`
      SELECT mission_id, run_id, action_id, evidence_type, provenance_json,
        verification_state, source, created_by
      FROM evidence WHERE id = ?
    `).get(postEvidenceId) as {
      readonly mission_id: string; readonly run_id: string | null; readonly action_id: string | null;
      readonly evidence_type: string; readonly provenance_json: string;
      readonly verification_state: string; readonly source: string; readonly created_by: string;
    } | undefined;
    if (
      !post || post.mission_id !== action.missionId || post.run_id !== action.runId
      || post.action_id !== action.id || post.evidence_type !== "health_check_result"
      || post.verification_state !== "verified" || post.source !== RESET_EVALUATOR
      || post.created_by !== RESET_EVALUATOR
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_evidence_invalid",
        "Receipt issuance requires typed post-reset health evidence from the trusted local evaluator",
        "evidence_insufficient",
      );
    }
    const provenance = object(JSON.parse(post.provenance_json), "Post-reset health provenance");
    const health = object(provenance.healthAssessment, "Post-reset health assessment");
    if (
      health.schema !== HEALTH_PROOF_SCHEMA || health.phase !== "after_reset"
      || health.resetCompleted !== true || health.baselineRestored !== true
      || health.attackAttemptId !== attemptId || health.recoveryActionId !== action.id
      || health.targetContextFingerprint !== targetContextFingerprint
      || containsPublicModelAttribution(provenance)
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_evidence_invalid",
        "Post-reset health evidence does not attest this exact completed reset and restored baseline",
        "evidence_insufficient",
      );
    }
    const custody = this.database.prepare(`
      SELECT 1 FROM evidence_chain_events WHERE evidence_id = ? AND event_type = 'verified' LIMIT 1
    `).get(postEvidenceId);
    if (!custody) {
      throw new OperationalHazardObservationError(
        "hazard_reset_health_custody_required",
        "Post-reset health evidence is missing immutable verification custody",
        "evidence_insufficient",
      );
    }
    const controlReceipt = resetControlReceipt(health.resetControlReceipt);
    new OperationalResetControlAttestor(this.#key).verify(controlReceipt, {
      missionId: action.missionId,
      runId: action.runId,
      recoveryActionId: action.id,
      targetContextFingerprint,
    });
    const receiptFingerprint = resetControlReceiptFingerprint(controlReceipt);
    if (health.resetControlReceiptFingerprint !== receiptFingerprint) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_invalid",
        "The typed post-reset evidence does not match its reset-control receipt",
        "evidence_insufficient",
      );
    }
    const hashes = {
      controllerIdHash: this.#hmac(`controller\0${controlReceipt.controllerId}`),
      resetOperationIdHash: this.#hmac(
        `operation\0${controlReceipt.controllerId}\0${controlReceipt.resetOperationId}`,
      ),
      targetGenerationIdHash: this.#hmac(
        `generation\0${controlReceipt.controllerId}\0${targetContextFingerprint}\0${controlReceipt.targetGenerationId}`,
      ),
    };
    const receiptKeyHash = this.#hmac(canonicalJson({
      kind: "physical_reset",
      targetContextFingerprint,
      ...hashes,
    }));
    const receiptId = `resetctl_${receiptKeyHash}`;
    const issuedAt = action.endedAt ?? new Date().toISOString();
    const signed = {
      id: receiptId,
      receiptKeyHash,
      authorizationId: authorization.id,
      missionId: action.missionId,
      runId: action.runId,
      recoveryActionId: action.id,
      targetAssetId: attempt.target_asset_id,
      targetServiceId: attempt.target_service_id,
      targetContextFingerprint,
      ...hashes,
      receiptFingerprint,
      postResetHealthEvidenceId: postEvidenceId,
      issuedBy: RESET_CONTROL_RECEIPT_ISSUER,
      issuedAt,
    };
    const receiptHmac = this.#hmac(canonicalJson(signed));
    this.database.prepare(`
      INSERT OR IGNORE INTO operational_reset_control_receipts (
        id, receipt_key_hash, receipt_hmac, authorization_id, mission_id, run_id,
        recovery_action_id, target_asset_id, target_service_id,
        target_context_fingerprint, controller_id_hash, reset_operation_id_hash,
        target_generation_id_hash, receipt_fingerprint,
        post_reset_health_evidence_id, issued_by, issued_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      receiptId, receiptKeyHash, receiptHmac, authorization.id, action.missionId, action.runId,
      action.id, attempt.target_asset_id, attempt.target_service_id,
      targetContextFingerprint, hashes.controllerIdHash, hashes.resetOperationIdHash,
      hashes.targetGenerationIdHash, receiptFingerprint, postEvidenceId,
      RESET_CONTROL_RECEIPT_ISSUER, issuedAt, issuedAt,
    );
    const row = this.database.prepare(`
      SELECT * FROM operational_reset_control_receipts WHERE id = ?
    `).get(receiptId) as OperationalResetControlReceiptRow | undefined;
    if (!row || !secureSha256Equal(row.receipt_hmac, receiptHmac) || !this.#matches(row, signed)) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_reused",
        "This physical reset operation or target generation is already bound to another canonical action",
        "conflict",
      );
    }
    return mapResetControlReceipt(row);
  }

  verify(input: {
    readonly receiptId: string;
    readonly recoveryActionId: string;
    readonly targetContextFingerprint: string;
    readonly receiptFingerprint: string;
  }): OperationalResetControlReceipt {
    const row = this.database.prepare(`
      SELECT * FROM operational_reset_control_receipts WHERE id = ?
    `).get(id(input.receiptId, "Reset-control receipt ID")) as OperationalResetControlReceiptRow | undefined;
    if (!row) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_not_issued",
        "No canonical server-issued reset-control receipt exists for this claimed reset",
        "evidence_insufficient",
      );
    }
    const signed = {
      id: row.id,
      receiptKeyHash: row.receipt_key_hash,
      authorizationId: row.authorization_id,
      missionId: row.mission_id,
      runId: row.run_id,
      recoveryActionId: row.recovery_action_id,
      targetAssetId: row.target_asset_id,
      targetServiceId: row.target_service_id,
      targetContextFingerprint: row.target_context_fingerprint,
      controllerIdHash: row.controller_id_hash,
      resetOperationIdHash: row.reset_operation_id_hash,
      targetGenerationIdHash: row.target_generation_id_hash,
      receiptFingerprint: row.receipt_fingerprint,
      postResetHealthEvidenceId: row.post_reset_health_evidence_id,
      issuedBy: row.issued_by,
      issuedAt: row.issued_at,
    };
    if (
      !secureSha256Equal(row.receipt_hmac, this.#hmac(canonicalJson(signed)))
      || row.recovery_action_id !== input.recoveryActionId
      || row.target_context_fingerprint !== input.targetContextFingerprint
      || row.receipt_fingerprint !== input.receiptFingerprint
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_signature_invalid",
        "The reset-control receipt failed its server-only authenticity or scope check",
        "evidence_insufficient",
      );
    }
    return mapResetControlReceipt(row);
  }

  #matches(row: OperationalResetControlReceiptRow, signed: Readonly<Record<string, unknown>>): boolean {
    return row.receipt_key_hash === signed.receiptKeyHash
      && row.authorization_id === signed.authorizationId
      && row.mission_id === signed.missionId && row.run_id === signed.runId
      && row.recovery_action_id === signed.recoveryActionId
      && row.target_asset_id === signed.targetAssetId && row.target_service_id === signed.targetServiceId
      && row.target_context_fingerprint === signed.targetContextFingerprint
      && row.controller_id_hash === signed.controllerIdHash
      && row.reset_operation_id_hash === signed.resetOperationIdHash
      && row.target_generation_id_hash === signed.targetGenerationIdHash
      && row.receipt_fingerprint === signed.receiptFingerprint
      && row.post_reset_health_evidence_id === signed.postResetHealthEvidenceId
      && row.issued_by === signed.issuedBy && row.issued_at === signed.issuedAt;
  }

  #hmac(value: string): string {
    return createHmac("sha256", this.#key).update(value, "utf8").digest("hex");
  }

  #authorizationForAction(actionId: string): OperationalResetAuthorizationRow | undefined {
    return this.database.prepare(`
      SELECT * FROM operational_reset_authorizations WHERE recovery_action_id = ?
    `).get(actionId) as OperationalResetAuthorizationRow | undefined;
  }

  #authorizationMatches(
    row: OperationalResetAuthorizationRow,
    signed: Readonly<Record<string, unknown>>,
  ): boolean {
    return row.authorization_key_hash === signed.authorizationKeyHash
      && row.mission_id === signed.missionId && row.run_id === signed.runId
      && row.recovery_action_id === signed.recoveryActionId
      && row.target_asset_id === signed.targetAssetId && row.target_service_id === signed.targetServiceId
      && row.target_context_fingerprint === signed.targetContextFingerprint
      && row.issued_by === signed.issuedBy && row.issued_at === signed.issuedAt
      && row.expires_at === signed.expiresAt;
  }

  #verifyAuthorization(
    row: OperationalResetAuthorizationRow,
    input: {
      readonly action: DurableAction;
      readonly targetAssetId: string | null;
      readonly targetServiceId: string | null;
      readonly targetContextFingerprint: string;
    },
  ): void {
    const signed = {
      id: row.id,
      authorizationKeyHash: row.authorization_key_hash,
      missionId: row.mission_id,
      runId: row.run_id,
      recoveryActionId: row.recovery_action_id,
      targetAssetId: row.target_asset_id,
      targetServiceId: row.target_service_id,
      targetContextFingerprint: row.target_context_fingerprint,
      issuedBy: row.issued_by,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
    };
    if (
      !secureSha256Equal(row.authorization_hmac, this.#hmac(canonicalJson(signed)))
      || row.mission_id !== input.action.missionId || row.run_id !== input.action.runId
      || row.recovery_action_id !== input.action.id
      || row.target_asset_id !== input.targetAssetId || row.target_service_id !== input.targetServiceId
      || row.target_context_fingerprint !== input.targetContextFingerprint
      || Date.parse(row.expires_at) < Date.parse(input.action.endedAt ?? new Date().toISOString())
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_authorization_invalid",
        "The one-use reset authorization failed its server-only signature, scope, or expiry check",
        "policy_denied",
      );
    }
  }
}

/**
 * Trusted local boundary that turns one canonical reset episode into one and
 * only one compiler receipt. It never confirms, verifies, or promotes the
 * resulting memory candidates.
 */
export class OperationalHazardObservationService {
  readonly #key: Buffer;
  readonly #clock: () => Date;
  readonly #compiler: AttackKnowledgeCompiler;
  readonly #events: EventRepository;
  readonly #audit: AuditTrailWriter;
  readonly #resetReceipts: OperationalResetControlReceiptIssuer;

  constructor(
    private readonly database: SqliteDatabase,
    options: { readonly hmacKey: string | Buffer; readonly clock?: () => Date },
  ) {
    this.#key = Buffer.isBuffer(options.hmacKey)
      ? Buffer.from(options.hmacKey)
      : Buffer.from(options.hmacKey, "utf8");
    if (this.#key.byteLength < 32) {
      throw new TypeError("Operational hazard observation HMAC key must contain at least 32 bytes");
    }
    this.#clock = options.clock ?? (() => new Date());
    this.#compiler = new AttackKnowledgeCompiler(database, {
      receiptHmacKey: this.#key,
      clock: this.#clock,
    });
    this.#events = new EventRepository(database);
    this.#audit = new AuditTrailWriter(database);
    this.#resetReceipts = new OperationalResetControlReceiptIssuer(database, this.#key);
  }

  recordCanonicalReset(input: {
    readonly recoveryEventId: string;
    readonly actor: OperationalActor;
    readonly idempotencyKey: string;
  }): RecordOperationalHazardOccurrenceResult {
    const recoveryEventId = id(input.recoveryEventId, "Recovery event ID");
    const actorId = id(input.actor.id, "Actor ID");
    if (!IDEMPOTENCY_KEY.test(input.idempotencyKey)) {
      throw new OperationalHazardObservationError("hazard_observation_idempotency_required", "A valid 8-200 character idempotency key is required");
    }
    const event = this.#event(recoveryEventId);
    const payload = this.#payload(event);
    const attempt = this.#attempt(payload.attackAttemptId);
    this.#assertScope(attempt, event);
    const targetContextFingerprint = operationalHazardTargetContextFingerprint({
      missionId: attempt.mission_id,
      runId: attempt.run_id,
      targetAssetId: attempt.target_asset_id,
      targetServiceId: attempt.target_service_id,
    });
    if (payload.targetContextFingerprint !== targetContextFingerprint) {
      throw new OperationalHazardObservationError(
        "hazard_target_context_mismatch",
        "The reset event does not match the failed attempt's canonical target context",
        "scope_conflict",
      );
    }
    const recoveryAction = this.#recoveryAction(payload.recoveryActionId, attempt);
    const deterministicResetProofId = new OperationalHazardLocalResetEvaluator(this.database)
      .evaluateCompletedAction(new ActionRepository(this.database).get(recoveryAction.id));
    if (
      !deterministicResetProofId
      || payload.verifiedEvidenceIds.length !== 1
      || payload.verifiedEvidenceIds[0] !== deterministicResetProofId
    ) {
      throw new OperationalHazardObservationError(
        "hazard_observation_verified_local_evidence_required",
        "Only the deterministic proof derived from the exact typed local pre/post reset health pair may establish an exact reset",
        "evidence_insufficient",
      );
    }
    const evidence = this.#verifiedEvidence(
      attempt,
      recoveryAction.id,
      targetContextFingerprint,
      payload.verifiedEvidenceIds,
    );
    if (payload.resetControlReceiptFingerprint !== evidence.resetControlReceiptFingerprint) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_mismatch",
        "The reset event does not match the trusted local reset-control receipt",
        "evidence_insufficient",
      );
    }
    if (payload.resetControlReceiptId !== evidence.resetControlReceiptId) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_mismatch",
        "The reset event does not name the canonical server-issued reset-control receipt",
        "evidence_insufficient",
      );
    }
    const resetControlReceipt = this.#resetReceipts.verify({
      receiptId: evidence.resetControlReceiptId,
      recoveryActionId: recoveryAction.id,
      targetContextFingerprint,
      receiptFingerprint: evidence.resetControlReceiptFingerprint,
    });
    const resetControlReceiptHash = resetControlReceipt.receiptKeyHash;
    const knowledge = payload.knowledge ?? this.#knowledgeForHazard(payload.hazardNodeId, attempt.id);
    const normalizedKnowledge = this.#oneOccurrenceKnowledge(knowledge, evidence.rows.length);
    const knowledgeHash = sha256(canonicalJson(normalizedKnowledge));
    const occurrenceKeyHash = this.#hmac(`occurrence\0${resetControlReceiptHash}`);
    const requestKeyHash = this.#hmac(`request\0${actorId}\0${input.idempotencyKey}`);
    const requestHash = sha256(canonicalJson({ recoveryEventId, recoveryActionId: recoveryAction.id, knowledgeHash }));

    return inImmediateTransaction(this.database, () => {
      const replay = this.#findReplay(requestKeyHash, occurrenceKeyHash, requestHash, knowledgeHash);
      if (replay) return this.#occurrenceResult(replay, true);
      const sourceHash = sha256(canonicalJson({
        attackAttemptId: attempt.id,
        recoveryActionId: recoveryAction.id,
        recoveryEventId: event.id,
        evidence: evidence.rows.map((item) => ({ id: item.id, contentHash: item.content_hash })),
        resetControlReceiptHash,
      }));
      const compiled = this.#compiler.compile({
        source: {
          privateSourceReference: `attack_attempt:${attempt.id};recovery_event:${event.id}`,
          privateLabels: this.#privateLabels(attempt.mission_id),
          sourceClass: "current",
          sourceHash,
          observedAt: event.occurred_at,
          evidenceCount: evidence.rows.length,
          canonicalEvidenceIds: evidence.rows.map((item) => item.id),
        },
        knowledge: normalizedKnowledge,
        confidence: payload.confidence,
      });
      if (
        compiled.status !== "staged" || !compiled.bundleId || !compiled.provenanceReceiptId
        || compiled.exactProcedureCounts.operatorReportedAggregateResetMinimum !== null
      ) {
        throw new OperationalHazardObservationError(
          "hazard_observation_compiler_rejected",
          "The reset observation did not produce a candidate-only reusable knowledge bundle",
          "policy_denied",
        );
      }
      const occurrenceId = `hazocc_${occurrenceKeyHash}`;
      const now = this.#clock().toISOString();
      const auditId = this.#audit.append({
        missionId: attempt.mission_id,
        runId: attempt.run_id,
        actor: input.actor,
        action: "operational_hazard.reset_occurrence_staged",
        resourceType: "operational_hazard_occurrence",
        resourceId: occurrenceId,
        reason: "Recorded one uniquely attributable reset episode and staged generalized candidates for operator review",
        details: {
          occurrenceId,
          recoveryEventId: event.id,
          recoveryActionId: recoveryAction.id,
          attackAttemptId: attempt.id,
          targetContextFingerprint,
          resetControlReceiptId: resetControlReceipt.id,
          bundleId: compiled.bundleId,
          provenanceReceiptId: compiled.provenanceReceiptId,
          evidenceCount: evidence.rows.length,
          resetControlReceiptHash,
          exactResetDelta: 1,
          aggregateMinimumAttributed: false,
          promoted: false,
        },
        occurredAt: now,
      });
      const audit = this.database.prepare("SELECT record_hash FROM audit_records WHERE id = ?")
        .get(auditId) as { readonly record_hash: string };
      this.database.prepare(`
        INSERT INTO operational_hazard_occurrences (
          id, occurrence_key_hash, request_key_hash, request_hash,
          mission_id, run_id, attack_attempt_id, recovery_action_id, recovery_event_id,
          target_asset_id, target_service_id, target_context_fingerprint,
          reset_control_receipt_id, reset_control_receipt_hash,
          evidence_ids_json, bundle_id, provenance_receipt_id, knowledge_hash,
          exact_attempt_count, exact_reproducibility_count, exact_reset_count,
          recorded_by, audit_record_id, audit_record_hash, observed_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 1, ?, ?, ?, ?, ?)
      `).run(
        occurrenceId, occurrenceKeyHash, requestKeyHash, requestHash,
        attempt.mission_id, attempt.run_id, attempt.id, recoveryAction.id, event.id,
        attempt.target_asset_id, attempt.target_service_id, targetContextFingerprint,
        resetControlReceipt.id, resetControlReceiptHash,
        canonicalJson(evidence.rows.map((item) => item.id)), compiled.bundleId,
        compiled.provenanceReceiptId, knowledgeHash, actorId, auditId,
        audit.record_hash, event.occurred_at, now,
      );
      this.#events.append({
        missionId: attempt.mission_id,
        runId: attempt.run_id,
        eventType: "operational_hazard.reset_occurrence_staged",
        actorType: input.actor.type,
        actorId,
        summary: "One attributable reset episode was retained privately; generalized attack knowledge is awaiting operator review.",
        payload: {
          occurrenceId,
          recoveryActionId: recoveryAction.id,
          targetContextFingerprint,
          resetControlReceiptId: resetControlReceipt.id,
          resetControlReceiptHash,
          bundleId: compiled.bundleId,
          candidateCount: compiled.candidateIds.length,
          exactResetDelta: 1,
          aggregateMinimumAttributed: false,
          promoted: false,
        },
        sensitivity: "private",
        redaction: { canonicalOperationalIds: "private", reusableCandidates: "generalized" },
      });
      const row = this.database.prepare("SELECT * FROM operational_hazard_occurrences WHERE id = ?")
        .get(occurrenceId) as OccurrenceRow;
      return this.#occurrenceResult(row, false, compiled);
    });
  }

  reportAggregateResetMinimum(input: {
    readonly missionId: string;
    readonly runId: string;
    readonly reportedMinimum: number;
    readonly actor: OperationalActor;
    readonly idempotencyKey: string;
  }): { readonly observation: OperationalHazardAggregateObservation; readonly totals: OperationalHazardResetTotals; readonly replayed: boolean } {
    const missionId = id(input.missionId, "Mission ID");
    const runId = id(input.runId, "Run ID");
    const actorId = id(input.actor.id, "Actor ID");
    if (input.actor.type !== "operator") {
      throw new OperationalHazardObservationError(
        "hazard_aggregate_operator_required",
        "Only an authenticated operator may report an unattributed aggregate reset minimum",
        "policy_denied",
      );
    }
    if (!Number.isSafeInteger(input.reportedMinimum) || input.reportedMinimum < 1) {
      throw new OperationalHazardObservationError("hazard_aggregate_minimum_invalid", "Reported reset minimum must be a positive integer");
    }
    if (!IDEMPOTENCY_KEY.test(input.idempotencyKey)) {
      throw new OperationalHazardObservationError("hazard_observation_idempotency_required", "A valid 8-200 character idempotency key is required");
    }
    const scope = this.database.prepare("SELECT mission_id FROM runs WHERE id = ?")
      .get(runId) as { readonly mission_id: string } | undefined;
    if (!scope || scope.mission_id !== missionId) {
      throw new OperationalHazardObservationError("hazard_observation_scope_mismatch", "Run does not belong to the supplied mission", "scope_conflict");
    }
    const requestKeyHash = this.#hmac(`aggregate-request\0${actorId}\0${input.idempotencyKey}`);
    const requestHash = sha256(canonicalJson({ missionId, runId, reportedMinimum: input.reportedMinimum }));
    return inImmediateTransaction(this.database, () => {
      const existing = this.database.prepare(`
        SELECT * FROM operational_hazard_aggregate_reset_observations WHERE request_key_hash = ?
      `).get(requestKeyHash) as AggregateRow | undefined;
      if (existing) {
        if (existing.request_hash !== requestHash) {
          throw new OperationalHazardObservationError("hazard_observation_idempotency_conflict", "Idempotency key was reused for a different aggregate observation", "conflict");
        }
        return { observation: mapAggregate(existing), totals: this.totals(missionId, runId), replayed: true };
      }
      const now = this.#clock().toISOString();
      const statement = this.#events.append({
        missionId,
        runId,
        eventType: AGGREGATE_EVENT_TYPE,
        actorType: input.actor.type,
        actorId,
        summary: `The operator reported at least ${input.reportedMinimum} reset episodes; exact procedure attribution remains separate.`,
        payload: { reportedMinimum: input.reportedMinimum, procedureAttribution: null },
        sensitivity: "private",
        redaction: { targetIdentity: "excluded", procedureAttribution: "none" },
      });
      const observationId = `hazagg_${this.#hmac(`aggregate\0${statement.id}`)}`;
      const auditId = this.#audit.append({
        missionId,
        runId,
        actor: input.actor,
        action: AGGREGATE_EVENT_TYPE,
        resourceType: "operational_hazard_aggregate_reset_observation",
        resourceId: observationId,
        reason: "Preserved an operator-reported aggregate lower bound without assigning it to a procedure",
        details: {
          reportedMinimum: input.reportedMinimum,
          statementEventId: statement.id,
          aggregation: "maximum_only",
          procedureAttribution: null,
        },
        occurredAt: now,
      });
      const audit = this.database.prepare("SELECT record_hash FROM audit_records WHERE id = ?")
        .get(auditId) as { readonly record_hash: string };
      this.database.prepare(`
        INSERT INTO operational_hazard_aggregate_reset_observations (
          id, request_key_hash, request_hash, mission_id, run_id,
          reported_minimum, statement_event_id, recorded_by, audit_record_id,
          audit_record_hash, reported_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        observationId, requestKeyHash, requestHash, missionId, runId,
        input.reportedMinimum, statement.id, actorId, auditId,
        audit.record_hash, now, now,
      );
      const row = this.database.prepare(`
        SELECT * FROM operational_hazard_aggregate_reset_observations WHERE id = ?
      `).get(observationId) as AggregateRow;
      return { observation: mapAggregate(row), totals: this.totals(missionId, runId), replayed: false };
    });
  }

  totals(missionId: string, runId: string): OperationalHazardResetTotals {
    const row = this.database.prepare(`
      SELECT * FROM operational_hazard_reset_totals WHERE mission_id = ? AND run_id = ?
    `).get(id(missionId, "Mission ID"), id(runId, "Run ID")) as {
      mission_id: string;
      run_id: string;
      exact_attributable_reset_count: number;
      operator_reported_reset_minimum: number | null;
      minimum_unattributed_reset_count: number;
    } | undefined;
    return {
      missionId,
      runId,
      exactAttributableResetCount: row?.exact_attributable_reset_count ?? 0,
      operatorReportedResetMinimum: row?.operator_reported_reset_minimum ?? null,
      minimumUnattributedResetCount: row?.minimum_unattributed_reset_count ?? 0,
    };
  }

  #occurrenceResult(
    row: OccurrenceRow,
    replayed: boolean,
    compiled?: AttackKnowledgeCompileResult,
  ): RecordOperationalHazardOccurrenceResult {
    const bundle = this.database.prepare(`
      SELECT semantic_fingerprint, exact_procedure_attempt_count,
        exact_procedure_reproducibility_count, exact_procedure_evidence_count,
        exact_procedure_reset_count, operator_reported_reset_count_minimum
      FROM attack_knowledge_bundles WHERE id = ?
    `).get(row.bundle_id) as Record<string, unknown>;
    const candidateIds = (this.database.prepare(`
      SELECT registry.candidate_id FROM attack_knowledge_bundle_candidates link
      JOIN attack_knowledge_candidate_registry registry
        ON registry.content_fingerprint = link.content_fingerprint
      WHERE link.bundle_id = ? ORDER BY link.ordinal
    `).all(row.bundle_id) as Array<{ candidate_id: string }>).map((item) => item.candidate_id);
    return {
      occurrence: mapOccurrence(row),
      compile: compiled ? {
        status: compiled.status,
        bundleFingerprint: compiled.bundleFingerprint,
        candidateIds: compiled.candidateIds,
        candidatesCreated: compiled.candidatesCreated,
        candidatesReused: compiled.candidatesReused,
        edgeProposalsStaged: compiled.edgeProposalsStaged,
        exactProcedureCounts: compiled.exactProcedureCounts,
      } : {
        status: "staged",
        bundleFingerprint: String(bundle.semantic_fingerprint),
        candidateIds,
        candidatesCreated: 0,
        candidatesReused: candidateIds.length,
        edgeProposalsStaged: Number((this.database.prepare(`
          SELECT COUNT(*) AS count FROM attack_knowledge_bundle_edges WHERE bundle_id = ?
        `).get(row.bundle_id) as { count: number }).count),
        exactProcedureCounts: {
          attempts: Number(bundle.exact_procedure_attempt_count),
          reproducibleOutcomes: Number(bundle.exact_procedure_reproducibility_count),
          evidenceItems: Number(bundle.exact_procedure_evidence_count),
          exactResets: Number(bundle.exact_procedure_reset_count),
          operatorReportedAggregateResetMinimum: bundle.operator_reported_reset_count_minimum === null
            ? null : Number(bundle.operator_reported_reset_count_minimum),
        },
      },
      totals: this.totals(row.mission_id, row.run_id),
      replayed,
    };
  }

  #findReplay(
    requestKeyHash: string,
    occurrenceKeyHash: string,
    requestHash: string,
    knowledgeHash: string,
  ): OccurrenceRow | undefined {
    const row = this.database.prepare(`
      SELECT * FROM operational_hazard_occurrences
      WHERE request_key_hash = ? OR occurrence_key_hash = ?
      ORDER BY CASE WHEN request_key_hash = ? THEN 0 ELSE 1 END LIMIT 1
    `).get(requestKeyHash, occurrenceKeyHash, requestKeyHash) as OccurrenceRow | undefined;
    if (!row) return undefined;
    if (row.request_hash !== requestHash || row.knowledge_hash !== knowledgeHash) {
      throw new OperationalHazardObservationError(
        "hazard_observation_idempotency_conflict",
        "The idempotency key or canonical reset episode already names different knowledge",
        "conflict",
      );
    }
    return row;
  }

  #event(eventId: string): EventRow {
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, event_type, occurred_at, payload_json
      FROM events WHERE id = ?
    `).get(eventId) as EventRow | undefined;
    if (!row) throw new OperationalHazardObservationError("hazard_recovery_event_not_found", "Canonical recovery event was not found", "not_found");
    if (row.event_type !== RESET_EVENT_TYPE) {
      throw new OperationalHazardObservationError("hazard_recovery_event_invalid", "Only a typed verified target-reset event can count as an exact reset", "evidence_insufficient");
    }
    return row;
  }

  #payload(event: EventRow): Required<Pick<OperationalHazardResetEventPayload,
    "attackAttemptId" | "recoveryActionId" | "resetKind" | "targetContextFingerprint" |
    "resetControlReceiptId" | "resetControlReceiptFingerprint" | "verifiedEvidenceIds" | "confidence">> &
    Pick<OperationalHazardResetEventPayload, "knowledge" | "hazardNodeId"> {
    let raw: Record<string, unknown>;
    try { raw = object(JSON.parse(event.payload_json), "Reset event payload"); }
    catch (error) {
      if (error instanceof OperationalHazardObservationError) throw error;
      throw new OperationalHazardObservationError("hazard_recovery_event_invalid", "Reset event payload is malformed");
    }
    const allowed = new Set(["attackAttemptId", "recoveryActionId", "resetKind", "targetContextFingerprint", "resetControlReceiptId", "resetControlReceiptFingerprint", "verifiedEvidenceIds", "hazardNodeId", "knowledge", "confidence"]);
    if (Object.keys(raw).some((key) => !allowed.has(key))) {
      throw new OperationalHazardObservationError("hazard_recovery_event_invalid", "Reset event payload contains unsupported fields");
    }
    if (raw.resetKind !== "target_reset") {
      throw new OperationalHazardObservationError("hazard_recovery_event_invalid", "Only an attributable target reset increments the exact reset count");
    }
    if ((raw.knowledge === undefined) === (raw.hazardNodeId === undefined)) {
      throw new OperationalHazardObservationError("hazard_recovery_event_invalid", "Reset event must contain either new generalized knowledge or one verified hazard node ID");
    }
    return {
      attackAttemptId: id(raw.attackAttemptId, "Attack-attempt ID"),
      recoveryActionId: id(raw.recoveryActionId, "Recovery action ID"),
      resetKind: "target_reset",
      targetContextFingerprint: (() => {
        const value = id(raw.targetContextFingerprint, "Target-context fingerprint");
        if (!SHA256.test(value)) {
          throw new OperationalHazardObservationError("hazard_recovery_event_invalid", "Target-context fingerprint must be a SHA-256 digest");
        }
        return value;
      })(),
      resetControlReceiptId: id(raw.resetControlReceiptId, "Reset-control receipt ID"),
      resetControlReceiptFingerprint: (() => {
        const value = id(raw.resetControlReceiptFingerprint, "Reset-control receipt fingerprint");
        if (!SHA256.test(value)) {
          throw new OperationalHazardObservationError(
            "hazard_recovery_event_invalid",
            "Reset-control receipt fingerprint must be a SHA-256 digest",
          );
        }
        return value;
      })(),
      verifiedEvidenceIds: ids(raw.verifiedEvidenceIds, "Verified evidence IDs"),
      ...(raw.hazardNodeId === undefined ? {} : { hazardNodeId: id(raw.hazardNodeId, "Hazard node ID") }),
      ...(raw.knowledge === undefined ? {} : { knowledge: raw.knowledge as OperationalHazardKnowledge }),
      confidence: confidence(raw.confidence),
    };
  }

  #attempt(attemptId: string): AttemptRow {
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, status, target_asset_id, target_service_id
      FROM attack_attempts WHERE id = ?
    `).get(attemptId) as AttemptRow | undefined;
    if (!row) throw new OperationalHazardObservationError("hazard_attack_attempt_not_found", "Canonical attack attempt was not found", "not_found");
    if (!["failed", "safely_aborted", "blocked", "waiting_conditions"].includes(row.status)) {
      throw new OperationalHazardObservationError("hazard_attack_attempt_not_terminal", "Reset attribution requires a preserved failed, safely aborted, blocked, or waiting attack attempt", "conflict");
    }
    return row;
  }

  #assertScope(attempt: AttemptRow, event: EventRow): void {
    if (attempt.mission_id !== event.mission_id || attempt.run_id !== event.run_id) {
      throw new OperationalHazardObservationError("hazard_observation_scope_mismatch", "Recovery event and attack attempt belong to different mission/run scopes", "scope_conflict");
    }
  }

  #recoveryAction(actionId: string, attempt: AttemptRow): RecoveryActionRow {
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, status, action_type,
        normalized_arguments_json, scoped_target FROM actions WHERE id = ?
    `).get(actionId) as RecoveryActionRow | undefined;
    if (
      !row || row.mission_id !== attempt.mission_id || row.run_id !== attempt.run_id
      || row.status !== "succeeded" || !["target_reset", "environment_reset"].includes(row.action_type)
    ) {
      throw new OperationalHazardObservationError(
        "hazard_recovery_action_invalid",
        "Exact reset attribution requires one succeeded canonical target/environment reset action from the same run",
        "evidence_insufficient",
      );
    }
    let represented: Record<string, unknown>;
    try {
      const stored = object(JSON.parse(row.normalized_arguments_json), "Recovery action arguments");
      const input = object(stored.input, "Recovery action input");
      represented = object(input.operationalHazardReset, "Operational-hazard reset contract");
    } catch (error) {
      if (error instanceof OperationalHazardObservationError) throw error;
      throw new OperationalHazardObservationError(
        "hazard_reset_contract_invalid",
        "The canonical reset action has malformed represented arguments",
        "evidence_insufficient",
      );
    }
    if (
      represented.schemaVersion !== RESET_RUNTIME_CONTRACT_SCHEMA
      || represented.attackAttemptId !== attempt.id
      || (represented.targetAssetId ?? null) !== attempt.target_asset_id
      || (represented.targetServiceId ?? null) !== attempt.target_service_id
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_target_binding_mismatch",
        "The canonical reset action is not bound to this exact failed attempt and target context",
        "scope_conflict",
      );
    }
    const targetId = attempt.target_service_id ?? attempt.target_asset_id;
    const target = targetId ? this.database.prepare(`
      SELECT primary_label, normalized_identity FROM topology_nodes
      WHERE id = ? AND mission_id = ?
    `).get(targetId, attempt.mission_id) as {
      readonly primary_label: string; readonly normalized_identity: string;
    } | undefined : undefined;
    if (!target || (row.scoped_target !== target.primary_label && row.scoped_target !== target.normalized_identity)) {
      throw new OperationalHazardObservationError(
        "hazard_reset_target_binding_mismatch",
        "The reset action's scoped target does not match its canonical target asset or service",
        "scope_conflict",
      );
    }
    return row;
  }

  #verifiedEvidence(
    attempt: AttemptRow,
    recoveryActionId: string,
    targetContextFingerprint: string,
    evidenceIds: readonly string[],
  ): VerifiedResetEvidence {
    const rows: Array<{
      id: string; content_hash: string; mission_id: string; run_id: string | null;
      action_id: string | null; verification_state: string; evidence_type: string;
      source: string; created_by: string; provenance_json: string;
    }> = [];
    let sharedResetReceiptId: string | undefined;
    let sharedResetReceiptFingerprint: string | undefined;
    for (const evidenceId of evidenceIds) {
      const row = this.database.prepare(`
        SELECT id, content_hash, mission_id, run_id, action_id,
          verification_state, evidence_type, source, created_by, provenance_json
        FROM evidence WHERE id = ?
      `).get(evidenceId) as typeof rows[number] | undefined;
      if (
        !row || row.mission_id !== attempt.mission_id || row.run_id !== attempt.run_id
        || row.action_id !== recoveryActionId || row.verification_state !== "verified"
      ) {
        throw new OperationalHazardObservationError("hazard_observation_verified_evidence_required", "Every reset observation needs verified evidence produced by the exact canonical reset action", "evidence_insufficient");
      }
      let provenance: unknown;
      try { provenance = JSON.parse(row.provenance_json) as unknown; }
      catch {
        throw new OperationalHazardObservationError(
          "hazard_observation_verified_local_evidence_required",
          "Reset evidence has malformed provenance and cannot count as a locally verified reset",
          "evidence_insufficient",
        );
      }
      const forbiddenType = ["operator_supplied", "guided_text_result", "guided_manual_result"].includes(row.evidence_type);
      if (
        forbiddenType
        || row.evidence_type !== "target_reset_result"
        || row.source !== RESET_EVALUATOR
        || row.created_by !== RESET_EVALUATOR
        || containsPublicModelAttribution(row.source)
        || containsPublicModelAttribution(row.created_by)
        || containsPublicModelAttribution(provenance)
      ) {
        throw new OperationalHazardObservationError(
          "hazard_observation_verified_local_evidence_required",
          "Operator-acknowledged or public-model evidence cannot establish an exact physical reset occurrence",
          "evidence_insufficient",
        );
      }
      const resetAssessment = provenance && typeof provenance === "object" && !Array.isArray(provenance)
        ? (provenance as Record<string, unknown>).resetAssessment
        : undefined;
      if (!resetAssessment || typeof resetAssessment !== "object" || Array.isArray(resetAssessment)) {
        throw new OperationalHazardObservationError(
          "hazard_observation_reset_proof_invalid",
          "Verified reset evidence is missing its typed local reset assessment",
          "evidence_insufficient",
        );
      }
      const proof = resetAssessment as Record<string, unknown>;
      if (
        proof.schema !== RESET_PROOF_SCHEMA
        || proof.resetCompleted !== true
        || proof.baselineRestored !== true
        || proof.attackAttemptId !== attempt.id
        || proof.recoveryActionId !== recoveryActionId
        || proof.targetContextFingerprint !== targetContextFingerprint
        || typeof proof.resetControlReceiptId !== "string"
        || typeof proof.resetControlReceiptFingerprint !== "string"
        || !SHA256.test(proof.resetControlReceiptFingerprint)
      ) {
        throw new OperationalHazardObservationError(
          "hazard_observation_reset_proof_invalid",
          "The typed local reset proof does not attest this exact action, attempt, restored baseline, and target context",
          "evidence_insufficient",
        );
      }
      if (
        sharedResetReceiptId !== undefined
        && sharedResetReceiptId !== proof.resetControlReceiptId
      ) {
        throw new OperationalHazardObservationError(
          "hazard_reset_control_receipt_mismatch",
          "All reset evidence must name the same canonical server-issued reset-control receipt",
          "evidence_insufficient",
        );
      }
      if (
        sharedResetReceiptFingerprint !== undefined
        && sharedResetReceiptFingerprint !== proof.resetControlReceiptFingerprint
      ) {
        throw new OperationalHazardObservationError(
          "hazard_reset_control_receipt_mismatch",
          "All reset evidence must describe the same physical reset-control receipt",
          "evidence_insufficient",
        );
      }
      sharedResetReceiptId = id(proof.resetControlReceiptId, "Reset-control receipt ID");
      sharedResetReceiptFingerprint = proof.resetControlReceiptFingerprint;
      const custody = this.database.prepare(`
        SELECT 1 FROM evidence_chain_events WHERE evidence_id = ? AND event_type = 'verified' LIMIT 1
      `).get(evidenceId);
      if (!custody) {
        throw new OperationalHazardObservationError("hazard_observation_evidence_custody_required", "Verified reset evidence is missing its chain-of-custody event", "evidence_insufficient");
      }
      rows.push(row);
    }
    if (!sharedResetReceiptId || !sharedResetReceiptFingerprint) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_invalid",
        "A trusted local reset-control receipt is required",
        "evidence_insufficient",
      );
    }
    return {
      rows: rows.sort((left, right) => left.id.localeCompare(right.id)),
      resetControlReceiptId: sharedResetReceiptId,
      resetControlReceiptFingerprint: sharedResetReceiptFingerprint,
    };
  }

  #knowledgeForHazard(hazardNodeId: string | undefined, attackAttemptId: string): OperationalHazardKnowledge {
    if (!hazardNodeId) {
      throw new OperationalHazardObservationError("hazard_observation_knowledge_required", "New hazards require structured generalized knowledge", "evidence_insufficient");
    }
    const rows = this.database.prepare(`
      SELECT DISTINCT bundle.sanitized_bundle_json
      FROM attack_knowledge_promotion_receipts promotion
      JOIN attack_knowledge_bundles bundle ON bundle.id = promotion.bundle_id
      JOIN operational_hazard_profiles profile
        ON profile.node_id = promotion.hazard_profile_node_id
      JOIN attack_attempt_knowledge_contexts binding
        ON binding.attack_attempt_id = ?
       AND binding.procedure_node_id = profile.procedure_node_id
       AND binding.procedure_version_node_id IS profile.procedure_version_node_id
      WHERE promotion.hazard_profile_node_id = ?
      ORDER BY promotion.promotion_sequence DESC
      LIMIT 2
    `).all(attackAttemptId, hazardNodeId) as Array<{ sanitized_bundle_json: string }>;
    if (rows.length !== 1) {
      throw new OperationalHazardObservationError("hazard_observation_verified_bundle_required", "Runtime reset staging needs one exact promoted hazard bundle bound to the attack attempt", "evidence_insufficient");
    }
    const document = object(JSON.parse(rows[0]!.sanitized_bundle_json), "Promoted hazard bundle");
    const knowledge = document.knowledge;
    if (!knowledge || typeof knowledge !== "object" || Array.isArray(knowledge)) {
      throw new OperationalHazardObservationError("hazard_observation_verified_bundle_required", "Promoted hazard bundle is malformed", "evidence_insufficient");
    }
    return knowledge as OperationalHazardKnowledge;
  }

  #oneOccurrenceKnowledge(knowledge: OperationalHazardKnowledge, evidenceCount: number): OperationalHazardKnowledge {
    const root = object(knowledge, "Operational hazard knowledge");
    if (root.kind !== "operational_hazard") {
      throw new OperationalHazardObservationError("hazard_observation_knowledge_invalid", "Reset observations require operational-hazard knowledge");
    }
    const hazard = object(root.hazard, "Operational hazard");
    const recoveryCost = object(hazard.recoveryCost ?? {}, "Recovery cost");
    const normalized = {
      ...root,
      hazard: {
        ...hazard,
        recoveryCost: {
          ...recoveryCost,
          exactProcedureResetCount: 1,
          operatorReportedResetCountMinimum: undefined,
        },
      },
      corroboration: {
        exactProcedureAttemptCount: 1,
        exactProcedureReproducibilityCount: 1,
        exactProcedureEvidenceCount: evidenceCount,
      },
    };
    return JSON.parse(canonicalJson(normalized)) as OperationalHazardKnowledge;
  }

  #privateLabels(missionId: string): readonly string[] {
    const rows = this.database.prepare(`
      SELECT mission.name, mission.engagement_id, target.target, target.normalized_target
      FROM missions mission LEFT JOIN mission_targets target ON target.mission_id = mission.id
      WHERE mission.id = ?
    `).all(missionId) as Array<Record<string, unknown>>;
    return [...new Set(rows.flatMap((row) => [row.name, row.engagement_id, row.target, row.normalized_target])
      .filter((value): value is string => typeof value === "string" && value.trim().length >= 5)
      .map((value) => value.normalize("NFKC").trim()))];
  }

  #hmac(value: string): string {
    return createHmac("sha256", this.#key).update(value, "utf8").digest("hex");
  }
}

export interface OperationalHazardResetRuntimeContract {
  readonly schemaVersion: typeof RESET_RUNTIME_CONTRACT_SCHEMA;
  readonly attackAttemptId: string;
  readonly targetAssetId: string | null;
  readonly targetServiceId: string | null;
  readonly preResetHealthEvidenceId: string;
  readonly postResetHealthEvidenceId: string;
  readonly hazardNodeId?: string;
  readonly knowledge?: OperationalHazardKnowledge;
  readonly confidence?: number;
}

export interface OperationalHazardResetRuntimeReceipt {
  readonly recoveryEventId: string;
  readonly recoveryActionId: string;
  readonly verifiedEvidenceIds: readonly string[];
  readonly resetControlReceiptId: string;
  readonly resetControlReceiptFingerprint: string;
  readonly queued: true;
}

interface LocalHealthProofRow {
  readonly id: string;
  readonly mission_id: string;
  readonly run_id: string | null;
  readonly action_id: string | null;
  readonly evidence_type: string;
  readonly content_hash: string;
  readonly provenance_json: string;
  readonly verification_state: string;
  readonly source: string;
  readonly created_by: string;
}

/**
 * Trusted deterministic evaluator that promotes neither logs nor model prose.
 * It creates one verified reset proof only from a false-before/true-after pair
 * of typed local health observations bound to the exact reset action, failed
 * attempt, and canonical target fingerprint.
 */
export class OperationalHazardLocalResetEvaluator {
  constructor(private readonly database: SqliteDatabase) {}

  evaluateCompletedAction(action: DurableAction): string | undefined {
    if (!["target_reset", "environment_reset"].includes(action.actionType)) return undefined;
    if (action.status !== "succeeded") {
      throw new OperationalHazardObservationError(
        "hazard_recovery_action_invalid",
        "Local reset evaluation requires a succeeded canonical reset action",
        "evidence_insufficient",
      );
    }
    const contract = object(action.arguments.operationalHazardReset, "Operational-hazard reset contract");
    const allowed = new Set([
      "schemaVersion", "attackAttemptId", "targetAssetId", "targetServiceId",
      "preResetHealthEvidenceId", "postResetHealthEvidenceId",
      "hazardNodeId", "knowledge", "confidence",
    ]);
    if (
      contract.schemaVersion !== RESET_RUNTIME_CONTRACT_SCHEMA
      || Object.keys(contract).some((key) => !allowed.has(key))
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_contract_invalid",
        "Local reset evaluation requires the exact represented reset-contract schema",
        "evidence_insufficient",
      );
    }
    const attackAttemptId = id(contract.attackAttemptId, "Attack-attempt ID");
    const preEvidenceId = id(contract.preResetHealthEvidenceId, "Pre-reset health evidence ID");
    const postEvidenceId = id(contract.postResetHealthEvidenceId, "Post-reset health evidence ID");
    if (preEvidenceId === postEvidenceId) {
      throw new OperationalHazardObservationError(
        "hazard_reset_health_pair_invalid",
        "Pre-reset and post-reset health observations must be distinct",
        "evidence_insufficient",
      );
    }
    const attempt = this.database.prepare(`
      SELECT mission_id, run_id, target_asset_id, target_service_id
      FROM attack_attempts WHERE id = ?
    `).get(attackAttemptId) as {
      readonly mission_id: string; readonly run_id: string;
      readonly target_asset_id: string | null; readonly target_service_id: string | null;
    } | undefined;
    if (
      !attempt || attempt.mission_id !== action.missionId || attempt.run_id !== action.runId
      || (contract.targetAssetId ?? null) !== attempt.target_asset_id
      || (contract.targetServiceId ?? null) !== attempt.target_service_id
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_target_binding_mismatch",
        "Local reset evaluation does not match the failed attempt's canonical target",
        "scope_conflict",
      );
    }
    const targetContextFingerprint = operationalHazardTargetContextFingerprint({
      missionId: action.missionId,
      runId: action.runId,
      targetAssetId: attempt.target_asset_id,
      targetServiceId: attempt.target_service_id,
    });
    const pre = this.#healthProof(preEvidenceId, action, attackAttemptId, targetContextFingerprint, "before_reset", false);
    const post = this.#healthProof(postEvidenceId, action, attackAttemptId, targetContextFingerprint, "after_reset", true);
    const postProvenance = object(JSON.parse(post.provenance_json), "Post-reset health provenance");
    const postAssessment = object(postProvenance.healthAssessment, "Post-reset health assessment");
    const controlReceipt = resetControlReceipt(postAssessment.resetControlReceipt);
    const controlReceiptFingerprint = resetControlReceiptFingerprint(controlReceipt);
    if (postAssessment.resetControlReceiptFingerprint !== controlReceiptFingerprint) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_invalid",
        "The post-reset health proof does not match its trusted reset-control receipt",
        "evidence_insufficient",
      );
    }
    const issuedReceipt = this.database.prepare(`
      SELECT id FROM operational_reset_control_receipts
      WHERE recovery_action_id = ? AND post_reset_health_evidence_id = ?
        AND target_context_fingerprint = ? AND receipt_fingerprint = ?
    `).get(action.id, post.id, targetContextFingerprint, controlReceiptFingerprint) as {
      readonly id: string;
    } | undefined;
    if (!issuedReceipt) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_not_issued",
        "The trusted local reset controller did not issue a canonical receipt for this physical reset",
        "evidence_insufficient",
      );
    }
    const provenance = {
      resetAssessment: {
        schema: RESET_PROOF_SCHEMA,
        resetCompleted: true,
        baselineRestored: true,
        attackAttemptId,
        recoveryActionId: action.id,
        targetContextFingerprint,
        resetControlReceiptId: issuedReceipt.id,
        resetControlReceiptFingerprint: controlReceiptFingerprint,
        preResetHealthEvidenceId: pre.id,
        preResetHealthEvidenceHash: pre.content_hash,
        postResetHealthEvidenceId: post.id,
        postResetHealthEvidenceHash: post.content_hash,
      },
    };
    const contentHash = sha256(canonicalJson(provenance));
    const evidenceId = `hazresetproof_${sha256(canonicalJson({
      recoveryActionId: action.id,
      attackAttemptId,
      targetContextFingerprint,
      resetControlReceiptId: issuedReceipt.id,
      resetControlReceiptFingerprint: controlReceiptFingerprint,
      pre: { id: pre.id, hash: pre.content_hash },
      post: { id: post.id, hash: post.content_hash },
    }))}`;
    const existing = this.database.prepare(`
      SELECT mission_id, run_id, action_id, evidence_type, content_hash,
        provenance_json, verification_state, source, created_by
      FROM evidence WHERE id = ?
    `).get(evidenceId) as LocalHealthProofRow | undefined;
    if (existing) {
      if (
        existing.mission_id !== action.missionId || existing.run_id !== action.runId
        || existing.action_id !== action.id || existing.evidence_type !== "target_reset_result"
        || existing.content_hash !== contentHash || existing.verification_state !== "verified"
        || existing.source !== RESET_EVALUATOR || existing.created_by !== RESET_EVALUATOR
        || canonicalJson(JSON.parse(existing.provenance_json)) !== canonicalJson(provenance)
      ) {
        throw new OperationalHazardObservationError(
          "hazard_reset_proof_integrity_conflict",
          "The deterministic local reset proof identity already names different content",
          "conflict",
        );
      }
      return evidenceId;
    }
    const now = action.endedAt ?? new Date().toISOString();
    this.database.prepare(`
      INSERT INTO evidence (
        id, mission_id, run_id, step_id, action_id, source, acquired_at,
        target, evidence_type, content_hash, provenance_json, confidence,
        sensitivity, verification_state, summary, created_by, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'target_reset_result', ?, ?, 1,
        'private', 'verified', ?, ?, ?)
    `).run(
      evidenceId, action.missionId, action.runId, action.stepId, action.id,
      RESET_EVALUATOR, now, action.target, contentHash, canonicalJson(provenance),
      "Typed local pre/post health observations prove one completed reset and restored baseline",
      RESET_EVALUATOR, now,
    );
    this.database.prepare(`
      INSERT INTO evidence_chain_events (
        id, evidence_id, event_type, actor, details_json, occurred_at
      ) VALUES (?, ?, 'verified', ?, ?, ?)
    `).run(
      `chain_${sha256(`verified\0${evidenceId}`)}`,
      evidenceId,
      RESET_EVALUATOR,
      canonicalJson({
        evaluator: RESET_EVALUATOR,
        schema: RESET_PROOF_SCHEMA,
        sourceEvidenceIds: [pre.id, post.id],
        resetControlReceiptId: issuedReceipt.id,
        resetControlReceiptFingerprint: controlReceiptFingerprint,
      }),
      now,
    );
    return evidenceId;
  }

  #healthProof(
    evidenceId: string,
    action: DurableAction,
    attackAttemptId: string,
    targetContextFingerprint: string,
    expectedPhase: "before_reset" | "after_reset",
    expectedBaseline: boolean,
  ): LocalHealthProofRow {
    const row = this.database.prepare(`
      SELECT id, mission_id, run_id, action_id, evidence_type, content_hash,
        provenance_json, verification_state, source, created_by
      FROM evidence WHERE id = ?
    `).get(evidenceId) as LocalHealthProofRow | undefined;
    if (
      !row || row.mission_id !== action.missionId || row.run_id !== action.runId
      || row.action_id !== action.id || row.evidence_type !== "health_check_result"
      || row.verification_state !== "verified" || row.source !== RESET_EVALUATOR
      || row.created_by !== RESET_EVALUATOR
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_verified_local_health_required",
        "Reset evaluation requires exact typed local pre-reset and post-reset health evidence",
        "evidence_insufficient",
      );
    }
    let provenance: unknown;
    try { provenance = JSON.parse(row.provenance_json) as unknown; } catch { provenance = undefined; }
    const health = provenance && typeof provenance === "object" && !Array.isArray(provenance)
      ? (provenance as Record<string, unknown>).healthAssessment
      : undefined;
    const typed = health && typeof health === "object" && !Array.isArray(health)
      ? health as Record<string, unknown>
      : undefined;
    if (
      !typed || typed.schema !== HEALTH_PROOF_SCHEMA || typed.phase !== expectedPhase
      || typed.baselineRestored !== expectedBaseline
      || typed.attackAttemptId !== attackAttemptId
      || typed.recoveryActionId !== action.id
      || typed.targetContextFingerprint !== targetContextFingerprint
      || containsPublicModelAttribution(provenance)
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_health_pair_invalid",
        "Typed local pre/post health evidence does not prove a down-before and restored-after transition for this reset",
        "evidence_insufficient",
      );
    }
    if (expectedPhase === "after_reset" && typed.resetCompleted !== true) {
      throw new OperationalHazardObservationError(
        "hazard_reset_health_pair_invalid",
        "Post-reset health evidence does not attest that the reset completed",
        "evidence_insufficient",
      );
    }
    if (expectedPhase === "after_reset") {
      const receipt = resetControlReceipt(typed.resetControlReceipt);
      if (typed.resetControlReceiptFingerprint !== resetControlReceiptFingerprint(receipt)) {
        throw new OperationalHazardObservationError(
          "hazard_reset_control_receipt_invalid",
          "Post-reset health evidence does not carry a valid trusted reset-control receipt",
          "evidence_insufficient",
        );
      }
    }
    const custody = this.database.prepare(`
      SELECT 1 FROM evidence_chain_events
      WHERE evidence_id = ? AND event_type = 'verified' LIMIT 1
    `).get(evidenceId);
    if (!custody) {
      throw new OperationalHazardObservationError(
        "hazard_reset_health_custody_required",
        "Typed local health evidence is missing immutable verification custody",
        "evidence_insufficient",
      );
    }
    return row;
  }
}

/**
 * Production action-completion seam. A reset counts only when the ordinary
 * runtime has already committed one succeeded reset action and one or more
 * locally verified evidence records linked to that exact action. The seam
 * appends the immutable event only; candidate compilation is handled by the
 * durable observation worker after the enclosing action transaction commits.
 */
export class OperationalHazardRuntimeRecoveryProducer {
  readonly #evaluator: OperationalHazardLocalResetEvaluator;

  constructor(private readonly database: SqliteDatabase) {
    this.#evaluator = new OperationalHazardLocalResetEvaluator(database);
  }

  recordCompletedAction(
    action: DurableAction,
    actor: OperationalActor,
  ): OperationalHazardResetRuntimeReceipt | undefined {
    if (!["target_reset", "environment_reset"].includes(action.actionType)) return undefined;
    if (action.status !== "succeeded") {
      throw new OperationalHazardObservationError(
        "hazard_recovery_action_invalid",
        "Operational-hazard reset ingestion requires a succeeded canonical reset action",
        "evidence_insufficient",
      );
    }
    const raw = object(action.arguments.operationalHazardReset, "Operational-hazard reset contract");
    const allowed = new Set([
      "schemaVersion", "attackAttemptId", "targetAssetId", "targetServiceId",
      "preResetHealthEvidenceId", "postResetHealthEvidenceId",
      "hazardNodeId", "knowledge", "confidence",
    ]);
    if (Object.keys(raw).some((key) => !allowed.has(key))) {
      throw new OperationalHazardObservationError(
        "hazard_reset_contract_invalid",
        "The represented reset contract contains unsupported fields",
      );
    }
    if (raw.schemaVersion !== RESET_RUNTIME_CONTRACT_SCHEMA) {
      throw new OperationalHazardObservationError(
        "hazard_reset_contract_invalid",
        "The represented reset contract schema version is unsupported",
      );
    }
    if ((raw.knowledge === undefined) === (raw.hazardNodeId === undefined)) {
      throw new OperationalHazardObservationError(
        "hazard_reset_contract_invalid",
        "The represented reset contract must name either one verified hazard or one new candidate knowledge document",
      );
    }
    const attempt = this.database.prepare(`
      SELECT mission_id, run_id, target_asset_id, target_service_id
      FROM attack_attempts WHERE id = ?
    `).get(id(raw.attackAttemptId, "Attack-attempt ID")) as {
      readonly mission_id: string; readonly run_id: string;
      readonly target_asset_id: string | null; readonly target_service_id: string | null;
    } | undefined;
    if (
      !attempt || attempt.mission_id !== action.missionId || attempt.run_id !== action.runId
      || (raw.targetAssetId ?? null) !== attempt.target_asset_id
      || (raw.targetServiceId ?? null) !== attempt.target_service_id
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_target_binding_mismatch",
        "The completed reset action is not bound to the exact failed attempt and canonical target context",
        "scope_conflict",
      );
    }
    const targetContextFingerprint = operationalHazardTargetContextFingerprint({
      missionId: action.missionId,
      runId: action.runId,
      targetAssetId: attempt.target_asset_id,
      targetServiceId: attempt.target_service_id,
    });
    const resetProofId = this.#evaluator.evaluateCompletedAction(action);
    if (!resetProofId) {
      throw new OperationalHazardObservationError(
        "hazard_observation_verified_evidence_required",
        "A completed reset action must have one deterministic locally verified reset proof",
        "evidence_insufficient",
      );
    }
    const proof = this.database.prepare(`
      SELECT provenance_json FROM evidence WHERE id = ?
    `).get(resetProofId) as { readonly provenance_json: string } | undefined;
    const proofProvenance = object(JSON.parse(proof?.provenance_json ?? "null"), "Reset proof provenance");
    const resetAssessment = object(proofProvenance.resetAssessment, "Reset assessment");
    const controlReceiptId = id(
      resetAssessment.resetControlReceiptId,
      "Reset-control receipt ID",
    );
    const controlReceiptFingerprint = id(
      resetAssessment.resetControlReceiptFingerprint,
      "Reset-control receipt fingerprint",
    );
    if (!SHA256.test(controlReceiptFingerprint)) {
      throw new OperationalHazardObservationError(
        "hazard_reset_control_receipt_invalid",
        "The deterministic reset proof has an invalid reset-control receipt fingerprint",
        "evidence_insufficient",
      );
    }
    const payload: OperationalHazardResetEventPayload = {
      attackAttemptId: id(raw.attackAttemptId, "Attack-attempt ID"),
      recoveryActionId: action.id,
      resetKind: "target_reset",
      targetContextFingerprint,
      resetControlReceiptId: controlReceiptId,
      resetControlReceiptFingerprint: controlReceiptFingerprint,
      verifiedEvidenceIds: [resetProofId],
      ...(raw.hazardNodeId === undefined
        ? { knowledge: raw.knowledge as OperationalHazardKnowledge }
        : { hazardNodeId: id(raw.hazardNodeId, "Hazard node ID") }),
      confidence: confidence(raw.confidence),
    };
    const recoveryEventId = appendVerifiedOperationalHazardReset({
      database: this.database,
      missionId: action.missionId,
      runId: action.runId,
      actor,
      payload,
      ...(action.endedAt ? { occurredAt: action.endedAt } : {}),
    });
    return {
      recoveryEventId,
      recoveryActionId: action.id,
      verifiedEvidenceIds: payload.verifiedEvidenceIds,
      resetControlReceiptId: controlReceiptId,
      resetControlReceiptFingerprint: controlReceiptFingerprint,
      queued: true,
    };
  }
}

/**
 * Production event consumer. Runtime components append one typed, verified
 * reset event; this worker stages it without requiring a developer to call the
 * compiler. Failures are quarantined and never promoted.
 */
export class OperationalHazardObservationWorker {
  readonly #service: OperationalHazardObservationService;
  readonly #clock: () => Date;
  readonly #workerId: string;
  readonly #leaseMs: number;
  #timer?: ReturnType<typeof setInterval>;
  #running = false;

  constructor(
    private readonly database: SqliteDatabase,
    options: {
      readonly hmacKey: string | Buffer;
      readonly clock?: () => Date;
      readonly workerId?: string;
      readonly leaseMs?: number;
    },
  ) {
    this.#clock = options.clock ?? (() => new Date());
    this.#workerId = options.workerId?.trim() || `operational-hazard-worker:${randomUUID()}`;
    this.#leaseMs = options.leaseMs ?? 300_000;
    if (!/^[A-Za-z0-9._:@/-]{1,300}$/u.test(this.#workerId)) {
      throw new TypeError("Operational hazard worker ID is invalid");
    }
    if (!Number.isSafeInteger(this.#leaseMs) || this.#leaseMs < 1_000 || this.#leaseMs > 300_000) {
      throw new RangeError("Operational hazard worker lease must be 1000 through 300000 ms");
    }
    this.#service = new OperationalHazardObservationService(database, options);
  }

  drain(limit = 25): {
    readonly completed: number;
    readonly quarantined: number;
    readonly deferred?: { readonly reason: "database_busy" };
  } {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new RangeError("Observation drain limit must be 1 through 100");
    const now = this.#clock();
    const nowIso = now.toISOString();
    let rows: Array<{ event_id: string }>;
    try {
      this.database.prepare(`
        UPDATE operational_hazard_observation_jobs
        SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL,
          claimed_at = NULL, available_at = ?, updated_at = ?
        WHERE status = 'processing' AND lease_expires_at <= ?
      `).run(nowIso, nowIso, nowIso);
      rows = this.database.prepare(`
        SELECT event_id FROM operational_hazard_observation_jobs
        WHERE status = 'pending' AND available_at <= ?
        ORDER BY available_at, event_id LIMIT ?
      `).all(nowIso, limit) as Array<{ event_id: string }>;
    } catch (error) {
      if (!isSqliteBusy(error)) throw error;
      return { completed: 0, quarantined: 0, deferred: { reason: "database_busy" } };
    }
    let completed = 0;
    let quarantined = 0;
    for (const row of rows) {
      const claimedAt = this.#clock().toISOString();
      const leaseExpiresAt = new Date(Date.parse(claimedAt) + this.#leaseMs).toISOString();
      let claimed: number;
      try {
        claimed = this.database.prepare(`
          UPDATE operational_hazard_observation_jobs
          SET status = 'processing', attempt_count = attempt_count + 1,
            lease_owner = ?, lease_expires_at = ?, claimed_at = ?, updated_at = ?
          WHERE event_id = ? AND status = 'pending'
        `).run(this.#workerId, leaseExpiresAt, claimedAt, claimedAt, row.event_id).changes;
      } catch (error) {
        if (!isSqliteBusy(error)) throw error;
        return { completed, quarantined, deferred: { reason: "database_busy" } };
      }
      if (claimed !== 1) continue;
      try {
        const result = this.#service.recordCanonicalReset({
          recoveryEventId: row.event_id,
          actor: { id: "operational-hazard-observation-worker", type: "system" },
          idempotencyKey: `runtime:${row.event_id}`,
        });
        const doneAt = this.#clock().toISOString();
        this.database.prepare(`
          UPDATE operational_hazard_observation_jobs
          SET status = 'completed', occurrence_id = ?, completed_at = ?,
            lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
          WHERE event_id = ? AND status = 'processing' AND lease_owner = ?
        `).run(result.occurrence.id, doneAt, doneAt, row.event_id, this.#workerId);
        completed += 1;
      } catch (error) {
        if (isSqliteBusy(error)) {
          // A canonical occurrence may already have committed before the job
          // completion write encountered contention. Return the lease to the
          // queue when possible; otherwise the normal lease-expiry path will
          // reclaim it and the idempotent recorder will replay safely.
          try {
            const retryAt = this.#clock().toISOString();
            this.database.prepare(`
              UPDATE operational_hazard_observation_jobs
              SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL,
                claimed_at = NULL, available_at = ?, updated_at = ?
              WHERE event_id = ? AND status = 'processing' AND lease_owner = ?
            `).run(retryAt, retryAt, row.event_id, this.#workerId);
          } catch (releaseError) {
            if (!isSqliteBusy(releaseError)) throw releaseError;
          }
          return { completed, quarantined, deferred: { reason: "database_busy" } };
        }
        const failedAt = this.#clock().toISOString();
        const category = error instanceof OperationalHazardObservationError ? error.code : "hazard_observation_internal_error";
        try {
          this.database.prepare(`
            UPDATE operational_hazard_observation_jobs
            SET status = 'quarantined', failure_category = ?, completed_at = ?,
              lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
            WHERE event_id = ? AND status = 'processing' AND lease_owner = ?
          `).run(category, failedAt, failedAt, row.event_id, this.#workerId);
        } catch (quarantineError) {
          if (!isSqliteBusy(quarantineError)) throw quarantineError;
          return { completed, quarantined, deferred: { reason: "database_busy" } };
        }
        quarantined += 1;
      }
    }
    return { completed, quarantined };
  }

  start(intervalMs = 1_000): void {
    if (this.#timer) return;
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 100 || intervalMs > 60_000) {
      throw new RangeError("Observation worker interval must be 100 through 60000 ms");
    }
    this.drain();
    this.#timer = setInterval(() => {
      if (this.#running) return;
      this.#running = true;
      try { this.drain(); } finally { this.#running = false; }
    }, intervalMs);
    this.#timer.unref();
  }

  stop(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = undefined;
  }
}

export function appendVerifiedOperationalHazardReset(input: {
  readonly database: SqliteDatabase;
  readonly missionId: string;
  readonly runId: string;
  readonly actor: OperationalActor;
  readonly payload: OperationalHazardResetEventPayload;
  readonly occurredAt?: string;
}): string {
  const eventId = `hazreset_${sha256(canonicalJson({
    missionId: input.missionId,
    runId: input.runId,
    attackAttemptId: input.payload.attackAttemptId,
    recoveryActionId: input.payload.recoveryActionId,
  }))}`;
  const payload = input.payload as unknown as JsonValue;
  const existing = input.database.prepare(`
    SELECT mission_id, run_id, event_type, payload_json FROM events WHERE id = ?
  `).get(eventId) as {
    mission_id: string; run_id: string; event_type: string; payload_json: string;
  } | undefined;
  if (existing) {
    if (
      existing.mission_id !== input.missionId || existing.run_id !== input.runId
      || existing.event_type !== RESET_EVENT_TYPE
      || canonicalJson(JSON.parse(existing.payload_json)) !== canonicalJson(payload)
    ) {
      throw new OperationalHazardObservationError(
        "hazard_reset_event_idempotency_conflict",
        "This canonical reset action already produced a different immutable reset event",
        "conflict",
      );
    }
    return eventId;
  }
  const event = new EventRepository(input.database).append({
    id: eventId,
    missionId: input.missionId,
    runId: input.runId,
    eventType: RESET_EVENT_TYPE,
    actorType: input.actor.type,
    actorId: input.actor.id,
    summary: "A target reset was completed and locally verified after a preserved operational hazard.",
    payload,
    ...(input.occurredAt ? { occurredAt: input.occurredAt } : {}),
    sensitivity: "private",
    redaction: { targetIdentity: "canonical_private_records", reusableKnowledge: "candidate_only" },
  });
  return event.id;
}

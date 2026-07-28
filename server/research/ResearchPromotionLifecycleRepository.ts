import { randomUUID } from "node:crypto";
import { canonicalResearchPromotionDecision } from "../../shared/ResearchPromotionDecision";
import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { canonicalJson, hashCanonical, sha256 } from "../missions/canonical";
import { MissionApiError } from "../missions/errors";
import {
  IntegrityAuthority,
  type ExperimentIntegrityReceipt,
} from "./IntegrityVerifier";
import {
  type ProviderExposureReceipt,
  validateProviderExposureReceipt,
} from "./LlmExposurePolicy";
import {
  PromotionService,
  type PromotionDecisionContext,
  type PromotionRecord,
  type PromotionState,
} from "./PromotionService";
import {
  HARD_GATE_CODES,
  type HardGateCode,
} from "./SecurityEvaluationHarness";

export const LOCAL_RESEARCH_PROMOTION_ACTIONS = [
  "policy_accept",
  "policy_reject",
  "start_benchmark",
  "development_pass",
  "development_fail",
  "validation_pass",
  "validation_fail",
  "hidden_holdout_pass",
  "hidden_holdout_fail",
  "shadow_pass",
  "shadow_fail",
  "canary_pass",
  "canary_fail",
] as const;

export type LocalResearchPromotionAction =
  (typeof LOCAL_RESEARCH_PROMOTION_ACTIONS)[number];

export const HUMAN_RESEARCH_PROMOTION_ACTIONS = [
  "approve_human_review",
  "reject_human_review",
  "start_shadow",
  "approve_canary",
  "start_canary",
  "verify",
  "reject",
  "mark_stale",
  "supersede",
  "rollback",
] as const;

export type HumanResearchPromotionAction =
  (typeof HUMAN_RESEARCH_PROMOTION_ACTIONS)[number];

export type ResearchPromotionStage =
  | "development"
  | "validation"
  | "hidden_holdout"
  | "human_review"
  | "shadow"
  | "bounded_canary"
  | "verified"
  | "terminal";

export interface CanaryBounds {
  readonly maxMissions: number;
  readonly maxWallClockMs: number;
}

export interface ResearchPromotionTransitionRecord {
  readonly id: string;
  readonly sequence: number;
  readonly version: number;
  readonly fromState: PromotionState;
  readonly toState: PromotionState;
  readonly action: LocalResearchPromotionAction | HumanResearchPromotionAction;
  readonly actorKind: PromotionDecisionContext["actorKind"];
  readonly actorId: string;
  readonly rationale: string;
  readonly evidenceRefs: readonly string[];
  readonly hardGateFailures: readonly HardGateCode[];
  readonly decisionFingerprint?: string;
  readonly integrityReceiptId?: string;
  readonly exposureReceiptIds: readonly string[];
  readonly deploymentId?: string;
  readonly createdAt: string;
}

export interface ResearchPromotionLifecycleRecord {
  readonly experimentId: string;
  readonly campaignId: string;
  readonly strategyVersionId: string;
  readonly state: PromotionState;
  readonly stage: ResearchPromotionStage;
  readonly milestones: PromotionRecord["milestones"];
  readonly version: number;
  readonly updatedAt: string;
  readonly latestIntegrityReceiptId?: string;
  readonly availableHumanActions: readonly HumanResearchPromotionAction[];
  readonly rollbackTargets: readonly {
    readonly experimentId: string;
    readonly strategyVersionId: string;
  }[];
  readonly transitions: readonly ResearchPromotionTransitionRecord[];
}

export interface ResearchPromotionMutation {
  readonly schemaVersion: "2.4";
  readonly lifecycle: ResearchPromotionLifecycleRecord;
}

interface LifecycleRow {
  readonly experiment_id: string;
  readonly campaign_id: string;
  readonly strategy_version_id: string;
  readonly promotion_record_json: string;
  readonly record_hash: string;
  readonly version: number;
  readonly created_at: string;
  readonly updated_at: string;
}

interface TransitionRow {
  readonly id: string;
  readonly sequence: number;
  readonly lifecycle_version: number;
  readonly from_state: PromotionState;
  readonly to_state: PromotionState;
  readonly action: LocalResearchPromotionAction | HumanResearchPromotionAction;
  readonly actor_kind: PromotionDecisionContext["actorKind"];
  readonly actor_id: string;
  readonly rationale: string;
  readonly evidence_refs_json: string;
  readonly hard_gate_failures_json: string;
  readonly decision_fingerprint: string | null;
  readonly integrity_receipt_id: string | null;
  readonly exposure_receipt_ids_json: string;
  readonly deployment_id: string | null;
  readonly created_at: string;
}

interface IntegrityReceiptRow {
  readonly id: string;
  readonly experiment_id: string;
  readonly charter_hash: string;
  readonly strategy_hashes_json: string;
  readonly evaluator_version: string;
  readonly evaluation_stage: ExperimentIntegrityReceipt["evaluationStage"];
  readonly evaluation_action: ExperimentIntegrityReceipt["evaluationAction"];
  readonly evaluation_result: ExperimentIntegrityReceipt["evaluationResult"];
  readonly evaluation_attempt_id: string;
  readonly hard_gate_failures_json: string;
  readonly evaluator_hash: string;
  readonly benchmark_snapshot_hash: string;
  readonly container_image_digest: string;
  readonly execution_environment_kind: string;
  readonly execution_environment_identity_hash: string;
  readonly tool_manifest_hash: string;
  readonly provider_model_json: string;
  readonly context_pack_ids_json: string;
  readonly random_seeds_json: string;
  readonly event_hash: string;
  readonly evidence_hash: string;
  readonly metrics_hash: string;
  readonly exposure_receipt_ids_json: string;
  readonly algorithm: "legacy_unverified" | "hmac-sha256";
  readonly signature: string;
  readonly signed_at: string;
}

interface ExperimentScopeRow {
  readonly experiment_id: string;
  readonly campaign_id: string;
  readonly charter_hash: string;
  readonly baseline_strategy_id: string;
  readonly baseline_strategy_hash: string;
  readonly candidate_strategy_id: string;
  readonly candidate_strategy_hash: string;
  readonly benchmark_snapshot_hash: string;
  readonly evaluator_version: string;
  readonly evaluator_hash: string;
  readonly tool_manifest_hash: string;
  readonly container_image_digest: string;
  readonly execution_environment_kind: string;
  readonly execution_environment_identity_hash: string;
  readonly public_llm_spec_hash: string | null;
}

interface IdempotencyValue<T> {
  readonly requestHash: string;
  readonly response: T;
}

function error(
  status: number,
  code: string,
  humanMessage: string,
  category: string,
  remediation?: string,
): MissionApiError {
  return new MissionApiError(status, code, humanMessage, {
    humanMessage,
    category,
    ...(remediation ? { remediation } : {}),
  });
}

function parseStringArray(value: string, label: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  if (
    !Array.isArray(parsed)
    || parsed.some((item) => typeof item !== "string" || item.trim().length === 0)
  ) {
    throw new Error(`${label} is not a stable string array.`);
  }
  return parsed;
}

function promotionStage(record: PromotionRecord): ResearchPromotionStage {
  if (
    record.state === "policy_rejected"
    || record.state === "early_aborted"
    || record.state === "failed"
    || record.state === "holdout_failed"
    || record.state === "rejected"
    || record.state === "stale"
    || record.state === "superseded"
    || record.state === "rolled_back"
  ) return "terminal";
  if (record.state === "verified") return "verified";
  if (record.state === "shadow_ready" || record.state === "shadow_running") return "shadow";
  if (record.state === "canary_ready" || record.state === "canary_running") return "bounded_canary";
  if (record.state === "benchmarked") {
    return record.milestones.hiddenHoldoutPassed ? "human_review" : "hidden_holdout";
  }
  if (record.state === "proposed" || record.state === "queued") return "development";
  if (record.state === "running") {
    return record.milestones.developmentPassed ? "validation" : "development";
  }
  return "terminal";
}

function humanActions(record: PromotionRecord): HumanResearchPromotionAction[] {
  if (record.state === "benchmarked" && record.milestones.hiddenHoldoutPassed) {
    return ["approve_human_review", "reject_human_review"];
  }
  if (record.state === "shadow_ready") return ["start_shadow", "reject"];
  if (record.state === "shadow_running" && record.milestones.shadowPassed) {
    return ["approve_canary", "reject"];
  }
  if (record.state === "canary_ready") return ["start_canary", "reject"];
  if (record.state === "canary_running" && record.milestones.canaryPassed) {
    return ["verify", "reject"];
  }
  if (record.state === "verified") {
    return ["mark_stale", "supersede", "rollback"];
  }
  if (
    record.state === "proposed"
    || record.state === "queued"
    || record.state === "running"
    || record.state === "shadow_running"
    || record.state === "canary_running"
  ) return ["reject"];
  return [];
}

function idempotencySetting(
  actorId: string,
  operation: string,
  key: string,
): string {
  return `idempotency.research.${operation}.${sha256(actorId)}.${sha256(key)}`;
}

function assertText(
  value: string,
  label: string,
  minimum = 3,
  maximum = 4_000,
  allowReadableWhitespace = false,
): string {
  const result = value.trim();
  const unsafeControl = allowReadableWhitespace
    ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u
    : /[\u0000-\u001f\u007f]/u;
  if (
    result.length < minimum
    || result.length > maximum
    || unsafeControl.test(result)
  ) {
    throw error(
      400,
      "invalid_research_promotion_request",
      `${label} must contain ${minimum} to ${maximum} readable characters.`,
      "invalid_input",
    );
  }
  return result;
}

function assertEvidenceRefs(values: readonly string[]): string[] {
  const result = [...new Set(values.map((value) => value.trim()))];
  if (
    result.length === 0
    || result.some((value) =>
      value.length === 0
      || value.length > 500
      || /[\u0000-\u001f\u007f]/u.test(value))
  ) {
    throw error(
      400,
      "research_promotion_evidence_required",
      "Promotion decisions require at least one stable evidence or receipt reference.",
      "invalid_input",
    );
  }
  return result;
}

function assertHardGates(values: readonly string[]): HardGateCode[] {
  const result = [...new Set(values)];
  if (result.some((value) => !HARD_GATE_CODES.includes(value as HardGateCode))) {
    throw error(
      400,
      "unknown_research_hard_gate",
      "The evaluator returned a hard-gate code that is not owned by the immutable harness.",
      "integrity",
    );
  }
  return result as HardGateCode[];
}

export class ResearchPromotionLifecycleRepository {
  readonly #promotion = new PromotionService();

  constructor(
    private readonly database: SqliteDatabase,
    private readonly integrityAuthority?: IntegrityAuthority,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  private experimentScope(experimentId: string): ExperimentScopeRow {
    const row = this.database.prepare(`
      SELECT
        experiment.id AS experiment_id,
        experiment.campaign_id,
        charter.charter_hash,
        experiment.baseline_strategy_id,
        baseline.bundle_hash AS baseline_strategy_hash,
        experiment.candidate_strategy_id,
        candidate.bundle_hash AS candidate_strategy_hash,
        snapshot.snapshot_hash AS benchmark_snapshot_hash,
        family.evaluator_version,
        snapshot.evaluator_hash,
        snapshot.tool_manifest_hash,
        snapshot.container_image_digest,
        snapshot.execution_environment_kind,
        snapshot.execution_environment_identity_hash,
        experiment.public_llm_spec_hash
      FROM experiments experiment
      JOIN research_charters charter ON charter.id = experiment.charter_id
      JOIN strategy_versions baseline
        ON baseline.id = experiment.baseline_strategy_id
      JOIN strategy_versions candidate
        ON candidate.id = experiment.candidate_strategy_id
      JOIN benchmark_snapshots snapshot
        ON snapshot.id = experiment.benchmark_snapshot_id
      JOIN benchmark_families family
        ON family.id = snapshot.family_id
      WHERE experiment.id = ?
    `).get(experimentId) as ExperimentScopeRow | undefined;
    if (!row) {
      throw error(
        404,
        "research_experiment_not_found",
        "The requested experiment does not exist or its immutable bindings are incomplete.",
        "not_found",
      );
    }
    return row;
  }

  private lifecycleRow(experimentId: string): LifecycleRow {
    const row = this.database.prepare(`
      SELECT *
      FROM research_promotion_lifecycles
      WHERE experiment_id = ?
    `).get(experimentId) as LifecycleRow | undefined;
    if (!row) {
      throw error(
        404,
        "research_promotion_not_found",
        "This experiment does not have a durable promotion lifecycle.",
        "not_found",
      );
    }
    return row;
  }

  private promotionRecord(row: LifecycleRow): PromotionRecord {
    const record = JSON.parse(row.promotion_record_json) as PromotionRecord;
    this.#promotion.validate(record);
    if (
      record.strategyVersionId !== row.strategy_version_id
      || hashCanonical(record) !== row.record_hash
    ) {
      throw error(
        500,
        "research_promotion_integrity_failed",
        "The durable promotion projection does not match its immutable strategy binding.",
        "integrity",
      );
    }
    return record;
  }

  private transitionRows(experimentId: string): TransitionRow[] {
    return this.database.prepare(`
      SELECT *
      FROM research_promotion_transitions
      WHERE experiment_id = ?
      ORDER BY sequence ASC
    `).all(experimentId) as TransitionRow[];
  }

  private rollbackTargets(
    row: LifecycleRow,
  ): ResearchPromotionLifecycleRecord["rollbackTargets"] {
    return (this.database.prepare(`
      SELECT lifecycle.experiment_id, lifecycle.strategy_version_id
      FROM research_promotion_lifecycles lifecycle
      JOIN experiments experiment ON experiment.id = lifecycle.experiment_id
      JOIN strategy_versions strategy
        ON strategy.id = lifecycle.strategy_version_id
      WHERE lifecycle.campaign_id = ?
        AND lifecycle.strategy_version_id <> ?
        AND strategy.status = 'verified'
      ORDER BY lifecycle.updated_at DESC, lifecycle.strategy_version_id ASC
    `).all(row.campaign_id, row.strategy_version_id) as Array<{
      readonly experiment_id: string;
      readonly strategy_version_id: string;
    }>).map((target) => ({
      experimentId: target.experiment_id,
      strategyVersionId: target.strategy_version_id,
    }));
  }

  private record(row: LifecycleRow): ResearchPromotionLifecycleRecord {
    const promotion = this.promotionRecord(row);
    const transitions = this.transitionRows(row.experiment_id).map(
      (transition): ResearchPromotionTransitionRecord => ({
        id: transition.id,
        sequence: transition.sequence,
        version: transition.lifecycle_version,
        fromState: transition.from_state,
        toState: transition.to_state,
        action: transition.action,
        actorKind: transition.actor_kind,
        actorId: transition.actor_id,
        rationale: transition.rationale,
        evidenceRefs: parseStringArray(
          transition.evidence_refs_json,
          "Promotion evidence references",
        ),
        hardGateFailures: assertHardGates(
          parseStringArray(
            transition.hard_gate_failures_json,
            "Promotion hard gates",
          ),
        ),
        ...(transition.decision_fingerprint
          ? { decisionFingerprint: transition.decision_fingerprint }
          : {}),
        ...(transition.integrity_receipt_id
          ? { integrityReceiptId: transition.integrity_receipt_id }
          : {}),
        exposureReceiptIds: parseStringArray(
          transition.exposure_receipt_ids_json,
          "Promotion exposure receipts",
        ),
        ...(transition.deployment_id
          ? { deploymentId: transition.deployment_id }
          : {}),
        createdAt: transition.created_at,
      }),
    );
    const latestIntegrityReceiptId = [...transitions]
      .reverse()
      .find((transition) => transition.integrityReceiptId)
      ?.integrityReceiptId;
    return {
      experimentId: row.experiment_id,
      campaignId: row.campaign_id,
      strategyVersionId: row.strategy_version_id,
      state: promotion.state,
      stage: promotionStage(promotion),
      milestones: promotion.milestones,
      version: row.version,
      updatedAt: row.updated_at,
      ...(latestIntegrityReceiptId ? { latestIntegrityReceiptId } : {}),
      availableHumanActions: humanActions(promotion),
      rollbackTargets: this.rollbackTargets(row),
      transitions,
    };
  }

  list(): ResearchPromotionLifecycleRecord[] {
    return (this.database.prepare(`
      SELECT *
      FROM research_promotion_lifecycles
      ORDER BY updated_at DESC, experiment_id ASC
      LIMIT 50
    `).all() as LifecycleRow[]).map((row) => this.record(row));
  }

  get(experimentId: string): ResearchPromotionLifecycleRecord {
    return this.record(this.lifecycleRow(experimentId));
  }

  initialize(input: {
    readonly experimentId: string;
    readonly actorId: string;
  }): ResearchPromotionLifecycleRecord {
    const actorId = assertText(input.actorId, "Local policy actor", 1, 240);
    return inImmediateTransaction(this.database, () => {
      const existing = this.database.prepare(`
        SELECT experiment_id
        FROM research_promotion_lifecycles
        WHERE experiment_id = ?
      `).get(input.experimentId) as { readonly experiment_id: string } | undefined;
      if (existing) return this.get(existing.experiment_id);
      const scope = this.experimentScope(input.experimentId);
      const now = this.clock().toISOString();
      const promotion = this.#promotion.create(scope.candidate_strategy_id);
      this.database.prepare(`
        INSERT INTO research_promotion_lifecycles (
          experiment_id, campaign_id, strategy_version_id,
          promotion_record_json, record_hash, version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
      `).run(
        scope.experiment_id,
        scope.campaign_id,
        scope.candidate_strategy_id,
        canonicalJson(promotion),
        hashCanonical(promotion),
        now,
        now,
      );
      this.appendAudit(
        actorId,
        "local_policy",
        "research_promotion.initialized",
        scope.experiment_id,
        "Local policy compiler initialized a durable candidate lifecycle.",
        {
          campaignId: scope.campaign_id,
          strategyVersionId: scope.candidate_strategy_id,
          state: promotion.state,
          automaticProductionDeployment: false,
        },
        now,
      );
      return this.get(scope.experiment_id);
    });
  }

  persistExposureReceipt(
    receipt: ProviderExposureReceipt,
  ): ProviderExposureReceipt {
    if (receipt.blocked) {
      throw error(
        409,
        "research_provider_exposure_blocked",
        "A blocked provider exposure receipt cannot authorize an experiment proposal.",
        "privacy",
      );
    }
    if (!receipt.experimentId) {
      throw error(
        400,
        "research_exposure_experiment_required",
        "Research provider exposure must be bound to one experiment.",
        "integrity",
      );
    }
    const scope = this.database.prepare(`
      SELECT experiment.id, experiment.campaign_id, dimension.name
      FROM experiments experiment
      JOIN research_dimensions dimension
        ON dimension.id = experiment.dimension_id
      WHERE experiment.id = ?
    `).get(receipt.experimentId) as {
      readonly id: string;
      readonly campaign_id: string;
      readonly name: string;
    } | undefined;
    if (!scope) throw error(404, "research_experiment_not_found", "The exposure receipt experiment does not exist.", "not_found");
    const reasons = validateProviderExposureReceipt(receipt, {
      campaignId: scope.campaign_id,
      dimensionId: scope.name,
      experimentId: scope.id,
    });
    if (reasons.length > 0) {
      throw error(
        409,
        "research_exposure_integrity_failed",
        `The provider exposure receipt is not disclosure-safe: ${reasons.join(" ")}`,
        "privacy",
      );
    }
    this.database.prepare(`
      INSERT INTO provider_exposure_receipts (
        id, provider_id, model_id, experiment_id,
        disclosure_policy_version, input_classification,
        selected_context_ids_json, rejected_context_ids_json,
        sanitization_actions_json, untrusted_content_envelope_hash,
        exposed_payload_hash, blocked, block_reason, created_at
      ) VALUES (?, ?, ?, ?, ?, 'sanitized_research_brief', ?, ?, ?, ?, ?, 0, NULL, ?)
    `).run(
      receipt.id,
      receipt.providerId,
      receipt.modelId,
      receipt.experimentId,
      receipt.disclosurePolicyVersion,
      canonicalJson(receipt.selectedContextIds),
      canonicalJson(receipt.rejectedContext),
      canonicalJson(receipt.sanitizationActions),
      receipt.untrustedContentEnvelopeHash ?? null,
      receipt.exposedPayloadHash,
      receipt.createdAt,
    );
    return receipt;
  }

  persistIntegrityReceipt(
    receipt: ExperimentIntegrityReceipt,
  ): ExperimentIntegrityReceipt {
    if (!this.integrityAuthority) {
      throw error(
        503,
        "research_integrity_verifier_unavailable",
        "The local evaluator integrity verifier is unavailable.",
        "dependency_missing",
        "Configure the local Research Lab HMAC authority before accepting experiment results.",
      );
    }
    const scope = this.experimentScope(receipt.experimentId);
    if (
      scope.execution_environment_kind === "legacy_unverified"
      || scope.execution_environment_identity_hash === "legacy_unverified"
    ) {
      throw error(
        409,
        "research_execution_environment_attestation_required",
        "The immutable benchmark snapshot has no attested execution-environment identity.",
        "integrity",
        "Re-attest the exact local execution environment before recording evaluator results.",
      );
    }
    this.integrityAuthority.assertReceipt(receipt, {
      experimentId: scope.experiment_id,
      charterHash: scope.charter_hash,
      baselineStrategyHash: scope.baseline_strategy_hash,
      candidateStrategyHash: scope.candidate_strategy_hash,
      benchmarkSnapshotHash: scope.benchmark_snapshot_hash,
      evaluatorVersion: scope.evaluator_version,
      evaluatorHash: scope.evaluator_hash,
      containerImageDigest: scope.execution_environment_kind === "local_bwrap"
        ? "not_applicable:local_bwrap"
        : scope.container_image_digest,
      executionEnvironmentKind:
        scope.execution_environment_kind as "local_bwrap" | "oci_container",
      executionEnvironmentIdentityHash:
        scope.execution_environment_identity_hash,
      toolManifestHash: scope.tool_manifest_hash,
      exposureReceiptIds: receipt.exposureReceiptIds,
    });
    if (scope.public_llm_spec_hash === null) {
      if (
        receipt.providerModel !== null
        || receipt.exposureReceiptIds.length !== 0
      ) {
        throw error(
          409,
          "research_unexpected_provider_binding",
          "This built-in local experiment cannot contain a public-provider binding.",
          "integrity",
        );
      }
    } else if (!receipt.providerModel) {
      throw error(
        409,
        "research_provider_binding_required",
        "The experiment result lacks its immutable provider, model, or prompt-template binding.",
        "integrity",
      );
    }
    if (
      scope.public_llm_spec_hash !== null
      && receipt.providerModel
      && receipt.providerModel.promptTemplateHash
        !== scope.public_llm_spec_hash
    ) {
      throw error(
        409,
        "research_prompt_binding_mismatch",
        "The signed prompt-template hash does not match the immutable experiment proposal.",
        "integrity",
      );
    }
    for (const exposureId of receipt.exposureReceiptIds) {
      const exposure = this.database.prepare(`
        SELECT id, provider_id, model_id
        FROM provider_exposure_receipts
        WHERE id = ?
          AND experiment_id = ?
          AND blocked = 0
          AND input_classification = 'sanitized_research_brief'
      `).get(exposureId, receipt.experimentId) as {
        readonly id: string;
        readonly provider_id: string;
        readonly model_id: string;
      } | undefined;
      if (!exposure) {
        throw error(
          409,
          "research_exposure_receipt_missing",
          "The signed result references a missing, blocked, or differently scoped provider exposure receipt.",
          "integrity",
        );
      }
      if (
        exposure.provider_id !== receipt.providerModel?.providerId
        || exposure.model_id !== receipt.providerModel?.modelId
      ) {
        throw error(
          409,
          "research_provider_binding_mismatch",
          "The signed provider/model does not match its disclosure receipt.",
          "integrity",
        );
      }
    }
    this.database.prepare(`
      INSERT INTO integrity_receipts (
        id, experiment_id, charter_hash, strategy_hashes_json,
        evaluator_hash, benchmark_snapshot_hash, container_image_digest,
        tool_manifest_hash, provider_model_json, context_pack_ids_json,
        random_seeds_json, event_hash, evidence_hash, metrics_hash,
        exposure_receipt_ids_json, signature, signed_at, algorithm,
        evaluator_version, evaluation_stage, evaluation_action,
        evaluation_result, evaluation_attempt_id, hard_gate_failures_json
        , execution_environment_kind,
        execution_environment_identity_hash
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        'hmac-sha256', ?, ?, ?, ?, ?, ?, ?, ?
      )
    `).run(
      receipt.id,
      receipt.experimentId,
      receipt.charterHash,
      canonicalJson(receipt.strategyHashes),
      receipt.evaluatorHash,
      receipt.benchmarkSnapshotHash,
      receipt.containerImageDigest,
      receipt.toolManifestHash,
      canonicalJson(receipt.providerModel),
      canonicalJson(receipt.contextPackIds),
      canonicalJson(receipt.randomSeeds),
      receipt.eventHash,
      receipt.evidenceHash,
      receipt.metricsHash,
      canonicalJson(receipt.exposureReceiptIds),
      receipt.signature,
      receipt.signedAt,
      receipt.evaluatorVersion,
      receipt.evaluationStage,
      receipt.evaluationAction,
      receipt.evaluationResult,
      receipt.evaluationAttemptId,
      canonicalJson(receipt.hardGateFailures),
      receipt.executionEnvironment?.kind ?? "legacy_unverified",
      receipt.executionEnvironment?.identityHash ?? "legacy_unverified",
    );
    return receipt;
  }

  private integrityReceipt(
    experimentId: string,
    integrityReceiptId: string,
  ): {
    readonly receipt: ExperimentIntegrityReceipt;
    readonly exposureReceiptIds: readonly string[];
  } {
    if (!this.integrityAuthority) {
      throw error(
        503,
        "research_integrity_verifier_unavailable",
        "The local evaluator integrity verifier is unavailable.",
        "dependency_missing",
        "Configure the local Research Lab HMAC authority before advancing this candidate.",
      );
    }
    const row = this.database.prepare(`
      SELECT *
      FROM integrity_receipts
      WHERE id = ? AND experiment_id = ?
    `).get(integrityReceiptId, experimentId) as IntegrityReceiptRow | undefined;
    if (!row || row.algorithm !== "hmac-sha256") {
      throw error(
        409,
        "research_integrity_receipt_required",
        "This transition requires a locally signed integrity receipt for the same experiment.",
        "integrity",
      );
    }
    const receipt: ExperimentIntegrityReceipt = {
      id: row.id,
      algorithm: "hmac-sha256",
      experimentId: row.experiment_id,
      charterHash: row.charter_hash,
      strategyHashes: JSON.parse(row.strategy_hashes_json) as ExperimentIntegrityReceipt["strategyHashes"],
      evaluatorVersion: row.evaluator_version,
      evaluatorHash: row.evaluator_hash,
      benchmarkSnapshotHash: row.benchmark_snapshot_hash,
      containerImageDigest: row.container_image_digest,
      ...(row.execution_environment_kind === "legacy_unverified"
        ? {}
        : {
            executionEnvironment: {
              kind: row.execution_environment_kind as
                "local_bwrap" | "oci_container",
              identityHash:
                row.execution_environment_identity_hash,
            },
          }),
      toolManifestHash: row.tool_manifest_hash,
      providerModel: JSON.parse(row.provider_model_json) as ExperimentIntegrityReceipt["providerModel"],
      contextPackIds: parseStringArray(row.context_pack_ids_json, "Integrity context packs"),
      randomSeeds: parseStringArray(row.random_seeds_json, "Integrity random seeds"),
      eventHash: row.event_hash,
      evidenceHash: row.evidence_hash,
      metricsHash: row.metrics_hash,
      exposureReceiptIds: parseStringArray(
        row.exposure_receipt_ids_json,
        "Integrity exposure receipts",
      ),
      evaluationStage: row.evaluation_stage,
      evaluationAction: row.evaluation_action,
      evaluationResult: row.evaluation_result,
      evaluationAttemptId: row.evaluation_attempt_id,
      hardGateFailures: parseStringArray(
        row.hard_gate_failures_json,
        "Integrity hard-gate failures",
      ),
      signature: row.signature,
      signedAt: row.signed_at,
    };
    const scope = this.experimentScope(experimentId);
    this.integrityAuthority.assertReceipt(receipt, {
      experimentId,
      charterHash: scope.charter_hash,
      baselineStrategyHash: scope.baseline_strategy_hash,
      candidateStrategyHash: scope.candidate_strategy_hash,
      benchmarkSnapshotHash: scope.benchmark_snapshot_hash,
      evaluatorVersion: scope.evaluator_version,
      evaluatorHash: scope.evaluator_hash,
      containerImageDigest: scope.execution_environment_kind === "local_bwrap"
        ? "not_applicable:local_bwrap"
        : scope.container_image_digest,
      executionEnvironmentKind:
        scope.execution_environment_kind as "local_bwrap" | "oci_container",
      executionEnvironmentIdentityHash:
        scope.execution_environment_identity_hash,
      toolManifestHash: scope.tool_manifest_hash,
      exposureReceiptIds: receipt.exposureReceiptIds,
    });
    if (scope.public_llm_spec_hash === null) {
      if (
        receipt.providerModel !== null
        || receipt.exposureReceiptIds.length !== 0
      ) {
        throw error(
          409,
          "research_provider_binding_mismatch",
          "The local built-in result unexpectedly references a public provider.",
          "integrity",
        );
      }
    } else if (
      !receipt.providerModel
      || receipt.providerModel.promptTemplateHash
        !== scope.public_llm_spec_hash
    ) {
      throw error(
        409,
        "research_provider_binding_mismatch",
        "The signed provider prompt does not match the immutable experiment proposal.",
        "integrity",
      );
    }
    for (const exposureId of receipt.exposureReceiptIds) {
      const exposure = this.database.prepare(`
        SELECT id, provider_id, model_id
        FROM provider_exposure_receipts
        WHERE id = ?
          AND experiment_id = ?
          AND blocked = 0
          AND input_classification = 'sanitized_research_brief'
      `).get(exposureId, experimentId) as {
        readonly id: string;
        readonly provider_id: string;
        readonly model_id: string;
      } | undefined;
      if (!exposure) {
        throw error(
          409,
          "research_exposure_receipt_missing",
          "The integrity receipt includes a provider exposure that is missing, blocked, or outside this experiment.",
          "privacy",
        );
      }
      if (
        exposure.provider_id !== receipt.providerModel?.providerId
        || exposure.model_id !== receipt.providerModel?.modelId
      ) {
        throw error(
          409,
          "research_provider_binding_mismatch",
          "The signed provider/model does not match its disclosure receipt.",
          "integrity",
        );
      }
    }
    return {
      receipt,
      exposureReceiptIds: receipt.exposureReceiptIds,
    };
  }

  private latestIntegrityReceiptId(experimentId: string): string {
    const row = this.database.prepare(`
      SELECT integrity_receipt_id
      FROM research_promotion_transitions
      WHERE experiment_id = ? AND integrity_receipt_id IS NOT NULL
      ORDER BY sequence DESC
      LIMIT 1
    `).get(experimentId) as {
      readonly integrity_receipt_id: string;
    } | undefined;
    if (!row) {
      throw error(
        409,
        "research_integrity_receipt_required",
        "The previous trusted stage did not produce a signed integrity receipt.",
        "integrity",
      );
    }
    return row.integrity_receipt_id;
  }

  applyLocalTransition(input: {
    readonly experimentId: string;
    readonly expectedVersion: number;
    readonly action: LocalResearchPromotionAction;
    readonly actorId: string;
    readonly rationale: string;
    readonly evidenceRefs: readonly string[];
    readonly hardGateFailures?: readonly string[];
    readonly integrityReceiptId?: string;
  }): ResearchPromotionLifecycleRecord {
    const actorId = assertText(input.actorId, "Local evaluator actor", 1, 240);
    const rationale = assertText(input.rationale, "Evaluator rationale");
    const evidenceRefs = assertEvidenceRefs(input.evidenceRefs);
    const hardGateFailures = assertHardGates(input.hardGateFailures ?? []);
    const passingResult = input.action.endsWith("_pass");
    if (passingResult && hardGateFailures.length > 0) {
      throw error(
        409,
        "research_hard_gate_failed",
        "A candidate with a hard-gate failure cannot advance.",
        "policy_denied",
        "Record the failed result, retain its evidence, and review a different candidate.",
      );
    }
    return inImmediateTransaction(this.database, () => {
      const row = this.lifecycleRow(input.experimentId);
      this.assertVersion(row, input.expectedVersion);
      const current = this.promotionRecord(row);
      const context: PromotionDecisionContext = {
        actorId,
        actorKind: input.action.startsWith("policy_")
          ? "local_policy"
          : "local_evaluator",
        rationale,
        evidenceRefs,
        occurredAt: this.clock().toISOString(),
      };
      const next = this.applyLocalAction(current, input.action, context);
      const requiresReceipt = /^(?:development|validation|hidden_holdout|shadow|canary)_(?:pass|fail)$/u
        .test(input.action);
      const receipt = requiresReceipt
        ? this.integrityReceipt(
            input.experimentId,
            input.integrityReceiptId
              ?? (() => {
                throw error(
                  409,
                  "research_integrity_receipt_required",
                  "Evaluator results require their exact locally signed integrity receipt.",
                  "integrity",
                );
              })(),
          )
        : undefined;
      if (receipt) {
        const expectedStage = input.action.startsWith("hidden_holdout_")
          ? "hidden_holdout"
          : input.action.split("_", 1)[0] as
            ExperimentIntegrityReceipt["evaluationStage"];
        this.integrityAuthority!.assertReceipt(receipt.receipt, {
          evaluationStage: expectedStage,
          evaluationAction: input.action as
            ExperimentIntegrityReceipt["evaluationAction"],
          evaluationResult: passingResult ? "pass" : "fail",
          hardGateFailures,
        });
        const used = this.database.prepare(`
          SELECT id
          FROM research_promotion_transitions
          WHERE integrity_receipt_id = ?
            AND action IN (
              'development_pass', 'development_fail',
              'validation_pass', 'validation_fail',
              'hidden_holdout_pass', 'hidden_holdout_fail',
              'shadow_pass', 'shadow_fail',
              'canary_pass', 'canary_fail'
            )
        `).get(receipt.receipt.id);
        if (used) {
          throw error(
            409,
            "research_integrity_receipt_reused",
            "This signed evaluator attempt has already been consumed by a lifecycle transition.",
            "integrity",
          );
        }
      }
      return this.persistTransition({
        row,
        current,
        next,
        action: input.action,
        context,
        hardGateFailures,
        ...(receipt
          ? {
              integrityReceiptId: receipt.receipt.id,
              exposureReceiptIds: receipt.exposureReceiptIds,
            }
          : {}),
      });
    });
  }

  applyHumanTransition(input: {
    readonly experimentId: string;
    readonly expectedVersion: number;
    readonly action: HumanResearchPromotionAction;
    readonly actorId: string;
    readonly rationale: string;
    readonly evidenceRefs: readonly string[];
    readonly targetStrategyVersionId?: string;
    readonly canaryBounds?: CanaryBounds;
    readonly idempotencyKey: string;
  }): ResearchPromotionMutation {
    const actorId = assertText(input.actorId, "Human reviewer", 1, 240);
    const rationale = assertText(
      input.rationale,
      "Review rationale",
      3,
      4_000,
      true,
    );
    const evidenceRefs = assertEvidenceRefs(input.evidenceRefs);
    const targetStrategyVersionId = input.targetStrategyVersionId?.trim();
    const decisionFingerprint = sha256(canonicalResearchPromotionDecision({
      expectedVersion: input.expectedVersion,
      action: input.action,
      actorId,
      rationale,
      evidenceRefs,
      ...(targetStrategyVersionId ? { targetStrategyVersionId } : {}),
      ...(input.canaryBounds ? { canaryBounds: input.canaryBounds } : {}),
    }));
    const requestHash = hashCanonical({
      experimentId: input.experimentId,
      expectedVersion: input.expectedVersion,
      action: input.action,
      rationale,
      evidenceRefs,
      targetStrategyVersionId: targetStrategyVersionId ?? null,
      canaryBounds: input.canaryBounds ?? null,
    });
    const replay = this.readIdempotency<ResearchPromotionMutation>(
      actorId,
      "promotion-transition",
      input.idempotencyKey,
      requestHash,
    );
    if (replay) return replay;
    return inImmediateTransaction(this.database, () => {
      const prior = this.readIdempotency<ResearchPromotionMutation>(
        actorId,
        "promotion-transition",
        input.idempotencyKey,
        requestHash,
      );
      if (prior) return prior;
      const row = this.lifecycleRow(input.experimentId);
      this.assertVersion(row, input.expectedVersion);
      const current = this.promotionRecord(row);
      if (!humanActions(current).includes(input.action)) {
        throw error(
          409,
          "research_promotion_action_unavailable",
          `The ${input.action.replaceAll("_", " ")} action is not valid from ${current.state}.`,
          "conflict",
          "Refresh the Research Lab and choose one of the currently represented actions.",
        );
      }
      if (
        input.action === "mark_stale"
        || input.action === "supersede"
        || input.action === "rollback"
      ) {
        const latestActivation = this.database.prepare(`
          SELECT selected_strategy_version_id
          FROM research_strategy_activation_versions
          WHERE campaign_id = ?
          ORDER BY ordinal DESC
          LIMIT 1
        `).get(row.campaign_id) as {
          readonly selected_strategy_version_id: string;
        } | undefined;
        if (
          latestActivation?.selected_strategy_version_id
          === row.strategy_version_id
          && input.action !== "rollback"
        ) {
          throw error(
            409,
            "research_active_strategy_requires_forward_selection",
            "The currently selected strategy cannot become stale or superseded without first selecting a different verified strategy.",
            "conflict",
            "Use the represented forward rollback action to select a verified fallback first.",
          );
        }
        if (
          input.action === "rollback"
          && latestActivation?.selected_strategy_version_id
            !== row.strategy_version_id
        ) {
          throw error(
            409,
            "research_rollback_source_not_active",
            "Rollback can originate only from the strategy selected by the latest immutable activation.",
            "conflict",
            "Refresh the lifecycle and review the currently selected strategy.",
          );
        }
      }
      const now = this.clock().toISOString();
      const context: PromotionDecisionContext = {
        actorId,
        actorKind: "human_reviewer",
        rationale,
        evidenceRefs,
        occurredAt: now,
      };
      let deploymentId: string | undefined;
      let integrityReceiptId: string | undefined;
      let exposureReceiptIds: readonly string[] = [];
      let next: PromotionRecord;
      if (input.action === "rollback") {
        const rollback = this.rollbackTransition({
          row,
          current,
          targetStrategyVersionId,
          context,
        });
        next = rollback.next;
        deploymentId = rollback.deploymentId;
        integrityReceiptId = rollback.currentIntegrityReceiptId;
        exposureReceiptIds = rollback.currentExposureReceiptIds;
      } else {
        next = this.applyHumanAction(current, input.action, context);
        if (
          input.action !== "reject"
          && input.action !== "reject_human_review"
          && input.action !== "mark_stale"
          && input.action !== "supersede"
        ) {
          integrityReceiptId = this.latestIntegrityReceiptId(input.experimentId);
          const receipt = this.integrityReceipt(
            input.experimentId,
            integrityReceiptId,
          );
          exposureReceiptIds = receipt.exposureReceiptIds;
        }
        if (input.action === "start_shadow") {
          deploymentId = this.createShadowDeployment(row, actorId, now);
        }
        if (input.action === "start_canary") {
          deploymentId = this.createCanaryDeployment(
            row,
            actorId,
            input.canaryBounds,
            now,
          );
        }
      }
      const lifecycle = this.persistTransition({
        row,
        current,
        next,
        action: input.action,
        context,
        hardGateFailures: [],
        decisionFingerprint,
        ...(integrityReceiptId ? { integrityReceiptId } : {}),
        exposureReceiptIds,
        ...(deploymentId ? { deploymentId } : {}),
      });
      if (input.action === "verify" && integrityReceiptId) {
        this.appendActivation({
          row,
          selectedStrategyVersionId: row.strategy_version_id,
          action: "verified_selection",
          reason: rationale,
          actorId,
          integrityReceiptId,
          now,
        });
      }
      const response: ResearchPromotionMutation = {
        schemaVersion: "2.4",
        lifecycle,
      };
      this.storeIdempotency(
        actorId,
        "promotion-transition",
        input.idempotencyKey,
        requestHash,
        response,
        now,
      );
      return response;
    });
  }

  private applyLocalAction(
    current: PromotionRecord,
    action: LocalResearchPromotionAction,
    context: PromotionDecisionContext,
  ): PromotionRecord {
    switch (action) {
      case "policy_accept": return this.#promotion.policyDecision(current, true, context);
      case "policy_reject": return this.#promotion.policyDecision(current, false, context);
      case "start_benchmark": return this.#promotion.startBenchmark(current, context);
      case "development_pass": return this.#promotion.developmentResult(current, true, context);
      case "development_fail": return this.#promotion.developmentResult(current, false, context);
      case "validation_pass": return this.#promotion.validationResult(current, true, context);
      case "validation_fail": return this.#promotion.validationResult(current, false, context);
      case "hidden_holdout_pass": return this.#promotion.hiddenHoldoutResult(current, true, context);
      case "hidden_holdout_fail": return this.#promotion.hiddenHoldoutResult(current, false, context);
      case "shadow_pass": return this.#promotion.shadowResult(current, true, context);
      case "shadow_fail": return this.#promotion.shadowResult(current, false, context);
      case "canary_pass": return this.#promotion.canaryResult(current, true, context);
      case "canary_fail": return this.#promotion.canaryResult(current, false, context);
    }
  }

  private applyHumanAction(
    current: PromotionRecord,
    action: Exclude<HumanResearchPromotionAction, "rollback">,
    context: PromotionDecisionContext,
  ): PromotionRecord {
    switch (action) {
      case "approve_human_review": return this.#promotion.humanReview(current, true, context);
      case "reject_human_review": return this.#promotion.humanReview(current, false, context);
      case "start_shadow": return this.#promotion.startShadow(current, context);
      case "approve_canary": return this.#promotion.approveCanary(current, context);
      case "start_canary": return this.#promotion.startCanary(current, context);
      case "verify": return this.#promotion.verify(current, context);
      case "reject": return this.#promotion.reject(current, context);
      case "mark_stale": return this.#promotion.markStale(current, context);
      case "supersede": return this.#promotion.supersede(current, context);
    }
  }

  private assertVersion(row: LifecycleRow, expectedVersion: number): void {
    if (
      !Number.isSafeInteger(expectedVersion)
      || expectedVersion < 1
      || row.version !== expectedVersion
    ) {
      throw error(
        409,
        "research_promotion_version_conflict",
        "The candidate lifecycle changed after this view loaded.",
        "conflict",
        "Refresh the Research Lab, inspect the immutable transition history, and choose a current action.",
      );
    }
  }

  private createShadowDeployment(
    row: LifecycleRow,
    actorId: string,
    now: string,
  ): string {
    const id = `research_deployment_${randomUUID()}`;
    this.database.prepare(`
      INSERT INTO strategy_deployments (
        id, strategy_version_id, deployment_stage, scope_json, status,
        approved_by, started_at, created_at, isolation_mode,
        lifecycle_version
      ) VALUES (
        ?, ?, 'shadow', ?, 'running', ?, ?, ?, 'no_live_effect', ?
      )
    `).run(
      id,
      row.strategy_version_id,
      canonicalJson({
        liveExecutionEffect: false,
        environment: "isolated_shadow",
        productionMutationAllowed: false,
      }),
      actorId,
      now,
      now,
      row.version + 1,
    );
    return id;
  }

  private createCanaryDeployment(
    row: LifecycleRow,
    actorId: string,
    bounds: CanaryBounds | undefined,
    now: string,
  ): string {
    if (
      !bounds
      || !Number.isSafeInteger(bounds.maxMissions)
      || bounds.maxMissions < 1
      || bounds.maxMissions > 10
      || !Number.isSafeInteger(bounds.maxWallClockMs)
      || bounds.maxWallClockMs < 60_000
      || bounds.maxWallClockMs > 86_400_000
    ) {
      throw error(
        400,
        "research_canary_bounds_required",
        "Bounded canary requires one to ten missions and a one-minute to twenty-four-hour time limit.",
        "invalid_input",
      );
    }
    const id = `research_deployment_${randomUUID()}`;
    this.database.prepare(`
      INSERT INTO strategy_deployments (
        id, strategy_version_id, deployment_stage, scope_json, status,
        approved_by, started_at, created_at, isolation_mode,
        max_missions, max_wall_clock_ms, lifecycle_version
      ) VALUES (
        ?, ?, 'canary', ?, 'running', ?, ?, ?, 'bounded_canary', ?, ?, ?
      )
    `).run(
      id,
      row.strategy_version_id,
      canonicalJson({
        liveExecutionEffect: "bounded_only",
        productionDeployment: false,
        maxMissions: bounds.maxMissions,
        maxWallClockMs: bounds.maxWallClockMs,
      }),
      actorId,
      now,
      now,
      bounds.maxMissions,
      bounds.maxWallClockMs,
      row.version + 1,
    );
    return id;
  }

  private rollbackTransition(input: {
    readonly row: LifecycleRow;
    readonly current: PromotionRecord;
    readonly targetStrategyVersionId?: string;
    readonly context: PromotionDecisionContext;
  }): {
    readonly next: PromotionRecord;
    readonly deploymentId: string;
    readonly currentIntegrityReceiptId: string;
    readonly currentExposureReceiptIds: readonly string[];
  } {
    if (!input.targetStrategyVersionId) {
      throw error(
        400,
        "research_rollback_target_required",
        "Choose a different previously verified strategy for the forward rollback transition.",
        "invalid_input",
      );
    }
    const target = this.database.prepare(`
      SELECT lifecycle.experiment_id, lifecycle.strategy_version_id
      FROM research_promotion_lifecycles lifecycle
      JOIN strategy_versions strategy
        ON strategy.id = lifecycle.strategy_version_id
      WHERE lifecycle.campaign_id = ?
        AND lifecycle.strategy_version_id = ?
        AND lifecycle.strategy_version_id <> ?
        AND strategy.status = 'verified'
    `).get(
      input.row.campaign_id,
      input.targetStrategyVersionId,
      input.row.strategy_version_id,
    ) as {
      readonly experiment_id: string;
      readonly strategy_version_id: string;
    } | undefined;
    if (!target) {
      throw error(
        409,
        "research_rollback_target_not_verified",
        "Rollback can point only to a different previously verified strategy from this campaign.",
        "integrity",
      );
    }
    const deployment = this.database.prepare(`
      SELECT id
      FROM strategy_deployments
      WHERE strategy_version_id = ?
        AND status IN ('running', 'completed')
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `).get(input.row.strategy_version_id) as { readonly id: string } | undefined;
    if (!deployment) {
      throw error(
        409,
        "research_rollback_deployment_missing",
        "This candidate has no represented shadow or canary deployment to roll back.",
        "conflict",
      );
    }
    const currentIntegrityReceiptId = this.latestIntegrityReceiptId(
      input.row.experiment_id,
    );
    const currentIntegrity = this.integrityReceipt(
      input.row.experiment_id,
      currentIntegrityReceiptId,
    );
    const targetIntegrityReceiptId = this.latestIntegrityReceiptId(
      target.experiment_id,
    );
    this.integrityReceipt(target.experiment_id, targetIntegrityReceiptId);
    const rollback = this.#promotion.rollback(
      input.current,
      {
        strategyVersionId: target.strategy_version_id,
        state: "verified",
      },
      true,
      input.context,
    );
    const activationVersionId = this.appendActivation({
      row: input.row,
      selectedStrategyVersionId: target.strategy_version_id,
      action: "forward_rollback",
      reason: input.context.rationale,
      actorId: input.context.actorId,
      integrityReceiptId: targetIntegrityReceiptId,
      now: input.context.occurredAt,
    });
    const rollbackId = `research_rollback_${randomUUID()}`;
    this.database.prepare(`
      INSERT INTO strategy_rollbacks (
        id, deployment_id, from_strategy_id, to_strategy_id, reason,
        initiated_by, integrity_verified, rolled_back_at,
        activation_version_id
      ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
    `).run(
      rollbackId,
      deployment.id,
      input.row.strategy_version_id,
      target.strategy_version_id,
      input.context.rationale,
      input.context.actorId,
      input.context.occurredAt,
      activationVersionId,
    );
    this.database.prepare(`
      UPDATE strategy_deployments
      SET status = 'rolled_back', ended_at = ?
      WHERE id = ?
    `).run(input.context.occurredAt, deployment.id);
    return {
      next: rollback.promotion,
      deploymentId: deployment.id,
      currentIntegrityReceiptId,
      currentExposureReceiptIds: currentIntegrity.exposureReceiptIds,
    };
  }

  private appendActivation(input: {
    readonly row: LifecycleRow;
    readonly selectedStrategyVersionId: string;
    readonly action: "verified_selection" | "forward_rollback";
    readonly reason: string;
    readonly actorId: string;
    readonly integrityReceiptId: string;
    readonly now: string;
  }): string {
    const previous = this.database.prepare(`
      SELECT id, ordinal
      FROM research_strategy_activation_versions
      WHERE campaign_id = ?
      ORDER BY ordinal DESC
      LIMIT 1
    `).get(input.row.campaign_id) as {
      readonly id: string;
      readonly ordinal: number;
    } | undefined;
    const id = `research_activation_${randomUUID()}`;
    this.database.prepare(`
      INSERT INTO research_strategy_activation_versions (
        id, campaign_id, previous_activation_id,
        selected_strategy_version_id, source_experiment_id, ordinal,
        action, reason, actor_id, integrity_receipt_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      input.row.campaign_id,
      previous?.id ?? null,
      input.selectedStrategyVersionId,
      input.row.experiment_id,
      (previous?.ordinal ?? 0) + 1,
      input.action,
      input.reason,
      input.actorId,
      input.integrityReceiptId,
      input.now,
    );
    return id;
  }

  private persistTransition(input: {
    readonly row: LifecycleRow;
    readonly current: PromotionRecord;
    readonly next: PromotionRecord;
    readonly action: LocalResearchPromotionAction | HumanResearchPromotionAction;
    readonly context: PromotionDecisionContext;
    readonly hardGateFailures: readonly HardGateCode[];
    readonly decisionFingerprint?: string;
    readonly integrityReceiptId?: string;
    readonly exposureReceiptIds?: readonly string[];
    readonly deploymentId?: string;
  }): ResearchPromotionLifecycleRecord {
    this.#promotion.validate(input.next);
    const humanDecision = input.context.actorKind === "human_reviewer";
    if (
      (humanDecision && !/^[a-f0-9]{64}$/u.test(input.decisionFingerprint ?? ""))
      || (!humanDecision && input.decisionFingerprint !== undefined)
    ) {
      throw error(
        500,
        "research_promotion_decision_fingerprint_invalid",
        "The immutable transition could not be bound to its exact decision.",
        "integrity",
      );
    }
    const nextVersion = input.row.version + 1;
    const nextHash = hashCanonical(input.next);
    const auditId = this.appendAudit(
      input.context.actorId,
      input.context.actorKind,
      `research_promotion.${input.action}`,
      input.row.experiment_id,
      input.context.rationale,
      {
        strategyVersionId: input.row.strategy_version_id,
        fromState: input.current.state,
        toState: input.next.state,
        lifecycleVersion: nextVersion,
        decisionFingerprint: input.decisionFingerprint ?? null,
        evidenceRefs: input.context.evidenceRefs,
        hardGateFailures: input.hardGateFailures,
        integrityReceiptId: input.integrityReceiptId ?? null,
        exposureReceiptIds: input.exposureReceiptIds ?? [],
        deploymentId: input.deploymentId ?? null,
        automaticProductionDeployment: false,
      },
      input.context.occurredAt,
    );
    const transitionId = `research_transition_${randomUUID()}`;
    this.database.prepare(`
      INSERT INTO research_promotion_transitions (
        id, experiment_id, strategy_version_id, sequence,
        lifecycle_version, from_state, to_state, action,
        actor_kind, actor_id, rationale, evidence_refs_json,
        hard_gate_failures_json, decision_fingerprint, integrity_receipt_id,
        exposure_receipt_ids_json, deployment_id,
        previous_record_hash, resulting_record_hash,
        audit_record_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      transitionId,
      input.row.experiment_id,
      input.row.strategy_version_id,
      input.next.history.length,
      nextVersion,
      input.current.state,
      input.next.state,
      input.action,
      input.context.actorKind,
      input.context.actorId,
      input.context.rationale,
      canonicalJson(input.context.evidenceRefs),
      canonicalJson(input.hardGateFailures),
      input.decisionFingerprint ?? null,
      input.integrityReceiptId ?? null,
      canonicalJson(input.exposureReceiptIds ?? []),
      input.deploymentId ?? null,
      input.row.record_hash,
      nextHash,
      auditId,
      input.context.occurredAt,
    );
    const updated = this.database.prepare(`
      UPDATE research_promotion_lifecycles
      SET promotion_record_json = ?, record_hash = ?, version = ?, updated_at = ?
      WHERE experiment_id = ? AND version = ? AND record_hash = ?
    `).run(
      canonicalJson(input.next),
      nextHash,
      nextVersion,
      input.context.occurredAt,
      input.row.experiment_id,
      input.row.version,
      input.row.record_hash,
    );
    if (updated.changes !== 1) {
      throw error(
        409,
        "research_promotion_version_conflict",
        "The candidate lifecycle changed before the transition committed.",
        "conflict",
      );
    }
    this.database.prepare(`
      UPDATE experiments
      SET status = ?, updated_at = ?
      WHERE id = ?
    `).run(
      input.next.state,
      input.context.occurredAt,
      input.row.experiment_id,
    );
    this.database.prepare(`
      UPDATE strategy_versions
      SET status = ?
      WHERE id = ?
    `).run(input.next.state, input.row.strategy_version_id);
    if (input.context.actorKind === "human_reviewer") {
      this.database.prepare(`
        INSERT INTO promotion_reviews (
          id, strategy_version_id, from_stage, to_stage, decision,
          reviewer, rationale, evidence_refs_json, decided_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        `research_review_${randomUUID()}`,
        input.row.strategy_version_id,
        promotionStage(input.current),
        promotionStage(input.next),
        input.action === "rollback"
          ? "rollback"
          : input.next.state === "rejected"
            ? "reject"
            : "advance",
        input.context.actorId,
        input.context.rationale,
        canonicalJson(input.context.evidenceRefs),
        input.context.occurredAt,
      );
    }
    const deployment = input.deploymentId
      ? { id: input.deploymentId }
      : this.database.prepare(`
          SELECT id
          FROM strategy_deployments
          WHERE strategy_version_id = ? AND status = 'running'
          ORDER BY created_at DESC, id DESC
          LIMIT 1
        `).get(input.row.strategy_version_id) as { readonly id: string } | undefined;
    if (deployment) {
      if (input.action === "shadow_pass" || input.action === "canary_pass") {
        this.database.prepare(`
          UPDATE strategy_deployments
          SET status = 'completed', ended_at = ?
          WHERE id = ?
        `).run(input.context.occurredAt, deployment.id);
      }
      if (input.action === "shadow_fail" || input.action === "canary_fail") {
        this.database.prepare(`
          UPDATE strategy_deployments
          SET status = 'stopped', ended_at = ?
          WHERE id = ?
        `).run(input.context.occurredAt, deployment.id);
      }
    }
    return this.get(input.row.experiment_id);
  }

  private appendAudit(
    actorId: string,
    actorKind: PromotionDecisionContext["actorKind"],
    action: string,
    resourceId: string,
    reason: string,
    details: unknown,
    now: string,
  ): string {
    const previous = this.database.prepare(`
      SELECT record_hash
      FROM audit_records
      ORDER BY rowid DESC
      LIMIT 1
    `).get() as { readonly record_hash: string } | undefined;
    const auditId = `audit_${randomUUID()}`;
    const actorType = actorKind === "human_reviewer"
      ? "operator"
      : actorKind === "local_evaluator"
        ? "worker"
        : "system";
    const recordHash = hashCanonical({
      auditId,
      previousHash: previous?.record_hash ?? null,
      actorType,
      actorId,
      action,
      resourceId,
      reason,
      details,
      now,
    });
    this.database.prepare(`
      INSERT INTO audit_records (
        id, actor_type, actor_id, action, resource_type, resource_id,
        reason, details_json, previous_hash, record_hash, occurred_at
      ) VALUES (?, ?, ?, ?, 'research_promotion', ?, ?, ?, ?, ?, ?)
    `).run(
      auditId,
      actorType,
      actorId,
      action,
      resourceId,
      reason,
      canonicalJson(details),
      previous?.record_hash ?? null,
      recordHash,
      now,
    );
    return auditId;
  }

  private readIdempotency<T>(
    actorId: string,
    operation: string,
    key: string,
    requestHash: string,
  ): T | undefined {
    const row = this.database.prepare(`
      SELECT value_json
      FROM settings
      WHERE key = ?
    `).get(idempotencySetting(actorId, operation, key)) as {
      readonly value_json: string;
    } | undefined;
    if (!row) return undefined;
    const stored = JSON.parse(row.value_json) as IdempotencyValue<T>;
    if (stored.requestHash !== requestHash) {
      throw error(
        409,
        "research_idempotency_conflict",
        "This promotion submission key was already used for a different decision.",
        "conflict",
        "Submit the materially different decision with a new Idempotency-Key.",
      );
    }
    return stored.response;
  }

  private storeIdempotency<T>(
    actorId: string,
    operation: string,
    key: string,
    requestHash: string,
    response: T,
    now: string,
  ): void {
    this.database.prepare(`
      INSERT INTO settings (
        key, value_json, sensitivity, version, updated_by, updated_at
      ) VALUES (?, ?, 'private', 1, ?, ?)
    `).run(
      idempotencySetting(actorId, operation, key),
      canonicalJson({ requestHash, response }),
      actorId,
      now,
    );
  }
}

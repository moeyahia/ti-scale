import type { SqliteDatabase } from "../db";
import { inImmediateTransaction } from "../db";
import { canonicalJson } from "../missions/canonical";
import {
  validateProviderExposureReceipt,
  type ProviderExposureReceipt,
} from "../research/LlmExposurePolicy";
import {
  PROVIDER_ADVISORY_DIMENSION_ID,
  PROVIDER_ADVISORY_EXPOSURE_POLICY_VERSION,
} from "./ProviderAdvisoryExposure";
import {
  isProviderAdvisoryPlanningDisclosureMode,
  providerAdvisoryDisclosureIdentityHash,
  type ProviderAdvisoryPlanningDisclosureMode,
} from "./ProviderAdvisoryDisclosureIdentity";
import { ProviderAdvisoryPlanningError } from "./ProviderAdvisoryPlanningTypes";

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export interface PersistProviderAdvisoryExposureInput {
  readonly receipt: ProviderExposureReceipt;
  readonly planningRequestId: string;
  readonly missionId: string;
  readonly runId: string;
  readonly contextPackId: string;
  readonly providerTurnId: string;
  readonly modelConfigurationHash: string;
  readonly planningDisclosureMode: ProviderAdvisoryPlanningDisclosureMode;
}

export interface PersistedProviderAdvisoryExposure {
  readonly exposureReceiptId: string;
  readonly contextPackId: string;
  readonly providerTurnId: string;
  readonly providerId: string;
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly planningRequestId: string;
  readonly planningDisclosureMode: ProviderAdvisoryPlanningDisclosureMode;
  readonly advisoryIdentityHash: string;
  readonly exposedPayloadHash: string;
  readonly createdAt: string;
}

interface ProviderTurnRow {
  readonly run_id: string | null;
  readonly provider: string;
  readonly model: string | null;
  readonly model_configuration_hash: string | null;
  readonly status: string;
  readonly release_data_class: string;
}

interface ContextPackRow {
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly journey: string;
  readonly release_data_class: string;
}

interface ExistingReceiptRow {
  readonly provider_id: string;
  readonly model_id: string;
  readonly provider_turn_id: string | null;
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly context_pack_id: string | null;
  readonly model_configuration_hash: string | null;
  readonly advisory_planning_request_id: string | null;
  readonly planning_disclosure_mode: string | null;
  readonly advisory_identity_hash: string | null;
  readonly disclosure_policy_version: string;
  readonly input_classification: string;
  readonly selected_context_ids_json: string;
  readonly rejected_context_ids_json: string;
  readonly sanitization_actions_json: string;
  readonly untrusted_content_envelope_hash: string | null;
  readonly exposed_payload_hash: string;
  readonly blocked: number;
  readonly block_reason: string | null;
  readonly created_at: string;
  readonly release_data_class: string;
}

function fail(
  code: string,
  message: string,
  category: "disclosure_denied" | "policy_drift" = "policy_drift",
): never {
  throw new ProviderAdvisoryPlanningError(code, message, category, false);
}

function opaqueId(value: unknown, label: string): string {
  if (typeof value !== "string" || !OPAQUE_ID.test(value.trim())) {
    fail(
      "provider_advisory_exposure_binding_invalid",
      `${label} is not an opaque canonical identifier.`,
    );
  }
  return value.trim();
}

function exactHash(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(
      "provider_advisory_exposure_binding_invalid",
      `${label} is not an exact SHA-256 hash.`,
    );
  }
  return value;
}

function expectedRow(
  input: PersistProviderAdvisoryExposureInput,
): ExistingReceiptRow {
  const advisoryIdentityHash = providerAdvisoryDisclosureIdentityHash({
    exposureReceiptId: input.receipt.id,
    planningRequestId: input.planningRequestId,
    missionId: input.missionId,
    runId: input.runId,
    contextPackId: input.contextPackId,
    providerTurnId: input.providerTurnId,
    providerId: input.receipt.providerId,
    modelId: input.receipt.modelId,
    modelConfigurationHash: input.modelConfigurationHash,
    disclosurePolicyVersion: input.receipt.disclosurePolicyVersion,
    planningDisclosureMode: input.planningDisclosureMode,
    exposedPayloadHash: input.receipt.exposedPayloadHash,
  });
  return {
    provider_id: input.receipt.providerId,
    model_id: input.receipt.modelId,
    provider_turn_id: input.providerTurnId,
    mission_id: input.missionId,
    run_id: input.runId,
    context_pack_id: input.contextPackId,
    model_configuration_hash: input.modelConfigurationHash,
    advisory_planning_request_id: input.planningRequestId,
    planning_disclosure_mode: input.planningDisclosureMode,
    advisory_identity_hash: advisoryIdentityHash,
    disclosure_policy_version: input.receipt.disclosurePolicyVersion,
    input_classification: input.receipt.inputClassification,
    selected_context_ids_json: canonicalJson(input.receipt.selectedContextIds),
    rejected_context_ids_json: canonicalJson(input.receipt.rejectedContext),
    sanitization_actions_json: canonicalJson(input.receipt.sanitizationActions),
    untrusted_content_envelope_hash:
      input.receipt.untrustedContentEnvelopeHash ?? null,
    exposed_payload_hash: input.receipt.exposedPayloadHash,
    blocked: 0,
    block_reason: null,
    created_at: input.receipt.createdAt,
    release_data_class: "canonical",
  };
}

function sameExistingReceipt(
  actual: ExistingReceiptRow,
  expected: ExistingReceiptRow,
): boolean {
  return (Object.keys(expected) as Array<keyof ExistingReceiptRow>)
    .every((key) => actual[key] === expected[key]);
}

/**
 * Commits the deterministic advisory disclosure receipt to the exact started
 * provider turn before any network client receives the sanitized brief.
 *
 * Candidate IDs may appear in the receipt, but exact targets, tool bindings,
 * arguments, evidence payloads and raw Brain content never do. The provider
 * request auditor subsequently binds the exact outbound request bytes to this
 * same immutable turn/Context Pack/model tuple.
 */
export class ProviderAdvisoryExposureRepository {
  constructor(private readonly database: SqliteDatabase) {}

  persist(
    rawInput: PersistProviderAdvisoryExposureInput,
  ): PersistedProviderAdvisoryExposure {
    const input: PersistProviderAdvisoryExposureInput = {
      ...rawInput,
      planningRequestId: opaqueId(
        rawInput.planningRequestId,
        "Planning request ID",
      ),
      missionId: opaqueId(rawInput.missionId, "Mission ID"),
      runId: opaqueId(rawInput.runId, "Run ID"),
      contextPackId: opaqueId(rawInput.contextPackId, "Context Pack ID"),
      providerTurnId: opaqueId(
        rawInput.providerTurnId,
        "Provider turn ID",
      ),
      modelConfigurationHash: exactHash(
        rawInput.modelConfigurationHash,
        "Model configuration hash",
      ),
      planningDisclosureMode: rawInput.planningDisclosureMode,
    };
    if (!isProviderAdvisoryPlanningDisclosureMode(
      input.planningDisclosureMode,
    )) {
      fail(
        "provider_advisory_disclosure_mode_invalid",
        "The planning disclosure mode is not one exact supported signed mode.",
        "disclosure_denied",
      );
    }
    const receiptErrors = validateProviderExposureReceipt(input.receipt, {
      campaignId: input.planningRequestId,
      dimensionId: PROVIDER_ADVISORY_DIMENSION_ID,
    });
    if (
      receiptErrors.length > 0
      || input.receipt.blocked
      || input.receipt.disclosurePolicyVersion !==
        PROVIDER_ADVISORY_EXPOSURE_POLICY_VERSION
    ) {
      fail(
        "provider_advisory_exposure_integrity_failed",
        "The advisory disclosure receipt is blocked or does not match the local planning exposure policy.",
        "disclosure_denied",
      );
    }
    const expected = expectedRow(input);

    return inImmediateTransaction(this.database, () => {
      const turn = this.database.prepare(`
        SELECT
          run_id, provider, model, model_configuration_hash, status,
          release_data_class
        FROM provider_turns
        WHERE id = ?
      `).get(input.providerTurnId) as ProviderTurnRow | undefined;
      if (
        !turn
        || turn.run_id !== input.runId
        || turn.provider !== input.receipt.providerId
        || turn.model !== input.receipt.modelId
        || turn.model_configuration_hash !== input.modelConfigurationHash
        || turn.status !== "started"
        || turn.release_data_class !== "canonical"
      ) {
        fail(
          "provider_advisory_provider_turn_mismatch",
          "The advisory disclosure does not match one canonical started planning-provider turn.",
        );
      }
      const pack = this.database.prepare(`
        SELECT mission_id, run_id, journey, release_data_class
        FROM memory_context_packs
        WHERE id = ?
      `).get(input.contextPackId) as ContextPackRow | undefined;
      if (
        !pack
        || pack.mission_id !== input.missionId
        || pack.run_id !== input.runId
        || pack.journey !== "autonomous"
        || pack.release_data_class !== "canonical"
      ) {
        fail(
          "provider_advisory_context_pack_mismatch",
          "The advisory disclosure Context Pack does not belong to this exact Autonomous mission and run.",
        );
      }

      const existing = this.database.prepare(`
        SELECT
          provider_id, model_id, provider_turn_id, mission_id, run_id,
          context_pack_id, model_configuration_hash,
          advisory_planning_request_id, planning_disclosure_mode,
          advisory_identity_hash,
          disclosure_policy_version, input_classification,
          selected_context_ids_json, rejected_context_ids_json,
          sanitization_actions_json, untrusted_content_envelope_hash,
          exposed_payload_hash, blocked, block_reason, created_at,
          release_data_class
        FROM provider_exposure_receipts
        WHERE id = ?
      `).get(input.receipt.id) as ExistingReceiptRow | undefined;
      if (existing) {
        if (!sameExistingReceipt(existing, expected)) {
          fail(
            "provider_advisory_exposure_receipt_conflict",
            "The deterministic advisory exposure identity is already bound to different canonical records.",
          );
        }
      } else {
        this.database.prepare(`
          INSERT INTO provider_exposure_receipts (
            id, provider_id, model_id, provider_turn_id, mission_id, run_id,
            context_pack_id, model_configuration_hash,
            advisory_planning_request_id, planning_disclosure_mode,
            advisory_identity_hash,
            disclosure_policy_version, input_classification,
            selected_context_ids_json, rejected_context_ids_json,
            sanitization_actions_json, untrusted_content_envelope_hash,
            exposed_payload_hash, blocked, block_reason, created_at,
            release_data_class
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, 'canonical')
        `).run(
          input.receipt.id,
          expected.provider_id,
          expected.model_id,
          expected.provider_turn_id,
          expected.mission_id,
          expected.run_id,
          expected.context_pack_id,
          expected.model_configuration_hash,
          expected.advisory_planning_request_id,
          expected.planning_disclosure_mode,
          expected.advisory_identity_hash,
          expected.disclosure_policy_version,
          expected.input_classification,
          expected.selected_context_ids_json,
          expected.rejected_context_ids_json,
          expected.sanitization_actions_json,
          expected.untrusted_content_envelope_hash,
          expected.exposed_payload_hash,
          expected.created_at,
        );
      }

      return Object.freeze({
        exposureReceiptId: input.receipt.id,
        contextPackId: input.contextPackId,
        providerTurnId: input.providerTurnId,
        providerId: input.receipt.providerId,
        modelId: input.receipt.modelId,
        modelConfigurationHash: input.modelConfigurationHash,
        planningRequestId: input.planningRequestId,
        planningDisclosureMode: input.planningDisclosureMode,
        advisoryIdentityHash: expected.advisory_identity_hash!,
        exposedPayloadHash: input.receipt.exposedPayloadHash,
        createdAt: input.receipt.createdAt,
      });
    });
  }
}

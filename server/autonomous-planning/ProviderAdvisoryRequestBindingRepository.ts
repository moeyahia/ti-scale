import type { SqliteDatabase } from "../db";
import {
  isProviderAdvisoryPlanningDisclosureMode,
  providerAdvisoryDisclosureIdentityHash,
  type ProviderAdvisoryPlanningDisclosureMode,
} from "./ProviderAdvisoryDisclosureIdentity";
import { ProviderAdvisoryPlanningError } from "./ProviderAdvisoryPlanningTypes";

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export const PROVIDER_ADVISORY_REQUEST_CONTRACT_VERSION =
  "ti-scale.openrouter-structured-request.v1" as const;
export const PROVIDER_ADVISORY_OPENROUTER_ENDPOINT =
  "https://openrouter.ai/api/v1/chat/completions" as const;

export interface ProviderAdvisoryRequestBinding {
  readonly exposureReceiptId: string;
  readonly providerTurnId: string;
  readonly contextPackId: string;
  readonly providerId: "openrouter";
  readonly modelId: string;
  readonly modelConfigurationHash: string;
  readonly planningRequestId: string;
  readonly planningDisclosureMode: ProviderAdvisoryPlanningDisclosureMode;
  readonly advisoryIdentityHash: string;
  readonly requestBodyHash: string;
  readonly requestBodyBytes: number;
  readonly requestContractVersion:
    typeof PROVIDER_ADVISORY_REQUEST_CONTRACT_VERSION;
  readonly requestEndpoint: typeof PROVIDER_ADVISORY_OPENROUTER_ENDPOINT;
  readonly authorizedAt: string;
}

interface BindingRow {
  readonly provider_id: string;
  readonly model_id: string;
  readonly provider_turn_id: string | null;
  readonly context_pack_id: string | null;
  readonly mission_id: string | null;
  readonly run_id: string | null;
  readonly model_configuration_hash: string | null;
  readonly advisory_planning_request_id: string | null;
  readonly planning_disclosure_mode: string | null;
  readonly advisory_identity_hash: string | null;
  readonly disclosure_policy_version: string;
  readonly exposed_payload_hash: string;
  readonly request_body_hash: string | null;
  readonly request_body_bytes: number | null;
  readonly request_contract_version: string | null;
  readonly request_endpoint: string | null;
  readonly request_authorized_at: string | null;
  readonly blocked: number;
  readonly release_data_class: string;
  readonly turn_status: string;
}

function fail(code: string, message: string): never {
  throw new ProviderAdvisoryPlanningError(
    code,
    message,
    "policy_drift",
    false,
  );
}

function opaqueId(value: unknown, label: string): string {
  if (typeof value !== "string" || !OPAQUE_ID.test(value.trim())) {
    fail(
      "provider_advisory_request_binding_invalid",
      `${label} is not an opaque canonical identifier.`,
    );
  }
  return value.trim();
}

/**
 * Reads the immutable request authorization written by the provider client
 * immediately before credential access and network dispatch. A provider
 * response is never accepted unless this exact-byte binding exists.
 */
export class ProviderAdvisoryRequestBindingRepository {
  constructor(private readonly database: SqliteDatabase) {}

  requireBound(input: {
    readonly exposureReceiptId: string;
    readonly providerTurnId: string;
    readonly contextPackId: string;
    readonly modelId: string;
    readonly modelConfigurationHash: string;
    readonly planningDisclosureMode: ProviderAdvisoryPlanningDisclosureMode;
    readonly advisoryIdentityHash: string;
  }): ProviderAdvisoryRequestBinding {
    const exposureReceiptId = opaqueId(
      input.exposureReceiptId,
      "Exposure receipt ID",
    );
    const providerTurnId = opaqueId(
      input.providerTurnId,
      "Provider turn ID",
    );
    const contextPackId = opaqueId(input.contextPackId, "Context Pack ID");
    const modelId = opaqueId(input.modelId, "Model ID");
    if (!SHA256.test(input.modelConfigurationHash)) {
      fail(
        "provider_advisory_request_binding_invalid",
        "Model configuration hash is not an exact SHA-256 hash.",
      );
    }
    if (
      !isProviderAdvisoryPlanningDisclosureMode(
        input.planningDisclosureMode,
      )
      || !SHA256.test(input.advisoryIdentityHash)
    ) {
      fail(
        "provider_advisory_request_binding_invalid",
        "The signed planning disclosure mode or advisory identity hash is invalid.",
      );
    }

    const row = this.database.prepare(`
      SELECT
        receipt.provider_id,
        receipt.model_id,
        receipt.provider_turn_id,
        receipt.context_pack_id,
        receipt.mission_id,
        receipt.run_id,
        receipt.model_configuration_hash,
        receipt.advisory_planning_request_id,
        receipt.planning_disclosure_mode,
        receipt.advisory_identity_hash,
        receipt.disclosure_policy_version,
        receipt.exposed_payload_hash,
        receipt.request_body_hash,
        receipt.request_body_bytes,
        receipt.request_contract_version,
        receipt.request_endpoint,
        receipt.request_authorized_at,
        receipt.blocked,
        receipt.release_data_class,
        turn.status AS turn_status
      FROM provider_exposure_receipts AS receipt
      JOIN provider_turns AS turn ON turn.id = receipt.provider_turn_id
      WHERE receipt.id = ?
    `).get(exposureReceiptId) as BindingRow | undefined;

    if (
      !row
      || row.provider_id !== "openrouter"
      || row.model_id !== modelId
      || row.provider_turn_id !== providerTurnId
      || row.context_pack_id !== contextPackId
      || row.model_configuration_hash !== input.modelConfigurationHash
      || row.planning_disclosure_mode !== input.planningDisclosureMode
      || row.advisory_identity_hash !== input.advisoryIdentityHash
      || row.advisory_planning_request_id === null
      || row.mission_id === null
      || row.run_id === null
      || row.request_contract_version !==
        PROVIDER_ADVISORY_REQUEST_CONTRACT_VERSION
      || row.request_endpoint !== PROVIDER_ADVISORY_OPENROUTER_ENDPOINT
      || row.blocked !== 0
      || row.release_data_class !== "canonical"
      || row.turn_status !== "started"
      || row.request_body_hash === null
      || !SHA256.test(row.request_body_hash)
      || row.request_body_bytes === null
      || !Number.isSafeInteger(row.request_body_bytes)
      || row.request_body_bytes <= 0
      || row.request_authorized_at === null
      || !Number.isFinite(Date.parse(row.request_authorized_at))
    ) {
      fail(
        "provider_advisory_request_binding_missing",
        "The advisory result has no matching durable exact-request authorization.",
      );
    }
    const recomputedIdentity = providerAdvisoryDisclosureIdentityHash({
      exposureReceiptId,
      planningRequestId: row.advisory_planning_request_id,
      missionId: row.mission_id,
      runId: row.run_id,
      contextPackId,
      providerTurnId,
      providerId: "openrouter",
      modelId,
      modelConfigurationHash: input.modelConfigurationHash,
      disclosurePolicyVersion: row.disclosure_policy_version,
      planningDisclosureMode: input.planningDisclosureMode,
      exposedPayloadHash: row.exposed_payload_hash,
    });
    if (recomputedIdentity !== input.advisoryIdentityHash) {
      fail(
        "provider_advisory_request_binding_identity_mismatch",
        "The advisory result disclosure identity does not match its persisted authority tuple.",
      );
    }

    return Object.freeze({
      exposureReceiptId,
      providerTurnId,
      contextPackId,
      providerId: "openrouter",
      modelId,
      modelConfigurationHash: input.modelConfigurationHash,
      planningRequestId: row.advisory_planning_request_id,
      planningDisclosureMode: input.planningDisclosureMode,
      advisoryIdentityHash: input.advisoryIdentityHash,
      requestBodyHash: row.request_body_hash,
      requestBodyBytes: row.request_body_bytes,
      requestContractVersion: PROVIDER_ADVISORY_REQUEST_CONTRACT_VERSION,
      requestEndpoint: PROVIDER_ADVISORY_OPENROUTER_ENDPOINT,
      authorizedAt: row.request_authorized_at,
    });
  }
}

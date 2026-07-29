import { inImmediateTransaction, type SqliteDatabase } from "../../db";
import {
  isProviderAdvisoryPlanningDisclosureMode,
  providerAdvisoryDisclosureIdentityHash,
} from "../../autonomous-planning/ProviderAdvisoryDisclosureIdentity";
import {
  OpenRouterPlanningError,
  type ProviderRequestAuthorization,
  type ProviderRequestAuthorizationInput,
  type ProviderRequestAuditor,
} from "./types";

const HASH = /^[a-f0-9]{64}$/u;
const DEFAULT_MAXIMUM_RECEIPT_AGE_MS = 10 * 60_000;
const MAXIMUM_RECEIPT_AGE_MS = 60 * 60_000;
const MAXIMUM_CLOCK_SKEW_MS = 30_000;

interface ReceiptRow {
  readonly provider_id: string;
  readonly model_id: string;
  readonly provider_turn_id: string | null;
  readonly run_id: string | null;
  readonly mission_id: string | null;
  readonly context_pack_id: string | null;
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
  readonly created_at: string;
  readonly turn_run_id: string | null;
  readonly turn_provider: string;
  readonly turn_model: string | null;
  readonly turn_model_configuration_hash: string | null;
  readonly turn_status: string;
}

export interface OpenRouterProviderRequestAuditorOptions {
  readonly database: SqliteDatabase;
  readonly maximumReceiptAgeMs?: number;
  readonly now?: () => Date;
}

function denied(code: string, message: string): OpenRouterPlanningError {
  return new OpenRouterPlanningError(code, message, {
    status: 503,
    category: "policy_denied",
    retryable: false,
    remediation: "Create a fresh matching provider turn and disclosure receipt, then rebuild the request.",
  });
}

function persistenceFailure(): OpenRouterPlanningError {
  return new OpenRouterPlanningError(
    "openrouter_request_audit_persistence_failed",
    "The exact public-provider request authorization could not be durably committed",
    {
      status: 503,
      category: "persistence",
      retryable: true,
      remediation: "Restore the V2 database write path before retrying the explanation.",
    },
  );
}

function validAge(createdAt: string, now: Date, maximumAgeMs: number): boolean {
  const timestamp = Date.parse(createdAt);
  return Number.isFinite(timestamp) &&
    timestamp <= now.getTime() + MAXIMUM_CLOCK_SKEW_MS &&
    now.getTime() - timestamp <= maximumAgeMs;
}

/** SQLite-backed fail-closed request authorizer used immediately before credential access. */
export class OpenRouterProviderRequestAuditor implements ProviderRequestAuditor {
  readonly #database: SqliteDatabase;
  readonly #maximumReceiptAgeMs: number;
  readonly #now: () => Date;

  constructor(options: OpenRouterProviderRequestAuditorOptions) {
    if (!options.database?.open) throw new TypeError("An open V2 database is required for provider request auditing");
    const maximumAge = options.maximumReceiptAgeMs ?? DEFAULT_MAXIMUM_RECEIPT_AGE_MS;
    if (!Number.isSafeInteger(maximumAge) || maximumAge < 1_000 || maximumAge > MAXIMUM_RECEIPT_AGE_MS) {
      throw new RangeError("Provider exposure receipt age is outside its safe bound");
    }
    this.#database = options.database;
    this.#maximumReceiptAgeMs = maximumAge;
    this.#now = options.now ?? (() => new Date());
  }

  async authorize(input: ProviderRequestAuthorizationInput): Promise<ProviderRequestAuthorization> {
    if (
      input.providerId !== "openrouter" ||
      !HASH.test(input.requestBodyHash) ||
      !HASH.test(input.exposure.modelConfigurationHash) ||
      !Number.isSafeInteger(input.requestBodyBytes) ||
      input.requestBodyBytes <= 0
    ) {
      throw denied("openrouter_request_audit_input_invalid", "The provider request audit input is invalid");
    }
    const now = this.#now();
    if (!Number.isFinite(now.getTime())) throw persistenceFailure();
    try {
      return inImmediateTransaction(this.#database, () => {
        const row = this.#database.prepare(`
          SELECT
            receipt.provider_id,
            receipt.model_id,
            receipt.provider_turn_id,
            receipt.run_id,
            receipt.mission_id,
            receipt.context_pack_id,
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
            receipt.created_at,
            turn.run_id AS turn_run_id,
            turn.provider AS turn_provider,
            turn.model AS turn_model,
            turn.model_configuration_hash AS turn_model_configuration_hash,
            turn.status AS turn_status
          FROM provider_exposure_receipts AS receipt
          JOIN provider_turns AS turn ON turn.id = receipt.provider_turn_id
          WHERE receipt.id = ?
        `).get(input.exposure.exposureReceiptId) as ReceiptRow | undefined;
        if (!row) throw denied("openrouter_request_receipt_missing", "The public-provider exposure receipt is missing");
        if (row.blocked !== 0) throw denied("openrouter_request_receipt_blocked", "The public-provider exposure receipt is blocked");
        if (!validAge(row.created_at, now, this.#maximumReceiptAgeMs)) {
          throw denied("openrouter_request_receipt_stale", "The public-provider exposure receipt is stale");
        }
        if (
          row.provider_id !== "openrouter" || row.turn_provider !== "openrouter" ||
          row.model_id !== input.requestedModel || row.turn_model !== input.requestedModel ||
          row.context_pack_id !== input.exposure.contextPackId ||
          row.model_configuration_hash !== input.exposure.modelConfigurationHash ||
          row.turn_model_configuration_hash !== input.exposure.modelConfigurationHash ||
          row.run_id !== row.turn_run_id || row.turn_status !== "started"
        ) {
          throw denied(
            "openrouter_request_receipt_mismatch",
            "The request does not match its started provider turn and disclosure receipt",
          );
        }
        const advisory =
          row.disclosure_policy_version ===
            "autonomous-planning-exposure-v1";
        if (advisory) {
          if (
            row.mission_id === null
            || row.advisory_planning_request_id === null
            || !isProviderAdvisoryPlanningDisclosureMode(
              row.planning_disclosure_mode,
            )
            || row.advisory_identity_hash === null
            || !HASH.test(row.advisory_identity_hash)
            || input.exposure.planningDisclosureMode
              !== row.planning_disclosure_mode
            || input.exposure.advisoryIdentityHash
              !== row.advisory_identity_hash
            || row.provider_turn_id === null
            || row.run_id === null
            || row.context_pack_id === null
          ) {
            throw denied(
              "openrouter_advisory_disclosure_identity_mismatch",
              "The request does not match its signed advisory planning disclosure mode and identity.",
            );
          }
          const identity = providerAdvisoryDisclosureIdentityHash({
            exposureReceiptId: input.exposure.exposureReceiptId,
            planningRequestId: row.advisory_planning_request_id,
            missionId: row.mission_id,
            runId: row.run_id,
            contextPackId: row.context_pack_id,
            providerTurnId: row.provider_turn_id,
            providerId: row.provider_id,
            modelId: row.model_id,
            modelConfigurationHash: row.model_configuration_hash!,
            disclosurePolicyVersion: row.disclosure_policy_version,
            planningDisclosureMode: row.planning_disclosure_mode,
            exposedPayloadHash: row.exposed_payload_hash,
          });
          if (identity !== row.advisory_identity_hash) {
            throw denied(
              "openrouter_advisory_disclosure_identity_invalid",
              "The persisted advisory planning disclosure identity failed local recomputation.",
            );
          }
        } else if (
          input.exposure.planningDisclosureMode !== undefined
          || input.exposure.advisoryIdentityHash !== undefined
          || row.advisory_planning_request_id !== null
          || row.planning_disclosure_mode !== null
          || row.advisory_identity_hash !== null
        ) {
          throw denied(
            "openrouter_non_advisory_identity_forbidden",
            "A non-advisory provider request cannot claim an Autonomous planning disclosure identity.",
          );
        }
        if (row.request_authorized_at !== null || row.request_body_hash !== null) {
          if (
            row.request_body_hash !== input.requestBodyHash ||
            row.request_body_bytes !== input.requestBodyBytes ||
            row.request_contract_version !== input.requestContractVersion ||
            row.request_endpoint !== input.endpoint
          ) {
            throw denied("openrouter_request_hash_mismatch", "The provider turn was already bound to a different request");
          }
          throw denied(
            "openrouter_request_receipt_already_authorized",
            "The provider turn already authorized one dispatch; a retry requires a fresh turn and receipt",
          );
        }
        const committedAt = now.toISOString();
        const update = this.#database.prepare(`
          UPDATE provider_exposure_receipts SET
            request_body_hash = ?,
            request_body_bytes = ?,
            request_contract_version = ?,
            request_endpoint = ?,
            request_authorized_at = ?
          WHERE id = ?
            AND blocked = 0
            AND request_body_hash IS NULL
            AND request_authorized_at IS NULL
        `).run(
          input.requestBodyHash,
          input.requestBodyBytes,
          input.requestContractVersion,
          input.endpoint,
          committedAt,
          input.exposure.exposureReceiptId,
        );
        if (update.changes !== 1) throw persistenceFailure();
        return {
          authorized: true,
          exposureReceiptId: input.exposure.exposureReceiptId,
          contextPackId: input.exposure.contextPackId,
          providerTurnId: row.provider_turn_id!,
          requestedModel: input.requestedModel,
          modelConfigurationHash: input.exposure.modelConfigurationHash,
          ...(advisory
            ? {
                planningDisclosureMode:
                  input.exposure.planningDisclosureMode,
                advisoryIdentityHash:
                  input.exposure.advisoryIdentityHash,
              }
            : {}),
          requestBodyHash: input.requestBodyHash,
          committedAt,
        };
      });
    } catch (error) {
      if (error instanceof OpenRouterPlanningError) throw error;
      throw persistenceFailure();
    }
  }
}

export function createOpenRouterProviderRequestAuditor(
  options: OpenRouterProviderRequestAuditorOptions,
): OpenRouterProviderRequestAuditor {
  return new OpenRouterProviderRequestAuditor(options);
}

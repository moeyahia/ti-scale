import type { SqliteDatabase } from "../db";
import type {
  ProviderUsageReport,
  RuntimeModelBindingReceipt,
} from "../command-runtime/types";
import { canonicalJson } from "../missions/canonical";
import type { AutonomousPlanningSelection } from "../model-config";
import type { StructuredJsonProviderClient } from "../providers/openrouter";
import { OpenRouterPlanningError } from "../providers/openrouter";
import type { ResearchSourceItem } from "../research/LlmExposurePolicy";
import type {
  PrepareProviderAdvisoryBrainContextInput,
} from "./ProviderAdvisoryBrainContextAdapter";
import {
  buildProviderAdvisoryCandidateCatalog,
} from "./ProviderAdvisoryCandidateCatalog";
import {
  compileProviderAdvisorySelection,
  validateProviderAdvisorySelection,
} from "./ProviderAdvisoryCompiler";
import {
  prepareProviderAdvisoryBrief,
} from "./ProviderAdvisoryExposure";
import {
  ProviderAdvisoryExposureRepository,
} from "./ProviderAdvisoryExposureRepository";
import {
  ProviderAdvisoryRequestBindingRepository,
  type ProviderAdvisoryRequestBinding,
} from "./ProviderAdvisoryRequestBindingRepository";
import {
  ProviderAdvisoryPlanningError,
  type BuildProviderAdvisoryCatalogInput,
  type CompiledProviderAdvisoryPlan,
  type PreparedProviderAdvisoryBrief,
  type ProviderAdvisoryProviderResult,
} from "./ProviderAdvisoryPlanningTypes";
import {
  StructuredJsonProviderAdvisoryAdapter,
} from "./StructuredJsonProviderAdvisoryAdapter";

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export interface ProviderAdvisoryResolvedPlanningBinding {
  readonly agentId: string;
  readonly primaryConfigurationId: string;
  readonly providerId: "openrouter";
  readonly modelId: string;
  /**
   * Exact backend identifier returned by the fresh content-free readiness
   * completion. Production supplies it immediately before provider contact;
   * operational advice must return the same identifier during that TTL.
   */
  readonly attestedReturnedModel?: string;
  /**
   * Exact provider request-configuration hash. This is the value persisted on
   * the canonical provider turn and verified again immediately before fetch.
   */
  readonly modelConfigurationHash: string;
  readonly disclosureClass: "public_only" | "sanitized_internal";
  readonly enforcementMode: "advisor_only";
  readonly executionAuthority: "none";
}

/**
 * Binds the provider-safe Brain projection to the exact policy/node generation
 * that produced it. Production re-runs `preparation` after any readiness wait
 * and rejects the turn if either hash changed before provider exposure.
 */
export interface ProviderAdvisoryBrainContextSnapshot {
  readonly preparation: PrepareProviderAdvisoryBrainContextInput;
  readonly inputFingerprint: string;
  readonly outputHash: string;
}

export interface ProviderAdvisoryRuntimeRequest {
  readonly missionId: string;
  readonly runId: string;
  readonly providerTurnId: string;
  readonly signedSelection: AutonomousPlanningSelection;
  readonly resolvedBinding: ProviderAdvisoryResolvedPlanningBinding;
  readonly candidateCatalog: BuildProviderAdvisoryCatalogInput;
  readonly createdAt: string;
  readonly contextItems?: readonly ResearchSourceItem[];
  readonly brainContextSnapshot?: ProviderAdvisoryBrainContextSnapshot;
}

export type AttestedProviderAdvisoryRuntimeRequest =
  Omit<ProviderAdvisoryRuntimeRequest, "resolvedBinding"> & {
    readonly resolvedBinding:
      Omit<ProviderAdvisoryResolvedPlanningBinding, "attestedReturnedModel">
      & { readonly attestedReturnedModel: string };
  };

/**
 * Internal post-readiness delegate. The public runtime port accepts an
 * unattested request; only this narrower port may cross the final gate.
 */
export interface AttestedProviderAdvisoryRuntimePort {
  readonly route: "provider_advisory";
  readonly executionAuthority: "none";
  plan(
    input: AttestedProviderAdvisoryRuntimeRequest,
    signal: AbortSignal,
  ): Promise<ProviderAdvisoryRuntimeOutcome>;
}

export interface ProviderAdvisoryRuntimeSuccess
  extends CompiledProviderAdvisoryPlan {
  readonly status: "planned";
  readonly route: "provider_advisory";
  readonly localFallbackApplied: false;
  readonly preparedBrief: PreparedProviderAdvisoryBrief;
  readonly requestBinding: ProviderAdvisoryRequestBinding;
  readonly providerResult: ProviderAdvisoryProviderResult;
  /**
   * Advisor identity is reported separately and has no execution authority.
   * Step execution remains pinned to the locally reviewed candidate bindings.
   */
  readonly advisorBinding: ProviderAdvisoryResolvedPlanningBinding;
  readonly executionBindings: readonly RuntimeModelBindingReceipt[];
}

export interface ProviderAdvisoryRuntimeSafeStop {
  readonly schemaVersion: "ti-scale.provider-advisory-safe-stop.v1";
  readonly transition: "safe_stop";
  readonly route: "provider_advisory";
  readonly code: string;
  readonly category:
    | "provider_unavailable"
    | "provider_refused"
    | "audit_unavailable"
    | "rate_limit"
    | "timeout"
    | "authentication_missing"
    | "authentication_failed"
    | "cancelled";
  readonly humanReason: string;
  readonly remediation: string;
  readonly retryable: boolean;
  readonly retryAfterMs?: number;
  readonly httpStatus?: number;
  readonly missionId: string;
  readonly runId: string;
  readonly providerTurnId: string;
  readonly planningRequestId: string;
  readonly localCandidatesPreserved: true;
  readonly localFallbackApplied: false;
  /** Exact usage already billed before a later local validation failure. */
  readonly providerUsage?: ProviderUsageReport;
}

export interface ProviderAdvisoryRuntimeStopped {
  readonly status: "safe_stopped";
  readonly safeStop: ProviderAdvisoryRuntimeSafeStop;
}

export type ProviderAdvisoryRuntimeOutcome =
  | ProviderAdvisoryRuntimeSuccess
  | ProviderAdvisoryRuntimeStopped;

export interface ProviderAdvisoryRuntimePort {
  readonly route: "provider_advisory";
  readonly executionAuthority: "none";
  plan(
    input: ProviderAdvisoryRuntimeRequest,
    signal: AbortSignal,
  ): Promise<ProviderAdvisoryRuntimeOutcome>;
}

interface CanonicalBoundaryRow {
  readonly mission_id: string;
  readonly journey: string;
  readonly contract_id: string | null;
  readonly contract_hash_bound: string | null;
  readonly contract_hash: string;
  readonly contract_state: string;
  readonly action_policy_json: string;
  readonly turn_run_id: string | null;
  readonly turn_provider: string;
  readonly turn_model: string | null;
  readonly turn_model_configuration_hash: string | null;
  readonly turn_agent_id: string | null;
  readonly turn_configuration_id: string | null;
  readonly turn_status: string;
  readonly turn_release_data_class: string;
}

function planningError(
  code: string,
  message: string,
  category: ConstructorParameters<typeof ProviderAdvisoryPlanningError>[2] =
    "policy_drift",
): never {
  throw new ProviderAdvisoryPlanningError(code, message, category, false);
}

function opaqueId(value: unknown, label: string): string {
  if (typeof value !== "string" || !OPAQUE_ID.test(value.trim())) {
    planningError(
      "provider_advisory_runtime_binding_invalid",
      `${label} is not an opaque canonical identifier.`,
    );
  }
  return value.trim();
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  return actual.length === canonical.length
    && actual.every((key, index) => key === canonical[index]);
}

function exactSignedProviderSelection(
  value: AutonomousPlanningSelection,
): Extract<AutonomousPlanningSelection, { readonly route: "provider_advisory" }> {
  if (
    !plainRecord(value)
    || !exactKeys(value, [
      "route",
      "agentId",
      "primaryConfigurationId",
      "fallbackConfigurationId",
      "enforcementMode",
      "disclosureClass",
      "executionAuthority",
    ])
    || value.route !== "provider_advisory"
    || value.enforcementMode !== "advisor_only"
    || value.executionAuthority !== "none"
    || (
      value.disclosureClass !== "public_only"
      && value.disclosureClass !== "sanitized_internal"
    )
    || typeof value.agentId !== "string"
    || !OPAQUE_ID.test(value.agentId)
    || typeof value.primaryConfigurationId !== "string"
    || !OPAQUE_ID.test(value.primaryConfigurationId)
    || (
      value.fallbackConfigurationId !== null
      && (
        typeof value.fallbackConfigurationId !== "string"
        || !OPAQUE_ID.test(value.fallbackConfigurationId)
      )
    )
  ) {
    planningError(
      "provider_advisory_signed_route_invalid",
      "The runtime request is not the exact signed provider-advisory route.",
    );
  }
  return value as Extract<
    AutonomousPlanningSelection,
    { readonly route: "provider_advisory" }
  >;
}

function stringList(
  value: unknown,
  label: string,
): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    planningError(
      "provider_advisory_contract_policy_invalid",
      `${label} is not a canonical string list.`,
    );
  }
  return value as readonly string[];
}

function canonicalActionPolicy(value: string): {
  readonly planningSelection: AutonomousPlanningSelection;
  readonly allowedActionClasses: readonly string[];
  readonly prohibitedActionClasses: readonly string[];
  readonly specialistAgentIds: readonly string[];
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    planningError(
      "provider_advisory_contract_policy_invalid",
      "The signed Autonomous action policy is not valid JSON.",
    );
  }
  if (!plainRecord(parsed) || !("planningSelection" in parsed)) {
    planningError(
      "provider_advisory_contract_policy_invalid",
      "The signed Autonomous action policy omits its planning selection.",
    );
  }
  return {
    planningSelection:
      parsed.planningSelection as AutonomousPlanningSelection,
    allowedActionClasses: stringList(
      parsed.allowedActionClasses,
      "Allowed action classes",
    ),
    prohibitedActionClasses: stringList(
      parsed.prohibitedActionClasses,
      "Prohibited action classes",
    ),
    specialistAgentIds: stringList(
      parsed.specialistAgentIds,
      "Specialist agent IDs",
    ),
  };
}

function safeCode(error: unknown): string {
  if (
    error !== null
    && typeof error === "object"
    && "code" in error
    && typeof error.code === "string"
    && /^[a-z0-9_.:-]{1,120}$/u.test(error.code)
  ) return error.code;
  return "provider_advisory_unavailable";
}

export function providerAdvisorySafeStop(
  input: ProviderAdvisoryRuntimeRequest,
  error: unknown,
): ProviderAdvisoryRuntimeStopped {
  const providerError = error instanceof OpenRouterPlanningError
    ? error
    : undefined;
  const planning = error instanceof ProviderAdvisoryPlanningError
    ? error
    : undefined;
  const cancelled = providerError?.category === "cancelled"
    || planning?.category === "cancelled";
  const auditUnavailable = providerError?.category === "persistence"
    || providerError?.category === "policy_denied"
    || planning?.category === "policy_drift"
    || planning?.category === "disclosure_denied"
    || planning?.category === "invalid_catalog";
  const refused = providerError?.category === "provider_protocol"
    || providerError?.category === "invalid_configuration"
    || providerError?.category === "invalid_input"
    || planning?.category === "invalid_provider_response";
  const category = cancelled
    ? "cancelled"
    : providerError?.category === "rate_limit"
      ? "rate_limit"
      : providerError?.category === "timeout"
        ? "timeout"
        : providerError?.category === "authentication_missing"
          ? "authentication_missing"
          : providerError?.category === "authentication_failed"
            ? "authentication_failed"
    : auditUnavailable
      ? "audit_unavailable"
      : refused
        ? "provider_refused"
        : "provider_unavailable";
  const retryable =
    category === "provider_unavailable"
    || category === "rate_limit"
    || category === "timeout"
      ? providerError?.retryable
        ?? planning?.retryable
        ?? true
      : false;
  const humanReason = category === "cancelled"
    ? "Provider-advisory planning was cancelled before a valid plan was accepted."
    : category === "rate_limit"
      ? "Planning safe-stopped because the signed advisory provider is rate-limited."
      : category === "timeout"
        ? "Planning safe-stopped because the signed advisory provider exceeded its bounded response time."
        : category === "authentication_missing"
          ? "Planning safe-stopped because the signed advisory provider has no usable authentication."
          : category === "authentication_failed"
            ? "Planning safe-stopped because the signed advisory provider rejected its authentication."
    : category === "audit_unavailable"
      ? "Planning safe-stopped because the exact public-provider request could not be durably proven."
      : category === "provider_refused"
        ? "Planning safe-stopped because the provider did not return one valid advisory-only candidate ordering."
        : "Planning safe-stopped because the signed advisory provider is currently unavailable.";
  const remediation = category === "audit_unavailable"
    ? "Restore the canonical provider audit path, start a fresh provider turn, and retry without reusing this request."
    : providerError?.remediation
      ? providerError.remediation
    : category === "provider_refused"
      ? "Review provider authentication and strict structured-output compatibility, then start a new run or provider turn."
      : category === "cancelled"
        ? "Start a fresh provider turn only when the operator or supervisor deliberately resumes planning."
        : "Wait for provider readiness or deliberately amend the signed planning route in a new contract or run.";
  const providerUsage: ProviderUsageReport | undefined =
    providerError?.usage
      ? {
          providerId: "openrouter",
          requestedModel: input.resolvedBinding.modelId,
          ...(providerError.returnedModel
            ? { returnedModel: providerError.returnedModel }
            : {}),
          ...(providerError.usage.inputTokens === undefined
            ? {}
            : { inputTokens: providerError.usage.inputTokens }),
          ...(providerError.usage.outputTokens === undefined
            ? {}
            : { outputTokens: providerError.usage.outputTokens }),
          ...(providerError.usage.providerTokens === undefined
            ? {}
            : {
                totalTokens: providerError.usage.providerTokens,
                providerTokens: providerError.usage.providerTokens,
              }),
          ...(providerError.usage.billedCostUsd === undefined
            ? {}
            : {
                billedCostUsd: providerError.usage.billedCostUsd,
                estimatedCost: providerError.usage.billedCostUsd,
              }),
          exactTokenUsage: providerError.usage.exactTokenUsage,
          exactCostUsage: providerError.usage.exactCostUsage,
        }
      : undefined;
  return Object.freeze({
    status: "safe_stopped",
    safeStop: Object.freeze({
      schemaVersion: "ti-scale.provider-advisory-safe-stop.v1",
      transition: "safe_stop",
      route: "provider_advisory",
      code: safeCode(error),
      category,
      humanReason,
      remediation,
      retryable,
      ...(providerError?.retryAfterMs === undefined
        ? {}
        : { retryAfterMs: providerError.retryAfterMs }),
      ...(providerError?.status === undefined
        ? {}
        : { httpStatus: providerError.status }),
      missionId: input.missionId,
      runId: input.runId,
      providerTurnId: input.providerTurnId,
      planningRequestId: input.candidateCatalog.planningRequestId,
      localCandidatesPreserved: true,
      localFallbackApplied: false,
      ...(providerUsage ? { providerUsage } : {}),
    }),
  });
}

/**
 * Per-call provider-advisory planning port.
 *
 * The signed contract selects this route. Local code builds every executable
 * candidate before disclosure, persists the deterministic disclosure receipt,
 * and only then invokes the audited structured provider client. The provider
 * can return one complete opaque-ID permutation plus a concise rationale; all
 * executable fields and evidence requirements are re-materialized locally.
 */
export class ProviderAdvisoryRuntimeService
implements ProviderAdvisoryRuntimePort {
  readonly route = "provider_advisory" as const;
  readonly executionAuthority = "none" as const;
  readonly #provider;
  readonly #exposureRepository;
  readonly #requestBindingRepository;

  constructor(options: {
    readonly database: SqliteDatabase;
    readonly providerClient: StructuredJsonProviderClient;
  }) {
    this.#provider = new StructuredJsonProviderAdvisoryAdapter(
      options.providerClient,
    );
    this.#exposureRepository =
      new ProviderAdvisoryExposureRepository(options.database);
    this.#requestBindingRepository =
      new ProviderAdvisoryRequestBindingRepository(options.database);
    this.database = options.database;
  }

  private readonly database: SqliteDatabase;

  async plan(
    rawInput: ProviderAdvisoryRuntimeRequest,
    signal: AbortSignal,
  ): Promise<ProviderAdvisoryRuntimeOutcome> {
    const input: ProviderAdvisoryRuntimeRequest = {
      ...rawInput,
      missionId: opaqueId(rawInput.missionId, "Mission ID"),
      runId: opaqueId(rawInput.runId, "Run ID"),
      providerTurnId: opaqueId(
        rawInput.providerTurnId,
        "Provider turn ID",
      ),
    };
    if (signal.aborted) return providerAdvisorySafeStop(
      input,
      new ProviderAdvisoryPlanningError(
        "provider_advisory_cancelled",
        "Provider-advisory planning was cancelled.",
        "cancelled",
        true,
      ),
    );
    const signed = exactSignedProviderSelection(input.signedSelection);
    this.assertCanonicalBoundary(input, signed);
    const catalog = buildProviderAdvisoryCandidateCatalog(
      input.candidateCatalog,
    );
    if (catalog.contractHash !== input.candidateCatalog.contractHash) {
      planningError(
        "provider_advisory_contract_binding_mismatch",
        "The local candidate catalog does not bind the signed contract.",
      );
    }
    if (catalog.candidates.some(({ step }) =>
      !step.runtimeModelBinding
      || step.runtimeModelBinding.agentId !== step.assignedAgentId)) {
      planningError(
        "provider_advisory_execution_binding_missing",
        "Every advisory candidate must retain one exact locally reviewed specialist model binding.",
      );
    }
    const prepared = prepareProviderAdvisoryBrief({
      catalog,
      providerId: input.resolvedBinding.providerId,
      modelId: input.resolvedBinding.modelId,
      createdAt: input.createdAt,
      contextItems: input.contextItems,
    });

    const persistedExposure = this.#exposureRepository.persist({
      receipt: prepared.exposureReceipt,
      planningRequestId: catalog.planningRequestId,
      missionId: input.missionId,
      runId: input.runId,
      contextPackId: catalog.contextPackId,
      providerTurnId: input.providerTurnId,
      modelConfigurationHash:
        input.resolvedBinding.modelConfigurationHash,
      planningDisclosureMode:
        input.resolvedBinding.disclosureClass,
    });
    const exposure = Object.freeze({
      exposureReceiptId: prepared.exposureReceipt.id,
      contextPackId: catalog.contextPackId,
      modelConfigurationHash:
        input.resolvedBinding.modelConfigurationHash,
      planningDisclosureMode:
        persistedExposure.planningDisclosureMode,
      advisoryIdentityHash:
        persistedExposure.advisoryIdentityHash,
    });

    try {
      const providerResult = await this.#provider.advise({
        modelId: input.resolvedBinding.modelId,
        brief: prepared.brief,
        exposure,
        signal,
      });
      if (
        providerResult.providerId !== input.resolvedBinding.providerId
        || providerResult.requestedModel !== input.resolvedBinding.modelId
        || typeof providerResult.returnedModel !== "string"
        || !providerResult.returnedModel.trim()
        || (
          input.resolvedBinding.attestedReturnedModel !== undefined
          && providerResult.returnedModel !==
            input.resolvedBinding.attestedReturnedModel
        )
        || providerResult.usage.exactTokenUsage !== true
        || providerResult.usage.exactCostUsage !== true
      ) {
        throw new OpenRouterPlanningError(
          "provider_advisory_result_binding_mismatch",
          "The provider result does not match its exact advisory model and usage contract.",
          {
            status: 502,
            category: "provider_protocol",
            retryable: false,
            usage: providerResult.usage,
            returnedModel: providerResult.returnedModel,
          },
        );
      }
      const selection = validateProviderAdvisorySelection(
        providerResult.value,
        catalog,
      );
      const requestBinding = this.#requestBindingRepository.requireBound({
        exposureReceiptId: prepared.exposureReceipt.id,
        providerTurnId: input.providerTurnId,
        contextPackId: catalog.contextPackId,
        modelId: input.resolvedBinding.modelId,
        modelConfigurationHash:
          input.resolvedBinding.modelConfigurationHash,
        planningDisclosureMode:
          persistedExposure.planningDisclosureMode,
        advisoryIdentityHash:
          persistedExposure.advisoryIdentityHash,
      });
      const compiled = compileProviderAdvisorySelection({
        catalog,
        selection,
        expectedContractHash: catalog.contractHash,
        expectedPolicyHash: catalog.policyHash,
        expectedContextPackId: catalog.contextPackId,
        source: "provider_advisory",
        providerResult,
        briefHash: prepared.briefHash,
        exposureReceiptId: prepared.exposureReceipt.id,
      });
      return Object.freeze({
        status: "planned",
        route: "provider_advisory",
        localFallbackApplied: false,
        ...compiled,
        preparedBrief: prepared,
        requestBinding,
        providerResult,
        advisorBinding: Object.freeze({ ...input.resolvedBinding }),
        executionBindings: Object.freeze(compiled.plan.steps.map((step) =>
          step.runtimeModelBinding!)),
      });
    } catch (error) {
      return providerAdvisorySafeStop(input, error);
    }
  }

  private assertCanonicalBoundary(
    input: ProviderAdvisoryRuntimeRequest,
    signed: Extract<
      AutonomousPlanningSelection,
      { readonly route: "provider_advisory" }
    >,
  ): void {
    const binding = input.resolvedBinding;
    if (
      binding.providerId !== "openrouter"
      || binding.agentId !== signed.agentId
      || binding.primaryConfigurationId !==
        signed.primaryConfigurationId
      || binding.disclosureClass !== signed.disclosureClass
      || binding.enforcementMode !== "advisor_only"
      || binding.executionAuthority !== "none"
      || !OPAQUE_ID.test(binding.modelId)
      || !SHA256.test(binding.modelConfigurationHash)
      || this.#provider.providerId !== binding.providerId
    ) {
      planningError(
        "provider_advisory_resolved_binding_mismatch",
        "The resolved advisor does not exactly match the signed planning route.",
      );
    }

    const row = this.database.prepare(`
      SELECT
        run.mission_id,
        run.journey,
        run.contract_id,
        run.contract_hash_bound,
        contract.contract_hash,
        contract.state AS contract_state,
        contract.action_policy_json,
        turn.run_id AS turn_run_id,
        turn.provider AS turn_provider,
        turn.model AS turn_model,
        turn.model_configuration_hash AS turn_model_configuration_hash,
        turn.agent_id AS turn_agent_id,
        turn.model_configuration_id AS turn_configuration_id,
        turn.status AS turn_status,
        turn.release_data_class AS turn_release_data_class
      FROM runs AS run
      JOIN mission_contracts AS contract ON contract.id = run.contract_id
      JOIN provider_turns AS turn ON turn.id = ?
      WHERE run.id = ?
    `).get(
      input.providerTurnId,
      input.runId,
    ) as CanonicalBoundaryRow | undefined;
    if (
      !row
      || row.mission_id !== input.missionId
      || row.journey !== "autonomous"
      || row.contract_id === null
      || row.contract_state !== "confirmed"
      || row.contract_hash !== input.candidateCatalog.contractHash
      || row.contract_hash_bound !== row.contract_hash
      || row.turn_run_id !== input.runId
      || row.turn_provider !== binding.providerId
      || row.turn_model !== binding.modelId
      || row.turn_model_configuration_hash !==
        binding.modelConfigurationHash
      || row.turn_agent_id !== binding.agentId
      || row.turn_configuration_id !==
        binding.primaryConfigurationId
      || row.turn_status !== "started"
      || row.turn_release_data_class !== "canonical"
    ) {
      planningError(
        "provider_advisory_canonical_boundary_mismatch",
        "The advisory request does not match one confirmed Autonomous contract and started provider turn.",
      );
    }
    const policy = canonicalActionPolicy(row.action_policy_json);
    if (
      canonicalJson(policy.planningSelection) !== canonicalJson(signed)
      || input.candidateCatalog.allowedActionClassIds.some((actionClassId) =>
        !policy.allowedActionClasses.includes(actionClassId))
      || input.candidateCatalog.allowedActionClassIds.some((actionClassId) =>
        policy.prohibitedActionClasses.includes(actionClassId))
      || input.candidateCatalog.allowedAgentIds.some((agentId) =>
        !policy.specialistAgentIds.includes(agentId))
    ) {
      planningError(
        "provider_advisory_signed_policy_mismatch",
        "The advisory candidate boundary does not match the signed Autonomous action policy.",
      );
    }
    const authorizedTargets = new Set(
      (this.database.prepare(`
        SELECT target, normalized_target
        FROM mission_targets
        WHERE mission_id = ? AND disposition = 'allowed'
      `).all(input.missionId) as {
        readonly target: string;
        readonly normalized_target: string;
      }[]).flatMap(({ target, normalized_target }) => [
        target,
        normalized_target,
      ]),
    );
    if (
      input.candidateCatalog.allowedTargets.some((target) =>
        !authorizedTargets.has(target))
    ) {
      planningError(
        "provider_advisory_target_scope_mismatch",
        "The advisory catalog includes a target outside the signed mission scope.",
      );
    }
  }
}

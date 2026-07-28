import { randomUUID } from "node:crypto";
import type { BrainContextService } from "../../brain-runtime";
import type { SqliteDatabase } from "../../db";
import type { SecondBrainService } from "../../memory";
import { createOpenRouterAuditedCompletionVerifier } from "./OpenRouterAuditedCompletionVerifier";
import {
  createOpenRouterPlanningClient,
  type OpenRouterPlanningClientOptions,
} from "./OpenRouterPlanningClient";
import { createOpenRouterProviderRequestAuditor } from "./OpenRouterProviderRequestAuditor";
import type {
  OpenRouterCompletionProbeResult,
  OpenRouterCompletionVerifier,
} from "./OpenRouterReadinessProbe";
import type { ResolvedOpenRouterModelConfiguration } from "./OpenRouterModelConfiguration";
import { OpenRouterPlanningError } from "./types";
import type { OpenRouterCredentialReader } from "./OpenRouterCredential";

export interface OpenRouterDurableReadinessVerifierOptions {
  readonly database: SqliteDatabase;
  readonly secondBrain: SecondBrainService;
  readonly brainContext: BrainContextService;
  readonly credentialPath: string;
  readonly credentialReader?: OpenRouterCredentialReader;
  readonly serviceUid?: number;
  readonly fetch?: OpenRouterPlanningClientOptions["fetch"];
  readonly timeoutMs?: number;
}

function failureCategory(error: unknown): string {
  return error instanceof OpenRouterPlanningError
    ? error.category
    : "provider_unavailable";
}

/**
 * Creates one fresh, content-free Context Pack, provider turn, and exposure
 * receipt for every readiness completion. The exact request body is then
 * authorized by the same SQLite-backed auditor used by operational Guided
 * provider calls. A receipt is single-use, so refreshes can never replay a
 * previously authorized public-provider request.
 */
export class OpenRouterDurableReadinessVerifier implements OpenRouterCompletionVerifier {
  readonly #database: SqliteDatabase;
  readonly #secondBrain: SecondBrainService;
  readonly #brainContext: BrainContextService;
  readonly #credentialPath: string;
  readonly #credentialReader?: OpenRouterCredentialReader;
  readonly #serviceUid?: number;
  readonly #fetch?: OpenRouterPlanningClientOptions["fetch"];
  readonly #timeoutMs?: number;

  constructor(options: OpenRouterDurableReadinessVerifierOptions) {
    if (!options.database?.open) throw new TypeError("An open V2 database is required");
    if (!options.secondBrain || !options.brainContext) {
      throw new TypeError("Canonical Second Brain services are required");
    }
    if (typeof options.credentialPath !== "string" || !options.credentialPath.trim()) {
      throw new TypeError("A private OpenRouter credential path is required");
    }
    this.#database = options.database;
    this.#secondBrain = options.secondBrain;
    this.#brainContext = options.brainContext;
    this.#credentialPath = options.credentialPath.trim();
    this.#credentialReader = options.credentialReader;
    this.#serviceUid = options.serviceUid;
    this.#fetch = options.fetch;
    this.#timeoutMs = options.timeoutMs;
  }

  async verify(
    configuration: ResolvedOpenRouterModelConfiguration,
    signal: AbortSignal,
  ): Promise<OpenRouterCompletionProbeResult> {
    if (signal.aborted) {
      throw new OpenRouterPlanningError(
        "openrouter_readiness_cancelled",
        "The durable readiness completion was cancelled",
        { status: 499, category: "cancelled", retryable: true },
      );
    }

    const pack = this.#secondBrain.repository.persistContextPack({
      journey: "guided",
      purpose: "Content-free public-provider readiness audit",
      queryRedacted: "content-free readiness acknowledgement",
      scopePolicy: {
        journey: "guided",
        maximumSensitivity: "public",
        allowGlobal: false,
        allowedStatuses: ["confirmed", "verified"],
        contextBudget: 0,
        graphDepth: 0,
        exactNodeIds: [],
        exactNodeIdsOnly: true,
      },
      contextBudget: 0,
      retrievalMetrics: {
        retrievedCount: 0,
        source: "openrouter-content-free-readiness",
      },
      releaseDataClass: "startup_readiness",
      createdBy: "openrouter-readiness-monitor",
      items: [],
    });
    const providerTurnId = `provider-readiness-${randomUUID()}`;
    const startedAt = new Date().toISOString();
    this.#database.prepare(`
      INSERT INTO provider_turns (
        id, provider, model, model_configuration_hash, status, started_at,
        release_data_class
      ) VALUES (?, 'openrouter', ?, ?, 'started', ?, 'startup_readiness')
    `).run(
      providerTurnId,
      configuration.model,
      configuration.configurationHash,
      startedAt,
    );

    try {
      const providerContext = this.#brainContext.preparePersistedContextPack(pack, {
        providerTurnId,
        providerId: "openrouter",
        modelId: configuration.model,
        modelConfigurationHash: configuration.configurationHash,
      });
      if (!providerContext.exposureReceiptId) {
        throw new OpenRouterPlanningError(
          "openrouter_readiness_exposure_receipt_missing",
          "The content-free provider exposure receipt was not persisted",
          {
            status: 503,
            category: "persistence",
            retryable: true,
            remediation: "Restore the canonical provider audit store before retrying readiness.",
          },
        );
      }
      const client = createOpenRouterPlanningClient({
        credentialPath: this.#credentialPath,
        ...(this.#credentialReader ? { credentialReader: this.#credentialReader } : {}),
        requestAuditor: createOpenRouterProviderRequestAuditor({ database: this.#database }),
        ...(this.#serviceUid === undefined ? {} : { serviceUid: this.#serviceUid }),
        ...(this.#fetch ? { fetch: this.#fetch } : {}),
        ...(this.#timeoutMs === undefined ? {} : { timeoutMs: this.#timeoutMs }),
      });
      const result = await createOpenRouterAuditedCompletionVerifier({
        client,
        exposureReceiptId: providerContext.exposureReceiptId,
        contextPackId: providerContext.contextPackId,
      }).verify(configuration, signal);
      const totalTokens = result.totalTokens ?? null;
      const billedCostUsd = result.billedCostUsd ?? null;
      const completed = this.#database.prepare(`
        UPDATE provider_turns SET
          status = 'completed', input_tokens = ?, output_tokens = ?, total_tokens = ?,
          estimated_cost = ?, billed_cost_usd = ?, returned_model = ?,
          exact_token_usage = ?, exact_cost_usage = ?, latency_ms = ?, ended_at = ?
        WHERE id = ? AND status = 'started'
      `).run(
        result.inputTokens ?? null,
        result.outputTokens ?? null,
        totalTokens,
        billedCostUsd,
        billedCostUsd,
        result.returnedModel,
        Number(result.exactTokenUsage),
        Number(result.exactCostUsage),
        result.latencyMs ?? null,
        new Date().toISOString(),
        providerTurnId,
      );
      if (completed.changes !== 1) {
        throw new OpenRouterPlanningError(
          "openrouter_readiness_turn_commit_failed",
          "The durable readiness provider turn could not be completed",
          { status: 503, category: "persistence", retryable: true },
        );
      }
      return result;
    } catch (error) {
      this.#database.prepare(`
        UPDATE provider_turns SET
          status = 'failed', error_category = ?, ended_at = ?
        WHERE id = ? AND status = 'started'
      `).run(failureCategory(error), new Date().toISOString(), providerTurnId);
      throw error;
    }
  }
}

export function createOpenRouterDurableReadinessVerifier(
  options: OpenRouterDurableReadinessVerifierOptions,
): OpenRouterDurableReadinessVerifier {
  return new OpenRouterDurableReadinessVerifier(options);
}

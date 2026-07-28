import { PRODUCT_AGENT_REGISTRY } from "../../agents";
import type { SqliteDatabase } from "../../db";
import { inImmediateTransaction } from "../../db";
import { canonicalJson, sha256 } from "../../missions/canonical";
import { OpenRouterConnectionError } from "./OpenRouterConnectionError";
import { OpenRouterConnectionStore } from "./OpenRouterConnectionStore";
import {
  OPENROUTER_CONNECTION_SCHEMA_VERSION,
  type OpenRouterAttestationRefreshResult,
  type OpenRouterConfigurationSource,
  type OpenRouterConnectionMutationResult,
  type OpenRouterConnectionStatus,
  type PutOpenRouterConnectionInput,
} from "./OpenRouterConnectionTypes";
import type { OpenRouterReadinessRuntimeSnapshot } from "./OpenRouterReadinessRuntime";
import type { OpenRouterGuidedStandaloneConfiguration } from "./OpenRouterStandaloneConfiguration";

const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/u;

interface RefreshIdempotencyDocument {
  readonly schemaVersion: "ti-scale.openrouter-attestation-idempotency.v1";
  readonly requestHash: string;
  readonly state: "pending" | "completed";
  readonly startedAt: string;
  readonly response?: OpenRouterAttestationRefreshResult;
}

export interface OpenRouterConnectionServiceOptions {
  readonly database: SqliteDatabase;
  readonly store: OpenRouterConnectionStore;
  readonly activeConfiguration: OpenRouterGuidedStandaloneConfiguration;
  readonly activeConfigurationSource: OpenRouterConfigurationSource;
  readonly activeConfigurationVersion: number | null;
  readonly readRuntime: () => OpenRouterReadinessRuntimeSnapshot;
  readonly refreshRuntime: () => Promise<OpenRouterReadinessRuntimeSnapshot>;
  /** Immediately republishes a newly refreshed runtime/catalog projection. */
  readonly publishRuntimeProjection: () => void;
  readonly clock?: () => Date;
}

function conflict(
  code: string,
  message: string,
  remediation: string,
): OpenRouterConnectionError {
  return new OpenRouterConnectionError(
    code,
    message,
    409,
    "state_conflict",
    remediation,
  );
}

function sourceConfiguration(
  active: OpenRouterGuidedStandaloneConfiguration,
): {
  readonly enabled: boolean;
  readonly model: string;
  readonly credentialConfigured: boolean;
} {
  if (active.state === "configured_unattested") {
    return {
      enabled: true,
      model: active.modelConfiguration.model,
      credentialConfigured: true,
    };
  }
  return {
    enabled: false,
    model: "openai/gpt-5.2",
    credentialConfigured: false,
  };
}

function idempotencyStorageKey(actorId: string, key: string): string {
  return `idempotency.openrouter_attestation.${sha256(`${actorId}\u0000${key}`)}`;
}

function parseRefreshDocument(value: string): RefreshIdempotencyDocument {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("OpenRouter attestation idempotency record is malformed");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("OpenRouter attestation idempotency record is invalid");
  }
  const document = parsed as Record<string, unknown>;
  if (
    document.schemaVersion !== "ti-scale.openrouter-attestation-idempotency.v1"
    || typeof document.requestHash !== "string"
    || (document.state !== "pending" && document.state !== "completed")
    || typeof document.startedAt !== "string"
  ) {
    throw new Error("OpenRouter attestation idempotency record is incomplete");
  }
  return document as unknown as RefreshIdempotencyDocument;
}

export class OpenRouterConnectionService {
  readonly #database: SqliteDatabase;
  readonly #store: OpenRouterConnectionStore;
  readonly #activeConfiguration: OpenRouterGuidedStandaloneConfiguration;
  readonly #activeConfigurationSource: OpenRouterConfigurationSource;
  readonly #activeConfigurationVersion: number | null;
  readonly #readRuntime: () => OpenRouterReadinessRuntimeSnapshot;
  readonly #refreshRuntime: () => Promise<OpenRouterReadinessRuntimeSnapshot>;
  readonly #publishRuntimeProjection: () => void;
  readonly #clock: () => Date;

  constructor(options: OpenRouterConnectionServiceOptions) {
    this.#database = options.database;
    this.#store = options.store;
    this.#activeConfiguration = options.activeConfiguration;
    this.#activeConfigurationSource = options.activeConfigurationSource;
    this.#activeConfigurationVersion = options.activeConfigurationVersion;
    this.#readRuntime = options.readRuntime;
    this.#refreshRuntime = options.refreshRuntime;
    this.#publishRuntimeProjection = options.publishRuntimeProjection;
    this.#clock = options.clock ?? (() => new Date());
  }

  status(): OpenRouterConnectionStatus {
    const stored = this.#store.read();
    const activeFallback = sourceConfiguration(this.#activeConfiguration);
    const source = stored
      ? "canonical_provider_config"
      : this.#activeConfigurationSource;
    const configuredVersion = stored?.version ?? 0;
    const enabled = stored?.enabled ?? activeFallback.enabled;
    const model = stored?.model ?? activeFallback.model;
    const credentialConfigured = stored
      ? Boolean(stored.credentialSha256)
      : activeFallback.credentialConfigured;
    const restartRequired = Boolean(
      stored
      && (
        this.#activeConfigurationSource !== "canonical_provider_config"
        || stored.version !== this.#activeConfigurationVersion
      ),
    );
    const runtime = this.#readRuntime();
    const activationStatus = !stored
      && this.#activeConfigurationSource === "none"
      ? "not_configured"
      : restartRequired
        ? "restart_required"
        : !enabled
          ? "disabled"
          : runtime.status === "ready"
            ? "active"
            : "degraded";
    const humanMessage = activationStatus === "restart_required"
      ? "The private connection record is saved. Restart Ti-Scale to load this exact version and run the audited provider check."
      : activationStatus === "active"
        ? "OpenRouter is active for sanitized Guided planning and advisory work."
        : activationStatus === "degraded"
          ? "OpenRouter is loaded but has not passed the complete fresh readiness and content-free completion attestation."
          : activationStatus === "disabled"
            ? "OpenRouter is disabled and no provider credential is active."
            : "OpenRouter is not configured.";
    return {
      schemaVersion: OPENROUTER_CONNECTION_SCHEMA_VERSION,
      providerId: "openrouter",
      configuration: {
        source,
        version: configuredVersion,
        enabled,
        model,
        credentialConfigured,
        updatedAt: stored?.updatedAt ?? null,
        updatedBy: stored?.updatedBy ?? null,
        storage: "service_owned_mode_0600",
        browserStorage: false,
      },
      activation: {
        activeConfigurationVersion: this.#activeConfigurationVersion,
        configuredVersion,
        restartRequired,
        status: activationStatus,
        humanMessage,
      },
      runtime,
      planningCompatibility: {
        enforcementMode: "advisor_only",
        compatibleAgentIds: PRODUCT_AGENT_REGISTRY.map(({ id }) => id),
        localExecutionAuthorityUnchanged: true,
        explanation: "OpenRouter may plan, explain, critique, and summarize for every canonical specialist after attestation. Local policy-gated adapters retain all tool and Autonomous execution authority.",
      },
    };
  }

  put(
    input: PutOpenRouterConnectionInput,
    actorId: string,
    idempotencyKey: string,
  ): OpenRouterConnectionMutationResult {
    return this.#store.put(input, actorId, idempotencyKey);
  }

  async refreshAttestation(
    expectedVersion: number,
    actorId: string,
    idempotencyKey: string,
  ): Promise<OpenRouterAttestationRefreshResult> {
    const key = idempotencyKey.trim();
    if (!IDEMPOTENCY_KEY.test(key)) {
      throw new OpenRouterConnectionError(
        "openrouter_attestation_idempotency_key_invalid",
        "A valid Idempotency-Key header containing 8-200 safe characters is required.",
        400,
        "invalid_input",
        "Supply a unique Idempotency-Key for this bounded provider check.",
      );
    }
    const stored = this.#store.read();
    if (!stored || !stored.enabled) {
      throw conflict(
        "openrouter_attestation_configuration_missing",
        "OpenRouter must have an enabled canonical connection before it can be refreshed.",
        "Save an enabled connection, restart Ti-Scale, then verify the provider.",
      );
    }
    if (expectedVersion !== stored.version) {
      throw conflict(
        "openrouter_attestation_version_conflict",
        `The OpenRouter connection changed from expected version ${expectedVersion} to ${stored.version}.`,
        "Refresh the connection record before starting another attestation.",
      );
    }
    if (
      this.#activeConfigurationSource !== "canonical_provider_config"
      || this.#activeConfigurationVersion !== stored.version
    ) {
      throw conflict(
        "openrouter_attestation_restart_required",
        "The saved OpenRouter connection is not loaded by this process.",
        "Restart Ti-Scale, then run the provider verification.",
      );
    }

    const actor = actorId.trim();
    if (!actor) {
      throw new OpenRouterConnectionError(
        "openrouter_connection_authentication_required",
        "Authenticated operator identity is required.",
        401,
        "authentication_required",
        "Sign in to the isolated Ti-Scale control plane.",
      );
    }
    const requestHash = sha256(canonicalJson({
      providerId: "openrouter",
      expectedVersion,
    }));
    const storageKey = idempotencyStorageKey(actor, key);
    const existing = inImmediateTransaction(this.#database, () => {
      const row = this.#database.prepare(
        "SELECT value_json FROM settings WHERE key = ?",
      ).get(storageKey) as { readonly value_json: string } | undefined;
      if (row) return parseRefreshDocument(row.value_json);
      const pending: RefreshIdempotencyDocument = {
        schemaVersion: "ti-scale.openrouter-attestation-idempotency.v1",
        requestHash,
        state: "pending",
        startedAt: this.#clock().toISOString(),
      };
      this.#database.prepare(`
        INSERT INTO settings (
          key, value_json, sensitivity, version, updated_by, updated_at
        ) VALUES (?, ?, 'restricted', 1, ?, ?)
      `).run(
        storageKey,
        canonicalJson(pending),
        actor,
        pending.startedAt,
      );
      return undefined;
    });
    if (existing) {
      if (existing.requestHash !== requestHash) {
        throw conflict(
          "openrouter_attestation_idempotency_conflict",
          "The Idempotency-Key was already used for another provider check.",
          "Use a new Idempotency-Key for the changed request.",
        );
      }
      if (existing.state === "completed" && existing.response) {
        return { ...existing.response, replayed: true };
      }
      throw conflict(
        "openrouter_attestation_already_running",
        "This exact OpenRouter verification is already running or stopped before its result was committed.",
        "Wait for the in-flight check, or use a new Idempotency-Key after confirming its state.",
      );
    }

    await this.#refreshRuntime();
    this.#publishRuntimeProjection();
    const response: OpenRouterAttestationRefreshResult = {
      schemaVersion: OPENROUTER_CONNECTION_SCHEMA_VERSION,
      providerId: "openrouter",
      replayed: false,
      connection: this.status(),
    };
    inImmediateTransaction(this.#database, () => {
      const completed: RefreshIdempotencyDocument = {
        schemaVersion: "ti-scale.openrouter-attestation-idempotency.v1",
        requestHash,
        state: "completed",
        startedAt: this.#clock().toISOString(),
        response,
      };
      const updated = this.#database.prepare(`
        UPDATE settings
        SET value_json = ?, version = version + 1, updated_by = ?, updated_at = ?
        WHERE key = ?
      `).run(
        canonicalJson(completed),
        actor,
        this.#clock().toISOString(),
        storageKey,
      );
      if (updated.changes !== 1) {
        throw new OpenRouterConnectionError(
          "openrouter_attestation_receipt_commit_failed",
          "The OpenRouter attestation result could not be committed.",
          503,
          "persistence",
          "Restore the canonical Ti-Scale settings store before retrying.",
          true,
        );
      }
    });
    return response;
  }
}

import {
  resolveOpenRouterGuidedStandaloneConfiguration,
  type OpenRouterGuidedStandaloneConfiguration,
} from "./OpenRouterStandaloneConfiguration";
import {
  OpenRouterReadinessProbe,
  type OpenRouterCompletionVerifier,
  type OpenRouterModelAttestation,
} from "./OpenRouterReadinessProbe";
import {
  OpenRouterPlanningError,
  type OpenRouterPlanningErrorCategory,
} from "./types";
import type { OpenRouterCredentialReader } from "./OpenRouterCredential";

export type OpenRouterReadinessRuntimeStatus =
  | "disabled"
  | "blocked"
  | "probing"
  | "degraded"
  | "ready"
  | "stopped";

export interface OpenRouterReadinessRuntimeSnapshot {
  readonly status: OpenRouterReadinessRuntimeStatus;
  readonly configured: boolean;
  readonly authenticated: boolean;
  readonly callable: boolean;
  readonly supportsGuided: boolean;
  readonly enforcesAutonomousBoundary: false;
  readonly reportsExactTokenUsage: boolean;
  readonly reportsExactCostUsage: boolean;
  readonly requestedModel?: string;
  readonly returnedModel?: string;
  readonly modelConfigurationHash?: string;
  readonly contextLength?: number;
  readonly completionProbeReceiptId?: string;
  readonly lastCheckedAt?: string;
  readonly attestedAt?: string;
  readonly expiresAt?: string;
  readonly failureCode?: string;
  readonly failureCategory?: OpenRouterPlanningErrorCategory;
  readonly failureRetryable?: boolean;
  readonly failureHttpStatus?: number;
  readonly retryAfterMs?: number;
  readonly remediation?: string;
  readonly reason: string;
}

export interface OpenRouterAttestationProbe {
  attest(signal?: AbortSignal): Promise<OpenRouterModelAttestation>;
}

export interface OpenRouterReadinessRuntimeOptions {
  readonly configuration: OpenRouterGuidedStandaloneConfiguration;
  readonly probe?: OpenRouterAttestationProbe;
  readonly now?: () => Date;
  readonly refreshIntervalMs?: number;
}

const DEFAULT_REFRESH_INTERVAL_MS = 4 * 60_000;

function configuredSnapshot(
  configuration: Extract<OpenRouterGuidedStandaloneConfiguration, { state: "configured_unattested" }>,
): OpenRouterReadinessRuntimeSnapshot {
  return Object.freeze({
    status: "degraded",
    configured: true,
    authenticated: false,
    callable: false,
    supportsGuided: false,
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: false,
    reportsExactCostUsage: false,
    requestedModel: configuration.modelConfiguration.model,
    modelConfigurationHash: configuration.modelConfiguration.configurationHash,
    remediation: configuration.remediation,
    reason: configuration.reason,
  });
}

function initialSnapshot(
  configuration: OpenRouterGuidedStandaloneConfiguration,
  observedAt: string,
): OpenRouterReadinessRuntimeSnapshot {
  if (configuration.state === "configured_unattested") {
    return Object.freeze({
      ...configuredSnapshot(configuration),
      // This is the local registry/configuration observation time. It is not
      // an upstream provider attestation and therefore grants no model,
      // authentication, callability, or execution claim.
      lastCheckedAt: observedAt,
    });
  }
  return Object.freeze({
    status: configuration.state === "blocked" ? "blocked" : "disabled",
    configured: false,
    authenticated: false,
    callable: false,
    supportsGuided: false,
    enforcesAutonomousBoundary: false,
    reportsExactTokenUsage: false,
    reportsExactCostUsage: false,
    // Keep the permanent runtime provider identity reconcilable with its
    // capability-manifest entry even when the optional adapter is disabled.
    // No network request is implied by this timestamp.
    lastCheckedAt: observedAt,
    failureCode: configuration.reasonCode,
    ...(configuration.remediation ? { remediation: configuration.remediation } : {}),
    reason: configuration.reason,
  });
}

function safeFailure(error: unknown): Pick<
  OpenRouterReadinessRuntimeSnapshot,
  | "failureCode"
  | "failureCategory"
  | "failureRetryable"
  | "failureHttpStatus"
  | "reason"
  | "retryAfterMs"
  | "remediation"
> {
  if (!(error instanceof OpenRouterPlanningError)) {
    return {
      failureCode: "openrouter_readiness_failed",
      failureCategory: "provider_unavailable",
      failureRetryable: true,
      failureHttpStatus: 503,
      reason: "The bounded OpenRouter readiness check failed safely.",
      remediation: "Inspect redacted provider health logs, then retry readiness after the dependency is restored.",
    };
  }
  const reason = error.category === "authentication_missing"
    ? "The configured OpenRouter credential file could not be verified."
    : error.category === "authentication_failed"
      ? "OpenRouter rejected the configured completion credential."
      : error.category === "rate_limit"
        ? "OpenRouter temporarily rate-limited the bounded readiness check."
        : error.category === "timeout"
          ? "OpenRouter did not complete the bounded readiness check in time."
          : error.category === "provider_protocol"
            ? "OpenRouter did not return the exact reviewed key and model metadata contract."
            : "The bounded OpenRouter readiness check could not reach a usable provider route.";
  return {
    failureCode: error.code,
    failureCategory: error.category,
    failureRetryable: error.retryable,
    failureHttpStatus: error.status,
    reason,
    ...(error.retryAfterMs === undefined ? {} : { retryAfterMs: error.retryAfterMs }),
    ...(error.remediation ? { remediation: error.remediation } : {}),
  };
}

/**
 * Maintains a fresh, secret-free OpenRouter readiness snapshot. Metadata-only
 * probes prove the credential and exact pinned model but cannot claim
 * callability. A production caller may attach the separately audited,
 * content-free completion verifier; only its fresh receipt permits callability.
 */
export class OpenRouterReadinessRuntime {
  readonly #configuration: OpenRouterGuidedStandaloneConfiguration;
  readonly #probe: OpenRouterAttestationProbe | undefined;
  readonly #now: () => Date;
  readonly #refreshIntervalMs: number;
  #state: OpenRouterReadinessRuntimeSnapshot;
  #attestation: OpenRouterModelAttestation | undefined;
  #timer: ReturnType<typeof setInterval> | undefined;
  #inFlight: Promise<OpenRouterReadinessRuntimeSnapshot> | undefined;
  #controller: AbortController | undefined;
  #stopped = false;

  constructor(options: OpenRouterReadinessRuntimeOptions) {
    this.#configuration = options.configuration;
    this.#probe = options.probe;
    this.#now = options.now ?? (() => new Date());
    this.#refreshIntervalMs = options.refreshIntervalMs ?? DEFAULT_REFRESH_INTERVAL_MS;
    if (!Number.isSafeInteger(this.#refreshIntervalMs)
      || this.#refreshIntervalMs < 10_000
      || this.#refreshIntervalMs > 60 * 60_000) {
      throw new RangeError("OpenRouter readiness refresh interval must be between 10 seconds and 1 hour");
    }
    if (this.#configuration.state === "configured_unattested" && !this.#probe) {
      throw new TypeError("Configured OpenRouter readiness requires an attestation probe");
    }
    this.#state = initialSnapshot(this.#configuration, this.#now().toISOString());
  }

  snapshot(): OpenRouterReadinessRuntimeSnapshot {
    const state = this.#state;
    if ((state.status !== "ready" && state.status !== "degraded") || !state.expiresAt) {
      return state;
    }
    if (Date.parse(state.expiresAt) > this.#now().getTime()) return state;
    const expiredState = { ...state };
    delete expiredState.completionProbeReceiptId;
    return Object.freeze({
      ...expiredState,
      status: "degraded",
      authenticated: false,
      callable: false,
      supportsGuided: false,
      reportsExactTokenUsage: false,
      reportsExactCostUsage: false,
      failureCode: "openrouter_attestation_expired",
      failureCategory: "provider_unavailable",
      failureRetryable: true,
      failureHttpStatus: 503,
      remediation: "Refresh OpenRouter readiness before using the provider.",
      reason: "The OpenRouter model attestation expired; the provider remains unavailable until a fresh check succeeds.",
    });
  }

  /**
   * Returns the exact currently fresh attestation used to construct an
   * operational planning port. Callers must never reconstruct this richer
   * receipt from the public readiness projection.
   */
  attestation(): OpenRouterModelAttestation | undefined {
    const value = this.#attestation;
    if (!value) return undefined;
    if (Date.parse(value.expiresAt) <= this.#now().getTime()) {
      this.#attestation = undefined;
      return undefined;
    }
    return value;
  }

  refreshNow(): Promise<OpenRouterReadinessRuntimeSnapshot> {
    if (this.#inFlight) return this.#inFlight;
    if (this.#configuration.state !== "configured_unattested" || !this.#probe) {
      return Promise.resolve(this.snapshot());
    }
    const pending = this.#performRefresh().finally(() => {
      if (this.#inFlight === pending) this.#inFlight = undefined;
    });
    this.#inFlight = pending;
    return pending;
  }

  async #performRefresh(): Promise<OpenRouterReadinessRuntimeSnapshot> {
    if (this.#stopped) return this.#setStopped();
    const configuration = this.#configuration;
    if (configuration.state !== "configured_unattested" || !this.#probe) return this.#state;
    const checkedAt = this.#now().toISOString();
    this.#state = Object.freeze({
      ...configuredSnapshot(configuration),
      status: "probing",
      lastCheckedAt: checkedAt,
      reason: "Ti-Scale is verifying the service-owned OpenRouter credential and exact pinned model metadata.",
    });
    const controller = new AbortController();
    this.#controller = controller;
    try {
      const attestation = await this.#probe.attest(controller.signal);
      const completedAt = this.#now().toISOString();
      if (
        attestation.model !== configuration.modelConfiguration.model
        || attestation.modelConfigurationHash !== configuration.modelConfiguration.configurationHash
        || Date.parse(attestation.expiresAt) <= this.#now().getTime()
      ) {
        this.#attestation = undefined;
        this.#state = Object.freeze({
          ...configuredSnapshot(configuration),
          lastCheckedAt: completedAt,
          failureCode: "openrouter_attestation_mismatch",
          failureCategory: "policy_denied",
          failureRetryable: false,
          failureHttpStatus: 409,
          reason: "OpenRouter returned an expired or mismatched model attestation; no provider capability is available.",
        });
        return this.#state;
      }
      const callable = attestation.callable === true
        && attestation.supportsGuided === true
        && attestation.callabilityVerification === "audited_content_free_completion"
        && typeof attestation.completionProbeReceiptId === "string"
        && attestation.completionProbeReceiptId.length > 0
        && typeof attestation.completionReturnedModel === "string"
        && attestation.completionReturnedModel.length > 0;
      this.#attestation = callable ? attestation : undefined;
      this.#state = Object.freeze({
        status: callable ? "ready" : "degraded",
        configured: true,
        authenticated: true,
        callable,
        supportsGuided: callable,
        enforcesAutonomousBoundary: false,
        reportsExactTokenUsage: callable && attestation.reportsExactTokenUsage,
        reportsExactCostUsage: callable && attestation.reportsExactCostUsage,
        requestedModel: attestation.model,
        ...(attestation.completionReturnedModel
          ? { returnedModel: attestation.completionReturnedModel }
          : {}),
        modelConfigurationHash: attestation.modelConfigurationHash,
        contextLength: attestation.contextLength,
        ...(callable && attestation.completionProbeReceiptId
          ? { completionProbeReceiptId: attestation.completionProbeReceiptId }
          : {}),
        lastCheckedAt: completedAt,
        attestedAt: attestation.attestedAt,
        expiresAt: attestation.expiresAt,
        ...(!callable ? { remediation: configuration.remediation } : {}),
        ...(!callable
          ? {
              failureCode: "openrouter_completion_attestation_unavailable",
              failureCategory: "provider_protocol" as const,
              failureRetryable: true,
              failureHttpStatus: 503,
            }
          : {}),
        reason: callable
          ? "OpenRouter passed credential, exact-model, strict-schema, tool-denial, and durable completion-receipt checks for Guided planning."
          : "OpenRouter credential and exact pinned model metadata are verified, but no audited content-free completion receipt proves callability.",
      });
      return this.#state;
    } catch (error) {
      if (this.#stopped) return this.#setStopped();
      this.#attestation = undefined;
      const failure = safeFailure(error);
      this.#state = Object.freeze({
        ...configuredSnapshot(configuration),
        lastCheckedAt: this.#now().toISOString(),
        ...failure,
      });
      return this.#state;
    } finally {
      if (this.#controller === controller) this.#controller = undefined;
    }
  }

  start(): void {
    if (this.#stopped || this.#timer || this.#configuration.state !== "configured_unattested") return;
    void this.refreshNow();
    this.#timer = setInterval(() => void this.refreshNow(), this.#refreshIntervalMs);
    this.#timer.unref?.();
  }

  beginStop(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = undefined;
    this.#stopped = true;
    this.#controller?.abort("Ti-Scale is stopping");
  }

  async stop(): Promise<void> {
    this.beginStop();
    await this.#inFlight;
    this.#setStopped();
  }

  #setStopped(): OpenRouterReadinessRuntimeSnapshot {
    const previous = this.#state;
    this.#attestation = undefined;
    this.#state = Object.freeze({
      status: "stopped",
      configured: this.#configuration.state === "configured_unattested",
      authenticated: false,
      callable: false,
      supportsGuided: false,
      enforcesAutonomousBoundary: false,
      reportsExactTokenUsage: false,
      reportsExactCostUsage: false,
      ...(previous.requestedModel ? { requestedModel: previous.requestedModel } : {}),
      ...(previous.modelConfigurationHash
        ? { modelConfigurationHash: previous.modelConfigurationHash }
        : {}),
      ...(previous.lastCheckedAt ? { lastCheckedAt: previous.lastCheckedAt } : {}),
      reason: "The OpenRouter readiness monitor is stopped.",
    });
    return this.#state;
  }
}

export interface ProductionOpenRouterReadinessRuntimeOptions {
  /**
   * Exact configuration already resolved by the standalone connection store.
   * Supplying it prevents the readiness monitor from independently falling
   * back to stale process environment after a canonical configuration exists.
   */
  readonly configuration?: OpenRouterGuidedStandaloneConfiguration;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  /**
   * Optional durable, content-free completion verifier. Without it the
   * production monitor intentionally remains metadata-only and non-callable.
   */
  readonly completionVerifier?: OpenRouterCompletionVerifier;
  readonly credentialReader?: OpenRouterCredentialReader;
  readonly now?: () => Date;
  readonly refreshIntervalMs?: number;
}

/** Creates a production monitor; callability still requires the injected durable verifier. */
export function createProductionOpenRouterReadinessRuntime(
  options: ProductionOpenRouterReadinessRuntimeOptions = {},
): OpenRouterReadinessRuntime {
  if (options.configuration && options.environment) {
    throw new TypeError(
      "OpenRouter readiness accepts either a resolved configuration or an environment, not both",
    );
  }
  const configuration = options.configuration
    ?? resolveOpenRouterGuidedStandaloneConfiguration(
      options.environment ?? process.env,
    );
  const probe = configuration.state === "configured_unattested"
    ? new OpenRouterReadinessProbe({
      credentialPath: configuration.credentialPath,
      ...(options.credentialReader ? { credentialReader: options.credentialReader } : {}),
      model: configuration.modelConfiguration.model,
      ...(options.completionVerifier ? { completionVerifier: options.completionVerifier } : {}),
      ...(options.now ? { now: options.now } : {}),
      })
    : undefined;
  return new OpenRouterReadinessRuntime({
    configuration,
    ...(probe ? { probe } : {}),
    ...(options.now ? { now: options.now } : {}),
    ...(options.refreshIntervalMs ? { refreshIntervalMs: options.refreshIntervalMs } : {}),
  });
}

import {
  ProviderAdvisoryBrainContextAdapter,
  ProviderAdvisoryBrainContextPolicyError,
  ProviderAdvisoryPlanningError,
  providerAdvisorySafeStop,
  ProviderAdvisoryRuntimeService,
  type AttestedProviderAdvisoryRuntimePort,
  type AttestedProviderAdvisoryRuntimeRequest,
  type PrepareProviderAdvisoryBrainContextInput,
  type ProviderAdvisoryBrainContextResult,
  type ProviderAdvisoryRuntimeOutcome,
  type ProviderAdvisoryRuntimePort,
  type ProviderAdvisoryRuntimeRequest,
} from "../autonomous-planning";
import type { AutonomousProviderPlanningContextPort } from "../command-runtime";
import type { SqliteDatabase } from "../db";
import { canonicalJson } from "../missions/canonical";
import {
  OpenRouterPlanningError,
  type OpenRouterModelAttestation,
  type OpenRouterReadinessRuntimeSnapshot,
  type StructuredJsonProviderClient,
} from "../providers/openrouter";

export interface AutonomousProviderAdvisoryComposition {
  readonly providerAdvisory: ProviderAdvisoryRuntimePort;
  readonly providerPlanningContext: AutonomousProviderPlanningContextPort;
}

export interface AutonomousProviderAdvisoryCompositionOptions {
  readonly database: SqliteDatabase;
  readonly providerClient: StructuredJsonProviderClient;
  readonly readReadiness: () => OpenRouterReadinessRuntimeSnapshot;
  readonly readAttestation: () => OpenRouterModelAttestation | undefined;
  /**
   * Waits only a provider-selected planning call for the currently in-flight
   * readiness probe. Local journeys and local-deterministic Autonomous runs
   * never await this optional dependency.
   */
  readonly waitForReadiness?: () => Promise<OpenRouterReadinessRuntimeSnapshot>;
  readonly now?: () => Date;
}

function unavailableError(
  snapshot: OpenRouterReadinessRuntimeSnapshot,
): OpenRouterPlanningError {
  const failureCode = snapshot.failureCode ?? "openrouter_provider_advisory_not_ready";
  const category = snapshot.failureCategory ?? "provider_unavailable";
  return new OpenRouterPlanningError(
    failureCode,
    snapshot.reason,
    {
      status: snapshot.failureHttpStatus ?? 503,
      category,
      retryable: snapshot.failureRetryable
        ?? (category === "provider_unavailable" || category === "rate_limit"),
      ...(snapshot.retryAfterMs === undefined
        ? {}
        : { retryAfterMs: snapshot.retryAfterMs }),
      ...(snapshot.remediation
        ? { remediation: snapshot.remediation }
        : {}),
    },
  );
}

export interface ReadinessGatedProviderAdvisoryOptions {
  readonly delegate: AttestedProviderAdvisoryRuntimePort;
  readonly readReadiness: () => OpenRouterReadinessRuntimeSnapshot;
  readonly readAttestation: () => OpenRouterModelAttestation | undefined;
  readonly waitForReadiness?: () => Promise<OpenRouterReadinessRuntimeSnapshot>;
  /**
   * Production supplies the canonical Brain disclosure adapter. If present,
   * every call must carry the original preparation proof and the adapter is
   * rerun after readiness settles but before any exposure receipt is written.
   */
  readonly reprepareContext?: (
    input: PrepareProviderAdvisoryBrainContextInput,
  ) => ProviderAdvisoryBrainContextResult;
  readonly now?: () => Date;
}

async function waitForProviderReadiness(
  wait: () => Promise<OpenRouterReadinessRuntimeSnapshot>,
  signal: AbortSignal,
): Promise<OpenRouterReadinessRuntimeSnapshot | undefined> {
  if (signal.aborted) return undefined;
  return await new Promise((resolve, reject) => {
    let settled = false;
    let cancelled: () => void;
    const cleanup = (): void => {
      signal.removeEventListener("abort", cancelled);
    };
    const resolveOnce = (
      snapshot: OpenRouterReadinessRuntimeSnapshot | undefined,
    ): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(snapshot);
    };
    const rejectOnce = (error: unknown): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    cancelled = (): void => {
      resolveOnce(undefined);
    };
    signal.addEventListener("abort", cancelled, { once: true });
    if (signal.aborted) {
      cancelled();
      return;
    }
    let pending: Promise<OpenRouterReadinessRuntimeSnapshot>;
    try {
      pending = wait();
    } catch (error) {
      rejectOnce(error);
      return;
    }
    void pending.then(resolveOnce, rejectOnce);
  });
}

class ReadinessGatedProviderAdvisory implements ProviderAdvisoryRuntimePort {
  readonly route = "provider_advisory" as const;
  readonly executionAuthority = "none" as const;

  constructor(
    private readonly delegate: AttestedProviderAdvisoryRuntimePort,
    private readonly options: Omit<
      ReadinessGatedProviderAdvisoryOptions,
      "delegate" | "now"
    > & { readonly now: () => Date },
  ) {}

  async plan(
    input: ProviderAdvisoryRuntimeRequest,
    signal: AbortSignal,
  ): Promise<ProviderAdvisoryRuntimeOutcome> {
    if (signal.aborted) {
      return providerAdvisorySafeStop(
        input,
        new OpenRouterPlanningError(
          "openrouter_provider_advisory_cancelled",
          "Provider-advisory planning was cancelled before readiness could be proven.",
          {
            status: 499,
            category: "cancelled",
            retryable: false,
          },
        ),
      );
    }
    const initialSnapshot = this.options.readReadiness();
    if (
      initialSnapshot.status === "probing"
      && this.options.waitForReadiness
    ) {
      try {
        const refreshed = await waitForProviderReadiness(
          this.options.waitForReadiness,
          signal,
        );
        if (!refreshed) {
          return providerAdvisorySafeStop(
            input,
            new OpenRouterPlanningError(
              "openrouter_provider_advisory_cancelled",
              "Provider-advisory planning was cancelled while waiting for its current readiness proof.",
              {
                status: 499,
                category: "cancelled",
                retryable: false,
              },
            ),
          );
        }
      } catch {
        // The final exact read below retains the canonical diagnosis. A
        // synchronous wait failure is intentionally not allowed to bypass it.
      }
    }
    if (signal.aborted) {
      return providerAdvisorySafeStop(
        input,
        new OpenRouterPlanningError(
          "openrouter_provider_advisory_cancelled",
          "Provider-advisory planning was cancelled before context could be revalidated.",
          {
            status: 499,
            category: "cancelled",
            retryable: false,
          },
        ),
      );
    }

    const preContextReadiness = this.options.readReadiness();
    const nominalBeforeContext =
      preContextReadiness.status === "ready"
      && preContextReadiness.configured
      && preContextReadiness.authenticated
      && preContextReadiness.callable
      && preContextReadiness.supportsGuided
      && preContextReadiness.enforcesAutonomousBoundary === false
      && preContextReadiness.reportsExactTokenUsage
      && preContextReadiness.reportsExactCostUsage
      && typeof preContextReadiness.completionProbeReceiptId === "string"
      && preContextReadiness.completionProbeReceiptId.length > 0
      && typeof preContextReadiness.expiresAt === "string"
      && Date.parse(preContextReadiness.expiresAt) >
        this.options.now().getTime()
      && this.options.readAttestation() !== undefined;
    if (!nominalBeforeContext) {
      return providerAdvisorySafeStop(
        input,
        unavailableError(preContextReadiness),
      );
    }

    let delegatedInput: ProviderAdvisoryRuntimeRequest = input;
    if (this.options.reprepareContext) {
      const original = input.brainContextSnapshot;
      const preparation = original?.preparation;
      const exactPreparation =
        original !== undefined
        && preparation !== undefined
        && /^[a-f0-9]{64}$/u.test(original.inputFingerprint)
        && /^[a-f0-9]{64}$/u.test(original.outputHash)
        && preparation.missionId === input.missionId
        && preparation.runId === input.runId
        && preparation.contextPackId ===
          input.candidateCatalog.contextPackId
        && input.signedSelection.route === "provider_advisory"
        && preparation.actorId === input.signedSelection.agentId
        && preparation.disclosureClass ===
          input.signedSelection.disclosureClass;
      if (!exactPreparation) {
        return providerAdvisorySafeStop(
          input,
          new ProviderAdvisoryPlanningError(
            "provider_advisory_brain_context_snapshot_missing",
            "The provider-safe Brain context is not bound to one exact pre-readiness policy and node generation.",
            "disclosure_denied",
            false,
          ),
        );
      }
      let refreshedContext: ProviderAdvisoryBrainContextResult;
      try {
        refreshedContext = this.options.reprepareContext(preparation);
      } catch (error) {
        const code = error instanceof ProviderAdvisoryBrainContextPolicyError
          ? error.code
          : "provider_advisory_brain_context_revalidation_failed";
        return providerAdvisorySafeStop(
          input,
          new ProviderAdvisoryPlanningError(
            code,
            "The provider-safe Brain context could not be revalidated after provider readiness settled.",
            "disclosure_denied",
            false,
          ),
        );
      }
      const sameGeneration =
        refreshedContext.contextPackId === preparation.contextPackId
        && refreshedContext.disclosureClass === preparation.disclosureClass
        && refreshedContext.telemetry.inputFingerprint ===
          original.inputFingerprint
        && refreshedContext.telemetry.outputHash === original.outputHash
        && canonicalJson(refreshedContext.items) ===
          canonicalJson(input.contextItems ?? []);
      if (!sameGeneration) {
        return providerAdvisorySafeStop(
          input,
          new ProviderAdvisoryPlanningError(
            "provider_advisory_brain_context_changed_during_readiness",
            "The Brain consent, node state, sensitivity, retention, scope, or sanitized projection changed while provider readiness was pending.",
            "disclosure_denied",
            false,
          ),
        );
      }
      delegatedInput = Object.freeze({
        ...input,
        contextItems: refreshedContext.items,
      });
    }
    if (signal.aborted) {
      return providerAdvisorySafeStop(
        input,
        new OpenRouterPlanningError(
          "openrouter_provider_advisory_cancelled",
          "Provider-advisory planning was cancelled after context revalidation and before provider exposure.",
          {
            status: 499,
            category: "cancelled",
            retryable: false,
          },
        ),
      );
    }

    // This is deliberately a fresh read after the Brain revalidation. It is
    // the last synchronous gate before the delegate writes an exposure receipt
    // and begins the provider request.
    const snapshot = this.options.readReadiness();
    const attestation = this.options.readAttestation();
    const ready =
      snapshot.status === "ready"
      && snapshot.configured
      && snapshot.authenticated
      && snapshot.callable
      && snapshot.supportsGuided
      && snapshot.enforcesAutonomousBoundary === false
      && snapshot.reportsExactTokenUsage
      && snapshot.reportsExactCostUsage
      && typeof snapshot.completionProbeReceiptId === "string"
      && snapshot.completionProbeReceiptId.length > 0
      && typeof snapshot.expiresAt === "string"
      && Date.parse(snapshot.expiresAt) > this.options.now().getTime();
    if (!ready || !attestation) {
      return providerAdvisorySafeStop(input, unavailableError(snapshot));
    }
    const exactBinding =
      attestation.providerId === "openrouter"
      && attestation.model === input.resolvedBinding.modelId
      && snapshot.requestedModel === input.resolvedBinding.modelId
      && attestation.modelConfigurationHash
        === input.resolvedBinding.modelConfigurationHash
      && snapshot.modelConfigurationHash
        === input.resolvedBinding.modelConfigurationHash
      && attestation.callable
      && attestation.callabilityVerification
        === "audited_content_free_completion"
      && attestation.supportsGuided
      && attestation.enforcesAutonomousBoundary === false
      && attestation.reportsExactTokenUsage
      && attestation.reportsExactCostUsage
      && attestation.completionProbeReceiptId
        === snapshot.completionProbeReceiptId
      && typeof attestation.completionReturnedModel === "string"
      && attestation.completionReturnedModel.length > 0
      && attestation.completionReturnedModel === snapshot.returnedModel
      && attestation.expiresAt === snapshot.expiresAt
      && Date.parse(attestation.expiresAt) > this.options.now().getTime();
    if (!exactBinding) {
      return providerAdvisorySafeStop(
        delegatedInput,
        new ProviderAdvisoryPlanningError(
          "provider_advisory_readiness_binding_mismatch",
          "The fresh OpenRouter attestation does not match the signed advisor model binding.",
          "policy_drift",
          false,
        ),
      );
    }
    if (signal.aborted) {
      return providerAdvisorySafeStop(
        delegatedInput,
        new OpenRouterPlanningError(
          "openrouter_provider_advisory_cancelled",
          "Provider-advisory planning was cancelled at the final provider boundary.",
          {
            status: 499,
            category: "cancelled",
            retryable: false,
          },
        ),
      );
    }
    const attestedInput: AttestedProviderAdvisoryRuntimeRequest =
      Object.freeze({
        ...delegatedInput,
        resolvedBinding: Object.freeze({
          ...delegatedInput.resolvedBinding,
          attestedReturnedModel: attestation.completionReturnedModel,
        }),
      });
    return this.delegate.plan(attestedInput, signal);
  }
}

export function createReadinessGatedProviderAdvisory(
  options: ReadinessGatedProviderAdvisoryOptions,
): ProviderAdvisoryRuntimePort {
  return new ReadinessGatedProviderAdvisory(options.delegate, {
    readReadiness: options.readReadiness,
    readAttestation: options.readAttestation,
    ...(options.waitForReadiness
      ? { waitForReadiness: options.waitForReadiness }
      : {}),
    ...(options.reprepareContext
      ? { reprepareContext: options.reprepareContext }
      : {}),
    now: options.now ?? (() => new Date()),
  });
}

/**
 * Compose the optional public-provider planning advisor as one indivisible
 * production boundary. The provider receives only the locally filtered Brain
 * projection and has no execution authority; callers cannot accidentally
 * mount one half of the boundary without the other.
 */
export function createAutonomousProviderAdvisoryComposition(
  options: AutonomousProviderAdvisoryCompositionOptions,
): AutonomousProviderAdvisoryComposition {
  const providerPlanningContext = new ProviderAdvisoryBrainContextAdapter({
    database: options.database,
    ...(options.now ? { clock: options.now } : {}),
  });
  const delegate = new ProviderAdvisoryRuntimeService({
    database: options.database,
    providerClient: options.providerClient,
  });
  const providerAdvisory = createReadinessGatedProviderAdvisory({
    delegate,
    readReadiness: options.readReadiness,
    readAttestation: options.readAttestation,
    ...(options.waitForReadiness
      ? { waitForReadiness: options.waitForReadiness }
      : {}),
    reprepareContext: (input) => providerPlanningContext.prepare(input),
    now: options.now ?? (() => new Date()),
  });
  return Object.freeze({
    providerAdvisory,
    providerPlanningContext,
  });
}

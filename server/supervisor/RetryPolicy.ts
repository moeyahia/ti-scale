import { isRetryableCategory, type FailureCategory } from "./ErrorTaxonomy";

export interface RetryPolicyConfig {
  maxAutomaticRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /** Excessive provider waits safe-stop instead of being shortened. */
  maxProviderRetryAfterMs: number;
  jitterRatio: number;
}

export const DEFAULT_RETRY_POLICY: RetryPolicyConfig = {
  maxAutomaticRetries: 2,
  baseDelayMs: 500,
  maxDelayMs: 30_000,
  maxProviderRetryAfterMs: 30 * 60_000,
  jitterRatio: 0.2,
};

export interface RetryDecision {
  retry: boolean;
  reason: "transient" | "non_retryable" | "retry_budget_exhausted" | "provider_retry_after_exceeds_bound";
  delayMs?: number;
}

function resolveConfig(config: Partial<RetryPolicyConfig> | undefined): RetryPolicyConfig {
  const resolved = { ...DEFAULT_RETRY_POLICY, ...config };
  if (
    !Number.isInteger(resolved.maxAutomaticRetries) ||
    resolved.maxAutomaticRetries < 0 ||
    !Number.isFinite(resolved.baseDelayMs) ||
    resolved.baseDelayMs < 0 ||
    !Number.isFinite(resolved.maxDelayMs) ||
    resolved.maxDelayMs < 0 ||
    !Number.isFinite(resolved.maxProviderRetryAfterMs) ||
    resolved.maxProviderRetryAfterMs < 0 ||
    !Number.isFinite(resolved.jitterRatio) ||
    resolved.jitterRatio < 0 ||
    resolved.jitterRatio > 1
  ) throw new Error("Invalid retry policy configuration");
  return resolved;
}

export function computeBackoffMs(input: {
  retriesUsed: number;
  retryAfterMs?: number;
  config?: Partial<RetryPolicyConfig>;
  random?: () => number;
}): number {
  const config = resolveConfig(input.config);
  const exponent = Math.max(0, input.retriesUsed);
  const exponential = Math.min(config.maxDelayMs, config.baseDelayMs * 2 ** exponent);
  const providerDelay = Math.max(0, input.retryAfterMs ?? 0);
  if (!Number.isFinite(providerDelay) || providerDelay > config.maxProviderRetryAfterMs) {
    throw new Error("Provider Retry-After exceeds the automatic retry bound");
  }
  const random = Math.min(1, Math.max(0, (input.random ?? Math.random)()));
  const jitterMultiplier = 1 - config.jitterRatio + random * config.jitterRatio * 2;
  const jitteredExponential = Math.min(
    config.maxDelayMs,
    Math.max(0, Math.round(exponential * jitterMultiplier)),
  );
  // Jitter may spread our own backoff, but it must never schedule before a
  // provider's explicit Retry-After boundary.
  return Math.max(providerDelay, jitteredExponential);
}

export function decideRetry(input: {
  category: FailureCategory;
  retriesUsed: number;
  retryAfterMs?: number;
  config?: Partial<RetryPolicyConfig>;
  random?: () => number;
}): RetryDecision {
  const config = resolveConfig(input.config);
  if (!isRetryableCategory(input.category)) return { retry: false, reason: "non_retryable" };
  if (input.retriesUsed >= config.maxAutomaticRetries) {
    return { retry: false, reason: "retry_budget_exhausted" };
  }
  if (
    input.retryAfterMs !== undefined
    && (!Number.isFinite(input.retryAfterMs)
      || input.retryAfterMs < 0
      || input.retryAfterMs > config.maxProviderRetryAfterMs)
  ) {
    return { retry: false, reason: "provider_retry_after_exceeds_bound" };
  }
  return {
    retry: true,
    reason: "transient",
    delayMs: computeBackoffMs(input),
  };
}

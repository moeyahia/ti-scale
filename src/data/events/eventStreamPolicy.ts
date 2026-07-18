export const STREAM_FAILURES_BEFORE_FALLBACK = 3;
export const FALLBACK_REFRESH_INTERVAL_MS = 30_000;
export const MAX_RECONNECT_DELAY_MS = 30_000;
export const RECONNECT_JITTER_MS = 350;

export interface StreamFallbackConditions {
  readonly consecutiveFailures: number;
  readonly online: boolean;
  readonly visible: boolean;
}

/**
 * A low-frequency query fallback is reserved for an online, visible client
 * whose SSE connection has failed repeatedly. Offline and background clients
 * must remain quiet.
 */
export function shouldUseAuthoritativeFallback(input: StreamFallbackConditions): boolean {
  return input.online
    && input.visible
    && input.consecutiveFailures >= STREAM_FAILURES_BEFORE_FALLBACK;
}

/**
 * Exponential reconnect backoff with bounded positive jitter. The injected
 * random source keeps the policy deterministic in tests without weakening the
 * production implementation.
 */
export function reconnectDelayMs(attempt: number, random: () => number = Math.random): number {
  const normalizedAttempt = Number.isFinite(attempt) ? Math.max(1, Math.floor(attempt)) : 1;
  const base = Math.min(MAX_RECONNECT_DELAY_MS, 1_000 * (2 ** Math.min(normalizedAttempt - 1, 5)));
  const sample = Math.min(0.999_999, Math.max(0, random()));
  return base + Math.floor(sample * RECONNECT_JITTER_MS);
}

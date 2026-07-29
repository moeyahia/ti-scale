export type CircuitState = "closed" | "open" | "half_open";

export interface CircuitBreakerConfig {
  failureThreshold: number;
  resetTimeoutMs: number;
  halfOpenMaxCalls: number;
  successThreshold: number;
}

export const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 3,
  resetTimeoutMs: 60_000,
  halfOpenMaxCalls: 1,
  successThreshold: 1,
};

export interface CircuitBreakerSnapshot {
  state: CircuitState;
  consecutiveFailures: number;
  halfOpenSuccesses: number;
  halfOpenInFlight: number;
  openedAt?: number;
}

export interface CircuitPermission {
  allowed: boolean;
  state: CircuitState;
  retryAt?: number;
  reason?: "circuit_open" | "half_open_capacity";
}

export class CircuitBreaker {
  readonly config: CircuitBreakerConfig;
  private current: CircuitBreakerSnapshot;

  constructor(config: Partial<CircuitBreakerConfig> = {}, initial?: CircuitBreakerSnapshot) {
    this.config = { ...DEFAULT_CIRCUIT_BREAKER_CONFIG, ...config };
    if (
      this.config.failureThreshold < 1 ||
      this.config.resetTimeoutMs < 0 ||
      this.config.halfOpenMaxCalls < 1 ||
      this.config.successThreshold < 1
    ) throw new Error("Invalid circuit breaker configuration");
    this.current = initial
      ? { ...initial }
      : { state: "closed", consecutiveFailures: 0, halfOpenSuccesses: 0, halfOpenInFlight: 0 };
  }

  snapshot(): CircuitBreakerSnapshot {
    return { ...this.current };
  }

  allowRequest(now: number): CircuitPermission {
    if (this.current.state === "open") {
      const retryAt = (this.current.openedAt ?? now) + this.config.resetTimeoutMs;
      if (now < retryAt) return { allowed: false, state: "open", retryAt, reason: "circuit_open" };
      this.current = {
        ...this.current,
        state: "half_open",
        halfOpenSuccesses: 0,
        halfOpenInFlight: 0,
      };
    }
    if (this.current.state === "half_open") {
      if (this.current.halfOpenInFlight >= this.config.halfOpenMaxCalls) {
        return { allowed: false, state: "half_open", reason: "half_open_capacity" };
      }
      this.current = { ...this.current, halfOpenInFlight: this.current.halfOpenInFlight + 1 };
    }
    return { allowed: true, state: this.current.state };
  }

  recordSuccess(): CircuitBreakerSnapshot {
    if (this.current.state === "half_open") {
      const successes = this.current.halfOpenSuccesses + 1;
      if (successes >= this.config.successThreshold) {
        this.current = {
          state: "closed",
          consecutiveFailures: 0,
          halfOpenSuccesses: 0,
          halfOpenInFlight: 0,
        };
      } else {
        this.current = {
          ...this.current,
          halfOpenSuccesses: successes,
          halfOpenInFlight: Math.max(0, this.current.halfOpenInFlight - 1),
        };
      }
    } else if (this.current.state === "closed") {
      this.current = { ...this.current, consecutiveFailures: 0 };
    }
    return this.snapshot();
  }

  recordFailure(now: number, counted = true): CircuitBreakerSnapshot {
    if (!counted) {
      if (this.current.state === "half_open") {
        this.current = { ...this.current, halfOpenInFlight: Math.max(0, this.current.halfOpenInFlight - 1) };
      }
      return this.snapshot();
    }
    const failures = this.current.consecutiveFailures + 1;
    if (this.current.state === "half_open" || failures >= this.config.failureThreshold) {
      this.current = {
        state: "open",
        consecutiveFailures: failures,
        halfOpenSuccesses: 0,
        halfOpenInFlight: 0,
        openedAt: now,
      };
    } else {
      this.current = { ...this.current, consecutiveFailures: failures };
    }
    return this.snapshot();
  }
}

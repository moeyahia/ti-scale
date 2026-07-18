import { describe, expect, test } from "bun:test";
import { BudgetManager, checkBudget } from "../BudgetManager";
import { CircuitBreaker } from "../CircuitBreaker";
import { classifyFailure, isRetryableCategory } from "../ErrorTaxonomy";
import {
  LeaseConflictError,
  acquireLease,
  classifyInFlightAction,
  heartbeatLease,
  isLeaseExpired,
  releaseLease,
} from "../LeaseManager";
import { planRecovery } from "../RecoveryPlanner";
import { computeBackoffMs, decideRetry } from "../RetryPolicy";

describe("error taxonomy and retry policy", () => {
  test("classifies representative failures without treating policy errors as transient", () => {
    expect(classifyFailure({ httpStatus: 429, source: "provider" })).toBe("rate_limit");
    expect(classifyFailure({ httpStatus: 503, source: "provider" })).toBe("provider_unavailable");
    expect(classifyFailure({ message: "ETIMEDOUT while connecting" })).toBe("timeout");
    expect(classifyFailure({ message: "target outside scope" })).toBe("scope_conflict");
    expect(classifyFailure({ message: "invalid argument: port" })).toBe("invalid_input");
    expect(isRetryableCategory("timeout")).toBe(true);
    expect(isRetryableCategory("policy_denied")).toBe(false);
  });

  test("covers infrastructure, enforcement, evidence, and deterministic error families", () => {
    expect(classifyFailure({ httpStatus: 401 })).toBe("authentication_missing");
    expect(classifyFailure({ httpStatus: 403 })).toBe("authorization_denied");
    expect(classifyFailure({ message: "policy denied this request" })).toBe("policy_denied");
    expect(classifyFailure({ message: "operator rejected action", source: "operator" })).toBe("operator_rejection");
    expect(classifyFailure({ message: "dependency missing" })).toBe("dependency_missing");
    expect(classifyFailure({ message: "insufficient evidence" })).toBe("evidence_insufficient");
    expect(classifyFailure({ message: "worker heartbeat expired" })).toBe("worker_lost");
    expect(classifyFailure({ message: "process crashed" })).toBe("process_crash");
    expect(classifyFailure({ message: "MCP connection unavailable", source: "mcp" })).toBe("mcp_unavailable");
    expect(classifyFailure({ message: "provider overloaded", source: "provider" })).toBe("provider_unavailable");
    expect(classifyFailure({ message: "ECONNRESET from remote" })).toBe("transient_network");
    expect(classifyFailure({ message: "exited code 2", source: "tool" })).toBe("deterministic_tool_error");
    expect(classifyFailure({ message: "unclassified" })).toBe("unknown");
  });

  test("classifies Grok ACP boundary failures into actionable dependency families", () => {
    expect(classifyFailure({
      message: "GROK_BIN must be root-owned before the ACP planning boundary can start",
      source: "provider",
    })).toBe("dependency_missing");
    expect(classifyFailure({
      message: "Grok OAuth auth path does not contain refreshable cached_token state",
      source: "provider",
    })).toBe("authentication_missing");
    expect(classifyFailure({
      message: "Grok ACP exited before completing the planning turn",
      source: "provider",
    })).toBe("provider_unavailable");
  });

  test("allows no more than two automatic retries by default", () => {
    expect(decideRetry({ category: "timeout", retriesUsed: 0, random: () => 0.5 }).retry).toBe(true);
    expect(decideRetry({ category: "timeout", retriesUsed: 1, random: () => 0.5 }).retry).toBe(true);
    expect(decideRetry({ category: "timeout", retriesUsed: 2, random: () => 0.5 })).toEqual({
      retry: false,
      reason: "retry_budget_exhausted",
    });
  });

  test("never retries deterministic, authorization, scope, or operator failures", () => {
    for (const category of [
      "invalid_input",
      "deterministic_tool_error",
      "authorization_denied",
      "policy_denied",
      "scope_conflict",
      "operator_rejection",
    ] as const) {
      expect(decideRetry({ category, retriesUsed: 0 }).reason).toBe("non_retryable");
    }
  });

  test("exponential backoff honors retry-after without shortening it to the local jitter cap", () => {
    expect(computeBackoffMs({ retriesUsed: 0, random: () => 0.5 })).toBe(500);
    expect(computeBackoffMs({ retriesUsed: 1, retryAfterMs: 10_000, random: () => 0.5 })).toBe(10_000);
    expect(computeBackoffMs({ retriesUsed: 99, retryAfterMs: 90_000, random: () => 1 })).toBe(90_000);
    expect(computeBackoffMs({ retriesUsed: 1, retryAfterMs: 120_000, random: () => 0 })).toBe(120_000);
    const low = computeBackoffMs({ retriesUsed: 1, random: () => 0 });
    const high = computeBackoffMs({ retriesUsed: 1, random: () => 1 });
    expect(low).toBe(800);
    expect(high).toBe(1_200);
  });

  test("safe-stops instead of retrying before an excessive provider boundary", () => {
    expect(decideRetry({
      category: "rate_limit",
      retriesUsed: 0,
      retryAfterMs: 30 * 60_000 + 1,
      random: () => 0.5,
    })).toEqual({ retry: false, reason: "provider_retry_after_exceeds_bound" });
    expect(() => computeBackoffMs({
      retriesUsed: 0,
      retryAfterMs: 30 * 60_000 + 1,
    })).toThrow(/Retry-After exceeds/u);
  });

  test("rejects unsafe retry configuration", () => {
    expect(() => decideRetry({ category: "timeout", retriesUsed: 0, config: { jitterRatio: 2 } })).toThrow(
      /Invalid retry policy/,
    );
    expect(() => decideRetry({ category: "timeout", retriesUsed: 0, config: { maxAutomaticRetries: 1.5 } })).toThrow(
      /Invalid retry policy/,
    );
    expect(() => decideRetry({ category: "timeout", retriesUsed: 0, config: { maxProviderRetryAfterMs: -1 } })).toThrow(
      /Invalid retry policy/,
    );
  });
});

describe("budget enforcement", () => {
  test("permits the exact limit and rejects projected overflow atomically", () => {
    const atLimit = checkBudget(
      { limits: { toolCalls: 3, estimatedCost: 2 }, usage: { toolCalls: 2, estimatedCost: 1 } },
      { toolCalls: 1, estimatedCost: 1 },
    );
    expect(atLimit.allowed).toBe(true);
    const overflow = checkBudget(
      { limits: { toolCalls: 3, estimatedCost: 2 }, usage: { toolCalls: 2, estimatedCost: 1 } },
      { toolCalls: 2, estimatedCost: 1.1 },
    );
    expect(overflow.allowed).toBe(false);
    expect(overflow.exhausted).toEqual([
      "estimatedCost",
      "toolCalls",
    ] as typeof overflow.exhausted);
  });

  test("tracks all budget dimensions and releases concurrency without going negative", () => {
    const manager = new BudgetManager({ concurrency: 2, retries: 2, replans: 2 });
    manager.consume({ concurrency: 2, retries: 1, replans: 2 });
    expect(manager.check({ concurrency: 1 }).allowed).toBe(false);
    manager.releaseConcurrency(9);
    expect(manager.snapshot().usage.concurrency).toBe(0);
    expect(() => manager.consume({ replans: 1 })).toThrow(/Budget exceeded/);
  });

  test("rejects negative or non-finite usage", () => {
    expect(() => new BudgetManager({ toolCalls: -1 })).toThrow(/Invalid/);
    expect(() => checkBudget({ limits: {}, usage: {} }, { retries: Number.NaN })).toThrow(/Invalid/);
  });
});

describe("circuit breaker", () => {
  test("opens at threshold, gates requests, probes half-open, then closes on success", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 2, resetTimeoutMs: 1_000 });
    breaker.recordFailure(0);
    expect(breaker.snapshot().state).toBe("closed");
    breaker.recordFailure(100);
    expect(breaker.snapshot().state).toBe("open");
    expect(breaker.allowRequest(1_099)).toMatchObject({ allowed: false, retryAt: 1_100 });
    expect(breaker.allowRequest(1_100)).toMatchObject({ allowed: true, state: "half_open" });
    expect(breaker.allowRequest(1_100)).toMatchObject({ allowed: false, reason: "half_open_capacity" });
    breaker.recordSuccess();
    expect(breaker.snapshot()).toMatchObject({ state: "closed", consecutiveFailures: 0 });
  });

  test("a failed half-open probe reopens the circuit", () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, resetTimeoutMs: 10 });
    breaker.recordFailure(0);
    breaker.allowRequest(10);
    breaker.recordFailure(11);
    expect(breaker.snapshot()).toMatchObject({ state: "open", openedAt: 11 });
  });
});

describe("leases and restart safety", () => {
  test("prevents lease theft, supports heartbeat fencing, and permits expired takeover", () => {
    const first = acquireLease({
      resourceType: "run",
      resourceId: "run-1",
      ownerId: "worker-a",
      now: 100,
      ttlMs: 50,
    });
    expect(() =>
      acquireLease({
        existing: first,
        resourceType: "run",
        resourceId: "run-1",
        ownerId: "worker-b",
        now: 149,
        ttlMs: 50,
      }),
    ).toThrow(LeaseConflictError);
    expect(() =>
      acquireLease({
        existing: first,
        resourceType: "action",
        resourceId: "action-1",
        ownerId: "worker-b",
        now: 200,
        ttlMs: 50,
      }),
    ).toThrow(/different resource/);
    const renewed = heartbeatLease({ lease: first, ownerId: "worker-a", expectedVersion: 1, now: 120, ttlMs: 50 });
    expect(renewed).toMatchObject({ expiresAt: 170, version: 2 });
    expect(() =>
      heartbeatLease({ lease: renewed, ownerId: "worker-a", expectedVersion: 1, now: 130, ttlMs: 50 }),
    ).toThrow(/version mismatch/);
    expect(isLeaseExpired(renewed, 170)).toBe(true);
    const takeover = acquireLease({
      existing: renewed,
      resourceType: "run",
      resourceId: "run-1",
      ownerId: "worker-b",
      now: 170,
      ttlMs: 50,
    });
    expect(takeover).toMatchObject({ ownerId: "worker-b", version: 3 });
    expect(releaseLease({ lease: takeover, ownerId: "worker-b", expectedVersion: 3 })).toBeNull();
  });

  test("only known-safe idempotent in-flight actions resume automatically", () => {
    expect(classifyInFlightAction({ idempotent: true, destructive: false, completionKnown: false })).toBe(
      "resume_idempotently",
    );
    expect(classifyInFlightAction({ idempotent: false, destructive: false, completionKnown: false })).toBe(
      "review_required",
    );
    expect(classifyInFlightAction({ idempotent: true, destructive: true, completionKnown: false })).toBe(
      "review_required",
    );
    expect(classifyInFlightAction({ idempotent: true, destructive: false, completionKnown: true })).toBe(
      "do_not_repeat",
    );
  });
});

describe("journey-aware recovery", () => {
  const exhausted = { retry: false, reason: "retry_budget_exhausted" as const };

  test("prefers a safe retry, then bounded alternative, specialist, and materially new plan", () => {
    expect(
      planRecovery({
        journey: "autonomous",
        category: "timeout",
        retryDecision: { retry: true, reason: "transient", delayMs: 500 },
        retrySafe: true,
        inContract: true,
        materiallyNewReplanAvailable: false,
        replanBudgetAvailable: true,
      }).kind,
    ).toBe("retry");
    expect(
      planRecovery({
        journey: "autonomous",
        category: "timeout",
        retryDecision: exhausted,
        retrySafe: false,
        inContract: true,
        boundedAlternativeId: "alternative-1",
        materiallyNewReplanAvailable: false,
        replanBudgetAvailable: true,
      }).kind,
    ).toBe("bounded_alternative");
    expect(
      planRecovery({
        journey: "autonomous",
        category: "worker_lost",
        retryDecision: exhausted,
        retrySafe: false,
        inContract: true,
        reassignmentAgentId: "specialist-2",
        materiallyNewReplanAvailable: false,
        replanBudgetAvailable: true,
      }).kind,
    ).toBe("reassign");
    expect(
      planRecovery({
        journey: "autonomous",
        category: "deterministic_tool_error",
        retryDecision: { retry: false, reason: "non_retryable" },
        retrySafe: false,
        inContract: true,
        materiallyNewReplanAvailable: true,
        replanBudgetAvailable: true,
      }).kind,
    ).toBe("replan");
    expect(
      planRecovery({
        journey: "autonomous",
        category: "deterministic_tool_error",
        retryDecision: { retry: false, reason: "non_retryable" },
        retrySafe: false,
        inContract: true,
        materiallyNewReplanAvailable: false,
        replanBudgetAvailable: false,
      }).kind,
    ).toBe("fail");
  });

  test("Guided requests one decision while Autonomous outside contract safe-stops", () => {
    const common = {
      category: "scope_conflict" as const,
      retryDecision: { retry: false, reason: "non_retryable" as const },
      retrySafe: false,
      inContract: false,
      materiallyNewReplanAvailable: false,
      replanBudgetAvailable: false,
    };
    expect(planRecovery({ journey: "guided", ...common }).kind).toBe("waiting_guided_decision");
    expect(
      planRecovery({
        journey: "guided",
        category: "timeout",
        retryDecision: { retry: true, reason: "transient", delayMs: 100 },
        retrySafe: true,
        inContract: true,
        materiallyNewReplanAvailable: false,
        replanBudgetAvailable: true,
      }).kind,
    ).toBe("waiting_guided_decision");
    expect(planRecovery({ journey: "autonomous", ...common })).toMatchObject({
      kind: "safe_stop",
      exceptionCode: "outside_contract",
    });
  });
});

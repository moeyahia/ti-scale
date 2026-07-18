import { describe, expect, test } from "bun:test";

import {
  PromotionService,
  Ucb1SearchPolicy,
  type PromotionDecisionContext,
  type ResearchDimensionStatistics,
} from "../../../server/research";

function context(
  actorKind: PromotionDecisionContext["actorKind"],
  rationale: string,
): PromotionDecisionContext {
  return {
    actorId: actorKind === "human_reviewer" ? "reviewer-1" : actorKind,
    actorKind,
    rationale,
    evidenceRefs: ["evidence-1"],
    occurredAt: "2026-07-16T00:00:00.000Z",
  };
}

function verifiedRecord(service: PromotionService, strategyVersionId: string) {
  let record = service.create(strategyVersionId);
  record = service.policyDecision(record, true, context("local_policy", "Patch is within policy."));
  record = service.startBenchmark(record, context("local_evaluator", "Start development."));
  record = service.developmentResult(record, true, context("local_evaluator", "Development passed."));
  record = service.validationResult(record, true, context("local_evaluator", "Validation passed."));
  record = service.hiddenHoldoutResult(record, true, context("local_evaluator", "Holdout passed."));
  record = service.humanReview(record, true, context("human_reviewer", "Approve shadow."));
  record = service.startShadow(record, context("human_reviewer", "Start shadow."));
  record = service.shadowResult(record, true, context("local_evaluator", "Shadow passed."));
  record = service.approveCanary(record, context("human_reviewer", "Approve canary."));
  record = service.startCanary(record, context("human_reviewer", "Start canary."));
  record = service.canaryResult(record, true, context("local_evaluator", "Canary passed."));
  return service.verify(record, context("human_reviewer", "Verify after all gates."));
}

describe("bounded UCB1 research search", () => {
  const policy = new Ucb1SearchPolicy();
  const stats: ResearchDimensionStatistics[] = [
    {
      id: "loop.max_identical_fingerprints",
      trials: 5,
      meanImprovement: 0.2,
      variance: 0.01,
      failureCount: 0,
      safetyFailureCount: 0,
    },
    {
      id: "loop.no_progress_action_limit",
      trials: 0,
      meanImprovement: 0,
      variance: 0,
      failureCount: 0,
      safetyFailureCount: 0,
    },
    {
      id: "loop.max_automatic_replans",
      trials: 2,
      meanImprovement: 0.3,
      variance: 0.02,
      failureCount: 1,
      safetyFailureCount: 0,
    },
  ];

  test("deterministically prioritizes an untried eligible dimension", () => {
    const selection = policy.select(
      stats,
      ["loop.max_identical_fingerprints", "loop.no_progress_action_limit", "loop.max_automatic_replans"],
      { maxTrialsPerDimension: 10, safetyFailureCircuitBreaker: 2 },
    );
    expect(selection.selectedDimensionId).toBe("loop.no_progress_action_limit");
    expect(selection.method).toBe("ucb1");
  });

  test("opens safety circuit breakers and stops exhausted dimensions", () => {
    const stopped = stats.map((item) => ({
      ...item,
      trials: 10,
      safetyFailureCount: item.id === "loop.no_progress_action_limit" ? 2 : item.safetyFailureCount,
    }));
    expect(() => policy.select(
      stopped,
      ["loop.max_identical_fingerprints", "loop.no_progress_action_limit", "loop.max_automatic_replans"],
      { maxTrialsPerDimension: 10, safetyFailureCircuitBreaker: 2 },
    )).toThrow("All research dimensions are stopped");
  });

  test("updates mean, variance, failure, and safety statistics without random state", () => {
    const first = policy.recordOutcome(stats[1]!, 0.4, "success", "2026-07-16T00:00:00Z");
    const second = policy.recordOutcome(first, -0.2, "safety_failure", "2026-07-16T00:01:00Z");
    expect(first.trials).toBe(1);
    expect(first.meanImprovement).toBeCloseTo(0.4);
    expect(second.trials).toBe(2);
    expect(second.meanImprovement).toBeCloseTo(0.1);
    expect(second.variance).toBeGreaterThan(0);
    expect(second.safetyFailureCount).toBe(1);
  });
});

describe("promotion state machine", () => {
  const service = new PromotionService();

  test("enforces development, validation, hidden holdout, human review, shadow, canary, and verification in order", () => {
    let record = service.create("strategy-candidate");
    record = service.policyDecision(record, true, context("local_policy", "Patch is inside charter."));
    record = service.startBenchmark(record, context("local_evaluator", "Start development fixtures."));
    record = service.developmentResult(record, true, context("local_evaluator", "Development passed."));
    record = service.validationResult(record, true, context("local_evaluator", "Validation passed."));
    record = service.hiddenHoldoutResult(record, true, context("local_evaluator", "Hidden holdout passed."));
    record = service.humanReview(record, true, context("human_reviewer", "Approve shadow only."));
    record = service.startShadow(record, context("human_reviewer", "Start non-impacting shadow."));
    record = service.shadowResult(record, true, context("local_evaluator", "Shadow non-regression passed."));
    record = service.approveCanary(record, context("human_reviewer", "Approve bounded canary."));
    record = service.startCanary(record, context("human_reviewer", "Start bounded canary."));
    record = service.canaryResult(record, true, context("local_evaluator", "Canary passed."));
    record = service.verify(record, context("human_reviewer", "Promote after canary review."));

    expect(record.state).toBe("verified");
    expect(record.milestones).toEqual({
      developmentPassed: true,
      validationPassed: true,
      hiddenHoldoutPassed: true,
      humanReviewApproved: true,
      shadowPassed: true,
      canaryPassed: true,
    });
    expect(record.history.map(({ to }) => to)).toEqual([
      "queued",
      "running",
      "running",
      "benchmarked",
      "benchmarked",
      "shadow_ready",
      "shadow_running",
      "shadow_running",
      "canary_ready",
      "canary_running",
      "canary_running",
      "verified",
    ]);
  });

  test("rejects stage skipping and non-human deployment or promotion", () => {
    const proposed = service.create("strategy-skip");
    expect(() => service.humanReview(proposed, true, context("human_reviewer", "Skip everything."))).toThrow(
      "expected benchmarked",
    );
    const queued = service.policyDecision(proposed, true, context("local_policy", "Policy pass."));
    const running = service.startBenchmark(queued, context("local_evaluator", "Start."));
    expect(() => service.validationResult(running, true, context("local_evaluator", "Skip dev."))).toThrow(
      "before development",
    );
    const developed = service.developmentResult(running, true, context("local_evaluator", "Dev pass."));
    const benchmarked = service.validationResult(developed, true, context("local_evaluator", "Validation pass."));
    expect(() => service.humanReview(benchmarked, true, context("human_reviewer", "Skip holdout."))).toThrow(
      "before hidden holdout",
    );
    const held = service.hiddenHoldoutResult(benchmarked, true, context("local_evaluator", "Holdout pass."));
    const shadowReady = service.humanReview(held, true, context("human_reviewer", "Shadow approved."));
    expect(() => service.startShadow(shadowReady, context("local_evaluator", "Auto deploy."))).toThrow(
      "human_reviewer",
    );
  });

  test("retains failed and rejected states without promotion", () => {
    const proposed = service.create("strategy-failure");
    const rejected = service.policyDecision(proposed, false, context("local_policy", "Forbidden path."));
    expect(rejected.state).toBe("policy_rejected");

    const queued = service.policyDecision(service.create("strategy-early"), true, context("local_policy", "Allowed."));
    const running = service.startBenchmark(queued, context("local_evaluator", "Start."));
    expect(service.developmentResult(running, false, context("local_evaluator", "Clear regression.")).state).toBe(
      "early_aborted",
    );
  });

  test("rollback requires a human, a different verified target, and local integrity verification", () => {
    const deployed = verifiedRecord(service, "strategy-current");
    expect(() => service.rollback(
      deployed,
      { strategyVersionId: "strategy-baseline", state: "verified" },
      false,
      context("human_reviewer", "Integrity missing."),
    )).toThrow("integrity must be verified");
    expect(() => service.rollback(
      deployed,
      { strategyVersionId: "strategy-current", state: "verified" },
      true,
      context("human_reviewer", "Same strategy."),
    )).toThrow("different previously verified");

    const result = service.rollback(
      deployed,
      { strategyVersionId: "strategy-baseline", state: "verified" },
      true,
      context("human_reviewer", "Canary regression; restore verified baseline."),
    );
    expect(result.promotion.state).toBe("rolled_back");
    expect(result.rollback).toMatchObject({
      fromStrategyVersionId: "strategy-current",
      toStrategyVersionId: "strategy-baseline",
      integrityVerified: true,
    });
  });

  test("rejects forged current states, milestone flags, history, authority, and evidence-free decisions", () => {
    const proposed = service.create("strategy-forged");
    expect(() => service.rollback(
      { ...proposed, state: "verified" },
      { strategyVersionId: "strategy-baseline", state: "verified" },
      true,
      context("human_reviewer", "Attempt forged rollback."),
    )).toThrow("state does not match its history");

    const queued = service.policyDecision(proposed, true, context("local_policy", "Policy accepted."));
    expect(() => service.startBenchmark(
      { ...queued, milestones: { ...queued.milestones, hiddenHoldoutPassed: true } },
      context("local_evaluator", "Forged holdout milestone."),
    )).toThrow("does not match immutable history");

    const wrongAuthority = structuredClone(queued);
    (wrongAuthority.history[0] as { actorKind: string }).actorKind = "human_reviewer";
    expect(() => service.startBenchmark(wrongAuthority, context("local_evaluator", "Bad history actor."))).toThrow(
      "wrong decision authority",
    );

    expect(() => service.policyDecision(service.create("strategy-no-evidence"), true, {
      ...context("local_policy", "No evidence."),
      evidenceRefs: [],
    })).toThrow("evidence reference");
  });
});

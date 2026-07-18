import { describe, expect, test } from "bun:test";
import { createDatabaseConnection, migrateDatabase } from "../../../server/db";

import {
  DEFAULT_STRATEGY_BUNDLE,
  INITIAL_RESEARCH_CAMPAIGNS,
  LlmExposurePolicy,
  ResearchBudgetExceededError,
  ResearchOrchestrator,
  ResearchOrchestratorStateStore,
  type LabExecutionContext,
  type ExperimentEstimatedCost,
  type InitialResearchCampaignId,
  type InitialResearchDimensionId,
  type MutableStrategyPath,
  type PlanExperimentInput,
} from "../../../server/research";
import {
  BENCHMARK_SCENARIOS,
  DEFAULT_RESEARCH_BUDGETS,
  HASH_A,
  HASH_B,
  charter,
  dimensionStatistics,
} from "./fixtures";

const DEFAULT_ESTIMATE: ExperimentEstimatedCost = {
  wallClockMs: 1_000,
  publicLlmTokens: 500,
  estimatedCost: 0.5,
  toolCalls: 10,
};

const campaignCases: readonly {
  readonly campaignId: InitialResearchCampaignId;
  readonly dimensionId: InitialResearchDimensionId;
  readonly path: MutableStrategyPath;
  readonly value: number;
}[] = [
  {
    campaignId: "repeated_no_progress_action_reduction",
    dimensionId: "loop.max_identical_fingerprints",
    path: "/loopControl/maxIdenticalFingerprints",
    value: 2,
  },
  {
    campaignId: "specialist_routing_quality",
    dimensionId: "routing.minimum_capability_score",
    path: "/specialistRouting/minimumCapabilityScore",
    value: 0.8,
  },
  {
    campaignId: "memory_retrieval_precision",
    dimensionId: "memory.minimum_confidence",
    path: "/memoryRetrieval/minimumConfidence",
    value: 0.75,
  },
];

function inputFor(
  campaignId: InitialResearchCampaignId = "repeated_no_progress_action_reduction",
  dimensionId: InitialResearchDimensionId = "loop.max_identical_fingerprints",
  path: MutableStrategyPath = "/loopControl/maxIdenticalFingerprints",
  value: number | boolean = 2,
  overrides: Partial<PlanExperimentInput> = {},
): PlanExperimentInput {
  return {
    idempotencyKey: `idempotency-${campaignId}-${String(overrides.createdAt ?? "1")}`,
    campaignId,
    charter: charter(campaignId),
    baselineStrategyId: "strategy-baseline",
    baseline: DEFAULT_STRATEGY_BUNDLE,
    dimensionStatistics: dimensionStatistics(campaignId, dimensionId),
    proposedSpec: {
      schemaVersion: "1",
      hypothesis: `Changing ${path} will improve the campaign metric without safety regression.`,
      expectedMechanism: "The bounded threshold changes orchestration behavior on isolated fixtures.",
      patch: [{ op: "replace", path, value }],
    },
    estimatedCost: DEFAULT_ESTIMATE,
    createdBy: "research-orchestrator",
    createdAt: "2026-07-16T00:00:00.000Z",
    ...overrides,
  };
}

describe("deterministic bounded ResearchOrchestrator", () => {
  test("plans only the three initial safety/reliability campaigns", () => {
    expect(INITIAL_RESEARCH_CAMPAIGNS.map(({ id }) => id)).toEqual([
      "repeated_no_progress_action_reduction",
      "specialist_routing_quality",
      "memory_retrieval_precision",
    ]);
    for (const item of campaignCases) {
      const orchestrator = new ResearchOrchestrator();
      const plan = orchestrator.planExperiment(
        inputFor(item.campaignId, item.dimensionId, item.path, item.value),
      );
      expect(plan.campaignId).toBe(item.campaignId);
      expect(plan.dimensionId).toBe(item.dimensionId);
      expect(plan.status).toBe("queued");
      expect(plan.executionBoundary).toEqual({
        disposableLocalLabRequired: true,
        publicProviderMayExecute: false,
        liveClientTargetAllowed: false,
        candidateMayModifyEvaluator: false,
        candidateMayAutoDeploy: false,
        hiddenHoldoutDetailsIncluded: false,
      });
      expect(JSON.stringify(plan)).not.toContain("groundTruth");
      expect(JSON.stringify(plan)).not.toContain("hidden_holdout");
    }
  });

  test("is idempotent and rejects an idempotency key reused for different content", () => {
    const orchestrator = new ResearchOrchestrator();
    const request = inputFor();
    const first = orchestrator.planExperiment(request);
    const second = orchestrator.planExperiment(structuredClone(request));
    expect(second).toBe(first);
    expect(orchestrator.usage.experiments).toBe(1);

    const changed = {
      ...request,
      proposedSpec: {
        ...request.proposedSpec,
        patch: [{ op: "replace" as const, path: "/loopControl/maxIdenticalFingerprints" as const, value: 1 }],
      },
    };
    expect(() => orchestrator.planExperiment(changed)).toThrow("Idempotency key was reused");
  });

  test("rejects off-dimension patches, broad charters, forbidden paths, and no-op candidates", () => {
    const orchestrator = new ResearchOrchestrator();
    expect(() => orchestrator.planExperiment(inputFor(
      "repeated_no_progress_action_reduction",
      "loop.max_identical_fingerprints",
      "/loopControl/noProgressActionLimit",
      2,
    ))).toThrow("must change only selected dimension");

    const request = inputFor();
    expect(() => orchestrator.planExperiment({
      ...request,
      idempotencyKey: "broad-charter",
      charter: {
        ...request.charter,
        mutablePaths: [...request.charter.mutablePaths, "/planDecomposition/maxSteps"],
      },
    })).toThrow("mutable paths exceed");

    expect(() => orchestrator.planExperiment({
      ...request,
      idempotencyKey: "forbidden-patch",
      proposedSpec: {
        ...request.proposedSpec,
        patch: [{ op: "replace", path: "/safety/engagementIsolation", value: false }] as never,
      },
    })).toThrow("immutable safety or evaluation surface");

    expect(() => orchestrator.planExperiment({
      ...request,
      idempotencyKey: "no-op",
      proposedSpec: {
        ...request.proposedSpec,
        patch: [{ op: "replace", path: "/loopControl/maxIdenticalFingerprints", value: 3 }],
      },
    })).toThrow("does not create a novel strategy");
  });

  test("requires a locally verifiable provider-exposure receipt for every public-model proposal", () => {
    const base = inputFor();
    const publicSpec = { ...base.proposedSpec, publicLlmProposalHash: HASH_A };
    expect(() => new ResearchOrchestrator().planExperiment({
      ...base,
      idempotencyKey: "public-without-exposure-receipt",
      proposedSpec: publicSpec,
    })).toThrow("provider-exposure receipt");

    const decision = new LlmExposurePolicy("test-policy-v1").buildResearchBrief({
      campaignId: base.campaignId,
      dimensionId: "loop.max_identical_fingerprints",
      objective: "Reduce repeated actions on isolated benchmark fixtures.",
      providerId: "public-provider",
      modelId: "proposal-model",
      createdAt: base.createdAt,
      items: [{
        id: "metric-summary-1",
        kind: "metric_summary",
        classification: "internal",
        disclosureClass: "internal_sanitized",
        content: "Duplicate action rate is 0.20 on the local development benchmark.",
        verified: true,
      }],
    });
    expect(decision.brief).toBeDefined();
    const accepted = new ResearchOrchestrator().planExperiment({
      ...base,
      idempotencyKey: "public-with-valid-exposure-receipt",
      proposedSpec: publicSpec,
      providerExposureReceipt: decision.receipt,
    });
    expect(accepted.publicLlmProposalHash).toBe(HASH_A);
    expect(accepted.providerExposureReceiptId).toBe(decision.receipt.id);

    expect(() => new ResearchOrchestrator().planExperiment({
      ...base,
      idempotencyKey: "public-with-tampered-exposure-receipt",
      proposedSpec: publicSpec,
      providerExposureReceipt: { ...decision.receipt, exposedPayloadHash: HASH_B },
    })).toThrow("receipt identity does not match");
  });

  test("stops before reserving every exceeded estimated-resource budget", () => {
    const cases: readonly [keyof ExperimentEstimatedCost, number, string][] = [
      ["wallClockMs", DEFAULT_RESEARCH_BUDGETS.maxWallClockMs + 1, "wall-clock"],
      ["publicLlmTokens", DEFAULT_RESEARCH_BUDGETS.maxPublicLlmTokens + 1, "public-LLM token"],
      ["estimatedCost", DEFAULT_RESEARCH_BUDGETS.maxEstimatedCost + 1, "estimated cost"],
      ["toolCalls", DEFAULT_RESEARCH_BUDGETS.maxToolCalls + 1, "tool-call"],
    ];
    for (const [field, value, message] of cases) {
      const orchestrator = new ResearchOrchestrator();
      const request = inputFor();
      expect(() => orchestrator.planExperiment({
        ...request,
        idempotencyKey: `budget-${field}`,
        estimatedCost: { ...request.estimatedCost, [field]: value },
      })).toThrow(message);
      expect(orchestrator.usage.experiments).toBe(0);
    }
  });

  test("enforces experiment count, concurrency, retry, and failure circuit budgets", () => {
    const tight = {
      ...DEFAULT_RESEARCH_BUDGETS,
      maxExperiments: 1,
      maxConcurrentExperiments: 1,
      maxRetries: 1,
      maxFailures: 1,
    };
    const orchestrator = new ResearchOrchestrator();
    const firstRequest = inputFor(undefined, undefined, undefined, undefined, {
      charter: charter("repeated_no_progress_action_reduction", tight),
    });
    const plan = orchestrator.planExperiment(firstRequest);
    expect(orchestrator.recordRetry(plan.id).retries).toBe(1);
    expect(() => orchestrator.recordRetry(plan.id)).toThrow(ResearchBudgetExceededError);
    expect(orchestrator.recordTerminalOutcome(plan.id, "failed").failures).toBe(1);
    expect(orchestrator.recordTerminalOutcome(plan.id, "failed").failures).toBe(1);
    expect(() => orchestrator.recordTerminalOutcome(plan.id, "completed")).toThrow("conflicts");

    const next = inputFor(undefined, undefined, undefined, 1, {
      idempotencyKey: "second-experiment",
      charter: charter("repeated_no_progress_action_reduction", tight),
      createdAt: "2026-07-16T00:01:00.000Z",
    });
    expect(() => orchestrator.planExperiment(next)).toThrow(ResearchBudgetExceededError);
  });

  test("stops when every dimension reaches its trial or safety circuit bound", () => {
    const request = inputFor();
    const stoppedStats = request.dimensionStatistics.map((item) => ({
      ...item,
      trials: request.charter.budgets.maxTrialsPerDimension,
      safetyFailureCount: request.charter.budgets.safetyFailureCircuitBreaker,
    }));
    expect(() => new ResearchOrchestrator().planExperiment({
      ...request,
      dimensionStatistics: stoppedStats,
    })).toThrow("All research dimensions are stopped");
  });

  test("restores durable idempotency, usage, retry, and terminal state after restart", () => {
    const orchestrator = new ResearchOrchestrator();
    const request = inputFor();
    const plan = orchestrator.planExperiment(request);
    orchestrator.recordRetry(plan.id);
    orchestrator.reconcileActualUsage(plan.id, {
      wallClockMs: 750,
      publicLlmTokens: 400,
      estimatedCost: 0.4,
      toolCalls: 8,
    });
    const snapshot = orchestrator.snapshot();
    const restored = ResearchOrchestrator.restore(structuredClone(snapshot));
    expect(restored.usage).toEqual(orchestrator.usage);
    expect(restored.planExperiment(structuredClone(request))).toEqual(plan);
    expect(restored.usage.experiments).toBe(1);
    expect(restored.recordTerminalOutcome(plan.id, "completed").concurrentExperiments).toBe(0);
    expect(restored.recordTerminalOutcome(plan.id, "completed").concurrentExperiments).toBe(0);

    const tampered = structuredClone(snapshot);
    (tampered.usage as { toolCalls: number }).toolCalls += 1;
    expect(() => ResearchOrchestrator.restore(tampered)).toThrow("snapshot integrity check failed");
  });

  test("persists restart state atomically in the V2 database and rejects stored corruption", () => {
    const database = createDatabaseConnection({ filename: ":memory:" });
    migrateDatabase(database);
    try {
      const request = inputFor();
      const running = new ResearchOrchestrator();
      const plan = running.planExperiment(request);
      running.recordRetry(plan.id);
      const store = new ResearchOrchestratorStateStore(database, "research-worker-main");
      expect(store.save(running.snapshot(), "local-supervisor", "2026-07-16T00:00:01.000Z")).toBe(1);
      const afterRestart = store.loadOrchestrator()!;
      expect(afterRestart.planExperiment(structuredClone(request))).toEqual(plan);
      expect(afterRestart.usage).toEqual(running.usage);
      afterRestart.recordTerminalOutcome(plan.id, "completed");
      expect(store.save(afterRestart.snapshot(), "local-supervisor", "2026-07-16T00:00:02.000Z")).toBe(2);

      const row = database.prepare(
        "SELECT key, value_json FROM settings WHERE key LIKE 'research.orchestrator.snapshot.%'",
      ).get() as { key: string; value_json: string };
      const corrupted = JSON.parse(row.value_json) as { stateHash: string };
      corrupted.stateHash = HASH_A;
      database.prepare("UPDATE settings SET value_json = ? WHERE key = ?")
        .run(JSON.stringify(corrupted), row.key);
      expect(() => store.loadOrchestrator()).toThrow("snapshot integrity check failed");
    } finally {
      database.close();
    }
  });

  test("safe-stops and preserves actual usage when an in-flight experiment overruns a budget", () => {
    const budgets = { ...DEFAULT_RESEARCH_BUDGETS, maxToolCalls: 12 };
    const orchestrator = new ResearchOrchestrator();
    const plan = orchestrator.planExperiment(inputFor(undefined, undefined, undefined, undefined, {
      charter: charter("repeated_no_progress_action_reduction", budgets),
    }));
    expect(() => orchestrator.reconcileActualUsage(plan.id, {
      ...DEFAULT_ESTIMATE,
      toolCalls: 13,
    })).toThrow("actual tool-call budget");
    expect(orchestrator.usage).toMatchObject({ toolCalls: 13, concurrentExperiments: 0, failures: 1 });
    expect(orchestrator.recordTerminalOutcome(plan.id, "safety_failure").failures).toBe(1);
    expect(() => orchestrator.recordRetry(plan.id)).toThrow("terminal experiment");

    const restored = ResearchOrchestrator.restore(structuredClone(orchestrator.snapshot()));
    expect(restored.usage).toEqual(orchestrator.usage);
    expect(() => restored.authorizeExecution(plan.id, {
      scenario: BENCHMARK_SCENARIOS[0]!,
      context: {} as LabExecutionContext,
      trustedToolManifestHash: HASH_A,
      authorizedAt: "2026-07-16T00:00:00.000Z",
    })).toThrow("terminal experiment");
  });

  test("authorizes only an isolated resettable benchmark lab and rejects live-client execution", () => {
    const orchestrator = new ResearchOrchestrator();
    const plan = orchestrator.planExperiment(inputFor());
    const scenario = BENCHMARK_SCENARIOS[0]!;
    const context: LabExecutionContext = {
      environmentId: "disposable-lab-7",
      environmentDigest: scenario.environmentDigest,
      targetClass: "synthetic_fixture",
      authorizationScope: "benchmark_scenario_only",
      resetMode: "snapshot_restore",
      resetReceiptHash: HASH_B,
      workerProcessKind: "isolated_experiment_worker",
      productionCredentialMounts: 0,
      outboundNetworkPolicy: "benchmark_allowlist",
      publicProviderHasExecutionAuthority: false,
      candidateCanMutateHarness: false,
      benchmarkSnapshotHash: plan.benchmarkSnapshotHash,
      evaluatorHash: plan.evaluatorHash,
      toolManifestHash: HASH_A,
    };
    const authorization = orchestrator.authorizeExecution(plan.id, {
      scenario,
      context,
      trustedToolManifestHash: HASH_A,
      authorizedAt: "2026-07-16T00:00:00.000Z",
    });
    expect(authorization).toMatchObject({
      experimentId: plan.id,
      scenarioId: scenario.id,
      liveClientTargetAllowed: false,
      publicProviderMayExecute: false,
      candidateMayModifyHarness: false,
    });
    expect(JSON.stringify(authorization)).not.toContain(context.environmentId);

    for (const unsafeContext of [
      { ...context, targetClass: "live_client" as const },
      { ...context, authorizationScope: "external_scope" as const },
      { ...context, resetMode: "none" as const },
      { ...context, workerProcessKind: "shared_runtime_worker" as const },
      { ...context, productionCredentialMounts: 1 },
      { ...context, outboundNetworkPolicy: "unrestricted" as const },
      { ...context, publicProviderHasExecutionAuthority: true },
      { ...context, candidateCanMutateHarness: true },
      { ...context, environmentDigest: "sha256:live-client-image" },
      { ...context, toolManifestHash: HASH_B },
    ]) {
      expect(() => orchestrator.authorizeExecution(plan.id, {
        scenario,
        context: unsafeContext,
        trustedToolManifestHash: HASH_A,
        authorizedAt: "2026-07-16T00:00:00.000Z",
      })).toThrow();
    }
  });
});

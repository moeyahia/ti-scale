import { deepFreeze, hashCanonical, type JsonValue } from "./canonical";
import {
  ExperimentExecutionPolicy,
  type AuthorizeExperimentExecutionInput,
  type ExperimentExecutionAuthorization,
} from "./ExperimentExecutionPolicy";
import {
  validateProviderExposureReceipt,
  type ProviderExposureReceipt,
} from "./LlmExposurePolicy";
import {
  applyStrategyPatch,
  validateStrategyBundle,
  validateStrategyPatch,
  type AppliedStrategyPatch,
  type MutableStrategyPath,
  type StrategyBundle,
  type StrategyPatchOperation,
} from "./StrategyBundleSchema";
import { Ucb1SearchPolicy, type ResearchDimensionStatistics } from "./SearchPolicy";
import {
  campaignDefinition,
  dimensionDefinition,
  type ExperimentEstimatedCost,
  type InitialResearchCampaignId,
  type InitialResearchDimensionId,
  type ResearchBudgetUsage,
  type ResearchBudgets,
  type ResearchCharter,
} from "./ResearchTypes";

export interface TypedExperimentSpec {
  readonly schemaVersion: "1";
  readonly hypothesis: string;
  readonly expectedMechanism: string;
  readonly patch: readonly StrategyPatchOperation[];
  readonly publicLlmProposalHash?: string;
}

export interface PlanExperimentInput {
  readonly idempotencyKey: string;
  readonly campaignId: InitialResearchCampaignId;
  readonly charter: ResearchCharter;
  readonly baselineStrategyId: string;
  readonly baseline: StrategyBundle;
  readonly dimensionStatistics: readonly ResearchDimensionStatistics[];
  readonly proposedSpec: TypedExperimentSpec;
  readonly providerExposureReceipt?: ProviderExposureReceipt;
  readonly estimatedCost: ExperimentEstimatedCost;
  readonly createdBy: string;
  readonly createdAt: string;
}

export interface PlannedExperiment {
  readonly id: string;
  readonly campaignId: InitialResearchCampaignId;
  readonly charterId: string;
  readonly charterHash: string;
  readonly dimensionId: InitialResearchDimensionId;
  readonly baselineStrategyId: string;
  readonly baselineStrategyHash: string;
  readonly candidateStrategyId: string;
  readonly candidate: StrategyBundle;
  readonly candidateStrategyHash: string;
  readonly patch: readonly StrategyPatchOperation[];
  readonly patchHash: string;
  readonly hypothesis: string;
  readonly expectedMechanism: string;
  readonly publicLlmProposalHash?: string;
  readonly providerExposureReceiptId?: string;
  readonly benchmarkSnapshotHash: string;
  readonly evaluatorHash: string;
  readonly status: "queued";
  readonly estimatedCost: ExperimentEstimatedCost;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly executionBoundary: {
    readonly disposableLocalLabRequired: true;
    readonly publicProviderMayExecute: false;
    readonly liveClientTargetAllowed: false;
    readonly candidateMayModifyEvaluator: false;
    readonly candidateMayAutoDeploy: false;
    readonly hiddenHoldoutDetailsIncluded: false;
  };
}

interface IdempotencyRecord {
  readonly requestHash: string;
  readonly plan: PlannedExperiment;
}

export type TerminalExperimentOutcome = "completed" | "failed" | "safety_failure" | "cancelled";

export interface ResearchOrchestratorSnapshotEntry {
  readonly idempotencyKey: string;
  readonly requestHash: string;
  readonly plan: PlannedExperiment;
  readonly budgets: ResearchBudgets;
  readonly accountedCost: ExperimentEstimatedCost;
  readonly reportedActualCost: ExperimentEstimatedCost | null;
  readonly retryCount: number;
  readonly terminalOutcome: TerminalExperimentOutcome | null;
}

export interface ResearchOrchestratorSnapshot {
  readonly schemaVersion: "1";
  readonly usage: ResearchBudgetUsage;
  readonly entries: readonly ResearchOrchestratorSnapshotEntry[];
  readonly stateHash: string;
}

export class ResearchBudgetExceededError extends Error {
  readonly code = "RESEARCH_BUDGET_EXCEEDED";
  constructor(message: string) {
    super(message);
    this.name = "ResearchBudgetExceededError";
  }
}

function zeroUsage(): ResearchBudgetUsage {
  return {
    experiments: 0,
    wallClockMs: 0,
    publicLlmTokens: 0,
    estimatedCost: 0,
    toolCalls: 0,
    concurrentExperiments: 0,
    failures: 0,
    retries: 0,
  };
}

function validateBudgets(budgets: ResearchBudgets): void {
  const integerFields: readonly (keyof ResearchBudgets)[] = [
    "maxExperiments",
    "maxWallClockMs",
    "maxPublicLlmTokens",
    "maxToolCalls",
    "maxConcurrentExperiments",
    "maxFailures",
    "maxRetries",
    "maxPatchOperations",
    "maxTrialsPerDimension",
    "safetyFailureCircuitBreaker",
  ];
  for (const field of integerFields) {
    const value = budgets[field];
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Research budget ${field} is invalid.`);
  }
  if (!Number.isFinite(budgets.maxEstimatedCost) || budgets.maxEstimatedCost < 0) {
    throw new Error("Research budget maxEstimatedCost is invalid.");
  }
  if (
    budgets.maxExperiments === 0 ||
    budgets.maxConcurrentExperiments === 0 ||
    budgets.maxPatchOperations === 0 ||
    budgets.maxTrialsPerDimension === 0 ||
    budgets.safetyFailureCircuitBreaker === 0
  ) {
    throw new Error("Experiment, concurrency, patch, trial, and safety circuit budgets must be positive.");
  }
}

function validateEstimate(estimate: ExperimentEstimatedCost): void {
  for (const [field, value] of Object.entries(estimate)) {
    if (!Number.isFinite(value) || value < 0) throw new Error(`Experiment estimate ${field} is invalid.`);
  }
  if (!Number.isSafeInteger(estimate.wallClockMs) || !Number.isSafeInteger(estimate.publicLlmTokens) || !Number.isSafeInteger(estimate.toolCalls)) {
    throw new Error("Wall-clock, token, and tool-call estimates must be integers.");
  }
}

function zeroEstimate(): ExperimentEstimatedCost {
  return { wallClockMs: 0, publicLlmTokens: 0, estimatedCost: 0, toolCalls: 0 };
}

function validateUsage(usage: ResearchBudgetUsage): void {
  const integerFields: readonly (keyof ResearchBudgetUsage)[] = [
    "experiments", "wallClockMs", "publicLlmTokens", "toolCalls",
    "concurrentExperiments", "failures", "retries",
  ];
  for (const field of integerFields) {
    if (!Number.isSafeInteger(usage[field]) || usage[field] < 0) {
      throw new Error(`Research runtime usage ${field} is invalid.`);
    }
  }
  if (!Number.isFinite(usage.estimatedCost) || usage.estimatedCost < 0) {
    throw new Error("Research runtime usage estimatedCost is invalid.");
  }
}

function sameEstimate(left: ExperimentEstimatedCost, right: ExperimentEstimatedCost): boolean {
  return left.wallClockMs === right.wallClockMs &&
    left.publicLlmTokens === right.publicLlmTokens &&
    left.estimatedCost === right.estimatedCost &&
    left.toolCalls === right.toolCalls;
}

function snapshotPayload(snapshot: Omit<ResearchOrchestratorSnapshot, "stateHash">): JsonValue {
  return snapshot as unknown as JsonValue;
}

function requestHash(input: PlanExperimentInput, normalizedPatch: readonly StrategyPatchOperation[]): string {
  return hashCanonical({
    idempotencyKey: input.idempotencyKey,
    campaignId: input.campaignId,
    charterHash: input.charter.charterHash,
    baselineStrategyId: input.baselineStrategyId,
    baselineHash: hashCanonical(input.baseline as unknown as JsonValue),
    dimensionStatistics: input.dimensionStatistics,
    spec: {
      schemaVersion: input.proposedSpec.schemaVersion,
      hypothesis: input.proposedSpec.hypothesis,
      expectedMechanism: input.proposedSpec.expectedMechanism,
      patch: normalizedPatch,
      publicLlmProposalHash: input.proposedSpec.publicLlmProposalHash ?? null,
    },
    providerExposureReceipt: input.providerExposureReceipt === undefined
      ? null
      : {
          id: input.providerExposureReceipt.id,
          exposedPayloadHash: input.providerExposureReceipt.exposedPayloadHash,
          providerId: input.providerExposureReceipt.providerId,
          modelId: input.providerExposureReceipt.modelId,
        },
    estimatedCost: input.estimatedCost,
    createdBy: input.createdBy,
    createdAt: input.createdAt,
  } as unknown as JsonValue);
}

function validateText(value: string, label: string, maximum: number): void {
  if (value.trim().length === 0 || value.length > maximum) {
    throw new Error(`${label} must contain 1 through ${maximum} characters.`);
  }
}

export class ResearchOrchestrator {
  readonly #searchPolicy: Ucb1SearchPolicy;
  readonly #idempotency = new Map<string, IdempotencyRecord>();
  readonly #plans = new Map<string, PlannedExperiment>();
  readonly #planBudgets = new Map<string, ResearchBudgets>();
  readonly #accountedCosts = new Map<string, ExperimentEstimatedCost>();
  readonly #reportedActualCosts = new Map<string, ExperimentEstimatedCost>();
  readonly #retryCounts = new Map<string, number>();
  readonly #terminal = new Map<string, TerminalExperimentOutcome>();
  #usage: ResearchBudgetUsage = zeroUsage();

  constructor(
    searchPolicy = new Ucb1SearchPolicy(),
    snapshot?: ResearchOrchestratorSnapshot,
  ) {
    this.#searchPolicy = searchPolicy;
    if (snapshot !== undefined) this.#restore(snapshot);
  }

  static restore(
    snapshot: ResearchOrchestratorSnapshot,
    searchPolicy = new Ucb1SearchPolicy(),
  ): ResearchOrchestrator {
    return new ResearchOrchestrator(searchPolicy, snapshot);
  }

  get usage(): ResearchBudgetUsage {
    return deepFreeze(structuredClone(this.#usage));
  }

  snapshot(): ResearchOrchestratorSnapshot {
    const entries = [...this.#idempotency.entries()]
      .map(([idempotencyKey, record]): ResearchOrchestratorSnapshotEntry => {
        const plan = record.plan;
        return {
          idempotencyKey,
          requestHash: record.requestHash,
          plan,
          budgets: this.#planBudgets.get(plan.id)!,
          accountedCost: this.#accountedCosts.get(plan.id)!,
          reportedActualCost: this.#reportedActualCosts.get(plan.id) ?? null,
          retryCount: this.#retryCounts.get(plan.id) ?? 0,
          terminalOutcome: this.#terminal.get(plan.id) ?? null,
        };
      })
      .sort((left, right) => left.plan.id.localeCompare(right.plan.id));
    const payload = deepFreeze({
      schemaVersion: "1" as const,
      usage: this.usage,
      entries: structuredClone(entries),
    });
    return deepFreeze({
      ...payload,
      stateHash: hashCanonical(snapshotPayload(payload)),
    });
  }

  #restore(snapshot: ResearchOrchestratorSnapshot): void {
    if (snapshot.schemaVersion !== "1") throw new Error("Unsupported ResearchOrchestrator snapshot version.");
    const { stateHash, ...payload } = snapshot;
    if (!/^[a-f0-9]{64}$/u.test(stateHash) || hashCanonical(snapshotPayload(payload)) !== stateHash) {
      throw new Error("ResearchOrchestrator snapshot integrity check failed.");
    }
    validateUsage(snapshot.usage);
    const planIds = new Set<string>();
    const idempotencyKeys = new Set<string>();
    let expectedFailures = 0;
    let expectedRetries = 0;
    let expectedConcurrent = 0;
    let expectedWallClockMs = 0;
    let expectedPublicLlmTokens = 0;
    let expectedEstimatedCost = 0;
    let expectedToolCalls = 0;
    for (const entry of snapshot.entries) {
      validateText(entry.idempotencyKey, "Snapshot idempotency key", 200);
      if (idempotencyKeys.has(entry.idempotencyKey)) throw new Error("Snapshot repeats an idempotency key.");
      idempotencyKeys.add(entry.idempotencyKey);
      if (!/^[a-f0-9]{64}$/u.test(entry.requestHash)) throw new Error("Snapshot request hash is invalid.");
      const plan = structuredClone(entry.plan);
      if (plan.status !== "queued" || plan.id.trim().length === 0 || planIds.has(plan.id)) {
        throw new Error("Snapshot contains an invalid or duplicate experiment plan.");
      }
      planIds.add(plan.id);
      const candidateErrors = validateStrategyBundle(plan.candidate);
      if (candidateErrors.length > 0) throw new Error(`Snapshot candidate is invalid: ${candidateErrors.join("; ")}`);
      if (hashCanonical(plan.candidate as unknown as JsonValue) !== plan.candidateStrategyHash) {
        throw new Error("Snapshot candidate strategy hash does not match its bundle.");
      }
      if (hashCanonical(plan.patch as unknown as JsonValue) !== plan.patchHash) {
        throw new Error("Snapshot patch hash does not match its operations.");
      }
      const expectedPlanId = `experiment_${hashCanonical({
        campaignId: plan.campaignId,
        charterHash: plan.charterHash,
        baselineHash: plan.baselineStrategyHash,
        patchHash: plan.patchHash,
        idempotencyKey: entry.idempotencyKey,
      }).slice(0, 24)}`;
      if (plan.id !== expectedPlanId || plan.candidateStrategyId !== `strategy_${plan.candidateStrategyHash.slice(0, 24)}`) {
        throw new Error("Snapshot experiment or candidate identity is not canonical.");
      }
      if (
        !plan.executionBoundary.disposableLocalLabRequired ||
        plan.executionBoundary.publicProviderMayExecute ||
        plan.executionBoundary.liveClientTargetAllowed ||
        plan.executionBoundary.candidateMayModifyEvaluator ||
        plan.executionBoundary.candidateMayAutoDeploy ||
        plan.executionBoundary.hiddenHoldoutDetailsIncluded
      ) {
        throw new Error("Snapshot plan weakens the immutable execution boundary.");
      }
      validateBudgets(entry.budgets);
      validateEstimate(entry.accountedCost);
      if (entry.reportedActualCost !== null) {
        validateEstimate(entry.reportedActualCost);
        if (!sameEstimate(entry.accountedCost, entry.reportedActualCost)) {
          throw new Error("Snapshot accounted and reported actual usage disagree.");
        }
      }
      if (!Number.isSafeInteger(entry.retryCount) || entry.retryCount < 0 || entry.retryCount > entry.budgets.maxRetries) {
        throw new Error("Snapshot retry count is invalid.");
      }
      if (entry.terminalOutcome !== null && ![
        "completed", "failed", "safety_failure", "cancelled",
      ].includes(entry.terminalOutcome)) {
        throw new Error("Snapshot terminal outcome is invalid.");
      }
      expectedRetries += entry.retryCount;
      expectedFailures += entry.terminalOutcome === "failed" || entry.terminalOutcome === "safety_failure" ? 1 : 0;
      expectedConcurrent += entry.terminalOutcome === null ? 1 : 0;
      expectedWallClockMs += entry.accountedCost.wallClockMs;
      expectedPublicLlmTokens += entry.accountedCost.publicLlmTokens;
      expectedEstimatedCost += entry.accountedCost.estimatedCost;
      expectedToolCalls += entry.accountedCost.toolCalls;

      const frozenPlan = deepFreeze(plan);
      this.#idempotency.set(entry.idempotencyKey, { requestHash: entry.requestHash, plan: frozenPlan });
      this.#plans.set(plan.id, frozenPlan);
      this.#planBudgets.set(plan.id, deepFreeze(structuredClone(entry.budgets)));
      this.#accountedCosts.set(plan.id, deepFreeze(structuredClone(entry.accountedCost)));
      if (entry.reportedActualCost !== null) {
        this.#reportedActualCosts.set(plan.id, deepFreeze(structuredClone(entry.reportedActualCost)));
      }
      this.#retryCounts.set(plan.id, entry.retryCount);
      if (entry.terminalOutcome !== null) this.#terminal.set(plan.id, entry.terminalOutcome);
    }
    const approximatelyEqual = (left: number, right: number) => Math.abs(left - right) < 1e-9;
    if (
      snapshot.usage.experiments !== snapshot.entries.length ||
      snapshot.usage.concurrentExperiments !== expectedConcurrent ||
      snapshot.usage.failures !== expectedFailures ||
      snapshot.usage.retries !== expectedRetries ||
      snapshot.usage.wallClockMs !== expectedWallClockMs ||
      snapshot.usage.publicLlmTokens !== expectedPublicLlmTokens ||
      !approximatelyEqual(snapshot.usage.estimatedCost, expectedEstimatedCost) ||
      snapshot.usage.toolCalls !== expectedToolCalls
    ) {
      throw new Error("ResearchOrchestrator snapshot usage does not reconcile with its experiments.");
    }
    this.#usage = structuredClone(snapshot.usage);
  }

  #validateCharter(charter: ResearchCharter, campaignId: InitialResearchCampaignId): void {
    if (charter.status !== "approved" || charter.approvedBy.trim().length === 0) {
      throw new Error("Research charter must be explicitly approved by a human owner.");
    }
    if (charter.campaignId !== campaignId) throw new Error("Research charter campaign does not match request.");
    if (!Number.isSafeInteger(charter.version) || charter.version <= 0) throw new Error("Research charter version is invalid.");
    if (charter.charterHash.length < 32 || charter.immutableBenchmarkSnapshotHash.length < 32 || charter.immutableEvaluatorHash.length < 32) {
      throw new Error("Research charter integrity bindings are incomplete.");
    }
    validateBudgets(charter.budgets);
    const campaignPaths = new Set<MutableStrategyPath>(
      campaignDefinition(campaignId).dimensionIds.map((id) => dimensionDefinition(id).path),
    );
    const outsideCampaign = charter.mutablePaths.filter((path) => !campaignPaths.has(path));
    if (outsideCampaign.length > 0 || charter.mutablePaths.length === 0) {
      throw new Error(`Research charter mutable paths exceed the initial campaign: ${outsideCampaign.join(", ")}`);
    }
  }

  #assertBudget(budgets: ResearchBudgets, estimate: ExperimentEstimatedCost): void {
    const projected = {
      experiments: this.#usage.experiments + 1,
      wallClockMs: this.#usage.wallClockMs + estimate.wallClockMs,
      publicLlmTokens: this.#usage.publicLlmTokens + estimate.publicLlmTokens,
      estimatedCost: this.#usage.estimatedCost + estimate.estimatedCost,
      toolCalls: this.#usage.toolCalls + estimate.toolCalls,
      concurrentExperiments: this.#usage.concurrentExperiments + 1,
    };
    const exceeded = [
      projected.experiments > budgets.maxExperiments ? "experiment count" : undefined,
      projected.wallClockMs > budgets.maxWallClockMs ? "wall-clock" : undefined,
      projected.publicLlmTokens > budgets.maxPublicLlmTokens ? "public-LLM token" : undefined,
      projected.estimatedCost > budgets.maxEstimatedCost ? "estimated cost" : undefined,
      projected.toolCalls > budgets.maxToolCalls ? "tool-call" : undefined,
      projected.concurrentExperiments > budgets.maxConcurrentExperiments ? "concurrency" : undefined,
      this.#usage.failures > 0 && this.#usage.failures >= budgets.maxFailures ? "failure" : undefined,
      this.#usage.retries > 0 && this.#usage.retries >= budgets.maxRetries ? "retry" : undefined,
    ].filter((value): value is string => value !== undefined);
    if (exceeded.length > 0) {
      throw new ResearchBudgetExceededError(`Research stopped at ${exceeded.join(", ")} budget.`);
    }
  }

  planExperiment(input: PlanExperimentInput): PlannedExperiment {
    validateText(input.idempotencyKey, "Idempotency key", 200);
    validateText(input.baselineStrategyId, "Baseline strategy ID", 200);
    validateText(input.createdBy, "Experiment author", 200);
    validateText(input.proposedSpec.hypothesis, "Experiment hypothesis", 2_000);
    validateText(input.proposedSpec.expectedMechanism, "Expected mechanism", 2_000);
    if (input.proposedSpec.schemaVersion !== "1") throw new Error("Unsupported ExperimentSpec schema version.");
    if (input.proposedSpec.publicLlmProposalHash !== undefined) {
      if (!/^[a-f0-9]{64}$/u.test(input.proposedSpec.publicLlmProposalHash)) {
        throw new Error("Public-LLM proposal hash must be a SHA-256 digest.");
      }
      if (input.providerExposureReceipt === undefined) {
        throw new Error("Public-LLM proposals require a local provider-exposure receipt.");
      }
    } else if (input.providerExposureReceipt !== undefined) {
      throw new Error("A provider-exposure receipt may only accompany a hashed public-LLM proposal.");
    }
    this.#validateCharter(input.charter, input.campaignId);
    validateEstimate(input.estimatedCost);
    const baselineErrors = validateStrategyBundle(input.baseline);
    if (baselineErrors.length > 0) throw new Error(`Baseline strategy is invalid: ${baselineErrors.join("; ")}`);

    const broadValidation = validateStrategyPatch(input.proposedSpec.patch, {
      approvedMutablePaths: input.charter.mutablePaths,
      forbiddenPathPrefixes: input.charter.forbiddenPathPrefixes,
      maxOperations: input.charter.budgets.maxPatchOperations,
    });
    if (!broadValidation.valid) {
      throw new Error(`Experiment policy rejected: ${broadValidation.violations.map(({ message }) => message).join("; ")}`);
    }
    const fingerprint = requestHash(input, broadValidation.normalizedPatch);
    const prior = this.#idempotency.get(input.idempotencyKey);
    if (prior !== undefined) {
      if (prior.requestHash !== fingerprint) throw new Error("Idempotency key was reused with a different experiment request.");
      return prior.plan;
    }

    const campaign = campaignDefinition(input.campaignId);
    const selection = this.#searchPolicy.select(input.dimensionStatistics, campaign.dimensionIds, {
      maxTrialsPerDimension: input.charter.budgets.maxTrialsPerDimension,
      safetyFailureCircuitBreaker: input.charter.budgets.safetyFailureCircuitBreaker,
    });
    const selected = dimensionDefinition(selection.selectedDimensionId);
    if (input.providerExposureReceipt !== undefined) {
      const exposureErrors = validateProviderExposureReceipt(input.providerExposureReceipt, {
        campaignId: input.campaignId,
        dimensionId: selection.selectedDimensionId,
      });
      if (exposureErrors.length > 0) {
        throw new Error(`Provider-exposure receipt rejected: ${exposureErrors.join("; ")}`);
      }
    }
    const offDimension = broadValidation.normalizedPatch.filter(({ path }) => path !== selected.path);
    if (offDimension.length > 0) {
      throw new Error(
        `Experiment must change only selected dimension ${selection.selectedDimensionId} at ${selected.path}.`,
      );
    }
    this.#assertBudget(input.charter.budgets, input.estimatedCost);
    const applied: AppliedStrategyPatch = applyStrategyPatch(input.baseline, broadValidation.normalizedPatch, {
      approvedMutablePaths: [selected.path],
      forbiddenPathPrefixes: input.charter.forbiddenPathPrefixes,
      maxOperations: input.charter.budgets.maxPatchOperations,
    });
    const baselineHash = hashCanonical(input.baseline as unknown as JsonValue);
    if (applied.bundleHash === baselineHash) throw new Error("Candidate patch does not create a novel strategy version.");
    const experimentId = `experiment_${hashCanonical({
      campaignId: input.campaignId,
      charterHash: input.charter.charterHash,
      baselineHash,
      patchHash: applied.patchHash,
      idempotencyKey: input.idempotencyKey,
    }).slice(0, 24)}`;
    const candidateStrategyId = `strategy_${applied.bundleHash.slice(0, 24)}`;
    const plan: PlannedExperiment = deepFreeze({
      id: experimentId,
      campaignId: input.campaignId,
      charterId: input.charter.id,
      charterHash: input.charter.charterHash,
      dimensionId: selection.selectedDimensionId,
      baselineStrategyId: input.baselineStrategyId,
      baselineStrategyHash: baselineHash,
      candidateStrategyId,
      candidate: applied.bundle,
      candidateStrategyHash: applied.bundleHash,
      patch: broadValidation.normalizedPatch,
      patchHash: applied.patchHash,
      hypothesis: input.proposedSpec.hypothesis.trim(),
      expectedMechanism: input.proposedSpec.expectedMechanism.trim(),
      ...(input.proposedSpec.publicLlmProposalHash === undefined
        ? {}
        : { publicLlmProposalHash: input.proposedSpec.publicLlmProposalHash }),
      ...(input.providerExposureReceipt === undefined
        ? {}
        : { providerExposureReceiptId: input.providerExposureReceipt.id }),
      benchmarkSnapshotHash: input.charter.immutableBenchmarkSnapshotHash,
      evaluatorHash: input.charter.immutableEvaluatorHash,
      status: "queued",
      estimatedCost: { ...input.estimatedCost },
      createdBy: input.createdBy,
      createdAt: input.createdAt,
      executionBoundary: {
        disposableLocalLabRequired: true,
        publicProviderMayExecute: false,
        liveClientTargetAllowed: false,
        candidateMayModifyEvaluator: false,
        candidateMayAutoDeploy: false,
        hiddenHoldoutDetailsIncluded: false,
      },
    });
    this.#usage = {
      ...this.#usage,
      experiments: this.#usage.experiments + 1,
      wallClockMs: this.#usage.wallClockMs + input.estimatedCost.wallClockMs,
      publicLlmTokens: this.#usage.publicLlmTokens + input.estimatedCost.publicLlmTokens,
      estimatedCost: this.#usage.estimatedCost + input.estimatedCost.estimatedCost,
      toolCalls: this.#usage.toolCalls + input.estimatedCost.toolCalls,
      concurrentExperiments: this.#usage.concurrentExperiments + 1,
    };
    this.#idempotency.set(input.idempotencyKey, { requestHash: fingerprint, plan });
    this.#plans.set(plan.id, plan);
    this.#planBudgets.set(plan.id, structuredClone(input.charter.budgets));
    this.#accountedCosts.set(plan.id, deepFreeze(structuredClone(input.estimatedCost)));
    this.#retryCounts.set(plan.id, 0);
    return plan;
  }

  authorizeExecution(
    experimentId: string,
    input: Omit<AuthorizeExperimentExecutionInput, "plan">,
    policy = new ExperimentExecutionPolicy(),
  ): ExperimentExecutionAuthorization {
    const plan = this.#plans.get(experimentId);
    if (plan === undefined) throw new Error(`Unknown planned experiment ${experimentId}.`);
    if (this.#terminal.has(experimentId)) {
      throw new Error("A terminal experiment cannot receive new execution authority.");
    }
    return policy.authorize({ ...input, plan });
  }

  reconcileActualUsage(
    experimentId: string,
    actualTotal: ExperimentEstimatedCost,
  ): ResearchBudgetUsage {
    const plan = this.#plans.get(experimentId);
    if (plan === undefined) throw new Error(`Unknown planned experiment ${experimentId}.`);
    if (this.#terminal.has(experimentId)) throw new Error("A terminal experiment cannot report additional usage.");
    validateEstimate(actualTotal);
    const previousActual = this.#reportedActualCosts.get(experimentId) ?? zeroEstimate();
    if (
      actualTotal.wallClockMs < previousActual.wallClockMs ||
      actualTotal.publicLlmTokens < previousActual.publicLlmTokens ||
      actualTotal.estimatedCost < previousActual.estimatedCost ||
      actualTotal.toolCalls < previousActual.toolCalls
    ) {
      throw new Error("Experiment actual usage totals must be monotonic.");
    }
    const priorAccounted = this.#accountedCosts.get(experimentId) ?? plan.estimatedCost;
    const projected: ResearchBudgetUsage = {
      ...this.#usage,
      wallClockMs: this.#usage.wallClockMs - priorAccounted.wallClockMs + actualTotal.wallClockMs,
      publicLlmTokens:
        this.#usage.publicLlmTokens - priorAccounted.publicLlmTokens + actualTotal.publicLlmTokens,
      estimatedCost:
        this.#usage.estimatedCost - priorAccounted.estimatedCost + actualTotal.estimatedCost,
      toolCalls: this.#usage.toolCalls - priorAccounted.toolCalls + actualTotal.toolCalls,
    };
    validateUsage(projected);
    this.#accountedCosts.set(experimentId, deepFreeze(structuredClone(actualTotal)));
    this.#reportedActualCosts.set(experimentId, deepFreeze(structuredClone(actualTotal)));
    const budgets = this.#planBudgets.get(experimentId)!;
    const exceeded = [
      projected.wallClockMs > budgets.maxWallClockMs ? "wall-clock" : undefined,
      projected.publicLlmTokens > budgets.maxPublicLlmTokens ? "public-LLM token" : undefined,
      projected.estimatedCost > budgets.maxEstimatedCost ? "estimated cost" : undefined,
      projected.toolCalls > budgets.maxToolCalls ? "tool-call" : undefined,
    ].filter((value): value is string => value !== undefined);
    if (exceeded.length > 0) {
      this.#terminal.set(experimentId, "safety_failure");
      this.#usage = {
        ...projected,
        concurrentExperiments: Math.max(0, projected.concurrentExperiments - 1),
        failures: projected.failures + 1,
      };
      throw new ResearchBudgetExceededError(
        `Research stopped at actual ${exceeded.join(", ")} budget.`,
      );
    }
    this.#usage = projected;
    return this.usage;
  }

  recordRetry(experimentId: string): ResearchBudgetUsage {
    if (!this.#plans.has(experimentId)) throw new Error(`Unknown planned experiment ${experimentId}.`);
    if (this.#terminal.has(experimentId)) throw new Error("A terminal experiment cannot be retried in place.");
    const budgets = this.#planBudgets.get(experimentId)!;
    if (this.#usage.retries >= budgets.maxRetries) {
      throw new ResearchBudgetExceededError("Research stopped at retry budget.");
    }
    this.#usage = { ...this.#usage, retries: this.#usage.retries + 1 };
    this.#retryCounts.set(experimentId, (this.#retryCounts.get(experimentId) ?? 0) + 1);
    return this.usage;
  }

  recordTerminalOutcome(experimentId: string, outcome: TerminalExperimentOutcome): ResearchBudgetUsage {
    if (!this.#plans.has(experimentId)) throw new Error(`Unknown planned experiment ${experimentId}.`);
    const prior = this.#terminal.get(experimentId);
    if (prior !== undefined) {
      if (prior !== outcome) throw new Error("Experiment terminal outcome conflicts with its persisted outcome.");
      return this.usage;
    }
    this.#terminal.set(experimentId, outcome);
    this.#usage = {
      ...this.#usage,
      concurrentExperiments: Math.max(0, this.#usage.concurrentExperiments - 1),
      failures: this.#usage.failures + (outcome === "failed" || outcome === "safety_failure" ? 1 : 0),
    };
    return this.usage;
  }
}
